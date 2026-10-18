use super::support::*;
use rss_examples::webhook::{Endpoint, Timer};
use rss_transactional_messaging::{
    policy::OperationDeadline,
    transport::{PublishOutcome, Publisher},
};
use rss_transactional_messaging_webhook::*;
use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

#[tokio::test]
async fn real_tls_signature_and_all_http_outcomes() -> anyhow::Result<()> {
    let mut receiver = Receiver::new(response(204)).await?;
    let publisher = receiver.publisher()?;
    let message = message("https-outcomes")?;
    for status in [
        200, 204, 299, 301, 302, 307, 308, 400, 401, 403, 404, 429, 500, 503,
    ] {
        *receiver.mode.lock().await = response(status);
        let outcome = publisher.publish(message.envelope(), deadline()).await;
        assert_eq!(
            matches!(outcome, PublishOutcome::Confirmed(_)),
            (200..300).contains(&status)
        );
        if status >= 300 {
            assert!(outcome.is_ambiguous());
        }
        let record = receiver.received().await?;
        record.verify(&receiver.endpoint.secret)?;
        assert_eq!(record.body, message.envelope().payload().as_slice());
        assert_eq!(
            record.headers.get("webhook-id").map(String::as_str),
            Some("https-outcomes")
        );
        assert_eq!(record.request_line, "POST /events?version=1 HTTP/1.1");
    }
    receiver.stop().await
}
#[tokio::test]
async fn tls_identity_policy_and_binding_fail_before_http() -> anyhow::Result<()> {
    let receiver = Receiver::new(response(204)).await?;
    let message = message("reject")?;
    let mut configs = Vec::new();
    let mut foreign = receiver.endpoint.clone();
    foreign.ca = rcgen::generate_simple_self_signed(vec!["localhost".into()])?
        .cert
        .der()
        .to_vec();
    configs.push(foreign);
    let mut hostname = receiver.endpoint.clone();
    hostname.url = hostname.url.replace("localhost", "other.invalid");
    configs.push(hostname);
    let mut tenant = receiver.endpoint.clone();
    tenant.tenant = "f47ac10b-58cc-4372-a567-0e02b2c3d478".into();
    configs.push(tenant);
    for endpoint in configs {
        let p = WebhookPublisher::new(endpoint, Timer, Timer, rss_examples::webhook::limits()?);
        assert!(matches!(
            p.publish(message.envelope(), deadline()).await,
            PublishOutcome::DefinitelyNotPublished(_)
        ));
    }
    for url in [
        "http://localhost/",
        "https://user:pass@localhost/",
        "https://localhost/#fragment",
    ] {
        let mut endpoint = receiver.endpoint.clone();
        endpoint.url = url.into();
        let p = WebhookPublisher::new(endpoint, Timer, Timer, rss_examples::webhook::limits()?);
        assert!(matches!(
            p.publish(message.envelope(), deadline()).await,
            PublishOutcome::DefinitelyNotPublished(_)
        ));
    }
    assert!(
        NetworkAccess::new(vec![receiver.endpoint.address], vec!["10.0.0.0/8".parse()?]).is_err()
    );
    receiver.stop().await
}
#[tokio::test]
async fn confirmation_loss_header_limits_and_unread_body() -> anyhow::Result<()> {
    let mut receiver = Receiver::new(Mode::DropResponse).await?;
    let publisher = receiver.publisher()?;
    let message = message("confirmation")?;
    assert!(
        publisher
            .publish(message.envelope(), deadline())
            .await
            .is_ambiguous()
    );
    receiver
        .received()
        .await?
        .verify(&receiver.endpoint.secret)?;
    *receiver.mode.lock().await = Mode::Reply(
        format!("HTTP/1.1 200 OK\r\nX-Large: {}\r\n\r\n", "x".repeat(32768)).into_bytes(),
    );
    assert!(
        publisher
            .publish(message.envelope(), deadline())
            .await
            .is_ambiguous()
    );
    receiver.received().await?;
    *receiver.mode.lock().await =
        Mode::Reply(b"HTTP/1.1 202 Accepted\r\nContent-Length: 999999999\r\n\r\n".to_vec());
    assert!(matches!(
        publisher.publish(message.envelope(), deadline()).await,
        PublishOutcome::Confirmed(_)
    ));
    receiver.received().await?;
    receiver.stop().await
}
#[tokio::test]
async fn cancellation_deadlines_and_capacity_release_actual_connections() -> anyhow::Result<()> {
    let mut receiver = Receiver::new(Mode::StallHeaders).await?;
    let publisher = Arc::new(WebhookPublisher::new(
        receiver.endpoint.clone(),
        Timer,
        Timer,
        Limits::new(1, 65536, 4, 32, 8192)?,
    ));
    let pending = message("cancel")?;
    let task = {
        let publisher = publisher.clone();
        tokio::spawn(async move { publisher.publish(pending.envelope(), deadline()).await })
    };
    receiver.received().await?;
    let pending = message("capacity")?;
    assert!(
        matches!(publisher.publish(pending.envelope(),deadline()).await,PublishOutcome::DefinitelyNotPublished(f) if f.kind().is_retryable())
    );
    assert_eq!(receiver.connections.load(Ordering::SeqCst), 1);
    task.abort();
    assert!(task.await.is_err_and(|e| e.is_cancelled()));
    wait_count(&receiver.closed, 1).await?;
    let short = OperationDeadline::from_remaining(Duration::from_millis(80));
    assert!(
        publisher
            .publish(pending.envelope(), short)
            .await
            .is_ambiguous()
    );
    receiver.received().await?;
    wait_count(&receiver.closed, 2).await?;
    *receiver.mode.lock().await = Mode::StallTls;
    assert!(matches!(
        publisher.publish(pending.envelope(), short).await,
        PublishOutcome::DefinitelyNotPublished(_)
    ));
    wait_count(&receiver.closed, 3).await?;
    *receiver.mode.lock().await = response(200);
    assert!(matches!(
        publisher.publish(pending.envelope(), deadline()).await,
        PublishOutcome::Confirmed(_)
    ));
    receiver.received().await?;
    receiver.stop().await
}
struct Rotating {
    endpoint: Endpoint,
}
impl TargetAuthorizer for Rotating {
    async fn authorize(
        &self,
        p: &Publication<'_>,
        d: OperationDeadline,
    ) -> Result<AuthorizedTarget, AuthorizationFailure> {
        let base = &self.endpoint;
        base.authorize(p, d).await?;
        AuthorizedTarget::new(
            p.tenant(),
            p.target().clone(),
            &base.url,
            NetworkAccess::new(
                vec![base.address],
                vec![ipnet::IpNet::from(base.address.ip())],
            )
            .map_err(|_| AuthorizationFailure::Denied)?,
            TrustRoots::from_der([base.ca.clone()]).map_err(|_| AuthorizationFailure::Denied)?,
            SigningKeys::new(
                SigningKey::new(vec![12; 32]).map_err(|_| AuthorizationFailure::Denied)?,
                Some(
                    SigningKey::new(base.secret.clone())
                        .map_err(|_| AuthorizationFailure::Denied)?,
                ),
            ),
        )
        .map_err(|_| AuthorizationFailure::Denied)
    }
}
#[tokio::test]
async fn rotation_produces_two_valid_signatures() -> anyhow::Result<()> {
    let mut receiver = Receiver::new(response(200)).await?;
    let publisher = WebhookPublisher::new(
        Rotating {
            endpoint: receiver.endpoint.clone(),
        },
        Timer,
        Timer,
        rss_examples::webhook::limits()?,
    );
    assert!(matches!(
        publisher
            .publish(message("rotation")?.envelope(), deadline())
            .await,
        PublishOutcome::Confirmed(_)
    ));
    let record = receiver.received().await?;
    record.verify(&[11; 32])?;
    record.verify(&[12; 32])?;
    receiver.stop().await
}

struct CurrentAuthorization {
    endpoint: Endpoint,
    state: Arc<std::sync::atomic::AtomicUsize>,
    cancelled: Arc<std::sync::atomic::AtomicUsize>,
}
struct Authorizing(Arc<std::sync::atomic::AtomicUsize>);
impl Drop for Authorizing {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
impl TargetAuthorizer for CurrentAuthorization {
    async fn authorize(
        &self,
        p: &Publication<'_>,
        d: OperationDeadline,
    ) -> Result<AuthorizedTarget, AuthorizationFailure> {
        let _guard = Authorizing(self.cancelled.clone());
        match self.state.load(Ordering::SeqCst) {
            1 => return Err(AuthorizationFailure::Denied),
            2 => std::future::pending::<()>().await,
            3 => {
                return AuthorizedTarget::new(
                    p.tenant(),
                    Target::new(
                        TargetId::parse("receiver").map_err(|_| AuthorizationFailure::Denied)?,
                        TargetVersion::new(2).map_err(|_| AuthorizationFailure::Denied)?,
                    ),
                    &self.endpoint.url,
                    NetworkAccess::new(
                        vec![self.endpoint.address],
                        vec![ipnet::IpNet::from(self.endpoint.address.ip())],
                    )
                    .map_err(|_| AuthorizationFailure::Denied)?,
                    TrustRoots::from_der([self.endpoint.ca.clone()])
                        .map_err(|_| AuthorizationFailure::Denied)?,
                    SigningKeys::new(
                        SigningKey::new(self.endpoint.secret.clone())
                            .map_err(|_| AuthorizationFailure::Denied)?,
                        None,
                    ),
                )
                .map_err(|_| AuthorizationFailure::Denied);
            }
            _ => {}
        }
        self.endpoint.authorize(p, d).await
    }
}
#[tokio::test]
async fn every_attempt_reauthorizes_and_authorization_deadline_cancels_work() -> anyhow::Result<()>
{
    let mut receiver = Receiver::new(response(200)).await?;
    let state = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let cancelled = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let publisher = WebhookPublisher::new(
        CurrentAuthorization {
            endpoint: receiver.endpoint.clone(),
            state: state.clone(),
            cancelled: cancelled.clone(),
        },
        Timer,
        Timer,
        rss_examples::webhook::limits()?,
    );
    let pending = message("reauthorize")?;
    assert!(matches!(
        publisher.publish(pending.envelope(), deadline()).await,
        PublishOutcome::Confirmed(_)
    ));
    receiver.received().await?;
    for value in [1, 2, 3] {
        state.store(value, Ordering::SeqCst);
        assert!(matches!(
            publisher
                .publish(
                    pending.envelope(),
                    OperationDeadline::from_remaining(Duration::from_millis(40))
                )
                .await,
            PublishOutcome::DefinitelyNotPublished(_)
        ));
    }
    assert_eq!(cancelled.load(Ordering::SeqCst), 4);
    assert_eq!(receiver.connections.load(Ordering::SeqCst), 1);
    receiver.stop().await
}
