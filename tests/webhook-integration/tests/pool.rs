use super::support::*;
use rss_examples::webhook::{Endpoint, Timer};
use rss_request_context::{Clock, Deadline, ExecutionTimer, TenantId};
use rss_transactional_messaging::{
    message::{AuthoredMessageMetadata, MessageMetadata, MessageMetadataExtensions},
    outbox::PendingMessage,
    policy::OperationDeadline,
    transport::{PublishOutcome, Publisher},
};
use rss_transactional_messaging_webhook::*;
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    net::TcpListener,
    sync::{Mutex, watch},
};

const SECOND_TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d478";
const EMPTY: &[u8] = b"HTTP/1.1 204 No Content\r\n\r\n";

struct Policy {
    url: String,
    addresses: Vec<SocketAddr>,
    roots: Vec<Vec<u8>>,
    current: Vec<u8>,
    retiring: Option<Vec<u8>>,
    denied: bool,
}
#[derive(Clone)]
struct Authorization {
    policy: Arc<Mutex<Policy>>,
    calls: Arc<AtomicUsize>,
}
impl Authorization {
    fn new(endpoint: &Endpoint) -> Self {
        Self {
            policy: Arc::new(Mutex::new(Policy {
                url: endpoint.url.clone(),
                addresses: vec![endpoint.address],
                roots: vec![endpoint.ca.clone()],
                current: endpoint.secret.clone(),
                retiring: None,
                denied: false,
            })),
            calls: Arc::default(),
        }
    }
}

impl TargetAuthorizer for Authorization {
    async fn authorize(
        &self,
        publication: &Publication<'_>,
        _: OperationDeadline,
    ) -> Result<AuthorizedTarget, AuthorizationFailure> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let policy = self.policy.lock().await;
        if policy.denied {
            return Err(AuthorizationFailure::Denied);
        }
        let target = || {
            AuthorizedTarget::new(
                publication.tenant(),
                publication.target().clone(),
                &policy.url,
                NetworkAccess::new(
                    policy.addresses.clone(),
                    policy.addresses.iter().map(|a| a.ip().into()).collect(),
                )?,
                TrustRoots::from_der(policy.roots.clone())?,
                SigningKeys::new(
                    SigningKey::new(policy.current.clone())?,
                    policy.retiring.clone().map(SigningKey::new).transpose()?,
                ),
            )
        };
        target().map_err(|_| AuthorizationFailure::Denied)
    }
}
fn limits(pool: Option<IdlePoolLimits>) -> anyhow::Result<Limits> {
    Ok(Limits::new(4, 65536, 4, 32, 8192, pool)?)
}
fn enabled() -> anyhow::Result<Limits> {
    limits(Some(IdlePoolLimits::new(4, Duration::from_secs(30))?))
}
fn cutoff() -> anyhow::Result<Deadline> {
    Ok(Deadline::from_timeout(&Timer, Duration::from_secs(2))?)
}
fn bound(tenant: &str, version: u64, id: &str) -> anyhow::Result<PendingMessage<Vec<u8>>> {
    let base = message(id)?;
    let msg = base.envelope();
    let m = msg.metadata();
    let metadata = MessageMetadata::new(
        AuthoredMessageMetadata::new(
            TenantId::parse(tenant)?,
            m.occurred_at(),
            m.domain().clone(),
            m.route().clone(),
            m.contract().clone(),
        ),
        MessageMetadataExtensions::default(),
    );
    Ok(pending_message(
        msg.id().clone(),
        metadata,
        Target::new(TargetId::parse("receiver")?, TargetVersion::new(version)?),
        msg.payload().clone(),
    )?)
}
async fn accepted<P: Publisher<Vec<u8>, Receipt = WebhookPublishReceipt>>(
    publisher: &P,
    pending: &PendingMessage<Vec<u8>>,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        matches!(
            publisher.publish(pending.envelope(), deadline()).await,
            PublishOutcome::Confirmed(_)
        ),
        "expected final 2xx"
    );
    Ok(())
}

#[tokio::test]
async fn eight_requests_measure_tcp_tls_and_current_authorization() -> anyhow::Result<()> {
    let mut receiver = Receiver::new(Mode::KeepAlive(EMPTY.to_vec())).await?;
    for (pool, expected) in [
        (None, 8),
        (Some(IdlePoolLimits::new(1, Duration::from_secs(30))?), 1),
    ] {
        let start = receiver.connections.load(Ordering::SeqCst);
        let tls = receiver.handshakes.load(Ordering::SeqCst);
        let auth = Authorization::new(&receiver.endpoint);
        let publisher = WebhookPublisher::new(auth.clone(), Timer, Timer, limits(pool)?);
        for n in 0..8 {
            let id = format!("delivery-{n}");
            accepted(&publisher, &message(&id)?).await?;
            let record = receiver.received().await?;
            assert_eq!(record.headers["webhook-id"], id);
            assert_eq!(
                record.headers.get("connection").map(String::as_str),
                pool.is_none().then_some("close")
            );
            record.verify(&receiver.endpoint.secret)?;
            assert_eq!(
                record.connection,
                start + if pool.is_some() { 0 } else { n }
            );
        }
        let tcp = receiver.connections.load(Ordering::SeqCst) - start;
        let tls = receiver.handshakes.load(Ordering::SeqCst) - tls;
        let calls = auth.calls.load(Ordering::SeqCst);
        eprintln!(
            "pool={} requests=8 authorizations={calls} tcp={tcp} tls={tls}",
            pool.is_some()
        );
        assert_eq!((calls, tcp, tls), (8, expected, expected));
        publisher.close(cutoff()?).await?;
        wait_count(&receiver.closed, start + expected).await?;
    }
    receiver.stop().await
}

#[tokio::test]
async fn stalled_first_address_and_lost_confirmation_send_only_once() -> anyhow::Result<()> {
    let mut healthy = Receiver::new(Mode::DropResponse).await?;
    let listener = TcpListener::bind(("::1", healthy.endpoint.address.port())).await?;
    let mut stalled = Receiver::on(listener, Mode::StallTls).await?;
    let auth = Authorization::new(&healthy.endpoint);
    auth.policy.lock().await.addresses = vec![
        stalled.endpoint.address,
        stalled.endpoint.address,
        healthy.endpoint.address,
    ];
    let publisher = WebhookPublisher::new(auth.clone(), Timer, Timer, enabled()?);
    *healthy.mode.lock().await = response(204);
    accepted(&publisher, &message("fallback")?).await?;
    let record = healthy.received().await?;
    record.verify(&healthy.endpoint.secret)?;
    assert_eq!(record.sni.as_deref(), Some("localhost"));
    assert_eq!(record.local, healthy.endpoint.address);
    wait_count(&stalled.closed, 1).await?;
    assert_eq!(stalled.connections.load(Ordering::SeqCst), 1);
    assert_eq!(stalled.handshakes.load(Ordering::SeqCst), 0);

    *healthy.mode.lock().await = Mode::DropResponse;
    *stalled.mode.lock().await = response(204);
    {
        let mut policy = auth.policy.lock().await;
        policy.addresses = vec![healthy.endpoint.address, stalled.endpoint.address];
        policy.roots.push(stalled.endpoint.ca.clone());
    }
    assert!(
        publisher
            .publish(message("lost")?.envelope(), deadline())
            .await
            .is_ambiguous()
    );
    assert_eq!(healthy.received().await?.headers["webhook-id"], "lost");
    healthy.assert_no_request()?;
    stalled.assert_no_request()?;
    assert_eq!(stalled.connections.load(Ordering::SeqCst), 1);
    publisher.close(cutoff()?).await?;
    stalled.stop().await?;
    healthy.stop().await
}

#[tokio::test]
async fn checkout_matches_each_current_authorization_fact() -> anyhow::Result<()> {
    let mut a = Receiver::new(Mode::KeepAlive(EMPTY.to_vec())).await?;
    let mut b = Receiver::on(
        TcpListener::bind(("::1", a.endpoint.address.port())).await?,
        Mode::KeepAlive(EMPTY.to_vec()),
    )
    .await?;
    let auth = Authorization::new(&a.endpoint);
    let publisher = WebhookPublisher::new(auth.clone(), Timer, Timer, enabled()?);
    let mut tenant = TENANT;
    let mut version = 1;
    for step in 0..8 {
        {
            let mut policy = auth.policy.lock().await;
            match step {
                1 => tenant = SECOND_TENANT,
                2 => version = 2,
                3 => policy.current = vec![12; 32],
                4 => policy.retiring = Some(vec![13; 32]),
                5 => policy.roots.push(b.endpoint.ca.clone()),
                6 => policy.url.push_str("&new=1"),
                7 => policy.addresses = vec![b.endpoint.address],
                _ => {} // reason: first request establishes the baseline connection.
            }
        }
        accepted(
            &publisher,
            &bound(tenant, version, &format!("binding-{step}"))?,
        )
        .await?;
        let record = if step == 7 {
            b.received().await?
        } else {
            a.received().await?
        };
        assert_eq!(record.connection, if step == 7 { 0 } else { step });
        if step == 7 {
            assert_eq!(record.local, b.endpoint.address);
        }
        let policy = auth.policy.lock().await;
        record.verify(&policy.current)?;
        if let Some(key) = &policy.retiring {
            record.verify(key)?;
        }
    }
    auth.policy.lock().await.denied = true;
    assert!(
        matches!(publisher.publish(bound(tenant, version, "revoked")?.envelope(), deadline()).await, PublishOutcome::DefinitelyNotPublished(f) if f.kind().is_permanent())
    );
    assert_eq!(auth.calls.load(Ordering::SeqCst), 9);
    assert_eq!(a.handshakes.load(Ordering::SeqCst), 7);
    assert_eq!(b.handshakes.load(Ordering::SeqCst), 1);
    a.assert_no_request()?;
    b.assert_no_request()?;
    publisher.close(cutoff()?).await?;
    a.stop().await?;
    b.stop().await
}

#[tokio::test]
async fn response_boundary_controls_reuse_independently_of_receipt() -> anyhow::Result<()> {
    let mut receiver = Receiver::new(Mode::KeepAlive(EMPTY.to_vec())).await?;
    let publisher = receiver.publisher()?;
    for (wire, expected_id, confirmed) in [
        (
            &b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc"[..],
            0,
            true,
        ),
        (EMPTY, 0, true),
        (
            b"HTTP/1.1 202 Accepted\r\nContent-Length: 999999999\r\n\r\n",
            0,
            true,
        ),
        (b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nx", 1, true),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            2,
            true,
        ),
        (b"HTTP/1.1 503 Busy\r\nContent-Length: 0\r\n\r\n", 3, false),
        (EMPTY, 4, true),
    ] {
        *receiver.mode.lock().await = Mode::KeepAlive(wire.to_vec());
        let outcome = publisher
            .publish(message("response")?.envelope(), deadline())
            .await;
        assert_eq!(matches!(outcome, PublishOutcome::Confirmed(_)), confirmed);
        assert_eq!(outcome.is_ambiguous(), !confirmed);
        assert_eq!(receiver.received().await?.connection, expected_id);
    }
    publisher.close(cutoff()?).await?;
    receiver.stop().await
}

#[derive(Clone)]
struct ManualTimer(watch::Sender<Instant>);
impl Clock for ManualTimer {
    fn now(&self) -> Instant {
        *self.0.borrow()
    }
}
impl ExecutionTimer for ManualTimer {
    async fn sleep_until(&self, deadline: Deadline) {
        let mut clock = self.0.subscribe();
        let _ = clock.wait_for(|now| deadline.is_expired(*now)).await;
    }
}

#[tokio::test]
async fn global_idle_capacity_and_quiet_ttl_close_real_sockets() -> anyhow::Result<()> {
    let mut receiver = Receiver::new(Mode::KeepAlive(EMPTY.to_vec())).await?;
    let ttl = Duration::from_secs(5);
    let timer = ManualTimer(watch::channel(Timer.now()).0);
    let publisher = WebhookPublisher::new(
        Authorization::new(&receiver.endpoint),
        timer.clone(),
        Timer,
        limits(Some(IdlePoolLimits::new(1, ttl)?))?,
    );
    for tenant in [TENANT, SECOND_TENANT] {
        accepted(&publisher, &bound(tenant, 1, "idle")?).await?;
        receiver.received().await?;
    }
    wait_count(&receiver.closed, 1).await?;
    assert_eq!(receiver.closed.load(Ordering::SeqCst), 1);
    timer.0.send_modify(|now| *now += ttl);
    wait_count(&receiver.closed, 2).await?;
    publisher
        .close(Deadline::from_timeout(&timer, ttl)?)
        .await?;
    receiver.stop().await
}

#[tokio::test]
async fn close_rejects_admission_and_can_resume_wait_after_timeout() -> anyhow::Result<()> {
    let mut receiver = Receiver::new(Mode::KeepAlive(EMPTY.to_vec())).await?;
    let publisher = Arc::new(WebhookPublisher::new(
        Authorization::new(&receiver.endpoint),
        Timer,
        Timer,
        enabled()?,
    ));
    accepted(&*publisher, &message("idle")?).await?;
    receiver.received().await?;
    *receiver.mode.lock().await = Mode::StallHeaders;
    let active = bound(SECOND_TENANT, 1, "active")?;
    let task = {
        let publisher = publisher.clone();
        tokio::spawn(async move { publisher.publish(active.envelope(), deadline()).await })
    };
    receiver.received().await?;
    assert_eq!(
        publisher
            .close(Deadline::from_timeout(&Timer, Duration::from_millis(30))?)
            .await,
        Err(CloseError::Deadline)
    );
    wait_count(&receiver.closed, 1).await?;
    assert!(matches!(
        publisher
            .publish(message("closed")?.envelope(), deadline())
            .await,
        PublishOutcome::DefinitelyNotPublished(_)
    ));
    receiver.assert_no_request()?;
    task.abort();
    assert!(task.await.is_err_and(|e| e.is_cancelled()));
    publisher.close(cutoff()?).await?;
    wait_count(&receiver.closed, 2).await?;
    publisher.close(cutoff()?).await?;
    receiver.stop().await
}

#[tokio::test]
async fn admitted_publish_completes_while_close_drains() -> anyhow::Result<()> {
    let release = Arc::new(tokio::sync::Notify::new());
    let mut receiver = Receiver::new(Mode::ReleaseHeaders(release.clone())).await?;
    let publisher = Arc::new(receiver.publisher()?);
    let task = {
        let publisher = publisher.clone();
        tokio::spawn(async move { accepted(&*publisher, &message("draining")?).await })
    };
    receiver.received().await?;
    let close = publisher.close(cutoff()?);
    tokio::pin!(close);
    // Poll close into its drain wait before releasing the final headers.
    tokio::select! {
        biased;
        result = &mut close => anyhow::bail!("close completed with an active publish: {result:?}"),
        () = std::future::ready(()) => (),
    }
    assert!(matches!(
        publisher
            .publish(message("late")?.envelope(), deadline())
            .await,
        PublishOutcome::DefinitelyNotPublished(_)
    ));
    release.notify_one();
    task.await??;
    close.await?;
    wait_count(&receiver.closed, 1).await?;
    receiver.assert_no_request()?;
    receiver.stop().await
}

#[tokio::test]
async fn runtime_cancellation_releases_idle_sockets_without_another_publish() -> anyhow::Result<()>
{
    let mut receiver = Receiver::new(Mode::KeepAlive(EMPTY.to_vec())).await?;
    let publisher = Arc::new(receiver.publisher()?);
    let client = publisher.clone();
    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(accepted(&*client, &message("idle-runtime")?))?;
        Ok(())
    })
    .await??;
    receiver.received().await?;
    wait_count(&receiver.closed, 1).await?;
    assert_eq!(publisher.close(cutoff()?).await, Err(CloseError::Cleanup));
    receiver.stop().await
}
