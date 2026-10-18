use crate::{
    AuthorizationFailure, AuthorizedTarget, Limits, Publication, TargetAuthorizer, WallClock,
};
use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, client::conn::http1};
use hyper_util::rt::TokioIo;
use rss_request_context::{Deadline, ExecutionTimer};
use rss_transactional_messaging::{
    message::MessageEnvelope,
    policy::{OperationDeadline, within},
    transport::{
        PublishFailure, PublishFailureKind as Kind, PublishFailureReason as Reason,
        PublishFailureStage as Stage, PublishOutcome, Publisher,
    },
};
use tokio::{net::TcpStream, sync::Semaphore};
use tokio_rustls::TlsConnector;

/// Move-only evidence of HTTP acceptance; cannot be constructed or deserialized by consumers.
/// It does not prove business processing, uniqueness or durable receiver storage.
/// ```compile_fail
/// use rss_transactional_messaging_webhook::WebhookPublishReceipt;
/// let forged = WebhookPublishReceipt { status: 200 };
/// ```
#[derive(Debug)]
pub struct WebhookPublishReceipt {
    status: u16,
}
impl WebhookPublishReceipt {
    /// Final HTTP 2xx status observed from the authorized TLS peer.
    pub const fn status(&self) -> u16 {
        self.status
    }
}
/// Single-request HTTPS transport; owns no background tasks, retry queue or connection pool.
/// Dropping a publish future drops its connection. Hosts own relay task cancellation and joining.
pub struct WebhookPublisher<A, T, W> {
    authorizer: A,
    timer: T,
    wall_clock: W,
    limits: Limits,
    capacity: Semaphore,
}
impl<A, T, W> WebhookPublisher<A, T, W> {
    /// Inject current authorization, monotonic timer, UTC clock and explicit resource limits.
    pub fn new(authorizer: A, timer: T, wall_clock: W, limits: Limits) -> Self {
        Self {
            authorizer,
            timer,
            wall_clock,
            capacity: Semaphore::new(limits.concurrent),
            limits,
        }
    }
}
impl<A: TargetAuthorizer, T: ExecutionTimer, W: WallClock> Publisher<Vec<u8>>
    for WebhookPublisher<A, T, W>
{
    type Receipt = WebhookPublishReceipt;
    async fn publish(
        &self,
        message: &MessageEnvelope<Vec<u8>>,
        deadline: OperationDeadline,
    ) -> PublishOutcome<Self::Receipt> {
        // Freeze the relative snapshot before any validation, hashing or host call.
        let Ok(cutoff) = Deadline::from_timeout(&self.timer, deadline.timeout()) else {
            return definite(Kind::Permanent, Stage::Admission, Reason::InvalidMessage);
        };
        let mut sending = false;
        match within(&self.timer, cutoff, |_| {
            self.attempt(message, cutoff, &mut sending)
        })
        .await
        {
            Ok(outcome) => outcome,
            Err(_) if sending => ambiguous(Reason::DeadlineElapsed),
            Err(_) => definite(Kind::Transient, Stage::Admission, Reason::DeadlineElapsed),
        }
    }
}
impl<A: TargetAuthorizer, T: ExecutionTimer, W: WallClock> WebhookPublisher<A, T, W> {
    async fn attempt(
        &self,
        message: &MessageEnvelope<Vec<u8>>,
        cutoff: Deadline,
        sending: &mut bool,
    ) -> PublishOutcome<WebhookPublishReceipt> {
        let Ok(_permit) = self.capacity.try_acquire() else {
            return definite(
                Kind::Transient,
                Stage::Admission,
                Reason::TransportUnavailable,
            );
        };
        if message.payload().len() > self.limits.body_bytes {
            return definite(Kind::Permanent, Stage::Encode, Reason::InvalidMessage);
        }
        let Ok(publication) = Publication::parse(message) else {
            return definite(Kind::Permanent, Stage::Encode, Reason::InvalidMessage);
        };
        let target = match self
            .authorizer
            .authorize(
                &publication,
                OperationDeadline::from_cutoff(cutoff, &self.timer),
            )
            .await
        {
            Ok(target) => target,
            Err(AuthorizationFailure::Denied) => {
                return definite(Kind::Permanent, Stage::Admission, Reason::ProviderRejected);
            }
            Err(AuthorizationFailure::Unavailable) => {
                return definite(
                    Kind::Transient,
                    Stage::Admission,
                    Reason::TransportUnavailable,
                );
            }
        };
        if target.tenant != publication.tenant()
            || &target.target != publication.target()
            || target.network.addresses.len() > self.limits.addresses
        {
            return definite(Kind::Permanent, Stage::Admission, Reason::InvalidMessage);
        }
        let Ok(tls) = connect(&target).await else {
            return definite(
                Kind::Transient,
                Stage::Admission,
                Reason::TransportUnavailable,
            );
        };
        let mut builder = http1::Builder::new();
        builder
            .max_headers(self.limits.headers)
            .max_buf_size(self.limits.header_bytes);
        let Ok((mut sender, connection)) = builder.handshake(TokioIo::new(tls)).await else {
            return definite(
                Kind::Transient,
                Stage::Admission,
                Reason::TransportUnavailable,
            );
        };
        let seconds = self.wall_clock.unix_seconds();
        if seconds < 0 {
            // The attempt timestamp is temporarily unrepresentable; authored facts remain valid.
            return definite(Kind::Transient, Stage::Encode, Reason::InvalidMessage);
        }
        let Ok(request) = self.request(message, &target, seconds) else {
            return definite(Kind::Permanent, Stage::Encode, Reason::InvalidMessage);
        };
        // Synchronous preparation may consume the remaining budget; do not start sending late.
        if OperationDeadline::from_cutoff(cutoff, &self.timer)
            .timeout()
            .is_zero()
        {
            return definite(Kind::Transient, Stage::Admission, Reason::DeadlineElapsed);
        }
        *sending = true;
        let request = sender.send_request(request);
        tokio::pin!(connection, request);
        // Drive both futures locally; cancellation drops the entire IO owner, never a JoinHandle.
        let result = tokio::select! {
            biased;
            response = &mut request => response,
            _ = &mut connection => request.await,
        };
        match result {
            Ok(response) if response.status().is_success() => {
                PublishOutcome::Confirmed(WebhookPublishReceipt {
                    status: response.status().as_u16(),
                })
            }
            Ok(_) => ambiguous(Reason::ProviderRejected),
            Err(_) => ambiguous(Reason::TransportUnavailable),
        }
    }
    fn request(
        &self,
        message: &MessageEnvelope<Vec<u8>>,
        target: &AuthorizedTarget,
        seconds: i64,
    ) -> Result<Request<Full<Bytes>>, crate::Error> {
        let (timestamp, signature) =
            target
                .keys
                .sign(message.id().as_str(), seconds, message.payload())?;
        let mut signature =
            hyper::header::HeaderValue::from_str(&signature).map_err(|_| crate::Error::Signing)?;
        signature.set_sensitive(true);
        Request::post(&target.url[url::Position::BeforePath..url::Position::AfterQuery])
            .header(
                "host",
                &target.url[url::Position::BeforeHost..url::Position::AfterPort],
            )
            .header("webhook-id", message.id().as_str())
            .header("webhook-timestamp", timestamp)
            .header("webhook-signature", signature)
            .header("content-type", "application/octet-stream")
            .header("connection", "close")
            .body(Full::new(Bytes::copy_from_slice(message.payload())))
            .map_err(|_| crate::Error::Binding)
    }
}
async fn connect(
    target: &AuthorizedTarget,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, ()> {
    let mut stream = None;
    for address in &target.network.addresses {
        if let Ok(connected) = TcpStream::connect(address).await {
            let peer = connected.peer_addr().map_err(|_| ())?;
            if peer != *address || !target.network.permits(peer.ip()) {
                return Err(());
            }
            stream = Some(connected);
            break;
        }
    }
    let name = match target.url.host().ok_or(())? {
        url::Host::Domain(name) => {
            rustls::pki_types::ServerName::try_from(name.to_owned()).map_err(|_| ())?
        }
        url::Host::Ipv4(ip) => rustls::pki_types::ServerName::IpAddress(ip.into()),
        url::Host::Ipv6(ip) => rustls::pki_types::ServerName::IpAddress(ip.into()),
    };
    TlsConnector::from(target.trust.0.clone())
        .connect(name, stream.ok_or(())?)
        .await
        .map_err(|_| ())
}
fn definite(kind: Kind, stage: Stage, reason: Reason) -> PublishOutcome<WebhookPublishReceipt> {
    PublishOutcome::DefinitelyNotPublished(PublishFailure::new(kind, stage, reason))
}
fn ambiguous(reason: Reason) -> PublishOutcome<WebhookPublishReceipt> {
    PublishOutcome::Ambiguous(PublishFailure::new(Kind::Transient, Stage::Confirm, reason))
}
