use crate::{
    AuthorizationFailure, AuthorizedTarget, Limits, Publication, TargetAuthorizer, WallClock,
};
use crate::{
    connection::Connection,
    pool::{CloseError, Connections, Identity},
};
use bytes::Bytes;
use http_body_util::Full;
use hyper::Request;
use rss_request_context::{Deadline, ExecutionTimer};
use rss_transactional_messaging::{
    message::MessageEnvelope,
    policy::{OperationDeadline, within},
    transport::{
        PublishFailure, PublishFailureKind as Kind, PublishFailureReason as Reason,
        PublishFailureStage as Stage, PublishOutcome, Publisher,
    },
};
use std::sync::Arc;

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
/// Bounded HTTPS publisher. Each publish exclusively owns its active connection.
/// An explicitly enabled idle pool is scoped to this publisher.
pub struct WebhookPublisher<A, T, W> {
    authorizer: A,
    timer: Arc<T>,
    wall_clock: W,
    limits: Limits,
    connections: Connections,
}
impl<A, T, W> WebhookPublisher<A, T, W> {
    /// Inject current authorization, monotonic timer, UTC clock and explicit resource limits.
    pub fn new(authorizer: A, timer: T, wall_clock: W, limits: Limits) -> Self {
        Self {
            authorizer,
            timer: Arc::new(timer),
            wall_clock,
            connections: Connections::new(limits),
            limits,
        }
    }
}
impl<A: TargetAuthorizer, T: ExecutionTimer + 'static, W: WallClock> Publisher<Vec<u8>>
    for WebhookPublisher<A, T, W>
{
    type Receipt = WebhookPublishReceipt;
    async fn publish(
        &self,
        message: &MessageEnvelope<Vec<u8>>,
        deadline: OperationDeadline,
    ) -> PublishOutcome<Self::Receipt> {
        // Freeze the relative snapshot before any validation, hashing or host call.
        let Ok(cutoff) = Deadline::from_timeout(self.timer.as_ref(), deadline.timeout()) else {
            return definite(Kind::Permanent, Stage::Admission, Reason::InvalidMessage);
        };
        let mut sending = false;
        match within(self.timer.as_ref(), cutoff, |_| {
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
impl<A: TargetAuthorizer, T: ExecutionTimer + 'static, W: WallClock> WebhookPublisher<A, T, W> {
    /// Stop admission, release idle connections and wait for in-flight publishes and cleanup.
    /// A timeout or cancelled wait leaves admission closed; callers can wait again.
    pub async fn close(&self, deadline: Deadline) -> Result<(), CloseError> {
        self.connections.close(self.timer.as_ref(), deadline).await
    }

    async fn attempt(
        &self,
        message: &MessageEnvelope<Vec<u8>>,
        cutoff: Deadline,
        sending: &mut bool,
    ) -> PublishOutcome<WebhookPublishReceipt> {
        let Some(_permit) = self.connections.admit() else {
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
                OperationDeadline::from_cutoff(cutoff, self.timer.as_ref()),
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
        let reuse = self
            .limits
            .pool
            .map(|limits| (limits, Identity::of(&target)));
        let cached = reuse.as_ref().and_then(|(_, identity)| {
            self.connections
                .checkout(identity, &target, self.timer.as_ref())
        });
        let mut connection = match cached {
            Some(connection) => connection,
            None => {
                match Connection::connect(&target, self.limits, self.timer.as_ref(), cutoff).await {
                    Ok(connection) => connection,
                    Err(()) => {
                        let reason = if cutoff.is_expired(self.timer.now()) {
                            Reason::DeadlineElapsed
                        } else {
                            Reason::TransportUnavailable
                        };
                        return definite(Kind::Transient, Stage::Admission, reason);
                    }
                }
            }
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
        if OperationDeadline::from_cutoff(cutoff, self.timer.as_ref())
            .timeout()
            .is_zero()
        {
            return definite(Kind::Transient, Stage::Admission, Reason::DeadlineElapsed);
        }
        *sending = true;
        match connection.send(request).await {
            Ok((mut response, driver_live)) if response.status().is_success() => {
                let receipt = WebhookPublishReceipt {
                    status: response.status().as_u16(),
                };
                if let Some((limits, identity)) = reuse
                    && driver_live
                    && connection.finish_response(response.body_mut())
                {
                    self.connections
                        .put(connection, identity, limits, &self.timer);
                }
                PublishOutcome::Confirmed(receipt)
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
            .body(Full::new(Bytes::copy_from_slice(message.payload())))
            .map_err(|_| crate::Error::Binding)
    }
}
fn definite(kind: Kind, stage: Stage, reason: Reason) -> PublishOutcome<WebhookPublishReceipt> {
    PublishOutcome::DefinitelyNotPublished(PublishFailure::new(kind, stage, reason))
}
fn ambiguous(reason: Reason) -> PublishOutcome<WebhookPublishReceipt> {
    PublishOutcome::Ambiguous(PublishFailure::new(Kind::Transient, Stage::Confirm, reason))
}
