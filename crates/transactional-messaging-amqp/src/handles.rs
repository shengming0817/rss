//! One port handle and one move-only lifecycle owner per connection.
use crate::{
    AmqpConnectError, AmqpDeliveries, AmqpPrivateCa, AmqpPublisherEndpoint, AmqpSettlement,
    AmqpSubscriberEndpoint,
};
use crate::{publisher::PublisherInner, subscriber::SubscriberInner};
use rss_runtime::{ManagedResource, ShutdownError};
use rss_transactional_messaging::{
    error::MessagingError,
    message::{MessageEnvelope, SubscriptionIdentity},
    policy::OperationDeadline,
    transport::{DeliverySource, ManagedDeliveryStream, PublishOutcome, Publisher},
};
use std::sync::Arc;
use std::time::Duration;

/// Cloneable publishing capability. Its resource owns shutdown and transport replacement.
#[derive(Clone)]
pub struct AmqpPublisher(Arc<PublisherInner>);
/// Unique owner of one publisher connection and its recovery task.
#[must_use = "immediately register this owner with StartupTransaction"]
pub struct AmqpPublisherResource(Arc<PublisherInner>);
/// Cloneable delivery capability. Every delivery retains its original settlement channel.
#[derive(Clone)]
pub struct AmqpSubscriber(Arc<SubscriberInner>);
/// Unique owner of one subscriber connection and all its subscription tasks.
#[must_use = "immediately register this owner with StartupTransaction"]
pub struct AmqpSubscriberResource(Arc<SubscriberInner>);

impl AmqpPublisher {
    /// Connect using exclusive private CA trust and a bounded transport recovery budget.
    /// `recovery_timeout` must be an integral number of milliseconds from 1 ms through 24 hours.
    pub async fn connect(
        endpoint: &AmqpPublisherEndpoint,
        name: impl Into<String>,
        ca: &AmqpPrivateCa,
        recovery_timeout: Duration,
    ) -> Result<(Self, AmqpPublisherResource), AmqpConnectError> {
        let inner =
            PublisherInner::connect_with_private_ca(&endpoint.0, name, recovery_timeout, ca)
                .await?;
        Ok(Self::pair(inner))
    }
    fn pair(inner: PublisherInner) -> (Self, AmqpPublisherResource) {
        let inner = Arc::new(inner);
        (Self(Arc::clone(&inner)), AmqpPublisherResource(inner))
    }
    /// Connect a local test fixture using WebPKI or explicitly allowed loopback plaintext.
    /// `recovery_timeout` has the same integral-millisecond 1 ms through 24 hour range as `connect`.
    #[cfg(feature = "test-support")]
    pub async fn connect_for_test(
        endpoint: &AmqpPublisherEndpoint,
        name: impl Into<String>,
        recovery_timeout: Duration,
    ) -> Result<(Self, AmqpPublisherResource), AmqpConnectError> {
        Ok(Self::pair(
            PublisherInner::connect_with_webpki_for_test(&endpoint.0, name, recovery_timeout)
                .await?,
        ))
    }
    /// Inject one deterministic connection loss after the driver has accepted a publish.
    #[cfg(feature = "test-support")]
    pub fn inject_post_send_connection_close_once(&self) {
        self.0.inject_post_send_connection_close_once();
    }
    /// Pause one publication after send so tests can cancel the actual provider future.
    #[cfg(feature = "test-support")]
    pub fn pause_next_confirmation_for_test(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        self.0.pause_confirmation()
    }
    /// Read the current transport generation without admitting another publication.
    #[cfg(feature = "test-support")]
    pub fn transport_generation_for_test(&self) -> Option<u64> {
        self.0.generation()
    }
    /// Await bounded transport replacement without exposing raw provider handles.
    #[cfg(feature = "test-support")]
    pub async fn wait_until_publish_ready_for_test(&self) -> bool {
        self.0.wait_until_publish_ready_for_test().await
    }
}
impl Publisher<Vec<u8>> for AmqpPublisher {
    type Receipt = ();
    async fn publish(
        &self,
        message: &MessageEnvelope<Vec<u8>>,
        deadline: OperationDeadline,
    ) -> PublishOutcome<()> {
        self.0.publish(message, deadline).await
    }
}
impl ManagedResource for AmqpPublisherResource {
    fn name(&self) -> &str {
        self.0.name()
    }
    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.0.shutdown().await
    }
}
impl Drop for AmqpPublisherResource {
    fn drop(&mut self) {
        self.0.request_shutdown();
    }
}
impl AmqpSubscriber {
    /// Connect using the subscriber role credential and exclusive private CA trust.
    /// Recovery uses one integral-millisecond budget from 1 ms through 24 hours per replacement.
    pub async fn connect(
        endpoint: &AmqpSubscriberEndpoint,
        name: impl Into<String>,
        ca: &AmqpPrivateCa,
        recovery_timeout: Duration,
    ) -> Result<(Self, AmqpSubscriberResource), AmqpConnectError> {
        Ok(Self::pair(
            SubscriberInner::connect_with_private_ca(&endpoint.0, name, ca, recovery_timeout)
                .await?,
        ))
    }
    fn pair(inner: SubscriberInner) -> (Self, AmqpSubscriberResource) {
        let inner = Arc::new(inner);
        (Self(Arc::clone(&inner)), AmqpSubscriberResource(inner))
    }
    /// Connect a local test fixture; the same 1 ms through 24 hour recovery budget applies.
    #[cfg(feature = "test-support")]
    pub async fn connect_for_test(
        endpoint: &AmqpSubscriberEndpoint,
        name: impl Into<String>,
        recovery_timeout: Duration,
    ) -> Result<(Self, AmqpSubscriberResource), AmqpConnectError> {
        Ok(Self::pair(
            SubscriberInner::connect_with_webpki_for_test(&endpoint.0, name, recovery_timeout)
                .await?,
        ))
    }
    /// Pause one subscription after broker setup and before lifecycle registration.
    #[cfg(feature = "test-support")]
    pub fn pause_next_subscription_registration_for_test(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        self.0.pause_registration()
    }
    /// Pause a replacement connection before installation to exercise cancellation and shutdown.
    #[cfg(feature = "test-support")]
    pub fn pause_next_recovery_installation_for_test(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        self.0.pause_recovery()
    }
}
impl DeliverySource<Vec<u8>> for AmqpSubscriber {
    type Settlement = AmqpSettlement;
    type Deliveries = AmqpDeliveries;
    async fn deliveries(
        &self,
        subscription: &SubscriptionIdentity,
    ) -> Result<ManagedDeliveryStream<Self::Deliveries>, MessagingError> {
        self.0.deliveries(subscription).await
    }
}
impl ManagedResource for AmqpSubscriberResource {
    fn name(&self) -> &str {
        self.0.name()
    }
    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.0.shutdown().await
    }
}
impl Drop for AmqpSubscriberResource {
    fn drop(&mut self) {
        self.0.request_shutdown();
    }
}
