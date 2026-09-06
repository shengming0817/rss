// Compiled outside the workspace, without feature unification from other consumers.
use amqp::{AmqpPublisherResource, AmqpSubscriberResource, AmqpShutdownError};
use std::time::Duration;

pub async fn publisher(resource: AmqpPublisherResource) -> Result<(), AmqpShutdownError> {
    resource.shutdown(Duration::from_secs(1)).await
}
pub async fn subscriber(resource: AmqpSubscriberResource) -> Result<(), AmqpShutdownError> {
    resource.shutdown(Duration::from_secs(1)).await
}
#[cfg(feature = "bridge-probe")]
pub fn managed_resources() {
    fn managed<T: rss_runtime::ManagedResource>() {}
    managed::<AmqpPublisherResource>();
    managed::<AmqpSubscriberResource>();
}
#[cfg(feature = "reuse-probe")]
pub async fn reuse(resource: AmqpPublisherResource) {
    let _ = resource.shutdown(Duration::from_secs(1)).await;
    let _ = resource.shutdown(Duration::from_secs(1)).await;
}
#[cfg(feature = "handle-probe")]
pub fn handles_cannot_close() {
    fn managed<T: rss_runtime::ManagedResource>() {}
    managed::<amqp::AmqpPublisher>();
    managed::<amqp::AmqpSubscriber>();
}
