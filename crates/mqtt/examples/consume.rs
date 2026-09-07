//! Compileable external composition: callers supply session storage, TLS, clock and routing.
use rss_mqtt::{
    MqttConfig, MqttError, MqttOutboxPlan, MqttOutboxPublisher, MqttOutboxTopic, MqttReceiver,
    MqttResource,
};
use rss_request_context::Clock;
use rss_transactional_messaging::{
    message::{MessageRoute, MessagingDomain},
    transport::Publisher,
};
use std::sync::Arc;

pub fn compose(
    config: MqttConfig,
    clock: Arc<dyn Clock>,
    store: Arc<dyn rumqttc::SessionStore>,
) -> Result<
    (
        impl Publisher<Vec<u8>, Receipt = ()>,
        MqttReceiver,
        MqttResource,
    ),
    MqttError,
> {
    let (publisher, receiver, resource) = rss_mqtt::connect(config, clock, store)?;
    let plan = MqttOutboxPlan::new(
        MessagingDomain::parse("application").map_err(|_| MqttError::InvalidConfig)?,
        [(
            MessageRoute::parse("events").map_err(|_| MqttError::InvalidConfig)?,
            MqttOutboxTopic::new("application/events")?,
        )],
    )?;
    let outbox = MqttOutboxPublisher::new(publisher, plan);
    Ok((outbox, receiver, resource))
}
#[path = "support/logging.rs"]
mod logging;
fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Explicit application initialization; the library never replaces the process logger.
    tracing_subscriber::fmt()
        .with_env_filter(logging::filter())
        .try_init()?;
    Ok(())
}

/// Hand this source to the canonical ConsumerWorker with an Inbox, transaction and verifier.
#[cfg(feature = "consumer")]
pub fn compose_consumer(
    receiver: MqttReceiver,
    subscription: rss_transactional_messaging::message::SubscriptionIdentity,
) -> Result<rss_mqtt::MqttDeliverySource, MqttError> {
    rss_mqtt::MqttDeliverySource::new(receiver, subscription)
}
