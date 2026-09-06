//! Compileable external composition: callers supply session storage, TLS, clock and routing.
use rss_mqtt::{
    MqttConfig, MqttError, MqttOutboxPublisher, MqttReceiver, MqttResource, PublishRequest,
};
use rss_transactional_messaging::{message::MessageEnvelope, policy::Clock, transport::Publisher};
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
    let outbox = MqttOutboxPublisher::new(publisher, |envelope: &MessageEnvelope<Vec<u8>>| {
        Ok(
            PublishRequest::new("application/events", envelope.payload().clone())
                .map_err(|_| rss_mqtt::EncodeError)?
                .user_properties(vec![("message-id".into(), envelope.id().as_str().into())]),
        )
    });
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
