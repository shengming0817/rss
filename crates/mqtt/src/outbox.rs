//! Immutable routing and sole Outbox writer. Payload encoding precedes durable append.
//! ref: rss Kafka record writer; rumqtt client.rs@aa7a694f9b76b17d4c31200cf73d79616acae9b3.
use crate::{MqttError, MqttPublisher, PublishRequest, codec, outcome};
use rss_transactional_messaging::{
    message::{MessageEnvelope, MessageRoute, MessagingDomain},
    policy::OperationDeadline,
    transport::{
        PublishFailureKind, PublishFailureReason, PublishFailureStage, PublishOutcome, Publisher,
    },
};
use std::collections::HashMap;

/// Fixed MQTT destination and protocol options; no payload or metadata override capability.
#[derive(Clone)]
pub struct MqttOutboxTopic {
    topic: String,
    retain: bool,
    expiry: Option<u32>,
}
impl MqttOutboxTopic {
    /// Validate one concrete publication topic (wildcards are not destinations).
    pub fn new(topic: impl Into<String>) -> Result<Self, MqttError> {
        let request = PublishRequest::new(topic, Vec::new())?;
        Ok(Self {
            topic: request.topic,
            retain: false,
            expiry: None,
        })
    }
    /// Select retained publication for this fixed route.
    #[must_use]
    pub const fn retain(mut self, value: bool) -> Self {
        self.retain = value;
        self
    }
    /// Fixed MQTT message expiry interval; this does not reset the Outbox delivery budget.
    #[must_use]
    pub const fn message_expiry_interval(mut self, seconds: u32) -> Self {
        self.expiry = Some(seconds);
        self
    }
}

/// Immutable domain/route binding. Changing it across deployments is an explicit routing migration.
pub struct MqttOutboxPlan {
    domain: MessagingDomain,
    routes: HashMap<MessageRoute, MqttOutboxTopic>,
}
impl MqttOutboxPlan {
    /// Reject empty routing and duplicate logical routes, rather than silently overriding them.
    pub fn new(
        domain: MessagingDomain,
        routes: impl IntoIterator<Item = (MessageRoute, MqttOutboxTopic)>,
    ) -> Result<Self, MqttError> {
        let mut entries = HashMap::new();
        for (route, topic) in routes {
            if entries.insert(route, topic).is_some() {
                return Err(MqttError::InvalidConfig);
            }
        }
        if entries.is_empty() {
            return Err(MqttError::InvalidConfig);
        }
        Ok(Self {
            domain,
            routes: entries,
        })
    }
    pub(crate) fn encode(
        &self,
        message: &MessageEnvelope<Vec<u8>>,
        limit: u32,
    ) -> Result<PublishRequest, MqttError> {
        if message.metadata().domain() != &self.domain {
            return Err(MqttError::InvalidMessage);
        }
        let topic = self
            .routes
            .get(message.metadata().route())
            .ok_or(MqttError::InvalidMessage)?;
        #[cfg(test)]
        crate::handles::tests::preflight();
        // Bound authored input before copying it; the publisher validates final MQTT framing.
        let properties = codec::encode(message, limit as usize)?;
        let mut request = PublishRequest::new(topic.topic.clone(), message.payload().clone())?
            .retain(topic.retain);
        request.properties.user_properties = properties;
        request.properties.message_expiry_interval = topic.expiry;
        Ok(request)
    }
}

/// RSS Outbox publication: immutable authored bytes and adapter-owned canonical metadata.
/// INVARIANT: OUTBOX-METADATA-FUNNEL-01. No callback can replace identity, metadata or payload.
///
/// ```compile_fail
/// use rss_mqtt::{MqttOutboxPublisher, MqttPublisher, PublishRequest};
/// fn bypass(publisher: MqttPublisher) {
///     MqttOutboxPublisher::new(publisher, |_| Ok(PublishRequest::new("events", vec![]).unwrap()));
/// }
/// ```
pub struct MqttOutboxPublisher {
    publisher: MqttPublisher,
    plan: MqttOutboxPlan,
}
impl MqttOutboxPublisher {
    /// Consume the immutable plan; encoding must have happened before the Outbox append.
    pub const fn new(publisher: MqttPublisher, plan: MqttOutboxPlan) -> Self {
        Self { publisher, plan }
    }
}
impl Publisher<Vec<u8>> for MqttOutboxPublisher {
    type Receipt = ();
    async fn publish(
        &self,
        message: &MessageEnvelope<Vec<u8>>,
        deadline: OperationDeadline,
    ) -> PublishOutcome<()> {
        let Ok(cutoff) = self.publisher.shared.deadline(deadline.timeout()) else {
            return outcome::definite(
                PublishFailureKind::Permanent,
                PublishFailureStage::Admission,
                PublishFailureReason::InvalidMessage,
            );
        };
        match self.plan.encode(message, self.publisher.packet_bytes) {
            Ok(request) => self.publisher.publish_until(request, cutoff).await,
            Err(_) => outcome::definite(
                PublishFailureKind::Permanent,
                PublishFailureStage::Encode,
                PublishFailureReason::InvalidMessage,
            ),
        }
    }
}
