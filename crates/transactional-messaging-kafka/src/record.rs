//! Sole envelope-to-Kafka writer. Authored bytes are checked before any record copy.
use crate::config::PublishPlan;
use rdkafka::message::{Header, OwnedHeaders};
use rss_transactional_messaging::message::MessageEnvelope;

pub(crate) struct Record {
    pub(crate) topic: String,
    pub(crate) key: Option<String>,
    pub(crate) payload: Vec<u8>,
    pub(crate) headers: OwnedHeaders,
}
impl Record {
    pub(crate) fn encode(message: &MessageEnvelope<Vec<u8>>, config: &PublishPlan) -> Option<Self> {
        if message.metadata().domain() != &config.domain {
            return None;
        }
        let topic = config.routes.get(message.metadata().route())?;
        let key = message.metadata().partition().map(|p| p.key().as_str());
        let mut size = topic
            .len()
            .checked_add(message.payload().len())?
            .checked_add(key.map_or(0, str::len))?;
        if size > config.limits.record_bytes {
            return None;
        }
        let m = message.metadata();
        let context = message.transport_context();
        let tenant = m.tenant_id().to_string();
        let version = m.contract().version().to_string();
        let occurred = m.occurred_at().unix_seconds().to_string();
        let required = [
            ("messageId", message.id().as_str()),
            ("tenantId", tenant.as_str()),
            ("domain", m.domain().as_str()),
            ("route", m.route().as_str()),
            ("contractId", m.contract().id().as_str()),
            ("schemaVersion", version.as_str()),
            ("schemaHash", m.contract().schema_digest().as_str()),
            ("occurredAt", occurred.as_str()),
        ];
        let optional = [
            key.map(|v| ("partitionKey", v)),
            m.correlation().map(|v| ("correlation", v)),
            m.causation().map(|v| ("causationId", v.as_str())),
            context.trace().map(|v| ("trace", v)),
            context.tenant_authority().map(|v| ("tenantAuthority", v)),
        ];
        let headers = required.into_iter().chain(optional.into_iter().flatten());
        let mut count = 0;
        for (name, value) in headers.clone() {
            size = size
                .checked_add(name.len())?
                .checked_add(value.len())?
                .checked_add(64)?;
            if size > config.limits.record_bytes {
                return None;
            }
            count += 1;
        }
        for (name, value) in m.attributes() {
            size = size
                .checked_add(name.len())?
                .checked_add(value.len())?
                .checked_add(128 + "attribute.".len())?;
            if size > config.limits.record_bytes || name.contains('\0') {
                return None;
            }
            count += 1;
        }
        let mut wire = OwnedHeaders::new_with_capacity(count);
        for (key, value) in headers {
            wire = wire.insert(Header {
                key,
                value: Some(value),
            });
        }
        for (name, value) in m.attributes() {
            wire = wire.insert(Header {
                key: &format!("attribute.{name}"),
                value: Some(value),
            });
        }
        Some(Self {
            topic: topic.clone(),
            key: key.map(str::to_owned),
            payload: message.payload().clone(),
            headers: wire,
        })
    }
}
