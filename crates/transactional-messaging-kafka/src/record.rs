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
/// Header names form this adapter's wire representation; attributes cannot shadow them.
fn headers(message: &MessageEnvelope<Vec<u8>>, mut emit: impl FnMut(&str, &str)) {
    let m = message.metadata();
    emit("messageId", message.id().as_str());
    emit("tenantId", &m.tenant_id().to_string());
    emit("domain", m.domain().as_str());
    emit("route", m.route().as_str());
    emit("contractId", m.contract().id().as_str());
    emit("schemaVersion", &m.contract().version().to_string());
    emit("schemaHash", m.contract().schema_digest().as_str());
    emit("occurredAt", &m.occurred_at().unix_seconds().to_string());
    if let Some(p) = m.partition() {
        emit("partitionKey", p.key().as_str());
    }
    if let Some(v) = m.correlation() {
        emit("correlation", v);
    }
    if let Some(v) = m.causation() {
        emit("causationId", v.as_str());
    }
    if let Some(v) = message.transport_context().trace() {
        emit("trace", v);
    }
    if let Some(v) = message.transport_context().tenant_authority() {
        emit("tenantAuthority", v);
    }
    // Attributes are visited separately, avoiding an unbounded format! allocation during preflight.
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
        let mut valid = size <= config.limits.record_bytes;
        let mut add = |name: &str, value: &str| {
            // Include a conservative fixed per-header framing/allocation charge, even for empty values.
            match size
                .checked_add(name.len())
                .and_then(|n| n.checked_add(value.len()))
                .and_then(|n| n.checked_add(64))
            {
                Some(n) if n <= config.limits.record_bytes => size = n,
                _ => valid = false,
            }
        };
        headers(message, &mut add);
        if !valid {
            return None;
        }
        for (k, v) in message.metadata().attributes() {
            if k.contains('\0') {
                return None;
            }
            size = size
                .checked_add(k.len())?
                .checked_add(v.len())?
                .checked_add(128 + "attribute.".len())?;
            if size > config.limits.record_bytes {
                return None;
            }
        }
        let mut pairs = Vec::new();
        headers(message, |k, v| pairs.push((k.to_owned(), v.to_owned())));
        pairs.extend(
            message
                .metadata()
                .attributes()
                .map(|(k, v)| (format!("attribute.{k}"), v.to_owned())),
        );
        let mut wire = OwnedHeaders::new_with_capacity(pairs.len());
        for (k, v) in &pairs {
            wire = wire.insert(Header {
                key: k,
                value: Some(v.as_str()),
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
