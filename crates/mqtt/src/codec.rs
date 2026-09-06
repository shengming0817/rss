//! Sole MQTT envelope representation; protocol delivery never authenticates these fields.
use crate::MqttError;
use rss_transactional_messaging::message::MessageEnvelope;

// Canonical wire names have one production owner; tests keep independent wire literals.
const MESSAGE_ID: &str = "messageId";
const TENANT_ID: &str = "tenantId";
const DOMAIN: &str = "domain";
const ROUTE: &str = "route";
const CONTRACT_ID: &str = "contractId";
const SCHEMA_VERSION: &str = "schemaVersion";
const SCHEMA_HASH: &str = "schemaHash";
const OCCURRED_AT: &str = "occurredAt";
const PARTITION_KEY: &str = "partitionKey";
const CORRELATION: &str = "correlation";
const CAUSATION_ID: &str = "causationId";
const TRACE: &str = "trace";
const TENANT_AUTHORITY: &str = "tenantAuthority";
const ATTRIBUTE_PREFIX: &str = "attribute.";

pub(crate) fn encode(
    message: &MessageEnvelope<Vec<u8>>,
    limit: usize,
) -> Result<Vec<(String, String)>, MqttError> {
    let mut size = message.payload().len();
    let mut fields = Vec::new();
    let mut emit = |key: &str, value: &str| -> Result<(), MqttError> {
        size = size
            .checked_add(key.len())
            .and_then(|n| n.checked_add(value.len()))
            .and_then(|n| n.checked_add(5))
            .ok_or(MqttError::InvalidMessage)?;
        if size > limit
            || key.len() > u16::MAX as usize
            || value.len() > u16::MAX as usize
            || key.contains('\0')
            || value.contains('\0')
        {
            return Err(MqttError::InvalidMessage);
        }
        fields.push((key.to_owned(), value.to_owned()));
        Ok(())
    };
    let m = message.metadata();
    emit(MESSAGE_ID, message.id().as_str())?;
    emit(TENANT_ID, &m.tenant_id().to_string())?;
    emit(DOMAIN, m.domain().as_str())?;
    emit(ROUTE, m.route().as_str())?;
    emit(CONTRACT_ID, m.contract().id().as_str())?;
    emit(SCHEMA_VERSION, &m.contract().version().to_string())?;
    emit(SCHEMA_HASH, m.contract().schema_digest().as_str())?;
    emit(OCCURRED_AT, &m.occurred_at().unix_seconds().to_string())?;
    if let Some(v) = m.partition() {
        emit(PARTITION_KEY, v.key().as_str())?;
    }
    if let Some(v) = m.correlation() {
        emit(CORRELATION, v)?;
    }
    if let Some(v) = m.causation() {
        emit(CAUSATION_ID, v.as_str())?;
    }
    if let Some(v) = message.transport_context().trace() {
        emit(TRACE, v)?;
    }
    if let Some(v) = message.transport_context().tenant_authority() {
        emit(TENANT_AUTHORITY, v)?;
    }
    for (key, value) in m.attributes() {
        if key.len() > u16::MAX as usize - ATTRIBUTE_PREFIX.len() {
            return Err(MqttError::InvalidMessage);
        }
        emit(&format!("{ATTRIBUTE_PREFIX}{key}"), value)?;
    }
    Ok(fields)
}

#[cfg(feature = "consumer")]
pub(crate) fn decode(
    publish: &rumqttc::mqttbytes::v5::Publish,
    subscription: &rss_transactional_messaging::message::SubscriptionIdentity,
) -> Result<
    MessageEnvelope<Vec<u8>>,
    rss_transactional_messaging::transaction::EnvelopeValidationFailure,
> {
    use rss_transactional_messaging::{
        message::*, transaction::EnvelopeValidationFailure as Failure,
    };
    use std::collections::BTreeMap;
    let mut headers = BTreeMap::new();
    for (k, v) in publish
        .properties
        .as_ref()
        .ok_or(Failure::MalformedMetadata)?
        .user_properties
        .iter()
    {
        if headers.insert(k.as_str(), v.as_str()).is_some() {
            return Err(Failure::MalformedMetadata);
        }
    }
    let mut required = |key| {
        headers
            .remove(key)
            .filter(|v| !v.is_empty())
            .ok_or(Failure::MalformedMetadata)
    };
    let id = MessageId::parse(required(MESSAGE_ID)?).map_err(|_| Failure::MalformedIdentity)?;
    let tenant = rss_request_context::TenantId::parse(required(TENANT_ID)?)
        .map_err(|_| Failure::MalformedIdentity)?;
    let occurred = required(OCCURRED_AT)?
        .parse::<i64>()
        .ok()
        .and_then(|v| rss_contract::Timepoint::try_from(v).ok())
        .ok_or(Failure::MalformedMetadata)?;
    let domain =
        MessagingDomain::parse(required(DOMAIN)?).map_err(|_| Failure::MalformedMetadata)?;
    let route = MessageRoute::parse(required(ROUTE)?).map_err(|_| Failure::MalformedMetadata)?;
    let contract = ContractIdentity::new(
        rss_contract::ContractId::parse(required(CONTRACT_ID)?)
            .map_err(|_| Failure::UnsupportedContract)?,
        rss_contract::ContractVersion::parse(required(SCHEMA_VERSION)?)
            .map_err(|_| Failure::UnsupportedContract)?,
        rss_contract::SchemaDigest::parse(required(SCHEMA_HASH)?)
            .map_err(|_| Failure::UnsupportedContract)?,
    );
    let correlation = headers
        .remove(CORRELATION)
        .map(rss_diag_context::CorrelationId::parse)
        .transpose()
        .map_err(|_| Failure::MalformedMetadata)?;
    let partition = headers
        .remove(PARTITION_KEY)
        .map(PartitionKey::parse)
        .transpose()
        .map_err(|_| Failure::MalformedMetadata)?;
    let causation = headers
        .remove(CAUSATION_ID)
        .map(MessageId::parse)
        .transpose()
        .map_err(|_| Failure::MalformedMetadata)?;
    let transport = TransportContext::new(
        headers.remove(TRACE).map(str::to_owned),
        headers.remove(TENANT_AUTHORITY).map(str::to_owned),
    );
    let mut attributes = BTreeMap::new();
    for (key, value) in headers {
        let key = key
            .strip_prefix(ATTRIBUTE_PREFIX)
            .ok_or(Failure::MalformedMetadata)?;
        attributes.insert(key.to_owned(), value.to_owned());
    }
    let message = MessageEnvelope::new(
        id,
        MessageMetadata::new(
            AuthoredMessageMetadata::new(tenant, occurred, domain, route, contract),
            MessageMetadataExtensions::new(correlation, partition, causation, attributes),
        ),
        publish.payload.to_vec(),
    )
    .with_transport_context(transport);
    if !subscription.accepts(&message) {
        return Err(Failure::UnsupportedContract);
    }
    Ok(message)
}

#[cfg(all(test, feature = "consumer"))]
mod tests {
    use super::*;
    use rss_transactional_messaging::message::*;
    fn message() -> anyhow::Result<MessageEnvelope<Vec<u8>>> {
        Ok(MessageEnvelope::new(
            MessageId::parse("identity")?,
            MessageMetadata::new(
                AuthoredMessageMetadata::new(
                    rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")?,
                    rss_contract::Timepoint::try_from(42_i64)?,
                    MessagingDomain::parse("domain")?,
                    MessageRoute::parse("created")?,
                    ContractIdentity::new(
                        rss_contract::ContractId::parse("domain.created")?,
                        rss_contract::ContractVersion::from_major(1)?,
                        rss_contract::SchemaDigest::parse(&format!("sha256:{}", "a".repeat(64)))?,
                    ),
                ),
                MessageMetadataExtensions::new(
                    Some(rss_diag_context::CorrelationId::parse("correlation")?),
                    Some(PartitionKey::parse("partition")?),
                    Some(MessageId::parse("parent")?),
                    std::collections::BTreeMap::from([
                        ("messageId".into(), "forged".into()),
                        ("custom".into(), "value".into()),
                    ]),
                ),
            ),
            b"durable bytes".to_vec(),
        )
        .with_transport_context(TransportContext::new(
            Some("trace".into()),
            Some("authority".into()),
        )))
    }
    #[test]
    fn canonical_writer_preserves_all_authored_bytes_and_namespaces_attributes()
    -> anyhow::Result<()> {
        let message = message()?;
        let m = message.metadata();
        let subscription =
            SubscriptionIdentity::new(m.domain().clone(), m.route().clone(), m.contract().clone());
        let plan = crate::MqttOutboxPlan::new(
            m.domain().clone(),
            [(
                m.route().clone(),
                crate::MqttOutboxTopic::new("wire/events")?,
            )],
        )?;
        let request = plan.encode(&message, 4096)?;
        assert_eq!(request.payload.as_ref(), message.payload());
        // Independent golden names detect a shared writer/reader spelling drift.
        assert_eq!(
            request
                .properties
                .user_properties
                .iter()
                .map(|(key, _)| key.as_str())
                .collect::<Vec<_>>(),
            [
                "messageId",
                "tenantId",
                "domain",
                "route",
                "contractId",
                "schemaVersion",
                "schemaHash",
                "occurredAt",
                "partitionKey",
                "correlation",
                "causationId",
                "trace",
                "tenantAuthority",
                "attribute.custom",
                "attribute.messageId"
            ]
        );
        assert!(
            request
                .properties
                .user_properties
                .contains(&("messageId".into(), "identity".into()))
        );
        assert!(
            request
                .properties
                .user_properties
                .contains(&("attribute.messageId".into(), "forged".into()))
        );
        let packet = rumqttc::mqttbytes::v5::Publish::new(
            request.topic,
            rumqttc::QoS::AtLeastOnce,
            request.payload,
            Some(request.properties),
        );
        let decoded =
            decode(&packet, &subscription).map_err(|_| anyhow::anyhow!("decode failed"))?;
        assert_eq!(decoded, message);
        assert_eq!(
            MessageFingerprint::of(&decoded),
            MessageFingerprint::of(&message)
        );
        assert!(plan.encode(&message, 8).is_err());
        let wrong_plan = crate::MqttOutboxPlan::new(
            MessagingDomain::parse("other")?,
            [(
                m.route().clone(),
                crate::MqttOutboxTopic::new("wire/events")?,
            )],
        )?;
        assert!(wrong_plan.encode(&message, 4096).is_err());
        Ok(())
    }
    #[test]
    fn decoder_rejects_missing_duplicate_malformed_and_wrong_subscription() -> anyhow::Result<()> {
        let message = message()?;
        let m = message.metadata();
        let subscription =
            SubscriptionIdentity::new(m.domain().clone(), m.route().clone(), m.contract().clone());
        let fields = encode(&message, 4096)?;
        for key in [
            "messageId",
            "tenantId",
            "domain",
            "route",
            "contractId",
            "schemaVersion",
            "schemaHash",
            "occurredAt",
        ] {
            for case in 0..3 {
                let mut altered = fields.clone();
                match case {
                    0 => altered.retain(|(k, _)| k != key),
                    1 => altered.push((key.into(), "duplicate".into())),
                    _ => {
                        for (k, v) in &mut altered {
                            if k == key {
                                v.clear();
                            }
                        }
                    }
                }
                let packet = rumqttc::mqttbytes::v5::Publish::new(
                    "wire/events",
                    rumqttc::QoS::AtLeastOnce,
                    message.payload().clone(),
                    Some(rumqttc::mqttbytes::v5::PublishProperties {
                        user_properties: altered,
                        ..Default::default()
                    }),
                );
                assert!(decode(&packet, &subscription).is_err(), "{key} case {case}");
            }
        }
        let packet = rumqttc::mqttbytes::v5::Publish::new(
            "wire/events",
            rumqttc::QoS::AtLeastOnce,
            message.payload().clone(),
            Some(rumqttc::mqttbytes::v5::PublishProperties {
                user_properties: fields,
                ..Default::default()
            }),
        );
        let wrong = SubscriptionIdentity::new(
            m.domain().clone(),
            MessageRoute::parse("other")?,
            m.contract().clone(),
        );
        assert!(decode(&packet, &wrong).is_err());
        Ok(())
    }
}
