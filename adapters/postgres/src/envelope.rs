//! Private durable encoding. Core owns canonical identity and fingerprint validation.
use crate::PgError;
use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_diag_context::CorrelationId;
use rss_request_context::TenantId;
use rss_transactional_messaging::message::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Envelope {
    id: String,
    tenant: String,
    occurred_at: i64,
    domain: String,
    route: String,
    contract: String,
    version: String,
    schema: String,
    correlation: Option<String>,
    partition: Option<String>,
    causation: Option<String>,
    attributes: BTreeMap<String, String>,
    trace: Option<String>,
    tenant_authority: Option<String>,
    payload: Vec<u8>,
}
impl Envelope {
    pub(crate) fn encode(message: &MessageEnvelope<Vec<u8>>) -> Result<String, PgError> {
        let m = message.metadata();
        serde_json::to_string(&Self {
            id: message.id().as_str().into(),
            tenant: m.tenant_id().to_string(),
            occurred_at: m.occurred_at().unix_seconds(),
            domain: m.domain().as_str().into(),
            route: m.route().as_str().into(),
            contract: m.contract().id().as_str().into(),
            version: m.contract().version().to_string(),
            schema: m.contract().schema_digest().as_str().into(),
            correlation: m.correlation().map(Into::into),
            partition: m.partition().map(|p| p.key().as_str().into()),
            causation: m.causation().map(|id| id.as_str().into()),
            attributes: m.attributes().map(|(k, v)| (k.into(), v.into())).collect(),
            trace: message.transport_context().trace().map(Into::into),
            tenant_authority: message
                .transport_context()
                .tenant_authority()
                .map(Into::into),
            payload: message.payload().clone(),
        })
        .map_err(|_| PgError::invariant())
    }
    pub(crate) fn decode(raw: &str) -> Result<MessageEnvelope<Vec<u8>>, PgError> {
        let value: Self = serde_json::from_str(raw).map_err(|_| PgError::invariant())?;
        let invalid = |_| PgError::invariant();
        let contract = ContractIdentity::new(
            ContractId::parse(&value.contract).map_err(invalid)?,
            ContractVersion::parse(&value.version).map_err(invalid)?,
            SchemaDigest::parse(&value.schema).map_err(invalid)?,
        );
        let required = AuthoredMessageMetadata::new(
            TenantId::parse(&value.tenant).map_err(|_| PgError::invariant())?,
            Timepoint::try_from(value.occurred_at).map_err(|_| PgError::invariant())?,
            MessagingDomain::parse(&value.domain).map_err(|_| PgError::invariant())?,
            MessageRoute::parse(&value.route).map_err(|_| PgError::invariant())?,
            contract,
        );
        let extensions = MessageMetadataExtensions::new(
            value
                .correlation
                .as_deref()
                .map(CorrelationId::parse)
                .transpose()
                .map_err(|_| PgError::invariant())?,
            value
                .partition
                .as_deref()
                .map(PartitionKey::parse)
                .transpose()
                .map_err(|_| PgError::invariant())?,
            value
                .causation
                .as_deref()
                .map(MessageId::parse)
                .transpose()
                .map_err(|_| PgError::invariant())?,
            value.attributes,
        );
        Ok(MessageEnvelope::new(
            MessageId::parse(&value.id).map_err(|_| PgError::invariant())?,
            MessageMetadata::new(required, extensions),
            value.payload,
        )
        .with_transport_context(TransportContext::new(value.trace, value.tenant_authority)))
    }
}
