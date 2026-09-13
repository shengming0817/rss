//! Private durable encoding. Core owns canonical identity and fingerprint validation.
use crate::PgError;
use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_diag_context::CorrelationId;
use rss_request_context::TenantId;
use rss_transactional_messaging::message::*;
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Deserialize)]
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
