//! Caller-owned deterministic message for the public examples.
use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_request_context::TenantId;
use rss_transactional_messaging::{
    message::{
        AuthoredMessageMetadata, ContractIdentity, MessageEnvelope, MessageId, MessageMetadata,
        MessageMetadataExtensions, MessageRoute, MessagingDomain,
    },
    outbox::PendingMessage,
};
pub fn message(tenant: TenantId, id: &str) -> anyhow::Result<PendingMessage<Vec<u8>>> {
    Ok(PendingMessage::new(MessageEnvelope::new(
        MessageId::parse(id)?,
        MessageMetadata::new(
            AuthoredMessageMetadata::new(
                tenant,
                Timepoint::try_from(1_i64)?,
                MessagingDomain::parse("writer-example")?,
                MessageRoute::parse("created")?,
                ContractIdentity::new(
                    ContractId::parse("example.created")?,
                    ContractVersion::from_major(1)?,
                    SchemaDigest::parse(&format!("sha256:{}", "a".repeat(64)))?,
                ),
            ),
            MessageMetadataExtensions::default(),
        ),
        vec![1, 2, 3],
    )))
}
