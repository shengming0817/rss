//! PostgreSQL HOT dead-letter persistence adapter.
//!
//! [`PgDeadLetterStore`] implements [`diport::DeadLetterStore`]. HOT rows are immutable: this
//! serving capability can only insert through tenant-scoped transactions. Cross-tenant archive and
//! purge live exclusively in the dedicated `rss_dlx_archiver` repository.
//!
//! `replay_capsule` contains only ciphertext. Payload, persisted replay metadata, and provenance
//! are serialized once and encrypted with v3 AAD; no v1/v2 decoder or plaintext fallback exists.

use diport::{
    DeadLetterRecord, DeadLetterStore, DeadLetterStoreError, EnvelopeMetadata, KEY_TENANT_AUTHORITY,
};

use crate::PgStore;
use crate::cotx::{PgTenantPool, infra_tenant_scope};
use crate::dead_letter_payload::{
    DLX_REPLAY_CAPSULE_ENCODING, DlxPayloadContext, DlxPayloadProtector,
};

/// Tenant-scoped HOT dead-letter writer.
pub struct PgDeadLetterStore {
    tenant_pool: PgTenantPool,
    payload_protector: DlxPayloadProtector,
}

impl PgStore {
    pub(crate) fn dead_letter(&self, payload_protector: DlxPayloadProtector) -> PgDeadLetterStore {
        PgDeadLetterStore {
            tenant_pool: PgTenantPool::new(self),
            payload_protector,
        }
    }
}

impl DeadLetterStore for PgDeadLetterStore {
    async fn write_dead_letter(
        &self,
        record: DeadLetterRecord,
    ) -> Result<(), DeadLetterStoreError> {
        let source_kind = record.source().as_str();
        let metadata = metadata_json(record.metadata());
        let protected = self
            .payload_protector
            .encrypt(
                DlxPayloadContext::new(
                    record.tenant(),
                    source_kind,
                    record.producer_domain(),
                    record.consumer_domain(),
                    record.contract_id(),
                    record.topic(),
                    record.consumer_group(),
                    record.message_id(),
                ),
                record.original_payload(),
                &metadata,
            )
            .await
            .map_err(DeadLetterStoreError::new)?;

        self.tenant_pool
            .write(
                infra_tenant_scope(record.tenant()),
                move |conn| {
                    Box::pin(async move {
                        sqlx::query(
                            r#"
                            INSERT INTO dead_letter
                                (tenant_id, message_id, producer_domain, consumer_domain,
                                 contract_id, topic, consumer_group,
                                 replay_capsule, replay_capsule_key_ref, payload_len,
                                 replay_capsule_encoding, metadata_digest,
                                 error_summary, num_attempts, source_kind)
                            VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
                            ON CONFLICT (tenant_id, source_kind, consumer_group, message_id)
                            WHERE source_kind = 'projection'
                            DO NOTHING
                            "#,
                        )
                        .bind(record.tenant().to_string())
                        .bind(record.message_id())
                        .bind(record.producer_domain())
                        .bind(record.consumer_domain())
                        .bind(record.contract_id())
                        .bind(record.topic())
                        .bind(record.consumer_group())
                        .bind(sqlx::types::Json(protected.replay_capsule()))
                        .bind(protected.key_ref())
                        .bind(protected.payload_len())
                        .bind(DLX_REPLAY_CAPSULE_ENCODING)
                        .bind(protected.metadata_digest())
                        .bind(record.error_summary())
                        .bind(i32::try_from(record.num_attempts()).unwrap_or(i32::MAX))
                        .bind(source_kind)
                        .execute(conn.conn())
                        .await
                        .map_err(DeadLetterStoreError::new)
                        .map(|_| ())
                    })
                },
                DeadLetterStoreError::new,
            )
            .await
    }

    async fn shutdown(&self) -> Result<(), DeadLetterStoreError> {
        Ok(())
    }
}

/// Envelope metadata → capsule JSON object. Tenant authority is intentionally discarded.
pub(crate) fn metadata_json(metadata: &EnvelopeMetadata) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for (key, value) in metadata.iter_persisted_metadata() {
        if key == KEY_TENANT_AUTHORITY {
            continue;
        }
        map.insert(
            key.to_string(),
            serde_json::Value::String(value.to_string()),
        );
    }
    serde_json::Value::Object(map)
}

#[cfg(test)]
mod tests {
    use core::marker::PhantomData;

    use diport::{DeadLetterStore, EnvelopeMetadata, KEY_CORRELATION, KEY_TENANT_AUTHORITY};

    use super::metadata_json;

    #[test]
    fn metadata_json_drops_tenant_authority_token() {
        let mut metadata = EnvelopeMetadata::empty();
        metadata.insert_wire_pair(KEY_TENANT_AUTHORITY, "SECRET_AUTHORITY");
        metadata.insert_wire_pair(KEY_CORRELATION, "corr-1");
        let rendered = metadata_json(&metadata);

        assert_eq!(rendered[KEY_CORRELATION], "corr-1");
        assert!(rendered.get(KEY_TENANT_AUTHORITY).is_none());
    }

    #[test]
    fn pg_dead_letter_store_is_only_a_hot_writer() {
        fn assert_dead_letter_store<T: DeadLetterStore>(_: PhantomData<T>) {}
        assert_dead_letter_store(PhantomData::<super::PgDeadLetterStore>);
    }
}
