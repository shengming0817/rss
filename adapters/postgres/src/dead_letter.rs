//! PostgreSQL HOT dead-letter persistence adapter.
//!
//! [`PgDeadLetterStore`] implements [`diport::DeadLetterStore`]. HOT rows are immutable: this
//! serving capability can only insert through tenant-scoped transactions. Cross-tenant archive and
//! purge live exclusively in the dedicated `rss_dlx_archiver` repository.
//!
//! `replay_capsule` contains only ciphertext. Payload, persisted replay metadata, and provenance
//! are serialized once and encrypted with v3 AAD; no v1/v2 decoder or plaintext fallback exists.

#[cfg(all(test, feature = "integration"))]
use crate::PgStore;
use crate::cotx::{MaintenanceWriteLane, ServingWriteLane, TenantDb, infra_tenant_scope};
use crate::dead_letter_payload::{DlxPayloadContext, DlxPayloadProtector};
use crate::pool::{VerifiedPgMaintenanceStore, VerifiedPgWriteStore};
use diport::{
    DeadLetterRecord, DeadLetterStore, DeadLetterStoreError, EnvelopeMetadata, KEY_TENANT_AUTHORITY,
};

/// Tenant-scoped HOT dead-letter writer.
pub struct PgDeadLetterStore {
    lane: DeadLetterLane,
    payload_protector: DlxPayloadProtector,
}

enum DeadLetterLane {
    Serving(TenantDb<ServingWriteLane>),
    Maintenance(TenantDb<MaintenanceWriteLane>),
}

#[cfg(all(test, feature = "integration"))]
impl PgStore {
    pub(crate) fn dead_letter(&self, payload_protector: DlxPayloadProtector) -> PgDeadLetterStore {
        PgDeadLetterStore {
            lane: DeadLetterLane::Serving(TenantDb::<ServingWriteLane>::from_unverified_for_test(
                self,
            )),
            payload_protector,
        }
    }
}

impl PgDeadLetterStore {
    pub(crate) fn new(
        writer: &VerifiedPgWriteStore,
        payload_protector: DlxPayloadProtector,
    ) -> Self {
        Self {
            lane: DeadLetterLane::Serving(TenantDb::<ServingWriteLane>::new(writer)),
            payload_protector,
        }
    }

    pub(crate) fn new_maintenance(
        store: &VerifiedPgMaintenanceStore,
        payload_protector: DlxPayloadProtector,
    ) -> Self {
        Self {
            lane: DeadLetterLane::Maintenance(TenantDb::<MaintenanceWriteLane>::new_maintenance(
                store,
            )),
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

        match &self.lane {
            DeadLetterLane::Serving(pool) => {
                pool.dlq_write(
                    infra_tenant_scope(record.tenant()),
                    move |mut tx| {
                        Box::pin(async move {
                            tx.dead_letter_insert_projection(&record, &protected)
                                .await
                                .map_err(DeadLetterStoreError::new)
                        })
                    },
                    DeadLetterStoreError::new,
                )
                .await
            }
            DeadLetterLane::Maintenance(pool) => {
                pool.dlq_write(
                    infra_tenant_scope(record.tenant()),
                    move |mut tx| {
                        Box::pin(async move {
                            tx.dead_letter_insert_projection(&record, &protected)
                                .await
                                .map_err(DeadLetterStoreError::new)
                        })
                    },
                    DeadLetterStoreError::new,
                )
                .await
            }
        }
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
