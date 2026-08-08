use diport::{DeadLetterRecord, DeadLetterSource, DeadLetterStore, DeadLetterStoreError};

use super::{ProjectionWorkerTarget, VerifiedPgProjectionWorkerStore};
use crate::dead_letter::metadata_json;
use crate::dead_letter_payload::{DlxPayloadContext, DlxPayloadProtector};

/// Target-bound DLQ carrier for the function-only projection worker credential.
pub(crate) struct PgProjectionWorkerDeadLetterStore {
    store: VerifiedPgProjectionWorkerStore,
    target: ProjectionWorkerTarget,
    tenant: vocab::TenantId,
    owner: Box<str>,
    checkpoint_id: Box<str>,
    payload_protector: DlxPayloadProtector,
}

impl PgProjectionWorkerDeadLetterStore {
    pub(super) fn new(
        store: &VerifiedPgProjectionWorkerStore,
        target: &ProjectionWorkerTarget,
        tenant: vocab::TenantId,
        payload_protector: DlxPayloadProtector,
    ) -> Self {
        let selector = target.selector(tenant);
        Self {
            store: store.clone(),
            target: target.clone(),
            tenant,
            owner: selector.shadow_checkpoint_owner().as_str().into(),
            checkpoint_id: selector.shadow_checkpoint_id().as_str().into(),
            payload_protector,
        }
    }

    fn ensure_target(&self, record: &DeadLetterRecord) -> Result<(), DeadLetterStoreError> {
        if record.source() == DeadLetterSource::Projection
            && record.tenant() == self.tenant
            && record.consumer_domain() == Some(self.owner.as_ref())
            && record.consumer_group() == Some(self.checkpoint_id.as_ref())
        {
            Ok(())
        } else {
            Err(DeadLetterStoreError::new(std::io::Error::other(
                "projection dead letter does not match target-bound worker capability",
            )))
        }
    }
}

impl DeadLetterStore for PgProjectionWorkerDeadLetterStore {
    async fn write_dead_letter(
        &self,
        record: DeadLetterRecord,
    ) -> Result<(), DeadLetterStoreError> {
        self.ensure_target(&record)?;
        tokio::time::timeout(super::PROJECTION_WORKER_SHORT_OPERATION_TIMEOUT, async {
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
                    record.original_payload().as_bytes(),
                    &metadata,
                )
                .await
                .map_err(DeadLetterStoreError::new)?;
            let mut tx = self
                .store
                .0
                .pool
                .begin()
                .await
                .map_err(DeadLetterStoreError::new)?;
            crate::cotx::set_local_tenant(&mut tx, record.tenant())
                .await
                .map_err(DeadLetterStoreError::new)?;
            sqlx::query(
                r#"
                    SELECT public.rss_projection_worker_insert_dead_letter(
                        $1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                        $13::jsonb, $14, $15, $16, $17, $18, $19, $20
                    )
                    "#,
            )
            .bind(record.tenant().to_string())
            .bind(self.target.projection_id())
            .bind(self.target.target_generation())
            .bind(self.target.definition_version())
            .bind(self.target.definition_schema_digest())
            .bind(self.target.input_generation())
            .bind(record.message_id())
            .bind(record.producer_domain())
            .bind(record.consumer_domain())
            .bind(record.contract_id())
            .bind(record.topic())
            .bind(record.consumer_group())
            .bind(sqlx::types::Json(protected.replay_capsule()))
            .bind(protected.key_ref())
            .bind(protected.payload_len())
            .bind(crate::dead_letter_payload::DLX_REPLAY_CAPSULE_ENCODING)
            .bind(protected.metadata_digest())
            .bind(record.error_summary())
            .bind(i32::try_from(record.num_attempts()).unwrap_or(i32::MAX))
            .bind(record.source().as_str())
            .execute(&mut *tx)
            .await
            .map_err(DeadLetterStoreError::new)?;
            tx.commit().await.map_err(DeadLetterStoreError::new)
        })
        .await
        .map_err(DeadLetterStoreError::new)?
    }

    async fn shutdown(&self) -> Result<(), DeadLetterStoreError> {
        Ok(())
    }
}
