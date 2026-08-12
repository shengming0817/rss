use consistency::Lsn;
use diport::{
    Checkpoint, CheckpointId, CheckpointOwner, CheckpointStoreError, CheckpointVersion,
    OwnerCheckpointStore, SaveOutcome,
};

use super::{ProjectionWorkerTarget, VerifiedPgProjectionWorkerStore};

/// Target-bound checkpoint carrier for the function-only projection worker credential.
pub(crate) struct PgProjectionWorkerCheckpointStore {
    store: VerifiedPgProjectionWorkerStore,
    target: ProjectionWorkerTarget,
    tenant: rss_request_context::TenantId,
    owner: CheckpointOwner,
    id: CheckpointId,
}

impl PgProjectionWorkerCheckpointStore {
    pub(super) fn new(
        store: &VerifiedPgProjectionWorkerStore,
        target: &ProjectionWorkerTarget,
        tenant: rss_request_context::TenantId,
    ) -> Self {
        let selector = target.selector(tenant);
        Self {
            store: store.clone(),
            target: target.clone(),
            tenant,
            owner: selector.shadow_checkpoint_owner(),
            id: selector.shadow_checkpoint_id(),
        }
    }

    fn ensure_target(
        &self,
        owner: &CheckpointOwner,
        id: &CheckpointId,
    ) -> Result<(), CheckpointStoreError> {
        if owner == &self.owner && id == &self.id {
            Ok(())
        } else {
            Err(CheckpointStoreError::new(std::io::Error::other(
                "projection checkpoint target does not match scoped worker capability",
            )))
        }
    }
}

impl OwnerCheckpointStore for PgProjectionWorkerCheckpointStore {
    async fn get_checkpoint(
        &self,
        owner: &CheckpointOwner,
        id: &CheckpointId,
    ) -> Result<Option<Checkpoint>, CheckpointStoreError> {
        self.ensure_target(owner, id)?;
        let row: Option<(i64, i64)> =
            tokio::time::timeout(super::PROJECTION_WORKER_SHORT_OPERATION_TIMEOUT, async {
                let mut tx = self.store.0.pool.begin().await?;
                crate::cotx::set_local_tenant(&mut tx, self.tenant).await?;
                let row = sqlx::query_as(
                    "SELECT offset_lsn, version FROM public.rss_projection_worker_get_checkpoint(\
                     $1::uuid, $2, $3, $4, $5, $6)",
                )
                .bind(self.tenant.to_string())
                .bind(self.target.projection_id())
                .bind(self.target.target_generation())
                .bind(self.target.definition_version())
                .bind(self.target.definition_schema_digest())
                .bind(self.target.input_generation())
                .fetch_optional(&mut *tx)
                .await?;
                tx.rollback().await?;
                Ok::<_, sqlx::Error>(row)
            })
            .await
            .map_err(CheckpointStoreError::new)?
            .map_err(CheckpointStoreError::new)?;

        row.map(|(offset_lsn, version)| {
            let offset = Lsn::new(u64::try_from(offset_lsn).map_err(CheckpointStoreError::new)?);
            let version =
                CheckpointVersion::new(u64::try_from(version).map_err(CheckpointStoreError::new)?);
            Ok(Checkpoint { offset, version })
        })
        .transpose()
    }

    async fn save_checkpoint(
        &self,
        owner: &CheckpointOwner,
        id: &CheckpointId,
        offset: Lsn,
        expected: CheckpointVersion,
    ) -> Result<SaveOutcome, CheckpointStoreError> {
        self.ensure_target(owner, id)?;
        let offset_lsn = i64::try_from(offset.get()).map_err(CheckpointStoreError::new)?;
        let expected = i64::try_from(expected.get()).map_err(CheckpointStoreError::new)?;
        let saved = tokio::time::timeout(super::PROJECTION_WORKER_SHORT_OPERATION_TIMEOUT, async {
            let mut tx = self.store.0.pool.begin().await?;
            crate::cotx::set_local_tenant(&mut tx, self.tenant).await?;
            let saved: bool = sqlx::query_scalar(
                "SELECT public.rss_projection_worker_save_checkpoint(\
                     $1::uuid, $2, $3, $4, $5, $6, $7, $8)",
            )
            .bind(self.tenant.to_string())
            .bind(self.target.projection_id())
            .bind(self.target.target_generation())
            .bind(self.target.definition_version())
            .bind(self.target.definition_schema_digest())
            .bind(self.target.input_generation())
            .bind(offset_lsn)
            .bind(expected)
            .fetch_one(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok::<_, sqlx::Error>(saved)
        })
        .await
        .map_err(CheckpointStoreError::new)?
        .map_err(CheckpointStoreError::new)?;
        Ok(if saved {
            SaveOutcome::Saved
        } else {
            SaveOutcome::StaleVersion
        })
    }

    async fn shutdown(&self) -> Result<(), CheckpointStoreError> {
        Ok(())
    }
}
