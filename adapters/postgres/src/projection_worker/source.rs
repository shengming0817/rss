use consistency::{
    EngineError, EngineErrorKind, Lsn, PartitionSerialDelivery, ProjectionBatchLimit,
    ProjectionEventRecord, ProjectionEventSource,
};

use super::{ProjectionWorkerTarget, VerifiedPgProjectionWorkerStore};
use crate::projection_events::{
    ProjectionEventRow, ProjectionSourceReadError, decode_projection_rows,
    map_projection_source_sqlx_error,
};

/// Tenant-bound source on the dedicated function-only worker credential.
pub(crate) struct PgProjectionWorkerSource {
    store: VerifiedPgProjectionWorkerStore,
    target: ProjectionWorkerTarget,
    tenant: rss_request_context::TenantId,
}

impl PgProjectionWorkerSource {
    pub(super) fn new(
        store: &VerifiedPgProjectionWorkerStore,
        target: &ProjectionWorkerTarget,
        tenant: rss_request_context::TenantId,
    ) -> Self {
        Self {
            store: store.clone(),
            target: target.clone(),
            tenant,
        }
    }

    async fn read_batch(
        &self,
        after: Option<Lsn>,
        limit: ProjectionBatchLimit,
    ) -> Result<Vec<ProjectionEventRecord>, EngineError> {
        let after = after
            .map(|lsn| lsn.get())
            .map(i64::try_from)
            .transpose()
            .map_err(|_| EngineError::new(EngineErrorKind::Invariant))?
            .unwrap_or(0);
        let rows: Vec<ProjectionEventRow> = tokio::time::timeout(
            super::PROJECTION_WORKER_SHORT_OPERATION_TIMEOUT,
            async {
                let mut tx = self.store.0.pool.begin().await?;
                crate::cotx::set_local_tenant(&mut tx, self.tenant).await?;
                let rows = sqlx::query_as(
                    "SELECT id, event_id, domain, event_type, payload, contract_id, contract_version, \
                            schema_hash, metadata, partition_key, causation_id \
                     FROM public.rss_projection_worker_read_events(\
                         $1::uuid, $2, $3, $4, $5, $6, $7, $8::integer\
                     )",
                )
                .bind(self.tenant.to_string())
                .bind(self.target.projection_id())
                .bind(self.target.target_generation())
                .bind(self.target.definition_version())
                .bind(self.target.definition_schema_digest())
                .bind(self.target.input_generation())
                .bind(after)
                .bind(i64::from(limit.get()))
                .fetch_all(&mut *tx)
                .await?;
                tx.rollback().await?;
                Ok::<_, sqlx::Error>(rows)
            },
        )
        .await
        .map_err(|_| EngineError::new(EngineErrorKind::Transient))?
        .map_err(map_projection_source_sqlx_error)
        .map_err(ProjectionSourceReadError::into_engine)?;
        decode_projection_rows(rows)
    }
}

impl PartitionSerialDelivery for PgProjectionWorkerSource {}

impl ProjectionEventSource for PgProjectionWorkerSource {
    async fn read_from(
        &self,
        after: Option<Lsn>,
        limit: ProjectionBatchLimit,
    ) -> Result<Vec<ProjectionEventRecord>, EngineError> {
        self.read_batch(after, limit).await
    }
}
