//! Settings-owned PostgreSQL projection worker capability slice.
//!
//! The parent module is selected atomically by `domain-settings`; core graphs never compile the
//! worker target, provider capability, checkpoint, dead-letter, or source carriers.

use std::sync::Arc;

use diport::ManagedResource as _;

use crate::PgStore;
use crate::cotx::settings_projection::ProjectionWorkerBoundPool;
use crate::pool::ProjectionWorkerMint;

mod checkpoint;
mod dead_letter;
mod runtime;
mod source;

pub(crate) use checkpoint::PgProjectionWorkerCheckpointStore;
pub(crate) use dead_letter::PgProjectionWorkerDeadLetterStore;
#[cfg(test)]
pub(crate) use runtime::PROJECTION_WORKER_OBSERVE_TENANT_SQL;
pub use runtime::PgProjectionWorkerDeps;
pub(crate) use runtime::{
    PROJECTION_WORKER_APPLY_TIMEOUT, PROJECTION_WORKER_SHORT_OPERATION_TIMEOUT,
};
pub(crate) use source::PgProjectionWorkerSource;

#[cfg(all(test, feature = "integration"))]
pub(crate) fn checkpoint_for_integration(
    store: &VerifiedPgProjectionWorkerStore,
    target: &ProjectionWorkerTarget,
    tenant: rss_request_context::TenantId,
) -> PgProjectionWorkerCheckpointStore {
    PgProjectionWorkerCheckpointStore::new(store, target, tenant)
}

#[cfg(all(test, feature = "integration"))]
pub(crate) fn dead_letter_for_integration(
    store: &VerifiedPgProjectionWorkerStore,
    target: &ProjectionWorkerTarget,
    tenant: rss_request_context::TenantId,
    payload_protector: crate::dead_letter_payload::DlxPayloadProtector,
) -> PgProjectionWorkerDeadLetterStore {
    PgProjectionWorkerDeadLetterStore::new(store, target, tenant, payload_protector)
}

/// Opaque worker store minted only by the exact capability verification gate.
#[derive(Clone)]
pub(crate) struct VerifiedPgProjectionWorkerStore(Arc<PgStore>);

impl VerifiedPgProjectionWorkerStore {
    pub(crate) fn mint(store: Arc<PgStore>, _mint: ProjectionWorkerMint) -> Self {
        Self(store)
    }

    pub(crate) fn bind_pool(&self, target: &ProjectionWorkerTarget) -> ProjectionWorkerBoundPool {
        ProjectionWorkerBoundPool::mint(
            self.0.pool.clone(),
            target.clone(),
            ProjectionWorkerApplyMint(()),
        )
    }

    pub(crate) async fn shutdown(&self) -> Result<(), diport::ShutdownError> {
        let pool = crate::PgStoreGuard::new_runtime_named(
            Arc::clone(&self.0),
            "postgres-settings-projection-worker",
        );
        pool.shutdown().await
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn pool_for_integration(&self) -> &sqlx::PgPool {
        &self.0.pool
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) async fn shutdown_for_integration(&self) -> Result<(), diport::ShutdownError> {
        self.0.pool.close().await;
        Ok(())
    }
}

/// Unforgeable proof for the target-bound worker apply lane handoff.
pub(crate) struct ProjectionWorkerApplyMint(());

/// Exact plan-bound worker target shared by source, checkpoint, DLQ, and apply constructors.
#[derive(Clone)]
pub(crate) struct ProjectionWorkerTarget {
    execution: eventexec::ProjectionBackgroundExecutionIssuer,
    projection: eventexec::ProjectionId,
    target_generation: eventexec::ProjectionVersion,
    definition_version: Box<str>,
    definition_schema_digest: Box<str>,
    input_generation: Box<str>,
}

impl ProjectionWorkerTarget {
    fn from_binding(binding: &eventexec::ProjectionRuntimeBinding) -> Self {
        let definition = binding.definition();
        let Ok(projection) = eventexec::ProjectionId::parse(definition.contract_id()) else {
            unreachable!("plan-issued projection id is canonical")
        };
        Self {
            execution: binding.background_execution_issuer(),
            projection,
            target_generation: binding.target_generation().clone(),
            definition_version: definition.version().into(),
            definition_schema_digest: definition.schema_hash().into(),
            input_generation: binding.input_generation().into(),
        }
    }

    #[cfg(test)]
    pub(crate) fn from_binding_for_test(binding: &eventexec::ProjectionRuntimeBinding) -> Self {
        Self::from_binding(binding)
    }

    pub(crate) fn projection_id(&self) -> &str {
        self.projection.as_str()
    }

    pub(crate) fn target_generation(&self) -> &str {
        self.target_generation.as_str()
    }

    pub(crate) fn definition_version(&self) -> &str {
        &self.definition_version
    }

    pub(crate) fn definition_schema_digest(&self) -> &str {
        &self.definition_schema_digest
    }

    pub(crate) fn input_generation(&self) -> &str {
        &self.input_generation
    }

    pub(crate) fn selector(
        &self,
        tenant: rss_request_context::TenantId,
    ) -> eventexec::ProjectionSelector {
        eventexec::ProjectionSelector::new(
            tenant,
            self.projection.clone(),
            self.target_generation.clone(),
        )
    }

    pub(crate) fn for_generation(&self, target_generation: eventexec::ProjectionVersion) -> Self {
        let mut selected = self.clone();
        selected.target_generation = target_generation;
        selected
    }

    pub(crate) fn background_execution(
        &self,
        tenant: rss_request_context::TenantId,
    ) -> eventexec::ProjectionExecutionContext {
        self.execution.issue(tenant)
    }
}
