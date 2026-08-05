//! PostgreSQL adapter for the Settings metadata-only current-state projection.
//!
//! Read capability stays on the serving reader lane. One apply store serves both the serving and
//! operator write lanes, and both lane capabilities terminate in the same closed transaction and
//! fixed-function mutation funnel. Neither adapter exposes a pool.

use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use consistency::{LocalTxFinalStatus, Lsn};
use eventexec::{
    ProjectionTargetStore, ProjectionTargetStoreError, ProjectionVersion, ValidatedProjectionApply,
};
use settings::ports::{
    ActiveProjectionResolveError, ActiveProjectionResolver, ActiveProjectionSelection,
    ActiveProjectionSnapshot, SettingKey, SettingsConfigChangeKind, SettingsConfigProjectionRow,
    SettingsProjectionApplyScope, SettingsProjectionMutation, SettingsProjectionReadRepo,
    SettingsProjectionReadScope, SettingsProjectionRepoError, TenantRepoScope,
    settings_projection_apply_from_validated,
};

use crate::cotx::{
    ProjectionOperatorWriteLane, ProjectionWorkerWriteLane, ServingReadLane, TenantDb,
};
use crate::pool::{
    VerifiedPgProjectionOperatorStore, VerifiedPgProjectionWorkerStore, VerifiedPgReadStore,
};
use crate::tx_retry::{SETTINGS_PROJECTION_BOUNDARY, record_settlement};

/// Read-only PostgreSQL adapter for one tenant-bound Settings projection generation.
pub struct PgSettingsProjectionReadRepo {
    pool: TenantDb<ServingReadLane>,
}

impl PgSettingsProjectionReadRepo {
    pub(crate) fn new(store: &VerifiedPgReadStore) -> Self {
        Self {
            pool: TenantDb::<ServingReadLane>::new(store),
        }
    }
}

/// Fixed-function active Settings generation resolver on the tenant serving-read lane.
pub struct PgActiveProjectionResolver {
    pool: TenantDb<ServingReadLane>,
}

impl PgActiveProjectionResolver {
    pub(crate) fn new(store: &VerifiedPgReadStore) -> Self {
        Self {
            pool: TenantDb::<ServingReadLane>::new(store),
        }
    }
}

impl ActiveProjectionResolver for PgActiveProjectionResolver {
    async fn resolve(
        &self,
        scope: TenantRepoScope,
    ) -> Result<ActiveProjectionSelection, ActiveProjectionResolveError> {
        let stored = self
            .pool
            .settings_projection_resolve_active(scope)
            .await
            .map_err(ActiveProjectionResolveError::storage)?;
        let Some(stored) = stored else {
            return Ok(ActiveProjectionSelection::Uninitialized);
        };
        let generation = ProjectionVersion::parse(&stored.generation)
            .map_err(|_| ActiveProjectionResolveError::IdentityMismatch)?;
        let promoted_high_water = u64::try_from(stored.promoted_high_water_lsn)
            .map(Lsn::new)
            .map_err(|_| ActiveProjectionResolveError::IdentityMismatch)?;
        let token = u64::try_from(stored.token)
            .map(vocab::Epoch::new)
            .map_err(|_| ActiveProjectionResolveError::IdentityMismatch)?;
        ActiveProjectionSnapshot::validated(
            scope,
            generation,
            &stored.definition_version,
            &stored.definition_schema_digest,
            &stored.input_generation,
            promoted_high_water,
            token,
        )
        .map(ActiveProjectionSelection::Active)
    }
}

/// Atomic PostgreSQL apply adapter for Settings current rows, receipts, and high-water state.
pub(crate) struct PgSettingsProjectionApplyStore {
    pool: SettingsProjectionApplyPool,
    #[cfg(all(test, feature = "integration"))]
    test_calls: std::sync::atomic::AtomicU64,
    #[cfg(all(test, feature = "integration"))]
    test_fault: std::sync::Mutex<Option<SettingsProjectionTestFault>>,
}

#[cfg(all(test, feature = "integration"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SettingsProjectionTestFault {
    ConfirmedRollback,
    CommitUnknown,
    RollbackFailed,
}

enum SettingsProjectionApplyPool {
    Worker(TenantDb<ProjectionWorkerWriteLane>),
    Operator(TenantDb<ProjectionOperatorWriteLane>),
}

impl PgSettingsProjectionApplyStore {
    pub(crate) fn new_projection_worker(store: &VerifiedPgProjectionWorkerStore) -> Self {
        Self {
            pool: SettingsProjectionApplyPool::Worker(
                TenantDb::<ProjectionWorkerWriteLane>::new_projection_worker(store),
            ),
            #[cfg(all(test, feature = "integration"))]
            test_calls: std::sync::atomic::AtomicU64::new(0),
            #[cfg(all(test, feature = "integration"))]
            test_fault: std::sync::Mutex::new(None),
        }
    }

    pub(crate) fn new_projection_operator(store: &VerifiedPgProjectionOperatorStore) -> Self {
        Self {
            pool: SettingsProjectionApplyPool::Operator(
                TenantDb::<ProjectionOperatorWriteLane>::new_projection_operator(store),
            ),
            #[cfg(all(test, feature = "integration"))]
            test_calls: std::sync::atomic::AtomicU64::new(0),
            #[cfg(all(test, feature = "integration"))]
            test_fault: std::sync::Mutex::new(None),
        }
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn inject_test_fault(&self, fault: SettingsProjectionTestFault) {
        *self
            .test_fault
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(fault);
    }

    async fn apply_parts(
        &self,
        scope: SettingsProjectionApplyScope,
        mutation: SettingsProjectionMutation,
    ) -> Result<eventexec::ProjectionTargetStoreOutcome, ProjectionTargetStoreError> {
        #[cfg(all(test, feature = "integration"))]
        let fault = self
            .test_fault
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let attempt = match &self.pool {
            SettingsProjectionApplyPool::Worker(pool) => {
                pool.settings_projection_apply(
                    scope,
                    mutation,
                    #[cfg(all(test, feature = "integration"))]
                    fault,
                )
                .await
            }
            SettingsProjectionApplyPool::Operator(pool) => {
                pool.settings_projection_apply(
                    scope,
                    mutation,
                    #[cfg(all(test, feature = "integration"))]
                    fault,
                )
                .await
            }
        };
        settle_apply(attempt)
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn apply_calls(&self) -> u64 {
        self.test_calls.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[derive(Debug, thiserror::Error)]
enum SettingsProjectionHydrationError {
    #[error("stored settings projection numeric metadata is invalid")]
    Numeric,
    #[error("stored settings projection change kind is invalid")]
    ChangeKind,
    #[error("stored settings projection timestamp is invalid")]
    Timestamp,
    #[error("stored settings projection row violates the domain model")]
    Row(#[source] settings::ports::SettingsProjectionRowError),
}

fn change_kind(raw: &str) -> Result<SettingsConfigChangeKind, SettingsProjectionHydrationError> {
    SettingsConfigChangeKind::from_str(raw)
        .map_err(|_| SettingsProjectionHydrationError::ChangeKind)
}

fn system_time(epoch_micros: i64) -> Result<SystemTime, SettingsProjectionHydrationError> {
    if epoch_micros >= 0 {
        UNIX_EPOCH
            .checked_add(Duration::from_micros(epoch_micros.unsigned_abs()))
            .ok_or(SettingsProjectionHydrationError::Timestamp)
    } else {
        UNIX_EPOCH
            .checked_sub(Duration::from_micros(epoch_micros.unsigned_abs()))
            .ok_or(SettingsProjectionHydrationError::Timestamp)
    }
}

impl SettingsProjectionReadRepo for PgSettingsProjectionReadRepo {
    async fn find(
        &self,
        scope: SettingsProjectionReadScope,
        key: &SettingKey,
    ) -> Result<Option<SettingsConfigProjectionRow>, SettingsProjectionRepoError> {
        let stored = self
            .pool
            .settings_projection_find(scope.clone(), key.clone())
            .await
            .map_err(SettingsProjectionRepoError::storage)?;
        let Some(stored) = stored else {
            return Ok(None);
        };

        let config_version = u64::try_from(stored.config_version).map_err(|_| {
            SettingsProjectionRepoError::storage(SettingsProjectionHydrationError::Numeric)
        })?;
        let source_lsn = u64::try_from(stored.source_lsn).map_err(|_| {
            SettingsProjectionRepoError::storage(SettingsProjectionHydrationError::Numeric)
        })?;
        let occurred_at = u64::try_from(stored.source_occurred_at_secs).map_err(|_| {
            SettingsProjectionRepoError::storage(SettingsProjectionHydrationError::Numeric)
        })?;
        let row = SettingsConfigProjectionRow::restore(
            scope.tenant_scope().tenant(),
            scope.generation().clone(),
            key.clone(),
            config_version,
            change_kind(&stored.change_kind).map_err(SettingsProjectionRepoError::storage)?,
            stored.source_event_id,
            Lsn::new(source_lsn),
            occurred_at,
            system_time(stored.created_at_epoch_micros)
                .map_err(SettingsProjectionRepoError::storage)?,
            system_time(stored.updated_at_epoch_micros)
                .map_err(SettingsProjectionRepoError::storage)?,
        )
        .map_err(|error| {
            SettingsProjectionRepoError::storage(SettingsProjectionHydrationError::Row(error))
        })?;
        Ok(Some(row))
    }
}

impl ProjectionTargetStore for PgSettingsProjectionApplyStore {
    fn apply<'a>(
        &'a self,
        input: &'a ValidatedProjectionApply,
    ) -> futures::future::BoxFuture<
        'a,
        Result<eventexec::ProjectionTargetStoreOutcome, ProjectionTargetStoreError>,
    > {
        Box::pin(async move {
            #[cfg(all(test, feature = "integration"))]
            self.test_calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let expected = match &self.pool {
                SettingsProjectionApplyPool::Worker(_) => (
                    "rss-projection-worker",
                    eventexec::ProjectionPurpose::BackgroundWorker,
                ),
                SettingsProjectionApplyPool::Operator(_) => (
                    "rss-projection-replay",
                    eventexec::ProjectionPurpose::OperatorReplay,
                ),
            };
            if input.execution().identity().actor() != expected.0
                || input.execution().identity().purpose() != expected.1
            {
                return Err(ProjectionTargetStoreError::new(
                    consistency::ProjectionApplyErrorReason::ProviderInvariant,
                    SettingsProjectionExecutionMismatch,
                ));
            }
            let (scope, mutation) = settings_projection_apply_from_validated(input)
                .map_err(|error| ProjectionTargetStoreError::new(error.reason(), error))?;
            match &self.pool {
                SettingsProjectionApplyPool::Worker(_) => tokio::time::timeout(
                    crate::bundle::PROJECTION_WORKER_APPLY_TIMEOUT,
                    self.apply_parts(scope, mutation),
                )
                .await
                .map_err(|error| {
                    ProjectionTargetStoreError::new(
                        consistency::ProjectionApplyErrorReason::CommitUnknown,
                        error,
                    )
                })?,
                SettingsProjectionApplyPool::Operator(_) => self.apply_parts(scope, mutation).await,
            }
        })
    }
}

#[derive(Debug, thiserror::Error)]
#[error("settings projection execution purpose does not match PostgreSQL lane")]
struct SettingsProjectionExecutionMismatch;

fn settle_apply(
    attempt: crate::cotx::LocalTxAttempt<
        eventexec::ProjectionTargetStoreOutcome,
        crate::cotx::settings_projection::SettingsProjectionTxError,
    >,
) -> Result<eventexec::ProjectionTargetStoreOutcome, ProjectionTargetStoreError> {
    let settlement = attempt.settlement();
    record_settlement(SETTINGS_PROJECTION_BOUNDARY, settlement);
    attempt.into_result().map_err(|error| {
        let final_status = settlement.map_or("unsettled", LocalTxFinalStatus::as_label);
        let reason = match settlement {
            Some(LocalTxFinalStatus::CommitUnknown) => {
                consistency::ProjectionApplyErrorReason::CommitUnknown
            }
            Some(LocalTxFinalStatus::RollbackFailed) => {
                consistency::ProjectionApplyErrorReason::RollbackFailed
            }
            Some(LocalTxFinalStatus::RolledBack) | None => error.target_reason(),
            Some(LocalTxFinalStatus::Committed) => {
                consistency::ProjectionApplyErrorReason::ProviderInvariant
            }
        };
        tracing::warn!(
            target: "postgres",
            reason = reason.as_label(),
            final_status,
            "settings projection apply failed"
        );
        ProjectionTargetStoreError::new(reason, error)
    })
}
