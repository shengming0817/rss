//! PostgreSQL adapter for the Settings metadata-only current-state projection.
//!
//! Read capability stays on the serving reader lane. One apply store serves both the serving and
//! operator write lanes, and both lane capabilities terminate in the same closed transaction and
//! fixed-function mutation funnel. Neither adapter exposes a pool.

use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use consistency::{LocalTxFinalStatus, Lsn};
use eventexec::{ProjectionTargetStore, ProjectionTargetStoreError, ValidatedProjectionApply};
use settings::ports::{
    SettingKey, SettingsConfigChangeKind, SettingsConfigProjectionRow,
    SettingsProjectionApplyScope, SettingsProjectionMutation, SettingsProjectionReadRepo,
    SettingsProjectionReadScope, SettingsProjectionRepoError,
    settings_projection_apply_from_validated,
};

use crate::cotx::{ProjectionOperatorWriteLane, ServingReadLane, ServingWriteLane, TenantDb};
use crate::pool::{VerifiedPgProjectionOperatorStore, VerifiedPgReadStore, VerifiedPgWriteStore};
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

/// Atomic PostgreSQL apply adapter for Settings current rows, receipts, and high-water state.
pub(crate) struct PgSettingsProjectionApplyStore {
    pool: SettingsProjectionApplyPool,
    #[cfg(all(test, feature = "integration"))]
    test_store: std::sync::Arc<crate::PgStore>,
    #[cfg(all(test, feature = "integration"))]
    test_scope: std::sync::Mutex<Option<(vocab::TenantId, String)>>,
    #[cfg(all(test, feature = "integration"))]
    test_calls: std::sync::atomic::AtomicU64,
    #[cfg(all(test, feature = "integration"))]
    test_effects: std::sync::atomic::AtomicU64,
    #[cfg(all(test, feature = "integration"))]
    test_receipts: std::sync::atomic::AtomicU64,
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
    Serving(TenantDb<ServingWriteLane>),
    Operator(TenantDb<ProjectionOperatorWriteLane>),
}

impl PgSettingsProjectionApplyStore {
    pub(crate) fn new(store: &VerifiedPgWriteStore) -> Self {
        Self {
            pool: SettingsProjectionApplyPool::Serving(TenantDb::<ServingWriteLane>::new(store)),
            #[cfg(all(test, feature = "integration"))]
            test_store: store.store_arc(),
            #[cfg(all(test, feature = "integration"))]
            test_scope: std::sync::Mutex::new(None),
            #[cfg(all(test, feature = "integration"))]
            test_calls: std::sync::atomic::AtomicU64::new(0),
            #[cfg(all(test, feature = "integration"))]
            test_effects: std::sync::atomic::AtomicU64::new(0),
            #[cfg(all(test, feature = "integration"))]
            test_receipts: std::sync::atomic::AtomicU64::new(0),
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
            test_store: store.store_arc(),
            #[cfg(all(test, feature = "integration"))]
            test_scope: std::sync::Mutex::new(None),
            #[cfg(all(test, feature = "integration"))]
            test_calls: std::sync::atomic::AtomicU64::new(0),
            #[cfg(all(test, feature = "integration"))]
            test_effects: std::sync::atomic::AtomicU64::new(0),
            #[cfg(all(test, feature = "integration"))]
            test_receipts: std::sync::atomic::AtomicU64::new(0),
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
        {
            *self
                .test_scope
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((
                scope.tenant_scope().tenant(),
                scope.target_generation().as_str().to_owned(),
            ));
        }
        #[cfg(all(test, feature = "integration"))]
        let fault = self
            .test_fault
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let attempt = match &self.pool {
            SettingsProjectionApplyPool::Serving(pool) => {
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
    pub(crate) async fn refresh_counts(&self) -> Result<(), sqlx::Error> {
        let Some((tenant, generation)) = self
            .test_scope
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
        else {
            return Ok(());
        };
        let (effects, receipts) = crate::cotx::settings_projection_conformance_counts(
            &self.test_store.pool,
            tenant,
            &generation,
        )
        .await?;
        self.test_effects
            .store(effects as u64, std::sync::atomic::Ordering::Relaxed);
        self.test_receipts
            .store(receipts as u64, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn counts(&self) -> (u64, u64, u64) {
        (
            self.test_calls.load(std::sync::atomic::Ordering::Relaxed),
            self.test_effects.load(std::sync::atomic::Ordering::Relaxed),
            self.test_receipts
                .load(std::sync::atomic::Ordering::Relaxed),
        )
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn transaction_counts(&self) -> (u64, u64) {
        let (_, effects, receipts) = self.counts();
        (effects, receipts)
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
            let (scope, mutation) = settings_projection_apply_from_validated(input)
                .map_err(|error| ProjectionTargetStoreError::new(error.reason(), error))?;
            self.apply_parts(scope, mutation).await
        })
    }
}

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
