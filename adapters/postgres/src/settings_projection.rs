//! PostgreSQL adapter for the Settings metadata-only current-state projection.
//!
//! The read and apply capabilities are intentionally separate: the former owns only a serving
//! reader lane, while the latter owns only a serving writer lane. Neither adapter exposes a pool.

use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use consistency::{LocalTxFinalStatus, Lsn};
use eventexec::{ProjectionTargetStoreError, ProjectionTargetStoreErrorKind};
use settings::ports::{
    SettingKey, SettingsConfigChangeKind, SettingsConfigProjectionRow,
    SettingsProjectionApplyScope, SettingsProjectionApplyStore, SettingsProjectionMutation,
    SettingsProjectionReadRepo, SettingsProjectionReadScope, SettingsProjectionRepoError,
};

use crate::cotx::{ServingReadLane, ServingWriteLane, TenantDb};
use crate::pool::{VerifiedPgReadStore, VerifiedPgWriteStore};
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
pub struct PgSettingsProjectionApplyStore {
    pool: TenantDb<ServingWriteLane>,
}

impl PgSettingsProjectionApplyStore {
    pub(crate) fn new(store: &VerifiedPgWriteStore) -> Self {
        Self {
            pool: TenantDb::<ServingWriteLane>::new(store),
        }
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

impl SettingsProjectionApplyStore for PgSettingsProjectionApplyStore {
    async fn apply(
        &self,
        scope: SettingsProjectionApplyScope,
        mutation: SettingsProjectionMutation,
    ) -> Result<eventexec::ProjectionTargetStoreOutcome, ProjectionTargetStoreError> {
        let attempt = self.pool.settings_projection_apply(scope, mutation).await;
        let settlement = attempt.settlement();
        record_settlement(SETTINGS_PROJECTION_BOUNDARY, settlement);
        attempt.into_result().map_err(|error| {
            record_apply_failure(settlement, error.reason());
            let kind = match settlement {
                Some(LocalTxFinalStatus::CommitUnknown) => {
                    ProjectionTargetStoreErrorKind::CommitUnknown
                }
                Some(LocalTxFinalStatus::RollbackFailed) => {
                    ProjectionTargetStoreErrorKind::RollbackFailed
                }
                Some(LocalTxFinalStatus::RolledBack) | None => error.target_kind(),
                Some(LocalTxFinalStatus::Committed) => ProjectionTargetStoreErrorKind::Permanent,
            };
            ProjectionTargetStoreError::new(kind, error)
        })
    }
}

fn record_apply_failure(settlement: Option<LocalTxFinalStatus>, reason: &'static str) {
    let final_status = settlement.map_or("unsettled", LocalTxFinalStatus::as_label);
    metrics::counter!(
        "settings_projection_apply_failure_total",
        "reason" => reason,
        "final_status" => final_status,
    )
    .increment(1);
    tracing::warn!(
        target: "postgres",
        reason,
        final_status,
        "settings projection apply failed"
    );
}
