//! Narrow global capability for the fixed saga candidate-tenant function.
//!
//! The SECURITY DEFINER function is the reviewed cross-tenant discovery boundary. Keeping its
//! pool in a non-repository capability prevents tenant repositories from retaining a raw pool.

use std::num::NonZeroUsize;
use std::time::{Duration, SystemTime};

use diport::{
    SagaDurableStoreError, SagaDurableStoreErrorKind, SagaTenantCursor, SagaTenantPage,
    SagaUnresolvedObservation, SagaWorkerIdentity,
};

use crate::pool::VerifiedPgWriteStore;
use crate::saga::{SagaStorageStage, storage_error};

const MAX_TENANT_PAGE_SIZE: usize = 10_000;

#[derive(sqlx::FromRow)]
struct SagaUnresolvedRow {
    operator_required_count: i64,
    degraded_count: i64,
    compensation_failed_count: i64,
    oldest_unresolved_epoch_micros: Option<i64>,
}

#[derive(Clone)]
pub(crate) struct PgSagaCandidateSource {
    pool: sqlx::PgPool,
}

impl PgSagaCandidateSource {
    pub(crate) fn new(store: &VerifiedPgWriteStore) -> Self {
        Self {
            pool: store.pool().clone(),
        }
    }

    pub(crate) async fn list(
        &self,
        identity: &SagaWorkerIdentity,
        cursor: Option<SagaTenantCursor>,
        limit: NonZeroUsize,
    ) -> Result<SagaTenantPage, SagaDurableStoreError> {
        if limit.get() > MAX_TENANT_PAGE_SIZE {
            return Err(SagaDurableStoreError::new(
                SagaDurableStoreErrorKind::Integrity,
                std::io::Error::other("saga tenant page limit exceeds 10000"),
            ));
        }
        let fetch_limit = limit.get().checked_add(1).ok_or_else(|| {
            SagaDurableStoreError::new(
                SagaDurableStoreErrorKind::Integrity,
                std::io::Error::other("saga tenant page limit overflow"),
            )
        })?;
        let fetch_limit = i64::try_from(fetch_limit).map_err(|error| {
            SagaDurableStoreError::new(SagaDurableStoreErrorKind::Integrity, error)
        })?;
        let after = cursor.map(|cursor| cursor.tenant().to_string());
        let rows: Vec<(String,)> = sqlx::query_as(
            r#"
            SELECT tenant_id::text
            FROM public.rss_saga_candidate_tenants($1, $2, $3::uuid, $4)
            "#,
        )
        .bind(identity.owner())
        .bind(identity.contract_id().as_str())
        .bind(after)
        .bind(fetch_limit)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error(SagaStorageStage::ListCandidateTenants))?;
        let mut tenants = rows
            .into_iter()
            .map(|(tenant,)| {
                rss_request_context::TenantId::parse(&tenant).map_err(|error| {
                    SagaDurableStoreError::new(SagaDurableStoreErrorKind::Integrity, error)
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let has_more = tenants.len() > limit.get();
        tenants.truncate(limit.get());
        let next = has_more
            .then(|| tenants.last().copied().map(SagaTenantCursor::new))
            .flatten();
        Ok(SagaTenantPage::new(tenants, next))
    }

    pub(crate) async fn observe_unresolved(
        &self,
        identity: &SagaWorkerIdentity,
    ) -> Result<SagaUnresolvedObservation, SagaDurableStoreError> {
        let row: SagaUnresolvedRow = sqlx::query_as(
            "SELECT operator_required_count, degraded_count, compensation_failed_count, \
                    CASE WHEN oldest_unresolved_at IS NULL THEN NULL \
                         ELSE (EXTRACT(EPOCH FROM oldest_unresolved_at) \
                               * 1000000)::bigint END AS oldest_unresolved_epoch_micros \
             FROM public.rss_saga_observe_unresolved($1, $2)",
        )
        .bind(identity.owner())
        .bind(identity.contract_id().as_str())
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error(SagaStorageStage::ObserveUnresolved))?;
        let operator_required = unresolved_count(row.operator_required_count)?;
        let degraded = unresolved_count(row.degraded_count)?;
        let compensation_failed = unresolved_count(row.compensation_failed_count)?;
        let total = operator_required
            .checked_add(degraded)
            .and_then(|count| count.checked_add(compensation_failed))
            .ok_or_else(|| unresolved_integrity("saga unresolved count overflow"))?;
        if (total == 0) != row.oldest_unresolved_epoch_micros.is_none() {
            return Err(unresolved_integrity(
                "saga unresolved count and oldest timestamp disagree",
            ));
        }
        Ok(SagaUnresolvedObservation::new(
            operator_required,
            degraded,
            compensation_failed,
            row.oldest_unresolved_epoch_micros
                .map(epoch_micros_to_system_time)
                .transpose()?,
        ))
    }
}

fn unresolved_count(count: i64) -> Result<u64, SagaDurableStoreError> {
    u64::try_from(count).map_err(|_| unresolved_integrity("saga unresolved count is negative"))
}

fn unresolved_integrity(message: &'static str) -> SagaDurableStoreError {
    SagaDurableStoreError::new(
        SagaDurableStoreErrorKind::Integrity,
        std::io::Error::other(message),
    )
}

fn epoch_micros_to_system_time(value: i64) -> Result<SystemTime, SagaDurableStoreError> {
    let delta = Duration::from_micros(value.unsigned_abs());
    if value >= 0 {
        SystemTime::UNIX_EPOCH.checked_add(delta)
    } else {
        SystemTime::UNIX_EPOCH.checked_sub(delta)
    }
    .ok_or_else(|| unresolved_integrity("saga unresolved timestamp is out of range"))
}
