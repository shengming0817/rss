//! Narrow global capability for the fixed saga candidate-tenant function.
//!
//! The SECURITY DEFINER function is the reviewed cross-tenant discovery boundary. Keeping its
//! pool in a non-repository capability prevents tenant repositories from retaining a raw pool.

use std::num::NonZeroUsize;

use diport::{
    SagaDurableStoreError, SagaDurableStoreErrorKind, SagaTenantCursor, SagaTenantPage,
    SagaUnresolvedState, SagaWorkerIdentity,
};

use crate::pool::VerifiedPgWriteStore;

const MAX_TENANT_PAGE_SIZE: usize = 10_000;

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

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn from_unverified_for_test(store: &crate::PgStore) -> Self {
        Self {
            pool: store.pool.clone(),
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
        .map_err(|error| SagaDurableStoreError::new(SagaDurableStoreErrorKind::Storage, error))?;
        let mut tenants = rows
            .into_iter()
            .map(|(tenant,)| {
                vocab::TenantId::parse(&tenant).map_err(|error| {
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
    ) -> Result<SagaUnresolvedState, SagaDurableStoreError> {
        let present: bool = sqlx::query_scalar("SELECT public.rss_saga_observe_unresolved($1, $2)")
            .bind(identity.owner())
            .bind(identity.contract_id().as_str())
            .fetch_one(&self.pool)
            .await
            .map_err(|error| {
                SagaDurableStoreError::new(SagaDurableStoreErrorKind::Storage, error)
            })?;
        Ok(if present {
            SagaUnresolvedState::Present
        } else {
            SagaUnresolvedState::Clear
        })
    }
}
