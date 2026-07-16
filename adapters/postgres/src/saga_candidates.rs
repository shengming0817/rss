//! Narrow global capability for the fixed saga candidate-tenant function.
//!
//! The SECURITY DEFINER function is the reviewed cross-tenant discovery boundary. Keeping its
//! pool in a non-repository capability prevents tenant repositories from retaining a raw pool.

use std::num::NonZeroUsize;

use diport::{SagaInstanceStoreError, SagaWorkerIdentity};

use crate::pool::VerifiedPgWriteStore;

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
        limit: NonZeroUsize,
    ) -> Result<Vec<vocab::TenantId>, SagaInstanceStoreError> {
        let limit = i64::try_from(limit.get()).map_err(SagaInstanceStoreError::new)?;
        let rows: Vec<(String,)> = sqlx::query_as(
            r#"
            SELECT tenant_id::text
            FROM rss_saga_candidate_tenants($1, $2, $3)
            "#,
        )
        .bind(identity.owner())
        .bind(identity.contract_id().as_str())
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(SagaInstanceStoreError::new)?;
        rows.into_iter()
            .map(|(tenant,)| vocab::TenantId::parse(&tenant).map_err(SagaInstanceStoreError::new))
            .collect()
    }
}
