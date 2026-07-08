//! Durable service-token replay guard.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use diport::{ServiceTokenReplayError, ServiceTokenReplayGuard};

use crate::PgStore;

/// Postgres-backed service-token `jti` replay guard.
///
/// `ServiceTokenReplayGuard` is synchronous because JWT verification is CPU-local. Operator CLIs
/// already run inside the Tokio multi-thread runtime, so this adapter bridges to the async pool
/// with `block_in_place` and fails closed on runtime or storage errors.
pub struct PgServiceTokenReplayGuard {
    store: Arc<PgStore>,
}

impl PgServiceTokenReplayGuard {
    pub(crate) fn new(store: Arc<PgStore>) -> Self {
        Self { store }
    }

    async fn record_nonce(
        store: Arc<PgStore>,
        nonce: String,
        expires_at: SystemTime,
    ) -> Result<bool, ServiceTokenReplayError> {
        let expires_at = expires_at
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ServiceTokenReplayError::Guard)?
            .as_secs();
        let expires_at = i64::try_from(expires_at).map_err(|_| ServiceTokenReplayError::Guard)?;
        let inserted: Option<(String,)> = sqlx::query_as(
            r#"
            WITH pruned AS (
                DELETE FROM service_token_replay_nonces
                WHERE expires_at <= now()
            )
            INSERT INTO service_token_replay_nonces (nonce, expires_at)
            VALUES ($1, to_timestamp($2))
            ON CONFLICT (nonce) DO NOTHING
            RETURNING nonce
            "#,
        )
        .bind(nonce)
        .bind(expires_at)
        .fetch_optional(&store.pool)
        .await
        .map_err(|err| {
            tracing::warn!(
                target: "postgres",
                error = %err,
                "service-token replay nonce record failed"
            );
            ServiceTokenReplayError::Guard
        })?;
        Ok(inserted.is_some())
    }
}

impl ServiceTokenReplayGuard for PgServiceTokenReplayGuard {
    fn check_and_record(
        &self,
        nonce: &str,
        expires_at: SystemTime,
    ) -> Result<(), ServiceTokenReplayError> {
        let handle =
            tokio::runtime::Handle::try_current().map_err(|_| ServiceTokenReplayError::Guard)?;
        let store = Arc::clone(&self.store);
        let nonce = nonce.to_owned();
        let inserted = tokio::task::block_in_place(|| {
            handle.block_on(Self::record_nonce(store, nonce, expires_at))
        })?;
        if inserted {
            Ok(())
        } else {
            Err(ServiceTokenReplayError::Replayed)
        }
    }
}
