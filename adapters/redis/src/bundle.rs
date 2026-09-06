//! redis capability bundle（#1498 / RW-W-hardening）：把 pool 构造 + distlock/CAS 能力派发 +
//! managed-resource/rollback 单源派生收口到单一 funnel，作 redis provider 的**唯一装配出口**。
//!
//! 泛化自 pg `PgRuntimeDeps`/`PgInfraDeps`（#1422/#1423，ADR-010 §2.2）。

use core::time::Duration;
use std::sync::Arc;

use crate::{InvalidLeaseTtl, RedisStore};
use crate::{
    InvalidRateLimitNamespace, RedisRateLimitCapabilityError, RedisRateLimiter,
    RedisRateLimiterCapability,
};
use deadpool_redis::{Manager, Pool, Runtime};
use diport::{DynCasStore, DynLockStore};
use rss_runtime::{DynManagedResource, ManagedResource, ShutdownError};

/// Explicit private trust anchor for a REDISS connection.
#[derive(Clone)]
pub struct RedisPrivateCa(Vec<u8>);

/// Invalid explicit Redis trust anchor. The fixed message does not expose PEM material.
#[derive(Debug, thiserror::Error)]
#[error("invalid Redis private CA PEM")]
pub struct RedisPrivateCaError;

impl RedisPrivateCa {
    /// Build a non-empty PEM trust anchor. The Redis rustls client performs full certificate
    /// parsing when the typed connection is assembled.
    pub fn from_pem(pem: Vec<u8>) -> Result<Self, RedisPrivateCaError> {
        let text = std::str::from_utf8(&pem).map_err(|_| RedisPrivateCaError)?;
        if text.trim().is_empty()
            || !text.contains("-----BEGIN CERTIFICATE-----")
            || !text.contains("-----END CERTIFICATE-----")
        {
            return Err(RedisPrivateCaError);
        }
        Ok(Self(pem))
    }
}

/// Typed REDISS pool construction failure. Messages are stable and contain no endpoint/PEM data.
#[derive(Debug, thiserror::Error)]
pub enum RedisConnectError {
    #[error("redis TLS client construction failed")]
    Client,
    #[error("redis pool construction failed")]
    Pool,
}

#[cfg(test)]
mod private_ca_tests {
    use super::RedisPrivateCa;

    #[test]
    fn private_ca_rejects_empty_and_malformed_pem() {
        assert!(RedisPrivateCa::from_pem(Vec::new()).is_err());
        assert!(RedisPrivateCa::from_pem(b"not a certificate".to_vec()).is_err());
    }
}

/// Redis readiness ping failed. Display is intentionally stable and does not include endpoint data.
#[derive(Debug, thiserror::Error)]
#[error("redis ping failed")]
pub struct RedisPingError;

/// 组合根级 redis 能力包：集中 pool 构造，派发 infra 能力句柄，并产出 shutdown 资源。
#[derive(Clone)]
pub struct RedisRuntimeDeps {
    store: Arc<RedisStore>,
}

impl RedisRuntimeDeps {
    /// Production REDISS assembly path with a required explicit private CA. The custom root store
    /// is embedded in every connection produced by the pool; no optional CA/default constructor is
    /// reachable through this funnel.
    pub fn connect_with_private_ca(
        endpoint: &secure::RedisEndpoint,
        ca: RedisPrivateCa,
    ) -> Result<Self, RedisConnectError> {
        #[allow(clippy::disallowed_methods)]
        // reason: sole typed Redis TLS client construction callsite; endpoint is validated/redacted.
        let client = deadpool_redis::redis::Client::build_with_tls(
            endpoint.expose(),
            deadpool_redis::redis::TlsCertificates {
                client_tls: None,
                root_cert: Some(ca.0),
            },
        )
        .map_err(|_| RedisConnectError::Client)?;
        let manager = Manager::new(client.get_connection_info().clone())
            .map_err(|_| RedisConnectError::Client)?;
        let pool = Pool::builder(manager)
            .runtime(Runtime::Tokio1)
            .build()
            .map_err(|_| RedisConnectError::Pool)?;
        Ok(Self::from_pool(pool))
    }

    /// Private pool injection funnel. Production callers cannot supply a raw pool.
    #[must_use]
    fn from_pool(pool: Pool) -> Self {
        Self {
            store: Arc::new(RedisStore::new(pool)),
        }
    }

    /// Test-only raw-pool seam for provider integration fixtures.
    #[cfg(any(test, feature = "integration"))]
    #[must_use]
    pub fn setup_for_test(pool: Pool) -> Self {
        Self::from_pool(pool)
    }

    pub(crate) fn validate_ttl(ttl: Duration) -> Result<(), InvalidLeaseTtl> {
        if ttl.as_millis() == 0 {
            return Err(InvalidLeaseTtl);
        }
        Ok(())
    }

    /// 派发 framework/global 基建能力句柄 [`RedisInfraDeps`]。
    #[must_use]
    pub fn infra(&self) -> RedisInfraDeps {
        RedisInfraDeps {
            store: Arc::clone(&self.store),
        }
    }

    /// 包装私有 `Arc<RedisStore>` 为可注册进 `ShutdownStack` 的 guard，不泄漏 `Arc<RedisStore>` 本身。
    #[must_use]
    fn store_guard(&self) -> RedisStoreGuard {
        RedisStoreGuard(Arc::clone(&self.store))
    }

    /// 单源 managed-resource/rollback 派生：当前只产 redis pool guard。
    #[must_use]
    pub fn runtime_resources(&self) -> Vec<Box<DynManagedResource<'static>>> {
        vec![DynManagedResource::new_box(self.store_guard())]
    }

    /// Redis readiness probe operation. This is the only public live-check path exposed by the
    /// bundle, so composition code never reaches into `deadpool_redis::Pool` directly.
    pub async fn ping(&self) -> Result<(), RedisPingError> {
        let mut conn = self.store.pool().get().await.map_err(|e| {
            tracing::warn!(error = %rss_redact::redact_error(&e), "redis readiness pool checkout failed");
            RedisPingError
        })?;
        let pong: String = deadpool_redis::redis::cmd("PING")
            .query_async(&mut *conn)
            .await
            .map_err(|e| {
                tracing::warn!(error = %rss_redact::redact_error(&e), "redis readiness ping failed");
                RedisPingError
            })?;
        if pong == "PONG" {
            Ok(())
        } else {
            tracing::warn!("redis readiness ping returned unexpected response");
            Err(RedisPingError)
        }
    }
}

/// framework/global redis 基建能力句柄（`Clone`，provider-agnostic、非单域）。
#[derive(Clone)]
pub struct RedisInfraDeps {
    store: Arc<RedisStore>,
}

impl RedisInfraDeps {
    /// Verify and mint the cluster-global rate-limiter capability from the existing pool.
    pub async fn rate_limiter_capability(
        &self,
        namespace: &'static str,
        quota: diport::RateLimitQuota,
    ) -> Result<RedisRateLimiterCapability, RedisRateLimitCapabilityError> {
        let limiter = RedisRateLimiter::new(Arc::clone(&self.store), namespace, quota)
            .map_err(|_: InvalidRateLimitNamespace| RedisRateLimitCapabilityError)?;
        limiter.verify_capability().await
    }

    /// Redis distlock provider 句柄（DI-ready dyn port）。
    #[must_use]
    pub fn lock_store(&self) -> Box<DynLockStore<'static>> {
        DynLockStore::new_box(RedisLockStore {
            store: Arc::clone(&self.store),
        })
    }

    /// Redis distlock provider typed handle for Sync consumers that must not serialize via dyn port
    /// ownership guards.
    #[must_use]
    pub fn lock_store_handle(&self) -> RedisLockStore {
        RedisLockStore {
            store: Arc::clone(&self.store),
        }
    }

    /// Redis state-CAS provider 句柄（DI-ready dyn port）。
    #[must_use]
    pub fn cas_store(&self) -> Box<DynCasStore<'static>> {
        DynCasStore::new_box(RedisCasStore {
            store: Arc::clone(&self.store),
        })
    }
}

/// Redis distlock provider handle。
#[derive(Clone)]
pub struct RedisLockStore {
    store: Arc<RedisStore>,
}

impl RedisLockStore {
    pub(crate) fn store(&self) -> &RedisStore {
        &self.store
    }
}

/// Redis CAS provider handle。
#[derive(Clone)]
pub struct RedisCasStore {
    store: Arc<RedisStore>,
}

impl RedisCasStore {
    pub(crate) fn store(&self) -> &RedisStore {
        &self.store
    }
}

/// `Arc<RedisStore>` 的 `ManagedResource` guard wrapper。
pub(crate) struct RedisStoreGuard(Arc<RedisStore>);

impl ManagedResource for RedisStoreGuard {
    fn name(&self) -> &str {
        self.0.name()
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.0.shutdown().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deadpool_redis::{Config, Runtime};

    #[allow(clippy::expect_used)]
    fn lazy_pool() -> Pool {
        Config::from_url("redis://127.0.0.1:6379")
            .create_pool(Some(Runtime::Tokio1))
            .expect("lazy pool build")
    }

    fn deps() -> RedisRuntimeDeps {
        RedisRuntimeDeps::setup_for_test(lazy_pool())
    }

    #[tokio::test]
    async fn clone_shares_store() {
        let d = deps();
        let c = d.clone();
        assert!(Arc::ptr_eq(&d.store, &c.store));
    }

    #[tokio::test]
    async fn infra_lock_and_cas_handles_construct() {
        let infra = deps().infra();
        let _lock = infra.lock_store();
        let lock_handle = infra.lock_store_handle();
        let _cas = infra.cas_store();
        assert!(Arc::ptr_eq(&infra.store, &lock_handle.store));
    }

    #[tokio::test]
    async fn store_guard_name_is_redis() {
        assert_eq!(deps().store_guard().name(), "redis");
    }

    #[tokio::test]
    async fn runtime_resources_single_sources_pool_guard() {
        let resources = deps().runtime_resources();
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].name(), "redis");
    }
}
