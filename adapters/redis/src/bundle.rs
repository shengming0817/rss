//! redis capability bundle（#1498 / RW-W-hardening）：把 pool 构造 + idempotency/distlock/CAS 能力派发 +
//! managed-resource/rollback 单源派生收口到单一 funnel，作 redis provider 的**唯一装配出口**。
//!
//! 泛化自 pg `PgRuntimeDeps`/`PgInfraDeps`（#1422/#1423，ADR-010 §2.2）。redis 的 `IdempotencyStore` /
//! `LockStore` / `CasStore` 均是 provider-agnostic infra，故落 [`RedisInfraDeps`]。

use core::time::Duration;
use std::sync::Arc;

use consistency::{ConsumerGroup, IdemKey, IdempotencyStore, LeaseOutcome, LeaseToken, SeenState};
use deadpool_redis::Pool;
use diport::{DynCasStore, DynLockStore, DynManagedResource, ManagedResource, ShutdownError};

use crate::{InvalidClaimTtl, RedisStore, claimer};

/// 组合根级 redis 能力包：集中 pool 构造，派发 infra 能力句柄，并产出 shutdown 资源。
#[derive(Clone)]
pub struct RedisRuntimeDeps {
    store: Arc<RedisStore>,
}

impl RedisRuntimeDeps {
    /// 唯一公开构造路径：新建 `Arc<RedisStore>`。`RedisStore::new` 为 crate 内可见，外部不能绕过 bundle。
    #[must_use]
    pub fn setup(pool: Pool) -> Self {
        Self {
            store: Arc::new(RedisStore::new(pool)),
        }
    }

    /// 校验 Redis lease TTL：拒绝 `< 1ms`（亚毫秒丢精度、零非法），不静默钳制。
    pub(crate) fn validate_ttl(ttl: Duration) -> Result<(), InvalidClaimTtl> {
        if ttl.as_millis() == 0 {
            return Err(InvalidClaimTtl);
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

    #[cfg(test)]
    pub(crate) fn setup_with_ttl_validation(
        pool: Pool,
        ttl: Duration,
    ) -> Result<Self, InvalidClaimTtl> {
        Self::validate_ttl(ttl)?;
        Ok(Self::setup(pool))
    }
}

/// framework/global redis 基建能力句柄（`Clone`，provider-agnostic、非单域）。
#[derive(Clone)]
pub struct RedisInfraDeps {
    store: Arc<RedisStore>,
}

impl RedisInfraDeps {
    /// 幂等 claimer 句柄。`group` 是幂等去重 PK 第二维度；`ttl` 由 Redis 服务端 `PX` 管过期。
    pub fn idempotency(
        &self,
        group: ConsumerGroup,
        ttl: Duration,
    ) -> Result<RedisIdempotencyStore, InvalidClaimTtl> {
        RedisRuntimeDeps::validate_ttl(ttl)?;
        Ok(RedisIdempotencyStore {
            store: Arc::clone(&self.store),
            ttl,
            group,
        })
    }

    /// Redis distlock provider 句柄（DI-ready dyn port）。
    #[must_use]
    pub fn lock_store(&self) -> Box<DynLockStore<'static>> {
        DynLockStore::new_box(RedisLockStore {
            store: Arc::clone(&self.store),
        })
    }

    /// Redis state-CAS provider 句柄（DI-ready dyn port）。
    #[must_use]
    pub fn cas_store(&self) -> Box<DynCasStore<'static>> {
        DynCasStore::new_box(RedisCasStore {
            store: Arc::clone(&self.store),
        })
    }
}

/// Redis 幂等 claimer provider handle：能力配置随 handle 绑定，`RedisRuntimeDeps` 只承载 pool。
#[derive(Clone)]
pub struct RedisIdempotencyStore {
    store: Arc<RedisStore>,
    ttl: Duration,
    group: ConsumerGroup,
}

impl RedisIdempotencyStore {
    /// 供组合根派生续租周期，与后端 claim TTL 同源。
    #[must_use]
    pub fn lease_ttl(&self) -> Duration {
        self.ttl
    }
}

impl IdempotencyStore for RedisIdempotencyStore {
    async fn try_claim(
        &self,
        key: &IdemKey,
        lease: &LeaseToken,
    ) -> Result<SeenState, consistency::EngineError> {
        claimer::try_claim_impl(self.store.pool(), self.ttl, &self.group, key, lease).await
    }

    async fn extend(
        &self,
        key: &IdemKey,
        lease: &LeaseToken,
    ) -> Result<LeaseOutcome, consistency::EngineError> {
        claimer::extend_impl(self.store.pool(), self.ttl, &self.group, key, lease).await
    }

    async fn commit(
        &self,
        key: &IdemKey,
        lease: &LeaseToken,
    ) -> Result<LeaseOutcome, consistency::EngineError> {
        claimer::commit_impl(self.store.pool(), &self.group, key, lease).await
    }

    async fn release(
        &self,
        key: &IdemKey,
        lease: &LeaseToken,
    ) -> Result<(), consistency::EngineError> {
        claimer::release_impl(self.store.pool(), &self.group, key, lease).await
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

    #[allow(clippy::expect_used)]
    fn group() -> ConsumerGroup {
        ConsumerGroup::parse("bundle-test").expect("non-empty group")
    }

    fn deps() -> RedisRuntimeDeps {
        RedisRuntimeDeps::setup(lazy_pool())
    }

    #[tokio::test]
    async fn setup_rejects_zero_ttl() {
        assert!(RedisRuntimeDeps::validate_ttl(Duration::ZERO).is_err());
    }

    #[tokio::test]
    async fn setup_accepts_valid_ttl() {
        assert!(
            RedisRuntimeDeps::setup_with_ttl_validation(lazy_pool(), Duration::from_millis(1))
                .is_ok()
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn infra_idempotency_shares_store_arc() {
        let d = deps();
        let store = d
            .infra()
            .idempotency(group(), Duration::from_millis(50))
            .expect("valid ttl");
        assert!(Arc::ptr_eq(&store.store, &d.store));
    }

    #[tokio::test]
    async fn clone_shares_store() {
        let d = deps();
        let c = d.clone();
        assert!(Arc::ptr_eq(&d.store, &c.store));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn lease_ttl_propagates() {
        let idem = deps()
            .infra()
            .idempotency(group(), Duration::from_millis(123))
            .expect("valid ttl");
        assert_eq!(idem.lease_ttl(), Duration::from_millis(123));
    }

    #[tokio::test]
    async fn infra_lock_and_cas_handles_construct() {
        let infra = deps().infra();
        let _lock = infra.lock_store();
        let _cas = infra.cas_store();
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
