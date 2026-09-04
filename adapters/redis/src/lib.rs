//! Redis adapter for cluster-global lock, CAS, rate-limit, and managed-resource capabilities.
//!
//! 单一 `RedisStore` 资源 + typed handles：
//! - `RedisStore` 始终 `impl rss_runtime::ManagedResource`（已冻结，ADAPTER-PORT-FREEZE-09）。
//!
//! feature-off（default build）：空壳编译、freeze smoke 类型断言仍有效；不引入任何 infra 依赖。
//! feature-on（`--features backend`）：deadpool-redis Pool + TTL 构造，不注入 Clock（TTL 由 redis
//! 服务端 PX 管过期，与 clippy disallowed-methods 的系统时钟禁令一致）。

#[cfg(feature = "backend")]
mod bundle;
#[cfg(feature = "backend")]
mod cas;
#[cfg(feature = "backend")]
mod lock;
#[cfg(feature = "backend")]
mod rate_limit;
#[cfg(feature = "integration")]
mod saga_effect_fixture;

#[cfg(feature = "backend")]
pub use bundle::{
    RedisCasStore, RedisConnectError, RedisInfraDeps, RedisLockStore, RedisPingError,
    RedisPrivateCa, RedisPrivateCaError, RedisRuntimeDeps,
};
#[cfg(feature = "backend")]
pub use rate_limit::{
    InvalidRateLimitNamespace, RedisRateLimitCapabilityError, RedisRateLimiter,
    RedisRateLimiterCapability,
};
#[cfg(feature = "integration")]
pub use saga_effect_fixture::{
    RedisSagaEffectApplyOutcome, RedisSagaEffectError, RedisSagaEffectFixture,
    RedisSagaEffectObservation, RedisSagaEffectProbeOutcome,
};

use rss_runtime::{ManagedResource, ShutdownError};

/// Redis adapter store（sealed-marker）。
///
/// `backend` feature 关时为空壳（仅供 freeze smoke 类型断言）；开时只持有 deadpool-redis Pool。具体能力
/// （distlock / CAS）由 bundle 派发的 typed handle 绑定其自身配置，避免把某个能力的
/// `ConsumerGroup`/TTL 污染到整个 redis runtime bundle。
pub struct RedisStore {
    #[cfg(feature = "backend")]
    pool: deadpool_redis::Pool,
}

/// Invalid Redis-backed lease duration.
#[cfg(feature = "backend")]
#[derive(Debug, thiserror::Error)]
#[error("lease ttl must be at least 1ms")]
pub(crate) struct InvalidLeaseTtl;

#[cfg(feature = "backend")]
impl RedisStore {
    /// 由连接池构造 redis store。
    ///
    /// `pub(crate)`：生产公开构造路径是 [`RedisRuntimeDeps::connect_with_private_ca`]
    /// （funnel，REDIS-BUNDLE-FUNNEL-01）；外部 crate 不能直接 mint `RedisStore`，须经 bundle 装配出口。
    pub(crate) fn new(pool: deadpool_redis::Pool) -> Self {
        Self { pool }
    }

    pub(crate) fn pool(&self) -> &deadpool_redis::Pool {
        &self.pool
    }
}

/// INVARIANT: ADAPTER-PORT-FREEZE-09 { level = "Hard", exec = "native-compile", source = "code", native = "sealed ManagedResource implementation on the production provider" }.
impl ManagedResource for RedisStore {
    fn name(&self) -> &str {
        "redis"
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        #[cfg(feature = "backend")]
        self.pool.close(); // 关闭连接池（释放后端连接）
        // reason: feature-off 无 infra 资源，关闭无需释放。
        Ok(())
    }
}

#[cfg(test)]
mod smoke {
    //! build smoke：编译期断言 sealed-marker 已 impl 冻结的 diport DI port trait。
    //! PhantomData 绑定检查——不构造、不执行 body。
    //!
    //! ADAPTER-PORT-FREEZE-09 support：sealed-marker impl 冻结的 diport DI port trait；
    //! 去掉任一 impl 即编译失败（anti-vacuity）。
    use core::marker::PhantomData;

    fn assert_managed_resource<T: rss_runtime::ManagedResource>(_: PhantomData<T>) {}

    #[test]
    fn impls_frozen_ports() {
        assert_managed_resource(PhantomData::<super::RedisStore>);
    }

    #[cfg(feature = "backend")]
    fn assert_cas_store<T: diport::CasStore>(_: PhantomData<T>) {}
    #[cfg(feature = "backend")]
    fn assert_lock_store<T: diport::LockStore>(_: PhantomData<T>) {}
    #[cfg(feature = "backend")]
    fn assert_rate_limiter<T: diport::RateLimiter>(_: PhantomData<T>) {}

    #[cfg(feature = "backend")]
    #[test]
    fn impls_backend_ports() {
        assert_cas_store(PhantomData::<super::RedisCasStore>);
        assert_lock_store(PhantomData::<super::RedisLockStore>);
        assert_rate_limiter(PhantomData::<super::RedisRateLimiter>);
    }
}
