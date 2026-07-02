//! redis adapter —— RSS workspace（W 阶段真身，#1009 幂等 claimer 切片）。
//!
//! 单一 `RedisStore` 资源 + typed handles：
//! - `RedisStore` 始终 `impl diport::ManagedResource`（已冻结，ADAPTER-PORT-FREEZE-09）。
//! - `backend` feature 开时暴露 `RedisInboxStore: consistency::InboxStore`（`SET NX PX` claimer）。
//!
//! feature-off（default build）：空壳编译、freeze smoke 类型断言仍有效；不引入任何 infra 依赖。
//! feature-on（`--features backend`）：deadpool-redis Pool + TTL 构造，不注入 Clock（TTL 由 redis
//! 服务端 PX 管过期，与 clippy disallowed-methods 的系统时钟禁令一致）。

mod claimer;

#[cfg(feature = "backend")]
mod bundle;
#[cfg(feature = "backend")]
mod cas;
#[cfg(feature = "backend")]
mod lock;

#[cfg(feature = "backend")]
pub use bundle::{
    RedisCasStore, RedisInboxStore, RedisInfraDeps, RedisLockStore, RedisPingError,
    RedisRuntimeDeps,
};

use diport::{ManagedResource, ShutdownError};

/// Redis adapter store（sealed-marker）。
///
/// `backend` feature 关时为空壳（仅供 freeze smoke 类型断言）；开时只持有 deadpool-redis Pool。具体能力
/// （幂等 claimer / distlock / CAS）由 bundle 派发的 typed handle 绑定其自身配置，避免把某个能力的
/// `ConsumerGroup`/TTL 污染到整个 redis runtime bundle。
pub struct RedisStore {
    #[cfg(feature = "backend")]
    pool: deadpool_redis::Pool,
}

/// 无效 claim TTL（构造期 fail-fast，不静默钳制）。
#[cfg(feature = "backend")]
#[derive(Debug, thiserror::Error)]
#[error("claim ttl must be at least 1ms")]
pub struct InvalidClaimTtl;

#[cfg(feature = "backend")]
impl RedisStore {
    /// 由连接池构造 redis store。
    ///
    /// `pub(crate)`：唯一公开构造路径是 [`RedisRuntimeDeps::setup`]（funnel，REDIS-BUNDLE-FUNNEL-01）；
    /// 外部 crate 不能直接 mint `RedisStore`，须经 bundle 装配出口。
    pub(crate) fn new(pool: deadpool_redis::Pool) -> Self {
        Self { pool }
    }

    pub(crate) fn pool(&self) -> &deadpool_redis::Pool {
        &self.pool
    }
}

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
    //! INVARIANT: ADAPTER-PORT-FREEZE-09 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" }—— sealed-marker impl 冻结的 diport DI port trait；
    //! 去掉任一 impl 即编译失败（anti-vacuity）。
    use core::marker::PhantomData;

    fn assert_managed_resource<T: diport::ManagedResource>(_: PhantomData<T>) {}

    #[test]
    fn impls_frozen_ports() {
        assert_managed_resource(PhantomData::<super::RedisStore>);
    }

    #[cfg(feature = "backend")]
    fn assert_inbox_store<T: consistency::InboxStore>(_: PhantomData<T>) {}
    #[cfg(feature = "backend")]
    fn assert_cas_store<T: diport::CasStore>(_: PhantomData<T>) {}
    #[cfg(feature = "backend")]
    fn assert_lock_store<T: diport::LockStore>(_: PhantomData<T>) {}

    #[cfg(feature = "backend")]
    #[test]
    fn impls_inbox_store() {
        assert_inbox_store(PhantomData::<super::RedisInboxStore>);
        assert_cas_store(PhantomData::<super::RedisCasStore>);
        assert_lock_store(PhantomData::<super::RedisLockStore>);
    }
}

// F2：构造期 TTL fail-fast（lazy pool 无需 live redis）。
#[cfg(all(test, feature = "backend"))]
mod backend_tests {
    use super::{InvalidClaimTtl, RedisRuntimeDeps};
    use core::time::Duration;
    use deadpool_redis::{Config, Runtime};

    #[allow(clippy::expect_used)]
    // reason: deadpool lazy pool 构造不连后端；item-level carve-out。
    fn lazy_pool() -> deadpool_redis::Pool {
        Config::from_url("redis://127.0.0.1:6379")
            .create_pool(Some(Runtime::Tokio1))
            .expect("lazy pool build")
    }

    fn validate_ttl(ttl: Duration) -> Result<(), InvalidClaimTtl> {
        RedisRuntimeDeps::validate_ttl(ttl)
    }

    #[test]
    fn new_rejects_zero_ttl() {
        assert!(validate_ttl(Duration::ZERO).is_err());
    }

    #[test]
    fn new_rejects_subms_ttl() {
        // 亚毫秒（500µs）as_millis()==0 → 拒绝（不静默钳成 1ms）。
        assert!(validate_ttl(Duration::from_micros(500)).is_err());
    }

    #[test]
    fn new_accepts_1ms_ttl() {
        let _pool = lazy_pool();
        assert!(validate_ttl(Duration::from_millis(1)).is_ok());
    }
}
