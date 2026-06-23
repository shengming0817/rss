//! redis adapter —— RSS workspace（W 阶段真身，#1009 幂等 claimer 切片）。
//!
//! 单一 `RedisStore` 实现：
//! - 始终 `impl diport::ManagedResource`（已冻结，ADAPTER-PORT-FREEZE-09）。
//! - `backend` feature 开时增补 `impl consistency::IdempotencyStore`（`SET NX EX` claimer）。
//!
//! feature-off（default build）：空壳编译、freeze smoke 类型断言仍有效；不引入任何 infra 依赖。
//! feature-on（`--features backend`）：deadpool-redis Pool + TTL 构造，不注入 Clock（TTL 由 redis
//! 服务端 EX 管过期，与 clippy disallowed-methods 的系统时钟禁令一致）。

mod claimer;

use diport::{ManagedResource, ShutdownError};

/// Redis 幂等 claimer adapter（sealed-marker）。
///
/// `backend` feature 关时为空壳（仅供 freeze smoke 类型断言）；开时持有 deadpool-redis Pool + TTL。
pub struct RedisStore {
    #[cfg(feature = "backend")]
    pool: deadpool_redis::Pool,
    #[cfg(feature = "backend")]
    ttl: core::time::Duration,
}

/// 无效 claim TTL（构造期 fail-fast，不静默钳制）。
#[cfg(feature = "backend")]
#[derive(Debug, thiserror::Error)]
#[error("claim ttl must be at least 1ms")]
pub struct InvalidClaimTtl;

#[cfg(feature = "backend")]
impl RedisStore {
    /// 由连接池 + claim TTL 构造（无 Clock：TTL 由 redis 服务端 `PX` 管过期）。
    ///
    /// **fail-fast**：拒绝 `< 1ms` 的 TTL（亚毫秒丢精度、零非法）——错误配置在组合根接线期即暴露，
    /// 不在运行期命令层静默钳制（review F2）。
    pub fn new(
        pool: deadpool_redis::Pool,
        ttl: core::time::Duration,
    ) -> Result<Self, InvalidClaimTtl> {
        if ttl.as_millis() == 0 {
            return Err(InvalidClaimTtl);
        }
        Ok(Self { pool, ttl })
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

#[cfg(feature = "backend")]
impl consistency::IdempotencyStore for RedisStore {
    async fn check(
        &self,
        key: &consistency::IdemKey,
    ) -> Result<consistency::SeenState, consistency::EngineError> {
        // 逻辑拆出到 claimer::check_impl 控制认知复杂度。
        claimer::check_impl(&self.pool, self.ttl, key).await
    }
}

#[cfg(test)]
mod smoke {
    //! build smoke：编译期断言 sealed-marker 已 impl 冻结的 diport DI port trait。
    //! PhantomData 绑定检查——不构造、不执行 body。
    //!
    //! INVARIANT: ADAPTER-PORT-FREEZE-09 —— sealed-marker impl 冻结的 diport DI port trait；
    //! 去掉任一 impl 即编译失败（anti-vacuity）。
    use core::marker::PhantomData;

    fn assert_managed_resource<T: diport::ManagedResource>(_: PhantomData<T>) {}

    #[test]
    fn impls_frozen_ports() {
        assert_managed_resource(PhantomData::<super::RedisStore>);
    }

    #[cfg(feature = "backend")]
    fn assert_idempotency_store<T: consistency::IdempotencyStore>(_: PhantomData<T>) {}

    #[cfg(feature = "backend")]
    #[test]
    fn impls_idempotency_store() {
        assert_idempotency_store(PhantomData::<super::RedisStore>);
    }
}

// F2：构造期 TTL fail-fast（lazy pool 无需 live redis）。
#[cfg(all(test, feature = "backend"))]
mod backend_tests {
    use super::RedisStore;
    use core::time::Duration;
    use deadpool_redis::{Config, Runtime};

    #[allow(clippy::expect_used)]
    // reason: deadpool lazy pool 构造不连后端；item-level carve-out。
    fn lazy_pool() -> deadpool_redis::Pool {
        Config::from_url("redis://127.0.0.1:6379")
            .create_pool(Some(Runtime::Tokio1))
            .expect("lazy pool build")
    }

    #[test]
    fn new_rejects_zero_ttl() {
        assert!(RedisStore::new(lazy_pool(), Duration::ZERO).is_err());
    }

    #[test]
    fn new_rejects_subms_ttl() {
        // 亚毫秒（500µs）as_millis()==0 → 拒绝（不静默钳成 1ms）。
        assert!(RedisStore::new(lazy_pool(), Duration::from_micros(500)).is_err());
    }

    #[test]
    fn new_accepts_1ms_ttl() {
        assert!(RedisStore::new(lazy_pool(), Duration::from_millis(1)).is_ok());
    }
}
