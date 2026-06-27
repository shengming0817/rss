//! redis capability bundle（#1498 / RW-W-hardening）：把 pool 构造 + idempotency 能力派发 +
//! managed-resource/rollback 单源派生收口到单一 funnel，作 redis provider 的**唯一装配出口**，
//! 杜绝组合根回退多通道手写（D5）。
//!
//! 泛化自 pg `PgRuntimeDeps`/`PgInfraDeps`（#1422/#1423，ADR-010 §2.2）。redis 当前唯一能力
//! `IdempotencyStore` 是 **provider-agnostic infra**（非绑单一域，keyed by `ConsumerGroup`），故落
//! [`RedisInfraDeps`]——无 per-domain `RedisDomainDeps<D>`（redis 无 per-domain repo；不造空壳）。
//!
//! 两个类型：
//! - [`RedisRuntimeDeps`]：组合根级集中 funnel。唯一公开构造路径 [`RedisRuntimeDeps::setup`]（TTL
//!   fail-fast → 新建 `Arc<RedisStore>`）；派发 [`RedisRuntimeDeps::infra`]、产出 shutdown 资源
//!   （[`RedisRuntimeDeps::runtime_resources`] 单源）。
//! - [`RedisInfraDeps`]：framework/global 基建能力句柄——`idempotency()` 派发幂等 claimer，不绑域。
//!
//! ## INVARIANT
//!
//! - **REDIS-BUNDLE-FUNNEL-01**（Hard，可见性封装）：[`RedisRuntimeDeps::setup`] 是唯一公开 store 构造
//!   路径——`RedisStore::new` 已降 `pub(crate)`，外部无法 mint `RedisStore`，只能经 bundle 构造（funnel）。
//! - **REDIS-BUNDLE-POOL-02**（Hard）：本模块无任何返回裸 `deadpool_redis::Pool` 的公开 accessor；
//!   `RedisStore.pool` 字段私有，bundle 只派发 `Arc<RedisStore>` 能力句柄（pool 不外泄）。
//!
//! ## 单源装配（`runtime_resources`）
//!
//! adapter **不依赖 `bootstrap`**（与 pg adapter 一致），故不返回 `bootstrap::DomainModuleResult`；改经
//! [`RedisRuntimeDeps::runtime_resources`] 单源派生 `Vec<Box<DynManagedResource>>`（仅 `diport` 类型），
//! 组合根 `module.resources.extend(deps.redis.runtime_resources())` 装配进 `DomainModuleResult.resources`。
//! redis 当前只产 pool-guard resource（无 probe/worker＝syshealth 独立任务），故此即完整单源。
//!
//! ## 开源对标
//!
//! `ref: oxidecomputer/omicron nexus/src/context.rs@8eb92537bd12598dfd2c861f897a88962fabf684`——
//! `Arc<ServerContext>` 共享 infra clone 进各 server（RSS `SharedRuntimeDeps` 同 lineage）；capability-bundle
//! funnel 对标 omicron `DataStore` 集中构造 + accessor。本模块对应：`setup` 集中构造 + `Arc<RedisStore>` 私有持有
//! + `infra()` 派发受控句柄。
//!
//! ## Live 接入
//!
//! redis bundle 本轮 seam-first（无 live 消费方），live durable 接入 `SharedRuntimeDeps`/`eventexec`
//! 随 redis durable body **#1116-1120** 落地。

use core::time::Duration;
use std::sync::Arc;

use consistency::ConsumerGroup;
use deadpool_redis::Pool;
use diport::{DynManagedResource, ManagedResource, ShutdownError};

use crate::{InvalidClaimTtl, RedisStore};

/// 组合根级 redis 能力包：集中 pool 构造 + TTL 门控，派发 infra 能力句柄，并产出 shutdown 资源。
///
/// 字段私有（`store`）；不暴露裸 `Pool`（REDIS-BUNDLE-POOL-02）。经 [`RedisRuntimeDeps::setup`] 构造
/// （REDIS-BUNDLE-FUNNEL-01）。`Clone` 廉价（仅 `Arc` clone）。
#[derive(Clone)]
pub struct RedisRuntimeDeps {
    store: Arc<RedisStore>,
}

impl RedisRuntimeDeps {
    /// 唯一公开构造路径：TTL fail-fast 校验（`< 1ms` 拒绝，见 [`RedisStore::new`]）→ 新建
    /// `Arc<RedisStore>`。对标 `PgRuntimeDeps::setup`（构造器集中 + 门控，对象返回前校验）。
    ///
    /// `group` 是幂等去重 PK 的组维度（构造期绑定）；`ttl` 由 redis 服务端 `PX` 管过期（无 Clock 注入）。
    pub fn setup(pool: Pool, ttl: Duration, group: ConsumerGroup) -> Result<Self, InvalidClaimTtl> {
        Ok(Self {
            store: Arc::new(RedisStore::new(pool, ttl, group)?),
        })
    }

    /// 派发 framework/global 基建能力句柄 [`RedisInfraDeps`]——idempotency claimer 是 provider-agnostic
    /// infra（非绑单一域），故不进（不存在的）per-domain 句柄。
    #[must_use]
    pub fn infra(&self) -> RedisInfraDeps {
        RedisInfraDeps {
            store: Arc::clone(&self.store),
        }
    }

    /// 续租间隔同源：组合根经 `eventexec::LeaseConfig::from_ttl(redis.lease_ttl())` 派生续租周期，
    /// 与后端 claim TTL 同源（杜绝 mismatch footgun）。
    #[must_use]
    pub fn lease_ttl(&self) -> Duration {
        self.store.lease_ttl()
    }

    /// 包装私有 `Arc<RedisStore>` 为可注册进 `ShutdownStack` 的 guard——**不**泄漏 `Arc<RedisStore>` 本身。
    #[must_use]
    fn store_guard(&self) -> RedisStoreGuard {
        RedisStoreGuard(Arc::clone(&self.store))
    }

    /// **单源** managed-resource/rollback 派生：组合根
    /// `module.resources.extend(deps.redis.runtime_resources())` 即装配 redis 全部受管资源
    /// （当前仅 pool-guard），杜绝逐 channel 手写 `register_detached`（D5）。
    #[must_use]
    pub fn runtime_resources(&self) -> Vec<Box<DynManagedResource<'static>>> {
        vec![DynManagedResource::new_box(self.store_guard())]
    }
}

/// framework/global redis 基建能力句柄（`Clone`，provider-agnostic、非单域）。
///
/// 私有持 `Arc<RedisStore>`，经 [`RedisRuntimeDeps::infra`] 派发；只暴露 idempotency claimer——
/// 与 [`RedisRuntimeDeps`] 一样不返回裸 `Pool`（REDIS-BUNDLE-POOL-02）。
#[derive(Clone)]
pub struct RedisInfraDeps {
    store: Arc<RedisStore>,
}

impl RedisInfraDeps {
    /// 幂等 claimer 句柄（`Arc<RedisStore>`，`impl consistency::IdempotencyStore` 经 deref）。
    /// 组合根注入 `eventexec` 消费——L0 引擎策略 trait 泛型静态分发（无 dyn wrapper）。
    #[must_use]
    pub fn idempotency(&self) -> Arc<RedisStore> {
        Arc::clone(&self.store)
    }
}

/// `Arc<RedisStore>` 的 `ManagedResource` guard wrapper——`Arc` 非 fundamental ⇒ 不能直接
/// `impl ManagedResource for Arc<RedisStore>`（孤儿规则），故经 newtype（对标 `PgStoreGuard`）。
/// LIFO 注册：guard 先注册 ⇒ 最后关池。
/// crate 内可见（`pub(crate)`）：组合根只经 `runtime_resources()` 消费 `Box<DynManagedResource>`，
/// 无需命名 guard 类型本身。
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
    //! bundle 单元测：lazy pool（不发真实连接）旁路真实 redis，覆盖 funnel 派发 + accessor 构造 +
    //! 单源 runtime_resources。
    //! INVARIANT: REDIS-BUNDLE-FUNNEL-01 / REDIS-BUNDLE-POOL-02。

    use super::*;
    use deadpool_redis::{Config, Runtime};

    #[allow(clippy::expect_used)] // reason: deadpool lazy pool 构造不连后端；item-level carve-out。
    fn lazy_pool() -> Pool {
        Config::from_url("redis://127.0.0.1:6379")
            .create_pool(Some(Runtime::Tokio1))
            .expect("lazy pool build")
    }

    #[allow(clippy::expect_used)] // reason: 非空组名 parse 必过；item-level carve-out。
    fn group() -> ConsumerGroup {
        ConsumerGroup::parse("bundle-test").expect("non-empty group")
    }

    #[allow(clippy::expect_used)] // reason: 1ms TTL 合法，setup 必成功；item-level carve-out。
    fn deps() -> RedisRuntimeDeps {
        RedisRuntimeDeps::setup(lazy_pool(), Duration::from_millis(50), group())
            .expect("valid setup")
    }

    // sqlx-style：lazy pool 需 Tokio context，故 `#[tokio::test]`（body 不 await）。

    #[tokio::test]
    async fn setup_rejects_zero_ttl() {
        assert!(RedisRuntimeDeps::setup(lazy_pool(), Duration::ZERO, group()).is_err());
    }

    #[tokio::test]
    async fn setup_accepts_valid_ttl() {
        assert!(RedisRuntimeDeps::setup(lazy_pool(), Duration::from_millis(1), group()).is_ok());
    }

    #[tokio::test]
    async fn infra_idempotency_shares_store_arc() {
        let d = deps();
        let store = d.infra().idempotency();
        // REDIS-BUNDLE-POOL-02：句柄内部 store 与 runtime deps 同一 Arc（in-crate 验证私有字段）。
        assert!(
            Arc::ptr_eq(&store, &d.store),
            "infra().idempotency() 共享 store Arc"
        );
    }

    #[tokio::test]
    async fn clone_shares_store() {
        let d = deps();
        let c = d.clone();
        assert!(
            Arc::ptr_eq(&d.store, &c.store),
            "clone 廉价共享 store Arc（非深拷贝）"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)] // reason: 1ms+ TTL 合法，setup 必成功；item-level carve-out。
    async fn lease_ttl_propagates() {
        let d = RedisRuntimeDeps::setup(lazy_pool(), Duration::from_millis(123), group())
            .expect("valid setup");
        assert_eq!(d.lease_ttl(), Duration::from_millis(123));
    }

    #[tokio::test]
    async fn store_guard_name_is_redis() {
        assert_eq!(deps().store_guard().name(), "redis");
    }

    #[tokio::test]
    async fn runtime_resources_single_sources_pool_guard() {
        let resources = deps().runtime_resources();
        assert_eq!(resources.len(), 1, "redis 当前只产 pool-guard 单一受管资源");
        assert_eq!(
            resources[0].name(),
            "redis",
            "单源 resource 即 redis pool guard"
        );
    }
}
