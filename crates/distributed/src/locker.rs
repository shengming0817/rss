//! `Locker` —— typed 分布式互斥锁 facade：把 `LockKey` + TTL 经 [`diport::DynLockStore`] 落地，产出
//! 持锁凭据 [`LockGrant`]（key + fencing token + ttl）。
//!
//! 锁无 payload（区别于 crate-private maintenance state-CAS 的 typed `T`），故本 facade 不序列化——只做类型映射：
//! `LockKey` ↔ `diport::LockStoreKey`、`FencingToken` ↔ `vocab::Epoch`、port outcome ↔ `Option<LockGrant>`、
//! `diport::LockStoreError` ↔ `DistError::Transport`。
//!
//! 持有凭据 = fencing token（无独立 holder 身份，对齐 `LockGrant` 无 holder 字段）：`renew`/`release` 用 grant
//! 携带的 token 向 provider 证明持有；token 不匹配（已易手 / 过期被接管）则 `renew` 返回 `Ok(None)`、`release` no-op。
//!
//! ref: kubernetes/client-go tools/leaderelection/leaderelection.go@master（tryAcquireOrRenew lease）；
//! ref: databendlabs/openraft openraft/src/log_id/mod.rs（LogId.index 单调 = fencing token）。

use std::time::Duration;

use crate::{DistError, FencingToken, LockGrant, LockKey};
use diport::LockStore as _;

/// Typed 分布式互斥锁 facade。组合根经构造器注入 [`diport::DynLockStore`] provider（必填位置参，缺失即编译错误）。
pub struct Locker {
    store: Box<diport::DynLockStore<'static>>,
}

impl Locker {
    /// 组合根注入锁 provider（必填位置参，缺失即编译错误）。
    pub fn new(store: Box<diport::DynLockStore<'static>>) -> Self {
        Self { store }
    }

    /// 争夺 `key` 上的锁：
    /// - `Ok(Some(LockGrant))`：获取成功，grant 携新任期 fencing token + TTL。
    /// - `Ok(None)`：锁已被他者持有（未过期）——调用方退避重试 / 放弃。
    /// - `Err(DistError::Transport)`：infra 故障（port 返回 `LockStoreError`，可重试）。
    pub async fn acquire(
        &self,
        key: LockKey,
        ttl: Duration,
    ) -> Result<Option<LockGrant>, DistError> {
        let store_key = diport::LockStoreKey::new(key.as_str());
        let outcome = self.store.acquire(store_key, ttl).await.map_err(|e| {
            // reason: 不记 raw lock key（含租户/资源标识，零信任 PII 边界）——对齐 cas.rs，关联靠 tracing span 上下文。
            tracing::warn!(error = %e, "locker: acquire transport failure");
            DistError::Transport
        })?;
        match outcome {
            diport::LockAcquireOutcome::Acquired { token } => Ok(Some(LockGrant::new(
                key,
                FencingToken::new(token.get()),
                ttl,
            ))),
            // Held = 锁被他者持有（预期争用）。高频，不记日志（争用率走 metrics，非 log spam）。
            diport::LockAcquireOutcome::Held => Ok(None),
            // reason: LockAcquireOutcome 是 #[non_exhaustive]，跨 crate match 须带 catch-all；当前无此分支变体
            // （unreachable），未来新增变体保守映射为 infra 级 Fatal（fail-safe，不静默成功授锁）。
            _ => Err(DistError::Fatal),
        }
    }

    /// 续租 `grant` 持有的锁（延 TTL）：
    /// - `Ok(Some(LockGrant))`：续租成功，token 不变（同任期），TTL 重置。
    /// - `Ok(None)`：已失去锁（token 非当前持有者：过期被接管 / 已释放）——调用方停止受锁保护的写、重新 acquire。
    /// - `Err(DistError::Transport)`：infra 故障。
    pub async fn renew(&self, grant: &LockGrant) -> Result<Option<LockGrant>, DistError> {
        let store_key = diport::LockStoreKey::new(grant.key().as_str());
        let token = vocab::Epoch::new(grant.token().value());
        let outcome = self
            .store
            .renew(store_key, token, grant.ttl())
            .await
            .map_err(|e| {
                // reason: 不记 raw lock key（零信任 PII 边界）——对齐 cas.rs。
                tracing::warn!(error = %e, "locker: renew transport failure");
                DistError::Transport
            })?;
        match outcome {
            diport::LockRenewOutcome::Renewed { token } => Ok(Some(LockGrant::new(
                grant.key().clone(),
                FencingToken::new(token.get()),
                grant.ttl(),
            ))),
            // Lost = 已失去锁（过期被接管 / 已释放）——fencing 相关事件，记 debug 供排障（对齐 cas.rs Fenced debug）。
            // 不记 raw key（零信任 PII 边界）；调用方据 grant 自有上下文判定。
            diport::LockRenewOutcome::Lost => {
                tracing::debug!("locker: renew lost — 锁已被接管 / 过期");
                Ok(None)
            }
            // reason: LockRenewOutcome 是 #[non_exhaustive]，catch-all 当前 unreachable，保守兜底 Fatal（fail-safe）。
            _ => Err(DistError::Fatal),
        }
    }

    /// 释放 `grant` 持有的锁（幂等：仅当 grant token 是当前持有者才放锁，否则 provider no-op）。
    pub async fn release(&self, grant: LockGrant) -> Result<(), DistError> {
        let store_key = diport::LockStoreKey::new(grant.key().as_str());
        let token = vocab::Epoch::new(grant.token().value());
        self.store.release(store_key, token).await.map_err(|e| {
            // reason: 不记 raw lock key（零信任 PII 边界）——对齐 cas.rs。
            tracing::warn!(error = %e, "locker: release transport failure");
            DistError::Transport
        })
    }

    /// 委派注入的 provider 释放 infra 资源（生产 adapter 经 `bootstrap::ShutdownStack` 编排；本方法是 port-local 关闭路径）。
    pub async fn shutdown(&self) -> Result<(), diport::LockStoreError> {
        self.store.shutdown().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    /// FakeLockStore 内部 map 类型别名（规避 clippy::type_complexity）：key → (当前持有 token（None=空闲）, 已发最高 token)。
    type LockState = HashMap<String, (Option<vocab::Epoch>, u64)>;

    /// 内联 FakeLockStore（per-key 单调 token 互斥）——仅在 #[cfg(test)] 子树，不被 dylint impl-allowlist 扫描。
    /// 克隆共享同一底座（`Arc<Mutex>`），供测试持一份调 `evict` 模拟过期、另一份注入 facade。
    #[derive(Clone, Default)]
    struct FakeLockStore {
        state: Arc<Mutex<LockState>>,
    }

    impl FakeLockStore {
        /// 测试钩子：模拟 TTL 过期——清持有者，使下次 acquire 可接管（token 续单调）。
        fn evict(&self, key: &str) {
            let mut m = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(entry) = m.get_mut(key) {
                entry.0 = None;
            }
        }
    }

    impl diport::LockStore for FakeLockStore {
        async fn acquire(
            &self,
            key: diport::LockStoreKey,
            _ttl: Duration,
        ) -> Result<diport::LockAcquireOutcome, diport::LockStoreError> {
            let mut m = self.state.lock().unwrap_or_else(|e| e.into_inner());
            let entry = m.entry(key.as_str().to_owned()).or_insert((None, 0));
            if entry.0.is_some() {
                Ok(diport::LockAcquireOutcome::Held)
            } else {
                let token = vocab::Epoch::new(entry.1.saturating_add(1));
                entry.1 = token.get();
                entry.0 = Some(token);
                Ok(diport::LockAcquireOutcome::Acquired { token })
            }
        }

        async fn renew(
            &self,
            key: diport::LockStoreKey,
            token: vocab::Epoch,
            _ttl: Duration,
        ) -> Result<diport::LockRenewOutcome, diport::LockStoreError> {
            let m = self.state.lock().unwrap_or_else(|e| e.into_inner());
            match m.get(key.as_str()) {
                Some((Some(held), _)) if *held == token => {
                    Ok(diport::LockRenewOutcome::Renewed { token })
                }
                _ => Ok(diport::LockRenewOutcome::Lost),
            }
        }

        async fn release(
            &self,
            key: diport::LockStoreKey,
            token: vocab::Epoch,
        ) -> Result<(), diport::LockStoreError> {
            let mut m = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(entry) = m.get_mut(key.as_str())
                && entry.0 == Some(token)
            {
                entry.0 = None;
            }
            Ok(())
        }

        async fn shutdown(&self) -> Result<(), diport::LockStoreError> {
            // reason: in-mem fake store 无 infra 资源，关闭无需释放。
            Ok(())
        }
    }

    fn make_facade() -> Locker {
        Locker::new(diport::DynLockStore::<'static>::new_box(
            FakeLockStore::default(),
        ))
    }

    fn ttl() -> Duration {
        Duration::from_secs(30)
    }

    #[allow(clippy::expect_used)]
    // reason: 测试用 canonical literal 解析 LockKey，item-level carve-out。
    fn lk(s: &str) -> LockKey {
        LockKey::parse(s).expect("canonical test lock key")
    }

    /// 空闲锁 acquire → Some(LockGrant)，grant 携 token=FencingToken(1) + key + ttl。
    #[tokio::test]
    async fn acquire_free_lock_returns_grant() -> Result<(), DistError> {
        let locker = make_facade();
        let grant = locker
            .acquire(lk("tenant-1/cert-renew"), ttl())
            .await?
            .ok_or(DistError::Fatal)?;
        assert_eq!(grant.key().as_str(), "tenant-1/cert-renew");
        assert_eq!(grant.token().value(), 1);
        assert_eq!(grant.ttl(), ttl());
        Ok(())
    }

    /// 已被持有的锁 acquire → None（互斥）。
    #[tokio::test]
    async fn acquire_held_lock_returns_none() -> Result<(), DistError> {
        let locker = make_facade();
        locker.acquire(lk("k"), ttl()).await?;
        let second = locker.acquire(lk("k"), ttl()).await?;
        assert!(
            second.is_none(),
            "held lock should yield None, got {second:?}"
        );
        Ok(())
    }

    /// 持有者 renew → Some(LockGrant)，token 不变（同任期）。
    #[tokio::test]
    async fn renew_held_lock_keeps_same_token() -> Result<(), DistError> {
        let locker = make_facade();
        let grant = locker
            .acquire(lk("k"), ttl())
            .await?
            .ok_or(DistError::Fatal)?;
        let renewed = locker.renew(&grant).await?.ok_or(DistError::Fatal)?;
        assert_eq!(
            renewed.token().value(),
            grant.token().value(),
            "续租同任期 token 不变"
        );
        assert_eq!(renewed.key().as_str(), "k");
        Ok(())
    }

    /// release 后锁空闲：可被再次 acquire（token 单调 +1）。
    #[tokio::test]
    async fn released_lock_can_be_reacquired_with_monotonic_token() -> Result<(), DistError> {
        let locker = make_facade();
        let grant = locker
            .acquire(lk("k"), ttl())
            .await?
            .ok_or(DistError::Fatal)?;
        assert_eq!(grant.token().value(), 1);
        locker.release(grant).await?;
        let regrant = locker
            .acquire(lk("k"), ttl())
            .await?
            .ok_or(DistError::Fatal)?;
        assert_eq!(regrant.token().value(), 2, "释放后重获 token 单调递增");
        Ok(())
    }

    /// anti-vacuity：evict（模拟过期）后旧 grant renew → None（已失去锁），release → no-op。
    #[tokio::test]
    async fn stale_grant_after_eviction_loses_renew_and_release_is_noop() -> Result<(), DistError> {
        let store = FakeLockStore::default();
        let locker = Locker::new(diport::DynLockStore::<'static>::new_box(store.clone()));
        let grant = locker
            .acquire(lk("k"), ttl())
            .await?
            .ok_or(DistError::Fatal)?;
        assert_eq!(grant.token().value(), 1);

        // 模拟 TTL 过期 → 他者接管（token=2）。
        store.evict("k");
        let other = locker
            .acquire(lk("k"), ttl())
            .await?
            .ok_or(DistError::Fatal)?;
        assert_eq!(other.token().value(), 2);

        // 旧 grant(token=1) renew → None（已失去）。
        let lost = locker.renew(&grant).await?;
        assert!(lost.is_none(), "stale grant renew 应 None, got {lost:?}");

        // 旧 grant(token=1) release → no-op：锁仍被 token=2 持有。
        locker.release(grant).await?;
        let still_held = locker.acquire(lk("k"), ttl()).await?;
        assert!(
            still_held.is_none(),
            "旧 grant release 应 no-op，锁仍被 token=2 持有"
        );
        Ok(())
    }

    /// shutdown 委派：FakeLockStore 注入后 locker.shutdown().await 返回 Ok(())。
    #[tokio::test]
    async fn shutdown_delegates_to_store() -> Result<(), diport::LockStoreError> {
        let locker = make_facade();
        locker.shutdown().await
    }

    /// provider 永远返回 infra 错误，覆盖 `LockStore` port error → `DistError::Transport` 的 map_err 路径。
    #[derive(Default)]
    struct AlwaysFailLockStore;

    impl diport::LockStore for AlwaysFailLockStore {
        async fn acquire(
            &self,
            _key: diport::LockStoreKey,
            _ttl: Duration,
        ) -> Result<diport::LockAcquireOutcome, diport::LockStoreError> {
            Err(diport::LockStoreError::new(std::io::Error::other("boom")))
        }
        async fn renew(
            &self,
            _key: diport::LockStoreKey,
            _token: vocab::Epoch,
            _ttl: Duration,
        ) -> Result<diport::LockRenewOutcome, diport::LockStoreError> {
            Err(diport::LockStoreError::new(std::io::Error::other("boom")))
        }
        async fn release(
            &self,
            _key: diport::LockStoreKey,
            _token: vocab::Epoch,
        ) -> Result<(), diport::LockStoreError> {
            Err(diport::LockStoreError::new(std::io::Error::other("boom")))
        }
        async fn shutdown(&self) -> Result<(), diport::LockStoreError> {
            Ok(())
        }
    }

    /// port 返回 infra 错误时，acquire/renew/release 三个方法均映射为 `Err(DistError::Transport)`。
    #[tokio::test]
    async fn port_error_maps_to_transport_on_all_methods() {
        let locker = Locker::new(diport::DynLockStore::<'static>::new_box(
            AlwaysFailLockStore,
        ));
        let grant = LockGrant::new(lk("k"), FencingToken::new(1), ttl());
        assert!(matches!(
            locker.acquire(lk("k"), ttl()).await,
            Err(DistError::Transport)
        ));
        assert!(matches!(
            locker.renew(&grant).await,
            Err(DistError::Transport)
        ));
        assert!(matches!(
            locker.release(grant).await,
            Err(DistError::Transport)
        ));
    }
}
