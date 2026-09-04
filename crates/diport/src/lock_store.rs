//! `LockStore` —— 分布式互斥锁 provider DI port（可替换：prod etcd/Redis/Consul / test in-mem）。
//!
//! **按 key 互斥**接缝：consumer 携 `key` + `ttl` 争夺锁，provider 维护**每个 key 各自**的 per-key 单调
//! fencing token；锁的持有凭据**就是 token**（无独立 holder 身份——对齐 `distributed::LockGrant{key,token,ttl}`
//! 无 holder 字段，区别于 [`crate::LeaderElector`] 的全局单 leader + `LeaderId`）：
//! - **空闲 / 已过期** → [`LockAcquireOutcome::Acquired`]（授予**新任期** token，per-key 单调 `+1`）；
//! - **已被他者持有**（未过期）→ [`LockAcquireOutcome::Held`]（本次未获取）；
//! - **续租**（`token` 匹配当前持有者）→ [`LockRenewOutcome::Renewed`]（延 TTL，**同任期** token 不变）；
//!   `token` 不匹配（已易手 / 过期被接管）→ [`LockRenewOutcome::Lost`]；
//! - **释放**幂等：仅当 `token` 是当前持有者才放锁，否则 no-op（不误释他人锁 / stale token）。
//!
//! `ttl` 是租约时长（holder 须在过期前 `renew` 续租；超时未续 ⇒ 他者可 `acquire` 接管，token 单调递增）。
//!
//! ref: kubernetes/client-go tools/leaderelection/leaderelection.go@master（`tryAcquireOrRenew` 争夺/续租
//!   入口 + 单调任期 transition）；RSS 把全局选举推广为**按 key 互斥锁**、用 token-as-capability 替 holder identity。
//! ref: databendlabs/openraft openraft/src/log_id/mod.rs（LogId.index 单调 derive Ord = fencing token 防脑裂）；
//! Martin Kleppmann《DDIA》§8.3 fencing token（storage 拒绝 token 低于已见高水位的写）。
//! INVARIANT: DISTLOCK-FENCE-MONO-01 { level = "Medium", exec = "manual/opt-in", source = "code" }（**per-key** fencing token 单调 + 互斥语义：空闲/过期受、已持有回 Held、
//! 续租 token 不变、易手 `+1`、stale token renew→Lost / release→no-op。回归见 `adapters/memory` MemLockStore
//! 测试 + 本模块 smoke reference impl）。该不变式是 **Medium（运行期 `#[test]`）固有**：单调性是对**运行期**
//! token 值的比较（当前持有者在运行期才知），无法上移编译期类型系统；守卫 = adapter 行为测试 + anti-vacuity
//! （evict 后旧 token renew 必 Lost / release 必 no-op），非 Hard。

use std::time::Duration;

use dynosaur::dynosaur;

use rss_redact::RedactedSource;

/// 锁 key（互斥 / fencing 维度）。provider 按 key **各自**维护单调 token。
/// newtype funnel（私有字段，单一构造入口）——独立语义不复用裸 `String`。
/// 字节端口层 key，对应 typed facade `distributed::LockKey`（经 `Locker` 映射）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LockStoreKey(String);

impl LockStoreKey {
    /// 由锁资源标识构造（如 `tenant-42/reconcile/cert-3`、设备收敛 key）。
    pub fn new(key: impl Into<String>) -> Self {
        Self(key.into())
    }
    /// 借出底层 key。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// acquire 结论（typed outcome，非 error——「已被持有」是预期控制流，对标 [`crate::WriteOutcome`] /
/// `crate::CasStoreOutcome`）。token 是版本元数据，可观测，无 payload ⇒ 无需手写脱敏 `Debug`。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LockAcquireOutcome {
    /// 获取成功：锁空闲 / 已过期，授予**新任期** fencing token（per-key 单调 `+1`）。
    Acquired { token: vocab::Epoch },
    /// 锁已被他者持有（未过期）——本次未获取，调用方应退避后重试或放弃。
    Held,
}

/// renew 结论（typed outcome）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LockRenewOutcome {
    /// 续租成功：`token` 仍是当前持有者，延 TTL，**同任期** token 不变。
    Renewed { token: vocab::Epoch },
    /// 已失去锁：`token` 非当前持有者（过期被接管 / 已释放）——调用方应停止受锁保护的写、重新 acquire。
    Lost,
}

/// 锁操作失败（infra 故障，**非** Held/Lost——后两者是 outcome 的 `Ok`）。
///
/// PII 边界（与 [`crate::SignerError`] / `crate::CasStoreError` 同范式）：source 经 [`RedactedSource`] 脱敏。
/// 见 INVARIANT: DIPORT-ERR-SOURCE-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }。
#[derive(Debug, thiserror::Error)]
#[error("lock store operation failed")]
pub struct LockStoreError {
    #[source]
    source: RedactedSource,
}

impl LockStoreError {
    /// 把 adapter 内部错误包成锁操作失败。原始错误仅作 internal source 保留，不经 `Display` 暴露（PII 边界）。
    pub fn new<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            source: RedactedSource::new(source),
        }
    }
}

/// 分布式互斥锁 provider DI port（async）。
///
/// 公开 [`LockStore`] 是 **Send 变体**（adapters `impl LockStore for ...`），[`DynLockStore`] 是其
/// dyn-compatible wrapper（组合根经 `Box<DynLockStore>` 注入、`distributed::Locker` facade 消费）。
/// 非 Send 基 trait `LockStoreLocal` 不在 crate 根 re-export。
#[trait_variant::make(LockStore: Send)]
#[dynosaur(pub DynLockStore = dyn(box) LockStore, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: base trait 为非 Send native AFIT；Send 由 trait_variant 生成的 `LockStore` 变体 +
// dynosaur `DynLockStore` 承载（DI 注入走 Send wrapper）。这是 ADR-003 既定 dyn-port 范式。
pub trait LockStoreLocal {
    /// 争夺 `key` 上的锁：空闲 / 已过期 ⇒ [`LockAcquireOutcome::Acquired`]（授新任期单调 token）；
    /// 已被他者持有 ⇒ [`LockAcquireOutcome::Held`]。`ttl` = 租约时长；`Err` 仅表 infra 故障。
    async fn acquire(
        &self,
        key: LockStoreKey,
        ttl: Duration,
    ) -> Result<LockAcquireOutcome, LockStoreError>;

    /// 续租 `key` 上的锁：`token` 匹配当前持有者 ⇒ [`LockRenewOutcome::Renewed`]（延 TTL，同任期 token 不变）；
    /// 否则 ⇒ [`LockRenewOutcome::Lost`]（已易手 / 过期被接管）。`Err` 仅表 infra 故障。
    async fn renew(
        &self,
        key: LockStoreKey,
        token: vocab::Epoch,
        ttl: Duration,
    ) -> Result<LockRenewOutcome, LockStoreError>;

    /// 释放 `key` 上的锁：仅当 `token` 是当前持有者才放锁；否则幂等 no-op（不误释他人锁 / stale token）。
    async fn release(&self, key: LockStoreKey, token: vocab::Epoch) -> Result<(), LockStoreError>;

    /// 异步释放 provider 资源（无 async Drop）。有 infra 资源的 adapter 应同时 `impl ManagedResource`
    /// 由 `rss_runtime::ShutdownStack` 统一编排；本方法是 port-local 关闭路径。
    async fn shutdown(&self) -> Result<(), LockStoreError>;
}

#[cfg(test)]
mod smoke {
    //! build smoke：证明 async DI port 可 native AFIT impl + 经 `Box<DynLockStore>` 跨 spawn（Send）动态注入，
    //! 并以一个 per-key token 单调 reference impl 断言 Acquired/Held/Renewed/Lost 契约（DISTLOCK-FENCE-MONO-01）。
    use super::{
        DynLockStore, LockAcquireOutcome, LockRenewOutcome, LockStore, LockStoreError, LockStoreKey,
    };
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::Duration;

    #[test]
    fn lock_store_error_redacts_source() {
        let err = LockStoreError::new(std::io::Error::other("leak-marker-lock"));
        assert_eq!(err.to_string(), "lock store operation failed");
        assert!(std::error::Error::source(&err).is_some());
        // anti-vacuity：内层自身 Debug 携 marker，wrapper Debug 经 RedactedSource 脱敏不泄漏。
        assert!(
            format!("{:?}", std::io::Error::other("leak-marker-lock")).contains("leak-marker-lock")
        );
        assert!(
            !format!("{err:?}").contains("leak-marker-lock"),
            "source 泄漏: {err:?}"
        );
    }

    #[test]
    fn lock_store_key_round_trips() {
        let key = LockStoreKey::new("tenant-42/reconcile/cert-3");
        assert_eq!(key.as_str(), "tenant-42/reconcile/cert-3");
    }

    /// per-key 单调 token reference store：`held`=当前持有 token（None=空闲），`minted`=该 key 已发最高 token。
    #[derive(Default)]
    struct LockMap {
        state: Mutex<HashMap<String, (Option<vocab::Epoch>, u64)>>,
    }

    impl LockMap {
        /// 测试钩子：模拟 TTL 过期 / holder crash——清持有者，使下次 acquire 可接管（token 续单调）。
        fn evict(&self, key: &str) {
            let mut m = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(entry) = m.get_mut(key) {
                entry.0 = None;
            }
        }
    }

    impl LockStore for LockMap {
        async fn acquire(
            &self,
            key: LockStoreKey,
            _ttl: Duration,
        ) -> Result<LockAcquireOutcome, LockStoreError> {
            let mut m = self.state.lock().unwrap_or_else(|e| e.into_inner());
            let entry = m.entry(key.as_str().to_owned()).or_insert((None, 0));
            if entry.0.is_some() {
                Ok(LockAcquireOutcome::Held)
            } else {
                let token = vocab::Epoch::new(entry.1.saturating_add(1));
                entry.1 = token.get();
                entry.0 = Some(token);
                Ok(LockAcquireOutcome::Acquired { token })
            }
        }

        async fn renew(
            &self,
            key: LockStoreKey,
            token: vocab::Epoch,
            _ttl: Duration,
        ) -> Result<LockRenewOutcome, LockStoreError> {
            let m = self.state.lock().unwrap_or_else(|e| e.into_inner());
            match m.get(key.as_str()) {
                Some((Some(held), _)) if *held == token => Ok(LockRenewOutcome::Renewed { token }),
                _ => Ok(LockRenewOutcome::Lost),
            }
        }

        async fn release(
            &self,
            key: LockStoreKey,
            token: vocab::Epoch,
        ) -> Result<(), LockStoreError> {
            let mut m = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(entry) = m.get_mut(key.as_str())
                && entry.0 == Some(token)
            {
                entry.0 = None;
            }
            Ok(())
        }

        async fn shutdown(&self) -> Result<(), LockStoreError> {
            // reason: in-mem reference store 无 infra 资源，关闭无需释放。
            Ok(())
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn lock_store_is_dyn_injectable_and_honors_mutex_and_fencing() {
        let store: Box<DynLockStore> = DynLockStore::new_box(LockMap::default());
        let outcome = tokio::spawn(async move {
            let ttl = Duration::from_secs(30);

            // 空闲 → Acquired{token=1}。
            let first = store.acquire(LockStoreKey::new("lock-a"), ttl).await?;
            assert_eq!(
                first,
                LockAcquireOutcome::Acquired {
                    token: vocab::Epoch::new(1)
                }
            );

            // 已持有 → Held（互斥）。
            let again = store.acquire(LockStoreKey::new("lock-a"), ttl).await?;
            assert_eq!(again, LockAcquireOutcome::Held);

            // 持有者续租 → Renewed，token 不变（同任期）。
            let renewed = store
                .renew(LockStoreKey::new("lock-a"), vocab::Epoch::new(1), ttl)
                .await?;
            assert_eq!(
                renewed,
                LockRenewOutcome::Renewed {
                    token: vocab::Epoch::new(1)
                }
            );

            store.shutdown().await?;
            Ok::<_, LockStoreError>(())
        })
        .await;
        assert!(matches!(outcome, Ok(Ok(()))));
    }

    /// anti-vacuity：evict（模拟过期）后他者 acquire 获**单调递增** token；旧 token renew→Lost、release→no-op。
    #[tokio::test]
    async fn evicted_lock_reacquires_with_monotonic_token_and_old_token_loses()
    -> Result<(), LockStoreError> {
        let store = LockMap::default();
        let ttl = Duration::from_secs(30);

        let first = store.acquire(LockStoreKey::new("k"), ttl).await?;
        assert_eq!(
            first,
            LockAcquireOutcome::Acquired {
                token: vocab::Epoch::new(1)
            }
        );

        // 模拟 TTL 过期。
        store.evict("k");

        // 他者接管 → token 单调 +1（=2），证明 evict 不回退 minted。
        let second = store.acquire(LockStoreKey::new("k"), ttl).await?;
        assert_eq!(
            second,
            LockAcquireOutcome::Acquired {
                token: vocab::Epoch::new(2)
            }
        );

        // 旧 token(1) 续租 → Lost（已易手）。
        let lost = store
            .renew(LockStoreKey::new("k"), vocab::Epoch::new(1), ttl)
            .await?;
        assert_eq!(lost, LockRenewOutcome::Lost);

        // 旧 token(1) 释放 → no-op（不误释新持有者 token=2 的锁）。
        store
            .release(LockStoreKey::new("k"), vocab::Epoch::new(1))
            .await?;
        let still_held = store.acquire(LockStoreKey::new("k"), ttl).await?;
        assert_eq!(
            still_held,
            LockAcquireOutcome::Held,
            "旧 token release 应 no-op，锁仍被 token=2 持有"
        );
        Ok(())
    }

    /// 显式 release 后锁空闲：再 acquire 得**单调 +1** token（minted 不因 release 回退）。
    #[tokio::test]
    async fn release_then_reacquire_is_monotonic() -> Result<(), LockStoreError> {
        let store = LockMap::default();
        let ttl = Duration::from_secs(30);

        let first = store.acquire(LockStoreKey::new("k"), ttl).await?;
        assert_eq!(
            first,
            LockAcquireOutcome::Acquired {
                token: vocab::Epoch::new(1)
            }
        );

        // 持有者主动释放（token 匹配 → 放锁）。
        store
            .release(LockStoreKey::new("k"), vocab::Epoch::new(1))
            .await?;

        // 释放后重获 → token 单调 +1（=2），证明 release 不回退 minted。
        let second = store.acquire(LockStoreKey::new("k"), ttl).await?;
        assert_eq!(
            second,
            LockAcquireOutcome::Acquired {
                token: vocab::Epoch::new(2)
            },
            "release 后重获 token 应单调递增到 2"
        );
        Ok(())
    }
}
