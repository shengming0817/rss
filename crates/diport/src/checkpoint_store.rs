//! `OwnerCheckpointStore` —— owner 断点续投 DI port（可替换：prod postgres / test in-mem）。
//!
//! saga journal resume 与 projection 断点续投共享：`(owner, checkpoint_id)` 主键 + `offset`（已处理
//! 位点 [`Lsn`]）+ `version`（CAS 版本）。`save_checkpoint` 经**版本 CAS** 推进——`expected` 与存储版本
//! 不符即 [`SaveOutcome::StaleVersion`]（旧写被拒，并发执行器/投影实例 fence），不静默覆盖。
//!
//! 数据无 PII（仅 owner 标识 + 偏移 + 版本，均为路由 / 版本元数据），故无 payload Debug 脱敏；
//! 错误 source 仍经 [`RedactedSource`] 脱敏（adapter 原始错误可能携连接串）。
//!
//! ref: oxidecomputer/steno（saga 进度 checkpoint）+ `contracts/**/contract.toml`、`generated` 与 `crates/consistency`）。

use dynosaur::dynosaur;

use consistency::Lsn;

use rss_redact::RedactedSource;

// ── owner / checkpoint id newtype funnel ──────────────────────────────────────

/// checkpoint owner（saga：saga 域 owner；projection：projector owner）。newtype funnel（私有字段，
/// 单一构造入口）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CheckpointOwner(String);

impl CheckpointOwner {
    /// 由 owner 标识构造。
    pub fn new(owner: impl Into<String>) -> Self {
        Self(owner.into())
    }
    /// 借出底层 owner。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// checkpoint 标识（saga：saga 实例 id；projection：事件流 / 投影标识）。newtype funnel。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CheckpointId(String);

impl CheckpointId {
    /// 由标识构造（如 saga uuid 串、投影名）。
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
    /// 借出底层标识。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// CAS 版本（单调递增；`save_checkpoint` 成功后推进到 `expected.next()`）。首存用
/// [`CheckpointVersion::INITIAL`] 表「期望无既存行」。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CheckpointVersion(u64);

impl CheckpointVersion {
    /// 首存期望版本——表「期望无既存行」。`save_checkpoint(expected = INITIAL)` ⇒ 仅当行不存在时插入。
    pub const INITIAL: CheckpointVersion = CheckpointVersion(0);

    /// 由版本号构造。
    pub fn new(v: u64) -> Self {
        Self(v)
    }
    /// 取底层版本号。
    pub fn get(&self) -> u64 {
        self.0
    }
    /// 下一版本（CAS 成功后高水位推进）。
    pub fn next(&self) -> Self {
        Self(self.0 + 1)
    }
}

/// 读到的 checkpoint：已处理位点 + 当前 CAS 版本（save 时回传作 `expected`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checkpoint {
    /// 已处理位点（saga：已完成 step 数；projection：已处理事件 Lsn）。
    pub offset: Lsn,
    /// 当前 CAS 版本（下次 `save_checkpoint` 的 `expected`）。
    pub version: CheckpointVersion,
}

/// CAS 保存结论（typed outcome，非 error —— 版本竞争是预期控制流，对标
/// [`crate::WriteOutcome::Fenced`]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SaveOutcome {
    /// 已保存（`expected` 与存储版本一致 / 首存无既存行），版本推进到 `expected.next()`。
    Saved,
    /// 版本失配（`expected` ≠ 存储版本）——并发执行器/投影写被拒；调用方应重读 checkpoint 再决策。
    StaleVersion,
}

// ── 错误 ──────────────────────────────────────────────────────────────────────

/// checkpoint 操作失败（infra 故障，**非** 版本竞争——竞争是 [`SaveOutcome::StaleVersion`] 的 `Ok`）。
///
/// PII 边界（与 [`crate::SignerError`] 同范式）：`Display` 仅安全摘要常量；source 经 [`RedactedSource`]
/// 脱敏。见 INVARIANT: DIPORT-ERR-SOURCE-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }。
#[derive(Debug, thiserror::Error)]
#[error("checkpoint store operation failed")]
pub struct CheckpointStoreError {
    #[source]
    source: RedactedSource,
}

impl CheckpointStoreError {
    /// 把 adapter 内部错误包成 checkpoint 操作失败。原始错误仅作 internal source 保留，不经 `Display`
    /// 暴露（PII 边界）。
    pub fn new<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            source: RedactedSource::new(source),
        }
    }
}

// ── OwnerCheckpointStore DI port（async）──────────────────────────────────────

/// owner 断点续投 DI port（async）。
///
/// 公开 [`OwnerCheckpointStore`] 是 **Send 变体**（adapters `impl OwnerCheckpointStore for ...`），
/// [`DynOwnerCheckpointStore`] 是其 dyn-compatible wrapper（组合根经 `Box<DynOwnerCheckpointStore>` /
/// `Arc<...>` 注入）。非 Send 基 trait `OwnerCheckpointStoreLocal` 不在 crate 根 re-export。
#[trait_variant::make(OwnerCheckpointStore: Send)]
#[dynosaur(pub DynOwnerCheckpointStore = dyn(box) OwnerCheckpointStore, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: base trait 为非 Send native AFIT；Send 由 trait_variant 生成的 `OwnerCheckpointStore` 变体 +
// dynosaur `DynOwnerCheckpointStore` 承载（DI 注入走 Send wrapper）。这是 ADR-003 既定 dyn-port 范式。
pub trait OwnerCheckpointStoreLocal {
    /// 读 `(owner, id)` 当前 checkpoint。`None` ⇒ 从未保存（调用方从 version 0 / Lsn 0 起）。
    async fn get_checkpoint(
        &self,
        owner: &CheckpointOwner,
        id: &CheckpointId,
    ) -> Result<Option<Checkpoint>, CheckpointStoreError>;

    /// CAS 保存：仅当存储版本 == `expected` 时成功；成功则存 `offset` 并把版本推进到 `expected.next()`，
    /// 返回 [`SaveOutcome::Saved`]；版本失配返回 [`SaveOutcome::StaleVersion`]。`Err` 仅表 infra 故障。
    ///
    /// `expected` 语义：
    /// - `expected == CheckpointVersion::INITIAL`（0）= 首存（仅当行不存在时插入）；
    /// - `expected > 0` = CAS 更新（期望当前版本 == expected，并发写者版本不符被拒）。
    async fn save_checkpoint(
        &self,
        owner: &CheckpointOwner,
        id: &CheckpointId,
        offset: Lsn,
        expected: CheckpointVersion,
    ) -> Result<SaveOutcome, CheckpointStoreError>;

    /// 异步释放 provider 资源（无 async Drop）。有 infra 资源的 adapter 应同时 `impl ManagedResource`
    /// 由 `bootstrap::ShutdownStack` 统一编排；本方法是 port-local 关闭路径。
    async fn shutdown(&self) -> Result<(), CheckpointStoreError>;
}

#[cfg(test)]
mod smoke {
    //! build smoke：async DI port 可 native AFIT impl + 经 `Box<DynOwnerCheckpointStore>` 跨 spawn 注入。
    use super::{
        Checkpoint, CheckpointId, CheckpointOwner, CheckpointStoreError, CheckpointVersion,
        DynOwnerCheckpointStore, OwnerCheckpointStore, SaveOutcome,
    };
    use consistency::Lsn;

    #[test]
    fn checkpoint_version_next_is_monotone() {
        let v = CheckpointVersion::new(3);
        assert_eq!(v.next().get(), 4);
        assert!(v < v.next());
    }

    struct StaticStore;
    impl OwnerCheckpointStore for StaticStore {
        async fn get_checkpoint(
            &self,
            _owner: &CheckpointOwner,
            _id: &CheckpointId,
        ) -> Result<Option<Checkpoint>, CheckpointStoreError> {
            Ok(Some(Checkpoint {
                offset: Lsn::new(2),
                version: CheckpointVersion::new(1),
            }))
        }
        async fn save_checkpoint(
            &self,
            _owner: &CheckpointOwner,
            _id: &CheckpointId,
            _offset: Lsn,
            _expected: CheckpointVersion,
        ) -> Result<SaveOutcome, CheckpointStoreError> {
            Ok(SaveOutcome::Saved)
        }
        async fn shutdown(&self) -> Result<(), CheckpointStoreError> {
            Ok(())
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn checkpoint_store_is_dyn_injectable() {
        let store: Box<DynOwnerCheckpointStore> = DynOwnerCheckpointStore::new_box(StaticStore);
        let joined = tokio::spawn(async move {
            let owner = CheckpointOwner::new("billing");
            let id = CheckpointId::new("saga-1");
            let read = store.get_checkpoint(&owner, &id).await;
            let saved = store
                .save_checkpoint(&owner, &id, Lsn::new(3), CheckpointVersion::new(1))
                .await;
            matches!(read, Ok(Some(_)))
                && matches!(saved, Ok(SaveOutcome::Saved))
                && store.shutdown().await.is_ok()
        })
        .await;
        assert!(matches!(joined, Ok(true)));
    }
}

#[cfg(test)]
mod error_redaction {
    //! `CheckpointStoreError` derive(Debug) 经 `RedactedSource` 不展开 source、`Error::source()` 恒 `None`。
    //! INVARIANT: DIPORT-ERR-SOURCE-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }。
    use super::CheckpointStoreError;

    #[test]
    fn error_debug_redacts_source() {
        let secret = std::io::Error::other("postgres://user:hunter2@db.internal:5432/rss");
        assert!(
            format!("{secret:?}").contains("hunter2"),
            "前提失效：source 未携密"
        );
        let err = CheckpointStoreError::new(secret);
        let rendered = format!("{err:?}");
        assert!(
            !rendered.contains("hunter2") && !rendered.contains("postgres://"),
            "Debug 泄漏 source: {rendered}"
        );
        let mut cur = std::error::Error::source(&err);
        while let Some(e) = cur {
            assert!(
                !format!("{e:?}").contains("hunter2") && !format!("{e:?}").contains("postgres://"),
                "source 链泄漏: {e:?}"
            );
            cur = e.source();
        }
    }
}
