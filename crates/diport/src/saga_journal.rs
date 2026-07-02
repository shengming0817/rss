//! `SagaJournal` —— saga 执行日志 DI port（可替换：prod postgres / test in-mem）。
//!
//! append-only：执行器逐步前向 append（`Executing`→`Completed`），失败逆序补偿
//! （`Compensating`→`Compensated`），补偿失败写 `Failed`。`read` 按 `seq` 升序回放，执行器用
//! `consistency::saga` 的 reducer 重建栈供 resume（crash recovery）。主键 `(saga_id, seq)`——`append`
//! 须幂等（重投同 `(saga_id, seq)` no-op），故崩溃后重 append 安全。
//!
//! durable record 模型单源在 `consistency::saga`；本 port 只定义 provider 可替换边界。append/read
//! record 类型分离，record 不承载 step output，`read` 路径亦不回传 runtime-only `error_summary`。
//!
//! ref: oxidecomputer/steno src/saga_log.rs@main（saga node event log + replay 重建）。

use dynosaur::dynosaur;

use consistency::{SagaId, SagaJournalAppendRecord, SagaJournalRecord};

use crate::redacted::RedactedSource;

// ── 错误 ──────────────────────────────────────────────────────────────────────

/// saga journal 操作失败（infra 故障）。
///
/// PII 边界（与 [`crate::SignerError`] 同范式）：`Display` 仅安全摘要常量；source 经 [`RedactedSource`]
/// 脱敏。见 INVARIANT: DIPORT-ERR-SOURCE-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }。
#[derive(Debug, thiserror::Error)]
#[error("saga journal operation failed")]
pub struct SagaJournalError {
    #[source]
    source: RedactedSource,
}

impl SagaJournalError {
    /// 把 adapter 内部错误包成 saga journal 操作失败。原始错误仅作 internal source 保留，不经 `Display`
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

// ── SagaJournal DI port（async）───────────────────────────────────────────────

/// saga 执行日志 DI port（async）。
///
/// 公开 [`SagaJournal`] 是 **Send 变体**（adapters `impl SagaJournal for ...`），[`DynSagaJournal`] 是其
/// dyn-compatible wrapper。非 Send 基 trait `SagaJournalLocal` 不在 crate 根 re-export。
#[trait_variant::make(SagaJournal: Send)]
#[dynosaur(pub DynSagaJournal = dyn(box) SagaJournal, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: base trait 为非 Send native AFIT；Send 由 trait_variant 生成的 `SagaJournal` 变体 +
// dynosaur `DynSagaJournal` 承载（DI 注入走 Send wrapper）。这是 ADR-003 既定 dyn-port 范式。
pub trait SagaJournalLocal {
    /// 在 `(saga_id, entry.seq())` append 一条记录。append-only、never UPDATE/DELETE。
    /// 实现须幂等（同 `(saga_id, seq)` 重 append no-op，崩溃后重放安全）。
    async fn append(
        &self,
        saga_id: &SagaId,
        entry: SagaJournalAppendRecord,
    ) -> Result<(), SagaJournalError>;

    /// 读某 saga 全部 journal 条目，按 `seq` 升序（resume 据此重建栈与阶段）。read record 不回传
    /// runtime-only `error_summary`（resume 不需，见模块 doc）。
    async fn read(&self, saga_id: &SagaId) -> Result<Vec<SagaJournalRecord>, SagaJournalError>;

    /// 异步释放 provider 资源（无 async Drop）。有 infra 资源的 adapter 应同时 `impl ManagedResource`。
    async fn shutdown(&self) -> Result<(), SagaJournalError>;
}

#[cfg(test)]
mod smoke {
    //! build smoke：async DI port 可 native AFIT impl + 经 `Box<DynSagaJournal>` 跨 spawn 注入。
    use super::{DynSagaJournal, SagaJournal, SagaJournalError};
    use consistency::{SagaId, SagaJournalAppendRecord, SagaJournalRecord, StepName};

    struct NoopJournal;
    impl SagaJournal for NoopJournal {
        async fn append(
            &self,
            _saga_id: &SagaId,
            _entry: SagaJournalAppendRecord,
        ) -> Result<(), SagaJournalError> {
            Ok(())
        }
        async fn read(
            &self,
            _saga_id: &SagaId,
        ) -> Result<Vec<SagaJournalRecord>, SagaJournalError> {
            Ok(Vec::new())
        }
        async fn shutdown(&self) -> Result<(), SagaJournalError> {
            Ok(())
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::unwrap_used)] // reason: 测试内字面量 step name 必为合法 ident（item-level carve-out）
    async fn saga_journal_is_dyn_injectable() {
        let journal: Box<DynSagaJournal> = DynSagaJournal::new_box(NoopJournal);
        let joined = tokio::spawn(async move {
            let id = SagaId::new(uuid::Uuid::nil());
            let step = StepName::parse("reserve_funds").unwrap();
            let appended = journal
                .append(&id, SagaJournalAppendRecord::executing(0, step))
                .await;
            appended.is_ok() && journal.read(&id).await.is_ok() && journal.shutdown().await.is_ok()
        })
        .await;
        assert!(matches!(joined, Ok(true)));
    }
}

#[cfg(test)]
mod error_redaction {
    //! `SagaJournalError` derive(Debug) 经 `RedactedSource` 不展开 source、`Error::source()` 恒 `None`。
    //! INVARIANT: DIPORT-ERR-SOURCE-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }。
    use super::SagaJournalError;

    #[test]
    fn error_debug_redacts_source() {
        let secret = std::io::Error::other("postgres://user:hunter2@db.internal:5432/rss");
        assert!(format!("{secret:?}").contains("hunter2"), "前提失效");
        let err = SagaJournalError::new(secret);
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
