//! `SagaJournal` —— saga 执行日志 DI port（可替换：prod postgres / test in-mem）。
//!
//! append-only：执行器逐步前向 append（`Executing`→`Completed`），失败逆序补偿
//! （`Compensating`→`Compensated`），补偿失败写 `Failed`。`read` 按 `seq` 升序回放重建栈供
//! resume（crash recovery）。主键 `(saga_id, seq)`——`append` 须幂等（重投同 `(saga_id, seq)` no-op），
//! 故崩溃后重 append 安全。
//!
//! `JournalEntry.output`（step 输出字节，可能含 PII）经 [`RedactedBytes`] 脱敏；`read` 路径**不回传**
//! `output`/`error_summary`（resume 只需 `seq`/`step_name`/`status` 重建栈与阶段；output/error_summary
//! 仅落库供运维巡检）。
//!
//! ref: oxidecomputer/steno src/saga_log.rs@main（saga node event log + replay 重建）。

use dynosaur::dynosaur;

use consistency::StepName;

use crate::redacted::RedactedSource;
use crate::redacted_bytes::RedactedBytes;

// ── saga id newtype funnel ────────────────────────────────────────────────────

/// saga 实例标识（uuid newtype funnel）。落 `diport`（端口签名引用）——`eventexec::SagaId` re-export 本类型
/// （diport 不可依赖 eventexec，层序）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SagaId(uuid::Uuid);

impl SagaId {
    /// 由 uuid 构造。
    pub fn new(id: uuid::Uuid) -> Self {
        Self(id)
    }
    /// 取底层 uuid。
    pub fn as_uuid(&self) -> uuid::Uuid {
        self.0
    }
}

// ── journal status ────────────────────────────────────────────────────────────

/// journal 条目状态。`as_str` 值集是**单源**（= postgres 迁移 `CHECK` 子句；drift 测试在 postgres
/// adapter 守，对标 outbox `status_consts_match_migration_check`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum JournalStatus {
    /// step 前向执行中（`do_it` 调用前 append）。
    Executing,
    /// step 前向完成（`do_it` 返回 `Ok`）。
    Completed,
    /// step 补偿中（逆序 `undo_it` 调用前 append）。
    Compensating,
    /// step 补偿完成（`undo_it` 返回 `Ok`）。
    Compensated,
    /// step 补偿失败（`undo_it` 返回 `Err`）——saga dead-letter，须人工介入。
    Failed,
}

impl JournalStatus {
    /// wire / DB 值（snake_case，单源——postgres 迁移 `CHECK` 与本表对齐）。
    pub fn as_str(&self) -> &'static str {
        match self {
            JournalStatus::Executing => "executing",
            JournalStatus::Completed => "completed",
            JournalStatus::Compensating => "compensating",
            JournalStatus::Compensated => "compensated",
            JournalStatus::Failed => "failed",
        }
    }

    /// 从 DB 值解析（postgres `read` 用）；未知值 → `None`（fail-closed，由 adapter 升 Invariant 错误）。
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "executing" => Some(JournalStatus::Executing),
            "completed" => Some(JournalStatus::Completed),
            "compensating" => Some(JournalStatus::Compensating),
            "compensated" => Some(JournalStatus::Compensated),
            "failed" => Some(JournalStatus::Failed),
            _ => None,
        }
    }

    /// 全状态序（drift 测试 / 穷尽枚举用）。
    pub const ALL: [JournalStatus; 5] = [
        JournalStatus::Executing,
        JournalStatus::Completed,
        JournalStatus::Compensating,
        JournalStatus::Compensated,
        JournalStatus::Failed,
    ];
}

// ── journal entry ─────────────────────────────────────────────────────────────

/// 一条 journal 记录（append 写形态）。
///
/// `output`（step 输出字节，可能含 PII）经 [`RedactedBytes`] 脱敏（INVARIANT: DIPORT-DTO-BYTES-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }）。
/// `error_summary` 是 `&'static str` const literal（补偿失败原因摘要，非 runtime 数据；对齐
/// [`crate::DeadLetterSummary`] 的 PII 边界）。
///
/// **read 路径字段有效性**：`read` 回传的条目仅 `seq` / `step_name` / `status` 有意义，
/// `output` / `error_summary` 恒 `None`（resume 不需；二者仅落库供运维巡检）。
///
/// PII 边界（类型层 Hard，对标 `DeadLetterRecord` / `FencedWriteRequest`）：`output`（step 输出字节，可能含 PII）
/// 经 [`RedactedBytes`] 持有（`Debug` 恒 `<redacted>`），故 `derive(Debug)` 即安全（INVARIANT: DIPORT-DTO-BYTES-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }）。
#[derive(Debug, Clone)]
pub struct JournalEntry {
    /// append 序号（主键 `(saga_id, seq)` 的第二段；单调 0..）。
    pub seq: u64,
    /// step 名（执行器经此名重物化 action —— resume）。
    pub step_name: StepName,
    /// 条目状态。
    pub status: JournalStatus,
    /// step 输出字节（仅 `Completed` 条目携带，[`RedactedBytes`] 持有；`read` 回传恒 `None`）。
    pub output: Option<RedactedBytes>,
    /// 补偿失败安全摘要（`&'static str` const literal；仅 `Failed` 条目携带；`read` 回传恒 `None`）。
    pub error_summary: Option<&'static str>,
}

impl JournalEntry {
    /// 前向执行中条目（`do_it` 前 append）。
    pub fn executing(seq: u64, step_name: StepName) -> Self {
        Self {
            seq,
            step_name,
            status: JournalStatus::Executing,
            output: None,
            error_summary: None,
        }
    }
    /// 前向完成条目（携 step 输出）。
    pub fn completed(seq: u64, step_name: StepName, output: Vec<u8>) -> Self {
        Self {
            seq,
            step_name,
            status: JournalStatus::Completed,
            output: Some(RedactedBytes::new(output)),
            error_summary: None,
        }
    }
    /// 补偿中条目（逆序 `undo_it` 前 append）。
    pub fn compensating(seq: u64, step_name: StepName) -> Self {
        Self {
            seq,
            step_name,
            status: JournalStatus::Compensating,
            output: None,
            error_summary: None,
        }
    }
    /// 补偿完成条目。
    pub fn compensated(seq: u64, step_name: StepName) -> Self {
        Self {
            seq,
            step_name,
            status: JournalStatus::Compensated,
            output: None,
            error_summary: None,
        }
    }
    /// 补偿失败条目（携安全摘要 const literal）。
    pub fn failed(seq: u64, step_name: StepName, error_summary: &'static str) -> Self {
        Self {
            seq,
            step_name,
            status: JournalStatus::Failed,
            output: None,
            error_summary: Some(error_summary),
        }
    }
}

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
    /// 在 `(saga_id, entry.seq)` append 一条记录。append-only、never UPDATE/DELETE。
    /// 实现须幂等（同 `(saga_id, seq)` 重 append no-op，崩溃后重放安全）。
    async fn append(&self, saga_id: &SagaId, entry: JournalEntry) -> Result<(), SagaJournalError>;

    /// 读某 saga 全部 journal 条目，按 `seq` 升序（resume 据此重建栈与阶段）。回传条目的
    /// `output`/`error_summary` 恒 `None`（resume 不需，见模块 doc）。
    async fn read(&self, saga_id: &SagaId) -> Result<Vec<JournalEntry>, SagaJournalError>;

    /// 异步释放 provider 资源（无 async Drop）。有 infra 资源的 adapter 应同时 `impl ManagedResource`。
    async fn shutdown(&self) -> Result<(), SagaJournalError>;
}

#[cfg(test)]
mod smoke {
    //! build smoke：async DI port 可 native AFIT impl + 经 `Box<DynSagaJournal>` 跨 spawn 注入。
    use super::{
        DynSagaJournal, JournalEntry, JournalStatus, SagaId, SagaJournal, SagaJournalError,
    };
    use consistency::StepName;

    #[test]
    fn status_str_round_trips() {
        for s in JournalStatus::ALL {
            assert_eq!(JournalStatus::parse(s.as_str()), Some(s));
        }
        assert_eq!(JournalStatus::parse("bogus"), None);
    }

    struct NoopJournal;
    impl SagaJournal for NoopJournal {
        async fn append(
            &self,
            _saga_id: &SagaId,
            _entry: JournalEntry,
        ) -> Result<(), SagaJournalError> {
            Ok(())
        }
        async fn read(&self, _saga_id: &SagaId) -> Result<Vec<JournalEntry>, SagaJournalError> {
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
            let appended = journal.append(&id, JournalEntry::executing(0, step)).await;
            appended.is_ok() && journal.read(&id).await.is_ok() && journal.shutdown().await.is_ok()
        })
        .await;
        assert!(matches!(joined, Ok(true)));
    }
}

#[cfg(test)]
mod pii_debug {
    //! `JournalEntry.output`（step 输出字节，可能含 PII）Debug 脱敏回归。
    //! INVARIANT: DIPORT-DTO-PII-DEBUG-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }。
    use super::JournalEntry;
    use consistency::StepName;

    #[test]
    #[allow(clippy::unwrap_used)] // reason: 测试内字面量 step name 必为合法 ident（item-level carve-out）
    fn journal_entry_debug_redacts_output() {
        // anti-vacuity：原始 Vec<u8> Debug 把 0xDE 渲染成 "222"。
        assert!(format!("{:?}", vec![0xDE_u8]).contains("222"));
        let step = StepName::parse("reserve_funds").unwrap();
        let entry = JournalEntry::completed(1, step, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let dbg = format!("{entry:?}");
        assert!(!dbg.contains("222"), "output 字节泄漏(0xDE=222): {dbg}");
        assert!(!dbg.contains("173"), "output 字节泄漏(0xAD=173): {dbg}");
        assert!(dbg.contains("<redacted>"), "缺 <redacted>: {dbg}");
        assert!(dbg.contains("reserve_funds"), "step_name 应可见: {dbg}");
        assert!(dbg.contains("Completed"), "status 应可见: {dbg}");
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
