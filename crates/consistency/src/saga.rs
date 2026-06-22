//! Saga 编排接缝（L3）—— do/undo 前向动作 + 逆序补偿。
//!
//! `SagaStep` 是 L3 引擎策略 trait（native AFIT：`execute` 前向 + `compensate` 补偿）；step name /
//! outcome 是纯类型。**compensation order 只能 reverse**（saga.md §Governance）——逆序由执行器
//! （eventexec saga executor）持栈驱动，consistency 只冻接缝形态。
//! ref: oxidecomputer/steno src/saga_action_generic.rs@main（`Action::do_it`/`undo_it`/`name` 对标；
//! RSS 拒其 `ActionData: Serialize+DeserializeOwned` bound（ADR-004 C6）、用 native AFIT 替 BoxFuture）。

/// saga step 名 newtype（私有字段；可生成 Rust 标识符且唯一 —— saga.md §Governance）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StepName(String);

/// `StepName` 解析错误。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StepNameError {
    #[error("saga step name is empty")]
    Empty,
    #[error("saga step name is not a valid identifier")]
    NotIdent,
}

impl StepName {
    /// 解析；要求非空且为合法 Rust 标识符（codegen 生成 step 函数名，fail-closed）。
    pub fn parse(_raw: &str) -> Result<Self, StepNameError> {
        todo!()
    }

    /// 借出底层字符串视图。
    pub fn as_str(&self) -> &str {
        todo!()
    }
}

/// 单 step 前向结果（穷尽闭值集）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaOutcome {
    /// step 完成，推进下一步。
    Completed,
    /// step 失败，触发**逆序**补偿（saga.md：order 只能 reverse）。
    Failed,
}

/// 补偿结果（穷尽闭值集）。补偿失败需人工/DLX 介入，不静默吞。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CompensationOutcome {
    /// 补偿完成。
    Compensated,
    /// 补偿失败（需上报，进入 saga dead-letter）。
    Failed,
}

/// Saga step 策略（L3 引擎策略 trait，native AFIT）。
///
/// `execute` 前向动作；`compensate` 其逆操作（对标 steno do_it/undo_it）。执行器持已完成 step 栈，
/// 失败时**逆序** `compensate`（saga.md）。native AFIT ⇒ 非 object-safe，执行器泛型 `<S: SagaStep>` 消费。
#[allow(async_fn_in_trait)]
// reason: native AFIT 引擎策略 trait 仅泛型静态分发消费，无 Send-bound 跨 await 持有问题；这是 ADR-003 既定范式。
pub trait SagaStep {
    /// 稳定 step 名（codegen 派生唯一标识；saga.md governance）。
    fn name(&self) -> &StepName;

    /// 前向执行此 step。
    async fn execute(&self) -> Result<SagaOutcome, crate::error::EngineError>;

    /// 补偿此 step（逆操作）。仅对已 `Completed` 的 step 由执行器逆序调用。
    async fn compensate(&self) -> Result<CompensationOutcome, crate::error::EngineError>;
}
