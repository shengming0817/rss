//! Saga 编排接缝（L3）—— do/undo 前向动作 + 逆序补偿。
//!
//! `SagaStep` 是 L3 引擎策略 trait（native AFIT：`execute` 前向 + `compensate` 补偿）；step name /
//! outcome 是纯类型。**compensation order 只能 reverse**（saga.md §Governance）——逆序由执行器
//! （eventexec saga executor）持栈驱动，consistency 只冻接缝形态。
//! ref: oxidecomputer/steno src/saga_action_generic.rs@main（`Action::do_it`/`undo_it`/`name` 对标；
//! RSS 拒其 `ActionData: Serialize+DeserializeOwned` bound（ADR-004 C6）、用 native AFIT 替 BoxFuture）。
//! ref: oxidecomputer/steno src/saga_log.rs@main（durable journal event → load status replay；RSS
//! 偏离其 serde output 持久化，journal record 不承载 step output）。

use std::collections::{HashMap, HashSet};

use vocab::TenantId;

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
    pub fn parse(raw: &str) -> Result<Self, StepNameError> {
        if raw.is_empty() {
            return Err(StepNameError::Empty);
        }
        if !is_rust_ident(raw) {
            return Err(StepNameError::NotIdent);
        }
        Ok(Self(raw.to_string()))
    }

    /// 借出底层字符串视图。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// ASCII Rust 标识符文法：首字节 `[A-Za-z_]`、其余 `[A-Za-z0-9_]`，且**非** Rust 关键字、**非**裸 `_`
/// （空串 → false）。
///
/// **对齐 xtask R10 契约面校验** `name.starts_with("r#") || syn::parse_str::<syn::Ident>(name).is_err()`
/// （`xtask/src/contract/validate.rs:484`）——step name 是 codegen 生成的 step 函数符号，契约声明面与运行期
/// `StepName` 构造面文法须同形：funnel 弱于治理规则会把非法 step name（关键字 / `_`）冻进 consistency 公共 API。
/// 本谓词在 ASCII 内与 R10 **同拒集**：拒 Rust 关键字（[`is_rust_keyword`]，对标 `syn::Ident` 拒关键字）、拒裸 `_`
/// （syn 视其为 `Underscore` token 非 ident）、拒 `r#` raw ident（`#` 不在 `[A-Za-z0-9_]`，文法天然拒，R10 亦显式拒）。
/// 唯一残留分歧：R10 / `syn::Ident` 接受 non-ASCII unicode XID 标识符，本谓词只收 ASCII（runtime 偏严方向——
/// unicode saga step 名非真实用例，codegen 生成 unicode 符号亦不干净）。统一单源（runtime 与 xtask 共用单一
/// 标识符语法 + 关键字源、含 unicode）见 #1175（同 outbox `is_canonical_dotted` ↔ `is_dotted_id` #1126 范式）。
fn is_rust_ident(s: &str) -> bool {
    if s == "_" || is_rust_keyword(s) {
        return false;
    }
    let mut bytes = s.bytes();
    matches!(bytes.next(), Some(b) if b == b'_' || b.is_ascii_alphabetic())
        && bytes.all(|b| b == b'_' || b.is_ascii_alphanumeric())
}

/// Rust strict 关键字（2015 + 2018 + 2024）——对标 `syn::Ident` 拒关键字语义。
const RUST_STRICT_KEYWORDS: &[&str] = &[
    "as", "break", "const", "continue", "crate", "dyn", "else", "enum", "extern", "false", "fn",
    "for", "gen", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref",
    "return", "self", "Self", "static", "struct", "super", "trait", "true", "type", "unsafe",
    "use", "where", "while", "async", "await",
];

/// Rust reserved 关键字（未来保留，`syn::Ident` 亦拒）。
const RUST_RESERVED_KEYWORDS: &[&str] = &[
    "abstract", "become", "box", "do", "final", "macro", "override", "priv", "typeof", "unsized",
    "virtual", "yield", "try",
];

/// step name 流入 codegen 须能作裸 fn 名——拒 strict + reserved 关键字（对标 `syn::Ident`）。
fn is_rust_keyword(s: &str) -> bool {
    RUST_STRICT_KEYWORDS.contains(&s) || RUST_RESERVED_KEYWORDS.contains(&s)
}

/// saga 实例标识（uuid newtype funnel）。
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

/// tenant-scoped saga instance identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SagaInstanceRef {
    tenant: TenantId,
    saga_id: SagaId,
}

/// `SagaInstanceRef` parse/validation error.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaInstanceRefError {
    /// `SagaId` was nil UUID.
    #[error("saga id is nil uuid")]
    NilSagaId,
}

impl SagaInstanceRef {
    /// Build a tenant-scoped saga identity. Nil saga UUID is rejected so tenant-scoped stores never
    /// carry a sentinel row key.
    pub fn new(tenant: TenantId, saga_id: SagaId) -> Result<Self, SagaInstanceRefError> {
        if saga_id.as_uuid().is_nil() {
            return Err(SagaInstanceRefError::NilSagaId);
        }
        Ok(Self { tenant, saga_id })
    }

    /// Tenant boundary.
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }

    /// Saga UUID newtype.
    pub fn saga_id(&self) -> SagaId {
        self.saga_id
    }
}

/// Durable saga instance lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaInstanceStatus {
    /// Registered but not yet running.
    Ready,
    /// Forward path is running.
    Running,
    /// All steps completed.
    Succeeded,
    /// Compensation path is running.
    Compensating,
    /// Compensation completed after a forward failure.
    Compensated,
    /// Compensation failed and requires manual intervention.
    Failed,
    /// Durable state is inconsistent or journal append conflicted.
    Degraded,
}

impl SagaInstanceStatus {
    /// All DB labels.
    pub const ALL: [Self; 7] = [
        Self::Ready,
        Self::Running,
        Self::Succeeded,
        Self::Compensating,
        Self::Compensated,
        Self::Failed,
        Self::Degraded,
    ];

    /// DB/wire label.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Compensating => "compensating",
            Self::Compensated => "compensated",
            Self::Failed => "failed",
            Self::Degraded => "degraded",
        }
    }

    /// Parse DB/wire label.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "ready" => Some(Self::Ready),
            "running" => Some(Self::Running),
            "succeeded" => Some(Self::Succeeded),
            "compensating" => Some(Self::Compensating),
            "compensated" => Some(Self::Compensated),
            "failed" => Some(Self::Failed),
            "degraded" => Some(Self::Degraded),
            _ => None,
        }
    }
}

/// Durable saga instance row visible to tailers/executors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SagaInstanceRecord {
    instance: SagaInstanceRef,
    status: SagaInstanceStatus,
}

impl SagaInstanceRecord {
    /// Build an instance row value.
    pub fn new(instance: SagaInstanceRef, status: SagaInstanceStatus) -> Self {
        Self { instance, status }
    }

    /// Instance identity.
    pub fn instance(&self) -> SagaInstanceRef {
        self.instance
    }

    /// Current durable instance status.
    pub fn status(&self) -> SagaInstanceStatus {
        self.status
    }
}

/// Saga lease CAS state. Journal writes are fenced by this token+epoch pair.
#[derive(Clone, PartialEq, Eq)]
pub struct SagaLease {
    instance: SagaInstanceRef,
    holder_id: String,
    lease_token: uuid::Uuid,
    epoch: u64,
}

impl std::fmt::Debug for SagaLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SagaLease")
            .field("instance", &self.instance)
            .field("holder_id", &self.holder_id)
            .field("lease_token", &"<redacted>")
            .field("epoch", &self.epoch)
            .finish()
    }
}

/// `SagaLease` validation error.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaLeaseError {
    /// Holder id was empty or blank.
    #[error("saga lease holder id is empty")]
    EmptyHolder,
    /// Lease token was nil UUID.
    #[error("saga lease token is nil uuid")]
    NilToken,
    /// Lease epoch must be positive after acquisition.
    #[error("saga lease epoch must be positive")]
    ZeroEpoch,
}

impl SagaLease {
    /// Build a validated lease value returned by an instance store.
    pub fn new(
        instance: SagaInstanceRef,
        holder_id: impl Into<String>,
        lease_token: uuid::Uuid,
        epoch: u64,
    ) -> Result<Self, SagaLeaseError> {
        let holder_id = holder_id.into();
        if holder_id.trim().is_empty() {
            return Err(SagaLeaseError::EmptyHolder);
        }
        if lease_token.is_nil() {
            return Err(SagaLeaseError::NilToken);
        }
        if epoch == 0 {
            return Err(SagaLeaseError::ZeroEpoch);
        }
        Ok(Self {
            instance,
            holder_id,
            lease_token,
            epoch,
        })
    }

    /// Protected saga instance.
    pub fn instance(&self) -> SagaInstanceRef {
        self.instance
    }

    /// Current holder id.
    pub fn holder_id(&self) -> &str {
        &self.holder_id
    }

    /// Opaque lease token.
    pub fn lease_token(&self) -> uuid::Uuid {
        self.lease_token
    }

    /// Monotonic instance-local epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

/// Lease CAS check outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaLeaseOutcome {
    /// Token+epoch are still held.
    Held,
    /// Token+epoch no longer match or the lease expired.
    Lost,
}

/// Saga journal append outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaJournalAppendOutcome {
    /// New journal row was inserted.
    Appended,
    /// Existing `(tenant_id, saga_id, seq)` row exactly matched the append record.
    IdempotentDuplicate,
    /// Existing row differs from the append record.
    AppendConflict,
    /// Lease token/epoch did not fence the write.
    LeaseLost,
}

/// Non-business interruption reason. These outcomes must not trigger compensation or app DLX.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaInterruption {
    /// Runtime distributed lock is held by another runner.
    RuntimeLockBusy,
    /// Previously acquired runtime distributed lock was lost or expired.
    RuntimeLockLost,
    /// Runtime distributed lock provider returned an infrastructure error.
    RuntimeLockUnavailable,
    /// Another holder owns the instance.
    LeaseBusy,
    /// Previously acquired lease was lost or expired.
    LeaseLost,
    /// Journal append conflicted with an existing different row.
    JournalConflict,
    /// Durable saga instance store returned an infrastructure or invariant error.
    StoreUnavailable,
    /// `run` was asked to start an instance that already exists.
    AlreadyStarted,
    /// Durable instance status is degraded and requires manual intervention.
    InstanceDegraded,
}

impl SagaInterruption {
    /// Closed-set diagnostic label for non-business saga interruptions.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::RuntimeLockBusy => "runtime_lock_busy",
            Self::RuntimeLockLost => "runtime_lock_lost",
            Self::RuntimeLockUnavailable => "runtime_lock_unavailable",
            Self::LeaseBusy => "lease_busy",
            Self::LeaseLost => "lease_lost",
            Self::JournalConflict => "journal_conflict",
            Self::StoreUnavailable => "store_unavailable",
            Self::AlreadyStarted => "already_started",
            Self::InstanceDegraded => "instance_degraded",
        }
    }
}

/// saga durable journal 条目状态。label 与 postgres `saga_journal.status` CHECK 集合同源。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaJournalStatus {
    /// step 前向执行中（`do_it` 调用前 append）。
    Executing,
    /// step 前向完成。
    Completed,
    /// step 补偿中（逆序 `undo_it` 调用前 append）。
    Compensating,
    /// step 补偿完成。
    Compensated,
    /// step 补偿失败，saga 进入人工介入 / dead-letter 终态。
    Failed,
}

impl SagaJournalStatus {
    /// 全状态序（drift 测试 / 穷尽枚举用）。
    pub const ALL: [Self; 5] = [
        Self::Executing,
        Self::Completed,
        Self::Compensating,
        Self::Compensated,
        Self::Failed,
    ];

    /// wire / DB label（snake_case）。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Executing => "executing",
            Self::Completed => "completed",
            Self::Compensating => "compensating",
            Self::Compensated => "compensated",
            Self::Failed => "failed",
        }
    }

    /// 从 wire / DB label 解析；未知值返回 `None`，由调用方升为 fail-closed invariant。
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "executing" => Some(Self::Executing),
            "completed" => Some(Self::Completed),
            "compensating" => Some(Self::Compensating),
            "compensated" => Some(Self::Compensated),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

/// saga 模型错误。
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaModelError {
    /// saga definition 没有 step。
    #[error("saga definition must contain at least one step")]
    EmptyDefinition,
    /// step name 字面量非法。
    #[error("saga step name is invalid")]
    InvalidStepName { raw: String },
    /// saga definition 内 step name 重复。
    #[error("saga step name is duplicated")]
    DuplicateStepName { step_name: StepName },
    /// journal 引用了 definition 中不存在的 step。
    #[error("saga journal references an unknown step")]
    UnknownStep { step_name: StepName },
    /// journal seq 重复。
    #[error("saga journal seq is duplicated")]
    DuplicateSeq { seq: u64 },
    /// journal 状态转换非法。
    #[error("saga journal transition is illegal")]
    IllegalTransition {
        step_name: StepName,
        status: SagaJournalStatus,
    },
    /// journal 不是完整前缀。
    #[error("saga completed steps are not a prefix of the definition")]
    NonPrefixCompleted { step_name: StepName },
}

/// saga 定义（有序 step 列表；compensation order 固定 reverse）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SagaDefinition {
    steps: Vec<StepName>,
}

impl SagaDefinition {
    /// 由已解析 step 名构造；拒空和重复 step。
    pub fn new(steps: Vec<StepName>) -> Result<Self, SagaModelError> {
        if steps.is_empty() {
            return Err(SagaModelError::EmptyDefinition);
        }
        let mut seen = HashSet::new();
        for step in &steps {
            if !seen.insert(step.as_str()) {
                return Err(SagaModelError::DuplicateStepName {
                    step_name: step.clone(),
                });
            }
        }
        Ok(Self { steps })
    }

    /// 由 raw step name 构造；统一走 [`StepName::parse`] fail-closed。
    pub fn from_step_names<'a>(
        names: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, SagaModelError> {
        let mut steps = Vec::new();
        for raw in names {
            let step = StepName::parse(raw).map_err(|_| SagaModelError::InvalidStepName {
                raw: raw.to_string(),
            })?;
            steps.push(step);
        }
        Self::new(steps)
    }

    /// step 列表。
    pub fn steps(&self) -> &[StepName] {
        &self.steps
    }

    /// 按定义序查询 step index。
    pub fn step_index(&self, step: &StepName) -> Option<usize> {
        self.steps.iter().position(|s| s == step)
    }

    /// 从 durable journal replay 出恢复决策。
    pub fn replay(
        &self,
        records: &[SagaJournalRecord],
    ) -> Result<SagaReplayDecision, SagaModelError> {
        replay_records(self, records)
    }
}

/// 一条 saga durable journal append record。
///
/// 写入路径类型与 read/replay 类型分离：append record 的 `Failed` 必须携静态安全摘要，避免 read 路径构造出的
/// 无摘要 `Failed` 被误传回 append port。record 不承载 step output，避免 durable journal 成为 PII 载体；执行器
/// 需要的末步 output 只保留在 `run` 内存路径。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SagaJournalAppendRecord {
    seq: u64,
    step_name: StepName,
    status: SagaJournalStatus,
    error_summary: Option<&'static str>,
}

impl SagaJournalAppendRecord {
    /// 前向执行中 record。
    pub fn executing(seq: u64, step_name: StepName) -> Self {
        Self::new(seq, step_name, SagaJournalStatus::Executing, None)
    }

    /// 前向完成 record。step output 不进入 durable journal。
    pub fn completed(seq: u64, step_name: StepName) -> Self {
        Self::new(seq, step_name, SagaJournalStatus::Completed, None)
    }

    /// 补偿中 record。
    pub fn compensating(seq: u64, step_name: StepName) -> Self {
        Self::new(seq, step_name, SagaJournalStatus::Compensating, None)
    }

    /// 补偿完成 record。
    pub fn compensated(seq: u64, step_name: StepName) -> Self {
        Self::new(seq, step_name, SagaJournalStatus::Compensated, None)
    }

    /// 补偿失败 record；summary 必须是静态安全摘要。
    pub fn failed(seq: u64, step_name: StepName, error_summary: &'static str) -> Self {
        Self::new(
            seq,
            step_name,
            SagaJournalStatus::Failed,
            Some(error_summary),
        )
    }

    fn new(
        seq: u64,
        step_name: StepName,
        status: SagaJournalStatus,
        error_summary: Option<&'static str>,
    ) -> Self {
        Self {
            seq,
            step_name,
            status,
            error_summary,
        }
    }

    /// append 序号。
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// step 名。
    pub fn step_name(&self) -> &StepName {
        &self.step_name
    }

    /// record 状态。
    pub fn status(&self) -> SagaJournalStatus {
        self.status
    }

    /// 补偿失败安全摘要。
    pub fn error_summary(&self) -> Option<&'static str> {
        self.error_summary
    }
}

/// 一条从 durable journal read/replay 路径重建的 record。
///
/// replay record 不携 runtime-only `error_summary`，也不能作为 append port 入参；补偿失败摘要只能经
/// [`SagaJournalAppendRecord::failed`] 写入。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SagaJournalRecord {
    seq: u64,
    step_name: StepName,
    status: SagaJournalStatus,
}

impl SagaJournalRecord {
    /// 从 durable read 路径重建 record；runtime-only summary/output 不回传。
    pub fn replayed(seq: u64, step_name: StepName, status: SagaJournalStatus) -> Self {
        Self {
            seq,
            step_name,
            status,
        }
    }

    /// append 序号。
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// step 名。
    pub fn step_name(&self) -> &StepName {
        &self.step_name
    }

    /// record 状态。
    pub fn status(&self) -> SagaJournalStatus {
        self.status
    }
}

/// 从 journal 推导出的 durable saga 状态。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaDurableStatus {
    /// 未开始。
    NotStarted,
    /// 前向执行中。
    Running,
    /// 全 step 前向完成。
    Succeeded,
    /// 正在逆序补偿。
    Compensating,
    /// 补偿完成；业务结论仍是失败，但无需继续执行。
    Compensated,
    /// 补偿失败 / dead-letter 终态。
    Failed { failed_step: StepName },
}

impl SagaDurableStatus {
    /// 是否仍有运行中动作。
    pub fn is_running(&self) -> bool {
        matches!(self, Self::Running | Self::Compensating)
    }

    /// 是否是终态。
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Compensated | Self::Failed { .. }
        )
    }
}

/// journal replay 后执行器下一步决策。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaReplayDecision {
    /// 续前向：从 `start` 续跑，`completed` 是已完成前缀。
    Forward {
        start: usize,
        next_seq: u64,
        completed: Vec<(usize, StepName)>,
    },
    /// 续补偿：`pending` 按 reverse order 排列。
    Compensating {
        next_seq: u64,
        pending: Vec<(usize, StepName)>,
        failed_step: Option<StepName>,
    },
    /// 终态。
    Terminal { status: SagaDurableStatus },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StepLoadStatus {
    NeverStarted,
    Executing,
    Completed,
    Compensating,
    Compensated,
    Failed,
}

impl StepLoadStatus {
    fn transition(
        self,
        step_name: &StepName,
        status: SagaJournalStatus,
    ) -> Result<Self, SagaModelError> {
        match (self, status) {
            (Self::NeverStarted, SagaJournalStatus::Executing) => Ok(Self::Executing),
            (Self::Executing, SagaJournalStatus::Executing) => Ok(Self::Executing),
            (Self::NeverStarted | Self::Executing, SagaJournalStatus::Completed) => {
                Ok(Self::Completed)
            }
            (Self::Executing | Self::Completed, SagaJournalStatus::Compensating) => {
                Ok(Self::Compensating)
            }
            (Self::Compensating, SagaJournalStatus::Compensating) => Ok(Self::Compensating),
            (
                Self::Executing | Self::Completed | Self::Compensating,
                SagaJournalStatus::Compensated,
            ) => Ok(Self::Compensated),
            (Self::Executing | Self::Completed | Self::Compensating, SagaJournalStatus::Failed) => {
                Ok(Self::Failed)
            }
            _ => Err(SagaModelError::IllegalTransition {
                step_name: step_name.clone(),
                status,
            }),
        }
    }
}

fn is_compensation_event(status: SagaJournalStatus) -> bool {
    matches!(
        status,
        SagaJournalStatus::Compensating
            | SagaJournalStatus::Compensated
            | SagaJournalStatus::Failed
    )
}

fn validate_reverse_compensation(
    latest: &[StepLoadStatus],
    idx: usize,
    ceiling: &mut Option<usize>,
    step_name: &StepName,
    status: SagaJournalStatus,
) -> Result<(), SagaModelError> {
    if ceiling.is_none() {
        *ceiling = initial_compensation_ceiling(latest, idx);
    }
    let Some(limit) = *ceiling else {
        return Err(illegal_transition(step_name, status));
    };
    if expected_compensation_idx(latest, limit) == Some(idx) {
        return Ok(());
    }
    Err(illegal_transition(step_name, status))
}

fn initial_compensation_ceiling(latest: &[StepLoadStatus], idx: usize) -> Option<usize> {
    if latest
        .get(idx)
        .is_some_and(|status| *status == StepLoadStatus::Executing)
    {
        return Some(idx);
    }
    latest
        .iter()
        .enumerate()
        .rev()
        .find(|(_, status)| {
            matches!(
                **status,
                StepLoadStatus::Completed | StepLoadStatus::Compensating
            )
        })
        .map(|(idx, _)| idx)
}

fn expected_compensation_idx(latest: &[StepLoadStatus], ceiling: usize) -> Option<usize> {
    if let Some((idx, _)) = latest
        .iter()
        .enumerate()
        .take(ceiling + 1)
        .rev()
        .find(|(_, status)| **status == StepLoadStatus::Compensating)
    {
        return Some(idx);
    }
    if let Some((idx, _)) = latest
        .iter()
        .enumerate()
        .take(ceiling + 1)
        .rev()
        .find(|(_, status)| **status == StepLoadStatus::Completed)
    {
        return Some(idx);
    }
    latest
        .get(ceiling)
        .is_some_and(|status| *status == StepLoadStatus::Executing)
        .then_some(ceiling)
}

fn illegal_transition(step_name: &StepName, status: SagaJournalStatus) -> SagaModelError {
    SagaModelError::IllegalTransition {
        step_name: step_name.clone(),
        status,
    }
}

fn replay_records(
    definition: &SagaDefinition,
    records: &[SagaJournalRecord],
) -> Result<SagaReplayDecision, SagaModelError> {
    if records.is_empty() {
        return Ok(SagaReplayDecision::Forward {
            start: 0,
            next_seq: 0,
            completed: Vec::new(),
        });
    }

    let mut sorted = records.to_vec();
    sorted.sort_by_key(SagaJournalRecord::seq);
    reject_duplicate_seq(&sorted)?;

    let mut latest = vec![StepLoadStatus::NeverStarted; definition.steps.len()];
    let mut index_by_name = HashMap::new();
    for (i, step) in definition.steps.iter().enumerate() {
        index_by_name.insert(step.as_str(), i);
    }

    let mut compensation_ceiling = None;
    let mut compensation_failed_step = None;
    let mut terminal_failed: Option<StepName> = None;
    for record in &sorted {
        if terminal_failed.is_some() {
            return Err(SagaModelError::IllegalTransition {
                step_name: record.step_name.clone(),
                status: record.status,
            });
        }
        if compensation_ceiling.is_some()
            && matches!(
                record.status,
                SagaJournalStatus::Executing | SagaJournalStatus::Completed
            )
        {
            return Err(SagaModelError::IllegalTransition {
                step_name: record.step_name.clone(),
                status: record.status,
            });
        }
        let Some(&idx) = index_by_name.get(record.step_name.as_str()) else {
            return Err(SagaModelError::UnknownStep {
                step_name: record.step_name.clone(),
            });
        };
        if is_compensation_event(record.status) {
            if compensation_ceiling.is_none() {
                compensation_failed_step = inferred_forward_failure_step(definition, &latest);
            }
            validate_reverse_compensation(
                &latest,
                idx,
                &mut compensation_ceiling,
                &record.step_name,
                record.status,
            )?;
        }
        let next = latest[idx].transition(&record.step_name, record.status)?;
        latest[idx] = next;
        if next == StepLoadStatus::Failed {
            terminal_failed = Some(record.step_name.clone());
        }
    }

    validate_prefix(definition, &latest)?;
    let next_seq = sorted.last().map_or(0, |record| record.seq + 1);
    Ok(decision_from_latest(
        definition,
        &latest,
        next_seq,
        compensation_failed_step,
    ))
}

fn inferred_forward_failure_step(
    definition: &SagaDefinition,
    latest: &[StepLoadStatus],
) -> Option<StepName> {
    latest
        .iter()
        .enumerate()
        .rev()
        .find(|(_, status)| **status == StepLoadStatus::Executing)
        .map(|(idx, _)| definition.steps[idx].clone())
}

fn reject_duplicate_seq(records: &[SagaJournalRecord]) -> Result<(), SagaModelError> {
    for window in records.windows(2) {
        if window[0].seq == window[1].seq {
            return Err(SagaModelError::DuplicateSeq { seq: window[0].seq });
        }
    }
    Ok(())
}

fn validate_prefix(
    definition: &SagaDefinition,
    latest: &[StepLoadStatus],
) -> Result<(), SagaModelError> {
    let mut found_gap = false;
    for (idx, status) in latest.iter().enumerate() {
        if *status == StepLoadStatus::NeverStarted {
            found_gap = true;
            continue;
        }
        if found_gap {
            return Err(SagaModelError::NonPrefixCompleted {
                step_name: definition.steps[idx].clone(),
            });
        }
    }
    Ok(())
}

fn decision_from_latest(
    definition: &SagaDefinition,
    latest: &[StepLoadStatus],
    next_seq: u64,
    compensation_failed_step: Option<StepName>,
) -> SagaReplayDecision {
    if let Some((idx, _)) = latest
        .iter()
        .enumerate()
        .find(|(_, status)| **status == StepLoadStatus::Failed)
    {
        return SagaReplayDecision::Terminal {
            status: SagaDurableStatus::Failed {
                failed_step: definition.steps[idx].clone(),
            },
        };
    }

    let unwinding = latest.iter().any(|status| {
        matches!(
            status,
            StepLoadStatus::Compensating | StepLoadStatus::Compensated
        )
    });
    if unwinding {
        let pending = pending_compensations(definition, latest);
        if pending.is_empty() {
            return SagaReplayDecision::Terminal {
                status: SagaDurableStatus::Compensated,
            };
        }
        return SagaReplayDecision::Compensating {
            next_seq,
            pending,
            failed_step: compensation_failed_step,
        };
    }

    let completed = completed_prefix(definition, latest);
    if completed.len() == definition.steps.len() {
        return SagaReplayDecision::Terminal {
            status: SagaDurableStatus::Succeeded,
        };
    }
    SagaReplayDecision::Forward {
        start: completed.len(),
        next_seq,
        completed,
    }
}

fn completed_prefix(
    definition: &SagaDefinition,
    latest: &[StepLoadStatus],
) -> Vec<(usize, StepName)> {
    latest
        .iter()
        .enumerate()
        .take_while(|(_, status)| **status == StepLoadStatus::Completed)
        .map(|(idx, _)| (idx, definition.steps[idx].clone()))
        .collect()
}

fn pending_compensations(
    definition: &SagaDefinition,
    latest: &[StepLoadStatus],
) -> Vec<(usize, StepName)> {
    let mut pending = latest
        .iter()
        .enumerate()
        .filter(|(_, status)| {
            matches!(
                **status,
                StepLoadStatus::Completed | StepLoadStatus::Compensating
            )
        })
        .map(|(idx, _)| (idx, definition.steps[idx].clone()))
        .collect::<Vec<_>>();
    pending.reverse();
    pending
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

#[cfg(test)]
mod tests {
    use super::{
        SagaDefinition, SagaDurableStatus, SagaId, SagaInstanceRef, SagaInstanceRefError,
        SagaJournalAppendRecord, SagaJournalRecord, SagaJournalStatus, SagaLease, SagaLeaseError,
        SagaModelError, SagaReplayDecision, StepName, StepNameError,
    };

    #[allow(clippy::unwrap_used)]
    fn step(raw: &str) -> StepName {
        StepName::parse(raw).unwrap()
    }

    #[allow(clippy::unwrap_used)]
    fn definition(names: &[&str]) -> SagaDefinition {
        SagaDefinition::from_step_names(names.iter().copied()).unwrap()
    }

    #[test]
    fn saga_id_round_trips_uuid() {
        let raw = uuid::Uuid::from_u128(0x1627);
        let id = SagaId::new(raw);
        assert_eq!(id.as_uuid(), raw);
    }

    #[test]
    fn saga_journal_status_labels_round_trip_and_are_closed() {
        let expected = [
            (SagaJournalStatus::Executing, "executing"),
            (SagaJournalStatus::Completed, "completed"),
            (SagaJournalStatus::Compensating, "compensating"),
            (SagaJournalStatus::Compensated, "compensated"),
            (SagaJournalStatus::Failed, "failed"),
        ];
        assert_eq!(SagaJournalStatus::ALL.len(), expected.len());
        for (status, label) in expected {
            assert!(
                SagaJournalStatus::ALL.contains(&status),
                "ALL 缺 {status:?}"
            );
            assert_eq!(status.as_str(), label);
            assert_eq!(SagaJournalStatus::parse(label), Some(status));
        }
        assert_eq!(SagaJournalStatus::parse("succeeded"), None);
        assert_eq!(SagaJournalStatus::parse(""), None);
    }

    #[test]
    fn saga_definition_rejects_empty_invalid_and_duplicate_steps() {
        assert_eq!(
            SagaDefinition::from_step_names([]),
            Err(SagaModelError::EmptyDefinition)
        );
        assert_eq!(
            SagaDefinition::from_step_names(["step1", "not-a-step"]),
            Err(SagaModelError::InvalidStepName {
                raw: "not-a-step".to_string()
            })
        );
        assert_eq!(
            SagaDefinition::from_step_names(["step1", "step1"]),
            Err(SagaModelError::DuplicateStepName {
                step_name: step("step1")
            })
        );
    }

    #[test]
    fn saga_definition_preserves_order_and_reverse_compensation_order_is_replay_decision() {
        let def = definition(&["step1", "step2", "step3"]);
        assert_eq!(
            def.steps().iter().map(StepName::as_str).collect::<Vec<_>>(),
            vec!["step1", "step2", "step3"]
        );
        assert_eq!(def.step_index(&step("step2")), Some(1));

        let records = vec![
            SagaJournalRecord::replayed(0, step("step1"), SagaJournalStatus::Completed),
            SagaJournalRecord::replayed(1, step("step2"), SagaJournalStatus::Completed),
            SagaJournalRecord::replayed(2, step("step2"), SagaJournalStatus::Compensating),
        ];
        assert_eq!(
            def.replay(&records),
            Ok(SagaReplayDecision::Compensating {
                next_seq: 3,
                pending: vec![(1, step("step2")), (0, step("step1"))],
                failed_step: None,
            })
        );
    }

    #[test]
    fn saga_journal_append_record_constructors_set_private_fields_without_output() {
        let completed = SagaJournalAppendRecord::completed(7, step("reserve"));
        assert_eq!(completed.seq(), 7);
        assert_eq!(completed.step_name().as_str(), "reserve");
        assert_eq!(completed.status(), SagaJournalStatus::Completed);
        assert_eq!(completed.error_summary(), None);

        let failed = SagaJournalAppendRecord::failed(8, step("reserve"), "undo failed");
        assert_eq!(failed.seq(), 8);
        assert_eq!(failed.status(), SagaJournalStatus::Failed);
        assert_eq!(failed.error_summary(), Some("undo failed"));

        let replayed = SagaJournalRecord::replayed(9, step("reserve"), SagaJournalStatus::Failed);
        assert_eq!(replayed.seq(), 9);
        assert_eq!(replayed.step_name().as_str(), "reserve");
        assert_eq!(replayed.status(), SagaJournalStatus::Failed);
    }

    #[test]
    fn replay_completed_prefix_runs_forward_from_next_step() {
        let def = definition(&["step1", "step2", "step3"]);
        let records = vec![
            SagaJournalRecord::replayed(0, step("step1"), SagaJournalStatus::Executing),
            SagaJournalRecord::replayed(1, step("step1"), SagaJournalStatus::Completed),
        ];

        assert_eq!(
            def.replay(&records),
            Ok(SagaReplayDecision::Forward {
                start: 1,
                next_seq: 2,
                completed: vec![(0, step("step1"))]
            })
        );
    }

    #[test]
    fn replay_empty_journal_starts_forward_from_zero() {
        let def = definition(&["step1"]);

        assert_eq!(
            def.replay(&[]),
            Ok(SagaReplayDecision::Forward {
                start: 0,
                next_seq: 0,
                completed: Vec::new()
            })
        );
    }

    #[test]
    fn replay_all_completed_is_terminal_success() {
        let def = definition(&["step1", "step2"]);
        let records = vec![
            SagaJournalRecord::replayed(0, step("step1"), SagaJournalStatus::Completed),
            SagaJournalRecord::replayed(1, step("step2"), SagaJournalStatus::Completed),
        ];

        assert_eq!(
            def.replay(&records),
            Ok(SagaReplayDecision::Terminal {
                status: SagaDurableStatus::Succeeded
            })
        );
    }

    #[test]
    fn replay_compensating_crash_resumes_reverse_compensation() {
        let def = definition(&["step1", "step2"]);
        let records = vec![
            SagaJournalRecord::replayed(0, step("step1"), SagaJournalStatus::Completed),
            SagaJournalRecord::replayed(1, step("step2"), SagaJournalStatus::Completed),
            SagaJournalRecord::replayed(2, step("step2"), SagaJournalStatus::Compensating),
        ];

        assert_eq!(
            def.replay(&records),
            Ok(SagaReplayDecision::Compensating {
                next_seq: 3,
                pending: vec![(1, step("step2")), (0, step("step1"))],
                failed_step: None,
            })
        );
    }

    #[test]
    fn replay_treats_repeated_executing_as_idempotent_retry_intent() {
        let def = definition(&["step1", "step2"]);
        let records = vec![
            SagaJournalRecord::replayed(0, step("step1"), SagaJournalStatus::Executing),
            SagaJournalRecord::replayed(1, step("step1"), SagaJournalStatus::Executing),
        ];

        assert_eq!(
            def.replay(&records),
            Ok(SagaReplayDecision::Forward {
                start: 0,
                next_seq: 2,
                completed: Vec::new(),
            })
        );
    }

    #[test]
    fn replay_compensation_done_is_terminal_compensated() {
        let def = definition(&["step1", "step2"]);
        let records = vec![
            SagaJournalRecord::replayed(0, step("step1"), SagaJournalStatus::Completed),
            SagaJournalRecord::replayed(1, step("step2"), SagaJournalStatus::Completed),
            SagaJournalRecord::replayed(2, step("step2"), SagaJournalStatus::Compensating),
            SagaJournalRecord::replayed(3, step("step2"), SagaJournalStatus::Compensated),
            SagaJournalRecord::replayed(4, step("step1"), SagaJournalStatus::Compensating),
            SagaJournalRecord::replayed(5, step("step1"), SagaJournalStatus::Compensated),
        ];

        assert_eq!(
            def.replay(&records),
            Ok(SagaReplayDecision::Terminal {
                status: SagaDurableStatus::Compensated
            })
        );
    }

    #[test]
    fn replay_allows_forward_failure_to_skip_executing_step_and_compensate_completed_prefix() {
        let def = definition(&["step1", "step2"]);
        let records = vec![
            SagaJournalRecord::replayed(0, step("step1"), SagaJournalStatus::Completed),
            SagaJournalRecord::replayed(1, step("step2"), SagaJournalStatus::Executing),
            SagaJournalRecord::replayed(2, step("step1"), SagaJournalStatus::Compensating),
            SagaJournalRecord::replayed(3, step("step1"), SagaJournalStatus::Compensated),
        ];

        assert_eq!(
            def.replay(&records),
            Ok(SagaReplayDecision::Terminal {
                status: SagaDurableStatus::Compensated
            })
        );
    }

    #[test]
    fn replay_compensation_decision_keeps_failed_forward_step() {
        let def = definition(&["step1", "step2"]);
        let records = vec![
            SagaJournalRecord::replayed(0, step("step1"), SagaJournalStatus::Completed),
            SagaJournalRecord::replayed(1, step("step2"), SagaJournalStatus::Executing),
            SagaJournalRecord::replayed(2, step("step1"), SagaJournalStatus::Compensating),
            SagaJournalRecord::replayed(3, step("step1"), SagaJournalStatus::Compensating),
        ];

        assert_eq!(
            def.replay(&records),
            Ok(SagaReplayDecision::Compensating {
                next_seq: 4,
                pending: vec![(0, step("step1"))],
                failed_step: Some(step("step2")),
            })
        );
    }

    #[test]
    fn replay_allows_executing_step_to_compensate_when_completed_append_was_lost() {
        let def = definition(&["step1"]);
        let records = vec![
            SagaJournalRecord::replayed(0, step("step1"), SagaJournalStatus::Executing),
            SagaJournalRecord::replayed(1, step("step1"), SagaJournalStatus::Compensating),
            SagaJournalRecord::replayed(2, step("step1"), SagaJournalStatus::Compensated),
        ];

        assert_eq!(
            def.replay(&records),
            Ok(SagaReplayDecision::Terminal {
                status: SagaDurableStatus::Compensated
            })
        );
    }

    #[test]
    fn replay_failed_terminal_does_not_rerun() {
        let def = definition(&["step1", "step2"]);
        let records = vec![
            SagaJournalRecord::replayed(0, step("step1"), SagaJournalStatus::Completed),
            SagaJournalRecord::replayed(1, step("step1"), SagaJournalStatus::Compensating),
            SagaJournalRecord::replayed(2, step("step1"), SagaJournalStatus::Failed),
        ];

        assert_eq!(
            def.replay(&records),
            Ok(SagaReplayDecision::Terminal {
                status: SagaDurableStatus::Failed {
                    failed_step: step("step1")
                }
            })
        );
    }

    #[test]
    fn durable_status_helpers_report_liveness() {
        assert!(SagaDurableStatus::Running.is_running());
        assert!(SagaDurableStatus::Compensating.is_running());
        assert!(!SagaDurableStatus::Succeeded.is_running());
        assert!(SagaDurableStatus::Succeeded.is_terminal());
        assert!(SagaDurableStatus::Compensated.is_terminal());
        assert!(
            SagaDurableStatus::Failed {
                failed_step: step("step1")
            }
            .is_terminal()
        );
        assert!(!SagaDurableStatus::NotStarted.is_terminal());
    }

    #[test]
    fn replay_rejects_unknown_step_duplicate_seq_and_non_prefix() {
        let def = definition(&["step1", "step2"]);

        assert_eq!(
            def.replay(&[SagaJournalRecord::replayed(
                0,
                step("ghost"),
                SagaJournalStatus::Completed
            )]),
            Err(SagaModelError::UnknownStep {
                step_name: step("ghost")
            })
        );
        assert_eq!(
            def.replay(&[
                SagaJournalRecord::replayed(0, step("step1"), SagaJournalStatus::Executing),
                SagaJournalRecord::replayed(0, step("step1"), SagaJournalStatus::Completed),
            ]),
            Err(SagaModelError::DuplicateSeq { seq: 0 })
        );
        assert_eq!(
            def.replay(&[SagaJournalRecord::replayed(
                0,
                step("step2"),
                SagaJournalStatus::Completed
            )]),
            Err(SagaModelError::NonPrefixCompleted {
                step_name: step("step2")
            })
        );
    }

    #[test]
    fn replay_rejects_illegal_status_transitions() {
        let def = definition(&["step1", "step2"]);

        assert_eq!(
            def.replay(&[
                SagaJournalRecord::replayed(0, step("step1"), SagaJournalStatus::Completed),
                SagaJournalRecord::replayed(1, step("step1"), SagaJournalStatus::Executing),
            ]),
            Err(SagaModelError::IllegalTransition {
                step_name: step("step1"),
                status: SagaJournalStatus::Executing
            })
        );
        assert_eq!(
            def.replay(&[
                SagaJournalRecord::replayed(0, step("step1"), SagaJournalStatus::Completed),
                SagaJournalRecord::replayed(1, step("step1"), SagaJournalStatus::Compensating),
                SagaJournalRecord::replayed(2, step("step2"), SagaJournalStatus::Completed),
            ]),
            Err(SagaModelError::IllegalTransition {
                step_name: step("step2"),
                status: SagaJournalStatus::Completed
            })
        );
        assert_eq!(
            def.replay(&[
                SagaJournalRecord::replayed(0, step("step1"), SagaJournalStatus::Completed),
                SagaJournalRecord::replayed(1, step("step1"), SagaJournalStatus::Failed),
                SagaJournalRecord::replayed(2, step("step1"), SagaJournalStatus::Compensating),
            ]),
            Err(SagaModelError::IllegalTransition {
                step_name: step("step1"),
                status: SagaJournalStatus::Compensating
            })
        );
        assert_eq!(
            def.replay(&[SagaJournalRecord::replayed(
                0,
                step("step1"),
                SagaJournalStatus::Failed
            )]),
            Err(SagaModelError::IllegalTransition {
                step_name: step("step1"),
                status: SagaJournalStatus::Failed
            })
        );
        assert_eq!(
            def.replay(&[
                SagaJournalRecord::replayed(0, step("step1"), SagaJournalStatus::Completed),
                SagaJournalRecord::replayed(1, step("step2"), SagaJournalStatus::Completed),
                SagaJournalRecord::replayed(2, step("step1"), SagaJournalStatus::Compensating),
            ]),
            Err(SagaModelError::IllegalTransition {
                step_name: step("step1"),
                status: SagaJournalStatus::Compensating
            })
        );
        assert_eq!(
            def.replay(&[
                SagaJournalRecord::replayed(0, step("step1"), SagaJournalStatus::Completed),
                SagaJournalRecord::replayed(1, step("step2"), SagaJournalStatus::Executing),
                SagaJournalRecord::replayed(2, step("step1"), SagaJournalStatus::Compensating),
                SagaJournalRecord::replayed(3, step("step2"), SagaJournalStatus::Compensating),
            ]),
            Err(SagaModelError::IllegalTransition {
                step_name: step("step2"),
                status: SagaJournalStatus::Compensating
            })
        );
    }

    // parse 接受合法 Rust 标识符（首字符 [A-Za-z_]、其余 [A-Za-z0-9_]，非关键字、非裸 `_`）+ as_str 往返。
    #[test]
    #[allow(clippy::unwrap_used)]
    // reason: 测试 happy-path 断言已 is_ok 的 parse 结果，item-level carve-out（error-handling.md §Carve-out）。
    fn step_name_parse_accepts_idents_and_round_trips() {
        let cases: &[&str] = &["a", "A", "_x", "step_one", "A1", "create_session", "x9_y8"];
        for &raw in cases {
            assert!(StepName::parse(raw).is_ok(), "expected Ok for raw={raw:?}");
            assert_eq!(StepName::parse(raw).unwrap().as_str(), raw, "raw={raw:?}");
        }
    }

    // 空 → Empty（fail-closed；codegen 生成 step 函数名，空名不可表达）。
    #[test]
    fn step_name_parse_rejects_empty() {
        assert!(matches!(StepName::parse(""), Err(StepNameError::Empty)));
    }

    // 非标识符 → NotIdent（段首数字 / 连字符 / 点 / 空格 / 非法字符 / 非 ASCII / 制表符 / r# raw ident）。
    #[test]
    fn step_name_parse_rejects_non_ident() {
        let cases: &[&str] = &[
            "1a", "9", "a-b", "a.b", "a b", "a$", " a", "a ", "föö", "a\tb", "r#fn",
        ];
        for &raw in cases {
            assert!(
                matches!(StepName::parse(raw), Err(StepNameError::NotIdent)),
                "expected NotIdent for raw={raw:?}"
            );
        }
    }

    // 关键字 / 裸 `_` → NotIdent（对齐 xtask R10：codegen step 函数名不可为关键字 / `_`）。
    #[test]
    fn step_name_parse_rejects_keywords_and_underscore() {
        for raw in [
            "fn", "if", "let", "pub", "match", "self", "Self", "async", "gen", "yield", "_",
        ] {
            assert!(
                matches!(StepName::parse(raw), Err(StepNameError::NotIdent)),
                "expected NotIdent for raw={raw:?}"
            );
        }
    }

    // 私有 is_rust_ident 谓词独立语义（空串短路 false 分支，文法分支全覆盖；
    // parse 已前置拒空，此处守 helper 独立调用时空串 false，仿 outbox is_canonical_dotted_standalone）。
    #[test]
    fn is_rust_ident_standalone() {
        assert!(!super::is_rust_ident(""));
        assert!(super::is_rust_ident("a"));
        assert!(!super::is_rust_ident("_")); // 裸 `_` 现拒（对齐 syn::Ident Underscore token）
        assert!(super::is_rust_ident("_x")); // 含后缀的下划线名仍合法
        assert!(super::is_rust_ident("A1_b"));
        assert!(!super::is_rust_ident("1a"));
        assert!(!super::is_rust_ident("a-b"));
    }

    // 对齐 R10（anti-regression）：runtime 与 xtask R10 契约面 `syn::Ident` 在 ASCII 内**同拒** Rust 关键字
    // 与裸 `_`（codegen step 函数名不可为关键字 / `_`）。固定该对齐：若未来放松接受关键字，本测试触发回归复审。
    // 残留 unicode 分歧 + 单一标识符/关键字源统一见 #1175。
    #[test]
    fn is_rust_ident_rejects_keywords_and_underscore_matching_r10() {
        for raw in [
            "fn", "if", "let", "pub", "match", "self", "Self", "async", "gen", "yield", "_",
        ] {
            assert!(
                !super::is_rust_ident(raw),
                "runtime 应与 R10 同拒 {raw:?}（关键字 / 裸 `_` 不可作 codegen step 函数名）"
            );
        }
        // 含 keyword 子串但非关键字、单 `r`（非 r# raw）仍接受。
        assert!(super::is_rust_ident("function"));
        assert!(super::is_rust_ident("r"));
        assert!(!super::is_rust_ident("r#fn"));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    // reason: 测试 canonical tenant literal 与 non-nil uuid happy path，item-level carve-out。
    fn saga_instance_ref_is_tenant_scoped_and_rejects_nil_saga_id() {
        let tenant = vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap();
        let id = SagaId::new(uuid::Uuid::from_u128(42));

        let instance = SagaInstanceRef::new(tenant, id).unwrap();

        assert_eq!(instance.tenant(), tenant);
        assert_eq!(instance.saga_id(), id);
        assert_eq!(
            SagaInstanceRef::new(tenant, SagaId::new(uuid::Uuid::nil())),
            Err(SagaInstanceRefError::NilSagaId)
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    // reason: 测试 canonical literals，item-level carve-out。
    fn saga_lease_rejects_empty_holder_nil_token_and_zero_epoch() {
        let tenant = vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap();
        let instance =
            SagaInstanceRef::new(tenant, SagaId::new(uuid::Uuid::from_u128(42))).unwrap();
        let token = uuid::Uuid::from_u128(7);

        assert_eq!(
            SagaLease::new(instance, " ", token, 1),
            Err(SagaLeaseError::EmptyHolder)
        );
        assert_eq!(
            SagaLease::new(instance, "runner-a", uuid::Uuid::nil(), 1),
            Err(SagaLeaseError::NilToken)
        );
        assert_eq!(
            SagaLease::new(instance, "runner-a", token, 0),
            Err(SagaLeaseError::ZeroEpoch)
        );
        let lease = SagaLease::new(instance, "runner-a", token, 1).unwrap();
        assert_eq!(lease.instance(), instance);
        assert_eq!(lease.holder_id(), "runner-a");
        assert_eq!(lease.lease_token(), token);
        assert_eq!(lease.epoch(), 1);

        let rendered = format!("{lease:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(
            !rendered.contains(&token.to_string()),
            "SagaLease Debug must not expose bearer lease token: {rendered}"
        );
    }
}
