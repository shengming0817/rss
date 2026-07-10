//! saga 执行与编排 —— 接缝类型 + 执行器实现（runtime lock gate + 前向 append journal + 失败逆序补偿 + checkpoint resume）。
//!
//! 两个 step 抽象的关系（reviewer 常问）：
//! - [`SagaAction`]（本模块，object-safe `BoxFuture`）= **erased 运行时动作栈**——执行器
//!   ([`SagaExecutorImpl`]) 驱动 [`SagaActionFactory`] 产出的 `Vec<Box<dyn SagaAction>>`，前向
//!   `do_it` / 逆序 `undo_it`。
//! - `consistency::saga::SagaStep`（native AFIT，`execute`/`compensate`）= **typed authoring / codegen
//!   目标** trait。外部组合根只注册 typed step factory；[`TypedSagaActionFactory`] 在构造期校验 generated
//!   saga spec 的 step 数量、顺序、名称与 output schema，再擦除成内部 [`SagaAction`]。
//!
//! resume 真正崩溃恢复：journal 只存 step 名，执行器经注入的 typed factory（saga 模板，对标
//! steno saga template registry）按声明序重物化整个 action 序，再据 journal 已完成前缀跳过、续跑或续补偿。
//!
//! 本 executor 仍是 direct primitive；background worker / `WorkerHealth` / readyz probe 封装在
//! [`crate::saga_worker`]，由组合根按 live saga registration 显式接线。
//!
//! ref: oxidecomputer/steno src/saga_action_generic.rs@main（`Action::do_it`/`undo_it`/`name` + 逆序补偿）。
//! ref: oxidecomputer/steno src/saga_log.rs@main（journal event replay 到 load status）。

use std::future::Future;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

use futures::future::BoxFuture;
use serde::Serialize;

use consistency::{
    CompensationOutcome, EngineError, EngineErrorKind, Lsn, SagaDefinition, SagaDurableStatus,
    SagaInstanceRef, SagaInstanceStatus, SagaJournalAppendOutcome, SagaJournalAppendRecord,
    SagaJournalRecord, SagaLease, SagaLeaseOutcome, SagaModelError, SagaReplayDecision, SagaStep,
    SagaStepCtx, StepName,
};
use diport::{
    CheckpointId, CheckpointOwner, CheckpointVersion, DeadLetterProvenance, DeadLetterRecord,
    DeadLetterStore, DeadLetterSummary, EnvelopeMetadata, LockAcquireOutcome, LockRenewOutcome,
    LockStoreError, LockStoreKey, OwnerCheckpointStore, SagaContractId, SagaInstanceRegistration,
    SagaInstanceStore, SagaJournal, SagaWorkerIdentity, SaveOutcome,
};

/// saga 实例标识（uuid newtype）。模型单源在 `consistency::saga`，本模块 re-export 供域 / 组合根经
/// `eventexec::SagaId` 命名。
pub use consistency::SagaId;
pub use consistency::SagaInterruption;

// ── 冻结接缝类型（do/undo 动作 + 结论 + 命令 + 执行状态）─────────────────────────

/// saga 动作上下文：标识动作运行所在的 saga + 节点。私有字段（F6 funnel，外部不可字面构造，只经
/// [`SagaActionCtx::new`]）。journal / checkpoint 句柄归执行器，**不**入 ctx（保单写者不变式）。
pub(crate) struct SagaActionCtx {
    instance: SagaInstanceRef,
    #[allow(dead_code)]
    // reason: erased action tests inspect node identity; typed runtime uses SagaStepCtx
    node_name: String,
}

impl SagaActionCtx {
    /// 受控构造（执行器在每次 `do_it`/`undo_it` 前构造并移交动作）。
    pub fn new(instance: SagaInstanceRef, node_name: impl Into<String>) -> Self {
        Self {
            instance,
            node_name: node_name.into(),
        }
    }

    /// 所属 tenant-scoped saga 实例。
    pub fn instance(&self) -> SagaInstanceRef {
        self.instance
    }

    /// 所属租户。
    #[allow(dead_code)] // reason: retained for internal erased-action tests while public entry is typed
    pub fn tenant(&self) -> vocab::TenantId {
        self.instance.tenant()
    }

    /// 所属 saga 实例。
    #[allow(dead_code)] // reason: retained for internal erased-action tests while public entry is typed
    pub fn saga_id(&self) -> SagaId {
        self.instance.saga_id()
    }

    /// 当前节点（step）名。
    #[allow(dead_code)] // reason: retained for internal erased-action tests while public entry is typed
    pub fn node_name(&self) -> &str {
        &self.node_name
    }
}

/// saga 动作（erased runtime primitive；外部代码经 [`TypedSagaActionFactory`] 注册 typed
/// [`consistency::SagaStep`]，不直接实现本 trait）。
///
/// 对标 steno `Action`：`do_it` 前向（返回输出字节），`undo_it` 补偿（幂等，逆序调用）。
pub(crate) trait SagaAction: std::fmt::Debug + Send + Sync {
    /// step 名（须为合法 Rust 标识符；执行器据此落 journal + resume 时由 factory 重物化）。
    fn name(&self) -> &str;

    /// 前向执行；`Ok(output)` 完成（output 仅作为 run 路径末步结果，不进入 durable journal）。
    fn do_it(&self, ctx: SagaActionCtx) -> BoxFuture<'static, Result<Vec<u8>, SagaActionError>>;

    /// Whether this action's failed `do_it` means forward side effects already ran and must be
    /// compensated. Erased test actions default to fail-before-complete; typed actions use this for
    /// post-execute output serialization failures.
    fn failed_after_forward_effect(&self, _error: &SagaActionError) -> bool {
        false
    }

    /// 补偿（撤销 `do_it` 副作用）；仅对**已完成**步逆序调用。
    fn undo_it(&self, ctx: SagaActionCtx) -> BoxFuture<'static, Result<(), SagaActionError>>;
}

/// saga 执行结论。
#[derive(Debug)]
#[non_exhaustive]
pub enum SagaOutcome {
    /// 全步成功；`output` = 末步 `do_it` 输出（`run` 路径）。
    /// resume 路径终态成功时 `output` 恒为空字节——journal `read` 不回传 output，consumer 不得依赖。
    Succeeded { output: Vec<u8> },
    /// 失败（前向某步失败 → 已完成步逆序补偿后返回原失败，或补偿失败 → dead-letter）。
    Failed {
        failed_node: String,
        error: SagaActionError,
    },
    /// Non-business interruption: lease contention/loss or durable journal conflict.
    Interrupted { reason: SagaInterruption },
}

/// saga 编排控制命令（saga-orchestration control 接缝，非通用命令分发）。
///
/// **F14：crate-internal（`pub(crate)`）**——P9 无 saga 控制命令执行路径（`Start`/`Cancel` 均无
/// executor 入口），故不暴露公开 API（避免「公开命令面暗示 runtime 已支持」）。
///
/// **注意**：此枚举是 saga Start/Cancel 编排控制的未来接缝，与 #1124 交付的**通用 outbox-topic 命令
/// 分发机制**（`eventexec::command` + `generated::command`）无关。通用命令 dispatch 已落地；此枚举
/// 待 saga 控制面（中断语义 / leader-elect 等后续 issue）消费时再公开。
#[allow(dead_code)]
// reason: 冻结 saga 编排控制接缝占位（#997 saga seam）；P9 无 saga 控制命令消费者，pub(crate) 隐藏
// 未实现命令面（F14），待 saga 控制面后续 issue 消费（与通用 command dispatch #1124 无关）
#[derive(Debug)]
#[non_exhaustive]
pub(crate) enum SagaCommand {
    /// 启动新 saga。
    Start { saga_id: SagaId },
    /// 取消 saga（P9：无中断实现，待 P11 落地）。
    Cancel { saga_id: SagaId },
}

/// saga 执行状态（[`SagaTailer`] 粗粒度 liveness；细分结论在 [`SagaOutcome`]）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaExecStatus {
    /// 已登记未起（保留——当前 journal 驱动的 tailer **不产出**此变体，待 registry-aware tailer）。
    Ready,
    /// 执行 / 补偿在飞。
    Running,
    /// 终态（成功 / 已补偿 / dead-letter）。
    Done,
    /// durable journal 或 factory definition 与模型不一致，需运维介入。
    Degraded,
}

/// saga 动作错误（`#[non_exhaustive]`；执行器对各变体同样处理——任一 `do_it` 错 → 补偿，任一 `undo_it`
/// 错 → dead-letter；变体保留进 [`SagaOutcome::Failed`] 供调用方）。
///
/// 各变体均可出现在 [`SagaOutcome::Failed`]`.error`；consumer 若需区分是否已触发补偿，须查 journal 是否有
/// `Compensating`/`Compensated` 行（`SerializeFailed` 可表示 step 名非法的 fail-fast，也可表示 typed output
/// 在 `execute` 后 JSON 编码失败并已触发当前 step 补偿）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SagaActionError {
    /// 动作执行失败。
    #[error("action failed")]
    ActionFailed,
    /// Non-retryable action failure.
    #[error("non-retryable action failed")]
    NonRetryableActionFailed,
    /// 输出 / 标识序列化失败（含 step 名非法标识符）。
    #[error("serialize failed")]
    SerializeFailed,
    /// 子 saga 创建失败。
    #[error("subsaga create failed")]
    SubsagaCreateFailed,
    /// 动作超过 saga runtime policy 的单 phase 总预算。
    #[error("action timed out")]
    ActionTimedOut,
}

impl SagaActionError {
    fn as_label(&self) -> &'static str {
        match self {
            Self::ActionFailed => "action_failed",
            Self::NonRetryableActionFailed => "non_retryable_action_failed",
            Self::SerializeFailed => "serialize_failed",
            Self::SubsagaCreateFailed => "subsaga_create_failed",
            Self::ActionTimedOut => "action_timed_out",
        }
    }
}

/// Error constructing a typed saga action factory from generated contract metadata.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TypedSagaFactoryError {
    /// Generated step name failed runtime `StepName` validation.
    #[error("typed saga step name is invalid: name={name:?}")]
    InvalidStepName { name: &'static str },
    /// Registered typed steps do not match the generated contract step count.
    #[error(
        "typed saga step count does not match generated contract: expected={expected} actual={actual}"
    )]
    StepCountMismatch { expected: usize, actual: usize },
    /// Registered typed step binding differs from the generated ordered binding.
    #[error(
        "typed saga step binding does not match generated contract: index={index} expected={expected:?} actual={actual:?}"
    )]
    StepBindingMismatch {
        index: usize,
        expected: Box<vocab::SagaStepBinding>,
        actual: Box<vocab::SagaStepBinding>,
    },
    /// Registered typed step output DTO binding differs from the step binding.
    #[error(
        "typed saga step output binding does not match step binding: step={step:?} output={output:?}"
    )]
    StepOutputBindingMismatch {
        step: Box<vocab::SagaStepBinding>,
        output: Box<vocab::SagaStepBinding>,
    },
}

/// Typed saga action factory consumed by [`SagaExecutorDeps::new`].
///
/// It is built from one generated [`vocab::SagaContractBinding`] and typed
/// [`consistency::SagaStep`] factories. `finish` validates exact step count/order/contract/name/schema
/// before any executor can be constructed.
pub struct TypedSagaActionFactory {
    spec: vocab::SagaContractBinding,
    steps: Vec<Box<dyn TypedSagaStepSlot>>,
}

impl TypedSagaActionFactory {
    /// Start building a typed saga action factory from generated saga contract metadata.
    pub fn builder(spec: vocab::SagaContractBinding) -> TypedSagaActionFactoryBuilder {
        TypedSagaActionFactoryBuilder::new(spec)
    }

    /// Generated saga contract binding used to build this typed factory.
    #[must_use]
    pub fn spec(&self) -> vocab::SagaContractBinding {
        self.spec
    }
}

/// Builder for [`TypedSagaActionFactory`].
pub struct TypedSagaActionFactoryBuilder {
    spec: vocab::SagaContractBinding,
    steps: Vec<Box<dyn TypedSagaStepSlot>>,
}

impl TypedSagaActionFactoryBuilder {
    /// Create a builder tied to one generated saga contract binding.
    pub fn new(spec: vocab::SagaContractBinding) -> Self {
        Self {
            spec,
            steps: Vec::new(),
        }
    }

    /// Register one typed step factory in generated contract order.
    pub fn register_step<S, F>(&mut self, factory: F) -> Result<(), TypedSagaFactoryError>
    where
        S: SagaStep + std::fmt::Debug + Send + Sync + 'static,
        S::Output: Serialize + Send + 'static,
        F: Fn() -> S + Send + Sync + 'static,
    {
        let step_name = parse_binding_name(S::BINDING)?;
        let output_binding = <S::Output as vocab::SagaStepOutputBinding>::BINDING;
        if output_binding != S::BINDING {
            return Err(TypedSagaFactoryError::StepOutputBindingMismatch {
                step: Box::new(S::BINDING),
                output: Box::new(output_binding),
            });
        }
        self.steps.push(Box::new(RegisteredSagaStep::<S, F> {
            factory,
            step_name,
            _marker: PhantomData,
        }));
        Ok(())
    }

    /// Validate exact generated step parity and produce a runtime factory.
    pub fn finish(self) -> Result<TypedSagaActionFactory, TypedSagaFactoryError> {
        let expected = self.spec.steps();
        if expected.len() != self.steps.len() {
            return Err(TypedSagaFactoryError::StepCountMismatch {
                expected: expected.len(),
                actual: self.steps.len(),
            });
        }
        for (index, (expected, actual)) in expected.iter().zip(&self.steps).enumerate() {
            let actual = actual.binding();
            if *expected != actual {
                return Err(TypedSagaFactoryError::StepBindingMismatch {
                    index,
                    expected: Box::new(*expected),
                    actual: Box::new(actual),
                });
            }
        }
        Ok(TypedSagaActionFactory {
            spec: self.spec,
            steps: self.steps,
        })
    }
}

trait TypedSagaStepSlot: Send + Sync {
    fn binding(&self) -> vocab::SagaStepBinding;
    fn build_action(&self) -> Box<dyn SagaAction>;
}

struct RegisteredSagaStep<S, F> {
    factory: F,
    step_name: StepName,
    _marker: PhantomData<fn() -> S>,
}

impl<S, F> TypedSagaStepSlot for RegisteredSagaStep<S, F>
where
    S: SagaStep + std::fmt::Debug + Send + Sync + 'static,
    S::Output: Serialize + Send + 'static,
    F: Fn() -> S + Send + Sync + 'static,
{
    fn binding(&self) -> vocab::SagaStepBinding {
        S::BINDING
    }

    fn build_action(&self) -> Box<dyn SagaAction> {
        Box::new(TypedSagaStepAction {
            step: Arc::new((self.factory)()),
            step_name: self.step_name.clone(),
        })
    }
}

#[derive(Debug)]
struct TypedSagaStepAction<S> {
    step: Arc<S>,
    step_name: StepName,
}

impl<S> SagaAction for TypedSagaStepAction<S>
where
    S: SagaStep + std::fmt::Debug + Send + Sync + 'static,
    S::Output: Serialize + Send + 'static,
{
    fn name(&self) -> &str {
        self.step_name.as_str()
    }

    fn do_it(&self, ctx: SagaActionCtx) -> BoxFuture<'static, Result<Vec<u8>, SagaActionError>> {
        let step = self.step.clone();
        let step_name = self.step_name.clone();
        Box::pin(async move {
            let output = step
                .execute(SagaStepCtx::new(ctx.instance(), step_name))
                .await
                .map_err(engine_error_to_action_error)?;
            serde_json::to_vec(&output).map_err(|_| SagaActionError::SerializeFailed)
        })
    }

    fn failed_after_forward_effect(&self, error: &SagaActionError) -> bool {
        matches!(error, SagaActionError::SerializeFailed)
    }

    fn undo_it(&self, ctx: SagaActionCtx) -> BoxFuture<'static, Result<(), SagaActionError>> {
        let step = self.step.clone();
        let step_name = self.step_name.clone();
        Box::pin(async move {
            match step
                .compensate(SagaStepCtx::new(ctx.instance(), step_name))
                .await
                .map_err(engine_error_to_action_error)?
            {
                CompensationOutcome::Compensated => Ok(()),
                CompensationOutcome::Failed => Err(SagaActionError::NonRetryableActionFailed),
                _ => Err(SagaActionError::NonRetryableActionFailed),
            }
        })
    }
}

fn parse_binding_name(binding: vocab::SagaStepBinding) -> Result<StepName, TypedSagaFactoryError> {
    StepName::parse(binding.name()).map_err(|_| TypedSagaFactoryError::InvalidStepName {
        name: binding.name(),
    })
}

fn engine_error_to_action_error(error: EngineError) -> SagaActionError {
    match error.kind() {
        EngineErrorKind::Transient => SagaActionError::ActionFailed,
        EngineErrorKind::Permanent | EngineErrorKind::Invariant => {
            SagaActionError::NonRetryableActionFailed
        }
        _ => SagaActionError::NonRetryableActionFailed,
    }
}

/// Validated saga runtime policy.
///
/// Construction is intentionally funneled through `TryFrom<SagaRuntimePolicySpec>`: contract glue
/// exposes raw millisecond specs, while the executor only accepts validated runtime states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaPolicy {
    /// Retry and timeout are disabled (`retryMillis = 0`, `timeoutMillis = 0`).
    Disabled,
    /// One step phase has a total timeout budget, and may have fixed-delay retry.
    Bounded(SagaBoundedPolicy),
}

/// Sealed bounded saga policy state.
///
/// Fields stay private and there is no public raw-`Duration` constructor; the only production
/// boundary is `TryFrom<vocab::SagaRuntimePolicySpec>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SagaBoundedPolicy {
    retry_delay: Option<Duration>,
    step_timeout: Duration,
}

impl SagaBoundedPolicy {
    fn retry_delay(self) -> Option<Duration> {
        self.retry_delay
    }

    fn step_timeout(self) -> Duration {
        self.step_timeout
    }
}

/// Invalid generated saga runtime policy spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SagaPolicyError {
    /// Retry without a timeout budget can run forever.
    #[error("saga retry policy requires timeout budget")]
    RetryWithoutTimeout,
}

impl TryFrom<vocab::SagaRuntimePolicySpec> for SagaPolicy {
    type Error = SagaPolicyError;

    fn try_from(spec: vocab::SagaRuntimePolicySpec) -> Result<Self, Self::Error> {
        match (spec.retry_millis(), spec.timeout_millis()) {
            (0, 0) => Ok(Self::Disabled),
            (_, 0) => Err(SagaPolicyError::RetryWithoutTimeout),
            (0, timeout_millis) => Ok(Self::Bounded(SagaBoundedPolicy {
                retry_delay: None,
                step_timeout: Duration::from_millis(timeout_millis),
            })),
            (retry_millis, timeout_millis) => Ok(Self::Bounded(SagaBoundedPolicy {
                retry_delay: Some(Duration::from_millis(retry_millis)),
                step_timeout: Duration::from_millis(timeout_millis),
            })),
        }
    }
}

// ── 执行器 / 进度跟踪接缝 ──────────────────────────────────────────────────────

/// Saga 执行器接缝：驱动 [`SagaAction`] 栈（前向执行 + 失败逆序补偿）。对标 steno SEC。
pub trait SagaExecutor: Send + Sync {
    /// 执行 saga：注册 instance、获取 lease，然后经注入的 [`SagaActionFactory`] 顺序驱动动作。
    fn run(&self, instance: SagaInstanceRef) -> BoxFuture<'static, SagaOutcome>;

    /// 从 journal 恢复（crash recovery；经注入 [`SagaActionFactory`] 重物化 action 序续跑 / 续补偿）。
    ///
    /// resume 终态成功时 [`SagaOutcome::Succeeded`]`.output` 恒为空字节——journal `read` 不回传
    /// output；末步 output 仅 `run` 路径可信。consumer 不得依赖 resume 的 output 字节。
    fn resume(&self, instance: SagaInstanceRef) -> BoxFuture<'static, SagaOutcome>;
}

/// Saga 进度跟踪接缝：查询执行状态。对标 steno saga status。
pub trait SagaTailer: Send + Sync {
    /// 查 saga 当前粗粒度状态（`None` = 未知 saga）。
    ///
    /// 当前 journal-driven 实现**不产出** [`SagaExecStatus::Ready`]（保留给 registry-aware tailer）；
    /// 只返回 `None` / `Running` / `Done` / `Degraded`。
    fn status(&self, instance: SagaInstanceRef) -> BoxFuture<'static, Option<SagaExecStatus>>;
}

/// Saga runtime lock provider.
///
/// The lock is an outer multi-pod gate for `run`/`resume`; Postgres saga instance lease and
/// journal CAS remain the final fencing layer.
///
/// INVARIANT: SAGA-RUNTIME-LOCK-REQUIRED-01 { level = "Hard", exec = "native-compile", source = "code", native = "constructor required parameter" }——
/// `SagaExecutorDeps::new` requires this non-optional dependency, so composition roots cannot
/// construct a saga executor without choosing a memory/demo or Redis/durable lock provider.
#[derive(Clone)]
pub struct SagaRuntimeLock {
    provider: Arc<dyn SagaRuntimeLockProvider>,
}

impl SagaRuntimeLock {
    /// Wrap a lock provider chosen by the composition root.
    pub fn new<L>(provider: L) -> Self
    where
        L: diport::LockStore + Send + Sync + 'static,
    {
        Self {
            provider: Arc::new(provider),
        }
    }

    async fn acquire(
        &self,
        instance: SagaInstanceRef,
        contract_id: &str,
        operation: &'static str,
        ttl: Duration,
    ) -> Result<SagaRuntimeLockGrant, SagaInterruption> {
        let key = saga_runtime_lock_key(instance);
        let outcome = self
            .provider
            .acquire_lock(LockStoreKey::new(key.clone()), ttl)
            .await
            .map_err(|err| map_runtime_lock_error(instance, contract_id, operation, &err))?;
        match outcome {
            LockAcquireOutcome::Acquired { token } => Ok(SagaRuntimeLockGrant {
                lock: self.clone(),
                instance,
                contract_id: contract_id.to_string(),
                operation,
                key,
                token,
                ttl,
            }),
            LockAcquireOutcome::Held => {
                let reason = SagaInterruption::RuntimeLockBusy;
                log_runtime_lock_interrupted(instance, contract_id, operation, reason);
                Err(reason)
            }
            _ => {
                let reason = SagaInterruption::RuntimeLockUnavailable;
                log_runtime_lock_interrupted(instance, contract_id, operation, reason);
                Err(reason)
            }
        }
    }
}

trait SagaRuntimeLockProvider: Send + Sync {
    fn acquire_lock(
        &self,
        key: LockStoreKey,
        ttl: Duration,
    ) -> BoxFuture<'_, Result<LockAcquireOutcome, LockStoreError>>;

    fn renew_lock(
        &self,
        key: LockStoreKey,
        token: vocab::Epoch,
        ttl: Duration,
    ) -> BoxFuture<'_, Result<LockRenewOutcome, LockStoreError>>;

    fn release_lock(
        &self,
        key: LockStoreKey,
        token: vocab::Epoch,
    ) -> BoxFuture<'_, Result<(), LockStoreError>>;
}

impl<L> SagaRuntimeLockProvider for L
where
    L: diport::LockStore + Send + Sync + 'static,
{
    fn acquire_lock(
        &self,
        key: LockStoreKey,
        ttl: Duration,
    ) -> BoxFuture<'_, Result<LockAcquireOutcome, LockStoreError>> {
        Box::pin(diport::LockStore::acquire(self, key, ttl))
    }

    fn renew_lock(
        &self,
        key: LockStoreKey,
        token: vocab::Epoch,
        ttl: Duration,
    ) -> BoxFuture<'_, Result<LockRenewOutcome, LockStoreError>> {
        Box::pin(diport::LockStore::renew(self, key, token, ttl))
    }

    fn release_lock(
        &self,
        key: LockStoreKey,
        token: vocab::Epoch,
    ) -> BoxFuture<'_, Result<(), LockStoreError>> {
        Box::pin(diport::LockStore::release(self, key, token))
    }
}

fn log_runtime_lock_interrupted(
    instance: SagaInstanceRef,
    contract_id: &str,
    operation: &'static str,
    reason: SagaInterruption,
) {
    tracing::warn!(
        tenant_id = %instance.tenant(),
        saga_id = %instance.saga_id().as_uuid(),
        contract_id = %contract_id,
        operation = operation,
        reason = reason.as_label(),
        "saga: runtime lock interrupted"
    );
}

fn log_runtime_lock_interrupted_error(
    instance: SagaInstanceRef,
    contract_id: &str,
    operation: &'static str,
    reason: SagaInterruption,
    error: &LockStoreError,
) {
    tracing::warn!(
        tenant_id = %instance.tenant(),
        saga_id = %instance.saga_id().as_uuid(),
        contract_id = %contract_id,
        operation = operation,
        reason = reason.as_label(),
        error = %error,
        "saga: runtime lock interrupted"
    );
}

fn log_runtime_lock_release_failed(
    instance: SagaInstanceRef,
    contract_id: &str,
    operation: &'static str,
    error: &LockStoreError,
) {
    tracing::warn!(
        tenant_id = %instance.tenant(),
        saga_id = %instance.saga_id().as_uuid(),
        contract_id = %contract_id,
        operation = operation,
        reason = "runtime_lock_release_failed",
        error = %error,
        "saga: runtime lock release failed"
    );
}

fn map_runtime_lock_error(
    instance: SagaInstanceRef,
    contract_id: &str,
    operation: &'static str,
    error: &LockStoreError,
) -> SagaInterruption {
    let reason = SagaInterruption::RuntimeLockUnavailable;
    log_runtime_lock_interrupted_error(instance, contract_id, operation, reason, error);
    reason
}

struct SagaRuntimeLockGrant {
    lock: SagaRuntimeLock,
    instance: SagaInstanceRef,
    contract_id: String,
    operation: &'static str,
    key: String,
    token: vocab::Epoch,
    ttl: Duration,
}

impl SagaRuntimeLockGrant {
    async fn renew(&mut self) -> Result<(), SagaInterruption> {
        let outcome = self
            .lock
            .provider
            .renew_lock(LockStoreKey::new(self.key.clone()), self.token, self.ttl)
            .await
            .map_err(|err| {
                map_runtime_lock_error(self.instance, &self.contract_id, self.operation, &err)
            })?;
        match outcome {
            LockRenewOutcome::Renewed { token } => {
                self.token = token;
                Ok(())
            }
            LockRenewOutcome::Lost => {
                let reason = SagaInterruption::RuntimeLockLost;
                log_runtime_lock_interrupted(
                    self.instance,
                    &self.contract_id,
                    self.operation,
                    reason,
                );
                Err(reason)
            }
            _ => {
                let reason = SagaInterruption::RuntimeLockUnavailable;
                log_runtime_lock_interrupted(
                    self.instance,
                    &self.contract_id,
                    self.operation,
                    reason,
                );
                Err(reason)
            }
        }
    }

    async fn release_best_effort(&self) {
        if let Err(err) = self
            .lock
            .provider
            .release_lock(LockStoreKey::new(self.key.clone()), self.token)
            .await
        {
            log_runtime_lock_release_failed(self.instance, &self.contract_id, self.operation, &err);
        }
    }
}

async fn run_with_runtime_lock<F>(mut grant: SagaRuntimeLockGrant, operation: F) -> SagaOutcome
where
    F: Future<Output = SagaOutcome>,
{
    tokio::pin!(operation);
    let mut renew_sleep = Box::pin(tokio::time::sleep(lease_renewal_delay(grant.ttl)));
    loop {
        tokio::select! {
            biased;
            outcome = &mut operation => {
                grant.release_best_effort().await;
                return outcome;
            }
            () = &mut renew_sleep => {
                match grant.renew().await {
                    Ok(()) => {
                        renew_sleep = Box::pin(tokio::time::sleep(lease_renewal_delay(grant.ttl)));
                    }
                    Err(reason) => {
                        grant.release_best_effort().await;
                        return SagaOutcome::Interrupted { reason };
                    }
                }
            }
        }
    }
}

fn saga_runtime_lock_key(instance: SagaInstanceRef) -> String {
    format!(
        "saga/{}/{}",
        instance.tenant(),
        instance.saga_id().as_uuid()
    )
}

/// saga 模板：按声明序产出全部 [`SagaAction`]。resume 用——执行器仅持 `saga_id`，须经此重物化整个
/// action 序（journal 只存 step 名，无法重建闭包）。对标 steno saga template / dag registry。
pub(crate) trait SagaActionFactory: Send + Sync {
    /// 构造该 saga 类型的有序 action 序（每次新建实例；执行器据 journal 已完成前缀决定跳过 / 续跑）。
    ///
    /// 实现必须每次返回**相同的完整有序 action 序**（与 `run` 传入序的 step 名 + 顺序一致）。
    /// resume 靠 journal step 名与 action index 一一对应重建状态，缺步 / 重排即导致错跳 / 补偿错乱。
    fn build(&self) -> Vec<Box<dyn SagaAction>>;
}

impl SagaActionFactory for TypedSagaActionFactory {
    fn build(&self) -> Vec<Box<dyn SagaAction>> {
        self.steps.iter().map(|step| step.build_action()).collect()
    }
}

/// 补偿失败安全摘要（`&'static str` const literal；进 journal `Failed` 行 + DLX 摘要 + tracing，不携 runtime
/// 数据，INVARIANT: DIPORT-DLX-SUMMARY-STATIC-01 { level = "Medium", exec = "manual/opt-in", source = "code" }）。
const SAGA_COMPENSATION_FAILED: &str = "saga compensation step failed";
const SAGA_COMPENSATION_COMPLETION_LOST: &str =
    "saga compensation completion journal append failed";

/// resume 未知 saga（缺失实例行）占位 failed_node。
const UNKNOWN_SAGA: &str = "<unknown-saga>";

// ── SagaExecutorImpl ──────────────────────────────────────────────────────────

/// saga 执行器实现：必填依赖走构造器**位置参**（saga.md §构造器，缺失即编译错误）。泛型静态分发 +
/// `Arc<S>`（`run`/`resume` 返回 `'static` future，须 clone 句柄进 future；对齐 diport 注入形态表
/// spawn/Send-'static 行）。
///
/// `kind:saga` 契约声明的 `retryMillis`/`timeoutMillis` 先经 generated
/// [`vocab::SagaRuntimePolicySpec`] 暴露，再由组合根转成 [`SagaPolicy`] 注入 executor。执行器仅接受已验证
/// runtime policy：`do_it` / `undo_it` 都被同一总预算 + 固定退避策略包住。
pub struct SagaExecutorImpl<J, C, D, S> {
    journal: Arc<J>,
    instance_store: Arc<S>,
    checkpoint: Arc<C>,
    dead_letter: Arc<D>,
    factory: Arc<dyn SagaActionFactory>,
    runtime_lock: SagaRuntimeLock,
    owner: CheckpointOwner,
    identity: SagaWorkerIdentity,
    holder_id: String,
    lease_ttl: Duration,
    policy: SagaPolicy,
}

/// Saga executor durable dependencies.
pub struct SagaExecutorDeps<J, C, D, S> {
    journal: Arc<J>,
    instance_store: Arc<S>,
    checkpoint: Arc<C>,
    dead_letter: Arc<D>,
    factory: Arc<dyn SagaActionFactory>,
    runtime_lock: SagaRuntimeLock,
}

impl<J, C, D, S> SagaExecutorDeps<J, C, D, S> {
    pub fn new(
        journal: Arc<J>,
        instance_store: Arc<S>,
        checkpoint: Arc<C>,
        dead_letter: Arc<D>,
        factory: TypedSagaActionFactory,
        runtime_lock: SagaRuntimeLock,
    ) -> Self {
        Self {
            journal,
            instance_store,
            checkpoint,
            dead_letter,
            factory: Arc::new(factory),
            runtime_lock,
        }
    }

    #[cfg(test)]
    pub(crate) fn new_erased(
        journal: Arc<J>,
        instance_store: Arc<S>,
        checkpoint: Arc<C>,
        dead_letter: Arc<D>,
        factory: Arc<dyn SagaActionFactory>,
        runtime_lock: SagaRuntimeLock,
    ) -> Self {
        Self {
            journal,
            instance_store,
            checkpoint,
            dead_letter,
            factory,
            runtime_lock,
        }
    }
}

/// Saga executor identity and lease configuration.
pub struct SagaExecutorConfig {
    owner: CheckpointOwner,
    identity: SagaWorkerIdentity,
    holder_id: String,
    lease_ttl: Duration,
    policy: SagaPolicy,
}

/// Error constructing [`SagaExecutorConfig`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SagaExecutorConfigError {
    /// Generated saga policy was invalid.
    #[error(transparent)]
    Policy(#[from] SagaPolicyError),
    /// Generated contract id was invalid.
    #[error(transparent)]
    ContractId(#[from] diport::SagaContractIdError),
    /// Saga worker identity was invalid.
    #[error(transparent)]
    Identity(#[from] diport::SagaWorkerIdentityError),
}

impl SagaExecutorConfig {
    /// Build executor config from the same generated saga contract binding used by the typed factory.
    ///
    /// Runtime composition receives one object for action registration and derives contract id and
    /// policy from it, so the executor config cannot drift to a different saga contract.
    pub fn from_typed_factory(
        owner: CheckpointOwner,
        holder_id: impl Into<String>,
        lease_ttl: Duration,
        factory: &TypedSagaActionFactory,
    ) -> Result<Self, SagaExecutorConfigError> {
        Self::from_contract_spec(owner, holder_id, lease_ttl, factory.spec())
    }

    fn from_contract_spec(
        owner: CheckpointOwner,
        holder_id: impl Into<String>,
        lease_ttl: Duration,
        spec: vocab::SagaContractBinding,
    ) -> Result<Self, SagaExecutorConfigError> {
        let policy = SagaPolicy::try_from(spec.policy())?;
        Self::new(owner, spec.contract_id(), holder_id, lease_ttl, policy)
    }

    fn new(
        owner: CheckpointOwner,
        contract_id: impl Into<String>,
        holder_id: impl Into<String>,
        lease_ttl: Duration,
        policy: SagaPolicy,
    ) -> Result<Self, SagaExecutorConfigError> {
        let contract_id = contract_id.into();
        let contract_id = SagaContractId::parse(&contract_id)?;
        let identity = SagaWorkerIdentity::new(owner.as_str(), contract_id)?;
        Ok(Self {
            owner,
            identity,
            holder_id: holder_id.into(),
            lease_ttl,
            policy,
        })
    }

    /// Worker identity derived from the generated saga contract binding.
    pub fn identity(&self) -> &SagaWorkerIdentity {
        &self.identity
    }

    /// Lease holder id used by this executor.
    pub fn holder_id(&self) -> &str {
        &self.holder_id
    }

    /// Lease ttl used by this executor.
    pub fn lease_ttl(&self) -> Duration {
        self.lease_ttl
    }
}

impl<J, C, D, S> SagaExecutorImpl<J, C, D, S>
where
    J: SagaJournal + Send + Sync + 'static,
    C: OwnerCheckpointStore + Send + Sync + 'static,
    D: DeadLetterStore + Send + Sync + 'static,
    S: SagaInstanceStore + Send + Sync + 'static,
{
    /// 构造（全依赖必填位置参）。
    ///
    /// `config.owner` = DLX domain（如 `"billing"`）；`config.contract_id` = 契约 id（如
    /// `"billing.checkout"`）。二者同进 DLX 记录（SC-006），勿传反。
    pub fn new(deps: SagaExecutorDeps<J, C, D, S>, config: SagaExecutorConfig) -> Self {
        Self {
            journal: deps.journal,
            instance_store: deps.instance_store,
            checkpoint: deps.checkpoint,
            dead_letter: deps.dead_letter,
            factory: deps.factory,
            runtime_lock: deps.runtime_lock,
            owner: config.owner,
            identity: config.identity,
            holder_id: config.holder_id,
            lease_ttl: config.lease_ttl,
            policy: config.policy,
        }
    }
}

impl<J, C, D, S> SagaExecutor for SagaExecutorImpl<J, C, D, S>
where
    J: SagaJournal + Send + Sync + 'static,
    C: OwnerCheckpointStore + Send + Sync + 'static,
    D: DeadLetterStore + Send + Sync + 'static,
    S: SagaInstanceStore + Send + Sync + 'static,
{
    fn run(&self, instance: SagaInstanceRef) -> BoxFuture<'static, SagaOutcome> {
        let journal = self.journal.clone();
        let instance_store = self.instance_store.clone();
        let checkpoint = self.checkpoint.clone();
        let dead_letter = self.dead_letter.clone();
        let owner = self.owner.clone();
        let identity = self.identity.clone();
        let holder_id = self.holder_id.clone();
        let lease_ttl = self.lease_ttl;
        let policy = self.policy;
        let factory = self.factory.clone();
        let runtime_lock = self.runtime_lock.clone();
        Box::pin(async move {
            let grant = match runtime_lock
                .acquire(instance, identity.contract_id().as_str(), "run", lease_ttl)
                .await
            {
                Ok(grant) => grant,
                Err(reason) => return SagaOutcome::Interrupted { reason },
            };
            run_with_runtime_lock(grant, async move {
                let actions = factory.build();
                if let Err(err) = definition_from_actions(&actions) {
                    let failed_node = model_error_node(&err);
                    tracing::error!(
                        tenant_id = %instance.tenant(),
                        saga_id = %instance.saga_id().as_uuid(),
                        failed_node = %failed_node,
                        "saga: action definition invalid"
                    );
                    return SagaOutcome::Failed {
                        failed_node,
                        error: SagaActionError::SerializeFailed,
                    };
                }
                let lease = match acquire_run_lease(
                    &*instance_store,
                    instance,
                    identity.clone(),
                    &holder_id,
                    lease_ttl,
                )
                .await
                {
                    Ok(lease) => lease,
                    Err(reason) => return SagaOutcome::Interrupted { reason },
                };
                let ctx = ExecCtx {
                    journal: &*journal,
                    instance_store: &*instance_store,
                    checkpoint: &*checkpoint,
                    dead_letter: &*dead_letter,
                    owner: &owner,
                    contract_id: identity.contract_id().as_str(),
                    instance,
                    lease,
                    lease_ttl,
                    policy,
                    checkpoint_id: saga_checkpoint_id(instance),
                };
                ctx.run_forward(&actions, 0, Cursor::new()).await
            })
            .await
        })
    }

    fn resume(&self, instance: SagaInstanceRef) -> BoxFuture<'static, SagaOutcome> {
        let journal = self.journal.clone();
        let instance_store = self.instance_store.clone();
        let checkpoint = self.checkpoint.clone();
        let dead_letter = self.dead_letter.clone();
        let owner = self.owner.clone();
        let identity = self.identity.clone();
        let holder_id = self.holder_id.clone();
        let lease_ttl = self.lease_ttl;
        let policy = self.policy;
        let factory = self.factory.clone();
        let runtime_lock = self.runtime_lock.clone();
        Box::pin(async move {
            let grant = match runtime_lock
                .acquire(
                    instance,
                    identity.contract_id().as_str(),
                    "resume",
                    lease_ttl,
                )
                .await
            {
                Ok(grant) => grant,
                Err(reason) => return SagaOutcome::Interrupted { reason },
            };
            run_with_runtime_lock(grant, async move {
                let actions = factory.build();
                let lease =
                    match acquire_resume_lease(&*instance_store, instance, &holder_id, lease_ttl)
                        .await
                    {
                        ResumeLeaseDecision::Acquired(lease) => lease,
                        ResumeLeaseDecision::Unknown => return unknown_saga_outcome(),
                        ResumeLeaseDecision::Terminal(status) => {
                            return outcome_from_instance_status(status);
                        }
                        ResumeLeaseDecision::Interrupted(reason) => {
                            return SagaOutcome::Interrupted { reason };
                        }
                    };
                let ctx = ExecCtx {
                    journal: &*journal,
                    instance_store: &*instance_store,
                    checkpoint: &*checkpoint,
                    dead_letter: &*dead_letter,
                    owner: &owner,
                    contract_id: identity.contract_id().as_str(),
                    instance,
                    lease,
                    lease_ttl,
                    policy,
                    checkpoint_id: saga_checkpoint_id(instance),
                };
                ctx.resume(&actions).await
            })
            .await
        })
    }
}

impl<J, C, D, S> SagaTailer for SagaExecutorImpl<J, C, D, S>
where
    J: SagaJournal + Send + Sync + 'static,
    C: OwnerCheckpointStore + Send + Sync + 'static,
    D: DeadLetterStore + Send + Sync + 'static,
    S: SagaInstanceStore + Send + Sync + 'static,
{
    fn status(&self, instance: SagaInstanceRef) -> BoxFuture<'static, Option<SagaExecStatus>> {
        let journal = self.journal.clone();
        let instance_store = self.instance_store.clone();
        let factory = self.factory.clone();
        Box::pin(async move {
            let actions = factory.build();
            status_of(&*journal, &*instance_store, instance, &actions).await
        })
    }
}

async fn acquire_run_lease<S>(
    store: &S,
    instance: SagaInstanceRef,
    identity: SagaWorkerIdentity,
    holder_id: &str,
    lease_ttl: Duration,
) -> Result<SagaLease, SagaInterruption>
where
    S: SagaInstanceStore,
{
    match store.get(&instance).await {
        Ok(Some(row)) => match row.status() {
            SagaInstanceStatus::Ready => {}
            SagaInstanceStatus::Degraded => return Err(SagaInterruption::InstanceDegraded),
            _ => return Err(SagaInterruption::AlreadyStarted),
        },
        Ok(None) => {
            let registration = SagaInstanceRegistration::new(instance, identity);
            store
                .register(registration)
                .await
                .map_err(|_| SagaInterruption::StoreUnavailable)?;
        }
        Err(_) => return Err(SagaInterruption::StoreUnavailable),
    }
    store
        .acquire_lease(&instance, holder_id, lease_ttl)
        .await
        .map_err(|_| SagaInterruption::StoreUnavailable)?
        .ok_or(SagaInterruption::LeaseBusy)
}

enum ResumeLeaseDecision {
    Acquired(SagaLease),
    Unknown,
    Terminal(SagaInstanceStatus),
    Interrupted(SagaInterruption),
}

async fn acquire_resume_lease<S>(
    store: &S,
    instance: SagaInstanceRef,
    holder_id: &str,
    lease_ttl: Duration,
) -> ResumeLeaseDecision
where
    S: SagaInstanceStore,
{
    let row = match store.get(&instance).await {
        Ok(Some(row)) => row,
        Ok(None) => return ResumeLeaseDecision::Unknown,
        Err(_) => return ResumeLeaseDecision::Interrupted(SagaInterruption::StoreUnavailable),
    };
    match row.status() {
        SagaInstanceStatus::Succeeded
        | SagaInstanceStatus::Compensated
        | SagaInstanceStatus::Failed => ResumeLeaseDecision::Terminal(row.status()),
        SagaInstanceStatus::Degraded => {
            ResumeLeaseDecision::Interrupted(SagaInterruption::InstanceDegraded)
        }
        SagaInstanceStatus::Ready
        | SagaInstanceStatus::Running
        | SagaInstanceStatus::Compensating => {
            match store.acquire_lease(&instance, holder_id, lease_ttl).await {
                Ok(Some(lease)) => ResumeLeaseDecision::Acquired(lease),
                Ok(None) => ResumeLeaseDecision::Interrupted(SagaInterruption::LeaseBusy),
                Err(_) => ResumeLeaseDecision::Interrupted(SagaInterruption::StoreUnavailable),
            }
        }
        _ => ResumeLeaseDecision::Interrupted(SagaInterruption::StoreUnavailable),
    }
}

fn saga_checkpoint_id(instance: SagaInstanceRef) -> CheckpointId {
    CheckpointId::new(format!(
        "{}:{}",
        instance.tenant(),
        instance.saga_id().as_uuid()
    ))
}

// ── 执行上下文（持运行时句柄引用，方法实现前向 / 补偿 / checkpoint）─────────────

/// 前向游标：journal append 序号 + 已完成步栈（index + StepName）+ 末步输出。
struct Cursor {
    seq: u64,
    completed: Vec<(usize, StepName)>,
    last_output: Option<Vec<u8>>,
}

impl Cursor {
    fn new() -> Self {
        Self {
            seq: 0,
            completed: Vec::new(),
            last_output: None,
        }
    }
}

struct ExecCtx<'a, J, C, D, S> {
    journal: &'a J,
    instance_store: &'a S,
    checkpoint: &'a C,
    dead_letter: &'a D,
    owner: &'a CheckpointOwner,
    contract_id: &'a str,
    instance: SagaInstanceRef,
    lease: SagaLease,
    lease_ttl: Duration,
    policy: SagaPolicy,
    checkpoint_id: CheckpointId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SagaActionPhase {
    Forward,
    Compensation,
}

impl SagaActionPhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::Forward => "forward",
            Self::Compensation => "compensation",
        }
    }
}

fn is_saga_action_retryable(err: &SagaActionError) -> bool {
    !matches!(
        err,
        SagaActionError::SerializeFailed | SagaActionError::NonRetryableActionFailed
    )
}

fn duration_millis_u64(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn lease_renewal_delay(lease_ttl: Duration) -> Duration {
    let delay = lease_ttl / 2;
    if delay.is_zero() {
        Duration::from_millis(1)
    } else {
        delay
    }
}

#[derive(Debug)]
enum SagaPhaseError {
    Action(SagaActionError),
    Interrupted(SagaInterruption),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AppendFailure {
    LeaseLost,
    JournalConflict,
    Storage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AppendDecision {
    Success,
    LeaseLost,
    JournalConflict,
    Storage,
}

impl<J, C, D, S> ExecCtx<'_, J, C, D, S>
where
    J: SagaJournal,
    C: OwnerCheckpointStore,
    D: DeadLetterStore,
    S: SagaInstanceStore,
{
    /// append 一条 journal，返回是否成功（失败记结构化日志）。
    ///
    /// F1：journal 写是执行状态机**一等边**，不再 best-effort 吞错——前向路径据返回值 fail-closed
    /// （`Executing` 写失败 ⇒ 不执行副作用；`Completed` 写失败 ⇒ 补偿含本步在内的栈）。补偿路径同样
    /// fail-closed：任一 journal 边界写失败即停止后续 undo / DLX 外部副作用。
    async fn append(&self, entry: SagaJournalAppendRecord) -> Result<(), AppendFailure> {
        let seq = entry.seq();
        let status = entry.status().as_str();
        let decision = match self.journal.append(&self.lease, entry).await {
            Ok(outcome) => Self::append_decision(outcome),
            Err(_) => {
                self.error_append_failed(seq, status);
                AppendDecision::Storage
            }
        };
        self.handle_append_decision(decision, seq, status).await
    }

    fn append_decision(outcome: SagaJournalAppendOutcome) -> AppendDecision {
        match outcome {
            SagaJournalAppendOutcome::Appended | SagaJournalAppendOutcome::IdempotentDuplicate => {
                AppendDecision::Success
            }
            SagaJournalAppendOutcome::LeaseLost => AppendDecision::LeaseLost,
            SagaJournalAppendOutcome::AppendConflict => AppendDecision::JournalConflict,
            _ => AppendDecision::Storage,
        }
    }

    async fn handle_append_decision(
        &self,
        decision: AppendDecision,
        seq: u64,
        status: &'static str,
    ) -> Result<(), AppendFailure> {
        match decision {
            AppendDecision::Success => Ok(()),
            AppendDecision::LeaseLost => {
                self.warn_append_lease_lost(seq, status);
                Err(AppendFailure::LeaseLost)
            }
            AppendDecision::JournalConflict => {
                self.mark_status_and_release_best_effort(SagaInstanceStatus::Degraded)
                    .await;
                self.error_append_conflict(seq, status);
                Err(AppendFailure::JournalConflict)
            }
            AppendDecision::Storage => Err(AppendFailure::Storage),
        }
    }

    fn warn_append_lease_lost(&self, seq: u64, status: &'static str) {
        tracing::warn!(
            tenant_id = %self.instance.tenant(),
            saga_id = %self.instance.saga_id().as_uuid(),
            seq,
            status,
            "saga: journal append lease lost"
        );
    }

    fn error_append_conflict(&self, seq: u64, status: &'static str) {
        tracing::error!(
            tenant_id = %self.instance.tenant(),
            saga_id = %self.instance.saga_id().as_uuid(),
            seq,
            status,
            "saga: journal append conflict"
        );
    }

    fn error_append_failed(&self, seq: u64, status: &'static str) {
        tracing::error!(
            tenant_id = %self.instance.tenant(),
            saga_id = %self.instance.saga_id().as_uuid(),
            seq,
            status,
            "saga: journal append failed"
        );
    }

    async fn refresh_lease(&self) -> bool {
        matches!(
            self.instance_store
                .extend_lease(&self.lease, self.lease_ttl)
                .await,
            Ok(SagaLeaseOutcome::Held)
        )
    }

    async fn mark_status_best_effort(&self, status: SagaInstanceStatus) {
        let _ = self.instance_store.mark_status(&self.lease, status).await;
    }

    async fn release_lease_best_effort(&self) {
        let _ = self.instance_store.release_lease(&self.lease).await;
    }

    async fn mark_status_and_release_best_effort(&self, status: SagaInstanceStatus) {
        self.mark_status_best_effort(status).await;
        self.release_lease_best_effort().await;
    }

    fn interrupted(reason: SagaInterruption) -> SagaOutcome {
        SagaOutcome::Interrupted { reason }
    }

    fn append_failure_outcome(&self, failure: AppendFailure, failed_node: &str) -> SagaOutcome {
        match failure {
            AppendFailure::LeaseLost => Self::interrupted(SagaInterruption::LeaseLost),
            AppendFailure::JournalConflict => Self::interrupted(SagaInterruption::JournalConflict),
            AppendFailure::Storage => SagaOutcome::Failed {
                failed_node: failed_node.to_string(),
                error: SagaActionError::ActionFailed,
            },
        }
    }

    /// CAS 推进 checkpoint，返回是否可继续前向。
    ///
    /// F2：`StaleVersion` = 并发执行器已推进 checkpoint = 本 runner **失 fence** ⇒ 返 `false`（停跑，不续后续
    /// step）；infra 读/写错误 ⇒ 记日志续跑（`true`，journal 为权威，checkpoint 仅快进游标，不因瞬时故障停
    /// saga）。日志收口到 [`ExecCtx::warn_checkpoint`] 控制认知复杂度 ≤15。
    async fn advance_checkpoint(&self, offset: Lsn) -> bool {
        let expected = match self
            .checkpoint
            .get_checkpoint(self.owner, &self.checkpoint_id)
            .await
        {
            Ok(Some(cp)) => cp.version,
            Ok(None) => CheckpointVersion::INITIAL,
            Err(_) => {
                self.warn_checkpoint("saga: checkpoint read failed");
                return true;
            }
        };
        match self
            .checkpoint
            .save_checkpoint(self.owner, &self.checkpoint_id, offset, expected)
            .await
        {
            Ok(SaveOutcome::Saved) => true,
            // StaleVersion：并发执行器 fence 本 runner ⇒ 停跑（F2）。
            Ok(SaveOutcome::StaleVersion) => {
                self.warn_checkpoint("saga: checkpoint fenced by concurrent executor, stopping");
                false
            }
            // 未来 #[non_exhaustive] 变体：journal 权威，记日志续跑。
            Ok(_) => {
                self.warn_checkpoint("saga: checkpoint not saved (unsupported outcome)");
                true
            }
            Err(_) => {
                self.warn_checkpoint("saga: checkpoint save failed");
                true
            }
        }
    }

    /// checkpoint 推进告警收口（tracing 宏出 [`ExecCtx::advance_checkpoint`]，控制其复杂度）。
    fn warn_checkpoint(&self, msg: &'static str) {
        tracing::warn!(
            tenant_id = %self.instance.tenant(),
            saga_id = %self.instance.saga_id().as_uuid(),
            "{msg}"
        );
    }

    async fn run_forward_action(&self, action: &dyn SagaAction) -> Result<Vec<u8>, SagaPhaseError> {
        self.run_action_with_policy(action.name(), SagaActionPhase::Forward, || {
            let ctx = SagaActionCtx::new(self.instance, action.name());
            action.do_it(ctx)
        })
        .await
    }

    async fn run_compensation_action(&self, action: &dyn SagaAction) -> Result<(), SagaPhaseError> {
        self.run_action_with_policy(action.name(), SagaActionPhase::Compensation, || {
            let ctx = SagaActionCtx::new(self.instance, action.name());
            action.undo_it(ctx)
        })
        .await
    }

    async fn run_action_with_policy<T, Op>(
        &self,
        action_name: &str,
        phase: SagaActionPhase,
        mut op: Op,
    ) -> Result<T, SagaPhaseError>
    where
        Op: FnMut() -> BoxFuture<'static, Result<T, SagaActionError>>,
    {
        match self.policy {
            SagaPolicy::Disabled => self
                .run_action_until_done_or_lease_lost(action_name, phase, op())
                .await
                .map_err(SagaPhaseError::Interrupted)?
                .map_err(SagaPhaseError::Action),
            SagaPolicy::Bounded(policy) => {
                self.run_bounded_action(action_name, phase, policy, &mut op)
                    .await
            }
        }
    }

    async fn run_bounded_action<T, Op>(
        &self,
        action_name: &str,
        phase: SagaActionPhase,
        policy: SagaBoundedPolicy,
        op: &mut Op,
    ) -> Result<T, SagaPhaseError>
    where
        Op: FnMut() -> BoxFuture<'static, Result<T, SagaActionError>>,
    {
        let action = self.retry_action(action_name, phase, policy.retry_delay(), op);
        let result_or_interruption =
            self.run_action_until_done_or_lease_lost(action_name, phase, action);
        match tokio::time::timeout(policy.step_timeout(), result_or_interruption).await {
            Ok(Ok(result)) => result.map_err(SagaPhaseError::Action),
            Ok(Err(interruption)) => Err(SagaPhaseError::Interrupted(interruption)),
            Err(_) => {
                self.warn_action_timeout(action_name, phase, policy);
                Err(SagaPhaseError::Action(SagaActionError::ActionTimedOut))
            }
        }
    }

    async fn run_action_until_done_or_lease_lost<T, Action>(
        &self,
        action_name: &str,
        phase: SagaActionPhase,
        action: Action,
    ) -> Result<Result<T, SagaActionError>, SagaInterruption>
    where
        Action: Future<Output = Result<T, SagaActionError>>,
    {
        tokio::pin!(action);
        let lease_renewal = self.renew_lease_during_action(action_name, phase);
        tokio::pin!(lease_renewal);
        tokio::select! {
            result = &mut action => Ok(result),
            interruption = &mut lease_renewal => Err(interruption),
        }
    }

    async fn renew_lease_during_action(
        &self,
        action_name: &str,
        phase: SagaActionPhase,
    ) -> SagaInterruption {
        loop {
            tokio::time::sleep(lease_renewal_delay(self.lease_ttl)).await;
            if !self.refresh_lease().await {
                self.warn_action_lease_lost(action_name, phase);
                return SagaInterruption::LeaseLost;
            }
        }
    }

    async fn retry_action<T, Op>(
        &self,
        action_name: &str,
        phase: SagaActionPhase,
        retry_delay: Option<Duration>,
        op: &mut Op,
    ) -> Result<T, SagaActionError>
    where
        Op: FnMut() -> BoxFuture<'static, Result<T, SagaActionError>>,
    {
        let mut attempt = 1_u32;
        loop {
            match op().await {
                Ok(output) => return Ok(output),
                Err(err) if !is_saga_action_retryable(&err) => {
                    self.warn_action_not_retrying(action_name, phase, attempt, err.as_label());
                    return Err(err);
                }
                Err(err) => {
                    let Some(delay) = retry_delay else {
                        self.warn_action_not_retrying(action_name, phase, attempt, err.as_label());
                        return Err(err);
                    };
                    self.warn_action_retry(action_name, phase, attempt, delay, err.as_label());
                    tokio::time::sleep(delay).await;
                    attempt = attempt.saturating_add(1);
                }
            }
        }
    }

    fn warn_action_timeout(
        &self,
        action_name: &str,
        phase: SagaActionPhase,
        policy: SagaBoundedPolicy,
    ) {
        let step_timeout_ms = duration_millis_u64(policy.step_timeout());
        let retry_delay_ms = policy.retry_delay().map(duration_millis_u64).unwrap_or(0);
        tracing::warn!(
            tenant_id = %self.instance.tenant(),
            saga_id = %self.instance.saga_id().as_uuid(),
            contract_id = self.contract_id,
            step_name = action_name,
            phase = phase.as_str(),
            step_timeout_ms,
            retry_delay_ms,
            "saga: action timed out"
        );
    }

    fn warn_action_lease_lost(&self, action_name: &str, phase: SagaActionPhase) {
        tracing::warn!(
            tenant_id = %self.instance.tenant(),
            saga_id = %self.instance.saga_id().as_uuid(),
            contract_id = self.contract_id,
            step_name = action_name,
            phase = phase.as_str(),
            "saga: action lease lost"
        );
    }

    fn warn_action_retry(
        &self,
        action_name: &str,
        phase: SagaActionPhase,
        attempt: u32,
        retry_delay: Duration,
        error_kind: &'static str,
    ) {
        let retry_delay_ms = duration_millis_u64(retry_delay);
        tracing::warn!(
            tenant_id = %self.instance.tenant(),
            saga_id = %self.instance.saga_id().as_uuid(),
            contract_id = self.contract_id,
            step_name = action_name,
            phase = phase.as_str(),
            attempt,
            retry_delay_ms,
            error_kind,
            "saga: action failed, retrying"
        );
    }

    fn warn_action_not_retrying(
        &self,
        action_name: &str,
        phase: SagaActionPhase,
        attempt: u32,
        error_kind: &'static str,
    ) {
        tracing::warn!(
            tenant_id = %self.instance.tenant(),
            saga_id = %self.instance.saga_id().as_uuid(),
            contract_id = self.contract_id,
            step_name = action_name,
            phase = phase.as_str(),
            attempt,
            error_kind,
            "saga: action failed, not retrying"
        );
    }

    /// 前向执行 `actions[start..]`；失败逆序补偿 `cursor.completed`（含 resume 预填前缀）。
    async fn run_forward(
        &self,
        actions: &[Box<dyn SagaAction>],
        start: usize,
        mut cursor: Cursor,
    ) -> SagaOutcome {
        for (i, action) in actions.iter().enumerate().skip(start) {
            let action = action.as_ref();
            if !self.refresh_lease().await {
                return Self::interrupted(SagaInterruption::LeaseLost);
            }
            let Ok(step) = StepName::parse(action.name()) else {
                // step 名非法标识符 = Invariant（动作未受治理约束）：fail-fast，不 journal。
                return SagaOutcome::Failed {
                    failed_node: action.name().to_string(),
                    error: SagaActionError::SerializeFailed,
                };
            };
            // F1：Executing append fail-closed —— 写失败则**不执行副作用**（无 journal 无法 durable 恢复）。
            if let Err(failure) = self
                .append(SagaJournalAppendRecord::executing(cursor.seq, step.clone()))
                .await
            {
                return self.append_failure_outcome(failure, action.name());
            }
            cursor.seq += 1;
            let output = match self.run_forward_action(action).await {
                Ok(o) => o,
                Err(SagaPhaseError::Action(err)) => {
                    if action.failed_after_forward_effect(&err) {
                        return self
                            .compensate_after_forward_effect(
                                actions,
                                &cursor.completed,
                                (i, step),
                                cursor.seq,
                                action.name(),
                                err,
                            )
                            .await;
                    }
                    return self
                        .compensate(actions, &cursor.completed, cursor.seq, action.name(), err)
                        .await;
                }
                Err(SagaPhaseError::Interrupted(reason)) => return Self::interrupted(reason),
            };
            // 副作用已发生：先入已完成栈（含本步），再写 Completed；写失败 ⇒ 补偿含本步在内的栈（F1）。
            cursor.completed.push((i, step.clone()));
            let completed_result = self
                .append(SagaJournalAppendRecord::completed(cursor.seq, step))
                .await;
            cursor.seq += 1;
            if let Err(failure) = completed_result {
                if matches!(
                    failure,
                    AppendFailure::LeaseLost | AppendFailure::JournalConflict
                ) {
                    return self.append_failure_outcome(failure, action.name());
                }
                return self
                    .compensate(
                        actions,
                        &cursor.completed,
                        cursor.seq,
                        action.name(),
                        SagaActionError::ActionFailed,
                    )
                    .await;
            }
            cursor.last_output = Some(output);
            // F2：checkpoint fence —— StaleVersion 表并发执行器已接管 ⇒ 停跑。
            if !self.advance_checkpoint(Lsn::new(i as u64 + 1)).await {
                return SagaOutcome::Failed {
                    failed_node: action.name().to_string(),
                    error: SagaActionError::ActionFailed,
                };
            }
        }
        self.mark_status_and_release_best_effort(SagaInstanceStatus::Succeeded)
            .await;
        SagaOutcome::Succeeded {
            output: cursor.last_output.unwrap_or_default(),
        }
    }

    /// 逆序补偿已完成步；补偿失败 → journal `Failed` + dead-letter + 终态 `Failed`。
    ///
    /// 首个 `undo_it` 失败即终止（写 `Failed` journal 行 + dead-letter），**剩余已完成步不再补偿**
    /// （steno 语义，须人工介入）。
    async fn compensate(
        &self,
        actions: &[Box<dyn SagaAction>],
        completed: &[(usize, StepName)],
        seq: u64,
        failed_node: &str,
        original_error: SagaActionError,
    ) -> SagaOutcome {
        let mut pending = completed.to_vec();
        pending.reverse();
        self.compensate_pending(actions, &pending, seq, failed_node, original_error)
            .await
    }

    /// Compensate a step whose forward side effect already happened but whose `Completed` record is
    /// not valid to write, for example typed output serialization failure after `execute`.
    async fn compensate_after_forward_effect(
        &self,
        actions: &[Box<dyn SagaAction>],
        completed: &[(usize, StepName)],
        current: (usize, StepName),
        seq: u64,
        failed_node: &str,
        original_error: SagaActionError,
    ) -> SagaOutcome {
        let (current_idx, current_step) = current;
        if !self.refresh_lease().await {
            return Self::interrupted(SagaInterruption::LeaseLost);
        }
        if let Err(failure) = self
            .append(SagaJournalAppendRecord::compensating(
                seq,
                current_step.clone(),
            ))
            .await
        {
            return self.append_failure_outcome(failure, failed_node);
        }
        let action = actions[current_idx].as_ref();
        let next_seq = match self
            .compensate_step_after_intent(action, &current_step, seq + 1, failed_node)
            .await
        {
            Ok(next_seq) => next_seq,
            Err(outcome) => return outcome,
        };
        let mut remaining = completed.to_vec();
        remaining.reverse();
        self.compensate_pending(actions, &remaining, next_seq, failed_node, original_error)
            .await
    }

    /// 按传入顺序补偿 pending step；`pending` 必须已是 reverse compensation order。
    async fn compensate_pending(
        &self,
        actions: &[Box<dyn SagaAction>],
        pending: &[(usize, StepName)],
        mut seq: u64,
        failed_node: &str,
        original_error: SagaActionError,
    ) -> SagaOutcome {
        for (i, step) in pending {
            let action = actions[*i].as_ref();
            seq = match self.compensate_step(action, step, seq, failed_node).await {
                Ok(next_seq) => next_seq,
                Err(outcome) => return outcome,
            };
        }
        self.mark_status_and_release_best_effort(SagaInstanceStatus::Compensated)
            .await;
        SagaOutcome::Failed {
            failed_node: failed_node.to_string(),
            error: original_error,
        }
    }

    async fn compensate_step(
        &self,
        action: &dyn SagaAction,
        step: &StepName,
        seq: u64,
        failed_node: &str,
    ) -> Result<u64, SagaOutcome> {
        if !self.refresh_lease().await {
            return Err(Self::interrupted(SagaInterruption::LeaseLost));
        }
        if let Err(failure) = self
            .append(SagaJournalAppendRecord::compensating(seq, step.clone()))
            .await
        {
            return Err(self.append_failure_outcome(failure, failed_node));
        }
        self.compensate_step_after_intent(action, step, seq + 1, failed_node)
            .await
    }

    async fn compensate_step_after_intent(
        &self,
        action: &dyn SagaAction,
        step: &StepName,
        seq: u64,
        failed_node: &str,
    ) -> Result<u64, SagaOutcome> {
        if !self.refresh_lease().await {
            return Err(Self::interrupted(SagaInterruption::LeaseLost));
        }
        match self.run_compensation_action(action).await {
            Ok(()) => {
                self.finish_compensation_success(action, step, seq, failed_node)
                    .await
            }
            Err(SagaPhaseError::Action(undo_err)) => Err(self
                .finish_compensation_failure(action, step, seq, failed_node, undo_err)
                .await),
            Err(SagaPhaseError::Interrupted(reason)) => Err(Self::interrupted(reason)),
        }
    }

    async fn finish_compensation_success(
        &self,
        action: &dyn SagaAction,
        step: &StepName,
        seq: u64,
        failed_node: &str,
    ) -> Result<u64, SagaOutcome> {
        if let Err(failure) = self
            .append(SagaJournalAppendRecord::compensated(seq, step.clone()))
            .await
        {
            return Err(self
                .compensated_append_failure_outcome(failure, action.name(), step, seq, failed_node)
                .await);
        }
        Ok(seq + 1)
    }

    async fn compensated_append_failure_outcome(
        &self,
        failure: AppendFailure,
        action_name: &str,
        step: &StepName,
        seq: u64,
        failed_node: &str,
    ) -> SagaOutcome {
        if matches!(
            failure,
            AppendFailure::LeaseLost | AppendFailure::JournalConflict
        ) {
            return self.append_failure_outcome(failure, action_name);
        }
        self.record_compensation_completion_lost(step, seq, action_name, failed_node)
            .await;
        SagaOutcome::Failed {
            failed_node: action_name.to_string(),
            error: SagaActionError::ActionFailed,
        }
    }

    async fn record_compensation_completion_lost(
        &self,
        step: &StepName,
        seq: u64,
        action_name: &str,
        failed_node: &str,
    ) {
        if self
            .append(SagaJournalAppendRecord::failed(
                seq,
                step.clone(),
                SAGA_COMPENSATION_COMPLETION_LOST,
            ))
            .await
            .is_ok()
        {
            self.dead_letter_compensation_failure(
                action_name,
                failed_node,
                SAGA_COMPENSATION_COMPLETION_LOST,
            )
            .await;
            self.mark_status_and_release_best_effort(SagaInstanceStatus::Failed)
                .await;
        }
    }

    async fn finish_compensation_failure(
        &self,
        action: &dyn SagaAction,
        step: &StepName,
        seq: u64,
        failed_node: &str,
        undo_err: SagaActionError,
    ) -> SagaOutcome {
        if let Err(failure) = self
            .append(SagaJournalAppendRecord::failed(
                seq,
                step.clone(),
                SAGA_COMPENSATION_FAILED,
            ))
            .await
        {
            return match failure {
                AppendFailure::LeaseLost => Self::interrupted(SagaInterruption::LeaseLost),
                AppendFailure::JournalConflict => {
                    Self::interrupted(SagaInterruption::JournalConflict)
                }
                AppendFailure::Storage => SagaOutcome::Failed {
                    failed_node: action.name().to_string(),
                    error: undo_err,
                },
            };
        }
        // F5：DLX 携 saga_id + 原始前向失败步（failed_node）+ 补偿失败步，诊断闭环。
        self.dead_letter_compensation_failure(action.name(), failed_node, SAGA_COMPENSATION_FAILED)
            .await;
        self.mark_status_and_release_best_effort(SagaInstanceStatus::Failed)
            .await;
        SagaOutcome::Failed {
            failed_node: action.name().to_string(),
            error: undo_err,
        }
    }

    /// 补偿失败 → 结构化 error 日志（saga_id / step_name / error_summary）+ 写 dead-letter
    /// （domain / contract_id 取 saga owner，SC-006）。DLX 写失败：记日志，journal `Failed` 行是 durable 审计。
    /// tracing 宏收口到 [`ExecCtx::error_compensation_failed`] / [`ExecCtx::error_dlx_write_failed`]，
    /// 控制本函数认知复杂度 ≤15（同 consumer.rs 日志 helper 范式）。
    async fn dead_letter_compensation_failure(
        &self,
        comp_step: &str,
        forward_step: &str,
        error_summary: &'static str,
    ) {
        self.error_compensation_failed(comp_step, forward_step, error_summary);
        // F5：DLX 记录 topic = saga_id（诊断闭环）；original_payload = 失败步标识 JSON（uuid + step 名均为
        // identifier，非 PII；Debug 仍按 DeadLetterRecord 脱敏，运维经 DLX store 查询取用）。
        let payload = format!(
            "{{\"sagaId\":\"{}\",\"failedForwardStep\":\"{forward_step}\",\"failedCompensationStep\":\"{comp_step}\"}}",
            self.instance.saga_id().as_uuid()
        )
        .into_bytes();
        let record = DeadLetterRecord::new(
            self.instance.tenant(),
            self.instance.saga_id().as_uuid().to_string(),
            DeadLetterProvenance::saga(self.owner.as_str()),
            self.contract_id,
            self.instance.saga_id().as_uuid().to_string(),
            None,
            payload,
            DeadLetterSummary::new(error_summary),
            1,
            EnvelopeMetadata::empty(),
        );
        match self.dead_letter.write_dead_letter(record).await {
            Ok(()) => self.record_dead_letter("written"),
            Err(error) => {
                self.record_dead_letter("write_error");
                self.error_dlx_write_failed(comp_step, &error);
            }
        }
    }

    fn record_dead_letter(&self, outcome: &'static str) {
        metrics::counter!(
            "saga_dead_letters_total",
            "domain" => self.owner.as_str().to_owned(),
            "contract_id" => self.contract_id.to_owned(),
            "outcome" => outcome,
        )
        .increment(1);
    }

    /// 补偿失败结构化 error 日志（saga_id / step_name / failed_forward_step / error_summary，T009.6 / SC-006）。
    fn error_compensation_failed(
        &self,
        comp_step: &str,
        forward_step: &str,
        error_summary: &'static str,
    ) {
        tracing::error!(
            tenant_id = %self.instance.tenant(),
            saga_id = %self.instance.saga_id().as_uuid(),
            step_name = comp_step,
            failed_forward_step = forward_step,
            error_summary,
            "saga: compensation failed, writing dead-letter (manual intervention required)"
        );
    }

    /// DLX 写失败 error 日志（journal `Failed` 行是 durable 审计兜底）。
    fn error_dlx_write_failed(&self, node_name: &str, error: &diport::DeadLetterStoreError) {
        tracing::error!(
            tenant_id = %self.instance.tenant(),
            saga_id = %self.instance.saga_id().as_uuid(),
            step_name = node_name,
            domain = self.owner.as_str(),
            contract_id = self.contract_id,
            error = %error,
            "saga: dead-letter write failed (journal Failed row is durable audit)"
        );
    }

    /// resume journal 读失败 error 日志（存储故障，与空 journal 可从 step0 恢复区分）。
    fn error_resume_read_failed(&self) {
        tracing::error!(
            tenant_id = %self.instance.tenant(),
            saga_id = %self.instance.saga_id().as_uuid(),
            "saga: resume journal read failed"
        );
    }

    /// resume：读 journal 重建状态，续前向 / 续补偿 / 终态直返。
    async fn resume(&self, actions: &[Box<dyn SagaAction>]) -> SagaOutcome {
        let entries = match self.read_resume_entries().await {
            Ok(entries) => entries,
            Err(outcome) => {
                self.release_lease_best_effort().await;
                return outcome;
            }
        };

        let definition = match self.definition_for_resume(actions) {
            Ok(definition) => definition,
            Err(outcome) => {
                self.release_lease_best_effort().await;
                return outcome;
            }
        };

        match definition.replay(&entries) {
            Ok(decision) => self.apply_replay_decision(actions, decision).await,
            Err(err) => {
                self.release_lease_best_effort().await;
                self.replay_error_outcome(&err)
            }
        }
    }

    async fn read_resume_entries(&self) -> Result<Vec<SagaJournalRecord>, SagaOutcome> {
        match self.journal.read(&self.instance).await {
            Ok(entries) => Ok(entries),
            Err(_) => {
                self.error_resume_read_failed();
                Err(unknown_saga_outcome())
            }
        }
    }

    fn definition_for_resume(
        &self,
        actions: &[Box<dyn SagaAction>],
    ) -> Result<SagaDefinition, SagaOutcome> {
        definition_from_actions(actions).map_err(|err| {
            let failed_node = model_error_node(&err);
            tracing::error!(tenant_id = %self.instance.tenant(), saga_id = %self.instance.saga_id().as_uuid(), failed_node = %failed_node, "saga: resume action definition invalid");
            SagaOutcome::Failed {
                failed_node,
                error: SagaActionError::SerializeFailed,
            }
        })
    }

    async fn apply_replay_decision(
        &self,
        actions: &[Box<dyn SagaAction>],
        decision: SagaReplayDecision,
    ) -> SagaOutcome {
        match decision {
            SagaReplayDecision::Forward {
                start,
                next_seq,
                completed,
            } => {
                self.run_forward(
                    actions,
                    start,
                    Cursor {
                        seq: next_seq,
                        completed,
                        last_output: None,
                    },
                )
                .await
            }
            SagaReplayDecision::Compensating {
                next_seq,
                pending,
                failed_step,
            } => {
                let failed_node = failed_step.as_ref().map_or(UNKNOWN_SAGA, StepName::as_str);
                self.compensate_pending(
                    actions,
                    &pending,
                    next_seq,
                    failed_node,
                    SagaActionError::ActionFailed,
                )
                .await
            }
            SagaReplayDecision::Terminal { status } => {
                self.release_lease_best_effort().await;
                outcome_from_terminal_status(status)
            }
            _ => SagaOutcome::Failed {
                failed_node: UNKNOWN_SAGA.to_string(),
                error: SagaActionError::SerializeFailed,
            },
        }
    }

    fn replay_error_outcome(&self, err: &SagaModelError) -> SagaOutcome {
        let failed_node = model_error_node(err);
        tracing::error!(tenant_id = %self.instance.tenant(), saga_id = %self.instance.saga_id().as_uuid(), failed_node = %failed_node, "saga: resume journal replay failed");
        SagaOutcome::Failed {
            failed_node,
            error: SagaActionError::SerializeFailed,
        }
    }
}

// ── resume/status 重建（pure model adapter）───────────────────────────────────

fn unknown_saga_outcome() -> SagaOutcome {
    SagaOutcome::Failed {
        failed_node: UNKNOWN_SAGA.to_string(),
        error: SagaActionError::ActionFailed,
    }
}

fn definition_from_actions(
    actions: &[Box<dyn SagaAction>],
) -> Result<SagaDefinition, SagaModelError> {
    SagaDefinition::from_step_names(actions.iter().map(|a| a.name()))
}

fn model_error_node(err: &SagaModelError) -> String {
    match err {
        SagaModelError::InvalidStepName { raw } => raw.clone(),
        SagaModelError::DuplicateStepName { step_name }
        | SagaModelError::UnknownStep { step_name }
        | SagaModelError::IllegalTransition { step_name, .. }
        | SagaModelError::NonPrefixCompleted { step_name } => step_name.as_str().to_string(),
        SagaModelError::EmptyDefinition | SagaModelError::DuplicateSeq { .. } => {
            UNKNOWN_SAGA.to_string()
        }
        _ => UNKNOWN_SAGA.to_string(),
    }
}

fn outcome_from_terminal_status(status: SagaDurableStatus) -> SagaOutcome {
    match status {
        SagaDurableStatus::Succeeded => SagaOutcome::Succeeded { output: Vec::new() },
        SagaDurableStatus::Failed { failed_step } => SagaOutcome::Failed {
            failed_node: failed_step.as_str().to_string(),
            error: SagaActionError::ActionFailed,
        },
        SagaDurableStatus::Compensated => SagaOutcome::Failed {
            failed_node: UNKNOWN_SAGA.to_string(),
            error: SagaActionError::ActionFailed,
        },
        SagaDurableStatus::NotStarted
        | SagaDurableStatus::Running
        | SagaDurableStatus::Compensating => SagaOutcome::Failed {
            failed_node: UNKNOWN_SAGA.to_string(),
            error: SagaActionError::SerializeFailed,
        },
        _ => SagaOutcome::Failed {
            failed_node: UNKNOWN_SAGA.to_string(),
            error: SagaActionError::SerializeFailed,
        },
    }
}

fn outcome_from_instance_status(status: SagaInstanceStatus) -> SagaOutcome {
    match status {
        SagaInstanceStatus::Succeeded => SagaOutcome::Succeeded { output: Vec::new() },
        SagaInstanceStatus::Compensated | SagaInstanceStatus::Failed => SagaOutcome::Failed {
            failed_node: UNKNOWN_SAGA.to_string(),
            error: SagaActionError::ActionFailed,
        },
        SagaInstanceStatus::Degraded => SagaOutcome::Interrupted {
            reason: SagaInterruption::InstanceDegraded,
        },
        SagaInstanceStatus::Ready
        | SagaInstanceStatus::Running
        | SagaInstanceStatus::Compensating => SagaOutcome::Interrupted {
            reason: SagaInterruption::LeaseBusy,
        },
        _ => SagaOutcome::Interrupted {
            reason: SagaInterruption::StoreUnavailable,
        },
    }
}

/// SagaTailer 粗粒度状态（按 factory action definition + durable reducer 判断）。
async fn status_of<J: SagaJournal, S: SagaInstanceStore>(
    journal: &J,
    instance_store: &S,
    instance: SagaInstanceRef,
    actions: &[Box<dyn SagaAction>],
) -> Option<SagaExecStatus> {
    let instance_status = match read_instance_status(instance_store, instance).await {
        Ok(status) => status,
        Err(status) => return Some(status),
    };
    if instance_status == Some(SagaInstanceStatus::Degraded) {
        return Some(SagaExecStatus::Degraded);
    }
    let entries = match read_status_entries(journal, instance).await {
        Ok(entries) => entries,
        Err(status) => return Some(status),
    };
    if entries.is_empty() {
        return instance_status.and_then(exec_status_from_instance_status);
    }
    let Some(definition) = build_status_definition(instance, actions) else {
        return Some(SagaExecStatus::Degraded);
    };
    let replay_status = status_from_replay(instance, definition.replay(&entries));
    Some(merge_instance_and_replay_status(
        instance_status,
        replay_status,
    ))
}

async fn read_instance_status<S: SagaInstanceStore>(
    store: &S,
    instance: SagaInstanceRef,
) -> Result<Option<SagaInstanceStatus>, SagaExecStatus> {
    store
        .get(&instance)
        .await
        .map(|row| row.map(|r| r.status()))
        .inspect_err(|_| {
            tracing::warn!(
                tenant_id = %instance.tenant(),
                saga_id = %instance.saga_id().as_uuid(),
                "saga: status instance read failed"
            );
        })
        .map_err(|_| SagaExecStatus::Degraded)
}

fn exec_status_from_instance_status(status: SagaInstanceStatus) -> Option<SagaExecStatus> {
    match status {
        SagaInstanceStatus::Ready => Some(SagaExecStatus::Ready),
        SagaInstanceStatus::Running | SagaInstanceStatus::Compensating => {
            Some(SagaExecStatus::Running)
        }
        SagaInstanceStatus::Succeeded
        | SagaInstanceStatus::Compensated
        | SagaInstanceStatus::Failed => Some(SagaExecStatus::Done),
        SagaInstanceStatus::Degraded => Some(SagaExecStatus::Degraded),
        _ => Some(SagaExecStatus::Degraded),
    }
}

fn merge_instance_and_replay_status(
    instance_status: Option<SagaInstanceStatus>,
    replay_status: SagaExecStatus,
) -> SagaExecStatus {
    match instance_status.and_then(exec_status_from_instance_status) {
        Some(SagaExecStatus::Degraded) => SagaExecStatus::Degraded,
        Some(SagaExecStatus::Done) => SagaExecStatus::Done,
        _ => replay_status,
    }
}

async fn read_status_entries<J: SagaJournal>(
    journal: &J,
    instance: SagaInstanceRef,
) -> Result<Vec<SagaJournalRecord>, SagaExecStatus> {
    journal
        .read(&instance)
        .await
        .inspect_err(|_| {
            tracing::warn!(
                tenant_id = %instance.tenant(),
                saga_id = %instance.saga_id().as_uuid(),
                "saga: status journal read failed"
            );
        })
        .map_err(|_| SagaExecStatus::Degraded)
}

fn build_status_definition(
    instance: SagaInstanceRef,
    actions: &[Box<dyn SagaAction>],
) -> Option<SagaDefinition> {
    match definition_from_actions(actions) {
        Ok(definition) => Some(definition),
        Err(err) => {
            warn_status_model_error(instance, &err, "saga: status action definition invalid");
            None
        }
    }
}

fn status_from_replay(
    instance: SagaInstanceRef,
    replay: Result<SagaReplayDecision, SagaModelError>,
) -> SagaExecStatus {
    match replay {
        Ok(SagaReplayDecision::Forward { .. } | SagaReplayDecision::Compensating { .. }) => {
            SagaExecStatus::Running
        }
        Ok(SagaReplayDecision::Terminal { .. }) | Ok(_) => SagaExecStatus::Done,
        Err(err) => {
            warn_status_model_error(instance, &err, "saga: status journal replay failed");
            SagaExecStatus::Degraded
        }
    }
}

fn warn_status_model_error(instance: SagaInstanceRef, err: &SagaModelError, message: &'static str) {
    let failed_node = model_error_node(err);
    tracing::warn!(
        tenant_id = %instance.tenant(),
        saga_id = %instance.saga_id().as_uuid(),
        failed_node = %failed_node,
        "{message}"
    );
}

#[cfg(test)]
mod tests;
