//! saga 执行与编排 —— 接缝类型 + 执行器实现（fenced intent/permit +
//! protected receipt/completion + typed probe recovery + 失败逆序补偿）。
//!
//! Typed authoring 与 erased runtime 的关系：
//! - [`SagaAction`]（本模块，object-safe `BoxFuture`）= **erased 运行时动作栈**——执行器
//!   ([`SagaExecutorImpl`]) 驱动 [`SagaActionFactory`] 产出的 `Vec<Box<dyn SagaAction>>`，前向
//!   `do_it` / 逆序 `undo_it`。
//! - [`SagaStep<generated::saga::StepMarker>`] = **typed authoring** trait。generated receipt DTO 与
//!   definition-specific typestate cursor 在编译期强制 step 数量、顺序、归属与 receipt 配对，再擦除成
//!   内部 [`SagaAction`]。
//!
//! resume 崩溃恢复从单一 durable recovery snapshot 重建 journal cursor，按 pinned
//! definition 重物化 typed action，再 hydrate protected receipt 或 probe 未完成 intent。
//!
//! 本 executor 仍是 direct primitive；background worker / `WorkerHealth` / readyz probe 封装在
//! [`crate::saga_worker`]，由组合根按 live saga registration 显式接线。
//!
//! ref: oxidecomputer/steno src/saga_action_generic.rs@main（`Action::do_it`/`undo_it`/`name` + 逆序补偿）。
//! ref: oxidecomputer/steno src/saga_log.rs@main（journal event replay 到 load status）。

use std::any::Any;
use std::collections::HashMap;
use std::future::Future;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

use futures::future::BoxFuture;
use serde::{Serialize, de::DeserializeOwned};
#[cfg(test)]
use sha2::{Digest, Sha256};

use consistency::{
    CompensationOutcome, EngineError, EngineErrorKind, SagaCompensationCause, SagaDefinition,
    SagaDurableStatus, SagaEffectPhase, SagaIdempotencyKey, SagaInstanceRef, SagaInstanceStatus,
    SagaJournalRecord, SagaJournalStatus, SagaLease, SagaLeaseOutcome, SagaModelError,
    SagaOperatorReason, SagaReceiptFormatVersion, SagaReceiptScope, SagaReplayDecision,
};
use diport::{
    CheckpointOwner, DeadLetterProvenance, DeadLetterRecord, DeadLetterStore, DeadLetterSummary,
    EnvelopeMetadata, SagaClaimOutcome, SagaClaimRequest, SagaCompensationCompletion,
    SagaCompensationFailure, SagaCompensationIntent, SagaCompensationNotApplied,
    SagaCompensationProgress, SagaContractId, SagaDurableMutation, SagaDurableMutationOutcome,
    SagaDurableStore, SagaDurableStoreError, SagaDurableStoreErrorKind, SagaForwardCompletion,
    SagaForwardIntent, SagaForwardNotApplied, SagaForwardProgress, SagaInstanceRegistration,
    SagaLeaseHolder, SagaLeaseTtl, SagaOperatorAuthorization, SagaOperatorCasOutcome,
    SagaOperatorClaimOutcome, SagaOperatorRepair, SagaOperatorRepairReason,
    SagaOperatorStatusOutcome, SagaOperatorStore, SagaRecoveryOutcome, SagaRecoveryRequest,
    SagaRunnableInstance, SagaStepCompletion, SagaTerminalReceiptOutcome,
    SagaTerminalReceiptRequest, SagaVerifiedTerminalReceipt, SagaWorkerIdentity, StoredSagaReceipt,
    saga_operator_action,
};
use vocab::StepName;

/// saga 实例标识（uuid newtype）。模型单源在 `consistency::saga`，本模块 re-export 供域 / 组合根经
/// `eventexec::SagaId` 命名。
pub use consistency::SagaId;
pub use consistency::SagaInterruption;

/// Closed result of one external Saga effect attempt.
///
/// `NotApplied` is the only error that the executor may retry automatically. `Unknown` means the
/// provider cannot prove whether the effect committed and must always enter the mandatory probe
/// path before another effect attempt is authorized.
#[derive(Debug)]
#[non_exhaustive]
pub enum SagaAttemptOutcome<T> {
    /// The external effect was applied and returned its typed result.
    Applied(T),
    /// The provider proved that no external effect was applied.
    NotApplied(EngineError),
    /// The provider cannot determine whether the external effect was applied.
    Unknown,
}

/// Closed result of querying an effect by its deterministic idempotency key.
#[derive(Debug)]
#[non_exhaustive]
pub enum SagaProbeOutcome<T> {
    /// The effect is durably visible at the provider.
    Applied(T),
    /// The provider proved that the effect is absent.
    NotApplied,
    /// The provider still cannot determine the effect outcome.
    Unknown,
}

impl<T> SagaProbeOutcome<T> {
    fn try_map_applied<U>(
        self,
        map: impl FnOnce(T) -> Result<U, SagaActionError>,
    ) -> Result<SagaProbeOutcome<U>, SagaActionError> {
        match self {
            Self::Applied(value) => map(value).map(SagaProbeOutcome::Applied),
            Self::NotApplied => Ok(SagaProbeOutcome::NotApplied),
            Self::Unknown => Ok(SagaProbeOutcome::Unknown),
        }
    }
}

/// Forward action context. Only the executor can construct it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SagaForwardContext {
    instance: SagaInstanceRef,
    step_name: StepName,
    idempotency_key: SagaIdempotencyKey,
}

/// Compensation action context. Its distinct type prevents phase/key mixups.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SagaCompensationContext {
    instance: SagaInstanceRef,
    step_name: StepName,
    idempotency_key: SagaIdempotencyKey,
}

impl SagaForwardContext {
    /// Saga instance receiving the forward effect.
    pub fn instance(&self) -> SagaInstanceRef {
        self.instance
    }

    /// Tenant owning the saga instance.
    pub fn tenant(&self) -> rss_request_context::TenantId {
        self.instance.tenant()
    }

    /// Durable saga identifier.
    pub fn saga_id(&self) -> SagaId {
        self.instance.saga_id()
    }

    /// Generated step name for this effect.
    pub fn step_name(&self) -> &StepName {
        &self.step_name
    }

    /// Stable retry-independent key for the forward effect.
    pub fn idempotency_key(&self) -> &SagaIdempotencyKey {
        &self.idempotency_key
    }
}

impl SagaCompensationContext {
    /// Saga instance receiving the compensation effect.
    pub fn instance(&self) -> SagaInstanceRef {
        self.instance
    }

    /// Tenant owning the saga instance.
    pub fn tenant(&self) -> rss_request_context::TenantId {
        self.instance.tenant()
    }

    /// Durable saga identifier.
    pub fn saga_id(&self) -> SagaId {
        self.instance.saga_id()
    }

    /// Generated step name for this compensation.
    pub fn step_name(&self) -> &StepName {
        &self.step_name
    }

    /// Stable retry-independent key for the compensation effect.
    pub fn idempotency_key(&self) -> &SagaIdempotencyKey {
        &self.idempotency_key
    }
}

// ── 冻结接缝类型（do/undo 动作 + 结论 + 命令 + 执行状态）─────────────────────────

/// saga 动作上下文：标识动作运行所在的 saga + 节点。私有字段（F6 funnel，外部不可字面构造）。
pub(crate) struct SagaActionCtx {
    instance: SagaInstanceRef,
    #[allow(dead_code)]
    // reason: erased action tests inspect node identity; typed runtime uses phase-specific contexts
    node_name: String,
    idempotency_key: SagaIdempotencyKey,
}

/// Executor-minted authority to invoke one effect after its durable intent committed.
pub(crate) struct SagaEffectPermit<I> {
    context: SagaActionCtx,
    lease: SagaLease,
    intent: I,
}

pub(crate) trait SagaPermitIntent {
    fn step(&self) -> &StepName;
    fn effect_key(&self) -> &SagaIdempotencyKey;
}

impl SagaPermitIntent for SagaForwardIntent {
    fn step(&self) -> &StepName {
        SagaForwardIntent::step(self)
    }

    fn effect_key(&self) -> &SagaIdempotencyKey {
        SagaForwardIntent::effect_key(self)
    }
}

impl SagaPermitIntent for SagaCompensationIntent {
    fn step(&self) -> &StepName {
        SagaCompensationIntent::step(self)
    }

    fn effect_key(&self) -> &SagaIdempotencyKey {
        SagaCompensationIntent::effect_key(self)
    }
}

impl<I: SagaPermitIntent> SagaEffectPermit<I> {
    fn new(context: SagaActionCtx, lease: SagaLease, intent: I) -> Result<Self, SagaActionError> {
        if lease.instance() != context.instance
            || intent.effect_key() != &context.idempotency_key
            || intent.step().as_str() != context.node_name
        {
            return Err(SagaActionError::InvariantViolation);
        }
        Ok(Self {
            context,
            lease,
            intent,
        })
    }

    fn into_context(self) -> Result<SagaActionCtx, SagaActionError> {
        if self.lease.instance() != self.context.instance
            || self.intent.effect_key() != &self.context.idempotency_key
            || self.intent.step().as_str() != self.context.node_name
        {
            return Err(SagaActionError::InvariantViolation);
        }
        Ok(self.context)
    }
}

/// Forward authority bound to one exact lease generation and durable intent.
pub(crate) type SagaForwardPermit = SagaEffectPermit<SagaForwardIntent>;

/// Compensation authority bound to one exact lease generation and durable intent.
pub(crate) type SagaCompensationPermit = SagaEffectPermit<SagaCompensationIntent>;

#[cfg(test)]
fn erased_test_binding(
    node_name: &str,
    definition: &consistency::SagaDefinitionIdentity,
) -> vocab::SagaStepBinding {
    // This harness exists only in the crate's unit-test binary. Keeping the synthetic binding here
    // avoids exposing any raw receipt-scope or idempotency-key constructor from production crates.
    let leak = |value: &str| -> &'static str { Box::leak(value.to_owned().into_boxed_str()) };
    let domain = definition.contract_id().split('.').next().unwrap_or("test");
    let contract = vocab::ContractBinding::from_static(
        leak(domain),
        leak(definition.contract_id()),
        leak(definition.version()),
        leak(definition.schema_digest()),
    );
    vocab::SagaStepBinding::from_static(
        contract,
        leak(node_name),
        "test.receipt.v1",
        "test.forward-effect",
        "test.compensation-effect",
        vocab::SagaRetryClass::Transient,
    )
}

impl SagaActionCtx {
    /// 受控构造（执行器在每次 `do_it`/`undo_it` 前构造并移交动作）。
    #[cfg(test)]
    #[allow(dead_code)]
    pub fn new(instance: SagaInstanceRef, node_name: impl Into<String>) -> Self {
        let node_name = node_name.into();
        let definition =
            consistency::SagaDefinitionIdentity::from_binding(generated::saga::billing_v1::SPEC);
        Self::for_action(
            instance,
            &definition,
            erased_test_binding(&node_name, &definition),
            SagaActionPhase::Forward,
        )
    }

    #[cfg(test)]
    #[allow(dead_code)]
    fn instance(&self) -> SagaInstanceRef {
        self.instance
    }

    fn for_action(
        instance: SagaInstanceRef,
        definition: &consistency::SagaDefinitionIdentity,
        binding: vocab::SagaStepBinding,
        phase: SagaActionPhase,
    ) -> Self {
        Self {
            instance,
            node_name: binding.name().to_string(),
            idempotency_key: SagaIdempotencyKey::derive(
                instance,
                definition,
                binding,
                phase.effect_phase(),
            ),
        }
    }

    /// 所属租户。
    #[allow(dead_code)] // reason: retained for internal erased-action tests while public entry is typed
    pub fn tenant(&self) -> rss_request_context::TenantId {
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
/// [`SagaStep`]，不直接实现本 trait）。
///
/// 对标 steno `Action`：`do_it` 前向，`undo_it` 补偿（幂等，逆序调用）。
pub(crate) trait SagaAction: std::fmt::Debug + Send + Sync {
    /// step 名（须为合法 Rust 标识符；执行器据此落 journal + resume 时由 factory 重物化）。
    fn name(&self) -> &str;

    /// Retry permission sealed into the generated step binding.
    fn retry_class(&self) -> vocab::SagaRetryClass {
        vocab::SagaRetryClass::Never
    }

    fn binding(&self) -> Option<vocab::SagaStepBinding> {
        None
    }

    /// 前向执行；只能消费执行器在 durable intent 之后签发的 permit。
    fn do_it(
        &self,
        permit: SagaForwardPermit,
    ) -> BoxFuture<'static, Result<SagaActionReceipt, SagaActionError>>;

    /// Query one uncertain forward effect without creating a new effect.
    fn probe_it(
        &self,
        ctx: SagaActionCtx,
    ) -> BoxFuture<'static, Result<SagaProbeOutcome<SagaActionReceipt>, SagaActionError>>;

    /// 补偿（撤销 `do_it` 副作用）；仅对**已完成**步逆序调用。
    fn undo_it(
        &self,
        permit: SagaCompensationPermit,
        receipt: Arc<dyn Any + Send + Sync>,
    ) -> BoxFuture<'static, Result<(), SagaActionError>>;

    /// Query one uncertain compensation without creating a new effect.
    fn probe_undo(
        &self,
        ctx: SagaActionCtx,
        receipt: Arc<dyn Any + Send + Sync>,
    ) -> BoxFuture<'static, Result<SagaProbeOutcome<()>, SagaActionError>>;

    /// Decode one provider-verified durable receipt into this generated step's exact DTO.
    fn decode_receipt(
        &self,
        plaintext: &[u8],
    ) -> Result<Arc<dyn Any + Send + Sync>, SagaActionError>;
}

pub(crate) struct SagaActionReceipt {
    output: Result<Vec<u8>, SagaActionError>,
    value: Arc<dyn Any + Send + Sync>,
}

impl SagaActionReceipt {
    fn new<R>(output: Vec<u8>, value: R) -> Self
    where
        R: Any + Send + Sync + 'static,
    {
        Self {
            output: Ok(output),
            value: Arc::new(value),
        }
    }

    fn post_effect_failure<R>(error: SagaActionError, value: R) -> Self
    where
        R: Any + Send + Sync + 'static,
    {
        Self {
            output: Err(error),
            value: Arc::new(value),
        }
    }
}

/// Durable reference to the final typed receipt of a successful Saga.
///
/// The plaintext receipt and idempotency key are intentionally inaccessible and never rendered by
/// `Debug`; trusted consumers resolve the exact scope through the protected durable store.
#[derive(Clone, PartialEq, Eq)]
pub struct SagaSuccessReference {
    scope: SagaReceiptScope,
}

impl SagaSuccessReference {
    fn new(scope: SagaReceiptScope) -> Self {
        Self { scope }
    }

    #[cfg(test)]
    #[allow(clippy::expect_used)]
    pub(crate) fn for_test(
        instance: SagaInstanceRef,
        worker: SagaWorkerIdentity,
        definition: consistency::SagaDefinitionIdentity,
        binding: vocab::SagaStepBinding,
    ) -> Self {
        let effect_key =
            SagaIdempotencyKey::derive(instance, &definition, binding, SagaEffectPhase::Forward);
        let scope = SagaReceiptScope::new(instance, worker, definition, binding, effect_key)
            .expect("generated test binding must form a valid success reference");
        Self::new(scope)
    }

    /// Successful Saga instance.
    pub fn instance(&self) -> SagaInstanceRef {
        self.scope.instance()
    }

    /// Exact pinned definition that produced the success receipt.
    pub fn definition(&self) -> &consistency::SagaDefinitionIdentity {
        self.scope.definition()
    }

    /// Final generated step name.
    pub fn step_name(&self) -> &StepName {
        self.scope.step_name()
    }

    /// Generated schema identifier of the final typed receipt.
    pub fn receipt_schema(&self) -> &str {
        self.scope.receipt_schema()
    }

    /// Resolve and decode the store-verified final receipt into its exact generated step DTO.
    ///
    /// A marker for any other step or definition is rejected before plaintext decoding. The store
    /// must prove that the requested scope is the terminal `ForwardCompleted` transition of a
    /// `Succeeded` aggregate; status alone is never accepted as success proof.
    pub async fn resolve_receipt<M, S>(
        &self,
        store: &S,
    ) -> Result<M::Receipt, SagaSuccessReceiptError>
    where
        M: generated::saga::StepMarker,
        M::Receipt: DeserializeOwned,
        S: SagaDurableStore,
    {
        let binding = M::BINDING;
        let expected_key = SagaIdempotencyKey::derive(
            self.scope.instance(),
            self.scope.definition(),
            binding,
            SagaEffectPhase::Forward,
        );
        if self.scope.step_name().as_str() != binding.name()
            || self.scope.receipt_schema() != binding.receipt_schema()
            || self.scope.definition().contract_id() != binding.contract_id()
            || self.scope.definition().version() != binding.version()
            || self.scope.definition().schema_digest() != binding.schema_hash()
            || self.scope.effect_key() != &expected_key
        {
            return Err(SagaSuccessReceiptError::MarkerMismatch);
        }
        let receipt = load_verified_terminal_receipt(store, self.scope.clone())
            .await
            .map_err(SagaSuccessReceiptError::from)?;
        serde_json::from_slice(receipt.plaintext().expose())
            .map_err(|_| SagaSuccessReceiptError::DecodeFailed)
    }
}

impl std::fmt::Debug for SagaSuccessReference {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SagaSuccessReference(<redacted>)")
    }
}

/// Failure resolving the final typed receipt of a successful Saga.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SagaSuccessReceiptError {
    /// The requested generated step marker is not the reference's exact final binding.
    #[error("saga success receipt marker does not match the final binding")]
    MarkerMismatch,
    /// The terminal aggregate or protected receipt is missing.
    #[error("saga success receipt is missing")]
    Missing,
    /// The aggregate is not durably succeeded.
    #[error("saga aggregate is not succeeded")]
    NotSucceeded,
    /// Journal, identity, scope or receipt metadata failed exact validation.
    #[error("saga success receipt integrity validation failed")]
    Integrity,
    /// The protected receipt format is not supported by this runtime.
    #[error("saga success receipt format is unsupported")]
    UnsupportedFormat,
    /// Durable storage could not provide an authoritative proof.
    #[error("saga success receipt store is unavailable")]
    StoreUnavailable,
    /// The verified plaintext is not the generated marker's receipt DTO.
    #[error("saga success receipt decoding failed")]
    DecodeFailed,
}

/// saga 执行结论。
#[derive(Debug)]
#[non_exhaustive]
pub enum SagaOutcome {
    /// 全步成功；run/resume 都返回相同的 durable final-receipt reference.
    Succeeded {
        reference: Box<SagaSuccessReference>,
    },
    /// 失败（前向某步失败 → 已完成步逆序补偿后返回原失败，或补偿失败 → dead-letter）。
    Failed {
        failed_node: String,
        error: SagaActionError,
    },
    /// Non-business interruption: lease contention/loss or durable journal conflict.
    Interrupted { reason: SagaInterruption },
}

/// Result of one authenticated, audited operator recovery attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaOperatorRecoveryOutcome {
    /// A confirmed-applied or confirmed-not-applied decision was durably repaired.
    Repaired,
    /// The provider still cannot prove the effect outcome; the Saga remains operator-required.
    StillUnknown,
    /// Another operator currently holds the exact intervention lease.
    Busy,
    /// The requested Saga no longer exists.
    Missing,
    /// The authorization is bound to another assembly-selected worker identity.
    IdentityConflict,
    /// The durable lifecycle state changed before the exact claim.
    StaleStatus(SagaInstanceStatus),
    /// The durable reason changed before the exact claim.
    StaleReason(SagaOperatorReason),
    /// Infrastructure, fencing or integrity interrupted the recovery attempt.
    Interrupted { reason: SagaInterruption },
}

/// saga 执行状态（细分结论在 [`SagaOutcome`]）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaExecStatus {
    /// 已登记未起。
    Ready,
    /// 执行 / 补偿在飞。
    Running,
    /// Automatic progress is stopped and an authorized operator action is required.
    Blocked,
    /// 终态（成功 / 已补偿 / dead-letter）。
    Done,
    /// durable journal 或 factory definition 与模型不一致，需运维介入。
    Degraded,
}

/// saga 动作错误（`#[non_exhaustive]`；执行器对各变体同样处理——任一 `do_it` 错 → 补偿，任一 `undo_it`
/// 错 → dead-letter；变体保留进 [`SagaOutcome::Failed`] 供调用方）。
///
/// 各变体均可出现在 [`SagaOutcome::Failed`]`.error`；consumer 若需区分是否已触发补偿，须查 fenced
/// recovery snapshot 中的 `compensation_intent` / `compensation_completed` transition。
/// Typed receipt JSON 编码失败会进入 operator-required，不尝试携非 durable receipt 盲补偿。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SagaActionError {
    /// 动作执行失败。
    #[error("action failed")]
    ActionFailed,
    /// Non-retryable action failure.
    #[error("non-retryable action failed")]
    NonRetryableActionFailed,
    /// Authoring or generated runtime invariant was violated.
    #[error("action invariant violated")]
    InvariantViolation,
    /// 输出 / 标识序列化失败（含 step 名非法标识符）。
    #[error("serialize failed")]
    SerializeFailed,
    /// 子 saga 创建失败。
    #[error("subsaga create failed")]
    SubsagaCreateFailed,
    /// 动作超过 saga runtime policy 的单 phase 总预算。
    #[error("action timed out")]
    ActionTimedOut,
    /// The action may have committed but no trustworthy receipt was observed.
    #[error("action outcome is unknown")]
    OutcomeUnknown,
    /// Lease/ownership was lost while the action was in flight.
    #[error("action ownership was lost")]
    OwnershipLost,
}

/// Closed saga failure classification. New error paths must select one class explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SagaFailureClass {
    Transient,
    Permanent,
    Invariant,
    OutcomeUnknown,
    OwnershipLost,
}

impl SagaActionError {
    fn classification(&self) -> SagaFailureClass {
        match self {
            Self::ActionFailed => SagaFailureClass::Transient,
            Self::ActionTimedOut => SagaFailureClass::OutcomeUnknown,
            Self::NonRetryableActionFailed | Self::SubsagaCreateFailed => {
                SagaFailureClass::Permanent
            }
            Self::SerializeFailed | Self::InvariantViolation => SagaFailureClass::Invariant,
            Self::OutcomeUnknown => SagaFailureClass::OutcomeUnknown,
            Self::OwnershipLost => SagaFailureClass::OwnershipLost,
        }
    }

    pub(crate) fn degrades_worker_permanently(&self) -> bool {
        matches!(
            self.classification(),
            SagaFailureClass::OutcomeUnknown | SagaFailureClass::OwnershipLost
        )
    }
}

/// Authoring seam tied to exactly one generated step marker and its receipt DTO.
///
/// Each implementation is statically bound to one generated marker `M`; the marker fixes the step
/// order, retry permission and sole legal receipt DTO. The executor retries only proven
/// `NotApplied` transient errors when that generated step declares `retryClass = "transient"`.
/// Protected receipts are hydrated back into this exact DTO during crash recovery.
pub trait SagaStep<M>: Send + Sync
where
    M: generated::saga::StepMarker,
{
    /// Execute the forward effect once for the supplied attempt.
    ///
    /// The context contains the executor-minted, attempt-independent idempotency key. Implementors
    /// must pass it to the external effect. `Unknown` never enters normal retry/backoff.
    fn execute(
        &self,
        context: SagaForwardContext,
    ) -> impl Future<Output = SagaAttemptOutcome<M::Receipt>> + Send;

    /// Resolve an uncertain forward attempt by its deterministic idempotency key.
    fn probe(
        &self,
        context: SagaForwardContext,
    ) -> impl Future<Output = SagaProbeOutcome<M::Receipt>> + Send;

    /// Compensate a previously successful forward effect using its exact typed receipt.
    ///
    /// Compensation has a distinct context and idempotency key. `Compensated` is the only success
    /// outcome; `Failed` is terminal and enters the Saga failure/dead-letter path.
    fn compensate(
        &self,
        context: SagaCompensationContext,
        receipt: M::Receipt,
    ) -> impl Future<Output = SagaAttemptOutcome<CompensationOutcome>> + Send;

    /// Resolve an uncertain compensation by its deterministic idempotency key.
    fn probe_compensation(
        &self,
        context: SagaCompensationContext,
        receipt: M::Receipt,
    ) -> impl Future<Output = SagaProbeOutcome<CompensationOutcome>> + Send;
}

/// Complete action factory for one exact generated definition.
pub struct TypedSagaActionFactory<D: generated::saga::Definition> {
    spec: vocab::SagaContractBinding,
    steps: Vec<Box<dyn TypedSagaStepSlot>>,
    marker: PhantomData<fn() -> D>,
}

impl<D: generated::saga::Definition> TypedSagaActionFactory<D> {
    /// Start registration at the definition's generated first-step cursor.
    ///
    /// No raw spec is accepted: identity, policy and ordered cursors come solely from `D`.
    pub fn builder() -> TypedSagaActionFactoryBuilder<D, D::Start> {
        TypedSagaActionFactoryBuilder {
            steps: Vec::new(),
            marker: PhantomData,
        }
    }

    #[must_use]
    /// Return the complete generated binding sealed into this factory.
    pub fn spec(&self) -> vocab::SagaContractBinding {
        self.spec
    }
}

/// Definition-specific typestate builder. Its cursor is advanced only by the generated next step.
pub struct TypedSagaActionFactoryBuilder<D, C>
where
    D: generated::saga::Definition,
{
    steps: Vec<Box<dyn TypedSagaStepSlot>>,
    marker: PhantomData<fn() -> (D, C)>,
}

impl<D, C> TypedSagaActionFactoryBuilder<D, C>
where
    D: generated::saga::Definition,
    C: generated::saga::Step<D> + 'static,
    C::Receipt: Serialize + DeserializeOwned + Clone + Send + Sync + 'static,
{
    /// Register exactly the current generated cursor and advance to its generated successor.
    ///
    /// The consumed builder prevents omission, duplication and reordering. `S` must return and
    /// compensate with `C`'s receipt, so cross-definition steps and wrong receipts do not compile.
    pub fn register<S, F>(mut self, factory: F) -> TypedSagaActionFactoryBuilder<D, C::Next>
    where
        S: SagaStep<C> + std::fmt::Debug + Send + Sync + 'static,
        F: Fn() -> S + Send + Sync + 'static,
    {
        self.steps.push(Box::new(RegisteredSagaStep::<S, F, C> {
            factory,
            marker: PhantomData,
        }));
        TypedSagaActionFactoryBuilder {
            steps: self.steps,
            marker: PhantomData,
        }
    }
}

impl<D, C> TypedSagaActionFactoryBuilder<D, C>
where
    D: generated::saga::Definition,
    C: generated::saga::End<D>,
{
    /// Finish only after the generated `End` cursor has been reached.
    ///
    /// Calling this before every declared step is registered is a compile-time error.
    pub fn finish(self) -> TypedSagaActionFactory<D> {
        TypedSagaActionFactory {
            spec: D::SPEC,
            steps: self.steps,
            marker: PhantomData,
        }
    }
}

trait TypedSagaStepSlot: Send + Sync {
    fn build_action(&self) -> Box<dyn SagaAction>;
}

struct RegisteredSagaStep<S, F, M> {
    factory: F,
    marker: PhantomData<fn() -> (S, M)>,
}

impl<S, F, M> TypedSagaStepSlot for RegisteredSagaStep<S, F, M>
where
    M: generated::saga::StepMarker + 'static,
    M::Receipt: Serialize + DeserializeOwned + Clone + Send + Sync + 'static,
    S: SagaStep<M> + std::fmt::Debug + Send + Sync + 'static,
    F: Fn() -> S + Send + Sync + 'static,
{
    fn build_action(&self) -> Box<dyn SagaAction> {
        Box::new(TypedSagaStepAction::<S, M> {
            step: Arc::new((self.factory)()),
            marker: PhantomData,
        })
    }
}

struct TypedSagaStepAction<S, M> {
    step: Arc<S>,
    marker: PhantomData<fn() -> M>,
}

impl<S: std::fmt::Debug, M> std::fmt::Debug for TypedSagaStepAction<S, M> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TypedSagaStepAction")
            .field("step", &self.step)
            .finish()
    }
}

impl<S, M> SagaAction for TypedSagaStepAction<S, M>
where
    M: generated::saga::StepMarker + 'static,
    M::Receipt: Serialize + DeserializeOwned + Clone + Send + Sync + 'static,
    S: SagaStep<M> + std::fmt::Debug + Send + Sync + 'static,
{
    fn name(&self) -> &str {
        M::BINDING.name()
    }
    fn retry_class(&self) -> vocab::SagaRetryClass {
        M::BINDING.retry_class()
    }
    fn binding(&self) -> Option<vocab::SagaStepBinding> {
        Some(M::BINDING)
    }

    fn do_it(
        &self,
        permit: SagaForwardPermit,
    ) -> BoxFuture<'static, Result<SagaActionReceipt, SagaActionError>> {
        let Ok(ctx) = permit.into_context() else {
            return Box::pin(async { Err(SagaActionError::InvariantViolation) });
        };
        let step = self.step.clone();
        let Ok(step_name) = StepName::parse(M::BINDING.name()) else {
            return Box::pin(async { Err(SagaActionError::SerializeFailed) });
        };
        let context = SagaForwardContext {
            instance: ctx.instance,
            step_name,
            idempotency_key: ctx.idempotency_key,
        };
        Box::pin(async move {
            match step.execute(context).await {
                SagaAttemptOutcome::Applied(receipt) => serialize_action_receipt(receipt),
                SagaAttemptOutcome::NotApplied(error) => Err(engine_error_to_action_error(error)),
                SagaAttemptOutcome::Unknown => Err(SagaActionError::OutcomeUnknown),
            }
        })
    }

    fn probe_it(
        &self,
        ctx: SagaActionCtx,
    ) -> BoxFuture<'static, Result<SagaProbeOutcome<SagaActionReceipt>, SagaActionError>> {
        let step = self.step.clone();
        let Ok(step_name) = StepName::parse(M::BINDING.name()) else {
            return Box::pin(async { Err(SagaActionError::SerializeFailed) });
        };
        let context = SagaForwardContext {
            instance: ctx.instance,
            step_name,
            idempotency_key: ctx.idempotency_key,
        };
        Box::pin(async move {
            step.probe(context)
                .await
                .try_map_applied(serialize_action_receipt)
        })
    }

    fn undo_it(
        &self,
        permit: SagaCompensationPermit,
        receipt: Arc<dyn Any + Send + Sync>,
    ) -> BoxFuture<'static, Result<(), SagaActionError>> {
        let Ok(ctx) = permit.into_context() else {
            return Box::pin(async { Err(SagaActionError::InvariantViolation) });
        };
        let step = self.step.clone();
        let Some(receipt) = receipt.downcast_ref::<M::Receipt>().cloned() else {
            return Box::pin(async { Err(SagaActionError::SerializeFailed) });
        };
        let Ok(step_name) = StepName::parse(M::BINDING.name()) else {
            return Box::pin(async { Err(SagaActionError::SerializeFailed) });
        };
        let context = SagaCompensationContext {
            instance: ctx.instance,
            step_name,
            idempotency_key: ctx.idempotency_key,
        };
        Box::pin(async move {
            match step.compensate(context, receipt).await {
                SagaAttemptOutcome::Applied(CompensationOutcome::Compensated) => Ok(()),
                SagaAttemptOutcome::Applied(CompensationOutcome::Failed) => {
                    Err(SagaActionError::NonRetryableActionFailed)
                }
                SagaAttemptOutcome::Applied(_) => Err(SagaActionError::NonRetryableActionFailed),
                SagaAttemptOutcome::NotApplied(error) => Err(engine_error_to_action_error(error)),
                SagaAttemptOutcome::Unknown => Err(SagaActionError::OutcomeUnknown),
            }
        })
    }

    fn probe_undo(
        &self,
        ctx: SagaActionCtx,
        receipt: Arc<dyn Any + Send + Sync>,
    ) -> BoxFuture<'static, Result<SagaProbeOutcome<()>, SagaActionError>> {
        let step = self.step.clone();
        let Some(receipt) = receipt.downcast_ref::<M::Receipt>().cloned() else {
            return Box::pin(async { Err(SagaActionError::SerializeFailed) });
        };
        let Ok(step_name) = StepName::parse(M::BINDING.name()) else {
            return Box::pin(async { Err(SagaActionError::SerializeFailed) });
        };
        let context = SagaCompensationContext {
            instance: ctx.instance,
            step_name,
            idempotency_key: ctx.idempotency_key,
        };
        Box::pin(async move {
            step.probe_compensation(context, receipt)
                .await
                .try_map_applied(|outcome| match outcome {
                    CompensationOutcome::Compensated => Ok(()),
                    CompensationOutcome::Failed => Err(SagaActionError::NonRetryableActionFailed),
                    _ => Err(SagaActionError::NonRetryableActionFailed),
                })
        })
    }

    fn decode_receipt(
        &self,
        plaintext: &[u8],
    ) -> Result<Arc<dyn Any + Send + Sync>, SagaActionError> {
        serde_json::from_slice::<M::Receipt>(plaintext)
            .map(|receipt| Arc::new(receipt) as Arc<dyn Any + Send + Sync>)
            .map_err(|_| SagaActionError::SerializeFailed)
    }
}

fn serialize_action_receipt<R>(receipt: R) -> Result<SagaActionReceipt, SagaActionError>
where
    R: Any + Serialize + Send + Sync + 'static,
{
    match serde_json_canonicalizer::to_vec(&receipt) {
        Ok(output) => Ok(SagaActionReceipt::new(output, receipt)),
        Err(_) => Ok(SagaActionReceipt::post_effect_failure(
            SagaActionError::InvariantViolation,
            receipt,
        )),
    }
}

fn engine_error_to_action_error(error: EngineError) -> SagaActionError {
    match error.kind() {
        EngineErrorKind::Transient => SagaActionError::ActionFailed,
        EngineErrorKind::Permanent => SagaActionError::NonRetryableActionFailed,
        EngineErrorKind::Invariant => SagaActionError::InvariantViolation,
        _ => SagaActionError::InvariantViolation,
    }
}

/// Validated saga runtime policy.
///
/// Construction is intentionally funneled through `TryFrom<SagaRuntimePolicySpec>`: contract glue
/// exposes raw millisecond specs, while the executor only accepts validated runtime states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SagaPolicy {
    max_attempts: u32,
    time_budget: Duration,
    backoff: vocab::SagaBackoff,
    initial_backoff: Duration,
    max_backoff: Duration,
    jitter: vocab::SagaJitter,
}

impl SagaPolicy {
    fn delay_for(self, retry_number: u32, entropy: u64) -> Duration {
        let exponent = retry_number.saturating_sub(1).min(63);
        let initial = self.initial_backoff.as_millis();
        let raw = match self.backoff {
            vocab::SagaBackoff::Fixed => initial,
            vocab::SagaBackoff::Exponential => initial.saturating_mul(1_u128 << exponent),
        };
        let capped = raw.min(self.max_backoff.as_millis()).min(u64::MAX as u128) as u64;
        let millis = match self.jitter {
            vocab::SagaJitter::None => capped,
            vocab::SagaJitter::Full => entropy % capped.saturating_add(1),
        };
        Duration::from_millis(millis)
    }
}

/// Invalid generated saga runtime policy spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SagaPolicyError {
    #[error("saga maxAttempts must include at least the initial attempt")]
    ZeroAttempts,
    #[error("saga time budget must be positive")]
    ZeroTimeBudget,
    #[error("saga initial backoff exceeds maximum backoff")]
    BackoffInverted,
}

impl TryFrom<vocab::SagaRuntimePolicySpec> for SagaPolicy {
    type Error = SagaPolicyError;

    fn try_from(spec: vocab::SagaRuntimePolicySpec) -> Result<Self, Self::Error> {
        if spec.max_attempts() == 0 {
            return Err(SagaPolicyError::ZeroAttempts);
        }
        if spec.time_budget_millis() == 0 {
            return Err(SagaPolicyError::ZeroTimeBudget);
        }
        if spec.initial_backoff_millis() > spec.max_backoff_millis() {
            return Err(SagaPolicyError::BackoffInverted);
        }
        Ok(Self {
            max_attempts: spec.max_attempts(),
            time_budget: Duration::from_millis(spec.time_budget_millis()),
            backoff: spec.backoff(),
            initial_backoff: Duration::from_millis(spec.initial_backoff_millis()),
            max_backoff: Duration::from_millis(spec.max_backoff_millis()),
            jitter: spec.jitter(),
        })
    }
}

// ── 执行器 / 进度跟踪接缝 ──────────────────────────────────────────────────────

/// Saga 执行器接缝：驱动 [`SagaAction`] 栈（前向执行 + 失败逆序补偿）。对标 steno SEC。
pub trait SagaExecutor: Send + Sync {
    /// Advance one already-registered instance from its exact durable, version-pinned state.
    fn advance_registered(
        &self,
        instance: SagaInstanceRef,
        listed_definition: consistency::SagaDefinitionIdentity,
    ) -> BoxFuture<'static, SagaOutcome>;
}

/// Business-owned start request. Definition identity is intentionally absent and is supplied by
/// the assembly-bound executor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SagaStartRequest {
    instance: SagaInstanceRef,
}

impl SagaStartRequest {
    pub const fn new(instance: SagaInstanceRef) -> Self {
        Self { instance }
    }

    pub const fn instance(self) -> SagaInstanceRef {
        self.instance
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SagaStartError {
    #[error("saga start authorization does not match the assembly-bound target")]
    AuthorizationMismatch,
    #[error(transparent)]
    Store(#[from] SagaDurableStoreError),
}

/// Typed adopter port for authenticated and durably audited registration.
pub trait SagaStartPort: Send + Sync {
    fn start(
        &self,
        authorization: diport::SagaStartAuthorization,
        request: SagaStartRequest,
    ) -> BoxFuture<'static, Result<consistency::SagaInstanceRecord, SagaStartError>>;
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

impl<D: generated::saga::Definition> SagaActionFactory for TypedSagaActionFactory<D> {
    fn build(&self) -> Vec<Box<dyn SagaAction>> {
        self.steps.iter().map(|step| step.build_action()).collect()
    }
}

/// Immutable exact map of generated definition identities to complete typed factories.
#[derive(Clone)]
pub struct SagaDefinitionRegistry {
    definitions: Arc<HashMap<consistency::SagaDefinitionIdentity, SagaDefinitionRuntime>>,
}

#[derive(Clone)]
struct SagaDefinitionRuntime {
    factory: Arc<dyn SagaActionFactory>,
    policy: SagaPolicy,
}

impl SagaDefinitionRegistry {
    /// Start an immutable registry assembly.
    pub fn builder() -> SagaDefinitionRegistryBuilder {
        SagaDefinitionRegistryBuilder {
            definitions: HashMap::new(),
        }
    }

    #[must_use]
    pub fn contains(&self, identity: &consistency::SagaDefinitionIdentity) -> bool {
        self.definitions.contains_key(identity)
    }

    fn resolve(
        &self,
        identity: &consistency::SagaDefinitionIdentity,
    ) -> Option<SagaDefinitionRuntime> {
        self.definitions.get(identity).cloned()
    }

    #[cfg(test)]
    #[allow(dead_code)]
    fn from_erased(
        identity: consistency::SagaDefinitionIdentity,
        factory: Arc<dyn SagaActionFactory>,
        policy: SagaPolicy,
    ) -> Self {
        Self {
            definitions: Arc::new(HashMap::from([(
                identity,
                SagaDefinitionRuntime { factory, policy },
            )])),
        }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    fn with_erased(
        mut self,
        identity: consistency::SagaDefinitionIdentity,
        factory: Arc<dyn SagaActionFactory>,
        policy: SagaPolicy,
    ) -> Self {
        Arc::make_mut(&mut self.definitions)
            .insert(identity, SagaDefinitionRuntime { factory, policy });
        self
    }
}

/// Assembly-time builder; no mutation or retirement API exists after `finish`.
pub struct SagaDefinitionRegistryBuilder {
    definitions: HashMap<consistency::SagaDefinitionIdentity, SagaDefinitionRuntime>,
}

/// Invalid immutable Saga definition registry assembly.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SagaDefinitionRegistryError {
    /// The same complete generated identity was registered more than once.
    #[error("duplicate saga definition identity")]
    DuplicateIdentity,
    /// Generated retry policy is structurally invalid.
    #[error("invalid generated saga retry policy")]
    InvalidPolicy(#[from] SagaPolicyError),
}

impl SagaDefinitionRegistryBuilder {
    /// Register one complete typed factory under its generated exact identity.
    pub fn register<D>(
        mut self,
        factory: TypedSagaActionFactory<D>,
    ) -> Result<Self, SagaDefinitionRegistryError>
    where
        D: generated::saga::Definition + 'static,
    {
        let spec = factory.spec();
        let identity = consistency::SagaDefinitionIdentity::from_binding(spec);
        let policy = SagaPolicy::try_from(spec.policy())?;
        let runtime = SagaDefinitionRuntime {
            factory: Arc::new(factory),
            policy,
        };
        if self.definitions.insert(identity, runtime).is_some() {
            return Err(SagaDefinitionRegistryError::DuplicateIdentity);
        }
        Ok(self)
    }

    #[must_use]
    /// Seal the registry. The resulting map has no mutation or retirement API.
    pub fn finish(self) -> SagaDefinitionRegistry {
        SagaDefinitionRegistry {
            definitions: Arc::new(self.definitions),
        }
    }
}

/// The assembly-selected exact definition is absent from the immutable registry.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("selected saga definition is not registered")]
pub struct SagaDefinitionRegistryLookupError;

/// 补偿失败安全摘要（`&'static str` const literal；进 journal `Failed` 行 + DLX 摘要 + tracing，不携 runtime
/// 数据，INVARIANT: DIPORT-DLX-SUMMARY-STATIC-01 { level = "Medium", exec = "manual/opt-in", source = "code" }）。
const SAGA_COMPENSATION_FAILED: &str = "saga compensation step failed";
/// resume 未知 saga（缺失实例行）占位 failed_node。
const UNKNOWN_SAGA: &str = "<unknown-saga>";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TerminalReceiptFailure {
    Missing,
    NotSucceeded,
    Integrity,
    UnsupportedFormat,
    StoreUnavailable,
}

impl TerminalReceiptFailure {
    const fn operator_reason(self) -> Option<SagaOperatorReason> {
        match self {
            Self::Missing => Some(SagaOperatorReason::ReceiptMissing),
            Self::Integrity | Self::NotSucceeded => Some(SagaOperatorReason::ReceiptIntegrity),
            Self::UnsupportedFormat => Some(SagaOperatorReason::ReceiptFormatUnsupported),
            Self::StoreUnavailable => None,
        }
    }

    const fn interruption(self) -> SagaInterruption {
        match self {
            Self::StoreUnavailable => SagaInterruption::StoreUnavailable,
            Self::Missing | Self::NotSucceeded | Self::Integrity | Self::UnsupportedFormat => {
                SagaInterruption::ReceiptUnavailable
            }
        }
    }
}

impl From<TerminalReceiptFailure> for SagaSuccessReceiptError {
    fn from(failure: TerminalReceiptFailure) -> Self {
        match failure {
            TerminalReceiptFailure::Missing => Self::Missing,
            TerminalReceiptFailure::NotSucceeded => Self::NotSucceeded,
            TerminalReceiptFailure::Integrity => Self::Integrity,
            TerminalReceiptFailure::UnsupportedFormat => Self::UnsupportedFormat,
            TerminalReceiptFailure::StoreUnavailable => Self::StoreUnavailable,
        }
    }
}

async fn load_verified_terminal_receipt<S: SagaDurableStore>(
    store: &S,
    scope: SagaReceiptScope,
) -> Result<StoredSagaReceipt, TerminalReceiptFailure> {
    let outcome = store
        .terminal_receipt(SagaTerminalReceiptRequest::new(scope.clone()))
        .await
        .map_err(|error| match error.kind() {
            SagaDurableStoreErrorKind::Integrity => TerminalReceiptFailure::Integrity,
            SagaDurableStoreErrorKind::UnsupportedFormat => {
                TerminalReceiptFailure::UnsupportedFormat
            }
            _ => TerminalReceiptFailure::StoreUnavailable,
        })?;
    match outcome {
        SagaTerminalReceiptOutcome::Verified(proof) => {
            validate_verified_terminal_receipt(&scope, proof)
        }
        SagaTerminalReceiptOutcome::Missing => Err(TerminalReceiptFailure::Missing),
        SagaTerminalReceiptOutcome::NotSucceeded(_) => Err(TerminalReceiptFailure::NotSucceeded),
        _ => Err(TerminalReceiptFailure::Integrity),
    }
}

fn validate_verified_terminal_receipt(
    scope: &SagaReceiptScope,
    proof: Box<SagaVerifiedTerminalReceipt>,
) -> Result<StoredSagaReceipt, TerminalReceiptFailure> {
    let instance = proof.instance();
    let receipt = proof.receipt();
    let journal = proof.journal();
    let Some(last) = journal.last() else {
        return Err(TerminalReceiptFailure::Integrity);
    };
    if instance.instance() != scope.instance()
        || instance.status() != SagaInstanceStatus::Succeeded
        || instance.identity() != scope.worker()
        || instance.definition() != scope.definition()
        || receipt.scope() != scope
        || receipt.format() != SagaReceiptFormatVersion::V1
        || last.status() != SagaJournalStatus::ForwardCompleted
        || last.step_name() != scope.step_name()
        || last.seq() != receipt.completed_seq()
        || receipt.attempt().get()
            != count_attempts(journal, scope.step_name(), SagaJournalStatus::ForwardIntent)
    {
        return Err(TerminalReceiptFailure::Integrity);
    }
    Ok(proof.into_receipt())
}

fn terminal_scope_for_action(
    instance: SagaInstanceRef,
    identity: &SagaWorkerIdentity,
    definition: &consistency::SagaDefinitionIdentity,
    action: &dyn SagaAction,
) -> Result<SagaReceiptScope, TerminalReceiptFailure> {
    let binding = action.binding().ok_or(TerminalReceiptFailure::Integrity)?;
    let effect_key =
        SagaIdempotencyKey::derive(instance, definition, binding, SagaEffectPhase::Forward);
    SagaReceiptScope::new(
        instance,
        identity.clone(),
        definition.clone(),
        binding,
        effect_key,
    )
    .map_err(|_| TerminalReceiptFailure::Integrity)
}

// ── SagaExecutorImpl ──────────────────────────────────────────────────────────

/// saga 执行器实现：必填依赖走构造器**位置参**（generated / diport::SagaDurableStore / saga conformance，缺失即编译错误）。泛型静态分发 +
/// `Arc<R>`（`run`/`resume` 返回 `'static` future，须 clone 句柄进 future；对齐 diport 注入形态表
/// spawn/Send-'static 行）。
///
/// `kind:saga` 契约声明的完整 retry policy 先经 generated
/// [`vocab::SagaRuntimePolicySpec`] 暴露，再由组合根转成 [`SagaPolicy`] 注入 executor。执行器仅接受已验证
/// runtime policy：forward/compensation 都被同一 attempt/time 双预算与声明的退避策略约束。
pub struct SagaExecutorImpl<R, D> {
    store: Arc<R>,
    dead_letter: Arc<D>,
    registry: SagaDefinitionRegistry,
    owner: CheckpointOwner,
    identity: SagaWorkerIdentity,
    definition: consistency::SagaDefinitionIdentity,
    holder: SagaLeaseHolder,
    lease_ttl: SagaLeaseTtl,
}

/// Saga executor dependencies. `store` is the sole owner of instance, lease, journal, protected
/// receipt and recovery cursor transitions.
pub struct SagaExecutorDeps<R, D> {
    store: Arc<R>,
    dead_letter: Arc<D>,
    registry: SagaDefinitionRegistry,
}

impl<R, D> SagaExecutorDeps<R, D> {
    /// Install the complete immutable registry. Selection is joined with config in executor construction.
    pub fn new(store: Arc<R>, dead_letter: Arc<D>, registry: SagaDefinitionRegistry) -> Self {
        Self {
            store,
            dead_letter,
            registry,
        }
    }
}

/// Saga executor identity and lease configuration.
pub struct SagaExecutorConfig {
    owner: CheckpointOwner,
    identity: SagaWorkerIdentity,
    definition: consistency::SagaDefinitionIdentity,
    holder: SagaLeaseHolder,
    lease_ttl: SagaLeaseTtl,
}

/// Error constructing [`SagaExecutorConfig`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SagaExecutorConfigError {
    /// Generated contract id was invalid.
    #[error(transparent)]
    ContractId(#[from] diport::SagaContractIdError),
    /// Saga worker identity was invalid.
    #[error(transparent)]
    Identity(#[from] diport::SagaWorkerIdentityError),
    /// Lease holder identity is not canonical or exceeds the provider limit.
    #[error(transparent)]
    LeaseHolder(#[from] diport::SagaLeaseHolderError),
    /// Lease TTL cannot be represented exactly by every durable provider.
    #[error(transparent)]
    LeaseTtl(#[from] diport::SagaLeaseTtlError),
}

impl SagaExecutorConfig {
    /// Build executor config from the same generated saga contract binding used by the typed factory.
    ///
    /// Runtime composition receives one object for action registration and derives contract id and
    /// policy from it, so the executor config cannot drift to a different saga contract.
    pub fn from_typed_factory<D: generated::saga::Definition>(
        owner: CheckpointOwner,
        holder_id: impl Into<String>,
        lease_ttl: Duration,
        factory: &TypedSagaActionFactory<D>,
    ) -> Result<Self, SagaExecutorConfigError> {
        Self::from_contract_spec(owner, holder_id, lease_ttl, factory.spec())
    }

    fn from_contract_spec(
        owner: CheckpointOwner,
        holder_id: impl Into<String>,
        lease_ttl: Duration,
        spec: vocab::SagaContractBinding,
    ) -> Result<Self, SagaExecutorConfigError> {
        Self::new(owner, spec, holder_id, lease_ttl)
    }

    fn new(
        owner: CheckpointOwner,
        spec: vocab::SagaContractBinding,
        holder_id: impl Into<String>,
        lease_ttl: Duration,
    ) -> Result<Self, SagaExecutorConfigError> {
        let contract_id = SagaContractId::parse(spec.contract_id())?;
        let identity = SagaWorkerIdentity::new(owner.as_str(), contract_id)?;
        let holder = SagaLeaseHolder::parse(holder_id.into())?;
        let lease_ttl = SagaLeaseTtl::new(lease_ttl)?;
        Ok(Self {
            owner,
            identity,
            definition: consistency::SagaDefinitionIdentity::from_binding(spec),
            holder,
            lease_ttl,
        })
    }

    /// Worker identity derived from the generated saga contract binding.
    pub fn identity(&self) -> &SagaWorkerIdentity {
        &self.identity
    }

    /// Lease holder id used by this executor.
    pub fn holder_id(&self) -> &str {
        self.holder.as_str()
    }

    /// Lease ttl used by this executor.
    pub fn lease_ttl(&self) -> Duration {
        self.lease_ttl.as_duration()
    }

    /// Complete generated definition identity selected by assembly.
    pub fn definition(&self) -> &consistency::SagaDefinitionIdentity {
        &self.definition
    }
}

impl<R, D> SagaExecutorImpl<R, D>
where
    R: SagaDurableStore + Send + Sync + 'static,
    D: DeadLetterStore + Send + Sync + 'static,
{
    /// 构造（全依赖必填位置参）。
    ///
    /// `config.owner` 是 DLX domain（如 `"billing"`）；contract identity 与完整 definition
    /// 均由同一个 typed factory 派生并在这里与 immutable registry 精确 join。owner 与派生的
    /// contract id 同进 [`DeadLetterStore`] durable 记录。
    pub fn new(
        deps: SagaExecutorDeps<R, D>,
        config: SagaExecutorConfig,
    ) -> Result<Self, SagaDefinitionRegistryLookupError> {
        if deps.registry.resolve(&config.definition).is_none() {
            return Err(SagaDefinitionRegistryLookupError);
        }
        Ok(Self {
            store: deps.store,
            dead_letter: deps.dead_letter,
            registry: deps.registry,
            owner: config.owner,
            identity: config.identity,
            definition: config.definition,
            holder: config.holder,
            lease_ttl: config.lease_ttl,
        })
    }

    /// Build the one action-typed operator service for this assembly-selected Saga identity.
    pub fn operator_service(&self) -> SagaOperatorService<R>
    where
        R: SagaOperatorStore,
    {
        SagaOperatorService {
            store: Arc::clone(&self.store),
            registry: self.registry.clone(),
            identity: self.identity.clone(),
            holder: self.holder.clone(),
            lease_ttl: self.lease_ttl,
        }
    }
}

/// The single public operator surface for one assembly-selected Saga identity.
pub struct SagaOperatorService<R> {
    store: Arc<R>,
    registry: SagaDefinitionRegistry,
    identity: SagaWorkerIdentity,
    holder: SagaLeaseHolder,
    lease_ttl: SagaLeaseTtl,
}

impl<R> Clone for SagaOperatorService<R> {
    fn clone(&self) -> Self {
        Self {
            store: Arc::clone(&self.store),
            registry: self.registry.clone(),
            identity: self.identity.clone(),
            holder: self.holder.clone(),
            lease_ttl: self.lease_ttl,
        }
    }
}

impl<R> SagaOperatorService<R>
where
    R: SagaDurableStore + SagaOperatorStore + Send + Sync + 'static,
{
    /// Exact assembly-selected worker identity owned by this operator service.
    pub fn identity(&self) -> &SagaWorkerIdentity {
        &self.identity
    }

    #[cfg(test)]
    pub(crate) fn for_runtime_test(
        store: Arc<R>,
        registry: SagaDefinitionRegistry,
        identity: SagaWorkerIdentity,
        holder: SagaLeaseHolder,
        lease_ttl: SagaLeaseTtl,
    ) -> Self {
        Self {
            store,
            registry,
            identity,
            holder,
            lease_ttl,
        }
    }

    /// Read exactly one tenant-scoped Saga instance.
    pub fn status(
        &self,
        authorization: SagaOperatorAuthorization<saga_operator_action::Status>,
    ) -> BoxFuture<'static, Result<SagaOperatorStatusOutcome, SagaDurableStoreError>> {
        if authorization.identity() != &self.identity {
            return Box::pin(async { Ok(SagaOperatorStatusOutcome::IdentityConflict) });
        }
        let store = Arc::clone(&self.store);
        Box::pin(async move { store.operator_status(authorization).await })
    }

    /// Retry only the exact compensation-failed journal basis carried by the authorization.
    pub fn retry_compensation(
        &self,
        authorization: SagaOperatorAuthorization<saga_operator_action::RetryCompensation>,
    ) -> BoxFuture<'static, Result<SagaOperatorCasOutcome, SagaDurableStoreError>> {
        if authorization.identity() != &self.identity {
            return Box::pin(async { Ok(SagaOperatorCasOutcome::IdentityConflict) });
        }
        let store = Arc::clone(&self.store);
        Box::pin(async move { store.retry_compensation(authorization).await })
    }

    /// Probe and repair one exact operator-required external-effect outcome.
    ///
    /// The caller supplies only a typed authorization with the expected closed reason. Applied
    /// versus not-applied is derived inside this service from the typed effect probe.
    pub fn repair(
        &self,
        authorization: SagaOperatorAuthorization<saga_operator_action::Repair>,
    ) -> BoxFuture<'static, SagaOperatorRecoveryOutcome> {
        if authorization.identity() != &self.identity {
            return Box::pin(async { SagaOperatorRecoveryOutcome::IdentityConflict });
        }
        let store = Arc::clone(&self.store);
        let identity = self.identity.clone();
        let holder = self.holder.clone();
        let lease_ttl = self.lease_ttl;
        let registry = self.registry.clone();
        Box::pin(async move {
            let instance = authorization.instance();
            let expected_reason = authorization.evidence().reason();
            let operator = match store.claim_repair(authorization, holder, lease_ttl).await {
                Ok(SagaOperatorClaimOutcome::Acquired(operator)) => operator,
                Ok(SagaOperatorClaimOutcome::Busy) => {
                    return SagaOperatorRecoveryOutcome::Busy;
                }
                Ok(SagaOperatorClaimOutcome::Missing) => {
                    return SagaOperatorRecoveryOutcome::Missing;
                }
                Ok(SagaOperatorClaimOutcome::StaleStatus(status)) => {
                    return SagaOperatorRecoveryOutcome::StaleStatus(status);
                }
                Ok(SagaOperatorClaimOutcome::StaleReason(reason)) => {
                    return SagaOperatorRecoveryOutcome::StaleReason(reason);
                }
                Err(_) | Ok(_) => {
                    return SagaOperatorRecoveryOutcome::Interrupted {
                        reason: SagaInterruption::StoreUnavailable,
                    };
                }
            };
            let row = match store.get(&instance).await {
                Ok(Some(row)) => row,
                Ok(None) => {
                    let _ = store.release_repair(operator).await;
                    return SagaOperatorRecoveryOutcome::Missing;
                }
                Err(_) => {
                    let _ = store.release_repair(operator).await;
                    return SagaOperatorRecoveryOutcome::Interrupted {
                        reason: SagaInterruption::StoreUnavailable,
                    };
                }
            };
            if row.identity() != &identity
                || row.status() != SagaInstanceStatus::OperatorRequired
                || row.operator_reason() != Some(expected_reason.as_operator_reason())
            {
                let _ = store.release_repair(operator).await;
                return SagaOperatorRecoveryOutcome::StaleStatus(row.status());
            }
            let definition = row.definition().clone();
            let Some(runtime) = registry.resolve(&definition) else {
                let _ = store.release_repair(operator).await;
                return SagaOperatorRecoveryOutcome::Interrupted {
                    reason: SagaInterruption::UnsupportedDefinition,
                };
            };
            let actions = runtime.factory.build();
            if definition_from_actions(&actions).is_err() {
                let _ = store.release_repair(operator).await;
                return SagaOperatorRecoveryOutcome::Interrupted {
                    reason: SagaInterruption::UnsupportedDefinition,
                };
            }
            let ctx = OperatorRecoveryCtx {
                store: &*store,
                identity: &identity,
                definition: &definition,
                instance,
                policy: runtime.policy,
            };
            ctx.recover(&actions, operator, expected_reason).await
        })
    }
}

impl<R, D> SagaStartPort for SagaExecutorImpl<R, D>
where
    R: SagaDurableStore + Send + Sync + 'static,
    D: DeadLetterStore + Send + Sync + 'static,
{
    fn start(
        &self,
        authorization: diport::SagaStartAuthorization,
        request: SagaStartRequest,
    ) -> BoxFuture<'static, Result<consistency::SagaInstanceRecord, SagaStartError>> {
        let store = Arc::clone(&self.store);
        let identity = self.identity.clone();
        let definition = self.definition.clone();
        Box::pin(async move {
            let instance = request.instance();
            if authorization.instance() != instance || authorization.identity() != &identity {
                return Err(SagaStartError::AuthorizationMismatch);
            }
            let registration = SagaInstanceRegistration::new(instance, identity, definition)
                .map_err(|_| SagaStartError::AuthorizationMismatch)?;
            store
                .register(authorization, registration)
                .await
                .map_err(SagaStartError::Store)
        })
    }
}

impl<R, D> SagaExecutorImpl<R, D>
where
    R: SagaDurableStore + Send + Sync + 'static,
    D: DeadLetterStore + Send + Sync + 'static,
{
    #[cfg(test)]
    fn run(&self, instance: SagaInstanceRef) -> BoxFuture<'static, SagaOutcome> {
        let store = self.store.clone();
        let dead_letter = self.dead_letter.clone();
        let owner = self.owner.clone();
        let identity = self.identity.clone();
        let selected_definition = self.definition.clone();
        let holder = self.holder.clone();
        let lease_ttl = self.lease_ttl;
        let registry = self.registry.clone();
        Box::pin(async move {
            let durable_row = match store.get(&instance).await {
                Ok(row) => row,
                Err(_) => {
                    return SagaOutcome::Interrupted {
                        reason: SagaInterruption::StoreUnavailable,
                    };
                }
            };
            let definition = match durable_row.as_ref() {
                Some(row) if row.identity() == &identity => row.definition().clone(),
                Some(_) => {
                    return SagaOutcome::Interrupted {
                        reason: SagaInterruption::UnsupportedDefinition,
                    };
                }
                None => selected_definition,
            };
            let Some(runtime) = registry.resolve(&definition) else {
                if durable_row.is_some() {
                    mark_definition_unsupported_best_effort(&*store, instance, &holder, lease_ttl)
                        .await;
                }
                return SagaOutcome::Interrupted {
                    reason: SagaInterruption::UnsupportedDefinition,
                };
            };
            {
                let actions = runtime.factory.build();
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
                    &*store,
                    instance,
                    identity.clone(),
                    definition.clone(),
                    &holder,
                    lease_ttl,
                )
                .await
                {
                    Ok(lease) => lease,
                    Err(reason) => return SagaOutcome::Interrupted { reason },
                };
                let ctx = ExecCtx {
                    store: &*store,
                    dead_letter: &*dead_letter,
                    owner: &owner,
                    identity: &identity,
                    contract_id: identity.contract_id().as_str(),
                    definition: &definition,
                    instance,
                    lease,
                    lease_ttl,
                    policy: runtime.policy,
                };
                ctx.run_forward(&actions, 0, Cursor::new()).await
            }
        })
    }

    fn resume(
        &self,
        instance: SagaInstanceRef,
        listed_definition: consistency::SagaDefinitionIdentity,
    ) -> BoxFuture<'static, SagaOutcome> {
        let store = self.store.clone();
        let dead_letter = self.dead_letter.clone();
        let owner = self.owner.clone();
        let identity = self.identity.clone();
        let holder = self.holder.clone();
        let lease_ttl = self.lease_ttl;
        let registry = self.registry.clone();
        Box::pin(async move {
            let row = match store.get(&instance).await {
                Ok(Some(row)) => row,
                Ok(None) => return unknown_saga_outcome(),
                Err(_) => {
                    return SagaOutcome::Interrupted {
                        reason: SagaInterruption::StoreUnavailable,
                    };
                }
            };
            let definition = row.definition().clone();
            if row.identity() != &identity {
                return SagaOutcome::Interrupted {
                    reason: SagaInterruption::UnsupportedDefinition,
                };
            }
            if listed_definition != definition {
                tracing::warn!(
                    tenant_id = %instance.tenant(),
                    saga_id = %instance.saga_id().as_uuid(),
                    "saga: runnable listing identity changed before resume; durable identity wins"
                );
            }
            let Some(runtime) = registry.resolve(&definition) else {
                mark_definition_unsupported_best_effort(&*store, instance, &holder, lease_ttl)
                    .await;
                return SagaOutcome::Interrupted {
                    reason: SagaInterruption::UnsupportedDefinition,
                };
            };
            {
                let actions = runtime.factory.build();
                let lease = match acquire_resume_lease(
                    &*store,
                    instance,
                    &identity,
                    &definition,
                    &holder,
                    lease_ttl,
                )
                .await
                {
                    ResumeLeaseDecision::Acquired(lease) => lease,
                    ResumeLeaseDecision::Unknown => return unknown_saga_outcome(),
                    ResumeLeaseDecision::Terminal(status) => {
                        if status == SagaInstanceStatus::Succeeded {
                            let proof = actions
                                .last()
                                .ok_or(TerminalReceiptFailure::Integrity)
                                .and_then(|action| {
                                    terminal_scope_for_action(
                                        instance,
                                        &identity,
                                        &definition,
                                        action.as_ref(),
                                    )
                                });
                            let scope = match proof {
                                Ok(scope) => scope,
                                Err(failure) => {
                                    return SagaOutcome::Interrupted {
                                        reason: failure.interruption(),
                                    };
                                }
                            };
                            return match load_verified_terminal_receipt(&*store, scope.clone())
                                .await
                            {
                                Ok(_) => SagaOutcome::Succeeded {
                                    reference: Box::new(SagaSuccessReference::new(scope)),
                                },
                                Err(failure) => SagaOutcome::Interrupted {
                                    reason: failure.interruption(),
                                },
                            };
                        }
                        return outcome_from_instance_status(status);
                    }
                    ResumeLeaseDecision::Interrupted(reason) => {
                        return SagaOutcome::Interrupted { reason };
                    }
                };
                let ctx = ExecCtx {
                    store: &*store,
                    dead_letter: &*dead_letter,
                    owner: &owner,
                    identity: &identity,
                    contract_id: identity.contract_id().as_str(),
                    definition: &definition,
                    instance,
                    lease,
                    lease_ttl,
                    policy: runtime.policy,
                };
                ctx.resume(&actions).await
            }
        })
    }
}

impl<R, D> SagaExecutor for SagaExecutorImpl<R, D>
where
    R: SagaDurableStore + Send + Sync + 'static,
    D: DeadLetterStore + Send + Sync + 'static,
{
    fn advance_registered(
        &self,
        instance: SagaInstanceRef,
        listed_definition: consistency::SagaDefinitionIdentity,
    ) -> BoxFuture<'static, SagaOutcome> {
        self.resume(instance, listed_definition)
    }
}

#[cfg(test)]
async fn acquire_run_lease<S>(
    store: &S,
    instance: SagaInstanceRef,
    identity: SagaWorkerIdentity,
    definition: consistency::SagaDefinitionIdentity,
    holder: &SagaLeaseHolder,
    lease_ttl: SagaLeaseTtl,
) -> Result<SagaLease, SagaInterruption>
where
    S: SagaDurableStore,
{
    let registration =
        SagaInstanceRegistration::new(instance, identity.clone(), definition.clone())
            .map_err(|_| SagaInterruption::UnsupportedDefinition)?;
    let authorization = diport::test_support::saga_start_authorization(
        vocab::ServiceCallerDomain::MaintenanceOperator,
        identity.clone(),
        instance,
        diport::SagaStartAuditId::parse("eventexec-test-start")
            .map_err(|_| SagaInterruption::StoreUnavailable)?,
    );
    let row = store
        .register(authorization, registration)
        .await
        .map_err(|error| {
            if error.kind() == SagaDurableStoreErrorKind::IdentityConflict {
                SagaInterruption::UnsupportedDefinition
            } else {
                SagaInterruption::StoreUnavailable
            }
        })?;
    match row.status() {
        SagaInstanceStatus::Ready
            if row.identity() == &identity && row.definition() == &definition => {}
        SagaInstanceStatus::Ready => return Err(SagaInterruption::UnsupportedDefinition),
        SagaInstanceStatus::Degraded => return Err(SagaInterruption::InstanceDegraded),
        _ => return Err(SagaInterruption::AlreadyStarted),
    }
    let runnable = SagaRunnableInstance::new(instance, row.status(), identity, definition)
        .map_err(|_| SagaInterruption::AlreadyStarted)?;
    claim_runnable(store, runnable, holder, lease_ttl).await
}

async fn mark_definition_unsupported_best_effort<S>(
    store: &S,
    instance: SagaInstanceRef,
    holder: &SagaLeaseHolder,
    lease_ttl: SagaLeaseTtl,
) where
    S: SagaDurableStore,
{
    let Ok(Some(row)) = store.get(&instance).await else {
        return;
    };
    let Ok(runnable) = SagaRunnableInstance::new(
        row.instance(),
        row.status(),
        row.identity().clone(),
        row.definition().clone(),
    ) else {
        return;
    };
    if let Ok(lease) = claim_runnable(store, runnable, holder, lease_ttl).await {
        let _ = store
            .mutate(
                &lease,
                SagaDurableMutation::OperatorRequired(SagaOperatorReason::DefinitionUnsupported),
            )
            .await;
    }
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
    identity: &SagaWorkerIdentity,
    definition: &consistency::SagaDefinitionIdentity,
    holder: &SagaLeaseHolder,
    lease_ttl: SagaLeaseTtl,
) -> ResumeLeaseDecision
where
    S: SagaDurableStore,
{
    let row = match store.get(&instance).await {
        Ok(Some(row)) => row,
        Ok(None) => return ResumeLeaseDecision::Unknown,
        Err(_) => return ResumeLeaseDecision::Interrupted(SagaInterruption::StoreUnavailable),
    };
    if row.identity() != identity {
        return ResumeLeaseDecision::Interrupted(SagaInterruption::UnsupportedDefinition);
    }
    if row.definition() != definition {
        return ResumeLeaseDecision::Interrupted(SagaInterruption::UnsupportedDefinition);
    }
    match row.status() {
        SagaInstanceStatus::Succeeded
        | SagaInstanceStatus::Compensated
        | SagaInstanceStatus::Expired
        | SagaInstanceStatus::Terminated => ResumeLeaseDecision::Terminal(row.status()),
        SagaInstanceStatus::OperatorRequired
        | SagaInstanceStatus::CompensationFailed
        | SagaInstanceStatus::Degraded => {
            ResumeLeaseDecision::Interrupted(SagaInterruption::InstanceDegraded)
        }
        SagaInstanceStatus::Ready
        | SagaInstanceStatus::Running
        | SagaInstanceStatus::Compensating => {
            let runnable = match SagaRunnableInstance::new(
                instance,
                row.status(),
                identity.clone(),
                definition.clone(),
            ) {
                Ok(runnable) => runnable,
                Err(_) => {
                    return ResumeLeaseDecision::Interrupted(SagaInterruption::StoreUnavailable);
                }
            };
            match claim_runnable(store, runnable, holder, lease_ttl).await {
                Ok(lease) => ResumeLeaseDecision::Acquired(lease),
                Err(reason) => ResumeLeaseDecision::Interrupted(reason),
            }
        }
        _ => ResumeLeaseDecision::Interrupted(SagaInterruption::StoreUnavailable),
    }
}

async fn claim_runnable<S: SagaDurableStore>(
    store: &S,
    runnable: SagaRunnableInstance,
    holder: &SagaLeaseHolder,
    lease_ttl: SagaLeaseTtl,
) -> Result<SagaLease, SagaInterruption> {
    let request = SagaClaimRequest::new(runnable, holder.clone(), lease_ttl);
    match store
        .claim(request)
        .await
        .map_err(|_| SagaInterruption::StoreUnavailable)?
    {
        SagaClaimOutcome::Acquired(lease) => Ok(lease),
        SagaClaimOutcome::Busy => Err(SagaInterruption::LeaseBusy),
        SagaClaimOutcome::Missing => Err(SagaInterruption::StoreUnavailable),
        SagaClaimOutcome::IdentityConflict => Err(SagaInterruption::UnsupportedDefinition),
        SagaClaimOutcome::Stale(_) | SagaClaimOutcome::Terminal(_) => {
            Err(SagaInterruption::AlreadyStarted)
        }
        SagaClaimOutcome::OperatorRequired(_) | SagaClaimOutcome::Degraded => {
            Err(SagaInterruption::InstanceDegraded)
        }
        _ => Err(SagaInterruption::StoreUnavailable),
    }
}

// ── 执行上下文（持运行时句柄引用，方法实现前向 / 补偿）─────────────────

/// 前向游标：journal append 序号 + 已完成步栈（index + StepName）+ 末步输出。
struct Cursor {
    seq: u64,
    completed: Vec<CompletedStep>,
    last_reference: Option<SagaSuccessReference>,
    next_attempt: Option<u32>,
}

#[derive(Clone)]
struct CompletedStep {
    index: usize,
    name: StepName,
    receipt: Option<Arc<dyn Any + Send + Sync>>,
    compensation_attempt: u32,
}

enum PendingCompensationProbe {
    None,
    Applied(u32),
    NotApplied(u32),
    Operator(SagaOperatorReason),
    Interrupted(SagaInterruption),
}

struct ForwardStep<'a> {
    actions: &'a [Box<dyn SagaAction>],
    index: usize,
}

struct ForwardReceiptContext<'a> {
    index: usize,
    step: StepName,
    seq: u64,
    action_name: &'a str,
}

#[derive(Debug, Clone, Copy)]
struct SagaPhaseDeadline {
    at: tokio::time::Instant,
}

impl SagaPhaseDeadline {
    #[allow(clippy::disallowed_methods)]
    fn new(budget: Duration) -> Self {
        Self {
            at: tokio::time::Instant::now() + budget,
        }
    }

    #[allow(clippy::disallowed_methods)]
    fn remaining(self) -> Duration {
        self.at
            .saturating_duration_since(tokio::time::Instant::now())
    }

    async fn sleep(self, delay: Duration) -> bool {
        tokio::time::timeout_at(self.at, tokio::time::sleep(delay))
            .await
            .is_ok()
    }
}

impl Cursor {
    #[cfg(test)]
    fn new() -> Self {
        Self {
            seq: 0,
            completed: Vec::new(),
            last_reference: None,
            next_attempt: None,
        }
    }
}

struct ExecCtx<'a, R, D> {
    store: &'a R,
    dead_letter: &'a D,
    owner: &'a CheckpointOwner,
    identity: &'a SagaWorkerIdentity,
    contract_id: &'a str,
    definition: &'a consistency::SagaDefinitionIdentity,
    instance: SagaInstanceRef,
    lease: SagaLease,
    lease_ttl: SagaLeaseTtl,
    policy: SagaPolicy,
}

struct OperatorRecoveryCtx<'a, R> {
    store: &'a R,
    identity: &'a SagaWorkerIdentity,
    definition: &'a consistency::SagaDefinitionIdentity,
    instance: SagaInstanceRef,
    policy: SagaPolicy,
}

impl<R> OperatorRecoveryCtx<'_, R>
where
    R: SagaOperatorStore,
{
    async fn recover(
        &self,
        actions: &[Box<dyn SagaAction>],
        claim: R::RepairClaim,
        expected_reason: SagaOperatorRepairReason,
    ) -> SagaOperatorRecoveryOutcome {
        let snapshot = match self
            .validated_snapshot(actions, &claim, expected_reason)
            .await
        {
            Ok(snapshot) => snapshot,
            Err(outcome) => {
                let _ = self.store.release_repair(claim).await;
                return outcome;
            }
        };
        let (_, entries, receipts, _, compensation_cause) = snapshot.into_parts();
        let Some(intent) = entries.last() else {
            let _ = self.store.release_repair(claim).await;
            return SagaOperatorRecoveryOutcome::Interrupted {
                reason: SagaInterruption::JournalConflict,
            };
        };
        let Some((index, action)) = actions
            .iter()
            .enumerate()
            .find(|(_, action)| action.name() == intent.step_name().as_str())
        else {
            let _ = self.store.release_repair(claim).await;
            return SagaOperatorRecoveryOutcome::Interrupted {
                reason: SagaInterruption::UnsupportedDefinition,
            };
        };
        let Some(next_seq) = intent.seq().checked_add(1) else {
            let _ = self.store.release_repair(claim).await;
            return SagaOperatorRecoveryOutcome::Interrupted {
                reason: SagaInterruption::JournalConflict,
            };
        };
        let decision = if expected_reason == SagaOperatorRepairReason::CompensationOutcomeUnknown {
            self.probe_compensation(
                actions,
                index,
                action.as_ref(),
                intent,
                next_seq,
                &entries,
                &receipts,
                compensation_cause,
            )
            .await
        } else {
            self.probe_forward(actions, index, action.as_ref(), intent, next_seq, &entries)
                .await
        };
        let Some(decision) = decision else {
            let _ = self.store.release_repair(claim).await;
            return SagaOperatorRecoveryOutcome::StillUnknown;
        };
        match self.store.commit_repair(claim, decision).await {
            Ok(SagaOperatorCasOutcome::Applied) => SagaOperatorRecoveryOutcome::Repaired,
            Ok(SagaOperatorCasOutcome::LeaseLost) => SagaOperatorRecoveryOutcome::Interrupted {
                reason: SagaInterruption::LeaseLost,
            },
            Ok(
                SagaOperatorCasOutcome::StaleJournal
                | SagaOperatorCasOutcome::StaleStatus(_)
                | SagaOperatorCasOutcome::StaleReason(_),
            ) => SagaOperatorRecoveryOutcome::Interrupted {
                reason: SagaInterruption::JournalConflict,
            },
            Err(_) | Ok(_) => SagaOperatorRecoveryOutcome::Interrupted {
                reason: SagaInterruption::StoreUnavailable,
            },
        }
    }

    async fn validated_snapshot(
        &self,
        actions: &[Box<dyn SagaAction>],
        claim: &R::RepairClaim,
        expected_reason: SagaOperatorRepairReason,
    ) -> Result<diport::SagaRecoverySnapshot, SagaOperatorRecoveryOutcome> {
        let scopes =
            self.receipt_scopes(actions)
                .ok_or(SagaOperatorRecoveryOutcome::Interrupted {
                    reason: SagaInterruption::UnsupportedDefinition,
                })?;
        let snapshot = match self.store.repair_snapshot(claim, scopes).await {
            Ok(SagaRecoveryOutcome::Available(snapshot)) => snapshot,
            Ok(SagaRecoveryOutcome::LeaseLost) => {
                return Err(SagaOperatorRecoveryOutcome::Interrupted {
                    reason: SagaInterruption::LeaseLost,
                });
            }
            Err(_) | Ok(_) => {
                return Err(SagaOperatorRecoveryOutcome::Interrupted {
                    reason: SagaInterruption::StoreUnavailable,
                });
            }
        };
        let row = snapshot.instance();
        if row.instance() != self.instance
            || row.identity() != self.identity
            || row.definition() != self.definition
        {
            return Err(SagaOperatorRecoveryOutcome::Interrupted {
                reason: SagaInterruption::JournalConflict,
            });
        }
        if snapshot.operator_reason() != Some(expected_reason.as_operator_reason()) {
            return Err(snapshot.operator_reason().map_or(
                SagaOperatorRecoveryOutcome::Interrupted {
                    reason: SagaInterruption::InstanceDegraded,
                },
                SagaOperatorRecoveryOutcome::StaleReason,
            ));
        }
        Ok(snapshot)
    }

    fn receipt_scopes(&self, actions: &[Box<dyn SagaAction>]) -> Option<Vec<SagaReceiptScope>> {
        actions
            .iter()
            .map(|action| {
                let step = StepName::parse(action.name()).ok()?;
                self.forward_receipt_scope(action.as_ref(), step)
            })
            .collect()
    }

    fn action_context(
        &self,
        action: &dyn SagaAction,
        phase: SagaActionPhase,
    ) -> Result<SagaActionCtx, SagaActionError> {
        if let Some(binding) = action.binding() {
            return Ok(SagaActionCtx::for_action(
                self.instance,
                self.definition,
                binding,
                phase,
            ));
        }
        #[cfg(test)]
        {
            Ok(SagaActionCtx::for_action(
                self.instance,
                self.definition,
                erased_test_binding(action.name(), self.definition),
                phase,
            ))
        }
        #[cfg(not(test))]
        {
            Err(SagaActionError::InvariantViolation)
        }
    }

    fn forward_receipt_scope(
        &self,
        action: &dyn SagaAction,
        step: StepName,
    ) -> Option<SagaReceiptScope> {
        let binding = if let Some(binding) = action.binding() {
            binding
        } else {
            #[cfg(test)]
            {
                erased_test_binding(step.as_str(), self.definition)
            }
            #[cfg(not(test))]
            {
                let _ = step;
                return None;
            }
        };
        let effect_key = SagaIdempotencyKey::derive(
            self.instance,
            self.definition,
            binding,
            SagaEffectPhase::Forward,
        );
        SagaReceiptScope::new(
            self.instance,
            self.identity.clone(),
            self.definition.clone(),
            binding,
            effect_key,
        )
        .ok()
    }

    async fn probe_action<T>(
        &self,
        action: BoxFuture<'_, Result<SagaProbeOutcome<T>, SagaActionError>>,
    ) -> Result<SagaProbeOutcome<T>, SagaPhaseError>
    where
        T: Send,
    {
        match tokio::time::timeout(self.policy.time_budget, action).await {
            Ok(result) => result.map_err(SagaPhaseError::Action),
            Err(_) => Ok(SagaProbeOutcome::Unknown),
        }
    }

    async fn probe_forward(
        &self,
        actions: &[Box<dyn SagaAction>],
        index: usize,
        action: &dyn SagaAction,
        intent: &SagaJournalRecord,
        next_seq: u64,
        entries: &[SagaJournalRecord],
    ) -> Option<SagaOperatorRepair> {
        if intent.status() != SagaJournalStatus::ForwardIntent {
            return None;
        }
        let attempt = consistency::SagaAttempt::new(count_attempts(
            entries,
            intent.step_name(),
            SagaJournalStatus::ForwardIntent,
        ))
        .ok()?;
        let context = self.action_context(action, SagaActionPhase::Forward).ok()?;
        let effect_key = context.idempotency_key.clone();
        match self.probe_action(action.probe_it(context)).await {
            Ok(SagaProbeOutcome::Applied(receipt)) => {
                let output = receipt.output.ok()?;
                let scope = self.forward_receipt_scope(action, intent.step_name().clone())?;
                Some(SagaOperatorRepair::ForwardApplied(Box::new(
                    SagaForwardCompletion::new(
                        SagaStepCompletion::new(
                            scope,
                            attempt,
                            SagaReceiptFormatVersion::V1,
                            secure::Plaintext::new(output),
                            next_seq,
                        ),
                        if index + 1 == actions.len() {
                            SagaForwardProgress::Succeeded
                        } else {
                            SagaForwardProgress::Continue
                        },
                    ),
                )))
            }
            Ok(SagaProbeOutcome::NotApplied) => SagaForwardNotApplied::new(
                next_seq,
                intent.step_name().clone(),
                attempt,
                effect_key,
            )
            .ok()
            .map(SagaOperatorRepair::ForwardNotApplied),
            Ok(_) | Err(_) => None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn probe_compensation(
        &self,
        actions: &[Box<dyn SagaAction>],
        index: usize,
        action: &dyn SagaAction,
        intent: &SagaJournalRecord,
        next_seq: u64,
        entries: &[SagaJournalRecord],
        receipts: &[StoredSagaReceipt],
        compensation_cause: Option<SagaCompensationCause>,
    ) -> Option<SagaOperatorRepair> {
        if intent.status() != SagaJournalStatus::CompensationIntent {
            return None;
        }
        let cause = compensation_cause?;
        let attempt = consistency::SagaAttempt::new(count_attempts(
            entries,
            intent.step_name(),
            SagaJournalStatus::CompensationIntent,
        ))
        .ok()?;
        let context = self
            .action_context(action, SagaActionPhase::Compensation)
            .ok()?;
        let effect_key = context.idempotency_key.clone();
        let forward_scope = self.forward_receipt_scope(action, intent.step_name().clone())?;
        let completed_seq = entries
            .iter()
            .find(|record| {
                record.step_name() == intent.step_name()
                    && record.status() == SagaJournalStatus::ForwardCompleted
            })?
            .seq();
        let stored = receipts.iter().find(|receipt| {
            receipt.scope() == &forward_scope && receipt.completed_seq() == completed_seq
        })?;
        if stored.format() != SagaReceiptFormatVersion::V1
            || stored.attempt().get()
                != count_attempts(
                    entries,
                    intent.step_name(),
                    SagaJournalStatus::ForwardIntent,
                )
        {
            return None;
        }
        let receipt = action.decode_receipt(stored.plaintext().expose()).ok()?;
        match self.probe_action(action.probe_undo(context, receipt)).await {
            Ok(SagaProbeOutcome::Applied(())) => {
                let terminal = definition_from_actions(actions)
                    .ok()?
                    .replay(entries)
                    .ok()
                    .and_then(|decision| match decision {
                        SagaReplayDecision::Compensating { pending, .. } => Some(
                            pending.len() == 1
                                && pending
                                    .first()
                                    .is_some_and(|(candidate, _)| *candidate == index),
                        ),
                        _ => None,
                    })?;
                SagaCompensationCompletion::new(
                    next_seq,
                    intent.step_name().clone(),
                    attempt,
                    effect_key,
                    if terminal {
                        match cause {
                            SagaCompensationCause::Expired => SagaCompensationProgress::Expired,
                            _ => SagaCompensationProgress::Compensated,
                        }
                    } else {
                        SagaCompensationProgress::Continue
                    },
                )
                .ok()
                .map(SagaOperatorRepair::CompensationApplied)
            }
            Ok(SagaProbeOutcome::NotApplied) => SagaCompensationNotApplied::new(
                next_seq,
                intent.step_name().clone(),
                attempt,
                effect_key,
                cause,
            )
            .ok()
            .map(SagaOperatorRepair::CompensationNotApplied),
            Ok(_) | Err(_) => None,
        }
    }
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

    const fn effect_phase(self) -> SagaEffectPhase {
        match self {
            Self::Forward => SagaEffectPhase::Forward,
            Self::Compensation => SagaEffectPhase::Compensation,
        }
    }
}

#[allow(dead_code)]
fn duration_millis_u64(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(not(test))]
fn saga_retry_entropy(
    _instance: SagaInstanceRef,
    _action_name: &str,
    _phase: SagaActionPhase,
    _attempt: u32,
) -> u64 {
    let bytes = *uuid::Uuid::new_v4().as_bytes();
    u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

/// Deterministic entropy is a unit-test seam only. Production samples fresh OS-backed UUID
/// randomness for every retry so replicas and lease takeovers cannot synchronize their jitter.
#[cfg(test)]
fn saga_retry_entropy(
    instance: SagaInstanceRef,
    action_name: &str,
    phase: SagaActionPhase,
    attempt: u32,
) -> u64 {
    let mut hash = Sha256::new();
    hash.update(b"rss.saga.retry-entropy.v1");
    let tenant = instance.tenant().to_string();
    let saga_id = instance.saga_id().as_uuid();
    let attempt_bytes = attempt.to_be_bytes();
    for bytes in [
        tenant.as_bytes(),
        saga_id.as_bytes(),
        action_name.as_bytes(),
        phase.as_str().as_bytes(),
        &attempt_bytes,
    ] {
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    let digest = hash.finalize();
    u64::from_be_bytes([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ])
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReceiptCommitFailure {
    LeaseLost,
    Operator(SagaOperatorReason),
    Recoverable,
    OutcomeUnknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReceiptFailureLogKind {
    LeaseLost,
    Conflict,
    CommitUnknown,
    Protection,
    Storage,
    Integrity,
    UnsupportedFormat,
    UnexpectedOutcome,
    UnknownErrorKind,
}

impl ReceiptFailureLogKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::LeaseLost => "lease_lost",
            Self::Conflict => "conflict",
            Self::CommitUnknown => "commit_unknown",
            Self::Protection => "protection",
            Self::Storage => "storage",
            Self::Integrity => "integrity",
            Self::UnsupportedFormat => "unsupported_format",
            Self::UnexpectedOutcome => "unexpected_outcome",
            Self::UnknownErrorKind => "unknown_error_kind",
        }
    }
}

enum CompensatedOutcome {
    Failed(SagaActionError),
    Interrupted(SagaInterruption),
}

impl CompensatedOutcome {
    fn cause(&self) -> SagaCompensationCause {
        match self {
            Self::Failed(SagaActionError::ActionTimedOut) => SagaCompensationCause::Expired,
            Self::Failed(_) | Self::Interrupted(_) => SagaCompensationCause::BusinessFailure,
        }
    }

    fn into_saga_outcome(self, failed_node: &str) -> SagaOutcome {
        match self {
            Self::Failed(error) => SagaOutcome::Failed {
                failed_node: failed_node.to_string(),
                error,
            },
            Self::Interrupted(reason) => SagaOutcome::Interrupted { reason },
        }
    }
}

impl<R, D> ExecCtx<'_, R, D>
where
    R: SagaDurableStore,
    D: DeadLetterStore,
{
    async fn mutate(
        &self,
        action: &dyn SagaAction,
        step: &StepName,
        mutation: SagaDurableMutation,
        seq: u64,
        status: SagaJournalStatus,
    ) -> Result<(), AppendFailure> {
        let status_label = status.as_str();
        let decision = match self.store.mutate(&self.lease, mutation).await {
            Ok(outcome) => Self::mutation_decision(outcome),
            Err(error) if error.kind() == SagaDurableStoreErrorKind::CommitUnknown => {
                if self
                    .journal_transition_visible(action, step, seq, status)
                    .await
                {
                    AppendDecision::Success
                } else {
                    self.error_append_failed(seq, status_label);
                    AppendDecision::Storage
                }
            }
            Err(_) => {
                self.error_append_failed(seq, status_label);
                AppendDecision::Storage
            }
        };
        self.handle_append_decision(decision, seq, status_label)
            .await
    }

    fn mutation_decision(outcome: SagaDurableMutationOutcome) -> AppendDecision {
        match outcome {
            SagaDurableMutationOutcome::Applied
            | SagaDurableMutationOutcome::IdempotentDuplicate => AppendDecision::Success,
            SagaDurableMutationOutcome::LeaseLost => AppendDecision::LeaseLost,
            SagaDurableMutationOutcome::Conflict => AppendDecision::JournalConflict,
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
                self.mark_degraded_best_effort().await;
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
            self.store.renew(&self.lease, self.lease_ttl).await,
            Ok(SagaLeaseOutcome::Held)
        )
    }

    async fn release_lease_best_effort(&self) {
        let _ = self.store.release(&self.lease).await;
    }

    async fn mark_degraded_best_effort(&self) {
        let _ = self
            .store
            .mutate(&self.lease, SagaDurableMutation::Degraded)
            .await;
    }

    async fn require_operator(&self, reason: SagaOperatorReason) -> SagaOutcome {
        match self
            .store
            .mutate(&self.lease, SagaDurableMutation::OperatorRequired(reason))
            .await
        {
            Ok(
                SagaDurableMutationOutcome::Applied
                | SagaDurableMutationOutcome::IdempotentDuplicate,
            ) => Self::interrupted(SagaInterruption::OperatorRequired),
            Ok(SagaDurableMutationOutcome::LeaseLost) => {
                Self::interrupted(SagaInterruption::LeaseLost)
            }
            Ok(SagaDurableMutationOutcome::Conflict) => {
                Self::interrupted(SagaInterruption::JournalConflict)
            }
            Err(error) if error.kind() == SagaDurableStoreErrorKind::CommitUnknown => {
                match self.store.get(&self.instance).await {
                    Ok(Some(row)) if row.status() == SagaInstanceStatus::OperatorRequired => {
                        Self::interrupted(SagaInterruption::OperatorRequired)
                    }
                    _ => Self::interrupted(SagaInterruption::StoreUnavailable),
                }
            }
            Err(_) | Ok(_) => Self::interrupted(SagaInterruption::StoreUnavailable),
        }
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

    async fn run_forward_action(
        &self,
        action: &dyn SagaAction,
        intent: SagaForwardIntent,
        time_budget: Duration,
    ) -> Result<SagaActionReceipt, SagaPhaseError> {
        if time_budget.is_zero() {
            self.warn_action_timeout(action.name(), SagaActionPhase::Forward, self.policy);
            return Err(SagaPhaseError::Action(SagaActionError::ActionTimedOut));
        }
        let action_future = match self
            .action_context(action, SagaActionPhase::Forward)
            .and_then(|context| SagaForwardPermit::new(context, self.lease.clone(), intent))
        {
            Ok(permit) => action.do_it(permit),
            Err(error) => Box::pin(async move { Err(error) }),
        };
        match tokio::time::timeout(
            time_budget,
            self.run_action_until_done_or_lease_lost(
                action.name(),
                SagaActionPhase::Forward,
                action_future,
            ),
        )
        .await
        {
            Ok(Ok(result)) => result.map_err(SagaPhaseError::Action),
            Ok(Err(reason)) => Err(SagaPhaseError::Interrupted(reason)),
            Err(_) => {
                self.warn_action_timeout(action.name(), SagaActionPhase::Forward, self.policy);
                Err(SagaPhaseError::Action(SagaActionError::ActionTimedOut))
            }
        }
    }

    async fn run_compensation_action(
        &self,
        action: &dyn SagaAction,
        intent: SagaCompensationIntent,
        receipt: Arc<dyn Any + Send + Sync>,
        time_budget: Duration,
    ) -> Result<(), SagaPhaseError> {
        if time_budget.is_zero() {
            self.warn_action_timeout(action.name(), SagaActionPhase::Compensation, self.policy);
            return Err(SagaPhaseError::Action(SagaActionError::ActionTimedOut));
        }
        let action_future = match self
            .action_context(action, SagaActionPhase::Compensation)
            .and_then(|context| SagaCompensationPermit::new(context, self.lease.clone(), intent))
        {
            Ok(permit) => action.undo_it(permit, receipt),
            Err(error) => Box::pin(async move { Err(error) }),
        };
        match tokio::time::timeout(
            time_budget,
            self.run_action_until_done_or_lease_lost(
                action.name(),
                SagaActionPhase::Compensation,
                action_future,
            ),
        )
        .await
        {
            Ok(Ok(result)) => result.map_err(SagaPhaseError::Action),
            Ok(Err(reason)) => Err(SagaPhaseError::Interrupted(reason)),
            Err(_) => {
                self.warn_action_timeout(action.name(), SagaActionPhase::Compensation, self.policy);
                Err(SagaPhaseError::Action(SagaActionError::ActionTimedOut))
            }
        }
    }

    fn action_context(
        &self,
        action: &dyn SagaAction,
        phase: SagaActionPhase,
    ) -> Result<SagaActionCtx, SagaActionError> {
        if let Some(binding) = action.binding() {
            return Ok(SagaActionCtx::for_action(
                self.instance,
                self.definition,
                binding,
                phase,
            ));
        }
        #[cfg(test)]
        {
            Ok(SagaActionCtx::for_action(
                self.instance,
                self.definition,
                erased_test_binding(action.name(), self.definition),
                phase,
            ))
        }
        #[cfg(not(test))]
        {
            Err(SagaActionError::InvariantViolation)
        }
    }

    async fn probe_forward_action(
        &self,
        action: &dyn SagaAction,
    ) -> Result<SagaProbeOutcome<SagaActionReceipt>, SagaPhaseError> {
        let probe = match self.action_context(action, SagaActionPhase::Forward) {
            Ok(ctx) => action.probe_it(ctx),
            Err(error) => Box::pin(async move { Err(error) }),
        };
        match tokio::time::timeout(
            self.policy.time_budget,
            self.run_action_until_done_or_lease_lost(
                action.name(),
                SagaActionPhase::Forward,
                probe,
            ),
        )
        .await
        {
            Ok(Ok(result)) => result.map_err(SagaPhaseError::Action),
            Ok(Err(reason)) => Err(SagaPhaseError::Interrupted(reason)),
            Err(_) => Ok(SagaProbeOutcome::Unknown),
        }
    }

    async fn probe_compensation_action(
        &self,
        action: &dyn SagaAction,
        receipt: Arc<dyn Any + Send + Sync>,
    ) -> Result<SagaProbeOutcome<()>, SagaPhaseError> {
        let probe = match self.action_context(action, SagaActionPhase::Compensation) {
            Ok(ctx) => action.probe_undo(ctx, receipt),
            Err(error) => Box::pin(async move { Err(error) }),
        };
        match tokio::time::timeout(
            self.policy.time_budget,
            self.run_action_until_done_or_lease_lost(
                action.name(),
                SagaActionPhase::Compensation,
                probe,
            ),
        )
        .await
        {
            Ok(Ok(result)) => result.map_err(SagaPhaseError::Action),
            Ok(Err(reason)) => Err(SagaPhaseError::Interrupted(reason)),
            Err(_) => Ok(SagaProbeOutcome::Unknown),
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
            tokio::time::sleep(lease_renewal_delay(self.lease_ttl.as_duration())).await;
            if !self.refresh_lease().await {
                self.warn_action_lease_lost(action_name, phase);
                return SagaInterruption::LeaseLost;
            }
        }
    }

    fn warn_action_timeout(&self, action_name: &str, phase: SagaActionPhase, policy: SagaPolicy) {
        let step_timeout_ms = duration_millis_u64(policy.time_budget);
        tracing::warn!(
            tenant_id = %self.instance.tenant(),
            saga_id = %self.instance.saga_id().as_uuid(),
            contract_id = self.contract_id,
            step_name = action_name,
            phase = phase.as_str(),
            step_timeout_ms,
            max_attempts = policy.max_attempts,
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

    /// 前向执行 `actions[start..]`；失败逆序补偿 `cursor.completed`（含 resume 预填前缀）。
    async fn run_forward(
        &self,
        actions: &[Box<dyn SagaAction>],
        start: usize,
        mut cursor: Cursor,
    ) -> SagaOutcome {
        for index in start..actions.len() {
            if let Err(outcome) = self
                .run_forward_step(ForwardStep { actions, index }, &mut cursor)
                .await
            {
                return outcome;
            }
        }
        match cursor.last_reference {
            Some(reference) => {
                match load_verified_terminal_receipt(self.store, reference.scope.clone()).await {
                    Ok(_) => SagaOutcome::Succeeded {
                        reference: Box::new(reference),
                    },
                    Err(failure) => match failure.operator_reason() {
                        Some(reason) => self.require_operator(reason).await,
                        None => Self::interrupted(failure.interruption()),
                    },
                }
            }
            None => SagaOutcome::Failed {
                failed_node: UNKNOWN_SAGA.to_string(),
                error: SagaActionError::InvariantViolation,
            },
        }
    }

    async fn run_forward_step(
        &self,
        forward: ForwardStep<'_>,
        cursor: &mut Cursor,
    ) -> Result<(), SagaOutcome> {
        let action = forward.actions[forward.index].as_ref();
        if !self.refresh_lease().await {
            return Err(Self::interrupted(SagaInterruption::LeaseLost));
        }
        let Ok(step) = StepName::parse(action.name()) else {
            // step 名非法标识符 = Invariant（动作未受治理约束）：fail-fast，不 journal。
            return Err(SagaOutcome::Failed {
                failed_node: action.name().to_string(),
                error: SagaActionError::SerializeFailed,
            });
        };
        let effect_key = self
            .action_context(action, SagaActionPhase::Forward)
            .map_err(|error| SagaOutcome::Failed {
                failed_node: action.name().to_string(),
                error,
            })?
            .idempotency_key;
        let deadline = SagaPhaseDeadline::new(self.policy.time_budget);
        let mut attempt_number = cursor.next_attempt.take().unwrap_or(1);
        let (successful_attempt, receipt) = loop {
            let attempt =
                consistency::SagaAttempt::new(attempt_number).map_err(|_| SagaOutcome::Failed {
                    failed_node: action.name().to_string(),
                    error: SagaActionError::InvariantViolation,
                })?;
            let intent =
                SagaForwardIntent::new(cursor.seq, step.clone(), attempt, effect_key.clone())
                    .map_err(|_| SagaOutcome::Failed {
                        failed_node: action.name().to_string(),
                        error: SagaActionError::InvariantViolation,
                    })?;
            if let Err(failure) = self
                .mutate(
                    action,
                    &step,
                    SagaDurableMutation::ForwardIntent(intent.clone()),
                    cursor.seq,
                    SagaJournalStatus::ForwardIntent,
                )
                .await
            {
                return Err(self.append_failure_outcome(failure, action.name()));
            }
            cursor.seq += 1;

            // The intent may have committed near lease expiry. Revalidate this exact lease
            // generation synchronously before minting the intent-bound permit or constructing the
            // provider future. A failed/lost renewal therefore cannot call the external effect.
            if !self.refresh_lease().await {
                self.warn_action_lease_lost(action.name(), SagaActionPhase::Forward);
                return Err(Self::interrupted(SagaInterruption::LeaseLost));
            }

            let time_budget = deadline.remaining();
            let result = match self.run_forward_action(action, intent, time_budget).await {
                Ok(receipt) => Ok(receipt),
                Err(SagaPhaseError::Action(error))
                    if error.classification() == SagaFailureClass::OutcomeUnknown =>
                {
                    match self.probe_forward_action(action).await {
                        Ok(SagaProbeOutcome::Applied(receipt)) => Ok(receipt),
                        Ok(SagaProbeOutcome::NotApplied) => {
                            if matches!(error, SagaActionError::ActionTimedOut) {
                                Err(SagaActionError::ActionTimedOut)
                            } else {
                                Err(SagaActionError::ActionFailed)
                            }
                        }
                        Ok(SagaProbeOutcome::Unknown) | Err(SagaPhaseError::Action(_)) => {
                            return Err(self
                                .require_operator(SagaOperatorReason::ForwardOutcomeUnknown)
                                .await);
                        }
                        Err(SagaPhaseError::Interrupted(reason)) => {
                            return Err(Self::interrupted(reason));
                        }
                    }
                }
                Err(SagaPhaseError::Action(error)) => Err(error),
                Err(SagaPhaseError::Interrupted(reason)) => {
                    return Err(Self::interrupted(reason));
                }
            };
            match result {
                Ok(receipt) => break (attempt, receipt),
                Err(error) => {
                    if error.classification() == SagaFailureClass::Transient
                        && action.retry_class() == vocab::SagaRetryClass::Transient
                        && attempt_number < self.policy.max_attempts
                    {
                        let entropy = saga_retry_entropy(
                            self.instance,
                            action.name(),
                            SagaActionPhase::Forward,
                            attempt_number,
                        );
                        let delay = self.policy.delay_for(attempt_number, entropy);
                        if deadline.sleep(delay).await {
                            attempt_number = attempt_number.saturating_add(1);
                            continue;
                        }
                        return Err(self
                            .compensate(
                                forward.actions,
                                &cursor.completed,
                                cursor.seq,
                                action.name(),
                                CompensatedOutcome::Failed(SagaActionError::ActionTimedOut),
                            )
                            .await);
                    }
                    return Err(self
                        .compensate(
                            forward.actions,
                            &cursor.completed,
                            cursor.seq,
                            action.name(),
                            CompensatedOutcome::Failed(error),
                        )
                        .await);
                }
            }
        };
        let (output, completed_step) = match self
            .accept_forward_receipt(
                forward.actions,
                &cursor.completed,
                receipt,
                ForwardReceiptContext {
                    index: forward.index,
                    step: step.clone(),
                    seq: cursor.seq,
                    action_name: action.name(),
                },
            )
            .await
        {
            Ok(accepted) => accepted,
            Err(outcome) => return Err(outcome),
        };
        // 副作用已发生：先入同一运行期补偿栈，再经单一 store 原子提交 receipt + transition + cursor。
        cursor.completed.push(completed_step);
        let completed_result = self
            .commit_forward_completion(
                action,
                step,
                successful_attempt,
                output.as_slice(),
                cursor.seq,
                forward.index + 1 == forward.actions.len(),
            )
            .await;
        cursor.seq += 1;
        let success_reference = match completed_result {
            Ok(reference) => reference,
            Err(failure) => match failure {
                ReceiptCommitFailure::LeaseLost => {
                    return Err(Self::interrupted(SagaInterruption::LeaseLost));
                }
                ReceiptCommitFailure::Operator(reason) => {
                    return Err(self.require_operator(reason).await);
                }
                ReceiptCommitFailure::OutcomeUnknown => {
                    return Err(self
                        .require_operator(SagaOperatorReason::CompletionCommitUnknown)
                        .await);
                }
                ReceiptCommitFailure::Recoverable => {
                    return Err(self
                        .compensate(
                            forward.actions,
                            &cursor.completed,
                            cursor.seq,
                            action.name(),
                            CompensatedOutcome::Interrupted(SagaInterruption::StoreUnavailable),
                        )
                        .await);
                }
            },
        };
        cursor.last_reference = Some(success_reference);
        Ok(())
    }

    async fn commit_forward_completion(
        &self,
        action: &dyn SagaAction,
        step: StepName,
        attempt: consistency::SagaAttempt,
        output: &[u8],
        completed_seq: u64,
        terminal: bool,
    ) -> Result<SagaSuccessReference, ReceiptCommitFailure> {
        let scope = self.forward_receipt_scope(action, step.clone())?;
        let reference = SagaSuccessReference::new(scope.clone());
        let verification_scope = scope.clone();
        let completion = SagaStepCompletion::new(
            scope,
            attempt,
            SagaReceiptFormatVersion::V1,
            secure::Plaintext::new(output.to_vec()),
            completed_seq,
        );
        match self
            .store
            .mutate(
                &self.lease,
                SagaDurableMutation::ForwardCompleted(SagaForwardCompletion::new(
                    completion,
                    if terminal {
                        SagaForwardProgress::Succeeded
                    } else {
                        SagaForwardProgress::Continue
                    },
                )),
            )
            .await
        {
            Ok(
                SagaDurableMutationOutcome::Applied
                | SagaDurableMutationOutcome::IdempotentDuplicate,
            ) => Ok(reference),
            Ok(SagaDurableMutationOutcome::LeaseLost) => self.receipt_completion_failed(
                action.name(),
                completed_seq,
                ReceiptFailureLogKind::LeaseLost,
                ReceiptCommitFailure::LeaseLost,
            ),
            Ok(SagaDurableMutationOutcome::Conflict) => self.receipt_completion_failed(
                action.name(),
                completed_seq,
                ReceiptFailureLogKind::Conflict,
                ReceiptCommitFailure::Operator(SagaOperatorReason::ReceiptIntegrity),
            ),
            Ok(_) => self.receipt_completion_failed(
                action.name(),
                completed_seq,
                ReceiptFailureLogKind::UnexpectedOutcome,
                ReceiptCommitFailure::Operator(SagaOperatorReason::ReceiptIntegrity),
            ),
            Err(error) if error.kind() == SagaDurableStoreErrorKind::CommitUnknown => {
                if self
                    .forward_completion_visible(verification_scope, &step, completed_seq, terminal)
                    .await
                {
                    Ok(reference)
                } else {
                    self.receipt_completion_failed(
                        action.name(),
                        completed_seq,
                        ReceiptFailureLogKind::CommitUnknown,
                        ReceiptCommitFailure::OutcomeUnknown,
                    )
                }
            }
            Err(error) => {
                let (log_kind, failure) = match error.kind() {
                    SagaDurableStoreErrorKind::Protection => (
                        ReceiptFailureLogKind::Protection,
                        ReceiptCommitFailure::Recoverable,
                    ),
                    SagaDurableStoreErrorKind::Storage => (
                        ReceiptFailureLogKind::Storage,
                        ReceiptCommitFailure::Recoverable,
                    ),
                    SagaDurableStoreErrorKind::Integrity => (
                        ReceiptFailureLogKind::Integrity,
                        ReceiptCommitFailure::Operator(SagaOperatorReason::ReceiptIntegrity),
                    ),
                    SagaDurableStoreErrorKind::UnsupportedFormat => (
                        ReceiptFailureLogKind::UnsupportedFormat,
                        ReceiptCommitFailure::Operator(
                            SagaOperatorReason::ReceiptFormatUnsupported,
                        ),
                    ),
                    _ => (
                        ReceiptFailureLogKind::UnknownErrorKind,
                        ReceiptCommitFailure::Operator(SagaOperatorReason::ReceiptIntegrity),
                    ),
                };
                self.receipt_completion_failed(action.name(), completed_seq, log_kind, failure)
            }
        }
    }

    async fn forward_completion_visible(
        &self,
        scope: SagaReceiptScope,
        step: &StepName,
        completed_seq: u64,
        terminal: bool,
    ) -> bool {
        let Ok(request) = SagaRecoveryRequest::new(self.lease.clone(), vec![scope.clone()]) else {
            return false;
        };
        match self.store.recovery_snapshot(request).await {
            Ok(SagaRecoveryOutcome::Available(snapshot)) => {
                snapshot.journal().iter().any(|record| {
                    record.seq() == completed_seq
                        && record.step_name() == step
                        && record.status() == SagaJournalStatus::ForwardCompleted
                }) && snapshot.receipts().iter().any(|receipt| {
                    receipt.scope() == &scope && receipt.completed_seq() == completed_seq
                })
            }
            _ if terminal => matches!(
                self.store.get(&self.instance).await,
                Ok(Some(row)) if row.status() == SagaInstanceStatus::Succeeded
            ),
            _ => false,
        }
    }

    async fn journal_transition_visible(
        &self,
        action: &dyn SagaAction,
        step: &StepName,
        seq: u64,
        status: SagaJournalStatus,
    ) -> bool {
        let Ok(scope) = self.forward_receipt_scope(action, step.clone()) else {
            return false;
        };
        let Ok(request) = SagaRecoveryRequest::new(self.lease.clone(), vec![scope]) else {
            return false;
        };
        let Ok(SagaRecoveryOutcome::Available(snapshot)) =
            self.store.recovery_snapshot(request).await
        else {
            return false;
        };
        snapshot.journal().iter().any(|record| {
            record.seq() == seq && record.step_name() == step && record.status() == status
        })
    }

    fn receipt_completion_failed<T>(
        &self,
        step: &str,
        completed_seq: u64,
        log_kind: ReceiptFailureLogKind,
        failure: ReceiptCommitFailure,
    ) -> Result<T, ReceiptCommitFailure> {
        tracing::error!(
            tenant_id = %self.instance.tenant(),
            saga_id = %self.instance.saga_id().as_uuid(),
            contract_id = self.contract_id,
            step,
            completed_seq,
            receipt_error_kind = log_kind.as_str(),
            "saga: receipt completion failed"
        );
        Err(failure)
    }

    fn forward_receipt_scope(
        &self,
        action: &dyn SagaAction,
        step: StepName,
    ) -> Result<SagaReceiptScope, ReceiptCommitFailure> {
        if let Some(binding) = action.binding() {
            let effect_key = SagaIdempotencyKey::derive(
                self.instance,
                self.definition,
                binding,
                SagaEffectPhase::Forward,
            );
            return SagaReceiptScope::new(
                self.instance,
                self.identity.clone(),
                self.definition.clone(),
                binding,
                effect_key,
            )
            .map_err(|_| ReceiptCommitFailure::Operator(SagaOperatorReason::ReceiptIntegrity));
        }
        #[cfg(test)]
        {
            let binding = erased_test_binding(step.as_str(), self.definition);
            let effect_key = SagaIdempotencyKey::derive(
                self.instance,
                self.definition,
                binding,
                SagaEffectPhase::Forward,
            );
            SagaReceiptScope::new(
                self.instance,
                self.identity.clone(),
                self.definition.clone(),
                binding,
                effect_key,
            )
            .map_err(|_| ReceiptCommitFailure::Operator(SagaOperatorReason::ReceiptIntegrity))
        }
        #[cfg(not(test))]
        {
            let _ = step;
            Err(ReceiptCommitFailure::Operator(
                SagaOperatorReason::ReceiptIntegrity,
            ))
        }
    }

    async fn accept_forward_receipt(
        &self,
        actions: &[Box<dyn SagaAction>],
        completed: &[CompletedStep],
        receipt: SagaActionReceipt,
        forward: ForwardReceiptContext<'_>,
    ) -> Result<(Vec<u8>, CompletedStep), SagaOutcome> {
        let completed_step = CompletedStep {
            index: forward.index,
            name: forward.step,
            receipt: Some(receipt.value),
            compensation_attempt: 1,
        };
        match receipt.output {
            Ok(output) => Ok((output, completed_step)),
            Err(_error) => {
                let _ = (actions, completed, forward.seq, forward.action_name);
                Err(self
                    .require_operator(SagaOperatorReason::ReceiptFormatUnsupported)
                    .await)
            }
        }
    }

    /// 逆序补偿已完成步；补偿失败 → journal `Failed` + dead-letter + 终态 `Failed`。
    ///
    /// 首个 `undo_it` 失败即终止（写 `Failed` journal 行 + dead-letter），**剩余已完成步不再补偿**
    /// （steno 语义，须人工介入）。
    async fn compensate(
        &self,
        actions: &[Box<dyn SagaAction>],
        completed: &[CompletedStep],
        seq: u64,
        failed_node: &str,
        completed_outcome: CompensatedOutcome,
    ) -> SagaOutcome {
        let mut pending = completed.to_vec();
        pending.reverse();
        self.compensate_pending(actions, &pending, seq, failed_node, completed_outcome)
            .await
    }

    /// 按传入顺序补偿 pending step；`pending` 必须已是 reverse compensation order。
    async fn compensate_pending(
        &self,
        actions: &[Box<dyn SagaAction>],
        pending: &[CompletedStep],
        mut seq: u64,
        failed_node: &str,
        completed_outcome: CompensatedOutcome,
    ) -> SagaOutcome {
        let cause = completed_outcome.cause();
        if pending.is_empty() {
            let Some(action) = actions.iter().find(|action| action.name() == failed_node) else {
                return self
                    .require_operator(SagaOperatorReason::DefinitionUnsupported)
                    .await;
            };
            if let Err(outcome) = self
                .complete_noop_compensation(action.as_ref(), seq, cause)
                .await
            {
                return outcome;
            }
            return completed_outcome.into_saga_outcome(failed_node);
        }
        for (position, completed) in pending.iter().enumerate() {
            let action = actions[completed.index].as_ref();
            seq = match self
                .compensate_step(
                    action,
                    &completed.name,
                    completed.receipt.clone(),
                    seq,
                    failed_node,
                    cause,
                    position + 1 == pending.len(),
                    completed.compensation_attempt,
                )
                .await
            {
                Ok(next_seq) => next_seq,
                Err(outcome) => return outcome,
            };
        }
        completed_outcome.into_saga_outcome(failed_node)
    }

    async fn complete_noop_compensation(
        &self,
        action: &dyn SagaAction,
        seq: u64,
        cause: SagaCompensationCause,
    ) -> Result<u64, SagaOutcome> {
        let step = StepName::parse(action.name()).map_err(|_| SagaOutcome::Failed {
            failed_node: action.name().to_string(),
            error: SagaActionError::InvariantViolation,
        })?;
        let effect_key = self
            .action_context(action, SagaActionPhase::Compensation)
            .map_err(|error| SagaOutcome::Failed {
                failed_node: action.name().to_string(),
                error,
            })?
            .idempotency_key;
        let attempt = consistency::SagaAttempt::new(1).map_err(|_| SagaOutcome::Failed {
            failed_node: action.name().to_string(),
            error: SagaActionError::InvariantViolation,
        })?;
        let intent =
            SagaCompensationIntent::new(seq, step.clone(), attempt, effect_key.clone(), cause)
                .map_err(|_| SagaOutcome::Failed {
                    failed_node: action.name().to_string(),
                    error: SagaActionError::InvariantViolation,
                })?;
        self.mutate(
            action,
            &step,
            SagaDurableMutation::CompensationIntent(intent),
            seq,
            SagaJournalStatus::CompensationIntent,
        )
        .await
        .map_err(|failure| self.append_failure_outcome(failure, action.name()))?;
        self.finish_compensation_success(
            action,
            &step,
            attempt,
            effect_key,
            seq + 1,
            action.name(),
            cause,
            true,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn compensate_step(
        &self,
        action: &dyn SagaAction,
        step: &StepName,
        receipt: Option<Arc<dyn Any + Send + Sync>>,
        seq: u64,
        failed_node: &str,
        cause: SagaCompensationCause,
        terminal: bool,
        starting_attempt: u32,
    ) -> Result<u64, SagaOutcome> {
        if !self.refresh_lease().await {
            return Err(Self::interrupted(SagaInterruption::LeaseLost));
        }
        let Some(receipt) = receipt else {
            return Err(self
                .require_operator(SagaOperatorReason::ReceiptMissing)
                .await);
        };
        let effect_key = self
            .action_context(action, SagaActionPhase::Compensation)
            .map_err(|error| SagaOutcome::Failed {
                failed_node: action.name().to_string(),
                error,
            })?
            .idempotency_key;
        let mut next_seq = seq;
        let mut attempt_number = starting_attempt;
        let deadline = SagaPhaseDeadline::new(self.policy.time_budget);
        loop {
            let attempt =
                consistency::SagaAttempt::new(attempt_number).map_err(|_| SagaOutcome::Failed {
                    failed_node: action.name().to_string(),
                    error: SagaActionError::InvariantViolation,
                })?;
            let intent = SagaCompensationIntent::new(
                next_seq,
                step.clone(),
                attempt,
                effect_key.clone(),
                cause,
            )
            .map_err(|_| SagaOutcome::Failed {
                failed_node: action.name().to_string(),
                error: SagaActionError::InvariantViolation,
            })?;
            self.mutate(
                action,
                step,
                SagaDurableMutation::CompensationIntent(intent.clone()),
                next_seq,
                SagaJournalStatus::CompensationIntent,
            )
            .await
            .map_err(|failure| self.append_failure_outcome(failure, failed_node))?;
            next_seq += 1;

            // Bind authorization to the exact durable intent and still-current lease generation
            // before the compensation provider future exists.
            if !self.refresh_lease().await {
                self.warn_action_lease_lost(action.name(), SagaActionPhase::Compensation);
                return Err(Self::interrupted(SagaInterruption::LeaseLost));
            }

            let time_budget = deadline.remaining();
            let result = match self
                .run_compensation_action(action, intent, receipt.clone(), time_budget)
                .await
            {
                Ok(()) => Ok(()),
                Err(SagaPhaseError::Action(error))
                    if error.classification() == SagaFailureClass::OutcomeUnknown =>
                {
                    match self
                        .probe_compensation_action(action, receipt.clone())
                        .await
                    {
                        Ok(SagaProbeOutcome::Applied(())) => Ok(()),
                        Ok(SagaProbeOutcome::NotApplied) => {
                            if matches!(error, SagaActionError::ActionTimedOut) {
                                Err(SagaActionError::ActionTimedOut)
                            } else {
                                Err(SagaActionError::ActionFailed)
                            }
                        }
                        // `SagaProbeOutcome` is non-exhaustive; every non-Applied/NotApplied
                        // provider answer is fail-closed as an uncertain compensation outcome.
                        Ok(_) => {
                            return Err(self
                                .require_operator(SagaOperatorReason::CompensationOutcomeUnknown)
                                .await);
                        }
                        Err(SagaPhaseError::Action(_)) => {
                            return Err(self
                                .require_operator(SagaOperatorReason::CompensationOutcomeUnknown)
                                .await);
                        }
                        Err(SagaPhaseError::Interrupted(reason)) => {
                            return Err(Self::interrupted(reason));
                        }
                    }
                }
                Err(SagaPhaseError::Action(error)) => Err(error),
                Err(SagaPhaseError::Interrupted(reason)) => {
                    return Err(Self::interrupted(reason));
                }
            };
            match result {
                Ok(()) => {
                    return self
                        .finish_compensation_success(
                            action,
                            step,
                            attempt,
                            effect_key,
                            next_seq,
                            failed_node,
                            cause,
                            terminal,
                        )
                        .await;
                }
                Err(error) => {
                    if error.classification() == SagaFailureClass::Transient
                        && action.retry_class() == vocab::SagaRetryClass::Transient
                        && attempt_number < self.policy.max_attempts
                    {
                        let entropy = saga_retry_entropy(
                            self.instance,
                            action.name(),
                            SagaActionPhase::Compensation,
                            attempt_number,
                        );
                        let delay = self.policy.delay_for(attempt_number, entropy);
                        if deadline.sleep(delay).await {
                            attempt_number = attempt_number.saturating_add(1);
                            continue;
                        }
                        return Err(self
                            .finish_compensation_failure(
                                action,
                                step,
                                attempt,
                                effect_key,
                                next_seq,
                                failed_node,
                                SagaActionError::ActionTimedOut,
                            )
                            .await);
                    }
                    return Err(self
                        .finish_compensation_failure(
                            action,
                            step,
                            attempt,
                            effect_key,
                            next_seq,
                            failed_node,
                            error,
                        )
                        .await);
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn finish_compensation_success(
        &self,
        action: &dyn SagaAction,
        step: &StepName,
        attempt: consistency::SagaAttempt,
        effect_key: SagaIdempotencyKey,
        seq: u64,
        failed_node: &str,
        cause: SagaCompensationCause,
        terminal: bool,
    ) -> Result<u64, SagaOutcome> {
        let progress = if terminal {
            match cause {
                SagaCompensationCause::Expired => SagaCompensationProgress::Expired,
                SagaCompensationCause::BusinessFailure => SagaCompensationProgress::Compensated,
                _ => SagaCompensationProgress::Compensated,
            }
        } else {
            SagaCompensationProgress::Continue
        };
        let completion =
            SagaCompensationCompletion::new(seq, step.clone(), attempt, effect_key, progress)
                .map_err(|_| SagaOutcome::Failed {
                    failed_node: action.name().to_string(),
                    error: SagaActionError::InvariantViolation,
                })?;
        match self
            .store
            .mutate(
                &self.lease,
                SagaDurableMutation::CompensationCompleted(completion),
            )
            .await
        {
            Ok(
                SagaDurableMutationOutcome::Applied
                | SagaDurableMutationOutcome::IdempotentDuplicate,
            ) => {}
            Ok(SagaDurableMutationOutcome::LeaseLost) => {
                return Err(Self::interrupted(SagaInterruption::LeaseLost));
            }
            Ok(SagaDurableMutationOutcome::Conflict) => {
                self.mark_degraded_best_effort().await;
                return Err(Self::interrupted(SagaInterruption::JournalConflict));
            }
            Err(error) if error.kind() == SagaDurableStoreErrorKind::CommitUnknown => {
                let terminal_visible = if terminal {
                    let expected = match cause {
                        SagaCompensationCause::Expired => SagaInstanceStatus::Expired,
                        SagaCompensationCause::BusinessFailure => SagaInstanceStatus::Compensated,
                        _ => SagaInstanceStatus::Compensated,
                    };
                    matches!(
                        self.store.get(&self.instance).await,
                        Ok(Some(row)) if row.status() == expected
                    )
                } else {
                    false
                };
                if !terminal_visible
                    && !self
                        .journal_transition_visible(
                            action,
                            step,
                            seq,
                            SagaJournalStatus::CompensationCompleted,
                        )
                        .await
                {
                    return Err(self
                        .require_operator(SagaOperatorReason::CompensationOutcomeUnknown)
                        .await);
                }
            }
            Err(_) | Ok(_) => {
                return Err(SagaOutcome::Interrupted {
                    reason: SagaInterruption::StoreUnavailable,
                });
            }
        }
        let _ = failed_node;
        Ok(seq + 1)
    }

    #[allow(clippy::too_many_arguments)]
    async fn finish_compensation_failure(
        &self,
        action: &dyn SagaAction,
        step: &StepName,
        attempt: consistency::SagaAttempt,
        effect_key: SagaIdempotencyKey,
        seq: u64,
        failed_node: &str,
        undo_err: SagaActionError,
    ) -> SagaOutcome {
        let failure = match SagaCompensationFailure::new(
            seq,
            step.clone(),
            attempt,
            effect_key,
            SAGA_COMPENSATION_FAILED,
        ) {
            Ok(failure) => failure,
            Err(_) => {
                return SagaOutcome::Failed {
                    failed_node: action.name().to_string(),
                    error: SagaActionError::InvariantViolation,
                };
            }
        };
        match self
            .store
            .mutate(
                &self.lease,
                SagaDurableMutation::CompensationFailed(failure),
            )
            .await
        {
            Ok(
                SagaDurableMutationOutcome::Applied
                | SagaDurableMutationOutcome::IdempotentDuplicate,
            ) => {}
            Ok(SagaDurableMutationOutcome::LeaseLost) => {
                return Self::interrupted(SagaInterruption::LeaseLost);
            }
            Ok(SagaDurableMutationOutcome::Conflict) => {
                self.mark_degraded_best_effort().await;
                return Self::interrupted(SagaInterruption::JournalConflict);
            }
            Err(error) if error.kind() == SagaDurableStoreErrorKind::CommitUnknown => {
                let terminal_visible = matches!(
                    self.store.get(&self.instance).await,
                    Ok(Some(row)) if row.status() == SagaInstanceStatus::CompensationFailed
                );
                if !terminal_visible
                    && !self
                        .journal_transition_visible(
                            action,
                            step,
                            seq,
                            SagaJournalStatus::CompensationFailed,
                        )
                        .await
                {
                    return self
                        .require_operator(SagaOperatorReason::CompletionCommitUnknown)
                        .await;
                }
            }
            Err(_) | Ok(_) => {
                return Self::interrupted(SagaInterruption::StoreUnavailable);
            }
        }
        // F5：DLX 携 saga_id + 原始前向失败步（failed_node）+ 补偿失败步，诊断闭环。
        self.dead_letter_compensation_failure(action.name(), failed_node, SAGA_COMPENSATION_FAILED)
            .await;
        SagaOutcome::Failed {
            failed_node: action.name().to_string(),
            error: undo_err,
        }
    }

    /// 补偿失败 → 结构化 error 日志（saga_id / step_name / error_summary）+ 写 dead-letter
    /// （domain / contract_id 取 saga owner，由 [`DeadLetterStore`] durable record 承载）。DLX 写失败：记日志，journal `Failed` 行是 durable 审计。
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

    /// 补偿失败结构化 error 日志（saga_id / step_name / failed_forward_step / error_summary），
    /// 与 [`ExecCtx::error_dlx_write_failed`] 共同承载 durable DLX 可观测性。
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
        let snapshot = match self.read_recovery_snapshot(actions).await {
            Ok(snapshot) => snapshot,
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

        let (_, entries, receipts, operator_reason, compensation_cause) = snapshot.into_parts();
        if operator_reason.is_some() {
            self.release_lease_best_effort().await;
            return Self::interrupted(SagaInterruption::OperatorRequired);
        }
        match definition.replay(&entries) {
            Ok(decision) => {
                self.apply_replay_decision(
                    actions,
                    decision,
                    &entries,
                    &receipts,
                    compensation_cause,
                )
                .await
            }
            Err(err) => {
                self.release_lease_best_effort().await;
                self.replay_error_outcome(&err)
            }
        }
    }

    async fn read_recovery_snapshot(
        &self,
        actions: &[Box<dyn SagaAction>],
    ) -> Result<diport::SagaRecoverySnapshot, SagaOutcome> {
        let mut scopes = Vec::with_capacity(actions.len());
        for action in actions {
            let step = StepName::parse(action.name()).map_err(|_| SagaOutcome::Failed {
                failed_node: action.name().to_string(),
                error: SagaActionError::InvariantViolation,
            })?;
            scopes.push(
                self.forward_receipt_scope(action.as_ref(), step)
                    .map_err(|_| SagaOutcome::Failed {
                        failed_node: action.name().to_string(),
                        error: SagaActionError::InvariantViolation,
                    })?,
            );
        }
        let request = SagaRecoveryRequest::new(self.lease.clone(), scopes).map_err(|_| {
            SagaOutcome::Failed {
                failed_node: UNKNOWN_SAGA.to_string(),
                error: SagaActionError::InvariantViolation,
            }
        })?;
        match self.store.recovery_snapshot(request).await {
            Ok(SagaRecoveryOutcome::Available(snapshot)) => {
                let row = snapshot.instance();
                if row.instance() != self.instance
                    || row.identity() != self.identity
                    || row.definition() != self.definition
                {
                    return Err(self
                        .require_operator(SagaOperatorReason::ReceiptIntegrity)
                        .await);
                }
                Ok(snapshot)
            }
            Ok(SagaRecoveryOutcome::LeaseLost) => {
                Err(Self::interrupted(SagaInterruption::LeaseLost))
            }
            Err(error) => {
                self.error_resume_read_failed();
                match error.kind() {
                    SagaDurableStoreErrorKind::Protection
                    | SagaDurableStoreErrorKind::Integrity => Err(self
                        .require_operator(SagaOperatorReason::ReceiptIntegrity)
                        .await),
                    SagaDurableStoreErrorKind::UnsupportedFormat => Err(self
                        .require_operator(SagaOperatorReason::ReceiptFormatUnsupported)
                        .await),
                    _ => Err(Self::interrupted(SagaInterruption::StoreUnavailable)),
                }
            }
            Ok(_) => Err(Self::interrupted(SagaInterruption::StoreUnavailable)),
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
        entries: &[SagaJournalRecord],
        receipts: &[StoredSagaReceipt],
        compensation_cause: Option<SagaCompensationCause>,
    ) -> SagaOutcome {
        match decision {
            SagaReplayDecision::Forward {
                start,
                next_seq,
                completed,
            } => {
                self.apply_forward_replay(actions, start, next_seq, completed, entries, receipts)
                    .await
            }
            SagaReplayDecision::Compensating {
                next_seq,
                pending,
                failed_step,
            } => {
                self.apply_compensating_replay(
                    actions,
                    next_seq,
                    pending,
                    failed_step,
                    entries,
                    receipts,
                    compensation_cause,
                )
                .await
            }
            SagaReplayDecision::Terminal { status } => {
                self.outcome_from_terminal_status(actions, status).await
            }
            _ => SagaOutcome::Failed {
                failed_node: UNKNOWN_SAGA.to_string(),
                error: SagaActionError::SerializeFailed,
            },
        }
    }

    async fn apply_forward_replay(
        &self,
        actions: &[Box<dyn SagaAction>],
        start: usize,
        next_seq: u64,
        completed: Vec<(usize, StepName)>,
        entries: &[SagaJournalRecord],
        receipts: &[StoredSagaReceipt],
    ) -> SagaOutcome {
        let (completed, last_reference) =
            match self.hydrate_completed_steps(actions, completed, entries, receipts) {
                Ok(hydrated) => hydrated,
                Err(reason) => return self.require_operator(reason).await,
            };
        let mut cursor = Cursor {
            seq: next_seq,
            completed,
            last_reference,
            next_attempt: None,
        };
        if start < actions.len()
            && entries.last().is_some_and(|record| {
                record.status() == SagaJournalStatus::ForwardIntent
                    && record.step_name().as_str() == actions[start].name()
            })
        {
            return self
                .recover_forward_intent(actions, start, entries, &mut cursor)
                .await;
        }
        self.run_forward(actions, start, cursor).await
    }

    #[allow(clippy::too_many_arguments)]
    async fn apply_compensating_replay(
        &self,
        actions: &[Box<dyn SagaAction>],
        next_seq: u64,
        pending: Vec<(usize, StepName)>,
        failed_step: Option<StepName>,
        entries: &[SagaJournalRecord],
        receipts: &[StoredSagaReceipt],
        compensation_cause: Option<SagaCompensationCause>,
    ) -> SagaOutcome {
        let failed_node = failed_step.as_ref().map_or(UNKNOWN_SAGA, StepName::as_str);
        let (mut pending, _) =
            match self.hydrate_completed_steps(actions, pending, entries, receipts) {
                Ok(hydrated) => hydrated,
                Err(reason) => return self.require_operator(reason).await,
            };
        let cause = compensation_cause.unwrap_or(SagaCompensationCause::BusinessFailure);
        match self
            .probe_pending_compensation(actions, &pending, entries)
            .await
        {
            PendingCompensationProbe::Applied(attempts) => {
                return self
                    .settle_replayed_compensation_applied(
                        actions,
                        pending,
                        attempts,
                        next_seq,
                        failed_node,
                        cause,
                    )
                    .await;
            }
            PendingCompensationProbe::NotApplied(attempts)
                if attempts >= self.policy.max_attempts =>
            {
                return self
                    .settle_replayed_compensation_exhausted(
                        actions,
                        &pending,
                        attempts,
                        next_seq,
                        failed_node,
                    )
                    .await;
            }
            PendingCompensationProbe::NotApplied(attempts) => {
                if let Some(first) = pending.first_mut() {
                    first.compensation_attempt = attempts.saturating_add(1);
                }
            }
            PendingCompensationProbe::Operator(reason) => {
                return self.require_operator(reason).await;
            }
            PendingCompensationProbe::Interrupted(reason) => {
                return Self::interrupted(reason);
            }
            PendingCompensationProbe::None => {}
        }
        self.compensate_pending(
            actions,
            &pending,
            next_seq,
            failed_node,
            compensated_outcome_for(cause),
        )
        .await
    }

    async fn probe_pending_compensation(
        &self,
        actions: &[Box<dyn SagaAction>],
        pending: &[CompletedStep],
        entries: &[SagaJournalRecord],
    ) -> PendingCompensationProbe {
        let Some(first) = pending.first() else {
            return PendingCompensationProbe::None;
        };
        if !entries.last().is_some_and(|record| {
            record.status() == SagaJournalStatus::CompensationIntent
                && record.step_name() == &first.name
        }) {
            return PendingCompensationProbe::None;
        }
        let attempts = count_attempts(entries, &first.name, SagaJournalStatus::CompensationIntent);
        let Some(action) = actions.get(first.index) else {
            return PendingCompensationProbe::Operator(SagaOperatorReason::DefinitionUnsupported);
        };
        let Some(receipt) = first.receipt.clone() else {
            return PendingCompensationProbe::Operator(SagaOperatorReason::ReceiptMissing);
        };
        match self
            .probe_compensation_action(action.as_ref(), receipt)
            .await
        {
            Ok(SagaProbeOutcome::Applied(())) => PendingCompensationProbe::Applied(attempts),
            Ok(SagaProbeOutcome::NotApplied) => PendingCompensationProbe::NotApplied(attempts),
            Ok(SagaProbeOutcome::Unknown) | Err(SagaPhaseError::Action(_)) => {
                PendingCompensationProbe::Operator(SagaOperatorReason::CompensationOutcomeUnknown)
            }
            Err(SagaPhaseError::Interrupted(reason)) => {
                PendingCompensationProbe::Interrupted(reason)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn settle_replayed_compensation_applied(
        &self,
        actions: &[Box<dyn SagaAction>],
        mut pending: Vec<CompletedStep>,
        attempts: u32,
        next_seq: u64,
        failed_node: &str,
        cause: SagaCompensationCause,
    ) -> SagaOutcome {
        let first = &pending[0];
        let Some(action) = actions.get(first.index) else {
            return self
                .require_operator(SagaOperatorReason::DefinitionUnsupported)
                .await;
        };
        let Ok(attempt) = consistency::SagaAttempt::new(attempts) else {
            return self
                .require_operator(SagaOperatorReason::ReceiptIntegrity)
                .await;
        };
        let Ok(context) = self.action_context(action.as_ref(), SagaActionPhase::Compensation)
        else {
            return self
                .require_operator(SagaOperatorReason::DefinitionUnsupported)
                .await;
        };
        if let Err(outcome) = self
            .finish_compensation_success(
                action.as_ref(),
                &first.name,
                attempt,
                context.idempotency_key,
                next_seq,
                failed_node,
                cause,
                pending.len() == 1,
            )
            .await
        {
            return outcome;
        }
        pending.remove(0);
        self.compensate_pending(
            actions,
            &pending,
            next_seq + 1,
            failed_node,
            compensated_outcome_for(cause),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn settle_replayed_compensation_exhausted(
        &self,
        actions: &[Box<dyn SagaAction>],
        pending: &[CompletedStep],
        attempts: u32,
        next_seq: u64,
        failed_node: &str,
    ) -> SagaOutcome {
        let first = &pending[0];
        let Some(action) = actions.get(first.index) else {
            return self
                .require_operator(SagaOperatorReason::DefinitionUnsupported)
                .await;
        };
        let Ok(attempt) = consistency::SagaAttempt::new(attempts) else {
            return self
                .require_operator(SagaOperatorReason::ReceiptIntegrity)
                .await;
        };
        let Ok(context) = self.action_context(action.as_ref(), SagaActionPhase::Compensation)
        else {
            return self
                .require_operator(SagaOperatorReason::DefinitionUnsupported)
                .await;
        };
        self.finish_compensation_failure(
            action.as_ref(),
            &first.name,
            attempt,
            context.idempotency_key,
            next_seq,
            failed_node,
            SagaActionError::ActionFailed,
        )
        .await
    }

    fn hydrate_completed_steps(
        &self,
        actions: &[Box<dyn SagaAction>],
        completed: Vec<(usize, StepName)>,
        entries: &[SagaJournalRecord],
        receipts: &[StoredSagaReceipt],
    ) -> Result<(Vec<CompletedStep>, Option<SagaSuccessReference>), SagaOperatorReason> {
        let mut hydrated = Vec::with_capacity(completed.len());
        let mut last_reference = None;
        for (index, name) in completed {
            let action = actions
                .get(index)
                .ok_or(SagaOperatorReason::DefinitionUnsupported)?;
            if action.name() != name.as_str() {
                return Err(SagaOperatorReason::DefinitionUnsupported);
            }
            let scope = self
                .forward_receipt_scope(action.as_ref(), name.clone())
                .map_err(|_| SagaOperatorReason::DefinitionUnsupported)?;
            let completed_seq = entries
                .iter()
                .find(|record| {
                    record.step_name() == &name
                        && record.status() == SagaJournalStatus::ForwardCompleted
                })
                .map(SagaJournalRecord::seq);
            let receipt = if let Some(completed_seq) = completed_seq {
                let stored = receipts
                    .iter()
                    .find(|receipt| receipt.scope() == &scope)
                    .ok_or(SagaOperatorReason::ReceiptMissing)?;
                if stored.completed_seq() != completed_seq
                    || stored.format() != SagaReceiptFormatVersion::V1
                    || stored.attempt().get()
                        != count_attempts(entries, &name, SagaJournalStatus::ForwardIntent)
                {
                    return Err(SagaOperatorReason::ReceiptIntegrity);
                }
                let value = action
                    .decode_receipt(stored.plaintext().expose())
                    .map_err(|_| SagaOperatorReason::ReceiptFormatUnsupported)?;
                last_reference = Some(SagaSuccessReference::new(scope));
                Some(value)
            } else {
                None
            };
            hydrated.push(CompletedStep {
                index,
                name,
                receipt,
                compensation_attempt: 1,
            });
        }
        Ok((hydrated, last_reference))
    }

    async fn recover_forward_intent(
        &self,
        actions: &[Box<dyn SagaAction>],
        start: usize,
        entries: &[SagaJournalRecord],
        cursor: &mut Cursor,
    ) -> SagaOutcome {
        let Some(action) = actions.get(start) else {
            return self
                .require_operator(SagaOperatorReason::DefinitionUnsupported)
                .await;
        };
        let step = match StepName::parse(action.name()) {
            Ok(step) => step,
            Err(_) => {
                return self
                    .require_operator(SagaOperatorReason::DefinitionUnsupported)
                    .await;
            }
        };
        let attempts = count_attempts(entries, &step, SagaJournalStatus::ForwardIntent);
        match self.probe_forward_action(action.as_ref()).await {
            Ok(SagaProbeOutcome::Applied(receipt)) => {
                let attempt = match consistency::SagaAttempt::new(attempts) {
                    Ok(attempt) => attempt,
                    Err(_) => {
                        return self
                            .require_operator(SagaOperatorReason::ReceiptIntegrity)
                            .await;
                    }
                };
                let output = match receipt.output {
                    Ok(output) => output,
                    Err(_) => {
                        return self
                            .require_operator(SagaOperatorReason::ReceiptFormatUnsupported)
                            .await;
                    }
                };
                let completed_step = CompletedStep {
                    index: start,
                    name: step.clone(),
                    receipt: Some(receipt.value),
                    compensation_attempt: 1,
                };
                cursor.completed.push(completed_step);
                let reference = match self
                    .commit_forward_completion(
                        action.as_ref(),
                        step,
                        attempt,
                        &output,
                        cursor.seq,
                        start + 1 == actions.len(),
                    )
                    .await
                {
                    Ok(reference) => reference,
                    Err(ReceiptCommitFailure::LeaseLost) => {
                        return Self::interrupted(SagaInterruption::LeaseLost);
                    }
                    Err(ReceiptCommitFailure::Operator(reason)) => {
                        return self.require_operator(reason).await;
                    }
                    Err(ReceiptCommitFailure::OutcomeUnknown) => {
                        return self
                            .require_operator(SagaOperatorReason::CompletionCommitUnknown)
                            .await;
                    }
                    Err(ReceiptCommitFailure::Recoverable) => {
                        return Self::interrupted(SagaInterruption::StoreUnavailable);
                    }
                };
                cursor.last_reference = Some(reference);
                cursor.seq += 1;
                self.run_forward(
                    actions,
                    start + 1,
                    Cursor {
                        seq: cursor.seq,
                        completed: cursor.completed.clone(),
                        last_reference: cursor.last_reference.clone(),
                        next_attempt: None,
                    },
                )
                .await
            }
            Ok(SagaProbeOutcome::NotApplied) => {
                if attempts >= self.policy.max_attempts {
                    return self
                        .compensate(
                            actions,
                            &cursor.completed,
                            cursor.seq,
                            action.name(),
                            CompensatedOutcome::Failed(SagaActionError::ActionFailed),
                        )
                        .await;
                }
                cursor.next_attempt = Some(attempts.saturating_add(1));
                self.run_forward(
                    actions,
                    start,
                    Cursor {
                        seq: cursor.seq,
                        completed: cursor.completed.clone(),
                        last_reference: cursor.last_reference.clone(),
                        next_attempt: cursor.next_attempt,
                    },
                )
                .await
            }
            Ok(SagaProbeOutcome::Unknown) | Err(SagaPhaseError::Action(_)) => {
                self.require_operator(SagaOperatorReason::ForwardOutcomeUnknown)
                    .await
            }
            Err(SagaPhaseError::Interrupted(reason)) => Self::interrupted(reason),
        }
    }

    async fn outcome_from_terminal_status(
        &self,
        actions: &[Box<dyn SagaAction>],
        status: SagaDurableStatus,
    ) -> SagaOutcome {
        if status == SagaDurableStatus::Succeeded {
            let scope = match actions
                .last()
                .ok_or(TerminalReceiptFailure::Integrity)
                .and_then(|action| {
                    terminal_scope_for_action(
                        self.instance,
                        self.identity,
                        self.definition,
                        action.as_ref(),
                    )
                }) {
                Ok(scope) => scope,
                Err(failure) => {
                    return match failure.operator_reason() {
                        Some(reason) => self.require_operator(reason).await,
                        None => Self::interrupted(failure.interruption()),
                    };
                }
            };
            return match load_verified_terminal_receipt(self.store, scope.clone()).await {
                Ok(_) => {
                    self.release_lease_best_effort().await;
                    SagaOutcome::Succeeded {
                        reference: Box::new(SagaSuccessReference::new(scope)),
                    }
                }
                Err(failure) => match failure.operator_reason() {
                    Some(reason) => self.require_operator(reason).await,
                    None => {
                        self.release_lease_best_effort().await;
                        Self::interrupted(failure.interruption())
                    }
                },
            };
        }
        self.release_lease_best_effort().await;
        outcome_from_terminal_status(status)
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

fn count_attempts(
    entries: &[SagaJournalRecord],
    step: &StepName,
    status: SagaJournalStatus,
) -> u32 {
    u32::try_from(
        entries
            .iter()
            .filter(|record| record.step_name() == step && record.status() == status)
            .count(),
    )
    .unwrap_or(u32::MAX)
}

fn compensated_outcome_for(cause: SagaCompensationCause) -> CompensatedOutcome {
    match cause {
        SagaCompensationCause::Expired => {
            CompensatedOutcome::Failed(SagaActionError::ActionTimedOut)
        }
        SagaCompensationCause::BusinessFailure => {
            CompensatedOutcome::Failed(SagaActionError::ActionFailed)
        }
        _ => CompensatedOutcome::Failed(SagaActionError::ActionFailed),
    }
}

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
        SagaDurableStatus::Succeeded => SagaOutcome::Interrupted {
            reason: SagaInterruption::ReceiptUnavailable,
        },
        SagaDurableStatus::CompensationFailed { failed_step } => SagaOutcome::Failed {
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
        SagaInstanceStatus::Succeeded => SagaOutcome::Interrupted {
            reason: SagaInterruption::ReceiptUnavailable,
        },
        SagaInstanceStatus::Compensated
        | SagaInstanceStatus::Expired
        | SagaInstanceStatus::Terminated => SagaOutcome::Failed {
            failed_node: UNKNOWN_SAGA.to_string(),
            error: SagaActionError::ActionFailed,
        },
        SagaInstanceStatus::OperatorRequired
        | SagaInstanceStatus::CompensationFailed
        | SagaInstanceStatus::Degraded => SagaOutcome::Interrupted {
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

#[cfg(test)]
mod tests;
