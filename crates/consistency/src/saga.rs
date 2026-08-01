//! Saga 编排接缝（L3）—— do/undo 前向动作 + 逆序补偿。
//!
//! 本模块冻结 Saga 的 durable identity 与 journal/replay 纯模型，并消费 `vocab` 的 canonical
//! step name；业务 authoring 只经
//! `eventexec::SagaStep<GeneratedStepMarker>`，由 generated receipt 与 definition 专属 typestate
//! 约束。**compensation order 只能 reverse**（saga.md §Governance）——逆序由 eventexec executor
//! 持栈驱动，consistency 不再暴露平行 step authoring trait。
//! ref: oxidecomputer/steno src/saga_action_generic.rs@main（`Action::do_it`/`undo_it`/`name` 对标；
//! RSS 拒其 `ActionData: Serialize+DeserializeOwned` bound（ADR-004 C6）、用 native AFIT 替 BoxFuture）。
//! ref: oxidecomputer/steno src/saga_log.rs@main（durable journal event → load status replay；RSS
//! 偏离其 serde output 持久化，journal record 不承载 generated receipt；durable receipt 另有专属边界）。

use sha2::{Digest as _, Sha256};
use std::collections::{HashMap, HashSet};
use std::num::NonZeroU32;
use vocab::{StepName, TenantId};

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

/// Phase-specific identity of one Saga external effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SagaEffectPhase {
    /// Forward effect produced by `execute`.
    Forward,
    /// Reverse effect produced by `compensate`.
    Compensation,
}

impl SagaEffectPhase {
    /// Stable domain-separation label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Forward => "forward",
            Self::Compensation => "compensation",
        }
    }
}

/// Canonical retry-independent key for exactly one Saga effect.
///
/// Normal command paths derive all durable identity dimensions with length-prefixed hashing.
/// Durable providers may hydrate the already-persisted opaque bytes only through the explicit
/// storage constructor, which also requires the closed effect phase.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SagaIdempotencyKey {
    bytes: [u8; 32],
    phase: SagaEffectPhase,
}

impl std::fmt::Debug for SagaIdempotencyKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SagaIdempotencyKey(<redacted>)")
    }
}

impl SagaIdempotencyKey {
    /// Derive the canonical key from the complete pinned definition and generated step binding.
    pub fn derive(
        instance: SagaInstanceRef,
        definition: &SagaDefinitionIdentity,
        step: vocab::SagaStepBinding,
        phase: SagaEffectPhase,
    ) -> Self {
        let tenant = instance.tenant().to_string();
        let saga_id = instance.saga_id().as_uuid();
        let scope = match phase {
            SagaEffectPhase::Forward => step.effect_scope(),
            SagaEffectPhase::Compensation => step.compensation_effect_scope(),
        };
        let mut hash = Sha256::new();
        hash.update(b"rss.saga.idempotency-key.v1");
        for bytes in [
            tenant.as_bytes(),
            saga_id.as_bytes(),
            definition.contract_id().as_bytes(),
            definition.version().as_bytes(),
            definition.schema_digest().as_bytes(),
            definition.action_registry_generation().as_bytes(),
            step.name().as_bytes(),
            phase.as_str().as_bytes(),
            scope.as_bytes(),
        ] {
            hash.update((bytes.len() as u64).to_be_bytes());
            hash.update(bytes);
        }
        Self {
            bytes: hash.finalize().into(),
            phase,
        }
    }

    /// Hydrate an exact key previously persisted by a durable provider.
    ///
    /// The fixed-size array prevents truncated or extended digests, while [`SagaEffectPhase`]
    /// prevents unrecognized phase labels from entering the model. Command paths should use
    /// [`Self::derive`]; this constructor exists for authoritative storage replay only.
    pub const fn from_storage(bytes: [u8; 32], phase: SagaEffectPhase) -> Self {
        Self { bytes, phase }
    }

    /// Opaque storage representation. Never log or expose this value as diagnostics.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Effect phase bound into this key.
    pub const fn phase(&self) -> SagaEffectPhase {
        self.phase
    }

    /// Stable lowercase hexadecimal representation for an external effect request header.
    pub fn to_hex(&self) -> String {
        use std::fmt::Write as _;

        let mut output = String::with_capacity(64);
        for byte in self.bytes {
            let _ = write!(output, "{byte:02x}");
        }
        output
    }
}

/// Positive successful action attempt retained only as audit metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SagaAttempt(NonZeroU32);

/// Invalid Saga attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("saga attempt must be positive")]
pub struct SagaAttemptError;

impl SagaAttempt {
    /// Construct positive attempt metadata.
    pub fn new(attempt: u32) -> Result<Self, SagaAttemptError> {
        NonZeroU32::new(attempt).map(Self).ok_or(SagaAttemptError)
    }

    /// One-based successful attempt number.
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

/// Durable receipt storage envelope version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SagaReceiptFormatVersion {
    /// Canonical JSON protected by Saga-scoped envelope encryption.
    V1 = 1,
}

/// Unsupported durable receipt storage envelope version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("unsupported saga receipt format version")]
pub struct SagaReceiptFormatVersionError;

impl TryFrom<u16> for SagaReceiptFormatVersion {
    type Error = SagaReceiptFormatVersionError;

    fn try_from(raw: u16) -> Result<Self, Self::Error> {
        match raw {
            1 => Ok(Self::V1),
            _ => Err(SagaReceiptFormatVersionError),
        }
    }
}

impl From<SagaReceiptFormatVersion> for u16 {
    fn from(version: SagaReceiptFormatVersion) -> Self {
        version as u16
    }
}

/// tenant-scoped saga instance identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SagaInstanceRef {
    tenant: TenantId,
    saga_id: SagaId,
}

/// Durable, exact identity of one generated saga definition.
///
/// The schema digest and action generation are deliberately separate: the former identifies the
/// JSON schema bundle, while the latter identifies ordered executable semantics and retry policy.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SagaDefinitionIdentity {
    contract_id: String,
    version: String,
    schema_digest: vocab::CanonicalSha256Digest,
    action_registry_generation: vocab::CanonicalSha256Digest,
}

/// Canonical Saga contract id shared by durable identity and worker discovery.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SagaContractId(String);

/// Invalid Saga contract id.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaContractIdError {
    /// Contract id was empty.
    #[error("saga contract id is empty")]
    Empty,
    /// Contract id does not use canonical dotted grammar.
    #[error("saga contract id is not a canonical dotted name")]
    Format,
}

impl SagaContractId {
    /// Parse a generated Saga contract id.
    pub fn parse(raw: &str) -> Result<Self, SagaContractIdError> {
        if raw.is_empty() {
            return Err(SagaContractIdError::Empty);
        }
        if !is_canonical_dotted(raw) {
            return Err(SagaContractIdError::Format);
        }
        Ok(Self(raw.to_string()))
    }

    /// Borrow the canonical contract id string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Complete durable Saga owner identity: owner + contract id.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SagaWorkerIdentity {
    owner: String,
    contract_id: SagaContractId,
}

/// Invalid Saga worker identity.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaWorkerIdentityError {
    /// Owner was empty or blank.
    #[error("saga worker owner is empty")]
    EmptyOwner,
}

impl SagaWorkerIdentity {
    /// Build a validated Saga worker identity.
    pub fn new(
        owner: impl Into<String>,
        contract_id: SagaContractId,
    ) -> Result<Self, SagaWorkerIdentityError> {
        let owner = owner.into();
        if owner.trim().is_empty() {
            return Err(SagaWorkerIdentityError::EmptyOwner);
        }
        Ok(Self { owner, contract_id })
    }

    /// Saga owner/domain.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Saga contract id.
    pub fn contract_id(&self) -> &SagaContractId {
        &self.contract_id
    }
}

/// Invalid durable saga definition identity.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaDefinitionIdentityError {
    #[error("saga contract id is invalid")]
    ContractId,
    #[error("saga definition version is invalid")]
    Version,
    #[error("saga schema digest is invalid")]
    SchemaDigest,
    #[error("saga action registry generation is invalid")]
    ActionRegistryGeneration,
}

impl SagaDefinitionIdentity {
    /// Construct a validated identity read from a generated definition or durable store.
    pub fn new(
        contract_id: impl Into<String>,
        version: impl Into<String>,
        schema_digest: impl Into<String>,
        action_registry_generation: impl Into<String>,
    ) -> Result<Self, SagaDefinitionIdentityError> {
        let contract_id = contract_id.into();
        let version = version.into();
        let schema_digest = vocab::CanonicalSha256Digest::parse(schema_digest.into())
            .map_err(|_| SagaDefinitionIdentityError::SchemaDigest)?;
        let action_registry_generation =
            vocab::CanonicalSha256Digest::parse(action_registry_generation.into())
                .map_err(|_| SagaDefinitionIdentityError::ActionRegistryGeneration)?;
        if !is_canonical_dotted(&contract_id) {
            return Err(SagaDefinitionIdentityError::ContractId);
        }
        if !is_version(&version) {
            return Err(SagaDefinitionIdentityError::Version);
        }
        Ok(Self {
            contract_id,
            version,
            schema_digest,
            action_registry_generation,
        })
    }

    /// Copy an exact generated static identity into its durable owned representation.
    #[allow(
        clippy::expect_used,
        reason = "generated saga bindings are compile-time governed canonical identities"
    )]
    pub fn from_binding(binding: vocab::SagaContractBinding) -> Self {
        Self {
            contract_id: binding.contract_id().to_string(),
            version: binding.version().to_string(),
            schema_digest: vocab::CanonicalSha256Digest::parse(binding.schema_hash())
                .expect("generated saga schema digest must be canonical"),
            action_registry_generation: vocab::CanonicalSha256Digest::parse(
                binding.action_registry_generation(),
            )
            .expect("generated saga action generation must be canonical"),
        }
    }

    pub fn contract_id(&self) -> &str {
        &self.contract_id
    }
    pub fn version(&self) -> &str {
        &self.version
    }
    pub fn schema_digest(&self) -> &str {
        self.schema_digest.as_str()
    }
    pub fn action_registry_generation(&self) -> &str {
        self.action_registry_generation.as_str()
    }
}

/// Complete durable identity of one forward Saga receipt.
///
/// Private fields and the generated-binding constructor keep tenant, owner, pinned definition,
/// step, schema and effect key as one atom. Attempt metadata deliberately lives outside this key.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SagaReceiptScope {
    instance: SagaInstanceRef,
    worker: SagaWorkerIdentity,
    definition: SagaDefinitionIdentity,
    step_name: StepName,
    receipt_schema: Box<str>,
    effect_key: SagaIdempotencyKey,
}

impl std::fmt::Debug for SagaReceiptScope {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SagaReceiptScope")
            .field("instance", &self.instance)
            .field("worker", &self.worker)
            .field("definition", &self.definition)
            .field("step_name", &self.step_name)
            .field("receipt_schema", &self.receipt_schema)
            .field("effect_key", &"<redacted>")
            .finish()
    }
}

/// Invalid or mismatched Saga receipt scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SagaReceiptScopeError {
    /// Worker owner differs from the generated contract domain.
    #[error("saga receipt worker owner mismatch")]
    WorkerOwnerMismatch,
    /// Worker contract differs from the pinned/generated contract.
    #[error("saga receipt worker contract mismatch")]
    WorkerContractMismatch,
    /// Pinned definition version differs from the generated binding.
    #[error("saga receipt definition version mismatch")]
    DefinitionVersionMismatch,
    /// Pinned definition schema digest differs from the generated binding.
    #[error("saga receipt definition schema mismatch")]
    DefinitionSchemaMismatch,
    /// Generated step name is not a valid runtime step identity.
    #[error("saga receipt step name is invalid")]
    InvalidStepName,
    /// Generated receipt schema identifier is empty.
    #[error("saga receipt schema is empty")]
    EmptyReceiptSchema,
    /// The supplied effect key is not the canonical forward key for this scope.
    #[error("saga receipt effect key mismatch")]
    EffectKeyMismatch,
}

impl SagaReceiptScope {
    /// Construct an exact receipt scope from trusted instance identity and a generated step binding.
    pub fn new(
        instance: SagaInstanceRef,
        worker: SagaWorkerIdentity,
        definition: SagaDefinitionIdentity,
        step: vocab::SagaStepBinding,
        effect_key: SagaIdempotencyKey,
    ) -> Result<Self, SagaReceiptScopeError> {
        if worker.owner() != step.domain() {
            return Err(SagaReceiptScopeError::WorkerOwnerMismatch);
        }
        if worker.contract_id().as_str() != definition.contract_id()
            || worker.contract_id().as_str() != step.contract_id()
        {
            return Err(SagaReceiptScopeError::WorkerContractMismatch);
        }
        if definition.version() != step.version() {
            return Err(SagaReceiptScopeError::DefinitionVersionMismatch);
        }
        if definition.schema_digest() != step.schema_hash() {
            return Err(SagaReceiptScopeError::DefinitionSchemaMismatch);
        }
        let step_name =
            StepName::parse(step.name()).map_err(|_| SagaReceiptScopeError::InvalidStepName)?;
        if step.receipt_schema().is_empty() {
            return Err(SagaReceiptScopeError::EmptyReceiptSchema);
        }
        let expected =
            SagaIdempotencyKey::derive(instance, &definition, step, SagaEffectPhase::Forward);
        if effect_key != expected {
            return Err(SagaReceiptScopeError::EffectKeyMismatch);
        }
        Ok(Self {
            instance,
            worker,
            definition,
            step_name,
            receipt_schema: step.receipt_schema().into(),
            effect_key,
        })
    }

    /// Tenant-scoped Saga instance.
    pub const fn instance(&self) -> SagaInstanceRef {
        self.instance
    }

    /// Exact worker owner and contract identity.
    pub const fn worker(&self) -> &SagaWorkerIdentity {
        &self.worker
    }

    /// Exact pinned definition identity.
    pub const fn definition(&self) -> &SagaDefinitionIdentity {
        &self.definition
    }

    /// Generated step name.
    pub const fn step_name(&self) -> &StepName {
        &self.step_name
    }

    /// Generated business receipt schema identifier.
    pub const fn receipt_schema(&self) -> &str {
        &self.receipt_schema
    }

    /// Canonical forward effect key. The bytes remain redacted from `Debug`.
    pub const fn effect_key(&self) -> &SagaIdempotencyKey {
        &self.effect_key
    }
}

fn is_canonical_dotted(raw: &str) -> bool {
    !raw.is_empty()
        && raw.split('.').all(|segment| {
            matches!(segment.bytes().next(), Some(byte) if byte.is_ascii_lowercase())
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

fn is_version(raw: &str) -> bool {
    raw.strip_prefix('v').is_some_and(|digits| {
        matches!(digits.bytes().next(), Some(byte) if byte.is_ascii_digit() && byte != b'0')
            && digits.bytes().all(|byte| byte.is_ascii_digit())
    })
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
    /// Phase budget expired after the external effect was proven not applied and prior work was
    /// compensated.
    Expired,
    /// Compensation failed and requires manual intervention.
    CompensationFailed,
    /// An authorized, audited and fenced operator decision terminated the instance permanently.
    /// This is a true terminal state: workers must never resume it.
    Terminated,
    /// External effect or durable receipt state cannot be determined automatically.
    OperatorRequired,
    /// Durable state is inconsistent or journal append conflicted.
    Degraded,
}

impl SagaInstanceStatus {
    /// All DB labels.
    pub const ALL: [Self; 10] = [
        Self::Ready,
        Self::Running,
        Self::Succeeded,
        Self::Compensating,
        Self::Compensated,
        Self::Expired,
        Self::CompensationFailed,
        Self::Terminated,
        Self::OperatorRequired,
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
            Self::Expired => "expired",
            Self::CompensationFailed => "compensation_failed",
            Self::Terminated => "terminated",
            Self::OperatorRequired => "operator_required",
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
            "expired" => Some(Self::Expired),
            "compensation_failed" => Some(Self::CompensationFailed),
            "terminated" => Some(Self::Terminated),
            "operator_required" => Some(Self::OperatorRequired),
            "degraded" => Some(Self::Degraded),
            _ => None,
        }
    }

    /// Whether this lifecycle state is permanently terminal and cannot be resumed by a worker.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Compensated | Self::Expired | Self::Terminated
        )
    }
}

/// Closed durable reason for a Saga instance that cannot make automatic progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaOperatorReason {
    ForwardOutcomeUnknown,
    CompensationOutcomeUnknown,
    ReceiptMissing,
    ReceiptIntegrity,
    ReceiptFormatUnsupported,
    CompletionCommitUnknown,
    DefinitionUnsupported,
}

impl SagaOperatorReason {
    pub const ALL: [Self; 7] = [
        Self::ForwardOutcomeUnknown,
        Self::CompensationOutcomeUnknown,
        Self::ReceiptMissing,
        Self::ReceiptIntegrity,
        Self::ReceiptFormatUnsupported,
        Self::CompletionCommitUnknown,
        Self::DefinitionUnsupported,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ForwardOutcomeUnknown => "forward_outcome_unknown",
            Self::CompensationOutcomeUnknown => "compensation_outcome_unknown",
            Self::ReceiptMissing => "receipt_missing",
            Self::ReceiptIntegrity => "receipt_integrity",
            Self::ReceiptFormatUnsupported => "receipt_format_unsupported",
            Self::CompletionCommitUnknown => "completion_commit_unknown",
            Self::DefinitionUnsupported => "definition_unsupported",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "forward_outcome_unknown" => Some(Self::ForwardOutcomeUnknown),
            "compensation_outcome_unknown" => Some(Self::CompensationOutcomeUnknown),
            "receipt_missing" => Some(Self::ReceiptMissing),
            "receipt_integrity" => Some(Self::ReceiptIntegrity),
            "receipt_format_unsupported" => Some(Self::ReceiptFormatUnsupported),
            "completion_commit_unknown" => Some(Self::CompletionCommitUnknown),
            "definition_unsupported" => Some(Self::DefinitionUnsupported),
            _ => None,
        }
    }

    /// Whether entering this operator state must retain the pinned compensation root cause.
    pub const fn preserves_compensation_cause(self) -> bool {
        matches!(self, Self::CompensationOutcomeUnknown)
    }
}

/// Root cause retained while a Saga unwinds completed forward effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaCompensationCause {
    BusinessFailure,
    Expired,
}

impl SagaCompensationCause {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BusinessFailure => "business_failure",
            Self::Expired => "expired",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "business_failure" => Some(Self::BusinessFailure),
            "expired" => Some(Self::Expired),
            _ => None,
        }
    }
}

/// Durable saga instance row visible to tailers/executors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SagaInstanceRecord {
    instance: SagaInstanceRef,
    status: SagaInstanceStatus,
    identity: SagaWorkerIdentity,
    definition: SagaDefinitionIdentity,
    operator_reason: Option<SagaOperatorReason>,
}

/// Invalid durable Saga instance record.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaInstanceRecordError {
    /// Worker contract and pinned definition contract differ.
    #[error("saga worker contract does not match pinned definition")]
    DefinitionContractMismatch,
    /// An operator reason was attached to a non-operator lifecycle state.
    #[error("saga operator reason does not match instance status")]
    OperatorReasonStatusMismatch,
}

impl SagaInstanceRecord {
    /// Build an instance row value.
    pub fn new(
        instance: SagaInstanceRef,
        status: SagaInstanceStatus,
        identity: SagaWorkerIdentity,
        definition: SagaDefinitionIdentity,
    ) -> Result<Self, SagaInstanceRecordError> {
        if identity.contract_id().as_str() != definition.contract_id() {
            return Err(SagaInstanceRecordError::DefinitionContractMismatch);
        }
        Ok(Self {
            instance,
            status,
            identity,
            definition,
            operator_reason: None,
        })
    }

    /// Attach the exact durable reason to an operator-required record.
    pub fn with_operator_reason(
        mut self,
        reason: SagaOperatorReason,
    ) -> Result<Self, SagaInstanceRecordError> {
        if self.status != SagaInstanceStatus::OperatorRequired {
            return Err(SagaInstanceRecordError::OperatorReasonStatusMismatch);
        }
        self.operator_reason = Some(reason);
        Ok(self)
    }

    /// Instance identity.
    pub fn instance(&self) -> SagaInstanceRef {
        self.instance
    }

    /// Current durable instance status.
    pub fn status(&self) -> SagaInstanceStatus {
        self.status
    }

    /// Exact owner + contract identity pinned when the instance was registered.
    pub fn identity(&self) -> &SagaWorkerIdentity {
        &self.identity
    }

    /// Exact definition pinned when the instance was registered.
    pub fn definition(&self) -> &SagaDefinitionIdentity {
        &self.definition
    }

    /// Exact durable intervention reason, present only for `operator_required`.
    pub const fn operator_reason(&self) -> Option<SagaOperatorReason> {
        self.operator_reason
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

/// Non-business interruption reason. These outcomes must not trigger compensation or app DLX.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaInterruption {
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
    /// Durable current state is repairable through the authorized operator workflow.
    OperatorRequired,
    /// Pinned definition identity is not present in the immutable runtime registry.
    UnsupportedDefinition,
    /// Durable recovery requires a receipt that is not yet persisted (#1924).
    ReceiptUnavailable,
}

impl SagaInterruption {
    /// Closed-set diagnostic label for non-business saga interruptions.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::LeaseBusy => "lease_busy",
            Self::LeaseLost => "lease_lost",
            Self::JournalConflict => "journal_conflict",
            Self::StoreUnavailable => "store_unavailable",
            Self::AlreadyStarted => "already_started",
            Self::InstanceDegraded => "instance_degraded",
            Self::OperatorRequired => "operator_required",
            Self::UnsupportedDefinition => "unsupported_definition",
            Self::ReceiptUnavailable => "receipt_unavailable",
        }
    }
}

/// saga durable journal 条目状态。label 与 postgres `saga_journal.status` CHECK 集合同源。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaJournalStatus {
    /// Durable intent recorded before one forward attempt.
    ForwardIntent,
    /// step 前向完成。
    ForwardCompleted,
    /// An authorized, audited operator decision proved the forward effect was not applied.
    ForwardNotApplied,
    /// Durable intent recorded before one compensation attempt.
    CompensationIntent,
    /// step 补偿完成。
    CompensationCompleted,
    /// An authorized, audited operator decision proved compensation was not applied.
    CompensationNotApplied,
    /// step 补偿失败，saga 进入人工介入 / dead-letter 终态。
    CompensationFailed,
}

impl SagaJournalStatus {
    /// 全状态序（drift 测试 / 穷尽枚举用）。
    pub const ALL: [Self; 7] = [
        Self::ForwardIntent,
        Self::ForwardCompleted,
        Self::ForwardNotApplied,
        Self::CompensationIntent,
        Self::CompensationCompleted,
        Self::CompensationNotApplied,
        Self::CompensationFailed,
    ];

    /// wire / DB label（snake_case）。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ForwardIntent => "forward_intent",
            Self::ForwardCompleted => "forward_completed",
            Self::ForwardNotApplied => "forward_not_applied",
            Self::CompensationIntent => "compensation_intent",
            Self::CompensationCompleted => "compensation_completed",
            Self::CompensationNotApplied => "compensation_not_applied",
            Self::CompensationFailed => "compensation_failed",
        }
    }

    /// 从 wire / DB label 解析；未知值返回 `None`，由调用方升为 fail-closed invariant。
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "forward_intent" => Some(Self::ForwardIntent),
            "forward_completed" => Some(Self::ForwardCompleted),
            "forward_not_applied" => Some(Self::ForwardNotApplied),
            "compensation_intent" => Some(Self::CompensationIntent),
            "compensation_completed" => Some(Self::CompensationCompleted),
            "compensation_not_applied" => Some(Self::CompensationNotApplied),
            "compensation_failed" => Some(Self::CompensationFailed),
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

/// 一条从 durable journal read/replay 路径重建的 record。
///
/// Replay records are read-only model values; durable writes flow only through the closed
/// `SagaDurableMutation` command set owned by `diport`.
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
    CompensationFailed { failed_step: StepName },
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
            Self::Succeeded | Self::Compensated | Self::CompensationFailed { .. }
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
    CompensationReady,
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
            (Self::NeverStarted, SagaJournalStatus::ForwardIntent) => Ok(Self::Executing),
            (Self::Executing, SagaJournalStatus::ForwardIntent) => Ok(Self::Executing),
            (Self::Executing, SagaJournalStatus::ForwardCompleted) => Ok(Self::Completed),
            (Self::Executing, SagaJournalStatus::ForwardNotApplied) => Ok(Self::NeverStarted),
            (Self::Executing | Self::Completed, SagaJournalStatus::CompensationIntent) => {
                Ok(Self::Compensating)
            }
            (Self::CompensationReady, SagaJournalStatus::CompensationIntent) => {
                Ok(Self::Compensating)
            }
            (Self::Compensating, SagaJournalStatus::CompensationIntent) => Ok(Self::Compensating),
            (Self::Compensating, SagaJournalStatus::CompensationCompleted) => Ok(Self::Compensated),
            (Self::Compensating, SagaJournalStatus::CompensationNotApplied) => {
                Ok(Self::CompensationReady)
            }
            (Self::Compensating, SagaJournalStatus::CompensationFailed) => Ok(Self::Failed),
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
        SagaJournalStatus::CompensationIntent
            | SagaJournalStatus::CompensationCompleted
            | SagaJournalStatus::CompensationNotApplied
            | SagaJournalStatus::CompensationFailed
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
    if latest.get(idx).is_some_and(|status| {
        matches!(
            *status,
            StepLoadStatus::Executing | StepLoadStatus::CompensationReady
        )
    }) {
        return Some(idx);
    }
    latest
        .iter()
        .enumerate()
        .rev()
        .find(|(_, status)| {
            matches!(
                **status,
                StepLoadStatus::Completed
                    | StepLoadStatus::CompensationReady
                    | StepLoadStatus::Compensating
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
        .find(|(_, status)| {
            matches!(
                **status,
                StepLoadStatus::CompensationReady | StepLoadStatus::Compensating
            )
        })
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
        .is_some_and(|status| {
            matches!(
                *status,
                StepLoadStatus::Executing | StepLoadStatus::CompensationReady
            )
        })
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
                SagaJournalStatus::ForwardIntent
                    | SagaJournalStatus::ForwardCompleted
                    | SagaJournalStatus::ForwardNotApplied
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
            status: SagaDurableStatus::CompensationFailed {
                failed_step: definition.steps[idx].clone(),
            },
        };
    }

    let unwinding = latest.iter().any(|status| {
        matches!(
            status,
            StepLoadStatus::CompensationReady
                | StepLoadStatus::Compensating
                | StepLoadStatus::Compensated
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
                StepLoadStatus::Completed
                    | StepLoadStatus::CompensationReady
                    | StepLoadStatus::Compensating
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

#[cfg(test)]
mod tests {
    use super::{
        SagaContractId, SagaDefinition, SagaDefinitionIdentity, SagaDefinitionIdentityError,
        SagaDurableStatus, SagaId, SagaInstanceRecord, SagaInstanceRecordError, SagaInstanceRef,
        SagaInstanceRefError, SagaInstanceStatus, SagaJournalRecord, SagaJournalStatus, SagaLease,
        SagaLeaseError, SagaModelError, SagaOperatorReason, SagaReplayDecision, SagaWorkerIdentity,
    };
    use vocab::{StepName, TenantId};

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
    fn saga_definition_identity_requires_canonical_positive_version() {
        const DIGEST: &str =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        const GENERATION: &str =
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        assert!(SagaDefinitionIdentity::new("billing.checkout", "v1", DIGEST, GENERATION).is_ok());
        assert!(SagaDefinitionIdentity::new("billing.checkout", "v42", DIGEST, GENERATION).is_ok());
        for version in ["v0", "v00", "v01", "v", "1"] {
            assert_eq!(
                SagaDefinitionIdentity::new("billing.checkout", version, DIGEST, GENERATION),
                Err(SagaDefinitionIdentityError::Version),
                "version {version:?} must be rejected before persistence"
            );
        }
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn saga_instance_record_requires_and_exposes_complete_worker_identity() {
        const DIGEST: &str =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        const GENERATION: &str =
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let tenant = TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap();
        let instance =
            SagaInstanceRef::new(tenant, SagaId::new(uuid::Uuid::from_u128(1923))).unwrap();
        let identity = SagaWorkerIdentity::new(
            "billing",
            SagaContractId::parse("billing.checkout").unwrap(),
        )
        .unwrap();
        let definition =
            SagaDefinitionIdentity::new("billing.checkout", "v1", DIGEST, GENERATION).unwrap();
        let record = SagaInstanceRecord::new(
            instance,
            SagaInstanceStatus::Ready,
            identity.clone(),
            definition,
        )
        .unwrap();
        assert_eq!(record.identity(), &identity);
        assert_eq!(record.operator_reason(), None);

        let wrong_definition =
            SagaDefinitionIdentity::new("billing.refund", "v1", DIGEST, GENERATION).unwrap();
        assert_eq!(
            SagaInstanceRecord::new(
                instance,
                SagaInstanceStatus::Ready,
                identity,
                wrong_definition,
            ),
            Err(SagaInstanceRecordError::DefinitionContractMismatch)
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn operator_reason_is_attached_only_to_operator_required_records() {
        const DIGEST: &str =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        const GENERATION: &str =
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let tenant = TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap();
        let instance =
            SagaInstanceRef::new(tenant, SagaId::new(uuid::Uuid::from_u128(1925))).unwrap();
        let identity = SagaWorkerIdentity::new(
            "billing",
            SagaContractId::parse("billing.checkout").unwrap(),
        )
        .unwrap();
        let definition =
            SagaDefinitionIdentity::new("billing.checkout", "v1", DIGEST, GENERATION).unwrap();

        let operator = SagaInstanceRecord::new(
            instance,
            SagaInstanceStatus::OperatorRequired,
            identity.clone(),
            definition.clone(),
        )
        .unwrap()
        .with_operator_reason(SagaOperatorReason::CompensationOutcomeUnknown)
        .unwrap();
        assert_eq!(
            operator.operator_reason(),
            Some(SagaOperatorReason::CompensationOutcomeUnknown)
        );
        assert!(SagaOperatorReason::CompensationOutcomeUnknown.preserves_compensation_cause());
        assert!(!SagaOperatorReason::ForwardOutcomeUnknown.preserves_compensation_cause());

        assert_eq!(
            SagaInstanceRecord::new(instance, SagaInstanceStatus::Running, identity, definition,)
                .unwrap()
                .with_operator_reason(SagaOperatorReason::ForwardOutcomeUnknown),
            Err(SagaInstanceRecordError::OperatorReasonStatusMismatch)
        );
    }

    #[test]
    fn saga_journal_status_labels_round_trip_and_are_closed() {
        let expected = [
            (SagaJournalStatus::ForwardIntent, "forward_intent"),
            (SagaJournalStatus::ForwardCompleted, "forward_completed"),
            (SagaJournalStatus::ForwardNotApplied, "forward_not_applied"),
            (SagaJournalStatus::CompensationIntent, "compensation_intent"),
            (
                SagaJournalStatus::CompensationCompleted,
                "compensation_completed",
            ),
            (
                SagaJournalStatus::CompensationNotApplied,
                "compensation_not_applied",
            ),
            (SagaJournalStatus::CompensationFailed, "compensation_failed"),
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
            SagaJournalRecord::replayed(0, step("step1"), SagaJournalStatus::ForwardIntent),
            SagaJournalRecord::replayed(1, step("step1"), SagaJournalStatus::ForwardCompleted),
            SagaJournalRecord::replayed(2, step("step2"), SagaJournalStatus::ForwardIntent),
            SagaJournalRecord::replayed(3, step("step2"), SagaJournalStatus::ForwardCompleted),
            SagaJournalRecord::replayed(4, step("step2"), SagaJournalStatus::CompensationIntent),
        ];
        assert_eq!(
            def.replay(&records),
            Ok(SagaReplayDecision::Compensating {
                next_seq: 5,
                pending: vec![(1, step("step2")), (0, step("step1"))],
                failed_step: None,
            })
        );
    }

    #[test]
    fn saga_replay_rejects_completion_without_phase_intent() {
        let def = definition(&["step1"]);
        assert_eq!(
            def.replay(&[SagaJournalRecord::replayed(
                0,
                step("step1"),
                SagaJournalStatus::ForwardCompleted,
            )]),
            Err(SagaModelError::IllegalTransition {
                step_name: step("step1"),
                status: SagaJournalStatus::ForwardCompleted,
            })
        );

        assert_eq!(
            def.replay(&[SagaJournalRecord::replayed(
                0,
                step("step1"),
                SagaJournalStatus::ForwardNotApplied,
            )]),
            Err(SagaModelError::IllegalTransition {
                step_name: step("step1"),
                status: SagaJournalStatus::ForwardNotApplied,
            })
        );

        for terminal in [
            SagaJournalStatus::CompensationCompleted,
            SagaJournalStatus::CompensationNotApplied,
            SagaJournalStatus::CompensationFailed,
        ] {
            assert_eq!(
                def.replay(&[
                    SagaJournalRecord::replayed(
                        0,
                        step("step1"),
                        SagaJournalStatus::ForwardIntent,
                    ),
                    SagaJournalRecord::replayed(
                        1,
                        step("step1"),
                        SagaJournalStatus::ForwardCompleted,
                    ),
                    SagaJournalRecord::replayed(2, step("step1"), terminal),
                ]),
                Err(SagaModelError::IllegalTransition {
                    step_name: step("step1"),
                    status: terminal,
                })
            );
        }
    }

    #[test]
    fn replay_operator_forward_not_applied_reopens_the_exact_step() {
        let def = definition(&["step1", "step2"]);
        let records = vec![
            SagaJournalRecord::replayed(0, step("step1"), SagaJournalStatus::ForwardIntent),
            SagaJournalRecord::replayed(1, step("step1"), SagaJournalStatus::ForwardNotApplied),
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
    fn replay_operator_compensation_not_applied_resumes_same_reverse_step() {
        let def = definition(&["step1"]);
        let mut records = vec![
            SagaJournalRecord::replayed(0, step("step1"), SagaJournalStatus::ForwardIntent),
            SagaJournalRecord::replayed(1, step("step1"), SagaJournalStatus::ForwardCompleted),
            SagaJournalRecord::replayed(2, step("step1"), SagaJournalStatus::CompensationIntent),
            SagaJournalRecord::replayed(
                3,
                step("step1"),
                SagaJournalStatus::CompensationNotApplied,
            ),
        ];

        assert_eq!(
            def.replay(&records),
            Ok(SagaReplayDecision::Compensating {
                next_seq: 4,
                pending: vec![(0, step("step1"))],
                failed_step: None,
            })
        );

        records.push(SagaJournalRecord::replayed(
            4,
            step("step1"),
            SagaJournalStatus::CompensationIntent,
        ));
        assert_eq!(
            def.replay(&records),
            Ok(SagaReplayDecision::Compensating {
                next_seq: 5,
                pending: vec![(0, step("step1"))],
                failed_step: None,
            })
        );
    }

    #[test]
    fn replay_completed_prefix_runs_forward_from_next_step() {
        let def = definition(&["step1", "step2", "step3"]);
        let records = vec![
            SagaJournalRecord::replayed(0, step("step1"), SagaJournalStatus::ForwardIntent),
            SagaJournalRecord::replayed(1, step("step1"), SagaJournalStatus::ForwardCompleted),
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
            SagaJournalRecord::replayed(0, step("step1"), SagaJournalStatus::ForwardIntent),
            SagaJournalRecord::replayed(1, step("step1"), SagaJournalStatus::ForwardCompleted),
            SagaJournalRecord::replayed(2, step("step2"), SagaJournalStatus::ForwardIntent),
            SagaJournalRecord::replayed(3, step("step2"), SagaJournalStatus::ForwardCompleted),
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
            SagaJournalRecord::replayed(0, step("step1"), SagaJournalStatus::ForwardIntent),
            SagaJournalRecord::replayed(1, step("step1"), SagaJournalStatus::ForwardCompleted),
            SagaJournalRecord::replayed(2, step("step2"), SagaJournalStatus::ForwardIntent),
            SagaJournalRecord::replayed(3, step("step2"), SagaJournalStatus::ForwardCompleted),
            SagaJournalRecord::replayed(4, step("step2"), SagaJournalStatus::CompensationIntent),
        ];

        assert_eq!(
            def.replay(&records),
            Ok(SagaReplayDecision::Compensating {
                next_seq: 5,
                pending: vec![(1, step("step2")), (0, step("step1"))],
                failed_step: None,
            })
        );
    }

    #[test]
    fn replay_compensates_post_effect_failure_intent_for_executing_step() {
        let def = definition(&["step1"]);
        let records = vec![
            SagaJournalRecord::replayed(0, step("step1"), SagaJournalStatus::ForwardIntent),
            SagaJournalRecord::replayed(1, step("step1"), SagaJournalStatus::CompensationIntent),
        ];

        assert_eq!(
            def.replay(&records),
            Ok(SagaReplayDecision::Compensating {
                next_seq: 2,
                pending: vec![(0, step("step1"))],
                failed_step: Some(step("step1")),
            })
        );
    }

    #[test]
    fn replay_treats_repeated_executing_as_idempotent_retry_intent() {
        let def = definition(&["step1", "step2"]);
        let records = vec![
            SagaJournalRecord::replayed(0, step("step1"), SagaJournalStatus::ForwardIntent),
            SagaJournalRecord::replayed(1, step("step1"), SagaJournalStatus::ForwardIntent),
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
            SagaJournalRecord::replayed(0, step("step1"), SagaJournalStatus::ForwardIntent),
            SagaJournalRecord::replayed(1, step("step1"), SagaJournalStatus::ForwardCompleted),
            SagaJournalRecord::replayed(2, step("step2"), SagaJournalStatus::ForwardIntent),
            SagaJournalRecord::replayed(3, step("step2"), SagaJournalStatus::ForwardCompleted),
            SagaJournalRecord::replayed(4, step("step2"), SagaJournalStatus::CompensationIntent),
            SagaJournalRecord::replayed(5, step("step2"), SagaJournalStatus::CompensationCompleted),
            SagaJournalRecord::replayed(6, step("step1"), SagaJournalStatus::CompensationIntent),
            SagaJournalRecord::replayed(7, step("step1"), SagaJournalStatus::CompensationCompleted),
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
            SagaJournalRecord::replayed(0, step("step1"), SagaJournalStatus::ForwardIntent),
            SagaJournalRecord::replayed(1, step("step1"), SagaJournalStatus::ForwardCompleted),
            SagaJournalRecord::replayed(2, step("step2"), SagaJournalStatus::ForwardIntent),
            SagaJournalRecord::replayed(3, step("step1"), SagaJournalStatus::CompensationIntent),
            SagaJournalRecord::replayed(4, step("step1"), SagaJournalStatus::CompensationCompleted),
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
            SagaJournalRecord::replayed(0, step("step1"), SagaJournalStatus::ForwardIntent),
            SagaJournalRecord::replayed(1, step("step1"), SagaJournalStatus::ForwardCompleted),
            SagaJournalRecord::replayed(2, step("step2"), SagaJournalStatus::ForwardIntent),
            SagaJournalRecord::replayed(3, step("step1"), SagaJournalStatus::CompensationIntent),
            SagaJournalRecord::replayed(4, step("step1"), SagaJournalStatus::CompensationIntent),
        ];

        assert_eq!(
            def.replay(&records),
            Ok(SagaReplayDecision::Compensating {
                next_seq: 5,
                pending: vec![(0, step("step1"))],
                failed_step: Some(step("step2")),
            })
        );
    }

    #[test]
    fn replay_allows_executing_step_to_compensate_when_completed_append_was_lost() {
        let def = definition(&["step1"]);
        let records = vec![
            SagaJournalRecord::replayed(0, step("step1"), SagaJournalStatus::ForwardIntent),
            SagaJournalRecord::replayed(1, step("step1"), SagaJournalStatus::CompensationIntent),
            SagaJournalRecord::replayed(2, step("step1"), SagaJournalStatus::CompensationCompleted),
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
            SagaJournalRecord::replayed(0, step("step1"), SagaJournalStatus::ForwardIntent),
            SagaJournalRecord::replayed(1, step("step1"), SagaJournalStatus::ForwardCompleted),
            SagaJournalRecord::replayed(2, step("step1"), SagaJournalStatus::CompensationIntent),
            SagaJournalRecord::replayed(3, step("step1"), SagaJournalStatus::CompensationFailed),
        ];

        assert_eq!(
            def.replay(&records),
            Ok(SagaReplayDecision::Terminal {
                status: SagaDurableStatus::CompensationFailed {
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
            SagaDurableStatus::CompensationFailed {
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
                SagaJournalStatus::ForwardCompleted
            )]),
            Err(SagaModelError::UnknownStep {
                step_name: step("ghost")
            })
        );
        assert_eq!(
            def.replay(&[
                SagaJournalRecord::replayed(0, step("step1"), SagaJournalStatus::ForwardIntent),
                SagaJournalRecord::replayed(0, step("step1"), SagaJournalStatus::ForwardCompleted),
            ]),
            Err(SagaModelError::DuplicateSeq { seq: 0 })
        );
        assert_eq!(
            def.replay(&[
                SagaJournalRecord::replayed(0, step("step2"), SagaJournalStatus::ForwardIntent),
                SagaJournalRecord::replayed(1, step("step2"), SagaJournalStatus::ForwardCompleted,),
            ]),
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
                SagaJournalRecord::replayed(0, step("step1"), SagaJournalStatus::ForwardIntent),
                SagaJournalRecord::replayed(1, step("step1"), SagaJournalStatus::ForwardCompleted),
                SagaJournalRecord::replayed(2, step("step1"), SagaJournalStatus::ForwardIntent),
            ]),
            Err(SagaModelError::IllegalTransition {
                step_name: step("step1"),
                status: SagaJournalStatus::ForwardIntent
            })
        );
        assert_eq!(
            def.replay(&[
                SagaJournalRecord::replayed(0, step("step1"), SagaJournalStatus::ForwardIntent),
                SagaJournalRecord::replayed(1, step("step1"), SagaJournalStatus::ForwardCompleted),
                SagaJournalRecord::replayed(2, step("step2"), SagaJournalStatus::ForwardIntent),
                SagaJournalRecord::replayed(
                    3,
                    step("step1"),
                    SagaJournalStatus::CompensationIntent
                ),
                SagaJournalRecord::replayed(4, step("step2"), SagaJournalStatus::ForwardCompleted),
            ]),
            Err(SagaModelError::IllegalTransition {
                step_name: step("step2"),
                status: SagaJournalStatus::ForwardCompleted
            })
        );
        assert_eq!(
            def.replay(&[
                SagaJournalRecord::replayed(0, step("step1"), SagaJournalStatus::ForwardIntent),
                SagaJournalRecord::replayed(1, step("step1"), SagaJournalStatus::ForwardCompleted),
                SagaJournalRecord::replayed(
                    2,
                    step("step1"),
                    SagaJournalStatus::CompensationIntent
                ),
                SagaJournalRecord::replayed(
                    3,
                    step("step1"),
                    SagaJournalStatus::CompensationFailed
                ),
                SagaJournalRecord::replayed(
                    4,
                    step("step1"),
                    SagaJournalStatus::CompensationIntent
                ),
            ]),
            Err(SagaModelError::IllegalTransition {
                step_name: step("step1"),
                status: SagaJournalStatus::CompensationIntent
            })
        );
        assert_eq!(
            def.replay(&[SagaJournalRecord::replayed(
                0,
                step("step1"),
                SagaJournalStatus::CompensationFailed
            )]),
            Err(SagaModelError::IllegalTransition {
                step_name: step("step1"),
                status: SagaJournalStatus::CompensationFailed
            })
        );
        assert_eq!(
            def.replay(&[
                SagaJournalRecord::replayed(0, step("step1"), SagaJournalStatus::ForwardIntent),
                SagaJournalRecord::replayed(1, step("step1"), SagaJournalStatus::ForwardCompleted),
                SagaJournalRecord::replayed(2, step("step2"), SagaJournalStatus::ForwardIntent),
                SagaJournalRecord::replayed(3, step("step2"), SagaJournalStatus::ForwardCompleted),
                SagaJournalRecord::replayed(
                    4,
                    step("step1"),
                    SagaJournalStatus::CompensationIntent
                ),
            ]),
            Err(SagaModelError::IllegalTransition {
                step_name: step("step1"),
                status: SagaJournalStatus::CompensationIntent
            })
        );
        assert_eq!(
            def.replay(&[
                SagaJournalRecord::replayed(0, step("step1"), SagaJournalStatus::ForwardIntent),
                SagaJournalRecord::replayed(1, step("step1"), SagaJournalStatus::ForwardCompleted),
                SagaJournalRecord::replayed(2, step("step2"), SagaJournalStatus::ForwardIntent),
                SagaJournalRecord::replayed(
                    3,
                    step("step1"),
                    SagaJournalStatus::CompensationIntent
                ),
                SagaJournalRecord::replayed(
                    4,
                    step("step2"),
                    SagaJournalStatus::CompensationIntent
                ),
            ]),
            Err(SagaModelError::IllegalTransition {
                step_name: step("step2"),
                status: SagaJournalStatus::CompensationIntent
            })
        );
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
