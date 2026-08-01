//! Closed durable Saga storage boundary.
//!
//! Instance state, leases, journal intents/completions and protected receipts intentionally share
//! one writer port. This keeps every externally visible Saga transition in one fenced local
//! transaction and prevents callers from composing a receipt, journal row and lifecycle status
//! through independently fallible stores.

use std::collections::HashSet;
use std::num::{NonZeroU64, NonZeroUsize};
use std::time::Duration;

use dynosaur::dynosaur;

use consistency::{
    SagaAttempt, SagaCompensationCause, SagaDefinitionIdentity, SagaEffectPhase,
    SagaIdempotencyKey, SagaInstanceRecord, SagaInstanceRef, SagaInstanceStatus, SagaJournalRecord,
    SagaLease, SagaLeaseOutcome, SagaOperatorReason, SagaReceiptFormatVersion, SagaReceiptScope,
};
pub use consistency::{
    SagaContractId, SagaContractIdError, SagaWorkerIdentity, SagaWorkerIdentityError,
};
use secure::Plaintext;
use vocab::StepName;

use crate::RedactedSource;

/// Stable, safe classification for all durable Saga storage failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaDurableStoreErrorKind {
    /// An existing instance is pinned to another owner or definition.
    IdentityConflict,
    /// Encryption, decryption or keyed-fingerprint processing failed.
    Protection,
    /// The storage operation failed before commit was attempted.
    Storage,
    /// The server may have committed, but no definitive acknowledgement was received.
    CommitUnknown,
    /// Durable metadata, journal/receipt pairing or lifecycle state is invalid.
    Integrity,
    /// A durable receipt format is not supported by this binary.
    UnsupportedFormat,
}

/// Redacted durable Saga storage error.
#[derive(Debug, thiserror::Error)]
#[error("saga durable store operation failed")]
pub struct SagaDurableStoreError {
    kind: SagaDurableStoreErrorKind,
    #[source]
    source: RedactedSource,
}

impl SagaDurableStoreError {
    /// Wrap an adapter error without exposing its source through `Display` or `Debug`.
    pub fn new<E>(kind: SagaDurableStoreErrorKind, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            kind,
            source: RedactedSource::new(source),
        }
    }

    /// Safe in-process failure classification.
    pub const fn kind(&self) -> SagaDurableStoreErrorKind {
        self.kind
    }
}

/// Registration request for a durable Saga instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SagaInstanceRegistration {
    instance: SagaInstanceRef,
    identity: SagaWorkerIdentity,
    definition: SagaDefinitionIdentity,
}

/// Invalid Saga instance registration.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaInstanceRegistrationError {
    /// Worker contract and pinned definition contract differ.
    #[error("saga worker contract does not match pinned definition")]
    DefinitionContractMismatch,
}

impl SagaInstanceRegistration {
    /// Build a registration request whose worker and definition identity agree.
    pub fn new(
        instance: SagaInstanceRef,
        identity: SagaWorkerIdentity,
        definition: SagaDefinitionIdentity,
    ) -> Result<Self, SagaInstanceRegistrationError> {
        if identity.contract_id().as_str() != definition.contract_id() {
            return Err(SagaInstanceRegistrationError::DefinitionContractMismatch);
        }
        Ok(Self {
            instance,
            identity,
            definition,
        })
    }

    pub const fn instance(&self) -> SagaInstanceRef {
        self.instance
    }

    pub const fn identity(&self) -> &SagaWorkerIdentity {
        &self.identity
    }

    pub fn owner(&self) -> &str {
        self.identity.owner()
    }

    pub fn contract_id(&self) -> &str {
        self.identity.contract_id().as_str()
    }

    pub const fn definition(&self) -> &SagaDefinitionIdentity {
        &self.definition
    }
}

/// Exact runnable instance observed by worker discovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SagaRunnableInstance {
    instance: SagaInstanceRef,
    status: SagaInstanceStatus,
    identity: SagaWorkerIdentity,
    definition: SagaDefinitionIdentity,
}

/// Invalid runnable Saga instance.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaRunnableInstanceError {
    #[error("saga instance status is not runnable")]
    NotRunnable,
    #[error("saga worker contract does not match pinned definition")]
    DefinitionContractMismatch,
}

impl SagaRunnableInstance {
    pub fn new(
        instance: SagaInstanceRef,
        status: SagaInstanceStatus,
        identity: SagaWorkerIdentity,
        definition: SagaDefinitionIdentity,
    ) -> Result<Self, SagaRunnableInstanceError> {
        if !matches!(
            status,
            SagaInstanceStatus::Ready
                | SagaInstanceStatus::Running
                | SagaInstanceStatus::Compensating
        ) {
            return Err(SagaRunnableInstanceError::NotRunnable);
        }
        if identity.contract_id().as_str() != definition.contract_id() {
            return Err(SagaRunnableInstanceError::DefinitionContractMismatch);
        }
        Ok(Self {
            instance,
            status,
            identity,
            definition,
        })
    }

    pub const fn instance(&self) -> SagaInstanceRef {
        self.instance
    }

    pub const fn status(&self) -> SagaInstanceStatus {
        self.status
    }

    pub const fn identity(&self) -> &SagaWorkerIdentity {
        &self.identity
    }

    pub const fn definition(&self) -> &SagaDefinitionIdentity {
        &self.definition
    }
}

/// Exact claim request built from one advisory discovery result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SagaClaimRequest {
    expected: SagaRunnableInstance,
    holder: SagaLeaseHolder,
    ttl: SagaLeaseTtl,
}

/// Canonical lease holder identity shared by every Saga provider.
#[derive(Clone, PartialEq, Eq)]
pub struct SagaLeaseHolder(String);

impl std::fmt::Debug for SagaLeaseHolder {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SagaLeaseHolder(<redacted>)")
    }
}

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaLeaseHolderError {
    #[error("saga lease holder is invalid")]
    Invalid,
}

impl SagaLeaseHolder {
    pub fn parse(raw: impl Into<String>) -> Result<Self, SagaLeaseHolderError> {
        let value = raw.into();
        if value.is_empty()
            || value.len() > 128
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(SagaLeaseHolderError::Invalid);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Positive microsecond-exact lease TTL representable by PostgreSQL without truncation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SagaLeaseTtl(NonZeroU64);

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaLeaseTtlError {
    #[error("saga lease ttl must be positive")]
    Zero,
    #[error("saga lease ttl must have microsecond precision")]
    Submicrosecond,
    #[error("saga lease ttl exceeds the durable provider range")]
    Overflow,
}

impl SagaLeaseTtl {
    pub fn new(ttl: Duration) -> Result<Self, SagaLeaseTtlError> {
        if ttl.is_zero() {
            return Err(SagaLeaseTtlError::Zero);
        }
        if !ttl.subsec_nanos().is_multiple_of(1_000) {
            return Err(SagaLeaseTtlError::Submicrosecond);
        }
        let micros = u64::try_from(ttl.as_micros()).map_err(|_| SagaLeaseTtlError::Overflow)?;
        if micros > i64::MAX as u64 {
            return Err(SagaLeaseTtlError::Overflow);
        }
        NonZeroU64::new(micros)
            .map(Self)
            .ok_or(SagaLeaseTtlError::Zero)
    }

    pub const fn as_micros(self) -> u64 {
        self.0.get()
    }

    pub const fn as_duration(self) -> Duration {
        Duration::from_micros(self.as_micros())
    }
}

impl SagaClaimRequest {
    pub fn new(expected: SagaRunnableInstance, holder: SagaLeaseHolder, ttl: SagaLeaseTtl) -> Self {
        Self {
            expected,
            holder,
            ttl,
        }
    }

    pub const fn expected(&self) -> &SagaRunnableInstance {
        &self.expected
    }

    pub fn holder_id(&self) -> &str {
        self.holder.as_str()
    }

    pub const fn ttl(&self) -> SagaLeaseTtl {
        self.ttl
    }
}

/// Closed result of an exact Saga claim CAS.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaClaimOutcome {
    Acquired(SagaLease),
    Busy,
    Missing,
    IdentityConflict,
    Stale(SagaInstanceStatus),
    Terminal(SagaInstanceStatus),
    OperatorRequired(SagaOperatorReason),
    Degraded,
}

/// One exact receipt plus the matching `forward_completed` journal sequence.
pub struct SagaStepCompletion {
    scope: SagaReceiptScope,
    attempt: SagaAttempt,
    format: SagaReceiptFormatVersion,
    plaintext: Plaintext,
    completed_seq: u64,
}

impl std::fmt::Debug for SagaStepCompletion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SagaStepCompletion(<redacted>)")
    }
}

impl SagaStepCompletion {
    pub fn new(
        scope: SagaReceiptScope,
        attempt: SagaAttempt,
        format: SagaReceiptFormatVersion,
        plaintext: Plaintext,
        completed_seq: u64,
    ) -> Self {
        Self {
            scope,
            attempt,
            format,
            plaintext,
            completed_seq,
        }
    }

    pub const fn scope(&self) -> &SagaReceiptScope {
        &self.scope
    }

    pub const fn attempt(&self) -> SagaAttempt {
        self.attempt
    }

    pub const fn format(&self) -> SagaReceiptFormatVersion {
        self.format
    }

    pub const fn completed_seq(&self) -> u64 {
        self.completed_seq
    }

    pub const fn plaintext(&self) -> &Plaintext {
        &self.plaintext
    }

    pub fn into_parts(
        self,
    ) -> (
        SagaReceiptScope,
        SagaAttempt,
        SagaReceiptFormatVersion,
        Plaintext,
        u64,
    ) {
        (
            self.scope,
            self.attempt,
            self.format,
            self.plaintext,
            self.completed_seq,
        )
    }
}

/// Provider-verified exact durable receipt.
pub struct StoredSagaReceipt {
    scope: SagaReceiptScope,
    attempt: SagaAttempt,
    format: SagaReceiptFormatVersion,
    plaintext: Plaintext,
    completed_seq: u64,
}

impl std::fmt::Debug for StoredSagaReceipt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("StoredSagaReceipt(<redacted>)")
    }
}

impl StoredSagaReceipt {
    pub fn new(
        scope: SagaReceiptScope,
        attempt: SagaAttempt,
        format: SagaReceiptFormatVersion,
        plaintext: Plaintext,
        completed_seq: u64,
    ) -> Self {
        Self {
            scope,
            attempt,
            format,
            plaintext,
            completed_seq,
        }
    }

    pub const fn scope(&self) -> &SagaReceiptScope {
        &self.scope
    }

    pub const fn attempt(&self) -> SagaAttempt {
        self.attempt
    }

    pub const fn format(&self) -> SagaReceiptFormatVersion {
        self.format
    }

    pub const fn completed_seq(&self) -> u64 {
        self.completed_seq
    }

    pub const fn plaintext(&self) -> &Plaintext {
        &self.plaintext
    }

    pub fn into_plaintext(self) -> Plaintext {
        self.plaintext
    }
}

/// Fenced request for one authoritative recovery view.
#[derive(Debug)]
pub struct SagaRecoveryRequest {
    lease: SagaLease,
    receipt_scopes: Vec<SagaReceiptScope>,
}

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaRecoveryRequestError {
    #[error("saga recovery receipt belongs to another instance")]
    ScopeInstanceMismatch,
    #[error("saga recovery receipt scope is duplicated")]
    DuplicateScope,
}

impl SagaRecoveryRequest {
    pub fn new(
        lease: SagaLease,
        receipt_scopes: Vec<SagaReceiptScope>,
    ) -> Result<Self, SagaRecoveryRequestError> {
        let mut unique = HashSet::with_capacity(receipt_scopes.len());
        for scope in &receipt_scopes {
            if scope.instance() != lease.instance() {
                return Err(SagaRecoveryRequestError::ScopeInstanceMismatch);
            }
            if !unique.insert(scope.clone()) {
                return Err(SagaRecoveryRequestError::DuplicateScope);
            }
        }
        Ok(Self {
            lease,
            receipt_scopes,
        })
    }

    pub const fn lease(&self) -> &SagaLease {
        &self.lease
    }

    pub fn receipt_scopes(&self) -> &[SagaReceiptScope] {
        &self.receipt_scopes
    }

    pub fn into_parts(self) -> (SagaLease, Vec<SagaReceiptScope>) {
        (self.lease, self.receipt_scopes)
    }
}

/// Authoritative instance, journal and verified receipt view from one storage snapshot.
#[derive(Debug)]
pub struct SagaRecoverySnapshot {
    instance: SagaInstanceRecord,
    journal: Vec<SagaJournalRecord>,
    receipts: Vec<StoredSagaReceipt>,
    operator_reason: Option<SagaOperatorReason>,
    compensation_cause: Option<SagaCompensationCause>,
}

impl SagaRecoverySnapshot {
    pub fn new(
        instance: SagaInstanceRecord,
        journal: Vec<SagaJournalRecord>,
        receipts: Vec<StoredSagaReceipt>,
        operator_reason: Option<SagaOperatorReason>,
        compensation_cause: Option<SagaCompensationCause>,
    ) -> Self {
        Self {
            instance,
            journal,
            receipts,
            operator_reason,
            compensation_cause,
        }
    }

    pub const fn instance(&self) -> &SagaInstanceRecord {
        &self.instance
    }

    pub fn journal(&self) -> &[SagaJournalRecord] {
        &self.journal
    }

    pub fn receipts(&self) -> &[StoredSagaReceipt] {
        &self.receipts
    }

    pub const fn operator_reason(&self) -> Option<SagaOperatorReason> {
        self.operator_reason
    }

    pub const fn compensation_cause(&self) -> Option<SagaCompensationCause> {
        self.compensation_cause
    }

    pub fn into_parts(
        self,
    ) -> (
        SagaInstanceRecord,
        Vec<SagaJournalRecord>,
        Vec<StoredSagaReceipt>,
        Option<SagaOperatorReason>,
        Option<SagaCompensationCause>,
    ) {
        (
            self.instance,
            self.journal,
            self.receipts,
            self.operator_reason,
            self.compensation_cause,
        )
    }
}

#[derive(Debug)]
#[non_exhaustive]
#[allow(clippy::large_enum_variant)]
// The available snapshot is intentionally returned by value as one coherent recovery view;
// boxing it would introduce an allocation into every durable recovery without shrinking the
// dominant receipt payloads held by that snapshot.
pub enum SagaRecoveryOutcome {
    Available(SagaRecoverySnapshot),
    LeaseLost,
}

/// Lease-independent request for the immutable final receipt of a succeeded Saga.
#[derive(Debug)]
pub struct SagaTerminalReceiptRequest {
    scope: SagaReceiptScope,
}

impl SagaTerminalReceiptRequest {
    pub fn new(scope: SagaReceiptScope) -> Self {
        Self { scope }
    }

    pub const fn scope(&self) -> &SagaReceiptScope {
        &self.scope
    }

    pub fn into_scope(self) -> SagaReceiptScope {
        self.scope
    }
}

/// Store-verified terminal aggregate proof. Construction is adapter-only.
#[derive(Debug)]
pub struct SagaVerifiedTerminalReceipt {
    instance: SagaInstanceRecord,
    journal: Vec<SagaJournalRecord>,
    receipt: StoredSagaReceipt,
}

impl SagaVerifiedTerminalReceipt {
    pub fn new(
        instance: SagaInstanceRecord,
        journal: Vec<SagaJournalRecord>,
        receipt: StoredSagaReceipt,
    ) -> Self {
        Self {
            instance,
            journal,
            receipt,
        }
    }

    pub const fn instance(&self) -> &SagaInstanceRecord {
        &self.instance
    }

    pub fn journal(&self) -> &[SagaJournalRecord] {
        &self.journal
    }

    pub const fn receipt(&self) -> &StoredSagaReceipt {
        &self.receipt
    }

    pub fn into_receipt(self) -> StoredSagaReceipt {
        self.receipt
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum SagaTerminalReceiptOutcome {
    Verified(Box<SagaVerifiedTerminalReceipt>),
    Missing,
    NotSucceeded(SagaInstanceStatus),
}

/// Durable identity of the start-audit record that precedes an operator action.
#[derive(Clone, PartialEq, Eq)]
pub struct SagaOperatorStartAuditId(String);

impl std::fmt::Debug for SagaOperatorStartAuditId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SagaOperatorStartAuditId(<redacted>)")
    }
}

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaOperatorStartAuditIdError {
    #[error("saga operator start audit id is invalid")]
    Invalid,
}

impl SagaOperatorStartAuditId {
    pub fn parse(raw: impl Into<String>) -> Result<Self, SagaOperatorStartAuditIdError> {
        let value = raw.into();
        if value.is_empty()
            || value.len() > 128
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(SagaOperatorStartAuditIdError::Invalid);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Target-bound proof for one authorized operator inspection.
///
/// This value deliberately is not `Clone`. Production issuance requires the crate-graph-gated
/// [`authmint::SagaOperatorMint`] capability after authentication, tenant authorization and the
/// start-audit append have succeeded.
#[derive(Debug)]
pub struct SagaOperatorInspectionAuthorization {
    caller: vocab::ServiceCallerDomain,
    identity: SagaWorkerIdentity,
    tenant: vocab::TenantId,
    start_audit_id: SagaOperatorStartAuditId,
}

impl SagaOperatorInspectionAuthorization {
    pub fn issue(
        _mint: authmint::SagaOperatorMint,
        caller: vocab::ServiceCallerDomain,
        identity: SagaWorkerIdentity,
        tenant: vocab::TenantId,
        start_audit_id: SagaOperatorStartAuditId,
    ) -> Self {
        Self {
            caller,
            identity,
            tenant,
            start_audit_id,
        }
    }

    pub const fn caller(&self) -> vocab::ServiceCallerDomain {
        self.caller
    }
    pub const fn identity(&self) -> &SagaWorkerIdentity {
        &self.identity
    }
    pub const fn tenant(&self) -> vocab::TenantId {
        self.tenant
    }
    pub const fn start_audit_id(&self) -> &SagaOperatorStartAuditId {
        &self.start_audit_id
    }
}

/// Reviewed change-ticket identity persisted with every operator decision.
#[derive(Clone, PartialEq, Eq)]
pub struct SagaOperatorChangeTicket(String);

impl std::fmt::Debug for SagaOperatorChangeTicket {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SagaOperatorChangeTicket(<redacted>)")
    }
}

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaOperatorChangeTicketError {
    #[error("saga operator change ticket is invalid")]
    Invalid,
}

impl SagaOperatorChangeTicket {
    pub fn parse(raw: impl Into<String>) -> Result<Self, SagaOperatorChangeTicketError> {
        let value = raw.into();
        if value.is_empty()
            || value.len() > 128
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(SagaOperatorChangeTicketError::Invalid);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Target-bound proof for one authorized operator repair.
///
/// The target, expected reason and audit attribution travel as one move-only value, so a caller
/// cannot pair authorization for one Saga with a different claim request.
#[derive(Debug)]
pub struct SagaOperatorRepairAuthorization {
    caller: vocab::ServiceCallerDomain,
    identity: SagaWorkerIdentity,
    instance: SagaInstanceRef,
    expected_reason: SagaOperatorReason,
    change_ticket: SagaOperatorChangeTicket,
    start_audit_id: SagaOperatorStartAuditId,
}

impl SagaOperatorRepairAuthorization {
    pub fn issue(
        _mint: authmint::SagaOperatorMint,
        caller: vocab::ServiceCallerDomain,
        identity: SagaWorkerIdentity,
        instance: SagaInstanceRef,
        expected_reason: SagaOperatorReason,
        change_ticket: SagaOperatorChangeTicket,
        start_audit_id: SagaOperatorStartAuditId,
    ) -> Self {
        Self {
            caller,
            identity,
            instance,
            expected_reason,
            change_ticket,
            start_audit_id,
        }
    }

    pub const fn caller(&self) -> vocab::ServiceCallerDomain {
        self.caller
    }
    pub const fn identity(&self) -> &SagaWorkerIdentity {
        &self.identity
    }
    pub const fn instance(&self) -> SagaInstanceRef {
        self.instance
    }
    pub const fn expected_reason(&self) -> SagaOperatorReason {
        self.expected_reason
    }
    pub const fn change_ticket(&self) -> &SagaOperatorChangeTicket {
        &self.change_ticket
    }
    pub const fn start_audit_id(&self) -> &SagaOperatorStartAuditId {
        &self.start_audit_id
    }
}

/// Read-only metadata exposed by a provider-owned, move-only operator claim.
pub trait SagaOperatorClaim: Send + Sync {
    fn instance(&self) -> SagaInstanceRef;
    fn expected_reason(&self) -> SagaOperatorReason;
}

#[derive(Debug)]
#[non_exhaustive]
pub enum SagaOperatorClaimOutcome<C> {
    Acquired(C),
    Busy,
    Missing,
    StaleStatus(SagaInstanceStatus),
    StaleReason(SagaOperatorReason),
}

/// One operator-required Saga visible through the authorized inspection surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SagaOperatorRequiredInstance {
    record: SagaInstanceRecord,
    reason: SagaOperatorReason,
}

impl SagaOperatorRequiredInstance {
    pub fn new(record: SagaInstanceRecord, reason: SagaOperatorReason) -> Self {
        Self { record, reason }
    }

    pub const fn record(&self) -> &SagaInstanceRecord {
        &self.record
    }
    pub const fn reason(&self) -> SagaOperatorReason {
        self.reason
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaForwardProgress {
    Continue,
    Succeeded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaCompensationProgress {
    Continue,
    Compensated,
    Expired,
}

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaDurableMutationError {
    #[error("saga effect key phase does not match durable transition")]
    EffectPhaseMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SagaForwardIntent {
    seq: u64,
    step: StepName,
    attempt: SagaAttempt,
    effect_key: SagaIdempotencyKey,
}

impl SagaForwardIntent {
    pub fn new(
        seq: u64,
        step: StepName,
        attempt: SagaAttempt,
        effect_key: SagaIdempotencyKey,
    ) -> Result<Self, SagaDurableMutationError> {
        if effect_key.phase() != SagaEffectPhase::Forward {
            return Err(SagaDurableMutationError::EffectPhaseMismatch);
        }
        Ok(Self {
            seq,
            step,
            attempt,
            effect_key,
        })
    }

    pub const fn seq(&self) -> u64 {
        self.seq
    }
    pub const fn step(&self) -> &StepName {
        &self.step
    }
    pub const fn attempt(&self) -> SagaAttempt {
        self.attempt
    }
    pub const fn effect_key(&self) -> &SagaIdempotencyKey {
        &self.effect_key
    }
}

#[derive(Debug)]
pub struct SagaForwardCompletion {
    completion: SagaStepCompletion,
    progress: SagaForwardProgress,
}

impl SagaForwardCompletion {
    pub fn new(completion: SagaStepCompletion, progress: SagaForwardProgress) -> Self {
        Self {
            completion,
            progress,
        }
    }

    pub const fn completion(&self) -> &SagaStepCompletion {
        &self.completion
    }
    pub const fn progress(&self) -> SagaForwardProgress {
        self.progress
    }
    pub fn into_parts(self) -> (SagaStepCompletion, SagaForwardProgress) {
        (self.completion, self.progress)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SagaCompensationIntent {
    seq: u64,
    step: StepName,
    attempt: SagaAttempt,
    effect_key: SagaIdempotencyKey,
    cause: SagaCompensationCause,
}

impl SagaCompensationIntent {
    pub fn new(
        seq: u64,
        step: StepName,
        attempt: SagaAttempt,
        effect_key: SagaIdempotencyKey,
        cause: SagaCompensationCause,
    ) -> Result<Self, SagaDurableMutationError> {
        require_compensation_phase(&effect_key)?;
        Ok(Self {
            seq,
            step,
            attempt,
            effect_key,
            cause,
        })
    }

    pub const fn seq(&self) -> u64 {
        self.seq
    }
    pub const fn step(&self) -> &StepName {
        &self.step
    }
    pub const fn attempt(&self) -> SagaAttempt {
        self.attempt
    }
    pub const fn effect_key(&self) -> &SagaIdempotencyKey {
        &self.effect_key
    }
    pub const fn cause(&self) -> SagaCompensationCause {
        self.cause
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SagaCompensationCompletion {
    seq: u64,
    step: StepName,
    attempt: SagaAttempt,
    effect_key: SagaIdempotencyKey,
    progress: SagaCompensationProgress,
}

impl SagaCompensationCompletion {
    pub fn new(
        seq: u64,
        step: StepName,
        attempt: SagaAttempt,
        effect_key: SagaIdempotencyKey,
        progress: SagaCompensationProgress,
    ) -> Result<Self, SagaDurableMutationError> {
        require_compensation_phase(&effect_key)?;
        Ok(Self {
            seq,
            step,
            attempt,
            effect_key,
            progress,
        })
    }

    pub const fn seq(&self) -> u64 {
        self.seq
    }
    pub const fn step(&self) -> &StepName {
        &self.step
    }
    pub const fn attempt(&self) -> SagaAttempt {
        self.attempt
    }
    pub const fn effect_key(&self) -> &SagaIdempotencyKey {
        &self.effect_key
    }
    pub const fn progress(&self) -> SagaCompensationProgress {
        self.progress
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SagaCompensationFailure {
    seq: u64,
    step: StepName,
    attempt: SagaAttempt,
    effect_key: SagaIdempotencyKey,
    error_summary: &'static str,
}

impl SagaCompensationFailure {
    pub fn new(
        seq: u64,
        step: StepName,
        attempt: SagaAttempt,
        effect_key: SagaIdempotencyKey,
        error_summary: &'static str,
    ) -> Result<Self, SagaDurableMutationError> {
        require_compensation_phase(&effect_key)?;
        Ok(Self {
            seq,
            step,
            attempt,
            effect_key,
            error_summary,
        })
    }

    pub const fn seq(&self) -> u64 {
        self.seq
    }
    pub const fn step(&self) -> &StepName {
        &self.step
    }
    pub const fn attempt(&self) -> SagaAttempt {
        self.attempt
    }
    pub const fn effect_key(&self) -> &SagaIdempotencyKey {
        &self.effect_key
    }
    pub const fn error_summary(&self) -> &'static str {
        self.error_summary
    }
}

/// Audited operator proof that one forward intent produced no external effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SagaForwardNotApplied {
    seq: u64,
    step: StepName,
    attempt: SagaAttempt,
    effect_key: SagaIdempotencyKey,
}

impl SagaForwardNotApplied {
    pub fn new(
        seq: u64,
        step: StepName,
        attempt: SagaAttempt,
        effect_key: SagaIdempotencyKey,
    ) -> Result<Self, SagaDurableMutationError> {
        if effect_key.phase() != SagaEffectPhase::Forward {
            return Err(SagaDurableMutationError::EffectPhaseMismatch);
        }
        Ok(Self {
            seq,
            step,
            attempt,
            effect_key,
        })
    }

    pub const fn seq(&self) -> u64 {
        self.seq
    }
    pub const fn step(&self) -> &StepName {
        &self.step
    }
    pub const fn attempt(&self) -> SagaAttempt {
        self.attempt
    }
    pub const fn effect_key(&self) -> &SagaIdempotencyKey {
        &self.effect_key
    }
}

/// Audited operator proof that one compensation intent produced no external effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SagaCompensationNotApplied {
    seq: u64,
    step: StepName,
    attempt: SagaAttempt,
    effect_key: SagaIdempotencyKey,
    cause: SagaCompensationCause,
}

impl SagaCompensationNotApplied {
    pub fn new(
        seq: u64,
        step: StepName,
        attempt: SagaAttempt,
        effect_key: SagaIdempotencyKey,
        cause: SagaCompensationCause,
    ) -> Result<Self, SagaDurableMutationError> {
        require_compensation_phase(&effect_key)?;
        Ok(Self {
            seq,
            step,
            attempt,
            effect_key,
            cause,
        })
    }

    pub const fn seq(&self) -> u64 {
        self.seq
    }
    pub const fn step(&self) -> &StepName {
        &self.step
    }
    pub const fn attempt(&self) -> SagaAttempt {
        self.attempt
    }
    pub const fn effect_key(&self) -> &SagaIdempotencyKey {
        &self.effect_key
    }
    pub const fn cause(&self) -> SagaCompensationCause {
        self.cause
    }
}

/// Closed operator repair decision. Applied decisions reuse the ordinary typed completion
/// carriers; not-applied decisions append an explicit journal proof before the instance reopens.
#[derive(Debug)]
#[non_exhaustive]
pub enum SagaOperatorRepair {
    ForwardApplied(Box<SagaForwardCompletion>),
    ForwardNotApplied(SagaForwardNotApplied),
    CompensationApplied(SagaCompensationCompletion),
    CompensationNotApplied(SagaCompensationNotApplied),
}

impl SagaOperatorRepair {
    pub const fn phase(&self) -> SagaEffectPhase {
        match self {
            Self::ForwardApplied(_) | Self::ForwardNotApplied(_) => SagaEffectPhase::Forward,
            Self::CompensationApplied(_) | Self::CompensationNotApplied(_) => {
                SagaEffectPhase::Compensation
            }
        }
    }
}

fn require_compensation_phase(
    effect_key: &SagaIdempotencyKey,
) -> Result<(), SagaDurableMutationError> {
    if effect_key.phase() == SagaEffectPhase::Compensation {
        Ok(())
    } else {
        Err(SagaDurableMutationError::EffectPhaseMismatch)
    }
}

/// Closed lease-fenced durable transition command set.
#[derive(Debug)]
#[non_exhaustive]
#[allow(clippy::large_enum_variant)]
// Mutations are short-lived move-only commands. Keeping their payloads inline avoids an
// allocation on every completed step while preserving the closed command boundary.
pub enum SagaDurableMutation {
    ForwardIntent(SagaForwardIntent),
    ForwardCompleted(SagaForwardCompletion),
    CompensationIntent(SagaCompensationIntent),
    CompensationCompleted(SagaCompensationCompletion),
    CompensationFailed(SagaCompensationFailure),
    OperatorRequired(SagaOperatorReason),
    Degraded,
}

/// Closed result of a lease-fenced durable transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaDurableMutationOutcome {
    Applied,
    IdempotentDuplicate,
    Conflict,
    LeaseLost,
}

/// Single writer boundary for every durable Saga transition and recovery read.
#[trait_variant::make(SagaDurableStore: Send)]
#[dynosaur(pub DynSagaDurableStore = dyn(box) SagaDurableStore, bridge(dyn))]
#[allow(async_fn_in_trait)]
pub trait SagaDurableStoreLocal: Send + Sync {
    async fn register(
        &self,
        registration: SagaInstanceRegistration,
    ) -> Result<SagaInstanceRecord, SagaDurableStoreError>;

    async fn get(
        &self,
        instance: &SagaInstanceRef,
    ) -> Result<Option<SagaInstanceRecord>, SagaDurableStoreError>;

    async fn list_runnable(
        &self,
        identity: &SagaWorkerIdentity,
        tenant: vocab::TenantId,
        limit: NonZeroUsize,
    ) -> Result<Vec<SagaRunnableInstance>, SagaDurableStoreError>;

    async fn claim(
        &self,
        request: SagaClaimRequest,
    ) -> Result<SagaClaimOutcome, SagaDurableStoreError>;

    async fn renew(
        &self,
        lease: &SagaLease,
        ttl: SagaLeaseTtl,
    ) -> Result<SagaLeaseOutcome, SagaDurableStoreError>;

    async fn release(&self, lease: &SagaLease) -> Result<SagaLeaseOutcome, SagaDurableStoreError>;

    async fn recovery_snapshot(
        &self,
        request: SagaRecoveryRequest,
    ) -> Result<SagaRecoveryOutcome, SagaDurableStoreError>;

    async fn terminal_receipt(
        &self,
        request: SagaTerminalReceiptRequest,
    ) -> Result<SagaTerminalReceiptOutcome, SagaDurableStoreError>;

    async fn mutate(
        &self,
        lease: &SagaLease,
        mutation: SagaDurableMutation,
    ) -> Result<SagaDurableMutationOutcome, SagaDurableStoreError>;

    async fn shutdown(&self) -> Result<(), SagaDurableStoreError>;
}

/// Operator-only extension of the durable Saga port.
///
/// The associated claim is owned by one provider implementation and consumed by release or
/// repair. It deliberately is not erased into the ordinary dyn runtime store because doing so
/// would erase provider ownership and reopen cross-provider claim substitution.
#[trait_variant::make(SagaOperatorStore: Send)]
#[allow(async_fn_in_trait)]
pub trait SagaOperatorStoreLocal {
    type Claim: SagaOperatorClaim;

    async fn list_operator_required(
        &self,
        authorization: SagaOperatorInspectionAuthorization,
        limit: NonZeroUsize,
    ) -> Result<Vec<SagaOperatorRequiredInstance>, SagaDurableStoreError>;

    async fn claim_operator(
        &self,
        authorization: SagaOperatorRepairAuthorization,
        holder: SagaLeaseHolder,
        ttl: SagaLeaseTtl,
    ) -> Result<SagaOperatorClaimOutcome<Self::Claim>, SagaDurableStoreError>;

    async fn operator_recovery_snapshot(
        &self,
        claim: &Self::Claim,
        scopes: Vec<SagaReceiptScope>,
    ) -> Result<SagaRecoveryOutcome, SagaDurableStoreError>;

    async fn release_operator(
        &self,
        claim: Self::Claim,
    ) -> Result<SagaLeaseOutcome, SagaDurableStoreError>;

    async fn repair(
        &self,
        claim: Self::Claim,
        decision: SagaOperatorRepair,
    ) -> Result<SagaDurableMutationOutcome, SagaDurableStoreError>;
}

/// Stable keyset cursor for runnable-tenant discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SagaTenantCursor {
    tenant: vocab::TenantId,
}

impl SagaTenantCursor {
    pub const fn new(tenant: vocab::TenantId) -> Self {
        Self { tenant }
    }

    pub const fn tenant(self) -> vocab::TenantId {
        self.tenant
    }
}

/// One deterministic page of runnable Saga tenants.
#[derive(Debug, PartialEq, Eq)]
pub struct SagaTenantPage {
    tenants: Vec<vocab::TenantId>,
    next: Option<SagaTenantCursor>,
}

impl SagaTenantPage {
    pub fn new(tenants: Vec<vocab::TenantId>, next: Option<SagaTenantCursor>) -> Self {
        Self { tenants, next }
    }

    pub fn tenants(&self) -> &[vocab::TenantId] {
        &self.tenants
    }

    pub const fn next(&self) -> Option<SagaTenantCursor> {
        self.next
    }

    pub fn into_parts(self) -> (Vec<vocab::TenantId>, Option<SagaTenantCursor>) {
        (self.tenants, self.next)
    }
}

/// Current durable unresolved state for one worker identity across tenants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaUnresolvedState {
    Clear,
    Present,
}

/// Candidate tenants remain a separate advisory discovery source.
#[trait_variant::make(SagaTenantSource: Send)]
#[dynosaur(pub DynSagaTenantSource = dyn(box) SagaTenantSource, bridge(dyn))]
#[allow(async_fn_in_trait)]
pub trait SagaTenantSourceLocal {
    async fn list_runnable_tenants(
        &self,
        identity: &SagaWorkerIdentity,
        cursor: Option<SagaTenantCursor>,
        limit: NonZeroUsize,
    ) -> Result<SagaTenantPage, SagaDurableStoreError>;

    async fn observe_unresolved(
        &self,
        identity: &SagaWorkerIdentity,
    ) -> Result<SagaUnresolvedState, SagaDurableStoreError>;
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{
        SagaDurableStoreError, SagaDurableStoreErrorKind, SagaLeaseHolder, SagaLeaseHolderError,
        SagaLeaseTtl, SagaLeaseTtlError, SagaOperatorChangeTicket, SagaOperatorChangeTicketError,
        SagaOperatorStartAuditId, SagaOperatorStartAuditIdError,
    };

    #[test]
    #[allow(clippy::expect_used)]
    // reason: this test proves the error contract always installs the redacted source wrapper.
    fn error_redacts_source() {
        let secret = std::io::Error::other("postgres://user:hunter2@db.internal/rss");
        let error = SagaDurableStoreError::new(SagaDurableStoreErrorKind::Storage, secret);
        let rendered = format!("{error:?}");
        assert!(!rendered.contains("hunter2") && !rendered.contains("postgres://"));
        assert_eq!(error.kind(), SagaDurableStoreErrorKind::Storage);
        let source = std::error::Error::source(&error).expect("redacted source wrapper");
        assert_eq!(source.to_string(), "<redacted>");
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn lease_holder_and_change_ticket_are_bounded_typed_values() {
        let holder = SagaLeaseHolder::parse("saga-worker:runtime-01").unwrap();
        assert_eq!(holder.as_str(), "saga-worker:runtime-01");
        assert_eq!(format!("{holder:?}"), "SagaLeaseHolder(<redacted>)");
        for invalid in ["", " runner", "runner ", "runner\n"] {
            assert_eq!(
                SagaLeaseHolder::parse(invalid),
                Err(SagaLeaseHolderError::Invalid)
            );
        }
        assert_eq!(
            SagaLeaseHolder::parse("x".repeat(129)),
            Err(SagaLeaseHolderError::Invalid)
        );

        let ticket = SagaOperatorChangeTicket::parse("CHG-1925").unwrap();
        assert_eq!(ticket.as_str(), "CHG-1925");
        assert_eq!(
            format!("{ticket:?}"),
            "SagaOperatorChangeTicket(<redacted>)"
        );
        for invalid in ["", " CHG-1925", "CHG-1925 ", "CHG\t1925"] {
            assert_eq!(
                SagaOperatorChangeTicket::parse(invalid),
                Err(SagaOperatorChangeTicketError::Invalid)
            );
        }
        assert_eq!(
            SagaOperatorChangeTicket::parse("x".repeat(129)),
            Err(SagaOperatorChangeTicketError::Invalid)
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn saga_lease_ttl_is_positive_microsecond_exact_and_provider_bounded() {
        let ttl = SagaLeaseTtl::new(Duration::from_micros(30_000_001)).unwrap();
        assert_eq!(ttl.as_micros(), 30_000_001);
        assert_eq!(ttl.as_duration(), Duration::from_micros(30_000_001));
        assert_eq!(
            SagaLeaseTtl::new(Duration::ZERO),
            Err(SagaLeaseTtlError::Zero)
        );
        assert_eq!(
            SagaLeaseTtl::new(Duration::from_nanos(1)),
            Err(SagaLeaseTtlError::Submicrosecond)
        );
        assert_eq!(
            SagaLeaseTtl::new(Duration::from_micros(i64::MAX as u64 + 1)),
            Err(SagaLeaseTtlError::Overflow)
        );
    }

    #[test]
    fn operator_start_audit_id_is_bounded_and_canonical() {
        let id = SagaOperatorStartAuditId::parse("audit-1925").unwrap();
        assert_eq!(id.as_str(), "audit-1925");
        for invalid in ["", " audit-1925", "audit-1925 ", "audit\n1925"] {
            assert_eq!(
                SagaOperatorStartAuditId::parse(invalid),
                Err(SagaOperatorStartAuditIdError::Invalid)
            );
        }
    }
}
