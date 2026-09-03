//! Closed durable Saga storage boundary.
//!
//! Instance state, leases, journal intents/completions and protected receipts intentionally share
//! one writer port. This keeps every externally visible Saga transition in one fenced local
//! transaction and prevents callers from composing a receipt, journal row and lifecycle status
//! through independently fallible stores.

use std::collections::HashSet;
use std::num::{NonZeroU64, NonZeroUsize};
use std::time::Duration;
use std::time::SystemTime;

use dynosaur::dynosaur;

use consistency::{
    SagaAttempt, SagaCompensationCause, SagaDefinitionIdentity, SagaEffectPhase,
    SagaIdempotencyKey, SagaInstanceRecord, SagaInstanceRef, SagaInstanceStatus, SagaJournalRecord,
    SagaLease, SagaLeaseOutcome, SagaOperatorReason, SagaReceiptFormatVersion, SagaReceiptScope,
};
pub use consistency::{
    SagaContractId, SagaContractIdError, SagaWorkerIdentity, SagaWorkerIdentityError,
};
use rss_data_protection::Plaintext;
use vocab::StepName;

use rss_redact::RedactedSource;

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

/// Durable identity of the audit record written before one business Saga start.
#[derive(PartialEq, Eq)]
pub struct SagaStartAuditId(String);

impl std::fmt::Debug for SagaStartAuditId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SagaStartAuditId(<redacted>)")
    }
}

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaStartAuditIdError {
    #[error("saga start audit id is invalid")]
    Invalid,
}

impl SagaStartAuditId {
    pub fn parse(raw: impl Into<String>) -> Result<Self, SagaStartAuditIdError> {
        let value = raw.into();
        if value.is_empty()
            || value.len() > 128
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(SagaStartAuditIdError::Invalid);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Move-only proof that business authentication, exact authorization and durable start audit
/// completed for one assembly-selected Saga instance.
#[derive(Debug)]
pub struct SagaStartAuthorization {
    caller: vocab::ServiceCallerDomain,
    identity: SagaWorkerIdentity,
    instance: SagaInstanceRef,
    start_audit_id: SagaStartAuditId,
}

impl SagaStartAuthorization {
    pub fn issue(
        caller: vocab::ServiceCallerDomain,
        identity: SagaWorkerIdentity,
        instance: SagaInstanceRef,
        start_audit_id: SagaStartAuditId,
    ) -> Self {
        Self {
            caller,
            identity,
            instance,
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
    pub const fn start_audit_id(&self) -> &SagaStartAuditId {
        &self.start_audit_id
    }
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
///
/// INVARIANT: SAGA-RECEIPT-COMPLETION-TYPE-01 { level = "Hard", exec = "native-compile", source = "code", native = "private fields; only SagaStepCompletion::new constructs values that feed SagaDurableMutation::ForwardCompleted; trybuild rejects struct-literal forgery" }.
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

/// Human-reviewed justification persisted with every mutating Saga operator action.
#[derive(Clone, PartialEq, Eq)]
pub struct SagaOperatorReasonText(String);

impl std::fmt::Debug for SagaOperatorReasonText {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SagaOperatorReasonText(<redacted>)")
    }
}

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaOperatorReasonTextError {
    #[error("saga operator reason text is invalid")]
    Invalid,
}

impl SagaOperatorReasonText {
    pub const MAX_BYTES: usize = 512;

    pub fn parse(raw: impl Into<String>) -> Result<Self, SagaOperatorReasonTextError> {
        let value = raw.into();
        if value.is_empty()
            || value.len() > Self::MAX_BYTES
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(SagaOperatorReasonTextError::Invalid);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

mod saga_operator_action_sealed {
    pub trait Sealed {}
}

/// Sealed operator action markers used by [`SagaOperatorAuthorization`].
pub mod saga_operator_action {
    /// Exact read-only status lookup for one Saga instance.
    #[derive(Debug)]
    pub struct Status(pub(super) ());
    /// Exact compensation-failure retry CAS for one Saga instance.
    #[derive(Debug)]
    pub struct RetryCompensation(pub(super) ());
    /// Typed effect-probe recovery for one operator-required Saga instance.
    #[derive(Debug)]
    pub struct Repair(pub(super) ());
    /// Pre-effect termination CAS for one ready Saga instance.
    #[derive(Debug)]
    pub struct Terminate(pub(super) ());
}

impl saga_operator_action_sealed::Sealed for saga_operator_action::Status {}
impl saga_operator_action_sealed::Sealed for saga_operator_action::RetryCompensation {}
impl saga_operator_action_sealed::Sealed for saga_operator_action::Repair {}
impl saga_operator_action_sealed::Sealed for saga_operator_action::Terminate {}

/// Closed action family accepted by [`SagaOperatorAuthorization`].
pub trait SagaOperatorAction: saga_operator_action_sealed::Sealed {
    type Evidence: std::fmt::Debug;
}

impl SagaOperatorAction for saga_operator_action::Status {
    type Evidence = ();
}

/// Exact journal fact used for stale-safe operator decisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SagaOperatorJournalExpectation {
    record: SagaJournalRecord,
    attempt: SagaAttempt,
    effect_key: SagaIdempotencyKey,
}

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaOperatorJournalExpectationError {
    #[error("saga operator journal effect phase does not match its status")]
    EffectPhaseMismatch,
    #[error("saga operator journal status is unsupported")]
    UnsupportedStatus,
}

impl SagaOperatorJournalExpectation {
    pub fn new(
        record: SagaJournalRecord,
        attempt: SagaAttempt,
        effect_key: SagaIdempotencyKey,
    ) -> Result<Self, SagaOperatorJournalExpectationError> {
        let expected_phase = match record.status() {
            consistency::SagaJournalStatus::ForwardIntent
            | consistency::SagaJournalStatus::ForwardCompleted
            | consistency::SagaJournalStatus::ForwardNotApplied => SagaEffectPhase::Forward,
            consistency::SagaJournalStatus::CompensationIntent
            | consistency::SagaJournalStatus::CompensationCompleted
            | consistency::SagaJournalStatus::CompensationNotApplied
            | consistency::SagaJournalStatus::CompensationFailed => SagaEffectPhase::Compensation,
            _ => return Err(SagaOperatorJournalExpectationError::UnsupportedStatus),
        };
        if effect_key.phase() != expected_phase {
            return Err(SagaOperatorJournalExpectationError::EffectPhaseMismatch);
        }
        Ok(Self {
            record,
            attempt,
            effect_key,
        })
    }

    pub const fn record(&self) -> &SagaJournalRecord {
        &self.record
    }
    pub const fn attempt(&self) -> SagaAttempt {
        self.attempt
    }
    pub const fn effect_key(&self) -> &SagaIdempotencyKey {
        &self.effect_key
    }
}

/// Retry evidence bound into one `RetryCompensation` authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SagaRetryCompensationExpectation {
    journal: SagaOperatorJournalExpectation,
    reason_text: SagaOperatorReasonText,
    change_ticket: SagaOperatorChangeTicket,
}

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaRetryCompensationExpectationError {
    #[error("saga retry-compensation expects a compensation-failed journal record")]
    ExpectedCompensationFailure,
}

impl SagaRetryCompensationExpectation {
    pub fn new(
        journal: SagaOperatorJournalExpectation,
        reason_text: SagaOperatorReasonText,
        change_ticket: SagaOperatorChangeTicket,
    ) -> Result<Self, SagaRetryCompensationExpectationError> {
        if journal.record().status() != consistency::SagaJournalStatus::CompensationFailed {
            return Err(SagaRetryCompensationExpectationError::ExpectedCompensationFailure);
        }
        Ok(Self {
            journal,
            reason_text,
            change_ticket,
        })
    }

    pub const fn journal(&self) -> &SagaOperatorJournalExpectation {
        &self.journal
    }
    pub const fn reason_text(&self) -> &SagaOperatorReasonText {
        &self.reason_text
    }
    pub const fn change_ticket(&self) -> &SagaOperatorChangeTicket {
        &self.change_ticket
    }
}

impl SagaOperatorAction for saga_operator_action::RetryCompensation {
    type Evidence = SagaRetryCompensationExpectation;
}

/// Only reasons whose authoritative result can be recovered through a typed effect probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SagaOperatorRepairReason {
    ForwardOutcomeUnknown,
    CompletionCommitUnknown,
    CompensationOutcomeUnknown,
}

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
#[error("saga operator reason is not repairable by an effect probe")]
pub struct SagaOperatorRepairReasonError;

impl TryFrom<SagaOperatorReason> for SagaOperatorRepairReason {
    type Error = SagaOperatorRepairReasonError;

    fn try_from(reason: SagaOperatorReason) -> Result<Self, Self::Error> {
        match reason {
            SagaOperatorReason::ForwardOutcomeUnknown => Ok(Self::ForwardOutcomeUnknown),
            SagaOperatorReason::CompletionCommitUnknown => Ok(Self::CompletionCommitUnknown),
            SagaOperatorReason::CompensationOutcomeUnknown => Ok(Self::CompensationOutcomeUnknown),
            _ => Err(SagaOperatorRepairReasonError),
        }
    }
}

impl SagaOperatorRepairReason {
    pub const fn as_operator_reason(self) -> SagaOperatorReason {
        match self {
            Self::ForwardOutcomeUnknown => SagaOperatorReason::ForwardOutcomeUnknown,
            Self::CompletionCommitUnknown => SagaOperatorReason::CompletionCommitUnknown,
            Self::CompensationOutcomeUnknown => SagaOperatorReason::CompensationOutcomeUnknown,
        }
    }
}

/// Repair evidence bound into one `Repair` authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SagaOperatorRepairExpectation {
    reason: SagaOperatorRepairReason,
    reason_text: SagaOperatorReasonText,
    change_ticket: SagaOperatorChangeTicket,
}

impl SagaOperatorRepairExpectation {
    pub fn new(
        reason: SagaOperatorRepairReason,
        reason_text: SagaOperatorReasonText,
        change_ticket: SagaOperatorChangeTicket,
    ) -> Self {
        Self {
            reason,
            reason_text,
            change_ticket,
        }
    }

    pub const fn reason(&self) -> SagaOperatorRepairReason {
        self.reason
    }
    pub const fn reason_text(&self) -> &SagaOperatorReasonText {
        &self.reason_text
    }
    pub const fn change_ticket(&self) -> &SagaOperatorChangeTicket {
        &self.change_ticket
    }
}

impl SagaOperatorAction for saga_operator_action::Repair {
    type Evidence = SagaOperatorRepairExpectation;
}

/// Change-ticket evidence bound into one `Terminate` authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SagaTerminateExpectation {
    reason_text: SagaOperatorReasonText,
    change_ticket: SagaOperatorChangeTicket,
}

impl SagaTerminateExpectation {
    pub fn new(
        reason_text: SagaOperatorReasonText,
        change_ticket: SagaOperatorChangeTicket,
    ) -> Self {
        Self {
            reason_text,
            change_ticket,
        }
    }

    pub const fn reason_text(&self) -> &SagaOperatorReasonText {
        &self.reason_text
    }

    pub const fn change_ticket(&self) -> &SagaOperatorChangeTicket {
        &self.change_ticket
    }
}

impl SagaOperatorAction for saga_operator_action::Terminate {
    type Evidence = SagaTerminateExpectation;
}

/// Move-only proof for one exact operator action against one tenant-scoped Saga instance.
#[derive(Debug)]
pub struct SagaOperatorAuthorization<A: SagaOperatorAction> {
    caller: vocab::ServiceCallerDomain,
    identity: SagaWorkerIdentity,
    instance: SagaInstanceRef,
    evidence: A::Evidence,
    start_audit_id: SagaOperatorStartAuditId,
}

impl<A: SagaOperatorAction> SagaOperatorAuthorization<A> {
    pub fn issue(
        _mint: sagaauthmint::SagaOperatorMint,
        caller: vocab::ServiceCallerDomain,
        identity: SagaWorkerIdentity,
        instance: SagaInstanceRef,
        evidence: A::Evidence,
        start_audit_id: SagaOperatorStartAuditId,
    ) -> Self {
        Self {
            caller,
            identity,
            instance,
            evidence,
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
    pub fn tenant(&self) -> rss_request_context::TenantId {
        self.instance.tenant()
    }
    pub const fn evidence(&self) -> &A::Evidence {
        &self.evidence
    }
    pub const fn start_audit_id(&self) -> &SagaOperatorStartAuditId {
        &self.start_audit_id
    }
}

/// Read-only metadata exposed by a provider-owned, move-only repair claim.
pub trait SagaOperatorRepairClaim: Send + Sync {
    fn instance(&self) -> SagaInstanceRef;
    fn expected_reason(&self) -> SagaOperatorRepairReason;
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

/// Exact read-only result for one authorized Saga instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SagaOperatorStatusSnapshot {
    record: SagaInstanceRecord,
    latest_journal: Option<SagaOperatorJournalExpectation>,
    has_effect_intent: bool,
    unresolved_at: Option<SystemTime>,
}

impl SagaOperatorStatusSnapshot {
    pub fn new(
        record: SagaInstanceRecord,
        latest_journal: Option<SagaOperatorJournalExpectation>,
        has_effect_intent: bool,
        unresolved_at: Option<SystemTime>,
    ) -> Self {
        Self {
            record,
            latest_journal,
            has_effect_intent,
            unresolved_at,
        }
    }

    pub const fn record(&self) -> &SagaInstanceRecord {
        &self.record
    }
    pub const fn latest_journal(&self) -> Option<&SagaOperatorJournalExpectation> {
        self.latest_journal.as_ref()
    }
    pub const fn has_effect_intent(&self) -> bool {
        self.has_effect_intent
    }
    pub const fn unresolved_at(&self) -> Option<SystemTime> {
        self.unresolved_at
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaOperatorStatusOutcome {
    Found(Box<SagaOperatorStatusSnapshot>),
    Missing,
    IdentityConflict,
}

/// Closed outcome of an exact operator lifecycle CAS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaOperatorCasOutcome {
    Applied,
    Busy,
    Missing,
    IdentityConflict,
    StaleStatus(SagaInstanceStatus),
    StaleReason(SagaOperatorReason),
    StaleJournal,
    EffectAlreadyStarted,
    LeaseLost,
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
/// INVARIANT: SAGA-RECEIPT-COMPLETION-TYPE-01 { level = "Hard", exec = "native-compile", source = "code", native = "private fields; only SagaForwardCompletion::new pairs a sealed SagaStepCompletion with progress for SagaDurableMutation::ForwardCompleted; trybuild rejects struct-literal forgery" }.
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
        authorization: SagaStartAuthorization,
        registration: SagaInstanceRegistration,
    ) -> Result<SagaInstanceRecord, SagaDurableStoreError>;

    async fn get(
        &self,
        instance: &SagaInstanceRef,
    ) -> Result<Option<SagaInstanceRecord>, SagaDurableStoreError>;

    async fn list_runnable(
        &self,
        identity: &SagaWorkerIdentity,
        tenant: rss_request_context::TenantId,
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
/// Every public operation consumes an action-specific, target-bound authorization. The associated
/// repair claim is owned by one provider implementation and consumed by release or commit. It is
/// not erased into the ordinary dyn runtime store because that would reopen cross-provider claim
/// substitution.
#[trait_variant::make(SagaOperatorStore: Send)]
#[allow(async_fn_in_trait)]
pub trait SagaOperatorStoreLocal {
    type RepairClaim: SagaOperatorRepairClaim;

    async fn operator_status(
        &self,
        authorization: SagaOperatorAuthorization<saga_operator_action::Status>,
    ) -> Result<SagaOperatorStatusOutcome, SagaDurableStoreError>;

    async fn retry_compensation(
        &self,
        authorization: SagaOperatorAuthorization<saga_operator_action::RetryCompensation>,
    ) -> Result<SagaOperatorCasOutcome, SagaDurableStoreError>;

    async fn claim_repair(
        &self,
        authorization: SagaOperatorAuthorization<saga_operator_action::Repair>,
        holder: SagaLeaseHolder,
        ttl: SagaLeaseTtl,
    ) -> Result<SagaOperatorClaimOutcome<Self::RepairClaim>, SagaDurableStoreError>;

    async fn repair_snapshot(
        &self,
        claim: &Self::RepairClaim,
        scopes: Vec<SagaReceiptScope>,
    ) -> Result<SagaRecoveryOutcome, SagaDurableStoreError>;

    async fn release_repair(
        &self,
        claim: Self::RepairClaim,
    ) -> Result<SagaLeaseOutcome, SagaDurableStoreError>;

    async fn commit_repair(
        &self,
        claim: Self::RepairClaim,
        decision: SagaOperatorRepair,
    ) -> Result<SagaOperatorCasOutcome, SagaDurableStoreError>;
}

/// Stable keyset cursor for runnable-tenant discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SagaTenantCursor {
    tenant: rss_request_context::TenantId,
}

impl SagaTenantCursor {
    pub const fn new(tenant: rss_request_context::TenantId) -> Self {
        Self { tenant }
    }

    pub const fn tenant(self) -> rss_request_context::TenantId {
        self.tenant
    }
}

/// One deterministic page of runnable Saga tenants.
#[derive(Debug, PartialEq, Eq)]
pub struct SagaTenantPage {
    tenants: Vec<rss_request_context::TenantId>,
    next: Option<SagaTenantCursor>,
}

impl SagaTenantPage {
    pub fn new(
        tenants: Vec<rss_request_context::TenantId>,
        next: Option<SagaTenantCursor>,
    ) -> Self {
        Self { tenants, next }
    }

    pub fn tenants(&self) -> &[rss_request_context::TenantId] {
        &self.tenants
    }

    pub const fn next(&self) -> Option<SagaTenantCursor> {
        self.next
    }

    pub fn into_parts(self) -> (Vec<rss_request_context::TenantId>, Option<SagaTenantCursor>) {
        (self.tenants, self.next)
    }
}

/// Current durable unresolved state for one worker identity across tenants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SagaUnresolvedObservation {
    operator_required: u64,
    degraded: u64,
    compensation_failed: u64,
    oldest_unresolved_at: Option<SystemTime>,
}

impl SagaUnresolvedObservation {
    pub fn new(
        operator_required: u64,
        degraded: u64,
        compensation_failed: u64,
        oldest_unresolved_at: Option<SystemTime>,
    ) -> Self {
        Self {
            operator_required,
            degraded,
            compensation_failed,
            oldest_unresolved_at,
        }
    }

    pub const fn operator_required(&self) -> u64 {
        self.operator_required
    }
    pub const fn degraded(&self) -> u64 {
        self.degraded
    }
    pub const fn compensation_failed(&self) -> u64 {
        self.compensation_failed
    }
    pub const fn oldest_unresolved_at(&self) -> Option<SystemTime> {
        self.oldest_unresolved_at
    }
    pub const fn is_clear(&self) -> bool {
        self.operator_required == 0 && self.degraded == 0 && self.compensation_failed == 0
    }
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
    ) -> Result<SagaUnresolvedObservation, SagaDurableStoreError>;
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{
        SagaDurableStoreError, SagaDurableStoreErrorKind, SagaInstanceRef, SagaLeaseHolder,
        SagaLeaseHolderError, SagaLeaseTtl, SagaLeaseTtlError, SagaOperatorAuthorization,
        SagaOperatorChangeTicket, SagaOperatorChangeTicketError, SagaOperatorReason,
        SagaOperatorReasonText, SagaOperatorReasonTextError, SagaOperatorRepairExpectation,
        SagaOperatorRepairReason, SagaOperatorStartAuditId, SagaOperatorStartAuditIdError,
        SagaWorkerIdentity, saga_operator_action,
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
    #[allow(clippy::unwrap_used)]
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

    #[test]
    #[allow(clippy::unwrap_used)]
    fn operator_authorization_is_action_tenant_and_instance_bound() {
        let tenant =
            rss_request_context::TenantId::parse("00000000-0000-4000-8000-000000001926").unwrap();
        let instance = SagaInstanceRef::new(
            tenant,
            consistency::SagaId::new(uuid::Uuid::from_u128(1926)),
        )
        .unwrap();
        let identity = SagaWorkerIdentity::new(
            "orders",
            super::SagaContractId::parse("orders.checkout").unwrap(),
        )
        .unwrap();
        let authorization: SagaOperatorAuthorization<saga_operator_action::Status> =
            SagaOperatorAuthorization::issue(
                sagaauthmint::SagaOperatorMint::capability(),
                vocab::ServiceCallerDomain::MaintenanceOperator,
                identity.clone(),
                instance,
                (),
                SagaOperatorStartAuditId::parse("audit-status-1926").unwrap(),
            );

        assert_eq!(authorization.identity(), &identity);
        assert_eq!(authorization.tenant(), tenant);
        assert_eq!(authorization.instance(), instance);
        assert_eq!(authorization.start_audit_id().as_str(), "audit-status-1926");
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn repair_expectation_accepts_only_probe_unknown_reasons() {
        for reason in [
            SagaOperatorReason::ForwardOutcomeUnknown,
            SagaOperatorReason::CompletionCommitUnknown,
            SagaOperatorReason::CompensationOutcomeUnknown,
        ] {
            let typed = SagaOperatorRepairReason::try_from(reason).unwrap();
            let expectation = SagaOperatorRepairExpectation::new(
                typed,
                SagaOperatorReasonText::parse("provider evidence reviewed").unwrap(),
                SagaOperatorChangeTicket::parse("CHG-1926").unwrap(),
            );
            assert_eq!(expectation.reason().as_operator_reason(), reason);
        }
        for unsupported in [
            SagaOperatorReason::ReceiptMissing,
            SagaOperatorReason::ReceiptIntegrity,
            SagaOperatorReason::ReceiptFormatUnsupported,
            SagaOperatorReason::DefinitionUnsupported,
        ] {
            assert!(SagaOperatorRepairReason::try_from(unsupported).is_err());
        }
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn operator_reason_text_is_bounded_canonical_and_redacted() {
        let reason = SagaOperatorReasonText::parse("provider evidence reviewed").unwrap();
        assert_eq!(reason.as_str(), "provider evidence reviewed");
        assert_eq!(format!("{reason:?}"), "SagaOperatorReasonText(<redacted>)");
        for invalid in ["", " leading", "trailing ", "line\nbreak"] {
            assert_eq!(
                SagaOperatorReasonText::parse(invalid),
                Err(SagaOperatorReasonTextError::Invalid)
            );
        }
        assert_eq!(
            SagaOperatorReasonText::parse("x".repeat(513)),
            Err(SagaOperatorReasonTextError::Invalid)
        );
    }
}
