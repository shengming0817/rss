//! Provider-neutral durable device-command and ingress-evidence port.
//!
//! The public mutation inputs deliberately exclude tenant identifiers, persisted snapshots,
//! optimistic versions chosen by callers, and server timestamps. Providers bind the associated
//! scope to an authenticated capability and mint all storage-owned fields inside the transaction.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::command::{
    CommandIntentDigest, CommandTransitionOutcome, CommandVersion, DeviceCommandError,
    DeviceCommandId, DeviceCommandSnapshot, DeviceCommandState,
};
use crate::generation::{
    CurrentFence, FenceCoordinate, FenceEpoch, MatchingReportedState, NewerGeneration,
    ObservedGeneration,
};

const MAX_INGRESS_ENVELOPE_ID_BYTES: usize = 256;
const MICROS_PER_SECOND: i128 = 1_000_000;
const NANOS_PER_MICRO: u32 = 1_000;
const PG_UNIX_MIN_MICROS: i128 = -210_866_803_200_000_000;

/// Stable ingress envelope identity used as the tenant-local idempotency key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DeviceIngressEnvelopeId(String);

impl DeviceIngressEnvelopeId {
    /// Validate an opaque envelope identifier.
    pub fn parse(raw: &str) -> Result<Self, DeviceIngressError> {
        if raw.is_empty()
            || raw.trim().is_empty()
            || raw.len() > MAX_INGRESS_ENVELOPE_ID_BYTES
            || raw.chars().any(char::is_control)
        {
            return Err(DeviceIngressError::InvalidEnvelopeId);
        }
        Ok(Self(raw.to_owned()))
    }

    /// Borrow the validated identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Nonnegative device-local ingress sequence shared by ACK and report contracts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceSequence(u64);

/// A device sequence was outside PostgreSQL's nonnegative signed-integer range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("device sequence must be in 0..=i64::MAX")]
pub struct InvalidDeviceSequence;

impl DeviceSequence {
    /// Validate a sequence representable by PostgreSQL `bigint`.
    pub fn try_new(raw: u64) -> Result<Self, InvalidDeviceSequence> {
        i64::try_from(raw)
            .map(|_| Self(raw))
            .map_err(|_| InvalidDeviceSequence)
    }

    /// Restore a persisted sequence.
    pub fn restore(raw: i64) -> Result<Self, InvalidDeviceSequence> {
        u64::try_from(raw)
            .map(Self)
            .map_err(|_| InvalidDeviceSequence)
    }

    /// Wire/domain representation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A command deadline was not exactly representable by the durable microsecond contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DeviceCommandDeadlineError {
    /// Sub-microsecond precision would make create replay provider-dependent.
    #[error("device command deadline must have exact microsecond precision")]
    Submicrosecond,
    /// The timestamp is outside PostgreSQL's durable timestamp range.
    #[error("device command deadline is outside the persistent timestamp range")]
    OutsidePersistentRange,
}

/// Canonical microsecond-precision command deadline.
///
/// Raw [`SystemTime`] is deliberately rejected at the durable store boundary:
///
/// ```compile_fail
/// use deviceloop::{CreateDeviceCommand, CommandIntentDigest, DeviceCommandId, CurrentFence};
/// use std::time::SystemTime;
/// fn forge(id: DeviceCommandId, digest: CommandIntentDigest, fence: CurrentFence) {
///     let _ = CreateDeviceCommand::new(id, digest, fence, SystemTime::UNIX_EPOCH);
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceCommandDeadline(i64);

impl DeviceCommandDeadline {
    /// Validate and canonicalize a caller deadline without truncation.
    pub fn try_new(value: SystemTime) -> Result<Self, DeviceCommandDeadlineError> {
        let (negative, duration) = match value.duration_since(UNIX_EPOCH) {
            Ok(duration) => (false, duration),
            Err(error) => (true, error.duration()),
        };
        if duration.subsec_nanos() % NANOS_PER_MICRO != 0 {
            return Err(DeviceCommandDeadlineError::Submicrosecond);
        }
        let magnitude = i128::from(duration.as_secs())
            .checked_mul(MICROS_PER_SECOND)
            .and_then(|seconds| seconds.checked_add(i128::from(duration.subsec_micros())))
            .ok_or(DeviceCommandDeadlineError::OutsidePersistentRange)?;
        let signed = if negative { -magnitude } else { magnitude };
        if !(PG_UNIX_MIN_MICROS..=i128::from(i64::MAX)).contains(&signed) {
            return Err(DeviceCommandDeadlineError::OutsidePersistentRange);
        }
        Ok(Self(i64::try_from(signed).map_err(|_| {
            DeviceCommandDeadlineError::OutsidePersistentRange
        })?))
    }

    /// Restore a canonical persisted epoch-microsecond value.
    pub fn restore(epoch_micros: i64) -> Result<Self, DeviceCommandDeadlineError> {
        if i128::from(epoch_micros) < PG_UNIX_MIN_MICROS {
            return Err(DeviceCommandDeadlineError::OutsidePersistentRange);
        }
        let deadline = Self(epoch_micros);
        deadline.system_time()?;
        Ok(deadline)
    }

    /// Exact PostgreSQL/wire representation.
    #[must_use]
    pub const fn epoch_micros(self) -> i64 {
        self.0
    }

    /// Reconstruct the canonical system timestamp.
    pub fn system_time(self) -> Result<SystemTime, DeviceCommandDeadlineError> {
        if self.0 >= 0 {
            UNIX_EPOCH
                .checked_add(Duration::from_micros(self.0.unsigned_abs()))
                .ok_or(DeviceCommandDeadlineError::OutsidePersistentRange)
        } else {
            UNIX_EPOCH
                .checked_sub(Duration::from_micros(self.0.unsigned_abs()))
                .ok_or(DeviceCommandDeadlineError::OutsidePersistentRange)
        }
    }
}

/// Exact semantic fingerprint of the authenticated ingress envelope.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceIngressFingerprint([u8; 32]);

impl DeviceIngressFingerprint {
    /// Construct an already computed SHA-256 fingerprint.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Exact bytes used by persistence providers.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for DeviceIngressFingerprint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DeviceIngressFingerprint(<sha256>)")
    }
}

/// Ingress validation error.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeviceIngressError {
    /// The envelope id is blank, too long, or contains a control character.
    #[error("device ingress envelope id is not canonical")]
    InvalidEnvelopeId,
    /// The device sequence is outside `0..=i64::MAX`.
    #[error(transparent)]
    InvalidSequence(#[from] InvalidDeviceSequence),
    /// Persisted server timestamps are not monotonic.
    #[error("device ingress receipt timestamps are not monotonic")]
    InvalidTimestampOrder,
}

/// Timestamp-free command creation request.
///
/// Server-owned state, version, and timestamps are absent by construction:
///
/// ```compile_fail
/// use deviceloop::CreateDeviceCommand;
/// use std::time::SystemTime;
/// fn forge(mut input: CreateDeviceCommand) {
///     input.queued_at = SystemTime::UNIX_EPOCH;
/// }
/// ```
#[derive(Debug)]
pub struct CreateDeviceCommand {
    command_id: DeviceCommandId,
    intent_digest: CommandIntentDigest,
    authority: CurrentFence,
    deadline: DeviceCommandDeadline,
}

impl CreateDeviceCommand {
    /// Bind a command identity and semantic intent to current generation authority.
    #[must_use]
    pub fn new(
        command_id: DeviceCommandId,
        intent_digest: CommandIntentDigest,
        authority: CurrentFence,
        deadline: DeviceCommandDeadline,
    ) -> Self {
        Self {
            command_id,
            intent_digest,
            authority,
            deadline,
        }
    }

    /// Command identity.
    #[must_use]
    pub fn command_id(&self) -> &DeviceCommandId {
        &self.command_id
    }

    /// Stable semantic intent digest.
    #[must_use]
    pub const fn intent_digest(&self) -> CommandIntentDigest {
        self.intent_digest
    }

    /// Authority-bound command scope.
    #[must_use]
    pub fn command_scope(&self) -> crate::DeviceCommandScope {
        self.authority.scope()
    }

    /// Authority-bound generation/fence coordinate.
    #[must_use]
    pub fn coordinate(&self) -> FenceCoordinate {
        self.authority.coordinate()
    }

    /// Caller-owned command deadline.
    #[must_use]
    pub const fn deadline(&self) -> DeviceCommandDeadline {
        self.deadline
    }

    /// Mint the initial state using provider-owned transaction time.
    pub fn into_state(
        self,
        queued_at: SystemTime,
    ) -> Result<DeviceCommandState, DeviceCommandError> {
        DeviceCommandState::queue(
            self.command_id,
            self.intent_digest,
            self.authority,
            queued_at,
            self.deadline
                .system_time()
                .map_err(|_| DeviceCommandError::InvalidDeadline)?,
        )
    }
}

/// Timestamp-free, closed command mutation vocabulary.
#[derive(Debug)]
pub enum DeviceCommandMutation {
    /// Record publication.
    Publish(CurrentFence),
    /// Record device ACK receipt.
    AckReceived(CurrentFence),
    /// Record device rejection.
    Reject(CurrentFence),
    /// Record matching reported-state application evidence.
    Apply(MatchingReportedState),
    /// Record deadline expiry.
    Timeout(CurrentFence),
    /// Record a newer desired generation.
    Supersede(NewerGeneration),
    /// Record owner cancellation.
    Cancel(CurrentFence),
}

impl DeviceCommandMutation {
    /// Publication mutation.
    #[must_use]
    pub const fn publish(authority: CurrentFence) -> Self {
        Self::Publish(authority)
    }

    /// Device ACK mutation.
    #[must_use]
    pub const fn ack_received(authority: CurrentFence) -> Self {
        Self::AckReceived(authority)
    }

    /// Device rejection mutation.
    #[must_use]
    pub const fn reject(authority: CurrentFence) -> Self {
        Self::Reject(authority)
    }

    /// Matching report mutation.
    #[must_use]
    pub const fn apply(evidence: MatchingReportedState) -> Self {
        Self::Apply(evidence)
    }

    /// Timeout mutation.
    #[must_use]
    pub const fn timeout(authority: CurrentFence) -> Self {
        Self::Timeout(authority)
    }

    /// Supersession mutation.
    #[must_use]
    pub const fn supersede(evidence: NewerGeneration) -> Self {
        Self::Supersede(evidence)
    }

    /// Cancellation mutation.
    #[must_use]
    pub const fn cancel(authority: CurrentFence) -> Self {
        Self::Cancel(authority)
    }

    /// Stable low-cardinality label.
    #[must_use]
    pub const fn as_label(&self) -> &'static str {
        match self {
            Self::Publish(_) => "publish",
            Self::AckReceived(_) => "ack_received",
            Self::Reject(_) => "reject",
            Self::Apply(_) => "apply",
            Self::Timeout(_) => "timeout",
            Self::Supersede(_) => "supersede",
            Self::Cancel(_) => "cancel",
        }
    }

    /// Apply the canonical Rust FSM at provider-owned transaction time.
    pub fn apply_to(
        self,
        state: DeviceCommandState,
        at: SystemTime,
    ) -> Result<crate::DeviceCommandTransition, crate::DeviceCommandTransitionError> {
        match self {
            Self::Publish(authority) => state.publish(authority, at),
            Self::AckReceived(authority) => state.ack_received(authority, at),
            Self::Reject(authority) => state.reject(authority, at),
            Self::Apply(evidence) => state.apply(evidence, at),
            Self::Timeout(authority) => state.timeout(authority, at),
            Self::Supersede(evidence) => state.supersede(evidence, at),
            Self::Cancel(authority) => state.cancel(authority, at),
        }
    }
}

/// Closed result of command creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateDeviceCommandOutcome {
    /// A new queued aggregate was inserted.
    Created(DeviceCommandSnapshot),
    /// The exact same command identity and immutable input already exist.
    Replay(DeviceCommandSnapshot),
    /// The command identity already names different immutable input.
    IdentityConflict,
    /// Another nonterminal command owns the canonical active coordinate and intent.
    ActiveConflict {
        /// Existing canonical command identity.
        command_id: DeviceCommandId,
    },
}

/// Closed result of an optimistic transition attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitionDeviceCommandOutcome {
    /// State and version advanced.
    Advanced(DeviceCommandSnapshot),
    /// Canonical FSM classified a stable zero-write result.
    NoChange {
        /// Persisted state, unchanged.
        snapshot: DeviceCommandSnapshot,
        /// Duplicate, late, or out-of-order classification.
        outcome: CommandTransitionOutcome,
    },
    /// The command identity is absent in the authorized scope.
    Missing,
    /// The expected version was stale or ahead; no row was written.
    VersionConflict {
        /// Actual persisted version.
        actual: CommandVersion,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DeviceIngressEvidenceKind {
    AckReceived {
        command_id: DeviceCommandId,
        coordinate: FenceCoordinate,
        sequence: DeviceSequence,
    },
    AckRejected {
        command_id: DeviceCommandId,
        coordinate: FenceCoordinate,
        sequence: DeviceSequence,
    },
    Report {
        observed_generation: ObservedGeneration,
        fence_epoch: FenceEpoch,
        sequence: DeviceSequence,
    },
}

/// Kind-specific append input. A report cannot accidentally carry a command id.
///
/// ```compile_fail
/// use deviceloop::DeviceIngressEvidence;
/// fn rewrite(mut evidence: DeviceIngressEvidence) {
///     evidence.kind = "report";
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceIngressEvidence {
    envelope_id: DeviceIngressEnvelopeId,
    fingerprint: DeviceIngressFingerprint,
    kind: DeviceIngressEvidenceKind,
}

impl DeviceIngressEvidence {
    /// Build device ACK-received evidence.
    #[must_use]
    pub fn ack_received(
        envelope_id: DeviceIngressEnvelopeId,
        command_id: DeviceCommandId,
        coordinate: FenceCoordinate,
        sequence: DeviceSequence,
        fingerprint: DeviceIngressFingerprint,
    ) -> Self {
        Self {
            envelope_id,
            fingerprint,
            kind: DeviceIngressEvidenceKind::AckReceived {
                command_id,
                coordinate,
                sequence,
            },
        }
    }

    /// Build device ACK-rejected evidence.
    #[must_use]
    pub fn ack_rejected(
        envelope_id: DeviceIngressEnvelopeId,
        command_id: DeviceCommandId,
        coordinate: FenceCoordinate,
        sequence: DeviceSequence,
        fingerprint: DeviceIngressFingerprint,
    ) -> Self {
        Self {
            envelope_id,
            fingerprint,
            kind: DeviceIngressEvidenceKind::AckRejected {
                command_id,
                coordinate,
                sequence,
            },
        }
    }

    /// Build reported-state evidence without a command identity.
    ///
    /// A desired write-authority coordinate cannot be substituted for observed generation:
    ///
    /// ```compile_fail
    /// use deviceloop::{DeviceIngressEnvelopeId, DeviceIngressEvidence, DeviceIngressFingerprint,
    ///     DeviceSequence, FenceCoordinate, FenceEpoch};
    /// fn forge(event: DeviceIngressEnvelopeId, desired: FenceCoordinate, epoch: FenceEpoch) {
    ///     let _ = DeviceIngressEvidence::report(
    ///         event,
    ///         desired,
    ///         epoch,
    ///         DeviceSequence::try_new(0).unwrap(),
    ///         DeviceIngressFingerprint::from_bytes([0; 32]),
    ///     );
    /// }
    /// ```
    #[must_use]
    pub fn report(
        envelope_id: DeviceIngressEnvelopeId,
        observed_generation: ObservedGeneration,
        fence_epoch: FenceEpoch,
        sequence: DeviceSequence,
        fingerprint: DeviceIngressFingerprint,
    ) -> Self {
        Self {
            envelope_id,
            fingerprint,
            kind: DeviceIngressEvidenceKind::Report {
                observed_generation,
                fence_epoch,
                sequence,
            },
        }
    }

    /// Stable envelope identity.
    #[must_use]
    pub const fn envelope_id(&self) -> &DeviceIngressEnvelopeId {
        &self.envelope_id
    }

    /// Exact semantic fingerprint.
    #[must_use]
    pub const fn fingerprint(&self) -> DeviceIngressFingerprint {
        self.fingerprint
    }

    /// Stable kind label.
    #[must_use]
    pub const fn kind_label(&self) -> &'static str {
        match self.kind {
            DeviceIngressEvidenceKind::AckReceived { .. } => "ack_received",
            DeviceIngressEvidenceKind::AckRejected { .. } => "ack_rejected",
            DeviceIngressEvidenceKind::Report { .. } => "report",
        }
    }

    /// Borrow the exhaustive persistence projection.
    #[must_use]
    pub fn view(&self) -> DeviceIngressEvidenceView<'_> {
        match &self.kind {
            DeviceIngressEvidenceKind::AckReceived {
                command_id,
                coordinate,
                sequence,
            } => DeviceIngressEvidenceView::AckReceived {
                command_id,
                coordinate: *coordinate,
                sequence: *sequence,
            },
            DeviceIngressEvidenceKind::AckRejected {
                command_id,
                coordinate,
                sequence,
            } => DeviceIngressEvidenceView::AckRejected {
                command_id,
                coordinate: *coordinate,
                sequence: *sequence,
            },
            DeviceIngressEvidenceKind::Report {
                observed_generation,
                fence_epoch,
                sequence,
            } => DeviceIngressEvidenceView::Report {
                observed_generation: *observed_generation,
                fence_epoch: *fence_epoch,
                sequence: *sequence,
            },
        }
    }
}

/// Exhaustive borrowed evidence projection for persistence adapters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceIngressEvidenceView<'a> {
    /// ACK confirming transport/device receipt.
    AckReceived {
        /// Bound command identity.
        command_id: &'a DeviceCommandId,
        /// Bound generation/fence.
        coordinate: FenceCoordinate,
        /// Device-local sequence.
        sequence: DeviceSequence,
    },
    /// ACK rejecting the command.
    AckRejected {
        /// Bound command identity.
        command_id: &'a DeviceCommandId,
        /// Bound generation/fence.
        coordinate: FenceCoordinate,
        /// Device-local sequence.
        sequence: DeviceSequence,
    },
    /// Device reported-state observation.
    Report {
        /// Generation observed by the device, never desired write authority.
        observed_generation: ObservedGeneration,
        /// Fence epoch reported with the observation.
        fence_epoch: FenceEpoch,
        /// Device-local sequence.
        sequence: DeviceSequence,
    },
}

/// Stable internal classification persisted with ingress evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeviceIngressDisposition {
    /// The command/report state advanced.
    Advanced,
    /// The event exactly repeated accepted state.
    Duplicate,
    /// The event arrived after a terminal command result.
    Late,
    /// The device explicitly rejected the command.
    Rejected,
    /// Tenant/device/command authority did not match.
    ScopeMismatch,
    /// The event requires an earlier protocol step or sequence.
    OutOfOrder,
}

impl DeviceIngressDisposition {
    /// Stable database label.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Advanced => "advanced",
            Self::Duplicate => "duplicate",
            Self::Late => "late",
            Self::Rejected => "rejected",
            Self::ScopeMismatch => "scope_mismatch",
            Self::OutOfOrder => "out_of_order",
        }
    }
}

/// Timestamp-free append request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendDeviceIngressEvidence {
    evidence: DeviceIngressEvidence,
    disposition: DeviceIngressDisposition,
}

impl AppendDeviceIngressEvidence {
    /// Bind immutable evidence to its closed internal classification.
    #[must_use]
    pub const fn new(
        evidence: DeviceIngressEvidence,
        disposition: DeviceIngressDisposition,
    ) -> Self {
        Self {
            evidence,
            disposition,
        }
    }

    /// Immutable envelope evidence.
    #[must_use]
    pub const fn evidence(&self) -> &DeviceIngressEvidence {
        &self.evidence
    }

    /// Internal outcome classification.
    #[must_use]
    pub const fn disposition(&self) -> DeviceIngressDisposition {
        self.disposition
    }
}

/// Restored immutable ingress receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceIngressReceipt {
    evidence: DeviceIngressEvidence,
    disposition: DeviceIngressDisposition,
    received_at: SystemTime,
    committed_at: SystemTime,
}

impl DeviceIngressReceipt {
    /// Restore provider-owned timestamps through a validating funnel.
    pub fn restore(
        evidence: DeviceIngressEvidence,
        disposition: DeviceIngressDisposition,
        received_at: SystemTime,
        committed_at: SystemTime,
    ) -> Result<Self, DeviceIngressError> {
        if committed_at < received_at {
            return Err(DeviceIngressError::InvalidTimestampOrder);
        }
        Ok(Self {
            evidence,
            disposition,
            received_at,
            committed_at,
        })
    }

    /// Immutable envelope evidence.
    #[must_use]
    pub const fn evidence(&self) -> &DeviceIngressEvidence {
        &self.evidence
    }

    /// Persisted internal disposition.
    #[must_use]
    pub const fn disposition(&self) -> DeviceIngressDisposition {
        self.disposition
    }

    /// Database receive time.
    #[must_use]
    pub const fn received_at(&self) -> SystemTime {
        self.received_at
    }

    /// Database commit-candidate time captured in the same transaction.
    #[must_use]
    pub const fn committed_at(&self) -> SystemTime {
        self.committed_at
    }
}

/// Closed append-once outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppendDeviceIngressOutcome {
    /// Evidence was appended for the first time.
    Appended(DeviceIngressReceipt),
    /// The exact immutable event already exists.
    Replay(DeviceIngressReceipt),
    /// The tenant-local envelope id was reused with different immutable evidence.
    Conflict,
}

/// Closed low-cardinality reason for a corrupt command row.
#[derive(Debug, thiserror::Error)]
pub enum DeviceCommandCorruption {
    /// A persisted identity was not canonical.
    #[error("persisted command identity is invalid")]
    Identity,
    /// A generation, fence, or version coordinate was invalid.
    #[error("persisted command coordinate is invalid")]
    Coordinate,
    /// The semantic digest had the wrong width.
    #[error("persisted command digest is invalid")]
    Digest,
    /// A timestamp was outside the canonical representation.
    #[error("persisted command timestamp is invalid")]
    Timestamp,
    /// Nullable columns did not match the closed state shape.
    #[error("persisted command row shape is invalid")]
    Shape,
    /// The state label was outside the closed vocabulary.
    #[error("persisted command state is invalid")]
    State,
    /// The restored state violated the canonical state machine.
    #[error("persisted command state violates domain invariants")]
    Domain(#[source] DeviceCommandError),
}

/// Closed low-cardinality reason for a corrupt ingress row.
#[derive(Debug, thiserror::Error)]
pub enum DeviceIngressCorruption {
    /// A persisted envelope, command, or device identity was invalid.
    #[error("persisted ingress identity is invalid")]
    Identity,
    /// A generation, fence, or sequence coordinate was invalid.
    #[error("persisted ingress coordinate is invalid")]
    Coordinate,
    /// The semantic fingerprint had the wrong width.
    #[error("persisted ingress fingerprint is invalid")]
    Fingerprint,
    /// A timestamp was outside the canonical representation.
    #[error("persisted ingress timestamp is invalid")]
    Timestamp,
    /// Kind-specific nullable columns did not match the closed evidence shape.
    #[error("persisted ingress row shape is invalid")]
    Shape,
    /// The kind or disposition label was outside its closed vocabulary.
    #[error("persisted ingress vocabulary is invalid")]
    Vocabulary,
    /// Restored evidence violated provider-neutral ingress invariants.
    #[error("persisted ingress evidence violates domain invariants")]
    Domain(#[source] DeviceIngressError),
}

/// Infrastructure or mutation failure at the durable command boundary.
#[derive(Debug, thiserror::Error)]
pub enum DeviceCommandStoreError {
    /// The authenticated capability does not match the sealed input scope.
    #[error("device command scope does not match authenticated capability")]
    ScopeMismatch,
    /// The canonical state machine rejected a create or transition request.
    #[error("device command mutation was rejected")]
    MutationRejected(#[source] DeviceCommandError),
    /// A database result contradicted an invariant already established in the transaction.
    #[error("device command storage invariant was violated")]
    InvariantViolation,
    /// A transient provider failure may be retried under a bounded caller policy.
    #[error("device command storage is transiently unavailable")]
    StorageTransient {
        /// Redacted provider source; its source chain terminates here.
        #[source]
        source: diport::RedactedSource,
    },
    /// A permanent provider failure must not be retried unchanged.
    #[error("device command storage rejected the operation permanently")]
    StoragePermanent {
        /// Redacted provider source; its source chain terminates here.
        #[source]
        source: diport::RedactedSource,
    },
    /// Commit acknowledgement was lost or rollback failed; replay is unsafe without reconciliation.
    #[error("device command transaction settlement is unknown")]
    SettlementUnknown {
        /// Redacted settlement source; its source chain terminates here.
        #[source]
        source: diport::RedactedSource,
    },
    /// A command row failed the canonical restore funnel.
    #[error("device command storage returned invalid command state")]
    CorruptCommand(#[source] DeviceCommandCorruption),
    /// An ingress row failed the canonical restore funnel.
    #[error("device command storage returned invalid ingress evidence")]
    CorruptIngress(#[source] DeviceIngressCorruption),
}

impl DeviceCommandStoreError {
    /// Wrap a transient provider error behind the shared write-only redaction boundary.
    pub fn storage_transient(source: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::StorageTransient {
            source: diport::RedactedSource::new(source),
        }
    }

    /// Wrap a permanent provider error behind the shared write-only redaction boundary.
    pub fn storage_permanent(source: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::StoragePermanent {
            source: diport::RedactedSource::new(source),
        }
    }

    /// Reclassify an unsafe settlement without exposing the original provider error.
    pub fn settlement_unknown(source: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::SettlementUnknown {
            source: diport::RedactedSource::new(source),
        }
    }
}

/// Durable command aggregate and append-once ingress-evidence port.
///
/// Production providers bind `Scope` to an authenticated opaque capability. This service-layer
/// trait intentionally has no dynamic wrapper or in-memory production implementation.
#[allow(async_fn_in_trait)]
pub trait DeviceCommandStore: Send + Sync {
    /// Provider-specific authenticated scope capability.
    type Scope: Send;

    /// Create the canonical queued aggregate at database transaction time.
    async fn create_command(
        &self,
        scope: Self::Scope,
        input: CreateDeviceCommand,
    ) -> Result<CreateDeviceCommandOutcome, DeviceCommandStoreError>;

    /// Apply a canonical FSM transition under optimistic version control.
    async fn transition_command(
        &self,
        scope: Self::Scope,
        command_id: DeviceCommandId,
        expected: CommandVersion,
        mutation: DeviceCommandMutation,
    ) -> Result<TransitionDeviceCommandOutcome, DeviceCommandStoreError>;

    /// Load one validated command aggregate.
    async fn load_command(
        &self,
        scope: Self::Scope,
        command_id: DeviceCommandId,
    ) -> Result<Option<DeviceCommandSnapshot>, DeviceCommandStoreError>;

    /// Append immutable ingress evidence or classify an idempotent replay/conflict.
    async fn append_ingress_evidence(
        &self,
        scope: Self::Scope,
        input: AppendDeviceIngressEvidence,
    ) -> Result<AppendDeviceIngressOutcome, DeviceCommandStoreError>;

    /// Load immutable ingress evidence by tenant-local envelope identity.
    async fn load_ingress_evidence(
        &self,
        scope: Self::Scope,
        envelope_id: DeviceIngressEnvelopeId,
    ) -> Result<Option<DeviceIngressReceipt>, DeviceCommandStoreError>;
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[derive(Debug, thiserror::Error)]
    #[error("sensitive-provider-marker")]
    struct SensitiveProviderError;

    #[test]
    fn receipt_restore_rejects_reversed_server_time() {
        let evidence = DeviceIngressEvidence::report(
            DeviceIngressEnvelopeId::parse("report-1").expect("id"),
            ObservedGeneration::try_new(1).expect("generation"),
            FenceEpoch::try_new(1).expect("epoch"),
            DeviceSequence::try_new(1).expect("sequence"),
            DeviceIngressFingerprint::from_bytes([1; 32]),
        );
        assert_eq!(
            DeviceIngressReceipt::restore(
                evidence,
                DeviceIngressDisposition::Advanced,
                SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(2),
                SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1),
            ),
            Err(DeviceIngressError::InvalidTimestampOrder)
        );
    }

    #[test]
    fn provider_error_source_is_redacted_and_chain_terminates() {
        let error = DeviceCommandStoreError::storage_transient(SensitiveProviderError);
        assert_eq!(
            error.to_string(),
            "device command storage is transiently unavailable"
        );
        assert!(!format!("{error:?}").contains("sensitive-provider-marker"));
        let source = std::error::Error::source(&error).expect("redacted source");
        assert_eq!(source.to_string(), "<redacted>");
        assert!(source.source().is_none());
    }
}
