//! Closed device-condition vocabulary.
//!
//! Conditions and their persistence representations are sum types, so each
//! condition kind can carry only its own reason vocabulary. Trusted snapshots
//! preserve every domain invariant. Untrusted persisted values enter through
//! [`DeviceConditionRestore`] and the single fallible [`DeviceCondition::restore`]
//! funnel.

use std::time::SystemTime;

use crate::generation::{DesiredGeneration, ObservedGeneration};

/// Status shared by condition variants other than `Ready`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionStatus {
    /// The condition is satisfied.
    True,
    /// The condition is not satisfied.
    False,
    /// The controller cannot currently determine the condition.
    Unknown,
}

impl ConditionStatus {
    /// Every status in declaration order.
    pub const ALL: [Self; 3] = [Self::True, Self::False, Self::Unknown];

    /// Return the stable external label.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::True => "True",
            Self::False => "False",
            Self::Unknown => "Unknown",
        }
    }
}

/// The only statuses constructible for `Ready` before the complete readiness proof exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotReadyStatus {
    /// Readiness is known not to hold.
    False,
    /// Readiness cannot currently be determined.
    Unknown,
}

impl NotReadyStatus {
    /// Every permitted `Ready` status in declaration order.
    pub const ALL: [Self; 2] = [Self::False, Self::Unknown];

    /// Return the stable external label.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::False => "False",
            Self::Unknown => "Unknown",
        }
    }
}

impl From<NotReadyStatus> for ConditionStatus {
    fn from(value: NotReadyStatus) -> Self {
        match value {
            NotReadyStatus::False => Self::False,
            NotReadyStatus::Unknown => Self::Unknown,
        }
    }
}

/// Closed readiness status. `True` is only produced by a validated [`ReadyProof`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadyStatus {
    /// Complete current evidence proves convergence.
    True,
    /// Readiness is known not to hold.
    False,
    /// Readiness cannot currently be determined.
    Unknown,
}

impl ReadyStatus {
    /// Return the stable external label.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::True => "True",
            Self::False => "False",
            Self::Unknown => "Unknown",
        }
    }
}

impl From<NotReadyStatus> for ReadyStatus {
    fn from(value: NotReadyStatus) -> Self {
        match value {
            NotReadyStatus::False => Self::False,
            NotReadyStatus::Unknown => Self::Unknown,
        }
    }
}

impl From<ReadyStatus> for ConditionStatus {
    fn from(value: ReadyStatus) -> Self {
        match value {
            ReadyStatus::True => Self::True,
            ReadyStatus::False => Self::False,
            ReadyStatus::Unknown => Self::Unknown,
        }
    }
}

macro_rules! readiness_digest {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, PartialEq, Eq)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Bind an already-validated SHA-256 value to its evidence role.
            #[must_use]
            pub const fn new(value: [u8; 32]) -> Self {
                Self(value)
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str(concat!(stringify!($name), "(<sha256>)"))
            }
        }
    };
}

readiness_digest!(
    ExpectedStateHash,
    "Desired state hash used by readiness validation."
);
readiness_digest!(
    ReportedStateHash,
    "Device-reported state hash used by readiness validation."
);
readiness_digest!(
    AuthorizedArtifactDigest,
    "Authorized certificate artifact digest."
);
readiness_digest!(
    ReportedArtifactDigest,
    "Device-reported certificate artifact digest."
);

/// Current revocation evidence for the authorized certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurrentCertificateStatus {
    /// The current revocation authority reports the certificate as non-revoked.
    NonRevoked,
    /// The current revocation authority reports the certificate as revoked.
    Revoked,
}

/// Current command evidence relevant to a readiness decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateCommandState {
    /// No conflicting update command exists.
    Absent,
    /// An update command conflicts with the otherwise matching report.
    Conflicting,
}

/// Complete evidence required to construct `Ready=True`.
///
/// Fields are private and the value is not cloneable, so callers can only obtain it from the
/// validating funnel and consume it once into a condition value.
///
/// ```compile_fail
/// use deviceloop::ReadyProof;
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<ReadyProof>();
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct ReadyProof {
    observed_generation: ObservedGeneration,
}

impl ReadyProof {
    /// Validate all generation, state, artifact, time, revocation, and command evidence.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        desired_generation: DesiredGeneration,
        reported_generation: ObservedGeneration,
        expected_state_hash: ExpectedStateHash,
        reported_state_hash: ReportedStateHash,
        authorized_artifact_digest: AuthorizedArtifactDigest,
        reported_artifact_digest: ReportedArtifactDigest,
        authoritative_now: SystemTime,
        not_after: SystemTime,
        certificate_status: CurrentCertificateStatus,
        update_command_state: UpdateCommandState,
    ) -> Result<Self, ReadyProofError> {
        if desired_generation.get() != reported_generation.get() {
            return Err(ReadyProofError::GenerationMismatch);
        }
        if expected_state_hash.0 != reported_state_hash.0 {
            return Err(ReadyProofError::StateHashMismatch);
        }
        if authorized_artifact_digest.0 != reported_artifact_digest.0 {
            return Err(ReadyProofError::ArtifactDigestMismatch);
        }
        if authoritative_now >= not_after {
            return Err(ReadyProofError::Expired);
        }
        if certificate_status == CurrentCertificateStatus::Revoked {
            return Err(ReadyProofError::Revoked);
        }
        if update_command_state == UpdateCommandState::Conflicting {
            return Err(ReadyProofError::ConflictingUpdateCommand);
        }
        Ok(Self {
            observed_generation: reported_generation,
        })
    }
}

/// Complete readiness evidence failed validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReadyProofError {
    /// Desired and reported generations differ.
    #[error("desired and reported generations differ")]
    GenerationMismatch,
    /// Expected and reported state hashes differ.
    #[error("expected and reported state hashes differ")]
    StateHashMismatch,
    /// Authorized and reported artifact digests differ.
    #[error("authorized and reported artifact digests differ")]
    ArtifactDigestMismatch,
    /// The authoritative time is at or beyond certificate expiry.
    #[error("certificate is expired")]
    Expired,
    /// Current revocation evidence reports the certificate as revoked.
    #[error("certificate is revoked")]
    Revoked,
    /// A conflicting update command exists.
    #[error("conflicting update command exists")]
    ConflictingUpdateCommand,
}

/// The six closed condition variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceConditionKind {
    /// Whether the device is ready for use.
    Ready,
    /// Whether desired state is actively converging.
    Reconciling,
    /// Whether progress is waiting on the device.
    PendingDevice,
    /// Whether service is impaired.
    Degraded,
    /// Whether the device is isolated from normal operation.
    Quarantined,
    /// Whether deletion is in progress or complete.
    Deleting,
}

impl DeviceConditionKind {
    /// Every condition kind in declaration order.
    pub const ALL: [Self; 6] = [
        Self::Ready,
        Self::Reconciling,
        Self::PendingDevice,
        Self::Degraded,
        Self::Quarantined,
        Self::Deleting,
    ];

    /// Return the stable external label.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Ready => "Ready",
            Self::Reconciling => "Reconciling",
            Self::PendingDevice => "PendingDevice",
            Self::Degraded => "Degraded",
            Self::Quarantined => "Quarantined",
            Self::Deleting => "Deleting",
        }
    }
}

/// Closed reasons for the `Ready` condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadyReason {
    /// Reported state matches desired state.
    StateMatches,
    /// Reported state differs from desired state.
    StateDrift,
    /// The controller is waiting for a device report.
    AwaitingDevice,
    /// The device rejected the command.
    CommandRejected,
    /// The command exceeded its deadline.
    CommandTimedOut,
    /// A protocol invariant was violated.
    ProtocolViolation,
    /// A required artifact is unavailable.
    ArtifactUnavailable,
    /// The device transport is unavailable.
    TransportUnavailable,
}

impl ReadyReason {
    /// Every `Ready` reason in declaration order.
    pub const ALL: [Self; 8] = [
        Self::StateMatches,
        Self::StateDrift,
        Self::AwaitingDevice,
        Self::CommandRejected,
        Self::CommandTimedOut,
        Self::ProtocolViolation,
        Self::ArtifactUnavailable,
        Self::TransportUnavailable,
    ];

    /// Return the stable external label.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::StateMatches => "StateMatches",
            Self::StateDrift => "StateDrift",
            Self::AwaitingDevice => "AwaitingDevice",
            Self::CommandRejected => "CommandRejected",
            Self::CommandTimedOut => "CommandTimedOut",
            Self::ProtocolViolation => "ProtocolViolation",
            Self::ArtifactUnavailable => "ArtifactUnavailable",
            Self::TransportUnavailable => "TransportUnavailable",
        }
    }
}

/// Closed reasons for the `Reconciling` condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcilingReason {
    /// A new desired generation was accepted.
    DesiredAccepted,
    /// A command was queued for publication.
    CommandQueued,
    /// A device report was accepted.
    DeviceReported,
    /// Reported state differs from desired state.
    StateDrift,
}

impl ReconcilingReason {
    /// Every `Reconciling` reason in declaration order.
    pub const ALL: [Self; 4] = [
        Self::DesiredAccepted,
        Self::CommandQueued,
        Self::DeviceReported,
        Self::StateDrift,
    ];

    /// Return the stable external label.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::DesiredAccepted => "DesiredAccepted",
            Self::CommandQueued => "CommandQueued",
            Self::DeviceReported => "DeviceReported",
            Self::StateDrift => "StateDrift",
        }
    }
}

/// Closed reasons for the `PendingDevice` condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingDeviceReason {
    /// A command is waiting to be published.
    CommandQueued,
    /// The controller is waiting for a device report.
    AwaitingDevice,
    /// The command exceeded its deadline.
    CommandTimedOut,
    /// The device transport is unavailable.
    TransportUnavailable,
}

impl PendingDeviceReason {
    /// Every `PendingDevice` reason in declaration order.
    pub const ALL: [Self; 4] = [
        Self::CommandQueued,
        Self::AwaitingDevice,
        Self::CommandTimedOut,
        Self::TransportUnavailable,
    ];

    /// Return the stable external label.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::CommandQueued => "CommandQueued",
            Self::AwaitingDevice => "AwaitingDevice",
            Self::CommandTimedOut => "CommandTimedOut",
            Self::TransportUnavailable => "TransportUnavailable",
        }
    }
}

/// Closed reasons for the `Degraded` condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DegradedReason {
    /// The device rejected the command.
    CommandRejected,
    /// The command exceeded its deadline.
    CommandTimedOut,
    /// A protocol invariant was violated.
    ProtocolViolation,
    /// A required artifact is unavailable.
    ArtifactUnavailable,
    /// The device transport is unavailable.
    TransportUnavailable,
}

impl DegradedReason {
    /// Every `Degraded` reason in declaration order.
    pub const ALL: [Self; 5] = [
        Self::CommandRejected,
        Self::CommandTimedOut,
        Self::ProtocolViolation,
        Self::ArtifactUnavailable,
        Self::TransportUnavailable,
    ];

    /// Return the stable external label.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::CommandRejected => "CommandRejected",
            Self::CommandTimedOut => "CommandTimedOut",
            Self::ProtocolViolation => "ProtocolViolation",
            Self::ArtifactUnavailable => "ArtifactUnavailable",
            Self::TransportUnavailable => "TransportUnavailable",
        }
    }
}

/// Closed reasons for the `Quarantined` condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuarantinedReason {
    /// A protocol invariant was violated.
    ProtocolViolation,
    /// An operator explicitly quarantined the device.
    QuarantinedByOperator,
}

impl QuarantinedReason {
    /// Every `Quarantined` reason in declaration order.
    pub const ALL: [Self; 2] = [Self::ProtocolViolation, Self::QuarantinedByOperator];

    /// Return the stable external label.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::ProtocolViolation => "ProtocolViolation",
            Self::QuarantinedByOperator => "QuarantinedByOperator",
        }
    }
}

/// Closed reasons for the `Deleting` condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeletingReason {
    /// Deletion has not yet converged.
    DeletionPending,
    /// Deletion has converged.
    DeletionComplete,
}

impl DeletingReason {
    /// Every `Deleting` reason in declaration order.
    pub const ALL: [Self; 2] = [Self::DeletionPending, Self::DeletionComplete];

    /// Return the stable external label.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::DeletionPending => "DeletionPending",
            Self::DeletionComplete => "DeletionComplete",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConditionData<S, R> {
    status: S,
    reason: R,
    observed_generation: Option<ObservedGeneration>,
    last_transition_time: SystemTime,
}

macro_rules! condition_payload {
    ($(#[$meta:meta])* $name:ident, $status:ty, $reason:ty) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name(ConditionData<$status, $reason>);

        impl $name {
            /// Return the condition status.
            #[must_use]
            pub const fn status(&self) -> $status { self.0.status }

            /// Return the condition reason.
            #[must_use]
            pub const fn reason(&self) -> $reason { self.0.reason }

            /// Return the reported generation associated with this condition.
            #[must_use]
            pub const fn observed_generation(&self) -> Option<ObservedGeneration> {
                self.0.observed_generation
            }

            /// Return the server timestamp of the most recent transition.
            #[must_use]
            pub const fn last_transition_time(&self) -> SystemTime {
                self.0.last_transition_time
            }
        }
    };
}

condition_payload!(
    /// Payload for a `Ready` condition.
    ReadyCondition,
    ReadyStatus,
    ReadyReason
);
condition_payload!(
    /// Payload for a `Reconciling` condition.
    ReconcilingCondition,
    ConditionStatus,
    ReconcilingReason
);
condition_payload!(
    /// Payload for a `PendingDevice` condition.
    PendingDeviceCondition,
    ConditionStatus,
    PendingDeviceReason
);
condition_payload!(
    /// Payload for a `Degraded` condition.
    DegradedCondition,
    ConditionStatus,
    DegradedReason
);
condition_payload!(
    /// Payload for a `Quarantined` condition.
    QuarantinedCondition,
    ConditionStatus,
    QuarantinedReason
);
condition_payload!(
    /// Payload for a `Deleting` condition.
    DeletingCondition,
    ConditionStatus,
    DeletingReason
);

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConditionStateData<S, R> {
    status: S,
    reason: R,
    observed_generation: Option<ObservedGeneration>,
}

macro_rules! condition_state_payload {
    ($(#[$meta:meta])* $name:ident, $status:ty, $reason:ty) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name(ConditionStateData<$status, $reason>);

        impl $name {
            /// Return the closed status.
            #[must_use]
            pub const fn status(&self) -> $status { self.0.status }

            /// Return the kind-specific reason.
            #[must_use]
            pub const fn reason(&self) -> $reason { self.0.reason }

            /// Return the optional reported generation coordinate.
            #[must_use]
            pub const fn observed_generation(&self) -> Option<ObservedGeneration> {
                self.0.observed_generation
            }
        }
    };
}

condition_state_payload!(
    /// Timestamp-free desired state for a `Ready` condition.
    ReadyConditionState,
    ReadyStatus,
    ReadyReason
);
condition_state_payload!(
    /// Timestamp-free desired state for a `Reconciling` condition.
    ReconcilingConditionState,
    ConditionStatus,
    ReconcilingReason
);
condition_state_payload!(
    /// Timestamp-free desired state for a `PendingDevice` condition.
    PendingDeviceConditionState,
    ConditionStatus,
    PendingDeviceReason
);
condition_state_payload!(
    /// Timestamp-free desired state for a `Degraded` condition.
    DegradedConditionState,
    ConditionStatus,
    DegradedReason
);
condition_state_payload!(
    /// Timestamp-free desired state for a `Quarantined` condition.
    QuarantinedConditionState,
    ConditionStatus,
    QuarantinedReason
);
condition_state_payload!(
    /// Timestamp-free desired state for a `Deleting` condition.
    DeletingConditionState,
    ConditionStatus,
    DeletingReason
);

/// Closed condition mutation state. Server transition time is deliberately absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceConditionState {
    /// Readiness state; its true case is only constructible from complete evidence.
    Ready(ReadyConditionState),
    /// Reconciliation state.
    Reconciling(ReconcilingConditionState),
    /// Waiting-on-device state.
    PendingDevice(PendingDeviceConditionState),
    /// Degradation state.
    Degraded(DegradedConditionState),
    /// Quarantine state.
    Quarantined(QuarantinedConditionState),
    /// Deletion state.
    Deleting(DeletingConditionState),
}

impl DeviceConditionState {
    /// Construct a not-ready state without accepting a timestamp.
    #[must_use]
    pub fn ready(
        status: NotReadyStatus,
        reason: ReadyReason,
        observed_generation: Option<ObservedGeneration>,
    ) -> Self {
        Self::Ready(ReadyConditionState(ConditionStateData {
            status: status.into(),
            reason,
            observed_generation,
        }))
    }

    /// Construct `Ready=True` from complete validated evidence.
    #[must_use]
    pub fn ready_true(proof: ReadyProof) -> Self {
        Self::Ready(ReadyConditionState(ConditionStateData {
            status: ReadyStatus::True,
            reason: ReadyReason::StateMatches,
            observed_generation: Some(proof.observed_generation),
        }))
    }

    /// Construct a reconciliation state.
    #[must_use]
    pub fn reconciling(
        status: ConditionStatus,
        reason: ReconcilingReason,
        observed_generation: Option<ObservedGeneration>,
    ) -> Self {
        Self::Reconciling(ReconcilingConditionState(ConditionStateData {
            status,
            reason,
            observed_generation,
        }))
    }

    /// Construct a waiting-on-device state.
    #[must_use]
    pub fn pending_device(
        status: ConditionStatus,
        reason: PendingDeviceReason,
        observed_generation: Option<ObservedGeneration>,
    ) -> Self {
        Self::PendingDevice(PendingDeviceConditionState(ConditionStateData {
            status,
            reason,
            observed_generation,
        }))
    }

    /// Construct a degradation state.
    #[must_use]
    pub fn degraded(
        status: ConditionStatus,
        reason: DegradedReason,
        observed_generation: Option<ObservedGeneration>,
    ) -> Self {
        Self::Degraded(DegradedConditionState(ConditionStateData {
            status,
            reason,
            observed_generation,
        }))
    }

    /// Construct a quarantine state.
    #[must_use]
    pub fn quarantined(
        status: ConditionStatus,
        reason: QuarantinedReason,
        observed_generation: Option<ObservedGeneration>,
    ) -> Self {
        Self::Quarantined(QuarantinedConditionState(ConditionStateData {
            status,
            reason,
            observed_generation,
        }))
    }

    /// Construct a deletion state.
    #[must_use]
    pub fn deleting(
        status: ConditionStatus,
        reason: DeletingReason,
        observed_generation: Option<ObservedGeneration>,
    ) -> Self {
        Self::Deleting(DeletingConditionState(ConditionStateData {
            status,
            reason,
            observed_generation,
        }))
    }

    /// Closed condition kind.
    #[must_use]
    pub const fn kind(&self) -> DeviceConditionKind {
        match self {
            Self::Ready(_) => DeviceConditionKind::Ready,
            Self::Reconciling(_) => DeviceConditionKind::Reconciling,
            Self::PendingDevice(_) => DeviceConditionKind::PendingDevice,
            Self::Degraded(_) => DeviceConditionKind::Degraded,
            Self::Quarantined(_) => DeviceConditionKind::Quarantined,
            Self::Deleting(_) => DeviceConditionKind::Deleting,
        }
    }

    /// Stable status label for persistence lowering.
    #[must_use]
    pub const fn status_label(&self) -> &'static str {
        match self {
            Self::Ready(value) => value.status().as_label(),
            Self::Reconciling(value) => value.status().as_label(),
            Self::PendingDevice(value) => value.status().as_label(),
            Self::Degraded(value) => value.status().as_label(),
            Self::Quarantined(value) => value.status().as_label(),
            Self::Deleting(value) => value.status().as_label(),
        }
    }

    /// Stable kind-specific reason label for persistence lowering.
    #[must_use]
    pub const fn reason_label(&self) -> &'static str {
        match self {
            Self::Ready(value) => value.reason().as_label(),
            Self::Reconciling(value) => value.reason().as_label(),
            Self::PendingDevice(value) => value.reason().as_label(),
            Self::Degraded(value) => value.reason().as_label(),
            Self::Quarantined(value) => value.reason().as_label(),
            Self::Deleting(value) => value.reason().as_label(),
        }
    }

    /// Optional observed generation represented by this state.
    #[must_use]
    pub const fn observed_generation(&self) -> Option<ObservedGeneration> {
        match self {
            Self::Ready(value) => value.observed_generation(),
            Self::Reconciling(value) => value.observed_generation(),
            Self::PendingDevice(value) => value.observed_generation(),
            Self::Degraded(value) => value.observed_generation(),
            Self::Quarantined(value) => value.observed_generation(),
            Self::Deleting(value) => value.observed_generation(),
        }
    }

    /// Combine semantic state with the authoritative server transition time.
    #[must_use]
    pub fn at(self, last_transition_time: SystemTime) -> DeviceCondition {
        match self {
            Self::Ready(value) => DeviceCondition::ready_status(
                value.status(),
                value.reason(),
                value.observed_generation(),
                last_transition_time,
            ),
            Self::Reconciling(value) => DeviceCondition::reconciling(
                value.status(),
                value.reason(),
                value.observed_generation(),
                last_transition_time,
            ),
            Self::PendingDevice(value) => DeviceCondition::pending_device(
                value.status(),
                value.reason(),
                value.observed_generation(),
                last_transition_time,
            ),
            Self::Degraded(value) => DeviceCondition::degraded(
                value.status(),
                value.reason(),
                value.observed_generation(),
                last_transition_time,
            ),
            Self::Quarantined(value) => DeviceCondition::quarantined(
                value.status(),
                value.reason(),
                value.observed_generation(),
                last_transition_time,
            ),
            Self::Deleting(value) => DeviceCondition::deleting(
                value.status(),
                value.reason(),
                value.observed_generation(),
                last_transition_time,
            ),
        }
    }
}

/// A condition whose variant statically selects the permitted reason set.
///
/// `Ready=True` is intentionally not expressible through the not-ready constructor:
///
/// ```compile_fail
/// use deviceloop::condition::{ConditionStatus, DeviceCondition, ReadyReason};
/// use std::time::SystemTime;
///
/// DeviceCondition::ready(
///     ConditionStatus::True,
///     ReadyReason::StateMatches,
///     None,
///     SystemTime::UNIX_EPOCH,
/// );
/// ```
///
/// A reason from another variant cannot be attached to `Ready`:
///
/// ```compile_fail
/// use deviceloop::condition::{DegradedReason, DeviceCondition, NotReadyStatus};
/// use std::time::SystemTime;
///
/// DeviceCondition::ready(
///     NotReadyStatus::False,
///     DegradedReason::ProtocolViolation,
///     None,
///     SystemTime::UNIX_EPOCH,
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceCondition {
    /// Readiness condition.
    Ready(ReadyCondition),
    /// Active reconciliation condition.
    Reconciling(ReconcilingCondition),
    /// Waiting-on-device condition.
    PendingDevice(PendingDeviceCondition),
    /// Service degradation condition.
    Degraded(DegradedCondition),
    /// Device quarantine condition.
    Quarantined(QuarantinedCondition),
    /// Device deletion condition.
    Deleting(DeletingCondition),
}

impl DeviceCondition {
    /// Construct a `Ready` condition that cannot claim readiness.
    #[must_use]
    pub fn ready(
        status: NotReadyStatus,
        reason: ReadyReason,
        observed_generation: Option<ObservedGeneration>,
        last_transition_time: SystemTime,
    ) -> Self {
        Self::Ready(ReadyCondition(ConditionData {
            status: status.into(),
            reason,
            observed_generation,
            last_transition_time,
        }))
    }

    /// Construct `Ready=True` from complete validated evidence.
    #[must_use]
    pub fn ready_true(proof: ReadyProof, last_transition_time: SystemTime) -> Self {
        Self::ready_status(
            ReadyStatus::True,
            ReadyReason::StateMatches,
            Some(proof.observed_generation),
            last_transition_time,
        )
    }

    fn ready_status(
        status: ReadyStatus,
        reason: ReadyReason,
        observed_generation: Option<ObservedGeneration>,
        last_transition_time: SystemTime,
    ) -> Self {
        Self::Ready(ReadyCondition(ConditionData {
            status,
            reason,
            observed_generation,
            last_transition_time,
        }))
    }

    /// Construct a `Reconciling` condition.
    #[must_use]
    pub fn reconciling(
        status: ConditionStatus,
        reason: ReconcilingReason,
        observed_generation: Option<ObservedGeneration>,
        last_transition_time: SystemTime,
    ) -> Self {
        Self::Reconciling(ReconcilingCondition(ConditionData {
            status,
            reason,
            observed_generation,
            last_transition_time,
        }))
    }

    /// Construct a `PendingDevice` condition.
    #[must_use]
    pub fn pending_device(
        status: ConditionStatus,
        reason: PendingDeviceReason,
        observed_generation: Option<ObservedGeneration>,
        last_transition_time: SystemTime,
    ) -> Self {
        Self::PendingDevice(PendingDeviceCondition(ConditionData {
            status,
            reason,
            observed_generation,
            last_transition_time,
        }))
    }

    /// Construct a `Degraded` condition.
    #[must_use]
    pub fn degraded(
        status: ConditionStatus,
        reason: DegradedReason,
        observed_generation: Option<ObservedGeneration>,
        last_transition_time: SystemTime,
    ) -> Self {
        Self::Degraded(DegradedCondition(ConditionData {
            status,
            reason,
            observed_generation,
            last_transition_time,
        }))
    }

    /// Construct a `Quarantined` condition.
    #[must_use]
    pub fn quarantined(
        status: ConditionStatus,
        reason: QuarantinedReason,
        observed_generation: Option<ObservedGeneration>,
        last_transition_time: SystemTime,
    ) -> Self {
        Self::Quarantined(QuarantinedCondition(ConditionData {
            status,
            reason,
            observed_generation,
            last_transition_time,
        }))
    }

    /// Construct a `Deleting` condition.
    #[must_use]
    pub fn deleting(
        status: ConditionStatus,
        reason: DeletingReason,
        observed_generation: Option<ObservedGeneration>,
        last_transition_time: SystemTime,
    ) -> Self {
        Self::Deleting(DeletingCondition(ConditionData {
            status,
            reason,
            observed_generation,
            last_transition_time,
        }))
    }

    /// Return the closed condition kind.
    #[must_use]
    pub const fn kind(&self) -> DeviceConditionKind {
        match self {
            Self::Ready(_) => DeviceConditionKind::Ready,
            Self::Reconciling(_) => DeviceConditionKind::Reconciling,
            Self::PendingDevice(_) => DeviceConditionKind::PendingDevice,
            Self::Degraded(_) => DeviceConditionKind::Degraded,
            Self::Quarantined(_) => DeviceConditionKind::Quarantined,
            Self::Deleting(_) => DeviceConditionKind::Deleting,
        }
    }

    /// Capture an owned snapshot that remains valid without another check.
    #[must_use]
    pub fn snapshot(&self) -> DeviceConditionSnapshot {
        match self {
            Self::Ready(value) => DeviceConditionSnapshot::ready_status(
                value.status(),
                value.reason(),
                value.observed_generation(),
                value.last_transition_time(),
            ),
            Self::Reconciling(value) => DeviceConditionSnapshot::reconciling(
                value.status(),
                value.reason(),
                value.observed_generation(),
                value.last_transition_time(),
            ),
            Self::PendingDevice(value) => DeviceConditionSnapshot::pending_device(
                value.status(),
                value.reason(),
                value.observed_generation(),
                value.last_transition_time(),
            ),
            Self::Degraded(value) => DeviceConditionSnapshot::degraded(
                value.status(),
                value.reason(),
                value.observed_generation(),
                value.last_transition_time(),
            ),
            Self::Quarantined(value) => DeviceConditionSnapshot::quarantined(
                value.status(),
                value.reason(),
                value.observed_generation(),
                value.last_transition_time(),
            ),
            Self::Deleting(value) => DeviceConditionSnapshot::deleting(
                value.status(),
                value.reason(),
                value.observed_generation(),
                value.last_transition_time(),
            ),
        }
    }

    /// Validate untrusted persisted condition state and reconstruct the domain value.
    ///
    /// # Errors
    ///
    /// Returns [`ConditionRestoreError::ReadyTrueForbidden`] when raw state claims
    /// `Ready=True` before the complete readiness proof is available.
    pub fn restore(input: DeviceConditionRestore) -> Result<Self, ConditionRestoreError> {
        match input {
            DeviceConditionRestore::Ready(value) => {
                let status = match value.status() {
                    ConditionStatus::False => NotReadyStatus::False,
                    ConditionStatus::Unknown => NotReadyStatus::Unknown,
                    ConditionStatus::True => return Err(ConditionRestoreError::ReadyTrueForbidden),
                };
                Ok(Self::ready(
                    status,
                    value.reason(),
                    value.observed_generation(),
                    value.last_transition_time(),
                ))
            }
            DeviceConditionRestore::Reconciling(value) => Ok(Self::reconciling(
                value.status(),
                value.reason(),
                value.observed_generation(),
                value.last_transition_time(),
            )),
            DeviceConditionRestore::PendingDevice(value) => Ok(Self::pending_device(
                value.status(),
                value.reason(),
                value.observed_generation(),
                value.last_transition_time(),
            )),
            DeviceConditionRestore::Degraded(value) => Ok(Self::degraded(
                value.status(),
                value.reason(),
                value.observed_generation(),
                value.last_transition_time(),
            )),
            DeviceConditionRestore::Quarantined(value) => Ok(Self::quarantined(
                value.status(),
                value.reason(),
                value.observed_generation(),
                value.last_transition_time(),
            )),
            DeviceConditionRestore::Deleting(value) => Ok(Self::deleting(
                value.status(),
                value.reason(),
                value.observed_generation(),
                value.last_transition_time(),
            )),
        }
    }

    /// Restore a persisted `Ready=True` row with freshly validated current evidence.
    ///
    /// # Errors
    ///
    /// Returns [`ConditionRestoreError::ReadyProofMismatch`] unless the raw row is exactly
    /// `Ready=True/StateMatches` at the generation bound into `proof`.
    pub fn restore_ready(
        input: DeviceConditionRestore,
        proof: ReadyProof,
    ) -> Result<Self, ConditionRestoreError> {
        let DeviceConditionRestore::Ready(value) = input else {
            return Err(ConditionRestoreError::ReadyProofMismatch);
        };
        if value.status() != ConditionStatus::True
            || value.reason() != ReadyReason::StateMatches
            || value.observed_generation() != Some(proof.observed_generation)
        {
            return Err(ConditionRestoreError::ReadyProofMismatch);
        }
        Ok(Self::ready_true(proof, value.last_transition_time()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SnapshotData<S, R> {
    status: S,
    reason: R,
    observed_generation: Option<ObservedGeneration>,
    last_transition_time: SystemTime,
}

macro_rules! snapshot_payload {
    ($(#[$meta:meta])* $name:ident, $status:ty, $reason:ty) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name(SnapshotData<$status, $reason>);

        impl $name {
            /// Return the validated snapshot status.
            #[must_use]
            pub const fn status(&self) -> $status { self.0.status }

            /// Return the variant-specific reason.
            #[must_use]
            pub const fn reason(&self) -> $reason { self.0.reason }

            /// Return the reported generation represented by the snapshot.
            #[must_use]
            pub const fn observed_generation(&self) -> Option<ObservedGeneration> { self.0.observed_generation }

            /// Return the server transition timestamp.
            #[must_use]
            pub const fn last_transition_time(&self) -> SystemTime { self.0.last_transition_time }
        }
    };
}

snapshot_payload!(
    /// Validated `Ready` snapshot payload.
    ReadyConditionSnapshot,
    ReadyStatus,
    ReadyReason
);
snapshot_payload!(
    /// Validated `Reconciling` snapshot payload.
    ReconcilingConditionSnapshot,
    ConditionStatus,
    ReconcilingReason
);
snapshot_payload!(
    /// Validated `PendingDevice` snapshot payload.
    PendingDeviceConditionSnapshot,
    ConditionStatus,
    PendingDeviceReason
);
snapshot_payload!(
    /// Validated `Degraded` snapshot payload.
    DegradedConditionSnapshot,
    ConditionStatus,
    DegradedReason
);
snapshot_payload!(
    /// Validated `Quarantined` snapshot payload.
    QuarantinedConditionSnapshot,
    ConditionStatus,
    QuarantinedReason
);
snapshot_payload!(
    /// Validated `Deleting` snapshot payload.
    DeletingConditionSnapshot,
    ConditionStatus,
    DeletingReason
);

/// Owned, always-valid, variant-specific persistence snapshot.
///
/// `Ready=True` cannot be placed in a trusted snapshot:
///
/// ```compile_fail
/// use deviceloop::condition::{ConditionStatus, DeviceConditionSnapshot, ReadyReason};
/// use std::time::SystemTime;
///
/// DeviceConditionSnapshot::ready(
///     ConditionStatus::True,
///     ReadyReason::StateMatches,
///     None,
///     SystemTime::UNIX_EPOCH,
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceConditionSnapshot {
    /// Validated readiness snapshot.
    Ready(ReadyConditionSnapshot),
    /// Validated reconciliation snapshot.
    Reconciling(ReconcilingConditionSnapshot),
    /// Validated waiting-on-device snapshot.
    PendingDevice(PendingDeviceConditionSnapshot),
    /// Validated degradation snapshot.
    Degraded(DegradedConditionSnapshot),
    /// Validated quarantine snapshot.
    Quarantined(QuarantinedConditionSnapshot),
    /// Validated deletion snapshot.
    Deleting(DeletingConditionSnapshot),
}

impl DeviceConditionSnapshot {
    /// Construct a valid `Ready` snapshot.
    #[must_use]
    pub fn ready(
        status: NotReadyStatus,
        reason: ReadyReason,
        observed_generation: Option<ObservedGeneration>,
        last_transition_time: SystemTime,
    ) -> Self {
        Self::Ready(ReadyConditionSnapshot(SnapshotData {
            status: status.into(),
            reason,
            observed_generation,
            last_transition_time,
        }))
    }

    fn ready_status(
        status: ReadyStatus,
        reason: ReadyReason,
        observed_generation: Option<ObservedGeneration>,
        last_transition_time: SystemTime,
    ) -> Self {
        Self::Ready(ReadyConditionSnapshot(SnapshotData {
            status,
            reason,
            observed_generation,
            last_transition_time,
        }))
    }

    /// Construct a valid `Reconciling` snapshot.
    #[must_use]
    pub fn reconciling(
        status: ConditionStatus,
        reason: ReconcilingReason,
        observed_generation: Option<ObservedGeneration>,
        last_transition_time: SystemTime,
    ) -> Self {
        Self::Reconciling(ReconcilingConditionSnapshot(SnapshotData {
            status,
            reason,
            observed_generation,
            last_transition_time,
        }))
    }

    /// Construct a valid `PendingDevice` snapshot.
    #[must_use]
    pub fn pending_device(
        status: ConditionStatus,
        reason: PendingDeviceReason,
        observed_generation: Option<ObservedGeneration>,
        last_transition_time: SystemTime,
    ) -> Self {
        Self::PendingDevice(PendingDeviceConditionSnapshot(SnapshotData {
            status,
            reason,
            observed_generation,
            last_transition_time,
        }))
    }

    /// Construct a valid `Degraded` snapshot.
    #[must_use]
    pub fn degraded(
        status: ConditionStatus,
        reason: DegradedReason,
        observed_generation: Option<ObservedGeneration>,
        last_transition_time: SystemTime,
    ) -> Self {
        Self::Degraded(DegradedConditionSnapshot(SnapshotData {
            status,
            reason,
            observed_generation,
            last_transition_time,
        }))
    }

    /// Construct a valid `Quarantined` snapshot.
    #[must_use]
    pub fn quarantined(
        status: ConditionStatus,
        reason: QuarantinedReason,
        observed_generation: Option<ObservedGeneration>,
        last_transition_time: SystemTime,
    ) -> Self {
        Self::Quarantined(QuarantinedConditionSnapshot(SnapshotData {
            status,
            reason,
            observed_generation,
            last_transition_time,
        }))
    }

    /// Construct a valid `Deleting` snapshot.
    #[must_use]
    pub fn deleting(
        status: ConditionStatus,
        reason: DeletingReason,
        observed_generation: Option<ObservedGeneration>,
        last_transition_time: SystemTime,
    ) -> Self {
        Self::Deleting(DeletingConditionSnapshot(SnapshotData {
            status,
            reason,
            observed_generation,
            last_transition_time,
        }))
    }

    /// Return the snapshot condition kind.
    #[must_use]
    pub const fn kind(&self) -> DeviceConditionKind {
        match self {
            Self::Ready(_) => DeviceConditionKind::Ready,
            Self::Reconciling(_) => DeviceConditionKind::Reconciling,
            Self::PendingDevice(_) => DeviceConditionKind::PendingDevice,
            Self::Degraded(_) => DeviceConditionKind::Degraded,
            Self::Quarantined(_) => DeviceConditionKind::Quarantined,
            Self::Deleting(_) => DeviceConditionKind::Deleting,
        }
    }

    /// Stable status label for persistence lowering.
    #[must_use]
    pub const fn status_label(&self) -> &'static str {
        match self {
            Self::Ready(value) => value.status().as_label(),
            Self::Reconciling(value) => value.status().as_label(),
            Self::PendingDevice(value) => value.status().as_label(),
            Self::Degraded(value) => value.status().as_label(),
            Self::Quarantined(value) => value.status().as_label(),
            Self::Deleting(value) => value.status().as_label(),
        }
    }
}

macro_rules! restore_payload {
    ($(#[$meta:meta])* $name:ident, $reason:ty) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name(SnapshotData<ConditionStatus, $reason>);

        impl $name {
            /// Return the untrusted persisted status.
            #[must_use]
            pub const fn status(&self) -> ConditionStatus { self.0.status }

            /// Return the variant-specific persisted reason.
            #[must_use]
            pub const fn reason(&self) -> $reason { self.0.reason }

            /// Return the persisted reported generation.
            #[must_use]
            pub const fn observed_generation(&self) -> Option<ObservedGeneration> { self.0.observed_generation }

            /// Return the persisted server transition timestamp.
            #[must_use]
            pub const fn last_transition_time(&self) -> SystemTime { self.0.last_transition_time }
        }
    };
}

restore_payload!(
    /// Raw `Ready` restore payload.
    ReadyConditionRestore,
    ReadyReason
);
restore_payload!(
    /// Raw `Reconciling` restore payload.
    ReconcilingConditionRestore,
    ReconcilingReason
);
restore_payload!(
    /// Raw `PendingDevice` restore payload.
    PendingDeviceConditionRestore,
    PendingDeviceReason
);
restore_payload!(
    /// Raw `Degraded` restore payload.
    DegradedConditionRestore,
    DegradedReason
);
restore_payload!(
    /// Raw `Quarantined` restore payload.
    QuarantinedConditionRestore,
    QuarantinedReason
);
restore_payload!(
    /// Raw `Deleting` restore payload.
    DeletingConditionRestore,
    DeletingReason
);

/// Untrusted, variant-specific condition fields accepted by the restore funnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceConditionRestore {
    /// Raw readiness fields; `True` is rejected by restore.
    Ready(ReadyConditionRestore),
    /// Raw reconciliation fields.
    Reconciling(ReconcilingConditionRestore),
    /// Raw waiting-on-device fields.
    PendingDevice(PendingDeviceConditionRestore),
    /// Raw degradation fields.
    Degraded(DegradedConditionRestore),
    /// Raw quarantine fields.
    Quarantined(QuarantinedConditionRestore),
    /// Raw deletion fields.
    Deleting(DeletingConditionRestore),
}

impl DeviceConditionRestore {
    /// Restore one persisted row through the owner-controlled closed label vocabulary.
    ///
    /// This is the sole string-to-domain funnel for condition persistence. Kind-specific reason
    /// parsing prevents cross-kind reason reuse. `Ready=True` remains untrusted until passed to
    /// [`DeviceCondition::restore_ready`] with a complete current proof.
    pub fn from_persisted_labels(
        kind: &str,
        status: &str,
        reason: &str,
        observed_generation: Option<ObservedGeneration>,
        last_transition_time: SystemTime,
    ) -> Result<Self, ConditionRestoreError> {
        let status = parse_condition_status(status)?;
        match kind {
            "Ready" => Ok(Self::ready(
                status,
                parse_ready_reason(reason)?,
                observed_generation,
                last_transition_time,
            )),
            "Reconciling" => Ok(Self::reconciling(
                status,
                parse_reconciling_reason(reason)?,
                observed_generation,
                last_transition_time,
            )),
            "PendingDevice" => Ok(Self::pending_device(
                status,
                parse_pending_device_reason(reason)?,
                observed_generation,
                last_transition_time,
            )),
            "Degraded" => Ok(Self::degraded(
                status,
                parse_degraded_reason(reason)?,
                observed_generation,
                last_transition_time,
            )),
            "Quarantined" => Ok(Self::quarantined(
                status,
                parse_quarantined_reason(reason)?,
                observed_generation,
                last_transition_time,
            )),
            "Deleting" => Ok(Self::deleting(
                status,
                parse_deleting_reason(reason)?,
                observed_generation,
                last_transition_time,
            )),
            _ => Err(ConditionRestoreError::InvalidKind),
        }
    }

    /// Construct raw `Ready` restore input. Validation is deferred to [`DeviceCondition::restore`].
    #[must_use]
    pub fn ready(
        status: ConditionStatus,
        reason: ReadyReason,
        observed_generation: Option<ObservedGeneration>,
        last_transition_time: SystemTime,
    ) -> Self {
        Self::Ready(ReadyConditionRestore(SnapshotData {
            status,
            reason,
            observed_generation,
            last_transition_time,
        }))
    }

    /// Construct raw `Reconciling` restore input.
    #[must_use]
    pub fn reconciling(
        status: ConditionStatus,
        reason: ReconcilingReason,
        observed_generation: Option<ObservedGeneration>,
        last_transition_time: SystemTime,
    ) -> Self {
        Self::Reconciling(ReconcilingConditionRestore(SnapshotData {
            status,
            reason,
            observed_generation,
            last_transition_time,
        }))
    }

    /// Construct raw `PendingDevice` restore input.
    #[must_use]
    pub fn pending_device(
        status: ConditionStatus,
        reason: PendingDeviceReason,
        observed_generation: Option<ObservedGeneration>,
        last_transition_time: SystemTime,
    ) -> Self {
        Self::PendingDevice(PendingDeviceConditionRestore(SnapshotData {
            status,
            reason,
            observed_generation,
            last_transition_time,
        }))
    }

    /// Construct raw `Degraded` restore input.
    #[must_use]
    pub fn degraded(
        status: ConditionStatus,
        reason: DegradedReason,
        observed_generation: Option<ObservedGeneration>,
        last_transition_time: SystemTime,
    ) -> Self {
        Self::Degraded(DegradedConditionRestore(SnapshotData {
            status,
            reason,
            observed_generation,
            last_transition_time,
        }))
    }

    /// Construct raw `Quarantined` restore input.
    #[must_use]
    pub fn quarantined(
        status: ConditionStatus,
        reason: QuarantinedReason,
        observed_generation: Option<ObservedGeneration>,
        last_transition_time: SystemTime,
    ) -> Self {
        Self::Quarantined(QuarantinedConditionRestore(SnapshotData {
            status,
            reason,
            observed_generation,
            last_transition_time,
        }))
    }

    /// Construct raw `Deleting` restore input.
    #[must_use]
    pub fn deleting(
        status: ConditionStatus,
        reason: DeletingReason,
        observed_generation: Option<ObservedGeneration>,
        last_transition_time: SystemTime,
    ) -> Self {
        Self::Deleting(DeletingConditionRestore(SnapshotData {
            status,
            reason,
            observed_generation,
            last_transition_time,
        }))
    }
}

fn parse_condition_status(raw: &str) -> Result<ConditionStatus, ConditionRestoreError> {
    match raw {
        "True" => Ok(ConditionStatus::True),
        "False" => Ok(ConditionStatus::False),
        "Unknown" => Ok(ConditionStatus::Unknown),
        _ => Err(ConditionRestoreError::InvalidStatus),
    }
}

fn parse_ready_reason(raw: &str) -> Result<ReadyReason, ConditionRestoreError> {
    match raw {
        "StateMatches" => Ok(ReadyReason::StateMatches),
        "StateDrift" => Ok(ReadyReason::StateDrift),
        "AwaitingDevice" => Ok(ReadyReason::AwaitingDevice),
        "CommandRejected" => Ok(ReadyReason::CommandRejected),
        "CommandTimedOut" => Ok(ReadyReason::CommandTimedOut),
        "ProtocolViolation" => Ok(ReadyReason::ProtocolViolation),
        "ArtifactUnavailable" => Ok(ReadyReason::ArtifactUnavailable),
        "TransportUnavailable" => Ok(ReadyReason::TransportUnavailable),
        _ => Err(ConditionRestoreError::InvalidReason),
    }
}

fn parse_reconciling_reason(raw: &str) -> Result<ReconcilingReason, ConditionRestoreError> {
    match raw {
        "DesiredAccepted" => Ok(ReconcilingReason::DesiredAccepted),
        "CommandQueued" => Ok(ReconcilingReason::CommandQueued),
        "DeviceReported" => Ok(ReconcilingReason::DeviceReported),
        "StateDrift" => Ok(ReconcilingReason::StateDrift),
        _ => Err(ConditionRestoreError::InvalidReason),
    }
}

fn parse_pending_device_reason(raw: &str) -> Result<PendingDeviceReason, ConditionRestoreError> {
    match raw {
        "CommandQueued" => Ok(PendingDeviceReason::CommandQueued),
        "AwaitingDevice" => Ok(PendingDeviceReason::AwaitingDevice),
        "CommandTimedOut" => Ok(PendingDeviceReason::CommandTimedOut),
        "TransportUnavailable" => Ok(PendingDeviceReason::TransportUnavailable),
        _ => Err(ConditionRestoreError::InvalidReason),
    }
}

fn parse_degraded_reason(raw: &str) -> Result<DegradedReason, ConditionRestoreError> {
    match raw {
        "CommandRejected" => Ok(DegradedReason::CommandRejected),
        "CommandTimedOut" => Ok(DegradedReason::CommandTimedOut),
        "ProtocolViolation" => Ok(DegradedReason::ProtocolViolation),
        "ArtifactUnavailable" => Ok(DegradedReason::ArtifactUnavailable),
        "TransportUnavailable" => Ok(DegradedReason::TransportUnavailable),
        _ => Err(ConditionRestoreError::InvalidReason),
    }
}

fn parse_quarantined_reason(raw: &str) -> Result<QuarantinedReason, ConditionRestoreError> {
    match raw {
        "ProtocolViolation" => Ok(QuarantinedReason::ProtocolViolation),
        "QuarantinedByOperator" => Ok(QuarantinedReason::QuarantinedByOperator),
        _ => Err(ConditionRestoreError::InvalidReason),
    }
}

fn parse_deleting_reason(raw: &str) -> Result<DeletingReason, ConditionRestoreError> {
    match raw {
        "DeletionPending" => Ok(DeletingReason::DeletionPending),
        "DeletionComplete" => Ok(DeletingReason::DeletionComplete),
        _ => Err(ConditionRestoreError::InvalidReason),
    }
}

impl From<DeviceConditionSnapshot> for DeviceConditionRestore {
    fn from(snapshot: DeviceConditionSnapshot) -> Self {
        match snapshot {
            DeviceConditionSnapshot::Ready(value) => Self::ready(
                value.status().into(),
                value.reason(),
                value.observed_generation(),
                value.last_transition_time(),
            ),
            DeviceConditionSnapshot::Reconciling(value) => Self::reconciling(
                value.status(),
                value.reason(),
                value.observed_generation(),
                value.last_transition_time(),
            ),
            DeviceConditionSnapshot::PendingDevice(value) => Self::pending_device(
                value.status(),
                value.reason(),
                value.observed_generation(),
                value.last_transition_time(),
            ),
            DeviceConditionSnapshot::Degraded(value) => Self::degraded(
                value.status(),
                value.reason(),
                value.observed_generation(),
                value.last_transition_time(),
            ),
            DeviceConditionSnapshot::Quarantined(value) => Self::quarantined(
                value.status(),
                value.reason(),
                value.observed_generation(),
                value.last_transition_time(),
            ),
            DeviceConditionSnapshot::Deleting(value) => Self::deleting(
                value.status(),
                value.reason(),
                value.observed_generation(),
                value.last_transition_time(),
            ),
        }
    }
}

/// Failure to validate untrusted persisted condition state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ConditionRestoreError {
    /// Persisted kind was outside the closed condition set.
    #[error("persisted condition kind is invalid")]
    InvalidKind,
    /// Persisted status was outside the closed condition set.
    #[error("persisted condition status is invalid")]
    InvalidStatus,
    /// Persisted reason was not valid for its condition kind.
    #[error("persisted condition reason is invalid for its kind")]
    InvalidReason,
    /// Raw state claimed `Ready=True` without the complete readiness proof.
    #[error("Ready=True is not restorable before the complete readiness proof exists")]
    ReadyTrueForbidden,
    /// Persisted readiness fields did not match the supplied current proof.
    #[error("persisted Ready=True fields do not match the readiness proof")]
    ReadyProofMismatch,
}

#[cfg(test)]
#[allow(clippy::cognitive_complexity, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const AT: SystemTime = SystemTime::UNIX_EPOCH;

    fn desired(raw: u64) -> DesiredGeneration {
        DesiredGeneration::try_new(raw).expect("valid desired generation")
    }

    fn observed(raw: u64) -> ObservedGeneration {
        ObservedGeneration::try_new(raw).expect("valid reported generation")
    }

    fn ready_proof() -> ReadyProof {
        ReadyProof::try_new(
            desired(7),
            observed(7),
            ExpectedStateHash::new([1; 32]),
            ReportedStateHash::new([1; 32]),
            AuthorizedArtifactDigest::new([2; 32]),
            ReportedArtifactDigest::new([2; 32]),
            AT,
            AT + std::time::Duration::from_secs(1),
            CurrentCertificateStatus::NonRevoked,
            UpdateCommandState::Absent,
        )
        .expect("complete matching evidence")
    }

    #[test]
    fn ready_true_requires_complete_matching_current_evidence() {
        let ready = DeviceCondition::ready_true(ready_proof(), AT);
        let DeviceConditionSnapshot::Ready(payload) = ready.snapshot() else {
            panic!("expected Ready");
        };
        assert_eq!(payload.status(), ReadyStatus::True);
        assert_eq!(payload.reason(), ReadyReason::StateMatches);
        assert_eq!(
            payload.observed_generation().map(ObservedGeneration::get),
            Some(7)
        );

        let cases = [
            ReadyProof::try_new(
                desired(8),
                observed(7),
                ExpectedStateHash::new([1; 32]),
                ReportedStateHash::new([1; 32]),
                AuthorizedArtifactDigest::new([2; 32]),
                ReportedArtifactDigest::new([2; 32]),
                AT,
                AT + std::time::Duration::from_secs(1),
                CurrentCertificateStatus::NonRevoked,
                UpdateCommandState::Absent,
            ),
            ReadyProof::try_new(
                desired(7),
                observed(7),
                ExpectedStateHash::new([1; 32]),
                ReportedStateHash::new([3; 32]),
                AuthorizedArtifactDigest::new([2; 32]),
                ReportedArtifactDigest::new([2; 32]),
                AT,
                AT + std::time::Duration::from_secs(1),
                CurrentCertificateStatus::NonRevoked,
                UpdateCommandState::Absent,
            ),
            ReadyProof::try_new(
                desired(7),
                observed(7),
                ExpectedStateHash::new([1; 32]),
                ReportedStateHash::new([1; 32]),
                AuthorizedArtifactDigest::new([2; 32]),
                ReportedArtifactDigest::new([3; 32]),
                AT,
                AT + std::time::Duration::from_secs(1),
                CurrentCertificateStatus::NonRevoked,
                UpdateCommandState::Absent,
            ),
            ReadyProof::try_new(
                desired(7),
                observed(7),
                ExpectedStateHash::new([1; 32]),
                ReportedStateHash::new([1; 32]),
                AuthorizedArtifactDigest::new([2; 32]),
                ReportedArtifactDigest::new([2; 32]),
                AT + std::time::Duration::from_secs(1),
                AT + std::time::Duration::from_secs(1),
                CurrentCertificateStatus::NonRevoked,
                UpdateCommandState::Absent,
            ),
            ReadyProof::try_new(
                desired(7),
                observed(7),
                ExpectedStateHash::new([1; 32]),
                ReportedStateHash::new([1; 32]),
                AuthorizedArtifactDigest::new([2; 32]),
                ReportedArtifactDigest::new([2; 32]),
                AT,
                AT + std::time::Duration::from_secs(1),
                CurrentCertificateStatus::Revoked,
                UpdateCommandState::Absent,
            ),
            ReadyProof::try_new(
                desired(7),
                observed(7),
                ExpectedStateHash::new([1; 32]),
                ReportedStateHash::new([1; 32]),
                AuthorizedArtifactDigest::new([2; 32]),
                ReportedArtifactDigest::new([2; 32]),
                AT,
                AT + std::time::Duration::from_secs(1),
                CurrentCertificateStatus::NonRevoked,
                UpdateCommandState::Conflicting,
            ),
        ];
        assert_eq!(
            cases,
            [
                Err(ReadyProofError::GenerationMismatch),
                Err(ReadyProofError::StateHashMismatch),
                Err(ReadyProofError::ArtifactDigestMismatch),
                Err(ReadyProofError::Expired),
                Err(ReadyProofError::Revoked),
                Err(ReadyProofError::ConflictingUpdateCommand),
            ]
        );
    }

    #[test]
    fn ready_true_restore_requires_matching_proof() {
        let generation_seven = Some(observed(7));
        let input = DeviceConditionRestore::from_persisted_labels(
            "Ready",
            "True",
            "StateMatches",
            generation_seven,
            AT,
        )
        .expect("closed persisted labels");
        let restored = DeviceCondition::restore_ready(input, ready_proof()).expect("proof matches");
        assert_eq!(restored.snapshot().kind(), DeviceConditionKind::Ready);
        assert_eq!(restored.snapshot().status_label(), "True");

        let wrong_generation = DeviceConditionRestore::from_persisted_labels(
            "Ready",
            "True",
            "StateMatches",
            Some(observed(8)),
            AT,
        )
        .expect("closed persisted labels");
        assert_eq!(
            DeviceCondition::restore_ready(wrong_generation, ready_proof()),
            Err(ConditionRestoreError::ReadyProofMismatch)
        );

        let wrong_reason = DeviceConditionRestore::from_persisted_labels(
            "Ready",
            "True",
            "StateDrift",
            generation_seven,
            AT,
        )
        .expect("closed persisted labels");
        assert_eq!(
            DeviceCondition::restore_ready(wrong_reason, ready_proof()),
            Err(ConditionRestoreError::ReadyProofMismatch)
        );
    }

    #[test]
    fn readiness_digests_have_role_types_and_redacted_debug() {
        assert_eq!(
            format!("{:?}", ExpectedStateHash::new([0x5a; 32])),
            "ExpectedStateHash(<sha256>)"
        );
        assert_eq!(
            format!("{:?}", AuthorizedArtifactDigest::new([0x5a; 32])),
            "AuthorizedArtifactDigest(<sha256>)"
        );
    }

    #[test]
    fn condition_and_reason_sets_are_exact_and_labels_are_closed() {
        assert_eq!(
            ConditionStatus::ALL.map(ConditionStatus::as_label),
            ["True", "False", "Unknown"]
        );
        assert_eq!(
            NotReadyStatus::ALL.map(NotReadyStatus::as_label),
            ["False", "Unknown"]
        );
        assert_eq!(
            DeviceConditionKind::ALL.map(DeviceConditionKind::as_label),
            [
                "Ready",
                "Reconciling",
                "PendingDevice",
                "Degraded",
                "Quarantined",
                "Deleting"
            ]
        );
        assert_eq!(
            ReadyReason::ALL.map(ReadyReason::as_label),
            [
                "StateMatches",
                "StateDrift",
                "AwaitingDevice",
                "CommandRejected",
                "CommandTimedOut",
                "ProtocolViolation",
                "ArtifactUnavailable",
                "TransportUnavailable"
            ]
        );
        assert_eq!(
            ReconcilingReason::ALL.map(ReconcilingReason::as_label),
            [
                "DesiredAccepted",
                "CommandQueued",
                "DeviceReported",
                "StateDrift"
            ]
        );
        assert_eq!(
            PendingDeviceReason::ALL.map(PendingDeviceReason::as_label),
            [
                "CommandQueued",
                "AwaitingDevice",
                "CommandTimedOut",
                "TransportUnavailable"
            ]
        );
        assert_eq!(
            DegradedReason::ALL.map(DegradedReason::as_label),
            [
                "CommandRejected",
                "CommandTimedOut",
                "ProtocolViolation",
                "ArtifactUnavailable",
                "TransportUnavailable"
            ]
        );
        assert_eq!(
            QuarantinedReason::ALL.map(QuarantinedReason::as_label),
            ["ProtocolViolation", "QuarantinedByOperator"]
        );
        assert_eq!(
            DeletingReason::ALL.map(DeletingReason::as_label),
            ["DeletionPending", "DeletionComplete"]
        );
    }

    #[test]
    fn dedicated_reason_types_construct_the_whole_matrix() {
        for reason in ReadyReason::ALL {
            assert_eq!(
                DeviceCondition::ready(NotReadyStatus::False, reason, None, AT).kind(),
                DeviceConditionKind::Ready
            );
        }
        for reason in ReconcilingReason::ALL {
            assert_eq!(
                DeviceCondition::reconciling(ConditionStatus::True, reason, None, AT).kind(),
                DeviceConditionKind::Reconciling
            );
        }
        for reason in PendingDeviceReason::ALL {
            assert_eq!(
                DeviceCondition::pending_device(ConditionStatus::True, reason, None, AT).kind(),
                DeviceConditionKind::PendingDevice
            );
        }
        for reason in DegradedReason::ALL {
            assert_eq!(
                DeviceCondition::degraded(ConditionStatus::True, reason, None, AT).kind(),
                DeviceConditionKind::Degraded
            );
        }
        for reason in QuarantinedReason::ALL {
            assert_eq!(
                DeviceCondition::quarantined(ConditionStatus::True, reason, None, AT).kind(),
                DeviceConditionKind::Quarantined
            );
        }
        for reason in DeletingReason::ALL {
            assert_eq!(
                DeviceCondition::deleting(ConditionStatus::True, reason, None, AT).kind(),
                DeviceConditionKind::Deleting
            );
        }
    }

    #[test]
    fn every_legal_variant_round_trips_exactly() {
        let observed = ObservedGeneration::try_new(7).expect("positive generation");
        let conditions = [
            DeviceCondition::ready(
                NotReadyStatus::Unknown,
                ReadyReason::AwaitingDevice,
                Some(observed),
                AT,
            ),
            DeviceCondition::reconciling(
                ConditionStatus::True,
                ReconcilingReason::DesiredAccepted,
                None,
                AT,
            ),
            DeviceCondition::pending_device(
                ConditionStatus::False,
                PendingDeviceReason::CommandTimedOut,
                None,
                AT,
            ),
            DeviceCondition::degraded(
                ConditionStatus::Unknown,
                DegradedReason::ProtocolViolation,
                None,
                AT,
            ),
            DeviceCondition::quarantined(
                ConditionStatus::True,
                QuarantinedReason::QuarantinedByOperator,
                None,
                AT,
            ),
            DeviceCondition::deleting(
                ConditionStatus::False,
                DeletingReason::DeletionComplete,
                None,
                AT,
            ),
        ];

        for condition in conditions {
            let snapshot = condition.snapshot();
            let restored =
                DeviceCondition::restore(snapshot.clone().into()).expect("valid snapshot");
            assert_eq!(restored, condition);
            assert_eq!(restored.snapshot(), snapshot);
        }
    }

    fn assert_persisted_labels_round_trip(state: DeviceConditionState) {
        let restored = DeviceConditionRestore::from_persisted_labels(
            state.kind().as_label(),
            state.status_label(),
            state.reason_label(),
            state.observed_generation(),
            AT,
        )
        .expect("closed labels must restore");
        assert_eq!(
            DeviceCondition::restore(restored).expect("legal labels must form a condition"),
            state.at(AT)
        );
    }

    #[test]
    fn persisted_label_funnel_round_trips_the_complete_legal_matrix() {
        let observed = Some(ObservedGeneration::try_new(7).expect("positive generation"));
        for status in NotReadyStatus::ALL {
            for reason in ReadyReason::ALL {
                assert_persisted_labels_round_trip(DeviceConditionState::ready(
                    status, reason, observed,
                ));
            }
        }
        for status in ConditionStatus::ALL {
            for reason in ReconcilingReason::ALL {
                assert_persisted_labels_round_trip(DeviceConditionState::reconciling(
                    status, reason, observed,
                ));
            }
            for reason in PendingDeviceReason::ALL {
                assert_persisted_labels_round_trip(DeviceConditionState::pending_device(
                    status, reason, observed,
                ));
            }
            for reason in DegradedReason::ALL {
                assert_persisted_labels_round_trip(DeviceConditionState::degraded(
                    status, reason, observed,
                ));
            }
            for reason in QuarantinedReason::ALL {
                assert_persisted_labels_round_trip(DeviceConditionState::quarantined(
                    status, reason, observed,
                ));
            }
            for reason in DeletingReason::ALL {
                assert_persisted_labels_round_trip(DeviceConditionState::deleting(
                    status, reason, observed,
                ));
            }
        }
    }

    #[test]
    fn persisted_label_funnel_rejects_unknown_and_cross_kind_values() {
        let restore = |kind, status, reason| {
            DeviceConditionRestore::from_persisted_labels(kind, status, reason, None, AT)
        };
        assert_eq!(
            restore("Other", "False", "StateDrift"),
            Err(ConditionRestoreError::InvalidKind)
        );
        assert_eq!(
            restore("Ready", "Invalid", "StateDrift"),
            Err(ConditionRestoreError::InvalidStatus)
        );
        assert_eq!(
            restore("Ready", "False", "DesiredAccepted"),
            Err(ConditionRestoreError::InvalidReason)
        );
        assert_eq!(
            restore("Reconciling", "False", "ProtocolViolation"),
            Err(ConditionRestoreError::InvalidReason)
        );
        let raw_true = restore("Ready", "True", "StateMatches")
            .expect("Ready=True labels require evidence at domain restore");
        assert_eq!(
            DeviceCondition::restore(raw_true),
            Err(ConditionRestoreError::ReadyTrueForbidden)
        );
    }

    #[test]
    fn valid_ready_snapshot_exposes_only_not_ready_status() {
        let snapshot =
            DeviceCondition::ready(NotReadyStatus::False, ReadyReason::StateDrift, None, AT)
                .snapshot();
        let DeviceConditionSnapshot::Ready(payload) = snapshot else {
            panic!("expected Ready");
        };
        let _: ReadyStatus = payload.status();
        assert_eq!(payload.status(), ReadyStatus::False);
    }

    #[test]
    fn raw_ready_true_restore_fails_closed_without_losing_projection_fields() {
        let input = DeviceConditionRestore::ready(
            ConditionStatus::True,
            ReadyReason::StateMatches,
            None,
            AT,
        );
        let DeviceConditionRestore::Ready(payload) = &input else {
            panic!("expected Ready");
        };
        assert_eq!(payload.status(), ConditionStatus::True);
        assert_eq!(payload.reason(), ReadyReason::StateMatches);
        assert_eq!(payload.observed_generation(), None);
        assert_eq!(payload.last_transition_time(), AT);
        assert_eq!(
            DeviceCondition::restore(input),
            Err(ConditionRestoreError::ReadyTrueForbidden)
        );
    }
}
