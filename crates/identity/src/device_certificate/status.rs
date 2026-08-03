//! Authorized, provider-neutral DeviceLatent status inspection.
//!
//! The read receipt is minted only from an exact route-authorized subject. Persistence providers
//! consume it by value, so a caller cannot replace authenticated tenant or path-device scope with
//! naked identifiers at the status-store boundary.

use dynosaur::dynosaur;

use super::{DeviceCertificateError, DeviceCertificateScope, DeviceCertificateStateSnapshot};
use deviceloop::{
    ConditionStatus, DegradedReason, DeletingReason, DesiredGeneration, DeviceConditionSnapshot,
    FenceEpoch, PendingDeviceReason, QuarantinedReason, ReadyReason, ReadyStatus,
    ReconcilingReason,
};

use generated::http::identity_v2::device_certificate_status_get as wire;

const STATUS_CONTRACT_ID: &str =
    generated::http::identity_v2::device_certificate_status_get::CONTRACT_ID;
const STATUS_PERMISSION: vocab::RoutePermissionId =
    vocab::RoutePermissionId::IdentityDeviceCertificateStatusRead;

/// Exact route authorization failed to bind the requested device-certificate status read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("device-certificate status read is not authorized")]
pub struct DeviceCertificateStatusAuthorizationError;

/// Move-only authorization receipt for one tenant/path-device status inspection.
///
/// Fields are private and there is no scope-based or test-only constructor. Even tests must pass
/// through an [`httpserve::AuthorizedSubject`] carrying exact generated route evidence.
///
/// ```compile_fail
/// use identity::ports::device_certificate::AuthorizedDeviceCertificateStatusRead;
///
/// let _ = AuthorizedDeviceCertificateStatusRead {};
/// ```
pub struct AuthorizedDeviceCertificateStatusRead {
    scope: DeviceCertificateScope,
    projection: httpserve::ResourceProjection,
}

impl AuthorizedDeviceCertificateStatusRead {
    /// Consume exact route-gate evidence into the only status-store query receipt.
    pub fn from_authorized_subject(
        subject: &httpserve::AuthorizedSubject,
        device: ids::DeviceId,
    ) -> Result<Self, DeviceCertificateStatusAuthorizationError> {
        let expected_resource = device.as_uuid().hyphenated().to_string();
        let exact_route = subject.contract_id() == STATUS_CONTRACT_ID
            && subject.permission() == STATUS_PERMISSION
            && subject
                .resource()
                .is_some_and(|resource| resource.id() == expected_resource);
        if !exact_route {
            return Err(DeviceCertificateStatusAuthorizationError);
        }
        Ok(Self {
            scope: DeviceCertificateScope::from_authorized(subject.tenant_id(), device),
            projection: subject.projection(),
        })
    }

    /// Authenticated tenant and exact path-device scope consumed by a persistence provider.
    #[doc(hidden)]
    #[must_use]
    pub const fn scope(&self) -> DeviceCertificateScope {
        self.scope
    }

    /// Field projection carried by the successful authorization decision.
    #[must_use]
    pub const fn projection(&self) -> httpserve::ResourceProjection {
        self.projection
    }
}

impl std::fmt::Debug for AuthorizedDeviceCertificateStatusRead {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthorizedDeviceCertificateStatusRead")
            .field("scope", &"<redacted>")
            .field("projection", &self.projection)
            .finish()
    }
}

/// The only command states exposed by the status inspection projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceCertificateActiveCommandState {
    /// Accepted for transport dispatch.
    Queued,
    /// Published to the device transport.
    Published,
    /// Receipt acknowledged by the device; convergence still requires a matching report.
    Received,
}

impl DeviceCertificateActiveCommandState {
    /// Restore the closed active subset from PostgreSQL's canonical command state.
    #[doc(hidden)]
    pub fn restore(raw: &str) -> Result<Self, DeviceCertificateError> {
        match raw {
            "queued" => Ok(Self::Queued),
            "published" => Ok(Self::Published),
            "received" => Ok(Self::Received),
            _ => Err(DeviceCertificateError::InvalidPersistedValue),
        }
    }
}

/// Payload-free summary of the unique nonterminal command for a device.
pub struct DeviceCertificateActiveCommand {
    generation: DesiredGeneration,
    fence_epoch: FenceEpoch,
    state: DeviceCertificateActiveCommandState,
    queued_at: std::time::SystemTime,
    published_at: Option<std::time::SystemTime>,
    received_at: Option<std::time::SystemTime>,
}

impl DeviceCertificateActiveCommand {
    /// Restore one provider row through bounded identity and closed-state funnels.
    #[doc(hidden)]
    pub fn restore(
        generation: DesiredGeneration,
        fence_epoch: FenceEpoch,
        state: DeviceCertificateActiveCommandState,
        queued_at: std::time::SystemTime,
        published_at: Option<std::time::SystemTime>,
        received_at: Option<std::time::SystemTime>,
    ) -> Result<Self, DeviceCertificateError> {
        let valid_progress = match state {
            DeviceCertificateActiveCommandState::Queued => {
                published_at.is_none() && received_at.is_none()
            }
            DeviceCertificateActiveCommandState::Published => {
                published_at.is_some_and(|published| published >= queued_at)
                    && received_at.is_none()
            }
            DeviceCertificateActiveCommandState::Received => {
                published_at.is_some_and(|published| {
                    published >= queued_at
                        && received_at.is_some_and(|received| received >= published)
                })
            }
        };
        if !valid_progress {
            return Err(DeviceCertificateError::InvalidPersistedValue);
        }
        Ok(Self {
            generation,
            fence_epoch,
            state,
            queued_at,
            published_at,
            received_at,
        })
    }

    fn queue_age_at(
        &self,
        now: std::time::SystemTime,
    ) -> Result<std::time::Duration, DeviceLatentObservationError> {
        self.published_at
            .unwrap_or(now)
            .duration_since(self.queued_at)
            .map_err(|_| DeviceLatentObservationError)
    }

    fn ack_latency_at(
        &self,
        now: std::time::SystemTime,
    ) -> Result<Option<std::time::Duration>, DeviceLatentObservationError> {
        self.published_at
            .map(|published| {
                self.received_at
                    .unwrap_or(now)
                    .duration_since(published)
                    .map_err(|_| DeviceLatentObservationError)
            })
            .transpose()
    }

    fn is_observed_by(&self, observed_at: std::time::SystemTime) -> bool {
        [Some(self.queued_at), self.published_at, self.received_at]
            .into_iter()
            .flatten()
            .all(|timestamp| timestamp <= observed_at)
    }
}

impl std::fmt::Debug for DeviceCertificateActiveCommand {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeviceCertificateActiveCommand")
            .field("generation", &self.generation)
            .field("fence_epoch", &self.fence_epoch)
            .field("state", &self.state)
            .finish()
    }
}

/// Provider-neutral authorized status evidence.
pub struct DeviceCertificateStatusEvidence {
    state: DeviceCertificateStateSnapshot,
    active_command: Option<DeviceCertificateActiveCommand>,
    observed_at: std::time::SystemTime,
}

fn timestamps_are_authoritative_at(
    state: &DeviceCertificateStateSnapshot,
    active_command: Option<&DeviceCertificateActiveCommand>,
    observed_at: std::time::SystemTime,
) -> bool {
    active_command.is_none_or(|command| command.is_observed_by(observed_at))
        && state
            .conditions()
            .iter()
            .all(|condition| condition_transition_time(condition) <= observed_at)
}

impl DeviceCertificateStatusEvidence {
    /// Bind the unique active command to the current desired generation.
    #[doc(hidden)]
    pub fn restore(
        state: DeviceCertificateStateSnapshot,
        active_command: Option<DeviceCertificateActiveCommand>,
        observed_at: std::time::SystemTime,
    ) -> Result<Self, DeviceCertificateError> {
        let generation_mismatch = active_command.as_ref().is_some_and(|command| {
            command.generation.get() != state.desired().generation().get()
        });
        if generation_mismatch
            || !timestamps_are_authoritative_at(&state, active_command.as_ref(), observed_at)
        {
            return Err(DeviceCertificateError::InvalidPersistedValue);
        }
        Ok(Self {
            state,
            active_command,
            observed_at,
        })
    }

    /// Derive identifier-free numeric convergence observations at one authoritative instant.
    pub fn observation(
        &self,
    ) -> Result<observ::DeviceLatentObservation, DeviceLatentObservationError> {
        let now = self.observed_at;
        if !timestamps_are_authoritative_at(&self.state, self.active_command.as_ref(), now) {
            return Err(DeviceLatentObservationError);
        }
        let desired = self.state.desired().generation().get();
        let observed = self
            .state
            .reported()
            .map_or(0, |reported| reported.observed_generation().get());
        let generation_lag = desired
            .checked_sub(observed)
            .ok_or(DeviceLatentObservationError)?;
        let drift_age = self
            .state
            .conditions()
            .iter()
            .find_map(|condition| match condition {
                DeviceConditionSnapshot::Ready(value)
                    if value.reason() == ReadyReason::StateDrift =>
                {
                    Some(value.last_transition_time())
                }
                _ => None,
            })
            .map(|transition| {
                now.duration_since(transition)
                    .map_err(|_| DeviceLatentObservationError)
            })
            .transpose()?;
        let (queue_age, ack_latency) = match self.active_command.as_ref() {
            Some(command) => (
                Some(command.queue_age_at(now)?),
                command.ack_latency_at(now)?,
            ),
            None => (None, None),
        };
        Ok(observ::DeviceLatentObservation::new(
            generation_lag,
            drift_age,
            queue_age,
            ack_latency,
        ))
    }

    /// Project validated domain evidence into the payload-free status response.
    pub fn to_wire_response(
        &self,
    ) -> Result<
        wire::IdentityDeviceCertificateStatusGetResponse,
        DeviceCertificateStatusProjectionError,
    > {
        let state = &self.state;
        let conditions = state
            .conditions()
            .iter()
            .map(project_condition)
            .collect::<Result<Vec<_>, _>>()?;
        let active_command = self
            .active_command
            .as_ref()
            .map(project_active_command)
            .transpose()?;
        Ok(wire::IdentityDeviceCertificateStatusGetResponse {
            data: wire::IdentityDeviceCertificateStatusGetData {
                active_command,
                conditions,
                desired_generation: bounded_i64(state.desired().generation().get())?,
                observed_generation: state.reported().map_or(Ok(0), |reported| {
                    bounded_i64(reported.observed_generation().get())
                })?,
            },
        })
    }
}

impl std::fmt::Debug for DeviceCertificateStatusEvidence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeviceCertificateStatusEvidence")
            .field("state", &"<redacted>")
            .field("active_command", &self.active_command)
            .finish()
    }
}

/// Validated status evidence could not be represented by the frozen generated response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("device-certificate status cannot be projected")]
pub struct DeviceCertificateStatusProjectionError;

/// Authoritative timestamps could not form a non-negative DeviceLatent observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("device-certificate status observation is invalid")]
pub struct DeviceLatentObservationError;

fn bounded_i64(value: u64) -> Result<i64, DeviceCertificateStatusProjectionError> {
    i64::try_from(value).map_err(|_| DeviceCertificateStatusProjectionError)
}

fn epoch_seconds(
    value: std::time::SystemTime,
) -> Result<i64, DeviceCertificateStatusProjectionError> {
    let seconds = value
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| DeviceCertificateStatusProjectionError)?
        .as_secs();
    bounded_i64(seconds)
}

fn project_active_command(
    command: &DeviceCertificateActiveCommand,
) -> Result<
    wire::IdentityDeviceCertificateStatusGetActiveCommand,
    DeviceCertificateStatusProjectionError,
> {
    let generation = std::num::NonZeroU64::new(command.generation.get())
        .ok_or(DeviceCertificateStatusProjectionError)?;
    let fence_epoch = std::num::NonZeroU64::new(command.fence_epoch.get())
        .ok_or(DeviceCertificateStatusProjectionError)?;
    let state = match command.state {
        DeviceCertificateActiveCommandState::Queued => {
            wire::IdentityDeviceCertificateStatusGetActiveCommandState::Queued
        }
        DeviceCertificateActiveCommandState::Published => {
            wire::IdentityDeviceCertificateStatusGetActiveCommandState::Published
        }
        DeviceCertificateActiveCommandState::Received => {
            wire::IdentityDeviceCertificateStatusGetActiveCommandState::Received
        }
    };
    Ok(wire::IdentityDeviceCertificateStatusGetActiveCommand {
        fence_epoch,
        generation,
        state,
    })
}

fn condition_transition_time(condition: &DeviceConditionSnapshot) -> std::time::SystemTime {
    match condition {
        DeviceConditionSnapshot::Ready(value) => value.last_transition_time(),
        DeviceConditionSnapshot::Reconciling(value) => value.last_transition_time(),
        DeviceConditionSnapshot::PendingDevice(value) => value.last_transition_time(),
        DeviceConditionSnapshot::Degraded(value) => value.last_transition_time(),
        DeviceConditionSnapshot::Quarantined(value) => value.last_transition_time(),
        DeviceConditionSnapshot::Deleting(value) => value.last_transition_time(),
    }
}

fn project_condition(
    condition: &DeviceConditionSnapshot,
) -> Result<wire::Condition, DeviceCertificateStatusProjectionError> {
    let (type_, status, reason, observed_generation, last_transition_time) = match condition {
        DeviceConditionSnapshot::Ready(value) => (
            wire::ConditionType::Ready,
            project_ready_status(value.status()),
            project_ready_reason(value.reason()),
            value.observed_generation(),
            value.last_transition_time(),
        ),
        DeviceConditionSnapshot::Reconciling(value) => (
            wire::ConditionType::Reconciling,
            project_status(value.status()),
            project_reconciling_reason(value.reason()),
            value.observed_generation(),
            value.last_transition_time(),
        ),
        DeviceConditionSnapshot::PendingDevice(value) => (
            wire::ConditionType::PendingDevice,
            project_status(value.status()),
            project_pending_device_reason(value.reason()),
            value.observed_generation(),
            value.last_transition_time(),
        ),
        DeviceConditionSnapshot::Degraded(value) => (
            wire::ConditionType::Degraded,
            project_status(value.status()),
            project_degraded_reason(value.reason()),
            value.observed_generation(),
            value.last_transition_time(),
        ),
        DeviceConditionSnapshot::Quarantined(value) => (
            wire::ConditionType::Quarantined,
            project_status(value.status()),
            project_quarantined_reason(value.reason()),
            value.observed_generation(),
            value.last_transition_time(),
        ),
        DeviceConditionSnapshot::Deleting(value) => (
            wire::ConditionType::Deleting,
            project_status(value.status()),
            project_deleting_reason(value.reason()),
            value.observed_generation(),
            value.last_transition_time(),
        ),
    };
    Ok(wire::Condition {
        last_transition_at: epoch_seconds(last_transition_time)?,
        observed_generation: observed_generation.map_or(Ok(0), |value| bounded_i64(value.get()))?,
        reason,
        status,
        type_,
    })
}

fn project_status(value: ConditionStatus) -> wire::ConditionStatus {
    match value {
        ConditionStatus::True => wire::ConditionStatus::True,
        ConditionStatus::False => wire::ConditionStatus::False,
        ConditionStatus::Unknown => wire::ConditionStatus::Unknown,
    }
}

fn project_ready_status(value: ReadyStatus) -> wire::ConditionStatus {
    match value {
        ReadyStatus::True => wire::ConditionStatus::True,
        ReadyStatus::False => wire::ConditionStatus::False,
        ReadyStatus::Unknown => wire::ConditionStatus::Unknown,
    }
}

fn project_ready_reason(value: ReadyReason) -> wire::ConditionReason {
    match value {
        ReadyReason::StateMatches => wire::ConditionReason::StateMatches,
        ReadyReason::StateDrift => wire::ConditionReason::StateDrift,
        ReadyReason::AwaitingDevice => wire::ConditionReason::AwaitingDevice,
        ReadyReason::CommandRejected => wire::ConditionReason::CommandRejected,
        ReadyReason::CommandTimedOut => wire::ConditionReason::CommandTimedOut,
        ReadyReason::ProtocolViolation => wire::ConditionReason::ProtocolViolation,
        ReadyReason::ArtifactUnavailable => wire::ConditionReason::ArtifactUnavailable,
        ReadyReason::TransportUnavailable => wire::ConditionReason::TransportUnavailable,
    }
}

fn project_reconciling_reason(value: ReconcilingReason) -> wire::ConditionReason {
    match value {
        ReconcilingReason::DesiredAccepted => wire::ConditionReason::DesiredAccepted,
        ReconcilingReason::CommandQueued => wire::ConditionReason::CommandQueued,
        ReconcilingReason::DeviceReported => wire::ConditionReason::DeviceReported,
        ReconcilingReason::StateDrift => wire::ConditionReason::StateDrift,
    }
}

fn project_pending_device_reason(value: PendingDeviceReason) -> wire::ConditionReason {
    match value {
        PendingDeviceReason::CommandQueued => wire::ConditionReason::CommandQueued,
        PendingDeviceReason::AwaitingDevice => wire::ConditionReason::AwaitingDevice,
        PendingDeviceReason::CommandTimedOut => wire::ConditionReason::CommandTimedOut,
        PendingDeviceReason::TransportUnavailable => wire::ConditionReason::TransportUnavailable,
    }
}

fn project_degraded_reason(value: DegradedReason) -> wire::ConditionReason {
    match value {
        DegradedReason::CommandRejected => wire::ConditionReason::CommandRejected,
        DegradedReason::CommandTimedOut => wire::ConditionReason::CommandTimedOut,
        DegradedReason::ProtocolViolation => wire::ConditionReason::ProtocolViolation,
        DegradedReason::ArtifactUnavailable => wire::ConditionReason::ArtifactUnavailable,
        DegradedReason::TransportUnavailable => wire::ConditionReason::TransportUnavailable,
    }
}

fn project_quarantined_reason(value: QuarantinedReason) -> wire::ConditionReason {
    match value {
        QuarantinedReason::ProtocolViolation => wire::ConditionReason::ProtocolViolation,
        QuarantinedReason::QuarantinedByOperator => wire::ConditionReason::QuarantinedByOperator,
    }
}

fn project_deleting_reason(value: DeletingReason) -> wire::ConditionReason {
    match value {
        DeletingReason::DeletionPending => wire::ConditionReason::DeletionPending,
        DeletingReason::DeletionComplete => wire::ConditionReason::DeletionComplete,
    }
}

/// Closed failure taxonomy for the read-only status-store boundary.
#[derive(Debug, thiserror::Error)]
pub enum DeviceCertificateStatusStoreError {
    /// The storage provider was unavailable or the read-only transaction failed.
    #[error("device-certificate status storage is unavailable")]
    StorageUnavailable {
        /// Opaque provider failure retained for controlled diagnostics.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// Persisted rows failed the domain restore funnel.
    #[error("device-certificate status storage returned invalid state")]
    CorruptState(#[source] DeviceCertificateError),
}

impl DeviceCertificateStatusStoreError {
    /// Preserve a provider failure without exposing it as domain state.
    pub fn storage_unavailable(source: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::StorageUnavailable {
            source: Box::new(source),
        }
    }
}

/// Identity-owned, authorization-consuming LocalOnly status read port.
#[trait_variant::make(DeviceCertificateStatusStore: Send)]
#[dynosaur(
    pub DynDeviceCertificateStatusStore = dyn(box) DeviceCertificateStatusStore,
    bridge(dyn)
)]
#[allow(async_fn_in_trait)]
pub trait DeviceCertificateStatusStoreLocal: Send + Sync {
    /// Inspect one exact authorized tenant/path-device scope without business mutation.
    async fn inspect(
        &self,
        query: AuthorizedDeviceCertificateStatusRead,
    ) -> Result<Option<DeviceCertificateStatusEvidence>, DeviceCertificateStatusStoreError>;
}

mod status_port_effect_sealed {
    pub trait Sealed {}
}

/// Closed owner classification for the canonical status-store dyn wrapper.
#[allow(private_bounds)]
pub trait DeviceCertificateStatusPortEffect: status_port_effect_sealed::Sealed {
    /// Strongest capability exposed by this port.
    type Effect: diport::PortEffectClass;
    /// Whether the port can cross tenant boundaries.
    type Privilege: diport::PortPrivilegeClass;
}

impl<'a> status_port_effect_sealed::Sealed for DynDeviceCertificateStatusStore<'a> {}
impl<'a> DeviceCertificateStatusPortEffect for DynDeviceCertificateStatusStore<'a> {
    type Effect = diport::ReadEffect;
    type Privilege = diport::LocalPrivilege;
}

impl<T> status_port_effect_sealed::Sealed for std::sync::Arc<T> where
    T: status_port_effect_sealed::Sealed + ?Sized
{
}
impl<T> DeviceCertificateStatusPortEffect for std::sync::Arc<T>
where
    T: DeviceCertificateStatusPortEffect + ?Sized,
{
    type Effect = T::Effect;
    type Privilege = T::Privilege;
}

impl<T> status_port_effect_sealed::Sealed for Box<T> where
    T: status_port_effect_sealed::Sealed + ?Sized
{
}
impl<T> DeviceCertificateStatusPortEffect for Box<T>
where
    T: DeviceCertificateStatusPortEffect + ?Sized,
{
    type Effect = T::Effect;
    type Privilege = T::Privilege;
}
