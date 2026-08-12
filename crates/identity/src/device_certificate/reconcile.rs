//! Pure DeviceLatent certificate reconcile decisions.
//!
//! This module has no broker, adapter, clock, or raw provider dependency. Callers obtain
//! authoritative time and revocation observations first, then submit this closed input.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use consistency::{ConvergeAction, EngineErrorKind, ReconcileError};
use deviceloop::{
    AuthorizedArtifactDigest, CommandIntentDigest, ConditionStatus, CurrentCertificateStatus,
    DegradedReason, DeletingReason, DeviceConditionState, ExpectedStateHash, FenceEpoch,
    NotReadyStatus, ObservedGeneration, PendingDeviceReason, QuarantinedReason, ReadyProof,
    ReadyReason, ReconcilingReason, ReportedArtifactDigest,
    ReportedStateHash as DeviceLoopReportedStateHash, UpdateCommandState,
};
use eventexec::reconcile::{
    AttemptCompletionOutcome, AttemptScope, DeviceCertificateCommandEvidence,
    DeviceCertificateCommandTtl, DurableReconcileOutcome, DurableReconciler,
    ReconcileScheduleErrorKind, ReconcileScheduleStore, ScheduleActionOutcome,
};

use crate::cert_artifact::{
    ArtifactEligibility, CertificateArtifactAcquisition, CertificateArtifactId,
    CertificateArtifactSource, PersistedCertificateArtifactSnapshot,
};
use diport::{CertNotAfter, CertSerial};

use super::{
    ArtifactAppendOutcome, ArtifactDigest, CertificateAttemptAuthority,
    CertificateConditionMutation, CertificateReconcileRepository,
    CertificateReconcileRepositoryError, CertificateTransportObservation, ConditionStateBatch,
    CurrentCommandExpiryOutcome, DesiredStateSnapshot, DeviceCertificateScope, DeviceSequence,
    ExpectedGeneration, FencedMutationOutcome, ReportEnvelopeId, ReportedStateHash,
    ReportedStateSnapshot, RotationOutcome,
};

const DEGRADED_RETRY_AFTER: Duration = Duration::from_secs(30);

trait CertificateRevocationAccess: Send + Sync {
    fn revoke<'a>(
        &'a self,
        serial: CertSerial,
        scope: diport::CertScope,
        not_after: CertNotAfter,
    ) -> Pin<Box<dyn Future<Output = Result<(), diport::RevocationStoreError>> + Send + 'a>>;

    fn is_revoked<'a>(
        &'a self,
        serial: CertSerial,
        scope: diport::CertScope,
    ) -> Pin<Box<dyn Future<Output = Result<bool, diport::RevocationStoreError>> + Send + 'a>>;
}

impl<T> CertificateRevocationAccess for T
where
    T: diport::RevocationStore + Send + Sync,
{
    fn revoke<'a>(
        &'a self,
        serial: CertSerial,
        scope: diport::CertScope,
        not_after: CertNotAfter,
    ) -> Pin<Box<dyn Future<Output = Result<(), diport::RevocationStoreError>> + Send + 'a>> {
        Box::pin(diport::RevocationStore::revoke(
            self, serial, scope, not_after,
        ))
    }

    fn is_revoked<'a>(
        &'a self,
        serial: CertSerial,
        scope: diport::CertScope,
    ) -> Pin<Box<dyn Future<Output = Result<bool, diport::RevocationStoreError>> + Send + 'a>> {
        Box::pin(diport::RevocationStore::is_revoked(self, serial, scope))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CertificateDependency {
    ArtifactAuthority,
    RevocationStore,
    DeviceTransport,
}

impl CertificateDependency {
    const fn as_label(self) -> &'static str {
        match self {
            Self::ArtifactAuthority => "artifact_authority",
            Self::RevocationStore => "revocation_store",
            Self::DeviceTransport => "device_transport",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CertificateDegradedObservation {
    dependency: CertificateDependency,
    reason: DegradedReason,
    retry_after: Duration,
}

impl CertificateDegradedObservation {
    const fn new(dependency: CertificateDependency, reason: DegradedReason) -> Self {
        Self {
            dependency,
            reason,
            retry_after: DEGRADED_RETRY_AFTER,
        }
    }

    fn into_outcome(self) -> DurableReconcileOutcome {
        tracing::warn!(
            dependency = self.dependency.as_label(),
            reason = self.reason.as_label(),
            retry_after_ms = 30_000_u64,
            "device-certificate dependency degraded; retry scheduled"
        );
        DurableReconcileOutcome::requeue_after(self.retry_after)
    }
}

/// Device command selected by the pure decision function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateCommandKind {
    /// No report exists for the desired generation.
    Create,
    /// A report exists but differs from the complete authorized state.
    Update,
}

/// Current report/transport observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateReportObservation<'a> {
    /// No device report has ever been accepted.
    Missing,
    /// The fenced transport observation forbids publication in this pass.
    Offline,
    /// One authenticated current report is available.
    Reported(&'a ReportedStateSnapshot),
}

/// Authoritative revocation-store observation for the current artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateRevocationObservation {
    /// Current serial is not revoked.
    Unrevoked,
    /// Current serial is revoked and requires a new desired generation.
    Revoked,
    /// The single revocation truth source was unavailable.
    Unavailable,
}

/// Closed result of reconciling every retained artifact against the single revocation truth
/// source. Callers cannot fabricate the terminal variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateDeletionObservation {
    /// Every retained artifact was already terminal or was successfully revoked in this pass.
    Complete(DeletionTerminalEvidence),
    /// A revocation read/write failed; deletion must retain its finalizer and retry.
    ArtifactUnavailable,
}

/// Sealed proof that all retained artifacts reached revocation or authoritative expiry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeletionTerminalEvidence {
    _seal: (),
}

/// Reconcile retained artifact terminal evidence before asking PostgreSQL to perform its final
/// transactional recheck and completion.
async fn reconcile_deletion_evidence<E>(
    receipts: &[PersistedCertificateArtifactSnapshot<E>],
    authoritative_now: SystemTime,
    revocations: &dyn CertificateRevocationAccess,
) -> CertificateDeletionObservation
where
    E: ArtifactEligibility,
{
    for receipt in receipts {
        if authoritative_now >= receipt.not_after().as_system_time() {
            continue;
        }
        let serial = receipt.serial().clone();
        let scope = receipt.cert_scope();
        let revoked = match revocations.is_revoked(serial.clone(), scope).await {
            Ok(revoked) => revoked,
            Err(_) => return CertificateDeletionObservation::ArtifactUnavailable,
        };
        if !revoked
            && revocations
                .revoke(serial, scope, receipt.not_after())
                .await
                .is_err()
        {
            return CertificateDeletionObservation::ArtifactUnavailable;
        }
    }
    CertificateDeletionObservation::Complete(DeletionTerminalEvidence { _seal: () })
}

/// Complete evidence needed to represent `Ready=True/StateMatches` in the persistence adapter.
/// Private fields prevent callers or adapters from fabricating readiness.
#[derive(Debug, PartialEq, Eq)]
pub struct CertificateReadyProof {
    core: ReadyProof,
    scope: DeviceCertificateScope,
    generation: ExpectedGeneration,
    fence_epoch: FenceEpoch,
    intent_digest: CommandIntentDigest,
    artifact_id: CertificateArtifactId,
    artifact_digest: ArtifactDigest,
    policy_hash: super::PolicyHash,
    state_hash: ReportedStateHash,
    report_envelope_id: ReportEnvelopeId,
    device_sequence: DeviceSequence,
    report_received_at: SystemTime,
    serial: CertSerial,
    not_after: CertNotAfter,
    authoritative_now: SystemTime,
    renew_at: SystemTime,
}

impl CertificateReadyProof {
    /// Revalidate complete current evidence reconstructed by a durable provider.
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn restore_current<E: ArtifactEligibility>(
        scope: DeviceCertificateScope,
        desired: &DesiredStateSnapshot,
        receipt: &PersistedCertificateArtifactSnapshot<E>,
        report: &ReportedStateSnapshot,
        command: &DeviceCertificateCommandEvidence,
        authoritative_now: SystemTime,
        revocation: CertificateRevocationObservation,
    ) -> Result<Self, CertificateReadyProofError> {
        if receipt.scope() != scope
            || receipt.generation().get() != desired.generation().get()
            || report.observed_generation().get() != desired.generation().get()
            || command.tenant() != scope.tenant()
            || command.device_id() != scope.device().as_uuid()
            || u64::try_from(command.desired_generation().get()).ok()
                != Some(desired.generation().get())
            || command.policy_hash() != desired.policy_hash().as_bytes()
            || receipt.policy_hash() != desired.policy_hash()
            || command.artifact_id() != receipt.artifact_id().as_str()
            || command.artifact_digest() != receipt.artifact_digest().as_bytes()
            || report.fence_epoch().get()
                != u64::try_from(command.fence_epoch().get()).unwrap_or_default()
        {
            return Err(CertificateReadyProofError::BindingMismatch);
        }
        let renew_before =
            Duration::from_secs(u64::from(desired.policy().durations().renew_before().get()));
        let renew_at = receipt
            .not_after()
            .as_system_time()
            .checked_sub(renew_before)
            .ok_or(CertificateReadyProofError::BindingMismatch)?;
        if authoritative_now >= renew_at {
            return Err(CertificateReadyProofError::RenewalRequired);
        }
        let core = ReadyProof::try_new(
            desired.generation(),
            report.observed_generation(),
            ExpectedStateHash::new(*receipt.expected_reported_state_hash().as_bytes()),
            DeviceLoopReportedStateHash::new(*report.state_hash().as_bytes()),
            AuthorizedArtifactDigest::new(*receipt.artifact_digest().as_bytes()),
            ReportedArtifactDigest::new(*report.artifact_digest().as_bytes()),
            authoritative_now,
            receipt.not_after().as_system_time(),
            match revocation {
                CertificateRevocationObservation::Unrevoked => CurrentCertificateStatus::NonRevoked,
                CertificateRevocationObservation::Revoked => CurrentCertificateStatus::Revoked,
                CertificateRevocationObservation::Unavailable => {
                    return Err(CertificateReadyProofError::RevocationUnavailable);
                }
            },
            UpdateCommandState::Absent,
        )?;
        let fence_epoch = FenceEpoch::try_new(
            u64::try_from(command.fence_epoch().get())
                .map_err(|_| CertificateReadyProofError::BindingMismatch)?,
        )
        .map_err(|_| CertificateReadyProofError::BindingMismatch)?;
        Ok(Self {
            core,
            scope,
            generation: receipt.generation(),
            fence_epoch,
            intent_digest: CommandIntentDigest::from_bytes(*command.intent_digest()),
            artifact_id: receipt.artifact_id().clone(),
            artifact_digest: receipt.artifact_digest().clone(),
            policy_hash: receipt.policy_hash().clone(),
            state_hash: report.state_hash().clone(),
            report_envelope_id: report.report_envelope_id().clone(),
            device_sequence: report.device_sequence(),
            report_received_at: report.received_at(),
            serial: receipt.serial().clone(),
            not_after: receipt.not_after(),
            authoritative_now,
            renew_at,
        })
    }

    /// Consume the extended proof into the single DeviceLatent readiness state chain.
    #[must_use]
    pub fn into_condition_state(self) -> DeviceConditionState {
        DeviceConditionState::ready_true(self.core)
    }

    pub(crate) fn into_core(self) -> ReadyProof {
        self.core
    }

    /// Proven tenant/device scope.
    #[must_use]
    pub const fn scope(&self) -> DeviceCertificateScope {
        self.scope
    }
    /// Proven desired generation.
    #[must_use]
    pub const fn generation(&self) -> ExpectedGeneration {
        self.generation
    }
    /// Proven current command fence epoch.
    #[must_use]
    pub const fn fence_epoch(&self) -> FenceEpoch {
        self.fence_epoch
    }
    /// Proven canonical current command intent.
    #[must_use]
    pub const fn intent_digest(&self) -> CommandIntentDigest {
        self.intent_digest
    }
    /// Proven provider artifact identity.
    #[must_use]
    pub const fn artifact_id(&self) -> &CertificateArtifactId {
        &self.artifact_id
    }
    /// Proven public artifact digest.
    #[must_use]
    pub const fn artifact_digest(&self) -> &ArtifactDigest {
        &self.artifact_digest
    }
    /// Proven expected and reported public state digest.
    #[must_use]
    pub const fn state_hash(&self) -> &ReportedStateHash {
        &self.state_hash
    }
    /// Proven report envelope high-water.
    #[must_use]
    pub const fn report_envelope_id(&self) -> &ReportEnvelopeId {
        &self.report_envelope_id
    }
    /// Proven device sequence high-water.
    #[must_use]
    pub const fn device_sequence(&self) -> DeviceSequence {
        self.device_sequence
    }
    /// Authoritative receive time of the proven report high-water.
    #[must_use]
    pub const fn report_received_at(&self) -> SystemTime {
        self.report_received_at
    }
    /// Proven desired policy digest.
    #[must_use]
    pub const fn policy_hash(&self) -> &super::PolicyHash {
        &self.policy_hash
    }
    /// Proven certificate serial.
    #[must_use]
    pub const fn serial(&self) -> &CertSerial {
        &self.serial
    }
    /// Proven terminal expiry coordinate.
    #[must_use]
    pub const fn not_after(&self) -> CertNotAfter {
        self.not_after
    }
    /// Authoritative time used for this proof.
    #[must_use]
    pub const fn authoritative_now(&self) -> SystemTime {
        self.authoritative_now
    }
    /// Exact renewal boundary checked by this proof.
    #[must_use]
    pub const fn renew_at(&self) -> SystemTime {
        self.renew_at
    }
}

/// Closed rejection while reconstructing complete readiness evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CertificateReadyProofError {
    /// A tenant/device/generation/policy/command coordinate differed.
    #[error("certificate readiness binding mismatch")]
    BindingMismatch,
    /// Current authoritative time entered the configured renewal window.
    #[error("certificate renewal is required")]
    RenewalRequired,
    /// Current revocation truth was unavailable.
    #[error("certificate revocation state is unavailable")]
    RevocationUnavailable,
    /// The shared DeviceLatent proof rejected state, artifact, time, or revocation evidence.
    #[error(transparent)]
    Core(#[from] deviceloop::ReadyProofError),
}

/// Closed reconcile decision. Every non-ready branch carries only existing DeviceLatent reasons.
#[derive(Debug, PartialEq, Eq)]
enum CertificateReconcileDecision {
    /// Queue a canonical create/update command and wait for device convergence.
    Issue {
        /// Canonical command operation.
        command: CertificateCommandKind,
        /// Ready=False reason.
        ready_reason: ReadyReason,
        /// PendingDevice=True reason.
        pending_reason: PendingDeviceReason,
    },
    /// A received command is the current report authority; keep waiting without replacing it.
    AwaitReport,
    /// Complete state, artifact, time, and revocation evidence matched.
    Ready(Box<CertificateReadyProof>),
    /// Advance desired generation exactly once before authoring another intent.
    Rotate,
    /// Bounded retry is required after a closed infrastructure/transport observation.
    RetryDegraded(CertificateDegradedObservation),
}

/// Immutable input to [`decide_certificate_reconcile`].
struct CertificateReconcileInput<'a, E: ArtifactEligibility> {
    scope: DeviceCertificateScope,
    desired: &'a DesiredStateSnapshot,
    receipt: Option<&'a PersistedCertificateArtifactSnapshot<E>>,
    report: CertificateReportObservation<'a>,
    revocation: CertificateRevocationObservation,
    authoritative_now: SystemTime,
    current_command: Option<&'a DeviceCertificateCommandEvidence>,
}

impl<'a, E: ArtifactEligibility> CertificateReconcileInput<'a, E> {
    /// Assemble active-workflow observations. Deletion owns a separate finalizer workflow.
    #[must_use]
    pub fn new(
        scope: DeviceCertificateScope,
        desired: &'a DesiredStateSnapshot,
        receipt: Option<&'a PersistedCertificateArtifactSnapshot<E>>,
        report: CertificateReportObservation<'a>,
        revocation: CertificateRevocationObservation,
        authoritative_now: SystemTime,
        current_command: Option<&'a DeviceCertificateCommandEvidence>,
    ) -> Self {
        Self {
            scope,
            desired,
            receipt,
            report,
            revocation,
            authoritative_now,
            current_command,
        }
    }
}

/// Select the next closed action without performing I/O.
#[must_use]
fn decide_certificate_reconcile<E: ArtifactEligibility>(
    input: &CertificateReconcileInput<'_, E>,
) -> CertificateReconcileDecision {
    if input.revocation == CertificateRevocationObservation::Unavailable {
        return CertificateReconcileDecision::RetryDegraded(CertificateDegradedObservation::new(
            CertificateDependency::RevocationStore,
            DegradedReason::ArtifactUnavailable,
        ));
    }

    match input.report {
        CertificateReportObservation::Missing => {
            if input.current_command.is_some() {
                CertificateReconcileDecision::AwaitReport
            } else {
                CertificateReconcileDecision::Issue {
                    command: CertificateCommandKind::Create,
                    ready_reason: ReadyReason::AwaitingDevice,
                    pending_reason: PendingDeviceReason::AwaitingDevice,
                }
            }
        }
        CertificateReportObservation::Offline => {
            CertificateReconcileDecision::RetryDegraded(CertificateDegradedObservation::new(
                CertificateDependency::DeviceTransport,
                DegradedReason::TransportUnavailable,
            ))
        }
        CertificateReportObservation::Reported(report) => decide_reported(input, report),
    }
}

fn decide_reported<E: ArtifactEligibility>(
    input: &CertificateReconcileInput<'_, E>,
    report: &ReportedStateSnapshot,
) -> CertificateReconcileDecision {
    let Some(receipt) = input.receipt else {
        return CertificateReconcileDecision::RetryDegraded(CertificateDegradedObservation::new(
            CertificateDependency::ArtifactAuthority,
            DegradedReason::ArtifactUnavailable,
        ));
    };

    if input.revocation == CertificateRevocationObservation::Revoked
        || renewal_window_open(input.desired, receipt, input.authoritative_now)
    {
        return CertificateReconcileDecision::Rotate;
    }

    let Some(command) = input.current_command else {
        return drift_decision();
    };

    match CertificateReadyProof::restore_current(
        input.scope,
        input.desired,
        receipt,
        report,
        command,
        input.authoritative_now,
        input.revocation,
    ) {
        Ok(proof) => CertificateReconcileDecision::Ready(Box::new(proof)),
        Err(CertificateReadyProofError::RenewalRequired) => CertificateReconcileDecision::Rotate,
        Err(CertificateReadyProofError::RevocationUnavailable) => {
            CertificateReconcileDecision::RetryDegraded(CertificateDegradedObservation::new(
                CertificateDependency::RevocationStore,
                DegradedReason::ArtifactUnavailable,
            ))
        }
        Err(CertificateReadyProofError::BindingMismatch | CertificateReadyProofError::Core(_)) => {
            drift_decision()
        }
    }
}

fn drift_decision() -> CertificateReconcileDecision {
    CertificateReconcileDecision::Issue {
        command: CertificateCommandKind::Update,
        ready_reason: ReadyReason::StateDrift,
        pending_reason: PendingDeviceReason::AwaitingDevice,
    }
}

fn renewal_window_open<E: ArtifactEligibility>(
    desired: &DesiredStateSnapshot,
    receipt: &PersistedCertificateArtifactSnapshot<E>,
    now: SystemTime,
) -> bool {
    if now >= receipt.not_after().as_system_time() {
        return true;
    }
    let renew_before =
        Duration::from_secs(u64::from(desired.policy().durations().renew_before().get()));
    receipt
        .not_after()
        .as_system_time()
        .duration_since(now)
        .map_or(true, |remaining| remaining <= renew_before)
}

/// Fully constructed durable certificate reconciler. Construction is deliberately separate from
/// scheduler activation, so composition can prove complete wiring without starting a worker.
pub struct DeviceCertificateReconciler<S, R, E>
where
    S: CertificateArtifactSource<Eligibility = E>,
    R: CertificateReconcileRepository<E>,
    E: ArtifactEligibility,
{
    repository: R,
    artifact_source: Arc<S>,
    revocations: Box<dyn CertificateRevocationAccess>,
    clock: Arc<dyn diport::Clock>,
    command_ttl: DeviceCertificateCommandTtl,
    eligibility: std::marker::PhantomData<fn() -> E>,
}

impl<S, R, E> DeviceCertificateReconciler<S, R, E>
where
    S: CertificateArtifactSource<Eligibility = E>,
    R: CertificateReconcileRepository<E>,
    E: ArtifactEligibility,
{
    /// Capture all mandatory, statically eligibility-bound dependencies.
    pub fn new<V>(
        repository: R,
        artifact_source: Arc<S>,
        revocations: V,
        clock: Arc<dyn diport::Clock>,
        command_ttl: DeviceCertificateCommandTtl,
    ) -> Self
    where
        V: diport::RevocationStore + Send + Sync + 'static,
    {
        Self {
            repository,
            artifact_source,
            revocations: Box::new(revocations),
            clock,
            command_ttl,
            eligibility: std::marker::PhantomData,
        }
    }

    async fn run<Store: ReconcileScheduleStore>(
        &self,
        attempt: &AttemptScope<'_, Store>,
    ) -> Result<DurableReconcileOutcome, ReconcileError> {
        let attempt_snapshot = attempt
            .device_certificate_snapshot()
            .map_err(map_schedule_error)?;
        let authority = CertificateAttemptAuthority::from_snapshot(&attempt_snapshot)
            .map_err(|_| invariant())?;
        let Some(view) = self
            .repository
            .load_current_view(&authority)
            .await
            .map_err(map_repo_error)?
        else {
            return Ok(DurableReconcileOutcome::settled());
        };
        let fence = view.fence();
        let now = self.clock.now();
        let receipts_result = self.repository.load_artifact_receipts(fence).await;
        let receipts = self.repo_after_fence(fence, receipts_result).await?;
        if view.deletion_requested() {
            return self.reconcile_deletion(attempt, &receipts, now).await;
        }
        match self
            .repository
            .expire_due_current_command(fence)
            .await
            .map_err(map_repo_error)?
        {
            CurrentCommandExpiryOutcome::NoCurrent | CurrentCommandExpiryOutcome::NotDue => {}
            CurrentCommandExpiryOutcome::Expired | CurrentCommandExpiryOutcome::AlreadyExpired => {
                self.write_degraded(fence, DegradedReason::CommandTimedOut)
                    .await?;
                return Ok(DurableReconcileOutcome::settled());
            }
            CurrentCommandExpiryOutcome::StaleFence => return Err(transient()),
        }
        let desired = view.state().desired();
        if view.transport() == CertificateTransportObservation::Unavailable {
            let offline = CertificateReconcileInput::<E>::new(
                authority.scope(),
                desired,
                None,
                CertificateReportObservation::Offline,
                CertificateRevocationObservation::Unrevoked,
                now,
                None,
            );
            let CertificateReconcileDecision::RetryDegraded(observation) =
                decide_certificate_reconcile(&offline)
            else {
                return Err(invariant());
            };
            self.write_degraded(fence, observation.reason).await?;
            return Ok(observation.into_outcome());
        }

        let mut receipt = receipts
            .into_iter()
            .find(|value| value.generation().get() == desired.generation().get());
        if receipt.is_none() {
            let request = CertificateArtifactAcquisition::from_desired(authority.scope(), desired)
                .map_err(|_| invariant())?;
            let authorized = match self.artifact_source.acquire(request).await {
                Ok(authorized) => authorized,
                Err(crate::cert_artifact::CertificateArtifactError::Unavailable) => {
                    let observation = CertificateDegradedObservation::new(
                        CertificateDependency::ArtifactAuthority,
                        DegradedReason::ArtifactUnavailable,
                    );
                    self.write_degraded(fence, observation.reason).await?;
                    return Ok(observation.into_outcome());
                }
                Err(
                    crate::cert_artifact::CertificateArtifactError::InvalidArtifactId
                    | crate::cert_artifact::CertificateArtifactError::BindingMismatch,
                ) => {
                    self.write_quarantined(fence).await?;
                    return Err(invariant());
                }
            };
            let authorization = authorized.into_append_authorization();
            let candidate = authorization.snapshot().clone();
            let append = self
                .repository
                .append_artifact_receipt(fence, authorization)
                .await;
            match self.repo_after_fence(fence, append).await? {
                ArtifactAppendOutcome::Appended | ArtifactAppendOutcome::Replayed => {
                    receipt = Some(candidate)
                }
                ArtifactAppendOutcome::Conflict => {
                    self.write_quarantined(fence).await?;
                    return Err(invariant());
                }
                ArtifactAppendOutcome::StaleFence => return Err(transient()),
            }
        }
        let Some(receipt) = receipt.as_ref() else {
            return Err(invariant());
        };
        let revocation = match self
            .revocations
            .is_revoked(receipt.serial().clone(), receipt.cert_scope())
            .await
        {
            Ok(false) => CertificateRevocationObservation::Unrevoked,
            Ok(true) => CertificateRevocationObservation::Revoked,
            Err(_) => CertificateRevocationObservation::Unavailable,
        };
        let command_result = self.repository.load_current_command_evidence(fence).await;
        let command = self.repo_after_fence(fence, command_result).await?;
        let report = view.state().reported().map_or(
            CertificateReportObservation::Missing,
            CertificateReportObservation::Reported,
        );
        let input = CertificateReconcileInput::new(
            authority.scope(),
            desired,
            Some(receipt),
            report,
            revocation,
            now,
            command.as_ref(),
        );
        self.apply_decision(
            attempt,
            fence,
            receipt,
            desired,
            now,
            decide_certificate_reconcile(&input),
        )
        .await
    }

    async fn reconcile_deletion<Store: ReconcileScheduleStore>(
        &self,
        attempt: &AttemptScope<'_, Store>,
        receipts: &[PersistedCertificateArtifactSnapshot<E>],
        now: SystemTime,
    ) -> Result<DurableReconcileOutcome, ReconcileError> {
        match reconcile_deletion_evidence(receipts, now, &*self.revocations).await {
            CertificateDeletionObservation::ArtifactUnavailable => {
                let observation = CertificateDegradedObservation::new(
                    CertificateDependency::RevocationStore,
                    DegradedReason::ArtifactUnavailable,
                );
                Ok(observation.into_outcome())
            }
            CertificateDeletionObservation::Complete(_) => match attempt
                .complete_device_certificate_deletion()
                .await
                .map_err(map_schedule_error)?
            {
                AttemptCompletionOutcome::Completed(receipt) => {
                    Ok(DurableReconcileOutcome::completed(receipt))
                }
                AttemptCompletionOutcome::EvidencePending => Ok(
                    DurableReconcileOutcome::requeue_after(Duration::from_secs(30)),
                ),
                AttemptCompletionOutcome::Lost => Err(transient()),
            },
        }
    }

    async fn apply_decision<Store: ReconcileScheduleStore>(
        &self,
        attempt: &AttemptScope<'_, Store>,
        fence: &super::CertificateAttemptFence,
        receipt: &PersistedCertificateArtifactSnapshot<E>,
        desired: &DesiredStateSnapshot,
        now: SystemTime,
        decision: CertificateReconcileDecision,
    ) -> Result<DurableReconcileOutcome, ReconcileError> {
        match decision {
            CertificateReconcileDecision::Issue {
                command,
                ready_reason,
                pending_reason,
            } => {
                let action = match command {
                    CertificateCommandKind::Create => ConvergeAction::Create,
                    CertificateCommandKind::Update => ConvergeAction::Update,
                };
                let reviewed = match attempt.review_device_certificate_command(
                    receipt.generation().get(),
                    receipt.artifact_id().as_str(),
                    *receipt.artifact_digest().as_bytes(),
                    *receipt.policy_hash().as_bytes(),
                    now,
                    self.command_ttl,
                ) {
                    Ok(reviewed) => reviewed,
                    Err(error) => return self.fail_after_schedule_error(fence, error).await,
                };
                let record = attempt
                    .record_device_certificate_command(action, reviewed)
                    .await;
                match record {
                    Ok(ScheduleActionOutcome::Enqueued | ScheduleActionOutcome::Duplicate) => {}
                    Ok(ScheduleActionOutcome::Lost) => return Err(transient()),
                    Err(error) => return self.fail_after_schedule_error(fence, error).await,
                }
                let generation = Some(
                    ObservedGeneration::try_new(desired.generation().get())
                        .map_err(|_| invariant())?,
                );
                let batch = active_issue_conditions(generation, ready_reason, pending_reason)
                    .map_err(|_| invariant())?;
                self.write_conditions(fence, CertificateConditionMutation::States(batch))
                    .await?;
                Ok(DurableReconcileOutcome::requeue_after(Duration::from_secs(
                    30,
                )))
            }
            CertificateReconcileDecision::AwaitReport => Ok(
                DurableReconcileOutcome::requeue_after(Duration::from_secs(30)),
            ),
            CertificateReconcileDecision::Ready(proof) => {
                self.write_conditions(fence, CertificateConditionMutation::Ready(proof))
                    .await?;
                Ok(DurableReconcileOutcome::settled())
            }
            CertificateReconcileDecision::Rotate => match self
                .repo_after_fence(fence, self.repository.rotate_generation(fence).await)
                .await?
            {
                RotationOutcome::Rotated { .. } => Ok(DurableReconcileOutcome::requeue_after(
                    Duration::from_secs(1),
                )),
                RotationOutcome::StaleFence => Err(transient()),
                RotationOutcome::GenerationExhausted => {
                    self.write_quarantined(fence).await?;
                    Err(invariant())
                }
            },
            CertificateReconcileDecision::RetryDegraded(observation) => {
                self.write_degraded(fence, observation.reason).await?;
                Ok(observation.into_outcome())
            }
        }
    }

    async fn write_degraded(
        &self,
        fence: &super::CertificateAttemptFence,
        reason: DegradedReason,
    ) -> Result<(), ReconcileError> {
        let generation = ObservedGeneration::try_new(fence.expected_generation().get())
            .map_err(|_| invariant())?;
        let batch =
            active_degraded_conditions(Some(generation), reason).map_err(|_| invariant())?;
        self.write_conditions(fence, CertificateConditionMutation::States(batch))
            .await
    }

    async fn write_quarantined(
        &self,
        fence: &super::CertificateAttemptFence,
    ) -> Result<(), ReconcileError> {
        let generation = ObservedGeneration::try_new(fence.expected_generation().get())
            .map_err(|_| invariant())?;
        let batch = active_quarantined_conditions(Some(generation)).map_err(|_| invariant())?;
        self.write_conditions(fence, CertificateConditionMutation::States(batch))
            .await
    }

    async fn write_conditions(
        &self,
        fence: &super::CertificateAttemptFence,
        mutation: CertificateConditionMutation,
    ) -> Result<(), ReconcileError> {
        match self
            .repository
            .write_conditions(fence, mutation)
            .await
            .map_err(map_repo_error)?
        {
            FencedMutationOutcome::Applied => Ok(()),
            FencedMutationOutcome::StaleFence | FencedMutationOutcome::MissingDesired => {
                Err(transient())
            }
        }
    }

    async fn fail_after_schedule_error(
        &self,
        fence: &super::CertificateAttemptFence,
        error: eventexec::reconcile::ReconcileScheduleError,
    ) -> Result<DurableReconcileOutcome, ReconcileError> {
        match error.kind() {
            ReconcileScheduleErrorKind::Infrastructure => Err(transient()),
            ReconcileScheduleErrorKind::PermanentFailure => {
                self.write_degraded(fence, DegradedReason::ProtocolViolation)
                    .await?;
                Err(ReconcileError::new(EngineErrorKind::Permanent))
            }
            ReconcileScheduleErrorKind::FactConflict
            | ReconcileScheduleErrorKind::InvariantViolation => {
                self.write_quarantined(fence).await?;
                Err(invariant())
            }
        }
    }

    async fn repo_after_fence<T>(
        &self,
        fence: &super::CertificateAttemptFence,
        result: Result<T, CertificateReconcileRepositoryError>,
    ) -> Result<T, ReconcileError> {
        match result {
            Ok(value) => Ok(value),
            Err(CertificateReconcileRepositoryError::StorageUnavailable { .. }) => Err(transient()),
            Err(
                CertificateReconcileRepositoryError::InvalidMutation
                | CertificateReconcileRepositoryError::CorruptState(_)
                | CertificateReconcileRepositoryError::CommandInvariant(_),
            ) => {
                self.write_quarantined(fence).await?;
                Err(invariant())
            }
        }
    }
}

impl<Store, Source, Repository, E> DurableReconciler<Store>
    for DeviceCertificateReconciler<Source, Repository, E>
where
    Store: ReconcileScheduleStore,
    Source: CertificateArtifactSource<Eligibility = E>,
    Repository: CertificateReconcileRepository<E>,
    E: ArtifactEligibility,
{
    async fn reconcile(
        &self,
        _ctx: &consistency::Context,
        _target: &eventexec::reconcile::ClaimedTarget,
        attempt: &AttemptScope<'_, Store>,
    ) -> Result<DurableReconcileOutcome, ReconcileError> {
        self.run(attempt).await
    }
}

fn active_issue_conditions(
    generation: Option<ObservedGeneration>,
    ready_reason: ReadyReason,
    pending_reason: PendingDeviceReason,
) -> Result<ConditionStateBatch, super::DeviceCertificateError> {
    ConditionStateBatch::new(vec![
        DeviceConditionState::ready(NotReadyStatus::False, ready_reason, generation),
        DeviceConditionState::reconciling(
            ConditionStatus::True,
            ReconcilingReason::CommandQueued,
            generation,
        ),
        DeviceConditionState::pending_device(ConditionStatus::True, pending_reason, generation),
        DeviceConditionState::degraded(
            ConditionStatus::False,
            DegradedReason::ArtifactUnavailable,
            generation,
        ),
        DeviceConditionState::quarantined(
            ConditionStatus::False,
            QuarantinedReason::ProtocolViolation,
            generation,
        ),
        DeviceConditionState::deleting(
            ConditionStatus::False,
            DeletingReason::DeletionPending,
            generation,
        ),
    ])
}

fn active_degraded_conditions(
    generation: Option<ObservedGeneration>,
    reason: DegradedReason,
) -> Result<ConditionStateBatch, super::DeviceCertificateError> {
    let ready_reason = match reason {
        DegradedReason::CommandRejected => ReadyReason::CommandRejected,
        DegradedReason::CommandTimedOut => ReadyReason::CommandTimedOut,
        DegradedReason::ProtocolViolation => ReadyReason::ProtocolViolation,
        DegradedReason::ArtifactUnavailable => ReadyReason::ArtifactUnavailable,
        DegradedReason::TransportUnavailable => ReadyReason::TransportUnavailable,
    };
    let pending_reason = match reason {
        DegradedReason::CommandTimedOut => PendingDeviceReason::CommandTimedOut,
        DegradedReason::TransportUnavailable => PendingDeviceReason::TransportUnavailable,
        DegradedReason::CommandRejected
        | DegradedReason::ProtocolViolation
        | DegradedReason::ArtifactUnavailable => PendingDeviceReason::AwaitingDevice,
    };
    ConditionStateBatch::new(vec![
        DeviceConditionState::ready(NotReadyStatus::False, ready_reason, generation),
        DeviceConditionState::reconciling(
            ConditionStatus::False,
            ReconcilingReason::StateDrift,
            generation,
        ),
        DeviceConditionState::pending_device(ConditionStatus::False, pending_reason, generation),
        DeviceConditionState::degraded(ConditionStatus::True, reason, generation),
        DeviceConditionState::quarantined(
            ConditionStatus::False,
            QuarantinedReason::ProtocolViolation,
            generation,
        ),
        DeviceConditionState::deleting(
            ConditionStatus::False,
            DeletingReason::DeletionPending,
            generation,
        ),
    ])
}

fn active_quarantined_conditions(
    generation: Option<ObservedGeneration>,
) -> Result<ConditionStateBatch, super::DeviceCertificateError> {
    ConditionStateBatch::new(vec![
        DeviceConditionState::ready(
            NotReadyStatus::False,
            ReadyReason::ProtocolViolation,
            generation,
        ),
        DeviceConditionState::reconciling(
            ConditionStatus::False,
            ReconcilingReason::StateDrift,
            generation,
        ),
        DeviceConditionState::pending_device(
            ConditionStatus::False,
            PendingDeviceReason::AwaitingDevice,
            generation,
        ),
        DeviceConditionState::degraded(
            ConditionStatus::False,
            DegradedReason::ProtocolViolation,
            generation,
        ),
        DeviceConditionState::quarantined(
            ConditionStatus::True,
            QuarantinedReason::ProtocolViolation,
            generation,
        ),
        DeviceConditionState::deleting(
            ConditionStatus::False,
            DeletingReason::DeletionPending,
            generation,
        ),
    ])
}

fn invariant() -> ReconcileError {
    ReconcileError::new(EngineErrorKind::Invariant)
}
fn transient() -> ReconcileError {
    ReconcileError::new(EngineErrorKind::Transient)
}

fn map_repo_error(error: CertificateReconcileRepositoryError) -> ReconcileError {
    match error {
        CertificateReconcileRepositoryError::StorageUnavailable { .. } => transient(),
        CertificateReconcileRepositoryError::InvalidMutation
        | CertificateReconcileRepositoryError::CorruptState(_)
        | CertificateReconcileRepositoryError::CommandInvariant(_) => invariant(),
    }
}

fn map_schedule_error(error: eventexec::reconcile::ReconcileScheduleError) -> ReconcileError {
    match error.kind() {
        ReconcileScheduleErrorKind::Infrastructure => transient(),
        ReconcileScheduleErrorKind::PermanentFailure => {
            ReconcileError::new(EngineErrorKind::Permanent)
        }
        ReconcileScheduleErrorKind::FactConflict
        | ReconcileScheduleErrorKind::InvariantViolation => invariant(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::collections::{HashMap, HashSet};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use deviceloop::{
        CertificateKeyUsage, CertificatePolicy, CertificatePolicyDurations,
        CertificateRenewBeforeSeconds, CertificateSan, CertificateValiditySeconds,
    };
    use diport::{CertNotAfter, CertScope, CertSerial};
    use eventexec::reconcile::{DeviceCertificateCommandEvidence, DeviceCommandAuditProof};
    use ids::DeviceId;
    use rss_request_context::TenantId;

    use crate::cert_artifact::{CertificateArtifactId, CertificatePublicKeyDigest};
    use crate::device_certificate::{DesiredStateRestore, PolicyHash};

    use super::*;

    const NOW_SECONDS: u64 = 10_000;

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn scope() -> DeviceCertificateScope {
        DeviceCertificateScope::for_test(
            TenantId::parse("11111111-1111-1111-1111-111111111111").unwrap(),
            DeviceId::parse("44444444-4444-4444-4444-444444444444").unwrap(),
        )
    }

    #[test]
    fn degraded_observations_emit_closed_low_cardinality_warn_fields() {
        use tracing::field::{Field, Visit};
        use tracing::span::{Attributes, Id, Record};
        use tracing::{Event, Metadata, Subscriber};

        struct CaptureSubscriber(Arc<Mutex<Vec<HashMap<String, String>>>>);
        struct CaptureVisitor(HashMap<String, String>);

        impl Visit for CaptureVisitor {
            fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                self.0.insert(field.name().to_owned(), format!("{value:?}"));
            }

            fn record_str(&mut self, field: &Field, value: &str) {
                self.0.insert(field.name().to_owned(), value.to_owned());
            }

            fn record_u64(&mut self, field: &Field, value: u64) {
                self.0.insert(field.name().to_owned(), value.to_string());
            }
        }

        impl Subscriber for CaptureSubscriber {
            fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
                true
            }

            fn new_span(&self, _span: &Attributes<'_>) -> Id {
                Id::from_u64(1)
            }

            fn record(&self, _span: &Id, _values: &Record<'_>) {}

            fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

            fn event(&self, event: &Event<'_>) {
                let mut visitor = CaptureVisitor(HashMap::from([(
                    "level".to_owned(),
                    event.metadata().level().as_str().to_owned(),
                )]));
                event.record(&mut visitor);
                self.0.lock().unwrap().push(visitor.0);
            }

            fn enter(&self, _span: &Id) {}

            fn exit(&self, _span: &Id) {}
        }

        let events = Arc::new(Mutex::new(Vec::new()));
        let subscriber = CaptureSubscriber(Arc::clone(&events));
        tracing::subscriber::with_default(subscriber, || {
            tracing::callsite::rebuild_interest_cache();
            for observation in [
                CertificateDegradedObservation::new(
                    CertificateDependency::ArtifactAuthority,
                    DegradedReason::ArtifactUnavailable,
                ),
                CertificateDegradedObservation::new(
                    CertificateDependency::RevocationStore,
                    DegradedReason::ArtifactUnavailable,
                ),
                CertificateDegradedObservation::new(
                    CertificateDependency::DeviceTransport,
                    DegradedReason::TransportUnavailable,
                ),
            ] {
                let _ = observation.into_outcome();
            }
            tracing::callsite::rebuild_interest_cache();
        });

        let events = events.lock().unwrap();
        assert_eq!(events.len(), 3, "events={events:?}");
        assert_eq!(
            events
                .iter()
                .map(|event| event.get("dependency").map(String::as_str))
                .collect::<Vec<_>>(),
            [
                Some("artifact_authority"),
                Some("revocation_store"),
                Some("device_transport")
            ]
        );
        for event in events.iter() {
            assert_eq!(event.get("level").map(String::as_str), Some("WARN"));
            assert!(event.contains_key("reason"), "event={event:?}");
            assert_eq!(
                event.get("retry_after_ms").map(String::as_str),
                Some("30000")
            );
        }
    }

    fn desired() -> DesiredStateSnapshot {
        DesiredStateSnapshot::restore(DesiredStateRestore::new(
            7,
            PolicyHash::parse(&digest('b')).unwrap(),
            CertificatePolicy::new(
                CertificatePolicyDurations::new(
                    CertificateValiditySeconds::try_new(3_600).unwrap(),
                    CertificateRenewBeforeSeconds::try_new(300).unwrap(),
                )
                .unwrap(),
                vec![CertificateKeyUsage::ClientAuth],
                vec![CertificateSan::parse("device.example").unwrap()],
            )
            .unwrap(),
            SystemTime::UNIX_EPOCH,
            SystemTime::UNIX_EPOCH,
        ))
        .unwrap()
    }

    fn receipt(
        not_after_seconds: u64,
    ) -> PersistedCertificateArtifactSnapshot<crate::cert_artifact::ProductionEligibility> {
        receipt_with_serial(1, not_after_seconds)
    }

    fn receipt_with_serial(
        serial: u8,
        not_after_seconds: u64,
    ) -> PersistedCertificateArtifactSnapshot<crate::cert_artifact::ProductionEligibility> {
        let scope = scope();
        PersistedCertificateArtifactSnapshot::restore(
            scope,
            ExpectedGeneration::try_new(7).unwrap(),
            PolicyHash::parse(&digest('b')).unwrap(),
            CertificatePublicKeyDigest::digest(b"key"),
            ArtifactDigest::parse(&digest('a')).unwrap(),
            ReportedStateHash::parse(&digest('b')).unwrap(),
            CertificateArtifactId::parse("artifact-device-certificate-v1").unwrap(),
            CertScope::new(scope.tenant(), scope.device()),
            CertSerial::try_new([serial]).unwrap(),
            CertNotAfter::try_from_system_time(
                SystemTime::UNIX_EPOCH + Duration::from_secs(not_after_seconds),
            )
            .unwrap(),
        )
        .unwrap()
    }

    struct FakeRevocations {
        revoked: Mutex<HashSet<Vec<u8>>>,
        reads: AtomicUsize,
        writes: AtomicUsize,
        fail_read: bool,
        fail_write: bool,
    }

    impl FakeRevocations {
        fn healthy(revoked: impl IntoIterator<Item = Vec<u8>>) -> Self {
            Self {
                revoked: Mutex::new(revoked.into_iter().collect()),
                reads: AtomicUsize::new(0),
                writes: AtomicUsize::new(0),
                fail_read: false,
                fail_write: false,
            }
        }
    }

    impl diport::RevocationStore for FakeRevocations {
        async fn revoke(
            &self,
            serial: CertSerial,
            _scope: CertScope,
            _not_after: CertNotAfter,
        ) -> Result<(), diport::RevocationStoreError> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            if self.fail_write {
                return Err(diport::RevocationStoreError::new(std::io::Error::other(
                    "write outage",
                )));
            }
            self.revoked
                .lock()
                .unwrap()
                .insert(serial.as_bytes().to_vec());
            Ok(())
        }

        async fn is_revoked(
            &self,
            serial: CertSerial,
            _scope: CertScope,
        ) -> Result<bool, diport::RevocationStoreError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            if self.fail_read {
                return Err(diport::RevocationStoreError::new(std::io::Error::other(
                    "read outage",
                )));
            }
            Ok(self.revoked.lock().unwrap().contains(serial.as_bytes()))
        }

        async fn shutdown(&self) -> Result<(), diport::RevocationStoreError> {
            Ok(())
        }
    }

    fn now() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(NOW_SECONDS)
    }

    fn command_intent() -> CommandIntentDigest {
        let digest = ArtifactDigest::parse(
            "sha256:5235fccf9c0cdc3ccb274a3e9447af6d05eb602385287e39f1510caae609ac5c",
        )
        .unwrap();
        CommandIntentDigest::from_bytes(*digest.as_bytes())
    }

    fn command_payload(epoch: u64) -> serde_json::Value {
        serde_json::json!({
            "artifactDigest": digest('a'),
            "artifactId": "artifact-device-certificate-v1",
            "deadlineEpochSeconds": 4_000_000_000_u64,
            "desiredGeneration": 7_u64,
            "deviceId": "44444444-4444-4444-4444-444444444444",
            "fenceEpoch": epoch,
            "intentDigest": "sha256:5235fccf9c0cdc3ccb274a3e9447af6d05eb602385287e39f1510caae609ac5c",
            "policyHash": digest('b'),
        })
    }

    fn command_audit(epoch: i64) -> DeviceCommandAuditProof {
        DeviceCommandAuditProof::restore_durable(
            scope().tenant(),
            scope().device().as_uuid(),
            7,
            epoch,
            *command_intent().as_bytes(),
            format!("attempt-{epoch}"),
        )
        .unwrap()
    }

    fn command_evidence(epoch: i64) -> DeviceCertificateCommandEvidence {
        DeviceCertificateCommandEvidence::restore_durable(
            command_audit(epoch),
            &serde_json::to_vec(&command_payload(epoch as u64)).unwrap(),
            4_000_000_000,
        )
        .unwrap()
    }

    #[test]
    fn missing_and_provider_outage_are_closed() {
        let desired = desired();
        let missing = CertificateReconcileInput::<crate::cert_artifact::ProductionEligibility>::new(
            scope(),
            &desired,
            None,
            CertificateReportObservation::Missing,
            CertificateRevocationObservation::Unrevoked,
            now(),
            None,
        );
        assert_eq!(
            decide_certificate_reconcile(&missing),
            CertificateReconcileDecision::Issue {
                command: CertificateCommandKind::Create,
                ready_reason: ReadyReason::AwaitingDevice,
                pending_reason: PendingDeviceReason::AwaitingDevice,
            }
        );
        let acknowledged = command_evidence(9);
        let awaiting_report =
            CertificateReconcileInput::<crate::cert_artifact::ProductionEligibility>::new(
                scope(),
                &desired,
                None,
                CertificateReportObservation::Missing,
                CertificateRevocationObservation::Unrevoked,
                now(),
                Some(&acknowledged),
            );
        assert_eq!(
            decide_certificate_reconcile(&awaiting_report),
            CertificateReconcileDecision::AwaitReport
        );
        let outage = CertificateReconcileInput::<crate::cert_artifact::ProductionEligibility>::new(
            scope(),
            &desired,
            None,
            CertificateReportObservation::Missing,
            CertificateRevocationObservation::Unavailable,
            now(),
            None,
        );
        assert!(matches!(
            decide_certificate_reconcile(&outage),
            CertificateReconcileDecision::RetryDegraded(CertificateDegradedObservation {
                dependency: CertificateDependency::RevocationStore,
                reason: DegradedReason::ArtifactUnavailable,
                retry_after: DEGRADED_RETRY_AFTER,
            })
        ));
    }

    #[test]
    fn drift_matching_renew_and_revoked_are_distinct() {
        let desired = desired();
        let current_receipt = receipt(NOW_SECONDS + 301);
        let matching_state = ReportedStateHash::parse(&digest('b')).unwrap();
        let matching_artifact = ArtifactDigest::parse(&digest('a')).unwrap();
        let drift_state = ReportedStateHash::parse(&digest('d')).unwrap();
        let command = command_evidence(9);
        let report = |epoch, state: ReportedStateHash| {
            ReportedStateSnapshot::restore(crate::device_certificate::ReportedStateRestore::new(
                7,
                epoch,
                state,
                matching_artifact.clone(),
                ReportEnvelopeId::parse(&format!("report-{epoch}")).unwrap(),
                DeviceSequence::try_new(epoch).unwrap(),
                None,
                None,
                now(),
            ))
            .unwrap()
        };
        let matching_report = report(9, matching_state.clone());
        let drift_report = report(9, drift_state);
        let drift = CertificateReconcileInput::new(
            scope(),
            &desired,
            Some(&current_receipt),
            CertificateReportObservation::Reported(&drift_report),
            CertificateRevocationObservation::Unrevoked,
            now(),
            Some(&command),
        );
        assert!(matches!(
            decide_certificate_reconcile(&drift),
            CertificateReconcileDecision::Issue {
                command: CertificateCommandKind::Update,
                ..
            }
        ));
        let matching = CertificateReconcileInput::new(
            scope(),
            &desired,
            Some(&current_receipt),
            CertificateReportObservation::Reported(&matching_report),
            CertificateRevocationObservation::Unrevoked,
            now(),
            Some(&command),
        );
        assert!(matches!(
            decide_certificate_reconcile(&matching),
            CertificateReconcileDecision::Ready(_)
        ));

        let missing_command = CertificateReconcileInput::new(
            scope(),
            &desired,
            Some(&current_receipt),
            CertificateReportObservation::Reported(&matching_report),
            CertificateRevocationObservation::Unrevoked,
            now(),
            None,
        );
        assert!(matches!(
            decide_certificate_reconcile(&missing_command),
            CertificateReconcileDecision::Issue {
                command: CertificateCommandKind::Update,
                ..
            }
        ));
        let stale_command = command_evidence(10);
        let stale_epoch = CertificateReconcileInput::new(
            scope(),
            &desired,
            Some(&current_receipt),
            CertificateReportObservation::Reported(&matching_report),
            CertificateRevocationObservation::Unrevoked,
            now(),
            Some(&stale_command),
        );
        assert!(matches!(
            decide_certificate_reconcile(&stale_epoch),
            CertificateReconcileDecision::Issue {
                command: CertificateCommandKind::Update,
                ..
            }
        ));
        let mut tampered_payload = command_payload(9);
        tampered_payload["artifactId"] =
            serde_json::Value::String("artifact-device-certificate-v2".to_owned());
        assert!(
            DeviceCertificateCommandEvidence::restore_durable(
                command_audit(9),
                &serde_json::to_vec(&tampered_payload).unwrap(),
                4_000_000_000,
            )
            .is_err(),
            "tampered typed payload cannot become command evidence"
        );
        let mut tampered_intent = command_payload(9);
        tampered_intent["intentDigest"] = serde_json::Value::String(digest('f'));
        assert!(
            DeviceCertificateCommandEvidence::restore_durable(
                command_audit(9),
                &serde_json::to_vec(&tampered_intent).unwrap(),
                4_000_000_000,
            )
            .is_err(),
            "tampered intent cannot become command evidence"
        );

        let renewing_receipt = receipt(NOW_SECONDS + 300);
        let renewing = CertificateReconcileInput::new(
            scope(),
            &desired,
            Some(&renewing_receipt),
            CertificateReportObservation::Reported(&matching_report),
            CertificateRevocationObservation::Unrevoked,
            now(),
            Some(&command),
        );
        assert_eq!(
            decide_certificate_reconcile(&renewing),
            CertificateReconcileDecision::Rotate
        );
        let revoked = CertificateReconcileInput::new(
            scope(),
            &desired,
            Some(&current_receipt),
            CertificateReportObservation::Reported(&matching_report),
            CertificateRevocationObservation::Revoked,
            now(),
            Some(&command),
        );
        assert_eq!(
            decide_certificate_reconcile(&revoked),
            CertificateReconcileDecision::Rotate
        );
    }

    #[test]
    fn persisted_ready_requires_and_consumes_fresh_current_proof() {
        let desired = desired();
        let receipt = receipt(NOW_SECONDS + 301);
        let report_restore = crate::device_certificate::ReportedStateRestore::new(
            7,
            9,
            ReportedStateHash::parse(&digest('b')).unwrap(),
            ArtifactDigest::parse(&digest('a')).unwrap(),
            ReportEnvelopeId::parse("ready-report-7").unwrap(),
            DeviceSequence::try_new(7).unwrap(),
            None,
            None,
            now(),
        );
        let report = ReportedStateSnapshot::restore(report_restore.clone()).unwrap();
        let proof = CertificateReadyProof::restore_current(
            scope(),
            &desired,
            &receipt,
            &report,
            &command_evidence(9),
            now(),
            CertificateRevocationObservation::Unrevoked,
        )
        .unwrap();
        let ready = deviceloop::DeviceConditionRestore::from_persisted_labels(
            "Ready",
            "True",
            "StateMatches",
            Some(ObservedGeneration::try_new(7).unwrap()),
            now(),
        )
        .unwrap();
        let desired_restore = crate::device_certificate::DesiredStateRestore::new(
            7,
            PolicyHash::parse(&digest('b')).unwrap(),
            desired.policy().clone(),
            SystemTime::UNIX_EPOCH,
            SystemTime::UNIX_EPOCH,
        );
        assert!(
            crate::device_certificate::DeviceCertificateStateSnapshot::restore(
                scope(),
                desired_restore.clone(),
                Some(report_restore.clone()),
                vec![ready.clone()],
            )
            .is_err(),
            "Ready=True cannot enter through the ordinary persisted-state funnel"
        );
        let state =
            crate::device_certificate::DeviceCertificateStateSnapshot::restore_with_ready_proof(
                scope(),
                desired_restore,
                Some(report_restore),
                vec![ready],
                proof,
            )
            .unwrap();
        assert_eq!(state.conditions()[0].status_label(), "True");
    }

    #[tokio::test]
    async fn deletion_revokes_first_and_multiple_history_before_complete() {
        let receipts = vec![
            receipt_with_serial(1, NOW_SECONDS + 60),
            receipt_with_serial(2, NOW_SECONDS + 60),
            receipt_with_serial(3, NOW_SECONDS),
        ];
        let store = FakeRevocations::healthy([vec![2]]);
        let evidence = reconcile_deletion_evidence(&receipts, now(), &store).await;
        assert!(matches!(
            evidence,
            CertificateDeletionObservation::Complete(_)
        ));
        assert_eq!(store.reads.load(Ordering::SeqCst), 2);
        assert_eq!(store.writes.load(Ordering::SeqCst), 1);
        assert!(store.revoked.lock().unwrap().contains(&vec![1]));

        let empty_store = FakeRevocations::healthy([]);
        let empty = reconcile_deletion_evidence::<crate::cert_artifact::ProductionEligibility>(
            &[],
            now(),
            &empty_store,
        )
        .await;
        assert!(matches!(empty, CertificateDeletionObservation::Complete(_)));
        assert_eq!(empty_store.reads.load(Ordering::SeqCst), 0);
        assert_eq!(empty_store.writes.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn deletion_outage_retains_finalizer_and_retries() {
        let receipts = [receipt_with_serial(1, NOW_SECONDS + 60)];
        let read_outage = FakeRevocations {
            fail_read: true,
            ..FakeRevocations::healthy([])
        };
        let unavailable = reconcile_deletion_evidence(&receipts, now(), &read_outage).await;
        assert_eq!(
            unavailable,
            CertificateDeletionObservation::ArtifactUnavailable
        );
        let write_outage = FakeRevocations {
            fail_write: true,
            ..FakeRevocations::healthy([])
        };
        assert_eq!(
            reconcile_deletion_evidence(&receipts, now(), &write_outage).await,
            CertificateDeletionObservation::ArtifactUnavailable
        );
    }

    mod component {
        use std::collections::BTreeMap;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        use consistency::{Context, OutboxFactConflict};
        use eventexec::command::{CommandAliasKey, CommandIdempotencyKeyring};
        use eventexec::reconcile::{
            AttemptResult, AttemptTrigger, ClaimedTarget, ClaimedTargetRestore, FailureStreak,
            ReconcileAttempt, ReconcileMaxInFlight, ReconcileScheduleError, ReconcileScheduleStore,
            ReconcileWake, ReviewedFencedCommand, ScheduleActionOutcome, ScheduleAttemptOutcome,
            ScheduleCompletionOutcome, ScheduleLeaseOutcome, ScheduleResultOutcome, WakeVersion,
        };
        use sha2::{Digest as _, Sha256};

        use crate::cert_artifact::{
            ArtifactAppendAuthorization, CertificateArtifactRequest, CertificateArtifactSource,
            ProductionEligibility, ProviderCertificateCandidate,
        };
        use crate::device_certificate::{
            CertificateAttemptFence, CertificateReconcileView, CertificateTransportObservation,
            CurrentCommandExpiryOutcome, DeletionRequestOutcome, DeviceCertificateStateSnapshot,
            ReportedStateRestore,
        };

        use super::*;

        #[derive(Clone, Copy)]
        enum SourceMode {
            Healthy,
            Unavailable,
            BindingMismatch,
        }

        struct FakeSource {
            mode: SourceMode,
            calls: AtomicUsize,
        }

        impl FakeSource {
            fn new(mode: SourceMode) -> Self {
                Self {
                    mode,
                    calls: AtomicUsize::new(0),
                }
            }
        }

        impl CertificateArtifactSource for FakeSource {
            type Eligibility = ProductionEligibility;

            async fn acquire(
                &self,
                request: CertificateArtifactAcquisition,
            ) -> Result<
                crate::cert_artifact::AuthorizedCertificateArtifact<
                    crate::cert_artifact::ProductionEligibility,
                >,
                crate::cert_artifact::CertificateArtifactError,
            > {
                self.calls.fetch_add(1, Ordering::SeqCst);
                match self.mode {
                    SourceMode::Unavailable => {
                        return Err(crate::cert_artifact::CertificateArtifactError::Unavailable);
                    }
                    SourceMode::BindingMismatch => {
                        return Err(
                            crate::cert_artifact::CertificateArtifactError::BindingMismatch,
                        );
                    }
                    SourceMode::Healthy => {}
                }
                let artifact = b"component-public-certificate".to_vec();
                let artifact_digest = ArtifactDigest::restore(&Sha256::digest(&artifact)).unwrap();
                let state_hash = ReportedStateHash::parse(&digest('b')).unwrap();
                let artifact_id = CertificateArtifactId::parse("component-artifact-0001").unwrap();
                let public_key = CertificatePublicKeyDigest::digest(b"component-public-key");
                let cert_scope = CertScope::new(request.scope().tenant(), request.scope().device());
                let serial = CertSerial::try_new([0x42]).unwrap();
                let not_after =
                    CertNotAfter::try_from_system_time(now() + Duration::from_secs(600)).unwrap();
                let expected = CertificateArtifactRequest::for_test(
                    request.scope(),
                    request.generation(),
                    request.policy_hash().clone(),
                    public_key.clone(),
                    artifact_digest,
                    state_hash.clone(),
                    artifact_id.clone(),
                    cert_scope,
                    serial.clone(),
                    not_after,
                )
                .unwrap();
                ProviderCertificateCandidate::new(
                    artifact,
                    request.scope(),
                    request.generation(),
                    request.policy_hash().clone(),
                    public_key,
                    state_hash,
                    artifact_id,
                    cert_scope,
                    serial,
                    not_after,
                )
                .authorize_production_for_test(&expected)
            }
        }

        #[derive(Default)]
        struct RepoState {
            view: Mutex<Option<CertificateReconcileView>>,
            receipts: Mutex<Vec<PersistedCertificateArtifactSnapshot<ProductionEligibility>>>,
            append_calls: AtomicUsize,
            append_conflict: AtomicBool,
            has_command: AtomicBool,
            expiry: Mutex<CurrentCommandExpiryOutcome>,
            expiry_calls: AtomicUsize,
            condition_failure_once: AtomicBool,
            conditions: Mutex<BTreeMap<String, (String, String)>>,
            rotations: AtomicUsize,
        }

        impl Default for CurrentCommandExpiryOutcome {
            fn default() -> Self {
                Self::NoCurrent
            }
        }

        #[derive(Clone)]
        struct FakeRepo(Arc<RepoState>);

        impl CertificateReconcileRepository<ProductionEligibility> for FakeRepo {
            async fn load_current_view(
                &self,
                _authority: &CertificateAttemptAuthority,
            ) -> Result<Option<CertificateReconcileView>, CertificateReconcileRepositoryError>
            {
                Ok(self.0.view.lock().unwrap().clone())
            }
            async fn load_artifact_receipts(
                &self,
                _fence: &CertificateAttemptFence,
            ) -> Result<
                Vec<PersistedCertificateArtifactSnapshot<ProductionEligibility>>,
                CertificateReconcileRepositoryError,
            > {
                Ok(self.0.receipts.lock().unwrap().clone())
            }
            async fn load_current_command_evidence(
                &self,
                _fence: &CertificateAttemptFence,
            ) -> Result<Option<DeviceCertificateCommandEvidence>, CertificateReconcileRepositoryError>
            {
                Ok(self
                    .0
                    .has_command
                    .load(Ordering::SeqCst)
                    .then(|| command_evidence(9)))
            }
            async fn expire_due_current_command(
                &self,
                _fence: &CertificateAttemptFence,
            ) -> Result<CurrentCommandExpiryOutcome, CertificateReconcileRepositoryError>
            {
                self.0.expiry_calls.fetch_add(1, Ordering::SeqCst);
                Ok(*self.0.expiry.lock().unwrap())
            }
            async fn append_artifact_receipt(
                &self,
                _fence: &CertificateAttemptFence,
                authorization: ArtifactAppendAuthorization<ProductionEligibility>,
            ) -> Result<ArtifactAppendOutcome, CertificateReconcileRepositoryError> {
                self.0.append_calls.fetch_add(1, Ordering::SeqCst);
                if self.0.append_conflict.load(Ordering::SeqCst) {
                    return Ok(ArtifactAppendOutcome::Conflict);
                }
                self.0
                    .receipts
                    .lock()
                    .unwrap()
                    .push(authorization.into_snapshot());
                Ok(ArtifactAppendOutcome::Appended)
            }
            async fn write_conditions(
                &self,
                _fence: &CertificateAttemptFence,
                mutation: CertificateConditionMutation,
            ) -> Result<FencedMutationOutcome, CertificateReconcileRepositoryError> {
                if self.0.condition_failure_once.swap(false, Ordering::SeqCst) {
                    return Err(CertificateReconcileRepositoryError::storage_unavailable(
                        std::io::Error::other("injected condition failure"),
                    ));
                }
                let states = match mutation {
                    CertificateConditionMutation::States(batch) => batch.into_states(),
                    CertificateConditionMutation::Ready(proof) => {
                        let generation =
                            Some(ObservedGeneration::try_new(proof.generation().get()).unwrap());
                        vec![
                            proof.into_condition_state(),
                            DeviceConditionState::reconciling(
                                ConditionStatus::False,
                                ReconcilingReason::DeviceReported,
                                generation,
                            ),
                            DeviceConditionState::pending_device(
                                ConditionStatus::False,
                                PendingDeviceReason::AwaitingDevice,
                                generation,
                            ),
                            DeviceConditionState::degraded(
                                ConditionStatus::False,
                                DegradedReason::ArtifactUnavailable,
                                generation,
                            ),
                            DeviceConditionState::quarantined(
                                ConditionStatus::False,
                                QuarantinedReason::ProtocolViolation,
                                generation,
                            ),
                            DeviceConditionState::deleting(
                                ConditionStatus::False,
                                DeletingReason::DeletionPending,
                                generation,
                            ),
                        ]
                    }
                };
                let mut conditions = self.0.conditions.lock().unwrap();
                for state in states {
                    conditions.insert(
                        state.kind().as_label().to_owned(),
                        (
                            state.status_label().to_owned(),
                            state.reason_label().to_owned(),
                        ),
                    );
                }
                Ok(FencedMutationOutcome::Applied)
            }
            async fn rotate_generation(
                &self,
                fence: &CertificateAttemptFence,
            ) -> Result<RotationOutcome, CertificateReconcileRepositoryError> {
                self.0.rotations.fetch_add(1, Ordering::SeqCst);
                Ok(RotationOutcome::Rotated {
                    generation: ExpectedGeneration::try_new(fence.expected_generation().get() + 1)
                        .unwrap(),
                    wake: ReconcileWake::new("target-component", WakeVersion::try_new(2).unwrap()),
                })
            }
            async fn request_deletion(
                &self,
                _fence: &CertificateAttemptFence,
            ) -> Result<DeletionRequestOutcome, CertificateReconcileRepositoryError> {
                Ok(DeletionRequestOutcome::Replayed)
            }
        }

        #[derive(Default)]
        struct ScheduleState {
            actions: Mutex<Vec<ConvergeAction>>,
            fact_conflict: AtomicBool,
            completions: AtomicUsize,
            terminal_condition: Mutex<Option<(String, String)>>,
        }

        #[derive(Clone)]
        struct FakeSchedule(Arc<ScheduleState>);

        impl ReconcileScheduleStore for FakeSchedule {
            async fn claim_due_targets(
                &self,
                _tenant: rss_request_context::TenantId,
                _reconciler_id: &str,
                _holder_id: &str,
                _limit: ReconcileMaxInFlight,
                _lease_ttl: Duration,
            ) -> Result<Vec<ClaimedTarget>, ReconcileScheduleError> {
                Ok(Vec::new())
            }
            async fn claim_targeted(
                &self,
                _tenant: rss_request_context::TenantId,
                _reconciler_id: &str,
                _holder_id: &str,
                _wake: &ReconcileWake,
                _lease_ttl: Duration,
            ) -> Result<Option<ClaimedTarget>, ReconcileScheduleError> {
                Ok(None)
            }
            async fn append_attempt(
                &self,
                _target: &ClaimedTarget,
                _holder_id: &str,
            ) -> Result<ScheduleAttemptOutcome, ReconcileScheduleError> {
                Ok(ScheduleAttemptOutcome::Lost)
            }
            async fn record_attempt_result(
                &self,
                _attempt: &ReconcileAttempt,
                _result: AttemptResult,
            ) -> Result<ScheduleResultOutcome, ReconcileScheduleError> {
                Ok(ScheduleResultOutcome::Recorded)
            }
            async fn record_fenced_command(
                &self,
                _attempt: &ReconcileAttempt,
                action: ConvergeAction,
                _command: ReviewedFencedCommand,
            ) -> Result<ScheduleActionOutcome, ReconcileScheduleError> {
                if self.0.fact_conflict.load(Ordering::SeqCst) {
                    return Err(ReconcileScheduleError::fact_conflict(OutboxFactConflict));
                }
                self.0.actions.lock().unwrap().push(action);
                Ok(ScheduleActionOutcome::Enqueued)
            }
            async fn complete_device_certificate_deletion(
                &self,
                _attempt: &ReconcileAttempt,
            ) -> Result<ScheduleCompletionOutcome, ReconcileScheduleError> {
                self.0.completions.fetch_add(1, Ordering::SeqCst);
                *self.0.terminal_condition.lock().unwrap() =
                    Some(("Deleting".to_owned(), "DeletionComplete".to_owned()));
                Ok(ScheduleCompletionOutcome::Completed)
            }
            async fn extend_lease(
                &self,
                _target: &ClaimedTarget,
                _lease_ttl: Duration,
            ) -> Result<ScheduleLeaseOutcome, ReconcileScheduleError> {
                Ok(ScheduleLeaseOutcome::Held)
            }
            async fn release_lease(
                &self,
                _target: &ClaimedTarget,
            ) -> Result<ScheduleLeaseOutcome, ReconcileScheduleError> {
                Ok(ScheduleLeaseOutcome::Held)
            }
            async fn pause_target(
                &self,
                _tenant: rss_request_context::TenantId,
                _target_id: &str,
            ) -> Result<(), ReconcileScheduleError> {
                Ok(())
            }
            async fn resume_target(
                &self,
                _tenant: rss_request_context::TenantId,
                _target_id: &str,
            ) -> Result<(), ReconcileScheduleError> {
                Ok(())
            }
        }

        struct FixedClock;
        impl diport::Clock for FixedClock {
            fn now(&self) -> SystemTime {
                now()
            }
        }

        struct DeadlineOverflowClock;
        impl diport::Clock for DeadlineOverflowClock {
            fn now(&self) -> SystemTime {
                SystemTime::UNIX_EPOCH + Duration::from_secs(i64::MAX as u64 / 1_000_000)
            }
        }

        fn target() -> ClaimedTarget {
            ClaimedTarget::restore(ClaimedTargetRestore {
                tenant: scope().tenant(),
                target_id: "target-component".to_owned(),
                reconciler_id: "identity.device-certificate".to_owned(),
                resource_kind: "device-certificate".to_owned(),
                resource_id: scope().device().as_uuid().hyphenated().to_string(),
                lease_token: "lease-component".to_owned(),
                epoch: 9,
                failure_streak: FailureStreak::restore(0),
                wake_version: WakeVersion::try_new(1).unwrap(),
                trigger: AttemptTrigger::Resync,
            })
        }

        fn keyring() -> CommandIdempotencyKeyring {
            CommandIdempotencyKeyring::new(
                CommandAliasKey::new("current", vec![0x42; 32]).unwrap(),
                Vec::new(),
            )
            .unwrap()
        }

        fn state(report: Option<ReportedStateRestore>) -> DeviceCertificateStateSnapshot {
            DeviceCertificateStateSnapshot::restore(
                scope(),
                DesiredStateRestore::new(
                    7,
                    PolicyHash::parse(&digest('b')).unwrap(),
                    desired().policy().clone(),
                    SystemTime::UNIX_EPOCH,
                    SystemTime::UNIX_EPOCH,
                ),
                report,
                Vec::new(),
            )
            .unwrap()
        }

        fn matching_report() -> ReportedStateRestore {
            ReportedStateRestore::new(
                7,
                9,
                ReportedStateHash::parse(&digest('b')).unwrap(),
                ArtifactDigest::parse(&digest('a')).unwrap(),
                ReportEnvelopeId::parse("component-report-7").unwrap(),
                DeviceSequence::try_new(7).unwrap(),
                None,
                None,
                now(),
            )
        }

        async fn run_case(
            source_mode: SourceMode,
            report: Option<ReportedStateRestore>,
            receipts: Vec<PersistedCertificateArtifactSnapshot<ProductionEligibility>>,
            transport: CertificateTransportObservation,
            deleting: bool,
            has_command: bool,
        ) -> (
            Result<DurableReconcileOutcome, ReconcileError>,
            Arc<RepoState>,
            Arc<ScheduleState>,
            Arc<FakeSource>,
        ) {
            let attempt = ReconcileAttempt::new("attempt-component", target());
            let authority = CertificateAttemptAuthority::for_test(scope(), &attempt).unwrap();
            let repo_state = Arc::new(RepoState::default());
            *repo_state.view.lock().unwrap() = Some(
                CertificateReconcileView::restore_current(
                    &authority,
                    state(report),
                    deleting,
                    transport,
                )
                .unwrap(),
            );
            *repo_state.receipts.lock().unwrap() = receipts;
            repo_state.has_command.store(has_command, Ordering::SeqCst);
            let repository = FakeRepo(Arc::clone(&repo_state));
            let source = Arc::new(FakeSource::new(source_mode));
            let reconciler = DeviceCertificateReconciler::new(
                repository,
                Arc::clone(&source),
                FakeRevocations::healthy([]),
                Arc::new(FixedClock),
                DeviceCertificateCommandTtl::try_new(Duration::from_secs(30)).unwrap(),
            );
            let schedule_state = Arc::new(ScheduleState::default());
            let schedule = FakeSchedule(Arc::clone(&schedule_state));
            let keys = keyring();
            let attempt_scope = AttemptScope::for_test(
                &schedule,
                &keys,
                eventexec::reconcile::DeviceCertificateSystemProducer::install(),
                attempt,
            );
            let result = DurableReconciler::reconcile(
                &reconciler,
                &Context::for_harness(None),
                &target(),
                &attempt_scope,
            )
            .await;
            (result, repo_state, schedule_state, source)
        }

        async fn run_existing(
            repo_state: Arc<RepoState>,
            schedule_state: Arc<ScheduleState>,
            source: Arc<FakeSource>,
        ) -> Result<DurableReconcileOutcome, ReconcileError> {
            let attempt = ReconcileAttempt::new("attempt-component", target());
            let repository = FakeRepo(repo_state);
            let reconciler = DeviceCertificateReconciler::new(
                repository,
                source,
                FakeRevocations::healthy([]),
                Arc::new(FixedClock),
                DeviceCertificateCommandTtl::try_new(Duration::from_secs(30)).unwrap(),
            );
            let schedule = FakeSchedule(schedule_state);
            let keys = keyring();
            let attempt_scope = AttemptScope::for_test(
                &schedule,
                &keys,
                eventexec::reconcile::DeviceCertificateSystemProducer::install(),
                attempt,
            );
            DurableReconciler::reconcile(
                &reconciler,
                &Context::for_harness(None),
                &target(),
                &attempt_scope,
            )
            .await
        }

        fn has_condition(state: &RepoState, kind: &str, reason: &str) -> bool {
            state
                .conditions
                .lock()
                .unwrap()
                .get(kind)
                .is_some_and(|(_, candidate_reason)| candidate_reason == reason)
        }

        fn condition_is(state: &RepoState, kind: &str, status: &str, reason: &str) -> bool {
            state.conditions.lock().unwrap().get(kind).is_some_and(
                |(candidate_status, candidate_reason)| {
                    candidate_status == status && candidate_reason == reason
                },
            )
        }

        #[tokio::test]
        async fn durable_component_covers_active_convergence_branches() {
            let (created, repo, schedule, source) = run_case(
                SourceMode::Healthy,
                None,
                vec![],
                CertificateTransportObservation::Available,
                false,
                false,
            )
            .await;
            assert!(created.is_ok());
            assert_eq!(source.calls.load(Ordering::SeqCst), 1);
            assert_eq!(repo.append_calls.load(Ordering::SeqCst), 1);
            assert_eq!(
                *schedule.actions.lock().unwrap(),
                vec![ConvergeAction::Create]
            );

            let (reused, repo, schedule, source) = run_case(
                SourceMode::Healthy,
                None,
                vec![receipt(NOW_SECONDS + 301)],
                CertificateTransportObservation::Available,
                false,
                false,
            )
            .await;
            assert!(reused.is_ok());
            assert_eq!(source.calls.load(Ordering::SeqCst), 0);
            assert_eq!(repo.append_calls.load(Ordering::SeqCst), 0);
            assert_eq!(
                *schedule.actions.lock().unwrap(),
                vec![ConvergeAction::Create]
            );

            let (ready, repo, schedule, _) = run_case(
                SourceMode::Healthy,
                Some(matching_report()),
                vec![receipt(NOW_SECONDS + 301)],
                CertificateTransportObservation::Available,
                false,
                true,
            )
            .await;
            assert!(ready.is_ok());
            assert!(schedule.actions.lock().unwrap().is_empty());
            assert!(has_condition(&repo, "Ready", "StateMatches"));

            let (rotated, repo, _, _) = run_case(
                SourceMode::Healthy,
                Some(matching_report()),
                vec![receipt(NOW_SECONDS + 300)],
                CertificateTransportObservation::Available,
                false,
                true,
            )
            .await;
            assert!(rotated.is_ok());
            assert_eq!(repo.rotations.load(Ordering::SeqCst), 1);
        }

        #[tokio::test]
        async fn durable_component_preserves_received_command_while_awaiting_report() {
            let (outcome, repo, schedule, source) = run_case(
                SourceMode::Healthy,
                None,
                vec![receipt(NOW_SECONDS + 301)],
                CertificateTransportObservation::Available,
                false,
                true,
            )
            .await;

            assert!(matches!(outcome, Ok(DurableReconcileOutcome::Schedule(_))));
            assert_eq!(source.calls.load(Ordering::SeqCst), 0);
            assert_eq!(repo.append_calls.load(Ordering::SeqCst), 0);
            assert!(repo.conditions.lock().unwrap().is_empty());
            assert!(schedule.actions.lock().unwrap().is_empty());
        }

        #[tokio::test]
        async fn durable_component_settles_expired_command_without_reissuing() {
            let attempt = ReconcileAttempt::new("attempt-component", target());
            let authority = CertificateAttemptAuthority::for_test(scope(), &attempt).unwrap();
            let repo_state = Arc::new(RepoState::default());
            *repo_state.view.lock().unwrap() = Some(
                CertificateReconcileView::restore_current(
                    &authority,
                    state(None),
                    false,
                    CertificateTransportObservation::Available,
                )
                .unwrap(),
            );
            *repo_state.receipts.lock().unwrap() = vec![receipt(NOW_SECONDS + 301)];
            *repo_state.expiry.lock().unwrap() = CurrentCommandExpiryOutcome::Expired;
            let schedule_state = Arc::new(ScheduleState::default());

            let result = run_existing(
                Arc::clone(&repo_state),
                Arc::clone(&schedule_state),
                Arc::new(FakeSource::new(SourceMode::Healthy)),
            )
            .await;

            assert!(matches!(result, Ok(DurableReconcileOutcome::Schedule(_))));
            assert_eq!(repo_state.expiry_calls.load(Ordering::SeqCst), 1);
            assert!(schedule_state.actions.lock().unwrap().is_empty());
            assert!(condition_is(
                &repo_state,
                "Degraded",
                "True",
                "CommandTimedOut"
            ));

            *repo_state.expiry.lock().unwrap() = CurrentCommandExpiryOutcome::AlreadyExpired;
            let repeated = run_existing(
                Arc::clone(&repo_state),
                Arc::clone(&schedule_state),
                Arc::new(FakeSource::new(SourceMode::Healthy)),
            )
            .await;
            assert!(repeated.is_ok());
            assert_eq!(repo_state.expiry_calls.load(Ordering::SeqCst), 2);
            assert!(schedule_state.actions.lock().unwrap().is_empty());
        }

        #[tokio::test]
        async fn durable_component_repairs_timed_out_conditions_after_transient_write_failure() {
            let attempt = ReconcileAttempt::new("attempt-component", target());
            let authority = CertificateAttemptAuthority::for_test(scope(), &attempt).unwrap();
            let repo_state = Arc::new(RepoState::default());
            *repo_state.view.lock().unwrap() = Some(
                CertificateReconcileView::restore_current(
                    &authority,
                    state(None),
                    false,
                    CertificateTransportObservation::Available,
                )
                .unwrap(),
            );
            *repo_state.expiry.lock().unwrap() = CurrentCommandExpiryOutcome::Expired;
            repo_state
                .condition_failure_once
                .store(true, Ordering::SeqCst);
            let schedule_state = Arc::new(ScheduleState::default());

            let first = run_existing(
                Arc::clone(&repo_state),
                Arc::clone(&schedule_state),
                Arc::new(FakeSource::new(SourceMode::Healthy)),
            )
            .await;
            assert!(first.is_err());
            assert!(repo_state.conditions.lock().unwrap().is_empty());
            assert!(schedule_state.actions.lock().unwrap().is_empty());

            *repo_state.expiry.lock().unwrap() = CurrentCommandExpiryOutcome::AlreadyExpired;
            let repaired = run_existing(
                Arc::clone(&repo_state),
                Arc::clone(&schedule_state),
                Arc::new(FakeSource::new(SourceMode::Healthy)),
            )
            .await;
            assert!(repaired.is_ok());
            assert!(condition_is(
                &repo_state,
                "Degraded",
                "True",
                "CommandTimedOut"
            ));
            assert!(schedule_state.actions.lock().unwrap().is_empty());
        }

        #[tokio::test]
        async fn durable_component_fails_closed_and_completes_deletion() {
            let (outage, repo, schedule, _) = run_case(
                SourceMode::Unavailable,
                None,
                vec![],
                CertificateTransportObservation::Available,
                false,
                false,
            )
            .await;
            assert!(outage.is_ok());
            assert!(schedule.actions.lock().unwrap().is_empty());
            assert!(has_condition(&repo, "Degraded", "ArtifactUnavailable"));

            let (binding, repo, _, _) = run_case(
                SourceMode::BindingMismatch,
                None,
                vec![],
                CertificateTransportObservation::Available,
                false,
                false,
            )
            .await;
            assert!(binding.is_err());
            assert!(has_condition(&repo, "Quarantined", "ProtocolViolation"));

            let (offline, repo, schedule, source) = run_case(
                SourceMode::Healthy,
                None,
                vec![],
                CertificateTransportObservation::Unavailable,
                false,
                false,
            )
            .await;
            assert!(offline.is_ok());
            assert_eq!(source.calls.load(Ordering::SeqCst), 0);
            assert!(schedule.actions.lock().unwrap().is_empty());
            assert!(has_condition(&repo, "Degraded", "TransportUnavailable"));

            let (deleted, repo, schedule, _) = run_case(
                SourceMode::Healthy,
                None,
                vec![],
                CertificateTransportObservation::Available,
                true,
                false,
            )
            .await;
            assert!(matches!(deleted, Ok(DurableReconcileOutcome::Completed(_))));
            assert_eq!(schedule.completions.load(Ordering::SeqCst), 1);
            assert_eq!(
                *schedule.terminal_condition.lock().unwrap(),
                Some(("Deleting".to_owned(), "DeletionComplete".to_owned()))
            );

            let attempt = ReconcileAttempt::new("attempt-component", target());
            let authority = CertificateAttemptAuthority::for_test(scope(), &attempt).unwrap();
            *repo.view.lock().unwrap() = Some(
                CertificateReconcileView::restore_current(
                    &authority,
                    state(None),
                    false,
                    CertificateTransportObservation::Available,
                )
                .unwrap(),
            );
            assert!(
                run_existing(
                    Arc::clone(&repo),
                    Arc::clone(&schedule),
                    Arc::new(FakeSource::new(SourceMode::Healthy)),
                )
                .await
                .is_ok()
            );
            assert!(condition_is(&repo, "Deleting", "False", "DeletionPending"));
            assert!(condition_is(
                &repo,
                "PendingDevice",
                "True",
                "AwaitingDevice"
            ));
        }

        #[tokio::test]
        async fn deletion_dependency_outage_requeues_without_clearing_deleting() {
            let attempt = ReconcileAttempt::new("attempt-component", target());
            let authority = CertificateAttemptAuthority::for_test(scope(), &attempt).unwrap();
            let repo_state = Arc::new(RepoState::default());
            *repo_state.view.lock().unwrap() = Some(
                CertificateReconcileView::restore_current(
                    &authority,
                    state(None),
                    true,
                    CertificateTransportObservation::Available,
                )
                .unwrap(),
            );
            *repo_state.receipts.lock().unwrap() = vec![receipt(NOW_SECONDS + 60)];
            repo_state.conditions.lock().unwrap().insert(
                "Deleting".to_owned(),
                ("True".to_owned(), "DeletionPending".to_owned()),
            );
            let reconciler = DeviceCertificateReconciler::new(
                FakeRepo(Arc::clone(&repo_state)),
                Arc::new(FakeSource::new(SourceMode::Healthy)),
                FakeRevocations {
                    fail_read: true,
                    ..FakeRevocations::healthy([])
                },
                Arc::new(FixedClock),
                DeviceCertificateCommandTtl::try_new(Duration::from_secs(30)).unwrap(),
            );
            let schedule_state = Arc::new(ScheduleState::default());
            let schedule = FakeSchedule(Arc::clone(&schedule_state));
            let keys = keyring();
            let attempt_scope = AttemptScope::for_test(
                &schedule,
                &keys,
                eventexec::reconcile::DeviceCertificateSystemProducer::install(),
                attempt,
            );

            let result = DurableReconciler::reconcile(
                &reconciler,
                &Context::for_harness(None),
                &target(),
                &attempt_scope,
            )
            .await;

            assert!(matches!(result, Ok(DurableReconcileOutcome::Schedule(_))));
            assert_eq!(schedule_state.completions.load(Ordering::SeqCst), 0);
            assert!(condition_is(
                &repo_state,
                "Deleting",
                "True",
                "DeletionPending"
            ));
            assert!(!has_condition(
                &repo_state,
                "Degraded",
                "ArtifactUnavailable"
            ));
        }

        #[tokio::test]
        async fn durable_component_outage_recovers_through_issue_to_ready_without_contradictions() {
            let (_, repo, schedule, _) = run_case(
                SourceMode::Unavailable,
                None,
                vec![],
                CertificateTransportObservation::Available,
                false,
                false,
            )
            .await;
            assert!(condition_is(&repo, "Ready", "False", "ArtifactUnavailable"));
            assert!(condition_is(&repo, "Reconciling", "False", "StateDrift"));
            assert!(condition_is(
                &repo,
                "PendingDevice",
                "False",
                "AwaitingDevice"
            ));
            assert!(condition_is(
                &repo,
                "Degraded",
                "True",
                "ArtifactUnavailable"
            ));
            assert!(condition_is(
                &repo,
                "Quarantined",
                "False",
                "ProtocolViolation"
            ));
            assert!(condition_is(&repo, "Deleting", "False", "DeletionPending"));

            assert!(
                run_existing(
                    Arc::clone(&repo),
                    Arc::clone(&schedule),
                    Arc::new(FakeSource::new(SourceMode::Healthy)),
                )
                .await
                .is_ok()
            );
            assert!(condition_is(&repo, "Ready", "False", "AwaitingDevice"));
            assert!(condition_is(&repo, "Reconciling", "True", "CommandQueued"));
            assert!(condition_is(
                &repo,
                "PendingDevice",
                "True",
                "AwaitingDevice"
            ));
            assert!(condition_is(
                &repo,
                "Degraded",
                "False",
                "ArtifactUnavailable"
            ));
            assert!(condition_is(
                &repo,
                "Quarantined",
                "False",
                "ProtocolViolation"
            ));
            assert!(condition_is(&repo, "Deleting", "False", "DeletionPending"));

            let attempt = ReconcileAttempt::new("attempt-component", target());
            let authority = CertificateAttemptAuthority::for_test(scope(), &attempt).unwrap();
            *repo.view.lock().unwrap() = Some(
                CertificateReconcileView::restore_current(
                    &authority,
                    state(Some(matching_report())),
                    false,
                    CertificateTransportObservation::Available,
                )
                .unwrap(),
            );
            *repo.receipts.lock().unwrap() = vec![receipt(NOW_SECONDS + 301)];
            repo.has_command.store(true, Ordering::SeqCst);
            assert!(
                run_existing(
                    Arc::clone(&repo),
                    schedule,
                    Arc::new(FakeSource::new(SourceMode::Healthy)),
                )
                .await
                .is_ok()
            );
            assert!(condition_is(&repo, "Ready", "True", "StateMatches"));
            assert!(condition_is(
                &repo,
                "Reconciling",
                "False",
                "DeviceReported"
            ));
            assert!(condition_is(
                &repo,
                "PendingDevice",
                "False",
                "AwaitingDevice"
            ));
            assert!(condition_is(
                &repo,
                "Degraded",
                "False",
                "ArtifactUnavailable"
            ));
            assert!(condition_is(
                &repo,
                "Quarantined",
                "False",
                "ProtocolViolation"
            ));
            assert!(condition_is(&repo, "Deleting", "False", "DeletionPending"));
        }

        #[tokio::test]
        async fn durable_component_quarantines_append_and_fact_conflicts() {
            let attempt = ReconcileAttempt::new("attempt-component", target());
            let authority = CertificateAttemptAuthority::for_test(scope(), &attempt).unwrap();
            let repo_state = Arc::new(RepoState::default());
            *repo_state.view.lock().unwrap() = Some(
                CertificateReconcileView::restore_current(
                    &authority,
                    state(None),
                    false,
                    CertificateTransportObservation::Available,
                )
                .unwrap(),
            );
            repo_state.append_conflict.store(true, Ordering::SeqCst);
            let source = Arc::new(FakeSource::new(SourceMode::Healthy));
            let reconciler = DeviceCertificateReconciler::new(
                FakeRepo(Arc::clone(&repo_state)),
                source,
                FakeRevocations::healthy([]),
                Arc::new(FixedClock),
                DeviceCertificateCommandTtl::try_new(Duration::from_secs(30)).unwrap(),
            );
            let schedule_state = Arc::new(ScheduleState::default());
            let schedule = FakeSchedule(Arc::clone(&schedule_state));
            let keys = keyring();
            let scope_attempt = AttemptScope::for_test(
                &schedule,
                &keys,
                eventexec::reconcile::DeviceCertificateSystemProducer::install(),
                attempt,
            );
            assert!(
                DurableReconciler::reconcile(
                    &reconciler,
                    &Context::for_harness(None),
                    &target(),
                    &scope_attempt
                )
                .await
                .is_err()
            );
            assert!(has_condition(
                &repo_state,
                "Quarantined",
                "ProtocolViolation"
            ));

            let attempt = ReconcileAttempt::new("attempt-fact-conflict", target());
            let authority = CertificateAttemptAuthority::for_test(scope(), &attempt).unwrap();
            let repo_state = Arc::new(RepoState::default());
            *repo_state.view.lock().unwrap() = Some(
                CertificateReconcileView::restore_current(
                    &authority,
                    state(None),
                    false,
                    CertificateTransportObservation::Available,
                )
                .unwrap(),
            );
            *repo_state.receipts.lock().unwrap() = vec![receipt(NOW_SECONDS + 301)];
            let reconciler = DeviceCertificateReconciler::new(
                FakeRepo(Arc::clone(&repo_state)),
                Arc::new(FakeSource::new(SourceMode::Healthy)),
                FakeRevocations::healthy([]),
                Arc::new(FixedClock),
                DeviceCertificateCommandTtl::try_new(Duration::from_secs(30)).unwrap(),
            );
            let schedule_state = Arc::new(ScheduleState::default());
            schedule_state.fact_conflict.store(true, Ordering::SeqCst);
            let schedule = FakeSchedule(schedule_state);
            let keys = keyring();
            let scope_attempt = AttemptScope::for_test(
                &schedule,
                &keys,
                eventexec::reconcile::DeviceCertificateSystemProducer::install(),
                attempt,
            );
            assert!(
                DurableReconciler::reconcile(
                    &reconciler,
                    &Context::for_harness(None),
                    &target(),
                    &scope_attempt,
                )
                .await
                .is_err()
            );
            assert!(has_condition(
                &repo_state,
                "Quarantined",
                "ProtocolViolation"
            ));
        }

        #[tokio::test]
        async fn durable_component_degrades_before_permanent_command_failure() {
            let attempt = ReconcileAttempt::new("attempt-permanent", target());
            let authority = CertificateAttemptAuthority::for_test(scope(), &attempt).unwrap();
            let repo_state = Arc::new(RepoState::default());
            *repo_state.view.lock().unwrap() = Some(
                CertificateReconcileView::restore_current(
                    &authority,
                    state(None),
                    false,
                    CertificateTransportObservation::Available,
                )
                .unwrap(),
            );
            *repo_state.receipts.lock().unwrap() = vec![receipt(NOW_SECONDS + 301)];
            let reconciler = DeviceCertificateReconciler::new(
                FakeRepo(Arc::clone(&repo_state)),
                Arc::new(FakeSource::new(SourceMode::Healthy)),
                FakeRevocations::healthy([]),
                Arc::new(DeadlineOverflowClock),
                DeviceCertificateCommandTtl::try_new(Duration::from_secs(30)).unwrap(),
            );
            let schedule = FakeSchedule(Arc::new(ScheduleState::default()));
            let keys = keyring();
            let scope_attempt = AttemptScope::for_test(
                &schedule,
                &keys,
                eventexec::reconcile::DeviceCertificateSystemProducer::install(),
                attempt,
            );
            let result = DurableReconciler::reconcile(
                &reconciler,
                &Context::for_harness(None),
                &target(),
                &scope_attempt,
            )
            .await;
            assert!(result.is_err_and(|error| error.is_permanent()));
            assert!(has_condition(&repo_state, "Degraded", "ProtocolViolation"));
        }
    }
}
