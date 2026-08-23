//! Canonical runtime bundle for the DeviceLatent draft pilot.
//!
//! The bundle is deliberately bound to draft artifact eligibility and the exact PostgreSQL/MQTT
//! providers selected by the `deviceidentity` assembly. It has no signer, SoftCA, in-memory, or
//! optional-provider path.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::Duration;

use diport::{
    CertNotAfter, CertScope, CertSerial, Clock, DynManagedResource, ManagedResource, ShutdownError,
};
use eventexec::command::CommandIdempotencyKeyring;
use eventexec::reconcile::{
    BackoffPolicy, DeviceCertificateSystemProducer, ReconcileConfigError, ReconcileMaxInFlight,
    ReconcileSchedulerBuilder, ReconcileWorkerControl, Tenancy, Trigger,
};
use eventexec::{RelayBudget, RelayConfig, WorkerHealth};
use futures::stream::{FuturesUnordered, StreamExt as _};
use identity::ports::device_certificate::{
    ArtifactAppendAuthorization, ArtifactAppendOutcome, ArtifactDigest,
    AuthorizedCertificateArtifact, CertificateArtifactAcquisition, CertificateArtifactError,
    CertificateArtifactId, CertificateArtifactMaterial as ArtifactBindingMaterial,
    CertificateArtifactRequest, CertificateArtifactSource, CertificateAttemptAuthority,
    CertificateAttemptFence, CertificateConditionMutation, CertificatePublicKeyDigest,
    CertificateReconcileRepository, CertificateReconcileRepositoryError, CertificateReconcileView,
    CurrentCommandExpiryOutcome, DeletionRequestOutcome, DeviceCertificateCommandTtl,
    DeviceCertificateReconciler, DeviceIngressRepository, DeviceIngressWrite, DraftEligibility,
    FencedMutationOutcome, PersistedCertificateArtifactSnapshot, ProviderCertificateCandidate,
    ReportedStateHash, RotationOutcome,
};
use mqtt::{MqttReadiness, MqttSession};
use postgres::{
    PgBrokerAcceptedDeviceOutbox, PgClaimedDeviceOutbox, PgDbReadiness,
    PgDeviceCertificateRepository, PgDeviceCommandStore, PgDeviceIdentityDraftRuntime,
    PgDeviceOutbox, PgDeviceOutboxSettlement, PoolReadiness,
};
use sha2::{Digest, Sha256};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use super::device_mqtt::DeviceMqttPublisher;
use crate::encoding::lowercase_hex;

const DEVICE_CERTIFICATE_RECONCILER_ID: &str = "identity.device-certificate";

/// Deterministic, public-only certificate material for the draft pilot.
///
/// The seed and terminal expiry are mandatory. The seed is never returned or logged, and the
/// provider can mint only [`DraftEligibility`].
pub struct DraftArtifactSimulator {
    seed: [u8; 32],
    not_after: CertNotAfter,
}

impl std::fmt::Debug for DraftArtifactSimulator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DraftArtifactSimulator(<redacted-seed>)")
    }
}

impl DraftArtifactSimulator {
    /// Construct one deterministic draft provider. There is intentionally no default seed or
    /// clock-derived expiry.
    #[must_use]
    pub const fn new(seed: [u8; 32], not_after: CertNotAfter) -> Self {
        Self { seed, not_after }
    }
}

struct DraftArtifactMaterial {
    artifact: Vec<u8>,
    binding: ArtifactBindingMaterial,
}

impl DraftArtifactMaterial {
    fn derive(
        simulator: &DraftArtifactSimulator,
        scope: identity::ports::device_certificate::DeviceCertificateScope,
        generation: identity::ports::device_certificate::ExpectedGeneration,
        policy_hash: &identity::ports::device_certificate::PolicyHash,
    ) -> Result<Self, CertificateArtifactError> {
        let coordinate = draft_digest(
            &simulator.seed,
            b"coordinate",
            scope,
            generation.get(),
            policy_hash.as_bytes(),
        );
        let public_key = draft_digest(
            &simulator.seed,
            b"public-key",
            scope,
            generation.get(),
            policy_hash.as_bytes(),
        );
        let mut artifact = b"RSS-DRAFT-CERTIFICATE-V1\0".to_vec();
        artifact.extend_from_slice(&coordinate);
        artifact.extend_from_slice(&public_key);
        let artifact_digest = ArtifactDigest::restore(&Sha256::digest(&artifact))
            .map_err(|_| CertificateArtifactError::BindingMismatch)?;
        let expected_reported_state_hash = ReportedStateHash::restore(&draft_digest(
            &simulator.seed,
            b"reported-state",
            scope,
            generation.get(),
            artifact_digest.as_bytes(),
        ))
        .map_err(|_| CertificateArtifactError::BindingMismatch)?;
        let artifact_id = CertificateArtifactId::parse(&format!(
            "draft-device-certificate-v1:{}",
            lowercase_hex(&coordinate)
        ))?;
        let mut serial = draft_digest(
            &simulator.seed,
            b"serial",
            scope,
            generation.get(),
            policy_hash.as_bytes(),
        )[..20]
            .to_vec();
        serial[0] &= 0x7f;
        if serial.iter().all(|byte| *byte == 0) {
            serial[19] = 1;
        }
        let serial =
            CertSerial::try_new(serial).map_err(|_| CertificateArtifactError::BindingMismatch)?;
        Ok(Self {
            artifact,
            binding: ArtifactBindingMaterial::new(
                CertificatePublicKeyDigest::digest(&public_key),
                artifact_digest,
                expected_reported_state_hash,
                artifact_id,
                CertScope::new(scope.tenant(), scope.device()),
                serial,
                simulator.not_after,
            ),
        })
    }
}

fn draft_digest(
    seed: &[u8; 32],
    purpose: &[u8],
    scope: identity::ports::device_certificate::DeviceCertificateScope,
    generation: u64,
    binding: &[u8],
) -> [u8; 32] {
    let tenant = scope.tenant().octets();
    let device = scope.device().as_uuid();
    let mut digest = Sha256::new();
    digest.update(b"rss.deviceidentity.draft-artifact.v1\0");
    digest.update((purpose.len() as u64).to_be_bytes());
    digest.update(purpose);
    digest.update(seed);
    digest.update(tenant);
    digest.update(device.as_bytes());
    digest.update(generation.to_be_bytes());
    digest.update((binding.len() as u64).to_be_bytes());
    digest.update(binding);
    digest.finalize().into()
}

impl CertificateArtifactSource for DraftArtifactSimulator {
    type Eligibility = DraftEligibility;

    async fn acquire(
        &self,
        acquisition: CertificateArtifactAcquisition,
    ) -> Result<AuthorizedCertificateArtifact<Self::Eligibility>, CertificateArtifactError> {
        let material = DraftArtifactMaterial::derive(
            self,
            acquisition.scope(),
            acquisition.generation(),
            acquisition.policy_hash(),
        )?;
        let expected =
            CertificateArtifactRequest::for_draft_provider(&acquisition, material.binding)?;
        ProviderCertificateCandidate::new(material.artifact, expected.binding().clone())
            .authorize_draft(&expected)
    }
}

/// Closed readiness levels used by the six-component pilot aggregation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PilotComponentReadiness {
    /// The component is actively serving.
    Ready,
    /// The component is live but experienced a retryable failure or saturation.
    Degraded,
    /// The component has not started, stopped, or cannot safely serve.
    Unready,
}

impl PilotComponentReadiness {
    const fn severity(self) -> u8 {
        match self {
            Self::Ready => 0,
            Self::Degraded => 1,
            Self::Unready => 2,
        }
    }

    const fn worst(self, other: Self) -> Self {
        if self.severity() >= other.severity() {
            self
        } else {
            other
        }
    }

    const fn probe_status(self) -> primitives::HealthStatus {
        match self {
            Self::Ready => primitives::HealthStatus::Healthy,
            Self::Degraded => primitives::HealthStatus::Degraded,
            Self::Unready => primitives::HealthStatus::Unhealthy,
        }
    }

    const fn probe_detail(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Degraded => "degraded",
            Self::Unready => "unready",
        }
    }
}

/// One synchronous readiness snapshot over the exact six pilot components.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceIdentityPilotReadiness {
    postgres: PilotComponentReadiness,
    reconcile: PilotComponentReadiness,
    command_relay: PilotComponentReadiness,
    receipt_relay: PilotComponentReadiness,
    mqtt: PilotComponentReadiness,
    ingress: PilotComponentReadiness,
}

impl DeviceIdentityPilotReadiness {
    const fn aggregate(components: [PilotComponentReadiness; 6]) -> Self {
        Self {
            postgres: components[0],
            reconcile: components[1],
            command_relay: components[2],
            receipt_relay: components[3],
            mqtt: components[4],
            ingress: components[5],
        }
    }

    /// Worst readiness across PostgreSQL, reconcile, command relay, receipt relay, MQTT, and
    /// ingress. A single unready component fails closed.
    #[must_use]
    pub const fn overall(self) -> PilotComponentReadiness {
        self.postgres
            .worst(self.reconcile)
            .worst(self.command_relay)
            .worst(self.receipt_relay)
            .worst(self.mqtt)
            .worst(self.ingress)
    }

    #[must_use]
    pub const fn postgres(self) -> PilotComponentReadiness {
        self.postgres
    }

    #[must_use]
    pub const fn reconcile(self) -> PilotComponentReadiness {
        self.reconcile
    }

    #[must_use]
    pub const fn command_relay(self) -> PilotComponentReadiness {
        self.command_relay
    }

    #[must_use]
    pub const fn receipt_relay(self) -> PilotComponentReadiness {
        self.receipt_relay
    }

    #[must_use]
    pub const fn mqtt(self) -> PilotComponentReadiness {
        self.mqtt
    }

    #[must_use]
    pub const fn ingress(self) -> PilotComponentReadiness {
        self.ingress
    }
}

/// Named reconcile inputs for one pilot scheduler.
pub struct DeviceIdentitySchedulerConfig {
    clock: Arc<dyn Clock>,
    keyring: Arc<CommandIdempotencyKeyring>,
    producer: DeviceCertificateSystemProducer,
    tenant: rss_request_context::TenantId,
    holder_id: String,
    tenancy: Tenancy,
    timing: DeviceIdentitySchedulerTiming,
}

/// Named reconcile cadence, retry, lease, and concurrency policy.
pub struct DeviceIdentitySchedulerTiming {
    trigger: Trigger,
    backoff: BackoffPolicy,
    lease_ttl: Duration,
    max_in_flight: ReconcileMaxInFlight,
}

impl DeviceIdentitySchedulerTiming {
    #[must_use]
    pub const fn new(
        trigger: Trigger,
        backoff: BackoffPolicy,
        lease_ttl: Duration,
        max_in_flight: ReconcileMaxInFlight,
    ) -> Self {
        Self {
            trigger,
            backoff,
            lease_ttl,
            max_in_flight,
        }
    }
}

impl DeviceIdentitySchedulerConfig {
    #[must_use]
    pub fn new(
        clock: Arc<dyn Clock>,
        keyring: Arc<CommandIdempotencyKeyring>,
        producer: DeviceCertificateSystemProducer,
        tenant: rss_request_context::TenantId,
        holder_id: impl Into<String>,
        tenancy: Tenancy,
        timing: DeviceIdentitySchedulerTiming,
    ) -> Self {
        Self {
            clock,
            keyring,
            producer,
            tenant,
            holder_id: holder_id.into(),
            tenancy,
            timing,
        }
    }
}

/// Named command and MQTT relay inputs for one pilot.
pub struct DeviceIdentityRelayConfig {
    command_ttl: DeviceCertificateCommandTtl,
    command_relay: RelayConfig,
    receipt_relay: RelayConfig,
    relay_budget: RelayBudget,
}

impl DeviceIdentityRelayConfig {
    #[must_use]
    pub const fn new(
        command_ttl: DeviceCertificateCommandTtl,
        command_relay: RelayConfig,
        receipt_relay: RelayConfig,
        relay_budget: RelayBudget,
    ) -> Self {
        Self {
            command_ttl,
            command_relay,
            receipt_relay,
            relay_budget,
        }
    }
}

/// Complete pilot configuration. PostgreSQL capabilities are carried by one separate
/// single-origin receipt rather than loose fields in this value.
pub struct DeviceIdentityPilotConfig {
    scheduler: DeviceIdentitySchedulerConfig,
    relays: DeviceIdentityRelayConfig,
    shutdown_timeout: Duration,
}

impl DeviceIdentityPilotConfig {
    #[must_use]
    pub fn new(
        scheduler: DeviceIdentitySchedulerConfig,
        relays: DeviceIdentityRelayConfig,
        shutdown_timeout: Duration,
    ) -> Self {
        Self {
            scheduler,
            relays,
            shutdown_timeout,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoopHealth {
    Starting,
    Ready,
    Degraded,
    Stopped,
}

impl LoopHealth {
    const fn readiness(self) -> PilotComponentReadiness {
        match self {
            Self::Ready => PilotComponentReadiness::Ready,
            Self::Degraded => PilotComponentReadiness::Degraded,
            Self::Starting | Self::Stopped => PilotComponentReadiness::Unready,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DrainObservation {
    paused: bool,
    in_flight: usize,
    stopped: bool,
}

impl DrainObservation {
    const fn running() -> Self {
        Self {
            paused: false,
            in_flight: 0,
            stopped: false,
        }
    }

    const fn is_drained(self) -> bool {
        self.stopped || (self.paused && self.in_flight == 0)
    }
}

#[derive(Clone)]
struct PilotLoopControl {
    paused: watch::Sender<bool>,
    drain: watch::Sender<DrainObservation>,
    drained: watch::Sender<bool>,
    health: watch::Sender<LoopHealth>,
}

impl PilotLoopControl {
    fn new() -> Self {
        let (paused, _) = watch::channel(false);
        let (drain, _) = watch::channel(DrainObservation::running());
        let (drained, _) = watch::channel(false);
        let (health, _) = watch::channel(LoopHealth::Starting);
        Self {
            paused,
            drain,
            drained,
            health,
        }
    }

    fn pause(&self) {
        self.paused.send_replace(true);
    }

    #[cfg(any(test, feature = "test-support"))]
    fn resume(&self) {
        if !self.drain.borrow().stopped {
            self.drain.send_modify(|state| state.paused = false);
            self.drained.send_replace(false);
            self.paused.send_replace(false);
        }
    }

    fn mark_paused(&self) {
        self.drain.send_modify(|state| state.paused = true);
        self.publish_drained();
    }

    fn set_in_flight(&self, in_flight: usize) {
        self.drain.send_modify(|state| state.in_flight = in_flight);
        self.publish_drained();
    }

    fn mark_stopped(&self) {
        self.health.send_replace(LoopHealth::Stopped);
        self.drain.send_replace(DrainObservation {
            paused: true,
            in_flight: 0,
            stopped: true,
        });
        self.drained.send_replace(true);
    }

    fn mark_ready(&self) {
        self.health.send_replace(LoopHealth::Ready);
    }

    fn mark_degraded(&self) {
        self.health.send_replace(LoopHealth::Degraded);
    }

    fn publish_drained(&self) {
        self.drained.send_replace(self.drain.borrow().is_drained());
    }

    async fn wait_drained(&self) {
        let mut changes = self.drain.subscribe();
        while !changes.borrow().is_drained() {
            if changes.changed().await.is_err() {
                break;
            }
        }
    }

    fn readiness(&self) -> PilotComponentReadiness {
        if *self.paused.borrow() {
            PilotComponentReadiness::Unready
        } else {
            self.health.borrow().readiness()
        }
    }

    fn drained_changes(&self) -> watch::Receiver<bool> {
        self.drained.subscribe()
    }
}

#[derive(Clone)]
struct SharedDraftCertificateRepository(Arc<PgDeviceCertificateRepository<DraftEligibility>>);

impl CertificateReconcileRepository<DraftEligibility> for SharedDraftCertificateRepository {
    async fn load_current_view(
        &self,
        authority: &CertificateAttemptAuthority,
    ) -> Result<Option<CertificateReconcileView>, CertificateReconcileRepositoryError> {
        self.0.load_current_view(authority).await
    }

    async fn load_artifact_receipts(
        &self,
        fence: &CertificateAttemptFence,
    ) -> Result<
        Vec<PersistedCertificateArtifactSnapshot<DraftEligibility>>,
        CertificateReconcileRepositoryError,
    > {
        self.0.load_artifact_receipts(fence).await
    }

    async fn load_current_command_evidence(
        &self,
        fence: &CertificateAttemptFence,
    ) -> Result<
        Option<eventexec::reconcile::DeviceCertificateCommandEvidence>,
        CertificateReconcileRepositoryError,
    > {
        self.0.load_current_command_evidence(fence).await
    }

    async fn expire_due_current_command(
        &self,
        fence: &CertificateAttemptFence,
    ) -> Result<CurrentCommandExpiryOutcome, CertificateReconcileRepositoryError> {
        self.0.expire_due_current_command(fence).await
    }

    async fn append_artifact_receipt(
        &self,
        fence: &CertificateAttemptFence,
        authorization: ArtifactAppendAuthorization<DraftEligibility>,
    ) -> Result<ArtifactAppendOutcome, CertificateReconcileRepositoryError> {
        self.0.append_artifact_receipt(fence, authorization).await
    }

    async fn write_conditions(
        &self,
        fence: &CertificateAttemptFence,
        conditions: CertificateConditionMutation,
    ) -> Result<FencedMutationOutcome, CertificateReconcileRepositoryError> {
        self.0.write_conditions(fence, conditions).await
    }

    async fn rotate_generation(
        &self,
        fence: &CertificateAttemptFence,
    ) -> Result<RotationOutcome, CertificateReconcileRepositoryError> {
        self.0.rotate_generation(fence).await
    }

    async fn request_deletion(
        &self,
        fence: &CertificateAttemptFence,
    ) -> Result<DeletionRequestOutcome, CertificateReconcileRepositoryError> {
        self.0.request_deletion(fence).await
    }
}

impl DeviceIngressRepository<DraftEligibility> for SharedDraftCertificateRepository {
    type Error = deviceloop::DeviceCommandStoreError;
    type Commit = postgres::PgDeviceIngressCommit<DraftEligibility>;

    async fn commit(&self, input: DeviceIngressWrite) -> Result<Self::Commit, Self::Error> {
        self.0.commit(input).await
    }
}

struct LoopStoppedGuard(PilotLoopControl);

impl Drop for LoopStoppedGuard {
    fn drop(&mut self) {
        self.0.mark_stopped();
    }
}

async fn run_ingress_loop(
    repository: SharedDraftCertificateRepository,
    mqtt: Arc<MqttSession>,
    settlement_timeout: Duration,
    cancellation: CancellationToken,
    control: PilotLoopControl,
    transport_shutdown_failed: Arc<PilotShutdownFailureLatch>,
) {
    let _stopped = LoopStoppedGuard(control.clone());
    let mut paused = control.paused.subscribe();
    control.mark_ready();
    while ingress_step(
        &repository,
        &mqtt,
        settlement_timeout,
        &cancellation,
        &control,
        &transport_shutdown_failed,
        &mut paused,
    )
    .await
        == LoopStep::Continue
    {}
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LoopStep {
    Continue,
    Stop,
}

async fn ingress_step(
    repository: &SharedDraftCertificateRepository,
    mqtt: &MqttSession,
    settlement_timeout: Duration,
    cancellation: &CancellationToken,
    control: &PilotLoopControl,
    transport_shutdown_failed: &PilotShutdownFailureLatch,
    paused: &mut watch::Receiver<bool>,
) -> LoopStep {
    if cancellation.is_cancelled() {
        return LoopStep::Stop;
    }
    if *paused.borrow() {
        control.mark_paused();
        return wait_for_admission_change(paused, cancellation).await;
    }
    match next_ingress_event(mqtt, paused, cancellation).await {
        IngressLoopEvent::Stop => LoopStep::Stop,
        IngressLoopEvent::AdmissionChanged => LoopStep::Continue,
        IngressLoopEvent::Delivery(delivery) => {
            handle_ingress_delivery(
                repository,
                mqtt,
                settlement_timeout,
                *delivery,
                cancellation,
                control,
                transport_shutdown_failed,
            )
            .await
        }
    }
}

enum IngressLoopEvent {
    Stop,
    AdmissionChanged,
    Delivery(Box<Result<mqtt::AuthenticatedDeviceDelivery, mqtt::MqttSessionError>>),
}

async fn next_ingress_event(
    mqtt: &MqttSession,
    paused: &mut watch::Receiver<bool>,
    cancellation: &CancellationToken,
) -> IngressLoopEvent {
    tokio::select! {
        biased;
        () = cancellation.cancelled() => IngressLoopEvent::Stop,
        changed = paused.changed() => {
            if changed.is_ok() {
                IngressLoopEvent::AdmissionChanged
            } else {
                IngressLoopEvent::Stop
            }
        },
        delivery = mqtt.next_uplink() => IngressLoopEvent::Delivery(Box::new(delivery)),
    }
}

async fn handle_ingress_delivery(
    repository: &SharedDraftCertificateRepository,
    mqtt: &MqttSession,
    settlement_timeout: Duration,
    delivery: Result<mqtt::AuthenticatedDeviceDelivery, mqtt::MqttSessionError>,
    cancellation: &CancellationToken,
    control: &PilotLoopControl,
    transport_shutdown_failed: &PilotShutdownFailureLatch,
) -> LoopStep {
    let Ok(delivery) = delivery else {
        control.mark_degraded();
        return LoopStep::Stop;
    };
    control.set_in_flight(1);
    let outcome = tokio::select! {
        biased;
        () = cancellation.cancelled() => return LoopStep::Stop,
        outcome = process_ingress(repository, delivery) => outcome,
    };
    let shutdown = ingress_outcome_requires_shutdown(&outcome);
    observe_ingress_outcome(outcome, control);
    control.set_in_flight(0);
    if shutdown {
        match tokio::time::timeout(settlement_timeout, ManagedResource::shutdown(mqtt)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => transport_shutdown_failed.record(error.kind()),
            Err(_) => {
                transport_shutdown_failed.record(diport::ShutdownErrorKind::DeadlineExceeded);
            }
        }
        LoopStep::Stop
    } else {
        LoopStep::Continue
    }
}

/// Single source of truth for whether `handle_ingress_delivery` must shut down transport.
///
/// `Commit` / `Settlement` are fatal. `Ok` and `StaleTerminalSettlement` (durable post-commit or
/// bounded unaddressable-poison terminal) keep the recovered session and await broker replay.
fn ingress_outcome_requires_shutdown(outcome: &Result<(), IngressFailure>) -> bool {
    match outcome {
        Ok(()) | Err(IngressFailure::StaleTerminalSettlement) => false,
        Err(IngressFailure::Commit | IngressFailure::Settlement) => true,
    }
}

fn observe_ingress_outcome(outcome: Result<(), IngressFailure>, control: &PilotLoopControl) {
    match outcome {
        Ok(()) => control.mark_ready(),
        Err(IngressFailure::StaleTerminalSettlement) => {
            tracing::info!(
                component = "deviceidentity_ingress",
                reason = IngressFailure::StaleTerminalSettlement.label(),
                "terminal settlement stale; awaiting broker same-envelope replay"
            );
        }
        Err(failure) => {
            log_ingress_failure(failure);
            control.mark_degraded();
        }
    }
}

async fn wait_for_admission_change(
    paused: &mut watch::Receiver<bool>,
    cancellation: &CancellationToken,
) -> LoopStep {
    tokio::select! {
        biased;
        () = cancellation.cancelled() => LoopStep::Stop,
        changed = paused.changed() => {
            if changed.is_ok() {
                LoopStep::Continue
            } else {
                LoopStep::Stop
            }
        },
    }
}

async fn process_ingress(
    repository: &SharedDraftCertificateRepository,
    delivery: mqtt::AuthenticatedDeviceDelivery,
) -> Result<(), IngressFailure> {
    let prepared = match identity::ports::device_certificate::prepare_device_ingress(&delivery) {
        identity::ports::device_certificate::DeviceIngressPreparation::Accepted(prepared)
        | identity::ports::device_certificate::DeviceIngressPreparation::Rejected(prepared) => {
            prepared
        }
        identity::ports::device_certificate::DeviceIngressPreparation::UnaddressablePoison(
            poison,
        ) => {
            tracing::warn!(
                component = "deviceidentity_ingress",
                reason = ?poison.reason(),
                "authenticated device ingress entered bounded poison terminal"
            );
            return super::device_ingress::acknowledge_unaddressable_device_ingress(
                delivery, poison,
            )
            .map_err(classify_transport_settlement);
        }
    };
    let (write, pending) = prepared.into_parts();
    let committed = repository
        .commit(write)
        .await
        .map_err(|_| IngressFailure::Commit)?;
    super::acknowledge_postgres_device_ingress(delivery, pending, committed)
        .await
        .map_err(classify_postgres_settlement)?;
    Ok(())
}

fn classify_transport_settlement(error: mqtt::MqttSessionError) -> IngressFailure {
    match error {
        mqtt::MqttSessionError::StaleTransportEpoch => IngressFailure::StaleTerminalSettlement,
        _ => IngressFailure::Settlement,
    }
}

fn classify_postgres_settlement(
    error: super::PostgresDeviceIngressSettlementError,
) -> IngressFailure {
    match error {
        super::PostgresDeviceIngressSettlementError::ReceiptMismatch(_) => {
            IngressFailure::Settlement
        }
        super::PostgresDeviceIngressSettlementError::Transport(transport) => {
            classify_transport_settlement(transport)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IngressFailure {
    Commit,
    Settlement,
    /// Terminal settlement crossed a recovered transport epoch (durable post-commit or
    /// bounded unaddressable-poison terminal). Keep the session; await broker replay.
    StaleTerminalSettlement,
}

impl IngressFailure {
    const fn label(self) -> &'static str {
        match self {
            Self::Commit => "commit",
            Self::Settlement => "puback",
            Self::StaleTerminalSettlement => "stale_terminal_settlement",
        }
    }
}

fn log_ingress_failure(failure: IngressFailure) {
    tracing::warn!(
        component = "deviceidentity_ingress",
        reason = failure.label(),
        "authenticated device ingress did not settle"
    );
}

#[derive(Clone, Copy)]
enum DeviceRelayKind {
    Command,
    Receipt,
}

impl DeviceRelayKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Command => "command",
            Self::Receipt => "receipt",
        }
    }
}

struct DeviceRelayRuntime {
    kind: DeviceRelayKind,
    outbox: Arc<PgDeviceOutbox>,
    publisher: DeviceMqttPublisher,
    config: RelayConfig,
    budget: RelayBudget,
    cancellation: CancellationToken,
    control: PilotLoopControl,
}

impl DeviceRelayRuntime {
    async fn run(self) {
        let _stopped = LoopStoppedGuard(self.control.clone());
        let mut paused = self.control.paused.subscribe();
        let mut ticker = tokio::time::interval(self.config.poll_interval());
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        self.control.mark_ready();
        while self.relay_step(&mut paused, &mut ticker).await == LoopStep::Continue {}
    }

    async fn relay_step(
        &self,
        paused: &mut watch::Receiver<bool>,
        ticker: &mut tokio::time::Interval,
    ) -> LoopStep {
        if self.cancellation.is_cancelled() {
            return LoopStep::Stop;
        }
        if *paused.borrow() {
            self.control.mark_paused();
            return wait_for_admission_change(paused, &self.cancellation).await;
        }
        match next_relay_event(paused, ticker, &self.cancellation).await {
            RelayLoopEvent::Stop => LoopStep::Stop,
            RelayLoopEvent::AdmissionChanged => LoopStep::Continue,
            RelayLoopEvent::Tick => self.run_round_or_cancel().await,
        }
    }

    async fn run_round_or_cancel(&self) -> LoopStep {
        let clean = tokio::select! {
            biased;
            () = self.cancellation.cancelled() => return LoopStep::Stop,
            clean = run_relay_round(
                self.kind,
                &self.outbox,
                &self.publisher,
                self.config.max_in_flight(),
                self.budget,
                &self.control,
            ) => clean,
        };
        if clean {
            self.control.mark_ready();
        } else {
            self.control.mark_degraded();
        }
        LoopStep::Continue
    }
}

enum RelayLoopEvent {
    Stop,
    AdmissionChanged,
    Tick,
}

async fn next_relay_event(
    paused: &mut watch::Receiver<bool>,
    ticker: &mut tokio::time::Interval,
    cancellation: &CancellationToken,
) -> RelayLoopEvent {
    tokio::select! {
        biased;
        () = cancellation.cancelled() => RelayLoopEvent::Stop,
        changed = paused.changed() => {
            if changed.is_ok() {
                RelayLoopEvent::AdmissionChanged
            } else {
                RelayLoopEvent::Stop
            }
        },
        _ = ticker.tick() => RelayLoopEvent::Tick,
    }
}

async fn run_relay_round(
    kind: DeviceRelayKind,
    outbox: &PgDeviceOutbox,
    publisher: &DeviceMqttPublisher,
    limit: usize,
    budget: RelayBudget,
    control: &PilotLoopControl,
) -> bool {
    let claims = match claim_relay_batch(kind, outbox, limit).await {
        Ok(claims) => claims,
        Err(_) => {
            tracing::warn!(
                component = "deviceidentity_relay",
                relay = kind.label(),
                reason = "claim",
                "device MQTT outbox claim failed"
            );
            return false;
        }
    };
    control.set_in_flight(claims.len());
    let mut clean = true;
    let mut remaining = claims.len();
    let mut publications = FuturesUnordered::new();
    for claim in claims {
        publications.push(publish_and_settle(outbox, publisher, claim, budget));
    }
    while let Some(settled) = publications.next().await {
        if !settled {
            clean = false;
        }
        remaining -= 1;
        control.set_in_flight(remaining);
    }
    clean
}

async fn claim_relay_batch(
    kind: DeviceRelayKind,
    outbox: &PgDeviceOutbox,
    limit: usize,
) -> Result<Vec<PgClaimedDeviceOutbox>, consistency::EngineError> {
    match kind {
        DeviceRelayKind::Command => outbox
            .claim_commands(limit)
            .await
            .map(|claims| claims.into_iter().map(Into::into).collect()),
        DeviceRelayKind::Receipt => outbox
            .claim_receipts(limit)
            .await
            .map(|claims| claims.into_iter().map(Into::into).collect()),
    }
}

async fn publish_and_settle(
    outbox: &PgDeviceOutbox,
    publisher: &DeviceMqttPublisher,
    claim: PgClaimedDeviceOutbox,
    budget: RelayBudget,
) -> bool {
    let Some(accepted) = publish_with_budget(publisher, claim, budget).await else {
        log_relay_failure("publish");
        return false;
    };
    if settle_puback(outbox, accepted).await {
        true
    } else {
        log_relay_failure("settle");
        false
    }
}

async fn publish_with_budget(
    publisher: &DeviceMqttPublisher,
    claim: PgClaimedDeviceOutbox,
    budget: RelayBudget,
) -> Option<PgBrokerAcceptedDeviceOutbox> {
    match tokio::time::timeout(budget.publish_timeout(), publisher.publish(claim)).await {
        Ok(Ok(accepted)) => Some(accepted),
        Ok(Err(_)) | Err(_) => None,
    }
}

async fn settle_puback(outbox: &PgDeviceOutbox, accepted: PgBrokerAcceptedDeviceOutbox) -> bool {
    let settled = outbox.settle_puback(accepted).await;
    matches!(settled, Ok(PgDeviceOutboxSettlement::Settled))
}

fn log_relay_failure(reason: &'static str) {
    tracing::warn!(
        component = "deviceidentity_relay",
        reason,
        "device MQTT outbox relay did not settle"
    );
}

/// Canonical owner of the draft pilot workers, admission controls, readiness, and shutdown.
struct DeviceIdentityPilot {
    postgres_readiness: Arc<PgDbReadiness>,
    mqtt: Arc<MqttSession>,
    _command_store: Arc<PgDeviceCommandStore<DraftEligibility>>,
    reconcile_health: Arc<WorkerHealth>,
    reconcile_control: ReconcileWorkerControl,
    ingress_control: PilotLoopControl,
    command_relay_control: PilotLoopControl,
    receipt_relay_control: PilotLoopControl,
    cancellation: CancellationToken,
    tasks: Vec<diport::ManagedTask>,
    transport_shutdown_failed: Arc<PilotShutdownFailureLatch>,
    shutdown_timeout: Duration,
}

/// One started pilot before its read handle and move-only adoption receipt are separated.
pub struct DeviceIdentityPilotLifecycle {
    handle: DeviceIdentityPilotHandle,
    adoption: DeviceIdentityPilotAdoption,
}

/// Cloneable, read-only view of one started pilot.
#[derive(Clone)]
pub struct DeviceIdentityPilotHandle {
    pilot: Arc<DeviceIdentityPilot>,
}

/// Test-only move guard proving one pilot loop acknowledged pause with zero in-flight work.
///
/// The fields are private and the guard is not cloneable. Explicit resume consumes it; dropping it
/// also restores admission so cancellation and early returns cannot strand the loop. Receipt relay
/// and ingress share this single guard type — there is no alias or second pause guard.
#[cfg(any(test, feature = "test-support"))]
#[must_use = "holding this guard keeps the paused pilot loop admission closed"]
pub struct PilotLoopPauseGuard {
    control: Option<PilotLoopControl>,
}

#[cfg(any(test, feature = "test-support"))]
impl PilotLoopPauseGuard {
    /// Resume the paused loop and consume the only pause guard.
    pub fn resume(mut self) {
        self.restore_admission();
    }

    fn restore_admission(&mut self) {
        if let Some(control) = self.control.take() {
            control.resume();
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
impl Drop for PilotLoopPauseGuard {
    fn drop(&mut self) {
        self.restore_admission();
    }
}

#[cfg(any(test, feature = "test-support"))]
async fn pause_pilot_loop_control_for_test(control: PilotLoopControl) -> PilotLoopPauseGuard {
    let guard = PilotLoopPauseGuard {
        control: Some(control.clone()),
    };
    control.pause();
    control.wait_drained().await;
    guard
}

/// Move-only authority to adopt one started pilot into generated domain lifecycle output.
pub struct DeviceIdentityPilotAdoption {
    pilot: Option<Arc<DeviceIdentityPilot>>,
}

impl DeviceIdentityPilotLifecycle {
    /// Start the pilot and seal it into the only lifecycle receipt accepted by the assembly.
    ///
    /// Omitting authenticated MQTT is a compile-time error; there is no optional transport path.
    ///
    /// ```compile_fail
    /// use identity_composition::{DeviceIdentityPilotConfig, DeviceIdentityPilotLifecycle, DraftArtifactSimulator};
    ///
    /// fn missing_mqtt(
    ///     postgres: postgres::PgDeviceIdentityDraftRuntime,
    ///     simulator: DraftArtifactSimulator,
    ///     config: DeviceIdentityPilotConfig,
    /// ) {
    ///     let _ = DeviceIdentityPilotLifecycle::start(postgres, simulator, config);
    /// }
    /// ```
    pub fn start(
        postgres: PgDeviceIdentityDraftRuntime,
        artifact_source: DraftArtifactSimulator,
        mqtt: Arc<MqttSession>,
        config: DeviceIdentityPilotConfig,
    ) -> Result<Self, DeviceIdentityPilotStartError> {
        let pilot = Arc::new(DeviceIdentityPilot::start(
            postgres,
            artifact_source,
            mqtt,
            config,
        )?);
        Ok(Self {
            handle: DeviceIdentityPilotHandle {
                pilot: Arc::clone(&pilot),
            },
            adoption: DeviceIdentityPilotAdoption { pilot: Some(pilot) },
        })
    }

    /// Split the started pilot into read-only observation and one adoption authority.
    #[must_use]
    pub fn into_parts(self) -> (DeviceIdentityPilotHandle, DeviceIdentityPilotAdoption) {
        (self.handle, self.adoption)
    }
}

impl DeviceIdentityPilotAdoption {
    /// Consume the only adoption authority into the generated domain's lifecycle output.
    pub fn into_domain_output(mut self) -> anyhow::Result<bootstrap::DomainModuleResult> {
        let name = primitives::ProbeName::parse("deviceidentity-pilot")?;
        let pilot = self.pilot.take().ok_or_else(|| {
            anyhow::anyhow!("deviceidentity adoption authority was already consumed")
        })?;
        let resource = PilotManagedResource {
            pilot: Arc::clone(&pilot),
            cleanup_armed: AtomicBool::new(true),
        };
        Ok(bootstrap::DomainModuleResult::from_parts(
            [(
                name.clone(),
                Box::new(PilotReadinessProbe { name, pilot }) as _,
            )],
            [],
            [bootstrap::WorkerSpec::observational_deferred(
                "composition.identity.src.pilot.01",
                move |_token| DynManagedResource::new_box(resource),
            )],
        ))
    }

    /// Cleanup-only path used when generated domain composition fails before lifecycle adoption.
    pub async fn shutdown_unadopted(mut self) -> Result<(), DeviceIdentityPilotShutdownError> {
        let Some(pilot) = self.pilot.take() else {
            return Ok(());
        };
        shutdown_unadopted_pilot(&pilot)
            .await
            .map_err(PilotShutdownFailure::into_public)
    }
}

impl Drop for DeviceIdentityPilotAdoption {
    fn drop(&mut self) {
        let Some(pilot) = self.pilot.take() else {
            return;
        };
        spawn_pilot_cleanup(pilot, "unadopted deviceidentity pilot cleanup failed");
    }
}

impl DeviceIdentityPilotHandle {
    #[must_use]
    pub fn readiness(&self) -> DeviceIdentityPilotReadiness {
        self.pilot.readiness()
    }

    #[must_use]
    pub fn ingress_drained_changes(&self) -> watch::Receiver<bool> {
        self.pilot.ingress_drained_changes()
    }

    /// Pause only the application-receipt relay for deterministic integration observation.
    ///
    /// This test-support surface returns only after the worker acknowledged the pause and all
    /// in-flight receipt publications completed. Dropping the returned guard resumes admission.
    #[cfg(feature = "test-support")]
    pub async fn pause_receipt_relay_for_test(&self) -> PilotLoopPauseGuard {
        pause_pilot_loop_control_for_test(self.pilot.receipt_relay_control.clone()).await
    }

    /// Pause only durable ingress consumption for deterministic join-hazard observation.
    ///
    /// Returns only after the ingress worker acknowledged the pause and in-flight settlement
    /// reached zero. Dropping the returned guard resumes admission; shared guard type with
    /// [`Self::pause_receipt_relay_for_test`].
    #[cfg(feature = "test-support")]
    pub async fn pause_ingress_for_test(&self) -> PilotLoopPauseGuard {
        pause_pilot_loop_control_for_test(self.pilot.ingress_control.clone()).await
    }
}

struct PilotManagedResource {
    pilot: Arc<DeviceIdentityPilot>,
    cleanup_armed: AtomicBool,
}

impl ManagedResource for PilotManagedResource {
    fn name(&self) -> &str {
        "deviceidentity-pilot"
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        let result = self
            .pilot
            .shutdown()
            .await
            .map_err(PilotShutdownFailure::into_shutdown_error);
        if result.is_ok() {
            self.cleanup_armed.store(false, Ordering::Release);
        }
        result
    }

    fn shutdown_timeout(&self) -> Duration {
        self.pilot.shutdown_timeout
    }
}

impl Drop for PilotManagedResource {
    fn drop(&mut self) {
        if self.cleanup_armed.swap(false, Ordering::AcqRel) {
            spawn_pilot_cleanup(
                Arc::clone(&self.pilot),
                "unregistered deviceidentity pilot cleanup failed",
            );
        }
    }
}

fn spawn_pilot_cleanup(pilot: Arc<DeviceIdentityPilot>, message: &'static str) {
    pilot.pause_admission();
    pilot.cancellation.cancel();
    if let Ok(runtime) = tokio::runtime::Handle::try_current() {
        runtime.spawn(async move {
            if let Err(error) = shutdown_unadopted_pilot(&pilot).await {
                tracing::error!(%error, reason = message, "deviceidentity pilot cleanup failed");
            }
        });
    }
}

async fn shutdown_unadopted_pilot(
    pilot: &Arc<DeviceIdentityPilot>,
) -> Result<(), PilotShutdownFailure> {
    shutdown_within_pilot_cleanup_budget(pilot.shutdown_timeout, pilot.shutdown()).await
}

async fn shutdown_within_pilot_cleanup_budget<F>(
    budget: Duration,
    shutdown: F,
) -> Result<(), PilotShutdownFailure>
where
    F: Future<Output = Result<(), PilotShutdownFailure>>,
{
    match tokio::time::timeout(budget, shutdown).await {
        Ok(result) => result,
        Err(_) => Err(PilotShutdownFailure::Worker(
            ShutdownError::deadline_exceeded(PilotCleanupDeadline),
        )),
    }
}

#[derive(Debug, thiserror::Error)]
#[error("deviceidentity pilot cleanup deadline exceeded")]
struct PilotCleanupDeadline;

struct PilotReadinessProbe {
    name: primitives::ProbeName,
    pilot: Arc<DeviceIdentityPilot>,
}

impl bootstrap::HealthProbe for PilotReadinessProbe {
    fn check(&self) -> primitives::HealthCheck {
        let readiness = self.pilot.readiness().overall();
        primitives::HealthCheck::new(
            self.name.clone(),
            readiness.probe_status(),
            readiness.probe_detail(),
        )
    }
}

impl Drop for DeviceIdentityPilot {
    fn drop(&mut self) {
        self.pause_admission();
        self.cancellation.cancel();
    }
}

/// Fail-fast pilot construction error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DeviceIdentityPilotStartError {
    #[error("deviceidentity pilot requires an active Tokio runtime")]
    MissingRuntime,
    #[error(
        "deviceidentity pilot holder identity must be non-empty without surrounding whitespace"
    )]
    InvalidHolderIdentity,
    #[error("deviceidentity pilot shutdown timeout must be non-zero")]
    InvalidShutdownTimeout,
    #[error("deviceidentity PostgreSQL stores are not ready")]
    PostgresNotReady,
    #[error("deviceidentity MQTT session is not authenticated and ready")]
    MqttNotReady,
    #[error("deviceidentity pilot reconcile configuration is invalid")]
    Reconcile(#[from] ReconcileConfigError),
}

/// Bounded shutdown failure. Admission remains closed after either outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DeviceIdentityPilotShutdownError {
    #[error("deviceidentity pilot worker terminated abnormally")]
    WorkerFailed,
    #[error("deviceidentity MQTT transport shutdown failed")]
    Transport,
}

#[derive(Debug, thiserror::Error)]
enum PilotShutdownFailure {
    #[error("deviceidentity pilot worker terminated abnormally")]
    Worker(#[source] ShutdownError),
    #[error("deviceidentity MQTT transport shutdown failed")]
    Transport(#[source] ShutdownError),
}

impl PilotShutdownFailure {
    fn into_public(self) -> DeviceIdentityPilotShutdownError {
        match self {
            Self::Worker(_) => DeviceIdentityPilotShutdownError::WorkerFailed,
            Self::Transport(_) => DeviceIdentityPilotShutdownError::Transport,
        }
    }

    fn into_shutdown_error(self) -> ShutdownError {
        match self {
            Self::Worker(error) | Self::Transport(error) => error,
        }
    }
}

struct PilotShutdownFailureLatch(AtomicU8);

impl PilotShutdownFailureLatch {
    const NONE: u8 = 0;

    const fn new() -> Self {
        Self(AtomicU8::new(Self::NONE))
    }

    fn record(&self, kind: diport::ShutdownErrorKind) {
        let encoded = match kind {
            diport::ShutdownErrorKind::Operation => 1,
            diport::ShutdownErrorKind::TaskPanicked => 2,
            diport::ShutdownErrorKind::TaskCancelled => 3,
            diport::ShutdownErrorKind::TaskUnknown => 4,
            diport::ShutdownErrorKind::DeadlineExceeded => 5,
        };
        let _ = self
            .0
            .compare_exchange(Self::NONE, encoded, Ordering::AcqRel, Ordering::Acquire);
    }

    fn load(&self) -> Option<diport::ShutdownErrorKind> {
        match self.0.load(Ordering::Acquire) {
            Self::NONE => None,
            1 => Some(diport::ShutdownErrorKind::Operation),
            2 => Some(diport::ShutdownErrorKind::TaskPanicked),
            3 => Some(diport::ShutdownErrorKind::TaskCancelled),
            4 => Some(diport::ShutdownErrorKind::TaskUnknown),
            5 => Some(diport::ShutdownErrorKind::DeadlineExceeded),
            _ => Some(diport::ShutdownErrorKind::TaskUnknown),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("deviceidentity MQTT transport previously failed during shutdown")]
struct LatchedTransportShutdownFailure;

fn latched_transport_shutdown_error(kind: diport::ShutdownErrorKind) -> ShutdownError {
    match kind {
        diport::ShutdownErrorKind::Operation => ShutdownError::new(LatchedTransportShutdownFailure),
        diport::ShutdownErrorKind::TaskPanicked => {
            ShutdownError::task_panicked(LatchedTransportShutdownFailure)
        }
        diport::ShutdownErrorKind::TaskCancelled => {
            ShutdownError::task_cancelled(LatchedTransportShutdownFailure)
        }
        diport::ShutdownErrorKind::TaskUnknown => {
            ShutdownError::task_unknown(LatchedTransportShutdownFailure)
        }
        diport::ShutdownErrorKind::DeadlineExceeded => {
            ShutdownError::deadline_exceeded(LatchedTransportShutdownFailure)
        }
    }
}

impl DeviceIdentityPilot {
    /// Start the canonical pilot from the single-origin PostgreSQL receipt, deterministic draft
    /// provider, authenticated MQTT provider, and one complete runtime configuration.
    ///
    fn start(
        postgres: PgDeviceIdentityDraftRuntime,
        artifact_source: DraftArtifactSimulator,
        mqtt: Arc<MqttSession>,
        config: DeviceIdentityPilotConfig,
    ) -> Result<Self, DeviceIdentityPilotStartError> {
        tokio::runtime::Handle::try_current()
            .map_err(|_| DeviceIdentityPilotStartError::MissingRuntime)?;
        if !valid_holder_identity(&config.scheduler.holder_id) {
            return Err(DeviceIdentityPilotStartError::InvalidHolderIdentity);
        }
        if config.shutdown_timeout.is_zero() {
            return Err(DeviceIdentityPilotStartError::InvalidShutdownTimeout);
        }
        let (repository, command_store, revocations, reconcile_store, postgres_readiness) =
            postgres.into_parts();
        if !matches!(postgres_readiness.snapshot(), PoolReadiness::Ready) {
            return Err(DeviceIdentityPilotStartError::PostgresNotReady);
        }
        if !matches!(mqtt.readiness(), MqttReadiness::Ready { .. }) {
            return Err(DeviceIdentityPilotStartError::MqttNotReady);
        }

        let DeviceIdentityPilotConfig {
            scheduler,
            relays,
            shutdown_timeout,
        } = config;
        let DeviceIdentitySchedulerConfig {
            clock,
            keyring,
            producer,
            tenant,
            holder_id,
            tenancy,
            timing,
        } = scheduler;
        let DeviceIdentitySchedulerTiming {
            trigger,
            backoff,
            lease_ttl,
            max_in_flight,
        } = timing;
        let DeviceIdentityRelayConfig {
            command_ttl,
            command_relay,
            receipt_relay,
            relay_budget,
        } = relays;

        let repository = SharedDraftCertificateRepository(Arc::new(repository));
        let reconciler = DeviceCertificateReconciler::new(
            repository.clone(),
            Arc::new(artifact_source),
            revocations,
            Arc::clone(&clock),
            command_ttl,
        );
        let scheduler = ReconcileSchedulerBuilder::new(
            reconcile_store,
            reconciler,
            keyring,
            producer,
            tenant,
            DEVICE_CERTIFICATE_RECONCILER_ID,
            holder_id,
            tenancy,
            trigger,
        )
        .with_backoff(backoff)
        .with_lease_ttl(lease_ttl)?
        .with_max_in_flight(max_in_flight)
        .build();
        let reconcile_control = scheduler.control();
        let reconcile_health = scheduler.health();

        let command_store = Arc::new(command_store);
        let outbox = Arc::new(command_store.device_outbox(relay_budget));
        let publisher = DeviceMqttPublisher::new(Arc::clone(&mqtt));
        let cancellation = CancellationToken::new();
        let ingress_control = PilotLoopControl::new();
        let command_relay_control = PilotLoopControl::new();
        let receipt_relay_control = PilotLoopControl::new();
        let transport_shutdown_failed = Arc::new(PilotShutdownFailureLatch::new());

        let reconcile_token = cancellation.child_token();
        let reconcile_task = spawn_pilot_task(
            "deviceidentity-reconcile",
            reconcile_token,
            move |task_token| scheduler.run(task_token),
        );
        let ingress_token = cancellation.child_token();
        let ingress_task =
            spawn_pilot_task("deviceidentity-ingress", ingress_token, move |task_token| {
                run_ingress_loop(
                    repository,
                    Arc::clone(&mqtt),
                    relay_budget.settle_timeout(),
                    task_token,
                    ingress_control.clone(),
                    Arc::clone(&transport_shutdown_failed),
                )
            });
        let command_relay_token = cancellation.child_token();
        let command_relay_task = spawn_pilot_task(
            "deviceidentity-command-relay",
            command_relay_token,
            move |task_token| {
                DeviceRelayRuntime {
                    kind: DeviceRelayKind::Command,
                    outbox: Arc::clone(&outbox),
                    publisher: publisher.clone(),
                    config: command_relay,
                    budget: relay_budget,
                    cancellation: task_token,
                    control: command_relay_control.clone(),
                }
                .run()
            },
        );
        let receipt_relay_token = cancellation.child_token();
        let receipt_relay_task = spawn_pilot_task(
            "deviceidentity-receipt-relay",
            receipt_relay_token,
            move |task_token| {
                DeviceRelayRuntime {
                    kind: DeviceRelayKind::Receipt,
                    outbox,
                    publisher,
                    config: receipt_relay,
                    budget: relay_budget,
                    cancellation: task_token,
                    control: receipt_relay_control.clone(),
                }
                .run()
            },
        );

        Ok(Self {
            postgres_readiness,
            mqtt,
            _command_store: command_store,
            reconcile_health,
            reconcile_control,
            ingress_control,
            command_relay_control,
            receipt_relay_control,
            cancellation,
            tasks: vec![
                reconcile_task,
                ingress_task,
                command_relay_task,
                receipt_relay_task,
            ],
            transport_shutdown_failed,
            shutdown_timeout,
        })
    }

    /// Read the exact six component states and return their fail-closed aggregate.
    #[must_use]
    fn readiness(&self) -> DeviceIdentityPilotReadiness {
        let reconcile = if self.reconcile_control.is_paused() {
            PilotComponentReadiness::Unready
        } else {
            worker_readiness(&self.reconcile_health)
        };
        DeviceIdentityPilotReadiness::aggregate([
            postgres_readiness(self.postgres_readiness.snapshot()),
            reconcile,
            self.command_relay_control.readiness(),
            self.receipt_relay_control.readiness(),
            mqtt_readiness(self.mqtt.readiness()),
            self.ingress_control.readiness(),
        ])
    }

    /// Subscribe to the ingress worker's acknowledged admission-drain state.
    #[must_use]
    fn ingress_drained_changes(&self) -> watch::Receiver<bool> {
        self.ingress_control.drained_changes()
    }

    /// Pause all four admission points without cancelling in-flight work.
    fn pause_admission(&self) {
        self.ingress_control.pause();
        self.reconcile_control.pause();
        self.command_relay_control.pause();
        self.receipt_relay_control.pause();
    }

    /// Stop admission, drain attempts and publications, then stop workers and MQTT within bounds.
    async fn shutdown(&self) -> Result<(), PilotShutdownFailure> {
        self.pause_admission();
        wait_pilot_drain(self).await;
        self.cancellation.cancel();
        let worker_result = join_pilot_tasks(&self.tasks).await;
        let mut transport_result = ManagedResource::shutdown(self.mqtt.as_ref()).await;
        if let Some(kind) = self.transport_shutdown_failed.load() {
            transport_result = Err(latched_transport_shutdown_error(kind));
        }
        worker_result
            .map_err(PilotShutdownFailure::Worker)
            .and_then(|()| transport_result.map_err(PilotShutdownFailure::Transport))
    }
}

fn spawn_pilot_task<F, Make>(
    name: &'static str,
    token: CancellationToken,
    make: Make,
) -> diport::ManagedTask
where
    F: Future<Output = ()> + Send + 'static,
    Make: FnOnce(CancellationToken) -> F + Send + 'static,
{
    let (start, _) = diport::ManagedTask::prepare(name, diport::DEFAULT_SHUTDOWN_TIMEOUT);
    start.spawn(token, |managed_token| async move {
        make(managed_token).await;
        Ok(())
    })
}

async fn wait_pilot_drain(pilot: &DeviceIdentityPilot) {
    tokio::join!(
        pilot.ingress_control.wait_drained(),
        pilot.reconcile_control.wait_drained(),
        pilot.command_relay_control.wait_drained(),
        pilot.receipt_relay_control.wait_drained(),
    );
}

async fn join_pilot_tasks(tasks: &[diport::ManagedTask]) -> Result<(), ShutdownError> {
    let mut first_failure = None;
    for task in tasks {
        if let Err(error) = ManagedResource::shutdown(task).await
            && first_failure.is_none()
        {
            first_failure = Some(error);
        }
    }
    first_failure.map_or(Ok(()), Err)
}

fn valid_holder_identity(holder_id: &str) -> bool {
    !holder_id.is_empty() && holder_id.trim() == holder_id
}

fn postgres_readiness(readiness: PoolReadiness) -> PilotComponentReadiness {
    match readiness {
        PoolReadiness::Ready => PilotComponentReadiness::Ready,
        PoolReadiness::Saturated => PilotComponentReadiness::Degraded,
        PoolReadiness::Down => PilotComponentReadiness::Unready,
        _ => PilotComponentReadiness::Unready,
    }
}

fn mqtt_readiness(readiness: MqttReadiness) -> PilotComponentReadiness {
    match readiness {
        MqttReadiness::Ready { .. } => PilotComponentReadiness::Ready,
        MqttReadiness::Reloading { .. } | MqttReadiness::Degraded { .. } => {
            PilotComponentReadiness::Degraded
        }
        MqttReadiness::Starting | MqttReadiness::Stopped => PilotComponentReadiness::Unready,
    }
}

fn worker_readiness(health: &WorkerHealth) -> PilotComponentReadiness {
    match health.status() {
        primitives::healthz::HealthStatus::Healthy => PilotComponentReadiness::Ready,
        primitives::healthz::HealthStatus::Degraded => PilotComponentReadiness::Degraded,
        primitives::healthz::HealthStatus::Unhealthy => PilotComponentReadiness::Unready,
        _ => PilotComponentReadiness::Unready,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use identity::ports::device_certificate::{
        DeviceCertificateScope, ExpectedGeneration, PolicyHash,
    };

    #[tokio::test(start_paused = true)]
    async fn unadopted_cleanup_budget_drops_hung_shutdown_future() {
        struct Dropped(Arc<AtomicBool>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        let dropped = Arc::new(AtomicBool::new(false));
        let marker = Dropped(Arc::clone(&dropped));
        let result = shutdown_within_pilot_cleanup_budget(Duration::from_secs(1), async move {
            let _marker = marker;
            std::future::pending::<Result<(), PilotShutdownFailure>>().await
        })
        .await;
        let PilotShutdownFailure::Worker(error) = result.expect_err("cleanup must time out") else {
            panic!("timeout must be a worker lifecycle failure");
        };
        assert_eq!(error.kind(), diport::ShutdownErrorKind::DeadlineExceeded);
        assert!(dropped.load(Ordering::Acquire));
    }

    #[test]
    fn stale_transport_epoch_is_nonfatal_terminal_settlement() {
        let failure = classify_transport_settlement(mqtt::MqttSessionError::StaleTransportEpoch);
        assert_eq!(failure, IngressFailure::StaleTerminalSettlement);
        assert!(!ingress_outcome_requires_shutdown(&Err(failure)));

        let control = PilotLoopControl::new();
        control.mark_ready();
        observe_ingress_outcome(Err(failure), &control);
        assert_eq!(control.readiness(), PilotComponentReadiness::Ready);
    }

    #[test]
    fn ack_unavailable_delivery_closed_and_broker_rejected_remain_fatal() {
        for error in [
            mqtt::MqttSessionError::AckUnavailable,
            mqtt::MqttSessionError::DeliveryClosed,
            mqtt::MqttSessionError::BrokerRejected,
        ] {
            let failure = classify_transport_settlement(error);
            assert_eq!(failure, IngressFailure::Settlement);
            assert!(ingress_outcome_requires_shutdown(&Err(failure)));
        }

        assert!(ingress_outcome_requires_shutdown(&Err(
            IngressFailure::Commit
        )));
        assert!(!ingress_outcome_requires_shutdown(&Ok(())));

        let control = PilotLoopControl::new();
        control.mark_ready();
        observe_ingress_outcome(Err(IngressFailure::Settlement), &control);
        assert_eq!(control.readiness(), PilotComponentReadiness::Degraded);
    }

    fn scope() -> DeviceCertificateScope {
        DeviceCertificateScope::for_test(
            rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
                .expect("tenant"),
            ids::DeviceId::parse("550e8400-e29b-41d4-a716-446655440000").expect("device"),
        )
    }

    #[test]
    fn draft_coordinates_are_deterministic_and_bound_to_generation() {
        let seed = [0x5a; 32];
        let policy = PolicyHash::parse(&format!("sha256:{}", "a".repeat(64))).expect("policy");
        let first = draft_digest(&seed, b"coordinate", scope(), 7, policy.as_bytes());
        let replay = draft_digest(&seed, b"coordinate", scope(), 7, policy.as_bytes());
        let next = draft_digest(&seed, b"coordinate", scope(), 8, policy.as_bytes());
        assert_eq!(first, replay);
        assert_ne!(first, next);
        assert_eq!(lowercase_hex(&first).len(), 64);
        let _: ExpectedGeneration = ExpectedGeneration::try_new(7).expect("generation");
    }

    #[test]
    fn draft_material_passes_the_complete_authorization_funnel() {
        let scope = scope();
        let generation = ExpectedGeneration::try_new(7).expect("generation");
        let policy = PolicyHash::parse(&format!("sha256:{}", "b".repeat(64))).expect("policy");
        let not_after = CertNotAfter::try_from_system_time(
            std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(4_102_444_800),
        )
        .expect("not-after");
        let simulator = DraftArtifactSimulator::new([0x33; 32], not_after);
        let material = DraftArtifactMaterial::derive(&simulator, scope, generation, &policy)
            .expect("draft material");
        let expected = CertificateArtifactRequest::for_test(
            scope,
            generation,
            policy.clone(),
            material.binding,
        )
        .expect("complete request");
        let authorized =
            ProviderCertificateCandidate::new(material.artifact, expected.binding().clone())
                .authorize_draft(&expected)
                .expect("draft authorization");
        let snapshot = authorized.into_append_authorization().into_snapshot();
        assert_eq!(snapshot.scope(), scope);
        assert_eq!(snapshot.generation(), generation);
        assert_eq!(snapshot.not_after(), not_after);
    }

    #[test]
    fn readiness_is_the_worst_of_exactly_six_components() {
        let ready = DeviceIdentityPilotReadiness::aggregate([PilotComponentReadiness::Ready; 6]);
        assert_eq!(ready.overall(), PilotComponentReadiness::Ready);

        for index in 0..6 {
            let mut components = [PilotComponentReadiness::Ready; 6];
            components[index] = PilotComponentReadiness::Degraded;
            assert_eq!(
                DeviceIdentityPilotReadiness::aggregate(components).overall(),
                PilotComponentReadiness::Degraded
            );
            components[index] = PilotComponentReadiness::Unready;
            assert_eq!(
                DeviceIdentityPilotReadiness::aggregate(components).overall(),
                PilotComponentReadiness::Unready
            );
        }
    }

    #[test]
    fn drain_matrix_requires_observed_pause_and_zero_in_flight() {
        for stopped in [false, true] {
            for paused in [false, true] {
                for in_flight in [0, 1] {
                    let observation = DrainObservation {
                        paused,
                        in_flight,
                        stopped,
                    };
                    assert_eq!(
                        observation.is_drained(),
                        stopped || (paused && in_flight == 0)
                    );
                }
            }
        }
    }

    #[test]
    fn pilot_probe_preserves_all_three_readiness_states() {
        assert_eq!(
            PilotComponentReadiness::Ready.probe_status(),
            primitives::HealthStatus::Healthy
        );
        assert_eq!(
            PilotComponentReadiness::Degraded.probe_status(),
            primitives::HealthStatus::Degraded
        );
        assert_eq!(
            PilotComponentReadiness::Unready.probe_status(),
            primitives::HealthStatus::Unhealthy
        );
    }

    #[test]
    fn lifecycle_adoption_receipt_is_move_only() {
        static_assertions::assert_not_impl_any!(DeviceIdentityPilotLifecycle: Clone, Copy);
        static_assertions::assert_not_impl_any!(DeviceIdentityPilotAdoption: Clone, Copy);
        static_assertions::assert_impl_all!(DeviceIdentityPilotHandle: Clone, Send, Sync);
    }

    #[test]
    fn pilot_loop_pause_guard_is_move_only() {
        static_assertions::assert_not_impl_any!(PilotLoopPauseGuard: Clone, Copy);
        static_assertions::assert_impl_all!(PilotLoopPauseGuard: Send, Sync);
    }

    #[tokio::test]
    async fn pilot_loop_test_pause_waits_for_acknowledged_zero_in_flight_drain() {
        let control = PilotLoopControl::new();
        control.set_in_flight(1);
        let pause = tokio::spawn(pause_pilot_loop_control_for_test(control.clone()));

        tokio::task::yield_now().await;
        assert!(*control.paused.borrow());
        assert!(!pause.is_finished());

        control.mark_paused();
        tokio::task::yield_now().await;
        assert!(!pause.is_finished());

        control.set_in_flight(0);
        let drained = pause.await.expect("pause task");
        assert!(control.drain.borrow().paused);
        assert_eq!(control.drain.borrow().in_flight, 0);

        drained.resume();
        assert!(!*control.paused.borrow());
        assert!(!control.drain.borrow().paused);
    }

    #[tokio::test]
    async fn cancelled_pilot_loop_test_pause_restores_admission() {
        let control = PilotLoopControl::new();
        control.set_in_flight(1);
        let pause = tokio::spawn(pause_pilot_loop_control_for_test(control.clone()));

        tokio::task::yield_now().await;
        assert!(*control.paused.borrow());
        pause.abort();
        assert!(matches!(pause.await, Err(error) if error.is_cancelled()));

        assert!(!*control.paused.borrow());
        assert!(!control.drain.borrow().paused);
    }

    #[tokio::test]
    async fn dropped_pilot_loop_pause_guard_restores_admission() {
        let control = PilotLoopControl::new();
        let pause = tokio::spawn(pause_pilot_loop_control_for_test(control.clone()));

        tokio::task::yield_now().await;
        control.mark_paused();
        let drained = pause.await.expect("pause task");
        assert!(*control.paused.borrow());

        drop(drained);
        assert!(!*control.paused.borrow());
        assert!(!control.drain.borrow().paused);
    }

    #[test]
    fn holder_identity_is_canonical_and_reconciler_is_not_caller_selected() {
        assert!(valid_holder_identity("deviceidentity-pilot-1"));
        assert!(!valid_holder_identity(""));
        assert!(!valid_holder_identity(" pilot "));
        assert_eq!(
            DEVICE_CERTIFICATE_RECONCILER_ID,
            "identity.device-certificate"
        );
    }

    #[tokio::test]
    async fn pause_drained_watch_closes_on_resume_and_stops_terminally() {
        let control = PilotLoopControl::new();
        let mut drained = control.drained_changes();
        assert!(!*drained.borrow());
        control.set_in_flight(1);
        control.pause();
        assert_eq!(control.readiness(), PilotComponentReadiness::Unready);
        control.mark_paused();
        assert!(!control.drain.borrow().is_drained());
        control.set_in_flight(0);
        drained.changed().await.expect("drain observation");
        assert!(*drained.borrow());
        control.resume();
        control.mark_ready();
        assert_eq!(control.readiness(), PilotComponentReadiness::Ready);
        drained.changed().await.expect("resume observation");
        assert!(!*drained.borrow());
        control.mark_stopped();
        drained.changed().await.expect("stop observation");
        assert!(*drained.borrow());
        control.resume();
        assert!(control.drain.borrow().is_drained());
    }

    #[test]
    fn transport_shutdown_latch_preserves_every_closed_kind() {
        for kind in [
            diport::ShutdownErrorKind::Operation,
            diport::ShutdownErrorKind::TaskPanicked,
            diport::ShutdownErrorKind::TaskCancelled,
            diport::ShutdownErrorKind::TaskUnknown,
            diport::ShutdownErrorKind::DeadlineExceeded,
        ] {
            let latch = PilotShutdownFailureLatch::new();
            latch.record(kind);
            assert_eq!(latch.load(), Some(kind));
            assert_eq!(latched_transport_shutdown_error(kind).kind(), kind);
        }
    }

    #[test]
    fn simulator_is_statically_draft_only() {
        fn require_draft<S: CertificateArtifactSource<Eligibility = DraftEligibility>>() {}
        require_draft::<DraftArtifactSimulator>();
        assert_eq!(
            format!(
                "{:?}",
                DraftArtifactSimulator::new(
                    [7; 32],
                    CertNotAfter::try_from_system_time(
                        std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(4_102_444_800),
                    )
                    .expect("not-after"),
                )
            ),
            "DraftArtifactSimulator(<redacted-seed>)"
        );
    }

    #[test]
    fn canonical_bundle_is_send_sync_and_has_one_exact_start_signature() {
        static_assertions::assert_impl_all!(DraftArtifactSimulator: Send, Sync);
        static_assertions::assert_impl_all!(DeviceIdentityPilot: Send, Sync);

        fn start(
            postgres: PgDeviceIdentityDraftRuntime,
            simulator: DraftArtifactSimulator,
            mqtt: Arc<MqttSession>,
            config: DeviceIdentityPilotConfig,
        ) -> Result<DeviceIdentityPilot, DeviceIdentityPilotStartError> {
            DeviceIdentityPilot::start(postgres, simulator, mqtt, config)
        }
        let _ = start;
    }
}
