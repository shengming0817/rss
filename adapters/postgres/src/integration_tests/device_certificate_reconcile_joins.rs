//! Real PostgreSQL / reconcile-worker join hazards for device-certificate seams.
//!
//! These two T2 proofs own cross-worker and crash-boundary joins that Hard lease/epoch/artifact
//! fences cannot statically close. Helpers stay private to this module.
//!
//! ref: kube-rs/kube kube-runtime/src/controller/mod.rs@main

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use consistency::ConvergeAction;
use diport::ManagedResource as _;
use diport::{CertNotAfter, CertScope, CertSerial};
use eventexec::command::CommandIdempotencyKeyring;
use eventexec::reconcile::DeviceCertificateCommandEvidence;
use eventexec::reconcile::{
    AttemptResult, DeviceCertificateCommandTtl, DeviceCertificateSystemProducer,
    ReconcileScheduleStore, ReconcileSchedulerBuilder, ReviewedFencedCommand,
    ScheduleActionOutcome, ScheduleAttemptOutcome, ScheduleCompletionOutcome, ScheduleLeaseOutcome,
    ScheduleResultOutcome, Tenancy, Trigger,
};
use identity::ports::device_certificate::{
    ArtifactAppendAuthorization, ArtifactAppendOutcome, ArtifactDigest,
    AuthorizedCertificateArtifact, CertificateArtifactAcquisition, CertificateArtifactError,
    CertificateArtifactId, CertificateArtifactRequest, CertificateArtifactSource,
    CertificateAttemptAuthority, CertificateAttemptFence, CertificateConditionMutation,
    CertificatePublicKeyDigest, CertificateReconcileRepository,
    CertificateReconcileRepositoryError, CertificateReconcileView, DeletionRequestOutcome,
    DeviceCertificateReconciler, FencedMutationOutcome, PersistedCertificateArtifactSnapshot,
    ProductionEligibility, ProviderCertificateCandidate, ReportedStateHash, RotationOutcome,
};
use sha2::{Digest as _, Sha256};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::{
    AttemptTrigger, ReconcileAttempt, ReconcileTargetKey, TestError, TestResult, command_keyring,
    connect_pg, insert_device_desired, integration_tenant_scope, reconcile_limit,
};
use crate::PgStore;
use crate::cotx::test_proof::DeviceCertificateJoinObservation;
use crate::cotx::{ServingReadLane, ServingWriteLane, TenantDb};
use crate::device_certificate::PgDeviceCertificateRepository;
use crate::reconcile::PgReconcileStore;

const RECONCILER_ID: &str = "identity.device-certificate";
const RESOURCE_KIND: &str = "device-certificate";
const GATE_BUDGET: Duration = Duration::from_secs(10);
const WORKER_BUDGET: Duration = Duration::from_secs(15);
const POLL_BUDGET: Duration = Duration::from_secs(10);
/// Worker lease TTL must dwarf GATE/POLL/WORKER budgets so a natural renew tick
/// (`lease_ttl / 3`) cannot race the SQL expiry → new-holder claim window.
const WORKER_LEASE_TTL: Duration = Duration::from_secs(300);

/// Stateful one-shot pause gate with loss-proof release and entered/released anti-vacuity.
///
/// `released` means the releaser has already stored the release bit (not merely that a waiter
/// woke). Waiters always check state → subscribe → re-check before awaiting, so a release that
/// lands before `notified()` is registered still unblocks.
struct PauseGate {
    entered: AtomicBool,
    released: AtomicBool,
    entered_notify: Notify,
    release_notify: Notify,
}

impl PauseGate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            entered: AtomicBool::new(false),
            released: AtomicBool::new(false),
            entered_notify: Notify::new(),
            release_notify: Notify::new(),
        })
    }

    fn entered(&self) -> bool {
        self.entered.load(Ordering::SeqCst)
    }

    fn released(&self) -> bool {
        self.released.load(Ordering::SeqCst)
    }

    async fn wait_entered(&self) -> TestResult {
        loop {
            if self.entered() {
                return Ok(());
            }
            let notified = self.entered_notify.notified();
            if self.entered() {
                return Ok(());
            }
            tokio::time::timeout(GATE_BUDGET, notified)
                .await
                .map_err(|_| "pause gate did not enter within budget")?;
        }
    }

    fn release(&self) {
        self.released.store(true, Ordering::SeqCst);
        self.release_notify.notify_waiters();
    }

    async fn pause_until_released(&self) {
        self.entered.store(true, Ordering::SeqCst);
        self.entered_notify.notify_waiters();
        loop {
            if self.released() {
                return;
            }
            let notified = self.release_notify.notified();
            if self.released() {
                return;
            }
            notified.await;
        }
    }
}

// reason: this join hazard does not exercise revocation; revocation coverage stays with existing owners.
struct AlwaysUnrevoked;

impl diport::RevocationStore for AlwaysUnrevoked {
    async fn revoke(
        &self,
        _serial: CertSerial,
        _scope: CertScope,
        _not_after: CertNotAfter,
    ) -> Result<(), diport::RevocationStoreError> {
        Ok(())
    }

    async fn is_revoked(
        &self,
        _serial: CertSerial,
        _scope: CertScope,
    ) -> Result<bool, diport::RevocationStoreError> {
        Ok(false)
    }

    async fn shutdown(&self) -> Result<(), diport::RevocationStoreError> {
        Ok(())
    }
}

/// Far-future clock so command deadlines remain after PostgreSQL `queued_at`.
struct JoinClock;

impl diport::Clock for JoinClock {
    fn now(&self) -> std::time::SystemTime {
        std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(3_900_000_000)
    }
}

fn join_clock() -> Arc<dyn diport::Clock> {
    Arc::new(JoinClock)
}

fn mint_authorized(
    request: &CertificateArtifactAcquisition,
    artifact_id: &str,
    serial_tail: u8,
) -> Result<AuthorizedCertificateArtifact<ProductionEligibility>, CertificateArtifactError> {
    let material = format!("join-certificate-material:{artifact_id}").into_bytes();
    let artifact_digest = ArtifactDigest::restore(&Sha256::digest(&material))
        .map_err(|_| CertificateArtifactError::BindingMismatch)?;
    let public_key = CertificatePublicKeyDigest::restore(&[0x21_u8; 32])
        .map_err(|_| CertificateArtifactError::BindingMismatch)?;
    let state_hash = ReportedStateHash::restore(&[0x41_u8; 32])
        .map_err(|_| CertificateArtifactError::BindingMismatch)?;
    let artifact_id = CertificateArtifactId::parse(artifact_id)?;
    let cert_scope = CertScope::new(request.scope().tenant(), request.scope().device());
    let serial = CertSerial::try_new([0x19, serial_tail])
        .map_err(|_| CertificateArtifactError::BindingMismatch)?;
    let not_after = CertNotAfter::try_from_system_time(
        std::time::UNIX_EPOCH + Duration::from_secs(4_000_000_000),
    )
    .map_err(|_| CertificateArtifactError::BindingMismatch)?;
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
    )?;
    ProviderCertificateCandidate::new(
        material,
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

struct ImmediateArtifactSource {
    serial_tail: u8,
}

impl CertificateArtifactSource for ImmediateArtifactSource {
    type Eligibility = ProductionEligibility;

    async fn acquire(
        &self,
        request: CertificateArtifactAcquisition,
    ) -> Result<AuthorizedCertificateArtifact<ProductionEligibility>, CertificateArtifactError>
    {
        let artifact_id = format!(
            "join-artifact-immediate-{}",
            uuid::Uuid::new_v4().as_simple()
        );
        mint_authorized(&request, &artifact_id, self.serial_tail)
    }
}

struct GatedArtifactSource {
    gate: Arc<PauseGate>,
    serial_tail: u8,
}

impl CertificateArtifactSource for GatedArtifactSource {
    type Eligibility = ProductionEligibility;

    async fn acquire(
        &self,
        request: CertificateArtifactAcquisition,
    ) -> Result<AuthorizedCertificateArtifact<ProductionEligibility>, CertificateArtifactError>
    {
        let artifact_id = format!("join-artifact-gated-{}", uuid::Uuid::new_v4().as_simple());
        let authorized = mint_authorized(&request, &artifact_id, self.serial_tail)?;
        self.gate.pause_until_released().await;
        Ok(authorized)
    }
}

/// Counts stale-fence append outcomes so the lost path cannot pass vacuously.
struct ObservingRepository {
    inner: PgDeviceCertificateRepository<ProductionEligibility>,
    stale_fence: Arc<AtomicUsize>,
}

impl CertificateReconcileRepository<ProductionEligibility> for ObservingRepository {
    async fn load_current_view(
        &self,
        authority: &CertificateAttemptAuthority,
    ) -> Result<Option<CertificateReconcileView>, CertificateReconcileRepositoryError> {
        self.inner.load_current_view(authority).await
    }

    async fn load_artifact_receipts(
        &self,
        fence: &CertificateAttemptFence,
    ) -> Result<
        Vec<PersistedCertificateArtifactSnapshot<ProductionEligibility>>,
        CertificateReconcileRepositoryError,
    > {
        self.inner.load_artifact_receipts(fence).await
    }

    async fn load_current_command_evidence(
        &self,
        fence: &CertificateAttemptFence,
    ) -> Result<Option<DeviceCertificateCommandEvidence>, CertificateReconcileRepositoryError> {
        self.inner.load_current_command_evidence(fence).await
    }

    async fn append_artifact_receipt(
        &self,
        fence: &CertificateAttemptFence,
        authorization: ArtifactAppendAuthorization<ProductionEligibility>,
    ) -> Result<ArtifactAppendOutcome, CertificateReconcileRepositoryError> {
        let outcome = self
            .inner
            .append_artifact_receipt(fence, authorization)
            .await?;
        if matches!(outcome, ArtifactAppendOutcome::StaleFence) {
            self.stale_fence.fetch_add(1, Ordering::SeqCst);
        }
        Ok(outcome)
    }

    async fn write_conditions(
        &self,
        fence: &CertificateAttemptFence,
        conditions: CertificateConditionMutation,
    ) -> Result<FencedMutationOutcome, CertificateReconcileRepositoryError> {
        self.inner.write_conditions(fence, conditions).await
    }

    async fn rotate_generation(
        &self,
        fence: &CertificateAttemptFence,
    ) -> Result<RotationOutcome, CertificateReconcileRepositoryError> {
        self.inner.rotate_generation(fence).await
    }

    async fn request_deletion(
        &self,
        fence: &CertificateAttemptFence,
    ) -> Result<DeletionRequestOutcome, CertificateReconcileRepositoryError> {
        self.inner.request_deletion(fence).await
    }
}

/// Test-only decorator: pauses only after the four command writes already committed.
struct PostCommitPauseStore {
    inner: PgReconcileStore,
    gate: Arc<PauseGate>,
}

impl ReconcileScheduleStore for PostCommitPauseStore {
    async fn claim_due_targets(
        &self,
        tenant: vocab::TenantId,
        reconciler_id: &str,
        holder_id: &str,
        limit: eventexec::ReconcileMaxInFlight,
        lease_ttl: Duration,
    ) -> Result<
        Vec<eventexec::reconcile::ClaimedTarget>,
        eventexec::reconcile::ReconcileScheduleError,
    > {
        ReconcileScheduleStore::claim_due_targets(
            &self.inner,
            tenant,
            reconciler_id,
            holder_id,
            limit,
            lease_ttl,
        )
        .await
    }

    async fn claim_targeted(
        &self,
        tenant: vocab::TenantId,
        reconciler_id: &str,
        holder_id: &str,
        wake: &eventexec::reconcile::ReconcileWake,
        lease_ttl: Duration,
    ) -> Result<
        Option<eventexec::reconcile::ClaimedTarget>,
        eventexec::reconcile::ReconcileScheduleError,
    > {
        ReconcileScheduleStore::claim_targeted(
            &self.inner,
            tenant,
            reconciler_id,
            holder_id,
            wake,
            lease_ttl,
        )
        .await
    }

    async fn append_attempt(
        &self,
        target: &eventexec::reconcile::ClaimedTarget,
        holder_id: &str,
    ) -> Result<ScheduleAttemptOutcome, eventexec::reconcile::ReconcileScheduleError> {
        ReconcileScheduleStore::append_attempt(&self.inner, target, holder_id).await
    }

    async fn record_attempt_result(
        &self,
        attempt: &ReconcileAttempt,
        result: AttemptResult,
    ) -> Result<ScheduleResultOutcome, eventexec::reconcile::ReconcileScheduleError> {
        ReconcileScheduleStore::record_attempt_result(&self.inner, attempt, result).await
    }

    async fn record_fenced_command(
        &self,
        attempt: &ReconcileAttempt,
        action: ConvergeAction,
        command: ReviewedFencedCommand,
    ) -> Result<ScheduleActionOutcome, eventexec::reconcile::ReconcileScheduleError> {
        let outcome =
            ReconcileScheduleStore::record_fenced_command(&self.inner, attempt, action, command)
                .await?;
        if matches!(outcome, ScheduleActionOutcome::Enqueued) {
            self.gate.pause_until_released().await;
        }
        Ok(outcome)
    }

    async fn complete_device_certificate_deletion(
        &self,
        attempt: &ReconcileAttempt,
    ) -> Result<ScheduleCompletionOutcome, eventexec::reconcile::ReconcileScheduleError> {
        ReconcileScheduleStore::complete_device_certificate_deletion(&self.inner, attempt).await
    }

    async fn extend_lease(
        &self,
        target: &eventexec::reconcile::ClaimedTarget,
        lease_ttl: Duration,
    ) -> Result<ScheduleLeaseOutcome, eventexec::reconcile::ReconcileScheduleError> {
        ReconcileScheduleStore::extend_lease(&self.inner, target, lease_ttl).await
    }

    async fn release_lease(
        &self,
        target: &eventexec::reconcile::ClaimedTarget,
    ) -> Result<ScheduleLeaseOutcome, eventexec::reconcile::ReconcileScheduleError> {
        ReconcileScheduleStore::release_lease(&self.inner, target).await
    }

    async fn pause_target(
        &self,
        tenant: vocab::TenantId,
        target_id: &str,
    ) -> Result<(), eventexec::reconcile::ReconcileScheduleError> {
        ReconcileScheduleStore::pause_target(&self.inner, tenant, target_id).await
    }

    async fn resume_target(
        &self,
        tenant: vocab::TenantId,
        target_id: &str,
    ) -> Result<(), eventexec::reconcile::ReconcileScheduleError> {
        ReconcileScheduleStore::resume_target(&self.inner, tenant, target_id).await
    }
}

fn command_ttl() -> Result<DeviceCertificateCommandTtl, TestError> {
    Ok(DeviceCertificateCommandTtl::try_new(Duration::from_secs(
        300,
    ))?)
}

fn build_worker<S, R>(
    store: S,
    reconciler: R,
    keyring: Arc<CommandIdempotencyKeyring>,
    tenant: vocab::TenantId,
    holder_id: &str,
) -> Result<eventexec::reconcile::ReconcileWorker<S, R>, TestError>
where
    S: ReconcileScheduleStore + Send + Sync + 'static,
    R: eventexec::reconcile::DurableReconciler<S> + Send + Sync + 'static,
{
    let trigger = Trigger::interval(Duration::from_millis(50))?;
    Ok(ReconcileSchedulerBuilder::new(
        store,
        reconciler,
        keyring,
        DeviceCertificateSystemProducer::install(),
        tenant,
        RECONCILER_ID,
        holder_id,
        Tenancy::tenant_scoped(),
        trigger,
    )
    .with_max_in_flight(reconcile_limit(1))
    // Renew interval is lease_ttl/3 (= 100s); keep it far above GATE/POLL budgets.
    .with_lease_ttl(WORKER_LEASE_TTL)?
    .build())
}

async fn expire_lease(store: &PgStore, tenant: vocab::TenantId, target_id: &str) -> TestResult {
    TenantDb::<ServingWriteLane>::from_unverified_for_test(store)
        .test_expire_reconcile_lease(integration_tenant_scope(tenant), target_id.to_owned())
        .await?;
    Ok(())
}

async fn lease_epoch(
    store: &PgStore,
    tenant: vocab::TenantId,
    target_id: &str,
) -> Result<i64, TestError> {
    let target = target_id.to_owned();
    let reader = TenantDb::<ServingReadLane>::from_unverified_for_test(store);
    Ok(reader
        .test_read(integration_tenant_scope(tenant), move |mut tx| {
            Box::pin(async move { tx.reconcile_lease_epoch(&target).await })
        })
        .await?)
}

async fn coordinate_snapshot(
    store: &PgStore,
    tenant: vocab::TenantId,
    device: &str,
    target_id: &str,
    generation: i64,
    epoch: i64,
) -> Result<DeviceCertificateJoinObservation, TestError> {
    let device = device.to_owned();
    let target = target_id.to_owned();
    let reader = TenantDb::<ServingReadLane>::from_unverified_for_test(store);
    Ok(reader
        .test_read(integration_tenant_scope(tenant), move |mut tx| {
            Box::pin(async move {
                tx.device_certificate_join_observation(&device, &target, generation, epoch)
                    .await
            })
        })
        .await?)
}

async fn wait_command_at_epoch(
    store: &PgStore,
    tenant: vocab::TenantId,
    device: &str,
    generation: i64,
    epoch: i64,
) -> TestResult {
    testkit::await_try(POLL_BUDGET, async || {
        let device = device.to_owned();
        let reader = TenantDb::<ServingReadLane>::from_unverified_for_test(store);
        let count = reader
            .test_read(integration_tenant_scope(tenant), move |mut tx| {
                Box::pin(async move {
                    tx.device_command_count_at_epoch(&device, generation, epoch)
                        .await
                })
            })
            .await?;
        Ok::<Option<()>, TestError>((count >= 1).then_some(()))
    })
    .await
    .map_err(|error| format!("current holder did not enqueue command at epoch {epoch}: {error}"))?;
    Ok(())
}

async fn attempt_count_for_trigger(
    store: &PgStore,
    tenant: vocab::TenantId,
    target_id: &str,
    trigger_kind: &str,
    epoch: i64,
) -> Result<i64, TestError> {
    let target = target_id.to_owned();
    let trigger = trigger_kind.to_owned();
    let reader = TenantDb::<ServingReadLane>::from_unverified_for_test(store);
    Ok(reader
        .test_read(integration_tenant_scope(tenant), move |mut tx| {
            Box::pin(async move {
                tx.reconcile_attempt_count_for_trigger(&target, &trigger, epoch)
                    .await
            })
        })
        .await?)
}

async fn command_count_at_epoch(
    store: &PgStore,
    tenant: vocab::TenantId,
    device: &str,
    generation: i64,
    epoch: i64,
) -> Result<i64, TestError> {
    let device = device.to_owned();
    let reader = TenantDb::<ServingReadLane>::from_unverified_for_test(store);
    Ok(reader
        .test_read(integration_tenant_scope(tenant), move |mut tx| {
            Box::pin(async move {
                tx.device_command_count_at_epoch(&device, generation, epoch)
                    .await
            })
        })
        .await?)
}

async fn wait_lease_epoch_gt(
    store: &PgStore,
    tenant: vocab::TenantId,
    target_id: &str,
    previous: i64,
) -> Result<i64, TestError> {
    testkit::await_try(POLL_BUDGET, async || {
        let epoch = lease_epoch(store, tenant, target_id).await?;
        Ok::<Option<i64>, TestError>((epoch > previous).then_some(epoch))
    })
    .await
    .map_err(|error| format!("lease epoch did not advance past {previous}: {error}").into())
}

async fn stop_worker(cancel: CancellationToken, join: JoinHandle<()>) -> TestResult {
    cancel.cancel();
    tokio::time::timeout(WORKER_BUDGET, join)
        .await
        .map_err(|_| "worker did not stop within budget")?
        .map_err(|error| format!("worker join failed: {error}"))?;
    Ok(())
}

async fn prepare_target(store: &PgStore) -> Result<(vocab::TenantId, String, String), TestError> {
    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let device = uuid::Uuid::new_v4().to_string();
    insert_device_desired(store, tenant, &device).await?;
    let key = ReconcileTargetKey::parse(RECONCILER_ID, RESOURCE_KIND, &device)?;
    let target = store.reconcile().upsert_target(tenant, &key).await?;
    Ok((tenant, device, target.target_id().to_owned()))
}

#[tokio::test(flavor = "multi_thread")]
async fn authorized_artifact_return_loses_to_lease_takeover_without_stale_command() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let (tenant, device, target_id) = prepare_target(&store).await?;
    let keyring = command_keyring();
    let ttl = command_ttl()?;
    let clock = join_clock();

    let acquire_gate = PauseGate::new();
    let stale_fence = Arc::new(AtomicUsize::new(0));
    let old_reconciler = DeviceCertificateReconciler::new(
        ObservingRepository {
            inner: PgDeviceCertificateRepository::from_unverified_for_test(&store),
            stale_fence: Arc::clone(&stale_fence),
        },
        Arc::new(GatedArtifactSource {
            gate: Arc::clone(&acquire_gate),
            serial_tail: 1,
        }),
        AlwaysUnrevoked,
        Arc::clone(&clock),
        ttl,
    );
    let old_cancel = CancellationToken::new();
    let old_worker = build_worker(
        store.reconcile(),
        old_reconciler,
        Arc::clone(&keyring),
        tenant,
        "holder-old",
    )?;
    let old_join = tokio::spawn(old_worker.run(old_cancel.child_token()));

    acquire_gate.wait_entered().await?;
    assert!(
        acquire_gate.entered() && !acquire_gate.released(),
        "old acquire must pause before return"
    );
    let old_epoch = lease_epoch(&store, tenant, &target_id).await?;

    expire_lease(&store, tenant, &target_id).await?;

    let new_reconciler = DeviceCertificateReconciler::new(
        PgDeviceCertificateRepository::<ProductionEligibility>::from_unverified_for_test(&store),
        Arc::new(ImmediateArtifactSource { serial_tail: 2 }),
        AlwaysUnrevoked,
        clock,
        ttl,
    );
    let new_cancel = CancellationToken::new();
    let new_worker = build_worker(
        store.reconcile(),
        new_reconciler,
        keyring,
        tenant,
        "holder-new",
    )?;
    let new_join = tokio::spawn(new_worker.run(new_cancel.child_token()));

    let new_epoch = wait_lease_epoch_gt(&store, tenant, &target_id, old_epoch).await?;
    wait_command_at_epoch(&store, tenant, &device, 1, new_epoch).await?;

    let reclaim_attempts = attempt_count_for_trigger(
        &store,
        tenant,
        &target_id,
        AttemptTrigger::LeaseReclaim.as_label(),
        new_epoch,
    )
    .await?;
    assert_eq!(
        reclaim_attempts, 1,
        "new holder must reclaim via LeaseReclaim with a strict epoch advance"
    );

    // Bound the current holder before releasing the stale return so the snapshot cannot race
    // with the new worker's own attempt-result append.
    stop_worker(new_cancel, new_join).await?;

    let before = coordinate_snapshot(&store, tenant, &device, &target_id, 1, new_epoch).await?;
    assert_eq!(
        before.artifacts, 1,
        "current holder must persist one artifact"
    );
    assert_eq!(
        before.device_commands, 1,
        "current holder must emit one command"
    );
    assert_eq!(before.journal, 1);
    assert_eq!(before.actions, 1);
    assert_eq!(before.outbox, 1);

    acquire_gate.release();
    testkit::await_try(POLL_BUDGET, async || {
        Ok::<Option<()>, TestError>(
            (acquire_gate.released() && stale_fence.load(Ordering::SeqCst) >= 1).then_some(()),
        )
    })
    .await
    .map_err(|error| {
        format!("stale/lost artifact return path did not execute (anti-vacuity): {error}")
    })?;
    assert!(
        acquire_gate.released(),
        "old artifact return must leave the gate"
    );
    assert!(
        stale_fence.load(Ordering::SeqCst) >= 1,
        "old return must hit the real StaleFence path"
    );

    let after = coordinate_snapshot(&store, tenant, &device, &target_id, 1, new_epoch).await?;
    assert_eq!(
        after, before,
        "stale authorized artifact return must be zero-write against the current snapshot"
    );
    let old_epoch_commands = command_count_at_epoch(&store, tenant, &device, 1, old_epoch).await?;
    assert_eq!(
        old_epoch_commands, 0,
        "stale return must not append a command under the lost epoch"
    );

    stop_worker(old_cancel, old_join).await?;
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn expire_reconcile_lease_rejects_missing_row() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let missing_target = uuid::Uuid::new_v4().to_string();

    let expire = TenantDb::<ServingWriteLane>::from_unverified_for_test(&store)
        .test_expire_reconcile_lease(integration_tenant_scope(tenant), missing_target)
        .await;
    match expire {
        Err(sqlx::Error::RowNotFound) => {}
        Ok(()) => return Err("missing reconcile lease must not report success".into()),
        Err(other) => {
            return Err(format!(
                "missing lease must surface sqlx::Error::RowNotFound, got {other:?}"
            )
            .into());
        }
    }

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn postcommit_worker_crash_reclaim_keeps_command_singular_and_exposes_interrupted_attempt()
-> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let (tenant, device, target_id) = prepare_target(&store).await?;
    let keyring = command_keyring();
    let ttl = command_ttl()?;
    let clock = join_clock();
    let postcommit_gate = PauseGate::new();

    let crash_reconciler = DeviceCertificateReconciler::new(
        PgDeviceCertificateRepository::<ProductionEligibility>::from_unverified_for_test(&store),
        Arc::new(ImmediateArtifactSource { serial_tail: 3 }),
        AlwaysUnrevoked,
        Arc::clone(&clock),
        ttl,
    );
    let pause_store = PostCommitPauseStore {
        inner: store.reconcile(),
        gate: Arc::clone(&postcommit_gate),
    };
    let crash_cancel = CancellationToken::new();
    let crash_worker = build_worker(
        pause_store,
        crash_reconciler,
        Arc::clone(&keyring),
        tenant,
        "holder-crash",
    )?;
    let crash_join = tokio::spawn(crash_worker.run(crash_cancel.child_token()));
    // Intentionally keep crash_cancel alive but unused: abort must not clean-cancel.
    let _keep_cancel = crash_cancel;

    postcommit_gate.wait_entered().await?;
    assert!(
        postcommit_gate.entered() && !postcommit_gate.released(),
        "post-commit pause must enter after the four writes commit"
    );

    let crash_epoch = lease_epoch(&store, tenant, &target_id).await?;
    let before_crash =
        coordinate_snapshot(&store, tenant, &device, &target_id, 1, crash_epoch).await?;
    assert_eq!(before_crash.artifacts, 1);
    assert_eq!(before_crash.journal, 1);
    assert_eq!(before_crash.device_commands, 1);
    assert_eq!(before_crash.actions, 1);
    assert_eq!(before_crash.outbox, 1);
    assert_eq!(before_crash.attempts_at_epoch, 1);
    assert_eq!(
        before_crash.results_at_epoch, 0,
        "interrupted attempt must exist without an attempt_result"
    );

    // Simulate process crash: abort the task; never cancel/release through the clean path.
    // ref: kube-rs/kube kube-runtime/src/controller/mod.rs@main forceful shutdown.
    crash_join.abort();
    let aborted = crash_join.await;
    let Err(join_error) = aborted else {
        return Err("crash simulation must abort the worker task".into());
    };
    assert!(
        join_error.is_cancelled(),
        "abort must surface JoinError::cancelled, not a test-implementation panic: {join_error}"
    );
    assert!(
        !postcommit_gate.released(),
        "crash must not release the post-commit gate via clean shutdown"
    );

    let before_reclaim =
        coordinate_snapshot(&store, tenant, &device, &target_id, 1, crash_epoch).await?;
    assert_eq!(before_reclaim, before_crash);

    expire_lease(&store, tenant, &target_id).await?;

    let reclaim_reconciler = DeviceCertificateReconciler::new(
        PgDeviceCertificateRepository::<ProductionEligibility>::from_unverified_for_test(&store),
        Arc::new(ImmediateArtifactSource { serial_tail: 4 }),
        AlwaysUnrevoked,
        clock,
        ttl,
    );
    let reclaim_cancel = CancellationToken::new();
    let reclaim_worker = build_worker(
        store.reconcile(),
        reclaim_reconciler,
        keyring,
        tenant,
        "holder-reclaim",
    )?;
    let reclaim_join = tokio::spawn(reclaim_worker.run(reclaim_cancel.child_token()));

    let reclaim_epoch = wait_lease_epoch_gt(&store, tenant, &target_id, crash_epoch).await?;
    testkit::await_try(POLL_BUDGET, async || {
        let attempts = attempt_count_for_trigger(
            &store,
            tenant,
            &target_id,
            AttemptTrigger::LeaseReclaim.as_label(),
            reclaim_epoch,
        )
        .await?;
        let snap =
            coordinate_snapshot(&store, tenant, &device, &target_id, 1, reclaim_epoch).await?;
        Ok::<Option<()>, TestError>((attempts == 1 && snap.results_at_epoch == 1).then_some(()))
    })
    .await
    .map_err(|error| {
        format!(
            "reclaim worker did not finish one LeaseReclaim attempt with a terminal result: {error}"
        )
    })?;

    // Bound reclaim before asserting so a later requeue cannot race the snapshot.
    // ref: kube-rs/kube kube-runtime/src/controller/mod.rs@main graceful shutdown.
    stop_worker(reclaim_cancel, reclaim_join).await?;

    let after_crash_epoch =
        coordinate_snapshot(&store, tenant, &device, &target_id, 1, crash_epoch).await?;
    assert_eq!(
        after_crash_epoch, before_crash,
        "reclaim must not duplicate the committed crash-epoch write set"
    );
    assert_eq!(
        after_crash_epoch.results_at_epoch, 0,
        "interrupted crash-epoch attempt remains result-less after reclaim"
    );

    let reclaim_attempt_count = attempt_count_for_trigger(
        &store,
        tenant,
        &target_id,
        AttemptTrigger::LeaseReclaim.as_label(),
        reclaim_epoch,
    )
    .await?;
    assert_eq!(
        reclaim_attempt_count, 1,
        "reclaim epoch must expose exactly one LeaseReclaim attempt"
    );
    let reclaim_snap =
        coordinate_snapshot(&store, tenant, &device, &target_id, 1, reclaim_epoch).await?;
    assert_eq!(
        reclaim_snap.attempts_at_epoch, 1,
        "reclaim epoch must keep a singular attempt row"
    );
    assert_eq!(
        reclaim_snap.results_at_epoch, 1,
        "reclaim epoch must expose a terminal attempt result"
    );
    // New-epoch command and supersede behavior remains owned by #1900; this proof only requires
    // real-worker reclaim completion plus the unchanged crash-epoch write set above.

    store.shutdown().await?;
    Ok(())
}
