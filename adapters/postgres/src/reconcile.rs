//! Postgres durable reconcile schema adapter (#1629).
//!
//! This module intentionally exposes only a narrow target/lease/attempt/action store. It does not
//! wire a runtime worker or define a new engine/domain trait. All tenant-table access goes through
//! distinct typed read/write pools, so `SET LOCAL rss.tenant_id` remains the single RLS funnel.
//!
//! ref: kube-rs kube-runtime/src/controller/mod.rs@b60b81c88d37ab1f1f0d1ff7d42ab0ca268b4221
//! ref: apalis-postgres migrations/20220530084123_jobs_workers.sql@5a930218b6b4128fc4c9e191cecc7cd0e1cbbbed

use std::sync::Arc;
use std::time::{Duration, SystemTime};

#[cfg(all(test, feature = "integration"))]
use crate::PgStore;
use crate::cotx::reconcile::{
    DeviceCertificateDeletionDb, ReconcileAttemptDb, ReconcileAttemptResultDb, ReconcileClaimedRow,
    ReconcileEnqueue, ReconcileLeaseFence, ReconcileLeaseMutation, ReconcileResultTransition,
    ReconcileTargetTransition, ReconcileTargetTransitionKind,
};
use crate::cotx::{
    MaintenanceReadLane, MaintenanceWriteLane, ServingWriteLane, TenantDb, TenantScopeHandle,
};
use crate::outbox::{OutboxEnvelope, metadata_with_ambient, unix_secs};
use crate::pool::{VerifiedPgMaintenanceStore, VerifiedPgWriteStore};
use diport::{Clock, RedactedSource};
use eventexec::reconcile::{
    AttemptErrorKind, AttemptResult, AttemptSchedule, AttemptTrigger, ClaimedTarget,
    ClaimedTargetRestore, DeviceCertificateCommandEvidence, FailureStreak,
    OperatorReconcileCapability, ReconcileAttempt, ReconcileMaxInFlight, ReconcileOperatorStore,
    ReconcileQuarantineReason, ReconcileScheduleError, ReconcileScheduleStore,
    ReconcileTargetStatus, ReconcileTargetSummary, ReconcileWake, ReviewedFencedCommand,
    ScheduleActionOutcome, ScheduleAttemptOutcome, ScheduleCompletionOutcome, ScheduleLeaseOutcome,
    ScheduleResultOutcome, WakeVersion,
};

/// Reconcile-private tenant authority. Keeping construction in this module prevents the generic
/// infrastructure scope from becoming an ambient escape hatch for repository code.
#[derive(Clone, Copy)]
struct ReconcileTenantScope {
    tenant: vocab::TenantId,
    _seal: (),
}

impl ReconcileTenantScope {
    fn new(tenant: vocab::TenantId) -> Self {
        Self { tenant, _seal: () }
    }
}

impl TenantScopeHandle for ReconcileTenantScope {
    fn tenant(self) -> vocab::TenantId {
        self.tenant
    }
}

fn reconcile_tenant_scope(tenant: vocab::TenantId) -> ReconcileTenantScope {
    ReconcileTenantScope::new(tenant)
}

/// Reconcile target identity under one tenant.
#[cfg(any(
    all(test, feature = "integration"),
    feature = "fault-matrix-test-support"
))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReconcileTargetKey {
    reconciler_id: String,
    resource_kind: String,
    resource_id: String,
}

#[cfg(any(
    all(test, feature = "integration"),
    feature = "fault-matrix-test-support"
))]
impl ReconcileTargetKey {
    /// Build a validated reconcile target key.
    pub(crate) fn parse(
        reconciler_id: impl Into<String>,
        resource_kind: impl Into<String>,
        resource_id: impl Into<String>,
    ) -> Result<Self, ReconcileKeyError> {
        let reconciler_id = validate_component(
            "reconciler_id",
            reconciler_id.into(),
            RECONCILE_ID_MAX_BYTES,
        )?;
        let resource_kind = validate_component(
            "resource_kind",
            resource_kind.into(),
            RECONCILE_ID_MAX_BYTES,
        )?;
        let resource_id =
            validate_component("resource_id", resource_id.into(), RESOURCE_ID_MAX_BYTES)?;
        Ok(Self {
            reconciler_id,
            resource_kind,
            resource_id,
        })
    }

    /// Reconciler namespace.
    pub(crate) fn reconciler_id(&self) -> &str {
        &self.reconciler_id
    }

    /// Resource kind within this reconciler.
    pub(crate) fn resource_kind(&self) -> &str {
        &self.resource_kind
    }

    /// Opaque resource id within this reconciler.
    pub(crate) fn resource_id(&self) -> &str {
        &self.resource_id
    }
}

/// Reconcile key parse error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub(crate) enum ReconcileKeyError {
    /// Component was empty.
    #[error("{component} is empty")]
    Empty { component: &'static str },
    /// Component was blank or contained control characters.
    #[error("{component} is blank or contains control characters")]
    NotCanonical { component: &'static str },
    /// Component exceeded the DB-bound byte limit.
    #[error("{component} exceeds max bytes")]
    TooLong { component: &'static str },
}

/// Durable target row created or found by [`PgReconcileStore::upsert_target`].
#[cfg(any(
    all(test, feature = "integration"),
    feature = "fault-matrix-test-support"
))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReconcileTarget {
    target_id: String,
}

#[cfg(any(
    all(test, feature = "integration"),
    feature = "fault-matrix-test-support"
))]
impl ReconcileTarget {
    /// DB target id as canonical UUID text.
    pub(crate) fn target_id(&self) -> &str {
        &self.target_id
    }
}

/// Lease CAS result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReconcileLeaseOutcome {
    /// Lease token and epoch still matched.
    Held,
    /// Lease token or epoch no longer matched.
    Lost,
}

/// Acquired reconcile lease.
#[cfg(any(
    all(test, feature = "integration"),
    feature = "fault-matrix-test-support"
))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReconcileLease {
    target_id: String,
    lease_token: String,
    epoch: u64,
}

#[cfg(any(
    all(test, feature = "integration"),
    feature = "fault-matrix-test-support"
))]
impl ReconcileLease {
    /// Target this lease protects.
    #[cfg(feature = "fault-matrix-test-support")]
    pub(crate) fn target_id(&self) -> &str {
        &self.target_id
    }

    /// Opaque lease token as UUID text.
    pub(crate) fn lease_token(&self) -> &str {
        &self.lease_token
    }

    /// Monotonic target-local epoch.
    pub(crate) fn epoch(&self) -> u64 {
        self.epoch
    }
}

/// Trigger reason for a reconcile attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReconcileAttemptTrigger {
    /// Periodic resync pulse.
    Resync,
    /// Targeted event dispatch.
    Targeted,
    /// Requeue requested by prior outcome.
    Requeue,
    /// Stale lease was reclaimed.
    LeaseReclaim,
}

impl ReconcileAttemptTrigger {
    pub(crate) fn as_label(self) -> &'static str {
        match self {
            Self::Resync => "resync",
            Self::Targeted => "targeted",
            Self::Requeue => "requeue",
            Self::LeaseReclaim => "lease_reclaim",
        }
    }
}

/// Append-only attempt insert request.
#[derive(Debug, Clone)]
pub(crate) struct ReconcileAttemptInsert<'a> {
    /// Target id as UUID text.
    pub target_id: &'a str,
    /// Lease token as UUID text.
    pub lease_token: &'a str,
    /// Lease epoch.
    pub epoch: u64,
    /// Holder id.
    pub holder_id: &'a str,
    /// Trigger reason.
    pub trigger: ReconcileAttemptTrigger,
    /// Durable retry streak captured by the claim.
    pub claimed_failure_streak: FailureStreak,
    /// Durable wake version captured by the claim.
    pub claimed_wake_version: WakeVersion,
}

/// Append-only attempt result insert request.
#[derive(Debug, Clone)]
pub(crate) struct ReconcileAttemptResultInsert<'a> {
    /// Attempt id as UUID text.
    pub attempt_id: &'a str,
    /// Target id as UUID text.
    pub target_id: &'a str,
    /// Reconcile result label.
    pub result: consistency::ReconcileResultLabel,
    /// Optional requeue delay.
    pub requeue_after: Option<Duration>,
    /// Optional error kind label.
    pub error_kind: Option<ReconcileActionErrorKind>,
    /// Target transition requested by this terminal result.
    pub schedule: AttemptSchedule,
}

/// Error kind recorded on an action result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReconcileActionErrorKind {
    /// Transient error.
    Transient,
    /// Permanent error.
    Permanent,
    /// Invariant error.
    Invariant,
}

impl ReconcileActionErrorKind {
    pub(crate) fn as_label(self) -> &'static str {
        match self {
            Self::Transient => "transient",
            Self::Permanent => "permanent",
            Self::Invariant => "invariant",
        }
    }
}

/// Append-only insert result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReconcileLedgerId {
    id: String,
}

impl ReconcileLedgerId {
    /// UUID id as canonical text.
    pub(crate) fn id(&self) -> &str {
        &self.id
    }
}

/// Postgres reconcile target/lease/attempt/action store.
///
/// Private field is the tenant-scoped pool wrapper; callers cannot bypass RLS setup through this
/// store.
pub struct PgReconcileStore {
    write: TenantDb<ServingWriteLane>,
    clock: Arc<dyn Clock>,
    #[cfg(all(test, feature = "integration"))]
    command_write_fault: Option<ReconcileCommandWriteFault>,
}

#[cfg(all(test, feature = "integration"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReconcileCommandWriteFault {
    Journal,
    DeviceCommand,
    Action,
    Outbox,
}

/// Maintenance-only reconcile operator store.
///
/// This concrete type cannot implement scheduler operations and therefore cannot acquire leases,
/// append attempts, or enqueue commands through the serving write lane.
pub struct PgMaintenanceReconcileStore {
    read: TenantDb<MaintenanceReadLane>,
    write: TenantDb<MaintenanceWriteLane>,
}

struct PgReconcileSystemClock;

impl Clock for PgReconcileSystemClock {
    fn now(&self) -> SystemTime {
        // reason: postgres reconcile outbox producer production clock; adapter-owned Clock impl is a sanctioned system-time boundary.
        #[allow(clippy::disallowed_methods)]
        SystemTime::now()
    }
}

#[cfg(all(test, feature = "integration"))]
impl PgStore {
    /// Construct the reconcile store from the shared pool.
    pub(crate) fn reconcile(&self) -> PgReconcileStore {
        PgReconcileStore {
            write: TenantDb::<ServingWriteLane>::from_unverified_for_test(self),
            clock: Arc::new(PgReconcileSystemClock),
            command_write_fault: None,
        }
    }
}

impl PgReconcileStore {
    #[cfg(feature = "fault-matrix-test-support")]
    pub(crate) async fn seed_device_desired_for_fault_matrix(
        &self,
        tenant: vocab::TenantId,
        device_id: &str,
    ) -> Result<(), ReconcileScheduleError> {
        let device_id = device_id.to_owned();
        self.write
            .reconcile_write(
                reconcile_tenant_scope(tenant),
                move |mut tx| {
                    Box::pin(async move {
                        tx.reconcile_seed_device_desired_for_fault_matrix(&device_id)
                            .await
                            .map_err(ReconcileScheduleError::new)
                    })
                },
                ReconcileScheduleError::new,
            )
            .await
            .map_err(ReconcileScheduleError::new)
    }

    pub(crate) fn new(writer: &VerifiedPgWriteStore) -> Self {
        Self {
            write: TenantDb::<ServingWriteLane>::new(writer),
            clock: Arc::new(PgReconcileSystemClock),
            #[cfg(all(test, feature = "integration"))]
            command_write_fault: None,
        }
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn with_command_write_fault(mut self, fault: ReconcileCommandWriteFault) -> Self {
        self.command_write_fault = Some(fault);
        self
    }
}

impl PgMaintenanceReconcileStore {
    pub(crate) fn new(store: &VerifiedPgMaintenanceStore) -> Self {
        Self {
            read: TenantDb::<MaintenanceReadLane>::new_maintenance(store),
            write: TenantDb::<MaintenanceWriteLane>::new_maintenance(store),
        }
    }

    /// Read the durable, payload-free audit proof for one fenced device command.
    ///
    /// The single SQL funnel requires command, outbox, journal, attempt, action and canonical
    /// target links to agree. Missing, cross-tenant or spoofed evidence fails closed as absence.
    pub async fn read_device_command_audit_proof(
        &self,
        tenant: vocab::TenantId,
        command_id: &str,
    ) -> Result<Option<eventexec::reconcile::DeviceCommandAuditProof>, ReconcileScheduleError> {
        let command_id = command_id.to_owned();
        let row = self
            .read
            .reconcile_read(reconcile_tenant_scope(tenant), move |mut tx| {
                Box::pin(async move { tx.reconcile_read_device_command_audit(&command_id).await })
            })
            .await
            .map_err(ReconcileScheduleError::new)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let device_id =
            uuid::Uuid::parse_str(&row.device_id).map_err(ReconcileScheduleError::new)?;
        let intent_digest: [u8; 32] = row
            .intent_digest
            .try_into()
            .map_err(|_| ReconcileScheduleError::new(DeviceCommandAuditDigestLength))?;
        eventexec::reconcile::DeviceCommandAuditProof::restore_durable(
            tenant,
            device_id,
            row.generation,
            row.fence_epoch,
            intent_digest,
            row.attempt_id,
        )
        .map(Some)
        .map_err(ReconcileScheduleError::new)
    }
}

impl PgReconcileStore {
    /// Upsert a target and ensure its lease row exists.
    #[cfg(any(
        all(test, feature = "integration"),
        feature = "fault-matrix-test-support"
    ))]
    pub(crate) async fn upsert_target(
        &self,
        tenant: vocab::TenantId,
        key: &ReconcileTargetKey,
    ) -> Result<ReconcileTarget, ReconcileStoreError> {
        let fields = TargetFields::from_key(key);
        self.write
            .reconcile_write(
                reconcile_tenant_scope(tenant),
                move |mut tx| {
                    Box::pin(async move {
                        let target_id = tx
                            .reconcile_upsert_target(&fields)
                            .await
                            .map_err(ReconcileStoreError::new)?;

                        Ok(ReconcileTarget { target_id })
                    })
                },
                ReconcileStoreError::new,
            )
            .await
    }

    /// Acquire a free or expired lease. Returns `Ok(None)` when another holder still owns it.
    #[cfg(any(
        all(test, feature = "integration"),
        feature = "fault-matrix-test-support"
    ))]
    pub(crate) async fn acquire_lease(
        &self,
        tenant: vocab::TenantId,
        target_id: &str,
        holder_id: &str,
        ttl: Duration,
    ) -> Result<Option<ReconcileLease>, ReconcileStoreError> {
        validate_runtime_component("target_id", target_id, UUID_TEXT_MAX_BYTES)?;
        validate_runtime_component("holder_id", holder_id, HOLDER_ID_MAX_BYTES)?;
        let ttl_secs = duration_secs(ttl)?;
        let target_id = target_id.to_string();
        let holder_id = holder_id.to_string();

        self.write
            .reconcile_write(
                reconcile_tenant_scope(tenant),
                move |mut tx| {
                    let target_id = target_id.clone();
                    let holder_id = holder_id.clone();
                    Box::pin(async move {
                        let row = tx
                            .reconcile_acquire_lease(&target_id, &holder_id, ttl_secs)
                            .await
                            .map_err(ReconcileStoreError::new)?;

                        row.map(|row| lease_from_row((row.target_id, row.lease_token, row.epoch)))
                            .transpose()
                    })
                },
                ReconcileStoreError::new,
            )
            .await
    }

    /// Extend a held lease by token and epoch CAS.
    pub(crate) async fn extend_lease(
        &self,
        tenant: vocab::TenantId,
        target_id: &str,
        lease_token: &str,
        epoch: u64,
        ttl: Duration,
    ) -> Result<ReconcileLeaseOutcome, ReconcileStoreError> {
        let ttl_secs = duration_secs(ttl)?;
        let epoch = epoch_to_db(epoch)?;
        self.cas_lease(
            tenant,
            LeaseCasRequest {
                target_id,
                lease_token,
                epoch,
                operation: LeaseCasOperation::Extend { ttl_secs },
            },
        )
        .await
    }

    /// Release a held lease by token and epoch CAS.
    pub(crate) async fn release_lease(
        &self,
        tenant: vocab::TenantId,
        target_id: &str,
        lease_token: &str,
        epoch: u64,
    ) -> Result<ReconcileLeaseOutcome, ReconcileStoreError> {
        let epoch = epoch_to_db(epoch)?;
        self.cas_lease(
            tenant,
            LeaseCasRequest {
                target_id,
                lease_token,
                epoch,
                operation: LeaseCasOperation::Release,
            },
        )
        .await
    }

    /// Append one immutable attempt row.
    pub(crate) async fn append_attempt(
        &self,
        tenant: vocab::TenantId,
        attempt: ReconcileAttemptInsert<'_>,
    ) -> Result<Option<ReconcileLedgerId>, ReconcileStoreError> {
        validate_runtime_component("target_id", attempt.target_id, UUID_TEXT_MAX_BYTES)?;
        validate_runtime_component("lease_token", attempt.lease_token, UUID_TEXT_MAX_BYTES)?;
        validate_runtime_component("holder_id", attempt.holder_id, HOLDER_ID_MAX_BYTES)?;
        let target_id = attempt.target_id.to_string();
        let lease_token = attempt.lease_token.to_string();
        let epoch = epoch_to_db(attempt.epoch)?;
        let holder_id = attempt.holder_id.to_string();
        let trigger = attempt.trigger.as_label();

        self.write
            .reconcile_write(
                reconcile_tenant_scope(tenant),
                move |mut tx| {
                    Box::pin(async move {
                        tx.reconcile_append_attempt(ReconcileAttemptDb {
                            fence: ReconcileLeaseFence {
                                target_id: &target_id,
                                lease_token: &lease_token,
                                epoch,
                            },
                            holder_id: &holder_id,
                            trigger,
                            claimed_failure_streak: i64::from(attempt.claimed_failure_streak.get()),
                            claimed_wake_version: wake_version_to_db(attempt.claimed_wake_version)?,
                        })
                        .await
                        .map_err(ReconcileStoreError::new)
                        .map(|id| id.map(|id| ReconcileLedgerId { id }))
                    })
                },
                ReconcileStoreError::new,
            )
            .await
    }

    /// Append one immutable attempt result row and schedule the next target run under lease CAS.
    pub(crate) async fn append_attempt_result(
        &self,
        tenant: vocab::TenantId,
        lease_token: &str,
        epoch: u64,
        result: ReconcileAttemptResultInsert<'_>,
    ) -> Result<ScheduleResultOutcome, ReconcileStoreError> {
        validate_runtime_component("attempt_id", result.attempt_id, UUID_TEXT_MAX_BYTES)?;
        validate_runtime_component("target_id", result.target_id, UUID_TEXT_MAX_BYTES)?;
        validate_runtime_component("lease_token", lease_token, UUID_TEXT_MAX_BYTES)?;
        let requeue_after_ms = result.requeue_after.map(duration_millis).transpose()?;
        let attempt_id = result.attempt_id.to_string();
        let target_id = result.target_id.to_string();
        let lease_token = lease_token.to_string();
        let epoch = epoch_to_db(epoch)?;
        let result_label = result.result.as_label();
        let error_kind = result.error_kind.map(ReconcileActionErrorKind::as_label);
        let transition = match result.schedule {
            AttemptSchedule::After(delay) => ReconcileResultTransition::ScheduleAfter {
                delay_ms: duration_millis(delay)?,
                transient: result.error_kind == Some(ReconcileActionErrorKind::Transient),
            },
            AttemptSchedule::Quarantine(reason) => ReconcileResultTransition::Quarantine {
                reason: reason.as_label(),
            },
        };

        self.write
            .reconcile_write(
                reconcile_tenant_scope(tenant),
                move |mut tx| {
                    Box::pin(async move {
                        tx.reconcile_record_attempt_result(ReconcileAttemptResultDb {
                            attempt_id: &attempt_id,
                            fence: ReconcileLeaseFence {
                                target_id: &target_id,
                                lease_token: &lease_token,
                                epoch,
                            },
                            result_label,
                            requeue_after_ms,
                            error_kind,
                            transition,
                        })
                        .await
                        .map_err(ReconcileStoreError::new)
                    })
                },
                ReconcileStoreError::new,
            )
            .await
    }

    async fn cas_lease(
        &self,
        tenant: vocab::TenantId,
        request: LeaseCasRequest<'_>,
    ) -> Result<ReconcileLeaseOutcome, ReconcileStoreError> {
        validate_runtime_component("target_id", request.target_id, UUID_TEXT_MAX_BYTES)?;
        validate_runtime_component("lease_token", request.lease_token, UUID_TEXT_MAX_BYTES)?;
        let target_id = request.target_id.to_string();
        let lease_token = request.lease_token.to_string();
        self.write
            .reconcile_write(
                reconcile_tenant_scope(tenant),
                move |mut tx| {
                    Box::pin(async move {
                        let mutation = match request.operation {
                            LeaseCasOperation::Extend { ttl_secs } => {
                                ReconcileLeaseMutation::Extend { ttl_secs }
                            }
                            LeaseCasOperation::Release => ReconcileLeaseMutation::Release,
                        };
                        let held = tx
                            .reconcile_cas_lease(
                                ReconcileLeaseFence {
                                    target_id: &target_id,
                                    lease_token: &lease_token,
                                    epoch: request.epoch,
                                },
                                mutation,
                            )
                            .await
                            .map_err(ReconcileStoreError::new)?;

                        Ok(if held {
                            ReconcileLeaseOutcome::Held
                        } else {
                            ReconcileLeaseOutcome::Lost
                        })
                    })
                },
                ReconcileStoreError::new,
            )
            .await
    }

    /// Pause a target: future due scans skip disabled rows.
    pub(crate) async fn pause_target(
        &self,
        tenant: vocab::TenantId,
        target_id: &str,
    ) -> Result<(), ReconcileStoreError> {
        serving_update_target_status(
            &self.write,
            tenant,
            target_id,
            ReconcileTargetTransitionKind::ServingPause,
        )
        .await
    }

    /// Resume a target and make it immediately due.
    pub(crate) async fn resume_target(
        &self,
        tenant: vocab::TenantId,
        target_id: &str,
    ) -> Result<(), ReconcileStoreError> {
        serving_update_target_status(
            &self.write,
            tenant,
            target_id,
            ReconcileTargetTransitionKind::ServingResume,
        )
        .await
    }
}

impl ReconcileOperatorStore for PgMaintenanceReconcileStore {
    async fn inspect_target(
        &self,
        tenant: vocab::TenantId,
        target_id: &str,
        _capability: OperatorReconcileCapability,
    ) -> Result<ReconcileTargetSummary, ReconcileScheduleError> {
        maintenance_inspect_target(&self.read, tenant, target_id)
            .await
            .map_err(ReconcileScheduleError::new)
    }

    async fn resume_target(
        &self,
        tenant: vocab::TenantId,
        target_id: &str,
        _capability: OperatorReconcileCapability,
    ) -> Result<ReconcileTargetSummary, ReconcileScheduleError> {
        maintenance_update_target_status(
            &self.write,
            tenant,
            target_id,
            ReconcileTargetTransitionKind::MaintenanceFactConflictResume,
        )
        .await
        .map_err(ReconcileScheduleError::new)?;
        maintenance_inspect_target(&self.read, tenant, target_id)
            .await
            .map_err(ReconcileScheduleError::new)
    }
}

impl ReconcileScheduleStore for PgReconcileStore {
    async fn claim_due_targets(
        &self,
        tenant: vocab::TenantId,
        reconciler_id: &str,
        holder_id: &str,
        limit: ReconcileMaxInFlight,
        lease_ttl: Duration,
    ) -> Result<Vec<ClaimedTarget>, ReconcileScheduleError> {
        validate_runtime_component("reconciler_id", reconciler_id, RECONCILE_ID_MAX_BYTES)
            .map_err(ReconcileScheduleError::new)?;
        validate_runtime_component("holder_id", holder_id, HOLDER_ID_MAX_BYTES)
            .map_err(ReconcileScheduleError::new)?;
        let ttl_secs = duration_secs(lease_ttl).map_err(ReconcileScheduleError::new)?;
        let reconciler_id = reconciler_id.to_string();
        let holder_id = holder_id.to_string();
        let limit = i64::from(limit.get());
        self.write
            .reconcile_write(
                reconcile_tenant_scope(tenant),
                move |mut tx| {
                    Box::pin(async move {
                        let rows = tx
                            .reconcile_claim_due_targets(
                                &reconciler_id,
                                &holder_id,
                                ttl_secs,
                                limit,
                            )
                            .await
                            .map_err(ReconcileScheduleError::new)?;
                        rows.into_iter()
                            .map(|row| claimed_target_from_row(tenant, row))
                            .collect()
                    })
                },
                ReconcileScheduleError::new,
            )
            .await
    }

    async fn claim_targeted(
        &self,
        tenant: vocab::TenantId,
        reconciler_id: &str,
        holder_id: &str,
        wake: &ReconcileWake,
        lease_ttl: Duration,
    ) -> Result<Option<ClaimedTarget>, ReconcileScheduleError> {
        validate_runtime_component("reconciler_id", reconciler_id, RECONCILE_ID_MAX_BYTES)
            .map_err(ReconcileScheduleError::new)?;
        validate_runtime_component("holder_id", holder_id, HOLDER_ID_MAX_BYTES)
            .map_err(ReconcileScheduleError::new)?;
        validate_runtime_component("target_id", wake.target_id(), UUID_TEXT_MAX_BYTES)
            .map_err(ReconcileScheduleError::new)?;
        let ttl_secs = duration_secs(lease_ttl).map_err(ReconcileScheduleError::new)?;
        let wake_version =
            wake_version_to_db(wake.version()).map_err(ReconcileScheduleError::new)?;
        let reconciler_id = reconciler_id.to_string();
        let holder_id = holder_id.to_string();
        let target_id = wake.target_id().to_string();
        self.write
            .reconcile_write(
                reconcile_tenant_scope(tenant),
                move |mut tx| {
                    Box::pin(async move {
                        tx.reconcile_claim_targeted(
                            &reconciler_id,
                            &target_id,
                            wake_version,
                            &holder_id,
                            ttl_secs,
                        )
                        .await
                        .map_err(ReconcileScheduleError::new)?
                        .map(|row| claimed_target_from_row(tenant, row))
                        .transpose()
                    })
                },
                ReconcileScheduleError::new,
            )
            .await
    }

    async fn append_attempt(
        &self,
        target: &ClaimedTarget,
        holder_id: &str,
    ) -> Result<ScheduleAttemptOutcome, ReconcileScheduleError> {
        let trigger = match target.trigger() {
            AttemptTrigger::Resync => ReconcileAttemptTrigger::Resync,
            AttemptTrigger::Targeted => ReconcileAttemptTrigger::Targeted,
            AttemptTrigger::Requeue => ReconcileAttemptTrigger::Requeue,
            AttemptTrigger::LeaseReclaim => ReconcileAttemptTrigger::LeaseReclaim,
        };
        let Some(id) = PgReconcileStore::append_attempt(
            self,
            target.tenant(),
            ReconcileAttemptInsert {
                target_id: target.target_id(),
                lease_token: target.lease_token(),
                epoch: target.epoch(),
                holder_id,
                trigger,
                claimed_failure_streak: target.failure_streak(),
                claimed_wake_version: target.wake_version(),
            },
        )
        .await
        .map_err(ReconcileScheduleError::new)?
        else {
            return Ok(ScheduleAttemptOutcome::Lost);
        };
        Ok(ScheduleAttemptOutcome::Started(ReconcileAttempt::new(
            id.id(),
            target.clone(),
        )))
    }

    async fn record_attempt_result(
        &self,
        attempt: &ReconcileAttempt,
        result: AttemptResult,
    ) -> Result<ScheduleResultOutcome, ReconcileScheduleError> {
        let error_kind = result.error_kind().map(map_attempt_error_kind);
        let outcome = self
            .append_attempt_result(
                attempt.target().tenant(),
                attempt.target().lease_token(),
                attempt.target().epoch(),
                ReconcileAttemptResultInsert {
                    attempt_id: attempt.attempt_id(),
                    target_id: attempt.target().target_id(),
                    result: result.result(),
                    requeue_after: result.requeue_after(),
                    error_kind,
                    schedule: result.schedule(),
                },
            )
            .await
            .map_err(ReconcileScheduleError::new)?;
        Ok(outcome)
    }

    async fn record_fenced_command(
        &self,
        attempt: &ReconcileAttempt,
        action: consistency::ConvergeAction,
        command: ReviewedFencedCommand,
    ) -> Result<ScheduleActionOutcome, ReconcileScheduleError> {
        let (intent, envelope_parts, audit, deadline_epoch_seconds) = command.into_parts();
        let (contract, command_tenant, subject_id, actor, partition_key, causation_id) =
            envelope_parts.into_parts();
        if command_tenant != attempt.target().tenant()
            || audit.tenant() != attempt.target().tenant()
            || audit.device_id().hyphenated().to_string() != attempt.target().resource_id()
            || u64::try_from(audit.fence_epoch().get()).ok() != Some(attempt.target().epoch())
            || audit.attempt_id() != attempt.attempt_id()
        {
            return Err(ReconcileScheduleError::new(ReconcileTenantMismatch));
        }
        let evidence = DeviceCertificateCommandEvidence::restore_durable(
            audit,
            intent.payload(),
            deadline_epoch_seconds.get(),
        )
        .map_err(ReconcileScheduleError::new)?;
        let env = OutboxEnvelope::new(
            contract.domain().to_string(),
            contract.contract_id().to_string(),
            metadata_with_ambient(unix_secs(self.clock.now()), command_tenant, contract)
                .with_subject_id(subject_id)
                .with_actor(actor),
        )
        .with_partition_key_opt(partition_key)
        .with_causation_id_opt(causation_id);
        let tenant = attempt.target().tenant();
        let attempt_id = attempt.attempt_id().to_string();
        let target_id = attempt.target().target_id().to_string();
        let lease_token = attempt.target().lease_token().to_string();
        let epoch = epoch_to_db(attempt.target().epoch()).map_err(ReconcileScheduleError::new)?;
        let action_kind = action.as_label();
        #[cfg(all(test, feature = "integration"))]
        let command_write_fault = self.command_write_fault;
        let committed = self
            .write
            .reconcile_write(
                reconcile_tenant_scope(tenant),
                move |mut tx| {
                    Box::pin(async move {
                        tx.reconcile_enqueue_command(ReconcileEnqueue {
                            attempt_id: &attempt_id,
                            fence: ReconcileLeaseFence {
                                target_id: &target_id,
                                lease_token: &lease_token,
                                epoch,
                            },
                            action_kind,
                            intent,
                            envelope: &env,
                            evidence,
                            deadline_epoch_seconds,
                            #[cfg(all(test, feature = "integration"))]
                            fault: command_write_fault,
                        })
                        .await
                    })
                },
                ReconcileScheduleError::new,
            )
            .await?;
        match committed {
            CommittedActionOutcome::Enqueued => Ok(ScheduleActionOutcome::Enqueued),
            CommittedActionOutcome::Duplicate => Ok(ScheduleActionOutcome::Duplicate),
            CommittedActionOutcome::Lost => Ok(ScheduleActionOutcome::Lost),
            CommittedActionOutcome::FactConflictQuarantined => Err(
                ReconcileScheduleError::fact_conflict(consistency::OutboxFactConflict),
            ),
        }
    }

    async fn complete_device_certificate_deletion(
        &self,
        attempt: &ReconcileAttempt,
    ) -> Result<ScheduleCompletionOutcome, ReconcileScheduleError> {
        let tenant = attempt.target().tenant();
        let attempt_id = attempt.attempt_id().to_string();
        let target_id = attempt.target().target_id().to_string();
        let lease_token = attempt.target().lease_token().to_string();
        let epoch = epoch_to_db(attempt.target().epoch()).map_err(ReconcileScheduleError::new)?;
        self.write
            .reconcile_write(
                reconcile_tenant_scope(tenant),
                move |mut tx| {
                    Box::pin(async move {
                        tx.reconcile_complete_device_certificate_deletion(
                            DeviceCertificateDeletionDb {
                                attempt_id: &attempt_id,
                                fence: ReconcileLeaseFence {
                                    target_id: &target_id,
                                    lease_token: &lease_token,
                                    epoch,
                                },
                            },
                        )
                        .await
                        .map_err(ReconcileScheduleError::new)
                    })
                },
                ReconcileScheduleError::new,
            )
            .await
    }

    async fn extend_lease(
        &self,
        target: &ClaimedTarget,
        lease_ttl: Duration,
    ) -> Result<ScheduleLeaseOutcome, ReconcileScheduleError> {
        let outcome = PgReconcileStore::extend_lease(
            self,
            target.tenant(),
            target.target_id(),
            target.lease_token(),
            target.epoch(),
            lease_ttl,
        )
        .await
        .map_err(ReconcileScheduleError::new)?;
        Ok(map_lease_outcome(outcome))
    }

    async fn release_lease(
        &self,
        target: &ClaimedTarget,
    ) -> Result<ScheduleLeaseOutcome, ReconcileScheduleError> {
        let outcome = PgReconcileStore::release_lease(
            self,
            target.tenant(),
            target.target_id(),
            target.lease_token(),
            target.epoch(),
        )
        .await
        .map_err(ReconcileScheduleError::new)?;
        Ok(map_lease_outcome(outcome))
    }

    async fn pause_target(
        &self,
        tenant: vocab::TenantId,
        target_id: &str,
    ) -> Result<(), ReconcileScheduleError> {
        PgReconcileStore::pause_target(self, tenant, target_id)
            .await
            .map_err(ReconcileScheduleError::new)
    }

    async fn resume_target(
        &self,
        tenant: vocab::TenantId,
        target_id: &str,
    ) -> Result<(), ReconcileScheduleError> {
        PgReconcileStore::resume_target(self, tenant, target_id)
            .await
            .map_err(ReconcileScheduleError::new)
    }
}

pub(crate) enum CommittedActionOutcome {
    Enqueued,
    Duplicate,
    Lost,
    FactConflictQuarantined,
}

#[derive(Debug, thiserror::Error)]
#[error("reconcile command tenant does not match attempt tenant")]
struct ReconcileTenantMismatch;

#[derive(Debug, thiserror::Error)]
#[error("durable device command audit digest is not SHA-256 sized")]
struct DeviceCommandAuditDigestLength;

/// Reconcile store error.
#[derive(Debug, thiserror::Error)]
#[error("reconcile store operation failed")]
pub(crate) struct ReconcileStoreError {
    #[source]
    source: RedactedSource,
}

impl ReconcileStoreError {
    fn new<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            source: RedactedSource::new(source),
        }
    }
}

impl From<ReconcileKeyError> for ReconcileStoreError {
    fn from(source: ReconcileKeyError) -> Self {
        Self::new(source)
    }
}

#[cfg(any(
    all(test, feature = "integration"),
    feature = "fault-matrix-test-support"
))]
pub(crate) struct TargetFields {
    pub(crate) reconciler_id: String,
    pub(crate) resource_kind: String,
    pub(crate) resource_id: String,
}

#[cfg(any(
    all(test, feature = "integration"),
    feature = "fault-matrix-test-support"
))]
impl TargetFields {
    fn from_key(key: &ReconcileTargetKey) -> Self {
        Self {
            reconciler_id: key.reconciler_id().to_string(),
            resource_kind: key.resource_kind().to_string(),
            resource_id: key.resource_id().to_string(),
        }
    }
}

struct LeaseCasRequest<'a> {
    target_id: &'a str,
    lease_token: &'a str,
    epoch: i64,
    operation: LeaseCasOperation,
}

enum LeaseCasOperation {
    Extend { ttl_secs: i64 },
    Release,
}

const RECONCILE_ID_MAX_BYTES: usize = 128;
#[cfg(any(
    all(test, feature = "integration"),
    feature = "fault-matrix-test-support"
))]
const RESOURCE_ID_MAX_BYTES: usize = 512;
const HOLDER_ID_MAX_BYTES: usize = 256;
const UUID_TEXT_MAX_BYTES: usize = 36;

fn validate_component(
    component: &'static str,
    value: String,
    max_bytes: usize,
) -> Result<String, ReconcileKeyError> {
    if value.is_empty() {
        return Err(ReconcileKeyError::Empty { component });
    }
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(ReconcileKeyError::NotCanonical { component });
    }
    if value.len() > max_bytes {
        return Err(ReconcileKeyError::TooLong { component });
    }
    Ok(value)
}

fn validate_runtime_component(
    component: &'static str,
    value: &str,
    max_bytes: usize,
) -> Result<(), ReconcileStoreError> {
    validate_component(component, value.to_string(), max_bytes)
        .map(|_| ())
        .map_err(ReconcileStoreError::from)
}

fn epoch_to_db(epoch: u64) -> Result<i64, ReconcileStoreError> {
    i64::try_from(epoch).map_err(ReconcileStoreError::new)
}

fn epoch_from_db(epoch: i64) -> Result<u64, ReconcileStoreError> {
    u64::try_from(epoch).map_err(ReconcileStoreError::new)
}

fn wake_version_to_db(wake_version: WakeVersion) -> Result<i64, ReconcileStoreError> {
    i64::try_from(wake_version.get()).map_err(ReconcileStoreError::new)
}

fn claimed_target_from_row(
    tenant: vocab::TenantId,
    row: ReconcileClaimedRow,
) -> Result<ClaimedTarget, ReconcileScheduleError> {
    let failure_streak = u32::try_from(row.failure_streak)
        .map(FailureStreak::restore)
        .map_err(ReconcileScheduleError::new)?;
    let wake_version =
        WakeVersion::restore(row.wake_version).map_err(ReconcileScheduleError::new)?;
    Ok(ClaimedTarget::restore(ClaimedTargetRestore {
        tenant,
        target_id: row.target_id,
        reconciler_id: row.reconciler_id,
        resource_kind: row.resource_kind,
        resource_id: row.resource_id,
        lease_token: row.lease_token,
        epoch: epoch_from_db(row.epoch).map_err(ReconcileScheduleError::new)?,
        failure_streak,
        wake_version,
        trigger: trigger_from_label(&row.trigger_kind).map_err(ReconcileScheduleError::new)?,
    }))
}

fn duration_secs(duration: Duration) -> Result<i64, ReconcileStoreError> {
    let secs = i64::try_from(duration.as_secs()).map_err(ReconcileStoreError::new)?;
    if secs <= 0 {
        return Err(ReconcileStoreError::new(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "lease ttl must be positive",
        )));
    }
    Ok(secs)
}

fn duration_millis(duration: Duration) -> Result<i64, ReconcileStoreError> {
    i64::try_from(duration.as_millis()).map_err(ReconcileStoreError::new)
}

#[cfg(any(
    all(test, feature = "integration"),
    feature = "fault-matrix-test-support"
))]
fn lease_from_row(row: (String, String, i64)) -> Result<ReconcileLease, ReconcileStoreError> {
    Ok(ReconcileLease {
        target_id: row.0,
        lease_token: row.1,
        epoch: epoch_from_db(row.2)?,
    })
}

async fn serving_update_target_status(
    pool: &TenantDb<ServingWriteLane>,
    tenant: vocab::TenantId,
    target_id: &str,
    kind: ReconcileTargetTransitionKind,
) -> Result<(), ReconcileStoreError> {
    validate_runtime_component("target_id", target_id, UUID_TEXT_MAX_BYTES)?;
    let target_id = target_id.to_string();
    pool.reconcile_write(
        reconcile_tenant_scope(tenant),
        move |mut tx| {
            Box::pin(async move {
                let updated = tx
                    .reconcile_transition_target(ReconcileTargetTransition {
                        target_id: &target_id,
                        kind,
                    })
                    .await
                    .map_err(ReconcileStoreError::new)?;
                if updated {
                    Ok(())
                } else {
                    Err(ReconcileStoreError::new(ReconcileTargetNotFound))
                }
            })
        },
        ReconcileStoreError::new,
    )
    .await
}

async fn maintenance_update_target_status(
    pool: &TenantDb<MaintenanceWriteLane>,
    tenant: vocab::TenantId,
    target_id: &str,
    kind: ReconcileTargetTransitionKind,
) -> Result<(), ReconcileStoreError> {
    validate_runtime_component("target_id", target_id, UUID_TEXT_MAX_BYTES)?;
    let target_id = target_id.to_string();
    pool.reconcile_write(
        reconcile_tenant_scope(tenant),
        move |mut tx| {
            Box::pin(async move {
                let updated = tx
                    .reconcile_transition_target(ReconcileTargetTransition {
                        target_id: &target_id,
                        kind,
                    })
                    .await
                    .map_err(ReconcileStoreError::new)?;
                if updated {
                    Ok(())
                } else {
                    Err(ReconcileStoreError::new(ReconcileTargetNotFound))
                }
            })
        },
        ReconcileStoreError::new,
    )
    .await
}

async fn maintenance_inspect_target(
    pool: &TenantDb<MaintenanceReadLane>,
    tenant: vocab::TenantId,
    target_id: &str,
) -> Result<ReconcileTargetSummary, ReconcileStoreError> {
    validate_runtime_component("target_id", target_id, UUID_TEXT_MAX_BYTES)?;
    let target_id = target_id.to_string();
    let row = pool
        .reconcile_read(reconcile_tenant_scope(tenant), move |mut tx| {
            Box::pin(async move { tx.reconcile_inspect_target(&target_id).await })
        })
        .await
        .map_err(ReconcileStoreError::new)?;
    let row = row.ok_or_else(|| ReconcileStoreError::new(ReconcileTargetNotFound))?;
    let status = match row.status.as_str() {
        "active" => ReconcileTargetStatus::Active,
        "disabled" => ReconcileTargetStatus::Disabled,
        _ => return Err(ReconcileStoreError::new(InvalidReconcileTargetState)),
    };
    let disabled_reason = match row.disabled_reason.as_deref() {
        None => None,
        Some("fact_conflict") => Some(ReconcileQuarantineReason::FactConflict),
        Some("permanent_failure") => Some(ReconcileQuarantineReason::PermanentFailure),
        Some("invariant_violation") => Some(ReconcileQuarantineReason::InvariantViolation),
        Some(_) => return Err(ReconcileStoreError::new(InvalidReconcileTargetState)),
    };
    ReconcileTargetSummary::new(
        tenant,
        row.target_id,
        row.reconciler_id,
        row.resource_kind,
        status,
        disabled_reason,
    )
    .map_err(ReconcileStoreError::new)
}

#[derive(Debug, thiserror::Error)]
#[error("reconcile target not found")]
struct ReconcileTargetNotFound;

#[derive(Debug, thiserror::Error)]
#[error("reconcile target state is invalid")]
struct InvalidReconcileTargetState;

fn trigger_from_label(label: &str) -> Result<AttemptTrigger, ReconcileStoreError> {
    match label {
        "resync" => Ok(AttemptTrigger::Resync),
        "targeted" => Ok(AttemptTrigger::Targeted),
        "requeue" => Ok(AttemptTrigger::Requeue),
        "lease_reclaim" => Ok(AttemptTrigger::LeaseReclaim),
        _ => Err(ReconcileStoreError::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unknown reconcile attempt trigger",
        ))),
    }
}

fn map_attempt_error_kind(kind: AttemptErrorKind) -> ReconcileActionErrorKind {
    match kind {
        AttemptErrorKind::Transient => ReconcileActionErrorKind::Transient,
        AttemptErrorKind::Permanent => ReconcileActionErrorKind::Permanent,
        AttemptErrorKind::Invariant => ReconcileActionErrorKind::Invariant,
    }
}

fn map_lease_outcome(outcome: ReconcileLeaseOutcome) -> ScheduleLeaseOutcome {
    match outcome {
        ReconcileLeaseOutcome::Held => ScheduleLeaseOutcome::Held,
        ReconcileLeaseOutcome::Lost => ScheduleLeaseOutcome::Lost,
    }
}

#[cfg(test)]
mod tests {
    #[cfg(any(
        all(test, feature = "integration"),
        feature = "fault-matrix-test-support"
    ))]
    use super::*;

    const MIGRATION_0041: &str = include_str!("../migrations/0041_create_reconcile_schema.sql");
    const MIGRATION_0044: &str =
        include_str!("../migrations/0044_create_reconcile_attempt_results.sql");
    const MIGRATION_0045: &str =
        include_str!("../migrations/0045_reconcile_actions_recorded_label.sql");
    const MIGRATION_0084: &str =
        include_str!("../migrations/0084_persist_reconcile_wake_and_device_policy_operations.sql");

    #[test]
    fn migration_locks_reconcile_labels_and_append_only_grants() {
        for needle in [
            "CHECK (status IN ('active', 'disabled'))",
            "CHECK (state IN ('free', 'held'))",
            "CHECK (trigger_kind IN ('resync', 'targeted', 'requeue', 'lease_reclaim'))",
            "CHECK (action_kind IN ('noop', 'create', 'update', 'delete'))",
            "CHECK (result_label IN ('settled', 'requeue_after', 'transient', 'permanent', 'invariant'))",
            "GRANT SELECT, INSERT ON reconcile_attempts TO rss_app",
            "REVOKE UPDATE, DELETE ON reconcile_attempts FROM rss_app",
            "GRANT SELECT, INSERT ON reconcile_actions TO rss_app",
            "REVOKE UPDATE, DELETE ON reconcile_actions FROM rss_app",
        ] {
            assert!(
                MIGRATION_0041.contains(needle),
                "0041 migration missing `{needle}`"
            );
        }
    }

    #[test]
    fn migration_locks_reconcile_rls_and_cas_predicates() {
        for table in [
            "reconcile_targets",
            "reconcile_leases",
            "reconcile_attempts",
            "reconcile_actions",
        ] {
            assert!(
                MIGRATION_0041.contains(&format!("ALTER TABLE {table} FORCE ROW LEVEL SECURITY")),
                "0041 migration must FORCE RLS on {table}"
            );
        }
        for needle in [
            "tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid",
            "CONSTRAINT reconcile_targets_tenant_resource_unique",
            "UNIQUE (tenant_id, reconciler_id, resource_kind, resource_id)",
            "CONSTRAINT reconcile_attempts_attempt_target_unique",
            "FOREIGN KEY (tenant_id, attempt_id, target_id)",
            "FOREIGN KEY (tenant_id, target_id)",
        ] {
            assert!(
                MIGRATION_0041.contains(needle),
                "0041 migration missing `{needle}`"
            );
        }
    }

    #[test]
    fn attempt_results_migration_is_append_only_and_tenant_scoped() {
        for needle in [
            "CREATE TABLE reconcile_attempt_results",
            "FOREIGN KEY (tenant_id, attempt_id, target_id)",
            "CHECK (result_label IN ('settled', 'requeue_after', 'transient', 'permanent', 'invariant'))",
            "CHECK (error_kind IS NULL OR error_kind IN ('transient', 'permanent', 'invariant'))",
            "GRANT SELECT, INSERT ON reconcile_attempt_results TO rss_app",
            "REVOKE UPDATE, DELETE ON reconcile_attempt_results FROM rss_app",
            "ALTER TABLE reconcile_attempt_results FORCE ROW LEVEL SECURITY",
            "tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid",
        ] {
            assert!(
                MIGRATION_0044.contains(needle),
                "0044 migration missing `{needle}`"
            );
        }
    }

    #[test]
    fn actions_record_only_converge_action_not_terminal_result() {
        for needle in [
            "UPDATE reconcile_actions",
            "SET result_label = 'recorded'",
            "DROP CONSTRAINT reconcile_actions_result_label_valid",
            "CHECK (result_label = 'recorded')",
            "CHECK (requeue_after_ms IS NULL AND error_kind IS NULL)",
        ] {
            assert!(
                MIGRATION_0045.contains(needle),
                "0045 migration missing `{needle}`"
            );
        }
    }

    #[test]
    fn durable_schedule_migration_captures_retry_wake_and_append_only_policy_operations() {
        for needle in [
            "ADD COLUMN failure_streak bigint NOT NULL DEFAULT 0",
            "ADD COLUMN last_result text",
            "ADD COLUMN wake_version bigint NOT NULL DEFAULT 0",
            "ADD COLUMN claimed_failure_streak bigint",
            "ADD COLUMN claimed_wake_version bigint",
            "ALTER COLUMN claimed_failure_streak SET NOT NULL",
            "CREATE TRIGGER reconcile_target_wake_monotonic",
            "NEW.reconciler_id",
            "NEW.resource_kind",
            "NEW.resource_id",
            ") IS DISTINCT FROM (",
            "CREATE TABLE public.device_certificate_policy_operations",
            "CHECK (pg_catalog.octet_length(request_digest) = 32)",
            "ALTER TABLE public.device_certificate_policy_operations FORCE ROW LEVEL SECURITY",
            "GRANT INSERT (",
            "REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER",
        ] {
            assert!(MIGRATION_0084.contains(needle), "0084 missing `{needle}`");
        }
    }

    #[cfg(any(
        all(test, feature = "integration"),
        feature = "fault-matrix-test-support"
    ))]
    #[test]
    fn key_parse_rejects_non_canonical_components() {
        assert!(ReconcileTargetKey::parse("", "kind", "res").is_err());
        assert!(ReconcileTargetKey::parse("rec", " ", "res").is_err());
        assert!(ReconcileTargetKey::parse("rec", "kind", "res\nid").is_err());
        assert!(ReconcileTargetKey::parse("rec", "kind", "res").is_ok());
    }
}
