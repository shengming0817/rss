//! PostgreSQL device-certificate desired/reported/condition authority.
//!
//! Every operation enters through the typed tenant transaction pools. Mutations lock the desired
//! row first, giving one stable per-device serialization point for CAS classification and
//! zero-write outcomes.
//!
//! ref: launchbadge/sqlx sqlx-core/src/transaction.rs@main

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use deviceloop::{
    CertificateKeyUsage, CertificatePolicy, DesiredGeneration, DeviceConditionRestore,
    ObservedGeneration,
};
use diport::{CertNotAfter, CertScope, CertSerial};
use eventexec::reconcile::{
    DeviceCertificateCommandEvidence, DeviceCommandAuditProof, ReconcileWake, WakeVersion,
};
use identity::ports::device_certificate::{
    AcceptDesiredPolicy, ArtifactAppendAuthorization, ArtifactAppendOutcome, ArtifactDigest,
    CertificateArtifactId, CertificateAttemptAuthority, CertificateAttemptFence,
    CertificateConditionMutation, CertificatePublicKeyDigest, CertificateReadyProof,
    CertificateReconcileRepository, CertificateReconcileRepositoryError, CertificateReconcileView,
    CertificateRevocationObservation, CertificateTransportObservation, DeletionRequestOutcome,
    DesiredPolicyAcceptOutcome, DesiredPolicyAccepted, DesiredPolicyAcceptedCondition,
    DesiredStateRestore, DesiredStateSnapshot, DeviceCertificateError, DeviceCertificateRepository,
    DeviceCertificateRepositoryError, DeviceCertificateScope, DeviceCertificateStateSnapshot,
    DeviceSequence, ExpectedGeneration, FencedMutationOutcome,
    PersistedCertificateArtifactSnapshot, PolicyHash, ReportEnvelopeId, ReportedStateHash,
    ReportedStateRestore, ReportedStateSnapshot, ReportedStateWrite, ReportedWriteOutcome,
    RotationOutcome,
};
use sqlx::PgConnection;

use crate::cotx::{ServingReadLane, ServingWriteLane, TenantDb};
use crate::pool::{VerifiedPgReadStore, VerifiedPgWriteStore};

type RepoError = DeviceCertificateRepositoryError;

const DEVICE_CERTIFICATE_COMMAND_DOMAIN: &str = "identity";
const DEVICE_CERTIFICATE_COMMAND_TOPIC: &str = "identity.commands.apply-device-certificate";
const DEVICE_CERTIFICATE_COMMAND_CONTRACT_ID: &str = "identity.apply-device-certificate";
const DEVICE_CERTIFICATE_COMMAND_VERSION: &str = "v1";
const DEVICE_CERTIFICATE_COMMAND_SCHEMA_HASH: &str =
    "sha256:b5e4a88a6b3b5c11dc928d5d723fe615a23e9560808164d66c260dc8ff415365";

/// Read-only device-certificate authority within one tenant-bound transaction.
pub(crate) struct DeviceCertificateReadTx<'tx> {
    conn: &'tx mut PgConnection,
}

impl<'tx> DeviceCertificateReadTx<'tx> {
    pub(crate) fn new(conn: &'tx mut PgConnection) -> Self {
        Self { conn }
    }
}

/// Mutable device-certificate authority within one tenant-bound transaction.
pub(crate) struct DeviceCertificateWriteTx<'tx> {
    conn: &'tx mut PgConnection,
}

/// Purpose-specific desired-policy acceptance authority. It is deliberately distinct from the
/// reported/condition writer so the atomic desired+target+operation funnel has one entry point.
pub(crate) struct DevicePolicyTx<'tx> {
    conn: &'tx mut PgConnection,
}

impl<'tx> DevicePolicyTx<'tx> {
    pub(crate) fn new(conn: &'tx mut PgConnection) -> Self {
        Self { conn }
    }
}

impl<'tx> DeviceCertificateWriteTx<'tx> {
    pub(crate) fn new(conn: &'tx mut PgConnection) -> Self {
        Self { conn }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RepositoryOperation {
    AcceptDesiredPolicy,
    AdvanceReported,
    LoadState,
}

#[derive(sqlx::FromRow)]
struct ArtifactReceiptRow {
    generation: i64,
    policy_hash: Vec<u8>,
    public_key_digest: Vec<u8>,
    expected_state_hash: Vec<u8>,
    artifact_digest: Vec<u8>,
    artifact_id: String,
    serial: Vec<u8>,
    not_after_seconds: i64,
}

#[derive(sqlx::FromRow)]
struct CurrentCommandEvidenceRow {
    device_id: String,
    generation: i64,
    fence_epoch: i64,
    intent_digest: Vec<u8>,
    attempt_id: String,
    deadline_epoch_seconds: i64,
    payload: Vec<u8>,
}

#[derive(sqlx::FromRow)]
struct RotationFunnelRow {
    next_generation: i64,
    target_id: String,
    wake_version: i64,
}

#[derive(sqlx::FromRow)]
struct DeletionFunnelRow {
    outcome: String,
    target_id: Option<String>,
    wake_version: Option<i64>,
}

struct CommandEvidenceFence {
    scope: DeviceCertificateScope,
    attempt_id: String,
    lease_token: String,
    epoch: i64,
    wake_version: i64,
    expected_generation: i64,
}

impl CommandEvidenceFence {
    fn from_domain(fence: &CertificateAttemptFence) -> Result<Self, RepoError> {
        Ok(Self {
            scope: fence.scope(),
            attempt_id: fence.attempt_id().to_owned(),
            lease_token: fence.lease_token().to_owned(),
            epoch: to_i64(fence.epoch().get())?,
            wake_version: to_i64(fence.wake_version().get())?,
            expected_generation: to_i64(fence.expected_generation().get())?,
        })
    }
}

impl RepositoryOperation {
    const fn as_label(self) -> &'static str {
        match self {
            Self::AcceptDesiredPolicy => "accept_desired_policy",
            Self::AdvanceReported => "advance_reported",
            Self::LoadState => "load_state",
        }
    }
}

/// Tenant-scoped PostgreSQL implementation of the device-certificate persistence port.
pub struct PgDeviceCertificateRepository {
    read_pool: TenantDb<ServingReadLane>,
    write_pool: TenantDb<ServingWriteLane>,
    #[cfg(all(test, feature = "integration"))]
    fail_after_desired_write: bool,
    #[cfg(all(test, feature = "integration"))]
    fail_after_target_wake: bool,
    #[cfg(all(test, feature = "integration"))]
    load_snapshot_hook: Option<std::sync::Arc<LoadSnapshotHook>>,
}

#[cfg(all(test, feature = "integration"))]
struct LoadSnapshotHook {
    desired_loaded: tokio::sync::Notify,
    resume: tokio::sync::Notify,
}

impl PgDeviceCertificateRepository {
    /// Construct from serving capabilities verified by the runtime bundle.
    pub(crate) fn new(reader: &VerifiedPgReadStore, writer: &VerifiedPgWriteStore) -> Self {
        Self {
            read_pool: TenantDb::<ServingReadLane>::new(reader),
            write_pool: TenantDb::<ServingWriteLane>::new(writer),
            #[cfg(all(test, feature = "integration"))]
            fail_after_desired_write: false,
            #[cfg(all(test, feature = "integration"))]
            fail_after_target_wake: false,
            #[cfg(all(test, feature = "integration"))]
            load_snapshot_hook: None,
        }
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn from_unverified_for_test(store: &crate::PgStore) -> Self {
        Self {
            read_pool: TenantDb::<ServingReadLane>::from_unverified_for_test(store),
            write_pool: TenantDb::<ServingWriteLane>::from_unverified_for_test(store),
            fail_after_desired_write: false,
            fail_after_target_wake: false,
            load_snapshot_hook: None,
        }
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn from_unverified_stores_for_test(
        reader: &crate::PgStore,
        writer: &crate::PgStore,
    ) -> Self {
        Self {
            read_pool: TenantDb::<ServingReadLane>::from_unverified_for_test(reader),
            write_pool: TenantDb::<ServingWriteLane>::from_unverified_for_test(writer),
            fail_after_desired_write: false,
            fail_after_target_wake: false,
            load_snapshot_hook: None,
        }
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn with_desired_write_fault_for_test(mut self) -> Self {
        self.fail_after_desired_write = true;
        self
    }

    #[cfg(all(test, feature = "integration"))]
    fn with_load_snapshot_hook_for_test(mut self, hook: std::sync::Arc<LoadSnapshotHook>) -> Self {
        self.load_snapshot_hook = Some(hook);
        self
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn with_target_wake_fault_for_test(mut self) -> Self {
        self.fail_after_target_wake = true;
        self
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) async fn load_current_command_evidence_for_test(
        &self,
        scope: DeviceCertificateScope,
        attempt: &eventexec::reconcile::ReconcileAttempt,
        expected_generation: ExpectedGeneration,
    ) -> Result<Option<DeviceCertificateCommandEvidence>, CertificateReconcileRepositoryError> {
        let fence = CommandEvidenceFence {
            scope,
            attempt_id: attempt.attempt_id().to_owned(),
            lease_token: attempt.target().lease_token().to_owned(),
            epoch: i64::try_from(attempt.target().epoch())
                .map_err(|_| CertificateReconcileRepositoryError::InvalidMutation)?,
            wake_version: i64::try_from(attempt.target().wake_version().get())
                .map_err(|_| CertificateReconcileRepositoryError::InvalidMutation)?,
            expected_generation: i64::try_from(expected_generation.get())
                .map_err(|_| CertificateReconcileRepositoryError::InvalidMutation)?,
        };
        self.write_pool
            .identity_write(
                scope,
                move |mut identity| {
                    Box::pin(async move {
                        let mut identity_write = identity.identity();
                        let mut certificates = identity_write.device_certificates();
                        certificates
                            .current_command_evidence_row(&fence)
                            .await
                            .map_err(reconcile_from_repo)?
                            .map(|row| restore_current_command_evidence(scope.tenant(), row))
                            .transpose()
                    })
                },
                reconcile_storage,
            )
            .await
    }
}

fn storage(error: sqlx::Error) -> RepoError {
    let database_code = error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(|code| code.into_owned());
    tracing::warn!(
        error.kind = "postgres",
        database.code = database_code.as_deref().unwrap_or("none"),
        error = %secure::redact_error(&error),
        "device-certificate repository operation failed"
    );
    RepoError::storage_unavailable(error)
}

fn corrupt(error: DeviceCertificateError) -> RepoError {
    tracing::warn!(
        error.kind = "corrupt_state",
        "device-certificate persisted state failed validation"
    );
    RepoError::CorruptState(error)
}

fn invalid_persisted_value() -> RepoError {
    corrupt(DeviceCertificateError::InvalidPersistedValue)
}

fn tenant_param(scope: DeviceCertificateScope) -> String {
    scope.tenant().as_uuid().to_string()
}

fn device_param(scope: DeviceCertificateScope) -> String {
    scope.device().as_uuid().to_string()
}

fn to_i64(value: u64) -> Result<i64, RepoError> {
    i64::try_from(value).map_err(|_| RepoError::InvalidMutation)
}

fn time_to_epoch_micros(value: SystemTime) -> Result<i64, RepoError> {
    let signed = match value.duration_since(UNIX_EPOCH) {
        Ok(duration) => {
            i128::try_from(duration.as_micros()).map_err(|_| RepoError::InvalidMutation)?
        }
        Err(error) => {
            -i128::try_from(error.duration().as_micros()).map_err(|_| RepoError::InvalidMutation)?
        }
    };
    // PostgreSQL's lower timestamp bound is 4713-01-01 BC. The upper bound of this wire codec is
    // the signed microsecond representation accepted by the parameterized SQL expression.
    const PG_UNIX_MIN_MICROS: i128 = -210_866_803_200_000_000;
    if !(PG_UNIX_MIN_MICROS..=i128::from(i64::MAX)).contains(&signed) {
        return Err(RepoError::InvalidMutation);
    }
    i64::try_from(signed).map_err(|_| RepoError::InvalidMutation)
}

fn time_to_epoch_seconds(value: SystemTime) -> Result<i64, RepoError> {
    value
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RepoError::InvalidMutation)
        .and_then(|duration| {
            i64::try_from(duration.as_secs()).map_err(|_| RepoError::InvalidMutation)
        })
}

fn optional_time_to_epoch_micros(value: Option<SystemTime>) -> Result<Option<i64>, RepoError> {
    value.map(time_to_epoch_micros).transpose()
}

fn epoch_micros_to_time(value: i64) -> Result<SystemTime, RepoError> {
    if value >= 0 {
        UNIX_EPOCH
            .checked_add(Duration::from_micros(value.unsigned_abs()))
            .ok_or_else(invalid_persisted_value)
    } else {
        UNIX_EPOCH
            .checked_sub(Duration::from_micros(value.unsigned_abs()))
            .ok_or_else(invalid_persisted_value)
    }
}

fn policy_columns(policy: &CertificatePolicy) -> (i32, i32, bool, bool, Vec<String>) {
    let usages = policy.key_usages();
    (
        policy.durations().validity().get() as i32,
        policy.durations().renew_before().get() as i32,
        usages.contains(&CertificateKeyUsage::ClientAuth),
        usages.contains(&CertificateKeyUsage::ServerAuth),
        policy
            .sans()
            .iter()
            .map(|san| san.as_str().to_owned())
            .collect(),
    )
}

#[derive(sqlx::FromRow)]
struct DesiredRow {
    generation: i64,
    policy_hash: Vec<u8>,
    validity_seconds: i32,
    renew_before_seconds: i32,
    client_auth: bool,
    server_auth: bool,
    sans: Vec<String>,
    created_at_micros: i64,
    updated_at_micros: i64,
}

fn restore_desired(row: DesiredRow) -> Result<DesiredStateRestore, RepoError> {
    let mut usages = Vec::with_capacity(2);
    if row.client_auth {
        usages.push(CertificateKeyUsage::ClientAuth.as_label().to_owned());
    }
    if row.server_auth {
        usages.push(CertificateKeyUsage::ServerAuth.as_label().to_owned());
    }
    let policy = CertificatePolicy::restore(
        u64::try_from(row.validity_seconds).map_err(|_| invalid_persisted_value())?,
        u64::try_from(row.renew_before_seconds).map_err(|_| invalid_persisted_value())?,
        usages,
        row.sans,
    )
    .map_err(DeviceCertificateError::from)
    .map_err(corrupt)?;
    Ok(DesiredStateRestore::new(
        u64::try_from(row.generation).map_err(|_| invalid_persisted_value())?,
        PolicyHash::restore(&row.policy_hash).map_err(corrupt)?,
        policy,
        epoch_micros_to_time(row.created_at_micros)?,
        epoch_micros_to_time(row.updated_at_micros)?,
    ))
}

async fn select_desired(
    conn: &mut PgConnection,
    tenant: &str,
    device: &str,
) -> Result<Option<DesiredRow>, RepoError> {
    sqlx::query_as::<_, DesiredRow>(
        "SELECT generation, policy_hash, validity_seconds, renew_before_seconds, client_auth, \
         server_auth, sans, floor(extract(epoch FROM created_at) * 1000000)::bigint \
         AS created_at_micros, floor(extract(epoch FROM updated_at) * 1000000)::bigint \
         AS updated_at_micros FROM device_certificate_desired_states \
         WHERE tenant_id = $1::uuid AND device_id = $2::uuid",
    )
    .bind(tenant)
    .bind(device)
    .fetch_optional(conn)
    .await
    .map_err(storage)
}

#[derive(sqlx::FromRow)]
struct ReportedRow {
    observed_generation: i64,
    fence_epoch: i64,
    state_hash: Vec<u8>,
    artifact_digest: Vec<u8>,
    report_envelope_id: String,
    device_sequence: i64,
    expires_at_micros: Option<i64>,
    device_observed_at_micros: Option<i64>,
    received_at_micros: i64,
}

fn restore_reported(row: ReportedRow) -> Result<ReportedStateRestore, RepoError> {
    Ok(ReportedStateRestore::new(
        u64::try_from(row.observed_generation).map_err(|_| invalid_persisted_value())?,
        u64::try_from(row.fence_epoch).map_err(|_| invalid_persisted_value())?,
        ReportedStateHash::restore(&row.state_hash).map_err(corrupt)?,
        ArtifactDigest::restore(&row.artifact_digest).map_err(corrupt)?,
        ReportEnvelopeId::parse(&row.report_envelope_id).map_err(corrupt)?,
        DeviceSequence::restore(row.device_sequence)
            .map_err(DeviceCertificateError::from)
            .map_err(corrupt)?,
        row.expires_at_micros
            .map(epoch_micros_to_time)
            .transpose()?,
        row.device_observed_at_micros
            .map(epoch_micros_to_time)
            .transpose()?,
        epoch_micros_to_time(row.received_at_micros)?,
    ))
}

async fn select_reported(
    conn: &mut PgConnection,
    tenant: &str,
    device: &str,
    for_update: bool,
) -> Result<Option<ReportedRow>, RepoError> {
    let query = if for_update {
        sqlx::query_as::<_, ReportedRow>(
            "SELECT observed_generation, fence_epoch, state_hash, artifact_digest, \
             report_envelope_id, device_sequence, \
             floor(extract(epoch FROM expires_at) * 1000000)::bigint AS expires_at_micros, \
             floor(extract(epoch FROM device_observed_at) * 1000000)::bigint \
             AS device_observed_at_micros, \
             floor(extract(epoch FROM received_at) * 1000000)::bigint AS received_at_micros \
             FROM device_certificate_reported_states \
             WHERE tenant_id = $1::uuid AND device_id = $2::uuid FOR UPDATE",
        )
    } else {
        sqlx::query_as::<_, ReportedRow>(
            "SELECT observed_generation, fence_epoch, state_hash, artifact_digest, \
             report_envelope_id, device_sequence, \
             floor(extract(epoch FROM expires_at) * 1000000)::bigint AS expires_at_micros, \
             floor(extract(epoch FROM device_observed_at) * 1000000)::bigint \
             AS device_observed_at_micros, \
             floor(extract(epoch FROM received_at) * 1000000)::bigint AS received_at_micros \
             FROM device_certificate_reported_states \
             WHERE tenant_id = $1::uuid AND device_id = $2::uuid",
        )
    };
    query
        .bind(tenant)
        .bind(device)
        .fetch_optional(conn)
        .await
        .map_err(storage)
}

#[derive(sqlx::FromRow)]
struct ConditionRow {
    condition_type: String,
    status: String,
    reason: String,
    observed_generation: Option<i64>,
    last_transition_at_micros: i64,
}

fn restore_condition(row: ConditionRow) -> Result<DeviceConditionRestore, RepoError> {
    let observed = row
        .observed_generation
        .map(|value| {
            u64::try_from(value)
                .map_err(|_| invalid_persisted_value())
                .and_then(|value| ObservedGeneration::try_new(value).map_err(|e| corrupt(e.into())))
        })
        .transpose()?;
    let at = epoch_micros_to_time(row.last_transition_at_micros)?;
    DeviceConditionRestore::from_persisted_labels(
        &row.condition_type,
        &row.status,
        &row.reason,
        observed,
        at,
    )
    .map_err(DeviceCertificateError::from)
    .map_err(corrupt)
}

async fn select_conditions(
    conn: &mut PgConnection,
    tenant: &str,
    device: &str,
) -> Result<Vec<DeviceConditionRestore>, RepoError> {
    let rows = sqlx::query_as::<_, ConditionRow>(
        "SELECT condition_type, status, reason, observed_generation, \
         floor(extract(epoch FROM last_transition_at) * 1000000)::bigint \
             AS last_transition_at_micros \
         FROM device_certificate_conditions \
         WHERE tenant_id = $1::uuid AND device_id = $2::uuid \
         ORDER BY condition_type COLLATE \"C\"",
    )
    .bind(tenant)
    .bind(device)
    .fetch_all(conn)
    .await
    .map_err(storage)?;
    rows.into_iter().map(restore_condition).collect()
}

fn reported_payload_equal(
    row: &ReportedRow,
    input: &ReportedStateWrite,
) -> Result<bool, RepoError> {
    Ok(row.fence_epoch == to_i64(input.fence_epoch().get())?
        && row.state_hash.as_slice() == input.state_hash().as_bytes()
        && row.artifact_digest.as_slice() == input.artifact_digest().as_bytes()
        && row.report_envelope_id == input.report_envelope_id().as_str()
        && row.device_sequence == to_i64(input.device_sequence().get())?
        && row.expires_at_micros == optional_time_to_epoch_micros(input.expires_at())?
        && row.device_observed_at_micros
            == optional_time_to_epoch_micros(input.device_observed_at())?)
}

impl DeviceCertificateReadTx<'_> {
    async fn desired(
        &mut self,
        tenant: &str,
        device: &str,
    ) -> Result<Option<DesiredRow>, RepoError> {
        select_desired(self.conn, tenant, device).await
    }

    async fn reported(
        &mut self,
        tenant: &str,
        device: &str,
    ) -> Result<Option<ReportedRow>, RepoError> {
        select_reported(self.conn, tenant, device, false).await
    }

    async fn conditions(
        &mut self,
        tenant: &str,
        device: &str,
    ) -> Result<Vec<DeviceConditionRestore>, RepoError> {
        select_conditions(self.conn, tenant, device).await
    }
}

impl DeviceCertificateWriteTx<'_> {
    async fn reconcile_fence_target(
        &mut self,
        fence: &CertificateAttemptFence,
    ) -> Result<Option<String>, RepoError> {
        sqlx::query_scalar(
            r#"
            SELECT target.target_id::text
            FROM reconcile_targets target
            JOIN reconcile_attempts attempt
              ON attempt.tenant_id = target.tenant_id AND attempt.target_id = target.target_id
            JOIN reconcile_leases lease
              ON lease.tenant_id = target.tenant_id AND lease.target_id = target.target_id
            JOIN device_certificate_desired_states desired
              ON desired.tenant_id = target.tenant_id
             AND desired.device_id::text = target.resource_id
            WHERE target.tenant_id = $1::uuid
              AND target.reconciler_id = $2 AND target.resource_kind = $3
              AND target.resource_id = $4
              AND attempt.attempt_id = $5::uuid
              AND attempt.lease_token = $6::uuid AND attempt.epoch = $7
              AND attempt.claimed_wake_version = $8 AND target.wake_version = $8
              AND lease.lease_token = $6::uuid AND lease.epoch = $7
              AND lease.state = 'held' AND lease.expires_at > pg_catalog.clock_timestamp()
              AND desired.generation = $9
            FOR UPDATE OF lease, target, desired
            "#,
        )
        .bind(tenant_param(fence.scope()))
        .bind(DEVICE_CERTIFICATE_RECONCILER_ID)
        .bind(DEVICE_CERTIFICATE_RESOURCE_KIND)
        .bind(device_param(fence.scope()))
        .bind(fence.attempt_id())
        .bind(fence.lease_token())
        .bind(to_i64(fence.epoch().get())?)
        .bind(to_i64(fence.wake_version().get())?)
        .bind(to_i64(fence.expected_generation().get())?)
        .fetch_optional(&mut *self.conn)
        .await
        .map_err(storage)
    }

    async fn reconcile_snapshot_with_ready_evidence(
        &mut self,
        authority: &CertificateAttemptAuthority,
        scope: DeviceCertificateScope,
        tenant: &str,
        device: &str,
    ) -> Result<Option<DeviceCertificateStateSnapshot>, RepoError> {
        let Some(desired_row) = self.desired(tenant, device).await? else {
            return Ok(None);
        };
        let desired_restore = restore_desired(desired_row)?;
        let desired = DesiredStateSnapshot::restore(desired_restore.clone()).map_err(corrupt)?;
        let reported_restore = select_reported(self.conn, tenant, device, false)
            .await?
            .map(restore_reported)
            .transpose()?;
        let conditions = self.conditions(tenant, device).await?;
        let ready_persisted = conditions.iter().any(|condition| {
            matches!(condition, DeviceConditionRestore::Ready(value)
                if value.status() == deviceloop::ConditionStatus::True)
        });
        if !ready_persisted {
            return DeviceCertificateStateSnapshot::restore(
                scope,
                desired_restore,
                reported_restore,
                conditions,
            )
            .map(Some)
            .map_err(corrupt);
        }
        let reported_restore = reported_restore.ok_or_else(invalid_persisted_value)?;
        let reported = ReportedStateSnapshot::restore(reported_restore.clone()).map_err(corrupt)?;
        let generation = to_i64(desired.generation().get())?;
        let receipt_row = self
            .artifact_rows(tenant, device)
            .await?
            .into_iter()
            .find(|row| row.generation == generation)
            .ok_or_else(invalid_persisted_value)?;
        let receipt =
            restore_artifact_receipt(scope, receipt_row).map_err(|error| match error {
                CertificateReconcileRepositoryError::CorruptState(source) => corrupt(source),
                _ => invalid_persisted_value(),
            })?;
        let command_fence = CommandEvidenceFence {
            scope,
            attempt_id: authority.attempt_id().to_owned(),
            lease_token: authority.lease_token().to_owned(),
            epoch: to_i64(authority.epoch().get())?,
            wake_version: to_i64(authority.wake_version().get())?,
            expected_generation: generation,
        };
        let command_row = self
            .current_command_evidence_row(&command_fence)
            .await?
            .ok_or_else(invalid_persisted_value)?;
        let command = restore_current_command_evidence(scope.tenant(), command_row)
            .map_err(|_| invalid_persisted_value())?;
        let revoked: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM certificate_revocations \
             WHERE tenant_id=$1::uuid AND device_id=$2::uuid AND serial=$3 \
               AND not_after=pg_catalog.to_timestamp($4))",
        )
        .bind(tenant)
        .bind(device)
        .bind(receipt.serial().as_bytes())
        .bind(receipt.not_after().unix_seconds())
        .fetch_one(&mut *self.conn)
        .await
        .map_err(storage)?;
        let now_micros: i64 = sqlx::query_scalar(
            "SELECT pg_catalog.floor(extract(epoch FROM pg_catalog.clock_timestamp()) \
             * 1000000)::bigint",
        )
        .fetch_one(&mut *self.conn)
        .await
        .map_err(storage)?;
        let authoritative_now = epoch_micros_to_time(now_micros)?;
        let renew_at = receipt
            .not_after()
            .as_system_time()
            .checked_sub(Duration::from_secs(u64::from(
                desired.policy().durations().renew_before().get(),
            )))
            .ok_or_else(invalid_persisted_value)?;
        if revoked || authoritative_now >= renew_at {
            let repaired: bool = sqlx::query_scalar(
                "SELECT public.rss_write_device_certificate_conditions( \
                 $1::uuid,$2::uuid,$3::uuid,$4::uuid,$5,$6,$7, \
                 ARRAY['Ready']::text[],ARRAY['False']::text[], \
                 ARRAY['StateDrift']::text[],ARRAY[$7]::bigint[])",
            )
            .bind(tenant)
            .bind(device)
            .bind(authority.attempt_id())
            .bind(authority.lease_token())
            .bind(to_i64(authority.epoch().get())?)
            .bind(to_i64(authority.wake_version().get())?)
            .bind(generation)
            .fetch_one(&mut *self.conn)
            .await
            .map_err(storage)?;
            if !repaired {
                return Ok(None);
            }
            return DeviceCertificateStateSnapshot::restore(
                scope,
                desired_restore,
                Some(reported_restore),
                self.conditions(tenant, device).await?,
            )
            .map(Some)
            .map_err(corrupt);
        }
        let proof = CertificateReadyProof::restore_current(
            scope,
            &desired,
            &receipt,
            &reported,
            &command,
            authoritative_now,
            CertificateRevocationObservation::Unrevoked,
        )
        .map_err(|_| invalid_persisted_value())?;
        DeviceCertificateStateSnapshot::restore_with_ready_proof(
            scope,
            desired_restore,
            Some(reported_restore),
            conditions,
            proof,
        )
        .map(Some)
        .map_err(corrupt)
    }

    async fn artifact_rows(
        &mut self,
        tenant: &str,
        device: &str,
    ) -> Result<Vec<ArtifactReceiptRow>, RepoError> {
        sqlx::query_as(
            "SELECT generation, policy_hash, public_key_digest, expected_state_hash, \
             artifact_digest, artifact_id, serial, \
             floor(extract(epoch FROM not_after))::bigint AS not_after_seconds \
             FROM device_certificate_authorized_artifacts \
             WHERE tenant_id = $1::uuid AND device_id = $2::uuid ORDER BY generation",
        )
        .bind(tenant)
        .bind(device)
        .fetch_all(&mut *self.conn)
        .await
        .map_err(storage)
    }

    async fn current_command_evidence_row(
        &mut self,
        fence: &CommandEvidenceFence,
    ) -> Result<Option<CurrentCommandEvidenceRow>, RepoError> {
        let tenant = tenant_param(fence.scope);
        let device = device_param(fence.scope);
        let target_id: Option<String> = sqlx::query_scalar(
            "SELECT target.target_id::text FROM reconcile_targets target \
             JOIN reconcile_attempts attempt ON attempt.tenant_id=target.tenant_id \
              AND attempt.target_id=target.target_id \
             JOIN reconcile_leases lease ON lease.tenant_id=target.tenant_id \
              AND lease.target_id=target.target_id \
             JOIN device_certificate_desired_states desired ON desired.tenant_id=target.tenant_id \
              AND desired.device_id::text=target.resource_id \
             WHERE target.tenant_id=$1::uuid AND target.reconciler_id=$2 \
              AND target.resource_kind=$3 AND target.resource_id=$4 \
              AND attempt.attempt_id=$5::uuid AND attempt.lease_token=$6::uuid \
              AND attempt.epoch=$7 AND attempt.claimed_wake_version=$8 \
              AND target.wake_version=$8 AND lease.lease_token=$6::uuid \
              AND lease.epoch=$7 AND lease.state='held' \
              AND lease.expires_at>pg_catalog.clock_timestamp() \
              AND desired.generation=$9 FOR UPDATE OF lease,target,desired",
        )
        .bind(&tenant)
        .bind(DEVICE_CERTIFICATE_RECONCILER_ID)
        .bind(DEVICE_CERTIFICATE_RESOURCE_KIND)
        .bind(&device)
        .bind(&fence.attempt_id)
        .bind(&fence.lease_token)
        .bind(fence.epoch)
        .bind(fence.wake_version)
        .bind(fence.expected_generation)
        .fetch_optional(&mut *self.conn)
        .await
        .map_err(storage)?;
        let Some(target_id) = target_id else {
            return Ok(None);
        };
        sqlx::query_as(
            r#"
            SELECT command.device_id::text AS device_id, command.generation,
                   command.fence_epoch, command.intent_digest,
                   attempt.attempt_id::text AS attempt_id,
                   extract(epoch FROM command.deadline)::bigint AS deadline_epoch_seconds,
                   outbox.payload
            FROM device_commands AS command
            JOIN outbox
              ON outbox.tenant_id = command.tenant_id
             AND outbox.event_id = command.command_id
            JOIN command_journal AS journal
              ON journal.tenant_id = command.tenant_id
             AND journal.command_id = command.command_id
             AND journal.outbox_event_id = outbox.event_id
             AND journal.topic = $6
             AND journal.contract_id = $7
             AND journal.contract_version = $8
             AND journal.schema_hash = $9
            JOIN reconcile_attempts AS attempt
              ON attempt.tenant_id = command.tenant_id
             AND attempt.attempt_id::text = outbox.causation_id
             AND attempt.target_id = $3::uuid
             AND attempt.epoch = command.fence_epoch
            JOIN reconcile_actions AS action
              ON action.tenant_id = attempt.tenant_id
             AND action.attempt_id = attempt.attempt_id
             AND action.target_id = attempt.target_id
             AND action.action_kind IN ('create', 'update')
             AND action.result_label = 'recorded'
            WHERE command.tenant_id = $1::uuid AND command.device_id = $2::uuid
              AND command.generation = $4
              AND command.state IN ('received', 'applied')
              AND outbox.domain = $5 AND outbox.topic = $6
              AND outbox.contract_id = $7 AND outbox.contract_version = $8
              AND outbox.schema_hash = $9
              AND outbox.metadata->>'tenantId' = $1
              AND outbox.metadata->>'subjectId' = command.device_id::text
              AND outbox.metadata#>>'{actor,kind}' = 'service'
              AND outbox.metadata#>>'{actor,id}' = 'rss.reconcile.device-certificate.v1'
              AND outbox.metadata#>>'{actor,scope}' = 'all'
            ORDER BY command.queued_at DESC, command.command_id DESC,
                     action.created_at, action.action_id
            LIMIT 1
            "#,
        )
        .bind(&tenant)
        .bind(&device)
        .bind(target_id)
        .bind(fence.expected_generation)
        .bind(DEVICE_CERTIFICATE_COMMAND_DOMAIN)
        .bind(DEVICE_CERTIFICATE_COMMAND_TOPIC)
        .bind(DEVICE_CERTIFICATE_COMMAND_CONTRACT_ID)
        .bind(DEVICE_CERTIFICATE_COMMAND_VERSION)
        .bind(DEVICE_CERTIFICATE_COMMAND_SCHEMA_HASH)
        .fetch_optional(&mut *self.conn)
        .await
        .map_err(storage)
    }

    async fn report_authority_for_update(
        &mut self,
        tenant: &str,
        device: &str,
    ) -> Result<Option<(i64, i64)>, RepoError> {
        let target_id: Option<String> = sqlx::query_scalar(
            "SELECT target_id::text FROM reconcile_targets \
             WHERE tenant_id = $1::uuid AND reconciler_id = $2 AND resource_kind = $3 \
               AND resource_id = $4 FOR UPDATE",
        )
        .bind(tenant)
        .bind(DEVICE_CERTIFICATE_RECONCILER_ID)
        .bind(DEVICE_CERTIFICATE_RESOURCE_KIND)
        .bind(device)
        .fetch_optional(&mut *self.conn)
        .await
        .map_err(storage)?;
        let Some(target_id) = target_id else {
            return Ok(None);
        };
        let epoch: Option<i64> = sqlx::query_scalar(
            "SELECT epoch FROM reconcile_leases \
             WHERE tenant_id = $1::uuid AND target_id = $2::uuid FOR UPDATE",
        )
        .bind(tenant)
        .bind(&target_id)
        .fetch_optional(&mut *self.conn)
        .await
        .map_err(storage)?;
        let Some(epoch) = epoch else {
            return Err(RepoError::ReconcileEnrollmentMissing);
        };
        let generation: Option<i64> = sqlx::query_scalar(
            "SELECT generation FROM device_certificate_desired_states \
             WHERE tenant_id = $1::uuid AND device_id = $2::uuid FOR UPDATE",
        )
        .bind(tenant)
        .bind(device)
        .fetch_optional(&mut *self.conn)
        .await
        .map_err(storage)?;
        Ok(generation.map(|generation| (generation, epoch)))
    }

    async fn reported_for_update(
        &mut self,
        tenant: &str,
        device: &str,
    ) -> Result<Option<ReportedRow>, RepoError> {
        // The authority rows above serialize writers before the SECURITY DEFINER funnel locks the
        // reported row. A serving role intentionally has no direct UPDATE privilege after 0087.
        select_reported(self.conn, tenant, device, false).await
    }

    async fn upsert_reported(
        &mut self,
        tenant: &str,
        device: &str,
        input: &ReportedStateWrite,
        observed: i64,
    ) -> Result<ReportedRow, RepoError> {
        let expires = optional_time_to_epoch_micros(input.expires_at())?;
        let observed_at = optional_time_to_epoch_micros(input.device_observed_at())?;
        sqlx::query_as::<_, ReportedRow>(
            "SELECT * FROM public.rss_upsert_device_certificate_report( \
                $1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10 \
             )",
        )
        .bind(tenant)
        .bind(device)
        .bind(observed)
        .bind(to_i64(input.fence_epoch().get())?)
        .bind(input.state_hash().as_bytes().as_slice())
        .bind(input.artifact_digest().as_bytes().as_slice())
        .bind(input.report_envelope_id().as_str())
        .bind(to_i64(input.device_sequence().get())?)
        .bind(expires)
        .bind(observed_at)
        .fetch_one(&mut *self.conn)
        .await
        .map_err(storage)
    }

    async fn conditions(
        &mut self,
        tenant: &str,
        device: &str,
    ) -> Result<Vec<DeviceConditionRestore>, RepoError> {
        select_conditions(self.conn, tenant, device).await
    }

    async fn desired(
        &mut self,
        tenant: &str,
        device: &str,
    ) -> Result<Option<DesiredRow>, RepoError> {
        select_desired(self.conn, tenant, device).await
    }
}

use crate::device_certificate_scope::{
    DEVICE_CERTIFICATE_RECONCILER_ID, DEVICE_CERTIFICATE_RESOURCE_KIND,
};

#[derive(sqlx::FromRow)]
struct PolicyAcceptFunnelRow {
    outcome: String,
    actual_generation: i64,
    target_id: Option<String>,
    wake_version: Option<i64>,
}

enum DevicePolicyAcceptTxOutcome {
    Accepted {
        result: DesiredPolicyAccepted,
        target_id: String,
        wake_version: WakeVersion,
    },
    Replayed(DesiredPolicyAccepted),
    ExpectedGenerationConflict(ExpectedGeneration),
    IdempotencyConflict,
}

#[derive(Debug, thiserror::Error)]
enum DevicePolicyTxError {
    #[error("device-policy transaction failed")]
    Repository(#[source] RepoError),
    #[error("device-policy reconcile enrollment is missing")]
    ReconcileEnrollmentMissing,
    #[error("device-policy reconcile target is quarantined")]
    ReconcileTargetQuarantined,
}

impl From<RepoError> for DevicePolicyTxError {
    fn from(error: RepoError) -> Self {
        Self::Repository(error)
    }
}

fn reconcile_storage(error: sqlx::Error) -> CertificateReconcileRepositoryError {
    CertificateReconcileRepositoryError::storage_unavailable(error)
}

fn reconcile_from_repo(error: RepoError) -> CertificateReconcileRepositoryError {
    match error {
        RepoError::InvalidMutation => CertificateReconcileRepositoryError::InvalidMutation,
        RepoError::CorruptState(source) => {
            CertificateReconcileRepositoryError::CorruptState(source)
        }
        RepoError::StorageUnavailable { source } => {
            CertificateReconcileRepositoryError::StorageUnavailable { source }
        }
        RepoError::ReconcileEnrollmentMissing | RepoError::ReconcileTargetQuarantined => {
            CertificateReconcileRepositoryError::InvalidMutation
        }
    }
}

fn restore_artifact_receipt(
    scope: DeviceCertificateScope,
    row: ArtifactReceiptRow,
) -> Result<PersistedCertificateArtifactSnapshot, CertificateReconcileRepositoryError> {
    let generation = ExpectedGeneration::restore(row.generation)
        .map_err(CertificateReconcileRepositoryError::CorruptState)?;
    let policy_hash = PolicyHash::restore(&row.policy_hash)
        .map_err(CertificateReconcileRepositoryError::CorruptState)?;
    let public_key_digest =
        CertificatePublicKeyDigest::restore(&row.public_key_digest).map_err(|_| {
            CertificateReconcileRepositoryError::CorruptState(
                DeviceCertificateError::InvalidPersistedValue,
            )
        })?;
    let artifact_digest = ArtifactDigest::restore(&row.artifact_digest)
        .map_err(CertificateReconcileRepositoryError::CorruptState)?;
    let state_hash = ReportedStateHash::restore(&row.expected_state_hash)
        .map_err(CertificateReconcileRepositoryError::CorruptState)?;
    let artifact_id = CertificateArtifactId::parse(&row.artifact_id).map_err(|_| {
        CertificateReconcileRepositoryError::CorruptState(
            DeviceCertificateError::InvalidPersistedValue,
        )
    })?;
    let serial = CertSerial::try_new(row.serial).map_err(|_| {
        CertificateReconcileRepositoryError::CorruptState(
            DeviceCertificateError::InvalidPersistedValue,
        )
    })?;
    let not_after = u64::try_from(row.not_after_seconds)
        .ok()
        .and_then(|seconds| UNIX_EPOCH.checked_add(Duration::from_secs(seconds)))
        .ok_or(CertificateReconcileRepositoryError::CorruptState(
            DeviceCertificateError::InvalidPersistedValue,
        ))
        .and_then(|value| {
            CertNotAfter::try_from_system_time(value).map_err(|_| {
                CertificateReconcileRepositoryError::CorruptState(
                    DeviceCertificateError::InvalidPersistedValue,
                )
            })
        })?;
    PersistedCertificateArtifactSnapshot::restore(
        scope,
        generation,
        policy_hash,
        public_key_digest,
        artifact_digest,
        state_hash,
        artifact_id,
        CertScope::new(scope.tenant(), scope.device()),
        serial,
        not_after,
    )
    .map_err(|_| {
        CertificateReconcileRepositoryError::CorruptState(
            DeviceCertificateError::InvalidPersistedValue,
        )
    })
}

fn restore_current_command_evidence(
    tenant: vocab::TenantId,
    row: CurrentCommandEvidenceRow,
) -> Result<DeviceCertificateCommandEvidence, CertificateReconcileRepositoryError> {
    let corrupt_evidence = || {
        CertificateReconcileRepositoryError::CorruptState(
            DeviceCertificateError::InvalidPersistedValue,
        )
    };
    let intent_digest: [u8; 32] = row
        .intent_digest
        .try_into()
        .map_err(|_| corrupt_evidence())?;
    let device_id = row.device_id.parse().map_err(|_| corrupt_evidence())?;
    let audit = DeviceCommandAuditProof::restore_durable(
        tenant,
        device_id,
        row.generation,
        row.fence_epoch,
        intent_digest,
        row.attempt_id,
    )
    .map_err(|_| corrupt_evidence())?;
    DeviceCertificateCommandEvidence::restore_durable(
        audit,
        &row.payload,
        row.deadline_epoch_seconds,
    )
    .map_err(|_| corrupt_evidence())
}

impl DevicePolicyTx<'_> {
    async fn accept_desired_policy(
        &mut self,
        tenant: &str,
        device: &str,
        input: AcceptDesiredPolicy,
        fail_after_desired_write: bool,
        fail_after_target_wake: bool,
    ) -> Result<DevicePolicyAcceptTxOutcome, DevicePolicyTxError> {
        let key = input.idempotency_key().as_uuid().to_string();
        let expected = to_i64(input.expected_generation().get())?;
        let next_generation = input.next_generation().map_err(corrupt)?;
        let next = to_i64(next_generation.get())?;
        let (validity, renew_before, client_auth, server_auth, sans) =
            policy_columns(input.policy());
        let row: PolicyAcceptFunnelRow = sqlx::query_as(
            "SELECT * FROM public.rss_accept_device_certificate_desired( \
             $1::uuid,$2::uuid,$3::uuid,$4,$5,$6,$7,$8,$9,$10,$11)",
        )
        .bind(tenant)
        .bind(device)
        .bind(&key)
        .bind(input.request_digest().as_bytes().as_slice())
        .bind(expected)
        .bind(next)
        .bind(validity)
        .bind(renew_before)
        .bind(client_auth)
        .bind(server_auth)
        .bind(sans)
        .fetch_one(&mut *self.conn)
        .await
        .map_err(storage)?;

        if fail_after_desired_write {
            return Err(DevicePolicyTxError::Repository(
                RepoError::storage_unavailable(std::io::Error::other(
                    "injected post-desired failure",
                )),
            ));
        }

        if fail_after_target_wake {
            return Err(DevicePolicyTxError::Repository(
                RepoError::storage_unavailable(std::io::Error::other(
                    "injected post-target-wake failure",
                )),
            ));
        }

        match row.outcome.as_str() {
            "accepted" => {
                let target_id = row.target_id.ok_or_else(invalid_persisted_value)?;
                let wake_version =
                    WakeVersion::restore(row.wake_version.ok_or_else(invalid_persisted_value)?)
                        .map_err(|_| invalid_persisted_value())?;
                Ok(DevicePolicyAcceptTxOutcome::Accepted {
                    result: DesiredPolicyAccepted::fresh(next_generation),
                    target_id,
                    wake_version,
                })
            }
            "replayed" => {
                let accepted_generation = DesiredGeneration::try_new(
                    u64::try_from(row.actual_generation).map_err(|_| invalid_persisted_value())?,
                )
                .map_err(DeviceCertificateError::from)
                .map_err(corrupt)?;
                Ok(DevicePolicyAcceptTxOutcome::Replayed(
                    DesiredPolicyAccepted::restore(
                        accepted_generation,
                        DesiredPolicyAcceptedCondition::Reconciling,
                    ),
                ))
            }
            "generation_conflict" => Ok(DevicePolicyAcceptTxOutcome::ExpectedGenerationConflict(
                ExpectedGeneration::restore(row.actual_generation).map_err(corrupt)?,
            )),
            "idempotency_conflict" => Ok(DevicePolicyAcceptTxOutcome::IdempotencyConflict),
            "missing_enrollment" => Err(DevicePolicyTxError::ReconcileEnrollmentMissing),
            "quarantined" => Err(DevicePolicyTxError::ReconcileTargetQuarantined),
            _ => Err(DevicePolicyTxError::Repository(invalid_persisted_value())),
        }
    }
}

impl DeviceCertificateRepository for PgDeviceCertificateRepository {
    #[tracing::instrument(
        name = "device_certificate.repository",
        skip_all,
        fields(
            component = "device_certificate_repository",
            operation = RepositoryOperation::AcceptDesiredPolicy.as_label()
        )
    )]
    async fn accept_desired_policy(
        &self,
        input: AcceptDesiredPolicy,
    ) -> Result<DesiredPolicyAcceptOutcome, RepoError> {
        let scope = input.scope();
        let tenant = tenant_param(scope);
        let device = device_param(scope);
        #[cfg(all(test, feature = "integration"))]
        let fail_after_desired_write = self.fail_after_desired_write;
        #[cfg(not(all(test, feature = "integration")))]
        let fail_after_desired_write = false;
        #[cfg(all(test, feature = "integration"))]
        let fail_after_target_wake = self.fail_after_target_wake;
        #[cfg(not(all(test, feature = "integration")))]
        let fail_after_target_wake = false;
        let outcome = self
            .write_pool
            .identity_write(
                scope,
                move |mut tx| {
                    Box::pin(async move {
                        let mut identity = tx.identity();
                        identity
                            .device_policy()
                            .accept_desired_policy(
                                &tenant,
                                &device,
                                input,
                                fail_after_desired_write,
                                fail_after_target_wake,
                            )
                            .await
                    })
                },
                |error| DevicePolicyTxError::Repository(storage(error)),
            )
            .await;
        match outcome {
            Ok(DevicePolicyAcceptTxOutcome::Accepted {
                result,
                target_id,
                wake_version,
            }) => Ok(DesiredPolicyAcceptOutcome::Accepted {
                result,
                wake: ReconcileWake::new(target_id, wake_version),
            }),
            Ok(DevicePolicyAcceptTxOutcome::Replayed(result)) => {
                Ok(DesiredPolicyAcceptOutcome::Replayed { result })
            }
            Ok(DevicePolicyAcceptTxOutcome::ExpectedGenerationConflict(actual)) => {
                Ok(DesiredPolicyAcceptOutcome::ExpectedGenerationConflict { actual })
            }
            Ok(DevicePolicyAcceptTxOutcome::IdempotencyConflict) => {
                Ok(DesiredPolicyAcceptOutcome::IdempotencyConflict)
            }
            Err(DevicePolicyTxError::ReconcileEnrollmentMissing) => {
                Err(RepoError::ReconcileEnrollmentMissing)
            }
            Err(DevicePolicyTxError::ReconcileTargetQuarantined) => {
                Err(RepoError::ReconcileTargetQuarantined)
            }
            Err(DevicePolicyTxError::Repository(error)) => Err(error),
        }
    }

    #[tracing::instrument(
        name = "device_certificate.repository",
        skip_all,
        fields(
            component = "device_certificate_repository",
            operation = RepositoryOperation::AdvanceReported.as_label()
        )
    )]
    async fn advance_reported(
        &self,
        input: ReportedStateWrite,
    ) -> Result<ReportedWriteOutcome, RepoError> {
        let scope = input.scope();
        let tenant = tenant_param(scope);
        let device = device_param(scope);
        self.write_pool
            .identity_write(
                scope,
                move |mut tx| {
                    Box::pin(async move {
                        let mut identity = tx.identity();
                        let mut tx = identity.device_certificates();
                        let Some((desired_generation, authority_epoch)) =
                            tx.report_authority_for_update(&tenant, &device).await?
                        else {
                            return Ok(ReportedWriteOutcome::MissingDesired);
                        };
                        let observed = to_i64(input.observed_generation().get())?;
                        if observed > desired_generation {
                            return Ok(ReportedWriteOutcome::AheadOfDesired);
                        }
                        if observed < desired_generation {
                            return Ok(ReportedWriteOutcome::StaleGeneration);
                        }
                        if to_i64(input.fence_epoch().get())? != authority_epoch {
                            return Err(RepoError::InvalidMutation);
                        }
                        let current = tx.reported_for_update(&tenant, &device).await?;
                        if let Some(row) = &current {
                            if observed < row.observed_generation {
                                return Ok(ReportedWriteOutcome::StaleGeneration);
                            }
                            if observed == row.observed_generation {
                                return Ok(if reported_payload_equal(row, &input)? {
                                    ReportedWriteOutcome::Duplicate
                                } else {
                                    ReportedWriteOutcome::StateConflict
                                });
                            }
                            if to_i64(input.device_sequence().get())? <= row.device_sequence {
                                return Ok(ReportedWriteOutcome::StaleSequence);
                            }
                        }
                        let row = tx
                            .upsert_reported(&tenant, &device, &input, observed)
                            .await?;
                        Ok(ReportedWriteOutcome::Applied(
                            ReportedStateSnapshot::restore(restore_reported(row)?)
                                .map_err(corrupt)?,
                        ))
                    })
                },
                storage,
            )
            .await
    }

    #[tracing::instrument(
        name = "device_certificate.repository",
        skip_all,
        fields(
            component = "device_certificate_repository",
            operation = RepositoryOperation::LoadState.as_label()
        )
    )]
    async fn load_state(
        &self,
        scope: DeviceCertificateScope,
    ) -> Result<Option<DeviceCertificateStateSnapshot>, RepoError> {
        let tenant = tenant_param(scope);
        let device = device_param(scope);
        #[cfg(all(test, feature = "integration"))]
        let load_snapshot_hook = self.load_snapshot_hook.clone();
        self.read_pool
            .identity_repeatable_read_map(
                scope,
                move |mut tx| {
                    Box::pin(async move {
                        let mut identity = tx.identity();
                        let mut tx = identity.device_certificates();
                        let Some(desired) = tx.desired(&tenant, &device).await? else {
                            return Ok(None);
                        };
                        #[cfg(all(test, feature = "integration"))]
                        if let Some(hook) = load_snapshot_hook {
                            hook.desired_loaded.notify_one();
                            hook.resume.notified().await;
                        }
                        let reported = tx
                            .reported(&tenant, &device)
                            .await?
                            .map(restore_reported)
                            .transpose()?;
                        let conditions = tx.conditions(&tenant, &device).await?;
                        DeviceCertificateStateSnapshot::restore(
                            scope,
                            restore_desired(desired)?,
                            reported,
                            conditions,
                        )
                        .map(Some)
                        .map_err(corrupt)
                    })
                },
                storage,
            )
            .await
    }
}

impl CertificateReconcileRepository for PgDeviceCertificateRepository {
    async fn load_current_view(
        &self,
        authority: &CertificateAttemptAuthority,
    ) -> Result<Option<CertificateReconcileView>, CertificateReconcileRepositoryError> {
        let authority = authority.clone();
        let scope = authority.scope();
        let tenant = tenant_param(scope);
        let device = device_param(scope);
        self.write_pool
            .identity_write(
                scope,
                move |mut identity| {
                    Box::pin(async move {
                        let mut identity_write = identity.identity();
                        let mut certificates = identity_write.device_certificates();
                        let deletion_requested: Option<bool> = sqlx::query_scalar(
                            "SELECT desired.deletion_requested_at IS NOT NULL \
                             FROM reconcile_targets target \
                             JOIN reconcile_attempts attempt USING (tenant_id,target_id) \
                             JOIN reconcile_leases lease USING (tenant_id,target_id) \
                             JOIN device_certificate_desired_states desired \
                               ON desired.tenant_id=target.tenant_id \
                              AND desired.device_id::text=target.resource_id \
                             WHERE target.tenant_id=$1::uuid AND target.target_id=$2::uuid \
                               AND target.reconciler_id=$3 AND target.resource_kind=$4 \
                               AND target.resource_id=$5 AND attempt.attempt_id=$6::uuid \
                               AND attempt.lease_token=$7::uuid AND attempt.epoch=$8 \
                               AND attempt.claimed_wake_version=$9 AND target.wake_version=$9 \
                               AND lease.lease_token=$7::uuid AND lease.epoch=$8 \
                               AND lease.state='held' \
                               AND lease.expires_at>pg_catalog.clock_timestamp() \
                             FOR UPDATE OF target,lease,desired",
                        )
                        .bind(&tenant)
                        .bind(authority.target_id())
                        .bind(DEVICE_CERTIFICATE_RECONCILER_ID)
                        .bind(DEVICE_CERTIFICATE_RESOURCE_KIND)
                        .bind(&device)
                        .bind(authority.attempt_id())
                        .bind(authority.lease_token())
                        .bind(to_i64(authority.epoch().get()).map_err(reconcile_from_repo)?)
                        .bind(to_i64(authority.wake_version().get()).map_err(reconcile_from_repo)?)
                        .fetch_optional(&mut *certificates.conn)
                        .await
                        .map_err(reconcile_storage)?;
                        let Some(deletion_requested) = deletion_requested else {
                            return Ok(None);
                        };
                        let state = certificates
                            .reconcile_snapshot_with_ready_evidence(
                                &authority, scope, &tenant, &device,
                            )
                            .await
                            .map_err(reconcile_from_repo)?
                            .ok_or(CertificateReconcileRepositoryError::InvalidMutation)?;
                        CertificateReconcileView::restore_current(
                            &authority,
                            state,
                            deletion_requested,
                            // This inactive constructor only proves the durable command-authoring
                            // path is available. It is deliberately not a device-online inference;
                            // activation may supply `Unavailable` from an authoritative provider.
                            CertificateTransportObservation::Available,
                        )
                        .map(Some)
                        .map_err(CertificateReconcileRepositoryError::CorruptState)
                    })
                },
                reconcile_storage,
            )
            .await
    }

    async fn load_artifact_receipts(
        &self,
        fence: &CertificateAttemptFence,
    ) -> Result<Vec<PersistedCertificateArtifactSnapshot>, CertificateReconcileRepositoryError>
    {
        let fence = fence.clone();
        let scope = fence.scope();
        let tenant = tenant_param(scope);
        let device = device_param(scope);
        self.write_pool
            .identity_write(
                scope,
                move |mut identity| {
                    Box::pin(async move {
                        let mut identity_write = identity.identity();
                        let mut certificates = identity_write.device_certificates();
                        if certificates
                            .reconcile_fence_target(&fence)
                            .await
                            .map_err(reconcile_from_repo)?
                            .is_none()
                        {
                            return Ok(Vec::new());
                        }
                        certificates
                            .artifact_rows(&tenant, &device)
                            .await
                            .map_err(reconcile_from_repo)?
                            .into_iter()
                            .map(|row| restore_artifact_receipt(scope, row))
                            .collect()
                    })
                },
                reconcile_storage,
            )
            .await
    }

    async fn load_current_command_evidence(
        &self,
        fence: &CertificateAttemptFence,
    ) -> Result<Option<DeviceCertificateCommandEvidence>, CertificateReconcileRepositoryError> {
        let fence = CommandEvidenceFence::from_domain(fence).map_err(reconcile_from_repo)?;
        let scope = fence.scope;
        self.write_pool
            .identity_write(
                scope,
                move |mut identity| {
                    Box::pin(async move {
                        let mut identity_write = identity.identity();
                        let mut certificates = identity_write.device_certificates();
                        let Some(row) = certificates
                            .current_command_evidence_row(&fence)
                            .await
                            .map_err(reconcile_from_repo)?
                        else {
                            return Ok(None);
                        };
                        restore_current_command_evidence(scope.tenant(), row).map(Some)
                    })
                },
                reconcile_storage,
            )
            .await
    }

    async fn append_artifact_receipt(
        &self,
        fence: &CertificateAttemptFence,
        authorization: ArtifactAppendAuthorization,
    ) -> Result<ArtifactAppendOutcome, CertificateReconcileRepositoryError> {
        let receipt = authorization.into_snapshot();
        if receipt.scope() != fence.scope() || receipt.generation() != fence.expected_generation() {
            return Err(CertificateReconcileRepositoryError::InvalidMutation);
        }
        let fence = fence.clone();
        let scope = fence.scope();
        let tenant = tenant_param(scope);
        let device = device_param(scope);
        self.write_pool
            .identity_write(
                scope,
                move |mut identity| {
                    Box::pin(async move {
                        let mut identity_write = identity.identity();
                        let certificates = identity_write.device_certificates();
                        let outcome: String = sqlx::query_scalar(
                            "SELECT public.rss_append_device_certificate_artifact( \
                                $1::uuid,$2::uuid,$3::uuid,$4::uuid,$5,$6,$7, \
                                $8,$9,$10,$11,$12,$13,$14)",
                        )
                        .bind(&tenant)
                        .bind(&device)
                        .bind(fence.attempt_id())
                        .bind(fence.lease_token())
                        .bind(to_i64(fence.epoch().get()).map_err(reconcile_from_repo)?)
                        .bind(to_i64(fence.wake_version().get()).map_err(reconcile_from_repo)?)
                        .bind(to_i64(receipt.generation().get()).map_err(reconcile_from_repo)?)
                        .bind(receipt.policy_hash().as_bytes().as_slice())
                        .bind(receipt.public_key_digest().as_bytes().as_slice())
                        .bind(receipt.expected_reported_state_hash().as_bytes().as_slice())
                        .bind(receipt.artifact_digest().as_bytes().as_slice())
                        .bind(receipt.artifact_id().as_str())
                        .bind(receipt.serial().as_bytes())
                        .bind(receipt.not_after().unix_seconds())
                        .fetch_one(&mut *certificates.conn)
                        .await
                        .map_err(reconcile_storage)?;
                        match outcome.as_str() {
                            "appended" => Ok(ArtifactAppendOutcome::Appended),
                            "replayed" => Ok(ArtifactAppendOutcome::Replayed),
                            "conflict" => Ok(ArtifactAppendOutcome::Conflict),
                            "stale_fence" => Ok(ArtifactAppendOutcome::StaleFence),
                            _ => Err(CertificateReconcileRepositoryError::InvalidMutation),
                        }
                    })
                },
                reconcile_storage,
            )
            .await
    }

    async fn write_conditions(
        &self,
        fence: &CertificateAttemptFence,
        conditions: CertificateConditionMutation,
    ) -> Result<FencedMutationOutcome, CertificateReconcileRepositoryError> {
        let fence = fence.clone();
        let scope = fence.scope();
        let tenant = tenant_param(scope);
        let device = device_param(scope);
        self.write_pool
            .identity_write(
                scope,
                move |mut identity| {
                    Box::pin(async move {
                        let mut identity_write = identity.identity();
                        let certificates = identity_write.device_certificates();
                        match conditions {
                            CertificateConditionMutation::States(batch) => {
                                let states = batch.into_states();
                                let condition_types = states
                                    .iter()
                                    .map(|state| state.kind().as_label().to_owned())
                                    .collect::<Vec<_>>();
                                let statuses = states
                                    .iter()
                                    .map(|state| state.status_label().to_owned())
                                    .collect::<Vec<_>>();
                                let reasons = states
                                    .iter()
                                    .map(|state| state.reason_label().to_owned())
                                    .collect::<Vec<_>>();
                                let observed_generations = states
                                    .iter()
                                    .map(|state| {
                                        state
                                            .observed_generation()
                                            .map(|value| to_i64(value.get()))
                                            .transpose()
                                            .map_err(reconcile_from_repo)
                                    })
                                    .collect::<Result<Vec<_>, _>>()?;
                                let applied: bool = sqlx::query_scalar(
                                    "SELECT public.rss_write_device_certificate_conditions( \
                             $1::uuid,$2::uuid,$3::uuid,$4::uuid,$5,$6,$7,$8,$9,$10,$11)",
                                )
                                .bind(&tenant)
                                .bind(&device)
                                .bind(fence.attempt_id())
                                .bind(fence.lease_token())
                                .bind(to_i64(fence.epoch().get()).map_err(reconcile_from_repo)?)
                                .bind(
                                    to_i64(fence.wake_version().get())
                                        .map_err(reconcile_from_repo)?,
                                )
                                .bind(
                                    to_i64(fence.expected_generation().get())
                                        .map_err(reconcile_from_repo)?,
                                )
                                .bind(condition_types)
                                .bind(statuses)
                                .bind(reasons)
                                .bind(observed_generations)
                                .fetch_one(&mut *certificates.conn)
                                .await
                                .map_err(reconcile_storage)?;
                                if !applied {
                                    return Ok(FencedMutationOutcome::StaleFence);
                                }
                            }
                            CertificateConditionMutation::Ready(proof) => {
                                if proof.scope() != scope
                                    || proof.generation() != fence.expected_generation()
                                {
                                    return Err(
                                        CertificateReconcileRepositoryError::InvalidMutation,
                                    );
                                }
                                let applied: bool = sqlx::query_scalar(
                                    "SELECT public.rss_mark_device_certificate_ready( \
                         $1::uuid,$2::uuid,$3::uuid,$4::uuid,$5,$6,$7,$8,$9,$10, \
                         $11,$12,$13,$14,$15,$16,$17,$18,$19,$20)",
                                )
                                .bind(&tenant)
                                .bind(&device)
                                .bind(fence.attempt_id())
                                .bind(fence.lease_token())
                                .bind(to_i64(fence.epoch().get()).map_err(reconcile_from_repo)?)
                                .bind(
                                    to_i64(fence.wake_version().get())
                                        .map_err(reconcile_from_repo)?,
                                )
                                .bind(
                                    to_i64(proof.generation().get())
                                        .map_err(reconcile_from_repo)?,
                                )
                                .bind(
                                    to_i64(proof.fence_epoch().get())
                                        .map_err(reconcile_from_repo)?,
                                )
                                .bind(proof.intent_digest().as_bytes().as_slice())
                                .bind(proof.artifact_id().as_str())
                                .bind(proof.artifact_digest().as_bytes().as_slice())
                                .bind(proof.policy_hash().as_bytes().as_slice())
                                .bind(proof.state_hash().as_bytes().as_slice())
                                .bind(proof.report_envelope_id().as_str())
                                .bind(
                                    to_i64(proof.device_sequence().get())
                                        .map_err(reconcile_from_repo)?,
                                )
                                .bind(
                                    time_to_epoch_micros(proof.report_received_at())
                                        .map_err(reconcile_from_repo)?,
                                )
                                .bind(proof.serial().as_bytes())
                                .bind(proof.not_after().unix_seconds())
                                .bind(
                                    time_to_epoch_seconds(proof.authoritative_now())
                                        .map_err(reconcile_from_repo)?,
                                )
                                // Audit coordinate only: the database recomputes the enforced
                                // renew boundary from desired.renew_before_seconds.
                                .bind(
                                    time_to_epoch_seconds(proof.renew_at())
                                        .map_err(reconcile_from_repo)?,
                                )
                                .fetch_one(&mut *certificates.conn)
                                .await
                                .map_err(reconcile_storage)?;
                                if !applied {
                                    return Ok(FencedMutationOutcome::StaleFence);
                                }
                            }
                        }
                        Ok(FencedMutationOutcome::Applied)
                    })
                },
                reconcile_storage,
            )
            .await
    }

    async fn rotate_generation(
        &self,
        fence: &CertificateAttemptFence,
    ) -> Result<RotationOutcome, CertificateReconcileRepositoryError> {
        if fence.expected_generation().get() == i64::MAX as u64 {
            return Ok(RotationOutcome::GenerationExhausted);
        }
        let fence = fence.clone();
        let scope = fence.scope();
        let tenant = tenant_param(scope);
        let device = device_param(scope);
        self.write_pool
            .identity_write(
                scope,
                move |mut identity| {
                    Box::pin(async move {
                        let mut identity_write = identity.identity();
                        let certificates = identity_write.device_certificates();
                        let row = sqlx::query_as::<_, RotationFunnelRow>(
                            "SELECT * FROM public.rss_rotate_device_certificate_generation( \
                             $1::uuid,$2::uuid,$3::uuid,$4::uuid,$5,$6,$7)",
                        )
                        .bind(&tenant)
                        .bind(&device)
                        .bind(fence.attempt_id())
                        .bind(fence.lease_token())
                        .bind(to_i64(fence.epoch().get()).map_err(reconcile_from_repo)?)
                        .bind(to_i64(fence.wake_version().get()).map_err(reconcile_from_repo)?)
                        .bind(
                            to_i64(fence.expected_generation().get())
                                .map_err(reconcile_from_repo)?,
                        )
                        .fetch_optional(&mut *certificates.conn)
                        .await
                        .map_err(reconcile_storage)?;
                        let Some(row) = row else {
                            return Ok(RotationOutcome::StaleFence);
                        };
                        let version = WakeVersion::restore(row.wake_version)
                            .map_err(|_| CertificateReconcileRepositoryError::InvalidMutation)?;
                        Ok(RotationOutcome::Rotated {
                            generation: ExpectedGeneration::restore(row.next_generation)
                                .map_err(CertificateReconcileRepositoryError::CorruptState)?,
                            wake: ReconcileWake::new(row.target_id, version),
                        })
                    })
                },
                reconcile_storage,
            )
            .await
    }

    async fn request_deletion(
        &self,
        fence: &CertificateAttemptFence,
    ) -> Result<DeletionRequestOutcome, CertificateReconcileRepositoryError> {
        let fence = fence.clone();
        let scope = fence.scope();
        let tenant = tenant_param(scope);
        let device = device_param(scope);
        self.write_pool
            .identity_write(
                scope,
                move |mut identity| {
                    Box::pin(async move {
                        let mut identity_write = identity.identity();
                        let certificates = identity_write.device_certificates();
                        let row: DeletionFunnelRow = sqlx::query_as(
                            "SELECT * FROM public.rss_request_device_certificate_deletion( \
                             $1::uuid,$2::uuid,$3::uuid,$4::uuid,$5,$6,$7)",
                        )
                        .bind(&tenant)
                        .bind(&device)
                        .bind(fence.attempt_id())
                        .bind(fence.lease_token())
                        .bind(to_i64(fence.epoch().get()).map_err(reconcile_from_repo)?)
                        .bind(to_i64(fence.wake_version().get()).map_err(reconcile_from_repo)?)
                        .bind(
                            to_i64(fence.expected_generation().get())
                                .map_err(reconcile_from_repo)?,
                        )
                        .fetch_one(&mut *certificates.conn)
                        .await
                        .map_err(reconcile_storage)?;
                        match row.outcome.as_str() {
                            "stale_fence" => Ok(DeletionRequestOutcome::StaleFence),
                            "replayed" => Ok(DeletionRequestOutcome::Replayed),
                            "requested" => {
                                let target_id = row
                                    .target_id
                                    .ok_or(CertificateReconcileRepositoryError::InvalidMutation)?;
                                let version =
                                    WakeVersion::restore(row.wake_version.ok_or(
                                        CertificateReconcileRepositoryError::InvalidMutation,
                                    )?)
                                    .map_err(|_| {
                                        CertificateReconcileRepositoryError::InvalidMutation
                                    })?;
                                Ok(DeletionRequestOutcome::Requested(ReconcileWake::new(
                                    target_id, version,
                                )))
                            }
                            _ => Err(CertificateReconcileRepositoryError::InvalidMutation),
                        }
                    })
                },
                reconcile_storage,
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durable_command_query_contract_identity_matches_generated_authority() {
        let contract = generated::command::identity_v1::CONTRACT;
        assert_eq!(DEVICE_CERTIFICATE_COMMAND_DOMAIN, contract.domain());
        assert_eq!(
            DEVICE_CERTIFICATE_COMMAND_TOPIC,
            generated::command::identity_v1::TOPIC
        );
        assert_eq!(
            DEVICE_CERTIFICATE_COMMAND_CONTRACT_ID,
            contract.contract_id()
        );
        assert_eq!(DEVICE_CERTIFICATE_COMMAND_VERSION, contract.version());
        assert_eq!(
            DEVICE_CERTIFICATE_COMMAND_SCHEMA_HASH,
            contract.schema_hash()
        );
    }

    #[test]
    fn repository_operation_labels_are_closed() {
        assert_eq!(
            [
                RepositoryOperation::AcceptDesiredPolicy.as_label(),
                RepositoryOperation::AdvanceReported.as_label(),
                RepositoryOperation::LoadState.as_label(),
            ],
            ["accept_desired_policy", "advance_reported", "load_state"]
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: unit fixture asserts codec round-trip on fixed micros; panic is the failure signal.
    fn epoch_micros_codec_preserves_both_sides_of_epoch() {
        for micros in [-1_i64, 0, 1, 1_700_000_000_123_456] {
            let restored = epoch_micros_to_time(micros).expect("bounded timestamp");
            assert!(matches!(time_to_epoch_micros(restored), Ok(value) if value == micros));
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: unit fixture requires a SystemTime below PostgreSQL range; panic if platform cannot form it.
    fn report_time_outside_postgres_range_is_an_invalid_mutation() {
        let before_postgres_epoch = UNIX_EPOCH
            .checked_sub(Duration::from_micros(210_866_803_200_000_001))
            .expect("platform SystemTime supports PostgreSQL lower-bound probe");
        assert!(matches!(
            time_to_epoch_micros(before_postgres_epoch),
            Err(RepoError::InvalidMutation)
        ));
    }
}

#[cfg(all(test, feature = "integration"))]
mod integration_tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use deviceloop::{CertificatePolicy, FenceEpoch, ObservedGeneration};
    use diport::ManagedResource as _;
    use identity::ports::device_certificate::{
        AcceptDesiredPolicy, ArtifactDigest, DesiredPolicyAcceptOutcome,
        DeviceCertificateRepository as _, DeviceCertificateRepositoryError, DeviceCertificateScope,
        DevicePolicyIdempotencyKey, DeviceSequence, ExpectedGeneration, ReportEnvelopeId,
        ReportedStateHash, ReportedStateWrite, ReportedWriteOutcome,
    };

    use super::PgDeviceCertificateRepository;
    use crate::reconcile::ReconcileTargetKey;

    type TestError = Box<dyn std::error::Error + Send + Sync>;
    type TestResult = Result<(), TestError>;

    fn scope() -> DeviceCertificateScope {
        DeviceCertificateScope::for_test(
            vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap(),
            ids::DeviceId::new(uuid::Uuid::new_v4()),
        )
    }

    fn policy(san: &str) -> CertificatePolicy {
        CertificatePolicy::restore(
            3_600,
            600,
            vec!["clientAuth".to_owned(), "serverAuth".to_owned()],
            vec![san.to_owned()],
        )
        .unwrap()
    }

    fn desired(scope: DeviceCertificateScope, expected: u64, san: &str) -> AcceptDesiredPolicy {
        desired_with_key(
            scope,
            expected,
            DevicePolicyIdempotencyKey::new(uuid::Uuid::new_v4()),
            san,
        )
    }

    fn desired_with_key(
        scope: DeviceCertificateScope,
        expected: u64,
        key: DevicePolicyIdempotencyKey,
        san: &str,
    ) -> AcceptDesiredPolicy {
        AcceptDesiredPolicy::for_test(
            scope,
            ExpectedGeneration::try_new(expected).unwrap(),
            key,
            policy(san),
        )
        .unwrap()
    }

    async fn precreate_reconcile_target(
        store: &crate::PgStore,
        scope: DeviceCertificateScope,
    ) -> Result<String, TestError> {
        let key = ReconcileTargetKey::parse(
            super::DEVICE_CERTIFICATE_RECONCILER_ID,
            super::DEVICE_CERTIFICATE_RESOURCE_KIND,
            scope.device().as_uuid().to_string(),
        )?;
        let target = store
            .reconcile()
            .upsert_target(scope.tenant(), &key)
            .await?;
        Ok(target.target_id().to_owned())
    }

    async fn set_reconcile_epoch(
        store: &crate::PgStore,
        scope: DeviceCertificateScope,
        epoch: i64,
    ) -> Result<(), TestError> {
        sqlx::query(
            "UPDATE reconcile_leases AS lease SET epoch = $3 \
             FROM reconcile_targets AS target \
             WHERE lease.tenant_id = target.tenant_id AND lease.target_id = target.target_id \
               AND target.tenant_id = $1::uuid AND target.resource_id = $2",
        )
        .bind(scope.tenant().as_uuid().to_string())
        .bind(scope.device().as_uuid().to_string())
        .bind(epoch)
        .execute(&store.pool)
        .await?;
        Ok(())
    }

    fn digest(label: char) -> String {
        format!("sha256:{}", label.to_string().repeat(64))
    }

    fn report(
        scope: DeviceCertificateScope,
        generation: u64,
        sequence: u64,
        state: char,
        artifact: char,
        envelope: &str,
    ) -> ReportedStateWrite {
        ReportedStateWrite::for_test(
            scope,
            ObservedGeneration::try_new(generation).unwrap(),
            FenceEpoch::try_new(41).unwrap(),
            ReportedStateHash::parse(&digest(state)).unwrap(),
            ArtifactDigest::parse(&digest(artifact)).unwrap(),
            ReportEnvelopeId::parse(envelope).unwrap(),
            DeviceSequence::try_new(sequence).unwrap(),
            None,
            None,
        )
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn desired_accept_has_one_winner_and_write_fault_rolls_back() -> TestResult {
        let (_pg, store) = crate::test_pg::connect_pg().await?;
        store.run_migrations().await?;
        let race_scope = scope();
        precreate_reconcile_target(&store, race_scope).await?;
        let left = PgDeviceCertificateRepository::from_unverified_for_test(&store);
        let right = PgDeviceCertificateRepository::from_unverified_for_test(&store);
        let (left, right) = tokio::join!(
            left.accept_desired_policy(desired(race_scope, 0, "a.example")),
            right.accept_desired_policy(desired(race_scope, 0, "b.example")),
        );
        let outcomes = [left?, right?];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, DesiredPolicyAcceptOutcome::Accepted { .. }))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(
                    outcome,
                    DesiredPolicyAcceptOutcome::ExpectedGenerationConflict { actual }
                        if actual.get() == 1
                ))
                .count(),
            1
        );

        let rollback_scope = scope();
        precreate_reconcile_target(&store, rollback_scope).await?;
        let faulted = PgDeviceCertificateRepository::from_unverified_for_test(&store)
            .with_desired_write_fault_for_test();
        assert!(
            faulted
                .accept_desired_policy(desired(rollback_scope, 0, "rollback.example"))
                .await
                .is_err()
        );
        let reader = PgDeviceCertificateRepository::from_unverified_for_test(&store);
        assert!(reader.load_state(rollback_scope).await?.is_none());

        drop((faulted, reader));
        store.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn desired_accept_replays_without_writes_and_conflicts_roll_back_the_bundle() -> TestResult
    {
        let (fixture, owner) = crate::test_pg::connect_pg().await?;
        owner.run_migrations().await?;
        let writer = crate::test_pg::connect_pg_rss_app_role(&fixture, &owner).await?;
        let reader = crate::test_pg::connect_pg_rss_app_read_role(&fixture, &owner).await?;
        let repo = PgDeviceCertificateRepository::from_unverified_stores_for_test(&reader, &writer);
        let target = scope();
        precreate_reconcile_target(&owner, target).await?;
        let key = DevicePolicyIdempotencyKey::new(uuid::Uuid::new_v4());
        let request = desired_with_key(target, 0, key, "replay.example");
        let accepted = repo.accept_desired_policy(request.clone()).await?;
        let wake = match accepted {
            DesiredPolicyAcceptOutcome::Accepted { result, wake } => {
                assert_eq!(result.accepted_generation().get(), 1);
                wake
            }
            other => {
                return Err(std::io::Error::other(format!(
                    "first policy accept must commit, got {other:?}"
                ))
                .into());
            }
        };
        assert_eq!(wake.version().get(), 1);

        let before: (String, String, i64, String, String) = sqlx::query_as(
            "SELECT to_jsonb(desired)::text, desired.xmin::text, \
                    (SELECT count(*) FROM device_certificate_policy_operations op \
                     WHERE op.tenant_id = desired.tenant_id AND op.device_id = desired.device_id), \
                    to_jsonb(target)::text, target.xmin::text \
             FROM device_certificate_desired_states desired \
             JOIN reconcile_targets target \
               ON target.tenant_id = desired.tenant_id \
              AND target.resource_id = desired.device_id::text \
              AND target.reconciler_id = 'identity.device-certificate' \
              AND target.resource_kind = 'device-certificate' \
             WHERE desired.tenant_id = $1::uuid AND desired.device_id = $2::uuid",
        )
        .bind(target.tenant().as_uuid().to_string())
        .bind(target.device().as_uuid().to_string())
        .fetch_one(&owner.pool)
        .await?;

        assert!(matches!(
            repo.accept_desired_policy(request).await?,
            DesiredPolicyAcceptOutcome::Replayed { ref result }
                if result.accepted_generation().get() == 1
        ));
        assert!(matches!(
            repo.accept_desired_policy(desired_with_key(target, 0, key, "different.example",))
                .await?,
            DesiredPolicyAcceptOutcome::IdempotencyConflict
        ));
        assert!(matches!(
            repo.accept_desired_policy(desired(target, 0, "stale-generation.example"))
                .await?,
            DesiredPolicyAcceptOutcome::ExpectedGenerationConflict { actual }
                if actual.get() == 1
        ));
        let same_target_faulted =
            PgDeviceCertificateRepository::from_unverified_stores_for_test(&reader, &writer)
                .with_target_wake_fault_for_test();
        assert!(
            same_target_faulted
                .accept_desired_policy(desired(target, 1, "same-target-fault.example"))
                .await
                .is_err()
        );
        let after: (String, String, i64, String, String) = sqlx::query_as(
            "SELECT to_jsonb(desired)::text, desired.xmin::text, \
                    (SELECT count(*) FROM device_certificate_policy_operations op \
                     WHERE op.tenant_id = desired.tenant_id AND op.device_id = desired.device_id), \
                    to_jsonb(target)::text, target.xmin::text \
             FROM device_certificate_desired_states desired \
             JOIN reconcile_targets target \
               ON target.tenant_id = desired.tenant_id \
              AND target.resource_id = desired.device_id::text \
              AND target.reconciler_id = 'identity.device-certificate' \
              AND target.resource_kind = 'device-certificate' \
             WHERE desired.tenant_id = $1::uuid AND desired.device_id = $2::uuid",
        )
        .bind(target.tenant().as_uuid().to_string())
        .bind(target.device().as_uuid().to_string())
        .fetch_one(&owner.pool)
        .await?;
        assert_eq!(
            after, before,
            "replay, both conflict families, and injected fault must perform zero writes"
        );

        let same_tenant_other_device = DeviceCertificateScope::for_test(
            target.tenant(),
            ids::DeviceId::new(uuid::Uuid::new_v4()),
        );
        let other_tenant = scope();
        for independent_scope in [same_tenant_other_device, other_tenant] {
            precreate_reconcile_target(&owner, independent_scope).await?;
            assert!(matches!(
                repo.accept_desired_policy(desired_with_key(
                    independent_scope,
                    0,
                    key,
                    "independent-key.example",
                ))
                .await?,
                DesiredPolicyAcceptOutcome::Accepted { .. }
            ));
        }

        let absent = scope();
        assert!(matches!(
            repo.accept_desired_policy(desired(absent, 1, "generation-conflict.example"))
                .await?,
            DesiredPolicyAcceptOutcome::ExpectedGenerationConflict { actual }
                if actual.get() == 0
        ));
        let absent_rows: i64 = sqlx::query_scalar(
            "SELECT \
                (SELECT count(*) FROM device_certificate_desired_states \
                 WHERE tenant_id = $1::uuid AND device_id = $2::uuid) + \
                (SELECT count(*) FROM device_certificate_policy_operations \
                 WHERE tenant_id = $1::uuid AND device_id = $2::uuid) + \
                (SELECT count(*) FROM reconcile_targets \
                 WHERE tenant_id = $1::uuid AND resource_id = $2::uuid::text)",
        )
        .bind(absent.tenant().as_uuid().to_string())
        .bind(absent.device().as_uuid().to_string())
        .fetch_one(&owner.pool)
        .await?;
        assert_eq!(absent_rows, 0, "generation conflict must write no rows");

        let missing_target = scope();
        assert!(matches!(
            repo.accept_desired_policy(desired(missing_target, 0, "missing-target.example"))
                .await,
            Err(DeviceCertificateRepositoryError::ReconcileEnrollmentMissing)
        ));
        let missing_rows: i64 = sqlx::query_scalar(
            "SELECT \
                (SELECT count(*) FROM device_certificate_desired_states \
                 WHERE tenant_id = $1::uuid AND device_id = $2::uuid) + \
                (SELECT count(*) FROM device_certificate_policy_operations \
                 WHERE tenant_id = $1::uuid AND device_id = $2::uuid) + \
                (SELECT count(*) FROM reconcile_targets \
                 WHERE tenant_id = $1::uuid AND resource_id = $2::uuid::text)",
        )
        .bind(missing_target.tenant().as_uuid().to_string())
        .bind(missing_target.device().as_uuid().to_string())
        .fetch_one(&owner.pool)
        .await?;
        assert_eq!(
            missing_rows, 0,
            "missing target failure must roll back desired state"
        );

        let incomplete = scope();
        let incomplete_before: (String, String) = sqlx::query_as(
            "INSERT INTO reconcile_targets \
                (tenant_id, reconciler_id, resource_kind, resource_id) \
             VALUES ($1::uuid, 'identity.device-certificate', 'device-certificate', \
                     $2::uuid::text) \
             RETURNING to_jsonb(reconcile_targets)::text, xmin::text",
        )
        .bind(incomplete.tenant().as_uuid().to_string())
        .bind(incomplete.device().as_uuid().to_string())
        .fetch_one(&owner.pool)
        .await?;
        assert!(matches!(
            repo.accept_desired_policy(desired(incomplete, 0, "missing-lease.example"))
                .await,
            Err(DeviceCertificateRepositoryError::ReconcileEnrollmentMissing)
        ));
        let incomplete_after: (String, String, i64, i64) = sqlx::query_as(
            "SELECT to_jsonb(target)::text, target.xmin::text, \
                    (SELECT count(*) FROM reconcile_leases lease \
                     WHERE lease.tenant_id = target.tenant_id \
                       AND lease.target_id = target.target_id), \
                    (SELECT count(*) FROM device_certificate_desired_states desired \
                     WHERE desired.tenant_id = target.tenant_id \
                       AND desired.device_id::text = target.resource_id) + \
                    (SELECT count(*) FROM device_certificate_policy_operations operation \
                     WHERE operation.tenant_id = target.tenant_id \
                       AND operation.device_id::text = target.resource_id) \
             FROM reconcile_targets target \
             WHERE tenant_id = $1::uuid AND resource_id = $2::uuid::text",
        )
        .bind(incomplete.tenant().as_uuid().to_string())
        .bind(incomplete.device().as_uuid().to_string())
        .fetch_one(&owner.pool)
        .await?;
        assert_eq!(
            (incomplete_after.0, incomplete_after.1),
            incomplete_before,
            "missing-lease failure must not mutate the target"
        );
        assert_eq!((incomplete_after.2, incomplete_after.3), (0, 0));

        let fault_scope = scope();
        precreate_reconcile_target(&owner, fault_scope).await?;
        let faulted =
            PgDeviceCertificateRepository::from_unverified_stores_for_test(&reader, &writer)
                .with_target_wake_fault_for_test();
        assert!(matches!(
            faulted
                .accept_desired_policy(desired(fault_scope, 0, "fault.example"))
                .await,
            Err(DeviceCertificateRepositoryError::StorageUnavailable { .. })
        ));
        let fault_rows: i64 = sqlx::query_scalar(
            "SELECT \
                (SELECT count(*) FROM device_certificate_desired_states \
                 WHERE tenant_id = $1::uuid AND device_id = $2::uuid) + \
                (SELECT count(*) FROM device_certificate_policy_operations \
                 WHERE tenant_id = $1::uuid AND device_id = $2::uuid) + \
                (SELECT count(*) FROM reconcile_targets \
                 WHERE tenant_id = $1::uuid AND resource_id = $2::uuid::text)",
        )
        .bind(fault_scope.tenant().as_uuid().to_string())
        .bind(fault_scope.device().as_uuid().to_string())
        .fetch_one(&owner.pool)
        .await?;
        assert_eq!(
            fault_rows, 1,
            "post-wake fault must preserve only the pre-existing target"
        );

        let quarantined = scope();
        let quarantined_target_id = precreate_reconcile_target(&owner, quarantined).await?;
        let quarantined_target: (String, String) = sqlx::query_as(
            "UPDATE reconcile_targets \
             SET status = 'disabled', disabled_reason = 'permanent_failure' \
             WHERE tenant_id = $1::uuid AND target_id = $2::uuid \
             RETURNING to_jsonb(reconcile_targets)::text, xmin::text",
        )
        .bind(quarantined.tenant().as_uuid().to_string())
        .bind(&quarantined_target_id)
        .fetch_one(&owner.pool)
        .await?;
        assert!(matches!(
            repo.accept_desired_policy(desired(quarantined, 0, "quarantined.example"))
                .await,
            Err(DeviceCertificateRepositoryError::ReconcileTargetQuarantined)
        ));
        let quarantined_after: (String, String, i64) = sqlx::query_as(
            "SELECT to_jsonb(target)::text, target.xmin::text, \
                    (SELECT count(*) FROM device_certificate_desired_states desired \
                     WHERE desired.tenant_id = target.tenant_id \
                       AND desired.device_id::text = target.resource_id) \
             FROM reconcile_targets target \
             WHERE tenant_id = $1::uuid AND resource_id = $2::uuid::text",
        )
        .bind(quarantined.tenant().as_uuid().to_string())
        .bind(quarantined.device().as_uuid().to_string())
        .fetch_one(&owner.pool)
        .await?;
        assert_eq!(
            (quarantined_after.0, quarantined_after.1),
            quarantined_target
        );
        assert_eq!(quarantined_after.2, 0);

        let paused = scope();
        let paused_target = precreate_reconcile_target(&owner, paused).await?;
        owner
            .reconcile()
            .pause_target(paused.tenant(), &paused_target)
            .await?;
        assert!(matches!(
            repo.accept_desired_policy(desired(paused, 0, "paused.example"))
                .await?,
            DesiredPolicyAcceptOutcome::Accepted { .. }
        ));
        let paused_state: (String, Option<String>, i64, bool, i64) = sqlx::query_as(
            "SELECT status, disabled_reason, wake_version, next_run_at <= now(), \
                    (SELECT count(*) FROM reconcile_leases lease \
                     WHERE lease.tenant_id = reconcile_targets.tenant_id \
                       AND lease.target_id = reconcile_targets.target_id) \
             FROM reconcile_targets \
             WHERE tenant_id = $1::uuid AND resource_id = $2::uuid::text",
        )
        .bind(paused.tenant().as_uuid().to_string())
        .bind(paused.device().as_uuid().to_string())
        .fetch_one(&owner.pool)
        .await?;
        assert_eq!(paused_state, ("active".to_owned(), None, 1, true, 1));

        drop((repo, faulted, same_target_faulted));
        reader.shutdown().await?;
        writer.shutdown().await?;
        owner.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn reported_repository_classifies_all_outcomes_and_converges_to_max_sequence()
    -> TestResult {
        let (_pg, store) = crate::test_pg::connect_pg().await?;
        store.run_migrations().await?;
        let repo = PgDeviceCertificateRepository::from_unverified_for_test(&store);
        let missing = scope();
        assert!(matches!(
            repo.advance_reported(report(missing, 1, 1, '1', '2', "missing"))
                .await?,
            ReportedWriteOutcome::MissingDesired
        ));
        assert!(repo.load_state(missing).await?.is_none());

        let target = scope();
        precreate_reconcile_target(&store, target).await?;
        assert!(matches!(
            repo.accept_desired_policy(desired(target, 0, "one.example"))
                .await?,
            DesiredPolicyAcceptOutcome::Accepted { .. }
        ));
        set_reconcile_epoch(&store, target, 41).await?;
        let initial = report(target, 1, 10, '1', '2', "report-1");
        assert!(matches!(
            repo.advance_reported(initial.clone()).await?,
            ReportedWriteOutcome::Applied(_)
        ));
        let unchanged = repo
            .load_state(target)
            .await?
            .unwrap()
            .reported()
            .unwrap()
            .clone();
        assert!(matches!(
            repo.advance_reported(initial).await?,
            ReportedWriteOutcome::Duplicate
        ));
        assert_eq!(
            repo.load_state(target).await?.unwrap().reported(),
            Some(&unchanged)
        );
        for conflicting in [
            report(target, 1, 10, '9', '2', "report-1"),
            report(target, 1, 10, '1', '9', "report-1"),
            report(target, 1, 10, '1', '2', "changed-envelope"),
        ] {
            assert!(matches!(
                repo.advance_reported(conflicting).await?,
                ReportedWriteOutcome::StateConflict
            ));
            assert_eq!(
                repo.load_state(target).await?.unwrap().reported().unwrap(),
                &unchanged
            );
        }

        assert!(matches!(
            repo.accept_desired_policy(desired(target, 1, "two.example"))
                .await?,
            DesiredPolicyAcceptOutcome::Accepted { .. }
        ));
        assert!(matches!(
            repo.advance_reported(report(target, 2, 10, '2', '3', "report-2-stale"))
                .await?,
            ReportedWriteOutcome::StaleSequence
        ));
        assert_eq!(
            repo.load_state(target).await?.unwrap().reported(),
            Some(&unchanged)
        );
        assert!(matches!(
            repo.advance_reported(report(target, 2, 11, '2', '3', "report-2"))
                .await?,
            ReportedWriteOutcome::Applied(_)
        ));
        let generation_two = repo
            .load_state(target)
            .await?
            .unwrap()
            .reported()
            .unwrap()
            .clone();
        assert!(matches!(
            repo.advance_reported(report(target, 1, 12, '1', '2', "old"))
                .await?,
            ReportedWriteOutcome::StaleGeneration
        ));
        assert_eq!(
            repo.load_state(target).await?.unwrap().reported(),
            Some(&generation_two)
        );
        assert!(matches!(
            repo.advance_reported(report(target, 3, 12, '3', '4', "ahead"))
                .await?,
            ReportedWriteOutcome::AheadOfDesired
        ));
        assert_eq!(
            repo.load_state(target).await?.unwrap().reported(),
            Some(&generation_two)
        );

        assert!(matches!(
            repo.accept_desired_policy(desired(target, 2, "three.example"))
                .await?,
            DesiredPolicyAcceptOutcome::Accepted { .. }
        ));
        assert!(matches!(
            repo.accept_desired_policy(desired(target, 3, "four.example"))
                .await?,
            DesiredPolicyAcceptOutcome::Accepted { .. }
        ));
        let left = PgDeviceCertificateRepository::from_unverified_for_test(&store);
        let right = PgDeviceCertificateRepository::from_unverified_for_test(&store);
        let (low, high) = tokio::join!(
            left.advance_reported(report(target, 3, 20, '3', '4', "low")),
            right.advance_reported(report(target, 4, 30, '4', '5', "high")),
        );
        assert!(matches!(
            low?,
            ReportedWriteOutcome::Applied(_) | ReportedWriteOutcome::StaleGeneration
        ));
        assert!(matches!(high?, ReportedWriteOutcome::Applied(_)));
        let snapshot = repo.load_state(target).await?.expect("desired exists");
        assert_eq!(
            snapshot
                .reported()
                .expect("reported exists")
                .device_sequence()
                .get(),
            30
        );

        drop((repo, left, right));
        store.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn real_serving_roles_complete_repository_conformance() -> TestResult {
        let (fixture, owner) = crate::test_pg::connect_pg().await?;
        owner.run_migrations().await?;
        let writer = crate::test_pg::connect_pg_rss_app_role(&fixture, &owner).await?;
        let reader = crate::test_pg::connect_pg_rss_app_read_role(&fixture, &owner).await?;
        let repo = PgDeviceCertificateRepository::from_unverified_stores_for_test(&reader, &writer);
        let target = scope();
        precreate_reconcile_target(&owner, target).await?;
        set_reconcile_epoch(&owner, target, 41).await?;

        assert!(matches!(
            repo.accept_desired_policy(desired(target, 0, "roles.example"))
                .await?,
            DesiredPolicyAcceptOutcome::Accepted { .. }
        ));
        assert!(matches!(
            repo.advance_reported(report(target, 1, 1, '1', '2', "roles-report"))
                .await?,
            ReportedWriteOutcome::Applied(_)
        ));
        let loaded = repo
            .load_state(target)
            .await?
            .expect("reader sees writer state");
        assert_eq!(loaded.desired().generation().get(), 1);
        assert_eq!(loaded.reported().unwrap().device_sequence().get(), 1);
        assert_eq!(loaded.conditions().len(), 6);

        drop(repo);
        reader.shutdown().await?;
        writer.shutdown().await?;
        owner.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn load_state_uses_one_repeatable_read_snapshot() -> TestResult {
        let (_fixture, store) = crate::test_pg::connect_pg().await?;
        store.run_migrations().await?;
        let target = scope();
        precreate_reconcile_target(&store, target).await?;
        set_reconcile_epoch(&store, target, 41).await?;
        let writer = PgDeviceCertificateRepository::from_unverified_for_test(&store);
        writer
            .accept_desired_policy(desired(target, 0, "snapshot-1.example"))
            .await?;
        writer
            .advance_reported(report(target, 1, 1, '1', '2', "snapshot-1"))
            .await?;

        let hook = std::sync::Arc::new(super::LoadSnapshotHook {
            desired_loaded: tokio::sync::Notify::new(),
            resume: tokio::sync::Notify::new(),
        });
        let loader = PgDeviceCertificateRepository::from_unverified_for_test(&store)
            .with_load_snapshot_hook_for_test(hook.clone());
        let load = tokio::spawn(async move { loader.load_state(target).await });
        hook.desired_loaded.notified().await;

        writer
            .accept_desired_policy(desired(target, 1, "snapshot-2.example"))
            .await?;
        writer
            .advance_reported(report(target, 2, 2, '2', '3', "snapshot-2"))
            .await?;
        hook.resume.notify_one();

        let snapshot = load
            .await??
            .expect("state existed in the original snapshot");
        assert_eq!(snapshot.desired().generation().get(), 1);
        assert_eq!(snapshot.reported().unwrap().observed_generation().get(), 1);

        drop(writer);
        store.shutdown().await?;
        Ok(())
    }
}
