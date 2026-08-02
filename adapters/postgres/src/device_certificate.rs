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
    ArtifactEligibility, CertificateArtifactId, CertificateAttemptAuthority,
    CertificateAttemptFence, CertificateConditionMutation, CertificatePublicKeyDigest,
    CertificateReadyProof, CertificateReconcileRepository, CertificateReconcileRepositoryError,
    CertificateReconcileView, CertificateRevocationObservation, CertificateTransportObservation,
    DeletionRequestOutcome, DesiredPolicyAcceptOutcome, DesiredPolicyAccepted,
    DesiredPolicyAcceptedCondition, DesiredStateRestore, DesiredStateSnapshot,
    DeviceCertificateError, DeviceCertificateRepository, DeviceCertificateRepositoryError,
    DeviceCertificateScope, DeviceCertificateStateSnapshot, DeviceSequence, ExpectedGeneration,
    FencedMutationOutcome, PersistedCertificateArtifactSnapshot, PolicyHash, ReportEnvelopeId,
    ReportedStateHash, ReportedStateRestore, ReportedStateSnapshot, RotationOutcome,
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
    EnrollReconcileTarget,
    AcceptDesiredPolicy,
    LoadState,
}

#[derive(sqlx::FromRow)]
struct ArtifactReceiptRow {
    artifact_eligibility: String,
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

#[derive(sqlx::FromRow)]
struct ReconcileViewFenceRow {
    target_id: String,
    deletion_requested: bool,
    generation: i64,
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
            Self::EnrollReconcileTarget => "enroll_reconcile_target",
            Self::AcceptDesiredPolicy => "accept_desired_policy",
            Self::LoadState => "load_state",
        }
    }
}

/// Tenant-scoped PostgreSQL implementation of the device-certificate persistence port.
pub struct PgDeviceCertificateRepository<
    E: ArtifactEligibility = identity::ports::device_certificate::ProductionEligibility,
> {
    read_pool: TenantDb<ServingReadLane>,
    write_pool: TenantDb<ServingWriteLane>,
    eligibility: std::marker::PhantomData<fn() -> E>,
    #[cfg(all(test, feature = "integration"))]
    fail_after_desired_write: bool,
    #[cfg(all(test, feature = "integration"))]
    fail_after_target_wake: bool,
    #[cfg(all(test, feature = "integration"))]
    device_ingress_fault: Option<crate::device_command::DeviceIngressFault>,
}

impl<E: ArtifactEligibility> PgDeviceCertificateRepository<E> {
    /// Construct from serving capabilities verified by the runtime bundle.
    pub(crate) fn new(reader: &VerifiedPgReadStore, writer: &VerifiedPgWriteStore) -> Self {
        Self {
            read_pool: TenantDb::<ServingReadLane>::new(reader),
            write_pool: TenantDb::<ServingWriteLane>::new(writer),
            eligibility: std::marker::PhantomData,
            #[cfg(all(test, feature = "integration"))]
            fail_after_desired_write: false,
            #[cfg(all(test, feature = "integration"))]
            fail_after_target_wake: false,
            #[cfg(all(test, feature = "integration"))]
            device_ingress_fault: None,
        }
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn from_unverified_for_test(store: &crate::PgStore) -> Self {
        Self {
            read_pool: TenantDb::<ServingReadLane>::from_unverified_for_test(store),
            write_pool: TenantDb::<ServingWriteLane>::from_unverified_for_test(store),
            eligibility: std::marker::PhantomData,
            fail_after_desired_write: false,
            fail_after_target_wake: false,
            device_ingress_fault: None,
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
            eligibility: std::marker::PhantomData,
            fail_after_desired_write: false,
            fail_after_target_wake: false,
            device_ingress_fault: None,
        }
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn with_desired_write_fault_for_test(mut self) -> Self {
        self.fail_after_desired_write = true;
        self
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn with_target_wake_fault_for_test(mut self) -> Self {
        self.fail_after_target_wake = true;
        self
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn with_device_ingress_fault_for_test(
        mut self,
        fault: crate::device_command::DeviceIngressFault,
    ) -> Self {
        self.device_ingress_fault = Some(fault);
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

impl<E> identity::ports::device_certificate::DeviceIngressRepository<E>
    for PgDeviceCertificateRepository<E>
where
    E: ArtifactEligibility,
{
    type Error = deviceloop::DeviceCommandStoreError;
    type Commit = crate::PgDeviceIngressCommit<E>;

    async fn commit(
        &self,
        input: identity::ports::device_certificate::DeviceIngressWrite,
    ) -> Result<Self::Commit, Self::Error> {
        crate::device_command::commit_device_ingress::<E>(
            &self.write_pool,
            &self.read_pool,
            input,
            #[cfg(all(test, feature = "integration"))]
            self.device_ingress_fault,
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
    async fn lock_reconcile_view(
        &mut self,
        scope: DeviceCertificateScope,
        attempt_id: &str,
        lease_token: &str,
        epoch: i64,
        wake_version: i64,
    ) -> Result<Option<ReconcileViewFenceRow>, RepoError> {
        sqlx::query_as(
            "SELECT target_id,deletion_requested,generation \
             FROM public.rss_lock_device_certificate_reconcile_view( \
               $1::uuid,$2::uuid,$3::uuid,$4::uuid,$5,$6)",
        )
        .bind(tenant_param(scope))
        .bind(device_param(scope))
        .bind(attempt_id)
        .bind(lease_token)
        .bind(epoch)
        .bind(wake_version)
        .fetch_optional(&mut *self.conn)
        .await
        .map_err(storage)
    }

    async fn reconcile_fence_target(
        &mut self,
        fence: &CertificateAttemptFence,
    ) -> Result<Option<()>, RepoError> {
        let row = self
            .lock_reconcile_view(
                fence.scope(),
                fence.attempt_id(),
                fence.lease_token(),
                to_i64(fence.epoch().get())?,
                to_i64(fence.wake_version().get())?,
            )
            .await?;
        let expected_generation = to_i64(fence.expected_generation().get())?;
        Ok(row
            .filter(|row| row.generation == expected_generation)
            .map(|_| ()))
    }

    async fn reconcile_snapshot_with_ready_evidence<E: ArtifactEligibility>(
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
            restore_artifact_receipt::<E>(scope, receipt_row).map_err(|error| match error {
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
            "SELECT artifact_eligibility, generation, policy_hash, public_key_digest, expected_state_hash, \
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
        let view_fence = self
            .lock_reconcile_view(
                fence.scope,
                &fence.attempt_id,
                &fence.lease_token,
                fence.epoch,
                fence.wake_version,
            )
            .await?;
        let Some(view_fence) =
            view_fence.filter(|view_fence| view_fence.generation == fence.expected_generation)
        else {
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
        .bind(view_fence.target_id)
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

#[cfg(test)]
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

fn restore_artifact_receipt<E: ArtifactEligibility>(
    scope: DeviceCertificateScope,
    row: ArtifactReceiptRow,
) -> Result<PersistedCertificateArtifactSnapshot<E>, CertificateReconcileRepositoryError> {
    if row.artifact_eligibility != E::PERSISTENCE_LABEL {
        return Err(CertificateReconcileRepositoryError::CorruptState(
            DeviceCertificateError::InvalidPersistedValue,
        ));
    }
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
    async fn enroll_reconcile_target(
        &mut self,
        tenant: &str,
        device: &str,
        initial_due_epoch_micros: i64,
    ) -> Result<(), RepoError> {
        let outcome: String = sqlx::query_scalar(
            "SELECT public.rss_enroll_device_certificate_reconcile_target( \
             $1::uuid,$2::uuid,$3)",
        )
        .bind(tenant)
        .bind(device)
        .bind(initial_due_epoch_micros)
        .fetch_one(&mut *self.conn)
        .await
        .map_err(storage)?;
        match outcome.as_str() {
            "enrolled" | "already_enrolled" => Ok(()),
            _ => Err(invalid_persisted_value()),
        }
    }

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

impl<E: ArtifactEligibility> PgDeviceCertificateRepository<E> {
    /// Idempotently enroll one device in the fixed certificate reconciler.
    ///
    /// The initial due time applies only when creating the target. Repeated calls do not expose its
    /// opaque id, reschedule it, re-enable a quarantined target, or reset an existing lease.
    #[tracing::instrument(
        name = "device_certificate.repository",
        skip_all,
        fields(
            component = "device_certificate_repository",
            operation = RepositoryOperation::EnrollReconcileTarget.as_label()
        )
    )]
    pub async fn enroll_reconcile_target(
        &self,
        scope: DeviceCertificateScope,
        initial_due: SystemTime,
    ) -> Result<(), RepoError> {
        let tenant = tenant_param(scope);
        let device = device_param(scope);
        let initial_due_epoch_micros = time_to_epoch_micros(initial_due)?;
        self.write_pool
            .identity_write(
                scope,
                move |mut tx| {
                    Box::pin(async move {
                        tx.identity()
                            .device_policy()
                            .enroll_reconcile_target(&tenant, &device, initial_due_epoch_micros)
                            .await
                    })
                },
                storage,
            )
            .await
    }
}

impl<E: ArtifactEligibility> DeviceCertificateRepository for PgDeviceCertificateRepository<E> {
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
            operation = RepositoryOperation::LoadState.as_label()
        )
    )]
    async fn load_state(
        &self,
        scope: DeviceCertificateScope,
    ) -> Result<Option<DeviceCertificateStateSnapshot>, RepoError> {
        let tenant = tenant_param(scope);
        let device = device_param(scope);
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

impl<E> CertificateReconcileRepository<E> for PgDeviceCertificateRepository<E>
where
    E: ArtifactEligibility,
{
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
                        let view_fence = certificates
                            .lock_reconcile_view(
                                scope,
                                authority.attempt_id(),
                                authority.lease_token(),
                                to_i64(authority.epoch().get()).map_err(reconcile_from_repo)?,
                                to_i64(authority.wake_version().get())
                                    .map_err(reconcile_from_repo)?,
                            )
                            .await
                            .map_err(reconcile_from_repo)?;
                        let Some(view_fence) = view_fence else {
                            return Ok(None);
                        };
                        let state = certificates
                            .reconcile_snapshot_with_ready_evidence::<E>(
                                &authority, scope, &tenant, &device,
                            )
                            .await
                            .map_err(reconcile_from_repo)?
                            .ok_or(CertificateReconcileRepositoryError::InvalidMutation)?;
                        if to_i64(state.desired().generation().get())
                            .map_err(reconcile_from_repo)?
                            != view_fence.generation
                        {
                            return Err(CertificateReconcileRepositoryError::InvalidMutation);
                        }
                        CertificateReconcileView::restore_current(
                            &authority,
                            state,
                            view_fence.deletion_requested,
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
    ) -> Result<Vec<PersistedCertificateArtifactSnapshot<E>>, CertificateReconcileRepositoryError>
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
        authorization: ArtifactAppendAuthorization<E>,
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
                        let query = match E::PERSISTENCE_LABEL {
                            "draft" => {
                                "SELECT public.rss_append_device_certificate_artifact_draft( \
                                $1::uuid,$2::uuid,$3::uuid,$4::uuid,$5,$6,$7, \
                                $8,$9,$10,$11,$12,$13,$14)"
                            }
                            "production" => {
                                "SELECT public.rss_append_device_certificate_artifact_production( \
                                $1::uuid,$2::uuid,$3::uuid,$4::uuid,$5,$6,$7, \
                                $8,$9,$10,$11,$12,$13,$14)"
                            }
                            _ => return Err(CertificateReconcileRepositoryError::InvalidMutation),
                        };
                        let outcome: String = sqlx::query_scalar(query)
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
                RepositoryOperation::EnrollReconcileTarget.as_label(),
                RepositoryOperation::AcceptDesiredPolicy.as_label(),
                RepositoryOperation::LoadState.as_label(),
            ],
            [
                "enroll_reconcile_target",
                "accept_desired_policy",
                "load_state"
            ]
        );
    }

    #[test]
    fn eligibility_cutover_purges_pre_ga_state_and_removes_legacy_funnels() {
        const MIGRATION: &str =
            include_str!("../migrations/0095_seal_device_artifact_eligibility.sql");

        for required in [
            "DELETE FROM public.device_ingress_receipts",
            "DELETE FROM public.device_commands",
            "DELETE FROM public.device_certificate_authorized_artifacts",
            "DELETE FROM public.device_certificate_desired_states",
            "ADD COLUMN artifact_eligibility text NOT NULL",
            "ADD COLUMN artifact_eligibility text NOT NULL",
            "DROP FUNCTION public.rss_append_device_certificate_artifact(",
            "DROP FUNCTION public.rss_install_fenced_device_command(",
        ] {
            assert!(
                MIGRATION.contains(required),
                "missing cutover carrier: {required}"
            );
        }
        assert!(MIGRATION.contains("CHECK (artifact_eligibility IN ('draft', 'production'))"));
        assert!(MIGRATION.contains("p_artifact_eligibility text"));
        assert!(MIGRATION.contains("rss_append_device_certificate_artifact_draft"));
        assert!(MIGRATION.contains("rss_append_device_certificate_artifact_production"));
        assert!(MIGRATION.contains("rss_resolve_device_certificate_artifact_eligibility"));
        assert!(MIGRATION.contains("rss_settle_device_command_published_draft"));
        assert!(MIGRATION.contains("rss_settle_device_command_published_production"));
        assert!(!MIGRATION.contains(
            "GRANT SELECT ON public.device_certificate_authorized_artifacts TO rss_device_command_funnel_owner"
        ));
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

    use std::time::{Duration, UNIX_EPOCH};

    use deviceloop::CertificatePolicy;
    use diport::ManagedResource as _;
    use eventexec::reconcile::{AttemptTrigger, ReconcileScheduleStore as _};
    use identity::ports::device_certificate::{
        AcceptDesiredPolicy, DesiredPolicyAcceptOutcome, DeviceCertificateRepository as _,
        DeviceCertificateRepositoryError, DeviceCertificateScope, DevicePolicyIdempotencyKey,
        DraftEligibility, ExpectedGeneration, ProductionEligibility,
    };

    use super::PgDeviceCertificateRepository as GenericPgDeviceCertificateRepository;
    use crate::cotx::{ServingWriteLane, TenantDb};
    use crate::reconcile::ReconcileTargetKey;

    type PgDeviceCertificateRepository =
        GenericPgDeviceCertificateRepository<ProductionEligibility>;

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

    #[tokio::test(flavor = "multi_thread")]
    async fn draft_enrollment_is_exact_tenant_scoped_and_claimable_after_accept() -> TestResult {
        let (fixture, owner) = crate::test_pg::connect_pg().await?;
        owner.run_migrations().await?;
        let writer = crate::test_pg::connect_pg_rss_app_role(&fixture, &owner).await?;
        let reader = crate::test_pg::connect_pg_rss_app_read_role(&fixture, &owner).await?;
        let repository = GenericPgDeviceCertificateRepository::<DraftEligibility>::
            from_unverified_stores_for_test(&reader, &writer);
        let enrolled_scope = scope();
        let initial_due_micros = 1_700_000_000_123_456_i64;
        let initial_due = UNIX_EPOCH + Duration::from_micros(initial_due_micros as u64);

        repository
            .enroll_reconcile_target(enrolled_scope, initial_due)
            .await?;
        repository
            .enroll_reconcile_target(enrolled_scope, initial_due + Duration::from_secs(86_400))
            .await?;

        let enrolled: (String, String, String, String, i64, String, i64, bool) = sqlx::query_as(
            "SELECT target.reconciler_id,target.resource_kind,target.resource_id,target.status, \
                    (EXTRACT(EPOCH FROM target.next_run_at)*1000000)::bigint, \
                    lease.state,lease.epoch, \
                    lease.lease_token IS NULL AND lease.holder_id IS NULL \
                      AND lease.acquired_at IS NULL AND lease.expires_at IS NULL \
                      AND lease.heartbeat_at IS NULL \
             FROM public.reconcile_targets AS target \
             JOIN public.reconcile_leases AS lease USING (tenant_id,target_id) \
             WHERE target.tenant_id=$1::uuid AND target.resource_id=$2::uuid::text",
        )
        .bind(enrolled_scope.tenant().as_uuid().to_string())
        .bind(enrolled_scope.device().as_uuid().to_string())
        .fetch_one(&owner.pool)
        .await?;
        assert_eq!(
            enrolled,
            (
                super::DEVICE_CERTIFICATE_RECONCILER_ID.to_owned(),
                super::DEVICE_CERTIFICATE_RESOURCE_KIND.to_owned(),
                enrolled_scope.device().as_uuid().to_string(),
                "active".to_owned(),
                initial_due_micros,
                "free".to_owned(),
                0,
                true,
            ),
            "repeat enrollment must preserve one fixed target and its canonical free lease"
        );

        let function_acl: (String, bool, bool, bool, bool, bool, Vec<String>) = sqlx::query_as(
            "SELECT owner.rolname,procedure.prosecdef,owner.rolcanlogin,owner.rolbypassrls, \
                    pg_catalog.has_function_privilege('rss_app',procedure.oid,'EXECUTE'), \
                    pg_catalog.has_function_privilege('rss_app_read',procedure.oid,'EXECUTE'), \
                    procedure.proconfig \
             FROM pg_catalog.pg_proc AS procedure \
             JOIN pg_catalog.pg_roles AS owner ON owner.oid=procedure.proowner \
             WHERE procedure.oid = \
               'public.rss_enroll_device_certificate_reconcile_target(uuid,uuid,bigint)'::regprocedure",
        )
        .fetch_one(&owner.pool)
        .await?;
        assert_eq!(
            function_acl,
            (
                "rss_device_certificate_funnel_owner".to_owned(),
                true,
                false,
                false,
                true,
                false,
                vec!["search_path=pg_catalog, pg_temp".to_owned()],
            )
        );
        let owner_grants: (bool, bool, bool, bool) = sqlx::query_as(
            "SELECT \
               pg_catalog.has_table_privilege( \
                 'rss_device_certificate_funnel_owner','public.reconcile_targets','INSERT'), \
               pg_catalog.has_column_privilege( \
                 'rss_device_certificate_funnel_owner','public.reconcile_targets','tenant_id','INSERT'), \
               pg_catalog.has_table_privilege( \
                 'rss_device_certificate_funnel_owner','public.reconcile_leases','INSERT'), \
               pg_catalog.has_column_privilege( \
                 'rss_device_certificate_funnel_owner','public.reconcile_leases','target_id','INSERT')",
        )
        .fetch_one(&owner.pool)
        .await?;
        assert_eq!(owner_grants, (false, true, false, true));

        let cross_tenant = TenantDb::<ServingWriteLane>::from_unverified_for_test(&writer);
        let cross_tenant_call = cross_tenant
            .identity_write(
                scope(),
                move |mut identity| {
                    Box::pin(async move {
                        let mut identity_write = identity.identity();
                        let certificates = identity_write.device_certificates();
                        sqlx::query_scalar::<_, String>(
                            "SELECT public.rss_enroll_device_certificate_reconcile_target( \
                             $1::uuid,$2::uuid,$3)",
                        )
                        .bind(enrolled_scope.tenant().as_uuid().to_string())
                        .bind(enrolled_scope.device().as_uuid().to_string())
                        .bind(initial_due_micros)
                        .fetch_one(&mut *certificates.conn)
                        .await
                    })
                },
                std::convert::identity,
            )
            .await;
        assert!(
            cross_tenant_call
                .as_ref()
                .err()
                .and_then(sqlx::Error::as_database_error)
                .and_then(sqlx::error::DatabaseError::code)
                .is_some_and(|code| code == "42501"),
            "the exact SECURITY DEFINER funnel must reject a mismatched tenant GUC"
        );
        let accepted = repository
            .accept_desired_policy(desired(enrolled_scope, 0, "draft-pilot.example"))
            .await?;
        let wake = match accepted {
            DesiredPolicyAcceptOutcome::Accepted { wake, .. } => wake,
            other => {
                return Err(std::io::Error::other(format!(
                    "enrolled desired policy must be accepted, got {other:?}"
                ))
                .into());
            }
        };
        let claimed = writer
            .reconcile()
            .claim_targeted(
                enrolled_scope.tenant(),
                super::DEVICE_CERTIFICATE_RECONCILER_ID,
                "draft-pilot-holder",
                &wake,
                Duration::from_secs(60),
            )
            .await?
            .ok_or_else(|| std::io::Error::other("accepted enrollment wake must be claimable"))?;
        assert_eq!(claimed.trigger(), AttemptTrigger::Targeted);
        assert_eq!(claimed.tenant(), enrolled_scope.tenant());
        assert_eq!(
            claimed.resource_id(),
            enrolled_scope.device().as_uuid().to_string()
        );
        assert_eq!(
            claimed.reconciler_id(),
            super::DEVICE_CERTIFICATE_RECONCILER_ID
        );
        assert_eq!(
            claimed.resource_kind(),
            super::DEVICE_CERTIFICATE_RESOURCE_KIND
        );

        drop((claimed, repository));
        reader.shutdown().await?;
        writer.shutdown().await?;
        owner.shutdown().await?;
        Ok(())
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
}
