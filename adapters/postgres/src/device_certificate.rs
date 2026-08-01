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
    DeviceConditionState, ObservedGeneration,
};
use eventexec::reconcile::{ReconcileWake, WakeVersion};
use identity::ports::device_certificate::{
    AcceptDesiredPolicy, ArtifactDigest, ConditionStateBatch, ConditionUpsertOutcome,
    DesiredPolicyAcceptOutcome, DesiredPolicyAccepted, DesiredPolicyAcceptedCondition,
    DesiredStateRestore, DeviceCertificateError, DeviceCertificateRepository,
    DeviceCertificateRepositoryError, DeviceCertificateScope, DeviceCertificateStateSnapshot,
    DeviceSequence, ExpectedGeneration, PolicyHash, ReportEnvelopeId, ReportedStateHash,
    ReportedStateRestore, ReportedStateSnapshot, ReportedStateWrite, ReportedWriteOutcome,
};
use sqlx::PgConnection;

use crate::cotx::{ServingReadLane, ServingWriteLane, TenantDb};
use crate::pool::{VerifiedPgReadStore, VerifiedPgWriteStore};

type RepoError = DeviceCertificateRepositoryError;

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
    UpsertConditionStates,
    LoadState,
}

impl RepositoryOperation {
    const fn as_label(self) -> &'static str {
        match self {
            Self::AcceptDesiredPolicy => "accept_desired_policy",
            Self::AdvanceReported => "advance_reported",
            Self::UpsertConditionStates => "upsert_condition_states",
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

async fn select_desired_for_update(
    conn: &mut PgConnection,
    tenant: &str,
    device: &str,
) -> Result<Option<i64>, RepoError> {
    sqlx::query_scalar(
        "SELECT generation FROM device_certificate_desired_states \
         WHERE tenant_id = $1::uuid AND device_id = $2::uuid FOR UPDATE",
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

struct DesiredWriteParams {
    expected: i64,
    next: i64,
    validity: i32,
    renew_before: i32,
    client_auth: bool,
    server_auth: bool,
    sans: Vec<String>,
}

enum DesiredWriteOutcome {
    Applied,
    Conflict(ExpectedGeneration),
}

async fn apply_desired_generation_cas(
    conn: &mut PgConnection,
    tenant: &str,
    device: &str,
    params: DesiredWriteParams,
) -> Result<DesiredWriteOutcome, RepoError> {
    let row = if params.expected == 0 {
        sqlx::query_as::<_, DesiredRow>(
            "INSERT INTO device_certificate_desired_states \
             (tenant_id, device_id, generation, validity_seconds, renew_before_seconds, \
              client_auth, server_auth, sans) \
             VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (tenant_id, device_id) DO NOTHING \
             RETURNING generation, policy_hash, validity_seconds, renew_before_seconds, \
             client_auth, server_auth, sans, \
             floor(extract(epoch FROM created_at) * 1000000)::bigint AS created_at_micros, \
             floor(extract(epoch FROM updated_at) * 1000000)::bigint AS updated_at_micros",
        )
        .bind(tenant)
        .bind(device)
        .bind(params.next)
        .bind(params.validity)
        .bind(params.renew_before)
        .bind(params.client_auth)
        .bind(params.server_auth)
        .bind(params.sans)
        .fetch_optional(&mut *conn)
        .await
        .map_err(storage)?
    } else {
        sqlx::query_as::<_, DesiredRow>(
            "UPDATE device_certificate_desired_states SET generation = $3, \
             validity_seconds = $4, renew_before_seconds = $5, client_auth = $6, \
             server_auth = $7, sans = $8 \
             WHERE tenant_id = $1::uuid AND device_id = $2::uuid AND generation = $9 \
             RETURNING generation, policy_hash, validity_seconds, renew_before_seconds, \
             client_auth, server_auth, sans, \
             floor(extract(epoch FROM created_at) * 1000000)::bigint AS created_at_micros, \
             floor(extract(epoch FROM updated_at) * 1000000)::bigint AS updated_at_micros",
        )
        .bind(tenant)
        .bind(device)
        .bind(params.next)
        .bind(params.validity)
        .bind(params.renew_before)
        .bind(params.client_auth)
        .bind(params.server_auth)
        .bind(params.sans)
        .bind(params.expected)
        .fetch_optional(&mut *conn)
        .await
        .map_err(storage)?
    };
    if row.is_some() {
        return Ok(DesiredWriteOutcome::Applied);
    }
    let actual = sqlx::query_scalar::<_, i64>(
        "SELECT generation FROM device_certificate_desired_states \
         WHERE tenant_id = $1::uuid AND device_id = $2::uuid FOR UPDATE",
    )
    .bind(tenant)
    .bind(device)
    .fetch_optional(conn)
    .await
    .map_err(storage)?
    .unwrap_or(0);
    Ok(DesiredWriteOutcome::Conflict(
        ExpectedGeneration::restore(actual).map_err(corrupt)?,
    ))
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
    async fn desired_generation_for_update(
        &mut self,
        tenant: &str,
        device: &str,
    ) -> Result<Option<i64>, RepoError> {
        select_desired_for_update(self.conn, tenant, device).await
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

    async fn upsert_condition(
        &mut self,
        tenant: &str,
        device: &str,
        state: DeviceConditionState,
    ) -> Result<(), RepoError> {
        upsert_condition(self.conn, tenant, device, state).await
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
struct PolicyOperationRow {
    request_digest: Vec<u8>,
    accepted_generation: i64,
    accepted_condition: String,
}

#[derive(sqlx::FromRow)]
struct ReconcileEnrollmentRow {
    target_id: String,
    disabled_reason: Option<String>,
    has_lease: bool,
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

fn restore_policy_operation(row: PolicyOperationRow) -> Result<DesiredPolicyAccepted, RepoError> {
    let accepted_generation = u64::try_from(row.accepted_generation)
        .map_err(|_| invalid_persisted_value())
        .and_then(|generation| {
            DesiredGeneration::try_new(generation)
                .map_err(DeviceCertificateError::from)
                .map_err(corrupt)
        })?;
    let condition = match row.accepted_condition.as_str() {
        "reconciling" => DesiredPolicyAcceptedCondition::Reconciling,
        _ => return Err(invalid_persisted_value()),
    };
    Ok(DesiredPolicyAccepted::restore(
        accepted_generation,
        condition,
    ))
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
        sqlx::query(
            "SELECT pg_advisory_xact_lock(hashtextextended(\
                $1::text || ':' || $2::text || ':' || $3::text, 0))",
        )
        .bind(tenant)
        .bind(device)
        .bind(&key)
        .execute(&mut *self.conn)
        .await
        .map_err(storage)?;

        let operation = sqlx::query_as::<_, PolicyOperationRow>(
            "SELECT request_digest, accepted_generation, accepted_condition \
             FROM device_certificate_policy_operations \
             WHERE tenant_id = $1::uuid AND device_id = $2::uuid \
               AND idempotency_key = $3::uuid",
        )
        .bind(tenant)
        .bind(device)
        .bind(&key)
        .fetch_optional(&mut *self.conn)
        .await
        .map_err(storage)?;
        if let Some(operation) = operation {
            if operation.request_digest.as_slice() == input.request_digest().as_bytes() {
                return restore_policy_operation(operation)
                    .map(DevicePolicyAcceptTxOutcome::Replayed)
                    .map_err(DevicePolicyTxError::from);
            }
            return Ok(DevicePolicyAcceptTxOutcome::IdempotencyConflict);
        }

        let expected = to_i64(input.expected_generation().get())?;
        let next_generation = input.next_generation().map_err(corrupt)?;
        let next = to_i64(next_generation.get())?;
        let (validity, renew_before, client_auth, server_auth, sans) =
            policy_columns(input.policy());
        match apply_desired_generation_cas(
            self.conn,
            tenant,
            device,
            DesiredWriteParams {
                expected,
                next,
                validity,
                renew_before,
                client_auth,
                server_auth,
                sans,
            },
        )
        .await?
        {
            DesiredWriteOutcome::Applied => {}
            DesiredWriteOutcome::Conflict(actual) => {
                return Ok(DevicePolicyAcceptTxOutcome::ExpectedGenerationConflict(
                    actual,
                ));
            }
        }

        if fail_after_desired_write {
            return Err(DevicePolicyTxError::Repository(
                RepoError::storage_unavailable(std::io::Error::other(
                    "injected post-desired failure",
                )),
            ));
        }

        let enrollment = sqlx::query_as::<_, ReconcileEnrollmentRow>(
            r#"
            SELECT
                target.target_id::text AS target_id,
                target.disabled_reason,
                EXISTS (
                    SELECT 1
                    FROM reconcile_leases AS lease
                    WHERE lease.tenant_id = target.tenant_id
                      AND lease.target_id = target.target_id
                ) AS has_lease
            FROM reconcile_targets AS target
            WHERE target.tenant_id = $1::uuid
              AND target.reconciler_id = $2
              AND target.resource_kind = $3
              AND target.resource_id = $4
            FOR UPDATE OF target
            "#,
        )
        .bind(tenant)
        .bind(DEVICE_CERTIFICATE_RECONCILER_ID)
        .bind(DEVICE_CERTIFICATE_RESOURCE_KIND)
        .bind(device)
        .fetch_optional(&mut *self.conn)
        .await
        .map_err(storage)?;
        let Some(enrollment) = enrollment else {
            return Err(DevicePolicyTxError::ReconcileEnrollmentMissing);
        };
        if enrollment.disabled_reason.is_some() {
            return Err(DevicePolicyTxError::ReconcileTargetQuarantined);
        }
        if !enrollment.has_lease {
            return Err(DevicePolicyTxError::ReconcileEnrollmentMissing);
        }

        let (target_id, raw_wake_version): (String, i64) = sqlx::query_as(
            "UPDATE reconcile_targets \
             SET next_run_at = pg_catalog.clock_timestamp(), \
                 wake_version = wake_version + 1, \
                 updated_at = pg_catalog.clock_timestamp() \
             WHERE tenant_id = $1::uuid AND target_id = $2::uuid \
             RETURNING target_id::text, wake_version",
        )
        .bind(tenant)
        .bind(&enrollment.target_id)
        .fetch_one(&mut *self.conn)
        .await
        .map_err(storage)?;
        let wake_version =
            WakeVersion::restore(raw_wake_version).map_err(|_| invalid_persisted_value())?;

        if fail_after_target_wake {
            return Err(DevicePolicyTxError::Repository(
                RepoError::storage_unavailable(std::io::Error::other(
                    "injected post-target-wake failure",
                )),
            ));
        }

        let result = DesiredPolicyAccepted::fresh(next_generation);
        sqlx::query(
            "INSERT INTO device_certificate_policy_operations \
                (tenant_id, device_id, idempotency_key, request_digest, \
                 accepted_generation, accepted_condition) \
             VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6)",
        )
        .bind(tenant)
        .bind(device)
        .bind(key)
        .bind(input.request_digest().as_bytes().as_slice())
        .bind(next)
        .bind(result.condition().as_label())
        .execute(&mut *self.conn)
        .await
        .map_err(storage)?;

        Ok(DevicePolicyAcceptTxOutcome::Accepted {
            result,
            target_id,
            wake_version,
        })
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
            operation = RepositoryOperation::UpsertConditionStates.as_label()
        )
    )]
    async fn upsert_condition_states(
        &self,
        scope: DeviceCertificateScope,
        conditions: ConditionStateBatch,
    ) -> Result<ConditionUpsertOutcome, RepoError> {
        let tenant = tenant_param(scope);
        let device = device_param(scope);
        self.write_pool
            .identity_write(
                scope,
                move |mut tx| {
                    Box::pin(async move {
                        let mut identity = tx.identity();
                        let mut tx = identity.device_certificates();
                        let Some(desired_generation) =
                            tx.desired_generation_for_update(&tenant, &device).await?
                        else {
                            return Ok(ConditionUpsertOutcome::MissingDesired);
                        };
                        if conditions.states().iter().any(|state| {
                            state
                                .observed_generation()
                                .is_some_and(|value| value.get() > desired_generation as u64)
                        }) {
                            return Ok(ConditionUpsertOutcome::AheadOfDesired);
                        }
                        for state in conditions.into_states() {
                            tx.upsert_condition(&tenant, &device, state).await?;
                        }
                        let restored = tx.conditions(&tenant, &device).await?;
                        let desired = tx.desired(&tenant, &device).await?.ok_or_else(|| {
                            corrupt(DeviceCertificateError::InvalidPersistedValue)
                        })?;
                        let snapshot = DeviceCertificateStateSnapshot::restore(
                            scope,
                            restore_desired(desired)?,
                            None,
                            restored,
                        )
                        .map_err(corrupt)?;
                        Ok(ConditionUpsertOutcome::Applied(
                            snapshot.conditions().to_vec(),
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

async fn upsert_condition(
    conn: &mut PgConnection,
    tenant: &str,
    device: &str,
    state: DeviceConditionState,
) -> Result<(), RepoError> {
    let observed = state
        .observed_generation()
        .map(|value| to_i64(value.get()))
        .transpose()?;
    sqlx::query(
        "INSERT INTO device_certificate_conditions \
         (tenant_id, device_id, condition_type, status, reason, observed_generation) \
         VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6) \
         ON CONFLICT (tenant_id, device_id, condition_type) DO UPDATE SET \
            status = EXCLUDED.status, reason = EXCLUDED.reason, \
            observed_generation = EXCLUDED.observed_generation",
    )
    .bind(tenant)
    .bind(device)
    .bind(state.kind().as_label())
    .bind(state.status_label())
    .bind(state.reason_label())
    .bind(observed)
    .execute(conn)
    .await
    .map_err(storage)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repository_operation_labels_are_closed() {
        assert_eq!(
            [
                RepositoryOperation::AcceptDesiredPolicy.as_label(),
                RepositoryOperation::AdvanceReported.as_label(),
                RepositoryOperation::UpsertConditionStates.as_label(),
                RepositoryOperation::LoadState.as_label(),
            ],
            [
                "accept_desired_policy",
                "advance_reported",
                "upsert_condition_states",
                "load_state",
            ]
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

    use deviceloop::{
        CertificatePolicy, ConditionStatus, DegradedReason, DeletingReason,
        DeviceConditionSnapshot, DeviceConditionState, FenceEpoch, NotReadyStatus,
        ObservedGeneration, PendingDeviceReason, QuarantinedReason, ReadyReason, ReconcilingReason,
    };
    use diport::ManagedResource as _;
    use identity::ports::device_certificate::{
        AcceptDesiredPolicy, ArtifactDigest, ConditionStateBatch, ConditionUpsertOutcome,
        DesiredPolicyAcceptOutcome, DeviceCertificateRepository as _,
        DeviceCertificateRepositoryError, DeviceCertificateScope, DevicePolicyIdempotencyKey,
        DeviceSequence, ExpectedGeneration, ReportEnvelopeId, ReportedStateHash,
        ReportedStateWrite, ReportedWriteOutcome,
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

    fn condition_labels(
        snapshot: &DeviceConditionSnapshot,
    ) -> (&'static str, &'static str, Option<ObservedGeneration>) {
        match snapshot {
            DeviceConditionSnapshot::Ready(value) => (
                value.status().as_label(),
                value.reason().as_label(),
                value.observed_generation(),
            ),
            DeviceConditionSnapshot::Reconciling(value) => (
                value.status().as_label(),
                value.reason().as_label(),
                value.observed_generation(),
            ),
            DeviceConditionSnapshot::PendingDevice(value) => (
                value.status().as_label(),
                value.reason().as_label(),
                value.observed_generation(),
            ),
            DeviceConditionSnapshot::Degraded(value) => (
                value.status().as_label(),
                value.reason().as_label(),
                value.observed_generation(),
            ),
            DeviceConditionSnapshot::Quarantined(value) => (
                value.status().as_label(),
                value.reason().as_label(),
                value.observed_generation(),
            ),
            DeviceConditionSnapshot::Deleting(value) => (
                value.status().as_label(),
                value.reason().as_label(),
                value.observed_generation(),
            ),
        }
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
        assert_eq!(paused_state, ("disabled".to_owned(), None, 1, true, 1));

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
    async fn condition_repository_round_trips_all_kinds_and_preserves_transition_time() -> TestResult
    {
        let (_pg, store) = crate::test_pg::connect_pg().await?;
        store.run_migrations().await?;
        let repo = PgDeviceCertificateRepository::from_unverified_for_test(&store);
        let missing = scope();
        let one = ObservedGeneration::try_new(1).unwrap();
        assert!(matches!(
            repo.upsert_condition_states(
                missing,
                ConditionStateBatch::for_test(vec![DeviceConditionState::ready(
                    NotReadyStatus::Unknown,
                    ReadyReason::AwaitingDevice,
                    Some(one),
                )])?,
            )
            .await?,
            ConditionUpsertOutcome::MissingDesired
        ));

        let target = scope();
        precreate_reconcile_target(&store, target).await?;
        repo.accept_desired_policy(desired(target, 0, "conditions.example"))
            .await?;
        let states = vec![
            DeviceConditionState::ready(
                NotReadyStatus::Unknown,
                ReadyReason::AwaitingDevice,
                Some(one),
            ),
            DeviceConditionState::reconciling(
                ConditionStatus::True,
                ReconcilingReason::DesiredAccepted,
                Some(one),
            ),
            DeviceConditionState::pending_device(
                ConditionStatus::True,
                PendingDeviceReason::AwaitingDevice,
                Some(one),
            ),
            DeviceConditionState::degraded(
                ConditionStatus::False,
                DegradedReason::TransportUnavailable,
                Some(one),
            ),
            DeviceConditionState::quarantined(
                ConditionStatus::False,
                QuarantinedReason::ProtocolViolation,
                Some(one),
            ),
            DeviceConditionState::deleting(
                ConditionStatus::False,
                DeletingReason::DeletionPending,
                Some(one),
            ),
        ];
        let applied = repo
            .upsert_condition_states(target, ConditionStateBatch::for_test(states.clone())?)
            .await?;
        assert!(matches!(applied, ConditionUpsertOutcome::Applied(ref rows) if rows.len() == 6));
        let round_trip = repo.load_state(target).await?.unwrap();
        for (snapshot, expected) in round_trip.conditions().iter().zip(&states) {
            assert_eq!(snapshot.kind(), expected.kind());
            let (status, reason, observed) = condition_labels(snapshot);
            assert_eq!(status, expected.status_label());
            assert_eq!(reason, expected.reason_label());
            assert_eq!(observed, expected.observed_generation());
        }

        let before: i64 = sqlx::query_scalar(
            "SELECT floor(extract(epoch FROM last_transition_at) * 1000000)::bigint \
             FROM device_certificate_conditions WHERE tenant_id = $1::uuid AND device_id = $2::uuid \
               AND condition_type = 'Reconciling'",
        )
        .bind(target.tenant().as_uuid().to_string())
        .bind(target.device().as_uuid().to_string())
        .fetch_one(&store.pool)
        .await?;
        repo.upsert_condition_states(target, ConditionStateBatch::for_test(states)?)
            .await?;
        let duplicate: i64 = sqlx::query_scalar(
            "SELECT floor(extract(epoch FROM last_transition_at) * 1000000)::bigint \
             FROM device_certificate_conditions WHERE tenant_id = $1::uuid AND device_id = $2::uuid \
               AND condition_type = 'Reconciling'",
        )
        .bind(target.tenant().as_uuid().to_string())
        .bind(target.device().as_uuid().to_string())
        .fetch_one(&store.pool)
        .await?;
        assert_eq!(duplicate, before);

        sqlx::query("SELECT pg_sleep(0.002)")
            .execute(&store.pool)
            .await?;
        repo.upsert_condition_states(
            target,
            ConditionStateBatch::for_test(vec![DeviceConditionState::reconciling(
                ConditionStatus::False,
                ReconcilingReason::StateDrift,
                Some(one),
            )])?,
        )
        .await?;
        let after: i64 = sqlx::query_scalar(
            "SELECT floor(extract(epoch FROM last_transition_at) * 1000000)::bigint \
             FROM device_certificate_conditions WHERE tenant_id = $1::uuid AND device_id = $2::uuid \
               AND condition_type = 'Reconciling'",
        )
        .bind(target.tenant().as_uuid().to_string())
        .bind(target.device().as_uuid().to_string())
        .fetch_one(&store.pool)
        .await?;
        assert!(after > before);
        assert_eq!(
            repo.load_state(target).await?.unwrap().conditions().len(),
            6
        );

        let two = ObservedGeneration::try_new(2).unwrap();
        let before_rejection = repo
            .load_state(target)
            .await?
            .unwrap()
            .conditions()
            .to_vec();
        assert!(matches!(
            repo.upsert_condition_states(
                target,
                ConditionStateBatch::for_test(vec![DeviceConditionState::ready(
                    NotReadyStatus::False,
                    ReadyReason::StateDrift,
                    Some(two),
                )])?,
            )
            .await?,
            ConditionUpsertOutcome::AheadOfDesired
        ));
        assert_eq!(
            repo.load_state(target).await?.unwrap().conditions(),
            before_rejection
        );

        drop(repo);
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
        assert!(matches!(
            repo.upsert_condition_states(
                target,
                ConditionStateBatch::for_test(vec![DeviceConditionState::ready(
                    NotReadyStatus::False,
                    ReadyReason::StateDrift,
                    Some(ObservedGeneration::try_new(1)?),
                )])?,
            )
            .await?,
            ConditionUpsertOutcome::Applied(_)
        ));
        let loaded = repo
            .load_state(target)
            .await?
            .expect("reader sees writer state");
        assert_eq!(loaded.desired().generation().get(), 1);
        assert_eq!(loaded.reported().unwrap().device_sequence().get(), 1);
        assert_eq!(loaded.conditions().len(), 1);

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
