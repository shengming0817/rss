//! PostgreSQL durable DeviceLatent command aggregate and append-once ingress evidence.
//!
//! Public operations enter only through exact-lane tenant transactions. The crate-private
//! transaction concerns keep command work composable with later outbox and ingress unit-of-work
//! owners without exposing a connection or accepting storage-owned timestamps.
//!
//! ref: launchbadge/sqlx sqlx-core/src/transaction.rs@1d674f51581598f55436451d5b4b73100cae0b56

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use deviceloop::{
    AppendDeviceIngressOutcome, DesiredGeneration, DeviceCommandId, DeviceCommandStoreError,
    DeviceIngressCorruption, DeviceIngressDisposition, DeviceIngressEnvelopeId, DeviceIngressError,
    DeviceIngressEvidence, DeviceIngressEvidenceView, DeviceIngressFingerprint,
    DeviceIngressReceipt, DeviceSequence, FenceCoordinate, FenceEpoch, ObservedGeneration,
};
#[cfg(test)]
use deviceloop::{
    CommandIntentDigest, CommandProgressRestore, CommandRestoreCommon, CommandVersion,
    DeviceCommandCorruption, DeviceCommandRestore, DeviceCommandScope, DeviceCommandState,
};
#[cfg(all(test, feature = "integration"))]
use deviceloop::{
    CommandTransitionOutcome, CreateDeviceCommand, CreateDeviceCommandOutcome,
    DeviceCommandMutation, TransitionDeviceCommandOutcome,
};
use identity::ports::device_certificate::DeviceCertificateScope;
use sqlx::PgConnection;

#[cfg(all(test, feature = "integration"))]
use crate::cotx::{ServingReadLane, ServingWriteLane, TenantDb};
use crate::device_certificate_scope::{
    DEVICE_CERTIFICATE_RECONCILER_ID, DEVICE_CERTIFICATE_RESOURCE_KIND,
};
#[cfg(all(test, feature = "integration"))]
use deviceloop::{DeviceCommandSnapshot, DeviceCommandSnapshotView, DeviceCommandStatus};

type StoreError = DeviceCommandStoreError;
const PG_UNIX_MIN_MICROS: i128 = -210_866_803_200_000_000;
#[cfg(test)]
macro_rules! epoch_micros_sql {
    ($parameter:literal) => {
        concat!(
            "TIMESTAMPTZ 'epoch' + $",
            stringify!($parameter),
            "::bigint * INTERVAL '1 microsecond'"
        )
    };
}
#[cfg(all(test, feature = "integration"))]
const EPOCH_MICROS_SQL_6: &str = epoch_micros_sql!(6);
#[cfg(test)]
const EPOCH_MICROS_SQL_7: &str = epoch_micros_sql!(7);
#[cfg(all(test, feature = "integration"))]
const EPOCH_MICROS_SQL_8: &str = epoch_micros_sql!(8);

/// Read-only command concern within one tenant-bound identity transaction.
#[cfg(all(test, feature = "integration"))]
pub(crate) struct DeviceCommandReadTx<'tx> {
    conn: &'tx mut PgConnection,
}

#[cfg(all(test, feature = "integration"))]
impl<'tx> DeviceCommandReadTx<'tx> {
    pub(crate) fn new(conn: &'tx mut PgConnection) -> Self {
        Self { conn }
    }

    async fn command(
        &mut self,
        tenant: &str,
        device: &str,
        command_id: &str,
    ) -> Result<Option<CommandRow>, StoreError> {
        select_command(self.conn, tenant, device, command_id, false).await
    }

    async fn receipt(
        &mut self,
        tenant: &str,
        device: &str,
        event_id: &str,
    ) -> Result<Option<IngressRow>, StoreError> {
        select_receipt(self.conn, tenant, device, event_id).await
    }
}

/// Mutable command concern within one tenant-bound identity transaction.
pub(crate) struct DeviceCommandWriteTx<'tx> {
    conn: &'tx mut PgConnection,
}

impl<'tx> DeviceCommandWriteTx<'tx> {
    pub(crate) fn new(conn: &'tx mut PgConnection) -> Self {
        Self { conn }
    }

    #[cfg(all(test, feature = "integration"))]
    async fn transaction_time(&mut self) -> Result<SystemTime, StoreError> {
        transaction_time(self.conn).await
    }

    #[cfg(all(test, feature = "integration"))]
    async fn insert_command(
        &mut self,
        tenant: &str,
        device: &str,
        snapshot: &DeviceCommandSnapshot,
    ) -> Result<Option<CommandRow>, StoreError> {
        insert_command(self.conn, tenant, device, snapshot).await
    }

    #[cfg(all(test, feature = "integration"))]
    async fn command_for_update(
        &mut self,
        tenant: &str,
        device: &str,
        command_id: &str,
    ) -> Result<Option<CommandRow>, StoreError> {
        select_command(self.conn, tenant, device, command_id, true).await
    }

    #[cfg(all(test, feature = "integration"))]
    async fn active_command_id(
        &mut self,
        tenant: &str,
        device: &str,
        coordinate: FenceCoordinate,
        digest: CommandIntentDigest,
    ) -> Result<Option<DeviceCommandId>, StoreError> {
        let generation = coordinate_to_i64(coordinate.generation().get())?;
        let command_id = sqlx::query_scalar::<_, String>(
            "SELECT command_id FROM device_commands \
             WHERE tenant_id = $1::uuid AND device_id = $2::uuid AND generation = $3 \
               AND intent_digest = $4 AND state IN ('queued', 'published', 'received') \
             FOR UPDATE",
        )
        .bind(tenant)
        .bind(device)
        .bind(generation)
        .bind(digest.as_bytes().as_slice())
        .fetch_optional(&mut *self.conn)
        .await
        .map_err(storage)?;
        command_id
            .map(|value| DeviceCommandId::parse(&value).map_err(corrupt_command))
            .transpose()
    }

    #[cfg(all(test, feature = "integration"))]
    async fn update_command(
        &mut self,
        tenant: &str,
        device: &str,
        expected: CommandVersion,
        snapshot: &DeviceCommandSnapshot,
    ) -> Result<bool, StoreError> {
        update_command(self.conn, tenant, device, expected, snapshot).await
    }

    #[allow(dead_code)] // Used by the crate-private #1903 ingress composition seam.
    async fn insert_receipt(
        &mut self,
        tenant: &str,
        device: &str,
        evidence: &DeviceIngressEvidence,
        disposition: DeviceIngressDisposition,
    ) -> Result<Option<IngressRow>, StoreError> {
        insert_receipt(self.conn, tenant, device, evidence, disposition).await
    }

    #[allow(dead_code)] // Used by the crate-private #1903 ingress composition seam.
    async fn receipt_for_device(
        &mut self,
        tenant: &str,
        device: &str,
        event_id: &str,
    ) -> Result<Option<IngressRow>, StoreError> {
        select_receipt(self.conn, tenant, device, event_id).await
    }

    #[cfg(all(test, feature = "integration"))]
    async fn probe_receipt_update(&mut self, event_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE device_ingress_receipts SET disposition = 'duplicate' WHERE event_id = $1",
        )
        .bind(event_id)
        .execute(&mut *self.conn)
        .await
        .map(|_| ())
    }

    #[cfg(all(test, feature = "integration"))]
    async fn probe_receipt_delete(&mut self, event_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM device_ingress_receipts WHERE event_id = $1")
            .bind(event_id)
            .execute(&mut *self.conn)
            .await
            .map(|_| ())
    }

    #[cfg(all(test, feature = "integration"))]
    async fn probe_version_gap(&mut self, command_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE device_commands SET version = version + 2 WHERE command_id = $1")
            .bind(command_id)
            .execute(&mut *self.conn)
            .await
            .map(|_| ())
    }

    #[cfg(all(test, feature = "integration"))]
    async fn inject_rollback_failed_after_rollback(&mut self) -> Result<(), sqlx::Error> {
        sqlx::query("SELECT set_config('rss.test_rollback_failed_after_rollback', '1', true)")
            .execute(&mut *self.conn)
            .await
            .map(|_| ())
    }
}

/// Transaction-owned ingress classifier for authenticated ACK/report evidence.
///
/// The caller supplies no disposition. Authority, replay and protocol state are derived while the
/// desired row and canonical reconcile lease are locked by the caller's transaction.
#[allow(dead_code)] // Constructed by #1903 inside its authenticated ingress transaction.
pub(crate) struct FencedIngressTx<'tx> {
    commands: DeviceCommandWriteTx<'tx>,
}

#[derive(Clone, Copy)]
struct DeviceAuthority {
    generation: i64,
    fence_epoch: i64,
}

#[allow(dead_code)] // The complete caller UoW is intentionally deferred to #1903.
impl<'tx> FencedIngressTx<'tx> {
    #[allow(dead_code)] // #1903 composes this crate-private concern into authenticated ingress UoW.
    pub(crate) fn new(conn: &'tx mut PgConnection) -> Self {
        Self {
            commands: DeviceCommandWriteTx::new(conn),
        }
    }

    pub(crate) async fn record(
        &mut self,
        scope: DeviceCertificateScope,
        evidence: DeviceIngressEvidence,
    ) -> Result<AppendDeviceIngressOutcome, StoreError> {
        let (tenant, device) = scope_params(scope);
        if let Some(outcome) = self.existing_outcome(&tenant, &device, &evidence).await? {
            return Ok(outcome);
        }

        let authority = lock_device_authority(&mut *self.commands.conn, &tenant, &device).await?;

        // Serialize the tenant-local envelope identity before any command mutation. PostgreSQL
        // transaction advisory locks survive savepoints and close the absent-row collision race.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(format!("{tenant}:{}", evidence.envelope_id().as_str()))
            .execute(&mut *self.commands.conn)
            .await
            .map_err(storage)?;

        if let Some(outcome) = self.existing_outcome(&tenant, &device, &evidence).await? {
            return Ok(outcome);
        }

        let (_, command_id, incoming_generation, incoming_epoch, sequence) =
            evidence_columns(&evidence);
        let disposition = match command_id {
            Some(command_id) => {
                self.classify_ack(
                    &tenant,
                    &device,
                    command_id,
                    evidence.kind_label(),
                    incoming_generation,
                    incoming_epoch,
                    sequence,
                    authority,
                )
                .await?
            }
            None => {
                self.classify_report(
                    &tenant,
                    &device,
                    incoming_generation,
                    incoming_epoch,
                    sequence,
                    authority,
                )
                .await?
            }
        };

        if let Some(row) = self
            .commands
            .insert_receipt(&tenant, &device, &evidence, disposition)
            .await?
        {
            return restore_receipt(row).map(AppendDeviceIngressOutcome::Appended);
        }
        self.existing_outcome(&tenant, &device, &evidence)
            .await?
            .ok_or(StoreError::InvariantViolation)
    }

    async fn existing_outcome(
        &mut self,
        tenant: &str,
        device: &str,
        evidence: &DeviceIngressEvidence,
    ) -> Result<Option<AppendDeviceIngressOutcome>, StoreError> {
        let Some(row) = self
            .commands
            .receipt_for_device(tenant, device, evidence.envelope_id().as_str())
            .await?
        else {
            let tenant_collision: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM device_ingress_receipts \
                 WHERE tenant_id = $1::uuid AND event_id = $2)",
            )
            .bind(tenant)
            .bind(evidence.envelope_id().as_str())
            .fetch_one(&mut *self.commands.conn)
            .await
            .map_err(storage)?;
            return Ok(tenant_collision.then_some(AppendDeviceIngressOutcome::Conflict));
        };
        let receipt = restore_receipt(row)?;
        Ok(Some(if receipt.evidence() == evidence {
            AppendDeviceIngressOutcome::Replay(receipt)
        } else {
            AppendDeviceIngressOutcome::Conflict
        }))
    }

    async fn authoritative_sequence_is_stale(
        &mut self,
        tenant: &str,
        device: &str,
        generation: i64,
        fence_epoch: i64,
        sequence: DeviceSequence,
    ) -> Result<bool, StoreError> {
        let high_water: Option<i64> = sqlx::query_scalar(
            r#"
            SELECT max(device_sequence)
            FROM device_ingress_receipts
            WHERE tenant_id = $1::uuid AND device_id = $2::uuid
              AND generation = $3 AND fence_epoch = $4
              AND disposition IN ('advanced', 'device_rejected')
            "#,
        )
        .bind(tenant)
        .bind(device)
        .bind(generation)
        .bind(fence_epoch)
        .fetch_one(&mut *self.commands.conn)
        .await
        .map_err(storage)?;
        Ok(high_water.is_some_and(|high_water| {
            u64::try_from(high_water).is_ok_and(|high_water| sequence.get() <= high_water)
        }))
    }

    async fn classify_report(
        &mut self,
        tenant: &str,
        device: &str,
        incoming_generation: u64,
        incoming_epoch: u64,
        sequence: DeviceSequence,
        authority: DeviceAuthority,
    ) -> Result<DeviceIngressDisposition, StoreError> {
        if i64::try_from(incoming_generation).ok().is_none()
            || i64::try_from(incoming_epoch).ok().is_none()
        {
            return Ok(DeviceIngressDisposition::Rejected);
        }
        let authority_generation = u64::try_from(authority.generation).unwrap_or_default();
        let authority_epoch = u64::try_from(authority.fence_epoch).unwrap_or_default();
        if incoming_generation < authority_generation {
            return Ok(DeviceIngressDisposition::StaleGeneration);
        }
        if incoming_generation > authority_generation {
            return Ok(DeviceIngressDisposition::Rejected);
        }
        if incoming_epoch < authority_epoch {
            return Ok(DeviceIngressDisposition::StaleFence);
        }
        if incoming_epoch > authority_epoch {
            return Ok(DeviceIngressDisposition::Rejected);
        }
        if self
            .authoritative_sequence_is_stale(
                tenant,
                device,
                authority.generation,
                authority.fence_epoch,
                sequence,
            )
            .await?
        {
            return Ok(DeviceIngressDisposition::StaleSequence);
        }
        Ok(DeviceIngressDisposition::Advanced)
    }

    #[allow(clippy::too_many_arguments)]
    async fn classify_ack(
        &mut self,
        tenant: &str,
        device: &str,
        command_id: &str,
        kind: &str,
        incoming_generation: u64,
        incoming_epoch: u64,
        sequence: DeviceSequence,
        authority: DeviceAuthority,
    ) -> Result<DeviceIngressDisposition, StoreError> {
        let row: Option<(String, String, i64, i64)> = sqlx::query_as(
            r#"
            SELECT device_id::text, state, generation, fence_epoch
            FROM device_commands
            WHERE tenant_id = $1::uuid AND command_id = $2
            "#,
        )
        .bind(tenant)
        .bind(command_id)
        .fetch_optional(&mut *self.commands.conn)
        .await
        .map_err(storage)?;
        let Some((command_device, state, command_generation, command_epoch)) = row else {
            return Ok(DeviceIngressDisposition::ScopeMismatch);
        };
        if command_device != device {
            return Ok(DeviceIngressDisposition::ScopeMismatch);
        }
        if i64::try_from(incoming_generation).ok() != Some(command_generation)
            || i64::try_from(incoming_epoch).ok() != Some(command_epoch)
        {
            return Ok(DeviceIngressDisposition::ScopeMismatch);
        }
        let coordinate_disposition = self
            .classify_report(
                tenant,
                device,
                incoming_generation,
                incoming_epoch,
                sequence,
                authority,
            )
            .await?;
        if coordinate_disposition != DeviceIngressDisposition::Advanced {
            return Ok(coordinate_disposition);
        }
        let (next_state, disposition) = match (kind, state.as_str()) {
            ("ack_received", "published") => (Some("received"), DeviceIngressDisposition::Advanced),
            ("ack_received", "received") => (None, DeviceIngressDisposition::Duplicate),
            ("ack_rejected", "published") => {
                (Some("rejected"), DeviceIngressDisposition::DeviceRejected)
            }
            ("ack_rejected", "rejected") => (None, DeviceIngressDisposition::Duplicate),
            (_, "queued") => (None, DeviceIngressDisposition::OutOfOrder),
            (_, "applied" | "rejected" | "timed_out" | "superseded" | "cancelled") => {
                (None, DeviceIngressDisposition::Late)
            }
            _ => (None, DeviceIngressDisposition::OutOfOrder),
        };
        if let Some(next_state) = next_state {
            let updated: bool = sqlx::query_scalar(
                r#"
                SELECT public.rss_apply_device_command_ack(
                    $1::uuid, $2::uuid, $3, $4, $5, $6
                )
                "#,
            )
            .bind(tenant)
            .bind(device)
            .bind(command_id)
            .bind(command_generation)
            .bind(command_epoch)
            .bind(kind)
            .fetch_one(&mut *self.commands.conn)
            .await
            .map_err(storage)?;
            if !updated {
                let current: Option<String> = sqlx::query_scalar(
                    "SELECT state FROM device_commands \
                     WHERE tenant_id = $1::uuid AND device_id = $2::uuid AND command_id = $3",
                )
                .bind(tenant)
                .bind(device)
                .bind(command_id)
                .fetch_optional(&mut *self.commands.conn)
                .await
                .map_err(storage)?;
                return match (kind, current.as_deref()) {
                    ("ack_received", Some("received")) | ("ack_rejected", Some("rejected")) => {
                        Ok(DeviceIngressDisposition::Duplicate)
                    }
                    (
                        _,
                        Some("applied" | "rejected" | "timed_out" | "superseded" | "cancelled"),
                    ) => Ok(DeviceIngressDisposition::Late),
                    _ => Err(StoreError::InvariantViolation),
                };
            }
            debug_assert_eq!(
                next_state,
                if kind == "ack_received" {
                    "received"
                } else {
                    "rejected"
                }
            );
        }
        Ok(disposition)
    }
}

/// Tenant/device-scoped PostgreSQL read facade and crate-private ingress test harness.
#[cfg(all(test, feature = "integration"))]
pub struct PgDeviceCommandStore {
    read_pool: TenantDb<ServingReadLane>,
    write_pool: TenantDb<ServingWriteLane>,
}

#[cfg(all(test, feature = "integration"))]
impl PgDeviceCommandStore {
    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn from_unverified_stores_for_test(
        reader: &crate::PgStore,
        writer: &crate::PgStore,
    ) -> Self {
        Self {
            read_pool: TenantDb::<ServingReadLane>::from_unverified_for_test(reader),
            write_pool: TenantDb::<ServingWriteLane>::from_unverified_for_test(writer),
        }
    }

    #[cfg(all(test, feature = "integration"))]
    async fn record_fenced_ingress_for_test(
        &self,
        scope: DeviceCertificateScope,
        evidence: DeviceIngressEvidence,
    ) -> Result<AppendDeviceIngressOutcome, StoreError> {
        let attempt = self
            .write_pool
            .identity_write_attempt(
                scope,
                move |mut tx| {
                    Box::pin(async move {
                        let mut identity = tx.identity();
                        let commands = identity.device_commands();
                        FencedIngressTx { commands }.record(scope, evidence).await
                    })
                },
                storage,
            )
            .await;
        finish_write_attempt(attempt)
    }
}

fn storage(error: sqlx::Error) -> StoreError {
    let database_code = error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(|code| code.into_owned());
    tracing::warn!(
        error.kind = "postgres",
        database.code = database_code.as_deref().unwrap_or("none"),
        error = %secure::redact_error(&error),
        "device-command store operation failed"
    );
    match crate::tx_retry::classify_sqlx_error(&error) {
        consistency::TxRetryClass::Transient => StoreError::storage_transient(error),
        consistency::TxRetryClass::Conflict
        | consistency::TxRetryClass::Permanent
        | consistency::TxRetryClass::OwnershipLost => StoreError::storage_permanent(error),
    }
}

#[cfg(test)]
fn corrupt_command(error: deviceloop::DeviceCommandError) -> StoreError {
    tracing::warn!(
        error.kind = "corrupt_command",
        "persisted command failed validation"
    );
    StoreError::CorruptCommand(DeviceCommandCorruption::Domain(error))
}

fn corrupt_ingress(error: DeviceIngressError) -> StoreError {
    tracing::warn!(
        error.kind = "corrupt_ingress",
        "persisted ingress receipt failed validation"
    );
    StoreError::CorruptIngress(DeviceIngressCorruption::Domain(error))
}

#[cfg(test)]
fn command_corruption(reason: DeviceCommandCorruption) -> StoreError {
    StoreError::CorruptCommand(reason)
}

fn ingress_corruption(reason: DeviceIngressCorruption) -> StoreError {
    StoreError::CorruptIngress(reason)
}

#[cfg(all(test, feature = "integration"))]
fn finish_write_attempt<T>(
    attempt: crate::cotx::LocalTxAttempt<T, StoreError>,
) -> Result<T, StoreError> {
    let unsafe_settlement = matches!(
        attempt.settlement(),
        Some(
            consistency::LocalTxFinalStatus::CommitUnknown
                | consistency::LocalTxFinalStatus::RollbackFailed
        )
    );
    attempt.into_result().map_err(|error| {
        if unsafe_settlement {
            StoreError::settlement_unknown(error)
        } else {
            error
        }
    })
}

fn scope_params(scope: DeviceCertificateScope) -> (String, String) {
    (
        scope.tenant().as_uuid().to_string(),
        scope.device().as_uuid().to_string(),
    )
}

async fn lock_device_authority(
    conn: &mut PgConnection,
    tenant: &str,
    device: &str,
) -> Result<DeviceAuthority, StoreError> {
    let target_id: Option<String> = sqlx::query_scalar(
        r#"
        SELECT target_id::text
        FROM reconcile_targets
        WHERE tenant_id = $1::uuid AND reconciler_id = $2 AND resource_kind = $3
          AND resource_id = $4
        FOR UPDATE
        "#,
    )
    .bind(tenant)
    .bind(DEVICE_CERTIFICATE_RECONCILER_ID)
    .bind(DEVICE_CERTIFICATE_RESOURCE_KIND)
    .bind(device)
    .fetch_optional(&mut *conn)
    .await
    .map_err(storage)?;
    let Some(target_id) = target_id else {
        return Err(StoreError::InvariantViolation);
    };

    let fence_epoch: Option<i64> = sqlx::query_scalar(
        "SELECT epoch FROM reconcile_leases \
         WHERE tenant_id = $1::uuid AND target_id = $2::uuid FOR UPDATE",
    )
    .bind(tenant)
    .bind(&target_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(storage)?;
    let Some(fence_epoch) = fence_epoch else {
        return Err(StoreError::InvariantViolation);
    };

    let generation: Option<i64> = sqlx::query_scalar(
        "SELECT generation FROM device_certificate_desired_states \
         WHERE tenant_id = $1::uuid AND device_id = $2::uuid FOR UPDATE",
    )
    .bind(tenant)
    .bind(device)
    .fetch_optional(conn)
    .await
    .map_err(storage)?;
    generation
        .map(|generation| DeviceAuthority {
            generation,
            fence_epoch,
        })
        .ok_or(StoreError::InvariantViolation)
}

#[cfg(all(test, feature = "integration"))]
fn scope_matches(scope: DeviceCertificateScope, command: DeviceCommandScope) -> bool {
    scope.tenant() == command.tenant() && scope.device() == command.device()
}

fn coordinate_to_i64(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::InvariantViolation)
}

#[cfg(all(test, feature = "integration"))]
fn raw_system_time_to_micros(value: SystemTime) -> Option<i64> {
    let signed = match value.duration_since(UNIX_EPOCH) {
        Ok(duration) => i128::try_from(duration.as_micros()).ok()?,
        Err(error) => -i128::try_from(error.duration().as_micros()).ok()?,
    };
    if !(PG_UNIX_MIN_MICROS..=i128::from(i64::MAX)).contains(&signed) {
        return None;
    }
    let micros = i64::try_from(signed).ok()?;
    if raw_micros_to_system_time(micros)? != value {
        return None;
    }
    Some(micros)
}

fn raw_micros_to_system_time(value: i64) -> Option<SystemTime> {
    if value >= 0 {
        UNIX_EPOCH.checked_add(Duration::from_micros(value.unsigned_abs()))
    } else {
        UNIX_EPOCH.checked_sub(Duration::from_micros(value.unsigned_abs()))
    }
}

#[cfg(all(test, feature = "integration"))]
fn encode_command_time(value: SystemTime) -> Result<i64, StoreError> {
    raw_system_time_to_micros(value).ok_or(StoreError::InvariantViolation)
}

#[cfg(test)]
fn decode_command_time(value: i64) -> Result<SystemTime, StoreError> {
    if i128::from(value) < PG_UNIX_MIN_MICROS {
        return Err(command_corruption(DeviceCommandCorruption::Timestamp));
    }
    raw_micros_to_system_time(value)
        .ok_or_else(|| command_corruption(DeviceCommandCorruption::Timestamp))
}

fn decode_ingress_time(value: i64) -> Result<SystemTime, StoreError> {
    if i128::from(value) < PG_UNIX_MIN_MICROS {
        return Err(ingress_corruption(DeviceIngressCorruption::Timestamp));
    }
    raw_micros_to_system_time(value)
        .ok_or_else(|| ingress_corruption(DeviceIngressCorruption::Timestamp))
}

#[cfg(all(test, feature = "integration"))]
async fn transaction_time(conn: &mut PgConnection) -> Result<SystemTime, StoreError> {
    let micros = sqlx::query_scalar::<_, i64>(
        "SELECT floor(extract(epoch FROM transaction_timestamp()) * 1000000)::bigint",
    )
    .fetch_one(conn)
    .await
    .map_err(storage)?;
    raw_micros_to_system_time(micros).ok_or(StoreError::InvariantViolation)
}

#[cfg(test)]
#[derive(sqlx::FromRow)]
struct CommandRow {
    command_id: String,
    device_id: String,
    generation: i64,
    fence_epoch: i64,
    intent_digest: Vec<u8>,
    deadline_micros: i64,
    state: String,
    version: i64,
    queued_at_micros: i64,
    published_at_micros: Option<i64>,
    received_at_micros: Option<i64>,
    terminal_at_micros: Option<i64>,
}

#[cfg(all(test, feature = "integration"))]
const COMMAND_COLUMNS: &str = "command_id, device_id::text AS device_id, generation, fence_epoch, \
    intent_digest, floor(extract(epoch FROM deadline) * 1000000)::bigint AS deadline_micros, \
    state, version, floor(extract(epoch FROM queued_at) * 1000000)::bigint AS queued_at_micros, \
    floor(extract(epoch FROM published_at) * 1000000)::bigint AS published_at_micros, \
    floor(extract(epoch FROM received_at) * 1000000)::bigint AS received_at_micros, \
    floor(extract(epoch FROM terminal_at) * 1000000)::bigint AS terminal_at_micros";

#[cfg(all(test, feature = "integration"))]
fn command_query(suffix: &str) -> String {
    format!("SELECT {COMMAND_COLUMNS} FROM device_commands {suffix}")
}

#[cfg(all(test, feature = "integration"))]
async fn select_command(
    conn: &mut PgConnection,
    tenant: &str,
    device: &str,
    command_id: &str,
    for_update: bool,
) -> Result<Option<CommandRow>, StoreError> {
    let lock = if for_update { " FOR UPDATE" } else { "" };
    let query = command_query(&format!(
        "WHERE tenant_id = $1::uuid AND device_id = $2::uuid AND command_id = $3{lock}"
    ));
    sqlx::query_as::<_, CommandRow>(&query)
        .bind(tenant)
        .bind(device)
        .bind(command_id)
        .fetch_optional(conn)
        .await
        .map_err(storage)
}

#[cfg(test)]
fn command_bytes32(value: &[u8]) -> Result<[u8; 32], StoreError> {
    value
        .try_into()
        .map_err(|_| command_corruption(DeviceCommandCorruption::Digest))
}

fn ingress_bytes32(value: &[u8]) -> Result<[u8; 32], StoreError> {
    value
        .try_into()
        .map_err(|_| ingress_corruption(DeviceIngressCorruption::Fingerprint))
}

#[cfg(test)]
fn command_progress(row: &CommandRow) -> Result<CommandProgressRestore, StoreError> {
    match (row.published_at_micros, row.received_at_micros) {
        (None, None) => Ok(CommandProgressRestore::queued()),
        (Some(published), None) => Ok(CommandProgressRestore::published(decode_command_time(
            published,
        )?)),
        (Some(published), Some(received)) => Ok(CommandProgressRestore::received(
            decode_command_time(published)?,
            decode_command_time(received)?,
        )),
        (None, Some(_)) => Err(command_corruption(DeviceCommandCorruption::Shape)),
    }
}

#[cfg(test)]
fn restore_command(
    tenant: vocab::TenantId,
    row: CommandRow,
) -> Result<DeviceCommandState, StoreError> {
    let device_uuid = uuid::Uuid::parse_str(&row.device_id)
        .map_err(|_| command_corruption(DeviceCommandCorruption::Identity))?;
    let generation = u64::try_from(row.generation)
        .map_err(|_| command_corruption(DeviceCommandCorruption::Coordinate))?;
    let epoch = u64::try_from(row.fence_epoch)
        .map_err(|_| command_corruption(DeviceCommandCorruption::Coordinate))?;
    let common = CommandRestoreCommon::new(
        DeviceCommandScope::new(tenant, ids::DeviceId::new(device_uuid)),
        DeviceCommandId::parse(&row.command_id).map_err(corrupt_command)?,
        CommandIntentDigest::from_bytes(command_bytes32(&row.intent_digest)?),
        FenceCoordinate::new(
            DesiredGeneration::try_new(generation)
                .map_err(|_| command_corruption(DeviceCommandCorruption::Coordinate))?,
            FenceEpoch::try_new(epoch)
                .map_err(|_| command_corruption(DeviceCommandCorruption::Coordinate))?,
        ),
        decode_command_time(row.deadline_micros)?,
        CommandVersion::restore(row.version).map_err(corrupt_command)?,
        decode_command_time(row.queued_at_micros)?,
    );
    let restore = match row.state.as_str() {
        "queued" => DeviceCommandRestore::queued(common),
        "published" => DeviceCommandRestore::published(
            common,
            decode_command_time(
                row.published_at_micros
                    .ok_or_else(|| command_corruption(DeviceCommandCorruption::Shape))?,
            )?,
        ),
        "received" => DeviceCommandRestore::received(
            common,
            decode_command_time(
                row.published_at_micros
                    .ok_or_else(|| command_corruption(DeviceCommandCorruption::Shape))?,
            )?,
            decode_command_time(
                row.received_at_micros
                    .ok_or_else(|| command_corruption(DeviceCommandCorruption::Shape))?,
            )?,
        ),
        "applied" => DeviceCommandRestore::applied(
            common,
            decode_command_time(
                row.published_at_micros
                    .ok_or_else(|| command_corruption(DeviceCommandCorruption::Shape))?,
            )?,
            decode_command_time(
                row.received_at_micros
                    .ok_or_else(|| command_corruption(DeviceCommandCorruption::Shape))?,
            )?,
            decode_command_time(
                row.terminal_at_micros
                    .ok_or_else(|| command_corruption(DeviceCommandCorruption::Shape))?,
            )?,
        ),
        "rejected" => DeviceCommandRestore::rejected(
            common,
            decode_command_time(
                row.published_at_micros
                    .ok_or_else(|| command_corruption(DeviceCommandCorruption::Shape))?,
            )?,
            decode_command_time(
                row.terminal_at_micros
                    .ok_or_else(|| command_corruption(DeviceCommandCorruption::Shape))?,
            )?,
        ),
        "timed_out" => DeviceCommandRestore::timed_out(
            common,
            command_progress(&row)?,
            decode_command_time(
                row.terminal_at_micros
                    .ok_or_else(|| command_corruption(DeviceCommandCorruption::Shape))?,
            )?,
        ),
        "superseded" => DeviceCommandRestore::superseded(
            common,
            command_progress(&row)?,
            decode_command_time(
                row.terminal_at_micros
                    .ok_or_else(|| command_corruption(DeviceCommandCorruption::Shape))?,
            )?,
        ),
        "cancelled" => DeviceCommandRestore::cancelled(
            common,
            command_progress(&row)?,
            decode_command_time(
                row.terminal_at_micros
                    .ok_or_else(|| command_corruption(DeviceCommandCorruption::Shape))?,
            )?,
        ),
        _ => return Err(command_corruption(DeviceCommandCorruption::State)),
    };
    DeviceCommandState::restore(restore).map_err(corrupt_command)
}

#[cfg(test)]
struct SnapshotColumns<'a> {
    common: deviceloop::CommandSnapshotCommon<'a>,
    state: DeviceCommandStatus,
    published_at: Option<SystemTime>,
    received_at: Option<SystemTime>,
    terminal_at: Option<SystemTime>,
}

#[cfg(test)]
fn snapshot_columns(snapshot: &DeviceCommandSnapshot) -> SnapshotColumns<'_> {
    match snapshot.view() {
        DeviceCommandSnapshotView::Queued { common } => SnapshotColumns {
            common,
            state: DeviceCommandStatus::Queued,
            published_at: None,
            received_at: None,
            terminal_at: None,
        },
        DeviceCommandSnapshotView::Published {
            common,
            published_at,
        } => SnapshotColumns {
            common,
            state: DeviceCommandStatus::Published,
            published_at: Some(published_at),
            received_at: None,
            terminal_at: None,
        },
        DeviceCommandSnapshotView::Received {
            common,
            published_at,
            received_at,
        } => SnapshotColumns {
            common,
            state: DeviceCommandStatus::Received,
            published_at: Some(published_at),
            received_at: Some(received_at),
            terminal_at: None,
        },
        DeviceCommandSnapshotView::Applied {
            common,
            published_at,
            received_at,
            applied_at,
        } => SnapshotColumns {
            common,
            state: DeviceCommandStatus::Applied,
            published_at: Some(published_at),
            received_at: Some(received_at),
            terminal_at: Some(applied_at),
        },
        DeviceCommandSnapshotView::Rejected {
            common,
            published_at,
            rejected_at,
        } => SnapshotColumns {
            common,
            state: DeviceCommandStatus::Rejected,
            published_at: Some(published_at),
            received_at: None,
            terminal_at: Some(rejected_at),
        },
        DeviceCommandSnapshotView::TimedOut {
            common,
            progress,
            timed_out_at,
        } => terminal_columns(
            common,
            progress,
            DeviceCommandStatus::TimedOut,
            timed_out_at,
        ),
        DeviceCommandSnapshotView::Superseded {
            common,
            progress,
            superseded_at,
        } => terminal_columns(
            common,
            progress,
            DeviceCommandStatus::Superseded,
            superseded_at,
        ),
        DeviceCommandSnapshotView::Cancelled {
            common,
            progress,
            cancelled_at,
        } => terminal_columns(
            common,
            progress,
            DeviceCommandStatus::Cancelled,
            cancelled_at,
        ),
    }
}

#[cfg(all(test, feature = "integration"))]
fn same_create_identity(left: &DeviceCommandSnapshot, right: &DeviceCommandSnapshot) -> bool {
    let left = snapshot_columns(left);
    let right = snapshot_columns(right);
    left.common.scope() == right.common.scope()
        && left.common.command_id() == right.common.command_id()
        && left.common.intent_digest() == right.common.intent_digest()
        && left.common.coordinate() == right.common.coordinate()
        && left.common.deadline() == right.common.deadline()
}

#[cfg(test)]
fn terminal_columns<'a>(
    common: deviceloop::CommandSnapshotCommon<'a>,
    progress: deviceloop::CommandProgressSnapshot,
    state: DeviceCommandStatus,
    terminal_at: SystemTime,
) -> SnapshotColumns<'a> {
    let (published_at, received_at) = match progress {
        deviceloop::CommandProgressSnapshot::Queued => (None, None),
        deviceloop::CommandProgressSnapshot::Published { published_at } => {
            (Some(published_at), None)
        }
        deviceloop::CommandProgressSnapshot::Received {
            published_at,
            received_at,
        } => (Some(published_at), Some(received_at)),
    };
    SnapshotColumns {
        common,
        state,
        published_at,
        received_at,
        terminal_at: Some(terminal_at),
    }
}

#[cfg(all(test, feature = "integration"))]
async fn insert_command(
    conn: &mut PgConnection,
    tenant: &str,
    device: &str,
    snapshot: &DeviceCommandSnapshot,
) -> Result<Option<CommandRow>, StoreError> {
    let columns = snapshot_columns(snapshot);
    let returning = COMMAND_COLUMNS;
    let deadline = EPOCH_MICROS_SQL_7;
    sqlx::query_as::<_, CommandRow>(&format!(
        "INSERT INTO device_commands (tenant_id, command_id, device_id, generation, fence_epoch, \
         intent_digest, deadline, state, version) VALUES ( \
         $1::uuid, $2, $3::uuid, $4, $5, $6, \
         {deadline}, $8, $9) \
         ON CONFLICT DO NOTHING RETURNING {returning}"
    ))
    .bind(tenant)
    .bind(columns.common.command_id().as_str())
    .bind(device)
    .bind(coordinate_to_i64(
        columns.common.coordinate().generation().get(),
    )?)
    .bind(coordinate_to_i64(
        columns.common.coordinate().epoch().get(),
    )?)
    .bind(columns.common.intent_digest().as_bytes().as_slice())
    .bind(encode_command_time(columns.common.deadline())?)
    .bind(columns.state.as_label())
    .bind(columns.common.version().get())
    .fetch_optional(conn)
    .await
    .map_err(storage)
}

#[cfg(all(test, feature = "integration"))]
async fn update_command(
    conn: &mut PgConnection,
    tenant: &str,
    device: &str,
    expected: CommandVersion,
    snapshot: &DeviceCommandSnapshot,
) -> Result<bool, StoreError> {
    let columns = snapshot_columns(snapshot);
    let published_at = EPOCH_MICROS_SQL_6;
    let received_at = EPOCH_MICROS_SQL_7;
    let terminal_at = EPOCH_MICROS_SQL_8;
    let query = format!(
        "UPDATE device_commands SET state = $4, version = $5, \
         published_at = {published_at}, received_at = {received_at}, \
         terminal_at = {terminal_at} WHERE tenant_id = $1::uuid AND device_id = $2::uuid \
         AND command_id = $3 AND version = $9"
    );
    let result = sqlx::query(&query)
        .bind(tenant)
        .bind(device)
        .bind(columns.common.command_id().as_str())
        .bind(columns.state.as_label())
        .bind(columns.common.version().get())
        .bind(columns.published_at.map(encode_command_time).transpose()?)
        .bind(columns.received_at.map(encode_command_time).transpose()?)
        .bind(columns.terminal_at.map(encode_command_time).transpose()?)
        .bind(expected.get())
        .execute(conn)
        .await
        .map_err(storage)?;
    Ok(result.rows_affected() == 1)
}

#[derive(sqlx::FromRow)]
struct IngressRow {
    event_id: String,
    device_id: String,
    kind: String,
    command_id: Option<String>,
    generation: i64,
    fence_epoch: i64,
    device_sequence: i64,
    fingerprint: Vec<u8>,
    disposition: String,
    received_at_micros: i64,
    committed_at_micros: i64,
}

const INGRESS_COLUMNS: &str = "event_id, device_id::text AS device_id, kind, command_id, generation, \
    fence_epoch, device_sequence, fingerprint, disposition, \
    floor(extract(epoch FROM received_at) * 1000000)::bigint AS received_at_micros, \
    floor(extract(epoch FROM committed_at) * 1000000)::bigint AS committed_at_micros";

#[allow(dead_code)] // Used only through FencedIngressTx until #1903 composes the ingress UoW.
fn evidence_columns(
    evidence: &DeviceIngressEvidence,
) -> (&'static str, Option<&str>, u64, u64, DeviceSequence) {
    let kind = evidence.kind_label();
    match evidence.view() {
        DeviceIngressEvidenceView::AckReceived {
            command_id,
            coordinate,
            sequence,
        } => (
            kind,
            Some(command_id.as_str()),
            coordinate.generation().get(),
            coordinate.epoch().get(),
            sequence,
        ),
        DeviceIngressEvidenceView::AckRejected {
            command_id,
            coordinate,
            sequence,
        } => (
            kind,
            Some(command_id.as_str()),
            coordinate.generation().get(),
            coordinate.epoch().get(),
            sequence,
        ),
        DeviceIngressEvidenceView::Report {
            observed_generation,
            fence_epoch,
            sequence,
        } => (
            kind,
            None,
            observed_generation.get(),
            fence_epoch.get(),
            sequence,
        ),
    }
}

#[allow(dead_code)] // Used only through FencedIngressTx until #1903 composes the ingress UoW.
async fn insert_receipt(
    conn: &mut PgConnection,
    tenant: &str,
    device: &str,
    evidence: &DeviceIngressEvidence,
    disposition: DeviceIngressDisposition,
) -> Result<Option<IngressRow>, StoreError> {
    let (kind, command_id, generation, fence_epoch, sequence) = evidence_columns(evidence);
    sqlx::query_as::<_, IngressRow>(&format!(
        "INSERT INTO device_ingress_receipts (tenant_id, event_id, device_id, kind, command_id, \
         generation, fence_epoch, device_sequence, fingerprint, disposition) VALUES ( \
         $1::uuid, $2, $3::uuid, $4, $5, $6, $7, $8, $9, $10) \
         ON CONFLICT DO NOTHING RETURNING {INGRESS_COLUMNS}"
    ))
    .bind(tenant)
    .bind(evidence.envelope_id().as_str())
    .bind(device)
    .bind(kind)
    .bind(command_id)
    .bind(coordinate_to_i64(generation)?)
    .bind(coordinate_to_i64(fence_epoch)?)
    .bind(coordinate_to_i64(sequence.get())?)
    .bind(evidence.fingerprint().as_bytes().as_slice())
    .bind(disposition.as_label())
    .fetch_optional(conn)
    .await
    .map_err(storage)
}

async fn select_receipt(
    conn: &mut PgConnection,
    tenant: &str,
    device: &str,
    event_id: &str,
) -> Result<Option<IngressRow>, StoreError> {
    let query = format!(
        "SELECT {INGRESS_COLUMNS} FROM device_ingress_receipts \
         WHERE tenant_id = $1::uuid AND event_id = $2 AND device_id = $3::uuid"
    );
    sqlx::query_as::<_, IngressRow>(&query)
        .bind(tenant)
        .bind(event_id)
        .bind(device)
        .fetch_optional(conn)
        .await
        .map_err(storage)
}

fn parse_disposition(value: &str) -> Result<DeviceIngressDisposition, StoreError> {
    match value {
        "advanced" => Ok(DeviceIngressDisposition::Advanced),
        "duplicate" => Ok(DeviceIngressDisposition::Duplicate),
        "late" => Ok(DeviceIngressDisposition::Late),
        "rejected" => Ok(DeviceIngressDisposition::Rejected),
        "device_rejected" => Ok(DeviceIngressDisposition::DeviceRejected),
        "scope_mismatch" => Ok(DeviceIngressDisposition::ScopeMismatch),
        "out_of_order" => Ok(DeviceIngressDisposition::OutOfOrder),
        "stale_generation" => Ok(DeviceIngressDisposition::StaleGeneration),
        "stale_fence" => Ok(DeviceIngressDisposition::StaleFence),
        "stale_sequence" => Ok(DeviceIngressDisposition::StaleSequence),
        _ => Err(ingress_corruption(DeviceIngressCorruption::Vocabulary)),
    }
}

fn restore_receipt(row: IngressRow) -> Result<DeviceIngressReceipt, StoreError> {
    uuid::Uuid::parse_str(&row.device_id)
        .map_err(|_| ingress_corruption(DeviceIngressCorruption::Identity))?;
    let envelope = DeviceIngressEnvelopeId::parse(&row.event_id).map_err(corrupt_ingress)?;
    let generation = u64::try_from(row.generation)
        .map_err(|_| ingress_corruption(DeviceIngressCorruption::Coordinate))?;
    let epoch = u64::try_from(row.fence_epoch)
        .map_err(|_| ingress_corruption(DeviceIngressCorruption::Coordinate))?;
    let fence_epoch = FenceEpoch::try_new(epoch)
        .map_err(|_| ingress_corruption(DeviceIngressCorruption::Coordinate))?;
    let sequence = DeviceSequence::restore(row.device_sequence)
        .map_err(|_| ingress_corruption(DeviceIngressCorruption::Coordinate))?;
    let fingerprint = DeviceIngressFingerprint::from_bytes(ingress_bytes32(&row.fingerprint)?);
    let evidence = match row.kind.as_str() {
        "ack_received" => DeviceIngressEvidence::ack_received(
            envelope,
            DeviceCommandId::parse(
                row.command_id
                    .as_deref()
                    .ok_or_else(|| ingress_corruption(DeviceIngressCorruption::Shape))?,
            )
            .map_err(|_| ingress_corruption(DeviceIngressCorruption::Identity))?,
            FenceCoordinate::new(
                DesiredGeneration::try_new(generation)
                    .map_err(|_| ingress_corruption(DeviceIngressCorruption::Coordinate))?,
                fence_epoch,
            ),
            sequence,
            fingerprint,
        ),
        "ack_rejected" => DeviceIngressEvidence::ack_rejected(
            envelope,
            DeviceCommandId::parse(
                row.command_id
                    .as_deref()
                    .ok_or_else(|| ingress_corruption(DeviceIngressCorruption::Shape))?,
            )
            .map_err(|_| ingress_corruption(DeviceIngressCorruption::Identity))?,
            FenceCoordinate::new(
                DesiredGeneration::try_new(generation)
                    .map_err(|_| ingress_corruption(DeviceIngressCorruption::Coordinate))?,
                fence_epoch,
            ),
            sequence,
            fingerprint,
        ),
        "report" if row.command_id.is_none() => DeviceIngressEvidence::report(
            envelope,
            ObservedGeneration::try_new(generation)
                .map_err(|_| ingress_corruption(DeviceIngressCorruption::Coordinate))?,
            fence_epoch,
            sequence,
            fingerprint,
        ),
        "report" => return Err(ingress_corruption(DeviceIngressCorruption::Shape)),
        _ => return Err(ingress_corruption(DeviceIngressCorruption::Vocabulary)),
    };
    DeviceIngressReceipt::restore(
        evidence,
        parse_disposition(&row.disposition)?,
        decode_ingress_time(row.received_at_micros)?,
        decode_ingress_time(row.committed_at_micros)?,
    )
    .map_err(corrupt_ingress)
}

// Crate-private helpers exist only behind the explicit integration-test feature for real-provider
// conformance. Production command creation is fenced inside `AttemptScope::record_fenced_command`;
// authenticated ACK/report mutation enters through `FencedIngressTx`.
#[cfg(all(test, feature = "integration"))]
impl PgDeviceCommandStore {
    #[tracing::instrument(
        name = "device_command.store",
        skip_all,
        fields(component = "device_command_store", operation = "create")
    )]
    async fn create_command(
        &self,
        scope: DeviceCertificateScope,
        input: CreateDeviceCommand,
    ) -> Result<CreateDeviceCommandOutcome, StoreError> {
        if !scope_matches(scope, input.command_scope()) {
            return Err(StoreError::ScopeMismatch);
        }
        let (tenant, device) = scope_params(scope);
        let command_id = input.command_id().as_str().to_owned();
        let coordinate = input.coordinate();
        let digest = input.intent_digest();
        let attempt = self
            .write_pool
            .identity_write_attempt(
                scope,
                move |mut tx| {
                    Box::pin(async move {
                        let mut identity = tx.identity();
                        let mut commands = identity.device_commands();
                        let authority =
                            lock_device_authority(&mut *commands.conn, &tenant, &device).await?;
                        if coordinate_to_i64(coordinate.generation().get())? != authority.generation
                            || coordinate_to_i64(coordinate.epoch().get())? != authority.fence_epoch
                        {
                            return Err(StoreError::InvariantViolation);
                        }
                        let at = commands.transaction_time().await?;
                        let snapshot = input
                            .into_state(at)
                            .map_err(StoreError::MutationRejected)?
                            .snapshot();
                        if let Some(row) = commands
                            .command_for_update(&tenant, &device, &command_id)
                            .await?
                        {
                            let persisted = restore_command(scope.tenant(), row)?.snapshot();
                            return Ok(if same_create_identity(&persisted, &snapshot) {
                                CreateDeviceCommandOutcome::Replay(persisted)
                            } else {
                                CreateDeviceCommandOutcome::IdentityConflict
                            });
                        }
                        if let Some(active) = commands
                            .active_command_id(&tenant, &device, coordinate, digest)
                            .await?
                        {
                            return Ok(CreateDeviceCommandOutcome::ActiveConflict {
                                command_id: active,
                            });
                        }
                        let row = commands
                            .insert_command(&tenant, &device, &snapshot)
                            .await?
                            .ok_or(StoreError::InvariantViolation)?;
                        Ok(CreateDeviceCommandOutcome::Created(
                            restore_command(scope.tenant(), row)?.snapshot(),
                        ))
                    })
                },
                storage,
            )
            .await;
        finish_write_attempt(attempt)
    }

    #[tracing::instrument(
        name = "device_command.store",
        skip_all,
        fields(
            component = "device_command_store",
            operation = mutation.as_label()
        )
    )]
    async fn transition_command(
        &self,
        scope: DeviceCertificateScope,
        command_id: DeviceCommandId,
        expected: CommandVersion,
        mutation: DeviceCommandMutation,
    ) -> Result<TransitionDeviceCommandOutcome, StoreError> {
        let (tenant, device) = scope_params(scope);
        let attempt = self
            .write_pool
            .identity_write_attempt(
                scope,
                move |mut tx| {
                    Box::pin(async move {
                        {
                            let mut identity = tx.identity();
                            let commands = identity.device_commands();
                            lock_device_authority(&mut *commands.conn, &tenant, &device).await?;
                        }
                        let row = {
                            let mut identity = tx.identity();
                            identity
                                .device_commands()
                                .command_for_update(&tenant, &device, command_id.as_str())
                                .await?
                        };
                        let Some(row) = row else {
                            return Ok(TransitionDeviceCommandOutcome::Missing);
                        };
                        let state = restore_command(scope.tenant(), row)?;
                        if state.version() != expected {
                            return Ok(TransitionDeviceCommandOutcome::VersionConflict {
                                actual: state.version(),
                            });
                        }
                        let at = {
                            let mut identity = tx.identity();
                            identity.device_commands().transaction_time().await?
                        };
                        let transition = mutation
                            .apply_to(state, at)
                            .map_err(|error| StoreError::MutationRejected(error.error().clone()))?;
                        let outcome = transition.outcome();
                        let snapshot = transition.into_state().snapshot();
                        if outcome != CommandTransitionOutcome::Advanced {
                            return Ok(TransitionDeviceCommandOutcome::NoChange {
                                snapshot,
                                outcome,
                            });
                        }
                        let updated = {
                            let mut identity = tx.identity();
                            identity
                                .device_commands()
                                .update_command(&tenant, &device, expected, &snapshot)
                                .await?
                        };
                        if !updated {
                            return Err(StoreError::InvariantViolation);
                        }
                        Ok(TransitionDeviceCommandOutcome::Advanced(snapshot))
                    })
                },
                storage,
            )
            .await;
        finish_write_attempt(attempt)
    }

    #[tracing::instrument(
        name = "device_command.store",
        skip_all,
        fields(component = "device_command_store", operation = "load")
    )]
    async fn load_command(
        &self,
        scope: DeviceCertificateScope,
        command_id: DeviceCommandId,
    ) -> Result<Option<DeviceCommandSnapshot>, StoreError> {
        let (tenant, device) = scope_params(scope);
        self.read_pool
            .identity_repeatable_read_map(
                scope,
                move |mut tx| {
                    Box::pin(async move {
                        let row = tx
                            .identity()
                            .device_commands()
                            .command(&tenant, &device, command_id.as_str())
                            .await?;
                        row.map(|row| {
                            restore_command(scope.tenant(), row).map(|state| state.snapshot())
                        })
                        .transpose()
                    })
                },
                storage,
            )
            .await
    }

    #[tracing::instrument(
        name = "device_command.store",
        skip_all,
        fields(component = "device_command_store", operation = "load_ingress")
    )]
    async fn load_ingress_evidence(
        &self,
        scope: DeviceCertificateScope,
        envelope_id: DeviceIngressEnvelopeId,
    ) -> Result<Option<DeviceIngressReceipt>, StoreError> {
        let (tenant, device) = scope_params(scope);
        self.read_pool
            .identity_repeatable_read_map(
                scope,
                move |mut tx| {
                    Box::pin(async move {
                        tx.identity()
                            .device_commands()
                            .receipt(&tenant, &device, envelope_id.as_str())
                            .await?
                            .map(restore_receipt)
                            .transpose()
                    })
                },
                storage,
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_command_row() -> CommandRow {
        CommandRow {
            command_id: "command-1".to_owned(),
            device_id: "00000000-0000-4000-8000-000000000002".to_owned(),
            generation: 1,
            fence_epoch: 2,
            intent_digest: vec![7; 32],
            deadline_micros: 10_000_000,
            state: "received".to_owned(),
            version: 3,
            queued_at_micros: 1_000_000,
            published_at_micros: Some(2_000_000),
            received_at_micros: Some(3_000_000),
            terminal_at_micros: None,
        }
    }

    fn valid_ingress_row() -> IngressRow {
        IngressRow {
            event_id: "event-1".to_owned(),
            device_id: "00000000-0000-4000-8000-000000000002".to_owned(),
            kind: "ack_received".to_owned(),
            command_id: Some("command-1".to_owned()),
            generation: 1,
            fence_epoch: 2,
            device_sequence: 0,
            fingerprint: vec![9; 32],
            disposition: "advanced".to_owned(),
            received_at_micros: 1,
            committed_at_micros: 1,
        }
    }

    #[test]
    fn write_projection_keeps_domain_state_vocabulary() {
        let tenant = vocab::TenantId::parse("00000000-0000-4000-8000-000000000001").unwrap();
        let snapshot = restore_command(tenant, valid_command_row())
            .expect("valid command")
            .snapshot();
        let state: deviceloop::DeviceCommandStatus = snapshot_columns(&snapshot).state;
        assert_eq!(state, deviceloop::DeviceCommandStatus::Received);
    }

    #[test]
    fn epoch_micros_sql_uses_a_controlled_exact_fragment() {
        assert_eq!(
            EPOCH_MICROS_SQL_7,
            "TIMESTAMPTZ 'epoch' + $7::bigint * INTERVAL '1 microsecond'"
        );
    }

    #[test]
    fn command_row_codec_restores_state_specific_snapshot() {
        let tenant = vocab::TenantId::parse("00000000-0000-4000-8000-000000000001").unwrap();
        let state = restore_command(tenant, valid_command_row()).expect("valid row");
        assert_eq!(state.status().as_label(), "received");
        assert_eq!(state.version().get(), 3);
        assert_eq!(state.intent_digest().as_bytes(), &[7; 32]);
    }

    #[test]
    fn command_row_codec_reports_every_closed_corruption_reason() {
        let tenant = vocab::TenantId::parse("00000000-0000-4000-8000-000000000001").unwrap();
        let mut row = valid_command_row();
        row.device_id = "not-a-uuid".to_owned();
        assert!(matches!(
            restore_command(tenant, row),
            Err(StoreError::CorruptCommand(
                DeviceCommandCorruption::Identity
            ))
        ));

        let mut row = valid_command_row();
        row.generation = 0;
        assert!(matches!(
            restore_command(tenant, row),
            Err(StoreError::CorruptCommand(
                DeviceCommandCorruption::Coordinate
            ))
        ));

        let mut row = valid_command_row();
        row.intent_digest.pop();
        assert!(matches!(
            restore_command(tenant, row),
            Err(StoreError::CorruptCommand(DeviceCommandCorruption::Digest))
        ));

        let mut row = valid_command_row();
        row.deadline_micros = i64::MIN;
        assert!(matches!(
            restore_command(tenant, row),
            Err(StoreError::CorruptCommand(
                DeviceCommandCorruption::Timestamp
            ))
        ));

        let mut row = valid_command_row();
        row.published_at_micros = None;
        assert!(matches!(
            restore_command(tenant, row),
            Err(StoreError::CorruptCommand(DeviceCommandCorruption::Shape))
        ));

        let mut row = valid_command_row();
        row.state = "invented".to_owned();
        assert!(matches!(
            restore_command(tenant, row),
            Err(StoreError::CorruptCommand(DeviceCommandCorruption::State))
        ));
    }

    #[test]
    fn ingress_row_codec_restores_exact_evidence() {
        let receipt = restore_receipt(valid_ingress_row()).expect("valid receipt");
        assert_eq!(receipt.evidence().kind_label(), "ack_received");
        assert_eq!(receipt.disposition(), DeviceIngressDisposition::Advanced);
        assert_eq!(evidence_columns(receipt.evidence()).4.get(), 0);
    }

    #[test]
    fn report_row_codec_preserves_observed_generation_and_zero_sequence() {
        let row = IngressRow {
            event_id: "report-1".to_owned(),
            device_id: "00000000-0000-4000-8000-000000000002".to_owned(),
            kind: "report".to_owned(),
            command_id: None,
            generation: 3,
            fence_epoch: 4,
            device_sequence: 0,
            fingerprint: vec![8; 32],
            disposition: "duplicate".to_owned(),
            received_at_micros: 1,
            committed_at_micros: 1,
        };
        let receipt = restore_receipt(row).expect("valid report receipt");
        assert!(matches!(
            receipt.evidence().view(),
            DeviceIngressEvidenceView::Report {
                observed_generation,
                fence_epoch,
                sequence,
            } if observed_generation.get() == 3 && fence_epoch.get() == 4 && sequence.get() == 0
        ));
    }

    #[test]
    fn ingress_row_codec_reports_every_closed_corruption_reason() {
        let mut row = valid_ingress_row();
        row.device_id = "not-a-uuid".to_owned();
        assert!(matches!(
            restore_receipt(row),
            Err(StoreError::CorruptIngress(
                DeviceIngressCorruption::Identity
            ))
        ));

        let mut row = valid_ingress_row();
        row.device_sequence = -1;
        assert!(matches!(
            restore_receipt(row),
            Err(StoreError::CorruptIngress(
                DeviceIngressCorruption::Coordinate
            ))
        ));

        let mut row = valid_ingress_row();
        row.fingerprint.pop();
        assert!(matches!(
            restore_receipt(row),
            Err(StoreError::CorruptIngress(
                DeviceIngressCorruption::Fingerprint
            ))
        ));

        let mut row = valid_ingress_row();
        row.received_at_micros = i64::MIN;
        assert!(matches!(
            restore_receipt(row),
            Err(StoreError::CorruptIngress(
                DeviceIngressCorruption::Timestamp
            ))
        ));

        let mut row = valid_ingress_row();
        row.command_id = None;
        assert!(matches!(
            restore_receipt(row),
            Err(StoreError::CorruptIngress(DeviceIngressCorruption::Shape))
        ));

        let mut row = valid_ingress_row();
        row.kind = "invented".to_owned();
        assert!(matches!(
            restore_receipt(row),
            Err(StoreError::CorruptIngress(
                DeviceIngressCorruption::Vocabulary
            ))
        ));

        let mut row = valid_ingress_row();
        row.disposition = "invented".to_owned();
        assert!(matches!(
            restore_receipt(row),
            Err(StoreError::CorruptIngress(
                DeviceIngressCorruption::Vocabulary
            ))
        ));
    }

    #[test]
    fn migration_closes_sequence_and_report_shape_at_storage_boundary() {
        const MIGRATION: &str = include_str!("../migrations/0082_create_device_commands.sql");
        assert!(MIGRATION.contains("device_sequence >= 0"));
        assert!(MIGRATION.contains("kind = 'report' AND command_id IS NULL"));

        let evidence = DeviceIngressEvidence::report(
            DeviceIngressEnvelopeId::parse("report-observed-semantics").unwrap(),
            ObservedGeneration::try_new(3).unwrap(),
            FenceEpoch::try_new(4).unwrap(),
            DeviceSequence::try_new(0).unwrap(),
            DeviceIngressFingerprint::from_bytes([6; 32]),
        );
        assert_eq!(
            evidence_columns(&evidence),
            ("report", None, 3, 4, DeviceSequence::try_new(0).unwrap())
        );
    }

    #[test]
    fn storage_error_mapping_is_closed_and_redacted() {
        let transient = storage(sqlx::Error::PoolTimedOut);
        assert!(matches!(&transient, StoreError::StorageTransient { .. }));
        let transient_source = std::error::Error::source(&transient).expect("redacted source");
        assert_eq!(transient_source.to_string(), "<redacted>");
        assert!(transient_source.source().is_none());

        let raw = sqlx::Error::Protocol("sensitive-protocol-marker".to_owned());
        assert!(format!("{raw:?}").contains("sensitive-protocol-marker"));
        let permanent = storage(raw);
        assert!(matches!(&permanent, StoreError::StoragePermanent { .. }));
        assert!(!format!("{permanent:?}").contains("sensitive-protocol-marker"));
        let permanent_source = std::error::Error::source(&permanent).expect("redacted source");
        assert_eq!(permanent_source.to_string(), "<redacted>");
        assert!(permanent_source.source().is_none());
    }
}

#[cfg(all(test, feature = "integration"))]
mod integration_tests {
    #![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

    use std::sync::Arc;

    use deviceloop::{
        AppendDeviceIngressOutcome, CommandIntentDigest, CommandVersion, CreateDeviceCommand,
        CreateDeviceCommandOutcome, DesiredGeneration, DeviceCommandDeadline, DeviceCommandId,
        DeviceCommandMutation, DeviceCommandScope, DeviceCommandSnapshot, DeviceCommandStatus,
        DeviceIngressDisposition, DeviceIngressEnvelopeId, DeviceIngressEvidence,
        DeviceIngressFingerprint, DeviceSequence, FenceEpoch, GenerationTracker,
        ObservedGeneration, TransitionDeviceCommandOutcome,
    };
    use diport::ManagedResource as _;
    use identity::ports::device_certificate::DeviceCertificateScope;
    use testkit::device_command_conformance::{
        DeviceCommandCasCase, DeviceCommandCasObservation, DeviceCommandCreateCase,
        DeviceCommandCreateObservation, DeviceIngressConformanceCase,
        DeviceIngressConformanceObservation, assert_device_command_cas,
        assert_device_command_create, assert_device_command_restart_equivalence,
        assert_device_ingress_conformance,
    };

    use super::PgDeviceCommandStore;

    type TestError = Box<dyn std::error::Error + Send + Sync>;
    type TestResult = Result<(), TestError>;

    #[derive(Clone, Copy)]
    struct Target {
        scope: DeviceCertificateScope,
        command_scope: DeviceCommandScope,
    }

    #[derive(Clone, Copy)]
    enum IngressKind {
        AckReceived,
        AckRejected,
        Report,
    }

    impl IngressKind {
        const fn label(self) -> &'static str {
            match self {
                Self::AckReceived => "ack-received",
                Self::AckRejected => "ack-rejected",
                Self::Report => "report",
            }
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    struct CommandObservation {
        command_id: String,
        state: &'static str,
        version: i64,
        digest: [u8; 32],
    }

    fn observe_command(snapshot: DeviceCommandSnapshot) -> CommandObservation {
        let columns = super::snapshot_columns(&snapshot);
        CommandObservation {
            command_id: columns.common.command_id().as_str().to_owned(),
            state: columns.state.as_label(),
            version: columns.common.version().get(),
            digest: *columns.common.intent_digest().as_bytes(),
        }
    }

    #[derive(Clone, Copy)]
    enum DatabaseGuardProbe {
        ReceiptUpdate,
        ReceiptDelete,
        VersionGap,
    }

    impl DatabaseGuardProbe {
        const fn expected_code(self) -> &'static str {
            match self {
                Self::ReceiptUpdate | Self::ReceiptDelete | Self::VersionGap => "42501",
            }
        }
    }

    fn new_target() -> Target {
        let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
        new_target_for_tenant(tenant)
    }

    fn new_target_for_tenant(tenant: vocab::TenantId) -> Target {
        let device = ids::DeviceId::new(uuid::Uuid::new_v4());
        Target {
            scope: DeviceCertificateScope::for_test(tenant, device),
            command_scope: DeviceCommandScope::new(tenant, device),
        }
    }

    fn tracker(target: Target) -> GenerationTracker<&'static str> {
        GenerationTracker::new(
            target.command_scope,
            DesiredGeneration::try_new(1).unwrap(),
            "desired",
            FenceEpoch::try_new(7).unwrap(),
        )
    }

    fn deadline() -> std::time::SystemTime {
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(4_000_000_000)
    }

    fn near_deadline() -> std::time::SystemTime {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time after epoch");
        let micros = u64::try_from(now.as_micros()).expect("current timestamp fits u64");
        std::time::UNIX_EPOCH + std::time::Duration::from_micros(micros + 2_000_000)
    }

    fn create(target: Target, id: &str, digest: u8) -> CreateDeviceCommand {
        create_with_deadline(target, id, digest, deadline())
    }

    fn create_with_deadline(
        target: Target,
        id: &str,
        digest: u8,
        deadline: std::time::SystemTime,
    ) -> CreateDeviceCommand {
        CreateDeviceCommand::new(
            DeviceCommandId::parse(id).unwrap(),
            CommandIntentDigest::from_bytes([digest; 32]),
            tracker(target).current_fence(),
            DeviceCommandDeadline::try_new(deadline).unwrap(),
        )
    }

    async fn created_snapshot(
        store: &PgDeviceCommandStore,
        target: Target,
        id: &str,
        digest: u8,
        deadline: std::time::SystemTime,
    ) -> Result<DeviceCommandSnapshot, TestError> {
        match store
            .create_command(
                target.scope,
                create_with_deadline(target, id, digest, deadline),
            )
            .await?
        {
            CreateDeviceCommandOutcome::Created(snapshot) => Ok(snapshot),
            other => panic!("expected created command, got {other:?}"),
        }
    }

    async fn transition_snapshot(
        store: &PgDeviceCommandStore,
        target: Target,
        id: &str,
        current: &DeviceCommandSnapshot,
        mutation: DeviceCommandMutation,
    ) -> Result<DeviceCommandSnapshot, TestError> {
        let expected = super::snapshot_columns(current).common.version();
        match store
            .transition_command(
                target.scope,
                DeviceCommandId::parse(id)?,
                expected,
                mutation,
            )
            .await?
        {
            TransitionDeviceCommandOutcome::Advanced(snapshot) => Ok(snapshot),
            other => panic!("expected advanced command, got {other:?}"),
        }
    }

    fn report(event: &str, fingerprint: u8) -> DeviceIngressEvidence {
        DeviceIngressEvidence::report(
            DeviceIngressEnvelopeId::parse(event).unwrap(),
            ObservedGeneration::try_new(1).unwrap(),
            FenceEpoch::try_new(7).unwrap(),
            DeviceSequence::try_new(1).unwrap(),
            DeviceIngressFingerprint::from_bytes([fingerprint; 32]),
        )
    }

    fn ingress(
        kind: IngressKind,
        event: &str,
        command_id: &str,
        generation: u64,
        epoch: u64,
        sequence: u64,
        fingerprint: u8,
        disposition: DeviceIngressDisposition,
    ) -> DeviceIngressEvidence {
        let envelope = DeviceIngressEnvelopeId::parse(event).unwrap();
        let epoch = FenceEpoch::try_new(epoch).unwrap();
        let sequence = DeviceSequence::try_new(sequence).unwrap();
        let fingerprint = DeviceIngressFingerprint::from_bytes([fingerprint; 32]);
        let evidence = match kind {
            IngressKind::AckReceived => DeviceIngressEvidence::ack_received(
                envelope,
                DeviceCommandId::parse(command_id).unwrap(),
                deviceloop::FenceCoordinate::new(
                    DesiredGeneration::try_new(generation).unwrap(),
                    epoch,
                ),
                sequence,
                fingerprint,
            ),
            IngressKind::AckRejected => DeviceIngressEvidence::ack_rejected(
                envelope,
                DeviceCommandId::parse(command_id).unwrap(),
                deviceloop::FenceCoordinate::new(
                    DesiredGeneration::try_new(generation).unwrap(),
                    epoch,
                ),
                sequence,
                fingerprint,
            ),
            IngressKind::Report => DeviceIngressEvidence::report(
                envelope,
                ObservedGeneration::try_new(generation).unwrap(),
                epoch,
                sequence,
                fingerprint,
            ),
        };
        let _ = disposition;
        evidence
    }

    fn observe_create(
        outcome: CreateDeviceCommandOutcome,
    ) -> DeviceCommandCreateObservation<CommandObservation, DeviceCommandId> {
        match outcome {
            CreateDeviceCommandOutcome::Created(snapshot) => {
                DeviceCommandCreateObservation::Created(observe_command(snapshot))
            }
            CreateDeviceCommandOutcome::Replay(snapshot) => {
                DeviceCommandCreateObservation::Replay(observe_command(snapshot))
            }
            CreateDeviceCommandOutcome::IdentityConflict => {
                DeviceCommandCreateObservation::IdentityConflict
            }
            CreateDeviceCommandOutcome::ActiveConflict { command_id } => {
                DeviceCommandCreateObservation::ActiveConflict { command_id }
            }
        }
    }

    fn observe_cas(
        outcome: TransitionDeviceCommandOutcome,
    ) -> DeviceCommandCasObservation<CommandObservation, CommandVersion> {
        match outcome {
            TransitionDeviceCommandOutcome::Advanced(snapshot) => {
                DeviceCommandCasObservation::Advanced(observe_command(snapshot))
            }
            TransitionDeviceCommandOutcome::VersionConflict { actual } => {
                DeviceCommandCasObservation::VersionConflict { actual }
            }
            TransitionDeviceCommandOutcome::NoChange { .. } => {
                DeviceCommandCasObservation::NoChange
            }
            TransitionDeviceCommandOutcome::Missing => DeviceCommandCasObservation::Missing,
        }
    }

    fn observe_ingress(
        outcome: AppendDeviceIngressOutcome,
    ) -> DeviceIngressConformanceObservation<deviceloop::DeviceIngressReceipt> {
        match outcome {
            AppendDeviceIngressOutcome::Appended(receipt) => {
                DeviceIngressConformanceObservation::Appended(receipt)
            }
            AppendDeviceIngressOutcome::Replay(receipt) => {
                DeviceIngressConformanceObservation::Replay(receipt)
            }
            AppendDeviceIngressOutcome::Conflict => DeviceIngressConformanceObservation::Conflict,
        }
    }

    async fn insert_desired(store: &crate::PgStore, target: Target) -> TestResult {
        sqlx::query(
            "INSERT INTO device_certificate_desired_states \
             (tenant_id, device_id, generation, validity_seconds, renew_before_seconds, \
              client_auth, server_auth, sans) \
             VALUES ($1::uuid, $2::uuid, 1, 3600, 600, true, false, ARRAY[]::text[])",
        )
        .bind(target.scope.tenant().as_uuid().to_string())
        .bind(target.scope.device().as_uuid().to_string())
        .execute(&store.pool)
        .await?;
        let target_id: String = sqlx::query_scalar(
            "INSERT INTO reconcile_targets \
             (tenant_id, reconciler_id, resource_kind, resource_id) \
             VALUES ($1::uuid, $2, $3, $4) \
             RETURNING target_id::text",
        )
        .bind(target.scope.tenant().as_uuid().to_string())
        .bind(super::DEVICE_CERTIFICATE_RECONCILER_ID)
        .bind(super::DEVICE_CERTIFICATE_RESOURCE_KIND)
        .bind(target.scope.device().as_uuid().to_string())
        .fetch_one(&store.pool)
        .await?;
        sqlx::query(
            "INSERT INTO reconcile_leases (tenant_id, target_id, epoch) \
             VALUES ($1::uuid, $2::uuid, 7)",
        )
        .bind(target.scope.tenant().as_uuid().to_string())
        .bind(target_id)
        .execute(&store.pool)
        .await?;
        Ok(())
    }

    async fn assert_database_guard(
        store: &PgDeviceCommandStore,
        scope: DeviceCertificateScope,
        probe: DatabaseGuardProbe,
    ) -> TestResult {
        let result = store
            .write_pool
            .identity_write(
                scope,
                move |mut tx| {
                    Box::pin(async move {
                        let mut identity = tx.identity();
                        let mut commands = identity.device_commands();
                        match probe {
                            DatabaseGuardProbe::ReceiptUpdate => {
                                commands.probe_receipt_update("event-1").await
                            }
                            DatabaseGuardProbe::ReceiptDelete => {
                                commands.probe_receipt_delete("event-1").await
                            }
                            DatabaseGuardProbe::VersionGap => {
                                commands.probe_version_gap("command-1").await
                            }
                        }
                    })
                },
                std::convert::identity,
            )
            .await;
        let error = result.expect_err("database guard probe must reject the statement");
        assert_eq!(
            error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .as_deref(),
            Some(probe.expected_code())
        );
        Ok(())
    }

    fn appended_disposition(outcome: AppendDeviceIngressOutcome) -> DeviceIngressDisposition {
        match outcome {
            AppendDeviceIngressOutcome::Appended(receipt) => receipt.disposition(),
            other => panic!("expected appended receipt, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn real_postgres_fenced_ingress_classifies_and_claims_before_mutation() -> TestResult {
        let (fixture, owner) = crate::test_pg::connect_pg().await?;
        owner.run_migrations().await?;
        let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
        let report_target = new_target_for_tenant(tenant);
        let received_target = new_target_for_tenant(tenant);
        let rejected_target = new_target_for_tenant(tenant);
        let queued_target = new_target_for_tenant(tenant);
        let spoof_target = new_target_for_tenant(tenant);
        let collision_left = new_target_for_tenant(tenant);
        let collision_right = new_target_for_tenant(tenant);
        let all_targets = [
            report_target,
            received_target,
            rejected_target,
            queued_target,
            spoof_target,
            collision_left,
            collision_right,
        ];
        for target in all_targets {
            insert_desired(&owner, target).await?;
        }

        sqlx::query(
            "UPDATE device_certificate_desired_states SET generation = 2 \
             WHERE tenant_id = $1::uuid AND device_id = $2::uuid",
        )
        .bind(tenant.as_uuid().to_string())
        .bind(report_target.scope.device().as_uuid().to_string())
        .execute(&owner.pool)
        .await?;

        let writer = crate::test_pg::connect_pg_rss_app_role(&fixture, &owner).await?;
        let reader = crate::test_pg::connect_pg_rss_app_read_role(&fixture, &owner).await?;
        let store = Arc::new(PgDeviceCommandStore::from_unverified_stores_for_test(
            &reader, &writer,
        ));
        let authority_store = PgDeviceCommandStore::from_unverified_stores_for_test(&owner, &owner);

        // A rejected future coordinate with a huge sequence must not poison the exact authority.
        assert_eq!(
            appended_disposition(
                store
                    .record_fenced_ingress_for_test(
                        report_target.scope,
                        ingress(
                            IngressKind::Report,
                            "future-high-sequence",
                            "unused",
                            3,
                            7,
                            10_000,
                            1,
                            DeviceIngressDisposition::Rejected,
                        ),
                    )
                    .await?,
            ),
            DeviceIngressDisposition::Rejected
        );
        assert_eq!(
            appended_disposition(
                store
                    .record_fenced_ingress_for_test(
                        report_target.scope,
                        ingress(
                            IngressKind::Report,
                            "exact-low-sequence",
                            "unused",
                            2,
                            7,
                            1,
                            2,
                            DeviceIngressDisposition::Advanced,
                        ),
                    )
                    .await?,
            ),
            DeviceIngressDisposition::Advanced
        );
        for (event, generation, epoch, sequence, expected) in [
            (
                "stale-generation",
                1,
                7,
                20_000,
                DeviceIngressDisposition::StaleGeneration,
            ),
            (
                "stale-fence",
                2,
                6,
                20_001,
                DeviceIngressDisposition::StaleFence,
            ),
            (
                "stale-sequence",
                2,
                7,
                1,
                DeviceIngressDisposition::StaleSequence,
            ),
        ] {
            assert_eq!(
                appended_disposition(
                    store
                        .record_fenced_ingress_for_test(
                            report_target.scope,
                            ingress(
                                IngressKind::Report,
                                event,
                                "unused",
                                generation,
                                epoch,
                                sequence,
                                3,
                                expected,
                            ),
                        )
                        .await?,
                ),
                expected
            );
        }

        async fn create_and_publish(
            store: &PgDeviceCommandStore,
            owner: &crate::PgStore,
            target: Target,
            id: &str,
            digest: u8,
        ) -> Result<DeviceCommandSnapshot, TestError> {
            created_snapshot(store, target, id, digest, deadline()).await?;
            sqlx::query(
                "UPDATE device_commands SET state = 'published', version = version + 1, \
                 published_at = transaction_timestamp() \
                 WHERE tenant_id = $1::uuid AND device_id = $2::uuid AND command_id = $3",
            )
            .bind(target.scope.tenant().as_uuid().to_string())
            .bind(target.scope.device().as_uuid().to_string())
            .bind(id)
            .execute(&owner.pool)
            .await?;
            store
                .load_command(target.scope, DeviceCommandId::parse(id)?)
                .await?
                .ok_or_else(|| std::io::Error::other("seeded command missing").into())
        }

        let received = create_and_publish(
            &authority_store,
            &owner,
            received_target,
            "ack-received",
            10,
        )
        .await?;
        assert_eq!(
            appended_disposition(
                store
                    .record_fenced_ingress_for_test(
                        received_target.scope,
                        ingress(
                            IngressKind::AckReceived,
                            "ack-received-event",
                            "ack-received",
                            1,
                            7,
                            1,
                            10,
                            DeviceIngressDisposition::Advanced,
                        ),
                    )
                    .await?,
            ),
            DeviceIngressDisposition::Advanced
        );
        assert_eq!(
            super::snapshot_columns(
                &store
                    .load_command(
                        received_target.scope,
                        DeviceCommandId::parse("ack-received")?
                    )
                    .await?
                    .expect("received command"),
            )
            .state,
            DeviceCommandStatus::Received
        );
        assert_eq!(
            appended_disposition(
                store
                    .record_fenced_ingress_for_test(
                        received_target.scope,
                        ingress(
                            IngressKind::AckReceived,
                            "ack-received-duplicate",
                            "ack-received",
                            1,
                            7,
                            2,
                            11,
                            DeviceIngressDisposition::Duplicate,
                        ),
                    )
                    .await?,
            ),
            DeviceIngressDisposition::Duplicate
        );
        assert_eq!(
            super::snapshot_columns(&received).state,
            DeviceCommandStatus::Published
        );

        create_and_publish(
            &authority_store,
            &owner,
            rejected_target,
            "ack-rejected",
            20,
        )
        .await?;
        assert_eq!(
            appended_disposition(
                store
                    .record_fenced_ingress_for_test(
                        rejected_target.scope,
                        ingress(
                            IngressKind::AckRejected,
                            "ack-rejected-event",
                            "ack-rejected",
                            1,
                            7,
                            1,
                            20,
                            DeviceIngressDisposition::DeviceRejected,
                        ),
                    )
                    .await?,
            ),
            DeviceIngressDisposition::DeviceRejected
        );
        for (event, kind, sequence, expected) in [
            (
                "ack-rejected-duplicate",
                IngressKind::AckRejected,
                2,
                DeviceIngressDisposition::Duplicate,
            ),
            (
                "ack-rejected-late",
                IngressKind::AckReceived,
                3,
                DeviceIngressDisposition::Late,
            ),
        ] {
            assert_eq!(
                appended_disposition(
                    store
                        .record_fenced_ingress_for_test(
                            rejected_target.scope,
                            ingress(kind, event, "ack-rejected", 1, 7, sequence, 21, expected),
                        )
                        .await?,
                ),
                expected
            );
        }
        assert_eq!(
            super::snapshot_columns(
                &store
                    .load_command(
                        rejected_target.scope,
                        DeviceCommandId::parse("ack-rejected")?
                    )
                    .await?
                    .expect("rejected command"),
            )
            .state,
            DeviceCommandStatus::Rejected
        );

        created_snapshot(
            &authority_store,
            queued_target,
            "queued-command",
            30,
            deadline(),
        )
        .await?;
        assert_eq!(
            appended_disposition(
                store
                    .record_fenced_ingress_for_test(
                        queued_target.scope,
                        ingress(
                            IngressKind::AckReceived,
                            "queued-out-of-order",
                            "queued-command",
                            1,
                            7,
                            1,
                            30,
                            DeviceIngressDisposition::OutOfOrder,
                        ),
                    )
                    .await?,
            ),
            DeviceIngressDisposition::OutOfOrder
        );

        create_and_publish(&authority_store, &owner, spoof_target, "spoof-command", 40).await?;
        assert_eq!(
            appended_disposition(
                store
                    .record_fenced_ingress_for_test(
                        queued_target.scope,
                        ingress(
                            IngressKind::AckReceived,
                            "cross-device-spoof",
                            "spoof-command",
                            9,
                            9,
                            99_999,
                            40,
                            DeviceIngressDisposition::ScopeMismatch,
                        ),
                    )
                    .await?,
            ),
            DeviceIngressDisposition::ScopeMismatch
        );

        create_and_publish(
            &authority_store,
            &owner,
            collision_left,
            "collision-left",
            50,
        )
        .await?;
        create_and_publish(
            &authority_store,
            &owner,
            collision_right,
            "collision-right",
            51,
        )
        .await?;
        let left = Arc::clone(&store);
        let right = Arc::clone(&store);
        let (left_outcome, right_outcome) = tokio::join!(
            left.record_fenced_ingress_for_test(
                collision_left.scope,
                ingress(
                    IngressKind::AckReceived,
                    "shared-envelope",
                    "collision-left",
                    1,
                    7,
                    1,
                    50,
                    DeviceIngressDisposition::Advanced,
                ),
            ),
            right.record_fenced_ingress_for_test(
                collision_right.scope,
                ingress(
                    IngressKind::AckReceived,
                    "shared-envelope",
                    "collision-right",
                    1,
                    7,
                    1,
                    51,
                    DeviceIngressDisposition::Advanced,
                ),
            )
        );
        let collision_outcomes = [left_outcome?, right_outcome?];
        assert_eq!(
            collision_outcomes
                .iter()
                .filter(|outcome| matches!(outcome, AppendDeviceIngressOutcome::Appended(_)))
                .count(),
            1
        );
        assert_eq!(
            collision_outcomes
                .iter()
                .filter(|outcome| matches!(outcome, AppendDeviceIngressOutcome::Conflict))
                .count(),
            1
        );
        let collision_states = [
            store
                .load_command(
                    collision_left.scope,
                    DeviceCommandId::parse("collision-left")?,
                )
                .await?
                .expect("left command"),
            store
                .load_command(
                    collision_right.scope,
                    DeviceCommandId::parse("collision-right")?,
                )
                .await?
                .expect("right command"),
        ];
        assert_eq!(
            collision_states
                .iter()
                .filter(|snapshot| super::snapshot_columns(snapshot).state
                    == DeviceCommandStatus::Received)
                .count(),
            1,
            "only the receipt owner may mutate its command"
        );
        assert_eq!(
            collision_states
                .iter()
                .filter(|snapshot| super::snapshot_columns(snapshot).state
                    == DeviceCommandStatus::Published)
                .count(),
            1,
            "the colliding envelope must leave the losing command unchanged"
        );

        drop(store);
        reader.shutdown().await?;
        writer.shutdown().await?;
        owner.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn real_postgres_enforces_lifecycle_idempotency_and_append_only() -> TestResult {
        let (fixture, owner) = crate::test_pg::connect_pg().await?;
        owner.run_migrations().await?;
        let target = new_target();
        let cas_target = new_target();
        let command_target = new_target();
        let race_target = new_target();
        let cross_tenant = new_target();
        let other_device_id = ids::DeviceId::new(uuid::Uuid::new_v4());
        let other_device = Target {
            scope: DeviceCertificateScope::for_test(target.scope.tenant(), other_device_id),
            command_scope: DeviceCommandScope::new(target.scope.tenant(), other_device_id),
        };
        insert_desired(&owner, target).await?;
        insert_desired(&owner, cas_target).await?;
        insert_desired(&owner, command_target).await?;
        insert_desired(&owner, race_target).await?;
        insert_desired(&owner, other_device).await?;
        insert_desired(&owner, cross_tenant).await?;

        let rls: Vec<(String, bool, bool)> = sqlx::query_as(
            "SELECT relname::text, relrowsecurity, relforcerowsecurity FROM pg_class \
             WHERE relname IN ('device_commands', 'device_ingress_receipts') ORDER BY relname",
        )
        .fetch_all(&owner.pool)
        .await?;
        assert_eq!(
            rls,
            vec![
                ("device_commands".to_owned(), true, true),
                ("device_ingress_receipts".to_owned(), true, true),
            ]
        );
        let active_index: bool = sqlx::query_scalar(
            "SELECT indexdef LIKE '%WHERE (state = ANY%' OR indexdef LIKE '%WHERE state IN%' \
             FROM pg_indexes WHERE indexname = 'device_commands_one_nonterminal_per_device'",
        )
        .fetch_one(&owner.pool)
        .await?;
        assert!(active_index);
        let acl_closed: bool = sqlx::query_scalar(
            "SELECT has_table_privilege('rss_app', 'device_ingress_receipts', 'SELECT') \
                AND NOT has_table_privilege('rss_app', 'device_ingress_receipts', 'UPDATE') \
                AND NOT has_table_privilege('rss_app', 'device_ingress_receipts', 'DELETE') \
                AND has_table_privilege('rss_app_read', 'device_commands', 'SELECT') \
                AND NOT has_table_privilege('rss_app_read', 'device_commands', 'INSERT') \
                AND NOT has_table_privilege('rss_app_read', 'device_commands', 'UPDATE')",
        )
        .fetch_one(&owner.pool)
        .await?;
        assert!(acl_closed);

        let writer = crate::test_pg::connect_pg_rss_app_role(&fixture, &owner).await?;
        let reader = crate::test_pg::connect_pg_rss_app_read_role(&fixture, &owner).await?;
        let _fixture = fixture;
        // The generic lifecycle carrier is test-only after 0087 revokes direct serving-role DML.
        // Production ingress authority is exercised separately through the fenced funnel test.
        let store = Arc::new(PgDeviceCommandStore::from_unverified_stores_for_test(
            &owner, &owner,
        ));
        let serving_store = PgDeviceCommandStore::from_unverified_stores_for_test(&reader, &writer);

        let scope_mismatch = store
            .create_command(
                target.scope,
                create(other_device, "scope-mismatch-command", 48),
            )
            .await;
        assert!(matches!(
            scope_mismatch,
            Err(super::StoreError::ScopeMismatch)
        ));
        let scope_mismatch_rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM device_commands WHERE command_id = 'scope-mismatch-command'",
        )
        .fetch_one(&owner.pool)
        .await?;
        assert_eq!(
            scope_mismatch_rows, 0,
            "scope mismatch must perform no write"
        );

        let missing_id = DeviceCommandId::parse("missing-command")?;
        assert_eq!(
            store.load_command(target.scope, missing_id.clone()).await?,
            None
        );
        assert!(matches!(
            store
                .transition_command(
                    target.scope,
                    missing_id,
                    CommandVersion::FIRST,
                    DeviceCommandMutation::publish(tracker(target).current_fence()),
                )
                .await?,
            TransitionDeviceCommandOutcome::Missing
        ));
        let missing_rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM device_commands WHERE command_id = 'missing-command'",
        )
        .fetch_one(&owner.pool)
        .await?;
        assert_eq!(missing_rows, 0, "missing transition must perform no write");

        #[derive(Clone, Copy)]
        enum CreateCaseInput {
            First,
            Replay,
            IdentityConflict,
            ActiveConflict,
        }

        #[derive(Clone, Copy)]
        enum CasCaseInput {
            Contender,
            Stale,
            NoChange,
            Missing,
        }

        let create_store = Arc::clone(&store);
        assert_device_command_create(DeviceCommandCreateCase {
            first_input: CreateCaseInput::First,
            replay_input: CreateCaseInput::Replay,
            identity_conflict_input: CreateCaseInput::IdentityConflict,
            active_conflict_input: CreateCaseInput::ActiveConflict,
            expected_snapshot: CommandObservation {
                command_id: "conformance-create".to_owned(),
                state: "queued",
                version: 1,
                digest: [50; 32],
            },
            expected_active_command_id: DeviceCommandId::parse("conformance-create")?,
            create: move |case| {
                let store = Arc::clone(&create_store);
                async move {
                    let input = match case {
                        CreateCaseInput::First | CreateCaseInput::Replay => {
                            create(target, "conformance-create", 50)
                        }
                        CreateCaseInput::IdentityConflict => {
                            create(target, "conformance-create", 51)
                        }
                        CreateCaseInput::ActiveConflict => {
                            create(target, "conformance-active-conflict", 50)
                        }
                    };
                    store
                        .create_command(target.scope, input)
                        .await
                        .map(observe_create)
                }
            },
        })
        .await?;

        let expected_restart = CommandObservation {
            command_id: "conformance-create".to_owned(),
            state: "queued",
            version: 1,
            digest: [50; 32],
        };
        assert_device_command_restart_equivalence(
            DeviceCommandId::parse("conformance-create")?,
            expected_restart,
            |command_id| async {
                let restarted =
                    PgDeviceCommandStore::from_unverified_stores_for_test(&owner, &owner);
                restarted
                    .load_command(target.scope, command_id)
                    .await
                    .map(|snapshot| snapshot.map(observe_command))
            },
        )
        .await?;

        let conformance_create = store
            .load_command(target.scope, DeviceCommandId::parse("conformance-create")?)
            .await?
            .expect("conformance command exists");
        transition_snapshot(
            &store,
            target,
            "conformance-create",
            &conformance_create,
            DeviceCommandMutation::cancel(tracker(target).current_fence()),
        )
        .await?;

        let cas_created =
            created_snapshot(&store, cas_target, "conformance-cas", 52, deadline()).await?;
        assert_eq!(
            super::snapshot_columns(&cas_created).state,
            DeviceCommandStatus::Queued
        );
        let cas_transition_store = Arc::clone(&store);
        let cas_load_store = Arc::clone(&store);
        let cas_missing_load_store = Arc::clone(&store);
        let cas_winner = assert_device_command_cas(DeviceCommandCasCase {
            contender_a_input: CasCaseInput::Contender,
            contender_b_input: CasCaseInput::Contender,
            stale_input: CasCaseInput::Stale,
            no_change_input: CasCaseInput::NoChange,
            missing_input: CasCaseInput::Missing,
            expected_actual_version: CommandVersion::restore(2)?,
            transition: move |case| {
                let store = Arc::clone(&cas_transition_store);
                async move {
                    let (command_id, expected) = match case {
                        CasCaseInput::Contender | CasCaseInput::Stale => {
                            ("conformance-cas", CommandVersion::FIRST)
                        }
                        CasCaseInput::NoChange => {
                            ("conformance-cas", CommandVersion::restore(2).unwrap())
                        }
                        CasCaseInput::Missing => ("conformance-cas-missing", CommandVersion::FIRST),
                    };
                    store
                        .transition_command(
                            cas_target.scope,
                            DeviceCommandId::parse(command_id).unwrap(),
                            expected,
                            DeviceCommandMutation::publish(tracker(cas_target).current_fence()),
                        )
                        .await
                        .map(observe_cas)
                }
            },
            load: move || {
                let store = Arc::clone(&cas_load_store);
                async move {
                    store
                        .load_command(
                            cas_target.scope,
                            DeviceCommandId::parse("conformance-cas").unwrap(),
                        )
                        .await
                        .map(|snapshot| snapshot.map(observe_command))
                }
            },
            load_missing: move || {
                let store = Arc::clone(&cas_missing_load_store);
                async move {
                    store
                        .load_command(
                            cas_target.scope,
                            DeviceCommandId::parse("conformance-cas-missing").unwrap(),
                        )
                        .await
                        .map(|snapshot| snapshot.map(observe_command))
                }
            },
        })
        .await?;
        assert_eq!(cas_winner.state, "published");
        let cas_snapshot = store
            .load_command(cas_target.scope, DeviceCommandId::parse("conformance-cas")?)
            .await?
            .expect("CAS command exists");
        transition_snapshot(
            &store,
            cas_target,
            "conformance-cas",
            &cas_snapshot,
            DeviceCommandMutation::cancel(tracker(cas_target).current_fence()),
        )
        .await?;

        let ingress_store = Arc::clone(&store);
        let ingress_load_store = Arc::clone(&store);
        let ingress_event = DeviceIngressEnvelopeId::parse("conformance-ingress")?;
        assert_device_ingress_conformance(DeviceIngressConformanceCase {
            tenant_a: target,
            tenant_b: cross_tenant,
            event_id: ingress_event.clone(),
            first_input: report("conformance-ingress", 60),
            replay_input: report("conformance-ingress", 60),
            conflict_input: report("conformance-ingress", 61),
            tenant_b_input: report("conformance-ingress", 62),
            append: move |target: Target, input: DeviceIngressEvidence| {
                let store = Arc::clone(&ingress_store);
                async move {
                    store
                        .record_fenced_ingress_for_test(target.scope, input)
                        .await
                        .map(observe_ingress)
                }
            },
            load: move |target: Target, event_id: DeviceIngressEnvelopeId| {
                let store = Arc::clone(&ingress_load_store);
                async move { store.load_ingress_evidence(target.scope, event_id).await }
            },
        })
        .await?;

        let left = PgDeviceCommandStore::from_unverified_stores_for_test(&owner, &owner);
        let right = PgDeviceCommandStore::from_unverified_stores_for_test(&owner, &owner);
        let (left, right) = tokio::join!(
            left.create_command(race_target.scope, create(race_target, "race-left", 9)),
            right.create_command(race_target.scope, create(race_target, "race-right", 9)),
        );
        let raced = [left?, right?];
        assert_eq!(
            raced
                .iter()
                .filter(|outcome| matches!(outcome, CreateDeviceCommandOutcome::Created(_)))
                .count(),
            1
        );
        let race_command_id = raced
            .iter()
            .find_map(|outcome| match outcome {
                CreateDeviceCommandOutcome::Created(snapshot) => Some(
                    super::snapshot_columns(snapshot)
                        .common
                        .command_id()
                        .clone(),
                ),
                _ => None,
            })
            .expect("race has one created command");
        let left = PgDeviceCommandStore::from_unverified_stores_for_test(&owner, &owner);
        let right = PgDeviceCommandStore::from_unverified_stores_for_test(&owner, &owner);
        let (left, right) = tokio::join!(
            left.transition_command(
                race_target.scope,
                race_command_id.clone(),
                CommandVersion::FIRST,
                DeviceCommandMutation::publish(tracker(race_target).current_fence()),
            ),
            right.transition_command(
                race_target.scope,
                race_command_id,
                CommandVersion::FIRST,
                DeviceCommandMutation::publish(tracker(race_target).current_fence()),
            ),
        );
        let transitions = [left?, right?];
        assert_eq!(
            transitions
                .iter()
                .filter(|outcome| matches!(outcome, TransitionDeviceCommandOutcome::Advanced(_)))
                .count(),
            1
        );
        assert_eq!(
            transitions
                .iter()
                .filter(|outcome| matches!(
                    outcome,
                    TransitionDeviceCommandOutcome::VersionConflict { actual }
                        if actual.get() == 2
                ))
                .count(),
            1
        );
        assert_eq!(
            raced
                .iter()
                .filter(|outcome| matches!(
                    outcome,
                    CreateDeviceCommandOutcome::ActiveConflict { .. }
                ))
                .count(),
            1
        );

        let created = store
            .create_command(command_target.scope, create(command_target, "command-1", 1))
            .await?;
        let created = match created {
            CreateDeviceCommandOutcome::Created(snapshot) => snapshot,
            other => panic!("expected created, got {other:?}"),
        };
        assert_eq!(
            store
                .load_command(cross_tenant.scope, DeviceCommandId::parse("command-1")?)
                .await?,
            None,
            "cross-tenant load must hide an existing command"
        );
        assert!(matches!(
            store
                .transition_command(
                    cross_tenant.scope,
                    DeviceCommandId::parse("command-1")?,
                    CommandVersion::FIRST,
                    DeviceCommandMutation::publish(tracker(cross_tenant).current_fence()),
                )
                .await?,
            TransitionDeviceCommandOutcome::Missing
        ));
        assert_eq!(
            super::snapshot_columns(&created).common.version(),
            CommandVersion::FIRST
        );
        let reloaded = store
            .load_command(command_target.scope, DeviceCommandId::parse("command-1")?)
            .await?
            .expect("restart reload");
        assert_eq!(reloaded, created);
        let restarted = PgDeviceCommandStore::from_unverified_stores_for_test(&owner, &owner);
        assert_eq!(
            restarted
                .load_command(command_target.scope, DeviceCommandId::parse("command-1")?)
                .await?,
            Some(created.clone())
        );
        assert!(matches!(
            store
                .create_command(command_target.scope, create(command_target, "command-1", 1))
                .await?,
            CreateDeviceCommandOutcome::Replay(ref snapshot) if snapshot == &created
        ));
        assert!(matches!(
            store
                .create_command(command_target.scope, create(command_target, "command-1", 2))
                .await?,
            CreateDeviceCommandOutcome::IdentityConflict
        ));
        assert!(matches!(
            store
                .create_command(command_target.scope, create(command_target, "command-2", 1))
                .await?,
            CreateDeviceCommandOutcome::ActiveConflict { .. }
        ));

        let published = store
            .transition_command(
                command_target.scope,
                DeviceCommandId::parse("command-1")?,
                CommandVersion::FIRST,
                DeviceCommandMutation::publish(tracker(command_target).current_fence()),
            )
            .await?;
        let published = match published {
            TransitionDeviceCommandOutcome::Advanced(snapshot) => snapshot,
            other => panic!("expected transition, got {other:?}"),
        };
        let version = super::snapshot_columns(&published).common.version();
        assert_eq!(version.get(), 2);
        assert!(matches!(
            store
                .create_command(command_target.scope, create(command_target, "command-1", 1))
                .await?,
            CreateDeviceCommandOutcome::Replay(ref snapshot) if snapshot == &published
        ));
        assert!(matches!(
            store
                .transition_command(
                    command_target.scope,
                    DeviceCommandId::parse("command-1")?,
                    version,
                    DeviceCommandMutation::publish(tracker(command_target).current_fence()),
                )
                .await?,
            TransitionDeviceCommandOutcome::NoChange { .. }
        ));
        let unchanged = store
            .load_command(command_target.scope, DeviceCommandId::parse("command-1")?)
            .await?
            .unwrap();
        assert_eq!(
            super::snapshot_columns(&unchanged).common.version(),
            version
        );
        assert!(matches!(
            store
                .transition_command(
                    command_target.scope,
                    DeviceCommandId::parse("command-1")?,
                    CommandVersion::FIRST,
                    DeviceCommandMutation::publish(tracker(command_target).current_fence()),
                )
                .await?,
            TransitionDeviceCommandOutcome::VersionConflict { actual } if actual == version
        ));

        let received = transition_snapshot(
            &store,
            command_target,
            "command-1",
            &published,
            DeviceCommandMutation::ack_received(tracker(command_target).current_fence()),
        )
        .await?;
        assert!(matches!(
            store
                .create_command(command_target.scope, create(command_target, "command-1", 1))
                .await?,
            CreateDeviceCommandOutcome::Replay(ref snapshot) if snapshot == &received
        ));
        let cancelled = transition_snapshot(
            &store,
            command_target,
            "command-1",
            &received,
            DeviceCommandMutation::cancel(tracker(command_target).current_fence()),
        )
        .await?;
        assert!(matches!(
            store
                .create_command(command_target.scope, create(command_target, "command-1", 1))
                .await?,
            CreateDeviceCommandOutcome::Replay(ref snapshot) if snapshot == &cancelled
        ));

        let appended = store
            .record_fenced_ingress_for_test(target.scope, report("event-1", 1))
            .await?;
        let receipt = match appended {
            AppendDeviceIngressOutcome::Appended(receipt) => receipt,
            other => panic!("expected appended, got {other:?}"),
        };
        assert!(matches!(
            store
                .record_fenced_ingress_for_test(target.scope, report("event-1", 1))
                .await?,
            AppendDeviceIngressOutcome::Replay(ref replay) if replay == &receipt
        ));
        assert!(matches!(
            store
                .record_fenced_ingress_for_test(target.scope, report("event-1", 2))
                .await?,
            AppendDeviceIngressOutcome::Conflict
        ));
        assert!(matches!(
            store
                .record_fenced_ingress_for_test(other_device.scope, report("event-1", 1))
                .await?,
            AppendDeviceIngressOutcome::Conflict
        ));
        assert!(matches!(
            store
                .record_fenced_ingress_for_test(cross_tenant.scope, report("event-1", 1))
                .await?,
            AppendDeviceIngressOutcome::Appended(_)
        ));
        assert_eq!(
            store
                .load_ingress_evidence(target.scope, DeviceIngressEnvelopeId::parse("event-1")?,)
                .await?,
            Some(receipt)
        );

        let dispositions = [
            DeviceIngressDisposition::Advanced,
            DeviceIngressDisposition::Duplicate,
            DeviceIngressDisposition::Late,
            DeviceIngressDisposition::Rejected,
            DeviceIngressDisposition::DeviceRejected,
            DeviceIngressDisposition::ScopeMismatch,
            DeviceIngressDisposition::OutOfOrder,
        ];
        for kind in [
            IngressKind::AckReceived,
            IngressKind::AckRejected,
            IngressKind::Report,
        ] {
            for disposition in dispositions {
                let event = format!("matrix-{}-{}", kind.label(), disposition.as_label());
                let input = ingress(kind, &event, "matrix-command", 1, 7, 0, 70, disposition);
                let first = store
                    .record_fenced_ingress_for_test(target.scope, input.clone())
                    .await?;
                let receipt = match first {
                    AppendDeviceIngressOutcome::Appended(receipt) => receipt,
                    other => panic!("expected matrix append for {event}, got {other:?}"),
                };
                assert_eq!(super::evidence_columns(receipt.evidence()).4.get(), 0);
                let expected = match kind {
                    IngressKind::AckReceived | IngressKind::AckRejected => {
                        DeviceIngressDisposition::ScopeMismatch
                    }
                    IngressKind::Report => DeviceIngressDisposition::StaleSequence,
                };
                assert_eq!(
                    receipt.disposition(),
                    expected,
                    "ACK scope is validated before sequence; caller disposition is ignored"
                );
                assert!(matches!(
                    store
                        .record_fenced_ingress_for_test(target.scope, input)
                        .await?,
                    AppendDeviceIngressOutcome::Replay(ref replay) if replay == &receipt
                ));
            }
        }

        let axis_event = "ingress-axis-conflict";
        let axis_original_input = ingress(
            IngressKind::AckReceived,
            axis_event,
            "axis-command",
            1,
            7,
            0,
            80,
            DeviceIngressDisposition::Advanced,
        );
        let axis_original = match store
            .record_fenced_ingress_for_test(target.scope, axis_original_input.clone())
            .await?
        {
            AppendDeviceIngressOutcome::Appended(receipt) => receipt,
            other => panic!("expected axis fixture append, got {other:?}"),
        };
        let axis_conflicts = [
            (
                "kind",
                ingress(
                    IngressKind::AckRejected,
                    axis_event,
                    "axis-command",
                    1,
                    7,
                    0,
                    80,
                    DeviceIngressDisposition::Advanced,
                ),
            ),
            (
                "command",
                ingress(
                    IngressKind::AckReceived,
                    axis_event,
                    "other-axis-command",
                    1,
                    7,
                    0,
                    80,
                    DeviceIngressDisposition::Advanced,
                ),
            ),
            (
                "generation",
                ingress(
                    IngressKind::AckReceived,
                    axis_event,
                    "axis-command",
                    2,
                    7,
                    0,
                    80,
                    DeviceIngressDisposition::Advanced,
                ),
            ),
            (
                "epoch",
                ingress(
                    IngressKind::AckReceived,
                    axis_event,
                    "axis-command",
                    1,
                    8,
                    0,
                    80,
                    DeviceIngressDisposition::Advanced,
                ),
            ),
            (
                "sequence",
                ingress(
                    IngressKind::AckReceived,
                    axis_event,
                    "axis-command",
                    1,
                    7,
                    1,
                    80,
                    DeviceIngressDisposition::Advanced,
                ),
            ),
            (
                "fingerprint",
                ingress(
                    IngressKind::AckReceived,
                    axis_event,
                    "axis-command",
                    1,
                    7,
                    0,
                    81,
                    DeviceIngressDisposition::Advanced,
                ),
            ),
        ];
        for (axis, conflict) in axis_conflicts {
            assert!(
                matches!(
                    store
                        .record_fenced_ingress_for_test(target.scope, conflict)
                        .await?,
                    AppendDeviceIngressOutcome::Conflict
                ),
                "changed {axis} must conflict"
            );
            assert_eq!(
                store
                    .load_ingress_evidence(
                        target.scope,
                        DeviceIngressEnvelopeId::parse(axis_event)?,
                    )
                    .await?,
                Some(axis_original.clone()),
                "changed {axis} must not overwrite the original receipt"
            );
        }
        assert!(matches!(
            store
                .record_fenced_ingress_for_test(other_device.scope, axis_original_input)
                .await?,
            AppendDeviceIngressOutcome::Conflict
        ));
        assert_eq!(
            store
                .load_ingress_evidence(
                    other_device.scope,
                    DeviceIngressEnvelopeId::parse(axis_event)?,
                )
                .await?,
            None,
            "cross-device event collision must not disclose the owning receipt"
        );
        assert_eq!(
            store
                .load_ingress_evidence(target.scope, DeviceIngressEnvelopeId::parse(axis_event)?,)
                .await?,
            Some(axis_original)
        );

        let concurrent_input = report("concurrent-exact-replay", 90);
        let outcomes =
            futures::future::join_all((0..8).map(|_| {
                store.record_fenced_ingress_for_test(target.scope, concurrent_input.clone())
            }))
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, AppendDeviceIngressOutcome::Appended(_)))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, AppendDeviceIngressOutcome::Replay(_)))
                .count(),
            7
        );
        let concurrent_receipt = outcomes
            .iter()
            .find_map(|outcome| match outcome {
                AppendDeviceIngressOutcome::Appended(receipt) => Some(receipt.clone()),
                _ => None,
            })
            .expect("concurrent append has exactly one durable receipt");
        assert!(outcomes.iter().all(|outcome| match outcome {
            AppendDeviceIngressOutcome::Appended(receipt)
            | AppendDeviceIngressOutcome::Replay(receipt) => receipt == &concurrent_receipt,
            AppendDeviceIngressOutcome::Conflict => false,
        }));
        assert!(matches!(
            store
                .record_fenced_ingress_for_test(target.scope, report("concurrent-exact-replay", 91))
                .await?,
            AppendDeviceIngressOutcome::Conflict
        ));
        assert_eq!(
            store
                .load_ingress_evidence(
                    target.scope,
                    DeviceIngressEnvelopeId::parse("concurrent-exact-replay")?,
                )
                .await?,
            Some(concurrent_receipt)
        );

        let unscoped_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM device_ingress_receipts")
                .fetch_one(&writer.pool)
                .await?;
        assert_eq!(
            unscoped_count, 0,
            "missing SET LOCAL must see no tenant rows"
        );
        let unscoped_insert = sqlx::query(
            "INSERT INTO device_ingress_receipts (tenant_id, event_id, device_id, kind, \
             command_id, generation, fence_epoch, device_sequence, fingerprint, disposition) \
             VALUES ($1::uuid, 'unscoped-event', $2::uuid, 'report', NULL, 1, 7, 1, $3, \
             'advanced')",
        )
        .bind(target.scope.tenant().as_uuid().to_string())
        .bind(target.scope.device().as_uuid().to_string())
        .bind(vec![3_u8; 32])
        .execute(&writer.pool)
        .await
        .expect_err("missing SET LOCAL must deny tenant writes");
        assert_eq!(
            unscoped_insert
                .as_database_error()
                .and_then(|value| value.code()),
            Some(std::borrow::Cow::Borrowed("42501"))
        );

        let unscoped_command_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM device_commands")
                .fetch_one(&writer.pool)
                .await?;
        assert_eq!(
            unscoped_command_count, 0,
            "missing SET LOCAL must see no command rows"
        );
        let unscoped_command_insert = sqlx::query(
            "INSERT INTO device_commands (tenant_id, command_id, device_id, generation, \
             fence_epoch, intent_digest, deadline, state, version) VALUES \
             ($1::uuid, 'unscoped-command', $2::uuid, 1, 7, $3, \
              TIMESTAMPTZ '2100-01-01 00:00:00+00', 'queued', 1)",
        )
        .bind(target.scope.tenant().as_uuid().to_string())
        .bind(target.scope.device().as_uuid().to_string())
        .bind(vec![4_u8; 32])
        .execute(&writer.pool)
        .await
        .expect_err("missing SET LOCAL must deny command writes");
        assert!(matches!(
            unscoped_command_insert
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .as_deref(),
            Some("42501" | "23503")
        ));

        assert_database_guard(
            &serving_store,
            target.scope,
            DatabaseGuardProbe::ReceiptUpdate,
        )
        .await?;
        assert_database_guard(
            &serving_store,
            target.scope,
            DatabaseGuardProbe::ReceiptDelete,
        )
        .await?;
        assert_database_guard(
            &serving_store,
            command_target.scope,
            DatabaseGuardProbe::VersionGap,
        )
        .await?;

        let mut expected_states = Vec::new();
        let queued_target = new_target();
        insert_desired(&owner, queued_target).await?;
        let queued =
            created_snapshot(&store, queued_target, "reload-queued", 11, deadline()).await?;
        transition_snapshot(
            &store,
            queued_target,
            "reload-queued",
            &queued,
            DeviceCommandMutation::cancel(tracker(queued_target).current_fence()),
        )
        .await?;

        let published_target = new_target();
        insert_desired(&owner, published_target).await?;
        let mut published =
            created_snapshot(&store, published_target, "reload-published", 12, deadline()).await?;
        published = transition_snapshot(
            &store,
            published_target,
            "reload-published",
            &published,
            DeviceCommandMutation::publish(tracker(published_target).current_fence()),
        )
        .await?;
        transition_snapshot(
            &store,
            published_target,
            "reload-published",
            &published,
            DeviceCommandMutation::cancel(tracker(published_target).current_fence()),
        )
        .await?;

        let received_target = new_target();
        insert_desired(&owner, received_target).await?;
        let mut received =
            created_snapshot(&store, received_target, "reload-received", 13, deadline()).await?;
        received = transition_snapshot(
            &store,
            received_target,
            "reload-received",
            &received,
            DeviceCommandMutation::publish(tracker(received_target).current_fence()),
        )
        .await?;
        received = transition_snapshot(
            &store,
            received_target,
            "reload-received",
            &received,
            DeviceCommandMutation::ack_received(tracker(received_target).current_fence()),
        )
        .await?;
        transition_snapshot(
            &store,
            received_target,
            "reload-received",
            &received,
            DeviceCommandMutation::cancel(tracker(received_target).current_fence()),
        )
        .await?;

        let applied_target = new_target();
        insert_desired(&owner, applied_target).await?;
        let mut applied =
            created_snapshot(&store, applied_target, "reload-applied", 14, deadline()).await?;
        applied = transition_snapshot(
            &store,
            applied_target,
            "reload-applied",
            &applied,
            DeviceCommandMutation::publish(tracker(applied_target).current_fence()),
        )
        .await?;
        applied = transition_snapshot(
            &store,
            applied_target,
            "reload-applied",
            &applied,
            DeviceCommandMutation::ack_received(tracker(applied_target).current_fence()),
        )
        .await?;
        let mut matching_tracker = tracker(applied_target);
        let matching = matching_tracker
            .report(
                ObservedGeneration::try_new(1)?,
                FenceEpoch::try_new(7)?,
                "desired",
            )
            .into_matching()
            .expect("matching report evidence");
        applied = transition_snapshot(
            &store,
            applied_target,
            "reload-applied",
            &applied,
            DeviceCommandMutation::apply(matching),
        )
        .await?;
        expected_states.push((
            applied_target,
            "reload-applied",
            DeviceCommandStatus::Applied,
            applied,
        ));

        let rejected_target = new_target();
        insert_desired(&owner, rejected_target).await?;
        let mut rejected =
            created_snapshot(&store, rejected_target, "reload-rejected", 15, deadline()).await?;
        rejected = transition_snapshot(
            &store,
            rejected_target,
            "reload-rejected",
            &rejected,
            DeviceCommandMutation::publish(tracker(rejected_target).current_fence()),
        )
        .await?;
        rejected = transition_snapshot(
            &store,
            rejected_target,
            "reload-rejected",
            &rejected,
            DeviceCommandMutation::reject(tracker(rejected_target).current_fence()),
        )
        .await?;
        expected_states.push((
            rejected_target,
            "reload-rejected",
            DeviceCommandStatus::Rejected,
            rejected,
        ));

        let timeout_deadline = near_deadline();
        let timeout_target = new_target();
        insert_desired(&owner, timeout_target).await?;
        let mut timed_out = created_snapshot(
            &store,
            timeout_target,
            "reload-timed-out",
            16,
            timeout_deadline,
        )
        .await?;
        tokio::time::sleep(std::time::Duration::from_millis(2_100)).await;
        timed_out = transition_snapshot(
            &store,
            timeout_target,
            "reload-timed-out",
            &timed_out,
            DeviceCommandMutation::timeout(tracker(timeout_target).current_fence()),
        )
        .await?;
        expected_states.push((
            timeout_target,
            "reload-timed-out",
            DeviceCommandStatus::TimedOut,
            timed_out,
        ));

        let cancelled_target = new_target();
        insert_desired(&owner, cancelled_target).await?;
        let mut cancelled =
            created_snapshot(&store, cancelled_target, "reload-cancelled", 18, deadline()).await?;
        cancelled = transition_snapshot(
            &store,
            cancelled_target,
            "reload-cancelled",
            &cancelled,
            DeviceCommandMutation::cancel(tracker(cancelled_target).current_fence()),
        )
        .await?;
        let cancelled_version = super::snapshot_columns(&cancelled).common.version();
        for (operation, mutation) in [
            (
                "publish",
                DeviceCommandMutation::publish(tracker(cancelled_target).current_fence()),
            ),
            (
                "ack_received",
                DeviceCommandMutation::ack_received(tracker(cancelled_target).current_fence()),
            ),
            (
                "timeout",
                DeviceCommandMutation::timeout(tracker(cancelled_target).current_fence()),
            ),
        ] {
            match store
                .transition_command(
                    cancelled_target.scope,
                    DeviceCommandId::parse("reload-cancelled")?,
                    cancelled_version,
                    mutation,
                )
                .await?
            {
                TransitionDeviceCommandOutcome::NoChange { snapshot, outcome } => {
                    assert_eq!(
                        outcome,
                        deviceloop::CommandTransitionOutcome::Late,
                        "terminal {operation} must report the exact late reason"
                    );
                    assert_eq!(snapshot, cancelled, "late {operation} must preserve state");
                    assert_eq!(
                        super::snapshot_columns(&snapshot).common.version(),
                        cancelled_version,
                        "late {operation} must preserve the durable version"
                    );
                }
                other => panic!("terminal {operation} must be a late no-change, got {other:?}"),
            }
        }
        expected_states.push((
            cancelled_target,
            "reload-cancelled",
            DeviceCommandStatus::Cancelled,
            cancelled,
        ));

        let isolation_target = new_target();
        insert_desired(&owner, isolation_target).await?;
        assert!(matches!(
            store
                .create_command(
                    isolation_target.scope,
                    create(isolation_target, "isolation-target", 95),
                )
                .await?,
            CreateDeviceCommandOutcome::Created(_)
        ));
        assert!(matches!(
            store
                .create_command(
                    other_device.scope,
                    create(other_device, "isolation-other-device", 95),
                )
                .await?,
            CreateDeviceCommandOutcome::Created(_)
        ));
        assert!(matches!(
            store
                .create_command(
                    cross_tenant.scope,
                    create(cross_tenant, "isolation-target", 95),
                )
                .await?,
            CreateDeviceCommandOutcome::Created(_)
        ));

        let restarted_all = PgDeviceCommandStore::from_unverified_stores_for_test(&owner, &owner);
        for (reload_target, command_id, status, expected) in expected_states {
            let restored = restarted_all
                .load_command(reload_target.scope, DeviceCommandId::parse(command_id)?)
                .await?
                .expect("persisted command state");
            assert_eq!(super::snapshot_columns(&restored).state, status);
            assert_eq!(restored, expected);
        }

        let commit_unknown_attempt = store
            .write_pool
            .identity_write_attempt(
                target.scope,
                |mut tx| {
                    Box::pin(async move {
                        tx.inject_commit_unknown_after_commit()
                            .await
                            .map_err(super::storage)?;
                        Ok(())
                    })
                },
                super::storage,
            )
            .await;
        let commit_unknown = super::finish_write_attempt(commit_unknown_attempt)
            .expect_err("lost commit acknowledgement must be settlement-unknown");
        assert!(matches!(
            &commit_unknown,
            super::StoreError::SettlementUnknown { .. }
        ));
        let source = std::error::Error::source(&commit_unknown).expect("redacted source");
        assert_eq!(source.to_string(), "<redacted>");
        assert!(source.source().is_none());

        const ROLLBACK_MARKER: &str = "device-command-rollback-sensitive-marker";
        let rollback_failed_attempt = store
            .write_pool
            .identity_write_attempt(
                target.scope,
                |mut tx| {
                    Box::pin(async move {
                        tx.identity()
                            .device_commands()
                            .inject_rollback_failed_after_rollback()
                            .await
                            .map_err(super::storage)?;
                        Err::<(), _>(super::StoreError::storage_permanent(sqlx::Error::Protocol(
                            ROLLBACK_MARKER.to_owned(),
                        )))
                    })
                },
                super::storage,
            )
            .await;
        let rollback_failed = super::finish_write_attempt(rollback_failed_attempt)
            .expect_err("failed rollback must be settlement-unknown");
        assert!(matches!(
            &rollback_failed,
            super::StoreError::SettlementUnknown { .. }
        ));
        assert!(!format!("{rollback_failed:?}").contains(ROLLBACK_MARKER));
        let source = std::error::Error::source(&rollback_failed).expect("redacted source");
        assert_eq!(source.to_string(), "<redacted>");
        assert!(source.source().is_none());

        drop((store, serving_store, restarted, restarted_all));
        reader.shutdown().await?;
        writer.shutdown().await?;
        owner.shutdown().await?;
        Ok(())
    }
}
