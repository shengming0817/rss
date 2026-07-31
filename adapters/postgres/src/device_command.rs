//! PostgreSQL durable DeviceLatent command aggregate and append-once ingress evidence.
//!
//! Public operations enter only through exact-lane tenant transactions. The crate-private
//! transaction concerns keep command work composable with later outbox and ingress unit-of-work
//! owners without exposing a connection or accepting storage-owned timestamps.
//!
//! ref: launchbadge/sqlx sqlx-core/src/transaction.rs@1d674f51581598f55436451d5b4b73100cae0b56

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use deviceloop::{
    AppendDeviceIngressEvidence, AppendDeviceIngressOutcome, CommandIntentDigest,
    CommandProgressRestore, CommandRestoreCommon, CommandTransitionOutcome, CommandVersion,
    CreateDeviceCommand, CreateDeviceCommandOutcome, DesiredGeneration, DeviceCommandCorruption,
    DeviceCommandId, DeviceCommandMutation, DeviceCommandRestore, DeviceCommandScope,
    DeviceCommandSnapshot, DeviceCommandSnapshotView, DeviceCommandState, DeviceCommandStatus,
    DeviceCommandStore, DeviceCommandStoreError, DeviceIngressCorruption, DeviceIngressDisposition,
    DeviceIngressEnvelopeId, DeviceIngressError, DeviceIngressEvidence, DeviceIngressEvidenceView,
    DeviceIngressFingerprint, DeviceIngressReceipt, DeviceSequence, FenceCoordinate, FenceEpoch,
    ObservedGeneration, TransitionDeviceCommandOutcome,
};
use identity::ports::device_certificate::DeviceCertificateScope;
use sqlx::PgConnection;

use crate::cotx::{ServingReadLane, ServingWriteLane, TenantDb};
use crate::pool::{VerifiedPgReadStore, VerifiedPgWriteStore};

type StoreError = DeviceCommandStoreError;
const PG_UNIX_MIN_MICROS: i128 = -210_866_803_200_000_000;
macro_rules! epoch_micros_sql {
    ($parameter:literal) => {
        concat!(
            "TIMESTAMPTZ 'epoch' + $",
            stringify!($parameter),
            "::bigint * INTERVAL '1 microsecond'"
        )
    };
}
const EPOCH_MICROS_SQL_6: &str = epoch_micros_sql!(6);
const EPOCH_MICROS_SQL_7: &str = epoch_micros_sql!(7);
const EPOCH_MICROS_SQL_8: &str = epoch_micros_sql!(8);

/// Read-only command concern within one tenant-bound identity transaction.
pub(crate) struct DeviceCommandReadTx<'tx> {
    conn: &'tx mut PgConnection,
}

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

    async fn transaction_time(&mut self) -> Result<SystemTime, StoreError> {
        transaction_time(self.conn).await
    }

    async fn insert_command(
        &mut self,
        tenant: &str,
        device: &str,
        snapshot: &DeviceCommandSnapshot,
    ) -> Result<Option<CommandRow>, StoreError> {
        insert_command(self.conn, tenant, device, snapshot).await
    }

    async fn command_for_update(
        &mut self,
        tenant: &str,
        device: &str,
        command_id: &str,
    ) -> Result<Option<CommandRow>, StoreError> {
        select_command(self.conn, tenant, device, command_id, true).await
    }

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

    async fn update_command(
        &mut self,
        tenant: &str,
        device: &str,
        expected: CommandVersion,
        snapshot: &DeviceCommandSnapshot,
    ) -> Result<bool, StoreError> {
        update_command(self.conn, tenant, device, expected, snapshot).await
    }

    async fn insert_receipt(
        &mut self,
        tenant: &str,
        device: &str,
        input: &AppendDeviceIngressEvidence,
    ) -> Result<Option<IngressRow>, StoreError> {
        insert_receipt(self.conn, tenant, device, input).await
    }

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

/// Tenant/device-scoped PostgreSQL implementation of [`DeviceCommandStore`].
pub struct PgDeviceCommandStore {
    read_pool: TenantDb<ServingReadLane>,
    write_pool: TenantDb<ServingWriteLane>,
}

impl PgDeviceCommandStore {
    /// Construct from verified serving capabilities.
    pub(crate) fn new(reader: &VerifiedPgReadStore, writer: &VerifiedPgWriteStore) -> Self {
        Self {
            read_pool: TenantDb::<ServingReadLane>::new(reader),
            write_pool: TenantDb::<ServingWriteLane>::new(writer),
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
        }
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

fn command_corruption(reason: DeviceCommandCorruption) -> StoreError {
    StoreError::CorruptCommand(reason)
}

fn ingress_corruption(reason: DeviceIngressCorruption) -> StoreError {
    StoreError::CorruptIngress(reason)
}

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

fn scope_matches(scope: DeviceCertificateScope, command: DeviceCommandScope) -> bool {
    scope.tenant() == command.tenant() && scope.device() == command.device()
}

fn coordinate_to_i64(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::InvariantViolation)
}

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

fn encode_command_time(value: SystemTime) -> Result<i64, StoreError> {
    raw_system_time_to_micros(value).ok_or(StoreError::InvariantViolation)
}

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

async fn transaction_time(conn: &mut PgConnection) -> Result<SystemTime, StoreError> {
    let micros = sqlx::query_scalar::<_, i64>(
        "SELECT floor(extract(epoch FROM transaction_timestamp()) * 1000000)::bigint",
    )
    .fetch_one(conn)
    .await
    .map_err(storage)?;
    raw_micros_to_system_time(micros).ok_or(StoreError::InvariantViolation)
}

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

const COMMAND_COLUMNS: &str = "command_id, device_id::text AS device_id, generation, fence_epoch, \
    intent_digest, floor(extract(epoch FROM deadline) * 1000000)::bigint AS deadline_micros, \
    state, version, floor(extract(epoch FROM queued_at) * 1000000)::bigint AS queued_at_micros, \
    floor(extract(epoch FROM published_at) * 1000000)::bigint AS published_at_micros, \
    floor(extract(epoch FROM received_at) * 1000000)::bigint AS received_at_micros, \
    floor(extract(epoch FROM terminal_at) * 1000000)::bigint AS terminal_at_micros";

fn command_query(suffix: &str) -> String {
    format!("SELECT {COMMAND_COLUMNS} FROM device_commands {suffix}")
}

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

struct SnapshotColumns<'a> {
    common: deviceloop::CommandSnapshotCommon<'a>,
    state: DeviceCommandStatus,
    published_at: Option<SystemTime>,
    received_at: Option<SystemTime>,
    terminal_at: Option<SystemTime>,
}

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

fn same_create_identity(left: &DeviceCommandSnapshot, right: &DeviceCommandSnapshot) -> bool {
    let left = snapshot_columns(left);
    let right = snapshot_columns(right);
    left.common.scope() == right.common.scope()
        && left.common.command_id() == right.common.command_id()
        && left.common.intent_digest() == right.common.intent_digest()
        && left.common.coordinate() == right.common.coordinate()
        && left.common.deadline() == right.common.deadline()
}

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

async fn insert_receipt(
    conn: &mut PgConnection,
    tenant: &str,
    device: &str,
    input: &AppendDeviceIngressEvidence,
) -> Result<Option<IngressRow>, StoreError> {
    let evidence = input.evidence();
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
    .bind(input.disposition().as_label())
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
        "scope_mismatch" => Ok(DeviceIngressDisposition::ScopeMismatch),
        "out_of_order" => Ok(DeviceIngressDisposition::OutOfOrder),
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

impl DeviceCommandStore for PgDeviceCommandStore {
    type Scope = DeviceCertificateScope;

    #[tracing::instrument(
        name = "device_command.store",
        skip_all,
        fields(component = "device_command_store", operation = "create")
    )]
    async fn create_command(
        &self,
        scope: Self::Scope,
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
                        let at = {
                            let mut identity = tx.identity();
                            identity.device_commands().transaction_time().await?
                        };
                        let snapshot = input
                            .into_state(at)
                            .map_err(StoreError::MutationRejected)?
                            .snapshot();
                        let mut identity = tx.identity();
                        let mut commands = identity.device_commands();
                        if let Some(row) =
                            commands.insert_command(&tenant, &device, &snapshot).await?
                        {
                            return Ok(CreateDeviceCommandOutcome::Created(
                                restore_command(scope.tenant(), row)?.snapshot(),
                            ));
                        }
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
                        let active = commands
                            .active_command_id(&tenant, &device, coordinate, digest)
                            .await?
                            .ok_or(StoreError::InvariantViolation)?;
                        Ok(CreateDeviceCommandOutcome::ActiveConflict { command_id: active })
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
        scope: Self::Scope,
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
        scope: Self::Scope,
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
        fields(component = "device_command_store", operation = "append_ingress")
    )]
    async fn append_ingress_evidence(
        &self,
        scope: Self::Scope,
        input: AppendDeviceIngressEvidence,
    ) -> Result<AppendDeviceIngressOutcome, StoreError> {
        let (tenant, device) = scope_params(scope);
        let event_id = input.evidence().envelope_id().as_str().to_owned();
        let attempt = self
            .write_pool
            .identity_write_attempt(
                scope,
                move |mut tx| {
                    Box::pin(async move {
                        let mut identity = tx.identity();
                        let mut commands = identity.device_commands();
                        if let Some(row) = commands.insert_receipt(&tenant, &device, &input).await?
                        {
                            return restore_receipt(row).map(AppendDeviceIngressOutcome::Appended);
                        }
                        let Some(row) = commands
                            .receipt_for_device(&tenant, &device, &event_id)
                            .await?
                        else {
                            return Ok(AppendDeviceIngressOutcome::Conflict);
                        };
                        let receipt = restore_receipt(row)?;
                        Ok(
                            if receipt.evidence() == input.evidence()
                                && receipt.disposition() == input.disposition()
                            {
                                AppendDeviceIngressOutcome::Replay(receipt)
                            } else {
                                AppendDeviceIngressOutcome::Conflict
                            },
                        )
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
        fields(component = "device_command_store", operation = "load_ingress")
    )]
    async fn load_ingress_evidence(
        &self,
        scope: Self::Scope,
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
        AppendDeviceIngressEvidence, AppendDeviceIngressOutcome, CommandIntentDigest,
        CommandVersion, CreateDeviceCommand, CreateDeviceCommandOutcome, DesiredGeneration,
        DeviceCommandDeadline, DeviceCommandId, DeviceCommandMutation, DeviceCommandScope,
        DeviceCommandSnapshot, DeviceCommandStatus, DeviceCommandStore as _,
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
                Self::ReceiptUpdate | Self::ReceiptDelete => "42501",
                Self::VersionGap => "23514",
            }
        }
    }

    fn new_target() -> Target {
        let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
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

    fn report(event: &str, fingerprint: u8) -> AppendDeviceIngressEvidence {
        AppendDeviceIngressEvidence::new(
            DeviceIngressEvidence::report(
                DeviceIngressEnvelopeId::parse(event).unwrap(),
                ObservedGeneration::try_new(1).unwrap(),
                FenceEpoch::try_new(7).unwrap(),
                DeviceSequence::try_new(1).unwrap(),
                DeviceIngressFingerprint::from_bytes([fingerprint; 32]),
            ),
            DeviceIngressDisposition::Advanced,
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
    ) -> AppendDeviceIngressEvidence {
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
        AppendDeviceIngressEvidence::new(evidence, disposition)
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

    #[tokio::test(flavor = "multi_thread")]
    async fn real_postgres_enforces_lifecycle_idempotency_and_append_only() -> TestResult {
        let (fixture, owner) = crate::test_pg::connect_pg().await?;
        owner.run_migrations().await?;
        let target = new_target();
        let race_target = new_target();
        let cross_tenant = new_target();
        let other_device_id = ids::DeviceId::new(uuid::Uuid::new_v4());
        let other_device = Target {
            scope: DeviceCertificateScope::for_test(target.scope.tenant(), other_device_id),
            command_scope: DeviceCommandScope::new(target.scope.tenant(), other_device_id),
        };
        insert_desired(&owner, target).await?;
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
             FROM pg_indexes WHERE indexname = 'device_commands_one_active_intent'",
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
        let store = Arc::new(PgDeviceCommandStore::from_unverified_stores_for_test(
            &reader, &writer,
        ));

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
                    PgDeviceCommandStore::from_unverified_stores_for_test(&reader, &writer);
                restarted
                    .load_command(target.scope, command_id)
                    .await
                    .map(|snapshot| snapshot.map(observe_command))
            },
        )
        .await?;

        let cas_created =
            created_snapshot(&store, target, "conformance-cas", 52, deadline()).await?;
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
                            target.scope,
                            DeviceCommandId::parse(command_id).unwrap(),
                            expected,
                            DeviceCommandMutation::publish(tracker(target).current_fence()),
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
                            target.scope,
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
                            target.scope,
                            DeviceCommandId::parse("conformance-cas-missing").unwrap(),
                        )
                        .await
                        .map(|snapshot| snapshot.map(observe_command))
                }
            },
        })
        .await?;
        assert_eq!(cas_winner.state, "published");

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
            append: move |target: Target, input: AppendDeviceIngressEvidence| {
                let store = Arc::clone(&ingress_store);
                async move {
                    store
                        .append_ingress_evidence(target.scope, input)
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

        let left = PgDeviceCommandStore::from_unverified_stores_for_test(&reader, &writer);
        let right = PgDeviceCommandStore::from_unverified_stores_for_test(&reader, &writer);
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
        let left = PgDeviceCommandStore::from_unverified_stores_for_test(&reader, &writer);
        let right = PgDeviceCommandStore::from_unverified_stores_for_test(&reader, &writer);
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
            .create_command(target.scope, create(target, "command-1", 1))
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
            .load_command(target.scope, DeviceCommandId::parse("command-1")?)
            .await?
            .expect("restart reload");
        assert_eq!(reloaded, created);
        let restarted = PgDeviceCommandStore::from_unverified_stores_for_test(&reader, &writer);
        assert_eq!(
            restarted
                .load_command(target.scope, DeviceCommandId::parse("command-1")?)
                .await?,
            Some(created.clone())
        );
        assert!(matches!(
            store
                .create_command(target.scope, create(target, "command-1", 1))
                .await?,
            CreateDeviceCommandOutcome::Replay(ref snapshot) if snapshot == &created
        ));
        assert!(matches!(
            store
                .create_command(target.scope, create(target, "command-1", 2))
                .await?,
            CreateDeviceCommandOutcome::IdentityConflict
        ));
        assert!(matches!(
            store
                .create_command(target.scope, create(target, "command-2", 1))
                .await?,
            CreateDeviceCommandOutcome::ActiveConflict { .. }
        ));

        let published = store
            .transition_command(
                target.scope,
                DeviceCommandId::parse("command-1")?,
                CommandVersion::FIRST,
                DeviceCommandMutation::publish(tracker(target).current_fence()),
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
                .create_command(target.scope, create(target, "command-1", 1))
                .await?,
            CreateDeviceCommandOutcome::Replay(ref snapshot) if snapshot == &published
        ));
        assert!(matches!(
            store
                .transition_command(
                    target.scope,
                    DeviceCommandId::parse("command-1")?,
                    version,
                    DeviceCommandMutation::publish(tracker(target).current_fence()),
                )
                .await?,
            TransitionDeviceCommandOutcome::NoChange { .. }
        ));
        let unchanged = store
            .load_command(target.scope, DeviceCommandId::parse("command-1")?)
            .await?
            .unwrap();
        assert_eq!(
            super::snapshot_columns(&unchanged).common.version(),
            version
        );
        assert!(matches!(
            store
                .transition_command(
                    target.scope,
                    DeviceCommandId::parse("command-1")?,
                    CommandVersion::FIRST,
                    DeviceCommandMutation::publish(tracker(target).current_fence()),
                )
                .await?,
            TransitionDeviceCommandOutcome::VersionConflict { actual } if actual == version
        ));

        let received = transition_snapshot(
            &store,
            target,
            "command-1",
            &published,
            DeviceCommandMutation::ack_received(tracker(target).current_fence()),
        )
        .await?;
        assert!(matches!(
            store
                .create_command(target.scope, create(target, "command-1", 1))
                .await?,
            CreateDeviceCommandOutcome::Replay(ref snapshot) if snapshot == &received
        ));
        let cancelled = transition_snapshot(
            &store,
            target,
            "command-1",
            &received,
            DeviceCommandMutation::cancel(tracker(target).current_fence()),
        )
        .await?;
        assert!(matches!(
            store
                .create_command(target.scope, create(target, "command-1", 1))
                .await?,
            CreateDeviceCommandOutcome::Replay(ref snapshot) if snapshot == &cancelled
        ));

        let appended = store
            .append_ingress_evidence(target.scope, report("event-1", 1))
            .await?;
        let receipt = match appended {
            AppendDeviceIngressOutcome::Appended(receipt) => receipt,
            other => panic!("expected appended, got {other:?}"),
        };
        assert!(matches!(
            store
                .append_ingress_evidence(target.scope, report("event-1", 1))
                .await?,
            AppendDeviceIngressOutcome::Replay(ref replay) if replay == &receipt
        ));
        assert!(matches!(
            store
                .append_ingress_evidence(target.scope, report("event-1", 2))
                .await?,
            AppendDeviceIngressOutcome::Conflict
        ));
        assert!(matches!(
            store
                .append_ingress_evidence(other_device.scope, report("event-1", 1))
                .await?,
            AppendDeviceIngressOutcome::Conflict
        ));
        assert!(matches!(
            store
                .append_ingress_evidence(cross_tenant.scope, report("event-1", 1))
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
                    .append_ingress_evidence(target.scope, input.clone())
                    .await?;
                let receipt = match first {
                    AppendDeviceIngressOutcome::Appended(receipt) => receipt,
                    other => panic!("expected matrix append for {event}, got {other:?}"),
                };
                assert_eq!(super::evidence_columns(receipt.evidence()).4.get(), 0);
                assert_eq!(receipt.disposition(), disposition);
                assert!(matches!(
                    store
                        .append_ingress_evidence(target.scope, input)
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
            .append_ingress_evidence(target.scope, axis_original_input.clone())
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
            (
                "disposition",
                ingress(
                    IngressKind::AckReceived,
                    axis_event,
                    "axis-command",
                    1,
                    7,
                    0,
                    80,
                    DeviceIngressDisposition::Duplicate,
                ),
            ),
        ];
        for (axis, conflict) in axis_conflicts {
            assert!(
                matches!(
                    store
                        .append_ingress_evidence(target.scope, conflict)
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
                .append_ingress_evidence(other_device.scope, axis_original_input)
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
        let outcomes = futures::future::join_all(
            (0..8).map(|_| store.append_ingress_evidence(target.scope, concurrent_input.clone())),
        )
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
                .append_ingress_evidence(target.scope, report("concurrent-exact-replay", 91))
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
        assert_eq!(
            unscoped_command_insert
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code),
            Some(std::borrow::Cow::Borrowed("42501"))
        );

        assert_database_guard(&store, target.scope, DatabaseGuardProbe::ReceiptUpdate).await?;
        assert_database_guard(&store, target.scope, DatabaseGuardProbe::ReceiptDelete).await?;
        assert_database_guard(&store, target.scope, DatabaseGuardProbe::VersionGap).await?;

        let mut expected_states = Vec::new();
        let queued = created_snapshot(&store, target, "reload-queued", 11, deadline()).await?;
        expected_states.push(("reload-queued", DeviceCommandStatus::Queued, queued));

        let mut published =
            created_snapshot(&store, target, "reload-published", 12, deadline()).await?;
        published = transition_snapshot(
            &store,
            target,
            "reload-published",
            &published,
            DeviceCommandMutation::publish(tracker(target).current_fence()),
        )
        .await?;
        expected_states.push((
            "reload-published",
            DeviceCommandStatus::Published,
            published,
        ));

        let mut received =
            created_snapshot(&store, target, "reload-received", 13, deadline()).await?;
        received = transition_snapshot(
            &store,
            target,
            "reload-received",
            &received,
            DeviceCommandMutation::publish(tracker(target).current_fence()),
        )
        .await?;
        received = transition_snapshot(
            &store,
            target,
            "reload-received",
            &received,
            DeviceCommandMutation::ack_received(tracker(target).current_fence()),
        )
        .await?;
        expected_states.push(("reload-received", DeviceCommandStatus::Received, received));

        let mut applied =
            created_snapshot(&store, target, "reload-applied", 14, deadline()).await?;
        applied = transition_snapshot(
            &store,
            target,
            "reload-applied",
            &applied,
            DeviceCommandMutation::publish(tracker(target).current_fence()),
        )
        .await?;
        applied = transition_snapshot(
            &store,
            target,
            "reload-applied",
            &applied,
            DeviceCommandMutation::ack_received(tracker(target).current_fence()),
        )
        .await?;
        let mut matching_tracker = tracker(target);
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
            target,
            "reload-applied",
            &applied,
            DeviceCommandMutation::apply(matching),
        )
        .await?;
        expected_states.push(("reload-applied", DeviceCommandStatus::Applied, applied));

        let mut rejected =
            created_snapshot(&store, target, "reload-rejected", 15, deadline()).await?;
        rejected = transition_snapshot(
            &store,
            target,
            "reload-rejected",
            &rejected,
            DeviceCommandMutation::publish(tracker(target).current_fence()),
        )
        .await?;
        rejected = transition_snapshot(
            &store,
            target,
            "reload-rejected",
            &rejected,
            DeviceCommandMutation::reject(tracker(target).current_fence()),
        )
        .await?;
        expected_states.push(("reload-rejected", DeviceCommandStatus::Rejected, rejected));

        let timeout_deadline = near_deadline();
        let mut timed_out =
            created_snapshot(&store, target, "reload-timed-out", 16, timeout_deadline).await?;
        tokio::time::sleep(std::time::Duration::from_millis(2_100)).await;
        timed_out = transition_snapshot(
            &store,
            target,
            "reload-timed-out",
            &timed_out,
            DeviceCommandMutation::timeout(tracker(target).current_fence()),
        )
        .await?;
        expected_states.push(("reload-timed-out", DeviceCommandStatus::TimedOut, timed_out));

        let mut superseded =
            created_snapshot(&store, target, "reload-superseded", 17, deadline()).await?;
        let mut newer_tracker = tracker(target);
        let newer = newer_tracker.advance_desired(
            DesiredGeneration::try_new(2)?,
            "new-desired",
            FenceEpoch::try_new(8)?,
        )?;
        superseded = transition_snapshot(
            &store,
            target,
            "reload-superseded",
            &superseded,
            DeviceCommandMutation::supersede(newer),
        )
        .await?;
        expected_states.push((
            "reload-superseded",
            DeviceCommandStatus::Superseded,
            superseded,
        ));

        let mut cancelled =
            created_snapshot(&store, target, "reload-cancelled", 18, deadline()).await?;
        cancelled = transition_snapshot(
            &store,
            target,
            "reload-cancelled",
            &cancelled,
            DeviceCommandMutation::cancel(tracker(target).current_fence()),
        )
        .await?;
        let cancelled_version = super::snapshot_columns(&cancelled).common.version();
        for (operation, mutation) in [
            (
                "publish",
                DeviceCommandMutation::publish(tracker(target).current_fence()),
            ),
            (
                "ack_received",
                DeviceCommandMutation::ack_received(tracker(target).current_fence()),
            ),
            (
                "timeout",
                DeviceCommandMutation::timeout(tracker(target).current_fence()),
            ),
        ] {
            match store
                .transition_command(
                    target.scope,
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
            "reload-cancelled",
            DeviceCommandStatus::Cancelled,
            cancelled,
        ));

        for (terminal_state, command_id, digest) in [
            ("applied", "after-applied", 14),
            ("rejected", "after-rejected", 15),
            ("timed_out", "after-timed-out", 16),
            ("superseded", "after-superseded", 17),
            ("cancelled", "after-cancelled", 18),
        ] {
            assert!(
                matches!(
                    store
                        .create_command(target.scope, create(target, command_id, digest))
                        .await?,
                    CreateDeviceCommandOutcome::Created(_)
                ),
                "terminal state {terminal_state} must release active uniqueness"
            );
        }

        assert!(matches!(
            store
                .create_command(target.scope, create(target, "isolation-target", 95))
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

        let restarted_all = PgDeviceCommandStore::from_unverified_stores_for_test(&reader, &writer);
        for (command_id, status, expected) in expected_states {
            let restored = restarted_all
                .load_command(target.scope, DeviceCommandId::parse(command_id)?)
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

        drop((store, restarted, restarted_all));
        reader.shutdown().await?;
        writer.shutdown().await?;
        owner.shutdown().await?;
        Ok(())
    }
}
