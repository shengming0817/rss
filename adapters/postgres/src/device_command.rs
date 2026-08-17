//! PostgreSQL durable DeviceLatent command aggregate and append-once ingress evidence.
//!
//! Public operations enter only through exact-lane tenant transactions. The crate-private
//! transaction concerns keep command work composable with later outbox and ingress unit-of-work
//! owners without exposing a connection or accepting storage-owned timestamps.
//!
//! ref: launchbadge/sqlx sqlx-core/src/transaction.rs@1d674f51581598f55436451d5b4b73100cae0b56

use std::num::NonZeroU64;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use deviceloop::DeviceCommandMutation;
use deviceloop::DeviceCommandSnapshotView;
#[cfg(all(test, feature = "integration"))]
use deviceloop::TransitionDeviceCommandOutcome;
use deviceloop::{
    AppendDeviceIngressOutcome, CommandIntentDigest, CommandProgressRestore, CommandRestoreCommon,
    CommandTransitionOutcome, CommandVersion, DesiredGeneration, DeviceCommandCorruption,
    DeviceCommandId, DeviceCommandRestore, DeviceCommandScope, DeviceCommandSnapshot,
    DeviceCommandState, DeviceCommandStoreError, DeviceIngressCorruption, DeviceIngressDisposition,
    DeviceIngressEnvelopeId, DeviceIngressError, DeviceIngressEvidence, DeviceIngressEvidenceView,
    DeviceIngressFingerprint, DeviceIngressReceipt, DeviceSequence, FenceCoordinate, FenceEpoch,
    GenerationTracker, ObservedGeneration,
};
#[cfg(all(test, feature = "integration"))]
use deviceloop::{CreateDeviceCommand, CreateDeviceCommandOutcome};
use identity::ports::device_certificate::{
    ArtifactEligibility, CertificateAttemptFence, CurrentCommandExpiryOutcome,
    DeviceCertificateScope, DeviceIngressWrite, ReportedStateWrite,
};
use sqlx::PgConnection;

use crate::cotx::{MapOutboxAppendError as _, ServingReadLane, ServingWriteLane, TenantDb};
#[cfg(all(test, feature = "integration"))]
use crate::device_certificate_scope::{
    DEVICE_CERTIFICATE_RECONCILER_ID, DEVICE_CERTIFICATE_RESOURCE_KIND,
};
use crate::pool::{VerifiedPgReadStore, VerifiedPgWriteStore};

type StoreError = DeviceCommandStoreError;
const PG_UNIX_MIN_MICROS: i128 = -210_866_803_200_000_000;

pub(crate) struct DeviceIngressReadbackTx<'tx> {
    conn: &'tx mut PgConnection,
}

/// Opaque PostgreSQL evidence minted only after the durable ingress UoW committed or exact
/// receipt-plus-Outbox readback proved that an acknowledged commit already exists.
pub struct PgDeviceIngressCommitProof<E: ArtifactEligibility> {
    _provider_owned: (),
    _eligibility: std::marker::PhantomData<fn() -> E>,
}

impl<E: ArtifactEligibility> PgDeviceIngressCommitProof<E> {
    fn committed() -> Self {
        Self {
            _provider_owned: (),
            _eligibility: std::marker::PhantomData,
        }
    }
}

/// Move-only provider outcome required before transport settlement may be authorized.
pub struct PgDeviceIngressCommit<E: ArtifactEligibility> {
    receipt: DeviceIngressReceipt,
    proof: PgDeviceIngressCommitProof<E>,
}

impl<E: ArtifactEligibility> PgDeviceIngressCommit<E> {
    fn committed(receipt: DeviceIngressReceipt) -> Self {
        Self {
            receipt,
            proof: PgDeviceIngressCommitProof::committed(),
        }
    }

    pub const fn receipt(&self) -> &DeviceIngressReceipt {
        &self.receipt
    }

    pub fn into_parts(self) -> (DeviceIngressReceipt, PgDeviceIngressCommitProof<E>) {
        (self.receipt, self.proof)
    }
}

#[cfg(all(test, feature = "integration"))]
#[derive(Clone, Copy)]
pub(crate) enum DeviceIngressFault {
    CommitUnknown,
    AfterOutbox,
}

impl<'tx> DeviceIngressReadbackTx<'tx> {
    pub(crate) fn new(conn: &'tx mut PgConnection) -> Self {
        Self { conn }
    }

    async fn exact_receipt(
        &mut self,
        scope: DeviceCertificateScope,
        evidence: &DeviceIngressEvidence,
    ) -> Result<Option<DeviceIngressReceipt>, StoreError> {
        let (tenant, device) = scope_params(scope);
        let Some(row) =
            select_receipt(self.conn, &tenant, &device, evidence.envelope_id().as_str()).await?
        else {
            return Ok(None);
        };
        let receipt = restore_receipt(row)?;
        Ok((receipt.evidence() == evidence).then_some(receipt))
    }

    async fn outbox_fingerprint(
        &mut self,
        tenant: rss_request_context::TenantId,
        event_id: &str,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        sqlx::query_scalar(
            "SELECT fact_fingerprint FROM outbox \
             WHERE tenant_id=$1::uuid AND event_id=$2",
        )
        .bind(tenant.to_string())
        .bind(event_id)
        .fetch_optional(&mut *self.conn)
        .await
        .map_err(storage)
    }
}
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
}

/// Mutable command concern within one tenant-bound identity transaction.
pub(crate) struct DeviceCommandWriteTx<'tx> {
    conn: &'tx mut PgConnection,
}

#[derive(sqlx::FromRow)]
struct CurrentCommandExpirySelectionRow {
    outcome: String,
    artifact_eligibility: Option<String>,
    command_id: Option<String>,
    device_id: Option<String>,
    generation: Option<i64>,
    fence_epoch: Option<i64>,
    intent_digest: Option<Vec<u8>>,
    deadline_micros: Option<i64>,
    state: Option<String>,
    version: Option<i64>,
    queued_at_micros: Option<i64>,
    published_at_micros: Option<i64>,
    received_at_micros: Option<i64>,
    terminal_at_micros: Option<i64>,
    authority_time_micros: i64,
}

impl CurrentCommandExpirySelectionRow {
    fn into_command(self) -> Result<(CommandRow, SystemTime), StoreError> {
        let required = || command_corruption(DeviceCommandCorruption::Shape);
        let command = CommandRow {
            artifact_eligibility: self.artifact_eligibility.ok_or_else(required)?,
            command_id: self.command_id.ok_or_else(required)?,
            device_id: self.device_id.ok_or_else(required)?,
            generation: self.generation.ok_or_else(required)?,
            fence_epoch: self.fence_epoch.ok_or_else(required)?,
            intent_digest: self.intent_digest.ok_or_else(required)?,
            deadline_micros: self.deadline_micros.ok_or_else(required)?,
            state: self.state.ok_or_else(required)?,
            version: self.version.ok_or_else(required)?,
            queued_at_micros: self.queued_at_micros.ok_or_else(required)?,
            published_at_micros: self.published_at_micros,
            received_at_micros: self.received_at_micros,
            terminal_at_micros: self.terminal_at_micros,
        };
        Ok((command, decode_command_time(self.authority_time_micros)?))
    }
}

impl<'tx> DeviceCommandWriteTx<'tx> {
    pub(crate) fn new(conn: &'tx mut PgConnection) -> Self {
        Self { conn }
    }

    #[cfg(all(test, feature = "integration"))]
    async fn transaction_time(&mut self) -> Result<SystemTime, StoreError> {
        transaction_time(self.conn).await
    }

    /// Expire the provider-selected current-generation command using only transaction-owned
    /// identity and time. PostgreSQL seals selection and settlement around the canonical Rust FSM.
    pub(crate) async fn expire_due_current<E: ArtifactEligibility>(
        &mut self,
        fence: &CertificateAttemptFence,
    ) -> Result<CurrentCommandExpiryOutcome, StoreError> {
        let scope = fence.scope();
        let (tenant, device) = scope_params(scope);
        let lane = match E::PERSISTENCE_LABEL {
            "draft" => "draft",
            "production" => "production",
            _ => return Err(StoreError::InvariantViolation),
        };
        let selection = sqlx::query_as::<_, CurrentCommandExpirySelectionRow>(&format!(
            "SELECT * FROM public.rss_select_due_current_device_command_{lane}(\
             $1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::bigint,$6::bigint,$7::bigint)"
        ))
        .bind(&tenant)
        .bind(&device)
        .bind(fence.attempt_id())
        .bind(fence.lease_token())
        .bind(coordinate_to_i64(fence.epoch().get())?)
        .bind(coordinate_to_i64(fence.wake_version().get())?)
        .bind(coordinate_to_i64(fence.expected_generation().get())?)
        .fetch_one(&mut *self.conn)
        .await
        .map_err(storage)?;
        match selection.outcome.as_str() {
            "no_current" => return Ok(CurrentCommandExpiryOutcome::NoCurrent),
            "not_due" => return Ok(CurrentCommandExpiryOutcome::NotDue),
            "already_expired" => return Ok(CurrentCommandExpiryOutcome::AlreadyExpired),
            "stale_fence" => return Ok(CurrentCommandExpiryOutcome::StaleFence),
            "due" => {}
            _ => return Err(StoreError::InvariantViolation),
        }

        let (row, authority_time) = selection.into_command()?;
        let expected = CommandVersion::restore(row.version).map_err(corrupt_command)?;
        let state = restore_command::<E>(scope.tenant(), row)?;
        let coordinate = state.coordinate();
        let authority = GenerationTracker::new(
            state.scope(),
            coordinate.generation(),
            (),
            coordinate.epoch(),
        )
        .current_fence();
        let transition = DeviceCommandMutation::timeout(authority)
            .apply_to(state, authority_time)
            .map_err(|error| StoreError::MutationRejected(error.error().clone()))?;
        if transition.outcome() != CommandTransitionOutcome::Advanced {
            return Err(StoreError::InvariantViolation);
        }
        let snapshot = transition.into_state().snapshot();
        let (common, terminal_at) = match snapshot.view() {
            DeviceCommandSnapshotView::TimedOut {
                common,
                timed_out_at,
                ..
            } => (common, timed_out_at),
            _ => return Err(StoreError::InvariantViolation),
        };
        let outcome = sqlx::query_scalar::<_, String>(&format!(
            "SELECT public.rss_settle_due_current_device_command_{lane}(\
             $1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::bigint,$6::bigint,$7::bigint,\
             $8,$9::bigint,$10::bigint,$11::bigint)"
        ))
        .bind(&tenant)
        .bind(&device)
        .bind(fence.attempt_id())
        .bind(fence.lease_token())
        .bind(coordinate_to_i64(fence.epoch().get())?)
        .bind(coordinate_to_i64(fence.wake_version().get())?)
        .bind(coordinate_to_i64(fence.expected_generation().get())?)
        .bind(common.command_id().as_str())
        .bind(expected.get())
        .bind(common.version().get())
        .bind(encode_command_time(terminal_at)?)
        .fetch_one(&mut *self.conn)
        .await
        .map_err(storage)?;
        match outcome.as_str() {
            "expired" => Ok(CurrentCommandExpiryOutcome::Expired),
            "stale_fence" => Ok(CurrentCommandExpiryOutcome::StaleFence),
            "version_conflict" => Err(StoreError::InvariantViolation),
            _ => Err(StoreError::InvariantViolation),
        }
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
pub(crate) struct FencedIngressTx<'tx> {
    commands: DeviceCommandWriteTx<'tx>,
}

#[cfg(all(test, feature = "integration"))]
#[derive(Clone, Copy)]
struct DeviceAuthority {
    generation: i64,
    fence_epoch: i64,
}

impl<'tx> FencedIngressTx<'tx> {
    pub(crate) async fn record(
        &mut self,
        scope: DeviceCertificateScope,
        evidence: DeviceIngressEvidence,
        reported: Option<&ReportedStateWrite>,
        credential_generation: u64,
        payload_scope_matches: bool,
    ) -> Result<AppendDeviceIngressOutcome, StoreError> {
        let (tenant, device) = scope_params(scope);
        if let Some(outcome) = self.existing_outcome(&tenant, &device, &evidence).await? {
            return Ok(outcome);
        }

        let (_, command_id, incoming_generation, incoming_epoch, sequence) =
            evidence_columns(&evidence);
        let row = if matches!(
            evidence.view(),
            DeviceIngressEvidenceView::ProtocolViolation { .. }
        ) {
            sqlx::query_as::<_, IngressRow>(
                "SELECT * FROM public.rss_commit_device_ingress_protocol_violation( \
                 $1::uuid,$2::uuid,$3,$4,$5)",
            )
            .bind(&tenant)
            .bind(&device)
            .bind(evidence.envelope_id().as_str())
            .bind(evidence.fingerprint().as_bytes().as_slice())
            .bind(coordinate_to_i64(credential_generation)?)
            .fetch_one(&mut *self.commands.conn)
            .await
            .map_err(storage)?
        } else if let Some(command_id) = command_id {
            sqlx::query_as::<_, IngressRow>(
                "SELECT * FROM public.rss_commit_device_command_ack_ingress( \
                 $1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
            )
            .bind(&tenant)
            .bind(&device)
            .bind(evidence.envelope_id().as_str())
            .bind(command_id)
            .bind(coordinate_to_i64(incoming_generation)?)
            .bind(coordinate_to_i64(incoming_epoch)?)
            .bind(coordinate_to_i64(sequence)?)
            .bind(evidence.fingerprint().as_bytes().as_slice())
            .bind(evidence.kind_label())
            .bind(coordinate_to_i64(credential_generation)?)
            .bind(payload_scope_matches)
            .fetch_one(&mut *self.commands.conn)
            .await
            .map_err(storage)?
        } else {
            let reported = reported.ok_or(StoreError::InvariantViolation)?;
            sqlx::query_as::<_, IngressRow>(
                "SELECT * FROM public.rss_commit_device_certificate_report_ingress( \
                 $1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
            )
            .bind(&tenant)
            .bind(&device)
            .bind(evidence.envelope_id().as_str())
            .bind(coordinate_to_i64(incoming_generation)?)
            .bind(coordinate_to_i64(incoming_epoch)?)
            .bind(coordinate_to_i64(sequence)?)
            .bind(evidence.fingerprint().as_bytes().as_slice())
            .bind(reported.state_hash().as_bytes().as_slice())
            .bind(reported.artifact_digest().as_bytes().as_slice())
            .bind(optional_system_time_to_micros(reported.expires_at())?)
            .bind(optional_system_time_to_micros(
                reported.device_observed_at(),
            )?)
            .bind(coordinate_to_i64(credential_generation)?)
            .bind(payload_scope_matches)
            .fetch_one(&mut *self.commands.conn)
            .await
            .map_err(storage)?
        };
        restore_receipt(row).map(AppendDeviceIngressOutcome::Appended)
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
}

pub(crate) async fn commit_device_ingress<E: ArtifactEligibility>(
    write_pool: &TenantDb<ServingWriteLane>,
    read_pool: &TenantDb<ServingReadLane>,
    input: DeviceIngressWrite,
    #[cfg(all(test, feature = "integration"))] fault: Option<DeviceIngressFault>,
) -> Result<PgDeviceIngressCommit<E>, StoreError> {
    let scope = input.scope();
    let expected_evidence = input.evidence().clone();
    let write_evidence = expected_evidence.clone();
    let reported = input.reported().cloned();
    let credential_generation = input.credential_generation();
    let payload_scope_matches = input.payload_scope_matches();
    let attempt = write_pool
        .identity_device_ingress_attempt(
            scope,
            move |mut tx| {
                Box::pin(async move {
                    #[cfg(all(test, feature = "integration"))]
                    match fault {
                        Some(DeviceIngressFault::CommitUnknown) => tx
                            .inject_commit_unknown_after_commit()
                            .await
                            .map_err(storage)?,
                        Some(DeviceIngressFault::AfterOutbox) => tx
                            .inject_failure_after_outbox_append_before_commit()
                            .await
                            .map_err(storage)?,
                        None => {}
                    }
                    let mut identity = tx.identity();
                    let commands = identity.device_commands();
                    let outcome = FencedIngressTx { commands }
                        .record(
                            scope,
                            write_evidence,
                            reported.as_ref(),
                            credential_generation,
                            payload_scope_matches,
                        )
                        .await?;
                    let receipt = match outcome {
                        AppendDeviceIngressOutcome::Appended(receipt)
                        | AppendDeviceIngressOutcome::Replay(receipt) => receipt,
                        AppendDeviceIngressOutcome::Conflict => {
                            return Err(StoreError::InvariantViolation);
                        }
                    };
                    let occurred_at = receipt.committed_at();
                    let public =
                        identity::ports::device_certificate::application_receipt(scope, &receipt)
                            .map_err(|_| StoreError::InvariantViolation)?;
                    let event = public
                        .reviewed_event()
                        .await
                        .map_err(|_| StoreError::InvariantViolation)?;
                    let fact =
                        crate::cotx::identity::CanonicalDeviceIngressFact::from_reviewed_event(
                            scope,
                            event,
                            occurred_at,
                            credential_generation,
                        )
                        .map_err(StoreError::from_outbox_append)?;
                    Ok(crate::cotx::identity::DeviceIngressTxOutcome::new(
                        receipt, fact,
                    ))
                })
            },
            storage,
        )
        .await;
    let commit_unknown = matches!(
        attempt.settlement(),
        Some(consistency::LocalTxFinalStatus::CommitUnknown)
    );
    match attempt.into_result() {
        Ok(receipt) => Ok(PgDeviceIngressCommit::committed(receipt)),
        Err(error) if commit_unknown => {
            match exact_device_ingress_readback(
                read_pool,
                scope,
                &expected_evidence,
                credential_generation,
            )
            .await
            {
                Ok(Some(receipt)) => Ok(PgDeviceIngressCommit::committed(receipt)),
                Ok(None) | Err(_) => Err(StoreError::settlement_unknown(error)),
            }
        }
        Err(error) => Err(error),
    }
}

async fn exact_device_ingress_readback(
    read_pool: &TenantDb<ServingReadLane>,
    scope: DeviceCertificateScope,
    evidence: &DeviceIngressEvidence,
    credential_generation: u64,
) -> Result<Option<DeviceIngressReceipt>, StoreError> {
    let expected = evidence.clone();
    read_pool
        .identity_repeatable_read_map(
            scope,
            move |mut tx| {
                Box::pin(async move {
                    let mut identity = tx.identity();
                    let mut readback = identity.device_ingress_readback();
                    let Some(receipt) = readback.exact_receipt(scope, &expected).await? else {
                        return Ok(None);
                    };
                    let fact =
                        expected_receipt_fact(scope, &receipt, credential_generation).await?;
                    let stored = readback
                        .outbox_fingerprint(scope.tenant(), fact.event_id())
                        .await?;
                    Ok(stored
                        .is_some_and(|stored| stored.as_slice() == fact.fingerprint().as_bytes())
                        .then_some(receipt))
                })
            },
            storage,
        )
        .await
}

async fn expected_receipt_fact(
    scope: DeviceCertificateScope,
    receipt: &DeviceIngressReceipt,
    credential_generation: u64,
) -> Result<crate::cotx::identity::CanonicalDeviceIngressFact, StoreError> {
    let public = identity::ports::device_certificate::application_receipt(scope, receipt)
        .map_err(|_| StoreError::InvariantViolation)?;
    let reviewed = public
        .reviewed_event()
        .await
        .map_err(|_| StoreError::InvariantViolation)?;
    crate::cotx::identity::CanonicalDeviceIngressFact::from_reviewed_event(
        scope,
        reviewed,
        receipt.committed_at(),
        credential_generation,
    )
    .map_err(StoreError::from_outbox_append)
}

/// Tenant/device-scoped PostgreSQL command facade bound to one sealed artifact eligibility.
///
/// The serving role retains no raw command-table mutation privilege. Command install and state
/// settlement enter only through the fixed SECURITY DEFINER funnels owned by this adapter.
pub struct PgDeviceCommandStore<E: ArtifactEligibility> {
    read_pool: TenantDb<ServingReadLane>,
    write_pool: TenantDb<ServingWriteLane>,
    device_outbox_pool: crate::device_outbox::PgDeviceOutboxClaimPool,
    eligibility: std::marker::PhantomData<fn() -> E>,
}

impl<E: ArtifactEligibility> PgDeviceCommandStore<E> {
    pub(crate) fn new(reader: &VerifiedPgReadStore, writer: &VerifiedPgWriteStore) -> Self {
        Self {
            read_pool: TenantDb::<ServingReadLane>::new(reader),
            write_pool: TenantDb::<ServingWriteLane>::new(writer),
            device_outbox_pool: crate::device_outbox::PgDeviceOutboxClaimPool::new(
                writer.pool().clone(),
            ),
            eligibility: std::marker::PhantomData,
        }
    }

    /// Load one validated command only when its persisted artifact eligibility matches `E`.
    pub async fn load_command(
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
                            restore_command::<E>(scope.tenant(), row).map(|state| state.snapshot())
                        })
                        .transpose()
                    })
                },
                storage,
            )
            .await
    }
}

impl PgDeviceCommandStore<identity::ports::device_certificate::DraftEligibility> {
    /// Derive the exact DeviceLatent MQTT outbox from this combined command/outbox provider.
    ///
    /// No independent store/provider input is accepted: both handles retain the same verified
    /// serving writer lane and the outbox can settle command publication only through its consumed
    /// SQL claim.
    #[must_use]
    pub fn device_outbox(&self, relay_budget: eventexec::RelayBudget) -> crate::PgDeviceOutbox {
        crate::PgDeviceOutbox::from_command_store(
            self.device_outbox_pool.clone(),
            self.write_pool.clone(),
            relay_budget,
        )
    }
}

#[cfg(all(test, feature = "integration"))]
impl PgDeviceCommandStore<identity::ports::device_certificate::DraftEligibility> {
    pub(crate) fn from_unverified_stores_for_test(
        reader: &crate::PgStore,
        writer: &crate::PgStore,
    ) -> Self {
        Self {
            read_pool: TenantDb::<ServingReadLane>::from_unverified_for_test(reader),
            write_pool: TenantDb::<ServingWriteLane>::from_unverified_for_test(writer),
            device_outbox_pool: crate::device_outbox::PgDeviceOutboxClaimPool::new(
                writer.pool.clone(),
            ),
            eligibility: std::marker::PhantomData,
        }
    }
}

pub(crate) fn storage(error: sqlx::Error) -> StoreError {
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
        scope.tenant().to_string(),
        scope.device().as_uuid().to_string(),
    )
}

#[cfg(all(test, feature = "integration"))]
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

fn optional_system_time_to_micros(value: Option<SystemTime>) -> Result<Option<i64>, StoreError> {
    value
        .map(|time| raw_system_time_to_micros(time).ok_or(StoreError::InvariantViolation))
        .transpose()
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

#[derive(sqlx::FromRow)]
struct CommandRow {
    artifact_eligibility: String,
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

const COMMAND_COLUMNS: &str = "artifact_eligibility, command_id, device_id::text AS device_id, generation, fence_epoch, \
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

fn restore_command<E: ArtifactEligibility>(
    tenant: rss_request_context::TenantId,
    row: CommandRow,
) -> Result<DeviceCommandState, StoreError> {
    if row.artifact_eligibility != E::PERSISTENCE_LABEL {
        return Err(command_corruption(DeviceCommandCorruption::Shape));
    }
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

#[cfg(all(test, feature = "integration"))]
struct SnapshotColumns<'a> {
    common: deviceloop::CommandSnapshotCommon<'a>,
    state: deviceloop::DeviceCommandStatus,
    published_at: Option<SystemTime>,
    received_at: Option<SystemTime>,
    terminal_at: Option<SystemTime>,
}

#[cfg(all(test, feature = "integration"))]
fn snapshot_columns(snapshot: &DeviceCommandSnapshot) -> SnapshotColumns<'_> {
    match snapshot.view() {
        DeviceCommandSnapshotView::Queued { common } => SnapshotColumns {
            common,
            state: deviceloop::DeviceCommandStatus::Queued,
            published_at: None,
            received_at: None,
            terminal_at: None,
        },
        DeviceCommandSnapshotView::Published {
            common,
            published_at,
        } => SnapshotColumns {
            common,
            state: deviceloop::DeviceCommandStatus::Published,
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
            state: deviceloop::DeviceCommandStatus::Received,
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
            state: deviceloop::DeviceCommandStatus::Applied,
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
            state: deviceloop::DeviceCommandStatus::Rejected,
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
            deviceloop::DeviceCommandStatus::TimedOut,
            timed_out_at,
        ),
        DeviceCommandSnapshotView::Superseded {
            common,
            progress,
            superseded_at,
        } => terminal_columns(
            common,
            progress,
            deviceloop::DeviceCommandStatus::Superseded,
            superseded_at,
        ),
        DeviceCommandSnapshotView::Cancelled {
            common,
            progress,
            cancelled_at,
        } => terminal_columns(
            common,
            progress,
            deviceloop::DeviceCommandStatus::Cancelled,
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

#[cfg(all(test, feature = "integration"))]
fn terminal_columns<'a>(
    common: deviceloop::CommandSnapshotCommon<'a>,
    progress: deviceloop::CommandProgressSnapshot,
    state: deviceloop::DeviceCommandStatus,
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
         artifact_eligibility, intent_digest, deadline, state, version) VALUES ( \
         $1::uuid, $2, $3::uuid, $4, $5, 'draft', $6, \
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

fn evidence_columns(
    evidence: &DeviceIngressEvidence,
) -> (&'static str, Option<&str>, u64, u64, u64) {
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
            sequence.get(),
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
            sequence.get(),
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
            sequence.get(),
        ),
        DeviceIngressEvidenceView::ProtocolViolation {
            credential_generation,
        } => (kind, None, credential_generation.get(), 0, 0),
    }
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
                FenceEpoch::try_new(epoch)
                    .map_err(|_| ingress_corruption(DeviceIngressCorruption::Coordinate))?,
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
                FenceEpoch::try_new(epoch)
                    .map_err(|_| ingress_corruption(DeviceIngressCorruption::Coordinate))?,
            ),
            sequence,
            fingerprint,
        ),
        "report" if row.command_id.is_none() => DeviceIngressEvidence::report(
            envelope,
            ObservedGeneration::try_new(generation)
                .map_err(|_| ingress_corruption(DeviceIngressCorruption::Coordinate))?,
            FenceEpoch::try_new(epoch)
                .map_err(|_| ingress_corruption(DeviceIngressCorruption::Coordinate))?,
            sequence,
            fingerprint,
        ),
        "report" => return Err(ingress_corruption(DeviceIngressCorruption::Shape)),
        "protocol_violation"
            if row.command_id.is_none() && row.fence_epoch == 0 && row.device_sequence == 0 =>
        {
            DeviceIngressEvidence::protocol_violation(
                envelope,
                NonZeroU64::new(generation)
                    .ok_or_else(|| ingress_corruption(DeviceIngressCorruption::Coordinate))?,
                fingerprint,
            )
        }
        "protocol_violation" => {
            return Err(ingress_corruption(DeviceIngressCorruption::Shape));
        }
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
impl PgDeviceCommandStore<identity::ports::device_certificate::DraftEligibility> {
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
                            let persisted = restore_command::<
                                identity::ports::device_certificate::DraftEligibility,
                            >(scope.tenant(), row)?
                            .snapshot();
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
                        Ok(
                            CreateDeviceCommandOutcome::Created(
                                restore_command::<
                                    identity::ports::device_certificate::DraftEligibility,
                                >(scope.tenant(), row)?
                                .snapshot(),
                            ),
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
                        let state = restore_command::<
                            identity::ports::device_certificate::DraftEligibility,
                        >(scope.tenant(), row)?;
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_command_row() -> CommandRow {
        CommandRow {
            artifact_eligibility: "draft".to_owned(),
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
        let tenant =
            rss_request_context::TenantId::parse("00000000-0000-4000-8000-000000000001").unwrap();
        let state = restore_command::<identity::ports::device_certificate::DraftEligibility>(
            tenant,
            valid_command_row(),
        )
        .expect("valid command");
        assert_eq!(state.status(), deviceloop::DeviceCommandStatus::Received);
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
        let tenant =
            rss_request_context::TenantId::parse("00000000-0000-4000-8000-000000000001").unwrap();
        let state = restore_command::<identity::ports::device_certificate::DraftEligibility>(
            tenant,
            valid_command_row(),
        )
        .expect("valid row");
        assert_eq!(state.status().as_label(), "received");
        assert_eq!(state.version().get(), 3);
        assert_eq!(state.intent_digest().as_bytes(), &[7; 32]);
    }

    #[test]
    fn command_row_codec_reports_every_closed_corruption_reason() {
        let tenant =
            rss_request_context::TenantId::parse("00000000-0000-4000-8000-000000000001").unwrap();
        let mut row = valid_command_row();
        row.device_id = "not-a-uuid".to_owned();
        assert!(matches!(
            restore_command::<identity::ports::device_certificate::DraftEligibility>(tenant, row),
            Err(StoreError::CorruptCommand(
                DeviceCommandCorruption::Identity
            ))
        ));

        let mut row = valid_command_row();
        row.generation = 0;
        assert!(matches!(
            restore_command::<identity::ports::device_certificate::DraftEligibility>(tenant, row),
            Err(StoreError::CorruptCommand(
                DeviceCommandCorruption::Coordinate
            ))
        ));

        let mut row = valid_command_row();
        row.intent_digest.pop();
        assert!(matches!(
            restore_command::<identity::ports::device_certificate::DraftEligibility>(tenant, row),
            Err(StoreError::CorruptCommand(DeviceCommandCorruption::Digest))
        ));

        let mut row = valid_command_row();
        row.deadline_micros = i64::MIN;
        assert!(matches!(
            restore_command::<identity::ports::device_certificate::DraftEligibility>(tenant, row),
            Err(StoreError::CorruptCommand(
                DeviceCommandCorruption::Timestamp
            ))
        ));

        let mut row = valid_command_row();
        row.published_at_micros = None;
        assert!(matches!(
            restore_command::<identity::ports::device_certificate::DraftEligibility>(tenant, row),
            Err(StoreError::CorruptCommand(DeviceCommandCorruption::Shape))
        ));

        let mut row = valid_command_row();
        row.state = "invented".to_owned();
        assert!(matches!(
            restore_command::<identity::ports::device_certificate::DraftEligibility>(tenant, row),
            Err(StoreError::CorruptCommand(DeviceCommandCorruption::State))
        ));
    }

    #[test]
    fn ingress_row_codec_restores_exact_evidence() {
        let receipt = restore_receipt(valid_ingress_row()).expect("valid receipt");
        assert_eq!(receipt.evidence().kind_label(), "ack_received");
        assert_eq!(receipt.disposition(), DeviceIngressDisposition::Advanced);
        assert_eq!(evidence_columns(receipt.evidence()).4, 0);
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
        assert_eq!(evidence_columns(&evidence), ("report", None, 3, 4, 0));
    }

    #[test]
    fn protocol_violation_has_one_closed_rejected_storage_shape() {
        const MIGRATION: &str =
            include_str!("../migrations/0095_seal_device_artifact_eligibility.sql");
        assert!(MIGRATION.contains("rss_commit_device_ingress_protocol_violation"));
        assert!(MIGRATION.contains("'protocol_violation',NULL"));
        assert!(MIGRATION.contains("p_credential_generation,0,0,p_fingerprint,'rejected'"));

        let evidence = DeviceIngressEvidence::protocol_violation(
            DeviceIngressEnvelopeId::parse("malformed-1").unwrap(),
            NonZeroU64::new(7).unwrap(),
            DeviceIngressFingerprint::from_bytes([7; 32]),
        );
        assert_eq!(
            evidence_columns(&evidence),
            ("protocol_violation", None, 7, 0, 0)
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

    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use deviceloop::{
        CommandIntentDigest, CommandVersion, CreateDeviceCommand, CreateDeviceCommandOutcome,
        DesiredGeneration, DeviceCommandDeadline, DeviceCommandId, DeviceCommandMutation,
        DeviceCommandScope, DeviceCommandSnapshot, DeviceCommandStatus, DeviceIngressDisposition,
        FenceEpoch, GenerationTracker, ObservedGeneration, TransitionDeviceCommandOutcome,
    };
    use diport::ManagedResource as _;
    use identity::ports::device_certificate::{DeviceCertificateScope, DraftEligibility};
    use testkit::device_command_conformance::{
        DeviceCommandCasCase, DeviceCommandCasObservation, DeviceCommandCreateCase,
        DeviceCommandCreateObservation, assert_device_command_cas, assert_device_command_create,
        assert_device_command_restart_equivalence,
    };

    use super::PgDeviceCommandStore as GenericPgDeviceCommandStore;

    type PgDeviceCommandStore = GenericPgDeviceCommandStore<DraftEligibility>;

    type TestError = Box<dyn std::error::Error + Send + Sync>;
    type TestResult = Result<(), TestError>;

    struct IngressDelivery {
        target: Target,
        credential_generation: u64,
        contract: identity::ports::device_certificate::DeviceIngressContract,
        event_id: String,
        payload: Vec<u8>,
        settled: Arc<AtomicBool>,
    }

    impl identity::ports::device_certificate::DeviceIngressDelivery for IngressDelivery {
        fn tenant(&self) -> rss_request_context::TenantId {
            self.target.scope.tenant()
        }

        fn device(&self) -> ids::DeviceId {
            self.target.scope.device()
        }

        fn credential_generation(&self) -> u64 {
            self.credential_generation
        }

        fn contract(&self) -> identity::ports::device_certificate::DeviceIngressContract {
            self.contract
        }

        fn correlation_data(&self) -> Option<&[u8]> {
            Some(self.event_id.as_bytes())
        }

        fn payload(&self) -> &[u8] {
            &self.payload
        }
    }

    async fn run_device_ingress(
        delivery: IngressDelivery,
        repository: &crate::device_certificate::PgDeviceCertificateRepository<DraftEligibility>,
    ) -> Result<deviceloop::DeviceIngressReceipt, TestError> {
        let prepared = match identity::ports::device_certificate::prepare_device_ingress(&delivery)
        {
            identity::ports::device_certificate::DeviceIngressPreparation::Accepted(prepared)
            | identity::ports::device_certificate::DeviceIngressPreparation::Rejected(prepared) => {
                prepared
            }
            identity::ports::device_certificate::DeviceIngressPreparation::UnaddressablePoison(
                _,
            ) => return Err(std::io::Error::other("unaddressable test ingress").into()),
        };
        let (write, pending) = prepared.into_parts();
        let committed = <crate::device_certificate::PgDeviceCertificateRepository<
            DraftEligibility,
        > as
            identity::ports::device_certificate::DeviceIngressRepository<
                DraftEligibility,
            >>::commit(repository, write)
        .await?;
        let (receipt, proof) = committed.into_parts();
        let outcome = pending.verify_receipt(receipt)?;
        let _consumed_proof = proof;
        delivery.settled.store(true, Ordering::SeqCst);
        Ok(outcome.into_receipt())
    }

    #[derive(Clone, Copy)]
    struct Target {
        scope: DeviceCertificateScope,
        command_scope: DeviceCommandScope,
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
        let tenant =
            rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
        new_target_for_tenant(tenant)
    }

    fn new_target_for_tenant(tenant: rss_request_context::TenantId) -> Target {
        let device = ids::DeviceId::new(uuid::Uuid::new_v4());
        Target {
            scope: DeviceCertificateScope::for_test(tenant, device),
            command_scope: DeviceCommandScope::new(tenant, device),
        }
    }

    fn tracker(target: Target) -> GenerationTracker<&'static str> {
        tracker_at(target, 1)
    }

    fn tracker_at(target: Target, generation: u64) -> GenerationTracker<&'static str> {
        GenerationTracker::new(
            target.command_scope,
            DesiredGeneration::try_new(generation).unwrap(),
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
        created_snapshot_at(store, target, id, digest, 1, deadline).await
    }

    async fn created_snapshot_at(
        store: &PgDeviceCommandStore,
        target: Target,
        id: &str,
        digest: u8,
        generation: u64,
        deadline: std::time::SystemTime,
    ) -> Result<DeviceCommandSnapshot, TestError> {
        let input = CreateDeviceCommand::new(
            DeviceCommandId::parse(id)?,
            CommandIntentDigest::from_bytes([digest; 32]),
            tracker_at(target, generation).current_fence(),
            DeviceCommandDeadline::try_new(deadline)?,
        );
        match store.create_command(target.scope, input).await? {
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

    async fn insert_desired(store: &crate::PgStore, target: Target) -> TestResult {
        insert_desired_at(store, target, 1).await
    }

    async fn insert_desired_at(
        store: &crate::PgStore,
        target: Target,
        generation: u64,
    ) -> TestResult {
        sqlx::query(
            "INSERT INTO device_certificate_desired_states \
             (tenant_id, device_id, generation, validity_seconds, renew_before_seconds, \
              client_auth, server_auth, sans) \
             VALUES ($1::uuid, $2::uuid, $3, 3600, 600, true, false, ARRAY[]::text[])",
        )
        .bind(target.scope.tenant().to_string())
        .bind(target.scope.device().as_uuid().to_string())
        .bind(i64::try_from(generation)?)
        .execute(&store.pool)
        .await?;
        let target_id: String = sqlx::query_scalar(
            "INSERT INTO reconcile_targets \
             (tenant_id, reconciler_id, resource_kind, resource_id) \
             VALUES ($1::uuid, $2, $3, $4) \
             RETURNING target_id::text",
        )
        .bind(target.scope.tenant().to_string())
        .bind(super::DEVICE_CERTIFICATE_RECONCILER_ID)
        .bind(super::DEVICE_CERTIFICATE_RESOURCE_KIND)
        .bind(target.scope.device().as_uuid().to_string())
        .fetch_one(&store.pool)
        .await?;
        sqlx::query(
            "INSERT INTO reconcile_leases (tenant_id, target_id, epoch) \
             VALUES ($1::uuid, $2::uuid, 7)",
        )
        .bind(target.scope.tenant().to_string())
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

    fn ack_delivery(
        target: Target,
        event_id: &str,
        command_id: &str,
    ) -> (IngressDelivery, Arc<AtomicBool>) {
        ack_delivery_at_for_payload_device(
            target,
            event_id,
            command_id,
            1,
            7,
            1,
            target.scope.device().as_uuid(),
        )
    }

    fn ack_delivery_at(
        target: Target,
        event_id: &str,
        command_id: &str,
        generation: u64,
        fence_epoch: u64,
        device_sequence: u64,
    ) -> (IngressDelivery, Arc<AtomicBool>) {
        ack_delivery_at_for_payload_device(
            target,
            event_id,
            command_id,
            generation,
            fence_epoch,
            device_sequence,
            target.scope.device().as_uuid(),
        )
    }

    fn ack_delivery_for_payload_device(
        target: Target,
        event_id: &str,
        command_id: &str,
        payload_device: uuid::Uuid,
    ) -> (IngressDelivery, Arc<AtomicBool>) {
        ack_delivery_at_for_payload_device(target, event_id, command_id, 1, 7, 1, payload_device)
    }

    #[allow(clippy::too_many_arguments)]
    fn ack_delivery_at_for_payload_device(
        target: Target,
        event_id: &str,
        command_id: &str,
        generation: u64,
        fence_epoch: u64,
        device_sequence: u64,
        payload_device: uuid::Uuid,
    ) -> (IngressDelivery, Arc<AtomicBool>) {
        let settled = Arc::new(AtomicBool::new(false));
        let payload = serde_json::json!({
            "deviceId": payload_device,
            "commandId": command_id,
            "desiredGeneration": generation,
            "fenceEpoch": fence_epoch,
            "deviceSequence": device_sequence,
            "result": "received",
            "reason": "None",
            "observedAt": 1_700_000_000_000_000_i64
        });
        (
            IngressDelivery {
                target,
                credential_generation: 1,
                contract: identity::ports::device_certificate::DeviceIngressContract::CommandAcked,
                event_id: event_id.to_owned(),
                payload: serde_json::to_vec(&payload).expect("ACK payload"),
                settled: Arc::clone(&settled),
            },
            settled,
        )
    }

    fn rejected_ack_delivery(
        target: Target,
        event_id: &str,
        command_id: &str,
    ) -> (IngressDelivery, Arc<AtomicBool>) {
        let settled = Arc::new(AtomicBool::new(false));
        let payload = serde_json::json!({
            "deviceId": target.scope.device().as_uuid(),
            "commandId": command_id,
            "desiredGeneration": 1,
            "fenceEpoch": 7,
            "deviceSequence": 1,
            "result": "rejected",
            "reason": "DeviceFailure",
            "observedAt": 1_700_000_000_000_000_i64
        });
        (
            IngressDelivery {
                target,
                credential_generation: 1,
                contract: identity::ports::device_certificate::DeviceIngressContract::CommandAcked,
                event_id: event_id.to_owned(),
                payload: serde_json::to_vec(&payload).expect("rejected ACK payload"),
                settled: Arc::clone(&settled),
            },
            settled,
        )
    }

    fn report_delivery(target: Target, event_id: &str) -> (IngressDelivery, Arc<AtomicBool>) {
        report_delivery_at(target, event_id, 1, 7, 2)
    }

    fn report_delivery_at(
        target: Target,
        event_id: &str,
        generation: u64,
        fence_epoch: u64,
        device_sequence: u64,
    ) -> (IngressDelivery, Arc<AtomicBool>) {
        let settled = Arc::new(AtomicBool::new(false));
        let payload = serde_json::json!({
            "deviceId": target.scope.device().as_uuid(),
            "observedGeneration": generation,
            "fenceEpoch": fence_epoch,
            "deviceSequence": device_sequence,
            "stateHash": format!("sha256:{}", "1".repeat(64)),
            "artifactDigest": format!("sha256:{}", "2".repeat(64)),
            "observedAt": 1_700_000_000_000_001_i64
        });
        (
            IngressDelivery {
                target,
                credential_generation: 1,
                contract:
                    identity::ports::device_certificate::DeviceIngressContract::CertificateReported,
                event_id: event_id.to_owned(),
                payload: serde_json::to_vec(&payload).expect("report payload"),
                settled: Arc::clone(&settled),
            },
            settled,
        )
    }

    fn with_credential_generation(
        delivery: (IngressDelivery, Arc<AtomicBool>),
        credential_generation: u64,
    ) -> (IngressDelivery, Arc<AtomicBool>) {
        let (mut delivery, settled) = delivery;
        delivery.credential_generation = credential_generation;
        (delivery, settled)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn durable_ingress_commits_ack_receipt_conditions_wake_and_outbox_once() -> TestResult {
        let (fixture, owner) = crate::test_pg::connect_pg().await?;
        owner.run_migrations().await?;
        let ingress_funnel_acl: (bool, bool, bool, bool, bool, bool, bool, bool) =
            sqlx::query_as(
            "SELECT
                to_regprocedure('public.rss_apply_device_command_ack(uuid,uuid,text,bigint,bigint,text)') IS NULL,
                to_regprocedure('public.rss_upsert_device_certificate_report(uuid,uuid,bigint,bigint,bytea,bytea,text,bigint,bigint,bigint)') IS NULL,
                has_function_privilege('rss_app', 'public.rss_commit_device_command_ack_ingress(uuid,uuid,text,text,bigint,bigint,bigint,bytea,text,bigint,boolean)', 'EXECUTE'),
                has_function_privilege('rss_app', 'public.rss_commit_device_certificate_report_ingress(uuid,uuid,text,bigint,bigint,bigint,bytea,bytea,bytea,bigint,bigint,bigint,boolean)', 'EXECUTE'),
                has_function_privilege('rss_app', 'public.rss_commit_device_ingress_protocol_violation(uuid,uuid,text,bytea,bigint)', 'EXECUTE'),
                NOT has_function_privilege('rss_app_read', 'public.rss_commit_device_command_ack_ingress(uuid,uuid,text,text,bigint,bigint,bigint,bytea,text,bigint,boolean)', 'EXECUTE'),
                NOT has_function_privilege('rss_app_read', 'public.rss_commit_device_ingress_protocol_violation(uuid,uuid,text,bytea,bigint)', 'EXECUTE'),
                NOT has_table_privilege('rss_app', 'public.device_commands', 'UPDATE')
                  AND NOT has_table_privilege('rss_app', 'public.device_certificate_reported_states', 'INSERT,UPDATE')
                  AND NOT has_table_privilege('rss_app', 'public.device_certificate_conditions', 'INSERT,UPDATE')
                  AND NOT has_table_privilege('rss_app', 'public.device_ingress_receipts', 'INSERT,UPDATE,DELETE')",
        )
            .fetch_one(&owner.pool)
            .await?;
        assert_eq!(
            ingress_funnel_acl,
            (true, true, true, true, true, true, true, true)
        );
        let funnel_owners: Vec<String> = sqlx::query_scalar(
            "SELECT pg_get_userbyid(proowner) FROM pg_proc
             WHERE proname IN ('rss_commit_device_command_ack_ingress',
                                'rss_commit_device_certificate_report_ingress',
                                'rss_commit_device_ingress_protocol_violation')
             ORDER BY proname",
        )
        .fetch_all(&owner.pool)
        .await?;
        assert_eq!(
            funnel_owners,
            vec![
                "rss_device_command_funnel_owner".to_owned(),
                "rss_device_command_funnel_owner".to_owned(),
                "rss_device_command_funnel_owner".to_owned(),
            ]
        );
        let hard_database_carriers: (bool, bool, bool, bool) = sqlx::query_as(
            "SELECT
                (SELECT count(*)=4 AND bool_and(relrowsecurity AND relforcerowsecurity)
                 FROM pg_class WHERE relname IN ('device_ingress_receipts','device_commands',
                   'device_certificate_reported_states','device_certificate_conditions')),
                (SELECT NOT rolcanlogin FROM pg_roles
                 WHERE rolname='rss_device_command_funnel_owner'),
                (SELECT NOT rolbypassrls FROM pg_roles
                 WHERE rolname='rss_device_command_funnel_owner'),
                NOT EXISTS (
                  SELECT 1 FROM pg_class table_row
                  JOIN pg_attribute column_row ON column_row.attrelid=table_row.oid
                  WHERE table_row.relname IN ('device_ingress_receipts','device_commands',
                    'device_certificate_reported_states','device_certificate_conditions')
                    AND column_row.attnum>0 AND NOT column_row.attisdropped
                    AND (has_column_privilege('rss_app',table_row.oid,column_row.attnum,'INSERT')
                      OR has_column_privilege('rss_app',table_row.oid,column_row.attnum,'UPDATE')))",
        )
        .fetch_one(&owner.pool)
        .await?;
        assert_eq!(hard_database_carriers, (true, true, true, true));
        let target = new_target();
        insert_desired(&owner, target).await?;
        let command_store = PgDeviceCommandStore::from_unverified_stores_for_test(&owner, &owner);
        let created =
            created_snapshot(&command_store, target, "ingress-command", 9, deadline()).await?;
        let _published = transition_snapshot(
            &command_store,
            target,
            "ingress-command",
            &created,
            DeviceCommandMutation::publish(tracker(target).current_fence()),
        )
        .await?;

        let writer = crate::test_pg::connect_pg_rss_app_role(&fixture, &owner).await?;
        let reader = crate::test_pg::connect_pg_rss_app_read_role(&fixture, &owner).await?;
        let repository = Arc::new(crate::device_certificate::PgDeviceCertificateRepository::<
            DraftEligibility,
        >::from_unverified_stores_for_test(&reader, &writer));

        let (left_delivery, left_settled) =
            ack_delivery(target, "ack-ingress-1", "ingress-command");
        let (right_delivery, right_settled) =
            ack_delivery(target, "ack-ingress-1", "ingress-command");
        let (left, right) = tokio::join!(
            run_device_ingress(left_delivery, repository.as_ref()),
            run_device_ingress(right_delivery, repository.as_ref())
        );
        left.expect("left concurrent ingress succeeds");
        right.expect("right concurrent replay succeeds");
        assert!(left_settled.load(Ordering::SeqCst));
        assert!(right_settled.load(Ordering::SeqCst));

        let command_state: String = sqlx::query_scalar(
            "SELECT state FROM device_commands WHERE tenant_id=$1::uuid AND command_id=$2",
        )
        .bind(target.scope.tenant().to_string())
        .bind("ingress-command")
        .fetch_one(&owner.pool)
        .await?;
        assert_eq!(command_state, "received");
        let durable_counts: (i64, i64) = sqlx::query_as(
            "SELECT
                (SELECT count(*) FROM device_ingress_receipts WHERE tenant_id=$1::uuid AND event_id=$2),
                (SELECT count(*) FROM outbox WHERE tenant_id=$1::uuid
                    AND contract_id='identity.device-ingress-receipted')",
        )
        .bind(target.scope.tenant().to_string())
        .bind("ack-ingress-1")
        .fetch_one(&owner.pool)
        .await?;
        assert_eq!(durable_counts, (1, 1));
        let conditions: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT condition_type,status,reason FROM device_certificate_conditions
             WHERE tenant_id=$1::uuid AND device_id=$2::uuid
               AND condition_type IN ('Ready','Reconciling','PendingDevice')
             ORDER BY condition_type",
        )
        .bind(target.scope.tenant().to_string())
        .bind(target.scope.device().as_uuid().to_string())
        .fetch_all(&owner.pool)
        .await?;
        assert!(conditions.contains(&(
            "Ready".to_owned(),
            "False".to_owned(),
            "AwaitingDevice".to_owned()
        )));

        let (delivery, settled) =
            ack_delivery(target, "ack-ingress-semantic-duplicate", "ingress-command");
        run_device_ingress(delivery, repository.as_ref())
            .await
            .expect("semantic ACK duplicate is durable");
        assert!(settled.load(Ordering::SeqCst));
        let duplicate_ack: String = sqlx::query_scalar(
            "SELECT disposition FROM device_ingress_receipts
             WHERE tenant_id=$1::uuid AND event_id='ack-ingress-semantic-duplicate'",
        )
        .bind(target.scope.tenant().to_string())
        .fetch_one(&owner.pool)
        .await?;
        assert_eq!(duplicate_ack, "duplicate");
        assert!(conditions.contains(&(
            "Reconciling".to_owned(),
            "True".to_owned(),
            "CommandQueued".to_owned()
        )));
        assert!(conditions.contains(&(
            "PendingDevice".to_owned(),
            "True".to_owned(),
            "AwaitingDevice".to_owned()
        )));

        let (delivery, settled) = report_delivery(target, "report-ingress-1");
        run_device_ingress(delivery, repository.as_ref())
            .await
            .expect("durable report ingress succeeds");
        assert!(settled.load(Ordering::SeqCst));
        let report_state: (String, i64, i64, i64) = sqlx::query_as(
            "SELECT command.state,reported.observed_generation,reported.device_sequence,
                    (SELECT count(*) FROM outbox WHERE tenant_id=$1::uuid
                       AND contract_id='identity.device-ingress-receipted')
             FROM device_commands command
             JOIN device_certificate_reported_states reported
               ON reported.tenant_id=command.tenant_id AND reported.device_id=command.device_id
             WHERE command.tenant_id=$1::uuid AND command.command_id=$2",
        )
        .bind(target.scope.tenant().to_string())
        .bind("ingress-command")
        .fetch_one(&owner.pool)
        .await?;
        assert_eq!(report_state, ("applied".to_owned(), 1, 2, 3));
        let report_conditions: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT condition_type,status,reason FROM device_certificate_conditions
             WHERE tenant_id=$1::uuid AND device_id=$2::uuid
               AND condition_type IN ('Ready','Reconciling','PendingDevice')",
        )
        .bind(target.scope.tenant().to_string())
        .bind(target.scope.device().as_uuid().to_string())
        .fetch_all(&owner.pool)
        .await?;
        assert!(report_conditions.contains(&(
            "Ready".to_owned(),
            "False".to_owned(),
            "AwaitingDevice".to_owned()
        )));

        let (delivery, settled) = report_delivery(target, "report-ingress-semantic-duplicate");
        run_device_ingress(delivery, repository.as_ref())
            .await
            .expect("semantic report duplicate is durable");
        assert!(settled.load(Ordering::SeqCst));
        let duplicate_report: (String, i64) = sqlx::query_as(
            "SELECT disposition,
                (SELECT count(*) FROM outbox WHERE tenant_id=$1::uuid
                  AND contract_id='identity.device-ingress-receipted')
             FROM device_ingress_receipts
             WHERE tenant_id=$1::uuid AND event_id='report-ingress-semantic-duplicate'",
        )
        .bind(target.scope.tenant().to_string())
        .fetch_one(&owner.pool)
        .await?;
        assert_eq!(duplicate_report, ("duplicate".to_owned(), 4));
        assert!(report_conditions.contains(&(
            "Reconciling".to_owned(),
            "True".to_owned(),
            "DeviceReported".to_owned()
        )));
        assert!(report_conditions.contains(&(
            "PendingDevice".to_owned(),
            "False".to_owned(),
            "AwaitingDevice".to_owned()
        )));

        let malformed_delivery = |settled: Arc<AtomicBool>| IngressDelivery {
            target,
            credential_generation: 1,
            contract: identity::ports::device_certificate::DeviceIngressContract::CommandAcked,
            event_id: "stable-malformed-ingress".to_owned(),
            payload: b"not-json".to_vec(),
            settled,
        };
        let first_poison_settled = Arc::new(AtomicBool::new(false));
        let first_poison = run_device_ingress(
            malformed_delivery(Arc::clone(&first_poison_settled)),
            repository.as_ref(),
        )
        .await?;
        assert_eq!(first_poison.evidence().kind_label(), "protocol_violation");
        assert_eq!(
            first_poison.disposition(),
            DeviceIngressDisposition::Rejected
        );
        assert!(first_poison_settled.load(Ordering::SeqCst));

        let replay_poison_settled = Arc::new(AtomicBool::new(false));
        let replay_poison = run_device_ingress(
            malformed_delivery(Arc::clone(&replay_poison_settled)),
            repository.as_ref(),
        )
        .await?;
        assert_eq!(replay_poison, first_poison);
        assert!(replay_poison_settled.load(Ordering::SeqCst));
        let poison_counts: (String, String, i64, i64) = sqlx::query_as(
            "SELECT kind, disposition,
                (SELECT count(*) FROM device_ingress_receipts
                  WHERE tenant_id=$1::uuid AND event_id='stable-malformed-ingress'),
                (SELECT count(*) FROM outbox WHERE tenant_id=$1::uuid
                  AND contract_id='identity.device-ingress-receipted')
             FROM device_ingress_receipts
             WHERE tenant_id=$1::uuid AND event_id='stable-malformed-ingress'",
        )
        .bind(target.scope.tenant().to_string())
        .fetch_one(&owner.pool)
        .await?;
        assert_eq!(
            poison_counts,
            ("protocol_violation".to_owned(), "rejected".to_owned(), 1, 5)
        );

        let (post_poison_delivery, post_poison_settled) =
            report_delivery(target, "post-poison-valid-ingress");
        let post_poison = run_device_ingress(post_poison_delivery, repository.as_ref()).await?;
        assert_eq!(
            post_poison.disposition(),
            DeviceIngressDisposition::Duplicate
        );
        assert!(post_poison_settled.load(Ordering::SeqCst));
        let outbox_after_post_poison: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM outbox WHERE tenant_id=$1::uuid
               AND contract_id='identity.device-ingress-receipted'",
        )
        .bind(target.scope.tenant().to_string())
        .fetch_one(&owner.pool)
        .await?;
        assert_eq!(outbox_after_post_poison, 6);

        drop((repository, command_store));
        reader.shutdown().await?;
        writer.shutdown().await?;
        owner.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn durable_ingress_commit_unknown_reads_back_and_precommit_failure_rolls_back()
    -> TestResult {
        let (fixture, owner) = crate::test_pg::connect_pg().await?;
        owner.run_migrations().await?;
        let command_store = PgDeviceCommandStore::from_unverified_stores_for_test(&owner, &owner);
        let committed_target = new_target();
        let rolled_back_target = new_target();
        for (target, command_id) in [
            (committed_target, "commit-unknown-command"),
            (rolled_back_target, "rollback-command"),
        ] {
            insert_desired(&owner, target).await?;
            let created =
                created_snapshot(&command_store, target, command_id, 7, deadline()).await?;
            transition_snapshot(
                &command_store,
                target,
                command_id,
                &created,
                DeviceCommandMutation::publish(tracker(target).current_fence()),
            )
            .await?;
        }
        let writer = crate::test_pg::connect_pg_rss_app_role(&fixture, &owner).await?;
        let reader = crate::test_pg::connect_pg_rss_app_read_role(&fixture, &owner).await?;

        let commit_unknown_repository = Arc::new(
            crate::device_certificate::PgDeviceCertificateRepository::<DraftEligibility>::
                from_unverified_stores_for_test(&reader, &writer)
                .with_device_ingress_fault_for_test(super::DeviceIngressFault::CommitUnknown),
        );
        let (delivery, settled) = ack_delivery(
            committed_target,
            "commit-unknown-ingress",
            "commit-unknown-command",
        );
        run_device_ingress(delivery, commit_unknown_repository.as_ref())
            .await
            .expect("exact readback resolves committed transaction");
        assert!(settled.load(Ordering::SeqCst));

        let ingress_row: super::IngressRow = sqlx::query_as(&format!(
            "SELECT {} FROM device_ingress_receipts
             WHERE tenant_id=$1::uuid AND event_id=$2",
            super::INGRESS_COLUMNS
        ))
        .bind(committed_target.scope.tenant().to_string())
        .bind("commit-unknown-ingress")
        .fetch_one(&owner.pool)
        .await?;
        let committed_receipt = super::restore_receipt(ingress_row)?;
        let committed_evidence = committed_receipt.evidence().clone();
        assert!(
            super::exact_device_ingress_readback(
                &command_store.read_pool,
                committed_target.scope,
                &committed_evidence,
                1,
            )
            .await?
            .is_some()
        );
        let receipt_fact =
            super::expected_receipt_fact(committed_target.scope, &committed_receipt, 1).await?;
        let receipt_event_id = receipt_fact.event_id().to_owned();
        let original_payload: Vec<u8> = sqlx::query_scalar(
            "UPDATE outbox SET payload=payload || decode('00','hex')
             WHERE tenant_id=$1::uuid AND event_id=$2 RETURNING substring(payload FROM 1 FOR octet_length(payload)-1)",
        )
        .bind(committed_target.scope.tenant().to_string())
        .bind(&receipt_event_id)
        .fetch_one(&owner.pool)
        .await?;
        assert!(
            super::exact_device_ingress_readback(
                &command_store.read_pool,
                committed_target.scope,
                &committed_evidence,
                1,
            )
            .await?
            .is_none(),
            "conflicting Outbox fact must not authorize settlement"
        );
        sqlx::query(
            "UPDATE outbox SET payload=$3
             WHERE tenant_id=$1::uuid AND event_id=$2",
        )
        .bind(committed_target.scope.tenant().to_string())
        .bind(&receipt_event_id)
        .bind(original_payload)
        .execute(&owner.pool)
        .await?;
        sqlx::query("DELETE FROM outbox WHERE tenant_id=$1::uuid AND event_id=$2")
            .bind(committed_target.scope.tenant().to_string())
            .bind(&receipt_event_id)
            .execute(&owner.pool)
            .await?;
        assert!(
            super::exact_device_ingress_readback(
                &command_store.read_pool,
                committed_target.scope,
                &committed_evidence,
                1,
            )
            .await?
            .is_none(),
            "missing Outbox fact must not authorize settlement"
        );

        let rollback_repository = Arc::new(
            crate::device_certificate::PgDeviceCertificateRepository::<DraftEligibility>::
                from_unverified_stores_for_test(&reader, &writer)
                .with_device_ingress_fault_for_test(super::DeviceIngressFault::AfterOutbox),
        );
        let (delivery, settled) =
            ack_delivery(rolled_back_target, "rollback-ingress", "rollback-command");
        let failed = run_device_ingress(delivery, rollback_repository.as_ref()).await;
        assert!(failed.is_err());
        assert!(!settled.load(Ordering::SeqCst));
        let rollback_state: (String, i64, i64) = sqlx::query_as(
            "SELECT command.state,
                (SELECT count(*) FROM device_ingress_receipts WHERE tenant_id=$1::uuid AND event_id=$3),
                (SELECT count(*) FROM outbox WHERE tenant_id=$1::uuid
                    AND contract_id='identity.device-ingress-receipted'
                    AND metadata->>'subjectId'=$2)
             FROM device_commands command
             WHERE command.tenant_id=$1::uuid AND command.command_id='rollback-command'",
        )
        .bind(rolled_back_target.scope.tenant().to_string())
        .bind(rolled_back_target.scope.device().as_uuid().to_string())
        .bind("rollback-ingress")
        .fetch_one(&owner.pool)
        .await?;
        assert_eq!(rollback_state, ("published".to_owned(), 0, 0));

        drop((
            commit_unknown_repository,
            rollback_repository,
            command_store,
        ));
        reader.shutdown().await?;
        writer.shutdown().await?;
        owner.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn durable_ingress_fail_closed_protocol_and_stale_matrix() -> TestResult {
        let (fixture, owner) = crate::test_pg::connect_pg().await?;
        owner.run_migrations().await?;
        let target = new_target();
        let rejected_target = new_target();
        let old_fence_unreceived_target = new_target_for_tenant(target.scope.tenant());
        let ack_old_fence_unreceived_target = new_target_for_tenant(target.scope.tenant());
        insert_desired(&owner, target).await?;
        insert_desired(&owner, rejected_target).await?;
        insert_desired(&owner, old_fence_unreceived_target).await?;
        insert_desired(&owner, ack_old_fence_unreceived_target).await?;
        let command_store = PgDeviceCommandStore::from_unverified_stores_for_test(&owner, &owner);
        let created =
            created_snapshot(&command_store, target, "matrix-command", 12, deadline()).await?;
        transition_snapshot(
            &command_store,
            target,
            "matrix-command",
            &created,
            DeviceCommandMutation::publish(tracker(target).current_fence()),
        )
        .await?;
        let rejected_created = created_snapshot(
            &command_store,
            rejected_target,
            "rejected-command",
            13,
            deadline(),
        )
        .await?;
        transition_snapshot(
            &command_store,
            rejected_target,
            "rejected-command",
            &rejected_created,
            DeviceCommandMutation::publish(tracker(rejected_target).current_fence()),
        )
        .await?;
        let old_fence_unreceived_created = created_snapshot(
            &command_store,
            old_fence_unreceived_target,
            "old-fence-unreceived-command",
            14,
            deadline(),
        )
        .await?;
        transition_snapshot(
            &command_store,
            old_fence_unreceived_target,
            "old-fence-unreceived-command",
            &old_fence_unreceived_created,
            DeviceCommandMutation::publish(tracker(old_fence_unreceived_target).current_fence()),
        )
        .await?;
        let ack_old_fence_unreceived_created = created_snapshot(
            &command_store,
            ack_old_fence_unreceived_target,
            "ack-old-fence-unreceived-command",
            15,
            deadline(),
        )
        .await?;
        transition_snapshot(
            &command_store,
            ack_old_fence_unreceived_target,
            "ack-old-fence-unreceived-command",
            &ack_old_fence_unreceived_created,
            DeviceCommandMutation::publish(
                tracker(ack_old_fence_unreceived_target).current_fence(),
            ),
        )
        .await?;
        let writer = crate::test_pg::connect_pg_rss_app_role(&fixture, &owner).await?;
        let reader = crate::test_pg::connect_pg_rss_app_read_role(&fixture, &owner).await?;
        let repository = Arc::new(crate::device_certificate::PgDeviceCertificateRepository::<
            DraftEligibility,
        >::from_unverified_stores_for_test(&reader, &writer));

        let (delivery, rejected_settled) =
            rejected_ack_delivery(rejected_target, "device-rejected", "rejected-command");
        run_device_ingress(delivery, repository.as_ref())
            .await
            .expect("device rejection commits");
        assert!(rejected_settled.load(Ordering::SeqCst));
        let rejected_state: (String, i64) = sqlx::query_as(
            "SELECT state,
                (SELECT count(*) FROM device_certificate_conditions
                 WHERE tenant_id=$1::uuid AND device_id=$2::uuid
                   AND ((condition_type='Ready' AND status='False' AND reason='CommandRejected')
                     OR (condition_type='Reconciling' AND status='False' AND reason='StateDrift')
                     OR (condition_type='PendingDevice' AND status='False' AND reason='AwaitingDevice')
                     OR (condition_type='Degraded' AND status='True' AND reason='CommandRejected')))
             FROM device_commands WHERE tenant_id=$1::uuid AND command_id='rejected-command'",
        )
        .bind(rejected_target.scope.tenant().to_string())
        .bind(rejected_target.scope.device().as_uuid().to_string())
        .fetch_one(&owner.pool)
        .await?;
        assert_eq!(rejected_state, ("rejected".to_owned(), 4));

        let (delivery, report_before_ack_settled) = report_delivery(target, "report-before-ack");
        run_device_ingress(delivery, repository.as_ref())
            .await
            .expect("report-before-ACK is durably receipted");
        assert!(report_before_ack_settled.load(Ordering::SeqCst));

        let (delivery, conflicting_reuse_settled) =
            ack_delivery(target, "report-before-ack", "matrix-command");
        assert!(
            run_device_ingress(delivery, repository.as_ref())
                .await
                .is_err()
        );
        assert!(!conflicting_reuse_settled.load(Ordering::SeqCst));

        let (delivery, ack_settled) = ack_delivery(target, "matrix-ack", "matrix-command");
        run_device_ingress(delivery, repository.as_ref())
            .await
            .expect("ACK commits");
        assert!(ack_settled.load(Ordering::SeqCst));

        for (delivery, settled) in [
            ack_delivery(target, "unknown-command", "not-visible-command"),
            ack_delivery_for_payload_device(
                target,
                "payload-device-mismatch",
                "matrix-command",
                uuid::Uuid::new_v4(),
            ),
        ] {
            run_device_ingress(delivery, repository.as_ref())
                .await
                .expect("non-oracle rejection is durably receipted");
            assert!(settled.load(Ordering::SeqCst));
        }

        for (event_id, generation, epoch, sequence) in
            [("stale-sequence", 1, 7, 1), ("future-generation", 2, 7, 3)]
        {
            let (delivery, settled) =
                report_delivery_at(target, event_id, generation, epoch, sequence);
            run_device_ingress(delivery, repository.as_ref())
                .await
                .expect("closed non-advanced outcome commits");
            assert!(settled.load(Ordering::SeqCst));
        }

        sqlx::query(
            "UPDATE reconcile_leases SET epoch=8
             WHERE tenant_id=$1::uuid AND target_id=(
               SELECT target_id FROM reconcile_targets
               WHERE tenant_id=$1::uuid AND resource_id=$2)",
        )
        .bind(target.scope.tenant().to_string())
        .bind(target.scope.device().as_uuid().to_string())
        .execute(&owner.pool)
        .await?;
        let (delivery, received_old_fence_settled) =
            report_delivery_at(target, "received-old-fence", 1, 7, 4);
        run_device_ingress(delivery, repository.as_ref())
            .await
            .expect("an exact received command retains report authority after lease advance");
        assert!(received_old_fence_settled.load(Ordering::SeqCst));

        sqlx::query(
            "UPDATE reconcile_leases SET epoch=8
             WHERE tenant_id=$1::uuid AND target_id=(
               SELECT target_id FROM reconcile_targets
               WHERE tenant_id=$1::uuid AND resource_id=$2)",
        )
        .bind(old_fence_unreceived_target.scope.tenant().to_string())
        .bind(
            old_fence_unreceived_target
                .scope
                .device()
                .as_uuid()
                .to_string(),
        )
        .execute(&owner.pool)
        .await?;
        let (delivery, unreceived_old_fence_settled) =
            report_delivery_at(old_fence_unreceived_target, "unreceived-old-fence", 1, 7, 2);
        run_device_ingress(delivery, repository.as_ref())
            .await
            .expect("an old fence without a received command is durably rejected");
        assert!(unreceived_old_fence_settled.load(Ordering::SeqCst));

        sqlx::query(
            "UPDATE reconcile_leases SET epoch=8
             WHERE tenant_id=$1::uuid AND target_id=(
               SELECT target_id FROM reconcile_targets
               WHERE tenant_id=$1::uuid AND resource_id=$2)",
        )
        .bind(ack_old_fence_unreceived_target.scope.tenant().to_string())
        .bind(
            ack_old_fence_unreceived_target
                .scope
                .device()
                .as_uuid()
                .to_string(),
        )
        .execute(&owner.pool)
        .await?;
        let (delivery, ack_unreceived_old_fence_settled) = ack_delivery_at(
            ack_old_fence_unreceived_target,
            "ack-unreceived-old-fence",
            "ack-old-fence-unreceived-command",
            1,
            7,
            1,
        );
        run_device_ingress(delivery, repository.as_ref())
            .await
            .expect("an ACK with an old fence against an unreceived command is durably rejected");
        assert!(ack_unreceived_old_fence_settled.load(Ordering::SeqCst));

        sqlx::query(
            "UPDATE device_certificate_desired_states SET generation=2
             WHERE tenant_id=$1::uuid AND device_id=$2::uuid",
        )
        .bind(target.scope.tenant().to_string())
        .bind(target.scope.device().as_uuid().to_string())
        .execute(&owner.pool)
        .await?;
        let (delivery, stale_generation_settled) =
            with_credential_generation(report_delivery_at(target, "stale-generation", 1, 8, 5), 2);
        run_device_ingress(delivery, repository.as_ref())
            .await
            .expect("stale generation commits without business mutation");
        assert!(stale_generation_settled.load(Ordering::SeqCst));

        let observations: Vec<(String, String)> = sqlx::query_as(
            "SELECT event_id,disposition FROM device_ingress_receipts
             WHERE tenant_id=$1::uuid AND event_id = ANY($2::text[]) ORDER BY event_id",
        )
        .bind(target.scope.tenant().to_string())
        .bind(vec![
            "report-before-ack",
            "matrix-ack",
            "stale-sequence",
            "future-generation",
            "stale-generation",
            "received-old-fence",
            "unreceived-old-fence",
            "ack-unreceived-old-fence",
            "unknown-command",
            "payload-device-mismatch",
        ])
        .fetch_all(&owner.pool)
        .await?;
        assert_eq!(
            observations,
            vec![
                (
                    "ack-unreceived-old-fence".to_owned(),
                    "stale_fence".to_owned()
                ),
                ("future-generation".to_owned(), "rejected".to_owned()),
                ("matrix-ack".to_owned(), "advanced".to_owned()),
                (
                    "payload-device-mismatch".to_owned(),
                    "scope_mismatch".to_owned()
                ),
                ("received-old-fence".to_owned(), "advanced".to_owned()),
                ("report-before-ack".to_owned(), "out_of_order".to_owned()),
                ("stale-generation".to_owned(), "stale_generation".to_owned()),
                ("stale-sequence".to_owned(), "stale_sequence".to_owned()),
                ("unknown-command".to_owned(), "scope_mismatch".to_owned()),
                ("unreceived-old-fence".to_owned(), "stale_fence".to_owned()),
            ]
        );
        let business_state: (String, i64, i64, String, String) = sqlx::query_as(
            "SELECT state,
                (SELECT count(*) FROM device_certificate_reported_states
                 WHERE tenant_id=$1::uuid AND device_id=$2::uuid),
                (SELECT count(*) FROM outbox
                 WHERE tenant_id=$1::uuid AND contract_id='identity.device-ingress-receipted'),
                (SELECT state FROM device_commands
                 WHERE tenant_id=$1::uuid AND command_id='old-fence-unreceived-command'),
                (SELECT state FROM device_commands
                 WHERE tenant_id=$1::uuid AND command_id='ack-old-fence-unreceived-command')
             FROM device_commands WHERE tenant_id=$1::uuid AND command_id='matrix-command'",
        )
        .bind(target.scope.tenant().to_string())
        .bind(target.scope.device().as_uuid().to_string())
        .fetch_one(&owner.pool)
        .await?;
        assert_eq!(
            business_state,
            (
                "applied".to_owned(),
                1,
                10,
                "published".to_owned(),
                "published".to_owned()
            )
        );
        let public_reasons: Vec<String> = sqlx::query_scalar(
            "SELECT convert_from(payload,'UTF8')::jsonb->>'reason' FROM outbox
             WHERE tenant_id=$1::uuid
               AND convert_from(payload,'UTF8')::jsonb->>'ingressEnvelopeId'
                 IN ('unknown-command','payload-device-mismatch')
             ORDER BY convert_from(payload,'UTF8')::jsonb->>'ingressEnvelopeId'",
        )
        .bind(target.scope.tenant().to_string())
        .fetch_all(&owner.pool)
        .await?;
        assert_eq!(public_reasons, vec!["NotAccepted", "NotAccepted"]);

        drop((repository, command_store));
        reader.shutdown().await?;
        writer.shutdown().await?;
        owner.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn durable_ingress_accepts_credential_generation_independent_of_desired_generation()
    -> TestResult {
        let (fixture, owner) = crate::test_pg::connect_pg().await?;
        owner.run_migrations().await?;
        let tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
        let ack_target = new_target_for_tenant(tenant);
        let report_target = new_target_for_tenant(tenant);
        for target in [ack_target, report_target] {
            insert_desired(&owner, target).await?;
        }
        sqlx::query(
            "UPDATE device_certificate_desired_states SET generation=2
             WHERE tenant_id=$1::uuid AND device_id::text=ANY($2::text[])",
        )
        .bind(tenant.to_string())
        .bind(vec![
            ack_target.scope.device().as_uuid().to_string(),
            report_target.scope.device().as_uuid().to_string(),
        ])
        .execute(&owner.pool)
        .await?;
        let command_store = PgDeviceCommandStore::from_unverified_stores_for_test(&owner, &owner);
        for (target, command_id, digest) in [
            (ack_target, "independent-credential-ack-command", 31),
            (report_target, "independent-credential-report-command", 32),
        ] {
            let created =
                created_snapshot_at(&command_store, target, command_id, digest, 2, deadline())
                    .await?;
            transition_snapshot(
                &command_store,
                target,
                command_id,
                &created,
                DeviceCommandMutation::publish(tracker_at(target, 2).current_fence()),
            )
            .await?;
        }
        let writer = crate::test_pg::connect_pg_rss_app_role(&fixture, &owner).await?;
        let reader = crate::test_pg::connect_pg_rss_app_read_role(&fixture, &owner).await?;
        let repository = Arc::new(crate::device_certificate::PgDeviceCertificateRepository::<
            DraftEligibility,
        >::from_unverified_stores_for_test(&reader, &writer));

        let (delivery, settled) = with_credential_generation(
            ack_delivery_at(
                ack_target,
                "independent-credential-ack",
                "independent-credential-ack-command",
                2,
                7,
                1,
            ),
            1,
        );
        run_device_ingress(delivery, repository.as_ref())
            .await
            .expect("credential generation one advances desired generation two ACK");
        assert!(settled.load(Ordering::SeqCst));

        let (delivery, _) = with_credential_generation(
            ack_delivery_at(
                report_target,
                "independent-credential-report-prerequisite-ack",
                "independent-credential-report-command",
                2,
                7,
                1,
            ),
            1,
        );
        run_device_ingress(delivery, repository.as_ref())
            .await
            .expect("independent credential generation advances report prerequisite ACK");
        let (delivery, settled) = with_credential_generation(
            report_delivery_at(report_target, "independent-credential-report", 2, 7, 2),
            1,
        );
        run_device_ingress(delivery, repository.as_ref())
            .await
            .expect("credential generation one advances desired generation two report");
        assert!(settled.load(Ordering::SeqCst));

        let observations: Vec<(String, String)> = sqlx::query_as(
            "SELECT event_id,disposition FROM device_ingress_receipts
             WHERE tenant_id=$1::uuid AND event_id=ANY($2::text[]) ORDER BY event_id",
        )
        .bind(ack_target.scope.tenant().to_string())
        .bind(vec![
            "independent-credential-ack",
            "independent-credential-report",
        ])
        .fetch_all(&owner.pool)
        .await?;
        assert_eq!(
            observations,
            vec![
                (
                    "independent-credential-ack".to_owned(),
                    "advanced".to_owned()
                ),
                (
                    "independent-credential-report".to_owned(),
                    "advanced".to_owned()
                ),
            ]
        );
        let states: Vec<(String, String)> = sqlx::query_as(
            "SELECT command_id,state FROM device_commands
             WHERE tenant_id=$1::uuid AND command_id=ANY($2::text[]) ORDER BY command_id",
        )
        .bind(ack_target.scope.tenant().to_string())
        .bind(vec![
            "independent-credential-ack-command",
            "independent-credential-report-command",
        ])
        .fetch_all(&owner.pool)
        .await?;
        assert_eq!(
            states,
            vec![
                (
                    "independent-credential-ack-command".to_owned(),
                    "received".to_owned()
                ),
                (
                    "independent-credential-report-command".to_owned(),
                    "applied".to_owned()
                ),
            ]
        );
        let reported: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM device_certificate_reported_states
             WHERE tenant_id=$1::uuid AND device_id=$2::uuid",
        )
        .bind(report_target.scope.tenant().to_string())
        .bind(report_target.scope.device().as_uuid().to_string())
        .fetch_one(&owner.pool)
        .await?;
        assert_eq!(reported, 1);

        drop((repository, command_store));
        reader.shutdown().await?;
        writer.shutdown().await?;
        owner.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn ack_old_fence_after_lease_advance_is_stale_fence_while_command_stays_published()
    -> TestResult {
        let (fixture, owner) = crate::test_pg::connect_pg().await?;
        owner.run_migrations().await?;
        let target = new_target();
        insert_desired(&owner, target).await?;
        let command_store = PgDeviceCommandStore::from_unverified_stores_for_test(&owner, &owner);
        let created = created_snapshot(
            &command_store,
            target,
            "ack-old-fence-command",
            51,
            deadline(),
        )
        .await?;
        transition_snapshot(
            &command_store,
            target,
            "ack-old-fence-command",
            &created,
            DeviceCommandMutation::publish(tracker(target).current_fence()),
        )
        .await?;

        sqlx::query(
            "UPDATE reconcile_leases SET epoch=8
             WHERE tenant_id=$1::uuid AND target_id=(
               SELECT target_id FROM reconcile_targets
               WHERE tenant_id=$1::uuid AND resource_id=$2)",
        )
        .bind(target.scope.tenant().to_string())
        .bind(target.scope.device().as_uuid().to_string())
        .execute(&owner.pool)
        .await?;

        let writer = crate::test_pg::connect_pg_rss_app_role(&fixture, &owner).await?;
        let reader = crate::test_pg::connect_pg_rss_app_read_role(&fixture, &owner).await?;
        let repository = Arc::new(crate::device_certificate::PgDeviceCertificateRepository::<
            DraftEligibility,
        >::from_unverified_stores_for_test(&reader, &writer));

        let (delivery, settled) =
            ack_delivery_at(target, "ack-old-fence", "ack-old-fence-command", 1, 7, 1);
        run_device_ingress(delivery, repository.as_ref())
            .await
            .expect("ACK with an old fence must commit a durable stale_fence receipt");
        assert!(settled.load(Ordering::SeqCst));

        let disposition: String = sqlx::query_scalar(
            "SELECT disposition FROM device_ingress_receipts
             WHERE tenant_id=$1::uuid AND event_id='ack-old-fence'",
        )
        .bind(target.scope.tenant().to_string())
        .fetch_one(&owner.pool)
        .await?;
        assert_eq!(disposition, "stale_fence");

        let command_state: String = sqlx::query_scalar(
            "SELECT state FROM device_commands
             WHERE tenant_id=$1::uuid AND command_id='ack-old-fence-command'",
        )
        .bind(target.scope.tenant().to_string())
        .fetch_one(&owner.pool)
        .await?;
        assert_eq!(command_state, "published");

        drop((repository, command_store));
        reader.shutdown().await?;
        writer.shutdown().await?;
        owner.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn raw_invalid_credential_and_null_scope_proofs_are_rejected_without_mutation()
    -> TestResult {
        let (fixture, owner) = crate::test_pg::connect_pg().await?;
        owner.run_migrations().await?;
        let tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
        let ack_target = new_target_for_tenant(tenant);
        let report_target = new_target_for_tenant(tenant);
        for target in [ack_target, report_target] {
            insert_desired(&owner, target).await?;
        }
        let command_store = PgDeviceCommandStore::from_unverified_stores_for_test(&owner, &owner);
        for (target, command_id, digest) in [
            (ack_target, "null-scope-ack-command", 41),
            (report_target, "null-scope-report-command", 42),
        ] {
            let created =
                created_snapshot(&command_store, target, command_id, digest, deadline()).await?;
            transition_snapshot(
                &command_store,
                target,
                command_id,
                &created,
                DeviceCommandMutation::publish(tracker(target).current_fence()),
            )
            .await?;
        }
        let writer = crate::test_pg::connect_pg_rss_app_role(&fixture, &owner).await?;
        let reader = crate::test_pg::connect_pg_rss_app_read_role(&fixture, &owner).await?;
        let repository = Arc::new(crate::device_certificate::PgDeviceCertificateRepository::<
            DraftEligibility,
        >::from_unverified_stores_for_test(&reader, &writer));
        let (delivery, _) = ack_delivery(
            report_target,
            "null-scope-prerequisite-ack",
            "null-scope-report-command",
        );
        run_device_ingress(delivery, repository.as_ref())
            .await
            .expect("report prerequisite ACK");

        for delivery in [
            ack_delivery(ack_target, "null-scope-ack", "null-scope-ack-command").0,
            report_delivery(report_target, "null-scope-report").0,
        ] {
            run_device_ingress(delivery, repository.as_ref())
                .await
                .expect("valid ingress fact commits before NULL replay");
        }

        let ack_fingerprint: Vec<u8> = sqlx::query_scalar(
            "SELECT fingerprint FROM device_ingress_receipts
             WHERE tenant_id=$1::uuid AND event_id='null-scope-ack'",
        )
        .bind(tenant.to_string())
        .fetch_one(&owner.pool)
        .await?;
        let report_fingerprint: Vec<u8> = sqlx::query_scalar(
            "SELECT fingerprint FROM device_ingress_receipts
             WHERE tenant_id=$1::uuid AND event_id='null-scope-report'",
        )
        .bind(tenant.to_string())
        .fetch_one(&owner.pool)
        .await?;
        let before_counts: (i64, i64, i64) = sqlx::query_as(
            "SELECT
               (SELECT count(*) FROM device_ingress_receipts WHERE tenant_id=$1::uuid),
               (SELECT count(*) FROM device_certificate_reported_states WHERE tenant_id=$1::uuid),
               (SELECT count(*) FROM outbox WHERE tenant_id=$1::uuid)",
        )
        .bind(tenant.to_string())
        .fetch_one(&owner.pool)
        .await?;

        let invalid_authorities = [
            ("zero credential generation", Some(0_i64), Some(true)),
            ("negative credential generation", Some(-1_i64), Some(true)),
            ("missing credential generation", None, Some(true)),
            ("NULL scope proof", Some(1_i64), None),
        ];
        for (case, credential_generation, scope_matches) in invalid_authorities {
            let mut ack_tx = writer.pool.begin().await?;
            crate::cotx::set_local_tenant(&mut ack_tx, tenant).await?;
            let ack_error = sqlx::query_scalar::<_, String>(
                "SELECT disposition FROM public.rss_commit_device_command_ack_ingress(
                 $1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
            )
            .bind(tenant.to_string())
            .bind(ack_target.scope.device().as_uuid().to_string())
            .bind("null-scope-ack")
            .bind("null-scope-ack-command")
            .bind(1_i64)
            .bind(7_i64)
            .bind(1_i64)
            .bind(ack_fingerprint.as_slice())
            .bind("ack_received")
            .bind(credential_generation)
            .bind(scope_matches)
            .fetch_one(&mut *ack_tx)
            .await
            .expect_err(case);
            assert_eq!(
                ack_error
                    .as_database_error()
                    .and_then(sqlx::error::DatabaseError::code)
                    .as_deref(),
                Some("42501"),
                "ACK must fail closed for {case}"
            );
            drop(ack_tx);

            let mut report_tx = writer.pool.begin().await?;
            crate::cotx::set_local_tenant(&mut report_tx, tenant).await?;
            let report_error = sqlx::query_scalar::<_, String>(
                "SELECT disposition FROM public.rss_commit_device_certificate_report_ingress(
                 $1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
            )
            .bind(tenant.to_string())
            .bind(report_target.scope.device().as_uuid().to_string())
            .bind("null-scope-report")
            .bind(1_i64)
            .bind(7_i64)
            .bind(2_i64)
            .bind(report_fingerprint.as_slice())
            .bind(vec![1_u8; 32])
            .bind(vec![2_u8; 32])
            .bind(Option::<i64>::None)
            .bind(Option::<i64>::None)
            .bind(credential_generation)
            .bind(scope_matches)
            .fetch_one(&mut *report_tx)
            .await
            .expect_err(case);
            assert_eq!(
                report_error
                    .as_database_error()
                    .and_then(sqlx::error::DatabaseError::code)
                    .as_deref(),
                Some("42501"),
                "report must fail closed for {case}"
            );
            drop(report_tx);
        }

        let states: Vec<(String, String)> = sqlx::query_as(
            "SELECT command_id,state FROM device_commands
             WHERE tenant_id=$1::uuid AND command_id=ANY($2::text[]) ORDER BY command_id",
        )
        .bind(ack_target.scope.tenant().to_string())
        .bind(vec!["null-scope-ack-command", "null-scope-report-command"])
        .fetch_all(&owner.pool)
        .await?;
        assert_eq!(
            states,
            vec![
                ("null-scope-ack-command".to_owned(), "received".to_owned()),
                ("null-scope-report-command".to_owned(), "applied".to_owned()),
            ]
        );
        let reported: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM device_certificate_reported_states
             WHERE tenant_id=$1::uuid AND device_id=$2::uuid",
        )
        .bind(report_target.scope.tenant().to_string())
        .bind(report_target.scope.device().as_uuid().to_string())
        .fetch_one(&owner.pool)
        .await?;
        assert_eq!(reported, 1);
        let after_counts: (i64, i64, i64) = sqlx::query_as(
            "SELECT
               (SELECT count(*) FROM device_ingress_receipts WHERE tenant_id=$1::uuid),
               (SELECT count(*) FROM device_certificate_reported_states WHERE tenant_id=$1::uuid),
               (SELECT count(*) FROM outbox WHERE tenant_id=$1::uuid)",
        )
        .bind(tenant.to_string())
        .fetch_one(&owner.pool)
        .await?;
        assert_eq!(after_counts, before_counts);

        drop((repository, command_store));
        reader.shutdown().await?;
        writer.shutdown().await?;
        owner.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn rejected_high_sequences_do_not_pollute_ack_or_report_high_water_and_plan_is_indexed()
    -> TestResult {
        let (fixture, owner) = crate::test_pg::connect_pg().await?;
        owner.run_migrations().await?;
        let tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
        let ack_target = new_target_for_tenant(tenant);
        let report_target = new_target_for_tenant(tenant);
        for target in [ack_target, report_target] {
            insert_desired(&owner, target).await?;
        }
        let command_store = PgDeviceCommandStore::from_unverified_stores_for_test(&owner, &owner);
        for (target, command_id, digest) in [
            (ack_target, "high-water-ack-command", 61),
            (report_target, "high-water-report-command", 62),
        ] {
            let created =
                created_snapshot(&command_store, target, command_id, digest, deadline()).await?;
            transition_snapshot(
                &command_store,
                target,
                command_id,
                &created,
                DeviceCommandMutation::publish(tracker(target).current_fence()),
            )
            .await?;
        }
        let writer = crate::test_pg::connect_pg_rss_app_role(&fixture, &owner).await?;
        let reader = crate::test_pg::connect_pg_rss_app_read_role(&fixture, &owner).await?;
        let repository = Arc::new(crate::device_certificate::PgDeviceCertificateRepository::<
            DraftEligibility,
        >::from_unverified_stores_for_test(&reader, &writer));

        for (delivery, expected) in [
            (
                ack_delivery_at(
                    ack_target,
                    "high-rejected-ack",
                    "unknown-high-water-command",
                    1,
                    7,
                    100,
                ),
                "scope_mismatch",
            ),
            (
                ack_delivery_at(
                    ack_target,
                    "low-valid-ack",
                    "high-water-ack-command",
                    1,
                    7,
                    1,
                ),
                "advanced",
            ),
            (
                report_delivery_at(report_target, "high-rejected-report", 1, 7, 100),
                "out_of_order",
            ),
            (
                ack_delivery_at(
                    report_target,
                    "report-prerequisite-ack",
                    "high-water-report-command",
                    1,
                    7,
                    1,
                ),
                "advanced",
            ),
            (
                report_delivery_at(report_target, "low-valid-report", 1, 7, 2),
                "advanced",
            ),
        ] {
            let (delivery, settled) = delivery;
            let receipt = run_device_ingress(delivery, repository.as_ref())
                .await
                .expect("ingress outcome commits");
            assert_eq!(receipt.disposition().as_label(), expected);
            assert!(settled.load(Ordering::SeqCst));
        }

        let state: (String, String, i64, i64) = sqlx::query_as(
            "SELECT
                (SELECT state FROM device_commands WHERE tenant_id=$1::uuid AND command_id='high-water-ack-command'),
                (SELECT state FROM device_commands WHERE tenant_id=$1::uuid AND command_id='high-water-report-command'),
                (SELECT count(*) FROM device_certificate_reported_states WHERE tenant_id=$1::uuid AND device_id=$2::uuid),
                (SELECT count(*) FROM device_ingress_receipts WHERE tenant_id=$1::uuid AND event_id=ANY($3::text[]))",
        )
        .bind(tenant.to_string())
        .bind(report_target.scope.device().as_uuid().to_string())
        .bind(vec![
            "high-rejected-ack",
            "low-valid-ack",
            "high-rejected-report",
            "report-prerequisite-ack",
            "low-valid-report",
        ])
        .fetch_one(&owner.pool)
        .await?;
        assert_eq!(state, ("received".to_owned(), "applied".to_owned(), 1, 5));

        let mut plan_tx = owner.pool.begin().await?;
        sqlx::query("SET LOCAL enable_seqscan=off")
            .execute(&mut *plan_tx)
            .await?;
        let plan = sqlx::query_scalar::<_, String>(
            "EXPLAIN (COSTS OFF)
             SELECT max(device_sequence) FROM device_ingress_receipts
             WHERE tenant_id=$1::uuid AND device_id=$2::uuid
               AND generation=$3 AND fence_epoch=$4
               AND disposition IN ('advanced','device_rejected')",
        )
        .bind(tenant.to_string())
        .bind(report_target.scope.device().as_uuid().to_string())
        .bind(1_i64)
        .bind(7_i64)
        .fetch_all(&mut *plan_tx)
        .await?
        .join("\n");
        assert!(
            plan.contains("device_ingress_receipts_high_water_idx"),
            "high-water plan must consume the supporting partial index: {plan}"
        );
        plan_tx.rollback().await?;

        drop((repository, command_store));
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
        .bind(target.scope.tenant().to_string())
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
             fence_epoch, artifact_eligibility, intent_digest, deadline, state, version) VALUES \
             ($1::uuid, 'unscoped-command', $2::uuid, 1, 7, 'draft', $3, \
              TIMESTAMPTZ '2100-01-01 00:00:00+00', 'queued', 1)",
        )
        .bind(target.scope.tenant().to_string())
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
