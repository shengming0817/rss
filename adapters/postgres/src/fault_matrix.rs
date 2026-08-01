//! N-028 consistency fault matrix typed harness.
//!
//! This module is only compiled behind `fault-matrix-test-support`. It keeps the fault-matrix
//! journey out of `sqlx` by crate graph while still letting the postgres adapter own the tiny
//! amount of privileged setup and typed observation needed by the real-backend lane.
//!
//! # INVARIANT: CONSISTENCY-FAULT-MATRIX-SEAM-01 { level = "Hard", exec = "native-compile", source = "code", native = "feature-gated module exposes closed enums/newtypes while keeping raw PgPool and SQL private to the postgres adapter" }
//!
//! External fault-matrix tests cannot name `PgPool` or raw SQL through this module. The public
//! surface is closed enums/newtypes and runtime-seam methods; all pool access remains inside the
//! postgres adapter.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, bail};
use consistency::{
    ConsumerGroup, ConvergeAction, Disposition, EventTopic, IdemKey, InboxReceiptContext,
    InboxStore, LeaseOutcome, LeaseToken, Lsn, OutboxRelay, PartitionSerialDelivery,
    ProjectionApplyError, ProjectionApplyErrorKind, ProjectionApplyOutcome, ProjectionEvent,
    ProjectionEventMetadata, ProjectionEventRecord, Projector, SagaAttempt, SagaDefinitionIdentity,
    SagaEffectPhase, SagaIdempotencyKey, SagaInstanceRef, SagaInstanceStatus, SagaOperatorReason,
    SagaReceiptFormatVersion, SagaReceiptScope, SeenState, SerialInOrder,
};
use diport::{
    Checkpoint, CheckpointId, CheckpointOwner, CheckpointStoreError, CheckpointVersion,
    DeadLetterSource, DynKeyProvider, DynPublisher, EncryptOutput, KeyName, KeyProvider,
    KeyProviderError, KeyRef, KeyVersion, ManagedResource, OwnerCheckpointStore, PublishRequest,
    Publisher, PublisherError, RedactedBytes, SagaContractId, SagaDurableMutation,
    SagaDurableMutationOutcome, SagaDurableStore, SagaForwardCompletion, SagaForwardProgress,
    SagaStepCompletion, SagaWorkerIdentity, SaveOutcome,
};
use eventexec::command::{CommandAliasKey, CommandIdempotencyKeyring};
use eventexec::reconcile::{
    ApplyDeviceCertificateReconcileCommand, ReconcileAttempt, ReconcileScheduleStore,
    ReviewedFencedCommand, ScheduleActionOutcome, ScheduleAttemptOutcome,
};
use eventexec::{ProjectionHarness, ProjectionStop, RelayBudget, TenantAuthority};
use identity::ports::{FaultMatrixSessionCreatedPayload, SESSION_CREATED_FACT};
use primitives::{Mac, MacAlgorithm, MacKey, MacVerifier};
use secure::Plaintext;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode as SqlxPgSslMode};
use sqlx::{PgPool, Row};

use crate::cotx::eventing::SagaFaultObservationRow;
use crate::cotx::{FaultMatrixReadLane, FaultMatrixWriteLane, TenantDb, infra_tenant_scope};
use crate::{
    DlxPayloadProtector, PgConfig, PgPassword, PgRuntimeDeps, PgSslMode, PgTenantReadConfig,
};

const RSS_APP_ROLE: &str = "rss_app";
const RSS_APP_READ_ROLE: &str = "rss_app_read";
const SCHEMA_HASH: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
type FaultMatrixCertificateCommand = ApplyDeviceCertificateReconcileCommand;

async fn review_certificate_reconcile_commands(
    commands: [FaultMatrixCertificateCommand; 2],
    attempt: &ReconcileAttempt,
) -> FaultMatrixResult<[ReviewedFencedCommand; 2]> {
    let keyring = Arc::new(CommandIdempotencyKeyring::new(
        CommandAliasKey::new("fault-matrix-current", vec![0x42; 32])?,
        Vec::new(),
    )?);
    let [first, retry] = commands;
    Ok([
        crate::reconcile_test_driver::drive_reviewed_device_command(
            attempt,
            first,
            Arc::clone(&keyring),
        )
        .await?,
        crate::reconcile_test_driver::drive_reviewed_device_command(attempt, retry, keyring)
            .await?,
    ])
}

/// Error returned by the fault-matrix harness.
pub type FaultMatrixResult<T> = anyhow::Result<T>;

/// Closed generated `identity.session-created` fixture accepted by the real-backend matrix.
pub struct FaultMatrixSessionCreatedInput {
    tenant: vocab::TenantId,
    session_id: uuid::Uuid,
    payload: FaultMatrixSessionCreatedPayload,
    idem_key: IdemKey,
}

impl std::fmt::Debug for FaultMatrixSessionCreatedInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FaultMatrixSessionCreatedInput")
            .field("tenant", &self.tenant)
            .field("session_id", &"<redacted>")
            .field("event_id", &self.idem_key.as_str())
            .finish()
    }
}

impl FaultMatrixSessionCreatedInput {
    /// Build the closed fixture from the exact generated payload type.
    ///
    /// Tenant and session identity are derived from the payload; callers cannot pair a typed
    /// payload with parallel identity arguments.
    pub fn new(
        payload: FaultMatrixSessionCreatedPayload,
        idem_key: IdemKey,
    ) -> FaultMatrixResult<Self> {
        let tenant = vocab::TenantId::parse(&payload.tenant_id)?;
        let session_id = ids::SessionId::parse(&payload.session_id)?.as_uuid();
        Ok(Self {
            tenant,
            session_id,
            payload,
            idem_key,
        })
    }

    pub fn event_id(&self) -> &str {
        self.idem_key.as_str()
    }
}

/// One production relay attempt observed through the durable session-created row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FaultMatrixSessionCreatedRelayObservation {
    event_id: String,
    disposition: Disposition,
    status: FaultMatrixOutboxStatus,
}

impl FaultMatrixSessionCreatedRelayObservation {
    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    pub fn disposition(&self) -> Disposition {
        self.disposition
    }

    pub fn status(&self) -> FaultMatrixOutboxStatus {
        self.status
    }
}

/// Closed result of dispatching one real broker delivery through the Postgres ConsumerTx.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultMatrixConsumerDelivery {
    Committed,
    Duplicate,
}

/// Durable duplicate-effect evidence for one exact session-created delivery identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FaultMatrixSessionCreatedEffectObservation {
    business_mutations: u64,
    inbox_done_rows: u64,
}

impl FaultMatrixSessionCreatedEffectObservation {
    pub fn business_mutations(&self) -> u64 {
        self.business_mutations
    }

    pub fn inbox_done_rows(&self) -> u64 {
        self.inbox_done_rows
    }
}

/// Closed production settlement outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultMatrixSettlementOutcome {
    Settled,
    Expired,
    LostLease,
}

/// Stale contender settlement evidence without exposing lease material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FaultMatrixStaleSettlementObservation {
    stale: FaultMatrixSettlementOutcome,
    current: FaultMatrixSettlementOutcome,
    intermediate_no_terminal: bool,
    final_status: FaultMatrixOutboxStatus,
}

impl FaultMatrixStaleSettlementObservation {
    pub fn stale(&self) -> FaultMatrixSettlementOutcome {
        self.stale
    }

    pub fn current(&self) -> FaultMatrixSettlementOutcome {
        self.current
    }

    pub fn intermediate_no_terminal(&self) -> bool {
        self.intermediate_no_terminal
    }

    pub fn final_status(&self) -> FaultMatrixOutboxStatus {
        self.final_status
    }
}

/// Exact-deadline expiry evidence without exposing the persisted deadline or token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FaultMatrixExpiredSettlementObservation {
    outcome: FaultMatrixSettlementOutcome,
    persisted_deadline_evaluated: bool,
    still_publishing: bool,
    no_terminal: bool,
}

impl FaultMatrixExpiredSettlementObservation {
    pub fn outcome(&self) -> FaultMatrixSettlementOutcome {
        self.outcome
    }

    pub fn persisted_deadline_evaluated(&self) -> bool {
        self.persisted_deadline_evaluated
    }

    pub fn still_publishing(&self) -> bool {
        self.still_publishing
    }

    pub fn no_terminal(&self) -> bool {
        self.no_terminal
    }
}

/// Connection settings for the postgres fault-matrix harness.
#[derive(Clone)]
pub struct PgFaultMatrixConfig {
    host: String,
    port: u16,
    database: String,
    owner_username: String,
    owner_password: String,
}

impl PgFaultMatrixConfig {
    /// Build from test fixture connection parts.
    pub fn new(
        host: impl Into<String>,
        port: u16,
        database: impl Into<String>,
        owner_username: impl Into<String>,
        owner_password: impl Into<String>,
    ) -> Self {
        Self {
            host: host.into(),
            port,
            database: database.into(),
            owner_username: owner_username.into(),
            owner_password: owner_password.into(),
        }
    }
}

/// Opaque credentials generated for one fault-matrix harness and provisioned by its journey.
///
/// Fields stay private so callers cannot replace the generated values. Named accessors keep the
/// intended serving/reader association explicit; if a caller pairs them incorrectly during
/// provisioning, the subsequent role-authenticated setup fails. The journey must provision these
/// exact pairs before moving the value into [`PgFaultMatrixHarness::setup`].
pub struct PgFaultMatrixLoginCredentials {
    serving_password: String,
    reader_password: String,
}

impl PgFaultMatrixLoginCredentials {
    /// Generate fresh credentials for one fault-matrix run.
    pub fn generate() -> Self {
        Self {
            serving_password: format!("rss_app_{}", uuid::Uuid::new_v4().simple()),
            reader_password: format!("rss_app_read_{}", uuid::Uuid::new_v4().simple()),
        }
    }

    pub fn serving_role(&self) -> &'static str {
        RSS_APP_ROLE
    }

    pub fn serving_password(&self) -> &str {
        &self.serving_password
    }

    pub fn reader_role(&self) -> &'static str {
        RSS_APP_READ_ROLE
    }

    pub fn reader_password(&self) -> &str {
        &self.reader_password
    }
}

/// Closed outbox status observer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultMatrixOutboxStatus {
    Pending,
    Published,
    Dlx,
}

impl FaultMatrixOutboxStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Published => "published",
            Self::Dlx => "dlx",
        }
    }

    fn parse(raw: &str) -> FaultMatrixResult<Self> {
        match raw {
            "pending" => Ok(Self::Pending),
            "published" => Ok(Self::Published),
            "dlx" => Ok(Self::Dlx),
            _ => bail!("unknown fault-matrix outbox status `{raw}`"),
        }
    }
}

/// Typed durable retry observation for one exact outbox event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FaultMatrixOutboxRetryObservation {
    status: FaultMatrixOutboxStatus,
    retry_count: u32,
    retry_after_scheduled: bool,
    lease_cleared: bool,
}

impl FaultMatrixOutboxRetryObservation {
    fn try_from_row(row: Option<(String, i32, bool, bool)>) -> FaultMatrixResult<Self> {
        let (status, retry_count, retry_after_scheduled, lease_cleared) =
            row.ok_or_else(|| anyhow!("outbox retry row missing for fault-matrix event"))?;
        Ok(Self {
            status: FaultMatrixOutboxStatus::parse(&status)?,
            retry_count: u32::try_from(retry_count)
                .map_err(|_| anyhow!("negative fault-matrix outbox retry_count `{retry_count}`"))?,
            retry_after_scheduled,
            lease_cleared,
        })
    }

    /// Return the closed durable outbox status.
    pub fn status(&self) -> FaultMatrixOutboxStatus {
        self.status
    }

    /// Return the validated non-negative durable retry count.
    pub fn retry_count(&self) -> u32 {
        self.retry_count
    }

    /// Whether `retry_after` is present and strictly later than the row's settlement update.
    pub fn retry_after_scheduled(&self) -> bool {
        self.retry_after_scheduled
    }

    /// Whether both lease token and lease deadline were cleared by requeue settlement.
    pub fn lease_cleared(&self) -> bool {
        self.lease_cleared
    }
}

/// Closed dead-letter source observer for the fault matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultMatrixDeadLetterSource {
    OutboxRelay,
}

impl FaultMatrixDeadLetterSource {
    fn parse(raw: &str) -> FaultMatrixResult<Self> {
        match DeadLetterSource::parse(raw) {
            Some(DeadLetterSource::OutboxRelay) => Ok(Self::OutboxRelay),
            Some(other) => bail!("unexpected fault-matrix dead-letter source {other:?}"),
            None => bail!("unknown fault-matrix dead-letter source `{raw}`"),
        }
    }
}

/// Closed dead-letter summary observer for the fault matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultMatrixDeadLetterSummary {
    OutboxRelayPublishFailed,
}

impl FaultMatrixDeadLetterSummary {
    fn parse(raw: &str) -> FaultMatrixResult<Self> {
        match raw {
            "outbox relay publish failed" => Ok(Self::OutboxRelayPublishFailed),
            _ => bail!("unexpected fault-matrix dead-letter summary `{raw}`"),
        }
    }
}

/// Closed dead-letter payload encoding observer for the fault matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultMatrixDeadLetterEncoding {
    KeyProviderV3,
}

impl FaultMatrixDeadLetterEncoding {
    fn parse(raw: &str) -> FaultMatrixResult<Self> {
        match raw {
            crate::dead_letter_payload::DLX_REPLAY_CAPSULE_ENCODING => Ok(Self::KeyProviderV3),
            _ => bail!("unexpected fault-matrix dead-letter encoding `{raw}`"),
        }
    }
}

/// Typed dead-letter observation for outbox relay DLX assertions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FaultMatrixDeadLetterObservation {
    source: FaultMatrixDeadLetterSource,
    summary: FaultMatrixDeadLetterSummary,
    encoding: FaultMatrixDeadLetterEncoding,
    payload_len: i64,
}

impl FaultMatrixDeadLetterObservation {
    pub fn source(&self) -> FaultMatrixDeadLetterSource {
        self.source
    }

    pub fn summary(&self) -> FaultMatrixDeadLetterSummary {
        self.summary
    }

    pub fn encoding(&self) -> FaultMatrixDeadLetterEncoding {
        self.encoding
    }

    pub fn payload_len(&self) -> i64 {
        self.payload_len
    }
}

/// Result of expiring one exact Saga lease through the fault-only control plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultMatrixSagaLeaseExpiry {
    /// The exact tenant, Saga, token, and epoch still identified the durable lease.
    Expired,
    /// The lease had already been released or replaced.
    Lost,
}

fn lease_expiry_outcome(rows_affected: u64) -> FaultMatrixResult<FaultMatrixSagaLeaseExpiry> {
    match rows_affected {
        1 => Ok(FaultMatrixSagaLeaseExpiry::Expired),
        0 => Ok(FaultMatrixSagaLeaseExpiry::Lost),
        count => bail!("Saga lease expiry changed unexpected row count `{count}`"),
    }
}

/// Closed outcome of injecting the fixed competing protected forward completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultMatrixSagaCompletionInjection {
    /// No active lease with an exact matching forward intent exists.
    MissingIntent,
    /// The generated definition or step does not match the pinned durable identity.
    IdentityConflict,
    /// The production protected receipt transaction committed the completion.
    Applied,
    /// The same fixed competing completion was already committed.
    ExactDuplicate,
    /// A different protected completion already owns the receipt scope.
    Conflict,
    /// The active lease changed after the control plane observed it.
    LeaseLost,
}

fn completion_injection_outcome(
    outcome: SagaDurableMutationOutcome,
) -> FaultMatrixResult<FaultMatrixSagaCompletionInjection> {
    match outcome {
        SagaDurableMutationOutcome::Applied => Ok(FaultMatrixSagaCompletionInjection::Applied),
        SagaDurableMutationOutcome::IdempotentDuplicate => {
            Ok(FaultMatrixSagaCompletionInjection::ExactDuplicate)
        }
        SagaDurableMutationOutcome::Conflict => Ok(FaultMatrixSagaCompletionInjection::Conflict),
        SagaDurableMutationOutcome::LeaseLost => Ok(FaultMatrixSagaCompletionInjection::LeaseLost),
        _ => bail!("unsupported Saga durable mutation outcome"),
    }
}

/// Redacted counts of closed Saga journal transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FaultMatrixSagaJournalObservation {
    forward_intents: u64,
    forward_completions: u64,
    forward_not_applied: u64,
    compensation_intents: u64,
    compensation_completions: u64,
    compensation_not_applied: u64,
    compensation_failures: u64,
}

impl FaultMatrixSagaJournalObservation {
    pub fn forward_intents(&self) -> u64 {
        self.forward_intents
    }

    pub fn forward_completions(&self) -> u64 {
        self.forward_completions
    }

    pub fn forward_not_applied(&self) -> u64 {
        self.forward_not_applied
    }

    pub fn compensation_intents(&self) -> u64 {
        self.compensation_intents
    }

    pub fn compensation_completions(&self) -> u64 {
        self.compensation_completions
    }

    pub fn compensation_not_applied(&self) -> u64 {
        self.compensation_not_applied
    }

    pub fn compensation_failures(&self) -> u64 {
        self.compensation_failures
    }
}

/// Redacted durable Saga observation for the real-backend fault journeys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FaultMatrixSagaObservation {
    status: SagaInstanceStatus,
    operator_reason: Option<SagaOperatorReason>,
    epoch: u64,
    active_lease: bool,
    journal: FaultMatrixSagaJournalObservation,
    receipts: u64,
}

impl FaultMatrixSagaObservation {
    fn try_from_row(row: SagaFaultObservationRow) -> FaultMatrixResult<Self> {
        let status = SagaInstanceStatus::parse(&row.status)
            .ok_or_else(|| anyhow!("invalid fault-matrix Saga status `{}`", row.status))?;
        let operator_reason = row
            .operator_reason
            .as_deref()
            .map(|raw| {
                SagaOperatorReason::parse(raw)
                    .ok_or_else(|| anyhow!("invalid fault-matrix Saga operator reason `{raw}`"))
            })
            .transpose()?;
        if (status == SagaInstanceStatus::OperatorRequired) != operator_reason.is_some() {
            bail!("fault-matrix Saga status/operator reason invariant violated");
        }
        Ok(Self {
            status,
            operator_reason,
            epoch: non_negative_count(row.epoch, "Saga epoch")?,
            active_lease: row.active_lease,
            journal: FaultMatrixSagaJournalObservation {
                forward_intents: non_negative_count(row.forward_intents, "forward intents")?,
                forward_completions: non_negative_count(
                    row.forward_completions,
                    "forward completions",
                )?,
                forward_not_applied: non_negative_count(
                    row.forward_not_applied,
                    "forward not-applied",
                )?,
                compensation_intents: non_negative_count(
                    row.compensation_intents,
                    "compensation intents",
                )?,
                compensation_completions: non_negative_count(
                    row.compensation_completions,
                    "compensation completions",
                )?,
                compensation_not_applied: non_negative_count(
                    row.compensation_not_applied,
                    "compensation not-applied",
                )?,
                compensation_failures: non_negative_count(
                    row.compensation_failures,
                    "compensation failures",
                )?,
            },
            receipts: non_negative_count(row.receipts, "Saga receipts")?,
        })
    }

    pub fn status(&self) -> SagaInstanceStatus {
        self.status
    }

    pub fn operator_reason(&self) -> Option<SagaOperatorReason> {
        self.operator_reason
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn active_lease(&self) -> bool {
        self.active_lease
    }

    pub fn journal(&self) -> FaultMatrixSagaJournalObservation {
        self.journal
    }

    pub fn receipts(&self) -> u64 {
        self.receipts
    }
}

/// Minimal fault-only control plane over the production durable Saga schema.
///
/// The production [`diport::SagaDurableStore`] remains responsible for claims, protected
/// completions, and every normal mutation. This type exposes only the impossible-to-express lease
/// expiry, fixed competing-completion injection, and redacted observation; its pool and SQL remain
/// private to the adapter.
pub struct PgSagaFaultControl {
    read_db: TenantDb<FaultMatrixReadLane>,
    write_db: TenantDb<FaultMatrixWriteLane>,
}

impl std::fmt::Debug for PgSagaFaultControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgSagaFaultControl").finish_non_exhaustive()
    }
}

impl PgSagaFaultControl {
    pub(crate) fn new(owner_pool: &PgPool) -> Self {
        Self {
            read_db: TenantDb::<FaultMatrixReadLane>::new_fault_control(owner_pool),
            write_db: TenantDb::<FaultMatrixWriteLane>::new_fault_control(owner_pool),
        }
    }

    /// Expire the active lease at the expected epoch without exposing its token.
    pub async fn expire_active_lease(
        &self,
        instance: SagaInstanceRef,
        expected_epoch: u64,
    ) -> FaultMatrixResult<FaultMatrixSagaLeaseExpiry> {
        let expected_epoch =
            i64::try_from(expected_epoch).map_err(|_| anyhow!("Saga lease epoch overflow"))?;
        let affected = self
            .write_db
            .saga_fault_write(
                infra_tenant_scope(instance.tenant()),
                move |mut tx| {
                    Box::pin(async move {
                        tx.saga_fault_expire_active_lease(instance, expected_epoch)
                            .await
                    })
                },
                std::convert::identity,
            )
            .await?;
        lease_expiry_outcome(affected)
    }

    /// Commit a fixed competing receipt through the production protected completion path.
    ///
    /// The active lease is reconstructed entirely inside the adapter from the exact tenant-scoped
    /// row. The supplied generated bindings must match the pinned definition and an existing
    /// forward intent; callers cannot provide lease authority, sequence, attempt, effect key, or
    /// receipt plaintext.
    pub async fn inject_competing_forward_completion(
        &self,
        store: &crate::PgSagaDurableStore,
        instance: SagaInstanceRef,
        definition_binding: vocab::SagaContractBinding,
        step: vocab::SagaStepBinding,
    ) -> FaultMatrixResult<FaultMatrixSagaCompletionInjection> {
        let step_name = step.name().to_owned();
        let row = self
            .write_db
            .saga_fault_write(
                infra_tenant_scope(instance.tenant()),
                move |mut tx| {
                    Box::pin(async move {
                        tx.saga_fault_competing_completion(instance, &step_name)
                            .await
                    })
                },
                std::convert::identity,
            )
            .await?;
        let Some(row) = row else {
            return Ok(FaultMatrixSagaCompletionInjection::MissingIntent);
        };

        let definition = SagaDefinitionIdentity::from_binding(definition_binding);
        if row.contract_id != definition.contract_id()
            || row.definition_version != definition.version()
            || row.definition_schema_digest != definition.schema_digest()
            || row.action_registry_generation != definition.action_registry_generation()
            || step.contract_id() != definition.contract_id()
            || step.version() != definition.version()
            || step.schema_hash() != definition.schema_digest()
        {
            return Ok(FaultMatrixSagaCompletionInjection::IdentityConflict);
        }
        let effect_key =
            SagaIdempotencyKey::derive(instance, &definition, step, SagaEffectPhase::Forward);
        if row.effect_key.as_slice() != effect_key.as_bytes() {
            return Ok(FaultMatrixSagaCompletionInjection::IdentityConflict);
        }
        let epoch = u64::try_from(row.epoch).map_err(|_| anyhow!("invalid Saga lease epoch"))?;
        let lease = consistency::SagaLease::new(
            instance,
            row.holder_id,
            uuid::Uuid::parse_str(&row.lease_token)?,
            epoch,
        )?;
        let worker = SagaWorkerIdentity::new(row.owner, SagaContractId::parse(&row.contract_id)?)?;
        let scope = SagaReceiptScope::new(instance, worker, definition, step, effect_key)?;
        let attempt = SagaAttempt::new(
            u32::try_from(row.attempt).map_err(|_| anyhow!("invalid Saga intent attempt"))?,
        )?;
        let completed_seq = u64::try_from(row.intent_seq)
            .map_err(|_| anyhow!("invalid Saga intent sequence"))?
            .checked_add(1)
            .ok_or_else(|| anyhow!("Saga completion sequence overflow"))?;
        let completion = SagaForwardCompletion::new(
            SagaStepCompletion::new(
                scope,
                attempt,
                SagaReceiptFormatVersion::V1,
                Plaintext::new(br#"{"faultMatrixCompetingReceipt":"postgres"}"#.to_vec()),
                completed_seq,
            ),
            SagaForwardProgress::Continue,
        );
        completion_injection_outcome(
            store
                .mutate(&lease, SagaDurableMutation::ForwardCompleted(completion))
                .await?,
        )
    }

    /// Observe only status, epoch, transition counts, receipt count, and lease liveness.
    pub async fn observe(
        &self,
        instance: SagaInstanceRef,
    ) -> FaultMatrixResult<Option<FaultMatrixSagaObservation>> {
        let row = self
            .read_db
            .saga_fault_read_map(
                infra_tenant_scope(instance.tenant()),
                move |mut tx| Box::pin(async move { tx.saga_fault_observe(instance).await }),
                std::convert::identity,
            )
            .await?;
        row.map(FaultMatrixSagaObservation::try_from_row)
            .transpose()
    }
}

/// Projection runtime probe produced through `ProjectionHarness`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FaultMatrixProjectionProbe {
    apply_calls: u32,
    unique_applied: usize,
    checkpoint_offset: Lsn,
}

impl FaultMatrixProjectionProbe {
    pub fn apply_calls(&self) -> u32 {
        self.apply_calls
    }

    pub fn unique_applied(&self) -> usize {
        self.unique_applied
    }

    pub fn checkpoint_offset(&self) -> Lsn {
        self.checkpoint_offset
    }
}

/// Typed harness that owns the postgres runtime deps and private owner pool.
pub struct PgFaultMatrixHarness {
    deps: PgRuntimeDeps,
    owner_pool: PgPool,
    relay_budget: RelayBudget,
}

impl PgFaultMatrixHarness {
    /// Use already-provisioned opaque logins, run migrations, and construct runtime deps.
    pub async fn setup(
        config: PgFaultMatrixConfig,
        logins: PgFaultMatrixLoginCredentials,
        relay_budget: RelayBudget,
        projection_capture: eventexec::ProjectionCaptureView<'_>,
    ) -> FaultMatrixResult<Self> {
        let migrator = pg_config(
            &config.host,
            config.port,
            &config.database,
            &config.owner_username,
            &config.owner_password,
        );
        let serving = pg_config(
            &config.host,
            config.port,
            &config.database,
            RSS_APP_ROLE,
            &logins.serving_password,
        );
        let tenant_read = PgTenantReadConfig::new(pg_config(
            &config.host,
            config.port,
            &config.database,
            RSS_APP_READ_ROLE,
            &logins.reader_password,
        ));
        let deps = PgRuntimeDeps::setup_test_fixture(
            &migrator,
            &serving,
            &tenant_read,
            None,
            projection_capture,
        )
        .await?;
        let owner_pool = owner_pool(&config).await?;
        Ok(Self {
            deps,
            owner_pool,
            relay_budget,
        })
    }

    /// Close private postgres resources.
    pub async fn shutdown(self) -> FaultMatrixResult<()> {
        let (resources, _sampler_factory) = self.deps.into_runtime_parts(Duration::from_secs(1));
        self.owner_pool.close().await;
        let mut first_error = None;
        for resource in resources.into_iter().rev() {
            if let Err(error) = resource.shutdown().await
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        if let Some(error) = first_error {
            return Err(error.into());
        }
        Ok(())
    }

    /// Construct the production durable Saga store used by fault journeys.
    pub fn saga_durable_store(&self) -> FaultMatrixResult<crate::PgSagaDurableStore> {
        Ok(self
            .deps
            .handle()
            .infra()
            .saga_durable_store(test_saga_receipt_protection()?))
    }

    /// Construct the production dead-letter writer used by Saga fault journeys.
    pub fn saga_dead_letter_store(&self) -> FaultMatrixResult<crate::PgDeadLetterStore> {
        Ok(self
            .deps
            .handle()
            .infra()
            .dead_letter(test_dlx_payload_protector()?))
    }

    /// Construct the minimal fault-only control plane paired with the production Saga store.
    pub fn saga_fault_control(&self) -> PgSagaFaultControl {
        PgSagaFaultControl::new(&self.owner_pool)
    }

    /// Seed one provenance-checked generated `identity.session-created` durable fact.
    pub async fn seed_session_created(
        &self,
        input: FaultMatrixSessionCreatedInput,
    ) -> FaultMatrixResult<()> {
        seed_session_created(&self.owner_pool, input).await
    }

    /// Drive one production relay attempt for an already-seeded session-created fact.
    pub async fn relay_session_created_once(
        &self,
        event_id: &str,
        publisher: Box<DynPublisher<'static>>,
    ) -> FaultMatrixResult<FaultMatrixSessionCreatedRelayObservation> {
        let outbox = self.outbox_for_domain(SESSION_CREATED_FACT.contract().domain(), publisher)?;
        let claimed = outbox
            .fault_matrix_claim_exact(&self.owner_pool, event_id)
            .await?
            .ok_or_else(|| anyhow!("seeded session-created outbox row was not claimed"))?;
        let tenant = claimed.subject().tenant_id();
        let disposition = outbox.relay(claimed).await?;
        let status = self.outbox_status(tenant, event_id).await?;
        Ok(FaultMatrixSessionCreatedRelayObservation {
            event_id: event_id.to_string(),
            disposition,
            status,
        })
    }

    /// Make the exact pending session-created retry immediately claimable.
    pub async fn make_session_created_retry_due(
        &self,
        tenant: vocab::TenantId,
        event_id: &str,
    ) -> FaultMatrixResult<()> {
        let affected = sqlx::query(
            "UPDATE outbox SET retry_after = clock_timestamp() - interval '1 microsecond' \
             WHERE tenant_id = $1::uuid AND event_id = $2 AND domain = $3 \
               AND contract_id = $4 AND status = 'pending'",
        )
        .bind(tenant.to_string())
        .bind(event_id)
        .bind(SESSION_CREATED_FACT.contract().domain())
        .bind(SESSION_CREATED_FACT.contract().contract_id())
        .execute(&self.owner_pool)
        .await?
        .rows_affected();
        if affected != 1 {
            bail!("session-created retry row was not pending");
        }
        Ok(())
    }

    /// Dispatch one real delivery through Inbox and the real audit ConsumerTx.
    #[cfg(feature = "domain-audit")]
    pub async fn consume_session_created_delivery(
        &self,
        tenant: vocab::TenantId,
        group: &str,
        message: diport::Message,
    ) -> FaultMatrixResult<FaultMatrixConsumerDelivery> {
        let store = self.deps.handle().infra().inbox();
        let ctx = session_created_inbox_ctx(tenant, group)?;
        let key = IdemKey::parse(message.id.as_str())?;
        let lease = LeaseToken::mint();
        match store.try_claim(&ctx, &key, &lease).await? {
            SeenState::Duplicate => Ok(FaultMatrixConsumerDelivery::Duplicate),
            SeenState::InProgress => bail!("session-created delivery claim is already in progress"),
            SeenState::Fresh => {
                let hasher = audit::ports::AuditChainHasher::new(
                    TestMac,
                    MacKey::from_bytes(vec![0x42; 32]),
                )
                .ok_or_else(|| anyhow!("fault-matrix audit chain key was rejected"))?;
                let consumer = Arc::new(
                    self.deps
                        .handle()
                        .for_domain::<crate::caps::Audit>()
                        .session_created_consumer_tx(hasher),
                );
                match consumer.handle(message, ctx, key, lease).await {
                    crate::PgConsumerTxOutcome::Committed(_) => {
                        Ok(FaultMatrixConsumerDelivery::Committed)
                    }
                    crate::PgConsumerTxOutcome::Requeue(_)
                    | crate::PgConsumerTxOutcome::LeaseLost { .. }
                    | crate::PgConsumerTxOutcome::Reject { .. } => {
                        bail!("session-created ConsumerTx did not commit")
                    }
                }
            }
        }
    }

    /// Observe the exact audit business effect and Inbox Done row for one delivery identity.
    pub async fn session_created_effect_observation(
        &self,
        tenant: vocab::TenantId,
        event_id: &str,
        group: &str,
        session_id: uuid::Uuid,
    ) -> FaultMatrixResult<FaultMatrixSessionCreatedEffectObservation> {
        let business_mutations: i64 = sqlx::query_scalar(
            "SELECT count(*)::bigint FROM audit_entries \
             WHERE tenant_id = $1::uuid AND action = 'identity:login' \
               AND resource_kind = 'session' AND resource_id = $2 AND outcome = 'success'",
        )
        .bind(tenant.to_string())
        .bind(session_id.to_string())
        .fetch_one(&self.owner_pool)
        .await?;
        let inbox_done_rows: i64 = sqlx::query_scalar(
            "SELECT count(*)::bigint FROM inbox_receipts \
             WHERE tenant_id = $1::uuid AND event_id = $2 AND consumer_group = $3 \
               AND domain = $4 AND contract_id = $5 AND status = 'done'",
        )
        .bind(tenant.to_string())
        .bind(event_id)
        .bind(group)
        .bind(SESSION_CREATED_FACT.contract().domain())
        .bind(SESSION_CREATED_FACT.contract().contract_id())
        .fetch_one(&self.owner_pool)
        .await?;
        Ok(FaultMatrixSessionCreatedEffectObservation {
            business_mutations: non_negative_count(business_mutations, "audit mutation")?,
            inbox_done_rows: non_negative_count(inbox_done_rows, "Inbox Done")?,
        })
    }

    /// Exercise stale-holder fencing and current-holder settlement through the production funnel.
    pub async fn stale_outbox_settlement(
        &self,
        tenant: vocab::TenantId,
        event_id: &str,
    ) -> FaultMatrixResult<FaultMatrixStaleSettlementObservation> {
        seed_outbox(
            &self.owner_pool,
            tenant,
            event_id,
            SESSION_CREATED_FACT.contract().domain(),
            SESSION_CREATED_FACT.topic(),
            SESSION_CREATED_FACT.contract().contract_id(),
            FaultMatrixOutboxStatus::Pending,
        )
        .await?;
        let outbox = self.outbox_for_domain(
            SESSION_CREATED_FACT.contract().domain(),
            FaultMatrixPublishOutcome::Ok.publisher(),
        )?;
        let claim_a = claim_exact(&self.owner_pool, &outbox, event_id).await?;
        age_outbox_publishing(&self.owner_pool, tenant, event_id, self.relay_budget).await?;
        let claim_b = claim_exact(&self.owner_pool, &outbox, event_id).await?;

        let stale = parse_settlement_outcome(
            outbox
                .fault_matrix_published_settlement_outcome(&claim_a)
                .await?,
        )?;
        let intermediate = outbox_terminal_observation(&self.owner_pool, tenant, event_id).await?;
        let current = parse_settlement_outcome(
            outbox
                .fault_matrix_published_settlement_outcome(&claim_b)
                .await?,
        )?;
        let final_status = self.outbox_status(tenant, event_id).await?;
        Ok(FaultMatrixStaleSettlementObservation {
            stale,
            current,
            intermediate_no_terminal: intermediate.status == "publishing"
                && intermediate.no_terminal,
            final_status,
        })
    }

    /// Exercise an expired current exact deadline through the production settlement funnel.
    pub async fn expired_outbox_settlement(
        &self,
        tenant: vocab::TenantId,
        event_id: &str,
    ) -> FaultMatrixResult<FaultMatrixExpiredSettlementObservation> {
        seed_outbox(
            &self.owner_pool,
            tenant,
            event_id,
            SESSION_CREATED_FACT.contract().domain(),
            SESSION_CREATED_FACT.topic(),
            SESSION_CREATED_FACT.contract().contract_id(),
            FaultMatrixOutboxStatus::Pending,
        )
        .await?;
        let outbox = self.outbox_for_domain(
            SESSION_CREATED_FACT.contract().domain(),
            FaultMatrixPublishOutcome::Ok.publisher(),
        )?;
        let mut claimed = claim_exact(&self.owner_pool, &outbox, event_id).await?;
        let expired_deadline_epoch_micros: i64 = sqlx::query_scalar(
            "UPDATE outbox SET updated_at = clock_timestamp() - interval '61 seconds', \
                    lease_until = clock_timestamp() - interval '1 second' \
             WHERE tenant_id = $1::uuid AND event_id = $2 AND domain = $3 \
               AND contract_id = $4 AND status = 'publishing' \
             RETURNING (EXTRACT(EPOCH FROM lease_until) * 1000000)::bigint",
        )
        .bind(tenant.to_string())
        .bind(event_id)
        .bind(SESSION_CREATED_FACT.contract().domain())
        .bind(SESSION_CREATED_FACT.contract().contract_id())
        .fetch_one(&self.owner_pool)
        .await?;
        claimed.fault_matrix_expire_persisted_deadline(
            expired_deadline_epoch_micros,
            self.relay_budget,
        );
        let outcome = match outbox
            .fault_matrix_persisted_deadline_settlement_evidence(&claimed)
            .await?
        {
            crate::outbox::FaultMatrixPublishedSettlementEvidence::PersistedDeadlineExpired => {
                FaultMatrixSettlementOutcome::Expired
            }
            unexpected => bail!(
                "fault-matrix exact persisted deadline did not expire in SQL settlement: \
                 {unexpected:?}"
            ),
        };
        let observed = outbox_terminal_observation(&self.owner_pool, tenant, event_id).await?;
        Ok(FaultMatrixExpiredSettlementObservation {
            outcome,
            persisted_deadline_evaluated: true,
            still_publishing: observed.status == "publishing",
            no_terminal: observed.no_terminal,
        })
    }

    /// Seed a pending outbox row as fixture input, then claim and drive `PgOutbox::relay`.
    pub async fn run_outbox_publish(
        &self,
        tenant: vocab::TenantId,
        event_id: &str,
        domain: &str,
        topic: &str,
        contract_id: &str,
        outcome: FaultMatrixPublishOutcome,
    ) -> FaultMatrixResult<()> {
        seed_outbox(
            &self.owner_pool,
            tenant,
            event_id,
            domain,
            topic,
            contract_id,
            FaultMatrixOutboxStatus::Pending,
        )
        .await?;
        let outbox = self.outbox_for_domain(domain, outcome.publisher())?;
        let claimed = outbox
            .fault_matrix_claim_exact(&self.owner_pool, event_id)
            .await?
            .ok_or_else(|| anyhow!("seeded outbox row was not claimed"))?;
        outbox.relay(claimed).await?;
        Ok(())
    }

    /// Drive a retryable publish outcome from pending through the exact relay retry budget.
    ///
    /// Every attempt must keep the durable event id. Intermediate attempts must settle back to
    /// pending; only the budget-exhausting attempt may settle to DLX.
    pub async fn run_outbox_publish_to_budget(
        &self,
        tenant: vocab::TenantId,
        event_id: &str,
        domain: &str,
        topic: &str,
        contract_id: &str,
        outcome: FaultMatrixPublishOutcome,
    ) -> FaultMatrixResult<Vec<String>> {
        match outcome {
            FaultMatrixPublishOutcome::Transient => {}
            FaultMatrixPublishOutcome::Ok | FaultMatrixPublishOutcome::Permanent => {
                bail!("publish-to-budget requires a closed retryable outcome")
            }
        }
        seed_outbox(
            &self.owner_pool,
            tenant,
            event_id,
            domain,
            topic,
            contract_id,
            FaultMatrixOutboxStatus::Pending,
        )
        .await?;
        let message_ids = Arc::new(Mutex::new(Vec::new()));
        let outbox = self.outbox_for_domain(
            domain,
            outcome.publisher_with_messages(Arc::clone(&message_ids)),
        )?;

        for attempt in 1..=crate::outbox::MAX_PUBLISH_ATTEMPTS {
            if attempt > 1 {
                let affected = sqlx::query(
                    "UPDATE outbox SET retry_after = clock_timestamp() - interval '1 microsecond' \
                     WHERE tenant_id = $1::uuid AND event_id = $2 AND status = 'pending'",
                )
                .bind(tenant.to_string())
                .bind(event_id)
                .execute(&self.owner_pool)
                .await?
                .rows_affected();
                if affected != 1 {
                    bail!("retryable outbox row was not pending before attempt {attempt}");
                }
            }

            let claimed = outbox
                .fault_matrix_claim_exact(&self.owner_pool, event_id)
                .await?
                .ok_or_else(|| {
                    anyhow!("retryable outbox row was not claimed at attempt {attempt}")
                })?;
            let disposition = outbox.relay(claimed).await?;
            let budget_exhausted = attempt == crate::outbox::MAX_PUBLISH_ATTEMPTS;
            match (budget_exhausted, disposition) {
                (false, Disposition::Requeue) | (true, Disposition::Reject) => {}
                _ => bail!(
                    "retryable publish attempt {attempt} settled as {disposition:?}; budget_exhausted={budget_exhausted}"
                ),
            }
            let expected_status = if budget_exhausted {
                FaultMatrixOutboxStatus::Dlx
            } else {
                FaultMatrixOutboxStatus::Pending
            };
            if self.outbox_count(tenant, event_id, expected_status).await? != 1 {
                bail!("retryable publish attempt {attempt} did not settle to {expected_status:?}");
            }
        }

        let observed = message_ids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let expected_attempts = usize::try_from(crate::outbox::MAX_PUBLISH_ATTEMPTS)?;
        if observed.len() != expected_attempts || observed.iter().any(|id| id != event_id) {
            bail!(
                "retryable publish attempts must use the same event id exactly {expected_attempts} times"
            );
        }
        Ok(observed)
    }

    fn outbox_for_domain(
        &self,
        domain: &str,
        publisher: Box<DynPublisher<'static>>,
    ) -> FaultMatrixResult<crate::PgOutbox> {
        let outbox = match domain {
            "identity" => self
                .deps
                .handle()
                .for_domain::<crate::caps::Identity>()
                .outbox(
                    publisher,
                    self.relay_budget,
                    test_tenant_authority()?,
                    test_dlx_payload_protector()?,
                ),
            "settings" => self
                .deps
                .handle()
                .for_domain::<crate::caps::Settings>()
                .outbox(
                    publisher,
                    self.relay_budget,
                    test_tenant_authority()?,
                    test_dlx_payload_protector()?,
                ),
            _ => bail!("unsupported fault-matrix outbox domain `{domain}`"),
        };
        Ok(outbox)
    }

    /// Run the publish-succeeded / settle-not-yet-run phase.
    pub async fn publish_outbox_before_settle(
        &self,
        tenant: vocab::TenantId,
        event_id: &str,
        topic: &str,
        publisher: Box<DynPublisher<'static>>,
    ) -> FaultMatrixResult<()> {
        seed_outbox(
            &self.owner_pool,
            tenant,
            event_id,
            "identity",
            topic,
            SESSION_CREATED_FACT.contract().contract_id(),
            FaultMatrixOutboxStatus::Pending,
        )
        .await?;
        crate::outbox::fault_matrix_publish_before_settle(
            &self.owner_pool,
            publisher,
            self.relay_budget,
            test_tenant_authority()?,
            test_dlx_payload_protector()?,
            "identity",
            event_id,
        )
        .await?;
        Ok(())
    }

    /// Age the publishing lease, then recover through `PgOutbox::claim_batch` and `PgOutbox::relay`.
    pub async fn recover_stale_outbox_publish(
        &self,
        tenant: vocab::TenantId,
        event_id: &str,
        domain: &str,
        publisher: Box<DynPublisher<'static>>,
    ) -> FaultMatrixResult<()> {
        age_outbox_publishing(&self.owner_pool, tenant, event_id, self.relay_budget).await?;
        let outbox = match domain {
            "identity" => self
                .deps
                .handle()
                .for_domain::<crate::caps::Identity>()
                .outbox(
                    publisher,
                    self.relay_budget,
                    test_tenant_authority()?,
                    test_dlx_payload_protector()?,
                ),
            "settings" => self
                .deps
                .handle()
                .for_domain::<crate::caps::Settings>()
                .outbox(
                    publisher,
                    self.relay_budget,
                    test_tenant_authority()?,
                    test_dlx_payload_protector()?,
                ),
            _ => bail!("unsupported fault-matrix outbox domain `{domain}`"),
        };
        let claimed = outbox
            .fault_matrix_claim_exact(&self.owner_pool, event_id)
            .await?
            .ok_or_else(|| anyhow!("stale publishing outbox row was not reclaimed"))?;
        outbox.relay(claimed).await?;
        Ok(())
    }

    /// Count outbox rows by closed status.
    pub async fn outbox_count(
        &self,
        tenant: vocab::TenantId,
        event_id: &str,
        status: FaultMatrixOutboxStatus,
    ) -> FaultMatrixResult<i64> {
        let row = sqlx::query(
            "SELECT count(*)::bigint FROM outbox WHERE tenant_id = $1::uuid AND event_id = $2 AND status = $3",
        )
        .bind(tenant.to_string())
        .bind(event_id)
        .bind(status.as_str())
        .fetch_one(&self.owner_pool)
        .await?;
        Ok(row.get::<i64, _>(0))
    }

    async fn outbox_status(
        &self,
        tenant: vocab::TenantId,
        event_id: &str,
    ) -> FaultMatrixResult<FaultMatrixOutboxStatus> {
        let status: String = sqlx::query_scalar(
            "SELECT status FROM outbox \
             WHERE tenant_id = $1::uuid AND event_id = $2 \
               AND domain = $3 AND contract_id = $4",
        )
        .bind(tenant.to_string())
        .bind(event_id)
        .bind(SESSION_CREATED_FACT.contract().domain())
        .bind(SESSION_CREATED_FACT.contract().contract_id())
        .fetch_one(&self.owner_pool)
        .await?;
        FaultMatrixOutboxStatus::parse(&status)
    }

    /// Read the authoritative retry state for one tenant-scoped outbox event.
    pub async fn outbox_retry_observation(
        &self,
        tenant: vocab::TenantId,
        event_id: &str,
    ) -> FaultMatrixResult<FaultMatrixOutboxRetryObservation> {
        let row: Option<(String, i32, bool, bool)> = sqlx::query_as(
            "SELECT status, retry_count, \
                    retry_after IS NOT NULL AND retry_after > updated_at, \
                    lease_token IS NULL AND lease_until IS NULL \
             FROM outbox WHERE tenant_id = $1::uuid AND event_id = $2",
        )
        .bind(tenant.to_string())
        .bind(event_id)
        .fetch_optional(&self.owner_pool)
        .await?;
        FaultMatrixOutboxRetryObservation::try_from_row(row)
    }

    /// Read the authoritative unified dead-letter row written by outbox relay DLX.
    pub async fn outbox_dead_letter(
        &self,
        tenant: vocab::TenantId,
        event_id: &str,
    ) -> FaultMatrixResult<FaultMatrixDeadLetterObservation> {
        let row = sqlx::query(
            "SELECT source_kind, error_summary, replay_capsule_encoding, payload_len \
             FROM dead_letter WHERE tenant_id = $1::uuid AND message_id = $2",
        )
        .bind(tenant.to_string())
        .bind(event_id)
        .fetch_optional(&self.owner_pool)
        .await?;
        let row = row.ok_or_else(|| anyhow!("dead_letter row missing for outbox event"))?;
        Ok(FaultMatrixDeadLetterObservation {
            source: FaultMatrixDeadLetterSource::parse(row.get::<String, _>(0).as_str())?,
            summary: FaultMatrixDeadLetterSummary::parse(row.get::<String, _>(1).as_str())?,
            encoding: FaultMatrixDeadLetterEncoding::parse(row.get::<String, _>(2).as_str())?,
            payload_len: row.get::<i64, _>(3),
        })
    }

    /// Drive `PgInboxStore::try_claim` with an expired claim.
    pub async fn reclaim_stale_inbox_claim(
        &self,
        tenant: vocab::TenantId,
        event_id: &str,
        group: &str,
    ) -> FaultMatrixResult<SeenState> {
        let store = self.deps.handle().infra().inbox();
        let ctx = session_created_inbox_ctx(tenant, group)?;
        let first = LeaseToken::mint();
        let key = IdemKey::parse(event_id)?;
        let _ = store.try_claim(&ctx, &key, &first).await?;
        age_inbox_claim(&self.owner_pool, tenant, event_id, group).await?;
        let second = LeaseToken::mint();
        Ok(store.try_claim(&ctx, &key, &second).await?)
    }

    /// Drive stale lease commit through `PgInboxStore::commit`.
    pub async fn stale_inbox_lease_commit(
        &self,
        tenant: vocab::TenantId,
        event_id: &str,
        group: &str,
    ) -> FaultMatrixResult<LeaseOutcome> {
        let store = self.deps.handle().infra().inbox();
        let ctx = session_created_inbox_ctx(tenant, group)?;
        let key = IdemKey::parse(event_id)?;
        let lease = LeaseToken::mint();
        let _ = store.try_claim(&ctx, &key, &lease).await?;
        store.release(&ctx, &key, &lease).await?;
        Ok(store.commit(&ctx, &key, &lease).await?)
    }

    /// Drive `ProjectionHarness` through apply-before-checkpoint-failure, then replay idempotently.
    pub async fn projection_replay_after_checkpoint_failure(
        &self,
        owner: &str,
        checkpoint_id: &str,
        tenant: vocab::TenantId,
    ) -> FaultMatrixResult<FaultMatrixProjectionProbe> {
        let checkpoint = Arc::new(self.deps.handle().infra().checkpoint());
        let failing_checkpoint = Arc::new(FailOnceCheckpoint::new(checkpoint.clone()));
        let dlx = Arc::new(
            self.deps
                .handle()
                .infra()
                .dead_letter(test_dlx_payload_protector()?),
        );
        let owner = CheckpointOwner::new(owner);
        let id = CheckpointId::new(checkpoint_id);
        let projector = Arc::new(FaultMatrixProjectionProjector::default());
        let source = FaultMatrixProjectionSource;
        let event = fault_matrix_projection_event(tenant, Lsn::new(10))?;

        let first = ProjectionHarness::new(
            projector.clone(),
            failing_checkpoint,
            owner.clone(),
            id.clone(),
            dlx.clone(),
            SerialInOrder::from_source(&source),
        )
        .run(std::slice::from_ref(&event))
        .await;
        if first.stop != ProjectionStop::CheckpointUnsaved {
            bail!(
                "projection first run should stop after unsaved checkpoint, got {:?}",
                first.stop
            );
        }

        let second = ProjectionHarness::new(
            projector.clone(),
            checkpoint.clone(),
            owner.clone(),
            id.clone(),
            dlx,
            SerialInOrder::from_source(&source),
        )
        .run(std::slice::from_ref(&event))
        .await;
        if second.stop != ProjectionStop::Completed {
            bail!(
                "projection replay should complete after checkpoint recovery, got {:?}",
                second.stop
            );
        }
        let current = checkpoint
            .get_checkpoint(&owner, &id)
            .await?
            .ok_or_else(|| anyhow!("checkpoint missing after projection replay"))?;
        Ok(FaultMatrixProjectionProbe {
            apply_calls: projector.apply_calls(),
            unique_applied: projector.unique_applied(),
            checkpoint_offset: current.offset,
        })
    }

    /// Drive checkpoint stale-writer CAS.
    pub async fn stale_projection_checkpoint_writer(
        &self,
        owner: &str,
        checkpoint_id: &str,
    ) -> FaultMatrixResult<SaveOutcome> {
        let store = self.deps.handle().infra().checkpoint();
        let owner = CheckpointOwner::new(owner);
        let id = CheckpointId::new(checkpoint_id);
        let _ = store
            .save_checkpoint(&owner, &id, Lsn::new(20), CheckpointVersion::INITIAL)
            .await?;
        Ok(store
            .save_checkpoint(&owner, &id, Lsn::new(19), CheckpointVersion::INITIAL)
            .await?)
    }

    /// Drive reconcile schedule store attempt/action recording and verify stable dispatch idempotence.
    pub async fn reconcile_dispatch_key_stable(
        &self,
        tenant: vocab::TenantId,
        dispatch_key: &str,
        commands: [ApplyDeviceCertificateReconcileCommand; 2],
    ) -> FaultMatrixResult<i64> {
        let store = self.deps.handle().infra().reconcile();
        let device_id = "b497a9ce-6ac5-4d44-a0a3-869af114db5f";
        store
            .seed_device_desired_for_fault_matrix(tenant, device_id)
            .await?;
        let key = crate::reconcile::ReconcileTargetKey::parse(
            "identity.device-certificate",
            "device-certificate",
            device_id,
        )?;
        let target = store.upsert_target(tenant, &key).await?;
        let max_in_flight = eventexec::ReconcileMaxInFlight::try_new(1)?;
        let claimed = store
            .claim_due_targets(
                tenant,
                "identity.device-certificate",
                "fault-matrix",
                max_in_flight,
                Duration::from_secs(60),
            )
            .await?
            .into_iter()
            .find(|candidate| candidate.target_id() == target.target_id())
            .ok_or_else(|| anyhow!("reconcile target was not claimed"))?;
        let ScheduleAttemptOutcome::Started(attempt) =
            ReconcileScheduleStore::append_attempt(&store, &claimed, "fault-matrix").await?
        else {
            bail!("reconcile attempt was not started under the claimed lease");
        };
        let commands = review_certificate_reconcile_commands(commands, &attempt).await?;
        let [first, retry] = commands;
        let first_alias = first
            .aliases()
            .current()
            .ok_or_else(|| anyhow!("reviewed reconcile command omitted its current alias"))?;
        let retry_alias = retry
            .aliases()
            .current()
            .ok_or_else(|| anyhow!("retry reconcile command omitted its current alias"))?;
        if first_alias.key_id() != retry_alias.key_id()
            || first_alias.digest() != retry_alias.digest()
        {
            bail!("same generated command key derived different sealed aliases");
        }
        if format!("{:?}", first.aliases()).contains(dispatch_key) {
            bail!("sealed command alias debug output leaked its raw idempotency key");
        }
        let alias_key_id = first_alias.key_id().to_string();
        let alias_digest = first_alias.digest().to_vec();
        for (index, command) in [first, retry].into_iter().enumerate() {
            let outcome = store
                .record_fenced_command(&attempt, ConvergeAction::Update, command)
                .await?;
            let expected = if index == 0 {
                ScheduleActionOutcome::Enqueued
            } else {
                ScheduleActionOutcome::Duplicate
            };
            if outcome != expected {
                bail!("reconcile action lost lease before enqueue");
            }
        }
        let canonical_rows = sqlx::query(
            "SELECT command_id FROM command_idempotency_aliases \
             WHERE tenant_id = $1::uuid AND key_id = $2 AND alias_digest = $3",
        )
        .bind(tenant.to_string())
        .bind(alias_key_id)
        .bind(alias_digest)
        .fetch_all(&self.owner_pool)
        .await?;
        if canonical_rows.len() != 1 {
            bail!(
                "sealed reconcile alias must resolve to exactly one canonical command id, got {}",
                canonical_rows.len()
            );
        }
        let opaque_dispatch_id = canonical_rows[0].get::<String, _>("command_id");
        if opaque_dispatch_id.contains(dispatch_key) {
            bail!("random canonical command id leaked its raw idempotency key");
        }
        self.outbox_count(
            tenant,
            &opaque_dispatch_id,
            FaultMatrixOutboxStatus::Pending,
        )
        .await
    }

    /// Drive reconcile lease CAS with a stale token.
    pub async fn stale_reconcile_lease_is_rejected(
        &self,
        tenant: vocab::TenantId,
        target_suffix: &str,
    ) -> FaultMatrixResult<bool> {
        let store = self.deps.handle().infra().reconcile();
        let key =
            crate::reconcile::ReconcileTargetKey::parse("fault-matrix", "device", target_suffix)?;
        let target = store.upsert_target(tenant, &key).await?;
        let lease = store
            .acquire_lease(
                tenant,
                target.target_id(),
                "fault-matrix",
                Duration::from_secs(60),
            )
            .await?
            .ok_or_else(|| anyhow!("reconcile lease not acquired"))?;
        let lost = store
            .release_lease(
                tenant,
                lease.target_id(),
                lease.lease_token(),
                lease.epoch(),
            )
            .await?;
        if lost != crate::reconcile::ReconcileLeaseOutcome::Held {
            bail!("reconcile release lost active lease");
        }
        Ok(store
            .extend_lease(
                tenant,
                lease.target_id(),
                lease.lease_token(),
                lease.epoch(),
                Duration::from_secs(60),
            )
            .await?
            == crate::reconcile::ReconcileLeaseOutcome::Lost)
    }
}

/// Publisher outcome used by the outbox fault matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultMatrixPublishOutcome {
    Ok,
    Transient,
    Permanent,
}

impl FaultMatrixPublishOutcome {
    fn publisher(self) -> Box<DynPublisher<'static>> {
        DynPublisher::new_box(match self {
            Self::Ok => RecordingPublisher::ok(),
            Self::Transient => RecordingPublisher::transient(),
            Self::Permanent => RecordingPublisher::permanent(),
        })
    }

    fn publisher_with_messages(
        self,
        message_ids: Arc<Mutex<Vec<String>>>,
    ) -> Box<DynPublisher<'static>> {
        DynPublisher::new_box(RecordingPublisher {
            result: self,
            message_ids: Some(message_ids),
        })
    }
}

fn pg_config(host: &str, port: u16, database: &str, username: &str, password: &str) -> PgConfig {
    PgConfig::new(
        host.to_string(),
        port,
        database.to_string(),
        username.to_string(),
        PgPassword::new(password.to_string()),
    )
    .with_ssl_mode(PgSslMode::Prefer)
    .with_acquire_timeout(Duration::from_secs(5))
}

async fn owner_pool(config: &PgFaultMatrixConfig) -> FaultMatrixResult<PgPool> {
    let options = PgConnectOptions::new()
        .host(&config.host)
        .port(config.port)
        .database(&config.database)
        .username(&config.owner_username)
        .password(&config.owner_password)
        .ssl_mode(SqlxPgSslMode::Prefer);
    Ok(PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(options)
        .await?)
}

async fn seed_session_created(
    pool: &PgPool,
    input: FaultMatrixSessionCreatedInput,
) -> FaultMatrixResult<()> {
    let payload = serde_json::to_vec(&input.payload)?;
    let metadata = serde_json::json!({
        "tenantId": input.tenant.to_string(),
        "schemaVersion": SESSION_CREATED_FACT.contract().version(),
        "schemaHash": SESSION_CREATED_FACT.contract().schema_hash(),
    })
    .to_string();
    sqlx::query(
        r#"
        INSERT INTO outbox (
            event_id, tenant_id, domain, topic, contract_id, payload, metadata,
            status, contract_version, schema_hash, partition_key
        )
        VALUES ($1, $2::uuid, $3, $4, $5, $6, $7::jsonb,
                'pending', $8, $9, $10)
        "#,
    )
    .bind(input.idem_key.as_str())
    .bind(input.tenant.to_string())
    .bind(SESSION_CREATED_FACT.contract().domain())
    .bind(SESSION_CREATED_FACT.topic())
    .bind(SESSION_CREATED_FACT.contract().contract_id())
    .bind(payload)
    .bind(metadata)
    .bind(SESSION_CREATED_FACT.contract().version())
    .bind(SESSION_CREATED_FACT.contract().schema_hash())
    .bind(format!("session-{}", input.session_id))
    .execute(pool)
    .await?;
    Ok(())
}

async fn claim_exact(
    owner_pool: &PgPool,
    outbox: &crate::PgOutbox,
    event_id: &str,
) -> FaultMatrixResult<crate::outbox::PgClaimedOutboxEntry> {
    outbox
        .fault_matrix_claim_exact(owner_pool, event_id)
        .await?
        .ok_or_else(|| anyhow!("fault-matrix outbox row was not claimed"))
}

struct OutboxTerminalObservation {
    status: String,
    no_terminal: bool,
}

async fn outbox_terminal_observation(
    pool: &PgPool,
    tenant: vocab::TenantId,
    event_id: &str,
) -> FaultMatrixResult<OutboxTerminalObservation> {
    let row: (String, bool) = sqlx::query_as(
        "SELECT status, published_at IS NULL AND dlx_at IS NULL \
         FROM outbox WHERE tenant_id = $1::uuid AND event_id = $2 \
           AND domain = $3 AND contract_id = $4",
    )
    .bind(tenant.to_string())
    .bind(event_id)
    .bind(SESSION_CREATED_FACT.contract().domain())
    .bind(SESSION_CREATED_FACT.contract().contract_id())
    .fetch_one(pool)
    .await?;
    Ok(OutboxTerminalObservation {
        status: row.0,
        no_terminal: row.1,
    })
}

fn parse_settlement_outcome(raw: &str) -> FaultMatrixResult<FaultMatrixSettlementOutcome> {
    match raw {
        "settled" => Ok(FaultMatrixSettlementOutcome::Settled),
        "expired" => Ok(FaultMatrixSettlementOutcome::Expired),
        "lost_lease" => Ok(FaultMatrixSettlementOutcome::LostLease),
        _ => bail!("unknown fault-matrix settlement outcome"),
    }
}

fn non_negative_count(value: i64, label: &str) -> FaultMatrixResult<u64> {
    u64::try_from(value).map_err(|_| anyhow!("negative fault-matrix {label} count"))
}

async fn seed_outbox(
    pool: &PgPool,
    tenant: vocab::TenantId,
    event_id: &str,
    domain: &str,
    topic: &str,
    contract_id: &str,
    status: FaultMatrixOutboxStatus,
) -> FaultMatrixResult<()> {
    sqlx::query(
        r#"
        INSERT INTO outbox (
            event_id, tenant_id, domain, topic, contract_id, payload, metadata,
            status, contract_version, schema_hash, partition_key
        )
        VALUES (
            $1, $2::uuid, $3, $4, $5, decode('70', 'hex'), $6::jsonb,
            $7, 'v1', $8, $9
        )
        "#,
    )
    .bind(event_id)
    .bind(tenant.to_string())
    .bind(domain)
    .bind(topic)
    .bind(contract_id)
    .bind(metadata_json(tenant))
    .bind(status.as_str())
    .bind(SCHEMA_HASH)
    .bind(format!("pk-{event_id}"))
    .execute(pool)
    .await?;
    Ok(())
}

async fn age_outbox_publishing(
    pool: &PgPool,
    tenant: vocab::TenantId,
    event_id: &str,
    relay_budget: RelayBudget,
) -> FaultMatrixResult<()> {
    sqlx::query(
        "UPDATE outbox \
         SET updated_at = clock_timestamp() - $4 * interval '1 millisecond', \
             lease_until = clock_timestamp() - interval '1 second' \
         WHERE tenant_id = $1::uuid AND event_id = $2 AND status = $3",
    )
    .bind(tenant.to_string())
    .bind(event_id)
    .bind(crate::outbox::STATUS_PUBLISHING)
    .bind(relay_budget.lease_ttl_millis().saturating_add(10_000))
    .execute(pool)
    .await?;
    Ok(())
}

async fn age_inbox_claim(
    pool: &PgPool,
    tenant: vocab::TenantId,
    event_id: &str,
    group: &str,
) -> FaultMatrixResult<()> {
    sqlx::query(
        "UPDATE inbox_receipts SET claimed_at = now() - interval '70 seconds' \
         WHERE tenant_id = $1::uuid AND event_id = $2 AND consumer_group = $3",
    )
    .bind(tenant.to_string())
    .bind(event_id)
    .bind(group)
    .execute(pool)
    .await?;
    Ok(())
}

fn session_created_inbox_ctx(
    tenant: vocab::TenantId,
    group: &str,
) -> FaultMatrixResult<InboxReceiptContext> {
    Ok(InboxReceiptContext::new(
        tenant,
        ConsumerGroup::parse(group)?,
        SESSION_CREATED_FACT.contract().domain(),
        SESSION_CREATED_FACT.topic(),
        SESSION_CREATED_FACT.contract().contract_id(),
        SESSION_CREATED_FACT.contract().version(),
        SESSION_CREATED_FACT.contract().schema_hash(),
        None,
        None,
    )?)
}

#[derive(Default)]
struct FaultMatrixProjectionProjector {
    apply_calls: AtomicU32,
    applied_lsn: Mutex<BTreeSet<u64>>,
}

impl FaultMatrixProjectionProjector {
    fn apply_calls(&self) -> u32 {
        self.apply_calls.load(Ordering::SeqCst)
    }

    fn unique_applied(&self) -> usize {
        self.applied_lsn
            .lock()
            .map(|applied| applied.len())
            .unwrap_or_default()
    }
}

impl Projector for FaultMatrixProjectionProjector {
    async fn apply<E: ProjectionEvent>(
        &self,
        event: &E,
    ) -> Result<ProjectionApplyOutcome, ProjectionApplyError> {
        self.apply_calls.fetch_add(1, Ordering::SeqCst);
        let mut applied = self.applied_lsn.lock().map_err(|_| {
            ProjectionApplyError::from_reason(
                consistency::ProjectionApplyErrorReason::ProviderInvariant,
            )
        })?;
        applied.insert(event.lsn().get());
        Ok(ProjectionApplyOutcome::Applied)
    }
}

struct FaultMatrixProjectionSource;

impl PartitionSerialDelivery for FaultMatrixProjectionSource {}

struct FailOnceCheckpoint<C> {
    inner: Arc<C>,
    fail_next_save: AtomicBool,
}

impl<C> FailOnceCheckpoint<C> {
    fn new(inner: Arc<C>) -> Self {
        Self {
            inner,
            fail_next_save: AtomicBool::new(true),
        }
    }
}

impl<C> OwnerCheckpointStore for FailOnceCheckpoint<C>
where
    C: OwnerCheckpointStore + Send + Sync,
{
    async fn get_checkpoint(
        &self,
        owner: &CheckpointOwner,
        id: &CheckpointId,
    ) -> Result<Option<Checkpoint>, CheckpointStoreError> {
        self.inner.get_checkpoint(owner, id).await
    }

    async fn save_checkpoint(
        &self,
        owner: &CheckpointOwner,
        id: &CheckpointId,
        offset: Lsn,
        expected: CheckpointVersion,
    ) -> Result<SaveOutcome, CheckpointStoreError> {
        if self.fail_next_save.swap(false, Ordering::SeqCst) {
            Err(CheckpointStoreError::new(std::io::Error::other(
                "fault matrix checkpoint save failure",
            )))
        } else {
            self.inner
                .save_checkpoint(owner, id, offset, expected)
                .await
        }
    }

    async fn shutdown(&self) -> Result<(), CheckpointStoreError> {
        self.inner.shutdown().await
    }
}

fn fault_matrix_projection_event(
    tenant: vocab::TenantId,
    lsn: Lsn,
) -> FaultMatrixResult<ProjectionEventRecord> {
    let metadata = ProjectionEventMetadata::new(
        tenant,
        format!("projection-event-{}", lsn.get()),
        "audit",
        "audit.session-projection",
        "v1",
        SCHEMA_HASH,
        serde_json::json!({
            "tenantId": tenant.to_string(),
            "schemaVersion": "v1",
            "schemaHash": SCHEMA_HASH
        }),
        Some(format!("projection-partition-{}", lsn.get())),
        None,
    );
    Ok(ProjectionEventRecord::with_metadata(
        lsn,
        EventTopic::parse("audit.session-projection")?,
        vec![0x70],
        metadata,
    ))
}

fn metadata_json(tenant: vocab::TenantId) -> String {
    serde_json::json!({
        "tenantId": tenant.to_string(),
        "schemaVersion": "v1",
        "schemaHash": SCHEMA_HASH
    })
    .to_string()
}

#[derive(Clone)]
struct RecordingPublisher {
    result: FaultMatrixPublishOutcome,
    message_ids: Option<Arc<Mutex<Vec<String>>>>,
}

impl RecordingPublisher {
    fn ok() -> Self {
        Self {
            result: FaultMatrixPublishOutcome::Ok,
            message_ids: None,
        }
    }

    fn transient() -> Self {
        Self {
            result: FaultMatrixPublishOutcome::Transient,
            message_ids: None,
        }
    }

    fn permanent() -> Self {
        Self {
            result: FaultMatrixPublishOutcome::Permanent,
            message_ids: None,
        }
    }
}

impl Publisher for RecordingPublisher {
    async fn publish(&self, request: PublishRequest) -> Result<(), PublisherError> {
        if let Some(message_ids) = &self.message_ids {
            message_ids
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(request.event_id().as_str().to_string());
        }
        match self.result {
            FaultMatrixPublishOutcome::Ok => Ok(()),
            FaultMatrixPublishOutcome::Transient => Err(PublisherError::transient(
                std::io::Error::other("fault matrix transient publish failure"),
            )),
            FaultMatrixPublishOutcome::Permanent => Err(PublisherError::permanent(
                std::io::Error::other("fault matrix permanent publish failure"),
            )),
        }
    }

    async fn shutdown(&self) -> Result<(), PublisherError> {
        Ok(())
    }
}

#[derive(Debug)]
struct TestMac;

impl MacVerifier for TestMac {
    fn sign(&self, key: &MacKey, _algorithm: MacAlgorithm, message: &[u8]) -> Mac {
        use sha2::Digest as _;

        let mut hasher = sha2::Sha256::new();
        hasher.update(key.as_bytes());
        hasher.update(message);
        Mac::from_bytes(hasher.finalize().to_vec())
    }

    fn verify(&self, key: &MacKey, algorithm: MacAlgorithm, message: &[u8], tag: &Mac) -> bool {
        self.sign(key, algorithm, message).as_bytes() == tag.as_bytes()
    }
}

fn test_tenant_authority() -> FaultMatrixResult<Arc<TenantAuthority>> {
    Ok(Arc::new(TenantAuthority::new(
        Arc::new(TestMac),
        MacKey::from_bytes(vec![0x42; 32]),
        3600,
        60,
        Arc::new(|| 1_700_000_000),
    )?))
}

struct FaultMatrixKeyProvider;

impl KeyProvider for FaultMatrixKeyProvider {
    async fn encrypt(
        &self,
        key: KeyName,
        plaintext: Plaintext,
        _aad: secure::DerivedAad,
    ) -> Result<EncryptOutput, KeyProviderError> {
        Ok(EncryptOutput::new(
            plaintext
                .expose()
                .iter()
                .map(|byte| byte ^ 0xA5)
                .collect::<Vec<_>>(),
            KeyRef::new(key, KeyVersion::new(1)),
        ))
    }

    async fn decrypt(
        &self,
        ciphertext: RedactedBytes,
        _key: KeyRef,
        _aad: secure::DerivedAad,
    ) -> Result<Plaintext, KeyProviderError> {
        Ok(Plaintext::new(
            ciphertext
                .into_bytes()
                .into_iter()
                .map(|byte| byte ^ 0xA5)
                .collect(),
        ))
    }

    async fn rewrap(
        &self,
        ciphertext: RedactedBytes,
        key: KeyRef,
        aad: secure::DerivedAad,
    ) -> Result<EncryptOutput, KeyProviderError> {
        let plaintext = self.decrypt(ciphertext, key.clone(), aad.clone()).await?;
        self.encrypt(key.name().clone(), plaintext, aad).await
    }

    async fn shutdown(&self) -> Result<(), KeyProviderError> {
        Ok(())
    }
}

fn test_dlx_payload_protector() -> FaultMatrixResult<DlxPayloadProtector> {
    Ok(DlxPayloadProtector::new(
        DynKeyProvider::new_box(FaultMatrixKeyProvider),
        eventexec::DlxHotKeyName::try_new("fault-matrix-dlx")?,
    ))
}

fn test_saga_receipt_protection() -> FaultMatrixResult<crate::PgSagaReceiptProtection> {
    let integrity = secure::SagaReceiptIntegrityKeyring::new(
        secure::VersionedSagaReceiptIntegrityKey::new(
            secure::SagaReceiptIntegrityKeyId::parse("fault-matrix-v1")?,
            secure::RedactionHashKey::from_bytes(vec![0x24; 32])?,
        ),
        Vec::new(),
    )?;
    Ok(crate::PgSagaReceiptProtection::new(
        DynKeyProvider::new_box(FaultMatrixKeyProvider),
        integrity,
    ))
}

#[cfg(test)]
mod tests {
    use consistency::IdemKey;
    use identity::ports::FaultMatrixSessionCreatedPayload;
    use sha2::{Digest as _, Sha256};

    use super::{
        FaultMatrixCertificateCommand, FaultMatrixOutboxRetryObservation, FaultMatrixOutboxStatus,
        FaultMatrixResult, FaultMatrixSagaCompletionInjection, FaultMatrixSagaObservation,
        FaultMatrixSessionCreatedInput, SagaFaultObservationRow, completion_injection_outcome,
        lease_expiry_outcome, review_certificate_reconcile_commands,
    };

    fn certificate_command(
        _tenant: vocab::TenantId,
        idempotency_key: &str,
    ) -> FaultMatrixResult<FaultMatrixCertificateCommand> {
        let semantic_suffix = format!("{:x}", Sha256::digest(idempotency_key.as_bytes()));
        Ok(crate::reconcile_test_driver::canonical_device_command(
            serde_json::json!({
                "deviceId": "b497a9ce-6ac5-4d44-a0a3-869af114db5f",
                "desiredGeneration": 2,
                "fenceEpoch": 1,
                "policyHash": format!("sha256:{}", "1".repeat(64)),
                "artifactId": format!("certificate-artifact-1-{}", &semantic_suffix[..16]),
                "artifactDigest": format!("sha256:{}", "2".repeat(64)),
                "deadlineEpochSeconds": 42
            }),
        )?)
    }

    fn certificate_attempt(tenant: vocab::TenantId) -> eventexec::reconcile::ReconcileAttempt {
        let target = eventexec::reconcile::ClaimedTarget::restore(
            eventexec::reconcile::ClaimedTargetRestore {
                tenant,
                target_id: "11111111-1111-1111-1111-111111111111".to_owned(),
                reconciler_id: "identity.device-certificate".to_owned(),
                resource_kind: "device-certificate".to_owned(),
                resource_id: "b497a9ce-6ac5-4d44-a0a3-869af114db5f".to_owned(),
                lease_token: "22222222-2222-2222-2222-222222222222".to_owned(),
                epoch: 1,
                failure_streak: eventexec::reconcile::FailureStreak::restore(0),
                wake_version: eventexec::reconcile::WakeVersion::try_new(1).expect("wake version"),
                trigger: eventexec::AttemptTrigger::Resync,
            },
        );
        eventexec::reconcile::ReconcileAttempt::new("fault-matrix-attempt", target)
    }

    fn generated_session_payload(
        tenant: vocab::TenantId,
        session_id: uuid::Uuid,
    ) -> FaultMatrixSessionCreatedPayload {
        FaultMatrixSessionCreatedPayload {
            occurred_at: 1_700_000_000,
            session_id: session_id.to_string(),
            subject: uuid::Uuid::from_u128(7),
            tenant_id: tenant.to_string(),
        }
    }

    #[test]
    fn session_created_input_derives_identity_from_exact_generated_payload() -> FaultMatrixResult<()>
    {
        let tenant = vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")?;
        let session_id = uuid::Uuid::from_u128(9);
        let input = FaultMatrixSessionCreatedInput::new(
            generated_session_payload(tenant, session_id),
            IdemKey::parse("fault-matrix-session-created")?,
        )?;
        assert_eq!(input.event_id(), "fault-matrix-session-created");
        assert_eq!(input.tenant, tenant);
        assert_eq!(input.session_id, session_id);
        Ok(())
    }

    #[test]
    fn session_created_input_rejects_invalid_payload_tenant_identity() -> FaultMatrixResult<()> {
        let payload = FaultMatrixSessionCreatedPayload {
            occurred_at: 1_700_000_000,
            session_id: uuid::Uuid::from_u128(9).to_string(),
            subject: uuid::Uuid::from_u128(7),
            tenant_id: "not-a-tenant".to_string(),
        };
        assert!(
            FaultMatrixSessionCreatedInput::new(
                payload,
                IdemKey::parse("fault-matrix-invalid-tenant")?,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn session_created_input_rejects_invalid_payload_session_identity() -> FaultMatrixResult<()> {
        let tenant = vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")?;
        let payload = FaultMatrixSessionCreatedPayload {
            occurred_at: 1_700_000_000,
            session_id: "not-a-session".to_string(),
            subject: uuid::Uuid::from_u128(7),
            tenant_id: tenant.to_string(),
        };
        assert!(
            FaultMatrixSessionCreatedInput::new(
                payload,
                IdemKey::parse("fault-matrix-invalid-session")?,
            )
            .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn certificate_reconcile_commands_are_reviewed_with_stable_sealed_aliases()
    -> FaultMatrixResult<()> {
        let tenant = vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")?;
        let raw_key = "fault-matrix-certificate-dispatch";
        let attempt = certificate_attempt(tenant);
        let [first, retry] = review_certificate_reconcile_commands(
            [
                certificate_command(tenant, raw_key)?,
                certificate_command(tenant, raw_key)?,
            ],
            &attempt,
        )
        .await?;
        let first_alias = first
            .aliases()
            .current()
            .expect("current alias is required");
        let retry_alias = retry
            .aliases()
            .current()
            .expect("current alias is required");

        assert_eq!(first_alias.key_id(), retry_alias.key_id());
        assert_eq!(first_alias.digest(), retry_alias.digest());
        assert!(!format!("{:?}", first.aliases()).contains(raw_key));
        Ok(())
    }

    #[test]
    fn outbox_retry_observation_accepts_closed_retry_state() -> FaultMatrixResult<()> {
        let observation = FaultMatrixOutboxRetryObservation::try_from_row(Some((
            "pending".to_string(),
            1,
            true,
            true,
        )))?;
        assert_eq!(observation.status(), FaultMatrixOutboxStatus::Pending);
        assert_eq!(observation.retry_count(), 1);
        assert!(observation.retry_after_scheduled());
        assert!(observation.lease_cleared());
        Ok(())
    }

    #[test]
    fn outbox_retry_observation_rejects_missing_row() {
        assert!(FaultMatrixOutboxRetryObservation::try_from_row(None).is_err());
    }

    #[test]
    fn outbox_retry_observation_rejects_unknown_status() {
        let row = Some(("publishing".to_string(), 1, true, true));
        assert!(FaultMatrixOutboxRetryObservation::try_from_row(row).is_err());
    }

    #[test]
    fn outbox_retry_observation_rejects_negative_retry_count() {
        let row = Some(("pending".to_string(), -1, true, true));
        assert!(FaultMatrixOutboxRetryObservation::try_from_row(row).is_err());
    }

    #[test]
    fn saga_observation_classifies_only_closed_redacted_counts() -> FaultMatrixResult<()> {
        let observation = FaultMatrixSagaObservation::try_from_row(SagaFaultObservationRow {
            status: "operator_required".to_string(),
            operator_reason: Some("receipt_integrity".to_string()),
            epoch: 7,
            active_lease: false,
            forward_intents: 3,
            forward_completions: 1,
            forward_not_applied: 2,
            compensation_intents: 1,
            compensation_completions: 1,
            compensation_not_applied: 0,
            compensation_failures: 1,
            receipts: 1,
        })?;

        assert_eq!(
            observation.status(),
            consistency::SagaInstanceStatus::OperatorRequired
        );
        assert_eq!(observation.epoch(), 7);
        assert!(!observation.active_lease());
        assert_eq!(observation.journal().forward_intents(), 3);
        assert_eq!(observation.journal().forward_completions(), 1);
        assert_eq!(observation.journal().forward_not_applied(), 2);
        assert_eq!(observation.journal().compensation_intents(), 1);
        assert_eq!(observation.journal().compensation_completions(), 1);
        assert_eq!(observation.journal().compensation_not_applied(), 0);
        assert_eq!(observation.journal().compensation_failures(), 1);
        assert_eq!(observation.receipts(), 1);
        assert_eq!(
            observation.operator_reason(),
            Some(consistency::SagaOperatorReason::ReceiptIntegrity)
        );
        Ok(())
    }

    #[test]
    fn saga_observation_rejects_invalid_or_negative_database_values() {
        let invalid_status = SagaFaultObservationRow {
            status: "foreign".to_string(),
            operator_reason: None,
            epoch: 1,
            active_lease: false,
            forward_intents: 0,
            forward_completions: 0,
            forward_not_applied: 0,
            compensation_intents: 0,
            compensation_completions: 0,
            compensation_not_applied: 0,
            compensation_failures: 0,
            receipts: 0,
        };
        assert!(FaultMatrixSagaObservation::try_from_row(invalid_status).is_err());

        let negative_epoch = SagaFaultObservationRow {
            status: "running".to_string(),
            operator_reason: None,
            epoch: -1,
            active_lease: false,
            forward_intents: 0,
            forward_completions: 0,
            forward_not_applied: 0,
            compensation_intents: 0,
            compensation_completions: 0,
            compensation_not_applied: 0,
            compensation_failures: 0,
            receipts: 0,
        };
        assert!(FaultMatrixSagaObservation::try_from_row(negative_epoch).is_err());

        let missing_operator_reason = SagaFaultObservationRow {
            status: "operator_required".to_string(),
            operator_reason: None,
            epoch: 1,
            active_lease: false,
            forward_intents: 0,
            forward_completions: 0,
            forward_not_applied: 0,
            compensation_intents: 0,
            compensation_completions: 0,
            compensation_not_applied: 0,
            compensation_failures: 0,
            receipts: 0,
        };
        assert!(FaultMatrixSagaObservation::try_from_row(missing_operator_reason).is_err());
    }

    #[test]
    fn competing_completion_preserves_exact_duplicate_and_conflict_outcomes()
    -> FaultMatrixResult<()> {
        assert_eq!(
            completion_injection_outcome(diport::SagaDurableMutationOutcome::IdempotentDuplicate)?,
            FaultMatrixSagaCompletionInjection::ExactDuplicate
        );
        assert_eq!(
            completion_injection_outcome(diport::SagaDurableMutationOutcome::Conflict)?,
            FaultMatrixSagaCompletionInjection::Conflict
        );
        Ok(())
    }

    #[test]
    fn active_lease_expiry_maps_exact_cas_cardinality() -> FaultMatrixResult<()> {
        assert_eq!(
            lease_expiry_outcome(1)?,
            super::FaultMatrixSagaLeaseExpiry::Expired
        );
        assert_eq!(
            lease_expiry_outcome(0)?,
            super::FaultMatrixSagaLeaseExpiry::Lost
        );
        assert!(lease_expiry_outcome(2).is_err());
        Ok(())
    }
}
