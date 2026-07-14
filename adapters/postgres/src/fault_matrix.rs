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
    CompensationOutcome, ConsumerGroup, ConvergeAction, EngineError, EngineErrorKind, EventTopic,
    IdemKey, InboxReceiptContext, InboxStore, LeaseOutcome, LeaseToken, Lsn, OutboxRelay,
    PartitionSerialDelivery, ProjectionApplyOutcome, ProjectionEvent, ProjectionEventMetadata,
    ProjectionEventRecord, Projector, SagaId, SagaInstanceRef, SagaJournalAppendRecord, SagaStep,
    SagaStepCtx, SeenState, SerialInOrder, StepName,
};
use diport::{
    Checkpoint, CheckpointId, CheckpointOwner, CheckpointStoreError, CheckpointVersion,
    DeadLetterSource, DynKeyProvider, DynPublisher, EncryptOutput, KeyName, KeyProvider,
    KeyProviderError, KeyRef, KeyVersion, LockStore, ManagedResource, OwnerCheckpointStore,
    PublishRequest, Publisher, PublisherError, RedactedBytes, SagaContractId,
    SagaInstanceRegistration, SagaInstanceStore, SagaJournal, SagaWorkerIdentity, SaveOutcome,
};
use eventexec::reconcile::{
    ReconcileScheduleStore, ReviewedCommand, ScheduleActionOutcome, ScheduleAttemptOutcome,
};
use eventexec::{
    ProjectionHarness, ProjectionStop, SagaExecutor, SagaExecutorConfig, SagaExecutorDeps,
    SagaExecutorImpl, SagaOutcome, SagaRuntimeLock, TenantAuthority, TypedSagaActionFactory,
};
use primitives::{Mac, MacAlgorithm, MacKey, MacVerifier};
use secure::Plaintext;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode as SqlxPgSslMode};
use sqlx::{PgPool, Row};

use crate::{DlxPayloadProtector, PgConfig, PgPassword, PgRuntimeDeps, PgSslMode};

mod saga_fixture;

const RSS_APP_ROLE: &str = "rss_app";
const SCHEMA_HASH: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// Error returned by the fault-matrix harness.
pub type FaultMatrixResult<T> = anyhow::Result<T>;

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

/// Saga runtime probe produced through `SagaExecutor::resume`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FaultMatrixSagaProbe {
    reserve_forward_count: u32,
    charge_forward_count: u32,
    reserve_compensation_count: u32,
    charge_compensation_count: u32,
}

impl FaultMatrixSagaProbe {
    pub fn reserve_forward_count(&self) -> u32 {
        self.reserve_forward_count
    }

    pub fn charge_forward_count(&self) -> u32 {
        self.charge_forward_count
    }

    pub fn reserve_compensation_count(&self) -> u32 {
        self.reserve_compensation_count
    }

    pub fn charge_compensation_count(&self) -> u32 {
        self.charge_compensation_count
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
}

impl PgFaultMatrixHarness {
    /// Provision the least-privilege serving role, run migrations, and construct runtime deps.
    pub async fn setup(
        config: PgFaultMatrixConfig,
        projection_generation: &'static str,
        projection_inputs: &'static [vocab::ProjectionInputBinding],
    ) -> FaultMatrixResult<Self> {
        let serving_password = format!("rss_app_{}", uuid::Uuid::new_v4().simple());
        provision_rss_app_login(&config, &serving_password).await?;
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
            &serving_password,
        );
        let deps = PgRuntimeDeps::setup(
            &migrator,
            &serving,
            projection_generation,
            projection_inputs,
        )
        .await?;
        let owner_pool = owner_pool(&config).await?;
        Ok(Self { deps, owner_pool })
    }

    /// Close private postgres resources.
    pub async fn shutdown(self) -> FaultMatrixResult<()> {
        let (resources, _sampler_factory) = self.deps.into_runtime_parts(Duration::from_secs(1));
        self.owner_pool.close().await;
        for resource in resources.into_iter().rev() {
            resource.shutdown().await?;
        }
        Ok(())
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
        let publisher = outcome.publisher();
        let outbox = match domain {
            "identity" => self
                .deps
                .handle()
                .for_domain::<crate::caps::Identity>()
                .outbox(
                    publisher,
                    test_tenant_authority()?,
                    test_dlx_payload_protector()?,
                ),
            "settings" => self
                .deps
                .handle()
                .for_domain::<crate::caps::Settings>()
                .outbox(
                    publisher,
                    test_tenant_authority()?,
                    test_dlx_payload_protector()?,
                ),
            _ => bail!("unsupported fault-matrix outbox domain `{domain}`"),
        };
        let claimed = outbox
            .claim_batch(10)
            .await?
            .into_iter()
            .find(|entry| entry.idem_key().as_str() == event_id)
            .ok_or_else(|| anyhow!("seeded outbox row was not claimed"))?;
        outbox.relay(claimed).await?;
        Ok(())
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
            "identity.session-created",
            FaultMatrixOutboxStatus::Pending,
        )
        .await?;
        crate::outbox::fault_matrix_publish_before_settle(
            &self.owner_pool,
            publisher,
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
        age_outbox_publishing(&self.owner_pool, tenant, event_id).await?;
        let outbox = match domain {
            "identity" => self
                .deps
                .handle()
                .for_domain::<crate::caps::Identity>()
                .outbox(
                    publisher,
                    test_tenant_authority()?,
                    test_dlx_payload_protector()?,
                ),
            "settings" => self
                .deps
                .handle()
                .for_domain::<crate::caps::Settings>()
                .outbox(
                    publisher,
                    test_tenant_authority()?,
                    test_dlx_payload_protector()?,
                ),
            _ => bail!("unsupported fault-matrix outbox domain `{domain}`"),
        };
        let claimed = outbox
            .claim_batch(10)
            .await?
            .into_iter()
            .find(|entry| entry.entry().idem_key().as_str() == event_id)
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
        let ctx = inbox_ctx(tenant, group)?;
        let first = LeaseToken::mint();
        let key = IdemKey::parse(event_id)?;
        let _ = store.try_claim(&ctx, &key, &first).await?;
        age_inbox_claim(&self.owner_pool, tenant, event_id, group).await?;
        let second = LeaseToken::mint();
        Ok(store.try_claim(&ctx, &key, &second).await?)
    }

    /// Drive claim+commit, then replay the same key through `PgInboxStore`.
    pub async fn commit_then_redeliver_inbox(
        &self,
        tenant: vocab::TenantId,
        event_id: &str,
        group: &str,
    ) -> FaultMatrixResult<SeenState> {
        let store = self.deps.handle().infra().inbox();
        let ctx = inbox_ctx(tenant, group)?;
        let key = IdemKey::parse(event_id)?;
        let first = LeaseToken::mint();
        let _ = store.try_claim(&ctx, &key, &first).await?;
        let committed = store.commit(&ctx, &key, &first).await?;
        if committed != LeaseOutcome::Held {
            bail!("inbox commit lost lease");
        }
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
        let ctx = inbox_ctx(tenant, group)?;
        let key = IdemKey::parse(event_id)?;
        let lease = LeaseToken::mint();
        let _ = store.try_claim(&ctx, &key, &lease).await?;
        store.release(&ctx, &key, &lease).await?;
        Ok(store.commit(&ctx, &key, &lease).await?)
    }

    /// Resume a saga with the first forward step already completed in the journal.
    pub async fn saga_forward_resume_skips_completed<L>(
        &self,
        tenant: vocab::TenantId,
        saga_uuid: uuid::Uuid,
        spec: vocab::SagaContractBinding,
        runtime_lock: L,
    ) -> FaultMatrixResult<FaultMatrixSagaProbe>
    where
        L: LockStore + Send + Sync + 'static,
    {
        let infra = self.deps.handle().infra();
        let instances = infra.saga_instance_store();
        let journal = infra.saga_journal();
        let instance = saga_instance(tenant, saga_uuid)?;
        instances
            .register(fault_matrix_saga_registration(instance)?)
            .await?;
        let lease = instances
            .acquire_lease(&instance, "fault-matrix", Duration::from_secs(60))
            .await?
            .ok_or_else(|| anyhow!("saga lease not acquired"))?;
        let step = StepName::parse("reserve_funds")?;
        journal
            .append(&lease, SagaJournalAppendRecord::completed(0, step))
            .await?;
        instances.release_lease(&lease).await?;

        let factory = FaultMatrixSagaFactory::new(false, false);
        let typed_factory = factory.typed_factory(spec)?;
        let exec = self.saga_executor(journal, instances, typed_factory, runtime_lock)?;
        let outcome = exec.resume(instance).await;
        if !matches!(outcome, SagaOutcome::Succeeded { .. }) {
            bail!("saga resume should succeed after completed first step, got {outcome:?}");
        }
        Ok(factory.probe())
    }

    /// Resume a saga whose compensation crashed after starting the last completed step.
    pub async fn saga_compensation_resume_once<L>(
        &self,
        tenant: vocab::TenantId,
        saga_uuid: uuid::Uuid,
        spec: vocab::SagaContractBinding,
        runtime_lock: L,
    ) -> FaultMatrixResult<FaultMatrixSagaProbe>
    where
        L: LockStore + Send + Sync + 'static,
    {
        let infra = self.deps.handle().infra();
        let instances = infra.saga_instance_store();
        let journal = infra.saga_journal();
        let instance = saga_instance(tenant, saga_uuid)?;
        instances
            .register(fault_matrix_saga_registration(instance)?)
            .await?;
        let lease = instances
            .acquire_lease(&instance, "fault-matrix", Duration::from_secs(60))
            .await?
            .ok_or_else(|| anyhow!("saga lease not acquired"))?;
        let reserve = StepName::parse("reserve_funds")?;
        let capture = StepName::parse("capture")?;
        journal
            .append(
                &lease,
                SagaJournalAppendRecord::completed(0, reserve.clone()),
            )
            .await?;
        journal
            .append(
                &lease,
                SagaJournalAppendRecord::completed(1, capture.clone()),
            )
            .await?;
        journal
            .append(&lease, SagaJournalAppendRecord::compensating(2, capture))
            .await?;
        instances.release_lease(&lease).await?;

        let factory = FaultMatrixSagaFactory::new(false, false);
        let typed_factory = factory.typed_factory(spec)?;
        let exec = self.saga_executor(journal, instances, typed_factory, runtime_lock)?;
        let outcome = exec.resume(instance).await;
        if !matches!(outcome, SagaOutcome::Failed { .. }) {
            bail!(
                "saga compensation resume should finish failed after compensation, got {outcome:?}"
            );
        }
        Ok(factory.probe())
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
        commands: [ReviewedCommand; 2],
    ) -> FaultMatrixResult<i64> {
        let store = self.deps.handle().infra().reconcile();
        let key = crate::ReconcileTargetKey::parse("fault-matrix", "device", dispatch_key)?;
        let target = store.upsert_target(tenant, &key).await?;
        let claimed = store
            .claim_due_targets(
                tenant,
                "fault-matrix",
                "fault-matrix",
                1,
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
        for command in [first, retry] {
            let outcome = store
                .record_action_and_enqueue_command(&attempt, ConvergeAction::Update, command)
                .await?;
            if outcome != ScheduleActionOutcome::Enqueued {
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
    ) -> FaultMatrixResult<crate::ReconcileLeaseOutcome> {
        let store = self.deps.handle().infra().reconcile();
        let key = crate::ReconcileTargetKey::parse("fault-matrix", "device", target_suffix)?;
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
        if lost != crate::ReconcileLeaseOutcome::Held {
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
            .await?)
    }

    fn saga_executor<L>(
        &self,
        journal: crate::PgSagaJournal,
        instances: crate::PgSagaInstanceStore,
        factory: TypedSagaActionFactory,
        runtime_lock: L,
    ) -> FaultMatrixResult<
        SagaExecutorImpl<
            crate::PgSagaJournal,
            crate::PgCheckpointStore,
            crate::PgDeadLetterStore,
            crate::PgSagaInstanceStore,
        >,
    >
    where
        L: LockStore + Send + Sync + 'static,
    {
        let infra = self.deps.handle().infra();
        let config = SagaExecutorConfig::from_typed_factory(
            CheckpointOwner::new("billing"),
            "fault-matrix",
            Duration::from_secs(60),
            &factory,
        )?;
        Ok(SagaExecutorImpl::new(
            SagaExecutorDeps::new(
                Arc::new(journal),
                Arc::new(instances),
                Arc::new(infra.checkpoint()),
                Arc::new(infra.dead_letter(test_dlx_payload_protector()?)),
                factory,
                SagaRuntimeLock::new(runtime_lock),
            ),
            config,
        ))
    }
}

/// Publisher outcome used by the outbox fault matrix.
#[derive(Debug, Clone, Copy)]
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

async fn provision_rss_app_login(
    config: &PgFaultMatrixConfig,
    password: &str,
) -> FaultMatrixResult<()> {
    if !password
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        bail!("generated rss_app password contains an unsafe SQL literal byte");
    }
    let pool = owner_pool(config).await?;
    sqlx::query(
        r#"
        DO $$
        BEGIN
            PERFORM pg_advisory_xact_lock(hashtext('rss_app'));
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'rss_app') THEN
                CREATE ROLE rss_app LOGIN NOBYPASSRLS;
            ELSE
                ALTER ROLE rss_app LOGIN NOBYPASSRLS;
            END IF;
        END
        $$;
        "#,
    )
    .execute(&pool)
    .await?;
    sqlx::query(&format!(
        "ALTER ROLE {RSS_APP_ROLE} LOGIN PASSWORD '{password}' NOBYPASSRLS"
    ))
    .execute(&pool)
    .await?;
    pool.close().await;
    Ok(())
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
) -> FaultMatrixResult<()> {
    sqlx::query(
        "UPDATE outbox \
         SET updated_at = clock_timestamp() - make_interval(secs => $4::int), \
             lease_until = clock_timestamp() - interval '1 second' \
         WHERE tenant_id = $1::uuid AND event_id = $2 AND status = $3",
    )
    .bind(tenant.to_string())
    .bind(event_id)
    .bind(crate::outbox::STATUS_PUBLISHING)
    .bind(crate::outbox::LEASE_TTL_SECONDS + 10)
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

fn inbox_ctx(tenant: vocab::TenantId, group: &str) -> FaultMatrixResult<InboxReceiptContext> {
    Ok(InboxReceiptContext::new(
        tenant,
        ConsumerGroup::parse(group)?,
        "identity",
        "identity.session-created",
        "identity.session-created",
        "v1",
        SCHEMA_HASH,
        None,
        None,
    )?)
}

fn saga_instance(
    tenant: vocab::TenantId,
    saga_uuid: uuid::Uuid,
) -> FaultMatrixResult<SagaInstanceRef> {
    Ok(SagaInstanceRef::new(tenant, SagaId::new(saga_uuid))?)
}

fn fault_matrix_saga_registration(
    instance: SagaInstanceRef,
) -> FaultMatrixResult<SagaInstanceRegistration> {
    let identity = SagaWorkerIdentity::new("billing", SagaContractId::parse("billing.checkout")?)?;
    Ok(SagaInstanceRegistration::new(instance, identity))
}

struct FaultMatrixSagaFactory {
    reserve: FaultMatrixSagaStepState,
    capture: FaultMatrixSagaStepState,
}

impl FaultMatrixSagaFactory {
    fn new(reserve_forward_fails: bool, capture_forward_fails: bool) -> Self {
        Self {
            reserve: FaultMatrixSagaStepState::new(reserve_forward_fails),
            capture: FaultMatrixSagaStepState::new(capture_forward_fails),
        }
    }

    fn typed_factory(
        &self,
        spec: vocab::SagaContractBinding,
    ) -> FaultMatrixResult<TypedSagaActionFactory> {
        let mut builder = TypedSagaActionFactory::builder(spec);
        let reserve = self.reserve.clone();
        builder.register_step::<FaultMatrixReserveFundsStep, _>(move || {
            FaultMatrixReserveFundsStep {
                state: reserve.clone(),
            }
        })?;
        let capture = self.capture.clone();
        builder.register_step::<FaultMatrixCaptureStep, _>(move || FaultMatrixCaptureStep {
            state: capture.clone(),
        })?;
        Ok(builder.finish()?)
    }

    fn probe(&self) -> FaultMatrixSagaProbe {
        FaultMatrixSagaProbe {
            reserve_forward_count: self.reserve.forward_count.load(Ordering::SeqCst),
            charge_forward_count: self.capture.forward_count.load(Ordering::SeqCst),
            reserve_compensation_count: self.reserve.compensation_count.load(Ordering::SeqCst),
            charge_compensation_count: self.capture.compensation_count.load(Ordering::SeqCst),
        }
    }
}

#[derive(Debug, Clone)]
struct FaultMatrixSagaStepState {
    forward_fails: bool,
    forward_count: Arc<AtomicU32>,
    compensation_count: Arc<AtomicU32>,
}

impl FaultMatrixSagaStepState {
    fn new(forward_fails: bool) -> Self {
        Self {
            forward_fails,
            forward_count: Arc::new(AtomicU32::new(0)),
            compensation_count: Arc::new(AtomicU32::new(0)),
        }
    }
}

#[derive(Debug)]
struct FaultMatrixReserveFundsStep {
    state: FaultMatrixSagaStepState,
}

impl SagaStep for FaultMatrixReserveFundsStep {
    const BINDING: vocab::SagaStepBinding = saga_fixture::RESERVE_STEP;

    type Output = saga_fixture::ReserveFundsOutput;

    async fn execute(&self, _ctx: SagaStepCtx) -> Result<Self::Output, EngineError> {
        let state = self.state.clone();
        fault_matrix_saga_execute(state)?;
        Ok(saga_fixture::ReserveFundsOutput::new("reserve_funds"))
    }

    async fn compensate(&self, _ctx: SagaStepCtx) -> Result<CompensationOutcome, EngineError> {
        let state = self.state.clone();
        state.compensation_count.fetch_add(1, Ordering::SeqCst);
        Ok(CompensationOutcome::Compensated)
    }
}

#[derive(Debug)]
struct FaultMatrixCaptureStep {
    state: FaultMatrixSagaStepState,
}

impl SagaStep for FaultMatrixCaptureStep {
    const BINDING: vocab::SagaStepBinding = saga_fixture::CAPTURE_STEP;

    type Output = saga_fixture::CaptureOutput;

    async fn execute(&self, _ctx: SagaStepCtx) -> Result<Self::Output, EngineError> {
        let state = self.state.clone();
        fault_matrix_saga_execute(state)?;
        Ok(saga_fixture::CaptureOutput::new("capture"))
    }

    async fn compensate(&self, _ctx: SagaStepCtx) -> Result<CompensationOutcome, EngineError> {
        let state = self.state.clone();
        state.compensation_count.fetch_add(1, Ordering::SeqCst);
        Ok(CompensationOutcome::Compensated)
    }
}

fn fault_matrix_saga_execute(state: FaultMatrixSagaStepState) -> Result<(), EngineError> {
    state.forward_count.fetch_add(1, Ordering::SeqCst);
    if state.forward_fails {
        Err(EngineError::new(EngineErrorKind::Transient))
    } else {
        Ok(())
    }
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
    ) -> Result<ProjectionApplyOutcome, EngineError> {
        self.apply_calls.fetch_add(1, Ordering::SeqCst);
        let mut applied = self
            .applied_lsn
            .lock()
            .map_err(|_| EngineError::new(EngineErrorKind::Invariant))?;
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
}

impl RecordingPublisher {
    fn ok() -> Self {
        Self {
            result: FaultMatrixPublishOutcome::Ok,
        }
    }

    fn transient() -> Self {
        Self {
            result: FaultMatrixPublishOutcome::Transient,
        }
    }

    fn permanent() -> Self {
        Self {
            result: FaultMatrixPublishOutcome::Permanent,
        }
    }
}

impl Publisher for RecordingPublisher {
    async fn publish(&self, _request: PublishRequest) -> Result<(), PublisherError> {
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
        let mut tag = Vec::from(key.as_bytes());
        tag.extend_from_slice(message);
        Mac::from_bytes(tag)
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
