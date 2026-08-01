//! Real PostgreSQL/Redis Saga fault-recovery journeys for #1928.

#![cfg(feature = "integration")]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail, ensure};
use consistency::{
    CompensationOutcome, EngineError, EngineErrorKind, SagaDefinitionIdentity, SagaEffectPhase,
    SagaId, SagaIdempotencyKey, SagaInstanceRef, SagaInstanceStatus, SagaOperatorReason,
};
use deadpool_redis::{Config as RedisConfig, Runtime as RedisRuntime};
use diport::{CheckpointOwner, ManagedResource, SagaStartAuditId, SagaWorkerIdentity};
use eventexec::{
    RelayBudget, SagaAttemptOutcome, SagaCompensationContext, SagaDefinitionRegistry, SagaExecutor,
    SagaExecutorConfig, SagaExecutorDeps, SagaExecutorImpl, SagaForwardContext, SagaOutcome,
    SagaProbeOutcome, SagaStartPort, SagaStartRequest, SagaStep, TypedSagaActionFactory,
};
use futures::future::BoxFuture;
use generated::saga::{billing_v1, billing_v2};
use postgres::fault_matrix::{
    FaultMatrixSagaCompletionInjection, FaultMatrixSagaLeaseExpiry, FaultMatrixSagaObservation,
    PgFaultMatrixConfig, PgFaultMatrixHarness, PgFaultMatrixLoginCredentials, PgSagaFaultControl,
};
use postgres::{PgDeadLetterStore, PgSagaDurableStore};
use redis::{
    RedisRuntimeDeps, RedisSagaEffectApplyOutcome, RedisSagaEffectFixture,
    RedisSagaEffectObservation, RedisSagaEffectProbeOutcome,
};
use testkit::crash_matrix::{CrashFaultSpec, CrashRunner};
use tokio::sync::watch;
use uuid::Uuid;

const LEASE_TTL: Duration = Duration::from_secs(2);
const WAIT_TIMEOUT: Duration = Duration::from_secs(20);

type SagaCaseRunnerFn = fn() -> BoxFuture<'static, Result<SagaFaultEvidenceReceipt>>;

struct ReadyCaseRunner {
    _id: &'static str,
    _fault_spec: CrashFaultSpec,
    _runner: CrashRunner,
    _contract: vocab::ContractBinding,
    run: SagaCaseRunnerFn,
}

impl ReadyCaseRunner {
    const fn new(
        fault_spec: CrashFaultSpec,
        contract: vocab::ContractBinding,
        run: SagaCaseRunnerFn,
    ) -> Self {
        let Some(case) = fault_spec.saga_case() else {
            panic!("Saga runner requires Saga catalog metadata");
        };
        Self {
            _id: case.fixture_id,
            _fault_spec: fault_spec,
            _runner: fault_spec.expected_runner(),
            _contract: contract,
            run,
        }
    }
}

const READY_CASE_RUNNERS: &[ReadyCaseRunner] = &[
    ReadyCaseRunner::new(
        CrashFaultSpec::SagaForwardEffectBeforeCompletion,
        generated::saga::billing_v1::CONTRACT,
        run_saga_forward_effect_before_completion,
    ),
    ReadyCaseRunner::new(
        CrashFaultSpec::SagaCompensationBeforeJournal,
        generated::saga::billing_v1::CONTRACT,
        run_saga_compensation_before_journal,
    ),
    ReadyCaseRunner::new(
        CrashFaultSpec::SagaLeaseLostDuringCall,
        generated::saga::billing_v1::CONTRACT,
        run_saga_lease_lost_during_call,
    ),
    ReadyCaseRunner::new(
        CrashFaultSpec::SagaReceiptDuplicateConflict,
        generated::saga::billing_v1::CONTRACT,
        run_saga_receipt_duplicate_conflict,
    ),
    ReadyCaseRunner::new(
        CrashFaultSpec::SagaRetryExhaustion,
        generated::saga::billing_v1::CONTRACT,
        run_saga_retry_exhaustion,
    ),
    ReadyCaseRunner::new(
        CrashFaultSpec::SagaOldDefinitionResume,
        generated::saga::billing_v1::CONTRACT,
        run_saga_old_definition_resume,
    ),
    ReadyCaseRunner::new(
        CrashFaultSpec::SagaTenantFencingIsolation,
        generated::saga::billing_v1::CONTRACT,
        run_saga_tenant_fencing_isolation,
    ),
];

fn run_case(case: CrashFaultSpec) -> BoxFuture<'static, Result<SagaFaultEvidenceReceipt>> {
    Box::pin(async move {
        let providers = Providers::setup().await?;
        let result = execute_case(&providers, case).await;
        let cleanup = providers.shutdown().await;
        match (result, cleanup) {
            (Err(error), _) => Err(error),
            (Ok(_receipt), Err(error)) => Err(error),
            (Ok(receipt), Ok(())) => Ok(receipt),
        }
    })
}

fn run_saga_forward_effect_before_completion()
-> BoxFuture<'static, Result<SagaFaultEvidenceReceipt>> {
    run_case(CrashFaultSpec::SagaForwardEffectBeforeCompletion)
}

fn run_saga_compensation_before_journal() -> BoxFuture<'static, Result<SagaFaultEvidenceReceipt>> {
    run_case(CrashFaultSpec::SagaCompensationBeforeJournal)
}

fn run_saga_lease_lost_during_call() -> BoxFuture<'static, Result<SagaFaultEvidenceReceipt>> {
    run_case(CrashFaultSpec::SagaLeaseLostDuringCall)
}

fn run_saga_receipt_duplicate_conflict() -> BoxFuture<'static, Result<SagaFaultEvidenceReceipt>> {
    run_case(CrashFaultSpec::SagaReceiptDuplicateConflict)
}

fn run_saga_retry_exhaustion() -> BoxFuture<'static, Result<SagaFaultEvidenceReceipt>> {
    run_case(CrashFaultSpec::SagaRetryExhaustion)
}

fn run_saga_old_definition_resume() -> BoxFuture<'static, Result<SagaFaultEvidenceReceipt>> {
    run_case(CrashFaultSpec::SagaOldDefinitionResume)
}

fn run_saga_tenant_fencing_isolation() -> BoxFuture<'static, Result<SagaFaultEvidenceReceipt>> {
    run_case(CrashFaultSpec::SagaTenantFencingIsolation)
}

struct Providers {
    _pg_fixture: testkit::PgFixture,
    _redis_fixture: testkit::RedisFixture,
    pg: PgFaultMatrixHarness,
    redis: RedisRuntimeDeps,
    unavailable_redis: RedisRuntimeDeps,
    store: Arc<PgSagaDurableStore>,
    control: PgSagaFaultControl,
    effects: RedisSagaEffectFixture,
    unavailable_effects: RedisSagaEffectFixture,
}

impl Providers {
    async fn setup() -> Result<Self> {
        let mut setup = ProviderSetup::default();
        match setup.populate().await {
            Ok(parts) => setup.finish(parts),
            Err(primary) => match setup.shutdown().await {
                Ok(()) => Err(primary),
                Err(cleanup) => Err(primary.context(format!(
                    "provider setup rollback failed: {}",
                    secure::redact_error(cleanup.root_cause())
                ))),
            },
        }
    }

    async fn shutdown(self) -> Result<()> {
        let mut setup = ProviderSetup {
            pg_fixture: Some(self._pg_fixture),
            redis_fixture: Some(self._redis_fixture),
            pg: Some(self.pg),
            redis: Some(self.redis),
            unavailable_redis: Some(self.unavailable_redis),
        };
        setup.shutdown().await
    }
}

struct ProviderParts {
    store: Arc<PgSagaDurableStore>,
    control: PgSagaFaultControl,
    effects: RedisSagaEffectFixture,
    unavailable_effects: RedisSagaEffectFixture,
}

#[derive(Default)]
struct ProviderSetup {
    pg_fixture: Option<testkit::PgFixture>,
    redis_fixture: Option<testkit::RedisFixture>,
    pg: Option<PgFaultMatrixHarness>,
    redis: Option<RedisRuntimeDeps>,
    unavailable_redis: Option<RedisRuntimeDeps>,
}

impl ProviderSetup {
    async fn populate(&mut self) -> Result<ProviderParts> {
        self.pg_fixture = Some(testkit::env_or_postgres().await?);
        let parameters = self
            .pg_fixture
            .as_ref()
            .ok_or_else(|| anyhow!("PostgreSQL fixture setup lost ownership"))?
            .params();
        let config = PgFaultMatrixConfig::new(
            parameters.host.clone(),
            parameters.port,
            parameters.database.clone(),
            parameters.username.clone(),
            parameters.password.clone(),
        );
        let logins = PgFaultMatrixLoginCredentials::generate();
        testkit::provision_postgres_test_logins(
            parameters,
            &[
                testkit::PostgresTestLogin::new(logins.serving_role(), logins.serving_password()),
                testkit::PostgresTestLogin::new(logins.reader_role(), logins.reader_password()),
            ],
        )
        .await?;
        self.pg = Some(
            PgFaultMatrixHarness::setup(
                config,
                logins,
                relay_budget()?,
                eventexec::WorkflowRuntimePlan::disabled_fixture().projection_capture(),
            )
            .await?,
        );
        let pg = self
            .pg
            .as_ref()
            .ok_or_else(|| anyhow!("PostgreSQL harness setup lost ownership"))?;
        let store = Arc::new(pg.saga_durable_store()?);
        let control = pg.saga_fault_control();

        self.redis_fixture = Some(testkit::env_or_redis().await?);
        let pool = RedisConfig::from_url(
            self.redis_fixture
                .as_ref()
                .ok_or_else(|| anyhow!("Redis fixture setup lost ownership"))?
                .url(),
        )
        .create_pool(Some(RedisRuntime::Tokio1))?;
        self.redis = Some(RedisRuntimeDeps::setup(pool));
        let effects = self
            .redis
            .as_ref()
            .ok_or_else(|| anyhow!("Redis runtime setup lost ownership"))?
            .infra()
            .saga_effect_fixture();
        let unavailable_pool =
            RedisConfig::from_url("redis://127.0.0.1:1").create_pool(Some(RedisRuntime::Tokio1))?;
        self.unavailable_redis = Some(RedisRuntimeDeps::setup(unavailable_pool));
        let unavailable_effects = self
            .unavailable_redis
            .as_ref()
            .ok_or_else(|| anyhow!("unavailable Redis runtime setup lost ownership"))?
            .infra()
            .saga_effect_fixture();
        Ok(ProviderParts {
            store,
            control,
            effects,
            unavailable_effects,
        })
    }

    fn finish(self, parts: ProviderParts) -> Result<Providers> {
        let (Some(pg_fixture), Some(redis_fixture), Some(pg), Some(redis), Some(unavailable_redis)) = (
            self.pg_fixture,
            self.redis_fixture,
            self.pg,
            self.redis,
            self.unavailable_redis,
        ) else {
            bail!("provider setup transfer was incomplete");
        };
        Ok(Providers {
            _pg_fixture: pg_fixture,
            _redis_fixture: redis_fixture,
            pg,
            redis,
            unavailable_redis,
            store: parts.store,
            control: parts.control,
            effects: parts.effects,
            unavailable_effects: parts.unavailable_effects,
        })
    }

    async fn shutdown(&mut self) -> Result<()> {
        let mut actions: Vec<BoxFuture<'static, Result<()>>> = Vec::new();
        if let Some(pg) = self.pg.take() {
            actions.push(Box::pin(async move { pg.shutdown().await }));
        }
        for redis in [&mut self.redis, &mut self.unavailable_redis] {
            if let Some(redis) = redis.take() {
                actions.extend(redis.runtime_resources().into_iter().map(|resource| {
                    Box::pin(async move { resource.shutdown().await.map_err(Into::into) })
                        as BoxFuture<'static, Result<()>>
                }));
            }
        }
        run_cleanup_actions(actions).await
    }
}

async fn run_cleanup_actions(actions: Vec<BoxFuture<'static, Result<()>>>) -> Result<()> {
    let mut first_error = None;
    for action in actions.into_iter().rev() {
        if let Err(error) = action.await
            && first_error.is_none()
        {
            first_error = Some(error);
        }
    }
    if let Some(error) = first_error {
        Err(error)
    } else {
        Ok(())
    }
}

fn relay_budget() -> Result<RelayBudget> {
    Ok(RelayBudget::new(
        Duration::from_secs(60),
        Duration::from_secs(40),
        Duration::from_secs(5),
        Duration::from_secs(5),
    )?)
}

struct PauseGate {
    entered: watch::Sender<bool>,
    released: watch::Sender<bool>,
}

impl Default for PauseGate {
    fn default() -> Self {
        let (entered, _) = watch::channel(false);
        let (released, _) = watch::channel(false);
        Self { entered, released }
    }
}

impl std::fmt::Debug for PauseGate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PauseGate(<state-only>)")
    }
}

impl PauseGate {
    async fn pause_once(&self) {
        if !self.entered.send_if_modified(|entered| {
            if *entered {
                false
            } else {
                *entered = true;
                true
            }
        }) {
            return;
        }
        let mut released = self.released.subscribe();
        while !*released.borrow_and_update() {
            if released.changed().await.is_err() {
                return;
            }
        }
    }

    async fn wait_entered(&self) -> Result<()> {
        let mut entered = self.entered.subscribe();
        tokio::time::timeout(WAIT_TIMEOUT, async {
            while !*entered.borrow_and_update() {
                entered
                    .changed()
                    .await
                    .map_err(|_| anyhow!("injected Saga fault gate closed"))?;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await
        .context("timed out waiting for injected Saga fault point")??;
        Ok(())
    }

    fn release(&self) {
        self.released.send_replace(true);
    }
}

async fn join_saga_task(
    task: tokio::task::JoinHandle<SagaOutcome>,
    timeout_context: &'static str,
) -> Result<SagaOutcome> {
    join_saga_task_with_timeout(task, WAIT_TIMEOUT, timeout_context).await
}

async fn join_saga_task_with_timeout(
    mut task: tokio::task::JoinHandle<SagaOutcome>,
    timeout: Duration,
    timeout_context: &'static str,
) -> Result<SagaOutcome> {
    match tokio::time::timeout(timeout, &mut task).await {
        Ok(outcome) => Ok(outcome?),
        Err(_) => {
            task.abort();
            let _ = task.await;
            bail!(timeout_context)
        }
    }
}

#[derive(Debug, Clone)]
enum ActionMode {
    Normal,
    PauseForward(Arc<PauseGate>),
    PauseCompensation(Arc<PauseGate>),
    ProbeUnavailable(RedisSagaEffectFixture),
    PermanentFailure,
    RetryExhausted,
}

#[derive(Debug, Clone)]
struct V1Plan {
    reserve: ActionMode,
    capture: ActionMode,
}

impl V1Plan {
    fn normal() -> Self {
        Self {
            reserve: ActionMode::Normal,
            capture: ActionMode::Normal,
        }
    }
}

#[derive(Debug, Clone)]
struct ReserveV1 {
    effects: RedisSagaEffectFixture,
    mode: ActionMode,
}

impl SagaStep<billing_v1::ReserveFundsStep> for ReserveV1 {
    async fn execute(
        &self,
        context: SagaForwardContext,
    ) -> SagaAttemptOutcome<billing_v1::BillingReserveFundsReceipt> {
        if matches!(self.mode, ActionMode::RetryExhausted) {
            return match self.effects.probe(context.idempotency_key()).await {
                Ok(RedisSagaEffectProbeOutcome::Missing) => {
                    SagaAttemptOutcome::NotApplied(EngineError::new(EngineErrorKind::Transient))
                }
                _ => SagaAttemptOutcome::Unknown,
            };
        }
        if matches!(self.mode, ActionMode::PermanentFailure) {
            return SagaAttemptOutcome::NotApplied(EngineError::new(EngineErrorKind::Permanent));
        }
        match self
            .effects
            .apply(context.idempotency_key(), b"billing-v1/reserve/forward")
            .await
        {
            Ok(
                RedisSagaEffectApplyOutcome::Applied | RedisSagaEffectApplyOutcome::ExactDuplicate,
            ) => {
                if let ActionMode::PauseForward(gate) = &self.mode {
                    gate.pause_once().await;
                }
                SagaAttemptOutcome::Applied(billing_v1::BillingReserveFundsReceipt {
                    reservation_id: "reservation-v1".into(),
                })
            }
            _ => SagaAttemptOutcome::Unknown,
        }
    }

    async fn probe(
        &self,
        context: SagaForwardContext,
    ) -> SagaProbeOutcome<billing_v1::BillingReserveFundsReceipt> {
        let probe_effects = match &self.mode {
            ActionMode::ProbeUnavailable(effects) => effects,
            _ => &self.effects,
        };
        match probe_effects.probe(context.idempotency_key()).await {
            Ok(RedisSagaEffectProbeOutcome::Applied) => {
                SagaProbeOutcome::Applied(billing_v1::BillingReserveFundsReceipt {
                    reservation_id: "reservation-v1".into(),
                })
            }
            Ok(RedisSagaEffectProbeOutcome::Missing) => SagaProbeOutcome::NotApplied,
            Err(_) => SagaProbeOutcome::Unknown,
        }
    }

    async fn compensate(
        &self,
        context: SagaCompensationContext,
        _receipt: billing_v1::BillingReserveFundsReceipt,
    ) -> SagaAttemptOutcome<CompensationOutcome> {
        match self
            .effects
            .apply(
                context.idempotency_key(),
                b"billing-v1/reserve/compensation",
            )
            .await
        {
            Ok(
                RedisSagaEffectApplyOutcome::Applied | RedisSagaEffectApplyOutcome::ExactDuplicate,
            ) => {
                if let ActionMode::PauseCompensation(gate) = &self.mode {
                    gate.pause_once().await;
                }
                SagaAttemptOutcome::Applied(CompensationOutcome::Compensated)
            }
            _ => SagaAttemptOutcome::Unknown,
        }
    }

    async fn probe_compensation(
        &self,
        context: SagaCompensationContext,
        _receipt: billing_v1::BillingReserveFundsReceipt,
    ) -> SagaProbeOutcome<CompensationOutcome> {
        match self.effects.probe(context.idempotency_key()).await {
            Ok(RedisSagaEffectProbeOutcome::Applied) => {
                SagaProbeOutcome::Applied(CompensationOutcome::Compensated)
            }
            Ok(RedisSagaEffectProbeOutcome::Missing) => SagaProbeOutcome::NotApplied,
            Err(_) => SagaProbeOutcome::Unknown,
        }
    }
}

#[derive(Debug, Clone)]
struct CaptureV1 {
    effects: RedisSagaEffectFixture,
    mode: ActionMode,
}

impl SagaStep<billing_v1::CaptureStep> for CaptureV1 {
    async fn execute(
        &self,
        context: SagaForwardContext,
    ) -> SagaAttemptOutcome<billing_v1::BillingCaptureReceipt> {
        if matches!(self.mode, ActionMode::PermanentFailure) {
            return SagaAttemptOutcome::NotApplied(EngineError::new(EngineErrorKind::Permanent));
        }
        match self
            .effects
            .apply(context.idempotency_key(), b"billing-v1/capture/forward")
            .await
        {
            Ok(
                RedisSagaEffectApplyOutcome::Applied | RedisSagaEffectApplyOutcome::ExactDuplicate,
            ) => {
                if let ActionMode::PauseForward(gate) = &self.mode {
                    gate.pause_once().await;
                }
                SagaAttemptOutcome::Applied(billing_v1::BillingCaptureReceipt {
                    capture_id: "capture-v1".into(),
                })
            }
            _ => SagaAttemptOutcome::Unknown,
        }
    }

    async fn probe(
        &self,
        context: SagaForwardContext,
    ) -> SagaProbeOutcome<billing_v1::BillingCaptureReceipt> {
        match self.effects.probe(context.idempotency_key()).await {
            Ok(RedisSagaEffectProbeOutcome::Applied) => {
                SagaProbeOutcome::Applied(billing_v1::BillingCaptureReceipt {
                    capture_id: "capture-v1".into(),
                })
            }
            Ok(RedisSagaEffectProbeOutcome::Missing) => SagaProbeOutcome::NotApplied,
            Err(_) => SagaProbeOutcome::Unknown,
        }
    }

    async fn compensate(
        &self,
        context: SagaCompensationContext,
        _receipt: billing_v1::BillingCaptureReceipt,
    ) -> SagaAttemptOutcome<CompensationOutcome> {
        match self
            .effects
            .apply(
                context.idempotency_key(),
                b"billing-v1/capture/compensation",
            )
            .await
        {
            Ok(
                RedisSagaEffectApplyOutcome::Applied | RedisSagaEffectApplyOutcome::ExactDuplicate,
            ) => {
                if let ActionMode::PauseCompensation(gate) = &self.mode {
                    gate.pause_once().await;
                }
                SagaAttemptOutcome::Applied(CompensationOutcome::Compensated)
            }
            _ => SagaAttemptOutcome::Unknown,
        }
    }

    async fn probe_compensation(
        &self,
        context: SagaCompensationContext,
        _receipt: billing_v1::BillingCaptureReceipt,
    ) -> SagaProbeOutcome<CompensationOutcome> {
        match self.effects.probe(context.idempotency_key()).await {
            Ok(RedisSagaEffectProbeOutcome::Applied) => {
                SagaProbeOutcome::Applied(CompensationOutcome::Compensated)
            }
            Ok(RedisSagaEffectProbeOutcome::Missing) => SagaProbeOutcome::NotApplied,
            Err(_) => SagaProbeOutcome::Unknown,
        }
    }
}

#[derive(Debug, Clone)]
struct CaptureV2(RedisSagaEffectFixture);

impl SagaStep<billing_v2::CaptureStep> for CaptureV2 {
    async fn execute(
        &self,
        context: SagaForwardContext,
    ) -> SagaAttemptOutcome<billing_v2::BillingCaptureReceipt> {
        match self
            .0
            .apply(context.idempotency_key(), b"billing-v2/capture/forward")
            .await
        {
            Ok(
                RedisSagaEffectApplyOutcome::Applied | RedisSagaEffectApplyOutcome::ExactDuplicate,
            ) => SagaAttemptOutcome::Applied(billing_v2::BillingCaptureReceipt {
                capture_id: "capture-v2".into(),
            }),
            _ => SagaAttemptOutcome::Unknown,
        }
    }

    async fn probe(
        &self,
        context: SagaForwardContext,
    ) -> SagaProbeOutcome<billing_v2::BillingCaptureReceipt> {
        match self.0.probe(context.idempotency_key()).await {
            Ok(RedisSagaEffectProbeOutcome::Applied) => {
                SagaProbeOutcome::Applied(billing_v2::BillingCaptureReceipt {
                    capture_id: "capture-v2".into(),
                })
            }
            Ok(RedisSagaEffectProbeOutcome::Missing) => SagaProbeOutcome::NotApplied,
            Err(_) => SagaProbeOutcome::Unknown,
        }
    }

    async fn compensate(
        &self,
        context: SagaCompensationContext,
        _receipt: billing_v2::BillingCaptureReceipt,
    ) -> SagaAttemptOutcome<CompensationOutcome> {
        match self
            .0
            .apply(
                context.idempotency_key(),
                b"billing-v2/capture/compensation",
            )
            .await
        {
            Ok(
                RedisSagaEffectApplyOutcome::Applied | RedisSagaEffectApplyOutcome::ExactDuplicate,
            ) => SagaAttemptOutcome::Applied(CompensationOutcome::Compensated),
            _ => SagaAttemptOutcome::Unknown,
        }
    }

    async fn probe_compensation(
        &self,
        context: SagaCompensationContext,
        _receipt: billing_v2::BillingCaptureReceipt,
    ) -> SagaProbeOutcome<CompensationOutcome> {
        match self.0.probe(context.idempotency_key()).await {
            Ok(RedisSagaEffectProbeOutcome::Applied) => {
                SagaProbeOutcome::Applied(CompensationOutcome::Compensated)
            }
            Ok(RedisSagaEffectProbeOutcome::Missing) => SagaProbeOutcome::NotApplied,
            Err(_) => SagaProbeOutcome::Unknown,
        }
    }
}

#[derive(Debug, Clone)]
struct ReserveV2(RedisSagaEffectFixture);

impl SagaStep<billing_v2::ReserveFundsStep> for ReserveV2 {
    async fn execute(
        &self,
        context: SagaForwardContext,
    ) -> SagaAttemptOutcome<billing_v2::BillingReserveFundsReceipt> {
        match self
            .0
            .apply(context.idempotency_key(), b"billing-v2/reserve/forward")
            .await
        {
            Ok(
                RedisSagaEffectApplyOutcome::Applied | RedisSagaEffectApplyOutcome::ExactDuplicate,
            ) => SagaAttemptOutcome::Applied(billing_v2::BillingReserveFundsReceipt {
                reservation_id: "reservation-v2".into(),
            }),
            _ => SagaAttemptOutcome::Unknown,
        }
    }

    async fn probe(
        &self,
        context: SagaForwardContext,
    ) -> SagaProbeOutcome<billing_v2::BillingReserveFundsReceipt> {
        match self.0.probe(context.idempotency_key()).await {
            Ok(RedisSagaEffectProbeOutcome::Applied) => {
                SagaProbeOutcome::Applied(billing_v2::BillingReserveFundsReceipt {
                    reservation_id: "reservation-v2".into(),
                })
            }
            Ok(RedisSagaEffectProbeOutcome::Missing) => SagaProbeOutcome::NotApplied,
            Err(_) => SagaProbeOutcome::Unknown,
        }
    }

    async fn compensate(
        &self,
        context: SagaCompensationContext,
        _receipt: billing_v2::BillingReserveFundsReceipt,
    ) -> SagaAttemptOutcome<CompensationOutcome> {
        match self
            .0
            .apply(
                context.idempotency_key(),
                b"billing-v2/reserve/compensation",
            )
            .await
        {
            Ok(
                RedisSagaEffectApplyOutcome::Applied | RedisSagaEffectApplyOutcome::ExactDuplicate,
            ) => SagaAttemptOutcome::Applied(CompensationOutcome::Compensated),
            _ => SagaAttemptOutcome::Unknown,
        }
    }

    async fn probe_compensation(
        &self,
        context: SagaCompensationContext,
        _receipt: billing_v2::BillingReserveFundsReceipt,
    ) -> SagaProbeOutcome<CompensationOutcome> {
        match self.0.probe(context.idempotency_key()).await {
            Ok(RedisSagaEffectProbeOutcome::Applied) => {
                SagaProbeOutcome::Applied(CompensationOutcome::Compensated)
            }
            Ok(RedisSagaEffectProbeOutcome::Missing) => SagaProbeOutcome::NotApplied,
            Err(_) => SagaProbeOutcome::Unknown,
        }
    }
}

type RealExecutor = SagaExecutorImpl<PgSagaDurableStore, PgDeadLetterStore>;

struct Assembly {
    executor: RealExecutor,
    identity: SagaWorkerIdentity,
    definition: SagaDefinitionIdentity,
}

fn assemble(
    providers: &Providers,
    plan: V1Plan,
    v2: Option<(RedisSagaEffectFixture, Arc<AtomicU64>)>,
) -> Result<Assembly> {
    let effects = providers.effects.clone();
    let reserve_effects = effects.clone();
    let reserve_mode = plan.reserve.clone();
    let capture_effects = effects.clone();
    let capture_mode = plan.capture.clone();
    let v1 = TypedSagaActionFactory::<billing_v1::Definition>::builder()
        .register::<ReserveV1, _>(move || ReserveV1 {
            effects: reserve_effects.clone(),
            mode: reserve_mode.clone(),
        })
        .register::<CaptureV1, _>(move || CaptureV1 {
            effects: capture_effects.clone(),
            mode: capture_mode.clone(),
        })
        .finish();
    let config = SagaExecutorConfig::from_typed_factory(
        CheckpointOwner::new("billing"),
        format!("fault-matrix-{}", Uuid::new_v4().simple()),
        LEASE_TTL,
        &v1,
    )?;
    let identity = config.identity().clone();
    let definition = config.definition().clone();
    let mut registry = SagaDefinitionRegistry::builder().register(v1)?;
    if let Some((v2_effects, factory_calls)) = v2 {
        let capture_effects = v2_effects.clone();
        let reserve_effects = v2_effects;
        let capture_factory_calls = factory_calls.clone();
        let reserve_factory_calls = factory_calls;
        let v2 = TypedSagaActionFactory::<billing_v2::Definition>::builder()
            .register::<CaptureV2, _>(move || {
                capture_factory_calls.fetch_add(1, Ordering::Relaxed);
                CaptureV2(capture_effects.clone())
            })
            .register::<ReserveV2, _>(move || {
                reserve_factory_calls.fetch_add(1, Ordering::Relaxed);
                ReserveV2(reserve_effects.clone())
            })
            .finish();
        registry = registry.register(v2)?;
    }
    let executor = SagaExecutorImpl::new(
        SagaExecutorDeps::new(
            providers.store.clone(),
            Arc::new(providers.pg.saga_dead_letter_store()?),
            registry.finish(),
        ),
        config,
    )?;
    Ok(Assembly {
        executor,
        identity,
        definition,
    })
}

fn tenant() -> Result<vocab::TenantId> {
    Ok(vocab::TenantId::parse(&Uuid::new_v4().to_string())?)
}

fn instance(tenant: vocab::TenantId) -> Result<SagaInstanceRef> {
    Ok(SagaInstanceRef::new(tenant, SagaId::new(Uuid::new_v4()))?)
}

async fn start(assembly: &Assembly, instance: SagaInstanceRef) -> Result<()> {
    let authorization = diport::test_support::saga_start_authorization(
        vocab::ServiceCallerDomain::MaintenanceOperator,
        assembly.identity.clone(),
        instance,
        SagaStartAuditId::parse(format!("fault-matrix-{}", Uuid::new_v4().simple()))?,
    );
    assembly
        .executor
        .start(authorization, SagaStartRequest::new(instance))
        .await?;
    Ok(())
}

async fn advance(assembly: &Assembly, instance: SagaInstanceRef) -> SagaOutcome {
    assembly
        .executor
        .advance_registered(instance, assembly.definition.clone())
        .await
}

fn ensure_succeeded(outcome: SagaOutcome) -> Result<()> {
    match outcome {
        SagaOutcome::Succeeded { .. } => Ok(()),
        other => bail!("expected Saga success, got {other:?}"),
    }
}

fn ensure_failed(outcome: SagaOutcome) -> Result<()> {
    match outcome {
        SagaOutcome::Failed { .. } => Ok(()),
        other => bail!("expected Saga business failure, got {other:?}"),
    }
}

#[derive(Debug, Clone, Copy)]
enum OutcomeProof {
    Succeeded,
    Failed,
    Interrupted,
}

/// Private construction is the evidence authority: callers cannot forge a passing receipt from
/// raw keys, receipt bytes, pools, or lease fields. Both carried observations are sanitized.
#[derive(Debug)]
struct SagaFaultEvidenceReceipt {
    _case: CrashFaultSpec,
    _provider: ProviderProof,
    _outcome: OutcomeProof,
    _postgres: FaultMatrixSagaObservation,
    _redis: RedisSagaEffectObservation,
    _isolation_proven: bool,
    _fencing_proven: bool,
}

#[derive(Debug, Clone, Copy)]
enum ProviderProof {
    PostgresRedis,
}

impl SagaFaultEvidenceReceipt {
    fn prove(
        case: CrashFaultSpec,
        outcome: OutcomeProof,
        postgres: FaultMatrixSagaObservation,
        redis: RedisSagaEffectObservation,
        expected_status: SagaInstanceStatus,
        minimum_epoch: u64,
        expected_writes: u64,
        isolation_proven: bool,
        fencing_proven: bool,
    ) -> Result<Self> {
        ensure!(
            postgres.status() == expected_status,
            "unexpected durable Saga status"
        );
        ensure!(
            postgres.epoch() >= minimum_epoch,
            "Saga lease generation did not advance"
        );
        ensure!(
            !postgres.active_lease(),
            "terminal Saga retained an active lease"
        );
        ensure!(
            redis.write_count() == expected_writes,
            "unexpected Redis effect write count"
        );
        ensure!(
            redis.conflict_count() == 0,
            "unexpected Redis effect conflict"
        );
        Ok(Self {
            _case: case,
            _provider: ProviderProof::PostgresRedis,
            _outcome: outcome,
            _postgres: postgres,
            _redis: redis,
            _isolation_proven: isolation_proven,
            _fencing_proven: fencing_proven,
        })
    }
}

async fn observation(
    providers: &Providers,
    instance: SagaInstanceRef,
) -> Result<FaultMatrixSagaObservation> {
    providers
        .control
        .observe(instance)
        .await?
        .ok_or_else(|| anyhow!("real PostgreSQL Saga observation is missing"))
}

async fn active_epoch(
    providers: &Providers,
    instance: SagaInstanceRef,
    minimum_epoch: u64,
) -> Result<u64> {
    tokio::time::timeout(WAIT_TIMEOUT, async {
        loop {
            if let Some(observation) = providers.control.observe(instance).await?
                && observation.active_lease()
                && observation.epoch() >= minimum_epoch
            {
                return Ok::<_, anyhow::Error>(observation.epoch());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("timed out waiting for a real PostgreSQL Saga lease")?
}

async fn expire(
    providers: &Providers,
    instance: SagaInstanceRef,
    expected_epoch: u64,
) -> Result<()> {
    ensure!(
        providers
            .control
            .expire_active_lease(instance, expected_epoch)
            .await?
            == FaultMatrixSagaLeaseExpiry::Expired,
        "expected exact Saga lease to expire"
    );
    Ok(())
}

async fn execute_case(
    providers: &Providers,
    case: CrashFaultSpec,
) -> Result<SagaFaultEvidenceReceipt> {
    match case {
        CrashFaultSpec::SagaForwardEffectBeforeCompletion => {
            forward_effect_before_completion(providers).await
        }
        CrashFaultSpec::SagaCompensationBeforeJournal => {
            compensation_before_journal(providers).await
        }
        CrashFaultSpec::SagaLeaseLostDuringCall => lease_lost_during_call(providers).await,
        CrashFaultSpec::SagaReceiptDuplicateConflict => receipt_duplicate_conflict(providers).await,
        CrashFaultSpec::SagaRetryExhaustion => retry_exhaustion(providers).await,
        CrashFaultSpec::SagaOldDefinitionResume => old_definition_resume(providers).await,
        CrashFaultSpec::SagaTenantFencingIsolation => tenant_fencing_isolation(providers).await,
        _ => bail!("non-Saga fault cannot enter the Saga recovery target"),
    }
}

async fn forward_effect_before_completion(
    providers: &Providers,
) -> Result<SagaFaultEvidenceReceipt> {
    let instance = instance(tenant()?)?;
    let gate = Arc::new(PauseGate::default());
    let first = assemble(
        providers,
        V1Plan {
            reserve: ActionMode::PauseForward(gate.clone()),
            capture: ActionMode::Normal,
        },
        None,
    )?;
    start(&first, instance).await?;
    let task = tokio::spawn(
        first
            .executor
            .advance_registered(instance, first.definition.clone()),
    );
    gate.wait_entered().await?;
    let epoch = active_epoch(providers, instance, 1).await?;
    task.abort();
    let _ = task.await;
    expire(providers, instance, epoch).await?;

    let recovery = assemble(providers, V1Plan::normal(), None)?;
    ensure_succeeded(advance(&recovery, instance).await)?;
    let pg = observation(providers, instance).await?;
    ensure!(
        pg.journal().forward_intents() == 2,
        "expected two forward intents"
    );
    ensure!(
        pg.journal().forward_completions() == 2,
        "expected two forward completions"
    );
    ensure!(pg.receipts() == 2, "expected two protected receipts");
    let redis = providers.effects.observation();
    ensure!(
        redis.probe_count() == 1,
        "recovery must probe the uncertain effect once"
    );
    SagaFaultEvidenceReceipt::prove(
        CrashFaultSpec::SagaForwardEffectBeforeCompletion,
        OutcomeProof::Succeeded,
        pg,
        redis,
        SagaInstanceStatus::Succeeded,
        2,
        2,
        false,
        false,
    )
}

async fn compensation_before_journal(providers: &Providers) -> Result<SagaFaultEvidenceReceipt> {
    let instance = instance(tenant()?)?;
    let gate = Arc::new(PauseGate::default());
    let plan = V1Plan {
        reserve: ActionMode::PauseCompensation(gate.clone()),
        capture: ActionMode::PermanentFailure,
    };
    let first = assemble(providers, plan.clone(), None)?;
    start(&first, instance).await?;
    let task = tokio::spawn(
        first
            .executor
            .advance_registered(instance, first.definition.clone()),
    );
    gate.wait_entered().await?;
    let epoch = active_epoch(providers, instance, 1).await?;
    task.abort();
    let _ = task.await;
    expire(providers, instance, epoch).await?;

    let recovery = assemble(providers, plan, None)?;
    let outcome = match advance(&recovery, instance).await {
        SagaOutcome::Failed { .. } => OutcomeProof::Failed,
        SagaOutcome::Interrupted { .. } => OutcomeProof::Interrupted,
        other => bail!("expected compensated Saga result, got {other:?}"),
    };
    let pg = observation(providers, instance).await?;
    ensure!(
        pg.journal().compensation_intents() == 1,
        "expected one compensation intent"
    );
    ensure!(
        pg.journal().compensation_completions() == 1,
        "expected one compensation completion"
    );
    let redis = providers.effects.observation();
    ensure!(
        redis.probe_count() == 1,
        "recovery must probe the uncertain compensation once"
    );
    SagaFaultEvidenceReceipt::prove(
        CrashFaultSpec::SagaCompensationBeforeJournal,
        outcome,
        pg,
        redis,
        SagaInstanceStatus::Compensated,
        2,
        2,
        false,
        false,
    )
}

async fn lease_lost_during_call(providers: &Providers) -> Result<SagaFaultEvidenceReceipt> {
    let instance = instance(tenant()?)?;
    let gate = Arc::new(PauseGate::default());
    let first = assemble(
        providers,
        V1Plan {
            reserve: ActionMode::PauseForward(gate.clone()),
            capture: ActionMode::Normal,
        },
        None,
    )?;
    start(&first, instance).await?;
    let old_task = tokio::spawn(
        first
            .executor
            .advance_registered(instance, first.definition.clone()),
    );
    gate.wait_entered().await?;
    let old_epoch = active_epoch(providers, instance, 1).await?;
    expire(providers, instance, old_epoch).await?;

    let replacement = assemble(
        providers,
        V1Plan {
            reserve: ActionMode::ProbeUnavailable(providers.unavailable_effects.clone()),
            capture: ActionMode::Normal,
        },
        None,
    )?;
    ensure!(
        matches!(
            advance(&replacement, instance).await,
            SagaOutcome::Interrupted { .. }
        ),
        "unknown recovery probe must interrupt for operator repair"
    );
    gate.release();
    let old_outcome = join_saga_task(old_task, "stale Saga call did not return").await?;
    match old_outcome {
        SagaOutcome::Interrupted { .. } => {}
        other => bail!("stale leased Saga call was not fenced: {other:?}"),
    }
    let pg = observation(providers, instance).await?;
    let redis = providers.effects.observation();
    let unavailable = providers.unavailable_effects.observation();
    ensure!(
        pg.operator_reason() == Some(SagaOperatorReason::ForwardOutcomeUnknown),
        "unknown recovery probe must retain its exact operator reason"
    );
    ensure!(
        redis.write_count() == 1,
        "stale recovery re-applied the effect"
    );
    ensure!(
        unavailable.probe_count() == 1 && unavailable.apply_count() == 0,
        "recovery must map one unavailable provider probe to Unknown without applying"
    );
    SagaFaultEvidenceReceipt::prove(
        CrashFaultSpec::SagaLeaseLostDuringCall,
        OutcomeProof::Interrupted,
        pg,
        redis,
        SagaInstanceStatus::OperatorRequired,
        2,
        1,
        false,
        true,
    )
}

async fn receipt_duplicate_conflict(providers: &Providers) -> Result<SagaFaultEvidenceReceipt> {
    let instance = instance(tenant()?)?;
    let gate = Arc::new(PauseGate::default());
    let assembly = assemble(
        providers,
        V1Plan {
            reserve: ActionMode::PauseForward(gate.clone()),
            capture: ActionMode::Normal,
        },
        None,
    )?;
    start(&assembly, instance).await?;
    let key = SagaIdempotencyKey::derive(
        instance,
        &assembly.definition,
        billing_v1::STEP_0,
        SagaEffectPhase::Forward,
    );
    ensure!(
        providers
            .effects
            .apply(&key, b"billing-v1/reserve/forward")
            .await?
            == RedisSagaEffectApplyOutcome::Applied,
        "failed to seed the exact provider receipt"
    );
    let definition = assembly.definition.clone();
    let task = tokio::spawn(assembly.executor.advance_registered(instance, definition));
    gate.wait_entered().await?;
    ensure!(
        providers
            .control
            .inject_competing_forward_completion(
                providers.store.as_ref(),
                instance,
                billing_v1::SPEC,
                billing_v1::STEP_0,
            )
            .await?
            == FaultMatrixSagaCompletionInjection::Applied,
        "competing protected receipt was not committed"
    );
    gate.release();
    let outcome = join_saga_task(task, "receipt-conflict Saga did not return").await?;
    match outcome {
        SagaOutcome::Interrupted { .. } => {}
        other => bail!("receipt conflict did not interrupt the Saga: {other:?}"),
    }
    let pg = observation(providers, instance).await?;
    ensure!(
        pg.status() == SagaInstanceStatus::OperatorRequired,
        "conflict must require an operator"
    );
    ensure!(
        pg.operator_reason() == Some(SagaOperatorReason::ReceiptIntegrity),
        "receipt conflict must retain the receipt-integrity operator reason"
    );
    ensure!(
        pg.receipts() == 1,
        "conflict must retain exactly one protected receipt"
    );
    let redis = providers.effects.observation();
    ensure!(
        redis.write_count() == 1,
        "the conflict case must apply one external effect"
    );
    ensure!(
        redis.duplicate_count() == 1,
        "the action must recover the provider's exact duplicate"
    );
    ensure!(
        redis.conflict_count() == 0,
        "durable conflict must not be confused with Redis conflict"
    );
    SagaFaultEvidenceReceipt::prove(
        CrashFaultSpec::SagaReceiptDuplicateConflict,
        OutcomeProof::Interrupted,
        pg,
        redis,
        SagaInstanceStatus::OperatorRequired,
        1,
        1,
        false,
        false,
    )
}

async fn retry_exhaustion(providers: &Providers) -> Result<SagaFaultEvidenceReceipt> {
    let instance = instance(tenant()?)?;
    let assembly = assemble(
        providers,
        V1Plan {
            reserve: ActionMode::RetryExhausted,
            capture: ActionMode::Normal,
        },
        None,
    )?;
    start(&assembly, instance).await?;
    ensure_failed(advance(&assembly, instance).await)?;
    let pg = observation(providers, instance).await?;
    ensure!(
        pg.journal().forward_intents() == 3,
        "retry budget must stop after three attempts"
    );
    ensure!(
        pg.journal().forward_not_applied() == 0,
        "normal retry path must not use the operator-repair transition"
    );
    let redis = providers.effects.observation();
    ensure!(
        redis.apply_count() == 0,
        "proven-not-applied retries must not write effects"
    );
    ensure!(
        redis.probe_count() == 3,
        "retry exhaustion must not perform a fourth probe"
    );
    SagaFaultEvidenceReceipt::prove(
        CrashFaultSpec::SagaRetryExhaustion,
        OutcomeProof::Failed,
        pg,
        redis,
        SagaInstanceStatus::Compensated,
        1,
        0,
        false,
        false,
    )
}

async fn old_definition_resume(providers: &Providers) -> Result<SagaFaultEvidenceReceipt> {
    let instance = instance(tenant()?)?;
    let gate = Arc::new(PauseGate::default());
    let v2_effects = providers.redis.infra().saga_effect_fixture();
    let v2_factory_calls = Arc::new(AtomicU64::new(0));
    let first = assemble(
        providers,
        V1Plan {
            reserve: ActionMode::PauseForward(gate.clone()),
            capture: ActionMode::Normal,
        },
        Some((v2_effects.clone(), v2_factory_calls.clone())),
    )?;
    ensure!(
        first.definition == SagaDefinitionIdentity::from_binding(billing_v1::SPEC),
        "executor did not pin the v1 identity"
    );
    ensure!(
        first.definition != SagaDefinitionIdentity::from_binding(billing_v2::SPEC),
        "v1 and v2 definitions unexpectedly alias"
    );
    start(&first, instance).await?;
    let task = tokio::spawn(
        first
            .executor
            .advance_registered(instance, first.definition.clone()),
    );
    gate.wait_entered().await?;
    let epoch = active_epoch(providers, instance, 1).await?;
    task.abort();
    let _ = task.await;
    expire(providers, instance, epoch).await?;

    let retained = assemble(
        providers,
        V1Plan::normal(),
        Some((v2_effects.clone(), v2_factory_calls.clone())),
    )?;
    ensure_succeeded(advance(&retained, instance).await)?;
    let pg = observation(providers, instance).await?;
    let redis = providers.effects.observation();
    let v2 = v2_effects.observation();
    ensure!(
        v2_factory_calls.load(Ordering::Relaxed) == 0,
        "the v2 action factory was invoked while resuming a pinned v1 instance"
    );
    ensure!(
        v2.apply_count() == 0 && v2.probe_count() == 0,
        "the pinned v1 resume performed v2 provider I/O"
    );
    SagaFaultEvidenceReceipt::prove(
        CrashFaultSpec::SagaOldDefinitionResume,
        OutcomeProof::Succeeded,
        pg,
        redis,
        SagaInstanceStatus::Succeeded,
        2,
        2,
        false,
        false,
    )
}

async fn tenant_fencing_isolation(providers: &Providers) -> Result<SagaFaultEvidenceReceipt> {
    let shared_saga_id = SagaId::new(Uuid::new_v4());
    let first_instance = SagaInstanceRef::new(tenant()?, shared_saga_id)?;
    let second_instance = SagaInstanceRef::new(tenant()?, shared_saga_id)?;
    let gate = Arc::new(PauseGate::default());
    let first = assemble(
        providers,
        V1Plan {
            reserve: ActionMode::PauseForward(gate.clone()),
            capture: ActionMode::Normal,
        },
        None,
    )?;
    start(&first, first_instance).await?;
    let first_task = tokio::spawn(
        first
            .executor
            .advance_registered(first_instance, first.definition.clone()),
    );
    gate.wait_entered().await?;
    let first_epoch = active_epoch(providers, first_instance, 1).await?;

    let second = assemble(providers, V1Plan::normal(), None)?;
    start(&second, second_instance).await?;
    ensure_succeeded(advance(&second, second_instance).await)?;
    expire(providers, first_instance, first_epoch).await?;
    let first_recovery = assemble(providers, V1Plan::normal(), None)?;
    ensure_succeeded(advance(&first_recovery, first_instance).await)?;
    gate.release();
    let stale_outcome =
        join_saga_task(first_task, "cross-tenant stale Saga call did not return").await?;
    ensure!(
        matches!(stale_outcome, SagaOutcome::Interrupted { .. }),
        "stale epoch mutation was not fenced"
    );

    let first_pg = observation(providers, first_instance).await?;
    let second_pg = observation(providers, second_instance).await?;
    ensure!(
        first_pg.epoch() >= 2,
        "faulted tenant did not advance its fence"
    );
    ensure!(second_pg.epoch() == 1, "other tenant's fence was changed");
    ensure!(
        first_pg.status() == SagaInstanceStatus::Succeeded,
        "faulted tenant did not recover"
    );
    ensure!(
        second_pg.status() == SagaInstanceStatus::Succeeded,
        "other tenant was disturbed"
    );
    ensure!(
        first_pg.receipts() == 2 && second_pg.receipts() == 2,
        "tenant-scoped protected receipts were not isolated"
    );
    ensure!(
        !first_pg.active_lease() && !second_pg.active_lease(),
        "tenant-scoped leases did not terminate independently"
    );
    let redis = providers.effects.observation();
    ensure!(
        redis.write_count() == 4,
        "same Saga UUID across tenants must create four isolated effects"
    );
    ensure!(
        redis.duplicate_count() == 0,
        "tenant-scoped effect keys aliased"
    );
    ensure!(
        redis.conflict_count() == 0,
        "tenant-scoped effect keys conflicted"
    );
    SagaFaultEvidenceReceipt::prove(
        CrashFaultSpec::SagaTenantFencingIsolation,
        OutcomeProof::Succeeded,
        first_pg,
        redis,
        SagaInstanceStatus::Succeeded,
        2,
        4,
        true,
        true,
    )
}

async fn execute(fault_spec: CrashFaultSpec) -> Result<()> {
    let runner = READY_CASE_RUNNERS
        .iter()
        .find(|runner| runner._fault_spec == fault_spec)
        .ok_or_else(|| anyhow!("missing Saga case runner"))?;
    let receipt = (runner.run)().await?;
    let _sanitized_receipt = format!("{receipt:?}");
    Ok(())
}

#[tokio::test]
async fn pause_gate_preserves_state_published_before_observation() -> Result<()> {
    let gate = PauseGate::default();
    gate.release();
    gate.pause_once().await;
    gate.wait_entered().await
}

#[tokio::test]
async fn saga_task_timeout_aborts_and_reaps_before_return() {
    struct DropSignal(Arc<AtomicU64>);
    impl Drop for DropSignal {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    let drops = Arc::new(AtomicU64::new(0));
    let task_drops = Arc::clone(&drops);
    let task = tokio::spawn(async move {
        let _signal = DropSignal(task_drops);
        std::future::pending::<SagaOutcome>().await
    });
    tokio::task::yield_now().await;
    assert!(
        join_saga_task_with_timeout(task, Duration::from_millis(1), "expected timeout")
            .await
            .is_err()
    );
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn provider_setup_rollback_is_reverse_and_continue_on_error() {
    let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut actions: Vec<BoxFuture<'static, Result<()>>> = Vec::new();
    for (name, fail) in [("postgres", false), ("redis", true), ("unavailable", false)] {
        let observed = Arc::clone(&observed);
        actions.push(Box::pin(async move {
            observed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(name);
            if fail {
                bail!("synthetic cleanup failure");
            }
            Ok(())
        }));
    }
    assert!(run_cleanup_actions(actions).await.is_err());
    assert_eq!(
        *observed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        ["unavailable", "redis", "postgres"]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn saga_forward_effect_before_completion() -> Result<()> {
    execute(CrashFaultSpec::SagaForwardEffectBeforeCompletion).await
}

#[tokio::test(flavor = "multi_thread")]
async fn saga_compensation_before_journal() -> Result<()> {
    execute(CrashFaultSpec::SagaCompensationBeforeJournal).await
}

#[tokio::test(flavor = "multi_thread")]
async fn saga_lease_lost_during_call() -> Result<()> {
    execute(CrashFaultSpec::SagaLeaseLostDuringCall).await
}

#[tokio::test(flavor = "multi_thread")]
async fn saga_receipt_duplicate_conflict() -> Result<()> {
    execute(CrashFaultSpec::SagaReceiptDuplicateConflict).await
}

#[tokio::test(flavor = "multi_thread")]
async fn saga_retry_exhaustion() -> Result<()> {
    execute(CrashFaultSpec::SagaRetryExhaustion).await
}

#[tokio::test(flavor = "multi_thread")]
async fn saga_old_definition_resume() -> Result<()> {
    execute(CrashFaultSpec::SagaOldDefinitionResume).await
}

#[tokio::test(flavor = "multi_thread")]
async fn saga_tenant_fencing_isolation() -> Result<()> {
    execute(CrashFaultSpec::SagaTenantFencingIsolation).await
}
