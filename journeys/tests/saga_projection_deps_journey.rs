use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, bail};
use bootstrap::Topology;
use bootstrap::sagaprojectiondeps::{
    PostgresUrl, ResolvedSagaProjection, SagaProjectionConfig, SagaProjectionResolveError, resolve,
};
use consistency::{CompensationOutcome, SagaInstanceRef};
use diport::CheckpointOwner;
use eventexec::{
    SagaAttemptOutcome, SagaCompensationContext, SagaDefinitionRegistry, SagaExecStatus,
    SagaExecutor, SagaExecutorConfig, SagaExecutorDeps, SagaExecutorImpl, SagaForwardContext,
    SagaId, SagaOutcome, SagaProbeOutcome, SagaStep, SagaTailer, TypedSagaActionFactory,
};
use generated::saga::billing_v1::{
    BillingCaptureReceipt, BillingReserveFundsReceipt, CaptureStep, Definition, ReserveFundsStep,
};
use memory::{MemDeadLetterStore, MemSagaDurableStore};

const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

type DemoExec = SagaExecutorImpl<MemSagaDurableStore, MemDeadLetterStore>;

struct DemoHarness {
    exec: DemoExec,
    dead_letter: Arc<MemDeadLetterStore>,
}

#[derive(Debug)]
struct DemoReserveFundsStep;

impl SagaStep<ReserveFundsStep> for DemoReserveFundsStep {
    async fn execute(
        &self,
        ctx: SagaForwardContext,
    ) -> SagaAttemptOutcome<BillingReserveFundsReceipt> {
        SagaAttemptOutcome::Applied(BillingReserveFundsReceipt {
            reservation_id: format!("{}:reserve_funds", ctx.saga_id().as_uuid()),
        })
    }

    async fn probe(
        &self,
        _ctx: SagaForwardContext,
    ) -> SagaProbeOutcome<BillingReserveFundsReceipt> {
        SagaProbeOutcome::NotApplied
    }

    async fn compensate(
        &self,
        _ctx: SagaCompensationContext,
        _receipt: BillingReserveFundsReceipt,
    ) -> SagaAttemptOutcome<CompensationOutcome> {
        SagaAttemptOutcome::Applied(CompensationOutcome::Compensated)
    }

    async fn probe_compensation(
        &self,
        _ctx: SagaCompensationContext,
        _receipt: BillingReserveFundsReceipt,
    ) -> SagaProbeOutcome<CompensationOutcome> {
        SagaProbeOutcome::NotApplied
    }
}

#[derive(Debug)]
struct DemoCaptureStep;

impl SagaStep<CaptureStep> for DemoCaptureStep {
    async fn execute(&self, ctx: SagaForwardContext) -> SagaAttemptOutcome<BillingCaptureReceipt> {
        SagaAttemptOutcome::Applied(BillingCaptureReceipt {
            capture_id: format!("{}:capture", ctx.saga_id().as_uuid()),
        })
    }

    async fn probe(&self, _ctx: SagaForwardContext) -> SagaProbeOutcome<BillingCaptureReceipt> {
        SagaProbeOutcome::NotApplied
    }

    async fn compensate(
        &self,
        _ctx: SagaCompensationContext,
        _receipt: BillingCaptureReceipt,
    ) -> SagaAttemptOutcome<CompensationOutcome> {
        SagaAttemptOutcome::Applied(CompensationOutcome::Compensated)
    }

    async fn probe_compensation(
        &self,
        _ctx: SagaCompensationContext,
        _receipt: BillingCaptureReceipt,
    ) -> SagaProbeOutcome<CompensationOutcome> {
        SagaProbeOutcome::NotApplied
    }
}

fn demo_harness() -> Result<DemoHarness> {
    let resolved = resolve(Topology::Demo, SagaProjectionConfig::default())?;
    match resolved {
        ResolvedSagaProjection::Demo => {
            let store = Arc::new(MemSagaDurableStore::new());
            let dead_letter = Arc::new(MemDeadLetterStore::new());
            let factory = TypedSagaActionFactory::<Definition>::builder()
                .register::<DemoReserveFundsStep, _>(|| DemoReserveFundsStep)
                .register::<DemoCaptureStep, _>(|| DemoCaptureStep)
                .finish();
            let config = SagaExecutorConfig::from_typed_factory(
                CheckpointOwner::new("billing"),
                "journey-runner",
                Duration::from_secs(30),
                &factory,
            )?;
            let registry = SagaDefinitionRegistry::builder()
                .register(factory)?
                .finish();
            let deps = SagaExecutorDeps::new(store, Arc::clone(&dead_letter), registry);
            Ok(DemoHarness {
                exec: SagaExecutorImpl::new(deps, config)?,
                dead_letter,
            })
        }
        other => bail!("demo topology resolved to non-demo saga deps: {other:?}"),
    }
}

fn instance() -> Result<SagaInstanceRef> {
    let tenant = vocab::TenantId::parse(TENANT)?;
    Ok(SagaInstanceRef::new(
        tenant,
        SagaId::new(uuid::Uuid::from_u128(1637)),
    )?)
}

#[tokio::test]
async fn demo_resolver_yields_memory_saga_executor_roundtrip() -> Result<()> {
    let harness = demo_harness()?;
    let instance = instance()?;

    let outcome = harness.exec.run(instance).await;

    assert!(
        matches!(outcome, SagaOutcome::Succeeded { .. }),
        "{outcome:?}"
    );
    assert_eq!(
        harness.exec.status(instance).await,
        Some(SagaExecStatus::Done)
    );
    assert!(
        harness.dead_letter.records().is_empty(),
        "successful demo saga must not write DLX"
    );
    Ok(())
}

#[test]
fn durable_topology_fails_closed_without_postgres() {
    let got = resolve(Topology::DurableShared, SagaProjectionConfig::default());
    assert!(matches!(
        got,
        Err(SagaProjectionResolveError::MissingPostgresUrl)
    ));
}

#[test]
fn durable_topology_needs_only_the_unified_postgres_store() {
    let cfg = SagaProjectionConfig::new(Some(PostgresUrl::new("postgres://host/rss")));
    let got = resolve(Topology::DurableIsolated, cfg);
    assert!(matches!(got, Ok(ResolvedSagaProjection::Durable { .. })));
}
