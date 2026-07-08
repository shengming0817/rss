use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, bail};
use bootstrap::Topology;
use bootstrap::sagaprojectiondeps::{
    PostgresUrl, ResolvedSagaProjection, SagaProjectionConfig, SagaProjectionResolveError, resolve,
};
use consistency::SagaInstanceRef;
use diport::CheckpointOwner;
use eventexec::{
    SagaAction, SagaActionCtx, SagaActionError, SagaActionFactory, SagaExecStatus, SagaExecutor,
    SagaExecutorConfig, SagaExecutorDeps, SagaExecutorImpl, SagaId, SagaOutcome, SagaRuntimeLock,
    SagaTailer,
};
use futures::future::BoxFuture;
use memory::{MemCheckpointStore, MemDeadLetterStore, MemLockStore, MemSagaInstanceStore};

const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

type DemoExec = SagaExecutorImpl<
    memory::MemSagaJournal,
    MemCheckpointStore,
    MemDeadLetterStore,
    MemSagaInstanceStore,
>;

struct DemoHarness {
    exec: DemoExec,
    dead_letter: Arc<MemDeadLetterStore>,
}

#[derive(Debug)]
struct DemoAction {
    name: &'static str,
}

impl SagaAction for DemoAction {
    fn name(&self) -> &str {
        self.name
    }

    fn do_it(&self, ctx: SagaActionCtx) -> BoxFuture<'static, Result<Vec<u8>, SagaActionError>> {
        let node = self.name.to_string();
        Box::pin(async move { Ok(format!("{}:{}", ctx.saga_id().as_uuid(), node).into_bytes()) })
    }

    fn undo_it(&self, _ctx: SagaActionCtx) -> BoxFuture<'static, Result<(), SagaActionError>> {
        Box::pin(async { Ok(()) })
    }
}

struct DemoFactory;

impl SagaActionFactory for DemoFactory {
    fn build(&self) -> Vec<Box<dyn SagaAction>> {
        vec![
            Box::new(DemoAction { name: "reserve" }),
            Box::new(DemoAction { name: "capture" }),
        ]
    }
}

fn demo_harness() -> Result<DemoHarness> {
    let resolved = resolve(Topology::Demo, SagaProjectionConfig::default())?;
    match resolved {
        ResolvedSagaProjection::Demo => {
            let instances = Arc::new(MemSagaInstanceStore::new());
            let journal = Arc::new(instances.journal());
            let checkpoint = Arc::new(MemCheckpointStore::new());
            let dead_letter = Arc::new(MemDeadLetterStore::new());
            let runtime_lock = SagaRuntimeLock::new(MemLockStore::new());
            let factory = Arc::new(DemoFactory);
            let deps = SagaExecutorDeps::new(
                journal,
                instances,
                checkpoint,
                Arc::clone(&dead_letter),
                factory,
                runtime_lock,
            );
            let config = SagaExecutorConfig::from_contract_spec(
                CheckpointOwner::new("billing"),
                "journey-runner",
                Duration::from_secs(30),
                generated::saga::billing_v1::SPEC,
            )?;
            Ok(DemoHarness {
                exec: SagaExecutorImpl::new(deps, config),
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
fn durable_topology_fails_closed_without_redis() {
    let cfg = SagaProjectionConfig::new(Some(PostgresUrl::new("postgres://host/rss")), None);
    let got = resolve(Topology::DurableIsolated, cfg);
    assert!(matches!(
        got,
        Err(SagaProjectionResolveError::MissingRedisUrl)
    ));
}
