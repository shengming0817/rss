//! Reopen durable state with the exact definition and explicitly resume failed compensation.
mod actions;
use actions::*;
use rss_saga::*;
use rss_saga_postgres::{CloseOutcome, PgStore};
use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use tokio_util::sync::CancellationToken;

pub async fn run(input: crate::pg::Input) -> anyhow::Result<()> {
    use ring::rand::SecureRandom as _;
    let mut key = [0; 32];
    let mut integrity = [0; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut key)
        .map_err(|_| anyhow::anyhow!("example key generation"))?;
    ring::rand::SystemRandom::new()
        .fill(&mut integrity)
        .map_err(|_| anyhow::anyhow!("example integrity key generation"))?;
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    let c = Control::new(&clock, Duration::from_secs(30), &cancel);
    let scope = Scope::new(
        rss_request_context::TenantId::parse(&input.tenant)?,
        uuid::Uuid::new_v4(),
    );
    let definition = definition(&["one", "two", "three"])?;
    // This in-memory effect service remains alive while the durable executor is reconstructed.
    let effects = Arc::new(Effects::default());
    effects.fail_undo.store(true, Ordering::SeqCst);
    let executor = Executor::new(
        PgStore::new(input.pool().await?, &c).await?,
        protection(key, integrity)?,
        registry(definition.clone(), effects.clone(), true)?,
    );
    executor.register(scope, &definition, &c).await?;
    let report = executor.run(scope, 30, &c).await?;
    anyhow::ensure!(
        report.status == Status::CompensationFailed,
        "expected persisted compensation failure"
    );
    anyhow::ensure!(
        executor.store().close(&c).await == CloseOutcome::Drained,
        "first store did not drain"
    );
    drop(executor);
    let store = PgStore::new(input.pool().await?, &c).await?;
    let executor = Executor::new(
        store.clone(),
        protection(key, integrity)?,
        registry(definition.clone(), effects.clone(), true)?,
    );
    let recovered = executor.resume(scope, report.revision, 30, &c).await?;
    anyhow::ensure!(
        recovered.status == Status::Compensated,
        "reconstructed executor did not compensate"
    );
    let lease = store.claim(scope, Duration::from_secs(5), &c).await?;
    let snapshot = store.snapshot(&lease, &c).await?;
    anyhow::ensure!(
        snapshot.definition() == &definition,
        "definition identity changed on recovery"
    );
    let forwards = snapshot
        .events()
        .iter()
        .filter(|e| e.kind == EventKind::ForwardApplied)
        .count();
    let undos = snapshot
        .events()
        .iter()
        .filter(|e| e.kind == EventKind::CompensationApplied)
        .count();
    anyhow::ensure!(
        forwards == 2 && undos == 2,
        "journal did not persist exact forward/compensation effects"
    );
    let undo = effects
        .undo
        .lock()
        .map_err(|_| anyhow::anyhow!("effect lock poisoned"))?
        .clone();
    anyhow::ensure!(
        undo == ["two", "one"],
        "compensation was not reverse ordered and idempotent"
    );
    store.release(&lease, &c).await?;
    anyhow::ensure!(
        store.close(&c).await == CloseOutcome::Drained,
        "reopened store did not drain"
    );
    Ok(())
}
