//! Run on the candidate and on a detached worktree at the issue baseline.
//! From the candidate checkout, apply only the measurement harness to the baseline:
//! `git diff 15380c399 HEAD -- tests/reconcile-postgres-integration/tests/measure | git -C "$baseline" apply`.
//! Use a separate Cargo target directory for each checkout. With Docker and Python 3 + psycopg 3:
//! `cargo build --locked -p testkit --features containers --bin rss-test-launcher`
//! then `RSS_TEST_RUN_ID="hot-$(uuidgen)" "${CARGO_TARGET_DIR:-target}/debug/rss-test-launcher" -- cargo test --locked -p reconcile-postgres-integration --test suite hot_scan_profile -- --ignored --nocapture`.
//! Each run compiles that checkout's worker and embedded DDL and emits five untraced samples per layout.
use super::*;
use std::sync::{
    OnceLock,
    atomic::{AtomicUsize, Ordering},
};

// Count production PgStore responses and timestamp the first committed claim before
// the worker enqueues it. Seeding, admission, settlement and tracing are outside timing.
struct Measured<'a> {
    store: &'a PgStore,
    calls: AtomicUsize,
    receipt: OnceLock<Duration>,
    stop: CancellationToken,
}

impl DurableStore for Measured<'_> {
    type Claim = PgClaim;
    async fn wake<T: Timer>(
        &self,
        target: &Target,
        resources: &ResourceSet,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        self.store.wake(target, resources, control).await
    }
    async fn bind_resources<T: Timer>(
        &self,
        target: &Target,
        resources: &ResourceSet,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        self.store.bind_resources(target, resources, control).await
    }
    async fn claim_due<T: Timer>(
        &self,
        scope: &Scope,
        limit: usize,
        scan_budget: u32,
        lease: Duration,
        control: &Control<'_, T>,
    ) -> Result<ClaimBatch<PgClaim>, Error> {
        let batch = self
            .store
            .claim_due(scope, limit, scan_budget, lease, control)
            .await?;
        self.calls.fetch_add(1, Ordering::Relaxed);
        if !batch.claims.is_empty() {
            assert!(self.receipt.set(control.elapsed()).is_ok());
        }
        Ok(batch)
    }
    async fn renew<T: Timer>(
        &self,
        claim: &PgClaim,
        lease: Duration,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        self.store.renew(claim, lease, control).await
    }
    async fn finish<T: Timer>(
        &self,
        claim: &PgClaim,
        completion: Completion,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        self.store.finish(claim, completion, control).await
    }
    async fn release<T: Timer>(
        &self,
        claim: &PgClaim,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        self.store.release(claim, control).await
    }
}

impl Reconciler<PgClaim> for Measured<'_> {
    type State = ();
    async fn observe<T: Timer>(
        &self,
        claim: &PgClaim,
        _: &Control<'_, T>,
    ) -> Result<ReconcileStep<ReconcileDiff<()>>, Error> {
        assert_eq!(claim.target().entity(), "10001");
        self.stop.cancel();
        Ok(ReconcileStep::Ready(ReconcileDiff::between(
            DesiredState::present(()),
            ActualState::present(()),
        )))
    }
    async fn apply<T: Timer>(
        &self,
        _: &PgClaim,
        _: ReconcileDiff<()>,
        _: &Control<'_, T>,
    ) -> Result<ReconcileStep<()>, Error> {
        Err(Error::new(ErrorKind::Invariant))
    }
}

#[tokio::test]
#[ignore = "paired PG 17.6 worker timings and separate auto_explain diagnostics"]
async fn hot_scan_profile() -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?.canonicalize()?;
    let package = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).canonicalize()?;
    let workspace = package.join("../..").canonicalize()?;
    anyhow::ensure!(
        cwd == package || cwd == workspace,
        "measurement binary belongs to a different checkout; use separate Cargo target directories"
    );
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    let control = Control::new(&clock, Duration::from_secs(240), &cancel);
    let db = Database::new(&control).await?;
    let store = PgStore::new(db.pool.clone(), &control).await?;
    let mut owner = db.owner.acquire().await?;
    sqlx::raw_sql(include_str!("hot_seed.sql"))
        .execute(&mut *owner)
        .await?;
    let scope = Scope::new(TenantId::parse(TENANT)?, "profile")?;
    let policy = Policy::try_from(PolicyConfig {
        concurrency: 1,
        claim_batch_size: 1,
        scan_budget: 128,
        lease_ttl: Duration::from_secs(60),
        attempt_timeout: Duration::from_secs(10),
        scan_interval: Duration::from_secs(1),
        idle_scan_interval: Duration::from_secs(30),
        initial_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_secs(1),
        max_attempts: 1,
    })?;
    for round in 1..=5 {
        for layout in ["future", "hit", "miss"] {
            sqlx::query("SELECT pg_temp.seed_hot_scan($1)")
                .bind(layout)
                .execute(&mut *owner)
                .await?;
            let measured = Measured {
                store: &store,
                calls: AtomicUsize::new(0),
                receipt: OnceLock::new(),
                stop: CancellationToken::new(),
            };
            let start = clock.now();
            let report = run(
                &measured,
                &measured,
                &scope,
                policy,
                &control,
                &measured.stop,
                |_| {},
            )
            .await?;
            anyhow::ensure!(
                report.converged == 1
                    && report.scan_failed == 0
                    && report.claim_unknown_batches == 0
            );
            let elapsed = *measured
                .receipt
                .get()
                .ok_or_else(|| anyhow::anyhow!("missing confirmed claim"))?
                - start;
            let calls = measured.calls.load(Ordering::Relaxed);
            println!(
                "RUNNER layout={layout} round={round} calls={calls} empty={} elapsed_us={} claim_sql_s={:.2} empty_s={:.2}",
                calls - 1,
                elapsed.as_micros(),
                calls as f64 / elapsed.as_secs_f64(),
                (calls - 1) as f64 / elapsed.as_secs_f64()
            );
        }
    }
    drop(owner);
    python_profile(&db, &["--hot"]).await
}
