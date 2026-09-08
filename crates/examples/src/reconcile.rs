//! Durable convergence: successful application always requires a fresh observation.
use rss_reconcile::*;
use rss_reconcile_postgres::{CloseOutcome, PgClaim, PgStore};
use rss_request_context::TenantId;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

struct Clock(Instant);
impl Clock {
    #[allow(clippy::disallowed_methods)] // reason: this example owns the injected monotonic origin.
    fn new() -> Self {
        Self(Instant::now())
    }
}
impl Timer for Clock {
    #[allow(clippy::disallowed_methods)] // reason: read the caller-owned monotonic origin.
    fn now(&self) -> Duration {
        self.0.elapsed()
    }
    async fn sleep_until(&self, deadline: Duration) {
        tokio::time::sleep(deadline.saturating_sub(self.now())).await;
    }
}
/// Minimal application table; the fixture owner installs it before running the consumer.
pub const FIXTURE_SQL: &str = include_str!("../fixtures/reconcile.sql");
struct Business<'a>(&'a PgStore);
impl Reconciler<PgClaim> for Business<'_> {
    type State = i64;
    async fn observe<T: Timer>(
        &self,
        claim: &PgClaim,
        c: &Control<'_, T>,
    ) -> Result<ReconcileDiff<i64>, Error> {
        let value = value(self.0, claim.target().scope(), c).await?;
        Ok(ReconcileDiff::between(
            DesiredState::present(1),
            ActualState::present(value),
        ))
    }
    async fn apply<T: Timer>(
        &self,
        claim: &PgClaim,
        _: ReconcileDiff<i64>,
        c: &Control<'_, T>,
    ) -> Result<(), Error> {
        let tenant = claim.target().scope().tenant().to_string();
        self.0.protect(claim, c, tenant, |tenant, tx| Box::pin(async move {
            let tenant = tenant.clone();
            tx.with_connection(move |conn| Box::pin(async move {
                sqlx::query("INSERT INTO public.reconcile_demo(tenant_id,n) VALUES($1::uuid,1) ON CONFLICT(tenant_id) DO UPDATE SET n=1")
                    .bind(tenant.as_str()).execute(conn).await?;
                Ok(())
            })).await
        })).await
    }
}
async fn value<T: Timer>(store: &PgStore, scope: &Scope, c: &Control<'_, T>) -> Result<i64, Error> {
    store
        .local_tx(scope, c, |tx| {
            Box::pin(async move {
                tx.with_connection(|conn| {
                    Box::pin(async move {
                        sqlx::query_scalar(
                            "SELECT coalesce(sum(n),0)::bigint FROM public.reconcile_demo",
                        )
                        .fetch_one(conn)
                        .await
                    })
                })
                .await
            })
        })
        .await
}
async fn scenario(
    store: &PgStore,
    tenant: TenantId,
    clock: &Clock,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let target = Target::new(Scope::new(tenant, "example")?, "entity")?;
    store.wake(&target, c).await?;
    let business = Business(store);
    let policy = Policy::try_from(PolicyConfig {
        concurrency: 1,
        lease_ttl: Duration::from_secs(10),
        attempt_timeout: Duration::from_secs(5),
        scan_interval: Duration::from_millis(10),
        initial_backoff: Duration::from_millis(5),
        max_backoff: Duration::from_millis(50),
        max_attempts: 3,
    })?;
    let cancel = CancellationToken::new();
    let worker_control = Control::new(clock, c.remaining(), &cancel);
    let completion = async {
        loop {
            let done: bool = store.local_tx(target.scope(), c, |tx| Box::pin(async move {
                tx.with_connection(|conn| Box::pin(async move {
                    sqlx::query_scalar("SELECT coalesce(result='converged',false) FROM rss_reconcile.targets WHERE reconciler='example' AND entity='entity'").fetch_one(conn).await
                })).await
            })).await?;
            if done {
                cancel.cancel();
                return Ok::<(), Error>(());
            }
            c.sleep(Duration::from_millis(10)).await;
        }
    };
    let (report, finished) = tokio::join!(
        rss_reconcile::run(
            store,
            &business,
            target.scope(),
            policy,
            &worker_control,
            |_| {}
        ),
        completion
    );
    finished?;
    let report = report?;
    anyhow::ensure!(
        report.reobserve == 1 && report.converged == 1,
        "worker skipped fresh observation"
    );
    anyhow::ensure!(
        report.execution_failed == 0 && report.scan_failed == 0 && report.fenced == 0,
        "worker failed"
    );
    anyhow::ensure!(
        value(store, target.scope(), c).await? == 1,
        "effect missing"
    );
    anyhow::ensure!(
        store
            .claim_due(target.scope(), 1, Duration::from_secs(10), c)
            .await?
            .is_empty(),
        "completed work still pending"
    );
    Ok(())
}
pub async fn run(input: crate::pg::Input) -> anyhow::Result<()> {
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    let c = Control::new(&clock, Duration::from_secs(30), &cancel);
    let store = PgStore::new(input.pool().await?, &c).await?;
    let result = scenario(&store, TenantId::parse(&input.tenant)?, &clock, &c).await;
    let cleanup = Control::new(&clock, Duration::from_secs(5), &cancel);
    let closed = store.close(&cleanup).await;
    result?;
    anyhow::ensure!(closed == CloseOutcome::Drained, "reconcile close failed");
    Ok(())
}
