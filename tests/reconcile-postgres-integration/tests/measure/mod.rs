//! Run the same manual load on the baseline and candidate, outside the CI timing gate.
use super::*;
use futures::future::try_join_all;
mod timing;

const LEASE: Duration = Duration::from_secs(300);
const WORKERS: usize = 4;
const BATCH: usize = 4;
const BUDGET: u32 = 16;
const WARM: Duration = Duration::from_secs(1);
const WINDOW: Duration = Duration::from_secs(3);

async fn seed(db: &Database, store: &PgStore, c: &Control<'_, Clock>) -> anyhow::Result<Scope> {
    sqlx::raw_sql("TRUNCATE rss_reconcile.target_resources,rss_reconcile.resources,rss_reconcile.targets,rss_reconcile.scans; ALTER SEQUENCE rss_reconcile.queue_tickets RESTART")
        .execute(&db.owner).await?;
    let scope = Scope::new(TenantId::parse(TENANT)?, "fixed-load")?;
    let holder = Target::new(scope.clone(), "holder")?;
    store
        .wake(&holder, &ResourceSet::new(scope.tenant(), ["shared"])?, c)
        .await?;
    claim(store, &holder, LEASE, c).await?;
    for i in 0..40 {
        let name = format!("item-{i}");
        let mut keys: Vec<_> = (0..3).map(|j| format!("{name}:{j}")).collect();
        keys.push(if i < 32 {
            "shared".into()
        } else {
            format!("{name}:3")
        });
        store
            .wake(
                &Target::new(scope.clone(), name)?,
                &ResourceSet::new(scope.tenant(), keys)?,
                c,
            )
            .await?;
    }
    Ok(scope)
}

#[derive(Default)]
struct Counts {
    calls: usize,
    empty: usize,
    claims: usize,
}
async fn load(
    store: &PgStore,
    scope: &Scope,
    clock: &Clock,
    c: &Control<'_, Clock>,
    window: Duration,
) -> anyhow::Result<(Counts, f64)> {
    let start = clock.now();
    let lanes = try_join_all((0..WORKERS).map(|_| async {
        let mut counts = Counts::default();
        while clock.now() - start < window {
            let batch = store.claim_due(scope, BATCH, BUDGET, LEASE, c).await?;
            counts.calls += 1;
            counts.empty += usize::from(batch.claims.is_empty());
            counts.claims += batch.claims.len();
            for selected in batch.claims {
                store.release(&selected, c).await?;
            }
        }
        Ok::<_, anyhow::Error>(counts)
    }))
    .await?;
    let mut total = Counts::default();
    for counts in lanes {
        total.calls += counts.calls;
        total.empty += counts.empty;
        total.claims += counts.claims;
    }
    anyhow::ensure!(
        total.claims > 0 && total.empty > 0,
        "load missed contention or progress"
    );
    Ok((total, (clock.now() - start).as_secs_f64()))
}

async fn count_writes(
    db: &Database,
    store: &PgStore,
    scope: &Scope,
    clock: &Clock,
    c: &Control<'_, Clock>,
) -> anyhow::Result<(i64, usize)> {
    // Rows in this isolated probe commit atomically with the update they count.
    sqlx::raw_sql("CREATE TABLE public.same_ticket(n int); GRANT INSERT ON public.same_ticket TO reconcile_owner;
        CREATE FUNCTION public.count_ticket() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN INSERT INTO public.same_ticket VALUES(1); RETURN NULL; END $$;
        CREATE TRIGGER count_ticket AFTER UPDATE OF waiting_ticket ON rss_reconcile.target_resources FOR EACH ROW
        WHEN (OLD.waiting_ticket IS NOT DISTINCT FROM NEW.waiting_ticket) EXECUTE FUNCTION public.count_ticket()")
        .execute(&db.owner).await?;
    let (counts, _) = load(store, scope, clock, c, WINDOW).await?;
    let count = sqlx::query_scalar("SELECT count(*) FROM public.same_ticket")
        .fetch_one(&db.owner)
        .await?;
    sqlx::raw_sql("DROP TRIGGER count_ticket ON rss_reconcile.target_resources; DROP FUNCTION public.count_ticket(); DROP TABLE public.same_ticket")
        .execute(&db.owner).await?;
    Ok((count, counts.calls))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "explicit same-load PostgreSQL comparison on both revisions"]
async fn fixed_load() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(180), measure()).await?
}

async fn measure() -> anyhow::Result<()> {
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    let c = Control::new(&clock, Duration::from_secs(150), &cancel);
    let db = Database::new(&c).await?;
    let store = PgStore::new(db.pool.clone(), &c).await?;
    timing::install(&db.owner).await?;
    for round in 1..=3 {
        let scope = seed(&db, &store, &c).await?;
        load(&store, &scope, &clock, &c, WARM).await?;
        let (counts, elapsed) = load(&store, &scope, &clock, &c, WINDOW).await?;
        let (same, write_calls) = count_writes(&db, &store, &scope, &clock, &c).await?;
        let bounds = timing::sample(&db.pool, &scope, &clock).await?;
        println!(
            "MEASURE round={round} calls={} empty={} claims={} elapsed_s={elapsed:.4} claims_s={:.2} same_ticket_updates={same} write_calls={write_calls} {bounds}",
            counts.calls,
            counts.empty,
            counts.claims,
            counts.claims as f64 / elapsed
        );
    }
    assert_eq!(store.close(&c).await, CloseOutcome::Drained);
    Ok(())
}
