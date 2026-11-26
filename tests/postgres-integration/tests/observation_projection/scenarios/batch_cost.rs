//! Same public journal and Facts mapping for single-event and page execution.
use super::*;
use rss_projection::Timer as _;
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::collections::BTreeMap;

const PAGE: u32 = 8;
const EVENTS: u64 = 25;

#[tokio::test]
async fn observation_batch_sql_cost() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let stream = scope(TENANT, "batch-cost", "r1", "agent", "e1")?;
    let store = f.store().await?;
    activate(&store, &stream, None).await?;
    for i in 0..EVENTS {
        let changes = vec![up("key", i as u8)?];
        let body = if i == 0 {
            Body::Snapshot(changes)
        } else {
            Body::Delta {
                baseline: Id::new("event-0")?,
                previous: i - 1,
                changes,
            }
        };
        store
            .receive(
                &batch(&stream, &format!("event-{i}"), i, "cost", body)?,
                deadline(),
            )
            .await?;
    }
    sqlx::raw_sql("CREATE TABLE public.cost_xids (xid xid8 PRIMARY KEY);
        CREATE FUNCTION public.cost_xid() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN INSERT INTO public.cost_xids VALUES(pg_current_xact_id()) ON CONFLICT DO NOTHING; RETURN NULL; END $$;
        GRANT INSERT ON public.cost_xids TO handoff_runtime;
        CREATE TRIGGER cost_xid AFTER INSERT OR UPDATE OR DELETE ON public.observation_facts
        FOR EACH STATEMENT EXECUTE FUNCTION public.cost_xid()").execute(&f.admin).await?;
    let raw: i64 =
        sqlx::query_scalar("SELECT sum(octet_length(raw))::bigint FROM rss_observation.batches")
            .fetch_one(&f.admin)
            .await?;
    if std::env::var_os("RSS_PG_WORK_PROFILE").is_some() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter("sqlx::postgres::notice=info")
            .with_ansi(false)
            .try_init();
        sqlx::raw_sql(
            "ALTER ROLE handoff_runtime SET session_preload_libraries='auto_explain';
            ALTER ROLE handoff_runtime SET auto_explain.log_min_duration=0;
            ALTER ROLE handoff_runtime SET auto_explain.log_nested_statements=on;
            ALTER ROLE handoff_runtime SET auto_explain.log_analyze=on;
            ALTER ROLE handoff_runtime SET auto_explain.log_buffers=on;
            ALTER ROLE handoff_runtime SET auto_explain.log_timing=off;
            ALTER ROLE handoff_runtime SET auto_explain.log_format=json;
            ALTER ROLE handoff_runtime SET auto_explain.log_level=notice",
        )
        .execute(&f.admin)
        .await?;
    }
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(f.options.clone())
        .await?;
    let clock = ProjectionClock(rss_observation::Clock::now(&Clock));
    let stop = tokio_util::sync::CancellationToken::new();
    let control = Control::new(&clock, Duration::from_secs(120), &stop);
    let source = f.source(
        Arc::new(ObsStore::new(pool.clone(), Clock, deadline()).await?),
        TENANT,
    )?;
    let projection = rss_projection_postgres::PgStore::new(pool.clone(), &control).await?;
    let all = source
        .read(
            source.scope(),
            None,
            BatchLimit::new(EVENTS as u32)?,
            &control,
        )
        .await?;
    let mut expected: Vec<_> = all
        .iter()
        .map(|e| (e.id().to_owned(), e.fingerprint().to_vec()))
        .collect();
    expected.sort();
    let history: i32 = std::env::var("RSS_PROJECTION_HISTORY")
        .ok()
        .map(|s| s.parse())
        .transpose()?
        .unwrap_or(0);
    for mode in ["single", "batch"] {
        let s = ProjectionScope::new(source.scope().clone(), "cost", mode)?;
        let exec = session(&projection, &s, &source, &control).await?;
        sqlx::query("INSERT INTO rss_projection.receipts SELECT tenant_id,source_id,projection_id,generation,'history-'||i,decode(repeat('00',32),'hex'),false FROM rss_projection.checkpoints CROSS JOIN generate_series(1,$2) i WHERE generation=$1").bind(mode).bind(history).execute(&f.admin).await?;
        sqlx::raw_sql("ANALYZE rss_projection.receipts; TRUNCATE public.cost_xids")
            .execute(&f.admin)
            .await?;
        let before = counters(&pool).await?;
        let limit = RunLimit::new(BatchLimit::new(PAGE)?, EVENTS)?;
        println!("PROJECTION_PROFILE_BEGIN {mode}");
        let start = clock.now();
        let report = if mode == "single" {
            rss_projection::run(&*source, &exec, &control, limit).await
        } else {
            rss_projection::run_batched(&*source, &exec, &control, limit).await
        }
        .into_result()?;
        let elapsed = clock.now() - start;
        println!("PROJECTION_PROFILE_END {mode}");
        let mut delta = counters(&pool).await?;
        for (key, value) in before {
            *delta.entry(key).or_default() -= value;
        }
        // Runner reads once before the first source page. Only later reads belong to batch management.
        *delta.entry("checkpoint".into()).or_default() -= 1;
        let xids: i64 = sqlx::query_scalar("SELECT count(*) FROM public.cost_xids")
            .fetch_one(&f.admin)
            .await?;
        println!(
            "projection_cost mode={mode} history={history} raw_bytes={raw} elapsed_us={} xids={xids} counters={delta:?}",
            elapsed.as_micros()
        );
        assert_eq!(
            (report.position, report.applied),
            (all.last().map(Event::position), EVENTS)
        );
        assert_eq!(
            values(&f, mode, "cost").await?,
            vec![("key".into(), vec![24])]
        );
        let mut receipts: Vec<(String,Vec<u8>)> = sqlx::query_as("SELECT event_id,fingerprint FROM rss_projection.receipts WHERE generation=$1 AND event_id NOT LIKE 'history-%'").bind(mode).fetch_all(&f.admin).await?;
        receipts.sort();
        assert_eq!(receipts, expected);
        let count = |key: &str| delta.get(key).copied().unwrap_or(0);
        let calls = if mode == "single" { 25 } else { 4 };
        assert_eq!(
            (count("checkpoint"), count("lock"), count("finish")),
            (0, calls, calls)
        );

        assert_eq!(xids, calls);
    }
    Ok(())
}

pub(super) async fn counters(pool: &PgPool) -> anyhow::Result<BTreeMap<String, i64>> {
    let rows = sqlx::query_as::<_, (String, i64)>(
        "SELECT statement,custom_plans+generic_plans FROM pg_prepared_statements",
    )
    .fetch_all(pool)
    .await?;
    let mut totals = BTreeMap::new();
    for (sql, count) in rows {
        let category = if sql.starts_with("SELECT position,replay") {
            "checkpoint"
        } else if sql.starts_with("SELECT rss_projection.lock_") {
            "lock"
        } else if sql.starts_with("SELECT rss_projection.finish_") {
            "finish"
        } else if sql.contains("rss_observation.batches")
            && !sql.contains("rss_observation.journals")
        {
            "resolve"
        } else if sql.contains("public.observation_facts")
            && (sql.starts_with("DELETE") || sql.starts_with("INSERT"))
        {
            "effect"
        } else if sql.contains("rss_observation.journals") {
            "page"
        } else if sql.starts_with("SELECT set_config(") {
            "setup"
        } else {
            continue;
        };
        *totals.entry(category.to_owned()).or_default() += count;
    }
    Ok(totals)
}
