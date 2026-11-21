//! Opt-in before/after measurement. Run this same module against both revisions.
use super::*;
use std::sync::Arc;

struct Load {
    samples: usize,
    definitions: usize,
    series: usize,
    workers: usize,
    separate_namespaces: bool,
}

// Each pool connection exposes its own server-side prepared statement execution counters.
// Hold every lease while summing to count each backend once; exclude the observer itself.
async fn calls(pool: &PgPool) -> anyhow::Result<i64> {
    let mut leases = Vec::new();
    let mut count = 0;
    for _ in 0..pool.options().get_max_connections() {
        let mut c = pool.acquire().await?;
        count+=sqlx::query_scalar::<_,i64>("SELECT coalesce(sum(custom_plans+generic_plans),0)::bigint FROM pg_prepared_statements WHERE statement NOT LIKE '%pg_prepared_statements%'").fetch_one(&mut *c).await?;
        leases.push(c);
    }
    Ok(count)
}
async fn inputs(f: &Fixture, tag: usize, load: &Load) -> anyhow::Result<Vec<Authorized<Batch>>> {
    let mut all = Vec::new();
    let streams = if load.workers == 1 && load.samples != 64 {
        1
    } else {
        4
    };
    let mut namespaces = Vec::new();
    for ns in 0..if load.separate_namespaces { streams } else { 1 } {
        let mut defs = Vec::new();
        for k in 0..load.definitions {
            let mut spec = definition(TENANT)?.spec().clone();
            spec.scope = Scope::new(
                TenantId::parse(TENANT)?,
                id(&format!("measure-{tag}-{ns}"))?,
            );
            spec.key = id(&format!("metric-{k}"))?;
            let d = Definition::new(spec)?;
            f.register(&d).await?;
            defs.push(d);
        }
        namespaces.push(defs);
    }
    for b in 0..if load.samples > 1000 { 4 } else { 16 } {
        let lane = b % streams;
        let defs = &namespaces[if load.separate_namespaces { lane } else { 0 }];
        let stream = Stream::new(
            defs[0].spec().scope.clone(),
            id(&format!("source-{lane}"))?,
            id("generation")?,
        );
        let mut items = Vec::new();
        for j in 0..load.samples {
            let d = &defs[j % load.definitions];
            let mut input = sample(d, &format!("id-{b}-{j}"), j as i64, j as u64)?
                .input()
                .clone();
            input.stream = stream.clone();
            input.series = Series::new(
                d.clone(),
                id(&format!("subject-{}", j % load.series))?,
                id("resource")?,
                Default::default(),
            )?;
            items.push(Sample::new(input)?);
        }
        all.push(Authorized::<Batch>::verify(
            &authority(TENANT)?,
            batch(&format!("batch-{b}"), items)?,
        )?);
    }
    Ok(all)
}

async fn measure(f: Arc<Fixture>, tag: usize, load: Load) -> anyhow::Result<()> {
    let batches = inputs(&f, tag, &load).await?;
    let committed = batches.len();
    let mut lanes: Vec<Vec<_>> = (0..load.workers).map(|_| Vec::new()).collect();
    for (index, batch) in batches.into_iter().enumerate() {
        lanes[index % load.workers].push(batch);
    }
    let start_calls = calls(&f.pool).await?;
    let lsn: String = sqlx::query_scalar("SELECT pg_current_wal_insert_lsn()::text")
        .fetch_one(&f.admin)
        .await?;
    let start = Timer.now();
    let mut jobs = tokio::task::JoinSet::new();
    for lane in lanes {
        let fixture = f.clone();
        jobs.spawn(async move {
            let mut latency = Vec::new();
            for batch in lane {
                let t = Timer.now();
                let outcome = fixture
                    .store
                    .write(
                        &batch,
                        Deadline::from_timeout(&Timer, Duration::from_secs(90))?,
                    )
                    .await?;
                anyhow::ensure!(matches!(outcome, Outcome::Accepted(_)));
                latency.push(t.elapsed().as_micros());
            }
            anyhow::Ok(latency)
        });
    }
    let mut latency = Vec::new();
    let mut waits = 0i64;
    let mut polls = 0;
    let mut interval = tokio::time::interval(Duration::from_millis(5));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    while !jobs.is_empty() {
        tokio::select! {
            result=jobs.join_next()=>latency.extend(result.ok_or_else(||anyhow::anyhow!("missing worker"))???),
            _=interval.tick()=>{
                waits+=sqlx::query_scalar::<_,i64>("SELECT count(*) FROM pg_stat_activity WHERE usename='ts_runtime' AND wait_event_type='Lock'").fetch_one(&f.admin).await?;
                polls+=1;
            }
        }
    }
    let elapsed = start.elapsed();
    let wal: i64 = sqlx::query_scalar(
        "SELECT pg_wal_lsn_diff(pg_current_wal_insert_lsn(),$1::pg_lsn)::bigint",
    )
    .bind(lsn)
    .fetch_one(&f.admin)
    .await?;
    let calls = calls(&f.pool).await? - start_calls;
    latency.sort_unstable();
    let quantile = |q: usize| latency[(q * latency.len()).div_ceil(100) - 1];
    println!(
        "MEASURE samples={} defs={} series={} workers={} separate={} confirmed_tx={} sql={} wal={} p50_us={} p95_us={} samples_sec={:.0} lock_waiter_observations={} polls={}",
        load.samples,
        load.definitions,
        load.series,
        load.workers,
        load.separate_namespaces,
        committed,
        calls,
        wal,
        quantile(50),
        quantile(95),
        (load.samples * committed) as f64 / elapsed.as_secs_f64(),
        waits,
        polls
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "fixed-load PostgreSQL performance evidence, run explicitly on both revisions"]
async fn fixed_load() -> anyhow::Result<()> {
    let f = Arc::new(Fixture::new("ts-write-measure").await?);
    let mut loads = Vec::new();
    for (samples, definitions, series) in [
        (1, 1, 1),
        (100, 1, 1),
        (100, 4, 16),
        (1000, 4, 16),
        (4096, 4, 16),
    ] {
        loads.push(Load {
            samples,
            definitions,
            series,
            workers: 1,
            separate_namespaces: false,
        });
    }
    for workers in [1, 2, 4] {
        for separate_namespaces in [false, true] {
            loads.push(Load {
                samples: 64,
                definitions: 1,
                series: 4,
                workers,
                separate_namespaces,
            });
        }
    }
    for (tag, load) in loads.into_iter().enumerate() {
        measure(f.clone(), tag, load).await?;
    }
    Ok(())
}
