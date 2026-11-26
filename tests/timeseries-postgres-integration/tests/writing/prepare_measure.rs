//! Run each load in a fresh release-mode test process on both revisions.
//! With Docker available, select repeat, unique, large or dense via RSS_PREPARE_LOAD.
//! Run `cargo test --release --locked -p timeseries-postgres-integration --test suite -- writing::prepare_measure::fixed_load --exact --ignored --nocapture`.
//! RSS_PREPARE_TIMING=1 disables per-object instrumentation for independent stage timings.
//! The measurement-only baseline revision and results are recorded in PR 1750.
use super::*;
use rss_timeseries::measurement::{self, Session};
use tokio::sync::Semaphore;
async fn first_poll<F: Future>(
    mut future: std::pin::Pin<&mut F>,
    entered: &Semaphore,
) -> anyhow::Result<()> {
    tokio::select! { biased;
        _=&mut future => anyhow::bail!("operation completed with every connection held"),
        ()=std::future::ready(())=>entered.add_permits(1),
    }
    Ok(())
}
async fn wait_for_polls(entered: &Semaphore, count: usize) -> anyhow::Result<()> {
    tokio::time::timeout(
        Duration::from_secs(15),
        entered.acquire_many(count.try_into()?),
    )
    .await??
    .forget();
    Ok(())
}
use std::sync::Arc;
use tokio::task::JoinSet;

fn rss_kib() -> anyhow::Result<usize> {
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()?;
    anyhow::ensure!(out.status.success());
    Ok(std::str::from_utf8(&out.stdout)?.trim().parse()?)
}

fn items(d: &Definition, lane: usize, n: usize, unique: bool) -> anyhow::Result<Vec<Sample>> {
    let source = id(&format!("source-{lane:03}"))?;
    let wide = n == Batch::MAX_SAMPLES;
    let resource = id(&"r".repeat(if wide { 200 } else { 8 }))?;
    (0..n)
        .map(|j| {
            let mut input = sample(d, &format!("s-{lane:03}-{j:04}"), j as i64, j as u64)?
                .input()
                .clone();
            input.stream = Stream::new(d.spec().scope.clone(), source.clone(), id("generation")?);
            let subject = format!(
                "s{:0width$}",
                if unique { j } else { 0 },
                width = if wide { 199 } else { 4 }
            );
            input.series = Series::new(
                d.clone(),
                id(&subject)?,
                resource.clone(),
                Default::default(),
            )?;
            Ok(Sample::new(input)?)
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "isolated fixed-load PostgreSQL preparation comparison"]
async fn fixed_load() -> anyhow::Result<()> {
    let load = std::env::var("RSS_PREPARE_LOAD").unwrap_or_else(|_| "repeat".into());
    let (jobs, samples, unique, pressure) = match load.as_str() {
        "repeat" => (4, 1024, false, false),
        "unique" => (4, 1024, true, false),
        "large" => (8, 4096, false, true),
        "dense" => (96, 1, false, true),
        _ => anyhow::bail!("unknown load"),
    };
    let f = Arc::new(Fixture::new("ts-prepare-measure").await?);
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let seed = batch("seed", vec![sample(&d, "seed", 1, 1)?])?;
    confirmed(f.write(&seed).await?)?;
    let lookup = Authorized::<ReceiptQuery>::verify(&authority(TENANT)?, receipt_query(&seed)?)?;
    let probe = batch("probe", vec![sample(&d, "probe", 2, 1)?])?;
    let mut occupied = Vec::new();
    for _ in 0..f.pool.options().get_max_connections() {
        occupied.push(f.pool.acquire().await?);
    }
    if !pressure {
        occupied.clear();
    }
    let mut input = (0..jobs)
        .map(|i| items(&d, i, samples, unique))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let rss_start = rss_kib()?;
    let detail = std::env::var_os("RSS_PREPARE_TIMING").is_none();
    measurement::start(detail);
    let entered = Arc::new(Semaphore::new(0));
    let mut writes = JoinSet::new();
    let barrier = Arc::new(tokio::sync::Barrier::new(jobs + 1));
    for (i, samples) in input.drain(..).enumerate() {
        let start = measurement::timer();
        let b = batch(&format!("batch-{i:03}"), samples)?;
        measurement::record("batch_new", start, 0, 0);
        let req = Authorized::<Batch>::verify(&authority(TENANT)?, b)?;
        let entered = entered.clone();
        let f = f.clone();
        let ready = barrier.clone();
        writes.spawn(async move {
            ready.wait().await;
            let cutoff = Deadline::from_timeout(&Timer, Duration::from_secs(90))?;
            let mut op = Box::pin(f.store.write(&req, cutoff));
            if pressure {
                first_poll(op.as_mut(), &entered).await?;
            }
            anyhow::ensure!(matches!(op.await?, Outcome::Accepted(_)));
            anyhow::Ok(())
        });
    }
    barrier.wait().await;
    let mut peak_rss = rss_kib()?;
    let mut probes = JoinSet::new();
    let mut all_released = None;
    if pressure {
        wait_for_polls(&entered, jobs).await?;
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let mut at_pool = false;
                Session::current().update(|r| at_pool = r.stages.contains_key("pool_enter"));
                if at_pool {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await?;
        for _ in 0..10 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            peak_rss = peak_rss.max(rss_kib()?);
        }
        let read = f.clone();
        let read_entered = entered.clone();
        probes.spawn(async move {
            let start = Timer.now();
            let mut op = Box::pin(read.store.receipt(&lookup, deadline()?));
            first_poll(op.as_mut(), &read_entered).await?;
            let result = op.await;
            anyhow::ensure!(matches!(result?, Lookup::Found(_)));
            anyhow::Ok(("receipt", start.elapsed(), Timer.now()))
        });
        let write = f.clone();
        let write_entered = entered.clone();
        probes.spawn(async move {
            let start = Timer.now();
            let mut op = Box::pin(write.write(&probe));
            first_poll(op.as_mut(), &write_entered).await?;
            anyhow::ensure!(confirmed(op.await?)?.new_samples() == 1);
            anyhow::Ok(("write", start.elapsed(), Timer.now()))
        });
        wait_for_polls(&entered, 2).await?;
        drop(occupied.pop());
        for _ in 0..8 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            peak_rss = peak_rss.max(rss_kib()?);
        }
        all_released = Some(Timer.now());
        occupied.clear();
    }
    while !writes.is_empty() {
        tokio::select! {
            Some(r) = writes.join_next() => r??,
            () = tokio::time::sleep(Duration::from_millis(10)) => { peak_rss=peak_rss.max(rss_kib()?); }
        }
    }
    while let Some(r) = probes.join_next().await {
        let (kind, latency, ack) = r??;
        println!(
            "PROBE {kind} ok=1 single_slot={} latency_us={}",
            all_released.is_some_and(|end| ack <= end),
            latency.as_micros()
        );
    }
    let report = rss_timeseries::measurement::finish();
    anyhow::ensure!(report.live_bytes == 0 && report.reserved_bytes == 0);
    for (name, s) in report.stages {
        println!(
            "STAGE {name} calls={} json={} sha={} ns={}",
            s.calls,
            s.json_bytes,
            s.sha_bytes,
            s.elapsed.as_nanos()
        );
    }
    println!(
        "LOAD {load} jobs={jobs} samples={samples} bind={} peak_buffers={} peak_reserved={} rss_start_kib={rss_start} rss_peak_kib={} rss_end_kib={}",
        report.bind_bytes,
        report.peak_live_bytes,
        report.peak_reserved_bytes,
        peak_rss.max(rss_kib()?),
        rss_kib()?
    );
    Ok(())
}
