//! Run each RSS_QUEUE_LOAD (2, 8, 24, mixed, pair) in a fresh release test process.
//! From the workspace root, with Docker available:
//! ```text
//! RSS_TEST_RUN_ID="rss-$(uuidgen)" RSS_QUEUE_LOAD=mixed cargo run --release --locked -p testkit --features containers --bin rss-test-launcher -- -- cargo test --release --locked -p timeseries-postgres-integration --test suite -- writing::queue_measure::load --exact --ignored --nocapture
//! ```
use super::{
    prepare_measure::{items, rss_kib},
    *,
};
use rss_timeseries::measurement;

#[tokio::test]
#[ignore = "isolated PostgreSQL preparation queue measurement"]
async fn load() -> anyhow::Result<()> {
    let load = std::env::var("RSS_QUEUE_LOAD")?;
    let mut caps = limits()?;
    caps.max_prepare_waiters = 2;
    let limit = caps.max_prepare_waiters as usize;
    let f = Fixture::with_limits(
        "ts-queue-measure",
        rss_timeseries_postgres::StorageProfile::PostgreSQL,
        caps,
    )
    .await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let warm = batch("warm", vec![sample(&d, "warm", 1, 1)?])?;
    confirmed(f.write(&warm).await?)?;
    if load == "pair" {
        return pair_latency(&f, &d).await;
    }
    let jobs = match load.as_str() {
        "2" => 2,
        "8" => 8,
        "24" | "mixed" => 24,
        _ => anyhow::bail!("unknown queue load {load}"),
    };
    let mut held = Vec::new();
    for _ in 0..f.pool.options().get_max_connections() {
        held.push(f.pool.acquire().await?);
    }
    let full = f.store.available_preparation();
    let mut granted = Vec::new();
    let mut queued = Vec::new();
    let mut rejected = 0;
    let mut input_bytes = 0;
    let start_rss = rss_kib()?;
    let mut peak_rss = start_rss;
    measurement::start(true);
    for i in 0..jobs {
        let small = load == "mixed" && i % 3 == 2;
        let samples = items(&d, i, if small { 1 } else { Batch::MAX_SAMPLES }, false)?;
        let b = batch(&format!("pressure-{i:03}"), samples)?;
        let size = b.encoded_len();
        let r = Authorized::<Batch>::verify(&authority(TENANT)?, b)?;
        let store = &f.store;
        let cutoff = Deadline::from_timeout(&Timer, Duration::from_secs(90))?;
        let mut write = Box::pin(async move { store.write(&r, cutoff).await });
        let before = store.available_preparation();
        let bound_before = store.preparation_phases()[1];
        let result = tokio::select! { biased;
            result = &mut write => Some(result),
            () = std::future::ready(()) => None,
        };
        match result {
            Some(Err(Error::Overloaded)) => rejected += 1,
            Some(result) => anyhow::bail!("unexpected first poll {result:?}"),
            None if store.available_preparation() == before => {
                assert!(queued.len() < limit, "preparation queue exceeded its limit");
                input_bytes += size;
                queued.push(write);
            }
            None => {
                // Drive all cooperative encoding yields up to the held pool.
                while store.preparation_phases()[1] == bound_before {
                    tokio::select! { biased;
                        result = &mut write => anyhow::bail!("unexpected write {result:?}"),
                        () = tokio::task::yield_now() => {}
                    }
                }
                granted.push(write);
            }
        }
        peak_rss = peak_rss.max(rss_kib()?);
    }
    let (active, waiting) = (granted.len(), queued.len());
    let stable_rss = rss_kib()?;
    // In the mixed run, observe one real queued grant before cancelling it at the held pool.
    let survivor = if load == "mixed" { queued.pop() } else { None };
    drop(queued);
    drop(granted);
    if let Some(mut write) = survivor {
        tokio::select! { biased;
            result = &mut write => anyhow::bail!("resumed write settled with the pool held: {result:?}"),
            () = std::future::ready(()) => {}
        }
    }
    let report = measurement::finish();
    assert_eq!(report.preparation_waits.len(), usize::from(load == "mixed"));
    let wait_us = report
        .preparation_waits
        .first()
        .map(|w| (w.granted - w.queued).as_micros());
    let peak_waiters = report
        .capacity_samples
        .iter()
        .map(|s| s.queued)
        .max()
        .unwrap_or(0);
    assert_eq!(report.preparation_rejections, rejected as u64);
    assert_eq!(peak_waiters, waiting);
    assert_eq!(waiting, limit.min(jobs - active));
    assert_eq!(rejected, jobs - active - waiting);
    if load != "mixed" {
        assert_eq!(active, 1);
    }
    assert_eq!(report.capacity_samples.last().map(|s| s.queued), Some(0));
    assert!(report.peak_reserved_bytes <= full.1);
    assert_eq!((report.granted_batches, report.reserved_bytes), (0, 0));
    assert_eq!(f.store.available_preparation(), full);
    assert_eq!(f.count().await?, 1); // Only the warm-up write was committed.
    println!(
        "QUEUE {load} active={active} queued={waiting} rejected={rejected} input_bytes={input_bytes} queued_grant_us={wait_us:?} peak_charge={} rss_start_kib={start_rss} rss_peak_kib={peak_rss} rss_held_kib={stable_rss} rss_cancelled_kib={} cancelled={} writes_committed=0",
        report.peak_reserved_bytes,
        rss_kib()?,
        active + waiting
    );
    Ok(())
}

async fn pair_latency(f: &Fixture, d: &Definition) -> anyhow::Result<()> {
    let mut us = Vec::new();
    for i in 0..16 {
        let request = |lane| -> anyhow::Result<_> {
            let b = batch(&format!("pair-{lane:03}"), items(d, lane, 1, false)?)?;
            Ok(Authorized::<Batch>::verify(&authority(TENANT)?, b)?)
        };
        let write = |req| async move {
            let start = Timer.now();
            assert!(matches!(
                f.store.write(&req, deadline()?).await?,
                Outcome::Accepted(_)
            ));
            anyhow::Ok((Timer.now() - start).as_micros())
        };
        let (a, b) = tokio::try_join!(write(request(i * 2)?), write(request(i * 2 + 1)?))?;
        us.extend([a, b]);
    }
    us.sort_unstable();
    println!(
        "PAIR samples={} p50_us={} p95_us={} p99_us={}",
        us.len(),
        us[15],
        us[30],
        us[31]
    );
    Ok(())
}
