//! Matched arrival schedule, in a fresh database for each load and repetition.
use super::*;
use rss_timeseries::measurement;
use std::sync::Arc;
use tokio::task::JoinSet;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "isolated release-mode mixed preparation measurement"]
async fn arrivals() -> anyhow::Result<()> {
    let load = std::env::var("RSS_MIXED_LOAD")?;
    anyhow::ensure!(matches!(load.as_str(), "small" | "large" | "mixed"));
    let f = Arc::new(Fixture::new("ts-prepare-mixed").await?);
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let auth = authority(TENANT)?;
    let mut schedule = Vec::new();
    let mut sizes = [0; 2];
    // Send two large writers per burst to exercise the weighted queue even on
    // an idle pool. Small writers have exactly the same schedule in both arms.
    for i in 0..128 {
        for lane in 0..3 {
            let large = lane < 2;
            if large && (load == "small" || i % 32 != 0) || !large && load == "large" {
                continue;
            }
            let n = if large { Batch::MAX_SAMPLES } else { 1 };
            let input = prepare_measure::items(&d, i * 3 + lane, n, false)?;
            let b = batch(&format!("arrival-{i}-{lane}"), input)?;
            sizes[usize::from(large)] = b.encoded_len();
            schedule.push((i as u64, large, Authorized::<Batch>::verify(&auth, b)?));
        }
    }
    let full = f.store.available_preparation();
    let started = Timer.now();
    let mut writes = JoinSet::new();
    measurement::start(true);
    for (i, large, req) in schedule {
        let arrival = started + Duration::from_millis(2 * i);
        tokio::time::sleep_until(arrival.into()).await;
        let f = f.clone();
        let label = if large { "large" } else { "small" };
        writes.spawn(measurement::probe(label, async move {
            let cutoff = Deadline::from_timeout(&Timer, Duration::from_secs(90))?;
            anyhow::ensure!(matches!(
                f.store.write(&req, cutoff).await?,
                Outcome::Accepted(_)
            ));
            anyhow::Ok((usize::from(large), (Timer.now() - arrival).as_micros()))
        }));
    }
    let mut latencies = [Vec::new(), Vec::new()];
    while let Some(result) = writes.join_next().await {
        let (class, us) = result??;
        latencies[class].push(us);
    }
    let elapsed = Timer.now() - started;
    let report = measurement::finish();
    assert_eq!(f.store.available_preparation(), full);
    assert_eq!(
        (report.live_bytes, report.reserved_bytes, report.encoders),
        (0, 0, 0)
    );
    for (label, values) in ["small", "large"].into_iter().zip(&mut latencies) {
        if values.is_empty() {
            continue;
        }
        values.sort_unstable();
        let p = |q: usize| values[(q * values.len()).div_ceil(100) - 1];
        println!(
            "MIX {load} {label} n={} p95_us={} p99_us={} batches_s={:.1}",
            values.len(),
            p(95),
            p(99),
            values.len() as f64 / elapsed.as_secs_f64()
        );
    }
    waiting_cost(&report, full.0)?;
    for ((class, stage), total) in &report.probe_stages {
        if ["permit_wait", "pool_wait", "prepare"].contains(stage) {
            println!(
                "MIX_STAGE {load} {class} {stage} calls={} us={} charge_bytes={}",
                total.calls,
                total.elapsed.as_micros(),
                if *stage == "permit_wait" {
                    total.json_bytes
                } else {
                    0
                }
            );
        }
    }
    if load == "mixed" {
        let charge = |class| -> u64 {
            let t = &report.probe_stages[&(class, "permit_wait")];
            t.json_bytes / t.calls
        };
        assert!(
            charge("large") * 2 > full.1 as u64
                && charge("large") + charge("small") <= full.1 as u64
        );
    }
    println!(
        "MIX_CAP {load} input_bytes={sizes:?} slots={} bytes={} peak_reserved={} peak_buffers={} peak_encoders={}",
        full.0, full.1, report.peak_reserved_bytes, report.peak_live_bytes, report.peak_encoders
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "release-mode probes behind a byte-blocked writer"]
async fn byte_blocked_probes() -> anyhow::Result<()> {
    let fixture = Fixture::new("ts-byte-probes").await?;
    let d = definition(TENANT)?;
    fixture.register(&d).await?;
    let auth = authority(TENANT)?;
    let mut small_latency = Vec::new();
    let mut before_head = 0;
    for i in 0..32 {
        let request = |lane, size| {
            let input = prepare_measure::items(&d, lane, size, false)?;
            Ok::<_, anyhow::Error>(Authorized::<Batch>::verify(
                &auth,
                batch(&format!("load-{lane}"), input)?,
            )?)
        };
        let left = request(3 * i, Batch::MAX_SAMPLES)?;
        let head = request(3 * i + 1, Batch::MAX_SAMPLES)?;
        let small = request(3 * i + 2, 1)?;
        let cutoff = deadline()?;
        let mut first = Box::pin(fixture.store.write(&left, cutoff));
        let mut blocked = Box::pin(fixture.store.write(&head, cutoff));
        // Establish the same arrival order on either algorithm. The first
        // writer has its bytes, the second is queued, and the pool can run probes.
        for future in [&mut first, &mut blocked] {
            tokio::select! { biased; result=future.as_mut()=>anyhow::bail!("large batch completed on first poll: {result:?}"), ()=std::future::ready(())=>{} }
        }
        let arrival = Timer.now();
        let (a, b, s) = tokio::join!(first, async { (blocked.await, Timer.now()) }, async {
            (fixture.store.write(&small, cutoff).await, Timer.now())
        });
        confirmed(a?)?;
        confirmed(b.0?)?;
        confirmed(s.0?)?;
        before_head += usize::from(s.1 < b.1);
        small_latency.push((s.1 - arrival).as_micros());
    }
    small_latency.sort_unstable();
    println!(
        "BYTE_PROBE n={} before_queued_large={before_head} p95_us={} p99_us={}",
        small_latency.len(),
        small_latency[30],
        small_latency[31]
    );
    Ok(())
}

// The runtime records constant-size transitions. Replay them after all tasks
// settle, so measurement does not add a waiter scan to the capacity mutex.
fn wait_parts(
    samples: &[measurement::CapacitySample],
    wait: &measurement::PreparationWait,
) -> [Duration; 4] {
    let mut parts = [Duration::ZERO; 4];
    let first = samples
        .partition_point(|s| s.at <= wait.queued)
        .saturating_sub(1);
    let mut from = wait.queued;
    for (i, s) in samples[first..].iter().enumerate() {
        if from >= wait.granted {
            break;
        }
        let until = samples
            .get(first + i + 1)
            .map_or(wait.granted, |s| s.at.min(wait.granted));
        let reason = if s.slots == 0 {
            0
        } else if s.bytes < wait.weight {
            1
        } else {
            2
        };
        parts[reason] += until - from;
        from = until;
    }
    parts[3] = wait.resumed - wait.granted;
    parts
}
fn waiting_cost(report: &measurement::Report, slots: usize) -> anyhow::Result<()> {
    let samples = &report.capacity_samples;
    let mut peak_partial = 0;
    for s in samples.iter().filter(|s| s.queued > 0) {
        peak_partial = peak_partial.max(
            slots
                .checked_sub(s.slots as usize + s.granted)
                .ok_or(Error::Invariant)?,
        );
    }
    println!("WAIT_CAP peak_held_by_waiters={peak_partial}");
    assert_eq!(peak_partial, 0);
    for class in ["small", "large"] {
        let mut totals = [Duration::ZERO; 4];
        let mut arrivals = [0usize; 3];
        for w in report
            .preparation_waits
            .iter()
            .filter(|w| w.class == Some(class))
        {
            let entry = samples
                .partition_point(|s| s.at <= w.queued)
                .checked_sub(1)
                .ok_or(Error::Invariant)?;
            let s = &samples[entry];
            arrivals[if s.slots == 0 {
                0
            } else if s.bytes < w.weight {
                1
            } else {
                2
            }] += 1;
            let parts = wait_parts(samples, w);
            assert_eq!(parts.iter().sum::<Duration>(), w.resumed - w.queued);
            for (total, part) in totals.iter_mut().zip(parts) {
                *total += part;
            }
        }
        println!(
            "WAIT_PHASE {class} arrivals_slot_byte_order={arrivals:?} slot_us={} byte_us={} order_us={} wake_us={}",
            totals[0].as_micros(),
            totals[1].as_micros(),
            totals[2].as_micros(),
            totals[3].as_micros()
        );
    }
    Ok(())
}

#[test]
fn wait_attribution_splits_resource_changes_and_wakeup() {
    let start = Timer.now();
    let at = |n| start + Duration::from_millis(n);
    let samples = [(0, 0, 0), (2, 1, 1), (5, 1, 4), (9, 0, 0)].map(|(n, slots, bytes)| {
        measurement::CapacitySample {
            at: at(n),
            slots,
            bytes,
            queued: 1,
            granted: 0,
        }
    });
    let w = measurement::PreparationWait {
        class: Some("small"),
        weight: 3,
        queued: start,
        granted: at(9),
        resumed: at(14),
    };
    assert_eq!(
        wait_parts(&samples, &w),
        [2, 3, 4, 5].map(Duration::from_millis)
    );
}
