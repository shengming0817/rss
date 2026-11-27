use super::*;
use rss_observation::Batch;
use rss_observation_postgres::read_profile::{ReadProfile, ReadWork};
use sqlx::postgres::PgPoolOptions;
use std::sync::atomic::Ordering::Relaxed;
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn small_page_cost() -> anyhow::Result<()> {
    measure("small").await
}
#[tokio::test]
async fn large_page_cost() -> anyhow::Result<()> {
    measure("large").await
}
#[tokio::test]
async fn mixed_page_cost() -> anyhow::Result<()> {
    measure("mixed").await
}

#[tokio::test]
async fn small_reference_page_cost() -> anyhow::Result<()> {
    measure_references("small").await
}
#[tokio::test]
async fn large_reference_page_cost() -> anyhow::Result<()> {
    measure_references("large").await
}
#[tokio::test]
async fn mixed_reference_page_cost() -> anyhow::Result<()> {
    measure_references("mixed").await
}

pub(super) async fn seed_page(f: &Fixture, shape: &str) -> anyhow::Result<Vec<u32>> {
    let store = f.store().await?;
    let stream = scope(TENANT, "read-cost", "r", "s", "e")?;
    activate(&store, &stream, None).await?;
    let mut sizes = Vec::new();
    for i in 0..8 {
        let large = shape == "large" || shape == "mixed" && i % 2 == 0;
        let len = if large { 65_000 } else { 1 };
        let changes = (0..16)
            .map(|key| {
                Ok(Change::upsert(
                    Id::new(key.to_string())?,
                    vec![240 + i as u8; len],
                ))
            })
            .collect::<Result<Vec<_>, rss_observation::Error>>()?;
        let body = if i == 0 {
            Body::Snapshot(changes)
        } else {
            Body::Delta {
                baseline: Id::new("b0")?,
                previous: i - 1,
                changes,
            }
        };
        let input = batch(&stream, &format!("b{i}"), i, "cost", body)?;
        let n = u32::try_from(input.batch().encode().len())?;
        let max = Batch::MAX_ENCODED_BYTES;
        assert!(!large || (max - max / 100..=max).contains(&n));
        store.receive(&input, deadline()).await?;
        sizes.push(n);
    }
    Ok(sizes)
}

async fn measure_references(shape: &str) -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let sizes = seed_page(&f, shape).await?;
    let store = f.store().await?;
    let max = Batch::MAX_ENCODED_BYTES;
    // Large: the first two exactly fit. Mixed: a later small report could fit
    // behind the excluded large report, but must wait for the following page.
    let budget = if shape == "large" {
        sizes[0] + sizes[1]
    } else {
        max
    };
    let source = f.reference_source(store, TENANT, budget)?;
    let clock = ProjectionClock(rss_observation::Clock::now(&Clock));
    let stop = CancellationToken::new();
    let control = Control::new(&clock, Duration::from_secs(180), &stop);
    let limit = page_budget(8)?;
    let mut start = 0;
    let mut after = None;
    while start < sizes.len() {
        let mut bytes = 0;
        let mut end = start;
        while end < sizes.len() && sizes[end] <= budget - bytes {
            bytes += sizes[end];
            end += 1;
        }
        let count = (end - start) as u64;
        assert!(count > 0);
        let work = async {
            let page = expected_events(source.read(source.scope(), after, limit, &control).await?)?;
            assert_eq!(page.len() as u64, count);
            for (index, event) in page.iter().enumerate() {
                assert_eq!(event.position().get(), (start + index + 1) as u64);
                let record = source.resolve(event, &control).await?;
                assert_eq!(
                    record.record().batch().encode().len(),
                    sizes[start + index] as usize
                );
            }
            Ok::<_, anyhow::Error>(())
        };
        let (result, profile) = profiled(&format!("reference-{shape}-{start}"), work).await?;
        result?;
        let expected = [u64::from(bytes), count, count, count, 0];
        assert_eq!(totals(&profile.source), expected);
        assert_eq!(totals(&profile.resolver), expected);
        println!(
            "observation_reference shape={shape} after={start} end={end} budget={budget} source={:?} resolver={:?}",
            profile.source, profile.resolver
        );
        after = Some(Position::new(end as u64)?);
        start = end;
    }
    assert!(
        expected_events(source.read(source.scope(), after, limit, &control).await?)?.is_empty()
    );
    Ok(())
}

async fn measure(shape: &str) -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let sizes = seed_page(&f, shape).await?;
    let bytes: u32 = sizes.iter().sum();
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(f.options.clone())
        .await?;
    let source = Arc::new(
        f.reference_source(
            Arc::new(ObsStore::new(pool.clone(), Clock, deadline()).await?),
            TENANT,
            bytes.max(Batch::MAX_ENCODED_BYTES),
        )?
        .into_local(),
    );
    let clock = ProjectionClock(rss_observation::Clock::now(&Clock));
    let stop = CancellationToken::new();
    let control = Control::new(&clock, Duration::from_secs(180), &stop);
    let pg = rss_projection_postgres::PgStore::new(pool.clone(), &control).await?;
    let scope = ProjectionScope::new(source.scope().clone(), "read-cost", shape)?;
    let exec = session(&pg, &scope, &source, &control).await?;
    let before = batch_cost::counters(&pool).await?;
    let limit = RunLimit::new(page_budget(8)?, 8)?;
    let run = rss_projection::run_batched(&*source, &exec, &control, limit);
    let (report, profile) = profiled(shape, std::future::IntoFuture::into_future(run)).await?;
    assert_eq!(report.into_result()?.applied, 8);
    let mut sql = batch_cost::counters(&pool).await?;
    for (k, v) in before {
        *sql.entry(k).or_default() -= v;
    }
    assert_eq!(
        exec.checkpoint(&control).await?.position,
        Some(Position::new(8)?)
    );
    assert_facts(&f, shape).await?;
    assert_cost(shape, u64::from(bytes), &sql, &profile);
    Ok(())
}

fn assert_cost(
    shape: &str,
    bytes: u64,
    sql: &std::collections::BTreeMap<String, i64>,
    profile: &ReadProfile,
) {
    assert_eq!(
        (
            sql["page"],
            sql["resolve"],
            sql["lock"],
            sql["finish"],
            sql["effect"]
        ),
        (1, 8, 1, 1, 129)
    );
    println!(
        "observation_cost shape={shape} raw={bytes} sql={sql:?} source={:?} resolver={:?}",
        profile.source, profile.resolver
    );
    assert_eq!(totals(&profile.source), [bytes, 8, 8, 8, 0]);
    assert_eq!(totals(&profile.resolver), [0, 0, 0, 0, 8]);
}

fn totals(work: &ReadWork) -> [u64; 5] {
    [
        work.raw_bytes.load(Relaxed),
        work.decodes.load(Relaxed),
        work.encodes.load(Relaxed),
        work.fingerprints.load(Relaxed),
        work.database_fingerprints.load(Relaxed),
    ]
}

async fn assert_facts(f: &Fixture, shape: &str) -> anyhow::Result<()> {
    let expected_len = if shape == "large" { 65_000 } else { 1 };
    let facts = values(f, shape, "cost").await?;
    assert_eq!(facts.len(), 16);
    assert!(
        facts
            .iter()
            .all(|(_, v)| v.len() == expected_len && v.iter().all(|b| *b == 247))
    );
    Ok(())
}

async fn profiled<F: Future>(
    shape: &str,
    work: F,
) -> anyhow::Result<(F::Output, Arc<ReadProfile>)> {
    // RSS is meaningful only with one test per process; regular T2 measures deterministic work.
    if std::env::var_os("RSS_OBSERVATION_RSS").is_none() {
        let profile = Arc::new(ReadProfile::default());
        return Ok((profile.run(work).await, profile));
    }
    let (sender, boundary) = std::sync::mpsc::channel();
    let profile = Arc::new(ReadProfile::with_page_end(move || {
        let _ = sender.send(rss_kib());
    }));
    let initial = rss_kib()?;
    let sampler = profile.clone();
    let stop = CancellationToken::new();
    let signal = stop.clone().drop_guard();
    let thread = std::thread::spawn(move || sample_peaks(initial, &sampler, &stop));
    let result = profile.run(work).await;
    drop(signal);
    let mut peaks = thread
        .join()
        .map_err(|_| anyhow::anyhow!("RSS sampler failed"))??;
    for bytes in boundary.try_iter() {
        peaks[0] = peaks[0].max(bytes?);
    }
    peaks[1] = peaks[1].max(rss_kib()?);
    println!("observation_rss shape={shape} initial_kib={initial} phase_peak_kib={peaks:?}");
    Ok((result, profile))
}

fn sample_peaks(
    initial: u64,
    profile: &ReadProfile,
    stop: &CancellationToken,
) -> anyhow::Result<[u64; 2]> {
    let mut peaks = [initial; 2];
    while !stop.is_cancelled() {
        let phase = profile.transition();
        let bytes = rss_kib()?;
        if profile.transition() == phase {
            let index = usize::from(phase.is_multiple_of(2));
            peaks[index] = peaks[index].max(bytes);
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    Ok(peaks)
}
