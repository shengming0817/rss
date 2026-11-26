use super::*;
use rss_observation_postgres::read_profile::ReadProfile;
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

pub(super) async fn seed_page(f: &Fixture, shape: &str) -> anyhow::Result<u64> {
    let store = f.store().await?;
    let stream = scope(TENANT, "read-cost", "r", "s", "e")?;
    activate(&store, &stream, None).await?;
    let mut bytes = 0;
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
        let n = input.batch().encode().len();
        assert!(!large || (4_194_304 * 99 / 100..=4_194_304).contains(&n));
        store.receive(&input, deadline()).await?;
        bytes += n as u64;
    }
    Ok(bytes)
}

fn rss_kib() -> anyhow::Result<u64> {
    let output = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()?;
    anyhow::ensure!(output.status.success());
    Ok(std::str::from_utf8(&output.stdout)?.trim().parse()?)
}

async fn measure(shape: &str) -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let bytes = seed_page(&f, shape).await?;
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(f.options.clone())
        .await?;
    let source = f.source(
        Arc::new(ObsStore::new(pool.clone(), Clock, deadline()).await?),
        TENANT,
    )?;
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
    assert_cost(shape, bytes, &sql, &profile);
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
    use rss_observation_postgres::read_profile::ReadWork;
    let totals = |work: &ReadWork| {
        [
            work.raw_bytes.load(Relaxed),
            work.decodes.load(Relaxed),
            work.encodes.load(Relaxed),
            work.fingerprints.load(Relaxed),
            work.database_fingerprints.load(Relaxed),
        ]
    };
    assert_eq!(totals(&profile.source), [bytes, 8, 8, 8, 0]);
    assert_eq!(totals(&profile.resolver), [0, 0, 0, 0, 8]);
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
