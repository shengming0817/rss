use super::*;
use rss_observation_postgres::read_profile::ReadProfile;
use sqlx::postgres::PgPoolOptions;
use std::sync::atomic::Ordering::Relaxed;
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn small_page_cost() -> anyhow::Result<()> { measure("small").await }
#[tokio::test]
async fn large_page_cost() -> anyhow::Result<()> { measure("large").await }
#[tokio::test]
async fn mixed_page_cost() -> anyhow::Result<()> { measure("mixed").await }

async fn seed_page(f: &Fixture, shape: &str) -> anyhow::Result<u64> {
    let store = f.store().await?;
    let stream = scope(TENANT, "read-cost", "r", "s", "e")?;
    activate(&store, &stream, None).await?;
    let mut bytes = 0;
    for i in 0..8 {
        let large = shape == "large" || shape == "mixed" && i % 2 == 0;
        let len = if large { 65_000 } else { 1 };
        let changes = (0..16).map(|key| {
            Ok(Change::upsert(Id::new(key.to_string())?, vec![240 + i as u8; len]))
        }).collect::<Result<Vec<_>,rss_observation::Error>>()?;
        let body = if i == 0 { Body::Snapshot(changes) } else {
            Body::Delta { baseline: Id::new("b0")?, previous: i-1, changes }
        };
        let input = batch(&stream, &format!("b{i}"), i, "cost", body)?;
        let n = input.batch().encode().len();
        assert!(!large || (4_194_304*99/100..=4_194_304).contains(&n));
        store.receive(&input, deadline()).await?;
        bytes += n as u64;
    }
    Ok(bytes)
}

fn rss_kib() -> anyhow::Result<u64> {
    let output = std::process::Command::new("ps")
        .args(["-o","rss=","-p",&std::process::id().to_string()]).output()?;
    anyhow::ensure!(output.status.success());
    Ok(std::str::from_utf8(&output.stdout)?.trim().parse()?)
}

async fn measure(shape: &str) -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let bytes = seed_page(&f, shape).await?;
    let pool = PgPoolOptions::new().max_connections(1).connect_with(f.options.clone()).await?;
    let source = f.source(Arc::new(ObsStore::new(pool.clone(), Clock, deadline()).await?), TENANT)?;
    let clock = ProjectionClock(rss_observation::Clock::now(&Clock));
    let stop = CancellationToken::new();
    let control = Control::new(&clock, Duration::from_secs(180), &stop);
    let pg = rss_projection_postgres::PgStore::new(pool.clone(), &control).await?;
    let scope = ProjectionScope::new(source.scope().clone(), "read-cost", shape)?;
    let exec = session(&pg, &scope, &source, &control).await?;
    let before = batch_cost::counters(&pool).await?;
    let profile = Arc::new(ReadProfile::default());
    let sampler = profile.clone();
    let done = CancellationToken::new();
    let signal = done.clone().drop_guard();
    let initial = rss_kib()?;
    let thread = std::thread::spawn(move || -> anyhow::Result<[u64; 2]> {
        let mut peak = [initial; 2];
        while !done.is_cancelled() {
            let phase = usize::from(!sampler.reading_page());
            peak[phase] = peak[phase].max(rss_kib()?);
            std::thread::sleep(Duration::from_millis(2));
        }
        Ok(peak)
    });
    let limit = RunLimit::new(BatchLimit::new(8)?,8)?;
    let report = profile.run(std::future::IntoFuture::into_future(
        rss_projection::run_batched(&*source,&exec,&control,limit)
    )).await;
    drop(signal);
    let peaks = thread.join().map_err(|_|anyhow::anyhow!("RSS sampler failed"))??;
    assert_eq!(report.into_result()?.applied,8);
    assert_eq!(exec.checkpoint(&control).await?.position,Some(Position::new(8)?));
    let mut sql = batch_cost::counters(&pool).await?;
    for (k,v) in before { *sql.entry(k).or_default() -= v; }
    // Exclude the explicit post-run inspection and its session setup.
    *sql.entry("checkpoint".into()).or_default() -= 1;
    *sql.entry("setup".into()).or_default() -= 1;
    let expected_len = if shape == "large" {65_000} else {1};
    let facts = values(&f,shape,"cost").await?;
    assert_eq!(facts.len(),16);
    assert!(facts.iter().all(|(_,v)| v.len()==expected_len && v.iter().all(|b| *b==247)));
    assert_eq!(sql["page"],1);
    assert_eq!(sql["resolve"],8);
    assert_eq!((sql["lock"],sql["finish"],sql["effect"]),(1,1,129));
    println!("observation_cost shape={shape} raw={bytes} sql={sql:?} profile={profile:?} initial_kib={initial} phase_peak_kib={peaks:?}");
    assert_eq!(profile.source.raw_bytes.load(Relaxed),bytes);
    assert_eq!(profile.source.decodes.load(Relaxed),8);
    assert_eq!(profile.resolver.raw_bytes.load(Relaxed),bytes);
    assert_eq!(profile.resolver.decodes.load(Relaxed),8);
    assert_eq!(profile.source.fingerprints.load(Relaxed),16);
    assert_eq!(profile.resolver.fingerprints.load(Relaxed),16);
    Ok(())
}
