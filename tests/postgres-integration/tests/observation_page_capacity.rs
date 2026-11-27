//! Run one capacity sample per process. See the ignored test for its inputs.
//! Use `rss-test-launcher -- <test-binary> --exact observation_page_capacity --ignored --nocapture`.
//! Run with `RSS_PG_WORK_PROFILE=1` in a separate process for server-side plans and timings.
#[allow(
    dead_code,
    reason = "this executable uses only the shared Observation fixture setup"
)]
#[path = "observation_projection/fixture.rs"]
mod fixture;
#[path = "../../../crates/examples/src/observation/install.rs"]
mod installer;
#[path = "observation_projection/capacity_metrics.rs"]
mod metrics;

use anyhow::{Context, ensure};
use fixture::{
    Clock, Fixture, ProjectionClock, activate, batch, deadline, expected_events, page_budget, scope,
};
use rss_observation::{ApplicableRecord, Batch, Body, Change, Id, ObservationStore};
use rss_observation_postgres::{
    LocalPages, PgSource, VerifiedObservation, read_profile::ReadProfile,
};
use rss_projection::{
    ApplyOutcome, BatchExecution, Control, DefinitionIdentity, Event, EventWith, GenerationStart,
    Phase, Position, ProjectionScope, ReplayBound, Source, SourceScope, Timer,
};
use rss_projection_postgres::{
    EffectIsolation, PgEffect, PgEffectOutcome, PgOperationError, PgProjection, PgStore,
    PgTransaction,
};
use sqlx::{
    ConnectOptions, PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use std::{
    future::Future,
    sync::{Arc, Mutex, PoisonError, Weak},
    time::Duration,
};
use tokio::{sync::Semaphore, task::JoinSet};
use tokio_util::sync::CancellationToken;

const PAGE_BYTES: u32 = 4 * 1024 * 1024;
const PAGE_ROWS: u32 = 64;
const HOLD: Duration = Duration::from_millis(100);
const TIMEOUT: Duration = Duration::from_secs(120);
const DEFINITION: DefinitionIdentity = DefinitionIdentity::new([36; 32]);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "opt-in capacity sample, one mode/shape/concurrency per fresh process"]
async fn observation_page_capacity() -> anyhow::Result<()> {
    // RSS_OBS_MODE=reference|local RSS_OBS_SHAPE=small|large|mixed RSS_OBS_PAGES=1|2|4
    let mode = std::env::var("RSS_OBS_MODE")?;
    let (shape, pages, reports) = input()?;
    ensure!(
        matches!(mode.as_str(), "reference" | "local"),
        "invalid mode"
    );
    let fixture = Fixture::new().await?;
    fixture.pool.close().await;
    let seeded_bytes = seed_in_child(&fixture).await?;
    fixture.enable_query_plans().await?;
    let connect = || {
        PgPoolOptions::new()
            .min_connections(pages)
            .max_connections(pages)
            .connect_with(fixture.options.clone())
    };
    let (read_pool, effect_pool) = tokio::try_join!(connect(), connect())?;
    let read_store = Arc::new(
        rss_observation_postgres::PgStore::new(read_pool.clone(), Clock, deadline()).await?,
    );
    let sources = (0..pages)
        .map(|index| fixture.reference_source(read_store.clone(), &tenant(index), PAGE_BYTES))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let run = CapacityRun {
        pages,
        reports,
        seeded_bytes,
        read_pool,
        effect_pool,
        observer: fixture.admin.clone(),
        gate: Arc::new(PageGate::new()),
        profile: Arc::new(ReadProfile::default()),
        timing: Arc::new(metrics::ResolverTime::default()),
        clock: Arc::new(clock()),
        stop: CancellationToken::new(),
    };
    let sample = if mode == "local" {
        run.measure(sources.into_iter().map(PgSource::into_local))
            .await?
    } else {
        run.measure(sources).await?
    };
    sample.assert_work(&mode, u64::from(pages * reports));
    let query_plans = std::env::var_os("RSS_PG_WORK_PROFILE").is_some();
    println!(
        "observation_capacity mode={mode} shape={shape} pages={pages} reports_per_page={reports} page_budget={PAGE_BYTES} query_plans={query_plans} artificial_hold_ms={}",
        HOLD.as_millis()
    );
    sample.print();
    Ok(())
}

fn input() -> anyhow::Result<(String, u32, u32)> {
    let pages = std::env::var("RSS_OBS_PAGES")?.parse()?;
    ensure!(matches!(pages, 1 | 2 | 4), "expected 1, 2 or 4 pages");
    let shape = std::env::var("RSS_OBS_SHAPE")?;
    let reports = match shape.as_str() {
        "small" => PAGE_ROWS,
        "large" => 1,
        "mixed" => 8,
        _ => anyhow::bail!("invalid shape"),
    };
    Ok((shape, pages, reports))
}

async fn seed_in_child(fixture: &Fixture) -> anyhow::Result<u64> {
    // Keep the encode/write allocation high-water outside the measured process.
    let result_dir = tempfile::tempdir()?;
    let result_path = result_dir.path().join("canonical-bytes");
    let output = tokio::time::timeout(
        TIMEOUT,
        tokio::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "capacity_seed_worker",
                "--ignored",
                "--nocapture",
            ])
            .env("RSS_OBS_SEED_URL", fixture.options.to_url_lossy().as_str())
            .env("RSS_OBS_SEED_CA", fixture.server.ca_pem())
            .env("RSS_OBS_SEED_RESULT", &result_path)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .context("seed worker timed out")??;
    ensure!(
        output.status.success(),
        "seed worker failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::read_to_string(result_path)
        .context("read seed worker canonical byte count")?
        .parse()
        .context("invalid seed worker canonical byte count")
}

#[tokio::test]
#[ignore = "child process launched by observation_page_capacity"]
async fn capacity_seed_worker() -> anyhow::Result<()> {
    let (shape, pages, reports) = input()?;
    let result_path =
        std::env::var_os("RSS_OBS_SEED_RESULT").context("missing seed result path")?;
    let options: PgConnectOptions = std::env::var("RSS_OBS_SEED_URL")?.parse()?;
    let options = options.ssl_root_cert_from_pem(std::env::var("RSS_OBS_SEED_CA")?.into_bytes());
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await?;
    let store = rss_observation_postgres::PgStore::new(pool.clone(), Clock, deadline()).await?;
    let bytes = seed(&store, &shape, reports, pages).await?;
    // End the backend session to publish its seed statistics before the baseline.
    pool.close().await;
    std::fs::write(result_path, bytes.to_string())
        .context("write seed worker canonical byte count")?;
    Ok(())
}

fn clock() -> ProjectionClock {
    ProjectionClock(rss_observation::Clock::now(&Clock))
}

fn tenant(index: u32) -> String {
    format!("00000000-0000-0000-0000-{:012x}", index + 1)
}

async fn seed(
    store: &rss_observation_postgres::PgStore<Clock>,
    shape: &str,
    reports: u32,
    pages: u32,
) -> anyhow::Result<u64> {
    let mut total = 0;
    for worker in 0..pages {
        let stream = scope(&tenant(worker), "capacity", "r", "s", "e")?;
        activate(store, &stream, None).await?;
        let mut page_bytes = 0;
        for index in 0..reports {
            let large = shape != "small" && index == 0;
            let changes = changes(worker, index, large)?;
            let body = if index == 0 {
                Body::Snapshot(changes)
            } else {
                Body::Delta {
                    baseline: Id::new("b0")?,
                    previous: u64::from(index - 1),
                    changes,
                }
            };
            let input = batch(
                &stream,
                &format!("b{index}"),
                u64::from(index),
                "capacity",
                body,
            )?;
            let bytes = u32::try_from(input.batch().encode().len())?;
            assert!(!large || (Batch::MAX_ENCODED_BYTES * 99 / 100..=PAGE_BYTES).contains(&bytes));
            page_bytes += bytes;
            store.receive(&input, deadline()).await?;
        }
        assert!(page_bytes <= PAGE_BYTES);
        total += u64::from(page_bytes);
    }
    Ok(total)
}

fn changes(worker: u32, index: u32, large: bool) -> anyhow::Result<Vec<Change>> {
    let len = if large { 65_000 } else { 1 };
    let mut state = 1 + worker * PAGE_ROWS + index;
    (0..16)
        .map(|key| {
            let bytes = (0..len)
                .map(|_| {
                    // A fixed seed gives both modes identical inputs with realistic TOAST activity.
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    100 + (state % 156) as u8
                })
                .collect();
            Ok(Change::upsert(Id::new(key.to_string())?, bytes))
        })
        .collect()
}

struct PageGate {
    ready: Stage,
    holding: Stage,
}

impl PageGate {
    fn new() -> Self {
        Self {
            ready: Stage::new(),
            holding: Stage::new(),
        }
    }
}

struct Stage {
    arrived: Semaphore,
    release: Semaphore,
}

impl Stage {
    fn new() -> Self {
        Self {
            arrived: Semaphore::new(0),
            release: Semaphore::new(0),
        }
    }

    async fn pause(&self) {
        self.arrived.add_permits(1);
        if let Ok(permit) = self.release.acquire().await {
            permit.forget();
        }
    }

    async fn all_arrived(&self, pages: u32) -> anyhow::Result<()> {
        self.arrived.acquire_many(pages).await?.forget();
        Ok(())
    }
}

struct CapacityRun {
    pages: u32,
    reports: u32,
    seeded_bytes: u64,
    read_pool: PgPool,
    effect_pool: PgPool,
    observer: PgPool,
    gate: Arc<PageGate>,
    profile: Arc<ReadProfile>,
    timing: Arc<metrics::ResolverTime>,
    clock: Arc<ProjectionClock>,
    stop: CancellationToken,
}

type RecordProbes = Arc<Mutex<Vec<Weak<ApplicableRecord>>>>;

impl CapacityRun {
    async fn measure<R: Resolver>(
        &self,
        sources: impl IntoIterator<Item = R>,
    ) -> anyhow::Result<metrics::Sample> {
        let control = Control::new(&*self.clock, TIMEOUT, &self.stop);
        let pg = PgStore::new(self.effect_pool.clone(), &control).await?;
        let mut prepared = Vec::new();
        for source in sources {
            let source = Arc::new(source);
            let scope = ProjectionScope::new(source.source_scope().clone(), "capacity", "fresh")?;
            pg.initialize(
                &scope,
                &DEFINITION,
                GenerationStart::beginning(),
                ReplayBound::Live,
                &control,
            )
            .await?;
            let claim = pg.takeover(&scope, &DEFINITION, &control).await?;
            let records = Arc::new(Mutex::new(Vec::with_capacity(self.reports as usize)));
            let effect = ProbeEffect {
                source: source.clone(),
                gate: self.gate.clone(),
                timing: self.timing.clone(),
                clock: self.clock.clone(),
                stop: self.stop.clone(),
                records: records.clone(),
            };
            prepared.push((source, pg.projection(claim, effect)?, records));
        }
        let before = self.io().await?;
        let baseline = metrics::Memory::sample().await?;
        let sampler = metrics::Sampler::start(baseline);
        let mut workers = JoinSet::new();
        for (source, execution, records) in prepared {
            let clock = self.clock.clone();
            let stop = self.stop.clone();
            let profile = self.profile.clone();
            let gate = self.gate.clone();
            let reports = self.reports;
            workers.spawn(async move {
                profile
                    .run(execute_page(
                        source, execution, &gate, &clock, &stop, reports, records,
                    ))
                    .await
            });
        }
        let workload = tokio::time::timeout(TIMEOUT, async {
            tokio::try_join!(self.observe_pages(), finish_pages(&mut workers))
        })
        .await;
        let peak = sampler.finish().await;
        let (observed, hold_max) = workload.context("capacity workload did not finish")??;
        let peak = peak?;
        let settled = metrics::Memory::sample().await?;
        let after = self.io().await?;
        let calls = metrics::resolver_calls(&self.read_pool, self.pages).await?
            + metrics::resolver_calls(&self.effect_pool, self.pages).await?;
        tokio::time::timeout(TIMEOUT, async {
            tokio::join!(self.read_pool.close(), self.effect_pool.close());
        })
        .await
        .context("measured pools did not close")?;
        Ok(metrics::Sample {
            canonical_bytes: self.seeded_bytes,
            source: metrics::Work::from(&self.profile.source),
            resolver: metrics::Work::from(&self.profile.resolver),
            resolver_calls: calls,
            resolver_elapsed_us: self.timing.snapshot(),
            source_io: metrics::delta_io(observed.io, before),
            resolver_io: metrics::delta_io(after, observed.io),
            baseline,
            ready: observed.ready,
            held: observed.held,
            peak,
            settled,
            pools_closed: metrics::Memory::sample().await?,
            hold_max,
        })
    }

    async fn observe_pages(&self) -> anyhow::Result<ObservedPages> {
        self.gate.ready.all_arrived(self.pages).await?;
        let ready = metrics::Memory::sample().await?;
        let io = self.io().await?;
        self.gate.ready.release.add_permits(self.pages as usize);
        self.gate.holding.all_arrived(self.pages).await?;
        let held = metrics::Memory::sample().await?;
        tokio::time::sleep(HOLD).await;
        self.gate.holding.release.add_permits(self.pages as usize);
        Ok(ObservedPages { ready, held, io })
    }

    async fn io(&self) -> anyhow::Result<metrics::Io> {
        metrics::flush(&self.read_pool, self.pages).await?;
        metrics::flush(&self.effect_pool, self.pages).await?;
        metrics::io(&self.observer).await
    }
}

struct ObservedPages {
    ready: metrics::Memory,
    held: metrics::Memory,
    io: metrics::Io,
}

async fn execute_page<R: Resolver>(
    source: Arc<R>,
    execution: PgProjection<ProbeEffect<R>>,
    gate: &PageGate,
    clock: &ProjectionClock,
    stop: &CancellationToken,
    reports: u32,
    records: RecordProbes,
) -> anyhow::Result<Duration> {
    let control = Control::new(clock, TIMEOUT, stop);
    let page = expected_events(
        source
            .read(
                source.source_scope(),
                None,
                page_budget(PAGE_ROWS)?,
                &control,
            )
            .await?,
    )?;
    assert_eq!(page.len(), reports as usize);
    let received = clock.now();
    gate.ready.pause().await;
    let outcomes = execution.execute_batch(None, page, &control).await?;
    let owned = clock.now().saturating_sub(received);
    assert_eq!(outcomes, vec![ApplyOutcome::Filtered; reports as usize]);
    let records = records.lock().unwrap_or_else(PoisonError::into_inner);
    assert_eq!(records.len(), reports as usize);
    assert!(records.iter().all(|record| record.strong_count() == 0));
    Ok(owned)
}

async fn finish_pages(workers: &mut JoinSet<anyhow::Result<Duration>>) -> anyhow::Result<Duration> {
    let mut longest = Duration::ZERO;
    while let Some(result) = workers.join_next().await {
        longest = longest.max(result??);
    }
    Ok(longest)
}

trait Resolver: Source<Item: Clone + 'static> + 'static {
    fn source_scope(&self) -> &SourceScope;
    fn restore(
        &self,
        tx: &mut PgTransaction<'_>,
        item: &Self::Item,
        control: &Control<'_, ProjectionClock>,
    ) -> impl Future<Output = Result<Arc<ApplicableRecord>, rss_projection::Error>> + Send;
}

impl Resolver for PgSource<Clock> {
    fn source_scope(&self) -> &SourceScope {
        self.scope()
    }

    async fn restore(
        &self,
        _: &mut PgTransaction<'_>,
        item: &Event,
        control: &Control<'_, ProjectionClock>,
    ) -> Result<Arc<ApplicableRecord>, rss_projection::Error> {
        self.resolve(item, control).await.map(Arc::new)
    }
}

impl Resolver for PgSource<Clock, LocalPages> {
    fn source_scope(&self) -> &SourceScope {
        self.scope()
    }

    async fn restore(
        &self,
        tx: &mut PgTransaction<'_>,
        item: &EventWith<VerifiedObservation>,
        _: &Control<'_, ProjectionClock>,
    ) -> Result<Arc<ApplicableRecord>, rss_projection::Error> {
        self.resolve_in_transaction(tx, item).await
    }
}

struct ProbeEffect<R> {
    source: Arc<R>,
    gate: Arc<PageGate>,
    timing: Arc<metrics::ResolverTime>,
    clock: Arc<ProjectionClock>,
    stop: CancellationToken,
    records: RecordProbes,
}

impl<R: Resolver> PgEffect for ProbeEffect<R> {
    type Item = R::Item;
    const ISOLATION: EffectIsolation = EffectIsolation::ReadCommitted;

    async fn apply(
        &self,
        tx: &mut PgTransaction<'_>,
        _: &ProjectionScope,
        item: &Self::Item,
    ) -> Result<PgEffectOutcome, PgOperationError> {
        let control = Control::new(&*self.clock, TIMEOUT, &self.stop);
        let position: Position = item.as_ref().position();
        let started = self.clock.now();
        let record = self
            .source
            .restore(tx, item, &control)
            .await
            .map_err(|e| PgOperationError::rejected(Phase::Restore, None, Some(position), e))?;
        self.timing.record(self.clock.now().saturating_sub(started));
        self.records
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Arc::downgrade(&record));
        if position.get() == 1 {
            self.gate.holding.pause().await;
        }
        // Both callbacks consume the report and advance through real atomic settlement.
        std::hint::black_box(record.record().batch().encode());
        Ok(PgEffectOutcome::Filtered)
    }
}
