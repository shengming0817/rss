use super::*;
use crate::pg_settlement::{LOSE_COMMIT, Proxy};
use std::future::IntoFuture;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

#[derive(Default)]
struct Recorder {
    paused: CancellationToken,
    resume: CancellationToken,
    reject: AtomicBool,
    calls: std::sync::atomic::AtomicUsize,
    lose: Option<Arc<AtomicU8>>,
}
struct Writer(Arc<Recorder>);
impl PgEffect for Writer {
    async fn apply(
        &self,
        tx: &mut PgTransaction<'_>,
        scope: &ProjectionScope,
        event: &Event,
    ) -> Result<PgEffectOutcome, PgOperationError> {
        self.0.calls.fetch_add(1, Ordering::SeqCst);
        if event.payload() == b"filter" {
            return Ok(PgEffectOutcome::Filtered);
        }
        let scope = scope.clone();
        let position = event.position().get() as i64;
        tx.with_connection(move |conn| Box::pin(async move {
            sqlx::query("INSERT INTO public.batch_steps(tenant_id,source_id,projection_id,generation,position,xid) VALUES($1::uuid,$2,$3,$4,$5,pg_current_xact_id())")
                .bind(scope.source().tenant().to_string()).bind(scope.source().source()).bind(scope.projection()).bind(scope.generation()).bind(position).execute(conn).await?;
            Ok(())
        })).await?;
        if event.payload() == b"pause" {
            self.0.paused.cancel();
            self.0.resume.cancelled().await;
            if self.0.reject.load(Ordering::SeqCst) {
                return Err(PgOperationError::rejected(
                    Phase::Application,
                    None,
                    Some(event.position()),
                    std::io::Error::other("fixture rejection"),
                ));
            }
        }
        if event.payload() == b"lose"
            && let Some(arm) = &self.0.lose
        {
            arm.store(LOSE_COMMIT, Ordering::SeqCst);
        }
        Ok(PgEffectOutcome::Applied)
    }
}

async fn worker(
    store: &PgStore,
    scope: &ProjectionScope,
    bound: ReplayBound,
    effect: Arc<Recorder>,
    c: &Control<'_, Clock>,
) -> anyhow::Result<PgProjection<Writer>> {
    store
        .initialize(scope, &DEFINITION, GenerationStart::beginning(), bound, c)
        .await?;
    Ok(store.projection(store.takeover(scope, &DEFINITION, c).await?, Writer(effect))?)
}

type Snapshot = (Option<i64>, i64, Vec<i64>, i64);
async fn snapshot(owner: &PgPool, s: &ProjectionScope) -> anyhow::Result<Snapshot> {
    // One statement snapshot couples all three committed facts. The identity
    // column records application order independently of the input positions.
    Ok(sqlx::query_as("SELECT c.position, (SELECT count(*) FROM rss_projection.receipts r WHERE (r.tenant_id,r.source_id,r.projection_id,r.generation)=(c.tenant_id,c.source_id,c.projection_id,c.generation)), ARRAY(SELECT position FROM public.batch_steps b WHERE (b.tenant_id,b.source_id,b.projection_id,b.generation)=(c.tenant_id,c.source_id,c.projection_id,c.generation) ORDER BY ordinal), (SELECT count(DISTINCT xid::text) FROM public.batch_steps b WHERE (b.tenant_id,b.source_id,b.projection_id,b.generation)=(c.tenant_id,c.source_id,c.projection_id,c.generation)) FROM rss_projection.checkpoints c WHERE tenant_id=$1::uuid AND source_id=$2 AND projection_id=$3 AND generation=$4")
        .bind(s.source().tenant().to_string()).bind(s.source().source()).bind(s.projection()).bind(s.generation()).fetch_one(owner).await?)
}
fn generation(s: &ProjectionScope, name: &str) -> Result<ProjectionScope, Error> {
    ProjectionScope::new(s.source().clone(), s.projection(), name)
}
pub(crate) async fn verify(
    store: &PgStore,
    owner: &PgPool,
    fixture: &testkit::PgTlsFixture,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    sqlx::raw_sql("CREATE TABLE public.batch_steps(ordinal bigint GENERATED ALWAYS AS IDENTITY, tenant_id uuid NOT NULL,source_id text NOT NULL,projection_id text NOT NULL,generation text NOT NULL,position bigint NOT NULL,xid xid8 NOT NULL); GRANT INSERT ON public.batch_steps TO projection_runtime").execute(owner).await?;
    atomic(store, owner, c).await?;
    interrupted_page(store, owner, c).await?;
    lost_ack(store, owner, fixture, c).await?;
    comparison(store, owner, c).await
}
async fn atomic(store: &PgStore, owner: &PgPool, c: &Control<'_, Clock>) -> anyhow::Result<()> {
    let s = generation(&scope("batch-mixed", TENANT)?, "mixed")?;
    direct_bound(store, &s, c).await?;
    let peer = generation(&scope("batch-peer", OTHER)?, "peer")?;
    let recorder = Arc::new(Recorder::default());
    recorder.reject.store(true, Ordering::SeqCst);
    let exec = worker(store, &s, ReplayBound::Live, recorder.clone(), c).await?;
    let independent = worker(store, &peer, ReplayBound::Live, Arc::default(), c).await?;
    let events = vec![
        event(&s, 0, "one", b"one")?,
        event(&s, 1, "one", b"one")?,
        event(&s, 2, "two", b"filter")?,
        event(&s, 3, "three", b"pause")?,
    ];
    let inspect = async {
        recorder.paused.cancelled().await;
        assert_eq!(snapshot(owner, &s).await?, (None, 0, vec![], 0));
        independent
            .execute_batch(None, vec![event(&peer, 0, "other", b"one")?], c)
            .await?;
        recorder.resume.cancel();
        Ok::<_, anyhow::Error>(())
    };
    let (failed, observed) = tokio::join!(exec.execute_batch(None, events.clone(), c), inspect);
    observed?;
    assert!(matches!(failed,Err(e) if e.kind()==ErrorKind::Rejected));
    assert_eq!(snapshot(owner, &s).await?, (None, 0, vec![], 0));
    retry(store, owner, &s, &peer, exec, recorder, events, c).await
}

#[allow(
    clippy::too_many_arguments,
    reason = "same failed page, worker claim and observer"
)]
async fn retry(
    store: &PgStore,
    owner: &PgPool,
    s: &ProjectionScope,
    peer: &ProjectionScope,
    exec: PgProjection<Writer>,
    recorder: Arc<Recorder>,
    events: Vec<Event>,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    recorder.reject.store(false, Ordering::SeqCst);
    let mut conflict = events.clone();
    conflict[1] = event(s, 1, "one", b"changed")?;
    assert!(
        matches!(exec.execute_batch(None,conflict,c).await,Err(e) if e.kind()==ErrorKind::Conflict)
    );
    assert_eq!(snapshot(owner, s).await?, (None, 0, vec![], 0));
    takeover(store, owner, s, peer, exec, recorder, events, c).await
}

#[allow(
    clippy::too_many_arguments,
    reason = "a resumed worker replaces the old claim on the same page"
)]
async fn takeover(
    store: &PgStore,
    owner: &PgPool,
    s: &ProjectionScope,
    peer: &ProjectionScope,
    exec: PgProjection<Writer>,
    recorder: Arc<Recorder>,
    events: Vec<Event>,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let fresh = worker(store, s, ReplayBound::Live, recorder, c).await?;
    assert!(
        matches!(exec.execute_batch(None,events.clone(),c).await,Err(e) if e.kind()==ErrorKind::Fenced)
    );
    assert!(
        matches!(fresh.execute_batch(None,vec![event(peer,0,"other",b"one")?],c).await,Err(e) if e.kind()==ErrorKind::ScopeMismatch)
    );
    assert_eq!(
        fresh.execute_batch(None, events, c).await?,
        [
            ApplyOutcome::Applied,
            ApplyOutcome::Duplicate,
            ApplyOutcome::Filtered,
            ApplyOutcome::Applied
        ]
    );
    assert_eq!(snapshot(owner, s).await?, (Some(3), 3, vec![0, 3], 1));
    Ok(())
}
async fn lost_ack(
    store: &PgStore,
    owner: &PgPool,
    fixture: &testkit::PgTlsFixture,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let s = generation(&scope("batch-ack", TENANT)?, "ack")?;
    for (id, payload) in [
        ("one", "one"),
        ("two", "two"),
        ("three", "lose"),
        ("four", "four"),
        ("outside", "outside"),
    ] {
        append(store, &s, id, payload.as_bytes(), c).await?;
    }
    let proxy = Proxy::new(fixture).await?;
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(
            PgConnectOptions::new()
                .host("127.0.0.1")
                .port(proxy.port)
                .database(&fixture.params().database)
                .username("projection_runtime")
                .password("fixture-only")
                .ssl_mode(PgSslMode::Disable),
        )
        .await?;
    let loss_store = PgStore::new(pool, c).await?;
    let effect = Recorder {
        lose: Some(proxy.arm.clone()),
        ..Default::default()
    };
    let exec = worker(
        &loss_store,
        &s,
        ReplayBound::Through(Some(Position::new(3)?)),
        Arc::new(effect),
        c,
    )
    .await?;
    verify_recovery(store, owner, &s, &exec, &proxy, c).await?;
    assert_eq!(loss_store.close(c).await, CloseOutcome::Drained);
    Ok(())
}
async fn comparison(store: &PgStore, owner: &PgPool, c: &Control<'_, Clock>) -> anyhow::Result<()> {
    const N: i64 = 25;
    const B: u32 = 8;
    let s = scope("batch-measure", TENANT)?;
    for i in 0..N {
        append(store, &s, &format!("fact-{i}"), b"work", c).await?;
    }
    let limits = RunLimit::new(BatchLimit::new(B)?, N as u64 + 1)?;
    let clock = Clock::new();
    let mut samples = [Vec::new(), Vec::new()];
    let measure = std::env::var_os("RSS_PROJECTION_MEASURE").is_some();
    for round in 0..=if measure { 10 } else { 1 } {
        for i in 0..2 {
            let mode = (i + round) % 2;
            let gen_scope = generation(&s, &format!("measure-{round}-{mode}"))?;
            let exec = worker(store, &gen_scope, ReplayBound::Live, Arc::default(), c).await?;
            let start = clock.now();
            let report = if mode == 0 {
                run(store, &exec, c, limits).await
            } else {
                run_batched(store, &exec, c, limits).await
            }
            .into_result()?;
            let elapsed = clock.now() - start;
            assert_eq!(report.applied, N as u64);
            let expected_tx = if mode == 0 {
                N
            } else {
                (N + i64::from(B) - 1) / i64::from(B)
            };
            assert_eq!(
                snapshot(owner, &gen_scope).await?,
                (Some(N - 1), N, (0..N).collect(), expected_tx)
            );
            if round > 0 {
                samples[mode].push(elapsed);
            }
        }
    }
    report_samples(samples, N, B);
    Ok(())
}

async fn direct_bound(
    store: &PgStore,
    s: &ProjectionScope,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let replay = generation(s, "bounded")?;
    let witness = Arc::new(Recorder::default());
    let bounded = worker(
        store,
        &replay,
        ReplayBound::Through(Some(Position::new(1)?)),
        witness.clone(),
        c,
    )
    .await?;
    let over = vec![
        event(&replay, 0, "first", b"one")?,
        event(&replay, 2, "overflow", b"two")?,
    ];
    assert!(
        matches!(bounded.execute_batch(None,over,c).await,Err(e) if e.kind()==ErrorKind::OutOfOrder)
    );
    assert_eq!(witness.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

async fn verify_recovery(
    store: &PgStore,
    owner: &PgPool,
    s: &ProjectionScope,
    exec: &PgProjection<Writer>,
    proxy: &Proxy,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let limits = RunLimit::new(BatchLimit::new(2)?, 10)?;
    let run = run_batched(store, exec, c, limits);
    let observation = run.observation();
    let report = run.await;
    assert!(matches!(&report.stop,Stop::Failed(e) if e.kind()==ErrorKind::CommitUnknown));
    assert_eq!(
        (report.applied, report.position),
        (2, Some(Position::new(1)?))
    );
    assert_eq!(observation.read(), ObservationStatus::Stopped(report));
    assert_eq!(proxy.lost.load(Ordering::SeqCst), 1);
    assert_eq!(snapshot(owner, s).await?, (Some(3), 4, vec![0, 1, 2, 3], 2));
    let resumed = run_batched(store, exec, c, limits).await.into_result()?;
    assert_eq!(
        (resumed.position, resumed.applied, resumed.stop),
        (Some(Position::new(3)?), 0, Stop::CaughtUp)
    );
    Ok(())
}

fn report_samples(samples: [Vec<Duration>; 2], n: i64, b: u32) {
    for (mode, mut durations) in samples.into_iter().enumerate() {
        durations.sort();
        let p50 = durations[(durations.len() - 1) / 2];
        let p95 = durations[durations.len() - 1];
        println!(
            "projection_measure mode={mode} events={n} page={b} p50_ms={:.3} p95_ms={:.3} median_events_per_s={:.1}",
            p50.as_secs_f64() * 1000.,
            p95.as_secs_f64() * 1000.,
            n as f64 / p50.as_secs_f64()
        );
    }
}

async fn interrupted_page(
    store: &PgStore,
    owner: &PgPool,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let s = generation(&scope("batch-stop", TENANT)?, "stopped")?;
    for (i, body) in ["one", "two", "three", "pause"].into_iter().enumerate() {
        append(store, &s, &format!("e{i}"), body.as_bytes(), c).await?;
    }
    let recorder = Arc::new(Recorder::default());
    let exec = worker(store, &s, ReplayBound::Live, recorder.clone(), c).await?;
    let limits = RunLimit::new(BatchLimit::new(2)?, 8)?;
    let clock = Clock::new();
    let stop = CancellationToken::new();
    let interrupted = Control::new(&clock, Duration::from_secs(10), &stop);
    let run = run_batched(store, &exec, &interrupted, limits);
    let observation = run.observation();
    let cancel = async {
        recorder.paused.cancelled().await;
        assert_eq!(snapshot(owner, &s).await?, (Some(1), 2, vec![0, 1], 1));
        stop.cancel();
        Ok::<_, anyhow::Error>(())
    };
    let (report, checked) = tokio::join!(run.into_future(), cancel);
    checked?;
    assert_eq!(
        (report.position, report.applied),
        (Some(Position::new(1)?), 2)
    );
    assert!(matches!(&report.stop,Stop::Failed(e) if e.kind()==ErrorKind::CommitUnknown));
    assert_eq!(observation.read(), ObservationStatus::Stopped(report));
    recorder.resume.cancel();
    let recovered = run_batched(store, &exec, c, limits).await.into_result()?;
    assert_eq!((recovered.stop, recovered.applied), (Stop::CaughtUp, 2));
    assert_eq!(
        snapshot(owner, &s).await?,
        (Some(3), 4, vec![0, 1, 2, 3], 2)
    );
    Ok(())
}
