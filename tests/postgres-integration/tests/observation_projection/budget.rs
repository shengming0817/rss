//! Projection owns source-read time even when the Observation Clock has another origin.
use super::fixture::*;
use anyhow::Context as _;
use rss_observation::{Body, ObservationStore};
use rss_projection::{BatchLimit, Control, ErrorKind, Event, Source, Timer};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
// SQLx close_on_drop may spend five seconds retiring a blocked connection before releasing
// its pool permit. This guard observes cleanup; it is not the operation budget.
// ref: sqlx-core/src/pool/connection.rs CLOSE_ON_DROP_TIMEOUT@v0.9.0
const GUARD: Duration = Duration::from_secs(10);
use tokio_util::sync::CancellationToken;
#[derive(Clone)]
pub(super) struct ManualTimer(tokio::sync::watch::Sender<Duration>);
impl ManualTimer {
    pub(super) fn new() -> Self {
        Self(tokio::sync::watch::channel(Duration::ZERO).0)
    }
    pub(super) fn advance(&self, seconds: u64) {
        self.0.send_replace(Duration::from_secs(seconds));
    }
}
impl Timer for ManualTimer {
    fn now(&self) -> Duration {
        *self.0.borrow()
    }
    async fn sleep_until(&self, end: Duration) {
        let mut receiver = self.0.subscribe();
        loop {
            if *receiver.borrow_and_update() >= end {
                return;
            }
            if receiver.changed().await.is_err() {
                return;
            }
        }
    }
}
type ObsSource = rss_observation_postgres::PgSource<Clock>;
pub(super) async fn verify(f: &Fixture) -> anyhow::Result<()> {
    let timer = ManualTimer::new();
    let acquired = timer.clone();
    let armed = Arc::new(AtomicBool::new(false));
    let trigger = armed.clone();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .test_before_acquire(false)
        .before_acquire(move |_, _| {
            if trigger.load(Ordering::SeqCst) {
                acquired.0.send_replace(Duration::from_millis(59_920));
            }
            Box::pin(async { Ok(true) })
        })
        .connect_with(
            f.options
                .clone()
                .username("handoff_runtime")
                .password("fixture-only"),
        )
        .await?;
    let store =
        Arc::new(rss_observation_postgres::PgStore::new(pool.clone(), Clock, deadline()).await?);
    let stream = scope(TENANT, "budget", "r", "source", "e")?;
    activate(&store, &stream, None).await?;
    store
        .receive(
            &batch(&stream, "budget", 0, "all", Body::Snapshot(vec![]))?,
            deadline(),
        )
        .await?;
    let source = f.source(store.clone(), TENANT)?;
    let cancel = CancellationToken::new();
    let control = Control::new(&timer, Duration::from_secs(60), &cancel);
    let events = source
        .read(source.scope(), None, BatchLimit::new(1024)?, &control)
        .await?;
    let event = events
        .last()
        .ok_or_else(|| anyhow::anyhow!("missing fixture event"))?;
    for stage in 0..3 {
        for kind in [ErrorKind::Cancelled, ErrorKind::Deadline] {
            acquire_wait(&pool, &source, event, &timer, stage, kind).await?;
        }
        timer.advance(0);
        let huge = Control::new(&timer, Duration::MAX, &cancel);
        assert_eq!(
            read(&source, event, stage, &huge)
                .await
                .err()
                .map(|e| e.kind()),
            Some(ErrorKind::InvalidInput)
        );
        // No conversion to the unrelated Observation Instant is involved.
        timer.advance(31);
        read(&source, event, stage, &control).await?;
    }
    acquired_budget(f, &pool, &source, event, &timer, &armed).await?;
    store.close(deadline()).await?;
    Ok(())
}
async fn read(
    source: &ObsSource,
    event: &Event,
    stage: u8,
    control: &Control<'_, ManualTimer>,
) -> Result<(), rss_projection::Error> {
    match stage {
        0 => source.high_water(source.scope(), control).await.map(|_| ()),
        1 => source
            .read(source.scope(), None, BatchLimit::new(1024)?, control)
            .await
            .map(|_| ()),
        _ => source.resolve(event, control).await.map(|_| ()),
    }
}

async fn acquired_budget(
    f: &Fixture,
    pool: &sqlx::PgPool,
    source: &ObsSource,
    event: &Event,
    timer: &ManualTimer,
    armed: &AtomicBool,
) -> anyhow::Result<()> {
    let mut blocker = f.admin.begin().await?;
    sqlx::query(
        "LOCK TABLE rss_observation.journals,rss_observation.batches IN ACCESS EXCLUSIVE MODE",
    )
    .execute(&mut *blocker)
    .await?;
    for stage in 0..3 {
        timer.advance(0);
        armed.store(true, Ordering::SeqCst);
        let cancel = CancellationToken::new();
        let control = Control::new(timer, Duration::from_secs(60), &cancel);
        // Only the server clock runs: 59.920 seconds consumed by acquisition leaves 80ms.
        // Fixed 30s or a renewed 60s watchdog cannot complete within this guard.
        let result = tokio::time::timeout(GUARD, read(source, event, stage, &control))
            .await
            .with_context(|| format!("remaining SQL watchdog did not fire: stage={stage}"))?;
        assert_eq!(result.err().map(|e| e.kind()), Some(ErrorKind::Deadline));
        assert_eq!(timer.now(), Duration::from_millis(59_920));
        armed.store(false, Ordering::SeqCst);
    }
    for stage in 0..3 {
        for expired in [false, true] {
            let pid = interrupted_query(f, pool, source, event, timer, stage, expired).await?;
            // Cleanup is observed separately from the already-returned interruption result.
            blocker.rollback().await?;
            tokio::time::timeout(GUARD, wait_for_backend(&f.admin, pid, false))
                .await
                .context("quarantined backend did not retire")??;
            blocker = f.admin.begin().await?;
            sqlx::query("LOCK TABLE rss_observation.journals,rss_observation.batches IN ACCESS EXCLUSIVE MODE")
                .execute(&mut *blocker)
                .await?;
        }
    }
    blocker.rollback().await?;
    Ok(())
}
async fn wait_for_backend(admin: &sqlx::PgPool, pid: i32, waiting: bool) -> anyhow::Result<()> {
    loop {
        let (exists,locked): (bool,bool) = sqlx::query_as("SELECT EXISTS(SELECT FROM pg_stat_activity WHERE pid=$1),EXISTS(SELECT FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')").bind(pid).fetch_one(admin).await?;
        if (waiting && locked) || (!waiting && !exists) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn acquire_wait(
    pool: &sqlx::PgPool,
    source: &ObsSource,
    event: &Event,
    timer: &ManualTimer,
    stage: u8,
    kind: ErrorKind,
) -> anyhow::Result<()> {
    let signal = CancellationToken::new();
    timer.advance(0);
    let budget = Control::new(timer, Duration::from_secs(60), &signal);
    let held = pool.acquire().await?;
    let mut work = Box::pin(read(source, event, stage, &budget));
    assert!(futures::poll!(work.as_mut()).is_pending());
    timer.advance(31);
    assert!(futures::poll!(work.as_mut()).is_pending());
    if kind == ErrorKind::Cancelled {
        signal.cancel();
    } else {
        timer.advance(60);
    }
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), work)
            .await?
            .err()
            .map(|e| e.kind()),
        Some(kind)
    );
    // Already interrupted direct calls must not wait for the held checkout either.
    assert_eq!(
        read(source, event, stage, &budget)
            .await
            .err()
            .map(|e| e.kind()),
        Some(kind)
    );
    drop(held);
    Ok(())
}

async fn interrupted_query(
    f: &Fixture,
    pool: &sqlx::PgPool,
    source: &ObsSource,
    event: &Event,
    timer: &ManualTimer,
    stage: u8,
    expired: bool,
) -> anyhow::Result<i32> {
    timer.advance(0);
    let mut held = pool.acquire().await?;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *held)
        .await?;
    drop(held);
    let cancel = CancellationToken::new();
    let control = Control::new(timer, Duration::from_secs(60), &cancel);
    let mut operation = Box::pin(read(source, event, stage, &control));
    tokio::time::timeout(GUARD,async {
                tokio::select! {
                    result = &mut operation => anyhow::bail!("read did not wait for its SQL lock: {result:?}"),
                    result = wait_for_backend(&f.admin,pid,true) => result,
                }
            }).await.with_context(||format!("query did not reach lock: stage={stage}"))??;
    if expired {
        timer.advance(60);
    } else {
        cancel.cancel();
    }
    assert_eq!(
        operation.await.err().map(|e| e.kind()),
        Some(if expired {
            ErrorKind::Deadline
        } else {
            ErrorKind::Cancelled
        })
    );
    let mut replacement = tokio::time::timeout(GUARD, pool.acquire())
        .await
        .context("quarantine retained pool permit")??;
    let next: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *replacement)
        .await?;
    assert_ne!(pid, next, "unconfirmed source connection returned to pool");
    drop(replacement);
    Ok(pid)
}
