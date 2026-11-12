//! Projection owns source-read time even when the Observation Clock has another origin.
use super::fixture::*;
use rss_observation::{Body, ObservationStore};
use rss_projection::{BatchLimit, Control, ErrorKind, Event, Source, Timer};
use std::{sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
struct ManualTimer(tokio::sync::watch::Sender<Duration>);
impl ManualTimer {
    fn new() -> Self {
        Self(tokio::sync::watch::channel(Duration::ZERO).0)
    }
    fn advance(&self, seconds: u64) {
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
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
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
    let timer = ManualTimer::new();
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
            let signal = CancellationToken::new();
            timer.advance(0);
            let budget = Control::new(&timer, Duration::from_secs(60), &signal);
            let held = pool.acquire().await?;
            let mut work = Box::pin(read(&source, event, stage, &budget));
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
                read(&source, event, stage, &budget)
                    .await
                    .err()
                    .map(|e| e.kind()),
                Some(kind)
            );
            drop(held);
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
