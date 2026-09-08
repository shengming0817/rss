//! Each probe is driven to a deterministic provider boundary before inspecting the reader.
use super::*;
use std::{
    future::{Future, IntoFuture},
    task::{Context, Poll, Waker},
};

#[derive(Clone, Copy)]
enum Boundary {
    Checkpoint,
    Read,
    Execute,
    Unknown,
    Panic,
    Complete,
}
struct Probe {
    memory: Memory,
    boundary: Boundary,
}
impl Execution for Probe {
    fn scope(&self) -> &ProjectionScope {
        self.memory.scope()
    }
    fn definition_identity(&self) -> &DefinitionIdentity {
        &DEFINITION
    }
    async fn checkpoint(&self) -> Result<Checkpoint, Error> {
        if matches!(self.boundary, Boundary::Checkpoint) {
            std::future::pending::<()>().await;
        }
        self.memory.checkpoint().await
    }
    #[allow(clippy::panic)]
    // reason: test a provider unwinding after one acknowledged event.
    async fn execute<T: Timer>(
        &self,
        expected: Option<Position>,
        event: &Event,
        control: &Control<'_, T>,
    ) -> Result<ApplyOutcome, Error> {
        if event.position().get() == 2 {
            match self.boundary {
                Boundary::Execute => std::future::pending::<()>().await,
                Boundary::Panic => panic!("test provider unwind"),
                Boundary::Unknown => {
                    self.memory.execute(expected, event, control).await?;
                    return Err(Error::new(ErrorKind::CommitUnknown));
                }
                _ => {}
            }
        }
        self.memory.execute(expected, event, control).await?;
        Ok(match event.position().get() {
            2 => ApplyOutcome::Duplicate,
            9 => ApplyOutcome::Filtered,
            _ => ApplyOutcome::Applied,
        })
    }
}
struct Fixture {
    source: Journal,
    execution: Probe,
    clock: Clock,
    cancel: CancellationToken,
}
impl Fixture {
    fn new(boundary: Boundary) -> anyhow::Result<Self> {
        let scope = scope()?;
        Ok(Self {
            source: Journal(vec![
                event(&scope, 0)?,
                event(&scope, 2)?,
                event(&scope, 9)?,
            ]),
            execution: Probe {
                memory: Memory::new(scope, ReplayBound::Live),
                boundary,
            },
            clock: Clock(AtomicU64::new(0)),
            cancel: CancellationToken::new(),
        })
    }
    fn control(&self) -> Control<'_, Clock> {
        Control::new(&self.clock, Duration::from_secs(10), &self.cancel)
    }
}
impl Source for Fixture {
    async fn high_water(&self, _: &SourceScope) -> Result<Option<Position>, Error> {
        // Observation must not introduce this extra provider operation.
        Err(Error::new(ErrorKind::SourceContract))
    }
    async fn read(
        &self,
        scope: &SourceScope,
        after: Option<Position>,
        limit: BatchLimit,
    ) -> Result<Vec<Event>, Error> {
        if matches!(self.execution.boundary, Boundary::Read) {
            std::future::pending::<()>().await;
        }
        self.source.read(scope, after, limit).await
    }
}
fn limit(events: u64) -> anyhow::Result<RunLimit> {
    Ok(RunLimit::new(BatchLimit::new(3)?, events)?)
}
fn first() -> anyhow::Result<ConfirmedProgress> {
    Ok(ConfirmedProgress {
        position: Some(Position::new(0)?),
        applied: 1,
        duplicates: 0,
        filtered: 0,
    })
}
fn empty() -> ConfirmedProgress {
    ConfirmedProgress {
        position: None,
        applied: 0,
        duplicates: 0,
        filtered: 0,
    }
}

#[tokio::test]
async fn observation_pending_running_and_instance_isolation() -> anyhow::Result<()> {
    let fixture = Fixture::new(Boundary::Execute)?;
    let control = fixture.control();
    let work = run(&fixture, &fixture.execution, &control, limit(3)?);
    let reader = work.observation();
    let clone = reader.clone();
    let other = run(&fixture, &fixture.execution, &control, limit(3)?);
    assert_eq!(reader, clone);
    assert_ne!(reader, other.observation());
    assert_eq!(reader.scope(), fixture.execution.scope());
    assert_eq!(reader.definition_identity(), &DEFINITION);
    let pending = reader.read();
    assert_eq!(pending, ObservationStatus::Pending);
    let mut future = Box::pin(work.into_future());
    assert!(
        future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    assert_eq!(reader.read(), ObservationStatus::Running(first()?));
    assert_eq!(pending, ObservationStatus::Pending);
    assert_eq!(other.observation().read(), ObservationStatus::Pending);
    fixture.cancel.cancel();
    let report = future.await;
    assert_eq!(
        report.stop,
        Stop::Failed(Error::new(ErrorKind::CommitUnknown))
    );
    assert_eq!(report.position, first()?.position);
    assert_eq!(reader.read(), ObservationStatus::Stopped(report.clone()));
    assert_eq!(clone.read(), ObservationStatus::Stopped(report));
    Ok(())
}

#[tokio::test]
async fn observation_checkpoint_pending_differs_from_confirmed_empty() -> anyhow::Result<()> {
    for (boundary, expected) in [
        (Boundary::Checkpoint, ObservationStatus::Pending),
        (Boundary::Read, ObservationStatus::Running(empty())),
    ] {
        let fixture = Fixture::new(boundary)?;
        let control = fixture.control();
        let work = run(&fixture, &fixture.execution, &control, limit(3)?);
        let reader = work.observation();
        let mut future = Box::pin(work.into_future());
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        assert_eq!(reader.read(), expected);
        fixture.cancel.cancel();
        let report = future.await;
        assert_eq!(report.stop, Stop::Failed(Error::new(ErrorKind::Cancelled)));
        assert_eq!(reader.read(), ObservationStatus::Stopped(report));
    }
    Ok(())
}

#[tokio::test]
async fn observation_unknown_settlement_never_advances() -> anyhow::Result<()> {
    let fixture = Fixture::new(Boundary::Unknown)?;
    let control = fixture.control();
    let work = run(&fixture, &fixture.execution, &control, limit(3)?);
    let reader = work.observation();
    let report = work.await;
    assert_eq!(
        report.stop,
        Stop::Failed(Error::new(ErrorKind::CommitUnknown))
    );
    assert_eq!(report.position, first()?.position);
    assert_eq!(
        (report.applied, report.duplicates, report.filtered),
        (1, 0, 0)
    );
    assert_eq!(
        fixture.execution.checkpoint().await?.position,
        Some(Position::new(2)?)
    );
    assert_eq!(reader.read(), ObservationStatus::Stopped(report));
    Ok(())
}

#[tokio::test]
async fn observation_terminal_report_and_counts_are_exact() -> anyhow::Result<()> {
    for (events, stop) in [(2, Stop::EventLimit), (4, Stop::CaughtUp)] {
        let fixture = Fixture::new(Boundary::Complete)?;
        let control = fixture.control();
        let work = run(&fixture, &fixture.execution, &control, limit(events)?);
        let reader = work.observation();
        let report = work.await.into_result()?;
        assert_eq!(report.stop, stop);
        assert_eq!((report.applied, report.duplicates), (1, 1));
        assert_eq!(report.filtered, u64::from(events == 4));
        assert_eq!(reader.read(), ObservationStatus::Stopped(report.clone()));
        // A later invocation and fencing must not overwrite the old instance.
        let _next = run(&fixture, &fixture.execution, &control, limit(4)?).await;
        fixture.execution.memory.stale.store(true, Ordering::SeqCst);
        assert_eq!(reader.read(), ObservationStatus::Stopped(report));
    }
    Ok(())
}

#[tokio::test]
async fn observation_unpolled_and_inflight_drop_latch_unavailable() -> anyhow::Result<()> {
    let fixture = Fixture::new(Boundary::Complete)?;
    let control = fixture.control();
    let work = run(&fixture, &fixture.execution, &control, limit(3)?);
    let reader = work.observation();
    drop(work);
    assert_eq!(
        reader.read(),
        ObservationStatus::Unavailable {
            last_confirmed: None
        }
    );
    let work = run(&fixture, &fixture.execution, &control, limit(3)?);
    let reader = work.observation();
    drop(work.into_future());
    assert_eq!(
        reader.read(),
        ObservationStatus::Unavailable {
            last_confirmed: None
        }
    );
    for (boundary, progress) in [
        (Boundary::Checkpoint, None),
        (Boundary::Read, Some(empty())),
        (Boundary::Execute, Some(first()?)),
    ] {
        let fixture = Fixture::new(boundary)?;
        let control = fixture.control();
        let work = run(&fixture, &fixture.execution, &control, limit(3)?);
        let reader = work.observation();
        let mut future = Box::pin(work.into_future());
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        drop(future);
        assert_eq!(
            reader.read(),
            ObservationStatus::Unavailable {
                last_confirmed: progress
            }
        );
        fixture.cancel.cancel();
        assert_eq!(
            reader.read(),
            ObservationStatus::Unavailable {
                last_confirmed: progress
            }
        );
    }
    Ok(())
}

#[tokio::test]
async fn observation_unwind_latches_last_confirmed_progress() -> anyhow::Result<()> {
    let fixture = Fixture::new(Boundary::Panic)?;
    let control = fixture.control();
    let work = run(&fixture, &fixture.execution, &control, limit(3)?);
    let reader = work.observation();
    let mut future = Box::pin(work.into_future());
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
    }));
    assert!(outcome.is_err());
    assert_eq!(
        reader.read(),
        ObservationStatus::Unavailable {
            last_confirmed: Some(first()?)
        }
    );
    Ok(())
}

#[tokio::test]
async fn observation_deadline_and_fencing_preserve_report() -> anyhow::Result<()> {
    for kind in [ErrorKind::Deadline, ErrorKind::Fenced] {
        let fixture = Fixture::new(Boundary::Complete)?;
        let control = fixture.control();
        if kind == ErrorKind::Deadline {
            fixture.clock.0.store(10, Ordering::SeqCst);
        } else {
            fixture.execution.memory.stale.store(true, Ordering::SeqCst);
        }
        let work = run(&fixture, &fixture.execution, &control, limit(3)?);
        let reader = work.observation();
        let report = work.await;
        assert_eq!(report.stop, Stop::Failed(Error::new(kind)));
        assert_eq!(report.position, None);
        assert_eq!(report.applied, 0);
        assert_eq!(reader.read(), ObservationStatus::Stopped(report));
    }
    Ok(())
}

#[tokio::test]
async fn observation_task_abort_latches_unavailable() -> anyhow::Result<()> {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let fixture = Fixture::new(Boundary::Execute)?;
        let control = fixture.control();
        let work = run(&fixture, &fixture.execution, &control, limit(3)?);
        let reader = work.observation();
        let mut future = Box::pin(work.into_future());
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        sender
            .send(reader)
            .map_err(|_| anyhow::anyhow!("reader receiver dropped"))?;
        Ok::<_, anyhow::Error>(future.await)
    });
    let reader = tokio::time::timeout(Duration::from_secs(5), receiver).await??;
    assert_eq!(reader.read(), ObservationStatus::Running(first()?));
    task.abort();
    let result = tokio::time::timeout(Duration::from_secs(5), task).await?;
    assert!(matches!(result, Err(error) if error.is_cancelled()));
    assert_eq!(
        reader.read(),
        ObservationStatus::Unavailable {
            last_confirmed: Some(first()?)
        }
    );
    Ok(())
}

#[tokio::test]
async fn observation_retained_snapshots_allow_cross_thread_completion() -> anyhow::Result<()> {
    let fixture = Fixture::new(Boundary::Complete)?;
    let control = fixture.control();
    let work = run(&fixture, &fixture.execution, &control, limit(4)?);
    let reader = work.observation();
    let old = reader.read();
    let report = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let mut future = Box::pin(work.into_future());
                future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
            })
            .join()
    })
    .map_err(|_| anyhow::anyhow!("worker panicked"))?;
    let Poll::Ready(report) = report else {
        anyhow::bail!("unexpected provider wait")
    };
    assert_eq!(old, ObservationStatus::Pending);
    assert_eq!(reader.read(), ObservationStatus::Stopped(report));
    Ok(())
}
