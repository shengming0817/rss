//! Scenarios extracted from projection_worker_restart.rs@5b63e10; no product bindings.
use rss_projection::*;
use rss_request_context::TenantId;
use std::{
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio_util::sync::CancellationToken;

struct Clock(AtomicU64);
impl Timer for Clock {
    fn now(&self) -> Duration {
        Duration::from_secs(self.0.load(Ordering::SeqCst))
    }
    async fn sleep_until(&self, _: Duration) {
        std::future::pending::<()>().await;
    }
}
fn scope() -> anyhow::Result<ProjectionScope> {
    Ok(ProjectionScope::new(
        SourceScope::new(
            TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")?,
            "journal",
        )?,
        "count",
        "v1",
    )?)
}
fn event(scope: &ProjectionScope, n: u64) -> anyhow::Result<Event> {
    Ok(Event::new(
        scope.source().clone(),
        Position::new(n)?,
        format!("e{n}"),
        vec![1],
    )?)
}
struct Journal(Vec<Event>);
impl Source for Journal {
    async fn high_water(&self, _: &SourceScope) -> Result<Option<Position>, Error> {
        Ok(self.0.last().map(Event::position))
    }
    async fn read(
        &self,
        _: &SourceScope,
        after: Option<Position>,
        limit: BatchLimit,
    ) -> Result<Vec<Event>, Error> {
        Ok(self
            .0
            .iter()
            .filter(|e| after.is_none_or(|p| e.position() > p))
            .take(limit.get() as usize)
            .cloned()
            .collect())
    }
}
struct Memory {
    scope: ProjectionScope,
    state: Mutex<Checkpoint>,
    applied: AtomicU64,
    stale: AtomicBool,
}
impl Memory {
    fn new(scope: ProjectionScope, bound: ReplayBound) -> Self {
        Self {
            scope,
            state: Mutex::new(Checkpoint {
                position: None,
                bound,
            }),
            applied: AtomicU64::new(0),
            stale: AtomicBool::new(false),
        }
    }
}
impl Execution for Memory {
    fn scope(&self) -> &ProjectionScope {
        &self.scope
    }
    async fn checkpoint(&self) -> Result<Checkpoint, Error> {
        if self.stale.load(Ordering::SeqCst) {
            return Err(Error::new(rss_projection::ErrorKind::Fenced));
        }
        self.state
            .lock()
            .map(|v| *v)
            .map_err(|_| Error::new(rss_projection::ErrorKind::Unavailable))
    }
    async fn execute<T: Timer>(
        &self,
        expected: Option<Position>,
        event: &Event,
        _: &Control<'_, T>,
    ) -> Result<ApplyOutcome, Error> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::new(rss_projection::ErrorKind::Unavailable))?;
        if self.stale.load(Ordering::SeqCst) || state.position != expected {
            return Err(Error::new(rss_projection::ErrorKind::Fenced));
        }
        self.applied.fetch_add(1, Ordering::SeqCst);
        state.position = Some(event.position());
        Ok(ApplyOutcome::Applied)
    }
}
#[tokio::test]
async fn resumes_from_zero_and_stops_at_total_event_budget() -> anyhow::Result<()> {
    let scope = scope()?;
    let source = Journal(vec![
        event(&scope, 0)?,
        event(&scope, 2)?,
        event(&scope, 9)?,
    ]);
    let execution = Memory::new(scope, ReplayBound::Live);
    let clock = Clock(AtomicU64::new(0));
    let cancel = CancellationToken::new();
    let control = Control::new(&clock, Duration::from_secs(10), &cancel);
    let limit = RunLimit::new(BatchLimit::new(100)?, 2)?;
    let first = run(&source, &execution, &control, limit).await;
    assert_eq!(first.applied, 2);
    assert_eq!(first.stop, Stop::EventLimit);
    let next = run(&source, &execution, &control, limit).await;
    assert_eq!(next.applied, 1);
    assert_eq!(next.stop, Stop::CaughtUp);
    assert_eq!(execution.applied.load(Ordering::SeqCst), 3);
    Ok(())
}
#[tokio::test]
async fn malformed_batches_are_rejected_before_any_effect() -> anyhow::Result<()> {
    let scope = scope()?;
    let other = ProjectionScope::new(
        SourceScope::new(
            TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d478")?,
            "journal",
        )?,
        "count",
        "v1",
    )?;
    for (events, reason) in [
        (
            vec![event(&scope, 2)?, event(&scope, 1)?],
            Error::new(rss_projection::ErrorKind::OutOfOrder),
        ),
        (
            vec![event(&scope, 1)?, event(&scope, 1)?],
            Error::new(rss_projection::ErrorKind::OutOfOrder),
        ),
        (
            vec![event(&scope, 1)?, event(&other, 2)?],
            Error::new(rss_projection::ErrorKind::ScopeMismatch),
        ),
    ] {
        let execution = Memory::new(scope.clone(), ReplayBound::Live);
        let clock = Clock(AtomicU64::new(0));
        let cancel = CancellationToken::new();
        let report = run(
            &Journal(events),
            &execution,
            &Control::new(&clock, Duration::from_secs(10), &cancel),
            RunLimit::new(BatchLimit::new(10)?, 10)?,
        )
        .await;
        assert_eq!(report.stop, Stop::Failed(reason));
        assert_eq!(execution.applied.load(Ordering::SeqCst), 0);
    }
    Ok(())
}
#[tokio::test]
async fn replay_has_immutable_empty_and_nonempty_boundaries() -> anyhow::Result<()> {
    let scope = scope()?;
    let source = Journal(vec![
        event(&scope, 0)?,
        event(&scope, 1)?,
        event(&scope, 2)?,
    ]);
    let clock = Clock(AtomicU64::new(0));
    let cancel = CancellationToken::new();
    for (bound, count) in [
        (ReplayBound::Through(None), 0),
        (ReplayBound::Through(Some(Position::new(1)?)), 2),
    ] {
        let execution = Memory::new(scope.clone(), bound);
        let report = run(
            &source,
            &execution,
            &Control::new(&clock, Duration::from_secs(10), &cancel),
            RunLimit::new(BatchLimit::new(10)?, 10)?,
        )
        .await;
        assert_eq!(report.stop, Stop::CaughtUp);
        assert_eq!(report.applied, count);
    }
    Ok(())
}
#[tokio::test]
async fn cancellation_deadline_and_fencing_admit_no_effects() -> anyhow::Result<()> {
    let scope = scope()?;
    let source = Journal(vec![event(&scope, 0)?]);
    for cause in [
        Error::new(rss_projection::ErrorKind::Cancelled),
        Error::new(rss_projection::ErrorKind::Deadline),
        Error::new(rss_projection::ErrorKind::Fenced),
    ] {
        let execution = Memory::new(scope.clone(), ReplayBound::Live);
        let clock = Clock(AtomicU64::new(0));
        let cancel = CancellationToken::new();
        if cause == Error::new(rss_projection::ErrorKind::Cancelled) {
            cancel.cancel();
        }
        if cause == Error::new(rss_projection::ErrorKind::Deadline) {
            clock.0.store(10, Ordering::SeqCst);
        }
        if cause == Error::new(rss_projection::ErrorKind::Fenced) {
            execution.stale.store(true, Ordering::SeqCst);
        }
        let report = run(
            &source,
            &execution,
            &Control::new(&clock, Duration::from_secs(10), &cancel),
            RunLimit::new(BatchLimit::new(10)?, 10)?,
        )
        .await;
        assert_eq!(report.stop, Stop::Failed(cause));
        assert_eq!(execution.applied.load(Ordering::SeqCst), 0);
    }
    Ok(())
}
struct Remote {
    facts: Mutex<std::collections::HashMap<String, [u8; 32]>>,
    writes: AtomicU64,
}
impl ExternalTarget for &Remote {
    async fn apply<T: Timer>(
        &self,
        _: &ProjectionScope,
        event: &Event,
        control: &Control<'_, T>,
    ) -> Result<ApplyOutcome, Error> {
        control.check()?;
        let mut facts = self
            .facts
            .lock()
            .map_err(|_| Error::new(rss_projection::ErrorKind::Unavailable))?;
        if let Some(digest) = facts.get(event.id()) {
            return if digest == &event.fingerprint() {
                Ok(ApplyOutcome::Duplicate)
            } else {
                Err(Error::new(rss_projection::ErrorKind::Conflict))
            };
        }
        facts.insert(event.id().into(), event.fingerprint());
        self.writes.fetch_add(1, Ordering::SeqCst);
        Ok(ApplyOutcome::Applied)
    }
}
struct Progress {
    inner: Memory,
    fail: AtomicBool,
}
impl ExternalCheckpoint for &Progress {
    fn scope(&self) -> &ProjectionScope {
        &self.inner.scope
    }
    async fn load(&self) -> Result<Checkpoint, Error> {
        self.inner.checkpoint().await
    }
    async fn advance<T: Timer>(
        &self,
        expected: Option<Position>,
        event: &Event,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        control.check()?;
        if self.fail.swap(false, Ordering::SeqCst) {
            return Err(Error::new(rss_projection::ErrorKind::Unavailable));
        }
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| Error::new(rss_projection::ErrorKind::Unavailable))?;
        if state.position != expected {
            return Err(Error::new(rss_projection::ErrorKind::Fenced));
        }
        state.position = Some(event.position());
        Ok(())
    }
}
#[tokio::test]
async fn external_apply_before_checkpoint_failure_recovers_by_fact_identity() -> anyhow::Result<()>
{
    let scope = scope()?;
    let fact = event(&scope, 0)?;
    let progress = Progress {
        inner: Memory::new(scope.clone(), ReplayBound::Live),
        fail: AtomicBool::new(true),
    };
    let remote = Remote {
        facts: Mutex::new(std::collections::HashMap::new()),
        writes: AtomicU64::new(0),
    };
    let execution = AtLeastOnce::new(&progress, &remote);
    let clock = Clock(AtomicU64::new(0));
    let cancel = CancellationToken::new();
    let control = Control::new(&clock, Duration::from_secs(10), &cancel);
    assert_eq!(
        execution.execute(None, &fact, &control).await,
        Err(Error::new(rss_projection::ErrorKind::Unavailable))
    );
    assert_eq!(
        execution.execute(None, &fact, &control).await?,
        ApplyOutcome::Duplicate
    );
    let repeated = Event::new(
        scope.source().clone(),
        Position::new(1)?,
        fact.id(),
        fact.payload().to_vec(),
    )?;
    assert_eq!(
        execution
            .execute(Some(fact.position()), &repeated, &control)
            .await?,
        ApplyOutcome::Duplicate
    );
    let conflict = Event::new(
        scope.source().clone(),
        Position::new(2)?,
        fact.id(),
        vec![9],
    )?;
    assert_eq!(
        execution
            .execute(Some(repeated.position()), &conflict, &control)
            .await,
        Err(Error::new(rss_projection::ErrorKind::Conflict))
    );
    assert_eq!(remote.writes.load(Ordering::SeqCst), 1);
    Ok(())
}

struct ConsumingTime<'a> {
    memory: Memory,
    clock: &'a Clock,
}
impl Execution for ConsumingTime<'_> {
    fn scope(&self) -> &ProjectionScope {
        self.memory.scope()
    }
    async fn checkpoint(&self) -> Result<Checkpoint, Error> {
        self.memory.checkpoint().await
    }
    async fn execute<T: Timer>(
        &self,
        expected: Option<Position>,
        event: &Event,
        control: &Control<'_, T>,
    ) -> Result<ApplyOutcome, Error> {
        let outcome = self.memory.execute(expected, event, control).await?;
        self.clock.0.fetch_add(6, Ordering::SeqCst);
        Ok(outcome)
    }
}
#[tokio::test]
async fn total_deadline_is_not_reset_between_events() -> anyhow::Result<()> {
    let scope = scope()?;
    let clock = Clock(AtomicU64::new(0));
    let cancel = CancellationToken::new();
    let source = Journal(vec![
        event(&scope, 0)?,
        event(&scope, 1)?,
        event(&scope, 2)?,
    ]);
    let execution = ConsumingTime {
        memory: Memory::new(scope, ReplayBound::Live),
        clock: &clock,
    };
    let report = run(
        &source,
        &execution,
        &Control::new(&clock, Duration::from_secs(10), &cancel),
        RunLimit::new(BatchLimit::new(10)?, 10)?,
    )
    .await;
    assert_eq!(report.applied, 2);
    assert_eq!(
        report.stop,
        Stop::Failed(Error::new(rss_projection::ErrorKind::Deadline))
    );
    Ok(())
}
struct BlockedSource {
    entered: tokio::sync::Notify,
}
impl Source for BlockedSource {
    async fn high_water(&self, _: &SourceScope) -> Result<Option<Position>, Error> {
        Ok(None)
    }
    async fn read(
        &self,
        _: &SourceScope,
        _: Option<Position>,
        _: BatchLimit,
    ) -> Result<Vec<Event>, Error> {
        self.entered.notify_one();
        std::future::pending().await
    }
}
#[tokio::test]
async fn cancellation_interrupts_a_blocked_source() -> anyhow::Result<()> {
    let execution = Memory::new(scope()?, ReplayBound::Live);
    let clock = Clock(AtomicU64::new(0));
    let cancel = CancellationToken::new();
    let source = BlockedSource {
        entered: tokio::sync::Notify::new(),
    };
    let control = Control::new(&clock, Duration::from_secs(10), &cancel);
    let work = run(
        &source,
        &execution,
        &control,
        RunLimit::new(BatchLimit::new(10)?, 10)?,
    );
    let cancellation = async {
        source.entered.notified().await;
        cancel.cancel();
    };
    let (report, ()) = tokio::join!(work, cancellation);
    assert_eq!(
        report.stop,
        Stop::Failed(Error::new(rss_projection::ErrorKind::Cancelled))
    );
    assert_eq!(report.applied, 0);
    Ok(())
}
#[tokio::test]
async fn missing_replay_end_is_not_reported_as_complete() -> anyhow::Result<()> {
    let scope = scope()?;
    let source = Journal(vec![event(&scope, 0)?, event(&scope, 3)?]);
    let execution = Memory::new(scope, ReplayBound::Through(Some(Position::new(2)?)));
    let clock = Clock(AtomicU64::new(0));
    let cancel = CancellationToken::new();
    let report = run(
        &source,
        &execution,
        &Control::new(&clock, Duration::from_secs(10), &cancel),
        RunLimit::new(BatchLimit::new(10)?, 10)?,
    )
    .await;
    assert_eq!(
        report.stop,
        Stop::Failed(Error::new(rss_projection::ErrorKind::SourceContract))
    );
    assert_eq!(report.applied, 1);
    Ok(())
}

struct FailingObserver;
impl Observer for FailingObserver {
    #[allow(clippy::panic)]
    // reason: deliberate observer failure after the caller already owns its durable report.
    fn settled(&self, _: ApplyOutcome, _: u64) {
        panic!("test observer failed")
    }
    fn stopped(&self, _: Stop) {}
}
#[tokio::test]
async fn observer_failure_cannot_prevent_or_erase_the_execution_report() -> anyhow::Result<()> {
    let s = scope()?;
    let source = Journal(vec![event(&s, 0)?]);
    let execution = Memory::new(s, ReplayBound::Live);
    let clock = Clock(AtomicU64::new(0));
    let cancel = CancellationToken::new();
    let report = run(
        &source,
        &execution,
        &Control::new(&clock, Duration::from_secs(10), &cancel),
        RunLimit::new(BatchLimit::new(10)?, 10)?,
    )
    .await
    .into_result()?;
    assert_eq!(report.applied, 1);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || report.observe(&FailingObserver)
        ))
        .is_err()
    );
    assert_eq!(report.position, execution.checkpoint().await?.position);
    assert_eq!(report.into_result()?.stop, Stop::CaughtUp);
    Ok(())
}

struct Filtering(Memory);
impl Execution for Filtering {
    fn scope(&self) -> &ProjectionScope {
        self.0.scope()
    }
    async fn checkpoint(&self) -> Result<Checkpoint, Error> {
        self.0.checkpoint().await
    }
    async fn execute<T: Timer>(
        &self,
        expected: Option<Position>,
        event: &Event,
        control: &Control<'_, T>,
    ) -> Result<ApplyOutcome, Error> {
        self.0.execute(expected, event, control).await?;
        Ok(ApplyOutcome::Filtered)
    }
}
#[tokio::test]
async fn filtered_events_advance_and_consume_total_budget() -> anyhow::Result<()> {
    let scope = scope()?;
    let source = Journal(vec![
        event(&scope, 0)?,
        event(&scope, 1)?,
        event(&scope, 2)?,
    ]);
    let execution = Filtering(Memory::new(scope, ReplayBound::Live));
    let clock = Clock(AtomicU64::new(0));
    let cancel = CancellationToken::new();
    let control = Control::new(&clock, Duration::from_secs(10), &cancel);
    let report = run(
        &source,
        &execution,
        &control,
        RunLimit::new(BatchLimit::new(1)?, 2)?,
    )
    .await
    .into_result()?;
    assert_eq!(
        (report.filtered, report.applied, report.duplicates),
        (2, 0, 0)
    );
    assert_eq!(report.position, Some(Position::new(1)?));
    assert_eq!(report.stop, Stop::EventLimit);
    assert_eq!(execution.checkpoint().await?.position, report.position);
    Ok(())
}
