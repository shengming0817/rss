//! Budget enforcement belongs to the operation owner, including deterministic settlement races.
use super::*;
use std::{
    future::Future,
    task::{Context, Waker},
};

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
    async fn sleep_until(&self, deadline: Duration) {
        let mut receiver = self.0.subscribe();
        loop {
            if *receiver.borrow_and_update() >= deadline {
                return;
            }
            if receiver.changed().await.is_err() {
                return;
            }
        }
    }
}
struct Waiting(Memory, AtomicU64);
impl Waiting {
    async fn wait<T: Timer, R>(&self, control: &Control<'_, T>) -> Result<R, Error> {
        control
            .run(async {
                self.1.fetch_add(1, Ordering::SeqCst);
                std::future::pending().await
            })
            .await
    }
}
impl Source for Waiting {
    type Item = rss_projection::Event;
    async fn high_water<T: Timer>(
        &self,
        _: &SourceScope,
        control: &Control<'_, T>,
    ) -> Result<Option<Position>, Error> {
        self.wait(control).await
    }
    async fn read<T: Timer>(
        &self,
        _: &SourceScope,
        _: Option<Position>,
        _: PageBudget,
        control: &Control<'_, T>,
    ) -> Result<ReadPage<Event>, Error> {
        self.wait(control).await
    }
}
impl Execution for Waiting {
    type Item = rss_projection::Event;
    fn scope(&self) -> &ProjectionScope {
        self.0.scope()
    }
    fn definition_identity(&self) -> &DefinitionIdentity {
        &DEFINITION
    }
    async fn checkpoint<T: Timer>(&self, control: &Control<'_, T>) -> Result<Checkpoint, Error> {
        self.wait(control).await
    }
    async fn execute<T: Timer>(
        &self,
        expected: Option<Position>,
        event: &Event,
        control: &Control<'_, T>,
    ) -> Result<ApplyOutcome, Error> {
        self.0.execute(expected, event, control).await
    }
}
impl ExternalCheckpoint for Waiting {
    fn scope(&self) -> &ProjectionScope {
        self.0.scope()
    }
    fn definition_identity(&self) -> &DefinitionIdentity {
        &DEFINITION
    }
    async fn load<T: Timer>(&self, control: &Control<'_, T>) -> Result<Checkpoint, Error> {
        self.wait(control).await
    }
    async fn advance<T: Timer>(
        &self,
        expected: Option<Position>,
        event: &Event,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        self.0.execute(expected, event, control).await.map(|_| ())
    }
}
async fn read_port(
    ports: &Waiting,
    stage: u8,
    control: &Control<'_, ManualTimer>,
) -> Result<(), Error> {
    match stage {
        0 => ports
            .high_water(ports.0.scope().source(), control)
            .await
            .map(|_| ()),
        1 => ports
            .read(
                ports.0.scope().source(),
                None,
                PageBudget::new(1, Event::MAX_PAYLOAD_BYTES)?,
                control,
            )
            .await
            .map(|_| ()),
        2 => ports.checkpoint(control).await.map(|_| ()),
        _ => ports.load(control).await.map(|_| ()),
    }
}
#[tokio::test]
async fn direct_read_ports_use_full_original_budget() -> anyhow::Result<()> {
    for stage in 0..4 {
        let ports = Waiting(Memory::new(scope()?, ReplayBound::Live), AtomicU64::new(0));
        let timer = ManualTimer::new();
        let cancel = CancellationToken::new();
        let control = Control::new(&timer, Duration::from_secs(60), &cancel);
        let mut operation = Box::pin(read_port(&ports, stage, &control));
        assert!(
            operation
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        timer.advance(31);
        assert!(
            operation
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        timer.advance(60);
        assert_eq!(operation.await, Err(ErrorKind::Deadline.into()));
        assert_eq!(ports.1.load(Ordering::SeqCst), 1);
        cancel.cancel(); // Cancellation takes precedence even at the same expired deadline.
        assert_eq!(
            read_port(&ports, stage, &control).await,
            Err(ErrorKind::Cancelled.into())
        );
        assert_eq!(ports.1.load(Ordering::SeqCst), 1);
    }
    Ok(())
}
struct EmptyAtDeadline<'a>(&'a Clock);
impl Source for EmptyAtDeadline<'_> {
    type Item = rss_projection::Event;
    async fn high_water<T: Timer>(
        &self,
        _: &SourceScope,
        control: &Control<'_, T>,
    ) -> Result<Option<Position>, Error> {
        control.check()?;
        Ok(None)
    }
    async fn read<T: Timer>(
        &self,
        _: &SourceScope,
        _: Option<Position>,
        _: PageBudget,
        control: &Control<'_, T>,
    ) -> Result<ReadPage<Event>, Error> {
        control.check()?;
        self.0.0.store(10, Ordering::SeqCst);
        Ok(ReadPage::Events(vec![])) // Models expiry between provider return and runner validation.
    }
}
#[tokio::test]
async fn terminal_budget_checks_preserve_confirmed_progress() -> anyhow::Result<()> {
    let timer = Clock(AtomicU64::new(0));
    let cancel = CancellationToken::new();
    let control = Control::new(&timer, Duration::from_secs(10), &cancel);
    let execution = Memory::new(scope()?, ReplayBound::Live);
    let report = run(
        &EmptyAtDeadline(&timer),
        &execution,
        &control,
        RunLimit::new(PageBudget::new(1, Event::MAX_PAYLOAD_BYTES)?, 1)?,
    )
    .await;
    assert_eq!(report.stop, Stop::Failed(ErrorKind::Deadline.into()));
    timer.0.store(0, Ordering::SeqCst);
    let execution = ConsumingTime {
        memory: Memory::new(scope()?, ReplayBound::Through(Some(Position::new(1)?))),
        clock: &timer,
    };
    let source = Journal(vec![
        event(execution.scope(), 0)?,
        event(execution.scope(), 1)?,
    ]);
    let work = run(
        &source,
        &execution,
        &control,
        RunLimit::new(PageBudget::new(2, Event::MAX_PAYLOAD_BYTES)?, 2)?,
    );
    let observation = work.observation();
    let report = work.await;
    assert_eq!(report.stop, Stop::Failed(ErrorKind::Deadline.into()));
    assert_eq!(report.applied, 2);
    assert_eq!(report.position, Some(Position::new(1)?));
    assert_eq!(observation.read(), ObservationStatus::Stopped(report));
    Ok(())
}
struct Settlement<'a> {
    memory: Memory,
    cancel: &'a CancellationToken,
    target_error: Option<ErrorKind>,
    advance_error: Option<ErrorKind>,
    cancel_after_target: bool,
    advances: AtomicU64,
}
impl ExternalCheckpoint for &Settlement<'_> {
    fn scope(&self) -> &ProjectionScope {
        self.memory.scope()
    }
    fn definition_identity(&self) -> &DefinitionIdentity {
        &DEFINITION
    }
    async fn load<T: Timer>(&self, control: &Control<'_, T>) -> Result<Checkpoint, Error> {
        self.memory.checkpoint(control).await
    }
    async fn advance<T: Timer>(
        &self,
        _: Option<Position>,
        _: &Event,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        control.check()?;
        self.advances.fetch_add(1, Ordering::SeqCst);
        if let Some(error) = self.advance_error {
            self.cancel.cancel();
            return Err(error.into());
        }
        Ok(())
    }
}
impl ExternalTarget for &Settlement<'_> {
    async fn apply<T: Timer>(
        &self,
        _: &ProjectionScope,
        _: &DefinitionIdentity,
        _: &Event,
        control: &Control<'_, T>,
    ) -> Result<ApplyOutcome, Error> {
        control.check()?;
        if self.cancel_after_target || self.target_error.is_some() {
            self.cancel.cancel();
        }
        self.target_error
            .map_or(Ok(ApplyOutcome::Applied), |error| Err(error.into()))
    }
}
#[tokio::test]
async fn composition_preserves_owner_settlement_and_remote_effects() -> anyhow::Result<()> {
    for (target_error, advance_error, cancel_after_target, expected, advances) in [
        (
            Some(ErrorKind::RollbackFailed),
            None,
            false,
            ErrorKind::RollbackFailed,
            0,
        ),
        (
            Some(ErrorKind::Cancelled),
            None,
            false,
            ErrorKind::Cancelled,
            0,
        ),
        (
            Some(ErrorKind::Deadline),
            None,
            false,
            ErrorKind::Deadline,
            0,
        ),
        (
            Some(ErrorKind::CommitUnknown),
            None,
            false,
            ErrorKind::CommitUnknown,
            0,
        ),
        (
            None,
            Some(ErrorKind::RollbackFailed),
            false,
            ErrorKind::RollbackFailed,
            1,
        ),
        (
            None,
            Some(ErrorKind::Cancelled),
            false,
            ErrorKind::CommitUnknown,
            1,
        ),
        (None, None, true, ErrorKind::CommitUnknown, 0),
    ] {
        let timer = Clock(AtomicU64::new(0));
        let cancel = CancellationToken::new();
        let control = Control::new(&timer, Duration::from_secs(10), &cancel);
        let fixture = Settlement {
            memory: Memory::new(scope()?, ReplayBound::Live),
            cancel: &cancel,
            target_error,
            advance_error,
            cancel_after_target,
            advances: AtomicU64::new(0),
        };
        let source = Journal(vec![event(fixture.memory.scope(), 0)?]);
        let execution = AtLeastOnce::new(&fixture, &fixture);
        let report = run(
            &source,
            &execution,
            &control,
            RunLimit::new(PageBudget::new(1, Event::MAX_PAYLOAD_BYTES)?, 1)?,
        )
        .await;
        assert_eq!(report.stop, Stop::Failed(expected.into()));
        assert_eq!(fixture.advances.load(Ordering::SeqCst), advances);
        assert_eq!(report.position, None);
    }
    Ok(())
}
