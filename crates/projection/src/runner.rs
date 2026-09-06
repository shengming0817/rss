//! ref: baseline 5b63e10 crates/eventexec/src/projection.rs; ordered resume algorithm only.
use crate::{
    ApplyOutcome, BatchLimit, Checkpoint, Control, Error, ErrorKind, Event, Execution, Position,
    ReplayBound, Source, Timer,
};

/// Bound work independently of elapsed time.
#[derive(Debug, Clone, Copy)]
pub struct RunLimit {
    batch: BatchLimit,
    events: u64,
}
impl RunLimit {
    /// Non-zero total events; every examined event consumes the budget, including duplicates.
    pub const fn new(batch: BatchLimit, events: u64) -> Result<Self, Error> {
        if events == 0 {
            Err(Error::new(ErrorKind::InvalidInput))
        } else {
            Ok(Self { batch, events })
        }
    }
}
/// Why the bounded invocation ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stop {
    /// No more visible events, or the fixed replay snapshot is exhausted.
    CaughtUp,
    /// Total event allowance consumed.
    EventLimit,
    /// Execution stopped; durable progress must be reloaded before retry.
    Failed(Error),
}
/// Progress acknowledged during this invocation, excluding uncertain settlements.
#[must_use = "inspect stop or call into_result; a report can contain a failed execution"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// Last acknowledged coordinate, not a claim about an unknown transaction.
    pub position: Option<Position>,
    /// Newly committed effects.
    pub applied: u64,
    /// Previously committed facts.
    pub duplicates: u64,
    /// Intentionally ignored events.
    pub filtered: u64,
    /// Stop reason.
    pub stop: Stop,
}
impl Report {
    /// Propagate execution failure while preserving successful bounded progress reports.
    pub fn into_result(self) -> Result<Self, Error> {
        match self.stop {
            Stop::Failed(error) => Err(error),
            _ => Ok(self),
        }
    }
}
/// Explicit post-run observation. Called by the application only after it owns the report;
/// callbacks are outside the execution deadline and cannot prevent run from returning.
pub trait Observer {
    /// Aggregate acknowledged progress with a closed outcome label.
    fn settled(&self, outcome: ApplyOutcome, count: u64);
    /// The closed stop classification.
    fn stopped(&self, reason: Stop);
}
impl Report {
    /// Publish aggregate observations under the caller's own execution policy. This borrows
    /// rather than consumes the report; observer failure cannot erase acknowledged progress.
    pub fn observe(&self, observer: &impl Observer) {
        observer.settled(ApplyOutcome::Applied, self.applied);
        observer.settled(ApplyOutcome::Duplicate, self.duplicates);
        observer.settled(ApplyOutcome::Filtered, self.filtered);
        observer.stopped(self.stop.clone());
    }
}

pub(crate) fn validate_next(checkpoint: Checkpoint, event: &Event) -> Result<(), Error> {
    if checkpoint.position.is_some_and(|p| event.position() <= p) {
        return Err(Error::new(ErrorKind::OutOfOrder));
    }
    match checkpoint.bound {
        ReplayBound::Through(None) => Err(Error::new(ErrorKind::OutOfOrder)),
        ReplayBound::Through(Some(end)) if event.position() > end => {
            Err(Error::new(ErrorKind::OutOfOrder))
        }
        _ => Ok(()),
    }
}
fn validate_batch(
    events: &[Event],
    execution: &impl Execution,
    after: Option<Position>,
    limit: BatchLimit,
) -> Result<(), Error> {
    if events.len() > limit.get() as usize {
        return Err(Error::new(ErrorKind::SourceContract));
    }
    let mut previous = after;
    for event in events {
        if event.source() != execution.scope().source() {
            return Err(Error::new(ErrorKind::ScopeMismatch));
        }
        if previous.is_some_and(|p| event.position() <= p) {
            return Err(Error::new(ErrorKind::OutOfOrder));
        }
        previous = Some(event.position());
    }
    Ok(())
}
/// Run until caught up, interrupted, failed or bounded. No task is spawned and no implicit
/// retry or epoch takeover occurs. The caller controls subsequent invocations.
pub async fn run<S: Source, E: Execution, T: Timer>(
    source: &S,
    execution: &E,
    control: &Control<'_, T>,
    limit: RunLimit,
) -> Report {
    let mut report = Report {
        position: None,
        applied: 0,
        duplicates: 0,
        filtered: 0,
        stop: Stop::CaughtUp,
    };
    report.stop = match drive(source, execution, control, limit, &mut report).await {
        Ok(stop) => stop,
        Err(error) => Stop::Failed(error),
    };
    report
}
async fn drive<S: Source, E: Execution, T: Timer>(
    source: &S,
    execution: &E,
    control: &Control<'_, T>,
    limit: RunLimit,
    report: &mut Report,
) -> Result<Stop, Error> {
    let mut checkpoint = control.run(execution.checkpoint()).await?;
    report.position = checkpoint.position;
    let mut remaining = limit.events;
    loop {
        control.check()?;
        if remaining == 0 {
            return Ok(Stop::EventLimit);
        }
        if replay_done(checkpoint) {
            return Ok(Stop::CaughtUp);
        }
        let batch = BatchLimit::new(
            u32::try_from(remaining.min(u64::from(limit.batch.get())))
                .map_err(|_| Error::new(ErrorKind::InvalidInput))?,
        )?;
        let events = control
            .run(source.read(execution.scope().source(), checkpoint.position, batch))
            .await?;
        validate_batch(&events, execution, checkpoint.position, batch)?;
        if events.is_empty() {
            return empty_stop(checkpoint);
        }
        for event in events {
            if matches!(checkpoint.bound, ReplayBound::Through(Some(end)) if event.position() > end)
            {
                return Err(Error::new(ErrorKind::SourceContract));
            }
            control.check()?;
            let result = control
                .run(execution.execute(checkpoint.position, &event, control))
                .await
                .map_err(Error::uncertain)?;
            match result {
                ApplyOutcome::Applied => report.applied += 1,
                ApplyOutcome::Duplicate => report.duplicates += 1,
                ApplyOutcome::Filtered => report.filtered += 1,
            }
            checkpoint.position = Some(event.position());
            report.position = checkpoint.position;
            remaining -= 1;
            if replay_done(checkpoint) {
                return Ok(Stop::CaughtUp);
            }
        }
    }
}
fn replay_done(checkpoint: Checkpoint) -> bool {
    match checkpoint.bound {
        ReplayBound::Live => false,
        ReplayBound::Through(None) => true,
        ReplayBound::Through(Some(end)) => checkpoint.position.is_some_and(|p| p >= end),
    }
}
fn empty_stop(checkpoint: Checkpoint) -> Result<Stop, Error> {
    if matches!(checkpoint.bound, ReplayBound::Through(Some(_))) && !replay_done(checkpoint) {
        Err(Error::new(ErrorKind::SourceContract))
    } else {
        Ok(Stop::CaughtUp)
    }
}
