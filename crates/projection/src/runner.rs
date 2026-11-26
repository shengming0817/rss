//! ref: baseline 5b63e10 crates/eventexec/src/projection.rs; ordered resume algorithm only.
use crate::observation::Publisher;
use crate::{
    ApplyOutcome, BatchExecution, PageBudget, ReadPage, Checkpoint, Control, Error, ErrorKind, Event,
    Execution, Position, ReplayBound, RunObservation, Source, Timer,
};
use std::future::{Future, IntoFuture};

/// Bound work independently of elapsed time.
#[derive(Debug, Clone, Copy)]
pub struct RunLimit {
    page: PageBudget,
    events: u64,
}
impl RunLimit {
    /// Non-zero total events; every examined event consumes the budget, including duplicates.
    pub const fn new(page: PageBudget, events: u64) -> Result<Self, Error> {
        if events == 0 {
            Err(Error::new(ErrorKind::InvalidInput))
        } else {
            Ok(Self { page, events })
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
    /// The next event exceeds the per-page byte budget. Resume with a larger page.
    PayloadBudget {
        /// Position of the pending event. The acknowledged cursor precedes it.
        position: Position,
        /// Exact encoded payload bytes needed for this event.
        required_bytes: u32,
    },
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
    events: &[impl AsRef<Event>],
    execution: &impl Execution,
    after: Option<Position>,
    limit: PageBudget,
) -> Result<(), Error> {
    if events.len() > limit.rows() as usize {
        return Err(Error::new(ErrorKind::SourceContract));
    }
    let mut previous = after;
    let mut bytes_left = limit.payload_bytes() as usize;
    for item in events {
        let event = item.as_ref();
        if event.source() != execution.scope().source() {
            return Err(Error::new(ErrorKind::ScopeMismatch));
        }
        if previous.is_some_and(|p| event.position() <= p) {
            return Err(Error::new(ErrorKind::OutOfOrder));
        }
        bytes_left = bytes_left.checked_sub(event.payload().len())
            .ok_or(Error::new(ErrorKind::SourceContract))?;
        previous = Some(event.position());
    }
    Ok(())
}
/// One bounded invocation. Obtain its read-only handle before awaiting it, or use
/// `IntoFuture::into_future` where an API requires a `Future`. No task is spawned.
#[must_use = "await the run to execute it; dropping it marks observation unavailable"]
pub struct Run<F> {
    future: F,
    observation: RunObservation,
}
impl<F> Run<F> {
    /// Retain a read-only handle to this exact invocation.
    pub fn observation(&self) -> RunObservation {
        self.observation.clone()
    }
}
impl<F: Future<Output = Report>> IntoFuture for Run<F> {
    type Output = Report;
    type IntoFuture = F;
    fn into_future(self) -> F {
        self.future
    }
}

/// Prepare a run until caught up, interrupted, failed or bounded. Execution begins when awaited;
/// only local observation state is allocated here. No implicit retry or epoch takeover occurs.
/// Dropping the run or its future before a final report latches an unavailable observation.
pub fn run<'a, S: Source<Item = E::Item>, E: Execution, T: Timer>(
    source: &'a S,
    execution: &'a E,
    control: &'a Control<'_, T>,
    limit: RunLimit,
) -> Run<impl Future<Output = Report> + Send + 'a> {
    prepare::<_, _, _, Individual>(source, execution, control, limit)
}

/// Run ordered, atomic pages. A rejected or uncertain page publishes no progress.
/// Read size and remaining event budget bound each transaction.
pub fn run_batched<'a, S: Source<Item = E::Item>, E: BatchExecution, T: Timer>(
    source: &'a S,
    execution: &'a E,
    control: &'a Control<'_, T>,
    limit: RunLimit,
) -> Run<impl Future<Output = Report> + Send + 'a> {
    prepare::<_, _, _, AtomicPage>(source, execution, control, limit)
}

fn prepare<'a, S: Source<Item = E::Item>, E: Execution, T: Timer, M: Settlement<E>>(
    source: &'a S,
    execution: &'a E,
    control: &'a Control<'_, T>,
    limit: RunLimit,
) -> Run<impl Future<Output = Report> + Send + 'a> {
    let mut publisher = Publisher::new(execution.scope().clone(), *execution.definition_identity());
    let observation = publisher.observation();
    let future = async move {
        let mut report = Report {
            position: None,
            applied: 0,
            duplicates: 0,
            filtered: 0,
            stop: Stop::CaughtUp,
        };
        report.stop = match drive::<_, _, _, M>(
            source,
            execution,
            control,
            limit,
            &mut report,
            &mut publisher,
        )
        .await
        {
            Ok(stop) => stop,
            Err(error) => Stop::Failed(error),
        };
        publisher.finish(&report);
        report
    };
    Run {
        future,
        observation,
    }
}
async fn drive<S: Source<Item = E::Item>, E: Execution, T: Timer, M: Settlement<E>>(
    source: &S,
    execution: &E,
    control: &Control<'_, T>,
    limit: RunLimit,
    report: &mut Report,
    publisher: &mut Publisher,
) -> Result<Stop, Error> {
    control.check()?;
    let mut checkpoint = execution.checkpoint(control).await?;
    report.position = checkpoint.position;
    publisher.confirmed(report);
    let mut remaining = limit.events;
    loop {
        control.check()?;
        if remaining == 0 {
            return Ok(Stop::EventLimit);
        }
        if replay_done(checkpoint) {
            return Ok(Stop::CaughtUp);
        }
        let rows = remaining.min(u64::from(limit.page.rows())) as u32;
        let page = PageBudget::new(rows, limit.page.payload_bytes())?;
        let read = source.read(execution.scope().source(), checkpoint.position, page, control).await?;
        control.check()?;
        let events = match read {
            ReadPage::Events(events) => events,
            ReadPage::Blocked { position, required_bytes } => {
                if checkpoint.position.is_some_and(|p| position <= p)
                    || matches!(checkpoint.bound, ReplayBound::Through(Some(end)) if position > end)
                    || required_bytes <= page.payload_bytes()
                    || required_bytes > Event::MAX_PAYLOAD_BYTES
                {
                    return Err(Error::new(ErrorKind::SourceContract));
                }
                return Ok(Stop::PayloadBudget { position, required_bytes });
            }
        };
        validate_batch(&events, execution, checkpoint.position, page)?;
        if events.is_empty() {
            return empty_stop(checkpoint);
        }
        let mut events = events.into_iter();
        while !events.as_slice().is_empty() {
            control.check()?;
            let (position, outcomes) = M::next(execution, checkpoint, &mut events, control).await?;
            for outcome in outcomes {
                match outcome {
                    ApplyOutcome::Applied => report.applied += 1,
                    ApplyOutcome::Duplicate => report.duplicates += 1,
                    ApplyOutcome::Filtered => report.filtered += 1,
                }
                remaining -= 1;
            }
            checkpoint.position = Some(position);
            report.position = checkpoint.position;
            publisher.confirmed(report);
            control.check()?;
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

trait Settlement<E: Execution> {
    type Outcomes: IntoIterator<Item = ApplyOutcome> + Send;
    fn next<T: Timer>(
        execution: &E,
        checkpoint: Checkpoint,
        events: &mut std::vec::IntoIter<E::Item>,
        control: &Control<'_, T>,
    ) -> impl Future<Output = Result<(Position, Self::Outcomes), Error>> + Send;
}

struct Individual;
impl<E: Execution> Settlement<E> for Individual {
    type Outcomes = [ApplyOutcome; 1];
    async fn next<T: Timer>(
        execution: &E,
        checkpoint: Checkpoint,
        events: &mut std::vec::IntoIter<E::Item>,
        control: &Control<'_, T>,
    ) -> Result<(Position, Self::Outcomes), Error> {
        let event = events.next().ok_or(Error::new(ErrorKind::SourceContract))?;
        let position = event.as_ref().position();
        if matches!(checkpoint.bound, ReplayBound::Through(Some(end)) if position > end) {
            return Err(Error::new(ErrorKind::SourceContract));
        }
        let outcome = execution
            .execute(checkpoint.position, &event, control)
            .await?;
        Ok((position, [outcome]))
    }
}

struct AtomicPage;
impl<E: BatchExecution> Settlement<E> for AtomicPage {
    type Outcomes = Vec<ApplyOutcome>;
    async fn next<T: Timer>(
        execution: &E,
        checkpoint: Checkpoint,
        events: &mut std::vec::IntoIter<E::Item>,
        control: &Control<'_, T>,
    ) -> Result<(Position, Self::Outcomes), Error> {
        let mut page: Vec<_> = std::mem::take(events).collect();
        if let ReplayBound::Through(Some(end)) = checkpoint.bound {
            match page.binary_search_by_key(&end, |e| e.as_ref().position()) {
                Ok(index) => page.truncate(index + 1),
                Err(index) if index < page.len() => {
                    return Err(Error::new(ErrorKind::SourceContract));
                }
                Err(_) => {}
            }
        }
        let position = page
            .last()
            .ok_or(Error::new(ErrorKind::SourceContract))?
            .as_ref()
            .position();
        let len = page.len();
        let outcomes = execution
            .execute_batch(checkpoint.position, page, control)
            .await?;
        if outcomes.len() != len {
            return Err(Error::new(ErrorKind::StorageContract));
        }
        Ok((position, outcomes))
    }
}
