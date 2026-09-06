//! Single lifecycle reducer. Historical source: deviceloop/command.rs@5b63e10.
//! ref: mdeloof/statig statig/src/awaitable/state_machine.rs@3780eecdbcf4326051c38676d592c6c2b4a3bab5
use crate::{CommandSpec, Coordinate, DeviceEvent, DeviceReport, Error, StateDigest};

/// Persisted closed lifecycle vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Dispatch admitted atomically with command creation.
    Queued,
    /// Durable broker confirmation observed.
    Published,
    /// Receipt acknowledged by the device.
    Received,
    /// Matching actual state observed after receipt.
    Applied,
    /// Device rejected execution.
    Rejected,
    /// Deadline elapsed; execution absence is not proven.
    TimedOut,
    /// A newer authority replaced the command.
    Superseded,
    /// Owner cancelled; execution absence is not proven.
    Cancelled,
}
impl Status {
    /// All states for exhaustive conformance.
    pub const ALL: [Self; 8] = [
        Self::Queued,
        Self::Published,
        Self::Received,
        Self::Applied,
        Self::Rejected,
        Self::TimedOut,
        Self::Superseded,
        Self::Cancelled,
    ];
    /// Stable storage/diagnostic label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Published => "published",
            Self::Received => "received",
            Self::Applied => "applied",
            Self::Rejected => "rejected",
            Self::TimedOut => "timed_out",
            Self::Superseded => "superseded",
            Self::Cancelled => "cancelled",
        }
    }
    /// Reject unknown persisted vocabulary.
    pub fn restore(raw: &str) -> Result<Self, Error> {
        Self::ALL
            .into_iter()
            .find(|s| s.as_str() == raw)
            .ok_or(Error::InvalidSnapshot)
    }
    /// Terminal states absorb later observations.
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Queued | Self::Published | Self::Received)
    }
}
/// Reducer inputs, including provider/control facts. These are not authentication evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// The provider observed durable publication of the exact dispatch message.
    Published,
    /// Device receipt.
    Received,
    /// Actual state report.
    Reported(StateDigest),
    /// Device rejection.
    Rejected,
    /// Explicit deadline sweep.
    Expire,
    /// Owner cancellation.
    Cancel,
    /// Authority has advanced to the supplied current coordinate.
    Supersede,
}
/// Outcome does not imply that an enclosing transaction committed.
/// ```compile_fail
/// #![deny(unused_must_use)]
/// fn ignore(value: Result<rss_device_command::Outcome, ()>) -> Result<(), ()> {
///     value?;
///     Ok(())
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "inspect OutOfOrder before settling ingress"]
pub enum Outcome {
    /// State changed and its version advanced exactly once.
    Advanced,
    /// The requested fact is already reflected, or expiry is not yet due.
    Duplicate,
    /// A terminal command absorbed a later event.
    Late,
    /// Preceding protocol milestone is missing; retain input for redelivery.
    OutOfOrder,
}
/// Untrusted persisted representation; only `Command::restore` admits it as a state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Immutable facts.
    pub spec: CommandSpec,
    /// Positive optimistic version.
    pub version: i64,
    /// Closed state.
    pub status: Status,
    /// Server queue time.
    pub queued_at: i64,
    /// Server time durable publication was observed.
    pub published_at: Option<i64>,
    /// Server receipt time.
    pub received_at: Option<i64>,
    /// Server terminal decision time.
    pub terminal_at: Option<i64>,
}
/// Validated state. Private storage prevents unchecked mutation of version or milestones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command(Record);
impl Command {
    /// Queue at provider-authoritative time, never a client timestamp.
    pub fn queue(spec: CommandSpec, now: i64) -> Result<Self, Error> {
        if now >= spec.deadline() {
            return Err(Error::DeadlineElapsed);
        }
        Self::restore(Record {
            spec,
            version: 1,
            status: Status::Queued,
            queued_at: now,
            published_at: None,
            received_at: None,
            terminal_at: None,
        })
    }
    /// Validate every persisted milestone and version before use.
    pub fn restore(record: Record) -> Result<Self, Error> {
        validate(&record)?;
        Ok(Self(record))
    }
    /// Immutable authored identity.
    pub fn spec(&self) -> &CommandSpec {
        &self.0.spec
    }
    /// Current lifecycle state.
    pub const fn status(&self) -> Status {
        self.0.status
    }
    /// Current version; only actual transitions increase it.
    pub const fn version(&self) -> i64 {
        self.0.version
    }
    /// Snapshot for a provider's checked persistence path.
    pub fn record(&self) -> &Record {
        &self.0
    }
    /// Scope and coordinate checks precede all device observations, including duplicates.
    pub fn report(
        &mut self,
        input: &DeviceReport,
        current: Coordinate,
        now: i64,
    ) -> Result<Outcome, Error> {
        if input.scope != self.spec().scope()
            || input.command_id != *self.spec().id()
            || input.coordinate != self.spec().coordinate()
        {
            return Err(Error::Fenced);
        }
        let event = match input.event {
            DeviceEvent::Received => Event::Received,
            DeviceEvent::Rejected => Event::Rejected,
            DeviceEvent::Reported(d) => Event::Reported(d),
        };
        self.transition(event, current, now)
    }
    /// Apply one trusted provider/control fact. Invalid/no-op inputs retain the exact snapshot.
    pub fn transition(
        &mut self,
        event: Event,
        current: Coordinate,
        now: i64,
    ) -> Result<Outcome, Error> {
        let authorized = if event == Event::Supersede {
            current.supersedes(self.spec().coordinate())
        } else {
            current == self.spec().coordinate()
        };
        if !authorized {
            return Err(Error::Fenced);
        }
        if let Event::Reported(digest) = event
            && digest != self.spec().expected()
        {
            return Err(Error::Conflict);
        }
        let next = decision(self.status(), event, now >= self.spec().deadline());
        let status = match next {
            Ok(status) => status,
            Err(outcome) => return Ok(outcome),
        };
        let mut record = self.0.clone();
        record.version = record
            .version
            .checked_add(1)
            .ok_or(Error::VersionOverflow)?;
        record.status = status;
        match status {
            Status::Published => record.published_at = Some(now),
            Status::Received => record.received_at = Some(now),
            _ => record.terminal_at = Some(now),
        }
        *self = Self::restore(record)?;
        Ok(Outcome::Advanced)
    }
}
fn decision(status: Status, event: Event, expired: bool) -> Result<Status, Outcome> {
    use {Event as E, Status as S};
    if status.is_terminal() {
        return Err(
            if matches!(
                (status, event),
                (S::Applied, E::Reported(_))
                    | (S::Rejected, E::Rejected)
                    | (S::TimedOut, E::Expire)
                    | (S::Cancelled, E::Cancel)
                    | (S::Superseded, E::Supersede)
            ) {
                Outcome::Duplicate
            } else {
                Outcome::Late
            },
        );
    }
    match event {
        E::Cancel => return Ok(S::Cancelled),
        E::Supersede => return Ok(S::Superseded),
        E::Rejected => {
            return if matches!(status, S::Published | S::Received) {
                Ok(S::Rejected)
            } else {
                Err(Outcome::OutOfOrder)
            };
        }
        _ => {}
    }
    if expired {
        return Ok(S::TimedOut);
    }
    match (status, event) {
        (_, E::Cancel) => Ok(S::Cancelled),
        (_, E::Supersede) => Ok(S::Superseded),
        (_, E::Expire) => Err(Outcome::Duplicate),
        (S::Queued, E::Published) => Ok(S::Published),
        (S::Published, E::Received) => Ok(S::Received),
        (S::Received, E::Reported(_)) => Ok(S::Applied),
        (S::Published | S::Received, E::Rejected) => Ok(S::Rejected),
        (S::Published | S::Received, E::Published) | (S::Received, E::Received) => {
            Err(Outcome::Duplicate)
        }
        _ => Err(Outcome::OutOfOrder),
    }
}
fn validate(r: &Record) -> Result<(), Error> {
    let steps = 1
        + i64::from(r.published_at.is_some())
        + i64::from(r.received_at.is_some())
        + i64::from(r.terminal_at.is_some());
    if r.version != steps || r.queued_at >= r.spec.deadline() {
        return Err(Error::InvalidSnapshot);
    }
    let mut previous = r.queued_at;
    for time in [r.published_at, r.received_at, r.terminal_at]
        .into_iter()
        .flatten()
    {
        if time < previous {
            return Err(Error::InvalidSnapshot);
        }
        previous = time;
    }
    if r.received_at.is_some() && r.published_at.is_none() {
        return Err(Error::InvalidSnapshot);
    }
    let shape = match r.status {
        Status::Queued => {
            r.published_at.is_none() && r.received_at.is_none() && r.terminal_at.is_none()
        }
        Status::Published => {
            r.published_at.is_some() && r.received_at.is_none() && r.terminal_at.is_none()
        }
        Status::Received => {
            r.published_at.is_some() && r.received_at.is_some() && r.terminal_at.is_none()
        }
        Status::Applied => r.received_at.is_some() && r.terminal_at.is_some(),
        Status::Rejected => r.published_at.is_some() && r.terminal_at.is_some(),
        _ => r.terminal_at.is_some(),
    };
    if !shape
        || r.published_at.is_some_and(|t| t >= r.spec.deadline())
        || r.received_at.is_some_and(|t| t >= r.spec.deadline())
    {
        return Err(Error::InvalidSnapshot);
    }
    if let Some(t) = r.terminal_at
        && ((r.status == Status::TimedOut && t < r.spec.deadline())
            || (r.status == Status::Applied && t >= r.spec.deadline()))
    {
        return Err(Error::InvalidSnapshot);
    }
    Ok(())
}
