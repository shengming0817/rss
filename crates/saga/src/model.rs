//! One replay algorithm for live execution and restart.
use crate::{Definition, Error, ProtectedReceipt};
use rss_request_context::TenantId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// Tenant-scoped instance identity. These values are not authentication evidence.
pub struct Scope {
    tenant: TenantId,
    id: uuid::Uuid,
}
impl Scope {
    /// Bind a caller-authorized tenant and caller-selected instance UUID.
    pub const fn new(tenant: TenantId, id: uuid::Uuid) -> Self {
        Self { tenant, id }
    }
    /// Tenant used for every storage query and receipt/effect identity.
    pub const fn tenant(self) -> TenantId {
        self.tenant
    }
    /// Instance UUID, interpreted only together with its tenant.
    pub const fn id(self) -> uuid::Uuid {
        self.id
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
/// Closed external effect phase, included in stable idempotency-key derivation.
pub enum Phase {
    /// Original step effect.
    Forward,
    /// Reverse effect for an already applied step.
    Compensation,
}
impl Phase {
    /// Stable v1 domain-separation label for this effect phase.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Forward => "forward",
            Self::Compensation => "compensation",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
/// Durable instance status. Compensation failure is paused rather than terminal.
pub enum Status {
    /// No current intent; the next forward step can be admitted.
    Ready,
    /// Forward progress or an unresolved forward intent.
    Running,
    /// Reverse compensation is pending or in progress.
    Compensating,
    /// Compensation is paused until an explicit revision-checked resume.
    CompensationFailed,
    /// All forward effects and protected receipts are committed.
    Succeeded,
    /// Every applied forward effect has been compensated.
    Compensated,
}
impl Status {
    /// True only after complete success or complete compensation.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Compensated)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
/// Closed journal transitions shared by live execution and recovery.
pub enum EventKind {
    /// Durable authority to attempt a forward effect.
    ForwardIntent,
    /// Forward receipt and completion committed atomically.
    ForwardApplied,
    /// A direct effect invocation proved absent; charge one proven failure.
    ForwardNotApplied,
    /// Recovery proved an unfinished effect absent; retain attempt history without charging a failure.
    ForwardProbeNotApplied,
    /// Pinned forward failure limit exhausted; start reverse compensation.
    Abort,
    /// Durable authority for the next reverse effect.
    CompensationIntent,
    /// The compensation was confirmed applied.
    CompensationApplied,
    /// Recovery proved a compensation absent and permits a fresh intent.
    CompensationNotApplied,
    /// Direct compensation failed definitively; pause for explicit recovery.
    CompensationFailed,
    /// Revision-checked authorization for one more paused compensation attempt.
    Resume,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
/// Untrusted journal read data; Snapshot validates ordering, transitions and receipt pairing.
pub struct Event {
    /// Consecutive zero-based journal sequence and expected revision.
    pub seq: u64,
    /// Index in the pinned ordered definition.
    pub step: usize,
    /// Monotonic phase-specific attempt number, never reset by recovery.
    pub attempt: u32,
    /// Closed transition to validate against the current replay state.
    pub kind: EventKind,
    /// Present only for a paired forward completion; contains no plaintext.
    pub receipt: Option<ProtectedReceipt>,
}
#[derive(Debug, Clone)]
/// Validated aggregate replay of a single instance definition and journal.
pub struct Snapshot {
    definition: Definition,
    events: Vec<Event>,
    progress: Progress,
}
#[derive(Debug, Clone)]
pub(crate) struct Progress {
    pub status: Status,
    pub forward: usize,
    pub completed: Vec<(usize, ProtectedReceipt)>,
    pub pending: Option<Event>,
    pub forward_attempts: Vec<u32>,
    pub forward_failures: Vec<u32>,
    pub compensation_attempts: Vec<u32>,
}
impl Snapshot {
    /// Construct the empty state for an already validated registered definition.
    pub fn empty(definition: Definition) -> Self {
        let len = definition.steps().len();
        Self {
            definition,
            events: Vec::new(),
            progress: Progress {
                status: Status::Ready,
                forward: 0,
                completed: Vec::new(),
                pending: None,
                forward_attempts: vec![0; len],
                forward_failures: vec![0; len],
                compensation_attempts: vec![0; len],
            },
        }
    }
    /// Validate stored definition fingerprint and replay every event in exact sequence order.
    pub fn from_events(definition: Definition, events: Vec<Event>) -> Result<Self, Error> {
        definition.validate()?;
        let mut snapshot = Self::empty(definition);
        for event in events {
            snapshot.append(event)?;
        }
        Ok(snapshot)
    }
    /// Pinned definition used to validate this snapshot.
    pub fn definition(&self) -> &Definition {
        &self.definition
    }
    /// Validated committed journal prefix; protected receipts remain opaque.
    pub fn events(&self) -> &[Event] {
        &self.events
    }
    /// Next journal sequence number and expected mutation CAS revision.
    pub fn revision(&self) -> u64 {
        self.events.len() as u64
    }
    /// Status derived from the complete validated journal prefix.
    pub fn status(&self) -> Status {
        self.progress.status
    }
    pub(crate) fn progress(&self) -> &Progress {
        &self.progress
    }
    /// Shared transition validation for adapters and the executor. Storage input is never trusted.
    pub fn apply(&self, event: Event) -> Result<Self, Error> {
        let mut next = self.clone();
        next.append(event)?;
        Ok(next)
    }
    fn append(&mut self, event: Event) -> Result<(), Error> {
        let revision = self.revision();
        let status = self.status();
        let p = &mut self.progress;
        if event.seq != revision
            || event.step >= self.definition.steps().len()
            || status.is_terminal()
        {
            return Err(Error::new(crate::ErrorKind::Integrity));
        }
        if (event.kind == EventKind::ForwardApplied) != event.receipt.is_some() {
            return Err(Error::new(crate::ErrorKind::Integrity));
        }
        let pending_matches = |phase| {
            p.pending.as_ref().is_some_and(|e| {
                e.step == event.step && e.attempt == event.attempt && e.kind == phase
            })
        };
        match event.kind {
            EventKind::ForwardIntent => {
                if !matches!(p.status, Status::Ready | Status::Running)
                    || p.pending.is_some()
                    || event.step != p.forward
                    || Some(event.attempt) != p.forward_attempts[event.step].checked_add(1)
                {
                    return Err(Error::new(crate::ErrorKind::Integrity));
                }
                p.forward_attempts[event.step] = event.attempt;
                p.pending = Some(event.clone());
                p.status = Status::Running;
            }
            EventKind::ForwardApplied => {
                if !pending_matches(EventKind::ForwardIntent) {
                    return Err(Error::new(crate::ErrorKind::Integrity));
                }
                let receipt = event
                    .receipt
                    .clone()
                    .ok_or(Error::new(crate::ErrorKind::Integrity))?;
                if receipt.attempt() != event.attempt || receipt.completed_seq() != event.seq {
                    return Err(Error::new(crate::ErrorKind::Integrity));
                }
                p.completed.push((event.step, receipt));
                p.forward += 1;
                p.pending = None;
                p.status = if p.forward == self.definition.steps().len() {
                    Status::Succeeded
                } else {
                    Status::Running
                };
            }
            EventKind::ForwardNotApplied | EventKind::ForwardProbeNotApplied => {
                if !pending_matches(EventKind::ForwardIntent) {
                    return Err(Error::new(crate::ErrorKind::Integrity));
                }
                p.pending = None;
                if event.kind == EventKind::ForwardNotApplied {
                    p.forward_failures[event.step] = p.forward_failures[event.step]
                        .checked_add(1)
                        .ok_or(Error::new(crate::ErrorKind::Integrity))?;
                }
                p.status = Status::Ready;
            }
            EventKind::Abort => {
                if p.status != Status::Ready
                    || p.pending.is_some()
                    || event.step != p.forward
                    || event.attempt != p.forward_attempts[event.step]
                    || event.attempt == 0
                {
                    return Err(Error::new(crate::ErrorKind::Integrity));
                }
                p.status = if p.completed.is_empty() {
                    Status::Compensated
                } else {
                    Status::Compensating
                };
            }
            EventKind::CompensationIntent => {
                if p.status != Status::Compensating
                    || p.pending.is_some()
                    || p.completed.last().map(|(i, _)| *i) != Some(event.step)
                    || Some(event.attempt) != p.compensation_attempts[event.step].checked_add(1)
                {
                    return Err(Error::new(crate::ErrorKind::Integrity));
                }
                p.compensation_attempts[event.step] = event.attempt;
                p.pending = Some(event.clone());
            }
            EventKind::CompensationApplied
            | EventKind::CompensationNotApplied
            | EventKind::CompensationFailed => {
                if !pending_matches(EventKind::CompensationIntent) {
                    return Err(Error::new(crate::ErrorKind::Integrity));
                }
                p.pending = None;
                if event.kind == EventKind::CompensationApplied {
                    p.completed.pop();
                    p.status = if p.completed.is_empty() {
                        Status::Compensated
                    } else {
                        Status::Compensating
                    };
                } else if event.kind == EventKind::CompensationNotApplied {
                    p.status = Status::Compensating;
                } else {
                    p.status = Status::CompensationFailed;
                }
            }
            EventKind::Resume => {
                if p.status != Status::CompensationFailed
                    || p.pending.is_some()
                    || p.completed.last().map(|(i, _)| *i) != Some(event.step)
                    || event.attempt != p.compensation_attempts[event.step]
                {
                    return Err(Error::new(crate::ErrorKind::Integrity));
                }
                p.status = Status::Compensating;
            }
        }
        self.events.push(event);
        Ok(())
    }
}
