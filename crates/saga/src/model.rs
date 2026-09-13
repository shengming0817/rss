//! One replay algorithm for live execution and restart.
use crate::{
    Definition, Error, ErrorKind, HistoryCapacity, HistoryHead, ProtectedReceipt, ReadBudget,
};
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
impl EventKind {
    /// Stable effect phase associated with the closed transition.
    pub const fn phase(self) -> Phase {
        match self {
            Self::ForwardIntent
            | Self::ForwardApplied
            | Self::ForwardNotApplied
            | Self::ForwardProbeNotApplied
            | Self::Abort => Phase::Forward,
            _ => Phase::Compensation,
        }
    }
}
impl Event {
    /// Conservative complete V1 event charge, independent of database tuple/TOAST storage.
    pub fn encoded_bytes(&self) -> Result<u64, Error> {
        Ok(crate::EVENT_BYTES
            + self
                .receipt
                .as_ref()
                .map_or(Ok(0), ProtectedReceipt::encoded_bytes)?)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Intent {
    pub step: usize,
    pub attempt: u32,
    pub kind: EventKind,
}
impl Intent {
    pub(crate) fn event(self, seq: u64) -> Event {
        Event {
            seq,
            step: self.step,
            attempt: self.attempt,
            kind: self.kind,
            receipt: None,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Fixed-size current projection. Storage data is checked against complete bounded replay.
pub(crate) struct Progress {
    pub(crate) status: Status,
    pub(crate) forward: usize,
    pub(crate) forward_attempt: u32,
    pub(crate) forward_failures: u32,
    pub(crate) compensation: Option<usize>,
    pub(crate) compensation_attempt: u32,
    pub(crate) pending: Option<Intent>,
    pub(crate) last_kind: Option<EventKind>,
}
impl Progress {
    /// Acknowledged business state; capacity exhaustion does not replace it.
    pub(crate) const fn status(&self) -> Status {
        self.status
    }
    pub(crate) fn empty() -> Self {
        Self {
            status: Status::Ready,
            forward: 0,
            forward_attempt: 0,
            forward_failures: 0,
            compensation: None,
            compensation_attempt: 0,
            pending: None,
            last_kind: None,
        }
    }
    pub(crate) fn reserve(&self) -> Result<(u64, u64), Error> {
        if self.forward > 1024
            || self.compensation.is_some_and(|c| c >= 1024)
            || self.pending.is_some_and(|p| {
                p.step >= 1024
                    || !matches!(
                        p.kind,
                        EventKind::ForwardIntent | EventKind::CompensationIntent
                    )
            })
        {
            return Err(ErrorKind::Integrity.into());
        }
        if self.status.is_terminal() {
            return Ok((0, 0));
        }
        let (entries, receipt) = if matches!(self.status, Status::Ready | Status::Running) {
            let pending = self.pending.is_some();
            (
                2 * self.forward as u64 + 1 + if pending { 3 } else { 0 },
                pending,
            )
        } else {
            let earlier = self.compensation.unwrap_or(0) as u64;
            let current = if self.pending.is_some() {
                1
            } else if self.compensation_attempt == 0 || self.last_kind == Some(EventKind::Resume) {
                2
            } else {
                0
            };
            (2 * earlier + current, false)
        };
        Ok((
            entries,
            entries * crate::EVENT_BYTES + if receipt { crate::RECEIPT_BYTES } else { 0 },
        ))
    }
    fn transition(&self, definition: &Definition, event: &Event) -> Result<Self, Error> {
        let mut p = *self;
        let invalid = || Error::new(ErrorKind::Integrity);
        if p.status.is_terminal()
            || event.step >= definition.steps().len()
            || event.attempt == 0
            || (event.kind == EventKind::ForwardApplied) != event.receipt.is_some()
        {
            return Err(invalid());
        }
        let matches = |kind| {
            self.pending
                == Some(Intent {
                    kind,
                    step: event.step,
                    attempt: event.attempt,
                })
        };
        match event.kind {
            EventKind::ForwardIntent => {
                if !matches!(p.status, Status::Ready | Status::Running)
                    || p.pending.is_some()
                    || event.step != p.forward
                    || Some(event.attempt) != p.forward_attempt.checked_add(1)
                    || p.forward_failures >= definition.steps()[event.step].max_failures()
                {
                    return Err(invalid());
                }
                p.forward_attempt = event.attempt;
                p.pending = Some(Intent {
                    step: event.step,
                    attempt: event.attempt,
                    kind: event.kind,
                });
                p.status = Status::Running;
            }
            EventKind::ForwardApplied => {
                if !matches(EventKind::ForwardIntent) {
                    return Err(invalid());
                }
                let receipt = event.receipt.as_ref().ok_or_else(invalid)?;
                if receipt.attempt() != event.attempt || receipt.completed_seq() != event.seq {
                    return Err(invalid());
                }
                p.forward += 1;
                p.forward_attempt = 0;
                p.forward_failures = 0;
                p.pending = None;
                p.status = if p.forward == definition.steps().len() {
                    Status::Succeeded
                } else {
                    Status::Running
                };
            }
            EventKind::ForwardNotApplied | EventKind::ForwardProbeNotApplied => {
                if !matches(EventKind::ForwardIntent) {
                    return Err(invalid());
                }
                p.pending = None;
                if event.kind == EventKind::ForwardNotApplied {
                    p.forward_failures = p.forward_failures.checked_add(1).ok_or_else(invalid)?;
                }
                p.status = Status::Ready;
            }
            EventKind::Abort => {
                if p.status != Status::Ready
                    || p.pending.is_some()
                    || event.step != p.forward
                    || event.attempt != p.forward_attempt
                    || p.forward_failures < definition.steps()[event.step].max_failures()
                    || p.last_kind != Some(EventKind::ForwardNotApplied)
                {
                    return Err(invalid());
                }
                p.compensation = p.forward.checked_sub(1);
                p.compensation_attempt = 0;
                p.status = if p.compensation.is_none() {
                    Status::Compensated
                } else {
                    Status::Compensating
                };
            }
            EventKind::CompensationIntent => {
                if p.status != Status::Compensating
                    || p.pending.is_some()
                    || p.compensation != Some(event.step)
                    || Some(event.attempt) != p.compensation_attempt.checked_add(1)
                {
                    return Err(invalid());
                }
                p.compensation_attempt = event.attempt;
                p.pending = Some(Intent {
                    step: event.step,
                    attempt: event.attempt,
                    kind: event.kind,
                });
            }
            EventKind::CompensationApplied
            | EventKind::CompensationNotApplied
            | EventKind::CompensationFailed => {
                if p.status != Status::Compensating || !matches(EventKind::CompensationIntent) {
                    return Err(invalid());
                }
                p.pending = None;
                if event.kind == EventKind::CompensationApplied {
                    p.compensation = event.step.checked_sub(1);
                    p.compensation_attempt = 0;
                    p.status = if p.compensation.is_none() {
                        Status::Compensated
                    } else {
                        Status::Compensating
                    };
                } else if event.kind == EventKind::CompensationFailed {
                    p.status = Status::CompensationFailed;
                }
            }
            EventKind::Resume => {
                if p.status != Status::CompensationFailed
                    || p.pending.is_some()
                    || p.compensation != Some(event.step)
                    || event.attempt != p.compensation_attempt
                {
                    return Err(invalid());
                }
                p.status = Status::Compensating;
            }
        }
        p.last_kind = Some(event.kind);
        Ok(p)
    }
}
#[derive(Debug, Clone)]
/// Complete bounded validated history; transitions copy only a fixed-size progress value.
pub struct Snapshot {
    definition: Definition,
    events: Vec<Event>,
    receipt_sequences: Vec<usize>,
    head: HistoryHead,
    read: ReadBudget,
}
impl Snapshot {
    /// Start bounded replay or a fresh registered instance; no unbounded construction exists.
    pub fn empty(
        definition: Definition,
        capacity: HistoryCapacity,
        read: ReadBudget,
    ) -> Result<Self, Error> {
        definition.validate()?;
        Ok(Self {
            definition,
            events: Vec::new(),
            receipt_sequences: Vec::new(),
            head: HistoryHead {
                revision: 0,
                encoded_bytes: 0,
                capacity,
                progress: Progress::empty(),
            },
            read,
        })
    }
    /// Replay one already persisted event. Historical admission is not reinterpreted under today's capacity.
    pub fn replay(&mut self, event: Event) -> Result<(), Error> {
        let after = self.prepare(&event, false)?;
        self.accept(event, after);
        Ok(())
    }
    /// Validate one new transition including its settlement reservation, without copying history.
    pub fn apply(&mut self, event: Event) -> Result<(), Error> {
        let after = self.prepare(&event, true)?;
        self.accept(event, after);
        Ok(())
    }
    /// Pinned immutable definition.
    pub fn definition(&self) -> &Definition {
        &self.definition
    }
    /// One owned journal prefix, including one copy of each protected receipt.
    pub fn events(&self) -> &[Event] {
        &self.events
    }
    /// Expected journal CAS revision.
    pub const fn revision(&self) -> u64 {
        self.head.revision
    }
    /// Acknowledged business status.
    pub const fn status(&self) -> Status {
        self.head.progress.status
    }
    /// Validated small metadata, independently comparable with the provider projection.
    pub const fn head(&self) -> &HistoryHead {
        &self.head
    }
    /// Resolve a completed forward receipt using its replay-built sequence reference.
    pub fn receipt(&self, step: usize) -> Result<&Event, Error> {
        self.receipt_sequences
            .get(step)
            .and_then(|seq| self.events.get(*seq))
            .ok_or(ErrorKind::ReceiptUnavailable.into())
    }
    /// Apply an acknowledged metadata-only capacity increase to a trusted provider's test/store state.
    pub fn extend_capacity(
        &mut self,
        expected: HistoryCapacity,
        next: HistoryCapacity,
    ) -> Result<(), Error> {
        if self.head.capacity != expected || !next.extends(expected) {
            return Err(ErrorKind::Conflict.into());
        }
        self.head.capacity = next;
        Ok(())
    }
    /// Rebind a caller's read budget after provider replay; validates actual retained history.
    pub fn with_read_budget(mut self, read: ReadBudget) -> Result<Self, Error> {
        self.head.check_read(read)?;
        self.read = read;
        Ok(self)
    }
    pub(crate) fn progress(&self) -> &Progress {
        &self.head.progress
    }
    pub(crate) fn prepare(&self, event: &Event, admission: bool) -> Result<HistoryHead, Error> {
        if event.seq != self.revision() {
            return Err(if admission {
                ErrorKind::Conflict
            } else {
                ErrorKind::Integrity
            }
            .into());
        }
        let progress = self.head.progress.transition(&self.definition, event)?;
        let after = HistoryHead {
            revision: self
                .revision()
                .checked_add(1)
                .ok_or(ErrorKind::HistoryLimited)?,
            encoded_bytes: self
                .head
                .encoded_bytes
                .checked_add(event.encoded_bytes()?)
                .ok_or(ErrorKind::HistoryLimited)?,
            capacity: self.head.capacity,
            progress,
        };
        if admission {
            after.check_admission(self.read)?;
        } else {
            after.check_read(self.read)?;
        }
        Ok(after)
    }
    pub(crate) fn accept(&mut self, event: Event, head: HistoryHead) {
        if event.kind == EventKind::ForwardApplied {
            self.receipt_sequences.push(self.events.len());
        }
        self.events.push(event);
        self.head = head;
    }
}
