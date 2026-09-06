use crate::{
    Batch, Decision, Error, ErrorKind, Id, LifecycleGrant, Policy, ReadGrant, Scope, State,
    VerifiedBatch,
};
use rss_request_context::Deadline;
use std::{future::Future, time::Instant};
/// Host-injected monotonic time source; the adapter never invents a new operation budget.
pub trait Clock: Send + Sync {
    /// Monotonic time in the same Instant domain as every supplied Deadline.
    fn now(&self) -> Instant;
}
/// Immutable durable batch and receipt. Construction is an explicit trusted provider boundary.
#[derive(Clone, Debug)]
pub struct Record {
    scope: Scope,
    batch: Batch,
    received_at: u64,
    policy: Policy,
    decision: Decision,
}
impl Record {
    /// Restore only after a commit ACK or a complete durable read. This verifies semantics,
    /// not the truthfulness of an arbitrary provider's durability assertion.
    pub fn from_durable(
        scope: Scope,
        batch: Batch,
        received_at: u64,
        policy: Policy,
        decision: Decision,
    ) -> Result<Self, Error> {
        if decision.before().advance(&batch, received_at, &policy)? != decision {
            return Err(ErrorKind::Invariant.into());
        }
        Ok(Self {
            scope,
            batch,
            received_at,
            policy,
            decision,
        })
    }
    /// Exact stream to which this immutable receipt belongs.
    pub const fn scope(&self) -> &Scope {
        &self.scope
    }
    /// Complete unredacted report, sufficient to replay its semantic input.
    pub const fn batch(&self) -> &Batch {
        &self.batch
    }
    /// Authoritative provider receipt time in nonnegative Unix seconds, unchanged on replay.
    pub const fn received_at(&self) -> u64 {
        self.received_at
    }
    /// Lifecycle policy captured with this record, not the current configuration.
    pub const fn policy(&self) -> &Policy {
        &self.policy
    }
    /// Immutable historical sync result; it does not claim Inventory or projection completion.
    pub const fn decision(&self) -> &Decision {
        &self.decision
    }
}
#[derive(Debug)]
/// Durable admission result; neither variant represents downstream projection completion.
pub enum ReceiveOutcome {
    /// This invocation obtained confirmation of the first durable insertion.
    Accepted(Record),
    /// An identical immutable batch already exists; its original receipt and time are returned.
    Replay(Record),
}
impl ReceiveOutcome {
    /// The original durable record for either first acceptance or exact replay.
    pub const fn record(&self) -> &Record {
        match self {
            Self::Accepted(r) | Self::Replay(r) => r,
        }
    }
}
/// Capability-owned atomic persistence port. All mutating outcomes require settlement evidence.
/// There is no public raw CRUD or caller-controlled transition write operation.
pub trait ObservationStore: Send + Sync {
    /// Atomically activate an authorized registration/epoch under expected object lifecycle revision.
    /// None permits only first activation; exact activation replay returns its original revision.
    /// Retired identity reuse or revision mismatch is LifecycleConflict. Budget/settlement rules
    /// apply to all provider stages, including uncertain-commit readback.
    fn activate(
        &self,
        grant: &LifecycleGrant,
        expected_revision: Option<u64>,
        policy: &Policy,
        deadline: Deadline,
    ) -> impl Future<Output = Result<u64, Error>> + Send;
    /// Commit complete report, receipt, sync result and any cursor update in one transaction.
    /// Resolve exact replay before active-epoch checks, without changing the old receipt or TTL.
    /// Changed facts conflict; new reports in retired streams fail. Never return success on
    /// unconfirmed commit unless exact durable readback verifies the complete record.
    fn receive(
        &self,
        batch: &VerifiedBatch,
        deadline: Deadline,
    ) -> impl Future<Output = Result<ReceiveOutcome, Error>> + Send;
    /// Read the original record under exact scope/batch identity, including retired epochs.
    /// None means no visible durable record was found; it is not proof that an unknown attempt
    /// rolled back. The same absolute deadline covers all provider work.
    fn lookup(
        &self,
        grant: &ReadGrant,
        id: &Id,
        deadline: Deadline,
    ) -> impl Future<Output = Result<Option<Record>, Error>> + Send;
    /// Read historical stream state; return UnknownStream when no activation exists.
    fn state(
        &self,
        grant: &ReadGrant,
        deadline: Deadline,
    ) -> impl Future<Output = Result<State, Error>> + Send;
}
