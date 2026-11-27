//! Capability-owned transaction port; providers own commit and resource cleanup.
use crate::{ClaimId, Delivery, DirectClaim};
use crate::{Command, CommandId, CommandSpec, Coordinate, DeviceReport, Outcome, Scope};

const MAX_BATCH_SIZE: u16 = 1024;

/// At most 1024 records per page; time is bounded by the enclosing transaction.
#[derive(Debug, Clone, Copy)]
pub struct BatchLimit(u16);
impl BatchLimit {
    /// Reject zero or unbounded work.
    pub fn new(value: u16) -> Result<Self, crate::Error> {
        if value == 0 || value > MAX_BATCH_SIZE {
            return Err(crate::Error::InvalidValue);
        }
        Ok(Self(value))
    }
    /// Maximum records examined, including no-ops.
    pub const fn get(self) -> u16 {
        self.0
    }
}
impl Default for BatchLimit {
    fn default() -> Self {
        Self(64)
    }
}
/// A caller-selected page of at most 1024 distinct command identities, in request order.
#[derive(Debug, Clone, Copy)]
pub struct ExactCommandIds<'a>(&'a [CommandId]);
impl<'a> ExactCommandIds<'a> {
    /// Accept empty pages and reject oversized pages or repeated identities.
    pub fn new(ids: &'a [CommandId]) -> Result<Self, crate::Error> {
        if ids.len() > usize::from(MAX_BATCH_SIZE) {
            return Err(crate::Error::InvalidValue);
        }
        let mut seen = std::collections::HashSet::with_capacity(ids.len());
        if !ids.iter().all(|id| seen.insert(id)) {
            return Err(crate::Error::InvalidValue);
        }
        Ok(Self(ids))
    }
    /// Borrow all validated identities in their original order.
    pub const fn as_slice(self) -> &'a [CommandId] {
        self.0
    }
}
/// Staged recovery output. `after` is valid only after the enclosing commit is acknowledged.
#[derive(Debug)]
#[must_use = "commit the page before advancing its recovery cursor"]
pub struct RecoveryPage {
    /// Commands examined with their resulting state.
    pub commands: Vec<Command>,
    /// Last examined identity; pass into the next page, then restart from None for another sweep.
    pub after: Option<CommandId>,
}
/// Exact command mutation result; an outer transaction must still commit.
/// ```compile_fail
/// #![deny(unused_must_use)]
/// fn ignore(value: Result<rss_device_command::Transition, ()>) -> Result<(), ()> {
///     value?;
///     Ok(())
/// }
/// ```
#[derive(Debug)]
#[must_use = "inspect OutOfOrder before settling ingress"]
pub struct Transition {
    /// Result classification; OutOfOrder must not terminally settle ingress.
    pub outcome: Outcome,
    /// Resulting durable candidate.
    pub command: Command,
}
/// Narrow borrowed-transaction operations. No method commits or starts another transaction.
///
/// Providers must roll back the whole transaction on error, interruption, or OutOfOrder ingress
/// redelivery; never turn a staged return value into transport ACK authority. The transaction
/// owner supplies a single deadline and quarantines unconfirmed settlement.
pub trait Store: Send + Sync {
    /// Provider-owned transaction, shared with Inbox/Outbox operations.
    type Transaction<'a>: Send;
    /// Provider failure; retain uncertainty in the enclosing transaction result.
    type Error: Send;
    /// Install an exact initial authority, or replay the same initialization.
    fn initialize(
        &self,
        tx: &mut Self::Transaction<'_>,
        scope: Scope,
        coordinate: Coordinate,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
    /// Replace authority and supersede all its active commands atomically.
    fn advance(
        &self,
        tx: &mut Self::Transaction<'_>,
        scope: Scope,
        expected: Coordinate,
        next: Coordinate,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
    /// Persist immutable intent, appending the dispatch only for Outbox delivery.
    fn queue(
        &self,
        tx: &mut Self::Transaction<'_>,
        spec: CommandSpec,
        delivery: Delivery,
    ) -> impl Future<Output = Result<Command, Self::Error>> + Send;
    /// Register or replay an exact direct issuance after checking current eligibility.
    /// Perform this check after all other eligibility-changing writes in the transaction.
    /// After confirmed commit validate the candidate at the protocol response boundary.
    fn claim_direct(
        &self,
        tx: &mut Self::Transaction<'_>,
        scope: Scope,
        id: &CommandId,
        coordinate: Coordinate,
        claim: ClaimId,
    ) -> impl Future<Output = Result<DirectClaim, Self::Error>> + Send;
    /// Read one exact scope/identity; another device must not be treated as the target.
    fn load(
        &self,
        tx: &mut Self::Transaction<'_>,
        scope: Scope,
        id: &CommandId,
    ) -> impl Future<Output = Result<Option<Command>, Self::Error>> + Send;
    /// Apply an exact device report under the stored current authority.
    fn report(
        &self,
        tx: &mut Self::Transaction<'_>,
        report: &DeviceReport,
    ) -> impl Future<Output = Result<Transition, Self::Error>> + Send;
    /// Cancel under an explicit coordinate; never accept stale owner authority.
    fn cancel(
        &self,
        tx: &mut Self::Transaction<'_>,
        scope: Scope,
        id: &CommandId,
        coordinate: Coordinate,
    ) -> impl Future<Output = Result<Transition, Self::Error>> + Send;
    /// Recover expiry/publication from durable state with a bounded stable keyset cursor.
    fn recover(
        &self,
        tx: &mut Self::Transaction<'_>,
        scope: Scope,
        limit: BatchLimit,
        after: Option<&CommandId>,
    ) -> impl Future<Output = Result<RecoveryPage, Self::Error>> + Send;
    /// Recover a caller-selected page in the admitted scope and original transaction.
    ///
    /// The result has one slot per requested ID, in request order. Terminal commands retain
    /// their exact snapshots; an absent tenant-local ID yields None. Another device's ID
    /// rejects the whole page. Runtime, tenant and authority checks also apply to empty pages.
    /// The caller owns candidate selection and advances its checkpoint only after commit.
    fn recover_exact(
        &self,
        tx: &mut Self::Transaction<'_>,
        scope: Scope,
        ids: ExactCommandIds<'_>,
    ) -> impl Future<Output = Result<Vec<Option<Command>>, Self::Error>> + Send;
}
