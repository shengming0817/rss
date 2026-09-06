//! Capability-owned transaction port; providers own commit and resource cleanup.
use crate::{Command, CommandId, CommandSpec, Coordinate, DeviceReport, Outcome, Scope};
use rss_transactional_messaging::outbox::PendingMessage;

/// At most 64 records per recovery page; time is bounded by the enclosing transaction.
#[derive(Debug, Clone, Copy)]
pub struct BatchLimit(u8);
impl BatchLimit {
    /// Reject zero or unbounded work.
    pub fn new(value: u8) -> Result<Self, crate::Error> {
        if value == 0 || value > 64 {
            return Err(crate::Error::InvalidValue);
        }
        Ok(Self(value))
    }
    /// Maximum records examined, including no-ops.
    pub const fn get(self) -> u8 {
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
    /// Queue immutable command facts and exactly one dispatch in the same transaction.
    fn queue(
        &self,
        tx: &mut Self::Transaction<'_>,
        spec: CommandSpec,
        message: PendingMessage<Vec<u8>>,
    ) -> impl Future<Output = Result<Command, Self::Error>> + Send;
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
}
