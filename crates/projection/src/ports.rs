use crate::{
    ApplyOutcome, BatchLimit, Checkpoint, Control, DefinitionIdentity, Error, ErrorKind, Event,
    Position, ProjectionScope, SourceScope, Timer,
};
use std::future::Future;

/// Append-only committed prefix. Implementations must not expose a higher position before
/// a lower position can still commit, and must never change a fact at an existing position.
/// Each operation owns enforcement of the supplied Control, including all waiting and decoding.
/// The runner does not wrap providers in another cancellation race.
pub trait Source: Send + Sync {
    /// Page-owned input carrying the stable event identity used by the runner.
    type Item: AsRef<Event> + Send + Sync;
    /// Exact scoped committed high-water; None means empty.
    fn high_water<T: Timer>(
        &self,
        scope: &SourceScope,
        control: &Control<'_, T>,
    ) -> impl Future<Output = Result<Option<Position>, Error>> + Send;
    /// Read strictly increasing positions after the cursor, at most limit records.
    /// Return HistoryExpired if the retained suffix cannot cover this cursor, even on an empty page.
    fn read<T: Timer>(
        &self,
        scope: &SourceScope,
        after: Option<Position>,
        limit: BatchLimit,
        control: &Control<'_, T>,
    ) -> impl Future<Output = Result<Vec<Self::Item>, Error>> + Send;
}
/// Execution session bound by a provider to write authority for a single generation.
/// A PostgreSQL implementation settles effect, receipt and checkpoint in one transaction.
/// Implementations enforce Control through settlement and classify interruption themselves.
/// Preserve confirmed progress; uncertain writes require CommitUnknown or RollbackFailed.
pub trait Execution: Send + Sync {
    /// Input accepted by this execution session.
    type Item: AsRef<Event> + Send + Sync;
    /// Immutable session scope.
    fn scope(&self) -> &ProjectionScope;
    /// Definition bound to this session. Providers must verify it before granting authority
    /// and on progress reads and writes, rejecting mismatches before any effect.
    fn definition_identity(&self) -> &DefinitionIdentity;
    /// Read progress while validating that this session still owns its epoch.
    fn checkpoint<T: Timer>(
        &self,
        control: &Control<'_, T>,
    ) -> impl Future<Output = Result<Checkpoint, Error>> + Send;
    /// Settle one event under expected progress. The implementation must fence before effects.
    fn execute<T: Timer>(
        &self,
        expected: Option<Position>,
        event: &Self::Item,
        control: &Control<'_, T>,
    ) -> impl Future<Output = Result<ApplyOutcome, Error>> + Send;
}
/// A session capable of settling a nonempty ordered page atomically. Only an
/// acknowledged commit returns one outcome per input, in the input order.
pub trait BatchExecution: Execution {
    /// Own the page through settlement. Validate the bound, source and expected
    /// cursor before effects; a failed page exposes no acknowledged prefix.
    fn execute_batch<T: Timer>(
        &self,
        expected: Option<Position>,
        events: Vec<Self::Item>,
        control: &Control<'_, T>,
    ) -> impl Future<Output = Result<Vec<ApplyOutcome>, Error>> + Send;
}
/// Checkpoint half of an explicitly at-least-once external projection.
/// Each operation enforces the original Control and owns its settlement classification.
pub trait ExternalCheckpoint: Send + Sync {
    /// Bound identity and generation.
    fn scope(&self) -> &ProjectionScope;
    /// Definition bound to this session. Providers must verify it before granting authority
    /// and on progress reads and writes, rejecting mismatches before any effect.
    fn definition_identity(&self) -> &DefinitionIdentity;
    /// Read and validate the current epoch.
    fn load<T: Timer>(
        &self,
        control: &Control<'_, T>,
    ) -> impl Future<Output = Result<Checkpoint, Error>> + Send;
    /// CAS advance after an externally acknowledged effect, validating the same epoch.
    fn advance<T: Timer>(
        &self,
        expected: Option<Position>,
        event: &Event,
        control: &Control<'_, T>,
    ) -> impl Future<Output = Result<(), Error>> + Send;
}
/// Cross-system effect. Implementers must deduplicate by scope/event identity and reject
/// changed payloads. Bind the definition immutably to the generation, rejecting changes;
/// do not add definition bytes to the deduplication key to admit another effect.
/// Remote fencing/conditional writes are the application's responsibility:
/// local checkpoint ownership cannot undo or fence an in-flight remote write.
/// The target enforces Control itself. Cancelled/Deadline require evidence of no effect;
/// an unconfirmed effect or rollback must return CommitUnknown or RollbackFailed.
pub trait ExternalTarget: Send + Sync {
    /// Apply idempotently; retries may occur after cancellation or checkpoint failure.
    fn apply<T: Timer>(
        &self,
        scope: &ProjectionScope,
        definition: &DefinitionIdentity,
        event: &Event,
        control: &Control<'_, T>,
    ) -> impl Future<Output = Result<ApplyOutcome, Error>> + Send;
}
/// Explicit at-least-once composition; never claims a distributed transaction.
pub struct AtLeastOnce<C, H> {
    checkpoint: C,
    target: H,
}
impl<C, H> AtLeastOnce<C, H> {
    /// Bind checkpoint authority and the caller's idempotent target.
    pub const fn new(checkpoint: C, target: H) -> Self {
        Self { checkpoint, target }
    }
}
impl<C: ExternalCheckpoint, H: ExternalTarget> Execution for AtLeastOnce<C, H> {
    type Item = Event;
    fn scope(&self) -> &ProjectionScope {
        self.checkpoint.scope()
    }
    fn definition_identity(&self) -> &DefinitionIdentity {
        self.checkpoint.definition_identity()
    }
    async fn checkpoint<T: Timer>(&self, control: &Control<'_, T>) -> Result<Checkpoint, Error> {
        control.check()?;
        self.checkpoint.load(control).await
    }
    async fn execute<T: Timer>(
        &self,
        expected: Option<Position>,
        event: &Event,
        control: &Control<'_, T>,
    ) -> Result<ApplyOutcome, Error> {
        control.check()?;
        if event.source() != self.scope().source() {
            return Err(Error::new(ErrorKind::ScopeMismatch));
        }
        let current = self.checkpoint.load(control).await?;
        if current.position != expected {
            return Err(Error::new(ErrorKind::Fenced));
        }
        crate::validate_next(current, event)?;
        control.check()?;
        let outcome = self
            .target
            .apply(self.scope(), self.definition_identity(), event, control)
            .await?;
        // A confirmed remote effect cannot be undone by a local interruption.
        control.check().map_err(Error::uncertain)?;
        self.checkpoint
            .advance(expected, event, control)
            .await
            .map_err(Error::uncertain)?;
        Ok(outcome)
    }
}
