use crate::{
    ApplyOutcome, BatchLimit, Checkpoint, Control, Error, ErrorKind, Event, Position,
    ProjectionScope, SourceScope, Timer,
};
use std::future::Future;

/// Append-only committed prefix. Implementations must not expose a higher position before
/// a lower position can still commit, and must never change a fact at an existing position.
pub trait Source: Send + Sync {
    /// Exact scoped committed high-water; None means empty.
    fn high_water(
        &self,
        scope: &SourceScope,
    ) -> impl Future<Output = Result<Option<Position>, Error>> + Send;
    /// Read strictly increasing positions after the cursor, at most limit records.
    fn read(
        &self,
        scope: &SourceScope,
        after: Option<Position>,
        limit: BatchLimit,
    ) -> impl Future<Output = Result<Vec<Event>, Error>> + Send;
}
/// Execution session bound by a provider to write authority for a single generation.
/// A PostgreSQL implementation settles effect, receipt and checkpoint in one transaction.
pub trait Execution: Send + Sync {
    /// Immutable session scope.
    fn scope(&self) -> &ProjectionScope;
    /// Read progress while validating that this session still owns its epoch.
    fn checkpoint(&self) -> impl Future<Output = Result<Checkpoint, Error>> + Send;
    /// Settle one event under expected progress. The implementation must fence before effects.
    fn execute<T: Timer>(
        &self,
        expected: Option<Position>,
        event: &Event,
        control: &Control<'_, T>,
    ) -> impl Future<Output = Result<ApplyOutcome, Error>> + Send;
}
/// Checkpoint half of an explicitly at-least-once external projection.
pub trait ExternalCheckpoint: Send + Sync {
    /// Bound identity and generation.
    fn scope(&self) -> &ProjectionScope;
    /// Read and validate the current epoch.
    fn load(&self) -> impl Future<Output = Result<Checkpoint, Error>> + Send;
    /// CAS advance after an externally acknowledged effect, validating the same epoch.
    fn advance<T: Timer>(
        &self,
        expected: Option<Position>,
        event: &Event,
        control: &Control<'_, T>,
    ) -> impl Future<Output = Result<(), Error>> + Send;
}
/// Cross-system effect. Implementers must deduplicate by scope/event identity and reject
/// changed payloads. Remote fencing/conditional writes are the application's responsibility:
/// local checkpoint ownership cannot undo or fence an in-flight remote write.
pub trait ExternalTarget: Send + Sync {
    /// Apply idempotently; retries may occur after cancellation or checkpoint failure.
    fn apply<T: Timer>(
        &self,
        scope: &ProjectionScope,
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
    fn scope(&self) -> &ProjectionScope {
        self.checkpoint.scope()
    }
    async fn checkpoint(&self) -> Result<Checkpoint, Error> {
        self.checkpoint.load().await
    }
    async fn execute<T: Timer>(
        &self,
        expected: Option<Position>,
        event: &Event,
        control: &Control<'_, T>,
    ) -> Result<ApplyOutcome, Error> {
        if event.source() != self.scope().source() {
            return Err(Error::new(ErrorKind::ScopeMismatch));
        }
        let current = control.run(self.checkpoint.load()).await?;
        if current.position != expected {
            return Err(Error::new(ErrorKind::Fenced));
        }
        crate::validate_next(current, event)?;
        let outcome = control
            .run(self.target.apply(self.scope(), event, control))
            .await
            .map_err(Error::uncertain)?;
        control
            .run(self.checkpoint.advance(expected, event, control))
            .await
            .map_err(Error::uncertain)?;
        Ok(outcome)
    }
}
