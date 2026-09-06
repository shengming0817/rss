//! Optional composition. Existing messaging runtime exclusively owns transaction settlement.
//! Every callback receives the SAME transaction used for reconcile state and Outbox append.
use crate::{
    PgClaim,
    store::{Key, lock, mark_applied, wake},
};
use futures::future::BoxFuture;
use rss_reconcile::{Control, Error, ErrorKind, Target, Timer};
use rss_transactional_messaging::{
    error::{MessagingError, MessagingErrorKind},
    policy::{AbsoluteDeadline, Clock, MonotonicInstant, OperationDeadline},
    transaction::LocalTxAttempt,
};
use rss_transactional_messaging_postgres::{PgError, PgRuntime, PgTransaction};

struct BridgeClock<'a, 'b, T>(&'a Control<'b, T>);
impl<T: Timer> Clock for BridgeClock<'_, '_, T> {
    fn now(&self) -> MonotonicInstant {
        MonotonicInstant::from_elapsed(self.0.elapsed())
    }
}
fn deadline<T: Timer>(control: &Control<'_, T>) -> Result<OperationDeadline, MessagingError> {
    let clock = BridgeClock(control);
    Ok(AbsoluteDeadline::from_timeout(&clock, control.remaining())
        .map_err(|e| MessagingError::new(MessagingErrorKind::Invariant, e))?
        .operation(&clock))
}
fn convert(error: Error) -> PgError {
    let kind = match error.kind() {
        ErrorKind::Fenced => MessagingErrorKind::OwnershipLost,
        ErrorKind::Transient => MessagingErrorKind::Transient,
        ErrorKind::Cancelled => MessagingErrorKind::DeadlineElapsed,
        ErrorKind::Deadline => MessagingErrorKind::DeadlineElapsed,
        _ => MessagingErrorKind::Invariant,
    };
    PgError::from(MessagingError::new(kind, error))
}
/// Protect trusted SQL and canonical messages with a borrowed application context.
/// The runtime remains the sole transaction owner; claim remains held for re-observation.
pub async fn protect<T: Timer, R: Send, C: Send, F>(
    runtime: &PgRuntime,
    claim: &PgClaim,
    control: &Control<'_, T>,
    context: C,
    operation: F,
) -> LocalTxAttempt<R, PgError>
where
    F: for<'c> FnOnce(&'c mut C, &'c mut PgTransaction<'_>) -> BoxFuture<'c, Result<R, PgError>>
        + Send,
{
    if let Err(e) = control.check() {
        return LocalTxAttempt::not_started(convert(e));
    }
    let deadline = match deadline(control) {
        Ok(d) => d,
        Err(e) => return LocalTxAttempt::not_started(PgError::from(e)),
    };
    let state = (Key::from(claim), Key::from(claim), context, Some(operation));
    let transaction = runtime.local_tx_with_context(
        claim.target().scope().tenant(),
        deadline,
        state,
        |state, tx| {
            Box::pin(async move {
                let first = &state.0;
                // with_connection accepts a bounded borrow. Results retain component classification.
                let checked = tx
                    .with_connection(|conn| {
                        Box::pin(async move { Ok(crate::probe::validate_connection(conn).await) })
                    })
                    .await?;
                checked.map_err(convert)?;
                component_lock(tx, first).await?;
                let operation = state
                    .3
                    .take()
                    .ok_or_else(|| convert(Error::new(ErrorKind::Invariant)))?;
                let value = operation(&mut state.2, tx).await?;
                component_mark(tx, &state.1).await?;
                Ok(value)
            })
        },
    );
    match control.run(async { Ok(transaction.await) }).await {
        Ok(result) => result,
        Err(error) => LocalTxAttempt::commit_unknown(convert(error)),
    }
}
/// Atomically register a durable wake with SQL/messages and a borrowed context.
pub async fn wake_with<T: Timer, R: Send, C: Send, F>(
    runtime: &PgRuntime,
    target: &Target,
    control: &Control<'_, T>,
    context: C,
    operation: F,
) -> LocalTxAttempt<R, PgError>
where
    F: for<'c> FnOnce(&'c mut C, &'c mut PgTransaction<'_>) -> BoxFuture<'c, Result<R, PgError>>
        + Send,
{
    if let Err(e) = control.check() {
        return LocalTxAttempt::not_started(convert(e));
    }
    let deadline = match deadline(control) {
        Ok(d) => d,
        Err(e) => return LocalTxAttempt::not_started(PgError::from(e)),
    };
    let transaction = runtime.local_tx_with_context(
        target.scope().tenant(),
        deadline,
        (target.clone(), context, Some(operation)),
        |state, tx| {
            Box::pin(async move {
                tx.with_connection(|conn| {
                    Box::pin(async move { Ok(crate::probe::validate_connection(conn).await) })
                })
                .await?
                .map_err(convert)?;
                let target = state.0.clone();
                tx.with_connection(move |conn| {
                    Box::pin(async move { Ok(wake(conn, &target).await) })
                })
                .await?
                .map_err(convert)?;
                let operation = state
                    .2
                    .take()
                    .ok_or_else(|| convert(Error::new(ErrorKind::Invariant)))?;
                operation(&mut state.1, tx).await
            })
        },
    );
    match control.run(async { Ok(transaction.await) }).await {
        Ok(result) => result,
        Err(error) => LocalTxAttempt::commit_unknown(convert(error)),
    }
}
async fn component_lock(tx: &mut PgTransaction<'_>, key: &Key) -> Result<(), PgError> {
    let key = key.copy_arguments();
    tx.with_connection(move |conn| Box::pin(async move { Ok(lock(conn, &key).await) }))
        .await?
        .map_err(convert)
}
async fn component_mark(tx: &mut PgTransaction<'_>, key: &Key) -> Result<(), PgError> {
    let key = key.copy_arguments();
    tx.with_connection(move |conn| Box::pin(async move { Ok(mark_applied(conn, &key).await) }))
        .await?
        .map_err(convert)
}
