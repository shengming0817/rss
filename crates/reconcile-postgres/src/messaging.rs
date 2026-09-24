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
    policy::OperationDeadline,
    transaction::LocalTxAttempt,
};
use rss_transactional_messaging_postgres::{PgError, PgRuntime, PgTransaction};

fn deadline<T: Timer>(control: &Control<'_, T>) -> OperationDeadline {
    OperationDeadline::from_remaining(control.remaining())
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
    let deadline = deadline(control);
    let state = (Key::from(claim), context, Some(operation));
    let transaction = runtime.local_tx_with_context(
        claim.target().scope().tenant(),
        deadline,
        state,
        |state, tx| {
            Box::pin(async move {
                let operation = state
                    .2
                    .take()
                    .ok_or_else(|| convert(Error::new(ErrorKind::Invariant)))?;
                protect_key_in(tx, &state.0, &mut state.1, operation).await
            })
        },
    );
    match control.run(async { Ok(transaction.await) }).await {
        Ok(result) => result,
        Err(error) => LocalTxAttempt::commit_unknown(convert(error)),
    }
}
/// Protect a claim inside a caller-owned messaging transaction.
///
/// Acquire any host locks ordered before the claim before calling this function.
/// It inherits the transaction's remaining budget and connection, validates tenant and
/// claim fencing, runs the callback, and marks Applied. Success is staged only:
/// propagate any error to the transaction owner and let that owner settle the whole unit.
/// No connection is acquired, session setting changed, or commit performed here.
pub async fn protect_in<R: Send, C: Send, F>(
    tx: &mut PgTransaction<'_>,
    claim: &PgClaim,
    mut context: C,
    operation: F,
) -> Result<R, PgError>
where
    F: for<'c> FnOnce(&'c mut C, &'c mut PgTransaction<'_>) -> BoxFuture<'c, Result<R, PgError>>
        + Send,
{
    if tx.tenant_id() != claim.target().scope().tenant() {
        return Err(convert(Error::new(ErrorKind::Fenced)));
    }
    protect_key_in(tx, &Key::from(claim), &mut context, operation).await
}

async fn protect_key_in<R: Send, C: Send, F>(
    tx: &mut PgTransaction<'_>,
    key: &Key,
    context: &mut C,
    operation: F,
) -> Result<R, PgError>
where
    F: for<'c> FnOnce(&'c mut C, &'c mut PgTransaction<'_>) -> BoxFuture<'c, Result<R, PgError>>
        + Send,
{
    tx.with_connection(|conn| {
        Box::pin(async move { Ok(crate::probe::validate_connection(conn).await) })
    })
    .await?
    .map_err(convert)?;
    component_lock(tx, key).await?;
    let value = operation(context, tx).await?;
    component_mark(tx, key).await?;
    Ok(value)
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
    let deadline = deadline(control);
    let transaction = runtime.local_tx_with_context(
        target.scope().tenant(),
        deadline,
        (target.clone(), context, Some(operation)),
        |state, tx| {
            Box::pin(async move {
                wake_target_in(tx, &state.0).await?;
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
/// Register a wake and run trusted SQL/messages in a caller-owned transaction.
///
/// The host can acquire preceding locks before entering this composition. It inherits
/// the transaction's tenant, connection and budget; success is staged, never commit proof.
/// Propagate errors to the original owner. No session changes or second connection occur.
pub async fn wake_in<R: Send, C: Send, F>(
    tx: &mut PgTransaction<'_>,
    target: &Target,
    mut context: C,
    operation: F,
) -> Result<R, PgError>
where
    F: for<'c> FnOnce(&'c mut C, &'c mut PgTransaction<'_>) -> BoxFuture<'c, Result<R, PgError>>
        + Send,
{
    wake_target_in(tx, target).await?;
    operation(&mut context, tx).await
}
async fn wake_target_in(tx: &mut PgTransaction<'_>, target: &Target) -> Result<(), PgError> {
    if tx.tenant_id() != target.scope().tenant() {
        return Err(convert(Error::new(ErrorKind::Fenced)));
    }
    tx.with_connection(|conn| {
        Box::pin(async move { Ok(crate::probe::validate_connection(conn).await) })
    })
    .await?
    .map_err(convert)?;
    let target = target.clone();
    tx.with_connection(move |conn| Box::pin(async move { Ok(wake(conn, &target).await) }))
        .await?
        .map_err(convert)
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
