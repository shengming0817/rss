//! Optional composition bound to the exact messaging runtime admitted at construction.
//! ref: sqlx v0.9.0 sqlx-core/src/transaction.rs (borrowed connection, sole settlement owner).
use crate::{
    PgClaim,
    probe::Identity,
    store::{Key, lock, mark_applied, wake},
};
use futures::future::BoxFuture;
use rss_reconcile::{Control, Error, ErrorKind, Target, Timer};
use rss_request_context::TenantId;
use rss_transactional_messaging::{
    error::{MessagingError, MessagingErrorKind},
    policy::OperationDeadline,
    transaction::LocalTxAttempt,
};
use rss_transactional_messaging_postgres::{PgError, PgRuntime, PgTransaction};
use std::sync::Arc;

fn deadline<T: Timer>(control: &Control<'_, T>) -> OperationDeadline {
    OperationDeadline::from_remaining(control.remaining())
}
fn convert(error: Error) -> PgError {
    let kind = match error.kind() {
        ErrorKind::Fenced => MessagingErrorKind::OwnershipLost,
        ErrorKind::Transient => MessagingErrorKind::Transient,
        ErrorKind::Cancelled | ErrorKind::Deadline => MessagingErrorKind::DeadlineElapsed,
        _ => MessagingErrorKind::Invariant,
    };
    PgError::from(MessagingError::new(kind, error))
}

/// Reconcile composition admitted on one actual messaging runtime.
/// Stop and drain consumers before schema/ACL changes, then construct a new handle.
/// This handle borrows the runtime; its owner retains shutdown and transaction settlement.
#[derive(Clone)]
pub struct PgMessagingStore {
    runtime: Arc<PgRuntime>,
    identity: Identity,
}
impl PgMessagingStore {
    /// Validate the complete reconcile contract using a tenant already bound to this runtime.
    /// Neither migrations nor grants are executed.
    pub async fn new(
        runtime: Arc<PgRuntime>,
        tenant: TenantId,
        deadline: OperationDeadline,
    ) -> Result<Self, PgError> {
        let identity = runtime
            .local_tx(tenant, deadline, |tx| {
                Box::pin(async move {
                    tx.with_connection(|conn| {
                        Box::pin(async move { Ok(crate::probe::validate_connection(conn).await) })
                    })
                    .await?
                    .map_err(convert)
                })
            })
            .await
            .fold(Ok, Err, Err, Err, Err, Err)?;
        Ok(Self { runtime, identity })
    }
    async fn check(&self, tx: &mut PgTransaction<'_>, tenant: TenantId) -> Result<(), PgError> {
        self.runtime.validate_transaction(tx)?;
        if tx.tenant_id() != tenant {
            return Err(convert(Error::new(ErrorKind::Fenced)));
        }
        tx.with_connection_context(&mut &self.identity, |identity, conn| {
            Box::pin(async move { Ok(identity.validate(conn).await) })
        })
        .await?
        .map_err(convert)
    }
    /// Protect SQL/messages in the bound runtime's transaction; preserve the owner's outcome.
    pub async fn protect<T: Timer, R: Send, C: Send, F>(
        &self,
        claim: &PgClaim,
        control: &Control<'_, T>,
        context: C,
        operation: F,
    ) -> LocalTxAttempt<R, PgError>
    where
        F: for<'c> FnOnce(
                &'c mut C,
                &'c mut PgTransaction<'_>,
            ) -> BoxFuture<'c, Result<R, PgError>>
            + Send,
    {
        if let Err(error) = control.check() {
            return LocalTxAttempt::not_started(convert(error));
        }
        let transaction = self.runtime.local_tx_with_context(
            claim.target().scope().tenant(),
            deadline(control),
            (self, Key::from(claim), context, Some(operation)),
            |state, tx| {
                Box::pin(async move {
                    let operation = state
                        .3
                        .take()
                        .ok_or_else(|| convert(Error::new(ErrorKind::Invariant)))?;
                    state
                        .0
                        .protect_key_in(tx, &state.1, &mut state.2, operation)
                        .await
                })
            },
        );
        match control.run(async { Ok(transaction.await) }).await {
            Ok(result) => result,
            Err(error) => LocalTxAttempt::commit_unknown(convert(error)),
        }
    }
    /// Protect a claim inside a transaction from this exact runtime. Success is staged only.
    pub async fn protect_in<R: Send, C: Send, F>(
        &self,
        tx: &mut PgTransaction<'_>,
        claim: &PgClaim,
        mut context: C,
        operation: F,
    ) -> Result<R, PgError>
    where
        F: for<'c> FnOnce(
                &'c mut C,
                &'c mut PgTransaction<'_>,
            ) -> BoxFuture<'c, Result<R, PgError>>
            + Send,
    {
        self.protect_key_in(tx, &Key::from(claim), &mut context, operation)
            .await
    }
    async fn protect_key_in<R: Send, C: Send, F>(
        &self,
        tx: &mut PgTransaction<'_>,
        key: &Key,
        context: &mut C,
        operation: F,
    ) -> Result<R, PgError>
    where
        F: for<'c> FnOnce(
                &'c mut C,
                &'c mut PgTransaction<'_>,
            ) -> BoxFuture<'c, Result<R, PgError>>
            + Send,
    {
        self.check(tx, key.target.scope().tenant()).await?;
        component_lock(tx, key).await?;
        let value = operation(context, tx).await?;
        component_mark(tx, key).await?;
        Ok(value)
    }
    /// Atomically register a wake and SQL/messages in the bound runtime.
    pub async fn wake_with<T: Timer, R: Send, C: Send, F>(
        &self,
        target: &Target,
        control: &Control<'_, T>,
        context: C,
        operation: F,
    ) -> LocalTxAttempt<R, PgError>
    where
        F: for<'c> FnOnce(
                &'c mut C,
                &'c mut PgTransaction<'_>,
            ) -> BoxFuture<'c, Result<R, PgError>>
            + Send,
    {
        if let Err(error) = control.check() {
            return LocalTxAttempt::not_started(convert(error));
        }
        let transaction = self.runtime.local_tx_with_context(
            target.scope().tenant(),
            deadline(control),
            (self, target.clone(), context, Some(operation)),
            |state, tx| {
                Box::pin(async move {
                    let operation = state
                        .3
                        .take()
                        .ok_or_else(|| convert(Error::new(ErrorKind::Invariant)))?;
                    state
                        .0
                        .wake_in(tx, &state.1, &mut state.2, |context, tx| {
                            operation(*context, tx)
                        })
                        .await
                })
            },
        );
        match control.run(async { Ok(transaction.await) }).await {
            Ok(result) => result,
            Err(error) => LocalTxAttempt::commit_unknown(convert(error)),
        }
    }
    /// Stage a wake and callback on an already borrowed transaction from this runtime.
    pub async fn wake_in<R: Send, C: Send, F>(
        &self,
        tx: &mut PgTransaction<'_>,
        target: &Target,
        mut context: C,
        operation: F,
    ) -> Result<R, PgError>
    where
        F: for<'c> FnOnce(
                &'c mut C,
                &'c mut PgTransaction<'_>,
            ) -> BoxFuture<'c, Result<R, PgError>>
            + Send,
    {
        self.check(tx, target.scope().tenant()).await?;
        let target = target.clone();
        tx.with_connection(move |conn| Box::pin(async move { Ok(wake(conn, &target).await) }))
            .await?
            .map_err(convert)?;
        operation(&mut context, tx).await
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
