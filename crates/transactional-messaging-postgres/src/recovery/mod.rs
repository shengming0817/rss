//! PG implementation of authorized recovery, sharing the original pool and transaction owner.
mod capture;
mod mutation;
mod query;
use crate::{PgConfig, PgError, PgRuntime};
use rss_data_protection::Aead;
use rss_transactional_messaging::policy::{
    AbsoluteDeadline, ExecutionTimer, OperationDeadline, within,
};
use rss_transactional_messaging::transaction::LocalTxAttempt;
use rss_transactional_messaging_recovery::{
    AuthorizedMutation, AuthorizedQuery, Error, Page, Receipt, RecoveryStore, StoreFailureKind,
};
use std::sync::Arc;

/// Verified permission to atomically capture protected consumer dead letters.
pub struct PgRecoveryCapture<K> {
    pub(crate) runtime: Arc<PgRuntime>,
    key: Arc<K>,
}
impl<K: Aead + Send + Sync> PgRecoveryCapture<K> {
    /// Validate capture schema, RLS and effective permissions before selecting recovery consumption.
    pub async fn new(
        runtime: Arc<PgRuntime>,
        key: Arc<K>,
        deadline: OperationDeadline,
    ) -> Result<Self, Error> {
        check(&runtime, false, deadline).await?;
        Ok(Self { runtime, key })
    }
}
/// Operator store sharing the canonical private PG transaction implementation. Authorization is mandatory per request.
///
/// ```compile_fail
/// use rss_transactional_messaging_postgres::{PgRecoveryStore, PgRuntime};
/// fn leak<K>(store: &PgRecoveryStore<K>) -> &PgRuntime { &store.runtime }
/// ```
/// ```compile_fail
/// use rss_transactional_messaging_postgres::{PgRecoveryStore, PgRuntime};
/// fn coerce<K>(store: &PgRecoveryStore<K>) -> &PgRuntime { store }
/// ```
pub struct PgRecoveryStore<K> {
    runtime: Arc<PgRuntime>,
    key: Arc<K>,
}
impl<K: Aead + Send + Sync> PgRecoveryStore<K> {
    /// Connect an operator role directly into a narrow recovery capability. No raw SQL/pool/runtime accessor exists.
    /// ref: cap-std README.md@main (resource handles restrict available operations).
    pub async fn connect<C: ExecutionTimer + 'static>(
        config: PgConfig,
        timer: C,
        key: Arc<K>,
    ) -> Result<Self, Error> {
        let runtime = Arc::new(
            PgRuntime::connect_profile(config, timer, true)
                .await
                .map_err(error)?,
        );
        Ok(Self { runtime, key })
    }
    /// Stop new acquisitions and drain the privately owned pool. The caller owns the final shutdown budget.
    pub async fn close(&self) {
        self.runtime.close().await;
    }
    /// Whether the underlying pool has stopped accepting work.
    pub fn is_closed(&self) -> bool {
        self.runtime.is_closed()
    }
    /// Inject one transaction fault without exposing raw connection authority.
    #[cfg(feature = "integration")]
    pub fn inject_next_transaction_fault(&self, fault: crate::PgTransactionFault) {
        self.runtime.inject_next_transaction_fault(fault);
    }
}

fn error(value: PgError) -> Error {
    if let PgError::Recovery(error) = value {
        return error;
    }
    match value.kind() {
        rss_transactional_messaging::error::MessagingErrorKind::Conflict => Error::Conflict,
        rss_transactional_messaging::error::MessagingErrorKind::DeadlineElapsed => Error::Deadline,
        rss_transactional_messaging::error::MessagingErrorKind::Transient => {
            Error::Store(StoreFailureKind::Transient)
        }
        rss_transactional_messaging::error::MessagingErrorKind::Permanent => {
            Error::Store(StoreFailureKind::Permanent)
        }
        rss_transactional_messaging::error::MessagingErrorKind::OwnershipLost => {
            Error::Store(StoreFailureKind::OwnershipLost)
        }
        rss_transactional_messaging::error::MessagingErrorKind::Invariant => {
            Error::Store(StoreFailureKind::Invariant)
        }
    }
}
fn map_attempt<T>(attempt: LocalTxAttempt<T, PgError>) -> LocalTxAttempt<T, Error> {
    attempt.fold(
        LocalTxAttempt::committed,
        |e| LocalTxAttempt::not_started(error(e)),
        |e| LocalTxAttempt::rolled_back(error(e)),
        |e| LocalTxAttempt::rollback_failed(error(e)),
        |e| LocalTxAttempt::commit_unknown(error(e)),
        |e| LocalTxAttempt::fenced(error(e)),
    )
}
pub(crate) async fn check(
    runtime: &PgRuntime,
    operator: bool,
    deadline: OperationDeadline,
) -> Result<(), Error> {
    let cutoff = AbsoluteDeadline::from_timeout(&runtime.timer, deadline.timeout())
        .map_err(|_| Error::Deadline)?;
    let mut connection = within(&runtime.timer, cutoff, |_| runtime.acquire())
        .await
        .map_err(|_| Error::Deadline)?
        .map_err(|e| error(e.into()))?;
    let valid = within(&runtime.timer, cutoff, |_| async {
        let mut tx = connection.begin().await?;
        let valid = sqlx::query_scalar::<_, bool>(include_str!("probe.sql"))
            .bind(operator)
            .fetch_one(tx.connection())
            .await?;
        tx.rollback().await?;
        Ok::<_, sqlx::Error>(valid)
    })
    .await
    .map_err(|_| Error::Deadline)?
    .map_err(|source| match PgError::probe(source) {
        PgError::PermissionDenied(_) | PgError::StorageContractProbe(_) => Error::StorageContract,
        other => error(other),
    })?;
    if valid {
        Ok(())
    } else {
        Err(Error::StorageContract)
    }
}
impl<K: Aead + Send + Sync> RecoveryStore for PgRecoveryStore<K> {
    async fn query(
        &self,
        request: &AuthorizedQuery,
        deadline: OperationDeadline,
    ) -> Result<Page, Error> {
        query::query(&self.runtime, request.request(), deadline).await
    }
    async fn mutate(
        &self,
        request: &AuthorizedMutation,
        deadline: OperationDeadline,
    ) -> LocalTxAttempt<Receipt, Error> {
        mutation::mutate(
            &self.runtime,
            self.key.as_ref(),
            request.request(),
            deadline,
        )
        .await
    }
    async fn receipt(
        &self,
        request: &AuthorizedMutation,
        deadline: OperationDeadline,
    ) -> Result<Option<Receipt>, Error> {
        let result = self
            .runtime
            .local_tx_with_context(
                request.request().tenant(),
                deadline,
                request.request(),
                |request, tx| Box::pin(mutation::read_receipt(tx, request)),
            )
            .await;
        map_attempt(result).fold(Ok, Err, Err, Err, Err, Err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rss_transactional_messaging::error::MessagingErrorKind as Kind;
    #[test]
    fn backend_failure_projection_preserves_class_without_source_text() {
        for (kind, expected) in [
            (Kind::Transient, Error::Store(StoreFailureKind::Transient)),
            (Kind::Permanent, Error::Store(StoreFailureKind::Permanent)),
            (
                Kind::OwnershipLost,
                Error::Store(StoreFailureKind::OwnershipLost),
            ),
            (Kind::Invariant, Error::Store(StoreFailureKind::Invariant)),
            (Kind::Conflict, Error::Conflict),
            (Kind::DeadlineElapsed, Error::Deadline),
        ] {
            let actual = error(PgError::classified(
                kind,
                std::io::Error::other("secret-provider-text"),
            ));
            assert_eq!(actual, expected);
            assert!(!format!("{actual:?} {actual}").contains("secret-provider-text"));
        }
    }
}
