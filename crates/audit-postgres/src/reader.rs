//! Read capability over a separately admitted, non-append credential.
use crate::{
    Committed, Control, Cursor, Error, Integrity, Page, PgAudit, ReadAuditTransaction, ReadLimit,
    TransactionError,
};
use futures::future::BoxFuture;
use rss_request_context::{ExecutionTimer, TenantId};
use rss_transactional_messaging::transaction::{LocalTxAttempt, LocalTxDeadlineStage};
use sqlx::{PgConnection, PgPool};

/// Read-only Audit capability. Its actual role and every reachable SET-role must lack
/// Audit/Ledger append authority. No append method or writer handle can be obtained from it.
/// The host owns the supplied pool and re-admission after controlled credential/schema changes.
#[derive(Clone)]
pub struct PgAuditReader {
    inner: PgAudit,
}
impl PgAuditReader {
    /// Admit a reader's actual pool using the full version-matched storage contract.
    pub async fn new<T: ExecutionTimer>(
        pool: PgPool,
        integrity: Integrity,
        control: &Control<'_, T>,
    ) -> Result<Self, Error> {
        Ok(Self {
            inner: PgAudit::connect(pool, integrity, control, None).await?,
        })
    }
    /// Validate another actual borrowed connection as the same strictly read-only capability.
    pub async fn validate_connection<T: ExecutionTimer>(
        &self,
        connection: &mut PgConnection,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        control
            .run(
                LocalTxDeadlineStage::Setup,
                crate::runtime::validate_storage(connection, &self.inner.integrity, control, false),
            )
            .await
    }
    /// Read an ordinary bounded page without claiming Ledger authentication.
    pub async fn read_page<T: ExecutionTimer>(
        &self,
        cursor: Cursor,
        limit: ReadLimit,
        control: &Control<'_, T>,
    ) -> LocalTxAttempt<Committed<Page>, Error> {
        self.inner.read_page(cursor, limit, control).await
    }
    /// Read and authenticate a bounded Ledger window; this is not an external tail checkpoint.
    #[cfg(feature = "ledger")]
    pub async fn read_verified<T: ExecutionTimer>(
        &self,
        tenant: TenantId,
        start: rss_ledger::Sequence,
        limit: rss_ledger_postgres::ReadLimit,
        control: &Control<'_, T>,
    ) -> LocalTxAttempt<Committed<rss_audit_core::VerifiedAuditWindow>, Error> {
        self.inner
            .read_verified(tenant, start, limit, control)
            .await
    }
    /// Borrow the original read-only tenant transaction; only the component settles it.
    pub async fn read_tx_with_context<T: ExecutionTimer, R: Send, E: Send, C: Send, F>(
        &self,
        tenant: TenantId,
        control: &Control<'_, T>,
        context: C,
        operation: F,
    ) -> LocalTxAttempt<Committed<R>, TransactionError<E>>
    where
        F: for<'a> FnOnce(
                &'a mut C,
                &'a mut ReadAuditTransaction<'_, '_, '_, T>,
            ) -> BoxFuture<'a, Result<R, E>>
            + Send,
    {
        self.inner
            .read_tx_with_context(tenant, control, context, operation)
            .await
    }
}
