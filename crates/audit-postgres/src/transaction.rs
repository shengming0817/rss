use crate::{Control, Error, Integrity, StagedAppend, repository};
use futures::future::BoxFuture;
use rss_audit_core::PreparedAuditV1;
use rss_request_context::{ExecutionTimer, TenantId};
use rss_transactional_messaging::transaction::LocalTxDeadlineStage as Stage;
use sqlx::{PgConnection, Postgres, Transaction};

/// Tenant-bound read access. PostgreSQL enforces read-only mode in a read transaction.
/// The enclosing owner alone settles; transaction/session control is forbidden in raw SQL.
///
/// ```compile_fail
/// use rss_audit_postgres::ReadAuditTransaction;
/// use rss_audit_core::PreparedAuditV1;
/// use rss_request_context::ExecutionTimer;
/// async fn append<T: ExecutionTimer>(tx: &mut ReadAuditTransaction<'_, '_, '_, T>, p: &PreparedAuditV1) {
///     tx.append(p).await;
/// }
/// ```
pub struct ReadAuditTransaction<'a, 'db, 'control, T> {
    pub(crate) tx: &'a mut Transaction<'db, Postgres>,
    pub(crate) control: &'control Control<'control, T>,
    pub(crate) integrity: &'control Integrity,
    pub(crate) tenant: TenantId,
}
impl<T: ExecutionTimer> ReadAuditTransaction<'_, '_, '_, T> {
    /// Fixed tenant of this transaction.
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant
    }
    /// Read within this transaction's tenant and the first page's fixed upper bound.
    pub async fn read_page(
        &mut self,
        cursor: crate::Cursor,
        limit: crate::ReadLimit,
    ) -> Result<crate::Page, Error> {
        self.control.check(Stage::Operation)?;
        if cursor.tenant() != self.tenant {
            return Err(Error::ScopeMismatch);
        }
        repository::page(self.tx, cursor, limit).await
    }
    /// Borrow trusted SQL; transaction control and tenant/session mutation are forbidden.
    /// The connection cannot escape the callback. This is not a SQL sandbox.
    /// The callback's error type is returned unchanged, without formatting bounds.
    pub async fn with_connection<R: Send, E: Send, F>(&mut self, operation: F) -> Result<R, E>
    where
        F: for<'c> FnOnce(&'c mut PgConnection) -> BoxFuture<'c, Result<R, E>> + Send,
    {
        self.with_connection_context(&mut (), move |_, c| operation(c))
            .await
    }
    /// Borrow trusted SQL and scoped host inputs together; neither can escape the callback.
    /// This has the same SQL/session restrictions as `with_connection`.
    ///
    /// ```compile_fail
    /// use rss_audit_postgres::{ReadAuditTransaction, Error};
    /// use rss_request_context::ExecutionTimer;
    /// async fn escape<T: ExecutionTimer>(tx: &mut ReadAuditTransaction<'_, '_, '_, T>) {
    ///     let mut context = String::new();
    ///     let escaped = tx.with_connection_context(&mut context, |context, connection| {
    ///         Box::pin(async move { Ok::<_, Error>((context, connection)) })
    ///     }).await;
    /// }
    /// ```
    pub async fn with_connection_context<R: Send, E: Send, C: Send, F>(
        &mut self,
        context: &mut C,
        operation: F,
    ) -> Result<R, E>
    where
        F: for<'c> FnOnce(&'c mut C, &'c mut PgConnection) -> BoxFuture<'c, Result<R, E>> + Send,
    {
        operation(context, self.tx).await
    }
    #[cfg(feature = "ledger")]
    pub(crate) async fn verified(
        &mut self,
        start: rss_ledger::Sequence,
        limit: rss_ledger_postgres::ReadLimit,
    ) -> Result<rss_audit_core::VerifiedAuditWindow, Error> {
        let Integrity::Ledger(auth) = self.integrity else {
            return Err(Error::IntegrityRequired);
        };
        crate::probe::tenant(self.tx, self.tenant).await?;
        let id = crate::runtime::ledger_id(self.tenant)?;
        let budget = self.control.ledger_control(Stage::Operation);
        let window = rss_ledger_postgres::read_window_in_transaction(
            self.tx, auth, &id, start, limit, &budget,
        )
        .await?;
        let audit =
            rss_audit_core::DecodedAuditWindow::from_ledger(self.tenant, window.verified())?;
        crate::verified::check_associations(self.tx, self.control, self.tenant, &audit).await?;
        Ok(audit.verify_identities()?)
    }
}

/// Tenant-bound write access, handed to the callback after optional Ledger locks.
/// Operations share the connection, admitted storage and absolute operation cutoff.
pub struct WriteAuditTransaction<'a, 'db, 'control, T> {
    pub(crate) write_budget: Option<&'control crate::WriteBudget>,
    pub(crate) held: &'a mut Option<tokio::sync::OwnedSemaphorePermit>,
    pub(crate) read: ReadAuditTransaction<'a, 'db, 'control, T>,
}
impl<'a, 'db, 'control, T> std::ops::Deref for WriteAuditTransaction<'a, 'db, 'control, T> {
    type Target = ReadAuditTransaction<'a, 'db, 'control, T>;
    fn deref(&self) -> &Self::Target {
        &self.read
    }
}
impl<T> std::ops::DerefMut for WriteAuditTransaction<'_, '_, '_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.read
    }
}
impl<T: ExecutionTimer> WriteAuditTransaction<'_, '_, '_, T> {
    /// Acquire optional ledger locks before deriving business facts.
    /// Does not append an event; only the original owner can settle this transaction.
    pub(crate) async fn lock_head(&mut self) -> Result<(), Error> {
        crate::probe::tenant(self.read.tx, self.read.tenant).await?;
        #[cfg(feature = "ledger")]
        if let Integrity::Ledger(auth) = self.read.integrity {
            let budget = self.read.control.ledger_control(Stage::Operation);
            rss_ledger_postgres::lock_head_in_transaction(
                self.read.tx,
                auth,
                &crate::runtime::ledger_id(self.read.tenant)?,
                &budget,
            )
            .await?;
        }
        Ok(())
    }
    /// Stage exact canonical bytes. Propagate any error to the enclosing owner.
    /// In Ledger mode acquire the chain before business/outbox locks.
    pub async fn append(&mut self, request: &PreparedAuditV1) -> Result<StagedAppend, Error> {
        self.read.control.check(Stage::Operation)?;
        let batch = self
            .write_budget
            .ok_or(Error::StorageContract)?
            .try_with_held(
                std::slice::from_ref(request),
                self.held.as_ref().map_or(0, |held| held.num_permits()),
            )?;
        self.append_admitted(batch)
            .await?
            .pop()
            .ok_or(Error::StorageContract)
    }
    /// Stage an admitted batch; its grant remains held through the owner's settlement.
    pub async fn append_admitted(
        &mut self,
        mut batch: crate::AdmittedBatch<'_>,
    ) -> Result<Vec<StagedAppend>, Error> {
        self.read.control.check(Stage::Operation)?;
        self.write_budget
            .ok_or(Error::StorageContract)?
            .check_domain(&batch)?;
        if batch
            .tenant
            .is_some_and(|tenant| tenant != self.read.tenant)
        {
            return Err(Error::ScopeMismatch);
        }
        if let Some(permit) = batch.take_permit() {
            if let Some(held) = self.held {
                held.merge(permit);
            } else {
                *self.held = Some(permit);
            }
        }
        // The outer deadline may drop the callback while SQL is in flight.
        crate::borrowed::append_batch(self.read.tx, self.read.integrity, &batch, self.read.control)
            .await
    }
}
