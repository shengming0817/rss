//! ref: launchbadge/sqlx sqlx-core/src/transaction.rs@v0.9.0
use crate::{Control, Error, StagedAppend, Timer, repository};
use futures::future::BoxFuture;
use rss_ledger::{AppendRequest, Authenticator, LedgerId, RecordId, Sequence};
use rss_request_context::TenantId;
use rss_transactional_messaging::transaction::{LocalTxAttempt, LocalTxDeadlineStage};
use sqlx::{Connection, PgConnection, PgPool, Postgres, pool::PoolConnection};
use std::sync::Arc;

/// Acknowledged enclosing commit. Only this adapter's settlement path constructs it.
#[derive(Debug)]
pub struct Committed<T>(T);
impl<T> Committed<T> {
    /// Consume the receipt and inspect its committed operation value.
    pub fn into_value(self) -> T {
        self.0
    }
    /// Inspect the committed value.
    pub const fn value(&self) -> &T {
        &self.0
    }
}
/// Independent PostgreSQL owner. The supplied pool and every clone share close admission.
/// Message consumers independently call `append_in` with their own authenticator.
#[derive(Clone)]
pub struct PgLedger {
    pool: PgPool,
    auth: Arc<Authenticator>,
    #[cfg(feature = "integration")]
    fault: Arc<std::sync::atomic::AtomicU8>,
}
impl PgLedger {
    /// Validate the ledger schema/runtime role within the caller's budget; execute no migration.
    pub async fn new<T: Timer>(
        pool: PgPool,
        auth: Authenticator,
        control: &Control<'_, T>,
    ) -> Result<Self, Error> {
        control.run(crate::probe::validate(&pool)).await?;
        Ok(Self {
            pool,
            auth: Arc::new(auth),
            #[cfg(feature = "integration")]
            fault: Arc::new(std::sync::atomic::AtomicU8::new(0)),
        })
    }
    /// Stop admission and drain within the caller's budget. Cancellation leaves admission closed.
    pub async fn close<T: Timer>(&self, control: &Control<'_, T>) -> Result<(), Error> {
        let closing = self.pool.close();
        control
            .run(async {
                closing.await;
                Ok(())
            })
            .await
    }
    /// Independently append and await settlement. Keep the original request for unknown recovery.
    pub async fn append<T: Timer>(
        &self,
        request: &AppendRequest,
        control: &Control<'_, T>,
    ) -> LocalTxAttempt<Committed<StagedAppend>, Error> {
        let request = request.clone();
        let tenant = request.ledger().tenant();
        self.local_tx(tenant, control, move |tx| {
            Box::pin(async move { tx.append(&request).await })
        })
        .await
    }
    /// Read by stable identity in a settled transaction. Absence does not prove an uncertain
    /// earlier append was rolled back; retry the original append to serialize recovery.
    pub async fn find<T: Timer>(
        &self,
        ledger: &LedgerId,
        id: &RecordId,
        control: &Control<'_, T>,
    ) -> LocalTxAttempt<Committed<Option<rss_ledger::Entry>>, Error> {
        let ledger = ledger.clone();
        let id = id.clone();
        self.local_tx(ledger.tenant(), control, move |tx| {
            Box::pin(async move { repository::find(tx.connection, tx.auth, &ledger, &id).await })
        })
        .await
    }
    /// Read and authenticate a bounded snapshot window, including its predecessor.
    pub async fn read_window<T: Timer>(
        &self,
        ledger: &LedgerId,
        start: Sequence,
        limit: crate::ReadLimit,
        control: &Control<'_, T>,
    ) -> LocalTxAttempt<Committed<crate::Window>, Error> {
        let ledger = ledger.clone();
        self.local_tx(ledger.tenant(), control, move |tx| {
            Box::pin(async move {
                repository::window(tx.connection, tx.auth, &ledger, start, limit).await
            })
        })
        .await
    }
    /// Execute trusted business SQL and ledger appends under one tenant and one absolute budget.
    /// Propagate errors to roll back. Do not issue transaction/session control through raw SQL.
    pub async fn local_tx<T: Timer, R: Send, F>(
        &self,
        tenant: TenantId,
        control: &Control<'_, T>,
        operation: F,
    ) -> LocalTxAttempt<Committed<R>, Error>
    where
        F: for<'a> FnOnce(&'a mut LedgerTransaction<'_>) -> BoxFuture<'a, Result<R, Error>> + Send,
    {
        let connection = match control
            .run_stage(LocalTxDeadlineStage::Acquire, async {
                self.pool.acquire().await.map_err(Error::from)
            })
            .await
        {
            Ok(c) => c,
            Err(e) => return LocalTxAttempt::not_started(e),
        };
        let mut lease = Lease {
            connection,
            quarantine: true,
        };
        let mut tx = match control
            .run_stage(LocalTxDeadlineStage::Begin, async {
                lease.connection.begin().await.map_err(Error::from)
            })
            .await
        {
            Ok(tx) => tx,
            Err(e) => return LocalTxAttempt::not_started(e),
        };
        #[cfg(feature = "integration")]
        let fault = self.fault.swap(0, std::sync::atomic::Ordering::SeqCst);
        let setup = control.run_stage(LocalTxDeadlineStage::Setup, async {
            let millis=control.remaining().as_millis().max(1).to_string();
            sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout',$2,true),set_config('lock_timeout',$2,true)")
                .bind(tenant.to_string()).bind(millis).execute(&mut *tx).await.map_err(Error::from)?;
            Ok(())
        }).await;
        let body = match setup {
            Ok(()) => match control
                .run_stage(LocalTxDeadlineStage::Operation, async {
                    Ok(operation(&mut LedgerTransaction {
                        connection: &mut tx,
                        auth: &self.auth,
                        tenant,
                    })
                    .await)
                })
                .await
            {
                Ok(result) => result,
                Err(error) => return LocalTxAttempt::commit_unknown(error),
            },
            Err(error @ (Error::Deadline(_) | Error::Cancelled(_))) => {
                return LocalTxAttempt::commit_unknown(error);
            }
            Err(error) => Err(error),
        };
        // An expired control cannot poll rollback; do not invent rollback evidence.
        if let Err(error) = control.check(LocalTxDeadlineStage::Operation) {
            return LocalTxAttempt::commit_unknown(error);
        }
        match body {
            Ok(value) => {
                let result = control
                    .run_stage(LocalTxDeadlineStage::Commit, async {
                        #[cfg(feature = "integration")]
                        if fault == PgFault::CommitPending as u8 {
                            std::future::pending::<()>().await;
                        }
                        tx.commit().await.map_err(Error::from)?;
                        #[cfg(feature = "integration")]
                        if fault == PgFault::CommitUnknownAfterAck as u8 {
                            return Err(Error::Deadline(LocalTxDeadlineStage::Commit));
                        }
                        Ok(())
                    })
                    .await;
                match result {
                    Ok(()) => {
                        lease.quarantine = false;
                        LocalTxAttempt::committed(Committed(value))
                    }
                    Err(e) => LocalTxAttempt::commit_unknown(e),
                }
            }
            Err(e) => {
                let mut rollback_started = false;
                let rollback = control
                    .run_stage(LocalTxDeadlineStage::Rollback, async {
                        rollback_started = true;
                        tx.rollback().await.map_err(Error::from)?;
                        #[cfg(feature = "integration")]
                        if fault == PgFault::RollbackFailedAfterAck as u8 {
                            return Err(Error::Deadline(LocalTxDeadlineStage::Rollback));
                        }
                        Ok(())
                    })
                    .await;
                match rollback {
                    Ok(()) => {
                        lease.quarantine = false;
                        LocalTxAttempt::rolled_back(e)
                    }
                    Err(settlement) if !rollback_started => {
                        LocalTxAttempt::commit_unknown(settlement)
                    }
                    Err(settlement) => LocalTxAttempt::rollback_failed(Error::Rollback {
                        operation: Box::new(e),
                        settlement: Box::new(settlement),
                    }),
                }
            }
        }
    }
    /// Inject one fixture-owned settlement fault. Never enabled by default.
    #[cfg(feature = "integration")]
    pub fn inject_next_fault(&self, fault: PgFault) {
        self.fault
            .store(fault as u8, std::sync::atomic::Ordering::SeqCst);
    }
}
struct Lease {
    connection: PoolConnection<Postgres>,
    quarantine: bool,
}
impl Drop for Lease {
    fn drop(&mut self) {
        if self.quarantine {
            self.connection.close_on_drop();
        }
    }
}
/// Trusted tenant-bound SQL borrow without pool or settlement ownership.
pub struct LedgerTransaction<'a> {
    connection: &'a mut PgConnection,
    auth: &'a Authenticator,
    tenant: TenantId,
}
impl LedgerTransaction<'_> {
    /// Tenant fixed by the enclosing owner.
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant
    }
    /// Stage an authenticated append. Propagate failures; positions remain uncommitted here.
    pub async fn append(&mut self, request: &AppendRequest) -> Result<StagedAppend, Error> {
        if request.ledger().tenant() != self.tenant {
            return Err(rss_ledger::Error::ScopeMismatch.into());
        }
        repository::append(self.connection, self.auth, request).await
    }
    /// Borrow trusted business SQL. The connection cannot escape the callback. This is not a
    /// SQL sandbox: transaction control and changing tenant/session settings are forbidden.
    pub async fn with_connection<R: Send, E, F>(&mut self, operation: F) -> Result<R, E>
    where
        F: for<'a> FnOnce(&'a mut PgConnection) -> BoxFuture<'a, Result<R, E>> + Send,
    {
        operation(self.connection).await
    }
}
/// Integration-only settlement fault injection; scope the runtime to one fixture.
#[cfg(feature = "integration")]
#[derive(Clone, Copy)]
#[repr(u8)]
pub enum PgFault {
    /// Suppress the acknowledgement after actual durable COMMIT.
    CommitUnknownAfterAck = 1,
    /// Leave commit pending until the control interrupts it.
    CommitPending = 2,
    /// Suppress the acknowledgement after actual ROLLBACK.
    RollbackFailedAfterAck = 3,
}
