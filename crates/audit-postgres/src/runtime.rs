use crate::{
    Control, Cursor, Error, Page, ReadAuditTransaction, ReadLimit, StagedAppend, TransactionError,
    WriteAuditTransaction, probe,
};
use futures::future::BoxFuture;
use rss_audit_core::{AuditEventV1, PreparedAuditV1};
use rss_request_context::{ExecutionTimer, TenantId};
use rss_transactional_messaging::transaction::{LocalTxAttempt, LocalTxDeadlineStage as Stage};
use sqlx::{Acquire, Connection, PgConnection, PgPool, Postgres, pool::PoolConnection};

/// Explicit integrity mode. There is no fallback from ledger failure to plain persistence.
#[derive(Clone)]
pub enum Integrity {
    /// Atomic append-only persistence without cryptographic integrity claims.
    Plain,
    /// Append the Audit bytes and ledger entry in the very same transaction.
    #[cfg(feature = "ledger")]
    Ledger(std::sync::Arc<rss_ledger::Authenticator>),
}

/// Operation value after this owner's acknowledged COMMIT. Construction is private.
///
/// ```compile_fail
/// let forged = rss_audit_postgres::Committed(());
/// ```
#[derive(Debug)]
pub struct Committed<R>(R);
impl<R> Committed<R> {
    /// Inspect the acknowledged operation value.
    pub const fn value(&self) -> &R {
        &self.0
    }
    /// Consume the commit receipt.
    pub fn into_value(self) -> R {
        self.0
    }
}

/// Independent Audit transaction owner over a host-supplied pool.
/// Does not run migrations or close the host pool. Message borrowing keeps its original owner.
#[derive(Clone)]
pub struct PgAudit {
    pub(crate) pool: PgPool,
    budget: Option<crate::WriteBudget>,
    pub(crate) integrity: Integrity,
    #[cfg(feature = "integration")]
    fault: std::sync::Arc<std::sync::atomic::AtomicU8>,
}
impl PgAudit {
    /// Validate the actual schema and runtime role, without migration or session mutation.
    pub async fn new<T: ExecutionTimer>(
        pool: PgPool,
        integrity: Integrity,
        budget: crate::WriteBudget,
        control: &Control<'_, T>,
    ) -> Result<Self, Error> {
        Self::connect(pool, integrity, control, Some(budget)).await
    }
    pub(crate) async fn connect<T: ExecutionTimer>(
        pool: PgPool,
        integrity: Integrity,
        control: &Control<'_, T>,
        budget: Option<crate::WriteBudget>,
    ) -> Result<Self, Error> {
        control
            .run(Stage::Acquire, async {
                let connection = pool.acquire().await?;
                let mut lease = Lease::new(connection);
                validate_storage(&mut lease.connection, &integrity, control, budget.is_some())
                    .await?;
                lease.confirmed = true;
                Ok(())
            })
            .await?;
        Ok(Self {
            budget,
            pool,
            integrity,
            #[cfg(feature = "integration")]
            fault: std::sync::Arc::new(std::sync::atomic::AtomicU8::new(0)),
        })
    }
    pub(crate) fn budget(&self) -> Result<&crate::WriteBudget, Error> {
        self.budget.as_ref().ok_or(Error::StorageContract)
    }
    /// Admit already prepared input on this writer's shared budget without waiting.
    pub fn try_admit<'a>(
        &self,
        records: &'a [PreparedAuditV1],
    ) -> Result<crate::AdmittedBatch<'a>, Error> {
        self.budget()?.try_admit(records)
    }
    /// Verify the actual host runtime connection before accepting work.
    /// Does not acquire another connection, change settings or settle a transaction.
    /// The host bounds server execution and isolates unconfirmed connections on cancellation.
    pub async fn validate_connection<T: ExecutionTimer>(
        &self,
        connection: &mut PgConnection,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        control
            .run(
                Stage::Setup,
                validate_storage(connection, &self.integrity, control, true),
            )
            .await
    }
    /// Assign recording time from PostgreSQL and return exact retry bytes, not commit evidence.
    /// Preserve this request, including its timestamp, after an uncertain append.
    pub async fn prepare<T: ExecutionTimer>(
        &self,
        event: AuditEventV1,
        control: &Control<'_, T>,
    ) -> Result<PreparedAuditV1, Error> {
        control.check(Stage::Operation)?;
        let _reservation = self
            .budget()?
            .try_reserve(1, rss_audit_core::canonical_len(&event)?)?;
        let recorded = control
            .run(Stage::Operation, async {
                let mut lease = Lease::new(self.pool.acquire().await?);
                let recorded = crate::repository::recording_time(&mut lease.connection).await?;
                lease.confirmed = true;
                Ok(recorded)
            })
            .await?;
        control.check(Stage::Operation)?;
        let prepared = rss_audit_core::prepare(event, recorded)?;
        control.check(Stage::Operation)?;
        Ok(prepared)
    }
    /// Append and settle independently. Retry the unchanged request after commit-unknown.
    pub async fn append<T: ExecutionTimer>(
        &self,
        request: &PreparedAuditV1,
        control: &Control<'_, T>,
    ) -> LocalTxAttempt<Committed<StagedAppend>, Error> {
        let batch = match control
            .check(Stage::Operation)
            .and_then(|()| self.try_admit(std::slice::from_ref(request)))
        {
            Ok(batch) => batch,
            Err(error) => return LocalTxAttempt::not_started(error),
        };
        audit_only(
            self.transact(
                request.identity().tenant(),
                control,
                Access::Append,
                Some(batch),
                |batch, tx| {
                    Box::pin(async move {
                        tx.append_admitted(batch.take().ok_or(Error::StorageContract)?)
                            .await?
                            .pop()
                            .ok_or(Error::StorageContract)
                    })
                },
            )
            .await,
        )
    }
    /// Read a bounded ordinary page, explicitly without a ledger authentication claim.
    pub async fn read_page<T: ExecutionTimer>(
        &self,
        cursor: Cursor,
        limit: ReadLimit,
        control: &Control<'_, T>,
    ) -> LocalTxAttempt<Committed<Page>, Error> {
        audit_only(
            self.transact(
                cursor.tenant(),
                control,
                Access::ReadOperation,
                (),
                move |_, tx| Box::pin(async move { tx.read_page(cursor, limit).await }),
            )
            .await,
        )
    }
    /// Authenticate a ledger window with its distinct sequence coordinate and encoded-byte budget.
    /// Same-database predecessors are not external checkpoints or proof against tail truncation.
    #[cfg(feature = "ledger")]
    pub async fn read_verified<T: ExecutionTimer>(
        &self,
        tenant: TenantId,
        start: rss_ledger::Sequence,
        limit: rss_ledger_postgres::ReadLimit,
        control: &Control<'_, T>,
    ) -> LocalTxAttempt<Committed<rss_audit_core::VerifiedAuditWindow>, Error> {
        audit_only(
            self.transact(tenant, control, Access::ReadOperation, (), move |_, tx| {
                Box::pin(async move { tx.verified(start, limit).await })
            })
            .await,
        )
    }
    /// Execute trusted read SQL in a PostgreSQL read-only tenant transaction.
    /// Storage is admitted at startup; Audit/Ledger heads are never reserved.
    /// Callback errors retain their type, and only acknowledged settlement yields a receipt.
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
        self.transact(
            tenant,
            control,
            Access::ReadCallback,
            context,
            move |c, tx| operation(c, &mut tx.read),
        )
        .await
    }
    /// Acquire optional Ledger before invoking trusted business SQL.
    /// Operation uses the shorter cutoff; acquisition/setup/settlement use the total cutoff.
    /// No fresh cleanup budget is minted, and unconfirmed connections are retired.
    pub async fn write_tx_with_context<T: ExecutionTimer, R: Send, E: Send, C: Send, F>(
        &self,
        tenant: TenantId,
        control: &Control<'_, T>,
        context: C,
        operation: F,
    ) -> LocalTxAttempt<Committed<R>, TransactionError<E>>
    where
        F: for<'a> FnOnce(
                &'a mut C,
                &'a mut WriteAuditTransaction<'_, '_, '_, T>,
            ) -> BoxFuture<'a, Result<R, E>>
            + Send,
    {
        self.transact(tenant, control, Access::WriteCallback, context, operation)
            .await
    }
    #[allow(
        clippy::expect_used,
        reason = "pending is initialized once; only COMMIT takes it, and both post-take outcomes return before rollback"
    )]
    async fn transact<T: ExecutionTimer, R: Send, E: Send, C: Send, F>(
        &self,
        tenant: TenantId,
        control: &Control<'_, T>,
        access: Access,
        mut context: C,
        operation: F,
    ) -> LocalTxAttempt<Committed<R>, TransactionError<E>>
    where
        F: for<'a> FnOnce(
                &'a mut C,
                &'a mut WriteAuditTransaction<'_, '_, '_, T>,
            ) -> BoxFuture<'a, Result<R, E>>
            + Send,
    {
        let connection = match control
            .run(Stage::Acquire, async { Ok(self.pool.acquire().await?) })
            .await
        {
            Ok(c) => c,
            Err(e) => return LocalTxAttempt::not_started(TransactionError::Audit(e)),
        };
        let mut lease = Lease::new(connection);
        let mut tx = match control
            .run(Stage::Begin, async { Ok(lease.connection.begin().await?) })
            .await
        {
            Ok(tx) => tx,
            Err(e) => return LocalTxAttempt::not_started(TransactionError::Audit(e)),
        };
        let body=control.run(Stage::Setup,async {
            if matches!(access, Access::ReadCallback | Access::ReadOperation) {
                sqlx::query("SET TRANSACTION READ ONLY").execute(&mut *tx).await?;
            }
            // Dropping a SQLx query does not cancel the statement on the server. Bound
            // that statement too, so ROLLBACK can be acknowledged within the owner cutoff.
            let millis=(control.operation_remaining().as_millis()+1).clamp(1,i32::MAX as u128).to_string();
            sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout',$2,true),set_config('lock_timeout',$2,true)")
                .bind(tenant.to_string()).bind(millis).execute(&mut *tx).await?;
            Ok(())
        }).await;
        let mut held = None;
        let body = match body {
            Ok(()) => control
                .run(Stage::Operation, async {
                    let mut transaction = WriteAuditTransaction {
                        write_budget: self.budget.as_ref(),
                        held: &mut held,
                        read: ReadAuditTransaction {
                            tx: &mut tx,
                            control,
                            integrity: &self.integrity,
                            tenant,
                        },
                    };
                    match access {
                        Access::WriteCallback => transaction.lock_head().await?,
                        Access::ReadCallback => probe::tenant(transaction.read.tx, tenant).await?,
                        // Private operations retain their tenant and data checks.
                        Access::Append | Access::ReadOperation => {}
                    }
                    control.check(Stage::Operation)?;
                    let result = operation(&mut context, &mut transaction).await;
                    // A callback can cross the cutoff in its final synchronous poll.
                    // Preserve its original failure, but never commit a late success.
                    if result.is_ok() {
                        control.check(Stage::Operation)?;
                    }
                    Ok(result)
                })
                .await
                .map_err(TransactionError::Audit)
                .and_then(|result| result.map_err(TransactionError::Operation)),
            Err(e) => Err(TransactionError::Audit(e)),
        };
        #[cfg(feature = "integration")]
        let fault = self.fault.swap(0, std::sync::atomic::Ordering::SeqCst);
        let mut pending = Some(tx);
        let operation = match body {
            Ok(value) => {
                let settled = control
                    .run(Stage::Commit, async {
                        // Keep ownership until COMMIT is actually attempted. A setup
                        // error or cancellation before this point still needs rollback.
                        let millis = control.total_remaining().as_millis().clamp(1, i32::MAX as u128).to_string();
                        sqlx::query("SELECT set_config('statement_timeout',$1,true),set_config('lock_timeout',$1,true)")
                            .bind(millis).execute(&mut **pending.as_mut().expect("transaction pending")).await?;
                        #[cfg(feature = "integration")]
                        if fault == PgFault::BeforeCommitPending as u8 {
                            std::future::pending::<()>().await;
                        }
                        pending.take().expect("transaction pending").commit().await?;
                        #[cfg(feature = "integration")]
                        if fault == PgFault::CommitUnknownAfterAck as u8 {
                            return Err(Error::Deadline(Stage::Commit));
                        }
                        Ok(())
                    })
                    .await;
                match settled {
                    Ok(()) => {
                        lease.confirmed = true;
                        return LocalTxAttempt::committed(Committed(value));
                    }
                    Err(e) if pending.is_none() => {
                        return LocalTxAttempt::commit_unknown(TransactionError::Audit(e));
                    }
                    Err(e) => TransactionError::Audit(e),
                }
            }
            Err(operation) => operation,
        };
        let mut tx = pending.expect("unattempted transaction");
        let settled = control
            .run(Stage::Rollback, async {
                drain(&mut tx).await?;
                tx.rollback().await?;
                #[cfg(feature = "integration")]
                if fault == PgFault::RollbackFailedAfterAck as u8 {
                    return Err(Error::Deadline(Stage::Rollback));
                }
                Ok(())
            })
            .await;
        match settled {
            Ok(()) => {
                lease.confirmed = true;
                LocalTxAttempt::rolled_back(operation)
            }
            Err(settlement) => LocalTxAttempt::rollback_failed(TransactionError::Rollback {
                operation: Box::new(operation),
                settlement,
            }),
        }
    }
    /// Inject one fixture-owned settlement fault. Not present in production feature sets.
    #[cfg(feature = "integration")]
    pub fn inject_next_fault(&self, fault: PgFault) {
        self.fault
            .store(fault as u8, std::sync::atomic::Ordering::SeqCst);
    }
}
enum Access {
    ReadCallback,
    WriteCallback,
    ReadOperation,
    Append,
}
// A timed-out SQL future may leave its server ErrorResponse unread. Consume it
// through ReadyForQuery before sending ROLLBACK; only the latter's ACK settles.
// Transport/protocol errors still fail settlement and retire the lease.
// ref: launchbadge/sqlx sqlx-postgres/src/connection/mod.rs@v0.9.0
async fn drain(connection: &mut PgConnection) -> Result<(), Error> {
    loop {
        match connection.flush().await {
            Ok(()) => return Ok(()),
            Err(sqlx::Error::Database(_)) => continue,
            Err(error) => return Err(error.into()),
        }
    }
}
struct Lease {
    connection: PoolConnection<Postgres>,
    confirmed: bool,
}
impl Lease {
    fn new(connection: PoolConnection<Postgres>) -> Self {
        Self {
            connection,
            confirmed: false,
        }
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        if !self.confirmed {
            self.connection.close_on_drop();
        }
    }
}
/// Test-only faults after real protocol acknowledgements or before sending COMMIT.
#[cfg(feature = "integration")]
#[derive(Clone, Copy)]
#[repr(u8)]
pub enum PgFault {
    /// Durable commit succeeded, but suppress its acknowledgement.
    CommitUnknownAfterAck = 1,
    /// Pause before sending COMMIT until interrupted by the host control.
    BeforeCommitPending = 2,
    /// Rollback succeeded, but suppress its acknowledgement.
    RollbackFailedAfterAck = 3,
}

fn audit_only<R>(
    attempt: LocalTxAttempt<Committed<R>, TransactionError<Error>>,
) -> LocalTxAttempt<Committed<R>, Error> {
    attempt.fold(
        LocalTxAttempt::committed,
        |e| LocalTxAttempt::not_started(e.into_audit()),
        |e| LocalTxAttempt::rolled_back(e.into_audit()),
        |e| LocalTxAttempt::rollback_failed(e.into_audit()),
        |e| LocalTxAttempt::commit_unknown(e.into_audit()),
        |e| LocalTxAttempt::fenced(e.into_audit()),
    )
}

#[cfg(feature = "ledger")]
pub(crate) fn ledger_id(tenant: TenantId) -> Result<rss_ledger::LedgerId, Error> {
    Ok(rss_ledger::LedgerId::new(
        tenant,
        rss_ledger::ChainId::parse(rss_audit_core::AUDIT_CHAIN_ID)
            .map_err(rss_audit_core::Error::from)?,
    ))
}

pub(crate) async fn validate_storage<T: ExecutionTimer>(
    connection: &mut PgConnection,
    integrity: &Integrity,
    control: &Control<'_, T>,
    append: bool,
) -> Result<(), Error> {
    if append {
        probe::validate(connection).await?;
    } else {
        probe::validate_read(connection).await?;
    }
    #[cfg(feature = "ledger")]
    if matches!(integrity, Integrity::Ledger(_)) {
        let clock = crate::control::LedgerClock(control.timer, control.timer.now());
        let budget = clock.budget(control, Stage::Setup);
        if append {
            rss_ledger_postgres::validate_connection(connection, &budget).await?;
        } else {
            rss_ledger_postgres::validate_read_connection(connection, &budget).await?;
        }
    }
    #[cfg(not(feature = "ledger"))]
    let _ = (integrity, control);
    Ok(())
}
