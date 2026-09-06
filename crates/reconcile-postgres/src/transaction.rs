//! ref: launchbadge/sqlx sqlx-core/src/transaction.rs and pool/inner.rs@v0.9.0
//! ref: baseline 5b63e10 adapters/postgres/src/cotx/settlement.rs
use futures::future::BoxFuture;
use rss_reconcile::{Control, Error, ErrorKind, Scope, Timer};
use rss_request_context::TenantId;
use sqlx::{Connection, PgConnection, PgPool, Postgres, pool::PoolConnection};
#[cfg(feature = "integration")]
use std::sync::Arc;
use std::time::Duration;

/// Component storage handle. The caller configures transport/TLS on the supplied pool.
/// Closing this handle closes that pool and all of its clones.
#[derive(Clone)]
pub struct PgStore {
    pub(crate) pool: PgPool,
    #[cfg(feature = "integration")]
    pub(crate) fault: Arc<std::sync::atomic::AtomicU8>,
}
impl PgStore {
    /// Adopt a runtime pool after checking schema identity, RLS and role separation.
    /// No migrations or role grants are executed.
    pub async fn new<T: Timer>(pool: PgPool, control: &Control<'_, T>) -> Result<Self, Error> {
        control.run(crate::probe::validate(&pool)).await?;
        Ok(Self {
            pool,

            #[cfg(feature = "integration")]
            fault: Arc::new(std::sync::atomic::AtomicU8::new(0)),
        })
    }
    /// Close admission immediately, then drain within the supplied cancellation/deadline.
    /// An interrupted drain leaves the pool closed; outstanding borrowers still own their work.
    pub async fn close<T: Timer>(&self, control: &Control<'_, T>) -> CloseOutcome {
        let drain = self.pool.close(); // SQLx marks closed synchronously before returning its future.
        match control
            .run(async {
                drain.await;
                Ok(())
            })
            .await
        {
            Ok(()) => CloseOutcome::Drained,
            Err(error) if error.kind() == ErrorKind::Cancelled => CloseOutcome::Cancelled,
            Err(_) => CloseOutcome::Deadline,
        }
    }
    /// Execute trusted application SQL and component writes in one tenant-bound transaction.
    /// Only an acknowledged commit returns Ok. Callback errors roll back the entire transaction.
    pub async fn local_tx<T: Timer, R: Send, F>(
        &self,
        scope: &Scope,
        control: &Control<'_, T>,
        operation: F,
    ) -> Result<R, Error>
    where
        F: for<'c> FnOnce(&'c mut PgTransaction<'_>) -> BoxFuture<'c, Result<R, PgOperationError>>
            + Send,
    {
        control.check()?;
        control
            .run(
                self.transact(scope.tenant(), control.remaining(), (), move |_, tx| {
                    operation(tx)
                }),
            )
            .await
            .map_err(Error::uncertain)
    }

    pub(crate) async fn controlled_tx<T: Timer, R: Send, F>(
        &self,
        scope: &Scope,
        control: &Control<'_, T>,
        operation: F,
    ) -> Result<R, Error>
    where
        F: for<'c> FnOnce(&'c mut PgTransaction<'_>) -> BoxFuture<'c, Result<R, Error>> + Send,
    {
        control.check()?;
        control
            .run(
                self.transact(scope.tenant(), control.remaining(), (), move |_, tx| {
                    operation(tx)
                }),
            )
            .await
            .map_err(Error::uncertain)
    }
    pub(crate) async fn context_tx<T: Timer, R: Send, C: Send, F>(
        &self,
        scope: &Scope,
        control: &Control<'_, T>,
        context: C,
        operation: F,
    ) -> Result<R, Error>
    where
        F: for<'c> FnOnce(&'c mut C, &'c mut PgTransaction<'_>) -> BoxFuture<'c, Result<R, Error>>
            + Send,
    {
        control.check()?;
        control
            .run(self.transact(scope.tenant(), control.remaining(), context, operation))
            .await
            .map_err(Error::uncertain)
    }
    pub(crate) async fn transact<R: Send, E: Into<Error> + Send, C: Send, F>(
        &self,
        tenant: TenantId,
        timeout: Duration,
        mut context: C,
        operation: F,
    ) -> Result<R, Error>
    where
        F: for<'c> FnOnce(&'c mut C, &'c mut PgTransaction<'_>) -> BoxFuture<'c, Result<R, E>>
            + Send,
    {
        let mut lease = Lease {
            connection: self.pool.acquire().await.map_err(map_sql)?,
            quarantine: true,
        };
        crate::probe::validate_connection(&mut lease.connection).await?;
        let mut tx = lease.connection.begin().await.map_err(map_sql)?;
        #[cfg(feature = "integration")]
        let fault = self.fault.swap(0, std::sync::atomic::Ordering::SeqCst);
        let result = async {
            setup(&mut tx, tenant, timeout).await?;
            operation(
                &mut context,
                &mut PgTransaction {
                    connection: &mut tx,
                    tenant,
                },
            )
            .await
            .map_err(Into::into)
        }
        .await;
        match result {
            Ok(value) => {
                #[cfg(feature = "integration")]
                if fault == PgFault::CommitPending as u8 {
                    std::future::pending::<()>().await;
                }
                tx.commit()
                    .await
                    .map_err(|e| Error::provider(ErrorKind::CommitUnknown, e))?;
                #[cfg(feature = "integration")]
                if fault == PgFault::CommitUnknownAfterAck as u8 {
                    return Err(Error::new(ErrorKind::CommitUnknown));
                }
                lease.quarantine = false;
                Ok(value)
            }
            Err(error) => {
                tx.rollback()
                    .await
                    .map_err(|e| Error::provider(ErrorKind::RollbackFailed, e))?;
                #[cfg(feature = "integration")]
                if fault == PgFault::RollbackFailedAfterAck as u8 {
                    return Err(Error::new(ErrorKind::RollbackFailed));
                }
                lease.quarantine = false;
                Err(error)
            }
        }
    }
    /// Inject one settlement fault into the next transaction on this handle and its clones.
    #[cfg(feature = "integration")]
    pub fn inject_next_fault(&self, fault: PgFault) {
        self.fault
            .store(fault as u8, std::sync::atomic::Ordering::SeqCst);
    }
}
/// Integration-only settlement faults; never enabled by default.
#[cfg(feature = "integration")]
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum PgFault {
    /// Commit completes but its acknowledgment is hidden from the caller.
    CommitUnknownAfterAck = 1,
    /// Commit remains pending until interrupted, exercising connection quarantine.
    CommitPending = 2,
    /// Rollback completes but its acknowledgment is hidden.
    RollbackFailedAfterAck = 3,
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
/// Borrowed trusted SQL capability. No pool or transaction settlement handle is exposed.
/// Raw SQL is trusted application code, not a sandbox against transaction-control statements.
pub struct PgTransaction<'a> {
    pub(crate) connection: &'a mut PgConnection,
    tenant: TenantId,
}
impl PgTransaction<'_> {
    /// Tenant bound by the enclosing transaction.
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }
    /// Execute trusted SQL on this same transaction. Do not issue transaction/session control
    /// or change tenant settings. Application tables must enforce their own RLS policy.
    pub async fn with_connection<R: Send, F>(&mut self, operation: F) -> Result<R, PgOperationError>
    where
        F: for<'a> FnOnce(&'a mut PgConnection) -> BoxFuture<'a, Result<R, sqlx::Error>> + Send,
    {
        operation(self.connection)
            .await
            .map_err(|e| PgOperationError(application_sql(e)))
    }
}
async fn setup(
    connection: &mut PgConnection,
    tenant: TenantId,
    timeout: Duration,
) -> Result<(), Error> {
    let millis = timeout.as_millis().clamp(1, i32::MAX as u128).to_string();
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true), set_config('statement_timeout',$2,true), set_config('lock_timeout',$2,true)")
        .bind(tenant.to_string()).bind(millis).execute(connection).await.map_err(map_sql)?;
    Ok(())
}
pub(crate) fn map_sql(error: sqlx::Error) -> Error {
    let kind = match &error {
        sqlx::Error::Database(db) => code_kind(db.code().as_deref()),
        sqlx::Error::Io(_) | sqlx::Error::PoolTimedOut => ErrorKind::Transient,
        sqlx::Error::PoolClosed | sqlx::Error::Tls(_) => ErrorKind::Permanent,
        _ => ErrorKind::StorageContract,
    };
    Error::provider(kind, error)
}
fn code_kind(code: Option<&str>) -> ErrorKind {
    match code {
        Some("P1001") => ErrorKind::InvalidInput,
        Some("P1002") => ErrorKind::Fenced,
        Some("P1003") => ErrorKind::InvalidInput,
        Some("P1004") => ErrorKind::InvalidInput,
        Some("23514" | "22003") => ErrorKind::InvalidInput,
        Some("42501" | "42P01" | "42883") => ErrorKind::StorageContract,
        Some(code) if transient_code(code) => ErrorKind::Transient,
        Some(code)
            if ["22", "23", "28"]
                .iter()
                .any(|class| code.starts_with(class)) =>
        {
            ErrorKind::Permanent
        }
        _ => ErrorKind::StorageContract,
    }
}
fn transient_code(code: &str) -> bool {
    code == "55P03"
        || ["08", "40", "53", "57", "58"]
            .iter()
            .any(|class| code.starts_with(class))
}
fn application_sql(error: sqlx::Error) -> Error {
    let code = error.as_database_error().and_then(|e| e.code());
    let transient = code.as_deref().is_none_or(transient_code);
    let kind = if transient {
        ErrorKind::Transient
    } else {
        ErrorKind::Permanent
    };
    Error::provider(kind, error)
}
/// Pool admission is closed in every outcome. An interrupted drain can be retried explicitly.
#[must_use = "inspect whether the pool drained or still has outstanding borrowers"]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseOutcome {
    /// Every connection returned and the pool finished draining.
    Drained,
    /// Cancellation interrupted draining; outstanding connections may remain.
    Cancelled,
    /// Deadline interrupted draining; outstanding connections may remain.
    Deadline,
}
/// Failure returned by an application operation. Provider-only decisions cannot be constructed
/// by application callbacks; errors from borrowed component operations can be propagated.
/// ```compile_fail
/// use rss_reconcile::{Error, ErrorKind};
/// use rss_reconcile_postgres::PgOperationError;
/// let forged: PgOperationError = Error::new(ErrorKind::CommitUnknown).into();
/// ```
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct PgOperationError(#[source] pub(crate) Error);
impl PgOperationError {
    /// Reject the application operation; the adapter will roll back before returning it.
    pub const fn rejected() -> Self {
        Self(Error::new(ErrorKind::Permanent))
    }
    /// Report an application dependency failure without asserting provider settlement.
    pub fn unavailable<E: std::error::Error + Send + Sync + 'static>(source: E) -> Self {
        Self(Error::provider(ErrorKind::Transient, source))
    }
}

impl From<PgOperationError> for Error {
    fn from(error: PgOperationError) -> Self {
        error.0
    }
}

#[cfg(test)]
mod classification {
    use super::*;
    #[test]
    fn unknown_sql_states_are_not_retryable() {
        assert!(transient_code("55P03"));
        assert!(!transient_code("55000"));
        for (code, expected) in [
            ("P1002", ErrorKind::Fenced),
            ("23514", ErrorKind::InvalidInput),
            ("08006", ErrorKind::Transient),
            ("40001", ErrorKind::Transient),
            ("55P03", ErrorKind::Transient),
            ("55000", ErrorKind::StorageContract),
            ("42804", ErrorKind::StorageContract),
            ("23503", ErrorKind::Permanent),
            ("22000", ErrorKind::Permanent),
            ("ZZ999", ErrorKind::StorageContract),
        ] {
            assert_eq!(code_kind(Some(code)), expected, "{code}");
        }
    }
}
