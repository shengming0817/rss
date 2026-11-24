//! ref: launchbadge/sqlx sqlx-core/src/transaction.rs and pool/inner.rs@v0.9.0
//! ref: baseline 5b63e10 adapters/postgres/src/cotx/settlement.rs
use crate::probe::Identity;
use futures::future::BoxFuture;
use rss_reconcile::{Control, Error, ErrorKind, Scope, Timer};
use rss_request_context::TenantId;
use sqlx::{Connection, PgConnection, PgPool, Postgres, pool::PoolConnection};
#[cfg(feature = "integration")]
use std::sync::Arc;
use std::{future::Future, time::Duration};
use tokio::runtime::Handle;
use tokio_util::task::{TaskTracker, task_tracker::TaskTrackerToken};

/// One database operation with a host-owned admission permit. Consumed by the
/// selected operation; dropping an unused handle returns its permit.
#[must_use = "use the admitted operation or drop it to release its permit"]
pub struct PgOperation<'a, P> {
    store: &'a PgStore,
    admission: Admission<P>,
}

struct Admission<P> {
    // Field order: release host capacity before declaring the operation drained.
    _permit: P,
    _tracked: TaskTrackerToken,
}

/// Component storage handle. The caller configures transport/TLS on the supplied pool.
/// Closing this handle closes that pool and all of its clones.
#[derive(Clone)]
pub struct PgStore {
    pub(crate) pool: PgPool,
    identity: Identity,
    operations: TaskTracker,
    #[cfg(feature = "integration")]
    pub(crate) fault: Arc<std::sync::atomic::AtomicU8>,
}
impl PgStore {
    /// Adopt a runtime pool after checking schema identity, RLS and role separation.
    /// No migrations or role grants are executed.
    pub async fn new<T: Timer>(pool: PgPool, control: &Control<'_, T>) -> Result<Self, Error> {
        let identity = control.run(crate::probe::validate(&pool)).await?;
        Ok(Self {
            pool,
            identity,
            operations: TaskTracker::new(),

            #[cfg(feature = "integration")]
            fault: Arc::new(std::sync::atomic::AtomicU8::new(0)),
        })
    }
    /// Hand off an already acquired permit. The host owns scheduling policy.
    /// A closed pool rejects the handoff and immediately releases the permit.
    pub fn with_permit<P: Send + 'static>(&self, permit: P) -> Result<PgOperation<'_, P>, Error> {
        let admission = Admission {
            _permit: permit,
            _tracked: self.operations.token(),
        };
        if self.pool.is_closed() {
            return Err(map_sql(sqlx::Error::PoolClosed));
        }
        Ok(PgOperation {
            store: self,
            admission,
        })
    }

    /// Close admission immediately, then drain within the supplied cancellation/deadline.
    /// An interrupted drain leaves the pool closed; outstanding borrowers still own their work.
    pub async fn close<T: Timer>(&self, control: &Control<'_, T>) -> CloseOutcome {
        let drain = self.pool.close(); // SQLx marks closed synchronously before returning its future.
        self.operations.close();
        match control
            .run(async {
                drain.await;
                self.operations.wait().await;
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
        self.with_permit(())?
            .local_tx(scope, control, operation)
            .await
    }
    /// Inject one settlement fault into the next transaction on this handle and its clones.
    #[cfg(feature = "integration")]
    pub fn inject_next_fault(&self, fault: PgFault) {
        self.fault
            .store(fault as u8, std::sync::atomic::Ordering::SeqCst);
    }
}
impl<P: Send + 'static> PgOperation<'_, P> {
    /// Execute trusted application SQL and component writes in one tenant-bound transaction.
    /// Only an acknowledged commit returns Ok. Callback errors roll back the entire transaction.
    pub async fn local_tx<T: Timer, R: Send, F>(
        self,
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
        self,
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
        self,
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
        self,
        tenant: TenantId,
        timeout: Duration,

        mut context: C,
        operation: F,
    ) -> Result<R, Error>
    where
        F: for<'c> FnOnce(&'c mut C, &'c mut PgTransaction<'_>) -> BoxFuture<'c, Result<R, E>>
            + Send,
    {
        let connection = self.store.pool.acquire().await.map_err(map_sql)?;
        let mut lease = Lease {
            live: Some((connection, self.admission)),
            runtime: Handle::current(),
        };
        let (connection, _) = lease
            .live
            .as_mut()
            .ok_or(Error::new(ErrorKind::Invariant))?;
        let mut tx = connection.begin().await.map_err(map_sql)?;
        #[cfg(feature = "integration")]
        let fault = self
            .store
            .fault
            .swap(0, std::sync::atomic::Ordering::SeqCst);
        let result = async {
            setup(&mut tx, tenant, timeout, &self.store.identity).await?;
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
                lease.recycle();
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
                if error.kind() != ErrorKind::StorageContract {
                    lease.recycle();
                }
                Err(error)
            }
        }
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
// ref: sqlx-core 0.9.0 pool/connection.rs. return_to_pool eagerly takes
// the live connection; dropping its future releases that exact pool slot.
struct Lease<P> {
    live: Option<(PoolConnection<Postgres>, Admission<P>)>,
    runtime: Handle,
}
struct Returning<F, P> {
    // If the runtime discards an unpolled task, release the floating connection first.
    work: F,
    admission: Admission<P>,
}
impl<F: Future, P> Returning<F, P> {
    async fn finish(self) {
        self.work.await;
        drop(self.admission);
    }
}
impl<P: Send + 'static> Lease<P> {
    fn recycle(mut self) {
        if let Some((mut connection, admission)) = self.live.take() {
            let returning = Returning {
                work: tokio::time::timeout(Duration::from_secs(5), connection.return_to_pool()),
                admission,
            };
            self.runtime.spawn(returning.finish());
        }
    }
}
impl<P> Drop for Lease<P> {
    fn drop(&mut self) {
        if let Some((connection, admission)) = self.live.take() {
            let _entered = self.runtime.enter();
            // Unsettled or cancelled: retire the socket synchronously. Never
            // enqueue an uncertain connection for an untracked background return.
            drop(connection.detach());
            drop(admission);
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
    identity: &Identity,
) -> Result<(), Error> {
    let millis = i32::try_from(timeout.as_millis().max(1))
        .map_err(|_| Error::new(ErrorKind::InvalidInput))?
        .to_string();
    let valid: bool = sqlx::query_scalar("SELECT session_user::text=$3 AND current_user::text=$4 AND current_database()::text=$5, set_config('rss.tenant_id',$1,true), set_config('statement_timeout',$2,true), set_config('lock_timeout',$2,true)")
        .bind(tenant.to_string()).bind(millis).bind(&identity.login).bind(&identity.role).bind(&identity.database)
        .fetch_one(connection).await.map_err(map_sql)?;
    if valid {
        Ok(())
    } else {
        Err(Error::new(ErrorKind::StorageContract))
    }
}
pub(crate) fn map_sql(error: sqlx::Error) -> Error {
    let kind = classify(&error);
    Error::provider(kind, error)
}
fn classify(error: &sqlx::Error) -> ErrorKind {
    match error {
        sqlx::Error::Database(db) => code_kind(db.code().as_deref()),
        sqlx::Error::Io(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::InvalidInput | std::io::ErrorKind::InvalidData
            ) =>
        {
            ErrorKind::Permanent
        }
        sqlx::Error::Io(_) | sqlx::Error::PoolTimedOut | sqlx::Error::WorkerCrashed => {
            ErrorKind::Transient
        }
        sqlx::Error::PoolClosed
        | sqlx::Error::Tls(_)
        | sqlx::Error::Configuration(_)
        | sqlx::Error::InvalidArgument(_)
        | sqlx::Error::Encode(_) => ErrorKind::Permanent,
        _ => ErrorKind::StorageContract,
    }
}
fn code_kind(code: Option<&str>) -> ErrorKind {
    match code {
        Some("P1001" | "22008" | "22015") => ErrorKind::InvalidInput,
        Some("P1002") => ErrorKind::Fenced,
        Some("P1003") => ErrorKind::InvalidInput,
        Some("P1004") => ErrorKind::BindingChanged,
        Some("P1005") => ErrorKind::StorageContract,
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
    // Explicit recoverable conditions only; a class also contains configuration/protocol failures.
    // ref: PostgreSQL 16 Appendix A (errcodes-appendix.html).
    matches!(
        code,
        "08000"
            | "08001"
            | "08003"
            | "08006"
            | "08007"
            | "40001"
            | "40P01"
            | "53200"
            | "53300"
            | "55P03"
            | "57014"
            | "57P01"
            | "57P02"
            | "57P03"
    )
}
fn application_sql(error: sqlx::Error) -> Error {
    let kind = if classify(&error) == ErrorKind::Transient {
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

#[cfg(test)]
mod regression {
    use super::*;
    #[test]
    fn structural_sqlx_errors_are_not_retryable() {
        for error in [
            sqlx::Error::RowNotFound,
            sqlx::Error::ColumnNotFound("secret-column".into()),
            sqlx::Error::ColumnIndexOutOfBounds { index: 9, len: 1 },
            sqlx::Error::Decode(Box::new(std::io::Error::other("secret-value"))),
            sqlx::Error::ColumnDecode {
                index: "secret-column".into(),
                source: Box::new(std::io::Error::other("secret-value")),
            },
            sqlx::Error::Configuration(Box::new(std::io::Error::other("secret-dsn"))),
            sqlx::Error::PoolClosed,
            sqlx::Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "secret",
            )),
        ] {
            assert_ne!(classify(&error), ErrorKind::Transient);
            let result = application_sql(error);
            assert_ne!(result.kind(), ErrorKind::Transient);
            assert!(!format!("{result:?} {result}").contains("secret"));
        }
    }
    #[test]
    fn sqlstate_recovery_contract() {
        for code in ["55P03", "08006", "40001", "40P01", "53300", "57014"] {
            assert_eq!(code_kind(Some(code)), ErrorKind::Transient, "{code}");
        }
        for code in [
            "28P01", "28000", "3D000", "42703", "42P01", "42501", "ZZ999", "58P01", "58P02",
            "57P04", "53400", "08P01", "40002", "53100",
        ] {
            assert_ne!(code_kind(Some(code)), ErrorKind::Transient, "{code}");
        }
        assert_ne!(code_kind(None), ErrorKind::Transient);
    }
    #[test]
    fn temporary_transport_is_retryable() {
        for error in [
            sqlx::Error::PoolTimedOut,
            sqlx::Error::Io(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "secret",
            )),
        ] {
            assert_eq!(application_sql(error).kind(), ErrorKind::Transient);
        }
    }
}
