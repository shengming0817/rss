//! Shared transaction kernel adapted from baseline cotx/settlement.rs.
use crate::PgConfig;
use futures::future::BoxFuture;
use rss_redact::RedactedSource;
use rss_request_context::TenantId;
use rss_transactional_messaging::{
    error::{MessagingError, MessagingErrorKind},
    policy::{
        AbsoluteDeadline, Clock, ExecutionTimer, MonotonicInstant, OperationDeadline, within,
    },
    transaction::{LocalTxAttempt, LocalTxDeadlineStage},
};
use sqlx::{
    Connection as _, PgConnection, PgPool, Postgres, Transaction, pool::PoolConnection,
    postgres::PgPoolOptions,
};
use std::sync::Arc;

/// Closed, non-sensitive storage-contract diagnostic returned by the live catalog probe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PgStorageContractFailure {
    /// Version or retention policy do not match this adapter.
    Policy,
    /// Runtime role isolation do not match this adapter.
    RuntimeRole,
    /// Relay role posture do not match this adapter.
    RelayRole,
    /// Column types or nullability do not match this adapter.
    Columns,
    /// Constraint definitions or unique keys do not match this adapter.
    Constraints,
    /// Column defaults or generated identity do not match this adapter.
    Defaults,
    /// Runtime table, sequence, schema or ownership permissions do not match this adapter.
    RuntimeAcl,
    /// Relay table, sequence or schema permissions do not match this adapter.
    RelayAcl,
    /// Row-security policy descriptors do not match this adapter.
    RlsPolicy,
    /// Definer ownership, search path or execution permissions do not match this adapter.
    Functions,
}
impl PgStorageContractFailure {
    /// Stable diagnostic label, never containing database identities or provider text.
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Policy => "policy",
            Self::RuntimeRole => "runtime_role",
            Self::RelayRole => "relay_role",
            Self::Columns => "columns",
            Self::Constraints => "constraints",
            Self::Defaults => "defaults",
            Self::RuntimeAcl => "runtime_acl",
            Self::RelayAcl => "relay_acl",
            Self::RlsPolicy => "rls_policy",
            Self::Functions => "functions",
        }
    }
    fn from_label(label: &str) -> Option<Self> {
        match label {
            "policy" => Some(Self::Policy),
            "runtime_role" => Some(Self::RuntimeRole),
            "relay_role" => Some(Self::RelayRole),
            "columns" => Some(Self::Columns),
            "constraints" => Some(Self::Constraints),
            "defaults" => Some(Self::Defaults),
            "runtime_acl" => Some(Self::RuntimeAcl),
            "relay_acl" => Some(Self::RelayAcl),
            "rls_policy" => Some(Self::RlsPolicy),
            "functions" => Some(Self::Functions),
            _ => None,
        }
    }
}
/// Safely redacted PostgreSQL failures. Transaction outcome is carried separately.
#[derive(Debug, thiserror::Error)]
pub enum PgError {
    /// Authentication failed; credentials must be corrected before retrying.
    #[error("PostgreSQL authentication failed")]
    Authentication(#[source] RedactedSource),
    /// The configured database does not exist.
    #[error("PostgreSQL database is missing")]
    DatabaseMissing(#[source] RedactedSource),
    /// The current operation requires permissions absent from the effective role.
    #[error("PostgreSQL permission denied")]
    PermissionDenied(#[source] RedactedSource),
    /// Invalid connection identity or credentials.
    #[error("invalid PostgreSQL connection configuration")]
    InvalidConnectionConfig,
    /// Invalid pool size.
    #[error("invalid PostgreSQL pool limits")]
    InvalidPoolLimits,
    /// A positive acquisition bound is required.
    #[error("invalid PostgreSQL acquire timeout")]
    InvalidAcquireTimeout,
    /// Lease must be an integral number of milliseconds between 1ms and 24h.
    #[error("invalid PostgreSQL lease duration: expected integral milliseconds in 1ms..=24h")]
    InvalidLeaseDuration,
    /// Own schema or effective permissions do not match this adapter.
    #[error("incompatible transactional messaging storage contract: {}", .0.as_label())]
    IncompatibleStorageContract(PgStorageContractFailure),
    /// Own schema could not be inspected because required objects or permissions are absent.
    #[error("PostgreSQL storage contract probe failed")]
    StorageContractProbe(#[source] RedactedSource),
    /// A classified error with no raw provider text in its source chain.
    #[error("PostgreSQL operation failed: {}", .kind.as_label())]
    Operation {
        /// Stable classification.
        kind: MessagingErrorKind,
        /// Redacted provider diagnostic.
        #[source]
        source: RedactedSource,
    },
}

impl PgError {
    fn probe(source: sqlx::Error) -> Self {
        match Self::from(source) {
            Self::PermissionDenied(source) => Self::StorageContractProbe(source),
            Self::Operation {
                kind: MessagingErrorKind::Invariant,
                source,
            } => Self::StorageContractProbe(source),
            error => error,
        }
    }
    /// Stable error classification, independent from transaction settlement outcome.
    #[must_use]
    pub const fn kind(&self) -> MessagingErrorKind {
        match self {
            Self::Operation { kind, .. } => *kind,
            Self::IncompatibleStorageContract(_) | Self::StorageContractProbe(_) => {
                MessagingErrorKind::Invariant
            }
            _ => MessagingErrorKind::Permanent,
        }
    }
    pub(crate) fn classified<E: std::error::Error + Send + Sync + 'static>(
        kind: MessagingErrorKind,
        source: E,
    ) -> Self {
        Self::Operation {
            kind,
            source: RedactedSource::new(source),
        }
    }
    pub(crate) fn invariant() -> Self {
        Self::classified(
            MessagingErrorKind::Invariant,
            std::io::Error::other("invalid durable state"),
        )
    }
    pub(crate) fn lost() -> Self {
        Self::classified(
            MessagingErrorKind::OwnershipLost,
            std::io::Error::other("lease lost"),
        )
    }
    pub(crate) fn port(self) -> MessagingError {
        MessagingError::new(self.kind(), self)
    }
}
impl From<sqlx::Error> for PgError {
    fn from(source: sqlx::Error) -> Self {
        if let sqlx::Error::Database(error) = &source {
            match error.code().as_deref() {
                Some("28000" | "28P01") => {
                    return Self::Authentication(RedactedSource::new(source));
                }
                Some("3D000") => return Self::DatabaseMissing(RedactedSource::new(source)),
                Some("42501") => return Self::PermissionDenied(RedactedSource::new(source)),
                _ => {}
            }
        }
        let kind = match &source {
            sqlx::Error::Io(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::InvalidData | std::io::ErrorKind::InvalidInput
                ) =>
            {
                MessagingErrorKind::Permanent
            }
            sqlx::Error::Io(_) | sqlx::Error::PoolTimedOut | sqlx::Error::WorkerCrashed => {
                MessagingErrorKind::Transient
            }
            // A closed pool never reopens; retrying against the same runtime cannot succeed.
            sqlx::Error::PoolClosed | sqlx::Error::Configuration(_) | sqlx::Error::Tls(_) => {
                MessagingErrorKind::Permanent
            }
            sqlx::Error::Database(error) => sqlstate_kind(error.code().as_deref()),
            _ => MessagingErrorKind::Invariant,
        };
        Self::classified(kind, source)
    }
}
fn sqlstate_kind(code: Option<&str>) -> MessagingErrorKind {
    match code {
        Some("28000" | "28P01" | "3D000" | "42501") => MessagingErrorKind::Permanent,
        Some("23505" | "23P01") => MessagingErrorKind::Conflict,
        Some("40001" | "40P01" | "55P03" | "57014") => MessagingErrorKind::Transient,
        Some(value)
            if value.starts_with("08")
                || value.starts_with("53")
                || value.starts_with("57")
                || value.starts_with("58") =>
        {
            MessagingErrorKind::Transient
        }
        Some(value) if value.starts_with("22") || value.starts_with("23") => {
            MessagingErrorKind::Permanent
        }
        _ => MessagingErrorKind::Invariant,
    }
}
impl From<MessagingError> for PgError {
    fn from(source: MessagingError) -> Self {
        Self::classified(source.kind(), source)
    }
}

// Internal type erasure keeps clock injection independent of public store/effect type parameters.
trait Timer: Send + Sync {
    fn now(&self) -> MonotonicInstant;
    fn sleep(&self, deadline: AbsoluteDeadline) -> BoxFuture<'_, ()>;
}
impl<C: ExecutionTimer> Timer for C {
    fn now(&self) -> MonotonicInstant {
        Clock::now(self)
    }
    fn sleep(&self, deadline: AbsoluteDeadline) -> BoxFuture<'_, ()> {
        Box::pin(self.sleep_until(deadline))
    }
}
pub(crate) struct PgTimer(Arc<dyn Timer>);
impl Clock for PgTimer {
    fn now(&self) -> MonotonicInstant {
        self.0.now()
    }
}
impl ExecutionTimer for PgTimer {
    fn sleep_until(&self, deadline: AbsoluteDeadline) -> impl Future<Output = ()> + Send {
        self.0.sleep(deadline)
    }
}

/// One private I/O watchdog and redacted phase diagnostic shared by all transaction owners.
pub(crate) async fn stage<T: Send, F>(
    timer: &PgTimer,
    cutoff: AbsoluteDeadline,
    phase: LocalTxDeadlineStage,
    future: F,
) -> Result<T, PgError>
where
    F: Future<Output = Result<T, sqlx::Error>> + Send,
{
    let result = match within(timer, cutoff, |_| future).await {
        Ok(result) => result.map_err(PgError::from),
        Err(error) => Err(error.into()),
    };
    if let Err(error) = &result {
        tracing::warn!(phase = phase.as_label(), kind = error.kind().as_label(), error = ?error, "PostgreSQL transaction stage failed");
    }
    result
}

/// Shared bounded pool. A caller supplies a timer sharing the runtime's monotonic time domain.
pub struct PgRuntime {
    pub(crate) pool: PgPool,
    pub(crate) timer: PgTimer,
    #[cfg(feature = "integration")]
    fault: std::sync::atomic::AtomicU8,
}

/// Integration-only transport uncertainty injected into the next acquired transaction.
#[cfg(feature = "integration")]
#[derive(Clone, Copy)]
#[repr(u8)]
pub enum PgTransactionFault {
    /// Execute COMMIT but suppress its ACK from the transaction owner.
    CommitUnknownAfterAck = 1,
    /// Execute ROLLBACK but suppress its ACK from the transaction owner.
    RollbackFailedAfterAck = 2,
    /// Hold COMMIT pending until the shared deadline or cancellation drops it.
    CommitPending = 3,
}

impl PgRuntime {
    /// Connect and validate only this package's schema and effective permissions.
    pub async fn connect<C: ExecutionTimer + 'static>(
        config: PgConfig,
        timer: C,
    ) -> Result<Self, PgError> {
        config.validate()?;
        let timer = PgTimer(Arc::new(timer));
        let cutoff = AbsoluteDeadline::from_timeout(&timer, config.acquire_timeout)
            .map_err(|_| PgError::invariant())?;
        let pool = within(&timer, cutoff, |_| async {
            PgPoolOptions::new()
                .min_connections(config.min_connections)
                .max_connections(config.max_connections)
                .acquire_timeout(config.acquire_timeout)
                .test_before_acquire(true)
                .connect_with(config.connect_options())
                .await
        })
        .await??;
        let runtime = Self {
            pool,
            timer,
            #[cfg(feature = "integration")]
            fault: std::sync::atomic::AtomicU8::new(0),
        };
        let failure = within(&runtime.timer, cutoff, |_| async {
            sqlx::query_scalar::<_, String>(include_str!("probe.sql"))
                .fetch_optional(&runtime.pool)
                .await
        })
        .await?
        .map_err(PgError::probe)?;
        if let Some(reason) = failure {
            let reason =
                PgStorageContractFailure::from_label(&reason).ok_or_else(PgError::invariant)?;
            tracing::warn!(
                phase = "probe",
                reason = reason.as_label(),
                "PostgreSQL storage contract rejected"
            );
            return Err(PgError::IncompatibleStorageContract(reason));
        }
        Ok(runtime)
    }

    /// Execute one tenant-bound transaction under one cutoff, including settlement.
    ///
    /// Only acknowledged commit/rollback permits connection reuse. Dropped futures quarantine
    /// their connection; cancellation alone does not prove that effects were rolled back.
    pub async fn local_tx<T: Send, F>(
        &self,
        tenant: TenantId,
        deadline: OperationDeadline,
        operation: F,
    ) -> LocalTxAttempt<T, PgError>
    where
        F: for<'a> FnOnce(&'a mut PgTransaction<'_>) -> BoxFuture<'a, Result<T, PgError>> + Send,
    {
        self.local_tx_with_context(tenant, deadline, (), move |_, tx| operation(tx))
            .await
    }

    /// Execute with application context reborrowed for the transaction. Context can contain
    /// non-static references; this retains the same single cutoff and settlement owner.
    pub async fn local_tx_with_context<T: Send, C: Send, F>(
        &self,
        tenant: TenantId,
        deadline: OperationDeadline,
        mut context: C,
        operation: F,
    ) -> LocalTxAttempt<T, PgError>
    where
        F: for<'a> FnOnce(
                &'a mut C,
                &'a mut PgTransaction<'_>,
            ) -> BoxFuture<'a, Result<T, PgError>>
            + Send,
    {
        let cutoff = match AbsoluteDeadline::from_timeout(&self.timer, deadline.timeout()) {
            Ok(value) => value,
            Err(_) => return LocalTxAttempt::not_started(PgError::invariant()),
        };
        let mut lease = match stage(
            &self.timer,
            cutoff,
            LocalTxDeadlineStage::Acquire,
            self.acquire(),
        )
        .await
        {
            Ok(value) => value,
            Err(error) => return LocalTxAttempt::not_started(error),
        };
        let mut transaction = match stage(
            &self.timer,
            cutoff,
            LocalTxDeadlineStage::Begin,
            lease.begin(),
        )
        .await
        {
            Ok(value) => value,
            Err(error) => return LocalTxAttempt::not_started(error),
        };
        let mut view = PgTransaction {
            connection: transaction.connection(),
            tenant,
            cutoff,
            timer: &self.timer,
        };
        let result = within(&self.timer, cutoff, |_| async {
            view.setup().await?;
            operation(&mut context, &mut view).await
        })
        .await;
        let result = match result {
            Ok(result) => result,
            Err(error) => return LocalTxAttempt::commit_unknown(error.into()),
        };
        if cutoff.remaining(&self.timer).is_zero() {
            return LocalTxAttempt::commit_unknown(PgError::classified(
                MessagingErrorKind::DeadlineElapsed,
                std::io::Error::other("transaction deadline elapsed"),
            ));
        }
        match result {
            Ok(value) => match stage(
                &self.timer,
                cutoff,
                LocalTxDeadlineStage::Commit,
                transaction.commit(),
            )
            .await
            {
                Ok(()) => LocalTxAttempt::committed(value),
                Err(error) => LocalTxAttempt::commit_unknown(error),
            },
            Err(error) => match stage(
                &self.timer,
                cutoff,
                LocalTxDeadlineStage::Rollback,
                transaction.rollback(),
            )
            .await
            {
                Ok(()) => {
                    if matches!(
                        error,
                        PgError::Operation {
                            kind: MessagingErrorKind::OwnershipLost,
                            ..
                        }
                    ) {
                        LocalTxAttempt::fenced(error)
                    } else {
                        LocalTxAttempt::rolled_back(error)
                    }
                }
                Err(source) => LocalTxAttempt::rollback_failed(source),
            },
        }
    }

    /// Stop pool admission and wait for all pooled connections to be released and closed.
    ///
    /// Closing starts when this future is first polled. Existing transactions retain their
    /// settlement authority and deadlines; closing does not abort them. The host must stop
    /// admitting work and apply its shutdown budget around this future. Cancelling the wait
    /// leaves the pool closed, and another call can resume waiting. Repeated and concurrent
    /// calls are safe. Dropping the runtime is not a substitute for awaiting graceful close.
    pub async fn close(&self) {
        self.pool.close().await;
    }

    /// Whether pool admission has stopped, not whether graceful close has completed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.pool.is_closed()
    }

    /// Inject only into a fixture-owned runtime; concurrent transactions consume this once.
    #[cfg(feature = "integration")]
    pub fn inject_next_transaction_fault(&self, fault: PgTransactionFault) {
        self.fault
            .store(fault as u8, std::sync::atomic::Ordering::SeqCst);
    }

    pub(crate) async fn acquire(&self) -> Result<ConnectionLease, sqlx::Error> {
        let lease = ConnectionLease::acquire(&self.pool).await?;
        #[cfg(feature = "integration")]
        let mut lease = lease;
        #[cfg(feature = "integration")]
        {
            lease.fault = self.fault.swap(0, std::sync::atomic::Ordering::SeqCst);
        }
        Ok(lease)
    }

    // SECURITY DEFINER calls use the same quarantine lease but no fabricated tenant identity.
    pub(crate) async fn relay<T: Send, F>(
        &self,
        cutoff: AbsoluteDeadline,
        operation: F,
    ) -> Result<T, PgError>
    where
        F: for<'a> FnOnce(&'a mut PgConnection) -> BoxFuture<'a, Result<T, PgError>> + Send,
    {
        let mut lease = stage(
            &self.timer,
            cutoff,
            LocalTxDeadlineStage::Acquire,
            self.acquire(),
        )
        .await?;
        let mut transaction = stage(
            &self.timer,
            cutoff,
            LocalTxDeadlineStage::Begin,
            lease.begin(),
        )
        .await?;
        let result = within(&self.timer, cutoff, |_| async {
            let millis = cutoff.remaining(&self.timer).as_millis().max(1);
            sqlx::query("SELECT set_config('rss.tenant_id', '', true), set_config('statement_timeout', $1, true)")
                .bind(format!("{millis}ms")).execute(transaction.connection()).await?;
            operation(transaction.connection()).await
        }).await.unwrap_or_else(|error| Err(error.into()));
        match result {
            Ok(value) => {
                stage(
                    &self.timer,
                    cutoff,
                    LocalTxDeadlineStage::Commit,
                    transaction.commit(),
                )
                .await?;
                Ok(value)
            }
            Err(error) => {
                stage(
                    &self.timer,
                    cutoff,
                    LocalTxDeadlineStage::Rollback,
                    transaction.rollback(),
                )
                .await?;
                Err(error)
            }
        }
    }
}

pub(crate) fn settled<T>(attempt: LocalTxAttempt<T, PgError>) -> Result<T, PgError> {
    attempt.fold(Ok, Err, Err, Err, Err, Err)
}
#[cfg(feature = "rss-runtime")]
impl rss_runtime::ManagedResource for PgRuntime {
    fn name(&self) -> &str {
        "postgres-transactional-messaging"
    }
    async fn shutdown(&self) -> Result<(), rss_runtime::ShutdownError> {
        PgRuntime::close(self).await;
        Ok(())
    }
}

/// Borrowed tenant transaction for trusted companion infrastructure, not application handlers.
///
/// The borrow cannot escape or yield a pool handle. Arbitrary SQL can still change transaction
/// state or tenant settings: this is a trusted extension point, not a SQL security sandbox.
///
/// ```compile_fail
/// use rss_transactional_messaging_postgres::{PgTransaction, PgError};
/// async fn escape(tx: &mut PgTransaction<'_>) -> Result<&'static mut sqlx::PgConnection, PgError> {
///     tx.with_connection(|connection| Box::pin(async move { Ok(connection) })).await
/// }
/// ```
pub struct PgTransaction<'tx> {
    pub(crate) connection: &'tx mut PgConnection,
    tenant: TenantId,
    cutoff: AbsoluteDeadline,
    timer: &'tx PgTimer,
}
impl PgTransaction<'_> {
    pub(crate) fn new<'a>(
        connection: &'a mut PgConnection,
        tenant: TenantId,
        cutoff: AbsoluteDeadline,
        timer: &'a PgTimer,
    ) -> PgTransaction<'a> {
        PgTransaction {
            connection,
            tenant,
            cutoff,
            timer,
        }
    }
    pub(crate) async fn setup(&mut self) -> Result<(), PgError> {
        let millis = self.cutoff.remaining(self.timer).as_millis().max(1);
        stage(self.timer, self.cutoff, LocalTxDeadlineStage::Setup,
            sqlx::query("SELECT set_config('rss.tenant_id', $1, true), set_config('statement_timeout', $2, true)")
                .bind(self.tenant.to_string()).bind(format!("{millis}ms")).execute(&mut *self.connection)).await?;
        Ok(())
    }
    /// Tenant bound by the transaction owner.
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant
    }
    /// Current remaining budget, never a fresh timeout.
    #[must_use]
    pub fn deadline(&self) -> OperationDeadline {
        self.cutoff.operation(self.timer)
    }
    /// Borrow the connection for a bounded SQL operation. No lifecycle authority is transferred.
    pub async fn with_connection<T: Send, F>(&mut self, operation: F) -> Result<T, PgError>
    where
        F: for<'a> FnOnce(&'a mut PgConnection) -> BoxFuture<'a, Result<T, sqlx::Error>> + Send,
    {
        stage(
            self.timer,
            self.cutoff,
            LocalTxDeadlineStage::Operation,
            operation(self.connection),
        )
        .await
    }
}

// ref: baseline/pre-community-core-20260902:adapters/postgres/src/cotx/settlement.rs
// ref: launchbadge/sqlx sqlx-core/src/transaction.rs@v0.8.6
pub(crate) struct ConnectionLease {
    connection: PoolConnection<Postgres>,
    quarantine: bool,
    #[cfg(feature = "integration")]
    fault: u8,
}
impl ConnectionLease {
    pub(crate) async fn acquire(pool: &PgPool) -> Result<Self, sqlx::Error> {
        Ok(Self {
            connection: pool.acquire().await?,
            quarantine: true,
            #[cfg(feature = "integration")]
            fault: 0,
        })
    }
    pub(crate) async fn begin(&mut self) -> Result<BorrowedTransaction<'_>, sqlx::Error> {
        let transaction = (*self.connection).begin().await?;
        Ok(BorrowedTransaction {
            transaction,
            quarantine: &mut self.quarantine,
            #[cfg(feature = "integration")]
            fault: self.fault,
        })
    }
}
impl Drop for ConnectionLease {
    fn drop(&mut self) {
        if self.quarantine {
            self.connection.close_on_drop();
        }
    }
}
pub(crate) struct BorrowedTransaction<'a> {
    transaction: Transaction<'a, Postgres>,
    quarantine: &'a mut bool,
    #[cfg(feature = "integration")]
    fault: u8,
}
impl BorrowedTransaction<'_> {
    pub(crate) fn connection(&mut self) -> &mut PgConnection {
        &mut self.transaction
    }
    pub(crate) async fn commit(self) -> Result<(), sqlx::Error> {
        #[cfg(feature = "integration")]
        if self.fault == PgTransactionFault::CommitPending as u8 {
            std::future::pending::<()>().await;
        }
        self.transaction.commit().await?;
        #[cfg(feature = "integration")]
        if self.fault == PgTransactionFault::CommitUnknownAfterAck as u8 {
            return Err(sqlx::Error::PoolTimedOut);
        }
        *self.quarantine = false;
        Ok(())
    }
    pub(crate) async fn rollback(self) -> Result<(), sqlx::Error> {
        self.transaction.rollback().await?;
        #[cfg(feature = "integration")]
        if self.fault == PgTransactionFault::RollbackFailedAfterAck as u8 {
            return Err(sqlx::Error::PoolTimedOut);
        }
        *self.quarantine = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn probe_preserves_transient_failures() {
        for source in [
            sqlx::Error::PoolTimedOut,
            sqlx::Error::Io(std::io::Error::other("secret endpoint")),
        ] {
            let error = PgError::probe(source);
            assert_eq!(error.kind(), MessagingErrorKind::Transient);
            assert!(!format!("{error:?}").contains("secret endpoint"));
        }
        assert!(matches!(
            PgError::probe(sqlx::Error::ColumnNotFound("missing".into())),
            PgError::StorageContractProbe(_)
        ));
    }
    #[test]
    fn closed_pool_is_not_retryable() {
        assert_eq!(
            PgError::from(sqlx::Error::PoolClosed).kind(),
            MessagingErrorKind::Permanent
        );
        assert_eq!(
            PgError::probe(sqlx::Error::PoolClosed).kind(),
            MessagingErrorKind::Permanent
        );
    }
    #[test]
    fn sql_errors_have_closed_safe_classifications() {
        for (code, expected) in [
            ("23505", MessagingErrorKind::Conflict),
            ("23514", MessagingErrorKind::Permanent),
            ("40001", MessagingErrorKind::Transient),
            ("08006", MessagingErrorKind::Transient),
            ("42501", MessagingErrorKind::Permanent),
            ("42P01", MessagingErrorKind::Invariant),
            ("22003", MessagingErrorKind::Permanent),
            ("28P01", MessagingErrorKind::Permanent),
            ("3D000", MessagingErrorKind::Permanent),
        ] {
            assert_eq!(sqlstate_kind(Some(code)), expected);
        }
        assert_eq!(sqlstate_kind(None), MessagingErrorKind::Invariant);
        assert_eq!(
            PgError::from(sqlx::Error::PoolTimedOut).kind(),
            MessagingErrorKind::Transient
        );
        let error = PgError::from(sqlx::Error::ColumnNotFound("secret-column".into()));
        assert_eq!(error.kind(), MessagingErrorKind::Invariant);
        assert!(!format!("{error:?}").contains("secret-column"));
    }
}
