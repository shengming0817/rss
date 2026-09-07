//! Narrow archive pool. Neither raw SQL nor the underlying runtime escapes this capability.
use rss_request_context::ExecutionTimer;
mod repository;
use crate::{PgConfig, PgError, PgRuntime};
use rss_transactional_messaging::{policy::OperationDeadline, transaction::LocalTxAttempt};
use rss_transactional_messaging_recovery::archive::Error;
/// PostgreSQL archive capability with private transaction authority.
pub struct PgArchiveRepository {
    runtime: PgRuntime,
}
impl PgArchiveRepository {
    /// Validate the archive schema and a dedicated, least-privilege archive role.
    pub async fn connect<C: ExecutionTimer + 'static>(
        config: PgConfig,
        timer: C,
        binding: rss_transactional_messaging::fence::ExecutionBinding,
    ) -> Result<Self, Error> {
        Ok(Self {
            runtime: PgRuntime::connect_profile(
                config,
                timer,
                binding,
                crate::transaction::Profile::Archive,
            )
            .await
            .map_err(error)?,
        })
    }
    /// Close the privately owned pool.
    pub async fn close(&self) {
        self.runtime.close().await;
    }
    /// Inject one transaction fault for real-provider recovery verification.
    #[cfg(feature = "integration")]
    pub fn inject_next_transaction_fault(&self, fault: crate::PgTransactionFault) {
        self.runtime.inject_next_transaction_fault(fault);
    }
}
fn error(e: PgError) -> Error {
    match e {
        PgError::Archive(value) => return value,
        PgError::IncompatibleStorageContract(_)
        | PgError::StorageContractProbe(_)
        | PgError::PermissionDenied(_) => return Error::StorageContract,
        _ => {}
    }
    match e.kind() {
        rss_transactional_messaging::error::MessagingErrorKind::Conflict
        | rss_transactional_messaging::error::MessagingErrorKind::OwnershipLost => Error::Conflict,
        rss_transactional_messaging::error::MessagingErrorKind::DeadlineElapsed => Error::Deadline,
        rss_transactional_messaging::error::MessagingErrorKind::Invariant => Error::Evidence,
        _ => Error::Unavailable,
    }
}
fn attempt<T>(v: LocalTxAttempt<T, PgError>) -> LocalTxAttempt<T, Error> {
    v.fold(
        LocalTxAttempt::committed,
        |e| LocalTxAttempt::not_started(error(e)),
        |e| LocalTxAttempt::rolled_back(error(e)),
        |e| LocalTxAttempt::rollback_failed(error(e)),
        |e| LocalTxAttempt::commit_unknown(error(e)),
        |e| LocalTxAttempt::fenced(error(e)),
    )
}
pub(crate) async fn check(runtime: &PgRuntime, deadline: OperationDeadline) -> Result<(), PgError> {
    let cutoff = rss_request_context::Deadline::from_timeout(&runtime.timer, deadline.timeout())
        .map_err(|_| PgError::invariant())?;
    let valid = rss_transactional_messaging::policy::within(&runtime.timer, cutoff, |_| async {
        sqlx::query_scalar::<_, bool>(include_str!("probe.sql"))
            .fetch_one(&runtime.pool)
            .await
    })
    .await?
    .map_err(PgError::probe)?;
    if valid {
        Ok(())
    } else {
        Err(PgError::Archive(Error::StorageContract))
    }
}

fn sql_error(error: sqlx::Error) -> PgError {
    if matches!(&error,sqlx::Error::Database(db) if db.code().as_deref()==Some("PZ001")) {
        return PgError::classified(
            rss_transactional_messaging::error::MessagingErrorKind::OwnershipLost,
            Error::Conflict,
        );
    }
    let kind = match &error {
        sqlx::Error::Database(db) => match db.code().as_deref() {
            Some("PZ002") => Some(Error::Missing),
            Some("PZ003") => Some(Error::Evidence),
            Some("P0002") => Some(Error::NotFound),
            Some("22023") => Some(Error::Retention),
            Some("40001") => Some(Error::Conflict),
            Some("55P03") => Some(Error::Busy),
            Some("23514") => Some(Error::Evidence),
            Some("42501" | "42P01" | "42703" | "42883") => Some(Error::StorageContract),
            _ => None,
        },
        _ => None,
    };
    match kind {
        Some(kind) => PgError::Archive(kind),
        None => error.into(),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn archive_size_projections_match_core() {
        let limit = rss_transactional_messaging_recovery::archive::MAX_OBJECT_BYTES;
        assert!(
            crate::ARCHIVE_UPGRADE_SQL
                .contains(&format!("octet_length(prepared) BETWEEN 1 AND {limit}"))
        );
        assert!(include_str!("probe.sql").contains(&format!("octet_length(prepared) <= {limit}")));
    }
}
