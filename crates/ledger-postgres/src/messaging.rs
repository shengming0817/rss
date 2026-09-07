use crate::{Error, StagedAppend, repository};
use rss_ledger::{AppendRequest, Authenticator};
use rss_redact::RedactedSource;
use rss_transactional_messaging::error::MessagingErrorKind;
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
use std::sync::Arc;
/// Stage in a message owner's transaction, inheriting its tenant and remaining budget.
/// Never settles, alters GUCs or opens another transaction. The returned value is staged.
/// Propagate errors through the enclosing local_tx or consumer effect to roll back.
pub async fn append_in(
    tx: &mut PgTransaction<'_>,
    auth: Arc<Authenticator>,
    request: &AppendRequest,
) -> Result<StagedAppend, Error> {
    if tx.tenant_id() != request.ledger().tenant() {
        return Err(rss_ledger::Error::ScopeMismatch.into());
    }
    let request = request.clone();
    tx.with_connection(move |connection| {
        Box::pin(async move {
            // Validate the actual borrowed database/role; the standalone pool may be different.
            Ok(async {
                crate::probe::validate_connection(connection).await?;
                repository::append(connection, &auth, &request).await
            }
            .await)
        })
    })
    .await
    .map_err(|e| Error::Storage(RedactedSource::new(e)))?
}
impl From<Error> for PgError {
    fn from(error: Error) -> Self {
        let kind = match &error {
            Error::Conflict => MessagingErrorKind::Conflict,
            Error::Deadline(_) => MessagingErrorKind::DeadlineElapsed,
            Error::Storage(_) => MessagingErrorKind::Transient,
            Error::StorageContract | Error::Admission(_) => MessagingErrorKind::Invariant,
            Error::Cancelled(_) => MessagingErrorKind::DeadlineElapsed,
            Error::Rollback { .. } => MessagingErrorKind::Transient,
            Error::Rejected => MessagingErrorKind::Permanent,
            Error::Protocol(error) => match error {
                rss_ledger::Error::InvalidInput
                | rss_ledger::Error::InvalidKey
                | rss_ledger::Error::ScopeMismatch
                | rss_ledger::Error::SequenceExhausted => MessagingErrorKind::Permanent,
                rss_ledger::Error::Authentication
                | rss_ledger::Error::SequenceGap
                | rss_ledger::Error::UnsupportedKey
                | rss_ledger::Error::UnsupportedEncoding => MessagingErrorKind::Invariant,
            },
        };
        PgError::Operation {
            kind,
            source: RedactedSource::new(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn integrity_failures_never_become_invalid_requests() {
        use rss_ledger::Error as Protocol;
        for error in [
            Protocol::Authentication,
            Protocol::SequenceGap,
            Protocol::UnsupportedKey,
            Protocol::UnsupportedEncoding,
        ] {
            assert_eq!(
                PgError::from(Error::Protocol(error)).kind(),
                MessagingErrorKind::Invariant
            );
        }
        for error in [
            Protocol::InvalidInput,
            Protocol::InvalidKey,
            Protocol::ScopeMismatch,
            Protocol::SequenceExhausted,
        ] {
            assert_eq!(
                PgError::from(Error::Protocol(error)).kind(),
                MessagingErrorKind::Permanent
            );
        }
        assert_eq!(
            PgError::from(Error::Conflict).kind(),
            MessagingErrorKind::Conflict
        );
    }
}
