use crate::{Error, StagedAppend, borrowed};
use rss_ledger::{AppendRequest, Authenticator, LedgerId};
use rss_redact::RedactedSource;
use rss_transactional_messaging::error::MessagingErrorKind;
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
use std::sync::Arc;
/// Lock a chain before business/outbox locks without producing an event.
/// Inherits the message owner's tenant, connection and remaining budget; never settles.
pub async fn lock_head_in(
    tx: &mut PgTransaction<'_>,
    auth: Arc<Authenticator>,
    ledger: &LedgerId,
) -> Result<(), Error> {
    if tx.tenant_id() != ledger.tenant() {
        return Err(rss_ledger::Error::ScopeMismatch.into());
    }
    let ledger = ledger.clone();
    tx.with_connection(move |connection| {
        Box::pin(async move { Ok(borrowed::lock_head(connection, &auth, &ledger).await) })
    })
    .await
    .map_err(Error::Messaging)?
}

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
            // The message owner already bounds this borrow; do not start another clock.
            Ok(borrowed::append(connection, &auth, &request).await)
        })
    })
    .await
    .map_err(Error::Messaging)?
}
impl From<Error> for PgError {
    fn from(error: Error) -> Self {
        let error = match error {
            Error::Messaging(original) => return original,
            other => other,
        };
        let kind = match &error {
            Error::Messaging(original) => original.kind(),
            Error::Conflict => MessagingErrorKind::Conflict,
            Error::Deadline(_) => MessagingErrorKind::DeadlineElapsed,
            Error::Storage(_) => MessagingErrorKind::Transient,
            Error::StorageContract | Error::Admission(_) => MessagingErrorKind::Invariant,
            Error::Cancelled(_) => MessagingErrorKind::DeadlineElapsed,
            Error::Rollback { .. } => MessagingErrorKind::Transient,
            Error::Rejected | Error::ReadBudgetExceeded => MessagingErrorKind::Permanent,
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
    fn owner_error_classifications_round_trip() {
        for kind in [
            MessagingErrorKind::Transient,
            MessagingErrorKind::Permanent,
            MessagingErrorKind::Conflict,
            MessagingErrorKind::OwnershipLost,
            MessagingErrorKind::Invariant,
            MessagingErrorKind::DeadlineElapsed,
        ] {
            let error = PgError::Operation {
                kind,
                source: RedactedSource::new(std::io::Error::other("private-owner-marker")),
            };
            let wrapped = Error::Messaging(error);
            assert!(!format!("{wrapped:?}").contains("private-owner-marker"));
            assert_eq!(PgError::from(wrapped).kind(), kind);
        }
    }
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
            PgError::from(Error::ReadBudgetExceeded).kind(),
            MessagingErrorKind::Permanent
        );
        assert_eq!(
            PgError::from(Error::Conflict).kind(),
            MessagingErrorKind::Conflict
        );
    }
}
