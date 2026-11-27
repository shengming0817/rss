//! Pool-free borrowing of the existing fenced transaction and its budget.
use crate::{Error, Integrity, StagedAppend, repository};
use rss_audit_core::PreparedAuditV1;
use rss_redact::RedactedSource;
use rss_transactional_messaging::error::MessagingErrorKind;
use rss_transactional_messaging_postgres::{PgError, PgTransaction};

/// Validate the actual borrowed writer connection at startup; never acquires or settles.
pub async fn validate_in(tx: &mut PgTransaction<'_>, integrity: &Integrity) -> Result<(), Error> {
    tx.with_connection(|c| Box::pin(async move { Ok(crate::probe::validate(c).await) }))
        .await??;
    #[cfg(feature = "ledger")]
    if matches!(integrity, Integrity::Ledger(_)) {
        rss_ledger_postgres::validate_in(tx).await?;
    }
    #[cfg(not(feature = "ledger"))]
    let _ = integrity;
    Ok(())
}
/// Acquire the selected Ledger chain before business locks. Plain never acquires a tenant head.
/// This is not a reservation or proof of commit; the original owner retains settlement.
pub async fn lock_head_in(tx: &mut PgTransaction<'_>, integrity: &Integrity) -> Result<(), Error> {
    let tenant = tx.tenant_id();
    tx.with_connection(move |c| Box::pin(async move { Ok(crate::probe::tenant(c, tenant).await) }))
        .await??;
    #[cfg(feature = "ledger")]
    if let Integrity::Ledger(auth) = integrity {
        rss_ledger_postgres::lock_head_in(tx, auth.clone(), &crate::runtime::ledger_id(tenant)?)
            .await?;
    }
    #[cfg(not(feature = "ledger"))]
    let _ = integrity;
    Ok(())
}
impl crate::WriteBudget {
    /// Stage one exact prepared record. Propagate errors to the original transaction owner.
    pub async fn append_in(
        &self,
        tx: &mut PgTransaction<'_>,
        integrity: &Integrity,
        request: &PreparedAuditV1,
    ) -> Result<StagedAppend, Error> {
        self.append_batch_in(
            tx,
            integrity,
            self.try_admit(std::slice::from_ref(request))?,
        )
        .await?
        .pop()
        .ok_or(Error::StorageContract)
    }
    /// Physically batch Audit writes on the original connection and remaining budget.
    /// Results follow input order. Empty input does no persistence; conflicts require whole-transaction
    /// rollback. The host supplies stable bytes and owns unknown-result recovery. No settings or
    /// settlement authority change; optional Ledger work retains its necessary chain ordering.
    pub async fn append_batch_in(
        &self,
        tx: &mut PgTransaction<'_>,
        integrity: &Integrity,
        batch: crate::AdmittedBatch<'_>,
    ) -> Result<Vec<StagedAppend>, Error> {
        self.check_domain(&batch)?;
        let Some(tenant) = batch.tenant else {
            return Ok(Vec::new());
        };
        if tenant != tx.tenant_id() {
            return Err(Error::ScopeMismatch);
        }
        // Fencing and expiry belong to the message owner, including on invalid input.
        let mut records = batch.records;
        let plain = matches!(integrity, Integrity::Plain);
        let input = tx
            .with_connection_context(&mut records, move |records, c| {
                let records = *records;
                Box::pin(async move {
                    let input = crate::append::Batch::new(records);
                    if plain && input.conflict.is_some() {
                        return Ok(crate::probe::tenant(c, tenant)
                            .await
                            .and(Err(Error::Conflict)));
                    }
                    Ok(Ok(input))
                })
            })
            .await??;
        let ledger: Option<Vec<(u64, bool)>> = match integrity {
            Integrity::Plain => None,
            #[cfg(feature = "ledger")]
            Integrity::Ledger(auth) => {
                let positions =
                    rss_ledger_postgres::append_batch_in(tx, auth, &input.ledger_requests()?)
                        .await?;
                Some(crate::append::coordinates(positions))
            }
        };
        // The context borrow carries the owner's cutoff and can include non-static prepared input.
        tx.with_connection_context(&mut (input, ledger), move |(input, ledger), c| {
            Box::pin(async move {
                Ok(repository::append_batch(c, tenant, input, ledger.as_deref()).await)
            })
        })
        .await?
    }
}

impl From<Error> for PgError {
    fn from(error: Error) -> Self {
        // Preserve the original message owner's closed classification without an error side channel.
        let kind = match error {
            Error::Messaging(original) => return original,
            #[cfg(feature = "ledger")]
            Error::Ledger(original) => return original.into(),
            Error::WriteBusy => MessagingErrorKind::Transient,
            Error::WriteLimit => MessagingErrorKind::Permanent,
            Error::Conflict => MessagingErrorKind::Conflict,
            Error::Deadline(_) | Error::Cancelled(_) => MessagingErrorKind::DeadlineElapsed,
            Error::Admission(_) | Error::StorageContract => MessagingErrorKind::Invariant,
            Error::Storage {
                kind: crate::StorageFailure::Transient,
                ..
            }
            | Error::Rollback { .. } => MessagingErrorKind::Transient,
            Error::Storage {
                kind: crate::StorageFailure::Permanent,
                ..
            } => MessagingErrorKind::Permanent,
            Error::ScopeMismatch
            | Error::InvalidBound
            | Error::ReadBudgetExceeded
            | Error::IntegrityRequired
            | Error::Protocol(_) => MessagingErrorKind::Permanent,
        };
        Self::Operation {
            kind,
            source: RedactedSource::new(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserves_all_owner_classifications() {
        for kind in [
            MessagingErrorKind::Transient,
            MessagingErrorKind::Permanent,
            MessagingErrorKind::Conflict,
            MessagingErrorKind::OwnershipLost,
            MessagingErrorKind::Invariant,
            MessagingErrorKind::DeadlineElapsed,
        ] {
            let original = PgError::Operation {
                kind,
                source: RedactedSource::new(std::io::Error::other("sensitive provider text")),
            };
            let returned = PgError::from(Error::from(original));
            assert_eq!(returned.kind(), kind);
            assert!(!format!("{returned:?}").contains("sensitive"));
        }
    }
}
