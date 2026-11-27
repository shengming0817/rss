//! Borrow the existing transaction; the host alone owns settlement and connection cleanup.
use crate::{Control, Error, Integrity, PgAudit, StagedAppend, repository};
use rss_audit_core::PreparedAuditV1;
use rss_request_context::ExecutionTimer;
use rss_transactional_messaging::transaction::LocalTxDeadlineStage as Stage;
use sqlx::{Postgres, Transaction};

impl PgAudit {
    /// Stage one exact record in the host's transaction. Never acquires or settles a connection.
    /// The host must configure server timeouts and propagate errors to rollback; cancellation
    /// does not prove that PostgreSQL stopped. Quarantine any unconfirmed connection.
    pub async fn append_in_transaction<T: ExecutionTimer>(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        request: &PreparedAuditV1,
        control: &Control<'_, T>,
    ) -> Result<StagedAppend, Error> {
        control.check(Stage::Operation)?;
        self.append_batch_in_transaction(
            tx,
            self.try_admit(std::slice::from_ref(request))?,
            control,
        )
        .await?
        .pop()
        .ok_or(Error::StorageContract)
    }
    /// Physically batch Audit writes on the original transaction and absolute budget.
    /// Results follow input order; repeated identical input returns the same record, with
    /// inserted=true only for its first occurrence. Empty input performs no database work.
    /// Ledger enhancement retains its necessary chain-order work. On any error the host must
    /// roll back the whole transaction. No GUC, isolation or settlement authority is changed.
    pub async fn append_batch_in_transaction<T: ExecutionTimer>(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        batch: crate::AdmittedBatch<'_>,
        control: &Control<'_, T>,
    ) -> Result<Vec<StagedAppend>, Error> {
        control.check(Stage::Operation)?;
        self.budget()?.check_domain(&batch)?;
        append_batch(tx, &self.integrity, &batch, control).await
    }
}

pub(crate) async fn append_batch<T: ExecutionTimer>(
    tx: &mut Transaction<'_, Postgres>,
    integrity: &Integrity,
    batch: &crate::AdmittedBatch<'_>,
    control: &Control<'_, T>,
) -> Result<Vec<StagedAppend>, Error> {
    control.check(Stage::Operation)?;
    let Some(tenant) = batch.tenant else {
        return Ok(Vec::new());
    };
    control
        .run(Stage::Operation, async {
            let input = crate::append::Batch::new(batch.records);
            let ledger: Option<Vec<(u64, bool)>> = match integrity {
                Integrity::Plain if input.conflict.is_some() => {
                    crate::probe::tenant(tx, tenant).await?;
                    return Err(Error::Conflict);
                }
                Integrity::Plain => None,
                #[cfg(feature = "ledger")]
                Integrity::Ledger(auth) => {
                    let clock = crate::control::LedgerClock(control.timer, control.timer.now());
                    let budget = clock.budget(control, Stage::Operation);
                    let positions = rss_ledger_postgres::append_batch_in_transaction(
                        tx,
                        auth,
                        &input.ledger_requests()?,
                        &budget,
                    )
                    .await?;
                    Some(crate::append::coordinates(positions))
                }
            };
            repository::append_batch(tx, tenant, &input, ledger.as_deref()).await
        })
        .await
}
