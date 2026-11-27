//! Identity-owned event meaning; Audit only persists the exact prepared records.
mod mapping;
#[cfg(test)]
mod tests;
use crate::transaction::{MAX_MUTATION_EVENTS, SecurityEvent, corrupt};
use rss_audit_postgres::Integrity;
use rss_identity_core::InstanceId;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgError, PgTransaction};

pub(crate) async fn append_events(
    tx: &mut PgTransaction<'_>,
    integrity: &Integrity,
    budget: &rss_audit_postgres::WriteBudget,
    instance: InstanceId,
    tenant: TenantId,
    events: Vec<SecurityEvent>,
) -> Result<(), PgError> {
    if tx.tenant_id() != tenant || events.len() > MAX_MUTATION_EVENTS {
        return Err(corrupt());
    }
    if events.is_empty() {
        return Ok(());
    }
    let now: i64 = tx
        .with_connection(|c| {
            Box::pin(async move {
                sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                    .fetch_one(c)
                    .await
            })
        })
        .await?;
    let now = rss_contract::Timepoint::try_from(now).map_err(|_| corrupt())?;
    let records = events
        .iter()
        .map(|event| {
            let event = mapping::map_event(instance, tenant, uuid::Uuid::new_v4(), now, event)
                .map_err(|_| corrupt())?;
            rss_audit_core::prepare(event, now).map_err(|_| corrupt())
        })
        .collect::<Result<Vec<_>, PgError>>()?;
    budget.append_batch_in(tx, integrity, budget.try_admit(&records)?)
        .await
        .map_err(|error| match error {
            rss_audit_postgres::Error::Conflict
            | rss_audit_postgres::Error::ScopeMismatch
            | rss_audit_postgres::Error::Protocol(_) => corrupt(),
            other => other.into(),
        })?;
    Ok(())
}
