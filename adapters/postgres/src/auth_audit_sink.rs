//! `PgAuthAuditSink` —— httpserve auth decision flat audit sink.
//!
//! This adapter intentionally targets `diport::AuditSink` directly instead of `audit::AuditRepo`: auth decision
//! principals can be users, services, super-admins, or anonymous-like rejected subjects, while the hash-chain audit
//! domain currently keys actors as `ids::UserId`.

use std::time::UNIX_EPOCH;

use audit::ports::actor_kind_to_db;
use diport::{AuditEvent, AuditOutcome, AuditSink, AuditSinkError};

use crate::PgStore;

const TABLE: &str = "auth_audit_events";

/// Flat durable sink for HTTP auth decisions.
///
/// Constructed through the postgres capability bundle; stores only the structured audit DTO supplied by httpserve.
pub struct PgAuthAuditSink {
    pool: sqlx::PgPool,
}

impl PgAuthAuditSink {
    pub(crate) fn new(store: &PgStore) -> Self {
        Self {
            pool: store.pool.clone(),
        }
    }
}

fn storage(e: sqlx::Error) -> AuditSinkError {
    AuditSinkError::new(e)
}

fn system_time_parts(at: std::time::SystemTime) -> Result<(i64, i32), AuditSinkError> {
    let duration = at.duration_since(UNIX_EPOCH).map_err(|e| {
        AuditSinkError::new(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("auth audit timestamp before epoch: {e}"),
        ))
    })?;
    let secs = i64::try_from(duration.as_secs()).map_err(|e| {
        AuditSinkError::new(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("auth audit timestamp out of range: {e}"),
        ))
    })?;
    let nanos = i32::try_from(duration.subsec_nanos()).map_err(|e| {
        AuditSinkError::new(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("auth audit timestamp nanos out of range: {e}"),
        ))
    })?;
    Ok((secs, nanos))
}

fn tenant_context(event: &AuditEvent) -> Option<String> {
    event.tenant_id.map(|tenant| tenant.as_uuid().to_string())
}

fn outcome_parts(outcome: &AuditOutcome) -> (&'static str, Option<&'static str>) {
    match outcome {
        AuditOutcome::Success => ("success", None),
        AuditOutcome::Failure { reason } => ("failure", Some(*reason)),
        _ => ("unknown", None),
    }
}

impl AuditSink for PgAuthAuditSink {
    async fn record(&self, event: AuditEvent) -> Result<(), AuditSinkError> {
        let (occurred_at_secs, occurred_at_nanos) = system_time_parts(event.occurred_at)?;
        let tenant_context = tenant_context(&event);
        let principal_kind = actor_kind_to_db(event.principal_kind);
        let (outcome, failure_reason) = outcome_parts(&event.outcome);

        sqlx::query(&format!(
            "INSERT INTO {TABLE} \
             (occurred_at_secs, occurred_at_nanos, principal_id, principal_kind, tenant_context, \
              resource_kind, resource_id, action, outcome, failure_reason, request_id, correlation_id) \
             VALUES ($1, $2, $3, $4, $5::uuid, $6, $7, $8, $9, $10, $11, $12)"
        ))
        .bind(occurred_at_secs)
        .bind(occurred_at_nanos)
        .bind(event.principal_id)
        .bind(principal_kind)
        .bind(tenant_context)
        .bind(event.resource_kind)
        .bind(event.resource_id)
        .bind(event.action)
        .bind(outcome)
        .bind(failure_reason)
        .bind(event.request_id)
        .bind(event.correlation_id)
        .execute(&self.pool)
        .await
        .map_err(storage)?;

        Ok(())
    }

    async fn shutdown(&self) -> Result<(), AuditSinkError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn outcome_parts_are_stable() {
        assert_eq!(outcome_parts(&AuditOutcome::Success), ("success", None));
        assert_eq!(
            outcome_parts(&AuditOutcome::Failure {
                reason: "forbidden"
            }),
            ("failure", Some("forbidden"))
        );
    }

    #[test]
    #[allow(clippy::expect_used)] // reason: const in-range UNIX_EPOCH + Duration must encode successfully.
    fn epoch_timestamp_encodes_losslessly() {
        let parts = system_time_parts(UNIX_EPOCH + Duration::new(7, 13)).expect("valid timestamp");
        assert_eq!(parts, (7, 13));
    }
}
