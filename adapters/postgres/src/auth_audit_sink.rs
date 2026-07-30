//! `PgAuthAuditSink` —— httpserve auth decision flat audit sink.
//!
//! This adapter serves both the generic `diport::AuditSink` used by auth middleware and the route-specific
//! `AuditListTenantAppender` LocalTx port. Auth decision principals can be users, services, super-admins, or
//! anonymous-like rejected subjects, while the separate hash-chain audit domain keys actors as `ids::UserId`.

use std::time::UNIX_EPOCH;

#[cfg(all(test, feature = "integration"))]
use std::collections::HashMap;
#[cfg(all(test, feature = "integration"))]
use std::sync::{Arc, Mutex};

#[cfg(feature = "domain-audit")]
use audit::ports::{AuditListTenantAppend, AuditListTenantAppender};
use diport::{AuditEvent, AuditOutcome, AuditSink, AuditSinkError};

#[cfg(all(test, feature = "integration"))]
use crate::PgStore;
#[cfg(feature = "domain-audit")]
use crate::cotx::settings_audit::EncodedAuditEvent;
#[cfg(feature = "domain-audit")]
use crate::cotx::{ServingWriteLane, TenantDb};
use crate::pool::VerifiedPgWriteStore;
#[cfg(feature = "domain-audit")]
use crate::tx_retry::{classify_sqlx_error, run_pg_localtx_retry};

const INSERT_AUTH_AUDIT_EVENT: &str = "INSERT INTO auth_audit_events \
     (occurred_at_secs, occurred_at_nanos, principal_id, principal_kind, tenant_context, \
      resource_kind, resource_id, action, outcome, failure_reason, request_id, correlation_id) \
     VALUES ($1, $2, $3, $4, $5::uuid, $6, $7, $8, $9, $10, $11, $12)";

/// Flat durable sink for HTTP auth decisions.
///
/// Constructed through the postgres capability bundle; stores only the structured audit DTO supplied by httpserve.
pub struct PgAuthAuditSink {
    global_pool: sqlx::PgPool,
    #[cfg(feature = "domain-audit")]
    pool: TenantDb<ServingWriteLane>,
    #[cfg(all(test, feature = "integration"))]
    append_faults: Arc<Mutex<AuthAuditAppendFaultState>>,
}

#[cfg(all(test, feature = "integration"))]
#[derive(Clone, Copy)]
pub(crate) enum AuthAuditAppendFault {
    Permanent,
    Transient,
    TransientBeforeWrite,
    CommitUnknown,
    RollbackFailed,
}

#[cfg(all(test, feature = "integration"))]
#[derive(Clone, Copy)]
struct AuthAuditAppendFaultPlan {
    fault: AuthAuditAppendFault,
    remaining: usize,
}

#[cfg(all(test, feature = "integration"))]
#[derive(Default)]
struct AuthAuditAppendFaultState {
    plans: HashMap<String, AuthAuditAppendFaultPlan>,
    attempts: HashMap<String, usize>,
}

#[cfg(all(test, feature = "integration"))]
pub(crate) struct AuthAuditAppendAttemptProbe {
    state: Arc<Mutex<AuthAuditAppendFaultState>>,
}

#[cfg(all(test, feature = "integration"))]
impl AuthAuditAppendAttemptProbe {
    pub(crate) fn attempts(&self, tenant: vocab::TenantId) -> usize {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .attempts
            .get(&tenant.as_uuid().to_string())
            .copied()
            .unwrap_or_default()
    }
}

impl PgAuthAuditSink {
    pub(crate) fn new(store: &VerifiedPgWriteStore) -> Self {
        Self {
            global_pool: store.pool().clone(),
            #[cfg(feature = "domain-audit")]
            pool: TenantDb::<ServingWriteLane>::new(store),
            #[cfg(all(test, feature = "integration"))]
            append_faults: Arc::new(Mutex::new(AuthAuditAppendFaultState::default())),
        }
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn from_unverified_for_test(store: &PgStore) -> Self {
        Self {
            global_pool: store.pool.clone(),
            #[cfg(feature = "domain-audit")]
            pool: TenantDb::<ServingWriteLane>::from_unverified_for_test(store),
            #[cfg(all(test, feature = "integration"))]
            append_faults: Arc::new(Mutex::new(AuthAuditAppendFaultState::default())),
        }
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn with_append_fault(
        self,
        tenant: vocab::TenantId,
        fault: AuthAuditAppendFault,
        remaining: usize,
    ) -> Self {
        assert!(remaining > 0, "fault plan must affect at least one attempt");
        self.append_faults
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .plans
            .insert(
                tenant.as_uuid().to_string(),
                AuthAuditAppendFaultPlan { fault, remaining },
            );
        self
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn append_attempt_probe(&self) -> AuthAuditAppendAttemptProbe {
        AuthAuditAppendAttemptProbe {
            state: Arc::clone(&self.append_faults),
        }
    }
}

#[cfg(all(test, feature = "integration"))]
fn record_append_attempt(state: &Mutex<AuthAuditAppendFaultState>, tenant: &str) {
    let mut state = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *state.attempts.entry(tenant.to_owned()).or_default() += 1;
}

#[cfg(all(test, feature = "integration"))]
fn take_append_fault_if(
    state: &Mutex<AuthAuditAppendFaultState>,
    tenant: &str,
    predicate: impl FnOnce(AuthAuditAppendFault) -> bool,
) -> Option<AuthAuditAppendFault> {
    let mut state = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let plan = state.plans.get_mut(tenant)?;
    let fault = plan.fault;
    if !predicate(fault) {
        return None;
    }
    plan.remaining -= 1;
    if plan.remaining == 0 {
        state.plans.remove(tenant);
    }
    Some(fault)
}

#[cfg(not(feature = "domain-audit"))]
#[derive(Clone)]
struct EncodedAuditEvent {
    occurred_at_secs: i64,
    occurred_at_nanos: i32,
    principal_id: String,
    principal_kind: &'static str,
    tenant_context: Option<String>,
    resource_kind: &'static str,
    resource_id: String,
    action: &'static str,
    outcome: &'static str,
    failure_reason: Option<&'static str>,
    request_id: Option<String>,
    correlation_id: Option<String>,
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

fn actor_kind_to_db(kind: vocab::PrincipalKind) -> &'static str {
    match kind {
        vocab::PrincipalKind::User => "user",
        vocab::PrincipalKind::Device => "device",
        vocab::PrincipalKind::Admin => "admin",
        vocab::PrincipalKind::SuperAdmin => "super_admin",
        vocab::PrincipalKind::Service => "service",
        vocab::PrincipalKind::Anonymous => "anonymous",
        _ => "unknown",
    }
}

fn outcome_parts(outcome: &AuditOutcome) -> (&'static str, Option<&'static str>) {
    match outcome {
        AuditOutcome::Success => ("success", None),
        AuditOutcome::Failure { reason } => ("failure", Some(*reason)),
        _ => ("unknown", None),
    }
}

fn encode_event(event: AuditEvent) -> Result<EncodedAuditEvent, AuditSinkError> {
    let (occurred_at_secs, occurred_at_nanos) = system_time_parts(event.occurred_at)?;
    let tenant_context = tenant_context(&event);
    let principal_kind = actor_kind_to_db(event.principal_kind);
    let (outcome, failure_reason) = outcome_parts(&event.outcome);
    Ok(EncodedAuditEvent {
        occurred_at_secs,
        occurred_at_nanos,
        principal_id: event.principal_id,
        principal_kind,
        tenant_context,
        resource_kind: event.resource_kind,
        resource_id: event.resource_id,
        action: event.action,
        outcome,
        failure_reason,
        request_id: event.request_id,
        correlation_id: event.correlation_id,
    })
}

fn insert_auth_audit_event_query(
    event: EncodedAuditEvent,
) -> sqlx::query::Query<'static, sqlx::Postgres, sqlx::postgres::PgArguments> {
    sqlx::query(INSERT_AUTH_AUDIT_EVENT)
        .bind(event.occurred_at_secs)
        .bind(event.occurred_at_nanos)
        .bind(event.principal_id)
        .bind(event.principal_kind)
        .bind(event.tenant_context)
        .bind(event.resource_kind)
        .bind(event.resource_id)
        .bind(event.action)
        .bind(event.outcome)
        .bind(event.failure_reason)
        .bind(event.request_id)
        .bind(event.correlation_id)
}

impl AuditSink for PgAuthAuditSink {
    async fn record(&self, event: AuditEvent) -> Result<(), AuditSinkError> {
        let event = encode_event(event)?;
        insert_auth_audit_event_query(event)
            .execute(&self.global_pool)
            .await
            .map_err(storage)?;

        Ok(())
    }

    async fn shutdown(&self) -> Result<(), AuditSinkError> {
        Ok(())
    }
}

#[cfg(feature = "domain-audit")]
impl AuditListTenantAppender for PgAuthAuditSink {
    async fn append(&self, command: AuditListTenantAppend) -> Result<(), AuditSinkError> {
        let (scope, event, observation) = command.into_parts();
        #[cfg(all(test, feature = "integration"))]
        let tenant = scope.tenant().as_uuid().to_string();
        let event = encode_event(event)?;
        #[cfg(all(test, feature = "integration"))]
        let append_faults = Arc::clone(&self.append_faults);
        run_pg_localtx_retry(
            observation,
            |_attempt, deadline| {
                let event = event.clone();
                #[cfg(all(test, feature = "integration"))]
                let tenant = tenant.clone();
                #[cfg(all(test, feature = "integration"))]
                let append_faults = Arc::clone(&append_faults);
                #[cfg(all(test, feature = "integration"))]
                record_append_attempt(&append_faults, &tenant);
                async move {
                    self.pool
                        .retry_auth_audit_write(
                            scope,
                            deadline,
                            move |mut tx| {
                                Box::pin(async move {
                                    #[cfg(all(test, feature = "integration"))]
                                    if take_append_fault_if(&append_faults, &tenant, |fault| {
                                        matches!(fault, AuthAuditAppendFault::TransientBeforeWrite)
                                    })
                                    .is_some()
                                    {
                                        return Err(sqlx::Error::PoolTimedOut);
                                    }
                                    tx.append_event(event).await?;
                                    #[cfg(all(test, feature = "integration"))]
                                    if let Some(fault) =
                                        take_append_fault_if(&append_faults, &tenant, |fault| {
                                            !matches!(
                                                fault,
                                                AuthAuditAppendFault::TransientBeforeWrite
                                            )
                                        })
                                    {
                                        match fault {
                                            AuthAuditAppendFault::Permanent => {
                                                return Err(sqlx::Error::Protocol(
                                                    "injected auth audit append failure"
                                                        .to_string(),
                                                ));
                                            }
                                            AuthAuditAppendFault::Transient => {
                                                return Err(sqlx::Error::PoolTimedOut);
                                            }
                                            AuthAuditAppendFault::TransientBeforeWrite => {
                                                unreachable!(
                                                    "before-write fault is consumed before SQL"
                                                );
                                            }
                                            AuthAuditAppendFault::CommitUnknown => {
                                                tx.inject_commit_unknown_after_commit().await?;
                                            }
                                            AuthAuditAppendFault::RollbackFailed => {
                                                tx.inject_rollback_failed_after_rollback().await?;
                                                return Err(sqlx::Error::PoolTimedOut);
                                            }
                                        }
                                    }
                                    Ok(())
                                })
                            },
                            std::convert::identity,
                        )
                        .await
                }
            },
            classify_sqlx_error,
        )
        .await
        .map_err(storage)
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
