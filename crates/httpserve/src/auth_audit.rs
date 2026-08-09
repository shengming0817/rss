//! Authentication/authorization audit enrichment after the decision is closed.
//!
//! This module is deliberately separate from `auth`: ambient diagnostic context may annotate an
//! already-decided audit event, but it cannot flow into authentication or authorization branches.

use diport::{AuditEvent, AuditSinkError};

use crate::auth::{AuthAudit, AuthDecision, Authenticated, AuthenticatedAuditEvent};

fn auth_audit_event(
    audit: &AuthAudit,
    decision: AuthDecision,
    contract_id: &'static str,
    rid: &str,
    evidence: &Authenticated,
) -> AuditEvent {
    evidence.audit_event(AuthenticatedAuditEvent {
        occurred_at: audit.now(),
        tenant_id: evidence.tenant_id(),
        resource_kind: "http_route",
        resource_id: contract_id.to_string(),
        action: "httpserve:authz",
        outcome: decision.audit_outcome(),
        request_id: (!rid.is_empty()).then(|| rid.to_string()),
        correlation_id: diagctx::correlation().map(|c| c.as_str().to_string()),
    })
}

pub(crate) async fn record_auth_audit(
    audit: Option<AuthAudit>,
    decision: AuthDecision,
    contract_id: &'static str,
    rid: String,
    evidence: Option<Authenticated>,
) -> Result<(), AuditSinkError> {
    let Some(audit) = audit else {
        return Ok(());
    };
    let Some(evidence) = evidence else {
        return Ok(());
    };
    let event = auth_audit_event(&audit, decision, contract_id, &rid, &evidence);
    audit.record(event).await
}
