// rss_operator_authorization_callsite UI fixture（capability caller allowlist）。
#![allow(unused)]

fn main() {
    let _auth = diport::DlqOperatorAuthorization::<diport::dlq_operator_action::List>::issue(
        dlqauthmint::DlqOperatorMint::capability(),
        vocab::ServiceCallerDomain::MaintenanceOperator,
        "operator".to_owned(),
        rss_request_context::TenantId::parse("00000000-0000-4000-8000-000000000001").unwrap(),
        diport::DlqOperatorStartAuditId::parse("ui-audit").unwrap(),
    );
    let _reconcile = eventexec::OperatorReconcileCapability::issue_for_authorized_operator();
    let issue_reconcile = eventexec::OperatorReconcileCapability::issue_for_authorized_operator;
    let _reconcile2 = issue_reconcile();
}
