// rss_operator_authorization_callsite UI fixture（disallowed caller）。
#![allow(unused, unknown_lints)]

fn main() {
    let _auth = diport::DlqOperatorAuthorization::<diport::dlq_operator_action::List>::issue(
        dlqauthmint::DlqOperatorMint::capability(),
        vocab::ServiceCallerDomain::MaintenanceOperator,
        "operator".to_owned(),
        tenant(),
        audit_id(),
    );

    let _reconcile = eventexec::OperatorReconcileCapability::issue_for_authorized_operator();
    let issue_reconcile = eventexec::OperatorReconcileCapability::issue_for_authorized_operator;
    let _reconcile2 = issue_reconcile();

    let _l2 = eventexec::OperatorL2DrRecoveryCapability::issue_for_authorized_operator();
    let issue_l2 = eventexec::OperatorL2DrRecoveryCapability::issue_for_authorized_operator;
    let _l2_2 = issue_l2();

    let _harmless = HarmlessOperatorPlan::from_authenticated_and_authorized();
    let harmless = HarmlessOperatorPlan::from_authenticated_and_authorized;
    let _harmless2 = harmless();

    let _harmless_capability = HarmlessOperatorCapability::issue_for_authorized_operator();
    let harmless_issue = HarmlessOperatorCapability::issue_for_authorized_operator;
    let _harmless_capability2 = harmless_issue();

    allowed_by_attr();
}

struct HarmlessOperatorCapability;

impl HarmlessOperatorCapability {
    fn issue_for_authorized_operator() -> Self {
        Self
    }
}

struct HarmlessOperatorPlan;

impl HarmlessOperatorPlan {
    fn from_authenticated_and_authorized() -> Self {
        Self
    }
}

#[allow(rss_operator_authorization_callsite)] // reason: UI fixture 验证逃生门
fn allowed_by_attr() {
    let _auth = diport::DlqOperatorAuthorization::<diport::dlq_operator_action::List>::issue(
        dlqauthmint::DlqOperatorMint::capability(),
        vocab::ServiceCallerDomain::MaintenanceOperator,
        "operator".to_owned(),
        tenant(),
        audit_id(),
    );
}

fn tenant() -> rss_request_context::TenantId {
    rss_request_context::TenantId::parse("00000000-0000-4000-8000-000000000001").unwrap()
}

fn audit_id() -> diport::DlqOperatorStartAuditId {
    diport::DlqOperatorStartAuditId::parse("ui-audit").unwrap()
}
