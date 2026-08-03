// rss_operator_authorization_callsite UI fixture（disallowed caller）。
#![allow(unused, unknown_lints)]

fn main() {
    let _cap = eventexec::OperatorDlqCapability::issue_for_authorized_operator();

    let issue = eventexec::OperatorDlqCapability::issue_for_authorized_operator;
    let _cap2 = issue();

    let _reconcile = eventexec::OperatorReconcileCapability::issue_for_authorized_operator();
    let issue_reconcile = eventexec::OperatorReconcileCapability::issue_for_authorized_operator;
    let _reconcile2 = issue_reconcile();

    let _l2 = eventexec::OperatorL2DrRecoveryCapability::issue_for_authorized_operator();
    let issue_l2 = eventexec::OperatorL2DrRecoveryCapability::issue_for_authorized_operator;
    let _l2_2 = issue_l2();

    let _receipt = eventexec::AuthorizedDlqOperatorReceipt::from_authenticated_and_authorized(
        vocab::ServiceCallerDomain::MaintenanceOperator,
    );
    let authorize = eventexec::AuthorizedDlqOperatorReceipt::from_authenticated_and_authorized;
    let _receipt2 = authorize(vocab::ServiceCallerDomain::MaintenanceOperator);

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
    let _cap = eventexec::OperatorDlqCapability::issue_for_authorized_operator();
}
