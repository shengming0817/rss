// rss_operator_authorization_callsite UI fixture（capability caller allowlist）。
#![allow(unused)]

fn main() {
    let _cap = eventexec::OperatorDlqCapability::issue_for_authorized_operator();
    let issue = eventexec::OperatorDlqCapability::issue_for_authorized_operator;
    let _cap2 = issue();
    let _reconcile = eventexec::OperatorReconcileCapability::issue_for_authorized_operator();
    let issue_reconcile = eventexec::OperatorReconcileCapability::issue_for_authorized_operator;
    let _reconcile2 = issue_reconcile();
    let _receipt = eventexec::AuthorizedDlqOperatorReceipt::from_authenticated_and_authorized(
        vocab::ServiceCallerDomain::MaintenanceOperator,
    );
    let authorize = eventexec::AuthorizedDlqOperatorReceipt::from_authenticated_and_authorized;
    let _receipt2 = authorize(vocab::ServiceCallerDomain::MaintenanceOperator);
}
