// rss_dlq_operator_callsite UI fixture（runtime 非整 crate allowlist；仅最小 wrapper 允许）。
#![allow(unused)]

fn main() {
    let _cap = issue_authorized_dlq_capability();
    let _reconcile = issue_authorized_reconcile_capability();
    let _receipt = dlq_operator_receipt();
    nested_runtime_module::call_same_named_non_boundary();
    non_boundary_runtime_call();
}

fn issue_authorized_reconcile_capability() -> eventexec::OperatorReconcileCapability {
    eventexec::OperatorReconcileCapability::issue_for_authorized_operator()
}

fn issue_authorized_dlq_capability() -> eventexec::OperatorDlqCapability {
    eventexec::OperatorDlqCapability::issue_for_authorized_operator()
}

fn dlq_operator_receipt() -> eventexec::AuthorizedDlqOperatorReceipt {
    eventexec::AuthorizedDlqOperatorReceipt::from_authenticated_and_authorized(
        vocab::ServiceCallerDomain::MaintenanceOperator,
    )
}

fn non_boundary_runtime_call() {
    let _cap = eventexec::OperatorDlqCapability::issue_for_authorized_operator();
    let _receipt = eventexec::AuthorizedDlqOperatorReceipt::from_authenticated_and_authorized(
        vocab::ServiceCallerDomain::MaintenanceOperator,
    );
}

mod nested_runtime_module {
    pub fn call_same_named_non_boundary() {
        let _cap = issue_authorized_dlq_capability();
        let _receipt = dlq_operator_receipt();
    }

    fn issue_authorized_dlq_capability() -> eventexec::OperatorDlqCapability {
        eventexec::OperatorDlqCapability::issue_for_authorized_operator()
    }

    fn dlq_operator_receipt() -> eventexec::AuthorizedDlqOperatorReceipt {
        eventexec::AuthorizedDlqOperatorReceipt::from_authenticated_and_authorized(
            vocab::ServiceCallerDomain::MaintenanceOperator,
        )
    }
}
