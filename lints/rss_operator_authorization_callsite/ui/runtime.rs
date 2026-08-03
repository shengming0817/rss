// rss_operator_authorization_callsite UI fixture（runtime 非整 crate allowlist；仅精确 wrapper 允许）。
#![allow(unused)]

fn main() {
    let _cap = operator::dlq::issue_authorized_dlq_capability();
    let _reconcile = operator::reconcile::issue_authorized_reconcile_capability();
    let _l2 = operator::dr_recovery::issue_authorized_l2_dr_recovery_capability();
    let _receipt = operator::dlq::dlq_operator_receipt();
    nested_runtime_module::call_same_named_non_boundary();
    non_boundary_runtime_call();
}

mod operator {
    pub(super) mod reconcile {
        pub(crate) fn issue_authorized_reconcile_capability()
        -> eventexec::OperatorReconcileCapability {
            eventexec::OperatorReconcileCapability::issue_for_authorized_operator()
        }
    }

    pub(super) mod dlq {
        pub(crate) fn issue_authorized_dlq_capability() -> eventexec::OperatorDlqCapability {
            eventexec::OperatorDlqCapability::issue_for_authorized_operator()
        }

        pub(crate) fn dlq_operator_receipt() -> eventexec::AuthorizedDlqOperatorReceipt {
            eventexec::AuthorizedDlqOperatorReceipt::from_authenticated_and_authorized(
                vocab::ServiceCallerDomain::MaintenanceOperator,
            )
        }
    }

    pub(super) mod dr_recovery {
        pub(crate) fn issue_authorized_l2_dr_recovery_capability()
        -> eventexec::OperatorL2DrRecoveryCapability {
            eventexec::OperatorL2DrRecoveryCapability::issue_for_authorized_operator()
        }

        pub(crate) fn execute_connected_l2_dr_recovery(
            plan: eventexec::L2DrRecoveryPlan,
            proof: eventexec::L2DrRecoveryDurableStartProof,
            capability: eventexec::OperatorL2DrRecoveryCapability,
        ) -> Result<eventexec::AuthorizedL2DrRecoveryPlan, eventexec::L2DrRecoveryError> {
            eventexec::AuthorizedL2DrRecoveryPlan::from_authenticated_and_authorized(
                plan, proof, capability,
            )
        }
    }
}

fn non_boundary_runtime_call() {
    let _cap = eventexec::OperatorDlqCapability::issue_for_authorized_operator();
    let _receipt = eventexec::AuthorizedDlqOperatorReceipt::from_authenticated_and_authorized(
        vocab::ServiceCallerDomain::MaintenanceOperator,
    );
    let issue = eventexec::OperatorDlqCapability::issue_for_authorized_operator;
    let _cap2 = issue();
    let authorize = eventexec::AuthorizedDlqOperatorReceipt::from_authenticated_and_authorized;
    let _receipt2 = authorize(vocab::ServiceCallerDomain::MaintenanceOperator);
    let _l2 = eventexec::OperatorL2DrRecoveryCapability::issue_for_authorized_operator();
}

fn direct_l2_recovery_plan_call(
    plan: eventexec::L2DrRecoveryPlan,
    proof: eventexec::L2DrRecoveryDurableStartProof,
    capability: eventexec::OperatorL2DrRecoveryCapability,
) {
    let _ = eventexec::AuthorizedL2DrRecoveryPlan::from_authenticated_and_authorized(
        plan, proof, capability,
    );
}

fn l2_recovery_plan_function_item(
    plan: eventexec::L2DrRecoveryPlan,
    proof: eventexec::L2DrRecoveryDurableStartProof,
    capability: eventexec::OperatorL2DrRecoveryCapability,
) {
    let authorize = eventexec::AuthorizedL2DrRecoveryPlan::from_authenticated_and_authorized;
    let _ = authorize(plan, proof, capability);
}

mod nested_runtime_module {
    pub fn call_same_named_non_boundary() {
        let _cap = issue_authorized_dlq_capability();
        let _receipt = dlq_operator_receipt();
        let issue = eventexec::OperatorDlqCapability::issue_for_authorized_operator;
        let _cap2 = issue();
        let authorize = eventexec::AuthorizedDlqOperatorReceipt::from_authenticated_and_authorized;
        let _receipt2 = authorize(vocab::ServiceCallerDomain::MaintenanceOperator);
        let _l2 = issue_authorized_l2_dr_recovery_capability();
    }

    fn issue_authorized_dlq_capability() -> eventexec::OperatorDlqCapability {
        eventexec::OperatorDlqCapability::issue_for_authorized_operator()
    }

    fn dlq_operator_receipt() -> eventexec::AuthorizedDlqOperatorReceipt {
        eventexec::AuthorizedDlqOperatorReceipt::from_authenticated_and_authorized(
            vocab::ServiceCallerDomain::MaintenanceOperator,
        )
    }

    fn issue_authorized_l2_dr_recovery_capability() -> eventexec::OperatorL2DrRecoveryCapability {
        eventexec::OperatorL2DrRecoveryCapability::issue_for_authorized_operator()
    }

    fn execute_connected_l2_dr_recovery(
        plan: eventexec::L2DrRecoveryPlan,
        proof: eventexec::L2DrRecoveryDurableStartProof,
        capability: eventexec::OperatorL2DrRecoveryCapability,
    ) -> Result<eventexec::AuthorizedL2DrRecoveryPlan, eventexec::L2DrRecoveryError> {
        eventexec::AuthorizedL2DrRecoveryPlan::from_authenticated_and_authorized(
            plan, proof, capability,
        )
    }
}
