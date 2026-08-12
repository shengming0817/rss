// rss_operator_authorization_callsite UI fixture（runtime 非整 crate allowlist；仅精确 wrapper 允许）。
#![allow(unused)]

fn main() {
    let _auth = operator::dlq::issue_dlq_authorization::<diport::dlq_operator_action::List>();
    let _reconcile = operator::reconcile::issue_authorized_reconcile_capability();
    let _l2 = operator::dr_recovery::issue_authorized_l2_dr_recovery_capability();
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
        pub(crate) fn issue_dlq_authorization<A: diport::DlqOperatorAction>()
        -> diport::DlqOperatorAuthorization<A> {
            diport::DlqOperatorAuthorization::issue(
                dlqauthmint::DlqOperatorMint::capability(),
                vocab::ServiceCallerDomain::MaintenanceOperator,
                "operator".to_owned(),
                super::super::tenant(),
                super::super::audit_id(),
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
    let _auth = diport::DlqOperatorAuthorization::<diport::dlq_operator_action::List>::issue(
        dlqauthmint::DlqOperatorMint::capability(),
        vocab::ServiceCallerDomain::MaintenanceOperator,
        "operator".to_owned(),
        tenant(),
        audit_id(),
    );
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
        let _auth = issue_dlq_authorization::<diport::dlq_operator_action::List>();
        let _l2 = issue_authorized_l2_dr_recovery_capability();
    }

    fn issue_dlq_authorization<A: diport::DlqOperatorAction>() -> diport::DlqOperatorAuthorization<A>
    {
        diport::DlqOperatorAuthorization::issue(
            dlqauthmint::DlqOperatorMint::capability(),
            vocab::ServiceCallerDomain::MaintenanceOperator,
            "operator".to_owned(),
            super::tenant(),
            super::audit_id(),
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

fn tenant() -> rss_request_context::TenantId {
    rss_request_context::TenantId::parse("00000000-0000-4000-8000-000000000001").unwrap()
}

fn audit_id() -> diport::DlqOperatorStartAuditId {
    diport::DlqOperatorStartAuditId::parse("ui-audit").unwrap()
}
