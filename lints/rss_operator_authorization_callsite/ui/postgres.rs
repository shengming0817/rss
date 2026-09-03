// rss_operator_authorization_callsite UI fixture（仅精确 Postgres audit issuer 可 mint proof）。
#![allow(unused)]

fn mint(
    subject: eventexec::L2DrRecoveryOperatorSubject,
    plan: &eventexec::L2DrRecoveryPlan,
    start: uuid::Uuid,
) -> Result<eventexec::L2DrRecoveryDurableStartProof, eventexec::L2DrRecoveryError> {
    eventexec::L2DrRecoveryDurableStartProof::from_store(
        vocab::ServiceCallerDomain::MaintenanceOperator,
        subject,
        plan.tenant(),
        plan.epoch_id(),
        *plan.digest(),
        start,
    )
}

fn mint_function_item(
    subject: eventexec::L2DrRecoveryOperatorSubject,
    plan: &eventexec::L2DrRecoveryPlan,
    start: uuid::Uuid,
) {
    let issue = eventexec::L2DrRecoveryDurableStartProof::from_store;
    let _ = issue(
        vocab::ServiceCallerDomain::MaintenanceOperator,
        subject,
        plan.tenant(),
        plan.epoch_id(),
        *plan.digest(),
        start,
    );
}

mod bundle {
    pub struct PgL2DrRecoveryDeps;

    impl PgL2DrRecoveryDeps {
        pub fn record_l2_dr_recovery_start_audit_subject(
            &self,
            subject: eventexec::L2DrRecoveryOperatorSubject,
            plan: &eventexec::L2DrRecoveryPlan,
            start: uuid::Uuid,
        ) -> Result<eventexec::L2DrRecoveryDurableStartProof, eventexec::L2DrRecoveryError>
        {
            eventexec::L2DrRecoveryDurableStartProof::from_store(
                vocab::ServiceCallerDomain::MaintenanceOperator,
                subject,
                plan.tenant(),
                plan.epoch_id(),
                *plan.digest(),
                start,
            )
        }
    }

    pub struct SameNamedSibling;

    impl SameNamedSibling {
        pub fn record_l2_dr_recovery_start_audit_subject(
            &self,
            subject: eventexec::L2DrRecoveryOperatorSubject,
            plan: &eventexec::L2DrRecoveryPlan,
            start: uuid::Uuid,
        ) -> Result<eventexec::L2DrRecoveryDurableStartProof, eventexec::L2DrRecoveryError>
        {
            eventexec::L2DrRecoveryDurableStartProof::from_store(
                vocab::ServiceCallerDomain::MaintenanceOperator,
                subject,
                plan.tenant(),
                plan.epoch_id(),
                *plan.digest(),
                start,
            )
        }
    }
}

fn main() {}
