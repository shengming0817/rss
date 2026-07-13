// rss_dlq_operator_callsite UI fixture（runtime 非整 crate allowlist；仅最小 wrapper 允许）。
#![allow(unused)]

fn main() {
    let _cap = issue_authorized_dlq_capability();
    let _reconcile = issue_authorized_reconcile_capability();
    let _subject = verified_dlq_operator_subject("operator:alice");
    nested_runtime_module::call_same_named_non_boundary();
    non_boundary_runtime_call();
}

fn issue_authorized_reconcile_capability() -> eventexec::OperatorReconcileCapability {
    eventexec::OperatorReconcileCapability::issue_for_authorized_operator()
}

fn issue_authorized_dlq_capability() -> eventexec::OperatorDlqCapability {
    eventexec::OperatorDlqCapability::issue_for_authorized_operator()
}

fn verified_dlq_operator_subject(
    raw: &str,
) -> Result<eventexec::VerifiedOperatorSubject, eventexec::DlqError> {
    eventexec::VerifiedOperatorSubject::from_verified(raw)
}

fn non_boundary_runtime_call() {
    let _cap = eventexec::OperatorDlqCapability::issue_for_authorized_operator();
    let _subject = eventexec::VerifiedOperatorSubject::from_verified("operator:mallory");
}

mod nested_runtime_module {
    pub fn call_same_named_non_boundary() {
        let _cap = issue_authorized_dlq_capability();
        let _subject = verified_dlq_operator_subject("operator:mallory");
    }

    fn issue_authorized_dlq_capability() -> eventexec::OperatorDlqCapability {
        eventexec::OperatorDlqCapability::issue_for_authorized_operator()
    }

    fn verified_dlq_operator_subject(
        raw: &str,
    ) -> Result<eventexec::VerifiedOperatorSubject, eventexec::DlqError> {
        eventexec::VerifiedOperatorSubject::from_verified(raw)
    }
}
