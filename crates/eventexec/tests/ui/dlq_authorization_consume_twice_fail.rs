fn main() {
    let authorization = diport::test_support::dlq_operator_authorization::<
        diport::dlq_operator_action::RedriveOutbox,
    >(
        vocab::ServiceCallerDomain::MaintenanceOperator,
        "trybuild-dlq-operator",
        vocab::TenantId::parse("00000000-0000-4000-8000-000000000001").unwrap(),
        diport::DlqOperatorStartAuditId::parse("audit-consume-twice").unwrap(),
    );
    let _first = eventexec::DlqRedriveRequest::new(
        authorization,
        consistency::IdemKey::parse("event-first").unwrap(),
    );
    let _second = eventexec::DlqRedriveRequest::new(
        authorization,
        consistency::IdemKey::parse("event-second").unwrap(),
    );
}
