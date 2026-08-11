fn main() {
    let tenant = vocab::TenantId::parse("00000000-0000-4000-8000-000000000001").unwrap();
    let _ = diport::DlqOperatorAuthorization::<diport::dlq_operator_action::List> {
        caller: vocab::ServiceCallerDomain::MaintenanceOperator,
        tenant,
        start_audit_id: diport::DlqOperatorStartAuditId::parse("audit").unwrap(),
        action: std::marker::PhantomData,
    };
}
