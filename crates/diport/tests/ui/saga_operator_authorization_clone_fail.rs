fn main() {
    let tenant = vocab::TenantId::parse("00000000-0000-0000-0000-000000000001").unwrap();
    let identity = diport::SagaWorkerIdentity::new(
        "billing",
        diport::SagaContractId::parse("billing.checkout").unwrap(),
    )
    .unwrap();
    let instance = consistency::SagaInstanceRef::new(
        tenant,
        consistency::SagaId::new(uuid::Uuid::from_u128(1)),
    )
    .unwrap();
    let authorization = diport::test_support::saga_operator_repair_authorization(
        vocab::ServiceCallerDomain::MaintenanceOperator,
        identity,
        instance,
        consistency::SagaOperatorReason::ForwardOutcomeUnknown,
        diport::SagaOperatorChangeTicket::parse("CHG-653").unwrap(),
        diport::SagaOperatorStartAuditId::parse("audit-653").unwrap(),
    );
    let _copy = authorization.clone();
}
