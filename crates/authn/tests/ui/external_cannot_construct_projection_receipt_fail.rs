fn main() {
    let _receipt = authn::ProjectionMaintenanceReceipt {
        operator_caller: vocab::ServiceCallerDomain::MaintenanceOperator,
        action: authn::ProjectionMaintenanceAction::Replay,
        tenant: rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap(),
        projection: "audit.session-projection".into(),
        _seal: (),
    };
}
