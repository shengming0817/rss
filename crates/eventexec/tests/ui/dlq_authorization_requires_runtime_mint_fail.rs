use diport::{DlqOperatorAuthorization, DlqOperatorStartAuditId, dlq_operator_action};
use rss_request_context::TenantId;
use vocab::ServiceCallerDomain;

fn main() {
    let tenant = TenantId::parse("00000000-0000-4000-8000-000000000001").unwrap();
    let audit = DlqOperatorStartAuditId::parse("audit").unwrap();
    let _ = DlqOperatorAuthorization::<dlq_operator_action::List>::issue(
        ServiceCallerDomain::MaintenanceOperator,
        "operator".to_string(),
        tenant,
        audit,
    );
}
