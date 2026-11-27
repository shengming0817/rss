use rss_audit_core::{EventId, OperationId, RecordIdentity, SourceContract, SourceId, SourceIdentity};
use rss_contract::{ContractId, ContractVersion, SchemaDigest};
use rss_request_context::TenantId;

fn main() {
    let tenant = TenantId::parse("018f47c2-8bd8-7f21-a52b-8d4f6ee2b203").unwrap();
    let source = SourceIdentity::new(
        SourceId::parse("rss-mdm").unwrap(),
        SourceContract::new(
            ContractId::parse("mdm.access-event").unwrap(),
            ContractVersion::from_major(1).unwrap(),
            SchemaDigest::parse("sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789").unwrap(),
        ),
    );
    let operation = OperationId::parse("event-1").unwrap();
    let _ = RecordIdentity::new(tenant, source, operation);
    let _: Option<EventId> = None;
}
