fn forge(event: diport::AuditEvent, target: rss_request_context::TenantId) {
    let _grant = authn::CrossTenantAuditGrant {
        target,
        event,
        _seal: (),
    };
}

fn main() {}
