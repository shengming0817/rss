fn forge(event: diport::AuditEvent, target: vocab::TenantId) {
    let _grant = authn::CrossTenantAuditGrant {
        target,
        event,
        _seal: (),
    };
}

fn main() {}
