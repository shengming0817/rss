use audit::ports::CrossTenantReadScope;

fn bypass(audited: authn::AuditedCrossTenantVisibility) {
    let _scope = CrossTenantReadScope { audited, _seal: () };
}

fn main() {}
