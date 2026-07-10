use audit::ports::CrossTenantReadScope;

fn bypass(audited: authn::AuditedCrossTenantVisibility) {
    let _scope = CrossTenantReadScope::from_audited_visibility(audited);
}

fn main() {}
