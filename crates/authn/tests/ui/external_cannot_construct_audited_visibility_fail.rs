fn main() {
    let target = vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap();
    let visibility = vocab::RowVisibility::new(vocab::ScopedTenant::Tenant, target);
    let _forged = authn::AuditedCrossTenantVisibility {
        visibility,
        target,
        _seal: (),
    };
}
