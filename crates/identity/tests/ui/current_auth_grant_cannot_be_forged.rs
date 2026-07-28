fn forge() -> identity::CurrentAuthGrant {
    identity::CurrentAuthGrant {
        grant_id: ids::CanonicalUuidV4::parse("550e8400-e29b-41d4-a716-446655440000").unwrap(),
        user_id: ids::UserId::parse("11111111-2222-4333-8444-555555555555").unwrap(),
        tenant_id: vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap(),
        authn_epoch: 0,
    }
}

fn main() {}
