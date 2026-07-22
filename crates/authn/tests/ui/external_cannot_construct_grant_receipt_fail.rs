fn forge(
    user_id: ids::UserId,
    tenant: vocab::TenantId,
    facts: &diport::VerifiedAccessGrantFacts,
) {
    let _ = authn::VerifiedGrantReceipt {
        user_id,
        tenant,
        grant: facts,
    };
}

fn main() {}
