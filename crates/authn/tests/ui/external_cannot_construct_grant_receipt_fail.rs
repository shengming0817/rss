fn forge(
    user_id: ids::UserId,
    tenant: rss_request_context::TenantId,
    facts: &diport::VerifiedAccessGrantFacts,
) {
    let _ = authn::VerifiedGrantReceipt {
        user_id,
        tenant,
        grant: facts,
    };
}

fn main() {}
