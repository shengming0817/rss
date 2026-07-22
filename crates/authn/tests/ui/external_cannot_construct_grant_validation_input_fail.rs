fn forge(
    grant_id: authn::AuthGrantId,
    user_id: ids::UserId,
    tenant: vocab::TenantId,
    authn_epoch: authn::AuthnEpoch,
) {
    let _ = authn::AccessGrantValidationInput {
        grant_id,
        user_id,
        tenant,
        auth_time_unix_secs: 0,
        authn_epoch,
    };
}

fn main() {}
