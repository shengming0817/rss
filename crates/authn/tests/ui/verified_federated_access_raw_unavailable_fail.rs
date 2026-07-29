fn raw_from_federated(access: &authn::VerifiedFederatedAccess) -> &str {
    access.verified_jwt().raw()
}

fn main() {}
