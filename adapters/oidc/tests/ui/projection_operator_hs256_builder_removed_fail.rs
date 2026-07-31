fn main() {
    let keys = oidc::ServiceTokenKeySource::builder().build();
    let _ = oidc::VerifierConfigBuilder::<diport::ProjectionOperatorTokenProfile>::new(
        "issuer",
        "audience",
    )
    .keys_hs256(keys);
}
