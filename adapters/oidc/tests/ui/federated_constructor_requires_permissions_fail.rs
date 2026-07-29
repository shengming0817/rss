fn main() {
    let _ = oidc::VerifierConfigBuilder::<diport::FederatedAccessProfile>::new(
        "issuer",
        "audience",
    );
}
