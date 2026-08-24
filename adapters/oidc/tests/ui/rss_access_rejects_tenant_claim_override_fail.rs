fn main() {
    let _ = oidc::VerifierConfigBuilder::<diport::RssAccessProfile>::new("issuer", "audience")
        .tenant_claim("tenant");
}
