fn main() {
    let _ = oidc::VerifierConfigBuilder::<diport::RssAccessProfile>::new("issuer", "audience")
        .kind_claim("principal_kind");
}
