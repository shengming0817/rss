fn main() {
    let _ = oidc::VerifierConfigBuilder::<diport::RssAccessProfile>::new("issuer", "audience")
        .trust_kind("user");
}
