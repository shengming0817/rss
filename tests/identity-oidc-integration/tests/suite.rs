#[path = "../../fixtures/oidc_clock.rs"]
mod fixture_clock;
mod support;
mod cases {
    mod entra;
    mod jwks_rotation;
    mod private_provider;
}
