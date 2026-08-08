//! External-consumer proof for the Postgres domain feature façade.
//!
//! INVARIANT: PG-DOMAIN-FEATURES-01 { level = "Hard", exec = "native-compile", source = "code", native = "parent-gated modules and conditional crate-root re-exports remove inactive domain APIs from rustc input" }

#[test]
fn domain_feature_surface_tracks_the_selected_graph() {
    let cases = trybuild::TestCases::new();

    if cfg!(feature = "domain-settings") {
        cases.pass("tests/ui/pg_projection_worker_feature_surface.rs");
    } else {
        cases.compile_fail("tests/ui/pg_projection_worker_feature_surface.rs");
    }

    if cfg!(feature = "domain-identity") {
        cases.pass("tests/ui/pg_device_latent_feature_surface.rs");
    } else {
        cases.compile_fail("tests/ui/pg_device_latent_feature_surface.rs");
    }
}
