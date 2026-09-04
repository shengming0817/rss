//! Compile-time boundaries for the retained provider-neutral runtime surface.

#[test]
fn dlq_operator_authorization_ui() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/dlq_authorization_requires_runtime_mint_fail.rs");
    tests.compile_fail("tests/ui/dlq_authorization_forge_fail.rs");
    tests.compile_fail("tests/ui/dlq_authorization_clone_fail.rs");
    tests.compile_fail("tests/ui/dlq_authorization_consume_twice_fail.rs");
    tests.compile_fail("tests/ui/dlq_authorization_cross_action_fail.rs");
    tests.compile_fail("tests/ui/dlq_request_separate_tenant_fail.rs");
}

#[test]
fn delivery_budget_is_opaque() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/delivery_budget_private_fields_fail.rs");
}

#[test]
fn dlx_lifecycle_proofs_and_capabilities_are_sealed() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/dlx_hot_archive_key_swap_fail.rs");
    tests.compile_fail("tests/ui/dlx_verified_receipt_forge_fail.rs");
    tests.compile_fail("tests/ui/dlx_missing_archive_proof_forge_fail.rs");
    tests.compile_fail("tests/ui/dlx_archive_store_delete_fail.rs");
}

#[test]
fn retry_surface_has_one_canonical_owner() {
    trybuild::TestCases::new().pass("tests/ui/retry_canonical_path_pass.rs");
}
