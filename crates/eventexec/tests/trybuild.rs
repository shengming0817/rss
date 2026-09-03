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
fn delivery_budget_and_envelope_values_are_opaque() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/delivery_budget_private_fields_fail.rs");
    tests.compile_fail("tests/ui/event_envelope_private_fields_fail.rs");
    tests.compile_fail("tests/ui/event_envelope_clone_fail.rs");
    tests.compile_fail("tests/ui/event_envelope_debug_fail.rs");
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
fn consumer_tx_policy_capabilities_are_sealed() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/consumer_tx_outcome_clone_fail.rs");
    tests.compile_fail("tests/ui/consumer_tx_outcome_debug_fail.rs");
    tests.compile_fail("tests/ui/consumer_tx_external_key_public_name_fail.rs");
}

#[test]
fn event_metadata_surface_is_narrow() {
    let tests = trybuild::TestCases::new();
    tests.pass("tests/ui/event_metadata_pass.rs");
    tests.compile_fail("tests/ui/event_metadata_private_fields_fail.rs");
    tests.compile_fail("tests/ui/event_metadata_debug_fail.rs");
    tests.compile_fail("tests/ui/event_metadata_display_fail.rs");
    tests.compile_fail("tests/ui/event_metadata_clone_fail.rs");
}

#[test]
fn managed_delivery_stream_constructor_is_private() {
    trybuild::TestCases::new()
        .compile_fail("tests/ui/managed_delivery_stream_constructor_private_fail.rs");
}

#[test]
fn retry_surface_has_one_canonical_owner() {
    trybuild::TestCases::new().pass("tests/ui/retry_canonical_path_pass.rs");
}
