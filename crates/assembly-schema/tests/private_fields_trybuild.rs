#[test]
fn assembly_lock_construction_is_sealed() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/assembly_digests_private.rs");
    cases.compile_fail("tests/ui/assembly_identity_private.rs");
    cases.compile_fail("tests/ui/assembly_lock_private.rs");
    cases.compile_fail("tests/ui/canonical_manifest_private.rs");
    cases.compile_fail("tests/ui/fingerprint_private.rs");
    cases.compile_fail("tests/ui/parsed_lock_trusted_access_private.rs");
    cases.compile_fail("tests/ui/contract_owner_private.rs");
    cases.compile_fail("tests/ui/raw_contract_owner_private.rs");
    cases.compile_fail("tests/ui/repository_contract_private.rs");
    cases.compile_fail("tests/ui/repository_manifest_private.rs");
}

#[test]
fn runtime_plan_construction_is_sealed() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/runtime_plan_derived_facts_private.rs");
    cases.compile_fail("tests/ui/runtime_plan_private.rs");
    cases.compile_fail("tests/ui/runtime_plan_fingerprint_private.rs");
    cases.compile_fail("tests/ui/runtime_plan_fake_lock_proxy_rejected.rs");
    cases.compile_fail("tests/ui/runtime_plan_parsed_lock_compile_rejected.rs");
    cases.compile_fail("tests/ui/runtime_plan_parsed_lock_reader_rejected.rs");
    cases.compile_fail("tests/ui/runtime_plan_unbound_reader_private.rs");
}

#[test]
fn workflow_plan_construction_is_sealed() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/workflow_plan_private.rs");
}
