//! INVARIANT: IDENTITY-DEVICE-CERTIFICATE-FACADE-01 { level = "Hard", exec = "test", source = "trybuild" }

#[test]
fn device_certificate_is_exposed_only_through_the_ports_facade() {
    let tests = trybuild::TestCases::new();
    tests.pass("tests/ui/device_certificate_ports_facade_pass.rs");
    tests.compile_fail("tests/ui/device_certificate_implementation_path_fail.rs");
    tests.compile_fail("tests/ui/device_certificate_artifact_private_fields_fail.rs");
    tests.compile_fail("tests/ui/device_certificate_artifact_clone_fail.rs");
    tests.compile_fail("tests/ui/device_certificate_append_authorization_clone_fail.rs");
    tests.compile_fail("tests/ui/device_certificate_persisted_snapshot_append_fail.rs");
    tests.compile_fail("tests/ui/device_certificate_draft_production_slot_fail.rs");
    tests.compile_fail("tests/ui/device_certificate_raw_signer_production_slot_fail.rs");
    tests.compile_fail("tests/ui/device_certificate_legacy_production_source_removed_fail.rs");
    tests.compile_fail("tests/ui/device_certificate_unfenced_condition_writer_fail.rs");
}
