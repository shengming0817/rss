//! INVARIANT: IDENTITY-DEVICE-CERTIFICATE-FACADE-01 { level = "Hard", exec = "test", source = "trybuild" }

#[test]
fn device_certificate_is_exposed_only_through_the_ports_facade() {
    let tests = trybuild::TestCases::new();
    tests.pass("tests/ui/device_certificate_ports_facade_pass.rs");
    tests.compile_fail("tests/ui/device_certificate_implementation_path_fail.rs");
}
