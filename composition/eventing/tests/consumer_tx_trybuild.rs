//! Compile-time proofs for the public ConsumerTx composition seal.

#[test]
fn consumer_tx_internals_are_not_external_capabilities() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/consumer_tx_external_impl_fail.rs");
    cases.compile_fail("tests/ui/consumer_tx_forged_committed_fail.rs");
    cases.compile_fail("tests/ui/consumer_tx_raw_capability_fail.rs");
    cases.compile_fail("tests/ui/bridged_subscriptions_forge_fail.rs");
}
