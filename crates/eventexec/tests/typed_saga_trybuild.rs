//! Hard typed Saga authoring gates backed by the generated test-only conformance catalog.
//!
//! Cargo requires `eventexec/test-support` for this target, so every UI case sees the same sealed
//! primary/foreign definitions while the feature-free trybuild target remains independently
//! runnable.

#[test]
fn typed_saga_ui() {
    let t = trybuild::TestCases::new();
    // generated SPEC + policy + ordered step binding + required compensation → 编译通过。
    t.pass("tests/ui/typed_saga_wrapper_pass.rs");
    // 漏 compensate required method → 编译错（Hard compensation requirement）。
    t.compile_fail("tests/ui/typed_saga_missing_compensation_fail.rs");
    t.compile_fail("tests/ui/typed_saga_missing_probe_fail.rs");
    // Definition 泛型必须来自 generated marker，不能由 raw spec 推断。
    t.compile_fail("tests/ui/typed_saga_missing_spec_fail.rs");
    t.compile_fail("tests/ui/typed_saga_finish_before_end_fail.rs");
    t.compile_fail("tests/ui/typed_saga_extra_step_fail.rs");
    t.compile_fail("tests/ui/typed_saga_reordered_step_fail.rs");
    t.compile_fail("tests/ui/typed_saga_cross_definition_step_fail.rs");
    t.compile_fail("tests/ui/typed_saga_wrong_receipt_fail.rs");
    t.compile_fail("tests/ui/typed_saga_sealed_marker_fail.rs");
    t.compile_fail("tests/ui/saga_operator_raw_target_recovery_fail.rs");
}
