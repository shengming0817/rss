//! reconcile Builder 必填位置参 compile-pass/fail 回归（INVARIANT: RECONCILE-TENANCY-REQ-01，Hard）。
//!
//! `Builder::new(reconciler, tenancy, trigger)` 三参必填——漏 `tenancy` / `trigger` 即编译错（E0061）。
//! 类型系统强制（非运行期校验），与 `diport` 的 dyn-port trybuild 同范式。

#[test]
fn ui() {
    let t = trybuild::TestCases::new();
    // 三参齐全 → 编译通过。
    t.pass("tests/ui/reconcile_builder_pass.rs");
    // 漏 tenancy（第二参）→ 编译错。
    t.compile_fail("tests/ui/reconcile_missing_tenancy_fail.rs");
    // 漏 trigger（第三参）→ 编译错。
    t.compile_fail("tests/ui/reconcile_missing_trigger_fail.rs");
}
