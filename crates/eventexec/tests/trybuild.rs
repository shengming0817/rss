//! compile-pass/fail 回归（Hard 类型系统门禁）。
//!
//! - **RECONCILE-TENANCY-REQ-01**（Hard）：`Builder::new(reconciler, tenancy, trigger)` 三参必填——
//!   漏 `tenancy` / `trigger` 即编译错（E0061）。
//! - **PROJECTION-SERIAL-WITNESS-01**（Hard）：`ProjectionHarness::new` 第 5 参须为
//!   `SerialInOrderGuarantor` witness——漏参 E0061，传非 witness 类型 E0277。
//!
//! 类型系统强制（非运行期校验），与 `diport` 的 dyn-port trybuild 同范式。

#[test]
fn reconcile_ui() {
    let t = trybuild::TestCases::new();
    // 三参齐全 → 编译通过。
    t.pass("tests/ui/reconcile_builder_pass.rs");
    // 漏 tenancy（第二参）→ 编译错。
    t.compile_fail("tests/ui/reconcile_missing_tenancy_fail.rs");
    // 漏 trigger（第三参）→ 编译错。
    t.compile_fail("tests/ui/reconcile_missing_trigger_fail.rs");
}

#[test]
fn projection_ui() {
    let t = trybuild::TestCases::new();
    // 五参齐全（含 SerialInOrderGuarantor witness）→ 编译通过。
    t.pass("tests/ui/projection_with_guarantor_pass.rs");
    // 漏 witness（第 5 参）→ E0061（fail-closed by absence）。
    t.compile_fail("tests/ui/projection_missing_guarantor_fail.rs");
    // 第 5 参传非 SerialInOrderGuarantor 类型 `()` → E0277（bound load-bearing anti-vacuity）。
    t.compile_fail("tests/ui/projection_non_serial_guarantor_fail.rs");
}
