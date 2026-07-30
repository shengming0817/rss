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
    // durable scheduler + command seam API 齐全 → 编译通过。
    t.pass("tests/ui/reconcile_durable_scheduler_pass.rs");
    // raw topic/contract/payload authoring API 不得从 eventexec 对外可达。
    t.compile_fail("tests/ui/reconcile_raw_command_authoring_fail.rs");
    // generated typed spec trait is sealed; downstream cannot forge routing/request pairings.
    t.compile_fail("tests/ui/reconcile_typed_command_spec_impl_fail.rs");
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
    // validated store input 字段私有，只能由 canonical target funnel 构造。
    t.compile_fail("tests/ui/projection_validated_input_forge_fail.rs");
    // runtime target trait sealed，外部只能实现 ProjectionTargetStore SPI。
    t.compile_fail("tests/ui/projection_external_target_impl_fail.rs");
}

#[test]
fn workflow_runtime_views_are_sealed() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/workflow_projection_capture_view_forge_fail.rs");
    t.compile_fail("tests/ui/workflow_projection_target_view_forge_fail.rs");
    t.compile_fail("tests/ui/workflow_saga_view_forge_fail.rs");
    t.compile_fail("tests/ui/workflow_activated_view_forge_fail.rs");
    t.compile_fail("tests/ui/workflow_plan_forge_fail.rs");
    t.compile_fail("tests/ui/workflow_old_projection_register_fail.rs");
}

#[test]
fn typed_saga_ui() {
    let t = trybuild::TestCases::new();
    // generated SPEC + policy + ordered step binding + required compensation → 编译通过。
    t.pass("tests/ui/typed_saga_wrapper_pass.rs");
    // 漏 compensate required method → 编译错（Hard compensation requirement）。
    t.compile_fail("tests/ui/typed_saga_missing_compensation_fail.rs");
    // builder 必须接收 generated SagaContractBinding；漏参即编译错。
    t.compile_fail("tests/ui/typed_saga_missing_spec_fail.rs");
}

#[test]
fn command_authoring_is_sealed() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/command_spec_constructor_private_fail.rs");
    t.compile_fail("tests/ui/reviewed_command_constructors_private_fail.rs");
    t.compile_fail("tests/ui/command_wrong_request_fail.rs");
    t.compile_fail("tests/ui/command_wrong_policy_fail.rs");
}

#[test]
fn relay_budget_fields_are_private() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/relay_budget_private_fields_fail.rs");
}

#[test]
fn dlx_lifecycle_proofs_and_capabilities_are_sealed() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/dlx_hot_archive_key_swap_fail.rs");
    t.compile_fail("tests/ui/dlx_verified_receipt_forge_fail.rs");
    t.compile_fail("tests/ui/dlx_missing_archive_proof_forge_fail.rs");
    t.compile_fail("tests/ui/dlx_archive_store_delete_fail.rs");
}

#[test]
fn consumer_tx_policy_capabilities_are_sealed() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/consumer_tx_external_impl_fail.rs");
    t.compile_fail("tests/ui/consumer_tx_forged_proof_fail.rs");
    t.compile_fail("tests/ui/consumer_tx_external_handler_construct_fail.rs");
    t.compile_fail("tests/ui/consumer_tx_wrong_policy_fail.rs");
    t.compile_fail("tests/ui/consumer_tx_inactive_policy_constructor_fail.rs");
    t.compile_fail("tests/ui/consumer_tx_external_key_public_name_fail.rs");
    t.compile_fail("tests/ui/consumer_tx_external_key_raw_construct_fail.rs");
    t.compile_fail("tests/ui/consumer_tx_transactional_raw_capability_fail.rs");
    t.compile_fail("tests/ui/consumer_tx_bare_handler_alias_fail.rs");
}
