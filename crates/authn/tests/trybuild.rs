//! 跨 crate 漏斗完整性编译锁（Medium，#1158 / F1）：`VerifiedJwt` / `VerifiedServiceToken` 的**生产端**
//! 在 crate 外不可达——外部 crate 既不能调 `pub(crate) seal`（E0624）、也不能用 struct 字面量赋私有字段
//! （E0451）绕过，只能经 authn-owned profile-specific verification funnels（验签后受控 mint）取得。
//! 注：`diport::VerifiedClaims` 是 pub（外部可造身份 claims），但封不进 `VerifiedJwt`——封住生产端。
//!
//! 两个 compile-fail 各覆盖两条 funnel（jwt + service-token），互为 anti-vacuity：单点可见性回归
//! （如把某 `seal` 改 `pub`、或某字段改 `pub`）只翻绿其中一处，另一文件 / 另一条仍守住，守卫非恒真。
//!
//! 正向「外部经 bridge **可** mint」由公开 profile-specific verify API + crate 内 `verify_bridge_tests`
//! 异步单测保证（async-in-trybuild-pass 需运行期 runtime，不划算）。
//!
//! INVARIANT: AUTHN-VERIFIEDJWT-SEAL-01 { level = "Medium", exec = "test", source = "trybuild" }（生产端闭环）。
#[test]
fn ui() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/external_cannot_seal_fail.rs");
    t.compile_fail("tests/ui/external_cannot_construct_fail.rs");
    t.compile_fail("tests/ui/external_cannot_construct_mtls_peer_fail.rs");
    t.compile_fail("tests/ui/external_cannot_seal_mtls_peer_fail.rs");
    t.compile_fail("tests/ui/external_cannot_construct_outbound_mtls_policy_fail.rs");
    t.compile_fail("tests/ui/external_cannot_construct_cross_tenant_grant_fail.rs");
    t.compile_fail("tests/ui/cross_tenant_grant_non_clone_fail.rs");
    t.compile_fail("tests/ui/audited_visibility_noop_recorder_fail.rs");
    t.compile_fail("tests/ui/external_cannot_construct_projection_receipt_fail.rs");
    t.compile_fail("tests/ui/projection_receipt_non_clone_fail.rs");
    t.compile_fail("tests/ui/token_profile_issuer_methods_fail.rs");
    t.compile_fail("tests/ui/rss_access_issue_input_private_fail.rs");
    t.compile_fail("tests/ui/verified_federated_access_private_fields_fail.rs");
    t.compile_fail("tests/ui/verified_federated_access_raw_unavailable_fail.rs");
    t.compile_fail("tests/ui/external_cannot_construct_grant_receipt_fail.rs");
    t.compile_fail("tests/ui/external_cannot_construct_grant_validation_input_fail.rs");
    t.compile_fail("tests/ui/service_caller_string_fail.rs");
    t.compile_fail("tests/ui/federated_issuer_unavailable_fail.rs");
    t.compile_fail("tests/ui/projection_operator_issuer_unavailable_fail.rs");
    t.pass("tests/ui/token_profile_issuers_pass.rs");
}
