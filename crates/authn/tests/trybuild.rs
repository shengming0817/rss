//! 跨 crate 漏斗完整性编译锁（Medium，#1158 / F1）：`VerifiedJwt` / `VerifiedServiceToken` 的**生产端**
//! 在 crate 外不可达——外部 crate 既不能调 `pub(crate) seal`（E0624）、也不能用 struct 字面量赋私有字段
//! （E0451）绕过，只能经 authn-owned `verify_jwt` / `verify_service_token`（验签后受控 mint）取得。
//! 注：`diport::VerifiedClaims` 是 pub（外部可造身份 claims），但封不进 `VerifiedJwt`——封住生产端。
//!
//! 两个 compile-fail 各覆盖两条 funnel（jwt + service-token），互为 anti-vacuity：单点可见性回归
//! （如把某 `seal` 改 `pub`、或某字段改 `pub`）只翻绿其中一处，另一文件 / 另一条仍守住，守卫非恒真。
//!
//! 正向「外部经 bridge **可** mint」由 `pub async fn verify_jwt` 的可见性 + crate 内 `verify_bridge_tests`
//! 异步单测保证（async-in-trybuild-pass 需运行期 runtime，不划算）。
//!
//! INVARIANT: AUTHN-VERIFIEDJWT-SEAL-01 { level = "Hard", exec = "verify", source = "trybuild" }（生产端闭环）。
#[test]
fn ui() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/external_cannot_seal_fail.rs");
    t.compile_fail("tests/ui/external_cannot_construct_fail.rs");
    t.compile_fail("tests/ui/external_cannot_construct_mtls_peer_fail.rs");
    t.compile_fail("tests/ui/external_cannot_seal_mtls_peer_fail.rs");
}
