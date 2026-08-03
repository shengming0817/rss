//! fail：`seal` 是 `pub(crate)`——外部 crate（trybuild 每个 ui 文件 = 独立 crate）不可调用，
//! 故无法绕过 profile-specific verification funnels 直接 mint `VerifiedJwt` / `VerifiedServiceToken`。
//! 锁 AUTHN-VERIFIEDJWT-SEAL-01 生产端保持 sealed（验签先于 mint 的唯一受控入口是 authn-owned bridge）。
//! 注：profile-shaped claims constructors are public for verifier adapters, but `seal` remains private.
fn main() {
    let _ = authn::VerifiedJwt::seal(
        "h.e.s".to_string(),
        diport::VerifiedClaims::service_token(vocab::ServiceCallerDomain::MaintenanceOperator, vocab::tenant::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap()),
    ); // E0624: associated function `seal` is private

    let _ = authn::VerifiedServiceToken::seal(
        authn::AccessToken::new("svc"),
        diport::VerifiedClaims::service_token(vocab::ServiceCallerDomain::MaintenanceOperator, vocab::tenant::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap()),
    ); // E0624: associated function `seal` is private
}
