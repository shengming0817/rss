//! fail：`VerifiedJwt` / `VerifiedServiceToken` 字段私有——外部 crate 不能用 struct 字面量绕过 `seal`
//! 伪造已验证 newtype。与 `external_cannot_seal_fail` 互补：堵死另一条 mint 通路。
fn main() {
    let _ = authn::VerifiedJwt {
        raw: "h.e.s".to_string(),
        claims: diport::VerifiedClaims::service_token(
            vocab::ServiceCallerDomain::MaintenanceOperator,
            rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap(),
        ),
    }; // E0451: 私有字段不可达

    let _ = authn::VerifiedServiceToken {
        token: authn::AccessToken::new("svc"),
        claims: diport::VerifiedClaims::service_token(
            vocab::ServiceCallerDomain::MaintenanceOperator,
            rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap(),
        ),
    }; // E0451: 私有字段不可达
}
