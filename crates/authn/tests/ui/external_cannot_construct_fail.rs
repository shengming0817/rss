//! fail：`VerifiedJwt` / `VerifiedServiceToken` 字段私有——外部 crate 不能用 struct 字面量绕过 `seal`
//! 伪造已验证 newtype。与 `external_cannot_seal_fail` 互补：堵死另一条 mint 通路。
fn main() {
    let _ = authn::VerifiedJwt {
        raw: "h.e.s".to_string(),
        claims: diport::VerifiedClaims::new("sub", None, None),
    }; // E0451: 私有字段不可达

    let _ = authn::VerifiedServiceToken {
        token: authn::AccessToken::new("svc"),
        claims: diport::VerifiedClaims::new("sub", None, None),
    }; // E0451: 私有字段不可达
}
