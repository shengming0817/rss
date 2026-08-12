//! AUTH-EVIDENCE-MINT-01：另一 profile constructor（`new_rss_user`）同样要求 mint token 为首参。
//! 缺首参时类型/arity 失败（与 `cannot_mint_authenticated_evidence` 的 `new_mtls` 对偶）。
fn main() {
    let _ = httpserve::Authenticated::new_rss_user(
        "11111111-2222-4333-8444-555555555555",
        rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap(),
    );
}
