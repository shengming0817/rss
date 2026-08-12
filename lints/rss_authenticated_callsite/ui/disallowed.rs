// rss_authenticated_callsite UI fixture（disallowed caller，crate 名 `authenticated_callsite_ui` ∉ allowlist）。
// golden 见 disallowed.stderr：证据与 grant issue funnel 的 direct / alias / re-export 均触发。
// 须用真 httpserve / vocab / authmint（dev-dep）：lint 按 callee crate 名（httpserve）匹配，本地 stub 无法触发。
// UI 测试只编译查诊断、不运行；body 不会执行。
// allow(unknown_lints)：普通 cargo build 本 example 时不认 rss_authenticated_callsite（仅 dylint driver 认），
// 抑制逃生门演示处的 unknown_lints 噪声；driver 编译时该 lint 已知，不影响 golden。
#![allow(unused, unknown_lints)]

use httpserve::Authenticated;
use rss_request_context::PrincipalKind;

fn main() {
    // R1：非组合根 crate 调 profile-specific evidence constructor → 触发。
    let _ev = Authenticated::new_federated(
        authmint::AuthenticatedMint::capability(),
        PrincipalKind::User,
        "subject-1",
        None,
        permissions(),
    );

    // R2（别名绕过闭合）：函数项别名引用即触发（path 解析到同一 DefId）；后续 `mint(...)` 调本地绑定不再触发。
    let mint = Authenticated::new_mtls;
    let _ev2 = mint(authmint::AuthenticatedMint::capability(), "service-1");

    // R2a：RSS evidence constructor remains restricted to the verification bridge.
    let _rss = Authenticated::new_rss_user(
        authmint::AuthenticatedMint::capability(),
        "11111111-2222-4333-8444-555555555555",
        rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap(),
    );

    // R2b：service-token typed mint 的直接引用、别名和 fn-pointer 同样触发。
    let _service = Authenticated::new_service(
        authmint::AuthenticatedMint::capability(),
        rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap(),
        vocab::ServiceCallerDomain::MaintenanceOperator,
    );
    let service_mint = Authenticated::new_service;
    let _service_fn: fn(
        authmint::AuthenticatedMint,
        rss_request_context::TenantId,
        vocab::ServiceCallerDomain,
    ) -> Authenticated = Authenticated::new_service;
    let _ = service_mint;

    // G1（specificity anti-vacuity）：调 Vec::new 不触发——证明 lint 非「任意 ::new 调用」，self-ty 检查生效。
    let _v: Vec<u8> = Vec::new();

    // G2（specificity anti-vacuity）：引用别的 httpserve fn 不触发——证明 lint 非「任意 httpserve 调用」，
    // 只针对 Authenticated 的 profile-specific constructor 闭集。
    let _f = httpserve::finalize_auth;

    // R3：非组合根 crate 引用 Principal 审计 subject accessor → 触发。
    let _subject = authn::Principal::audit_subject;
    let _caller = authn::Principal::service_caller_domain;
    inspect_principal;

    // R4：AuthGrant 生产与 RSS issue funnel 的直接、alias 与 re-export 均按 DefId 拦截。
    let _new_grant = authn::AuthGrant::new_active;
    let hydrate = authn::AuthGrant::hydrate;
    let _issue_input = grant_alias::Grant::access_issue_input;
    let _ = hydrate;

    // G3（逃生门）：item-level #[allow] 抑制。
    allowed_by_attr();
}

fn inspect_principal(principal: &authn::Principal) {
    let _ = principal.service_caller_domain();
}

mod grant_alias {
    pub use authn::AuthGrant as Grant;
}

fn forbidden_issue_access<S: diport::Signer + Send + Sync + 'static>() {
    let _issue = authn::JwtIssuer::<diport::RssAccessProfile, S>::issue_access;
}

#[allow(rss_authenticated_callsite)] // reason: UI fixture 验证逃生门
fn allowed_by_attr() {
    let _ev = Authenticated::new_federated(
        authmint::AuthenticatedMint::capability(),
        PrincipalKind::Admin,
        "admin-1",
        None,
        permissions(),
    );
    let _subject = authn::Principal::audit_subject;
}

fn permissions() -> &'static diport::VerifiedFederatedPermissions {
    unimplemented!()
}
