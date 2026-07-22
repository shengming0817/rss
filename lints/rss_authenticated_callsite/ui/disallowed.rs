// rss_authenticated_callsite UI fixture（disallowed caller，crate 名 `authenticated_callsite_ui` ∉ allowlist）。
// golden 见 disallowed.stderr：调 Authenticated::new 触发；Vec::new / httpserve 非-new fn 不触发。
// 须用真 httpserve / vocab（dev-dep）：lint 按 callee crate 名（httpserve）匹配，本地 stub 无法触发。
// UI 测试只编译查诊断、不运行；body 不会执行。
// allow(unknown_lints)：普通 cargo build 本 example 时不认 rss_authenticated_callsite（仅 dylint driver 认），
// 抑制逃生门演示处的 unknown_lints 噪声；driver 编译时该 lint 已知，不影响 golden。
#![allow(unused, unknown_lints)]

use httpserve::Authenticated;
use primitives::RequiredScheme;
use vocab::PrincipalKind;

fn main() {
    // R1：非组合根 crate 调 Authenticated::new → 触发。
    let _ev = Authenticated::new(
        RequiredScheme::RssAccessToken,
        PrincipalKind::User,
        "subject-1",
        None,
    );

    // R2（别名绕过闭合）：函数项别名引用即触发（path 解析到同一 DefId）；后续 `mint(...)` 调本地绑定不再触发。
    let mint = Authenticated::new;
    let _ev2 = mint(
        RequiredScheme::ServiceToken,
        PrincipalKind::Service,
        "service-1",
        None,
    );

    // R2b：service-token typed mint 的直接引用、别名和 fn-pointer 同样触发。
    let _service = Authenticated::new_service(
        vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap(),
        vocab::ServiceCallerDomain::MaintenanceOperator,
    );
    let service_mint = Authenticated::new_service;
    let _service_fn: fn(vocab::TenantId, vocab::ServiceCallerDomain) -> Authenticated =
        Authenticated::new_service;
    let _ = service_mint;

    // G1（specificity anti-vacuity）：调 Vec::new 不触发——证明 lint 非「任意 ::new 调用」，self-ty 检查生效。
    let _v: Vec<u8> = Vec::new();

    // G2（specificity anti-vacuity）：引用别的 httpserve fn 不触发——证明 lint 非「任意 httpserve 调用」，
    // 只针对 Authenticated::new（item 名 != "new"）。
    let _f = httpserve::finalize_auth;

    // R3：非组合根 crate 引用 Principal 审计 subject accessor → 触发。
    let _subject = authn::Principal::audit_subject;
    let _caller = authn::Principal::service_caller_domain;
    inspect_principal;

    // R4：typed caller 本身不是验签证明；settings maintenance capability 的 direct / alias /
    // fn-pointer mint 也必须由同一 runtime-only gate 阻断。
    let _config = postgres::ConfigValueMaintenanceCapability::from_verified_service_caller(
        vocab::ServiceCallerDomain::MaintenanceOperator,
    );
    let config_mint = postgres::ConfigValueMaintenanceCapability::from_verified_service_caller;
    let _config_fn: fn(vocab::ServiceCallerDomain) -> postgres::ConfigValueMaintenanceCapability =
        postgres::ConfigValueMaintenanceCapability::from_verified_service_caller;
    let _ = config_mint;

    // G3（逃生门）：item-level #[allow] 抑制。
    allowed_by_attr();
}

fn inspect_principal(principal: &authn::Principal) {
    let _ = principal.service_caller_domain();
}

#[allow(rss_authenticated_callsite)] // reason: UI fixture 验证逃生门
fn allowed_by_attr() {
    let _ev = Authenticated::new(
        RequiredScheme::RssAccessToken,
        PrincipalKind::Admin,
        "admin-1",
        None,
    );
    let _subject = authn::Principal::audit_subject;
}
