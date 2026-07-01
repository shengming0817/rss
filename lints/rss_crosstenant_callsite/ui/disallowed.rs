// rss_crosstenant_callsite UI fixture（disallowed caller，crate 名 `crosstenant_callsite_ui` ∉ allowlist）。
// golden 见 disallowed.stderr：调/引用跨租户 All-scope mint 三步触发；调别的 vocab fn / item-level #[allow] 不触发。
// 须用真 vocab（dev-dep）：lint 按 callee crate 名（vocab）匹配，本地 stub 模块 crate 名不为 vocab 无法触发。
// UI 测试只编译查诊断、不运行；funnel body 的 todo!() 不会执行。
// allow(unknown_lints)：普通 cargo build 本 example 时不认 rss_crosstenant_callsite（仅 dylint driver 认），
// 抑制 G2 逃生门演示处的 unknown_lints 噪声；driver 编译时该 lint 已知，不影响 golden。
#![allow(unused, unknown_lints)]

fn main() {
    // R：非 authn crate 直接 mint 跨租户 capability → 触发。
    let _cap = vocab::tenant::CrossTenantCapability::issue_for_verified_super_admin();

    // R2（别名绕过闭合）：函数项别名引用即触发（path 解析到同一 DefId）；后续 `issue()` 调本地绑定不再触发。
    let issue = vocab::tenant::CrossTenantCapability::issue_for_verified_super_admin;
    let _cap2 = issue();

    // R3：authorize / new_cross_tenant 也属于受控三步，函数项引用即触发。
    let authorize = vocab::tenant::CrossTenantVisibility::authorize;
    let new_cross_tenant = vocab::tenant::RowVisibility::new_cross_tenant;

    // G1（specificity anti-vacuity）：调别的 vocab fn 不触发——证明 lint 非「任意 vocab 调用」。
    let _ = vocab::tenant::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479");

    // G2（逃生门）：item-level #[allow] 抑制。
    allowed_by_attr();
}

#[allow(rss_crosstenant_callsite)] // reason: UI fixture 验证逃生门
fn allowed_by_attr() {
    let _cap = vocab::tenant::CrossTenantCapability::issue_for_verified_super_admin();
}
