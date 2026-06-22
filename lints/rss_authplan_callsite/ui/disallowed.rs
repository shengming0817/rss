// rss_authplan_callsite UI fixture（disallowed caller，crate 名 `authplan_callsite_ui` ∉ allowlist）。
// golden 见 disallowed.stderr：调 AuthPlan::new / AuthPlan::none 触发；Vec::new / 别的 fn 不触发。
// 须用真 primitives（dev-dep）：lint 按 callee crate 名（primitives）匹配，本地 stub 无法触发。
// UI 测试只编译查诊断、不运行；Result body 不会执行。
// allow(unknown_lints)：普通 cargo build 本 example 时不认 rss_authplan_callsite（仅 dylint driver 认），
// 抑制 G3 逃生门演示处的 unknown_lints 噪声；driver 编译时该 lint 已知，不影响 golden。
#![allow(unused, unknown_lints)]

use primitives::authplan::{AuthPlan, AuthScheme, ListenerKind};

fn main() {
    // R1：非组合根 crate 调 AuthPlan::new → 触发。
    let _plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::Jwt);

    // R2（别名绕过闭合）：函数项别名引用即触发（path 解析到同一 DefId）；后续 `new_fn(...)` 调本地绑定不再触发。
    let new_fn = AuthPlan::new;
    let _plan2 = new_fn(ListenerKind::Internal, AuthScheme::ServiceToken);

    // R3：非组合根 crate 调 AuthPlan::none → 触发。
    let _plan3 = AuthPlan::none(ListenerKind::Primary);

    // G1（specificity anti-vacuity）：调 Vec::new 不触发——证明 lint 非「任意 ::new 调用」，self-ty 检查生效。
    let _v: Vec<u8> = Vec::new();

    // G3（逃生门）：item-level #[allow] 抑制。
    allowed_by_attr();
}

// G2（specificity anti-vacuity）：调别的 primitives 类型 fn 不触发——
// 证明 lint 非「任意 primitives 调用」，只针对 AuthPlan::new / AuthPlan::none。
fn other_primitives_fn() {
    // RouteAuthOptOut::Public 是 primitives enum variant，不是 AuthPlan::new/none，不触发。
    let _opt = primitives::authplan::RouteAuthOptOut::Public;
}

#[allow(rss_authplan_callsite)] // reason: UI fixture 验证逃生门
fn allowed_by_attr() {
    let _plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::Jwt);
}
