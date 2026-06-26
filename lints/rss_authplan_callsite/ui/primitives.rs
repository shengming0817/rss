// rss_authplan_callsite UI fixture（allowed caller）。example target 名 `primitives` ⇒
// crate_name(LOCAL_CRATE)=="primitives" ⇒ 命中 ALLOWED_CALLER_CRATES ⇒ 调 funnel **不触发**。
// `primitives` 是 AuthPlan 定义 crate，`none()` 内调 `Self::new()` 是内部实现，合法豁免。
// golden ui/primitives.stderr 为空（anti-vacuity：证明 lint 非恒报，allowlist 分支生效）。
// 须用真 primitives（dev-dep）；UI 测试只编译查诊断、不运行。
#![allow(unused)]

use primitives::authplan::{AuthPlan, AuthScheme, ListenerKind};

fn main() {
    // G：primitives crate 内部（或以其 crate 名编译的 fixture）调 AuthPlan::new / none 不触发（合法豁免）。
    let _plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::Jwt);
    let _plan2 = AuthPlan::none(ListenerKind::Primary);
}
