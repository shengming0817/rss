// rss_authplan_callsite UI fixture（allowed caller）。example target 名 `rss` ⇒
// crate_name(LOCAL_CRATE)=="rss" ⇒ 命中 ALLOWED_CALLER_CRATES ⇒ 调 funnel **不触发**。
// golden ui/allowed.stderr 为空（anti-vacuity：证明 lint 非恒报，allowlist 分支生效）。
// 须用真 primitives（dev-dep）；UI 测试只编译查诊断、不运行。
#![allow(unused)]

use primitives::authplan::{AuthPlan, AuthScheme, ListenerKind};

fn main() {
    // G：组合根（rss bin crate）调 AuthPlan::new / none 不触发（合法的组合根装配点）。
    let _plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::Jwt);
    let _plan2 = AuthPlan::none(ListenerKind::Primary);
}
