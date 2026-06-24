// rss_authenticated_callsite UI fixture（allowed caller）。example target 名 `server` ⇒
// crate_name(LOCAL_CRATE)=="server" ⇒ 命中 ALLOWED_CALLER_CRATES ⇒ 调 funnel **不触发**。
// 用 "server"（非 "rss"）以避与 rss_authplan_callsite 的 example "rss" 在共享 lints workspace 撞 target 名。
// golden ui/server.stderr 为空（anti-vacuity：证明 lint 非恒报，allowlist 分支生效）。
// 须用真 httpserve / vocab（dev-dep）；UI 测试只编译查诊断、不运行。
#![allow(unused)]

use httpserve::Authenticated;
use primitives::RequiredScheme;
use vocab::PrincipalKind;

fn main() {
    // G：组合根（server bin crate）调 Authenticated::new 不触发（合法的验签桥构造点）。
    let _ev = Authenticated::new(RequiredScheme::Jwt, PrincipalKind::User);
}
