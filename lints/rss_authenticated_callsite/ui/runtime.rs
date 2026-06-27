// rss_authenticated_callsite UI fixture（allowed caller）。example target 名 `runtime` ⇒
// crate_name(LOCAL_CRATE)=="runtime" ⇒ 命中 ALLOWED_CALLER_CRATES ⇒ 调 funnel **不触发**。
// `runtime` 是 #1309 后的唯一组合根，验签桥在此处构造 Authenticated 是合法的。
// golden ui/runtime.stderr 为空（anti-vacuity：证明 lint 非恒报，allowlist 分支生效）。
// 须用真 httpserve / vocab / primitives（dev-dep）；UI 测试只编译查诊断、不运行。
#![allow(unused)]

use httpserve::Authenticated;
use primitives::RequiredScheme;
use vocab::PrincipalKind;

fn main() {
    // G：组合根（runtime assembly crate）调 Authenticated::new 不触发（合法的验签桥构造点）。
    let _ev = Authenticated::new(RequiredScheme::Jwt, PrincipalKind::User, "subject-1", None);
    let _subject = authn::Principal::audit_subject;
}
