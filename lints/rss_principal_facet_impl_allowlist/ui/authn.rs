// rss_principal_facet_impl_allowlist UI fixture（allowed impl-site）。example target 名 `authn` ⇒
// crate_name(LOCAL_CRATE)=="authn" ⇒ 命中 ALLOWED_IMPL_CRATES ⇒ impl runctx::PrincipalFacet **不触发**。
// golden ui/authn.stderr 为空（anti-vacuity：证明 lint 非恒报，allowlist 分支生效）。
// 须用真 runctx（dev-dep）；UI 测试只编译查诊断、不运行。
#![allow(unused)]

use runctx::PrincipalFacet;
use vocab::PrincipalKind;

// G：authn crate impl runctx::PrincipalFacet 不触发（生产唯一 impl-er：已验证 Principal 派生）。
struct AuthnPrincipal;
impl PrincipalFacet for AuthnPrincipal {
    fn kind(&self) -> PrincipalKind {
        PrincipalKind::User
    }
    fn matches_subject(&self, _subject: &str) -> bool {
        true
    }
}

fn main() {}
