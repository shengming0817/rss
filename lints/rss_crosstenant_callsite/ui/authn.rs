// rss_crosstenant_callsite UI fixture（allowed caller）。example target 名 `authn` ⇒
// crate_name(LOCAL_CRATE)=="authn" ⇒ 命中 ALLOWED_CALLER_CRATES ⇒ 调 funnel **不触发**。
// golden ui/authn.stderr 为空（anti-vacuity：证明 lint 非恒报，allowlist 分支生效）。
// 须用真 vocab（dev-dep）；UI 测试只编译查诊断、不运行，funnel 的 todo!() 不会执行。
#![allow(unused)]

fn main() {
    // G：authn crate 调 funnel 不触发（已校验 super-admin 派生路径的生产入口）。
    let _cap = vocab::tenant::CrossTenantCapability::issue_for_verified_super_admin();
    let _authorize = vocab::tenant::CrossTenantVisibility::authorize;
    let _new_cross_tenant = vocab::tenant::RowVisibility::new_cross_tenant;
}
