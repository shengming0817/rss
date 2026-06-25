//! typed route funnel 编译期 Hard 不变式的 compile-fail 回归锁（#1113/#1103，ADR-009）。
//!
//! 负向证据（trybuild compile_fail）——锁住「错误不可表达」：
//! - `cannot_bind_unfinalized`：`UnfinalizedRoutes` 无 `into_make_service`（无 public bindable 出口，ROUTE-AUTH-FUNNEL-01）。
//! - `cannot_mint_authenticated`：`AuthenticatedRoutes::new` 是 `pub(crate)`，外部 crate 无法 mint（ROUTE-AUTH-FUNNEL-02）。
//! - `nonprimary_cannot_mount_primary`：`mount_primary` 仅 `ListenerRouter<Primary>`，Internal/Admin/Health 均不可（ROUTE-LISTENER-TYPED-01）。
//! - `cannot_construct_listener_router`：`ListenerRouter::new` 是 `pub(crate)`，外部无法直接构造（无 raw-bypass）。
//! - `cannot_impl_listener_for_external`：外部 crate 无法实现 sealed `Listener`，不可新增 listener marker（ROUTE-LISTENER-TYPED-01 sealed 面）。
//!
//! 正向证据（compile pass）`funnel_pass`：funnel 正确用法编译通过（anti-vacuity——证明上述 fail 非「整个 API 不可用」）。
//!
//! INVARIANT: ROUTE-AUTH-FUNNEL-01 · ROUTE-AUTH-FUNNEL-02 · ROUTE-LISTENER-TYPED-01

#[test]
fn ui() {
    let t = trybuild::TestCases::new();
    t.pass("tests/ui/funnel_pass.rs");
    t.compile_fail("tests/ui/cannot_bind_unfinalized.rs");
    t.compile_fail("tests/ui/cannot_mint_authenticated.rs");
    t.compile_fail("tests/ui/nonprimary_cannot_mount_primary.rs");
    t.compile_fail("tests/ui/cannot_construct_listener_router.rs");
    t.compile_fail("tests/ui/cannot_impl_listener_for_external.rs");
}
