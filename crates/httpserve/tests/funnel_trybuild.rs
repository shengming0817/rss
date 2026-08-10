//! typed route funnel 编译期 Hard 不变式的 compile-fail 回归锁（#1113/#1103，ADR-009）。
//!
//! 负向证据（trybuild compile_fail）——锁住「错误不可表达」：
//! - `cannot_bind_unfinalized`：`UnfinalizedRoutes` 无 `into_server_service`（无 public bindable 出口，ROUTE-AUTH-FUNNEL-01）。
//! - `cannot_mint_authenticated`：`AuthenticatedRoutes::new` 是 `pub(crate)`，外部 crate 无法 mint（ROUTE-AUTH-FUNNEL-02）。
//! - `authenticated_routes_cannot_bind`：auth-finalized 中间态没有 public transport 出口；业务必须取得 rate-limit receipt。
//! - `cannot_mint_authenticated_evidence`：production `Authenticated::new_*` 需要 `authmint::AuthenticatedMint`，
//!   缺 mint 首参即 compile_fail（AUTH-EVIDENCE-MINT-01 Hard；本例锁 `new_mtls` arity）。
//! - `cannot_name_authmint_capability`：`AuthenticatedMint` 字段私有，不可 `AuthenticatedMint(())` 伪造
//!   （trybuild 继承 httpserve 的 authmint dep，故用 sealed 构造面代替 E0433；无 dep 半段由 deny.toml wrappers）。
//! - `cannot_mint_authenticated_rss_user`：`new_rss_user` 同样缺 mint 首参即 compile_fail。
//! - `nonprimary_cannot_mount_primary`：Primary endpoint 不能挂到 Internal/Admin/Health（ROUTE-LISTENER-TYPED-01）。
//! - `primary_cannot_mount_nonprimary`：普通 endpoint 不能挂到 Primary（ROUTE-LISTENER-TYPED-01）。
//! - `cannot_construct_listener_router`：`ListenerRouter::new` 是 `pub(crate)`，外部无法直接构造（无 raw-bypass）。
//! - `cannot_impl_listener_for_external`：外部 crate 无法实现 sealed `Listener`，不可新增 listener marker（ROUTE-LISTENER-TYPED-01 sealed 面）。
//! - `old_route_api_is_removed`：旧 Route/PrimaryRoute/字段级 auth scope/mount_primary 均不可用。
//! - `raw_method_router_cannot_mount`：production `mount` 签名不接受 MethodRouter；默认 feature graph
//!   完全不含 raw test helpers 的独立 Hard 证明见 `default_feature_surface.rs`。
//! - `producer_*`：OutboxFact route 只能经 generated producer binding + matching move-only marker
//!   mount；跨 route、旧 `new`、重复 emitted facts、receipt 伪造与 handler 选择 same-marker
//!   binding 均在编译期失败。
//!
//! 正向证据（compile pass）`funnel_pass`：funnel 正确用法编译通过（anti-vacuity——证明上述 fail 非「整个 API 不可用」）。
//!
//! INVARIANT: ROUTE-AUTH-FUNNEL-01 · ROUTE-AUTH-FUNNEL-02 · ROUTE-LISTENER-TYPED-01 · ROUTE-ENDPOINT-REQUIRED-01 · ROUTE-MOUNT-NOBYPASS-01 { level = "Hard", exec = "test", source = "trybuild" }
#[test]
fn ui() {
    let t = trybuild::TestCases::new();
    t.pass("tests/ui/funnel_pass.rs");
    t.pass("tests/ui/declared_response_funnel_pass.rs");
    t.pass("tests/ui/primary_declared_response_funnel_pass.rs");
    t.pass("tests/ui/local_only_classified_state_pass.rs");
    t.pass("tests/ui/primary_local_only_classified_state_pass.rs");
    t.pass("tests/ui/producer_funnel_pass.rs");
    t.pass("tests/ui/declared_producer_funnel_pass.rs");
    t.compile_fail("tests/ui/cannot_bind_unfinalized.rs");
    t.compile_fail("tests/ui/authenticated_routes_cannot_bind.rs");
    t.compile_fail("tests/ui/cannot_mint_authenticated.rs");
    t.compile_fail("tests/ui/cannot_mint_authenticated_evidence.rs");
    t.compile_fail("tests/ui/cannot_name_authmint_capability.rs");
    t.compile_fail("tests/ui/cannot_name_saga_operator_mint.rs");
    t.compile_fail("tests/ui/cannot_mint_authenticated_rss_user.rs");
    t.compile_fail("tests/ui/nonprimary_cannot_mount_primary.rs");
    t.compile_fail("tests/ui/internal_service_route_requires_policy.rs");
    t.compile_fail("tests/ui/primary_cannot_mount_nonprimary.rs");
    t.compile_fail("tests/ui/cannot_construct_listener_router.rs");
    t.compile_fail("tests/ui/cannot_impl_listener_for_external.rs");
    t.compile_fail("tests/ui/generated_endpoint_requires_evidence.rs");
    t.compile_fail("tests/ui/generated_endpoint_requires_handler.rs");
    t.compile_fail("tests/ui/declared_response_rejects_raw_response.rs");
    t.compile_fail("tests/ui/declared_response_rejects_open_constructor.rs");
    t.compile_fail("tests/ui/open_response_rejects_declared_constructor.rs");
    t.compile_fail("tests/ui/declared_result_rejects_raw_error.rs");
    t.compile_fail("tests/ui/declared_fixed_error_rejects_dto_injection.rs");
    t.compile_fail("tests/ui/declared_fixed_error_rejects_bare_request_id.rs");
    t.compile_fail("tests/ui/primary_declared_response_rejects_raw_response.rs");
    t.compile_fail("tests/ui/primary_declared_response_rejects_open_constructor.rs");
    t.compile_fail("tests/ui/primary_open_response_rejects_declared_constructor.rs");
    t.compile_fail("tests/ui/old_route_api_is_removed.rs");
    t.compile_fail("tests/ui/raw_method_router_cannot_mount.rs");
    t.compile_fail("tests/ui/local_only_cannot_with_state.rs");
    t.compile_fail("tests/ui/local_only_rejects_write_state.rs");
    t.compile_fail("tests/ui/local_only_rejects_cross_tenant_state.rs");
    t.compile_fail("tests/ui/local_only_route_state_proof_marker_mismatch.rs");
    t.compile_fail("tests/ui/consistency_marker_mismatch.rs");
    t.compile_fail("tests/ui/primary_local_only_cannot_with_state.rs");
    t.compile_fail("tests/ui/primary_local_only_rejects_write_state.rs");
    t.compile_fail("tests/ui/primary_local_only_rejects_cross_tenant_state.rs");
    t.compile_fail("tests/ui/primary_consistency_marker_mismatch.rs");
    t.compile_fail("tests/ui/producer_old_mount_is_rejected.rs");
    t.compile_fail("tests/ui/producer_marker_mismatch.rs");
    t.compile_fail("tests/ui/producer_receipt_cannot_be_forged.rs");
    t.compile_fail("tests/ui/producer_handler_cannot_select_binding.rs");
    t.compile_fail("tests/ui/producer_duplicate_facts.rs");
    t.compile_fail("tests/ui/declared_producer_rejects_raw_response.rs");
    t.compile_fail("tests/ui/authorized_subject_has_no_grant_evidence.rs");
}
