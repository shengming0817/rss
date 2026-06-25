//! 正向（compile pass）：funnel 正确用法编译通过（anti-vacuity——证明 compile_fail 用例非「整个 API 不可用」）。
use httpserve::routes::unfinalized_for_test;

fn main() {
    let routes = unfinalized_for_test::<httpserve::Admin>(|rb| {
        rb.mount(
            httpserve::Route {
                method: axum::http::Method::GET,
                path: "/x",
                contract_id: "ui.pass",
            },
            axum::routing::get(|| async {}),
        )
    });
    let plan =
        primitives::AuthPlan::new(primitives::ListenerKind::Admin, primitives::AuthScheme::Jwt)
            .unwrap();
    let authed = httpserve::finalize_auth(routes, plan).unwrap();
    let _make = authed.into_make_service();
}
