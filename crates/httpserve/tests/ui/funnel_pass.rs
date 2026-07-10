//! 正向（compile pass）：funnel 正确用法编译通过（anti-vacuity——证明 compile_fail 用例非「整个 API 不可用」）。
use httpserve::routes::unfinalized_for_test;

enum RouteMarker {}

fn main() {
    const EFFECTS: &[vocab::HttpEffectKind] = &[vocab::HttpEffectKind::Auth];
    let binding = vocab::HttpRouteBinding::<RouteMarker>::from_static(
        vocab::ContractBinding::from_static(
            "test",
            "ui.pass",
            "v1",
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        ),
        "/x",
        "GET",
        vocab::HttpRouteAuth::ServiceOwned,
        None,
        false,
        vocab::HttpConsistencyLevel::LocalOnly,
        vocab::HttpEffectProfile::new(EFFECTS),
    );
    let routes = unfinalized_for_test::<httpserve::Admin>(|rb| {
        let endpoint = httpserve::GeneratedEndpoint::new(
            binding,
            |_: httpserve::ContractMarker<RouteMarker>| async {},
        )?;
        rb.mount(endpoint)
    })
    .unwrap();
    let plan =
        primitives::AuthPlan::new(primitives::ListenerKind::Admin, primitives::AuthScheme::Jwt)
            .unwrap();
    let authed = httpserve::finalize_auth(routes, plan).unwrap();
    let _make = authed.into_make_service();
}
