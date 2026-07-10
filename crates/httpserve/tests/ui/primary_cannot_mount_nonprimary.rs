//! ROUTE-LISTENER-TYPED-01: a non-Primary generated endpoint cannot mount on Primary.

use httpserve::routes::unfinalized_for_test;

const EFFECTS: &[vocab::HttpEffectKind] = &[vocab::HttpEffectKind::Auth];
enum RouteMarker {}

fn endpoint() -> httpserve::GeneratedEndpoint<()> {
    let binding = vocab::HttpRouteBinding::<RouteMarker>::from_static(
        vocab::ContractBinding::from_static(
            "test",
            "ui.non-primary",
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
    httpserve::GeneratedEndpoint::new(
        binding,
        |_: httpserve::ContractMarker<RouteMarker>| async {},
    )
    .unwrap()
}

fn main() {
    let _primary = unfinalized_for_test::<httpserve::Primary>(|rb| rb.mount(endpoint()));
}
