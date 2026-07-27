//! ROUTE-LISTENER-TYPED-01: a non-Primary generated endpoint cannot mount on Primary.

use httpserve::routes::unfinalized_for_test;

const EFFECTS: &[vocab::HttpEffectKind] = &[vocab::HttpEffectKind::Auth];
enum RouteMarker {}

fn endpoint() -> httpserve::GeneratedEndpoint<(), vocab::http::LocalOnly> {
    let binding = vocab::HttpRouteBinding::<RouteMarker, vocab::http::LocalOnly>::from_static(
        vocab::HttpContractOwner::domain("test"),
        vocab::ContractBinding::from_static(
            "test",
            "ui.non-primary",
            "v1",
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        ),
        "/x",
        "GET",
        vocab::HttpSuccessStatus::new(200),
        vocab::HttpIdempotency::Idempotent,
        vocab::HttpRouteAuth::ServiceOwned,
        None,
        false,
        vocab::http::HttpResourceSharing::TenantScoped,
        vocab::HttpEffectProfile::new(EFFECTS),
    );
    httpserve::GeneratedEndpoint::new(binding, |_: httpserve::ContractMarker<RouteMarker>| async {
    })
    .unwrap()
}

fn main() {
    let _primary = unfinalized_for_test::<httpserve::Primary>(|rb| rb.mount(endpoint()));
}
