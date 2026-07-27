//! ROUTE-LISTENER-TYPED-01: a Primary generated endpoint cannot mount on any non-Primary listener.

use httpserve::routes::unfinalized_for_test;

const EFFECTS: &[vocab::HttpEffectKind] = &[vocab::HttpEffectKind::Auth];
enum RouteMarker {}

fn endpoint() -> httpserve::GeneratedPrimaryEndpoint<(), vocab::http::LocalOnly> {
    let binding = vocab::HttpRouteBinding::<RouteMarker, vocab::http::LocalOnly>::from_static(
        vocab::HttpContractOwner::domain("test"),
        vocab::ContractBinding::from_static(
            "test",
            "ui.primary",
            "v1",
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        ),
        "/x",
        "GET",
        vocab::HttpSuccessStatus::new(200),
        vocab::HttpIdempotency::Idempotent,
        vocab::HttpRouteAuth::Public,
        None,
        false,
        vocab::http::HttpResourceSharing::TenantScoped,
        vocab::HttpEffectProfile::new(EFFECTS),
    );
    httpserve::GeneratedPrimaryEndpoint::new(
        binding,
        |_: httpserve::ContractMarker<RouteMarker>| async {},
    )
    .unwrap()
}

fn main() {
    let _internal = unfinalized_for_test::<httpserve::Internal>(|rb| rb.mount(endpoint()));
    let _admin = unfinalized_for_test::<httpserve::Admin>(|rb| rb.mount(endpoint()));
    let _health = unfinalized_for_test::<httpserve::Health>(|rb| rb.mount(endpoint()));
}
