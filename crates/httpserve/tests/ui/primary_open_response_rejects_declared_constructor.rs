//! DECLARED-HTTP-RESPONSE-01: Primary open markers cannot use the declared constructor.

enum RouteMarker {}
impl vocab::http::OpenHttpResponseMarker for RouteMarker {}

fn main() {
    let _ = httpserve::GeneratedPrimaryEndpoint::<(), vocab::http::LocalOnly>::new_declared(
        binding(),
        |_: httpserve::ContractMarker<RouteMarker>| async {},
    );
}

fn binding() -> vocab::HttpRouteBinding<RouteMarker, vocab::http::LocalOnly> {
    vocab::HttpRouteBinding::from_static(
        vocab::HttpContractOwner::domain("test"),
        vocab::ContractBinding::from_static("test", "ui.primary-open-declared", "v1", "sha256:0000000000000000000000000000000000000000000000000000000000000000"),
        "/x", "GET", &[], vocab::HttpSuccessStatus::new(200), vocab::HttpIdempotency::Idempotent,
        vocab::HttpRouteAuth::ServiceOwned, None, false, vocab::http::HttpResourceSharing::TenantScoped,
        vocab::HttpEffectProfile::new(&[vocab::HttpEffectKind::Auth]),
    )
}
