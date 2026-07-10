//! ROUTE-ENDPOINT-REQUIRED-01: a typed route binding alone cannot construct an endpoint.

const EFFECTS: &[vocab::HttpEffectKind] = &[vocab::HttpEffectKind::Auth];
enum RouteMarker {}

fn main() {
    let binding = vocab::HttpRouteBinding::<RouteMarker>::from_static(
        vocab::ContractBinding::from_static(
            "test",
            "ui.missing-handler",
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
    let _ = httpserve::GeneratedEndpoint::<()>::new(binding);
}
