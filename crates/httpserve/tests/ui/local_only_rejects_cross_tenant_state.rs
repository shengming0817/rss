use axum::extract::State;

#[derive(Clone)]
struct CrossTenantState;

impl httpserve::ClassifiedRouteState for CrossTenantState {
    type Effect = diport::ReadEffect;
    type Privilege = diport::CrossTenantPrivilege;
}

enum RouteMarker {}

fn main() {
    let binding = vocab::HttpRouteBinding::<RouteMarker, vocab::http::LocalOnly>::from_static(
        vocab::HttpContractOwner::domain("test"),
        vocab::ContractBinding::from_static(
            "test",
            "ui.local-only-cross-tenant",
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
        vocab::HttpEffectProfile::new(&[vocab::HttpEffectKind::Read]),
    );
    let endpoint = httpserve::GeneratedEndpoint::new(
        binding,
        |_: httpserve::ContractMarker<RouteMarker>, State(_): State<CrossTenantState>| async {},
    )
    .unwrap();
    let _ = endpoint.with_classified_state(CrossTenantState);
}
