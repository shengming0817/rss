use axum::extract::State;

#[derive(Clone)]
struct WriteState;

impl httpserve::ClassifiedRouteState for WriteState {
    type Effect = diport::WriteEffect;
    type Privilege = diport::LocalPrivilege;
}

enum RouteMarker {}

fn main() {
    let binding = vocab::HttpRouteBinding::<RouteMarker, vocab::http::LocalOnly>::from_static(
        vocab::ContractBinding::from_static(
            "test",
            "ui.primary-local-only-write",
            "v1",
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        ),
        "/x",
        "GET",
        vocab::HttpRouteAuth::ServiceOwned,
        None,
        false,
        vocab::HttpEffectProfile::new(&[vocab::HttpEffectKind::Read]),
    );
    let endpoint = httpserve::GeneratedPrimaryEndpoint::new(
        binding,
        |_: httpserve::ContractMarker<RouteMarker>, State(_): State<WriteState>| async {},
    )
    .unwrap();
    let _ = endpoint.with_classified_state(WriteState);
}
