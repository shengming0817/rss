use axum::extract::State;
use httpserve::routes::unfinalized_for_test;

#[derive(Clone)]
struct ReadState;

impl httpserve::ClassifiedRouteState for ReadState {
    type Effect = diport::ReadEffect;
    type Privilege = diport::LocalPrivilege;
}

enum RouteMarker {}

fn main() {
    let binding = vocab::HttpRouteBinding::<RouteMarker, vocab::http::LocalOnly>::from_static(
        vocab::ContractBinding::from_static(
            "test",
            "ui.local-only-classified",
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
        vocab::HttpEffectProfile::new(&[vocab::HttpEffectKind::Read]),
    );
    let routes = unfinalized_for_test::<httpserve::Admin>(|rb| {
        let endpoint = httpserve::GeneratedEndpoint::new(
            binding,
            |_: httpserve::ContractMarker<RouteMarker>, State(_): State<ReadState>| async {},
        )?
        .with_classified_state(ReadState);
        rb.mount(endpoint)
    })
    .unwrap();
    let plan =
        primitives::AuthPlan::new(primitives::ListenerKind::Admin, primitives::AuthScheme::Jwt)
            .unwrap();
    let _make = httpserve::finalize_auth(routes, plan)
        .unwrap()
        .into_make_service();
}
