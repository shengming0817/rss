use httpserve::routes::unfinalized_for_test;

enum RouteMarker {}

fn main() {
    const EFFECTS: &[vocab::HttpEffectKind] = &[vocab::HttpEffectKind::Auth];
    let binding = vocab::HttpRouteBinding::<RouteMarker, vocab::http::LocalOnly>::from_static(
        vocab::HttpContractOwner::domain("test"),
        vocab::ContractBinding::from_static(
            "test",
            "ui.internal-policy",
            "v1",
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        ),
        "/internal",
        "POST",
        vocab::HttpSuccessStatus::new(200),
        vocab::HttpIdempotency::Idempotent,
        vocab::HttpRouteAuth::ServiceOwned,
        None,
        false,
        vocab::http::HttpResourceSharing::TenantScoped,
        vocab::HttpEffectProfile::new(EFFECTS),
    );
    let endpoint = httpserve::GeneratedEndpoint::new(
        binding,
        |_: httpserve::ContractMarker<RouteMarker>| async {},
    )
    .unwrap();
    let _ = unfinalized_for_test::<httpserve::Internal>(|router| router.mount(endpoint));
}
