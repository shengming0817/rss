enum RouteMarker {}

fn main() {
    let binding = vocab::HttpRouteBinding::<RouteMarker, vocab::http::LocalTx>::from_static(
        vocab::HttpContractOwner::domain("test"),
        vocab::ContractBinding::from_static(
            "test",
            "ui.consistency-mismatch",
            "v1",
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        ),
        "/x",
        "POST",
        vocab::HttpSuccessStatus::new(200),
        vocab::HttpIdempotency::Idempotent,
        vocab::HttpRouteAuth::ServiceOwned,
        None,
        false,
        vocab::HttpEffectProfile::new(&[vocab::HttpEffectKind::Transaction]),
    );
    let _ = httpserve::GeneratedEndpoint::<(), vocab::http::LocalOnly>::new(
        binding,
        |_: httpserve::ContractMarker<RouteMarker>| async {},
    );
}
