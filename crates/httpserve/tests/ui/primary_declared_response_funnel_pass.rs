//! DECLARED-HTTP-RESPONSE-01: Primary declared routes accept the exact generated output.

use axum::response::{IntoResponse, Response};

enum RouteMarker {}
struct DeclaredOutput;

impl IntoResponse for DeclaredOutput {
    fn into_response(self) -> Response {
        ().into_response()
    }
}

impl vocab::http::DeclaredHttpResponseMarker for RouteMarker {
    type HandlerOutput = DeclaredOutput;
}

fn main() {
    let _ = httpserve::GeneratedPrimaryEndpoint::<(), vocab::http::LocalOnly>::new_declared(
        binding(),
        |_: httpserve::ContractMarker<RouteMarker>| async { DeclaredOutput },
    );
}

fn binding() -> vocab::HttpRouteBinding<RouteMarker, vocab::http::LocalOnly> {
    vocab::HttpRouteBinding::from_static(
        vocab::HttpContractOwner::domain("test"),
        vocab::ContractBinding::from_static("test", "ui.primary-declared-pass", "v1", "sha256:0000000000000000000000000000000000000000000000000000000000000000"),
        "/x", "GET", &[], vocab::HttpSuccessStatus::new(200), vocab::HttpIdempotency::Idempotent,
        vocab::HttpRouteAuth::ServiceOwned, None, false, vocab::http::HttpResourceSharing::TenantScoped,
        vocab::HttpEffectProfile::new(&[vocab::HttpEffectKind::Auth]),
    )
}
