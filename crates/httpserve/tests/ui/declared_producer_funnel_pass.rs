//! DECLARED-HTTP-RESPONSE-01: OutboxFact producers support exact declared handler output.

use axum::response::{IntoResponse, Response};
use vocab::http::{
    HttpEffectKind, HttpEffectProfile, HttpIdempotency, HttpProducerBinding, HttpRouteBinding,
    HttpSuccessStatus, OutboxFact,
};
use vocab::{ContractBinding, HttpContractOwner, HttpRouteAuth};

enum RouteMarker {}
struct DeclaredOutput;

impl IntoResponse for DeclaredOutput {
    fn into_response(self) -> Response { ().into_response() }
}

impl vocab::http::DeclaredHttpResponseMarker for RouteMarker {
    type HandlerOutput = DeclaredOutput;
}

const FACT: ContractBinding = ContractBinding::from_static(
    "identity", "identity.session-created", "v1",
    "sha256:1111111111111111111111111111111111111111111111111111111111111111",
);
const EFFECTS: &[HttpEffectKind] = &[
    HttpEffectKind::BusinessWrite, HttpEffectKind::BusinessTransaction,
    HttpEffectKind::Outbox, HttpEffectKind::Publish,
];
const ROUTE: HttpRouteBinding<RouteMarker, OutboxFact> = HttpRouteBinding::from_static(
    HttpContractOwner::domain("identity"),
    ContractBinding::from_static("identity", "identity.login", "v1", "sha256:0000000000000000000000000000000000000000000000000000000000000000"),
    "/v1/login", "POST", &[], HttpSuccessStatus::new(200), HttpIdempotency::NonIdempotent,
    HttpRouteAuth::Public, None, false, vocab::http::HttpResourceSharing::TenantScoped,
    HttpEffectProfile::new(EFFECTS),
);
const PRODUCER: HttpProducerBinding<RouteMarker> = HttpProducerBinding::from_static(ROUTE, &[FACT]);

async fn handler(_: httpserve::ProducerMarker<RouteMarker>) -> DeclaredOutput { DeclaredOutput }

fn main() {
    let _ = httpserve::GeneratedPrimaryEndpoint::<(), OutboxFact>::new_declared_producer(
        PRODUCER, handler,
    );
}
