use vocab::http::{
    HttpEffectKind, HttpEffectProfile, HttpIdempotency, HttpProducerBinding, HttpRouteBinding,
    HttpSuccessStatus, OutboxFact,
};
use vocab::{ContractBinding, HttpContractOwner, HttpRouteAuth};

enum RouteMarker {}
impl vocab::http::OpenHttpResponseMarker for RouteMarker {}
enum OtherRouteMarker {}

const FACT: ContractBinding = ContractBinding::from_static(
    "identity",
    "identity.session-created",
    "v1",
    "sha256:1111111111111111111111111111111111111111111111111111111111111111",
);
const ROUTE: HttpRouteBinding<RouteMarker, OutboxFact> = HttpRouteBinding::from_static(
    HttpContractOwner::domain("identity"),
    ContractBinding::from_static(
        "identity",
        "identity.login",
        "v1",
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    ),
    "/v1/login",
    "POST",
    &[],
    HttpSuccessStatus::new(201),
    HttpIdempotency::NonIdempotent,
    HttpRouteAuth::Public,
    None,
    false,
    vocab::http::HttpResourceSharing::TenantScoped,
    HttpEffectProfile::new(&[
        HttpEffectKind::BusinessWrite,
        HttpEffectKind::BusinessTransaction,
        HttpEffectKind::Outbox,
        HttpEffectKind::Publish,
    ]),
);
const PRODUCER: HttpProducerBinding<RouteMarker> = HttpProducerBinding::from_static(ROUTE, &[FACT]);

async fn wrong_handler(marker: httpserve::ProducerMarker<OtherRouteMarker>) {
    let _ = marker.into_receipt();
}

fn main() {
    let _ = httpserve::GeneratedPrimaryEndpoint::<(), OutboxFact>::new_producer(
        PRODUCER,
        wrong_handler,
    );
}
