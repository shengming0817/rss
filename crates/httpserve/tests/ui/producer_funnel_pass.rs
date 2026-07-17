use vocab::http::{
    HttpEffectKind, HttpEffectProfile, HttpIdempotency, HttpProducerBinding, HttpRouteBinding,
    HttpSuccessStatus, OutboxFact,
};
use vocab::{ContractBinding, HttpContractOwner, HttpRouteAuth};

enum RouteMarker {}

const HTTP_CONTRACT: ContractBinding = ContractBinding::from_static(
    "identity",
    "identity.login",
    "v1",
    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
);
const FACT_CONTRACT: ContractBinding = ContractBinding::from_static(
    "identity",
    "identity.session-created",
    "v1",
    "sha256:1111111111111111111111111111111111111111111111111111111111111111",
);
const EFFECTS: &[HttpEffectKind] = &[
    HttpEffectKind::BusinessWrite,
    HttpEffectKind::BusinessTransaction,
    HttpEffectKind::Outbox,
    HttpEffectKind::Publish,
];
const ROUTE: HttpRouteBinding<RouteMarker, OutboxFact> = HttpRouteBinding::from_static(
    HttpContractOwner::domain("identity"),
    HTTP_CONTRACT,
    "/v1/login",
    "POST",
    HttpSuccessStatus::new(201),
    HttpIdempotency::NonIdempotent,
    HttpRouteAuth::Public,
    None,
    false,
    HttpEffectProfile::new(EFFECTS),
);
const PRODUCER: HttpProducerBinding<RouteMarker> =
    HttpProducerBinding::from_static(ROUTE, &[FACT_CONTRACT]);

async fn handler(marker: httpserve::ProducerMarker<RouteMarker>) {
    let receipt = marker.into_receipt();
    let authorization = receipt.authorize(FACT_CONTRACT).expect("generated fact");
    assert_eq!(authorization.fact_contract(), FACT_CONTRACT);
}

fn main() {
    let _ = httpserve::GeneratedPrimaryEndpoint::<(), OutboxFact>::new_producer(PRODUCER, handler);
}
