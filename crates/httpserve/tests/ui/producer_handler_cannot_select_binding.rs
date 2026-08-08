use vocab::http::{
    HttpEffectKind, HttpEffectProfile, HttpIdempotency, HttpProducerBinding, HttpRouteBinding,
    HttpSuccessStatus, OutboxFact,
};
use vocab::{ContractBinding, HttpContractOwner, HttpRouteAuth};

enum RouteMarker {}

const FACT: ContractBinding = ContractBinding::from_static(
    "identity",
    "identity.session-created",
    "v1",
    "sha256:1111111111111111111111111111111111111111111111111111111111111111",
);
const FORGED_FACT: ContractBinding = ContractBinding::from_static(
    "identity",
    "identity.policy-updated",
    "v1",
    "sha256:2222222222222222222222222222222222222222222222222222222222222222",
);
const EFFECTS: &[HttpEffectKind] = &[
    HttpEffectKind::BusinessWrite,
    HttpEffectKind::BusinessTransaction,
    HttpEffectKind::Outbox,
    HttpEffectKind::Publish,
];
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
    HttpEffectProfile::new(EFFECTS),
);
const FORGED_ROUTE: HttpRouteBinding<RouteMarker, OutboxFact> = HttpRouteBinding::from_static(
    HttpContractOwner::domain("identity"),
    ContractBinding::from_static(
        "identity",
        "identity.policies.update",
        "v1",
        "sha256:3333333333333333333333333333333333333333333333333333333333333333",
    ),
    "/v1/policies/{policyId}",
    "PUT",
    &[],
    HttpSuccessStatus::new(200),
    HttpIdempotency::Idempotent,
    HttpRouteAuth::Public,
    None,
    false,
    vocab::http::HttpResourceSharing::TenantScoped,
    HttpEffectProfile::new(EFFECTS),
);
const PRODUCER: HttpProducerBinding<RouteMarker> = HttpProducerBinding::from_static(ROUTE, &[FACT]);
const FORGED_PRODUCER: HttpProducerBinding<RouteMarker> =
    HttpProducerBinding::from_static(FORGED_ROUTE, &[FORGED_FACT]);

async fn handler(marker: httpserve::ProducerMarker<RouteMarker>) {
    let _ = marker.into_receipt(FORGED_PRODUCER);
}

fn main() {
    let _ = httpserve::GeneratedPrimaryEndpoint::<(), OutboxFact>::new_producer(PRODUCER, handler);
}
