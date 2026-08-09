use vocab::http::{
    HttpEffectKind, HttpEffectProfile, HttpIdempotency, HttpRouteBinding, HttpSuccessStatus,
    OutboxFact,
};
use vocab::{ContractBinding, HttpContractOwner, HttpRouteAuth};

enum RouteMarker {}
impl vocab::http::OpenHttpResponseMarker for RouteMarker {}

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

async fn handler(_: httpserve::ContractMarker<RouteMarker>) {}

fn main() {
    let _ = httpserve::GeneratedPrimaryEndpoint::<(), OutboxFact>::new(ROUTE, handler);
}
