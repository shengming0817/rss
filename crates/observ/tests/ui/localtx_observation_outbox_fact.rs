use consistency::LocalTxBoundary;
use observ::LocalTxObservation;
use vocab::{
    ContractBinding, HttpContractOwner, HttpEffectKind, HttpEffectProfile, HttpIdempotency,
    HttpRouteAuth, HttpRouteBinding, HttpSuccessStatus, http::OutboxFact,
};

struct Route;

fn main() {
    let route = HttpRouteBinding::<Route, OutboxFact>::from_static(
        HttpContractOwner::domain("identity"),
        ContractBinding::from_static("identity", "identity.test", "v1", "test"),
        "/test",
        "POST",
        HttpSuccessStatus::new(204),
        HttpIdempotency::NonIdempotent,
        HttpRouteAuth::ServiceOwned,
        None,
        false,
        vocab::http::HttpResourceSharing::TenantScoped,
        HttpEffectProfile::new(&[HttpEffectKind::BusinessWrite]),
    );
    let _ = LocalTxObservation::new(route, LocalTxBoundary::SingleDomain);
}
