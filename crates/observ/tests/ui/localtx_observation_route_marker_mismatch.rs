use consistency::LocalTxBoundary;
use observ::LocalTxObservation;
use vocab::{
    ContractBinding, HttpContractOwner, HttpEffectKind, HttpEffectProfile, HttpIdempotency,
    HttpRouteAuth, HttpRouteBinding, HttpSuccessStatus,
    http::LocalTx,
};

struct PasswordChangeRoute;
struct LogoutRoute;

fn route() -> HttpRouteBinding<LogoutRoute, LocalTx> {
    HttpRouteBinding::from_static(
        HttpContractOwner::domain("identity"),
        ContractBinding::from_static("identity", "identity.logout", "v1", "test"),
        "/test",
        "POST",
        HttpSuccessStatus::new(204),
        HttpIdempotency::NonIdempotent,
        HttpRouteAuth::ServiceOwned,
        None,
        false,
        HttpEffectProfile::new(&[HttpEffectKind::Write]),
    )
}

fn accept_password_change(_: LocalTxObservation<PasswordChangeRoute>) {}

fn main() {
    let logout = LocalTxObservation::new(route(), LocalTxBoundary::SingleDomain);
    accept_password_change(logout);
}
