//! Auth-finalized routes are not a production bind capability. Business listeners must consume
//! the client-rate-limit funnel and Health must use its distinct finalizer.
use httpserve::routes::unfinalized_for_test;

fn main() {
    let routes = unfinalized_for_test::<httpserve::Admin>(Ok).unwrap();
    let plan = primitives::AuthPlan::new(
        primitives::ListenerKind::Admin,
        primitives::AuthScheme::RssAccessToken,
    )
    .unwrap();
    let authenticated = httpserve::finalize_auth(routes, plan).unwrap();
    let _service =
        authenticated.into_server_service(httpserve::ServerRequestBudget::for_test());
}
