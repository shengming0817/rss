//! ROUTE-ENDPOINT-ATOMIC-01: the field-by-field legacy route carrier no longer exists.

fn main() {
    let _ = httpserve::Route {
        method: axum::http::Method::GET,
        path: "/x",
        contract_id: "ui.old",
    };
    let _ = core::mem::size_of::<httpserve::PrimaryRoute>();
    let _ = core::mem::size_of::<httpserve::RoutePermission>();
    let _ = core::mem::size_of::<httpserve::RouteResourceScope>();
}

fn old_primary_mount(router: httpserve::ListenerRouter<httpserve::Primary>) {
    let _ = router.mount_primary(axum::routing::get(|| async { "old" }));
}
