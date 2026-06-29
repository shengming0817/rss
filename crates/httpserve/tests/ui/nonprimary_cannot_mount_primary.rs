//! ROUTE-LISTENER-TYPED-01：`mount_primary`（opt-out）仅 `ListenerRouter<Primary>`——**全部** non-Primary
//! listener（Internal / Admin / Health）均不可 `mount_primary`（三者覆盖，非仅 Internal 代表）。
use httpserve::routes::unfinalized_for_test;
use httpserve::{RoutePermission, RouteResourceScope};

fn main() {
    let _internal = unfinalized_for_test::<httpserve::Internal>(|rb| {
        rb.mount_primary(
            httpserve::PrimaryRoute::permission(axum::http::Method::GET, "/x", "ui.fail", RoutePermission { permission: "test:read", scope: RouteResourceScope::None }),
            axum::routing::get(|| async {}),
        )
    });
    let _admin = unfinalized_for_test::<httpserve::Admin>(|rb| {
        rb.mount_primary(
            httpserve::PrimaryRoute::permission(axum::http::Method::GET, "/x", "ui.fail", RoutePermission { permission: "test:read", scope: RouteResourceScope::None }),
            axum::routing::get(|| async {}),
        )
    });
    let _health = unfinalized_for_test::<httpserve::Health>(|rb| {
        rb.mount_primary(
            httpserve::PrimaryRoute::permission(axum::http::Method::GET, "/x", "ui.fail", RoutePermission { permission: "test:read", scope: RouteResourceScope::None }),
            axum::routing::get(|| async {}),
        )
    });
}
