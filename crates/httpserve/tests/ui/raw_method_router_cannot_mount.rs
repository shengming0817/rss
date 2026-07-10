//! ROUTE-MOUNT-NOBYPASS-01: production mounting accepts a generated endpoint, not MethodRouter.

use httpserve::routes::unfinalized_for_test;

fn main() {
    let _ = unfinalized_for_test::<httpserve::Admin>(|rb| {
        rb.mount(axum::routing::get(|| async { "raw" }))
    });
}
