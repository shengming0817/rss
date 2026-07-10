//! ROUTE-ENDPOINT-REQUIRED-01: a generated endpoint cannot be built from a handler alone.

fn main() {
    let _ = httpserve::GeneratedEndpoint::<()>::new(|| async { "ok" });
}
