//! ServerService is an opaque capability; external code cannot populate its private fields.
fn main() {
    let _service = httpserve::ServerService {
        router: axum::Router::new(),
        observation_policy: httpserve::ServerObservationPolicy::Disabled,
    };
}
