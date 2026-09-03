//! Provider-neutral HTTP service core.

use futures::FutureExt as _;

mod budget;
pub mod error;
pub mod health;
pub mod protect;
mod real_ip;
mod server_observation;

pub use budget::{RequestControl, ServerRequestBudget};
pub use protect::{BodyLimit, EdgeHardening, SecurityHeaders};
pub use real_ip::{RealIpLayer, ResolvedClientIp, TrustedProxyConfig, TrustedProxyConfigError};
pub use server_observation::{
    ServerObservationListener, ServerObservationPolicy, ServerResponse, ServerResponseCauseKind,
};

/// Cloneable request core consumed by a transport adapter.
#[derive(Clone)]
#[must_use = "ServerService must be passed to an HTTP transport"]
pub struct ServerService {
    router: axum::Router,
    observation_policy: ServerObservationPolicy,
}

impl ServerService {
    pub fn new(router: axum::Router, listener: ServerObservationListener) -> Self {
        Self {
            router: seal_router(
                router,
                ServerRequestBudget::DEFAULT,
                ServerObservationPolicy::Enabled(listener),
            ),
            observation_policy: ServerObservationPolicy::Enabled(listener),
        }
    }

    pub fn health(routes: health::HealthRoutes) -> Self {
        Self {
            router: seal_router(
                routes.0,
                ServerRequestBudget::DEFAULT,
                ServerObservationPolicy::Disabled,
            ),
            observation_policy: ServerObservationPolicy::Disabled,
        }
    }

    #[cfg(any(test, feature = "test-util"))]
    pub fn from_router_for_test(router: axum::Router, _budget: ServerRequestBudget) -> Self {
        Self {
            router: seal_router(
                router,
                _budget,
                ServerObservationPolicy::Enabled(ServerObservationListener::Other),
            ),
            observation_policy: ServerObservationPolicy::Enabled(ServerObservationListener::Other),
        }
    }

    #[cfg(any(test, feature = "test-util"))]
    pub fn from_health_router_for_test(router: axum::Router) -> Self {
        Self {
            router: seal_router(
                router,
                ServerRequestBudget::DEFAULT,
                ServerObservationPolicy::Disabled,
            ),
            observation_policy: ServerObservationPolicy::Disabled,
        }
    }

    #[must_use]
    pub const fn observation_policy(&self) -> ServerObservationPolicy {
        self.observation_policy
    }
}

fn seal_router(
    router: axum::Router,
    budget: ServerRequestBudget,
    observation_policy: ServerObservationPolicy,
) -> axum::Router {
    let hardening = EdgeHardening::default();
    let router = router
        .layer(axum::middleware::from_fn_with_state(
            hardening.body_limit,
            body_limit,
        ))
        .layer(axum::middleware::from_fn(panic_recovery))
        .layer(axum::middleware::from_fn_with_state(budget, request_budget));
    let mut router = match observation_policy {
        ServerObservationPolicy::Enabled(_) => {
            router.layer(axum::middleware::from_fn(observation_metadata))
        }
        ServerObservationPolicy::Disabled => router,
    };
    for header_layer in hardening.headers.response_layers() {
        router = router.layer(header_layer);
    }
    router
}

async fn body_limit(
    axum::extract::State(limit): axum::extract::State<BodyLimit>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let declared = request
        .headers()
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    if declared.is_some_and(|length| length > limit.bytes() as u64) {
        return error::payload_too_large("");
    }
    let (parts, body) = request.into_parts();
    let body = http_body_util::Limited::new(body, limit.bytes());
    next.run(axum::http::Request::from_parts(
        parts,
        axum::body::Body::new(body),
    ))
    .await
}

async fn request_budget(
    axum::extract::State(budget): axum::extract::State<ServerRequestBudget>,
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let control = RequestControl::start(budget);
    request.extensions_mut().insert(control.clone());
    let _cancel_on_drop = budget::CancelRequestOnDrop(control.clone());
    match tokio::time::timeout_at(control.deadline().instant().into(), next.run(request)).await {
        Ok(response) => response,
        Err(_) => mark_response_cause(
            error::service_unavailable(""),
            server_observation::ServerResponseCause::timeout(),
        ),
    }
}

async fn observation_metadata(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let route = request
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(server_observation::ServerObservationRoute::from_matched_path);
    let mut response = next.run(request).await;
    if let Some(route) = route {
        response.extensions_mut().insert(route);
    }
    response
}

async fn panic_recovery(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    match std::panic::AssertUnwindSafe(next.run(request))
        .catch_unwind()
        .await
    {
        Ok(response) => response,
        Err(_) => mark_response_cause(
            error::internal_error(""),
            server_observation::ServerResponseCause::panic(),
        ),
    }
}

fn mark_response_cause(
    mut response: axum::response::Response,
    cause: server_observation::ServerResponseCause,
) -> axum::response::Response {
    response.extensions_mut().insert(cause);
    response
}

impl tower::Service<axum::extract::Request> for ServerService {
    type Response = ServerResponse;
    type Error = core::convert::Infallible;
    type Future =
        ServerResponseFuture<<axum::Router as tower::Service<axum::extract::Request>>::Future>;

    fn poll_ready(
        &mut self,
        context: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<(), Self::Error>> {
        <axum::Router as tower::Service<axum::extract::Request>>::poll_ready(
            &mut self.router,
            context,
        )
    }

    fn call(&mut self, request: axum::extract::Request) -> Self::Future {
        ServerResponseFuture {
            inner: <axum::Router as tower::Service<axum::extract::Request>>::call(
                &mut self.router,
                request,
            ),
        }
    }
}

pub struct ServerResponseFuture<F> {
    inner: F,
}

impl<F> core::future::Future for ServerResponseFuture<F>
where
    F: core::future::Future<Output = Result<axum::response::Response, core::convert::Infallible>>
        + Unpin,
{
    type Output = Result<ServerResponse, core::convert::Infallible>;

    fn poll(
        mut self: core::pin::Pin<&mut Self>,
        context: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        core::pin::Pin::new(&mut self.inner)
            .poll(context)
            .map(|result| result.map(ServerResponse::from_response))
    }
}

#[cfg(test)]
mod hardening_tests {
    use super::*;
    use axum::http::{Request, StatusCode, header};
    use tower::ServiceExt as _;

    #[tokio::test]
    #[allow(clippy::expect_used)]
    // reason: every request component is a static, known-valid test fixture.
    async fn sealed_service_rejects_declared_oversize_and_adds_security_headers() {
        let router = axum::Router::new().route("/", axum::routing::post(|| async { "ok" }));
        let service = ServerService::from_router_for_test(router, ServerRequestBudget::DEFAULT);
        let request = Request::builder()
            .method("POST")
            .uri("/")
            .header(header::CONTENT_LENGTH, BodyLimit::DEFAULT.bytes() + 1)
            .body(axum::body::Body::empty())
            .expect("valid request");

        let response = service
            .oneshot(request)
            .await
            .expect("infallible service")
            .into_response();

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        assert_eq!(response.headers()["x-frame-options"], "DENY");
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert!(response.headers().contains_key("strict-transport-security"));
    }
}
