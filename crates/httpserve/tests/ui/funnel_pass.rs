//! 正向（compile pass）：funnel 正确用法编译通过（anti-vacuity——证明 compile_fail 用例非「整个 API 不可用」）。
use axum::extract::State;
use httpserve::routes::unfinalized_for_test;
use std::sync::Arc;

struct AllowAll;

impl diport::RateLimiter for AllowAll {
    async fn check(
        &self,
        _key: diport::RateLimitKey,
    ) -> Result<diport::RateLimitDecision, diport::RateLimitError> {
        Ok(diport::RateLimitDecision::Allowed)
    }

    async fn shutdown(&self) -> Result<(), diport::RateLimitError> {
        Ok(())
    }
}

enum RouteMarker {}
enum StatefulRouteMarker {}

impl vocab::http::OpenHttpResponseMarker for RouteMarker {}
impl vocab::http::OpenHttpResponseMarker for StatefulRouteMarker {}

fn main() {
    const EFFECTS: &[vocab::HttpEffectKind] = &[vocab::HttpEffectKind::Auth];
    let binding = vocab::HttpRouteBinding::<RouteMarker, vocab::http::LocalOnly>::from_static(
        vocab::HttpContractOwner::domain("test"),
        vocab::ContractBinding::from_static(
            "test",
            "ui.pass",
            "v1",
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        ),
        "/x",
        "GET",
        &[],
        vocab::HttpSuccessStatus::new(200),
        vocab::HttpIdempotency::Idempotent,
        vocab::HttpRouteAuth::ServiceOwned,
        None,
        false,
        vocab::http::HttpResourceSharing::TenantScoped,
        vocab::HttpEffectProfile::new(EFFECTS),
    );
    let routes = unfinalized_for_test::<httpserve::Admin>(|rb| {
        let endpoint = httpserve::GeneratedEndpoint::new(
            binding,
            |_: httpserve::ContractMarker<RouteMarker>| async {},
        )?;
        let rb = rb.mount(endpoint)?;
        let stateful_binding =
            vocab::HttpRouteBinding::<StatefulRouteMarker, vocab::http::LocalTx>::from_static(
                vocab::HttpContractOwner::domain("test"),
                vocab::ContractBinding::from_static(
                    "test",
                    "ui.pass-stateful",
                    "v1",
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                ),
                "/stateful",
                "GET",
                &[],
                vocab::HttpSuccessStatus::new(200),
                vocab::HttpIdempotency::Idempotent,
                vocab::HttpRouteAuth::ServiceOwned,
                None,
                false,
                vocab::http::HttpResourceSharing::TenantScoped,
                vocab::HttpEffectProfile::new(&[vocab::HttpEffectKind::Read]),
            );
        rb.mount(
            httpserve::GeneratedEndpoint::new(
                stateful_binding,
                |_: httpserve::ContractMarker<StatefulRouteMarker>, State(_): State<String>| async {
                },
            )?
            .with_state(String::new()),
        )
    })
    .unwrap();
    let plan = primitives::AuthPlan::new(
        primitives::ListenerKind::Admin,
        primitives::AuthScheme::RssAccessToken,
    )
    .unwrap();
    let authed = httpserve::finalize_auth(routes, plan).unwrap();
    let rate_limited = httpserve::with_client_rate_limit(
        authed,
        Arc::new(AllowAll),
        httpserve::TrustedProxyConfig::disabled(),
    );
    let _make = rate_limited.into_server_service(httpserve::ServerRequestBudget::for_test());
}
