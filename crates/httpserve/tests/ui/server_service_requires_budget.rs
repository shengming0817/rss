//! Final transport capability construction must consume a non-zero server request budget.
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

fn main() {
    let routes = unfinalized_for_test::<httpserve::Admin>(Ok).unwrap();
    let plan = primitives::AuthPlan::new(
        primitives::ListenerKind::Admin,
        primitives::AuthScheme::RssAccessToken,
    )
    .unwrap();
    let authenticated = httpserve::finalize_auth(routes, plan).unwrap();
    let rate_limited = httpserve::with_client_rate_limit(
        authenticated,
        Arc::new(AllowAll),
        httpserve::TrustedProxyConfig::disabled(),
    );
    let _service = rate_limited.into_server_service();
}
