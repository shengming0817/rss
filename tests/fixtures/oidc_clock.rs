#[path = "pg_clock.rs"]
mod pg_clock;

#[allow(
    clippy::disallowed_methods,
    reason = "test host provides the UTC clock"
)]
pub fn clock() -> rss_identity_oidc::ProviderClock {
    rss_identity_oidc::ProviderClock::new(
        rss_request_context::SharedExecutionTimer::new(pg_clock::TestClock),
        std::time::SystemTime::now,
    )
}
