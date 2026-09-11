//! Scenario adapters use explicit production policies.
use axum::Router;
use rss_axum::{PlainTransport, ServePolicy};
use rss_runtime::ManagedTaskRegistration;
use std::time::Duration;
use tokio::net::TcpListener;

#[allow(clippy::expect_used)] // reason: fixed valid scenario budgets.
fn policy(drain: Duration) -> ServePolicy {
    ServePolicy::new(128, Duration::from_secs(8), drain).expect("valid policy")
}
#[cfg(feature = "http1")]
#[allow(clippy::expect_used)] // reason: existing tests exercise the 30-second header deadline.
fn h1_policy(drain: Duration) -> rss_axum::Http1ServePolicy {
    rss_axum::Http1ServePolicy::new(policy(drain), Duration::from_secs(30), 64, 32768)
        .expect("valid H1 policy")
}
#[cfg(feature = "http1")]
#[allow(dead_code)] // reason: harness is shared by separate H1 and H2 targets.
pub fn http1(
    listener: TcpListener,
    router: Router,
    name: &'static str,
    drain: Duration,
) -> ManagedTaskRegistration {
    rss_axum::serve_http1_registration(listener, router, PlainTransport, name, h1_policy(drain))
}
#[cfg(feature = "http2")]
#[allow(dead_code)] // reason: harness is shared by separate H1 and H2 targets.
pub fn http2(
    listener: TcpListener,
    router: Router,
    name: &'static str,
    drain: Duration,
) -> ManagedTaskRegistration {
    rss_axum::serve_http2_registration(listener, router, PlainTransport, name, policy(drain))
}
#[cfg(feature = "auto-protocol")]
pub fn auto(
    listener: TcpListener,
    router: Router,
    name: &'static str,
    drain: Duration,
) -> ManagedTaskRegistration {
    rss_axum::serve_auto_registration(listener, router, PlainTransport, name, h1_policy(drain))
}
