#![cfg(feature = "http1")]

use rss_axum::{Http1ServePolicy, ServePolicy};
use std::time::Duration;

#[test]
#[allow(clippy::unwrap_used)] // reason: positive policy is the test fixture.
fn policies_reject_unbounded_or_unrepresentable_inputs() {
    let second = Duration::from_secs(1);
    assert!(ServePolicy::new(0, second, second).is_err());
    for invalid in [Duration::ZERO, Duration::MAX] {
        assert!(ServePolicy::new(1, invalid, second).is_err());
        assert!(ServePolicy::new(1, second, invalid).is_err());
    }
    let serve = ServePolicy::new(1, second, second).unwrap();
    assert!(Http1ServePolicy::new(serve, Duration::ZERO, 64, 32768).is_err());
    assert!(Http1ServePolicy::new(serve, Duration::MAX, 64, 32768).is_err());
    assert!(Http1ServePolicy::new(serve, second, 0, 32768).is_err());
    assert!(Http1ServePolicy::new(serve, second, 64, 8191).is_err());
    assert!(Http1ServePolicy::new(serve, second, 64, 8192).is_ok());
}
