#![cfg(feature = "http1")]

use rss_axum::{Http1ServePolicy, ServePolicy};
use std::time::Duration;

#[test]
#[allow(clippy::unwrap_used)] // reason: positive policy is the test fixture.
fn policies_reject_unbounded_or_unsupported_inputs() {
    let second = Duration::from_secs(1);
    assert!(ServePolicy::new(0, second, Duration::from_secs(30), second).is_err());
    for invalid in [Duration::ZERO, Duration::MAX] {
        assert!(ServePolicy::new(1, invalid, Duration::from_secs(30), second).is_err());
        assert!(ServePolicy::new(1, second, Duration::from_secs(30), invalid).is_err());
    }
    let serve = ServePolicy::new(1, second, Duration::from_secs(30), second).unwrap();
    assert!(Http1ServePolicy::new(serve, Duration::ZERO, 64, 32768).is_err());
    assert!(Http1ServePolicy::new(serve, Duration::MAX, 64, 32768).is_err());
    assert!(Http1ServePolicy::new(serve, second, 0, 32768).is_err());
    assert!(Http1ServePolicy::new(serve, second, 64, 8191).is_err());
    assert!(Http1ServePolicy::new(serve, second, 64, 8192).is_ok());
}

#[test]
#[allow(clippy::expect_used)] // reason: known supported fixture budget.
fn phase_timeout_support_is_stable_and_includes_establishment() {
    let day = Duration::from_secs(24 * 60 * 60);
    let too_large = day + Duration::from_nanos(1);
    assert!(ServePolicy::new(1, day, day, day).is_ok());
    assert!(ServePolicy::new(1, too_large, day, day).is_err());
    assert!(ServePolicy::new(1, day, too_large, day).is_err());
    assert!(ServePolicy::new(1, day, day, too_large).is_err());
    assert!(ServePolicy::new(1, day, Duration::ZERO, day).is_err());
    assert!(ServePolicy::new(1, day, Duration::MAX, day).is_err());
    let serve = ServePolicy::new(1, day, day, day).expect("supported policy");
    assert!(Http1ServePolicy::new(serve, day, 64, 32768).is_ok());
    assert!(Http1ServePolicy::new(serve, too_large, 64, 32768).is_err());
}
