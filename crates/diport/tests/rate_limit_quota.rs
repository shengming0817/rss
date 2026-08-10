use diport::RateLimitQuota;

#[test]
#[allow(clippy::expect_used)]
// reason: fixed valid quota literals make construction failure a test setup defect.
fn quota_accepts_closed_safe_range() {
    let quota = RateLimitQuota::try_new(10, 20).expect("valid quota");
    assert_eq!(quota.per_second(), 10);
    assert_eq!(quota.burst(), 20);
    assert!(RateLimitQuota::try_new(1_000_000, 1_000_000).is_ok());
}

#[test]
fn quota_rejects_zero_and_values_above_safe_range() {
    assert!(RateLimitQuota::try_new(0, 1).is_err());
    assert!(RateLimitQuota::try_new(1, 0).is_err());
    assert!(RateLimitQuota::try_new(1_000_001, 1).is_err());
    assert!(RateLimitQuota::try_new(1, 1_000_001).is_err());
}
