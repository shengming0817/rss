#![allow(clippy::expect_used)]
// reason: fixed policy fixtures must fail loudly if construction unexpectedly regresses.

use std::time::Duration;

use rss_transactional_messaging::policy::{LeaseRenewalPolicy, LeaseRenewalPolicyError};

#[test]
fn lease_renewal_is_one_third_of_ttl_with_one_millisecond_floor() {
    assert_eq!(
        LeaseRenewalPolicy::from_ttl(Duration::ZERO),
        Err(LeaseRenewalPolicyError::ZeroTtl)
    );
    assert_eq!(
        LeaseRenewalPolicy::from_ttl(Duration::from_nanos(1))
            .expect_err("lease cannot outlive minimum renewal"),
        LeaseRenewalPolicyError::TooShort
    );
    assert_eq!(
        LeaseRenewalPolicy::from_ttl(Duration::from_millis(2))
            .expect("usable ttl")
            .interval(),
        Duration::from_millis(1)
    );
    assert_eq!(
        LeaseRenewalPolicy::from_ttl(Duration::from_millis(9))
            .expect("ttl")
            .interval(),
        Duration::from_millis(3)
    );
    assert_eq!(
        LeaseRenewalPolicy::from_ttl(Duration::from_millis(10))
            .expect("ttl")
            .interval(),
        Duration::from_nanos(3_333_333)
    );
}
