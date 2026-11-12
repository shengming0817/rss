use super::*;
use crate::{Scope, Target};
use rss_request_context::TenantId;
use std::collections::BTreeSet;

#[test]
fn retry_windows_keep_the_floor_and_spread_at_the_ceiling() -> Result<(), Error> {
    let scope = Scope::new(
        TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
            .map_err(|_| Error::new(ErrorKind::InvalidInput))?,
        "retry",
    )?;
    for (initial, cap) in [
        (5000, 60000),
        (1, 2),
        (2, 3),
        (59999, 60000),
        (5, 5),
        (1, 86400000),
        (86_400_001, u64::MAX),
    ] {
        let policy = Policy::try_from(PolicyConfig {
            claim_batch_size: 64,
            scan_budget: 64,
            concurrency: 2,
            lease_ttl: Duration::from_secs(1),
            attempt_timeout: Duration::from_secs(1),
            scan_interval: Duration::from_millis(1),
            idle_scan_interval: Duration::from_secs(1),
            initial_backoff: Duration::from_millis(initial),
            max_backoff: Duration::from_millis(cap),
            max_attempts: u32::MAX,
        })?;
        for failures in [0, 1, 4, 5, 6, 7, 32, u32::MAX] {
            let mut delays = BTreeSet::new();
            for index in 0..64 {
                let target = Target::new(scope.clone(), format!("target-{index}"))?;
                let delay = policy.retry_delay(&target, failures);
                assert_eq!(delay, policy.retry_delay(&target, failures));
                assert!(
                    delay >= Duration::from_millis(initial) && delay <= Duration::from_millis(cap)
                );
                assert_eq!(delay.subsec_nanos() % 1_000_000, 0);
                if initial == 5000 && cap == 60000 {
                    let (lower, upper) = if failures <= 1 {
                        (5000, 10000)
                    } else {
                        (30000, 60000)
                    };
                    assert!(
                        delay >= Duration::from_millis(lower)
                            && delay <= Duration::from_millis(upper)
                    );
                }
                if failures == u32::MAX {
                    assert!(delay >= Duration::from_millis(cap.div_ceil(2)));
                }
                delays.insert(delay);
            }
            if initial < cap {
                assert!(
                    delays.len() > 1,
                    "retry wave collapsed: {initial}/{cap}, failure {failures}"
                );
            } else {
                assert_eq!(delays.len(), 1);
            }
        }
    }
    Ok(())
}

#[test]
fn independent_claim_scan_and_time_bounds() -> Result<(), Error> {
    let config = PolicyConfig {
        concurrency: 1025,
        claim_batch_size: 1024,
        scan_budget: 4096,
        lease_ttl: Duration::from_secs(90_000),
        attempt_timeout: Duration::from_secs(89_000),
        scan_interval: Duration::from_secs(90_001),
        idle_scan_interval: Duration::from_secs(90_002),
        initial_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_secs(90_003),
        max_attempts: u32::MAX,
    };
    let policy = Policy::try_from(config)?;
    assert_eq!(policy.claim_batch_size(), 1024);
    assert_eq!(policy.scan_budget(), 4096);
    for claim_batch_size in [0, 1025] {
        assert!(
            Policy::try_from(PolicyConfig {
                claim_batch_size,
                ..config
            })
            .is_err()
        );
    }
    assert!(
        Policy::try_from(PolicyConfig {
            scan_budget: 0,
            ..config
        })
        .is_err()
    );
    assert!(
        Policy::try_from(PolicyConfig {
            max_attempts: 0,
            ..config
        })
        .is_err()
    );
    assert!(
        Policy::try_from(PolicyConfig {
            lease_ttl: Duration::from_nanos(3_000_001),
            ..config
        })
        .is_err()
    );
    Ok(())
}
