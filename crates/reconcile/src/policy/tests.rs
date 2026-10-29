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
    ] {
        let policy = Policy::try_from(PolicyConfig {
            concurrency: 2,
            lease_ttl: Duration::from_secs(1),
            attempt_timeout: Duration::from_secs(1),
            scan_interval: Duration::from_millis(1),
            idle_scan_interval: Duration::from_secs(1),
            initial_backoff: Duration::from_millis(initial),
            max_backoff: Duration::from_millis(cap),
            max_attempts: 1000,
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
