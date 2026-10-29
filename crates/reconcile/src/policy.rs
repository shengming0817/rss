use crate::{Error, ErrorKind};
use std::time::Duration;
/// Validated execution limits. No unbounded or zero-delay mode.
#[derive(Debug, Clone, Copy)]
pub struct Policy {
    pub(crate) concurrency: usize,
    pub(crate) lease: Duration,
    pub(crate) attempt: Duration,
    pub(crate) scan: Duration,
    pub(crate) idle_scan: Duration,
    backoff: Duration,
    cap: Duration,
    pub(crate) max_attempts: u32,
}
/// Named required limits, validated only by `Policy::try_from`.
#[derive(Debug, Clone, Copy)]
pub struct PolicyConfig {
    pub concurrency: usize,
    pub lease_ttl: Duration,
    pub attempt_timeout: Duration,
    /// Delay before observing a successfully applied target again.
    pub scan_interval: Duration,
    /// Recovery scan interval when no known target is due sooner.
    pub idle_scan_interval: Duration,
    /// Initial retry floor; independent targets spread within the remaining bounded delay.
    pub initial_backoff: Duration,
    /// Ceiling including retry jitter.
    pub max_backoff: Duration,
    /// Includes the first attempt; 1 means no automatic retry after the first failure.
    pub max_attempts: u32,
}
impl TryFrom<PolicyConfig> for Policy {
    type Error = Error;
    fn try_from(config: PolicyConfig) -> Result<Self, Error> {
        let PolicyConfig {
            concurrency,
            lease_ttl: lease,
            attempt_timeout: attempt,
            scan_interval: scan,
            idle_scan_interval: idle_scan,
            initial_backoff: backoff,
            max_backoff: cap,
            max_attempts,
        } = config;
        let valid = |d: Duration| {
            !d.is_zero()
                && d <= Duration::from_secs(86400)
                && d.subsec_nanos().is_multiple_of(1_000_000)
        };
        if !(1..=64).contains(&concurrency)
            || ![lease, attempt, scan, idle_scan, backoff, cap]
                .into_iter()
                .all(valid)
            || lease < Duration::from_millis(3)
            || cap < backoff
            || !(1..=1000).contains(&max_attempts)
        {
            return Err(Error::new(ErrorKind::InvalidInput));
        }
        Ok(Self {
            concurrency,
            lease,
            attempt,
            scan,
            idle_scan,
            backoff,
            cap,
            max_attempts,
        })
    }
}
impl Policy {
    /// Saturating capped exponential backoff; first failure uses the base duration.
    pub fn backoff(&self, failures: u32) -> Duration {
        self.backoff
            .saturating_mul(
                1u32.checked_shl(failures.saturating_sub(1))
                    .unwrap_or(u32::MAX),
            )
            .min(self.cap)
    }
    // ref: tower-rs/tower tower/src/retry/backoff.rs (capped additive jitter).
    // The claim identity and failure count spread a retry wave without new RNG/config
    // state. Persisted next_run remains authoritative across restart and notification.
    pub(crate) fn retry_delay(&self, target: &crate::Target, failures: u32) -> Duration {
        use std::hash::{Hash, Hasher};
        let base = self.backoff(failures);
        let room = base.min(self.cap - base);
        // Validation bounds all policy durations to one day and whole milliseconds.
        let room = room.as_secs() * 1000 + u64::from(room.subsec_millis());
        if room == 0 {
            return base;
        }
        let mut hash = std::collections::hash_map::DefaultHasher::new();
        target.hash(&mut hash);
        failures.hash(&mut hash);
        base + Duration::from_millis(hash.finish() % (room + 1))
    }
    /// Maximum concurrent entity executions.
    pub const fn concurrency(&self) -> usize {
        self.concurrency
    }
    /// Provider lease duration.
    pub const fn lease(&self) -> Duration {
        self.lease
    }
}
