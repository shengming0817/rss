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
    /// Absolute retry floor. Equal to max_backoff selects a fixed delay.
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
    // ref: tower-rs/tower tower/src/retry/backoff.rs@7dc533ef86b02f89f3dc5fe64644dd1a5dc3b37d
    // Unlike additive jitter, this window retains room at the cap. The absolute
    // floor remains intact; persisted next_run, not the hash, owns restart recovery.
    pub(crate) fn retry_delay(&self, target: &crate::Target, failures: u32) -> Duration {
        use std::hash::{Hash, Hasher};
        let upper = self
            .backoff
            .saturating_mul(1u32.checked_shl(failures.max(1)).unwrap_or(u32::MAX))
            .min(self.cap);
        // Validation bounds durations to one day and positive whole milliseconds.
        let upper = upper.as_secs() * 1000 + u64::from(upper.subsec_millis());
        let floor = self.backoff.as_secs() * 1000 + u64::from(self.backoff.subsec_millis());
        let lower = floor.max(upper.div_ceil(2));
        let mut hash = std::collections::hash_map::DefaultHasher::new();
        target.hash(&mut hash);
        failures.hash(&mut hash);
        Duration::from_millis(lower + hash.finish() % (upper - lower + 1))
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

#[cfg(test)]
mod tests;
