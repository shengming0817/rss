use crate::{Error, ErrorKind};
use std::time::Duration;
/// Validated execution limits. No unbounded or zero-delay mode.
#[derive(Debug, Clone, Copy)]
pub struct Policy {
    pub(crate) concurrency: usize,
    pub(crate) claim_batch_size: usize,
    pub(crate) scan_budget: u32,
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
    /// Maximum claims per request, independently of concurrency (1..=1024).
    pub claim_batch_size: usize,
    /// Positive candidate scan budget; provider representation is checked separately.
    pub scan_budget: u32,
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
            claim_batch_size,
            scan_budget,
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
                && d.subsec_nanos().is_multiple_of(1_000_000)
        };
        if concurrency == 0
            || !(1..=1024).contains(&claim_batch_size)
            || scan_budget == 0
            || ![lease, attempt, scan, idle_scan, backoff, cap]
                .into_iter()
                .all(valid)
            || lease < Duration::from_millis(3)
            || cap < backoff
            || max_attempts == 0
        {
            return Err(Error::new(ErrorKind::InvalidInput));
        }
        Ok(Self {
            concurrency,
            claim_batch_size,
            scan_budget,
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
        // Duration milliseconds fit u128; do not narrow large valid delays before jitter.
        let upper = upper.as_millis();
        let floor = self.backoff.as_millis();
        let lower = floor.max(upper.div_ceil(2));
        let mut hash = std::collections::hash_map::DefaultHasher::new();
        target.hash(&mut hash);
        failures.hash(&mut hash);
        let millis = lower + u128::from(hash.finish()) % (upper - lower + 1);
        // The result is bounded by cap, whose seconds already fit Duration.
        Duration::new((millis / 1000) as u64, ((millis % 1000) * 1_000_000) as u32)
    }
    /// Maximum concurrent entity executions.
    pub const fn concurrency(&self) -> usize {
        self.concurrency
    }
    /// Maximum returned claims in one request.
    pub const fn claim_batch_size(&self) -> usize { self.claim_batch_size }
    /// Maximum candidates visited in one provider scan.
    pub const fn scan_budget(&self) -> u32 { self.scan_budget }
    /// Provider lease duration.
    pub const fn lease(&self) -> Duration {
        self.lease
    }
}

#[cfg(test)]
mod tests;
