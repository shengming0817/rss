//! Shared source revalidation and fact projection clock for every session path.
//! ref: tokio tokio/src/time/clock.rs (test-only, explicitly scoped time control).
#[derive(Clone, Default)]
pub(crate) struct SessionChecks {
    pub(crate) platform: Option<std::sync::Arc<dyn crate::platform::PlatformVerifier>>,
    #[cfg(feature = "test-support")]
    pub(crate) controlled: Option<ControlledFactTime>,
}
impl SessionChecks {
    pub(crate) fn seconds(&self, database_now: i64) -> i64 {
        #[cfg(feature = "test-support")]
        if let Some(clock) = &self.controlled {
            return database_now.max(clock.0.load(std::sync::atomic::Ordering::SeqCst));
        }
        database_now
    }
}

/// Forward-only time floor for freshly loaded group/department facts.
/// Does not change signed/stored facts, session validity, retained proofs, or transaction time.
/// Attach to an Authority clone before sharing it; unrelated authorities remain on PG time.
#[cfg(feature = "test-support")]
#[derive(Clone, Default)]
pub struct ControlledFactTime(std::sync::Arc<std::sync::atomic::AtomicI64>);
#[cfg(feature = "test-support")]
impl ControlledFactTime {
    /// Advance subsequent fact reads to at least this Unix second. Never moves time backwards.
    pub fn advance_to(&self, seconds: i64) -> Result<(), crate::AuthorityError> {
        if seconds <= 0 || seconds > i64::MAX / 1_000_000 {
            return Err(crate::AuthorityError::Configuration);
        }
        self.0
            .fetch_max(seconds, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}
#[cfg(feature = "test-support")]
impl crate::Authority {
    /// Test-only fact projection time; clones made before this call are unaffected.
    pub fn with_fact_time(mut self, clock: ControlledFactTime) -> Self {
        self.session_checks.controlled = Some(clock);
        self
    }
}
