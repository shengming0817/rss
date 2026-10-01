//! Command time only; transaction, messaging and authorization clocks remain independent.
use rss_transactional_messaging_postgres::{PgError, PgTransaction};

/// Explicit authoritative time source for command decisions, in Unix microseconds.
pub enum CommandClock {
    /// Read PostgreSQL time inside the admitted transaction.
    Postgres,
    /// An instance-scoped, frozen clock for real-provider integration evidence.
    #[cfg(feature = "integration")]
    Controlled(std::sync::Arc<IntegrationClock>),
}
impl CommandClock {
    pub(crate) async fn now(&self, tx: &mut PgTransaction<'_>) -> Result<i64, PgError> {
        match self {
            Self::Postgres => crate::persistence::now(tx).await,
            #[cfg(feature = "integration")]
            Self::Controlled(clock) => Ok(clock.now()),
        }
    }
}

/// Shared integration time. Advances affect only stores explicitly constructed with this clock.
#[cfg(feature = "integration")]
pub struct IntegrationClock(std::sync::atomic::AtomicI64);
#[cfg(feature = "integration")]
impl IntegrationClock {
    /// Freeze time at a nonnegative Unix microsecond value.
    pub fn new(now: i64) -> Result<Self, rss_device_command::Error> {
        if now < 0 {
            return Err(rss_device_command::Error::InvalidValue);
        }
        Ok(Self(std::sync::atomic::AtomicI64::new(now)))
    }
    /// Observe the current frozen time without advancing it.
    pub fn now(&self) -> i64 {
        self.0.load(std::sync::atomic::Ordering::Acquire)
    }
    /// Move to an equal or later timestamp; competing advances never roll back time.
    pub fn advance_to(&self, now: i64) -> Result<(), rss_device_command::Error> {
        use std::sync::atomic::Ordering;
        self.0
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |previous| {
                (now >= previous).then_some(now)
            })
            .map(|_| ())
            .map_err(|_| rss_device_command::Error::InvalidValue)
    }
}
