#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
mod aggregate;
mod cursor;
mod definition;
mod lifecycle;
mod maintain;
mod probe;
mod profile;
pub use profile::StorageProfile;
mod read;
mod transaction;
mod write;
pub use cursor::CursorKey;
use rss_request_context::{Clock, Deadline};
use rss_timeseries::{Atomicity, Error, Guarantees};
use sqlx::PgPool;
use std::num::{NonZeroU32, NonZeroU64};
#[cfg(feature = "integration")]
pub use transaction::Fault;
/// External schema owner executes this once. Runtime construction never executes DDL.
pub const MIGRATION_SQL: &str = include_str!("../migrations/0001_install.sql");
/// Positive host caps; request point/series budgets may be lower. Bytes bound encoded output,
/// not exact process memory. A finite replay minimum is persisted on every new batch.
#[derive(Clone, Debug)]
pub struct Limits {
    pub max_points: NonZeroU32,
    pub max_series: NonZeroU32,
    pub max_bytes: NonZeroU32,
    pub replay_micros: NonZeroU64,
    pub cursor_micros: NonZeroU64,
}
/// Dedicated pool adopted by this adapter; closing it affects all pool clones.
pub struct PgStore<C> {
    pool: PgPool,
    clock: C,
    limits: Limits,
    key: CursorKey,
    instance: String,
    guarantees: Guarantees,
    #[cfg(feature = "integration")]
    fault: std::sync::atomic::AtomicU8,
}
impl<C: Clock> PgStore<C> {
    /// Validate deployment before serving requests. Roles/DDL changes require drain and re-admission.
    pub async fn new(
        profile: StorageProfile,
        pool: PgPool,
        clock: C,
        limits: Limits,
        key: CursorKey,
        deadline: Deadline,
    ) -> Result<Self, Error> {
        if limits.replay_micros.get() > i64::MAX as u64
            || limits.cursor_micros.get() > i64::MAX as u64
        {
            return Err(Error::InvalidInput);
        }
        let remaining = deadline.remaining(clock.now()).ok_or(Error::Deadline)?;
        let instance = tokio::time::timeout(remaining, profile.validate(&pool))
            .await
            .map_err(|_| Error::Deadline)??;
        let guarantees = Guarantees {
            atomicity: Atomicity::AtomicBatch,
            replay_micros: limits.replay_micros,
        };
        Ok(Self {
            pool,
            clock,
            limits,
            key,
            instance,
            guarantees,
            #[cfg(feature = "integration")]
            fault: std::sync::atomic::AtomicU8::new(0),
        })
    }
    /// Stop pool admission, then wait for borrowers within the original absolute deadline.
    pub async fn close(&self, deadline: Deadline) -> Result<(), Error> {
        let close = self.pool.close();
        tokio::time::timeout(
            deadline
                .remaining(self.clock.now())
                .ok_or(Error::Deadline)?,
            close,
        )
        .await
        .map_err(|_| Error::Deadline)
    }
    #[cfg(feature = "integration")]
    pub fn inject_next_fault(&self, fault: Fault) {
        self.fault
            .store(fault as u8, std::sync::atomic::Ordering::SeqCst);
    }
    fn take_fault(&self) -> u8 {
        #[cfg(feature = "integration")]
        {
            self.fault.swap(0, std::sync::atomic::Ordering::SeqCst)
        }
        #[cfg(not(feature = "integration"))]
        {
            0
        } // reason: production has no injection surface.
    }
}
