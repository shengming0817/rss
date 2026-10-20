#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
mod aggregate;
mod config;
mod control;
mod control_probe;
mod cursor;
mod definition;
mod install;
mod maintain;
mod probe;
mod projection;
mod read;
mod transaction;
mod write;
pub use config::{Connections, Credentials, Limits};
pub use cursor::CursorKey;
pub use install::{CONTROL_SQL, installation_sql};
use rss_request_context::{Clock, Deadline, TenantId};
use rss_timeseries::{Atomicity, Error, Guarantees};
use sqlx::PgPool;
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "integration")]
pub use write::Fault;
pub use write::ProjectionProgress;
/// A tenant-bound store. Its dedicated PG pool is adopted and closed on close().
/// Products own authentication, provisioning, recovery scheduling and host shutdown.
pub struct ChStore<C> {
    pool: PgPool,
    ch: Connections,
    tenant: TenantId,
    clock: C,
    limits: Limits,
    key: CursorKey,
    instance: String,
    guarantees: Guarantees,
    closed: AtomicBool,
    operations: tokio::sync::RwLock<()>,
    #[cfg(feature = "integration")]
    fault: std::sync::atomic::AtomicU8,
}
impl<C: Clock> ChStore<C> {
    pub async fn new(
        tenant: TenantId,
        pool: PgPool,
        ch: Connections,
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
        let instance = tokio::time::timeout(remaining, probe::validate(&pool, &ch, tenant))
            .await
            .map_err(|_| Error::Deadline)??;
        let guarantees = Guarantees {
            atomicity: Atomicity::RecoverableBatch,
            replay_micros: limits.replay_micros,
        };
        Ok(Self {
            pool,
            ch,
            tenant,
            clock,
            limits,
            key,
            instance,
            guarantees,
            closed: AtomicBool::new(false),
            operations: tokio::sync::RwLock::new(()),
            #[cfg(feature = "integration")]
            fault: std::sync::atomic::AtomicU8::new(0),
        })
    }
    pub async fn close(&self, deadline: Deadline) -> Result<(), Error> {
        self.closed.store(true, Ordering::Release);
        self.bounded(deadline, async {
            let _guard = self.operations.write().await;
            self.pool.close().await;
            Ok(())
        })
        .await
    }
}
