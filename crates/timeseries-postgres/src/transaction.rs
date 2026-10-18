// ref: launchbadge/sqlx sqlx-core/src/transaction.rs@v0.9.0
use crate::PgStore;
use futures::future::BoxFuture;
use rss_request_context::{Clock, Deadline, TenantId};
use rss_timeseries::{Error, Outcome};
use sqlx::{Connection, PgConnection, Postgres, pool::PoolConnection};
use std::sync::atomic::{AtomicBool, Ordering};
struct Lease {
    connection: PoolConnection<Postgres>,
    settled: bool,
}
impl Drop for Lease {
    fn drop(&mut self) {
        if !self.settled {
            self.connection.close_on_drop();
        }
    }
}
pub(crate) fn sql_error(e: sqlx::Error) -> Error {
    match e.as_database_error().and_then(|e| e.code()).as_deref() {
        Some("57014" | "55P03") => Error::Deadline,
        Some("TS001" | "23505") => Error::Conflict,
        Some("TS002") => Error::InvalidInput,
        Some("TS003") => Error::Retired,
        Some("42501") => Error::Unauthorized,
        Some("23514" | "23503" | "42P01" | "42703") => Error::Invariant,
        _ => Error::Unavailable,
    }
}
pub(crate) fn check(clock: &impl Clock, deadline: Deadline) -> Result<(), Error> {
    if deadline.is_expired(clock.now()) {
        Err(Error::Deadline)
    } else {
        Ok(())
    }
}
pub(crate) async fn db_now(c: &mut PgConnection) -> Result<i64, Error> {
    sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000000)::bigint")
        .fetch_one(c)
        .await
        .map_err(sql_error)
}
pub(crate) fn certain<T>(outcome: Outcome<T>) -> Result<T, Error> {
    match outcome {
        Outcome::Accepted(v) | Outcome::Replay(v) => Ok(v),
        Outcome::Unknown => Err(Error::Unavailable),
    }
}
impl<C: Clock> PgStore<C> {
    pub(crate) async fn transaction<T: Send>(
        &self,
        tenant: TenantId,
        deadline: Deadline,
        mutation: bool,
        operation: impl for<'a> FnOnce(&'a mut PgConnection, &'a C) -> BoxFuture<'a, Result<T, Error>>
        + Send,
    ) -> Result<Outcome<T>, Error> {
        let started = AtomicBool::new(false);
        let remaining = deadline
            .remaining(self.clock.now())
            .ok_or(Error::Deadline)?;
        let fault = if mutation { self.take_fault() } else { 0 };
        let result=tokio::time::timeout(remaining, async {
            let mut lease=Lease{connection:self.pool.acquire().await.map_err(sql_error)?,settled:false};
            let mut tx=lease.connection.begin().await.map_err(sql_error)?;
            let ms=deadline.remaining(self.clock.now()).ok_or(Error::Deadline)?.as_millis().clamp(1,i32::MAX as u128);
            sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout',$2,true),set_config('lock_timeout',$2,true)")
                .bind(tenant.to_string()).bind(format!("{ms}ms")).execute(&mut *tx).await.map_err(sql_error)?;
            check(&self.clock, deadline)?;
            started.store(true,Ordering::SeqCst);
            let result=operation(&mut tx,&self.clock).await;
            // No budget remains for rollback ACK once the injected clock reaches cutoff.
            // Quarantine instead of committing a staged mutation after its deadline.
            if check(&self.clock, deadline).is_err() {
                return if mutation { Ok(Outcome::Unknown) } else { Err(Error::Deadline) };
            }
            let result=if fault==1 && result.is_ok() { Err(Error::Unavailable) } else { result };
            match result {
                Ok(value) if mutation=> {
                    if fault==4 { std::future::pending::<()>().await; }
                    if tx.commit().await.is_err() { return Ok(Outcome::Unknown); }
                    lease.settled=true;
                    if fault==2 { return Ok(Outcome::Unknown); }
                    Ok(Outcome::Accepted(value))
                }
                result=> {
                    if tx.rollback().await.is_err() || fault==3 { return Ok(Outcome::Unknown); }
                    lease.settled=true;
                    result.map(Outcome::Accepted)
                }
            }
        }).await;
        match result {
            Ok(r) => r,
            Err(_) if mutation && started.load(Ordering::SeqCst) => Ok(Outcome::Unknown),
            Err(_) => Err(Error::Deadline),
        }
    }
}
/// One-shot deterministic faults around real database settlement, only for integration fixtures.
#[cfg(feature = "integration")]
#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum Fault {
    BeforeCommit = 1,
    CommitAckLost = 2,
    RollbackAckLost = 3,
    CommitPending = 4,
}
