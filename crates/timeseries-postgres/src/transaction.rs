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
        Some("TS004") => Error::HistoryExpired,
        Some("42501") => Error::Unauthorized,
        Some("22003") => Error::NumericRange,
        Some("TS005" | "23514" | "23503" | "42P01" | "42703") => Error::Invariant,
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
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Snapshot,
    Write,
    #[cfg(feature = "timescaledb")]
    RefreshPreflight,
}

#[derive(Clone, Copy)]
pub(crate) struct Budget {
    deadline: Deadline,
    end: tokio::time::Instant,
}
impl Budget {
    #[allow(clippy::disallowed_methods)] // reason: inspect the same Tokio watchdog that wakes pool and admission waits.
    pub(crate) fn remaining(self, clock: &impl Clock) -> Result<std::time::Duration, Error> {
        let logical = self
            .deadline
            .remaining(clock.now())
            .ok_or(Error::Deadline)?;
        let wall = self
            .end
            .saturating_duration_since(tokio::time::Instant::now());
        if wall.is_zero() {
            return Err(Error::Deadline);
        }
        Ok(wall.min(logical))
    }
}
impl<C: Clock> PgStore<C> {
    pub(crate) async fn transaction<T: Send>(
        &self,
        tenant: TenantId,
        deadline: Deadline,
        mode: Mode,
        operation: impl for<'a> FnOnce(&'a mut PgConnection, &'a C) -> BoxFuture<'a, Result<T, Error>>
        + Send,
    ) -> Result<Outcome<T>, Error> {
        self.prepared_transaction(
            tenant,
            deadline,
            mode,
            |_| std::future::ready(Ok(())),
            move |c, clock, ()| operation(c, clock),
        )
        .await
    }

    // One tenant gate and one wall-clock watchdog cover capacity, cooperative
    // preparation, BEGIN and settlement, even when injected clock readings repeat.
    pub(crate) async fn prepared_transaction<
        T: Send,
        P: Send,
        F: Future<Output = Result<P, Error>> + Send,
    >(
        &self,
        tenant: TenantId,
        deadline: Deadline,
        mode: Mode,
        prepare: impl FnOnce(Budget) -> F + Send,
        operation: impl for<'a> FnOnce(
            &'a mut PgConnection,
            &'a C,
            P,
        ) -> BoxFuture<'a, Result<T, Error>>
        + Send,
    ) -> Result<Outcome<T>, Error> {
        self.profile.check_tenant(tenant)?;
        let started = AtomicBool::new(false);
        let remaining = deadline
            .remaining(self.clock.now())
            .ok_or(Error::Deadline)?;
        let mutation = mode == Mode::Write;
        let fault = if mutation { self.take_fault() } else { 0 };
        #[allow(clippy::disallowed_methods)]
        // reason: capture the executor watchdog once alongside the injected clock.
        let end = tokio::time::Instant::now()
            .checked_add(remaining)
            .ok_or(Error::InvalidInput)?;
        let budget = Budget { deadline, end };
        let result=tokio::time::timeout_at(end, async {
            let prepared = prepare(budget).await?;
            budget.remaining(&self.clock)?;
            #[cfg(feature = "integration")]
            let pg_wait = rss_timeseries::measurement::timer();
            let connection = self.pool.acquire().await.map_err(sql_error)?;
            #[cfg(feature = "integration")]
            let lease_start = {
                rss_timeseries::measurement::record("pool_wait", pg_wait, 0, 0);
                rss_timeseries::measurement::timer()
            };
            budget.remaining(&self.clock)?;
            let mut lease=Lease{connection,settled:false};
            #[cfg(feature = "integration")]
            let tx_start = {
                rss_timeseries::measurement::record("lease_to_begin", lease_start, 0, 0);
                rss_timeseries::measurement::timer()
            };
            let mut tx = match mode {
                Mode::Snapshot => lease.connection.begin_with("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY").await,
                _ => lease.connection.begin_with("BEGIN ISOLATION LEVEL READ COMMITTED READ WRITE").await,
            }.map_err(sql_error)?;
            let ms=budget.remaining(&self.clock)?.as_millis().clamp(1,i32::MAX as u128);
            sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout',$2,true),set_config('lock_timeout',$2,true)")
                .bind(tenant.to_string()).bind(format!("{ms}ms")).execute(&mut *tx).await.map_err(sql_error)?;
            budget.remaining(&self.clock)?;
            started.store(true,Ordering::SeqCst);
            let result=operation(&mut tx,&self.clock,prepared).await;
            // No budget remains for rollback ACK once the injected clock reaches cutoff.
            // Quarantine instead of committing a staged mutation after its deadline.
            if budget.remaining(&self.clock).is_err() {
                return if mutation { Ok(Outcome::Unknown) } else { Err(Error::Deadline) };
            }
            let result=if fault==1 && result.is_ok() { Err(Error::Unavailable) } else { result };
            match result {
                Ok(value) if mutation=> {
                    if fault==4 { std::future::pending::<()>().await; }
                    if tx.commit().await.is_err() { return Ok(Outcome::Unknown); }
                    #[cfg(feature = "integration")]
                    rss_timeseries::measurement::record("transaction", tx_start, 0, 0);
                    lease.settled=true;
                    if fault==2 { return Ok(Outcome::Unknown); }
                    Ok(Outcome::Accepted(value))
                }
                result=> {
                    if tx.rollback().await.is_err() || fault==3 { return Ok(Outcome::Unknown); }
                    #[cfg(feature = "integration")]
                    rss_timeseries::measurement::record("transaction", tx_start, 0, 0);
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
