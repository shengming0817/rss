//! Atomic Saga persistence. The application owns migration execution and role provisioning.
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![doc = include_str!("../README.md")]
use futures::future::BoxFuture;
use rss_saga::{Control, Definition, Error, Event, Lease, Mutation, Scope, Snapshot, Store, Timer};
use rss_saga::{DiagnosticPhase, ErrorKind};
use sqlx::{Connection as _, PgConnection, PgPool, Row as _, pool::PoolConnection};
use std::time::Duration;

mod probe;
use probe::validate;
/// Version-matched fresh schema SQL for an external migrator; reading this constant executes nothing.
pub const MIGRATION_SQL: &str = include_str!("../migrations/0001_create_saga.sql");
#[derive(Clone)]
/// Adopted PostgreSQL pool implementing the atomic Saga storage contract.
pub struct PgStore {
    pool: PgPool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Pool admission is closed in every case; this outcome describes drain completion.
pub enum CloseOutcome {
    /// All adopted pool connections have drained.
    Drained,
    /// Drain waiting was cancelled; pool admission remains closed.
    Cancelled,
    /// Drain waiting exceeded the caller deadline; pool admission remains closed.
    Deadline,
}
impl PgStore {
    /// Verify executable schema, RLS and runtime authority before adopting the configured pool; execute no migrations.
    pub async fn new<T: Timer>(pool: PgPool, control: &Control<'_, T>) -> Result<Self, Error> {
        control
            .run(validate(&pool))
            .await
            .map_err(admission_error)?;
        Ok(Self { pool })
    }
    /// Close pool admission and bound draining by the supplied control. Outstanding borrowers remain owned by their tasks.
    pub async fn close<T: Timer>(&self, control: &Control<'_, T>) -> CloseOutcome {
        let drain = self.pool.close();
        match control
            .run(async {
                drain.await;
                Ok(())
            })
            .await
        {
            Ok(()) => CloseOutcome::Drained,
            Err(error) if error.kind() == rss_saga::ErrorKind::Cancelled => CloseOutcome::Cancelled,
            Err(_) => CloseOutcome::Deadline,
        }
    }
    async fn transact<T: Timer, R: Send, F>(
        &self,
        tenant: rss_request_context::TenantId,
        control: &Control<'_, T>,
        operation: F,
    ) -> Result<R, Error>
    where
        F: for<'c> FnOnce(&'c mut PgConnection) -> BoxFuture<'c, Result<R, Error>> + Send,
    {
        control.check()?;
        let timeout = control.remaining().as_millis().max(1).to_string() + "ms";
        let settlement = std::sync::atomic::AtomicU8::new(0);
        let result = control.run(async {
            let mut lease=ConnectionLease { connection:self.pool.acquire().await.map_err(|e|sql_error_at(DiagnosticPhase::Acquire,e))?,settled:false };
            let mut tx=lease.connection.begin().await.map_err(|e|sql_error_at(DiagnosticPhase::Begin,e))?;
            settlement.store(2, std::sync::atomic::Ordering::SeqCst);
            let result=async {
                sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout',$2,true),set_config('lock_timeout',$2,true)").bind(tenant.to_string()).bind(timeout).execute(&mut *tx).await.map_err(|e|sql_error_at(DiagnosticPhase::Setup,e))?;
                operation(&mut tx).await
            }.await;
            match result {
                Ok(value)=> {
                    settlement.store(1, std::sync::atomic::Ordering::SeqCst);
                    tx.commit().await.map_err(|e|settlement_error(ErrorKind::CommitUnknown,DiagnosticPhase::Commit,e))?;
                    lease.settled=true; Ok(value)
                }
                Err(error)=> { tx.rollback().await.map_err(|e|settlement_error(ErrorKind::RollbackUnknown,DiagnosticPhase::Rollback,e))?; lease.settled=true;Err(error) }
            }
        }).await;
        result.map_err(|error| {
            if matches!(error.kind(), ErrorKind::Cancelled | ErrorKind::Deadline) {
                match settlement.load(std::sync::atomic::Ordering::SeqCst) {
                    1 => Error::new(ErrorKind::CommitUnknown),
                    2 => Error::new(ErrorKind::RollbackUnknown),
                    _ => error,
                }
            } else {
                error
            }
        })
    }
}
struct ConnectionLease {
    connection: PoolConnection<sqlx::Postgres>,
    settled: bool,
}
impl Drop for ConnectionLease {
    fn drop(&mut self) {
        if !self.settled {
            self.connection.close_on_drop();
        }
    }
}
fn sql_error(error: sqlx::Error) -> Error {
    sql_error_at(DiagnosticPhase::Operation, error)
}
fn sql_error_at(phase: DiagnosticPhase, error: sqlx::Error) -> Error {
    let code = error
        .as_database_error()
        .and_then(|e| e.code())
        .map(|c| c.into_owned());
    let kind = match code.as_deref() {
        Some("RS001") => ErrorKind::Fenced,
        Some("RS002") => ErrorKind::Conflict,
        Some("RS003") => ErrorKind::Integrity,
        _ => ErrorKind::Store,
    };
    Error::provider(kind, phase, code.as_deref(), error)
}
fn settlement_error(kind: ErrorKind, phase: DiagnosticPhase, error: sqlx::Error) -> Error {
    let code = error
        .as_database_error()
        .and_then(|e| e.code())
        .map(|c| c.into_owned());
    Error::provider(kind, phase, code.as_deref(), error)
}
fn admission_error(error: Error) -> Error {
    if matches!(error.kind(), ErrorKind::Cancelled | ErrorKind::Deadline) {
        return error;
    }
    let state = error
        .diagnostic()
        .and_then(|d| d.sqlstate())
        .map(str::to_owned);
    Error::provider(
        ErrorKind::StorageContract,
        DiagnosticPhase::Probe,
        state.as_deref(),
        error,
    )
}
fn ttl_millis(ttl: Duration) -> Result<i64, Error> {
    let millis =
        i64::try_from(ttl.as_millis()).map_err(|_| Error::new(rss_saga::ErrorKind::LeaseInput))?;
    if !(1..=86_400_000).contains(&millis) {
        return Err(Error::new(rss_saga::ErrorKind::LeaseInput));
    }
    Ok(millis)
}
async fn locked(connection: &mut PgConnection, lease: &Lease) -> Result<serde_json::Value, Error> {
    sqlx::query_scalar("SELECT rss_saga.lock_instance($1,$2,$3)")
        .bind(lease.scope().id())
        .bind(lease.token())
        .bind(lease.epoch())
        .fetch_one(connection)
        .await
        .map_err(sql_error)
}
async fn load(connection: &mut PgConnection, lease: &Lease) -> Result<Snapshot, Error> {
    let row = locked(connection, lease).await?;
    let definition: Definition = serde_json::from_value(row["definition"].clone())
        .map_err(|_| Error::new(rss_saga::ErrorKind::Integrity))?;
    let rows=sqlx::query("SELECT j.seq,j.step,j.attempt,j.kind,j.effect_key,r.protected FROM rss_saga.journal j LEFT JOIN rss_saga.step_receipts r ON (r.tenant_id,r.saga_id,r.completed_seq)=(j.tenant_id,j.saga_id,j.seq) WHERE j.tenant_id=$1::text::uuid AND j.saga_id=$2 ORDER BY j.seq").bind(lease.scope().tenant().to_string()).bind(lease.scope().id()).fetch_all(connection).await.map_err(sql_error)?;
    let mut events = Vec::with_capacity(rows.len());
    for r in rows {
        let value = serde_json::json!({"seq":r.try_get::<i64,_>("seq").map_err(sql_error)?,"step":r.try_get::<i32,_>("step").map_err(sql_error)?,"attempt":r.try_get::<i64,_>("attempt").map_err(sql_error)?,"kind":r.try_get::<String,_>("kind").map_err(sql_error)?,"receipt":r.try_get::<Option<serde_json::Value>,_>("protected").map_err(sql_error)?});
        let event = serde_json::from_value::<Event>(value)
            .map_err(|_| Error::new(rss_saga::ErrorKind::Integrity))?;
        let key = definition.effect_key(lease.scope(), event.step, event_phase(event.kind))?;
        if r.try_get::<Vec<u8>, _>("effect_key").map_err(sql_error)? != key.as_bytes() {
            return Err(Error::new(rss_saga::ErrorKind::Integrity));
        }
        events.push(event);
    }
    let snapshot = Snapshot::from_events(definition, events)?;
    if row["revision"].as_u64() != Some(snapshot.revision())
        || row["status"]
            != serde_json::to_value(snapshot.status())
                .map_err(|_| Error::new(rss_saga::ErrorKind::Integrity))?
    {
        return Err(Error::new(rss_saga::ErrorKind::Integrity));
    }
    Ok(snapshot)
}
impl Store for PgStore {
    async fn register<T: Timer>(
        &self,
        scope: Scope,
        definition: &Definition,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        definition.validate()?;
        let definition = serde_json::to_value(definition)
            .map_err(|_| Error::new(rss_saga::ErrorKind::Definition))?;
        self.transact(scope.tenant(), control, |c| {
            Box::pin(async move {
                sqlx::query("SELECT rss_saga.register($1,$2)")
                    .bind(scope.id())
                    .bind(definition)
                    .execute(c)
                    .await
                    .map_err(sql_error)?;
                Ok(())
            })
        })
        .await
    }
    async fn claim<T: Timer>(
        &self,
        scope: Scope,
        ttl: Duration,
        control: &Control<'_, T>,
    ) -> Result<Lease, Error> {
        let token = uuid::Uuid::new_v4();
        let ttl = ttl_millis(ttl)?;
        let epoch = self
            .transact(scope.tenant(), control, |c| {
                Box::pin(async move {
                    sqlx::query_scalar("SELECT rss_saga.claim($1,$2,$3)")
                        .bind(scope.id())
                        .bind(token)
                        .bind(ttl)
                        .fetch_one(c)
                        .await
                        .map_err(sql_error)
                })
            })
            .await?;
        Lease::from_provider(scope, token, epoch)
    }
    async fn renew<T: Timer>(
        &self,
        lease: &Lease,
        ttl: Duration,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        self.update_lease(lease, ttl_millis(ttl)?, control).await
    }
    async fn release<T: Timer>(
        &self,
        lease: &Lease,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        self.update_lease(lease, 0, control).await
    }
    async fn snapshot<T: Timer>(
        &self,
        lease: &Lease,
        control: &Control<'_, T>,
    ) -> Result<Snapshot, Error> {
        let lease = lease.clone();
        self.transact(lease.scope().tenant(), control, |c| {
            Box::pin(async move { load(c, &lease).await })
        })
        .await
    }
    async fn commit<T: Timer>(
        &self,
        lease: &Lease,
        mutation: Mutation,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        let lease = lease.clone();
        self.transact(lease.scope().tenant(), control, |c| {
            Box::pin(async move {
                let snapshot = load(c, &lease).await?;
                if snapshot.revision() != mutation.event().seq {
                    return Err(Error::new(rss_saga::ErrorKind::Conflict));
                }
                snapshot.apply(mutation.event().clone())?;
                let event = serde_json::to_value(mutation.event())
                    .map_err(|_| Error::new(rss_saga::ErrorKind::Integrity))?;
                sqlx::query("SELECT rss_saga.commit_event($1,$2,$3,$4,$5)")
                    .bind(lease.scope().id())
                    .bind(lease.token())
                    .bind(lease.epoch())
                    .bind(event)
                    .bind(
                        snapshot
                            .definition()
                            .effect_key(
                                lease.scope(),
                                mutation.event().step,
                                event_phase(mutation.event().kind),
                            )?
                            .as_bytes()
                            .to_vec(),
                    )
                    .execute(c)
                    .await
                    .map_err(sql_error)?;
                Ok(())
            })
        })
        .await
    }
    async fn candidates<T: Timer>(
        &self,
        tenant: rss_request_context::TenantId,
        after: Option<uuid::Uuid>,
        limit: u32,
        control: &Control<'_, T>,
    ) -> Result<Vec<Scope>, Error> {
        if limit == 0 || limit > 10_000 {
            return Err(Error::new(rss_saga::ErrorKind::Budget));
        }
        self.transact(tenant,control,|c|Box::pin(async move {
            let ids:Vec<uuid::Uuid>=sqlx::query_scalar("SELECT saga_id FROM rss_saga.instances WHERE tenant_id=$1::text::uuid AND status IN ('Ready','Running','Compensating') AND (expires_at IS NULL OR expires_at<=clock_timestamp()) AND ($3::uuid IS NULL OR saga_id>$3) ORDER BY saga_id LIMIT $2").bind(tenant.to_string()).bind(i64::from(limit)).bind(after).fetch_all(c).await.map_err(sql_error)?;
            Ok(ids.into_iter().map(|id|Scope::new(tenant,id)).collect())
        })).await
    }
}
impl PgStore {
    async fn update_lease<T: Timer>(
        &self,
        lease: &Lease,
        ttl: i64,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        let lease = lease.clone();
        self.transact(lease.scope().tenant(), control, |c| {
            Box::pin(async move {
                sqlx::query("SELECT rss_saga.lease($1,$2,$3,$4)")
                    .bind(lease.scope().id())
                    .bind(lease.token())
                    .bind(lease.epoch())
                    .bind(ttl)
                    .execute(c)
                    .await
                    .map_err(sql_error)?;
                Ok(())
            })
        })
        .await
    }
}
#[cfg(feature = "rss-runtime")]
impl rss_runtime::ManagedResource for PgStore {
    fn name(&self) -> &str {
        "saga-postgres"
    }
    async fn shutdown(&self) -> Result<(), rss_runtime::ShutdownError> {
        self.pool.close().await;
        Ok(())
    }
}

fn event_phase(kind: rss_saga::EventKind) -> rss_saga::Phase {
    use rss_saga::{EventKind, Phase};
    match kind {
        EventKind::ForwardIntent
        | EventKind::ForwardApplied
        | EventKind::ForwardNotApplied
        | EventKind::ForwardProbeNotApplied
        | EventKind::Abort => Phase::Forward,
        EventKind::CompensationIntent
        | EventKind::CompensationApplied
        | EventKind::CompensationNotApplied
        | EventKind::CompensationFailed
        | EventKind::Resume => Phase::Compensation,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lease_input_errors_are_distinct_from_definition_errors() {
        for ttl in [
            Duration::ZERO,
            Duration::from_nanos(1),
            Duration::from_millis(86_400_001),
            Duration::MAX,
        ] {
            assert!(matches!(ttl_millis(ttl),Err(error) if error.kind()==ErrorKind::LeaseInput));
        }
        assert_eq!(ttl_millis(Duration::from_millis(1)), Ok(1));
        assert_eq!(ttl_millis(Duration::from_secs(86400)), Ok(86_400_000));
    }
}
