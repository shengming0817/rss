//! Atomic Saga persistence. The application owns migration execution and role provisioning.
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![doc = include_str!("../README.md")]
use futures::future::BoxFuture;
use rss_saga::{
    Control, Definition, Error, Event, EventKind, HistoryCapacity, HistoryHead, Lease, Mutation,
    ProtectedReceipt, ReadBudget, Scope, Snapshot, Store, Timer,
};
use rss_saga::{DiagnosticPhase, ErrorKind};
use sqlx::{Connection as _, PgConnection, PgPool, Row as _, pool::PoolConnection};
use std::time::Duration;

mod probe;
use probe::validate;
/// Version-matched fresh schema SQL for an external migrator; reading this constant executes nothing.
pub const MIGRATION_SQL: &str = concat!(
    include_str!("../migrations/0001_create_saga.sql"),
    "\n",
    include_str!("../migrations/0002_add_history_bounds.sql")
);
/// One-way upgrade executed only by the external migrator with writers stopped.
pub const UPGRADE_SQL: &str = include_str!("../migrations/0002_add_history_bounds.sql");
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
        Some("RS004") => ErrorKind::HistoryLimited(rss_saga::HistoryLimit::DurableCapacity),
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
async fn locked(connection: &mut PgConnection, lease: &Lease) -> Result<HistoryHead, Error> {
    let value: sqlx::types::Json<HistoryHead> =
        sqlx::query_scalar("SELECT rss_saga.lock_instance($1,$2,$3)")
            .bind(lease.scope().id())
            .bind(lease.token())
            .bind(lease.epoch())
            .fetch_one(connection)
            .await
            .map_err(sql_error)?;
    Ok(value.0)
}
async fn load(
    connection: &mut PgConnection,
    lease: &Lease,
    read: ReadBudget,
) -> Result<Snapshot, Error> {
    use futures::TryStreamExt as _;
    let head = locked(connection, lease).await?;
    head.check_read(read)?;
    // SQL withholds oversized payloads before SQLx receives a complete DataRow.
    let definition: Option<sqlx::types::Json<Definition>> = sqlx::query_scalar("SELECT CASE WHEN octet_length(definition::text)<=$3 THEN definition END FROM rss_saga.instances WHERE tenant_id=$1::text::uuid AND saga_id=$2")
        .bind(lease.scope().tenant().to_string()).bind(lease.scope().id()).bind(rss_saga::DEFINITION_BYTES as i64)
        .fetch_one(&mut *connection).await.map_err(sql_error)?;
    let definition = definition.ok_or(ErrorKind::HistoryReadLimit)?.0;
    let mut snapshot = Snapshot::empty(definition, head.capacity(), read)?;
    let mut rows = sqlx::query("SELECT seq,step,attempt,CASE WHEN octet_length(kind)<=32 THEN kind END AS kind,CASE WHEN octet_length(effect_key)=32 THEN effect_key END AS effect_key,encoded_bytes,CASE WHEN encoded_bytes<=$4 AND (protected IS NULL OR octet_length(protected::text)<=encoded_bytes-256) THEN protected END AS protected,octet_length(kind)<=32 AND octet_length(effect_key)=32 AND encoded_bytes<=$4 AND (protected IS NULL OR octet_length(protected::text)<=encoded_bytes-256) AS bounded FROM rss_saga.journal WHERE tenant_id=$1::text::uuid AND saga_id=$2 ORDER BY seq LIMIT $3")
        .bind(lease.scope().tenant().to_string()).bind(lease.scope().id()).bind(head.revision().saturating_add(1).min(i64::MAX as u64) as i64)
        .bind((rss_saga::EVENT_BYTES + rss_saga::RECEIPT_BYTES).min(read.history().max_encoded_bytes()) as i64).fetch(&mut *connection);
    while let Some(row) = rows.try_next().await.map_err(sql_error)? {
        cooperate().await;
        if !row.try_get::<bool, _>("bounded").map_err(sql_error)? {
            return Err(ErrorKind::HistoryReadLimit.into());
        }
        if snapshot.revision() >= head.revision() {
            return Err(ErrorKind::Integrity.into());
        }
        let kind: String = row.try_get("kind").map_err(sql_error)?;
        let kind: EventKind = serde_json::from_str(&format!("\"{kind}\""))
            .map_err(|_| Error::new(ErrorKind::Integrity))?;
        let receipt: Option<sqlx::types::Json<ProtectedReceipt>> =
            row.try_get("protected").map_err(sql_error)?;
        let event = Event {
            seq: u64::try_from(row.try_get::<i64, _>("seq").map_err(sql_error)?)
                .map_err(|_| Error::new(ErrorKind::Integrity))?,
            step: usize::try_from(row.try_get::<i32, _>("step").map_err(sql_error)?)
                .map_err(|_| Error::new(ErrorKind::Integrity))?,
            attempt: u32::try_from(row.try_get::<i64, _>("attempt").map_err(sql_error)?)
                .map_err(|_| Error::new(ErrorKind::Integrity))?,
            kind,
            receipt: receipt.map(|value| value.0),
        };
        let key =
            snapshot
                .definition()
                .effect_key(lease.scope(), event.step, event.kind.phase())?;
        if row.try_get::<Vec<u8>, _>("effect_key").map_err(sql_error)? != key.as_bytes()
            || row.try_get::<i64, _>("encoded_bytes").map_err(sql_error)?
                != event.encoded_bytes()? as i64
        {
            return Err(ErrorKind::Integrity.into());
        }
        snapshot.replay(event)?;
    }
    drop(rows);
    if snapshot.head() != &head {
        return Err(ErrorKind::Integrity.into());
    }
    Ok(snapshot)
}
// Yield even when SQLx already buffered the next row, so the outer injected Control and lease renewal can interrupt replay.
async fn cooperate() {
    let mut yielded = false;
    futures::future::poll_fn(|cx| {
        if yielded {
            std::task::Poll::Ready(())
        } else {
            yielded = true;
            cx.waker().wake_by_ref();
            std::task::Poll::Pending
        }
    })
    .await;
}
impl Store for PgStore {
    async fn register<T: Timer>(
        &self,
        scope: Scope,
        definition: &Definition,
        capacity: HistoryCapacity,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        definition.validate()?;
        let definition = sqlx::types::Json(definition.clone());
        self.transact(scope.tenant(), control, |c| {
            Box::pin(async move {
                sqlx::query("SELECT rss_saga.register($1,$2,$3)")
                    .bind(scope.id())
                    .bind(definition)
                    .bind(sqlx::types::Json(capacity))
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
    async fn history_head<T: Timer>(
        &self,
        lease: &Lease,
        control: &Control<'_, T>,
    ) -> Result<HistoryHead, Error> {
        let lease = lease.clone();
        self.transact(lease.scope().tenant(), control, |c| {
            Box::pin(async move { locked(c, &lease).await })
        })
        .await
    }
    async fn extend_history<T: Timer>(
        &self,
        lease: &Lease,
        expected_revision: u64,
        expected_capacity: HistoryCapacity,
        capacity: HistoryCapacity,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        if !capacity.extends(expected_capacity) {
            return Err(ErrorKind::Conflict.into());
        }
        let revision =
            i64::try_from(expected_revision).map_err(|_| Error::new(ErrorKind::Conflict))?;
        let lease = lease.clone();
        self.transact(lease.scope().tenant(), control, |c| {
            Box::pin(async move {
                sqlx::query("SELECT rss_saga.extend_history($1,$2,$3,$4,$5,$6)")
                    .bind(lease.scope().id())
                    .bind(lease.token())
                    .bind(lease.epoch())
                    .bind(revision)
                    .bind(sqlx::types::Json(expected_capacity))
                    .bind(sqlx::types::Json(capacity))
                    .execute(c)
                    .await
                    .map_err(sql_error)?;
                Ok(())
            })
        })
        .await
    }
    async fn snapshot<T: Timer>(
        &self,
        lease: &Lease,
        read: ReadBudget,
        control: &Control<'_, T>,
    ) -> Result<Snapshot, Error> {
        let lease = lease.clone();
        self.transact(lease.scope().tenant(), control, |c| {
            Box::pin(async move { load(c, &lease, read).await })
        })
        .await
    }
    async fn commit<T: Timer>(
        &self,
        lease: &Lease,
        mutation: &Mutation,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        if mutation.scope() != lease.scope() {
            return Err(ErrorKind::Fenced.into());
        }
        let mutation = mutation.clone();
        let lease = lease.clone();
        self.transact(lease.scope().tenant(), control, |c| {
            Box::pin(async move {
                sqlx::query("SELECT rss_saga.commit_event($1,$2,$3,$4,$5,$6,$7)")
                    .bind(lease.scope().id())
                    .bind(lease.token())
                    .bind(lease.epoch())
                    .bind(sqlx::types::Json(mutation.event()))
                    .bind(mutation.effect_key().as_bytes().as_slice())
                    .bind(sqlx::types::Json(mutation.before()))
                    .bind(sqlx::types::Json(mutation.after()))
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
        filter: rss_saga::CandidateFilter,
        tenant: rss_request_context::TenantId,
        after: Option<uuid::Uuid>,
        limit: u32,
        control: &Control<'_, T>,
    ) -> Result<Vec<Scope>, Error> {
        if limit == 0 || limit > 10_000 {
            return Err(Error::new(rss_saga::ErrorKind::InvalidBudget));
        }
        self.transact(tenant,control,|c|Box::pin(async move {
            let ids:Vec<uuid::Uuid>=sqlx::query_scalar("SELECT saga_id FROM rss_saga.instances WHERE tenant_id=$1::text::uuid AND progress->>'status' IN ('Ready','Running','Compensating') AND rss_saga.runnable(progress,definition,revision,history_encoded_bytes,history_entry_limit,history_byte_limit)=$4 AND (expires_at IS NULL OR expires_at<=clock_timestamp()) AND ($3::uuid IS NULL OR saga_id>$3) ORDER BY saga_id LIMIT $2").bind(tenant.to_string()).bind(i64::from(limit)).bind(after).bind(filter==rss_saga::CandidateFilter::Runnable).fetch_all(c).await.map_err(sql_error)?;
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
