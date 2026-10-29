use crate::{PgOperationError, PgStore, PgTransaction, transaction::map_sql};
use futures::future::BoxFuture;
use rss_reconcile::{
    Claim, ClaimBatch, Completion, Control, DurableStore, Error, ErrorKind, ReconcileStep,
    ResourceSet, Scope, Target, Timer,
};
use sqlx::{PgConnection, Row};
use std::time::Duration;
/// Move-only provider-minted authority; no raw-token constructor or serialization.
/// ```compile_fail
/// use rss_reconcile_postgres::PgClaim;
/// fn duplicate(claim: PgClaim) { let _second = claim.clone(); }
/// ```
/// ```compile_fail
/// use rss_reconcile_postgres::PgClaim;
/// fn forge(target: rss_reconcile::Target) {
///     let claim = PgClaim { target, token: String::new(), epoch: 10, wake: 1, failures: 0 };
/// }
/// ```
pub struct PgClaim {
    pub(crate) target: Target,
    pub(crate) token: String,
    pub(crate) epoch: i64,
    pub(crate) wake: i64,
    failures: u32,
    pub(crate) binding: i64,
}
impl Claim for PgClaim {
    fn target(&self) -> &Target {
        &self.target
    }
    fn failures(&self) -> u32 {
        self.failures
    }
}
impl PgClaim {
    /// Public metadata never grants authority to another target or tenant.
    pub const fn target(&self) -> &Target {
        &self.target
    }
    /// Monotonic generation, for diagnostics only; token stays private.
    pub const fn epoch(&self) -> i64 {
        self.epoch
    }
}
pub(crate) fn millis(value: Duration) -> Result<i64, Error> {
    if value.is_zero()
        || value > Duration::from_secs(86400)
        || !value.subsec_nanos().is_multiple_of(1_000_000)
    {
        return Err(Error::new(ErrorKind::InvalidInput));
    }
    Ok(value.as_millis() as i64)
}
impl PgStore {
    /// Atomically protect database effects and schedule another observation. Context may
    /// borrow application fields; callback and context are reborrowed for this transaction.
    pub async fn protect<T: Timer, R: Send, C: Send, F>(
        &self,
        claim: &PgClaim,
        control: &Control<'_, T>,
        context: C,
        operation: F,
    ) -> Result<ReconcileStep<R>, Error>
    where
        F: for<'c> FnOnce(
                &'c mut C,
                &'c mut PgTransaction<'_>,
            )
                -> BoxFuture<'c, Result<crate::ProtectedStep<R>, PgOperationError>>
            + Send,
    {
        self.context_tx(
            claim.target.scope(),
            control,
            (Key::from(claim), context, Some(operation)),
            |state, tx| {
                Box::pin(async move {
                    lock(tx.connection, &state.0).await?;
                    let operation = state
                        .2
                        .take()
                        .ok_or_else(|| Error::new(ErrorKind::Invariant))?;
                    let value = operation(&mut state.1, tx).await.map_err(Error::from)?;
                    complete_step(tx.connection, &state.0, value).await
                })
            },
        )
        .await
    }
    /// Atomically register explicit resources and work with trusted application SQL.
    pub async fn wake_with<T: Timer, R: Send, C: Send, F>(
        &self,
        target: &Target,
        resources: &ResourceSet,
        control: &Control<'_, T>,
        context: C,
        operation: F,
    ) -> Result<R, Error>
    where
        F: for<'c> FnOnce(
                &'c mut C,
                &'c mut PgTransaction<'_>,
            ) -> BoxFuture<'c, Result<R, PgOperationError>>
            + Send,
    {
        self.schedule_with(target, resources, true, control, context, operation)
            .await
    }

    /// Bind/rebind in the business transaction without resetting failures or the due time.
    pub async fn bind_with<T: Timer, R: Send, C: Send, F>(
        &self,
        target: &Target,
        resources: &ResourceSet,
        control: &Control<'_, T>,
        context: C,
        operation: F,
    ) -> Result<R, Error>
    where
        F: for<'c> FnOnce(
                &'c mut C,
                &'c mut PgTransaction<'_>,
            ) -> BoxFuture<'c, Result<R, PgOperationError>>
            + Send,
    {
        self.schedule_with(target, resources, false, control, context, operation)
            .await
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "private shared wake/bind transaction implementation"
    )]
    async fn schedule_with<T: Timer, R: Send, C: Send, F>(
        &self,
        target: &Target,
        resources: &ResourceSet,
        waking: bool,
        control: &Control<'_, T>,
        context: C,
        operation: F,
    ) -> Result<R, Error>
    where
        F: for<'c> FnOnce(
                &'c mut C,
                &'c mut PgTransaction<'_>,
            ) -> BoxFuture<'c, Result<R, PgOperationError>>
            + Send,
    {
        validate_resources(target, resources)?;
        self.context_tx(
            target.scope(),
            control,
            (target.clone(), resources.clone(), context, Some(operation)),
            |state, tx| {
                Box::pin(async move {
                    schedule(tx.connection, &state.0, &state.1, waking).await?;
                    let operation = state
                        .3
                        .take()
                        .ok_or_else(|| Error::new(ErrorKind::Invariant))?;
                    operation(&mut state.2, tx).await.map_err(Error::from)
                })
            },
        )
        .await
    }
}

impl DurableStore for PgStore {
    type Claim = PgClaim;
    async fn wake<T: Timer>(
        &self,
        target: &Target,
        resources: &ResourceSet,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        self.wake_with(target, resources, control, (), |_, _| {
            Box::pin(async { Ok(()) })
        })
        .await
    }
    async fn bind_resources<T: Timer>(
        &self,
        target: &Target,
        resources: &ResourceSet,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        self.bind_with(target, resources, control, (), |_, _| {
            Box::pin(async { Ok(()) })
        })
        .await
    }
    async fn claim_due<T: Timer>(
        &self,
        scope: &Scope,
        limit: usize,
        lease: Duration,
        control: &Control<'_, T>,
    ) -> Result<ClaimBatch<PgClaim>, Error> {
        if !(1..=64).contains(&limit) {
            return Err(Error::new(ErrorKind::InvalidInput));
        }
        let ttl = millis(lease)?;
        let scope = scope.clone();
        self.controlled_tx(&scope.clone(), control, move |tx| Box::pin(async move {
            let rows = sqlx::query("SELECT batch.more,c.tenant_id::text,c.reconciler,c.entity,c.token::text,c.epoch,c.wake_version,c.failures,c.binding_revision FROM rss_reconcile.claim_due($1::uuid,$2,$3,$4) batch LEFT JOIN LATERAL unnest(batch.claims) c ON true")
                .bind(scope.tenant().to_string()).bind(scope.reconciler()).bind(limit as i32).bind(ttl)
                .fetch_all(&mut *tx.connection).await.map_err(map_sql)?;
            decode_batch(&scope, rows)
        })).await
    }
    async fn renew<T: Timer>(
        &self,
        claim: &PgClaim,
        lease: Duration,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        let ttl = millis(lease)?;
        let key = Key::from(claim);
        self.controlled_tx(claim.target.scope(), control, move |tx| {
            Box::pin(async move {
                key.query("SELECT rss_reconcile.renew($1::uuid,$2,$3,$4::uuid,$5,$6,$7)")
                    .bind(key.binding)
                    .bind(ttl)
                    .execute(&mut *tx.connection)
                    .await
                    .map_err(map_sql)?;
                Ok(())
            })
        })
        .await
    }
    async fn finish<T: Timer>(
        &self,
        claim: &PgClaim,
        completion: Completion,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        let (result, delay, failures) = match completion {
            Completion::Converged => ("converged", 0, 0),
            Completion::Reobserve(d) => ("pending", millis(d)?, 0),
            Completion::Deferred(d) => ("deferred", millis(d)?, i64::from(claim.failures)),
            Completion::Retry { after, failures } => ("retry", millis(after)?, i64::from(failures)),
            Completion::Suspended { failures } => ("suspended", 0, i64::from(failures)),
        };
        let key = Key::from(claim);
        let wake = claim.wake;
        self.controlled_tx(claim.target.scope(), control, move |tx| {
            Box::pin(async move {
                key.query(
                    "SELECT rss_reconcile.finish($1::uuid,$2,$3,$4::uuid,$5,$6,$7,$8,$9,$10)",
                )
                .bind(key.binding)
                .bind(wake)
                .bind(result)
                .bind(delay)
                .bind(failures)
                .execute(&mut *tx.connection)
                .await
                .map_err(map_sql)?;
                Ok(())
            })
        })
        .await
    }
    async fn release<T: Timer>(
        &self,
        claim: &PgClaim,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        let key = Key::from(claim);
        self.controlled_tx(claim.target.scope(), control, move |tx| {
            Box::pin(async move {
                key.query("SELECT rss_reconcile.release($1::uuid,$2,$3,$4::uuid,$5)")
                    .execute(&mut *tx.connection)
                    .await
                    .map_err(map_sql)?;
                Ok(())
            })
        })
        .await
    }
}
/// Owned private SQL arguments; never a public second claim identity.
pub(crate) struct Key {
    pub(crate) target: Target,
    token: String,
    epoch: i64,
    binding: i64,
}
impl From<&PgClaim> for Key {
    fn from(c: &PgClaim) -> Self {
        Self {
            target: c.target.clone(),
            token: c.token.clone(),
            epoch: c.epoch,
            binding: c.binding,
        }
    }
}
impl Key {
    #[cfg(feature = "transactional-messaging")]
    pub(crate) fn copy_arguments(&self) -> Self {
        Self {
            target: self.target.clone(),
            token: self.token.clone(),
            epoch: self.epoch,
            binding: self.binding,
        }
    }
    fn query(
        &self,
        sql: &'static str,
    ) -> sqlx::query::Query<'static, sqlx::Postgres, sqlx::postgres::PgArguments> {
        sqlx::query(sql)
            .bind(self.target.scope().tenant().to_string())
            .bind(self.target.scope().reconciler().to_owned())
            .bind(self.target.entity().to_owned())
            .bind(self.token.clone())
            .bind(self.epoch)
    }
}
pub(crate) async fn lock(conn: &mut PgConnection, key: &Key) -> Result<(), Error> {
    let current: bool = key
        .query("SELECT rss_reconcile.lock_execution($1::uuid,$2,$3,$4::uuid,$5,$6)")
        .bind(key.binding)
        .fetch_one(conn)
        .await
        .map_err(map_sql)?
        .try_get(0)
        .map_err(map_sql)?;
    if current {
        Ok(())
    } else {
        Err(Error::new(ErrorKind::BindingChanged))
    }
}
pub(crate) async fn mark_applied(conn: &mut PgConnection, key: &Key) -> Result<(), Error> {
    key.query("SELECT rss_reconcile.mark_applied($1::uuid,$2,$3,$4::uuid,$5,$6)")
        .bind(key.binding)
        .execute(conn)
        .await
        .map_err(map_sql)?;
    Ok(())
}
pub(crate) fn validate_resources(target: &Target, resources: &ResourceSet) -> Result<(), Error> {
    if target.scope().tenant() != resources.tenant() {
        return Err(Error::new(ErrorKind::InvalidInput));
    }
    Ok(())
}
pub(crate) async fn schedule(
    conn: &mut PgConnection,
    target: &Target,
    resources: &ResourceSet,
    waking: bool,
) -> Result<(), Error> {
    validate_resources(target, resources)?;
    let sql = if waking {
        "SELECT rss_reconcile.wake($1::uuid,$2,$3,$4)"
    } else {
        "SELECT rss_reconcile.bind_resources($1::uuid,$2,$3,$4)"
    };
    sqlx::query(sql)
        .bind(target.scope().tenant().to_string())
        .bind(target.scope().reconciler())
        .bind(target.entity())
        .bind(resources.keys())
        .execute(conn)
        .await
        .map_err(map_sql)?;
    Ok(())
}
pub(crate) async fn complete_step<R>(
    conn: &mut PgConnection,
    key: &Key,
    step: crate::ProtectedStep<R>,
) -> Result<ReconcileStep<R>, Error> {
    match step {
        crate::ProtectedStep::Ready(value) => {
            mark_applied(conn, key).await?;
            Ok(ReconcileStep::Ready(value))
        }
        crate::ProtectedStep::Deferred(after) => {
            millis(after)?;
            authority(conn, key).await?;
            Ok(ReconcileStep::Deferred(after))
        }
        crate::ProtectedStep::Rebind(resources, after) => {
            millis(after)?;
            authority(conn, key).await?;
            schedule(conn, &key.target, &resources, false).await?;
            Ok(ReconcileStep::Deferred(after))
        }
    }
}
async fn authority(conn: &mut PgConnection, key: &Key) -> Result<(), Error> {
    key.query("SELECT rss_reconcile.lock_authority($1::uuid,$2,$3,$4::uuid,$5)")
        .execute(conn)
        .await
        .map_err(map_sql)?;
    Ok(())
}
fn decode_batch(
    scope: &Scope,
    rows: Vec<sqlx::postgres::PgRow>,
) -> Result<ClaimBatch<PgClaim>, Error> {
    let more = rows
        .first()
        .ok_or_else(|| Error::new(ErrorKind::StorageContract))?
        .try_get("more")
        .map_err(map_sql)?;
    let mut claims = Vec::new();
    for row in &rows {
        if row.try_get::<bool, _>("more").map_err(map_sql)? != more {
            return Err(Error::new(ErrorKind::StorageContract));
        }
        let Some(entity) = row
            .try_get::<Option<String>, _>("entity")
            .map_err(map_sql)?
        else {
            if rows.len() != 1 {
                return Err(Error::new(ErrorKind::StorageContract));
            }
            continue;
        };
        let tenant: String = row.try_get("tenant_id").map_err(map_sql)?;
        let reconciler: String = row.try_get("reconciler").map_err(map_sql)?;
        if tenant != scope.tenant().to_string() || reconciler != scope.reconciler() {
            return Err(Error::new(ErrorKind::StorageContract));
        }
        claims.push(PgClaim {
            target: Target::new(scope.clone(), entity)?,
            token: row.try_get("token").map_err(map_sql)?,
            epoch: row.try_get("epoch").map_err(map_sql)?,
            wake: row.try_get("wake_version").map_err(map_sql)?,
            binding: row.try_get("binding_revision").map_err(map_sql)?,
            failures: u32::try_from(row.try_get::<i64, _>("failures").map_err(map_sql)?)
                .map_err(|_| Error::new(ErrorKind::StorageContract))?,
        });
    }
    Ok(ClaimBatch { claims, more })
}
