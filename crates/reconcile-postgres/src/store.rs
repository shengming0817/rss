use crate::{PgOperationError, PgStore, PgTransaction, transaction::map_sql};
use futures::future::BoxFuture;
use rss_reconcile::{
    Claim, Completion, Control, DurableStore, Error, ErrorKind, Scope, Target, Timer,
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
    ) -> Result<R, Error>
    where
        F: for<'c> FnOnce(
                &'c mut C,
                &'c mut PgTransaction<'_>,
            ) -> BoxFuture<'c, Result<R, PgOperationError>>
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
                    mark_applied(tx.connection, &state.0).await?;
                    Ok(value)
                })
            },
        )
        .await
    }
    /// Atomically register work with trusted SQL, accepting borrowed application context.
    pub async fn wake_with<T: Timer, R: Send, C: Send, F>(
        &self,
        target: &Target,
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
        self.context_tx(
            target.scope(),
            control,
            (target.clone(), context, Some(operation)),
            |state, tx| {
                Box::pin(async move {
                    wake(tx.connection, &state.0).await?;
                    let operation = state
                        .2
                        .take()
                        .ok_or_else(|| Error::new(ErrorKind::Invariant))?;
                    operation(&mut state.1, tx).await.map_err(Error::from)
                })
            },
        )
        .await
    }
}
impl DurableStore for PgStore {
    type Claim = PgClaim;
    async fn wake<T: Timer>(&self, target: &Target, control: &Control<'_, T>) -> Result<(), Error> {
        self.wake_with(target, control, (), |_, _| Box::pin(async { Ok(()) }))
            .await
    }
    async fn claim_due<T: Timer>(
        &self,
        scope: &Scope,
        limit: usize,
        lease: Duration,
        control: &Control<'_, T>,
    ) -> Result<Vec<PgClaim>, Error> {
        if !(1..=64).contains(&limit) {
            return Err(Error::new(ErrorKind::InvalidInput));
        }
        let ttl = millis(lease)?;
        let scope = scope.clone();
        self.controlled_tx(&scope.clone(),control,move |tx| Box::pin(async move {
            let rows=sqlx::query("SELECT tenant_id::text,reconciler,entity,token::text,epoch,wake_version,failures FROM rss_reconcile.claim_due($1::uuid,$2,$3,$4)")
                .bind(scope.tenant().to_string()).bind(scope.reconciler()).bind(limit as i32).bind(ttl).fetch_all(&mut *tx.connection).await.map_err(map_sql)?;
            rows.into_iter().map(|row| {
                let tenant:String=row.try_get("tenant_id").map_err(map_sql)?;let reconciler:String=row.try_get("reconciler").map_err(map_sql)?;
                if tenant!=scope.tenant().to_string() || reconciler!=scope.reconciler() {return Err(Error::new(ErrorKind::StorageContract));}
                Ok(PgClaim {target:Target::new(scope.clone(),row.try_get::<String,_>("entity").map_err(map_sql)?)?, token:row.try_get("token").map_err(map_sql)?,epoch:row.try_get("epoch").map_err(map_sql)?,wake:row.try_get("wake_version").map_err(map_sql)?,failures:u32::try_from(row.try_get::<i64,_>("failures").map_err(map_sql)?).map_err(|_|Error::new(ErrorKind::StorageContract))?})
            }).collect()
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
                key.query("SELECT rss_reconcile.renew($1::uuid,$2,$3,$4::uuid,$5,$6)")
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
            Completion::Retry { after, failures } => ("retry", millis(after)?, i64::from(failures)),
            Completion::Suspended { failures } => ("suspended", 0, i64::from(failures)),
        };
        let key = Key::from(claim);
        let wake = claim.wake;
        self.controlled_tx(claim.target.scope(), control, move |tx| {
            Box::pin(async move {
                key.query("SELECT rss_reconcile.finish($1::uuid,$2,$3,$4::uuid,$5,$6,$7,$8,$9)")
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
    target: Target,
    token: String,
    epoch: i64,
}
impl From<&PgClaim> for Key {
    fn from(c: &PgClaim) -> Self {
        Self {
            target: c.target.clone(),
            token: c.token.clone(),
            epoch: c.epoch,
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
    key.query("SELECT rss_reconcile.lock_claim($1::uuid,$2,$3,$4::uuid,$5)")
        .execute(conn)
        .await
        .map_err(map_sql)?;
    Ok(())
}
pub(crate) async fn mark_applied(conn: &mut PgConnection, key: &Key) -> Result<(), Error> {
    key.query("SELECT rss_reconcile.mark_applied($1::uuid,$2,$3,$4::uuid,$5)")
        .execute(conn)
        .await
        .map_err(map_sql)?;
    Ok(())
}
pub(crate) async fn wake(conn: &mut PgConnection, target: &Target) -> Result<(), Error> {
    sqlx::query("SELECT rss_reconcile.wake($1::uuid,$2,$3)")
        .bind(target.scope().tenant().to_string())
        .bind(target.scope().reconciler())
        .bind(target.entity())
        .execute(conn)
        .await
        .map_err(map_sql)?;
    Ok(())
}
