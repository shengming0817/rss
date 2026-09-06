use crate::{
    PgOperationError, PgStore, PgTransaction,
    journal::{decode_position, encode_position},
    transaction::map_sql,
};
use rss_projection::{
    ApplyOutcome, Checkpoint, Control, Error, ErrorKind, Event, Execution, ExternalCheckpoint,
    GenerationStart, Position, ProjectionScope, ReplayBound, Timer,
};
use sqlx::Row;
use std::{future::Future, sync::Arc, time::Duration};
use uuid::Uuid;

/// A private provider-minted worker identity. Obtain a new one only by explicit takeover.
/// Moving it into a session binds that session to one store and generation.
pub struct PgClaim {
    scope: ProjectionScope,
    epoch: i64,
    token: Uuid,
    store: Arc<()>,
}
impl PgClaim {
    /// Generation bound to this claim.
    pub const fn scope(&self) -> &ProjectionScope {
        &self.scope
    }
}
impl PgStore {
    /// Create an immutable generation definition, or verify an identical existing definition.
    /// For replay, obtain the upper bound from Source::high_water under the caller's Control.
    pub async fn initialize<T: Timer>(
        &self,
        scope: &ProjectionScope,
        start: GenerationStart,
        bound: ReplayBound,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        if start
            .receipts()
            .iter()
            .any(|receipt| receipt.source() != scope.source())
        {
            return Err(Error::new(ErrorKind::ScopeMismatch));
        }
        let scope = scope.clone();
        let source = scope.source().clone();
        self.controlled_tx(&source, control, move |tx| {
            Box::pin(async move {
                let (replay, end) = match bound {
                    ReplayBound::Live => (false, None),
                    ReplayBound::Through(end) => (true, end),
                };
                sqlx::query("SELECT rss_projection.initialize($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9)")
                    .bind(scope.source().tenant().to_string())
                    .bind(scope.source().source())
                    .bind(scope.projection())
                    .bind(scope.generation())
                    .bind(encode_position(start.position()))
                    .bind(replay)
                    .bind(encode_position(end))
                    .bind(
                        start
                            .receipts()
                            .iter()
                            .map(|r| r.id().to_owned())
                            .collect::<Vec<_>>(),
                    )
                    .bind(
                        start
                            .receipts()
                            .iter()
                            .map(|r| r.fingerprint().to_vec())
                            .collect::<Vec<_>>(),
                    )
                    .execute(&mut *tx.connection)
                    .await
                    .map_err(map_sql)?;
                Ok(())
            })
        })
        .await
    }
    /// Explicitly supersede the old worker. No lease or automatic reacquisition is involved.
    pub async fn takeover<T: Timer>(
        &self,
        scope: &ProjectionScope,
        control: &Control<'_, T>,
    ) -> Result<PgClaim, Error> {
        let scope = scope.clone();
        let source = scope.source().clone();
        let token = Uuid::new_v4();
        let store = self.identity.clone();
        self.controlled_tx(&source, control, move |tx| {
            Box::pin(async move {
                let epoch = sqlx::query_scalar(
                    "SELECT rss_projection.takeover($1::uuid,$2,$3,$4,$5::uuid)",
                )
                .bind(scope.source().tenant().to_string())
                .bind(scope.source().source())
                .bind(scope.projection())
                .bind(scope.generation())
                .bind(token.to_string())
                .fetch_one(&mut *tx.connection)
                .await
                .map_err(map_sql)?;
                Ok(PgClaim {
                    scope,
                    epoch,
                    token,
                    store,
                })
            })
        })
        .await
    }
    /// Compose trusted read-model SQL with a provider-minted epoch.
    /// The effect owns its dependencies (for example Arc-backed repositories).
    pub fn projection<H: PgEffect + 'static>(
        &self,
        claim: PgClaim,
        effect: H,
    ) -> Result<PgProjection<H>, Error> {
        self.check_claim(&claim)?;
        Ok(PgProjection {
            store: self.clone(),
            claim: Arc::new(claim),
            effect: Arc::new(effect),
        })
    }
    /// Build the checkpoint half of an explicitly external, at-least-once projection.
    pub fn external_checkpoint(&self, claim: PgClaim) -> Result<PgCheckpoint, Error> {
        self.check_claim(&claim)?;
        Ok(PgCheckpoint {
            store: self.clone(),
            claim: Arc::new(claim),
        })
    }
    fn check_claim(&self, claim: &PgClaim) -> Result<(), Error> {
        if Arc::ptr_eq(&self.identity, &claim.store) {
            Ok(())
        } else {
            Err(Error::new(ErrorKind::ScopeMismatch))
        }
    }
    async fn checkpoint_for(&self, claim: Arc<PgClaim>) -> Result<Checkpoint, Error> {
        self.transact(claim.scope.source().tenant(), Duration::from_secs(30), move |tx| Box::pin(async move {
            let s = &claim.scope;
            let row = sqlx::query("SELECT position,replay,end_position FROM rss_projection.checkpoints WHERE tenant_id=$1::uuid AND source_id=$2 AND projection_id=$3 AND generation=$4 AND epoch=$5 AND worker_token=$6::uuid")
                .bind(s.source().tenant().to_string()).bind(s.source().source()).bind(s.projection()).bind(s.generation()).bind(claim.epoch).bind(claim.token.to_string())
                .fetch_optional(&mut *tx.connection).await.map_err(map_sql)?.ok_or(Error::new(ErrorKind::Fenced))?;
            let position = row.try_get::<Option<i64>,_>("position").map_err(map_sql)?.map(decode_position).transpose()?;
            let end = row.try_get::<Option<i64>,_>("end_position").map_err(map_sql)?.map(decode_position).transpose()?;
            Ok::<_, Error>(Checkpoint { position, bound: if row.try_get::<bool,_>("replay").map_err(map_sql)? { ReplayBound::Through(end) } else { ReplayBound::Live } })
        })).await
    }
}
/// Application decision before transaction settlement. Duplicate is deliberately absent:
/// only the adapter's locked receipt lookup may classify an already committed fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PgEffectOutcome {
    /// Stage a read-model effect.
    Applied,
    /// Intentionally ignore the fact while advancing its checkpoint.
    Filtered,
}
/// Trusted application read-model writer. Include tenant and generation in application keys.
/// A successful result means only that SQL was staged; the adapter still owns settlement.
pub trait PgEffect: Send + Sync {
    /// Apply within the borrowed transaction. Returning Err rolls back the entire event.
    fn apply(
        &self,
        tx: &mut PgTransaction<'_>,
        scope: &ProjectionScope,
        event: &Event,
    ) -> impl Future<Output = Result<PgEffectOutcome, PgOperationError>> + Send;
}
/// Atomic PostgreSQL projection session. No standalone checkpoint writer is exposed here.
pub struct PgProjection<H> {
    store: PgStore,
    claim: Arc<PgClaim>,
    effect: Arc<H>,
}
impl<H: PgEffect + 'static> Execution for PgProjection<H> {
    fn scope(&self) -> &ProjectionScope {
        &self.claim.scope
    }
    async fn checkpoint(&self) -> Result<Checkpoint, Error> {
        self.store.checkpoint_for(self.claim.clone()).await
    }
    async fn execute<T: Timer>(
        &self,
        expected: Option<Position>,
        event: &Event,
        control: &Control<'_, T>,
    ) -> Result<ApplyOutcome, Error> {
        if event.source() != self.scope().source() {
            return Err(Error::new(ErrorKind::ScopeMismatch));
        }
        let claim = self.claim.clone();
        let effect = self.effect.clone();
        let event = event.clone();
        self.store
            .controlled_tx(self.scope().source(), control, move |tx| {
                Box::pin(async move {
                    let duplicate = lock(tx, &claim, expected, &event).await?;
                    let outcome = if duplicate {
                        ApplyOutcome::Duplicate
                    } else {
                        match effect
                            .apply(tx, &claim.scope, &event)
                            .await
                            .map_err(|error| error.0)?
                        {
                            PgEffectOutcome::Applied => ApplyOutcome::Applied,
                            PgEffectOutcome::Filtered => ApplyOutcome::Filtered,
                        }
                    };
                    finish(tx, &claim, expected, &event).await?;
                    Ok(outcome)
                })
            })
            .await
    }
}
/// PostgreSQL checkpoint session for a remote target. This type does not claim atomic effects.
pub struct PgCheckpoint {
    store: PgStore,
    claim: Arc<PgClaim>,
}
impl ExternalCheckpoint for PgCheckpoint {
    fn scope(&self) -> &ProjectionScope {
        &self.claim.scope
    }
    async fn load(&self) -> Result<Checkpoint, Error> {
        self.store.checkpoint_for(self.claim.clone()).await
    }
    async fn advance<T: Timer>(
        &self,
        expected: Option<Position>,
        event: &Event,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        if event.source() != self.scope().source() {
            return Err(Error::new(ErrorKind::ScopeMismatch));
        }
        let claim = self.claim.clone();
        let event = event.clone();
        self.store
            .controlled_tx(self.scope().source(), control, move |tx| {
                Box::pin(async move { finish(tx, &claim, expected, &event).await })
            })
            .await
    }
}
async fn lock(
    tx: &mut PgTransaction<'_>,
    claim: &PgClaim,
    expected: Option<Position>,
    event: &Event,
) -> Result<bool, Error> {
    let s = &claim.scope;
    sqlx::query_scalar(
        "SELECT rss_projection.lock_event($1::uuid,$2,$3,$4,$5,$6::uuid,$7,$8,$9,$10)",
    )
    .bind(s.source().tenant().to_string())
    .bind(s.source().source())
    .bind(s.projection())
    .bind(s.generation())
    .bind(claim.epoch)
    .bind(claim.token.to_string())
    .bind(encode_position(expected))
    .bind(encode_position(Some(event.position())))
    .bind(event.id())
    .bind(event.fingerprint().as_slice())
    .fetch_one(&mut *tx.connection)
    .await
    .map_err(map_sql)
}
async fn finish(
    tx: &mut PgTransaction<'_>,
    claim: &PgClaim,
    expected: Option<Position>,
    event: &Event,
) -> Result<(), Error> {
    let s = &claim.scope;
    sqlx::query("SELECT rss_projection.finish_event($1::uuid,$2,$3,$4,$5,$6::uuid,$7,$8,$9,$10)")
        .bind(s.source().tenant().to_string())
        .bind(s.source().source())
        .bind(s.projection())
        .bind(s.generation())
        .bind(claim.epoch)
        .bind(claim.token.to_string())
        .bind(encode_position(expected))
        .bind(encode_position(Some(event.position())))
        .bind(event.id())
        .bind(event.fingerprint().as_slice())
        .execute(&mut *tx.connection)
        .await
        .map_err(map_sql)?;
    Ok(())
}
