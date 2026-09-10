//! A source is the immutable receipt journal itself, never a second delivery queue.
//! ref: EventStore/EventStoreDB-Client-Rust kurrentdb/src/types.rs@d76e58ba464b2dc77c196ffefbca330ce9df938d
use crate::{PgStore, store::restore, transaction::sql_error};
use futures::TryStreamExt;
use rss_observation::{ApplicableRecord, Clock, Error, ErrorKind, Id, JournalReadGrant, Scope};
use rss_projection::{BatchLimit, Event, Phase, Position, Source, SourceScope};
#[cfg(feature = "projection-postgres")]
use rss_projection_postgres::PgTransaction;
use rss_request_context::Deadline;
use serde::Serialize;
use sqlx::{Row, postgres::PgRow};
use std::{sync::Arc, time::Duration};
const LOOKUP: &str = "SELECT scope,batch_id,raw,fingerprint,received_at,policy,decision,sequence::text AS sequence,applicable,log_position FROM rss_observation.batches WHERE tenant_id=$1::uuid AND log_position=$2 AND applicable";
const READ: &str = "SELECT scope,batch_id,raw,fingerprint,received_at,policy,decision,sequence::text AS sequence,applicable,log_position FROM rss_observation.batches WHERE tenant_id=$1::uuid AND applicable AND ($2::bigint IS NULL OR log_position>$2) ORDER BY log_position LIMIT $3";
/// Tenant-authorized immutable source. The adopted Observation store owns the pool lifecycle.
/// Reauthorize a new grant for each host operation; cancel/join workers before revocation.
pub struct PgSource<C> {
    store: Arc<PgStore<C>>,
    scope: SourceScope,
    grant: JournalReadGrant,
}
impl<C: Clock> PgSource<C> {
    /// Bind the admitted journal to explicit tenant authority and caller-declared source lineage.
    /// Reuse this source on restart; use a new source after rebuilding the input journal.
    /// This declaration does not authenticate the caller or prove the database's provenance.
    pub fn new(
        store: Arc<PgStore<C>>,
        grant: JournalReadGrant,
        scope: SourceScope,
    ) -> Result<Self, Error> {
        if scope.tenant() != grant.tenant() {
            return Err(ErrorKind::Unauthorized.into());
        }
        Ok(Self {
            store,
            scope,
            grant,
        })
    }
    /// Exact tenant/source binding for runner and projection generation initialization.
    pub const fn scope(&self) -> &SourceScope {
        &self.scope
    }
    fn check(&self, scope: &SourceScope) -> Result<(), Error> {
        if scope != &self.scope {
            return Err(ErrorKind::Unauthorized.into());
        }
        Ok(())
    }
    fn deadline(&self) -> Deadline {
        Deadline::at(self.store.clock.now() + Duration::from_secs(30))
    }
    /// Resolve in an Observation-owned, caller-budgeted read transaction. Remote targets must
    /// resolve before sending and remain explicitly at least once with target-side deduplication.
    pub async fn resolve(
        &self,
        event: &Event,
        deadline: Deadline,
    ) -> Result<ApplicableRecord, rss_projection::Error> {
        self.check(event.source()).map_err(source_error)?;
        let event = event.clone();
        let tenant = self.grant.tenant();
        self.store
            .transact(
                tenant,
                deadline,
                self.store.take_fault(),
                move |connection, _| {
                    Box::pin(async move {
                        let row = sqlx::query(LOOKUP)
                            .bind(tenant.to_string())
                            .bind(event.position().get() as i64)
                            .fetch_optional(connection)
                            .await
                            .map_err(sql_error)?;
                        resolve_row(row, &event)
                    })
                },
            )
            .await
            .map_err(|error: BridgeError| error.0)
    }
    /// Resolve on the same borrowed transaction as the read-model effect/checkpoint. Does not
    /// change tenant, watchdogs or settlement authority; the enclosing Projection Control applies.
    #[cfg(feature = "projection-postgres")]
    pub async fn resolve_in_transaction(
        &self,
        tx: &mut PgTransaction<'_>,
        event: &Event,
    ) -> Result<ApplicableRecord, rss_projection::Error> {
        self.check(event.source()).map_err(source_error)?;
        if tx.tenant() != self.grant.tenant() {
            return Err(source_error(ErrorKind::Unauthorized.into()));
        }
        let tenant = self.grant.tenant().to_string();
        let position = event.position().get() as i64;
        let row = tx
            .with_connection(move |connection| {
                Box::pin(async move {
                    // Keep the SQL result inside the callback value so the Observation
                    // owner classifies its own static query before the application SQL wrapper.
                    Ok(sqlx::query(LOOKUP)
                        .bind(tenant)
                        .bind(position)
                        .fetch_optional(connection)
                        .await
                        .map_err(sql_error))
                })
            })
            .await
            .map_err(rss_projection::Error::from)?
            .map_err(source_error)?;
        resolve_row(row, event).map_err(|error| error.0)
    }
}
impl<C: Clock> Source for PgSource<C> {
    async fn high_water(
        &self,
        scope: &SourceScope,
    ) -> Result<Option<Position>, rss_projection::Error> {
        self.check(scope).map_err(source_error)?;
        let tenant = self.grant.tenant();
        self.store.transact(tenant, self.deadline(), 0, move |connection, _| Box::pin(async move {
            let value: Option<i64> = sqlx::query_scalar("SELECT max(log_position) FROM rss_observation.batches WHERE tenant_id=$1::uuid AND applicable")
                .bind(tenant.to_string()).fetch_one(connection).await.map_err(sql_error)?;
            value.map(position).transpose()
        })).await.map_err(source_error)
    }
    async fn read(
        &self,
        scope: &SourceScope,
        after: Option<Position>,
        limit: BatchLimit,
    ) -> Result<Vec<Event>, rss_projection::Error> {
        self.check(scope).map_err(source_error)?;
        let tenant = self.grant.tenant();
        let scope = self.scope.clone();
        self.store
            .transact(
                tenant,
                self.deadline(),
                self.store.take_fault(),
                move |connection, _| {
                    Box::pin(async move {
                        let mut rows = sqlx::query(READ)
                            .bind(tenant.to_string())
                            .bind(after.map(|p| p.get() as i64))
                            .bind(i64::from(limit.get()))
                            .fetch(connection);
                        let mut events = Vec::new();
                        while let Some(row) = rows.try_next().await.map_err(sql_error)? {
                            let (pos, record) = restore_row(row)?;
                            events.push(
                                event_for(&scope, pos, &record)
                                    .map_err(|e| restore_error(Some(pos), e))?,
                            );
                        }
                        Ok(events)
                    })
                },
            )
            .await
            .map_err(|error: BridgeError| error.0)
    }
}
// Only this adapter needs to carry projection diagnostics through Observation settlement.
struct BridgeError(rss_projection::Error);
impl From<Error> for BridgeError {
    fn from(error: Error) -> Self {
        Self(source_error(error))
    }
}
fn restore_error(position: Option<Position>, error: Error) -> BridgeError {
    BridgeError(rss_projection::Error::provider(
        rss_projection::ErrorKind::StorageContract,
        Phase::Restore,
        None,
        position,
        error,
    ))
}
fn position(value: i64) -> Result<Position, Error> {
    if value <= 0 {
        return Err(ErrorKind::Invariant.into());
    }
    Position::new(value as u64).map_err(projection_error)
}
fn restore_row(row: PgRow) -> Result<(Position, ApplicableRecord), BridgeError> {
    let pos = row
        .try_get("log_position")
        .map_err(sql_error)
        .and_then(position)
        .map_err(|e| restore_error(None, e))?;
    let record = (|| -> Result<ApplicableRecord, Error> {
        let scope: Scope = serde_json::from_str(row.try_get("scope").map_err(sql_error)?)
            .map_err(|e| Error::provider(ErrorKind::Invariant, e))?;
        let id = Id::new(row.try_get::<String, _>("batch_id").map_err(sql_error)?)
            .map_err(|e| Error::provider(ErrorKind::Invariant, e))?;
        restore(row, &scope, &id)?
            .into_applicable()
            .map_err(|e| Error::provider(ErrorKind::Invariant, e))
    })()
    .map_err(|e| restore_error(Some(pos), e))?;
    Ok((pos, record))
}
fn resolve_row(row: Option<PgRow>, event: &Event) -> Result<ApplicableRecord, BridgeError> {
    let row =
        row.ok_or_else(|| restore_error(Some(event.position()), ErrorKind::Invariant.into()))?;
    let (pos, record) = restore_row(row)?;
    // Reconstruct the only accepted encoding. No permissive parser or alternate identity.
    if event_for(event.source(), pos, &record).map_err(|e| restore_error(Some(pos), e))? != *event {
        return Err(BridgeError(rss_projection::Error::provider(
            rss_projection::ErrorKind::InvalidInput,
            Phase::Restore,
            None,
            Some(pos),
            Error::new(ErrorKind::InvalidInput),
        )));
    }
    Ok(record)
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Reference<'a> {
    version: u8,
    scope: &'a Scope,
    batch_id: &'a Id,
    fingerprint: [u8; 32],
}
fn event_for(
    scope: &SourceScope,
    position: Position,
    record: &ApplicableRecord,
) -> Result<Event, Error> {
    let record = record.record();
    if scope.tenant() != record.scope().tenant() {
        return Err(ErrorKind::Invariant.into());
    }
    let fingerprint = record.batch().fingerprint(record.scope())?;
    let id: String = fingerprint.iter().map(|b| format!("{b:02x}")).collect();
    let payload = serde_json::to_vec(&Reference {
        version: 1,
        scope: record.scope(),
        batch_id: record.batch().id(),
        fingerprint,
    })?;
    Event::new(scope.clone(), position, id, payload).map_err(projection_error)
}
fn projection_error(error: rss_projection::Error) -> Error {
    Error::provider(ErrorKind::Invariant, error)
}
fn source_error(error: Error) -> rss_projection::Error {
    use rss_projection::{ErrorKind as Kind, Phase};
    let (kind, phase) = match error.kind() {
        ErrorKind::Unauthorized => (Kind::ScopeMismatch, Phase::Admission),
        ErrorKind::Deadline => (Kind::Deadline, Phase::Operation),
        ErrorKind::CommitUnknown => (Kind::CommitUnknown, Phase::Commit),
        ErrorKind::RollbackFailed => (Kind::RollbackFailed, Phase::Rollback),
        ErrorKind::Storage => (Kind::Unavailable, Phase::Operation),
        ErrorKind::Invariant
        | ErrorKind::InvalidInput
        | ErrorKind::Conflict
        | ErrorKind::Closed
        | ErrorKind::LifecycleConflict
        | ErrorKind::StaleEpoch
        | ErrorKind::UnknownStream => (Kind::StorageContract, Phase::Operation),
    };
    rss_projection::Error::provider(kind, phase, None, None, error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rss_observation::{
        Batch, Body, Change, Coverage, Epoch, Policy, Record, Registration, State,
    };
    use rss_request_context::TenantId;
    #[test]
    fn reference_is_bounded_and_immutable_for_large_unicode_reports() -> anyhow::Result<()> {
        let tenant = TenantId::parse("00000000-0000-0000-0000-000000000001")?;
        let scope = Scope::new(
            tenant,
            Id::new("device")?,
            Registration::new("r")?,
            Id::new("source")?,
            Id::new("dataset")?,
            Epoch::new("e")?,
        );
        let changes = (0..15)
            .map(|n| Ok(Change::upsert(Id::new(n.to_string())?, vec![255; 65536])))
            .collect::<Result<Vec<_>, Error>>()?;
        let batch = Batch::new(
            Id::new("批".repeat(80))?,
            u64::MAX,
            rss_contract::Timepoint::try_from(100)?,
            Coverage::new(
                Id::new("all")?,
                Id::new("v1")?,
                Id::new("catalog")?,
                Id::new("bytes")?,
            ),
            Body::Snapshot(changes),
        )?;
        assert!(batch.encode().len() > 3_000_000);
        let policy = Policy::new(10, 1, 10)?;
        let decision = State::initial().advance(&batch, 100, &policy)?;
        let record =
            Record::from_durable(scope, batch, 100, policy, decision)?.into_applicable()?;
        let source = SourceScope::new(tenant, "rss.observation.v1")?;
        let first = event_for(&source, Position::new(1)?, &record)?;
        let second = event_for(&source, Position::new(2)?, &record)?;
        assert_eq!(first.id(), second.id());
        assert_eq!(first.payload(), second.payload());
        assert_eq!(first.id().len(), 64);
        assert!(first.payload().len() < 4096);
        let rebuilt = event_for(
            &SourceScope::new(tenant, "rebuilt")?,
            Position::new(1)?,
            &record,
        )?;
        assert_ne!(first.source(), rebuilt.source());
        assert_eq!(first.id(), rebuilt.id());
        assert_eq!(first.payload(), rebuilt.payload());
        assert_eq!(first.fingerprint(), rebuilt.fingerprint());
        Ok(())
    }
    #[test]
    fn reference_v1_wire_identity_is_fixed() -> anyhow::Result<()> {
        let scope: Scope = serde_json::from_str(
            r#"{"tenant":"00000000-0000-0000-0000-000000000001","object":"device","registration":"r","source":"source","dataset":"dataset","epoch":"e"}"#,
        )?;
        let batch=Batch::decode(br#"{"version":1,"id":"golden","sequence":0,"observedAt":100,"coverage":{"id":"all","version":"v1","definition":"catalog","format":"bytes"},"body":{"kind":"snapshot","data":[]}}"#)?;
        let policy = Policy::new(10, 1, 10)?;
        let decision = State::initial().advance(&batch, 100, &policy)?;
        let source = SourceScope::new(scope.tenant(), "rss.observation.v1")?;
        let record =
            Record::from_durable(scope, batch, 100, policy, decision)?.into_applicable()?;
        let event = event_for(&source, Position::new(1)?, &record)?;
        assert_eq!(
            event.id(),
            "b2d5ea9850975839417877d7b7f1c0e3d661b7187e1c1ced9c923cf78194116e"
        );
        assert_eq!(event.payload(),br#"{"version":1,"scope":{"tenant":"00000000-0000-0000-0000-000000000001","object":"device","registration":"r","source":"source","dataset":"dataset","epoch":"e"},"batchId":"golden","fingerprint":[178,213,234,152,80,151,88,57,65,120,119,215,183,241,192,227,214,97,183,24,126,28,28,237,156,146,60,247,129,148,17,110]}"#);
        Ok(())
    }
}
