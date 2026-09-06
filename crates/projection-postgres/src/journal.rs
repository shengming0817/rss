use crate::{PgOperationError, PgStore, PgTransaction, transaction::map_sql};
use rss_projection::{
    BatchLimit, Control, Error, ErrorKind, Event, Position, Source, SourceScope, Timer,
};
use sqlx::Row;
use std::time::Duration;

impl PgTransaction<'_> {
    /// Idempotently append a fact in this transaction, holding the source allocator lock until
    /// settlement. Same ID/bytes returns its original position; changed bytes conflict.
    /// Acquire source locks before application row locks, in sorted source order if multiple.
    pub async fn append(
        &mut self,
        source: &SourceScope,
        id: &str,
        payload: &[u8],
    ) -> Result<Position, PgOperationError> {
        if self.tenant() != source.tenant() {
            return Err(PgOperationError(Error::new(ErrorKind::ScopeMismatch)));
        }
        append_connection(self.connection, source, id, payload)
            .await
            .map_err(PgOperationError)
    }
}
/// Stage an append in a caller-owned SQLx transaction without taking settlement authority.
/// The caller must already bind `rss.tenant_id`, then commit or roll back its whole transaction.
/// On interruption discard or explicitly roll back the transaction; the returned position is
/// only staged and is not a durable-commit receipt. Source locks remain held until settlement.
/// This operation sets transaction-local statement/lock watchdogs from the remaining budget.
pub async fn append_in_transaction<T: Timer>(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    source: &SourceScope,
    id: &str,
    payload: &[u8],
    control: &Control<'_, T>,
) -> Result<Position, Error> {
    control.check()?;
    let millis = control
        .remaining()
        .as_millis()
        .clamp(1, i32::MAX as u128)
        .to_string();
    control
        .run(async {
            sqlx::query(
                "SELECT set_config('statement_timeout',$1,true),set_config('lock_timeout',$1,true)",
            )
            .bind(millis)
            .execute(&mut **transaction)
            .await
            .map_err(map_sql)?;
            append_connection(transaction, source, id, payload).await
        })
        .await
        .map_err(Error::uncertain)
}
async fn append_connection(
    connection: &mut sqlx::PgConnection,
    source: &SourceScope,
    id: &str,
    payload: &[u8],
) -> Result<Position, Error> {
    let checked = Event::new(source.clone(), Position::new(0)?, id, payload.to_vec())?;
    let position: i64 = sqlx::query_scalar("SELECT rss_projection.append_event($1::uuid,$2,$3,$4)")
        .bind(source.tenant().to_string())
        .bind(source.source())
        .bind(checked.id())
        .bind(checked.payload())
        .fetch_one(connection)
        .await
        .map_err(map_sql)?;
    decode_position(position)
}
impl Source for PgStore {
    async fn high_water(&self, source: &SourceScope) -> Result<Option<Position>, Error> {
        let scope = source.clone();
        self.transact(source.tenant(), Duration::from_secs(30), move |tx| Box::pin(async move {
            let value: Option<i64> = sqlx::query_scalar("SELECT max(position) FROM rss_projection.events WHERE tenant_id=$1::uuid AND source_id=$2")
                .bind(scope.tenant().to_string()).bind(scope.source()).fetch_one(&mut *tx.connection).await.map_err(map_sql)?;
            value.map(decode_position).transpose()
        })).await
    }
    async fn read(
        &self,
        source: &SourceScope,
        after: Option<Position>,
        limit: BatchLimit,
    ) -> Result<Vec<Event>, Error> {
        let scope = source.clone();
        self.transact(source.tenant(), Duration::from_secs(30), move |tx| Box::pin(async move {
            let rows = sqlx::query("SELECT position,event_id,payload FROM rss_projection.events WHERE tenant_id=$1::uuid AND source_id=$2 AND ($3::bigint IS NULL OR position>$3) ORDER BY position LIMIT $4")
                .bind(scope.tenant().to_string()).bind(scope.source()).bind(encode_position(after)).bind(i64::from(limit.get()))
                .fetch_all(&mut *tx.connection).await.map_err(map_sql)?;
            rows.into_iter().map(|row| Event::new(scope.clone(), decode_position(row.try_get("position").map_err(map_sql)?)?, row.try_get::<String,_>("event_id").map_err(map_sql)?, row.try_get("payload").map_err(map_sql)?)).collect()
        })).await
    }
}
pub(crate) fn encode_position(position: Option<Position>) -> Option<i64> {
    position.map(|p| p.get() as i64)
}
pub(crate) fn decode_position(value: i64) -> Result<Position, Error> {
    Position::new(u64::try_from(value).map_err(|_| Error::new(ErrorKind::StorageContract))?)
}
