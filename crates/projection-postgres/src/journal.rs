use crate::{
    PgOperationError, PgStore, PgTransaction,
    transaction::{map_sql, watchdog},
};
use futures::TryStreamExt;
use rss_projection::{
    Control, Error, ErrorKind, Event, PageBudget, Position, ReadPage, Source, SourceScope, Timer,
};
use sqlx::Row;

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
        self.check().map_err(PgOperationError)?;
        if self.tenant() != source.tenant() {
            return Err(PgOperationError(Error::new(ErrorKind::ScopeMismatch)));
        }
        let result = append_connection(self.connection, source, id, payload).await;
        self.check().map_err(PgOperationError)?;
        result.map_err(PgOperationError)
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
    let millis = watchdog(control.remaining())?.to_string();
    control
        .run(async {
            sqlx::query(
                "SELECT set_config('statement_timeout',$1,true),set_config('lock_timeout',$1,true)",
            )
            .bind(millis)
            .execute(&mut **transaction)
            .await
            .map_err(map_sql)?;
            control.check()?;
            let result = append_connection(transaction, source, id, payload).await;
            control.check()?;
            result
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
    type Item = rss_projection::Event;
    async fn high_water<T: Timer>(
        &self,
        source: &SourceScope,
        control: &Control<'_, T>,
    ) -> Result<Option<Position>, Error> {
        let scope = source.clone();
        self.controlled_read(source, control, move |tx| Box::pin(async move {
            let value: Option<i64> = sqlx::query_scalar("SELECT max(position) FROM rss_projection.events WHERE tenant_id=$1::uuid AND source_id=$2")
                .bind(scope.tenant().to_string()).bind(scope.source()).fetch_one(&mut *tx.connection).await.map_err(map_sql)?;
            value.map(decode_position).transpose()
        })).await
    }
    async fn read<T: Timer>(
        &self,
        source: &SourceScope,
        after: Option<Position>,
        budget: PageBudget,
        control: &Control<'_, T>,
    ) -> Result<ReadPage<Event>, Error> {
        let scope = source.clone();
        self.controlled_read(source, control, move |tx| {
            Box::pin(async move {
                let check = tx.check;
                let mut rows = sqlx::query(include_str!("journal_page.sql"))
                    .bind(scope.tenant().to_string())
                    .bind(scope.source())
                    .bind(encode_position(after).unwrap_or(-1))
                    .bind(i64::from(budget.rows()))
                    .bind(i64::from(budget.payload_bytes()))
                    .fetch(&mut *tx.connection);
                let mut events = Vec::new();
                while let Some(row) = rows.try_next().await.map_err(map_sql)? {
                    check()?;
                    let position = decode_position(row.try_get("position").map_err(map_sql)?)?;
                    let size: i32 = row.try_get("size").map_err(map_sql)?;
                    let required_bytes =
                        u32::try_from(size).map_err(|_| Error::new(ErrorKind::StorageContract))?;
                    if required_bytes > budget.payload_bytes() {
                        return Ok(ReadPage::Blocked {
                            position,
                            required_bytes,
                        });
                    }
                    events.push(Event::new(
                        scope.clone(),
                        position,
                        row.try_get::<String, _>("event_id").map_err(map_sql)?,
                        row.try_get("payload").map_err(map_sql)?,
                    )?);
                    check()?;
                    tokio::task::yield_now().await;
                }
                Ok(ReadPage::Events(events))
            })
        })
        .await
    }
}
pub(crate) fn encode_position(position: Option<Position>) -> Option<i64> {
    position.map(|p| p.get() as i64)
}
pub(crate) fn decode_position(value: i64) -> Result<Position, Error> {
    Position::new(u64::try_from(value).map_err(|_| Error::new(ErrorKind::StorageContract))?)
}
