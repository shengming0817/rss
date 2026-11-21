//! Page active commands under the authority lock held by the caller's transaction.
use crate::{
    CommandClock,
    persistence::{active_rows, decode, error},
};
use rss_device_command::{BatchLimit, Coordinate, Error, Event, Outcome, Scope};
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
use sqlx::{Row, postgres::PgRow};

pub(crate) async fn active_commands(
    tx: &mut PgTransaction<'_>,
    scope: Scope,
    next: Coordinate,
    limit: BatchLimit,
    clock: &CommandClock,
) -> Result<(), PgError> {
    let mut after = None;
    loop {
        let rows = active_rows(
            tx,
            scope,
            after.as_deref(),
            limit,
            matches!(clock, CommandClock::Postgres),
        )
        .await?;
        if rows.is_empty() {
            return Ok(());
        }
        let full = rows.len() == usize::from(limit.get());
        let last = save_page(tx, scope, next, rows, clock).await?;
        if !full {
            return Ok(());
        }
        after = Some(last);
    }
}

async fn save_page(
    tx: &mut PgTransaction<'_>,
    scope: Scope,
    next: Coordinate,
    rows: Vec<PgRow>,
    clock: &CommandClock,
) -> Result<String, PgError> {
    let count = rows.len();
    let mut ids = Vec::with_capacity(count);
    let mut versions = Vec::with_capacity(count);
    let mut published = Vec::with_capacity(count);
    let mut received = Vec::with_capacity(count);
    let mut terminal = Vec::with_capacity(count);
    for row in rows {
        let now = match clock {
            CommandClock::Postgres => row.try_get("command_time")?,
            #[cfg(feature = "integration")]
            CommandClock::Controlled(frozen) => frozen.now(),
        };
        let mut command = decode(row)?.command;
        versions.push(command.version());
        if command
            .transition(Event::Supersede, next, now)
            .map_err(error)?
            != Outcome::Advanced
        {
            return Err(error(Error::InvalidSnapshot));
        }
        let record = command.record();
        ids.push(record.spec.id().as_str().to_owned());
        published.push(record.published_at);
        received.push(record.received_at);
        terminal.push(record.terminal_at);
    }
    let last = ids
        .last()
        .cloned()
        .ok_or_else(|| error(Error::InvalidSnapshot))?;
    let changed: i64 = tx
        .with_connection(move |c| {
            Box::pin(async move {
                sqlx::query_scalar(
                    "SELECT count(*) FILTER (WHERE rss_device_command.save(
                    $1::uuid,$2::uuid,id,version,'superseded',published,received,terminal))
                FROM unnest($3::text[], $4::bigint[], $5::bigint[], $6::bigint[], $7::bigint[])
                     AS batch(id,version,published,received,terminal)",
                )
                .bind(scope.tenant().to_string())
                .bind(scope.device().as_uuid().to_string())
                .bind(ids)
                .bind(versions)
                .bind(published)
                .bind(received)
                .bind(terminal)
                .fetch_one(c)
                .await
            })
        })
        .await?;
    if usize::try_from(changed) != Ok(count) {
        return Err(error(Error::Fenced));
    }
    Ok(last)
}
