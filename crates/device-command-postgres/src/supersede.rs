//! Page active commands under the authority lock held by the caller's transaction.
use crate::{
    CommandClock,
    persistence::PageChanges,
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
    let mut changes = PageChanges::default();
    for row in rows {
        let now = match clock {
            CommandClock::Postgres => row.try_get("command_time")?,
            #[cfg(feature = "integration")]
            CommandClock::Controlled(frozen) => frozen.now(),
        };
        let mut command = decode(row)?.command;
        let previous = command.version();
        if command
            .transition(Event::Supersede, next, now)
            .map_err(error)?
            != Outcome::Advanced
        {
            return Err(error(Error::InvalidSnapshot));
        }
        changes.push(&command, previous);
    }
    let last = changes
        .ids
        .last()
        .cloned()
        .ok_or_else(|| error(Error::InvalidSnapshot))?;
    changes.save(tx, scope).await?;
    Ok(last)
}
