//! SQL projection of core-owned state; no transition decisions are duplicated here.
use rss_device_command::*;
use rss_transactional_messaging::{
    error::MessagingErrorKind,
    message::{MessageFingerprint, MessageId, MessagingDomain},
};
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
use sqlx::{Row, postgres::PgRow};

pub(crate) fn error(value: Error) -> PgError {
    let kind = match value {
        Error::Fenced => MessagingErrorKind::OwnershipLost,
        Error::Conflict => MessagingErrorKind::Conflict,
        Error::InvalidValue | Error::DeadlineElapsed => MessagingErrorKind::Permanent,
        _ => MessagingErrorKind::Invariant,
    };
    PgError::Operation {
        kind,
        source: rss_redact::RedactedSource::new(value),
    }
}
pub(crate) fn scope(tx: &PgTransaction<'_>, s: Scope) -> Result<(), PgError> {
    if tx.tenant_id() != s.tenant() {
        return Err(error(Error::Fenced));
    }
    Ok(())
}
pub(crate) async fn now(tx: &mut PgTransaction<'_>) -> Result<i64, PgError> {
    tx.with_connection(|c| {
        Box::pin(async move {
            sqlx::query_scalar(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000000)::bigint",
            )
            .fetch_one(c)
            .await
        })
    })
    .await
}
pub(crate) async fn authority(tx: &mut PgTransaction<'_>, s: Scope) -> Result<Coordinate, PgError> {
    scope(tx, s)?;
    let t = s.tenant().to_string();
    let d = s.device().as_uuid().to_string();
    let r=tx.with_connection(move |c|Box::pin(async move {
        sqlx::query("SELECT generation,authority_epoch FROM rss_device_command.lock_authority($1::uuid,$2::uuid)").bind(t).bind(d).fetch_optional(c).await
    })).await?.ok_or_else(||error(Error::Fenced))?;
    Coordinate::new(r.try_get("generation")?, r.try_get("authority_epoch")?).map_err(error)
}
pub(crate) struct Stored {
    pub command: Command,
    pub message_id: MessageId,
    pub fingerprint: MessageFingerprint,
    pub domain: MessagingDomain,
}
pub(crate) fn decode(row: PgRow) -> Result<Stored, PgError> {
    let bad = || error(Error::InvalidSnapshot);
    let tenant = rss_request_context::TenantId::parse(&row.try_get::<String, _>("tenant")?)
        .map_err(|_| bad())?;
    let device = DeviceId::parse(&row.try_get::<String, _>("device")?).map_err(error)?;
    let spec = CommandSpec::new(
        Scope::new(tenant, device),
        CommandId::parse(&row.try_get::<String, _>("command_id")?).map_err(error)?,
        Coordinate::new(row.try_get("generation")?, row.try_get("authority_epoch")?)
            .map_err(error)?,
        StateDigest::from_bytes(
            row.try_get::<Vec<u8>, _>("expected_digest")?
                .try_into()
                .map_err(|_| bad())?,
        ),
        row.try_get("deadline")?,
    );
    let command = Command::restore(Record {
        spec,
        version: row.try_get("version")?,
        status: Status::restore(&row.try_get::<String, _>("status")?).map_err(error)?,
        queued_at: row.try_get("queued_at")?,
        published_at: row.try_get("published_at")?,
        received_at: row.try_get("received_at")?,
        terminal_at: row.try_get("terminal_at")?,
    })
    .map_err(error)?;
    let message_id =
        MessageId::parse(&row.try_get::<String, _>("outbox_message_id")?).map_err(|_| bad())?;
    let fingerprint = MessageFingerprint::from_bytes(
        row.try_get::<Vec<u8>, _>("outbox_fingerprint")?
            .try_into()
            .map_err(|_| bad())?,
    );
    let domain =
        MessagingDomain::parse(&row.try_get::<String, _>("outbox_domain")?).map_err(|_| bad())?;
    Ok(Stored {
        domain,
        command,
        message_id,
        fingerprint,
    })
}
pub(crate) async fn read(
    tx: &mut PgTransaction<'_>,
    s: Scope,
    id: &CommandId,
) -> Result<Option<Stored>, PgError> {
    scope(tx, s)?;
    let t = s.tenant().to_string();
    let id = id.as_str().to_owned();
    let r=tx.with_connection(move |c|Box::pin(async move {
        sqlx::query("SELECT *,tenant_id::text AS tenant,device_id::text AS device FROM rss_device_command.commands WHERE tenant_id=$1::uuid AND command_id=$2").bind(t).bind(id).fetch_optional(c).await
    })).await?.map(decode).transpose()?;
    if r.as_ref().is_some_and(|r| r.command.spec().scope() != s) {
        return Err(error(Error::Fenced));
    }
    Ok(r)
}
pub(crate) async fn save(
    tx: &mut PgTransaction<'_>,
    command: &Command,
    previous: i64,
) -> Result<(), PgError> {
    if command.version() == previous {
        return Ok(());
    } // reason: duplicates preserve the exact persisted snapshot.
    let r = command.record();
    let t = r.spec.scope().tenant().to_string();
    let d = r.spec.scope().device().as_uuid().to_string();
    let id = r.spec.id().as_str().to_owned();
    let status = r.status.as_str();
    let published = r.published_at;
    let received = r.received_at;
    let terminal = r.terminal_at;
    let changed: bool = tx
        .with_connection(move |c| {
            Box::pin(async move {
                sqlx::query_scalar(
                    "SELECT rss_device_command.save($1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8)",
                )
                .bind(t)
                .bind(d)
                .bind(id)
                .bind(previous)
                .bind(status)
                .bind(published)
                .bind(received)
                .bind(terminal)
                .fetch_one(c)
                .await
            })
        })
        .await?;
    if !changed {
        return Err(error(Error::Fenced));
    }
    Ok(())
}
pub(crate) async fn page(
    tx: &mut PgTransaction<'_>,
    s: Scope,
    after: Option<&CommandId>,
    limit: i64,
) -> Result<Vec<Stored>, PgError> {
    scope(tx, s)?;
    let t = s.tenant().to_string();
    let d = s.device().as_uuid().to_string();
    let after = after.map(|id| id.as_str().to_owned());
    let rows=tx.with_connection(move |c|Box::pin(async move {
        sqlx::query("SELECT *,tenant_id::text AS tenant,device_id::text AS device FROM rss_device_command.commands WHERE tenant_id=$1::uuid AND device_id=$2::uuid AND terminal_at IS NULL AND ($3::text IS NULL OR command_id COLLATE \"C\">$3 COLLATE \"C\") ORDER BY command_id COLLATE \"C\" LIMIT $4").bind(t).bind(d).bind(after).bind(limit).fetch_all(c).await
    })).await?;
    rows.into_iter().map(decode).collect()
}
