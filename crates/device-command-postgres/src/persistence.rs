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
pub(crate) async fn authority(
    tx: &mut PgTransaction<'_>,
    s: Scope,
    exclusive: bool,
) -> Result<Coordinate, PgError> {
    scope(tx, s)?;
    let t = s.tenant().to_string();
    let d = s.device().as_uuid().to_string();
    let r=tx.with_connection(move |c|Box::pin(async move {
        let query = if exclusive {
            sqlx::query("SELECT generation,authority_epoch FROM rss_device_command.lock_authority_exclusive($1::uuid,$2::uuid)")
        } else {
            sqlx::query("SELECT generation,authority_epoch FROM rss_device_command.lock_authority($1::uuid,$2::uuid)")
        };
        query.bind(t).bind(d).fetch_optional(c).await
    })).await?.ok_or_else(||error(Error::Fenced))?;
    Coordinate::new(r.try_get("generation")?, r.try_get("authority_epoch")?).map_err(error)
}
pub(crate) fn decode(row: PgRow) -> Result<Command, PgError> {
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
    let content: Option<Vec<u8>> = row.try_get("content_digest")?;
    let delivery = match content {
        Some(bytes) => Delivery::Direct {
            content_digest: ContentDigest::from_bytes(bytes.try_into().map_err(|_| bad())?),
        },
        None => Delivery::Outbox(OutboxIdentity {
            message_id: MessageId::parse(row.try_get("outbox_message_id")?).map_err(|_| bad())?,
            domain: MessagingDomain::parse(row.try_get("outbox_domain")?).map_err(|_| bad())?,
            fingerprint: MessageFingerprint::from_bytes(
                row.try_get::<Vec<u8>, _>("outbox_fingerprint")?
                    .try_into()
                    .map_err(|_| bad())?,
            ),
        }),
    };
    Command::restore(Record {
        spec,
        delivery,
        claim_id: row
            .try_get::<Option<&str>, _>("issuance")?
            .map(ClaimId::parse)
            .transpose()
            .map_err(|_| bad())?,
        version: row.try_get("version")?,
        status: Status::restore(row.try_get("status")?).map_err(error)?,
        queued_at: row.try_get("queued_at")?,
        dispatched_at: row.try_get("dispatched_at")?,
        received_at: row.try_get("received_at")?,
        terminal_at: row.try_get("terminal_at")?,
    })
    .map_err(error)
}
// The tenant predicate and RLS select the tenant. Fence the device before decoding
// command facts so even a malformed foreign snapshot yields the same ownership error.
fn decode_for_device(row: PgRow, device: &str) -> Result<Command, PgError> {
    if row.try_get::<&str, _>("device")? != device {
        return Err(error(Error::Fenced));
    }
    decode(row)
}
pub(crate) async fn read(
    tx: &mut PgTransaction<'_>,
    s: Scope,
    id: &CommandId,
) -> Result<Option<Command>, PgError> {
    scope(tx, s)?;
    let t = s.tenant().to_string();
    let id = id.as_str().to_owned();
    let device = s.device().as_uuid().to_string();
    tx.with_connection(move |c|Box::pin(async move {
        sqlx::query("SELECT *,claim_id::text AS issuance,tenant_id::text AS tenant,device_id::text AS device FROM rss_device_command.commands WHERE tenant_id=$1::uuid AND command_id=$2").bind(t).bind(id).fetch_optional(c).await
    })).await?.map(|row| decode_for_device(row, &device)).transpose()
}
pub(crate) async fn locked_command(
    tx: &mut PgTransaction<'_>,
    s: Scope,
    id: &CommandId,
) -> Result<Command, PgError> {
    scope(tx, s)?;
    let tenant = s.tenant().to_string();
    let device = s.device().as_uuid().to_string();
    let id = id.as_str().to_owned();
    let row=tx.with_connection(move |c| Box::pin(async move {
        sqlx::query("SELECT *,claim_id::text AS issuance,tenant_id::text AS tenant,device_id::text AS device FROM rss_device_command.lock_command($1::uuid,$2::uuid,$3)")
            .bind(tenant).bind(device).bind(id).fetch_optional(c).await
    })).await?.ok_or_else(||error(Error::Fenced))?;
    decode(row)
}

// A command row does not yet exist for a first create. Serialize only that tenant-local
// identity, then read under a fresh statement snapshot before evaluating replay or expiry.
pub(crate) async fn lock_creation(
    tx: &mut PgTransaction<'_>,
    spec: &CommandSpec,
) -> Result<(), PgError> {
    let tenant = spec.scope().tenant().to_string();
    let id = spec.id().as_str().to_owned();
    tx.with_connection(move |c| Box::pin(async move {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('rss-device-command:' || $1::text || ':' || $2::text,0))")
            .bind(tenant).bind(id).execute(c).await.map(|_|())
    })).await
}

pub(crate) async fn exact_rows(
    tx: &mut PgTransaction<'_>,
    scope: Scope,
    ids: ExactCommandIds<'_>,
) -> Result<Vec<Option<Command>>, PgError> {
    if ids.as_slice().is_empty() {
        return Ok(Vec::new());
    }
    let tenant = scope.tenant().to_string();
    let requested: Vec<_> = ids
        .as_slice()
        .iter()
        .map(|id| id.as_str().to_owned())
        .collect();
    let rows = tx.with_connection(move |c| Box::pin(async move {
        // Look up tenant-local identities before checking device ownership. Filtering by
        // device here would turn an out-of-scope identity into an absent command.
        sqlx::query("SELECT cmd.*, cmd.claim_id::text AS issuance, cmd.tenant_id::text AS tenant, cmd.device_id::text AS device
            FROM unnest($2::text[]) WITH ORDINALITY AS requested(id, position)
            LEFT JOIN rss_device_command.commands cmd ON cmd.tenant_id=$1::uuid AND cmd.command_id=requested.id
            ORDER BY requested.position")
            .bind(tenant).bind(requested).fetch_all(c).await
    })).await?;
    let device = scope.device().as_uuid().to_string();
    rows.into_iter()
        .map(|row| {
            if row.try_get::<Option<&str>, _>("command_id")?.is_none() {
                return Ok(None);
            }
            decode_for_device(row, &device).map(Some)
        })
        .collect()
}
pub(crate) async fn insert_command(
    tx: &mut PgTransaction<'_>,
    command: &Command,
) -> Result<(), PgError> {
    let record = command.record();
    let spec = &record.spec;
    let tenant = spec.scope().tenant().to_string();
    let device = spec.scope().device().as_uuid().to_string();
    let id = spec.id().as_str().to_owned();
    let coordinate = spec.coordinate();
    let digest = spec.expected().as_bytes().to_vec();
    let deadline = spec.deadline();
    let queued = record.queued_at;
    let (domain, message, fingerprint, content) = match &record.delivery {
        Delivery::Outbox(facts) => (
            Some(facts.domain.as_str().to_owned()),
            Some(facts.message_id.as_str().to_owned()),
            Some(facts.fingerprint.as_bytes().to_vec()),
            None,
        ),
        Delivery::Direct { content_digest } => {
            (None, None, None, Some(content_digest.as_bytes().to_vec()))
        }
    };
    tx.with_connection(move |c| Box::pin(async move {
        sqlx::query("SELECT rss_device_command.enqueue($1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)")
            .bind(tenant).bind(device).bind(id).bind(coordinate.generation()).bind(coordinate.epoch())
            .bind(digest).bind(deadline).bind(queued).bind(message).bind(fingerprint).bind(domain).bind(content)
            .execute(c).await.map(|_|())
    })).await
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
    let dispatched = r.dispatched_at;
    let received = r.received_at;
    let terminal = r.terminal_at;
    let issuance = r.claim_id.map(|id| id.as_uuid().to_string());
    let changed: bool = tx
        .with_connection(move |c| {
            Box::pin(async move {
                sqlx::query_scalar(
                    "SELECT rss_device_command.save($1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8,$9::uuid)",
                )
                .bind(t)
                .bind(d)
                .bind(id)
                .bind(previous)
                .bind(status)
                .bind(dispatched)
                .bind(received)
                .bind(terminal)
                .bind(issuance)
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
pub(crate) async fn active_rows(
    tx: &mut PgTransaction<'_>,
    s: Scope,
    after: Option<&str>,
    limit: BatchLimit,
    sample_time: bool,
) -> Result<Vec<PgRow>, PgError> {
    scope(tx, s)?;
    let t = s.tenant().to_string();
    let d = s.device().as_uuid().to_string();
    let after = after.map(str::to_owned);
    tx.with_connection(move |c| Box::pin(async move {
        macro_rules! active_page {
            ($cursor:literal) => { concat!(
                r#"SELECT *,claim_id::text AS issuance,tenant_id::text AS tenant,device_id::text AS device,
                    CASE WHEN $4 THEN floor(extract(epoch FROM clock_timestamp())*1000000)::bigint END AS command_time
                   FROM rss_device_command.commands
                   WHERE tenant_id=$1::uuid AND device_id=$2::uuid AND terminal_at IS NULL "#,
                $cursor, r#" ORDER BY command_id COLLATE "C" LIMIT $3"#)
            };
        }
        let query = match after {
            Some(id) => sqlx::query(active_page!(r#"AND command_id COLLATE "C" > $5 COLLATE "C""#))
                .bind(t).bind(d).bind(i64::from(limit.get())).bind(sample_time).bind(id),
            None => sqlx::query(active_page!(""))
                .bind(t).bind(d).bind(i64::from(limit.get())).bind(sample_time),
        };
        query.fetch_all(c).await
    })).await
}

/// Only changed records cross the SQL boundary. PostgreSQL rejects a partial page.
#[derive(Default)]
pub(crate) struct PageChanges {
    pub(crate) ids: Vec<String>,
    versions: Vec<i64>,
    statuses: Vec<&'static str>,
    dispatched: Vec<Option<i64>>,
    received: Vec<Option<i64>>,
    terminal: Vec<Option<i64>>,
}

impl PageChanges {
    pub(crate) fn push(&mut self, command: &Command, previous: i64) {
        if command.version() == previous {
            return;
        }
        let record = command.record();
        self.ids.push(record.spec.id().as_str().to_owned());
        self.versions.push(previous);
        self.statuses.push(record.status.as_str());
        self.dispatched.push(record.dispatched_at);
        self.received.push(record.received_at);
        self.terminal.push(record.terminal_at);
    }
    pub(crate) async fn save(
        self,
        tx: &mut PgTransaction<'_>,
        scope: Scope,
    ) -> Result<(), PgError> {
        if self.ids.is_empty() {
            return Ok(());
        }
        tx.with_connection(move |c| {
            Box::pin(async move {
                sqlx::query(
                    "SELECT rss_device_command.save_page($1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8)",
                )
                .bind(scope.tenant().to_string())
                .bind(scope.device().as_uuid().to_string())
                .bind(self.ids)
                .bind(self.versions)
                .bind(self.statuses)
                .bind(self.dispatched)
                .bind(self.received)
                .bind(self.terminal)
                .execute(c)
                .await
                .map(|_| ())
            })
        })
        .await
    }
}
