use crate::{Cursor, Error, Page, ReadLimit, Record, StagedAppend, probe};
use futures::TryStreamExt;
use rss_audit_core::PreparedAuditV1;
use rss_request_context::TenantId;
use sqlx::{PgConnection, Row, postgres::PgRow};

pub(crate) async fn recording_time(c: &mut PgConnection) -> Result<rss_contract::Timepoint, Error> {
    let seconds: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(c)
            .await?;
    rss_contract::Timepoint::try_from(seconds).map_err(|_| Error::StorageContract)
}

/// Shared physical Audit write. The enclosing owner must roll back on any error.
pub(crate) async fn append_batch(
    c: &mut PgConnection,
    tenant: TenantId,
    batch: &crate::append::Batch<'_>,
    ledger: Option<&[(u64, bool)]>,
) -> Result<Vec<StagedAppend>, Error> {
    let count = batch.unique.len();
    if ledger.is_some_and(|entries| entries.len() != count) {
        return Err(Error::StorageContract);
    }
    let mut sources = Vec::with_capacity(count);
    let mut events = Vec::with_capacity(count);
    let mut recorded = Vec::with_capacity(count);
    let mut canonical = Vec::with_capacity(count);
    let mut sequences = Vec::with_capacity(count);
    for (slot, request) in batch.unique.iter().enumerate() {
        sources.push(request.identity().source().source_id().as_str());
        events.push(request.identity().event_id().as_str());
        recorded.push(request.recorded_at().unix_seconds());
        canonical.push(request.canonical_bytes());
        sequences.push(
            ledger
                .map(|entries| i64::try_from(entries[slot].0))
                .transpose()
                .map_err(|_| Error::StorageContract)?,
        );
    }
    let inserted: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT source_id,event_id,position FROM rss_audit.append_batch($1::uuid,$2,$3,$4,$5,$6)",
    )
    .bind(tenant.to_string())
    .bind(sources)
    .bind(events)
    .bind(recorded)
    .bind(canonical)
    .bind(sequences)
    .fetch_all(&mut *c)
    .await?;
    let mut stored = vec![None; count];
    let fresh = inserted.len();
    for (source, event, position) in inserted {
        let slot = batch.slot(&source, &event)?;
        if position < 0 || stored[slot].is_some() {
            return Err(Error::StorageContract);
        }
        stored[slot] = Some((
            Record {
                position,
                prepared: batch.unique[slot].clone(),
                ledger_sequence: ledger.map(|entries| entries[slot].0),
            },
            true,
        ));
    }
    let first_different = if fresh < count {
        read_replays(c, tenant, batch, &mut stored).await?
    } else {
        None
    };
    // Stable first-occurrence order also determines the public semantic error classification.
    for (slot, row) in stored.iter().enumerate() {
        let (record, added) = row.as_ref().ok_or(Error::StorageContract)?;
        if Some(slot) == first_different || record.ledger_sequence.is_some() != ledger.is_some() {
            return Err(Error::Conflict);
        }
        if let (Some(seq), Some(entries)) = (record.ledger_sequence, ledger)
            && entries[slot] != (seq, *added)
        {
            return Err(Error::StorageContract);
        }
    }
    batch.receipts(stored)
}

// A separate READ COMMITTED statement sees the winner after an INSERT waited on its key.
// Stream and validate every historical row before reporting an ordinary replay conflict.
async fn read_replays(
    c: &mut PgConnection,
    tenant: TenantId,
    batch: &crate::append::Batch<'_>,
    stored: &mut [Option<(Record, bool)>],
) -> Result<Option<usize>, Error> {
    let mut sources = Vec::new();
    let mut events = Vec::new();
    let mut lengths = Vec::new();
    for (slot, request) in batch.unique.iter().enumerate() {
        if stored[slot].is_none() {
            sources.push(request.identity().source().source_id().as_str());
            events.push(request.identity().event_id().as_str());
            lengths.push(
                i32::try_from(request.canonical_bytes().len())
                    .map_err(|_| Error::StorageContract)?,
            );
        }
    }
    let mut rows = sqlx::query(include_str!("append_readback.sql"))
        .bind(tenant.to_string())
        .bind(sources)
        .bind(events)
        .bind(lengths)
        .bind(i32::try_from(rss_audit_core::MAX_HEADER_BYTES).map_err(|_| Error::StorageContract)?)
        .fetch(c);
    let mut oversized = false;
    let mut first_different: Option<usize> = None;
    while let Some(row) = rows.try_next().await? {
        let slot = batch.slot(row.try_get("source_id")?, row.try_get("event_id")?)?;
        if stored[slot].is_some() {
            return Err(Error::StorageContract);
        }
        let request = batch.unique[slot];
        let bytes: &[u8] = row.try_get("canonical")?;
        #[cfg(feature = "integration")]
        tracing::trace!(target: "batch_cost::audit_body", bytes = bytes.len() as u64);
        let longer: bool = row.try_get("oversized")?;
        oversized |= longer;
        let same = !longer && bytes == request.canonical_bytes();
        let (position, sequence) = if same {
            coordinates(&row, tenant, request.identity(), request.recorded_at())?
        } else {
            let len = usize::try_from(row.try_get::<i32, _>("stored_bytes")?)
                .map_err(|_| Error::StorageContract)?;
            let (identity, at) = rss_audit_core::inspect_canonical_header(bytes, len)
                .map_err(|_| Error::StorageContract)?;
            coordinates(&row, tenant, &identity, at)?
        };
        if !same {
            first_different = Some(first_different.map_or(slot, |first| first.min(slot)));
        }
        stored[slot] = Some((
            Record {
                position,
                prepared: request.clone(),
                ledger_sequence: sequence,
            },
            false,
        ));
    }
    if stored.iter().any(Option::is_none) {
        return Err(Error::StorageContract);
    }
    if oversized {
        return Err(Error::Conflict);
    }
    Ok(first_different)
}

fn decode(row: &PgRow, tenant: TenantId) -> Result<Record, Error> {
    let bytes: Vec<u8> = row.try_get("canonical")?;
    let prepared =
        PreparedAuditV1::from_canonical_bytes(bytes).map_err(|_| Error::StorageContract)?;
    let (position, ledger_sequence) =
        coordinates(row, tenant, prepared.identity(), prepared.recorded_at())?;
    Ok(Record {
        position,
        prepared,
        ledger_sequence,
    })
}
fn coordinates(
    row: &PgRow,
    tenant: TenantId,
    identity: &rss_audit_core::RecordIdentity,
    at: rss_contract::Timepoint,
) -> Result<(i64, Option<u64>), Error> {
    let position: i64 = row.try_get("position")?;
    if identity.tenant() != tenant
        || row.try_get::<String, _>("tenant_id")? != tenant.to_string()
        || row.try_get::<&str, _>("source_id")? != identity.source().source_id().as_str()
        || row.try_get::<&str, _>("event_id")? != identity.event_id().as_str()
        || row.try_get::<i64, _>("recorded_at")? != at.unix_seconds()
        || position < 0
    {
        return Err(Error::StorageContract);
    }
    let ledger_sequence = row
        .try_get::<Option<i64>, _>("ledger_sequence")?
        .map(u64::try_from)
        .transpose()
        .map_err(|_| Error::StorageContract)?;
    Ok((position, ledger_sequence))
}

pub(crate) async fn page(
    c: &mut PgConnection,
    cursor: Cursor,
    limit: ReadLimit,
) -> Result<Page, Error> {
    probe::tenant(c, cursor.tenant()).await?;
    // Metadata first, in the very same statement snapshot as the payload. An over-budget
    // candidate never sends canonical bytes to SQLx, even when a single row is too large.
    let rows = sqlx::query(include_str!("page.sql"))
        .bind(cursor.tenant().to_string())
        .bind(cursor.after)
        .bind(limit.rows)
        .bind(limit.bytes)
        .bind(cursor.through)
        .fetch_all(c)
        .await?;
    let mut through = -1_i64;
    let mut has_more = false;
    let mut records = Vec::new();
    let mut bytes = 0_i64;
    for row in rows {
        match row.try_get::<i32, _>("status")? {
            0 => {}
            1 => return Err(Error::ReadBudgetExceeded),
            3 => return Err(Error::InvalidBound),
            _ => return Err(Error::StorageContract),
        }
        through = row.try_get("through")?;
        has_more = row.try_get("has_more")?;
        if row.try_get::<Option<i64>, _>("position")?.is_none() {
            continue;
        }
        let record = decode(&row, cursor.tenant())?;
        bytes = bytes
            .checked_add(
                i64::try_from(record.prepared.canonical_bytes().len())
                    .map_err(|_| Error::StorageContract)?,
            )
            .ok_or(Error::StorageContract)?;
        if bytes > limit.bytes || records.len() >= limit.rows as usize {
            return Err(Error::StorageContract);
        }
        records.push(record);
    }
    let next = records
        .last()
        .filter(|_| has_more)
        .map(|r| Cursor::resume(cursor.tenant(), r.position(), through as u64))
        .transpose()?;
    Ok(Page { records, next })
}
