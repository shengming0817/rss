use crate::budget::{FIXED_BIND, ROW_FRAMING};
use crate::{Control, Error};
use rss_audit_core::{DecodedAuditWindow, EventId, MAX_RECORD_BYTES, SourceId};
use rss_request_context::{ExecutionTimer, TenantId};
use rss_transactional_messaging::transaction::LocalTxDeadlineStage;
use sqlx::PgConnection;

const MAX_ROWS: usize = 32;
const MAX_BIND_BYTES: usize = 1 << 20;
// The first validated Audit record always fits, even with both maximal IDs.
const _: () = assert!(
    FIXED_BIND + ROW_FRAMING + MAX_RECORD_BYTES + SourceId::MAX_BYTES + EventId::MAX_BYTES
        <= MAX_BIND_BYTES
);

pub(crate) async fn check_associations(
    connection: &mut PgConnection,
    control: &Control<'_, impl ExecutionTimer>,
    tenant: TenantId,
    audit: &DecodedAuditWindow<'_>,
) -> Result<(), Error> {
    let tenant = tenant.to_string();
    let mut records = audit.decoded().peekable();
    while records.peek().is_some() {
        let mut bytes = FIXED_BIND;
        let mut sequences = Vec::new();
        let mut sources = Vec::new();
        let mut events = Vec::new();
        let mut recorded = Vec::new();
        let mut canonical = Vec::new();
        while sequences.len() < MAX_ROWS {
            let Some(&(entry, record)) = records.peek() else {
                break;
            };
            let source = record.event().identity().source().source_id().as_str();
            let event = record.event().identity().event_id().as_str();
            bytes += ROW_FRAMING + source.len() + event.len() + entry.payload().len();
            if bytes > MAX_BIND_BYTES {
                break;
            }
            sequences
                .push(i64::try_from(entry.sequence().get()).map_err(|_| Error::StorageContract)?);
            sources.push(source);
            events.push(event);
            recorded.push(record.recorded_at().unix_seconds());
            canonical.push(entry.payload());
            records.next();
        }
        // Compare the already-authenticated bytes even across READ COMMITTED statement snapshots.
        control.check(LocalTxDeadlineStage::Operation)?;
        let matches: bool = sqlx::query_scalar(
            "SELECT NOT EXISTS (
                SELECT FROM unnest($2::bigint[], $3::text[], $4::text[], $5::bigint[], $6::bytea[])
                    AS e(seq, source, event, recorded, canonical)
                WHERE NOT EXISTS (
                    SELECT FROM rss_audit.records r
                    WHERE r.tenant_id=$1::uuid AND r.ledger_sequence=e.seq
                      AND r.source_id=e.source AND r.event_id=e.event
                      AND r.recorded_at=e.recorded AND r.canonical=e.canonical
                )
            )",
        )
        .bind(&tenant)
        .bind(sequences)
        .bind(sources)
        .bind(events)
        .bind(recorded)
        .bind(canonical)
        .fetch_one(&mut *connection)
        .await?;
        if !matches {
            return Err(Error::StorageContract);
        }
    }
    Ok(audit.check_complete()?)
}
