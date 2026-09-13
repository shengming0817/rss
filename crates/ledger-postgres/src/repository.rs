use crate::{Error, error::sql_error};
use futures::TryStreamExt;
use rss_ledger::*;
use sqlx::{PgConnection, Row, postgres::PgRow};

const WINDOW_SQL: &str = include_str!("window.sql");

/// Checked conversion to the provider's signed storage range.
pub(crate) fn encode_sequence(value: Sequence) -> Result<i64, Error> {
    i64::try_from(value.get()).map_err(|_| rss_ledger::Error::SequenceExhausted.into())
}
/// Reject negative durable sequences rather than wrapping them.
pub(crate) fn decode_sequence(value: i64) -> Result<Sequence, Error> {
    Ok(Sequence::new(
        u64::try_from(value).map_err(|_| Error::StorageContract)?,
    ))
}
/// Required record-count and complete encoded-byte bounds for one snapshot window.
/// The byte charge includes the predecessor; the record count excludes it.
#[derive(Debug, Clone, Copy)]
pub struct ReadLimit {
    records: u16,
    encoded_bytes: i64,
}
impl ReadLimit {
    /// Accept 1..=1024 records and 1..=i64::MAX encoded bytes. Neither budget has a default.
    pub fn new(records: u16, max_encoded_bytes: u64) -> Result<Self, Error> {
        let encoded_bytes =
            i64::try_from(max_encoded_bytes).map_err(|_| rss_ledger::Error::InvalidInput)?;
        if !(1..=1024).contains(&records) || encoded_bytes == 0 {
            return Err(rss_ledger::Error::InvalidInput.into());
        }
        Ok(Self {
            records,
            encoded_bytes,
        })
    }
}
/// A record staged in a borrowed transaction, never a durable commit receipt.
#[derive(Debug)]
pub struct StagedAppend {
    entry: Entry,
    inserted: bool,
}
impl StagedAppend {
    /// Staged record, including its stable recovery identity.
    pub const fn entry(&self) -> &Entry {
        &self.entry
    }
    /// Whether this attempt inserted rather than replayed the original record.
    pub const fn inserted(&self) -> bool {
        self.inserted
    }
}
/// One verified database snapshot page. Its anchor has the same trust origin as the database.
#[derive(Debug)]
pub struct Window {
    predecessor: Option<Entry>,
    entries: Vec<Entry>,
    observed_tail: Option<Sequence>,
}
impl Window {
    /// Immediately preceding record, absent only at genesis.
    pub const fn predecessor(&self) -> Option<&Entry> {
        self.predecessor.as_ref()
    }
    /// Contiguous verified entries.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }
    /// Tail observed in the same snapshot, not an external anti-truncation checkpoint.
    pub const fn observed_tail(&self) -> Option<Sequence> {
        self.observed_tail
    }
}
pub(crate) async fn append(
    connection: &mut PgConnection,
    auth: &Authenticator,
    request: &AppendRequest,
) -> Result<StagedAppend, Error> {
    let ledger = request.ledger();
    sqlx::query("SELECT rss_ledger.prepare_append($1::uuid,$2,$3,1::smallint)")
        .bind(ledger.tenant().to_string())
        .bind(ledger.chain().as_str())
        .bind(auth.key_id().as_str())
        .execute(&mut *connection)
        .await
        .map_err(sql_error)?;
    let head = sqlx::query(
        "SELECT seq,tag FROM rss_ledger.heads WHERE tenant_id=$1::uuid AND chain_id=$2",
    )
    .bind(ledger.tenant().to_string())
    .bind(ledger.chain().as_str())
    .fetch_one(&mut *connection)
    .await
    .map_err(sql_error)?;
    let seq: Option<i64> = head.try_get("seq").map_err(sql_error)?;
    let previous = match seq {
        Some(seq) => {
            let row=sqlx::query("SELECT *,tenant_id::text AS tenant_text FROM rss_ledger.entries WHERE tenant_id=$1::uuid AND chain_id=$2 AND seq=$3")
                .bind(ledger.tenant().to_string()).bind(ledger.chain().as_str()).bind(seq)
                .fetch_optional(&mut *connection).await.map_err(sql_error)?.ok_or(Error::StorageContract)?;
            let entry = decode(row)?;
            auth.verify(&entry)?;
            let tag: Vec<u8> = head.try_get("tag").map_err(sql_error)?;
            if tag != entry.tag().as_bytes() {
                return Err(Error::StorageContract);
            }
            Some(entry)
        }
        None => None,
    };
    if let Some(existing) = find(connection, auth, ledger, request.record_id()).await? {
        if !existing.matches(request) {
            return Err(Error::Conflict);
        }
        if previous
            .as_ref()
            .is_none_or(|p| existing.sequence() > p.sequence())
        {
            return Err(Error::StorageContract);
        }
        return Ok(StagedAppend {
            entry: existing,
            inserted: false,
        });
    }
    let entry = auth.append(request, previous.as_ref())?;
    sqlx::query("SELECT rss_ledger.insert_entry($1::uuid,$2,$3,$4,$5,$6,$7,$8,1::smallint)")
        .bind(ledger.tenant().to_string())
        .bind(ledger.chain().as_str())
        .bind(entry.record_id().as_str())
        .bind(encode_sequence(entry.sequence())?)
        .bind(entry.previous_tag().as_bytes().as_slice())
        .bind(entry.tag().as_bytes().as_slice())
        .bind(entry.payload())
        .bind(entry.key_id().as_str())
        .execute(connection)
        .await
        .map_err(sql_error)?;
    Ok(StagedAppend {
        entry,
        inserted: true,
    })
}
pub(crate) async fn find(
    connection: &mut PgConnection,
    auth: &Authenticator,
    ledger: &LedgerId,
    id: &RecordId,
) -> Result<Option<Entry>, Error> {
    let row=sqlx::query("SELECT *,tenant_id::text AS tenant_text FROM rss_ledger.entries WHERE tenant_id=$1::uuid AND chain_id=$2 AND record_id=$3")
        .bind(ledger.tenant().to_string()).bind(ledger.chain().as_str()).bind(id.as_str())
        .fetch_optional(connection).await.map_err(sql_error)?;
    row.map(|row| {
        let e = decode(row)?;
        auth.verify(&e)?;
        Ok(e)
    })
    .transpose()
}
pub(crate) async fn window(
    connection: &mut PgConnection,
    auth: &Authenticator,
    ledger: &LedgerId,
    start: Sequence,
    limit: ReadLimit,
) -> Result<Window, Error> {
    // SQL admits the complete encoded result before any payload reaches SQLx. Streaming alone
    // cannot do that: SQLx yields only after receiving a complete DataRow.
    // ref: launchbadge/sqlx sqlx-postgres/src/connection/executor.rs@75bc0487eb661da811bb7a3c5d158f1bd463fef4
    let start_sql = encode_sequence(start)?;
    let end = start_sql
        .checked_add(i64::from(limit.records) - 1)
        .unwrap_or(i64::MAX);
    let mut rows = sqlx::query(WINDOW_SQL)
        .bind(ledger.tenant().to_string())
        .bind(ledger.chain().as_str())
        .bind(start_sql)
        .bind(end)
        .bind(limit.encoded_bytes)
        .bind(auth.key_id().as_str())
        .bind(i64::try_from(V1_ENTRY_FIXED_BYTES).map_err(|_| Error::StorageContract)?)
        .bind(i64::try_from(MAX_PAYLOAD_BYTES).map_err(|_| Error::StorageContract)?)
        .fetch(connection);
    let mut header = None;
    let mut entries = Vec::new();
    while let Some(row) = rows.try_next().await.map_err(sql_error)? {
        if row.try_get::<bool, _>("header").map_err(sql_error)? {
            if header.is_some() {
                return Err(Error::StorageContract);
            }
            header = Some(read_header(&row)?);
        } else {
            if entries.len() >= usize::from(limit.records) + usize::from(start.get() > 0) {
                return Err(Error::StorageContract);
            }
            entries.push(decode(row)?);
        }
    }
    let (observed_tail, expected, required_bytes) = header.ok_or(Error::StorageContract)?;
    if entries.len() != expected {
        return Err(rss_ledger::Error::SequenceGap.into());
    }
    // Detect a disagreement between the SQL length calculation and the canonical core owner.
    let decoded_bytes = entries.iter().try_fold(0u64, |total, entry| {
        total
            .checked_add(entry.encoded_len() as u64)
            .ok_or(Error::StorageContract)
    })?;
    if decoded_bytes != required_bytes || decoded_bytes > limit.encoded_bytes as u64 {
        return Err(Error::StorageContract);
    }
    entries.sort_unstable_by_key(Entry::sequence);
    let predecessor = if start.get() > 0 {
        if entries
            .first()
            .is_none_or(|e| e.sequence().get() != start.get() - 1)
        {
            return Err(rss_ledger::Error::SequenceGap.into());
        }
        Some(entries.remove(0))
    } else {
        None
    };
    auth.verify_window(ledger, predecessor.as_ref(), &entries)?;
    Ok(Window {
        predecessor,
        entries,
        observed_tail,
    })
}

fn read_header(row: &PgRow) -> Result<(Option<Sequence>, usize, u64), Error> {
    match row.try_get::<i32, _>("status").map_err(sql_error)? {
        0 => {}
        1 => return Err(rss_ledger::Error::UnsupportedKey.into()),
        2 => return Err(rss_ledger::Error::UnsupportedEncoding.into()),
        4 => return Err(rss_ledger::Error::SequenceGap.into()),
        5 => return Err(Error::ReadBudgetExceeded),
        _ => return Err(Error::StorageContract),
    }
    let tail = row
        .try_get::<Option<i64>, _>("observed_tail")
        .map_err(sql_error)?
        .map(decode_sequence)
        .transpose()?;
    let expected = usize::try_from(
        row.try_get::<i64, _>("expected_records")
            .map_err(sql_error)?,
    )
    .map_err(|_| Error::StorageContract)?;
    let bytes = u64::try_from(row.try_get::<i64, _>("required_bytes").map_err(sql_error)?)
        .map_err(|_| Error::StorageContract)?;
    Ok((tail, expected, bytes))
}

fn decode(row: PgRow) -> Result<Entry, Error> {
    let tenant: String = row
        .try_get("tenant_text")
        .map_err(|_| Error::StorageContract)?;
    let ledger = LedgerId::new(
        rss_request_context::TenantId::parse(&tenant).map_err(|_| Error::StorageContract)?,
        ChainId::parse(
            &row.try_get::<String, _>("chain_id")
                .map_err(|_| Error::StorageContract)?,
        )
        .map_err(|_| Error::StorageContract)?,
    );
    let request = AppendRequest::new(
        ledger,
        RecordId::parse(
            &row.try_get::<String, _>("record_id")
                .map_err(|_| Error::StorageContract)?,
        )
        .map_err(|_| Error::StorageContract)?,
        row.try_get("payload").map_err(|_| Error::StorageContract)?,
    )
    .map_err(|_| Error::StorageContract)?;
    let encoding = u16::try_from(
        row.try_get::<i16, _>("encoding_version")
            .map_err(|_| Error::StorageContract)?,
    )
    .map_err(|_| Error::StorageContract)?;
    Ok(Entry::from_parts(
        request,
        decode_sequence(row.try_get("seq").map_err(|_| Error::StorageContract)?)?,
        AuthenticationTag::from_bytes(
            &row.try_get::<Vec<u8>, _>("previous_tag")
                .map_err(|_| Error::StorageContract)?,
        )
        .map_err(|_| Error::StorageContract)?,
        AuthenticationTag::from_bytes(
            &row.try_get::<Vec<u8>, _>("tag")
                .map_err(|_| Error::StorageContract)?,
        )
        .map_err(|_| Error::StorageContract)?,
        EncodingVersion::parse(encoding)?,
        KeyId::parse(
            &row.try_get::<String, _>("key_id")
                .map_err(|_| Error::StorageContract)?,
        )
        .map_err(|_| Error::StorageContract)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sql_sequence_boundaries() {
        assert_eq!(
            encode_sequence(Sequence::new(i64::MAX as u64)).ok(),
            Some(i64::MAX)
        );
        assert!(encode_sequence(Sequence::new(i64::MAX as u64 + 1)).is_err());
        assert!(decode_sequence(-1).is_err());
        assert_eq!(decode_sequence(0).ok(), Some(Sequence::new(0)));
        assert!(ReadLimit::new(0, 1).is_err());
        assert!(ReadLimit::new(1025, 1).is_err());
        assert!(ReadLimit::new(1, 0).is_err());
        assert!(ReadLimit::new(1, i64::MAX as u64 + 1).is_err());
        assert!(ReadLimit::new(1, 1).is_ok());
        assert!(ReadLimit::new(1024, i64::MAX as u64).is_ok());
    }
}
