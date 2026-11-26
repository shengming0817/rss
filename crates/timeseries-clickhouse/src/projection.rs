// ref: ClickHouse/clickhouse-rs src/insert_formatted.rs@v0.15.3
// ref: ClickHouse/ClickHouse src/Interpreters/InterpreterKillQueryQuery.cpp@v25.8.12.129-lts
use crate::{
    Operation,
    transaction::{bytes, sql_error},
};
use rss_request_context::{Clock, Deadline};
use rss_timeseries::*;
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, Row};
use std::fmt::Write;
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}
pub(crate) fn literal(value: &str) -> String {
    format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'"))
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, clickhouse::Row)]
pub(crate) struct Raw {
    pub tenant: String,
    pub namespace: String,
    pub source: String,
    pub generation: String,
    pub sample_id: String,
    pub series: String,
    pub subject: String,
    pub resource: String,
    pub metric_key: String,
    pub observed_at: i64,
    pub sequence: u64,
    pub received_at: i64,
    pub revision: i64,
    pub digest: String,
    pub payload: String,
}
impl Raw {
    pub fn new(s: &Sample, received_at: i64, revision: i64) -> Result<Self, Error> {
        let i = s.input();
        Ok(Self {
            tenant: i.stream.scope().tenant().to_string(),
            namespace: i.stream.scope().namespace().as_str().to_owned(),
            source: i.stream.source().as_str().to_owned(),
            generation: i.stream.generation().as_str().to_owned(),
            sample_id: i.id.as_str().to_owned(),
            series: hex(i.series.digest()?.as_bytes()),
            subject: i.series.subject().as_str().to_owned(),
            resource: i.series.resource().as_str().to_owned(),
            metric_key: i.series.definition().spec().key.as_str().to_owned(),
            observed_at: i.observed_at.micros(),
            sequence: i.sequence,
            received_at,
            revision,
            digest: hex(s.digest()?.as_bytes()),
            payload: String::from_utf8(bytes(s)?).map_err(|_| Error::Invariant)?,
        })
    }
    pub fn sample(&self) -> Result<Sample, Error> {
        let s: Sample = crate::transaction::decode(self.payload.as_bytes())?;
        let expected = Self::new(&s, self.received_at, self.revision)?;
        if &expected != self {
            return Err(Error::Invariant);
        }
        Ok(s)
    }
}
pub(crate) const RAW_FIELDS: &str = "tenant,namespace,source,generation,sample_id,series,subject,resource,metric_key,observed_at,sequence,received_at,revision,digest,payload";
const RAW_INPUT: &str = "tenant String,namespace String,source String,generation String,sample_id String,series String,subject String,resource String,metric_key String,observed_at Int64,sequence UInt64,received_at Int64,revision Int64,digest String,payload String";
#[derive(Serialize, Deserialize, clickhouse::Row)]
pub(crate) struct SummaryRow {
    pub tenant: String,
    pub namespace: String,
    pub object_id: String,
    pub lo: i64,
    pub hi: i64,
    pub revision: i64,
    pub digest: String,
    pub payload: String,
}
pub(crate) struct Attempt {
    pub id: String,
    pub query: String,
    pub digest: String,
    pub revision: i64,
    pub target: &'static str,
}
pub(crate) async fn permit(
    c: &mut PgConnection,
    stream: &rss_timeseries::Stream,
    target: &'static str,
    digest: &str,
    revision: i64,
) -> Result<Attempt, Error> {
    let s = stream.scope();
    let r=sqlx::query("INSERT INTO rss_ts_ch.attempts(tenant_id,namespace,target,digest,revision,source,generation) VALUES($1::text::uuid,$2,$3,$4,$5,$6,$7) RETURNING id::text,query_id::text")
        .bind(s.tenant().to_string()).bind(s.namespace().as_str()).bind(target).bind(digest).bind(revision).bind(stream.source().as_str()).bind(stream.generation().as_str()).fetch_one(c).await.map_err(sql_error)?;
    Ok(Attempt {
        id: r.try_get("id").map_err(sql_error)?,
        query: r.try_get("query_id").map_err(sql_error)?,
        digest: digest.into(),
        revision,
        target,
    })
}
impl<C: Clock> Operation<'_, C> {
    pub(crate) fn ch_query(
        &self,
        query: clickhouse::query::Query,
        deadline: Deadline,
    ) -> Result<clickhouse::query::Query, Error> {
        let remaining = deadline
            .remaining(self.clock.now())
            .ok_or(Error::Deadline)?;
        Ok(self.limits.query(query, self.threads, remaining))
    }
    pub(crate) async fn insert<T: Serialize>(
        &self,
        attempt: &Attempt,
        rows: &[T],
        deadline: Deadline,
    ) -> Result<(), Error> {
        if rows.is_empty() {
            return Ok(());
        } // reason: an all-replay batch has no new raw projection.
        let (fields, input) = if attempt.target == "raw" {
            (RAW_FIELDS, RAW_INPUT)
        } else {
            (
                "tenant,namespace,object_id,lo,hi,revision,digest,payload",
                "tenant String,namespace String,object_id String,lo Int64,hi Int64,revision Int64,digest String,payload String",
            )
        };
        let fields = fields
            .split(',')
            .map(|f| format!("i.{f}"))
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "INSERT INTO rss_ts_ch.{} SELECT {} FROM input('{}') AS i INNER JOIN rss_ts_ch.active_attempts AS a ON i.tenant=a.tenant AND i.namespace=a.namespace AND i.revision=a.revision WHERE a.attempt={} AND a.query_id=initialQueryID() AND a.target={} AND a.digest={} AND a.installation={} FORMAT JSONEachRow",
            attempt.target,
            fields,
            input,
            literal(&attempt.id),
            literal(attempt.target),
            literal(&attempt.digest),
            literal(self.instance)
        );
        let mut payload = sql.into_bytes();
        payload.push(b'\n');
        for row in rows {
            serde_json::to_writer(&mut payload, row).map_err(|_| Error::Invariant)?;
            payload.push(b'\n');
        }
        let remaining = deadline
            .remaining(self.clock.now())
            .ok_or(Error::Deadline)?;
        // ref: ClickHouse/clickhouse-rs src/query.rs@v0.15.3
        // query_raw keeps JSON question marks literal and awaits the response in
        // this operation, unlike InsertFormatted's detached response task.
        let request = String::from_utf8(payload).map_err(|_| Error::Invariant)?;
        self.resources
            .ch
            .writer
            .query_raw(&request)
            .with_setting("query_id", &attempt.query)
            .with_setting(
                "insert_deduplication_token",
                if attempt.target == "summaries" {
                    format!("{}:summaries:{}", self.instance, attempt.id)
                } else {
                    format!(
                        "{}:raw:{}:{}",
                        self.instance, attempt.revision, attempt.digest
                    )
                },
            )
            .with_setting("max_execution_time", remaining.as_secs_f64().to_string())
            .with_setting("input_format_json_read_numbers_as_strings", "0")
            .with_setting("max_insert_threads", "1")
            .with_setting("max_insert_block_size", "4096")
            .with_setting("min_insert_block_size_rows", "4096")
            .with_setting("min_insert_block_size_bytes", "0")
            .with_setting("input_format_parallel_parsing", "0")
            .with_setting("max_threads", "1")
            .execute()
            .await
            .map_err(|e| provider_error("insert-response", e))
    }
    /// Revocation must already be committed. A zero-result kill is safe only because
    /// late arrivals must start a new PG guard read and cannot acquire that permit.
    pub(crate) async fn drain(&self, ids: &[String], deadline: Deadline) -> Result<(), Error> {
        if ids.is_empty() {
            return Ok(());
        } // reason: no network attempts have been registered.
        let ids = ids
            .iter()
            .map(|id| literal(id))
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!("KILL QUERY WHERE query_id IN ({ids}) SYNC");
        // KILL on an already finished query can return no result header at all.
        // Consume its complete HTTP response, then independently verify termination;
        // a successful HTTP status or a sent cancellation alone is not sufficient.
        self.ch_query(self.resources.ch.maintenance.query_raw(&sql), deadline)?
            .execute()
            .await
            .map_err(|e| provider_error("drain-kill", e))?;
        let remaining = self
            .ch_query(
                self.resources.ch.maintenance.query_raw(&format!(
                    "SELECT count() FROM system.processes WHERE query_id IN ({ids})"
                )),
                deadline,
            )?
            .fetch_all::<u64>()
            .await
            .map_err(|e| provider_error("drain-check", e))?;
        if remaining != vec![0] {
            return Err(Error::Unavailable);
        }
        Ok(())
    }
}

pub(crate) fn provider_error(stage: &str, error: clickhouse::error::Error) -> Error {
    #[cfg(feature = "integration")]
    {
        let (kind, code) = match &error {
            clickhouse::error::Error::BadResponse(s) => (
                "server",
                s.strip_prefix("Code: ")
                    .and_then(|s| s.split('.').next())
                    .and_then(|s| s.parse::<u32>().ok()),
            ),
            clickhouse::error::Error::SchemaMismatch(_) => ("schema", None),
            clickhouse::error::Error::Network(_) => ("network", None),
            _ => ("decode", None),
        };
        eprintln!("ClickHouse {stage}: {kind} code={code:?}");
        if let clickhouse::error::Error::BadResponse(s) = &error {
            for cap in [
                "CREATE TEMPORARY TABLE",
                "POSTGRES",
                "NAMED COLLECTION",
                "SELECT",
                "INSERT",
                "rss_ts_ch.raw",
                "rss_ts_ch.active_attempts",
                "system.settings",
                "input",
            ] {
                if s.contains(cap) {
                    eprintln!("ClickHouse diagnostic category: {cap}");
                }
            }
        }
    }
    #[cfg(not(feature = "integration"))]
    let _ = (stage, error);
    Error::Unavailable
}

// Read failures do not have the ambiguous-commit semantics of INSERT failures.
// ref: ClickHouse src/Common/ErrorCodes.cpp@v25.8.12.129-lts
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReadFailure {
    Capacity,
    QueryLength,
    Other(Error),
}

impl From<Error> for ReadFailure {
    fn from(error: Error) -> Self {
        Self::Other(error)
    }
}
impl From<ReadFailure> for Error {
    fn from(failure: ReadFailure) -> Self {
        match failure {
            ReadFailure::Capacity => Self::BudgetExceeded,
            ReadFailure::QueryLength => Self::Unavailable,
            ReadFailure::Other(error) => error,
        }
    }
}

pub(crate) fn read_error(error: clickhouse::error::Error) -> ReadFailure {
    use clickhouse::error::Error as ChError;
    match error {
        ChError::TimedOut => ReadFailure::Other(Error::Deadline),
        ChError::BadResponse(message) => {
            let diagnostic = message
                .strip_prefix("Code: ")
                .and_then(|s| s.split_once('.'));
            match diagnostic {
                Some(("158" | "307" | "396", _)) => ReadFailure::Capacity,
                Some(("241", tail)) if tail.starts_with(" DB::Exception: Query memory limit exceeded:") => ReadFailure::Capacity,
                Some(("241", _)) => ReadFailure::Other(Error::BudgetExceeded),
                Some(("159" | "160", _)) => ReadFailure::Other(Error::Deadline),
                // ClickHouse uses SYNTAX_ERROR for *all* parser errors. Only this
                // lexical diagnostic can be remedied by shortening a generated IN list.
                Some(("62", tail))
                    if tail.starts_with(" DB::Exception: Max query size exceeded (can be increased with the `max_query_size` setting):") =>
                {
                    ReadFailure::QueryLength
                }
                _ => ReadFailure::Other(Error::Unavailable),
            }
        }
        _ => ReadFailure::Other(Error::Unavailable),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "isolated release-mode canonical reconstruction allocation count"]
    fn raw_reconstruction_allocations() -> anyhow::Result<()> {
        use rss_request_context::TenantId;
        use std::hint::black_box;
        let scope = Scope::new(
            TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")?,
            Id::new("metrics")?,
        );
        for width in [0, 64] {
            let dims = (0..width)
                .map(|n| Ok((Id::new(format!("dim-{n}"))?, Id::new("value")?)))
                .collect::<Result<std::collections::BTreeMap<_, _>, Error>>()?;
            let definition = Definition::new(DefinitionSpec {
                scope: scope.clone(),
                key: Id::new("temperature")?,
                version: 1,
                unit: Id::new("unit")?,
                metric: Metric::Gauge {
                    number: NumberKind::U64,
                },
                dimensions: DimensionRules {
                    allowed: dims.keys().cloned().collect(),
                    required: Default::default(),
                    max_count: width,
                    max_value_bytes: 256,
                    max_total_bytes: 32768,
                },
            })?;
            let sample = Sample::new(SampleInput {
                stream: Stream::new(scope.clone(), Id::new("source")?, Id::new("gen")?),
                series: Series::new(definition, Id::new("device")?, Id::new("resource")?, dims)?,
                id: Id::new("point")?,
                sequence: 1,
                observed_at: Timestamp::new(1)?,
                interval: None,
                reading: Reading::Valid(Value::Number(Number::U64(1))),
            })?;
            let raw = Raw::new(&sample, 2, 1)?;
            assert_eq!(raw.sample()?, sample);
            let rebuild = allocation_counter::measure(|| {
                drop(black_box(Raw::new(black_box(&sample), 2, 1)));
            });
            let full = allocation_counter::measure(|| {
                drop(black_box(black_box(&raw).sample()));
            });
            println!(
                "RAW_ALLOC dims={width} json={} rebuild_allocs={} rebuild_bytes={} full_allocs={} full_bytes={} peak_bytes={}",
                raw.payload.len(),
                rebuild.count_total,
                rebuild.bytes_total,
                full.count_total,
                full.bytes_total,
                full.bytes_max
            );
            assert!(full.count_total >= rebuild.count_total && rebuild.count_total > 0);
        }
        Ok(())
    }
    #[test]
    fn only_query_local_memory_and_parser_length_can_shrink() {
        let classified =
            |message: &str| read_error(clickhouse::error::Error::BadResponse(message.into()));
        assert_eq!(
            classified("Code: 241. DB::Exception: Query memory limit exceeded: would use 100 MiB"),
            ReadFailure::Capacity
        );
        assert_eq!(
            classified("Code: 241. DB::Exception: User memory limit exceeded: would use 100 MiB"),
            ReadFailure::Other(Error::BudgetExceeded)
        );
        assert_eq!(
            classified(
                "Code: 62. DB::Exception: Max query size exceeded (can be increased with the `max_query_size` setting): Syntax error"
            ),
            ReadFailure::QueryLength
        );
        assert_eq!(
            classified("Code: 62. DB::Exception: Syntax error"),
            ReadFailure::Other(Error::Unavailable)
        );
    }
    #[test]
    fn reads_classify_budgets_and_time_without_exposing_provider_text() {
        for (code, expected) in [
            (158, Error::BudgetExceeded),
            (241, Error::BudgetExceeded),
            (307, Error::BudgetExceeded),
            (396, Error::BudgetExceeded),
            (159, Error::Deadline),
            (160, Error::Deadline),
            (60, Error::Unavailable),
        ] {
            assert_eq!(
                Error::from(read_error(clickhouse::error::Error::BadResponse(format!(
                    "Code: {code}. DB::Exception: private query"
                )))),
                expected
            );
        }
        for message in ["private Code: 158.", "Code: 158x.", "Code: 158"] {
            assert_eq!(
                Error::from(read_error(clickhouse::error::Error::BadResponse(
                    message.into()
                ))),
                Error::Unavailable
            );
        }
        assert_eq!(
            Error::from(read_error(clickhouse::error::Error::TimedOut)),
            Error::Deadline
        );
    }
}
