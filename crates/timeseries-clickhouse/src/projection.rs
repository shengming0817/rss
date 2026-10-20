// ref: ClickHouse/clickhouse-rs src/insert_formatted.rs@v0.15.3
// ref: ClickHouse/ClickHouse src/Interpreters/InterpreterKillQueryQuery.cpp@v25.8.12.129-lts
use crate::{
    ChStore,
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
#[derive(Clone, Serialize, Deserialize, clickhouse::Row)]
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
        if bytes(&expected)? != bytes(self)? {
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
    s: &Scope,
    target: &'static str,
    digest: &str,
    revision: i64,
) -> Result<Attempt, Error> {
    let r=sqlx::query("INSERT INTO rss_ts_ch.attempts(tenant_id,namespace,target,digest,revision) VALUES($1::text::uuid,$2,$3,$4,$5) RETURNING id::text,query_id::text")
        .bind(s.tenant().to_string()).bind(s.namespace().as_str()).bind(target).bind(digest).bind(revision).fetch_one(c).await.map_err(sql_error)?;
    Ok(Attempt {
        id: r.try_get("id").map_err(sql_error)?,
        query: r.try_get("query_id").map_err(sql_error)?,
        digest: digest.into(),
        revision,
        target,
    })
}
impl<C: Clock> ChStore<C> {
    pub(crate) fn ch_query(
        &self,
        client: &clickhouse::Client,
        sql: &str,
        deadline: Deadline,
    ) -> Result<clickhouse::query::Query, Error> {
        let remaining = deadline
            .remaining(self.clock.now())
            .ok_or(Error::Deadline)?
            .as_secs_f64();
        Ok(client
            .query(sql)
            .with_setting("max_execution_time", remaining.to_string())
            .with_setting("max_rows_to_read", self.limits.max_scan_rows.to_string())
            .with_setting("max_bytes_to_read", self.limits.max_scan_bytes.to_string())
            .with_setting("max_memory_usage", self.limits.max_memory_bytes.to_string())
            .with_setting("max_result_bytes", self.limits.max_bytes.to_string())
            .with_setting("read_overflow_mode", "throw")
            .with_setting("result_overflow_mode", "throw")
            .with_setting("timeout_overflow_mode", "throw")
            .with_setting("max_threads", "1")
            .with_setting("use_query_cache", "0"))
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
            literal(&self.instance)
        );
        let mut payload = Vec::new();
        for row in rows {
            serde_json::to_writer(&mut payload, row).map_err(|_| Error::Invariant)?;
            payload.push(b'\n');
        }
        let remaining = deadline
            .remaining(self.clock.now())
            .ok_or(Error::Deadline)?;
        let mut insert = self
            .ch
            .writer
            .insert_formatted_with(sql)
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
            .with_timeouts(Some(remaining), Some(remaining));
        insert
            .send(bytes::Bytes::from(payload))
            .await
            .map_err(|e| provider_error("insert-send", e))?;
        if self.fault(4) {
            std::future::pending::<()>().await;
        }
        insert
            .end()
            .await
            .map_err(|e| provider_error("insert-end", e))
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
        let sql = format!(
            "KILL QUERY WHERE user={} AND query_id IN ({ids}) SYNC",
            literal(&self.ch.users[1])
        );
        // KILL on an already finished query can return no result header at all.
        // Consume its complete HTTP response, then independently verify termination;
        // a successful HTTP status or a sent cancellation alone is not sufficient.
        self.ch_query(&self.ch.maintenance, &sql, deadline)?
            .execute()
            .await
            .map_err(|e| provider_error("drain-kill", e))?;
        let remaining = self
            .ch_query(
                &self.ch.maintenance,
                &format!(
                    "SELECT count() FROM system.processes WHERE user={} AND query_id IN ({ids})",
                    literal(&self.ch.users[1])
                ),
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
