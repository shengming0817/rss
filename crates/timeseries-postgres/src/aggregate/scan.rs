//! Bounded keyset reads shared by merged raw windows and resumable recomputation.
use super::*;
use crate::read::query;
use sqlx::{Postgres, QueryBuilder};
use std::collections::VecDeque;

pub(crate) type Key = (Timestamp, u64, Id);
const CHUNK: usize = 64;

pub(crate) struct Scan<'a> {
    spec: &'a SummarySpec,
    window: Interval,
    series: Digest,
    excluded: Option<String>,
    after: Option<Key>,
    ready: VecDeque<(Timestamp, Result<Vec<u8>, Error>)>,
    exhausted: bool,
    bucket: Option<Interval>,
    bytes: usize,
    rows: usize,
}
impl<'a> Scan<'a> {
    pub(crate) fn new(
        spec: &'a SummarySpec,
        window: Interval,
        available: &Availability,
        after: Option<Key>,
    ) -> Result<Self, Error> {
        Ok(Self {
            spec,
            window,
            series: spec.series().digest()?,
            excluded: query::excluded(available)?,
            after,
            ready: VecDeque::new(),
            exhausted: false,
            bucket: None,
            bytes: 0,
            rows: 0,
        })
    }
    pub(crate) fn more(&self) -> bool {
        !self.exhausted || !self.ready.is_empty()
    }
    // End limits consumption to the current output bucket. The header lookahead
    // establishes More for maintenance without fetching its payload.
    pub(crate) async fn next(
        &mut self,
        c: &mut PgConnection,
        end: Timestamp,
        remaining: usize,
        limits: &Limits,
    ) -> Result<Option<Sample>, Error> {
        if self.ready.is_empty() && !self.exhausted {
            self.fill(c, remaining.min(CHUNK), limits).await?;
        }
        if self.ready.front().is_none_or(|(at, _)| *at >= end) {
            return Ok(None);
        }
        let (_, raw) = self.ready.pop_front().ok_or(Error::Invariant)?;
        serde_json::from_slice(&raw?)
            .map(Some)
            .map_err(|_| Error::Invariant)
    }
    fn scoped(&self, sql: &mut QueryBuilder<Postgres>) {
        let stream = self.spec.stream();
        sql.push(" FROM rss_timeseries.samples s WHERE tenant_id=")
            .push_bind(stream.scope().tenant().to_string())
            .push("::text::uuid AND namespace=")
            .push_bind(stream.scope().namespace().as_str())
            .push(" AND source=")
            .push_bind(stream.source().as_str())
            .push(" AND generation=")
            .push_bind(stream.generation().as_str())
            .push(" AND series_digest=")
            .push_bind(self.series.as_bytes().as_slice())
            .push(" AND observed_at>=")
            .push_bind(self.window.start().micros())
            .push(" AND observed_at<")
            .push_bind(self.window.end().micros());
    }
    async fn fill(
        &mut self,
        c: &mut PgConnection,
        take: usize,
        limits: &Limits,
    ) -> Result<(), Error> {
        let mut headers = QueryBuilder::new("WITH ");
        query::push_excluded(&mut headers, self.excluded.as_deref());
        headers.push("headers AS (SELECT observed_at,sequence,sample_id,octet_length(raw) AS size");
        self.scoped(&mut headers);
        query::filter_excluded(&mut headers, self.excluded.is_some());
        if let Some((at, seq, id)) = &self.after {
            headers
                .push(" AND (observed_at,sequence,sample_id)>(")
                .push_bind(at.micros())
                .push(",")
                .push_bind(seq.to_string())
                .push("::text::numeric,")
                .push_bind(id.as_str())
                .push(" COLLATE \"C\")");
        }
        headers.push(" ORDER BY observed_at,sequence,sample_id LIMIT ").push_bind(take as i64 + 1)
            .push(") SELECT *,sequence::text AS seq FROM headers ORDER BY observed_at,sequence,sample_id");
        let rows = headers
            .build()
            .fetch_all(&mut *c)
            .await
            .map_err(sql_error)?;
        self.exhausted = rows.len() <= take;
        let mut ids = Vec::new();
        let mut times = Vec::new();
        let mut block_bytes = 0usize;
        let mut overflow = None;
        for row in rows.into_iter().take(take) {
            let at = Timestamp::new(row.try_get("observed_at").map_err(sql_error)?)?;
            let size = usize::try_from(row.try_get::<i32, _>("size").map_err(sql_error)?)
                .map_err(|_| Error::Invariant)?;
            let bucket = self.spec.bucket(at)?;
            if self.bucket != Some(bucket) {
                self.bucket = Some(bucket);
                self.rows = 0;
                self.bytes = 0;
            }
            let cap = limits.max_bytes.get() as usize;
            if size > cap - self.bytes || self.rows == limits.max_points.get() as usize {
                overflow = Some(at);
                self.exhausted = true;
                break;
            }
            if size > cap - block_bytes {
                self.exhausted = false;
                break;
            }
            let id = Id::new(row.try_get::<String, _>("sample_id").map_err(sql_error)?)?;
            let seq = row
                .try_get::<&str, _>("seq")
                .map_err(sql_error)?
                .parse()
                .map_err(|_| Error::Invariant)?;
            ids.push(id.as_str().to_owned());
            times.push(at.micros());
            self.after = Some((at, seq, id));
            self.bytes += size;
            self.rows += 1;
            block_bytes += size;
        }
        if !ids.is_empty() {
            let mut payloads = QueryBuilder::new("SELECT observed_at,raw");
            self.scoped(&mut payloads);
            payloads
                .push(" AND (sample_id,observed_at) IN (SELECT * FROM unnest(")
                .push_bind(ids)
                .push("::text[],")
                .push_bind(&times)
                .push("::bigint[])) ORDER BY observed_at,sequence,sample_id");
            let rows = payloads.build().fetch_all(c).await.map_err(sql_error)?;
            if rows.len() != times.len() {
                return Err(Error::Invariant);
            }
            for row in rows {
                let at = Timestamp::new(row.try_get("observed_at").map_err(sql_error)?)?;
                self.ready
                    .push_back((at, Ok(row.try_get("raw").map_err(sql_error)?)));
            }
        }
        if let Some(at) = overflow {
            self.ready.push_back((at, Err(Error::BudgetExceeded)));
        }
        Ok(())
    }
}
