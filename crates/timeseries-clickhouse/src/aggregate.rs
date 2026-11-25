use crate::{
    Operation,
    control::{self, Fence},
    page::{Dependencies, Request, View},
    projection::{SummaryRow, literal},
    read::{ReadRow, selection, visible},
    transaction::{bytes, decode, sql_error},
};
use rss_request_context::{Clock, Deadline};
use rss_timeseries::*;
use sqlx::PgConnection;
#[derive(Clone, sqlx::FromRow)]
struct SummaryRef {
    spec_digest: Vec<u8>,
    lo: i64,
    hi: i64,
    object_id: String,
}
pub(crate) struct References {
    rows: Vec<SummaryRef>,
    end: i64,
    attempted: Vec<SummaryRef>,
}
pub(crate) fn needs_prior(spec: &SummarySpec) -> bool {
    matches!(
        spec.series().definition().spec().metric,
        Metric::Counter {
            temporality: Temporality::Cumulative,
            ..
        } | Metric::Bool
            | Metric::State { .. }
    )
}
pub(crate) fn mask(
    builder: &mut SummaryBuilder,
    fences: &[Fence],
    spec: &SummarySpec,
    at: Timestamp,
) -> Result<(), Error> {
    for f in fences {
        if f.kind == "delete"
            && !f.restored
            && control::overlaps(&f.selection, &spec.selection())
            && f.window.start() <= at
            && builder
                .last_observed_at()
                .is_some_and(|last| f.window.end() > last && f.window.start() >= last)
        {
            builder.interrupt(f.window.start())?;
        }
    }
    Ok(())
}
pub(crate) fn mask_end(
    builder: &mut SummaryBuilder, fences: &[Fence], spec: &SummarySpec, window: Interval,
) -> Result<(), Error> {
    mask(builder, fences, spec, Timestamp::new(window.end().micros() - 1)?)
}
impl<C: Clock> Operation<'_, C> {
    pub(crate) async fn predecessor(
        &self,
        spec: &SummarySpec,
        at: Timestamp,
        boundary: i64,
        fences: &[Fence],
        deadline: Deadline,
    ) -> Result<Option<ReadRow>, Error> {
        if !needs_prior(spec) {
            return Ok(None);
        } // reason: Gauge and delta intervals do not need a predecessor.
        let condition = format!(
            "{} AND revision<={boundary} AND observed_at<{}{}",
            selection(&spec.selection())?,
            at.micros(),
            visible(fences)?
        );
        let rows = self
            .raw_rows(
                &condition,
                "observed_at DESC,sequence DESC,sample_id DESC",
                0,
                deadline,
            )
            .await?;
        Ok(rows.into_iter().next())
    }
    pub(crate) async fn builder(
        &self,
        spec: &SummarySpec,
        window: Interval,
        boundary: i64,
        fences: &[Fence],
        deadline: Deadline,
    ) -> Result<(SummaryBuilder, i64), Error> {
        let prior = self
            .predecessor(spec, window.start(), boundary, fences, deadline)
            .await?;
        if needs_prior(spec) {
            if fences.iter().any(|f| {
                f.kind == "pruned"
                    && control::overlaps(&f.selection, &spec.selection())
                    && f.window.start() < window.start()
                    && prior
                        .as_ref()
                        .is_none_or(|p| p.sample.input().observed_at < f.window.end())
            }) {
                return Err(Error::HistoryExpired);
            }
        }
        let mut builder = SummaryBuilder::new(spec.clone(), window)?;
        let max_input_revision = prior.as_ref().map_or(0, |row| row.revision);
        if let Some(prior) = prior {
            builder.push(prior.sample, self.limits.max_points.get() as usize)?;
        }
        Ok((builder, max_input_revision))
    }
    async fn raw_summary(
        &self,
        spec: &SummarySpec,
        window: Interval,
        boundary: i64,
        fences: &[Fence],
        deadline: Deadline,
    ) -> Result<Summary, Error> {
        if fences.iter().any(|f| {
            f.kind == "pruned"
                && control::overlaps(&f.selection, &spec.selection())
                && f.window.start() < window.end()
                && f.window.end() > window.start()
        }) {
            return Err(Error::HistoryExpired);
        }
        let (mut builder, _) = self
            .builder(spec, window, boundary, fences, deadline)
            .await?;
        let condition = format!(
            "{} AND revision<={boundary} AND observed_at>={} AND observed_at<{}{}",
            selection(&spec.selection())?,
            window.start().micros(),
            window.end().micros(),
            visible(fences)?
        );
        let rows = self
            .raw_rows(
                &condition,
                "observed_at,sequence,sample_id",
                self.limits.max_points.get(),
                deadline,
            )
            .await?;
        if rows.len() > self.limits.max_points.get() as usize {
            return Err(Error::BudgetExceeded);
        }
        for row in rows {
            let sample = row.sample;
            mask(&mut builder, fences, spec, sample.input().observed_at)?;
            builder.push(sample, self.limits.max_points.get() as usize)?;
        }
        mask_end(&mut builder, fences, spec, window)?;
        builder.finish(self.limits.max_points.get() as usize)
    }
    pub(crate) async fn summary_value(
        &self,
        id: &str,
        scope: &Scope,
        deadline: Deadline,
    ) -> Result<Summary, Error> {
        let sql = format!(
            "SELECT tenant,namespace,object_id,lo,hi,revision,digest,payload FROM rss_ts_ch.summaries FINAL WHERE tenant={} AND namespace={} AND object_id={} LIMIT 2",
            literal(&scope.tenant().to_string()),
            literal(scope.namespace().as_str()),
            literal(id)
        );
        let rows = self
            .ch_query(self.reader.query_raw(&sql), deadline)?
            .fetch_all::<SummaryRow>()
            .await
            .map_err(|_| Error::Unavailable)?;
        if rows.len() != 1 {
            return Err(Error::Invariant);
        }
        let row = rows.first().ok_or(Error::Invariant)?;
        let value: Summary = decode(row.payload.as_bytes())?;
        use sha2::{Digest, Sha256};
        if crate::projection::hex(&Sha256::digest(row.payload.as_bytes())) != row.digest
            || value.window.start().micros() != row.lo
            || value.window.end().micros() != row.hi
        {
            return Err(Error::Invariant);
        }
        Ok(value)
    }
    async fn references(
        &self,
        c: &mut PgConnection,
        q: &AggregateQuery,
        view: &View<Timestamp>,
    ) -> Result<References, Error> {
        if !view.exists {
            return Ok(References {
                rows: Vec::new(),
                attempted: Vec::new(),
                end: q.query().window().start().micros(),
            });
        }
        let scope = q.spec().stream().scope();
        let range = q.query().window();
        let start = view.position.unwrap_or(range.start());
        if start < range.start() || start >= range.end() {
            return Err(Error::InvalidCursor);
        }
        // Each bucket costs at least one point, including the partial first bucket.
        let extra = u64::from(q.query().budget().max_points.get() - 1)
            .saturating_mul(q.resolution_micros().get());
        let end = q
            .spec()
            .bucket(start)?
            .end()
            .micros()
            .saturating_add(i64::try_from(extra).unwrap_or(i64::MAX))
            .min(range.end().micros());
        // Fetch whole buckets in chronological order. If the reference budget runs out
        // partway through a later bucket, resume at that bucket with a fresh page budget.
        let mut rows: Vec<SummaryRef> = sqlx::query_as(
            "SELECT spec_digest,lo,hi,object_id::text FROM rss_ts_ch.summaries
            WHERE tenant_id=$1::text::uuid AND namespace=$2 AND semantics=$3 AND lo>=$4 AND hi<=$5
              AND max_input_revision<=$7 AND (dirty_from IS NULL OR dirty_from>$7) AND lo/$8::bigint=(hi-1)/$8::bigint
            ORDER BY lo,hi,object_id LIMIT $6",
        )
        .bind(scope.tenant().to_string())
        .bind(scope.namespace().as_str())
        .bind(q.spec().semantics()?.as_bytes().as_slice())
        .bind(start.micros())
        .bind(end)
        .bind(i64::from(self.limits.max_points.get()) + 1)
        .bind(view.published)
        .bind(i64::try_from(q.resolution_micros().get()).map_err(|_| Error::NumericRange)?)
        .fetch_all(c)
        .await
        .map_err(sql_error)?;
        let mut end = end;
        if let Some(row) = rows.get(self.limits.max_points.get() as usize) {
            end = q.spec().bucket(Timestamp::new(row.lo)?)?.start().micros();
            if end <= start.micros() {
                return Err(Error::BudgetExceeded);
            }
            rows.truncate(rows.partition_point(|row| row.lo < end));
        }
        rows.reverse();
        Ok(References { rows, end, attempted: Vec::new() })
    }
    async fn cached(
        &self,
        refs: &[SummaryRef],
        attempted: &mut Vec<SummaryRef>,
        scope: &Scope,
        window: Interval,
        deadline: Deadline,
    ) -> Result<Option<Summary>, Error> {
        // The bounded reference graph is acyclic (hi > lo). Solve coverage backwards
        // before reading values, so a long dead-end bucket cannot hide a valid shorter chain.
        let mut path = std::collections::BTreeMap::new();
        path.insert(window.end().micros(), None);
        let first = refs.partition_point(|r| r.lo >= window.end().micros());
        for row in refs[first..].iter().take_while(|r| r.lo >= window.start().micros()) {
            if row.hi <= row.lo { return Err(Error::Invariant); }
            if path.contains_key(&row.hi) { path.entry(row.lo).or_insert(Some(row)); }
        }
        let mut at = window.start().micros();
        if !path.contains_key(&at) {
            return Ok(None);
        }
        let mut value: Option<Summary> = None;
        let mut size = 0usize;
        while at < window.end().micros() {
            let row = path.get(&at).and_then(|r| *r).ok_or(Error::Invariant)?;
            attempted.push(row.clone());
            let summary = self.summary_value(&row.object_id, scope, deadline).await?;
            if summary.window.start().micros() != at || summary.window.end().micros() != row.hi {
                return Err(Error::Invariant);
            }
            size = size
                .checked_add(bytes(&summary)?.len())
                .ok_or(Error::BudgetExceeded)?;
            if size > self.limits.max_bytes.get() as usize {
                return Err(Error::BudgetExceeded);
            }
            value = Some(match value {
                None => summary,
                Some(old) => old.merge(summary, self.limits.max_points.get() as usize)?,
            });
            at = row.hi;
        }
        Ok(value)
    }
}
fn cost(bucket: &AggregateBucket) -> usize {
    1 + match &bucket.value {
        AggregateValue::StateSegments(v) => v.len(),
        AggregateValue::Transitions(v) => v.len(),
        AggregateValue::StateCoverage(v) => v.len(),
        _ => 0,
    }
}
impl Request for AggregateQuery {
    type Position = Timestamp;
    type Metadata = References;
    type Page = AggregatePage;
    const DOMAIN: &'static [u8] = b"rss.timeseries.clickhouse.aggregate.v2";
    const INVALIDATED: Error = Error::SnapshotInvalidated;
    fn query(&self) -> &Query {
        self.query()
    }
    fn binding(&self) -> Result<Digest, Error> {
        self.binding()
    }
    async fn dependencies<C: Clock>(
        &self, store: &Operation<'_, C>, c: &mut PgConnection, _: i64,
    ) -> Result<Dependencies, Error> {
        let stream = self.spec().stream();
        let scope = stream.scope();
        let state: Option<(bool, bool)> = sqlx::query_as("SELECT closed,reclaimed FROM rss_ts_ch.streams WHERE tenant_id=$1::text::uuid AND namespace=$2 AND source=$3 AND generation=$4")
            .bind(scope.tenant().to_string()).bind(scope.namespace().as_str()).bind(stream.source().as_str()).bind(stream.generation().as_str())
            .fetch_optional(&mut *c).await.map_err(sql_error)?;
        let (closed, reclaimed) = state.unwrap_or_default();
        if reclaimed { return Err(Error::HistoryExpired); }
        let start = if needs_prior(self.spec()) { 0 } else { self.query().window().start().micros() };
        let fences = control::visible_fences(c, self.query(), start, store.limits, true).await?;
        let tag = store.material.key.page_state(Self::DOMAIN, self.binding()?, store.instance, &(&fences, closed))?;
        Ok(Dependencies { fences, tag })
    }
    async fn valid<C: Clock>(
        &self, _: &Operation<'_, C>, c: &mut PgConnection, metadata: &References, ceiling: i64,
    ) -> Result<bool, Error> {
        if metadata.attempted.is_empty() { return Ok(true); }
        let scope = self.spec().stream().scope();
        let specs: Vec<_> = metadata.attempted.iter().map(|r| r.spec_digest.clone()).collect();
        let starts: Vec<_> = metadata.attempted.iter().map(|r| r.lo).collect();
        let ends: Vec<_> = metadata.attempted.iter().map(|r| r.hi).collect();
        let ids: Vec<_> = metadata.attempted.iter().map(|r| r.object_id.as_str()).collect();
        // Each attempted object is looked up by the existing summary primary key.
        sqlx::query_scalar("SELECT NOT EXISTS(SELECT FROM unnest($3::bytea[],$4::bigint[],$5::bigint[],$6::text[]) a(spec_digest,lo,hi,object_id) WHERE NOT EXISTS(SELECT FROM rss_ts_ch.summaries s WHERE s.tenant_id=$1::text::uuid AND s.namespace=$2 AND s.spec_digest=a.spec_digest AND s.lo=a.lo AND s.hi=a.hi AND s.object_id=a.object_id::uuid AND s.semantics=$7 AND s.max_input_revision<=$8 AND (s.dirty_from IS NULL OR s.dirty_from>$8)))")
            .bind(scope.tenant().to_string()).bind(scope.namespace().as_str()).bind(specs).bind(starts).bind(ends).bind(ids)
            .bind(self.spec().semantics()?.as_bytes().as_slice()).bind(ceiling).fetch_one(c).await.map_err(sql_error)
    }
    async fn metadata<C: Clock>(
        &self,
        store: &Operation<'_, C>,
        c: &mut PgConnection,
        view: &View<Timestamp>,
    ) -> Result<References, Error> {
        store.references(c, self, view).await
    }
    async fn read<C: Clock>(
        &self,
        store: &Operation<'_, C>,
        view: View<Timestamp>,
        refs: &mut References,
        deadline: Deadline,
    ) -> Result<(AggregatePage, Option<Timestamp>), Error> {
        let q = self;
        let mut at = view.position.unwrap_or(q.query().window().start());
        let fences = view.fences;
        let mut buckets = Vec::new();
        let mut used = 0usize;
        let mut size = 0usize;
        let mut refreshed = None;
        let mut continuous = true;
        let published = view.published;
        while view.exists
            && at.micros() < refs.end
            && used < (q.query().budget().max_points.get() as usize)
        {
            let end = q.spec().bucket(at)?.end().min(q.query().window().end());
            let window = Interval::new(at, end)?;
            let cached = store
                .cached(&refs.rows, &mut refs.attempted, q.spec().stream().scope(), window, deadline)
                .await?;
            let is_cached = cached.is_some();
            let value = match cached {
                Some(v) => v,
                None => {
                    store
                        .raw_summary(q.spec(), window, published, &fences, deadline)
                        .await?
                }
            };
            let bucket = value.project(q.operation())?;
            if used + cost(&bucket) > q.query().budget().max_points.get() as usize {
                if buckets.is_empty() {
                    return Err(Error::BudgetExceeded);
                }
                break;
            }
            used += cost(&bucket);
            size = size
                .checked_add(bytes(&bucket)?.len())
                .ok_or(Error::BudgetExceeded)?;
            if size > store.limits.max_bytes.get() as usize {
                return Err(Error::BudgetExceeded);
            }
            buckets.push(bucket);
            at = end;
            continuous &= is_cached;
            if continuous {
                refreshed = Some(end);
            }
        }
        let position = (view.exists && at < q.query().window().end()).then_some(at);
        Ok((
            AggregatePage {
                buckets,
                availability: control::availability(q.query(), &fences)?,
                resolution_micros: q.resolution_micros(),
                refreshed_through: refreshed,
                next: None,
            },
            position,
        ))
    }
}
