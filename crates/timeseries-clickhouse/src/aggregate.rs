use crate::{
    Operation,
    control::{self, Fence},
    page::{Request, View},
    projection::{SummaryRow, literal},
    read::{selection, visible},
    transaction::{bytes, decode, sql_error},
};
use rss_request_context::{Clock, Deadline};
use rss_timeseries::*;
use sqlx::PgConnection;
type SummaryRef = (i64, i64, String);
pub(crate) struct References {
    rows: Vec<SummaryRef>,
    end: i64,
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
impl<C: Clock> Operation<'_, C> {
    pub(crate) async fn predecessor(
        &self,
        spec: &SummarySpec,
        at: Timestamp,
        boundary: i64,
        fences: &[Fence],
        deadline: Deadline,
    ) -> Result<Option<Sample>, Error> {
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
        Ok(rows.into_iter().next().map(|row| row.sample))
    }
    pub(crate) async fn builder(
        &self,
        spec: &SummarySpec,
        window: Interval,
        boundary: i64,
        fences: &[Fence],
        deadline: Deadline,
    ) -> Result<SummaryBuilder, Error> {
        let prior = self
            .predecessor(spec, window.start(), boundary, fences, deadline)
            .await?;
        if needs_prior(spec) {
            let start = if matches!(
                spec.series().definition().spec().metric,
                Metric::Bool | Metric::State { .. }
            ) && spec.coverage() == CoveragePolicy::ObservedOnly
            {
                0
            } else {
                window
                    .start()
                    .micros()
                    .saturating_sub(i64::try_from(spec.lookback()).unwrap_or(i64::MAX))
                    .max(0)
            };
            if fences.iter().any(|f| {
                f.kind == "pruned"
                    && control::overlaps(&f.selection, &spec.selection())
                    && f.window.start() < window.start()
                    && f.window.end().micros() > start
                    && prior
                        .as_ref()
                        .is_none_or(|p| p.input().observed_at < f.window.end())
            }) {
                return Err(Error::HistoryExpired);
            }
        }
        let mut builder = SummaryBuilder::new(spec.clone(), window)?;
        if let Some(prior) = prior {
            builder.push(prior, self.limits.max_points.get() as usize)?;
        }
        Ok(builder)
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
        let mut builder = self
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
        mask(&mut builder, fences, spec, window.end())?;
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
            "SELECT lo,hi,object_id::text FROM rss_ts_ch.summaries
            WHERE tenant_id=$1::text::uuid AND namespace=$2 AND semantics=$3 AND lo>=$4 AND hi<=$5
              AND (dirty_from IS NULL OR dirty_from>$7) AND lo/$8::bigint=(hi-1)/$8::bigint
            ORDER BY lo,hi LIMIT $6",
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
        if let Some((lo, _, _)) = rows.get(self.limits.max_points.get() as usize) {
            end = q.spec().bucket(Timestamp::new(*lo)?)?.start().micros();
            if end <= start.micros() {
                return Err(Error::BudgetExceeded);
            }
            rows.truncate(rows.partition_point(|row| row.0 < end));
        }
        rows.reverse();
        Ok(References { rows, end })
    }
    async fn cached(
        &self,
        refs: &[SummaryRef],
        scope: &Scope,
        window: Interval,
        deadline: Deadline,
    ) -> Result<Option<Summary>, Error> {
        // The bounded reference graph is acyclic (hi > lo). Solve coverage backwards
        // before reading values, so a long dead-end bucket cannot hide a valid shorter chain.
        let mut path = std::collections::BTreeMap::new();
        path.insert(
            window.end().micros(),
            (window.end().micros(), String::new()),
        );
        let first = refs.partition_point(|r| r.0 >= window.end().micros());
        for (lo, hi, id) in refs[first..]
            .iter()
            .take_while(|r| r.0 >= window.start().micros())
        {
            let (lo, hi) = (*lo, *hi);
            if hi <= lo {
                return Err(Error::Invariant);
            }
            if path.contains_key(&hi) {
                path.entry(lo).or_insert((hi, id.clone()));
            }
        }
        let mut at = window.start().micros();
        if !path.contains_key(&at) {
            return Ok(None);
        }
        let mut value: Option<Summary> = None;
        let mut size = 0usize;
        while at < window.end().micros() {
            let (hi, id) = path.get(&at).ok_or(Error::Invariant)?;
            let summary = self.summary_value(id, scope, deadline).await?;
            if summary.window.start().micros() != at || summary.window.end().micros() != *hi {
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
            at = *hi;
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
    const AGGREGATE: bool = true;
    fn query(&self) -> &Query {
        self.query()
    }
    fn binding(&self) -> Result<Digest, Error> {
        self.binding()
    }
    fn fence_start(&self) -> i64 {
        if needs_prior(self.spec()) {
            0
        } else {
            self.query().window().start().micros()
        }
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
        refs: References,
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
                .cached(&refs.rows, q.spec().stream().scope(), window, deadline)
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
