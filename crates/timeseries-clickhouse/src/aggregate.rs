use crate::{
    ChStore,
    control::{self, Fence},
    projection::{SummaryRow, literal},
    read::{selection, visible},
    transaction::{bytes, decode, now, sql_error},
};
use rss_request_context::{Clock, Deadline};
use rss_timeseries::*;
use sqlx::{PgConnection, Row};
const DOMAIN: &[u8] = b"rss.timeseries.clickhouse.aggregate.v1";
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
impl<C: Clock> ChStore<C> {
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
        rows.first().map(|r| r.sample()).transpose()
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
            let sample = row.sample()?;
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
            .ch_query(&self.ch.reader, &sql, deadline)?
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
    async fn cached(
        &self,
        c: &mut PgConnection,
        spec: &SummarySpec,
        window: Interval,
        deadline: Deadline,
    ) -> Result<Option<Summary>, Error> {
        let scope = spec.stream().scope();
        let refs=sqlx::query("SELECT object_id::text,lo,hi FROM rss_ts_ch.summaries WHERE tenant_id=$1::text::uuid AND namespace=$2 AND semantics=$3 AND lo>=$4 AND hi<=$5 AND NOT dirty ORDER BY lo,hi DESC LIMIT $6")
            .bind(scope.tenant().to_string()).bind(scope.namespace().as_str()).bind(spec.semantics()?.as_bytes().as_slice()).bind(window.start().micros()).bind(window.end().micros()).bind(i64::from(self.limits.max_points.get())+1).fetch_all(c).await.map_err(sql_error)?;
        if refs.len() > self.limits.max_points.get() as usize {
            return Err(Error::BudgetExceeded);
        }
        let mut at = window.start().micros();
        let mut value: Option<Summary> = None;
        let mut size = 0usize;
        for r in refs {
            if r.try_get::<i64, _>("lo").map_err(sql_error)? != at {
                continue;
            }
            let summary = self
                .summary_value(
                    &r.try_get::<String, _>("object_id").map_err(sql_error)?,
                    scope,
                    deadline,
                )
                .await?;
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
            at = r.try_get("hi").map_err(sql_error)?;
            if at == window.end().micros() {
                return Ok(value);
            }
        }
        Ok(None)
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
pub(crate) async fn read<C: Clock>(
    store: &ChStore<C>,
    q: &AggregateQuery,
    after: Option<&Continuation>,
    deadline: Deadline,
) -> Result<AggregatePage, Error> {
    if q.query().budget().max_points > store.limits.max_points
        || q.query().budget().max_series > store.limits.max_series
    {
        return Err(Error::BudgetExceeded);
    }
    let mut tx = store
        .begin(q.spec().stream().scope(), false, deadline)
        .await?;
    let result = async {
        let time = now(tx.connection()).await?;
        let (expires, mut at) = match after {
            Some(t) => {
                store
                    .key
                    .open::<Timestamp>(DOMAIN, t, q.binding()?, &store.instance, time)?
            }
            None => (
                time.checked_add(store.limits.cursor_micros.get() as i64)
                    .ok_or(Error::NumericRange)?,
                q.query().window().start(),
            ),
        };
        if at < q.query().window().start() || at >= q.query().window().end() {
            return Err(Error::InvalidCursor);
        }
        let fences = control::fences(
            tx.connection(),
            q.spec().stream().scope(),
            store.limits.max_points.get(),
        )
        .await?;
        let mut buckets = Vec::new();
        let mut used = 0usize;
        let mut size = 0usize;
        let mut refreshed = None;
        let mut continuous = true;
        while at < q.query().window().end() {
            let end = q.spec().bucket(at)?.end().min(q.query().window().end());
            let window = Interval::new(at, end)?;
            let cached = store
                .cached(tx.connection(), q.spec(), window, deadline)
                .await?;
            let is_cached = cached.is_some();
            let value = match cached {
                Some(v) => v,
                None => {
                    store
                        .raw_summary(q.spec(), window, tx.published, &fences, deadline)
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
        let next = if at < q.query().window().end() {
            Some(
                store
                    .key
                    .seal(DOMAIN, q.binding()?, &store.instance, expires, &at)?,
            )
        } else {
            None
        };
        Ok(AggregatePage {
            buckets,
            availability: control::availability(q.query(), &fences)?,
            resolution_micros: q.resolution_micros(),
            refreshed_through: refreshed,
            next,
        })
    }
    .await;
    tx.read(result).await
}
