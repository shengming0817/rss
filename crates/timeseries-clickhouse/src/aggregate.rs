mod objects;
mod raw;

use crate::{
    Operation,
    control::{self, Fence},
    page::{Dependencies, Recheck, Request, View},
    projection::literal,
    read::{ReadRow, selection, visible},
    transaction::{bytes, decode, sql_error},
};
use rss_request_context::{Clock, Deadline};
use rss_timeseries::*;
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, Row};
use std::collections::VecDeque;
#[derive(Clone)]
struct SummaryRef {
    spec_digest: Vec<u8>,
    lo: i64,
    hi: i64,
    object_id: String,
    payload_bytes: u64,
    dependency_start: i64,
}
impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for SummaryRef {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            spec_digest: row.try_get("spec_digest")?,
            payload_bytes: row.try_get::<i64, _>("payload_bytes")?.cast_unsigned(),
            lo: row.try_get("lo")?,
            hi: row.try_get("hi")?,
            object_id: row.try_get("object_id")?,
            dependency_start: row.try_get("dependency_start")?,
        })
    }
}
#[derive(Serialize, Deserialize)]
pub(crate) struct Position {
    at: Timestamp,
    dependency_start: i64,
}
pub(crate) struct References {
    rows: Vec<SummaryRef>,
    end: i64,
    attempted: Vec<SummaryRef>,
    raw_budget: Option<Interval>,
    dependency_start: i64,
    fences: Vec<Fence>,
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
pub(crate) fn dependency_start(spec: &SummarySpec, start: Timestamp) -> i64 {
    if !needs_prior(spec) {
        return start.micros();
    }
    match (&spec.series().definition().spec().metric, spec.coverage()) {
        (Metric::Bool | Metric::State { .. }, CoveragePolicy::HoldLast(n)) => start
            .micros()
            .saturating_sub(i64::try_from(n.get()).unwrap_or(i64::MAX))
            .max(0),
        _ => 0,
    }
}
fn dependency_tag<C: Clock>(
    store: &Operation<'_, C>,
    q: &AggregateQuery,
    fences: &[Fence],
    start: i64,
    lifecycle: [u8; 32],
) -> Result<[u8; 32], Error> {
    let fences: Vec<_> = fences
        .iter()
        .filter(|f| f.window.end().micros() > start)
        .collect();
    store.material.key.page_state(
        AggregateQuery::DOMAIN,
        q.binding()?,
        store.instance,
        &(fences, lifecycle),
    )
}
pub(crate) fn mask(
    builder: &mut SummaryBuilder,
    fences: &[Fence],
    spec: &SummarySpec,
    window: Interval,
    at: Timestamp,
) -> Result<(), Error> {
    for f in fences {
        if f.kind == "delete"
            && !f.restored
            && control::overlaps(&f.selection, &spec.selection())
            && f.window.start() <= at
            && builder
                .last_observed_at()
                .map_or(f.window.end() > window.start(), |last| {
                    f.window.end() > last && f.window.start() >= last
                })
        {
            builder.interrupt(f.window.start())?;
        }
    }
    Ok(())
}
pub(crate) fn mask_end(
    builder: &mut SummaryBuilder,
    fences: &[Fence],
    spec: &SummarySpec,
    window: Interval,
) -> Result<(), Error> {
    mask(
        builder,
        fences,
        spec,
        window,
        Timestamp::new(window.end().micros() - 1)?,
    )
}
fn seeded_builder(
    spec: &SummarySpec,
    window: Interval,
    fences: &[Fence],
    prior: Option<&Sample>,
    limit: usize,
) -> Result<(SummaryBuilder, i64), Error> {
    let earliest = dependency_start(spec, window.start());
    let prior = prior.filter(|p| p.input().observed_at.micros() >= earliest);
    let dependency_start = prior.map_or(earliest, |p| p.input().observed_at.micros());
    if needs_prior(spec)
        && fences.iter().any(|f| {
            f.kind == "pruned"
                && control::overlaps(&f.selection, &spec.selection())
                && f.window.start() < window.start()
                && f.window.end().micros() > dependency_start
                && prior
                    .as_ref()
                    .is_none_or(|p| p.input().observed_at < f.window.end())
        })
    {
        return Err(Error::HistoryExpired);
    }
    let mut builder = SummaryBuilder::new(spec.clone(), window)?;
    if let Some(prior) = prior {
        builder.push(prior.clone(), limit)?;
    }
    Ok((builder, dependency_start))
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
            "{} AND revision<={boundary} AND observed_at>={} AND observed_at<{}{}",
            selection(&spec.selection())?,
            dependency_start(spec, at),
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
    ) -> Result<(SummaryBuilder, i64, i64), Error> {
        let prior = self
            .predecessor(spec, window.start(), boundary, fences, deadline)
            .await?;
        let revision = prior.as_ref().map_or(0, |r| r.revision);
        let (builder, start) = seeded_builder(
            spec,
            window,
            fences,
            prior.as_ref().map(|r| &r.sample),
            self.limits.max_points.get() as usize,
        )?;
        Ok((builder, revision, start))
    }
    async fn references(
        &self,
        c: &mut PgConnection,
        q: &AggregateQuery,
        view: &View<Position>,
    ) -> Result<References, Error> {
        let dependency_start = view.position.as_ref().map_or(
            dependency_start(q.spec(), q.query().window().start()),
            |p| p.dependency_start,
        );
        if !view.exists {
            return Ok(References {
                rows: Vec::new(),
                attempted: Vec::new(),
                raw_budget: None,
                dependency_start,
                fences: view.fences.clone(),
                end: q.query().window().start().micros(),
            });
        }
        let scope = q.spec().stream().scope();
        let range = q.query().window();
        let start = view.position.as_ref().map_or(range.start(), |p| p.at);
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
            "SELECT spec_digest,lo,hi,object_id::text,dependency_start,payload_bytes FROM rss_ts_ch.summaries
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
        Ok(References {
            rows,
            end,
            attempted: Vec::new(),
            raw_budget: None,
            dependency_start,
            fences: view.fences.clone(),
        })
    }
}
// The bounded DAG is solved backwards before reading any object.
fn coverage(refs: &[SummaryRef], window: Interval) -> Result<Option<Vec<&SummaryRef>>, Error> {
    let mut path = std::collections::BTreeMap::new();
    path.insert(window.end().micros(), None);
    let first = refs.partition_point(|r| r.lo >= window.end().micros());
    for row in refs[first..]
        .iter()
        .take_while(|r| r.lo >= window.start().micros())
    {
        if row.hi <= row.lo {
            return Err(Error::Invariant);
        }
        if path.contains_key(&row.hi) {
            path.entry(row.lo).or_insert(Some(row));
        }
    }
    let mut at = window.start().micros();
    if !path.contains_key(&at) {
        return Ok(None);
    }
    let mut chain = Vec::new();
    while at < window.end().micros() {
        let row = path.get(&at).and_then(|r| *r).ok_or(Error::Invariant)?;
        chain.push(row);
        at = row.hi;
    }
    Ok(Some(chain))
}
// Plan only buckets with candidate metadata; long empty runs cost no extra storage.
fn covered<'a>(
    q: &AggregateQuery,
    start: Timestamp,
    mut rows: &'a [SummaryRef],
) -> Result<VecDeque<(Interval, Vec<&'a SummaryRef>)>, Error> {
    let mut hits = VecDeque::new();
    while let Some(first) = rows.first() {
        let bucket = q.spec().bucket(Timestamp::new(first.lo)?)?;
        let count = rows.partition_point(|r| r.lo >= bucket.start().micros());
        let window = Interval::new(
            bucket.start().max(start),
            bucket.end().min(q.query().window().end()),
        )?;
        if let Some(path) = coverage(&rows[..count], window)? {
            hits.push_front((window, path));
        }
        rows = &rows[count..];
    }
    Ok(hits)
}
// State observations at equal microseconds are collapsed. A projected state entry
// starts at a distinct in-window tick (including a carried segment at the left edge).
// Include a later bucket only if the page must at least attempt it.
fn read_through(
    q: &AggregateQuery,
    window: Interval,
    remaining: usize,
    end: Timestamp,
) -> Result<Timestamp, Error> {
    let width = q.resolution_micros().get();
    let (first, full) = match q.operation() {
        AggregateOp::Timeline | AggregateOp::Transitions | AggregateOp::Coverage => {
            (1 + window.width_micros(), 1 + width)
        }
        _ => (1, 1),
    };
    let remaining = remaining as u64;
    let extra = remaining.saturating_sub(first).div_ceil(full);
    let span = i64::try_from(extra.saturating_mul(width)).unwrap_or(i64::MAX);
    Timestamp::new(window.end().micros().saturating_add(span).min(end.micros()))
}

// Wide reads are optional optimizations. Leave half of the remaining call budget for
// a narrower request and the PG evidence check, including when the HTTP body stalls.
fn batch_deadline<C: Clock>(
    store: &Operation<'_, C>,
    deadline: Deadline,
    wide: bool,
) -> Result<Deadline, Error> {
    if !wide {
        return Ok(deadline);
    }
    let now = store.clock.now();
    let left = deadline.remaining(now).ok_or(Error::Deadline)?;
    Ok(deadline.shortened_to(now + left / 2))
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
    type Position = Position;
    type Metadata = References;
    type Page = AggregatePage;
    const DOMAIN: &'static [u8] = b"rss.timeseries.clickhouse.aggregate.v3";
    const INVALIDATED: Error = Error::SnapshotInvalidated;
    fn query(&self) -> &Query {
        self.query()
    }
    fn binding(&self) -> Result<Digest, Error> {
        self.binding()
    }
    async fn dependencies<C: Clock>(
        &self,
        store: &Operation<'_, C>,
        c: &mut PgConnection,
        _: i64,
        position: Option<&Position>,
    ) -> Result<Dependencies, Error> {
        let stream = self.spec().stream();
        let scope = stream.scope();
        let state: Option<(bool, bool)> = sqlx::query_as("SELECT closed,reclaimed FROM rss_ts_ch.streams WHERE tenant_id=$1::text::uuid AND namespace=$2 AND source=$3 AND generation=$4")
            .bind(scope.tenant().to_string()).bind(scope.namespace().as_str()).bind(stream.source().as_str()).bind(stream.generation().as_str())
            .fetch_optional(&mut *c).await.map_err(sql_error)?;
        let (closed, reclaimed) = state.unwrap_or_default();
        if reclaimed {
            return Err(Error::HistoryExpired);
        }
        let start = position.map_or(
            dependency_start(self.spec(), self.query().window().start()),
            |p| p.dependency_start,
        );
        let fences = control::visible_fences(c, self.query(), start, store.limits, true).await?;
        let tag = store.material.key.page_state(
            Self::DOMAIN,
            self.binding()?,
            store.instance,
            &closed,
        )?;
        Ok(Dependencies { fences, tag })
    }
    fn state<C: Clock>(
        &self,
        store: &Operation<'_, C>,
        metadata: &References,
        tag: [u8; 32],
    ) -> Result<[u8; 32], Error> {
        dependency_tag(
            store,
            self,
            &metadata.fences,
            metadata.dependency_start,
            tag,
        )
    }
    async fn recheck<C: Clock>(
        &self,
        store: &Operation<'_, C>,
        c: &mut PgConnection,
        metadata: &References,
        check: Recheck,
    ) -> Result<(bool, bool), Error> {
        let position = Position {
            at: self.query().window().start(),
            dependency_start: metadata.dependency_start,
        };
        let deps = self
            .dependencies(store, c, check.fence, Some(&position))
            .await?;
        if dependency_tag(
            store,
            self,
            &deps.fences,
            metadata.dependency_start,
            deps.tag,
        )? != check.tag
        {
            return Ok((false, false));
        }
        if let Some(window) = metadata.raw_budget {
            let view = |published| View {
                published,
                fences: Vec::new(),
                position: Some(Position {
                    at: window.start(),
                    dependency_start: metadata.dependency_start,
                }),
                exists: true,
            };
            let original = store.references(c, self, &view(check.ceiling)).await?;
            if coverage(&original.rows, window)?.is_some() {
                return Ok((true, false));
            }
            if check.continuation && check.published > check.ceiling {
                let latest = store.references(c, self, &view(check.published)).await?;
                if coverage(&latest.rows, window)?.is_some() {
                    return Err(Error::SnapshotInvalidated);
                }
            }
        }
        if metadata.attempted.is_empty() {
            return Ok((true, true));
        }
        let scope = self.spec().stream().scope();
        let specs: Vec<_> = metadata
            .attempted
            .iter()
            .map(|r| r.spec_digest.clone())
            .collect();
        let starts: Vec<_> = metadata.attempted.iter().map(|r| r.lo).collect();
        let ends: Vec<_> = metadata.attempted.iter().map(|r| r.hi).collect();
        let ids: Vec<_> = metadata
            .attempted
            .iter()
            .map(|r| r.object_id.as_str())
            .collect();
        // Each attempted object is looked up by the existing summary primary key.
        sqlx::query_scalar("SELECT NOT EXISTS(SELECT FROM unnest($3::bytea[],$4::bigint[],$5::bigint[],$6::text[]) a(spec_digest,lo,hi,object_id) WHERE NOT EXISTS(SELECT FROM rss_ts_ch.summaries s WHERE s.tenant_id=$1::text::uuid AND s.namespace=$2 AND s.spec_digest=a.spec_digest AND s.lo=a.lo AND s.hi=a.hi AND s.object_id=a.object_id::uuid AND s.semantics=$7 AND s.max_input_revision<=$8 AND (s.dirty_from IS NULL OR s.dirty_from>$8)))")
            .bind(scope.tenant().to_string()).bind(scope.namespace().as_str()).bind(specs).bind(starts).bind(ends).bind(ids)
            .bind(self.spec().semantics()?.as_bytes().as_slice()).bind(check.ceiling).fetch_one(c).await.map(|valid| (true, valid)).map_err(sql_error)
    }
    async fn metadata<C: Clock>(
        &self,
        store: &Operation<'_, C>,
        c: &mut PgConnection,
        view: &View<Position>,
    ) -> Result<References, Error> {
        store.references(c, self, view).await
    }
    async fn read<C: Clock>(
        &self,
        store: &Operation<'_, C>,
        view: View<Position>,
        refs: &mut References,
        deadline: Deadline,
    ) -> Result<(AggregatePage, Option<Position>), Error> {
        let q = self;
        let mut at = view
            .position
            .as_ref()
            .map_or(q.query().window().start(), |p| p.at);
        let fences = view.fences;
        let mut buckets = Vec::new();
        let mut used = 0usize;
        let mut size = 0usize;
        let mut refreshed = None;
        let mut continuous = true;
        let published = view.published;
        let mut hits = covered(q, at, &refs.rows)?;
        let planned: Vec<_> = hits
            .iter()
            .flat_map(|(_, path)| path.iter().copied())
            .collect();
        let mut objects = objects::Reader::new(&planned);
        let mut raw = None;
        while view.exists
            && at.micros() < refs.end
            && used < (q.query().budget().max_points.get() as usize)
        {
            deadline
                .remaining(store.clock.now())
                .ok_or(Error::Deadline)?;
            let end = q.spec().bucket(at)?.end().min(q.query().window().end());
            let window = Interval::new(at, end)?;
            let remaining = q.query().budget().max_points.get() as usize - used;
            let through = read_through(q, window, remaining, Timestamp::new(refs.end)?)?;
            let is_cached = hits.front().is_some_and(|(w, _)| *w == window);
            let value = if is_cached {
                raw = None;
                let (_, path) = hits.pop_front().ok_or(Error::Invariant)?;
                if at == q.query().window().start() {
                    refs.dependency_start = path
                        .iter()
                        .map(|r| r.dependency_start)
                        .min()
                        .ok_or(Error::Invariant)?;
                }
                objects
                    .merge(
                        store,
                        q.spec().stream().scope(),
                        &path,
                        through,
                        &mut refs.attempted,
                        deadline,
                    )
                    .await?
            } else {
                let mut start = refs.dependency_start;
                let run_end = hits
                    .front()
                    .map_or(through, |(w, _)| w.start().min(through));
                let run = raw.get_or_insert_with(|| {
                    raw::Run::new(q.spec(), &fences, published, deadline, at)
                });
                let result = run.summary(store, window, run_end, &mut start).await;
                if at == q.query().window().start() {
                    refs.dependency_start = start;
                }
                if matches!(result, Err(Error::BudgetExceeded)) {
                    refs.raw_budget = Some(window);
                }
                result?
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
        let position = (view.exists && at < q.query().window().end()).then_some(Position {
            at,
            dependency_start: refs.dependency_start,
        });
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
