use crate::{
    Limits, PgStore,
    lifecycle::{availability, bytes, read_lock},
    transaction::{certain, check, db_now, sql_error},
};
use rss_request_context::{Clock, Deadline};
use rss_timeseries::*;
use sqlx::{PgConnection, Row};
const DOMAIN: &[u8] = b"rss.timeseries.aggregate.v2";

pub(crate) async fn raw(
    c: &mut PgConnection,
    spec: &SummarySpec,
    window: Interval,
    limits: &Limits,
) -> Result<Summary, Error> {
    let s = spec.stream();
    let prior = predecessor(c, spec, window.start()).await?;
    ensure_boundary(c, spec, window.start(), prior.as_ref(), limits).await?;
    let rows=sqlx::query("SELECT raw FROM rss_timeseries.samples WHERE tenant_id=$1::text::uuid AND namespace=$2 AND source=$3 AND generation=$4 AND series_digest=$5 AND observed_at >= $6 AND observed_at<$7 AND rss_timeseries.visible(convert_from(raw,'UTF8')::jsonb,observed_at) ORDER BY observed_at,sequence,sample_id LIMIT $8")
    .bind(s.scope().tenant().to_string()).bind(s.scope().namespace().as_str()).bind(s.source().as_str()).bind(s.generation().as_str()).bind(spec.series().digest()?.as_bytes().as_slice()).bind(window.start().micros()).bind(window.end().micros()).bind(i64::from(limits.max_points.get())+1).fetch_all(&mut *c).await.map_err(sql_error)?;
    if rows.len() > limits.max_points.get() as usize {
        return Err(Error::BudgetExceeded);
    }
    let mut total = 0usize;
    let mut samples: Vec<Sample> = Vec::new();
    for r in rows {
        let data: Vec<u8> = r.try_get("raw").map_err(sql_error)?;
        total = total.checked_add(data.len()).ok_or(Error::BudgetExceeded)?;
        if total > limits.max_bytes.get() as usize {
            return Err(Error::BudgetExceeded);
        }
        samples.push(serde_json::from_slice(&data).map_err(|_| Error::Invariant)?);
    }
    let gap_window = Interval::new(
        prior
            .as_ref()
            .map_or(window.start(), |p| p.input().observed_at),
        window.end(),
    )?;
    let gaps = deletions(c, spec, gap_window, limits).await?;
    let mut builder = SummaryBuilder::new(spec.clone(), window)?;
    if let Some(prior) = prior {
        builder.push(prior, limits.max_points.get() as usize)?;
    }
    for sample in samples {
        mask(&mut builder, &gaps, sample.input().observed_at)?;
        builder.push(sample, limits.max_points.get() as usize)?;
    }
    mask(&mut builder, &gaps, window.end())?;
    builder.finish(limits.max_points.get() as usize)
}
async fn cached(
    c: &mut PgConnection,
    spec: &SummarySpec,
    window: Interval,
    limits: &Limits,
) -> Result<Option<Summary>, Error> {
    let rows=sqlx::query("SELECT lo,hi,data FROM rss_timeseries.summaries WHERE tenant_id=$1::text::uuid AND namespace=$2 AND semantics=$3 AND lo >= $4 AND hi <= $5 AND NOT dirty ORDER BY lo,hi DESC LIMIT $6")
 .bind(spec.stream().scope().tenant().to_string()).bind(spec.stream().scope().namespace().as_str()).bind(spec.semantics()?.as_bytes().as_slice()).bind(window.start().micros()).bind(window.end().micros()).bind(i64::from(limits.max_points.get())+1).fetch_all(&mut *c).await.map_err(sql_error)?;
    if rows.len() > limits.max_points.get() as usize {
        return Err(Error::BudgetExceeded);
    }
    let mut at = window.start();
    let mut result: Option<Summary> = None;
    let mut size = 0usize;
    for r in rows {
        let lo = Timestamp::new(r.try_get("lo").map_err(sql_error)?)?;
        if lo != at {
            continue;
        }
        let data: Vec<u8> = r.try_get("data").map_err(sql_error)?;
        size = size.checked_add(data.len()).ok_or(Error::BudgetExceeded)?;
        if size > limits.max_bytes.get() as usize {
            return Err(Error::BudgetExceeded);
        }
        let summary: Summary = serde_json::from_slice(&data).map_err(|_| Error::Invariant)?;
        let hi = Timestamp::new(r.try_get("hi").map_err(sql_error)?)?;
        if summary.window != Interval::new(lo, hi)? {
            return Err(Error::Invariant);
        }
        result = Some(match result {
            None => summary,
            Some(old) => old.merge(summary, limits.max_points.get() as usize)?,
        });
        at = hi;
        if at == window.end() {
            return Ok(result);
        }
    }
    Ok(None)
}
pub(crate) async fn store(
    c: &mut PgConnection,
    spec: &SummarySpec,
    summary: &Summary,
    limits: &Limits,
) -> Result<(), Error> {
    let data = bytes(summary)?;
    if data.len() > limits.max_bytes.get() as usize {
        return Err(Error::BudgetExceeded);
    }
    sqlx::query("SELECT rss_timeseries.put_summary($1::text::uuid,$2,$3,$4,$5,$6,$7,$8)")
        .bind(spec.stream().scope().tenant().to_string())
        .bind(spec.stream().scope().namespace().as_str())
        .bind(spec.binding()?.as_bytes().as_slice())
        .bind(spec.semantics()?.as_bytes().as_slice())
        .bind(bytes(spec)?)
        .bind(summary.window.start().micros())
        .bind(summary.window.end().micros())
        .bind(data)
        .execute(c)
        .await
        .map_err(sql_error)?;
    Ok(())
}
fn cost(b: &AggregateBucket) -> usize {
    1 + match &b.value {
        AggregateValue::StateSegments(v) => v.len(),
        AggregateValue::Transitions(v) => v.len(),
        AggregateValue::StateCoverage(v) => v.len(),
        _ => 0,
    }
}
pub(crate) async fn read<C: Clock>(
    store: &PgStore<C>,
    query: &AggregateQuery,
    after: Option<&Continuation>,
    deadline: Deadline,
) -> Result<AggregatePage, Error> {
    if query.query().budget().max_points > store.limits.max_points
        || query.query().budget().max_series > store.limits.max_series
    {
        return Err(Error::BudgetExceeded);
    }
    let q = query.clone();
    let token = after.cloned();
    let limits = store.limits.clone();
    let key = store.key.clone();
    let instance = store.instance.clone();
    certain(
        store
            .transaction(
                query.spec().stream().scope().tenant(),
                deadline,
                false,
                move |c, clock| {
                    Box::pin(async move {
                        read_lock(c, q.spec().stream().scope()).await?;
                        let now = db_now(c).await?;
                        let binding = q.binding()?;
                        let (expires, mut at) = match token {
                            Some(t) => {
                                key.open::<Timestamp>(DOMAIN, &t, binding, &instance, now)?
                            }
                            None => (
                                now.checked_add(
                                    i64::try_from(limits.cursor_micros.get())
                                        .map_err(|_| Error::NumericRange)?,
                                )
                                .ok_or(Error::NumericRange)?,
                                q.query().window().start(),
                            ),
                        };
                        if at < q.query().window().start() || at >= q.query().window().end() {
                            return Err(Error::InvalidCursor);
                        }
                        let available = availability(c, q.query(), limits.max_points.get()).await?;
                        let mut buckets = Vec::new();
                        let mut used = 0usize;
                        let mut total_bytes = 0usize;
                        let mut refreshed = None;
                        let mut continuous = true;
                        while at < q.query().window().end() {
                            check(clock, deadline)?;
                            let end = q.spec().bucket(at)?.end().min(q.query().window().end());
                            let window = Interval::new(at, end)?;
                            let persisted = cached(c, q.spec(), window, &limits).await?;
                            let is_cached = persisted.is_some();
                            let summary = match persisted {
                                Some(v) => v,
                                None => {
                                    if available.excluded.iter().any(|r| {
                                        r.reason == UnavailableReason::Pruned
                                            && r.window.start() < end
                                            && r.window.end() > at
                                    }) {
                                        return Err(Error::HistoryExpired);
                                    }
                                    raw(c, q.spec(), window, &limits).await?
                                }
                            };
                            let bucket = summary.project(q.operation())?;
                            let points = cost(&bucket);
                            if used + points > q.query().budget().max_points.get() as usize {
                                if buckets.is_empty() {
                                    return Err(Error::BudgetExceeded);
                                }
                                break;
                            }
                            total_bytes = total_bytes
                                .checked_add(bytes(&bucket)?.len())
                                .ok_or(Error::BudgetExceeded)?;
                            if total_bytes > limits.max_bytes.get() as usize {
                                return Err(Error::BudgetExceeded);
                            }
                            used += points;
                            buckets.push(bucket);
                            at = end;
                            continuous &= is_cached;
                            if continuous {
                                refreshed = Some(end);
                            }
                        }
                        let next = if at < q.query().window().end() {
                            Some(key.seal(DOMAIN, binding, &instance, expires, &at)?)
                        } else {
                            None
                        };
                        Ok(AggregatePage {
                            buckets,
                            availability: available,
                            resolution_micros: q.resolution_micros(),
                            refreshed_through: refreshed,
                            next,
                        })
                    })
                },
            )
            .await?,
    )
}

pub(crate) async fn deletions(
    c: &mut PgConnection,
    spec: &SummarySpec,
    window: Interval,
    limits: &Limits,
) -> Result<Vec<Interval>, Error> {
    let mut gaps: Vec<_> = crate::lifecycle::fences(
        c,
        &spec.selection(),
        window,
        &["delete"],
        limits.max_points.get(),
    )
    .await?
    .into_iter()
    .filter(|f| {
        f.kind == "delete"
            && !f.restored
            && crate::lifecycle::overlaps(&f.selection, &spec.selection())
    })
    .map(|f| f.window)
    .collect();
    gaps.sort_by_key(|w| w.start());
    Ok(gaps)
}
pub(crate) fn mask(
    builder: &mut SummaryBuilder,
    gaps: &[Interval],
    at: Timestamp,
) -> Result<(), Error> {
    for gap in gaps {
        if gap.start() <= at
            && builder
                .last_observed_at()
                .is_some_and(|last| gap.end() > last && gap.start() >= last)
        {
            builder.interrupt(gap.start())?;
        }
    }
    Ok(())
}

pub(crate) async fn predecessor(
    c: &mut PgConnection,
    spec: &SummarySpec,
    at: Timestamp,
) -> Result<Option<Sample>, Error> {
    if matches!(
        spec.series().definition().spec().metric,
        Metric::Gauge { .. }
            | Metric::Counter {
                temporality: Temporality::Delta,
                ..
            }
    ) {
        return Ok(None);
    }
    let s = spec.stream();
    let raw:Option<Vec<u8>>=sqlx::query_scalar("SELECT raw FROM rss_timeseries.samples WHERE tenant_id=$1::text::uuid AND namespace=$2 AND source=$3 AND generation=$4 AND series_digest=$5 AND observed_at<$6 AND rss_timeseries.visible(convert_from(raw,'UTF8')::jsonb,observed_at) ORDER BY observed_at DESC,sequence DESC,sample_id DESC LIMIT 1")
 .bind(s.scope().tenant().to_string()).bind(s.scope().namespace().as_str()).bind(s.source().as_str()).bind(s.generation().as_str()).bind(spec.series().digest()?.as_bytes().as_slice()).bind(at.micros()).fetch_optional(c).await.map_err(sql_error)?;
    raw.map(|v| serde_json::from_slice(&v).map_err(|_| Error::Invariant))
        .transpose()
}
pub(crate) async fn ensure_boundary(
    c: &mut PgConnection,
    spec: &SummarySpec,
    at: Timestamp,
    prior: Option<&Sample>,
    limits: &Limits,
) -> Result<(), Error> {
    let observed_only = matches!(
        spec.series().definition().spec().metric,
        Metric::Bool | Metric::State { .. }
    ) && spec.coverage() == CoveragePolicy::ObservedOnly;
    let start = if observed_only {
        0
    } else {
        at.micros()
            .saturating_sub(i64::try_from(spec.lookback()).unwrap_or(i64::MAX))
            .max(0)
    };
    if start == at.micros() {
        return Ok(());
    }
    let window = Interval::new(Timestamp::new(start)?, at)?;
    for fence in crate::lifecycle::fences(
        c,
        &spec.selection(),
        window,
        &["pruned"],
        limits.max_points.get(),
    )
    .await?
    {
        if prior.is_none_or(|p| p.input().observed_at < fence.window.end()) {
            return Err(Error::HistoryExpired);
        }
    }
    Ok(())
}
