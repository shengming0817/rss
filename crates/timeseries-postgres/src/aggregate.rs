use crate::transaction::Mode;
use crate::{
    Limits, PgStore,
    lifecycle::{availability, bytes},
    transaction::{certain, check, db_now, sql_error},
};
use rss_request_context::{Clock, Deadline};
use rss_timeseries::*;
use sqlx::{PgConnection, Row};
const DOMAIN: &[u8] = b"rss.timeseries.aggregate.v2";

mod cache;
mod page;
pub(crate) mod scan;
pub(crate) async fn store(
    c: &mut PgConnection,
    spec: &SummarySpec,
    summary: &Summary,
    delete_from: Timestamp,
    gap_sensitive: bool,
    limits: &Limits,
) -> Result<(), Error> {
    let data = bytes(summary)?;
    if data.len() > limits.max_bytes.get() as usize {
        return Err(Error::BudgetExceeded);
    }
    let start = summary.window.start().micros();
    // Writes can fill an empty Gauge prefix or introduce a missing predecessor.
    let impact_start = if delete_from < summary.window.start() {
        delete_from.micros()
    } else {
        dependency_start(spec, start)
    };
    sqlx::query("SELECT rss_timeseries.put_summary($1::text::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)")
        .bind(spec.stream().scope().tenant().to_string())
        .bind(spec.stream().scope().namespace().as_str())
        .bind(spec.binding()?.as_bytes().as_slice())
        .bind(spec.semantics()?.as_bytes().as_slice())
        .bind(spec.stream().source().as_str())
        .bind(spec.stream().generation().as_str())
        .bind(spec.series().digest()?.as_bytes().as_slice())
        .bind(spec.series().subject().as_str())
        .bind(spec.series().resource().as_str())
        .bind(spec.series().definition().spec().key.as_str())
        .bind(start)
        .bind(summary.window.end().micros())
        .bind(impact_start)
        .bind(delete_from.micros())
        .bind(gap_sensitive)
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
                Mode::Snapshot,
                move |c, clock| {
                    Box::pin(async move {
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
                        let page =
                            page::collect(c, &q, &available, &limits, at, clock, deadline).await?;
                        at = page.at;
                        let next = if at < q.query().window().end() {
                            Some(key.seal(DOMAIN, binding, &instance, expires, &at)?)
                        } else {
                            None
                        };
                        Ok(AggregatePage {
                            buckets: page.buckets,
                            availability: available,
                            resolution_micros: q.resolution_micros(),
                            refreshed_through: page.refreshed,
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
    limits: &Limits,
) -> Result<Option<Sample>, Error> {
    if !needs_predecessor(spec) {
        return Ok(None);
    }
    let row = predecessor_row(c, spec, at, Some(limits.max_bytes.get())).await?;
    row.map(|row| {
        let raw = row
            .try_get::<Option<&[u8]>, _>("raw")
            .map_err(sql_error)?
            .ok_or(Error::BudgetExceeded)?;
        serde_json::from_slice(raw).map_err(|_| Error::Invariant)
    })
    .transpose()
}
pub(crate) async fn predecessor_time(
    c: &mut PgConnection,
    spec: &SummarySpec,
    at: Timestamp,
) -> Result<Option<Timestamp>, Error> {
    predecessor_row(c, spec, at, None)
        .await?
        .map(|row| Timestamp::new(row.try_get("observed_at").map_err(sql_error)?))
        .transpose()
}

async fn predecessor_row(
    c: &mut PgConnection,
    spec: &SummarySpec,
    at: Timestamp,
    max_bytes: Option<u32>,
) -> Result<Option<sqlx::postgres::PgRow>, Error> {
    let s = spec.stream();
    sqlx::query("SELECT observed_at,CASE WHEN $7::bigint IS NOT NULL AND octet_length(raw)::bigint <= $7 THEN raw END AS raw
        FROM rss_timeseries.samples WHERE tenant_id=$1::text::uuid AND namespace=$2 AND source=$3
        AND generation=$4 AND series_digest=$5 AND observed_at<$6 AND observed_at>=$8
        AND rss_timeseries.visible(tenant_id,namespace,source,generation,series_digest,subject,resource,key,observed_at)
        ORDER BY observed_at DESC,sequence DESC,sample_id DESC LIMIT 1")
        .bind(s.scope().tenant().to_string()).bind(s.scope().namespace().as_str())
        .bind(s.source().as_str()).bind(s.generation().as_str())
        .bind(spec.series().digest()?.as_bytes().as_slice()).bind(at.micros())
        .bind(max_bytes.map(i64::from)).bind(dependency_start(spec,at.micros())).fetch_optional(c).await.map_err(sql_error)
}
pub(crate) async fn ensure_boundary(
    c: &mut PgConnection,
    spec: &SummarySpec,
    at: Timestamp,
    prior: Option<&Sample>,
    limits: &Limits,
) -> Result<(), Error> {
    if !needs_predecessor(spec) {
        return Ok(());
    }
    let start = dependency_start(spec, at.micros());
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

// Earliest observation that can affect a bucket starting at this timestamp.
fn dependency_start(spec: &SummarySpec, start: i64) -> i64 {
    if !needs_predecessor(spec) {
        start
    } else if needs_history_anchor(spec) {
        0
    } else {
        start
            .saturating_sub(i64::try_from(spec.lookback()).unwrap_or(i64::MAX))
            .max(0)
    }
}

// Reset/invalid predecessor flags for cumulative counters are evaluated before
// max_gap. ObservedOnly transitions likewise depend on the last visible state.
pub(crate) fn needs_history_anchor(spec: &SummarySpec) -> bool {
    match spec.series().definition().spec().metric {
        Metric::Counter {
            temporality: Temporality::Cumulative,
            ..
        } => true,
        Metric::Bool | Metric::State { .. } => spec.coverage() == CoveragePolicy::ObservedOnly,
        _ => false,
    }
}

// Delta intervals contain their own increase; only cumulative/state semantics
// depend on an earlier observation. Share this classification with both readers.
fn needs_predecessor(spec: &SummarySpec) -> bool {
    matches!(
        spec.series().definition().spec().metric,
        Metric::Counter {
            temporality: Temporality::Cumulative,
            ..
        } | Metric::Bool
            | Metric::State { .. }
    )
}
