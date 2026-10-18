use super::*;
use crate::lifecycle::{covers, fences, overlaps};
async fn safe_raw(
    c: &mut PgConnection,
    r: &MaintenanceRequest,
    selection: &Selection,
    raw_before: Timestamp,
    summaries_before: Timestamp,
    now: i64,
    limits: &Limits,
) -> Result<Result<i64, MaintenanceBlock>, Error> {
    let fs = fences(
        c,
        selection,
        Interval::new(
            Timestamp::new(0)?,
            Timestamp::new(raw_before.micros().max(1))?,
        )?,
        &["cutoff", "delete"],
        limits.max_points.get(),
    )
    .await?;
    if raw_before.micros() > 0
        && !fs.iter().any(|f| {
            f.kind == "cutoff" && covers(&f.selection, selection) && f.window.end() >= raw_before
        })
    {
        return Ok(Err(MaintenanceBlock::Cutoff));
    }
    if fs.iter().any(|f| {
        f.kind == "delete"
            && !f.restored
            && f.until.is_some_and(|u| u > now)
            && f.window.start() < raw_before
            && overlaps(&f.selection, selection)
    }) {
        return Ok(Err(MaintenanceBlock::RestoreWindow));
    }
    let ranges=sqlx::query("SELECT spec,lo,hi FROM rss_timeseries.summary_ranges WHERE tenant_id=$1::text::uuid AND namespace=$2 AND hi>$3 AND rss_timeseries.matches($4::text::jsonb,convert_from(spec,'UTF8')::jsonb) LIMIT $5")
 .bind(r.scope().tenant().to_string()).bind(r.scope().namespace().as_str()).bind(summaries_before.micros()).bind(json(selection)?).bind(i64::from(limits.max_points.get())+1).fetch_all(&mut *c).await.map_err(sql_error)?;
    if ranges.len() > limits.max_points.get() as usize {
        return Err(Error::BudgetExceeded);
    }
    let mut halo = 0u64;
    let mut anchor_limit = raw_before.micros();
    for row in ranges {
        let spec: SummarySpec =
            serde_json::from_slice(&row.try_get::<Vec<u8>, _>("spec").map_err(sql_error)?)
                .map_err(|_| Error::Invariant)?;
        halo = halo.max(spec.lookback());
        if matches!(
            spec.series().definition().spec().metric,
            Metric::Bool | Metric::State { .. }
        ) && spec.coverage() == CoveragePolicy::ObservedOnly
            && let Some(prior) = crate::aggregate::predecessor(c, &spec, raw_before).await?
        {
            anchor_limit = anchor_limit.min(prior.input().observed_at.micros());
        }

        let lo: i64 = row.try_get("lo").map_err(sql_error)?;
        let hi: i64 = row.try_get("hi").map_err(sql_error)?;
        let start = lo.max(spec.bucket(summaries_before)?.start().micros());
        let end = hi.min(
            spec.bucket(Timestamp::new(raw_before.micros().saturating_sub(1))?)?
                .end()
                .micros(),
        );
        let complete:bool=sqlx::query_scalar("SELECT NOT EXISTS(SELECT FROM generate_series($4::bigint,$5::bigint-1,$6::bigint) x WHERE NOT EXISTS(SELECT FROM rss_timeseries.summaries WHERE tenant_id=$1::text::uuid AND namespace=$2 AND spec_digest=$3 AND lo=x AND NOT dirty))")
  .bind(r.scope().tenant().to_string()).bind(r.scope().namespace().as_str()).bind(spec.binding()?.as_bytes().as_slice()).bind(start).bind(end).bind(spec.resolution_micros().get() as i64).fetch_one(&mut *c).await.map_err(sql_error)?;
        if !complete {
            return Ok(Err(MaintenanceBlock::DirtySummary));
        }
    }
    Ok(Ok(raw_before
        .micros()
        .saturating_sub(i64::try_from(halo).unwrap_or(i64::MAX))
        .max(0)
        .min(anchor_limit)))
}
pub(super) async fn step(
    c: &mut PgConnection,
    r: &MaintenanceRequest,
    state: &mut State,
    now: i64,
    limits: &Limits,
) -> Result<Step, Error> {
    let MaintenanceAction::Prune {
        selection,
        raw_before,
        summaries_before,
    } = r.action()
    else {
        return Err(Error::Invariant);
    };
    let limit = match safe_raw(c, r, selection, *raw_before, *summaries_before, now, limits).await?
    {
        Ok(v) => v,
        Err(b) => return Ok(Step::Blocked(b)),
    };
    let raw_limit = match state.raw_limit {
        Some(v) => v,
        None => {
            // The fence is committed before any later bounded steps; new old input cannot race cleanup.
            put_fence(
                c,
                r,
                "pruned",
                selection,
                Interval::new(Timestamp::new(0)?, Timestamp::new(limit)?)?,
                None,
            )
            .await?;
            state.raw_limit = Some(limit);
            limit
        }
    };
    if raw_limit > limit {
        return Ok(Step::Blocked(MaintenanceBlock::DirtySummary));
    }
    let count: i32 = sqlx::query_scalar(
        "SELECT rss_timeseries.prune_rows($1::text::uuid,$2,$3::text::jsonb,$4,$5,$6)",
    )
    .bind(r.scope().tenant().to_string())
    .bind(r.scope().namespace().as_str())
    .bind(json(selection)?)
    .bind(raw_limit)
    .bind(summaries_before.micros())
    .bind(r.max_items().get() as i32)
    .fetch_one(c)
    .await
    .map_err(sql_error)?;
    let count = u32::try_from(count).map_err(|_| Error::Invariant)?;
    Ok(if count < r.max_items().get() {
        Step::Done(count)
    } else {
        Step::More(count)
    })
}
async fn receipt_guarantee(
    c: &mut PgConnection,
    s: &Stream,
    before: i64,
    now: i64,
) -> Result<bool, Error> {
    sqlx::query_scalar("SELECT EXISTS(SELECT FROM rss_timeseries.batches WHERE tenant_id=$1::text::uuid AND namespace=$2 AND source=$3 AND generation=$4 AND received_at<$5 AND replay_until>$6 AND NOT expired)").bind(s.scope().tenant().to_string()).bind(s.scope().namespace().as_str()).bind(s.source().as_str()).bind(s.generation().as_str()).bind(before).bind(now).fetch_one(c).await.map_err(sql_error)
}
pub(super) async fn expire(
    c: &mut PgConnection,
    r: &MaintenanceRequest,
    s: &Stream,
    before: Timestamp,
    now: i64,
) -> Result<Step, Error> {
    if receipt_guarantee(c, s, before.micros(), now).await? {
        return Ok(Step::Blocked(MaintenanceBlock::ReplayGuarantee));
    }
    let count: i32 =
        sqlx::query_scalar("SELECT rss_timeseries.expire_receipts($1::text::uuid,$2,$3,$4,$5,$6)")
            .bind(s.scope().tenant().to_string())
            .bind(s.scope().namespace().as_str())
            .bind(s.source().as_str())
            .bind(s.generation().as_str())
            .bind(before.micros())
            .bind(r.max_items().get() as i32)
            .fetch_one(c)
            .await
            .map_err(sql_error)?;
    let count = u32::try_from(count).map_err(|_| Error::Invariant)?;
    Ok(if count < r.max_items().get() {
        Step::Done(count)
    } else {
        Step::More(count)
    })
}
pub(super) async fn reclaim(
    c: &mut PgConnection,
    r: &MaintenanceRequest,
    s: &Stream,
    now: i64,
) -> Result<Step, Error> {
    if !crate::lifecycle::closed(c, s).await? {
        return Ok(Step::Blocked(MaintenanceBlock::StreamOpen));
    }
    if receipt_guarantee(c, s, i64::MAX, now).await? {
        return Ok(Step::Blocked(MaintenanceBlock::ReplayGuarantee));
    }
    let retained:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM rss_timeseries.samples WHERE tenant_id=$1::text::uuid AND namespace=$2 AND source=$3 AND generation=$4) OR EXISTS(SELECT FROM rss_timeseries.summaries WHERE tenant_id=$1::text::uuid AND namespace=$2 AND convert_from(spec,'UTF8')::jsonb#>>'{stream,source}'=$3 AND convert_from(spec,'UTF8')::jsonb#>>'{stream,generation}'=$4)").bind(s.scope().tenant().to_string()).bind(s.scope().namespace().as_str()).bind(s.source().as_str()).bind(s.generation().as_str()).fetch_one(&mut *c).await.map_err(sql_error)?;
    if retained {
        return Ok(Step::Blocked(MaintenanceBlock::RetainedData));
    }
    let count: i32 =
        sqlx::query_scalar("SELECT rss_timeseries.reclaim_rows($1::text::uuid,$2,$3,$4,$5)")
            .bind(s.scope().tenant().to_string())
            .bind(s.scope().namespace().as_str())
            .bind(s.source().as_str())
            .bind(s.generation().as_str())
            .bind(r.max_items().get() as i32)
            .fetch_one(c)
            .await
            .map_err(sql_error)?;
    let count = u32::try_from(count).map_err(|_| Error::Invariant)?;
    Ok(if count < r.max_items().get() {
        Step::Done(count)
    } else {
        Step::More(count)
    })
}
