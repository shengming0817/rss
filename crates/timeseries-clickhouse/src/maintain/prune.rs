use super::*;
use crate::{projection::literal, read::selection};
#[derive(Serialize, Deserialize)]
pub(super) struct Cleanup {
    raw_limit: i64,
    drained: bool,
    pending_summaries: Vec<String>,
}
async fn safe_limit<C: Clock>(
    store: &ChStore<C>,
    c: &mut PgConnection,
    r: &MaintenanceRequest,
    sel: &Selection,
    raw_before: Timestamp,
    summaries_before: Timestamp,
    boundary: i64,
    time: i64,
    deadline: Deadline,
) -> Result<Result<i64, MaintenanceBlock>, Error> {
    let fences = control::fences(c, r.scope(), store.limits.max_points.get()).await?;
    if raw_before.micros() > 0
        && !fences.iter().any(|f| {
            f.kind == "cutoff" && control::covers(&f.selection, sel) && f.window.end() >= raw_before
        })
    {
        return Ok(Err(MaintenanceBlock::Cutoff));
    }
    if fences.iter().any(|f| {
        f.kind == "delete"
            && !f.restored
            && control::overlaps(&f.selection, sel)
            && f.window.start() < raw_before
            && f.until.is_some_and(|u| u > time)
    }) {
        return Ok(Err(MaintenanceBlock::RestoreWindow));
    }
    if raw_before.micros() == 0 {
        return Ok(Ok(0));
    }
    let rows=sqlx::query("SELECT spec,lo,hi FROM rss_ts_ch.ranges WHERE tenant_id=$1::text::uuid AND namespace=$2 AND hi>$3 LIMIT $4")
        .bind(r.scope().tenant().to_string()).bind(r.scope().namespace().as_str()).bind(summaries_before.micros()).bind(i64::from(store.limits.max_points.get())+1).fetch_all(&mut *c).await.map_err(sql_error)?;
    if rows.len() > store.limits.max_points.get() as usize {
        return Err(Error::BudgetExceeded);
    }
    let mut limit = raw_before.micros();
    for row in rows {
        let spec: SummarySpec = decode(&row.try_get::<Vec<u8>, _>("spec").map_err(sql_error)?)?;
        if !control::overlaps(sel, &spec.selection()) {
            continue;
        }
        limit = limit.min(
            raw_before
                .micros()
                .saturating_sub(i64::try_from(spec.lookback()).unwrap_or(i64::MAX))
                .max(0),
        );
        if matches!(
            spec.series().definition().spec().metric,
            Metric::Bool | Metric::State { .. }
        ) && spec.coverage() == CoveragePolicy::ObservedOnly
        {
            if let Some(prior) = store
                .predecessor(&spec, raw_before, boundary, &fences, deadline)
                .await?
            {
                limit = limit.min(prior.input().observed_at.micros());
            }
        }
        let lo = row
            .try_get::<i64, _>("lo")
            .map_err(sql_error)?
            .max(spec.bucket(summaries_before)?.start().micros());
        let hi = row.try_get::<i64, _>("hi").map_err(sql_error)?.min(
            spec.bucket(Timestamp::new(raw_before.micros().saturating_sub(1))?)?
                .end()
                .micros(),
        );
        let complete:bool=sqlx::query_scalar("SELECT NOT EXISTS(SELECT FROM generate_series($4::bigint,$5::bigint-1,$6::bigint) x WHERE NOT EXISTS(SELECT FROM rss_ts_ch.summaries WHERE tenant_id=$1::text::uuid AND namespace=$2 AND spec_digest=$3 AND lo=x AND NOT dirty))")
            .bind(r.scope().tenant().to_string()).bind(r.scope().namespace().as_str()).bind(spec.binding()?.as_bytes().as_slice()).bind(lo).bind(hi).bind(spec.resolution_micros().get() as i64).fetch_one(&mut *c).await.map_err(sql_error)?;
        if !complete {
            return Ok(Err(MaintenanceBlock::DirtySummary));
        }
    }
    Ok(Ok(limit))
}
pub(super) async fn step<C: Clock>(
    store: &ChStore<C>,
    c: &mut PgConnection,
    r: &MaintenanceRequest,
    state: &mut State,
    boundary: i64,
    time: i64,
    deadline: Deadline,
) -> Result<Step, Error> {
    let MaintenanceAction::Prune {
        selection: sel,
        raw_before,
        summaries_before,
    } = r.action()
    else {
        return Err(Error::Invariant);
    };
    let limit = match safe_limit(
        store,
        c,
        r,
        sel,
        *raw_before,
        *summaries_before,
        boundary,
        time,
        deadline,
    )
    .await?
    {
        Ok(v) => v,
        Err(reason) => return Ok(Step::Blocked(reason)),
    };
    if state.cleanup.is_none() {
        if limit > 0 {
            control::put_fence(
                c,
                r,
                "pruned",
                sel,
                Interval::new(Timestamp::new(0)?, Timestamp::new(limit)?)?,
                None,
            )
            .await?;
        }
        sqlx::query("UPDATE rss_ts_ch.attempts SET allowed=false WHERE tenant_id=$1::text::uuid AND namespace=$2")
            .bind(r.scope().tenant().to_string()).bind(r.scope().namespace().as_str()).execute(&mut *c).await.map_err(sql_error)?;
        if limit == 0 {
            control::bump(c, r.scope()).await?;
        }
        state.cleanup = Some(Cleanup {
            raw_limit: limit,
            drained: false,
            pending_summaries: Vec::new(),
        });
        return Ok(Step::More(0));
    }
    let cleanup = state.cleanup.as_mut().ok_or(Error::Invariant)?;
    if cleanup.raw_limit > limit {
        return Ok(Step::Blocked(MaintenanceBlock::DirtySummary));
    }
    if !cleanup.drained {
        let ids=sqlx::query_scalar::<_,String>("SELECT query_id::text FROM rss_ts_ch.attempts WHERE tenant_id=$1::text::uuid AND namespace=$2 AND NOT allowed AND NOT drained ORDER BY id LIMIT $3")
            .bind(r.scope().tenant().to_string()).bind(r.scope().namespace().as_str()).bind(i64::from(r.budget().rows.get())).fetch_all(&mut *c).await.map_err(sql_error)?;
        store.drain(&ids, deadline).await?;
        sqlx::query("DELETE FROM rss_ts_ch.attempts WHERE tenant_id=$1::text::uuid AND namespace=$2 AND query_id::text=ANY($3) AND NOT allowed")
            .bind(r.scope().tenant().to_string()).bind(r.scope().namespace().as_str()).bind(&ids).execute(&mut *c).await.map_err(sql_error)?;
        cleanup.drained = ids.len() < r.budget().rows.get() as usize;
        return Ok(Step::More(
            u32::try_from(ids.len()).map_err(|_| Error::Invariant)?,
        ));
    }
    // No timestamp predicate can remove data from a later authorized generation.
    // Delete a bounded set of immutable identities only after their attempts drained.
    let condition = format!("{} AND observed_at<{}", selection(sel)?, cleanup.raw_limit);
    let rows = store
        .raw_rows(
            &condition,
            "observed_at,source,generation,sample_id",
            r.budget().rows.get(),
            deadline,
        )
        .await?;
    if !rows.is_empty() {
        let identities = rows
            .iter()
            .take(r.budget().rows.get() as usize)
            .map(|v| {
                format!(
                    "({},{},{})",
                    literal(&v.source),
                    literal(&v.generation),
                    literal(&v.sample_id)
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let predicate = format!(
            "tenant={} AND namespace={} AND (source,generation,sample_id) IN ({identities})",
            literal(&r.scope().tenant().to_string()),
            literal(r.scope().namespace().as_str())
        );
        delete(store, "raw", &predicate, deadline).await?;
        return Ok(Step::More(
            u32::try_from(rows.len().min(r.budget().rows.get() as usize))
                .map_err(|_| Error::Invariant)?,
        ));
    }
    prune_summaries(store, c, r, sel, *summaries_before, cleanup, deadline).await
}
async fn delete<C: Clock>(
    store: &ChStore<C>,
    table: &str,
    predicate: &str,
    deadline: Deadline,
) -> Result<(), Error> {
    store
        .ch_query(
            &store.ch.maintenance,
            &format!("ALTER TABLE rss_ts_ch.{table} DELETE WHERE {predicate}"),
            deadline,
        )?
        .with_setting("mutations_sync", "1")
        .execute()
        .await
        .map_err(|_| Error::Unavailable)?;
    let count = store
        .ch_query(
            &store.ch.maintenance,
            &format!("SELECT count() FROM rss_ts_ch.{table} WHERE {predicate}"),
            deadline,
        )?
        .fetch_all::<u64>()
        .await
        .map_err(|_| Error::Unavailable)?;
    if count != vec![0] {
        return Err(Error::Unavailable);
    }
    Ok(())
}
async fn prune_summaries<C: Clock>(
    store: &ChStore<C>,
    c: &mut PgConnection,
    r: &MaintenanceRequest,
    sel: &Selection,
    before: Timestamp,
    cleanup: &mut Cleanup,
    deadline: Deadline,
) -> Result<Step, Error> {
    if !cleanup.pending_summaries.is_empty() {
        let predicate = format!(
            "tenant={} AND namespace={} AND object_id IN ({})",
            literal(&r.scope().tenant().to_string()),
            literal(r.scope().namespace().as_str()),
            cleanup
                .pending_summaries
                .iter()
                .map(|v| literal(v))
                .collect::<Vec<_>>()
                .join(",")
        );
        delete(store, "summaries", &predicate, deadline).await?;
        let count = cleanup.pending_summaries.len();
        cleanup.pending_summaries.clear();
        return Ok(Step::More(
            u32::try_from(count).map_err(|_| Error::Invariant)?,
        ));
    }
    let rows=sqlx::query("SELECT spec,object_id::text,spec_digest,lo FROM rss_ts_ch.summaries WHERE tenant_id=$1::text::uuid AND namespace=$2 AND hi<=$3 ORDER BY lo LIMIT $4")
        .bind(r.scope().tenant().to_string()).bind(r.scope().namespace().as_str()).bind(before.micros()).bind(i64::from(store.limits.max_points.get())+1).fetch_all(&mut *c).await.map_err(sql_error)?;
    if rows.len() > store.limits.max_points.get() as usize {
        return Err(Error::BudgetExceeded);
    }
    let mut ids = Vec::new();
    for row in rows {
        let spec: SummarySpec = decode(&row.try_get::<Vec<u8>, _>("spec").map_err(sql_error)?)?;
        if !control::covers(sel, &spec.selection()) {
            continue;
        }
        ids.push(row.try_get::<String, _>("object_id").map_err(sql_error)?);
        if ids.len() == r.budget().rows.get() as usize {
            break;
        }
    }
    if !ids.is_empty() {
        sqlx::query("DELETE FROM rss_ts_ch.summaries WHERE tenant_id=$1::text::uuid AND namespace=$2 AND object_id::text=ANY($3)")
            .bind(r.scope().tenant().to_string()).bind(r.scope().namespace().as_str()).bind(&ids).execute(&mut *c).await.map_err(sql_error)?;
        cleanup.pending_summaries = ids.clone();
        return Ok(Step::More(
            u32::try_from(ids.len()).map_err(|_| Error::Invariant)?,
        ));
    }
    // Old unreferenced summary objects are also removed, never imported back into canonical refs.
    let active=sqlx::query_scalar::<_,String>("SELECT object_id::text FROM rss_ts_ch.summaries WHERE tenant_id=$1::text::uuid AND namespace=$2 UNION SELECT id::text FROM rss_ts_ch.attempts WHERE tenant_id=$1::text::uuid AND namespace=$2 AND allowed AND target='summaries' LIMIT $3")
        .bind(r.scope().tenant().to_string()).bind(r.scope().namespace().as_str()).bind(i64::from(store.limits.max_points.get())+1).fetch_all(&mut *c).await.map_err(sql_error)?;
    if active.len() > store.limits.max_points.get() as usize {
        return Err(Error::BudgetExceeded);
    }
    let exclude = if active.is_empty() {
        String::new()
    } else {
        format!(
            " AND object_id NOT IN ({})",
            active
                .iter()
                .map(|v| literal(v))
                .collect::<Vec<_>>()
                .join(",")
        )
    };
    let base = format!(
        "tenant={} AND namespace={}{}",
        literal(&r.scope().tenant().to_string()),
        literal(r.scope().namespace().as_str()),
        exclude
    );
    let orphans = store
        .ch_query(
            &store.ch.maintenance,
            &format!(
                "SELECT object_id FROM rss_ts_ch.summaries FINAL WHERE {base} LIMIT {}",
                r.budget().rows.get()
            ),
            deadline,
        )?
        .fetch_all::<String>()
        .await
        .map_err(|_| Error::Unavailable)?;
    if !orphans.is_empty() {
        delete(
            store,
            "summaries",
            &format!(
                "{base} AND object_id IN ({})",
                orphans
                    .iter()
                    .map(|v| literal(v))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            deadline,
        )
        .await?;
        return Ok(Step::More(
            u32::try_from(orphans.len()).map_err(|_| Error::Invariant)?,
        ));
    }
    Ok(Step::Done(0))
}
pub(super) async fn reclaim<C: Clock>(
    store: &ChStore<C>,
    c: &mut PgConnection,
    s: &Stream,
    limit: u32,
    time: i64,
    deadline: Deadline,
) -> Result<Step, Error> {
    let scope = s.scope();
    let closed:Option<bool>=sqlx::query_scalar("SELECT closed FROM rss_ts_ch.streams WHERE tenant_id=$1::text::uuid AND namespace=$2 AND source=$3 AND generation=$4")
        .bind(scope.tenant().to_string()).bind(scope.namespace().as_str()).bind(s.source().as_str()).bind(s.generation().as_str()).fetch_optional(&mut *c).await.map_err(sql_error)?;
    if closed != Some(true) {
        return Ok(Step::Blocked(MaintenanceBlock::StreamOpen));
    }
    let predicate = format!(
        "tenant={} AND namespace={} AND source={} AND generation={}",
        literal(&scope.tenant().to_string()),
        literal(scope.namespace().as_str()),
        literal(s.source().as_str()),
        literal(s.generation().as_str())
    );
    if !store
        .raw_rows(&predicate, "sample_id", 0, deadline)
        .await?
        .is_empty()
    {
        return Ok(Step::Blocked(MaintenanceBlock::RetainedData));
    }
    let fs = control::fences(c, scope, store.limits.max_points.get()).await?;
    if fs
        .iter()
        .any(|f| f.kind == "delete" && !f.restored && f.until.is_some_and(|u| u > time))
    {
        return Ok(Step::Blocked(MaintenanceBlock::RestoreWindow));
    }
    let specs=sqlx::query_scalar::<_,Vec<u8>>("SELECT spec FROM rss_ts_ch.summaries WHERE tenant_id=$1::text::uuid AND namespace=$2 LIMIT $3")
        .bind(scope.tenant().to_string()).bind(scope.namespace().as_str()).bind(i64::from(store.limits.max_points.get())+1).fetch_all(&mut *c).await.map_err(sql_error)?;
    if specs.len() > store.limits.max_points.get() as usize {
        return Err(Error::BudgetExceeded);
    }
    for spec in specs {
        if decode::<SummarySpec>(&spec)?.stream() == s {
            return Ok(Step::Blocked(MaintenanceBlock::RetainedData));
        }
    }
    let live:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM rss_ts_ch.batches WHERE tenant_id=$1::text::uuid AND namespace=$2 AND source=$3 AND generation=$4 AND (NOT expired OR replay_until>$5))")
        .bind(scope.tenant().to_string()).bind(scope.namespace().as_str()).bind(s.source().as_str()).bind(s.generation().as_str()).bind(time).fetch_one(&mut *c).await.map_err(sql_error)?;
    if live {
        return Ok(Step::Blocked(MaintenanceBlock::ReplayGuarantee));
    }
    let mut count = 0;
    for sql in [
        "DELETE FROM rss_ts_ch.batches WHERE ctid IN (SELECT ctid FROM rss_ts_ch.batches WHERE tenant_id=$1::text::uuid AND namespace=$2 AND source=$3 AND generation=$4 LIMIT $5)",
        "DELETE FROM rss_ts_ch.identities WHERE ctid IN (SELECT ctid FROM rss_ts_ch.identities WHERE tenant_id=$1::text::uuid AND namespace=$2 AND source=$3 AND generation=$4 LIMIT $5)",
    ] {
        let n = sqlx::query(sql)
            .bind(scope.tenant().to_string())
            .bind(scope.namespace().as_str())
            .bind(s.source().as_str())
            .bind(s.generation().as_str())
            .bind(i64::from(limit - count))
            .execute(&mut *c)
            .await
            .map_err(sql_error)?
            .rows_affected();
        count += u32::try_from(n).map_err(|_| Error::Invariant)?;
        if count == limit {
            return Ok(Step::More(count));
        }
    }
    sqlx::query("UPDATE rss_ts_ch.streams SET reclaimed=true WHERE tenant_id=$1::text::uuid AND namespace=$2 AND source=$3 AND generation=$4")
        .bind(scope.tenant().to_string()).bind(scope.namespace().as_str()).bind(s.source().as_str()).bind(s.generation().as_str()).execute(&mut *c).await.map_err(sql_error)?;
    Ok(Step::Done(count))
}
