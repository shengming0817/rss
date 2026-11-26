use crate::transaction::{bytes, decode, sql_error};
use rss_timeseries::*;
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, Row};

pub(crate) async fn pending(c: &mut PgConnection, s: &Scope) -> Result<bool, Error> {
    sqlx::query_scalar("SELECT EXISTS(SELECT FROM rss_ts_ch.batches WHERE tenant_id=$1::text::uuid AND namespace=$2 AND phase IN ('prepared','verified'))")
        .bind(s.tenant().to_string()).bind(s.namespace().as_str()).fetch_one(c).await.map_err(sql_error)
}
pub(crate) async fn invalidate(
    c: &mut PgConnection,
    s: &Scope,
    selection: &Selection,
    window: Interval,
    max: u32,
) -> Result<(), Error> {
    let rows = invalidation_targets(c, s, selection, window, max).await?;
    let mut digests = Vec::<Vec<u8>>::new();
    let mut starts = Vec::<i64>::new();
    for row in rows {
        let spec: SummarySpec = decode(row.try_get::<&[u8], _>("spec").map_err(sql_error)?)?;
        if overlaps(selection, &spec.selection()) {
            digests.push(row.try_get("spec_digest").map_err(sql_error)?);
            starts.push(row.try_get("lo").map_err(sql_error)?);
        }
    }
    if !digests.is_empty() {
        let changed = sqlx::query(
            "UPDATE rss_ts_ch.summaries s SET dirty_from=0
             FROM unnest($3::bytea[], $4::bigint[]) AS target(digest, lo)
             WHERE s.tenant_id=$1::text::uuid AND s.namespace=$2
               AND s.spec_digest=target.digest AND s.lo=target.lo",
        )
        .bind(s.tenant().to_string())
        .bind(s.namespace().as_str())
        .bind(&digests)
        .bind(&starts)
        .execute(&mut *c)
        .await
        .map_err(sql_error)?
        .rows_affected();
        if changed != digests.len() as u64 {
            return Err(Error::Invariant);
        }
        #[cfg(feature = "integration")]
        crate::measurement::record(|m| m.updated += changed);
    }
    bump(c, s).await
}
/// Filter the durable specs before applying the maintenance result budget.
async fn invalidation_targets(
    c: &mut PgConnection,
    s: &Scope,
    selection: &Selection,
    window: Interval,
    max: u32,
) -> Result<Vec<sqlx::postgres::PgRow>, Error> {
    let selection = String::from_utf8(bytes(selection)?).map_err(|_| Error::Invariant)?;
    let rows = sqlx::query("SELECT spec,spec_digest,lo FROM rss_ts_ch.summaries CROSS JOIN LATERAL (SELECT convert_from(spec,'UTF8')::jsonb AS doc) d WHERE tenant_id=$1::text::uuid AND namespace=$2 AND hi>$3 AND dependency_start<$6 AND dirty_from IS DISTINCT FROM 0 AND CASE WHEN $5::text::jsonb->>'selection'='exact' THEN doc->'stream'=$5::text::jsonb->'stream' AND doc->'series'=$5::text::jsonb->'series' ELSE doc->'stream'->'scope'=$5::text::jsonb->'scope' AND doc->'series'->'subject'=$5::text::jsonb->'subject' AND doc->'series'->'resource'=$5::text::jsonb->'resource' AND ($5::text::jsonb->'keys'='[]'::jsonb OR ($5::text::jsonb->'keys') ? (doc->'series'->'definition'->>'key')) END LIMIT $4")
        .bind(s.tenant().to_string()).bind(s.namespace().as_str()).bind(window.start().micros()).bind(i64::from(max)+1).bind(selection).bind(window.end().micros()).fetch_all(c).await.map_err(sql_error)?;
    #[cfg(feature = "integration")]
    crate::measurement::record(|m| m.candidates += rows.len());
    if rows.len() > max as usize {
        return Err(Error::BudgetExceeded);
    }
    Ok(rows)
}
pub(crate) async fn bump(c: &mut PgConnection, s: &Scope) -> Result<(), Error> {
    sqlx::query("UPDATE rss_ts_ch.namespaces SET revision=revision+1 WHERE tenant_id=$1::text::uuid AND namespace=$2")
        .bind(s.tenant().to_string()).bind(s.namespace().as_str()).execute(c).await.map_err(sql_error)?;
    Ok(())
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Fence {
    pub id: Id,
    pub kind: String,
    pub selection: Selection,
    pub window: Interval,
    pub until: Option<i64>,
    pub restored: bool,
}
pub(crate) async fn fences(c: &mut PgConnection, s: &Scope, max: u32) -> Result<Vec<Fence>, Error> {
    let rows=sqlx::query("SELECT id,kind,selection::text,lo,hi,restore_until,restored FROM rss_ts_ch.fences WHERE tenant_id=$1::text::uuid AND namespace=$2 ORDER BY lo,id LIMIT $3")
        .bind(s.tenant().to_string()).bind(s.namespace().as_str()).bind(i64::from(max)+1).fetch_all(c).await.map_err(sql_error)?;
    #[cfg(feature = "integration")]
    crate::measurement::record(|m| {
        use sqlx::ValueRef;
        m.fence_rows += rows.len();
        for row in &rows {
            for i in 0..row.len() {
                if let Ok(value) = row.try_get_raw(i)
                    && !value.is_null()
                    && let Ok(bytes) = value.as_bytes()
                {
                    m.fence_bytes += bytes.len();
                }
            }
        }
    });
    if rows.len() > max as usize {
        return Err(Error::BudgetExceeded);
    }
    rows.into_iter().map(fence).collect()
}
fn fence(r: sqlx::postgres::PgRow) -> Result<Fence, Error> {
    Ok(Fence {
        id: Id::new(r.try_get::<String, _>("id").map_err(sql_error)?)?,
        kind: r.try_get("kind").map_err(sql_error)?,
        selection: decode(
            r.try_get::<String, _>("selection")
                .map_err(sql_error)?
                .as_bytes(),
        )?,
        window: Interval::new(
            Timestamp::new(r.try_get("lo").map_err(sql_error)?)?,
            Timestamp::new(r.try_get("hi").map_err(sql_error)?)?,
        )?,
        until: r.try_get("restore_until").map_err(sql_error)?,
        restored: r.try_get("restored").map_err(sql_error)?,
    })
}
/// Both selector shapes denormalize to the same subject/resource index expressions.
pub(crate) async fn visible_fences(
    c: &mut PgConnection,
    q: &Query,
    start: i64,
    limits: &crate::Limits,
    include_restored: bool,
) -> Result<Vec<Fence>, Error> {
    use futures::TryStreamExt;
    let sel = q.selection();
    let (subject, resource) = match sel {
        Selection::Exact { series, .. } => (series.subject(), series.resource()),
        Selection::Resource {
            subject, resource, ..
        } => (subject, resource),
    };
    let doc = String::from_utf8(bytes(sel)?).map_err(|_| Error::Invariant)?;
    let mut rows = sqlx::query(include_str!("visible_fences.sql"))
        .bind(sel.scope().tenant().to_string())
        .bind(sel.scope().namespace().as_str())
        .bind(subject.as_str())
        .bind(resource.as_str())
        .bind(start)
        .bind(q.window().end().micros())
        .bind(doc)
        .bind(i64::from(limits.max_fences.get()) + 1)
        .bind(include_restored)
        .fetch(c);
    let mut result = Vec::new();
    let mut remaining = limits.max_bytes.get() as usize;
    while let Some(row) = rows.try_next().await.map_err(sql_error)? {
        if result.len() >= limits.max_fences.get() as usize {
            return Err(Error::BudgetExceeded);
        }
        let size = row
            .try_get::<&str, _>("selection")
            .map_err(sql_error)?
            .len()
            + row.try_get::<&str, _>("id").map_err(sql_error)?.len()
            + 32;
        remaining = remaining.checked_sub(size).ok_or(Error::BudgetExceeded)?;
        result.push(fence(row)?);
    }
    Ok(result)
}

pub(crate) async fn fence_changed(c: &mut PgConnection, s: &Scope) -> Result<(), Error> {
    sqlx::query("UPDATE rss_ts_ch.namespaces SET fence_epoch=fence_epoch+1 WHERE tenant_id=$1::text::uuid AND namespace=$2")
      .bind(s.tenant().to_string()).bind(s.namespace().as_str()).execute(c).await.map_err(sql_error)?;
    Ok(())
}
pub(crate) async fn put_fence(
    c: &mut PgConnection,
    r: &MaintenanceRequest,
    kind: &str,
    selection: &Selection,
    window: Interval,
    until: Option<i64>,
    max: u32,
) -> Result<(), Error> {
    // Namespace mutation lock serializes frontier replacement. Delete fences keep
    // their identity for Restore; monotone frontiers keep only uncovered bounds.
    if matches!(kind, "cutoff" | "pruned") {
        let selection = String::from_utf8(bytes(selection)?).map_err(|_| Error::Invariant)?;
        let covered: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM rss_ts_ch.fences WHERE tenant_id=$1::text::uuid AND namespace=$2 AND kind=$3 AND selection=$4::text::jsonb AND lo<=$5 AND hi>=$6)")
            .bind(r.scope().tenant().to_string()).bind(r.scope().namespace().as_str()).bind(kind).bind(&selection).bind(window.start().micros()).bind(window.end().micros()).fetch_one(&mut *c).await.map_err(sql_error)?;
        if covered {
            return Ok(()); // reason: plans retain each operation's replay identity.
        }
        sqlx::query("DELETE FROM rss_ts_ch.fences WHERE tenant_id=$1::text::uuid AND namespace=$2 AND kind=$3 AND selection=$4::text::jsonb AND lo>=$5 AND hi<=$6")
            .bind(r.scope().tenant().to_string()).bind(r.scope().namespace().as_str()).bind(kind).bind(&selection).bind(window.start().micros()).bind(window.end().micros()).execute(&mut *c).await.map_err(sql_error)?;
    }
    sqlx::query("INSERT INTO rss_ts_ch.fences(tenant_id,namespace,id,kind,selection,lo,hi,restore_until) VALUES($1::text::uuid,$2,$3,$4,$5::text::jsonb,$6,$7,$8)")
        .bind(r.scope().tenant().to_string()).bind(r.scope().namespace().as_str()).bind(r.id().as_str()).bind(kind).bind(String::from_utf8(bytes(selection)?).map_err(|_|Error::Invariant)?).bind(window.start().micros()).bind(window.end().micros()).bind(until).execute(&mut *c).await.map_err(sql_error)?;
    // Reject new distinct frontiers atomically, before poisoning future reads.
    let count:i64 = sqlx::query_scalar("SELECT count(*) FROM (SELECT 1 FROM rss_ts_ch.fences WHERE tenant_id=$1::text::uuid AND namespace=$2 LIMIT $3) bounded")
        .bind(r.scope().tenant().to_string()).bind(r.scope().namespace().as_str()).bind(i64::from(max)+1).fetch_one(&mut *c).await.map_err(sql_error)?;
    if count > i64::from(max) {
        return Err(Error::BudgetExceeded);
    }
    if kind == "pruned" {
        fence_changed(c, r.scope()).await?;
    }
    bump(c, r.scope()).await
}
pub(crate) fn availability(query: &Query, fences: &[Fence]) -> Result<Availability, Error> {
    let excluded = fences
        .iter()
        .filter(|f| {
            (f.kind == "pruned" || (f.kind == "delete" && !f.restored))
                && overlaps(&f.selection, query.selection())
        })
        .filter_map(|f| {
            let lo = f.window.start().max(query.window().start());
            let hi = f.window.end().min(query.window().end());
            (lo < hi).then(|| {
                Ok(UnavailableRange {
                    selection: f.selection.clone(),
                    window: Interval::new(lo, hi)?,
                    reason: if f.kind == "pruned" {
                        UnavailableReason::Pruned
                    } else {
                        UnavailableReason::Deleted
                    },
                })
            })
        })
        .collect::<Result<_, Error>>()?;
    Ok(Availability { excluded })
}
fn resource_matches(sel: &Selection, stream: &Stream, series: &Series) -> bool {
    match sel {
        Selection::Exact {
            stream: s,
            series: d,
        } => s == stream && d == series,
        Selection::Resource {
            scope,
            subject,
            resource,
            keys,
        } => {
            scope == stream.scope()
                && subject == series.subject()
                && resource == series.resource()
                && (keys.is_empty() || keys.contains(&series.definition().spec().key))
        }
    }
}
pub(crate) fn overlaps(a: &Selection, b: &Selection) -> bool {
    match (a, b) {
        (Selection::Exact { stream, series }, _) => resource_matches(b, stream, series),
        (_, Selection::Exact { stream, series }) => resource_matches(a, stream, series),
        (
            Selection::Resource {
                scope: a,
                subject: b,
                resource: c,
                keys: d,
            },
            Selection::Resource {
                scope: e,
                subject: f,
                resource: g,
                keys: h,
            },
        ) => a == e && b == f && c == g && (d.is_empty() || h.is_empty() || !d.is_disjoint(h)),
    }
}
pub(crate) fn covers(a: &Selection, b: &Selection) -> bool {
    match (a, b) {
        (_, Selection::Exact { stream, series }) => resource_matches(a, stream, series),
        (
            Selection::Resource {
                scope: a,
                subject: b,
                resource: c,
                keys: d,
            },
            Selection::Resource {
                scope: e,
                subject: f,
                resource: g,
                keys: h,
            },
        ) => a == e && b == f && c == g && (d.is_empty() || (!h.is_empty() && h.is_subset(d))),
        _ => false,
    }
}
