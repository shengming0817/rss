use crate::transaction::sql_error;
use rss_timeseries::*;
use sqlx::{PgConnection, Row};

pub(crate) fn json(v: &impl serde::Serialize) -> Result<String, Error> {
    serde_json::to_string(v).map_err(|_| Error::Invariant)
}
pub(crate) fn bytes(v: &impl serde::Serialize) -> Result<Vec<u8>, Error> {
    serde_json::to_vec(v).map_err(|_| Error::Invariant)
}
pub(crate) async fn lock(c: &mut PgConnection, s: &Scope) -> Result<i64, Error> {
    sqlx::query_scalar("SELECT rss_timeseries.lock_namespace($1::text::uuid,$2)")
        .bind(s.tenant().to_string())
        .bind(s.namespace().as_str())
        .fetch_one(c)
        .await
        .map_err(sql_error)
}
pub(crate) async fn read_lock(c: &mut PgConnection, s: &Scope) -> Result<(), Error> {
    sqlx::query("SELECT revision FROM rss_timeseries.namespaces WHERE tenant_id=$1::text::uuid AND namespace=$2 FOR SHARE").bind(s.tenant().to_string()).bind(s.namespace().as_str()).fetch_optional(c).await.map_err(sql_error)?;
    Ok(())
}
pub(crate) async fn absent_receipt(
    c: &mut PgConnection,
    s: &Stream,
) -> Result<Lookup<Receipt>, Error> {
    let reclaimed:Option<bool>=sqlx::query_scalar("SELECT reclaimed FROM rss_timeseries.streams WHERE tenant_id=$1::text::uuid AND namespace=$2 AND source=$3 AND generation=$4").bind(s.scope().tenant().to_string()).bind(s.scope().namespace().as_str()).bind(s.source().as_str()).bind(s.generation().as_str()).fetch_optional(c).await.map_err(sql_error)?;
    Ok(if reclaimed == Some(true) {
        Lookup::Expired
    } else {
        Lookup::NotVisible
    })
}
pub(crate) async fn admit_stream(c: &mut PgConnection, s: &Stream) -> Result<(), Error> {
    if closed(c, s).await? {
        Err(Error::HistoryExpired)
    } else {
        Ok(())
    }
}
pub(crate) async fn closed(c: &mut PgConnection, s: &Stream) -> Result<bool, Error> {
    Ok(sqlx::query_scalar::<_,bool>("SELECT closed FROM rss_timeseries.streams WHERE tenant_id=$1::text::uuid AND namespace=$2 AND source=$3 AND generation=$4").bind(s.scope().tenant().to_string()).bind(s.scope().namespace().as_str()).bind(s.source().as_str()).bind(s.generation().as_str()).fetch_optional(c).await.map_err(sql_error)?.unwrap_or(false))
}
#[derive(Debug)]
pub(crate) struct Fence {
    pub kind: String,
    pub selection: Selection,
    pub window: Interval,
    pub until: Option<i64>,
    pub restored: bool,
}
pub(crate) async fn fences(
    c: &mut PgConnection,
    s: &Scope,
    limit: u32,
) -> Result<Vec<Fence>, Error> {
    let rows=sqlx::query("SELECT id,kind,selection::text,lo,hi,restore_until,restored FROM rss_timeseries.fences WHERE tenant_id=$1::text::uuid AND namespace=$2 ORDER BY id LIMIT $3").bind(s.tenant().to_string()).bind(s.namespace().as_str()).bind(i64::from(limit)+1).fetch_all(c).await.map_err(sql_error)?;
    if rows.len() > limit as usize {
        return Err(Error::BudgetExceeded);
    }
    rows.into_iter()
        .map(|r| {
            Ok(Fence {
                kind: r.try_get("kind").map_err(sql_error)?,
                selection: serde_json::from_str(
                    &r.try_get::<String, _>("selection").map_err(sql_error)?,
                )
                .map_err(|_| Error::Invariant)?,
                window: Interval::new(
                    Timestamp::new(r.try_get("lo").map_err(sql_error)?)?,
                    Timestamp::new(r.try_get("hi").map_err(sql_error)?)?,
                )?,
                until: r.try_get("restore_until").map_err(sql_error)?,
                restored: r.try_get("restored").map_err(sql_error)?,
            })
        })
        .collect()
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
pub(crate) async fn availability(
    c: &mut PgConnection,
    q: &Query,
    limit: u32,
) -> Result<Availability, Error> {
    let mut excluded = Vec::new();
    for f in fences(c, q.selection().scope(), limit).await? {
        let reason = match f.kind.as_str() {
            "pruned" => UnavailableReason::Pruned,
            "delete" if !f.restored => UnavailableReason::Deleted,
            _ => continue,
        };
        let lo = f.window.start().max(q.window().start());
        let hi = f.window.end().min(q.window().end());
        if lo < hi && overlaps(&f.selection, q.selection()) {
            excluded.push(UnavailableRange {
                selection: f.selection,
                window: Interval::new(lo, hi)?,
                reason,
            });
        }
    }
    Ok(Availability { excluded })
}
pub(crate) async fn put_fence(
    c: &mut PgConnection,
    r: &MaintenanceRequest,
    kind: &str,
    selection: &Selection,
    window: Interval,
    until: Option<i64>,
) -> Result<(), Error> {
    sqlx::query(
        "SELECT rss_timeseries.put_fence($1::text::uuid,$2,$3,$4,$5::text::jsonb,$6,$7,$8)",
    )
    .bind(r.scope().tenant().to_string())
    .bind(r.scope().namespace().as_str())
    .bind(r.id().as_str())
    .bind(kind)
    .bind(json(selection)?)
    .bind(window.start().micros())
    .bind(window.end().micros())
    .bind(until)
    .execute(c)
    .await
    .map_err(sql_error)?;
    Ok(())
}
