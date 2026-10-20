use crate::transaction::{bytes, decode, sql_error};
use rss_timeseries::*;
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, Row};

pub(crate) async fn pending(c: &mut PgConnection, s: &Scope) -> Result<bool, Error> {
    sqlx::query_scalar("SELECT EXISTS(SELECT FROM rss_ts_ch.batches WHERE tenant_id=$1::text::uuid AND namespace=$2 AND NOT published)")
        .bind(s.tenant().to_string()).bind(s.namespace().as_str()).fetch_one(c).await.map_err(sql_error)
}
pub(crate) async fn invalidate(
    c: &mut PgConnection,
    s: &Scope,
    selection: &Selection,
    at: i64,
    max: u32,
) -> Result<(), Error> {
    let rows=sqlx::query("SELECT spec,spec_digest,lo FROM rss_ts_ch.summaries WHERE tenant_id=$1::text::uuid AND namespace=$2 AND hi>$3 AND NOT dirty LIMIT $4")
        .bind(s.tenant().to_string()).bind(s.namespace().as_str()).bind(at).bind(i64::from(max)+1).fetch_all(&mut *c).await.map_err(sql_error)?;
    if rows.len() > max as usize {
        return Err(Error::BudgetExceeded);
    }
    for row in rows {
        let spec: SummarySpec = decode(&row.try_get::<Vec<u8>, _>("spec").map_err(sql_error)?)?;
        if overlaps(selection, &spec.selection()) {
            sqlx::query("UPDATE rss_ts_ch.summaries SET dirty=true WHERE tenant_id=$1::text::uuid AND namespace=$2 AND spec_digest=$3 AND lo=$4")
                .bind(s.tenant().to_string()).bind(s.namespace().as_str()).bind(row.try_get::<Vec<u8>,_>("spec_digest").map_err(sql_error)?).bind(row.try_get::<i64,_>("lo").map_err(sql_error)?).execute(&mut *c).await.map_err(sql_error)?;
        }
    }
    bump(c, s).await
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
impl Fence {
    pub fn matches(&self, sample: &Sample) -> bool {
        self.selection.matches(sample)
            && sample.input().observed_at >= self.window.start()
            && sample.input().observed_at < self.window.end()
    }
}
pub(crate) async fn fences(c: &mut PgConnection, s: &Scope, max: u32) -> Result<Vec<Fence>, Error> {
    let rows=sqlx::query("SELECT id,kind,selection::text,lo,hi,restore_until,restored FROM rss_ts_ch.fences WHERE tenant_id=$1::text::uuid AND namespace=$2 ORDER BY lo,id LIMIT $3")
        .bind(s.tenant().to_string()).bind(s.namespace().as_str()).bind(i64::from(max)+1).fetch_all(c).await.map_err(sql_error)?;
    if rows.len() > max as usize {
        return Err(Error::BudgetExceeded);
    }
    rows.into_iter()
        .map(|r| {
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
        })
        .collect()
}
pub(crate) async fn put_fence(
    c: &mut PgConnection,
    r: &MaintenanceRequest,
    kind: &str,
    selection: &Selection,
    window: Interval,
    until: Option<i64>,
) -> Result<(), Error> {
    sqlx::query("INSERT INTO rss_ts_ch.fences(tenant_id,namespace,id,kind,selection,lo,hi,restore_until) VALUES($1::text::uuid,$2,$3,$4,$5::text::jsonb,$6,$7,$8)")
        .bind(r.scope().tenant().to_string()).bind(r.scope().namespace().as_str()).bind(r.id().as_str()).bind(kind).bind(String::from_utf8(bytes(selection)?).map_err(|_|Error::Invariant)?).bind(window.start().micros()).bind(window.end().micros()).bind(until).execute(&mut *c).await.map_err(sql_error)?;
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
