//! Bound selectors and keysets for raw reads in the page's tenant snapshot.
use super::Position;
use base64::{Engine, engine::general_purpose::STANDARD};
use rss_timeseries::{Availability, Error, Query, QueryMode, Selection};
use sqlx::{Postgres, QueryBuilder};

const GROUP: &str = "series_digest,source,generation";
const POSITION: &str = "series_digest,source,generation,observed_at,sequence,sample_id";

fn select(sql: &mut QueryBuilder<Postgres>, selection: &Selection) -> Result<(), Error> {
    match selection {
        Selection::Exact { stream, series } => {
            sql.push(" AND series_digest=")
                .push_bind(series.digest()?.as_bytes().as_slice())
                .push(" AND source=")
                .push_bind(stream.source().as_str())
                .push(" AND generation=")
                .push_bind(stream.generation().as_str());
        }
        Selection::Resource {
            subject,
            resource,
            keys,
            ..
        } => {
            sql.push(" AND subject=")
                .push_bind(subject.as_str())
                .push(" AND resource=")
                .push_bind(resource.as_str());
            if !keys.is_empty() {
                sql.push(" AND key=ANY(")
                    .push_bind(keys.iter().map(|key| key.as_str()).collect::<Vec<_>>())
                    .push(")");
            }
        }
    }
    Ok(())
}

fn continuation(sql: &mut QueryBuilder<Postgres>, mode: QueryMode, p: &Position) {
    let columns = match mode {
        QueryMode::History => POSITION,
        QueryMode::Latest => GROUP,
    };
    sql.push(" AND (")
        .push(columns)
        .push(") > (")
        .push_bind(p.series.as_slice())
        .push(",")
        .push_bind(p.source.as_str())
        .push(" COLLATE \"C\",")
        .push_bind(p.generation.as_str())
        .push(" COLLATE \"C\"");
    if mode == QueryMode::History {
        sql.push(",")
            .push_bind(p.time)
            .push(",")
            .push_bind(p.sequence.to_string())
            .push("::text::numeric,")
            .push_bind(p.id.as_str())
            .push(" COLLATE \"C\"");
    }
    sql.push(")");
}

// The scope and time window have already been applied by availability() in this
// page's snapshot. Bind all fences once, independently of the PG parameter limit.
pub(crate) fn excluded(availability: &Availability) -> Result<Option<String>, Error> {
    if availability.excluded.is_empty() {
        return Ok(None);
    }
    let mut ranges = Vec::with_capacity(availability.excluded.len());
    for range in &availability.excluded {
        let mut row = match &range.selection {
            Selection::Exact { stream, series } => serde_json::json!({
                "series": STANDARD.encode(series.digest()?.as_bytes()),
                "source": stream.source().as_str(), "generation": stream.generation().as_str(),
            }),
            Selection::Resource {
                subject,
                resource,
                keys,
                ..
            } => serde_json::json!({
                "subject": subject.as_str(), "resource": resource.as_str(), "keys": keys,
            }),
        };
        row["lo"] = range.window.start().micros().into();
        row["hi"] = range.window.end().micros().into();
        ranges.push(row);
    }
    crate::lifecycle::json(&ranges).map(Some)
}

pub(crate) fn push_excluded(sql: &mut QueryBuilder<Postgres>, excluded: Option<&str>) {
    if let Some(excluded) = excluded {
        sql.push("excluded AS MATERIALIZED (
              SELECT lo,hi,decode(series,'base64') AS series_digest,source,generation,subject,resource,keys
              FROM jsonb_to_recordset(")
            .push_bind(excluded)
            .push("::text::jsonb) AS f(lo bigint,hi bigint,series text,source text,generation text,
                                      subject text,resource text,keys text[])), ");
    }
}

pub(crate) fn filter_excluded(sql: &mut QueryBuilder<Postgres>, has_exclusions: bool) {
    if has_exclusions {
        sql.push(
            " AND NOT EXISTS (SELECT FROM excluded f
            WHERE s.observed_at >= f.lo AND s.observed_at < f.hi AND (
                (s.series_digest,s.source,s.generation) = (f.series_digest,f.source,f.generation)
                OR (s.subject=f.subject AND s.resource=f.resource
                    AND (cardinality(f.keys)=0 OR s.key=ANY(f.keys)))))",
        );
    }
}

pub(super) fn samples(
    q: &Query,
    availability: &Availability,
    after: Option<&Position>,
) -> Result<QueryBuilder<Postgres>, Error> {
    let exact = matches!(q.selection(), Selection::Exact { .. });
    let mut sql = QueryBuilder::new("WITH ");
    let excluded = excluded(availability)?;
    push_excluded(&mut sql, excluded.as_deref());
    sql.push("selected AS (SELECT ");
    if q.mode() == QueryMode::Latest && !exact {
        sql.push("DISTINCT ON (").push(GROUP).push(") ");
    }
    sql.push("s.* FROM rss_timeseries.samples s WHERE tenant_id=")
        .push_bind(q.selection().scope().tenant().to_string())
        .push("::text::uuid AND namespace=")
        .push_bind(q.selection().scope().namespace().as_str())
        .push(" AND observed_at>=")
        .push_bind(q.window().start().micros())
        .push(" AND observed_at<")
        .push_bind(q.window().end().micros());
    select(&mut sql, q.selection())?;
    if let Some(position) = after {
        continuation(&mut sql, q.mode(), position);
    }
    filter_excluded(&mut sql, excluded.is_some());
    sql.push(" ORDER BY ");
    let points = i64::from(q.budget().max_points.get());
    let limit = match q.mode() {
        QueryMode::History => {
            sql.push(POSITION);
            points + 1
        }
        QueryMode::Latest => {
            if !exact {
                sql.push(GROUP).push(",");
            }
            sql.push("observed_at DESC,sequence DESC,sample_id DESC");
            if exact {
                1
            } else {
                points.min(i64::from(q.budget().max_series.get())) + 1
            }
        }
    };
    sql.push(" LIMIT ")
        .push_bind(limit)
        .push(
            ") SELECT s.*,s.sequence::text AS sequence_text,s.version::text AS version_text,
                       i.digest,i.received_at AS original_received
                FROM selected s JOIN rss_timeseries.sample_identities i
                USING(tenant_id,namespace,source,generation,sample_id,observed_at)
                ORDER BY ",
        )
        .push(POSITION);
    Ok(sql)
}
