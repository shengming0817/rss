//! Discover complete, compatible tiles using narrow headers before fetching data.
use super::*;
use futures::TryStreamExt;
use std::collections::HashMap;

pub(super) struct Tile {
    identity: (Vec<u8>, i64),
    end: i64,
    bytes: usize,
}
#[derive(Default)]
pub(super) struct Cover {
    tiles: Vec<Tile>,
    pub(super) bytes: usize,
}
pub(super) struct Bucket {
    pub(super) window: Interval,
    pub(super) cover: Result<Option<Cover>, Error>,
}

pub(super) async fn plan(
    c: &mut PgConnection,
    q: &AggregateQuery,
    at: Timestamp,
    count: usize,
    limits: &Limits,
) -> Result<Vec<Bucket>, Error> {
    let spec = q.spec();
    let mut windows = Vec::new();
    let mut lo = at;
    while lo < q.query().window().end() && windows.len() < count {
        let hi = spec.bucket(lo)?.end().min(q.query().window().end());
        windows.push(Interval::new(lo, hi)?);
        lo = hi;
    }
    let scope = spec.stream().scope();
    let mut rows = sqlx::query("SELECT w.idx,t.spec_digest,t.lo,t.hi,t.size
        FROM unnest($4::bigint[],$5::bigint[]) WITH ORDINALITY w(l,h,idx)
        CROSS JOIN LATERAL (SELECT spec_digest,lo,hi,octet_length(data) AS size
          FROM rss_timeseries.summaries WHERE tenant_id=$1::text::uuid AND namespace=$2 AND semantics=$3
          AND NOT dirty AND lo>=w.l AND lo<w.h AND hi<=w.h ORDER BY lo,hi DESC LIMIT $6) t
        ORDER BY w.idx,t.lo,t.hi DESC")
        .bind(scope.tenant().to_string()).bind(scope.namespace().as_str()).bind(spec.semantics()?.as_bytes().as_slice())
        .bind(windows.iter().map(|w| w.start().micros()).collect::<Vec<_>>())
        .bind(windows.iter().map(|w| w.end().micros()).collect::<Vec<_>>())
        .bind(i64::from(limits.max_points.get())+1).fetch(c);
    let mut candidates: Vec<Vec<Tile>> = windows.iter().map(|_| Vec::new()).collect();
    while let Some(row) = rows.try_next().await.map_err(sql_error)? {
        let idx: i64 = row.try_get("idx").map_err(sql_error)?;
        candidates
            .get_mut((idx - 1) as usize)
            .ok_or(Error::Invariant)?
            .push(Tile {
                identity: (
                    row.try_get("spec_digest").map_err(sql_error)?,
                    row.try_get("lo").map_err(sql_error)?,
                ),
                end: row.try_get("hi").map_err(sql_error)?,
                bytes: usize::try_from(row.try_get::<i32, _>("size").map_err(sql_error)?)
                    .map_err(|_| Error::Invariant)?,
            });
    }
    Ok(windows
        .into_iter()
        .zip(candidates)
        .map(|(window, tiles)| Bucket {
            window,
            cover: choose(window, tiles, limits),
        })
        .collect())
}

// A longer tile may end at a dead end. Compute the cheapest complete suffix
// at each boundary, then prefer the longest viable tile in the original order.
fn choose(window: Interval, tiles: Vec<Tile>, limits: &Limits) -> Result<Option<Cover>, Error> {
    if tiles.len() > limits.max_points.get() as usize {
        return Err(Error::BudgetExceeded);
    }
    let mut suffix = HashMap::from([(window.end().micros(), 0u64)]);
    for t in tiles.iter().rev() {
        if let Some(rest) = suffix.get(&t.end) {
            let cost = rest + t.bytes as u64;
            let best = suffix.entry(t.identity.1).or_insert(cost);
            *best = (*best).min(cost);
        }
    }
    let mut at = window.start().micros();
    let Some(minimum) = suffix.get(&at) else {
        return Ok(None);
    };
    let cap = u64::from(limits.max_bytes.get());
    if *minimum > cap {
        return Err(Error::BudgetExceeded);
    }
    let mut cover = Cover::default();
    for t in tiles {
        if t.identity.1 == at
            && suffix
                .get(&t.end)
                .is_some_and(|rest| rest + t.bytes as u64 <= cap - cover.bytes as u64)
        {
            at = t.end;
            cover.bytes += t.bytes;
            cover.tiles.push(t);
        }
    }
    Ok(Some(cover))
}

pub(super) type Payloads = HashMap<(Vec<u8>, i64), Vec<u8>>;
pub(super) async fn fetch(
    c: &mut PgConnection,
    spec: &SummarySpec,
    buckets: &[Bucket],
) -> Result<Payloads, Error> {
    let mut digests = Vec::new();
    let mut starts = Vec::new();
    for b in buckets {
        let cover = b
            .cover
            .as_ref()
            .map_err(|e| *e)?
            .as_ref()
            .ok_or(Error::Invariant)?;
        for t in &cover.tiles {
            digests.push(&t.identity.0);
            starts.push(t.identity.1);
        }
    }
    let scope = spec.stream().scope();
    let mut rows = sqlx::query(
        "SELECT spec_digest,lo,data FROM rss_timeseries.summaries
        WHERE tenant_id=$1::text::uuid AND namespace=$2 AND NOT dirty
        AND (spec_digest,lo) IN (SELECT * FROM unnest($3::bytea[],$4::bigint[]))",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.namespace().as_str())
    .bind(digests)
    .bind(starts)
    .fetch(c);
    let mut payloads = HashMap::new();
    while let Some(row) = rows.try_next().await.map_err(sql_error)? {
        payloads.insert(
            (
                row.try_get("spec_digest").map_err(sql_error)?,
                row.try_get("lo").map_err(sql_error)?,
            ),
            row.try_get("data").map_err(sql_error)?,
        );
    }
    Ok(payloads)
}

impl Cover {
    pub(super) fn decode(&self, payloads: &mut Payloads, limit: usize) -> Result<Summary, Error> {
        let mut result: Option<Summary> = None;
        for t in &self.tiles {
            let bytes = payloads.remove(&t.identity).ok_or(Error::Invariant)?;
            let summary: Summary = serde_json::from_slice(&bytes).map_err(|_| Error::Invariant)?;
            if (
                summary.window.start().micros(),
                summary.window.end().micros(),
            ) != (t.identity.1, t.end)
            {
                return Err(Error::Invariant);
            }
            result = Some(match result {
                Some(old) => old.merge(summary, limit)?,
                None => summary,
            });
        }
        result.ok_or(Error::Invariant)
    }
}
