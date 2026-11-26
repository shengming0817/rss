//! Group immutable objects in first-use order and consume them in coverage order.
//! ref: thanos-io/thanos pkg/store/bucket.go@v0.37.2
use super::*;
use std::collections::{HashMap, HashSet, hash_map::Entry};

#[derive(clickhouse::Row, Deserialize)]
struct Stored {
    object_id: String,
    lo: i64,
    hi: i64,
    digest: String,
    payload: String,
}

pub(crate) struct Objects(HashMap<String, Result<Stored, Error>>);

impl Objects {
    pub(crate) fn value(&self, id: &str, lo: i64, hi: i64, len: usize) -> Result<Summary, Error> {
        let row = self
            .0
            .get(id)
            .ok_or(Error::Invariant)?
            .as_ref()
            .map_err(|e| *e)?;
        use sha2::{Digest, Sha256};
        if (row.lo, row.hi) != (lo, hi)
            || row.payload.len() != len
            || crate::projection::hex(&Sha256::digest(row.payload.as_bytes())) != row.digest
        {
            return Err(Error::Invariant);
        }
        let summary: Summary = decode(row.payload.as_bytes())?;
        if (
            summary.window.start().micros(),
            summary.window.end().micros(),
        ) != (lo, hi)
        {
            return Err(Error::Invariant);
        }
        Ok(summary)
    }
}

impl<C: Clock> Operation<'_, C> {
    pub(crate) async fn summary_objects(
        &self,
        scope: &Scope,
        ids: &[&str],
        deadline: Deadline,
    ) -> Result<Objects, Error> {
        let ids = ids
            .iter()
            .map(|id| literal(id))
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT object_id,lo,hi,digest,payload FROM rss_ts_ch.summaries FINAL WHERE tenant={} AND namespace={} AND object_id IN ({ids}) LIMIT 2 BY object_id",
            literal(&scope.tenant().to_string()),
            literal(scope.namespace().as_str())
        );
        let mut cursor = self
            .ch_query(self.reader.query_raw(&sql), deadline)?
            .fetch::<Stored>()
            .map_err(crate::projection::read_error)?;
        let mut objects = HashMap::new();
        let mut size = 0;
        while let Some(row) = cursor.next().await.map_err(crate::projection::read_error)? {
            match objects.entry(row.object_id.clone()) {
                Entry::Vacant(slot) => {
                    size += row.payload.len() as u64;
                    if size > u64::from(self.limits.max_bytes.get()) {
                        return Err(Error::BudgetExceeded);
                    }
                    slot.insert(Ok(row));
                }
                Entry::Occupied(mut slot) => {
                    slot.insert(Err(Error::Invariant));
                }
            }
        }
        Ok(Objects(objects))
    }
}

pub(super) struct Reader<'a> {
    remaining: &'a [&'a SummaryRef],
    group_left: usize,
    objects: Option<Objects>,
}

impl<'a> Reader<'a> {
    pub(super) fn new(remaining: &'a [&'a SummaryRef]) -> Self {
        Self {
            remaining,
            group_left: 0,
            objects: None,
        }
    }

    fn group(&self, limits: &crate::Limits) -> (usize, Vec<&'a str>) {
        let mut seen = HashSet::new();
        let mut ids = Vec::new();
        let mut size = 0u64;
        // Each ID may return a second row as evidence of a duplicate.
        // Bound the SQL text independently of response budgets (39 bytes per quoted UUID).
        const MAX_IDS: u64 = 512;
        let capacity = MAX_IDS
            .min(u64::from(limits.max_points.get()))
            .min((limits.max_scan_rows.get() / 2).max(1));
        for (index, r) in self.remaining.iter().enumerate() {
            if !seen.insert(r.object_id.as_str()) {
                continue;
            }
            // Include the fixed fields and RowBinary string prefixes in the estimate.
            let row_bytes = r
                .payload_bytes
                .saturating_add(r.object_id.len() as u64 + 16 + 64 + 12);
            size = size.saturating_add(row_bytes);
            if index > 0
                && (ids.len() as u64 >= capacity || size > u64::from(limits.max_bytes.get()))
            {
                return (index, ids);
            }
            ids.push(r.object_id.as_str());
        }
        (self.remaining.len(), ids)
    }

    async fn next<C: Clock>(
        &mut self,
        store: &Operation<'_, C>,
        scope: &Scope,
        deadline: Deadline,
    ) -> Result<Summary, Error> {
        let row = *self.remaining.first().ok_or(Error::Invariant)?;
        if self.group_left == 0 {
            let (count, ids) = self.group(store.limits);
            self.group_left = count;
            self.objects = match store.summary_objects(scope, &ids, deadline).await {
                // Per-query resource/parser limits and RowBinary errors in later rows
                // cannot decide this object. Narrow once under the same read deadline.
                Err(Error::BudgetExceeded | Error::Unavailable) if ids.len() > 1 => None,
                result => Some(result?),
            };
        }
        self.group_left -= 1;
        self.remaining = &self.remaining[1..];
        let singleton;
        let objects = match &self.objects {
            Some(batch) => batch,
            None => {
                singleton = store
                    .summary_objects(scope, &[&row.object_id], deadline)
                    .await?;
                &singleton
            }
        };
        objects.value(
            &row.object_id,
            row.lo,
            row.hi,
            usize::try_from(row.payload_bytes).map_err(|_| Error::Invariant)?,
        )
    }

    pub(super) async fn merge<C: Clock>(
        &mut self,
        store: &Operation<'_, C>,
        scope: &Scope,
        path: &[&SummaryRef],
        attempted: &mut Vec<SummaryRef>,
        deadline: Deadline,
    ) -> Result<Summary, Error> {
        let mut size = 0u64;
        let mut value: Option<Summary> = None;
        for &r in path {
            attempted.push(r.clone());
            let summary = self.next(store, scope, deadline).await?;
            size = size
                .checked_add(r.payload_bytes)
                .ok_or(Error::BudgetExceeded)?;
            if size > u64::from(store.limits.max_bytes.get()) {
                return Err(Error::BudgetExceeded);
            }
            value = Some(match value {
                None => summary,
                Some(previous) => {
                    previous.merge(summary, store.limits.max_points.get() as usize)?
                }
            });
        }
        value.ok_or(Error::Invariant)
    }
}
