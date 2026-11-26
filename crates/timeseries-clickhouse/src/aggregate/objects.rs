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
    ) -> Result<Objects, ReadFailure> {
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
            // Keep the provider status available when a result limit trips after the first block.
            .with_setting("wait_end_of_query", "1")
            .fetch::<Stored>()
            .map_err(crate::projection::read_error)?;
        let mut objects = HashMap::new();
        let mut size = 0;
        while let Some(row) = cursor.next().await.map_err(crate::projection::read_error)? {
            match objects.entry(row.object_id.clone()) {
                Entry::Vacant(slot) => {
                    size += row.payload.len() as u64;
                    if size > u64::from(self.limits.max_bytes.get()) {
                        return Err(ReadFailure::Capacity);
                    }
                    slot.insert(Ok(row));
                }
                Entry::Occupied(mut slot) => {
                    *slot.get_mut() = Err(Error::Invariant);
                }
            }
        }
        #[cfg(feature = "integration")]
        crate::measurement::record(|m| {
            let capacity = objects
                .values()
                .filter_map(|value| value.as_ref().ok())
                .map(|row| row.payload.capacity())
                .sum();
            m.largest_group_bytes = m.largest_group_bytes.max(capacity);
            m.summary_groups += 1;
        });
        Ok(Objects(objects))
    }
}

pub(super) struct Reader<'a> {
    remaining: &'a [&'a SummaryRef],
    group_left: usize,
    objects: Objects,
    max_ids: usize,
}

impl<'a> Reader<'a> {
    pub(super) fn new(remaining: &'a [&'a SummaryRef]) -> Self {
        Self {
            remaining,
            group_left: 0,
            objects: Objects(HashMap::new()),
            max_ids: 512, // 39 SQL bytes per quoted UUID, independent of response budgets.
        }
    }

    fn group(&self, limits: &crate::Limits, through: Timestamp) -> (usize, Vec<&'a str>) {
        let mut seen = HashSet::new();
        let mut ids = Vec::new();
        let mut size = 0u64;
        // Each ID may return a second row as evidence of a duplicate.
        // Bound the SQL text independently of response budgets (39 bytes per quoted UUID).
        let capacity = (self.max_ids as u64)
            .min(u64::from(limits.max_points.get()))
            .min((limits.max_scan_rows.get() / 2).max(1));
        for (index, r) in self.remaining.iter().enumerate() {
            if r.hi > through.micros() {
                return (index, ids);
            }
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

    async fn fill<C: Clock>(
        &mut self,
        store: &Operation<'_, C>,
        scope: &Scope,
        bounds: Lookahead,
        budget: &mut ReadBudget,
    ) -> Result<(), Error> {
        loop {
            let (through, optional_cutoff) = bounds.allowed(budget, store.clock);
            let (count, ids) = self.group(store.limits, through);
            if ids.is_empty() {
                return Err(Error::Invariant);
            }
            let speculative = self.remaining[count - 1].hi > bounds.required.micros();
            let cutoff = if speculative {
                optional_cutoff
            } else {
                budget.deadline
            };
            #[cfg(feature = "integration")]
            crate::measurement::record(|m| {
                let previous = self
                    .objects
                    .0
                    .values()
                    .filter_map(|value| value.as_ref().ok())
                    .map(|row| row.payload.capacity())
                    .sum();
                m.previous_group_bytes = m.previous_group_bytes.max(previous);
            });
            let read = store.summary_objects(scope, &ids, cutoff);
            match budget
                .group(store, cutoff, speculative, ids.len() > 1, true, read)
                .await?
            {
                Group::Required => continue,
                Group::Smaller => self.max_ids = ids.len().div_ceil(2),
                Group::Ready(objects) => {
                    self.objects = objects;
                    self.group_left = count;
                    return Ok(());
                }
            }
        }
    }

    async fn next<C: Clock>(
        &mut self,
        store: &Operation<'_, C>,
        scope: &Scope,
        bounds: Lookahead,
        budget: &mut ReadBudget,
    ) -> Result<Summary, Error> {
        let row = *self.remaining.first().ok_or(Error::Invariant)?;
        if self.group_left == 0 {
            self.fill(store, scope, bounds, budget).await?;
        }
        self.group_left -= 1;
        self.remaining = &self.remaining[1..];
        let value = self.objects.value(
            &row.object_id,
            row.lo,
            row.hi,
            usize::try_from(row.payload_bytes).map_err(|_| Error::Invariant)?,
        );
        if self.group_left == 0 {
            self.objects.0.clear();
        }
        value
    }

    pub(super) async fn merge<C: Clock>(
        &mut self,
        store: &Operation<'_, C>,
        scope: &Scope,
        path: &[&SummaryRef],
        bounds: Lookahead,
        attempted: &mut Vec<SummaryRef>,
        budget: &mut ReadBudget,
    ) -> Result<Summary, Error> {
        let mut size = 0u64;
        let mut value: Option<Summary> = None;
        for &r in path {
            attempted.push(r.clone());
            let summary = self.next(store, scope, bounds, budget).await?;
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
