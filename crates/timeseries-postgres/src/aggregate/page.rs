use super::{cache::Bucket, *};

pub(super) struct Page {
    pub(super) at: Timestamp,
    pub(super) buckets: Vec<AggregateBucket>,
    pub(super) refreshed: Option<Timestamp>,
    continuous: bool,
    points: usize,
    bytes: usize,
}
impl Page {
    fn push(
        &mut self,
        q: &AggregateQuery,
        summary: Summary,
        cached: bool,
        limits: &Limits,
    ) -> Result<bool, Error> {
        let bucket = summary.project(q.operation())?;
        let points = cost(&bucket);
        if points > q.query().budget().max_points.get() as usize - self.points {
            return if self.buckets.is_empty() {
                Err(Error::BudgetExceeded)
            } else {
                Ok(false)
            };
        }
        self.bytes = self
            .bytes
            .checked_add(bytes(&bucket)?.len())
            .ok_or(Error::BudgetExceeded)?;
        if self.bytes > limits.max_bytes.get() as usize {
            return Err(Error::BudgetExceeded);
        }
        self.points += points;
        self.at = bucket.window.end();
        self.continuous &= cached;
        if self.continuous {
            self.refreshed = Some(self.at);
        }
        self.buckets.push(bucket);
        Ok(self.points < q.query().budget().max_points.get() as usize)
    }
}

struct Read<'a, C> {
    q: &'a AggregateQuery,
    available: &'a Availability,
    limits: &'a Limits,
    clock: &'a C,
    deadline: Deadline,
}
impl<C: Clock> Read<'_, C> {
    async fn raw_run(
        &self,
        c: &mut PgConnection,
        buckets: &[Bucket],
        page: &mut Page,
    ) -> Result<bool, Error> {
        let spec = self.q.spec();
        let start = page.at;
        let end = buckets.last().ok_or(Error::Invariant)?.window.end();
        let mut prior = predecessor(c, spec, start, self.limits).await?;
        ensure_boundary(c, spec, start, prior.as_ref(), self.limits).await?;
        let mut gaps = deletions(c, spec, Interval::new(start, end)?, self.limits).await?;
        if let Some(p) = &prior {
            // The page bounds its own fences. Read the predecessor halo separately
            // so unrelated later buckets cannot exhaust the first bucket's budget.
            let mut prefix = deletions(
                c,
                spec,
                Interval::new(p.input().observed_at, start)?,
                self.limits,
            )
            .await?;
            gaps.retain(|g| g.start() >= start);
            prefix.extend(gaps);
            gaps = prefix;
        }
        let mut scan = scan::Scan::new(spec, Interval::new(start, end)?, self.available, None)?;
        let point_limit = self.limits.max_points.get() as usize;
        for bucket in buckets {
            let w = bucket.window;
            if self.available.excluded.iter().any(|r| {
                r.reason == UnavailableReason::Pruned
                    && r.window.start() < w.end()
                    && r.window.end() > w.start()
            }) {
                return Err(Error::HistoryExpired);
            }
            let mut builder = SummaryBuilder::new(spec.clone(), w)?;
            if let Some(p) = prior.as_ref()
                && p.input().observed_at.micros() >= dependency_start(spec, w.start().micros())
            {
                builder.push(p.clone(), point_limit)?;
            }
            let gap_start = builder.last_observed_at().unwrap_or(w.start());
            let gaps = &gaps[..gaps.partition_point(|g| g.start() < w.end())];
            let gaps: Vec<_> = gaps
                .iter()
                .copied()
                .filter(|g| g.end() > gap_start)
                .collect();
            if gaps.len() > point_limit {
                return Err(Error::BudgetExceeded);
            }
            while let Some(sample) = scan.next(c, w.end(), usize::MAX, self.limits).await? {
                check(self.clock, self.deadline)?;
                mask(&mut builder, &gaps, sample.input().observed_at)?;
                if needs_predecessor(spec) {
                    prior = Some(sample.clone());
                }
                builder.push(sample, point_limit)?;
            }
            mask(&mut builder, &gaps, w.end())?;
            if !page.push(self.q, builder.finish(point_limit)?, false, self.limits)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
    async fn block(
        &self,
        c: &mut PgConnection,
        page: &mut Page,
        mut buckets: &[Bucket],
    ) -> Result<bool, Error> {
        while let Some(first) = buckets.first() {
            check(self.clock, self.deadline)?;
            let n = if first.cover.as_ref().map_err(|e| *e)?.is_some() {
                let mut size = 0;
                let n = buckets
                    .iter()
                    .take_while(|b| {
                        let Ok(Some(cover)) = &b.cover else {
                            return false;
                        };
                        if cover.bytes > self.limits.max_bytes.get() as usize - size {
                            return false;
                        }
                        size += cover.bytes;
                        true
                    })
                    .count();
                let mut data = cache::fetch(c, self.q.spec(), &buckets[..n]).await?;
                for b in &buckets[..n] {
                    check(self.clock, self.deadline)?;
                    let cover = b
                        .cover
                        .as_ref()
                        .map_err(|e| *e)?
                        .as_ref()
                        .ok_or(Error::Invariant)?;
                    let summary = cover.decode(&mut data, self.limits.max_points.get() as usize)?;
                    if !page.push(self.q, summary, true, self.limits)? {
                        return Ok(false);
                    }
                }
                n
            } else {
                let n = buckets
                    .iter()
                    .take_while(|b| matches!(b.cover, Ok(None)))
                    .count();
                if !self.raw_run(c, &buckets[..n], page).await? {
                    return Ok(false);
                }
                n
            };
            buckets = &buckets[n..];
        }
        Ok(true)
    }
}
pub(super) async fn collect<C: Clock>(
    c: &mut PgConnection,
    q: &AggregateQuery,
    available: &Availability,
    limits: &Limits,
    at: Timestamp,
    clock: &C,
    deadline: Deadline,
) -> Result<Page, Error> {
    let read = Read {
        q,
        available,
        limits,
        clock,
        deadline,
    };
    let mut page = Page {
        at,
        buckets: Vec::new(),
        refreshed: None,
        continuous: true,
        points: 0,
        bytes: 0,
    };
    while page.at < q.query().window().end() {
        let count = (q.query().budget().max_points.get() as usize - page.points).min(16);
        let buckets = cache::plan(c, q, page.at, count, limits).await?;
        if !read.block(c, &mut page, &buckets).await? {
            break;
        }
    }
    Ok(page)
}
