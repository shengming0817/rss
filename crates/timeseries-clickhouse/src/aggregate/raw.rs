use super::*;

pub(super) struct Run<'a> {
    spec: &'a SummarySpec,
    fences: &'a [Fence],
    published: i64,
    seeded: bool,
    prior: Option<Sample>,
    rows: VecDeque<ReadRow>,
    complete_until: Timestamp,
    max_buckets: u64,
}

impl<'a> Run<'a> {
    pub(super) fn new(
        spec: &'a SummarySpec,
        fences: &'a [Fence],
        published: i64,
        start: Timestamp,
    ) -> Self {
        Self {
            spec,
            fences,
            published,
            seeded: false,
            prior: None,
            rows: VecDeque::new(),
            complete_until: start,
            max_buckets: u64::MAX,
        }
    }

    async fn fetch<C: Clock>(
        &self,
        store: &Operation<'_, C>,
        start: Timestamp,
        end: Timestamp,
        cutoff: Deadline,
    ) -> Result<Vec<ReadRow>, ReadFailure> {
        let condition = format!(
            "{} AND revision<={} AND observed_at>={} AND observed_at<{}{}",
            selection(&self.spec.selection())?,
            self.published,
            start.micros(),
            end.micros(),
            visible(self.fences)?
        );
        store
            .raw_rows(
                &condition,
                "observed_at,sequence,sample_id",
                store.limits.max_points.get(),
                cutoff,
            )
            .await
    }

    async fn refill<C: Clock>(
        &mut self,
        store: &Operation<'_, C>,
        window: Interval,
        bounds: Lookahead,
        budget: &mut ReadBudget,
    ) -> Result<(), Error> {
        let width = self.spec.resolution_micros().get();
        let (mut rows, mut end) = loop {
            let (through, optional_cutoff) = bounds.allowed(budget, store.clock);
            let tail = through.micros().abs_diff(window.end().micros());
            let count = (1 + tail.div_ceil(width)).min(self.max_buckets);
            let span = i64::try_from((count - 1).saturating_mul(width)).unwrap_or(i64::MAX);
            let end = Timestamp::new(window.end().micros().saturating_add(span))?.min(through);
            let speculative = end > bounds.required;
            let cutoff = if speculative {
                optional_cutoff
            } else {
                budget.deadline
            };
            let read = self.fetch(store, window.start(), end, cutoff);
            match budget.group(store, cutoff, speculative, count > 1, false, read).await? {
                Group::Required => continue,
                Group::Smaller => self.max_buckets = count.div_ceil(2),
                Group::Ready(rows) => break (rows, end),
            }
        };
        if rows.len() > store.limits.max_points.get() as usize {
            let tail = rows
                .last()
                .ok_or(Error::Invariant)?
                .sample
                .input()
                .observed_at;
            end = self.spec.bucket(tail)?.start();
            if end < window.end() {
                return Err(Error::BudgetExceeded);
            }
            rows.truncate(rows.partition_point(|r| r.sample.input().observed_at < end));
        }
        self.complete_until = end;
        self.rows = rows.into();
        Ok(())
    }

    pub(super) async fn summary<C: Clock>(
        &mut self,
        store: &Operation<'_, C>,
        window: Interval,
        bounds: Lookahead,
        budget: &mut ReadBudget,
        dependency: &mut i64,
    ) -> Result<Summary, Error> {
        if self.fences.iter().any(|f| {
            f.kind == "pruned"
                && control::overlaps(&f.selection, &self.spec.selection())
                && f.window.start() < window.end()
                && f.window.end() > window.start()
        }) {
            return Err(Error::HistoryExpired);
        }
        if !self.seeded {
            self.prior = store
                .predecessor(
                    self.spec,
                    window.start(),
                    self.published,
                    self.fences,
                    budget.deadline,
                )
                .await?
                .map(|r| r.sample);
            self.seeded = true;
        }
        let limit = store.limits.max_points.get() as usize;
        let (mut builder, start) =
            seeded_builder(self.spec, window, self.fences, self.prior.as_ref(), limit)?;
        *dependency = start;
        if self.complete_until < window.end() {
            self.refill(store, window, bounds, budget).await?;
        }
        while self
            .rows
            .front()
            .is_some_and(|r| r.sample.input().observed_at < window.end())
        {
            let sample = self.rows.pop_front().ok_or(Error::Invariant)?.sample;
            mask(
                &mut builder,
                self.fences,
                self.spec,
                window,
                sample.input().observed_at,
            )?;
            if needs_prior(self.spec) {
                self.prior = Some(sample.clone());
            }
            builder.push(sample, limit)?;
        }
        mask_end(&mut builder, self.fences, self.spec, window)?;
        builder.finish(limit)
    }
}
