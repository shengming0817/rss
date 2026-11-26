use super::*;

pub(super) struct Run<'a> {
    spec: &'a SummarySpec,
    fences: &'a [Fence],
    published: i64,
    deadline: Deadline,
    end: Timestamp,
    seeded: bool,
    prior: Option<Sample>,
    rows: VecDeque<ReadRow>,
    complete_until: Timestamp,
    single_bucket: bool,
}

impl<'a> Run<'a> {
    pub(super) fn new(
        spec: &'a SummarySpec,
        fences: &'a [Fence],
        published: i64,
        deadline: Deadline,
        start: Timestamp,
        end: Timestamp,
    ) -> Self {
        Self {
            spec,
            fences,
            published,
            deadline,
            end,
            seeded: false,
            prior: None,
            rows: VecDeque::new(),
            complete_until: start,
            single_bucket: false,
        }
    }

    async fn fetch<C: Clock>(
        &self,
        store: &Operation<'_, C>,
        start: Timestamp,
        end: Timestamp,
    ) -> Result<Vec<ReadRow>, Error> {
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
                self.deadline,
            )
            .await
    }

    async fn refill<C: Clock>(
        &mut self,
        store: &Operation<'_, C>,
        window: Interval,
        remaining: usize,
    ) -> Result<(), Error> {
        // Each bucket costs at least one point, including a partial first bucket.
        let span = (remaining.saturating_sub(1) as u64)
            .saturating_mul(self.spec.resolution_micros().get());
        let mut end = if self.single_bucket {
            window.end()
        } else {
            Timestamp::new(
                window
                    .end()
                    .micros()
                    .saturating_add(i64::try_from(span).unwrap_or(i64::MAX)),
            )?
            .min(self.end)
        };
        let result = self.fetch(store, window.start(), end).await;
        let mut rows = match result {
            // Local validation or a provider cap in a later bucket must not decide this bucket.
            Err(e)
                if end > window.end()
                    && !matches!(
                        e,
                        Error::Deadline | Error::Unavailable | Error::Unauthorized
                    ) =>
            {
                self.single_bucket = true;
                end = window.end();
                self.fetch(store, window.start(), end).await?
            }
            result => result?,
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
        remaining: usize,
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
                    self.deadline,
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
            self.refill(store, window, remaining).await?;
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
