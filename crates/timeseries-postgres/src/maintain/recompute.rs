use super::*;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Fold {
    at: Timestamp,
    revision: Revision,
    builder: Option<SummaryBuilder>,
    predecessor_at: Option<Timestamp>,
    last: Option<(Timestamp, u64, Id)>,
}
pub(super) async fn step(
    c: &mut PgConnection,
    r: &MaintenanceRequest,
    spec: &SummarySpec,
    window: Interval,
    state: &mut State,
    revision: Revision,
    limits: &Limits,
) -> Result<Step, Error> {
    if spec.bucket(window.start())?.start() != window.start()
        || spec
            .bucket(Timestamp::new(window.end().micros() - 1)?)?
            .end()
            != window.end()
    {
        return Err(Error::InvalidInput);
    }
    let availability_query = Query::new(
        spec.selection(),
        window,
        QueryBudget {
            max_points: r.budget().rows,
            max_series: r.budget().rows,
        },
        QueryMode::History,
    )?;
    let available =
        crate::lifecycle::availability(c, &availability_query, limits.max_points.get()).await?;
    if available
        .excluded
        .iter()
        .any(|f| f.reason == UnavailableReason::Pruned)
    {
        return Err(Error::HistoryExpired);
    }
    if state.fold.is_none() {
        sqlx::query("SELECT rss_timeseries.register_summary($1::text::uuid,$2,$3,$4,$5,$6)")
            .bind(r.scope().tenant().to_string())
            .bind(r.scope().namespace().as_str())
            .bind(spec.binding()?.as_bytes().as_slice())
            .bind(bytes(spec)?)
            .bind(window.start().micros())
            .bind(window.end().micros())
            .execute(&mut *c)
            .await
            .map_err(sql_error)?;
        state.fold = Some(Fold {
            at: window.start(),
            revision,
            builder: None,
            predecessor_at: None,
            last: None,
        });
    }
    let fold = state.fold.as_mut().ok_or(Error::Invariant)?;
    if fold.revision != revision {
        fold.at = window.start();
        fold.revision = revision;
        fold.builder = None;
        fold.last = None;
    }
    let bucket = spec.bucket(fold.at)?;
    if fold.builder.is_none() {
        let mut builder = SummaryBuilder::new(spec.clone(), bucket)?;
        let prior = crate::aggregate::predecessor(c, spec, fold.at, limits).await?;
        crate::aggregate::ensure_boundary(c, spec, fold.at, prior.as_ref(), limits).await?;
        fold.predecessor_at = prior.as_ref().map(|p| p.input().observed_at);
        if let Some(prior) = prior {
            builder.push(prior, limits.max_points.get() as usize)?;
        }
        fold.builder = Some(builder);
    }
    let gap_start = fold
        .builder
        .as_ref()
        .and_then(SummaryBuilder::last_observed_at)
        .unwrap_or(bucket.start());
    let gaps =
        crate::aggregate::deletions(c, spec, Interval::new(gap_start, bucket.end())?, limits)
            .await?;
    let mut scan = crate::aggregate::scan::Scan::new(spec, bucket, &available, fold.last.clone())?;
    let mut processed = 0;
    let cap = r.budget().rows.get();
    while processed < cap {
        let Some(sample) = scan
            .next(c, bucket.end(), (cap - processed) as usize, limits)
            .await?
        else {
            break;
        };
        let i = sample.input();
        fold.last = Some((i.observed_at, i.sequence, i.id.clone()));
        crate::aggregate::mask(
            fold.builder.as_mut().ok_or(Error::Invariant)?,
            &gaps,
            sample.input().observed_at,
        )?;
        fold.builder
            .as_mut()
            .ok_or(Error::Invariant)?
            .push(sample, limits.max_points.get() as usize)?;
        processed += 1;
    }
    if !scan.more() {
        crate::aggregate::mask(
            fold.builder.as_mut().ok_or(Error::Invariant)?,
            &gaps,
            bucket.end(),
        )?;
        let summary = fold
            .builder
            .take()
            .ok_or(Error::Invariant)?
            .finish(limits.max_points.get() as usize)?;
        crate::aggregate::store(c, spec, &summary, fold.predecessor_at, limits).await?;
        fold.at = bucket.end();
        fold.last = None;
        if fold.at == window.end() {
            state.fold = None;
            return Ok(Step::Done(processed));
        }
    }
    Ok(Step::More(processed))
}
