use super::*;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Fold {
    at: Timestamp,
    revision: i64,
    builder: Option<SummaryBuilder>,
    last: Option<(Timestamp, u64, Id)>,
}
pub(super) async fn step(
    c: &mut PgConnection,
    r: &MaintenanceRequest,
    spec: &SummarySpec,
    window: Interval,
    state: &mut State,
    revision: i64,
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
    if state.fold.is_none() {
        let q = Query::new(
            spec.selection(),
            window,
            QueryBudget {
                max_points: r.budget().rows,
                max_series: r.budget().rows,
            },
            QueryMode::History,
        )?;
        if crate::lifecycle::availability(c, &q, limits.max_points.get())
            .await?
            .excluded
            .iter()
            .any(|f| f.reason == UnavailableReason::Pruned)
        {
            return Err(Error::HistoryExpired);
        }
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
            last: None,
        });
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
    if crate::lifecycle::availability(c, &availability_query, limits.max_points.get())
        .await?
        .excluded
        .iter()
        .any(|f| f.reason == UnavailableReason::Pruned)
    {
        return Err(Error::HistoryExpired);
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
        let prior = crate::aggregate::predecessor(c, spec, fold.at).await?;
        crate::aggregate::ensure_boundary(c, spec, fold.at, prior.as_ref(), limits).await?;
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
    let s = spec.stream();
    let last = fold.last.as_ref();
    let rows=sqlx::query("SELECT raw FROM rss_timeseries.samples WHERE tenant_id=$1::text::uuid AND namespace=$2 AND source=$3 AND generation=$4 AND series_digest=$5 AND observed_at >= $6 AND observed_at<$7 AND ($8::bigint IS NULL OR (observed_at,sequence,sample_id)>($8,$9::text::numeric,$10::text COLLATE \"C\")) AND rss_timeseries.visible(convert_from(raw,'UTF8')::jsonb,observed_at) ORDER BY observed_at,sequence,sample_id LIMIT $11")
 .bind(s.scope().tenant().to_string()).bind(s.scope().namespace().as_str()).bind(s.source().as_str()).bind(s.generation().as_str()).bind(spec.series().digest()?.as_bytes().as_slice()).bind(bucket.start().micros()).bind(bucket.end().micros()).bind(last.map(|p|p.0.micros())).bind(last.map(|p|p.1.to_string())).bind(last.map(|p|p.2.as_str())).bind(i64::from(r.budget().rows.get())+1).fetch_all(&mut *c).await.map_err(sql_error)?;
    let more = rows.len() > r.budget().rows.get() as usize;
    let mut total = 0usize;
    let mut processed = 0;
    for row in rows.into_iter().take(r.budget().rows.get() as usize) {
        let raw: Vec<u8> = row.try_get("raw").map_err(sql_error)?;
        total = total.checked_add(raw.len()).ok_or(Error::BudgetExceeded)?;
        if total > limits.max_bytes.get() as usize {
            return Err(Error::BudgetExceeded);
        }
        let sample: Sample = serde_json::from_slice(&raw).map_err(|_| Error::Invariant)?;
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
    if !more {
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
        crate::aggregate::store(c, spec, &summary, limits).await?;
        fold.at = bucket.end();
        fold.last = None;
        if fold.at == window.end() {
            state.fold = None;
            return Ok(Step::Done(processed));
        }
    }
    Ok(Step::More(processed))
}
