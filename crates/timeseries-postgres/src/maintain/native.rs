//! Native work shares the component plan and publication state, but CALL refresh
//! must execute outside a transaction block. Never expose its intermediate results.
// ref: timescale/timescaledb tsl/src/continuous_aggs/refresh.c@2.30.2
use super::*;
use crate::{StorageProfile, transaction::certain};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Fold {
    at: Timestamp,
    revision: i64,
    phase: Phase,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
enum Phase {
    Project { last: Option<(i64, u64, String)> },
    Refresh,
}
#[derive(Clone)]
pub(super) struct Refreshed {
    ordinal: u64,
    at: Timestamp,
    revision: i64,
    resolution: i64,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(super) struct Cleanup {
    index: usize,
    after: i64,
    pending: Option<(i64, i64)>,
}
pub(super) fn selected(profile: &StorageProfile, r: &MaintenanceRequest) -> bool {
    let StorageProfile::TimescaleDedicatedTenant(config) = profile else {
        return false;
    };
    if matches!(r.action(), MaintenanceAction::Prune { .. }) {
        return true;
    }
    let MaintenanceAction::Recompute { spec, .. } = r.action() else {
        return false;
    };
    matches!(
        spec.series().definition().spec().metric,
        Metric::Gauge {
            number: NumberKind::I64 | NumberKind::U64
        }
    ) && config
        .resolutions
        .contains(&(spec.resolution_micros().get() as i64))
}
/// Preflight the same plan/token under its normal lock, then execute at most one
/// native bucket. A crash after CALL is recovered by refreshing that same bucket.
pub(super) async fn refresh<C: Clock>(
    store: &PgStore<C>,
    r: &MaintenanceRequest,
    after: Option<&Continuation>,
    deadline: Deadline,
) -> Result<Outcome<Option<Refreshed>>, Error> {
    let maintenance = store.maintenance.as_ref().ok_or(Error::Invariant)?;
    let request = r.clone();
    let token = after.cloned();
    let key = store.key.clone();
    let instance = store.instance.clone();
    let pending = certain(
        store
            .transaction(r.scope().tenant(), deadline, false, move |c, _| {
                Box::pin(async move {
                    let revision = lock(c, request.scope()).await?;
                    let (state, done) = load(c, &request).await?;
                    let now = db_now(c).await?;
                    if let Some(token) = &token {
                        let (_, ordinal) =
                            key.open::<u64>(DOMAIN, token, request.binding()?, &instance, now)?;
                        if ordinal > state.ordinal {
                            return Err(Error::InvalidCursor);
                        }
                        if ordinal < state.ordinal {
                            return Ok(None);
                        }
                    }
                    if done {
                        return Ok(None);
                    }
                    if let Some(cleanup) = &state.cleanup {
                        return cleanup
                            .pending
                            .map(|(resolution, at)| {
                                Ok(Refreshed {
                                    ordinal: state.ordinal,
                                    at: Timestamp::new(at)?,
                                    revision,
                                    resolution,
                                })
                            })
                            .transpose();
                    }
                    let MaintenanceAction::Recompute { spec, .. } = request.action() else {
                        return Ok(None);
                    };
                    let resolution = spec.resolution_micros().get() as i64;
                    Ok(state
                        .native
                        .filter(|f| f.revision == revision && matches!(f.phase, Phase::Refresh))
                        .map(|f| Refreshed {
                            ordinal: state.ordinal,
                            at: f.at,
                            revision,
                            resolution,
                        }))
                })
            })
            .await?,
    )?;
    let Some(pending) = pending else {
        return Ok(Outcome::Accepted(None));
    };
    let window = Interval::new(
        pending.at,
        Timestamp::new(pending.at.micros().saturating_add(pending.resolution))?,
    )?;
    let mut connection = tokio::time::timeout(
        deadline
            .remaining(store.clock.now())
            .ok_or(Error::Deadline)?,
        maintenance.acquire(),
    )
    .await
    .map_err(|_| Error::Deadline)?
    .map_err(sql_error)?;
    connection.close_on_drop();
    let ms = deadline
        .remaining(store.clock.now())
        .ok_or(Error::Deadline)?
        .as_millis()
        .clamp(1, i32::MAX as u128);
    tokio::time::timeout(
        deadline
            .remaining(store.clock.now())
            .ok_or(Error::Deadline)?,
        sqlx::query(
            "SELECT set_config('statement_timeout',$1,false),set_config('lock_timeout',$1,false)",
        )
        .bind(format!("{ms}ms"))
        .execute(&mut *connection),
    )
    .await
    .map_err(|_| Error::Deadline)?
    .map_err(sql_error)?;
    let duration = deadline
        .remaining(store.clock.now())
        .ok_or(Error::Deadline)?;
    let call=sqlx::query("CALL public.refresh_continuous_aggregate($1::text::regclass,$2::bigint,$3::bigint,force=>true,options=>'{\"buckets_per_batch\":0}'::jsonb)")
        .bind(format!("rss_timeseries.gauge_{}",pending.resolution))
        .bind(window.start().micros()).bind(window.end().micros()).execute(&mut *connection);
    match tokio::time::timeout(duration, call).await {
        Ok(Ok(_)) => Ok(Outcome::Accepted(Some(pending))),
        // reason: the provider may have committed materialization before an error or cancellation.
        _ => Ok(Outcome::Unknown),
    }
}
pub(super) async fn step(
    c: &mut PgConnection,
    r: &MaintenanceRequest,
    state: &mut State,
    revision: i64,
    limits: &Limits,
    refreshed: Option<&Refreshed>,
) -> Result<Step, Error> {
    let MaintenanceAction::Recompute { spec, window } = r.action() else {
        return Err(Error::Invariant);
    };
    if spec.bucket(window.start())?.start() != window.start()
        || spec
            .bucket(Timestamp::new(window.end().micros() - 1)?)?
            .end()
            != window.end()
    {
        return Err(Error::InvalidInput);
    }
    let query = Query::new(
        spec.selection(),
        *window,
        QueryBudget {
            max_points: r.budget().rows,
            max_series: r.budget().rows,
        },
        QueryMode::History,
    )?;
    if crate::lifecycle::availability(c, &query, limits.max_points.get())
        .await?
        .excluded
        .iter()
        .any(|f| f.reason == UnavailableReason::Pruned)
    {
        return Err(Error::HistoryExpired);
    }
    if state.native.is_none() {
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
    }
    if state.native.as_ref().is_none_or(|f| f.revision != revision) {
        state.native = Some(Fold {
            at: window.start(),
            revision,
            phase: Phase::Project { last: None },
        });
    }
    let fold = state.native.as_mut().ok_or(Error::Invariant)?;
    let bucket = spec.bucket(fold.at)?;
    match &mut fold.phase {
        Phase::Project { last } => {
            let stream = spec.stream();
            let rows=sqlx::query("SELECT observed_at,sequence::text,sample_id FROM rss_timeseries.sync_gauge($1::text::uuid,$2,$3,$4,$5,$6,$7,$8,$9::text::numeric,$10,$11)")
                .bind(r.scope().tenant().to_string()).bind(r.scope().namespace().as_str()).bind(stream.source().as_str()).bind(stream.generation().as_str()).bind(spec.series().digest()?.as_bytes().as_slice())
                .bind(bucket.start().micros()).bind(bucket.end().micros()).bind(last.as_ref().map(|p|p.0)).bind(last.as_ref().map(|p|p.1.to_string())).bind(last.as_ref().map(|p|p.2.as_str())).bind(i32::try_from(r.budget().rows.get()).map_err(|_|Error::BudgetExceeded)?)
                .fetch_all(&mut *c).await.map_err(sql_error)?;
            for row in &rows {
                let at: i64 = row.try_get("observed_at").map_err(sql_error)?;
                let seq = row
                    .try_get::<String, _>("sequence")
                    .map_err(sql_error)?
                    .parse::<u64>()
                    .map_err(|_| Error::Invariant)?;
                let id: String = row.try_get("sample_id").map_err(sql_error)?;
                if last
                    .as_ref()
                    .is_none_or(|p| (at, seq, id.as_str()) > (p.0, p.1, p.2.as_str()))
                {
                    *last = Some((at, seq, id));
                }
            }
            if rows.len() < r.budget().rows.get() as usize {
                fold.phase = Phase::Refresh;
            }
            Ok(Step::More(rows.len() as u32))
        }
        Phase::Refresh => {
            if !refreshed.is_some_and(|f| {
                f.ordinal == state.ordinal && f.at == fold.at && f.revision == revision
            }) {
                return Ok(Step::More(0));
            }
            let summary = statistics(c, spec, bucket, limits).await?;
            crate::aggregate::store(c, spec, &summary, limits).await?;
            fold.at = bucket.end();
            fold.phase = Phase::Project { last: None };
            Ok(if fold.at >= window.end() {
                Step::Done(1)
            } else {
                Step::More(1)
            })
        }
    }
}
async fn statistics(
    c: &mut PgConnection,
    spec: &SummarySpec,
    window: Interval,
    limits: &Limits,
) -> Result<Summary, Error> {
    let stream = spec.stream();
    let sql = format!(
        "SELECT total::text,valid,minimum::text,maximum::text,defects FROM rss_timeseries.gauge_{} WHERE tenant_id=$1::text::uuid AND namespace=$2 AND source=$3 AND generation=$4 AND series_digest=$5 AND bucket=$6",
        spec.resolution_micros()
    );
    let row = sqlx::query(sqlx::AssertSqlSafe(sql.as_str()))
        .bind(stream.scope().tenant().to_string())
        .bind(stream.scope().namespace().as_str())
        .bind(stream.source().as_str())
        .bind(stream.generation().as_str())
        .bind(spec.series().digest()?.as_bytes().as_slice())
        .bind(window.start().micros())
        .fetch_optional(&mut *c)
        .await
        .map_err(sql_error)?;
    let Metric::Gauge { number } = spec.series().definition().spec().metric else {
        return Err(Error::Invariant);
    };
    let mut stats = GaugeStatistics {
        sum: Sum::zero(number)?,
        count: 0,
        min: None,
        max: None,
        gaps: false,
    };
    if let Some(row) = row {
        stats.count = u64::try_from(row.try_get::<i64, _>("valid").map_err(sql_error)?)
            .map_err(|_| Error::NumericRange)?;
        stats.gaps = row.try_get::<i64, _>("defects").map_err(sql_error)? > 0;
        let total: Option<String> = row.try_get("total").map_err(sql_error)?;
        let min: Option<String> = row.try_get("minimum").map_err(sql_error)?;
        let max: Option<String> = row.try_get("maximum").map_err(sql_error)?;
        match number {
            NumberKind::I64 => {
                stats.sum = Sum::I128(
                    total
                        .as_deref()
                        .unwrap_or("0")
                        .parse()
                        .map_err(|_| Error::NumericRange)?,
                );
                stats.min = min
                    .map(|v| v.parse().map(Number::I64))
                    .transpose()
                    .map_err(|_| Error::NumericRange)?;
                stats.max = max
                    .map(|v| v.parse().map(Number::I64))
                    .transpose()
                    .map_err(|_| Error::NumericRange)?;
            }
            NumberKind::U64 => {
                stats.sum = Sum::U128(
                    total
                        .as_deref()
                        .unwrap_or("0")
                        .parse()
                        .map_err(|_| Error::NumericRange)?,
                );
                stats.min = min
                    .map(|v| v.parse().map(Number::U64))
                    .transpose()
                    .map_err(|_| Error::NumericRange)?;
                stats.max = max
                    .map(|v| v.parse().map(Number::U64))
                    .transpose()
                    .map_err(|_| Error::NumericRange)?;
            }
            NumberKind::F64 => return Err(Error::Unsupported),
        }
    }
    stats.gaps |= !crate::aggregate::deletions(c, spec, window, limits)
        .await?
        .is_empty();
    Summary::from_integer_gauge(spec, window, stats)
}

/// Physical native caches are not retained summaries. After raw pruning, purge their
/// stale contributions without ever publishing a Summary from this cleanup refresh.
pub(super) async fn cleanup(
    c: &mut PgConnection,
    r: &MaintenanceRequest,
    state: &mut State,
    resolutions: &[i64],
    refreshed: Option<&Refreshed>,
) -> Result<Step, Error> {
    let before = state.raw_limit.ok_or(Error::Invariant)?;
    let cleanup = state.cleanup.get_or_insert_with(Cleanup::default);
    if let Some((resolution, at)) = cleanup.pending {
        if refreshed.is_some_and(|f| {
            f.ordinal == state.ordinal && f.at.micros() == at && f.resolution == resolution
        }) {
            cleanup.after = at.saturating_add(resolution);
            cleanup.pending = None;
        } else {
            return Ok(Step::More(0));
        }
    }
    let Some(resolution) = resolutions.get(cleanup.index).copied() else {
        return Ok(Step::Done(0));
    };
    // Identifiers are exclusively validated positive resolution integers from the installation manifest.
    let query = format!(
        "SELECT min(bucket) FROM rss_timeseries.gauge_{resolution} WHERE tenant_id=$1::text::uuid AND namespace=$2 AND bucket >= $3 AND bucket < $4"
    );
    let bucket: Option<i64> = sqlx::query_scalar(sqlx::AssertSqlSafe(query.as_str()))
        .bind(r.scope().tenant().to_string())
        .bind(r.scope().namespace().as_str())
        .bind(cleanup.after)
        .bind(before)
        .fetch_one(c)
        .await
        .map_err(sql_error)?;
    if let Some(bucket) = bucket {
        cleanup.pending = Some((resolution, bucket));
    } else {
        cleanup.index += 1;
        cleanup.after = 0;
    }
    Ok(Step::More(0))
}
