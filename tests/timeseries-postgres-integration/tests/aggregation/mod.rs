use super::*;
pub(super) fn spec(d: &Definition, resolution: u64) -> anyhow::Result<SummarySpec> {
    let s = sample(d, "shape", 1, 1)?;
    Ok(SummarySpec::new(
        s.input().stream.clone(),
        s.input().series.clone(),
        NonZeroU64::new(resolution).ok_or(Error::InvalidInput)?,
        CoveragePolicy::ObservedOnly,
        None,
    )?)
}
pub(super) fn window(lo: i64, hi: i64) -> anyhow::Result<Interval> {
    Ok(Interval::new(Timestamp::new(lo)?, Timestamp::new(hi)?)?)
}
pub(super) fn plan(
    name: &str,
    action: MaintenanceAction,
    cap: u32,
) -> anyhow::Result<MaintenanceRequest> {
    Ok(MaintenanceRequest::new(
        id(name)?,
        action,
        MaintenanceBudget {
            rows: NonZeroU32::new(cap).ok_or(Error::InvalidInput)?,
            buckets: NonZeroU32::new(cap).ok_or(Error::InvalidInput)?,
        },
    )?)
}
pub(super) async fn complete(store: &PgStore<Timer>, r: MaintenanceRequest) -> anyhow::Result<()> {
    let request = Authorized::<MaintenanceRequest>::verify(&authority(TENANT)?, r)?;
    let mut after = None;
    for _ in 0..500 {
        match confirmed(store.step(&request, after.as_ref(), deadline()?).await?)? {
            MaintenanceProgress::Complete { .. } => return Ok(()),
            MaintenanceProgress::More { next, .. } => after = Some(next),
            MaintenanceProgress::Blocked { reason } => {
                anyhow::bail!("maintenance blocked: {reason:?}")
            }
        }
    }
    anyhow::bail!("bounded fixture steps exhausted")
}
pub(super) async fn aggregate(
    store: &PgStore<Timer>,
    spec: SummarySpec,
    lo: i64,
    hi: i64,
) -> anyhow::Result<AggregatePage> {
    let q = AggregateQuery::new(
        spec,
        window(lo, hi)?,
        QueryBudget {
            max_series: NonZeroU32::new(1).ok_or(Error::InvalidInput)?,
            max_points: NonZeroU32::new(100).ok_or(Error::InvalidInput)?,
        },
        AggregateOp::Mean,
    )?;
    Ok(store
        .aggregate(
            &Authorized::<AggregateQuery>::verify(&authority(TENANT)?, q)?,
            None,
            deadline()?,
        )
        .await?)
}
#[tokio::test]
async fn durable_rollup_late_invalidation_and_resumable_fold() -> anyhow::Result<()> {
    let f = Fixture::new("ts-rollup").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let samples = (1..20)
        .map(|i| sample(&d, &format!("p{i}"), i, i as u64))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let b = batch("initial", samples)?;
    f.write(&b).await?;
    let sp = spec(&d, 10)?;
    let r = plan(
        "refresh",
        MaintenanceAction::Recompute {
            spec: sp.clone(),
            window: window(0, 20)?,
        },
        2,
    )?;
    let authorized = Authorized::<MaintenanceRequest>::verify(&authority(TENANT)?, r.clone())?;
    assert!(matches!(
        confirmed(f.store.step(&authorized, None, deadline()?).await?)?,
        MaintenanceProgress::More { .. }
    ));
    let fresh = PgStore::new(
        rss_timeseries_postgres::StorageProfile::PostgreSQL,
        rss_timeseries_postgres::StoreConnections::Runtime(f.pool.clone()),
        Timer,
        limits()?,
        CursorKey::new([17; 32]),
        deadline()?,
    )
    .await?;
    complete(&fresh, r).await?;
    let page = aggregate(&fresh, sp.clone(), 0, 20).await?;
    assert_eq!(page.refreshed_through, Some(Timestamp::new(20)?));
    assert!(
        matches!(page.buckets[0].value,AggregateValue::Mean {sum:Sum::U128(45),count} if count.get()==9)
    );
    f.write(&batch("late", vec![sample(&d, "late", 5, 100)?])?)
        .await?;
    let page = aggregate(&fresh, sp.clone(), 0, 20).await?;
    assert_eq!(page.refreshed_through, None);
    assert!(
        matches!(page.buckets[0].value,AggregateValue::Mean {sum:Sum::U128(145),count} if count.get()==10)
    );
    complete(
        &fresh,
        plan(
            "refresh-late",
            MaintenanceAction::Recompute {
                spec: sp,
                window: window(0, 20)?,
            },
            2,
        )?,
    )
    .await?;
    let page = aggregate(&fresh, spec(&d, 20)?, 0, 20).await?;
    assert!(
        matches!(page.buckets[0].value,AggregateValue::Mean {sum:Sum::U128(290),count} if count.get()==20)
    );
    assert!(matches!(f.write(&b).await?, Outcome::Replay(_)));
    Ok(())
}
#[tokio::test]
async fn recompute_unknown_and_late_write_cannot_publish_stale_revision() -> anyhow::Result<()> {
    let f = Fixture::new("ts-refresh-race").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    f.write(&batch(
        "initial",
        vec![sample(&d, "one", 1, 1)?, sample(&d, "two", 2, 2)?],
    )?)
    .await?;
    let sp = spec(&d, 10)?;
    let r = plan(
        "refresh",
        MaintenanceAction::Recompute {
            spec: sp.clone(),
            window: window(0, 10)?,
        },
        1,
    )?;
    let authorized = Authorized::<MaintenanceRequest>::verify(&authority(TENANT)?, r.clone())?;
    f.store.inject_next_fault(Fault::CommitAckLost);
    assert!(matches!(
        f.store.step(&authorized, None, deadline()?).await?,
        Outcome::Unknown
    ));
    f.write(&batch("late", vec![sample(&d, "late", 0, 10)?])?)
        .await?;
    complete(&f.store, r).await?;
    let page = aggregate(&f.store, sp, 0, 10).await?;
    assert!(
        matches!(page.buckets[0].value,AggregateValue::Mean {sum:Sum::U128(13),count} if count.get()==3)
    );
    let changed = plan(
        "refresh",
        MaintenanceAction::CloseStream {
            stream: sample(&d, "x", 0, 0)?.input().stream.clone(),
        },
        1,
    )?;
    assert_eq!(
        f.store
            .step(
                &Authorized::<MaintenanceRequest>::verify(&authority(TENANT)?, changed)?,
                None,
                deadline()?
            )
            .await
            .err(),
        Some(Error::Conflict)
    );
    Ok(())
}

fn ordered_sample(
    d: &Definition,
    name: &str,
    at: i64,
    value: Value,
    start: Option<i64>,
) -> anyhow::Result<Sample> {
    let input = SampleInput {
        stream: Stream::new(d.spec().scope.clone(), id("sensor")?, id("generation")?),
        series: Series::new(
            d.clone(),
            id("device")?,
            id("resource")?,
            Default::default(),
        )?,
        id: id(name)?,
        sequence: at as u64,
        observed_at: Timestamp::new(at)?,
        interval: start.map(|v| window(v, at)).transpose()?,
        reading: Reading::Valid(value),
    };
    Ok(Sample::new(input)?)
}
async fn ordered_read(
    store: &PgStore<Timer>,
    spec: SummarySpec,
    range: Interval,
    op: AggregateOp,
) -> anyhow::Result<AggregatePage> {
    let q = AggregateQuery::new(
        spec,
        range,
        QueryBudget {
            max_series: NonZeroU32::MIN,
            max_points: NonZeroU32::new(100).ok_or(Error::InvalidInput)?,
        },
        op,
    )?;
    Ok(store
        .aggregate(
            &Authorized::<AggregateQuery>::verify(&authority(TENANT)?, q)?,
            None,
            deadline()?,
        )
        .await?)
}
fn ordered_spec(
    s: &Sample,
    coverage: CoveragePolicy,
    gap: Option<NonZeroU64>,
) -> anyhow::Result<SummarySpec> {
    Ok(SummarySpec::new(
        s.input().stream.clone(),
        s.input().series.clone(),
        NonZeroU64::new(10).ok_or(Error::InvalidInput)?,
        coverage,
        gap,
    )?)
}
#[tokio::test]
async fn ordered_provider_boundaries_survive_late_data_deletion_and_pruning() -> anyhow::Result<()>
{
    let f = Fixture::new("ts-ordered").await?;
    let mut ds = definition(TENANT)?.spec().clone();
    ds.key = id("counter")?;
    ds.metric = Metric::Counter {
        number: NumberKind::U64,
        temporality: Temporality::Cumulative,
    };
    let counter = Definition::new(ds)?;
    f.register(&counter).await?;
    // Construct directly because the Gauge fixture intentionally validates its input kind.
    let series = Series::new(
        counter.clone(),
        id("device")?,
        id("resource")?,
        Default::default(),
    )?;
    let stream = Stream::new(
        counter.spec().scope.clone(),
        id("sensor")?,
        id("generation")?,
    );
    let mut input = Vec::new();
    for (at, value) in [(1, 5), (6, 9), (11, 15)] {
        input.push(Sample::new(SampleInput {
            stream: stream.clone(),
            series: series.clone(),
            id: id(&format!("c{at}"))?,
            sequence: at as u64,
            observed_at: Timestamp::new(at)?,
            interval: Some(window(0, at)?),
            reading: Reading::Valid(Value::Number(Number::U64(value))),
        })?);
    }
    let sp = ordered_spec(&input[0], CoveragePolicy::ObservedOnly, NonZeroU64::new(10))?;
    f.write(&batch("counter", input)?).await?;
    complete(
        &f.store,
        plan(
            "counter-refresh",
            MaintenanceAction::Recompute {
                spec: sp.clone(),
                window: window(0, 20)?,
            },
            1,
        )?,
    )
    .await?;
    let wide = SummarySpec::new(
        stream,
        series,
        NonZeroU64::new(20).ok_or(Error::InvalidInput)?,
        CoveragePolicy::ObservedOnly,
        NonZeroU64::new(10),
    )?;
    let page = ordered_read(&f.store, wide, window(0, 20)?, AggregateOp::Rate).await?;
    assert!(
        matches!(page.buckets[0].value,AggregateValue::Rate {increase:Sum::U128(10),duration_micros} if duration_micros.get()==10)
    );
    let mut ds = definition(TENANT)?.spec().clone();
    ds.key = id("state")?;
    ds.metric = Metric::Bool;
    let state = Definition::new(ds)?;
    f.register(&state).await?;
    let a = ordered_sample(&state, "s15", 15, Value::Bool(true), None)?;
    let sp = ordered_spec(
        &a,
        CoveragePolicy::HoldLast(NonZeroU64::new(10).ok_or(Error::InvalidInput)?),
        None,
    )?;
    f.write(&batch("state", vec![a])?).await?;
    complete(
        &f.store,
        plan(
            "state-refresh",
            MaintenanceAction::Recompute {
                spec: sp.clone(),
                window: window(20, 30)?,
            },
            1,
        )?,
    )
    .await?;
    assert_eq!(
        ordered_read(&f.store, sp.clone(), window(20, 30)?, AggregateOp::Coverage)
            .await?
            .buckets[0]
            .covered_micros,
        5
    );
    complete(
        &f.store,
        plan(
            "state-cut",
            MaintenanceAction::AdvanceCutoff {
                selection: sp.selection(),
                before: Timestamp::new(20)?,
            },
            1,
        )?,
    )
    .await?;
    complete(
        &f.store,
        plan(
            "state-prune",
            MaintenanceAction::Prune {
                selection: sp.selection(),
                raw_before: Timestamp::new(20)?,
                summaries_before: Timestamp::new(20)?,
            },
            1,
        )?,
    )
    .await?;
    f.write(&batch(
        "state-late",
        vec![ordered_sample(&state, "s26", 26, Value::Bool(false), None)?],
    )?)
    .await?;
    let page = ordered_read(&f.store, sp.clone(), window(20, 30)?, AggregateOp::Coverage).await?;
    assert_eq!(page.refreshed_through, None);
    assert_eq!(page.buckets[0].covered_micros, 9);
    complete(
        &f.store,
        plan(
            "state-refreshed",
            MaintenanceAction::Recompute {
                spec: sp.clone(),
                window: window(20, 30)?,
            },
            1,
        )?,
    )
    .await?;
    complete(
        &f.store,
        plan(
            "state-delete",
            MaintenanceAction::Delete {
                selection: sp.selection(),
                window: window(21, 23)?,
                restore_until: Timestamp::new(i64::MAX)?,
            },
            1,
        )?,
    )
    .await?;
    let page = ordered_read(&f.store, sp.clone(), window(20, 30)?, AggregateOp::Coverage).await?;
    assert_eq!(page.buckets[0].covered_micros, 5);
    assert!(page.buckets[0].completeness.contains(&Completeness::Gaps));
    complete(
        &f.store,
        plan(
            "state-restore",
            MaintenanceAction::Restore {
                selection: sp.selection(),
                window: window(21, 23)?,
                deletion_fence: id("state-delete")?,
            },
            1,
        )?,
    )
    .await?;
    assert_eq!(
        ordered_read(&f.store, sp, window(20, 30)?, AggregateOp::Coverage)
            .await?
            .buckets[0]
            .covered_micros,
        9
    );
    Ok(())
}
#[tokio::test]
async fn observed_only_transition_invalidates_across_empty_buckets() -> anyhow::Result<()> {
    let f = Fixture::new("ts-observed-only").await?;
    let mut ds = definition(TENANT)?.spec().clone();
    ds.metric = Metric::Bool;
    let d = Definition::new(ds)?;
    f.register(&d).await?;
    let a = ordered_sample(&d, "a", 0, Value::Bool(false), None)?;
    let sp = ordered_spec(&a, CoveragePolicy::ObservedOnly, None)?;
    f.write(&batch(
        "initial",
        vec![a, ordered_sample(&d, "b", 25, Value::Bool(true), None)?],
    )?)
    .await?;
    complete(
        &f.store,
        plan(
            "refresh",
            MaintenanceAction::Recompute {
                spec: sp.clone(),
                window: window(20, 30)?,
            },
            1,
        )?,
    )
    .await?;
    assert!(
        matches!(ordered_read(&f.store,sp.clone(),window(20,30)?,AggregateOp::Transitions).await?.buckets[0].value,AggregateValue::Transitions(ref v) if v.len()==1)
    );
    f.write(&batch(
        "late",
        vec![ordered_sample(&d, "late", 5, Value::Bool(true), None)?],
    )?)
    .await?;
    let page = ordered_read(
        &f.store,
        sp.clone(),
        window(20, 30)?,
        AggregateOp::Transitions,
    )
    .await?;
    assert_eq!(page.refreshed_through, None);
    assert!(matches!(page.buckets[0].value,AggregateValue::Transitions(ref v) if v.is_empty()));
    complete(
        &f.store,
        plan(
            "refresh-late",
            MaintenanceAction::Recompute {
                spec: sp.clone(),
                window: window(20, 30)?,
            },
            1,
        )?,
    )
    .await?;
    complete(
        &f.store,
        plan(
            "cut",
            MaintenanceAction::AdvanceCutoff {
                selection: sp.selection(),
                before: Timestamp::new(20)?,
            },
            1,
        )?,
    )
    .await?;
    complete(
        &f.store,
        plan(
            "prune",
            MaintenanceAction::Prune {
                selection: sp.selection(),
                raw_before: Timestamp::new(20)?,
                summaries_before: Timestamp::new(20)?,
            },
            1,
        )?,
    )
    .await?;
    f.write(&batch(
        "later",
        vec![ordered_sample(&d, "later", 26, Value::Bool(false), None)?],
    )?)
    .await?;
    assert!(
        matches!(ordered_read(&f.store,sp,window(20,30)?,AggregateOp::Transitions).await?.buckets[0].value,AggregateValue::Transitions(ref v) if v.len()==1)
    );
    Ok(())
}

#[tokio::test]
async fn delta_after_prune_needs_no_predecessor_for_reads_or_recompute() -> anyhow::Result<()> {
    let f = Fixture::new("ts-delta-prune").await?;
    let mut definition_spec = definition(TENANT)?.spec().clone();
    definition_spec.metric = Metric::Counter {
        number: NumberKind::U64,
        temporality: Temporality::Delta,
    };
    let d = Definition::new(definition_spec)?;
    f.register(&d).await?;
    let sample = ordered_sample(&d, "delta", 25, Value::Number(Number::U64(7)), Some(20))?;
    let spec = ordered_spec(&sample, CoveragePolicy::ObservedOnly, NonZeroU64::new(10))?;
    f.write(&batch("delta", vec![sample])?).await?;
    complete(
        &f.store,
        plan(
            "cutoff",
            MaintenanceAction::AdvanceCutoff {
                selection: spec.selection(),
                before: Timestamp::new(20)?,
            },
            1,
        )?,
    )
    .await?;
    complete(
        &f.store,
        plan(
            "prune",
            MaintenanceAction::Prune {
                selection: spec.selection(),
                raw_before: Timestamp::new(20)?,
                summaries_before: Timestamp::new(20)?,
            },
            1,
        )?,
    )
    .await?;
    let page = ordered_read(&f.store, spec.clone(), window(20, 30)?, AggregateOp::Sum).await?;
    assert!(matches!(
        page.buckets[0].value,
        AggregateValue::Sum(Sum::U128(7))
    ));
    assert_eq!(page.refreshed_through, None);
    let page = ordered_read(&f.store, spec.clone(), window(20, 30)?, AggregateOp::Rate).await?;
    assert!(
        matches!(page.buckets[0].value,AggregateValue::Rate {increase:Sum::U128(7),duration_micros} if duration_micros.get()==5)
    );
    complete(
        &f.store,
        plan(
            "refresh",
            MaintenanceAction::Recompute {
                spec: spec.clone(),
                window: window(20, 30)?,
            },
            1,
        )?,
    )
    .await?;
    let page = ordered_read(&f.store, spec, window(20, 30)?, AggregateOp::Rate).await?;
    assert_eq!(page.refreshed_through, Some(Timestamp::new(30)?));
    assert!(
        matches!(page.buckets[0].value,AggregateValue::Rate {increase:Sum::U128(7),duration_micros} if duration_micros.get()==5)
    );
    Ok(())
}
