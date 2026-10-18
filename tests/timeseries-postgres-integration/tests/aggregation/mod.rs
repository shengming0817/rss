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
        NonZeroU32::new(cap).ok_or(Error::InvalidInput)?,
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
        f.pool.clone(),
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
