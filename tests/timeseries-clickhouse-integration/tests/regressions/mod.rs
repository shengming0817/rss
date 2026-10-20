use super::*;

#[tokio::test]
async fn monotone_frontiers_stay_bounded_and_preserve_replay() -> anyhow::Result<()> {
    let mut f = Fixture::new("ch-frontier").await?;
    let mut small = limits()?;
    small.max_points = NonZeroU32::new(2).ok_or(Error::InvalidInput)?;
    f.store = Fixture::connect_options(
        &f.ch,
        f.pool.clone(),
        TENANT,
        "ch_reader",
        "ch_writer",
        small,
    )
    .await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let selection = query(&d, QueryMode::History, 2)?.selection().clone();
    for n in 1..=5 {
        let before = Timestamp::new(n * 10)?;
        confirmed(
            f.write(&batch(
                &format!("b{n}"),
                vec![sample(&d, &format!("s{n}"), n * 10 - 1, 1)?],
            )?)
            .await?,
        )?;
        for (name, action) in [
            (
                format!("cut{n}"),
                MaintenanceAction::AdvanceCutoff {
                    selection: selection.clone(),
                    before,
                },
            ),
            (
                format!("prune{n}"),
                MaintenanceAction::Prune {
                    selection: selection.clone(),
                    raw_before: before,
                    summaries_before: Timestamp::new(0)?,
                },
            ),
        ] {
            assert!(matches!(
                f.maintain(&name, action).await?,
                MaintenanceProgress::Complete { .. }
            ));
        }
        assert!(
            f.store
                .query(
                    &Authorized::<Query>::verify(
                        &authority(TENANT)?,
                        query(&d, QueryMode::History, 2)?
                    )?,
                    None,
                    deadline()?
                )
                .await?
                .rows
                .is_empty()
        );
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_ts_ch.fences")
            .fetch_one(&f.admin)
            .await?;
        assert_eq!(count, 2);
    }
    assert!(matches!(
        f.maintain(
            "cut1",
            MaintenanceAction::AdvanceCutoff {
                selection: selection.clone(),
                before: Timestamp::new(10)?
            }
        )
        .await?,
        MaintenanceProgress::Complete { .. }
    ));
    assert!(
        f.write(&batch("old", vec![sample(&d, "old", 49, 1)?])?)
            .await
            .is_err()
    );
    // A third independent frontier fails atomically and cannot poison the namespace.
    let other = Selection::Resource {
        scope: d.spec().scope.clone(),
        subject: id("other")?,
        resource: id("resource")?,
        keys: Default::default(),
    };
    assert!(
        f.maintain(
            "distinct",
            MaintenanceAction::AdvanceCutoff {
                selection: other,
                before: Timestamp::new(10)?
            }
        )
        .await
        .is_err()
    );
    confirmed(
        f.write(&batch("new", vec![sample(&d, "new", 60, 1)?])?)
            .await?,
    )?;
    assert_eq!(
        f.store
            .query(
                &Authorized::<Query>::verify(
                    &authority(TENANT)?,
                    query(&d, QueryMode::History, 2)?
                )?,
                None,
                deadline()?
            )
            .await?
            .rows
            .len(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn invalidation_budget_is_scoped_and_checked_before_prepare() -> anyhow::Result<()> {
    let mut f = Fixture::new("ch-invalidate").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let b = batch("seed", vec![sample(&d, "seed", 1, 2)?])?;
    confirmed(f.write(&b).await?)?;
    let spec = SummarySpec::new(
        b.stream().clone(),
        b.samples()[0].input().series.clone(),
        NonZeroU64::new(10).ok_or(Error::InvalidInput)?,
        CoveragePolicy::ObservedOnly,
        None,
    )?;
    assert!(matches!(
        f.maintain(
            "cache",
            MaintenanceAction::Recompute {
                spec,
                window: Interval::new(Timestamp::new(0)?, Timestamp::new(40)?)?
            }
        )
        .await?,
        MaintenanceProgress::Complete { .. }
    ));
    let mut small = limits()?;
    small.max_points = NonZeroU32::new(2).ok_or(Error::InvalidInput)?;
    f.store = Fixture::connect_options(
        &f.ch,
        f.pool.clone(),
        TENANT,
        "ch_reader",
        "ch_writer",
        small,
    )
    .await?;
    let mut input = sample(&d, "unrelated", 2, 3)?.input().clone();
    input.series = Series::new(d.clone(), id("other")?, id("resource")?, Default::default())?;
    let unrelated = batch("unrelated", vec![Sample::new(input)?])?;
    confirmed(f.write(&unrelated).await?)?;
    let dirty: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_ts_ch.summaries WHERE dirty")
        .fetch_one(&f.admin)
        .await?;
    assert_eq!(dirty, 0);
    let related = batch("related", vec![sample(&d, "related", 2, 4)?])?;
    assert!(f.write(&related).await.is_err());
    let pending: i64 =
        sqlx::query_scalar("SELECT count(*) FROM rss_ts_ch.batches WHERE NOT published")
            .fetch_one(&f.admin)
            .await?;
    assert_eq!(pending, 0);
    // Maintenance is still available after the rejected admission, and resource
    // selection includes the metric key (not all keys of the resource).
    let selection = Selection::Resource {
        scope: d.spec().scope.clone(),
        subject: id("device")?,
        resource: id("resource")?,
        keys: [id("absent")?].into(),
    };
    assert!(matches!(
        f.maintain(
            "unrelated-delete",
            MaintenanceAction::Delete {
                selection,
                window: Interval::new(Timestamp::new(0)?, Timestamp::new(5)?)?,
                restore_until: Timestamp::new(i64::MAX)?
            }
        )
        .await?,
        MaintenanceProgress::Complete { .. }
    ));
    f.store = Fixture::connect(&f.ch, f.pool.clone(), TENANT, "ch_reader").await?;
    confirmed(f.write(&related).await?)?;
    let dirty: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_ts_ch.summaries WHERE dirty")
        .fetch_one(&f.admin)
        .await?;
    assert_eq!(dirty, 4);
    Ok(())
}
