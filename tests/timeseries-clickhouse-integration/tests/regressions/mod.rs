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
    let pending: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM rss_ts_ch.batches WHERE phase IN ('prepared','verified')",
    )
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
    // Two distinct series each fan out to two buckets. Their union exceeds
    // the per-series budget while each input remains admissible.
    let mut inputs = Vec::new();
    for key in ["pressure", "humidity"] {
        let definition = Definition::new(DefinitionSpec {
            key: id(key)?,
            ..d.spec().clone()
        })?;
        f.register(&definition).await?;
        let point = sample(&definition, key, 1, 1)?;
        let spec = SummarySpec::new(
            point.input().stream.clone(),
            point.input().series.clone(),
            NonZeroU64::new(10).ok_or(Error::Invariant)?,
            CoveragePolicy::ObservedOnly,
            None,
        )?;
        f.maintain(
            key,
            MaintenanceAction::Recompute {
                spec,
                window: Interval::new(Timestamp::new(0)?, Timestamp::new(20)?)?,
            },
        )
        .await?;
        inputs.push(point);
    }
    let mut caps = limits()?;
    caps.max_points = NonZeroU32::new(2).ok_or(Error::Invariant)?;
    f.store = Fixture::connect_options(
        &f.ch,
        f.pool.clone(),
        TENANT,
        "ch_reader",
        "ch_writer",
        caps,
    )
    .await?;
    assert_eq!(
        confirmed(f.write(&batch("two-series", inputs)?).await?)?.new_samples(),
        2
    );
    let dirty: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_ts_ch.summaries WHERE dirty")
        .fetch_one(&f.admin)
        .await?;
    assert_eq!(dirty, 8);
    Ok(())
}

fn stream_batch(d: &Definition, source: &str, name: &str, time: i64) -> anyhow::Result<Batch> {
    let mut input = sample(d, name, time, 1)?.input().clone();
    input.stream = Stream::new(d.spec().scope.clone(), id(source)?, id("generation")?);
    batch(name, vec![Sample::new(input)?])
}

#[tokio::test]
async fn independent_streams_publish_one_contiguous_prefix() -> anyhow::Result<()> {
    let f = Fixture::new("ch-prefix").await?;
    sqlx::query("UPDATE rss_ts_ch.installation SET max_pending_batches=2")
        .execute(&f.admin)
        .await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let seed = batch(
        "seed",
        vec![sample(&d, "first", 10, 1)?, sample(&d, "second", 20, 2)?],
    )?;
    confirmed(f.write(&seed).await?)?;
    let public = authority(TENANT)?;
    let q = Authorized::<Query>::verify(&public, query(&d, QueryMode::History, 1)?)?;
    let cursor = f
        .store
        .query(&q, None, deadline()?)
        .await?
        .next
        .ok_or(Error::Invariant)?;
    let a = stream_batch(&d, "left", "a", 30)?;
    let b = stream_batch(&d, "right", "b", 40)?;
    let spec = SummarySpec::new(
        b.stream().clone(),
        b.samples()[0].input().series.clone(),
        NonZeroU64::new(100).ok_or(Error::Invariant)?,
        CoveragePolicy::ObservedOnly,
        None,
    )?;
    let window = Interval::new(Timestamp::new(0)?, Timestamp::new(100)?)?;
    f.maintain(
        "seed-summary",
        MaintenanceAction::Recompute {
            spec: spec.clone(),
            window,
        },
    )
    .await?;
    let aq = Authorized::<AggregateQuery>::verify(
        &public,
        AggregateQuery::new(
            spec,
            window,
            QueryBudget {
                max_points: NonZeroU32::new(10).ok_or(Error::Invariant)?,
                max_series: NonZeroU32::MIN,
            },
            AggregateOp::Count,
        )?,
    )?;
    f.store.inject_next_fault(Fault::AfterInsert);
    assert!(matches!(f.write(&a).await?, Outcome::Unknown));
    assert!(
        f.write(&stream_batch(&d, "left", "different", 31)?)
            .await
            .is_err()
    );
    assert!(matches!(f.write(&b).await?, Outcome::Unknown));
    let qb = Authorized::<ReceiptQuery>::verify(&public, receipt_query(&b)?)?;
    assert_eq!(
        f.store.progress(&qb, deadline()?).await?,
        rss_timeseries_clickhouse::ProjectionProgress::Verified
    );
    assert!(matches!(
        f.store.receipt(&qb, deadline()?).await?,
        Lookup::NotVisible
    ));
    assert!(matches!(f.write(&b).await?, Outcome::Unknown));
    assert!(
        f.write(&stream_batch(&d, "third", "full", 35)?)
            .await
            .is_err()
    );
    assert_eq!(f.read(&d).await?.rows.len(), 2);
    let latest = Authorized::<Query>::verify(&public, query(&d, QueryMode::Latest, 10)?)?;
    assert_eq!(
        f.store.query(&latest, None, deadline()?).await?.rows.len(),
        1
    );
    assert!(matches!(
        f.store.aggregate(&aq, None, deadline()?).await?.buckets[0].value,
        AggregateValue::Missing
    ));
    assert!(matches!(
        f.maintain(
            "hold",
            MaintenanceAction::CloseStream {
                stream: b.stream().clone()
            }
        )
        .await?,
        MaintenanceProgress::Blocked {
            reason: MaintenanceBlock::PendingWrite
        }
    ));
    let permits: Vec<i64> = sqlx::query_scalar(
        "SELECT revision FROM rss_ts_ch.attempts WHERE target='raw' AND allowed",
    )
    .fetch_all(&f.admin)
    .await?;
    assert_eq!(
        permits,
        vec![2],
        "the successor cannot revoke the head's permit"
    );
    let recovered = confirmed(
        f.store
            .recover(&d.spec().scope, &public, deadline()?)
            .await?,
    )?
    .ok_or(Error::Invariant)?;
    assert_eq!(recovered.identity().batch_id, a.id().clone());
    assert!(matches!(
        f.store.receipt(&qb, deadline()?).await?,
        Lookup::Found(_)
    ));
    assert_eq!(f.read(&d).await?.rows.len(), 4);
    assert_eq!(
        f.store.query(&latest, None, deadline()?).await?.rows.len(),
        3
    );
    assert!(matches!(
        f.store.aggregate(&aq, None, deadline()?).await?.buckets[0].value,
        AggregateValue::Count(1)
    ));
    let old = f.store.query(&q, Some(&cursor), deadline()?).await?;
    assert_eq!(old.rows[0].sample.input().id, id("second")?);
    assert!(old.next.is_none());
    assert!(matches!(f.write(&b).await?, Outcome::Replay(_)));
    Ok(())
}

#[tokio::test]
async fn successor_verifies_while_the_heads_insert_response_is_in_flight() -> anyhow::Result<()> {
    let f = Fixture::new("ch-overlap").await?;
    sqlx::query("UPDATE rss_ts_ch.installation SET max_pending_batches=2")
        .execute(&f.admin)
        .await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let proxy = transport::Proxy::new(&f.ch).await?;
    let writer = proxy.store(f.pool.clone()).await?;
    let auth = authority(TENANT)?;
    let head = Authorized::<Batch>::verify(&auth, stream_batch(&d, "a", "head", 10)?)?;
    let tail = stream_batch(&d, "b", "tail", 20)?;
    let receipt = Authorized::<ReceiptQuery>::verify(&auth, receipt_query(&tail)?)?;
    proxy.arm(4);
    let writing = writer.write(&head, deadline()?);
    tokio::pin!(writing);
    tokio::select! {
        result=&mut writing => anyhow::bail!("head finished before the response gate: {}",result.is_ok()),
        ready=proxy.wait_held()=>ready?,
    }
    assert!(matches!(f.write(&tail).await?, Outcome::Unknown));
    assert_eq!(
        f.store.progress(&receipt, deadline()?).await?,
        rss_timeseries_clickhouse::ProjectionProgress::Verified
    );
    proxy.release();
    confirmed(writing.await?)?;
    assert!(matches!(
        f.store.receipt(&receipt, deadline()?).await?,
        Lookup::Found(_)
    ));
    assert_eq!(f.read(&d).await?.rows.len(), 2);
    Ok(())
}
