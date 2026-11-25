use super::pages::during_select;
use super::*;

fn window(start: i64, end: i64) -> anyhow::Result<Interval> {
    Ok(Interval::new(Timestamp::new(start)?, Timestamp::new(end)?)?)
}
fn count_query(b: &Batch, end: i64, points: u32) -> anyhow::Result<Authorized<AggregateQuery>> {
    let spec = SummarySpec::new(
        b.stream().clone(),
        b.samples()[0].input().series.clone(),
        NonZeroU64::new(100).ok_or(Error::Invariant)?,
        CoveragePolicy::ObservedOnly,
        None,
    )?;
    authorized(spec, window(0, end)?, points, AggregateOp::Count)
}
fn authorized(
    spec: SummarySpec,
    range: Interval,
    points: u32,
    op: AggregateOp,
) -> anyhow::Result<Authorized<AggregateQuery>> {
    Ok(Authorized::<AggregateQuery>::verify(
        &authority(TENANT)?,
        AggregateQuery::new(
            spec,
            range,
            QueryBudget {
                max_points: NonZeroU32::new(points).ok_or(Error::Invariant)?,
                max_series: NonZeroU32::MIN,
            },
            op,
        )?,
    )?)
}
async fn recompute(f: &Fixture, name: &str, q: &Authorized<AggregateQuery>) -> anyhow::Result<()> {
    assert!(matches!(
        f.maintain(
            name,
            MaintenanceAction::Recompute {
                spec: q.request().spec().clone(),
                window: q.request().query().window(),
            }
        )
        .await?,
        MaintenanceProgress::Complete { .. }
    ));
    Ok(())
}
async fn first_cursor(f: &Fixture, q: &Authorized<AggregateQuery>) -> anyhow::Result<Continuation> {
    Ok(f.store
        .aggregate(q, None, deadline()?)
        .await?
        .next
        .ok_or(Error::Invariant)?)
}

#[tokio::test]
async fn fixed_prefix_survives_continuous_publication_and_future_summary_replacement()
-> anyhow::Result<()> {
    let mut f = Fixture::new("ch-fixed-prefix").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let b = batch(
        "seed",
        vec![
            sample(&d, "a", 10, 1)?,
            sample(&d, "b", 110, 2)?,
            sample(&d, "c", 210, 3)?,
        ],
    )?;
    confirmed(f.write(&b).await?)?;
    let all = count_query(&b, 300, 3)?;
    recompute(&f, "initial", &all).await?;
    let baseline = f.store.aggregate(&all, None, deadline()?).await?.buckets;
    let q = count_query(&b, 300, 1)?;
    let proxy = transport::Proxy::new(&f.ch).await?;
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with((*f.pool.connect_options()).clone())
        .await?;
    f.store = proxy.store(pool).await?;
    let first = during_select(&proxy, f.store.aggregate(&q, None, deadline()?), async {
        confirmed(
            f.write(&stream_batch(&d, "other", "unrelated", 20)?)
                .await?,
        )?;
        confirmed(
            f.write(&batch("outside", vec![sample(&d, "outside", 410, 4)?])?)
                .await?,
        )?;
        let mut input = sample(&d, "other-series", 30, 5)?.input().clone();
        input.series = Series::new(
            d.clone(),
            id("other-device")?,
            id("resource")?,
            Default::default(),
        )?;
        confirmed(
            f.write(&batch("other-series", vec![Sample::new(input)?])?)
                .await?,
        )?;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    let mut buckets = first.buckets;
    let cursor = first.next.ok_or(Error::Invariant)?;
    let second = during_select(
        &proxy,
        f.store.aggregate(&q, Some(&cursor), deadline()?),
        async {
            confirmed(
                f.write(&batch(
                    "late",
                    vec![sample(&d, "late-b", 120, 6)?, sample(&d, "late-c", 220, 7)?],
                )?)
                .await?,
            )?;
            recompute(&f, "future", &all).await
        },
    )
    .await??;
    buckets.extend(second.buckets);
    let last = f
        .store
        .aggregate(&q, second.next.as_ref(), deadline()?)
        .await?;
    assert!(last.next.is_none());
    assert_eq!(last.refreshed_through, None); // new cache contains future inputs
    buckets.extend(last.buckets);
    assert_eq!(
        serde_json::to_value(buckets)?,
        serde_json::to_value(baseline)?
    );
    let latest = f.store.aggregate(&all, None, deadline()?).await?;
    assert!(matches!(latest.buckets[1].value, AggregateValue::Count(2)));
    assert!(matches!(latest.buckets[2].value, AggregateValue::Count(2)));
    Ok(())
}

#[tokio::test]
async fn equivalent_recompute_after_unrelated_publication_keeps_dense_cache_usable()
-> anyhow::Result<()> {
    let f = Fixture::new("ch-equivalent-summary").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let b = batch(
        "dense",
        (0..10)
            .map(|n| sample(&d, &format!("dense-{n}"), 101 + n, n as u64))
            .collect::<anyhow::Result<Vec<_>>>()?,
    )?;
    confirmed(f.write(&b).await?)?;
    let all = count_query(&b, 200, 2)?;
    recompute(&f, "cache", &all).await?;
    let q = count_query(&b, 200, 1)?;
    let cursor = first_cursor(&f, &q).await?;
    confirmed(f.write(&stream_batch(&d, "other", "other", 150)?).await?)?;
    let proxy = transport::Proxy::new(&f.ch).await?;
    let mut caps = limits()?;
    caps.max_points = NonZeroU32::new(2).ok_or(Error::Invariant)?;
    let store = proxy.store_with_limits(f.pool.clone(), caps).await?;
    let page = during_select(
        &proxy,
        store.aggregate(&q, Some(&cursor), deadline()?),
        recompute(&f, "equivalent", &all),
    )
    .await??;
    assert!(matches!(page.buckets[0].value, AggregateValue::Count(10)));
    assert_eq!(page.refreshed_through, Some(Timestamp::new(200)?));
    assert!(proxy.raw_read_threads().await.is_empty()); // dense raw fallback would exceed 2 points
    Ok(())
}

#[tokio::test]
async fn unused_reference_changes_do_not_retry_raw_reads_and_unlink_retries_used_objects()
-> anyhow::Result<()> {
    let f = Fixture::new("ch-reference-proof").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let b = batch(
        "seed",
        vec![sample(&d, "a", 10, 1)?, sample(&d, "b", 110, 2)?],
    )?;
    confirmed(f.write(&b).await?)?;
    let q = count_query(&b, 200, 1)?;
    let proxy = transport::Proxy::new(&f.ch).await?;
    let store = proxy.store(f.pool.clone()).await?;
    let first = during_select(&proxy, store.aggregate(&q, None, deadline()?), async {
        let second = authorized(
            q.request().spec().clone(),
            window(100, 200)?,
            1,
            AggregateOp::Count,
        )?;
        recompute(&f, "unused", &second).await
    })
    .await??;
    assert_eq!(proxy.raw_read_threads().await.len(), 1);
    let cursor = first.next.ok_or(Error::Invariant)?;
    let last = during_select(
        &proxy,
        store.aggregate(&q, Some(&cursor), deadline()?),
        async {
            assert!(matches!(
                f.maintain(
                    "unlink",
                    MaintenanceAction::Prune {
                        selection: q.request().spec().selection(),
                        raw_before: Timestamp::new(0)?,
                        summaries_before: Timestamp::new(200)?,
                    }
                )
                .await?,
                MaintenanceProgress::Complete { .. }
            ));
            Ok::<_, anyhow::Error>(())
        },
    )
    .await??;
    assert!(matches!(last.buckets[0].value, AggregateValue::Count(1)));
    assert_eq!(last.refreshed_through, None);
    Ok(())
}

#[tokio::test]
async fn delete_restore_aba_and_dirty_future_cache_require_reopen() -> anyhow::Result<()> {
    let f = Fixture::new("ch-snapshot-delete").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let b = batch(
        "seed",
        vec![sample(&d, "a", 10, 1)?, sample(&d, "b", 110, 2)?],
    )?;
    confirmed(f.write(&b).await?)?;
    let all = count_query(&b, 200, 2)?;
    recompute(&f, "cache", &all).await?;
    let q = count_query(&b, 200, 1)?;
    let cursor = first_cursor(&f, &q).await?;
    let selection = q.request().spec().selection();
    let cut = window(105, 115)?;
    let proxy = transport::Proxy::new(&f.ch).await?;
    let store = proxy.store(f.pool.clone()).await?;
    let result = during_select(
        &proxy,
        store.aggregate(&q, Some(&cursor), deadline()?),
        async {
            f.maintain(
                "hide",
                MaintenanceAction::Delete {
                    selection: selection.clone(),
                    window: cut,
                    restore_until: Timestamp::new(i64::MAX)?,
                },
            )
            .await?;
            f.maintain(
                "restore",
                MaintenanceAction::Restore {
                    selection: selection.clone(),
                    window: cut,
                    deletion_fence: id("hide")?,
                },
            )
            .await?;
            Ok::<_, anyhow::Error>(())
        },
    )
    .await?;
    assert!(matches!(result, Err(Error::SnapshotInvalidated)));
    let reopened = f.store.aggregate(&all, None, deadline()?).await?;
    assert!(matches!(
        reopened.buckets[1].value,
        AggregateValue::Count(1)
    ));
    recompute(&f, "restored-cache", &all).await?;
    let cursor = first_cursor(&f, &q).await?;
    confirmed(
        f.write(&batch("late", vec![sample(&d, "late", 120, 3)?])?)
            .await?,
    )?;
    let dirty: i64 = sqlx::query_scalar("SELECT dirty_from FROM rss_ts_ch.summaries WHERE lo=100")
        .fetch_one(&f.admin)
        .await?;
    assert!(dirty > 0);
    f.maintain(
        "hide-again",
        MaintenanceAction::Delete {
            selection: selection.clone(),
            window: cut,
            restore_until: Timestamp::new(i64::MAX)?,
        },
    )
    .await?;
    let dirty: i64 = sqlx::query_scalar("SELECT dirty_from FROM rss_ts_ch.summaries WHERE lo=100")
        .fetch_one(&f.admin)
        .await?;
    assert_eq!(dirty, 0);
    assert!(matches!(
        f.store.aggregate(&q, Some(&cursor), deadline()?).await,
        Err(Error::SnapshotInvalidated)
    ));
    assert!(matches!(
        f.store.aggregate(&all, None, deadline()?).await?.buckets[1].value,
        AggregateValue::Count(1)
    ));
    // Restore also clears a future dirty marker on a cache built while data was hidden.
    recompute(&f, "masked-cache", &all).await?;
    confirmed(
        f.write(&batch("later", vec![sample(&d, "later", 130, 4)?])?)
            .await?,
    )?;
    f.maintain(
        "restore-again",
        MaintenanceAction::Restore {
            selection,
            window: cut,
            deletion_fence: id("hide-again")?,
        },
    )
    .await?;
    let dirty: i64 = sqlx::query_scalar("SELECT dirty_from FROM rss_ts_ch.summaries WHERE lo=100")
        .fetch_one(&f.admin)
        .await?;
    assert_eq!(dirty, 0);
    assert!(matches!(
        f.store.aggregate(&all, None, deadline()?).await?.buckets[1].value,
        AggregateValue::Count(3)
    ));
    Ok(())
}

#[tokio::test]
async fn predecessor_revisions_remain_fixed_across_cached_and_raw_pages() -> anyhow::Result<()> {
    let f = Fixture::new("ch-snapshot-prior").await?;
    let mut definition = definition(TENANT)?.spec().clone();
    definition.metric = Metric::Counter {
        number: NumberKind::U64,
        temporality: Temporality::Cumulative,
    };
    let d = Definition::new(definition)?;
    f.register(&d).await?;
    let point = |name: &str, time: i64, value: u64| -> anyhow::Result<Sample> {
        let input = SampleInput {
            stream: Stream::new(d.spec().scope.clone(), id("sensor")?, id("generation")?),
            series: Series::new(
                d.clone(),
                id("device")?,
                id("resource")?,
                Default::default(),
            )?,
            id: id(name)?,
            sequence: time as u64,
            observed_at: Timestamp::new(time)?,
            interval: Some(window(0, time)?),
            reading: Reading::Valid(Value::Number(Number::U64(value))),
        };
        Ok(Sample::new(input)?)
    };
    let b = batch(
        "seed",
        vec![
            point("prior", 50, 200)?,
            point("first", 105, 100)?,
            point("second", 205, 5)?,
        ],
    )?;
    confirmed(f.write(&b).await?)?;
    let spec = SummarySpec::new(
        b.stream().clone(),
        b.samples()[0].input().series.clone(),
        NonZeroU64::new(100).ok_or(Error::Invariant)?,
        CoveragePolicy::ObservedOnly,
        NonZeroU64::new(10),
    )?;
    let q = authorized(spec.clone(), window(100, 300)?, 1, AggregateOp::Increase)?;
    let all = authorized(spec, window(100, 300)?, 2, AggregateOp::Increase)?;
    recompute(&f, "cache", &all).await?;
    let baseline = f.store.aggregate(&all, None, deadline()?).await?.buckets;
    assert!(
        baseline
            .iter()
            .all(|b| b.completeness.contains(&Completeness::ResetBoundary))
    );
    let proxy = transport::Proxy::new(&f.ch).await?;
    let store = proxy.store(f.pool.clone()).await?;
    let first = during_select(&proxy, store.aggregate(&q, None, deadline()?), async {
        confirmed(
            f.write(&batch("outside-prior", vec![point("new-prior", 90, 1)?])?)
                .await?,
        )
    })
    .await??;
    let cursor = first.next.ok_or(Error::Invariant)?;
    confirmed(
        f.write(&batch("next-prior", vec![point("next-prior", 199, 1)?])?)
            .await?,
    )?;
    recompute(&f, "future-prior-cache", &all).await?;
    let revision: i64 =
        sqlx::query_scalar("SELECT max_input_revision FROM rss_ts_ch.summaries WHERE lo=200")
            .fetch_one(&f.admin)
            .await?;
    assert_eq!(revision, 3); // the bucket's own sample is revision 1; only its predecessor is 3
    let second = store.aggregate(&q, Some(&cursor), deadline()?).await?;
    assert_eq!(
        serde_json::to_value(vec![first.buckets[0].clone(), second.buckets[0].clone()])?,
        serde_json::to_value(baseline)?
    );
    assert_eq!(second.refreshed_through, None);
    let current = f.store.aggregate(&all, None, deadline()?).await?;
    assert!(
        current
            .buckets
            .iter()
            .all(|b| !b.completeness.contains(&Completeness::ResetBoundary))
    );
    Ok(())
}

#[tokio::test]
async fn deletion_at_bucket_end_does_not_change_the_preceding_bucket() -> anyhow::Result<()> {
    let f = Fixture::new("ch-bucket-boundary").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let b = batch(
        "seed",
        vec![sample(&d, "a", 10, 1)?, sample(&d, "b", 150, 2)?],
    )?;
    confirmed(f.write(&b).await?)?;
    let all = count_query(&b, 200, 2)?;
    let baseline = f.store.aggregate(&all, None, deadline()?).await?.buckets[0].clone();
    recompute(&f, "cache", &all).await?;
    let cut = window(100, 110)?;
    let selection = all.request().spec().selection();
    f.maintain(
        "hide",
        MaintenanceAction::Delete {
            selection: selection.clone(),
            window: cut,
            restore_until: Timestamp::new(i64::MAX)?,
        },
    )
    .await?;
    assert_eq!(
        serde_json::to_value(&f.store.aggregate(&all, None, deadline()?).await?.buckets[0])?,
        serde_json::to_value(&baseline)?
    );
    f.maintain(
        "unlink",
        MaintenanceAction::Prune {
            selection: selection.clone(),
            raw_before: Timestamp::new(0)?,
            summaries_before: Timestamp::new(200)?,
        },
    )
    .await?;
    assert_eq!(
        serde_json::to_value(&f.store.aggregate(&all, None, deadline()?).await?.buckets[0])?,
        serde_json::to_value(&baseline)?
    );
    recompute(&f, "recompute", &all).await?;
    assert_eq!(
        serde_json::to_value(&f.store.aggregate(&all, None, deadline()?).await?.buckets[0])?,
        serde_json::to_value(&baseline)?
    );
    f.maintain(
        "restore",
        MaintenanceAction::Restore {
            selection,
            window: cut,
            deletion_fence: id("hide")?,
        },
    )
    .await?;
    assert_eq!(
        serde_json::to_value(&f.store.aggregate(&all, None, deadline()?).await?.buckets[0])?,
        serde_json::to_value(&baseline)?
    );
    Ok(())
}

#[tokio::test]
async fn close_and_physical_prune_separate_reopen_from_unrecoverable_history() -> anyhow::Result<()>
{
    let f = Fixture::new("ch-snapshot-prune").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let b = batch(
        "seed",
        vec![sample(&d, "a", 10, 1)?, sample(&d, "b", 110, 2)?],
    )?;
    confirmed(f.write(&b).await?)?;
    let q = count_query(&b, 200, 1)?;
    let cursor = first_cursor(&f, &q).await?;
    let proxy = transport::Proxy::new(&f.ch).await?;
    let store = proxy.store(f.pool.clone()).await?;
    let closed = during_select(
        &proxy,
        store.aggregate(&q, Some(&cursor), deadline()?),
        f.maintain(
            "close",
            MaintenanceAction::CloseStream {
                stream: b.stream().clone(),
            },
        ),
    )
    .await?;
    assert!(matches!(closed, Err(Error::SnapshotInvalidated)));
    let cursor = first_cursor(&f, &q).await?;
    let selection = q.request().spec().selection();
    f.maintain(
        "cutoff",
        MaintenanceAction::AdvanceCutoff {
            selection: selection.clone(),
            before: Timestamp::new(200)?,
        },
    )
    .await?;
    let pruned = during_select(
        &proxy,
        store.aggregate(&q, Some(&cursor), deadline()?),
        f.maintain(
            "prune",
            MaintenanceAction::Prune {
                selection,
                raw_before: Timestamp::new(200)?,
                summaries_before: Timestamp::new(200)?,
            },
        ),
    )
    .await?;
    assert!(matches!(pruned, Err(Error::SnapshotInvalidated)));
    assert!(matches!(
        f.store.aggregate(&q, None, deadline()?).await,
        Err(Error::HistoryExpired)
    ));
    assert_eq!(
        f.ch.sql("SELECT count() FROM rss_ts_ch.raw").await?.trim(),
        "0"
    );
    // Receipt retention is product input. Move fixture time facts beyond their live window.
    sqlx::query("UPDATE rss_ts_ch.batches SET received_at=0,replay_until=1")
        .execute(&f.admin)
        .await?;
    f.maintain(
        "expire",
        MaintenanceAction::ExpireReceipts {
            stream: b.stream().clone(),
            before: Timestamp::new(i64::MAX)?,
        },
    )
    .await?;
    assert!(matches!(
        f.maintain(
            "reclaim",
            MaintenanceAction::Reclaim {
                stream: b.stream().clone()
            }
        )
        .await?,
        MaintenanceProgress::Complete { .. }
    ));
    assert!(matches!(
        f.store.aggregate(&q, Some(&cursor), deadline()?).await,
        Err(Error::HistoryExpired)
    ));
    Ok(())
}

#[tokio::test]
async fn two_reference_replacements_exhaust_the_bounded_retry_without_moving_the_prefix()
-> anyhow::Result<()> {
    let f = Fixture::new("ch-reference-churn").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let b = batch(
        "seed",
        vec![sample(&d, "a", 10, 1)?, sample(&d, "b", 110, 2)?],
    )?;
    confirmed(f.write(&b).await?)?;
    let all = count_query(&b, 200, 2)?;
    recompute(&f, "cache", &all).await?;
    let q = count_query(&b, 200, 1)?;
    let cursor = first_cursor(&f, &q).await?;
    let proxy = transport::Proxy::new(&f.ch).await?;
    let store = proxy.store(f.pool.clone()).await?;
    for (label, after, expected) in [
        ("first", None, Error::Unavailable),
        ("next", Some(&cursor), Error::SnapshotInvalidated),
    ] {
        let reading = store.aggregate(&q, after, deadline()?);
        tokio::pin!(reading);
        proxy.arm(5);
        for turn in 0..2 {
            tokio::select! { _=&mut reading=>anyhow::bail!("read finished before replacement"), r=proxy.wait_held()=>r?, }
            recompute(&f, &format!("{label}-{turn}"), &all).await?;
            if turn == 0 {
                proxy.arm(5);
            }
            proxy.release();
        }
        assert!(matches!(reading.await,Err(e) if e==expected));
    }
    Ok(())
}
