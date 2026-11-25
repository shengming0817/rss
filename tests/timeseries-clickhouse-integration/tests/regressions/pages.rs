use super::*;

pub(super) async fn during_select<T, M>(
    proxy: &transport::Proxy,
    read: impl std::future::Future<Output = T>,
    change: impl std::future::Future<Output = anyhow::Result<M>>,
) -> anyhow::Result<T> {
    proxy.arm(5);
    tokio::pin!(read);
    tokio::select! { _=&mut read=>anyhow::bail!("page completed before SELECT response"), ready=proxy.wait_held()=>ready?, }
    change.await?;
    proxy.release();
    Ok(read.await)
}

#[tokio::test]
async fn slow_page_releases_single_pg_connection_and_checks_lifecycle() -> anyhow::Result<()> {
    let mut f = Fixture::new("ch-page-race").await?;
    let proxy = transport::Proxy::new(&f.ch).await?;
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with((*f.pool.connect_options()).clone())
        .await?;
    f.store = proxy.store(pool).await?;
    let d = definition(TENANT)?;
    let auth = authority(TENANT)?;
    let q = Authorized::<Query>::verify(&auth, query(&d, QueryMode::History, 1)?)?;
    assert!(f.store.query(&q, None, deadline()?).await?.rows.is_empty());
    let prototype = sample(&d, "empty", 1, 1)?;
    let spec = SummarySpec::new(
        prototype.input().stream.clone(),
        prototype.input().series.clone(),
        NonZeroU64::MIN,
        CoveragePolicy::ObservedOnly,
        None,
    )?;
    let empty = Authorized::<AggregateQuery>::verify(
        &auth,
        AggregateQuery::new(
            spec,
            Interval::new(Timestamp::new(0)?, Timestamp::new(2)?)?,
            QueryBudget {
                max_points: NonZeroU32::MIN,
                max_series: NonZeroU32::MIN,
            },
            AggregateOp::Count,
        )?,
    )?;
    let empty_page = f.store.aggregate(&empty, None, deadline()?).await?;
    assert!(empty_page.buckets.is_empty() && empty_page.next.is_none());
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_ts_ch.namespaces")
        .fetch_one(&f.admin)
        .await?;
    assert_eq!(n, 0);
    f.register(&d).await?;
    let seed = batch(
        "base",
        vec![sample(&d, "one", 1, 1)?, sample(&d, "two", 2, 2)?],
    )?;
    confirmed(f.write(&seed).await?)?;
    let b = stream_batch(&d, "z", "later", 3)?;
    let first = during_select(&proxy, f.store.query(&q, None, deadline()?), async {
        confirmed(f.write(&b).await?)
    })
    .await??;
    let cursor = first.next.ok_or(Error::Invariant)?;
    let last = f.store.query(&q, Some(&cursor), deadline()?).await?;
    assert_eq!(last.rows[0].sample.input().id, id("two")?);
    assert!(last.next.is_none());

    let window = Interval::new(Timestamp::new(0)?, Timestamp::new(3)?)?;
    let selection = q.request().selection().clone();
    let result = during_select(
        &proxy,
        f.store.query(&q, Some(&cursor), deadline()?),
        f.maintain(
            "hide",
            MaintenanceAction::Delete {
                selection: selection.clone(),
                window,
                restore_until: Timestamp::new(i64::MAX)?,
            },
        ),
    )
    .await?;
    assert!(matches!(result, Err(Error::HistoryExpired)));
    let restored = during_select(
        &proxy,
        f.store.query(&q, None, deadline()?),
        f.maintain(
            "restore",
            MaintenanceAction::Restore {
                selection: selection.clone(),
                window,
                deletion_fence: id("hide")?,
            },
        ),
    )
    .await??;
    assert_eq!(restored.rows[0].sample.input().id, id("one")?);
    f.maintain(
        "cut",
        MaintenanceAction::AdvanceCutoff {
            selection: selection.clone(),
            before: window.end(),
        },
    )
    .await?;
    let pruned = during_select(
        &proxy,
        f.store.query(&q, None, deadline()?),
        f.maintain(
            "prune",
            MaintenanceAction::Prune {
                selection,
                raw_before: window.end(),
                summaries_before: Timestamp::new(0)?,
            },
        ),
    )
    .await??;
    assert_eq!(pruned.rows[0].sample.input().id, id("later")?);
    Ok(())
}

#[tokio::test]
async fn aggregate_cursor_survives_publication_and_equivalent_reference_changes()
-> anyhow::Result<()> {
    let f = Fixture::new("ch-cache-page").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let b = stream_batch(&d, "sensor", "seed", 1)?;
    confirmed(f.write(&b).await?)?;
    let seeded = seed_count_query(&f, &b).await?;
    let spec = seeded.request().spec().clone();
    let q = Authorized::<AggregateQuery>::verify(
        &authority(TENANT)?,
        AggregateQuery::new(
            spec.clone(),
            Interval::new(Timestamp::new(0)?, Timestamp::new(200)?)?,
            QueryBudget {
                max_series: NonZeroU32::MIN,
                max_points: NonZeroU32::MIN,
            },
            AggregateOp::Count,
        )?,
    )?;
    let cursor = f
        .store
        .aggregate(&q, None, deadline()?)
        .await?
        .next
        .ok_or(Error::Invariant)?;
    confirmed(f.write(&stream_batch(&d, "other", "later", 3)?).await?)?;
    assert!(
        f.store
            .aggregate(&q, Some(&cursor), deadline()?)
            .await?
            .next
            .is_none()
    );
    let cursor = f
        .store
        .aggregate(&q, None, deadline()?)
        .await?
        .next
        .ok_or(Error::Invariant)?;
    let proxy = transport::Proxy::new(&f.ch).await?;
    let store = proxy.store(f.pool.clone()).await?;
    let page = during_select(
        &proxy,
        store.aggregate(&q, None, deadline()?),
        f.maintain(
            "replace",
            MaintenanceAction::Recompute {
                spec,
                window: seeded.request().query().window(),
            },
        ),
    )
    .await??;
    assert!(matches!(page.buckets[0].value, AggregateValue::Count(1)));
    assert!(
        f.store
            .aggregate(&q, Some(&cursor), deadline()?)
            .await?
            .next
            .is_none()
    );
    let uncached = during_select(
        &proxy,
        store.aggregate(&q, None, deadline()?),
        f.maintain(
            "unlink",
            MaintenanceAction::Prune {
                selection: q.request().spec().selection(),
                raw_before: Timestamp::new(0)?,
                summaries_before: Timestamp::new(100)?,
            },
        ),
    )
    .await??;
    assert!(matches!(
        uncached.buckets[0].value,
        AggregateValue::Count(1)
    ));
    assert_eq!(uncached.refreshed_through, None);
    assert!(page.refreshed_through.is_some());
    Ok(())
}

#[tokio::test]
async fn grouped_pages_apply_matched_fence_budget_and_reject_corrupt_samples() -> anyhow::Result<()>
{
    let f = Fixture::new("ch-group-page").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let samples = ["one", "two", "three"]
        .into_iter()
        .enumerate()
        .map(|(i, name)| -> anyhow::Result<Sample> {
            let mut input = sample(&d, name, i as i64 + 1, i as u64 + 1)?
                .input()
                .clone();
            input.stream = Stream::new(d.spec().scope.clone(), id("a?fields")?, id("gen??")?);
            Ok(Sample::new(input)?)
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let b = batch("base", samples)?;
    confirmed(f.write(&b).await?)?;
    confirmed(f.write(&stream_batch(&d, "z", "four", 4)?).await?)?;
    let range = Interval::new(Timestamp::new(0)?, Timestamp::new(10)?)?;
    for name in ["x", "y"] {
        f.maintain(
            name,
            MaintenanceAction::Delete {
                selection: Selection::Resource {
                    scope: d.spec().scope.clone(),
                    subject: id(name)?,
                    resource: id("resource")?,
                    keys: Default::default(),
                },
                window: range,
                restore_until: Timestamp::new(i64::MAX)?,
            },
        )
        .await?;
    }
    let mut caps = limits()?;
    caps.max_fences = NonZeroU32::MIN;
    let store = Fixture::connect_options(
        &f.ch,
        f.pool.clone(),
        TENANT,
        "ch_reader",
        "ch_writer",
        caps,
    )
    .await?;
    let selection = query(&d, QueryMode::History, 2)?.selection().clone();
    let q = Authorized::<Query>::verify(
        &authority(TENANT)?,
        Query::new(
            selection.clone(),
            range,
            QueryBudget {
                max_series: NonZeroU32::MIN,
                max_points: NonZeroU32::new(2).ok_or(Error::Invariant)?,
            },
            QueryMode::History,
        )?,
    )?;
    let mut ids = Vec::new();
    let mut cursor = None;
    loop {
        let page = store.query(&q, cursor.as_ref(), deadline()?).await?;
        ids.extend(page.rows.iter().map(|r| r.sample.input().id.clone()));
        cursor = page.next;
        if cursor.is_none() {
            break;
        }
        anyhow::ensure!(ids.len() < 4);
    }
    assert_eq!(ids, vec![id("one")?, id("two")?, id("three")?, id("four")?]);
    // The second page has room for a lookahead point but the following group is outside its budget.
    f.ch.sql("INSERT INTO rss_ts_ch.raw SELECT * REPLACE ('{}' AS payload) FROM rss_ts_ch.raw WHERE sample_id='four'").await?;
    let first = store.query(&q, None, deadline()?).await?;
    let second = store
        .query(&q, Some(&first.next.ok_or(Error::Invariant)?), deadline()?)
        .await?;
    assert_eq!(second.rows.len(), 1);
    assert_eq!(second.rows[0].sample.input().id, id("three")?);
    assert!(matches!(
        store
            .query(&q, Some(&second.next.ok_or(Error::Invariant)?), deadline()?)
            .await,
        Err(Error::Invariant)
    ));
    for name in ["match1", "match2"] {
        f.maintain(
            name,
            MaintenanceAction::Delete {
                selection: selection.clone(),
                window: range,
                restore_until: Timestamp::new(i64::MAX)?,
            },
        )
        .await?;
    }
    assert!(matches!(
        store.query(&q, None, deadline()?).await,
        Err(Error::BudgetExceeded)
    ));
    Ok(())
}

#[tokio::test]
async fn fine_retained_summaries_paginate_at_whole_bucket_boundaries() -> anyhow::Result<()> {
    let f = Fixture::new("ch-ref-budget").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let b = batch(
        "fine",
        vec![sample(&d, "a", 25, 1)?, sample(&d, "b", 125, 2)?],
    )?;
    confirmed(f.write(&b).await?)?;
    let spec = |width| {
        SummarySpec::new(
            b.stream().clone(),
            b.samples()[0].input().series.clone(),
            NonZeroU64::new(width).ok_or(Error::Invariant)?,
            CoveragePolicy::ObservedOnly,
            None,
        )
    };
    let range = Interval::new(Timestamp::new(0)?, Timestamp::new(200)?)?;
    f.maintain(
        "fine",
        MaintenanceAction::Recompute {
            spec: spec(50)?,
            window: range,
        },
    )
    .await?;
    let selection = spec(50)?.selection();
    f.maintain(
        "cut",
        MaintenanceAction::AdvanceCutoff {
            selection: selection.clone(),
            before: range.end(),
        },
    )
    .await?;
    f.maintain(
        "prune",
        MaintenanceAction::Prune {
            selection,
            raw_before: range.end(),
            summaries_before: Timestamp::new(0)?,
        },
    )
    .await?;
    let mut caps = limits()?;
    caps.max_points = NonZeroU32::new(2).ok_or(Error::Invariant)?;
    let q = Authorized::<AggregateQuery>::verify(
        &authority(TENANT)?,
        AggregateQuery::new(
            spec(100)?,
            range,
            QueryBudget {
                max_points: caps.max_points,
                max_series: NonZeroU32::MIN,
            },
            AggregateOp::Count,
        )?,
    )?;
    let store = Fixture::connect_options(
        &f.ch,
        f.pool.clone(),
        TENANT,
        "ch_reader",
        "ch_writer",
        caps,
    )
    .await?;
    let first = store.aggregate(&q, None, deadline()?).await?;
    assert_eq!(first.buckets.len(), 1);
    assert!(matches!(first.buckets[0].value, AggregateValue::Count(1)));
    let second = store
        .aggregate(&q, Some(&first.next.ok_or(Error::Invariant)?), deadline()?)
        .await?;
    assert_eq!(second.buckets.len(), 1);
    assert!(matches!(second.buckets[0].value, AggregateValue::Count(1)));
    assert!(second.next.is_none());
    Ok(())
}

#[tokio::test]
async fn covered_prune_does_not_strand_an_unrelated_summary_attempt() -> anyhow::Result<()> {
    let f = Fixture::new("ch-covered-prune").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let a = stream_batch(&d, "discard", "old", 1)?;
    let b = stream_batch(&d, "retain", "keep", 2)?;
    confirmed(f.write(&a).await?)?;
    confirmed(f.write(&b).await?)?;
    let selection = Selection::Exact {
        stream: a.stream().clone(),
        series: a.samples()[0].input().series.clone(),
    };
    let before = Timestamp::new(10)?;
    f.maintain(
        "cut",
        MaintenanceAction::AdvanceCutoff {
            selection: selection.clone(),
            before,
        },
    )
    .await?;
    let prune = MaintenanceAction::Prune {
        selection,
        raw_before: before,
        summaries_before: Timestamp::new(0)?,
    };
    f.maintain("first", prune.clone()).await?;
    let spec = SummarySpec::new(
        b.stream().clone(),
        b.samples()[0].input().series.clone(),
        NonZeroU64::new(10).ok_or(Error::Invariant)?,
        CoveragePolicy::ObservedOnly,
        None,
    )?;
    let recompute = MaintenanceAction::Recompute {
        spec,
        window: Interval::new(Timestamp::new(0)?, before)?,
    };
    let request = Authorized::<MaintenanceRequest>::verify(
        &authority(TENANT)?,
        MaintenanceRequest::new(
            id("summary")?,
            recompute.clone(),
            MaintenanceBudget {
                rows: NonZeroU32::new(2).ok_or(Error::Invariant)?,
                buckets: NonZeroU32::MIN,
            },
        )?,
    )?;
    assert!(matches!(
        confirmed(f.store.step(&request, None, deadline()?).await?)?,
        MaintenanceProgress::More { .. }
    ));
    let active: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT FROM rss_ts_ch.attempts WHERE allowed AND target='summaries')",
    )
    .fetch_one(&f.admin)
    .await?;
    assert!(active);
    f.maintain("covered", prune).await?;
    assert!(matches!(
        f.maintain("summary", recompute).await?,
        MaintenanceProgress::Complete { .. }
    ));
    Ok(())
}
