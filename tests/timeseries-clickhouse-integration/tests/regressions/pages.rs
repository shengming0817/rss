use super::*;

async fn during_select<T, M>(
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
async fn aggregate_cursor_observes_publication_and_reference_changes() -> anyhow::Result<()> {
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
    assert!(matches!(
        f.store.aggregate(&q, Some(&cursor), deadline()?).await,
        Err(Error::HistoryExpired)
    ));
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
    assert!(matches!(
        f.store.aggregate(&q, Some(&cursor), deadline()?).await,
        Err(Error::HistoryExpired)
    ));
    Ok(())
}

#[tokio::test]
async fn grouped_pages_apply_matched_fence_budget_and_reject_corrupt_samples() -> anyhow::Result<()>
{
    let f = Fixture::new("ch-group-page").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let b = batch(
        "base",
        vec![
            sample(&d, "one", 1, 1)?,
            sample(&d, "two", 2, 2)?,
            sample(&d, "three", 3, 3)?,
        ],
    )?;
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
    f.ch.sql("ALTER TABLE rss_ts_ch.raw UPDATE payload='{}' WHERE sample_id='one' SETTINGS mutations_sync=2").await?;
    assert!(matches!(
        store.query(&q, None, deadline()?).await,
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
