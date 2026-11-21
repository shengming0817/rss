//! Real resource/authority seams; the original suite owns the recovery fault matrix.
use super::*;

fn short() -> anyhow::Result<Deadline> {
    Ok(Deadline::from_timeout(&Timer, Duration::from_millis(40))?)
}
async fn register(store: &ChStore<Timer>, d: &Definition) -> anyhow::Result<()> {
    confirmed(
        store
            .change(
                &Authorized::<DefinitionMutation>::verify(
                    &authority(&d.spec().scope.tenant().to_string())?,
                    DefinitionMutation::Register {
                        definition: d.clone(),
                        expected_latest: None,
                    },
                )?,
                deadline()?,
            )
            .await?,
    )?;
    Ok(())
}
async fn write(store: &ChStore<Timer>, b: Batch) -> anyhow::Result<Outcome<Receipt>> {
    Ok(store
        .write(
            &Authorized::<Batch>::verify(&authority(&b.stream().scope().tenant().to_string())?, b)?,
            deadline()?,
        )
        .await?)
}
fn read_request(d: &Definition, points: u32) -> anyhow::Result<Authorized<Query>> {
    Ok(Authorized::<Query>::verify(
        &authority(&d.spec().scope.tenant().to_string())?,
        query(d, QueryMode::History, points)?,
    )?)
}

#[tokio::test]
async fn tenant_materials_share_actual_pool_and_transport() -> anyhow::Result<()> {
    let mut f = Fixture::new("ch-shared").await?;
    let proxy = transport::Proxy::new(&f.ch).await?;
    // A different physical pool to the same database must not be endpoint-deduplicated.
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with((*f.pool.connect_options()).clone())
        .await?;
    f.store = proxy.store(pool.clone()).await?;
    let other = bind(&f.store.owner, OTHER, "ch_other").await?;
    let a = definition(TENANT)?;
    let b = definition(OTHER)?;
    register(&f.store, &a).await?;
    register(&other, &b).await?;
    let a_batch = batch(
        "shared",
        vec![sample(&a, "a.1", 10, 1)?, sample(&a, "a.2", 20, 2)?],
    )?;
    let b_batch = batch("shared", vec![sample(&b, "a.1", 10, 9)?])?;
    confirmed(write(&f.store, a_batch.clone()).await?)?;
    confirmed(write(&other, b_batch.clone()).await?)?;
    assert!(matches!(
        write(&f.store, a_batch).await?,
        Outcome::Replay(_)
    ));
    assert!(matches!(write(&other, b_batch).await?, Outcome::Replay(_)));
    let qa = read_request(&a, 1)?;
    let qb = read_request(&b, 10)?;
    let page = f.store.query(&qa, None, deadline()?).await?;
    assert_eq!(page.rows.len(), 1);
    assert_eq!(other.query(&qb, None, deadline()?).await?.rows.len(), 1);
    assert!(matches!(
        other.query(&qa, None, deadline()?).await,
        Err(Error::Unauthorized)
    ));
    let held = pool.acquire().await?;
    let (ra, rb) = tokio::join!(
        f.store.query(&qa, None, short()?),
        other.query(&qb, None, short()?)
    );
    assert!(matches!(ra, Err(Error::Deadline)));
    assert!(matches!(rb, Err(Error::Deadline)));
    drop(held);
    // Versions describe material; explicit retirement is the revocation operation.
    let next = f
        .store
        .owner
        .bind_tenant(
            TenantId::parse(TENANT)?,
            credentials("ch_reader")?,
            CursorKey::new([42; 32]),
            NonZeroU64::new(2).ok_or(Error::InvalidInput)?,
            deadline()?,
        )
        .await?;
    let changed_key = f
        .store
        .owner
        .bind_tenant(
            TenantId::parse(TENANT)?,
            credentials("ch_reader")?,
            CursorKey::new([43; 32]),
            NonZeroU64::new(3).ok_or(Error::InvalidInput)?,
            deadline()?,
        )
        .await?;
    assert_eq!(next.tenant(), TenantId::parse(TENANT)?);
    assert_eq!(next.material_version().get(), 2);
    let cursor = page
        .next
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("continuation"))?;
    f.store.retire(deadline()?).await?;
    assert_eq!(
        next.query(&qa, Some(cursor), deadline()?).await?.rows.len(),
        1
    );
    assert!(matches!(
        changed_key.query(&qa, Some(cursor), deadline()?).await,
        Err(Error::InvalidCursor)
    ));
    other.retire(deadline()?).await?;
    assert!(!pool.is_closed());
    assert_eq!(next.query(&qa, None, deadline()?).await?.rows.len(), 1);
    let requests = proxy.requests().await;
    let shared_connection = requests.iter().any(|(connection, user)| {
        user == "ch_reader"
            && requests.iter().any(|(other_connection, other_user)| {
                connection == other_connection && other_user == "ch_other"
            })
    });
    assert!(
        shared_connection,
        "real keepalive connection carried both authenticated readers"
    );
    assert!(requests.iter().any(|(_, user)| user == "ch_writer"));
    assert!(requests.iter().any(|(_, user)| user == "ch_maint"));
    f.store.owner.close(deadline()?).await?;
    assert!(pool.is_closed());
    assert!(
        !f.pool.is_closed(),
        "same endpoint does not merge distinct pools"
    );
    assert!(matches!(
        next.query(&qa, None, deadline()?).await,
        Err(Error::Unavailable)
    ));
    Ok(())
}

#[tokio::test]
async fn shared_budget_and_retirement_drain_complete_write() -> anyhow::Result<()> {
    let mut f = Fixture::new("ch-retire").await?;
    let proxy = transport::Proxy::new(&f.ch).await?;
    let mut caps = limits()?;
    caps.query_threads = NonZeroU32::new(2).ok_or(Error::InvalidInput)?;
    caps.operation_permits = NonZeroU32::MIN;
    assert!(
        proxy
            .store_with_limits(f.pool.clone(), caps.clone())
            .await
            .is_err()
    );
    caps.operation_permits = caps.query_threads;
    f.store = proxy.store_with_limits(f.pool.clone(), caps).await?;
    let other = bind(&f.store.owner, OTHER, "ch_other").await?;
    let a = definition(TENANT)?;
    let b = definition(OTHER)?;
    register(&f.store, &a).await?;
    register(&other, &b).await?;
    let qb = read_request(&b, 10)?;
    proxy.arm(4);
    let writing = write(&f.store, batch("drain", vec![sample(&a, "drain", 10, 1)?])?);
    tokio::pin!(writing);
    tokio::select! {
        result = &mut writing => anyhow::bail!("write completed before response gate: {}", result.is_ok()),
        ready = proxy.wait_held() => ready?,
    }
    let before = proxy.requests().await.len();
    assert!(matches!(
        other.query(&qb, None, short()?).await,
        Err(Error::Deadline)
    ));
    // A cancelled capacity waiter must not strand the permit either.
    assert!(
        tokio::time::timeout(
            Duration::from_millis(20),
            other.query(&qb, None, deadline()?)
        )
        .await
        .is_err()
    );
    assert_eq!(proxy.requests().await.len(), before);
    assert!(matches!(
        f.store.retire(short()?).await,
        Err(Error::Deadline)
    ));
    assert!(matches!(
        f.store
            .query(&read_request(&a, 10)?, None, deadline()?)
            .await,
        Err(Error::Unavailable)
    ));
    proxy.release();
    assert!(
        matches!(writing.await?, Outcome::Accepted(_)),
        "admitted publication survives retirement"
    );
    f.store.retire(deadline()?).await?;
    confirmed(write(&other, batch("other", vec![sample(&b, "other", 10, 2)?])?).await?)?;
    assert_eq!(other.query(&qb, None, deadline()?).await?.rows.len(), 1);
    assert!(
        proxy.raw_read_threads().await.contains(&(2, 2)),
        "tenant SELECT carries both thread caps"
    );
    assert!(
        proxy.raw_read_threads().await.contains(&(1, 1)),
        "projection verification is a single-permit operation"
    );
    assert!(!f.pool.is_closed());
    f.store.owner.close(deadline()?).await?;
    assert!(f.pool.is_closed());
    Ok(())
}

#[tokio::test]
async fn cancelled_close_stays_closed_and_can_finish_draining() -> anyhow::Result<()> {
    let mut f = Fixture::new("ch-close").await?;
    let proxy = transport::Proxy::new(&f.ch).await?;
    f.store = proxy.store(f.pool.clone()).await?;
    let a = definition(TENANT)?;
    register(&f.store, &a).await?;
    let q = read_request(&a, 10)?;
    proxy.arm(4);
    let writing = write(&f.store, batch("close", vec![sample(&a, "close", 10, 1)?])?);
    tokio::pin!(writing);
    tokio::select! {
        result = &mut writing => anyhow::bail!("write completed before response gate: {}", result.is_ok()),
        ready = proxy.wait_held() => ready?,
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(20), f.store.owner.close(deadline()?))
            .await
            .is_err()
    );
    assert!(matches!(
        f.store.owner.close(short()?).await,
        Err(Error::Deadline)
    ));
    assert!(!f.pool.is_closed());
    assert!(matches!(
        f.store.query(&q, None, deadline()?).await,
        Err(Error::Unavailable)
    ));
    assert!(bind(&f.store.owner, OTHER, "ch_other").await.is_err());
    proxy.release();
    assert!(matches!(writing.await?, Outcome::Accepted(_)));
    f.store.owner.close(deadline()?).await?;
    f.store.owner.close(deadline()?).await?;
    assert!(f.pool.is_closed());
    f.store.retire(deadline()?).await?;
    Ok(())
}

#[tokio::test]
async fn dropped_owner_stops_admission_while_an_operation_keeps_resources_alive()
-> anyhow::Result<()> {
    let mut f = Fixture::new("ch-drop-owner").await?;
    let proxy = transport::Proxy::new(&f.ch).await?;
    f.store = proxy.store(f.pool.clone()).await?;
    let d = definition(TENANT)?;
    register(&f.store, &d).await?;
    let q = read_request(&d, 10)?;
    let OwnedStore { access, owner } = f.store;
    proxy.arm(4);
    let writing = write(&access, batch("drop", vec![sample(&d, "drop", 10, 1)?])?);
    tokio::pin!(writing);
    tokio::select! {
        result = &mut writing => anyhow::bail!("write completed before response gate: {}", result.is_ok()),
        ready = proxy.wait_held() => ready?,
    }
    drop(owner);
    assert!(matches!(
        access.query(&q, None, deadline()?).await,
        Err(Error::Unavailable)
    ));
    assert!(matches!(
        access.retire(short()?).await,
        Err(Error::Deadline)
    ));
    proxy.release();
    assert!(matches!(writing.await?, Outcome::Accepted(_)));
    access.retire(deadline()?).await?;
    f.pool.close().await;
    Ok(())
}

#[tokio::test]
async fn cancelled_write_releases_capacity_and_recovers_original_identity() -> anyhow::Result<()> {
    let mut f = Fixture::new("ch-cancel-call").await?;
    let proxy = transport::Proxy::new(&f.ch).await?;
    let mut caps = limits()?;
    caps.operation_permits = NonZeroU32::new(1).ok_or(Error::InvalidInput)?;
    f.store = proxy.store_with_limits(f.pool.clone(), caps).await?;
    let other = bind(&f.store.owner, OTHER, "ch_other").await?;
    let a = definition(TENANT)?;
    let b = definition(OTHER)?;
    register(&f.store, &a).await?;
    register(&other, &b).await?;
    proxy.arm(4);
    {
        let writing = write(
            &f.store,
            batch("cancel", vec![sample(&a, "cancel", 10, 1)?])?,
        );
        tokio::pin!(writing);
        tokio::select! {
            result = &mut writing => anyhow::bail!("write completed before gate: {}", result.is_ok()),
            ready = proxy.wait_held() => ready?,
        }
        // Drop the actual caller future after a real INSERT, without observing its result.
    }
    assert!(
        other
            .query(&read_request(&b, 10)?, None, deadline()?)
            .await?
            .rows
            .is_empty()
    );
    assert!(
        f.store
            .query(&read_request(&a, 10)?, None, deadline()?)
            .await?
            .rows
            .is_empty()
    );
    proxy.release();
    assert!(
        confirmed(
            f.store
                .recover(&a.spec().scope, &authority(TENANT)?, deadline()?)
                .await?
        )?
        .is_some()
    );
    assert_eq!(
        f.store
            .query(&read_request(&a, 10)?, None, deadline()?)
            .await?
            .rows
            .len(),
        1
    );
    f.store.owner.close(deadline()?).await?;
    Ok(())
}

#[tokio::test]
async fn new_reader_is_verified_on_an_already_admitted_owner() -> anyhow::Result<()> {
    let f = Fixture::new("ch-bind-probe").await?;
    assert!(bind(&f.store.owner, OTHER, "ch_reader").await.is_err());
    assert!(bind(&f.store.owner, OTHER, "ch_writer").await.is_err());
    for (bad, undo) in [
        (
            "GRANT INSERT ON rss_ts_ch.raw TO ch_other",
            "REVOKE INSERT ON rss_ts_ch.raw FROM ch_other",
        ),
        (
            "CREATE ROW POLICY broad ON rss_ts_ch.raw USING 1 TO ch_other",
            "DROP ROW POLICY broad ON rss_ts_ch.raw",
        ),
        (
            "CREATE ROLE inherited; GRANT inherited TO ch_other",
            "REVOKE inherited FROM ch_other; DROP ROLE inherited",
        ),
    ] {
        f.ch.sql(bad).await?;
        assert!(bind(&f.store.owner, OTHER, "ch_other").await.is_err());
        f.ch.sql(undo).await?;
    }
    let other = bind(&f.store.owner, OTHER, "ch_other").await?;
    let d = definition(OTHER)?;
    register(&other, &d).await?;
    confirmed(write(&other, batch("safe", vec![sample(&d, "safe", 10, 1)?])?).await?)?;
    assert_eq!(
        other
            .query(&read_request(&d, 10)?, None, deadline()?)
            .await?
            .rows
            .len(),
        1
    );
    Ok(())
}
