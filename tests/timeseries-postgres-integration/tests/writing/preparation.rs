use super::*;

#[derive(Clone, Copy, Debug)]
enum Phase {
    Admission,
    Encoding,
    Pool,
}

async fn pending<F: Future>(mut future: std::pin::Pin<&mut F>) -> anyhow::Result<()> {
    tokio::select! { biased;
        _=&mut future => anyhow::bail!("write settled before the expected phase"),
        ()=std::future::ready(())=>Ok(()),
    }
}

#[tokio::test]
async fn pre_transaction_cancellation_and_deadline_release_all_capacity() -> anyhow::Result<()> {
    let f = Fixture::new("ts-prepare-phases").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let mut limits = limits()?;
    limits.max_prepare_batches = NonZeroU32::MIN;
    let store = PgStore::new(
        f.profile.clone(),
        rss_timeseries_postgres::StoreConnections::Runtime(f.pool.clone()),
        Timer,
        limits,
        CursorKey::new([23; 32]),
        deadline()?,
    )
    .await?;
    let full = store.available_preparation();
    let auth = authority(TENANT)?;
    let holder =
        Authorized::<Batch>::verify(&auth, batch("holder", vec![sample(&d, "holder", 0, 0)?])?)?;
    let mut occupied = Vec::new();
    for _ in 0..f.pool.options().get_max_connections() {
        occupied.push(f.pool.acquire().await?);
    }
    for phase in [Phase::Admission, Phase::Encoding, Phase::Pool] {
        for expire in [false, true] {
            let n = if matches!(phase, Phase::Encoding) {
                96
            } else {
                1
            };
            let b = batch(
                &format!("{phase:?}-{expire}"),
                (0..n)
                    .map(|i| sample(&d, &format!("{phase:?}-{expire}-{i}"), i, i as u64))
                    .collect::<anyhow::Result<_>>()?,
            )?;
            let req = Authorized::<Batch>::verify(&auth, b)?;
            let q = Authorized::<ReceiptQuery>::verify(&auth, receipt_query(req.request())?)?;
            {
                let mut holder_future = Box::pin(store.write(&holder, deadline()?));
                if matches!(phase, Phase::Admission) {
                    pending(holder_future.as_mut()).await?;
                }
                let before = store.available_preparation();
                let [encoded, bound, begun] = store.preparation_phases();
                let mut write = Box::pin(store.write(
                    &req,
                    Deadline::from_timeout(&Timer, Duration::from_secs(2))?,
                ));
                // A multi-chunk batch yields within its first poll. One sample reaches
                // the exhausted pool synchronously. A second caller cannot start encoding.
                pending(write.as_mut()).await?;
                let during = store.available_preparation();
                match phase {
                    Phase::Admission => assert_eq!(during, before),
                    _ => {
                        assert_eq!(during.0, 0);
                        assert!(during.1 < before.1);
                    }
                }
                let expected = match phase {
                    Phase::Admission => [encoded, bound, begun],
                    Phase::Encoding => [encoded + 1, bound, begun],
                    Phase::Pool => [encoded + 1, bound + 1, begun],
                };
                assert_eq!(store.preparation_phases(), expected, "{phase:?}");
                if expire {
                    tokio::time::pause();
                    tokio::time::advance(Duration::from_secs(3)).await;
                    assert_eq!(write.await.err(), Some(Error::Deadline));
                    tokio::time::resume();
                }
            }
            assert_eq!(store.available_preparation(), full);
            drop(occupied.pop());
            assert!(matches!(
                store.receipt(&q, deadline()?).await?,
                Lookup::NotVisible
            ));
            let before = f.count().await?;
            assert!(matches!(
                store.write(&req, deadline()?).await?,
                Outcome::Accepted(_)
            ));
            assert_eq!(f.count().await?, before + n);
            occupied.push(f.pool.acquire().await?);
        }
    }
    Ok(())
}

#[tokio::test]
async fn byte_limit_applies_with_free_slots_and_close_wakes_waiters() -> anyhow::Result<()> {
    let f = Fixture::new("ts-prepare-weight").await?;
    let d = definition(TENANT)?;
    let mut occupied = Vec::new();
    let mut small = limits()?;
    small.max_prepare_bytes =
        NonZeroU32::new(Limits::MIN_PREPARE_BYTES - 1).ok_or(Error::InvalidInput)?;
    assert!(matches!(
        PgStore::new(
            f.profile.clone(),
            rss_timeseries_postgres::StoreConnections::Runtime(f.pool.clone()),
            Timer,
            small,
            CursorKey::new([23; 32]),
            deadline()?
        )
        .await,
        Err(Error::InvalidInput)
    ));
    let full = f.store.available_preparation();
    for _ in 0..f.pool.options().get_max_connections() {
        occupied.push(f.pool.acquire().await?);
    }
    let items = super::prepare_measure::items(&d, 0, Batch::MAX_SAMPLES, false)?;
    let req = Authorized::<Batch>::verify(&authority(TENANT)?, batch("large", items)?)?;
    let mut first = Box::pin(f.store.write(&req, deadline()?));
    pending(first.as_mut()).await?;
    let one = f.store.available_preparation();
    assert!(one.0 > 0 && one.1 < full.1 / 2);
    let mut second = Box::pin(f.store.write(&req, deadline()?));
    pending(second.as_mut()).await?;
    assert_eq!(f.store.available_preparation(), (one.0 - 1, one.1));
    drop(second);
    assert_eq!(f.store.available_preparation(), one);
    let mut second = Box::pin(f.store.write(&req, deadline()?));
    pending(second.as_mut()).await?;
    let mut closing = Box::pin(f.store.close(deadline()?));
    pending(closing.as_mut()).await?;
    assert_eq!(second.await.err(), Some(Error::Unavailable));
    drop(first);
    drop(occupied);
    closing.await?;
    assert_eq!(f.store.available_preparation(), full);
    assert_eq!(f.count().await?, 0);
    Ok(())
}

#[tokio::test]
async fn logical_clock_landing_exactly_on_cutoff_rejects_before_begin() -> anyhow::Result<()> {
    struct SwitchClock {
        start: Instant,
        cutoff: Instant,
        calls: std::sync::atomic::AtomicUsize,
    }
    impl Clock for SwitchClock {
        fn now(&self) -> Instant {
            if self
                .calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                < 2
            {
                self.start
            } else {
                self.cutoff
            }
        }
    }
    let f = Fixture::new("ts-exact-cutoff").await?;
    let start = Timer.now();
    let cutoff = start + Duration::from_secs(10);
    let store = PgStore::new(
        f.profile.clone(),
        rss_timeseries_postgres::StoreConnections::Runtime(f.pool.clone()),
        SwitchClock {
            start,
            cutoff,
            calls: Default::default(),
        },
        limits()?,
        CursorKey::new([23; 32]),
        Deadline::at(cutoff),
    )
    .await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let req = Authorized::<Batch>::verify(
        &authority(TENANT)?,
        batch("cutoff", vec![sample(&d, "cutoff", 1, 1)?])?,
    )?;
    assert_eq!(
        store.write(&req, Deadline::at(cutoff)).await.err(),
        Some(Error::Deadline)
    );
    assert_eq!(store.preparation_phases(), [0, 0, 0]);
    assert_eq!(f.count().await?, 0);
    Ok(())
}
