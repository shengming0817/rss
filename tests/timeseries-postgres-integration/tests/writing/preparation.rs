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
    let phases = f.store.preparation_phases();
    let mut second = Box::pin(f.store.write(&req, deadline()?));
    pending(second.as_mut()).await?;
    assert_eq!(f.store.available_preparation(), one);
    assert_eq!(f.store.preparation_phases(), phases);
    let small = Authorized::<Batch>::verify(
        &authority(TENANT)?,
        batch("bypass", vec![sample(&d, "bypass", 1, 1)?])?,
    )?;
    let mut bypass = Box::pin(f.store.write(&small, deadline()?));
    pending(bypass.as_mut()).await?;
    assert_eq!(f.store.available_preparation().0, one.0 - 1);
    drop(bypass);
    let mut third = Box::pin(f.store.write(&small, deadline()?));
    pending(third.as_mut()).await?;
    assert_eq!(f.store.available_preparation(), one);
    drop(second);
    // Cancelling the head grants the waiting successor before it is polled.
    assert_eq!(f.store.available_preparation().0, one.0 - 1);
    drop(third);
    assert_eq!(f.store.available_preparation(), one);
    let mut expiring = Box::pin(f.store.write(
        &req,
        Deadline::from_timeout(&Timer, Duration::from_secs(1))?,
    ));
    pending(expiring.as_mut()).await?;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(2)).await;
    assert_eq!(expiring.await.err(), Some(Error::Deadline));
    tokio::time::resume();
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
    use std::sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    };

    // Each read advances the logical clock by one second. The wall watchdog stays live.
    #[derive(Clone)]
    struct TickClock(Instant, Arc<AtomicU32>);
    impl Clock for TickClock {
        fn now(&self) -> Instant {
            self.0 + Duration::from_secs(self.1.fetch_add(1, Ordering::Relaxed).into())
        }
    }
    let f = Fixture::new("ts-exact-cutoff").await?;
    let clock = TickClock(Timer.now(), Default::default());
    let next_cutoff = || {
        Deadline::at(clock.0 + Duration::from_secs(u64::from(clock.1.load(Ordering::Relaxed)) + 1))
    };
    let later = Deadline::at(clock.0 + Duration::from_secs(600));
    let mut caps = limits()?;
    caps.max_prepare_batches = NonZeroU32::MIN;
    caps.max_prepare_waiters = 0;
    let store = PgStore::new(
        f.profile.clone(),
        rss_timeseries_postgres::StoreConnections::Runtime(f.pool.clone()),
        clock.clone(),
        caps,
        CursorKey::new([23; 32]),
        later,
    )
    .await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let req = Authorized::<Batch>::verify(
        &authority(TENANT)?,
        batch("cutoff", vec![sample(&d, "cutoff", 1, 1)?])?,
    )?;
    assert_eq!(
        store.write(&req, next_cutoff()).await.err(),
        Some(Error::Deadline)
    );
    assert_eq!(store.preparation_phases(), [0, 0, 0]);
    let mut occupied = Vec::new();
    for _ in 0..f.pool.options().get_max_connections() {
        occupied.push(f.pool.acquire().await?);
    }
    let full = store.available_preparation();
    let mut holder = Box::pin(store.write(&req, later));
    pending(holder.as_mut()).await?;
    let phases = store.preparation_phases();
    assert_eq!(
        store.write(&req, later).await.err(),
        Some(Error::Overloaded)
    );
    assert_eq!(
        store.write(&req, next_cutoff()).await.err(),
        Some(Error::Deadline)
    );
    assert_eq!(store.preparation_phases(), phases);
    drop(holder);
    assert_eq!(store.available_preparation(), full);
    assert_eq!(f.count().await?, 0);
    Ok(())
}

fn single_write(d: &Definition, name: &str) -> anyhow::Result<Authorized<Batch>> {
    let b = batch(name, vec![sample(d, name, 1, 1)?])?;
    Ok(Authorized::<Batch>::verify(&authority(TENANT)?, b)?)
}

async fn saturate_and_drain(
    f: &Fixture,
    d: &Definition,
    rejected: [&Authorized<Batch>; 2],
) -> anyhow::Result<()> {
    let full = f.store.available_preparation();
    let cutoff = deadline()?;
    let holder = single_write(d, "holder")?;
    let queued = single_write(d, "queued")?;
    let mut occupied = Vec::new();
    for _ in 0..f.pool.options().get_max_connections() {
        occupied.push(f.pool.acquire().await?);
    }
    let mut active = Box::pin(f.store.write(&holder, cutoff));
    let mut waiting = Box::pin(f.store.write(&queued, cutoff));
    pending(active.as_mut()).await?;
    let phases = f.store.preparation_phases();
    pending(waiting.as_mut()).await?;
    for req in rejected {
        assert_eq!(
            f.store.write(req, cutoff).await.err(),
            Some(Error::Overloaded)
        );
    }
    assert_eq!(f.store.preparation_phases(), phases);
    assert_eq!(f.count().await?, 1);
    drop(active);
    drop(occupied);
    assert!(matches!(waiting.await?, Outcome::Accepted(_)));
    assert_eq!(f.store.available_preparation(), full);
    Ok(())
}

async fn lookup(f: &Fixture, r: &Authorized<Batch>) -> anyhow::Result<Lookup<Receipt>> {
    let q = Authorized::<ReceiptQuery>::verify(&authority(TENANT)?, receipt_query(r.request())?)?;
    Ok(f.store.receipt(&q, deadline()?).await?)
}

async fn overload_and_recovery(
    name: &str,
    profile: rss_timeseries_postgres::StorageProfile,
) -> anyhow::Result<()> {
    let mut caps = limits()?;
    caps.max_prepare_batches = NonZeroU32::MIN;
    caps.max_prepare_waiters = 1;
    let f = Fixture::with_limits(name, profile, caps).await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let original = single_write(&d, "unknown")?;
    let fresh = single_write(&d, "fresh")?;
    f.store.inject_next_fault(Fault::CommitAckLost);
    assert!(matches!(
        f.store.write(&original, deadline()?).await?,
        Outcome::Unknown
    ));
    saturate_and_drain(&f, &d, [&original, &fresh]).await?;
    verify_recovery(&f, &original, &fresh).await
}

async fn verify_recovery(
    f: &Fixture,
    original: &Authorized<Batch>,
    fresh: &Authorized<Batch>,
) -> anyhow::Result<()> {
    assert!(matches!(lookup(f, original).await?, Lookup::Found(_)));
    assert!(matches!(lookup(f, fresh).await?, Lookup::NotVisible));
    let cutoff = deadline()?;
    assert!(matches!(
        f.store.write(original, cutoff).await?,
        Outcome::Replay(_)
    ));
    assert!(matches!(
        f.store.write(fresh, cutoff).await?,
        Outcome::Accepted(_)
    ));
    assert_eq!(f.count().await?, 3);
    Ok(())
}

#[tokio::test]
async fn postgres_overload_and_recovery() -> anyhow::Result<()> {
    overload_and_recovery(
        "ts-pg-queue",
        rss_timeseries_postgres::StorageProfile::PostgreSQL,
    )
    .await
}

#[tokio::test]
async fn shared_timescale_overload_and_recovery() -> anyhow::Result<()> {
    overload_and_recovery("ts-shared-queue", crate::timescale::shared()?).await
}

#[tokio::test]
async fn dedicated_timescale_overload_and_recovery() -> anyhow::Result<()> {
    overload_and_recovery("ts-native-queue", crate::timescale::dedicated()?).await
}
