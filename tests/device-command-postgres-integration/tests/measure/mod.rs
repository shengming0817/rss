//! Fixed-load, opt-in PG comparison. Use the same workload on both revisions.
use super::*;
use tokio::sync::oneshot;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "explicit isolated WAL and lock measurements"]
async fn authority_cost() -> anyhow::Result<()> {
    let network = testkit::bridge_network("authority-cost").await?;
    let pg = testkit::postgres_tls(
        testkit::NetworkAttachment {
            network: network.name(),
            dns_name: "authority-cost",
        },
        testkit::PgTlsServerIdentity::MatchingHost,
    )
    .await?;
    let f = setup_with_page_size(&pg, BatchLimit::default()).await?;
    let c = Coordinate::new(1, 1)?;
    let next = Coordinate::new(2, 2)?;
    for count in [0, 1, 64, 65, 256, 1024] {
        for contended in [false, true] {
            let k = count * 2 + usize::from(contended);
            let s = Scope::new(
                scope(TENANT)?.tenant(),
                DeviceId::parse(&format!("5c633c55-3dd4-4bcc-bd61-{k:012}"))?,
            );
            f.initialize(s, c).await?;
            for i in 0..count {
                f.queue(&format!("measure-{k}-{i}"), s, c).await?;
            }
            if contended {
                let wait_us = wait_cost(&f, s, c, next).await?;
                eprintln!("MEASURE active={count} same_device_wait_us={wait_us}");
            } else {
                let lsn: String = sqlx::query_scalar("SELECT pg_current_wal_insert_lsn()::text")
                    .fetch_one(&f.owner)
                    .await?;
                let start = Timer::new().now();
                committed(
                    compose::takeover(
                        &f.runtime,
                        crate::execution(s.tenant(), 1),
                        f.store.clone(),
                        s,
                        c,
                        next,
                        budget()?,
                    )
                    .await,
                )?;
                let elapsed = Timer::new()
                    .now()
                    .saturating_duration_since(start)
                    .as_micros();
                let wal: i64 = sqlx::query_scalar(
                    "SELECT pg_wal_lsn_diff(pg_current_wal_insert_lsn(),$1::pg_lsn)::bigint",
                )
                .bind(lsn)
                .fetch_one(&f.owner)
                .await?;
                eprintln!("MEASURE active={count} commit_us={elapsed} wal_bytes={wal}");
            }
            let superseded:i64=sqlx::query_scalar("SELECT count(*) FROM rss_device_command.commands WHERE device_id=$1::uuid AND status='superseded'").bind(s.device().as_uuid().to_string()).fetch_one(&f.owner).await?;
            assert_eq!(superseded, i64::try_from(count)?);
        }
    }
    ordinary(&f, c).await?;
    f.runtime.close().await;
    f.owner.close().await;
    Ok(())
}
async fn wait_edge(f: &Fixture, waiter: i32, blocker: i32) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let blocked: bool = sqlx::query_scalar("SELECT $2=ANY(pg_blocking_pids($1))")
                .bind(waiter)
                .bind(blocker)
                .fetch_one(&f.owner)
                .await?;
            if blocked {
                return anyhow::Ok(());
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await?
}
async fn session(
    tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
    ready: oneshot::Sender<i32>,
) -> Result<(), PgError> {
    let pid = tx
        .with_connection(|c| {
            Box::pin(async move {
                sqlx::query_scalar("SELECT pg_backend_pid()")
                    .fetch_one(c)
                    .await
            })
        })
        .await?;
    ready.send(pid).map_err(|_| sqlx::Error::PoolClosed)?;
    Ok(())
}
// Queue the exclusive handoff first and a real same-device check second. Start timing
// only when the test gate is released, excluding the deliberate lock-queue setup.
async fn wait_cost(f: &Fixture, s: Scope, c: Coordinate, next: Coordinate) -> anyhow::Result<u128> {
    let mut gate = f.owner.begin().await?;
    let gate_pid:i32=sqlx::query_scalar("SELECT pg_backend_pid() FROM rss_device_command.authorities WHERE device_id=$1::uuid FOR UPDATE").bind(s.device().as_uuid().to_string()).fetch_one(&mut *gate).await?;
    let (a_tx, a_rx) = oneshot::channel();
    let (b_tx, b_rx) = oneshot::channel();
    let store = f.store.clone();
    let a = f
        .runtime
        .local_tx(crate::execution(s.tenant(), 1), budget()?, move |tx| {
            Box::pin(async move {
                session(tx, a_tx).await?;
                store.advance(tx, s, c, next).await
            })
        });
    let probe = async {
        let a_pid = a_rx.await?;
        wait_edge(f, a_pid, gate_pid).await?;
        let store = f.store.clone();
        let b = f
            .runtime
            .local_tx(crate::execution(s.tenant(), 1), budget()?, move |tx| {
                Box::pin(async move {
                    session(tx, b_tx).await?;
                    store
                        .recover_exact(
                            tx,
                            s,
                            ExactCommandIds::new(&[]).map_err(|_| sqlx::Error::RowNotFound)?,
                        )
                        .await
                })
            });
        let release = async {
            let b_pid = b_rx.await?;
            wait_edge(f, b_pid, a_pid).await?;
            let start = Timer::new().now();
            gate.commit().await?;
            anyhow::Ok(start)
        };
        let (start, b) = tokio::join!(release, b);
        let interval = Timer::new()
            .now()
            .saturating_duration_since(start?)
            .as_micros();
        committed(b)?;
        anyhow::Ok(interval)
    };
    let (result, elapsed) = tokio::join!(a, probe);
    committed(result)?;
    elapsed
}
async fn ordinary(f: &Fixture, c: Coordinate) -> anyhow::Result<()> {
    let s = scope(TENANT)?;
    f.initialize(s, c).await?;
    let seed = f.queue("ordinary-held", s, c).await?;
    let (ready, started) = oneshot::channel();
    let (done, release) = oneshot::channel();
    let store = f.store.clone();
    let holder = f
        .runtime
        .local_tx(crate::execution(s.tenant(), 1), budget()?, move |tx| {
            Box::pin(async move {
                let _cancel = store.cancel(tx, s, seed.spec().id(), c).await?;
                ready.send(()).map_err(|_| sqlx::Error::PoolClosed)?;
                release.await.map_err(|_| sqlx::Error::PoolClosed)?;
                Ok(())
            })
        });
    let peer = async {
        started.await?;
        let start = Timer::new().now();
        let b = f.queue("ordinary-peer", s, c);
        tokio::pin!(b);
        let early = tokio::time::timeout(Duration::from_millis(150), &mut b).await;
        let independent = early.is_ok();
        done.send(())
            .map_err(|_| anyhow::anyhow!("holder ended early"))?;
        match early {
            Ok(result) => result?,
            Err(_) => b.await?,
        };
        eprintln!(
            "MEASURE independent_before_release={independent} peer_us={} hold_limit_ms=150",
            Timer::new()
                .now()
                .saturating_duration_since(start)
                .as_micros()
        );
        anyhow::Ok(())
    };
    let (a, b) = tokio::join!(holder, peer);
    committed(a)?;
    b
}
