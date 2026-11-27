//! Exercise issuance and transaction ordering through the public provider on independent sessions.
use super::*;
use rss_transactional_messaging::error::MessagingErrorKind;
use rss_transactional_messaging_postgres::PgTransaction;
use tokio::sync::oneshot;

fn direct() -> Delivery {
    Delivery::Direct {
        content_digest: ContentDigest::from_bytes([3; 32]),
    }
}
fn device(n: u32) -> anyhow::Result<Scope> {
    Ok(Scope::new(
        scope(TENANT)?.tenant(),
        DeviceId::parse(&format!("550e8400-e29b-41d4-a716-{n:012}"))?,
    ))
}
async fn create(
    f: &Fixture,
    name: &str,
    s: Scope,
    c: Coordinate,
    deadline: i64,
) -> anyhow::Result<Command> {
    let spec = CommandSpec::new(
        s,
        CommandId::parse(name)?,
        c,
        StateDigest::from_bytes([7; 32]),
        deadline,
    );
    let store = f.store.clone();
    committed(
        f.runtime
            .local_tx(crate::execution(s.tenant(), 1), budget()?, move |tx| {
                Box::pin(async move { store.queue(tx, spec, direct()).await })
            })
            .await,
    )
}
async fn claim(
    f: &Fixture,
    name: &str,
    s: Scope,
    c: Coordinate,
    id: ClaimId,
) -> anyhow::Result<LocalTxAttempt<DirectClaim, PgError>> {
    let cmd = CommandId::parse(name)?;
    let store = f.store.clone();
    Ok(f.runtime
        .local_tx(crate::execution(s.tenant(), 1), budget()?, move |tx| {
            Box::pin(async move { store.claim_direct(tx, s, &cmd, c, id).await })
        })
        .await)
}
fn kind<T>(attempt: LocalTxAttempt<T, PgError>) -> Option<MessagingErrorKind> {
    attempt
        .fold(|_| None, Some, Some, Some, Some, Some)
        .map(|e| e.kind())
}
async fn report(
    f: &Fixture,
    name: &str,
    s: Scope,
    c: Coordinate,
    source: ReportSource,
    event: DeviceEvent,
) -> anyhow::Result<LocalTxAttempt<Transition, PgError>> {
    let input = DeviceReport {
        scope: s,
        coordinate: c,
        command_id: CommandId::parse(name)?,
        source,
        event,
    };
    let store = f.store.clone();
    Ok(f.runtime
        .local_tx(crate::execution(s.tenant(), 1), budget()?, move |tx| {
            Box::pin(async move { store.report(tx, &input).await })
        })
        .await)
}
pub(crate) async fn run(original: &Fixture) -> anyhow::Result<()> {
    let (mut f, clock) = original.controlled().await?;
    let s = device(336501)?;
    let c = Coordinate::new(1, 1)?;
    let id = ClaimId::parse("5da81944-34a9-4be3-a838-1ceafef62bc7")?;
    let other = ClaimId::parse("5da81944-34a9-4be3-a838-1ceafef62bc8")?;
    f.initialize(s, c).await?;
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_transactional_messaging.outbox")
        .fetch_one(&f.owner)
        .await?;
    for name in [
        "direct-lost",
        "direct-expiry",
        "direct-cancel",
        "direct-rollback",
    ] {
        create(&f, name, s, c, 100).await?;
    }
    let ids = [
        CommandId::parse("direct-lost")?,
        CommandId::parse("direct-expiry")?,
    ];
    super::candidates::measured(&f, s, &ids, [1, 1, 0, 0, 0]).await?;
    let pending = f.load("direct-rollback", s).await?;
    let store = f.store.clone();
    let cmd = CommandId::parse("direct-rollback")?;
    let rolled = f
        .runtime
        .local_tx(crate::execution(s.tenant(), 1), budget()?, move |tx| {
            Box::pin(async move {
                assert!(matches!(
                    store.claim_direct(tx, s, &cmd, c, id).await?,
                    DirectClaim::Eligible(_)
                ));
                Err::<(), PgError>(sqlx::Error::PoolTimedOut.into())
            })
        })
        .await;
    assert_eq!(status(rolled), "rolled-back");
    assert_eq!(pending, f.load("direct-rollback", s).await?);
    f.runtime
        .inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    assert_eq!(status(claim(&f, "direct-lost", s, c, id).await?), "unknown");
    f.runtime.close().await;
    (f.runtime, f.store, f.outbox) = stores(
        f.config.clone(),
        rss_device_command_postgres::CommandClock::Controlled(clock.clone()),
    )
    .await?;
    let durable = f
        .load("direct-lost", s)
        .await?
        .ok_or(Error::InvalidSnapshot)?;
    assert_eq!(
        (
            durable.status(),
            durable.version(),
            durable.record().claim_id
        ),
        (Status::Claimed, 2, Some(id))
    );
    assert_eq!(
        committed(claim(&f, "direct-lost", s, c, id).await?)?,
        DirectClaim::Eligible(durable.clone())
    );
    assert_eq!(
        kind(claim(&f, "direct-lost", s, c, other).await?),
        Some(MessagingErrorKind::Conflict)
    );
    for target in [
        device(336502)?,
        Scope::new(TenantId::parse(OTHER)?, s.device()),
    ] {
        f.initialize(target, c).await?;
        assert_eq!(
            kind(claim(&f, "direct-lost", target, c, id).await?),
            Some(MessagingErrorKind::OwnershipLost)
        );
    }
    for origin in [ReportSource::Outbox, ReportSource::Direct(other)] {
        assert_eq!(
            kind(report(&f, "direct-lost", s, c, origin, DeviceEvent::Received).await?),
            Some(MessagingErrorKind::OwnershipLost)
        );
    }
    let source = ReportSource::Direct(id);
    let received =
        committed(report(&f, "direct-lost", s, c, source, DeviceEvent::Received).await?)?;
    assert_eq!(
        committed(claim(&f, "direct-lost", s, c, id).await?)?,
        DirectClaim::Unavailable(received.command)
    );
    let applied = committed(
        report(
            &f,
            "direct-lost",
            s,
            c,
            source,
            DeviceEvent::Reported(StateDigest::from_bytes([7; 32])),
        )
        .await?,
    )?;
    assert_eq!(applied.command.status(), Status::Applied);
    let _ = committed(claim(&f, "direct-expiry", s, c, id).await?)?;
    let cmd = CommandId::parse("direct-cancel")?;
    let store = f.store.clone();
    let cancelled = committed(
        f.runtime
            .local_tx(crate::execution(s.tenant(), 1), budget()?, move |tx| {
                Box::pin(async move { store.cancel(tx, s, &cmd, c).await })
            })
            .await,
    )?;
    assert_eq!(
        committed(claim(&f, "direct-cancel", s, c, id).await?)?,
        DirectClaim::Unavailable(cancelled.command)
    );
    clock.advance_to(100)?;
    assert!(
        matches!(committed(claim(&f,"direct-expiry",s,c,id).await?)?,DirectClaim::Unavailable(cmd) if cmd.status()==Status::TimedOut && cmd.record().claim_id==Some(id))
    );
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_transactional_messaging.outbox")
        .fetch_one(&f.owner)
        .await?;
    assert_eq!(before, after);
    concurrent(&f, c, id).await?;
    competing_claims(&f, c, id, other).await?;
    ordered(&f, c).await?;
    f.runtime.close().await;
    Ok(())
}
async fn pid(tx: &mut PgTransaction<'_>) -> Result<i32, PgError> {
    tx.with_connection(|c| {
        Box::pin(async move {
            sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(c)
                .await
        })
    })
    .await
}
async fn notify_and_hold(
    tx: &mut PgTransaction<'_>,
    ready: oneshot::Sender<i32>,
    release: oneshot::Receiver<()>,
) -> Result<(), PgError> {
    ready
        .send(pid(tx).await?)
        .map_err(|_| sqlx::Error::PoolClosed)?;
    release.await.map_err(|_| sqlx::Error::PoolClosed)?;
    Ok(())
}
async fn concurrent(f: &Fixture, c: Coordinate, id: ClaimId) -> anyhow::Result<()> {
    let s = device(336503)?;
    let next = Coordinate::new(2, 2)?;
    f.initialize(s, c).await?;
    let (a_ready, a_pid) = oneshot::channel();
    let (a_done, a_release) = oneshot::channel();
    let (b_ready, b_pid) = oneshot::channel();
    let (b_done, b_release) = oneshot::channel();
    let store = f.store.clone();
    let spec_a = spec("held-direct", s, c)?;
    let a = f
        .runtime
        .local_tx(crate::execution(s.tenant(), 1), budget()?, move |tx| {
            Box::pin(async move {
                let cmd = store.queue(tx, spec_a, direct()).await?;
                let _claim = store.claim_direct(tx, s, cmd.spec().id(), c, id).await?;
                notify_and_hold(tx, a_ready, a_release).await
            })
        });
    let b = async {
        let blocker = a_pid.await?;
        let store = f.store.clone();
        let spec_b = spec("held-outbox", s, c)?;
        let message = message("held-outbox", s.tenant())?;
        committed(
            f.runtime
                .local_tx(crate::execution(s.tenant(), 1), budget()?, move |tx| {
                    Box::pin(async move {
                        store.queue(tx, spec_b, Delivery::Outbox(message)).await?;
                        b_ready
                            .send((blocker, pid(tx).await?))
                            .map_err(|_| sqlx::Error::PoolClosed)?;
                        b_release.await.map_err(|_| sqlx::Error::PoolClosed)?;
                        Ok(())
                    })
                })
                .await,
        )
    };
    // Keep both independent commands staged. The handoff must wait for each transaction.
    let controller = async {
        let (blocker_a, blocker_b) = b_pid.await?;
        let takeover = compose::takeover(
            &f.runtime,
            crate::execution(s.tenant(), 1),
            f.store.clone(),
            s,
            c,
            next,
            budget()?,
        );
        tokio::pin!(takeover);
        let release = async {
            // PG may initially be waiting for either member of the MultiXact.
            tokio::select! {
                r=super::advance::wait_for_blocked(f,blocker_a)=>r?,
                r=super::advance::wait_for_blocked(f,blocker_b)=>r?,
            }
            a_done
                .send(())
                .map_err(|_| anyhow::anyhow!("first transaction ended"))?;
            super::advance::wait_for_blocked(f, blocker_b).await?;
            b_done
                .send(())
                .map_err(|_| anyhow::anyhow!("second transaction ended"))?;
            anyhow::Ok(())
        };
        let (result, unblocked) = tokio::join!(takeover, release);
        unblocked?;
        committed(result)
    };
    let (a, b, ctrl) = tokio::join!(a, b, controller);
    committed(a)?;
    b?;
    ctrl?;
    for name in ["held-direct", "held-outbox"] {
        assert_eq!(
            f.load(name, s).await?.map(|c| c.status()),
            Some(Status::Superseded)
        );
    }
    assert_eq!(
        kind(claim(f, "held-direct", s, c, id).await?),
        Some(MessagingErrorKind::OwnershipLost)
    );
    Ok(())
}
async fn competing_claims(
    f: &Fixture,
    c: Coordinate,
    id: ClaimId,
    other: ClaimId,
) -> anyhow::Result<()> {
    let s = device(336504)?;
    f.initialize(s, c).await?;
    create(f, "competing-direct", s, c, i64::MAX).await?;
    let cmd = CommandId::parse("competing-direct")?;
    let (ready, started) = oneshot::channel();
    let (done, release) = oneshot::channel();
    let store = f.store.clone();
    let first = f
        .runtime
        .local_tx(crate::execution(s.tenant(), 1), budget()?, move |tx| {
            Box::pin(async move {
                let result = store.claim_direct(tx, s, &cmd, c, id).await?;
                notify_and_hold(tx, ready, release).await?;
                Ok(result)
            })
        });
    let second = async {
        let pid = started.await?;
        let contender = claim(f, "competing-direct", s, c, other);
        let release = async {
            super::advance::wait_for_blocked(f, pid).await?;
            done.send(())
                .map_err(|_| anyhow::anyhow!("first claim ended"))
        };
        let (result, release) = tokio::join!(contender, release);
        release?;
        anyhow::Ok(kind(result?))
    };
    let (a, b) = tokio::join!(first, second);
    assert!(matches!(committed(a)?, DirectClaim::Eligible(_)));
    assert_eq!(b?, Some(MessagingErrorKind::Conflict));
    assert_eq!(
        f.load("competing-direct", s)
            .await?
            .ok_or(Error::InvalidSnapshot)?
            .version(),
        2
    );
    let attempted = spec("competing-direct", s, c)?;
    let different = message("competing-direct", s.tenant())?;
    let store = f.store.clone();
    let collision = f
        .runtime
        .local_tx(crate::execution(s.tenant(), 1), budget()?, move |tx| {
            Box::pin(async move {
                store
                    .queue(tx, attempted, Delivery::Outbox(different))
                    .await
            })
        })
        .await;
    assert_eq!(kind(collision), Some(MessagingErrorKind::Conflict));
    Ok(())
}
async fn ordered(f: &Fixture, c: Coordinate) -> anyhow::Result<()> {
    let s = device(336505)?;
    f.initialize(s, c).await?;
    create(f, "ordered-old", s, c, i64::MAX).await?;
    let next = Coordinate::new(2, 2)?;
    for rollback in [true, false, false] {
        let store = f.store.clone();
        let pending = message_with_partition(
            "ordered-new",
            s.tenant(),
            "device-tests",
            Some(PartitionKey::parse("ordered-direct")?),
        )?;
        let authored = spec("ordered-new", s, next)?;
        let result = f
            .runtime
            .local_tx(crate::execution(s.tenant(), 1), budget()?, move |tx| {
                Box::pin(async move {
                    let key = pending.partition().ok_or(sqlx::Error::RowNotFound)?;
                    tx.prepare_outbox_partitions(std::slice::from_ref(key))
                        .await?;
                    store.advance(tx, s, c, next).await?;
                    store.queue(tx, authored, Delivery::Outbox(pending)).await?;
                    if rollback {
                        return Err(sqlx::Error::PoolTimedOut.into());
                    }
                    Ok(())
                })
            })
            .await;
        if rollback {
            assert_eq!(status(result), "rolled-back");
            assert_eq!(
                f.load("ordered-old", s)
                    .await?
                    .ok_or(Error::InvalidSnapshot)?
                    .status(),
                Status::Queued
            );
            assert!(f.load("ordered-new", s).await?.is_none());
            assert_eq!(f.count("outbox", "dispatch.ordered-new").await?, 0);
        } else {
            committed(result)?;
        }
    }
    let ordinals:Vec<i64>=sqlx::query_scalar("SELECT partition_seq FROM rss_transactional_messaging.outbox WHERE partition_key='ordered-direct'").fetch_all(&f.owner).await?;
    assert_eq!(ordinals, [1]);
    Ok(())
}
