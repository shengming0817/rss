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
    direct_lifecycle(&mut f, &clock, s, c, id, other).await?;
    stale_at_commit(&f, &clock, c, id).await?;
    ordered_creation(&f, c).await?;
    concurrent(&f, c, id).await?;
    competing_claims(&f, c, id, other).await?;
    replay_during_claim(&f, c, id).await?;
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
        let (staged, evidence) = oneshot::channel();
        let result = f
            .runtime
            .local_tx(crate::execution(s.tenant(), 1), budget()?, move |tx| {
                Box::pin(async move {
                    let key = pending.partition().ok_or(sqlx::Error::RowNotFound)?;
                    tx.prepare_outbox_partitions(std::slice::from_ref(key))
                        .await?;
                    store.advance(tx, s, c, next).await?;
                    store.queue(tx, authored, Delivery::Outbox(pending)).await?;
                    staged.send(()).map_err(|_| sqlx::Error::PoolClosed)?;
                    if rollback {
                        return Err(sqlx::Error::PoolTimedOut.into());
                    }
                    Ok(())
                })
            })
            .await;
        evidence.await?;
        if rollback {
            assert_eq!(status(result), "rolled-back");
            assert_ordered_rollback(f, s).await?;
        } else {
            committed(result)?;
        }
    }
    let ordinals:Vec<i64>=sqlx::query_scalar("SELECT partition_seq FROM rss_transactional_messaging.outbox WHERE partition_key='ordered-direct'").fetch_all(&f.owner).await?;
    assert_eq!(ordinals, [1]);
    Ok(())
}

async fn replay_during_claim(f: &Fixture, c: Coordinate, id: ClaimId) -> anyhow::Result<()> {
    let s = device(336506)?;
    let name = "replay-during-claim";
    f.initialize(s, c).await?;
    let initial = create(f, name, s, c, i64::MAX).await?;
    let first_spec = initial.spec().clone();
    let second_spec = first_spec.clone();
    let (ready, started) = oneshot::channel();
    let (resume, release) = oneshot::channel();
    let store = f.store.clone();
    let claimant = f
        .runtime
        .local_tx(crate::execution(s.tenant(), 1), budget()?, move |tx| {
            Box::pin(async move {
                let _claim = store.claim_direct(tx, s, first_spec.id(), c, id).await?;
                notify_and_hold(tx, ready, release).await?;
                store.queue(tx, first_spec, direct()).await
            })
        });
    let replay = async {
        let blocker = started.await?;
        let store = f.store.clone();
        let other = f
            .runtime
            .local_tx(crate::execution(s.tenant(), 1), budget()?, move |tx| {
                Box::pin(async move {
                    let snapshot = store.queue(tx, second_spec, direct()).await?;
                    store.claim_direct(tx, s, snapshot.spec().id(), c, id).await
                })
            });
        let release = async {
            super::advance::wait_for_blocked(f, blocker).await?;
            resume
                .send(())
                .map_err(|_| anyhow::anyhow!("claim transaction ended"))
        };
        let (result, gate) = tokio::join!(other, release);
        gate?;
        committed(result)
    };
    let (first, second) = tokio::join!(claimant, replay);
    let command = committed(first)?;
    assert_eq!(command.version(), 2);
    assert_eq!(second?, DirectClaim::Eligible(command));
    Ok(())
}

async fn confirmed_reconnect(
    f: &Fixture,
    s: Scope,
    c: Coordinate,
    id: ClaimId,
    other: ClaimId,
) -> anyhow::Result<()> {
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
        committed(claim(f, "direct-lost", s, c, id).await?)?,
        DirectClaim::Eligible(durable.clone())
    );
    assert_eq!(
        kind(claim(f, "direct-lost", s, c, other).await?),
        Some(MessagingErrorKind::Conflict)
    );
    denied_sources(f, s, c, id, other).await?;
    let source = ReportSource::Direct(id);
    let received = committed(report(f, "direct-lost", s, c, source, DeviceEvent::Received).await?)?;
    assert_eq!(
        committed(claim(f, "direct-lost", s, c, id).await?)?,
        DirectClaim::Unavailable(received.command)
    );
    let applied = committed(
        report(
            f,
            "direct-lost",
            s,
            c,
            source,
            DeviceEvent::Reported(StateDigest::from_bytes([7; 32])),
        )
        .await?,
    )?;
    assert_eq!(applied.command.status(), Status::Applied);
    Ok(())
}

async fn rolled_back_claim(
    f: &Fixture,
    s: Scope,
    c: Coordinate,
    id: ClaimId,
) -> anyhow::Result<()> {
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
    Ok(())
}

async fn seed_direct(f: &Fixture, s: Scope, c: Coordinate) -> anyhow::Result<()> {
    for name in [
        "direct-lost",
        "direct-expiry",
        "direct-cancel",
        "direct-rollback",
    ] {
        create(f, name, s, c, 100).await?;
    }
    let ids = [
        CommandId::parse("direct-lost")?,
        CommandId::parse("direct-expiry")?,
    ];
    super::candidates::measured(f, s, &ids, [1, 1, 0, 0, 0]).await?;
    Ok(())
}

async fn stop_delivery(
    f: &Fixture,
    s: Scope,
    c: Coordinate,
    id: ClaimId,
    clock: &rss_device_command_postgres::IntegrationClock,
) -> anyhow::Result<()> {
    let _ = committed(claim(f, "direct-expiry", s, c, id).await?)?;
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
        committed(claim(f, "direct-cancel", s, c, id).await?)?,
        DirectClaim::Unavailable(cancelled.command)
    );
    clock.advance_to(100)?;
    assert!(
        matches!(committed(claim(f,"direct-expiry",s,c,id).await?)?,DirectClaim::Unavailable(cmd) if cmd.status()==Status::TimedOut && cmd.record().claim_id==Some(id))
    );
    Ok(())
}

async fn denied_sources(
    f: &Fixture,
    s: Scope,
    c: Coordinate,
    id: ClaimId,
    other: ClaimId,
) -> anyhow::Result<()> {
    for target in [
        device(336502)?,
        Scope::new(TenantId::parse(OTHER)?, s.device()),
    ] {
        f.initialize(target, c).await?;
        assert_eq!(
            kind(claim(f, "direct-lost", target, c, id).await?),
            Some(MessagingErrorKind::OwnershipLost)
        );
    }
    for origin in [ReportSource::Outbox, ReportSource::Direct(other)] {
        assert_eq!(
            kind(report(f, "direct-lost", s, c, origin, DeviceEvent::Received).await?),
            Some(MessagingErrorKind::OwnershipLost)
        );
    }
    Ok(())
}

async fn assert_ordered_rollback(f: &Fixture, s: Scope) -> anyhow::Result<()> {
    assert_eq!(
        f.load("ordered-old", s)
            .await?
            .ok_or(Error::InvalidSnapshot)?
            .status(),
        Status::Queued
    );
    assert!(f.load("ordered-new", s).await?.is_none());
    assert_eq!(f.count("outbox", "dispatch.ordered-new").await?, 0);
    Ok(())
}

async fn direct_lifecycle(
    f: &mut Fixture,
    clock: &Arc<rss_device_command_postgres::IntegrationClock>,
    s: Scope,
    c: Coordinate,
    id: ClaimId,
    other: ClaimId,
) -> anyhow::Result<()> {
    f.initialize(s, c).await?;
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_transactional_messaging.outbox")
        .fetch_one(&f.owner)
        .await?;
    seed_direct(f, s, c).await?;
    rolled_back_claim(f, s, c, id).await?;
    f.runtime
        .inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    assert_eq!(status(claim(f, "direct-lost", s, c, id).await?), "unknown");
    f.runtime.close().await;
    (f.runtime, f.store, f.outbox) = stores(
        f.config.clone(),
        rss_device_command_postgres::CommandClock::Controlled(clock.clone()),
    )
    .await?;
    confirmed_reconnect(f, s, c, id, other).await?;
    stop_delivery(f, s, c, id, clock).await?;
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_transactional_messaging.outbox")
        .fetch_one(&f.owner)
        .await?;
    assert_eq!(before, after);
    Ok(())
}

// A callback may keep running after the claim or change its state before commit.
// Neither candidate can authorize the response at the later handoff.
async fn stale_at_commit(
    f: &Fixture,
    clock: &Arc<rss_device_command_postgres::IntegrationClock>,
    c: Coordinate,
    id: ClaimId,
) -> anyhow::Result<()> {
    let s = device(336507)?;
    f.initialize(s, c).await?;
    for cancel in [false, true] {
        let name = if cancel {
            "cancel-before-commit"
        } else {
            "expire-before-commit"
        };
        let deadline = clock.now() + 10;
        let command = create(f, name, s, c, deadline).await?;
        let cmd = command.spec().id().clone();
        let store = f.store.clone();
        let frozen = clock.clone();
        let candidate = committed(
            f.runtime
                .local_tx(crate::execution(s.tenant(), 1), budget()?, move |tx| {
                    Box::pin(async move {
                        let candidate = store.claim_direct(tx, s, &cmd, c, id).await?;
                        if cancel {
                            let _cancelled = store.cancel(tx, s, &cmd, c).await?;
                        } else {
                            frozen
                                .advance_to(deadline)
                                .map_err(|_| sqlx::Error::RowNotFound)?;
                        }
                        Ok(candidate)
                    })
                })
                .await,
        )?;
        let latest = f.load(name, s).await?.ok_or(Error::InvalidSnapshot)?;
        assert!(matches!(candidate, DirectClaim::Eligible(_)));
        assert_eq!(candidate.dispatch_id_at(&latest, clock.now()), None);
    }
    Ok(())
}

// Transactions get opposite input orders. Each composition acquires the complete set
// in tenant-local command-ID order, including the race before a command row exists.
async fn ordered_creation(f: &Fixture, c: Coordinate) -> anyhow::Result<()> {
    let s = device(336508)?;
    f.initialize(s, c).await?;
    let a = spec("sorted-a", s, c)?;
    let b = spec("sorted-b", s, c)?;
    let (ready, started) = oneshot::channel();
    let (finish, release) = oneshot::channel();
    let mut reversed = [b.clone(), a.clone()];
    reversed.sort_by(|a, b| a.id().cmp(b.id()));
    let store = f.store.clone();
    let first = f
        .runtime
        .local_tx(crate::execution(s.tenant(), 1), budget()?, move |tx| {
            Box::pin(async move {
                let first = store.queue(tx, a, direct()).await?;
                // Only A is held. If the peer takes B first, it will still own B
                // when this callback resumes, exposing the opposite lock order.
                notify_and_hold(tx, ready, release).await?;
                let second = store.queue(tx, b, direct()).await?;
                Ok(vec![first, second])
            })
        });
    let second = async {
        let blocker = started.await?;
        let store = f.store.clone();
        let replay = f
            .runtime
            .local_tx(crate::execution(s.tenant(), 1), budget()?, move |tx| {
                Box::pin(async move {
                    let mut candidates = Vec::new();
                    for spec in reversed {
                        candidates.push(store.queue(tx, spec, direct()).await?);
                    }
                    Ok(candidates)
                })
            });
        let release = async {
            super::advance::wait_for_blocked(f, blocker).await?;
            finish
                .send(())
                .map_err(|_| anyhow::anyhow!("creation ended early"))
        };
        let (result, gate) = tokio::join!(replay, release);
        gate?;
        committed(result)
    };
    let (first, second) = tokio::join!(first, second);
    assert_eq!(committed(first)?, second?);
    for name in ["sorted-a", "sorted-b"] {
        assert_eq!(f.count("commands", name).await?, 1);
    }
    Ok(())
}
