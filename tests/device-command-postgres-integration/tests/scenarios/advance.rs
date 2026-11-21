//! The final page is locked after earlier pages have been staged in the original transaction.
use super::*;

async fn advance(
    f: &Fixture,
    s: Scope,
    old: Coordinate,
    next: Coordinate,
) -> anyhow::Result<LocalTxAttempt<(), PgError>> {
    Ok(compose::takeover(
        &f.runtime,
        crate::execution(s.tenant(), 1),
        f.store.clone(),
        s,
        old,
        next,
        budget()?,
    )
    .await)
}

async fn interrupt_last_page(
    f: &Fixture,
    s: Scope,
    old: Coordinate,
    next: Coordinate,
    cancel: bool,
) -> anyhow::Result<()> {
    let mut blocker = f.owner.begin().await?;
    let pid: i32 = sqlx::query_scalar(
        "SELECT pg_backend_pid() FROM rss_device_command.commands
        WHERE tenant_id=$1::uuid AND device_id=$2::uuid AND command_id='handoff-z' FOR UPDATE",
    )
    .bind(s.tenant().to_string())
    .bind(s.device().as_uuid().to_string())
    .fetch_one(&mut *blocker)
    .await?;
    let deadline = if cancel {
        budget()?
    } else {
        OperationDeadline::from_remaining(Duration::from_secs(3))
    };
    let mut attempt = Box::pin(compose::takeover(
        &f.runtime,
        crate::execution(s.tenant(), 1),
        f.store.clone(),
        s,
        old,
        next,
        deadline,
    ));
    // pg_blocking_pids ties this observation to this fixture's final-row lock.
    let blocked = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT FROM pg_stat_activity
                WHERE usename='device_runtime' AND $1=ANY(pg_blocking_pids(pid)))",
            )
            .bind(pid)
            .fetch_one(&f.owner)
            .await?;
            if waiting {
                return anyhow::Ok(());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    });
    tokio::select! {
        observed = blocked => observed??,
        result = &mut attempt => anyhow::bail!("advance settled before the final-row lock: {}", status(result)),
    }
    if cancel {
        drop(attempt);
    } else {
        let result = attempt.await;
        // The outer cutoff may quarantine a transaction before settlement is confirmed.
        assert!(matches!(
            status(result),
            "rolled-back" | "rollback-failed" | "unknown"
        ));
    }
    blocker.rollback().await?;
    assert_rolled_back(f, s, old).await
}

async fn assert_rolled_back(f: &Fixture, s: Scope, old: Coordinate) -> anyhow::Result<()> {
    // A plain MVCC read can still see the old version before rollback. Wait for
    // the original authority lock and verify that its update did not commit.
    let coordinate: (i64, i64) = sqlx::query_as(
        "SELECT generation,authority_epoch FROM rss_device_command.authorities
         WHERE tenant_id=$1::uuid AND device_id=$2::uuid FOR UPDATE",
    )
    .bind(s.tenant().to_string())
    .bind(s.device().as_uuid().to_string())
    .fetch_one(&f.owner)
    .await?;
    assert_eq!(coordinate, (old.generation(), old.epoch()));
    for id in ["handoff-a", "handoff-b", "handoff-z"] {
        let command = f
            .load(id, s)
            .await?
            .ok_or_else(|| anyhow::anyhow!("missing command"))?;
        assert_eq!((command.version(), command.status()), (1, Status::Queued));
    }
    Ok(())
}

pub(crate) async fn atomic_handoff(f: &Fixture) -> anyhow::Result<()> {
    let s = Scope::new(
        scope(TENANT)?.tenant(),
        DeviceId::parse("550e8400-e29b-41d4-a716-446655440066")?,
    );
    let old = Coordinate::new(1, 1)?;
    let next = Coordinate::new(2, 2)?;
    f.initialize(s, old).await?;
    for id in ["handoff-a", "handoff-b", "handoff-z"] {
        f.queue(id, s, old).await?;
    }
    for cancel in [true, false] {
        interrupt_last_page(f, s, old, next, cancel).await?;
    }
    isolated_handoff(f, s, old, next).await?;
    queue_race(f, s, next).await
}

async fn isolated_handoff(
    f: &Fixture,
    s: Scope,
    old: Coordinate,
    next: Coordinate,
) -> anyhow::Result<()> {
    let other_device = Scope::new(
        s.tenant(),
        DeviceId::parse("550e8400-e29b-41d4-a716-446655440067")?,
    );
    let other_tenant = Scope::new(TenantId::parse(OTHER)?, s.device());
    for (scope, name) in [
        (other_device, "other-device-pending"),
        (other_tenant, "other-tenant-pending"),
    ] {
        f.initialize(scope, old).await?;
        f.queue(name, scope, old).await?;
    }
    replay_after_unknown(f, s, old, next).await?;
    for (scope, name) in [
        (other_device, "other-device-pending"),
        (other_tenant, "other-tenant-pending"),
    ] {
        assert_eq!(
            f.load(name, scope).await?.map(|c| c.status()),
            Some(Status::Queued)
        );
    }
    assert!(f.queue("handoff-stale", s, old).await.is_err());
    Ok(())
}

async fn replay_after_unknown(
    f: &Fixture,
    s: Scope,
    old: Coordinate,
    next: Coordinate,
) -> anyhow::Result<()> {
    // An exact retry after ACK loss must not supersede any command a second time.
    f.runtime
        .inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    assert_eq!(status(advance(f, s, old, next).await?), "unknown");
    committed(advance(f, s, old, next).await?)?;
    for id in ["handoff-a", "handoff-b", "handoff-z"] {
        let command = f
            .load(id, s)
            .await?
            .ok_or_else(|| anyhow::anyhow!("missing command"))?;
        assert_eq!(
            (command.version(), command.status()),
            (2, Status::Superseded)
        );
        assert_eq!(f.recover_exact(id, s).await?, Some(command));
        assert_eq!(f.count("outbox", &format!("dispatch.{id}")).await?, 1);
    }
    Ok(())
}

async fn queue_race(f: &Fixture, s: Scope, next: Coordinate) -> anyhow::Result<()> {
    // Queue/advance race under the same authority lock: stale queue either commits first
    // and is superseded, or loses the coordinate and leaves no dispatch.
    let newer = Coordinate::new(2, 3)?;
    let (queued, updated) =
        tokio::join!(f.queue("handoff-race", s, next), advance(f, s, next, newer));
    committed(updated?)?;
    let snapshot = f.load("handoff-race", s).await?;
    if queued.is_ok() {
        assert!(snapshot.is_some_and(|c| c.version() == 2 && c.status() == Status::Superseded));
    } else {
        assert!(snapshot.is_none());
        assert_eq!(f.count("outbox", "dispatch.handoff-race").await?, 0);
    }
    Ok(())
}
