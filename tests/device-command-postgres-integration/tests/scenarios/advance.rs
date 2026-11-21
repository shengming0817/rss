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
    let runtime = f.runtime.clone();
    let store = f.store.clone();
    let deadline = if cancel {
        budget()?
    } else {
        OperationDeadline::from_remaining(Duration::from_secs(3))
    };
    let attempt = tokio::spawn(async move {
        compose::takeover(
            &runtime,
            crate::execution(s.tenant(), 1),
            store,
            s,
            old,
            next,
            deadline,
        )
        .await
    });
    // pg_blocking_pids ties this observation to this fixture's final-row lock.
    tokio::time::timeout(Duration::from_secs(8), async {
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
    })
    .await??;
    if cancel {
        attempt.abort();
        anyhow::ensure!(attempt.await.is_err_and(|error| error.is_cancelled()));
    } else {
        let result = attempt.await?;
        // The cutoff can expire before the runtime confirms rollback.
        assert!(matches!(status(result), "rolled-back" | "rollback-failed"));
    }
    blocker.rollback().await?;
    // Locking the authority for a fresh read waits for the interrupted transaction to settle.
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
    // An exact retry after ACK loss must not supersede any command a second time.
    f.runtime
        .inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    assert_eq!(status(advance(f, s, old, next).await?), "unknown");
    committed(advance(f, s, old, next).await?)?;
    for id in ["handoff-a", "handoff-b", "handoff-z"] {
        let command = f
            .recover_exact(id, s)
            .await?
            .ok_or_else(|| anyhow::anyhow!("missing command"))?;
        assert_eq!(
            (command.version(), command.status()),
            (2, Status::Superseded)
        );
        assert_eq!(f.count("outbox", &format!("dispatch.{id}")).await?, 1);
    }
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
