//! The final page is locked after earlier pages have been staged in the original transaction.
use super::*;
use anyhow::Context as _;
use rss_transactional_messaging::error::MessagingErrorKind;

const COMMANDS: [&str; 4] = ["handoff-a", "handoff-b", "handoff-y", "handoff-z"];

#[derive(Clone, Copy)]
enum Interruption {
    Cancel,
    Deadline,
    StaleVersion,
}

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

// pg_blocking_pids ties the observed wait to the fixture's final-row lock.
pub(super) async fn wait_for_blocked(f: &Fixture, pid: i32) -> anyhow::Result<()> {
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
    .await?
}

async fn interrupt_last_page(
    f: &Fixture,
    s: Scope,
    old: Coordinate,
    next: Coordinate,
    interruption: Interruption,
) -> anyhow::Result<()> {
    let (blocker, pid) = lock_last(f, s).await?;
    let deadline = match interruption {
        Interruption::Deadline => OperationDeadline::from_remaining(Duration::from_secs(3)),
        _ => budget()?,
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
    tokio::select! {
        observed = wait_for_blocked(f, pid) => observed?,
        result = &mut attempt => anyhow::bail!("advance settled before the final-row lock: {}", status(result)),
    }
    match interruption {
        Interruption::Cancel => drop(attempt),
        Interruption::Deadline => {
            // The outer cutoff can quarantine a transaction before settlement is confirmed.
            assert!(matches!(
                status(attempt.await),
                "rolled-back" | "rollback-failed" | "unknown"
            ));
        }
        Interruption::StaleVersion => {
            publish_last(blocker, s).await?;
            let fenced = attempt.await.fold(
                |_| None,
                |_| None,
                |_| None,
                |_| None,
                |_| None,
                |e| Some(e.kind()),
            );
            assert_eq!(fenced, Some(MessagingErrorKind::OwnershipLost));
            return assert_rolled_back(f, s, old, (2, Status::Published)).await;
        }
    }
    blocker.rollback().await?;
    assert_rolled_back(f, s, old, (1, Status::Queued)).await
}

async fn lock_last(
    f: &Fixture,
    s: Scope,
) -> anyhow::Result<(sqlx::Transaction<'_, sqlx::Postgres>, i32)> {
    let mut blocker = f.owner.begin().await?;
    let pid: i32 = sqlx::query_scalar(
        "SELECT pg_backend_pid() FROM rss_device_command.commands
        WHERE tenant_id=$1::uuid AND device_id=$2::uuid AND command_id='handoff-z' FOR UPDATE",
    )
    .bind(s.tenant().to_string())
    .bind(s.device().as_uuid().to_string())
    .fetch_one(&mut *blocker)
    .await?;
    Ok((blocker, pid))
}

async fn publish_last(
    mut blocker: sqlx::Transaction<'_, sqlx::Postgres>,
    s: Scope,
) -> anyhow::Result<()> {
    let published = sqlx::query(
        "UPDATE rss_device_command.commands SET status='published',published_at=queued_at,version=version+1
         WHERE tenant_id=$1::uuid AND device_id=$2::uuid AND command_id='handoff-z' AND version=1",
    )
    .bind(s.tenant().to_string())
    .bind(s.device().as_uuid().to_string())
    .execute(&mut *blocker)
    .await?;
    assert_eq!(published.rows_affected(), 1);
    blocker.commit().await?;
    Ok(())
}

async fn assert_rolled_back(
    f: &Fixture,
    s: Scope,
    old: Coordinate,
    last: (i64, Status),
) -> anyhow::Result<()> {
    // A plain MVCC read can still see the old version before rollback. Wait for
    // the original authority lock and verify that its update did not commit.
    let mut check = f.owner.begin().await?;
    sqlx::query("SET LOCAL lock_timeout='5s'")
        .execute(&mut *check)
        .await?;
    let coordinate: (i64, i64) = sqlx::query_as(
        "SELECT generation,authority_epoch FROM rss_device_command.authorities
         WHERE tenant_id=$1::uuid AND device_id=$2::uuid FOR UPDATE",
    )
    .bind(s.tenant().to_string())
    .bind(s.device().as_uuid().to_string())
    .fetch_one(&mut *check)
    .await
    .context("checking whether takeover released the authority lock within five seconds")?;
    check.commit().await?;
    assert_eq!(coordinate, (old.generation(), old.epoch()));
    for id in COMMANDS {
        let command = f
            .load(id, s)
            .await?
            .ok_or_else(|| anyhow::anyhow!("missing command"))?;
        let expected = if id == "handoff-z" {
            last
        } else {
            (1, Status::Queued)
        };
        assert_eq!((command.version(), command.status()), expected, "{id}");
    }
    Ok(())
}

pub(crate) async fn atomic_handoff(f: &Fixture) -> anyhow::Result<()> {
    partial_recovery(f, ["cas-page-a", "cas-page-z"], false).await?;
    partial_recovery(f, ["cas-exact-a", "cas-exact-z"], true).await?;
    let s = Scope::new(
        scope(TENANT)?.tenant(),
        DeviceId::parse("550e8400-e29b-41d4-a716-446655440066")?,
    );
    let old = Coordinate::new(1, 1)?;
    let next = Coordinate::new(2, 2)?;
    f.initialize(s, old).await?;
    for id in COMMANDS {
        f.queue(id, s, old).await?;
    }
    for interruption in [
        Interruption::Cancel,
        Interruption::Deadline,
        Interruption::StaleVersion,
    ] {
        interrupt_last_page(f, s, old, next, interruption).await?;
    }
    isolated_handoff(f, s, old, next).await?;
    queue_race(f, s, next).await
}

async fn partial_recovery(f: &Fixture, names: [&str; 2], exact: bool) -> anyhow::Result<()> {
    let scope = Scope::new(
        scope(TENANT)?.tenant(),
        DeviceId::parse("550e8400-e29b-41d4-a716-446655440068")?,
    );
    let current = Coordinate::new(1, 1)?;
    f.initialize(scope, current).await?;
    let first = f.queue(names[0], scope, current).await?;
    f.queue(names[1], scope, current).await?;
    // Only the competing version commits. The earlier successful save in this page rolls back.
    sqlx::query("UPDATE rss_transactional_messaging.outbox SET status='published' WHERE tenant_id=$1::uuid AND message_id=ANY($2::text[])")
        .bind(scope.tenant().to_string()).bind(names.map(|id| format!("dispatch.{id}"))).execute(&f.owner).await?;
    let mut competing = f.owner.begin().await?;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *competing)
        .await?;
    sqlx::query("UPDATE rss_device_command.commands SET status='published',published_at=queued_at,version=version+1 WHERE tenant_id=$1::uuid AND command_id=$2 AND version=1")
        .bind(scope.tenant().to_string()).bind(names[1]).execute(&mut *competing).await?;
    let recover = recover_conflicted_page(f, scope, current, names, exact);
    let release = async {
        wait_for_blocked(f, pid).await?;
        competing.commit().await?;
        anyhow::Ok(())
    };
    tokio::try_join!(recover, release)?;
    assert_cas_rollback(f, scope, names, first).await
}

async fn assert_cas_rollback(
    f: &Fixture,
    scope: Scope,
    names: [&str; 2],
    first: Command,
) -> anyhow::Result<()> {
    assert_eq!(f.load(names[0], scope).await?, Some(first));
    assert_eq!(
        f.load(names[1], scope)
            .await?
            .map(|c| (c.version(), c.status())),
        Some((2, Status::Published))
    );
    assert_eq!(f.count("commands", "cas-marker").await?, 0);
    assert_eq!(f.count("outbox", "dispatch.cas-marker").await?, 0);
    Ok(())
}

async fn recover_conflicted_page(
    f: &Fixture,
    scope: Scope,
    current: Coordinate,
    names: [&str; 2],
    exact: bool,
) -> anyhow::Result<()> {
    let store = f.store.clone();
    let ids = [CommandId::parse(names[0])?, CommandId::parse(names[1])?];
    let page = ExactCommandIds::new(&ids)?;
    let marker = spec("cas-marker", scope, current)?;
    let dispatch = message("cas-marker", scope.tenant())?;
    let result = f
        .runtime
        .local_tx_with_context(
            crate::execution(scope.tenant(), 1),
            budget()?,
            page,
            move |page, tx| {
                Box::pin(async move {
                    store.queue(tx, marker, dispatch).await?;
                    if exact {
                        store.recover_exact(tx, scope, *page).await?;
                    } else {
                        let _page = store
                            .recover(tx, scope, BatchLimit::default(), None)
                            .await?;
                    }
                    Ok(())
                })
            },
        )
        .await;
    assert_eq!(
        result.fold(
            |_| None,
            |_| None,
            |_| None,
            |_| None,
            |_| None,
            |e| Some(e.kind())
        ),
        Some(MessagingErrorKind::OwnershipLost)
    );
    anyhow::Ok(())
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
    for id in COMMANDS {
        let command = f
            .load(id, s)
            .await?
            .ok_or_else(|| anyhow::anyhow!("missing command"))?;
        let expected_version = if id == "handoff-z" { 3 } else { 2 };
        assert_eq!(
            (command.version(), command.status()),
            (expected_version, Status::Superseded),
            "{id}"
        );
        assert_eq!(f.recover_exact(&[id], s).await?, [Some(command)]);
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
