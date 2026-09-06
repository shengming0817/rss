use super::*;
pub(crate) async fn immutable_facts(f: &Fixture) -> anyhow::Result<()> {
    let s = scope(TENANT)?;
    let c = Coordinate::new(2, 3)?;
    let original = f.queue("immutable", s, c).await?;
    let mut cases = Vec::new();
    for (coordinate, digest, deadline) in [
        (c, [8; 32], i64::MAX),
        (c, [7; 32], i64::MAX - 1),
        (Coordinate::new(3, 4)?, [7; 32], i64::MAX),
    ] {
        cases.push((
            CommandSpec::new(
                s,
                CommandId::parse("immutable")?,
                coordinate,
                StateDigest::from_bytes(digest),
                deadline,
            ),
            message("immutable", s.tenant())?,
        ));
    }
    cases.push((
        original.spec().clone(),
        message("different-dispatch", s.tenant())?,
    ));
    let m = message("immutable", s.tenant())?;
    cases.push((
        original.spec().clone(),
        PendingMessage::new(MessageEnvelope::new(
            m.envelope().id().clone(),
            m.envelope().metadata().clone(),
            vec![9],
        )),
    ));
    for (request, msg) in cases {
        let store = f.store.clone();
        let attempt = f
            .runtime
            .local_tx(s.tenant(), budget()?, move |tx| {
                Box::pin(async move { store.queue(tx, request, msg).await })
            })
            .await;
        let rejected = attempt.fold(
            |_| false,
            |_| false,
            |e| e.kind() == rss_transactional_messaging::error::MessagingErrorKind::Conflict,
            |_| false,
            |_| false,
            |_| false,
        );
        assert!(rejected);
        assert_eq!(f.load("immutable", s).await?, Some(original.clone()));
    }
    assert_eq!(f.count("outbox", "dispatch.immutable").await?, 1);
    assert_eq!(f.count("outbox", "dispatch.different-dispatch").await?, 0);
    concurrent_conflict(f, s, c).await
}
async fn concurrent_conflict(f: &Fixture, s: Scope, c: Coordinate) -> anyhow::Result<()> {
    let left = CommandSpec::new(
        s,
        CommandId::parse("racing-facts")?,
        c,
        StateDigest::from_bytes([8; 32]),
        i64::MAX,
    );
    let right = CommandSpec::new(
        s,
        CommandId::parse("racing-facts")?,
        c,
        StateDigest::from_bytes([9; 32]),
        i64::MAX,
    );
    let a = f.store.clone();
    let b = f.store.clone();
    let ma = message("racing-facts", s.tenant())?;
    let mb = message("racing-facts", s.tenant())?;
    let (a, b) = tokio::join!(
        f.runtime
            .local_tx(s.tenant(), budget()?, move |tx| Box::pin(async move {
                a.queue(tx, left, ma).await
            })),
        f.runtime
            .local_tx(s.tenant(), budget()?, move |tx| Box::pin(async move {
                b.queue(tx, right, mb).await
            }))
    );
    assert_ne!(committed(a).is_ok(), committed(b).is_ok());
    assert_eq!(f.count("commands", "racing-facts").await?, 1);
    assert_eq!(f.count("outbox", "dispatch.racing-facts").await?, 1);
    Ok(())
}
pub(crate) async fn authority_rollback(f: &Fixture) -> anyhow::Result<()> {
    let s = scope(TENANT)?;
    let c = Coordinate::new(2, 3)?;
    let a = f.queue("authority-rollback-a", s, c).await?;
    let b = f.queue("authority-rollback-b", s, c).await?;
    let store = f.store.clone();
    let next = Coordinate::new(2, 4)?;
    let attempt = f
        .runtime
        .local_tx(s.tenant(), budget()?, move |tx| {
            Box::pin(async move {
                store.advance(tx, s, c, next).await?;
                Err::<(), PgError>(sqlx::Error::PoolTimedOut.into())
            })
        })
        .await;
    assert_eq!(status(attempt), "rolled-back");
    assert_eq!(f.load("authority-rollback-a", s).await?, Some(a));
    assert_eq!(f.load("authority-rollback-b", s).await?, Some(b));
    f.queue("authority-remains", s, c).await?;
    Ok(())
}
pub(crate) async fn late_controls(f: &Fixture) -> anyhow::Result<()> {
    let s = Scope::new(
        scope(TENANT)?.tenant(),
        DeviceId::parse("550e8400-e29b-41d4-a716-446655440002")?,
    );
    let c = Coordinate::new(1, 1)?;
    f.initialize(s, c).await?;
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000000)::bigint")
            .fetch_one(&f.owner)
            .await?;
    for id in ["late-cancel", "late-supersede", "late-reject"] {
        let request = CommandSpec::new(
            s,
            CommandId::parse(id)?,
            c,
            StateDigest::from_bytes([7; 32]),
            now + 1_000_000,
        );
        let msg = message(id, s.tenant())?;
        let store = f.store.clone();
        committed(
            f.runtime
                .local_tx(s.tenant(), budget()?, move |tx| {
                    Box::pin(async move { store.queue(tx, request, msg).await })
                })
                .await,
        )?;
    }
    f.publish().await?;
    let _page = f.recover(s).await?;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let store = f.store.clone();
    let id = CommandId::parse("late-cancel")?;
    let result = committed(
        f.runtime
            .local_tx(s.tenant(), budget()?, move |tx| {
                Box::pin(async move { store.cancel(tx, s, &id, c).await })
            })
            .await,
    )?;
    assert_eq!(result.command.status(), Status::Cancelled);
    assert_eq!(
        f.report("late-reject", s, c, DeviceEvent::Rejected)
            .await?
            .command
            .status(),
        Status::Rejected
    );
    let store = f.store.clone();
    let next = Coordinate::new(1, 2)?;
    committed(
        f.runtime
            .local_tx(s.tenant(), budget()?, move |tx| {
                Box::pin(async move { store.advance(tx, s, c, next).await })
            })
            .await,
    )?;
    assert_eq!(
        f.load("late-supersede", s).await?.map(|c| c.status()),
        Some(Status::Superseded)
    );
    Ok(())
}
pub(crate) async fn delayed_publication_read(f: &Fixture) -> anyhow::Result<()> {
    let s = Scope::new(
        scope(TENANT)?.tenant(),
        DeviceId::parse("550e8400-e29b-41d4-a716-446655440003")?,
    );
    let c = Coordinate::new(1, 1)?;
    f.initialize(s, c).await?;
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000000)::bigint")
            .fetch_one(&f.owner)
            .await?;
    let expires = now + 1_000_000;
    let request = CommandSpec::new(
        s,
        CommandId::parse("slow-confirm")?,
        c,
        StateDigest::from_bytes([7; 32]),
        expires,
    );
    let msg = message("slow-confirm", s.tenant())?;
    let store = f.store.clone();
    committed(
        f.runtime
            .local_tx(s.tenant(), budget()?, move |tx| {
                Box::pin(async move { store.queue(tx, request, msg).await })
            })
            .await,
    )?;
    f.publish().await?;
    let mut lock = f.owner.begin().await?;
    sqlx::query("LOCK TABLE rss_transactional_messaging.outbox IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *lock)
        .await?;
    let release = async {
        let ready=tokio::time::timeout(Duration::from_secs(3),async {
            loop {
                let blocked:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'SELECT domain,fingerprint,status FROM rss_transactional_messaging.outbox%')").fetch_one(&f.owner).await?;
                if blocked { return Ok::<(),anyhow::Error>(()); }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await;
        let seen: i64 = sqlx::query_scalar(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000000)::bigint",
        )
        .fetch_one(&f.owner)
        .await?;
        tokio::time::sleep(Duration::from_millis(1100)).await;
        lock.rollback().await?;
        ready??;
        assert!(
            seen < expires,
            "the publication read must start before deadline"
        );
        Ok::<(), anyhow::Error>(())
    };
    let (page, released) = tokio::join!(f.recover(s), release);
    released?;
    assert_eq!(
        page?.commands.first().map(Command::status),
        Some(Status::TimedOut)
    );
    Ok(())
}
pub(crate) async fn catalog_drift(f: &Fixture) -> anyhow::Result<()> {
    for (change, restore) in [
        (
            "ALTER POLICY tenant_scope ON rss_device_command.commands USING(true)",
            "ALTER POLICY tenant_scope ON rss_device_command.commands USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)",
        ),
        (
            "CREATE POLICY unwanted ON rss_device_command.commands USING(true)",
            "DROP POLICY unwanted ON rss_device_command.commands",
        ),
        (
            "GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_device_command TO PUBLIC",
            "REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_device_command FROM PUBLIC",
        ),
        (
            "ALTER FUNCTION rss_device_command.lock_authority(uuid,uuid) SET search_path=public",
            "ALTER FUNCTION rss_device_command.lock_authority(uuid,uuid) SET search_path=pg_catalog,rss_device_command",
        ),
        (
            "ALTER FUNCTION rss_device_command.lock_authority(uuid,uuid) SECURITY INVOKER",
            "ALTER FUNCTION rss_device_command.lock_authority(uuid,uuid) SECURITY DEFINER",
        ),
    ] {
        sqlx::raw_sql(change).execute(&f.owner).await?;
        let admitted = stores(f.config.clone()).await;
        sqlx::raw_sql(restore).execute(&f.owner).await?;
        assert!(admitted.is_err());
    }
    Ok(())
}
pub(crate) async fn closed_catalog(f: &Fixture) -> anyhow::Result<()> {
    for (change, restore) in [
        (
            "CREATE ROLE device_extra LOGIN; GRANT USAGE ON SCHEMA rss_device_command TO device_extra; GRANT SELECT ON rss_device_command.commands TO device_extra; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_device_command TO device_extra",
            "DROP OWNED BY device_extra; DROP ROLE device_extra",
        ),
        (
            "SET ROLE device_owner; CREATE FUNCTION rss_device_command.unexpected() RETURNS integer LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,rss_device_command AS 'SELECT 1'; RESET ROLE",
            "DROP FUNCTION rss_device_command.unexpected()",
        ),
    ] {
        let mut session = f.owner.acquire().await?;
        sqlx::raw_sql(change).execute(&mut *session).await?;
        let admitted = stores(f.config.clone()).await;
        if let Ok((runtime, _, _)) = &admitted {
            runtime.close().await;
        }
        sqlx::raw_sql(restore).execute(&mut *session).await?;
        assert!(
            admitted.is_err(),
            "unexpected ACL principal or function was admitted"
        );
    }
    Ok(())
}
