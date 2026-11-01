use super::*;

pub(crate) async fn recovery(f: &Fixture) -> anyhow::Result<()> {
    let (f, clock) = f.controlled().await?;
    let s = Scope::new(
        scope(TENANT)?.tenant(),
        DeviceId::parse("550e8400-e29b-41d4-a716-446655440041")?,
    );
    let coordinate = Coordinate::new(1, 1)?;
    f.initialize(s, coordinate).await?;
    let request = CommandSpec::new(
        s,
        CommandId::parse("exact-expiry")?,
        coordinate,
        StateDigest::from_bytes([7; 32]),
        100,
    );
    let msg = message("exact-expiry", s.tenant())?;
    let store = f.store.clone();
    let expiring = committed(
        f.runtime
            .local_tx(s.tenant(), budget()?, move |tx| {
                Box::pin(async move { store.queue(tx, request, msg).await })
            })
            .await,
    )?;
    let queued = f.queue("exact-published", s, coordinate).await?;
    assert_eq!(f.recover_exact("exact-published", s).await?, Some(queued));
    f.publish().await?;
    clock.advance_to(100)?;
    let published = f
        .recover_exact("exact-published", s)
        .await?
        .ok_or_else(|| anyhow::anyhow!("missing exact publication"))?;
    assert_eq!(published.status(), Status::Published);
    // Returning a filtered page after recovering the entire scope must fail this assertion.
    assert_eq!(f.load("exact-expiry", s).await?, Some(expiring));
    let expired = f
        .recover_exact("exact-expiry", s)
        .await?
        .ok_or_else(|| anyhow::anyhow!("missing exact expiry"))?;
    assert_eq!(expired.status(), Status::TimedOut);
    assert_eq!(expired.record().terminal_at, Some(100));
    assert_eq!(f.recover_exact("exact-expiry", s).await?, Some(expired));
    assert_eq!(f.recover_exact("exact-missing", s).await?, None);
    assert_eq!(f.load("exact-published", s).await?, Some(published));
    isolation(&f, s, coordinate).await?;
    settlement(&f, s, coordinate).await?;
    f.runtime.close().await;
    Ok(())
}

async fn isolation(f: &Fixture, s: Scope, coordinate: Coordinate) -> anyhow::Result<()> {
    let other_device = Scope::new(
        s.tenant(),
        DeviceId::parse("550e8400-e29b-41d4-a716-446655440042")?,
    );
    f.initialize(other_device, coordinate).await?;
    assert!(
        f.recover_exact("exact-published", other_device)
            .await
            .is_err()
    );
    let foreign_scope = Scope::new(TenantId::parse(OTHER)?, s.device());
    f.initialize(foreign_scope, coordinate).await?;
    assert_eq!(
        f.recover_exact("exact-published", foreign_scope).await?,
        None
    );
    let id = CommandId::parse("exact-published")?;
    let store = f.store.clone();
    let attempt = f
        .runtime
        .local_tx(s.tenant(), budget()?, move |tx| {
            Box::pin(async move { store.recover_exact(tx, foreign_scope, &id).await })
        })
        .await;
    assert_eq!(
        attempt
            .fold(|_| None, Some, Some, Some, Some, Some)
            .map(|e| e.kind()),
        Some(rss_transactional_messaging::error::MessagingErrorKind::OwnershipLost)
    );
    let absent_scope = Scope::new(
        s.tenant(),
        DeviceId::parse("550e8400-e29b-41d4-a716-446655440043")?,
    );
    assert!(
        f.recover_exact("exact-missing", absent_scope)
            .await
            .is_err()
    );
    let (foreign, _) = f.controlled().await?;
    let store = foreign.store.clone();
    let id = CommandId::parse("exact-published")?;
    assert!(
        committed(
            f.runtime
                .local_tx(s.tenant(), budget()?, move |tx| {
                    Box::pin(async move { store.recover_exact(tx, s, &id).await })
                })
                .await
        )
        .is_err()
    );
    foreign.runtime.close().await;
    Ok(())
}

async fn settlement(f: &Fixture, s: Scope, coordinate: Coordinate) -> anyhow::Result<()> {
    let original = f.queue("exact-rollback", s, coordinate).await?;
    f.publish().await?;
    let id = CommandId::parse("exact-rollback")?;
    let marker = spec("exact-rollback-marker", s, coordinate)?;
    let msg = message("exact-rollback-marker", s.tenant())?;
    let store = f.store.clone();
    let attempt = f
        .runtime
        .local_tx(s.tenant(), budget()?, move |tx| {
            Box::pin(async move {
                let recovered = store.recover_exact(tx, s, &id).await?;
                assert_eq!(recovered.map(|c| c.status()), Some(Status::Published));
                store.queue(tx, marker, msg).await?;
                Err::<(), PgError>(sqlx::Error::PoolTimedOut.into())
            })
        })
        .await;
    assert_eq!(status(attempt), "rolled-back");
    assert_eq!(f.load("exact-rollback", s).await?, Some(original));
    assert_eq!(f.count("commands", "exact-rollback-marker").await?, 0);
    assert_eq!(
        f.count("outbox", "dispatch.exact-rollback-marker").await?,
        0
    );
    // Authority advancement still supersedes every active command, not just an exact candidate.
    let store = f.store.clone();
    let next = Coordinate::new(2, 2)?;
    committed(
        f.runtime
            .local_tx(s.tenant(), budget()?, move |tx| {
                Box::pin(async move { store.advance(tx, s, coordinate, next).await })
            })
            .await,
    )?;
    let expected = f.load("exact-rollback", s).await?;
    assert_eq!(
        expected.as_ref().map(Command::status),
        Some(Status::Superseded)
    );
    assert_eq!(f.recover_exact("exact-rollback", s).await?, expected);
    assert_eq!(
        f.load("exact-published", s).await?.map(|c| c.status()),
        Some(Status::Superseded)
    );
    unknown_settlement(f, s, next).await?;
    Ok(())
}

async fn unknown_settlement(f: &Fixture, s: Scope, coordinate: Coordinate) -> anyhow::Result<()> {
    f.queue("exact-unknown", s, coordinate).await?;
    f.publish().await?;
    f.runtime
        .inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    let store = f.store.clone();
    let id = CommandId::parse("exact-unknown")?;
    let attempt = f
        .runtime
        .local_tx(s.tenant(), budget()?, move |tx| {
            Box::pin(async move { store.recover_exact(tx, s, &id).await })
        })
        .await;
    assert_eq!(status(attempt), "unknown");
    f.runtime.close().await;
    let (runtime, store, _) = stores(
        f.config.clone(),
        rss_device_command_postgres::CommandClock::Postgres,
    )
    .await?;
    let selected = store.clone();
    let id = CommandId::parse("exact-unknown")?;
    let durable = committed(
        runtime
            .local_tx(s.tenant(), budget()?, move |tx| {
                Box::pin(async move { selected.load(tx, s, &id).await })
            })
            .await,
    )?;
    assert_eq!(
        durable.as_ref().map(Command::status),
        Some(Status::Published)
    );
    let id = CommandId::parse("exact-unknown")?;
    let repeated = committed(
        runtime
            .local_tx(s.tenant(), budget()?, move |tx| {
                Box::pin(async move { store.recover_exact(tx, s, &id).await })
            })
            .await,
    )?;
    assert_eq!(repeated, durable);
    assert_eq!(f.count("outbox", "dispatch.exact-unknown").await?, 1);
    runtime.close().await;
    Ok(())
}
