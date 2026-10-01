use super::*;
use rss_device_command_postgres::{CommandClock, IntegrationClock};

pub(crate) async fn controlled_time(f: &Fixture) -> anyhow::Result<()> {
    let s = Scope::new(
        scope(TENANT)?.tenant(),
        DeviceId::parse("550e8400-e29b-41d4-a716-446655440009")?,
    );
    let c = Coordinate::new(1, 1)?;
    f.initialize(s, c).await?;
    let clock = Arc::new(IntegrationClock::new(10)?);
    let (runtime, store, _) =
        stores(f.config.clone(), CommandClock::Controlled(clock.clone())).await?;
    before_deadline(&runtime, &store, &clock, s, c).await?;
    let (restarted, recovered, _) =
        stores(f.config.clone(), CommandClock::Controlled(clock.clone())).await?;
    clock.advance_to(100)?;
    let expired = recover(&restarted, recovered.clone(), s).await?;
    assert_eq!(expired.commands[0].status(), Status::TimedOut);
    assert_eq!(expired.commands[0].record().terminal_at, Some(100));
    assert_eq!(
        f.load("clock-boundary", s).await?,
        Some(expired.commands[0].clone())
    );
    late_queue_and_ownership(f, &restarted, &recovered, &clock, s, c).await?;
    postgres_time(f).await?;
    runtime.close().await;
    restarted.close().await;
    Ok(())
}

async fn late_queue_and_ownership(
    f: &Fixture,
    restarted: &PgRuntime,
    recovered: &Arc<PgStore<()>>,
    clock: &IntegrationClock,
    s: Scope,
    c: Coordinate,
) -> anyhow::Result<()> {
    clock.advance_to(101)?;
    let selected = recovered.clone();
    let msg = message("clock-late", s.tenant())?;
    let request = CommandSpec::new(
        s,
        CommandId::parse("clock-late")?,
        c,
        StateDigest::from_bytes([7; 32]),
        100,
    );
    assert!(
        committed(
            restarted
                .local_tx(s.tenant(), budget()?, move |tx| {
                    Box::pin(async move { selected.queue(tx, request, msg).await })
                })
                .await
        )
        .is_err()
    );
    assert_eq!(f.count("commands", "clock-late").await?, 0);
    // A controlled clock does not admit a store from another runtime.
    let foreign = recovered.clone();
    assert!(
        committed(
            f.runtime
                .local_tx(s.tenant(), budget()?, move |tx| {
                    Box::pin(async move { foreign.now(tx).await })
                })
                .await
        )
        .is_err()
    );
    Ok(())
}
async fn postgres_time(f: &Fixture) -> anyhow::Result<()> {
    let s = scope(TENANT)?;
    let before: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000000)::bigint")
            .fetch_one(&f.owner)
            .await?;
    let selected = f.store.clone();
    let actual = committed(
        f.runtime
            .local_tx(s.tenant(), budget()?, move |tx| {
                Box::pin(async move { selected.now(tx).await })
            })
            .await,
    )?;
    let after: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000000)::bigint")
            .fetch_one(&f.owner)
            .await?;
    assert!((before..=after).contains(&actual));
    Ok(())
}

async fn recover(
    runtime: &PgRuntime,
    store: Arc<PgStore<()>>,
    scope: Scope,
) -> anyhow::Result<RecoveryPage> {
    let limit = BatchLimit::new(10)?;
    committed(
        runtime
            .local_tx(scope.tenant(), budget()?, move |tx| {
                Box::pin(async move { store.recover(tx, scope, limit, None).await })
            })
            .await,
    )
}

async fn queue(
    runtime: &PgRuntime,
    store: Arc<PgStore<()>>,
    s: Scope,
    c: Coordinate,
) -> anyhow::Result<Command> {
    let request = CommandSpec::new(
        s,
        CommandId::parse("clock-boundary")?,
        c,
        StateDigest::from_bytes([7; 32]),
        100,
    );
    let queued = store.clone();
    let msg = message("clock-boundary", s.tenant())?;
    committed(
        runtime
            .local_tx(s.tenant(), budget()?, move |tx| {
                Box::pin(async move { queued.queue(tx, request, msg).await })
            })
            .await,
    )
}

async fn before_deadline(
    runtime: &PgRuntime,
    store: &Arc<PgStore<()>>,
    clock: &IntegrationClock,
    s: Scope,
    c: Coordinate,
) -> anyhow::Result<()> {
    let command = queue(runtime, store.clone(), s, c).await?;
    assert_eq!(command.record().queued_at, 10);
    clock.advance_to(99)?;
    let before = recover(runtime, store.clone(), s).await?;
    assert_eq!(before.commands[0].status(), Status::Queued);
    Ok(())
}
