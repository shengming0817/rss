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
    let request = CommandSpec::new(
        s,
        CommandId::parse("clock-boundary")?,
        c,
        StateDigest::from_bytes([7; 32]),
        100,
    );
    let queued = store.clone();
    let msg = message("clock-boundary", s.tenant())?;
    let command = committed(
        runtime
            .local_tx(s.tenant(), budget()?, move |tx| {
                Box::pin(async move { queued.queue(tx, request, msg).await })
            })
            .await,
    )?;
    assert_eq!(command.record().queued_at, 10);
    clock.advance_to(99)?;
    let recovered = store.clone();
    let before = committed(
        runtime
            .local_tx(s.tenant(), budget()?, move |tx| {
                Box::pin(async move {
                    recovered
                        .recover(
                            tx,
                            s,
                            BatchLimit::new(10).map_err(|_| {
                                PgError::from(sqlx::Error::Protocol("invalid batch".into()))
                            })?,
                            None,
                        )
                        .await
                })
            })
            .await,
    )?;
    assert_eq!(before.commands[0].status(), Status::Queued);
    let (restarted, recovered, _) =
        stores(f.config.clone(), CommandClock::Controlled(clock.clone())).await?;
    clock.advance_to(100)?;
    let selected = recovered.clone();
    let expired = committed(
        restarted
            .local_tx(s.tenant(), budget()?, move |tx| {
                Box::pin(async move {
                    selected
                        .recover(
                            tx,
                            s,
                            BatchLimit::new(10).map_err(|_| {
                                PgError::from(sqlx::Error::Protocol("invalid batch".into()))
                            })?,
                            None,
                        )
                        .await
                })
            })
            .await,
    )?;
    assert_eq!(expired.commands[0].status(), Status::TimedOut);
    assert_eq!(expired.commands[0].record().terminal_at, Some(100));
    assert_eq!(
        f.load("clock-boundary", s).await?,
        Some(expired.commands[0].clone())
    );
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
    runtime.close().await;
    restarted.close().await;
    Ok(())
}
