//! Product-selected candidates, including terminal commands from a previous authority.
use super::*;
use rss_transactional_messaging_postgres::PgTransaction;

// Count client statements on the very same backend, excluding this observer.
async fn calls(tx: &mut PgTransaction<'_>) -> Result<([i64; 5], i64), PgError> {
    let (authority, commands, publication, save, clock, total): (i64, i64, i64, i64, i64, i64) =
        tx.with_connection(|c| Box::pin(async move {
            sqlx::query_as("SELECT
                coalesce(sum(n) FILTER (WHERE statement LIKE '%rss_device_command.lock_authority%'),0)::bigint,
                coalesce(sum(n) FILTER (WHERE statement LIKE '%rss_device_command.commands%'),0)::bigint,
                coalesce(sum(n) FILTER (WHERE statement LIKE '%rss_transactional_messaging.outbox%'),0)::bigint,
                coalesce(sum(n) FILTER (WHERE statement LIKE '%rss_device_command.save_page%'),0)::bigint,
                coalesce(sum(n) FILTER (WHERE statement LIKE '%clock_timestamp()%'),0)::bigint, coalesce(sum(n),0)::bigint
                FROM (SELECT statement, generic_plans + custom_plans AS n FROM pg_prepared_statements
                      WHERE statement NOT LIKE '%pg_prepared_statements%') plans")
                .fetch_one(c).await
        })).await?;
    Ok(([authority, commands, publication, save, clock], total))
}

async fn measured(
    f: &Fixture,
    s: Scope,
    ids: &[CommandId],
    expected: [i64; 5],
) -> anyhow::Result<Vec<Option<Command>>> {
    let store = f.store.clone();
    let (commands, delta, total) = committed(
        f.runtime
            .local_tx_with_context(
                crate::execution(s.tenant(), 1),
                budget()?,
                ExactCommandIds::new(ids)?,
                move |page, tx| {
                    Box::pin(async move {
                        let (before, total_before) = calls(tx).await?;
                        let commands = store.recover_exact(tx, s, *page).await?;
                        let (after, total_after) = calls(tx).await?;
                        Ok((
                            commands,
                            std::array::from_fn::<_, 5, _>(|i| after[i] - before[i]),
                            total_after - total_before,
                        ))
                    })
                },
            )
            .await,
    )?;
    eprintln!(
        "exact candidates={} SQL [authority, commands, publication, save, clock]={delta:?}",
        ids.len()
    );
    assert_eq!(delta, expected);
    assert_eq!(
        total,
        delta.iter().sum::<i64>(),
        "unexpected extra client SQL"
    );
    Ok(commands)
}

pub(crate) async fn owner_pages(database_clock: &Fixture) -> anyhow::Result<()> {
    let (f, clock) = database_clock.controlled().await?;
    let s = Scope::new(
        scope(TENANT)?.tenant(),
        DeviceId::parse("550e8400-e29b-41d4-a716-446655440083")?,
    );
    let current = Coordinate::new(1, 2)?;
    let mut expected = superseded_candidates(&f, s, current, clock.now()).await?;
    append_changing_candidates(&f, s, current, &mut expected).await?;
    let later = f.queue("owner-65", s, current).await?;
    let unselected = f.queue("another-owner", s, current).await?;
    f.publish().await?;
    expected.push(f.queue("owner-pending", s, current).await?);
    clock.advance_to(100)?;
    first_page(&f, s, expected, unselected).await?;
    later_page(&f, s, later).await?;

    database_clock_calls(database_clock, s).await?;
    f.runtime.close().await;
    Ok(())
}

async fn first_page(
    f: &Fixture,
    s: Scope,
    mut expected: Vec<Command>,
    unselected: Command,
) -> anyhow::Result<()> {
    expected.reverse();
    let ids: Vec<_> = expected.iter().map(|c| c.spec().id().clone()).collect();
    let result = measured(f, s, &ids, [1, 1, 1, 1, 0]).await?;
    // Read back every changed member after commit, outside the SQL measurement window.
    for command in expected
        .iter()
        .filter(|c| matches!(c.status(), Status::Published | Status::TimedOut))
    {
        let durable = f.load(command.spec().id().as_str(), s).await?;
        assert_eq!(durable.as_ref(), Some(command));
    }
    assert_eq!(result, expected.into_iter().map(Some).collect::<Vec<_>>());
    assert_eq!(f.load("another-owner", s).await?, Some(unselected));
    Ok(())
}

async fn superseded_candidates(
    f: &Fixture,
    s: Scope,
    current: Coordinate,
    now: i64,
) -> anyhow::Result<Vec<Command>> {
    let old = Coordinate::new(1, 1)?;
    f.initialize(s, old).await?;
    let mut expected = Vec::new();
    for i in 0..60 {
        let mut command = f.queue(&format!("owner-{i}"), s, old).await?;
        assert_eq!(
            command.transition(Event::Supersede, current, now)?,
            Outcome::Advanced
        );
        expected.push(command);
    }
    let store = f.store.clone();
    committed(
        f.runtime
            .local_tx(crate::execution(s.tenant(), 1), budget()?, move |tx| {
                Box::pin(async move { store.advance(tx, s, old, current).await })
            })
            .await,
    )?;
    Ok(expected)
}

async fn append_changing_candidates(
    f: &Fixture,
    s: Scope,
    current: Coordinate,
    expected: &mut Vec<Command>,
) -> anyhow::Result<()> {
    for name in ["owner-publish-a", "owner-publish-b"] {
        let mut command = f.queue(name, s, current).await?;
        assert_eq!(
            command.transition(Event::Published, current, 100)?,
            Outcome::Advanced
        );
        expected.push(command);
    }
    super::regressions::queue_expiring(f, s, current, "owner-expire", 100).await?;
    let mut expiring = f
        .load("owner-expire", s)
        .await?
        .ok_or(Error::InvalidSnapshot)?;
    assert_eq!(
        expiring.transition(Event::Expire, current, 100)?,
        Outcome::Advanced
    );
    expected.push(expiring);
    Ok(())
}

async fn database_clock_calls(database_clock: &Fixture, s: Scope) -> anyhow::Result<()> {
    // The PostgreSQL clock must not be sampled for all-terminal or all-missing requests.
    let terminal = [CommandId::parse("owner-0")?, CommandId::parse("owner-1")?];
    let missing = [
        CommandId::parse("missing-a")?,
        CommandId::parse("missing-b")?,
    ];
    let terminal_page = measured(database_clock, s, &terminal, [1, 1, 0, 0, 0]).await?;
    assert!(terminal_page.iter().all(|slot| {
        slot.as_ref()
            .is_some_and(|c| c.status() == Status::Superseded)
    }));
    assert_eq!(
        measured(database_clock, s, &missing, [1, 1, 0, 0, 0]).await?,
        [None, None]
    );
    let active = [
        CommandId::parse("owner-65")?,
        CommandId::parse("another-owner")?,
    ];
    let changed = measured(database_clock, s, &active, [1, 1, 1, 1, 2]).await?;
    assert!(changed.iter().all(|slot| {
        slot.as_ref()
            .is_some_and(|c| c.status() == Status::Published)
    }));
    Ok(())
}

async fn later_page(f: &Fixture, s: Scope, original: Command) -> anyhow::Result<()> {
    assert_eq!(f.load("owner-65", s).await?.as_ref(), Some(&original));
    let ids = [
        original.spec().id().clone(),
        CommandId::parse("orphan-candidate")?,
    ];
    let store = f.store.clone();
    let result = f.runtime.local_tx_with_context(crate::execution(s.tenant(), 1), budget()?, ExactCommandIds::new(&ids)?, move |page, tx| {
        Box::pin(async move {
            let recovered = store.recover_exact(tx, s, *page).await?;
            assert!(matches!(recovered.as_slice(), [Some(c), None] if c.status() == Status::Published));
            // This product requires every selected operation to own a matching command.
            recovered.into_iter().collect::<Option<Vec<_>>>().ok_or_else(|| sqlx::Error::RowNotFound.into())
        })
    }).await;
    assert_eq!(status(result), "rolled-back");
    assert_eq!(f.load("owner-65", s).await?, Some(original));
    Ok(())
}
