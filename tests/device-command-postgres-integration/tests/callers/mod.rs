//! Multiple declared logins retain separate runtime ownership on the same component schema.
use super::*;
use rss_device_command_postgres::CommandClock;
use rss_transactional_messaging_postgres::PgTransactionFault;
mod security;

const PAIR: &[&str] = &["device_runtime", "device_peer"];
const THREE: &[&str] = &["device_runtime", "device_peer", "Device Third"];

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn explicit_callers_keep_closed_admission_and_atomic_transactions() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(180), async {
        let network = testkit::bridge_network("command-callers").await?;
        let postgres = testkit::postgres_tls(
            testkit::NetworkAttachment {
                network: network.name(),
                dns_name: "command-callers",
            },
            testkit::PgTlsServerIdentity::MatchingHost,
        )
        .await?;
        let original = setup(&postgres).await?;
        original.runtime.close().await;
        sqlx::raw_sql("CREATE ROLE device_peer LOGIN PASSWORD 'fixture-only' NOBYPASSRLS")
            .execute(&original.owner)
            .await?;
        grant_runtime(&original.owner, "device_peer").await?;
        let first = paired(original.config.clone(), &original.owner, PAIR).await?;
        let second = paired(config(&postgres, "device_peer")?, &original.owner, PAIR).await?;
        for fixture in [&first, &second] {
            assert!(
                admit(
                    fixture,
                    CallerRoles::new(&["device_peer", "device_runtime"])?
                )
                .await?
            );
        }
        security::declarations(&first).await?;
        security::catalog(&first).await?;
        atomic(&first, "first-caller").await?;
        atomic(&second, "second-caller").await?;
        foreign(&first, &second).await?;
        foreign(&second, &first).await?;
        // A third exact catalog name extends the declaration without adding an API/profile.
        sqlx::raw_sql("CREATE ROLE \"Device Third\" LOGIN PASSWORD 'fixture-only' NOBYPASSRLS")
            .execute(&original.owner)
            .await?;
        grant_runtime(&original.owner, "Device Third").await?;
        assert!(!admit(&first, CallerRoles::new(PAIR)?).await?);
        for fixture in [&first, &second] {
            assert!(admit(fixture, CallerRoles::new(THREE)?).await?);
        }
        let third = paired(config(&postgres, "Device Third")?, &original.owner, THREE).await?;
        atomic(&third, "third-caller").await?;
        for fixture in [&first, &second, &third] {
            fixture.runtime.close().await;
        }
        original.owner.close().await;
        Ok::<(), anyhow::Error>(())
    })
    .await??;
    Ok(())
}

fn config(fixture: &testkit::PgTlsFixture, role: &str) -> anyhow::Result<PgConfig> {
    let p = fixture.params();
    Ok(PgConfig::new(
        &p.host,
        p.port,
        &p.database,
        role,
        PgPassword::new("fixture-only"),
        PgPrivateCa::from_pem(fixture.ca_pem().as_bytes().to_vec())?,
    ))
}
async fn paired(config: PgConfig, owner: &PgPool, names: &[&str]) -> anyhow::Result<Fixture> {
    let (runtime, store, outbox) = stores_for(
        config.clone(),
        CommandClock::Postgres,
        CallerRoles::new(names)?,
    )
    .await?;
    Ok(Fixture {
        runtime,
        store,
        outbox,
        owner: owner.clone(),
        config,
    })
}
async fn admit(f: &Fixture, callers: CallerRoles) -> anyhow::Result<bool> {
    let outbox = f.outbox.clone();
    let attempt = f
        .runtime
        .local_tx(scope(TENANT)?.tenant(), budget()?, move |tx| {
            Box::pin(
                async move { PgStore::new(tx, outbox, CommandClock::Postgres, &callers).await },
            )
        })
        .await;
    // A deadline/connection failure cannot masquerade as a successful security rejection.
    attempt.fold(
        |_| Ok(true),
        rejection,
        rejection,
        |e| Err(e.into()),
        |e| Err(e.into()),
        |e| Err(e.into()),
    )
}
fn rejection(error: PgError) -> anyhow::Result<bool> {
    anyhow::ensure!(
        matches!(
            &error,
            PgError::Operation {
                kind: rss_transactional_messaging::error::MessagingErrorKind::Invariant,
                ..
            }
        ),
        "admission must reject through the component contract: {error:?}"
    );
    Ok(false)
}
async fn snapshot(f: &Fixture) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar("SELECT jsonb_build_array((SELECT jsonb_agg(to_jsonb(c) ORDER BY tenant_id,command_id) FROM rss_device_command.commands c),(SELECT jsonb_agg(to_jsonb(a) ORDER BY tenant_id,device_id) FROM rss_device_command.authorities a),(SELECT jsonb_agg(to_jsonb(o) ORDER BY tenant_id,message_id) FROM rss_transactional_messaging.outbox o))::text")
        .fetch_one(&f.owner).await?)
}
async fn reject_change(f: &Fixture, change: &str, restore: &str) -> anyhow::Result<()> {
    let before = snapshot(f).await?;
    // The test matrix owns these SQL statements; none originate in runtime input.
    sqlx::raw_sql(sqlx::AssertSqlSafe(change))
        .execute(&f.owner)
        .await?;
    let result = admit(f, CallerRoles::new(PAIR)?).await;
    let unchanged = snapshot(f).await;
    sqlx::raw_sql(sqlx::AssertSqlSafe(restore))
        .execute(&f.owner)
        .await?;
    anyhow::ensure!(!result?, "unexpectedly admitted test mutation: {change}");
    assert_eq!(
        unchanged?, before,
        "rejected admission changed durable state"
    );
    assert!(admit(f, CallerRoles::new(PAIR)?).await?);
    Ok(())
}

async fn atomic(f: &Fixture, name: &str) -> anyhow::Result<()> {
    let s = scope(TENANT)?;
    let c = Coordinate::new(1, 1)?;
    f.initialize(s, c).await?;
    let rollback = format!("{name}-rollback");
    let store = f.store.clone();
    let request = spec(&rollback, s, c)?;
    let msg = message(&rollback, s.tenant())?;
    let attempt = f
        .runtime
        .local_tx(s.tenant(), budget()?, move |tx| {
            Box::pin(async move {
                store.queue(tx, request, msg).await?;
                Err::<(), PgError>(sqlx::Error::PoolTimedOut.into())
            })
        })
        .await;
    assert_eq!(status(attempt), "rolled-back");
    assert_eq!(f.count("commands", &rollback).await?, 0);
    assert_eq!(f.count("outbox", &format!("dispatch.{rollback}")).await?, 0);
    f.queue(name, s, c).await?;
    let unknown = format!("{name}-unknown");
    let request = spec(&unknown, s, c)?;
    let msg = message(&unknown, s.tenant())?;
    let store = f.store.clone();
    f.runtime
        .inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    let attempt = f
        .runtime
        .local_tx(s.tenant(), budget()?, move |tx| {
            Box::pin(async move { store.queue(tx, request, msg).await })
        })
        .await;
    assert_eq!(status(attempt), "unknown");
    // A fresh, paired store reloads and exactly replays the original durable identity.
    let roles = if name == "third-caller" { THREE } else { PAIR };
    let reopened = paired(f.config.clone(), &f.owner, roles).await?;
    let stored = reopened
        .load(&unknown, s)
        .await?
        .ok_or_else(|| anyhow::anyhow!("committed command missing"))?;
    assert_eq!(reopened.queue(&unknown, s, c).await?, stored);
    for id in [name, unknown.as_str()] {
        assert_eq!(f.count("commands", id).await?, 1);
        assert_eq!(f.count("outbox", &format!("dispatch.{id}")).await?, 1);
    }
    reopened.publish().await?;
    assert!(
        reopened
            .recover(s)
            .await?
            .commands
            .iter()
            .any(|command| command.spec().id().as_str() == unknown
                && command.status() == Status::Published)
    );
    reopened.runtime.close().await;
    Ok(())
}

async fn foreign(owner: &Fixture, other: &Fixture) -> anyhow::Result<()> {
    let before = snapshot(owner).await?;
    let s = scope(TENANT)?;
    let callers = CallerRoles::new(PAIR)?;
    let outbox = owner.outbox.clone();
    let constructor = other
        .runtime
        .local_tx(s.tenant(), budget()?, move |tx| {
            Box::pin(
                async move { PgStore::new(tx, outbox, CommandClock::Postgres, &callers).await },
            )
        })
        .await;
    assert!(committed(constructor).is_err());
    let store = owner.store.clone();
    let request = spec("foreign-caller", s, Coordinate::new(1, 1)?)?;
    let msg = message("foreign-caller", s.tenant())?;
    let operation = other
        .runtime
        .local_tx(s.tenant(), budget()?, move |tx| {
            Box::pin(async move { store.queue(tx, request, msg).await })
        })
        .await;
    assert!(committed(operation).is_err());
    let store = owner.store.clone();
    let request = spec("foreign-tenant", s, Coordinate::new(1, 1)?)?;
    let msg = message("foreign-tenant", s.tenant())?;
    let tenant = owner
        .runtime
        .local_tx(scope(OTHER)?.tenant(), budget()?, move |tx| {
            Box::pin(async move { store.queue(tx, request, msg).await })
        })
        .await;
    assert!(committed(tenant).is_err());
    assert_eq!(snapshot(owner).await?, before);
    Ok(())
}
