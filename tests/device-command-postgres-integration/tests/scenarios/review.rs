use super::*;
use std::{io::Write, sync::Mutex};
use tracing::instrument::WithSubscriber;
#[derive(Clone)]
struct Capture(Arc<Mutex<Vec<u8>>>);
impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| std::io::Error::other("capture poisoned"))?
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
pub(super) async fn admission_reason(f: &Fixture, expected: &str) -> anyhow::Result<()> {
    let capture = Capture(Arc::new(Mutex::new(Vec::new())));
    let writer = capture.clone();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let result = stores(f.config.clone()).with_subscriber(subscriber).await;
    assert!(result.is_err());
    let bytes = capture
        .0
        .lock()
        .map_err(|_| anyhow::anyhow!("capture poisoned"))?
        .clone();
    let mut reasons = Vec::new();
    for line in String::from_utf8(bytes)?.lines() {
        let record: serde_json::Value = serde_json::from_str(line)?;
        if record["fields"]["phase"] == "probe" {
            reasons.push(
                record["fields"]["reason"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
            );
        }
    }
    assert_eq!(reasons, vec![expected]);
    Ok(())
}
pub(crate) async fn diagnostic_classes(f: &Fixture) -> anyhow::Result<()> {
    for (change, restore, expected) in [
        (
            "COMMENT ON SCHEMA rss_device_command IS 'incorrect'",
            "COMMENT ON SCHEMA rss_device_command IS 'rss-device-command-postgres:1'",
            "revision",
        ),
        (
            "GRANT device_owner TO device_runtime",
            "REVOKE device_owner FROM device_runtime",
            "runtime_role",
        ),
        (
            "GRANT UPDATE ON rss_device_command.commands TO device_runtime",
            "REVOKE UPDATE ON rss_device_command.commands FROM device_runtime",
            "runtime_acl",
        ),
        (
            "ALTER POLICY tenant_scope ON rss_device_command.commands USING(true)",
            "ALTER POLICY tenant_scope ON rss_device_command.commands USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)",
            "rls_policy",
        ),
        (
            "ALTER FUNCTION rss_device_command.lock_authority(uuid,uuid) SECURITY INVOKER",
            "ALTER FUNCTION rss_device_command.lock_authority(uuid,uuid) SECURITY DEFINER",
            "functions",
        ),
    ] {
        sqlx::raw_sql(change).execute(&f.owner).await?;
        let rejected = admission_reason(f, expected).await;
        sqlx::raw_sql(restore).execute(&f.owner).await?;
        rejected?;
    }
    Ok(())
}
pub(crate) async fn full_outbox_states(f: &Fixture) -> anyhow::Result<()> {
    let s = Scope::new(
        scope(TENANT)?.tenant(),
        DeviceId::parse("550e8400-e29b-41d4-a716-446655440005")?,
    );
    let c = Coordinate::new(1, 1)?;
    f.initialize(s, c).await?;
    f.publish().await?;
    for id in ["held-publication", "terminal-dlq"] {
        f.queue(id, s, c).await?;
    }
    let claims = f
        .outbox
        .claim_partition_heads(std::num::NonZeroUsize::MIN.saturating_add(1), budget()?)
        .await?;
    assert_eq!(claims.len(), 2);
    for claim in claims {
        let id = PgOutboxStore::<()>::message(&claim)
            .envelope()
            .id()
            .as_str()
            .to_owned();
        if id == "dispatch.terminal-dlq" {
            f.outbox
                .settle(claim, OutboxSettlement::DeadLetter, budget()?)
                .await?;
            unconfirmed(f, s, "terminal-dlq").await?;
        } else {
            assert_eq!(id, "dispatch.held-publication");
            unconfirmed(f, s, "held-publication").await?;
            f.outbox
                .settle(claim, OutboxSettlement::Retry, budget()?)
                .await?;
        }
    }
    Ok(())
}
async fn unconfirmed(f: &Fixture, s: Scope, id: &str) -> anyhow::Result<()> {
    let m = message(id, s.tenant())?;
    let outbox = f.outbox.clone();
    let published = committed(
        f.runtime
            .local_tx(s.tenant(), budget()?, move |tx| {
                Box::pin(async move {
                    outbox
                        .is_published(
                            tx,
                            m.envelope().metadata().domain(),
                            m.envelope().id(),
                            m.fingerprint(),
                        )
                        .await
                })
            })
            .await,
    )?;
    assert!(!published);
    let page = f.recover(s).await?;
    assert!(page.commands.iter().all(|c| c.status() == Status::Queued));
    Ok(())
}
pub(crate) async fn authority_pages(f: &Fixture) -> anyhow::Result<()> {
    let s = Scope::new(
        scope(TENANT)?.tenant(),
        DeviceId::parse("550e8400-e29b-41d4-a716-446655440006")?,
    );
    let c = Coordinate::new(1, 1)?;
    f.initialize(s, c).await?;
    let mut requests = Vec::new();
    for index in 0..65 {
        let id = format!("many-{index:03}");
        requests.push((spec(&id, s, c)?, message(&id, s.tenant())?));
    }
    let store = f.store.clone();
    committed(
        f.runtime
            .local_tx(s.tenant(), budget()?, move |tx| {
                Box::pin(async move {
                    for (request, message) in requests {
                        store.queue(tx, request, message).await?;
                    }
                    Ok(())
                })
            })
            .await,
    )?;
    let next = Coordinate::new(1, 2)?;
    let store = f.store.clone();
    let aborted = f
        .runtime
        .local_tx(s.tenant(), budget()?, move |tx| {
            Box::pin(async move {
                store.advance(tx, s, c, next).await?;
                Err::<(), PgError>(sqlx::Error::PoolTimedOut.into())
            })
        })
        .await;
    assert_eq!(status(aborted), "rolled-back");
    assert_eq!(count_scope(f, s, "queued").await?, 65);
    let store = f.store.clone();
    committed(
        f.runtime
            .local_tx(s.tenant(), budget()?, move |tx| {
                Box::pin(async move { store.advance(tx, s, c, next).await })
            })
            .await,
    )?;
    assert_eq!(count_scope(f, s, "superseded").await?, 65);
    for id in ["many-000", "many-064"] {
        assert_eq!(
            f.load(id, s).await?.map(|c| c.status()),
            Some(Status::Superseded)
        );
    }
    Ok(())
}
async fn count_scope(f: &Fixture, s: Scope, state: &str) -> anyhow::Result<i64> {
    Ok(sqlx::query_scalar("SELECT count(*) FROM rss_device_command.commands WHERE tenant_id=$1::uuid AND device_id=$2::uuid AND status=$3").bind(s.tenant().to_string()).bind(s.device().as_uuid().to_string()).bind(state).fetch_one(&f.owner).await?)
}
pub(crate) async fn composition_boundaries(f: &Fixture) -> anyhow::Result<()> {
    let s = Scope::new(
        scope(TENANT)?.tenant(),
        DeviceId::parse("550e8400-e29b-41d4-a716-446655440007")?,
    );
    let c = Coordinate::new(1, 1)?;
    f.initialize(s, c).await?;
    runtime_boundaries(f, s).await?;
    domain_recovery(f, s, c).await
}

async fn runtime_boundaries(f: &Fixture, s: Scope) -> anyhow::Result<()> {
    let (other_runtime, _, other_outbox) = stores(f.config.clone()).await?;
    let foreign = committed(
        f.runtime
            .local_tx(s.tenant(), budget()?, move |tx| {
                Box::pin(async move { PgStore::new(tx, other_outbox).await })
            })
            .await,
    )
    .is_ok();
    let store = f.store.clone();
    let id = CommandId::parse("multi-a")?;
    let foreign_operation = committed(
        other_runtime
            .local_tx(s.tenant(), budget()?, move |tx| {
                Box::pin(async move { store.load(tx, s, &id).await })
            })
            .await,
    )
    .is_ok();
    let source = f.outbox.clone();
    let message = message("foreign-append", s.tenant())?;
    let foreign_append = committed(
        other_runtime
            .local_tx(s.tenant(), budget()?, move |tx| {
                Box::pin(async move { source.append(tx, message).await.map_err(PgError::from) })
            })
            .await,
    )
    .is_ok();
    assert!(!foreign_append);
    other_runtime.close().await;
    assert!(!foreign, "foreign runtime admitted by constructor");
    assert!(!foreign_operation, "foreign runtime admitted by operation");
    Ok(())
}

async fn domain_recovery(f: &Fixture, s: Scope, c: Coordinate) -> anyhow::Result<()> {
    let alternate = Arc::new(PgOutboxStore::<()>::new(
        f.runtime.clone(),
        MessagingDomain::parse("device-alt")?,
        DeliveryBudget::new(
            Duration::from_secs(60),
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )?,
    )?);
    let selected = alternate.clone();
    let other = committed(
        f.runtime
            .local_tx(s.tenant(), budget()?, move |tx| {
                Box::pin(async move { PgStore::new(tx, selected).await })
            })
            .await,
    )?;
    f.queue("multi-a", s, c).await?;
    let request = spec("multi-b", s, c)?;
    let msg = message_in_domain("multi-b", s.tenant(), "device-alt")?;
    committed(
        f.runtime
            .local_tx(s.tenant(), budget()?, move |tx| {
                Box::pin(async move { other.queue(tx, request, msg).await })
            })
            .await,
    )?;
    let _page = f.recover(s).await?;
    let claims = alternate
        .claim_partition_heads(std::num::NonZeroUsize::MIN, budget()?)
        .await?;
    for claim in claims {
        alternate
            .settle(claim, OutboxSettlement::Published(()), budget()?)
            .await?;
    }
    let _page = f.recover(s).await?;
    assert_eq!(
        f.load("multi-b", s).await?.map(|c| c.status()),
        Some(Status::Published)
    );
    assert_eq!(
        f.load("multi-a", s).await?.map(|c| c.status()),
        Some(Status::Queued)
    );
    Ok(())
}
