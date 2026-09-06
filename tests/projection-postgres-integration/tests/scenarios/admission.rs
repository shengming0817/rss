use super::*;

pub(crate) async fn rejects_dangerous_acl(pool: &PgPool, owner: &PgPool) -> anyhow::Result<()> {
    for (grant, revoke) in [
        (
            "GRANT UPDATE(position,epoch,worker_token) ON rss_projection.checkpoints TO projection_runtime",
            "REVOKE UPDATE(position,epoch,worker_token) ON rss_projection.checkpoints FROM projection_runtime",
        ),
        (
            "GRANT INSERT(position) ON rss_projection.checkpoints TO projection_runtime",
            "REVOKE INSERT(position) ON rss_projection.checkpoints FROM projection_runtime",
        ),
        (
            "GRANT TRIGGER ON rss_projection.events TO projection_runtime",
            "REVOKE TRIGGER ON rss_projection.events FROM projection_runtime",
        ),
        (
            "GRANT projection_owner TO projection_runtime WITH INHERIT FALSE, SET TRUE",
            "REVOKE projection_owner FROM projection_runtime",
        ),
    ] {
        sqlx::raw_sql(grant).execute(owner).await?;
        let adoption = PgStore::new(pool.clone()).await;
        sqlx::raw_sql(revoke).execute(owner).await?;
        assert!(
            matches!(adoption, Err(error) if error.kind() == rss_projection::ErrorKind::StorageContract)
        );
        PgStore::new(pool.clone()).await?;
    }
    Ok(())
}

pub(crate) async fn borrowed_timeout_rolls_back(
    pool: &PgPool,
    store: &PgStore,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let s = scope("borrowed-timeout", TENANT)?;
    let mut holder = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(TENANT)
        .execute(&mut *holder)
        .await?;
    append_in_transaction(&mut holder, s.source(), "holder", b"x", control).await?;
    let mut blocked = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(TENANT)
        .execute(&mut *blocked)
        .await?;
    let clock = ServerWatchdogTimer;
    let cancel = CancellationToken::new();
    let short = Control::new(&clock, Duration::from_millis(80), &cancel);
    let result = append_in_transaction(&mut blocked, s.source(), "blocked", b"x", &short).await;
    assert!(matches!(
        result.err().map(|error| error.kind()),
        Some(ErrorKind::CommitUnknown | ErrorKind::Unavailable)
    ));
    tokio::time::timeout(Duration::from_secs(2), blocked.rollback()).await??;
    holder.rollback().await?;
    assert_eq!(store.high_water(s.source()).await?, None);
    assert_eq!(append(store, &s, "after", b"x", control).await?.get(), 0);
    Ok(())
}

// A paused host timer isolates the database watchdog from the outer cancellation race.
struct ServerWatchdogTimer;
impl Timer for ServerWatchdogTimer {
    fn now(&self) -> Duration {
        Duration::ZERO
    }
    async fn sleep_until(&self, _: Duration) {
        std::future::pending::<()>().await;
    }
}

pub(crate) async fn store_identity(
    pool: &PgPool,
    store: &PgStore,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let s = scope("claim-identity", TENANT)?;
    store
        .initialize(&s, GenerationStart::beginning(), ReplayBound::Live, control)
        .await?;
    let second = PgStore::new(pool.clone()).await?;
    assert!(
        matches!(second.projection(store.takeover(&s, control).await?, Counter), Err(e) if e.kind() == ErrorKind::ScopeMismatch)
    );
    assert!(
        matches!(second.external_checkpoint(store.takeover(&s, control).await?), Err(e) if e.kind() == ErrorKind::ScopeMismatch)
    );
    store.projection(store.takeover(&s, control).await?, Counter)?;
    store.external_checkpoint(store.takeover(&s, control).await?)?;

    Ok(())
}

pub(crate) async fn bounded_close(
    pool: &PgPool,
    store: &PgStore,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let s = scope("closed-pool", TENANT)?;
    // A held checkout must not make close exceed its caller's budget.
    let held = pool.acquire().await?;
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    let short = Control::new(&clock, Duration::from_millis(30), &cancel);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), store.close(&short)).await?,
        CloseOutcome::Deadline
    );
    assert!(pool.is_closed());
    assert!(matches!(pool.acquire().await, Err(sqlx::Error::PoolClosed)));
    let error = store
        .high_water(s.source())
        .await
        .err()
        .ok_or_else(|| anyhow::anyhow!("closed pool served read"))?;
    assert_eq!(error.kind(), ErrorKind::Unavailable);
    assert_eq!(
        error
            .diagnostic()
            .ok_or_else(|| anyhow::anyhow!("missing checkout evidence"))?
            .phase(),
        Phase::Acquire
    );
    cancel.cancel();
    assert_eq!(store.close(&short).await, CloseOutcome::Cancelled);
    drop(held);
    assert_eq!(store.close(control).await, CloseOutcome::Drained);
    Ok(())
}

pub(crate) async fn application_error_cannot_claim_settlement(
    store: &PgStore,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let s = scope("application-error", TENANT)?;
    let source = s.source().clone();
    let result: Result<(), Error> = store.local_tx(s.source(), control, move |tx| Box::pin(async move {
        tx.append(&source, "rolled-back", b"x").await?;
        tx.with_connection(|conn| Box::pin(async move {
            sqlx::raw_sql("DO $$ BEGIN RAISE EXCEPTION 'password=private-value' USING ERRCODE='P1002'; END $$").execute(conn).await?;
            Ok(())
        })).await
    })).await;
    let error = result
        .err()
        .ok_or_else(|| anyhow::anyhow!("application SQL succeeded"))?;
    assert_eq!(error.kind(), ErrorKind::Rejected);
    let diagnostic = error
        .diagnostic()
        .ok_or_else(|| anyhow::anyhow!("missing SQL evidence"))?;
    assert_eq!(diagnostic.phase(), Phase::Application);
    assert_eq!(diagnostic.sqlstate(), Some("P1002"));
    assert!(!format!("{error:?} {error}").contains("private-value"));
    let source = std::error::Error::source(&error)
        .ok_or_else(|| anyhow::anyhow!("missing redacted evidence"))?;
    assert!(source.source().is_none());
    assert!(!format!("{source:?} {source}").contains("private-value"));
    assert_eq!(store.high_water(s.source()).await?, None);
    Ok(())
}
