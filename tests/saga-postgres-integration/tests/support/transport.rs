//! Real PostgreSQL frame loss. SQLx receives EOF, never a fabricated provider error.
//! ref: sqlx-postgres/src/transaction.rs@0.9.0; tokio-rustls/src/client.rs@0.26.4
use super::*;
#[path = "completion_transport.rs"]
mod completion_transport;
use crate::pg_settlement::Proxy;

async fn backend(pool: &PgPool) -> anyhow::Result<i32> {
    Ok(sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(pool)
        .await?)
}
pub async fn verify(
    fixture: &testkit::PgTlsFixture,
    direct: &PgStore,
    owner: &PgPool,
    d: &Definition,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let proxy = Proxy::new(fixture).await?;
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(
            PgConnectOptions::new()
                .host("127.0.0.1")
                .port(proxy.port)
                .database(&fixture.params().database)
                .username("saga_runtime")
                .password("fixture-only")
                .ssl_mode(PgSslMode::Disable),
        )
        .await?;
    let store = PgStore::new(pool.clone(), control).await?;
    registration_ack(&proxy, &store, &pool, direct, d, control).await?;
    completion(&proxy, &store, direct, owner, d, control, false).await?;
    completion(&proxy, &store, direct, owner, d, control, true).await?;
    pending(&proxy, &store, direct, owner, d, control).await?;
    aborted_commit(&proxy, &store, direct, owner, d, control).await?;
    Box::pin(discovery_ack(&proxy, &store, &pool, direct, d, control)).await?;
    assert_eq!(store.close(control).await, CloseOutcome::Drained);
    Ok(())
}
async fn discovery_ack(
    proxy: &Proxy,
    store: &PgStore,
    pool: &PgPool,
    direct: &PgStore,
    d: &Definition,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let s = scope("46634663-2222-4333-8444-555555555555")?;
    let pid = backend(pool).await?;
    let lost = proxy.lost.load(Ordering::SeqCst);
    let faulty = completion_transport::CompletionFault {
        store: store.clone(),
        armed: false.into(),
        arm: proxy.arm.clone(),
        fault: completion_transport::Fault::DiscoveryAck,
        committed: tokio::sync::Notify::new(),
    };
    let effects = Arc::new(Effects::default());
    let executor = Executor::new(
        faulty,
        protection()?,
        registry(d.clone(), effects.clone(), false)?,
        read_budget()?,
    );
    executor.register(s, d, history_capacity()?, c).await?;
    let page = executor
        .run_once(s.tenant(), None, SweepBudget::new(1, 30)?, c)
        .await?;
    assert_read_failure(&page)?;
    assert_eq!(proxy.lost.load(Ordering::SeqCst), lost + 1);
    assert_ne!(backend(pool).await?, pid);
    let lease = direct.claim(s, Duration::from_secs(5), c).await?;
    assert_eq!(direct.history_head(&lease, c).await?.revision(), 2);
    direct.release(&lease, c).await?;
    assert_eq!(
        *effects.calls.lock().map_err(|_| ErrorKind::Store)?,
        ["execute:one"]
    );
    Ok(())
}
fn assert_read_failure(page: &SweepReport) -> anyhow::Result<()> {
    let failure = page.items[0]
        .result
        .as_ref()
        .err()
        .ok_or_else(|| anyhow::anyhow!("expected lost discovery ACK"))?;
    assert_eq!(failure.error.kind(), ErrorKind::Store);
    assert_eq!(
        failure.error.diagnostic().map(Diagnostic::phase),
        Some(DiagnosticPhase::Commit)
    );
    assert_eq!(failure.advances, 1);
    assert_eq!(failure.head().map(HistoryHead::revision), Some(2));
    assert!(failure.release_error.is_none());
    Ok(())
}
async fn pending(
    proxy: &Proxy,
    store: &PgStore,
    direct: &PgStore,
    owner: &PgPool,
    d: &Definition,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    // Test-only deferred trigger runs inside COMMIT, after SQLx has sent COMMIT to PostgreSQL.
    let mut blocker = owner.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(2293931)")
        .execute(&mut *blocker)
        .await?;
    sqlx::raw_sql("CREATE FUNCTION rss_saga.test_hold_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(2293931); RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER test_hold_commit AFTER INSERT ON rss_saga.instances DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION rss_saga.test_hold_commit();").execute(owner).await?;
    let s = scope(TENANT)?;
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    let short = Control::new(&clock, Duration::from_secs(10), &cancel);
    proxy.arm.store(1, Ordering::SeqCst);
    assert_kind(
        cancel_during_commit(proxy, store, s, d, &short, &cancel).await,
        ErrorKind::CommitUnknown,
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_saga.instances WHERE saga_id=$1")
        .bind(s.id())
        .fetch_one(owner)
        .await?;
    assert_eq!(
        count, 0,
        "ordinary MVCC read does not prove absence after settlement"
    );
    assert_eq!(
        proxy.lost.load(Ordering::SeqCst),
        3,
        "server has not settled yet"
    );
    let recovery = direct.register(s, d, history_capacity()?, control);
    tokio::pin!(recovery);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut recovery)
            .await
            .is_err(),
        "recovery must wait for outstanding transaction, even though an ordinary read sees no row"
    );
    blocker.commit().await?;
    recovery.await?;
    sqlx::raw_sql("DROP TRIGGER test_hold_commit ON rss_saga.instances; DROP FUNCTION rss_saga.test_hold_commit();").execute(owner).await?;
    verify_snapshot(direct, s, d, control).await?;
    Ok(())
}

async fn completion(
    proxy: &Proxy,
    store: &PgStore,
    direct: &PgStore,
    owner: &PgPool,
    d: &Definition,
    control: &Control<'_, Clock>,
    interrupt_renewal: bool,
) -> anyhow::Result<()> {
    let s = scope(TENANT)?;
    let effects = Arc::new(Effects::default());
    let faulty = completion_transport::CompletionFault {
        store: store.clone(),
        armed: std::sync::atomic::AtomicBool::new(true),
        arm: proxy.arm.clone(),
        fault: if interrupt_renewal {
            completion_transport::Fault::Renewal
        } else {
            completion_transport::Fault::CommitAck
        },
        committed: tokio::sync::Notify::new(),
    };
    let executor = Executor::new(
        faulty,
        protection()?,
        registry(d.clone(), effects.clone(), false)?,
        read_budget()?,
    )
    .with_lease_policy(LeasePolicy::new(Duration::from_secs(6))?);
    // This proves lost COMMIT acknowledgement, not sub-second lease scheduling under load.
    executor
        .register(s, d, history_capacity()?, control)
        .await?;
    assert_kind(executor.run(s, 30, control).await, ErrorKind::CommitUnknown);
    assert_eq!(proxy.lost.load(Ordering::SeqCst), 3);
    assert_kind(
        direct.claim(s, Duration::from_secs(5), control).await,
        ErrorKind::Fenced,
    );
    expire(owner, s).await?;
    let recovered = Executor::new(
        direct.clone(),
        protection()?,
        registry(d.clone(), effects.clone(), false)?,
        read_budget()?,
    );
    assert_eq!(
        recovered.run(s, 30, control).await?.head().status(),
        Status::Succeeded
    );
    let receipts: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM rss_saga.journal WHERE protected IS NOT NULL AND saga_id=$1",
    )
    .bind(s.id())
    .fetch_one(owner)
    .await?;
    assert_eq!(receipts, 3);
    assert_eq!(
        *effects
            .calls
            .lock()
            .map_err(|_| anyhow::anyhow!("poisoned"))?,
        vec!["execute:one", "execute:two", "execute:three"]
    );
    Ok(())
}

fn assert_kind<T>(result: Result<T, Error>, kind: ErrorKind) {
    assert_eq!(result.err().map(|e| e.kind()), Some(kind));
}

async fn registration_ack(
    proxy: &Proxy,
    store: &PgStore,
    pool: &PgPool,
    direct: &PgStore,
    d: &Definition,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let s = scope(TENANT)?;
    let before = backend(pool).await?;
    proxy.arm.store(1, Ordering::SeqCst);
    assert_kind(
        store.register(s, d, history_capacity()?, control).await,
        ErrorKind::CommitUnknown,
    );
    assert_eq!(proxy.lost.load(Ordering::SeqCst), 1);
    assert_ne!(
        before,
        backend(pool).await?,
        "uncertain connection must not reenter pool"
    );
    // New transaction and instance lock prove the complete committed registration is present.
    direct.register(s, d, history_capacity()?, control).await?;
    verify_snapshot(direct, s, d, control).await?;
    rollback_ack(proxy, store, pool, s, d, control).await?;
    direct.register(s, d, history_capacity()?, control).await?;
    Ok(())
}
async fn rollback_ack(
    proxy: &Proxy,
    store: &PgStore,
    pool: &PgPool,
    s: Scope,
    d: &Definition,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let different = Definition::new("different-owner", d.identity().clone(), d.steps().to_vec())?;
    let before = backend(pool).await?;
    proxy.arm.store(2, Ordering::SeqCst);
    assert_kind(
        store
            .register(s, &different, history_capacity()?, control)
            .await,
        ErrorKind::RollbackUnknown,
    );
    assert_eq!(proxy.lost.load(Ordering::SeqCst), 2);
    assert_ne!(before, backend(pool).await?);
    Ok(())
}

async fn cancel_during_commit(
    proxy: &Proxy,
    store: &PgStore,
    s: Scope,
    d: &Definition,
    control: &Control<'_, Clock>,
    cancel: &CancellationToken,
) -> Result<(), Error> {
    let (result, ()) = tokio::join!(store.register(s, d, history_capacity()?, control), async {
        while proxy.arm.load(Ordering::SeqCst) != 0 {
            tokio::task::yield_now().await;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        cancel.cancel();
    });
    result
}

async fn verify_snapshot(
    direct: &PgStore,
    s: Scope,
    d: &Definition,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let lease = direct.claim(s, Duration::from_secs(5), control).await?;
    assert_eq!(
        direct
            .snapshot(&lease, read_budget()?, control)
            .await?
            .definition(),
        d
    );
    direct.release(&lease, control).await?;
    Ok(())
}

async fn aborted_commit(
    proxy: &Proxy,
    store: &PgStore,
    direct: &PgStore,
    owner: &PgPool,
    d: &Definition,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    sqlx::raw_sql("CREATE FUNCTION rss_saga.test_abort_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture rejection'; END $$; CREATE CONSTRAINT TRIGGER test_abort_commit AFTER INSERT ON rss_saga.instances DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION rss_saga.test_abort_commit();").execute(owner).await?;
    let s = scope(TENANT)?;
    proxy.arm.store(1, Ordering::SeqCst);
    assert_kind(
        store.register(s, d, history_capacity()?, control).await,
        ErrorKind::CommitUnknown,
    );
    sqlx::raw_sql("DROP TRIGGER test_abort_commit ON rss_saga.instances; DROP FUNCTION rss_saga.test_abort_commit();").execute(owner).await?;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_saga.instances WHERE saga_id=$1")
        .bind(s.id())
        .fetch_one(owner)
        .await?;
    assert_eq!(count, 0);
    // The fresh registration transaction serializes on unique identity and establishes absence.
    direct.register(s, d, history_capacity()?, control).await?;
    verify_snapshot(direct, s, d, control).await?;
    Ok(())
}
