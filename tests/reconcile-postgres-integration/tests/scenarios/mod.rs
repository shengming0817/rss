use super::*;
pub async fn run(
    store: &PgStore,
    pool: &PgPool,
    owner: &PgPool,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    scheduling(store, owner, c).await?;
    isolation(store, pool, owner, c).await?;
    fencing(store, owner, c).await?;
    atomicity(store, owner, c).await?;
    interruption(store, owner, c).await?;
    admission(pool, owner, c).await?;
    policy_admission(pool, owner, c).await?;
    live_connection_admission(store, owner, c).await?;
    Ok(())
}
async fn scheduling(store: &PgStore, owner: &PgPool, c: &Control<'_, Clock>) -> anyhow::Result<()> {
    let t = target("scheduling", TENANT)?;
    store.wake(&t, c).await?;
    let old = claim(store, &t, Duration::from_secs(2), c).await?;
    assert!(
        store
            .claim_due(t.scope(), 2, Duration::from_secs(1), c)
            .await?
            .is_empty()
    );
    store.renew(&old, Duration::from_secs(2), c).await?;
    store.wake(&t, c).await?;
    store.finish(&old, Completion::Converged, c).await?;
    let new = claim(store, &t, Duration::from_secs(2), c).await?;
    assert!(new.epoch() > old.epoch());
    retry_cycle(store, owner, c, &t, new).await
}
async fn retry_cycle(
    store: &PgStore,
    owner: &PgPool,
    c: &Control<'_, Clock>,
    t: &Target,
    new: PgClaim,
) -> anyhow::Result<()> {
    store
        .finish(
            &new,
            Completion::Retry {
                after: Duration::from_millis(20),
                failures: 2,
            },
            c,
        )
        .await?;
    assert!(
        store
            .claim_due(t.scope(), 1, Duration::from_secs(1), c)
            .await?
            .is_empty()
    );
    tokio::time::sleep(Duration::from_millis(25)).await;
    let again = claim(store, t, Duration::from_secs(2), c).await?;
    assert_eq!(again.failures(), 2);
    suspend_cycle(store, owner, c, t, again).await
}
async fn suspend_cycle(
    store: &PgStore,
    owner: &PgPool,
    c: &Control<'_, Clock>,
    t: &Target,
    again: PgClaim,
) -> anyhow::Result<()> {
    store
        .finish(&again, Completion::Suspended { failures: 3 }, c)
        .await?;
    assert!(
        store
            .claim_due(t.scope(), 1, Duration::from_secs(1), c)
            .await?
            .is_empty()
    );
    store.wake(t, c).await?;
    let awake = claim(store, t, Duration::from_secs(2), c).await?;
    assert_eq!(awake.failures(), 0);
    store.finish(&awake, Completion::Converged, c).await?;
    let epoch: i64 =
        sqlx::query_scalar("SELECT epoch FROM rss_reconcile.targets WHERE reconciler='scheduling'")
            .fetch_one(owner)
            .await?;
    assert_eq!(epoch, awake.epoch());
    Ok(())
}
async fn isolation(
    store: &PgStore,
    pool: &PgPool,
    owner: &PgPool,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let a = target("isolation", TENANT)?;
    let b = target("isolation", OTHER)?;
    store.wake(&a, c).await?;
    store.wake(&b, c).await?;
    raw_isolation(pool).await?;
    let ca = claim(store, &a, Duration::from_secs(2), c).await?;
    let cb = claim(store, &b, Duration::from_secs(2), c).await?;
    store.finish(&ca, Completion::Converged, c).await?;
    store.finish(&cb, Completion::Converged, c).await?;
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM rss_reconcile.targets WHERE reconciler='isolation'"
        )
        .fetch_one(owner)
        .await?,
        2
    );
    Ok(())
}
async fn fencing(store: &PgStore, owner: &PgPool, c: &Control<'_, Clock>) -> anyhow::Result<()> {
    let t = target("fencing", TENANT)?;
    store.wake(&t, c).await?;
    let old = claim(store, &t, Duration::from_millis(15), c).await?;
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(
        matches!(store.protect(&old,c, (),|_, tx|Box::pin(async move {effect(tx,"expired".into()).await})).await,Err(e) if e.kind()==ErrorKind::Fenced)
    );
    let fresh = claim(store, &t, Duration::from_secs(2), c).await?;
    assert!(fresh.epoch() > old.epoch());
    rejects_stale(store, &old, c).await?;
    commits_current(store, owner, c, &fresh).await
}
async fn commits_current(
    store: &PgStore,
    owner: &PgPool,
    c: &Control<'_, Clock>,
    fresh: &PgClaim,
) -> anyhow::Result<()> {
    store
        .protect(fresh, c, (), |_, tx| {
            Box::pin(async move { effect(tx, "fresh".into()).await })
        })
        .await?;
    assert_eq!(count(owner, "stale").await?, 0);
    assert_eq!(count(owner, "expired").await?, 0);
    assert_eq!(count(owner, "fresh").await?, 1);
    store.finish(fresh, Completion::Converged, c).await?;
    Ok(())
}
async fn atomicity(store: &PgStore, owner: &PgPool, c: &Control<'_, Clock>) -> anyhow::Result<()> {
    let t = target("atomic", TENANT)?;
    store.wake(&t, c).await?;
    let token = claim(store, &t, Duration::from_millis(40), c).await?;
    let entered = Arc::new(tokio::sync::Notify::new());
    let signal = entered.clone();
    let writer = store.protect(&token, c, (), move |_, tx| {
        Box::pin(async move {
            effect(tx, "rolled-back".into()).await?;
            signal.notify_one();
            tokio::time::sleep(Duration::from_millis(60)).await;
            Ok(())
        })
    });
    let contender = async {
        entered.notified().await;
        assert!(
            store
                .claim_due(t.scope(), 1, Duration::from_secs(1), c)
                .await?
                .is_empty()
        );
        Ok::<(), Error>(())
    };
    let (result, other) = tokio::join!(writer, contender);
    other?;
    assert!(matches!(result,Err(e) if e.kind()==ErrorKind::Fenced));
    assert_eq!(count(owner, "rolled-back").await?, 0);
    let retry = claim(store, &t, Duration::from_secs(1), c).await?;
    store
        .protect(&retry, c, (), |_, tx| {
            Box::pin(async move {
                effect(tx, "atomic".into()).await?;
                Err::<(), _>(PgOperationError::rejected())
            })
        })
        .await
        .err()
        .ok_or_else(|| anyhow::anyhow!("expected callback rejection"))?;
    assert_eq!(count(owner, "atomic").await?, 0);
    store.release(&retry, c).await?;
    Ok(())
}
async fn interruption(
    store: &PgStore,
    owner: &PgPool,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let t = target("unknown", TENANT)?;
    store.wake(&t, c).await?;
    let token = claim(store, &t, Duration::from_secs(2), c).await?;
    store.inject_next_fault(PgFault::CommitUnknownAfterAck);
    let result = store
        .protect(&token, c, (), |_, tx| {
            Box::pin(async move { effect(tx, "unknown".into()).await })
        })
        .await;
    assert!(matches!(result,Err(e) if e.kind()==ErrorKind::CommitUnknown));
    assert_eq!(count(owner, "unknown").await?, 1);
    uncertain_cleanup(store, owner, c, &token).await
}
async fn uncertain_cleanup(
    store: &PgStore,
    owner: &PgPool,
    c: &Control<'_, Clock>,
    token: &PgClaim,
) -> anyhow::Result<()> {
    let child = c.child(Duration::from_millis(15));
    store.inject_next_fault(PgFault::CommitPending);
    let result = store
        .protect(token, &child, (), |_, tx| {
            Box::pin(async move { effect(tx, "pending".into()).await })
        })
        .await;
    assert!(matches!(result,Err(e) if e.kind()==ErrorKind::CommitUnknown));
    assert_eq!(count(owner, "pending").await?, 0);
    store.inject_next_fault(PgFault::RollbackFailedAfterAck);
    let result = store
        .protect(token, c, (), |_, _| {
            Box::pin(async { Err::<(), _>(PgOperationError::rejected()) })
        })
        .await;
    assert!(matches!(result,Err(e) if e.kind()==ErrorKind::RollbackFailed));
    Ok(())
}
async fn admission(pool: &PgPool, owner: &PgPool, c: &Control<'_, Clock>) -> anyhow::Result<()> {
    sqlx::raw_sql("COMMENT ON SCHEMA rss_reconcile IS 'rss-reconcile-postgres:999'")
        .execute(owner)
        .await?;
    assert!(
        matches!(PgStore::new(pool.clone(),c).await,Err(e) if e.kind()==ErrorKind::StorageContract)
    );
    sqlx::raw_sql("COMMENT ON SCHEMA rss_reconcile IS 'rss-reconcile-postgres:1'; GRANT UPDATE ON rss_reconcile.targets TO reconcile_runtime;").execute(owner).await?;
    assert!(PgStore::new(pool.clone(), c).await.is_err());
    sqlx::raw_sql("REVOKE UPDATE ON rss_reconcile.targets FROM reconcile_runtime")
        .execute(owner)
        .await?;
    Ok(())
}

async fn raw_isolation(pool: &PgPool) -> anyhow::Result<()> {
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM rss_reconcile.targets")
            .fetch_one(pool)
            .await?,
        0
    );
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(TENANT)
        .execute(&mut *tx)
        .await?;
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM rss_reconcile.targets WHERE tenant_id=$1::uuid"
        )
        .bind(OTHER)
        .fetch_one(&mut *tx)
        .await?,
        0
    );
    assert!(
        sqlx::query("SELECT rss_reconcile.wake($1::uuid,'isolation','bad')")
            .bind(OTHER)
            .execute(&mut *tx)
            .await
            .is_err()
    );
    tx.rollback().await?;
    assert!(
        sqlx::query("UPDATE rss_reconcile.targets SET epoch=0")
            .execute(pool)
            .await
            .is_err()
    );
    Ok(())
}

async fn rejects_stale(
    store: &PgStore,
    old: &PgClaim,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    for result in [
        store.renew(old, Duration::from_secs(1), c).await,
        store.release(old, c).await,
        store.finish(old, Completion::Converged, c).await,
        store
            .protect(old, c, (), |_, tx| {
                Box::pin(async move { effect(tx, "stale".into()).await })
            })
            .await,
    ] {
        assert!(matches!(result,Err(e) if e.kind()==ErrorKind::Fenced));
    }
    Ok(())
}

async fn policy_admission(
    pool: &PgPool,
    owner: &PgPool,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    sqlx::raw_sql(
        "ALTER POLICY tenant_scope ON rss_reconcile.targets USING(true) WITH CHECK(true)",
    )
    .execute(owner)
    .await?;
    assert!(PgStore::new(pool.clone(), c).await.is_err());
    sqlx::raw_sql("ALTER POLICY tenant_scope ON rss_reconcile.targets USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid); ALTER FUNCTION rss_reconcile.lock_claim(uuid,text,text,uuid,bigint) SET search_path=public").execute(owner).await?;
    assert!(PgStore::new(pool.clone(), c).await.is_err());
    sqlx::raw_sql("ALTER FUNCTION rss_reconcile.lock_claim(uuid,text,text,uuid,bigint) SET search_path=pg_catalog,rss_reconcile").execute(owner).await?;
    Ok(())
}

async fn live_connection_admission(
    store: &PgStore,
    owner: &PgPool,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    use std::sync::atomic::{AtomicBool, Ordering};
    let t = target("live-admission", TENANT)?;
    store.wake(&t, c).await?;
    let claim = claim(store, &t, Duration::from_secs(2), c).await?;
    for (change, restore) in [
        (
            "GRANT UPDATE ON rss_reconcile.targets TO reconcile_runtime",
            "REVOKE UPDATE ON rss_reconcile.targets FROM reconcile_runtime",
        ),
        (
            "ALTER POLICY tenant_scope ON rss_reconcile.targets USING(true) WITH CHECK(true)",
            "ALTER POLICY tenant_scope ON rss_reconcile.targets USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)",
        ),
        (
            "ALTER FUNCTION rss_reconcile.lock_claim(uuid,text,text,uuid,bigint) SET search_path=public",
            "ALTER FUNCTION rss_reconcile.lock_claim(uuid,text,text,uuid,bigint) SET search_path=pg_catalog,rss_reconcile",
        ),
    ] {
        sqlx::raw_sql(change).execute(owner).await?;
        let called = AtomicBool::new(false);
        let result = store
            .protect(&claim, c, &called, |called, _| {
                Box::pin(async move {
                    called.store(true, Ordering::SeqCst);
                    Ok(())
                })
            })
            .await;
        sqlx::raw_sql(restore).execute(owner).await?;
        assert!(matches!(result,Err(e) if e.kind()==ErrorKind::StorageContract));
        assert!(!called.load(Ordering::SeqCst));
    }
    Ok(())
}
