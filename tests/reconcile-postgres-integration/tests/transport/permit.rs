use super::*;
use crate::pg_settlement::{HOLD_RETURN, Proxy};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

struct Slot {
    _slot: OwnedSemaphorePermit,
    drops: Arc<AtomicUsize>,
}
impl Drop for Slot {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}
async fn slot(tenant: &Arc<Semaphore>, drops: &Arc<AtomicUsize>) -> anyhow::Result<Slot> {
    Ok(Slot {
        _slot: tenant.clone().acquire_owned().await?,
        drops: drops.clone(),
    })
}
async fn pid(tx: &mut PgTransaction<'_>) -> Result<i32, PgOperationError> {
    tx.with_connection(|conn| {
        Box::pin(async move {
            sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(conn)
                .await
        })
    })
    .await
}
pub(crate) async fn verify(db: &Database, c: &Control<'_, Clock>) -> anyhow::Result<()> {
    let proxy = Proxy::new(&db.fixture).await?;
    let options = PgConnectOptions::new()
        .host("127.0.0.1")
        .port(proxy.port)
        .database(&db.fixture.params().database)
        .username("reconcile_runtime")
        .password("fixture-only")
        .ssl_mode(PgSslMode::Disable);
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .min_connections(1)
        .acquire_timeout(Duration::from_millis(600))
        .connect_with(options)
        .await?;
    let store = PgStore::new(pool.clone(), c).await?;
    let a = target("permit-a", TENANT)?;
    let b = target("permit-peer", OTHER)?;
    store
        .wake(&b, &ResourceSet::empty(b.scope().tenant()), c)
        .await?;
    let claim = claim(&store, &b, Duration::from_secs(10), c).await?;
    let tenant_a = Arc::new(Semaphore::new(1));
    let drops = Arc::new(AtomicUsize::new(0));
    fairness(db, &pool, &store, &proxy, &a, &claim, c, &tenant_a, &drops).await?;
    failures(&store, &pool, a.scope(), c, &tenant_a, &drops).await?;
    cancellation_and_drain(&store, a.scope(), c, &tenant_a, &drops).await?;
    assert_eq!(store.close(c).await, CloseOutcome::Drained);
    assert_eq!(drops.load(Ordering::SeqCst), 8);
    assert_eq!(tenant_a.available_permits(), 1);
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "same two-connection fixture and host admission state"
)]
async fn fairness(
    db: &Database,
    pool: &PgPool,
    store: &PgStore,
    proxy: &Proxy,
    a: &Target,
    claim: &PgClaim,
    c: &Control<'_, Clock>,
    tenant_a: &Arc<Semaphore>,
    drops: &Arc<AtomicUsize>,
) -> anyhow::Result<()> {
    proxy.arm.store(HOLD_RETURN, Ordering::SeqCst);
    let a1 = store
        .with_permit(slot(tenant_a, drops).await?)?
        .local_tx(a.scope(), c, |tx| Box::pin(pid(tx)))
        .await?;
    tokio::time::timeout(Duration::from_secs(2), proxy.gate.held.cancelled()).await?;
    let mut a2 = Box::pin(slot(tenant_a, drops));
    assert!(futures::poll!(&mut a2).is_pending());
    assert_ne!(a1, renew_peer(&db.owner, store, claim, c, drops).await?);
    assert!(futures::poll!(&mut a2).is_pending());
    // Occupy the other healthy connection so A2 must use the slot retired
    // by the watchdog. Keep the real return response held throughout.
    let healthy = pool.acquire().await?;
    let permit = tokio::time::timeout(Duration::from_secs(8), a2).await??;
    let replacement = store
        .with_permit(permit)?
        .local_tx(a.scope(), c, |tx| Box::pin(pid(tx)))
        .await?;
    assert_ne!(replacement, a1);
    proxy.gate.release.cancel();
    drop(healthy);
    Ok(())
}

async fn renew_peer(
    owner: &PgPool,
    store: &PgStore,
    claim: &PgClaim,
    c: &Control<'_, Clock>,
    drops: &Arc<AtomicUsize>,
) -> anyhow::Result<i32> {
    const STATE: &str = "SELECT epoch,(extract(epoch FROM lease_until)*1000000)::bigint FROM rss_reconcile.targets WHERE tenant_id=$1::uuid AND reconciler='permit-peer'";
    let mut blocker = owner.begin().await?;
    let tenant = claim.target().scope().tenant().to_string();
    let (epoch, before): (i64, i64) = sqlx::query_as("SELECT epoch,(extract(epoch FROM lease_until)*1000000)::bigint FROM rss_reconcile.targets WHERE tenant_id=$1::uuid AND reconciler='permit-peer' FOR UPDATE")
        .bind(&tenant)
        .fetch_one(&mut *blocker)
        .await?;
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await?;
    let tenant_b = Arc::new(Semaphore::new(1));
    let admitted = store.with_permit(slot(&tenant_b, drops).await?)?;
    let renew = admitted.renew(claim, Duration::from_secs(30), c);
    let observe = async {
        let pid=tokio::time::timeout(Duration::from_secs(2),async {
            loop {
                let pid=sqlx::query_scalar::<_,i32>("SELECT pid FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)) AND usename='reconcile_runtime'")
                    .bind(blocker_pid).fetch_optional(owner).await?;
                if let Some(pid)=pid { return Ok::<_, sqlx::Error>(pid); }
                tokio::task::yield_now().await;
            }
        }).await??;
        blocker.rollback().await?;
        Ok::<_, anyhow::Error>(pid)
    };
    let (pid, ()) = tokio::try_join!(observe, async { Ok(renew.await?) })?;
    let (new_epoch, after): (i64, i64) =
        sqlx::query_as(STATE).bind(&tenant).fetch_one(owner).await?;
    assert_eq!((epoch, new_epoch), (claim.epoch(), claim.epoch()));
    assert!(after > before);
    Ok(pid)
}
async fn failures(
    store: &PgStore,
    pool: &PgPool,
    scope: &Scope,
    c: &Control<'_, Clock>,
    tenant: &Arc<Semaphore>,
    drops: &Arc<AtomicUsize>,
) -> anyhow::Result<()> {
    let first = pool.acquire().await?;
    let second = pool.acquire().await?;
    let result = store
        .with_permit(slot(tenant, drops).await?)?
        .local_tx(scope, c, |tx| Box::pin(pid(tx)))
        .await;
    assert!(matches!(result, Err(e) if e.kind()==ErrorKind::Transient));
    assert_eq!(tenant.available_permits(), 1);
    drop((first, second));
    settlement_faults(store, scope, c, tenant, drops).await
}

async fn settlement_faults(
    store: &PgStore,
    scope: &Scope,
    c: &Control<'_, Clock>,
    tenant: &Arc<Semaphore>,
    drops: &Arc<AtomicUsize>,
) -> anyhow::Result<()> {
    store.inject_next_fault(PgFault::CommitUnknownAfterAck);
    let result = store
        .with_permit(slot(tenant, drops).await?)?
        .local_tx(scope, c, |tx| Box::pin(pid(tx)))
        .await;
    assert!(matches!(result,Err(e) if e.kind()==ErrorKind::CommitUnknown));
    store.inject_next_fault(PgFault::RollbackFailedAfterAck);
    let result: Result<(), _> = store
        .with_permit(slot(tenant, drops).await?)?
        .local_tx(scope, c, |_| {
            Box::pin(async { Err(PgOperationError::rejected()) })
        })
        .await;
    assert!(matches!(result,Err(e) if e.kind()==ErrorKind::RollbackFailed));
    Ok(())
}

async fn cancellation_and_drain(
    store: &PgStore,
    scope: &Scope,
    c: &Control<'_, Clock>,
    tenant: &Arc<Semaphore>,
    drops: &Arc<AtomicUsize>,
) -> anyhow::Result<()> {
    let started = CancellationToken::new();
    let stop = CancellationToken::new();
    let clock = Clock::new();
    let cancelled = Control::new(&clock, Duration::from_secs(10), &stop);
    let work = store
        .with_permit(slot(tenant, drops).await?)?
        .local_tx(scope, &cancelled, |_| {
            Box::pin({
                let started = started.clone();
                async move {
                    started.cancel();
                    std::future::pending::<Result<(), PgOperationError>>().await
                }
            })
        });
    let (result, ()) = tokio::join!(work, async {
        started.cancelled().await;
        stop.cancel();
    });
    assert!(matches!(result,Err(e) if e.kind()==ErrorKind::CommitUnknown));
    let waiting = store.with_permit(slot(tenant, drops).await?)?;
    let short = c.child(Duration::from_millis(50));
    assert_eq!(store.close(&short).await, CloseOutcome::Deadline);
    drop(waiting);
    Ok(())
}
