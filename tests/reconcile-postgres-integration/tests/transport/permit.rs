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
        .acquire_timeout(Duration::from_millis(600))
        .connect_with(options)
        .await?;
    let store = PgStore::new(pool.clone(), c).await?;
    // The test trigger identifies the actual renewing backend and its durable lease change.
    sqlx::raw_sql("CREATE TABLE public.peer_renew(pid int,epoch bigint,extended boolean); CREATE FUNCTION public.capture_renew() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN INSERT INTO public.peer_renew VALUES(pg_backend_pid(),NEW.epoch,NEW.lease_until>OLD.lease_until); RETURN NULL; END $$; CREATE TRIGGER capture_renew AFTER UPDATE OF lease_until ON rss_reconcile.targets FOR EACH ROW WHEN (NEW.reconciler='permit-peer' AND OLD.token=NEW.token) EXECUTE FUNCTION public.capture_renew()").execute(&db.owner).await?;
    let a = target("permit-a", TENANT)?;
    let b = target("permit-peer", OTHER)?;
    store
        .wake(&b, &ResourceSet::empty(b.scope().tenant()), c)
        .await?;
    let claim = claim(&store, &b, Duration::from_secs(10), c).await?;
    let tenant_a = Arc::new(Semaphore::new(1));
    let tenant_b = Arc::new(Semaphore::new(1));
    let drops = Arc::new(AtomicUsize::new(0));
    proxy.arm.store(HOLD_RETURN, Ordering::SeqCst);
    let a1 = store
        .with_permit(slot(&tenant_a, &drops).await?)?
        .local_tx(a.scope(), c, |tx| Box::pin(pid(tx)))
        .await?;
    tokio::time::timeout(Duration::from_secs(2), proxy.gate.held.cancelled()).await?;
    let mut a2 = Box::pin(slot(&tenant_a, &drops));
    assert!(futures::poll!(&mut a2).is_pending());
    store
        .with_permit(slot(&tenant_b, &drops).await?)?
        .renew(&claim, Duration::from_secs(30), c)
        .await?;
    let (peer_pid, epoch, extended): (i32, i64, bool) =
        sqlx::query_as("SELECT pid,epoch,extended FROM public.peer_renew")
            .fetch_one(&db.owner)
            .await?;
    assert_ne!(a1, peer_pid);
    assert_eq!((epoch, extended), (claim.epoch(), true));
    assert!(futures::poll!(&mut a2).is_pending());
    proxy.gate.release.cancel();
    let permit = tokio::time::timeout(Duration::from_secs(2), a2).await??;
    store
        .with_permit(permit)?
        .local_tx(a.scope(), c, |tx| Box::pin(pid(tx)))
        .await?;
    failures(&store, &pool, a.scope(), c, &tenant_a, &drops).await?;
    assert_eq!(store.close(c).await, CloseOutcome::Drained);
    assert_eq!(drops.load(Ordering::SeqCst), 8);
    assert_eq!(
        (tenant_a.available_permits(), tenant_b.available_permits()),
        (1, 1)
    );
    Ok(())
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
