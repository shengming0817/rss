use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Failing(AtomicUsize);
impl Reconciler<PgClaim> for Failing {
    type State = ();
    async fn observe<T: Timer>(
        &self,
        _: &PgClaim,
        _: &Control<'_, T>,
    ) -> Result<ReconcileDiff<()>, Error> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(Error::new(ErrorKind::Transient))
    }
    async fn apply<T: Timer>(
        &self,
        _: &PgClaim,
        _: ReconcileDiff<()>,
        _: &Control<'_, T>,
    ) -> Result<(), Error> {
        Err(Error::new(ErrorKind::Invariant))
    }
}

async fn snapshot(owner: &PgPool) -> anyhow::Result<Vec<(String, i64, i64)>> {
    Ok(sqlx::query_as("SELECT next_run::text,failures,epoch FROM rss_reconcile.targets WHERE reconciler='capped-retry' ORDER BY entity")
        .fetch_all(owner).await?)
}

pub(super) async fn run(
    store: &PgStore,
    pool: &PgPool,
    owner: &PgPool,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let scope = Scope::new(TenantId::parse(TENANT)?, "capped-retry")?;
    for entity in ["first", "second"] {
        store.wake(&Target::new(scope.clone(), entity)?, c).await?;
    }
    for claim in store
        .claim_due(&scope, 2, Duration::from_secs(1), c)
        .await?
    {
        store
            .finish(
                &claim,
                Completion::Retry {
                    after: Duration::from_millis(1),
                    failures: 5,
                },
                c,
            )
            .await?;
    }
    let policy = Policy::try_from(PolicyConfig {
        concurrency: 2,
        lease_ttl: Duration::from_secs(2),
        attempt_timeout: Duration::from_secs(2),
        scan_interval: Duration::from_millis(5),
        idle_scan_interval: Duration::from_millis(10),
        initial_backoff: Duration::from_secs(5),
        max_backoff: Duration::from_secs(60),
        max_attempts: 100,
    })?;
    let business = Failing(AtomicUsize::new(0));
    let stop = CancellationToken::new();
    let mut finished = 0;
    let report = rss_reconcile::run(store, &business, &scope, policy, c, &stop, |event| {
        if matches!(event, Observation::AttemptFailed { .. }) {
            finished += 1;
            if finished == 2 {
                stop.cancel();
            }
        }
    })
    .await?;
    assert_eq!(report.retried, 2);
    let before = snapshot(owner).await?;
    assert_eq!(before.len(), 2);
    assert!(
        before
            .iter()
            .all(|(_, failures, epoch)| *failures == 6 && *epoch == 2)
    );
    // T1 proves the delay spread. Different PG commit timestamps alone do not prove jitter.
    let restarted = PgStore::new(pool.clone(), c).await?;
    let stop = CancellationToken::new();
    let notify = tokio::sync::Notify::new();
    let notify_early = async {
        for _ in 0..5 {
            notify.notify_one();
            c.sleep(Duration::from_millis(10)).await;
        }
        stop.cancel();
    };
    let (report, ()) = tokio::join!(
        rss_reconcile::run_with_notify(
            &restarted,
            &business,
            &scope,
            policy,
            c,
            &stop,
            &notify,
            |_| {}
        ),
        notify_early
    );
    assert_eq!(report?.retried, 0);
    assert_eq!(business.0.load(Ordering::SeqCst), 2);
    assert!(
        restarted
            .claim_due(&scope, 2, Duration::from_secs(1), c)
            .await?
            .is_empty()
    );
    let still_future: bool = sqlx::query_scalar("SELECT bool_and(next_run>clock_timestamp()) FROM rss_reconcile.targets WHERE reconciler='capped-retry'")
        .fetch_one(owner).await?;
    assert!(
        still_future,
        "fixture must finish before the persisted retry deadline"
    );
    assert_eq!(snapshot(owner).await?, before);
    Ok(())
}
