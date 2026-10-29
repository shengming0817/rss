use super::*;

fn scope(name: &str) -> anyhow::Result<Scope> {
    Ok(Scope::new(TenantId::parse(TENANT)?, name)?)
}
async fn wake(
    store: &PgStore,
    scope: &Scope,
    entity: &str,
    keys: &[&str],
    c: &Control<'_, Clock>,
) -> anyhow::Result<Target> {
    let target = Target::new(scope.clone(), entity)?;
    store
        .wake(
            &target,
            &ResourceSet::new(scope.tenant(), keys.iter().copied())?,
            c,
        )
        .await?;
    Ok(target)
}
async fn owners(owner: &PgPool, key: &str) -> anyhow::Result<i64> {
    Ok(sqlx::query_scalar("SELECT count(*) FROM rss_reconcile.resources WHERE resource=$1 AND owner_token IS NOT NULL").bind(key).fetch_one(owner).await?)
}
async fn blocked(store: &PgStore, scope: &Scope, c: &Control<'_, Clock>) -> anyhow::Result<()> {
    assert!(
        store
            .claim_due(scope, 2, Duration::from_secs(2), c)
            .await?
            .claims
            .is_empty()
    );
    Ok(())
}
pub(super) async fn run(
    store: &PgStore,
    pool: &PgPool,
    owner: &PgPool,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    parallel_effects(store, owner, c).await?;
    fairness(store, owner, c).await?;
    rebinding(store, owner, c).await?;
    bounded_pages(store, c).await?;
    uncertainty(store, owner, c).await?;
    isolation_and_admission(store, pool, owner, c).await
}
async fn fairness(store: &PgStore, owner: &PgPool, c: &Control<'_, Clock>) -> anyhow::Result<()> {
    let holder = wake(store, &scope("fair-holder")?, "holder", &["fair:b"], c).await?;
    let held = claim(store, &holder, Duration::from_secs(5), c).await?;
    let old = wake(store, &scope("fair-old")?, "old", &["fair:a", "fair:b"], c).await?;
    blocked(store, old.scope(), c).await?; // durable queue head despite B being busy
    let young_scope = scope("fair-young")?;
    let young = wake(store, &young_scope, "young", &["fair:a"], c).await?;
    let separate = wake(store, &young_scope, "separate", &["fair:c"], c).await?;
    let batch = store
        .claim_due(&young_scope, 2, Duration::from_secs(5), c)
        .await?;
    assert_eq!(batch.claims.len(), 1);
    assert_eq!(batch.claims[0].target().entity(), separate.entity());
    store
        .finish(&batch.claims[0], Completion::Converged, c)
        .await?;
    for n in 0..3 {
        wake(store, &young_scope, &format!("new-{n}"), &["fair:a"], c).await?;
    }
    blocked(store, &young_scope, c).await?;
    store.release(&held, c).await?;
    let old_claim = claim(store, &old, Duration::from_secs(5), c).await?;
    assert_eq!(owners(owner, "fair:a").await?, 1);
    assert_eq!(owners(owner, "fair:b").await?, 1);
    blocked(store, &young_scope, c).await?;
    store
        .finish(&old_claim, Completion::Deferred(Duration::from_secs(30)), c)
        .await?;
    let next = claim(store, &young, Duration::from_secs(5), c).await?;
    assert_eq!(next.target().entity(), young.entity()); // future old task cannot block A
    store.finish(&next, Completion::Converged, c).await?;
    Ok(())
}
async fn rebinding(store: &PgStore, owner: &PgPool, c: &Control<'_, Clock>) -> anyhow::Result<()> {
    let t = wake(store, &scope("rebind")?, "work", &["rebind:a"], c).await?;
    let old = claim(store, &t, Duration::from_secs(5), c).await?;
    let replacement = ResourceSet::new(t.scope().tenant(), ["rebind:b"])?;
    let result: ReconcileStep<()> = store
        .protect(&old, c, replacement.clone(), |resources, _| {
            Box::pin(async move {
                Ok(ProtectedStep::Rebind(
                    resources.clone(),
                    Duration::from_millis(1),
                ))
            })
        })
        .await?;
    assert!(matches!(result, ReconcileStep::Deferred(_)));
    assert_eq!(
        owners(owner, "rebind:a").await?,
        1,
        "rebind does not release the old claim early"
    );
    let rejected = store
        .protect(&old, c, (), |_, tx| {
            Box::pin(async {
                effect(tx, "stale-rebind".into()).await?;
                Ok(ProtectedStep::Ready(()))
            })
        })
        .await;
    assert!(matches!(rejected, Err(e) if e.kind()==ErrorKind::BindingChanged));
    assert_eq!(count(owner, "stale-rebind").await?, 0);
    assert!(
        matches!(store.renew(&old, Duration::from_secs(5), c).await, Err(e) if e.kind()==ErrorKind::BindingChanged)
    );
    store
        .finish(&old, Completion::Deferred(Duration::from_millis(1)), c)
        .await?;
    assert_eq!(owners(owner, "rebind:a").await?, 0);
    c.sleep(Duration::from_millis(2)).await;
    let new = claim(store, &t, Duration::from_secs(5), c).await?;
    assert_eq!(owners(owner, "rebind:b").await?, 1);
    assert!(matches!(store.release(&old, c).await, Err(e) if e.kind()==ErrorKind::Fenced));
    assert_eq!(owners(owner, "rebind:b").await?, 1);
    store
        .finish(
            &new,
            Completion::Retry {
                after: Duration::from_secs(30),
                failures: 7,
            },
            c,
        )
        .await?;
    let before: (String,i64,i64) = sqlx::query_as("SELECT next_run::text,failures,wake_version FROM rss_reconcile.targets WHERE reconciler='rebind'").fetch_one(owner).await?;
    store
        .bind_resources(&t, &ResourceSet::new(t.scope().tenant(), ["rebind:c"])?, c)
        .await?;
    let after: (String,i64,i64) = sqlx::query_as("SELECT next_run::text,failures,wake_version FROM rss_reconcile.targets WHERE reconciler='rebind'").fetch_one(owner).await?;
    assert_eq!(before, after);
    blocked(store, t.scope(), c).await
}
async fn bounded_pages(store: &PgStore, c: &Control<'_, Clock>) -> anyhow::Result<()> {
    let held_target = wake(store, &scope("page-holder")?, "held", &["page:hot"], c).await?;
    let held = claim(store, &held_target, Duration::from_secs(10), c).await?;
    let queued = scope("page-queue")?;
    for n in 0..66 {
        wake(store, &queued, &format!("hot-{n}"), &["page:hot"], c).await?;
    }
    let free = wake(store, &queued, "free", &["page:free"], c).await?;
    let first = store
        .claim_due(&queued, 2, Duration::from_secs(3), c)
        .await?;
    assert!(first.claims.is_empty() && first.more);
    let second = store
        .claim_due(&queued, 2, Duration::from_secs(3), c)
        .await?;
    assert_eq!(second.claims.len(), 1);
    assert_eq!(second.claims[0].target().entity(), free.entity());
    store
        .finish(&second.claims[0], Completion::Converged, c)
        .await?;
    let work = wake(store, &queued, "free-runner", &["page:other"], c).await?;
    let stop = CancellationToken::new();
    let observer = StopOnObserve(&stop);
    let policy = Policy::try_from(PolicyConfig {
        concurrency: 2,
        lease_ttl: Duration::from_secs(2),
        attempt_timeout: Duration::from_secs(1),
        scan_interval: Duration::from_millis(5),
        idle_scan_interval: Duration::from_secs(30),
        initial_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(5),
        max_attempts: 2,
    })?;
    let bounded = c.child(Duration::from_secs(1));
    let report = rss_reconcile::run(
        store,
        &observer,
        work.scope(),
        policy,
        &bounded,
        &stop,
        |_| {},
    )
    .await?;
    assert_eq!(
        report.converged, 1,
        "runner must continue the scan before its 30s idle timer"
    );
    store.release(&held, c).await?;
    Ok(())
}
struct StopOnObserve<'a>(&'a CancellationToken);
impl Reconciler<PgClaim> for StopOnObserve<'_> {
    type State = ();
    async fn observe<T: Timer>(
        &self,
        claim: &PgClaim,
        _: &Control<'_, T>,
    ) -> Result<ReconcileStep<ReconcileDiff<()>>, Error> {
        assert_eq!(claim.target().entity(), "free-runner");
        self.0.cancel();
        Ok(ReconcileStep::Ready(ReconcileDiff::between(
            DesiredState::present(()),
            ActualState::present(()),
        )))
    }
    async fn apply<T: Timer>(
        &self,
        _: &PgClaim,
        _: ReconcileDiff<()>,
        _: &Control<'_, T>,
    ) -> Result<ReconcileStep<()>, Error> {
        Err(Error::new(ErrorKind::Invariant))
    }
}
async fn uncertainty(
    store: &PgStore,
    owner: &PgPool,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let first = wake(
        store,
        &scope("resource-unknown")?,
        "first",
        &["unknown:shared"],
        c,
    )
    .await?;
    let other = wake(
        store,
        &scope("resource-recover")?,
        "other",
        &["unknown:shared"],
        c,
    )
    .await?;
    store.inject_next_fault(PgFault::CommitUnknownAfterAck);
    assert!(
        matches!(store.claim_due(first.scope(), 1, Duration::from_millis(100), c).await, Err(e) if e.kind()==ErrorKind::CommitUnknown)
    );
    assert_eq!(owners(owner, "unknown:shared").await?, 1);
    blocked(store, other.scope(), c).await?;
    c.sleep(Duration::from_millis(110)).await;
    let recovered = claim(store, &other, Duration::from_secs(2), c).await?;
    store.inject_next_fault(PgFault::RollbackFailedAfterAck);
    let rollback: Result<ReconcileStep<()>, Error> = store
        .protect(&recovered, c, (), |_, _| {
            Box::pin(async {
                Err(PgOperationError::unavailable(std::io::Error::other(
                    "rollback probe",
                )))
            })
        })
        .await;
    assert!(matches!(rollback,Err(e) if e.kind()==ErrorKind::RollbackFailed));
    assert_eq!(owners(owner, "unknown:shared").await?, 1);
    store.inject_next_fault(PgFault::CommitUnknownAfterAck);
    assert!(
        matches!(store.finish(&recovered,Completion::Converged,c).await,Err(e) if e.kind()==ErrorKind::CommitUnknown)
    );
    assert_eq!(owners(owner, "unknown:shared").await?, 0);
    Ok(())
}
async fn isolation_and_admission(
    store: &PgStore,
    pool: &PgPool,
    owner: &PgPool,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let a = wake(
        store,
        &scope("resource-isolation")?,
        "a",
        &["tenant:shared"],
        c,
    )
    .await?;
    let other_scope = Scope::new(TenantId::parse(OTHER)?, "resource-isolation")?;
    let b = wake(store, &other_scope, "b", &["tenant:shared"], c).await?;
    let ca = claim(store, &a, Duration::from_secs(3), c).await?;
    let cb = claim(store, &b, Duration::from_secs(3), c).await?;
    assert!(
        matches!(store.bind_resources(&a,&ResourceSet::empty(other_scope.tenant()),c).await,Err(e) if e.kind()==ErrorKind::InvalidInput)
    );
    store.finish(&ca, Completion::Converged, c).await?;
    store.finish(&cb, Completion::Converged, c).await?;
    for table in ["resources", "target_resources", "scans"] {
        // Static fixture table names; this deliberately violates the runtime boundary.
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "GRANT UPDATE ON rss_reconcile.{table} TO reconcile_runtime"
        )))
        .execute(owner)
        .await?;
        let result = PgStore::new(pool.clone(), c).await;
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "REVOKE UPDATE ON rss_reconcile.{table} FROM reconcile_runtime"
        )))
        .execute(owner)
        .await?;
        assert!(matches!(result,Err(e) if e.kind()==ErrorKind::StorageContract));
    }
    Ok(())
}

async fn parallel_effects(
    store: &PgStore,
    owner: &PgPool,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let scope = scope("resource-parallel")?;
    wake(store, &scope, "a", &["parallel:a"], c).await?;
    wake(store, &scope, "b", &["parallel:b"], c).await?;
    let claims = store
        .claim_due(&scope, 2, Duration::from_secs(5), c)
        .await?
        .claims;
    assert_eq!(claims.len(), 2);
    let barrier = tokio::sync::Barrier::new(2);
    let a = store.protect(&claims[0], c, &barrier, |barrier, tx| {
        Box::pin(async move {
            barrier.wait().await;
            effect(tx, "parallel-a".into()).await?;
            Ok(ProtectedStep::Ready(()))
        })
    });
    let b = store.protect(&claims[1], c, &barrier, |barrier, tx| {
        Box::pin(async move {
            barrier.wait().await;
            effect(tx, "parallel-b".into()).await?;
            Ok(ProtectedStep::Ready(()))
        })
    });
    let (a, b) = tokio::join!(a, b);
    assert!(matches!(a?, ReconcileStep::Ready(())) && matches!(b?, ReconcileStep::Ready(())));
    assert_eq!(count(owner, "parallel-a").await?, 1);
    assert_eq!(count(owner, "parallel-b").await?, 1);
    for claim in &claims {
        store.finish(claim, Completion::Converged, c).await?;
    }
    Ok(())
}
