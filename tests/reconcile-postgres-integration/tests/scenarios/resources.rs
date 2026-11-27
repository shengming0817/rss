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
            .claim_due(scope, 2, 64, Duration::from_secs(2), c)
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
    expired_transaction_keeps_conflicting_resources_locked(store, owner, c).await?;
    fairness(store, owner, c).await?;
    partial_resource_lock(store, pool, owner, c).await?;
    rebinding(store, owner, c).await?;
    bounded_pages(store, c).await?;
    for budget in [1, 2] {
        blocked_ticket_probe(store, owner, c, budget).await?;
    }
    uncertainty(store, owner, c).await?;
    isolation_and_admission(store, pool, owner, c).await?;
    expanded_capacity(store, owner, c).await
}
async fn fairness(store: &PgStore, owner: &PgPool, c: &Control<'_, Clock>) -> anyhow::Result<()> {
    let holder = wake(store, &scope("fair-holder")?, "holder", &["fair:b"], c).await?;
    let held = claim(store, &holder, Duration::from_secs(60), c).await?;
    let old = wake(store, &scope("fair-old")?, "old", &["fair:a", "fair:b"], c).await?;
    stable_waiter(store, owner, &old, c).await?;
    let young = queued_young(store, owner, c).await?;
    store.release(&held, c).await?;
    finish_fair_turn(store, owner, c, old, young).await
}
async fn stable_waiter(
    store: &PgStore,
    owner: &PgPool,
    old: &Target,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    blocked(store, old.scope(), c).await?; // durable queue head despite B being busy
    let tickets = declarations(owner, old).await?;
    assert_eq!(tickets.len(), 2);
    let queue_ticket: i64 = sqlx::query_scalar("SELECT queue_ticket FROM rss_reconcile.targets WHERE tenant_id=$1::uuid AND reconciler=$2 AND entity=$3")
        .bind(TENANT).bind(old.scope().reconciler()).bind(old.entity()).fetch_one(owner).await?;
    assert!(
        tickets
            .iter()
            .all(|(_, ticket, _, _)| *ticket == Some(queue_ticket))
    );
    for _ in 0..10 {
        blocked(store, old.scope(), c).await?;
        assert_eq!(declarations(owner, old).await?, tickets);
    }
    Ok(())
}
type Declaration = (String, Option<i64>, String, String);
async fn declarations(owner: &PgPool, target: &Target) -> anyhow::Result<Vec<Declaration>> {
    Ok(sqlx::query_as("SELECT resource,waiting_ticket,ctid::text,xmin::text FROM rss_reconcile.target_resources WHERE tenant_id=$1::uuid AND reconciler=$2 AND entity=$3 ORDER BY resource")
        .bind(target.scope().tenant().to_string()).bind(target.scope().reconciler()).bind(target.entity()).fetch_all(owner).await?)
}

async fn queued_young(
    store: &PgStore,
    owner: &PgPool,
    c: &Control<'_, Clock>,
) -> anyhow::Result<Target> {
    let young_scope = scope("fair-young")?;
    // With two future tickets in front, the first two attempts come from the
    // truncated due sample. The registered old waiter is in a different scope.
    for entity in ["future-1", "future-2"] {
        wake(store, &young_scope, entity, &[], c).await?;
    }
    sqlx::query("UPDATE rss_reconcile.targets SET next_run=now()+interval '1 hour' WHERE tenant_id=$1::uuid AND reconciler=$2 AND entity LIKE 'future-%'").bind(TENANT).bind(young_scope.reconciler()).execute(owner).await?;
    let young = wake(store, &young_scope, "young", &["fair:a"], c).await?;
    let separate = wake(store, &young_scope, "separate", &["fair:c"], c).await?;
    for n in 0..3 {
        wake(store, &young_scope, &format!("new-{n}"), &["fair:a"], c).await?;
    }
    claim_uncontended(store, owner, &separate, c).await?;
    assert!(declarations(owner, &young).await?[0].1.is_some());
    blocked(store, &young_scope, c).await?;
    Ok(young)
}
async fn claim_uncontended(
    store: &PgStore,
    owner: &PgPool,
    separate: &Target,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let fresh = declarations(owner, separate).await?;
    assert_eq!(fresh.len(), 1);
    assert!(fresh[0].1.is_none());
    let batch = store
        .claim_due(separate.scope(), 2, 2, Duration::from_secs(5), c)
        .await?;
    assert_eq!(batch.claims.len(), 1);
    assert_eq!(batch.claims[0].target().entity(), separate.entity());
    assert_eq!(declarations(owner, separate).await?, fresh);
    store
        .finish(&batch.claims[0], Completion::Converged, c)
        .await?;
    assert_eq!(declarations(owner, separate).await?, fresh);
    Ok(())
}
async fn finish_fair_turn(
    store: &PgStore,
    owner: &PgPool,
    c: &Control<'_, Clock>,
    old: Target,
    young: Target,
) -> anyhow::Result<()> {
    let old_claim = claim(store, &old, Duration::from_secs(5), c).await?;
    assert_eq!(owners(owner, "fair:a").await?, 1);
    assert_eq!(owners(owner, "fair:b").await?, 1);
    blocked(store, young.scope(), c).await?;
    store
        .finish(&old_claim, Completion::Deferred(Duration::from_secs(30)), c)
        .await?;
    let next = claim(store, &young, Duration::from_secs(5), c).await?;
    assert_eq!(next.target().entity(), young.entity()); // future old task cannot block A
    store.finish(&next, Completion::Converged, c).await?;
    Ok(())
}
async fn blocked_ticket_probe(
    store: &PgStore,
    owner: &PgPool,
    c: &Control<'_, Clock>,
    budget: u32,
) -> anyhow::Result<()> {
    let queued = scope(&format!("wait-probe-{budget}"))?;
    let a = format!("probe:{budget}:a");
    let b = format!("probe:{budget}:b");
    let holder = wake(
        store,
        &scope(&format!("probe-holder-{budget}"))?,
        "holder",
        &[&b],
        c,
    )
    .await?;
    let lease = Duration::from_secs(60);
    let held = claim(store, &holder, lease, c).await?;
    assert_eq!(held.target(), &holder);
    let old = wake(store, &queued, "old", &[&a, &b], c).await?;
    let skipped = wake(store, &queued, "skipped", &[&b], c).await?;
    let free = wake(store, &queued, "free", &[], c).await?;
    wake(store, &queued, "young", &[&a], c).await?;
    wake(store, &queued, "last", &[&b], c).await?;
    sqlx::query("UPDATE rss_reconcile.targets SET next_run=now()-interval '1 hour' WHERE reconciler=$1 AND entity IN ('free','young','last')")
        .bind(queued.reconciler()).execute(owner).await?;
    check_probe_page(store, owner, c, budget, [&old, &skipped, &free]).await?;
    // A committed wake behind the cursor keeps the elder's position across release.
    let keys = ResourceSet::new(queued.tenant(), [&a[..], &b[..]])?;
    tokio::try_join!(store.wake(&old, &keys, c), store.release(&held, c))?;
    claim_released_elder(store, c, budget, &old, &free).await
}

async fn check_probe_page(
    store: &PgStore,
    owner: &PgPool,
    c: &Control<'_, Clock>,
    budget: u32,
    [old, skipped, free]: [&Target; 3],
) -> anyhow::Result<()> {
    let page = store
        .claim_due(old.scope(), 1, budget, Duration::from_secs(60), c)
        .await?;
    assert!(page.more);
    assert_eq!(page.claims.len(), (budget - 1) as usize);
    if let Some(granted) = page.claims.first() {
        assert_eq!(granted.target(), free);
        store.finish(granted, Completion::Converged, c).await?;
    }
    let cursor: i64 = sqlx::query_scalar(
        "SELECT cursor_ticket FROM rss_reconcile.scans WHERE tenant_id=$1::uuid AND reconciler=$2",
    )
    .bind(TENANT)
    .bind(old.scope().reconciler())
    .fetch_one(owner)
    .await?;
    let tickets = declarations(owner, old).await?;
    assert_eq!(tickets.len(), 2);
    assert!(tickets.iter().all(|entry| entry.1 == Some(cursor)));
    assert!(declarations(owner, skipped).await?[0].1.is_none());
    Ok(())
}

async fn claim_released_elder(
    store: &PgStore,
    c: &Control<'_, Clock>,
    budget: u32,
    old: &Target,
    free: &Target,
) -> anyhow::Result<()> {
    for _ in 0..8 {
        let page = store
            .claim_due(old.scope(), 1, budget, Duration::from_secs(60), c)
            .await?;
        if let Some(granted) = page.claims.first() {
            store.finish(granted, Completion::Converged, c).await?;
            if granted.target() == old {
                return Ok(());
            }
            assert_eq!(granted.target(), free);
        }
    }
    anyhow::bail!("old waiter did not recover after release")
}
async fn partial_resource_lock(
    store: &PgStore,
    pool: &PgPool,
    owner: &PgPool,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let scope = scope("partial-lock")?;
    let old = wake(store, &scope, "old", &["partial:a", "partial:z"], c).await?;
    let free = wake(store, &scope, "free", &["partial:independent"], c).await?;
    verify_partial_rollback(pool, owner, &free).await?;
    let fresh = claim(store, &old, Duration::from_secs(10), c).await?;
    assert_eq!(fresh.target(), &old);
    store.finish(&fresh, Completion::Converged, c).await?;
    reject_missing_resource(owner, &old).await
}
async fn verify_partial_rollback(
    pool: &PgPool,
    owner: &PgPool,
    free: &Target,
) -> anyhow::Result<()> {
    let mut blocker = owner.begin().await?;
    let lock = "SELECT 1 FROM rss_reconcile.resources WHERE tenant_id=$1::uuid AND resource=$2 FOR UPDATE NOWAIT";
    sqlx::query(lock)
        .bind(TENANT)
        .bind("partial:z")
        .fetch_one(&mut *blocker)
        .await?;

    // Keep the outer claim transaction alive so its COMMIT cannot release the first lock.
    let mut scan = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(TENANT)
        .execute(&mut *scan)
        .await?;
    let granted: Vec<String> = sqlx::query_scalar("SELECT c.entity FROM rss_reconcile.claim_due($1::uuid,$2,2,16,60000) b CROSS JOIN LATERAL unnest(b.claims) c")
        .bind(TENANT).bind(free.scope().reconciler()).fetch_all(&mut *scan).await?;
    assert_eq!(granted, [free.entity()]);
    sqlx::query(lock)
        .bind(TENANT)
        .bind("partial:a")
        .fetch_one(&mut *blocker)
        .await?;
    scan.rollback().await?;
    blocker.rollback().await?;
    Ok(())
}
async fn reject_missing_resource(owner: &PgPool, target: &Target) -> anyhow::Result<()> {
    for nonblocking in [false, true] {
        let error = sqlx::query(
            "SELECT rss_reconcile.lock_resources($1::uuid,$2,$3,ARRAY['partial:absent'],$4)",
        )
        .bind(TENANT)
        .bind(target.scope().reconciler())
        .bind(target.entity())
        .bind(nonblocking)
        .execute(owner)
        .await
        .err()
        .ok_or_else(|| anyhow::anyhow!("missing resource was accepted"))?;
        assert_eq!(
            error.as_database_error().and_then(|e| e.code()).as_deref(),
            Some("P1005")
        );
    }
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
    reject_old_binding(store, owner, c, &old).await?;
    release_and_reacquire(store, owner, c, t, old).await
}
async fn reject_old_binding(
    store: &PgStore,
    owner: &PgPool,
    c: &Control<'_, Clock>,
    old: &PgClaim,
) -> anyhow::Result<()> {
    let rejected = store
        .protect(old, c, (), |_, tx| {
            Box::pin(async {
                effect(tx, "stale-rebind".into()).await?;
                Ok(ProtectedStep::Ready(()))
            })
        })
        .await;
    assert!(matches!(rejected, Err(e) if e.kind()==ErrorKind::BindingChanged));
    assert_eq!(count(owner, "stale-rebind").await?, 0);
    assert!(
        matches!(store.renew(old, Duration::from_secs(5), c).await, Err(e) if e.kind()==ErrorKind::BindingChanged)
    );
    Ok(())
}
async fn release_and_reacquire(
    store: &PgStore,
    owner: &PgPool,
    c: &Control<'_, Clock>,
    t: Target,
    old: PgClaim,
) -> anyhow::Result<()> {
    store
        .finish(&old, Completion::Deferred(Duration::from_millis(1)), c)
        .await?;
    assert_eq!(owners(owner, "rebind:a").await?, 0);
    c.sleep(Duration::from_millis(2)).await;
    let new = claim(store, &t, Duration::from_secs(5), c).await?;
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
    preserve_schedule_binding(store, owner, c, &t).await
}
async fn preserve_schedule_binding(
    store: &PgStore,
    owner: &PgPool,
    c: &Control<'_, Clock>,
    t: &Target,
) -> anyhow::Result<()> {
    let before: (String,i64,i64) = sqlx::query_as("SELECT next_run::text,failures,wake_version FROM rss_reconcile.targets WHERE reconciler='rebind'").fetch_one(owner).await?;
    store
        .bind_resources(t, &ResourceSet::new(t.scope().tenant(), ["rebind:c"])?, c)
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
        .claim_due(&queued, 2, 64, Duration::from_secs(3), c)
        .await?;
    assert!(first.claims.is_empty() && first.more);
    let second = store
        .claim_due(&queued, 2, 64, Duration::from_secs(3), c)
        .await?;
    assert_eq!(second.claims.len(), 1);
    assert_eq!(second.claims[0].target().entity(), free.entity());
    store
        .finish(&second.claims[0], Completion::Converged, c)
        .await?;
    runner_continues_page(store, c, &queued).await?;
    store.release(&held, c).await?;
    Ok(())
}
async fn runner_continues_page(
    store: &PgStore,
    c: &Control<'_, Clock>,
    queued: &Scope,
) -> anyhow::Result<()> {
    let work = wake(store, queued, "free-runner", &["page:other"], c).await?;
    let stop = CancellationToken::new();
    let observer = StopOnObserve(&stop);
    let policy = Policy::try_from(PolicyConfig {
        claim_batch_size: 64,
        scan_budget: 64,
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
        matches!(store.claim_due(first.scope(), 1, 64, Duration::from_millis(100), c).await, Err(e) if e.kind()==ErrorKind::CommitUnknown)
    );
    assert_eq!(owners(owner, "unknown:shared").await?, 1);
    blocked(store, other.scope(), c).await?;
    c.sleep(Duration::from_millis(110)).await;
    let recovered = claim(store, &other, Duration::from_secs(2), c).await?;
    uncertain_settlement(store, owner, c, &recovered).await
}
async fn uncertain_settlement(
    store: &PgStore,
    owner: &PgPool,
    c: &Control<'_, Clock>,
    recovered: &PgClaim,
) -> anyhow::Result<()> {
    store.inject_next_fault(PgFault::RollbackFailedAfterAck);
    let rollback: Result<ReconcileStep<()>, Error> = store
        .protect(recovered, c, (), |_, _| {
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
        matches!(store.finish(recovered,Completion::Converged,c).await,Err(e) if e.kind()==ErrorKind::CommitUnknown)
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
    resource_admission(pool, owner, c).await
}
async fn resource_admission(
    pool: &PgPool,
    owner: &PgPool,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
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
        .claim_due(&scope, 2, 64, Duration::from_secs(5), c)
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

async fn expired_transaction_keeps_conflicting_resources_locked(
    store: &PgStore,
    owner: &PgPool,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let t = wake(
        store,
        &scope("expired-resource-holder")?,
        "holder",
        &["expired:shared"],
        c,
    )
    .await?;
    let other = wake(
        store,
        &scope("expired-resource-contender")?,
        "contender",
        &["expired:shared"],
        c,
    )
    .await?;
    let held = claim(store, &t, Duration::from_millis(150), c).await?;
    let entered = tokio::sync::Notify::new();
    let resume = tokio::sync::Notify::new();
    let write = store.protect(&held, c, (&entered, &resume), |state, tx| {
        Box::pin(async move {
            effect(tx, "expired-resource-write".into()).await?;
            state.0.notify_one();
            state.1.notified().await;
            Ok(ProtectedStep::Ready(()))
        })
    });
    let contend = async {
        entered.notified().await;
        loop {
            let expired: bool=sqlx::query_scalar("SELECT lease_until<=clock_timestamp() FROM rss_reconcile.targets WHERE reconciler='expired-resource-holder'").fetch_one(owner).await?;
            if expired {
                break;
            }
            c.sleep(Duration::from_millis(5)).await;
        }
        blocked(store, other.scope(), c).await?;
        resume.notify_one();
        Ok::<(), anyhow::Error>(())
    };
    let (write, contend) = tokio::join!(write, contend);
    contend?;
    assert!(matches!(write,Err(e) if e.kind()==ErrorKind::Fenced));
    assert_eq!(count(owner, "expired-resource-write").await?, 0);
    let fresh = claim(store, &other, Duration::from_secs(2), c).await?;
    store.finish(&fresh, Completion::Converged, c).await?;
    Ok(())
}

// Same durable owner and ACL path as the small fairness cases; no extra fixture service.
#[allow(
    clippy::cognitive_complexity,
    reason = "one durable fixture verifies resource admission and bounded scan cursor progression"
)]
async fn expanded_capacity(
    store: &PgStore,
    owner: &PgPool,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let scope = scope(&"r".repeat(255))?;
    let target = Target::new(scope.clone(), "e".repeat(255))?;
    let resources = ResourceSet::new(
        scope.tenant(),
        (0..1024).map(|i| format!("{i:04}{}", "x".repeat(251))),
    )?;
    store.wake(&target, &resources, c).await?;
    let claim = store
        .claim_due(&scope, 1024, 4096, Duration::from_secs(90_000), c)
        .await?
        .claims
        .remove(0);
    store.renew(&claim, Duration::from_secs(90_001), c).await?;
    store
        .finish(
            &claim,
            Completion::Retry {
                after: Duration::from_secs(90_002),
                failures: u32::MAX,
            },
            c,
        )
        .await?;
    let persisted: (i64, i64) = sqlx::query_as("SELECT failures,(SELECT count(*) FROM rss_reconcile.target_resources WHERE reconciler=$1) FROM rss_reconcile.targets WHERE reconciler=$1")
        .bind(scope.reconciler()).fetch_one(owner).await?;
    assert_eq!(persisted, (i64::from(u32::MAX), 1024));
    assert!(
        store
            .claim_due(&scope, 1025, 4096, Duration::from_secs(1), c)
            .await
            .is_err()
    );
    assert!(
        store
            .claim_due(&scope, 1, u32::MAX, Duration::from_secs(1), c)
            .await
            .is_err()
    );
    let queued = Scope::new(scope.tenant(), "expanded-scan")?;
    // Seed through the real definer in one fixture transaction, retaining canonical bindings.
    sqlx::query("SELECT rss_reconcile.wake($1::uuid,$2,'item-'||n,ARRAY[]::text[]) FROM generate_series(1,4096) n")
        .bind(queued.tenant().to_string()).bind(queued.reconciler()).execute(owner).await?;
    sqlx::query("UPDATE rss_reconcile.targets SET next_run=clock_timestamp()+interval '1 day' WHERE reconciler=$1 AND entity<>'item-4096'")
        .bind(queued.reconciler()).execute(owner).await?;
    let page = store
        .claim_due(&queued, 1024, 4096, Duration::from_secs(30), c)
        .await?;
    assert!(!page.more);
    assert_eq!(page.claims.len(), 1);
    assert_eq!(page.claims[0].target().entity(), "item-4096");
    store
        .finish(&page.claims[0], Completion::Converged, c)
        .await?;
    sqlx::query("UPDATE rss_reconcile.targets SET next_run=clock_timestamp() WHERE reconciler=$1 AND next_run IS NOT NULL")
        .bind(queued.reconciler()).execute(owner).await?;
    let page = store
        .claim_due(&queued, 1024, 4096, Duration::from_secs(30), c)
        .await?;
    assert_eq!(page.claims.len(), 1024);
    assert!(page.more);
    Ok(())
}
