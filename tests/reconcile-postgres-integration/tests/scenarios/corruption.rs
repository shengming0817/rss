//! INVARIANT: RECONCILE-STORAGE-CONTRACT-01 — real catalog damage must fail closed.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

pub(super) async fn run(
    store: &PgStore,
    pool: &PgPool,
    owner: &PgPool,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let scope = Scope::new(TenantId::parse(TENANT)?, "corruption")?;
    for entity in ["a-bad", "b-good"] {
        store.wake(&Target::new(scope.clone(), entity)?, c).await?;
    }
    schema_rejects_invalid_rows(owner).await?;
    check_definitions(store, pool, owner, &scope, c).await?;
    catalog_states(store, pool, owner, &scope, c).await?;
    damaged_row(store, pool, owner, &scope, c).await?;
    exhausted_wake(store, owner, c).await?;
    exhausted_epoch(store, owner, c).await
}

async fn snapshot(owner: &PgPool, reconciler: &str) -> anyhow::Result<Vec<String>> {
    Ok(sqlx::query_scalar("SELECT row_to_json(t)::text FROM rss_reconcile.targets t WHERE reconciler=$1 ORDER BY tenant_id,entity")
        .bind(reconciler).fetch_all(owner).await?)
}

async fn schema_rejects_invalid_rows(owner: &PgPool) -> anyhow::Result<()> {
    let before = snapshot(owner, "corruption").await?;
    for assignment in [
        "failures=-1",
        "failures=4294967296",
        "wake_version=0",
        "epoch=-1",
        "entity='invalid entity'",
        "reconciler='invalid scope'",
        "result='unknown'",
        "token=gen_random_uuid()",
        "token=gen_random_uuid(),lease_until=clock_timestamp(),next_run=NULL",
    ] {
        // SQL safety: assignments are static fixture literals, never external input.
        let error = sqlx::query(sqlx::AssertSqlSafe(format!("UPDATE rss_reconcile.targets SET {assignment} WHERE reconciler='corruption' AND entity='a-bad'")))
            .execute(owner).await.err().ok_or_else(|| anyhow::anyhow!("schema accepted {assignment}"))?;
        assert_eq!(
            error.as_database_error().and_then(|e| e.code()).as_deref(),
            Some("23514")
        );
        assert_eq!(snapshot(owner, "corruption").await?, before);
    }
    Ok(())
}

async fn check_definitions(
    store: &PgStore,
    pool: &PgPool,
    owner: &PgPool,
    scope: &Scope,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let definitions: Vec<(String, String)> = sqlx::query_as("SELECT conname::text,pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='rss_reconcile.targets'::regclass AND contype='c' ORDER BY conname")
        .fetch_all(owner).await?;
    assert_eq!(definitions.len(), 8);
    let before = snapshot(owner, scope.reconciler()).await?;
    for (name, definition) in definitions {
        // SQL safety: identifier is quoted; definition comes from this fixture's migrated catalog.
        let quoted = name.replace('"', "\"\"");
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("ALTER TABLE rss_reconcile.targets DROP CONSTRAINT \"{quoted}\", ADD CONSTRAINT \"{quoted}\" CHECK(true)")))
            .execute(owner).await?;
        let new_result = PgStore::new(pool.clone(), c).await;
        let live_result = store.claim_due(scope, 2, Duration::from_secs(1), c).await;
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("ALTER TABLE rss_reconcile.targets DROP CONSTRAINT \"{quoted}\", ADD CONSTRAINT \"{quoted}\" {definition}")))
            .execute(owner).await?;
        eprintln!("reconcile CHECK drift: {name}");
        assert_kind(new_result, ErrorKind::StorageContract);
        assert_kind(live_result, ErrorKind::StorageContract);
        assert_eq!(snapshot(owner, scope.reconciler()).await?, before);
        PgStore::new(pool.clone(), c).await?;
    }
    Ok(())
}

async fn catalog_states(
    store: &PgStore,
    pool: &PgPool,
    owner: &PgPool,
    scope: &Scope,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let before = snapshot(owner, scope.reconciler()).await?;
    for (damage, repair) in [
        (
            "ALTER TABLE rss_reconcile.targets DROP CONSTRAINT targets_wake_version_check, ADD CONSTRAINT targets_wake_version_check CHECK(wake_version > 0) NOT VALID",
            "ALTER TABLE rss_reconcile.targets VALIDATE CONSTRAINT targets_wake_version_check",
        ),
        (
            "ALTER TABLE rss_reconcile.targets ADD CONSTRAINT extra_check CHECK(true)",
            "ALTER TABLE rss_reconcile.targets DROP CONSTRAINT extra_check",
        ),
    ] {
        sqlx::raw_sql(damage).execute(owner).await?;
        let new_result = PgStore::new(pool.clone(), c).await;
        let live_result = store.claim_due(scope, 2, Duration::from_secs(1), c).await;
        sqlx::raw_sql(repair).execute(owner).await?;
        assert_kind(new_result, ErrorKind::StorageContract);
        assert_kind(live_result, ErrorKind::StorageContract);
        assert_eq!(snapshot(owner, scope.reconciler()).await?, before);
        PgStore::new(pool.clone(), c).await?;
    }
    Ok(())
}

async fn exhausted_wake(
    store: &PgStore,
    owner: &PgPool,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let scope = Scope::new(TenantId::parse(TENANT)?, "wake-exhaustion")?;
    let exhausted = Target::new(scope.clone(), "a-exhausted")?;
    let neighbor = Target::new(scope.clone(), "b-neighbor")?;
    store.wake(&exhausted, c).await?;
    store.wake(&neighbor, c).await?;
    sqlx::query("UPDATE rss_reconcile.targets SET wake_version=9223372036854775807 WHERE reconciler='wake-exhaustion' AND entity='a-exhausted'")
        .execute(owner).await?;
    let before = snapshot(owner, scope.reconciler()).await?;
    for _ in 0..2 {
        assert_kind(store.wake(&exhausted, c).await, ErrorKind::InvalidInput);
        assert_eq!(snapshot(owner, scope.reconciler()).await?, before);
    }
    store.wake(&neighbor, c).await?;
    let after = snapshot(owner, scope.reconciler()).await?;
    assert_eq!(after[0], before[0], "exhausted row remains intact");
    let version: i64 = sqlx::query_scalar("SELECT wake_version FROM rss_reconcile.targets WHERE reconciler='wake-exhaustion' AND entity='b-neighbor'")
        .fetch_one(owner).await?;
    assert_eq!(version, 2);
    Ok(())
}

async fn damaged_row(
    store: &PgStore,
    pool: &PgPool,
    owner: &PgPool,
    scope: &Scope,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let definition: String = sqlx::query_scalar("SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='rss_reconcile.targets'::regclass AND conname='targets_failures_check'")
        .fetch_one(owner).await?;
    sqlx::raw_sql("ALTER TABLE rss_reconcile.targets DROP CONSTRAINT targets_failures_check, ADD CONSTRAINT targets_failures_check CHECK(true); UPDATE rss_reconcile.targets SET failures=-1 WHERE reconciler='corruption' AND entity='a-bad'")
        .execute(owner).await?;
    let before = snapshot(owner, scope.reconciler()).await?;
    assert_kind(
        PgStore::new(pool.clone(), c).await,
        ErrorKind::StorageContract,
    );
    assert_kind(
        store.claim_due(scope, 2, Duration::from_secs(1), c).await,
        ErrorKind::StorageContract,
    );
    let called = AtomicUsize::new(0);
    let result = store
        .wake_with(
            &Target::new(scope.clone(), "blocked-callback")?,
            c,
            &called,
            |called, _| {
                Box::pin(async move {
                    called.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                })
            },
        )
        .await;
    assert_kind(result, ErrorKind::StorageContract);
    assert_eq!(called.load(Ordering::SeqCst), 0);
    worker_rejects(store, scope, c, ErrorKind::StorageContract).await?;
    assert_eq!(
        snapshot(owner, scope.reconciler()).await?,
        before,
        "admission rejects before claim writes"
    );
    sqlx::raw_sql("UPDATE rss_reconcile.targets SET failures=0 WHERE reconciler='corruption' AND entity='a-bad'").execute(owner).await?;
    // SQL safety: definition comes from this fixture's canonical migration, before damage.
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("ALTER TABLE rss_reconcile.targets DROP CONSTRAINT targets_failures_check, ADD CONSTRAINT targets_failures_check {definition}")))
        .execute(owner).await?;
    recovery(pool, owner, scope, c).await
}

async fn recovery(
    pool: &PgPool,
    owner: &PgPool,
    scope: &Scope,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let restarted = PgStore::new(pool.clone(), c).await?;
    let business = Observations(AtomicUsize::new(0));
    // Observe durable finish, using the existing caller budget rather than a performance cutoff.
    tokio::select! {
        result = rss_reconcile::run(&restarted, &business, scope, policy()?, c, |_| {}) => {
            anyhow::bail!("worker stopped before durable recovery: {:?}", result?);
        }
        result = tokio::time::timeout(c.remaining(), wait_for_recovery(owner, scope, c)) => { result??; }
    }
    assert_eq!(business.0.load(Ordering::SeqCst), 2);
    assert!(
        restarted
            .claim_due(scope, 2, Duration::from_secs(1), c)
            .await?
            .is_empty()
    );
    restarted
        .wake(&Target::new(scope.clone(), "c-later")?, c)
        .await?;
    let batch = restarted
        .claim_due(scope, 2, Duration::from_secs(1), c)
        .await?;
    assert_eq!(batch.len(), 1);
    assert_eq!(batch[0].target().entity(), "c-later");
    restarted
        .finish(&batch[0], Completion::Converged, c)
        .await?;
    Ok(())
}

async fn wait_for_recovery(
    owner: &PgPool,
    scope: &Scope,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    loop {
        let finished: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_reconcile.targets WHERE tenant_id=$1::uuid AND reconciler=$2 AND result='converged'")
            .bind(scope.tenant().to_string()).bind(scope.reconciler()).fetch_one(owner).await?;
        if finished == 2 {
            return Ok(());
        }
        c.sleep(Duration::from_millis(10)).await;
    }
}

async fn exhausted_epoch(
    store: &PgStore,
    owner: &PgPool,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let scope = Scope::new(TenantId::parse(TENANT)?, "epoch-exhaustion")?;
    for entity in ["a-exhausted", "b-neighbor"] {
        store.wake(&Target::new(scope.clone(), entity)?, c).await?;
    }
    // Supported CHECK range, accelerated by the fixture owner; no constraint is bypassed.
    sqlx::query("UPDATE rss_reconcile.targets SET epoch=9223372036854775807 WHERE reconciler='epoch-exhaustion' AND entity='a-exhausted'")
        .execute(owner).await?;
    let before = snapshot(owner, scope.reconciler()).await?;
    for _ in 0..2 {
        let result = store.claim_due(&scope, 2, Duration::from_secs(1), c).await;
        assert_kind(result, ErrorKind::InvalidInput);
        assert_eq!(
            snapshot(owner, scope.reconciler()).await?,
            before,
            "whole claim statement rolled back, including the neighbor"
        );
    }
    worker_rejects(store, &scope, c, ErrorKind::InvalidInput).await?;
    assert_eq!(snapshot(owner, scope.reconciler()).await?, before);
    let other = target("epoch-exhaustion", OTHER)?;
    store.wake(&other, c).await?;
    let independent = claim(store, &other, Duration::from_secs(1), c).await?;
    store.finish(&independent, Completion::Converged, c).await?;
    // The exhausted row remains intact. This is a documented scope failure, not isolation.
    Ok(())
}

fn policy() -> Result<Policy, Error> {
    Policy::try_from(PolicyConfig {
        concurrency: 2,
        lease_ttl: Duration::from_secs(1),
        attempt_timeout: Duration::from_millis(200),
        scan_interval: Duration::from_millis(10),
        initial_backoff: Duration::from_millis(10),
        max_backoff: Duration::from_millis(20),
        max_attempts: 2,
    })
}
struct Observations(AtomicUsize);
impl Reconciler<PgClaim> for Observations {
    type State = ();
    async fn observe<T: Timer>(
        &self,
        _: &PgClaim,
        _: &Control<'_, T>,
    ) -> Result<ReconcileDiff<()>, Error> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(ReconcileDiff::between(
            DesiredState::present(()),
            ActualState::present(()),
        ))
    }
    async fn apply<T: Timer>(
        &self,
        _: &PgClaim,
        _: ReconcileDiff<()>,
        _: &Control<'_, T>,
    ) -> Result<(), Error> {
        Err(Error::new(ErrorKind::Invariant)) // Equal states must never invoke apply.
    }
}
async fn worker_rejects(
    store: &PgStore,
    scope: &Scope,
    c: &Control<'_, Clock>,
    expected: ErrorKind,
) -> anyhow::Result<()> {
    let business = Observations(AtomicUsize::new(0));
    let result = rss_reconcile::run(
        store,
        &business,
        scope,
        policy()?,
        &c.child(Duration::from_secs(1)),
        |_| {},
    )
    .await;
    assert!(matches!(result, Err(e) if e.kind()==expected));
    assert_eq!(business.0.load(Ordering::SeqCst), 0);
    Ok(())
}

#[track_caller]
fn assert_kind<T>(result: Result<T, Error>, expected: ErrorKind) {
    assert_eq!(result.err().map(|error| error.kind()), Some(expected));
}
