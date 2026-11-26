//! Stable scans retain their physical tuple; real window progress still persists.
use super::*;
type Position = (i64, i64, String, String);
async fn position(owner: &PgPool, scope: &Scope) -> anyhow::Result<Position> {
    Ok(sqlx::query_as("SELECT cursor_ticket,high_watermark,ctid::text,xmin::text FROM rss_reconcile.scans WHERE tenant_id=$1::uuid AND reconciler=$2")
        .bind(scope.tenant().to_string()).bind(scope.reconciler()).fetch_one(owner).await?)
}
async fn unchanged(
    store: &PgStore,
    owner: &PgPool,
    scope: &Scope,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let before = position(owner, scope).await?;
    for _ in 0..10 {
        let batch = store
            .claim_due(scope, 1, 64, Duration::from_secs(60), c)
            .await?;
        assert!(batch.claims.is_empty());
        assert!(!batch.more);
        assert_eq!(
            position(owner, scope).await?,
            before,
            "committed no-op scans must not create a new tuple"
        );
    }
    println!("scan tuple stable across 10 committed scans: {before:?}");
    Ok(())
}
pub(super) async fn run(
    store: &PgStore,
    owner: &PgPool,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let t = target("scan-progress", TENANT)?;
    let scope = t.scope();
    assert!(
        store
            .claim_due(scope, 1, 64, Duration::from_secs(60), c)
            .await?
            .claims
            .is_empty()
    );
    store
        .wake(&t, &ResourceSet::empty(scope.tenant()), c)
        .await?;
    let before = position(owner, scope).await?;
    live_and_future(store, owner, c, &t, before).await?;
    empty_and_locked(store, owner, c, &t).await?;
    windows(store, owner, c).await
}
async fn live_and_future(
    store: &PgStore,
    owner: &PgPool,
    c: &Control<'_, Clock>,
    t: &Target,
    before: Position,
) -> anyhow::Result<()> {
    let scope = t.scope();
    let current = claim(store, t, Duration::from_secs(60), c).await?;
    assert_ne!(
        position(owner, scope).await?,
        before,
        "claim advances the scan"
    );
    unchanged(store, owner, scope, c).await?;
    store
        .finish(
            &current,
            Completion::Reobserve(Duration::from_secs(3600)),
            c,
        )
        .await?;
    let before = position(owner, scope).await?;
    assert!(
        store
            .claim_due(scope, 1, 64, Duration::from_secs(60), c)
            .await?
            .claims
            .is_empty()
    );
    assert_ne!(
        position(owner, scope).await?,
        before,
        "new future ticket advances the watermark without a claim"
    );
    unchanged(store, owner, scope, c).await?;
    Ok(())
}
async fn empty_and_locked(
    store: &PgStore,
    owner: &PgPool,
    c: &Control<'_, Clock>,
    t: &Target,
) -> anyhow::Result<()> {
    let scope = t.scope();
    store
        .wake(t, &ResourceSet::empty(scope.tenant()), c)
        .await?;
    let current = claim(store, t, Duration::from_secs(60), c).await?;
    store.finish(&current, Completion::Converged, c).await?;
    assert!(
        store
            .claim_due(scope, 1, 64, Duration::from_secs(60), c)
            .await?
            .claims
            .is_empty()
    );
    let empty = position(owner, scope).await?;
    assert_eq!((empty.0, empty.1), (0, 0));
    unchanged(store, owner, scope, c).await?;
    let mut held = owner.begin().await?;
    sqlx::query(
        "SELECT 1 FROM rss_reconcile.scans WHERE tenant_id=$1::uuid AND reconciler=$2 FOR UPDATE",
    )
    .bind(TENANT)
    .bind(scope.reconciler())
    .execute(&mut *held)
    .await?;
    let skipped = tokio::time::timeout(
        Duration::from_secs(2),
        store.claim_due(scope, 1, 64, Duration::from_secs(60), c),
    )
    .await??;
    assert!(skipped.claims.is_empty());
    held.rollback().await?;
    unchanged(store, owner, scope, c).await?;
    Ok(())
}
async fn windows(store: &PgStore, owner: &PgPool, c: &Control<'_, Clock>) -> anyhow::Result<()> {
    let scope = Scope::new(TenantId::parse(TENANT)?, "scan-window")?;
    let keys = ResourceSet::empty(scope.tenant());
    let old = Target::new(scope.clone(), "old")?;
    let locked = Target::new(scope.clone(), "locked")?;
    let last = Target::new(scope.clone(), "last")?;
    for target in [&old, &locked, &last] {
        store.wake(target, &keys, c).await?;
    }
    sqlx::query("UPDATE rss_reconcile.targets SET next_run=clock_timestamp()+interval '1 hour' WHERE tenant_id=$1::uuid AND reconciler=$2")
        .bind(TENANT).bind(scope.reconciler()).execute(owner).await?;
    let lease = Duration::from_secs(60);
    let empty = store.claim_due(&scope, 1, 1, lease, c).await?;
    assert!(empty.claims.is_empty() && !empty.more);

    store.wake(&locked, &keys, c).await?;
    store.wake(&last, &keys, c).await?;
    let mut held = owner.begin().await?;
    sqlx::query("SELECT FROM rss_reconcile.targets WHERE tenant_id=$1::uuid AND reconciler=$2 AND entity=$3 FOR UPDATE")
        .bind(TENANT).bind(scope.reconciler()).bind(locked.entity()).execute(&mut *held).await?;
    let blocked = store.claim_due(&scope, 1, 1, lease, c).await?;
    assert!(blocked.claims.is_empty() && blocked.more);
    let middle = position(owner, &scope).await?;
    assert!(middle.0 < middle.1);

    // The old target keeps its already-passed ticket. The new one is above this watermark.
    store.wake(&old, &keys, c).await?;
    let new = Target::new(scope.clone(), "new")?;
    store.wake(&new, &keys, c).await?;
    let tail = store.claim_due(&scope, 1, 1, lease, c).await?;
    assert_eq!(tail.claims.len(), 1);
    assert_eq!(tail.claims[0].target(), &last);
    assert!(!tail.more);
    let end = position(owner, &scope).await?;
    assert_eq!((end.0, end.1), (middle.1, middle.1));

    let next = store
        .claim_due(&scope, 3, i32::MAX as u32, lease, c)
        .await?;
    let targets: Vec<_> = next.claims.iter().map(Claim::target).collect();
    assert_eq!(targets, [&old, &new]);
    assert!(!next.more);
    held.rollback().await?;
    Ok(())
}
