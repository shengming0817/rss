//! Empty discovery does not execute structural admission or mint authority.
use super::*;

pub(super) async fn run(
    store: &PgStore,
    pool: &PgPool,
    owner: &PgPool,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let target = target("idle-discovery", TENANT)?;
    let scope = target.scope();
    sqlx::raw_sql("ALTER TABLE rss_reconcile.targets ADD CONSTRAINT idle_extra CHECK(true)")
        .execute(owner)
        .await?;
    let empty = store
        .claim_due(scope, 2, Duration::from_secs(1), control)
        .await;
    let startup = PgStore::new(pool.clone(), control).await;
    // The separately privileged fixture creates work while the admitted handle is idle.
    sqlx::query(
        "INSERT INTO rss_reconcile.targets(tenant_id,reconciler,entity) VALUES($1::uuid,$2,$3)",
    )
    .bind(TENANT)
    .bind(scope.reconciler())
    .bind(target.entity())
    .execute(owner)
    .await?;
    let due = store
        .claim_due(scope, 2, Duration::from_secs(1), control)
        .await;
    let untouched: bool = sqlx::query_scalar("SELECT epoch=0 AND token IS NULL FROM rss_reconcile.targets WHERE tenant_id=$1::uuid AND reconciler=$2")
        .bind(TENANT).bind(scope.reconciler()).fetch_one(owner).await?;
    sqlx::raw_sql("ALTER TABLE rss_reconcile.targets DROP CONSTRAINT idle_extra")
        .execute(owner)
        .await?;
    assert!(
        empty?.is_empty(),
        "empty discovery must not run the full structure probe"
    );
    assert_eq!(
        startup.err().map(|e| e.kind()),
        Some(ErrorKind::StorageContract)
    );
    assert_eq!(
        due.err().map(|e| e.kind()),
        Some(ErrorKind::StorageContract)
    );
    assert!(
        untouched,
        "structural admission precedes every claim mutation"
    );
    let claimed = claim(store, &target, Duration::from_secs(1), control).await?;
    store
        .finish(&claimed, Completion::Converged, control)
        .await?;
    for (damage, repair) in [
        (
            "GRANT UPDATE ON rss_reconcile.targets TO reconcile_runtime",
            "REVOKE UPDATE ON rss_reconcile.targets FROM reconcile_runtime",
        ),
        (
            "REVOKE SELECT ON rss_reconcile.targets FROM reconcile_runtime",
            "GRANT SELECT ON rss_reconcile.targets TO reconcile_runtime",
        ),
        (
            "ALTER ROLE reconcile_runtime BYPASSRLS",
            "ALTER ROLE reconcile_runtime NOBYPASSRLS",
        ),
        (
            "ALTER TABLE rss_reconcile.targets NO FORCE ROW LEVEL SECURITY",
            "ALTER TABLE rss_reconcile.targets FORCE ROW LEVEL SECURITY",
        ),
        (
            "CREATE POLICY hidden ON rss_reconcile.targets AS RESTRICTIVE USING(false)",
            "DROP POLICY hidden ON rss_reconcile.targets",
        ),
        (
            "GRANT EXECUTE ON FUNCTION rss_reconcile.claim_due(uuid,text,integer,bigint) TO PUBLIC",
            "REVOKE EXECUTE ON FUNCTION rss_reconcile.claim_due(uuid,text,integer,bigint) FROM PUBLIC",
        ),
    ] {
        sqlx::raw_sql(damage).execute(owner).await?;
        let rejected = store
            .claim_due(scope, 1, Duration::from_secs(1), control)
            .await;
        sqlx::raw_sql(repair).execute(owner).await?;
        assert_eq!(
            rejected.err().map(|e| e.kind()),
            Some(ErrorKind::StorageContract),
            "empty scan must reject: {damage}"
        );
    }
    assert!(
        store
            .claim_due(scope, 1, Duration::from_secs(1), control)
            .await?
            .is_empty()
    );
    Ok(())
}
