//! Admitted operations do not rescan catalogs; controlled drift requires re-admission.
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
    // Work is registered through the already admitted public boundary while catalog drift exists.
    store
        .wake(&target, &ResourceSet::empty(scope.tenant()), control)
        .await?;
    let due = store
        .claim_due(scope, 2, Duration::from_secs(1), control)
        .await;
    sqlx::raw_sql("ALTER TABLE rss_reconcile.targets DROP CONSTRAINT idle_extra")
        .execute(owner)
        .await?;
    assert!(
        empty?.claims.is_empty(),
        "empty discovery must not run the full structure probe"
    );
    assert_eq!(
        startup.err().map(|e| e.kind()),
        Some(ErrorKind::StorageContract)
    );
    let mut due = due?.claims;
    assert_eq!(due.len(), 1, "admitted operations do not revalidate DDL");
    let claimed = due.remove(0);
    store
        .finish(&claimed, Completion::Converged, control)
        .await?;
    safety(store, pool, owner, control, scope).await
}

async fn safety(
    store: &PgStore,
    pool: &PgPool,
    owner: &PgPool,
    control: &Control<'_, Clock>,
    scope: &Scope,
) -> anyhow::Result<()> {
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
        let rejected = PgStore::new(pool.clone(), control).await;
        sqlx::raw_sql(repair).execute(owner).await?;
        assert_eq!(
            rejected.err().map(|e| e.kind()),
            Some(ErrorKind::StorageContract),
            "re-admission must reject: {damage}"
        );
    }
    assert!(
        store
            .claim_due(scope, 1, Duration::from_secs(1), control)
            .await?
            .claims
            .is_empty()
    );
    Ok(())
}
