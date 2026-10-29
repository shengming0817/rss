use super::*;
const V1: &str =
    include_str!("../../../../crates/reconcile-postgres/migrations/0001_create_reconcile.sql");

pub(crate) async fn install(connection: &mut sqlx::PgConnection) -> anyhow::Result<()> {
    sqlx::raw_sql(V1).execute(&mut *connection).await?;
    sqlx::query("SELECT rss_reconcile.wake($1::uuid,'upgrade','past'),rss_reconcile.wake($1::uuid,'upgrade','future')")
        .bind(TENANT).execute(&mut *connection).await?;
    sqlx::query("UPDATE rss_reconcile.targets SET failures=5,epoch=7,wake_version=9,next_run=CASE WHEN entity='future' THEN clock_timestamp()+interval '1 hour' ELSE clock_timestamp()-interval '1 hour' END WHERE reconciler='upgrade'")
        .execute(&mut *connection).await?;
    sqlx::raw_sql(UPGRADE_SQL).execute(&mut *connection).await?;
    Ok(())
}
pub(super) async fn verify(
    store: &PgStore,
    owner: &PgPool,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let scope = Scope::new(TenantId::parse(TENANT)?, "upgrade")?;
    let before: Vec<(String,String,i64,i64,i64)> = sqlx::query_as("SELECT entity,next_run::text,failures,epoch,wake_version FROM rss_reconcile.targets WHERE reconciler='upgrade' ORDER BY entity").fetch_all(owner).await?;
    assert_eq!(before.len(), 2);
    for row in &before {
        assert_eq!((row.2, row.3, row.4), (5, 7, 9));
    }
    assert!(
        matches!(store.claim_due(&scope,2,Duration::from_secs(1),c).await,Err(e) if e.kind()==ErrorKind::StorageContract)
    );
    bind_pending(store, &scope, c).await?;
    let after: Vec<(String,String,i64,i64,i64)> = sqlx::query_as("SELECT entity,next_run::text,failures,epoch,wake_version FROM rss_reconcile.targets WHERE reconciler='upgrade' ORDER BY entity").fetch_all(owner).await?;
    assert_eq!(before, after);
    claim_bound(store, owner, &scope, c).await
}
async fn bind_pending(
    store: &PgStore,
    scope: &Scope,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    for entity in ["future", "past"] {
        store
            .bind_resources(
                &Target::new(scope.clone(), entity)?,
                &ResourceSet::empty(scope.tenant()),
                c,
            )
            .await?;
        if entity == "future" {
            assert!(
                matches!(store.claim_due(scope,2,Duration::from_secs(1),c).await,Err(e) if e.kind()==ErrorKind::StorageContract)
            );
        }
    }
    Ok(())
}
async fn claim_bound(
    store: &PgStore,
    owner: &PgPool,
    scope: &Scope,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let batch = store.claim_due(scope, 2, Duration::from_secs(2), c).await?;
    assert_eq!(batch.claims.len(), 1);
    assert_eq!(batch.claims[0].target().entity(), "past");
    assert_eq!(batch.claims[0].failures(), 5);
    assert_eq!(batch.claims[0].epoch(), 8);
    store
        .finish(&batch.claims[0], Completion::Converged, c)
        .await?;
    let old_absent: bool=sqlx::query_scalar("SELECT to_regprocedure('rss_reconcile.wake(uuid,text,text)') IS NULL AND to_regprocedure('rss_reconcile.lock_claim(uuid,text,text,uuid,bigint)') IS NULL").fetch_one(owner).await?;
    assert!(old_absent);
    Ok(())
}
