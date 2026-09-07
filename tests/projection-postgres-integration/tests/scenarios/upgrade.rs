use super::*;
use sqlx::PgConnection;
const V2: &str = concat!(
    include_str!("../../../../crates/projection-postgres/migrations/0001_create_projection.sql"),
    "\n",
    include_str!(
        "../../../../crates/projection-postgres/migrations/0002_require_baseline_receipts.sql"
    ),
);

pub(crate) async fn upgrade(connection: &mut PgConnection) -> anyhow::Result<()> {
    sqlx::raw_sql(V2).execute(&mut *connection).await?;
    seed_hidden_generation(connection).await?;
    rejected_upgrade(connection).await?;
    sqlx::raw_sql("DROP SCHEMA rss_projection CASCADE")
        .execute(&mut *connection)
        .await?;
    sqlx::raw_sql(V2).execute(&mut *connection).await?;
    sqlx::raw_sql(UPGRADE_SQL).execute(&mut *connection).await?;
    let upgraded = signatures(connection).await?;
    sqlx::raw_sql("DROP SCHEMA rss_projection CASCADE")
        .execute(&mut *connection)
        .await?;
    sqlx::raw_sql(MIGRATION_SQL)
        .execute(&mut *connection)
        .await?;
    assert_eq!(upgraded, signatures(connection).await?);
    Ok(())
}

async fn signatures(connection: &mut PgConnection) -> anyhow::Result<Vec<String>> {
    let names: Vec<String> = sqlx::query_scalar("SELECT oid::regprocedure::text FROM pg_proc WHERE pronamespace='rss_projection'::regnamespace ORDER BY oid::regprocedure::text").fetch_all(&mut *connection).await?;
    for old in [
        "rss_projection.initialize(uuid,text,text,text,bigint,boolean,bigint,text[],bytea[])",
        "rss_projection.takeover(uuid,text,text,text,uuid)",
        "rss_projection.lock_event(uuid,text,text,text,bigint,uuid,bigint,bigint,text,bytea)",
        "rss_projection.finish_event(uuid,text,text,text,bigint,uuid,bigint,bigint,text,bytea)",
    ] {
        assert!(!names.iter().any(|name| name == old));
    }
    Ok(names)
}

async fn seed_hidden_generation(connection: &mut PgConnection) -> anyhow::Result<()> {
    // Seed the OTHER tenant, then leave the owner viewing TENANT. FORCE RLS must not hide
    // this physical row from the migration's NOT NULL validation.
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(OTHER)
        .execute(&mut *connection)
        .await?;
    sqlx::query("SELECT rss_projection.initialize($1::uuid,'legacy','counter','v1',NULL,false,NULL,ARRAY[]::text[],ARRAY[]::bytea[])").bind(OTHER).execute(&mut *connection).await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(TENANT)
        .execute(&mut *connection)
        .await?;
    Ok(())
}

async fn rejected_upgrade(connection: &mut PgConnection) -> anyhow::Result<()> {
    let error = sqlx::raw_sql(UPGRADE_SQL)
        .execute(&mut *connection)
        .await
        .err()
        .ok_or_else(|| anyhow::anyhow!("populated generation was silently adopted"))?;
    assert_eq!(
        error.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("23502")
    );
    sqlx::raw_sql("ROLLBACK").execute(&mut *connection).await?;
    let revision: String =
        sqlx::query_scalar("SELECT obj_description('rss_projection'::regnamespace,'pg_namespace')")
            .fetch_one(&mut *connection)
            .await?;
    assert_eq!(revision, "rss-projection-postgres:2");
    let column: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_attribute WHERE attrelid='rss_projection.checkpoints'::regclass AND attname='definition_identity' AND NOT attisdropped").fetch_one(&mut *connection).await?;
    assert_eq!(column, 0);
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(OTHER)
        .execute(&mut *connection)
        .await?;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_projection.checkpoints WHERE source_id='legacy' AND epoch=0 AND position IS NULL").fetch_one(&mut *connection).await?;
    assert_eq!(count, 1);
    Ok(())
}
