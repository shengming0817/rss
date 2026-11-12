use super::*;
use sqlx::PgConnection;
const V3: &str = concat!(
    include_str!("../../../../crates/projection-postgres/migrations/0001_create_projection.sql"),
    "\n",
    include_str!(
        "../../../../crates/projection-postgres/migrations/0002_require_baseline_receipts.sql"
    ),
    "\n",
    include_str!(
        "../../../../crates/projection-postgres/migrations/0003_bind_definition_identity.sql"
    ),
);

pub(crate) async fn upgrade(connection: &mut PgConnection) -> anyhow::Result<()> {
    sqlx::raw_sql(V3).execute(&mut *connection).await?;
    // A different tenant's generation and receipt must survive without identity adoption.
    initialize(connection, OTHER, "existing", "counter").await?;
    let before = state(connection).await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(TENANT)
        .execute(&mut *connection)
        .await?;
    sqlx::raw_sql(UPGRADE_SQL).execute(&mut *connection).await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(OTHER)
        .execute(&mut *connection)
        .await?;
    assert_eq!(before, state(connection).await?);
    initialize(connection, TENANT, &"s".repeat(255), &"p".repeat(255)).await?;
    let stored: (String, String) = sqlx::query_as(
        "SELECT source_id,projection_id FROM rss_projection.checkpoints WHERE tenant_id=$1::uuid",
    )
    .bind(TENANT)
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(stored, ("s".repeat(255), "p".repeat(255)));
    for (source, projection) in [
        ("s".repeat(256), "valid".into()),
        ("valid".into(), "p".repeat(256)),
    ] {
        assert!(
            initialize(connection, TENANT, &source, &projection)
                .await
                .is_err()
        );
    }
    let upgraded = structure(connection).await?;
    sqlx::raw_sql("DROP SCHEMA rss_projection CASCADE")
        .execute(&mut *connection)
        .await?;
    sqlx::raw_sql(MIGRATION_SQL)
        .execute(&mut *connection)
        .await?;
    assert_eq!(upgraded, structure(connection).await?);
    Ok(())
}

async fn initialize(
    connection: &mut PgConnection,
    tenant: &str,
    source: &str,
    projection: &str,
) -> anyhow::Result<()> {
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(tenant)
        .execute(&mut *connection)
        .await?;
    sqlx::query("SELECT rss_projection.initialize($1::uuid,$2,$3,'v1',0,false,NULL,ARRAY['fact'],ARRAY[decode(repeat('22',32),'hex')],decode(repeat('11',32),'hex'))")
        .bind(tenant).bind(source).bind(projection).execute(&mut *connection).await?;
    Ok(())
}

async fn state(connection: &mut PgConnection) -> anyhow::Result<serde_json::Value> {
    Ok(sqlx::query_scalar("SELECT jsonb_build_array((SELECT jsonb_agg(to_jsonb(c)) FROM rss_projection.checkpoints c),(SELECT jsonb_agg(to_jsonb(r)) FROM rss_projection.receipts r))")
        .fetch_one(connection).await?)
}

async fn structure(connection: &mut PgConnection) -> anyhow::Result<Vec<String>> {
    Ok(sqlx::query_scalar("SELECT description FROM (SELECT oid::regprocedure::text AS description FROM pg_proc WHERE pronamespace='rss_projection'::regnamespace UNION ALL SELECT conrelid::regclass::text||':'||conname||':'||pg_get_constraintdef(oid) FROM pg_constraint WHERE connamespace='rss_projection'::regnamespace) s ORDER BY description")
        .fetch_all(connection).await?)
}
