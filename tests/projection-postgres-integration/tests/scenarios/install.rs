use super::*;
use sqlx::PgConnection;

pub(crate) async fn verify(connection: &mut PgConnection) -> anyhow::Result<()> {
    sqlx::raw_sql(MIGRATION_SQL).execute(&mut *connection).await?;
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
