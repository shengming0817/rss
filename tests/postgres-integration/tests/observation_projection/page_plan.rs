use super::{fixture::*, retention_scale::examined};
use rss_observation::{Body, ObservationStore};
use serde_json::Value;

const PAGE: &str = include_str!("../../../../crates/observation-postgres/src/projection/page.sql");

#[tokio::test]
async fn short_and_empty_pages_seek_bodies_in_large_tenant_history() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let store = f.store().await?;
    let old = scope(TENANT, "page-plan", "r", "source", "old")?;
    activate(&store, &old, None).await?;
    sqlx::query("INSERT INTO rss_observation.batches(tenant_id,scope,batch_id,sequence,fingerprint,received_at,applicable,log_position)
        SELECT $1::uuid,$2,n::text,n,sha256(convert_to(n::text,'utf8')),100,true,n FROM generate_series(1,99900) n")
        .bind(TENANT).bind(old.encode()?).execute(&f.admin).await?;
    sqlx::query("INSERT INTO rss_observation.journals(tenant_id,last_position,expired_through) VALUES ($1::uuid,99900,99900)")
        .bind(TENANT).execute(&f.admin).await?;
    let active = scope(TENANT, "page-plan", "r", "source", "new")?;
    activate(&store, &active, Some(1)).await?;
    for n in 0..100 {
        store.receive(&batch(&active, &n.to_string(), n, "all", Body::Snapshot(vec![]))?, deadline()).await?;
    }
    sqlx::raw_sql("ANALYZE rss_observation.journals; ANALYZE rss_observation.batches").execute(&f.admin).await?;

    let mut tx = f.pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)").bind(TENANT).execute(&mut *tx).await?;
    let prepare = format!("PREPARE obs_page(text,bigint,bigint,bigint) AS {PAGE}");
    sqlx::raw_sql(sqlx::AssertSqlSafe(prepare)).execute(&mut *tx).await?;
    for mode in ["force_custom_plan", "force_generic_plan"] {
        sqlx::query("SELECT set_config('plan_cache_mode',$1,true)").bind(mode).execute(&mut *tx).await?;
        for (after, count) in [(99900, 8), (100000, 0)] {
            let budget = rss_observation::Batch::MAX_ENCODED_BYTES;
            let explain = format!("EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) EXECUTE obs_page('{TENANT}',{after},8,{budget})");
            let plan: Value = sqlx::query_scalar(sqlx::AssertSqlSafe(explain)).fetch_one(&mut *tx).await?;
            let visited = examined(&plan[0]["Plan"], "batches");
            println!("observation_page_plan history=100000 mode={mode} after={after} visited={visited}");
            // One index candidate and one body lookup per admitted record.
            assert_eq!(visited, 2 * count, "{plan}");
        }
    }
    tx.rollback().await?;
    Ok(())
}
