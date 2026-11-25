//! Real maintenance-role checks after generic-plan warmup and increasing historical DR size.
use super::*;
use sqlx::Connection as _;

pub(super) async fn historical_work(owner: &sqlx::PgPool, after: i64) -> anyhow::Result<()> {
    let profile = std::env::var_os("RSS_PG_WORK_PROFILE").is_some();
    if profile {
        let _ = tracing_subscriber::fmt()
            .with_env_filter("sqlx::postgres::notice=info")
            .with_ansi(false)
            .try_init();
    }
    for (start, end) in [(1_i64, 100_i64), (101, 10_000)] {
        sqlx::query("INSERT INTO rss_transactional_messaging.dr_plans(tenant_id,operation_id,request_digest,lineage,epoch,kind,evidence) SELECT $1::uuid,gen_random_uuid(),sha256('history'::bytea),decode(repeat('03',16),'hex'),100000+n,'database','{\"fixture\":\"retention-history\"}'::jsonb FROM generate_series($2::bigint,$3::bigint) n")
            .bind(tenant().to_string()).bind(start).bind(end).execute(owner).await?;
        sqlx::query("INSERT INTO rss_transactional_messaging.dr_members(tenant_id,operation_id,ordinal,message_id,consumer_group,fingerprint,outbox_seq,status) SELECT p.tenant_id,p.operation_id,0,o.message_id,'',o.fingerprint,o.seq,'pending' FROM rss_transactional_messaging.dr_plans p JOIN rss_transactional_messaging.outbox o ON o.seq=$1 AND o.tenant_id=p.tenant_id WHERE p.evidence->>'fixture'='retention-history' AND p.epoch BETWEEN 100000+$2 AND 100000+$3")
            .bind(after+1).bind(start).bind(end).execute(owner).await?;
        measure(owner, after, end, profile).await?;
    }
    sqlx::query("DELETE FROM rss_transactional_messaging.dr_members d USING rss_transactional_messaging.dr_plans p WHERE d.tenant_id=p.tenant_id AND d.operation_id=p.operation_id AND p.evidence->>'fixture'='retention-history'").execute(owner).await?;
    sqlx::query("DELETE FROM rss_transactional_messaging.dr_plans WHERE evidence->>'fixture'='retention-history'").execute(owner).await?;
    Ok(())
}

async fn measure(owner: &sqlx::PgPool, after: i64, end: i64, profile: bool) -> anyhow::Result<()> {
    let mut c = sqlx::PgConnection::connect_with(owner.connect_options().as_ref()).await?;
    if profile {
        sqlx::raw_sql("LOAD 'auto_explain'; SET auto_explain.log_min_duration=0; SET auto_explain.log_nested_statements=on; SET auto_explain.log_analyze=on; SET auto_explain.log_buffers=on; SET auto_explain.log_timing=off; SET auto_explain.log_format=json; SET auto_explain.log_level=notice;").execute(&mut c).await?;
    }
    sqlx::query("SET SESSION AUTHORIZATION body_operator")
        .execute(&mut c)
        .await?;
    for attempt in 0..7 {
        if profile || attempt == 6 {
            println!("body-history population={end} attempt={attempt}");
        }
        let mut tx = c.begin().await?;
        let result:(i32,i32)=sqlx::query_as("SELECT scanned,reclaimed FROM rss_transactional_messaging.reclaim_published_bodies($1,$2,1)")
            .bind(i64::MAX).bind(after).fetch_one(&mut *tx).await?;
        assert_eq!(result, (1, 1), "historical DR cannot retain a closed body");
        tx.rollback().await?;
    }
    c.close().await?;
    Ok(())
}
