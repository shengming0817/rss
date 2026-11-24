//! Ordinary head ownership across two independent transactions.
use super::*;

pub(super) async fn handoff(raw: &PgPool, owner: &PgPool) -> anyhow::Result<()> {
    for (lane, commit_append, commit_settlement) in [
        ("head-commit", true, true),
        ("head-rollback", true, false),
        ("append-rollback", false, true),
    ] {
        let head = ordered(&format!("{lane}-first"), lane, "partition");
        let tail = ordered(&format!("{lane}-next"), lane, "partition");
        let tenant = head.metadata().tenant_id();
        let pairs = serde_json::json!([[lane, "partition"]]);
        let mut seed = sql_tx(raw, tenant).await?;
        sql_prepare(&mut seed, pairs.clone()).await?;
        sql_append(&mut seed, &head).await?;
        let (seq,token,until): (i64,String,i64) = sqlx::query_as("SELECT seq,lease_token::text,(extract(epoch FROM lease_until)*1000000)::bigint FROM rss_transactional_messaging.claim_outbox($1::uuid,$2,1,60000)")
            .bind(tenant.to_string()).bind(lane).fetch_one(&mut *seed).await?;
        seed.commit().await?;
        let mut writer = sql_tx(raw, tenant).await?;
        sql_prepare(&mut writer, pairs).await?;
        sql_append(&mut writer, &tail).await?;
        let mut relay = sql_tx(raw, tenant).await?;
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *relay)
            .await?;
        let settle = async {
            let result:String = sqlx::query_scalar("SELECT rss_transactional_messaging.settle_outbox($1::uuid,$2,$3::uuid,$4,'published',NULL)")
                .bind(tenant.to_string()).bind(seq).bind(token).bind(until).fetch_one(&mut *relay).await?;
            assert_eq!(result, "settled");
            if commit_settlement {
                relay.commit().await?;
            } else {
                relay.rollback().await?;
            }
            anyhow::Ok(())
        };
        let release = async {
            wait_lock(owner, pid).await?;
            if commit_append {
                writer.commit().await?;
            } else {
                writer.rollback().await?;
            }
            anyhow::Ok(())
        };
        tokio::try_join!(settle, release)?;
        let marked:Vec<String> = sqlx::query_scalar("SELECT message_id FROM rss_transactional_messaging.outbox WHERE tenant_id=$1::uuid AND domain=$2 AND partition_head")
            .bind(tenant.to_string()).bind(lane).fetch_all(owner).await?;
        let expected = if !commit_settlement {
            Some(head.id())
        } else if commit_append {
            Some(tail.id())
        } else {
            None
        };
        assert_eq!(
            marked,
            expected
                .into_iter()
                .map(MessageId::as_str)
                .collect::<Vec<_>>()
        );
    }
    capacity(raw).await
}

async fn capacity(raw: &PgPool) -> anyhow::Result<()> {
    let lane = "lock-scope";
    let tenant = message("one").metadata().tenant_id();
    let mut seed = sql_tx(raw, tenant).await?;
    sql_prepare(
        &mut seed,
        serde_json::json!([[lane, "a"], [lane, "b"], [lane, "c"]]),
    )
    .await?;
    for key in ["a", "b", "c"] {
        sql_append(&mut seed, &ordered(&format!("lock-scope-{key}"), lane, key)).await?;
    }
    seed.commit().await?;
    let mut first = sql_tx(raw, tenant).await?;
    let mut second = sql_tx(raw, tenant).await?;
    let query =
        "SELECT message_id FROM rss_transactional_messaging.claim_outbox($1::uuid,$2,$3,60000)";
    let one: Vec<String> = sqlx::query_scalar(query)
        .bind(tenant.to_string())
        .bind(lane)
        .bind(1i32)
        .fetch_all(&mut *first)
        .await?;
    let rest: Vec<String> = sqlx::query_scalar(query)
        .bind(tenant.to_string())
        .bind(lane)
        .bind(3i32)
        .fetch_all(&mut *second)
        .await?;
    assert_eq!(one, ["lock-scope-a"]);
    assert_eq!(rest, ["lock-scope-b", "lock-scope-c"]);
    second.rollback().await?;
    first.rollback().await?;
    Ok(())
}
