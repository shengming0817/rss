//! Ordinary head ownership across two independent transactions.
use super::*;

pub(super) async fn handoff(raw: &PgPool, owner: &PgPool) -> anyhow::Result<()> {
    for (lane, commit_append, commit_settlement, expected) in [
        ("head-commit", true, true, Some("next")),
        ("head-rollback", true, false, Some("first")),
        ("append-rollback", false, true, None),
    ] {
        concurrent_handoff(raw, owner, lane, commit_append, commit_settlement, expected).await?;
    }
    standalone_and_declared(raw, owner).await?;
    late_declaration(raw).await?;
    stale_snapshot(raw).await?;
    crossed_declarations(raw).await?;
    capacity(raw).await
}

async fn concurrent_handoff(
    raw: &PgPool,
    owner: &PgPool,
    lane: &str,
    commit_append: bool,
    commit_settlement: bool,
    expected: Option<&str>,
) -> anyhow::Result<()> {
    let head = ordered(&format!("{lane}-first"), lane, "partition");
    let tail = ordered(&format!("{lane}-next"), lane, "partition");
    let tenant = head.metadata().tenant_id();
    let pairs = serde_json::json!([[lane, "partition"]]);
    let claim = seed_claim(raw, &head).await?;
    let mut writer = sql_tx(raw, tenant).await?;
    sql_prepare(&mut writer, pairs).await?;
    sql_append(&mut writer, &tail).await?;
    // The writer owns the allocator and may next need this source. A standalone
    // handoff must release the source on contention, before either session waits.
    assert_busy(raw, tenant, &claim).await?;
    end_transaction(writer, commit_append).await?;
    finish_claim(sql_tx(raw, tenant).await?, tenant, claim, commit_settlement).await?;
    let marked:Vec<String> = sqlx::query_scalar("SELECT message_id FROM rss_transactional_messaging.outbox WHERE tenant_id=$1::uuid AND domain=$2 AND partition_head")
            .bind(tenant.to_string()).bind(lane).fetch_all(owner).await?;
    assert_eq!(
        marked,
        expected
            .into_iter()
            .map(|suffix| format!("{lane}-{suffix}"))
            .collect::<Vec<_>>()
    );
    Ok(())
}

async fn assert_busy(
    raw: &PgPool,
    tenant: TenantId,
    claim: &(i64, String, i64),
) -> anyhow::Result<()> {
    let mut relay = sql_tx(raw, tenant).await?;
    let error = settle(&mut relay, tenant, claim)
        .await
        .expect_err("busy source allocator");
    assert_eq!(code(&error).as_deref(), Some("55P03"));
    relay.rollback().await?;
    Ok(())
}

async fn seed_claim(
    raw: &PgPool,
    head: &MessageEnvelope<Vec<u8>>,
) -> anyhow::Result<(i64, String, i64)> {
    let tenant = head.metadata().tenant_id();
    let partition = head.metadata().partition().expect("ordered test message");
    let domain = head.metadata().domain().as_str();
    let mut seed = sql_tx(raw, tenant).await?;
    sql_prepare(
        &mut seed,
        serde_json::json!([[domain, partition.key().as_str()]]),
    )
    .await?;
    sql_append(&mut seed, head).await?;
    let claim = sqlx::query_as(
        "SELECT seq,lease_token::text,(extract(epoch FROM lease_until)*1000000)::bigint
        FROM rss_transactional_messaging.claim_outbox($1::uuid,$2,1,60000)",
    )
    .bind(tenant.to_string())
    .bind(domain)
    .fetch_one(&mut *seed)
    .await?;
    seed.commit().await?;
    Ok(claim)
}

async fn settle(
    tx: &mut PgConnection,
    tenant: TenantId,
    claim: &(i64, String, i64),
) -> Result<String, sqlx::Error> {
    sqlx::query_scalar("SELECT rss_transactional_messaging.settle_outbox($1::uuid,$2,$3::uuid,$4,'published',NULL)")
        .bind(tenant.to_string()).bind(claim.0).bind(&claim.1).bind(claim.2).fetch_one(tx).await
}

async fn finish_claim(
    mut tx: Transaction<'_, Postgres>,
    tenant: TenantId,
    claim: (i64, String, i64),
    commit: bool,
) -> anyhow::Result<()> {
    let result = settle(&mut tx, tenant, &claim).await?;
    assert_eq!(result, "settled");
    end_transaction(tx, commit).await
}

async fn end_transaction(tx: Transaction<'_, Postgres>, commit: bool) -> anyhow::Result<()> {
    if commit {
        tx.commit().await?;
    } else {
        tx.rollback().await?;
    }
    Ok(())
}

async fn fixed_snapshot(
    raw: &PgPool,
    tenant: TenantId,
) -> anyhow::Result<Transaction<'static, Postgres>> {
    let mut old = raw.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *old)
        .await?;
    sql_scope(&mut old, tenant).await?;
    let first:bool = sqlx::query_scalar("SELECT partition_head FROM rss_transactional_messaging.outbox WHERE message_id='repeatable-first'")
        .fetch_one(&mut *old).await?;
    assert!(first);
    Ok(old)
}

// The combined writer owns both declared allocators and is waiting on the
// standalone caller's source row. Only the writer may wait in this schedule.
async fn standalone_and_declared(raw: &PgPool, owner: &PgPool) -> anyhow::Result<()> {
    let head = ordered("composed-first", "composed", "source");
    let tenant = head.metadata().tenant_id();
    let claim = seed_claim(raw, &head).await?;
    let mut standalone = sql_tx(raw, tenant).await?;
    let _:i64=sqlx::query_scalar("SELECT lease_us FROM rss_transactional_messaging.outbox_lease($1::uuid,$2,$3::uuid,$4,0,NULL)")
        .bind(tenant.to_string()).bind(claim.0).bind(&claim.1).bind(claim.2).fetch_one(&mut *standalone).await?;
    let mut combined = sql_tx(raw, tenant).await?;
    sql_prepare(
        &mut combined,
        serde_json::json!([["composed", "source"], ["composed", "output"]]),
    )
    .await?;
    sql_append(
        &mut combined,
        &ordered("composed-result", "composed", "output"),
    )
    .await?;
    let pid = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *combined)
        .await?;
    let complete = finish_claim(combined, tenant, claim.clone(), true);
    let release = async {
        wait_lock(owner, pid).await?;
        let busy = settle(&mut standalone, tenant, &claim)
            .await
            .expect_err("source cannot wait for allocator");
        assert_eq!(code(&busy).as_deref(), Some("55P03"));
        standalone.rollback().await?;
        anyhow::Ok(())
    };
    tokio::try_join!(complete, release)?;
    Ok(())
}

async fn late_declaration(raw: &PgPool) -> anyhow::Result<()> {
    let head = ordered("implicit-first", "implicit", "a");
    let tenant = head.metadata().tenant_id();
    let claim = seed_claim(raw, &head).await?;
    let mut relay = sql_tx(raw, tenant).await?;
    assert_eq!(settle(&mut relay, tenant, &claim).await?, "settled");
    let error = sql_prepare(&mut relay, serde_json::json!([["implicit", "b"]]))
        .await
        .expect_err("late declaration");
    assert_eq!(code(&error).as_deref(), Some("PZ002"));
    relay.rollback().await?;
    finish_claim(sql_tx(raw, tenant).await?, tenant, claim, true).await
}

async fn stale_snapshot(raw: &PgPool) -> anyhow::Result<()> {
    let head = ordered("repeatable-first", "repeatable", "p");
    let next = ordered("repeatable-next", "repeatable", "p");
    let tenant = head.metadata().tenant_id();
    let pairs = serde_json::json!([["repeatable", "p"]]);
    let claim = seed_claim(raw, &head).await?;
    let mut old = fixed_snapshot(raw, tenant).await?;
    finish_claim(sql_tx(raw, tenant).await?, tenant, claim, true).await?;
    let error = sql_prepare(&mut old, pairs.clone())
        .await
        .expect_err("stale allocator snapshot");
    assert_eq!(code(&error).as_deref(), Some("40001"));
    old.rollback().await?;

    let mut retry = sql_tx(raw, tenant).await?;
    sql_prepare(&mut retry, pairs).await?;
    sql_append(&mut retry, &next).await?;
    let claimed:String = sqlx::query_scalar("SELECT message_id FROM rss_transactional_messaging.claim_outbox($1::uuid,'repeatable',1,60000)")
        .bind(tenant.to_string()).fetch_one(&mut *retry).await?;
    assert_eq!(claimed, next.id().as_str());
    retry.rollback().await?;
    Ok(())
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

async fn crossed_declarations(raw: &PgPool) -> anyhow::Result<()> {
    let domain = "crossed-heads";
    let tenant = message("a").metadata().tenant_id();
    let both = serde_json::json!([[domain, "a"], [domain, "b"]]);
    let mut seed = sql_tx(raw, tenant).await?;
    sql_prepare(&mut seed, both.clone()).await?;
    for key in ["a", "b"] {
        sql_append(
            &mut seed,
            &ordered(&format!("cross-head-{key}"), domain, key),
        )
        .await?;
    }
    let claims:Vec<(i64,String,i64)> = sqlx::query_as("SELECT seq,lease_token::text,(extract(epoch FROM lease_until)*1000000)::bigint FROM rss_transactional_messaging.claim_outbox($1::uuid,$2,2,60000) ORDER BY seq")
        .bind(tenant.to_string()).bind(domain).fetch_all(&mut *seed).await?;
    seed.commit().await?;
    assert_eq!(claims.len(), 2);
    let settle = "SELECT rss_transactional_messaging.settle_outbox($1::uuid,$2,$3::uuid,$4,'published',NULL)";
    let mut left = sql_tx(raw, tenant).await?;
    let mut right = sql_tx(raw, tenant).await?;
    for (tx, key) in [(&mut left, "b"), (&mut right, "a")] {
        sql_prepare(tx, serde_json::json!([[domain, key]])).await?;
        sql_append(tx, &ordered(&format!("cross-output-{key}"), domain, key)).await?;
    }
    let release = |mut tx: Transaction<'static, Postgres>,
                   (seq, token, until): (i64, String, i64)| async move {
        let error = sqlx::query(settle)
            .bind(tenant.to_string())
            .bind(seq)
            .bind(token)
            .bind(until)
            .execute(&mut *tx)
            .await
            .expect_err("source was not declared");
        assert_eq!(code(&error).as_deref(), Some("PZ002"));
        tx.rollback().await?;
        anyhow::Ok(())
    };
    tokio::try_join!(
        release(left, claims[0].clone()),
        release(right, claims[1].clone())
    )?;
    let complete = |claim: (i64, String, i64), key: &'static str, pairs: serde_json::Value| async move {
        let mut tx = sql_tx(raw, tenant).await?;
        sql_prepare(&mut tx, pairs).await?;
        sql_append(
            &mut tx,
            &ordered(&format!("cross-output-{key}"), domain, key),
        )
        .await?;
        let status: String = sqlx::query_scalar(settle)
            .bind(tenant.to_string())
            .bind(claim.0)
            .bind(claim.1)
            .bind(claim.2)
            .fetch_one(&mut *tx)
            .await?;
        assert_eq!(status, "settled");
        tx.commit().await?;
        anyhow::Ok(())
    };
    tokio::try_join!(
        complete(claims[0].clone(), "b", both),
        complete(
            claims[1].clone(),
            "a",
            serde_json::json!([[domain, "b"], [domain, "a"]])
        )
    )?;
    Ok(())
}
