use super::*;
use rss_transactional_messaging::message::MessageFingerprint;

// Write the 0006 durable wire shape, without using a runtime that requires 0007 admission.
pub async fn seed(owner: &sqlx::PgPool) -> anyhow::Result<(serde_json::Value, serde_json::Value)> {
    let msg = message("published");
    let m = msg.metadata();
    let envelope = serde_json::json!({
        "id": msg.id().as_str(), "tenant": m.tenant_id().to_string(), "occurred_at": m.occurred_at().unix_seconds(),
        "domain": m.domain().as_str(), "route": m.route().as_str(), "contract": m.contract().id().as_str(),
        "version": m.contract().version().to_string(), "schema": m.contract().schema_digest().as_str(),
        "correlation": m.correlation().map(String::from), "partition": m.partition().map(|p|p.key().as_str()),
        "causation": m.causation().map(|id|id.as_str()), "attributes": m.attributes().collect::<std::collections::BTreeMap<_,_>>(),
        "trace": msg.transport_context().trace(), "tenant_authority": msg.transport_context().tenant_authority(), "payload": msg.payload()
    });
    sqlx::query("INSERT INTO rss_transactional_messaging.outbox(tenant_id,message_id,domain,partition_key,envelope,fingerprint,status,automatic_retry_deadline) VALUES($1::uuid,'published','orders',$2,$3,$4,'published',clock_timestamp()+interval '1 hour')")
        .bind(tenant().to_string()).bind(m.partition().map(|p|p.key().as_str())).bind(envelope).bind(MessageFingerprint::of(&msg).as_bytes().as_slice()).execute(owner).await?;
    seed_terminal(owner).await?;
    facts(owner).await
}
pub async fn facts(owner: &sqlx::PgPool) -> anyhow::Result<(serde_json::Value, serde_json::Value)> {
    let outbox = sqlx::query_scalar("SELECT to_jsonb(o)-'claim_epoch'-'claim_lineage' FROM rss_transactional_messaging.outbox o WHERE message_id='published'").fetch_one(owner).await?;
    let inbox = sqlx::query_scalar("SELECT to_jsonb(i)-'claim_epoch'-'claim_lineage' FROM rss_transactional_messaging.inbox i WHERE message_id='legacy-terminal'").fetch_one(owner).await?;
    Ok((outbox, inbox))
}

pub async fn seed_terminal(owner: &sqlx::PgPool) -> anyhow::Result<()> {
    let msg = message("legacy-terminal");
    sqlx::query("INSERT INTO rss_transactional_messaging.inbox(tenant_id,message_id,consumer_group,contract,lease_token,lease_until,fingerprint,disposition) VALUES($1::uuid,'legacy-terminal','test',$2,gen_random_uuid(),clock_timestamp()-interval '1 hour',$3,'succeeded')")
        .bind(tenant().to_string()).bind(serde_json::to_string(&(msg.metadata().contract().id().as_str(), msg.metadata().contract().version().to_string(), msg.metadata().contract().schema_digest().as_str()))?).bind(MessageFingerprint::of(&msg).as_bytes().as_slice()).execute(owner).await?;
    Ok(())
}

#[allow(clippy::cognitive_complexity)] // reason: historical upgrade, rollback and unsupported-data evidence share one isolated fixture.
pub async fn install_current(owner: sqlx::PgPool) -> anyhow::Result<sqlx::PgPool> {
    let archive_schema = MIGRATION_SQL
        .strip_suffix(DR_UPGRADE_SQL)
        .ok_or_else(|| anyhow::anyhow!("DR upgrade boundary"))?;
    sqlx::raw_sql(archive_schema).execute(&owner).await?;
    let legacy = upgrade::seed(&owner).await?;
    let historical_dr = DR_UPGRADE_SQL
        .strip_suffix(OUTBOX_PARTITION_UPGRADE_SQL)
        .ok_or_else(|| anyhow::anyhow!("partition upgrade boundary"))?;
    let mut upgrade = owner.begin().await?;
    sqlx::raw_sql(historical_dr).execute(&mut *upgrade).await?;
    upgrade.rollback().await?;
    assert!(
        sqlx::query_scalar::<_, Option<String>>(
            "SELECT to_regclass('rss_transactional_messaging.dr_plans')::text"
        )
        .fetch_one(&owner)
        .await?
        .is_none()
    );
    assert_eq!(
        upgrade::facts(&owner).await?,
        legacy,
        "DDL rollback preserves old business records"
    );
    sqlx::raw_sql(historical_dr).execute(&owner).await?;
    assert_eq!(
        upgrade::facts(&owner).await?,
        legacy,
        "upgrade preserves terminal evidence and all Published facts"
    );
    // Keep the historical DR proof at its original schema boundary. New partition
    // order cannot be inferred from existing seq values, even for Published rows.
    let mut rejected = owner.begin().await?;
    let error = sqlx::raw_sql(OUTBOX_PARTITION_UPGRADE_SQL)
        .execute(&mut *rejected)
        .await
        .err()
        .ok_or_else(|| anyhow::anyhow!("old ordered data must be rejected"))?;
    assert_eq!(
        error.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("23514")
    );
    rejected.rollback().await?;
    assert_eq!(upgrade::facts(&owner).await?, legacy);
    sqlx::query("CREATE DATABASE partition_order_current")
        .execute(&owner)
        .await?;
    let options = (*owner.connect_options())
        .clone()
        .database("partition_order_current");
    owner.close().await;
    let owner = PgPoolOptions::new()
        .max_connections(6)
        .connect_with(options)
        .await?;
    sqlx::raw_sql(MIGRATION_SQL).execute(&owner).await?;
    sqlx::raw_sql("INSERT INTO rss_transactional_messaging.storage_lineage VALUES(true,decode(repeat('01',16),'hex'),decode(repeat('02',16),'hex')); INSERT INTO rss_transactional_messaging.tenant_epoch VALUES('11111111-1111-1111-1111-111111111111',1); GRANT USAGE ON SCHEMA rss_transactional_messaging TO dr_runtime,dr_operator; GRANT SELECT ON rss_transactional_messaging.policy TO dr_runtime; GRANT SELECT,INSERT,UPDATE,DELETE ON rss_transactional_messaging.inbox TO dr_runtime; GRANT SELECT ON rss_transactional_messaging.outbox TO dr_runtime; GRANT EXECUTE ON FUNCTION rss_transactional_messaging.prepare_outbox_partitions(jsonb),rss_transactional_messaging.append_outbox(text,text,text,jsonb,bytea) TO dr_runtime; GRANT EXECUTE ON FUNCTION rss_transactional_messaging.check_execution() TO dr_runtime,dr_operator; GRANT EXECUTE ON FUNCTION rss_transactional_messaging.claim_outbox(uuid,text,integer,bigint),rss_transactional_messaging.outbox_lease(uuid,bigint,uuid,bigint,bigint,uuid),rss_transactional_messaging.settle_outbox(uuid,bigint,uuid,bigint,text,uuid) TO dr_runtime; GRANT EXECUTE ON FUNCTION rss_transactional_messaging.apply_dr(uuid,bytea,text,jsonb,jsonb,bigint),rss_transactional_messaging.read_dr(uuid,bytea) TO dr_operator;").execute(&owner).await?;
    upgrade::seed_terminal(&owner).await?;
    Ok(owner)
}

pub async fn publish_current(
    runtime: Arc<PgRuntime>,
    outbox: Arc<PgOutboxStore<()>>,
) -> anyhow::Result<()> {
    let published = message("published");
    let writer = outbox.clone();
    committed(
        runtime
            .local_tx(tenant(), deadline(), move |tx| {
                Box::pin(async move {
                    tx.prepare_outbox_partitions(
                        &published
                            .metadata()
                            .partition()
                            .cloned()
                            .into_iter()
                            .collect::<Vec<_>>(),
                    )
                    .await?;
                    writer
                        .append(tx, PendingMessage::new(published))
                        .await
                        .map_err(Into::into)
                })
            })
            .await,
    )?;
    let published = outbox
        .claim_partition_heads(std::num::NonZeroUsize::MIN, deadline())
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("published seed"))?;
    outbox
        .settle(published, OutboxSettlement::Published(()), deadline())
        .await?;
    Ok(())
}
