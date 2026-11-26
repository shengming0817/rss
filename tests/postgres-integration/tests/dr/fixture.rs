//! Current-schema DR fixtures and durable terminal facts.
use super::*;
use rss_transactional_messaging::message::MessageFingerprint;

pub async fn seed_terminal(owner: &sqlx::PgPool) -> anyhow::Result<()> {
    let msg = message("legacy-terminal");
    sqlx::query("INSERT INTO rss_transactional_messaging.inbox(tenant_id,message_id,consumer_group,contract,lease_token,lease_until,fingerprint,disposition) VALUES($1::uuid,'legacy-terminal','test',$2,gen_random_uuid(),clock_timestamp()-interval '1 hour',$3,'succeeded')")
        .bind(tenant().to_string()).bind(serde_json::to_string(&(msg.metadata().contract().id().as_str(), msg.metadata().contract().version().to_string(), msg.metadata().contract().schema_digest().as_str()))?).bind(MessageFingerprint::of(&msg).as_bytes().as_slice()).execute(owner).await?;
    Ok(())
}

pub async fn install_current(owner: sqlx::PgPool) -> anyhow::Result<sqlx::PgPool> {
    sqlx::raw_sql(MIGRATION_SQL).execute(&owner).await?;
    sqlx::raw_sql("INSERT INTO rss_transactional_messaging.storage_lineage VALUES(true,decode(repeat('01',16),'hex'),decode(repeat('02',16),'hex')); INSERT INTO rss_transactional_messaging.tenant_epoch VALUES('11111111-1111-1111-1111-111111111111',1); GRANT USAGE ON SCHEMA rss_transactional_messaging TO dr_runtime,dr_operator; GRANT SELECT ON rss_transactional_messaging.policy TO dr_runtime; GRANT SELECT,INSERT,UPDATE,DELETE ON rss_transactional_messaging.inbox TO dr_runtime; GRANT SELECT ON rss_transactional_messaging.outbox TO dr_runtime; GRANT EXECUTE ON FUNCTION rss_transactional_messaging.prepare_outbox_partitions(jsonb),rss_transactional_messaging.append_outbox(bytea,jsonb) TO dr_runtime; GRANT EXECUTE ON FUNCTION rss_transactional_messaging.check_execution() TO dr_runtime,dr_operator; GRANT EXECUTE ON FUNCTION rss_transactional_messaging.claim_outbox(uuid,text,integer,integer,bigint),rss_transactional_messaging.next_outbox_wakeup(uuid,text),rss_transactional_messaging.outbox_lease(uuid,bigint,uuid,bigint,bigint,uuid),rss_transactional_messaging.settle_outbox(uuid,bigint,uuid,bigint,text,uuid) TO dr_runtime; GRANT EXECUTE ON FUNCTION rss_transactional_messaging.apply_dr(uuid,bytea,text,jsonb,jsonb,bigint),rss_transactional_messaging.read_dr(uuid,bytea) TO dr_operator;").execute(&owner).await?;
    seed_terminal(&owner).await?;
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
            .local_tx(crate::execution(tenant(), 1), deadline(), move |tx| {
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
        .claim_partition_heads(crate::binding(1)?, std::num::NonZeroUsize::MIN, deadline())
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("published seed"))?;
    outbox
        .settle(published, OutboxSettlement::Published(()), deadline())
        .await?;
    Ok(())
}
