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
    let msg = message("legacy-terminal");
    sqlx::query("INSERT INTO rss_transactional_messaging.inbox(tenant_id,message_id,consumer_group,contract,lease_token,lease_until,fingerprint,disposition) VALUES($1::uuid,'legacy-terminal','test',$2,gen_random_uuid(),clock_timestamp()-interval '1 hour',$3,'succeeded')")
        .bind(tenant().to_string()).bind(serde_json::to_string(&(msg.metadata().contract().id().as_str(), msg.metadata().contract().version().to_string(), msg.metadata().contract().schema_digest().as_str()))?).bind(MessageFingerprint::of(&msg).as_bytes().as_slice()).execute(owner).await?;
    facts(owner).await
}
pub async fn facts(owner: &sqlx::PgPool) -> anyhow::Result<(serde_json::Value, serde_json::Value)> {
    let outbox = sqlx::query_scalar("SELECT to_jsonb(o)-'claim_epoch'-'claim_lineage' FROM rss_transactional_messaging.outbox o WHERE message_id='published'").fetch_one(owner).await?;
    let inbox = sqlx::query_scalar("SELECT to_jsonb(i)-'claim_epoch'-'claim_lineage' FROM rss_transactional_messaging.inbox i WHERE message_id='legacy-terminal'").fetch_one(owner).await?;
    Ok((outbox, inbox))
}
