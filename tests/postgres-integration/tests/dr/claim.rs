use super::*;

#[allow(clippy::cognitive_complexity)] // reason: ordered two-tenant failure and settlement assertions share one database fixture.
pub async fn check(
    owner: &sqlx::PgPool,
    runtime: Arc<PgRuntime>,
    other: rss_request_context::TenantId,
) -> anyhow::Result<()> {
    let outbox = Arc::new(PgOutboxStore::<()>::new(
        runtime.clone(),
        rss_transactional_messaging::message::MessagingDomain::parse("orders")?,
        budget()?,
    )?);
    let append = outbox.clone();
    committed(
        runtime
            .local_tx(tenant(), deadline(), move |tx| {
                Box::pin(async move {
                    append
                        .append(tx, PendingMessage::new(message("partial-claim")))
                        .await?;
                    Ok(())
                })
            })
            .await,
    )?;
    // A malformed later tenant must not make an earlier committed claim disappear.
    let mut tx = owner.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(other.to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO rss_transactional_messaging.outbox(tenant_id,message_id,domain,envelope,fingerprint) SELECT $1::uuid,message_id,domain,'{}'::jsonb,fingerprint FROM rss_transactional_messaging.outbox WHERE message_id='partial-claim'").bind(other.to_string()).execute(&mut *tx).await?;
    tx.commit().await?;
    let limit = std::num::NonZeroUsize::new(2).ok_or_else(|| anyhow::anyhow!("limit"))?;
    let batch = outbox.claim_partition_heads(limit, deadline()).await?;
    let claims = batch.into_iter().collect::<Vec<_>>();
    assert_eq!(claims.len(), 1);
    assert!(
        outbox
            .claim_partition_heads(limit, deadline())
            .await
            .is_err(),
        "rotating next batch reaches the malformed tenant"
    );
    for claim in claims {
        outbox
            .settle(claim, OutboxSettlement::Published(()), deadline())
            .await?;
    }
    sqlx::query("DELETE FROM rss_transactional_messaging.outbox WHERE message_id='partial-claim' AND tenant_id=$1::uuid").bind(tenant().to_string()).execute(owner).await?;
    let mut tx = owner.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(other.to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM rss_transactional_messaging.outbox WHERE message_id='partial-claim'")
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}
