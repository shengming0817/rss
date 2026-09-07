use super::*;
pub(super) async fn fixture_sql(
    owner: &sqlx::PgPool,
    epoch: i64,
    sql: &'static str,
) -> anyhow::Result<()> {
    let mut tx = owner.begin().await?;
    sqlx::query("SELECT set_config('rss.execution_epoch',$1,true)")
        .bind(epoch.to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::raw_sql(sql).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}
pub(super) async fn runtime(
    config: &PgConfig,
    epoch: i64,
) -> anyhow::Result<(Arc<PgRuntime>, PgOutboxStore<()>)> {
    let r = Arc::new(
        Box::pin(PgRuntime::connect(
            config.clone(),
            Timer::new(),
            binding(epoch)?,
        ))
        .await?,
    );
    let outbox = PgOutboxStore::new(
        r.clone(),
        rss_transactional_messaging::message::MessagingDomain::parse("orders")?,
        budget()?,
    )?;
    Ok((r, outbox))
}
pub(super) async fn status(
    store: &PgDrStore,
    p: &AuthorizedPlan,
) -> anyhow::Result<Vec<MemberStatus>> {
    Ok(store
        .progress(p, deadline())
        .await?
        .ok_or_else(|| anyhow::anyhow!("progress"))?
        .members)
}
#[allow(clippy::cognitive_complexity)] // reason: negative fact cases assert atomic epoch and receipt behavior on one database.
async fn invalid_facts(owner: &sqlx::PgPool, store: &PgDrStore) -> anyhow::Result<()> {
    let reference = plan("published", 3, OperationId::new()).await?;
    for member in [
        Member::Outbox {
            message: reference.request().members()[0].message().clone(),
            fingerprint: rss_transactional_messaging::message::MessageFingerprint::from_bytes(
                [9; 32],
            ),
            version: Version::new(1)?,
        },
        Member::Outbox {
            message: reference.request().members()[0].message().clone(),
            fingerprint: reference.request().members()[0].fingerprint(),
            version: Version::new(2)?,
        },
    ] {
        let clock = Timer::new();
        let p = authorize_dr(
            &Allow,
            Plan::new(
                tenant(),
                OperationId::new(),
                binding(3)?.storage(),
                Epoch::new(3)?,
                RestoreEvidence::new([3; 32], [4; 32])?,
                vec![member],
            )?,
            &clock,
            clock.cutoff(),
        )
        .await?;
        assert!(store.apply(&p, deadline()).await.fold(
            |_| false,
            |_| false,
            |e| e == Error::Conflict,
            |_| false,
            |_| false,
            |_| false
        ));
        assert!(store.receipt(&p, deadline()).await?.is_none());
    }
    // Persist a fixture copy outside a pooled session's temporary namespace.
    fixture_sql(owner,3,"CREATE TABLE public.dr_original AS SELECT envelope,fingerprint,automatic_retry_deadline FROM rss_transactional_messaging.outbox WHERE message_id='published'; UPDATE rss_transactional_messaging.outbox SET automatic_retry_deadline=clock_timestamp()-interval '1 second' WHERE message_id='published'").await?;
    assert!(store.apply(&reference, deadline()).await.fold(
        |_| false,
        |_| false,
        |e| e == Error::Expired,
        |_| false,
        |_| false,
        |_| false
    ));
    assert!(store.receipt(&reference, deadline()).await?.is_none());
    fixture_sql(owner,3,"UPDATE rss_transactional_messaging.outbox SET automatic_retry_deadline=(SELECT automatic_retry_deadline FROM public.dr_original) WHERE message_id='published'").await?;
    let epoch: i64 = sqlx::query_scalar(
        "SELECT epoch FROM rss_transactional_messaging.tenant_epoch WHERE tenant_id=$1::uuid",
    )
    .bind(tenant().to_string())
    .fetch_one(owner)
    .await?;
    assert_eq!(epoch, 3);
    Ok(())
}
#[allow(clippy::cognitive_complexity)] // reason: ordered DR states and partition admission are one observable database protocol.
pub async fn run(
    owner: &sqlx::PgPool,
    config: &PgConfig,
    operator: &PgConfig,
) -> anyhow::Result<()> {
    let store3 = Box::pin(PgDrStore::connect(
        operator.clone(),
        Timer::new(),
        binding(3)?,
    ))
    .await?;
    Box::pin(invalid_facts(owner, &store3)).await?;
    let p = plan("published", 3, OperationId::new()).await?;
    committed(store3.apply(&p, deadline()).await)?;
    let (r4, outbox4) = runtime(config, 4).await?;
    let two = std::num::NonZeroUsize::new(2).ok_or_else(|| anyhow::anyhow!("limit"))?;
    let batch = outbox4.claim_partition_heads(two, deadline()).await?;
    assert_eq!(
        batch.len(),
        1,
        "DR head prevents successor admission in the same batch"
    );
    assert_eq!(status(&store3, &p).await?, vec![MemberStatus::Publishing]);
    let claim = batch
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("claim"))?;
    assert!(
        outbox4
            .claim_partition_heads(two, deadline())
            .await?
            .is_empty()
    );
    outbox4
        .settle(claim, OutboxSettlement::Retry, deadline())
        .await?;
    assert_eq!(status(&store3, &p).await?, vec![MemberStatus::Pending]);
    assert!(
        outbox4
            .claim_partition_heads(two, deadline())
            .await?
            .is_empty()
    );
    fixture_sql(owner,4,"UPDATE rss_transactional_messaging.dr_members SET retry_after=clock_timestamp()-interval '1 second' WHERE status='pending'").await?;
    let claim = outbox4
        .claim_partition_heads(two, deadline())
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("retry"))?;
    outbox4
        .settle(claim, OutboxSettlement::DeadLetter, deadline())
        .await?;
    assert_eq!(
        status(&store3, &p).await?,
        vec![MemberStatus::Blocked(BlockReason::PermanentPublishFailure)]
    );
    assert!(
        outbox4
            .claim_partition_heads(two, deadline())
            .await?
            .is_empty()
    );
    let store4 = Box::pin(PgDrStore::connect(
        operator.clone(),
        Timer::new(),
        binding(4)?,
    ))
    .await?;
    let expired = plan("published", 4, OperationId::new()).await?;
    committed(store4.apply(&expired, deadline()).await)?;
    let store5 = Box::pin(PgDrStore::connect(
        operator.clone(),
        Timer::new(),
        binding(5)?,
    ))
    .await?;
    assert_eq!(
        status(&store5, &p).await?,
        vec![MemberStatus::Superseded(Some(
            BlockReason::PermanentPublishFailure
        ))]
    );
    fixture_sql(owner,5,"UPDATE rss_transactional_messaging.outbox SET automatic_retry_deadline=clock_timestamp()-interval '1 second' WHERE message_id='published'").await?;
    let (r5, outbox5) = runtime(config, 5).await?;
    assert!(
        outbox5
            .claim_partition_heads(two, deadline())
            .await?
            .is_empty()
    );
    assert_eq!(
        status(&store5, &expired).await?,
        vec![MemberStatus::Blocked(BlockReason::DeadlineExpired)]
    );
    fixture_sql(owner,5,"UPDATE rss_transactional_messaging.outbox SET automatic_retry_deadline=(SELECT automatic_retry_deadline FROM public.dr_original) WHERE message_id='published'").await?;
    let completed = plan("published", 5, OperationId::new()).await?;
    committed(store5.apply(&completed, deadline()).await)?;
    let (r6, outbox6) = runtime(config, 6).await?;
    let claim = outbox6
        .claim_partition_heads(two, deadline())
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("head"))?;
    outbox6
        .settle(claim, OutboxSettlement::Published(()), deadline())
        .await?;
    assert_eq!(
        status(&store5, &completed).await?,
        vec![MemberStatus::Completed]
    );
    let successor = outbox6.claim_partition_heads(two, deadline()).await?;
    assert_eq!(successor.len(), 1);
    let claim = successor
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("successor"))?;
    assert_eq!(
        PgOutboxStore::<()>::message(&claim)
            .envelope()
            .id()
            .as_str(),
        "old-lease"
    );
    outbox6
        .settle(claim, OutboxSettlement::Published(()), deadline())
        .await?;
    let unchanged:bool=sqlx::query_scalar("SELECT o.status='published' AND o.envelope=r.envelope AND o.fingerprint=r.fingerprint AND o.automatic_retry_deadline=r.automatic_retry_deadline FROM rss_transactional_messaging.outbox o CROSS JOIN public.dr_original r WHERE o.message_id='published'").fetch_one(owner).await?;
    assert!(unchanged);
    r4.close().await;
    r5.close().await;
    r6.close().await;
    store3.close().await;
    store4.close().await;
    store5.close().await;
    Ok(())
}
