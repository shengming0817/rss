use super::states::{fixture_sql, runtime, status};
use super::*;

async fn authorized(plan: Plan) -> anyhow::Result<AuthorizedPlan> {
    let clock = Timer::new();
    Ok(authorize_dr(&Allow, plan, &clock, clock.cutoff()).await?)
}
fn ended(plan: &AuthorizedPlan, operation: OperationId) -> anyhow::Result<Plan> {
    Ok(Plan::terminate(
        tenant(),
        operation,
        binding(7)?.storage(),
        Epoch::new(7)?,
        plan.request().operation(),
        plan.request().digest(),
    )?)
}
fn is_committed(attempt: LocalTxAttempt<Receipt, Error>) -> bool {
    attempt.fold(
        |_| true,
        |_| false,
        |_| false,
        |_| false,
        |_| false,
        |_| false,
    )
}
#[allow(clippy::cognitive_complexity)] // reason: exact termination, epoch races and old-capability assertions share one persisted plan.
pub async fn run(
    owner: &sqlx::PgPool,
    config: &PgConfig,
    operator: &PgConfig,
) -> anyhow::Result<()> {
    let store6 = Box::pin(PgDrStore::connect(
        operator.clone(),
        Timer::new(),
        binding(6)?,
    ))
    .await?;
    let version = Version::new(1)?;
    let members = ["published", "old-lease"]
        .into_iter()
        .map(|id| Member::Outbox {
            message: message(id).id().clone(),
            fingerprint: PendingMessage::new(message(id)).fingerprint(),
            version,
        })
        .collect();
    let p = authorized(Plan::new(
        tenant(),
        OperationId::new(),
        binding(6)?.storage(),
        Epoch::new(6)?,
        RestoreEvidence::new([3; 32], [4; 32])?,
        members,
    )?)
    .await?;
    committed(store6.apply(&p, deadline()).await)?;
    let (r7, outbox7) = runtime(config, 7).await?;
    let outbox7 = Arc::new(outbox7);
    let append = outbox7.clone();
    committed(
        r7.local_tx(tenant(), deadline(), move |tx| {
            Box::pin(async move {
                append
                    .append(tx, PendingMessage::new(message("terminate-successor")))
                    .await?;
                Ok(())
            })
        })
        .await,
    )?;
    let one = std::num::NonZeroUsize::new(1).ok_or_else(|| anyhow::anyhow!("limit"))?;
    let first = outbox7
        .claim_partition_heads(one, deadline())
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("first"))?;
    outbox7
        .settle(first, OutboxSettlement::Published(()), deadline())
        .await?;
    let old = outbox7
        .claim_partition_heads(one, deadline())
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("old"))?;
    // All original member windows expire. Keep the old capability across its lease expiry and cutover.
    fixture_sql(owner,7,"UPDATE rss_transactional_messaging.outbox SET automatic_retry_deadline=clock_timestamp()-interval '1 second' WHERE message_id IN ('published','old-lease'); UPDATE rss_transactional_messaging.dr_members SET lease_until=clock_timestamp()-interval '1 second' WHERE status='publishing'").await?;
    assert!(
        outbox7
            .claim_partition_heads(one, deadline())
            .await?
            .is_empty()
    );
    let store7 = Box::pin(PgDrStore::connect(
        operator.clone(),
        Timer::new(),
        binding(7)?,
    ))
    .await?;
    assert_eq!(
        status(&store7, &p).await?,
        vec![
            MemberStatus::Blocked(BlockReason::DeadlineExpired),
            MemberStatus::Completed
        ]
    );
    let before:serde_json::Value=sqlx::query_scalar("SELECT jsonb_agg(to_jsonb(o) ORDER BY seq) FROM rss_transactional_messaging.outbox o WHERE message_id IN ('published','old-lease')").fetch_one(owner).await?;
    for invalid in [
        Plan::terminate(
            tenant(),
            OperationId::new(),
            binding(7)?.storage(),
            Epoch::new(7)?,
            p.request().operation(),
            [9; 32],
        )?,
        Plan::terminate(
            tenant(),
            OperationId::new(),
            binding(7)?.storage(),
            Epoch::new(7)?,
            OperationId::new(),
            p.request().digest(),
        )?,
        Plan::terminate(
            tenant(),
            OperationId::new(),
            binding(7)?.storage(),
            Epoch::new(6)?,
            p.request().operation(),
            p.request().digest(),
        )?,
        Plan::terminate(
            tenant(),
            OperationId::new(),
            StorageIdentity::new([1; 16], [9; 16])?,
            Epoch::new(7)?,
            p.request().operation(),
            p.request().digest(),
        )?,
        Plan::terminate(
            rss_request_context::TenantId::parse("22222222-2222-2222-2222-222222222222")?,
            OperationId::new(),
            binding(7)?.storage(),
            Epoch::new(7)?,
            p.request().operation(),
            p.request().digest(),
        )?,
    ] {
        let invalid = authorized(invalid).await?;
        assert!(!is_committed(store7.apply(&invalid, deadline()).await));
    }
    let epoch: i64 = sqlx::query_scalar(
        "SELECT epoch FROM rss_transactional_messaging.tenant_epoch WHERE tenant_id=$1::uuid",
    )
    .bind(tenant().to_string())
    .fetch_one(owner)
    .await?;
    assert_eq!(epoch, 7, "invalid requests cannot advance the epoch");
    let a = authorized(ended(&p, OperationId::new())?).await?;
    let b = authorized(ended(&p, OperationId::new())?).await?;
    let racer7 = Box::pin(PgDrStore::connect(
        operator.clone(),
        Timer::new(),
        binding(7)?,
    ))
    .await?;
    store7.inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    racer7.inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    let (ar, br) = tokio::join!(store7.apply(&a, deadline()), racer7.apply(&b, deadline()));
    let unknown = |attempt: LocalTxAttempt<Receipt, Error>| {
        attempt.fold(
            |_| false,
            |_| false,
            |_| false,
            |_| false,
            |_| true,
            |_| false,
        )
    };
    let a_won = unknown(ar);
    let b_won = unknown(br);
    assert_ne!(
        a_won, b_won,
        "one termination commits with a lost acknowledgement; the other is fenced"
    );
    let (winner, loser) = if a_won { (&a, &b) } else { (&b, &a) };
    assert!(store7.receipt(loser, deadline()).await?.is_none());
    let receipt = store7
        .receipt(winner, deadline())
        .await?
        .ok_or_else(|| anyhow::anyhow!("termination receipt"))?;
    assert_eq!(receipt.epoch, Epoch::new(8)?);
    let next = Box::pin(PgDrStore::connect(
        operator.clone(),
        Timer::new(),
        binding(8)?,
    ))
    .await?;
    assert_eq!(
        committed(next.apply(winner, deadline()).await)?,
        receipt,
        "restart retries do not advance again"
    );
    assert!(
        next.progress(winner, deadline())
            .await?
            .ok_or_else(|| anyhow::anyhow!("termination progress"))?
            .members
            .is_empty()
    );
    assert_eq!(
        status(&next, &p).await?,
        vec![
            MemberStatus::Terminated(Some(BlockReason::DeadlineExpired)),
            MemberStatus::Completed
        ]
    );
    for (target, digest) in [
        (p.request().operation(), p.request().digest()),
        (winner.request().operation(), winner.request().digest()),
    ] {
        let invalid = authorized(Plan::terminate(
            tenant(),
            OperationId::new(),
            binding(8)?.storage(),
            Epoch::new(8)?,
            target,
            digest,
        )?)
        .await?;
        assert!(
            !is_committed(next.apply(&invalid, deadline()).await),
            "neither a stale plan nor a termination receipt is a current recovery target"
        );
    }
    let changed = authorized(Plan::terminate(
        tenant(),
        winner.request().operation(),
        binding(8)?.storage(),
        Epoch::new(7)?,
        p.request().operation(),
        [8; 32],
    )?)
    .await?;
    assert!(
        !is_committed(next.apply(&changed, deadline()).await),
        "same operation cannot authorize a different digest"
    );
    let after:serde_json::Value=sqlx::query_scalar("SELECT jsonb_agg(to_jsonb(o) ORDER BY seq) FROM rss_transactional_messaging.outbox o WHERE message_id IN ('published','old-lease')").fetch_one(owner).await?;
    assert_eq!(
        before, after,
        "termination preserves Published, authored facts and original deadlines"
    );
    assert!(
        outbox7
            .settle(old, OutboxSettlement::Published(()), deadline())
            .await
            .is_err()
    );
    assert!(
        outbox7
            .claim_partition_heads(one, deadline())
            .await
            .is_err()
    );
    let (r8, outbox8) = runtime(config, 8).await?;
    let successor = outbox8
        .claim_partition_heads(one, deadline())
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("unblocked successor"))?;
    assert_eq!(
        PgOutboxStore::<()>::message(&successor)
            .envelope()
            .id()
            .as_str(),
        "terminate-successor"
    );
    outbox8
        .settle(successor, OutboxSettlement::Published(()), deadline())
        .await?;
    r7.close().await;
    r8.close().await;
    store6.close().await;
    store7.close().await;
    racer7.close().await;
    next.close().await;
    Ok(())
}
