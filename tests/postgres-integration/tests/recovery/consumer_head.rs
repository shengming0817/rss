use super::*;
use rss_transactional_messaging::{
    observability::{TransactionalMessagingEmitter, TransactionalMessagingObservation},
    transport::Delivery,
};
use rss_transactional_messaging_runtime::consumer::{
    ConsumerExecution, ProcessingDisposition, consume_once,
};
use rss_transactional_messaging_testkit::memory::RecordingSettlement;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Count(AtomicUsize);
impl TransactionalMessagingEmitter for Count {
    fn emit(&self, _: TransactionalMessagingObservation) {
        // The scenario inspects real settlements and counts handler entry directly.
    }
}
impl PgConsumerEffect<Vec<u8>> for &Count {
    async fn apply(
        &self,
        _: &mut PgTransaction<'_>,
        _: &MessageEnvelope<Vec<u8>>,
        _: OperationDeadline,
    ) -> Result<TerminalDisposition, PgConsumerEffectFailure> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(TerminalDisposition::Succeeded)
    }
}

async fn deliver(
    runtime: &Arc<PgRuntime>,
    message: MessageEnvelope<Vec<u8>>,
    count: &Count,
) -> anyhow::Result<(ProcessingDisposition, Vec<SettlementKind>)> {
    let meta = message.metadata();
    let sub = SubscriptionIdentity::new(
        meta.domain().clone(),
        meta.route().clone(),
        meta.contract().clone(),
    );
    let timer = Timer::new();
    let execution = ConsumerExecution::new(
        ConsumerGroup::parse("test")?,
        &Validator,
        &sub,
        &timer,
        ConsumerExecutionPolicy::new(
            RetryPolicy::STANDARD,
            ExecutionBudget::new(Duration::from_secs(2), Duration::from_millis(400))?,
        ),
        count,
    );
    let inbox = inbox(runtime)?;
    let settlement = RecordingSettlement::new();
    let result = consume_once(
        &inbox,
        &PgConsumerTx::receipt_only(runtime.clone(), count),
        &execution,
        Delivery::new(message, settlement.clone()),
    )
    .await?;
    Ok((result, settlement.settlements()))
}
fn inbox(runtime: &Arc<PgRuntime>) -> anyhow::Result<PgInboxStore> {
    Ok(PgInboxStore::new(
        runtime.clone(),
        LeaseRenewalPolicy::from_ttl(Duration::from_secs(30))?,
    )?)
}
async fn connect(config: &PgConfig) -> anyhow::Result<Arc<PgRuntime>> {
    Ok(Arc::new(
        PgRuntime::connect(config.clone(), Timer::new(), fence_fixture::storage()).await?,
    ))
}
pub(super) async fn run(
    config: &PgConfig,
    store: &PgRecoveryStore<Key>,
    owner: &sqlx::PgPool,
) -> anyhow::Result<()> {
    for (key, protected) in [("receipt-head", false), ("protected-head", true)] {
        let original = message_in_partition(&format!("{key}-a"), key);
        let successor = message_in_partition(&format!("{key}-b"), key);
        let first = connect(config).await?;
        let other = connect(config).await?;
        let holder = inbox(&first)?;
        let verified = binding(&original)?;
        let contender = inbox(&other)?;
        let successor_binding = binding(&successor)?;
        let IdempotencyDisposition::Acquired(initial) = holder.claim(&verified, deadline()).await?
        else {
            anyhow::bail!("first claim")
        };
        assert!(matches!(
            contender.claim(&successor_binding, deadline()).await?,
            IdempotencyDisposition::PartitionBlocked
        ));
        holder.release(initial, deadline()).await?;
        assert!(matches!(
            contender.claim(&successor_binding, deadline()).await?,
            IdempotencyDisposition::PartitionBlocked
        ));
        let IdempotencyDisposition::Acquired(head) = contender.claim(&verified, deadline()).await?
        else {
            anyhow::bail!("head reclaim")
        };
        let status = if protected {
            let capture =
                PgRecoveryCapture::new(other.clone(), Arc::new(Key(1)), deadline()).await?;
            PgConsumerTx::with_recovery(Reject, capture)
                .execute(&head, &original, verified.receipt_intent(), deadline())
                .await
                .status()
        } else {
            PgConsumerTx::receipt_only(other.clone(), Reject)
                .execute(&head, &original, verified.receipt_intent(), deadline())
                .await
                .status()
        };
        assert_eq!(status, TransactionalMessagingTransactionStatus::Committed);
        first.close().await;
        other.close().await;
        let restarted = connect(config).await?;
        let count = Count(AtomicUsize::new(0));
        assert_eq!(
            deliver(&restarted, successor.clone(), &count).await?,
            (
                ProcessingDisposition::PartitionBlocked,
                vec![SettlementKind::Requeue]
            )
        );
        assert_eq!(count.0.load(Ordering::SeqCst), 0);
        let reject =
            ProcessingDisposition::Duplicate(TerminalDisposition::Rejected(RejectKind::Permanent));
        assert_eq!(
            deliver(&restarted, original.clone(), &count).await?,
            (reject, vec![SettlementKind::Reject])
        );
        let independent = message_in_partition(&format!("{key}-independent"), "other-key");
        assert_eq!(
            deliver(&restarted, independent, &count).await?.0,
            ProcessingDisposition::Committed(TerminalDisposition::Succeeded)
        );
        resolve(store, owner, &original, &restarted, &successor, &count).await?;
        assert_eq!(deliver(&restarted, original, &count).await?.0, reject);
        assert_eq!(
            deliver(&restarted, successor, &count).await?.0,
            ProcessingDisposition::Duplicate(TerminalDisposition::Succeeded)
        );
        assert_eq!(count.0.load(Ordering::SeqCst), 2);
        restarted.close().await;
    }
    Ok(())
}

async fn resolve(
    store: &PgRecoveryStore<Key>,
    owner: &sqlx::PgPool,
    message: &MessageEnvelope<Vec<u8>>,
    runtime: &Arc<PgRuntime>,
    successor: &MessageEnvelope<Vec<u8>>,
    count: &Count,
) -> anyhow::Result<()> {
    let entries = page(
        store,
        Query::list(tenant(), Source::ConsumerHead, 128, None)?,
    )
    .await?
    .entries;
    let entry = entries
        .into_iter()
        .find(|entry| entry.message == *message.id())
        .context("missing Inbox head")?;
    let Target::ConsumerHead(head) = &entry.target else {
        anyhow::bail!("head kind")
    };
    let accepted = Action::Resolve(Resolution::AcceptedGap);
    let authorized = request(entry.target.clone(), entry.version, accepted.clone()).await?;
    let mut wrong = head.clone();
    wrong.partition = PartitionKey::parse("different")?;
    let missing = page(
        store,
        Query::inspect(tenant(), Target::ConsumerHead(wrong.clone())),
    )
    .await?;
    assert!(missing.entries.is_empty());
    let foreign = request(Target::ConsumerHead(wrong), entry.version, accepted.clone()).await?;
    let execution = crate::execution(tenant(), 1);
    assert_eq!(
        failure(store.mutate(execution, &foreign, deadline()).await),
        Some(Error::Conflict)
    );
    let mut tx = owner.begin().await?;
    sqlx::query("SET LOCAL ROLE recovery_runtime")
        .execute(&mut *tx)
        .await?;
    assert_eq!(
        sqlx::query("DELETE FROM rss_transactional_messaging.inbox WHERE message_id=$1")
            .bind(message.id().as_str())
            .execute(&mut *tx)
            .await?
            .rows_affected(),
        0
    );
    assert!(sqlx::query("UPDATE rss_transactional_messaging.inbox SET resolved_by=gen_random_uuid() WHERE message_id=$1").bind(message.id().as_str()).execute(&mut *tx).await.is_err());
    tx.rollback().await?;
    // Keep the resolver between the Inbox update and its mandatory receipt INSERT.
    let mut gate = owner.begin().await?;
    sqlx::query("LOCK TABLE rss_transactional_messaging.recovery_operations IN SHARE MODE")
        .execute(&mut *gate)
        .await?;
    let gate_pid = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *gate)
        .await?;
    let race = async {
        let resolver_pid = waiter(owner, gate_pid).await?;
        let unblock = async {
            waiter(owner, resolver_pid).await?;
            assert_eq!(
                count.0.load(Ordering::SeqCst),
                1,
                "successor has not entered its effect"
            );
            gate.commit().await?;
            anyhow::Ok(())
        };
        let (delivery, ()) = tokio::try_join!(deliver(runtime, successor.clone(), count), unblock)?;
        anyhow::Ok(delivery)
    };
    let (receipt, delivery) = tokio::join!(store.mutate(execution, &authorized, deadline()), race);
    assert_eq!(committed(receipt)?.outcome, Outcome::Resolved);
    assert_eq!(
        delivery?.0,
        ProcessingDisposition::Committed(TerminalDisposition::Succeeded)
    );
    assert_eq!(
        committed(store.mutate(execution, &authorized, deadline()).await)?
            .version
            .get(),
        2
    );
    let stale = request(entry.target.clone(), entry.version, accepted).await?;
    assert_eq!(
        failure(store.mutate(execution, &stale, deadline()).await),
        Some(Error::Conflict)
    );
    let inspected = page(store, Query::inspect(tenant(), entry.target)).await?;
    assert!(
        matches!(inspected.entries[0].details,Details::ConsumerHead { resolved_by: Some(id),.. } if id==authorized.request().operation())
    );
    Ok(())
}

async fn waiter(owner: &sqlx::PgPool, blocker: i32) -> anyhow::Result<i32> {
    testkit::await_try(Duration::from_secs(2), async || {
        Ok::<_, anyhow::Error>(sqlx::query_scalar(
            "SELECT pid FROM pg_stat_activity WHERE wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid)) LIMIT 1",
        ).bind(blocker).fetch_optional(owner).await?)
    }).await
}
