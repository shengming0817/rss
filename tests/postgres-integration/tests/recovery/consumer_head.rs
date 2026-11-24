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
    deliver_with_ttl(runtime, message, count, Duration::from_secs(30)).await
}

async fn deliver_with_ttl(
    runtime: &Arc<PgRuntime>,
    message: MessageEnvelope<Vec<u8>>,
    count: &Count,
    ttl: Duration,
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
    let inbox = PgInboxStore::new(runtime.clone(), LeaseRenewalPolicy::from_ttl(ttl)?)?;
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
        if protected {
            sqlx::query(
                "ALTER ROLE recovery_runtime SET default_transaction_isolation TO 'serializable'",
            )
            .execute(owner)
            .await?;
        }
        reject_after_takeover(owner, config, &original, &successor, protected).await?;
        let restarted = connect(config).await?;
        let count = Count(AtomicUsize::new(0));
        assert_blocked(&restarted, &original, &successor, key, &count).await?;
        resolve(store, owner, &original, &restarted, &successor, &count).await?;
        assert_eq!(deliver(&restarted, original, &count).await?.0, rejected());
        assert_eq!(
            deliver(&restarted, successor, &count).await?.0,
            ProcessingDisposition::Duplicate(TerminalDisposition::Succeeded)
        );
        assert_eq!(count.0.load(Ordering::SeqCst), 2);
        restarted.close().await;
    }
    sqlx::query("ALTER ROLE recovery_runtime RESET default_transaction_isolation")
        .execute(owner)
        .await?;
    Ok(())
}

fn rejected() -> ProcessingDisposition {
    ProcessingDisposition::Duplicate(TerminalDisposition::Rejected(RejectKind::Permanent))
}
async fn reject_after_takeover(
    owner: &sqlx::PgPool,
    config: &PgConfig,
    original: &MessageEnvelope<Vec<u8>>,
    successor: &MessageEnvelope<Vec<u8>>,
    protected: bool,
) -> anyhow::Result<()> {
    let first = connect(config).await?;
    let other = connect(config).await?;
    let holder = inbox(&first)?;
    let verified = binding(original)?;
    let contender = inbox(&other)?;
    let IdempotencyDisposition::Acquired(initial) = holder.claim(&verified, deadline()).await?
    else {
        anyhow::bail!("original claim")
    };
    let different =
        MessageEnvelope::new(original.id().clone(), original.metadata().clone(), vec![99]);
    let count = Count(AtomicUsize::new(0));
    assert_eq!(
        deliver(&other, different, &count).await?,
        (
            ProcessingDisposition::Rejected(EnvelopeValidationFailure::FingerprintConflict),
            vec![SettlementKind::Reject]
        )
    );
    holder.release(initial, deadline()).await?;
    let before = message_in_partition(
        &format!("{}-before", original.id().as_str()),
        original
            .metadata()
            .partition()
            .context("partition")?
            .key()
            .as_str(),
    );
    assert_eq!(
        deliver(&other, before, &count).await?.0,
        ProcessingDisposition::Committed(TerminalDisposition::Succeeded)
    );
    let IdempotencyDisposition::Acquired(head) = contender.claim(&verified, deadline()).await?
    else {
        anyhow::bail!("head reclaim")
    };
    reject_while_waiting(owner, &first, &other, &head, original, successor, protected).await?;
    first.close().await;
    other.close().await;
    Ok(())
}
struct HeldReject {
    entered: tokio::sync::mpsc::Sender<i32>,
    expected_isolation: &'static str,
    release: Arc<tokio::sync::Notify>,
}
impl PgConsumerEffect<Vec<u8>> for HeldReject {
    async fn apply(
        &self,
        tx: &mut PgTransaction<'_>,
        msg: &MessageEnvelope<Vec<u8>>,
        deadline: OperationDeadline,
    ) -> Result<TerminalDisposition, PgConsumerEffectFailure> {
        let (pid, isolation) = tx
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_as::<_, (i32, String)>(
                        "SELECT pg_backend_pid(),current_setting('transaction_isolation')",
                    )
                    .fetch_one(connection)
                    .await
                })
            })
            .await
            .map_err(PgConsumerEffectFailure::infrastructure)?;
        assert_eq!(isolation, self.expected_isolation);
        self.entered
            .send(pid)
            .await
            .map_err(PgConsumerEffectFailure::infrastructure)?;
        self.release.notified().await;
        Reject.apply(tx, msg, deadline).await
    }
}
async fn reject_while_waiting(
    owner: &sqlx::PgPool,
    first: &Arc<PgRuntime>,
    other: &Arc<PgRuntime>,
    head: &PgInboxClaim,
    original: &MessageEnvelope<Vec<u8>>,
    successor: &MessageEnvelope<Vec<u8>>,
    protected: bool,
) -> anyhow::Result<()> {
    // Admit both messages before either business snapshot. A concurrent Inbox INSERT may
    // legitimately abort the first transaction under SERIALIZABLE with SQLSTATE 40001.
    let verified = binding(successor)?;
    let contender = inbox(first)?;
    let IdempotencyDisposition::Acquired(next) = contender.claim(&verified, deadline()).await?
    else {
        anyhow::bail!("successor claim")
    };
    let (entered, mut started) = tokio::sync::mpsc::channel(1);
    let release = Arc::new(tokio::sync::Notify::new());
    let effect = HeldReject {
        expected_isolation: if protected {
            "serializable"
        } else {
            "read committed"
        },
        entered,
        release: release.clone(),
    };
    let reject = async {
        let intent = binding(original)?.receipt_intent();
        let status = if protected {
            let capture =
                PgRecoveryCapture::new(other.clone(), Arc::new(Key(1)), deadline()).await?;
            PgConsumerTx::with_recovery(effect, capture)
                .execute(head, original, intent, deadline())
                .await
                .status()
        } else {
            PgConsumerTx::receipt_only(other.clone(), effect)
                .execute(head, original, intent, deadline())
                .await
                .status()
        };
        anyhow::ensure!(
            status == TransactionalMessagingTransactionStatus::Committed,
            "reject commit {status:?}, protected={protected}"
        );
        anyhow::Ok(())
    };
    let compete = async {
        let pid = started.recv().await.context("handler started")?;
        let count = Count(AtomicUsize::new(0));
        let witness = async {
            waiter(owner, pid).await?;
            assert_eq!(count.0.load(Ordering::SeqCst), 0);
            release.notify_one();
            anyhow::Ok(())
        };
        let transaction = PgConsumerTx::receipt_only(first.clone(), &count);
        let attempt = transaction.execute(&next, successor, verified.receipt_intent(), deadline());
        let (outcome, ()) = tokio::try_join!(async { anyhow::Ok(attempt.await) }, witness)?;
        assert_eq!(
            outcome.status(),
            TransactionalMessagingTransactionStatus::PartitionBlocked
        );
        contender.release(next, deadline()).await?;
        assert_eq!(count.0.load(Ordering::SeqCst), 0);
        anyhow::Ok(())
    };
    tokio::try_join!(reject, compete)?;
    Ok(())
}
async fn assert_blocked(
    restarted: &Arc<PgRuntime>,
    original: &MessageEnvelope<Vec<u8>>,
    successor: &MessageEnvelope<Vec<u8>>,
    key: &str,
    count: &Count,
) -> anyhow::Result<()> {
    assert_eq!(
        deliver_with_ttl(
            restarted,
            successor.clone(),
            count,
            Duration::from_millis(150)
        )
        .await?,
        (
            ProcessingDisposition::PartitionBlocked,
            vec![SettlementKind::Requeue]
        )
    );
    assert_eq!(count.0.load(Ordering::SeqCst), 0);
    assert_eq!(
        deliver(restarted, original.clone(), count).await?,
        (rejected(), vec![SettlementKind::Reject])
    );
    let independent = message_in_partition(&format!("{key}-independent"), "other-key");
    assert_eq!(
        deliver(restarted, independent, count).await?.0,
        ProcessingDisposition::Committed(TerminalDisposition::Succeeded)
    );
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
    assert_foreign(store, head, entry.version).await?;
    runtime_permissions(owner, message).await?;
    race_resolution(store, owner, &authorized, runtime, successor, count).await?;
    let execution = crate::execution(tenant(), 1);
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

async fn assert_foreign(
    store: &PgRecoveryStore<Key>,
    head: &ConsumerHead,
    version: Version,
) -> anyhow::Result<()> {
    let mut wrong = head.clone();
    wrong.partition = PartitionKey::parse("different")?;
    let missing = page(
        store,
        Query::inspect(tenant(), Target::ConsumerHead(wrong.clone())),
    )
    .await?;
    assert!(missing.entries.is_empty());
    let foreign = request(
        Target::ConsumerHead(wrong),
        version,
        Action::Resolve(Resolution::AcceptedGap),
    )
    .await?;
    assert_eq!(
        failure(
            store
                .mutate(crate::execution(tenant(), 1), &foreign, deadline())
                .await
        ),
        Some(Error::Conflict)
    );
    Ok(())
}
async fn runtime_permissions(
    owner: &sqlx::PgPool,
    message: &MessageEnvelope<Vec<u8>>,
) -> anyhow::Result<()> {
    let mut tx = owner.begin().await?;
    sqlx::query("SET LOCAL ROLE recovery_runtime")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('rss.storage_target','01010101010101010101010101010101',true),set_config('rss.storage_lineage','02020202020202020202020202020202',true),set_config('rss.execution_epoch','1',true)").bind(tenant().to_string()).execute(&mut *tx).await?;
    let visible: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM rss_transactional_messaging.inbox WHERE message_id=$1 AND partition_key IS NOT NULL AND resolved_by IS NULL)").bind(message.id().as_str()).fetch_one(&mut *tx).await?;
    assert!(visible);
    let pending = format!("{}-pending", message.id().as_str());
    sqlx::query("INSERT INTO rss_transactional_messaging.inbox(tenant_id,message_id,consumer_group,contract,lease_token,lease_until,fingerprint) SELECT tenant_id,$2,consumer_group,contract,gen_random_uuid(),clock_timestamp(),fingerprint FROM rss_transactional_messaging.inbox WHERE message_id=$1")
        .bind(message.id().as_str()).bind(&pending).execute(&mut *tx).await?;
    assert_eq!(
        sqlx::query("DELETE FROM rss_transactional_messaging.inbox WHERE message_id=$1")
            .bind(&pending)
            .execute(&mut *tx)
            .await?
            .rows_affected(),
        1
    );
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
    Ok(())
}
async fn race_resolution(
    store: &PgRecoveryStore<Key>,
    owner: &sqlx::PgPool,
    authorized: &AuthorizedMutation,
    runtime: &Arc<PgRuntime>,
    successor: &MessageEnvelope<Vec<u8>>,
    count: &Count,
) -> anyhow::Result<()> {
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
    let (receipt, delivery) = tokio::join!(
        store.mutate(crate::execution(tenant(), 1), authorized, deadline()),
        race
    );
    assert_eq!(committed(receipt)?.outcome, Outcome::Resolved);
    assert_eq!(
        delivery?.0,
        ProcessingDisposition::Committed(TerminalDisposition::Succeeded)
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
