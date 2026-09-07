#[path = "../../fixtures/message_fence.rs"]
mod fence_fixture;
#[path = "recovery/support.rs"]
mod support;
use anyhow::Context;
use rss_transactional_messaging::{
    inbox::*, message::*, observability::TransactionalMessagingTransactionStatus, outbox::*,
    policy::*, transaction::*,
};
use rss_transactional_messaging_postgres::*;
use rss_transactional_messaging_recovery::*;
use sqlx::{
    Row,
    postgres::{PgConnectOptions, PgPoolOptions, PgSslMode},
};
use std::{sync::Arc, time::Duration};
use support::*;

struct Allow;
impl Authorizer for Allow {
    async fn authorize(
        &self,
        c: Challenge<'_>,
        _: OperationDeadline,
    ) -> Result<Authorization, Error> {
        Ok(c.authorized())
    }
}
struct Validator;
impl IngressValidator<Vec<u8>> for Validator {
    fn validate(
        &self,
        c: IngressChallenge<'_, Vec<u8>>,
    ) -> Result<VerifiedIngress, EnvelopeValidationFailure> {
        Ok(c.verified())
    }
}
fn deadline() -> OperationDeadline {
    {
        let clock = Timer::new();
        clock.cutoff().operation(&clock)
    }
}
fn binding(message: &MessageEnvelope<Vec<u8>>) -> anyhow::Result<VerifiedConsumerBinding> {
    let m = message.metadata();
    verify_ingress(
        &Validator,
        ConsumerGroup::parse("test")?,
        &SubscriptionIdentity::new(m.domain().clone(), m.route().clone(), m.contract().clone()),
        message,
    )
    .map_err(|_| anyhow::anyhow!("fixture ingress"))
}
fn committed<T, E: std::fmt::Display>(attempt: LocalTxAttempt<T, E>) -> anyhow::Result<T> {
    attempt.fold(
        Ok,
        |e| Err(anyhow::anyhow!("not started: {e}")),
        |e| Err(anyhow::anyhow!("rolled back: {e}")),
        |e| Err(anyhow::anyhow!("rollback failed: {e}")),
        |e| Err(anyhow::anyhow!("commit unknown: {e}")),
        |e| Err(anyhow::anyhow!("fenced: {e}")),
    )
}
fn failure<T>(attempt: LocalTxAttempt<T, Error>) -> Option<Error> {
    attempt.fold(|_| None, Some, Some, Some, Some, Some)
}
struct Reject;
impl PgConsumerEffect<Vec<u8>> for Reject {
    async fn apply(
        &self,
        tx: &mut PgTransaction<'_>,
        message: &MessageEnvelope<Vec<u8>>,
        _: OperationDeadline,
    ) -> Result<TerminalDisposition, PgConsumerEffectFailure> {
        let id = message.id().as_str().to_owned();
        tx.with_connection(move |c| {
            Box::pin(async move {
                sqlx::query("INSERT INTO public.effect (id) VALUES ($1)")
                    .bind(id)
                    .execute(c)
                    .await?;
                Ok(())
            })
        })
        .await
        .map_err(PgConsumerEffectFailure::infrastructure)?;
        Ok(TerminalDisposition::Rejected(RejectKind::Permanent))
    }
}
async fn capture(
    runtime: Arc<PgRuntime>,
    id: &str,
    key: u8,
) -> anyhow::Result<TransactionalMessagingTransactionStatus> {
    let message = message(id);
    let binding = binding(&message)?;
    let inbox = PgInboxStore::new(
        runtime.clone(),
        LeaseRenewalPolicy::from_ttl(Duration::from_secs(60))?,
    )?;
    let claim = inbox
        .claim(binding.identity(), deadline())
        .await
        .context("capture inbox claim")?;
    let IdempotencyDisposition::Acquired(claim) = claim else {
        anyhow::bail!("expected claim");
    };
    let capture = PgRecoveryCapture::new(runtime.clone(), Arc::new(Key(key)), deadline()).await?;
    if id == "unknown-capture" {
        runtime.inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    }
    Ok(PgConsumerTx::with_recovery(Reject, capture)
        .execute(&claim, &message, binding.receipt_intent(), deadline())
        .await
        .status())
}
async fn permit(mutation: Mutation) -> anyhow::Result<AuthorizedMutation> {
    let clock = Timer::new();
    Ok(authorize_mutation(&Allow, mutation, &clock, clock.cutoff()).await?)
}
async fn page<K: rss_data_protection::Aead + Send + Sync>(
    store: &PgRecoveryStore<K>,
    query: Query,
) -> anyhow::Result<Page> {
    let clock = Timer::new();
    let request = authorize_query(&Allow, query, &clock, clock.cutoff()).await?;
    Ok(store.query(&request, deadline()).await?)
}
async fn request(
    target: Target,
    version: Version,
    action: Action,
) -> anyhow::Result<AuthorizedMutation> {
    permit(Mutation::new(
        tenant(),
        OperationId::new(),
        target,
        version,
        action,
    )?)
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recovery_postgres_atomicity_and_fencing() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(180), run()).await??;
    Ok(())
}
#[allow(clippy::cognitive_complexity)] // reason: ordered real-database scenarios keep mutations adjacent to their durable assertions.
async fn run() -> anyhow::Result<()> {
    let network = testkit::bridge_network("recovery-pg").await?;
    let fixture = testkit::postgres_tls(
        testkit::NetworkAttachment {
            network: network.name(),
            dns_name: "recovery-pg",
        },
        testkit::PgTlsServerIdentity::MatchingHost,
    )
    .await?;
    let params = fixture.params();
    let options = PgConnectOptions::new()
        .host(&params.host)
        .port(params.port)
        .database(&params.database)
        .username(&params.username)
        .options([
            ("rss.tenant_id", "11111111-1111-1111-1111-111111111111"),
            ("rss.storage_target", "01010101010101010101010101010101"),
            ("rss.storage_lineage", "02020202020202020202020202020202"),
            ("rss.execution_epoch", "1"),
        ])
        .password(&params.password)
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert_from_pem(fixture.ca_pem().as_bytes().to_vec());
    let owner = PgPoolOptions::new()
        .max_connections(6)
        .connect_with(options)
        .await?;
    sqlx::raw_sql("CREATE ROLE rss_tmsg_relay NOLOGIN NOBYPASSRLS; CREATE ROLE recovery_runtime LOGIN PASSWORD 'fixture-only' NOBYPASSRLS;").execute(&owner).await?;
    sqlx::raw_sql(MIGRATION_SQL).execute(&owner).await?;
    let fresh = schema_signature(&owner).await?;
    sqlx::raw_sql("DROP SCHEMA rss_transactional_messaging CASCADE;")
        .execute(&owner)
        .await?;
    let original = MIGRATION_SQL
        .strip_suffix(RECOVERY_UPGRADE_SQL)
        .ok_or_else(|| anyhow::anyhow!("ordered migrations"))?;
    sqlx::raw_sql(original).execute(&owner).await?;
    let config = PgConfig::new(
        &params.host,
        params.port,
        &params.database,
        "recovery_runtime",
        PgPassword::new("fixture-only"),
        PgPrivateCa::from_pem(fixture.ca_pem().as_bytes().to_vec())?,
    );
    assert!(
        PgRuntime::connect(config.clone(), Timer::new(), fence_fixture::binding())
            .await
            .is_err(),
        "old schema rejected"
    );
    sqlx::raw_sql(RECOVERY_UPGRADE_SQL).execute(&owner).await?;
    assert_eq!(
        fresh,
        schema_signature(&owner).await?,
        "fresh and upgraded schema agree"
    );
    base_grants(&owner).await?;
    sqlx::raw_sql("CREATE TABLE public.effect (id text PRIMARY KEY); GRANT SELECT,INSERT ON public.effect TO recovery_runtime;").execute(&owner).await?;
    fence_fixture::provision(&owner).await?;
    let runtime =
        Arc::new(PgRuntime::connect(config.clone(), Timer::new(), fence_fixture::binding()).await?);
    assert!(
        PgRecoveryCapture::new(runtime.clone(), Arc::new(Key(1)), deadline())
            .await
            .is_err()
    );
    sqlx::raw_sql("GRANT SELECT,INSERT ON rss_transactional_messaging.consumer_dead_letter TO recovery_runtime;").execute(&owner).await?;
    assert!(
        PgRecoveryStore::connect(
            config.clone(),
            Timer::new(),
            fence_fixture::binding(),
            Arc::new(Key(1))
        )
        .await
        .is_err(),
        "capture does not grant mutation"
    );
    assert_eq!(
        capture(runtime.clone(), "rejected", 1).await?,
        TransactionalMessagingTransactionStatus::Committed
    );
    assert_eq!(
        capture(runtime.clone(), "protected-failure", 0).await?,
        TransactionalMessagingTransactionStatus::InfrastructureTransient
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM public.effect")
        .fetch_one(&owner)
        .await?;
    assert_eq!(count, 0);
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM rss_transactional_messaging.consumer_dead_letter")
            .fetch_one(&owner)
            .await?;
    assert_eq!(count, 1);
    let terminal: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM rss_transactional_messaging.inbox WHERE disposition IS NOT NULL",
    )
    .fetch_one(&owner)
    .await?;
    assert_eq!(terminal, 1);
    assert_eq!(
        capture(runtime.clone(), "unknown-capture", 1).await?,
        TransactionalMessagingTransactionStatus::CommitUnknown
    );
    let inbox = PgInboxStore::new(
        runtime.clone(),
        LeaseRenewalPolicy::from_ttl(Duration::from_secs(60))?,
    )?;
    let b = binding(&message("unknown-capture"))?;
    assert!(
        matches!(
            inbox.claim(b.identity(), deadline()).await?,
            IdempotencyDisposition::Terminal(_)
        ),
        "committed rejection survives missing ACK"
    );
    sqlx::raw_sql("CREATE ROLE recovery_operator LOGIN PASSWORD 'fixture-only' NOBYPASSRLS; GRANT recovery_runtime TO recovery_operator; GRANT UPDATE(recovery_version) ON rss_transactional_messaging.consumer_dead_letter TO recovery_operator; GRANT SELECT,INSERT ON rss_transactional_messaging.recovery_operations TO recovery_operator; GRANT UPDATE ON rss_transactional_messaging.outbox TO recovery_operator;").execute(&owner).await?;
    let operator_config = PgConfig::new(
        &params.host,
        params.port,
        &params.database,
        "recovery_operator",
        PgPassword::new("fixture-only"),
        PgPrivateCa::from_pem(fixture.ca_pem().as_bytes().to_vec())?,
    );
    assert!(
        PgRuntime::connect(
            operator_config.clone(),
            Timer::new(),
            fence_fixture::binding()
        )
        .await
        .is_err(),
        "application profile rejects operator privileges"
    );
    let store = Arc::new(
        PgRecoveryStore::connect(
            operator_config.clone(),
            Timer::new(),
            fence_fixture::binding(),
            Arc::new(Key(1)),
        )
        .await?,
    );
    sqlx::raw_sql("GRANT EXECUTE ON FUNCTION rss_transactional_messaging.apply_dr(uuid,bytea,text,jsonb,jsonb,bigint) TO recovery_operator").execute(&owner).await?;
    let excess = PgRecoveryStore::connect(
        operator_config.clone(),
        Timer::new(),
        fence_fixture::binding(),
        Arc::new(Key(1)),
    )
    .await;
    sqlx::raw_sql("REVOKE EXECUTE ON FUNCTION rss_transactional_messaging.apply_dr(uuid,bytea,text,jsonb,jsonb,bigint) FROM recovery_operator").execute(&owner).await?;
    assert!(
        excess.is_err(),
        "recovery operator must not possess DR authority"
    );
    replay_scenarios(store.clone(), &owner)
        .await
        .context("replay scenarios")?;
    concurrent_replay(store.clone(), &owner).await?;
    outbox_scenarios(runtime.clone(), store.clone(), &owner)
        .await
        .context("outbox scenarios")?;
    capture_failures(runtime.clone(), &owner).await?;
    replay_conflicts(runtime.clone(), store.clone(), &owner).await?;
    compensated(runtime.clone(), store.clone(), &owner).await?;
    privilege_failures(runtime.clone(), &operator_config, &owner).await?;
    schema_failures(&operator_config, &owner).await?;
    store.close().await;
    assert!(store.is_closed());
    let clock = Timer::new();
    let query = authorize_query(
        &Allow,
        Query::list(tenant(), Source::Consumer, 1, None)?,
        &clock,
        clock.cutoff(),
    )
    .await?;
    assert!(
        matches!(
            store.query(&query, deadline()).await,
            Err(Error::Store(StoreFailureKind::Permanent))
        ),
        "closed pool is not a schema mismatch"
    );
    sqlx::raw_sql("ALTER POLICY recovery_tenant ON rss_transactional_messaging.consumer_dead_letter USING (true);").execute(&owner).await?;
    assert!(
        PgRecoveryCapture::new(runtime.clone(), Arc::new(Key(1)), deadline())
            .await
            .is_err(),
        "broad RLS is rejected"
    );
    runtime.close().await;
    owner.close().await;
    drop(fixture);
    drop(network);
    Ok(())
}
async fn base_grants(owner: &sqlx::PgPool) -> anyhow::Result<()> {
    sqlx::raw_sql("GRANT USAGE ON SCHEMA rss_transactional_messaging TO recovery_runtime; GRANT SELECT ON rss_transactional_messaging.policy TO recovery_runtime; GRANT SELECT,INSERT,UPDATE,DELETE ON rss_transactional_messaging.inbox TO recovery_runtime; GRANT SELECT,INSERT ON rss_transactional_messaging.outbox TO recovery_runtime; GRANT USAGE ON ALL SEQUENCES IN SCHEMA rss_transactional_messaging TO recovery_runtime; GRANT EXECUTE ON FUNCTION rss_transactional_messaging.claim_outbox(uuid,text,integer,bigint),rss_transactional_messaging.outbox_lease(uuid,bigint,uuid,bigint,bigint,uuid),rss_transactional_messaging.settle_outbox(uuid,bigint,uuid,bigint,text,uuid) TO recovery_runtime;").execute(owner).await?;
    Ok(())
}
async fn schema_signature(owner: &sqlx::PgPool) -> anyhow::Result<Vec<String>> {
    Ok(sqlx::query_scalar("SELECT table_name||':'||column_name||':'||data_type||':'||is_nullable||':'||coalesce(column_default,'') FROM information_schema.columns WHERE table_schema='rss_transactional_messaging' UNION ALL SELECT c.relname||':'||con.conname||':'||pg_get_constraintdef(con.oid) FROM pg_constraint con JOIN pg_class c ON con.conrelid=c.oid JOIN pg_namespace n ON c.relnamespace=n.oid WHERE n.nspname='rss_transactional_messaging' UNION ALL SELECT indexname||':'||indexdef FROM pg_indexes WHERE schemaname='rss_transactional_messaging' ORDER BY 1").fetch_all(owner).await?)
}
#[allow(clippy::cognitive_complexity)] // reason: ordered real-database scenarios keep mutations adjacent to their durable assertions.
async fn replay_scenarios(
    store: Arc<PgRecoveryStore<Key>>,
    owner: &sqlx::PgPool,
) -> anyhow::Result<()> {
    let found = page(&store, Query::list(tenant(), Source::Consumer, 1, None)?).await?;
    assert_eq!(found.entries.len(), 1);
    assert!(found.next_cursor.is_some());
    let entry = found
        .entries
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("entry"))?;
    if let Details::Consumer(details) = &entry.details {
        assert_eq!(details.group.as_str(), "test");
        assert_eq!(details.reason, RejectKind::Permanent);
        assert!(details.captured_at_unix_micros > 0);
        assert_eq!(details.replay_count, 0);
    } else {
        anyhow::bail!("consumer detail");
    }
    let req = request(
        entry.target.clone(),
        entry.version,
        Action::Replay(MessageId::parse("replay-1")?),
    )
    .await?;
    store.inject_next_transaction_fault(PgTransactionFault::CommitAcknowledgedPending);
    let clock = Timer::new();
    let deadlines = ExecutionDeadlines::from_budget(
        &clock,
        ExecutionBudget::new(Duration::from_millis(500), Duration::from_millis(250))?,
    )?;
    let observer = RecordingObserver::default();
    let receipt = committed(execute(store.as_ref(), &req, &clock, deadlines, &observer).await)?;
    assert_eq!(
        observer
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("observations"))?[0]
            .status,
        AttemptStatus::Committed
    );
    assert_eq!(receipt.outcome, Outcome::Replayed);
    let inspected = page(&store, Query::inspect(tenant(), entry.target.clone())).await?;
    if let Details::Consumer(details) = &inspected.entries[0].details {
        assert_eq!(details.replay_count, 1);
        assert_eq!(
            details.last_replay.as_ref().map(MessageId::as_str),
            Some("replay-1")
        );
    } else {
        anyhow::bail!("consumer detail")
    }

    let second = committed(store.mutate(&req, deadline()).await)?;
    assert_eq!(receipt.version, second.version);
    let row=sqlx::query("SELECT envelope,fingerprint FROM rss_transactional_messaging.outbox WHERE message_id='replay-1'").fetch_one(owner).await?;
    let envelope: serde_json::Value = row.try_get("envelope")?;
    assert!(envelope["tenant_authority"].is_null());
    assert!(envelope["trace"].is_null());
    assert_eq!(
        envelope["payload"],
        serde_json::json!(b"secret-body".to_vec())
    );
    let duplicate = request(
        entry.target.clone(),
        receipt.version,
        Action::Replay(MessageId::parse("replay-1")?),
    )
    .await?;
    assert_eq!(
        failure(store.mutate(&duplicate, deadline()).await),
        Some(Error::Conflict)
    );
    assert!(store.receipt(&duplicate, deadline()).await?.is_none());
    let stale = request(
        entry.target.clone(),
        entry.version,
        Action::Replay(MessageId::parse("replay-2")?),
    )
    .await?;
    assert_eq!(
        failure(store.mutate(&stale, deadline()).await),
        Some(Error::Conflict)
    );
    let bad = Mutation::new(
        tenant(),
        req.request().operation(),
        entry.target.clone(),
        receipt.version,
        Action::Replay(MessageId::parse("different")?),
    )?;
    assert_eq!(
        failure(store.mutate(&permit(bad).await?, deadline()).await),
        Some(Error::Conflict)
    );
    let other = rss_request_context::TenantId::parse("22222222-2222-2222-2222-222222222222")?;
    assert!(
        page(&store, Query::inspect(other, entry.target.clone()))
            .await?
            .entries
            .is_empty()
    );
    let cross = Mutation::new(
        other,
        OperationId::new(),
        entry.target.clone(),
        receipt.version,
        Action::Replay(MessageId::parse("cross")?),
    )?;
    assert_eq!(
        failure(store.mutate(&permit(cross).await?, deadline()).await),
        Some(Error::NotFound)
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_transactional_messaging.outbox")
        .fetch_one(owner)
        .await?;
    assert_eq!(count, 1);
    // Simulate the persisted post-purge snapshot; the archive T2 suite proves the purge itself.
    sqlx::query("UPDATE rss_transactional_messaging.consumer_dead_letter SET capsule=NULL WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant().to_string()).bind(entry.target.key()).execute(owner).await?;
    assert_eq!(
        committed(store.mutate(&req, deadline()).await)?.version,
        receipt.version
    );
    let fresh = request(
        entry.target.clone(),
        receipt.version,
        Action::Replay(MessageId::parse("cold-replay")?),
    )
    .await?;
    assert_eq!(
        failure(store.mutate(&fresh, deadline()).await),
        Some(Error::Archived)
    );
    let inspected = page(&store, Query::inspect(tenant(), entry.target.clone())).await?;
    if let Details::Consumer(details) = &inspected.entries[0].details {
        assert!(!details.hot_available)
    } else {
        anyhow::bail!("consumer detail")
    }
    Ok(())
}
#[allow(clippy::cognitive_complexity)] // reason: ordered real-database scenarios keep mutations adjacent to their durable assertions.
async fn outbox_scenarios(
    runtime: Arc<PgRuntime>,
    store: Arc<PgRecoveryStore<Key>>,
    owner: &sqlx::PgPool,
) -> anyhow::Result<()> {
    let domain = MessagingDomain::parse("orders")?;
    let ttl = Duration::from_secs(60);
    let part = Duration::from_secs(10);
    let outbox = PgOutboxStore::<()>::new(
        runtime.clone(),
        domain,
        DeliveryBudget::new(ttl, part, part, part)?,
    )?;
    for id in ["head", "successor"] {
        committed(
            runtime
                .local_tx_with_context(tenant(), deadline(), (&outbox, id), |(outbox, id), tx| {
                    Box::pin(async move {
                        outbox
                            .append(tx, PendingMessage::new(message(id)))
                            .await
                            .map_err(|_| PgError::InvalidConnectionConfig)
                    })
                })
                .await,
        )?;
    }
    sqlx::query("UPDATE rss_transactional_messaging.outbox SET status='published' WHERE message_id LIKE 'replay-%'").execute(owner).await?;
    let batch = outbox
        .claim_partition_heads(std::num::NonZeroUsize::MIN, deadline())
        .await
        .context("outbox claim")?;
    let claim = batch
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("head claim"))?;
    outbox
        .settle(claim, OutboxSettlement::DeadLetter, deadline())
        .await
        .context("outbox settlement")?;
    let entry = page(
        &store,
        Query::inspect(tenant(), Target::Outbox(MessageId::parse("head")?)),
    )
    .await?
    .entries
    .into_iter()
    .next()
    .ok_or_else(|| anyhow::anyhow!("head"))?;
    let before:String=sqlx::query_scalar("SELECT automatic_retry_deadline::text FROM rss_transactional_messaging.outbox WHERE message_id='head'").fetch_one(owner).await?;
    let premature = request(
        entry.target.clone(),
        entry.version,
        Action::Resolve(Resolution::AcceptedGap),
    )
    .await?;
    assert_eq!(
        failure(store.mutate(&premature, deadline()).await),
        Some(Error::NotExpired)
    );
    let retry = request(entry.target.clone(), entry.version, Action::Redrive).await?;
    assert_eq!(
        committed(store.mutate(&retry, deadline()).await)?.outcome,
        Outcome::Redriven
    );
    let after:String=sqlx::query_scalar("SELECT automatic_retry_deadline::text FROM rss_transactional_messaging.outbox WHERE message_id='head'").fetch_one(owner).await?;
    assert_eq!(before, after);
    let batch = outbox
        .claim_partition_heads(std::num::NonZeroUsize::MIN, deadline())
        .await
        .context("outbox claim")?;
    let claim = batch
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("redrive claim"))?;
    outbox
        .settle(claim, OutboxSettlement::DeadLetter, deadline())
        .await
        .context("outbox settlement")?;
    sqlx::query("UPDATE rss_transactional_messaging.outbox SET automatic_retry_deadline=clock_timestamp()-interval '1 second' WHERE message_id='head'").execute(owner).await?;
    let entry = page(&store, Query::inspect(tenant(), entry.target))
        .await?
        .entries
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("head"))?;
    let expired = request(entry.target.clone(), entry.version, Action::Redrive).await?;
    assert_eq!(
        failure(store.mutate(&expired, deadline()).await),
        Some(Error::Expired)
    );
    assert!(
        outbox
            .claim_partition_heads(std::num::NonZeroUsize::MIN, deadline())
            .await
            .context("outbox claim")?
            .is_empty()
    );
    let wrong = request(
        entry.target.clone(),
        entry.version,
        Action::Resolve(Resolution::Compensated(MessageId::parse("replay-1")?)),
    )
    .await?;
    assert_eq!(
        failure(store.mutate(&wrong, deadline()).await),
        Some(Error::Evidence)
    );
    let resolve = request(
        entry.target,
        entry.version,
        Action::Resolve(Resolution::AcceptedGap),
    )
    .await?;
    committed(store.mutate(&resolve, deadline()).await)?;
    let state: String = sqlx::query_scalar(
        "SELECT status FROM rss_transactional_messaging.outbox WHERE message_id='head'",
    )
    .fetch_one(owner)
    .await?;
    assert_eq!(state, "resolved");
    assert_eq!(
        outbox
            .claim_partition_heads(std::num::NonZeroUsize::MIN, deadline())
            .await
            .context("outbox claim")?
            .len(),
        1
    );
    Ok(())
}

async fn concurrent_replay(
    store: Arc<PgRecoveryStore<Key>>,
    owner: &sqlx::PgPool,
) -> anyhow::Result<()> {
    let entries = page(&store, Query::list(tenant(), Source::Consumer, 100, None)?)
        .await?
        .entries;
    let entry = entries
        .into_iter()
        .find(|entry| entry.version.get() == 1)
        .ok_or_else(|| anyhow::anyhow!("unreplayed target"))?;
    let req = request(
        entry.target.clone(),
        entry.version,
        Action::Replay(MessageId::parse("replay-concurrent")?),
    )
    .await?;
    let (left, right) = tokio::join!(
        store.mutate(&req, deadline()),
        store.mutate(&req, deadline())
    );
    let first = committed(left)?;
    let second = committed(right)?;
    assert_eq!(first.version, second.version);
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM rss_transactional_messaging.recovery_operations WHERE operation_id=$1::uuid").bind(req.request().operation().to_string()).fetch_one(owner).await?;
    assert_eq!(count, 1);
    let pending = request(
        entry.target.clone(),
        first.version,
        Action::Replay(MessageId::parse("replay-pending")?),
    )
    .await?;
    store.inject_next_transaction_fault(PgTransactionFault::CommitPending);
    let clock = Timer::new();
    let timeout =
        AbsoluteDeadline::from_timeout(&clock, Duration::from_millis(50))?.operation(&clock);
    let result = store.mutate(&pending, timeout).await;
    assert_eq!(
        result.fold(
            |_| "committed",
            |_| "not-started",
            |_| "rollback",
            |_| "rollback-failed",
            |_| "unknown",
            |_| "fenced"
        ),
        "unknown"
    );
    assert!(store.receipt(&pending, deadline()).await?.is_none());
    let old = request(
        entry.target,
        entry.version,
        Action::Replay(MessageId::parse("stale-after-concurrency")?),
    )
    .await?;
    store.inject_next_transaction_fault(PgTransactionFault::RollbackFailedAfterAck);
    assert_eq!(
        store.mutate(&old, deadline()).await.fold(
            |_| "committed",
            |_| "not-started",
            |_| "rollback",
            |_| "rollback-failed",
            |_| "unknown",
            |_| "fenced"
        ),
        "rollback-failed"
    );
    Ok(())
}

// SQL keywords below come exclusively from the closed fixture array, never external input.
async fn privilege_failures(
    runtime: Arc<PgRuntime>,
    operator: &PgConfig,
    owner: &sqlx::PgPool,
) -> anyhow::Result<()> {
    for privilege in ["UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"] {
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("GRANT {privilege} ON rss_transactional_messaging.consumer_dead_letter TO recovery_runtime"))).execute(owner).await?;
        assert!(
            PgRecoveryCapture::new(runtime.clone(), Arc::new(Key(1)), deadline())
                .await
                .is_err()
        );
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("REVOKE {privilege} ON rss_transactional_messaging.consumer_dead_letter FROM recovery_runtime"))).execute(owner).await?;
    }
    for privilege in ["UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"] {
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("GRANT {privilege} ON rss_transactional_messaging.recovery_operations TO recovery_operator"))).execute(owner).await?;
        assert!(
            PgRecoveryStore::connect(
                operator.clone(),
                Timer::new(),
                fence_fixture::binding(),
                Arc::new(Key(1))
            )
            .await
            .is_err()
        );
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("REVOKE {privilege} ON rss_transactional_messaging.recovery_operations FROM recovery_operator"))).execute(owner).await?;
    }
    Ok(())
}

async fn schema_failures(operator: &PgConfig, owner: &sqlx::PgPool) -> anyhow::Result<()> {
    for (table, name) in [
        ("consumer_dead_letter", "consumer_dead_letter_capsule_check"),
        ("consumer_dead_letter", "consumer_dead_letter_reason_check"),
        ("recovery_operations", "operation_shape"),
        ("recovery_operations", "recovery_operations_outcome_check"),
    ] {
        let definition:String=sqlx::query_scalar("SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid=to_regclass($1) AND conname=$2").bind(format!("rss_transactional_messaging.{table}")).bind(name).fetch_one(owner).await?;
        // All identifiers are closed fixtures; the definition is read from the fixture's own canonical catalog.
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "ALTER TABLE rss_transactional_messaging.{table} DROP CONSTRAINT {name}"
        )))
        .execute(owner)
        .await?;
        assert!(
            PgRecoveryStore::connect(
                operator.clone(),
                Timer::new(),
                fence_fixture::binding(),
                Arc::new(Key(1))
            )
            .await
            .is_err()
        );
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "ALTER TABLE rss_transactional_messaging.{table} ADD CONSTRAINT {name} {definition}"
        )))
        .execute(owner)
        .await?;
    }
    sqlx::raw_sql("ALTER TABLE rss_transactional_messaging.consumer_dead_letter ALTER COLUMN recovery_version DROP DEFAULT").execute(owner).await?;
    assert!(
        PgRecoveryStore::connect(
            operator.clone(),
            Timer::new(),
            fence_fixture::binding(),
            Arc::new(Key(1))
        )
        .await
        .is_err()
    );
    sqlx::raw_sql("ALTER TABLE rss_transactional_messaging.consumer_dead_letter ALTER COLUMN recovery_version SET DEFAULT 1").execute(owner).await?;
    Ok(())
}

#[derive(Default)]
struct RecordingObserver(std::sync::Mutex<Vec<Observation>>);
impl Observer for RecordingObserver {
    fn observe(&self, value: Observation) {
        if let Ok(mut values) = self.0.lock() {
            values.push(value);
        }
    }
}
struct Fence {
    owner: sqlx::PgPool,
}
impl PgConsumerEffect<Vec<u8>> for Fence {
    async fn apply(
        &self,
        tx: &mut PgTransaction<'_>,
        message: &MessageEnvelope<Vec<u8>>,
        deadline: OperationDeadline,
    ) -> Result<TerminalDisposition, PgConsumerEffectFailure> {
        let result = Reject.apply(tx, message, deadline).await?;
        sqlx::query("UPDATE rss_transactional_messaging.inbox SET lease_token=gen_random_uuid(),lease_until=clock_timestamp()-interval '1 second' WHERE message_id=$1").bind(message.id().as_str()).execute(&self.owner).await.map_err(PgConsumerEffectFailure::infrastructure)?;
        Ok(result)
    }
}
#[allow(clippy::cognitive_complexity)] // reason: each failure is followed by assertions on all three durable effects.
async fn capture_failures(runtime: Arc<PgRuntime>, owner: &sqlx::PgPool) -> anyhow::Result<()> {
    for (id, fence) in [("insert-fails", false), ("lease-fenced", true)] {
        let message = message(id);
        let binding = binding(&message)?;
        let inbox = PgInboxStore::new(
            runtime.clone(),
            LeaseRenewalPolicy::from_ttl(Duration::from_secs(60))?,
        )?;
        let IdempotencyDisposition::Acquired(claim) =
            inbox.claim(binding.identity(), deadline()).await?
        else {
            anyhow::bail!("claim")
        };
        let capture = PgRecoveryCapture::new(runtime.clone(), Arc::new(Key(1)), deadline()).await?;
        let status = if fence {
            PgConsumerTx::with_recovery(
                Fence {
                    owner: owner.clone(),
                },
                capture,
            )
            .execute(&claim, &message, binding.receipt_intent(), deadline())
            .await
            .status()
        } else {
            sqlx::raw_sql("REVOKE INSERT ON rss_transactional_messaging.consumer_dead_letter FROM recovery_runtime").execute(owner).await?;
            let status = PgConsumerTx::with_recovery(Reject, capture)
                .execute(&claim, &message, binding.receipt_intent(), deadline())
                .await
                .status();
            sqlx::raw_sql("GRANT INSERT ON rss_transactional_messaging.consumer_dead_letter TO recovery_runtime").execute(owner).await?;
            status
        };
        assert_eq!(
            status,
            if fence {
                TransactionalMessagingTransactionStatus::Fenced
            } else {
                TransactionalMessagingTransactionStatus::InfrastructureTransient
            }
        );
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM rss_transactional_messaging.consumer_dead_letter WHERE message_id=$1").bind(id).fetch_one(owner).await?;
        assert_eq!(count, 0);
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM rss_transactional_messaging.inbox WHERE message_id=$1 AND disposition IS NOT NULL").bind(id).fetch_one(owner).await?;
        assert_eq!(count, 0);
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM public.effect WHERE id=$1")
            .bind(id)
            .fetch_one(owner)
            .await?;
        assert_eq!(count, 0);
    }
    Ok(())
}
async fn replay_conflicts(
    runtime: Arc<PgRuntime>,
    store: Arc<PgRecoveryStore<Key>>,
    owner: &sqlx::PgPool,
) -> anyhow::Result<()> {
    let entries = page(&store, Query::list(tenant(), Source::Consumer, 100, None)?)
        .await?
        .entries;
    let existing: String=sqlx::query_scalar("SELECT target_key FROM rss_transactional_messaging.recovery_operations WHERE replay_message_id='replay-1' LIMIT 1").fetch_one(owner).await?;
    let other = entries
        .iter()
        .find(|e| e.target.key() != existing)
        .ok_or_else(|| anyhow::anyhow!("other source"))?;
    let conflict = request(
        other.target.clone(),
        other.version,
        Action::Replay(MessageId::parse("replay-1")?),
    )
    .await?;
    assert_eq!(
        failure(store.mutate(&conflict, deadline()).await),
        Some(Error::Conflict)
    );
    assert!(store.receipt(&conflict, deadline()).await?.is_none());
    // Preoccupy an identity with precisely matching authored facts, but without recovery provenance.
    let original = message("occupied");
    let outbox = PgOutboxStore::<()>::new(
        runtime.clone(),
        original.metadata().domain().clone(),
        DeliveryBudget::new(
            Duration::from_secs(60),
            Duration::from_secs(10),
            Duration::from_secs(10),
            Duration::from_secs(10),
        )?,
    )?;
    committed(
        runtime
            .local_tx_with_context(
                tenant(),
                deadline(),
                (&outbox, original),
                |(outbox, message), tx| {
                    Box::pin(async move {
                        outbox
                            .append(
                                tx,
                                PendingMessage::new(MessageEnvelope::new(
                                    message.id().clone(),
                                    message.metadata().clone(),
                                    message.payload().clone(),
                                )),
                            )
                            .await
                            .map_err(|_| PgError::InvalidConnectionConfig)
                    })
                },
            )
            .await,
    )?;
    let occupied = request(
        other.target.clone(),
        other.version,
        Action::Replay(MessageId::parse("occupied")?),
    )
    .await?;
    assert_eq!(
        failure(store.mutate(&occupied, deadline()).await),
        Some(Error::Conflict)
    );
    let current = page(&store, Query::inspect(tenant(), other.target.clone())).await?;
    assert_eq!(current.entries[0].version, other.version);
    Ok(())
}
async fn compensated(
    runtime: Arc<PgRuntime>,
    store: Arc<PgRecoveryStore<Key>>,
    owner: &sqlx::PgPool,
) -> anyhow::Result<()> {
    let outbox = PgOutboxStore::<()>::new(
        runtime.clone(),
        MessagingDomain::parse("orders")?,
        DeliveryBudget::new(
            Duration::from_secs(60),
            Duration::from_secs(10),
            Duration::from_secs(10),
            Duration::from_secs(10),
        )?,
    )?;
    for id in ["compensated-head", "compensation-evidence"] {
        let mut authored = message(id);
        if id == "compensation-evidence" {
            let m = authored.metadata();
            let metadata = MessageMetadata::new(
                AuthoredMessageMetadata::new(
                    tenant(),
                    m.occurred_at(),
                    m.domain().clone(),
                    m.route().clone(),
                    m.contract().clone(),
                ),
                MessageMetadataExtensions::new(
                    None,
                    None,
                    Some(MessageId::parse("compensated-head")?),
                    Default::default(),
                ),
            );
            authored =
                MessageEnvelope::new(authored.id().clone(), metadata, authored.payload().clone());
        }
        committed(
            runtime
                .local_tx_with_context(
                    tenant(),
                    deadline(),
                    (&outbox, authored),
                    |(store, message), tx| {
                        Box::pin(async move {
                            store
                                .append(
                                    tx,
                                    PendingMessage::new(MessageEnvelope::new(
                                        message.id().clone(),
                                        message.metadata().clone(),
                                        message.payload().clone(),
                                    )),
                                )
                                .await
                                .map_err(|_| PgError::InvalidConnectionConfig)
                        })
                    },
                )
                .await,
        )?;
    }
    sqlx::query("UPDATE rss_transactional_messaging.outbox SET status='dead_letter',automatic_retry_deadline=clock_timestamp()-interval '1 second' WHERE message_id='compensated-head'").execute(owner).await?;
    sqlx::query("UPDATE rss_transactional_messaging.outbox SET status='published' WHERE message_id='compensation-evidence'").execute(owner).await?;
    let target = Target::Outbox(MessageId::parse("compensated-head")?);
    let entry = page(&store, Query::inspect(tenant(), target.clone()))
        .await?
        .entries
        .remove(0);
    let req = request(
        target,
        entry.version,
        Action::Resolve(Resolution::Compensated(MessageId::parse(
            "compensation-evidence",
        )?)),
    )
    .await?;
    committed(store.mutate(&req, deadline()).await)?;
    let fact = message("compensated-head");
    let published = committed(
        runtime
            .local_tx_with_context(
                tenant(),
                deadline(),
                (&outbox, fact),
                |(store, fact), tx| {
                    Box::pin(async move {
                        store
                            .is_published(
                                tx,
                                fact.metadata().domain(),
                                fact.id(),
                                MessageFingerprint::of(fact),
                            )
                            .await
                    })
                },
            )
            .await,
    )?;
    assert!(!published, "resolved is never publication evidence");
    Ok(())
}
