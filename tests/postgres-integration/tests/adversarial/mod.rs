use super::{Effect, Timer, binding, deadline, message};
use rss_transactional_messaging::{inbox::*, message::MessageEnvelope, policy::*, transaction::*};
use rss_transactional_messaging_postgres::*;
use std::{
    sync::{
        Arc,
        atomic::{AtomicI32, Ordering},
    },
    time::Duration,
};
use tokio::sync::Notify;
mod consumer_failures;
mod relay;

async fn count(owner: &sqlx::PgPool, id: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM public.business_effects WHERE id=$1")
        .bind(id)
        .fetch_one(owner)
        .await
        .expect("durable count")
}
async fn connection_gone(owner: &sqlx::PgPool, pid: i32) {
    assert!(pid > 0);
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let exists: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1)")
                    .bind(pid)
                    .fetch_one(owner)
                    .await
                    .expect("backend state");
            if !exists {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("uncertain connection must leave server");
}
struct GateEffect {
    entered: Arc<Notify>,
    release: Arc<Notify>,
}
impl PgConsumerEffect<Vec<u8>> for GateEffect {
    async fn apply(
        &self,
        tx: &mut PgTransaction<'_>,
        message: &MessageEnvelope<Vec<u8>>,
        deadline: OperationDeadline,
    ) -> Result<TerminalDisposition, PgConsumerEffectFailure> {
        Effect(TerminalDisposition::Succeeded)
            .apply(tx, message, deadline)
            .await?;
        self.entered.notify_one();
        self.release.notified().await;
        Ok(TerminalDisposition::Succeeded)
    }
}

#[allow(clippy::cognitive_complexity)]
// reason: the two explicit lock schedules keep the concurrent actors and durable assertions together.
async fn concurrency(runtime: Arc<PgRuntime>, owner: &sqlx::PgPool) -> anyhow::Result<()> {
    let inbox = Arc::new(PgInboxStore::new(
        runtime.clone(),
        rss_transactional_messaging::policy::LeaseRenewalPolicy::from_ttl(Duration::from_secs(60))?,
    )?);
    let mut contenders = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let inbox = inbox.clone();
        contenders.spawn(async move {
            inbox
                .claim(binding(&message("concurrent-claim")).identity(), deadline())
                .await
        });
    }
    let mut winners = Vec::new();
    while let Some(result) = contenders.join_next().await {
        if let IdempotencyDisposition::Acquired(claim) = result?? {
            winners.push(claim);
        }
    }
    assert_eq!(winners.len(), 1, "atomic claim admits one owner");
    let old = winners.pop().expect("winner");
    sqlx::query("UPDATE rss_transactional_messaging.inbox SET lease_until=clock_timestamp()-interval '1 second' WHERE message_id='concurrent-claim'").execute(owner).await?;
    let binding = binding(&message("concurrent-claim"));
    assert!(matches!(
        inbox.claim(binding.identity(), deadline()).await?,
        IdempotencyDisposition::Acquired(_)
    ));
    assert_eq!(inbox.extend(&old, deadline()).await?, LeaseStatus::Lost);
    let outcome = PgConsumerTx::new(runtime.clone(), Effect(TerminalDisposition::Succeeded))
        .execute(
            &old,
            &message("concurrent-claim"),
            binding.receipt_intent(),
            deadline(),
        )
        .await;
    assert_eq!(
        outcome.status(),
        rss_transactional_messaging::observability::TransactionalMessagingTransactionStatus::Fenced
    );
    assert_eq!(count(owner, "concurrent-claim").await, 0);
    assert_eq!(
        inbox
            .release(old, deadline())
            .await
            .expect_err("stale release")
            .kind(),
        rss_transactional_messaging::error::MessagingErrorKind::OwnershipLost
    );

    for lock_until_expired in [false, true] {
        let id = if lock_until_expired {
            "terminal-lock-expiry"
        } else {
            "renew-during-effect"
        };
        let message = message(id);
        let binding = super::binding(&message);
        let inbox = PgInboxStore::new(
            runtime.clone(),
            rss_transactional_messaging::policy::LeaseRenewalPolicy::from_ttl(
                Duration::from_millis(500),
            )?,
        )?;
        let IdempotencyDisposition::Acquired(claim) =
            inbox.claim(binding.identity(), deadline()).await?
        else {
            panic!("new claim")
        };
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let consumer = PgConsumerTx::new(
            runtime.clone(),
            GateEffect {
                entered: entered.clone(),
                release: release.clone(),
            },
        );
        let execution = consumer.execute(&claim, &message, binding.receipt_intent(), deadline());
        let coordination = async {
            entered.notified().await;
            if lock_until_expired {
                let mut blocker = owner.begin().await.expect("blocker");
                sqlx::query("SELECT 1 FROM rss_transactional_messaging.inbox WHERE message_id=$1 FOR UPDATE").bind(id).execute(&mut *blocker).await.expect("hold inbox lock");
                release.notify_one();
                tokio::time::sleep(Duration::from_millis(600)).await;
                blocker.rollback().await.expect("unlock");
            } else {
                let renewal = tokio::time::timeout(
                    Duration::from_millis(200),
                    inbox.extend(&claim, deadline()),
                )
                .await
                .expect("effect must not hold inbox lock")
                .expect("renew");
                assert!(matches!(renewal, LeaseStatus::Held { .. }));
                release.notify_one();
            }
        };
        let (outcome, ()) = tokio::join!(execution, coordination);
        assert_eq!(
            outcome.status(),
            if lock_until_expired {
                rss_transactional_messaging::observability::TransactionalMessagingTransactionStatus::Fenced
            } else {
                rss_transactional_messaging::observability::TransactionalMessagingTransactionStatus::Committed
            }
        );
        assert_eq!(count(owner, id).await, i64::from(!lock_until_expired));
    }
    Ok(())
}

async fn cancellation(runtime: Arc<PgRuntime>, owner: &sqlx::PgPool) -> anyhow::Result<()> {
    for mode in ["cancel-effect", "timeout-effect", "timeout-commit"] {
        let entered = Arc::new(Notify::new());
        let pid = Arc::new(AtomicI32::new(0));
        let task_runtime = runtime.clone();
        let entered_task = entered.clone();
        let pid_task = pid.clone();
        if mode == "timeout-commit" {
            runtime.inject_next_transaction_fault(PgTransactionFault::CommitPending);
        }
        let task = tokio::spawn(async move {
            let tenant = message(mode).metadata().tenant_id();
            let clock = Timer::new();
            let bound = AbsoluteDeadline::from_timeout(&clock, Duration::from_millis(150))
                .expect("deadline")
                .operation(&clock);
            task_runtime.local_tx(tenant, bound, move |tx| Box::pin(async move {
                let backend = tx.with_connection(move |connection| Box::pin(async move {
                    sqlx::query("INSERT INTO public.business_effects(tenant_id,id) VALUES($1::uuid,$2)").bind(tenant.to_string()).bind(mode).execute(&mut *connection).await?;
                    sqlx::query_scalar::<_, i32>("SELECT pg_backend_pid()").fetch_one(connection).await
                })).await?;
                pid_task.store(backend, Ordering::SeqCst); entered_task.notify_one();
                if mode != "timeout-commit" { std::future::pending::<()>().await; }
                Ok(())
            })).await
        });
        entered.notified().await;
        if mode == "cancel-effect" {
            task.abort();
            assert!(matches!(task.await, Err(error) if error.is_cancelled()));
        } else {
            let status = task.await?.fold(
                |_| "committed",
                |_| "not-started",
                |_| "rolled-back",
                |_| "rollback-failed",
                |_| "unknown",
                |_| "fenced",
            );
            assert_eq!(status, "unknown");
        }
        connection_gone(owner, pid.load(Ordering::SeqCst)).await;
        assert_eq!(count(owner, mode).await, 0);
    }
    Ok(())
}

#[allow(clippy::cognitive_complexity)]
// reason: fixture-owned permission mutations must remain adjacent to their rejection and restoration.
pub(super) async fn run(
    runtime: Arc<PgRuntime>,
    owner: &sqlx::PgPool,
    raw_runtime: &sqlx::PgPool,
    config: PgConfig,
) -> anyhow::Result<()> {
    sqlx::raw_sql("CREATE ROLE tmsg_bypass NOLOGIN BYPASSRLS; CREATE ROLE tmsg_bridge NOLOGIN; GRANT tmsg_bypass TO tmsg_bridge; GRANT tmsg_bridge TO tmsg_runtime").execute(owner).await?;
    let accepted = PgRuntime::connect(config.clone(), Timer::new())
        .await
        .is_ok();
    sqlx::raw_sql(
        "REVOKE tmsg_bridge FROM tmsg_runtime; DROP ROLE tmsg_bridge; DROP ROLE tmsg_bypass",
    )
    .execute(owner)
    .await?;
    assert!(
        !accepted,
        "indirect SET ROLE into BYPASSRLS must fail connect"
    );
    sqlx::query("INSERT INTO rss_transactional_messaging.outbox(tenant_id,message_id,domain,envelope,fingerprint) SELECT tenant_id,'ttl-bound','ttl-bound',envelope,fingerprint FROM rss_transactional_messaging.outbox LIMIT 1").execute(owner).await?;
    let claimed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM rss_transactional_messaging.claim_outbox('ttl-bound',1,86400001)",
    )
    .fetch_one(raw_runtime)
    .await?;
    assert_eq!(
        claimed, 0,
        "definer must reject overlong lease before mutation"
    );
    let lease: (i64, String, i64) = sqlx::query_as("SELECT seq,lease_token::text,(extract(epoch FROM lease_until)*1000000)::bigint FROM rss_transactional_messaging.claim_outbox('ttl-bound',1,60000)").fetch_one(raw_runtime).await?;
    for invalid in [-1_i64, 86400001, i64::MAX] {
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM rss_transactional_messaging.outbox_lease($1,$2::uuid,$3,$4)",
        )
        .bind(lease.0)
        .bind(&lease.1)
        .bind(lease.2)
        .bind(invalid)
        .fetch_one(raw_runtime)
        .await?;
        assert_eq!(count, 0, "invalid extension must not change lease");
        let actual: i64 = sqlx::query_scalar("SELECT (extract(epoch FROM lease_until)*1000000)::bigint FROM rss_transactional_messaging.outbox WHERE seq=$1").bind(lease.0).fetch_one(owner).await?;
        assert_eq!(actual, lease.2);
    }
    let original: String = sqlx::query_scalar("SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='rss_transactional_messaging.inbox'::regclass AND conname='inbox_receipt_shape'").fetch_one(owner).await?;
    sqlx::raw_sql("ALTER TABLE rss_transactional_messaging.inbox DROP CONSTRAINT inbox_receipt_shape, ADD CONSTRAINT inbox_receipt_shape CHECK(true)").execute(owner).await?;
    let accepted = PgRuntime::connect(config.clone(), Timer::new())
        .await
        .is_ok();
    // SQL safety: The definition comes from pg_get_constraintdef in this fixture-owned schema.
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("ALTER TABLE rss_transactional_messaging.inbox DROP CONSTRAINT inbox_receipt_shape, ADD CONSTRAINT inbox_receipt_shape {original}"))).execute(owner).await?;
    assert!(!accepted, "same-name weakened constraint must fail connect");
    storage_mutations(owner, &config).await?;
    consumer_failures::run(runtime.clone(), owner).await?;
    relay::run(runtime.clone(), owner).await?;
    projection_mismatch(runtime.clone(), owner).await?;
    sqlx::raw_sql(
        "CREATE POLICY accidental_widening ON rss_transactional_messaging.inbox USING (true)",
    )
    .execute(owner)
    .await?;
    let accepted = PgRuntime::connect(config.clone(), Timer::new())
        .await
        .is_ok();
    sqlx::raw_sql("DROP POLICY accidental_widening ON rss_transactional_messaging.inbox")
        .execute(owner)
        .await?;
    assert!(
        !accepted,
        "extra permissive tenant policy must fail connect"
    );
    sqlx::raw_sql("GRANT UPDATE ON rss_transactional_messaging.outbox TO tmsg_runtime")
        .execute(owner)
        .await?;
    let accepted = PgRuntime::connect(config.clone(), Timer::new())
        .await
        .is_ok();
    sqlx::raw_sql("REVOKE UPDATE ON rss_transactional_messaging.outbox FROM tmsg_runtime")
        .execute(owner)
        .await?;
    assert!(!accepted, "excess Outbox privilege must fail connect");
    sqlx::raw_sql("ALTER POLICY inbox_tenant ON rss_transactional_messaging.inbox USING (true) WITH CHECK (true)").execute(owner).await?;
    let accepted = PgRuntime::connect(config.clone(), Timer::new())
        .await
        .is_ok();
    sqlx::raw_sql("ALTER POLICY inbox_tenant ON rss_transactional_messaging.inbox USING (tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK (tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)").execute(owner).await?;
    assert!(!accepted, "altered tenant predicate must fail connect");
    tenant_isolation(runtime.clone(), raw_runtime).await?;
    inbox_lock_expiry(runtime.clone(), owner).await?;
    concurrency(runtime.clone(), owner).await?;
    cancellation(runtime, owner).await?;
    sqlx::raw_sql("GRANT EXECUTE ON FUNCTION rss_transactional_messaging.claim_outbox(text,integer,bigint) TO PUBLIC").execute(owner).await?;
    assert!(
        PgRuntime::connect(config.clone(), Timer::new())
            .await
            .is_err(),
        "PUBLIC definer entry must fail connect"
    );
    sqlx::raw_sql("REVOKE EXECUTE ON FUNCTION rss_transactional_messaging.claim_outbox(text,integer,bigint) FROM PUBLIC; GRANT rss_tmsg_relay TO tmsg_runtime").execute(owner).await?;
    assert!(
        PgRuntime::connect(config.clone(), Timer::new())
            .await
            .is_err(),
        "runtime must not inherit relay identity"
    );
    sqlx::raw_sql("REVOKE rss_tmsg_relay FROM tmsg_runtime")
        .execute(owner)
        .await?;
    Ok(())
}

async fn storage_defaults(owner: &sqlx::PgPool, config: &PgConfig) -> anyhow::Result<()> {
    for (relation, column, restore) in [
        ("inbox", "receive_count", "1"),
        ("outbox", "status", "'pending'::text"),
        ("outbox", "retry_count", "0"),
        ("outbox", "retry_after", "clock_timestamp()"),
    ] {
        // SQL safety: SQL fragments are literals from the fixture table below/above.
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "ALTER TABLE rss_transactional_messaging.{relation} ALTER COLUMN {column} DROP DEFAULT"
        )))
        .execute(owner)
        .await?;
        let error = PgRuntime::connect(config.clone(), Timer::new()).await.err();
        // SQL safety: SQL fragments are literals from the fixture table below/above.
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("ALTER TABLE rss_transactional_messaging.{relation} ALTER COLUMN {column} SET DEFAULT {restore}"))).execute(owner).await?;
        assert!(matches!(
            error,
            Some(PgError::IncompatibleStorageContract(
                PgStorageContractFailure::Defaults
            ))
        ));
    }
    Ok(())
}

async fn storage_mutations(owner: &sqlx::PgPool, config: &PgConfig) -> anyhow::Result<()> {
    storage_defaults(owner, config).await?;
    let definition: String = sqlx::query_scalar("SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='rss_transactional_messaging.outbox'::regclass AND conname='outbox_lease_shape'").fetch_one(owner).await?;
    sqlx::raw_sql(
        "ALTER TABLE rss_transactional_messaging.outbox DROP CONSTRAINT outbox_lease_shape",
    )
    .execute(owner)
    .await?;
    let error = PgRuntime::connect(config.clone(), Timer::new()).await.err();
    // SQL safety: The definition comes from pg_get_constraintdef in this fixture-owned schema.
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("ALTER TABLE rss_transactional_messaging.outbox ADD CONSTRAINT outbox_lease_shape {definition}"))).execute(owner).await?;
    assert!(matches!(
        error,
        Some(PgError::IncompatibleStorageContract(
            PgStorageContractFailure::Constraints
        ))
    ));
    sqlx::raw_sql(
        "ALTER TABLE rss_transactional_messaging.outbox ALTER COLUMN seq SET GENERATED BY DEFAULT",
    )
    .execute(owner)
    .await?;
    let error = PgRuntime::connect(config.clone(), Timer::new()).await.err();
    sqlx::raw_sql(
        "ALTER TABLE rss_transactional_messaging.outbox ALTER COLUMN seq SET GENERATED ALWAYS",
    )
    .execute(owner)
    .await?;
    assert!(matches!(
        error,
        Some(PgError::IncompatibleStorageContract(
            PgStorageContractFailure::Defaults
        ))
    ));
    Ok(())
}

async fn projection_mismatch(runtime: Arc<PgRuntime>, owner: &sqlx::PgPool) -> anyhow::Result<()> {
    use rss_transactional_messaging::{message::MessagingDomain, outbox::OutboxStore};
    let seq: i64 = sqlx::query_scalar(
        "SELECT seq FROM rss_transactional_messaging.outbox WHERE message_id='outbox-roundtrip'",
    )
    .fetch_one(owner)
    .await?;
    for (mutation, domain) in [
        (
            "tenant_id='f47ac10b-58cc-4372-a567-0e02b2c3d480'::uuid",
            "integration",
        ),
        ("message_id='projection-other'", "integration"),
        ("domain='projection-other'", "projection-other"),
        ("partition_key='projection-other'", "integration"),
    ] {
        // SQL safety: SQL fragments are literals from the fixture table below/above.
        sqlx::query(sqlx::AssertSqlSafe(format!("UPDATE rss_transactional_messaging.outbox SET status='pending', {mutation} WHERE seq=$1"))).bind(seq).execute(owner).await?;
        let store = PgOutboxStore::<()>::new(
            runtime.clone(),
            MessagingDomain::parse(domain)?,
            crate::outbox_budget(Duration::from_secs(60)),
        )?;
        let accepted = store
            .claim_partition_heads(std::num::NonZeroUsize::MIN, deadline())
            .await
            .is_ok();
        sqlx::query("UPDATE rss_transactional_messaging.outbox SET status='published', tenant_id='f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid, message_id='outbox-roundtrip', domain='integration', partition_key=NULL, lease_token=NULL, lease_until=NULL WHERE seq=$1").bind(seq).execute(owner).await?;
        assert!(
            !accepted,
            "mismatched relation projection must not become a claim: {mutation}"
        );
    }
    Ok(())
}

#[allow(clippy::cognitive_complexity)]
// reason: the two-tenant scenario keeps non-vacuous data setup and every RLS assertion in one scope.
async fn tenant_isolation(
    runtime: Arc<PgRuntime>,
    raw_runtime: &sqlx::PgPool,
) -> anyhow::Result<()> {
    use rss_transactional_messaging::{message::*, outbox::*};
    let a = message("tenant-template").metadata().tenant_id();
    let b = rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d480")?;
    let domain = MessagingDomain::parse("cross-tenant-relay")?;
    let store = Arc::new(PgOutboxStore::<()>::new(
        runtime.clone(),
        domain.clone(),
        crate::outbox_budget(Duration::from_secs(60)),
    )?);
    for (id, tenant) in [("tenant-a", a), ("tenant-b", b)] {
        let template = message(id);
        let m = template.metadata();
        let envelope = MessageEnvelope::new(
            template.id().clone(),
            MessageMetadata::new(
                AuthoredMessageMetadata::new(
                    tenant,
                    m.occurred_at(),
                    domain.clone(),
                    m.route().clone(),
                    m.contract().clone(),
                ),
                MessageMetadataExtensions::default(),
            ),
            vec![1],
        );
        let store = store.clone();
        let receipt_binding = binding(&envelope);
        let inbox = PgInboxStore::new(
            runtime.clone(),
            rss_transactional_messaging::policy::LeaseRenewalPolicy::from_ttl(
                Duration::from_secs(60),
            )?,
        )?;
        let IdempotencyDisposition::Acquired(claim) =
            inbox.claim(receipt_binding.identity(), deadline()).await?
        else {
            panic!("tenant claim")
        };
        let outcome = PgConsumerTx::new(runtime.clone(), Effect(TerminalDisposition::Succeeded))
            .execute(
                &claim,
                &envelope,
                receipt_binding.receipt_intent(),
                deadline(),
            )
            .await;
        assert_eq!(outcome.status(), rss_transactional_messaging::observability::TransactionalMessagingTransactionStatus::Committed);
        runtime
            .local_tx(tenant, deadline(), move |tx| {
                Box::pin(async move {
                    store
                        .append(tx, PendingMessage::new(envelope))
                        .await
                        .map_err(Into::into)
                })
            })
            .await
            .fold(Ok, Err, Err, Err, Err, Err)?;
    }
    let invisible: i64 =
        sqlx::query_scalar("SELECT count(*) FROM rss_transactional_messaging.outbox")
            .fetch_one(raw_runtime)
            .await?;
    assert_eq!(invisible, 0, "empty tenant must see no rows");
    let invisible: i64 =
        sqlx::query_scalar("SELECT count(*) FROM rss_transactional_messaging.inbox")
            .fetch_one(raw_runtime)
            .await?;
    assert_eq!(invisible, 0, "empty tenant must not read terminal receipts");
    let visible = runtime.local_tx(a, deadline(), |tx| Box::pin(async move {
        tx.with_connection(|connection| Box::pin(async move {
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM rss_transactional_messaging.inbox WHERE message_id IN ('tenant-a','tenant-b') AND disposition IS NOT NULL").fetch_one(connection).await
        })).await
    })).await.fold(Ok, Err, Err, Err, Err, Err)?;
    assert_eq!(visible, 1, "tenant A must see only its own durable receipt");
    let denied = runtime.local_tx(a, deadline(), move |tx| Box::pin(async move {
        tx.with_connection(move |connection| Box::pin(async move {
            sqlx::query("INSERT INTO rss_transactional_messaging.inbox(tenant_id,message_id,consumer_group,contract,lease_token,lease_until) VALUES($1::uuid,'cross-tenant-inbox-denied','suite','contract',gen_random_uuid(),clock_timestamp()+interval '1 minute')").bind(b.to_string()).execute(connection).await?; Ok(())
        })).await
    })).await;
    assert!(
        denied.fold(
            |_| false,
            |_| false,
            |_| true,
            |_| false,
            |_| false,
            |_| false
        ),
        "cross-tenant Inbox write must roll back"
    );
    let visible = runtime.local_tx(a, deadline(), |tx| Box::pin(async move {
        tx.with_connection(|connection| Box::pin(async move {
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM rss_transactional_messaging.outbox WHERE domain='cross-tenant-relay'").fetch_one(connection).await
        })).await
    })).await.fold(Ok, Err, Err, Err, Err, Err)?;
    assert_eq!(visible, 1);
    let denied = runtime.local_tx(a, deadline(), move |tx| Box::pin(async move {
        tx.with_connection(move |connection| Box::pin(async move {
            sqlx::query("INSERT INTO public.business_effects(tenant_id,id) VALUES($1::uuid,'cross-tenant-denied')").bind(b.to_string()).execute(connection).await?; Ok(())
        })).await
    })).await;
    assert_eq!(
        denied.fold(
            |_| "committed",
            |_| "not-started",
            |_| "rolled-back",
            |_| "rollback-failed",
            |_| "unknown",
            |_| "fenced"
        ),
        "rolled-back"
    );
    let store1 = store.clone();
    let store2 = store.clone();
    let (one, two) = tokio::join!(
        store1.claim_partition_heads(std::num::NonZeroUsize::MIN, deadline()),
        store2.claim_partition_heads(std::num::NonZeroUsize::MIN, deadline())
    );
    let claims: Vec<_> = one?.into_iter().chain(two?).collect();
    assert_eq!(
        claims.len(),
        2,
        "atomic cross-tenant relay must claim distinct rows"
    );
    assert_ne!(
        PgOutboxStore::<()>::message(&claims[0]).message_id(),
        PgOutboxStore::<()>::message(&claims[1]).message_id()
    );
    for claim in claims {
        store
            .settle(claim, OutboxSettlement::Published(()), deadline())
            .await?;
    }
    Ok(())
}

async fn inbox_lock_expiry(runtime: Arc<PgRuntime>, owner: &sqlx::PgPool) -> anyhow::Result<()> {
    for release in [false, true] {
        let id = if release {
            "release-lock-expiry"
        } else {
            "renew-lock-expiry"
        };
        let inbox = PgInboxStore::new(
            runtime.clone(),
            rss_transactional_messaging::policy::LeaseRenewalPolicy::from_ttl(
                Duration::from_millis(150),
            )?,
        )?;
        let binding = binding(&message(id));
        let IdempotencyDisposition::Acquired(claim) =
            inbox.claim(binding.identity(), deadline()).await?
        else {
            panic!("new claim")
        };
        let mut blocker = owner.begin().await?;
        sqlx::query(
            "SELECT 1 FROM rss_transactional_messaging.inbox WHERE message_id=$1 FOR UPDATE",
        )
        .bind(id)
        .execute(&mut *blocker)
        .await?;
        let unlock = async {
            tokio::time::sleep(Duration::from_millis(250)).await;
            blocker.rollback().await.expect("unlock");
        };
        let operation = async {
            if release {
                assert!(
                    inbox.release(claim, deadline()).await.is_err(),
                    "expired release must be fenced after waiting"
                );
            } else {
                assert_eq!(
                    inbox.extend(&claim, deadline()).await.expect("lease check"),
                    LeaseStatus::Lost
                );
            }
        };
        tokio::join!(operation, unlock);
    }
    Ok(())
}
