#[path = "dr/claim.rs"]
mod claim;
#[path = "dr/consumer.rs"]
mod consumer;
#[path = "dr/permissions.rs"]
mod permissions;
#[path = "dr/states.rs"]
mod states;
#[path = "recovery/support.rs"]
mod support;
#[path = "dr/terminate.rs"]
mod terminate;
#[path = "dr/upgrade.rs"]
mod upgrade;
use rss_transactional_messaging::{
    fence::{Epoch, ExecutionBinding, StorageIdentity},
    outbox::*,
    policy::*,
    transaction::LocalTxAttempt,
};
use rss_transactional_messaging_postgres::*;
use rss_transactional_messaging_recovery::{
    Authorization, Authorizer, Challenge, Error, OperationId, Version, authorize_dr, dr::*,
};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use std::{sync::Arc, time::Duration};
use support::{Timer, message, tenant};
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
fn binding(epoch: i64) -> anyhow::Result<ExecutionBinding> {
    Ok(ExecutionBinding::new(
        StorageIdentity::new([1; 16], [2; 16])?,
        vec![(tenant(), Epoch::new(epoch)?)],
    )?)
}
fn deadline() -> OperationDeadline {
    let timer = Timer::new();
    OperationDeadline::from_cutoff(timer.cutoff(), &timer)
}
fn committed<T, E: std::fmt::Display>(value: LocalTxAttempt<T, E>) -> anyhow::Result<T> {
    value.fold(
        Ok,
        |e| Err(anyhow::anyhow!("not started: {e}")),
        |e| Err(anyhow::anyhow!("rollback: {e}")),
        |e| Err(anyhow::anyhow!("rollback unknown: {e}")),
        |e| Err(anyhow::anyhow!("commit unknown: {e}")),
        |e| Err(anyhow::anyhow!("fenced: {e}")),
    )
}
fn budget() -> anyhow::Result<DeliveryBudget> {
    Ok(DeliveryBudget::new(
        Duration::from_secs(30),
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(5),
    )?)
}
async fn plan(id: &str, epoch: i64, op: OperationId) -> anyhow::Result<AuthorizedPlan> {
    let msg = PendingMessage::new(message(id));
    let clock = Timer::new();
    let plan = Plan::new(
        tenant(),
        op,
        binding(epoch)?.storage(),
        Epoch::new(epoch)?,
        RestoreEvidence::new([3; 32], [4; 32])?,
        vec![Member::Outbox {
            message: msg.envelope().id().clone(),
            fingerprint: msg.fingerprint(),
            version: Version::new(1)?,
        }],
    )?;
    Ok(authorize_dr(&Allow, plan, &clock, clock.cutoff()).await?)
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dr_atomic_apply_real_postgres() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(180), Box::pin(run())).await??;
    Ok(())
}
#[allow(clippy::cognitive_complexity)] // reason: ordered real-database cutover assertions share one isolated fixture.
async fn run() -> anyhow::Result<()> {
    let network = testkit::bridge_network("dr-pg").await?;
    let fixture = testkit::postgres_tls(
        testkit::NetworkAttachment {
            network: network.name(),
            dns_name: "dr-pg",
        },
        testkit::PgTlsServerIdentity::MatchingHost,
    )
    .await?;
    let p = fixture.params();
    let owner = PgPoolOptions::new()
        .max_connections(6)
        .connect_with(
            PgConnectOptions::new()
                .host(&p.host)
                .port(p.port)
                .database(&p.database)
                .username(&p.username)
                .password(&p.password)
                .ssl_mode(PgSslMode::VerifyFull)
                .ssl_root_cert_from_pem(fixture.ca_pem().as_bytes().to_vec())
                .options([
                    ("rss.tenant_id", "11111111-1111-1111-1111-111111111111"),
                    ("rss.storage_target", "01010101010101010101010101010101"),
                    ("rss.storage_lineage", "02020202020202020202020202020202"),
                    ("rss.execution_epoch", "1"),
                ]),
        )
        .await?;
    sqlx::raw_sql("CREATE ROLE rss_tmsg_relay NOLOGIN NOBYPASSRLS; CREATE ROLE dr_runtime LOGIN PASSWORD 'fixture-only' NOBYPASSRLS; CREATE ROLE dr_operator LOGIN PASSWORD 'fixture-only' NOBYPASSRLS;").execute(&owner).await?;
    let archive_schema = MIGRATION_SQL
        .strip_suffix(DR_UPGRADE_SQL)
        .ok_or_else(|| anyhow::anyhow!("DR upgrade boundary"))?;
    sqlx::raw_sql(archive_schema).execute(&owner).await?;
    let legacy = upgrade::seed(&owner).await?;
    let mut upgrade = owner.begin().await?;
    sqlx::raw_sql(DR_UPGRADE_SQL).execute(&mut *upgrade).await?;
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
    sqlx::raw_sql(DR_UPGRADE_SQL).execute(&owner).await?;
    assert_eq!(
        upgrade::facts(&owner).await?,
        legacy,
        "upgrade preserves terminal evidence and all Published facts"
    );
    sqlx::raw_sql("INSERT INTO rss_transactional_messaging.storage_lineage VALUES(true,decode(repeat('01',16),'hex'),decode(repeat('02',16),'hex')); INSERT INTO rss_transactional_messaging.tenant_epoch VALUES('11111111-1111-1111-1111-111111111111',1); GRANT USAGE ON SCHEMA rss_transactional_messaging TO dr_runtime,dr_operator; GRANT SELECT ON rss_transactional_messaging.policy TO dr_runtime; GRANT SELECT,INSERT,UPDATE,DELETE ON rss_transactional_messaging.inbox TO dr_runtime; GRANT SELECT,INSERT ON rss_transactional_messaging.outbox TO dr_runtime; GRANT USAGE ON ALL SEQUENCES IN SCHEMA rss_transactional_messaging TO dr_runtime; GRANT EXECUTE ON FUNCTION rss_transactional_messaging.check_execution() TO dr_runtime,dr_operator; GRANT EXECUTE ON FUNCTION rss_transactional_messaging.claim_outbox(uuid,text,integer,bigint),rss_transactional_messaging.outbox_lease(uuid,bigint,uuid,bigint,bigint,uuid),rss_transactional_messaging.settle_outbox(uuid,bigint,uuid,bigint,text,uuid) TO dr_runtime; GRANT EXECUTE ON FUNCTION rss_transactional_messaging.apply_dr(uuid,bytea,text,jsonb,jsonb,bigint),rss_transactional_messaging.read_dr(uuid,bytea) TO dr_operator;").execute(&owner).await?;
    let config = |role: &str| -> anyhow::Result<PgConfig> {
        Ok(PgConfig::new(
            &p.host,
            p.port,
            &p.database,
            role,
            PgPassword::new("fixture-only"),
            PgPrivateCa::from_pem(fixture.ca_pem().as_bytes().to_vec())?,
        ))
    };
    assert!(matches!(
        PgDrStore::connect(config("dr_missing")?, Timer::new(), binding(1)?).await,
        Err(Error::Store(
            rss_transactional_messaging_recovery::StoreFailureKind::Permanent
        ))
    ));
    Box::pin(permissions::check(
        &owner,
        &config("dr_runtime")?,
        &config("dr_operator")?,
    ))
    .await?;
    let other = rss_request_context::TenantId::parse("22222222-2222-2222-2222-222222222222")?;
    sqlx::query("INSERT INTO rss_transactional_messaging.tenant_epoch VALUES($1::uuid,1)")
        .bind(other.to_string())
        .execute(&owner)
        .await?;
    let multi = Arc::new(
        PgRuntime::connect(
            config("dr_runtime")?,
            Timer::new(),
            ExecutionBinding::new(
                binding(1)?.storage(),
                vec![(tenant(), Epoch::new(1)?), (other, Epoch::new(1)?)],
            )?,
        )
        .await?,
    );
    Box::pin(claim::check(&owner, multi.clone(), other)).await?;
    let multi_outbox = PgOutboxStore::<()>::new(
        multi.clone(),
        rss_transactional_messaging::message::MessagingDomain::parse("orders")?,
        budget()?,
    )?;
    let runtime =
        Arc::new(PgRuntime::connect(config("dr_runtime")?, Timer::new(), binding(1)?).await?);
    let outbox = Arc::new(PgOutboxStore::<()>::new(
        runtime.clone(),
        rss_transactional_messaging::message::MessagingDomain::parse("orders")?,
        budget()?,
    )?);
    let one = std::num::NonZeroUsize::new(1).ok_or_else(|| anyhow::anyhow!("limit"))?;
    // Old Inbox and Outbox capabilities must not acquire authority from a newer runtime.
    let inbox = PgInboxStore::new(
        runtime.clone(),
        rss_transactional_messaging::policy::LeaseRenewalPolicy::from_ttl(Duration::from_secs(30))?,
    )?;
    let envelope = message("consumer");
    let identity = rss_transactional_messaging::inbox::ConsumerIdentity::new(
        tenant(),
        rss_transactional_messaging::inbox::ConsumerGroup::parse("test")?,
        envelope.id().clone(),
        envelope.metadata().contract().clone(),
    );
    use rss_transactional_messaging::inbox::{IdempotencyDisposition, InboxStore, LeaseStatus};
    let legacy_message = message("legacy-terminal");
    let legacy_identity = rss_transactional_messaging::inbox::ConsumerIdentity::new(
        tenant(),
        rss_transactional_messaging::inbox::ConsumerGroup::parse("test")?,
        legacy_message.id().clone(),
        legacy_message.metadata().contract().clone(),
    );
    assert!(
        matches!(
            inbox.claim(&legacy_identity, deadline()).await?,
            IdempotencyDisposition::Terminal(_)
        ),
        "pre-upgrade terminal receipt remains terminal"
    );
    let old_inbox = match inbox.claim(&identity, deadline()).await? {
        IdempotencyDisposition::Acquired(c) => c,
        _ => anyhow::bail!("inbox claim"),
    };
    let append = outbox.clone();
    committed(
        runtime
            .local_tx(tenant(), deadline(), move |tx| {
                Box::pin(async move {
                    append
                        .append(tx, PendingMessage::new(message("old-lease")))
                        .await?;
                    Ok(())
                })
            })
            .await,
    )?;
    let old_outbox = outbox
        .claim_partition_heads(one, deadline())
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("old lease"))?;
    let store =
        Arc::new(PgDrStore::connect(config("dr_operator")?, Timer::new(), binding(1)?).await?);
    let request = Arc::new(plan("published", 1, OperationId::new()).await?);
    store.inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    let (entered_tx, entered) = tokio::sync::oneshot::channel();
    let (release, wait) = tokio::sync::oneshot::channel();
    let old_runtime = runtime.clone();
    let old_tx = tokio::spawn(async move {
        old_runtime
            .local_tx(tenant(), deadline(), move |_tx| {
                Box::pin(async move {
                    let _ = entered_tx.send(());
                    wait.await.map_err(|_| PgError::InvalidConnectionConfig)?;
                    Ok(())
                })
            })
            .await
    });
    entered.await?;
    let applying_store = store.clone();
    let applying_plan = request.clone();
    let applying =
        tokio::spawn(async move { applying_store.apply(&applying_plan, deadline()).await });
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(
        !applying.is_finished(),
        "epoch switch waits for admitted transaction settlement"
    );
    release.send(()).map_err(|_| anyhow::anyhow!("release"))?;
    committed(old_tx.await?)?;
    let attempt = applying.await?;
    assert!(attempt.fold(
        |_| false,
        |_| false,
        |_| false,
        |_| false,
        |_| true,
        |_| false
    ));
    let receipt = store
        .receipt(&request, deadline())
        .await?
        .ok_or_else(|| anyhow::anyhow!("receipt"))?;
    assert_eq!(receipt.epoch, Epoch::new(2)?);
    let restarted = PgDrStore::connect(config("dr_operator")?, Timer::new(), binding(2)?).await?;
    assert_eq!(
        restarted.receipt(&request, deadline()).await?,
        Some(receipt.clone())
    );
    assert_eq!(
        committed(restarted.apply(&request, deadline()).await)?,
        receipt
    );
    restarted.close().await;
    assert_eq!(committed(store.apply(&request, deadline()).await)?, receipt);
    assert!(outbox.claim_partition_heads(one, deadline()).await.is_err());
    committed(
        multi
            .local_tx(other, deadline(), |_| Box::pin(async { Ok(()) }))
            .await,
    )?;
    assert!(
        multi_outbox
            .claim_partition_heads(one, deadline())
            .await?
            .is_empty(),
        "fenced tenant A cannot stop valid tenant B relay"
    );
    multi.close().await;
    let conflicting = plan("different-member", 1, request.request().operation()).await?;
    assert!(
        store.apply(&conflicting, deadline()).await.fold(
            |_| false,
            |_| true,
            |_| true,
            |_| true,
            |_| false,
            |_| false
        ),
        "operation identity cannot authorize another digest"
    );

    let late = runtime
        .local_tx(tenant(), deadline(), |tx| {
            Box::pin(async move {
                tx.with_connection(|c| {
                    Box::pin(async move {
                        sqlx::query("SELECT 1").execute(c).await?;
                        Ok(())
                    })
                })
                .await
            })
        })
        .await;
    assert!(late.fold(
        |_| false,
        |_| false,
        |_| false,
        |_| false,
        |_| false,
        |_| true
    ));
    let next =
        Arc::new(PgRuntime::connect(config("dr_runtime")?, Timer::new(), binding(2)?).await?);
    let restored = PgOutboxStore::<()>::new(
        next.clone(),
        rss_transactional_messaging::message::MessagingDomain::parse("orders")?,
        budget()?,
    )?;
    let next_inbox = PgInboxStore::new(
        next.clone(),
        rss_transactional_messaging::policy::LeaseRenewalPolicy::from_ttl(Duration::from_secs(30))?,
    )?;
    assert!(matches!(
        next_inbox.extend(&old_inbox, deadline()).await?,
        LeaseStatus::Lost
    ));
    assert!(matches!(
        restored.lease_status(&old_outbox, deadline()).await?,
        OutboxLeaseStatus::Lost
    ));
    assert!(
        restored
            .settle(old_outbox, OutboxSettlement::Published(()), deadline())
            .await
            .is_err()
    );
    assert!(
        matches!(
            next_inbox.claim(&identity, deadline()).await?,
            IdempotencyDisposition::Acquired(_)
        ),
        "new epoch reclaims old lease immediately"
    );
    let original_deadline: i64=sqlx::query_scalar("SELECT (extract(epoch FROM automatic_retry_deadline)*1000000)::bigint FROM rss_transactional_messaging.outbox WHERE message_id='published'").fetch_one(&owner).await?;
    let claim = restored
        .claim_partition_heads(one, deadline())
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("DR claim"))?;
    assert_eq!(
        PgOutboxStore::<()>::message(&claim)
            .envelope()
            .id()
            .as_str(),
        "published"
    );
    restored
        .settle(claim, OutboxSettlement::Published(()), deadline())
        .await?;
    assert_eq!(
        store
            .progress(&request, deadline())
            .await?
            .ok_or_else(|| anyhow::anyhow!("progress"))?
            .members,
        vec![MemberStatus::Completed]
    );
    let preserved:(String,i64)=sqlx::query_as("SELECT status,(extract(epoch FROM automatic_retry_deadline)*1000000)::bigint FROM rss_transactional_messaging.outbox WHERE message_id='published'").fetch_one(&owner).await?;
    assert_eq!(preserved, ("published".into(), original_deadline));
    // Full-set atomicity: a valid first member cannot survive a later absent member.
    let operator2 =
        Arc::new(PgDrStore::connect(config("dr_operator")?, Timer::new(), binding(2)?).await?);
    let clock = Timer::new();
    let first = plan("published", 2, OperationId::new()).await?;
    let mut members = first.request().members().to_vec();
    members.push(Member::Outbox {
        message: rss_transactional_messaging::message::MessageId::parse("zz-missing")?,
        fingerprint: rss_transactional_messaging::message::MessageFingerprint::from_bytes([7; 32]),
        version: Version::new(1)?,
    });
    let invalid = authorize_dr(
        &Allow,
        Plan::new(
            tenant(),
            OperationId::new(),
            binding(2)?.storage(),
            Epoch::new(2)?,
            RestoreEvidence::new([3; 32], [4; 32])?,
            members,
        )?,
        &clock,
        clock.cutoff(),
    )
    .await?;
    assert!(operator2.apply(&invalid, deadline()).await.fold(
        |_| false,
        |_| false,
        |e| e == Error::NotFound,
        |_| false,
        |_| false,
        |_| false
    ));
    assert!(operator2.receipt(&invalid, deadline()).await?.is_none());
    let e: i64 = sqlx::query_scalar("SELECT epoch FROM rss_transactional_messaging.tenant_epoch WHERE tenant_id='11111111-1111-1111-1111-111111111111'")
        .fetch_one(&owner)
        .await?;
    assert_eq!(e, 2);
    let a = plan("published", 2, OperationId::new()).await?;
    let b = plan("published", 2, OperationId::new()).await?;
    let (a, b) = tokio::join!(
        operator2.apply(&a, deadline()),
        operator2.apply(&b, deadline())
    );
    let success =
        |v: LocalTxAttempt<Receipt, Error>| v.fold(|_| 1, |_| 0, |_| 0, |_| 0, |_| 0, |_| 0);
    assert_eq!(
        success(a) + success(b),
        1,
        "only one plan wins expected-epoch CAS"
    );
    operator2.close().await;
    Box::pin(states::run(
        &owner,
        &config("dr_runtime")?,
        &config("dr_operator")?,
    ))
    .await?;
    Box::pin(terminate::run(
        &owner,
        &config("dr_runtime")?,
        &config("dr_operator")?,
    ))
    .await?;
    Box::pin(consumer::run(
        config("dr_runtime")?,
        config("dr_operator")?,
        &owner,
    ))
    .await?;
    next.close().await;
    store.close().await;
    runtime.close().await;
    owner.close().await;
    Ok(())
}
