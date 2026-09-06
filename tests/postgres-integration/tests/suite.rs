#![allow(clippy::expect_used, clippy::panic)]
// reason: integration fixtures fail loudly on invalid static identities and test setup.
mod adversarial;
mod conformance;
mod lifecycle;
use rss_transactional_messaging::policy::{
    AbsoluteDeadline, Clock, ExecutionTimer, MonotonicInstant,
};
use rss_transactional_messaging_postgres::{PgConfig, PgPassword, PgRuntime};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

#[derive(Clone)]
struct Timer(Instant);
fn outbox_budget(ttl: Duration) -> rss_transactional_messaging::policy::DeliveryBudget {
    let part =
        Duration::from_millis(u64::try_from(ttl.as_millis() / 4).expect("bounded fixture TTL"));
    rss_transactional_messaging::policy::DeliveryBudget::new(ttl, part, part, part)
        .expect("test lease budget")
}
impl Timer {
    #[allow(clippy::disallowed_methods)]
    // reason: this is the injected real-time clock's single constructor, not provider code.
    fn new() -> Self {
        Self(Instant::now())
    }
}
impl Clock for Timer {
    #[allow(clippy::disallowed_methods)]
    // reason: the concrete test clock must read its monotonic source to implement Clock.
    fn now(&self) -> MonotonicInstant {
        MonotonicInstant::from_elapsed(self.0.elapsed())
    }
}
impl ExecutionTimer for Timer {
    async fn sleep_until(&self, deadline: AbsoluteDeadline) {
        tokio::time::sleep(deadline.remaining(self)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_transactional_messaging_suite() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(180), async {
        let network = testkit::bridge_network("tmsg-pg").await?;
        let fixture = testkit::postgres_tls(testkit::NetworkAttachment { network: network.name(), dns_name: "tmsg-pg" }, testkit::PgTlsServerIdentity::MatchingHost).await?;
        let params = fixture.params();
        let owner = PgPoolOptions::new().max_connections(4).acquire_timeout(Duration::from_secs(5))
            .connect_with(PgConnectOptions::new().host(&params.host).port(params.port).database(&params.database)
                .username(&params.username).password(&params.password).ssl_mode(PgSslMode::VerifyFull)
                .ssl_root_cert_from_pem(fixture.ca_pem().as_bytes().to_vec())).await?;
        sqlx::raw_sql("CREATE ROLE rss_tmsg_relay NOLOGIN NOBYPASSRLS; CREATE ROLE tmsg_runtime LOGIN PASSWORD 'fixture-only' NOBYPASSRLS; CREATE TABLE public.outbox (legacy boolean); CREATE TABLE public.rss_fences (legacy boolean);")
            .execute(&owner).await?;
        sqlx::raw_sql(rss_transactional_messaging_postgres::MIGRATION_SQL).execute(&owner).await?;
        sqlx::raw_sql("GRANT USAGE ON SCHEMA rss_transactional_messaging TO tmsg_runtime; GRANT SELECT ON rss_transactional_messaging.policy TO tmsg_runtime; GRANT SELECT,INSERT,UPDATE,DELETE ON rss_transactional_messaging.inbox TO tmsg_runtime; GRANT SELECT,INSERT ON rss_transactional_messaging.outbox TO tmsg_runtime; GRANT USAGE ON ALL SEQUENCES IN SCHEMA rss_transactional_messaging TO tmsg_runtime; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_transactional_messaging TO tmsg_runtime;")
            .execute(&owner).await?;
        sqlx::raw_sql("CREATE TABLE public.business_effects (tenant_id uuid NOT NULL, id text NOT NULL, PRIMARY KEY(tenant_id,id)); ALTER TABLE public.business_effects ENABLE ROW LEVEL SECURITY; ALTER TABLE public.business_effects FORCE ROW LEVEL SECURITY; CREATE POLICY tenant_effect ON public.business_effects USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid); GRANT SELECT,INSERT ON public.business_effects TO tmsg_runtime;").execute(&owner).await?;
        let timer = Timer::new();
        let config = PgConfig::new(&params.host, params.port, &params.database, "tmsg_runtime", PgPassword::new("fixture-only"), rss_transactional_messaging_postgres::PgPrivateCa::from_pem(fixture.ca_pem().as_bytes().to_vec())?);
        let raw_runtime = PgPoolOptions::new().max_connections(2).acquire_timeout(Duration::from_secs(5))
            .connect_with(PgConnectOptions::new().host(&params.host).port(params.port).database(&params.database)
                .username("tmsg_runtime").password("fixture-only").ssl_mode(PgSslMode::VerifyFull)
                .ssl_root_cert_from_pem(fixture.ca_pem().as_bytes().to_vec())).await?;
        let runtime = Arc::new(PgRuntime::connect(config.clone(), timer).await?);
        tls_rejections(&fixture, &network).await?;
        assert!(!runtime.is_closed());
        outbox_roundtrip(runtime.clone()).await?;
        consumer_receipt(runtime.clone(), &owner).await?;
        localtx_faults(runtime.clone(), &owner).await?;
        Box::pin(conformance::run(runtime.clone(), &owner)).await?;
        Box::pin(adversarial::run(runtime.clone(), &owner, &raw_runtime, config.clone())).await?;
        lifecycle::business_outbox_atomicity(runtime.clone(), &owner).await?;
        lifecycle::close_during_transaction(config.clone(), &owner).await?;
        #[cfg(feature = "rss-runtime")]
        lifecycle::managed_close(config).await?;
        runtime.close().await;
        assert!(runtime.is_closed());
        owner.close().await;
        raw_runtime.close().await;
        drop(fixture);
        Ok::<(), anyhow::Error>(())
    }).await??;
    Ok(())
}

async fn tls_rejections(
    fixture: &testkit::PgTlsFixture,
    network: &testkit::BridgeNetwork,
) -> anyhow::Result<()> {
    use rss_transactional_messaging::error::MessagingErrorKind;
    use rss_transactional_messaging_postgres::PgPrivateCa;
    let params = fixture.params();
    for (database, password, missing) in [
        (
            params.database.as_str(),
            "incorrect-fixture-password",
            false,
        ),
        ("missing_tmsg_database", params.password.as_str(), true),
    ] {
        let config = PgConfig::new(
            &params.host,
            params.port,
            database,
            &params.username,
            PgPassword::new(password),
            PgPrivateCa::from_pem(fixture.ca_pem().as_bytes().to_vec())?,
        );
        let error = PgRuntime::connect(config, Timer::new())
            .await
            .err()
            .expect("invalid configuration");
        assert_eq!(error.kind(), MessagingErrorKind::Permanent);
        assert!(if missing {
            matches!(
                error,
                rss_transactional_messaging_postgres::PgError::DatabaseMissing(_)
            )
        } else {
            matches!(
                error,
                rss_transactional_messaging_postgres::PgError::Authentication(_)
            )
        });
    }
    let wrong_ca = PgConfig::new(
        &params.host,
        params.port,
        &params.database,
        "tmsg_runtime",
        PgPassword::new("fixture-only"),
        PgPrivateCa::from_pem(fixture.wrong_ca_pem().as_bytes().to_vec())?,
    );
    let error = PgRuntime::connect(wrong_ca, Timer::new())
        .await
        .err()
        .expect("wrong CA must fail TLS");
    assert_eq!(error.kind(), MessagingErrorKind::Permanent);
    let wrong_identity = testkit::postgres_tls(
        testkit::NetworkAttachment {
            network: network.name(),
            dns_name: "tmsg-pg-wrong",
        },
        testkit::PgTlsServerIdentity::UnmatchedHost,
    )
    .await?;
    let params = wrong_identity.params();
    let wrong_host = PgConfig::new(
        &params.host,
        params.port,
        &params.database,
        &params.username,
        PgPassword::new(&params.password),
        PgPrivateCa::from_pem(wrong_identity.ca_pem().as_bytes().to_vec())?,
    );
    let result = PgRuntime::connect(wrong_host, Timer::new()).await;
    assert_eq!(
        result.err().expect("wrong hostname must fail TLS").kind(),
        MessagingErrorKind::Permanent
    );
    Ok(())
}

struct Effect(rss_transactional_messaging::transaction::TerminalDisposition);
impl rss_transactional_messaging_postgres::PgConsumerEffect<Vec<u8>> for Effect {
    async fn apply(
        &self,
        tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
        message: &rss_transactional_messaging::message::MessageEnvelope<Vec<u8>>,
        _deadline: rss_transactional_messaging::policy::OperationDeadline,
    ) -> Result<
        rss_transactional_messaging::transaction::TerminalDisposition,
        rss_transactional_messaging_postgres::PgConsumerEffectFailure,
    > {
        let id = message.id().as_str().to_owned();
        let tenant = tx.tenant_id().to_string();
        tx.with_connection(move |connection| {
            Box::pin(async move {
                sqlx::query(
                    "INSERT INTO public.business_effects(tenant_id,id) VALUES($1::uuid,$2)",
                )
                .bind(tenant)
                .bind(id)
                .execute(connection)
                .await?;
                Ok(())
            })
        })
        .await
        .map_err(rss_transactional_messaging_postgres::PgConsumerEffectFailure::infrastructure)?;
        Ok(self.0)
    }
}
struct Validator;
impl rss_transactional_messaging::transaction::IngressValidator<Vec<u8>> for Validator {
    fn validate(
        &self,
        challenge: rss_transactional_messaging::transaction::IngressChallenge<'_, Vec<u8>>,
    ) -> Result<
        rss_transactional_messaging::transaction::VerifiedIngress,
        rss_transactional_messaging::transaction::EnvelopeValidationFailure,
    > {
        Ok(challenge.verified())
    }
}
fn message(id: &str) -> rss_transactional_messaging::message::MessageEnvelope<Vec<u8>> {
    use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
    use rss_transactional_messaging::message::*;
    MessageEnvelope::new(
        MessageId::parse(id).expect("id"),
        MessageMetadata::new(
            AuthoredMessageMetadata::new(
                rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
                    .expect("tenant"),
                Timepoint::try_from(1_i64).expect("time"),
                MessagingDomain::parse("integration").expect("domain"),
                MessageRoute::parse("created").expect("route"),
                ContractIdentity::new(
                    ContractId::parse("integration.created").expect("contract"),
                    ContractVersion::from_major(1).expect("version"),
                    SchemaDigest::parse(&format!("sha256:{}", "a".repeat(64))).expect("digest"),
                ),
            ),
            MessageMetadataExtensions::default(),
        ),
        vec![1, 2, 3],
    )
}
fn binding(
    message: &rss_transactional_messaging::message::MessageEnvelope<Vec<u8>>,
) -> rss_transactional_messaging::transaction::VerifiedConsumerBinding {
    use rss_transactional_messaging::{
        inbox::ConsumerGroup, message::SubscriptionIdentity, transaction::verify_ingress,
    };
    let metadata = message.metadata();
    verify_ingress(
        &Validator,
        ConsumerGroup::parse("suite").expect("group"),
        &SubscriptionIdentity::new(
            metadata.domain().clone(),
            metadata.route().clone(),
            metadata.contract().clone(),
        ),
        message,
    )
    .unwrap_or_else(|_| panic!("valid test ingress"))
}
fn deadline() -> rss_transactional_messaging::policy::OperationDeadline {
    let clock = Timer::new();
    AbsoluteDeadline::from_timeout(&clock, Duration::from_secs(5))
        .expect("deadline")
        .operation(&clock)
}

async fn localtx_faults(runtime: Arc<PgRuntime>, owner: &sqlx::PgPool) -> anyhow::Result<()> {
    use rss_transactional_messaging_postgres::PgTransactionFault;
    let tenant = message("fault").metadata().tenant_id();
    for (id, fault, rollback, expected, durable) in [
        (
            "unknown-ack",
            PgTransactionFault::CommitUnknownAfterAck,
            false,
            "unknown",
            1_i64,
        ),
        (
            "rollback-ack",
            PgTransactionFault::RollbackFailedAfterAck,
            true,
            "rollback-failed",
            0_i64,
        ),
    ] {
        runtime.inject_next_transaction_fault(fault);
        let attempt = runtime
            .local_tx(tenant, deadline(), move |tx| {
                Box::pin(async move {
                    tx.with_connection(move |connection| Box::pin(async move {
                sqlx::query("INSERT INTO public.business_effects(tenant_id,id) VALUES($1::uuid,$2)")
                    .bind(tenant.to_string()).bind(id).execute(connection).await?;
                Ok(())
            })).await?;
                    if rollback {
                        Err(sqlx::Error::PoolTimedOut.into())
                    } else {
                        Ok(())
                    }
                })
            })
            .await;
        let status = attempt.fold(
            |_| "committed",
            |_| "not-started",
            |_| "rolled-back",
            |_| "rollback-failed",
            |_| "unknown",
            |_| "fenced",
        );
        assert_eq!(status, expected);
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM public.business_effects WHERE id=$1")
                .bind(id)
                .fetch_one(owner)
                .await?;
        assert_eq!(count, durable);
    }
    Ok(())
}
async fn consumer_receipt(runtime: Arc<PgRuntime>, owner: &sqlx::PgPool) -> anyhow::Result<()> {
    use rss_transactional_messaging::{
        inbox::{IdempotencyDisposition, InboxStore},
        transaction::{ConsumerTx, RejectKind, TerminalDisposition},
    };
    use rss_transactional_messaging_postgres::{PgConsumerTx, PgInboxStore};
    let inbox = PgInboxStore::new(
        runtime.clone(),
        rss_transactional_messaging::policy::LeaseRenewalPolicy::from_ttl(Duration::from_secs(60))?,
    )?;
    for (id, disposition, count) in [
        ("consumer-success", TerminalDisposition::Succeeded, 1_i64),
        (
            "consumer-reject",
            TerminalDisposition::Rejected(RejectKind::Permanent),
            0,
        ),
    ] {
        let message = message(id);
        let binding = binding(&message);
        let IdempotencyDisposition::Acquired(claim) =
            inbox.claim(binding.identity(), deadline()).await?
        else {
            panic!("new claim")
        };
        let consumer = PgConsumerTx::new(runtime.clone(), Effect(disposition));
        let outcome = consumer
            .execute(&claim, &message, binding.receipt_intent(), deadline())
            .await;
        assert_eq!(outcome.status(), rss_transactional_messaging::observability::TransactionalMessagingTransactionStatus::Committed);
        let receipt = inbox
            .read_terminal(binding.identity(), deadline())
            .await?
            .expect("durable receipt");
        assert_eq!(receipt.disposition(), disposition);
        assert!(binding.validate_terminal(receipt).is_ok());
        assert!(matches!(
            inbox.claim(binding.identity(), deadline()).await?,
            IdempotencyDisposition::Terminal(_)
        ));
        let actual: i64 =
            sqlx::query_scalar("SELECT count(*) FROM public.business_effects WHERE id=$1")
                .bind(id)
                .fetch_one(owner)
                .await?;
        assert_eq!(actual, count);
    }
    Ok(())
}

async fn outbox_roundtrip(runtime: Arc<PgRuntime>) -> anyhow::Result<()> {
    use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
    use rss_request_context::TenantId;
    use rss_transactional_messaging::{message::*, outbox::*};
    use rss_transactional_messaging_postgres::PgOutboxStore;
    let tenant = TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")?;
    let domain = MessagingDomain::parse("integration")?;
    let store = Arc::new(PgOutboxStore::<()>::new(
        runtime.clone(),
        domain.clone(),
        crate::outbox_budget(Duration::from_secs(60)),
    )?);
    let message = PendingMessage::new(MessageEnvelope::new(
        MessageId::parse("outbox-roundtrip")?,
        MessageMetadata::new(
            AuthoredMessageMetadata::new(
                tenant,
                Timepoint::try_from(1_i64)?,
                domain,
                MessageRoute::parse("created")?,
                ContractIdentity::new(
                    ContractId::parse("integration.created")?,
                    ContractVersion::from_major(1)?,
                    SchemaDigest::parse(&format!("sha256:{}", "a".repeat(64)))?,
                ),
            ),
            MessageMetadataExtensions::default(),
        ),
        vec![1, 2, 3],
    ));
    let clock = Timer::new();
    let deadline = || {
        AbsoluteDeadline::from_timeout(&clock, Duration::from_secs(5))
            .expect("deadline")
            .operation(&clock)
    };
    let append_store = store.clone();
    runtime
        .local_tx(tenant, deadline(), move |tx| {
            Box::pin(async move { append_store.append(tx, message).await.map_err(Into::into) })
        })
        .await
        .fold(
            |value| {
                assert_eq!(value, AppendOutcome::Inserted);
                Ok(())
            },
            Err,
            Err,
            Err,
            Err,
            Err,
        )?;
    let claims = store
        .claim_partition_heads(std::num::NonZeroUsize::MIN, deadline())
        .await?;
    let claim = claims.into_iter().next().expect("one durable claim");
    assert_eq!(
        PgOutboxStore::<()>::message(&claim).envelope().payload(),
        &[1, 2, 3]
    );
    assert!(
        matches!(store.extend(&claim, deadline()).await?, OutboxLeaseStatus::Held { delivery_remaining: Some(value), .. } if value > Duration::from_secs(86000))
    );
    store
        .settle(claim, OutboxSettlement::Published(()), deadline())
        .await?;
    assert_eq!(
        store
            .claim_partition_heads(std::num::NonZeroUsize::MIN, deadline())
            .await?
            .into_iter()
            .count(),
        0
    );
    Ok(())
}
