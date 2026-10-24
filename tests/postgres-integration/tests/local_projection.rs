//! Real PostgreSQL proof of local effect + Inbox + Outbox atomic settlement.
#[path = "local_projection/batch.rs"]
mod batch;
#[path = "../../fixtures/message_fence.rs"]
mod fence_fixture;
#[path = "../../fixtures/message_recovery.rs"]
mod support;
use rss_transactional_messaging::observability::TransactionalMessagingTransactionStatus as Status;
use rss_transactional_messaging::{
    inbox::ConsumerGroup,
    message::*,
    outbox::{OutboxWriter, PendingMessage},
    policy::{DeliveryBudget, LeaseRenewalPolicy, OperationDeadline},
    transaction::*,
};
use rss_transactional_messaging_postgres::*;
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions, PgSslMode},
};
use std::{num::NonZeroUsize, sync::Arc, time::Duration};
use support::{Key, Timer, tenant};
use tokio::sync::Notify;

fn deadline() -> OperationDeadline {
    let timer = Timer::new();
    OperationDeadline::from_cutoff(timer.cutoff(), &timer)
}
fn domain() -> anyhow::Result<MessagingDomain> {
    Ok(MessagingDomain::parse("orders")?)
}
fn group() -> anyhow::Result<ConsumerGroup> {
    Ok(ConsumerGroup::parse("projection")?)
}
fn committed<T>(attempt: LocalTxAttempt<T, PgError>) -> anyhow::Result<T> {
    attempt.fold(
        Ok,
        |e| Err(e.into()),
        |e| Err(e.into()),
        |e| Err(e.into()),
        |e| Err(e.into()),
        |e| Err(e.into()),
    )
}
fn projection_attempt(value: PgProjectionOutcome) -> anyhow::Result<PgProjectionAttempt> {
    match value {
        PgProjectionOutcome::Attempt(attempt) => Ok(*attempt),
        _ => anyhow::bail!("expected consumer transaction attempt"),
    }
}
fn attempt_status(value: PgProjectionOutcome) -> anyhow::Result<Status> {
    Ok(projection_attempt(value)?.into_parts().0.status())
}
fn committed_projection(value: PgProjectionOutcome) -> anyhow::Result<TerminalSettlement> {
    projection_attempt(value)?.into_parts().0.fold(
        |committed| Ok(committed.into_parts().1),
        |_| Err(anyhow::anyhow!("not started")),
        |_| Err(anyhow::anyhow!("rolled back")),
        || Err(anyhow::anyhow!("rollback failed")),
        || Err(anyhow::anyhow!("commit unknown")),
        || Err(anyhow::anyhow!("fenced")),
    )
}
fn uncertain_projection(value: PgProjectionOutcome) -> anyhow::Result<PgProjectionRecovery> {
    let (outcome, recovery) = projection_attempt(value)?.into_parts();
    assert_eq!(outcome.status(), Status::CommitUnknown);
    Ok(recovery)
}

fn message(id: &str, domain: &str) -> anyhow::Result<MessageEnvelope<Vec<u8>>> {
    message_partition(id, domain, None)
}
fn message_partition(
    id: &str,
    domain: &str,
    partition: Option<PartitionKey>,
) -> anyhow::Result<MessageEnvelope<Vec<u8>>> {
    let original = support::message(id);
    let authored = AuthoredMessageMetadata::new(
        tenant(),
        original.metadata().occurred_at(),
        MessagingDomain::parse(domain)?,
        original.metadata().route().clone(),
        original.metadata().contract().clone(),
    );
    Ok(MessageEnvelope::new(
        MessageId::parse(id)?,
        MessageMetadata::new(
            authored,
            MessageMetadataExtensions::new(None, partition, None, Default::default()),
        ),
        b"frozen-source".to_vec(),
    ))
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
struct RejectIngress;
impl IngressValidator<Vec<u8>> for RejectIngress {
    fn validate(
        &self,
        _: IngressChallenge<'_, Vec<u8>>,
    ) -> Result<VerifiedIngress, EnvelopeValidationFailure> {
        Err(EnvelopeValidationFailure::UnsupportedContract)
    }
}
#[derive(Clone, Default)]
struct Gate {
    entered: Arc<Notify>,
    resume: Arc<Notify>,
}
struct Effect {
    gate: Option<Gate>,
    reject: bool,
    fail: bool,
}
impl PgConsumerEffect<Vec<u8>> for Effect {
    async fn apply(
        &self,
        tx: &mut PgTransaction<'_>,
        message: &MessageEnvelope<Vec<u8>>,
        _: OperationDeadline,
    ) -> Result<TerminalDisposition, PgConsumerEffectFailure> {
        let mut id = message.id().as_str();
        tx.with_connection_context(&mut id, |id, c| {
            Box::pin(async move {
                sqlx::query("INSERT INTO public.effect_a VALUES($1)")
                    .bind(*id)
                    .execute(c)
                    .await?;
                Ok(())
            })
        })
        .await
        .map_err(PgConsumerEffectFailure::infrastructure)?;
        if let Some(gate) = &self.gate {
            gate.entered.notify_one();
            gate.resume.notified().await;
        }
        if self.fail {
            return Err(PgConsumerEffectFailure::handler_transient(
                std::io::Error::other("fixture effect failure"),
            ));
        }
        let id = message.id().as_str().to_owned();
        tx.with_connection(move |c| {
            Box::pin(async move {
                sqlx::query("INSERT INTO public.effect_b VALUES($1)")
                    .bind(id)
                    .execute(c)
                    .await?;
                Ok(())
            })
        })
        .await
        .map_err(PgConsumerEffectFailure::infrastructure)?;
        Ok(if self.reject {
            TerminalDisposition::Rejected(RejectKind::Permanent)
        } else {
            TerminalDisposition::Succeeded
        })
    }
}

struct Fixture {
    owner: PgPool,
    raw_worker: PgPool,
    producer: Arc<PgRuntime>,
    worker: Arc<PgRuntime>,
    config: PgConfig,
}
impl Fixture {
    async fn append(&self, id: &str, domain: &str) -> anyhow::Result<()> {
        let writer = PgOutboxWriter::new(self.producer.clone(), MessagingDomain::parse(domain)?);
        let message = PendingMessage::new(message(id, domain)?);
        committed(
            self.producer
                .local_tx_with_context(
                    tenant(),
                    deadline(),
                    (writer, Some(message)),
                    |(writer, message), tx| {
                        Box::pin(async move {
                            let message = message.take().ok_or_else(|| {
                                sqlx::Error::Protocol("fixture callback repeated".into())
                            })?;
                            writer
                                .append(tx, message)
                                .await
                                .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
                            Ok(())
                        })
                    },
                )
                .await,
        )
    }
    async fn projection(
        &self,
        effect: Effect,
    ) -> anyhow::Result<Arc<PgLocalProjection<Effect, Key>>> {
        Self::projection_on(self.worker.clone(), effect).await
    }
    async fn projection_on(
        runtime: Arc<PgRuntime>,
        effect: Effect,
    ) -> anyhow::Result<Arc<PgLocalProjection<Effect, Key>>> {
        let capture = PgRecoveryCapture::new(runtime, Arc::new(Key(1)), deadline()).await?;
        Ok(Arc::new(
            PgLocalProjection::new(
                capture,
                group()?,
                domain()?,
                effect,
                DeliveryBudget::new(
                    Duration::from_secs(2),
                    Duration::from_millis(400),
                    Duration::from_millis(400),
                    Duration::from_millis(400),
                )?,
                LeaseRenewalPolicy::from_ttl(Duration::from_secs(2))?,
                deadline(),
            )
            .await?,
        ))
    }
    async fn state(&self, id: &str) -> anyhow::Result<(i64, i64, Option<String>, String)> {
        Ok(sqlx::query_as("SELECT (SELECT count(*) FROM public.effect_a WHERE id=$1),(SELECT count(*) FROM public.effect_b WHERE id=$1),(SELECT disposition FROM rss_transactional_messaging.inbox WHERE message_id=$1 AND consumer_group='projection'),(SELECT status FROM rss_transactional_messaging.outbox WHERE message_id=$1)")
            .bind(id).fetch_one(&self.owner).await?)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn local_projection_atomicity_scope_and_recovery() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(180), Box::pin(run())).await??;
    Ok(())
}
#[allow(
    clippy::cognitive_complexity,
    reason = "Keep each sequential provider fault, its durable assertions and cleanup in one scenario."
)]
async fn run() -> anyhow::Result<()> {
    let network = testkit::bridge_network("local-projection").await?;
    let pg = testkit::postgres_tls(
        testkit::NetworkAttachment {
            network: network.name(),
            dns_name: "local-projection",
        },
        testkit::PgTlsServerIdentity::MatchingHost,
    )
    .await?;
    let params = pg.params();
    let options = PgConnectOptions::new()
        .host(&params.host)
        .port(params.port)
        .database(&params.database)
        .options([
            ("rss.tenant_id", "11111111-1111-1111-1111-111111111111"),
            ("rss.storage_target", "01010101010101010101010101010101"),
            ("rss.storage_lineage", "02020202020202020202020202020202"),
            ("rss.execution_epoch", "1"),
        ])
        .username(&params.username)
        .password(&params.password)
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert_from_pem(pg.ca_pem().as_bytes().to_vec());
    let owner = PgPoolOptions::new()
        .max_connections(6)
        .connect_with(options.clone())
        .await?;
    sqlx::raw_sql("CREATE ROLE rss_tmsg_relay NOLOGIN NOBYPASSRLS; CREATE ROLE projection_producer LOGIN PASSWORD 'fixture-only' NOBYPASSRLS; CREATE ROLE projection_worker LOGIN PASSWORD 'fixture-only' NOBYPASSRLS; CREATE ROLE projection_other LOGIN PASSWORD 'fixture-only' NOBYPASSRLS;").execute(&owner).await?;
    let installed_0012 = MIGRATION_SQL
        .strip_suffix(BATCH_PROJECTION_UPGRADE_SQL)
        .ok_or_else(|| anyhow::anyhow!("ordered migration boundary"))?;
    sqlx::raw_sql(installed_0012).execute(&owner).await?;
    sqlx::raw_sql("GRANT USAGE ON SCHEMA rss_transactional_messaging TO projection_producer; GRANT SELECT ON rss_transactional_messaging.policy,rss_transactional_messaging.outbox TO projection_producer; GRANT EXECUTE ON FUNCTION rss_transactional_messaging.prepare_outbox_partitions(jsonb),rss_transactional_messaging.append_outbox(bytea,jsonb) TO projection_producer;").execute(&owner).await?;
    {
        let mut tx = owner.begin().await?;
        grant_local_projection(&mut tx, "projection_worker", &domain()?, &group()?).await?;
        grant_consumer(&mut tx, "projection_other").await?;
        tx.commit().await?;
    }
    sqlx::raw_sql("GRANT projection_other TO projection_worker; GRANT SELECT,INSERT ON rss_transactional_messaging.consumer_dead_letter TO projection_worker,projection_other; CREATE TABLE public.effect_a(id text PRIMARY KEY); CREATE TABLE public.effect_b(id text PRIMARY KEY); GRANT SELECT,INSERT ON public.effect_a,public.effect_b TO projection_worker;").execute(&owner).await?;
    fence_fixture::provision(&owner).await?;
    for id in ["upgrade-pending", "upgrade-published"] {
        let message = message(id, "orders")?;
        sqlx::query("SELECT rss_transactional_messaging.append_outbox($1,$2)")
            .bind(message.canonical_bytes())
            .bind(serde_json::json!({"trace":null,"tenant_authority":null}))
            .execute(&owner)
            .await?;
    }
    sqlx::query("UPDATE rss_transactional_messaging.outbox SET status='published' WHERE message_id='upgrade-published'").execute(&owner).await?;
    sqlx::raw_sql(BATCH_PROJECTION_UPGRADE_SQL)
        .execute(&owner)
        .await?;
    let config = |user| -> anyhow::Result<PgConfig> {
        Ok(PgConfig::new(
            &params.host,
            params.port,
            &params.database,
            user,
            PgPassword::new("fixture-only"),
            PgPrivateCa::from_pem(pg.ca_pem().as_bytes().to_vec())?,
        ))
    };
    let producer = Arc::new(
        PgRuntime::connect_producer(
            config("projection_producer")?,
            Timer::new(),
            fence_fixture::binding(),
        )
        .await?,
    );
    let worker_config = config("projection_worker")?;
    let worker = Arc::new(
        PgRuntime::connect_consumer(
            worker_config.clone(),
            Timer::new(),
            fence_fixture::binding(),
        )
        .await?,
    );
    let raw_worker = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(
            options
                .username("projection_worker")
                .password("fixture-only"),
        )
        .await?;
    let f = Fixture {
        owner,
        raw_worker,
        producer,
        worker,
        config: worker_config,
    };
    let upgraded = f
        .projection(Effect {
            gate: None,
            reject: false,
            fail: false,
        })
        .await?;
    let items = upgraded
        .project_batch(
            &Validator,
            NonZeroUsize::new(2).unwrap(),
            deadline(),
            Duration::from_secs(5),
        )
        .await?;
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].message_id().as_str(), "upgrade-pending");
    committed_projection(only(items)?)?;
    assert_eq!(f.state("upgrade-published").await?.3, "published");
    drop(upgraded);
    Box::pin(batch::run(&f)).await?;
    Box::pin(success_and_duplicate(&f)).await?;
    Box::pin(ingress_rejection(&f)).await?;
    Box::pin(rejected_and_failed(&f)).await?;
    Box::pin(redrive_unknown(&f)).await?;
    Box::pin(unknown_commit(&f)).await?;
    Box::pin(unknown_rollback(&f)).await?;
    Box::pin(renewal_and_expiry(&f)).await?;
    Box::pin(cancellation_and_restart(&f)).await?;
    Box::pin(pool_capacity(&f)).await?;
    Box::pin(scoped_permissions(&f)).await?;
    Box::pin(dr_recovery(&f)).await?;
    f.worker.close().await;
    f.producer.close().await;
    f.raw_worker.close().await;
    f.owner.close().await;
    Ok(())
}
#[allow(
    clippy::cognitive_complexity,
    reason = "Keep the in-flight visibility, canonical commit proof and duplicate assertions in one sequence."
)]
async fn success_and_duplicate(f: &Fixture) -> anyhow::Result<()> {
    f.append("atomic-success", "orders").await?;
    let gate = Gate::default();
    let projection = f
        .projection(Effect {
            gate: Some(gate.clone()),
            reject: false,
            fail: false,
        })
        .await?;
    let task = tokio::spawn({
        let projection = projection.clone();
        async move {
            only(
                projection
                    .project_batch(
                        &Validator,
                        NonZeroUsize::MIN,
                        deadline(),
                        Duration::from_secs(5),
                    )
                    .await?,
            )
        }
    });
    gate.entered.notified().await;
    assert_eq!(
        f.state("atomic-success").await?,
        (0, 0, None, "publishing".into())
    );
    assert!(
        projection
            .project_batch(
                &Validator,
                NonZeroUsize::MIN,
                deadline(),
                Duration::from_secs(5)
            )
            .await?
            .is_empty()
    );
    gate.resume.notify_one();
    let receipt = committed_projection(task.await??)?;
    assert_eq!(receipt.disposition(), TerminalDisposition::Succeeded);
    assert_eq!(
        f.state("atomic-success").await?,
        (1, 1, Some("succeeded".into()), "published".into())
    );
    assert!(
        projection
            .project_batch(
                &Validator,
                NonZeroUsize::MIN,
                deadline(),
                Duration::from_secs(5)
            )
            .await?
            .is_empty()
    );
    Ok(())
}

async fn ingress_rejection(f: &Fixture) -> anyhow::Result<()> {
    let p = f
        .projection(Effect {
            gate: None,
            reject: false,
            fail: true,
        })
        .await?;
    assert!(!p.has_dead_letters(deadline()).await?);
    f.append("ingress-denied", "orders").await?;
    assert!(matches!(
        only(
            p.project_batch(
                &RejectIngress,
                NonZeroUsize::MIN,
                deadline(),
                Duration::from_secs(5)
            )
            .await?
        )?,
        PgProjectionOutcome::Rejected(EnvelopeValidationFailure::UnsupportedContract)
    ));
    assert_eq!(
        f.state("ingress-denied").await?,
        (0, 0, None, "dead_letter".into())
    );
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM rss_transactional_messaging.inbox WHERE message_id='ingress-denied'",
    )
    .fetch_one(&f.owner)
    .await?;
    assert_eq!(count, 0, "ingress rejection must precede Inbox claiming");
    assert!(p.has_dead_letters(deadline()).await?);
    Ok(())
}

#[allow(
    clippy::cognitive_complexity,
    reason = "Keep redrive, lost commit acknowledgement, durable readback and conflicting-terminal assertions together."
)]
async fn redrive_unknown(f: &Fixture) -> anyhow::Result<()> {
    // Preseed the confirmed Redrive state; recovery mutation authorization has its own T2 owner.
    let changed=sqlx::query("UPDATE rss_transactional_messaging.outbox SET status='pending',retry_after=clock_timestamp(),recovery_version=recovery_version+1 WHERE message_id='atomic-rejected' AND status='dead_letter'").execute(&f.owner).await?.rows_affected();
    assert_eq!(changed, 1);
    let p = f
        .projection(Effect {
            gate: None,
            reject: false,
            fail: true,
        })
        .await?;
    p.inject_next_projection_fault(PgTransactionFault::CommitPending)?;
    let pending = uncertain_projection(only(
        p.project_batch(
            &Validator,
            NonZeroUsize::MIN,
            deadline(),
            Duration::from_secs(5),
        )
        .await?,
    )?)?;
    assert_eq!(
        f.state("atomic-rejected").await?,
        (0, 0, Some("rejected_permanent".into()), "publishing".into())
    );
    assert!(
        p.resolve(&pending, deadline()).await?.is_none(),
        "publishing with a historical receipt is not corruption or completed settlement"
    );
    sqlx::query("UPDATE rss_transactional_messaging.outbox SET lease_until=clock_timestamp()-interval '1 second' WHERE message_id='atomic-rejected' AND status='publishing'").execute(&f.owner).await?;
    let receipt = committed_projection(only(
        p.project_batch(
            &Validator,
            NonZeroUsize::MIN,
            deadline(),
            Duration::from_secs(5),
        )
        .await?,
    )?)?;
    assert_eq!(
        receipt.disposition(),
        TerminalDisposition::Rejected(RejectKind::Permanent)
    );
    assert!(p.resolve(&pending, deadline()).await?.is_some());
    assert_eq!(
        f.state("atomic-rejected").await?,
        (
            0,
            0,
            Some("rejected_permanent".into()),
            "dead_letter".into()
        )
    );
    sqlx::query("UPDATE rss_transactional_messaging.outbox SET status='published' WHERE message_id='atomic-rejected'").execute(&f.owner).await?;
    assert!(
        p.resolve(&pending, deadline()).await.is_err(),
        "contradictory terminal facts remain an integrity error"
    );
    sqlx::query("UPDATE rss_transactional_messaging.outbox SET status='dead_letter' WHERE message_id='atomic-rejected'").execute(&f.owner).await?;
    Ok(())
}
#[allow(
    clippy::cognitive_complexity,
    reason = "Keep each sequential provider fault, its durable assertions and cleanup in one scenario."
)]
async fn rejected_and_failed(f: &Fixture) -> anyhow::Result<()> {
    f.append("atomic-rejected", "orders").await?;
    let p = f
        .projection(Effect {
            gate: None,
            reject: true,
            fail: false,
        })
        .await?;
    let receipt = committed_projection(only(
        p.project_batch(
            &Validator,
            NonZeroUsize::MIN,
            deadline(),
            Duration::from_secs(5),
        )
        .await?,
    )?)?;
    assert_eq!(
        receipt.disposition(),
        TerminalDisposition::Rejected(RejectKind::Permanent)
    );
    assert_eq!(
        f.state("atomic-rejected").await?,
        (
            0,
            0,
            Some("rejected_permanent".into()),
            "dead_letter".into()
        )
    );
    let captured:i64=sqlx::query_scalar("SELECT count(*) FROM rss_transactional_messaging.consumer_dead_letter WHERE message_id='atomic-rejected' AND capsule IS NOT NULL").fetch_one(&f.owner).await?;
    assert_eq!(captured, 1);
    f.append("atomic-failed", "orders").await?;
    let p = f
        .projection(Effect {
            gate: None,
            reject: false,
            fail: true,
        })
        .await?;
    assert_eq!(
        attempt_status(only(
            p.project_batch(
                &Validator,
                NonZeroUsize::MIN,
                deadline(),
                Duration::from_secs(5)
            )
            .await?
        )?)?,
        Status::HandlerTransient
    );
    assert_eq!(
        f.state("atomic-failed").await?,
        (0, 0, None, "pending".into())
    );
    // Keep later cases independent while retaining this failed source's original bytes.
    sqlx::query("UPDATE rss_transactional_messaging.outbox SET retry_after=clock_timestamp()+interval '1 day' WHERE message_id='atomic-failed'").execute(&f.owner).await?;
    Ok(())
}
async fn unknown_rollback(f: &Fixture) -> anyhow::Result<()> {
    f.append("atomic-rollback-unknown", "orders").await?;
    let p = f
        .projection(Effect {
            gate: None,
            reject: false,
            fail: true,
        })
        .await?;
    p.inject_next_projection_fault(PgTransactionFault::RollbackFailedAfterAck)?;
    let (outcome, recovery) = projection_attempt(only(
        p.project_batch(
            &Validator,
            NonZeroUsize::MIN,
            deadline(),
            Duration::from_secs(5),
        )
        .await?,
    )?)?
    .into_parts();
    // The owner cannot infer rollback from this fixture's suppressed acknowledgement.
    assert_eq!(outcome.status(), Status::RollbackFailed);
    assert_eq!(
        f.state("atomic-rollback-unknown").await?,
        (0, 0, None, "publishing".into())
    );
    assert!(p.resolve(&recovery, deadline()).await?.is_none());
    // Keep later cases independent; neither the API nor the worker releases this unknown claim.
    sqlx::query("UPDATE rss_transactional_messaging.outbox SET lease_until=clock_timestamp()+interval '1 day' WHERE message_id='atomic-rollback-unknown'").execute(&f.owner).await?;
    Ok(())
}
async fn unknown_commit(f: &Fixture) -> anyhow::Result<()> {
    f.append("atomic-unknown", "orders").await?;
    let p = f
        .projection(Effect {
            gate: None,
            reject: false,
            fail: false,
        })
        .await?;
    p.inject_next_projection_fault(PgTransactionFault::CommitUnknownAfterAck)?;
    let pending = uncertain_projection(only(
        p.project_batch(
            &Validator,
            NonZeroUsize::MIN,
            deadline(),
            Duration::from_secs(5),
        )
        .await?,
    )?)?;
    assert_eq!(
        f.state("atomic-unknown").await?,
        (1, 1, Some("succeeded".into()), "published".into())
    );
    let receipt = p
        .resolve(&pending, deadline())
        .await?
        .ok_or_else(|| anyhow::anyhow!("committed fact missing"))?;
    assert_eq!(receipt.disposition(), TerminalDisposition::Succeeded);
    assert!(
        p.project_batch(
            &Validator,
            NonZeroUsize::MIN,
            deadline(),
            Duration::from_secs(5)
        )
        .await?
        .is_empty()
    );
    Ok(())
}
#[allow(
    clippy::cognitive_complexity,
    reason = "Keep each sequential provider fault, its durable assertions and cleanup in one scenario."
)]
async fn renewal_and_expiry(f: &Fixture) -> anyhow::Result<()> {
    f.append("atomic-renewal", "orders").await?;
    let gate = Gate::default();
    let p = f
        .projection(Effect {
            gate: Some(gate.clone()),
            reject: false,
            fail: false,
        })
        .await?;
    let task = tokio::spawn({
        let p = p.clone();
        async move {
            only(
                p.project_batch(
                    &Validator,
                    NonZeroUsize::MIN,
                    deadline(),
                    Duration::from_secs(5),
                )
                .await?,
            )
        }
    });
    gate.entered.notified().await;
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert!(
        p.project_batch(
            &Validator,
            NonZeroUsize::MIN,
            deadline(),
            Duration::from_secs(5)
        )
        .await?
        .is_empty()
    );
    gate.resume.notify_one();
    assert_eq!(
        committed_projection(task.await??)?.disposition(),
        TerminalDisposition::Succeeded
    );
    assert_eq!(
        f.state("atomic-renewal").await?,
        (1, 1, Some("succeeded".into()), "published".into())
    );

    f.append("atomic-expired", "orders").await?;
    let gate = Gate::default();
    let p = f
        .projection(Effect {
            gate: Some(gate.clone()),
            reject: false,
            fail: false,
        })
        .await?;
    let task = tokio::spawn({
        let p = p.clone();
        async move {
            only(
                p.project_batch(
                    &Validator,
                    NonZeroUsize::MIN,
                    deadline(),
                    Duration::from_secs(5),
                )
                .await?,
            )
        }
    });
    gate.entered.notified().await;
    let mut blocker = f.owner.begin().await?;
    sqlx::query("SELECT seq FROM rss_transactional_messaging.outbox WHERE message_id='atomic-expired' FOR UPDATE").execute(&mut *blocker).await?;
    gate.resume.notify_one();
    tokio::time::sleep(Duration::from_millis(2500)).await;
    blocker.commit().await?;
    assert_eq!(
        attempt_status(task.await??)?,
        Status::InfrastructureTransient
    );
    assert_eq!(
        f.state("atomic-expired").await?,
        (0, 0, None, "publishing".into())
    );
    sqlx::query("UPDATE rss_transactional_messaging.outbox SET retry_after=clock_timestamp()+interval '1 day' WHERE message_id='atomic-expired'").execute(&f.owner).await?;
    Ok(())
}
#[allow(
    clippy::cognitive_complexity,
    reason = "Keep each sequential provider fault, its durable assertions and cleanup in one scenario."
)]
#[allow(
    clippy::expect_used,
    reason = "A forbidden real PG operation succeeding must fail this negative test immediately."
)]
async fn scoped_permissions(f: &Fixture) -> anyhow::Result<()> {
    direct_scope_predicate(f).await?;
    f.append("foreign-domain", "other").await?;
    let foreign: (i64,String,i64) = sqlx::query_as("SELECT seq,lease_token::text,(extract(epoch FROM lease_until)*1000000)::bigint FROM rss_transactional_messaging.claim_outbox($1::uuid,'other',1,5000)")
        .bind(tenant().to_string()).fetch_one(&f.owner).await?;
    let mut tx = f.raw_worker.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('rss.storage_target','01010101010101010101010101010101',true),set_config('rss.storage_lineage','02020202020202020202020202020202',true),set_config('rss.execution_epoch','1',true)").bind(tenant().to_string()).execute(&mut *tx).await?;
    sqlx::query("SET LOCAL ROLE projection_other")
        .execute(&mut *tx)
        .await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM rss_transactional_messaging.outbox WHERE domain='other'",
    )
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(count, 0, "SET ROLE must not widen the login domain");
    let claims = sqlx::query(
        "SELECT * FROM rss_transactional_messaging.claim_outbox($1::uuid,'other',1,2000)",
    )
    .bind(tenant().to_string())
    .fetch_all(&mut *tx)
    .await?;
    assert!(claims.is_empty(), "definer must enforce the same domain");
    let status: String = sqlx::query_scalar("SELECT rss_transactional_messaging.settle_outbox($1::uuid,$2,$3::uuid,$4,'published',NULL)")
        .bind(tenant().to_string()).bind(foreign.0).bind(&foreign.1).bind(foreign.2).fetch_one(&mut *tx).await?;
    assert_eq!(
        status, "lost_lease",
        "even a known foreign claim cannot be settled"
    );
    sqlx::query("SAVEPOINT forbidden_inbox")
        .execute(&mut *tx)
        .await?;
    assert!(sqlx::query("INSERT INTO rss_transactional_messaging.inbox(tenant_id,message_id,consumer_group,contract,lease_token,lease_until) VALUES($1::uuid,'foreign-domain','projection','foreign',gen_random_uuid(),clock_timestamp()+interval '5 seconds')")
        .bind(tenant().to_string()).execute(&mut *tx).await.is_err());
    sqlx::query("ROLLBACK TO SAVEPOINT forbidden_inbox")
        .execute(&mut *tx)
        .await?;
    // Keep the source domain valid and vary only consumer_group, with table ACLs admitted.
    let granted: bool = sqlx::query_scalar("SELECT has_table_privilege(current_user,'rss_transactional_messaging.inbox','INSERT') AND has_table_privilege(current_user,'rss_transactional_messaging.consumer_dead_letter','INSERT')")
        .fetch_one(&mut *tx).await?;
    assert!(granted);
    sqlx::query("SAVEPOINT wrong_group")
        .execute(&mut *tx)
        .await?;
    let error = sqlx::query("INSERT INTO rss_transactional_messaging.inbox(tenant_id,message_id,consumer_group,contract,lease_token,lease_until) VALUES($1::uuid,'atomic-success','wrong-group','foreign',gen_random_uuid(),clock_timestamp()+interval '5 seconds')")
        .bind(tenant().to_string()).execute(&mut *tx).await.expect_err("same-domain wrong group must fail RLS");
    assert_eq!(
        error.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("42501")
    );
    sqlx::query("ROLLBACK TO SAVEPOINT wrong_group")
        .execute(&mut *tx)
        .await?;
    let error = sqlx::query("INSERT INTO rss_transactional_messaging.consumer_dead_letter(tenant_id,id,message_id,consumer_group,contract,contract_version,schema_digest,fingerprint,capsule,reason) SELECT tenant_id,gen_random_uuid(),message_id,'wrong-group','orders.created','1','sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',fingerprint,decode('01','hex'),'rejected_permanent' FROM rss_transactional_messaging.outbox WHERE message_id='atomic-success'")
        .execute(&mut *tx).await.expect_err("same-domain wrong dead-letter group must fail RLS");
    assert_eq!(
        error.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("42501")
    );
    sqlx::query("ROLLBACK TO SAVEPOINT wrong_group")
        .execute(&mut *tx)
        .await?;
    tx.rollback().await?;
    sqlx::raw_sql(
        "ALTER TABLE rss_transactional_messaging.consumer_scope ENABLE ROW LEVEL SECURITY",
    )
    .execute(&f.owner)
    .await?;
    assert!(
        PgRuntime::connect_consumer(f.config.clone(), Timer::new(), fence_fixture::binding())
            .await
            .is_err(),
        "hidden scope bindings must fail admission"
    );
    sqlx::raw_sql(
        "ALTER TABLE rss_transactional_messaging.consumer_scope DISABLE ROW LEVEL SECURITY",
    )
    .execute(&f.owner)
    .await?;
    assert!(
        PgRuntime::connect_consumer(f.config.clone(), Timer::new(), fence_fixture::binding())
            .await
            .is_ok()
    );
    sqlx::raw_sql(
        "ALTER POLICY outbox_consumer_scope ON rss_transactional_messaging.outbox USING(true)",
    )
    .execute(&f.owner)
    .await?;
    assert!(
        PgRuntime::connect_consumer(f.config.clone(), Timer::new(), fence_fixture::binding())
            .await
            .is_err(),
        "weakened restrictive policy must fail admission"
    );
    sqlx::raw_sql("ALTER POLICY outbox_consumer_scope ON rss_transactional_messaging.outbox USING((domain=(SELECT rss_transactional_messaging.consumer_scope_domain())) IS NOT FALSE)").execute(&f.owner).await?;
    Ok(())
}

#[allow(
    clippy::cognitive_complexity,
    reason = "Keep each sequential provider fault, its durable assertions and cleanup in one scenario."
)]
async fn cancellation_and_restart(f: &Fixture) -> anyhow::Result<()> {
    f.append("atomic-cancelled", "orders").await?;
    let gate = Gate::default();
    let projection = f
        .projection(Effect {
            gate: Some(gate.clone()),
            reject: false,
            fail: false,
        })
        .await?;
    let task = tokio::spawn({
        let projection = projection.clone();
        async move {
            only(
                projection
                    .project_batch(
                        &Validator,
                        NonZeroUsize::MIN,
                        deadline(),
                        Duration::from_secs(5),
                    )
                    .await?,
            )
        }
    });
    gate.entered.notified().await;
    task.abort();
    assert!(task.await.is_err());
    assert_eq!(
        f.state("atomic-cancelled").await?,
        (0, 0, None, "publishing".into())
    );
    // Only the isolated fixture advances durable lease eligibility; production uses DB time.
    sqlx::query("UPDATE rss_transactional_messaging.outbox SET lease_until=clock_timestamp()-interval '1 second' WHERE message_id='atomic-cancelled'").execute(&f.owner).await?;
    sqlx::query("UPDATE rss_transactional_messaging.inbox SET lease_until=clock_timestamp()-interval '1 second' WHERE message_id='atomic-cancelled'").execute(&f.owner).await?;
    let runtime = Arc::new(
        PgRuntime::connect_consumer(f.config.clone(), Timer::new(), fence_fixture::binding())
            .await?,
    );
    let capture = PgRecoveryCapture::new(runtime.clone(), Arc::new(Key(1)), deadline()).await?;
    let restarted = PgLocalProjection::new(
        capture,
        group()?,
        domain()?,
        Effect {
            gate: None,
            reject: false,
            fail: false,
        },
        DeliveryBudget::new(
            Duration::from_secs(2),
            Duration::from_millis(400),
            Duration::from_millis(400),
            Duration::from_millis(400),
        )?,
        LeaseRenewalPolicy::from_ttl(Duration::from_secs(2))?,
        deadline(),
    )
    .await?;
    assert_eq!(
        committed_projection(only(
            restarted
                .project_batch(
                    &Validator,
                    NonZeroUsize::MIN,
                    deadline(),
                    Duration::from_secs(5)
                )
                .await?
        )?)?
        .disposition(),
        TerminalDisposition::Succeeded
    );
    assert_eq!(
        f.state("atomic-cancelled").await?,
        (1, 1, Some("succeeded".into()), "published".into())
    );
    runtime.close().await;
    Ok(())
}

#[allow(
    clippy::cognitive_complexity,
    reason = "Keep each sequential provider fault, its durable assertions and cleanup in one scenario."
)]
async fn pool_capacity(f: &Fixture) -> anyhow::Result<()> {
    let one = Arc::new(
        PgRuntime::connect_consumer(
            f.config.clone().with_pool_limits(0, 1),
            Timer::new(),
            fence_fixture::binding(),
        )
        .await?,
    );
    assert!(
        Fixture::projection_on(
            one.clone(),
            Effect {
                gate: None,
                reject: false,
                fail: false
            }
        )
        .await
        .is_err(),
        "a one-connection pool cannot renew while holding an effect connection"
    );
    one.close().await;
    let runtime = Arc::new(
        PgRuntime::connect_consumer(
            f.config.clone().with_pool_limits(0, 2),
            Timer::new(),
            fence_fixture::binding(),
        )
        .await?,
    );
    f.append("pool-first", "orders").await?;
    f.append("pool-second", "orders").await?;
    let gate = Gate::default();
    let a = Fixture::projection_on(
        runtime.clone(),
        Effect {
            gate: Some(gate.clone()),
            reject: false,
            fail: false,
        },
    )
    .await?;
    let b = Fixture::projection_on(
        runtime.clone(),
        Effect {
            gate: None,
            reject: false,
            fail: false,
        },
    )
    .await?;
    let first = tokio::spawn({
        let a = a.clone();
        async move {
            only(
                a.project_batch(
                    &Validator,
                    NonZeroUsize::MIN,
                    deadline(),
                    Duration::from_secs(5),
                )
                .await?,
            )
        }
    });
    gate.entered.notified().await;
    let second = tokio::spawn(async move {
        only(
            b.project_batch(
                &Validator,
                NonZeroUsize::MIN,
                deadline(),
                Duration::from_secs(5),
            )
            .await?,
        )
    });
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert_eq!(
        f.state("pool-second").await?,
        (0, 0, None, "pending".into()),
        "capacity waiting must precede durable claiming"
    );
    gate.resume.notify_one();
    assert_eq!(
        committed_projection(first.await??)?.disposition(),
        TerminalDisposition::Succeeded
    );
    assert_eq!(
        committed_projection(second.await??)?.disposition(),
        TerminalDisposition::Succeeded
    );
    runtime.close().await;
    Ok(())
}

#[allow(
    clippy::cognitive_complexity,
    reason = "Keep each sequential provider fault, its durable assertions and cleanup in one scenario."
)]
async fn dr_recovery(f: &Fixture) -> anyhow::Result<()> {
    // Preseed legal DR state: the tested boundary is settlement/readback, not plan authorization.
    // One member has historical local success; the other was published before local consumption.
    f.append("dr-rejected", "orders").await?;
    sqlx::query("UPDATE rss_transactional_messaging.outbox SET status='published',automatic_retry_deadline=clock_timestamp()+interval '1 day' WHERE message_id='dr-rejected'").execute(&f.owner).await?;
    sqlx::query("INSERT INTO rss_transactional_messaging.dr_plans(tenant_id,operation_id,request_digest,lineage,epoch,kind,evidence) VALUES($1::uuid,'00000000-0000-0000-0000-000000002891',$2,$3,1,'broker','{}')")
        .bind(tenant().to_string()).bind([7u8;32].as_slice()).bind([2u8;16].as_slice()).execute(&f.owner).await?;
    for (ordinal, id) in [(0, "atomic-success"), (1, "dr-rejected")] {
        sqlx::query("INSERT INTO rss_transactional_messaging.dr_members(tenant_id,operation_id,ordinal,message_id,consumer_group,fingerprint,outbox_seq,status) SELECT tenant_id,'00000000-0000-0000-0000-000000002891',$2,message_id,'',fingerprint,seq,'pending' FROM rss_transactional_messaging.outbox WHERE message_id=$1")
            .bind(id).bind(ordinal).execute(&f.owner).await?;
    }
    let p = f
        .projection(Effect {
            gate: None,
            reject: false,
            fail: false,
        })
        .await?;
    p.inject_next_projection_fault(PgTransactionFault::CommitPending)?;
    let pending = uncertain_projection(only(
        p.project_batch(
            &Validator,
            NonZeroUsize::MIN,
            deadline(),
            Duration::from_secs(5),
        )
        .await?,
    )?)?;
    assert_eq!(
        f.state("atomic-success").await?,
        (1, 1, Some("succeeded".into()), "published".into())
    );
    assert!(
        p.resolve(&pending, deadline()).await?.is_none(),
        "historical source and Inbox success cannot prove a new DR member completed"
    );
    sqlx::query("UPDATE rss_transactional_messaging.dr_members SET lease_until=clock_timestamp()-interval '1 second' WHERE message_id='atomic-success' AND status='publishing'").execute(&f.owner).await?;
    assert_eq!(
        committed_projection(only(
            p.project_batch(
                &Validator,
                NonZeroUsize::MIN,
                deadline(),
                Duration::from_secs(5)
            )
            .await?
        )?)?
        .disposition(),
        TerminalDisposition::Succeeded
    );
    assert!(p.resolve(&pending, deadline()).await?.is_some());

    let p = f
        .projection(Effect {
            gate: None,
            reject: true,
            fail: false,
        })
        .await?;
    p.inject_next_projection_fault(PgTransactionFault::CommitUnknownAfterAck)?;
    let pending = uncertain_projection(only(
        p.project_batch(
            &Validator,
            NonZeroUsize::MIN,
            deadline(),
            Duration::from_secs(5),
        )
        .await?,
    )?)?;
    assert_eq!(
        f.state("dr-rejected").await?,
        (0, 0, Some("rejected_permanent".into()), "published".into())
    );
    let receipt = p
        .resolve(&pending, deadline())
        .await?
        .ok_or_else(|| anyhow::anyhow!("DR rejection receipt missing"))?;
    assert_eq!(
        receipt.disposition(),
        TerminalDisposition::Rejected(RejectKind::Permanent)
    );
    let state: String = sqlx::query_scalar(
        "SELECT status FROM rss_transactional_messaging.dr_members WHERE message_id='dr-rejected'",
    )
    .fetch_one(&f.owner)
    .await?;
    assert_eq!(state, "blocked");
    Ok(())
}

async fn direct_scope_predicate(f: &Fixture) -> anyhow::Result<()> {
    let mut tx = f.raw_worker.begin().await?;
    for context in [
        tenant().to_string(),
        "22222222-2222-2222-2222-222222222222".into(),
        String::new(),
    ] {
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(&context)
            .execute(&mut *tx)
            .await?;
        for message in ["atomic-success", "never-existed"] {
            let permitted:bool=sqlx::query_scalar("SELECT rss_transactional_messaging.consumer_inbox_allowed($1::uuid,$2,'projection')")
                .bind(tenant().to_string()).bind(message).fetch_one(&mut *tx).await?;
            assert_eq!(
                permitted,
                context == tenant().to_string() && message == "atomic-success"
            );
        }
    }
    tx.rollback().await?;
    Ok(())
}

fn only(mut batch: Vec<PgProjectionItem>) -> Result<PgProjectionOutcome, PgError> {
    assert_eq!(batch.len(), 1, "expected one admitted source");
    batch.remove(0).into_outcome()
}
