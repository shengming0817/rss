mod review;
pub(super) use review::{
    authority_pages, composition_boundaries, diagnostic_classes, full_outbox_states,
};
mod ingress;
pub(super) use ingress::{actual_state_redelivery, permanent_inputs};
mod regressions;
use super::*;
pub(super) use regressions::{
    authority_rollback, catalog_drift, closed_catalog, delayed_publication_read, immutable_facts,
    late_controls,
};
use rss_transactional_messaging_postgres::PgTransactionFault;
pub(super) async fn lifecycle(f: &Fixture) -> anyhow::Result<()> {
    let s = scope(TENANT)?;
    let c = Coordinate::new(1, 1)?;
    f.initialize(s, c).await?;
    let first = f.queue("first", s, c).await?;
    f.queue("second", s, c).await?;
    assert_eq!(
        f.report("first", s, c, DeviceEvent::Received)
            .await?
            .outcome,
        Outcome::OutOfOrder
    );
    assert_eq!(
        f.report(
            "first",
            s,
            c,
            DeviceEvent::Reported(StateDigest::from_bytes([7; 32]))
        )
        .await?
        .outcome,
        Outcome::OutOfOrder
    );
    assert_eq!(f.queue("first", s, c).await?, first);
    assert_eq!(f.count("commands", "first").await?, 1);
    assert_eq!(f.count("outbox", "dispatch.first").await?, 1);
    confirmed_receipt(f).await?;
    Ok(())
}
async fn confirmed_receipt(f: &Fixture) -> anyhow::Result<()> {
    let s = scope(TENANT)?;
    let c = Coordinate::new(1, 1)?;
    f.publish().await?;
    let _page = f.recover(s).await?;
    assert_eq!(
        f.report("first", s, c, DeviceEvent::Received)
            .await?
            .command
            .status(),
        Status::Received
    );
    assert_eq!(
        f.load("second", s)
            .await?
            .ok_or_else(|| anyhow::anyhow!("missing"))?
            .status(),
        Status::Published
    );
    assert!(
        f.report(
            "first",
            s,
            c,
            DeviceEvent::Reported(StateDigest::from_bytes([9; 32]))
        )
        .await
        .is_err()
    );
    application_and_rejection(f).await?;
    Ok(())
}
async fn application_and_rejection(f: &Fixture) -> anyhow::Result<()> {
    let s = scope(TENANT)?;
    let c = Coordinate::new(1, 1)?;
    assert_eq!(
        f.report(
            "first",
            s,
            c,
            DeviceEvent::Reported(StateDigest::from_bytes([7; 32]))
        )
        .await?
        .command
        .status(),
        Status::Applied
    );
    assert_eq!(
        f.report("first", s, c, DeviceEvent::Received)
            .await?
            .outcome,
        Outcome::Late
    );
    assert_eq!(
        f.report("second", s, c, DeviceEvent::Received)
            .await?
            .outcome,
        Outcome::Advanced
    );
    assert_eq!(
        f.report("second", s, c, DeviceEvent::Rejected)
            .await?
            .command
            .status(),
        Status::Rejected
    );
    Ok(())
}
pub(super) async fn authority_changes(f: &Fixture) -> anyhow::Result<()> {
    let s = scope(TENANT)?;
    let c = Coordinate::new(1, 1)?;
    f.queue("takeover-a", s, c).await?;
    f.queue("takeover-b", s, c).await?;
    let store = f.store.clone();
    let next = Coordinate::new(1, 2)?;
    committed(
        f.runtime
            .local_tx(s.tenant(), budget()?, move |tx| {
                Box::pin(async move { store.advance(tx, s, c, next).await })
            })
            .await,
    )?;
    for id in ["takeover-a", "takeover-b"] {
        assert_eq!(
            f.load(id, s)
                .await?
                .ok_or_else(|| anyhow::anyhow!("missing"))?
                .status(),
            Status::Superseded
        );
    }
    assert!(
        f.report("takeover-a", s, c, DeviceEvent::Received)
            .await
            .is_err()
    );
    let store = f.store.clone();
    committed(
        f.runtime
            .local_tx(s.tenant(), budget()?, move |tx| {
                Box::pin(async move { store.advance(tx, s, c, next).await })
            })
            .await,
    )?;
    let store = f.store.clone();
    let newer = Coordinate::new(2, 3)?;
    committed(
        f.runtime
            .local_tx(s.tenant(), budget()?, move |tx| {
                Box::pin(async move { store.advance(tx, s, next, newer).await })
            })
            .await,
    )?;
    let (a, b) = tokio::join!(
        f.queue("concurrent", s, newer),
        f.queue("concurrent", s, newer)
    );
    assert_eq!(a?, b?);
    Ok(())
}
pub(super) async fn atomicity(f: &mut Fixture) -> anyhow::Result<()> {
    let s = scope(TENANT)?;
    let c = Coordinate::new(2, 3)?;
    let store = f.store.clone();
    let request = spec("rollback", s, c)?;
    let msg = message("rollback", s.tenant())?;
    let attempt = f
        .runtime
        .local_tx(s.tenant(), budget()?, move |tx| {
            Box::pin(async move {
                store.queue(tx, request, msg).await?;
                Err::<(), PgError>(sqlx::Error::PoolTimedOut.into())
            })
        })
        .await;
    assert_eq!(status(attempt), "rolled-back");
    assert_eq!(f.count("commands", "rollback").await?, 0);
    assert_eq!(f.count("outbox", "dispatch.rollback").await?, 0);
    // A failed outbox append must also discard the command candidate.
    let original = message("collision", s.tenant())?;
    let outbox = f.outbox.clone();
    committed(
        f.runtime
            .local_tx(s.tenant(), budget()?, move |tx| {
                Box::pin(async move { outbox.append(tx, original).await.map_err(PgError::from) })
            })
            .await,
    )?;
    let store = f.store.clone();
    let request = spec("collision", s, c)?;
    let original = message("collision", s.tenant())?;
    let changed = PendingMessage::new(MessageEnvelope::new(
        original.envelope().id().clone(),
        original.envelope().metadata().clone(),
        vec![8],
    ));
    assert!(
        committed(
            f.runtime
                .local_tx(s.tenant(), budget()?, move |tx| Box::pin(async move {
                    store.queue(tx, request, changed).await
                }))
                .await
        )
        .is_err()
    );
    assert_eq!(f.count("commands", "collision").await?, 0);
    Ok(())
}
pub(super) async fn uncertainty(f: &mut Fixture) -> anyhow::Result<()> {
    let s = scope(TENANT)?;
    let c = Coordinate::new(2, 3)?;
    f.runtime
        .inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    let store = f.store.clone();
    let request = spec("unknown", s, c)?;
    let msg = message("unknown", s.tenant())?;
    assert_eq!(
        status(
            f.runtime
                .local_tx(s.tenant(), budget()?, move |tx| Box::pin(async move {
                    store.queue(tx, request, msg).await
                }))
                .await
        ),
        "unknown"
    );
    f.runtime.close().await;
    let (runtime, store, outbox) = stores(f.config.clone()).await?;
    f.runtime = runtime;
    f.store = store;
    f.outbox = outbox;
    assert_eq!(f.queue("unknown", s, c).await?.status(), Status::Queued);
    assert_eq!(f.count("commands", "unknown").await?, 1);
    assert_eq!(f.count("outbox", "dispatch.unknown").await?, 1);
    publication_uncertainty(f).await?;
    Ok(())
}
async fn publication_uncertainty(f: &mut Fixture) -> anyhow::Result<()> {
    let s = scope(TENANT)?;
    f.publish().await?;
    f.runtime
        .inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    assert!(f.recover(s).await.is_err());
    let (runtime, store, outbox) = stores(f.config.clone()).await?;
    f.runtime.close().await;
    f.runtime = runtime;
    f.store = store;
    f.outbox = outbox;
    assert_eq!(
        f.load("unknown", s)
            .await?
            .ok_or_else(|| anyhow::anyhow!("missing"))?
            .status(),
        Status::Published
    );
    let _page = f.recover(s).await?;
    Ok(())
}
pub(super) async fn isolation(f: &Fixture) -> anyhow::Result<()> {
    let s = scope(OTHER)?;
    let c = Coordinate::new(1, 1)?;
    f.initialize(s, c).await?;
    assert!(f.load("first", s).await?.is_none());
    f.queue("first", s, c).await?;
    let wrong = Scope::new(
        s.tenant(),
        DeviceId::parse("550e8400-e29b-41d4-a716-446655440001")?,
    );
    assert!(f.load("first", wrong).await.is_err());
    let store = f.store.clone();
    let first = scope(TENANT)?;
    assert_eq!(
        status(
            f.runtime
                .local_tx(first.tenant(), budget()?, move |tx| Box::pin(async move {
                    store.initialize(tx, s, c).await
                }))
                .await
        ),
        "fenced"
    );
    let outbox = f.outbox.clone();
    let m = message("first", s.tenant())?;
    assert!(!committed(
        f.runtime
            .local_tx(s.tenant(), budget()?, move |tx| Box::pin(async move {
                outbox
                    .is_published(
                        tx,
                        m.envelope().metadata().domain(),
                        m.envelope().id(),
                        m.fingerprint(),
                    )
                    .await
            }))
            .await
    )?);
    let outbox = f.outbox.clone();
    let m = message("first", s.tenant())?;
    assert!(
        committed(
            f.runtime
                .local_tx(s.tenant(), budget()?, move |tx| Box::pin(async move {
                    outbox
                        .is_published(
                            tx,
                            m.envelope().metadata().domain(),
                            m.envelope().id(),
                            MessageFingerprint::from_bytes([0; 32]),
                        )
                        .await
                }))
                .await
        )
        .is_err()
    );
    admission(f).await?;
    Ok(())
}
async fn admission(f: &Fixture) -> anyhow::Result<()> {
    // Admission rejects runtime write bypasses even if inherited through SET ROLE.
    sqlx::raw_sql("GRANT UPDATE ON rss_device_command.commands TO device_runtime")
        .execute(&f.owner)
        .await?;
    assert!(stores(f.config.clone()).await.is_err());
    sqlx::raw_sql("REVOKE UPDATE ON rss_device_command.commands FROM device_runtime")
        .execute(&f.owner)
        .await?;
    Ok(())
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
fn binding(
    message: &MessageEnvelope<Vec<u8>>,
) -> anyhow::Result<rss_transactional_messaging::transaction::VerifiedConsumerBinding> {
    let m = message.metadata();
    rss_transactional_messaging::transaction::verify_ingress(
        &Validator,
        rss_transactional_messaging::inbox::ConsumerGroup::parse("device-ingress")?,
        &SubscriptionIdentity::new(m.domain().clone(), m.route().clone(), m.contract().clone()),
        message,
    )
    .map_err(|_| anyhow::anyhow!("invalid fixture ingress"))
}
struct Decoder {
    fingerprint: MessageFingerprint,
    report: DeviceReport,
}
impl compose::ReportDecoder for Decoder {
    fn decode(
        &self,
        message: &MessageEnvelope<Vec<u8>>,
    ) -> Result<DeviceReport, rss_transactional_messaging::transaction::RejectKind> {
        if MessageFingerprint::of(message) != self.fingerprint {
            return Err(rss_transactional_messaging::transaction::RejectKind::Permanent);
        }
        Ok(self.report.clone())
    }
}
pub(super) async fn inbox(f: &Fixture) -> anyhow::Result<()> {
    use rss_transactional_messaging::{
        inbox::{IdempotencyDisposition, InboxStore},
        observability::TransactionalMessagingTransactionStatus as TxStatus,
        transaction::ConsumerTx,
    };
    use rss_transactional_messaging_postgres::{PgConsumerTx, PgInboxStore};
    let s = scope(TENANT)?;
    let c = Coordinate::new(2, 3)?;
    f.queue("early", s, c).await?;
    let m = message("ack-early", s.tenant())?;
    let binding = binding(m.envelope())?;
    let inbox = PgInboxStore::new(
        f.runtime.clone(),
        LeaseRenewalPolicy::from_ttl(Duration::from_secs(60))?,
    )?;
    let IdempotencyDisposition::Acquired(claim) =
        inbox.claim(binding.identity(), budget()?).await?
    else {
        anyhow::bail!("new claim missing")
    };
    let consumer = PgConsumerTx::new(
        f.runtime.clone(),
        compose::ReportEffect {
            store: f.store.clone(),
            decoder: Decoder {
                fingerprint: m.fingerprint(),
                report: DeviceReport {
                    scope: s,
                    command_id: CommandId::parse("early")?,
                    coordinate: c,
                    event: DeviceEvent::Received,
                },
            },
        },
    );
    assert_ne!(
        consumer
            .execute(&claim, m.envelope(), binding.receipt_intent(), budget()?)
            .await
            .status(),
        TxStatus::Committed
    );
    assert!(
        inbox
            .read_terminal(binding.identity(), budget()?)
            .await?
            .is_none()
    );
    inbox.release(claim, budget()?).await?;
    f.publish().await?;
    let _page = f.recover(s).await?;
    let IdempotencyDisposition::Acquired(claim) =
        inbox.claim(binding.identity(), budget()?).await?
    else {
        anyhow::bail!("retry claim missing")
    };
    assert_eq!(
        consumer
            .execute(&claim, m.envelope(), binding.receipt_intent(), budget()?)
            .await
            .status(),
        TxStatus::Committed
    );
    assert_eq!(
        f.load("early", s).await?.map(|c| c.status()),
        Some(Status::Received)
    );
    verify_terminal(&inbox, &binding).await?;
    Ok(())
}
pub(super) async fn bounds(f: &Fixture) -> anyhow::Result<()> {
    let s = scope(TENANT)?;
    let c = Coordinate::new(2, 3)?;
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000000)::bigint")
            .fetch_one(&f.owner)
            .await?;
    let request = CommandSpec::new(
        s,
        CommandId::parse("expires")?,
        c,
        StateDigest::from_bytes([7; 32]),
        now + 1_000_000,
    );
    let msg = message("expires", s.tenant())?;
    let store = f.store.clone();
    committed(
        f.runtime
            .local_tx(s.tenant(), budget()?, move |tx| {
                Box::pin(async move { store.queue(tx, request, msg).await })
            })
            .await,
    )?;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let _page = f.recover(s).await?;
    assert_eq!(
        f.load("expires", s)
            .await?
            .ok_or_else(|| anyhow::anyhow!("missing"))?
            .status(),
        Status::TimedOut
    );
    f.queue("cancel", s, c).await?;
    let store = f.store.clone();
    let id = CommandId::parse("cancel")?;
    let transition = committed(
        f.runtime
            .local_tx(s.tenant(), budget()?, move |tx| {
                Box::pin(async move { store.cancel(tx, s, &id, c).await })
            })
            .await,
    )?;
    assert_eq!(transition.command.status(), Status::Cancelled);
    sql_and_cursor_bounds(f).await?;
    Ok(())
}
async fn sql_and_cursor_bounds(f: &Fixture) -> anyhow::Result<()> {
    let s = scope(TENANT)?;
    let leaked:i64=committed(f.runtime.local_tx(s.tenant(),budget()?,|tx|Box::pin(async move {tx.with_connection(|c|Box::pin(async move {
        sqlx::query_scalar("SELECT count(*) FROM rss_device_command.commands WHERE tenant_id<>current_setting('rss.tenant_id')::uuid").fetch_one(c).await
    })).await})).await)?;
    assert_eq!(leaked, 0);
    assert!(
        committed(
            f.runtime
                .local_tx(s.tenant(), budget()?, |tx| Box::pin(async move {
                    tx.with_connection(|c| {
                        Box::pin(async move {
                            sqlx::query("DELETE FROM rss_device_command.commands")
                                .execute(c)
                                .await
                                .map(|_| ())
                        })
                    })
                    .await
                }))
                .await
        )
        .is_err()
    );
    for (id, domain) in [("absent", "device-tests"), ("first", "another-domain")] {
        let outbox = Arc::new(PgOutboxStore::<()>::new(
            f.runtime.clone(),
            MessagingDomain::parse(domain)?,
            DeliveryBudget::new(
                Duration::from_secs(60),
                Duration::from_secs(5),
                Duration::from_secs(5),
                Duration::from_secs(5),
            )?,
        )?);
        let m = message(id, s.tenant())?;
        let domain = MessagingDomain::parse(domain)?;
        assert!(
            committed(
                f.runtime
                    .local_tx(s.tenant(), budget()?, move |tx| Box::pin(async move {
                        outbox
                            .is_published(tx, &domain, m.envelope().id(), m.fingerprint())
                            .await
                    }))
                    .await
            )
            .is_err()
        );
    }
    let store = f.store.clone();
    let limit = BatchLimit::new(1)?;
    let page = committed(
        f.runtime
            .local_tx(s.tenant(), budget()?, move |tx| {
                Box::pin(async move { store.recover(tx, s, limit, None).await })
            })
            .await,
    )?;
    assert_eq!(page.commands.len(), 1);
    let store = f.store.clone();
    let after = page.after;
    let next_cursor = after.clone();
    let next = committed(
        f.runtime
            .local_tx(s.tenant(), budget()?, move |tx| {
                Box::pin(async move { store.recover(tx, s, limit, next_cursor.as_ref()).await })
            })
            .await,
    )?;
    assert!(next.commands.len() <= 1);
    if let (Some(a), Some(b)) = (after, next.after) {
        assert!(a < b);
    }
    Ok(())
}

async fn verify_terminal(
    inbox: &rss_transactional_messaging_postgres::PgInboxStore,
    binding: &rss_transactional_messaging::transaction::VerifiedConsumerBinding,
) -> anyhow::Result<()> {
    use rss_transactional_messaging::inbox::{IdempotencyDisposition, InboxStore};
    let receipt = inbox
        .read_terminal(binding.identity(), budget()?)
        .await?
        .ok_or_else(|| anyhow::anyhow!("receipt missing"))?;
    assert!(binding.validate_terminal(receipt).is_ok());
    assert!(matches!(
        inbox.claim(binding.identity(), budget()?).await?,
        IdempotencyDisposition::Terminal(_)
    ));
    Ok(())
}
pub(super) async fn settlement_failures(f: &Fixture) -> anyhow::Result<()> {
    let s = scope(TENANT)?;
    let c = Coordinate::new(2, 3)?;
    for (id, fault, reject, want) in [
        (
            "rollback-failed",
            PgTransactionFault::RollbackFailedAfterAck,
            true,
            "rollback-failed",
        ),
        (
            "commit-pending",
            PgTransactionFault::CommitPending,
            false,
            "unknown",
        ),
    ] {
        f.runtime.inject_next_transaction_fault(fault);
        let request = spec(id, s, c)?;
        let msg = message(id, s.tenant())?;
        let store = f.store.clone();
        let timer = Timer::new();
        let deadline =
            AbsoluteDeadline::from_timeout(&timer, Duration::from_millis(100))?.operation(&timer);
        let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let called = attempts.clone();
        let result = f
            .runtime
            .local_tx(s.tenant(), deadline, move |tx| {
                Box::pin(async move {
                    called.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    store.queue(tx, request, msg).await?;
                    if reject {
                        return Err(sqlx::Error::PoolTimedOut.into());
                    }
                    Ok(())
                })
            })
            .await;
        assert_eq!(status(result), want);
        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 1);
        if reject {
            assert_eq!(f.count("commands", id).await?, 0);
        } else {
            let _observed = f.load(id, s).await?;
            f.queue(id, s, c).await?;
            assert_eq!(f.count("commands", id).await?, 1);
            assert_eq!(f.count("outbox", &format!("dispatch.{id}")).await?, 1);
        }
    }
    Ok(())
}
