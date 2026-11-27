//! Audit/Ledger consume the same provider transaction as Inbox and source Outbox settlement.
use super::*;
use futures::StreamExt;
use rss_data_protection::{Aead, AeadError, CiphertextEnvelope, DerivedAad, Plaintext};
use rss_transactional_messaging::{
    outbox::{OutboxWriter, PendingMessage},
    policy::DeliveryBudget,
};

// This suite tests successful effects and infrastructure rollback, never protected rejection.
// Missing key material fails closed if an unexpected capture path is reached.
struct UnavailableCaptureKey;
impl Aead for UnavailableCaptureKey {
    fn seal(&self, _: &[u8], _: &DerivedAad) -> Result<CiphertextEnvelope, AeadError> {
        Err(AeadError::Seal)
    }
    fn open(&self, _: &CiphertextEnvelope, _: &DerivedAad) -> Result<Plaintext, AeadError> {
        Err(AeadError::Open)
    }
}
struct ProjectionEffect {
    capacity: rss_audit_postgres::WriteBudget,
    integrity: Integrity,
    fail: bool,
}
impl PgConsumerEffect<Vec<u8>> for ProjectionEffect {
    async fn apply(
        &self,
        tx: &mut PgTransaction<'_>,
        message: &MessageEnvelope<Vec<u8>>,
        _: OperationDeadline,
    ) -> Result<TerminalDisposition, PgConsumerEffectFailure> {
        let prepared = PreparedAuditV1::from_canonical_bytes(message.payload())
            .map_err(PgConsumerEffectFailure::infrastructure)?;
        self.capacity
            .append_in(tx, &self.integrity, &prepared)
            .await
            .map_err(PgConsumerEffectFailure::infrastructure)?;
        if self.fail {
            return Err(PgConsumerEffectFailure::infrastructure(
                std::io::Error::other("fixture projection rollback"),
            ));
        }
        Ok(TerminalDisposition::Succeeded)
    }
}

pub(super) async fn run(
    ledger: &PgAudit,
    admin: &PgPool,
    fixture: &testkit::PgTlsFixture,
    control: &Control<'_, TestClock>,
    producer: &Arc<PgRuntime>,
) -> anyhow::Result<()> {
    let domain = MessagingDomain::parse("audit-test")?;
    let group = ConsumerGroup::parse("local-audit")?;
    sqlx::raw_sql("CREATE ROLE audit_projection LOGIN PASSWORD 'fixture-password' NOSUPERUSER NOBYPASSRLS; GRANT USAGE ON SCHEMA rss_audit,rss_ledger TO audit_projection; GRANT SELECT ON ALL TABLES IN SCHEMA rss_audit,rss_ledger TO audit_projection; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_audit,rss_ledger TO audit_projection; GRANT SELECT,INSERT ON rss_transactional_messaging.consumer_dead_letter TO audit_projection;").execute(admin).await?;
    {
        let mut tx = admin.begin().await?;
        grant_local_projection(&mut tx, "audit_projection", &domain, &group).await?;
        tx.commit().await?;
    }
    let p = fixture.params();
    let runtime = Arc::new(
        PgRuntime::connect_consumer(
            PgConfig::new(
                &p.host,
                p.port,
                &p.database,
                "audit_projection",
                PgPassword::new("fixture-password"),
                PgPrivateCa::from_pem(fixture.ca_pem().as_bytes().to_vec())?,
            ),
            TestClock,
            StorageIdentity::new([1; 16], [2; 16])?,
        )
        .await?,
    );
    let integrity = Integrity::Ledger(auth()?);
    runtime
        .local_tx(execution()?, deadline()?, move |tx| {
            Box::pin(async move {
                rss_audit_postgres::validate_in(tx, &integrity)
                    .await
                    .map_err(PgError::from)
            })
        })
        .await
        .fold(Ok, Err, Err, Err, Err, Err)?;
    for (id, fail, unknown) in [
        ("local-success", false, false),
        ("local-unknown", false, true),
        ("local-rollback", true, false),
    ] {
        Box::pin(scenario(
            ledger,
            admin,
            control,
            producer,
            &runtime,
            &domain,
            &group,
            (id, fail, unknown),
        ))
        .await?;
    }
    runtime.close().await;
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "The fixture explicitly supplies its original provider and Audit owners."
)]
#[allow(
    clippy::cognitive_complexity,
    reason = "Keep each projection outcome beside its four durable facts and exact byte assertions."
)]
async fn scenario(
    ledger: &PgAudit,
    admin: &PgPool,
    control: &Control<'_, TestClock>,
    producer: &Arc<PgRuntime>,
    runtime: &Arc<PgRuntime>,
    domain: &MessagingDomain,
    group: &ConsumerGroup,
    case: (&str, bool, bool),
) -> anyhow::Result<()> {
    let (id, fail, unknown) = case;
    let prepared = ledger
        .prepare(event(tenant()?, "local-projection", id, vec![7])?, control)
        .await?;
    let pending = PendingMessage::new(message(id, prepared.canonical_bytes().to_vec())?);
    let writer = PgOutboxWriter::new(producer.clone(), domain.clone());
    producer
        .local_tx_with_context(
            execution()?,
            deadline()?,
            (writer, Some(pending)),
            |(writer, pending), tx| {
                Box::pin(async move {
                    let pending = pending
                        .take()
                        .ok_or_else(|| sqlx::Error::Protocol("fixture callback repeated".into()))?;
                    writer
                        .append(tx, pending)
                        .await
                        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
                    Ok(())
                })
            },
        )
        .await
        .fold(Ok, Err, Err, Err, Err, Err)?;
    let capture = PgRecoveryCapture::new(
        runtime.clone(),
        Arc::new(UnavailableCaptureKey),
        deadline()?,
    )
    .await?;
    let projection = PgLocalProjection::new(
        capture,
        group.clone(),
        domain.clone(),
        ProjectionEffect {
            capacity: write_budget()?,
            integrity: Integrity::Ledger(auth()?),
            fail,
        },
        DeliveryBudget::new(
            Duration::from_secs(30),
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )?,
        LeaseRenewalPolicy::from_ttl(Duration::from_secs(30))?,
        deadline()?,
    )
    .await?;
    if unknown {
        projection.inject_next_projection_fault(
            PgTransactionFault::CommitUnknownAfterAck,
            std::future::ready(()),
        )?;
    }
    let mut batch = projection
        .project_batch(
            execution()?,
            &Validator,
            std::num::NonZeroUsize::MIN,
            deadline()?,
            Duration::from_secs(5),
        )
        .await?
        .collect::<Vec<_>>()
        .await;
    assert_eq!(batch.len(), 1);
    let PgProjectionOutcome::Attempt(attempt) = batch.remove(0).into_outcome()? else {
        anyhow::bail!("expected local Audit transaction attempt")
    };
    let (outcome, pending) = attempt.into_parts();
    let resolve = outcome.fold(
        |committed| {
            assert!(!fail && !unknown);
            assert_eq!(
                committed.into_parts().1.disposition(),
                TerminalDisposition::Succeeded
            );
            Ok(false)
        },
        |_| Err(anyhow::anyhow!("unexpected not-started result")),
        |_| {
            assert!(fail);
            Ok(false)
        },
        || Err(anyhow::anyhow!("unexpected rollback failure")),
        || {
            assert!(unknown);
            Ok(true)
        },
        || Err(anyhow::anyhow!("unexpected fence loss")),
    )?;
    if resolve {
        assert!(projection.resolve(&pending, deadline()?).await?.is_some());
    }
    let facts:(i64,i64,i64,String)=sqlx::query_as("SELECT (SELECT count(*) FROM rss_audit.records WHERE source_id='local-projection' AND event_id=$1),(SELECT count(*) FROM rss_ledger.entries WHERE record_id='v1:local-projection:'||$1),(SELECT count(*) FROM rss_transactional_messaging.inbox WHERE message_id=$1 AND consumer_group='local-audit' AND disposition='succeeded'),(SELECT status FROM rss_transactional_messaging.outbox WHERE message_id=$1)")
        .bind(id).fetch_one(admin).await?;
    let count = i64::from(!fail);
    assert_eq!(
        facts,
        (
            count,
            count,
            count,
            if fail { "pending" } else { "published" }.into()
        )
    );
    if !fail {
        let canonical:Vec<u8>=sqlx::query_scalar("SELECT canonical FROM rss_audit.records WHERE source_id='local-projection' AND event_id=$1").bind(id).fetch_one(admin).await?;
        let payload: Vec<u8> = sqlx::query_scalar(
            "SELECT payload FROM rss_ledger.entries WHERE record_id='v1:local-projection:'||$1",
        )
        .bind(id)
        .fetch_one(admin)
        .await?;
        assert_eq!(canonical, prepared.canonical_bytes());
        assert_eq!(payload, canonical);
        assert!(
            projection
                .project_batch(
                    execution()?,
                    &Validator,
                    std::num::NonZeroUsize::MIN,
                    deadline()?,
                    Duration::from_secs(5)
                )
                .await?
                .collect::<Vec<_>>()
                .await
                .is_empty()
        );
    }
    Ok(())
}
