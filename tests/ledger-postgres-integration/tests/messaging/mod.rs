use super::fence_fixture;
use super::{CancellationToken, Control, Duration, PgLedger, PgPool, auth, committed, request};
use rss_request_context::Deadline;
use rss_transactional_messaging::{
    inbox::{IdempotencyDisposition, InboxStore},
    message::MessageEnvelope,
    policy::{LeaseRenewalPolicy, OperationDeadline},
    transaction::{ConsumerTx, TerminalDisposition},
};
use rss_transactional_messaging_postgres::{
    PgConfig, PgConsumerEffect, PgConsumerEffectFailure, PgConsumerTx, PgInboxStore, PgPassword,
    PgPrivateCa, PgRuntime, PgTransaction, PgTransactionFault, grant_consumer,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
mod helpers;
use helpers::{binding, deadline, message};
struct Effect {
    auth: Arc<rss_ledger::Authenticator>,
    fail: bool,
    expired_after_append: Option<Arc<AtomicBool>>,
}
impl PgConsumerEffect<Vec<u8>> for Effect {
    async fn apply(
        &self,
        tx: &mut PgTransaction<'_>,
        m: &MessageEnvelope<Vec<u8>>,
        _: OperationDeadline,
    ) -> Result<TerminalDisposition, PgConsumerEffectFailure> {
        let r = request("inbox", m.id().as_str(), m.payload()).map_err(|_| {
            PgConsumerEffectFailure::infrastructure(std::io::Error::other("fixture request"))
        })?;
        rss_ledger_postgres::lock_head_in(tx, self.auth.clone(), r.ledger())
            .await
            .map_err(|e| {
                PgConsumerEffectFailure::infrastructure(
                    rss_transactional_messaging_postgres::PgError::from(e),
                )
            })?;
        let staged = match rss_ledger_postgres::append_in(tx, self.auth.clone(), &r).await {
            Ok(staged) => staged,
            Err(rss_ledger_postgres::Error::Conflict) => {
                return Ok(TerminalDisposition::Rejected(
                    rss_transactional_messaging::transaction::RejectKind::Permanent,
                ));
            }
            Err(error) => {
                return Err(PgConsumerEffectFailure::infrastructure(
                    rss_transactional_messaging_postgres::PgError::from(error),
                ));
            }
        };
        if let Some(observed) = &self.expired_after_append {
            assert!(staged.inserted());
            let tenant = tx.tenant_id().to_string();
            let message = m.id().as_str().to_owned();
            tx.with_connection(move |c| Box::pin(async move {
                sqlx::query("SELECT pg_sleep_until(lease_until + interval '1 millisecond') FROM rss_transactional_messaging.inbox WHERE tenant_id=$1::uuid AND message_id=$2 AND consumer_group='suite' AND disposition IS NULL AND isfinite(lease_until)")
                    .bind(tenant).bind(message).fetch_one(c).await?;
                Ok(())
            })).await.map_err(PgConsumerEffectFailure::infrastructure)?;
            observed.store(true, Ordering::Release);
        }
        if self.fail {
            return Err(PgConsumerEffectFailure::infrastructure(
                std::io::Error::other("fixture failure"),
            ));
        }
        Ok(TerminalDisposition::Succeeded)
    }
}
#[allow(clippy::cognitive_complexity)]
// reason: table-driven settlement faults retain their paired ledger/inbox assertions.
pub async fn run(
    store: &PgLedger,
    owner: &PgPool,
    fixture: &testkit::PgTlsFixture,
) -> anyhow::Result<()> {
    let mut tx = owner.begin().await?;
    sqlx::raw_sql("CREATE ROLE rss_tmsg_relay NOLOGIN NOBYPASSRLS;")
        .execute(&mut *tx)
        .await?;
    sqlx::raw_sql(rss_transactional_messaging_postgres::MIGRATION_SQL)
        .execute(&mut *tx)
        .await?;
    grant_consumer(&mut tx, "ledger_runtime").await?;
    sqlx::raw_sql("GRANT EXECUTE ON FUNCTION rss_transactional_messaging.prepare_outbox_partitions(jsonb),rss_transactional_messaging.append_outbox(bytea,jsonb) TO ledger_runtime;").execute(&mut *tx).await?;
    tx.commit().await?;
    fence_fixture::provision(owner).await?;
    let p = fixture.params();
    let config = PgConfig::new(
        &p.host,
        p.port,
        &p.database,
        "ledger_runtime",
        PgPassword::new("fixture-only"),
        PgPrivateCa::from_pem(fixture.ca_pem().as_bytes().to_vec())?,
    );
    let runtime =
        Arc::new(PgRuntime::connect(config, super::TestClock, fence_fixture::storage()).await?);
    let inbox = PgInboxStore::new(
        runtime.clone(),
        LeaseRenewalPolicy::from_ttl(Duration::from_secs(30))?,
    )?;
    let clock = super::TestClock;
    let cancel = CancellationToken::new();
    let control = Control::new(
        &clock,
        Deadline::from_timeout(&clock, Duration::from_secs(30))?,
        &cancel,
    );
    sqlx::raw_sql("GRANT UPDATE ON rss_ledger.entries TO ledger_runtime")
        .execute(owner)
        .await?;
    assert!(startup(&runtime).await.is_err());
    sqlx::raw_sql("REVOKE UPDATE ON rss_ledger.entries FROM ledger_runtime")
        .execute(owner)
        .await?;
    startup(&runtime).await?;
    for (id, fail, unknown) in [
        ("success", false, false),
        ("failure", true, false),
        ("unknown", false, true),
    ] {
        let m = message(id);
        let b = binding(&m);
        let IdempotencyDisposition::Acquired(claim) = helpers::claim(&inbox, &b).await? else {
            anyhow::bail!("expected inbox claim")
        };
        let consumer = PgConsumerTx::receipt_only(
            runtime.clone(),
            Effect {
                auth: Arc::new(auth()?),
                fail,
                expired_after_append: None,
            },
        );
        if unknown {
            runtime.inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
        }
        let result = consumer
            .execute(&claim, &m, b.receipt_intent(), deadline())
            .await;
        use rss_transactional_messaging::observability::TransactionalMessagingTransactionStatus as Status;
        assert_eq!(
            result.status(),
            if unknown {
                Status::CommitUnknown
            } else if fail {
                Status::InfrastructureTransient
            } else {
                Status::Committed
            }
        );
        let r = request("inbox", id, m.payload())?;
        let row = committed(store.find(r.ledger(), r.record_id(), &control).await)?;
        assert_eq!(row.is_some(), !fail);
        assert_eq!(
            inbox
                .read_terminal(
                    crate::binding(b.identity().tenant_id()),
                    b.identity(),
                    deadline()
                )
                .await?
                .is_some(),
            !fail
        );
        if unknown {
            let retry = committed(store.append(&r, &control).await)?;
            assert!(!retry.inserted());
            helpers::assert_terminal(&inbox, &b, TerminalDisposition::Succeeded).await?;
        }
    }
    {
        let id = "stable-conflict";
        let m = message(id);
        let b = binding(&m);
        let r = request("inbox", id, b"original")?;
        committed(store.append(&r, &control).await)?;
        let IdempotencyDisposition::Acquired(claim) = helpers::claim(&inbox, &b).await? else {
            anyhow::bail!("expected claim")
        };
        let consumer = PgConsumerTx::receipt_only(
            runtime.clone(),
            Effect {
                auth: Arc::new(auth()?),
                fail: false,
                expired_after_append: None,
            },
        );
        let outcome = consumer
            .execute(&claim, &m, b.receipt_intent(), deadline())
            .await;
        use rss_transactional_messaging::observability::TransactionalMessagingTransactionStatus as Status;
        let receipt = inbox
            .read_terminal(
                crate::binding(b.identity().tenant_id()),
                b.identity(),
                deadline(),
            )
            .await?;
        assert_eq!(outcome.status(), Status::Committed);
        let receipt = receipt.ok_or_else(|| anyhow::anyhow!("missing rejection"))?;
        assert_eq!(
            receipt.disposition(),
            TerminalDisposition::Rejected(
                rss_transactional_messaging::transaction::RejectKind::Permanent
            )
        );
        helpers::assert_terminal(&inbox, &b, receipt.disposition()).await?;
        assert_eq!(
            committed(store.find(r.ledger(), r.record_id(), &control).await)?
                .ok_or_else(|| anyhow::anyhow!("missing original"))?
                .payload(),
            b"original"
        );
    }
    let expired_after_append = Arc::new(AtomicBool::new(false));
    let short_inbox = PgInboxStore::new(
        runtime.clone(),
        LeaseRenewalPolicy::from_ttl(Duration::from_secs(2))?,
    )?;
    let m = message("lease-expired");
    let b = binding(&m);
    let IdempotencyDisposition::Acquired(claim) = helpers::claim(&short_inbox, &b).await? else {
        anyhow::bail!("expected short claim")
    };
    let consumer = PgConsumerTx::receipt_only(
        runtime.clone(),
        Effect {
            auth: Arc::new(auth()?),
            fail: false,
            expired_after_append: Some(expired_after_append.clone()),
        },
    );
    let result = consumer
        .execute(&claim, &m, b.receipt_intent(), deadline())
        .await;
    assert!(expired_after_append.load(Ordering::Acquire));
    assert_eq!(
        result.status(),
        rss_transactional_messaging::observability::TransactionalMessagingTransactionStatus::Fenced
    );
    assert!(
        short_inbox
            .read_terminal(b.execution(), b.identity(), deadline())
            .await?
            .is_none()
    );
    let r = request("inbox", "lease-expired", m.payload())?;
    assert!(committed(store.find(r.ledger(), r.record_id(), &control).await)?.is_none());
    runtime.close().await;
    Ok(())
}

async fn startup(runtime: &PgRuntime) -> anyhow::Result<()> {
    runtime
        .local_tx(
            crate::binding(rss_request_context::TenantId::parse(super::TENANT)?),
            deadline(),
            |tx| {
                Box::pin(async move {
                    rss_ledger_postgres::validate_in(tx)
                        .await
                        .map_err(rss_transactional_messaging_postgres::PgError::from)
                })
            },
        )
        .await
        .fold(Ok, Err, Err, Err, Err, Err)?;
    Ok(())
}
