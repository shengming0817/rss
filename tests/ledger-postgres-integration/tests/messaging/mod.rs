use super::{CancellationToken, Control, Duration, PgLedger, PgPool, auth, committed, request};
use rss_request_context::{Clock as MessageClock, Deadline, ExecutionTimer};
use rss_transactional_messaging::{
    inbox::{IdempotencyDisposition, InboxStore},
    message::MessageEnvelope,
    policy::{LeaseRenewalPolicy, OperationDeadline},
    transaction::{ConsumerTx, TerminalDisposition},
};
use rss_transactional_messaging_postgres::{
    PgConfig, PgConsumerEffect, PgConsumerEffectFailure, PgConsumerTx, PgInboxStore, PgPassword,
    PgPrivateCa, PgRuntime, PgTransaction, PgTransactionFault,
};
use std::sync::Arc;
#[path = "../../../fixtures/message_fence.rs"]
mod fence_fixture;
mod helpers;
use helpers::{binding, deadline, message};
impl MessageClock for super::Clock {
    fn now(&self) -> std::time::Instant {
        self.0 + rss_ledger_postgres::Timer::now(self)
    }
}
impl ExecutionTimer for super::Clock {
    async fn sleep_until(&self, d: Deadline) {
        tokio::task::unconstrained(async move {
            tokio::time::sleep(d.remaining(self.now()).unwrap_or_default()).await;
        })
        .await;
    }
}
struct Effect {
    auth: Arc<rss_ledger::Authenticator>,
    fail: bool,
    expire: bool,
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
        if let Err(error) = rss_ledger_postgres::append_in(tx, self.auth.clone(), &r).await {
            return match error {
                rss_ledger_postgres::Error::Conflict => Ok(TerminalDisposition::Rejected(
                    rss_transactional_messaging::transaction::RejectKind::Permanent,
                )),
                error => Err(PgConsumerEffectFailure::infrastructure(
                    rss_transactional_messaging_postgres::PgError::from(error),
                )),
            };
        }
        if self.expire {
            tokio::time::sleep(Duration::from_millis(120)).await;
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
    sqlx::raw_sql("CREATE ROLE rss_tmsg_relay NOLOGIN NOBYPASSRLS;")
        .execute(owner)
        .await?;
    sqlx::raw_sql(rss_transactional_messaging_postgres::MIGRATION_SQL)
        .execute(owner)
        .await?;
    sqlx::raw_sql("GRANT USAGE ON SCHEMA rss_transactional_messaging TO ledger_runtime; GRANT SELECT ON rss_transactional_messaging.policy TO ledger_runtime; GRANT SELECT,INSERT,UPDATE,DELETE ON rss_transactional_messaging.inbox TO ledger_runtime; GRANT SELECT,INSERT ON rss_transactional_messaging.outbox TO ledger_runtime; GRANT USAGE ON ALL SEQUENCES IN SCHEMA rss_transactional_messaging TO ledger_runtime; GRANT EXECUTE ON FUNCTION rss_transactional_messaging.claim_outbox(uuid,text,integer,bigint),rss_transactional_messaging.outbox_lease(uuid,bigint,uuid,bigint,bigint,uuid),rss_transactional_messaging.settle_outbox(uuid,bigint,uuid,bigint,text,uuid) TO ledger_runtime;").execute(owner).await?;
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
        Arc::new(PgRuntime::connect(config, super::Clock::new(), fence_fixture::binding()).await?);
    let inbox = PgInboxStore::new(
        runtime.clone(),
        LeaseRenewalPolicy::from_ttl(Duration::from_secs(30))?,
    )?;
    let clock = super::Clock::new();
    let cancel = CancellationToken::new();
    let control = Control::new(&clock, Duration::from_secs(30), &cancel);
    for (id, fail, unknown) in [
        ("success", false, false),
        ("failure", true, false),
        ("unknown", false, true),
    ] {
        let m = message(id);
        let b = binding(&m);
        let IdempotencyDisposition::Acquired(claim) = inbox.claim(b.identity(), deadline()).await?
        else {
            anyhow::bail!("expected inbox claim")
        };
        let consumer = PgConsumerTx::receipt_only(
            runtime.clone(),
            Effect {
                auth: Arc::new(auth()?),
                fail,
                expire: false,
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
                .read_terminal(b.identity(), deadline())
                .await?
                .is_some(),
            !fail
        );
        if unknown {
            let retry = committed(store.append(&r, &control).await)?;
            assert!(!retry.inserted());
            assert!(!matches!(
                inbox.claim(b.identity(), deadline()).await?,
                IdempotencyDisposition::Acquired(_)
            ));
        }
    }
    for (id, drift) in [("borrowed-drift", true), ("stable-conflict", false)] {
        let m = message(id);
        let b = binding(&m);
        let r = request("inbox", id, b"original")?;
        if !drift {
            committed(store.append(&r, &control).await)?;
        }
        let IdempotencyDisposition::Acquired(claim) = inbox.claim(b.identity(), deadline()).await?
        else {
            anyhow::bail!("expected claim")
        };
        if drift {
            sqlx::raw_sql("GRANT UPDATE ON rss_ledger.entries TO ledger_runtime")
                .execute(owner)
                .await?;
        }
        let consumer = PgConsumerTx::receipt_only(
            runtime.clone(),
            Effect {
                auth: Arc::new(auth()?),
                fail: false,
                expire: false,
            },
        );
        let outcome = consumer
            .execute(&claim, &m, b.receipt_intent(), deadline())
            .await;
        if drift {
            sqlx::raw_sql("REVOKE UPDATE ON rss_ledger.entries FROM ledger_runtime")
                .execute(owner)
                .await?;
        }
        use rss_transactional_messaging::observability::TransactionalMessagingTransactionStatus as Status;
        let receipt = inbox.read_terminal(b.identity(), deadline()).await?;
        if drift {
            assert_eq!(outcome.status(), Status::InfrastructureTransient);
            assert!(receipt.is_none());
            assert!(committed(store.find(r.ledger(), r.record_id(), &control).await)?.is_none());
        } else {
            assert_eq!(outcome.status(), Status::Committed);
            let receipt = receipt.ok_or_else(|| anyhow::anyhow!("missing rejection"))?;
            assert_eq!(
                receipt.disposition(),
                TerminalDisposition::Rejected(
                    rss_transactional_messaging::transaction::RejectKind::Permanent
                )
            );
            assert!(!matches!(
                inbox.claim(b.identity(), deadline()).await?,
                IdempotencyDisposition::Acquired(_)
            ));
            assert_eq!(
                committed(store.find(r.ledger(), r.record_id(), &control).await)?
                    .ok_or_else(|| anyhow::anyhow!("missing original"))?
                    .payload(),
                b"original"
            );
        }
    }
    let short_inbox = PgInboxStore::new(
        runtime.clone(),
        LeaseRenewalPolicy::from_ttl(Duration::from_millis(50))?,
    )?;
    let m = message("lease-expired");
    let b = binding(&m);
    let IdempotencyDisposition::Acquired(claim) =
        short_inbox.claim(b.identity(), deadline()).await?
    else {
        anyhow::bail!("expected short claim")
    };
    let consumer = PgConsumerTx::receipt_only(
        runtime.clone(),
        Effect {
            auth: Arc::new(auth()?),
            fail: false,
            expire: true,
        },
    );
    let result = consumer
        .execute(&claim, &m, b.receipt_intent(), deadline())
        .await;
    assert_ne!(result.status(),rss_transactional_messaging::observability::TransactionalMessagingTransactionStatus::Committed);
    let r = request("inbox", "lease-expired", m.payload())?;
    assert!(committed(store.find(r.ledger(), r.record_id(), &control).await)?.is_none());
    runtime.close().await;
    Ok(())
}
