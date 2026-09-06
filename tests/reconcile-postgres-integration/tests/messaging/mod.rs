use super::*;
use rss_transactional_messaging::{
    message::*,
    outbox::{OutboxStore, PendingMessage},
    policy::{
        AbsoluteDeadline, Clock as MessageClock, DeliveryBudget, ExecutionTimer, MonotonicInstant,
    },
};
use rss_transactional_messaging_postgres::{
    PgConfig, PgError, PgOutboxStore, PgPassword, PgPrivateCa, PgRuntime, PgTransactionFault,
};
struct MClock(Clock);
impl MessageClock for MClock {
    fn now(&self) -> MonotonicInstant {
        MonotonicInstant::from_elapsed(self.0.now())
    }
}
impl ExecutionTimer for MClock {
    async fn sleep_until(&self, d: AbsoluteDeadline) {
        tokio::time::sleep(d.remaining(self)).await;
    }
}
fn message(id: &str) -> anyhow::Result<MessageEnvelope<Vec<u8>>> {
    use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
    Ok(MessageEnvelope::new(
        MessageId::parse(id)?,
        MessageMetadata::new(
            AuthoredMessageMetadata::new(
                TenantId::parse(TENANT)?,
                Timepoint::try_from(1_i64)?,
                MessagingDomain::parse("integration")?,
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
    ))
}
pub async fn run(
    store: &PgStore,
    owner: &PgPool,
    fixture: &testkit::PgTlsFixture,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    sqlx::raw_sql("CREATE ROLE rss_tmsg_relay NOLOGIN NOBYPASSRLS;")
        .execute(owner)
        .await?;
    sqlx::raw_sql(rss_transactional_messaging_postgres::MIGRATION_SQL)
        .execute(owner)
        .await?;
    sqlx::raw_sql("GRANT USAGE ON SCHEMA rss_transactional_messaging TO reconcile_runtime; GRANT SELECT ON rss_transactional_messaging.policy TO reconcile_runtime; GRANT SELECT,INSERT,UPDATE,DELETE ON rss_transactional_messaging.inbox TO reconcile_runtime; GRANT SELECT,INSERT ON rss_transactional_messaging.outbox TO reconcile_runtime; GRANT USAGE ON ALL SEQUENCES IN SCHEMA rss_transactional_messaging TO reconcile_runtime; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_transactional_messaging TO reconcile_runtime;").execute(owner).await?;
    let p = fixture.params();
    let runtime = Arc::new(
        PgRuntime::connect(
            PgConfig::new(
                &p.host,
                p.port,
                &p.database,
                "reconcile_runtime",
                PgPassword::new("fixture-only"),
                PgPrivateCa::from_pem(fixture.ca_pem().as_bytes().to_vec())?,
            ),
            MClock(Clock::new()),
        )
        .await?,
    );
    for mode in ["commit", "rollback", "expired", "unknown", "wake"] {
        scenario(mode, store, owner, &runtime, c).await?;
    }
    for unknown in [false, true] {
        wake_failure(&runtime, owner, c, unknown).await?;
    }
    runtime.close().await;
    Ok(())
}
async fn scenario(
    mode: &str,
    store: &PgStore,
    owner: &PgPool,
    runtime: &Arc<PgRuntime>,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let id = format!("message-{mode}");
    let t = target(&id, TENANT)?;
    store.wake(&t, c).await?;
    let claim = claim(
        store,
        &t,
        if mode == "expired" {
            Duration::from_millis(30)
        } else {
            Duration::from_secs(3)
        },
        c,
    )
    .await?;
    let envelope = message(&id)?;
    let outbox = PgOutboxStore::<()>::new(
        runtime.clone(),
        envelope.metadata().domain().clone(),
        DeliveryBudget::new(
            Duration::from_secs(30),
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )?,
    )?;
    let rollback = mode == "rollback";
    let expired = mode == "expired";
    let effect_id = id.clone();
    let callback = scoped(move |_, tx| {
        Box::pin(async move {
            let tenant = tx.tenant_id().to_string();
            tx.with_connection(move |conn| {
                Box::pin(async move {
                    sqlx::query("INSERT INTO public.effects(tenant_id,id,n) VALUES($1::uuid,$2,1)")
                        .bind(tenant)
                        .bind(effect_id)
                        .execute(conn)
                        .await?;
                    Ok(())
                })
            })
            .await?;
            outbox.append(tx, PendingMessage::new(envelope)).await?;
            if expired {
                tokio::time::sleep(Duration::from_millis(45)).await;
            }
            if rollback {
                return Err(PgError::from(sqlx::Error::RowNotFound));
            }
            Ok(())
        })
    });
    if mode == "unknown" {
        runtime.inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    }
    let result = if mode == "wake" {
        rss_reconcile_postgres::messaging::wake_with(runtime, &t, c, (), callback).await
    } else {
        rss_reconcile_postgres::messaging::protect(runtime, &claim, c, (), callback).await
    };
    let status = result.fold(
        |()| "committed",
        |_| "not-started",
        |_| "rolled-back",
        |_| "rollback-failed",
        |_| "unknown",
        |_| "fenced",
    );
    verify_result(mode, &id, status, owner).await
}
async fn verify_result(mode: &str, id: &str, status: &str, owner: &PgPool) -> anyhow::Result<()> {
    match mode {
        "unknown" => assert_eq!(status, "unknown"),
        "rollback" => assert_eq!(status, "rolled-back"),
        "expired" => assert!(matches!(status, "fenced" | "rolled-back")),
        _ => assert_eq!(status, "committed"),
    }
    verify_counts(mode, id, owner).await
}
async fn verify_counts(mode: &str, id: &str, owner: &PgPool) -> anyhow::Result<()> {
    let expected = i64::from(!matches!(mode, "rollback" | "expired"));
    assert_eq!(count(owner, id).await?, expected);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM rss_transactional_messaging.outbox WHERE message_id=$1"
        )
        .bind(id)
        .fetch_one(owner)
        .await?,
        expected
    );
    let state: String =
        sqlx::query_scalar("SELECT result FROM rss_reconcile.targets WHERE reconciler=$1")
            .bind(id)
            .fetch_one(owner)
            .await?;
    assert_eq!(
        state,
        if mode == "wake" {
            "pending"
        } else if expected == 1 {
            "applied"
        } else {
            "running"
        }
    );
    Ok(())
}

fn scoped<F>(operation: F) -> F
where
    F: for<'a> FnOnce(
        &'a mut (),
        &'a mut rss_transactional_messaging_postgres::PgTransaction<'_>,
    ) -> futures::future::BoxFuture<'a, Result<(), PgError>>,
{
    operation
}

async fn wake_failure(
    runtime: &Arc<PgRuntime>,
    owner: &PgPool,
    c: &Control<'_, Clock>,
    unknown: bool,
) -> anyhow::Result<()> {
    struct Audit {
        id: String,
    }
    let audit = Audit {
        id: format!("new-wake-{unknown}"),
    };
    let t = target(&audit.id, TENANT)?;
    let envelope = message(&audit.id)?;
    let outbox = PgOutboxStore::<()>::new(
        runtime.clone(),
        envelope.metadata().domain().clone(),
        DeliveryBudget::new(
            Duration::from_secs(30),
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )?,
    )?;
    if unknown {
        runtime.inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    }
    let result =
        rss_reconcile_postgres::messaging::wake_with(runtime, &t, c, &audit, move |audit, tx| {
            Box::pin(async move {
                let id = audit.id.clone();
                let tenant = tx.tenant_id().to_string();
                tx.with_connection(move |conn| {
                    Box::pin(async move {
                        sqlx::query(
                            "INSERT INTO public.effects(tenant_id,id,n) VALUES($1::uuid,$2,1)",
                        )
                        .bind(tenant)
                        .bind(id)
                        .execute(conn)
                        .await?;
                        Ok(())
                    })
                })
                .await?;
                outbox.append(tx, PendingMessage::new(envelope)).await?;
                if unknown {
                    Ok(())
                } else {
                    Err(PgError::from(sqlx::Error::RowNotFound))
                }
            })
        })
        .await;
    let outcome = result.fold(
        |()| "commit",
        |_| "notstarted",
        |_| "rollback",
        |_| "rollbackfailed",
        |_| "unknown",
        |_| "fenced",
    );
    assert_eq!(outcome, if unknown { "unknown" } else { "rollback" });
    let counts:(i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM rss_reconcile.targets WHERE reconciler=$1),(SELECT count(*) FROM public.effects WHERE id=$1),(SELECT count(*) FROM rss_transactional_messaging.outbox WHERE message_id=$1)").bind(&audit.id).fetch_one(owner).await?;
    let expected = i64::from(unknown);
    assert_eq!(counts, (expected, expected, expected));
    Ok(())
}
