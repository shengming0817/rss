mod ledger;
use rss_request_context::{Clock as MessageClock, Deadline, ExecutionTimer};
#[path = "../../../fixtures/message_fence.rs"]
mod fence_fixture;
use super::*;
use rss_transactional_messaging::{
    message::*,
    outbox::{OutboxWriter, PendingMessage},
};
use rss_transactional_messaging_postgres::{
    PgConfig, PgError, PgOutboxWriter, PgPassword, PgPrivateCa, PgRuntime, PgTransactionFault,
};
struct MClock(Clock);
impl MessageClock for MClock {
    fn now(&self) -> std::time::Instant {
        self.0.0 + self.0.now()
    }
}
impl ExecutionTimer for MClock {
    async fn sleep_until(&self, d: Deadline) {
        tokio::task::unconstrained(async move {
            tokio::time::sleep(d.remaining(self.now()).unwrap_or_default()).await;
        })
        .await;
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
    install(owner).await?;
    let p = fixture.params();
    fence_fixture::provision(owner).await?;
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
            fence_fixture::binding(),
        )
        .await?,
    );
    for mode in ["commit", "rollback", "expired", "unknown", "wake"] {
        Box::pin(scenario(mode, store, owner, &runtime, c, false)).await?;
        Box::pin(scenario(mode, store, owner, &runtime, c, true)).await?;
    }
    Box::pin(scenario("outer-rollback", store, owner, &runtime, c, true)).await?;
    ledger::competition(store, owner, &runtime, c).await?;
    for unknown in [false, true] {
        wake_failure(&runtime, owner, c, unknown).await?;
    }
    borrowed_scope_rejected(store, &runtime, c).await?;
    runtime.close().await;
    Ok(())
}
async fn install(owner: &PgPool) -> anyhow::Result<()> {
    sqlx::raw_sql("CREATE ROLE rss_tmsg_relay NOLOGIN NOBYPASSRLS;")
        .execute(owner)
        .await?;
    sqlx::raw_sql(rss_transactional_messaging_postgres::MIGRATION_SQL)
        .execute(owner)
        .await?;
    sqlx::raw_sql("GRANT USAGE ON SCHEMA rss_transactional_messaging TO reconcile_runtime; GRANT SELECT ON rss_transactional_messaging.policy TO reconcile_runtime; GRANT SELECT,INSERT,UPDATE,DELETE ON rss_transactional_messaging.inbox TO reconcile_runtime; GRANT SELECT ON rss_transactional_messaging.outbox TO reconcile_runtime; GRANT EXECUTE ON FUNCTION rss_transactional_messaging.prepare_outbox_partitions(jsonb),rss_transactional_messaging.append_outbox(bytea,jsonb) TO reconcile_runtime; GRANT EXECUTE ON FUNCTION rss_transactional_messaging.claim_outbox(uuid,text,integer,bigint),rss_transactional_messaging.outbox_lease(uuid,bigint,uuid,bigint,bigint,uuid),rss_transactional_messaging.settle_outbox(uuid,bigint,uuid,bigint,text,uuid) TO reconcile_runtime;").execute(owner).await?;
    ledger::install(owner).await?;
    Ok(())
}
async fn scenario(
    mode: &str,
    store: &PgStore,
    owner: &PgPool,
    runtime: &Arc<PgRuntime>,
    c: &Control<'_, Clock>,
    borrowed: bool,
) -> anyhow::Result<()> {
    let id = format!("message-{mode}-{borrowed}");
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
    let outbox = PgOutboxWriter::new(runtime.clone(), envelope.metadata().domain().clone());
    let rollback = mode == "rollback";
    let expired = mode == "expired";
    let effect_id = id.clone();
    let ledger_request = ledger::request(&id, &id)?;
    let append_ledger = borrowed && mode != "outer-rollback";
    let request_for_callback = ledger_request.clone();
    let authenticator = ledger::auth()?;
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
            if append_ledger {
                rss_ledger_postgres::append_in(tx, authenticator, &request_for_callback)
                    .await
                    .map_err(PgError::from)?;
            }
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
    let outer_rollback = mode == "outer-rollback";
    let borrowed_wake = mode == "wake";
    let result = if borrowed {
        runtime
            .local_tx_with_context(
                TenantId::parse(TENANT)?,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    c.remaining(),
                ),
                (&claim, &t, Some(callback), ledger_request, ledger::auth()?),
                |(claim, target, callback, request, auth), tx| {
                    Box::pin(async move {
                        rss_ledger_postgres::lock_head_in(tx, auth.clone(), request.ledger())
                            .await
                            .map_err(PgError::from)?;
                        let callback = callback
                            .take()
                            .ok_or_else(|| PgError::from(sqlx::Error::RowNotFound))?;
                        if borrowed_wake {
                            rss_reconcile_postgres::messaging::wake_in(tx, target, (), callback)
                                .await?;
                        } else {
                            rss_reconcile_postgres::messaging::protect_in(tx, claim, (), callback)
                                .await?;
                        }
                        if outer_rollback {
                            return Err(PgError::from(sqlx::Error::RowNotFound));
                        }
                        Ok(())
                    })
                },
            )
            .await
    } else if mode == "wake" {
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
    verify_result(mode, &id, status, owner).await?;
    if borrowed {
        ledger::verify(
            owner,
            &id,
            !matches!(mode, "rollback" | "outer-rollback" | "expired"),
        )
        .await?;
    }
    Ok(())
}
async fn verify_result(mode: &str, id: &str, status: &str, owner: &PgPool) -> anyhow::Result<()> {
    match mode {
        "unknown" => assert_eq!(status, "unknown"),
        "rollback" | "outer-rollback" => assert_eq!(status, "rolled-back"),
        "expired" => assert!(matches!(status, "fenced" | "rolled-back")),
        _ => assert_eq!(status, "committed"),
    }
    verify_counts(mode, id, owner).await
}
async fn verify_counts(mode: &str, id: &str, owner: &PgPool) -> anyhow::Result<()> {
    let expected = i64::from(!matches!(mode, "rollback" | "outer-rollback" | "expired"));
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
    let outbox = PgOutboxWriter::new(runtime.clone(), envelope.metadata().domain().clone());
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

async fn borrowed_scope_rejected(
    store: &PgStore,
    runtime: &PgRuntime,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    use std::sync::atomic::{AtomicBool, Ordering};
    let target = target("borrowed-cross-tenant", TENANT)?;
    store.wake(&target, control).await?;
    let claim = claim(store, &target, Duration::from_secs(3), control).await?;
    let entered = AtomicBool::new(false);
    for wake in [false, true] {
        let result = runtime
            .local_tx_with_context(
                TenantId::parse("00000000-0000-0000-0000-000000000001")?,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    control.remaining(),
                ),
                (&claim, &entered),
                |(claim, entered), tx| {
                    Box::pin(async move {
                        if wake {
                            return rss_reconcile_postgres::messaging::wake_in(
                                tx,
                                claim.target(),
                                entered,
                                |entered, _| {
                                    Box::pin(async move {
                                        entered.store(true, Ordering::SeqCst);
                                        Ok(())
                                    })
                                },
                            )
                            .await;
                        }
                        rss_reconcile_postgres::messaging::protect_in(
                            tx,
                            claim,
                            entered,
                            |entered, _| {
                                Box::pin(async move {
                                    entered.store(true, Ordering::SeqCst);
                                    Ok(())
                                })
                            },
                        )
                        .await
                    })
                },
            )
            .await;
        let rejected = result.fold(
            |()| false,
            |_| false,
            |_| true,
            |_| false,
            |_| false,
            |_| true,
        );
        assert!(rejected);
        assert!(!entered.load(Ordering::SeqCst));
    }
    Ok(())
}
