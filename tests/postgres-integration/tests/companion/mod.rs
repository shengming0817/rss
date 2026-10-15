//! Additional execution fences remain owned by the outer transaction.
use super::{deadline, message};
use rss_request_context::TenantId;
use rss_transactional_messaging::error::MessagingErrorKind;
use rss_transactional_messaging_postgres::PgRuntime;
use std::sync::Arc;

pub(super) async fn run(runtime: Arc<PgRuntime>, owner: &sqlx::PgPool) -> anyhow::Result<()> {
    let target = message("companion").metadata().tenant_id();
    let source = TenantId::parse("00000000-0000-0000-0000-000000000073")?;
    let owner_copy = owner.clone();
    runtime.local_tx(target, deadline(), move |tx| Box::pin(async move {
        let scope: (String, String) = tx.with_tenant_connection(source, |c| Box::pin(async move {
            sqlx::query_as("SELECT current_setting('rss.tenant_id'),current_setting('rss.execution_epoch')")
                .fetch_one(c).await
        })).await?;
        assert_eq!(scope, (source.to_string(), "1".into()));
        assert_eq!(tx.tenant_id(), target);
        let restored: String = tx.with_connection(|c| Box::pin(async move {
            sqlx::query_scalar("SELECT current_setting('rss.tenant_id')").fetch_one(c).await
        })).await?;
        assert_eq!(restored, target.to_string());
        // Independent owner cannot advance the source epoch before the host settles.
        let mut contender = owner_copy.begin().await?;
        sqlx::query("SET LOCAL lock_timeout='100ms'").execute(&mut *contender).await?;
        let blocked = sqlx::query("UPDATE rss_transactional_messaging.tenant_epoch SET epoch=2 WHERE tenant_id=$1::uuid")
            .bind(source.to_string()).execute(&mut *contender).await;
        assert_eq!(blocked.expect_err("companion fence held").as_database_error().and_then(|e| e.code()).as_deref(), Some("55P03"));
        contender.rollback().await?;
        Ok(())
    })).await.fold(Ok, Err, Err, Err, Err, Err)?;
    sqlx::query(
        "UPDATE rss_transactional_messaging.tenant_epoch SET epoch=2 WHERE tenant_id=$1::uuid",
    )
    .bind(source.to_string())
    .execute(owner)
    .await?;
    let stale = runtime
        .local_tx(target, deadline(), move |tx| {
            Box::pin(async move {
                tx.with_tenant_connection(source, |_| {
                    Box::pin(async move {
                        panic!("stale companion must not run its callback");
                        #[allow(unreachable_code)]
                        Ok(())
                    })
                })
                .await
            })
        })
        .await
        .fold(Ok, Err, Err, Err, Err, Err);
    sqlx::query(
        "UPDATE rss_transactional_messaging.tenant_epoch SET epoch=1 WHERE tenant_id=$1::uuid",
    )
    .bind(source.to_string())
    .execute(owner)
    .await?;
    assert_eq!(
        stale.expect_err("source epoch changed").kind(),
        MessagingErrorKind::OwnershipLost
    );
    let conflict = runtime.local_tx(target, deadline(), move |tx| Box::pin(async move {
        tx.with_tenant_connection(source, move |c| Box::pin(async move {
            for _ in 0..2 {
                sqlx::query("INSERT INTO public.business_effects(tenant_id,id) VALUES($1::uuid,'companion-conflict')")
                    .bind(source.to_string()).execute(&mut *c).await?;
            }
            Ok(())
        })).await
    })).await.fold(Ok, Err, Err, Err, Err, Err);
    assert_eq!(
        conflict
            .expect_err("original unique violation preserved")
            .kind(),
        MessagingErrorKind::Conflict
    );
    let missing = TenantId::parse("99999999-9999-9999-9999-999999999999")?;
    let rejected = runtime
        .local_tx(target, deadline(), move |tx| {
            Box::pin(async move {
                tx.with_tenant_connection(missing, |_| Box::pin(async move { Ok(()) }))
                    .await
            })
        })
        .await
        .fold(Ok, Err, Err, Err, Err, Err);
    assert_eq!(
        rejected.expect_err("unbound companion").kind(),
        MessagingErrorKind::OwnershipLost
    );
    interrupted_scopes(runtime, owner, source, target).await?;
    Ok(())
}

async fn poison(
    tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
    source: TenantId,
    id: &'static str,
    cancel: bool,
) {
    let (sent, received) = tokio::sync::oneshot::channel();
    let mut borrowed = Box::pin(tx.with_tenant_connection(source, move |c| {
        Box::pin(async move {
            sqlx::query("INSERT INTO public.business_effects(tenant_id,id) VALUES($1::uuid,$2)")
                .bind(source.to_string())
                .bind(id)
                .execute(c)
                .await?;
            if cancel {
                let _ = sent.send(());
                std::future::pending::<()>().await;
            }
            Err::<(), _>(sqlx::Error::RowNotFound)
        })
    }));
    if cancel {
        tokio::select! {
            result = &mut borrowed => panic!("callback ended before cancellation: {result:?}"),
            result = received => result.expect("write acknowledged"),
        }
    } else {
        assert!(borrowed.as_mut().await.is_err());
    }
    drop(borrowed);
    assert_eq!(
        tx.with_connection(|_| Box::pin(async {
            panic!("invalid scope reused");
            #[allow(unreachable_code)]
            Ok(())
        }))
        .await
        .unwrap_err()
        .kind(),
        MessagingErrorKind::Invariant
    );
    assert!(
        tx.with_tenant_connection(source, |_| Box::pin(async { Ok(()) }))
            .await
            .is_err()
    );
    assert!(tx.prepare_outbox_partitions(&[]).await.is_err());
}

struct InterruptedEffect {
    source: TenantId,
    cancel: bool,
}
impl rss_transactional_messaging_postgres::PgConsumerEffect<Vec<u8>> for InterruptedEffect {
    async fn apply(
        &self,
        tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
        _message: &rss_transactional_messaging::message::MessageEnvelope<Vec<u8>>,
        _deadline: rss_transactional_messaging::policy::OperationDeadline,
    ) -> Result<
        rss_transactional_messaging::transaction::TerminalDisposition,
        rss_transactional_messaging_postgres::PgConsumerEffectFailure,
    > {
        use rss_transactional_messaging::transaction::{RejectKind, TerminalDisposition};
        poison(
            tx,
            self.source,
            "companion-interrupted-consumer",
            self.cancel,
        )
        .await;
        Ok(if self.cancel {
            TerminalDisposition::Rejected(RejectKind::Permanent)
        } else {
            TerminalDisposition::Succeeded
        })
    }
}
async fn interrupted_scopes(
    runtime: Arc<PgRuntime>,
    owner: &sqlx::PgPool,
    source: TenantId,
    target: TenantId,
) -> anyhow::Result<()> {
    use rss_transactional_messaging::{
        inbox::{IdempotencyDisposition, InboxStore},
        observability::TransactionalMessagingTransactionStatus,
        transaction::ConsumerTx,
    };
    use rss_transactional_messaging_postgres::{PgConsumerTx, PgInboxStore};
    let inbox = PgInboxStore::new(
        runtime.clone(),
        rss_transactional_messaging::policy::LeaseRenewalPolicy::from_ttl(
            std::time::Duration::from_secs(60),
        )?,
    )?;
    for cancel in [false, true] {
        let outcome = runtime
            .local_tx(target, deadline(), move |tx| {
                Box::pin(async move {
                    poison(tx, source, "companion-interrupted-local", cancel).await;
                    Ok(()) // Ignoring the error must not authorize commit.
                })
            })
            .await
            .fold(Ok, Err, Err, Err, Err, Err);
        assert_eq!(outcome.unwrap_err().kind(), MessagingErrorKind::Invariant);
        let message = message(if cancel {
            "companion-cancelled-consumer"
        } else {
            "companion-failed-consumer"
        });
        let binding = super::binding(&message);
        let IdempotencyDisposition::Acquired(claim) =
            inbox.claim(binding.identity(), deadline()).await?
        else {
            panic!("fresh claim");
        };
        let outcome =
            PgConsumerTx::receipt_only(runtime.clone(), InterruptedEffect { source, cancel })
                .execute(&claim, &message, binding.receipt_intent(), deadline())
                .await;
        assert_eq!(
            outcome.status(),
            TransactionalMessagingTransactionStatus::InfrastructureTransient
        );
        assert!(
            inbox
                .read_terminal(binding.identity(), deadline())
                .await?
                .is_none()
        );
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM public.business_effects WHERE id LIKE 'companion-interrupted-%'",
        )
        .fetch_one(owner)
        .await?;
        assert_eq!(count, 0);
    }
    Ok(())
}
