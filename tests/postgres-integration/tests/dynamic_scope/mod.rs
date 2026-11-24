//! One bounded pool accepts explicit tenant scopes provisioned after startup.
use super::{Effect, Timer, deadline, execution, fence_fixture};
use rss_request_context::TenantId;
use rss_transactional_messaging::{
    fence::{Epoch, ExecutionBinding, StorageIdentity},
    inbox::{ConsumerGroup, IdempotencyDisposition, InboxStore},
    message::{
        AuthoredMessageMetadata, MessageEnvelope, MessageMetadata, MessageMetadataExtensions,
        SubscriptionIdentity,
    },
    outbox::{OutboxRelayStore, OutboxSettlement, OutboxWriter, PendingMessage},
    transaction::{
        ConsumerTx, EnvelopeValidationFailure, IngressChallenge, IngressValidator,
        TerminalDisposition, VerifiedIngress, verify_ingress,
    },
};
use rss_transactional_messaging_postgres::{
    PgConfig, PgConsumerTx, PgError, PgInboxStore, PgOutboxStore, PgRuntime,
};
use std::{num::NonZeroUsize, sync::Arc, time::Duration};

struct Authority(ExecutionBinding);
impl IngressValidator<Vec<u8>> for Authority {
    fn validate(
        &self,
        c: IngressChallenge<'_, Vec<u8>>,
    ) -> Result<VerifiedIngress, EnvelopeValidationFailure> {
        if c.message().metadata().tenant_id() != self.0.tenant()
            || !c.subscription().accepts(c.message())
        {
            return Err(EnvelopeValidationFailure::MalformedIdentity);
        }
        Ok(c.verified(self.0))
    }
}
async fn observe(runtime: &PgRuntime, binding: ExecutionBinding) -> anyhow::Result<i32> {
    runtime.local_tx(binding, deadline(), move |tx| Box::pin(async move {
        let row: (i32, String, String, String, String) = tx.with_connection(|c| Box::pin(async move {
            sqlx::query_as("SELECT pg_backend_pid(), current_setting('rss.tenant_id'), current_setting('rss.execution_epoch'), current_setting('rss.storage_target'), current_setting('rss.storage_lineage')").fetch_one(c).await
        })).await?;
        assert_eq!(row.1, binding.tenant().to_string());
        assert_eq!(row.2, binding.epoch().get().to_string());
        assert_eq!(row.3, "01".repeat(16));
        assert_eq!(row.4, "02".repeat(16));
        Ok(row.0)
    })).await.fold(Ok, Err, Err, Err, Err, Err).map_err(Into::into)
}
async fn roundtrip(runtime: Arc<PgRuntime>, binding: ExecutionBinding) -> anyhow::Result<()> {
    let template = super::message("dynamic-shared-id");
    let m = template.metadata();
    let envelope = MessageEnvelope::new(
        template.id().clone(),
        MessageMetadata::new(
            AuthoredMessageMetadata::new(
                binding.tenant(),
                m.occurred_at(),
                m.domain().clone(),
                m.route().clone(),
                m.contract().clone(),
            ),
            MessageMetadataExtensions::default(),
        ),
        vec![1, 2, 3],
    );
    let writer = Arc::new(PgOutboxStore::<()>::new(
        runtime.clone(),
        m.domain().clone(),
        super::outbox_budget(Duration::from_secs(60)),
    )?);
    let append = writer.clone();
    let pending = PendingMessage::new(envelope.clone());
    runtime
        .local_tx(binding, deadline(), move |tx| {
            Box::pin(async move { append.append(tx, pending).await.map_err(Into::into) })
        })
        .await
        .fold(|_| Ok(()), Err, Err, Err, Err, Err)?;
    let claim = writer
        .claim_partition_heads(binding, NonZeroUsize::MIN, deadline())
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing outbox claim"))?;
    assert_eq!(
        PgOutboxStore::<()>::message(&claim)
            .envelope()
            .metadata()
            .tenant_id(),
        binding.tenant()
    );
    writer
        .settle(claim, OutboxSettlement::Published(()), deadline())
        .await?;
    let inbox = PgInboxStore::new(
        runtime.clone(),
        rss_transactional_messaging::policy::LeaseRenewalPolicy::from_ttl(Duration::from_secs(60))?,
    )?;
    let verified = verify_ingress(
        &Authority(binding),
        ConsumerGroup::parse("dynamic")?,
        &SubscriptionIdentity::new(m.domain().clone(), m.route().clone(), m.contract().clone()),
        &envelope,
    )
    .map_err(|_| anyhow::anyhow!("ingress"))?;
    let IdempotencyDisposition::Acquired(claim) = inbox.claim(&verified, deadline()).await? else {
        anyhow::bail!("missing inbox claim")
    };
    let result =
        PgConsumerTx::receipt_only(runtime.clone(), Effect(TerminalDisposition::Succeeded))
            .execute(&claim, &envelope, verified.receipt_intent(), deadline())
            .await;
    assert_eq!(result.status(), rss_transactional_messaging::observability::TransactionalMessagingTransactionStatus::Committed);
    let rows = runtime.local_tx(binding, deadline(), |tx| Box::pin(async {
        tx.with_connection(|c| Box::pin(async { sqlx::query_scalar::<_, i64>("SELECT count(*) FROM public.business_effects WHERE id='dynamic-shared-id'").fetch_one(c).await })).await
    })).await.fold(Ok, Err, Err, Err, Err, Err)?;
    assert_eq!(rows, 1, "RLS hides the other tenant's same-ID effect");
    Ok(())
}

pub(super) async fn run(config: PgConfig, owner: &sqlx::PgPool) -> anyhow::Result<()> {
    let a = TenantId::parse("00000000-0000-0000-0000-000000000090")?;
    let b = TenantId::parse("00000000-0000-0000-0000-000000000091")?;
    sqlx::query("INSERT INTO rss_transactional_messaging.tenant_epoch VALUES($1::uuid,1)")
        .bind(a.to_string())
        .execute(owner)
        .await?;
    let runtime = Arc::new(
        PgRuntime::connect(
            config.clone().with_pool_limits(1, 1),
            Timer::new(),
            fence_fixture::storage(),
        )
        .await?,
    );
    let policy =
        rss_transactional_messaging::policy::LeaseRenewalPolicy::from_ttl(Duration::from_secs(60))?;
    assert!(matches!(
        PgInboxStore::new(runtime.clone(), policy),
        Err(PgError::InsufficientRenewalCapacity)
    ));
    let consumer = Arc::new(
        PgRuntime::connect(
            config.with_pool_limits(1, 2),
            Timer::new(),
            fence_fixture::storage(),
        )
        .await?,
    );
    let first = observe(&runtime, execution(a, 1)).await?;
    unprovisioned_is_fenced(&runtime, b).await;
    newly_provisioned(runtime.clone(), &consumer, owner, a, b, first).await?;
    reject_wrong_storage(&runtime, a).await?;
    shared_capacity(runtime.clone(), a, b, first).await?;
    consumer.close().await;
    runtime.close().await;
    assert!(runtime.is_closed());
    Ok(())
}

async fn unprovisioned_is_fenced(runtime: &PgRuntime, b: TenantId) {
    let absent = runtime
        .local_tx(execution(b, 1), deadline(), |_| {
            Box::pin(async { panic!("unprovisioned scope executed") })
        })
        .await;
    assert!(absent.fold(
        |_: ()| false,
        |_| false,
        |_| false,
        |_| false,
        |_| false,
        |_| true
    ));
}

async fn reject_wrong_storage(runtime: &PgRuntime, a: TenantId) -> anyhow::Result<()> {
    for storage in [
        StorageIdentity::new([9; 16], [2; 16])?,
        StorageIdentity::new([1; 16], [9; 16])?,
    ] {
        let invalid = runtime
            .local_tx(
                ExecutionBinding::new(storage, a, Epoch::new(1)?),
                deadline(),
                |_| Box::pin(async { panic!("wrong storage executed") }),
            )
            .await;
        assert!(invalid.fold(
            |_: ()| false,
            |e| e.kind() == rss_transactional_messaging::error::MessagingErrorKind::OwnershipLost,
            |_| false,
            |_| false,
            |_| false,
            |_| false
        ));
    }
    Ok(())
}

async fn shared_capacity(
    runtime: Arc<PgRuntime>,
    a: TenantId,
    b: TenantId,
    first: i32,
) -> anyhow::Result<()> {
    let (entered_tx, entered) = tokio::sync::oneshot::channel();
    let (release, released) = tokio::sync::oneshot::channel();
    let held = runtime.clone();
    let first_task = tokio::spawn(async move {
        held.local_tx(execution(a, 1), deadline(), move |tx| {
            Box::pin(async move {
                let pid = tx
                    .with_connection(|c| {
                        Box::pin(async {
                            sqlx::query_scalar::<_, i32>("SELECT pg_backend_pid()")
                                .fetch_one(c)
                                .await
                        })
                    })
                    .await?;
                let _ = entered_tx.send(());
                released
                    .await
                    .map_err(|_| PgError::InvalidConnectionConfig)?;
                Ok(pid)
            })
        })
        .await
    });
    entered.await?;
    let pending = runtime.clone();
    let mut second_task = tokio::spawn(async move { observe(&pending, execution(b, 2)).await });
    assert!(
        tokio::time::timeout(Duration::from_millis(30), &mut second_task)
            .await
            .is_err(),
        "second tenant must wait for the one shared connection"
    );
    release.send(()).map_err(|_| anyhow::anyhow!("release"))?;
    assert_eq!(first_task.await?.fold(Ok, Err, Err, Err, Err, Err)?, first);
    assert_eq!(second_task.await??, first);
    Ok(())
}

async fn newly_provisioned(
    runtime: Arc<PgRuntime>,
    consumer: &Arc<PgRuntime>,
    owner: &sqlx::PgPool,
    a: TenantId,
    b: TenantId,
    first: i32,
) -> anyhow::Result<()> {
    sqlx::query("INSERT INTO rss_transactional_messaging.tenant_epoch VALUES($1::uuid,1)")
        .bind(b.to_string())
        .execute(owner)
        .await?;
    {
        let scope = execution(b, 1);
        assert_eq!(observe(&runtime, scope).await?, first);
        roundtrip(consumer.clone(), scope).await?;
    }
    assert!(!runtime.is_closed());
    roundtrip(consumer.clone(), execution(a, 1)).await?;
    assert_eq!(observe(&runtime, execution(a, 1)).await?, first);
    sqlx::query(
        "UPDATE rss_transactional_messaging.tenant_epoch SET epoch=2 WHERE tenant_id=$1::uuid",
    )
    .bind(b.to_string())
    .execute(owner)
    .await?;
    assert!(observe(&runtime, execution(b, 1)).await.is_err());
    assert_eq!(observe(&runtime, execution(b, 2)).await?, first);
    Ok(())
}
