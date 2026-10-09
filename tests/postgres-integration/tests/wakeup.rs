//! Real-PG scheduling snapshots share claim eligibility without acquiring message ownership.
use super::{Timer, deadline, fence_fixture, message, outbox_budget};
use rss_request_context::{Clock, TenantId};
use rss_transactional_messaging::{
    error::MessagingErrorKind,
    fence::{Epoch, ExecutionBinding},
    message::*,
    outbox::*,
    policy::OperationDeadline,
};
use rss_transactional_messaging_postgres::{PgConfig, PgOutboxStore, PgRuntime};
use sqlx::PgPool;
use std::{num::NonZeroUsize, sync::Arc, time::Duration};

fn event(
    id: &str,
    tenant: TenantId,
    domain: &str,
    partition: Option<&str>,
) -> MessageEnvelope<Vec<u8>> {
    let template = message(id);
    let m = template.metadata();
    MessageEnvelope::new(
        template.id().clone(),
        MessageMetadata::new(
            AuthoredMessageMetadata::new(
                tenant,
                m.occurred_at(),
                MessagingDomain::parse(domain).expect("domain"),
                m.route().clone(),
                m.contract().clone(),
            ),
            MessageMetadataExtensions::new(
                None,
                partition.map(|key| PartitionKey::parse(key).expect("partition")),
                None,
                Default::default(),
            ),
        ),
        template.payload().clone(),
    )
}

async fn append(
    runtime: &Arc<PgRuntime>,
    events: Vec<MessageEnvelope<Vec<u8>>>,
) -> anyhow::Result<()> {
    let tenant = events[0].metadata().tenant_id();
    let writer = PgOutboxStore::<()>::new(
        runtime.clone(),
        events[0].metadata().domain().clone(),
        outbox_budget(Duration::from_secs(60)),
    )?;
    runtime
        .local_tx(tenant, deadline(), move |tx| {
            Box::pin(async move {
                let partitions = events
                    .iter()
                    .filter_map(|m| m.metadata().partition().cloned())
                    .collect::<Vec<_>>();
                tx.prepare_outbox_partitions(&partitions).await?;
                for event in events {
                    assert_eq!(
                        writer.append(tx, PendingMessage::new(event)).await?,
                        AppendOutcome::Inserted
                    );
                }
                Ok(())
            })
        })
        .await
        .fold(Ok, Err, Err, Err, Err, Err)?;
    Ok(())
}

pub(super) async fn run(
    runtime: Arc<PgRuntime>,
    owner: &PgPool,
    config: PgConfig,
) -> anyhow::Result<()> {
    let tenant = message("wakeup").metadata().tenant_id();
    let scoped = Arc::new(
        PgRuntime::connect(
            config,
            Timer::new(),
            ExecutionBinding::new(
                fence_fixture::binding().storage(),
                vec![(tenant, Epoch::new(1)?)],
            )?,
        )
        .await?,
    );
    snapshots(&runtime, &scoped, owner, tenant).await?;
    partition_and_lease(&scoped, owner, tenant).await?;
    sqlx::query(
        "UPDATE rss_transactional_messaging.tenant_epoch SET epoch=2 WHERE tenant_id=$1::uuid",
    )
    .bind(tenant.to_string())
    .execute(owner)
    .await?;
    let store = PgOutboxStore::<()>::new(
        scoped.clone(),
        MessagingDomain::parse("wakeup.scope")?,
        outbox_budget(Duration::from_secs(60)),
    )?;
    let error = store
        .next_wakeup(deadline())
        .await
        .err()
        .expect("fenced scheduling rejected");
    let multi = PgOutboxStore::<()>::new(
        runtime.clone(),
        MessagingDomain::parse("wakeup.scope")?,
        outbox_budget(Duration::from_secs(60)),
    )?;
    let admitted = multi.next_wakeup(deadline()).await?;
    assert!(
        admitted.due_now() && admitted.next_deadline().is_none(),
        "fenced tenant is skipped without hiding another admitted tenant"
    );
    sqlx::query(
        "UPDATE rss_transactional_messaging.tenant_epoch SET epoch=1 WHERE tenant_id=$1::uuid",
    )
    .bind(tenant.to_string())
    .execute(owner)
    .await?;
    assert_eq!(error.kind(), MessagingErrorKind::OwnershipLost);
    scoped.close().await;
    Ok(())
}

async fn snapshots(
    runtime: &Arc<PgRuntime>,
    scoped: &Arc<PgRuntime>,
    owner: &PgPool,
    tenant: TenantId,
) -> anyhow::Result<()> {
    let other = TenantId::parse("22222222-2222-2222-2222-222222222222")?;
    let store = PgOutboxStore::<()>::new(
        scoped.clone(),
        MessagingDomain::parse("wakeup.scope")?,
        outbox_budget(Duration::from_secs(60)),
    )?;
    append(
        runtime,
        vec![event("wakeup.other-tenant", other, "wakeup.scope", None)],
    )
    .await?;
    append(
        runtime,
        vec![event("wakeup.other-domain", tenant, "wakeup.other", None)],
    )
    .await?;
    let idle = store.next_wakeup(deadline()).await?;
    assert!(!idle.due_now());
    assert!(
        idle.next_deadline().is_none(),
        "unbound tenant/domain cannot schedule this store"
    );
    append(
        scoped,
        vec![
            event("wakeup.ready", tenant, "wakeup.scope", None),
            event("wakeup.future", tenant, "wakeup.scope", None),
        ],
    )
    .await?;
    sqlx::query("UPDATE rss_transactional_messaging.outbox SET retry_after=clock_timestamp()+interval '10 seconds' WHERE message_id='wakeup.future'").execute(owner).await?;
    let before: Vec<serde_json::Value> = sqlx::query_scalar("SELECT to_jsonb(o) FROM rss_transactional_messaging.outbox o WHERE domain='wakeup.scope' ORDER BY seq").fetch_all(owner).await?;
    let start = Timer::new().now();
    let wake = store.next_wakeup(deadline()).await?;
    assert!(wake.due_now());
    let next = wake
        .next_deadline()
        .expect("due work must not hide the future retry");
    assert!(next.instant() > start && next.instant() <= start + Duration::from_secs(10));
    let after: Vec<serde_json::Value> = sqlx::query_scalar("SELECT to_jsonb(o) FROM rss_transactional_messaging.outbox o WHERE domain='wakeup.scope' ORDER BY seq").fetch_all(owner).await?;
    assert_eq!(
        before, after,
        "scheduling cannot alter ownership or durable state"
    );
    let mut locked = owner.begin().await?;
    sqlx::query("SELECT seq FROM rss_transactional_messaging.outbox WHERE message_id='wakeup.ready' FOR UPDATE").execute(&mut *locked).await?;
    assert!(
        store
            .claim_partition_heads(NonZeroUsize::MIN, deadline())
            .await?
            .is_empty()
    );
    let contended = store.next_wakeup(deadline()).await?;
    assert!(
        contended.due_now() && contended.next_deadline().is_some(),
        "a contended due row must not hide a future timer or block the snapshot"
    );
    locked.rollback().await?;
    assert!(
        store
            .next_wakeup(OperationDeadline::from_remaining(Duration::ZERO))
            .await
            .is_err()
    );
    Ok(())
}

async fn partition_and_lease(
    runtime: &Arc<PgRuntime>,
    owner: &PgPool,
    tenant: TenantId,
) -> anyhow::Result<()> {
    let store = PgOutboxStore::<()>::new(
        runtime.clone(),
        MessagingDomain::parse("wakeup.ordered")?,
        outbox_budget(Duration::from_secs(60)),
    )?;
    append(
        runtime,
        vec![
            event("wakeup.head", tenant, "wakeup.ordered", Some("head")),
            event("wakeup.tail", tenant, "wakeup.ordered", Some("head")),
        ],
    )
    .await?;
    let claim = store
        .claim_partition_heads(NonZeroUsize::MIN, deadline())
        .await?
        .into_iter()
        .next()
        .expect("head");
    let held = store.next_wakeup(deadline()).await?;
    assert!(
        !held.due_now(),
        "a held head blocks its already-due successor"
    );
    assert!(
        held.next_deadline().is_some(),
        "held lease schedules recovery"
    );
    store
        .settle(claim, OutboxSettlement::Retry, deadline())
        .await?;
    sqlx::query("UPDATE rss_transactional_messaging.outbox SET retry_after=clock_timestamp()+interval '10 seconds' WHERE message_id='wakeup.head'").execute(owner).await?;
    let retry = store.next_wakeup(deadline()).await?;
    assert!(!retry.due_now());
    assert!(retry.next_deadline().is_some());
    assert!(
        store
            .claim_partition_heads(NonZeroUsize::MIN, deadline())
            .await?
            .is_empty()
    );
    sqlx::query("UPDATE rss_transactional_messaging.outbox SET retry_after=clock_timestamp()-interval '1 second' WHERE message_id='wakeup.head'").execute(owner).await?;
    assert!(store.next_wakeup(deadline()).await?.due_now());
    let claim = store
        .claim_partition_heads(NonZeroUsize::MIN, deadline())
        .await?
        .into_iter()
        .next()
        .expect("retry due");
    sqlx::query("UPDATE rss_transactional_messaging.outbox SET lease_until=clock_timestamp()-interval '1 second' WHERE message_id='wakeup.head'").execute(owner).await?;
    assert!(
        store.next_wakeup(deadline()).await?.due_now(),
        "expired publishing lease is due"
    );
    assert!(
        store
            .next_wakeup(deadline())
            .await?
            .next_deadline()
            .is_none()
    );
    drop(claim); // This intentionally leaves the original expired lease for durable recovery.
    let reclaimed = store
        .claim_partition_heads(NonZeroUsize::MIN, deadline())
        .await?
        .into_iter()
        .next()
        .expect("expired lease recovery");
    store
        .settle(reclaimed, OutboxSettlement::Published(()), deadline())
        .await?;
    assert!(
        store.next_wakeup(deadline()).await?.due_now(),
        "publishing the head admits its successor"
    );
    let tail = store
        .claim_partition_heads(NonZeroUsize::MIN, deadline())
        .await?
        .into_iter()
        .next()
        .expect("tail");
    store
        .settle(tail, OutboxSettlement::Published(()), deadline())
        .await?;
    let idle = store.next_wakeup(deadline()).await?;
    assert!(!idle.due_now() && idle.next_deadline().is_none());
    Ok(())
}
