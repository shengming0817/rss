use super::*;
use rss_transactional_messaging::{
    error::{MessagingError, MessagingErrorKind},
    fence::ExecutionBinding,
};
use std::{num::NonZeroUsize, sync::Mutex};

type Store = PgOutboxStore<()>;

/// Hold the real claim reply at the runtime boundary until the DB race has completed.
struct Claimed<'a> {
    store: &'a Store,
    reply: Mutex<Option<OutboxClaimBatch<PgOutboxClaim>>>,
}

impl OutboxRelayStore<Vec<u8>> for Claimed<'_> {
    type Claim = PgOutboxClaim;
    type PublishReceipt = ();
    fn delivery_budget(&self) -> DeliveryBudget {
        self.store.delivery_budget()
    }
    async fn claim_partition_heads(
        &self,
        _: ExecutionBinding,
        _: NonZeroUsize,
        _: OperationDeadline,
    ) -> Result<OutboxClaimBatch<Self::Claim>, MessagingError> {
        Ok(self
            .reply
            .lock()
            .expect("fixture claim")
            .take()
            .expect("one request"))
    }
    async fn extend(
        &self,
        claim: &Self::Claim,
        deadline: OperationDeadline,
    ) -> Result<OutboxLeaseStatus, MessagingError> {
        self.store.extend(claim, deadline).await
    }
    fn message(claim: &Self::Claim) -> &PendingMessage<Vec<u8>> {
        Store::message(claim)
    }
    async fn settle(
        &self,
        _: Self::Claim,
        _: OutboxSettlement<()>,
        _: OperationDeadline,
    ) -> Result<(), MessagingError> {
        panic!("preparation never authorized settlement")
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Race {
    Expired,
    Takeover,
    Epoch,
    Unknown,
}

#[derive(Debug, PartialEq, sqlx::FromRow)]
struct Facts {
    token: String,
    lease: i64,
    window: i64,
}

async fn facts(owner: &sqlx::PgPool, id: &str) -> anyhow::Result<Facts> {
    Ok(sqlx::query_as("SELECT lease_token::text AS token, (extract(epoch FROM lease_until)*1000000)::bigint AS lease, (extract(epoch FROM automatic_retry_deadline)*1000000)::bigint AS window FROM rss_transactional_messaging.outbox WHERE message_id=$1 AND status='publishing'")
        .bind(id).fetch_one(owner).await?)
}

async fn expire(owner: &sqlx::PgPool, id: &str) -> anyhow::Result<()> {
    sqlx::query("UPDATE rss_transactional_messaging.outbox SET lease_until=clock_timestamp()-interval '1 second' WHERE message_id=$1")
        .bind(id).execute(owner).await?;
    Ok(())
}

async fn wait_for_expiry(owner: &sqlx::PgPool, id: &str, ttl: Duration) -> anyhow::Result<()> {
    let initial = facts(owner, id).await?;
    let wait = sqlx::query("SELECT pg_sleep_until(lease_until + interval '1 millisecond') FROM rss_transactional_messaging.outbox WHERE message_id=$1")
        .bind(id).fetch_one(owner);
    tokio::time::timeout(ttl + Duration::from_secs(2), wait).await??;
    let expired: bool = sqlx::query_scalar("SELECT lease_until <= clock_timestamp() FROM rss_transactional_messaging.outbox WHERE message_id=$1")
        .bind(id).fetch_one(owner).await?;
    assert!(expired);
    assert_eq!(
        facts(owner, id).await?,
        initial,
        "expired with the original token and CAS deadline"
    );
    Ok(())
}

pub(super) async fn run(
    runtime: Arc<PgRuntime>,
    owner: &sqlx::PgPool,
    budget: DeliveryBudget,
) -> anyhow::Result<()> {
    let epoch_tenant =
        rss_request_context::TenantId::parse("00000000-0000-0000-0000-000000003251")?;
    sqlx::query("INSERT INTO rss_transactional_messaging.tenant_epoch VALUES($1::uuid,1)")
        .bind(epoch_tenant.to_string())
        .execute(owner)
        .await?;
    // The owner connection can force lease expiry only in its configured fixture tenant.
    let owner_tenant = crate::fixture_tenant();
    for (race, tenant) in [
        (Race::Expired, owner_tenant),
        (Race::Takeover, owner_tenant),
        (Race::Unknown, owner_tenant),
        (Race::Epoch, epoch_tenant),
    ] {
        let binding = crate::execution(tenant, 1);
        let id = format!("real-relay-{race:?}").to_lowercase();
        let store = seed(runtime.clone(), &id, tenant, budget).await?;
        let acquired = store
            .claim_partition_heads(binding, NonZeroUsize::MIN, deadline())
            .await?;
        assert_eq!(acquired.len(), 1);
        let initial = facts(owner, &id).await?;
        let successor = race.inject(&runtime, owner, &store, binding, &id).await?;
        let reply = Claimed {
            store: &store,
            reply: Mutex::new(Some(acquired)),
        };
        race.check_preparation(owner, &id, &initial, reply, binding)
            .await?;
        let current_binding = crate::execution(tenant, if race == Race::Epoch { 2 } else { 1 });
        verify_reclaim(&store, current_binding, owner, &id, initial, successor).await?;
    }
    Ok(())
}

impl Race {
    async fn inject(
        self,
        runtime: &PgRuntime,
        owner: &sqlx::PgPool,
        store: &Store,
        binding: ExecutionBinding,
        id: &str,
    ) -> anyhow::Result<Option<PgOutboxClaim>> {
        match self {
            Self::Expired => {
                wait_for_expiry(owner, id, store.delivery_budget().lease_ttl()).await?
            }
            Self::Takeover => {
                expire(owner, id).await?;
                let claim = store
                    .claim_partition_heads(binding, NonZeroUsize::MIN, deadline())
                    .await?;
                return Ok(Some(claim.into_iter().next().expect("takeover")));
            }
            Self::Epoch => {
                sqlx::query("UPDATE rss_transactional_messaging.tenant_epoch SET epoch=2 WHERE tenant_id=$1::uuid")
                    .bind(binding.tenant().to_string()).execute(owner).await?;
            }
            Self::Unknown => {
                runtime.inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck)
            }
        }
        Ok(None)
    }

    async fn check_preparation(
        self,
        owner: &sqlx::PgPool,
        id: &str,
        initial: &Facts,
        reply: Claimed<'_>,
        binding: ExecutionBinding,
    ) -> anyhow::Result<()> {
        let before = facts(owner, id).await?;
        let publisher = MemoryPublisher::new([]);
        let result = relay_once(
            binding,
            &reply,
            &publisher,
            &Timer::new(),
            &Emitter,
            NonZeroUsize::MIN,
        )
        .await;
        let after = facts(owner, id).await?;
        assert!(publisher.message_ids().is_empty());
        if self == Self::Unknown {
            assert_eq!(
                result.expect_err("lost commit ACK").kind(),
                MessagingErrorKind::Transient
            );
            assert_eq!(after.token, initial.token);
            assert!(after.lease > initial.lease);
            expire(owner, id).await?;
        } else {
            assert_eq!(result?.fenced(), 1);
            assert_eq!(after, before);
        }
        assert_eq!(after.window, initial.window);
        Ok(())
    }
}

async fn verify_reclaim(
    store: &Store,
    binding: ExecutionBinding,
    owner: &sqlx::PgPool,
    id: &str,
    initial: Facts,
    successor: Option<PgOutboxClaim>,
) -> anyhow::Result<()> {
    let current = match successor {
        Some(claim) => claim,
        None => store
            .claim_partition_heads(binding, NonZeroUsize::MIN, deadline())
            .await?
            .into_iter()
            .next()
            .expect("same-ID reclaim"),
    };
    assert_eq!(Store::message(&current).message_id().as_str(), id);
    let current_facts = facts(owner, id).await?;
    assert_ne!(current_facts.token, initial.token);
    assert_eq!(current_facts.window, initial.window);
    store
        .settle(current, OutboxSettlement::Published(()), deadline())
        .await?;
    Ok(())
}
