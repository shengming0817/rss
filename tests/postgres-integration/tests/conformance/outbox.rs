use super::*;
use rss_transactional_messaging::outbox::*;
use rss_transactional_messaging_testkit::outbox::{
    OutboxDriver, ReclaimEvidence, StaleSettlementEvidence, TenantSettlement,
};
use std::num::NonZeroUsize;

pub(super) struct Driver {
    h: Harness,
    head: tokio::sync::Mutex<Option<PgOutboxClaim>>,
}
impl Driver {
    pub(super) fn new(runtime: Arc<PgRuntime>, owner: &sqlx::PgPool) -> Self {
        Self {
            h: Harness::new(runtime, owner, "outbox-conformance"),
            head: tokio::sync::Mutex::new(None),
        }
    }
    fn store(&self) -> Arc<PgOutboxStore<()>> {
        Arc::new(
            PgOutboxStore::new(
                self.h.runtime.clone(),
                MessagingDomain::parse(&self.h.id()).expect("domain"),
                crate::outbox_budget(Duration::from_secs(60)),
            )
            .expect("store"),
        )
    }
    fn envelope(&self, suffix: &str, payload: Vec<u8>) -> MessageEnvelope<Vec<u8>> {
        self.envelope_in_tenant(
            suffix,
            payload,
            message(&self.h.id()).metadata().tenant_id(),
        )
    }
    fn envelope_in_tenant(
        &self,
        suffix: &str,
        payload: Vec<u8>,
        tenant: rss_request_context::TenantId,
    ) -> MessageEnvelope<Vec<u8>> {
        let template = message(&format!("{}{suffix}", self.h.id()));
        let m = template.metadata();
        MessageEnvelope::new(
            template.id().clone(),
            MessageMetadata::new(
                AuthoredMessageMetadata::new(
                    tenant,
                    m.occurred_at(),
                    MessagingDomain::parse(&self.h.id()).expect("domain"),
                    m.route().clone(),
                    m.contract().clone(),
                ),
                MessageMetadataExtensions::new(
                    None,
                    Some(PartitionKey::parse("ordered").expect("partition")),
                    None,
                    Default::default(),
                ),
            ),
            payload,
        )
    }
    async fn append(
        &self,
        suffix: &str,
        payload: Vec<u8>,
    ) -> Result<AppendOutcome, MessagingError> {
        self.append_message(PendingMessage::new(self.envelope(suffix, payload)))
            .await
    }
    async fn append_message(
        &self,
        message: PendingMessage<Vec<u8>>,
    ) -> Result<AppendOutcome, MessagingError> {
        let tenant = message.envelope().metadata().tenant_id();
        let store = self.store();
        self.h
            .runtime
            .local_tx(tenant, deadline(), move |tx| {
                Box::pin(async move { store.append(tx, message).await.map_err(Into::into) })
            })
            .await
            .fold(Ok, Err, Err, Err, Err, Err)
            .map_err(|error| {
                let kind = match &error {
                    PgError::Operation { kind, .. } => *kind,
                    _ => MessagingErrorKind::Invariant,
                };
                MessagingError::new(kind, error)
            })
    }
    async fn claim(&self) -> Result<PgOutboxClaim, MessagingError> {
        self.store()
            .claim_partition_heads(NonZeroUsize::MIN, deadline())
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| port(std::io::Error::other("expected partition head")))
    }
    async fn expire(&self) -> Result<(), MessagingError> {
        sqlx::query("UPDATE rss_transactional_messaging.outbox SET lease_until=clock_timestamp()-interval '1 second' WHERE domain=$1 AND status='publishing'")
            .bind(self.h.id()).execute(&self.h.owner).await.map_err(port)?;
        Ok(())
    }
    async fn retry_ready(&self) -> Result<(), MessagingError> {
        sqlx::query("UPDATE rss_transactional_messaging.outbox SET retry_after=clock_timestamp()-interval '1 second' WHERE domain=$1")
            .bind(self.h.id()).execute(&self.h.owner).await.map_err(port)?;
        Ok(())
    }
    async fn fenced_settle(&self, claim: PgOutboxClaim) -> Result<(), MessagingError> {
        let snapshot = || {
            sqlx::query_scalar::<_, String>("SELECT row_to_json(o)::text FROM rss_transactional_messaging.outbox o WHERE domain=$1 AND message_id=$2").bind(self.h.id()).bind(self.h.id())
        };
        let before = snapshot().fetch_one(&self.h.owner).await.map_err(port)?;
        let error = self
            .store()
            .settle(claim, OutboxSettlement::DeadLetter, deadline())
            .await
            .expect_err("stale or expired settlement must fail");
        assert_eq!(error.kind(), MessagingErrorKind::OwnershipLost);
        let after = snapshot().fetch_one(&self.h.owner).await.map_err(port)?;
        assert_eq!(
            before, after,
            "fenced settlement must not mutate durable state"
        );
        Ok(())
    }
    async fn concurrent_append(&self, different: bool) -> Result<(), MessagingError> {
        let mut race = Self::new(self.h.runtime.clone(), &self.h.owner);
        race.h.prefix = if different {
            "append-race-conflict"
        } else {
            "append-race-same"
        };
        let first = race.envelope("", vec![1]);
        let second = race.envelope("", if different { vec![2] } else { vec![1] });
        let tenant = first.metadata().tenant_id();
        let inserted = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let store = race.store();
        let notify = inserted.clone();
        let gate = release.clone();
        let winner = self.h.runtime.local_tx(tenant, deadline(), move |tx| {
            Box::pin(async move {
                let outcome = store
                    .append(tx, PendingMessage::new(first))
                    .await
                    .map_err(PgError::from)?;
                notify.notify_one();
                gate.notified().await;
                Ok(outcome)
            })
        });
        let store = race.store();
        let loser = async {
            inserted.notified().await;
            self.h
                .runtime
                .local_tx(tenant, deadline(), move |tx| {
                    Box::pin(async move {
                        store
                            .append(tx, PendingMessage::new(second))
                            .await
                            .map_err(PgError::from)
                    })
                })
                .await
        };
        let unlock = async {
            tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name='rss-transactional-messaging-postgres' AND wait_event_type='Lock' AND query LIKE 'INSERT INTO rss_transactional_messaging.outbox%')").fetch_one(&self.h.owner).await.expect("lock witness");
                    if blocked { break; }
                    tokio::task::yield_now().await;
                }
            }).await.expect("second append must enter the MVCC conflict wait");
            release.notify_one();
        };
        let (winner, loser, ()) = tokio::join!(winner, loser, unlock);
        assert!(winner.fold(Ok, Err, Err, Err, Err, Err).is_ok());
        let result = loser.fold(Ok, Err, Err, Err, Err, Err);
        if different {
            assert_eq!(
                result.expect_err("conflicting fingerprint").kind(),
                MessagingErrorKind::Conflict
            );
        } else {
            assert_eq!(result.map_err(port)?, AppendOutcome::AlreadyPresent);
        }
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM rss_transactional_messaging.outbox WHERE domain=$1",
        )
        .bind(race.h.id())
        .fetch_one(&self.h.owner)
        .await
        .map_err(port)?;
        assert_eq!(count, 1);
        Ok(())
    }
    async fn disposition(
        &self,
        tenant: rss_request_context::TenantId,
        id: &MessageId,
    ) -> Result<OutboxDisposition, MessagingError> {
        let status: String = sqlx::query_scalar("SELECT status FROM rss_transactional_messaging.outbox WHERE tenant_id=$1::uuid AND domain=$2 AND message_id=$3")
            .bind(tenant.to_string()).bind(self.h.id()).bind(id.as_str()).fetch_one(&self.h.owner).await.map_err(port)?;
        match status.as_str() {
            "published" => Ok(OutboxDisposition::Published),
            "pending" => Ok(OutboxDisposition::Retry),
            "dead_letter" => Ok(OutboxDisposition::DeadLetter),
            _ => Err(port(std::io::Error::other("outbox not settled"))),
        }
    }
    async fn settle(
        &self,
        claim: PgOutboxClaim,
        settlement: OutboxSettlement<()>,
    ) -> Result<OutboxDisposition, MessagingError> {
        let envelope = PgOutboxStore::<()>::message(&claim).envelope();
        let tenant = envelope.metadata().tenant_id();
        let id = envelope.id().clone();
        self.store().settle(claim, settlement, deadline()).await?;
        self.disposition(tenant, &id).await
    }
}
impl OutboxDriver for Driver {
    async fn cross_tenant_completion(&self) -> Result<[TenantSettlement; 2], ConformanceError> {
        let a = message(&self.h.id()).metadata().tenant_id();
        let b = rss_request_context::TenantId::parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
            .map_err(|_| ConformanceError::fixture(MessagingErrorKind::Invariant))?;
        for tenant in [a, b] {
            self.append_message(PendingMessage::new(self.envelope_in_tenant(
                "",
                vec![1, 2, 3],
                tenant,
            )))
            .await
            .map_err(conformance)?;
        }
        // The provider may return a partial batch while paging tenants. Complete each identity.
        for _ in [a, b] {
            let claim = self.claim().await.map_err(conformance)?;
            self.settle(claim, OutboxSettlement::Published(()))
                .await
                .map_err(conformance)?;
        }
        let rows: Vec<(String, String, String)> = sqlx::query_as("SELECT tenant_id::text,message_id,status FROM rss_transactional_messaging.outbox WHERE domain=$1 ORDER BY tenant_id")
            .bind(self.h.id()).fetch_all(&self.h.owner).await.map_err(|e| conformance(port(e)))?;
        let evidence = rows
            .into_iter()
            .map(|(tenant, id, status)| {
                Ok(TenantSettlement {
                    tenant: rss_request_context::TenantId::parse(&tenant)
                        .map_err(|e| conformance(port(e)))?,
                    message_id: MessageId::parse(&id).map_err(|e| conformance(port(e)))?,
                    settlement: if status == "published" {
                        OutboxDisposition::Published
                    } else {
                        OutboxDisposition::Retry
                    },
                })
            })
            .collect::<Result<Vec<_>, ConformanceError>>()?;
        evidence
            .try_into()
            .map_err(|_| ConformanceError::fixture(MessagingErrorKind::Invariant))
    }

    async fn retry_settlement_reclaims_same_message(
        &self,
    ) -> Result<ReclaimEvidence, ConformanceError> {
        self.append_first().await.map_err(conformance)?;
        let first = self.claim().await.map_err(conformance)?;
        let first_id = PgOutboxStore::<()>::message(&first).envelope().id().clone();
        let settlement = self
            .settle(first, OutboxSettlement::Retry)
            .await
            .map_err(conformance)?;
        self.retry_ready().await.map_err(conformance)?;
        let second = self.claim().await.map_err(conformance)?;
        let second_id = PgOutboxStore::<()>::message(&second)
            .envelope()
            .id()
            .clone();
        let successor_settlement = self
            .settle(second, OutboxSettlement::Published(()))
            .await
            .map_err(conformance)?;
        Ok(ReclaimEvidence {
            claimed_message_ids: vec![first_id, second_id],
            settlement,
            successor_settlement,
        })
    }
    async fn reclaim_after_publish_before_settle(
        &self,
    ) -> Result<StaleSettlementEvidence, ConformanceError> {
        self.append_first().await.map_err(conformance)?;
        let first = self.claim().await.map_err(conformance)?;
        let first_id = PgOutboxStore::<()>::message(&first).envelope().id().clone();
        // Keep the old capability to exercise a delayed contender after database lease expiry.
        self.expire().await.map_err(conformance)?;
        let second = self.claim().await.map_err(conformance)?;
        let second_id = PgOutboxStore::<()>::message(&second)
            .envelope()
            .id()
            .clone();
        let stale_result = self
            .store()
            .settle(first, OutboxSettlement::DeadLetter, deadline())
            .await
            .map_err(|e| e.kind());
        let successor_settlement = self
            .settle(second, OutboxSettlement::Published(()))
            .await
            .map_err(conformance)?;
        Ok(StaleSettlementEvidence {
            stale_result,
            reclaim: ReclaimEvidence {
                claimed_message_ids: vec![first_id, second_id],
                settlement: successor_settlement,
                successor_settlement,
            },
        })
    }

    async fn delivery_window(&self) -> Result<Option<[OutboxLeaseStatus; 3]>, MessagingError> {
        self.append_first().await?;
        let claim = self.claim().await?;
        let first = self.store().lease_status(&claim, deadline()).await?;
        let renewed = self.store().extend(&claim, deadline()).await?;
        sqlx::query("UPDATE rss_transactional_messaging.outbox SET automatic_retry_deadline=clock_timestamp()-interval '1 second' WHERE message_id=$1")
            .bind(self.h.id()).execute(&self.h.owner).await.map_err(port)?;
        let expired = self.store().lease_status(&claim, deadline()).await?;
        Ok(Some([first, renewed, expired]))
    }
    fn reset(&self) {
        self.h.reset_case();
    }
    async fn append_first(&self) -> Result<AppendOutcome, MessagingError> {
        self.append("", vec![1, 2, 3]).await
    }
    async fn append_same(&self) -> Result<AppendOutcome, MessagingError> {
        self.concurrent_append(false).await?;
        self.append_first().await
    }
    async fn append_conflict(&self) -> Result<AppendOutcome, MessagingError> {
        self.concurrent_append(true).await?;
        self.append("", vec![9]).await
    }
    async fn partition_head_claims(&self) -> Result<usize, MessagingError> {
        self.append("-successor", vec![1, 2, 3]).await?;
        let claims: Vec<_> = self
            .store()
            .claim_partition_heads(NonZeroUsize::new(8).expect("limit"), deadline())
            .await?
            .into_iter()
            .collect();
        let count = claims.len();
        *self.head.lock().await = claims.into_iter().next();
        Ok(count)
    }
    async fn blocked_partition_claims(&self) -> Result<usize, MessagingError> {
        let claim = self.head.lock().await.take().expect("head");
        self.settle(claim, OutboxSettlement::DeadLetter).await?;
        Ok(self
            .store()
            .claim_partition_heads(NonZeroUsize::new(8).expect("limit"), deadline())
            .await?
            .into_iter()
            .count())
    }

    async fn stale_lease(&self) -> Result<OutboxLeaseStatus, MessagingError> {
        self.h.reset_case();
        self.append_first().await?;
        let old = self.claim().await?;
        self.expire().await?;
        let current = self.claim().await?;
        *self.head.lock().await = Some(current);
        let status = self.store().lease_status(&old, deadline()).await?;
        self.fenced_settle(old).await?;
        Ok(status)
    }
    async fn expired_lease(&self) -> Result<OutboxLeaseStatus, MessagingError> {
        self.h.reset_case();
        self.append_first().await?;
        let store = PgOutboxStore::<()>::new(
            self.h.runtime.clone(),
            MessagingDomain::parse(&self.h.id()).expect("domain"),
            crate::outbox_budget(Duration::from_millis(150)),
        )
        .expect("short valid budget");
        let claim = store
            .claim_partition_heads(NonZeroUsize::MIN, deadline())
            .await?
            .into_iter()
            .next()
            .expect("claim");
        let mut blocker = self.h.owner.begin().await.map_err(port)?;
        sqlx::query("SELECT 1 FROM rss_transactional_messaging.outbox WHERE domain=$1 FOR UPDATE")
            .bind(self.h.id())
            .execute(&mut *blocker)
            .await
            .map_err(port)?;
        let unlock = async {
            tokio::time::sleep(Duration::from_millis(250)).await;
            blocker.rollback().await.map_err(port)
        };
        let (result, unlocked) = tokio::join!(self.fenced_settle(claim), unlock);
        unlocked?;
        result?;
        Ok(OutboxLeaseStatus::Lost)
    }
}
