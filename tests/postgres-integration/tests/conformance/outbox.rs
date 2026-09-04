use super::*;
use rss_transactional_messaging::{outbox::*, transport::*};
use rss_transactional_messaging_testkit::{memory::MemoryPublisher, outbox::OutboxDriver};
use std::num::NonZeroUsize;

pub(super) struct Driver {
    h: Harness,
    head: tokio::sync::Mutex<Option<PgOutboxClaim>>,
    ids: Mutex<Vec<MessageId>>,
    settlements: Mutex<Vec<OutboxDisposition>>,
    effects: AtomicUsize,
}
impl Driver {
    pub(super) fn new(runtime: Arc<PgRuntime>, owner: &sqlx::PgPool) -> Self {
        Self {
            h: Harness::new(runtime, owner, "outbox-conformance"),
            head: tokio::sync::Mutex::new(None),
            ids: Mutex::new(Vec::new()),
            settlements: Mutex::new(Vec::new()),
            effects: AtomicUsize::new(0),
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
        let template = message(&format!("{}{suffix}", self.h.id()));
        let m = template.metadata();
        MessageEnvelope::new(
            template.id().clone(),
            MessageMetadata::new(
                AuthoredMessageMetadata::new(
                    m.tenant_id(),
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
        let message = PendingMessage::new(self.envelope(suffix, payload));
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
    async fn publish(
        &self,
        claim: &PgOutboxClaim,
        scripted: PublishOutcome<()>,
    ) -> Result<PublishOutcome<()>, MessagingError> {
        let message = PgOutboxStore::<()>::message(claim).envelope();
        let publisher = MemoryPublisher::new([scripted]);
        let result = publisher.publish(message, deadline()).await;
        self.ids
            .lock()
            .expect("ids")
            .extend(publisher.message_ids());
        if matches!(
            result,
            PublishOutcome::Confirmed(_) | PublishOutcome::Ambiguous(_)
        ) {
            let binding = binding(message);
            if let IdempotencyDisposition::Acquired(claim) =
                self.h.inbox().claim(binding.identity(), deadline()).await?
            {
                let outcome = PgConsumerTx::new(
                    self.h.runtime.clone(),
                    Effect(TerminalDisposition::Succeeded),
                )
                .execute(&claim, message, binding.receipt_intent(), deadline())
                .await;
                assert_eq!(outcome.status(), rss_transactional_messaging::observability::TransactionalMessagingTransactionStatus::Committed);
            }
            self.effects.store(self.h.count().await, Ordering::SeqCst);
        }
        Ok(result)
    }
    async fn settle(
        &self,
        claim: PgOutboxClaim,
        outcome: &PublishOutcome<()>,
    ) -> Result<(), MessagingError> {
        let settlement = duplicate(outcome).into_settlement();
        let disposition = settlement.disposition();
        self.store().settle(claim, settlement, deadline()).await?;
        let status: String = sqlx::query_scalar(
            "SELECT status FROM rss_transactional_messaging.outbox WHERE message_id=$1",
        )
        .bind(self.h.id())
        .fetch_one(&self.h.owner)
        .await
        .map_err(port)?;
        assert_eq!(
            status,
            match disposition {
                OutboxDisposition::Published => "published",
                OutboxDisposition::Retry => "pending",
                OutboxDisposition::DeadLetter => "dead_letter",
            }
        );
        self.settlements
            .lock()
            .expect("settlements")
            .push(disposition);
        Ok(())
    }
    async fn uncertain(&self, crash: bool) -> Result<Vec<PublishOutcome<()>>, ConformanceError> {
        self.append_first().await.map_err(conformance)?;
        let claim = self.claim().await.map_err(conformance)?;
        let first = self
            .publish(
                &claim,
                PublishOutcome::Ambiguous(failure(PublishFailureKind::Transient)),
            )
            .await
            .map_err(conformance)?;
        if crash {
            self.expire().await.map_err(conformance)?;
        } else {
            self.settle(claim, &first).await.map_err(conformance)?;
            self.retry_ready().await.map_err(conformance)?;
        }
        let claim = self.claim().await.map_err(conformance)?;
        let second = self
            .publish(&claim, PublishOutcome::Confirmed(()))
            .await
            .map_err(conformance)?;
        self.settle(claim, &second).await.map_err(conformance)?;
        Ok(vec![first, second])
    }
}
fn failure(kind: PublishFailureKind) -> PublishFailure {
    PublishFailure::new(
        kind,
        PublishFailureStage::Confirm,
        PublishFailureReason::DeadlineElapsed,
    )
}
fn duplicate(value: &PublishOutcome<()>) -> PublishOutcome<()> {
    match value {
        PublishOutcome::Confirmed(()) => PublishOutcome::Confirmed(()),
        PublishOutcome::Ambiguous(f) => PublishOutcome::Ambiguous(*f),
        PublishOutcome::DefinitelyNotPublished(f) => PublishOutcome::DefinitelyNotPublished(*f),
    }
}
impl OutboxDriver for Driver {
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
        self.ids.lock().expect("ids").clear();
        self.settlements.lock().expect("settlements").clear();
        self.effects.store(0, Ordering::SeqCst);
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
        self.store()
            .settle(claim, OutboxSettlement::DeadLetter, deadline())
            .await?;
        Ok(self
            .store()
            .claim_partition_heads(NonZeroUsize::new(8).expect("limit"), deadline())
            .await?
            .into_iter()
            .count())
    }
    async fn confirmed_publish(
        &self,
    ) -> Result<(PublishOutcome<()>, OutboxSettlement<()>), ConformanceError> {
        self.append_first().await.map_err(conformance)?;
        let claim = self.claim().await.map_err(conformance)?;
        let result = self
            .publish(&claim, PublishOutcome::Confirmed(()))
            .await
            .map_err(conformance)?;
        self.settle(claim, &result).await.map_err(conformance)?;
        Ok((result, OutboxSettlement::Published(())))
    }
    async fn transient_publish(&self) -> Result<PublishOutcome<()>, MessagingError> {
        self.append_first().await?;
        let claim = self.claim().await?;
        let result = self
            .publish(
                &claim,
                PublishOutcome::DefinitelyNotPublished(failure(PublishFailureKind::Transient)),
            )
            .await?;
        self.settle(claim, &result).await?;
        Ok(result)
    }
    async fn ambiguous_publish(&self) -> Result<Vec<PublishOutcome<()>>, ConformanceError> {
        self.uncertain(false).await
    }
    async fn permanent_publish(&self) -> Result<PublishOutcome<()>, MessagingError> {
        self.append_first().await?;
        let claim = self.claim().await?;
        let result = self
            .publish(
                &claim,
                PublishOutcome::DefinitelyNotPublished(failure(PublishFailureKind::Permanent)),
            )
            .await?;
        self.settle(claim, &result).await?;
        Ok(result)
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
    async fn publish_before_settle_recovery(
        &self,
    ) -> Result<Vec<PublishOutcome<()>>, ConformanceError> {
        self.uncertain(true).await
    }
    fn published_message_ids(&self) -> Vec<MessageId> {
        self.ids.lock().expect("ids").clone()
    }
    fn settlement_dispositions(&self) -> Vec<OutboxDisposition> {
        self.settlements.lock().expect("settlements").clone()
    }
    fn consumer_effects(&self) -> usize {
        self.effects.load(Ordering::SeqCst)
    }
}
