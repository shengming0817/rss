//! Real PostgreSQL drivers for the four canonical, provider-neutral conformance suites.
mod consumer;
mod outbox;
use super::{Effect, Timer, Validator, binding, deadline, message};
use rss_transactional_messaging::{
    error::{MessagingError, MessagingErrorKind},
    inbox::*,
    message::*,
    policy::*,
    transaction::*,
};
use rss_transactional_messaging_postgres::*;
use rss_transactional_messaging_testkit::{
    ConformanceError, inbox::InboxDriver, localtx::LocalTxDriver,
};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

fn port(error: impl std::error::Error + Send + Sync + 'static) -> MessagingError {
    MessagingError::new(MessagingErrorKind::Invariant, error)
}
fn conformance(error: MessagingError) -> ConformanceError {
    ConformanceError::fixture(error.kind())
}

struct Harness {
    runtime: Arc<PgRuntime>,
    owner: sqlx::PgPool,
    prefix: &'static str,
    generation: AtomicUsize,
    writes: AtomicUsize,
    attempts: AtomicUsize,
    old_claim: Mutex<Option<Arc<PgInboxClaim>>>,
}
impl Harness {
    fn new(runtime: Arc<PgRuntime>, owner: &sqlx::PgPool, prefix: &'static str) -> Self {
        Self {
            runtime,
            owner: owner.clone(),
            prefix,
            generation: AtomicUsize::new(0),
            writes: AtomicUsize::new(0),
            attempts: AtomicUsize::new(0),
            old_claim: Mutex::new(None),
        }
    }
    fn reset_case(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
        self.writes.store(0, Ordering::SeqCst);
        self.attempts.store(0, Ordering::SeqCst);
        *self.old_claim.lock().expect("old claim") = None;
    }
    fn id(&self) -> String {
        format!("{}-{}", self.prefix, self.generation.load(Ordering::SeqCst))
    }
    fn inbox(&self) -> PgInboxStore {
        PgInboxStore::new(
            self.runtime.clone(),
            rss_transactional_messaging::policy::LeaseRenewalPolicy::from_ttl(Duration::from_secs(
                60,
            ))
            .expect("lease"),
        )
        .expect("lease")
    }
    async fn count(&self) -> usize {
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM public.business_effects WHERE id=$1")
                .bind(self.id())
                .fetch_one(&self.owner)
                .await
                .expect("durable snapshot");
        usize::try_from(count).expect("count")
    }
    async fn expire(&self, id: &str) -> Result<(), MessagingError> {
        sqlx::query("UPDATE rss_transactional_messaging.inbox SET lease_until=clock_timestamp()-interval '1 second' WHERE message_id=$1")
            .bind(id).execute(&self.owner).await.map_err(port)?;
        Ok(())
    }
    async fn commit_effect(&self) -> Result<(), MessagingError> {
        let message = message(&self.id());
        let binding = binding(&message);
        if let IdempotencyDisposition::Acquired(claim) =
            self.inbox().claim(binding.identity(), deadline()).await?
        {
            let consumer =
                PgConsumerTx::new(self.runtime.clone(), Effect(TerminalDisposition::Succeeded));
            let result = consumer
                .execute(&claim, &message, binding.receipt_intent(), deadline())
                .await;
            if result.status() != rss_transactional_messaging::observability::TransactionalMessagingTransactionStatus::Committed {
                return Err(port(std::io::Error::other("expected real commit")));
            }
        }
        Ok(())
    }
    async fn local(&self, rollback: bool) -> LocalTxAttempt<(), FailureClass> {
        self.admitted_local(Some("f47ac10b-58cc-4372-a567-0e02b2c3d479"), rollback)
            .await
    }
    async fn admitted_local(
        &self,
        authorized_tenant: Option<&str>,
        rollback: bool,
    ) -> LocalTxAttempt<(), FailureClass> {
        // Companion preflight is shared by success and rejection cases, not an adapter auth claim.
        let Some(raw) = authorized_tenant else {
            return LocalTxAttempt::not_started(FailureClass::Permanent);
        };
        let Ok(tenant) = rss_request_context::TenantId::parse(raw) else {
            return LocalTxAttempt::not_started(FailureClass::Permanent);
        };
        self.attempts.fetch_add(1, Ordering::SeqCst);
        let id = self.id();
        let result = self
            .runtime
            .local_tx(tenant, deadline(), move |tx| {
                Box::pin(async move {
                    tx.with_connection(move |connection| Box::pin(async move {
                sqlx::query("INSERT INTO public.business_effects(tenant_id,id) VALUES($1::uuid,$2)")
                    .bind(tenant.to_string()).bind(id).execute(connection).await?; Ok(())
            })).await?;
                    if rollback {
                        Err(sqlx::Error::PoolTimedOut.into())
                    } else {
                        Ok(())
                    }
                })
            })
            .await;
        self.writes.store(self.count().await, Ordering::SeqCst);
        result.fold(
            LocalTxAttempt::committed,
            |_| LocalTxAttempt::not_started(FailureClass::Infrastructure),
            |_| LocalTxAttempt::rolled_back(FailureClass::Transient),
            |_| LocalTxAttempt::rollback_failed(FailureClass::Infrastructure),
            |_| LocalTxAttempt::commit_unknown(FailureClass::Infrastructure),
            |_| LocalTxAttempt::fenced(FailureClass::Infrastructure),
        )
    }
}
impl LocalTxDriver for Harness {
    type Error = FailureClass;
    type Snapshot = usize;
    fn reset(&self) {
        self.reset_case();
    }
    async fn committed(&self) -> LocalTxAttempt<(), Self::Error> {
        self.local(false).await
    }
    async fn rolled_back(&self) -> LocalTxAttempt<(), Self::Error> {
        self.local(true).await
    }
    async fn validation_rejected(&self) -> LocalTxAttempt<(), Self::Error> {
        self.admitted_local(Some(""), false).await
    }
    async fn authorization_rejected(&self) -> LocalTxAttempt<(), Self::Error> {
        self.admitted_local(None, false).await
    }
    async fn commit_unknown(&self) -> LocalTxAttempt<(), Self::Error> {
        self.runtime
            .inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
        self.local(false).await
    }
    async fn rollback_failed(&self) -> LocalTxAttempt<(), Self::Error> {
        self.runtime
            .inject_next_transaction_fault(PgTransactionFault::RollbackFailedAfterAck);
        self.local(true).await
    }
    fn classify(&self, error: &Self::Error) -> FailureClass {
        *error
    }
    fn writes(&self) -> usize {
        self.writes.load(Ordering::SeqCst)
    }
    fn attempts(&self) -> usize {
        self.attempts.load(Ordering::SeqCst)
    }
    async fn snapshot(&self) -> Self::Snapshot {
        self.count().await
    }
    fn committed_snapshot(&self) -> Self::Snapshot {
        1
    }
}
impl InboxDriver for Harness {
    type Claim = PgInboxClaim;
    fn reset(&self) {
        self.reset_case();
    }
    async fn first_claim(&self) -> Result<IdempotencyDisposition<Self::Claim>, MessagingError> {
        self.inbox()
            .claim(binding(&message(&self.id())).identity(), deadline())
            .await
    }
    async fn active_claim(&self) -> Result<IdempotencyDisposition<Self::Claim>, MessagingError> {
        self.first_claim().await
    }
    async fn other_group_claim(
        &self,
    ) -> Result<IdempotencyDisposition<Self::Claim>, MessagingError> {
        let message = message(&self.id());
        let identity = ConsumerIdentity::new(
            message.metadata().tenant_id(),
            ConsumerGroup::parse("other").expect("group"),
            message.id().clone(),
            message.metadata().contract().clone(),
        );
        self.inbox().claim(&identity, deadline()).await
    }
    async fn terminal_duplicate(
        &self,
    ) -> Result<IdempotencyDisposition<Self::Claim>, MessagingError> {
        self.commit_effect().await?;
        self.first_claim().await
    }
    async fn extend_owned(&self) -> Result<LeaseStatus, MessagingError> {
        let IdempotencyDisposition::Acquired(claim) = self.first_claim().await? else {
            return Err(port(std::io::Error::other("new claim")));
        };
        let claim = Arc::new(claim);
        let status = self.inbox().extend(&claim, deadline()).await?;
        *self.old_claim.lock().expect("claim") = Some(claim);
        Ok(status)
    }
    async fn reclaim_after_expiry(
        &self,
    ) -> Result<IdempotencyDisposition<Self::Claim>, MessagingError> {
        self.expire(&self.id()).await?;
        self.first_claim().await
    }
    async fn reclaim_after_release(
        &self,
    ) -> Result<IdempotencyDisposition<Self::Claim>, MessagingError> {
        let identity = binding(&message(&format!("{}-release", self.id())));
        let IdempotencyDisposition::Acquired(claim) =
            self.inbox().claim(identity.identity(), deadline()).await?
        else {
            return Err(port(std::io::Error::other("new claim")));
        };
        self.inbox().release(claim, deadline()).await?;
        self.inbox().claim(identity.identity(), deadline()).await
    }
    async fn stale_lease(&self) -> Result<LeaseStatus, MessagingError> {
        let old = self
            .old_claim
            .lock()
            .expect("claim")
            .clone()
            .expect("old claim");
        self.inbox().extend(&old, deadline()).await
    }
}

pub(super) async fn run(runtime: Arc<PgRuntime>, owner: &sqlx::PgPool) -> anyhow::Result<()> {
    let timer = Timer::new();
    rss_transactional_messaging_testkit::localtx::run_localtx_conformance(
        &Harness::new(runtime.clone(), owner, "local-conformance"),
        &timer,
        ExecutionBudget::STANDARD,
    )
    .await?;
    rss_transactional_messaging_testkit::inbox::run_inbox_conformance(
        &Harness::new(runtime.clone(), owner, "inbox-conformance"),
        &timer,
        ExecutionBudget::STANDARD,
    )
    .await?;
    rss_transactional_messaging_testkit::consumer::run_consumer_conformance(
        &Harness::new(runtime.clone(), owner, "consumer-conformance"),
        &timer,
        ExecutionBudget::STANDARD,
    )
    .await?;
    rss_transactional_messaging_testkit::outbox::run_outbox_conformance(
        &outbox::Driver::new(runtime, owner),
        &timer,
        ExecutionBudget::STANDARD,
    )
    .await?;
    Ok(())
}
