//! Same-database delivery: the effect, Inbox and source Outbox share one commit.
//! ref: sqlx sqlx-core/src/transaction.rs@v0.8.6 (one connection/commit owner).
use crate::consumer::PgConsumerTxCommitProof;
use crate::{
    PgConsumerEffect, PgConsumerEffectFailure, PgError, PgInboxClaim, PgInboxStore, PgOutboxClaim,
    PgOutboxStore, PgRecoveryCapture, PgRuntime, PgTransaction,
};
use futures::{Stream, stream::FuturesUnordered};
use rss_data_protection::Aead;
use rss_request_context::TenantId;
use rss_request_context::{Clock, Deadline, ExecutionTimer};
use rss_transactional_messaging::message::MessageId;
use rss_transactional_messaging::{
    error::MessagingError,
    fence::ExecutionBinding,
    inbox::{ConsumerGroup, ConsumerIdentity, IdempotencyDisposition, InboxStore, LeaseStatus},
    message::{MessageEnvelope, MessageFingerprint, MessagingDomain, SubscriptionIdentity},
    outbox::{OutboxLeaseStatus, OutboxRelayStore, OutboxSettlement},
    policy::{DeliveryBudget, LeaseRenewalPolicy, OperationDeadline, within},
    transaction::{
        EnvelopeValidationFailure, FailureClass, IngressValidator, ReceiptIntent,
        TerminalDisposition, TransactionOutcome, verify_ingress,
    },
};
use sqlx::Row;
use std::{
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, Instant},
};

/// A local terminal result, minted only from acknowledged commit or matching durable facts.
pub struct PgProjectionReceipt {
    disposition: TerminalDisposition,
}
impl PgProjectionReceipt {
    /// Success means both the consumer effect and source publication committed.
    #[must_use]
    pub const fn disposition(&self) -> TerminalDisposition {
        self.disposition
    }
}

/// Original identity retained after an unconfirmed transaction. It grants no retry authority.
pub struct PgProjectionRecovery {
    binding: ExecutionBinding,
    source: crate::outbox::LocalSourceIdentity,
    runtime: Arc<PgRuntime>,
    identity: ConsumerIdentity,
    fingerprint: MessageFingerprint,
    domain: MessagingDomain,
}

/// One provider attempt, retaining the canonical six-state result and original recovery identity.
/// Only the component can create this pair. The identity never grants permission to retry effects.
pub struct PgProjectionAttempt {
    outcome: TransactionOutcome<PgConsumerTxCommitProof>,
    recovery: PgProjectionRecovery,
}
impl PgProjectionAttempt {
    /// Consume the canonical result without dropping its proof or merging uncertain states.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        TransactionOutcome<PgConsumerTxCommitProof>,
        PgProjectionRecovery,
    ) {
        (self.outcome, self.recovery)
    }
}

/// Scheduling result of one bounded local delivery. Transaction semantics remain core-owned.
pub enum PgProjectionOutcome {
    /// Another live Inbox owner prevents this attempt.
    InProgress,
    /// A consumer transaction ran; inspect every canonical outcome before using recovery.
    Attempt(Box<PgProjectionAttempt>),
    /// The source's automatic delivery window expired and it was isolated without an effect.
    DeliveryExpired,
    /// Invalid ingress was retained in the source Outbox as a dead letter, without running effect.
    Rejected(EnvelopeValidationFailure),
}

/// Identity and independent result of one event in a claimed batch.
/// A failed sibling never erases this event's acknowledged or uncertain transaction facts.
pub struct PgProjectionItem {
    tenant: TenantId,
    message_id: MessageId,
    outcome: Result<PgProjectionOutcome, PgError>,
}
impl PgProjectionItem {
    /// Tenant of the original source event.
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant
    }
    /// Stable source identity, including when execution failed before a consumer transaction.
    pub fn message_id(&self) -> &MessageId {
        &self.message_id
    }
    /// Consume the independent result and its canonical recovery identity, when an attempt ran.
    pub fn into_outcome(self) -> Result<PgProjectionOutcome, PgError> {
        self.outcome
    }
}

/// Fixed-domain local projection with protected rejection capture and a single runtime owner.
/// Source claims are private to this handle: a claim from another database cannot be supplied.
pub struct PgLocalProjection<H, K> {
    runtime: Arc<PgRuntime>,
    outbox: PgOutboxStore<()>,
    inbox: PgInboxStore,
    capture: PgRecoveryCapture<K>,
    effect: H,
    domain: MessagingDomain,
    group: ConsumerGroup,
    renewal: LeaseRenewalPolicy,
    #[cfg(feature = "integration")]
    fault: std::sync::Mutex<Option<crate::transaction::TransactionInjection>>,
}

impl<H: PgConsumerEffect<Vec<u8>>, K: Aead + Send + Sync> PgLocalProjection<H, K> {
    /// Bind existing capture authority, exact ingress identity, and explicit lease budgets.
    pub async fn new(
        capture: PgRecoveryCapture<K>,
        group: ConsumerGroup,
        domain: MessagingDomain,
        effect: H,
        delivery: DeliveryBudget,
        renewal: LeaseRenewalPolicy,
        deadline: OperationDeadline,
    ) -> Result<Self, PgError> {
        if !renewal.fits(delivery.lease_ttl()) {
            return Err(PgError::InvalidLeaseDuration);
        }
        let runtime = capture.runtime.clone();
        if runtime.pool.options().get_max_connections() < 2 {
            return Err(PgError::invariant());
        }
        let cutoff = Deadline::from_timeout(&runtime.timer, deadline.timeout())
            .map_err(|_| PgError::invariant())?;
        let valid = within(&runtime.timer, cutoff, |_| async {
            sqlx::query_scalar::<_,bool>("SELECT rss_transactional_messaging.projection_scope_matches($1,$2) AND has_function_privilege(current_user,'rss_transactional_messaging.local_projection_dr_status(uuid,bigint,uuid)','EXECUTE') AND NOT EXISTS(SELECT FROM pg_roles r WHERE pg_has_role(current_user,r.oid,'SET') AND (has_function_privilege(r.oid,'rss_transactional_messaging.append_outbox(bytea,jsonb)','EXECUTE') OR has_function_privilege(r.oid,'rss_transactional_messaging.prepare_outbox_partitions(jsonb)','EXECUTE')))")
                .bind(domain.as_str()).bind(group.as_str()).fetch_one(&runtime.pool).await
        }).await??;
        if !valid {
            return Err(PgError::IncompatibleStorageContract(
                crate::PgStorageContractFailure::RuntimeAcl,
            ));
        }
        Ok(Self {
            outbox: PgOutboxStore::new(runtime.clone(), domain.clone(), delivery)?,
            inbox: PgInboxStore::new(runtime.clone(), renewal)?,
            runtime,
            capture,
            effect,
            domain,
            group,
            renewal,
            #[cfg(feature = "integration")]
            fault: std::sync::Mutex::new(None),
        })
    }

    /// Bind a fault to the next effect transaction, optionally pausing before its connection acquire.
    /// Sibling source/Inbox transactions cannot consume this injection. Use only in fixtures.
    #[cfg(feature = "integration")]
    pub fn inject_next_projection_fault(
        &self,
        fault: crate::PgTransactionFault,
        before_acquire: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> Result<(), PgError> {
        *self.fault.lock().map_err(|_| PgError::invariant())? =
            Some(crate::transaction::TransactionInjection {
                fault,
                before_acquire: Box::pin(before_acquire),
            });
        Ok(())
    }
    #[cfg(feature = "integration")]
    fn take_projection_fault(
        &self,
    ) -> Result<Option<crate::transaction::TransactionInjection>, PgError> {
        Ok(self.fault.lock().map_err(|_| PgError::invariant())?.take())
    }

    /// Durable scheduling hint; notifications remain optional and callers own bounded waiting.
    pub async fn next_wakeup(
        &self,
        binding: ExecutionBinding,
        deadline: OperationDeadline,
    ) -> Result<crate::OutboxWakeup, PgError> {
        self.outbox.next_wakeup(binding, deadline).await
    }

    /// Whether this projection has unresolved source dead letters.
    pub async fn has_dead_letters(
        &self,
        binding: ExecutionBinding,
        deadline: OperationDeadline,
    ) -> Result<bool, PgError> {
        self.outbox.has_dead_letters(binding, deadline).await
    }

    /// Claim once up to the currently available runtime capacity, then settle each event independently.
    /// Claim waiting has its own deadline. Each event receives a fresh execution budget when it starts;
    /// substeps share that event's absolute cutoff. Results are returned in completion order.
    /// No tasks are spawned: keep polling the returned stream to drive every claimed event.
    /// Completed items release their runtime capacity immediately. Callers may claim another batch
    /// while polling existing streams; stop claiming before draining during shutdown.
    /// Dropping the future or stream does not prove rollback: durable leases and receipts remain
    /// authoritative after cancellation. An item error does not cancel its siblings.
    pub async fn project_batch<'a, V: IngressValidator<Vec<u8>>>(
        &'a self,
        binding: ExecutionBinding,
        validator: &'a V,
        limit: NonZeroUsize,
        claim_deadline: OperationDeadline,
        execution_budget: Duration,
    ) -> Result<impl Stream<Item = PgProjectionItem> + Send + 'a, PgError> {
        self.runtime.validate_binding(binding)?;
        if execution_budget.is_zero() {
            return Err(PgError::invariant());
        }
        Deadline::from_timeout(&self.runtime.timer, execution_budget)
            .map_err(|_| PgError::invariant())?;
        let cutoff = Deadline::from_timeout(&self.runtime.timer, claim_deadline.timeout())
            .map_err(|_| PgError::invariant())?;
        let first = within(&self.runtime.timer, cutoff, |_| {
            self.runtime.projection_slots.acquire()
        })
        .await?
        .map_err(|_| PgError::invariant())?;
        let mut permits = vec![first];
        while permits.len() < limit.get() {
            let Ok(permit) = self.runtime.projection_slots.try_acquire() else {
                break;
            };
            permits.push(permit);
        }
        let capacity = NonZeroUsize::new(permits.len()).ok_or_else(PgError::invariant)?;
        let claims = self
            .outbox
            .claim_partition_heads(binding, capacity, remaining(self, cutoff))
            .await
            .map_err(pg)?;
        permits.truncate(claims.len());
        let pending = FuturesUnordered::new();
        for (source, permit) in claims.into_iter().zip(permits) {
            pending.push(async move {
                let _permit = permit;
                let message = PgOutboxStore::<()>::message(&source).envelope();
                let tenant = message.metadata().tenant_id();
                let message_id = message.id().clone();
                let outcome = self
                    .project_claimed(validator, source, execution_budget)
                    .await;
                PgProjectionItem {
                    tenant,
                    message_id,
                    outcome,
                }
            });
        }
        Ok(pending)
    }

    async fn project_claimed<V: IngressValidator<Vec<u8>>>(
        &self,
        validator: &V,
        source: PgOutboxClaim,
        budget: Duration,
    ) -> Result<PgProjectionOutcome, PgError> {
        let cutoff = Deadline::from_timeout(&self.runtime.timer, budget)
            .map_err(|_| PgError::invariant())?;
        if source.initial_window.is_expired(self.runtime.timer.now())
            && self.delivery_expired(&source, cutoff).await?
        {
            return self.expire(source, cutoff).await;
        }
        let message = PgOutboxStore::<()>::message(&source).envelope();
        let subscription = SubscriptionIdentity::new(
            self.domain.clone(),
            message.metadata().route().clone(),
            message.metadata().contract().clone(),
        );
        let binding = match verify_ingress(validator, self.group.clone(), &subscription, message) {
            Ok(binding) => binding,
            Err(error) => {
                let reason = error.reason();
                if reason == EnvelopeValidationFailure::ExecutionMismatch {
                    return Err(PgError::lost());
                }
                self.outbox
                    .settle(
                        source,
                        OutboxSettlement::DeadLetter,
                        remaining(self, cutoff),
                    )
                    .await
                    .map_err(pg)?;
                return Ok(PgProjectionOutcome::Rejected(reason));
            }
        };
        if binding.execution() != source.binding {
            return Err(PgError::lost());
        }
        let acquired = self
            .inbox
            .claim(
                binding.execution(),
                binding.identity(),
                remaining(self, cutoff),
            )
            .await
            .map_err(pg)?;
        // Ingress ran within the admitted window. The source CAS still fences settlement;
        // a wait for Inbox must not overturn a matching durable terminal receipt.
        let claim = match acquired {
            IdempotencyDisposition::Acquired(claim) => claim,
            IdempotencyDisposition::InProgress => {
                self.outbox
                    .settle(source, OutboxSettlement::Retry, remaining(self, cutoff))
                    .await
                    .map_err(pg)?;
                return Ok(PgProjectionOutcome::InProgress);
            }
            IdempotencyDisposition::Terminal(receipt) => {
                binding
                    .validate_terminal(receipt)
                    .map_err(|_| PgError::invariant())?;
                return self
                    .finish_existing(&source, binding.receipt_intent(), cutoff)
                    .await;
            }
        };
        let recovery = PgProjectionRecovery {
            binding: source.binding,
            source: source.local_identity(),
            runtime: self.runtime.clone(),
            identity: binding.identity().clone(),
            fingerprint: binding.receipt_intent().fingerprint(),
            domain: self.domain.clone(),
        };
        let effect = RenewedEffect {
            projection: self,
            source: &source,
            inbox: &claim,
        };
        #[cfg(feature = "integration")]
        let injection = self.take_projection_fault()?;
        let outcome = crate::consumer::execute_transaction(
            &self.runtime,
            &effect,
            &self.capture,
            &claim,
            message,
            binding.receipt_intent(),
            remaining(self, cutoff),
            Some((&self.outbox, &source)),
            #[cfg(feature = "integration")]
            injection,
        )
        .await;
        self.release_after_rollback(outcome.status(), claim, source, cutoff)
            .await;
        Ok(PgProjectionOutcome::Attempt(Box::new(
            PgProjectionAttempt { outcome, recovery },
        )))
    }

    async fn delivery_expired(
        &self,
        source: &PgOutboxClaim,
        cutoff: Deadline,
    ) -> Result<bool, PgError> {
        match self
            .outbox
            .lease_status(source, remaining(self, cutoff))
            .await
            .map_err(pg)?
        {
            OutboxLeaseStatus::Held {
                delivery_remaining: Some(window),
                ..
            } => Ok(window.is_zero()),
            OutboxLeaseStatus::Lost => Err(PgError::lost()),
            _ => Err(PgError::invariant()),
        }
    }

    async fn expire(
        &self,
        source: PgOutboxClaim,
        cutoff: Deadline,
    ) -> Result<PgProjectionOutcome, PgError> {
        self.outbox
            .settle(
                source,
                OutboxSettlement::DeadLetter,
                remaining(self, cutoff),
            )
            .await
            .map_err(pg)?;
        Ok(PgProjectionOutcome::DeliveryExpired)
    }

    async fn release_after_rollback(
        &self,
        status: rss_transactional_messaging::observability::TransactionalMessagingTransactionStatus,
        claim: crate::PgInboxClaim,
        source: PgOutboxClaim,
        cutoff: Deadline,
    ) {
        use rss_transactional_messaging::observability::TransactionalMessagingTransactionStatus as Status;
        // The canonical status is inspected only for safe cleanup, never substituted for the
        // original outcome. All three categories here prove not-started or acknowledged rollback.
        let retry = matches!(
            status,
            Status::HandlerTransient | Status::RejectedPermanent | Status::InfrastructureTransient
        );
        if !retry {
            return;
        }
        // Confirmed rollback permits retry; expired authority is left to durable recovery.
        log_cleanup(
            self.inbox.release(claim, remaining(self, cutoff)).await,
            "projection_inbox_release",
        );
        log_cleanup(
            self.outbox
                .settle(source, OutboxSettlement::Retry, remaining(self, cutoff))
                .await,
            "projection_outbox_release",
        );
    }

    async fn finish_existing(
        &self,
        source: &PgOutboxClaim,
        intent: ReceiptIntent,
        cutoff: Deadline,
    ) -> Result<PgProjectionOutcome, PgError> {
        let identity = intent.consumer();
        let fingerprint = intent.fingerprint();
        #[cfg(feature = "integration")]
        let injection = self.take_projection_fault()?;
        let attempt = self.runtime.transaction_with_context(source.binding, remaining(self, cutoff),
            (self, source, identity, fingerprint), true, #[cfg(feature = "integration")] injection, |(owner, source, identity, fingerprint), tx| Box::pin(async move {
                let row = sqlx::query("SELECT contract,fingerprint,disposition FROM rss_transactional_messaging.inbox WHERE tenant_id=$1::uuid AND message_id=$2 AND consumer_group=$3 FOR UPDATE")
                    .bind(identity.tenant_id().to_string()).bind(identity.message_id().as_str()).bind(identity.group().as_str())
                    .fetch_one(&mut *tx.connection).await?;
                let receipt = crate::inbox::receipt(&row, identity)?.ok_or_else(PgError::invariant)?;
                if !receipt.matches(identity, *fingerprint) { return Err(PgError::invariant()); }
                let disposition = receipt.disposition();
                owner.outbox.settle_local_in(tx, source, disposition).await?;
                Ok(disposition)
            })).await;
        let recovery = PgProjectionRecovery {
            binding: source.binding,
            source: source.local_identity(),
            runtime: self.runtime.clone(),
            identity: identity.clone(),
            fingerprint,
            domain: self.domain.clone(),
        };
        let outcome = attempt.fold(
            |disposition| crate::consumer::acknowledged_commit(intent, disposition),
            |_| TransactionOutcome::not_started(FailureClass::Infrastructure),
            |_| TransactionOutcome::rolled_back(FailureClass::Infrastructure),
            |_| TransactionOutcome::rollback_failed(),
            |_| TransactionOutcome::commit_unknown(),
            |_| TransactionOutcome::fenced(),
        );
        Ok(PgProjectionOutcome::Attempt(Box::new(
            PgProjectionAttempt { outcome, recovery },
        )))
    }

    /// Read both terminal facts in one SQL snapshot. `None` is not proof of rollback and never
    /// grants permission to re-run the effect; only a new durable claim can do that.
    pub async fn resolve(
        &self,
        pending: &PgProjectionRecovery,
        deadline: OperationDeadline,
    ) -> Result<Option<PgProjectionReceipt>, PgError> {
        if !Arc::ptr_eq(&self.runtime, &pending.runtime)
            || self.domain != pending.domain
            || self.group != *pending.identity.group()
        {
            return Err(PgError::invariant());
        }
        crate::transaction::settled(self.runtime.local_tx_with_context(pending.binding, deadline, pending,
            |pending, tx| Box::pin(async move {
                let row = sqlx::query("SELECT i.contract,i.fingerprint,i.disposition,o.domain,o.fingerprint AS source_fingerprint,o.status,d.status AS dr_status,d.fingerprint AS dr_fingerprint FROM rss_transactional_messaging.inbox i JOIN rss_transactional_messaging.outbox o USING(tenant_id,message_id) LEFT JOIN LATERAL rss_transactional_messaging.local_projection_dr_status(o.tenant_id,o.seq,$4::uuid) d ON true WHERE o.seq=$5 AND i.tenant_id=$1::uuid AND i.message_id=$2 AND i.consumer_group=$3")
                    .bind(pending.identity.tenant_id().to_string()).bind(pending.identity.message_id().as_str()).bind(pending.identity.group().as_str()).bind(&pending.source.dr_operation).bind(pending.source.seq)
                    .fetch_optional(&mut *tx.connection).await?;
                let Some(row) = row else { return Ok(None); };
                if row.try_get::<String,_>("domain")? != pending.domain.as_str()
                    || crate::inbox::fingerprint(row.try_get("source_fingerprint")?)? != pending.fingerprint { return Err(PgError::invariant()); }
                let Some(receipt) = crate::inbox::receipt(&row, &pending.identity)? else { return Ok(None); };
                if !receipt.matches(&pending.identity, pending.fingerprint) { return Err(PgError::invariant()); }
                if pending.source.dr_operation.is_some() {
                    let status: Option<String> = row.try_get("dr_status")?;
                    let Some(status) = status else { return Ok(None); };
                    if crate::inbox::fingerprint(row.try_get("dr_fingerprint")?)? != pending.fingerprint { return Err(PgError::invariant()); }
                    let expected = match receipt.disposition() { TerminalDisposition::Succeeded => "completed", TerminalDisposition::Rejected(_) => "blocked" };
                    if status != expected { return Ok(None); }
                } else {
                    let expected = match receipt.disposition() { TerminalDisposition::Succeeded => "published", TerminalDisposition::Rejected(_) => "dead_letter" };
                    let status: String = row.try_get("status")?;
                    if matches!(status.as_str(), "pending" | "publishing") { return Ok(None); }
                    if status != expected { return Err(PgError::invariant()); }
                }
                Ok(Some(PgProjectionReceipt { disposition: receipt.disposition() }))
            })).await)
    }
}

fn pg(error: MessagingError) -> PgError {
    PgError::classified(error.kind(), error)
}
fn log_cleanup(result: Result<(), MessagingError>, phase: &'static str) {
    if let Err(error) = ignore_lost(result) {
        tracing::warn!(
            phase,
            kind = error.kind().as_label(),
            "projection cleanup failed; canonical outcome retained"
        );
    }
}
fn ignore_lost(result: Result<(), MessagingError>) -> Result<(), PgError> {
    match result {
        Ok(()) => Ok(()),
        Err(error)
            if error.kind()
                == rss_transactional_messaging::error::MessagingErrorKind::OwnershipLost =>
        {
            Ok(())
        }
        Err(error) => Err(pg(error)),
    }
}
fn remaining<H, K>(owner: &PgLocalProjection<H, K>, cutoff: Deadline) -> OperationDeadline {
    OperationDeadline::from_cutoff(cutoff, &owner.runtime.timer)
}

struct RenewedEffect<'a, H, K> {
    projection: &'a PgLocalProjection<H, K>,
    source: &'a PgOutboxClaim,
    inbox: &'a PgInboxClaim,
}
impl<H: PgConsumerEffect<Vec<u8>>, K: Aead + Send + Sync> PgConsumerEffect<Vec<u8>>
    for RenewedEffect<'_, H, K>
{
    async fn apply(
        &self,
        tx: &mut PgTransaction<'_>,
        message: &MessageEnvelope<Vec<u8>>,
        deadline: OperationDeadline,
    ) -> Result<TerminalDisposition, PgConsumerEffectFailure> {
        let cutoff = Deadline::from_timeout(&self.projection.runtime.timer, deadline.timeout())
            .map_err(PgConsumerEffectFailure::infrastructure)?;
        let mut wake = self
            .check_leases(cutoff)
            .await
            .map_err(PgConsumerEffectFailure::infrastructure)?;
        let stop = tokio::sync::Notify::new();
        let renew = async {
            loop {
                tokio::select! {
                    biased;
                    () = stop.notified() => return Ok::<(), PgError>(()),
                    () = self.projection.runtime.timer.sleep_until(wake) => {},
                }
                wake = self.check_leases(cutoff).await?;
            }
        };
        tokio::pin!(renew);
        let effect = self.projection.effect.apply(tx, message, deadline);
        tokio::pin!(effect);
        tokio::select! {
            biased;
            result = &mut effect => {
                stop.notify_one();
                renew.await.map_err(PgConsumerEffectFailure::infrastructure)?;
                result
            },
            result = &mut renew => {
                result.map_err(PgConsumerEffectFailure::infrastructure)?;
                Err(PgConsumerEffectFailure::infrastructure(PgError::lost()))
            },
        }
    }
}
/// Both durations use the same conservative origin, taken before the first DB sample.
struct CheckedLeases {
    expected: i64,
    observed: Instant,
    remaining: Duration,
    delivery: Duration,
}
impl CheckedLeases {
    fn from_source(
        source: crate::outbox::SourceWindow,
        inbox: Duration,
        observed: Instant,
    ) -> Self {
        Self {
            expected: source.lease_us,
            observed,
            remaining: source.remaining.min(inbox),
            delivery: source.delivery,
        }
    }

    fn next_check(
        &self,
        timer: &crate::transaction::PgTimer,
        policy: LeaseRenewalPolicy,
        cutoff: Deadline,
    ) -> Result<Deadline, PgError> {
        let now = timer.now();
        let elapsed = now
            .checked_duration_since(self.observed)
            .ok_or_else(PgError::invariant)?;
        let lease = self.remaining.saturating_sub(elapsed);
        let delivery = self.delivery.saturating_sub(elapsed);
        if !policy.fits(lease) || delivery.is_zero() {
            return Err(PgError::lost());
        }
        let wait = policy.interval().min(lease / 2).min(delivery);
        Ok(cutoff.shortened_to(now.checked_add(wait).ok_or_else(PgError::invariant)?))
    }
}

impl<H: Sync, K: Send + Sync> RenewedEffect<'_, H, K> {
    async fn check_leases(&self, cutoff: Deadline) -> Result<Deadline, PgError> {
        let p = self.projection;
        let timer = &p.runtime.timer;
        let mut expected = within(timer, cutoff, |_| self.source.lease_us.lock()).await?;
        let previous = *expected;
        // The heartbeat runs nested inside the effect transaction on the same task.
        let attempt = Box::pin(p.runtime.local_tx_with_context(
            self.source.binding,
            remaining(p, cutoff),
            self,
            move |effect, tx| {
                Box::pin(async move { effect.check_locked(tx, previous, cutoff).await })
            },
        ))
        .await;
        let checked = crate::transaction::settled(attempt)?;
        *expected = checked.expected;
        checked.next_check(timer, p.renewal, cutoff)
    }

    async fn check_locked(
        &self,
        tx: &mut PgTransaction<'_>,
        previous: i64,
        cutoff: Deadline,
    ) -> Result<CheckedLeases, PgError> {
        let p = self.projection;
        let timer = &p.runtime.timer;
        let claim = self.inbox;
        if claim.binding != *tx.binding() || !claim.matches(&p.runtime) {
            return Err(PgError::lost());
        }
        // Same order as terminal settlement. Sample expiry only after waiting for both locks.
        crate::inbox::lock_identity(tx, &claim.identity).await?;
        let observed = timer.now();
        let source = self.source.lease_in(tx, previous, 0).await?;
        let inbox = sqlx::query_scalar::<_, i64>(
            "SELECT (extract(epoch FROM lease_until-clock_timestamp())*1000000)::bigint
             FROM rss_transactional_messaging.inbox WHERE tenant_id=$1::uuid AND message_id=$2
             AND consumer_group=$3 AND lease_token=$4::uuid AND disposition IS NULL",
        )
        .bind(claim.identity.tenant_id().to_string())
        .bind(claim.identity.message_id().as_str())
        .bind(claim.identity.group().as_str())
        .bind(&claim.token)
        .fetch_optional(&mut *tx.connection)
        .await?
        .ok_or_else(PgError::lost)?;
        if inbox <= 0 || source.delivery.is_zero() {
            return Err(PgError::lost());
        }
        let checked = CheckedLeases::from_source(
            source,
            Duration::from_micros(inbox.unsigned_abs()),
            observed,
        );
        if checked.next_check(timer, p.renewal, cutoff).is_ok() {
            return Ok(checked);
        }

        let observed = timer.now();
        let source = self
            .source
            .lease_in(tx, previous, p.outbox.lease_ms)
            .await?;
        let LeaseStatus::Held { remaining } =
            crate::inbox::extend_locked(tx, &claim.identity, &claim.token, p.inbox.lease_ms)
                .await?
        else {
            return Err(PgError::lost());
        };
        let checked = CheckedLeases::from_source(source, remaining, observed);
        checked.next_check(timer, p.renewal, cutoff)?;
        Ok(checked)
    }
}
