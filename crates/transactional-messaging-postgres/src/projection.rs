//! Same-database delivery: the effect, Inbox and source Outbox share one commit.
//! ref: sqlx sqlx-core/src/transaction.rs@v0.8.6 (one connection/commit owner).
use crate::consumer::PgConsumerTxCommitProof;
use crate::{
    PgConsumerEffect, PgConsumerEffectFailure, PgError, PgInboxClaim, PgInboxStore, PgOutboxClaim,
    PgOutboxStore, PgRecoveryCapture, PgRuntime, PgTransaction,
};
use futures::{StreamExt, stream::FuturesUnordered};
use rss_data_protection::Aead;
use rss_request_context::TenantId;
use rss_request_context::{Deadline, ExecutionTimer};
use rss_transactional_messaging::message::MessageId;
use rss_transactional_messaging::{
    error::MessagingError,
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
use std::{num::NonZeroUsize, sync::Arc, time::Duration};

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
    fault: std::sync::Mutex<Option<crate::PgTransactionFault>>,
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

    /// Inject the effect transaction rather than the preceding source/Inbox claims.
    /// Use only on an isolated fixture runtime with no concurrent projection calls.
    #[cfg(feature = "integration")]
    pub fn inject_next_projection_fault(
        &self,
        fault: crate::PgTransactionFault,
    ) -> Result<(), PgError> {
        *self.fault.lock().map_err(|_| PgError::invariant())? = Some(fault);
        Ok(())
    }
    #[cfg(feature = "integration")]
    fn inject_projection_fault(&self) -> Result<(), PgError> {
        if let Some(fault) = self.fault.lock().map_err(|_| PgError::invariant())?.take() {
            self.runtime.inject_next_transaction_fault(fault);
        }
        Ok(())
    }

    /// Durable scheduling hint; notifications remain optional and callers own bounded waiting.
    pub async fn next_wakeup(
        &self,
        deadline: OperationDeadline,
    ) -> Result<crate::OutboxWakeup, PgError> {
        self.outbox.next_wakeup(deadline).await
    }

    /// Whether this projection has unresolved source dead letters.
    pub async fn has_dead_letters(&self, deadline: OperationDeadline) -> Result<bool, PgError> {
        self.outbox.has_dead_letters(deadline).await
    }

    /// Claim once up to the currently available runtime capacity, then settle each event independently.
    /// Claim waiting has its own deadline. Each event receives a fresh execution budget when it starts;
    /// substeps share that event's absolute cutoff. Results are returned in completion order.
    /// No tasks are spawned. Dropping this future does not prove rollback: durable leases and receipts
    /// remain authoritative after cancellation. A single event failure never discards other results.
    pub async fn project_batch<V: IngressValidator<Vec<u8>>>(
        &self,
        validator: &V,
        limit: NonZeroUsize,
        claim_deadline: OperationDeadline,
        execution_budget: Duration,
    ) -> Result<Vec<PgProjectionItem>, PgError> {
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
            .claim_partition_heads(capacity, remaining(self, cutoff))
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
        Ok(pending.collect().await)
    }

    async fn project_claimed<V: IngressValidator<Vec<u8>>>(
        &self,
        validator: &V,
        source: PgOutboxClaim,
        budget: Duration,
    ) -> Result<PgProjectionOutcome, PgError> {
        let cutoff = Deadline::from_timeout(&self.runtime.timer, budget)
            .map_err(|_| PgError::invariant())?;
        if matches!(self.outbox.lease_status(&source, remaining(self, cutoff)).await.map_err(pg)?,
            OutboxLeaseStatus::Held { delivery_remaining: Some(time), .. } if time.is_zero())
        {
            self.outbox
                .settle(
                    source,
                    OutboxSettlement::DeadLetter,
                    remaining(self, cutoff),
                )
                .await
                .map_err(pg)?;
            return Ok(PgProjectionOutcome::DeliveryExpired);
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
        let acquired = self
            .inbox
            .claim(binding.identity(), remaining(self, cutoff))
            .await
            .map_err(pg)?;
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
        self.inject_projection_fault()?;
        let outcome = crate::consumer::execute_transaction(
            &self.runtime,
            &effect,
            &self.capture,
            &claim,
            message,
            binding.receipt_intent(),
            remaining(self, cutoff),
            Some((&self.outbox, &source)),
        )
        .await;
        self.release_after_rollback(outcome.status(), claim, source, cutoff)
            .await;
        Ok(PgProjectionOutcome::Attempt(Box::new(
            PgProjectionAttempt { outcome, recovery },
        )))
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
        self.inject_projection_fault()?;
        let attempt = self.runtime.local_tx_with_context(identity.tenant_id(), remaining(self, cutoff),
            (self, source, identity, fingerprint), |(owner, source, identity, fingerprint), tx| Box::pin(async move {
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
        crate::transaction::settled(self.runtime.local_tx_with_context(pending.identity.tenant_id(), deadline, pending,
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
        self.renew(cutoff)
            .await
            .map_err(PgConsumerEffectFailure::infrastructure)?;
        let stop = tokio::sync::Notify::new();
        let renew = async {
            loop {
                let wake = cutoff.capped(
                    &self.projection.runtime.timer,
                    self.projection.renewal.interval(),
                );
                tokio::select! {
                    biased;
                    () = stop.notified() => return Ok::<(), PgError>(()),
                    () = self.projection.runtime.timer.sleep_until(wake) => {},
                }
                self.renew(cutoff).await?;
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
impl<H, K> RenewedEffect<'_, H, K> {
    async fn renew(&self, cutoff: Deadline) -> Result<(), PgError> {
        let timer = &self.projection.runtime.timer;
        let source = within(timer, cutoff, |budget| {
            self.projection.outbox.extend(self.source, budget)
        })
        .await?
        .map_err(pg)?;
        if !matches!(source, OutboxLeaseStatus::Held { remaining, delivery_remaining } if self.projection.renewal.fits(remaining) && delivery_remaining.is_none_or(|time| !time.is_zero()))
        {
            return Err(PgError::lost());
        }
        let inbox = within(timer, cutoff, |budget| {
            self.projection.inbox.extend(self.inbox, budget)
        })
        .await?
        .map_err(pg)?;
        if !matches!(inbox, LeaseStatus::Held { remaining } if self.projection.renewal.fits(remaining))
        {
            return Err(PgError::lost());
        }
        Ok(())
    }
}
