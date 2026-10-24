//! Atomic outbox claim, same-ID fingerprint and closed settlement.
use crate::{
    PgError, PgRuntime, PgTransaction,
    envelope::Envelope,
    inbox::{fingerprint, milliseconds},
};
use rss_request_context::{Clock, Deadline};
use rss_transactional_messaging::{
    error::{MessagingError, MessagingErrorKind},
    message::MessagingDomain,
    outbox::*,
    policy::{DeliveryBudget, OperationDeadline, within},
};
use sqlx::Row as _;
use std::{marker::PhantomData, num::NonZeroUsize, sync::Arc, time::Duration};
use tokio::sync::Mutex;

/// Tenant-scoped Outbox admission using the caller's existing transaction.
///
/// This handle has no delivery methods or publisher receipt/budget parameters. For least-privilege
/// database admission, construct its shared runtime with [`PgRuntime::connect_producer`].
pub struct PgOutboxWriter {
    runtime: Arc<PgRuntime>,
    domain: MessagingDomain,
}
impl PgOutboxWriter {
    /// Bind one domain to the same runtime used by companion business repositories.
    pub fn new(runtime: Arc<PgRuntime>, domain: MessagingDomain) -> Self {
        Self { runtime, domain }
    }
    /// Reject a transaction from a different runtime before any companion operation.
    /// Transaction provenance is private and minted by the enclosing runtime, never caller data.
    /// Companion repositories must call this before reads or writes, including operations that
    /// append no message. This performs no SQL, grants no relay capability, and does not commit.
    /// It proves runtime ownership only; the host still owns tenant authorization and composition.
    pub fn validate_transaction(&self, tx: &PgTransaction<'_>) -> Result<(), PgError> {
        tx.check_scope()?;
        if !tx.belongs_to(&self.runtime) {
            tracing::warn!(
                phase = "transaction",
                reason = "runtime_mismatch",
                "outbox transaction owner rejected"
            );
            return Err(PgError::classified(
                MessagingErrorKind::Invariant,
                std::io::Error::other("transaction runtime mismatch"),
            ));
        }
        Ok(())
    }
}
impl OutboxWriter<Vec<u8>> for PgOutboxWriter {
    type Transaction<'tx> = PgTransaction<'tx>;
    async fn append(
        &self,
        tx: &mut Self::Transaction<'_>,
        message: PendingMessage<Vec<u8>>,
    ) -> Result<AppendOutcome, MessagingError> {
        if let Err(error) = self.validate_transaction(tx) {
            tx.outbox_admission = crate::outbox_admission::Admission::Failed;
            return Err(error.port());
        }
        append_message(tx, &self.domain, message).await
    }
}

/// Move-only claim with an internally synchronized, renewed persistent deadline.
pub struct PgOutboxClaim {
    message: PendingMessage<Vec<u8>>,
    seq: i64,
    dr_operation: Option<String>,
    storage: rss_transactional_messaging::fence::StorageIdentity,
    epoch: rss_transactional_messaging::fence::Epoch,
    token: String,
    lease_us: Mutex<i64>,
}
#[derive(Clone)]
#[cfg(feature = "recovery")]
pub(crate) struct LocalSourceIdentity {
    pub(crate) seq: i64,
    pub(crate) dr_operation: Option<String>,
}
impl PgOutboxClaim {
    #[cfg(feature = "recovery")]
    pub(crate) fn local_identity(&self) -> LocalSourceIdentity {
        LocalSourceIdentity {
            seq: self.seq,
            dr_operation: self.dr_operation.clone(),
        }
    }
}
/// Read-only scheduling hints for the store's admitted tenants and domain.
///
/// Due candidates may be locked or claimed by another relay. Neither hint grants a claim or proves
/// delivery. Keep a periodic recovery scan: commits and concurrent settlements can change this snapshot.
#[derive(Clone, Copy, Debug)]
pub struct OutboxWakeup {
    due_now: bool,
    next_deadline: Option<Deadline>,
}
impl OutboxWakeup {
    /// Whether the observed persistent state contains an already-due candidate.
    /// Bound immediate rescans after an empty claim instead of spinning on a contended row.
    #[must_use]
    pub const fn due_now(self) -> bool {
        self.due_now
    }
    /// Earliest observed future eligibility in the runtime's injected monotonic clock domain.
    /// It is anchored before database I/O, so query and settlement time never extend the wait.
    /// The deadline may already have elapsed when this snapshot is returned.
    #[must_use]
    pub const fn next_deadline(self) -> Option<Deadline> {
        self.next_deadline
    }
}
/// PostgreSQL outbox, generic over the selected publisher's receipt evidence.
pub struct PgOutboxStore<R> {
    writer: PgOutboxWriter,
    lease_ms: i64,
    budget: DeliveryBudget,
    receipt: PhantomData<fn() -> R>,
    next_tenant: std::sync::atomic::AtomicUsize,
}
impl<R> PgOutboxStore<R> {
    /// Bind one domain and the explicit lease duration.
    pub fn new(
        runtime: Arc<PgRuntime>,
        domain: MessagingDomain,
        budget: DeliveryBudget,
    ) -> Result<Self, PgError> {
        Ok(Self {
            writer: PgOutboxWriter::new(runtime, domain),
            lease_ms: milliseconds(budget.lease_ttl())?,
            budget,
            receipt: PhantomData,
            next_tenant: std::sync::atomic::AtomicUsize::new(0),
        })
    }
    /// Read whether this domain has unresolved dead letters in any bound tenant.
    /// One absolute budget covers every tenant. This is a read, not permission to resolve records;
    /// the consuming host decides how an unresolved record affects its admission policy.
    pub async fn has_dead_letters(&self, deadline: OperationDeadline) -> Result<bool, PgError> {
        let cutoff = Deadline::from_timeout(&self.writer.runtime.timer, deadline.timeout())
            .map_err(|_| PgError::invariant())?;
        for &(tenant, _) in self.writer.runtime.binding.tenants() {
            let domain = self.writer.domain.as_str().to_owned();
            let found=self.writer.runtime.relay(tenant,cutoff,move|c|Box::pin(async move {
                Ok(sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT FROM rss_transactional_messaging.outbox WHERE tenant_id=$1::uuid AND domain=$2 AND status='dead_letter')").bind(tenant.to_string()).bind(domain).fetch_one(c).await?)
            })).await?;
            if found {
                return Ok(true);
            }
        }
        Ok(false)
    }
    /// Observe durable scheduling without claiming, renewing or settling work.
    ///
    /// Shares the claim candidate definition, including partition heads, retry times, leases and
    /// active DR generations. One absolute operation budget covers all bound tenants. As in claim,
    /// fenced tenants are skipped and loss of every tenant returns ownership lost.
    pub async fn next_wakeup(&self, deadline: OperationDeadline) -> Result<OutboxWakeup, PgError> {
        let runtime = &self.writer.runtime;
        let cutoff = Deadline::from_timeout(&runtime.timer, deadline.timeout())
            .map_err(|_| PgError::invariant())?;
        let mut admitted = false;
        let mut wakeup = OutboxWakeup {
            due_now: false,
            next_deadline: None,
        };
        for &(tenant, _) in runtime.binding.tenants() {
            let domain = self.writer.domain.as_str().to_owned();
            let observed = runtime.timer.now();
            let result = runtime
                .relay(tenant, cutoff, move |connection| {
                    Box::pin(async move {
                        Ok(sqlx::query_as::<_, (bool, Option<i64>)>(
                            "SELECT due_now,next_us FROM rss_transactional_messaging.next_outbox_wakeup($1::uuid,$2)",
                        )
                        .bind(tenant.to_string())
                        .bind(domain)
                        .fetch_one(connection)
                        .await?)
                    })
                })
                .await;
            match result {
                Ok((due_now, micros)) => {
                    admitted = true;
                    wakeup.due_now |= due_now;
                    if let Some(micros) = micros {
                        let micros = u64::try_from(micros).map_err(|_| PgError::invariant())?;
                        let instant = observed
                            .checked_add(Duration::from_micros(micros))
                            .ok_or_else(PgError::invariant)?;
                        let next = Deadline::at(instant);
                        wakeup.next_deadline = Some(
                            wakeup
                                .next_deadline
                                .map_or(next, |old| old.shortened_to(instant)),
                        );
                    }
                }
                Err(error) if error.kind() == MessagingErrorKind::OwnershipLost => continue,
                Err(error) => return Err(error),
            }
        }
        if !admitted {
            return Err(PgError::lost());
        }
        Ok(wakeup)
    }
    /// Reject a transaction from a different runtime before any companion operation.
    pub fn validate_transaction(&self, tx: &PgTransaction<'_>) -> Result<(), PgError> {
        self.writer.validate_transaction(tx)
    }
    /// Read durable confirmation using the persisted exact domain and message identity.
    /// Readback may cross this store's relay domain, but cannot cross its runtime owner.
    /// Missing rows and malformed state are invariant failures; changed identity is a conflict.
    /// This is storage readback, not proof of device receipt or external execution.
    pub async fn is_published(
        &self,
        tx: &mut PgTransaction<'_>,
        domain: &MessagingDomain,
        message_id: &rss_transactional_messaging::message::MessageId,
        expected: rss_transactional_messaging::message::MessageFingerprint,
    ) -> Result<bool, PgError> {
        self.validate_transaction(tx)?;
        let tenant = tx.tenant_id().to_string();
        let id = message_id.as_str().to_owned();
        let row = tx.with_connection(move |connection| Box::pin(async move {
            sqlx::query("SELECT domain,fingerprint,status FROM rss_transactional_messaging.outbox WHERE tenant_id=$1::uuid AND message_id=$2")
                .bind(tenant).bind(id).fetch_optional(connection).await
        })).await?.ok_or_else(PgError::invariant)?;
        let digest: Vec<u8> = row.try_get("fingerprint")?;
        if row.try_get::<String, _>("domain")? != domain.as_str()
            || fingerprint(digest)? != expected
        {
            return Err(PgError::classified(
                MessagingErrorKind::Conflict,
                std::io::Error::other("dispatch identity conflict"),
            ));
        }
        match row.try_get::<String, _>("status")?.as_str() {
            "published" => Ok(true),
            "pending" | "publishing" | "dead_letter" | "resolved" => Ok(false),
            _ => Err(PgError::invariant()),
        }
    }
    fn valid_claim(&self, claim: &PgOutboxClaim) -> bool {
        self.writer.domain == *claim.message.envelope().metadata().domain()
            && self.writer.runtime.binding.storage() == claim.storage
            && self
                .writer
                .runtime
                .binding
                .epoch(claim.message.envelope().metadata().tenant_id())
                == Some(claim.epoch)
    }
    async fn lease(
        &self,
        claim: &PgOutboxClaim,
        deadline: OperationDeadline,
        extend_ms: i64,
    ) -> Result<OutboxLeaseStatus, MessagingError> {
        let cutoff = Deadline::from_timeout(&self.writer.runtime.timer, deadline.timeout())
            .map_err(|_| PgError::invariant().port())?;
        if !self.valid_claim(claim) {
            return Ok(OutboxLeaseStatus::Lost);
        }
        let tenant = claim.message.envelope().metadata().tenant_id();
        let dr = claim.dr_operation.clone();
        let mut lease = within(&self.writer.runtime.timer, cutoff, |_| {
            claim.lease_us.lock()
        })
        .await?;
        let previous = *lease;
        let seq = claim.seq;
        let token = claim.token.clone();
        let result = self
            .writer.runtime
            .relay(tenant, cutoff, move |connection| {
                Box::pin(async move {
                    Ok(sqlx::query(
                        "SELECT * FROM rss_transactional_messaging.outbox_lease($1::uuid,$2,$3::uuid,$4,$5,$6::uuid)",
                    )
                    .bind(tenant.to_string())
                    .bind(seq)
                    .bind(token)
                    .bind(previous)
                    .bind(extend_ms)
                    .bind(dr)
                    .fetch_optional(connection)
                    .await?)
                })
            })
            .await
            .map_err(PgError::port)?;
        match result {
            None => Ok(OutboxLeaseStatus::Lost),
            Some(row) => {
                let current: i64 = row
                    .try_get("lease_us")
                    .map_err(|e| PgError::from(e).port())?;
                let remaining: i64 = row
                    .try_get("remaining_us")
                    .map_err(|e| PgError::from(e).port())?;
                let delivery: i64 = row
                    .try_get("delivery_us")
                    .map_err(|e| PgError::from(e).port())?;
                *lease = current;
                Ok(OutboxLeaseStatus::Held {
                    remaining: Duration::from_micros(remaining.unsigned_abs()),
                    delivery_remaining: Some(Duration::from_micros(delivery.unsigned_abs())),
                })
            }
        }
    }
}

impl PgOutboxStore<()> {
    /// Private composition: only the consumer transaction owner may stage a local terminal result.
    pub(crate) async fn settle_local_in(
        &self,
        tx: &mut PgTransaction<'_>,
        claim: &PgOutboxClaim,
        disposition: rss_transactional_messaging::transaction::TerminalDisposition,
    ) -> Result<(), PgError> {
        self.writer.validate_transaction(tx)?;
        if !self.valid_claim(claim)
            || tx.tenant_id() != claim.message.envelope().metadata().tenant_id()
        {
            return Err(PgError::lost());
        }
        let lease = claim.lease_us.lock().await;
        let disposition = match disposition {
            rss_transactional_messaging::transaction::TerminalDisposition::Succeeded => "published",
            rss_transactional_messaging::transaction::TerminalDisposition::Rejected(_) => {
                "dead_letter"
            }
        };
        let result: String = sqlx::query_scalar(
            "SELECT rss_transactional_messaging.settle_outbox($1::uuid,$2,$3::uuid,$4,$5,$6::uuid)",
        )
        .bind(tx.tenant_id().to_string())
        .bind(claim.seq)
        .bind(&claim.token)
        .bind(*lease)
        .bind(disposition)
        .bind(&claim.dr_operation)
        .fetch_one(&mut *tx.connection)
        .await?;
        match result.as_str() {
            "settled" => Ok(()),
            "expired" | "lost_lease" => Err(PgError::lost()),
            _ => Err(PgError::invariant()),
        }
    }
}
impl<R> OutboxWriter<Vec<u8>> for PgOutboxStore<R> {
    type Transaction<'tx> = PgTransaction<'tx>;
    async fn append(
        &self,
        tx: &mut Self::Transaction<'_>,
        message: PendingMessage<Vec<u8>>,
    ) -> Result<AppendOutcome, MessagingError> {
        self.writer.append(tx, message).await
    }
}
impl<R: Send> OutboxRelayStore<Vec<u8>> for PgOutboxStore<R> {
    fn delivery_budget(&self) -> DeliveryBudget {
        self.budget
    }
    type Claim = PgOutboxClaim;
    type PublishReceipt = R;
    async fn claim_partition_heads(
        &self,
        limit: NonZeroUsize,
        deadline: OperationDeadline,
    ) -> Result<OutboxClaimBatch<Self::Claim>, MessagingError> {
        let cutoff = Deadline::from_timeout(&self.writer.runtime.timer, deadline.timeout())
            .map_err(|_| PgError::invariant().port())?;
        let count = i32::try_from(limit.get()).map_err(|_| PgError::invariant().port())?;
        let ttl = self.lease_ms;
        let mut admitted = false;
        let tenants = self.writer.runtime.binding.tenants();
        let first = self
            .next_tenant
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % tenants.len();
        for offset in 0..tenants.len() {
            let (tenant, epoch) = tenants[(first + offset) % tenants.len()];
            let storage = self.writer.runtime.binding.storage();
            let domain = self.writer.domain.as_str().to_owned();
            let batch = self.writer.runtime.relay(tenant, cutoff, move |connection| Box::pin(async move {
                let rows = sqlx::query("SELECT seq, tenant_id::text, message_id, domain, partition_key, lease_token::text AS token, (extract(epoch FROM lease_until)*1000000)::bigint AS lease_us, envelope::text, fingerprint, dr_operation::text FROM rss_transactional_messaging.claim_outbox($1::uuid,$2,$3,$4)")
                    .bind(tenant.to_string()).bind(&domain).bind(count).bind(ttl).fetch_all(connection).await?;
                rows.into_iter().map(|row| {
                    let message = PendingMessage::new(Envelope::decode(&row.try_get::<String,_>("envelope")?)?);
                    if message.fingerprint() != fingerprint(row.try_get("fingerprint")?)? { return Err(PgError::invariant()); }
                    let envelope = message.envelope();
                    if row.try_get::<String,_>("tenant_id")? != envelope.metadata().tenant_id().to_string()
                        || tenant != envelope.metadata().tenant_id()
                        || row.try_get::<String,_>("message_id")? != envelope.id().as_str()
                        || row.try_get::<String,_>("domain")? != envelope.metadata().domain().as_str()
                        || envelope.metadata().domain().as_str() != domain
                        || row.try_get::<Option<String>,_>("partition_key")?.as_deref() != message.partition().map(|p| p.key().as_str()) {
                        return Err(PgError::invariant());
                    }
                    Ok(PgOutboxClaim { message, storage, epoch, dr_operation:row.try_get("dr_operation")?, seq: row.try_get("seq")?, token: row.try_get("token")?, lease_us: Mutex::new(row.try_get("lease_us")?) })
                }).collect::<Result<Vec<_>, PgError>>()
            })).await;
            let batch = match batch {
                Ok(batch) => {
                    admitted = true;
                    batch
                }
                Err(error) if error.kind() == MessagingErrorKind::OwnershipLost => {
                    tracing::warn!(
                        phase = "relay_claim",
                        reason = "tenant_fenced",
                        "bound tenant execution was fenced"
                    );
                    continue;
                }
                Err(error) => return Err(error.port()),
            };
            // Return the committed tenant batch before awaiting any other transaction. This
            // preserves its claims even when the next tenant fails or the outer budget expires.
            if !batch.is_empty() {
                return OutboxClaimBatch::try_from_provider(batch, limit)
                    .map_err(|e| MessagingError::new(MessagingErrorKind::Invariant, e));
            }
        }
        if !admitted {
            return Err(PgError::lost().port());
        }
        OutboxClaimBatch::try_from_provider(Vec::new(), limit)
            .map_err(|e| MessagingError::new(MessagingErrorKind::Invariant, e))
    }
    async fn lease_status(
        &self,
        claim: &Self::Claim,
        deadline: OperationDeadline,
    ) -> Result<OutboxLeaseStatus, MessagingError> {
        self.lease(claim, deadline, 0).await
    }
    async fn extend(
        &self,
        claim: &Self::Claim,
        deadline: OperationDeadline,
    ) -> Result<OutboxLeaseStatus, MessagingError> {
        self.lease(claim, deadline, self.lease_ms).await
    }
    fn message(claim: &Self::Claim) -> &PendingMessage<Vec<u8>> {
        &claim.message
    }
    async fn settle(
        &self,
        claim: Self::Claim,
        settlement: OutboxSettlement<R>,
        deadline: OperationDeadline,
    ) -> Result<(), MessagingError> {
        if !self.valid_claim(&claim) {
            return Err(PgError::lost().port());
        }
        let tenant = claim.message.envelope().metadata().tenant_id();
        let cutoff = Deadline::from_timeout(&self.writer.runtime.timer, deadline.timeout())
            .map_err(|_| PgError::invariant().port())?;
        let disposition = match settlement {
            OutboxSettlement::Published(_) => "published",
            OutboxSettlement::Retry => "retry",
            OutboxSettlement::DeadLetter => "dead_letter",
        };
        let lease = claim.lease_us.into_inner();
        self.writer.runtime
            .relay(tenant, cutoff, move |connection| {
                Box::pin(async move {
                    let result: String = sqlx::query_scalar(
                        "SELECT rss_transactional_messaging.settle_outbox($1::uuid,$2,$3::uuid,$4,$5,$6::uuid)",
                    )
                    .bind(tenant.to_string())
                    .bind(claim.seq)
                    .bind(claim.token)
                    .bind(lease)
                    .bind(disposition)
                    .bind(claim.dr_operation)
                    .fetch_one(connection)
                    .await?;
                    match result.as_str() {
                        "settled" => Ok(()),
                        "expired" | "lost_lease" => Err(PgError::lost()),
                        _ => Err(PgError::invariant()),
                    }
                })
            })
            .await
            .map_err(PgError::port)
    }
}

/// Single canonical append funnel shared with recovery under the same PG transaction.
pub(crate) async fn append_message<P: AsRef<[u8]>>(
    tx: &mut PgTransaction<'_>,
    domain: &MessagingDomain,
    message: PendingMessage<P>,
) -> Result<AppendOutcome, MessagingError> {
    tx.outbox_admission.begin().map_err(PgError::port)?;
    let envelope = message.envelope();
    if tx.tenant_id() != envelope.metadata().tenant_id() || envelope.metadata().domain() != domain {
        return Err(PgError::invariant().port());
    }
    let encoded = envelope.canonical_bytes();
    let transport = serde_json::json!({
        "trace": envelope.transport_context().trace(),
        "tenant_authority": envelope.transport_context().tenant_authority(),
    });
    let outcome: String = tx
        .with_connection(move |connection| {
            Box::pin(async move {
                sqlx::query_scalar("SELECT rss_transactional_messaging.append_outbox($1,$2)")
                    .bind(encoded)
                    .bind(transport)
                    .fetch_one(connection)
                    .await
            })
        })
        .await
        .map_err(PgError::port)?;
    let result = match outcome.as_str() {
        "inserted" => AppendOutcome::Inserted,
        "already_present" => AppendOutcome::AlreadyPresent,
        "conflict" => {
            return Err(PgError::classified(
                MessagingErrorKind::Conflict,
                std::io::Error::other("same-ID fingerprint conflict"),
            )
            .port());
        }
        _ => return Err(PgError::invariant().port()),
    };
    tx.outbox_admission.complete();
    Ok(result)
}
