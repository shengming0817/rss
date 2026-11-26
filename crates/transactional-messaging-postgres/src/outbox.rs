//! Atomic outbox claim, same-ID fingerprint and closed settlement.
use crate::{
    PgError, PgRuntime, PgTransaction,
    envelope::Envelope,
    inbox::{fingerprint, milliseconds},
};
use rss_request_context::{Clock, Deadline, ExecutionTimer};
use rss_transactional_messaging::{
    error::{MessagingError, MessagingErrorKind},
    fence::ExecutionBinding,
    message::{MessageFingerprint, MessageId, MessagingDomain},
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
    pub(crate) binding: ExecutionBinding,
    token: String,
    pub(crate) lease_us: Mutex<i64>,
    #[cfg(feature = "recovery")]
    pub(crate) initial_window: Deadline,
}
#[derive(Clone)]
#[cfg(feature = "recovery")]
pub(crate) struct LocalSourceIdentity {
    pub(crate) seq: i64,
    pub(crate) dr_operation: Option<String>,
}
pub(crate) struct SourceWindow {
    pub(crate) lease_us: i64,
    pub(crate) remaining: Duration,
    pub(crate) delivery: Duration,
}
impl PgOutboxClaim {
    async fn settle_in(
        &self,
        connection: &mut sqlx::PgConnection,
        lease: i64,
        disposition: &str,
    ) -> Result<String, sqlx::Error> {
        sqlx::query_scalar(
            "SELECT rss_transactional_messaging.settle_outbox($1::uuid,$2,$3::uuid,$4,$5,$6::uuid)",
        )
        .bind(self.binding.tenant().to_string())
        .bind(self.seq)
        .bind(&self.token)
        .bind(lease)
        .bind(disposition)
        .bind(&self.dr_operation)
        .fetch_one(connection)
        .await
    }

    pub(crate) async fn lease_in(
        &self,
        tx: &mut PgTransaction<'_>,
        previous: i64,
        extend_ms: i64,
    ) -> Result<SourceWindow, PgError> {
        if *tx.binding() != self.binding {
            return Err(PgError::lost());
        }
        let row = sqlx::query("SELECT * FROM rss_transactional_messaging.outbox_lease($1::uuid,$2,$3::uuid,$4,$5,$6::uuid)")
            .bind(self.binding.tenant().to_string())
            .bind(self.seq)
            .bind(&self.token)
            .bind(previous)
            .bind(extend_ms)
            .bind(&self.dr_operation)
            .fetch_optional(&mut *tx.connection).await?.ok_or_else(PgError::lost)?;
        Ok(SourceWindow {
            lease_us: row.try_get("lease_us")?,
            remaining: Duration::from_micros(row.try_get::<i64, _>("remaining_us")?.unsigned_abs()),
            delivery: Duration::from_micros(row.try_get::<i64, _>("delivery_us")?.unsigned_abs()),
        })
    }

    #[cfg(feature = "recovery")]
    pub(crate) fn local_identity(&self) -> LocalSourceIdentity {
        LocalSourceIdentity {
            seq: self.seq,
            dr_operation: self.dr_operation.clone(),
        }
    }
}
/// Read-only scheduling hints for the selected tenant and store domain.
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
/// Maximum candidate headers admitted to one PostgreSQL claim window.
#[derive(Clone, Copy, Debug)]
pub struct PgOutboxScanBudget(u16);

impl PgOutboxScanBudget {
    /// Select a fixed window of 1–1024 headers, independently of claim capacity.
    pub fn new(headers: u16) -> Result<Self, PgError> {
        if !(1..=1024).contains(&headers) {
            return Err(PgError::InvalidScanBudget);
        }
        Ok(Self(headers))
    }

    fn for_claim(fixed: Option<Self>, capacity: i32) -> i32 {
        // The measured default from #3281 and #3288.
        fixed.map_or_else(|| capacity.saturating_mul(4).clamp(64, 1024), |v| i32::from(v.0))
    }
}

/// PostgreSQL outbox, generic over the selected publisher's receipt evidence.
pub struct PgOutboxStore<R> {
    writer: PgOutboxWriter,
    pub(crate) lease_ms: i64,
    budget: DeliveryBudget,
    scan_budget: Option<PgOutboxScanBudget>,
    receipt: PhantomData<fn() -> R>,
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
            scan_budget: None,
            receipt: PhantomData,
        })
    }
    /// Override the default candidate window for every claim on this store.
    #[must_use]
    pub fn with_scan_budget(mut self, budget: PgOutboxScanBudget) -> Self {
        self.scan_budget = Some(budget);
        self
    }

    /// Read unresolved dead letters for one explicitly selected tenant and this domain.
    /// The host decides how unresolved records affect its admission policy.
    pub async fn has_dead_letters(
        &self,
        binding: ExecutionBinding,
        deadline: OperationDeadline,
    ) -> Result<bool, PgError> {
        let cutoff = Deadline::from_timeout(&self.writer.runtime.timer, deadline.timeout())
            .map_err(|_| PgError::invariant())?;
        let tenant = binding.tenant();
        let domain = self.writer.domain.as_str().to_owned();
        self.writer.runtime.relay(binding, cutoff, move |c| Box::pin(async move {
            Ok(sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT FROM rss_transactional_messaging.outbox WHERE tenant_id=$1::uuid AND domain=$2 AND status='dead_letter')").bind(tenant.to_string()).bind(domain).fetch_one(c).await?)
        })).await
    }
    /// Observe one tenant's durable scheduling without claiming, renewing or settling work.
    /// Evaluates eligibility independently of the claim cursor, including active DR generations. A fenced target
    /// returns ownership lost; the host selects any subsequent tenant.
    pub async fn next_wakeup(
        &self,
        binding: ExecutionBinding,
        deadline: OperationDeadline,
    ) -> Result<OutboxWakeup, PgError> {
        let runtime = &self.writer.runtime;
        let cutoff = Deadline::from_timeout(&runtime.timer, deadline.timeout())
            .map_err(|_| PgError::invariant())?;
        let tenant = binding.tenant();
        let domain = self.writer.domain.as_str().to_owned();
        let observed = runtime.timer.now();
        let (due_now, micros) = runtime.relay(binding, cutoff, move |connection| Box::pin(async move {
            Ok(sqlx::query_as::<_, (bool, Option<i64>)>(
                "SELECT due_now,next_us FROM rss_transactional_messaging.next_outbox_wakeup($1::uuid,$2)",
            ).bind(tenant.to_string()).bind(domain).fetch_one(connection).await?)
        })).await?;
        let next_deadline = micros
            .map(|micros| {
                let micros = u64::try_from(micros).map_err(|_| PgError::invariant())?;
                observed
                    .checked_add(Duration::from_micros(micros))
                    .map(Deadline::at)
                    .ok_or_else(PgError::invariant)
            })
            .transpose()?;
        Ok(OutboxWakeup {
            due_now,
            next_deadline,
        })
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
        self.publication_states(tx, &[(domain, message_id, expected)])
            .await?
            .pop()
            .ok_or_else(PgError::invariant)
    }

    /// Verify each exact dispatch in the borrowed transaction, in request order.
    /// Missing rows are invariant failures even if another request in the batch matches.
    pub async fn publication_states(
        &self,
        tx: &mut PgTransaction<'_>,
        expected: &[(&MessagingDomain, &MessageId, MessageFingerprint)],
    ) -> Result<Vec<bool>, PgError> {
        self.validate_transaction(tx)?;
        if expected.is_empty() {
            return Ok(Vec::new());
        }
        let tenant = tx.tenant_id().to_string();
        let ids: Vec<_> = expected
            .iter()
            .map(|(_, id, _)| id.as_str().to_owned())
            .collect();
        let rows = tx.with_connection(move |connection| Box::pin(async move {
            sqlx::query("SELECT o.domain,o.fingerprint,o.status
                FROM unnest($2::text[]) WITH ORDINALITY requested(id,ordinal)
                LEFT JOIN rss_transactional_messaging.outbox o ON o.tenant_id=$1::uuid AND o.message_id=requested.id
                ORDER BY requested.ordinal")
                .bind(tenant).bind(ids).fetch_all(connection).await
        })).await?;
        rows.iter()
            .zip(expected)
            .map(|(row, (domain, _, digest))| {
                let actual = row
                    .try_get::<Option<&str>, _>("domain")?
                    .ok_or_else(PgError::invariant)?;
                if actual != domain.as_str() || fingerprint(row.try_get("fingerprint")?)? != *digest
                {
                    return Err(PgError::classified(
                        MessagingErrorKind::Conflict,
                        std::io::Error::other("dispatch identity conflict"),
                    ));
                }
                match row.try_get::<&str, _>("status")? {
                    "published" => Ok(true),
                    "pending" | "publishing" | "dead_letter" | "resolved" => Ok(false),
                    _ => Err(PgError::invariant()),
                }
            })
            .collect()
    }
    fn valid_claim(&self, claim: &PgOutboxClaim) -> bool {
        self.writer.domain == *claim.message.envelope().metadata().domain()
            && self.writer.runtime.storage == claim.binding.storage()
            && claim.binding.tenant() == claim.message.envelope().metadata().tenant_id()
    }
    #[cfg(feature = "recovery")]
    pub(crate) async fn inspect_lease(
        &self,
        claim: &PgOutboxClaim,
        deadline: OperationDeadline,
    ) -> Result<OutboxLeaseStatus, MessagingError> {
        self.lease(claim, deadline, 0).await
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
        let runtime = &self.writer.runtime;
        let mut expected = within(&runtime.timer, cutoff, |_| claim.lease_us.lock()).await?;
        let previous = *expected;
        let attempt = runtime
            .transaction_until(
                claim.binding,
                cutoff,
                claim,
                true,
                #[cfg(feature = "integration")]
                None,
                move |claim, tx| {
                    Box::pin(async move { claim.lease_in(tx, previous, extend_ms).await })
                },
            )
            .await;
        match crate::transaction::settled(attempt) {
            Ok(window) => {
                *expected = window.lease_us;
                Ok(OutboxLeaseStatus::Held {
                    remaining: window.remaining,
                    delivery_remaining: Some(window.delivery),
                })
            }
            Err(error) if error.kind() == MessagingErrorKind::OwnershipLost => {
                Ok(OutboxLeaseStatus::Lost)
            }
            Err(error) => Err(error.port()),
        }
    }
}

fn settlement_status(result: &str) -> Result<(), PgError> {
    match result {
        "settled" => Ok(()),
        "expired" | "lost_lease" => Err(PgError::lost()),
        _ => Err(PgError::invariant()),
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
        if !self.valid_claim(claim) || *tx.binding() != claim.binding {
            return Err(PgError::lost());
        }
        let lease = claim.lease_us.lock().await;
        let disposition = match disposition {
            rss_transactional_messaging::transaction::TerminalDisposition::Succeeded => "published",
            rss_transactional_messaging::transaction::TerminalDisposition::Rejected(_) => {
                "dead_letter"
            }
        };
        settlement_status(&claim.settle_in(tx.connection, *lease, disposition).await?)
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
        binding: ExecutionBinding,
        limit: NonZeroUsize,
        deadline: OperationDeadline,
    ) -> Result<OutboxClaimBatch<Self::Claim>, MessagingError> {
        let cutoff = Deadline::from_timeout(&self.writer.runtime.timer, deadline.timeout())
            .map_err(|_| PgError::invariant().port())?;
        let count = i32::try_from(limit.get()).map_err(|_| PgError::invariant().port())?;
        let scan = PgOutboxScanBudget::for_claim(self.scan_budget, count);
        let ttl = self.lease_ms;
        let tenant = binding.tenant();
        let domain = self.writer.domain.as_str().to_owned();
        #[cfg(feature = "recovery")]
        let started = self.writer.runtime.timer.now();
        let (batch, progress) = self.writer.runtime.relay(binding, cutoff, move |connection| Box::pin(async move {
                let rows = sqlx::query("SELECT seq, tenant_id::text, message_id, domain, partition_key, lease_token::text AS token, (extract(epoch FROM lease_until)*1000000)::bigint AS lease_us, envelope::text, payload, fingerprint, dr_operation::text, remaining_us, delivery_us FROM rss_transactional_messaging.claim_outbox($1::uuid,$2,$3,$4,$5)")
                    .bind(tenant.to_string()).bind(&domain).bind(count).bind(scan).bind(ttl).fetch_all(&mut *connection).await?;
                use rss_transactional_messaging::outbox::OutboxScanProgress;
                let action: String = sqlx::query_scalar("SELECT current_setting('rss.outbox_scan_progress')")
                    .fetch_one(&mut *connection).await?;
                let progress = match action.as_str() {
                    "continue" => OutboxScanProgress::Continue,
                    "retry_later" => OutboxScanProgress::RetryLater,
                    "complete" => OutboxScanProgress::Complete,
                    _ => return Err(PgError::invariant()),
                };
                let claims = rows.into_iter().map(|row| {
                    let message = PendingMessage::new(Envelope::decode(&row)?);
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
                    Ok(PgOutboxClaim {
                        #[cfg(feature = "recovery")]
                        initial_window: {
                            let window = row.try_get::<i64,_>("remaining_us")?.min(row.try_get("delivery_us")?);
                            let micros = u64::try_from(window).map_err(|_| PgError::invariant())?;
                            Deadline::at(started.checked_add(Duration::from_micros(micros)).ok_or_else(PgError::invariant)?)
                        },
                        message, binding, dr_operation:row.try_get("dr_operation")?, seq: row.try_get("seq")?, token: row.try_get("token")?, lease_us: Mutex::new(row.try_get("lease_us")?) })
                }).collect::<Result<Vec<_>, PgError>>()?;
                Ok((claims, progress))
        })).await.map_err(PgError::port)?;
        OutboxClaimBatch::try_from_provider(batch, limit, progress)
            .map_err(|e| MessagingError::new(MessagingErrorKind::Invariant, e))
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
        mut claim: Self::Claim,
        settlement: OutboxSettlement<R>,
        deadline: OperationDeadline,
    ) -> Result<(), MessagingError> {
        if !self.valid_claim(&claim) {
            return Err(PgError::lost().port());
        }
        let runtime = &self.writer.runtime;
        let cutoff = runtime.cutoff(deadline).map_err(PgError::port)?;
        let disposition = match settlement {
            OutboxSettlement::Published(_) => "published",
            OutboxSettlement::Retry => "retry",
            OutboxSettlement::DeadLetter => "dead_letter",
        };
        // No other task can renew this move-only claim after settlement starts.
        let lease = *claim.lease_us.get_mut();
        let mut delay = Duration::from_millis(5);
        loop {
            let mut allocator_busy = false;
            let attempt = runtime
                .transaction_until(
                    claim.binding,
                    cutoff,
                    (&claim, &mut allocator_busy),
                    true,
                    #[cfg(feature = "integration")]
                    None,
                    |(claim, allocator_busy), tx| {
                        Box::pin(async move {
                            let result = claim.settle_in(tx.connection, lease, disposition).await;
                            if let Err(sqlx::Error::Database(error)) = &result {
                                **allocator_busy = error.code().as_deref() == Some("55P03")
                                    && error.constraint() == Some("outbox_head_allocator");
                            }
                            settlement_status(&result?)
                        })
                    },
                )
                .await;
            // The SQL error alone cannot authorize a retry: rollback must be acknowledged.
            let retry = attempt
                .fold(
                    |()| Ok(false),
                    Err,
                    |e| if allocator_busy { Ok(true) } else { Err(e) },
                    Err,
                    Err,
                    Err,
                )
                .map_err(PgError::port)?;
            if !retry {
                return Ok(());
            }
            let wake = Deadline::from_timeout(&runtime.timer, delay)
                .map_err(|_| PgError::invariant().port())?;
            within(&runtime.timer, cutoff, |_| runtime.timer.sleep_until(wake)).await?;
            delay = (delay * 2).min(Duration::from_millis(100));
        }
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
