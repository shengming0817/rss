//! Atomic outbox claim, same-ID fingerprint and closed settlement.
use crate::{
    PgError, PgRuntime, PgTransaction,
    envelope::Envelope,
    inbox::{fingerprint, milliseconds},
};
use rss_transactional_messaging::{
    error::{MessagingError, MessagingErrorKind},
    message::MessagingDomain,
    outbox::*,
    policy::{AbsoluteDeadline, DeliveryBudget, OperationDeadline, within},
};
use sqlx::Row as _;
use std::{marker::PhantomData, num::NonZeroUsize, sync::Arc, time::Duration};
use tokio::sync::Mutex;

/// Move-only claim with an internally synchronized, renewed persistent deadline.
pub struct PgOutboxClaim {
    message: PendingMessage<Vec<u8>>,
    seq: i64,
    token: String,
    lease_us: Mutex<i64>,
}
/// PostgreSQL outbox, generic over the selected publisher's receipt evidence.
pub struct PgOutboxStore<R> {
    runtime: Arc<PgRuntime>,
    domain: MessagingDomain,
    lease_ms: i64,
    budget: DeliveryBudget,
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
            runtime,
            domain,
            lease_ms: milliseconds(budget.lease_ttl())?,
            budget,
            receipt: PhantomData,
        })
    }
    /// Reject a transaction from a different runtime before any companion operation.
    /// Transaction provenance is private and minted by the enclosing runtime, never caller data.
    pub fn validate_transaction(&self, tx: &PgTransaction<'_>) -> Result<(), PgError> {
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
            "pending" | "publishing" | "dead_letter" => Ok(false),
            _ => Err(PgError::invariant()),
        }
    }
    async fn lease(
        &self,
        claim: &PgOutboxClaim,
        deadline: OperationDeadline,
        extend_ms: i64,
    ) -> Result<OutboxLeaseStatus, MessagingError> {
        let cutoff = AbsoluteDeadline::from_timeout(&self.runtime.timer, deadline.timeout())
            .map_err(|_| PgError::invariant().port())?;
        let mut lease = within(&self.runtime.timer, cutoff, |_| claim.lease_us.lock()).await?;
        let previous = *lease;
        let seq = claim.seq;
        let token = claim.token.clone();
        let result = self
            .runtime
            .relay(cutoff, move |connection| {
                Box::pin(async move {
                    Ok(sqlx::query(
                        "SELECT * FROM rss_transactional_messaging.outbox_lease($1,$2::uuid,$3,$4)",
                    )
                    .bind(seq)
                    .bind(token)
                    .bind(previous)
                    .bind(extend_ms)
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
impl<R: Send> OutboxStore<Vec<u8>> for PgOutboxStore<R> {
    fn delivery_budget(&self) -> DeliveryBudget {
        self.budget
    }
    type Transaction<'tx> = PgTransaction<'tx>;
    type Claim = PgOutboxClaim;
    type PublishReceipt = R;
    async fn append(
        &self,
        tx: &mut Self::Transaction<'_>,
        message: PendingMessage<Vec<u8>>,
    ) -> Result<AppendOutcome, MessagingError> {
        self.validate_transaction(tx).map_err(PgError::port)?;
        let envelope = message.envelope();
        if tx.tenant_id() != envelope.metadata().tenant_id()
            || envelope.metadata().domain() != &self.domain
        {
            return Err(PgError::invariant().port());
        }
        let tenant = tx.tenant_id().to_string();
        let id = envelope.id().as_str().to_owned();
        let domain = self.domain.as_str().to_owned();
        let partition = message.partition().map(|p| p.key().as_str().to_owned());
        let encoded = Envelope::encode(envelope).map_err(PgError::port)?;
        let digest = *message.fingerprint().as_bytes();
        let count = tx.with_connection(move |connection| Box::pin(async move {
            sqlx::query("INSERT INTO rss_transactional_messaging.outbox (tenant_id,message_id,domain,partition_key,envelope,fingerprint) VALUES ($1::uuid,$2,$3,$4,$5::jsonb,$6) ON CONFLICT (tenant_id,message_id) DO NOTHING")
                .bind(tenant).bind(id).bind(domain).bind(partition).bind(encoded).bind(digest.as_slice()).execute(connection).await.map(|r| r.rows_affected())
        })).await.map_err(PgError::port)?;
        if count == 1 {
            return Ok(AppendOutcome::Inserted);
        }
        // Separate statement is required after a concurrent ON CONFLICT wait (fresh MVCC snapshot).
        let tenant = tx.tenant_id().to_string();
        let id = envelope.id().as_str().to_owned();
        let persisted = tx.with_connection(move |connection| Box::pin(async move {
            sqlx::query_scalar::<_, Vec<u8>>("SELECT fingerprint FROM rss_transactional_messaging.outbox WHERE tenant_id=$1::uuid AND message_id=$2")
                .bind(tenant).bind(id).fetch_one(connection).await
        })).await.map_err(PgError::port)?;
        if fingerprint(persisted).map_err(PgError::port)? == message.fingerprint() {
            Ok(AppendOutcome::AlreadyPresent)
        } else {
            Err(PgError::classified(
                MessagingErrorKind::Conflict,
                std::io::Error::other("same-ID fingerprint conflict"),
            )
            .port())
        }
    }
    async fn claim_partition_heads(
        &self,
        limit: NonZeroUsize,
        deadline: OperationDeadline,
    ) -> Result<OutboxClaimBatch<Self::Claim>, MessagingError> {
        let cutoff = AbsoluteDeadline::from_timeout(&self.runtime.timer, deadline.timeout())
            .map_err(|_| PgError::invariant().port())?;
        let count = i32::try_from(limit.get()).map_err(|_| PgError::invariant().port())?;
        if count > 64 {
            return Err(PgError::invariant().port());
        }
        let domain = self.domain.as_str().to_owned();
        let ttl = self.lease_ms;
        let claims = self.runtime.relay(cutoff, move |connection| Box::pin(async move {
            let rows = sqlx::query("SELECT seq, tenant_id::text, message_id, domain, partition_key, lease_token::text AS token, (extract(epoch FROM lease_until)*1000000)::bigint AS lease_us, envelope::text, fingerprint FROM rss_transactional_messaging.claim_outbox($1,$2,$3)")
                .bind(&domain).bind(count).bind(ttl).fetch_all(connection).await?;
            rows.into_iter().map(|row| {
                let message = PendingMessage::new(Envelope::decode(&row.try_get::<String,_>("envelope")?)?);
                if message.fingerprint() != fingerprint(row.try_get("fingerprint")?)? { return Err(PgError::invariant()); }
                let envelope = message.envelope();
                if row.try_get::<String,_>("tenant_id")? != envelope.metadata().tenant_id().to_string()
                    || row.try_get::<String,_>("message_id")? != envelope.id().as_str()
                    || row.try_get::<String,_>("domain")? != envelope.metadata().domain().as_str()
                    || envelope.metadata().domain().as_str() != domain
                    || row.try_get::<Option<String>,_>("partition_key")?.as_deref() != message.partition().map(|p| p.key().as_str()) {
                    return Err(PgError::invariant());
                }
                Ok(PgOutboxClaim { message, seq: row.try_get("seq")?, token: row.try_get("token")?, lease_us: Mutex::new(row.try_get("lease_us")?) })
            }).collect::<Result<Vec<_>, PgError>>()
        })).await.map_err(PgError::port)?;
        OutboxClaimBatch::try_from_provider(claims, limit)
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
        let cutoff = AbsoluteDeadline::from_timeout(&self.runtime.timer, deadline.timeout())
            .map_err(|_| PgError::invariant().port())?;
        let disposition = match settlement {
            OutboxSettlement::Published(_) => "published",
            OutboxSettlement::Retry => "retry",
            OutboxSettlement::DeadLetter => "dead_letter",
        };
        let lease = claim.lease_us.into_inner();
        self.runtime
            .relay(cutoff, move |connection| {
                Box::pin(async move {
                    let result: String = sqlx::query_scalar(
                        "SELECT rss_transactional_messaging.settle_outbox($1,$2::uuid,$3,$4)",
                    )
                    .bind(claim.seq)
                    .bind(claim.token)
                    .bind(lease)
                    .bind(disposition)
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
