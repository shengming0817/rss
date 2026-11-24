//! Durable inbox identity and lease CAS adapted from baseline cotx/eventing.rs.
use crate::transaction::PoolAccess;
use crate::{PgError, PgRuntime, PgTransaction, transaction::settled};
use rss_request_context::Clock as _;
use rss_transactional_messaging::{
    error::{MessagingError, MessagingErrorKind},
    inbox::{ConsumerIdentity, IdempotencyDisposition, InboxStore, LeaseStatus},
    message::{ContractIdentity, MessageFingerprint, PartitionIdentity},
    policy::{LeaseRenewalPolicy, OperationDeadline},
    transaction::{RejectKind, TerminalDisposition, TerminalReceipt, VerifiedConsumerBinding},
};
use sqlx::{Row as _, postgres::PgRow};
use std::{sync::Arc, time::Duration};

/// Private lease token minted only by an acknowledged database claim.
///
/// ```compile_fail
/// use rss_transactional_messaging_postgres::PgInboxClaim;
/// fn duplicate(claim: PgInboxClaim) { let replay = claim.clone(); }
/// ```
pub struct PgInboxClaim {
    // The first effect takes this worker's already-admitted slot. Only a confirmed
    // retryable outcome may return it to the same claim for another attempt.
    slot: std::sync::Mutex<Option<tokio::sync::OwnedSemaphorePermit>>,
    pub(crate) identity: ConsumerIdentity,
    pub(crate) fingerprint: MessageFingerprint,
    ordered: bool,
    pub(crate) token: String,
    pub(crate) binding: rss_transactional_messaging::fence::ExecutionBinding,
}
impl PgInboxClaim {
    pub(crate) fn take_slot(
        &self,
        runtime: &PgRuntime,
    ) -> Option<tokio::sync::OwnedSemaphorePermit> {
        self.slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .filter(|slot| runtime.owns_slot(slot))
    }

    pub(crate) fn return_slot(&self, slot: tokio::sync::OwnedSemaphorePermit) {
        *self
            .slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(slot);
    }

    pub(crate) fn matches(&self, runtime: &PgRuntime) -> bool {
        self.binding.storage() == runtime.storage
            && self.binding.tenant() == self.identity.tenant_id()
    }
}
/// PostgreSQL inbox. Lease duration uses exact PostgreSQL interval microseconds.
pub struct PgInboxStore {
    pub(crate) runtime: Arc<PgRuntime>,
    pub(crate) lease_ms: i64,
    policy: LeaseRenewalPolicy,
}
impl PgInboxStore {
    /// Bind the shared pool and lease policy.
    pub fn new(runtime: Arc<PgRuntime>, policy: LeaseRenewalPolicy) -> Result<Self, PgError> {
        if runtime.pool.options().get_max_connections() < 2 {
            return Err(PgError::InsufficientRenewalCapacity);
        }
        Ok(Self {
            runtime,
            lease_ms: milliseconds(policy.ttl())?,
            policy,
        })
    }
}
pub(crate) fn milliseconds(duration: Duration) -> Result<i64, PgError> {
    if duration.is_zero()
        || duration.as_micros() > i64::MAX as u128
        || !duration.subsec_nanos().is_multiple_of(1_000_000)
    {
        return Err(PgError::InvalidLeaseDuration);
    }
    i64::try_from(duration.as_millis()).map_err(|_| PgError::InvalidLeaseDuration)
}
pub(crate) fn contract_key(identity: &ContractIdentity) -> Result<String, PgError> {
    serde_json::to_string(&(
        identity.id().as_str(),
        identity.version().to_string(),
        identity.schema_digest().as_str(),
    ))
    .map_err(|_| PgError::invariant())
}
pub(crate) fn fingerprint(bytes: Vec<u8>) -> Result<MessageFingerprint, PgError> {
    Ok(MessageFingerprint::from_bytes(
        bytes.try_into().map_err(|_| PgError::invariant())?,
    ))
}
pub(crate) fn disposition(raw: &str) -> Result<TerminalDisposition, PgError> {
    match raw {
        "succeeded" => Ok(TerminalDisposition::Succeeded),
        "rejected_permanent" => Ok(TerminalDisposition::Rejected(RejectKind::Permanent)),
        "rejected_invariant" => Ok(TerminalDisposition::Rejected(RejectKind::Invariant)),
        _ => Err(PgError::invariant()),
    }
}
pub(crate) fn receipt(
    row: &PgRow,
    identity: &ConsumerIdentity,
) -> Result<Option<TerminalReceipt>, PgError> {
    if row.try_get::<String, _>("contract")? != contract_key(identity.contract())? {
        return Err(PgError::classified(
            MessagingErrorKind::Conflict,
            std::io::Error::other("contract conflict"),
        ));
    }
    row.try_get::<Option<String>, _>("disposition")?
        .map(|value| {
            Ok(TerminalReceipt::from_durable(
                identity.clone(),
                fingerprint(row.try_get("fingerprint")?)?,
                disposition(&value)?,
            ))
        })
        .transpose()
}
async fn read(
    transaction: &mut PgTransaction<'_>,
    identity: &ConsumerIdentity,
) -> Result<Option<PgRow>, PgError> {
    Ok(sqlx::query("SELECT contract, fingerprint, disposition,domain,partition_key FROM rss_transactional_messaging.inbox WHERE tenant_id=$1::uuid AND message_id=$2 AND consumer_group=$3")
        .bind(identity.tenant_id().to_string()).bind(identity.message_id().as_str()).bind(identity.group().as_str())
        .fetch_optional(&mut *transaction.connection).await?)
}

impl PgInboxStore {
    pub(crate) async fn claim_with_access(
        &self,
        verified: &VerifiedConsumerBinding,
        partition: Option<&PartitionIdentity>,
        deadline: OperationDeadline,
        access: PoolAccess<'_>,
    ) -> Result<IdempotencyDisposition<PgInboxClaim>, MessagingError> {
        let cutoff = self.runtime.cutoff(deadline).map_err(PgError::port)?;
        let lease_ms = self.lease_ms;
        settled(self.runtime.transaction_with_access(
            verified.execution(), cutoff, (verified, partition), true, access,
            #[cfg(feature = "integration")]
            None,
            move |(verified, partition), tx| Box::pin(claim_in(tx, verified, *partition, lease_ms)),
        ).await).map_err(PgError::port)
    }
}

async fn claim_in(
    tx: &mut PgTransaction<'_>,
    verified: &VerifiedConsumerBinding,
    partition: Option<&PartitionIdentity>,
    lease_ms: i64,
) -> Result<IdempotencyDisposition<PgInboxClaim>, PgError> {
    let identity = verified.identity();
    let tenant = identity.tenant_id().to_string();
    let message = identity.message_id().as_str();
    let group = identity.group().as_str();
    let domain = partition.map(|p| p.domain().as_str());
    let key = partition.map(|p| p.key().as_str());
    let acquired = |token| IdempotencyDisposition::Acquired(PgInboxClaim {
        slot: std::sync::Mutex::new(None),
        identity: identity.clone(),
        fingerprint: verified.fingerprint(),
        ordered: partition.is_some(),
        binding: verified.execution(),
        token,
    });
    let token = sqlx::query_scalar(CLAIM_SQL)
        .bind(&tenant).bind(message).bind(group).bind(contract_key(identity.contract())?)
        .bind(lease_ms).bind(verified.fingerprint().as_bytes().as_slice()).bind(domain).bind(key)
        .fetch_optional(&mut *tx.connection).await?;
    if let Some(token) = token {
        return Ok(acquired(token));
    }
    // A fresh READ COMMITTED statement sees the row whose insertion won either unique index.
    let Some(row) = read(tx, identity).await? else {
        return Ok(if partition.is_some() { IdempotencyDisposition::PartitionBlocked }
                  else { IdempotencyDisposition::InProgress });
    };
    if let Some(terminal) = receipt(&row, identity)? {
        return Ok(IdempotencyDisposition::Terminal(terminal));
    }
    if fingerprint(row.try_get("fingerprint")?)? != verified.fingerprint()
        || row.try_get::<Option<&str>, _>("domain")? != domain
        || row.try_get::<Option<&str>, _>("partition_key")? != key {
        return Err(PgError::classified(MessagingErrorKind::Conflict,
            std::io::Error::other("Inbox admission identity conflict")));
    }
    let token = sqlx::query_scalar(RECLAIM_SQL)
        .bind(&tenant).bind(message).bind(group).bind(lease_ms)
        .bind(verified.fingerprint().as_bytes().as_slice())
        .bind(domain).bind(key).fetch_optional(&mut *tx.connection).await?;
    Ok(token.map_or(IdempotencyDisposition::InProgress, acquired))
}
pub(crate) async fn lock_identity(
    tx: &mut PgTransaction<'_>,
    identity: &ConsumerIdentity,
) -> Result<(), PgError> {
    sqlx::query("SELECT 1 FROM rss_transactional_messaging.inbox WHERE tenant_id=$1::uuid AND message_id=$2 AND consumer_group=$3 FOR UPDATE")
        .bind(identity.tenant_id().to_string()).bind(identity.message_id().as_str()).bind(identity.group().as_str())
        .execute(&mut *tx.connection).await?;
    Ok(())
}
fn acknowledged_lease(
    status: LeaseStatus,
    elapsed: Duration,
    policy: LeaseRenewalPolicy,
) -> Result<LeaseStatus, PgError> {
    let LeaseStatus::Held { remaining } = status else {
        return Ok(LeaseStatus::Lost);
    };
    let remaining = remaining.saturating_sub(elapsed);
    if remaining.is_zero() {
        return Ok(LeaseStatus::Lost);
    }
    if !policy.fits(remaining) {
        return Err(PgError::classified(
            MessagingErrorKind::Transient,
            std::io::Error::other("insufficient acknowledged Inbox lease headroom"),
        ));
    }
    Ok(LeaseStatus::Held { remaining })
}

pub(crate) async fn extend_locked(
    tx: &mut PgTransaction<'_>,
    identity: &ConsumerIdentity,
    token: &str,
    lease_ms: i64,
) -> Result<LeaseStatus, PgError> {
    let remaining = sqlx::query_scalar::<_, i64>("UPDATE rss_transactional_messaging.inbox SET lease_until=clock_timestamp()+($5::bigint::text || ' milliseconds')::interval WHERE tenant_id=$1::uuid AND message_id=$2 AND consumer_group=$3 AND lease_token=$4::uuid AND disposition IS NULL AND lease_until>clock_timestamp() RETURNING GREATEST(0,(extract(epoch FROM lease_until-clock_timestamp())*1000000)::bigint)")
                .bind(identity.tenant_id().to_string()).bind(identity.message_id().as_str()).bind(identity.group().as_str()).bind(token).bind(lease_ms)
                .fetch_optional(&mut *tx.connection).await?;
    Ok(match remaining {
        Some(value) => LeaseStatus::Held {
            remaining: Duration::from_micros(value.unsigned_abs()),
        },
        None => LeaseStatus::Lost,
    })
}

impl InboxStore for PgInboxStore {
    fn lease_policy(&self) -> LeaseRenewalPolicy {
        self.policy
    }
    type Claim = PgInboxClaim;
    async fn claim(
        &self,
        verified: &VerifiedConsumerBinding,
        deadline: OperationDeadline,
    ) -> Result<IdempotencyDisposition<Self::Claim>, MessagingError> {
        self.runtime.validate_binding(verified.execution()).map_err(PgError::port)?;
        let Some(permit) = self.runtime.try_claim_slot().map_err(PgError::port)? else {
            return Ok(IdempotencyDisposition::CapacityBusy);
        };
        let outcome = self
            .claim_with_access(verified, verified.partition(), deadline, PoolAccess::Reserved(&permit))
            .await?;
        if let IdempotencyDisposition::Acquired(claim) = &outcome {
            claim.return_slot(permit);
        }
        Ok(outcome)
    }
    async fn read_terminal(
        &self,
        binding: rss_transactional_messaging::fence::ExecutionBinding,
        identity: &ConsumerIdentity,
        deadline: OperationDeadline,
    ) -> Result<Option<TerminalReceipt>, MessagingError> {
        if binding.tenant() != identity.tenant_id() {
            return Err(PgError::lost().port());
        }
        let identity = identity.clone();
        settled(
            self.runtime
                .local_tx(binding, deadline, move |tx| {
                    Box::pin(async move {
                        read(tx, &identity)
                            .await?
                            .map(|row| receipt(&row, &identity))
                            .transpose()
                            .map(Option::flatten)
                    })
                })
                .await,
        )
        .map_err(PgError::port)
    }
    async fn extend(
        &self,
        claim: &Self::Claim,
        deadline: OperationDeadline,
    ) -> Result<LeaseStatus, MessagingError> {
        if !claim.matches(&self.runtime) {
            return Ok(LeaseStatus::Lost);
        }
        let identity = claim.identity.clone();
        let token = claim.token.clone();
        let lease_ms = self.lease_ms;
        let timer = &self.runtime.timer;
        let started = timer.now();
        let cutoff = self.runtime.cutoff(deadline).map_err(PgError::port)?;
        let checked = settled(
            self.runtime
                .transaction_with_access(
                    claim.binding,
                    cutoff,
                    (),
                    true,
                    PoolAccess::Renewal,
                    #[cfg(feature = "integration")]
                    None,
                    move |_, tx| {
                        Box::pin(async move {
                            lock_identity(tx, &identity).await?;
                            let observed = tx.timer.now();
                            let status = extend_locked(tx, &identity, &token, lease_ms).await?;
                            Ok((observed, status))
                        })
                    },
                )
                .await,
        );
        let now = timer.now();
        tracing::debug!(
            renewal_us = now.saturating_duration_since(started).as_micros() as u64,
            "PostgreSQL Inbox renewal"
        );
        checked
            .and_then(|(observed, status)| {
                acknowledged_lease(status, now.saturating_duration_since(observed), self.policy)
            })
            .map_err(PgError::port)
            .or_else(|error| {
                if error.kind() == MessagingErrorKind::OwnershipLost {
                    Ok(LeaseStatus::Lost)
                } else {
                    Err(error)
                }
            })
    }
    async fn release(
        &self,
        claim: Self::Claim,
        deadline: OperationDeadline,
    ) -> Result<(), MessagingError> {
        if !claim.matches(&self.runtime) {
            return Err(PgError::lost().port());
        }
        let slot = claim.take_slot(&self.runtime);
        let access = slot
            .as_ref()
            .map_or(PoolAccess::Ordinary, PoolAccess::Reserved);
        let cutoff = self.runtime.cutoff(deadline).map_err(PgError::port)?;
        settled(self.runtime.transaction_with_access(claim.binding, cutoff, (), true, access, #[cfg(feature="integration")] None, move |_,tx| Box::pin(async move {
            lock_identity(tx, &claim.identity).await?;
            let statement = if claim.ordered {
                "UPDATE rss_transactional_messaging.inbox SET lease_until=clock_timestamp() WHERE tenant_id=$1::uuid AND message_id=$2 AND consumer_group=$3 AND lease_token=$4::uuid AND disposition IS NULL AND lease_until>clock_timestamp()"
            } else {
                "DELETE FROM rss_transactional_messaging.inbox WHERE tenant_id=$1::uuid AND message_id=$2 AND consumer_group=$3 AND lease_token=$4::uuid AND disposition IS NULL AND lease_until>clock_timestamp()"
            };
            let count = sqlx::query(statement)
                .bind(claim.identity.tenant_id().to_string()).bind(claim.identity.message_id().as_str()).bind(claim.identity.group().as_str()).bind(claim.token)
                .execute(&mut *tx.connection).await?.rows_affected();
            if count == 1 { Ok(()) } else { Err(PgError::lost()) }
        })).await).map_err(PgError::port)
    }
}

// DB time is sampled at the write; an expired claim is never resurrected by renew/release.
const CLAIM_SQL: &str = "INSERT INTO rss_transactional_messaging.inbox
 (tenant_id,message_id,consumer_group,contract,lease_token,lease_until,fingerprint,domain,partition_key)
 VALUES ($1::uuid,$2,$3,$4,gen_random_uuid(),clock_timestamp()+($5::bigint * interval '1 millisecond'),$6,$7,$8)
 ON CONFLICT DO NOTHING RETURNING lease_token::text";

const RECLAIM_SQL: &str = "UPDATE rss_transactional_messaging.inbox
 SET lease_token=gen_random_uuid(), lease_until=clock_timestamp()+($4::bigint * interval '1 millisecond'), receive_count=receive_count+1
 WHERE tenant_id=$1::uuid AND message_id=$2 AND consumer_group=$3 AND disposition IS NULL AND fingerprint=$5
 AND domain IS NOT DISTINCT FROM $6 AND partition_key IS NOT DISTINCT FROM $7
 AND (lease_until<=clock_timestamp() OR claim_epoch<>current_setting('rss.execution_epoch')::bigint
 OR claim_lineage IS DISTINCT FROM decode(current_setting('rss.storage_lineage'),'hex'))
 RETURNING lease_token::text";

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn durable_digest_requires_exact_length_and_roundtrips() {
        for length in [0, 31, 33, 64] {
            assert!(fingerprint(vec![7; length]).is_err());
        }
        assert_eq!(
            fingerprint(vec![7; 32]).map(|value| *value.as_bytes()).ok(),
            Some([7; 32])
        );
    }
    #[test]
    fn invalid_lease_is_configuration_not_durable_corruption() {
        for millis in [86_400_001, 9_223_372_036_854_775] {
            assert_eq!(
                milliseconds(Duration::from_millis(millis)).ok(),
                Some(millis as i64)
            );
        }
        for duration in [
            Duration::ZERO,
            Duration::from_nanos(1),
            Duration::from_millis(9_223_372_036_854_776),
        ] {
            assert!(matches!(
                milliseconds(duration),
                Err(PgError::InvalidLeaseDuration)
            ));
        }
    }
}

#[cfg(test)]
mod renewal_tests {
    use super::*;

    #[test]
    fn delayed_ack_can_consume_renewal_headroom() -> Result<(), Box<dyn std::error::Error>> {
        let ttl = Duration::from_millis(900);
        let policy = LeaseRenewalPolicy::from_ttl(ttl)?;
        let check =
            |elapsed| acknowledged_lease(LeaseStatus::Held { remaining: ttl }, elapsed, policy);
        assert_eq!(
            check(Duration::from_millis(100))?,
            LeaseStatus::Held {
                remaining: Duration::from_millis(800)
            }
        );
        assert_eq!(
            check(Duration::from_millis(600)).err().map(|e| e.kind()),
            Some(MessagingErrorKind::Transient)
        );
        assert_eq!(check(ttl)?, LeaseStatus::Lost);
        Ok(())
    }
}
