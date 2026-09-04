//! Durable inbox identity and lease CAS adapted from baseline cotx/eventing.rs.
use crate::{PgError, PgRuntime, PgTransaction, transaction::settled};
use rss_transactional_messaging::{
    error::{MessagingError, MessagingErrorKind},
    inbox::{ConsumerIdentity, IdempotencyDisposition, InboxStore, LeaseStatus},
    message::{ContractIdentity, MessageFingerprint},
    policy::{LeaseRenewalPolicy, OperationDeadline},
    transaction::{RejectKind, TerminalDisposition, TerminalReceipt},
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
    pub(crate) identity: ConsumerIdentity,
    pub(crate) token: String,
}
/// PostgreSQL inbox. Lease duration is explicit and bounded to one day.
pub struct PgInboxStore {
    pub(crate) runtime: Arc<PgRuntime>,
    lease_ms: i64,
    policy: LeaseRenewalPolicy,
}
impl PgInboxStore {
    /// Bind the shared pool and lease policy.
    pub fn new(runtime: Arc<PgRuntime>, policy: LeaseRenewalPolicy) -> Result<Self, PgError> {
        Ok(Self {
            runtime,
            lease_ms: milliseconds(policy.ttl())?,
            policy,
        })
    }
}
pub(crate) fn milliseconds(duration: Duration) -> Result<i64, PgError> {
    if duration.is_zero()
        || duration > Duration::from_secs(86400)
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
    Ok(sqlx::query("SELECT contract, fingerprint, disposition FROM rss_transactional_messaging.inbox WHERE tenant_id=$1::uuid AND message_id=$2 AND consumer_group=$3")
        .bind(identity.tenant_id().to_string()).bind(identity.message_id().as_str()).bind(identity.group().as_str())
        .fetch_optional(&mut *transaction.connection).await?)
}

async fn lock_identity(
    tx: &mut PgTransaction<'_>,
    identity: &ConsumerIdentity,
) -> Result<(), PgError> {
    sqlx::query("SELECT 1 FROM rss_transactional_messaging.inbox WHERE tenant_id=$1::uuid AND message_id=$2 AND consumer_group=$3 FOR UPDATE")
        .bind(identity.tenant_id().to_string()).bind(identity.message_id().as_str()).bind(identity.group().as_str())
        .execute(&mut *tx.connection).await?;
    Ok(())
}
impl InboxStore for PgInboxStore {
    fn lease_policy(&self) -> LeaseRenewalPolicy {
        self.policy
    }
    type Claim = PgInboxClaim;
    async fn claim(
        &self,
        identity: &ConsumerIdentity,
        deadline: OperationDeadline,
    ) -> Result<IdempotencyDisposition<Self::Claim>, MessagingError> {
        let identity = identity.clone();
        let lease_ms = self.lease_ms;
        settled(
            self.runtime
                .local_tx(identity.tenant_id(), deadline, move |tx| {
                    Box::pin(async move {
                        let row = sqlx::query(CLAIM_SQL)
                            .bind(identity.tenant_id().to_string())
                            .bind(identity.message_id().as_str())
                            .bind(identity.group().as_str())
                            .bind(contract_key(identity.contract())?)
                            .bind(lease_ms)
                            .fetch_optional(&mut *tx.connection)
                            .await?;
                        if let Some(row) = row {
                            return Ok(IdempotencyDisposition::Acquired(PgInboxClaim {
                                identity,
                                token: row.try_get("token")?,
                            }));
                        }
                        let row = read(tx, &identity).await?.ok_or_else(PgError::invariant)?;
                        Ok(match receipt(&row, &identity)? {
                            Some(value) => IdempotencyDisposition::Terminal(value),
                            None => IdempotencyDisposition::InProgress,
                        })
                    })
                })
                .await,
        )
        .map_err(PgError::port)
    }
    async fn read_terminal(
        &self,
        identity: &ConsumerIdentity,
        deadline: OperationDeadline,
    ) -> Result<Option<TerminalReceipt>, MessagingError> {
        let identity = identity.clone();
        settled(
            self.runtime
                .local_tx(identity.tenant_id(), deadline, move |tx| {
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
        let identity = claim.identity.clone();
        let token = claim.token.clone();
        let lease_ms = self.lease_ms;
        settled(self.runtime.local_tx(identity.tenant_id(), deadline, move |tx| Box::pin(async move {
            lock_identity(tx, &identity).await?;
            let remaining = sqlx::query_scalar::<_, i64>("UPDATE rss_transactional_messaging.inbox SET lease_until=clock_timestamp()+$5*interval '1 millisecond' WHERE tenant_id=$1::uuid AND message_id=$2 AND consumer_group=$3 AND lease_token=$4::uuid AND disposition IS NULL AND lease_until>clock_timestamp() RETURNING GREATEST(0,(extract(epoch FROM lease_until-clock_timestamp())*1000000)::bigint)")
                .bind(identity.tenant_id().to_string()).bind(identity.message_id().as_str()).bind(identity.group().as_str()).bind(token).bind(lease_ms)
                .fetch_optional(&mut *tx.connection).await?;
            Ok(match remaining { Some(value) => LeaseStatus::Held { remaining: Duration::from_micros(value.unsigned_abs()) }, None => LeaseStatus::Lost })
        })).await).map_err(PgError::port)
    }
    async fn release(
        &self,
        claim: Self::Claim,
        deadline: OperationDeadline,
    ) -> Result<(), MessagingError> {
        settled(self.runtime.local_tx(claim.identity.tenant_id(), deadline, move |tx| Box::pin(async move {
            lock_identity(tx, &claim.identity).await?;
            let count = sqlx::query("DELETE FROM rss_transactional_messaging.inbox WHERE tenant_id=$1::uuid AND message_id=$2 AND consumer_group=$3 AND lease_token=$4::uuid AND disposition IS NULL AND lease_until>clock_timestamp()")
                .bind(claim.identity.tenant_id().to_string()).bind(claim.identity.message_id().as_str()).bind(claim.identity.group().as_str()).bind(claim.token)
                .execute(&mut *tx.connection).await?.rows_affected();
            if count == 1 { Ok(()) } else { Err(PgError::lost()) }
        })).await).map_err(PgError::port)
    }
}

// DB time is sampled at the write; an expired claim is never resurrected by renew/release.
const CLAIM_SQL: &str = "INSERT INTO rss_transactional_messaging.inbox AS i
 (tenant_id,message_id,consumer_group,contract,lease_token,lease_until)
 VALUES ($1::uuid,$2,$3,$4,gen_random_uuid(),clock_timestamp()+$5*interval '1 millisecond')
 ON CONFLICT (tenant_id,message_id,consumer_group) DO UPDATE
 SET lease_token=gen_random_uuid(), lease_until=clock_timestamp()+$5*interval '1 millisecond', receive_count=i.receive_count+1
 WHERE i.disposition IS NULL AND i.lease_until<=clock_timestamp() AND i.contract=EXCLUDED.contract
 RETURNING lease_token::text AS token";

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
        for duration in [
            Duration::ZERO,
            Duration::from_nanos(1),
            Duration::from_secs(86401),
        ] {
            assert!(matches!(
                milliseconds(duration),
                Err(PgError::InvalidLeaseDuration)
            ));
        }
    }
}
