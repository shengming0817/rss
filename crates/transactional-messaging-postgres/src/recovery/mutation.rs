use super::map_attempt;
use crate::{PgError, PgRuntime, PgTransaction, outbox::append_message};
use rss_data_protection::Aead;
use rss_transactional_messaging::{
    inbox::{ConsumerGroup, ConsumerIdentity},
    message::{ContractIdentity, MessageEnvelope, MessageFingerprint, MessageId},
    outbox::{AppendOutcome, PendingMessage},
    policy::OperationDeadline,
    transaction::LocalTxAttempt,
};
use rss_transactional_messaging_recovery::{
    Action, Error, Mutation, Outcome, Receipt, Resolution, Target, Version,
    protection::{Capsule, CaptureContext, open},
};
use sqlx::{Row, postgres::PgRow};

pub(super) async fn mutate<K: Aead + Send + Sync>(
    runtime: &PgRuntime,
    key: &K,
    request: &Mutation,
    deadline: OperationDeadline,
) -> LocalTxAttempt<Receipt, Error> {
    let result = runtime
        .local_tx_with_context(
            request.tenant(),
            deadline,
            (key, request),
            |(key, request), tx| {
                Box::pin(async move {
                    // A transaction-scoped advisory lock serializes identical operation IDs even before a receipt exists.
                    // Hash collisions only serialize unrelated requests; they never share receipt identities.
                    let lock = format!("{}:{}", request.tenant(), request.operation());
                    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
                        .bind(lock)
                        .execute(&mut *tx.connection)
                        .await?;
                    if let Some(receipt) = read_receipt(tx, request).await? {
                        return Ok(receipt);
                    }
                    let receipt = match request.action() {
                        Action::Replay(id) => replay(tx, *key, request, id).await?,
                        Action::Redrive | Action::Resolve(_) => transition(tx, request).await?,
                    };
                    write_receipt(tx, &receipt).await?;
                    Ok(receipt)
                })
            },
        )
        .await;
    map_attempt(result)
}
pub(super) async fn read_receipt(
    tx: &mut PgTransaction<'_>,
    request: &Mutation,
) -> Result<Option<Receipt>, PgError> {
    let row = sqlx::query("SELECT request_digest,outcome,result_version FROM rss_transactional_messaging.recovery_operations WHERE tenant_id=$1::uuid AND operation_id=$2::uuid")
        .bind(request.tenant().to_string()).bind(request.operation().to_string()).fetch_optional(&mut *tx.connection).await?;
    row.map(|row| {
        let digest: Vec<u8> = row.try_get("request_digest")?;
        if digest != request.digest() {
            return Err(Error::Conflict.into());
        }
        let outcome = match row.try_get::<&str, _>("outcome")? {
            "replayed" => Outcome::Replayed,
            "redriven" => Outcome::Redriven,
            "resolved" => Outcome::Resolved,
            _ => {
                return Err(Error::Store(
                    rss_transactional_messaging_recovery::StoreFailureKind::Invariant,
                )
                .into());
            }
        };
        Ok(Receipt {
            request: request.clone(),
            outcome,
            version: Version::new(row.try_get("result_version")?)?,
        })
    })
    .transpose()
}
async fn write_receipt(tx: &mut PgTransaction<'_>, receipt: &Receipt) -> Result<(), PgError> {
    let request = &receipt.request;
    let (outcome, replay, resolution, evidence) = match request.action() {
        Action::Replay(id) => ("replayed", Some(id.as_str()), None, None),
        Action::Redrive => ("redriven", None, None, None),
        Action::Resolve(Resolution::AcceptedGap) => ("resolved", None, Some("accepted_gap"), None),
        Action::Resolve(Resolution::Compensated(id)) => {
            ("resolved", None, Some("compensated"), Some(id.as_str()))
        }
    };
    sqlx::query("INSERT INTO rss_transactional_messaging.recovery_operations (tenant_id,operation_id,request_digest,target_kind,target_key,outcome,result_version,replay_message_id,resolution,evidence_message_id) VALUES ($1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8,$9,$10)")
        .bind(request.tenant().to_string()).bind(request.operation().to_string()).bind(request.digest().as_slice()).bind(request.target().kind()).bind(request.target().key()).bind(outcome).bind(receipt.version.get()).bind(replay).bind(resolution).bind(evidence).execute(&mut *tx.connection).await?;
    Ok(())
}
fn next_version(row: &PgRow, request: &Mutation) -> Result<Version, PgError> {
    let current: i64 = row.try_get("recovery_version")?;
    if current != request.version().get() {
        return Err(Error::Conflict.into());
    }
    Ok(Version::new(
        current.checked_add(1).ok_or(Error::Conflict)?,
    )?)
}
async fn replay<K: Aead>(
    tx: &mut PgTransaction<'_>,
    key: &K,
    request: &Mutation,
    new_id: &MessageId,
) -> Result<Receipt, PgError> {
    let Target::DeadLetter(id) = request.target() else {
        return Err(Error::Invalid.into());
    };
    let row = sqlx::query("SELECT message_id,consumer_group,contract,contract_version,schema_digest,fingerprint,capsule,recovery_version FROM rss_transactional_messaging.consumer_dead_letter WHERE tenant_id=$1::uuid AND id=$2::uuid FOR UPDATE")
        .bind(request.tenant().to_string()).bind(id.to_string()).fetch_optional(&mut *tx.connection).await?.ok_or(Error::NotFound)?;
    let version = next_version(&row, request)?;
    let message_id = MessageId::parse(&row.try_get::<String, _>("message_id")?)
        .map_err(|_| Error::Protection)?;
    if &message_id == new_id {
        return Err(Error::Invalid.into());
    }
    let context = capture_context(&row, request, message_id)?;
    let capsule = Capsule::from_provider(
        row.try_get::<Option<Vec<u8>>, _>("capsule")?
            .ok_or(Error::Archived)?,
    )?;
    let original = open(key, &context, &capsule)?;
    let replay = MessageEnvelope::new(
        new_id.clone(),
        original.metadata().clone(),
        original.payload(),
    );
    let pending = PendingMessage::new(replay);
    let appended = append_message(tx, original.metadata().domain(), pending)
        .await
        .map_err(|e| PgError::classified(e.kind(), e))?;
    if appended == AppendOutcome::AlreadyPresent {
        // Exact operation retries were handled by read_receipt before executing this transition.
        return Err(Error::Conflict.into());
    }
    sqlx::query("UPDATE rss_transactional_messaging.consumer_dead_letter SET recovery_version=$3 WHERE tenant_id=$1::uuid AND id=$2::uuid")
        .bind(request.tenant().to_string()).bind(id.to_string()).bind(version.get()).execute(&mut *tx.connection).await?;
    Ok(Receipt {
        request: request.clone(),
        outcome: Outcome::Replayed,
        version,
    })
}
fn capture_context(
    row: &PgRow,
    request: &Mutation,
    message: MessageId,
) -> Result<CaptureContext, PgError> {
    let Target::DeadLetter(id) = request.target() else {
        return Err(Error::Invalid.into());
    };
    let contract = ContractIdentity::new(
        rss_contract::ContractId::parse(&row.try_get::<String, _>("contract")?)
            .map_err(|_| Error::Protection)?,
        rss_contract::ContractVersion::parse(&row.try_get::<String, _>("contract_version")?)
            .map_err(|_| Error::Protection)?,
        rss_contract::SchemaDigest::parse(&row.try_get::<String, _>("schema_digest")?)
            .map_err(|_| Error::Protection)?,
    );
    let group = ConsumerGroup::parse(&row.try_get::<String, _>("consumer_group")?)
        .map_err(|_| Error::Protection)?;
    let identity = ConsumerIdentity::new(request.tenant(), group, message, contract);
    let bytes: Vec<u8> = row.try_get("fingerprint")?;
    let digest: [u8; 32] = bytes.try_into().map_err(|_| Error::Protection)?;
    Ok(CaptureContext::from_provider(
        *id,
        identity,
        MessageFingerprint::from_bytes(digest),
    ))
}
async fn transition(tx: &mut PgTransaction<'_>, request: &Mutation) -> Result<Receipt, PgError> {
    let Target::Outbox(id) = request.target() else {
        return Err(Error::Invalid.into());
    };
    let row = sqlx::query("SELECT status,recovery_version FROM rss_transactional_messaging.outbox WHERE tenant_id=$1::uuid AND message_id=$2 FOR UPDATE")
        .bind(request.tenant().to_string()).bind(id.as_str()).fetch_optional(&mut *tx.connection).await?.ok_or(Error::NotFound)?;
    let version = next_version(&row, request)?;
    if row.try_get::<&str, _>("status")? != "dead_letter" {
        return Err(Error::Conflict.into());
    }
    // Sample DB time only after acquiring the target lock; a lock wait cannot extend the window.
    let clock = sqlx::query("SELECT (extract(epoch FROM automatic_retry_deadline)*1000000)::bigint AS deadline, (extract(epoch FROM clock_timestamp())*1000000)::bigint AS observed FROM rss_transactional_messaging.outbox WHERE tenant_id=$1::uuid AND message_id=$2")
        .bind(request.tenant().to_string()).bind(id.as_str()).fetch_one(&mut *tx.connection).await?;
    let expired = window_expired(clock.try_get("deadline")?, clock.try_get("observed")?)?;
    let (status, outcome) = match request.action() {
        Action::Redrive if expired => return Err(Error::Expired.into()),
        Action::Redrive => ("pending", Outcome::Redriven),
        Action::Resolve(resolution) => {
            if !expired {
                return Err(Error::NotExpired.into());
            }
            if let Resolution::Compensated(evidence) = resolution {
                validate_evidence(tx, request, evidence).await?;
            }
            ("resolved", Outcome::Resolved)
        }
        _ => return Err(Error::Invalid.into()),
    };
    let changed = sqlx::query("UPDATE rss_transactional_messaging.outbox SET status=$3,recovery_version=$4,lease_token=NULL,lease_until=NULL,retry_after=clock_timestamp() WHERE tenant_id=$1::uuid AND message_id=$2 AND (($3='pending' AND automatic_retry_deadline>clock_timestamp()) OR ($3='resolved' AND automatic_retry_deadline<=clock_timestamp()))")
        .bind(request.tenant().to_string()).bind(id.as_str()).bind(status).bind(version.get()).execute(&mut *tx.connection).await?;
    if changed.rows_affected() != 1 {
        return Err(Error::Expired.into());
    }
    Ok(Receipt {
        request: request.clone(),
        outcome,
        version,
    })
}
async fn validate_evidence(
    tx: &mut PgTransaction<'_>,
    request: &Mutation,
    evidence: &MessageId,
) -> Result<(), PgError> {
    let row = sqlx::query("SELECT status,envelope::text,fingerprint FROM rss_transactional_messaging.outbox WHERE tenant_id=$1::uuid AND message_id=$2 FOR SHARE")
        .bind(request.tenant().to_string()).bind(evidence.as_str()).fetch_optional(&mut *tx.connection).await?.ok_or(Error::Evidence)?;
    if row.try_get::<&str, _>("status")? != "published" {
        return Err(Error::Evidence.into());
    }
    let envelope = crate::envelope::Envelope::decode(&row.try_get::<String, _>("envelope")?)?;
    let digest: Vec<u8> = row.try_get("fingerprint")?;
    if envelope.id() != evidence
        || envelope.metadata().tenant_id() != request.tenant()
        || envelope.metadata().causation().map(MessageId::as_str)
            != Some(request.target().key().as_str())
        || digest != MessageFingerprint::of(&envelope).as_bytes()
    {
        return Err(Error::Evidence.into());
    }
    Ok(())
}

fn window_expired(deadline: Option<i64>, observed: i64) -> Result<bool, PgError> {
    Ok(deadline.ok_or(Error::Conflict)? <= observed)
}
#[cfg(test)]
mod tests {
    #[test]
    #[allow(clippy::expect_used)] // reason: exact database-microsecond boundary fixtures.
    fn same_id_window_is_closed_at_equality() {
        assert!(!super::window_expired(Some(10), 9).expect("before"));
        assert!(super::window_expired(Some(10), 10).expect("equal"));
        assert!(super::window_expired(Some(10), 11).expect("after"));
        assert!(super::window_expired(None, 10).is_err());
    }
}
