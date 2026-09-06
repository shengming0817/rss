use super::map_attempt;
use crate::{PgError, PgRuntime};
use rss_transactional_messaging::message::MessageId;
use rss_transactional_messaging::policy::OperationDeadline;
use rss_transactional_messaging_recovery::{
    ConsumerDetails, DeadLetterId, Details, Eligibility, Entry, Error, OutboxDetails, Page, Query,
    Source, Target, Version,
};
use sqlx::Row;

pub(super) async fn query(
    runtime: &PgRuntime,
    request: &Query,
    deadline: OperationDeadline,
) -> Result<Page, Error> {
    let result = runtime.local_tx_with_context(request.tenant(), deadline, request, |request, tx| Box::pin(async move {
        let sql = match request.source() {
            Source::Consumer => "SELECT capsule IS NOT NULL AS hot_available, id::text AS key, message_id, recovery_version, false AS resolved, consumer_group,contract,contract_version,schema_digest,reason,(extract(epoch FROM created_at)*1000000)::bigint AS captured_at, (SELECT count(*) FROM rss_transactional_messaging.recovery_operations o WHERE o.tenant_id=d.tenant_id AND o.target_kind='consumer' AND o.target_key=d.id::text AND o.outcome='replayed') AS replay_count, (SELECT replay_message_id FROM rss_transactional_messaging.recovery_operations o WHERE o.tenant_id=d.tenant_id AND o.target_kind='consumer' AND o.target_key=d.id::text AND o.outcome='replayed' ORDER BY created_at DESC,operation_id DESC LIMIT 1) AS last_replay FROM rss_transactional_messaging.consumer_dead_letter d WHERE tenant_id=$1::uuid AND ($2::text IS NULL OR id::text COLLATE \"C\" > $2 COLLATE \"C\") AND ($3::text IS NULL OR id::text=$3) ORDER BY id::text COLLATE \"C\" LIMIT $4",
            Source::Outbox => "SELECT message_id AS key, message_id, recovery_version, status='resolved' AS resolved, envelope::text,fingerprint,(extract(epoch FROM automatic_retry_deadline)*1000000)::bigint AS deadline, automatic_retry_deadline<=clock_timestamp() AS expired FROM rss_transactional_messaging.outbox WHERE tenant_id=$1::uuid AND status IN ('dead_letter','resolved') AND ($2::text IS NULL OR message_id COLLATE \"C\" > $2 COLLATE \"C\") AND ($3::text IS NULL OR message_id=$3) ORDER BY message_id COLLATE \"C\" LIMIT $4",
        };
        let rows = sqlx::query(sql).bind(request.tenant().to_string()).bind(request.after()).bind(request.target().map(Target::key)).bind(i64::from(request.limit())+1).fetch_all(&mut *tx.connection).await?;
        let has_more = rows.len() > usize::from(request.limit());
        let mut entries = Vec::new();
        let mut last = None;
        for row in rows.into_iter().take(usize::from(request.limit())) {
            let key: String = row.try_get("key")?;
            let target = match request.source() {
                Source::Consumer => Target::DeadLetter(DeadLetterId::parse(&key)?),
                Source::Outbox => Target::Outbox(MessageId::parse(&key).map_err(|_| Error::Invalid)?),
            };
            let details = details(&row, request)?;
            entries.push(Entry {
                details, target, version: Version::new(row.try_get("recovery_version")?)?, message: MessageId::parse(&row.try_get::<String,_>("message_id")?).map_err(|_| Error::Invalid)? });
            last = Some(key);
        }
        Ok::<_, PgError>(Page { entries, next_cursor: if has_more { last.map(|key| request.cursor(&key)) } else { None } })
    })).await;
    map_attempt(result).fold(Ok, Err, Err, Err, Err, Err)
}

fn details(row: &sqlx::postgres::PgRow, request: &Query) -> Result<Details, PgError> {
    use rss_transactional_messaging::{
        inbox::ConsumerGroup,
        message::{ContractIdentity, MessageFingerprint},
        transaction::RejectKind,
    };
    match request.source() {
        Source::Consumer => {
            let reason = match row.try_get::<&str, _>("reason")? {
                "rejected_permanent" => RejectKind::Permanent,
                "rejected_invariant" => RejectKind::Invariant,
                _ => return Err(Error::StorageContract.into()),
            };
            let contract = ContractIdentity::new(
                rss_contract::ContractId::parse(&row.try_get::<String, _>("contract")?)
                    .map_err(|_| Error::StorageContract)?,
                rss_contract::ContractVersion::parse(
                    &row.try_get::<String, _>("contract_version")?,
                )
                .map_err(|_| Error::StorageContract)?,
                rss_contract::SchemaDigest::parse(&row.try_get::<String, _>("schema_digest")?)
                    .map_err(|_| Error::StorageContract)?,
            );
            Ok(Details::Consumer(ConsumerDetails {
                hot_available: row.try_get("hot_available")?,
                group: ConsumerGroup::parse(&row.try_get::<String, _>("consumer_group")?)
                    .map_err(|_| Error::StorageContract)?,
                contract,
                reason,
                captured_at_unix_micros: row.try_get("captured_at")?,
                replay_count: u64::try_from(row.try_get::<i64, _>("replay_count")?)
                    .map_err(|_| Error::StorageContract)?,
                last_replay: row
                    .try_get::<Option<String>, _>("last_replay")?
                    .map(|id| MessageId::parse(&id).map_err(|_| Error::StorageContract))
                    .transpose()?,
            }))
        }
        Source::Outbox => {
            let envelope =
                crate::envelope::Envelope::decode(&row.try_get::<String, _>("envelope")?)?;
            let fingerprint: Vec<u8> = row.try_get("fingerprint")?;
            if envelope.metadata().tenant_id() != request.tenant()
                || envelope.id().as_str() != row.try_get::<&str, _>("message_id")?
                || fingerprint != MessageFingerprint::of(&envelope).as_bytes()
            {
                return Err(Error::Conflict.into());
            }
            let deadline = row.try_get("deadline")?;
            let eligibility = if row.try_get("resolved")? {
                Eligibility::Resolved
            } else {
                match row.try_get::<Option<bool>, _>("expired")? {
                    None => Eligibility::NoWindow,
                    Some(true) => Eligibility::Expired,
                    Some(false) => Eligibility::WithinWindow,
                }
            };
            Ok(Details::Outbox(OutboxDetails {
                domain: envelope.metadata().domain().clone(),
                route: envelope.metadata().route().clone(),
                contract: envelope.metadata().contract().clone(),
                deadline_unix_micros: deadline,
                eligibility,
            }))
        }
    }
}
