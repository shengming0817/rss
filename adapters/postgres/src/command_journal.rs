//! Postgres command persistence with random canonical ids and keyed alias rotation.

use consistency::idempotency::IdemKey;
use consistency::outbox::{OutboxPayload, StoredOutboxEntry};
use consistency::{
    CommandErrorSummary, CommandJournalOutcome, CommandJournalStatus,
    CommandJournalTerminalSummary, CommandRequestFingerprint, CommandResultSummary,
    OutboxAppendOutcome,
};
use diport::Clock;
use eventexec::command::{
    CommandAliasProbeSet, CommandDispatchStore, CommandJournalStore, CommandStoreError,
    ReviewedCommandDispatch, ReviewedCommandIntent, ReviewedCommandJournal,
};
use futures::future::BoxFuture;

#[cfg(all(test, feature = "integration"))]
use crate::PgStore;
use crate::cotx::{PgTenantWritePool, TxCapability, infra_tenant_scope};
use crate::outbox::{
    OutboxAppendError, OutboxEnvelope, append_outbox, metadata_with_ambient, unix_secs,
};
use crate::pool::VerifiedPgWriteStore;

#[cfg(all(test, feature = "integration"))]
impl PgStore {
    pub(crate) fn command_journal(&self, clock: Box<dyn Clock>) -> PgCommandJournal {
        PgCommandJournal {
            pool: PgTenantWritePool::from_unverified_for_test(self),
            clock,
        }
    }
}

/// Postgres command journal and direct-dispatch store.
pub struct PgCommandJournal {
    pool: PgTenantWritePool,
    clock: Box<dyn Clock>,
}

pub(crate) struct PreparedCommand {
    pub(crate) entry: StoredOutboxEntry,
    pub(crate) fingerprint: CommandRequestFingerprint,
}

impl PgCommandJournal {
    pub(crate) fn new(store: &VerifiedPgWriteStore, clock: Box<dyn Clock>) -> Self {
        Self {
            pool: PgTenantWritePool::new(store),
            clock,
        }
    }

    pub(crate) async fn record_command_with_business_write<F>(
        &self,
        command: ReviewedCommandJournal,
        business_write: F,
    ) -> Result<CommandJournalOutcome, CommandStoreError>
    where
        F: for<'c, 'tx> FnOnce(
                &'c mut TxCapability<'tx>,
            ) -> BoxFuture<
                'c,
                Result<CommandJournalTerminalSummary, CommandStoreError>,
            > + Send
            + 'static,
    {
        let (intent, envelope_parts) = command.into_parts();
        if intent.aliases().current().is_none() {
            return Err(CommandStoreError::internal(CommandAliasCurrentMissing));
        }
        let (contract, tenant, subject_id, actor, partition_key, causation_id) =
            envelope_parts.into_parts();
        let env = OutboxEnvelope::new(
            contract.domain().to_string(),
            contract.contract_id().to_string(),
            metadata_with_ambient(unix_secs(self.clock.now()), tenant, contract)
                .with_subject_id(subject_id)
                .with_actor(actor),
        )
        .with_partition_key_opt(partition_key)
        .with_causation_id_opt(causation_id);

        self.pool
            .write(
                infra_tenant_scope(tenant),
                move |tx| {
                    Box::pin(async move {
                        let prepared = prepare_command(tx, tenant, intent).await?;
                        if !insert_journal_claim(tx, tenant, &prepared, &env).await? {
                            return duplicate_outcome(
                                tx,
                                tenant,
                                prepared.entry.idem_key().as_str(),
                                &prepared.fingerprint,
                            )
                            .await;
                        }
                        match business_write(tx).await? {
                            CommandJournalTerminalSummary::Completed(result_summary) => {
                                append_or_match(tx, &prepared.entry, &env).await?;
                                mark_completed(
                                    tx,
                                    tenant,
                                    prepared.entry.idem_key().as_str(),
                                    result_summary,
                                )
                                .await?;
                            }
                            CommandJournalTerminalSummary::Failed(error_summary) => {
                                mark_failed(
                                    tx,
                                    tenant,
                                    prepared.entry.idem_key().as_str(),
                                    error_summary,
                                )
                                .await?;
                            }
                            _ => {
                                return Err(CommandStoreError::internal(
                                    CommandJournalUnknownTerminal,
                                ));
                            }
                        }
                        Ok(CommandJournalOutcome::Recorded)
                    })
                },
                map_sqlx_error,
            )
            .await
    }
}

impl CommandJournalStore for PgCommandJournal {
    async fn record_command(
        &self,
        command: ReviewedCommandJournal,
        result_summary: CommandResultSummary,
    ) -> Result<CommandJournalOutcome, CommandStoreError> {
        self.record_command_with_business_write(command, move |_tx| {
            Box::pin(async move { Ok(CommandJournalTerminalSummary::Completed(result_summary)) })
        })
        .await
    }
}

impl CommandDispatchStore for PgCommandJournal {
    async fn dispatch_command(
        &self,
        command: ReviewedCommandDispatch,
    ) -> Result<(), CommandStoreError> {
        let (intent, envelope_parts) = command.into_parts();
        let (contract, tenant, subject_id, actor, partition_key, causation_id) =
            envelope_parts.into_parts();
        let env = OutboxEnvelope::new(
            contract.domain().to_string(),
            contract.contract_id().to_string(),
            metadata_with_ambient(unix_secs(self.clock.now()), tenant, contract)
                .with_subject_id(subject_id)
                .with_actor(actor),
        )
        .with_partition_key_opt(partition_key)
        .with_causation_id_opt(causation_id);
        self.pool
            .write(
                infra_tenant_scope(tenant),
                move |tx| {
                    Box::pin(async move {
                        let prepared = prepare_command(tx, tenant, intent).await?;
                        append_or_match(tx, &prepared.entry, &env).await
                    })
                },
                map_sqlx_error,
            )
            .await
    }
}

pub(crate) async fn prepare_command(
    tx: &mut TxCapability<'_>,
    tenant: vocab::TenantId,
    intent: ReviewedCommandIntent,
) -> Result<PreparedCommand, CommandStoreError> {
    let (topic, payload, aliases, fingerprint) = intent.into_parts();
    let command_id = claim_command_identity(tx, tenant, topic, aliases).await?;
    let idem_key = IdemKey::parse(&command_id)
        .map_err(|_| CommandStoreError::internal(CommandCanonicalIdInvalid))?;
    let entry = StoredOutboxEntry::hydrate(
        topic,
        idem_key,
        OutboxPayload::from_reviewed_event_bytes(payload),
    )
    .map_err(|_| CommandStoreError::internal(CommandIntentInvalid))?;
    Ok(PreparedCommand { entry, fingerprint })
}

async fn claim_command_identity(
    tx: &mut TxCapability<'_>,
    tenant: vocab::TenantId,
    topic: &str,
    aliases: CommandAliasProbeSet,
) -> Result<String, CommandStoreError> {
    let (current, previous) = aliases.into_parts();
    let mut probes = Vec::with_capacity(previous.len() + usize::from(current.is_some()));
    if let Some(current) = current {
        probes.push(current.into_parts());
    }
    probes.extend(previous.into_iter().map(|probe| probe.into_parts()));
    if probes.is_empty() {
        return Ok(random_command_id());
    }
    if probes
        .iter()
        .any(|(key_id, digest)| key_id.trim().is_empty() || digest.len() != 32)
    {
        return Err(CommandStoreError::internal(CommandAliasInvalid));
    }

    let tenant_id = tenant.to_string();
    let mut canonical: Option<String> = None;
    for (key_id, digest) in &probes {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT command_id FROM command_idempotency_aliases \
             WHERE tenant_id = $1::uuid AND topic = $2 AND key_id = $3 \
               AND alias_digest = $4",
        )
        .bind(&tenant_id)
        .bind(topic)
        .bind(key_id)
        .bind(digest)
        .fetch_optional(tx.conn())
        .await
        .map_err(map_sqlx_error)?;
        if let Some((found,)) = row {
            match &canonical {
                Some(expected) if expected != &found => {
                    return Err(CommandStoreError::conflict(CommandAliasDiverged));
                }
                None => canonical = Some(found),
                Some(_) => {}
            }
        }
    }

    let mut canonical = canonical.unwrap_or_else(random_command_id);
    for (index, (key_id, digest)) in probes.iter().enumerate() {
        sqlx::query(
            "INSERT INTO command_idempotency_aliases \
             (tenant_id, topic, key_id, alias_digest, command_id) \
             VALUES ($1::uuid, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
        )
        .bind(&tenant_id)
        .bind(topic)
        .bind(key_id)
        .bind(digest)
        .bind(&canonical)
        .execute(tx.conn())
        .await
        .map_err(map_sqlx_error)?;
        let (persisted,): (String,) = sqlx::query_as(
            "SELECT command_id FROM command_idempotency_aliases \
             WHERE tenant_id = $1::uuid AND topic = $2 AND key_id = $3 \
               AND alias_digest = $4",
        )
        .bind(&tenant_id)
        .bind(topic)
        .bind(key_id)
        .bind(digest)
        .fetch_one(tx.conn())
        .await
        .map_err(map_sqlx_error)?;
        if persisted != canonical {
            if index == 0 {
                canonical = persisted;
            } else {
                return Err(CommandStoreError::conflict(CommandAliasDiverged));
            }
        }
    }
    Ok(canonical)
}

fn random_command_id() -> String {
    format!("command:v2:{}", uuid::Uuid::new_v4())
}

async fn insert_journal_claim(
    tx: &mut TxCapability<'_>,
    tenant: vocab::TenantId,
    prepared: &PreparedCommand,
    env: &OutboxEnvelope,
) -> Result<bool, CommandStoreError> {
    let result = sqlx::query(
        "INSERT INTO command_journal \
         (tenant_id, command_id, topic, contract_id, contract_version, schema_hash, \
          request_fingerprint, outbox_event_id, status, attempt, trace, correlation_id) \
         VALUES ($1::uuid,$2,$3,$4,$5,$6,$7,$2,$8,1,$9,$10) \
         ON CONFLICT (tenant_id, command_id) DO NOTHING",
    )
    .bind(tenant.to_string())
    .bind(prepared.entry.idem_key().as_str())
    .bind(prepared.entry.topic().as_str())
    .bind(env.contract_id())
    .bind(env.contract_version())
    .bind(env.schema_hash())
    .bind(prepared.fingerprint.as_str())
    .bind(CommandJournalStatus::InFlight.as_label())
    .bind(tracewire::capture())
    .bind(diagctx::correlation().map(|id| id.as_str().to_string()))
    .execute(tx.conn())
    .await
    .map_err(map_sqlx_error)?;
    Ok(result.rows_affected() == 1)
}

async fn duplicate_outcome(
    tx: &mut TxCapability<'_>,
    tenant: vocab::TenantId,
    command_id: &str,
    fingerprint: &CommandRequestFingerprint,
) -> Result<CommandJournalOutcome, CommandStoreError> {
    let row: Option<(String, String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT status, request_fingerprint, result_summary, error_summary \
         FROM command_journal WHERE tenant_id=$1::uuid AND command_id=$2 FOR UPDATE",
    )
    .bind(tenant.to_string())
    .bind(command_id)
    .fetch_optional(tx.conn())
    .await
    .map_err(map_sqlx_error)?;
    let Some((status, persisted, result, error)) = row else {
        return Err(CommandStoreError::internal(CommandJournalMissingDuplicate));
    };
    if persisted != fingerprint.as_str() {
        return Ok(CommandJournalOutcome::Conflict);
    }
    match status.as_str() {
        "in_flight" => Ok(CommandJournalOutcome::AlreadyInFlight),
        "completed" => result
            .as_deref()
            .and_then(CommandResultSummary::parse_persisted)
            .map(CommandJournalOutcome::AlreadyCompleted)
            .ok_or_else(|| CommandStoreError::internal(CommandJournalUnknownSummary)),
        "failed" => error
            .as_deref()
            .and_then(CommandErrorSummary::parse_persisted)
            .map(CommandJournalOutcome::AlreadyFailed)
            .ok_or_else(|| CommandStoreError::internal(CommandJournalUnknownSummary)),
        _ => Err(CommandStoreError::internal(CommandJournalUnknownStatus)),
    }
}

async fn append_or_match(
    tx: &mut TxCapability<'_>,
    entry: &StoredOutboxEntry,
    env: &OutboxEnvelope,
) -> Result<(), CommandStoreError> {
    match append_outbox(tx, entry, env)
        .await
        .map_err(map_append_error)?
    {
        OutboxAppendOutcome::Inserted | OutboxAppendOutcome::SameFact => Ok(()),
    }
}

async fn mark_completed(
    tx: &mut TxCapability<'_>,
    tenant: vocab::TenantId,
    command_id: &str,
    result_summary: CommandResultSummary,
) -> Result<(), CommandStoreError> {
    let result = sqlx::query(
        "UPDATE command_journal SET status=$3,result_summary=$4,error_summary=NULL,updated_at=now() \
         WHERE tenant_id=$1::uuid AND command_id=$2 AND status='in_flight'",
    ).bind(tenant.to_string()).bind(command_id)
        .bind(CommandJournalStatus::Completed.as_label()).bind(result_summary.as_str())
        .execute(tx.conn()).await.map_err(map_sqlx_error)?;
    if result.rows_affected() == 1 {
        Ok(())
    } else {
        Err(CommandStoreError::internal(CommandJournalStatusRace))
    }
}

async fn mark_failed(
    tx: &mut TxCapability<'_>,
    tenant: vocab::TenantId,
    command_id: &str,
    error_summary: CommandErrorSummary,
) -> Result<(), CommandStoreError> {
    let result = sqlx::query(
        "UPDATE command_journal SET status=$3,result_summary=NULL,error_summary=$4,updated_at=now() \
         WHERE tenant_id=$1::uuid AND command_id=$2 AND status='in_flight'",
    ).bind(tenant.to_string()).bind(command_id)
        .bind(CommandJournalStatus::Failed.as_label()).bind(error_summary.as_str())
        .execute(tx.conn()).await.map_err(map_sqlx_error)?;
    if result.rows_affected() == 1 {
        Ok(())
    } else {
        Err(CommandStoreError::internal(CommandJournalStatusRace))
    }
}

fn map_append_error(error: OutboxAppendError) -> CommandStoreError {
    match error {
        OutboxAppendError::Conflict(conflict) => CommandStoreError::conflict(conflict),
        OutboxAppendError::Storage(error) => map_sqlx_error(error),
        other => CommandStoreError::internal(other),
    }
}

fn map_sqlx_error(error: sqlx::Error) -> CommandStoreError {
    let unavailable = match &error {
        sqlx::Error::PoolTimedOut
        | sqlx::Error::PoolClosed
        | sqlx::Error::Io(_)
        | sqlx::Error::Tls(_) => true,
        sqlx::Error::Database(database) => database.code().is_some_and(|code| {
            code.starts_with("08") || matches!(code.as_ref(), "40001" | "40P01" | "53" | "57P01")
        }),
        _ => false,
    };
    if unavailable {
        CommandStoreError::unavailable(error)
    } else {
        CommandStoreError::internal(error)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("command alias current probe missing")]
struct CommandAliasCurrentMissing;
#[derive(Debug, thiserror::Error)]
#[error("command alias probe is invalid")]
struct CommandAliasInvalid;
#[derive(Debug, thiserror::Error)]
#[error("command aliases disagree on canonical id")]
struct CommandAliasDiverged;
#[derive(Debug, thiserror::Error)]
#[error("canonical command id is invalid")]
struct CommandCanonicalIdInvalid;
#[derive(Debug, thiserror::Error)]
#[error("reviewed command intent is invalid")]
struct CommandIntentInvalid;
#[derive(Debug, thiserror::Error)]
#[error("command journal duplicate row missing")]
struct CommandJournalMissingDuplicate;
#[derive(Debug, thiserror::Error)]
#[error("command journal persisted summary is unknown")]
struct CommandJournalUnknownSummary;
#[derive(Debug, thiserror::Error)]
#[error("command journal terminal outcome is unknown")]
struct CommandJournalUnknownTerminal;
#[derive(Debug, thiserror::Error)]
#[error("command journal persisted status is unknown")]
struct CommandJournalUnknownStatus;
#[derive(Debug, thiserror::Error)]
#[error("command journal status changed before completion")]
struct CommandJournalStatusRace;
#[cfg(test)]
mod tests {
    #[test]
    fn command_alias_migration_is_v2_and_rejects_legacy_rows() {
        const MIGRATION: &str = include_str!("../migrations/0053_command_alias_v2.sql");
        assert!(MIGRATION.contains("command_idempotency_aliases"));
        assert!(MIGRATION.contains("command:v2:"));
        assert!(MIGRATION.contains("must be empty before enabling command aliases v2"));
        assert!(!MIGRATION.contains("command:v1:sha256:[0-9a-f]{64}$')"));
    }
}
