//! Postgres command persistence with random canonical ids and keyed alias rotation.

use consistency::idempotency::IdemKey;
use consistency::outbox::{OutboxPayload, StoredOutboxEntry};
use consistency::{
    CommandErrorSummary, CommandJournalOutcome, CommandJournalTerminalSummary,
    CommandRequestFingerprint, CommandResultSummary, OutboxAppendOutcome,
};
use diport::Clock;
use eventexec::command::{
    CommandAliasProbeSet, CommandDispatchStore, CommandJournalStore, CommandStoreError,
    ReviewedCommandDispatch, ReviewedCommandIntent, ReviewedCommandJournal,
};
use futures::future::BoxFuture;

#[cfg(all(test, feature = "integration"))]
use crate::PgStore;
use crate::cotx::eventing::{CommandAliasClaim, CommandAliasKey, CommandTerminalUpdate, CommandTx};
use crate::cotx::{ServingWriteLane, TenantDb, infra_tenant_scope};
use crate::outbox::{OutboxAppendError, OutboxEnvelope, append_outbox, metadata_with_ambient};
use crate::pool::VerifiedPgWriteStore;

#[cfg(all(test, feature = "integration"))]
impl PgStore {
    pub(crate) fn command_journal(&self, clock: Box<dyn Clock>) -> PgCommandJournal {
        PgCommandJournal {
            pool: TenantDb::<ServingWriteLane>::from_unverified_for_test(self),
            clock,
        }
    }
}

/// Postgres command journal and direct-dispatch store.
pub struct PgCommandJournal {
    pool: TenantDb<ServingWriteLane>,
    clock: Box<dyn Clock>,
}

pub(crate) struct PreparedCommand {
    pub(crate) entry: StoredOutboxEntry,
    pub(crate) fingerprint: CommandRequestFingerprint,
}

impl PgCommandJournal {
    pub(crate) fn new(store: &VerifiedPgWriteStore, clock: Box<dyn Clock>) -> Self {
        Self {
            pool: TenantDb::<ServingWriteLane>::new(store),
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
                &'c mut CommandTx<'tx>,
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
            metadata_with_ambient(
                rss_contract::Timepoint::saturating_from_system_time(self.clock.now())
                    .unix_seconds(),
                tenant,
                contract,
            )
            .with_subject_id(subject_id)
            .with_actor(actor),
        )
        .with_partition_key_opt(partition_key)
        .with_causation_id_opt(causation_id);

        self.pool
            .command_write(
                infra_tenant_scope(tenant),
                move |mut tx| {
                    Box::pin(async move {
                        let prepared = prepare_command(&mut tx, intent).await?;
                        if !insert_journal_claim(&mut tx, &prepared, &env).await? {
                            return duplicate_outcome(
                                &mut tx,
                                prepared.entry.idem_key().as_str(),
                                &prepared.fingerprint,
                            )
                            .await;
                        }
                        match business_write(&mut tx).await? {
                            CommandJournalTerminalSummary::Completed(result_summary) => {
                                append_or_match(&mut tx, &prepared.entry, &env).await?;
                                mark_completed(
                                    &mut tx,
                                    prepared.entry.idem_key().as_str(),
                                    result_summary,
                                )
                                .await?;
                            }
                            CommandJournalTerminalSummary::Failed(error_summary) => {
                                mark_failed(
                                    &mut tx,
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
            metadata_with_ambient(
                rss_contract::Timepoint::saturating_from_system_time(self.clock.now())
                    .unix_seconds(),
                tenant,
                contract,
            )
            .with_subject_id(subject_id)
            .with_actor(actor),
        )
        .with_partition_key_opt(partition_key)
        .with_causation_id_opt(causation_id);
        self.pool
            .command_write(
                infra_tenant_scope(tenant),
                move |mut tx| {
                    Box::pin(async move {
                        let prepared = prepare_command(&mut tx, intent).await?;
                        append_or_match(&mut tx, &prepared.entry, &env).await
                    })
                },
                map_sqlx_error,
            )
            .await
    }
}

pub(crate) async fn prepare_command(
    tx: &mut CommandTx<'_>,
    intent: ReviewedCommandIntent,
) -> Result<PreparedCommand, CommandStoreError> {
    let (topic, payload, aliases, fingerprint) = intent.into_parts();
    let command_id = claim_command_identity(tx, topic, aliases).await?;
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
    tx: &mut CommandTx<'_>,
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

    let mut canonical: Option<String> = None;
    for (key_id, digest) in &probes {
        let row = tx
            .command_find_alias(CommandAliasKey {
                topic,
                key_id,
                digest,
            })
            .await
            .map_err(map_sqlx_error)?;
        if let Some(found) = row {
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
        let persisted = tx
            .command_claim_alias(CommandAliasClaim {
                key: CommandAliasKey {
                    topic,
                    key_id,
                    digest,
                },
                command_id: &canonical,
            })
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

pub(crate) async fn insert_journal_claim(
    tx: &mut CommandTx<'_>,
    prepared: &PreparedCommand,
    env: &OutboxEnvelope,
) -> Result<bool, CommandStoreError> {
    tx.command_insert_journal_claim(prepared, env)
        .await
        .map_err(map_sqlx_error)
}

pub(crate) async fn duplicate_outcome(
    tx: &mut CommandTx<'_>,
    command_id: &str,
    fingerprint: &CommandRequestFingerprint,
) -> Result<CommandJournalOutcome, CommandStoreError> {
    let Some(row) = tx
        .command_load_journal_for_update(command_id)
        .await
        .map_err(map_sqlx_error)?
    else {
        return Err(CommandStoreError::internal(CommandJournalMissingDuplicate));
    };
    if row.request_fingerprint != fingerprint.as_str() {
        return Ok(CommandJournalOutcome::Conflict);
    }
    match row.status.as_str() {
        "in_flight" => Ok(CommandJournalOutcome::AlreadyInFlight),
        "completed" => row
            .result_summary
            .as_deref()
            .and_then(CommandResultSummary::parse_persisted)
            .map(CommandJournalOutcome::AlreadyCompleted)
            .ok_or_else(|| CommandStoreError::internal(CommandJournalUnknownSummary)),
        "failed" => row
            .error_summary
            .as_deref()
            .and_then(CommandErrorSummary::parse_persisted)
            .map(CommandJournalOutcome::AlreadyFailed)
            .ok_or_else(|| CommandStoreError::internal(CommandJournalUnknownSummary)),
        _ => Err(CommandStoreError::internal(CommandJournalUnknownStatus)),
    }
}

async fn append_or_match(
    tx: &mut CommandTx<'_>,
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
    tx: &mut CommandTx<'_>,
    command_id: &str,
    result_summary: CommandResultSummary,
) -> Result<(), CommandStoreError> {
    if tx
        .command_settle_journal(
            command_id,
            CommandTerminalUpdate::Completed(&result_summary),
        )
        .await
        .map_err(map_sqlx_error)?
    {
        Ok(())
    } else {
        Err(CommandStoreError::internal(CommandJournalStatusRace))
    }
}

async fn mark_failed(
    tx: &mut CommandTx<'_>,
    command_id: &str,
    error_summary: CommandErrorSummary,
) -> Result<(), CommandStoreError> {
    if tx
        .command_settle_journal(command_id, CommandTerminalUpdate::Failed(&error_summary))
        .await
        .map_err(map_sqlx_error)?
    {
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
