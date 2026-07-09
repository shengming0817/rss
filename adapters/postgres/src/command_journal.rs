//! Postgres command journal foundation (#1441).
//!
//! This adapter owns producer-side command idempotency storage. It records command intent,
//! executes an optional local business write, appends the command outbox row, then marks the
//! journal completed in one tenant-scoped transaction.

use consistency::{
    CommandErrorSummary, CommandJournalOutcome, CommandJournalRecord, CommandJournalStatus,
    CommandJournalTerminalSummary, CommandResultSummary,
};
use diport::Clock;
use eventexec::command::{CommandJournalError, CommandJournalStore, ReviewedCommandJournal};
use futures::future::BoxFuture;

use crate::PgStore;
use crate::cotx::{PgTenantPool, TxCapability, infra_tenant_scope};
use crate::outbox::{
    OutboxAppendOutcome, OutboxEnvelope, append_outbox, metadata_with_ambient, unix_secs,
};

impl PgStore {
    /// Construct the command journal store from the shared pool with an injected producer clock.
    pub(crate) fn command_journal(&self, clock: Box<dyn Clock>) -> PgCommandJournal {
        PgCommandJournal {
            pool: PgTenantPool::new(self),
            clock,
        }
    }
}

/// Postgres command journal store.
pub struct PgCommandJournal {
    pool: PgTenantPool,
    clock: Box<dyn Clock>,
}

impl PgCommandJournal {
    /// Record a command with an extra business write in the same transaction.
    pub(crate) async fn record_command_with_business_write<F>(
        &self,
        command: ReviewedCommandJournal,
        business_write: F,
    ) -> Result<CommandJournalOutcome, CommandJournalError>
    where
        F: for<'c, 'tx> FnOnce(
                &'c mut TxCapability<'tx>,
            ) -> BoxFuture<
                'c,
                Result<CommandJournalTerminalSummary, CommandJournalError>,
            > + Send
            + 'static,
    {
        let (journal, entry, envelope_parts) = command.into_parts();
        let (contract, command_tenant, subject_id, actor, partition_key, causation_id) =
            envelope_parts.into_parts();
        if command_tenant != journal.tenant() {
            return Err(CommandJournalError::new(CommandJournalTenantMismatch));
        }
        let env = OutboxEnvelope::new(
            contract.domain().to_string(),
            contract.contract_id().to_string(),
            metadata_with_ambient(unix_secs(self.clock.now()), command_tenant, contract)
                .with_subject_id(subject_id)
                .with_actor(actor),
        )
        .with_partition_key_opt(partition_key)
        .with_causation_id_opt(causation_id);
        let tenant = journal.tenant();
        self.pool
            .write(
                infra_tenant_scope(tenant),
                move |tx| {
                    Box::pin(async move {
                        if !insert_journal_claim(tx, &journal, &entry, &env).await? {
                            return duplicate_outcome(tx, &journal).await;
                        }
                        match business_write(tx).await? {
                            CommandJournalTerminalSummary::Completed(result_summary) => {
                                match append_outbox(tx, &entry, &env)
                                    .await
                                    .map_err(CommandJournalError::new)?
                                {
                                    OutboxAppendOutcome::Inserted => {}
                                    OutboxAppendOutcome::AlreadyExists => {
                                        ensure_existing_outbox_matches(tx, &entry, &env).await?;
                                    }
                                }
                                mark_completed(tx, &journal, result_summary).await?;
                            }
                            CommandJournalTerminalSummary::Failed(error_summary) => {
                                mark_failed(tx, &journal, error_summary).await?;
                            }
                            _ => {
                                return Err(CommandJournalError::new(
                                    CommandJournalUnknownTerminal,
                                ));
                            }
                        }
                        Ok(CommandJournalOutcome::Recorded)
                    })
                },
                CommandJournalError::new,
            )
            .await
    }
}

impl CommandJournalStore for PgCommandJournal {
    async fn record_command(
        &self,
        command: ReviewedCommandJournal,
        result_summary: CommandResultSummary,
    ) -> Result<CommandJournalOutcome, CommandJournalError> {
        self.record_command_with_business_write(command, move |_tx| {
            Box::pin(async move { Ok(CommandJournalTerminalSummary::Completed(result_summary)) })
        })
        .await
    }
}

async fn insert_journal_claim(
    tx: &mut TxCapability<'_>,
    journal: &CommandJournalRecord,
    entry: &consistency::outbox::Entry,
    env: &OutboxEnvelope,
) -> Result<bool, CommandJournalError> {
    let trace = tracewire::capture();
    let correlation = diagctx::correlation().map(|id| id.as_str().to_string());
    let result = sqlx::query(
        r#"
        INSERT INTO command_journal (
            tenant_id, command_id, idempotency_key, topic, contract_id, contract_version,
            schema_hash, request_fingerprint, outbox_event_id, status, attempt,
            trace, correlation_id
        )
        VALUES (
            $1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, 1, $11, $12
        )
        ON CONFLICT (tenant_id, command_id) DO NOTHING
        "#,
    )
    .bind(journal.tenant().to_string())
    .bind(journal.command_id().as_str())
    .bind(journal.idempotency_key().as_str())
    .bind(entry.topic().as_str())
    .bind(env.contract_id())
    .bind(env.contract_version())
    .bind(env.schema_hash())
    .bind(journal.request_fingerprint().as_str())
    .bind(entry.idem_key().as_str())
    .bind(CommandJournalStatus::InFlight.as_label())
    .bind(trace)
    .bind(correlation)
    .execute(tx.conn())
    .await
    .map_err(CommandJournalError::new)?;
    Ok(result.rows_affected() == 1)
}

async fn duplicate_outcome(
    tx: &mut TxCapability<'_>,
    journal: &CommandJournalRecord,
) -> Result<CommandJournalOutcome, CommandJournalError> {
    let row: Option<(String, String, Option<String>, Option<String>)> = sqlx::query_as(
        r#"
        SELECT status, request_fingerprint, result_summary, error_summary
        FROM command_journal
        WHERE tenant_id = $1::uuid
          AND command_id = $2
        FOR UPDATE
        "#,
    )
    .bind(journal.tenant().to_string())
    .bind(journal.command_id().as_str())
    .fetch_optional(tx.conn())
    .await
    .map_err(CommandJournalError::new)?;

    let Some((status, fingerprint, result_summary, error_summary)) = row else {
        return Err(CommandJournalError::new(CommandJournalMissingDuplicate));
    };
    if fingerprint != journal.request_fingerprint().as_str() {
        return Ok(CommandJournalOutcome::Conflict);
    }
    match status.as_str() {
        "in_flight" => Ok(CommandJournalOutcome::AlreadyInFlight),
        "completed" => {
            let Some(summary) = result_summary
                .as_deref()
                .and_then(CommandResultSummary::parse_persisted)
            else {
                return Err(CommandJournalError::new(CommandJournalUnknownSummary));
            };
            Ok(CommandJournalOutcome::AlreadyCompleted(summary))
        }
        "failed" => {
            let Some(summary) = error_summary
                .as_deref()
                .and_then(CommandErrorSummary::parse_persisted)
            else {
                return Err(CommandJournalError::new(CommandJournalUnknownSummary));
            };
            Ok(CommandJournalOutcome::AlreadyFailed(summary))
        }
        _ => Err(CommandJournalError::new(CommandJournalUnknownStatus)),
    }
}

async fn mark_completed(
    tx: &mut TxCapability<'_>,
    journal: &CommandJournalRecord,
    result_summary: CommandResultSummary,
) -> Result<(), CommandJournalError> {
    let result = sqlx::query(
        r#"
        UPDATE command_journal
        SET status = $3,
            result_summary = $4,
            error_summary = NULL,
            updated_at = now()
        WHERE tenant_id = $1::uuid
          AND command_id = $2
          AND status = 'in_flight'
        "#,
    )
    .bind(journal.tenant().to_string())
    .bind(journal.command_id().as_str())
    .bind(CommandJournalStatus::Completed.as_label())
    .bind(result_summary.as_str())
    .execute(tx.conn())
    .await
    .map_err(CommandJournalError::new)?;
    if result.rows_affected() == 1 {
        Ok(())
    } else {
        Err(CommandJournalError::new(CommandJournalStatusRace))
    }
}

async fn mark_failed(
    tx: &mut TxCapability<'_>,
    journal: &CommandJournalRecord,
    error_summary: CommandErrorSummary,
) -> Result<(), CommandJournalError> {
    let result = sqlx::query(
        r#"
        UPDATE command_journal
        SET status = $3,
            result_summary = NULL,
            error_summary = $4,
            updated_at = now()
        WHERE tenant_id = $1::uuid
          AND command_id = $2
          AND status = 'in_flight'
        "#,
    )
    .bind(journal.tenant().to_string())
    .bind(journal.command_id().as_str())
    .bind(CommandJournalStatus::Failed.as_label())
    .bind(error_summary.as_str())
    .execute(tx.conn())
    .await
    .map_err(CommandJournalError::new)?;
    if result.rows_affected() == 1 {
        Ok(())
    } else {
        Err(CommandJournalError::new(CommandJournalStatusRace))
    }
}

async fn ensure_existing_outbox_matches(
    tx: &mut TxCapability<'_>,
    entry: &consistency::outbox::Entry,
    env: &OutboxEnvelope,
) -> Result<(), CommandJournalError> {
    let row: Option<(bool,)> = sqlx::query_as(
        r#"
        SELECT tenant_id = $2::uuid
           AND topic = $3
           AND domain = $4
           AND contract_id = $5
           AND contract_version = $6
           AND schema_hash = $7
           AND payload = $8
           AND metadata = $9::jsonb
           AND partition_key IS NOT DISTINCT FROM $10
           AND causation_id IS NOT DISTINCT FROM $11 AS matches
        FROM outbox
        WHERE event_id = $1
        "#,
    )
    .bind(entry.idem_key().as_str())
    .bind(env.tenant().to_string())
    .bind(entry.topic().as_str())
    .bind(env.domain())
    .bind(env.contract_id())
    .bind(env.contract_version())
    .bind(env.schema_hash())
    .bind(entry.payload())
    .bind(env.metadata_json())
    .bind(env.partition_key())
    .bind(env.causation_id())
    .fetch_optional(tx.conn())
    .await
    .map_err(CommandJournalError::new)?;

    match row {
        Some((true,)) => Ok(()),
        Some((false,)) | None => Err(CommandJournalError::new(CommandJournalOutboxConflict)),
    }
}

#[derive(Debug, thiserror::Error)]
#[error("command journal tenant mismatch")]
struct CommandJournalTenantMismatch;

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

#[derive(Debug, thiserror::Error)]
#[error("command journal outbox conflict")]
struct CommandJournalOutboxConflict;
