//! Typed tenant-transaction SQL operations for the eventing persistence adapters.
//!
//! This module is the only eventing child of `cotx` that can touch the private PostgreSQL
//! connection.  Every operation owns a fixed SQL statement and typed bind surface; no caller can
//! recover an executor or supply SQL text.

use consistency::{
    CommandErrorSummary, CommandJournalStatus, CommandResultSummary, OutboxAppendOutcome,
    OutboxFactIdentity,
};
use diport::{DeadLetterRecord, DeadLetterSource};
use futures::future::BoxFuture;
use sqlx::PgConnection;

use super::{
    MaintenanceReadLane, MaintenanceWriteLane, ServingReadLane, ServingWriteLane, TenantDb,
    TenantLane, TenantScopeHandle, TenantTx,
};
use crate::command_journal::PreparedCommand;
use crate::dead_letter_payload::{DLX_REPLAY_CAPSULE_ENCODING, ProtectedDlxCapsule, SensitiveJson};
use crate::inbox::ReceiptFields;
use crate::outbox::{
    AppendFingerprintObservation, CanonicalOutboxFact, OutboxAppendError, OutboxEnvelope,
    ReplayedOutboxAppend, classify_append_fingerprint,
};
use crate::projection_events::{ProjectionAppend, ProjectionWriteRegistry};
use crate::saga::{
    InstanceFields, JournalEntryFields, LeaseFields, RegistrationFields, SagaReceiptInsertFields,
    SagaReceiptScopeFields,
};

mod concern_seal {
    pub trait Sealed {}
}

#[doc(hidden)]
pub trait EventingConcern: concern_seal::Sealed + Send + 'static {}
#[doc(hidden)]
pub trait GeneratedOutboxConcern: EventingConcern {}
#[doc(hidden)]
pub trait InboxOperationConcern: EventingConcern {}

#[doc(hidden)]
pub struct CommandConcern;
#[doc(hidden)]
pub struct SagaConcern;
#[doc(hidden)]
pub struct DlqConcern;
#[doc(hidden)]
pub struct OutboxConcern;
#[doc(hidden)]
pub struct InboxConcern;
#[doc(hidden)]
#[cfg_attr(
    not(any(feature = "domain-settings", feature = "domain-audit")),
    allow(dead_code)
)]
pub struct ConsumerConcern;

macro_rules! seal_concerns {
    ($($concern:ty),+ $(,)?) => {$(
        impl concern_seal::Sealed for $concern {}
        impl EventingConcern for $concern {}
    )+};
}

seal_concerns!(
    CommandConcern,
    SagaConcern,
    DlqConcern,
    OutboxConcern,
    InboxConcern,
    ConsumerConcern,
);

impl GeneratedOutboxConcern for CommandConcern {}
impl GeneratedOutboxConcern for OutboxConcern {}
impl InboxOperationConcern for InboxConcern {}
impl InboxOperationConcern for ConsumerConcern {}

/// Exact eventing operation set. The sealed concern parameter prevents command, saga, DLQ,
/// outbox, projection, and inbox authorities from being interchanged in an arbitrary closure.
#[doc(hidden)]
pub struct EventingTx<'tx, L: TenantLane, C: EventingConcern> {
    pub(in crate::cotx) conn: &'tx mut PgConnection,
    pub(in crate::cotx) tenant: vocab::TenantId,
    _lane: std::marker::PhantomData<fn() -> L>,
    _concern: std::marker::PhantomData<fn() -> C>,
}

pub(crate) type CommandTx<'tx> = EventingTx<'tx, ServingWriteLane, CommandConcern>;
#[cfg(all(test, feature = "integration"))]
pub(crate) type SagaWriteTx<'tx> = EventingTx<'tx, ServingWriteLane, SagaConcern>;
#[doc(hidden)]
pub type OutboxTx<'tx> = EventingTx<'tx, ServingWriteLane, OutboxConcern>;
#[cfg(all(test, feature = "integration"))]
pub(crate) type InboxWriteTx<'tx> = EventingTx<'tx, ServingWriteLane, InboxConcern>;
#[cfg(any(feature = "domain-settings", feature = "domain-audit"))]
pub(crate) type ConsumerTx<'tx> = EventingTx<'tx, ServingWriteLane, ConsumerConcern>;

impl<'tx, L: TenantLane, C: EventingConcern> EventingTx<'tx, L, C> {
    pub(in crate::cotx) fn from_raw(tx: &'tx mut TenantTx<'_, L>) -> Self {
        Self {
            conn: &mut *tx.conn,
            tenant: tx.tenant,
            _lane: std::marker::PhantomData,
            _concern: std::marker::PhantomData,
        }
    }

    pub(in crate::cotx) fn from_parts(
        conn: &'tx mut PgConnection,
        tenant: vocab::TenantId,
    ) -> Self {
        Self {
            conn,
            tenant,
            _lane: std::marker::PhantomData,
            _concern: std::marker::PhantomData,
        }
    }

    #[cfg(any(feature = "domain-settings", feature = "domain-audit"))]
    pub(in crate::cotx) fn parts(&mut self) -> (&mut PgConnection, vocab::TenantId) {
        (&mut *self.conn, self.tenant)
    }

    pub(crate) fn tenant(&self) -> vocab::TenantId {
        self.tenant
    }
}

macro_rules! eventing_write_runner {
    ($lane:ty, $method:ident, $concern:ty) => {
        impl TenantDb<$lane> {
            pub(crate) async fn $method<S, T, F, E>(
                &self,
                scope: S,
                write: F,
                map_storage: impl Fn(sqlx::Error) -> E + Send,
            ) -> Result<T, E>
            where
                S: TenantScopeHandle,
                F: for<'tx> FnOnce(
                        EventingTx<'tx, $lane, $concern>,
                    ) -> BoxFuture<'tx, Result<T, E>>
                    + Send,
                E: std::error::Error + Send + Sync + 'static,
                T: Send,
            {
                self.write(
                    scope,
                    move |tx| write(EventingTx::<$lane, $concern>::from_raw(tx)),
                    map_storage,
                )
                .await
            }
        }
    };
}

macro_rules! eventing_read_runner {
    ($lane:ty, $method:ident, $concern:ty) => {
        impl TenantDb<$lane> {
            pub(crate) async fn $method<S, T, F>(&self, scope: S, read: F) -> Result<T, sqlx::Error>
            where
                S: TenantScopeHandle,
                F: for<'tx> FnOnce(
                        EventingTx<'tx, $lane, $concern>,
                    ) -> BoxFuture<'tx, Result<T, sqlx::Error>>
                    + Send,
                T: Send,
            {
                self.read(scope, move |tx| {
                    read(EventingTx::<$lane, $concern>::from_raw(tx))
                })
                .await
            }
        }
    };
}

macro_rules! eventing_read_map_runner {
    ($lane:ty, $method:ident, $concern:ty) => {
        impl TenantDb<$lane> {
            pub(crate) async fn $method<S, T, F, E>(
                &self,
                scope: S,
                read: F,
                map_storage: impl Fn(sqlx::Error) -> E + Send,
            ) -> Result<T, E>
            where
                S: TenantScopeHandle,
                F: for<'tx> FnOnce(
                        EventingTx<'tx, $lane, $concern>,
                    ) -> BoxFuture<'tx, Result<T, E>>
                    + Send,
                E: Send,
                T: Send,
            {
                self.read_map(
                    scope,
                    move |tx| read(EventingTx::<$lane, $concern>::from_raw(tx)),
                    map_storage,
                )
                .await
            }
        }
    };
}

eventing_write_runner!(ServingWriteLane, command_write, CommandConcern);
eventing_write_runner!(ServingWriteLane, saga_write, SagaConcern);
eventing_write_runner!(ServingWriteLane, dlq_write, DlqConcern);
eventing_write_runner!(MaintenanceWriteLane, dlq_write, DlqConcern);
eventing_write_runner!(ServingWriteLane, outbox_write, OutboxConcern);
eventing_write_runner!(ServingWriteLane, inbox_write, InboxConcern);
#[cfg(any(feature = "domain-settings", feature = "domain-audit"))]
eventing_write_runner!(ServingWriteLane, consumer_write, ConsumerConcern);

impl TenantDb<ServingWriteLane> {
    /// Saga receipt writes retain the opaque local transaction settlement until the adapter maps
    /// commit-unknown into its dedicated fail-closed port error.
    pub(crate) async fn saga_write_attempt<S, T, F, E>(
        &self,
        scope: S,
        write: F,
        map_storage: impl Fn(sqlx::Error) -> E + Send,
    ) -> super::LocalTxAttempt<T, E>
    where
        S: TenantScopeHandle,
        F: for<'tx> FnOnce(
                EventingTx<'tx, ServingWriteLane, SagaConcern>,
            ) -> BoxFuture<'tx, Result<T, E>>
            + Send,
        E: std::error::Error + Send + Sync + 'static,
        T: Send,
    {
        self.write_attempt(
            scope,
            move |tx| write(EventingTx::<ServingWriteLane, SagaConcern>::from_raw(tx)),
            map_storage,
        )
        .await
    }

    pub(crate) async fn outbox_deadline_write<S, T, F, E>(
        &self,
        scope: S,
        deadline: tokio::time::Instant,
        write: F,
        map_storage: impl Fn(sqlx::Error) -> E + Send + Sync,
        map_timeout: impl Fn() -> E + Send + Sync,
    ) -> Result<T, E>
    where
        S: TenantScopeHandle,
        F: for<'tx> FnOnce(OutboxTx<'tx>) -> BoxFuture<'tx, Result<T, E>> + Send,
        E: Send,
        T: Send,
    {
        self.deadline_write(
            scope,
            deadline,
            move |tx| write(OutboxTx::from_raw(tx)),
            map_storage,
            map_timeout,
        )
        .await
    }
}

eventing_read_map_runner!(ServingReadLane, saga_read_map, SagaConcern);
eventing_read_runner!(ServingReadLane, dlq_read, DlqConcern);
eventing_read_runner!(MaintenanceReadLane, dlq_read, DlqConcern);
eventing_read_runner!(ServingReadLane, inbox_read, InboxConcern);

#[derive(Debug, thiserror::Error)]
#[error("{carrier} tenant does not match tenant transaction")]
struct EmbeddedTenantMismatch {
    carrier: &'static str,
}

fn ensure_embedded_tenant(
    authoritative: vocab::TenantId,
    embedded: vocab::TenantId,
    carrier: &'static str,
) -> Result<(), sqlx::Error> {
    if authoritative == embedded {
        Ok(())
    } else {
        Err(sqlx::Error::AnyDriverError(Box::new(
            EmbeddedTenantMismatch { carrier },
        )))
    }
}

pub(crate) struct CommandAliasKey<'a> {
    pub(crate) topic: &'a str,
    pub(crate) key_id: &'a str,
    pub(crate) digest: &'a [u8],
}

/// Closed projection selection carried only by the DLQ replay concern.
///
/// Unlike [`ProjectionWriteRegistry`], this value cannot be used to configure a tenant lane or a
/// generic projection writer. Its private construction and fields make it an immutable witness for
/// the one operator replay operation.
#[derive(Clone)]
pub(crate) struct DlqReplayProjection {
    bindings: std::sync::Arc<[vocab::ProjectionInputBinding]>,
}

impl DlqReplayProjection {
    pub(crate) fn from_capture(capture: eventexec::ProjectionCaptureView<'_>) -> Self {
        Self {
            bindings: std::sync::Arc::from(capture.bindings()),
        }
    }

    #[cfg(test)]
    pub(crate) fn from_selected(bindings: &[vocab::ProjectionInputBinding]) -> Self {
        Self {
            bindings: std::sync::Arc::from(bindings),
        }
    }

    pub(crate) fn from_registry(registry: &ProjectionWriteRegistry) -> Self {
        Self {
            bindings: std::sync::Arc::from(registry.bindings()),
        }
    }

    fn is_bound(&self, replay: &ReplayedOutboxAppend) -> bool {
        self.bindings.iter().any(|binding| {
            binding.contract_id() == replay.contract_id
                && binding.version() == replay.contract_version
                && binding.schema_hash() == replay.schema_hash
                && binding.topic() == replay.topic
        })
    }
}

pub(crate) struct CommandAliasClaim<'a> {
    pub(crate) key: CommandAliasKey<'a>,
    pub(crate) command_id: &'a str,
}

#[derive(sqlx::FromRow)]
pub(crate) struct CommandJournalRow {
    pub(crate) status: String,
    pub(crate) request_fingerprint: String,
    pub(crate) result_summary: Option<String>,
    pub(crate) error_summary: Option<String>,
}

pub(crate) enum CommandTerminalUpdate<'a> {
    Completed(&'a CommandResultSummary),
    Failed(&'a CommandErrorSummary),
}

impl EventingTx<'_, ServingWriteLane, CommandConcern> {
    #[cfg(all(test, feature = "integration"))]
    pub(crate) async fn command_insert_test_marker(
        &mut self,
        marker: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("INSERT INTO command_journal_test_markers (marker) VALUES ($1)")
            .bind(marker)
            .execute(&mut *self.conn)
            .await?;
        Ok(())
    }

    pub(crate) async fn command_find_alias(
        &mut self,
        key: CommandAliasKey<'_>,
    ) -> Result<Option<String>, sqlx::Error> {
        sqlx::query_scalar(
            "SELECT command_id FROM command_idempotency_aliases \
             WHERE tenant_id = $1::uuid AND topic = $2 AND key_id = $3 \
               AND alias_digest = $4",
        )
        .bind(self.tenant.to_string())
        .bind(key.topic)
        .bind(key.key_id)
        .bind(key.digest)
        .fetch_optional(&mut *self.conn)
        .await
    }

    pub(crate) async fn command_claim_alias(
        &mut self,
        claim: CommandAliasClaim<'_>,
    ) -> Result<String, sqlx::Error> {
        sqlx::query(
            "INSERT INTO command_idempotency_aliases \
             (tenant_id, topic, key_id, alias_digest, command_id) \
             VALUES ($1::uuid, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
        )
        .bind(self.tenant.to_string())
        .bind(claim.key.topic)
        .bind(claim.key.key_id)
        .bind(claim.key.digest)
        .bind(claim.command_id)
        .execute(&mut *self.conn)
        .await?;

        sqlx::query_scalar(
            "SELECT command_id FROM command_idempotency_aliases \
             WHERE tenant_id = $1::uuid AND topic = $2 AND key_id = $3 \
               AND alias_digest = $4",
        )
        .bind(self.tenant.to_string())
        .bind(claim.key.topic)
        .bind(claim.key.key_id)
        .bind(claim.key.digest)
        .fetch_one(&mut *self.conn)
        .await
    }

    pub(crate) async fn command_insert_journal_claim(
        &mut self,
        prepared: &PreparedCommand,
        env: &OutboxEnvelope,
    ) -> Result<bool, sqlx::Error> {
        ensure_embedded_tenant(self.tenant, env.tenant(), "command outbox envelope")?;
        let result = sqlx::query(
            "INSERT INTO command_journal \
             (tenant_id, command_id, topic, contract_id, contract_version, schema_hash, \
              request_fingerprint, outbox_event_id, status, attempt, trace, correlation_id) \
             VALUES ($1::uuid,$2,$3,$4,$5,$6,$7,$2,$8,1,$9,$10) \
             ON CONFLICT (tenant_id, command_id) DO NOTHING",
        )
        .bind(self.tenant.to_string())
        .bind(prepared.entry.idem_key().as_str())
        .bind(prepared.entry.topic().as_str())
        .bind(env.contract_id())
        .bind(env.contract_version())
        .bind(env.schema_hash())
        .bind(prepared.fingerprint.as_str())
        .bind(CommandJournalStatus::InFlight.as_label())
        .bind(tracewire::capture())
        .bind(diagctx::correlation().map(|id| id.as_str().to_string()))
        .execute(&mut *self.conn)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub(crate) async fn command_load_journal_for_update(
        &mut self,
        command_id: &str,
    ) -> Result<Option<CommandJournalRow>, sqlx::Error> {
        sqlx::query_as(
            "SELECT status, request_fingerprint, result_summary, error_summary \
             FROM command_journal WHERE tenant_id=$1::uuid AND command_id=$2 FOR UPDATE",
        )
        .bind(self.tenant.to_string())
        .bind(command_id)
        .fetch_optional(&mut *self.conn)
        .await
    }

    pub(crate) async fn command_settle_journal(
        &mut self,
        command_id: &str,
        update: CommandTerminalUpdate<'_>,
    ) -> Result<bool, sqlx::Error> {
        let result = match update {
            CommandTerminalUpdate::Completed(summary) => sqlx::query(
                "UPDATE command_journal SET status=$3,result_summary=$4,error_summary=NULL,updated_at=now() \
                 WHERE tenant_id=$1::uuid AND command_id=$2 AND status='in_flight'",
            )
            .bind(self.tenant.to_string())
            .bind(command_id)
            .bind(CommandJournalStatus::Completed.as_label())
            .bind(summary.as_str())
            .execute(&mut *self.conn)
            .await?,
            CommandTerminalUpdate::Failed(summary) => sqlx::query(
                "UPDATE command_journal SET status=$3,result_summary=NULL,error_summary=$4,updated_at=now() \
                 WHERE tenant_id=$1::uuid AND command_id=$2 AND status='in_flight'",
            )
            .bind(self.tenant.to_string())
            .bind(command_id)
            .bind(CommandJournalStatus::Failed.as_label())
            .bind(summary.as_str())
            .execute(&mut *self.conn)
            .await?,
        };
        Ok(result.rows_affected() == 1)
    }
}

#[derive(sqlx::FromRow)]
pub(crate) struct SagaLeaseRow {
    pub(crate) lease_token: String,
    pub(crate) epoch: i64,
}

#[derive(Debug, sqlx::FromRow)]
pub(crate) struct SagaInstanceRow {
    pub(crate) owner: String,
    pub(crate) contract_id: String,
    pub(crate) definition_version: String,
    pub(crate) definition_schema_digest: String,
    pub(crate) action_registry_generation: String,
    pub(crate) status: String,
}

#[derive(sqlx::FromRow)]
pub(crate) struct SagaRunnableRow {
    pub(crate) saga_id: String,
    pub(crate) status: String,
    pub(crate) owner: String,
    pub(crate) contract_id: String,
    pub(crate) definition_version: String,
    pub(crate) definition_schema_digest: String,
    pub(crate) action_registry_generation: String,
}

#[derive(sqlx::FromRow)]
pub(crate) struct SagaJournalExistingRow {
    pub(crate) step_name: String,
    pub(crate) status: String,
    pub(crate) error_summary: Option<String>,
}

#[derive(sqlx::FromRow)]
pub(crate) struct SagaJournalRow {
    pub(crate) seq: i64,
    pub(crate) step_name: String,
    pub(crate) status: String,
}

#[derive(sqlx::FromRow)]
pub(crate) struct SagaReceiptRow {
    pub(crate) effect_key: Vec<u8>,
    pub(crate) receipt_schema: String,
    pub(crate) format_version: i16,
    pub(crate) ciphertext: Vec<u8>,
    pub(crate) key_ref: String,
    pub(crate) content_hmac_key_id: String,
    pub(crate) content_hmac: Vec<u8>,
    pub(crate) successful_attempt: i32,
    pub(crate) completed_seq: i64,
    pub(crate) journal_step_name: Option<String>,
    pub(crate) journal_status: Option<String>,
}

pub(crate) enum SagaLeaseMutation<'a> {
    Extend { ttl_secs: i64 },
    Release,
    MarkStatus(&'a str),
}

impl EventingTx<'_, ServingWriteLane, SagaConcern> {
    #[cfg(all(test, feature = "integration"))]
    pub(crate) async fn saga_inject_commit_unknown_after_commit(
        &mut self,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("SELECT set_config('rss.test_commit_unknown_after_commit', '1', true)")
            .execute(&mut *self.conn)
            .await
            .map(|_| ())
    }

    pub(crate) async fn saga_register_instance(
        &mut self,
        fields: &RegistrationFields,
    ) -> Result<(), sqlx::Error> {
        ensure_embedded_tenant(self.tenant, fields.instance.tenant(), "saga registration")?;
        sqlx::query(
            r#"
            INSERT INTO saga_instances
                (tenant_id, saga_id, owner, contract_id, definition_version,
                 definition_schema_digest, action_registry_generation)
            VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7)
            ON CONFLICT (tenant_id, saga_id) DO NOTHING
            "#,
        )
        .bind(self.tenant.to_string())
        .bind(&fields.saga_id)
        .bind(&fields.owner)
        .bind(&fields.contract_id)
        .bind(&fields.definition_version)
        .bind(&fields.definition_schema_digest)
        .bind(&fields.action_registry_generation)
        .execute(&mut *self.conn)
        .await?;
        Ok(())
    }

    pub(crate) async fn saga_load_instance(
        &mut self,
        fields: &InstanceFields,
    ) -> Result<SagaInstanceRow, sqlx::Error> {
        ensure_embedded_tenant(self.tenant, fields.instance.tenant(), "saga instance")?;
        sqlx::query_as(
            r#"
            SELECT owner, contract_id, definition_version,
                   definition_schema_digest, action_registry_generation, status
            FROM saga_instances
            WHERE tenant_id = $1::uuid AND saga_id = $2::uuid
            "#,
        )
        .bind(self.tenant.to_string())
        .bind(&fields.saga_id)
        .fetch_one(&mut *self.conn)
        .await
    }

    pub(crate) async fn saga_acquire_lease(
        &mut self,
        fields: &InstanceFields,
        holder_id: &str,
        ttl_secs: i64,
    ) -> Result<Option<SagaLeaseRow>, sqlx::Error> {
        ensure_embedded_tenant(self.tenant, fields.instance.tenant(), "saga instance")?;
        sqlx::query_as(
            r#"
            UPDATE saga_instances
            SET status = 'running',
                lease_token = gen_random_uuid(),
                holder_id = $3,
                epoch = epoch + 1,
                acquired_at = now(),
                expires_at = now() + make_interval(secs => $4),
                heartbeat_at = now(),
                updated_at = now()
            WHERE tenant_id = $1::uuid
              AND saga_id = $2::uuid
              AND (lease_token IS NULL OR expires_at <= now())
            RETURNING lease_token::text, epoch
            "#,
        )
        .bind(self.tenant.to_string())
        .bind(&fields.saga_id)
        .bind(holder_id)
        .bind(ttl_secs)
        .fetch_optional(&mut *self.conn)
        .await
    }

    pub(crate) async fn saga_cas_lease(
        &mut self,
        fields: &LeaseFields,
        mutation: SagaLeaseMutation<'_>,
    ) -> Result<bool, sqlx::Error> {
        ensure_embedded_tenant(self.tenant, fields.instance.tenant(), "saga lease")?;
        let result = match mutation {
            SagaLeaseMutation::Extend { ttl_secs } => {
                sqlx::query(
                    r#"
                UPDATE saga_instances
                SET expires_at = now() + make_interval(secs => $5),
                    heartbeat_at = now(), updated_at = now()
                WHERE tenant_id = $1::uuid AND saga_id = $2::uuid
                  AND lease_token = $3::uuid AND epoch = $4 AND expires_at > now()
                "#,
                )
                .bind(self.tenant.to_string())
                .bind(&fields.saga_id)
                .bind(&fields.lease_token)
                .bind(fields.epoch)
                .bind(ttl_secs)
                .execute(&mut *self.conn)
                .await?
            }
            SagaLeaseMutation::Release => {
                sqlx::query(
                    r#"
                UPDATE saga_instances
                SET lease_token = NULL, holder_id = NULL, acquired_at = NULL,
                    expires_at = NULL, heartbeat_at = NULL, updated_at = now()
                WHERE tenant_id = $1::uuid AND saga_id = $2::uuid
                  AND lease_token = $3::uuid AND epoch = $4 AND expires_at > now()
                "#,
                )
                .bind(self.tenant.to_string())
                .bind(&fields.saga_id)
                .bind(&fields.lease_token)
                .bind(fields.epoch)
                .execute(&mut *self.conn)
                .await?
            }
            SagaLeaseMutation::MarkStatus(status) => {
                sqlx::query(
                    r#"
                UPDATE saga_instances
                SET status = $5, updated_at = now()
                WHERE tenant_id = $1::uuid AND saga_id = $2::uuid
                  AND lease_token = $3::uuid AND epoch = $4 AND expires_at > now()
                "#,
                )
                .bind(self.tenant.to_string())
                .bind(&fields.saga_id)
                .bind(&fields.lease_token)
                .bind(fields.epoch)
                .bind(status)
                .execute(&mut *self.conn)
                .await?
            }
        };
        Ok(result.rows_affected() == 1)
    }

    pub(crate) async fn saga_insert_journal(
        &mut self,
        fields: &LeaseFields,
        entry: &JournalEntryFields,
    ) -> Result<bool, sqlx::Error> {
        ensure_embedded_tenant(self.tenant, fields.instance.tenant(), "saga lease")?;
        let inserted: Option<i32> = sqlx::query_scalar(
            r#"
            INSERT INTO saga_journal
                (tenant_id, saga_id, seq, step_name, status, error_summary)
            SELECT $1::uuid, $2::uuid, $5, $6, $7, $8
            FROM saga_instances
            WHERE tenant_id = $1::uuid AND saga_id = $2::uuid
              AND lease_token = $3::uuid AND epoch = $4
              AND expires_at > clock_timestamp()
            FOR UPDATE
            ON CONFLICT (tenant_id, saga_id, seq) DO NOTHING
            RETURNING 1
            "#,
        )
        .bind(self.tenant.to_string())
        .bind(&fields.saga_id)
        .bind(&fields.lease_token)
        .bind(fields.epoch)
        .bind(entry.seq)
        .bind(&entry.step_name)
        .bind(&entry.status)
        .bind(entry.error_summary.as_deref())
        .fetch_optional(&mut *self.conn)
        .await?;
        Ok(inserted.is_some())
    }

    pub(crate) async fn saga_insert_receipt(
        &mut self,
        lease: &LeaseFields,
        receipt: &SagaReceiptInsertFields,
    ) -> Result<bool, sqlx::Error> {
        ensure_embedded_tenant(self.tenant, lease.instance.tenant(), "saga receipt lease")?;
        ensure_embedded_tenant(
            self.tenant,
            receipt.scope.instance.tenant(),
            "saga receipt scope",
        )?;
        let inserted: Option<i32> = sqlx::query_scalar(
            r#"
            INSERT INTO saga_step_receipts
                (tenant_id, saga_id, owner, contract_id, definition_version,
                 definition_schema_digest, action_registry_generation, step_name, effect_key,
                 receipt_schema, format_version, ciphertext, key_ref, content_hmac_key_id,
                 content_hmac, successful_attempt, completed_seq)
            SELECT $1::uuid, $2::uuid, $5, $6, $7, $8, $9, $10, $11,
                   $12, $13, $14, $15, $16, $17, $18, $19
            FROM saga_instances
            WHERE tenant_id = $1::uuid AND saga_id = $2::uuid
              AND lease_token = $3::uuid AND epoch = $4
              AND expires_at > clock_timestamp()
              AND owner = $5 AND contract_id = $6 AND definition_version = $7
              AND definition_schema_digest = $8 AND action_registry_generation = $9
            FOR UPDATE
            ON CONFLICT DO NOTHING
            RETURNING 1
            "#,
        )
        .bind(self.tenant.to_string())
        .bind(&lease.saga_id)
        .bind(&lease.lease_token)
        .bind(lease.epoch)
        .bind(&receipt.scope.owner)
        .bind(&receipt.scope.contract_id)
        .bind(&receipt.scope.definition_version)
        .bind(&receipt.scope.definition_schema_digest)
        .bind(&receipt.scope.action_registry_generation)
        .bind(&receipt.scope.step_name)
        .bind(&receipt.effect_key)
        .bind(&receipt.receipt_schema)
        .bind(receipt.format_version)
        .bind(&receipt.ciphertext)
        .bind(&receipt.key_ref)
        .bind(&receipt.content_hmac_key_id)
        .bind(&receipt.content_hmac)
        .bind(receipt.successful_attempt)
        .bind(receipt.completed_seq)
        .fetch_optional(&mut *self.conn)
        .await?;
        Ok(inserted.is_some())
    }

    pub(crate) async fn saga_lease_is_held(
        &mut self,
        fields: &LeaseFields,
    ) -> Result<bool, sqlx::Error> {
        ensure_embedded_tenant(self.tenant, fields.instance.tenant(), "saga lease")?;
        let held: Option<i32> = sqlx::query_scalar(
            r#"
            SELECT 1 FROM saga_instances
            WHERE tenant_id = $1::uuid AND saga_id = $2::uuid
              AND lease_token = $3::uuid AND epoch = $4
              AND expires_at > clock_timestamp()
            FOR UPDATE
            "#,
        )
        .bind(self.tenant.to_string())
        .bind(&fields.saga_id)
        .bind(&fields.lease_token)
        .bind(fields.epoch)
        .fetch_optional(&mut *self.conn)
        .await?;
        Ok(held.is_some())
    }

    pub(crate) async fn saga_load_journal_entry(
        &mut self,
        fields: &InstanceFields,
        seq: i64,
    ) -> Result<Option<SagaJournalExistingRow>, sqlx::Error> {
        ensure_embedded_tenant(self.tenant, fields.instance.tenant(), "saga instance")?;
        sqlx::query_as(
            r#"
            SELECT step_name, status, error_summary
            FROM saga_journal
            WHERE tenant_id = $1::uuid AND saga_id = $2::uuid AND seq = $3
            "#,
        )
        .bind(self.tenant.to_string())
        .bind(&fields.saga_id)
        .bind(seq)
        .fetch_optional(&mut *self.conn)
        .await
    }
}

impl<L: TenantLane> EventingTx<'_, L, SagaConcern> {
    pub(crate) async fn saga_load_receipt(
        &mut self,
        fields: &SagaReceiptScopeFields,
    ) -> Result<Option<SagaReceiptRow>, sqlx::Error> {
        ensure_embedded_tenant(self.tenant, fields.instance.tenant(), "saga receipt")?;
        sqlx::query_as(
            r#"
            SELECT receipt.effect_key, receipt.receipt_schema, receipt.format_version,
                   receipt.ciphertext, receipt.key_ref, receipt.content_hmac_key_id,
                   receipt.content_hmac, receipt.successful_attempt, receipt.completed_seq,
                   journal.step_name AS journal_step_name, journal.status AS journal_status
            FROM saga_step_receipts AS receipt
            LEFT JOIN saga_journal AS journal
              ON journal.tenant_id = receipt.tenant_id
             AND journal.saga_id = receipt.saga_id
             AND journal.seq = receipt.completed_seq
            WHERE receipt.tenant_id = $1::uuid AND receipt.saga_id = $2::uuid
              AND receipt.owner = $3 AND receipt.contract_id = $4
              AND receipt.definition_version = $5
              AND receipt.definition_schema_digest = $6
              AND receipt.action_registry_generation = $7
              AND receipt.step_name = $8
            "#,
        )
        .bind(self.tenant.to_string())
        .bind(&fields.saga_id)
        .bind(&fields.owner)
        .bind(&fields.contract_id)
        .bind(&fields.definition_version)
        .bind(&fields.definition_schema_digest)
        .bind(&fields.action_registry_generation)
        .bind(&fields.step_name)
        .fetch_optional(&mut *self.conn)
        .await
    }
}

impl EventingTx<'_, ServingReadLane, SagaConcern> {
    pub(crate) async fn saga_get_instance(
        &mut self,
        fields: &InstanceFields,
    ) -> Result<Option<SagaInstanceRow>, sqlx::Error> {
        ensure_embedded_tenant(self.tenant, fields.instance.tenant(), "saga instance")?;
        sqlx::query_as(
            r#"
            SELECT owner, contract_id, definition_version,
                   definition_schema_digest, action_registry_generation, status
            FROM saga_instances
            WHERE tenant_id = $1::uuid AND saga_id = $2::uuid
            "#,
        )
        .bind(self.tenant.to_string())
        .bind(&fields.saga_id)
        .fetch_optional(&mut *self.conn)
        .await
    }

    pub(crate) async fn saga_list_runnable(
        &mut self,
        owner: &str,
        contract_id: &str,
        limit: i64,
    ) -> Result<Vec<SagaRunnableRow>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT saga_id::text, status, owner, contract_id, definition_version,
                   definition_schema_digest, action_registry_generation
            FROM saga_instances
            WHERE tenant_id = $1::uuid AND owner = $2 AND contract_id = $3
              AND status IN ('ready', 'running', 'compensating')
              AND (lease_token IS NULL OR expires_at <= now())
            ORDER BY updated_at, saga_id
            LIMIT $4
            "#,
        )
        .bind(self.tenant.to_string())
        .bind(owner)
        .bind(contract_id)
        .bind(limit)
        .fetch_all(&mut *self.conn)
        .await
    }

    pub(crate) async fn saga_read_journal(
        &mut self,
        fields: &InstanceFields,
    ) -> Result<Vec<SagaJournalRow>, sqlx::Error> {
        ensure_embedded_tenant(self.tenant, fields.instance.tenant(), "saga instance")?;
        sqlx::query_as(
            r#"
            SELECT seq, step_name, status
            FROM saga_journal
            WHERE tenant_id = $1::uuid AND saga_id = $2::uuid
            ORDER BY seq ASC
            "#,
        )
        .bind(self.tenant.to_string())
        .bind(&fields.saga_id)
        .fetch_all(&mut *self.conn)
        .await
    }
}

#[derive(sqlx::FromRow)]
pub(crate) struct ReplayDeadLetterRow {
    pub(crate) source_kind: String,
    pub(crate) message_id: String,
    pub(crate) producer_domain: String,
    pub(crate) consumer_domain: Option<String>,
    pub(crate) contract_id: String,
    pub(crate) replay_capsule: serde_json::Value,
    pub(crate) replay_capsule_key_ref: String,
    pub(crate) topic: String,
    pub(crate) consumer_group: Option<String>,
}

#[derive(sqlx::FromRow)]
pub(crate) struct DeadLetterRow {
    pub(crate) id: String,
    pub(crate) message_id: String,
    pub(crate) producer_domain: String,
    pub(crate) consumer_domain: Option<String>,
    pub(crate) contract_id: String,
    pub(crate) topic: String,
    pub(crate) consumer_group: Option<String>,
    pub(crate) payload_len: i64,
    pub(crate) error_summary: String,
    pub(crate) num_attempts: i32,
    pub(crate) source_kind: String,
    pub(crate) last_attempt_epoch: i64,
}

#[derive(sqlx::FromRow)]
pub(crate) struct OutboxDlxRow {
    pub(crate) event_id: String,
    pub(crate) domain: String,
    pub(crate) contract_id: String,
    pub(crate) topic: String,
    pub(crate) payload_len: i64,
    pub(crate) error_summary: String,
    pub(crate) retry_count: i32,
    pub(crate) dlx_epoch: i64,
}

pub(crate) struct DlqExpiredResolution<'a> {
    pub(crate) event_id: &'a str,
    pub(crate) kind: &'a str,
    pub(crate) change_ticket: &'a str,
    pub(crate) operator_subject: &'a str,
    pub(crate) evidence_event_id: Option<&'a str>,
}

pub(crate) struct DlqListFilter<'a> {
    pub(crate) producer_domain: Option<&'a str>,
    pub(crate) consumer_domain: Option<&'a str>,
    pub(crate) source: Option<&'a str>,
    pub(crate) contract_id: Option<&'a str>,
    pub(crate) cursor_epoch: Option<i64>,
    pub(crate) cursor_kind: Option<&'a str>,
    pub(crate) cursor_id: Option<&'a str>,
    pub(crate) limit: i64,
}

macro_rules! impl_dlq_write {
    ($lane:ty) => {
        impl EventingTx<'_, $lane, DlqConcern> {
            pub(crate) async fn dlq_load_replay_dead_letter(
                &mut self,
                dead_letter_id: &str,
            ) -> Result<Option<ReplayDeadLetterRow>, sqlx::Error> {
                sqlx::query_as(
                    r#"
                    SELECT source_kind, message_id, producer_domain, consumer_domain,
                           contract_id, replay_capsule, replay_capsule_key_ref, topic,
                           consumer_group
                    FROM dead_letter
                    WHERE id = $1::uuid AND tenant_id = $2::uuid
                    "#,
                )
                .bind(dead_letter_id)
                .bind(self.tenant.to_string())
                .fetch_optional(&mut *self.conn)
                .await
            }

            pub(crate) async fn dlq_redrive_outbox(
                &mut self,
                event_id: &str,
            ) -> Result<i64, sqlx::Error> {
                sqlx::query_scalar("SELECT rss_outbox_redrive($1, $2::uuid)")
                    .bind(event_id)
                    .bind(self.tenant.to_string())
                    .fetch_one(&mut *self.conn)
                    .await
            }

            pub(crate) async fn dlq_resolve_expired_outbox(
                &mut self,
                input: DlqExpiredResolution<'_>,
            ) -> Result<i64, sqlx::Error> {
                sqlx::query_scalar(
                    r#"
                    SELECT rss_outbox_resolve_expired($1, $2::uuid, $3, $4, $5, $6)
                    "#,
                )
                .bind(input.event_id)
                .bind(self.tenant.to_string())
                .bind(input.kind)
                .bind(input.change_ticket)
                .bind(input.operator_subject)
                .bind(input.evidence_event_id)
                .fetch_one(&mut *self.conn)
                .await
            }
        }
    };
}

impl_dlq_write!(ServingWriteLane);
impl_dlq_write!(MaintenanceWriteLane);

macro_rules! impl_dlq_read {
    ($lane:ty) => {
        impl EventingTx<'_, $lane, DlqConcern> {
            pub(crate) async fn dlq_inspect_dead_letter(
                &mut self,
                id: &str,
            ) -> Result<Option<DeadLetterRow>, sqlx::Error> {
                sqlx::query_as(
                    r#"
                    SELECT id::text, message_id, producer_domain, consumer_domain,
                           contract_id, topic, consumer_group, payload_len, error_summary,
                           num_attempts, source_kind,
                           EXTRACT(EPOCH FROM last_attempt_at)::bigint AS last_attempt_epoch
                    FROM dead_letter
                    WHERE tenant_id = $1::uuid AND id = $2::uuid AND source_kind <> $3
                    "#,
                )
                .bind(self.tenant.to_string())
                .bind(id)
                .bind(DeadLetterSource::OutboxRelay.as_str())
                .fetch_optional(&mut *self.conn)
                .await
            }

            pub(crate) async fn dlq_inspect_outbox(
                &mut self,
                event_id: &str,
            ) -> Result<Option<OutboxDlxRow>, sqlx::Error> {
                sqlx::query_as(
                    r#"
                    SELECT o.event_id, o.domain, o.contract_id, o.topic,
                           octet_length(o.payload)::bigint AS payload_len,
                           COALESCE(dl.error_summary, $4) AS error_summary,
                           o.retry_count,
                           EXTRACT(EPOCH FROM o.dlx_at)::bigint AS dlx_epoch
                    FROM outbox o
                    LEFT JOIN LATERAL (
                        SELECT dl.error_summary FROM dead_letter dl
                        WHERE dl.tenant_id = o.tenant_id AND dl.message_id = o.event_id
                          AND dl.source_kind = $5
                        ORDER BY dl.last_attempt_at DESC, dl.id DESC LIMIT 1
                    ) dl ON true
                    WHERE o.status = 'dlx' AND o.tenant_id = $2::uuid AND o.event_id = $3
                    "#,
                )
                .bind("dlx")
                .bind(self.tenant.to_string())
                .bind(event_id)
                .bind("outbox relay dlx")
                .bind(DeadLetterSource::OutboxRelay.as_str())
                .fetch_optional(&mut *self.conn)
                .await
            }

            pub(crate) async fn dlq_list_dead_letters(
                &mut self,
                filter: DlqListFilter<'_>,
            ) -> Result<Vec<DeadLetterRow>, sqlx::Error> {
                sqlx::query_as(
                    r#"
                    SELECT id::text, message_id, producer_domain, consumer_domain, contract_id,
                           topic, consumer_group, payload_len, error_summary, num_attempts,
                           source_kind,
                           EXTRACT(EPOCH FROM last_attempt_at)::bigint AS last_attempt_epoch
                    FROM dead_letter
                    WHERE tenant_id = $1::uuid
                      AND ($2::text IS NULL OR producer_domain = $2)
                      AND ($3::text IS NULL OR consumer_domain = $3)
                      AND ($4::text IS NULL OR source_kind = $4)
                      AND ($5::text IS NULL OR contract_id = $5)
                      AND source_kind <> $6
                      AND (
                            $7::bigint IS NULL
                         OR EXTRACT(EPOCH FROM last_attempt_at)::bigint < $7
                         OR (EXTRACT(EPOCH FROM last_attempt_at)::bigint = $7 AND $8::text > $9)
                         OR (EXTRACT(EPOCH FROM last_attempt_at)::bigint = $7 AND $8::text = $9
                             AND id::text > $10)
                      )
                    ORDER BY EXTRACT(EPOCH FROM last_attempt_at)::bigint DESC, id ASC
                    LIMIT $11
                    "#,
                )
                .bind(self.tenant.to_string())
                .bind(filter.producer_domain)
                .bind(filter.consumer_domain)
                .bind(filter.source)
                .bind(filter.contract_id)
                .bind(DeadLetterSource::OutboxRelay.as_str())
                .bind(filter.cursor_epoch)
                .bind("dead_letter")
                .bind(filter.cursor_kind)
                .bind(filter.cursor_id)
                .bind(filter.limit)
                .fetch_all(&mut *self.conn)
                .await
            }

            pub(crate) async fn dlq_list_outbox(
                &mut self,
                filter: DlqListFilter<'_>,
            ) -> Result<Vec<OutboxDlxRow>, sqlx::Error> {
                sqlx::query_as(
                    r#"
                    SELECT o.event_id, o.domain, o.contract_id, o.topic,
                           octet_length(o.payload)::bigint AS payload_len,
                           COALESCE(dl.error_summary, $9) AS error_summary,
                           o.retry_count,
                           EXTRACT(EPOCH FROM o.dlx_at)::bigint AS dlx_epoch
                    FROM outbox o
                    LEFT JOIN LATERAL (
                        SELECT dl.error_summary FROM dead_letter dl
                        WHERE dl.tenant_id = o.tenant_id AND dl.message_id = o.event_id
                          AND dl.source_kind = $10
                        ORDER BY dl.last_attempt_at DESC, dl.id DESC LIMIT 1
                    ) dl ON true
                    WHERE o.status = 'dlx' AND o.tenant_id = $2::uuid
                      AND ($3::text IS NULL OR o.domain = $3)
                      AND ($4::text IS NULL OR o.contract_id = $4)
                      AND (
                            $5::bigint IS NULL
                         OR EXTRACT(EPOCH FROM o.dlx_at)::bigint < $5
                         OR (EXTRACT(EPOCH FROM o.dlx_at)::bigint = $5 AND $6::text > $7)
                         OR (EXTRACT(EPOCH FROM o.dlx_at)::bigint = $5 AND $6::text = $7
                             AND o.event_id > $8)
                      )
                    ORDER BY EXTRACT(EPOCH FROM o.dlx_at)::bigint DESC, o.event_id ASC
                    LIMIT $11
                    "#,
                )
                .bind("dlx")
                .bind(self.tenant.to_string())
                .bind(filter.producer_domain)
                .bind(filter.contract_id)
                .bind(filter.cursor_epoch)
                .bind(eventexec::DlqEntryKind::OutboxDlx.cursor_part())
                .bind(filter.cursor_kind)
                .bind(filter.cursor_id)
                .bind("outbox relay dlx")
                .bind(DeadLetterSource::OutboxRelay.as_str())
                .bind(filter.limit)
                .fetch_all(&mut *self.conn)
                .await
            }
        }
    };
}

impl_dlq_read!(ServingReadLane);
impl_dlq_read!(MaintenanceReadLane);

pub(crate) struct RelayDeadLetterInsert<'a> {
    pub(crate) event_id: &'a str,
    pub(crate) domain: &'a str,
    pub(crate) contract_id: &'a str,
    pub(crate) topic: &'a str,
    pub(crate) protected: &'a ProtectedDlxCapsule,
    pub(crate) error_summary: &'a str,
    pub(crate) retry_count: i32,
}

macro_rules! impl_dead_letter_write {
    ($lane:ty) => {
        impl EventingTx<'_, $lane, DlqConcern> {
            pub(crate) async fn dead_letter_insert_projection(
                &mut self,
                record: &DeadLetterRecord,
                protected: &ProtectedDlxCapsule,
            ) -> Result<(), sqlx::Error> {
                ensure_embedded_tenant(self.tenant, record.tenant(), "dead-letter record")?;
                sqlx::query(
                    r#"
                    INSERT INTO dead_letter
                        (tenant_id, message_id, producer_domain, consumer_domain,
                         contract_id, topic, consumer_group,
                         replay_capsule, replay_capsule_key_ref, payload_len,
                         replay_capsule_encoding, metadata_digest,
                         error_summary, num_attempts, source_kind)
                    VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
                    ON CONFLICT (tenant_id, source_kind, consumer_group, message_id)
                    WHERE source_kind = 'projection'
                    DO NOTHING
                    "#,
                )
                .bind(self.tenant.to_string())
                .bind(record.message_id())
                .bind(record.producer_domain())
                .bind(record.consumer_domain())
                .bind(record.contract_id())
                .bind(record.topic())
                .bind(record.consumer_group())
                .bind(sqlx::types::Json(protected.replay_capsule()))
                .bind(protected.key_ref())
                .bind(protected.payload_len())
                .bind(DLX_REPLAY_CAPSULE_ENCODING)
                .bind(protected.metadata_digest())
                .bind(record.error_summary())
                .bind(i32::try_from(record.num_attempts()).unwrap_or(i32::MAX))
                .bind(record.source().as_str())
                .execute(&mut *self.conn)
                .await?;
                Ok(())
            }

        }
    };
}

impl_dead_letter_write!(ServingWriteLane);

impl EventingTx<'_, ServingWriteLane, OutboxConcern> {
    pub(crate) async fn dead_letter_insert_relay(
        &mut self,
        insert: RelayDeadLetterInsert<'_>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO dead_letter
                (tenant_id, message_id, producer_domain, consumer_domain,
                 contract_id, topic, consumer_group,
                 replay_capsule, replay_capsule_key_ref, payload_len,
                 replay_capsule_encoding, metadata_digest,
                 error_summary, num_attempts, source_kind)
            VALUES ($1::uuid, $2, $3, NULL, $4, $5, NULL, $6, $7, $8, $9, $10, $11, $12, $13)
            "#,
        )
        .bind(self.tenant.to_string())
        .bind(insert.event_id)
        .bind(insert.domain)
        .bind(insert.contract_id)
        .bind(insert.topic)
        .bind(sqlx::types::Json(insert.protected.replay_capsule()))
        .bind(insert.protected.key_ref())
        .bind(insert.protected.payload_len())
        .bind(DLX_REPLAY_CAPSULE_ENCODING)
        .bind(insert.protected.metadata_digest())
        .bind(insert.error_summary)
        .bind(insert.retry_count)
        .bind(DeadLetterSource::OutboxRelay.as_str())
        .execute(&mut *self.conn)
        .await?;
        Ok(())
    }
}

pub(crate) struct OutboxSettlementFence<'a> {
    pub(crate) event_id: &'a str,
    pub(crate) lease_token: &'a str,
    pub(crate) lease_deadline_epoch_micros: i64,
}

pub(crate) enum OutboxSettlementMutation {
    Published,
    Retry,
}

#[derive(sqlx::FromRow)]
pub(crate) struct MarkDlxRow {
    pub(crate) settlement_outcome: String,
    pub(crate) tenant_id: Option<String>,
    pub(crate) domain: Option<String>,
    pub(crate) contract_id: Option<String>,
    pub(crate) topic: Option<String>,
    pub(crate) payload: Option<Vec<u8>>,
    pub(crate) metadata_json: Option<String>,
    pub(crate) contract_version: Option<String>,
    pub(crate) schema_hash: Option<String>,
    pub(crate) retry_count: Option<i32>,
}

impl EventingTx<'_, ServingWriteLane, OutboxConcern> {
    pub(crate) async fn outbox_settle_delivery(
        &mut self,
        fence: OutboxSettlementFence<'_>,
        mutation: OutboxSettlementMutation,
    ) -> Result<String, sqlx::Error> {
        match mutation {
            OutboxSettlementMutation::Published => {
                sqlx::query_scalar("SELECT rss_outbox_settle_published($1, $2::uuid, $3)::text")
                    .bind(fence.event_id)
                    .bind(fence.lease_token)
                    .bind(fence.lease_deadline_epoch_micros)
                    .fetch_one(&mut *self.conn)
                    .await
            }
            OutboxSettlementMutation::Retry => {
                sqlx::query_scalar("SELECT rss_outbox_settle_retry($1, $2::uuid, $3)::text")
                    .bind(fence.event_id)
                    .bind(fence.lease_token)
                    .bind(fence.lease_deadline_epoch_micros)
                    .fetch_one(&mut *self.conn)
                    .await
            }
        }
    }

    pub(crate) async fn outbox_mark_dlx(
        &mut self,
        fence: OutboxSettlementFence<'_>,
    ) -> Result<MarkDlxRow, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT settlement_outcome::text, tenant_id, domain, contract_id, topic,
                   payload, metadata AS metadata_json, contract_version, schema_hash,
                   retry_count
            FROM rss_outbox_mark_dlx($1, $2::uuid, $3)
            "#,
        )
        .bind(fence.event_id)
        .bind(fence.lease_token)
        .bind(fence.lease_deadline_epoch_micros)
        .fetch_one(&mut *self.conn)
        .await
    }
}

impl<C: GeneratedOutboxConcern> EventingTx<'_, ServingWriteLane, C> {
    pub(crate) async fn outbox_insert_generated(
        &mut self,
        fact: &CanonicalOutboxFact<'_>,
    ) -> Result<Option<Vec<u8>>, sqlx::Error> {
        ensure_embedded_tenant(self.tenant, fact.tenant(), "canonical outbox fact")?;
        sqlx::query_scalar(
            r#"
            INSERT INTO outbox (
                event_id, tenant_id, domain, topic, contract_id, contract_version, schema_hash,
                payload, metadata, partition_key, causation_id
            )
            VALUES ($1, $2::uuid, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11)
            ON CONFLICT (event_id) DO NOTHING
            RETURNING fact_fingerprint
            "#,
        )
        .bind(fact.event_id())
        .bind(self.tenant.to_string())
        .bind(fact.domain())
        .bind(fact.topic())
        .bind(fact.contract_id())
        .bind(fact.contract_version())
        .bind(fact.schema_hash())
        .bind(fact.payload())
        .bind(fact.metadata_json())
        .bind(fact.partition_key())
        .bind(fact.causation_id())
        .fetch_optional(&mut *self.conn)
        .await
    }

    pub(crate) async fn outbox_load_fingerprint(
        &mut self,
        event_id: &str,
    ) -> Result<Option<Vec<u8>>, sqlx::Error> {
        sqlx::query_scalar("SELECT fact_fingerprint FROM outbox WHERE event_id = $1")
            .bind(event_id)
            .fetch_optional(&mut *self.conn)
            .await
    }

    pub(crate) async fn outbox_log_insert(
        &mut self,
        fact: &CanonicalOutboxFact<'_>,
        aggregate_id: &str,
    ) -> Result<Option<Vec<u8>>, sqlx::Error> {
        ensure_embedded_tenant(self.tenant, fact.tenant(), "canonical outbox fact")?;
        sqlx::query_scalar(
            r#"
            INSERT INTO outbox_log (
                event_id, tenant_id, aggregate_type, aggregate_id, topic, contract_id,
                contract_version, schema_hash, payload, metadata, causation_id, partition_key
            )
            VALUES ($1, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11, $12)
            ON CONFLICT (event_id) DO NOTHING
            RETURNING fact_fingerprint
            "#,
        )
        .bind(fact.event_id())
        .bind(self.tenant.to_string())
        .bind(fact.domain())
        .bind(aggregate_id)
        .bind(fact.topic())
        .bind(fact.contract_id())
        .bind(fact.contract_version())
        .bind(fact.schema_hash())
        .bind(fact.payload())
        .bind(fact.metadata_json())
        .bind(fact.causation_id())
        .bind(fact.partition_key())
        .fetch_optional(&mut *self.conn)
        .await
    }

    pub(crate) async fn outbox_log_load_fingerprint(
        &mut self,
        event_id: &str,
    ) -> Result<Option<Vec<u8>>, sqlx::Error> {
        sqlx::query_scalar("SELECT fact_fingerprint FROM outbox_log WHERE event_id = $1")
            .bind(event_id)
            .fetch_optional(&mut *self.conn)
            .await
    }
}

macro_rules! impl_replayed_outbox_write {
    ($lane:ty, $append:ident, $visibility:vis) => {
        impl EventingTx<'_, $lane, DlqConcern> {
            async fn outbox_insert_replayed(
                &mut self,
                replay: &ReplayedOutboxAppend,
                metadata_json: &str,
            ) -> Result<Option<Vec<u8>>, sqlx::Error> {
                sqlx::query_scalar(
                    r#"
                    INSERT INTO outbox (
                        event_id, tenant_id, domain, topic, contract_id, contract_version, schema_hash,
                        payload, metadata, partition_key, causation_id
                    )
                    VALUES ($1, $2::uuid, $3, $4, $5, $6, $7, $8, $9::jsonb, NULL, $10)
                    ON CONFLICT (event_id) DO NOTHING
                    RETURNING fact_fingerprint
                    "#,
                )
                .bind(&replay.event_id)
                .bind(self.tenant.to_string())
                .bind(&replay.domain)
                .bind(&replay.topic)
                .bind(&replay.contract_id)
                .bind(&replay.contract_version)
                .bind(&replay.schema_hash)
                .bind(replay.payload.expose())
                .bind(metadata_json)
                .bind(replay.causation_id.as_deref())
                .fetch_optional(&mut *self.conn)
                .await
            }

            async fn outbox_load_replayed_fingerprint(
                &mut self,
                event_id: &str,
            ) -> Result<Option<Vec<u8>>, sqlx::Error> {
                sqlx::query_scalar("SELECT fact_fingerprint FROM outbox WHERE event_id = $1")
                    .bind(event_id)
                    .fetch_optional(&mut *self.conn)
                    .await
            }

            async fn replayed_projection_append(
                &mut self,
                append: ProjectionAppend<'_>,
            ) -> Result<i64, sqlx::Error> {
                sqlx::query_scalar(
                    r#"
                    SELECT rss_append_projection_event(
                        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11, $12
                    )
                    "#,
                )
                .bind(append.event_id)
                .bind(append.domain)
                .bind(append.aggregate_id)
                .bind(append.topic)
                .bind(append.payload)
                .bind(append.correlation_id)
                .bind(append.contract_id)
                .bind(append.contract_version)
                .bind(append.schema_hash)
                .bind(append.metadata_json)
                .bind(append.partition_key)
                .bind(append.causation_id)
                .fetch_one(&mut *self.conn)
                .await
            }

            $visibility async fn $append(
                &mut self,
                replay: ReplayedOutboxAppend,
                projection: &DlqReplayProjection,
            ) -> Result<OutboxAppendOutcome, OutboxAppendError> {
                if self.tenant != replay.tenant {
                    return Err(OutboxAppendError::InvalidIdentity);
                }
                let metadata = SensitiveJson::new(
                    serde_json::from_slice::<serde_json::Value>(replay.metadata_json.expose())
                        .map_err(|_| OutboxAppendError::InvalidIdentity)?,
                );
                if !metadata.expose().is_object() {
                    return Err(OutboxAppendError::InvalidIdentity);
                }
                let metadata_json = std::str::from_utf8(replay.metadata_json.expose())
                    .map_err(|_| OutboxAppendError::InvalidIdentity)?;
                let tenant_id = self.tenant.to_string();
                let fingerprint = OutboxFactIdentity::new(
                    &replay.event_id,
                    &tenant_id,
                    &replay.domain,
                    &replay.topic,
                    &replay.contract_id,
                    &replay.contract_version,
                    &replay.schema_hash,
                    replay.payload.expose(),
                    None,
                    replay.causation_id.as_deref(),
                    metadata.expose(),
                )
                .fingerprint();
                let inserted = self.outbox_insert_replayed(&replay, metadata_json).await?;
                let outcome = if let Some(stored) = inserted.as_deref() {
                    classify_append_fingerprint(
                        fingerprint,
                        AppendFingerprintObservation::Inserted(stored),
                    )?
                } else {
                    let stored = self
                        .outbox_load_replayed_fingerprint(&replay.event_id)
                        .await?;
                    classify_append_fingerprint(
                        fingerprint,
                        AppendFingerprintObservation::Existing(stored.as_deref()),
                    )?
                };
                if outcome == OutboxAppendOutcome::Inserted
                    && projection.is_bound(&replay)
                {
                    let metadata_json = std::str::from_utf8(replay.metadata_json.expose())
                        .map_err(|error| sqlx::Error::Decode(Box::new(error)))?;
                    self.replayed_projection_append(ProjectionAppend {
                        event_id: &replay.event_id,
                        domain: &replay.domain,
                        aggregate_id: &replay.event_id,
                        topic: &replay.topic,
                        payload: replay.payload.expose(),
                        correlation_id: replay.causation_id.as_deref(),
                        contract_id: &replay.contract_id,
                        contract_version: &replay.contract_version,
                        schema_hash: &replay.schema_hash,
                        metadata_json,
                        partition_key: None,
                        causation_id: replay.causation_id.as_deref(),
                    })
                    .await?;
                }
                Ok(outcome)
            }
        }
    };
}

impl_replayed_outbox_write!(
    ServingWriteLane,
    outbox_append_replayed_with_projection,
    pub(crate)
);
impl_replayed_outbox_write!(MaintenanceWriteLane, dlq_append_replayed, pub(crate));

impl<C: GeneratedOutboxConcern> EventingTx<'_, ServingWriteLane, C> {
    pub(crate) async fn projection_append(
        &mut self,
        append: ProjectionAppend<'_>,
    ) -> Result<i64, sqlx::Error> {
        append_projection(&mut *self.conn, append).await
    }
}

async fn append_projection(
    conn: &mut PgConnection,
    append: ProjectionAppend<'_>,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        r#"
        SELECT rss_append_projection_event(
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11, $12
        )
        "#,
    )
    .bind(append.event_id)
    .bind(append.domain)
    .bind(append.aggregate_id)
    .bind(append.topic)
    .bind(append.payload)
    .bind(append.correlation_id)
    .bind(append.contract_id)
    .bind(append.contract_version)
    .bind(append.schema_hash)
    .bind(append.metadata_json)
    .bind(append.partition_key)
    .bind(append.causation_id)
    .fetch_one(conn)
    .await
}

#[derive(sqlx::FromRow)]
pub(crate) struct InboxBacklogRow {
    pub(crate) depth: i64,
    pub(crate) oldest_age_seconds: i64,
}

#[derive(sqlx::FromRow)]
pub(crate) struct InboxIdentityRow {
    pub(crate) domain: String,
    pub(crate) topic: String,
    pub(crate) contract_id: String,
    pub(crate) contract_version: String,
    pub(crate) schema_hash: String,
    pub(crate) status: String,
}

impl EventingTx<'_, ServingReadLane, InboxConcern> {
    pub(crate) async fn inbox_sample_backlog(
        &mut self,
        consumer_group: &str,
        lease_ttl_seconds: i64,
    ) -> Result<InboxBacklogRow, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT
              count(*)::bigint AS depth,
              COALESCE(EXTRACT(EPOCH FROM now() - MIN(claimed_at))::bigint, 0)
                AS oldest_age_seconds
            FROM inbox_receipts
            WHERE tenant_id = $1::uuid
              AND consumer_group = $2
              AND status = 'claimed'
              AND claimed_at <= now() - make_interval(secs => $3)
            "#,
        )
        .bind(self.tenant.to_string())
        .bind(consumer_group)
        .bind(lease_ttl_seconds)
        .fetch_one(&mut *self.conn)
        .await
    }
}

impl<C: InboxOperationConcern> EventingTx<'_, ServingWriteLane, C> {
    pub(crate) async fn inbox_commit_receipt(
        &mut self,
        fields: &ReceiptFields,
        event_id: &str,
        lease_token: &str,
    ) -> Result<bool, sqlx::Error> {
        ensure_embedded_tenant(self.tenant, fields.tenant, "inbox receipt")?;
        let result = sqlx::query(
            r#"
            UPDATE inbox_receipts
            SET status = 'done', committed_at = now(), updated_at = now()
            WHERE tenant_id = $1::uuid
              AND event_id = $2
              AND consumer_group = $3
              AND lease_token = $4::uuid
              AND status = 'claimed'
            "#,
        )
        .bind(self.tenant.to_string())
        .bind(event_id)
        .bind(&fields.consumer_group)
        .bind(lease_token)
        .execute(&mut *self.conn)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub(crate) async fn inbox_claim_receipt(
        &mut self,
        fields: &ReceiptFields,
        event_id: &str,
        lease_token: &str,
        lease_ttl_seconds: i64,
    ) -> Result<bool, sqlx::Error> {
        ensure_embedded_tenant(self.tenant, fields.tenant, "inbox receipt")?;
        let claimed: Option<String> = sqlx::query_scalar(
            r#"
            INSERT INTO inbox_receipts
                (tenant_id, event_id, consumer_group, domain, topic, contract_id,
                 contract_version, schema_hash, trace, correlation_id, status,
                 lease_token, receive_count, claimed_at, updated_at)
            VALUES
                ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'claimed',
                 $11::uuid, 1, now(), now())
            ON CONFLICT (tenant_id, event_id, consumer_group) DO UPDATE
              SET status = 'claimed',
                  lease_token = $11::uuid,
                  claimed_at = now(),
                  updated_at = now(),
                  receive_count = inbox_receipts.receive_count + 1
              WHERE inbox_receipts.status = 'claimed'
                AND inbox_receipts.claimed_at <= now() - make_interval(secs => $12)
                AND inbox_receipts.domain = $4
                AND inbox_receipts.topic = $5
                AND inbox_receipts.contract_id = $6
                AND inbox_receipts.contract_version = $7
                AND inbox_receipts.schema_hash = $8
            RETURNING lease_token::text
            "#,
        )
        .bind(self.tenant.to_string())
        .bind(event_id)
        .bind(&fields.consumer_group)
        .bind(&fields.domain)
        .bind(&fields.topic)
        .bind(&fields.contract_id)
        .bind(&fields.contract_version)
        .bind(&fields.schema_hash)
        .bind(fields.trace.as_deref())
        .bind(fields.correlation_id.as_deref())
        .bind(lease_token)
        .bind(lease_ttl_seconds)
        .fetch_optional(&mut *self.conn)
        .await?;
        Ok(claimed.is_some())
    }

    pub(crate) async fn inbox_load_identity(
        &mut self,
        fields: &ReceiptFields,
        event_id: &str,
    ) -> Result<Option<InboxIdentityRow>, sqlx::Error> {
        ensure_embedded_tenant(self.tenant, fields.tenant, "inbox receipt")?;
        sqlx::query_as(
            r#"
            SELECT domain, topic, contract_id, contract_version, schema_hash, status
            FROM inbox_receipts
            WHERE tenant_id = $1::uuid
              AND event_id = $2
              AND consumer_group = $3
            "#,
        )
        .bind(self.tenant.to_string())
        .bind(event_id)
        .bind(&fields.consumer_group)
        .fetch_optional(&mut *self.conn)
        .await
    }

    pub(crate) async fn inbox_extend_receipt(
        &mut self,
        fields: &ReceiptFields,
        event_id: &str,
        lease_token: &str,
    ) -> Result<bool, sqlx::Error> {
        ensure_embedded_tenant(self.tenant, fields.tenant, "inbox receipt")?;
        let result = sqlx::query(
            r#"
            UPDATE inbox_receipts
            SET claimed_at = now(), updated_at = now()
            WHERE tenant_id = $1::uuid
              AND event_id = $2
              AND consumer_group = $3
              AND lease_token = $4::uuid
              AND status = 'claimed'
            "#,
        )
        .bind(self.tenant.to_string())
        .bind(event_id)
        .bind(&fields.consumer_group)
        .bind(lease_token)
        .execute(&mut *self.conn)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub(crate) async fn inbox_release_receipt(
        &mut self,
        fields: &ReceiptFields,
        event_id: &str,
        lease_token: &str,
    ) -> Result<(), sqlx::Error> {
        ensure_embedded_tenant(self.tenant, fields.tenant, "inbox receipt")?;
        sqlx::query(
            r#"
            DELETE FROM inbox_receipts
            WHERE tenant_id = $1::uuid
              AND event_id = $2
              AND consumer_group = $3
              AND lease_token = $4::uuid
              AND status = 'claimed'
            "#,
        )
        .bind(self.tenant.to_string())
        .bind(event_id)
        .bind(&fields.consumer_group)
        .bind(lease_token)
        .execute(&mut *self.conn)
        .await?;
        Ok(())
    }
}
