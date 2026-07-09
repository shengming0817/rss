//! CDC-facing append-only outbox adapter.
//!
//! `PgOutboxCdcEmitter` is an explicit opt-in [`diport::OutboxEmitter`] implementation for
//! logical-decoding/CDC pipelines. It writes immutable rows to `outbox_log` and intentionally does
//! not participate in the relay `outbox` mutable status machine.

use consistency::Entry;
use diport::{Clock, EnvelopeSubjectId, OutboxEmitError, OutboxEmitter, OutboxEnvelopeParts};
use futures::future::BoxFuture;

use crate::PgStore;
use crate::cotx::{PgTenantPool, TxCapability, infra_tenant_scope};
use crate::outbox::{OutboxEnvelope, metadata_with_ambient, unix_secs};

/// PostgreSQL CDC outbox emitter.
///
/// This adapter is explicit opt-in and does not write to the relay `outbox` table.
pub struct PgOutboxCdcEmitter {
    pool: PgTenantPool,
    clock: Box<dyn Clock>,
}

impl PgOutboxCdcEmitter {
    /// Construct the CDC emitter from the sealed store funnel.
    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn new(store: &PgStore, clock: Box<dyn Clock>) -> Self {
        Self::new_with_store(store, clock)
    }

    pub(crate) fn new_with_store(store: &PgStore, clock: Box<dyn Clock>) -> Self {
        Self {
            pool: PgTenantPool::new(store),
            clock,
        }
    }
}

impl OutboxEmitter for PgOutboxCdcEmitter {
    async fn emit(
        &self,
        entry: Entry,
        envelope: OutboxEnvelopeParts,
    ) -> Result<(), OutboxEmitError> {
        let (contract, tenant, subject_id, actor, partition_key, causation_id) =
            envelope.into_parts();
        let aggregate_id = aggregate_id_for_log(&subject_id);
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
                infra_tenant_scope(env.tenant()),
                move |tx| {
                    Box::pin(async move {
                        append_outbox_log(tx, &entry, &env, &aggregate_id)
                            .await
                            .map(|_| ())
                            .map_err(OutboxEmitError::new)
                    }) as BoxFuture<'_, Result<(), OutboxEmitError>>
                },
                OutboxEmitError::new,
            )
            .await
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OutboxLogAppendOutcome {
    Inserted,
    AlreadyExists,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum OutboxLogAppendError {
    #[error("outbox_log insert failed")]
    Sql(#[from] sqlx::Error),
    #[error("outbox_log event_id conflict")]
    EventIdConflict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OutboxLogRecord {
    pub(crate) event_id: String,
    pub(crate) tenant_id: vocab::TenantId,
    pub(crate) aggregate_type: String,
    pub(crate) aggregate_id: String,
    pub(crate) topic: String,
    pub(crate) contract_id: String,
    pub(crate) contract_version: String,
    pub(crate) schema_hash: String,
    pub(crate) payload: Vec<u8>,
    pub(crate) metadata_json: String,
    pub(crate) causation_id: Option<String>,
}

impl OutboxLogRecord {
    pub(crate) fn from_entry_env(entry: &Entry, env: &OutboxEnvelope, aggregate_id: &str) -> Self {
        Self {
            event_id: entry.idem_key().as_str().to_string(),
            tenant_id: env.tenant(),
            aggregate_type: env.domain().to_string(),
            aggregate_id: aggregate_id.to_string(),
            topic: entry.topic().as_str().to_string(),
            contract_id: env.contract_id().to_string(),
            contract_version: env.contract_version().to_string(),
            schema_hash: env.schema_hash().to_string(),
            payload: entry.payload().to_vec(),
            metadata_json: env.metadata_json(),
            causation_id: env.causation_id().map(str::to_string),
        }
    }
}

pub(crate) async fn append_outbox_log(
    tx: &mut TxCapability<'_>,
    entry: &Entry,
    env: &OutboxEnvelope,
    aggregate_id: &str,
) -> Result<OutboxLogAppendOutcome, OutboxLogAppendError> {
    let record = OutboxLogRecord::from_entry_env(entry, env, aggregate_id);
    let result = sqlx::query(
        r#"
        INSERT INTO outbox_log (
            event_id, tenant_id, aggregate_type, aggregate_id, topic, contract_id,
            contract_version, schema_hash, payload, metadata, causation_id
        )
        VALUES ($1, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11)
        ON CONFLICT (event_id) DO NOTHING
        "#,
    )
    .bind(&record.event_id)
    .bind(record.tenant_id.to_string())
    .bind(&record.aggregate_type)
    .bind(&record.aggregate_id)
    .bind(&record.topic)
    .bind(&record.contract_id)
    .bind(&record.contract_version)
    .bind(&record.schema_hash)
    .bind(&record.payload)
    .bind(&record.metadata_json)
    .bind(record.causation_id.as_deref())
    .execute(tx.conn())
    .await?;
    if result.rows_affected() == 1 {
        return Ok(OutboxLogAppendOutcome::Inserted);
    }
    if existing_outbox_log_row_matches(tx, &record).await? {
        Ok(OutboxLogAppendOutcome::AlreadyExists)
    } else {
        Err(OutboxLogAppendError::EventIdConflict)
    }
}

async fn existing_outbox_log_row_matches(
    tx: &mut TxCapability<'_>,
    record: &OutboxLogRecord,
) -> Result<bool, sqlx::Error> {
    let same = sqlx::query_scalar::<_, bool>(
        r#"
        SELECT tenant_id = $2::uuid
           AND aggregate_type = $3
           AND aggregate_id = $4
           AND topic = $5
           AND contract_id = $6
           AND contract_version = $7
           AND schema_hash = $8
           AND payload = $9
           AND metadata = $10::jsonb
           AND causation_id IS NOT DISTINCT FROM $11
        FROM outbox_log
        WHERE event_id = $1
        "#,
    )
    .bind(&record.event_id)
    .bind(record.tenant_id.to_string())
    .bind(&record.aggregate_type)
    .bind(&record.aggregate_id)
    .bind(&record.topic)
    .bind(&record.contract_id)
    .bind(&record.contract_version)
    .bind(&record.schema_hash)
    .bind(&record.payload)
    .bind(&record.metadata_json)
    .bind(record.causation_id.as_deref())
    .fetch_optional(tx.conn())
    .await?;
    Ok(same.unwrap_or(false))
}

fn aggregate_id_for_log(subject_id: &EnvelopeSubjectId) -> String {
    subject_id.as_str().to_string()
}

#[cfg(test)]
mod tests {
    use consistency::{IdemKey, OutboxPayload, PartitionKey, Topic};

    use super::{OutboxLogRecord, aggregate_id_for_log};
    use crate::outbox::{OutboxEnvelope, OutboxMetadata};

    const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const HASH: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[allow(clippy::unwrap_used)]
    fn tenant() -> vocab::TenantId {
        vocab::TenantId::parse(TENANT).unwrap()
    }

    fn contract() -> vocab::ContractBinding {
        vocab::ContractBinding::from_static("identity", "identity.session-created", "v1", HASH)
    }

    #[allow(clippy::unwrap_used)]
    fn entry(event_id: &str) -> consistency::Entry {
        consistency::Entry::new(
            Topic::parse("identity.session-created").unwrap(),
            IdemKey::parse(event_id).unwrap(),
            OutboxPayload::from_reviewed_event_bytes(b"payload".to_vec()),
        )
    }

    #[allow(clippy::unwrap_used)]
    fn env() -> OutboxEnvelope {
        OutboxEnvelope::new(
            "identity".to_string(),
            "identity.session-created".to_string(),
            OutboxMetadata::new(42, tenant(), contract()),
        )
        .with_partition_key_opt(Some(PartitionKey::parse("tenant-7:session-9").unwrap()))
        .with_causation_id_opt(Some(
            diport::EnvelopeCausationId::from_opaque("cause-1").unwrap(),
        ))
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn aggregate_id_uses_subject_id_not_partition_key() {
        let subject_id =
            diport::EnvelopeSubjectId::from_opaque("subject-cdc-aggregate").expect("subject id");
        assert_eq!(aggregate_id_for_log(&subject_id), "subject-cdc-aggregate");
    }

    #[test]
    fn outbox_log_record_preserves_envelope_contract_and_payload_fields() {
        let entry = entry("evt-cdc-record");
        let record = OutboxLogRecord::from_entry_env(&entry, &env(), "subject-cdc-aggregate");

        assert_eq!(record.event_id, "evt-cdc-record");
        assert_eq!(record.tenant_id, tenant());
        assert_eq!(record.aggregate_type, "identity");
        assert_eq!(record.aggregate_id, "subject-cdc-aggregate");
        assert_eq!(record.topic, "identity.session-created");
        assert_eq!(record.contract_id, "identity.session-created");
        assert_eq!(record.contract_version, "v1");
        assert_eq!(record.schema_hash, HASH);
        assert_eq!(record.payload, b"payload");
        assert_eq!(record.causation_id.as_deref(), Some("cause-1"));
        assert!(
            record.metadata_json.contains(r#""tenantId":"#),
            "metadata should carry sealed tenant header: {}",
            record.metadata_json
        );
        assert!(
            record.metadata_json.contains(r#""schemaHash":"#),
            "metadata should carry sealed schema hash: {}",
            record.metadata_json
        );
        assert!(
            record.metadata_json.contains(r#""occurredAt":42"#),
            "metadata should carry sealed occurredAt source: {}",
            record.metadata_json
        );
    }

    #[test]
    fn outbox_log_migration_matches_adapter_contract() {
        let sql = include_str!("../migrations/0042_create_outbox_log.sql");
        for needle in [
            "CREATE TABLE outbox_log",
            "event_id text NOT NULL",
            "tenant_id uuid NOT NULL",
            "aggregate_type text NOT NULL",
            "aggregate_id text NOT NULL",
            "topic text NOT NULL",
            "contract_id text NOT NULL",
            "contract_version text NOT NULL",
            "schema_hash text NOT NULL",
            "payload bytea NOT NULL",
            "metadata jsonb NOT NULL",
            "metadata ? 'schemaVersion'",
            "metadata ? 'schemaHash'",
            "causation_id text NULL",
            "CONSTRAINT outbox_log_event_id_unique UNIQUE (event_id)",
            "ALTER TABLE outbox_log FORCE ROW LEVEL SECURITY",
            "GRANT SELECT, INSERT ON outbox_log TO rss_app",
            "REVOKE UPDATE, DELETE ON outbox_log FROM rss_app",
        ] {
            assert!(sql.contains(needle), "0042 migration missing `{needle}`");
        }
    }

    #[test]
    fn outbox_log_transport_headers_are_generated_from_metadata() {
        let sql = include_str!("../migrations/0049_outbox_log_transport_headers.sql");
        for needle in [
            "ADD COLUMN occurred_at text GENERATED ALWAYS AS (metadata ->> 'occurredAt') STORED",
            "ADD COLUMN trace text GENERATED ALWAYS AS (metadata ->> 'trace') STORED",
            "ADD COLUMN correlation_id text GENERATED ALWAYS AS (metadata ->> 'correlation') STORED",
            "outbox_log_metadata_occurred_at_present",
            "jsonb_typeof(metadata -> 'occurredAt') = 'number'",
            "outbox_log_trace_valid",
            "octet_length(trace) <= 512",
            "outbox_log_correlation_id_valid",
            "octet_length(correlation_id) <= 256",
        ] {
            assert!(sql.contains(needle), "0049 migration missing `{needle}`");
        }
    }

    #[test]
    fn migration_readme_documents_cdc_generated_header_columns() {
        let readme = include_str!("../migrations/README.md");
        for needle in [
            "`0049`",
            "`occurred_at`、`trace`、`correlation_id`",
            "stored generated columns",
            "nullable trace/correlation 保持 persisted-only",
            "`CREATE PUBLICATION ... WITH (publish_generated_columns = stored)`",
            "PostgreSQL 18+",
        ] {
            assert!(
                readme.contains(needle),
                "migration README must document CDC generated-column boundary `{needle}`"
            );
        }
    }
}
