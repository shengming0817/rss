//! PostgreSQL DLQ inspection/replay adapter (#1214).

use diport::key_provider::{KeyProviderError, KeyProviderErrorKind};
use diport::{
    DeadLetterSource, EnvelopeSchemaHash, EnvelopeSchemaVersion, KEY_SCHEMA_HASH,
    KEY_SCHEMA_VERSION, KEY_TENANT_ID,
};
use eventexec::{
    DlqEntryKind, DlqEntrySummary, DlqError, DlqListQuery, DlqListResult, DlqRedriveOutcome,
    DlqRedriveRequest, DlqReplayOutcome, DlqReplayRequest, DlqStore,
};

use crate::PgStore;
use crate::cotx::PgTenantPool;
use crate::dead_letter_payload::{DlxPayloadContext, DlxPayloadProtector};
use crate::outbox::{
    OutboxAppendOutcome, ReplayedOutboxAppend, STATUS_DLX, append_replayed_outbox_with_projection,
};
use crate::projection_events::ProjectionWriteRegistry;

const KEY_RELAY_FAILURE_REASON: &str = "relayFailureReason";
const OUTBOX_RELAY_DLX_FALLBACK_SUMMARY: &str = "outbox relay dlx";
#[cfg(test)]
const LIST_DEAD_LETTER_BIND_COUNT: u32 = 9;
const LIST_DEAD_LETTER_SQL: &str = r#"
    SELECT id::text,
           message_id,
           domain,
           contract_id,
           topic,
           consumer_group,
           original_entry_payload_len,
           error_summary,
           num_attempts,
           source_kind,
           EXTRACT(EPOCH FROM last_attempt_at)::bigint
    FROM dead_letter
    WHERE tenant_id = $1::uuid
      AND source_kind <> $4
      AND ($2::text IS NULL OR domain = $2)
      AND ($3::text IS NULL OR source_kind = $3)
      AND (
            $5::bigint IS NULL
         OR EXTRACT(EPOCH FROM last_attempt_at)::bigint < $5
         OR (
                EXTRACT(EPOCH FROM last_attempt_at)::bigint = $5
            AND $6::text > $7
            )
         OR (
                EXTRACT(EPOCH FROM last_attempt_at)::bigint = $5
            AND $6::text = $7
            AND id::text > $8
            )
      )
    ORDER BY last_attempt_at DESC, id ASC
    LIMIT $9
    "#;

/// PostgreSQL implementation of [`DlqStore`].
pub struct PgDlqStore {
    tenant_pool: PgTenantPool,
    payload_protector: DlxPayloadProtector,
    projection_registry: ProjectionWriteRegistry,
}

impl PgStore {
    /// 构造 DLQ inspection/replay adapter（pool clone 自 `PgStore`，轻量）。
    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn dlq(&self, payload_protector: DlxPayloadProtector) -> PgDlqStore {
        self.dlq_with_projection_registry(payload_protector, ProjectionWriteRegistry::empty())
    }

    pub(crate) fn dlq_with_projection_registry(
        &self,
        payload_protector: DlxPayloadProtector,
        projection_registry: ProjectionWriteRegistry,
    ) -> PgDlqStore {
        PgDlqStore {
            tenant_pool: PgTenantPool::new(self),
            payload_protector,
            projection_registry,
        }
    }
}

impl DlqStore for PgDlqStore {
    async fn list_dlq(&self, query: DlqListQuery) -> Result<DlqListResult, DlqError> {
        let mut rows = self.list_dead_letter(&query).await?;
        rows.extend(self.list_outbox_dlx(&query).await?);
        Ok(DlqListResult::from_sorted_rows(&query, rows))
    }

    async fn replay_dead_letter(
        &self,
        request: DlqReplayRequest,
    ) -> Result<DlqReplayOutcome, DlqError> {
        let payload_protector = self.payload_protector.clone();
        let projection_registry = self.projection_registry;
        self.tenant_pool
            .write(
                request.tenant(),
                move |conn| {
                    let payload_protector = payload_protector.clone();
                    Box::pin(async move {
                        let row: Option<ReplayDeadLetterRow> = sqlx::query_as(
                            r#"
                            SELECT source_kind, message_id, domain, contract_id, original_entry,
                                   original_entry_key_ref, topic, consumer_group, metadata
                            FROM dead_letter
                            WHERE id = $1::uuid
                              AND tenant_id = $2::uuid
                            "#,
                        )
                        .bind(request.dead_letter_id().as_str())
                        .bind(request.tenant().to_string())
                        .fetch_optional(conn.conn())
                        .await
                        .map_err(db_error("replay.fetch_dead_letter"))?;

                        let Some((
                            source,
                            message_id,
                            domain,
                            contract_id,
                            original_entry,
                            key_ref,
                            topic,
                            consumer_group,
                            metadata,
                        )) = row
                        else {
                            return Err(DlqError::NotFound);
                        };

                        match parse_source(&source)? {
                            DeadLetterSource::Consumer => {}
                            DeadLetterSource::Legacy
                            | DeadLetterSource::OutboxRelay
                            | DeadLetterSource::Projection
                            | DeadLetterSource::Saga => {
                                return Err(DlqError::NotReplayable);
                            }
                        }

                        let payload = payload_protector
                            .decrypt(
                                DlxPayloadContext::new(
                                    request.tenant(),
                                    &source,
                                    &domain,
                                    &contract_id,
                                    &topic,
                                    consumer_group.as_deref(),
                                    &message_id,
                                ),
                                &original_entry,
                                &key_ref,
                            )
                            .await
                            .map_err(|err| {
                                dlq_payload_error(
                                    "replay.decrypt_original_entry",
                                    request.dead_letter_id().as_str(),
                                    request.tenant(),
                                    err,
                                )
                            })?;
                        let (contract_version, schema_hash) = replay_schema_columns(&metadata)?;
                        let metadata = replay_metadata(
                            metadata,
                            request.tenant(),
                            request.dead_letter_id().as_str(),
                            &message_id,
                        );

                        let outcome = append_replayed_outbox_with_projection(
                            conn,
                            ReplayedOutboxAppend {
                                event_id: request.replay_id().as_str().to_string(),
                                tenant: request.tenant(),
                                domain,
                                topic,
                                contract_id,
                                contract_version,
                                schema_hash,
                                payload,
                                metadata_json: metadata.to_string(),
                                causation_id: None,
                            },
                            &projection_registry,
                        )
                        .await
                        .map_err(db_error("replay.insert_outbox"))?;

                        if outcome == OutboxAppendOutcome::Inserted {
                            Ok(DlqReplayOutcome::Inserted)
                        } else {
                            Ok(DlqReplayOutcome::AlreadyExists)
                        }
                    })
                },
                db_error("replay.tx"),
            )
            .await
    }

    async fn redrive_outbox(
        &self,
        request: DlqRedriveRequest,
    ) -> Result<DlqRedriveOutcome, DlqError> {
        let event_id = request.event_id().as_str().to_string();
        let tenant = request.tenant();
        let result = self
            .tenant_pool
            .write(
                tenant,
                move |conn| {
                    let event_id = event_id.clone();
                    Box::pin(async move {
                        let row: (i64,) = sqlx::query_as(
                            r#"
                            SELECT rss_outbox_redrive($1, $2::uuid)
                            "#,
                        )
                        .bind(&event_id)
                        .bind(tenant.to_string())
                        .fetch_one(conn.conn())
                        .await
                        .map_err(db_error("redrive.update_outbox"))?;
                        Ok(row.0)
                    })
                },
                db_error("redrive.tx"),
            )
            .await?;

        if result == 1 {
            Ok(DlqRedriveOutcome::Redriven)
        } else {
            Ok(DlqRedriveOutcome::NotFound)
        }
    }
}

impl PgDlqStore {
    async fn list_dead_letter(
        &self,
        query: &DlqListQuery,
    ) -> Result<Vec<DlqEntrySummary>, DlqError> {
        if query.source() == Some(DeadLetterSource::OutboxRelay) {
            return Ok(Vec::new());
        }

        let source = query
            .source()
            .map(DeadLetterSource::as_str)
            .map(str::to_owned);
        let tenant = query.tenant();
        let domain = query.domain().map(str::to_owned);
        let fetch_limit = query.fetch_limit();
        let cursor_epoch = query.cursor().map(|cursor| cursor.last_epoch_secs());
        let cursor_kind = query
            .cursor()
            .map(|cursor| cursor.last_kind().cursor_part().to_string());
        let cursor_id = query.cursor().map(|cursor| cursor.last_id().to_string());
        let rows: Vec<DeadLetterRow> = self
            .tenant_pool
            .read(tenant, move |conn| {
                Box::pin(async move {
                    sqlx::query_as(LIST_DEAD_LETTER_SQL)
                        .bind(tenant.to_string())
                        .bind(domain)
                        .bind(source)
                        .bind(DeadLetterSource::OutboxRelay.as_str())
                        .bind(cursor_epoch)
                        .bind(DlqEntryKind::DeadLetter.cursor_part())
                        .bind(cursor_kind)
                        .bind(cursor_id)
                        .bind(i64::from(fetch_limit))
                        .fetch_all(&mut *conn)
                        .await
                })
            })
            .await
            .map_err(db_error("list.fetch_dead_letter"))?;

        rows.into_iter()
            .map(|row| row.into_summary(DlqEntryKind::DeadLetter, query.tenant()))
            .collect()
    }

    async fn list_outbox_dlx(
        &self,
        query: &DlqListQuery,
    ) -> Result<Vec<DlqEntrySummary>, DlqError> {
        if let Some(source) = query.source()
            && source != DeadLetterSource::OutboxRelay
        {
            return Ok(Vec::new());
        }

        let tenant = query.tenant();
        let domain = query.domain().map(ToString::to_string);
        let cursor_epoch = query.cursor().map(|cursor| cursor.last_epoch_secs());
        let cursor_kind = query
            .cursor()
            .map(|cursor| cursor.last_kind().cursor_part().to_string());
        let cursor_id = query.cursor().map(|cursor| cursor.last_id().to_string());
        let limit = i64::from(query.fetch_limit());
        let rows: Vec<OutboxRow> = self
            .tenant_pool
            .read_map(
                tenant,
                move |conn| {
                    let domain = domain.clone();
                    let cursor_kind = cursor_kind.clone();
                    let cursor_id = cursor_id.clone();
                    Box::pin(async move {
                        sqlx::query_as(
                            r#"
                            SELECT o.event_id,
                                   o.domain,
                                   o.contract_id,
                                   o.topic,
                                   octet_length(o.payload)::bigint,
                                   COALESCE(dl.metadata ->> $8, dl.error_summary, $9),
                                   o.retry_count,
                                   EXTRACT(EPOCH FROM o.updated_at)::bigint
                            FROM outbox o
                            LEFT JOIN LATERAL (
                                SELECT dl.error_summary, dl.metadata
                                FROM dead_letter dl
                                WHERE dl.tenant_id = o.tenant_id
                                  AND dl.message_id = o.event_id
                                  AND dl.source_kind = $10
                                ORDER BY dl.last_attempt_at DESC, dl.id DESC
                                LIMIT 1
                            ) dl ON true
                            WHERE o.status = $1
                              AND o.tenant_id = $2::uuid
                              AND ($3::text IS NULL OR o.domain = $3)
                              AND (
                                    $4::bigint IS NULL
                                 OR EXTRACT(EPOCH FROM o.updated_at)::bigint < $4
                                 OR (
                                        EXTRACT(EPOCH FROM o.updated_at)::bigint = $4
                                    AND $5::text > $6
                                    )
                                 OR (
                                        EXTRACT(EPOCH FROM o.updated_at)::bigint = $4
                                    AND $5::text = $6
                                    AND o.event_id > $7
                                    )
                              )
                            ORDER BY o.updated_at DESC, o.event_id ASC
                            LIMIT $11
                            "#,
                        )
                        .bind(STATUS_DLX)
                        .bind(tenant.to_string())
                        .bind(domain)
                        .bind(cursor_epoch)
                        .bind(DlqEntryKind::OutboxDlx.cursor_part())
                        .bind(cursor_kind)
                        .bind(cursor_id)
                        .bind(KEY_RELAY_FAILURE_REASON)
                        .bind(OUTBOX_RELAY_DLX_FALLBACK_SUMMARY)
                        .bind(DeadLetterSource::OutboxRelay.as_str())
                        .bind(limit)
                        .fetch_all(&mut *conn)
                        .await
                        .map_err(db_error("list.fetch_outbox_dlx"))
                    })
                },
                db_error("list.outbox_tx"),
            )
            .await?;

        rows.into_iter()
            .map(|row| row.into_summary(query.tenant()))
            .collect()
    }
}

type DeadLetterRow = (
    String,
    String,
    String,
    String,
    String,
    Option<String>,
    i64,
    String,
    i32,
    String,
    i64,
);
type ReplayDeadLetterRow = (
    String,
    String,
    String,
    String,
    serde_json::Value,
    String,
    String,
    Option<String>,
    serde_json::Value,
);
type OutboxRow = (String, String, String, String, i64, String, i32, i64);

trait DeadLetterRowExt {
    fn into_summary(
        self,
        kind: DlqEntryKind,
        tenant: vocab::TenantId,
    ) -> Result<DlqEntrySummary, DlqError>;
}

impl DeadLetterRowExt for DeadLetterRow {
    fn into_summary(
        self,
        kind: DlqEntryKind,
        tenant: vocab::TenantId,
    ) -> Result<DlqEntrySummary, DlqError> {
        let (
            id,
            message_id,
            domain,
            contract_id,
            topic,
            consumer_group,
            payload_len,
            summary,
            attempts,
            source,
            ts,
        ) = self;
        Ok(DlqEntrySummary::new(
            kind,
            id,
            parse_source(&source)?,
            tenant,
            message_id,
            domain,
            contract_id,
            topic,
            consumer_group,
            u64_from_i64(payload_len)?,
            summary,
            u32::try_from(attempts).map_err(|_| DlqError::Store)?,
            ts,
        ))
    }
}

trait OutboxRowExt {
    fn into_summary(self, tenant: vocab::TenantId) -> Result<DlqEntrySummary, DlqError>;
}

impl OutboxRowExt for OutboxRow {
    fn into_summary(self, tenant: vocab::TenantId) -> Result<DlqEntrySummary, DlqError> {
        let (event_id, domain, contract_id, topic, payload_len, summary, attempts, ts) = self;
        Ok(DlqEntrySummary::new(
            DlqEntryKind::OutboxDlx,
            event_id.clone(),
            DeadLetterSource::OutboxRelay,
            tenant,
            event_id,
            domain,
            contract_id,
            topic,
            None,
            u64_from_i64(payload_len)?,
            summary,
            u32::try_from(attempts).map_err(|_| DlqError::Store)?,
            ts,
        ))
    }
}

fn replay_metadata(
    metadata: serde_json::Value,
    tenant: vocab::TenantId,
    dead_letter_id: &str,
    original_message_id: &str,
) -> serde_json::Value {
    let mut map = match metadata {
        serde_json::Value::Object(map) => map,
        _ => serde_json::Map::new(),
    };
    map.insert(
        KEY_TENANT_ID.to_string(),
        serde_json::Value::String(tenant.to_string()),
    );
    map.insert(
        "deadLetterId".to_string(),
        serde_json::Value::String(dead_letter_id.to_string()),
    );
    map.insert(
        "originalMessageId".to_string(),
        serde_json::Value::String(original_message_id.to_string()),
    );
    serde_json::Value::Object(map)
}

fn replay_schema_columns(metadata: &serde_json::Value) -> Result<(String, String), DlqError> {
    let Some(obj) = metadata.as_object() else {
        return Err(DlqError::InvalidSchemaHeaders);
    };
    let Some(version) = obj
        .get(KEY_SCHEMA_VERSION)
        .and_then(serde_json::Value::as_str)
    else {
        return Err(DlqError::InvalidSchemaHeaders);
    };
    let Some(hash) = obj.get(KEY_SCHEMA_HASH).and_then(serde_json::Value::as_str) else {
        return Err(DlqError::InvalidSchemaHeaders);
    };
    let version = EnvelopeSchemaVersion::parse(version.to_string())
        .map_err(|_| DlqError::InvalidSchemaHeaders)?;
    let hash =
        EnvelopeSchemaHash::parse(hash.to_string()).map_err(|_| DlqError::InvalidSchemaHeaders)?;
    Ok((version.as_str().to_string(), hash.as_str().to_string()))
}

fn parse_source(raw: &str) -> Result<DeadLetterSource, DlqError> {
    DeadLetterSource::parse(raw).ok_or(DlqError::Store)
}

fn u64_from_i64(n: i64) -> Result<u64, DlqError> {
    u64::try_from(n).map_err(|_| DlqError::Store)
}

fn db_error(operation: &'static str) -> impl Fn(sqlx::Error) -> DlqError {
    move |e| {
        tracing::warn!(
            target: "postgres",
            operation,
            error = %secure::redact_error(&e),
            "dlq: db error"
        );
        DlqError::Store
    }
}

fn dlq_payload_error(
    operation: &'static str,
    dead_letter_id: &str,
    tenant: vocab::TenantId,
    err: KeyProviderError,
) -> DlqError {
    let kind = err.kind();
    tracing::warn!(
        target: "postgres",
        operation,
        dead_letter_id,
        tenant_id = %tenant,
        key_provider_kind = ?kind,
        "dlq: original_entry payload decrypt failed"
    );
    match kind {
        KeyProviderErrorKind::Rejected => DlqError::InvalidPayload,
        KeyProviderErrorKind::Unavailable | KeyProviderErrorKind::Timeout => {
            DlqError::PayloadKeyUnavailable
        }
        KeyProviderErrorKind::Forbidden | KeyProviderErrorKind::NotFound => {
            DlqError::PayloadKeyForbidden
        }
        _ => DlqError::PayloadKeyUnavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::expect_used)]
    // reason: unit test fixture uses a known canonical tenant id.
    fn replay_metadata_overwrites_tenant_and_keeps_correlation() {
        let tenant = vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
            .expect("canonical tenant");
        let metadata = serde_json::json!({
            "tenantId": "11111111-1111-1111-1111-111111111111",
            "correlation": "corr-1"
        });
        let result = replay_metadata(metadata, tenant, "dl-1", "msg-1");
        assert_eq!(
            result["tenantId"],
            serde_json::Value::String("f47ac10b-58cc-4372-a567-0e02b2c3d479".to_string())
        );
        assert_eq!(result["correlation"], "corr-1");
        assert_eq!(result["deadLetterId"], "dl-1");
        assert_eq!(result["originalMessageId"], "msg-1");
    }

    #[test]
    fn replay_schema_columns_round_trips_valid_headers() -> Result<(), DlqError> {
        let metadata = serde_json::json!({
            "schemaVersion": "v1",
            "schemaHash": "sha256:999d2b098e6c89de6d1841416099942cad21279843456dfc287b1fcaa67a7516"
        });
        let columns = replay_schema_columns(&metadata)?;
        assert_eq!(
            columns,
            (
                "v1".to_string(),
                "sha256:999d2b098e6c89de6d1841416099942cad21279843456dfc287b1fcaa67a7516"
                    .to_string()
            )
        );
        Ok(())
    }

    #[test]
    fn replay_schema_columns_rejects_missing_or_invalid_headers_as_schema_headers() {
        for metadata in [
            serde_json::json!(null),
            serde_json::json!({}),
            serde_json::json!({ "schemaHash": "sha256:999d2b098e6c89de6d1841416099942cad21279843456dfc287b1fcaa67a7516" }),
            serde_json::json!({ "schemaVersion": "v1" }),
            serde_json::json!({
                "schemaVersion": "1",
                "schemaHash": "sha256:999d2b098e6c89de6d1841416099942cad21279843456dfc287b1fcaa67a7516"
            }),
            serde_json::json!({
                "schemaVersion": "v1",
                "schemaHash": "sha256:999D2B098E6C89DE6D1841416099942CAD21279843456DFC287B1FCAA67A7516"
            }),
        ] {
            assert!(
                matches!(
                    replay_schema_columns(&metadata),
                    Err(DlqError::InvalidSchemaHeaders)
                ),
                "metadata should be invalid replay schema headers: {metadata}"
            );
        }
    }

    #[test]
    fn list_dead_letter_sql_placeholders_match_bind_count() {
        assert_eq!(
            max_pg_placeholder(LIST_DEAD_LETTER_SQL),
            LIST_DEAD_LETTER_BIND_COUNT
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: unit test fixture uses a known canonical tenant id and summary result.
    fn legacy_outbox_summary_has_no_payload() {
        let tenant = vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
            .expect("canonical tenant");
        let row: OutboxRow = (
            "event-1".to_string(),
            "identity".to_string(),
            "contract-session".to_string(),
            "session.created".to_string(),
            9,
            "envelope_invalid_schema_hash".to_string(),
            10,
            1_700_000_000,
        );
        let summary = row.into_summary(tenant).expect("summary");
        assert_eq!(summary.kind(), DlqEntryKind::OutboxDlx);
        assert_eq!(summary.error_summary(), "envelope_invalid_schema_hash");
        assert_eq!(summary.payload_len(), 9);
        assert!(!format!("{summary:?}").contains("payload:"));
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: unit test fixture uses a known canonical tenant id.
    fn key_provider_rejected_maps_to_invalid_payload() {
        let err = KeyProviderError::new(
            KeyProviderErrorKind::Rejected,
            std::io::Error::other("bad ciphertext"),
        );
        let tenant = vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
            .expect("canonical tenant");
        assert!(matches!(
            dlq_payload_error("test", "dl-1", tenant, err),
            DlqError::InvalidPayload
        ));
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: unit test fixture uses a known canonical tenant id.
    fn key_provider_unavailable_stays_retryable_dependency_error() {
        let err = KeyProviderError::new(
            KeyProviderErrorKind::Unavailable,
            std::io::Error::other("kms unavailable"),
        );
        let tenant = vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
            .expect("canonical tenant");
        assert!(matches!(
            dlq_payload_error("test", "dl-1", tenant, err),
            DlqError::PayloadKeyUnavailable
        ));
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: unit test fixture uses a known canonical tenant id.
    fn key_provider_forbidden_stays_operator_config_error() {
        let err = KeyProviderError::new(
            KeyProviderErrorKind::Forbidden,
            std::io::Error::other("policy denied"),
        );
        let tenant = vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
            .expect("canonical tenant");
        assert!(matches!(
            dlq_payload_error("test", "dl-1", tenant, err),
            DlqError::PayloadKeyForbidden
        ));
    }

    fn max_pg_placeholder(sql: &str) -> u32 {
        let mut max = 0;
        let mut chars = sql.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch != '$' {
                continue;
            }
            let mut n = String::new();
            while let Some(next) = chars.peek().copied() {
                if !next.is_ascii_digit() {
                    break;
                }
                n.push(next);
                chars.next();
            }
            if let Ok(value) = n.parse::<u32>() {
                max = max.max(value);
            }
        }
        max
    }
}
