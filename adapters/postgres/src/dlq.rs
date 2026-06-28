//! PostgreSQL DLQ inspection/replay adapter (#1214).

use diport::{DeadLetterSource, KEY_TENANT_ID};
use eventexec::{
    DlqEntryKind, DlqEntrySummary, DlqError, DlqListQuery, DlqListResult, DlqRedriveOutcome,
    DlqRedriveRequest, DlqReplayOutcome, DlqReplayRequest, DlqStore,
};

use crate::PgStore;
use crate::cotx::PgTenantPool;
use crate::dead_letter::decode_original_entry;
use crate::outbox::{STATUS_DLX, STATUS_PENDING};

/// PostgreSQL implementation of [`DlqStore`].
pub struct PgDlqStore {
    tenant_pool: PgTenantPool,
    global_pool: sqlx::PgPool,
}

impl PgStore {
    /// 构造 DLQ inspection/replay adapter（pool clone 自 `PgStore`，轻量）。
    pub(crate) fn dlq(&self) -> PgDlqStore {
        PgDlqStore {
            tenant_pool: PgTenantPool::new(self),
            global_pool: self.pool.clone(),
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
        self.tenant_pool
            .write(
                request.tenant(),
                move |conn| {
                    Box::pin(async move {
                        let row: Option<(
                            String,
                            String,
                            String,
                            String,
                            serde_json::Value,
                            String,
                            serde_json::Value,
                        )> = sqlx::query_as(
                            r#"
                            SELECT source_kind, message_id, domain, contract_id, original_entry, topic, metadata
                            FROM dead_letter
                            WHERE id = $1::uuid
                              AND tenant_id = $2::uuid
                            "#,
                        )
                        .bind(request.dead_letter_id().as_str())
                        .bind(request.tenant().to_string())
                        .fetch_optional(&mut *conn)
                        .await
                        .map_err(db_error("replay.fetch_dead_letter"))?;

                        let Some((source, message_id, domain, contract_id, original_entry, topic, metadata)) =
                            row
                        else {
                            return Err(DlqError::NotFound);
                        };

                        match parse_source(&source)? {
                            DeadLetterSource::Consumer | DeadLetterSource::Saga => {}
                            DeadLetterSource::Legacy | DeadLetterSource::OutboxRelay => {
                                return Err(DlqError::NotReplayable);
                            }
                        }

                        let payload = decode_original_entry(&original_entry).map_err(|_| {
                            tracing::warn!(
                                target: "postgres",
                                operation = "replay.decode_original_entry",
                                dead_letter_id = %request.dead_letter_id(),
                                tenant_id = %request.tenant(),
                                "dlq: invalid original_entry payload"
                            );
                            DlqError::InvalidPayload
                        })?;
                        let metadata = replay_metadata(
                            metadata,
                            request.tenant(),
                            request.dead_letter_id().as_str(),
                            &message_id,
                        );

                        let result = sqlx::query(
                            r#"
                            INSERT INTO outbox (event_id, domain, topic, contract_id, payload, metadata, status)
                            VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7)
                            ON CONFLICT (event_id) DO NOTHING
                            "#,
                        )
                        .bind(request.replay_id().as_str())
                        .bind(domain)
                        .bind(topic)
                        .bind(contract_id)
                        .bind(payload)
                        .bind(metadata.to_string())
                        .bind(STATUS_PENDING)
                        .execute(&mut *conn)
                        .await
                        .map_err(db_error("replay.insert_outbox"))?;

                        if result.rows_affected() == 1 {
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
        let result = sqlx::query(
            r#"
            UPDATE outbox
            SET status = $3,
                retry_count = 0,
                retry_after = NULL,
                lease_token = NULL,
                updated_at = now()
            WHERE event_id = $1
              AND status = $4
              AND metadata ->> $5 = $2
            "#,
        )
        .bind(request.event_id().as_str())
        .bind(request.tenant().to_string())
        .bind(STATUS_PENDING)
        .bind(STATUS_DLX)
        .bind(KEY_TENANT_ID)
        .execute(&self.global_pool)
        .await
        .map_err(db_error("redrive.update_outbox"))?;

        if result.rows_affected() == 1 {
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
        let rows: Vec<DeadLetterRow> = self
            .tenant_pool
            .read(tenant, move |conn| {
                Box::pin(async move {
                    sqlx::query_as(
                        r#"
                        SELECT id::text,
                               message_id,
                               domain,
                               contract_id,
                               topic,
                               COALESCE(jsonb_array_length(original_entry -> 'bytes'), 0)::bigint,
                               error_summary,
                               num_attempts,
                               source_kind,
                               EXTRACT(EPOCH FROM last_attempt_at)::bigint
                        FROM dead_letter
                        WHERE tenant_id = $1::uuid
                          AND source_kind <> $5
                          AND ($2::text IS NULL OR domain = $2)
                          AND ($3::text IS NULL OR source_kind = $3)
                        ORDER BY last_attempt_at DESC
                        LIMIT $4
                        "#,
                    )
                    .bind(tenant.to_string())
                    .bind(domain)
                    .bind(source)
                    .bind(i64::from(fetch_limit))
                    .bind(DeadLetterSource::OutboxRelay.as_str())
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

        let rows: Vec<OutboxRow> = sqlx::query_as(
            r#"
            SELECT o.event_id,
                   o.domain,
                   o.contract_id,
                   o.topic,
                   octet_length(o.payload)::bigint,
                   o.retry_count,
                   EXTRACT(EPOCH FROM o.updated_at)::bigint
            FROM outbox o
            WHERE o.status = $1
              AND o.metadata ->> $2 = $3
              AND ($4::text IS NULL OR o.domain = $4)
            ORDER BY o.updated_at DESC
            LIMIT $5
            "#,
        )
        .bind(STATUS_DLX)
        .bind(KEY_TENANT_ID)
        .bind(query.tenant().to_string())
        .bind(query.domain())
        .bind(i64::from(query.fetch_limit()))
        .fetch_all(&self.global_pool)
        .await
        .map_err(db_error("list.fetch_outbox_dlx"))?;

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
    i64,
    String,
    i32,
    String,
    i64,
);
type OutboxRow = (String, String, String, String, i64, i32, i64);

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
        let (event_id, domain, contract_id, topic, payload_len, attempts, ts) = self;
        Ok(DlqEntrySummary::new(
            DlqEntryKind::OutboxDlx,
            event_id.clone(),
            DeadLetterSource::OutboxRelay,
            tenant,
            event_id,
            domain,
            contract_id,
            topic,
            u64_from_i64(payload_len)?,
            "outbox relay dlx",
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
            10,
            1_700_000_000,
        );
        let summary = row.into_summary(tenant).expect("summary");
        assert_eq!(summary.kind(), DlqEntryKind::OutboxDlx);
        assert_eq!(summary.payload_len(), 9);
        assert!(!format!("{summary:?}").contains("payload:"));
    }
}
