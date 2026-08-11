//! PostgreSQL DLQ inspection/replay adapter (#1214).

use crate::cotx::eventing::{
    DeadLetterRow, DlqExpiredResolution, DlqFinishAudit, DlqListFilter, DlqReplayProjection,
    OutboxDlxRow, ReplayedOutboxWriteError,
};
use crate::cotx::{MaintenanceReadLane, MaintenanceWriteLane, TenantDb, TenantScopeHandle};
use crate::dead_letter_payload::{DlxPayloadContext, DlxPayloadProtector, SensitiveJson};
use crate::outbox::{OutboxAppendError, ReplayedOutboxAppend};
use crate::pool::VerifiedPgMaintenanceStore;
use consistency::OutboxAppendOutcome;
use diport::key_provider::{KeyProviderError, KeyProviderErrorKind};
use diport::{
    DeadLetterSource, EnvelopeSchemaHash, EnvelopeSchemaVersion, KEY_SCHEMA_HASH,
    KEY_SCHEMA_VERSION, KEY_TENANT_ID,
};
use eventexec::{
    DlqEntryKind, DlqEntrySummary, DlqError, DlqInspectRequest, DlqInspectTarget, DlqListQuery,
    DlqListResult, DlqMutationKind, DlqRedriveOutcome, DlqRedriveRequest, DlqReplayOutcome,
    DlqReplayRequest, DlqReplayStoreStage, DlqStore, DurablyAuditedDlqMutation,
    OutboxExpiredResolutionOutcome, OutboxExpiredResolutionRequest, record_dlq_mutation_error,
    record_dlq_outbox_redrive, record_dlq_replay, record_outbox_expired_resolution,
};

/// DLQ-private tenant authority. Its private constructor keeps replay and maintenance access tied
/// to this concern instead of widening the generic infrastructure capability surface.
#[derive(Clone, Copy)]
struct DlqTenantScope {
    tenant: vocab::TenantId,
    _seal: (),
}

impl DlqTenantScope {
    fn new(tenant: vocab::TenantId) -> Self {
        Self { tenant, _seal: () }
    }
}

impl TenantScopeHandle for DlqTenantScope {
    fn tenant(self) -> vocab::TenantId {
        self.tenant
    }
}

fn dlq_tenant_scope(tenant: vocab::TenantId) -> DlqTenantScope {
    DlqTenantScope::new(tenant)
}

fn audit_timestamp(clock: &dyn diport::Clock) -> (i64, i32) {
    let now = clock
        .now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    (
        i64::try_from(now.as_secs()).unwrap_or(i64::MAX),
        i32::try_from(now.subsec_nanos()).unwrap_or(0),
    )
}

async fn replay_dead_letter_on_pool(
    pool: &TenantDb<MaintenanceWriteLane>,
    request: DlqReplayRequest,
    payload_protector: &DlxPayloadProtector,
    projection: DlqReplayProjection,
    occurred_at_secs: i64,
    occurred_at_nanos: i32,
) -> Result<DlqReplayOutcome, DlqError> {
    let payload_protector = payload_protector.clone();
    pool.dlq_write(
        dlq_tenant_scope(request.tenant()),
        move |mut conn| {
            Box::pin(async move {
                let row = conn
                    .dlq_load_replay_dead_letter(request.dead_letter_id().as_str())
                    .await
                    .map_err(replay_db_error(DlqReplayStoreStage::FetchDeadLetter))?;

                let Some(row) = row else {
                    return Err(DlqError::NotFound);
                };

                let source = DeadLetterSource::parse(&row.source_kind).ok_or_else(|| {
                    replay_store_error(DlqReplayStoreStage::FetchDeadLetter, None)
                })?;
                match source {
                    DeadLetterSource::Consumer => {}
                    DeadLetterSource::OutboxRelay
                    | DeadLetterSource::Projection
                    | DeadLetterSource::Saga => return Err(DlqError::NotReplayable),
                }

                let decoded = payload_protector
                    .decrypt_replay_capsule(
                        DlxPayloadContext::new(
                            request.tenant(),
                            &row.source_kind,
                            &row.producer_domain,
                            row.consumer_domain.as_deref(),
                            &row.contract_id,
                            &row.topic,
                            row.consumer_group.as_deref(),
                            &row.message_id,
                        ),
                        &row.replay_capsule,
                        &row.replay_capsule_key_ref,
                    )
                    .await
                    .map_err(dlq_payload_error)?;
                let (payload, mut metadata) = decoded.into_parts();
                let (contract_version, schema_hash) = replay_schema_columns(metadata.expose())?;
                let metadata = SensitiveJson::new(replay_metadata(
                    metadata.take(),
                    request.tenant(),
                    request.dead_letter_id().as_str(),
                    &row.message_id,
                ));
                let metadata_json =
                    secure::Plaintext::new(serde_json::to_vec(metadata.expose()).map_err(
                        |_| replay_store_error(DlqReplayStoreStage::EncodeMetadata, None),
                    )?);

                let outcome = conn
                    .dlq_append_replayed(
                        ReplayedOutboxAppend {
                            event_id: request.replay_id().as_str().to_string(),
                            tenant: request.tenant(),
                            domain: row.producer_domain,
                            topic: row.topic,
                            contract_id: row.contract_id,
                            contract_version,
                            schema_hash,
                            payload,
                            metadata_json,
                            causation_id: None,
                        },
                        &projection,
                    )
                    .await
                    .map_err(replayed_outbox_error)?;

                let outcome = match outcome {
                    OutboxAppendOutcome::Inserted => DlqReplayOutcome::Inserted,
                    OutboxAppendOutcome::SameFact => DlqReplayOutcome::AlreadyExists,
                };
                let resource_id = format!(
                    "operation=replay-dead-letter tenant={} dead_letter_id={} replay_id={}",
                    request.tenant(),
                    request.dead_letter_id(),
                    request.replay_id().as_str()
                );
                conn.dlq_record_finish_audit(DlqFinishAudit {
                    occurred_at_secs,
                    occurred_at_nanos,
                    operator_subject: request.operator_subject(),
                    action: "dlq.replay-dead-letter.finish",
                    outcome: "success",
                    failure_reason: None,
                    resource_id: &resource_id,
                    request_id: request.start_audit_id().as_str(),
                })
                .await
                .map_err(replay_db_error(DlqReplayStoreStage::Transaction))?;
                Ok(outcome)
            })
        },
        replay_db_error(DlqReplayStoreStage::Transaction),
    )
    .await
}

/// PostgreSQL implementation of [`DlqStore`].
pub struct PgDlqStore {
    read: TenantDb<MaintenanceReadLane>,
    write: TenantDb<MaintenanceWriteLane>,
    replay: MaintenanceReplayCapability,
    clock: std::sync::Arc<dyn diport::Clock>,
}

struct DlqListOwned {
    producer_domain: Option<String>,
    consumer_domain: Option<String>,
    source: Option<String>,
    contract_id: Option<String>,
    cursor_epoch: Option<i64>,
    cursor_kind: Option<String>,
    cursor_id: Option<String>,
    limit: i64,
}

impl DlqListOwned {
    fn as_filter(&self) -> DlqListFilter<'_> {
        DlqListFilter {
            producer_domain: self.producer_domain.as_deref(),
            consumer_domain: self.consumer_domain.as_deref(),
            source: self.source.as_deref(),
            contract_id: self.contract_id.as_deref(),
            cursor_epoch: self.cursor_epoch,
            cursor_kind: self.cursor_kind.as_deref(),
            cursor_id: self.cursor_id.as_deref(),
            limit: self.limit,
        }
    }
}

enum MaintenanceReplayCapability {
    Enabled {
        payload_protector: DlxPayloadProtector,
        projection: DlqReplayProjection,
    },
    Disabled,
}

impl PgDlqStore {
    pub(crate) fn with_replay_projection_maintenance(
        store: &VerifiedPgMaintenanceStore,
        payload_protector: DlxPayloadProtector,
        projection: DlqReplayProjection,
        clock: std::sync::Arc<dyn diport::Clock>,
    ) -> Self {
        Self {
            read: TenantDb::<MaintenanceReadLane>::new_maintenance(store),
            write: TenantDb::<MaintenanceWriteLane>::new_maintenance(store),
            replay: MaintenanceReplayCapability::Enabled {
                payload_protector,
                projection,
            },
            clock,
        }
    }

    pub(crate) fn without_payload_replay_maintenance(
        store: &VerifiedPgMaintenanceStore,
        clock: std::sync::Arc<dyn diport::Clock>,
    ) -> Self {
        Self {
            read: TenantDb::<MaintenanceReadLane>::new_maintenance(store),
            write: TenantDb::<MaintenanceWriteLane>::new_maintenance(store),
            replay: MaintenanceReplayCapability::Disabled,
            clock,
        }
    }
}

impl DlqStore for PgDlqStore {
    async fn list_dlq(&self, query: DlqListQuery) -> Result<DlqListResult, DlqError> {
        let mut rows = self.list_dead_letter(&query).await?;
        rows.extend(self.list_outbox_dlx(&query).await?);
        Ok(DlqListResult::from_sorted_rows(&query, rows))
    }

    async fn inspect_dlq(&self, request: DlqInspectRequest) -> Result<DlqEntrySummary, DlqError> {
        match request.target() {
            DlqInspectTarget::DeadLetter(id) => {
                self.inspect_dead_letter(request.tenant(), id.as_str())
                    .await
            }
            DlqInspectTarget::OutboxDlx(event_id) => {
                self.inspect_outbox_dlx(request.tenant(), event_id.as_str())
                    .await
            }
        }
    }

    async fn replay_dead_letter(
        &self,
        request: DlqReplayRequest,
    ) -> Result<DurablyAuditedDlqMutation<DlqReplayOutcome>, DlqError> {
        let tenant = request.tenant();
        let (occurred_at_secs, occurred_at_nanos) = audit_timestamp(self.clock.as_ref());
        let result = match &self.replay {
            MaintenanceReplayCapability::Enabled {
                payload_protector,
                projection,
            } => {
                replay_dead_letter_on_pool(
                    &self.write,
                    request,
                    payload_protector,
                    projection.clone(),
                    occurred_at_secs,
                    occurred_at_nanos,
                )
                .await
            }
            MaintenanceReplayCapability::Disabled => {
                let err = DlqError::PayloadKeyUnavailable;
                record_dlq_mutation_error(tenant, DlqMutationKind::DeadLetterReplay, &err);
                return Err(err);
            }
        };
        match &result {
            Ok(outcome) => record_dlq_replay(tenant, *outcome),
            Err(err) => {
                record_dlq_mutation_error(tenant, DlqMutationKind::DeadLetterReplay, err);
            }
        }
        result.map(DurablyAuditedDlqMutation::committed)
    }

    async fn redrive_outbox(
        &self,
        request: DlqRedriveRequest,
    ) -> Result<DurablyAuditedDlqMutation<DlqRedriveOutcome>, DlqError> {
        let event_id = request.event_id().as_str().to_string();
        let tenant = request.tenant();
        let operator_subject = request.operator_subject().to_owned();
        let start_audit_id = request.start_audit_id().as_str().to_owned();
        let resource_id = format!("operation=redrive-outbox tenant={tenant} event_id={event_id}");
        let (occurred_at_secs, occurred_at_nanos) = audit_timestamp(self.clock.as_ref());
        let result = self
            .write
            .dlq_write(
                dlq_tenant_scope(tenant),
                move |mut conn| {
                    Box::pin(async move {
                        let affected = conn
                            .dlq_redrive_outbox(&event_id)
                            .await
                            .map_err(db_error("redrive.update_outbox"))?;
                        let (outcome, audit_outcome, failure_reason) = match affected {
                            1 => (DlqRedriveOutcome::Redriven, "success", None),
                            -1 => (DlqRedriveOutcome::Expired, "failure", Some("expired")),
                            0 => (DlqRedriveOutcome::NotFound, "failure", Some("not_found")),
                            _ => return Err(DlqError::Store),
                        };
                        conn.dlq_record_finish_audit(DlqFinishAudit {
                            occurred_at_secs,
                            occurred_at_nanos,
                            operator_subject: &operator_subject,
                            action: "dlq.redrive-outbox.finish",
                            outcome: audit_outcome,
                            failure_reason,
                            resource_id: &resource_id,
                            request_id: &start_audit_id,
                        })
                        .await
                        .map_err(db_error("redrive.finish_audit"))?;
                        Ok(outcome)
                    })
                },
                db_error("redrive.tx"),
            )
            .await;

        let outcome = result;
        match &outcome {
            Ok(outcome) => record_dlq_outbox_redrive(tenant, *outcome),
            Err(err) => {
                record_dlq_mutation_error(tenant, DlqMutationKind::OutboxDlxRedrive, err);
            }
        }
        outcome.map(DurablyAuditedDlqMutation::committed)
    }

    async fn resolve_expired_outbox(
        &self,
        request: OutboxExpiredResolutionRequest,
    ) -> Result<DurablyAuditedDlqMutation<OutboxExpiredResolutionOutcome>, DlqError> {
        let tenant = request.tenant();
        let event_id = request.event_id().as_str().to_owned();
        let kind = request.kind().as_label();
        let evidence_event_id = request
            .evidence_event_id()
            .map(|value| value.as_str().to_owned());
        let change_ticket = request.change_ticket().as_str().to_owned();
        let operator_subject = request.operator_subject().to_owned();
        let start_audit_id = request.start_audit_id().as_str().to_owned();
        let resource_id = format!(
            "operation=resolve-expired-outbox tenant={tenant} event_id={event_id} resolution_kind={kind}"
        );
        let (occurred_at_secs, occurred_at_nanos) = audit_timestamp(self.clock.as_ref());
        let result = self
            .write
            .dlq_write(
                dlq_tenant_scope(tenant),
                move |mut conn| {
                    Box::pin(async move {
                        let affected = conn
                            .dlq_resolve_expired_outbox(DlqExpiredResolution {
                                event_id: &event_id,
                                kind,
                                change_ticket: &change_ticket,
                                operator_subject: &operator_subject,
                                evidence_event_id: evidence_event_id.as_deref(),
                            })
                            .await
                            .map_err(db_error("resolve_expired.update_outbox"))?;
                        let (outcome, audit_outcome, failure_reason) = match affected {
                            1 => (OutboxExpiredResolutionOutcome::Resolved, "success", None),
                            0 => (
                                OutboxExpiredResolutionOutcome::NotFound,
                                "failure",
                                Some("not_found"),
                            ),
                            -1 => (
                                OutboxExpiredResolutionOutcome::NotExpired,
                                "failure",
                                Some("not_expired"),
                            ),
                            -2 => (
                                OutboxExpiredResolutionOutcome::EvidenceRejected,
                                "failure",
                                Some("evidence_rejected"),
                            ),
                            _ => return Err(DlqError::Store),
                        };
                        conn.dlq_record_finish_audit(DlqFinishAudit {
                            occurred_at_secs,
                            occurred_at_nanos,
                            operator_subject: &operator_subject,
                            action: "dlq.resolve-expired-outbox.finish",
                            outcome: audit_outcome,
                            failure_reason,
                            resource_id: &resource_id,
                            request_id: &start_audit_id,
                        })
                        .await
                        .map_err(db_error("resolve_expired.finish_audit"))?;
                        Ok(outcome)
                    })
                },
                db_error("resolve_expired.tx"),
            )
            .await;

        let outcome = result;
        match &outcome {
            Ok(outcome) => record_outbox_expired_resolution(tenant, *outcome),
            Err(error) => {
                record_dlq_mutation_error(tenant, DlqMutationKind::OutboxDlxResolveExpired, error)
            }
        }
        outcome.map(DurablyAuditedDlqMutation::committed)
    }
}

impl PgDlqStore {
    async fn inspect_dead_letter(
        &self,
        tenant: vocab::TenantId,
        id: &str,
    ) -> Result<DlqEntrySummary, DlqError> {
        let id = id.to_string();
        let row = self
            .read
            .dlq_read(dlq_tenant_scope(tenant), move |mut tx| {
                Box::pin(async move { tx.dlq_inspect_dead_letter(&id).await })
            })
            .await
            .map_err(db_error("inspect.fetch_dead_letter"))?;
        row.ok_or(DlqError::NotFound)?
            .into_summary(DlqEntryKind::DeadLetter, tenant)
    }

    async fn inspect_outbox_dlx(
        &self,
        tenant: vocab::TenantId,
        event_id: &str,
    ) -> Result<DlqEntrySummary, DlqError> {
        let event_id = event_id.to_string();
        let row = self
            .read
            .dlq_read(dlq_tenant_scope(tenant), move |mut tx| {
                Box::pin(async move { tx.dlq_inspect_outbox(&event_id).await })
            })
            .await
            .map_err(db_error("inspect.outbox_tx"))?;
        row.ok_or(DlqError::NotFound)?.into_summary(tenant)
    }

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
        let producer_domain = query.producer_domain().map(str::to_owned);
        let consumer_domain = query.consumer_domain().map(str::to_owned);
        let contract_id = query.contract_id().map(str::to_owned);
        let fetch_limit = query.fetch_limit();
        let cursor_epoch = query.cursor().map(|cursor| cursor.last_epoch_secs());
        let cursor_kind = query
            .cursor()
            .map(|cursor| cursor.last_kind().cursor_part().to_string());
        let cursor_id = query.cursor().map(|cursor| cursor.last_id().to_string());
        let rows = self
            .read
            .dlq_read(dlq_tenant_scope(tenant), move |mut tx| {
                let filter = DlqListOwned {
                    producer_domain,
                    consumer_domain,
                    source,
                    contract_id,
                    cursor_epoch,
                    cursor_kind,
                    cursor_id,
                    limit: i64::from(fetch_limit),
                };
                Box::pin(async move { tx.dlq_list_dead_letters(filter.as_filter()).await })
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
        if query.consumer_domain().is_some() {
            return Ok(Vec::new());
        }
        let domain = query.producer_domain().map(ToString::to_string);
        let contract_id = query.contract_id().map(ToString::to_string);
        let cursor_epoch = query.cursor().map(|cursor| cursor.last_epoch_secs());
        let cursor_kind = query
            .cursor()
            .map(|cursor| cursor.last_kind().cursor_part().to_string());
        let cursor_id = query.cursor().map(|cursor| cursor.last_id().to_string());
        let limit = i64::from(query.fetch_limit());
        let rows = self
            .read
            .dlq_read(dlq_tenant_scope(tenant), move |mut tx| {
                let filter = DlqListOwned {
                    producer_domain: domain,
                    consumer_domain: None,
                    source: None,
                    contract_id,
                    cursor_epoch,
                    cursor_kind,
                    cursor_id,
                    limit,
                };
                Box::pin(async move { tx.dlq_list_outbox(filter.as_filter()).await })
            })
            .await
            .map_err(db_error("list.outbox_tx"))?;

        rows.into_iter()
            .map(|row| row.into_summary(query.tenant()))
            .collect()
    }
}

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
        Ok(DlqEntrySummary::new(
            kind,
            self.id,
            parse_source(&self.source_kind)?,
            tenant,
            self.message_id,
            self.producer_domain,
            self.consumer_domain,
            self.contract_id,
            self.topic,
            self.consumer_group,
            u64_from_i64(self.payload_len)?,
            self.error_summary,
            u32::try_from(self.num_attempts).map_err(|_| DlqError::Store)?,
            self.last_attempt_epoch,
        ))
    }
}

trait OutboxRowExt {
    fn into_summary(self, tenant: vocab::TenantId) -> Result<DlqEntrySummary, DlqError>;
}

impl OutboxRowExt for OutboxDlxRow {
    fn into_summary(self, tenant: vocab::TenantId) -> Result<DlqEntrySummary, DlqError> {
        Ok(DlqEntrySummary::new(
            DlqEntryKind::OutboxDlx,
            self.event_id.clone(),
            DeadLetterSource::OutboxRelay,
            tenant,
            self.event_id,
            self.domain,
            None,
            self.contract_id,
            self.topic,
            None,
            u64_from_i64(self.payload_len)?,
            self.error_summary,
            u32::try_from(self.retry_count).map_err(|_| DlqError::Store)?,
            self.dlx_epoch,
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

fn replay_db_error(stage: DlqReplayStoreStage) -> impl Fn(sqlx::Error) -> DlqError {
    move |error| replay_store_error(stage, Some(&error))
}

fn replay_store_error(
    stage: DlqReplayStoreStage,
    database_error: Option<&sqlx::Error>,
) -> DlqError {
    let database_error = database_error.and_then(|error| error.as_database_error());
    let sqlstate = database_error
        .and_then(sqlx::error::DatabaseError::code)
        .map(|code| code.into_owned())
        .unwrap_or_else(|| "none".to_string());
    let constraint = database_error
        .and_then(sqlx::error::DatabaseError::constraint)
        .unwrap_or("none");
    tracing::warn!(
        target: "postgres",
        stage = stage.as_label(),
        sqlstate,
        constraint,
        "dlq: replay store failed"
    );
    DlqError::ReplayStore(stage)
}

fn replayed_outbox_error(error: ReplayedOutboxWriteError) -> DlqError {
    match error {
        ReplayedOutboxWriteError::Append(OutboxAppendError::Conflict(conflict)) => {
            DlqError::FactConflict(conflict)
        }
        ReplayedOutboxWriteError::Append(OutboxAppendError::Storage(error)) => {
            replay_store_error(DlqReplayStoreStage::AppendOutbox, Some(&error))
        }
        ReplayedOutboxWriteError::Append(
            OutboxAppendError::CanonicalDrift | OutboxAppendError::InvalidIdentity,
        ) => replay_store_error(DlqReplayStoreStage::AppendOutbox, None),
        ReplayedOutboxWriteError::ProjectionMirror(error) => {
            replay_store_error(DlqReplayStoreStage::ProjectionMirror, Some(&error))
        }
    }
}

fn dlq_payload_error(err: KeyProviderError) -> DlqError {
    let kind = err.kind();
    tracing::warn!(
        target: "postgres",
        stage = "decrypt_payload",
        key_provider_kind = ?kind,
        "dlq: replay capsule decrypt failed"
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
    #[allow(clippy::expect_used)]
    // reason: unit test fixture uses a known canonical tenant id and summary result.
    fn legacy_outbox_summary_has_no_payload() {
        let tenant = vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
            .expect("canonical tenant");
        let row = OutboxDlxRow {
            event_id: "event-1".to_string(),
            domain: "identity".to_string(),
            contract_id: "contract-session".to_string(),
            topic: "session.created".to_string(),
            payload_len: 9,
            error_summary: "envelope_invalid_schema_hash".to_string(),
            retry_count: 10,
            dlx_epoch: 1_700_000_000,
        };
        let summary = row.into_summary(tenant).expect("summary");
        assert_eq!(summary.kind(), DlqEntryKind::OutboxDlx);
        assert_eq!(summary.error_summary(), "envelope_invalid_schema_hash");
        assert_eq!(summary.payload_len(), 9);
        assert!(!format!("{summary:?}").contains("payload:"));
    }

    #[test]
    fn key_provider_rejected_maps_to_invalid_payload() {
        let err = KeyProviderError::new(
            KeyProviderErrorKind::Rejected,
            std::io::Error::other("bad ciphertext"),
        );
        assert!(matches!(dlq_payload_error(err), DlqError::InvalidPayload));
    }

    #[test]
    fn key_provider_unavailable_stays_retryable_dependency_error() {
        let err = KeyProviderError::new(
            KeyProviderErrorKind::Unavailable,
            std::io::Error::other("kms unavailable"),
        );
        assert!(matches!(
            dlq_payload_error(err),
            DlqError::PayloadKeyUnavailable
        ));
    }

    #[test]
    fn key_provider_forbidden_stays_operator_config_error() {
        let err = KeyProviderError::new(
            KeyProviderErrorKind::Forbidden,
            std::io::Error::other("policy denied"),
        );
        assert!(matches!(
            dlq_payload_error(err),
            DlqError::PayloadKeyForbidden
        ));
    }

    #[test]
    fn replay_write_errors_map_to_closed_store_stages() {
        for (error, expected) in [
            (
                ReplayedOutboxWriteError::Append(OutboxAppendError::CanonicalDrift),
                DlqReplayStoreStage::AppendOutbox,
            ),
            (
                ReplayedOutboxWriteError::Append(OutboxAppendError::Storage(
                    sqlx::Error::RowNotFound,
                )),
                DlqReplayStoreStage::AppendOutbox,
            ),
            (
                ReplayedOutboxWriteError::ProjectionMirror(sqlx::Error::RowNotFound),
                DlqReplayStoreStage::ProjectionMirror,
            ),
        ] {
            assert!(matches!(
                replayed_outbox_error(error),
                DlqError::ReplayStore(stage) if stage == expected
            ));
        }
    }
}
