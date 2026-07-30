//! PostgreSQL DLQ inspection/replay adapter (#1214).

#[cfg(all(test, feature = "integration"))]
use crate::PgStore;
use crate::cotx::eventing::{
    DeadLetterRow, DlqExpiredResolution, DlqListFilter, DlqReplayProjection, OutboxDlxRow,
};
use crate::cotx::{
    MaintenanceReadLane, MaintenanceWriteLane, ServingReadLane, ServingWriteLane, TenantDb,
    TenantScopeHandle,
};
use crate::dead_letter_payload::{DlxPayloadContext, DlxPayloadProtector, SensitiveJson};
use crate::outbox::{OutboxAppendError, ReplayedOutboxAppend};
use crate::pool::{VerifiedPgMaintenanceStore, VerifiedPgReadStore, VerifiedPgWriteStore};
use crate::projection_events::ProjectionWriteRegistry;
use consistency::OutboxAppendOutcome;
use diport::key_provider::{KeyProviderError, KeyProviderErrorKind};
use diport::{
    DeadLetterSource, EnvelopeSchemaHash, EnvelopeSchemaVersion, KEY_SCHEMA_HASH,
    KEY_SCHEMA_VERSION, KEY_TENANT_ID,
};
use eventexec::{
    DlqEntryKind, DlqEntrySummary, DlqError, DlqInspectRequest, DlqInspectTarget, DlqListQuery,
    DlqListResult, DlqMutationKind, DlqRedriveOutcome, DlqRedriveRequest, DlqReplayOutcome,
    DlqReplayRequest, DlqStore, OutboxExpiredResolutionOutcome, OutboxExpiredResolutionRequest,
    record_dlq_mutation_error, record_dlq_outbox_redrive, record_dlq_replay,
    record_outbox_expired_resolution,
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

macro_rules! replay_dead_letter_on_pool {
    ($pool:expr, $request:expr, $payload_protector:expr, $projection:expr, $append:ident) => {{
        let projection = $projection;
        $pool
            .dlq_write(
                dlq_tenant_scope($request.tenant()),
                move |mut conn| {
                    let payload_protector = $payload_protector.clone();
                    Box::pin(async move {
                        let row = conn
                            .dlq_load_replay_dead_letter($request.dead_letter_id().as_str())
                            .await
                            .map_err(db_error("replay.fetch_dead_letter"))?;

                        let Some(row) = row else {
                            return Err(DlqError::NotFound);
                        };

                        match parse_source(&row.source_kind)? {
                            DeadLetterSource::Consumer => {}
                            DeadLetterSource::OutboxRelay
                            | DeadLetterSource::Projection
                            | DeadLetterSource::Saga => return Err(DlqError::NotReplayable),
                        }

                        let decoded = payload_protector
                            .decrypt_replay_capsule(
                                DlxPayloadContext::new(
                                    $request.tenant(),
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
                            .map_err(|err| {
                                dlq_payload_error(
                                    "replay.decrypt_replay_capsule",
                                    $request.dead_letter_id().as_str(),
                                    $request.tenant(),
                                    err,
                                )
                            })?;
                        let (payload, mut metadata) = decoded.into_parts();
                        let (contract_version, schema_hash) =
                            replay_schema_columns(metadata.expose())?;
                        let metadata = SensitiveJson::new(replay_metadata(
                            metadata.take(),
                            $request.tenant(),
                            $request.dead_letter_id().as_str(),
                            &row.message_id,
                        ));
                        let metadata_json = secure::Plaintext::new(
                            serde_json::to_vec(metadata.expose()).map_err(|_| DlqError::Store)?,
                        );

                        let outcome = conn
                            .$append(
                                ReplayedOutboxAppend {
                                    event_id: $request.replay_id().as_str().to_string(),
                                    tenant: $request.tenant(),
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
                            .map_err(append_error("replay.insert_outbox"))?;

                        match outcome {
                            OutboxAppendOutcome::Inserted => Ok(DlqReplayOutcome::Inserted),
                            OutboxAppendOutcome::SameFact => Ok(DlqReplayOutcome::AlreadyExists),
                        }
                    })
                },
                db_error("replay.tx"),
            )
            .await
    }};
}

/// PostgreSQL implementation of [`DlqStore`].
pub struct PgDlqStore {
    lane: DlqLane,
    replay: DlqReplayCapability,
}

// The serving lane is an explicit capability boundary even though the current composition root
// only exposes operator DLQ access through `PgMaintenanceDeps`; unit tests exercise both lanes.
#[allow(dead_code)]
enum DlqLane {
    Serving {
        read: TenantDb<ServingReadLane>,
        write: TenantDb<ServingWriteLane>,
    },
    Maintenance {
        read: TenantDb<MaintenanceReadLane>,
        write: TenantDb<MaintenanceWriteLane>,
    },
}

impl DlqLane {
    async fn inspect_dead_letter(
        &self,
        tenant: vocab::TenantId,
        id: String,
    ) -> Result<Option<DeadLetterRow>, sqlx::Error> {
        match self {
            Self::Serving { read, .. } => {
                read.dlq_read(dlq_tenant_scope(tenant), move |mut tx| {
                    Box::pin(async move { tx.dlq_inspect_dead_letter(&id).await })
                })
                .await
            }
            Self::Maintenance { read, .. } => {
                read.dlq_read(dlq_tenant_scope(tenant), move |mut tx| {
                    Box::pin(async move { tx.dlq_inspect_dead_letter(&id).await })
                })
                .await
            }
        }
    }

    async fn inspect_outbox(
        &self,
        tenant: vocab::TenantId,
        event_id: String,
    ) -> Result<Option<OutboxDlxRow>, sqlx::Error> {
        match self {
            Self::Serving { read, .. } => {
                read.dlq_read(dlq_tenant_scope(tenant), move |mut tx| {
                    Box::pin(async move { tx.dlq_inspect_outbox(&event_id).await })
                })
                .await
            }
            Self::Maintenance { read, .. } => {
                read.dlq_read(dlq_tenant_scope(tenant), move |mut tx| {
                    Box::pin(async move { tx.dlq_inspect_outbox(&event_id).await })
                })
                .await
            }
        }
    }

    async fn list_dead_letters(
        &self,
        tenant: vocab::TenantId,
        filter: DlqListOwned,
    ) -> Result<Vec<DeadLetterRow>, sqlx::Error> {
        match self {
            Self::Serving { read, .. } => {
                read.dlq_read(dlq_tenant_scope(tenant), move |mut tx| {
                    Box::pin(async move { tx.dlq_list_dead_letters(filter.as_filter()).await })
                })
                .await
            }
            Self::Maintenance { read, .. } => {
                read.dlq_read(dlq_tenant_scope(tenant), move |mut tx| {
                    Box::pin(async move { tx.dlq_list_dead_letters(filter.as_filter()).await })
                })
                .await
            }
        }
    }

    async fn list_outbox(
        &self,
        tenant: vocab::TenantId,
        filter: DlqListOwned,
    ) -> Result<Vec<OutboxDlxRow>, sqlx::Error> {
        match self {
            Self::Serving { read, .. } => {
                read.dlq_read(dlq_tenant_scope(tenant), move |mut tx| {
                    Box::pin(async move { tx.dlq_list_outbox(filter.as_filter()).await })
                })
                .await
            }
            Self::Maintenance { read, .. } => {
                read.dlq_read(dlq_tenant_scope(tenant), move |mut tx| {
                    Box::pin(async move { tx.dlq_list_outbox(filter.as_filter()).await })
                })
                .await
            }
        }
    }
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

enum DlqReplayCapability {
    Serving {
        payload_protector: DlxPayloadProtector,
    },
    Maintenance {
        payload_protector: DlxPayloadProtector,
        projection: DlqReplayProjection,
    },
    Disabled,
}

#[cfg(all(test, feature = "integration"))]
impl PgStore {
    pub(crate) fn dlq_with_projection_bindings(
        &self,
        payload_protector: DlxPayloadProtector,
        projection_bindings: &[vocab::ProjectionInputBinding],
    ) -> PgDlqStore {
        let projection_registry = ProjectionWriteRegistry::from_selected(projection_bindings);
        PgDlqStore {
            lane: DlqLane::Serving {
                read: TenantDb::<ServingReadLane>::from_unverified_for_test(self),
                write:
                    TenantDb::<ServingWriteLane>::from_unverified_with_projection_registry_for_test(
                        self,
                        projection_registry,
                    ),
            },
            replay: DlqReplayCapability::Serving { payload_protector },
        }
    }

    pub(crate) fn dlq_without_payload_replay(&self) -> PgDlqStore {
        PgDlqStore {
            lane: DlqLane::Serving {
                read: TenantDb::<ServingReadLane>::from_unverified_for_test(self),
                write: TenantDb::<ServingWriteLane>::from_unverified_for_test(self),
            },
            replay: DlqReplayCapability::Disabled,
        }
    }
}

impl PgDlqStore {
    #[allow(dead_code)]
    pub(crate) fn with_projection_registry(
        reader: &VerifiedPgReadStore,
        writer: &VerifiedPgWriteStore,
        payload_protector: DlxPayloadProtector,
        projection_registry: ProjectionWriteRegistry,
    ) -> Self {
        Self {
            lane: DlqLane::Serving {
                read: TenantDb::<ServingReadLane>::new(reader),
                write: TenantDb::<ServingWriteLane>::with_projection_registry(
                    writer,
                    projection_registry,
                ),
            },
            replay: DlqReplayCapability::Serving { payload_protector },
        }
    }

    #[allow(dead_code)]
    pub(crate) fn without_payload_replay(
        reader: &VerifiedPgReadStore,
        writer: &VerifiedPgWriteStore,
    ) -> Self {
        Self {
            lane: DlqLane::Serving {
                read: TenantDb::<ServingReadLane>::new(reader),
                write: TenantDb::<ServingWriteLane>::new(writer),
            },
            replay: DlqReplayCapability::Disabled,
        }
    }

    pub(crate) fn with_replay_projection_maintenance(
        store: &VerifiedPgMaintenanceStore,
        payload_protector: DlxPayloadProtector,
        projection: DlqReplayProjection,
    ) -> Self {
        Self {
            lane: DlqLane::Maintenance {
                read: TenantDb::<MaintenanceReadLane>::new_maintenance(store),
                write: TenantDb::<MaintenanceWriteLane>::new_maintenance(store),
            },
            replay: DlqReplayCapability::Maintenance {
                payload_protector,
                projection,
            },
        }
    }

    pub(crate) fn without_payload_replay_maintenance(store: &VerifiedPgMaintenanceStore) -> Self {
        Self {
            lane: DlqLane::Maintenance {
                read: TenantDb::<MaintenanceReadLane>::new_maintenance(store),
                write: TenantDb::<MaintenanceWriteLane>::new_maintenance(store),
            },
            replay: DlqReplayCapability::Disabled,
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
    ) -> Result<DlqReplayOutcome, DlqError> {
        let tenant = request.tenant();
        let result = match (&self.lane, &self.replay) {
            (
                DlqLane::Serving { write, .. },
                DlqReplayCapability::Serving { payload_protector },
            ) => {
                let projection = DlqReplayProjection::from_registry(&write.projection_registry());
                replay_dead_letter_on_pool!(
                    write,
                    request,
                    payload_protector,
                    projection,
                    outbox_append_replayed_with_projection
                )
            }
            (
                DlqLane::Maintenance { write, .. },
                DlqReplayCapability::Maintenance {
                    payload_protector,
                    projection,
                },
            ) => replay_dead_letter_on_pool!(
                write,
                request,
                payload_protector,
                projection.clone(),
                dlq_append_replayed
            ),
            (_, DlqReplayCapability::Disabled) => {
                let err = DlqError::PayloadKeyUnavailable;
                record_dlq_mutation_error(tenant, DlqMutationKind::DeadLetterReplay, &err);
                return Err(err);
            }
            _ => return Err(DlqError::Store),
        };
        match &result {
            Ok(outcome) => record_dlq_replay(tenant, *outcome),
            Err(err) => {
                record_dlq_mutation_error(tenant, DlqMutationKind::DeadLetterReplay, err);
            }
        }
        result
    }

    async fn redrive_outbox(
        &self,
        request: DlqRedriveRequest,
    ) -> Result<DlqRedriveOutcome, DlqError> {
        let event_id = request.event_id().as_str().to_string();
        let tenant = request.tenant();
        let result = match &self.lane {
            DlqLane::Serving { write, .. } => {
                write
                    .dlq_write(
                        dlq_tenant_scope(tenant),
                        move |mut conn| {
                            Box::pin(async move {
                                conn.dlq_redrive_outbox(&event_id)
                                    .await
                                    .map_err(db_error("redrive.update_outbox"))
                            })
                        },
                        db_error("redrive.tx"),
                    )
                    .await
            }
            DlqLane::Maintenance { write, .. } => {
                write
                    .dlq_write(
                        dlq_tenant_scope(tenant),
                        move |mut conn| {
                            Box::pin(async move {
                                conn.dlq_redrive_outbox(&event_id)
                                    .await
                                    .map_err(db_error("redrive.update_outbox"))
                            })
                        },
                        db_error("redrive.tx"),
                    )
                    .await
            }
        };

        let outcome = match result {
            Ok(1) => Ok(DlqRedriveOutcome::Redriven),
            Ok(-1) => Ok(DlqRedriveOutcome::Expired),
            Ok(0) => Ok(DlqRedriveOutcome::NotFound),
            Ok(_) => Err(DlqError::Store),
            Err(err) => Err(err),
        };
        match &outcome {
            Ok(outcome) => record_dlq_outbox_redrive(tenant, *outcome),
            Err(err) => {
                record_dlq_mutation_error(tenant, DlqMutationKind::OutboxDlxRedrive, err);
            }
        }
        outcome
    }

    async fn resolve_expired_outbox(
        &self,
        request: OutboxExpiredResolutionRequest,
    ) -> Result<OutboxExpiredResolutionOutcome, DlqError> {
        let tenant = request.tenant();
        let event_id = request.event_id().as_str().to_owned();
        let kind = request.kind().as_label();
        let evidence_event_id = request
            .evidence_event_id()
            .map(|value| value.as_str().to_owned());
        let change_ticket = request.change_ticket().as_str().to_owned();
        let operator_subject = request.operator_subject().as_str().to_owned();
        let result = match &self.lane {
            DlqLane::Serving { write, .. } => {
                write
                    .dlq_write(
                        dlq_tenant_scope(tenant),
                        move |mut conn| {
                            Box::pin(async move {
                                conn.dlq_resolve_expired_outbox(DlqExpiredResolution {
                                    event_id: &event_id,
                                    kind,
                                    change_ticket: &change_ticket,
                                    operator_subject: &operator_subject,
                                    evidence_event_id: evidence_event_id.as_deref(),
                                })
                                .await
                                .map_err(db_error("resolve_expired.update_outbox"))
                            })
                        },
                        db_error("resolve_expired.tx"),
                    )
                    .await
            }
            DlqLane::Maintenance { write, .. } => {
                write
                    .dlq_write(
                        dlq_tenant_scope(tenant),
                        move |mut conn| {
                            Box::pin(async move {
                                conn.dlq_resolve_expired_outbox(DlqExpiredResolution {
                                    event_id: &event_id,
                                    kind,
                                    change_ticket: &change_ticket,
                                    operator_subject: &operator_subject,
                                    evidence_event_id: evidence_event_id.as_deref(),
                                })
                                .await
                                .map_err(db_error("resolve_expired.update_outbox"))
                            })
                        },
                        db_error("resolve_expired.tx"),
                    )
                    .await
            }
        };

        let outcome = match result {
            Ok(1) => Ok(OutboxExpiredResolutionOutcome::Resolved),
            Ok(0) => Ok(OutboxExpiredResolutionOutcome::NotFound),
            Ok(-1) => Ok(OutboxExpiredResolutionOutcome::NotExpired),
            Ok(-2) => Ok(OutboxExpiredResolutionOutcome::EvidenceRejected),
            Ok(_) => Err(DlqError::Store),
            Err(error) => Err(error),
        };
        match &outcome {
            Ok(outcome) => record_outbox_expired_resolution(tenant, *outcome),
            Err(error) => {
                record_dlq_mutation_error(tenant, DlqMutationKind::OutboxDlxResolveExpired, error)
            }
        }
        outcome
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
            .lane
            .inspect_dead_letter(tenant, id)
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
            .lane
            .inspect_outbox(tenant, event_id)
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
            .lane
            .list_dead_letters(
                tenant,
                DlqListOwned {
                    producer_domain,
                    consumer_domain,
                    source,
                    contract_id,
                    cursor_epoch,
                    cursor_kind,
                    cursor_id,
                    limit: i64::from(fetch_limit),
                },
            )
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
            .lane
            .list_outbox(
                tenant,
                DlqListOwned {
                    producer_domain: domain,
                    consumer_domain: None,
                    source: None,
                    contract_id,
                    cursor_epoch,
                    cursor_kind,
                    cursor_id,
                    limit,
                },
            )
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

fn append_error(operation: &'static str) -> impl Fn(OutboxAppendError) -> DlqError {
    move |error| match error {
        OutboxAppendError::Conflict(conflict) => DlqError::FactConflict(conflict),
        other => {
            tracing::warn!(
                target: "postgres",
                operation,
                error = %secure::redact_error(&other),
                "dlq: outbox append error"
            );
            DlqError::Store
        }
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
}
