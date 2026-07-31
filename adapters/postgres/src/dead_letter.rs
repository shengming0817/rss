//! PostgreSQL HOT dead-letter persistence adapter.
//!
//! [`PgDeadLetterStore`] implements [`diport::DeadLetterStore`]. HOT rows are immutable: this
//! serving capability can only insert through tenant-scoped transactions. Cross-tenant archive and
//! purge live exclusively in the dedicated `rss_dlx_archiver` repository.
//!
//! `replay_capsule` contains only ciphertext. Payload, persisted replay metadata, and provenance
//! are serialized once and encrypted with v3 AAD; no v1/v2 decoder or plaintext fallback exists.

#[cfg(all(test, feature = "integration"))]
use crate::PgStore;
use crate::bundle::ProjectionOperatorTarget;
use crate::cotx::{ServingWriteLane, TenantDb, infra_tenant_scope};
use crate::dead_letter_payload::{DlxPayloadContext, DlxPayloadProtector};
use crate::pool::{VerifiedPgProjectionOperatorStore, VerifiedPgWriteStore};
use diport::{
    DeadLetterRecord, DeadLetterSource, DeadLetterStore, DeadLetterStoreError, EnvelopeMetadata,
    KEY_TENANT_AUTHORITY,
};

/// Tenant-scoped HOT dead-letter writer.
pub struct PgDeadLetterStore {
    lane: DeadLetterLane,
    payload_protector: DlxPayloadProtector,
}

enum DeadLetterLane {
    Serving(TenantDb<ServingWriteLane>),
    ProjectionOperator {
        pool: sqlx::PgPool,
        scope: ProjectionDeadLetterScope,
    },
}

struct ProjectionDeadLetterScope {
    tenant: vocab::TenantId,
    owner: Box<str>,
    checkpoint_id: Box<str>,
}

#[cfg(all(test, feature = "integration"))]
impl PgStore {
    pub(crate) fn dead_letter(&self, payload_protector: DlxPayloadProtector) -> PgDeadLetterStore {
        PgDeadLetterStore {
            lane: DeadLetterLane::Serving(TenantDb::<ServingWriteLane>::from_unverified_for_test(
                self,
            )),
            payload_protector,
        }
    }
}

impl PgDeadLetterStore {
    pub(crate) fn new(
        writer: &VerifiedPgWriteStore,
        payload_protector: DlxPayloadProtector,
    ) -> Self {
        Self {
            lane: DeadLetterLane::Serving(TenantDb::<ServingWriteLane>::new(writer)),
            payload_protector,
        }
    }

    pub(crate) fn new_projection_operator(
        store: &VerifiedPgProjectionOperatorStore,
        target: &ProjectionOperatorTarget,
        payload_protector: DlxPayloadProtector,
    ) -> Self {
        let selector = target.selector();
        Self {
            lane: DeadLetterLane::ProjectionOperator {
                pool: store.store_arc().pool.clone(),
                scope: ProjectionDeadLetterScope {
                    tenant: selector.tenant(),
                    owner: selector.shadow_checkpoint_owner().as_str().into(),
                    checkpoint_id: selector.shadow_checkpoint_id().as_str().into(),
                },
            },
            payload_protector,
        }
    }
}

impl DeadLetterStore for PgDeadLetterStore {
    async fn write_dead_letter(
        &self,
        record: DeadLetterRecord,
    ) -> Result<(), DeadLetterStoreError> {
        if let DeadLetterLane::ProjectionOperator { scope, .. } = &self.lane {
            ensure_projection_dead_letter_target(scope, &record)?;
        }
        let source_kind = record.source().as_str();
        let metadata = metadata_json(record.metadata());
        let protected = self
            .payload_protector
            .encrypt(
                DlxPayloadContext::new(
                    record.tenant(),
                    source_kind,
                    record.producer_domain(),
                    record.consumer_domain(),
                    record.contract_id(),
                    record.topic(),
                    record.consumer_group(),
                    record.message_id(),
                ),
                record.original_payload().as_bytes(),
                &metadata,
            )
            .await
            .map_err(DeadLetterStoreError::new)?;

        match &self.lane {
            DeadLetterLane::Serving(pool) => {
                pool.dlq_write(
                    infra_tenant_scope(record.tenant()),
                    move |mut tx| {
                        Box::pin(async move {
                            tx.dead_letter_insert_projection(&record, &protected)
                                .await
                                .map_err(DeadLetterStoreError::new)
                        })
                    },
                    DeadLetterStoreError::new,
                )
                .await
            }
            DeadLetterLane::ProjectionOperator { pool, .. } => sqlx::query(
                r#"
                SELECT public.rss_projection_operator_insert_dead_letter(
                    $1::uuid, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10, $11, $12,
                    $13, $14, $15
                )
                "#,
            )
            .bind(record.tenant().to_string())
            .bind(record.message_id())
            .bind(record.producer_domain())
            .bind(record.consumer_domain())
            .bind(record.contract_id())
            .bind(record.topic())
            .bind(record.consumer_group())
            .bind(sqlx::types::Json(protected.replay_capsule()))
            .bind(protected.key_ref())
            .bind(protected.payload_len())
            .bind(crate::dead_letter_payload::DLX_REPLAY_CAPSULE_ENCODING)
            .bind(protected.metadata_digest())
            .bind(record.error_summary())
            .bind(i32::try_from(record.num_attempts()).unwrap_or(i32::MAX))
            .bind(record.source().as_str())
            .execute(pool)
            .await
            .map(|_| ())
            .map_err(DeadLetterStoreError::new),
        }
    }

    async fn shutdown(&self) -> Result<(), DeadLetterStoreError> {
        Ok(())
    }
}

fn ensure_projection_dead_letter_target(
    scope: &ProjectionDeadLetterScope,
    record: &DeadLetterRecord,
) -> Result<(), DeadLetterStoreError> {
    if record.source() == DeadLetterSource::Projection
        && record.tenant() == scope.tenant
        && record.consumer_domain() == Some(scope.owner.as_ref())
        && record.consumer_group() == Some(scope.checkpoint_id.as_ref())
    {
        Ok(())
    } else {
        Err(DeadLetterStoreError::new(std::io::Error::other(
            "projection dead letter does not match target-bound operator capability",
        )))
    }
}

/// Envelope metadata → capsule JSON object. Tenant authority is intentionally discarded.
pub(crate) fn metadata_json(metadata: &EnvelopeMetadata) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for (key, value) in metadata.iter_persisted_metadata() {
        if key == KEY_TENANT_AUTHORITY {
            continue;
        }
        map.insert(
            key.to_string(),
            serde_json::Value::String(value.to_string()),
        );
    }
    serde_json::Value::Object(map)
}

#[cfg(test)]
mod tests {
    use core::marker::PhantomData;

    use diport::{
        DeadLetterProvenance, DeadLetterRecord, DeadLetterStore, DeadLetterSummary,
        EnvelopeMetadata, KEY_CORRELATION, KEY_TENANT_AUTHORITY,
    };

    use super::{ProjectionDeadLetterScope, ensure_projection_dead_letter_target, metadata_json};

    fn projection_record(
        tenant: vocab::TenantId,
        owner: &str,
        checkpoint_id: &str,
    ) -> DeadLetterRecord {
        DeadLetterRecord::new(
            tenant,
            "projection-message",
            DeadLetterProvenance::projection("audit", owner),
            "audit.session-created",
            "audit.session-created.v1",
            Some(checkpoint_id.to_owned()),
            Vec::new(),
            DeadLetterSummary::new("projection poison event"),
            1,
            EnvelopeMetadata::empty(),
        )
    }

    #[test]
    fn metadata_json_drops_tenant_authority_token() {
        let mut metadata = EnvelopeMetadata::empty();
        metadata.insert_wire_pair(KEY_TENANT_AUTHORITY, "SECRET_AUTHORITY");
        metadata.insert_wire_pair(KEY_CORRELATION, "corr-1");
        let rendered = metadata_json(&metadata);

        assert_eq!(rendered[KEY_CORRELATION], "corr-1");
        assert!(rendered.get(KEY_TENANT_AUTHORITY).is_none());
    }

    #[test]
    fn pg_dead_letter_store_is_only_a_hot_writer() {
        fn assert_dead_letter_store<T: DeadLetterStore>(_: PhantomData<T>) {}
        assert_dead_letter_store(PhantomData::<super::PgDeadLetterStore>);
    }

    #[test]
    fn projection_operator_dead_letter_rejects_cross_target_records()
    -> Result<(), Box<dyn std::error::Error>> {
        let tenant = vocab::TenantId::parse("00000000-0000-4000-8000-000000000002")?;
        let other_tenant = vocab::TenantId::parse("00000000-0000-4000-8000-000000000003")?;
        let scope = ProjectionDeadLetterScope {
            tenant,
            owner: "projection:00000000-0000-4000-8000-000000000002".into(),
            checkpoint_id: "audit.session-projection@v2:shadow".into(),
        };

        assert!(
            ensure_projection_dead_letter_target(
                &scope,
                &projection_record(tenant, &scope.owner, &scope.checkpoint_id),
            )
            .is_ok()
        );
        assert!(
            ensure_projection_dead_letter_target(
                &scope,
                &projection_record(other_tenant, &scope.owner, &scope.checkpoint_id),
            )
            .is_err()
        );
        assert!(
            ensure_projection_dead_letter_target(
                &scope,
                &projection_record(tenant, &scope.owner, "other.projection@v2:shadow"),
            )
            .is_err()
        );
        Ok(())
    }
}
