//! Closed tenant transaction façade for the Settings metadata projection.
//!
//! INVARIANT: SETTINGS-PROJECTION-ATOMIC-01 { level = "Medium", exec = "postgres-domain", source = "code" } -- current-row mutation, dedupe receipt, and persistent high-water share this one LocalTx settlement.
//! INVARIANT: SETTINGS-PROJECTION-ORDERING-01 { level = "Medium", exec = "postgres-domain", source = "code" } -- immutable generation identity, receipt-first idempotency, LSN ordering, and config-version monotonicity are checked while holding the generation row lock.

use futures::future::BoxFuture;
use settings::ports::{
    SETTINGS_CONFIG_PROJECTION_ID, SettingKey, SettingsProjectionApplyScope,
    SettingsProjectionMutation, SettingsProjectionReadScope,
};
use sqlx::PgConnection;

use super::{LocalTxAttempt, ServingReadLane, ServingWriteLane, TenantDb};

pub(crate) struct SettingsProjectionStoredRow {
    pub(crate) config_version: i64,
    pub(crate) change_kind: String,
    pub(crate) source_event_id: String,
    pub(crate) source_lsn: i64,
    pub(crate) source_occurred_at_secs: i64,
    pub(crate) created_at_epoch_micros: i64,
    pub(crate) updated_at_epoch_micros: i64,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum SettingsProjectionTxError {
    #[error("settings projection tenant identity mismatch")]
    TenantMismatch,
    #[error("settings projection definition identity mismatch")]
    DefinitionIdentityMismatch,
    #[error("settings projection numeric metadata is out of range")]
    NumericOutOfRange(SettingsProjectionNumericField),
    #[error("settings projection receipt conflicts with an existing fact")]
    Conflict,
    #[error("settings projection source LSN is behind persistent high-water")]
    OutOfOrder,
    #[error("settings projection config version is not monotonic")]
    VersionRegression,
    #[error("settings projection PostgreSQL operation failed")]
    Storage(#[source] sqlx::Error),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SettingsProjectionNumericField {
    SourceLsn,
    ConfigVersion,
    OccurredAt,
}

impl SettingsProjectionNumericField {
    const fn reason(self) -> &'static str {
        match self {
            Self::SourceLsn => "source_lsn_out_of_range",
            Self::ConfigVersion => "config_version_out_of_range",
            Self::OccurredAt => "occurred_at_out_of_range",
        }
    }
}

impl SettingsProjectionTxError {
    pub(crate) fn target_kind(&self) -> eventexec::ProjectionTargetStoreErrorKind {
        match self {
            Self::Conflict => eventexec::ProjectionTargetStoreErrorKind::Conflict,
            Self::OutOfOrder => eventexec::ProjectionTargetStoreErrorKind::OutOfOrder,
            Self::TenantMismatch
            | Self::DefinitionIdentityMismatch
            | Self::NumericOutOfRange(_)
            | Self::VersionRegression => eventexec::ProjectionTargetStoreErrorKind::Permanent,
            Self::Storage(error) => match crate::tx_retry::classify_sqlx_error(error) {
                consistency::TxRetryClass::Transient => {
                    eventexec::ProjectionTargetStoreErrorKind::Transient
                }
                consistency::TxRetryClass::Permanent
                | consistency::TxRetryClass::Conflict
                | consistency::TxRetryClass::OwnershipLost => {
                    eventexec::ProjectionTargetStoreErrorKind::Permanent
                }
            },
        }
    }

    pub(crate) const fn reason(&self) -> &'static str {
        match self {
            Self::TenantMismatch => "tenant_mismatch",
            Self::DefinitionIdentityMismatch => "definition_identity_mismatch",
            Self::NumericOutOfRange(field) => field.reason(),
            Self::Conflict => "fact_conflict",
            Self::OutOfOrder => "out_of_order",
            Self::VersionRegression => "version_regression",
            Self::Storage(_) => "storage",
        }
    }
}

struct SettingsProjectionReadTx<'tx> {
    conn: &'tx mut PgConnection,
    tenant: vocab::TenantId,
}

impl SettingsProjectionReadTx<'_> {
    async fn find(
        &mut self,
        scope: &SettingsProjectionReadScope,
        key: &SettingKey,
    ) -> Result<Option<SettingsProjectionStoredRow>, sqlx::Error> {
        let row = sqlx::query_as::<_, (i64, String, String, i64, i64, i64, i64)>(
            "SELECT config_version, change_kind, source_event_id, source_lsn, \
                    source_occurred_at_secs, \
                    (EXTRACT(EPOCH FROM created_at) * 1000000)::bigint, \
                    (EXTRACT(EPOCH FROM updated_at) * 1000000)::bigint \
             FROM public.settings_config_projection_rows \
             WHERE tenant_id = $1::uuid AND projection_id = $2 \
               AND generation = $3 AND config_key = $4",
        )
        .bind(self.tenant.as_uuid().to_string())
        .bind(SETTINGS_CONFIG_PROJECTION_ID)
        .bind(scope.generation().as_str())
        .bind(key.as_str())
        .fetch_optional(&mut *self.conn)
        .await?;
        Ok(row.map(
            |(
                config_version,
                change_kind,
                source_event_id,
                source_lsn,
                source_occurred_at_secs,
                created_at_epoch_micros,
                updated_at_epoch_micros,
            )| SettingsProjectionStoredRow {
                config_version,
                change_kind,
                source_event_id,
                source_lsn,
                source_occurred_at_secs,
                created_at_epoch_micros,
                updated_at_epoch_micros,
            },
        ))
    }
}

struct SettingsProjectionWriteTx<'tx> {
    conn: &'tx mut PgConnection,
    tenant: vocab::TenantId,
}

impl SettingsProjectionWriteTx<'_> {
    async fn apply(
        &mut self,
        scope: &SettingsProjectionApplyScope,
        mutation: &SettingsProjectionMutation,
    ) -> Result<eventexec::ProjectionTargetStoreOutcome, SettingsProjectionTxError> {
        if scope.tenant_scope().tenant() != self.tenant || mutation.tenant() != self.tenant {
            return Err(SettingsProjectionTxError::TenantMismatch);
        }

        let tenant = self.tenant.as_uuid().to_string();
        let projection = scope.projection().as_str();
        let generation = scope.target_generation().as_str();
        sqlx::query(
            "INSERT INTO public.settings_projection_generations (\
                 tenant_id, projection_id, generation, definition_version, \
                 definition_schema_digest, input_generation, high_water_lsn\
             ) VALUES ($1::uuid, $2, $3, $4, $5, $6, NULL) \
             ON CONFLICT (tenant_id, projection_id, generation) DO NOTHING",
        )
        .bind(&tenant)
        .bind(projection)
        .bind(generation)
        .bind(scope.definition_version())
        .bind(scope.definition_schema_digest())
        .bind(scope.input_generation())
        .execute(&mut *self.conn)
        .await
        .map_err(SettingsProjectionTxError::Storage)?;

        let generation_row = sqlx::query_as::<_, (String, String, String, Option<i64>)>(
            "SELECT definition_version, definition_schema_digest, input_generation, high_water_lsn \
             FROM public.settings_projection_generations \
             WHERE tenant_id = $1::uuid AND projection_id = $2 AND generation = $3 \
             FOR UPDATE",
        )
        .bind(&tenant)
        .bind(projection)
        .bind(generation)
        .fetch_one(&mut *self.conn)
        .await
        .map_err(SettingsProjectionTxError::Storage)?;
        if generation_row.0 != scope.definition_version()
            || generation_row.1 != scope.definition_schema_digest()
            || generation_row.2 != scope.input_generation()
        {
            return Err(SettingsProjectionTxError::DefinitionIdentityMismatch);
        }

        let existing_digest = sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT fact_digest \
             FROM public.settings_projection_dedupe_receipts \
             WHERE tenant_id = $1::uuid AND projection_id = $2 \
               AND generation = $3 AND source_event_id = $4",
        )
        .bind(&tenant)
        .bind(projection)
        .bind(generation)
        .bind(mutation.source_event_id())
        .fetch_optional(&mut *self.conn)
        .await
        .map_err(SettingsProjectionTxError::Storage)?;
        if let Some(existing_digest) = existing_digest {
            return if existing_digest.as_slice() == mutation.fact_digest() {
                Ok(eventexec::ProjectionTargetStoreOutcome::Duplicate)
            } else {
                Err(SettingsProjectionTxError::Conflict)
            };
        }

        let source_lsn = i64::try_from(mutation.source_lsn().get()).map_err(|_| {
            SettingsProjectionTxError::NumericOutOfRange(SettingsProjectionNumericField::SourceLsn)
        })?;
        if generation_row
            .3
            .is_some_and(|high_water| source_lsn < high_water)
        {
            return Err(SettingsProjectionTxError::OutOfOrder);
        }

        let current_version = sqlx::query_scalar::<_, i64>(
            "SELECT config_version \
             FROM public.settings_config_projection_rows \
             WHERE tenant_id = $1::uuid AND projection_id = $2 \
               AND generation = $3 AND config_key = $4 \
             FOR UPDATE",
        )
        .bind(&tenant)
        .bind(projection)
        .bind(generation)
        .bind(mutation.key().as_str())
        .fetch_optional(&mut *self.conn)
        .await
        .map_err(SettingsProjectionTxError::Storage)?;
        let config_version = i64::try_from(mutation.config_version()).map_err(|_| {
            SettingsProjectionTxError::NumericOutOfRange(
                SettingsProjectionNumericField::ConfigVersion,
            )
        })?;
        if current_version.is_some_and(|current| config_version <= current) {
            return Err(SettingsProjectionTxError::VersionRegression);
        }
        let occurred_at = i64::try_from(mutation.source_occurred_at_secs()).map_err(|_| {
            SettingsProjectionTxError::NumericOutOfRange(SettingsProjectionNumericField::OccurredAt)
        })?;

        sqlx::query(
            "INSERT INTO public.settings_config_projection_rows (\
                 tenant_id, projection_id, generation, config_key, config_version, change_kind, \
                 source_event_id, source_lsn, source_occurred_at_secs\
             ) VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (tenant_id, projection_id, generation, config_key) DO UPDATE SET \
                 config_version = EXCLUDED.config_version, \
                 change_kind = EXCLUDED.change_kind, \
                 source_event_id = EXCLUDED.source_event_id, \
                 source_lsn = EXCLUDED.source_lsn, \
                 source_occurred_at_secs = EXCLUDED.source_occurred_at_secs, \
                 updated_at = pg_catalog.now()",
        )
        .bind(&tenant)
        .bind(projection)
        .bind(generation)
        .bind(mutation.key().as_str())
        .bind(config_version)
        .bind(mutation.change_kind().to_string())
        .bind(mutation.source_event_id())
        .bind(source_lsn)
        .bind(occurred_at)
        .execute(&mut *self.conn)
        .await
        .map_err(SettingsProjectionTxError::Storage)?;

        let receipt_result = sqlx::query(
            "INSERT INTO public.settings_projection_dedupe_receipts (\
                 tenant_id, projection_id, generation, source_event_id, source_lsn, fact_digest\
             ) VALUES ($1::uuid, $2, $3, $4, $5, $6)",
        )
        .bind(&tenant)
        .bind(projection)
        .bind(generation)
        .bind(mutation.source_event_id())
        .bind(source_lsn)
        .bind(mutation.fact_digest().as_slice())
        .execute(&mut *self.conn)
        .await;
        if let Err(error) = receipt_result {
            if error
                .as_database_error()
                .and_then(|database| database.constraint())
                == Some("settings_projection_dedupe_receipts_source_lsn_unique")
            {
                return Err(SettingsProjectionTxError::Conflict);
            }
            return Err(SettingsProjectionTxError::Storage(error));
        }

        sqlx::query(
            "UPDATE public.settings_projection_generations \
             SET high_water_lsn = $4, updated_at = pg_catalog.now() \
             WHERE tenant_id = $1::uuid AND projection_id = $2 AND generation = $3",
        )
        .bind(&tenant)
        .bind(projection)
        .bind(generation)
        .bind(source_lsn)
        .execute(&mut *self.conn)
        .await
        .map_err(SettingsProjectionTxError::Storage)?;

        Ok(eventexec::ProjectionTargetStoreOutcome::Applied)
    }
}

impl TenantDb<ServingReadLane> {
    pub(crate) async fn settings_projection_find(
        &self,
        scope: SettingsProjectionReadScope,
        key: SettingKey,
    ) -> Result<Option<SettingsProjectionStoredRow>, sqlx::Error> {
        let tenant_scope = scope.tenant_scope();
        self.read(tenant_scope, move |tx| {
            Box::pin(async move {
                SettingsProjectionReadTx {
                    conn: &mut *tx.conn,
                    tenant: tx.tenant,
                }
                .find(&scope, &key)
                .await
            })
        })
        .await
    }
}

impl TenantDb<ServingWriteLane> {
    pub(crate) async fn settings_projection_apply(
        &self,
        scope: SettingsProjectionApplyScope,
        mutation: SettingsProjectionMutation,
    ) -> LocalTxAttempt<eventexec::ProjectionTargetStoreOutcome, SettingsProjectionTxError> {
        let tenant_scope = scope.tenant_scope();
        self.write_attempt(
            tenant_scope,
            move |tx| {
                Box::pin(async move {
                    let outcome = SettingsProjectionWriteTx {
                        conn: &mut *tx.conn,
                        tenant: tx.tenant,
                    }
                    .apply(&scope, &mutation)
                    .await?;
                    #[cfg(all(test, feature = "integration"))]
                    if outcome == eventexec::ProjectionTargetStoreOutcome::Applied
                        && mutation.source_event_id() == "settings-projection-commit-unknown"
                    {
                        tx.inject_commit_unknown_after_commit()
                            .await
                            .map_err(SettingsProjectionTxError::Storage)?;
                    }
                    #[cfg(all(test, feature = "integration"))]
                    if outcome == eventexec::ProjectionTargetStoreOutcome::Applied
                        && mutation.source_event_id() == "settings-projection-rollback-failed"
                    {
                        tx.inject_rollback_failed_after_rollback()
                            .await
                            .map_err(SettingsProjectionTxError::Storage)?;
                        return Err(SettingsProjectionTxError::Storage(sqlx::Error::Protocol(
                            "injected settings projection failure before rollback".into(),
                        )));
                    }
                    Ok(outcome)
                }) as BoxFuture<'_, _>
            },
            SettingsProjectionTxError::Storage,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::{SettingsProjectionNumericField, SettingsProjectionTxError};

    #[test]
    fn storage_classification_reuses_canonical_sqlx_taxonomy() {
        assert_eq!(
            SettingsProjectionTxError::Storage(sqlx::Error::PoolTimedOut).target_kind(),
            eventexec::ProjectionTargetStoreErrorKind::Transient
        );
        assert_eq!(
            SettingsProjectionTxError::Storage(sqlx::Error::Protocol("invalid".into()))
                .target_kind(),
            eventexec::ProjectionTargetStoreErrorKind::Permanent
        );
    }

    #[test]
    fn failure_reasons_are_closed_and_keep_permanent_failures_distinguishable() {
        let cases = [
            (
                SettingsProjectionTxError::TenantMismatch,
                "tenant_mismatch",
                eventexec::ProjectionTargetStoreErrorKind::Permanent,
            ),
            (
                SettingsProjectionTxError::DefinitionIdentityMismatch,
                "definition_identity_mismatch",
                eventexec::ProjectionTargetStoreErrorKind::Permanent,
            ),
            (
                SettingsProjectionTxError::NumericOutOfRange(
                    SettingsProjectionNumericField::SourceLsn,
                ),
                "source_lsn_out_of_range",
                eventexec::ProjectionTargetStoreErrorKind::Permanent,
            ),
            (
                SettingsProjectionTxError::NumericOutOfRange(
                    SettingsProjectionNumericField::ConfigVersion,
                ),
                "config_version_out_of_range",
                eventexec::ProjectionTargetStoreErrorKind::Permanent,
            ),
            (
                SettingsProjectionTxError::NumericOutOfRange(
                    SettingsProjectionNumericField::OccurredAt,
                ),
                "occurred_at_out_of_range",
                eventexec::ProjectionTargetStoreErrorKind::Permanent,
            ),
            (
                SettingsProjectionTxError::Conflict,
                "fact_conflict",
                eventexec::ProjectionTargetStoreErrorKind::Conflict,
            ),
            (
                SettingsProjectionTxError::OutOfOrder,
                "out_of_order",
                eventexec::ProjectionTargetStoreErrorKind::OutOfOrder,
            ),
            (
                SettingsProjectionTxError::VersionRegression,
                "version_regression",
                eventexec::ProjectionTargetStoreErrorKind::Permanent,
            ),
            (
                SettingsProjectionTxError::Storage(sqlx::Error::PoolTimedOut),
                "storage",
                eventexec::ProjectionTargetStoreErrorKind::Transient,
            ),
        ];

        for (error, expected_reason, expected_kind) in cases {
            assert_eq!(error.reason(), expected_reason);
            assert_eq!(error.target_kind(), expected_kind);
        }
    }
}
