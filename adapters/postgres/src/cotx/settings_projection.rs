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

use super::{
    LocalTxAttempt, ProjectionOperatorWriteLane, ServingReadLane, ServingWriteLane, TenantDb,
    TenantLane, WriteLane,
};

pub(in crate::cotx) trait SettingsProjectionWriteLane: WriteLane {}

impl SettingsProjectionWriteLane for ServingWriteLane {}
impl SettingsProjectionWriteLane for ProjectionOperatorWriteLane {}

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
    #[error("settings projection apply function returned an invalid outcome")]
    InvalidFunctionOutcome,
    #[error("settings projection PostgreSQL operation failed")]
    Storage(#[source] sqlx::Error),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SettingsProjectionNumericField {
    SourceLsn,
    ConfigVersion,
    OccurredAt,
}

impl SettingsProjectionTxError {
    fn from_sqlx(error: sqlx::Error) -> Self {
        match error
            .as_database_error()
            .and_then(|database| database.code())
        {
            Some(code) if code.as_ref() == "P1901" => Self::DefinitionIdentityMismatch,
            Some(code) if code.as_ref() == "P1902" => Self::TenantMismatch,
            Some(code) if code.as_ref() == "P1903" => Self::Conflict,
            Some(code) if code.as_ref() == "P1904" => Self::OutOfOrder,
            Some(code) if code.as_ref() == "P1905" => Self::VersionRegression,
            _ => Self::Storage(error),
        }
    }

    pub(crate) fn target_reason(&self) -> consistency::ProjectionApplyErrorReason {
        use consistency::ProjectionApplyErrorReason;
        match self {
            Self::TenantMismatch => ProjectionApplyErrorReason::TenantDrift,
            Self::DefinitionIdentityMismatch => ProjectionApplyErrorReason::TargetDefinitionDrift,
            Self::InvalidFunctionOutcome => ProjectionApplyErrorReason::ProviderInvariant,
            Self::Conflict => ProjectionApplyErrorReason::Conflict,
            Self::OutOfOrder => ProjectionApplyErrorReason::OutOfOrder,
            Self::NumericOutOfRange(_) => ProjectionApplyErrorReason::PayloadValueInvalid,
            Self::VersionRegression => ProjectionApplyErrorReason::VersionRegression,
            Self::Storage(error) => match crate::tx_retry::classify_sqlx_error(error) {
                consistency::TxRetryClass::Transient => ProjectionApplyErrorReason::Transient,
                consistency::TxRetryClass::Permanent => {
                    ProjectionApplyErrorReason::ProviderPermanent
                }
                consistency::TxRetryClass::Conflict | consistency::TxRetryClass::OwnershipLost => {
                    ProjectionApplyErrorReason::ProviderInvariant
                }
            },
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

        let source_lsn = i64::try_from(mutation.source_lsn().get()).map_err(|_| {
            SettingsProjectionTxError::NumericOutOfRange(SettingsProjectionNumericField::SourceLsn)
        })?;
        let config_version = i64::try_from(mutation.config_version()).map_err(|_| {
            SettingsProjectionTxError::NumericOutOfRange(
                SettingsProjectionNumericField::ConfigVersion,
            )
        })?;
        let occurred_at = i64::try_from(mutation.source_occurred_at_secs()).map_err(|_| {
            SettingsProjectionTxError::NumericOutOfRange(SettingsProjectionNumericField::OccurredAt)
        })?;
        let outcome = sqlx::query_scalar::<_, String>(
            "SELECT public.rss_settings_projection_apply(\
                 $1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13\
             )",
        )
        .bind(self.tenant.as_uuid().to_string())
        .bind(scope.projection().as_str())
        .bind(scope.target_generation().as_str())
        .bind(scope.definition_version())
        .bind(scope.definition_schema_digest().as_str())
        .bind(scope.input_generation().as_str())
        .bind(mutation.key().as_str())
        .bind(config_version)
        .bind(mutation.change_kind().to_string())
        .bind(mutation.source_event_id())
        .bind(source_lsn)
        .bind(occurred_at)
        .bind(mutation.fact_digest().as_slice())
        .fetch_one(&mut *self.conn)
        .await
        .map_err(SettingsProjectionTxError::from_sqlx)?;
        match outcome.as_str() {
            "applied" => Ok(eventexec::ProjectionTargetStoreOutcome::Applied),
            "duplicate" => Ok(eventexec::ProjectionTargetStoreOutcome::Duplicate),
            _ => Err(SettingsProjectionTxError::InvalidFunctionOutcome),
        }
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

// reason: the public TenantDb carrier is specialized only by this crate-private sealed lane set.
#[allow(private_bounds)]
impl<L> TenantDb<L>
where
    L: TenantLane + SettingsProjectionWriteLane,
{
    pub(crate) async fn settings_projection_apply(
        &self,
        scope: SettingsProjectionApplyScope,
        mutation: SettingsProjectionMutation,
        #[cfg(all(test, feature = "integration"))] fault: Option<
            crate::settings_projection::SettingsProjectionTestFault,
        >,
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
                    apply_test_fault(tx, outcome, fault).await?;
                    Ok(outcome)
                }) as BoxFuture<'_, _>
            },
            SettingsProjectionTxError::Storage,
        )
        .await
    }
}

#[cfg(all(test, feature = "integration"))]
async fn apply_test_fault<L: TenantLane>(
    tx: &mut super::TenantTx<'_, L>,
    outcome: eventexec::ProjectionTargetStoreOutcome,
    fault: Option<crate::settings_projection::SettingsProjectionTestFault>,
) -> Result<(), SettingsProjectionTxError> {
    use crate::settings_projection::SettingsProjectionTestFault;
    if outcome != eventexec::ProjectionTargetStoreOutcome::Applied {
        return Ok(());
    }
    match fault {
        Some(SettingsProjectionTestFault::CommitUnknown) => tx
            .inject_commit_unknown_after_commit()
            .await
            .map_err(SettingsProjectionTxError::Storage),
        Some(SettingsProjectionTestFault::RollbackFailed) => {
            tx.inject_rollback_failed_after_rollback()
                .await
                .map_err(SettingsProjectionTxError::Storage)?;
            Err(SettingsProjectionTxError::Storage(sqlx::Error::Protocol(
                "injected settings projection failure before rollback".into(),
            )))
        }
        Some(SettingsProjectionTestFault::ConfirmedRollback) => {
            Err(SettingsProjectionTxError::Storage(sqlx::Error::Protocol(
                "injected settings projection confirmed rollback".into(),
            )))
        }
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::{SettingsProjectionNumericField, SettingsProjectionTxError};

    #[test]
    fn storage_classification_reuses_canonical_sqlx_taxonomy() {
        assert_eq!(
            SettingsProjectionTxError::Storage(sqlx::Error::PoolTimedOut).target_reason(),
            consistency::ProjectionApplyErrorReason::Transient
        );
        assert_eq!(
            SettingsProjectionTxError::Storage(sqlx::Error::Protocol("invalid".into()))
                .target_reason(),
            consistency::ProjectionApplyErrorReason::ProviderPermanent
        );
    }

    #[test]
    fn failure_reasons_are_closed_and_keep_permanent_failures_distinguishable() {
        let cases = [
            (
                SettingsProjectionTxError::TenantMismatch,
                consistency::ProjectionApplyErrorReason::TenantDrift,
            ),
            (
                SettingsProjectionTxError::DefinitionIdentityMismatch,
                consistency::ProjectionApplyErrorReason::TargetDefinitionDrift,
            ),
            (
                SettingsProjectionTxError::NumericOutOfRange(
                    SettingsProjectionNumericField::SourceLsn,
                ),
                consistency::ProjectionApplyErrorReason::PayloadValueInvalid,
            ),
            (
                SettingsProjectionTxError::NumericOutOfRange(
                    SettingsProjectionNumericField::ConfigVersion,
                ),
                consistency::ProjectionApplyErrorReason::PayloadValueInvalid,
            ),
            (
                SettingsProjectionTxError::NumericOutOfRange(
                    SettingsProjectionNumericField::OccurredAt,
                ),
                consistency::ProjectionApplyErrorReason::PayloadValueInvalid,
            ),
            (
                SettingsProjectionTxError::Conflict,
                consistency::ProjectionApplyErrorReason::Conflict,
            ),
            (
                SettingsProjectionTxError::OutOfOrder,
                consistency::ProjectionApplyErrorReason::OutOfOrder,
            ),
            (
                SettingsProjectionTxError::VersionRegression,
                consistency::ProjectionApplyErrorReason::VersionRegression,
            ),
            (
                SettingsProjectionTxError::InvalidFunctionOutcome,
                consistency::ProjectionApplyErrorReason::ProviderInvariant,
            ),
            (
                SettingsProjectionTxError::Storage(sqlx::Error::PoolTimedOut),
                consistency::ProjectionApplyErrorReason::Transient,
            ),
        ];

        for (error, expected_reason) in cases {
            assert_eq!(error.target_reason(), expected_reason);
            assert_eq!(error.target_reason().as_label(), expected_reason.as_label());
        }
    }
}
