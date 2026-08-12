//! Closed tenant transaction façade for the Settings metadata projection.
//!
//! Runtime atomicity / ordering are Medium (SQL + row-lock semantics are not Hard-expressible).
//! INVARIANT: SETTINGS-PROJECTION-ATOMIC-01 { level = "Medium", exec = "test", source = "code", synthetic_red = "tests::rejects_split_settlement_sql_bait", anti_vacuity = "tests::facade_exposes_single_settlement_sql_per_lane" } -- current-row mutation, dedupe receipt, and persistent high-water share this one LocalTx settlement.
//! INVARIANT: SETTINGS-PROJECTION-ORDERING-01 { level = "Medium", exec = "test", source = "code", synthetic_red = "tests::rejects_unlocked_ordering_check_bait", anti_vacuity = "tests::facade_keeps_ordering_checks_on_locked_apply_path" } -- immutable generation identity, receipt-first idempotency, LSN ordering, and config-version monotonicity are checked while holding the generation row lock.

use futures::future::BoxFuture;
use settings::ports::{
    SETTINGS_CONFIG_PROJECTION_ID, SettingKey, SettingsProjectionApplyScope,
    SettingsProjectionMutation, SettingsProjectionReadScope, TenantRepoScope,
};
use sqlx::PgConnection;

use super::{
    LocalTxAttempt, ProjectionOperatorWriteLane, ServingReadLane, TenantDb, TenantLane, WriteLane,
    tenant_lane_seal,
};
use crate::projection_worker::{ProjectionWorkerApplyMint, ProjectionWorkerTarget};

/// Opaque handoff minted only from a verified worker store and its plan-issued target.
pub(crate) struct ProjectionWorkerBoundPool {
    pool: sqlx::PgPool,
    target: ProjectionWorkerTarget,
}

impl ProjectionWorkerBoundPool {
    pub(crate) fn mint(
        pool: sqlx::PgPool,
        target: ProjectionWorkerTarget,
        _mint: ProjectionWorkerApplyMint,
    ) -> Self {
        Self { pool, target }
    }
}

/// Closed write lane carried only by the Settings-owned projection worker slice.
#[derive(Clone)]
pub(crate) struct ProjectionWorkerWriteLane {
    target: ProjectionWorkerTarget,
}

impl tenant_lane_seal::Sealed for ProjectionWorkerWriteLane {}
impl TenantLane for ProjectionWorkerWriteLane {}
impl WriteLane for ProjectionWorkerWriteLane {}

impl TenantDb<ProjectionWorkerWriteLane> {
    pub(crate) fn new_projection_worker(pool: ProjectionWorkerBoundPool) -> Self {
        Self {
            pool: pool.pool,
            lane: ProjectionWorkerWriteLane {
                target: pool.target,
            },
        }
    }
}

pub(in crate::cotx) trait SettingsProjectionWriteLane: WriteLane {
    const APPLY_SQL: &'static str;

    fn matches_scope(&self, _scope: &SettingsProjectionApplyScope) -> bool {
        true
    }
}

impl SettingsProjectionWriteLane for ProjectionWorkerWriteLane {
    const APPLY_SQL: &'static str = "SELECT public.rss_settings_projection_apply_worker(\
         $1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13\
         )";

    fn matches_scope(&self, scope: &SettingsProjectionApplyScope) -> bool {
        scope.projection().as_str() == self.target.projection_id()
            && scope.target_generation().as_str() == self.target.target_generation()
            && scope.definition_version() == self.target.definition_version()
            && scope.definition_schema_digest().as_str() == self.target.definition_schema_digest()
            && scope.input_generation().as_str() == self.target.input_generation()
    }
}

impl SettingsProjectionWriteLane for ProjectionOperatorWriteLane {
    const APPLY_SQL: &'static str = "SELECT public.rss_settings_projection_apply_operator(\
         $1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13\
         )";
}

pub(crate) struct SettingsProjectionStoredRow {
    pub(crate) config_version: i64,
    pub(crate) change_kind: String,
    pub(crate) source_event_id: String,
    pub(crate) source_lsn: i64,
    pub(crate) source_occurred_at_secs: i64,
    pub(crate) created_at_epoch_micros: i64,
    pub(crate) updated_at_epoch_micros: i64,
}

pub(crate) struct ActiveProjectionStoredRow {
    pub(crate) generation: String,
    pub(crate) definition_version: String,
    pub(crate) definition_schema_digest: String,
    pub(crate) input_generation: String,
    pub(crate) promoted_high_water_lsn: i64,
    pub(crate) token: i64,
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
    tenant: rss_request_context::TenantId,
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
        .bind(self.tenant.to_string())
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
    tenant: rss_request_context::TenantId,
}

impl SettingsProjectionWriteTx<'_> {
    async fn apply(
        &mut self,
        apply_sql: &'static str,
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
        let outcome = sqlx::query_scalar::<_, String>(apply_sql)
            .bind(self.tenant.to_string())
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
    pub(crate) async fn settings_projection_resolve_active(
        &self,
        scope: TenantRepoScope,
    ) -> Result<Option<ActiveProjectionStoredRow>, sqlx::Error> {
        self.read(scope, move |tx| {
            Box::pin(async move {
                let row: Option<(String, String, String, String, i64, i64)> = sqlx::query_as(
                    "SELECT generation, definition_version, definition_schema_digest, \
                            input_generation, promoted_high_water_lsn, token \
                     FROM public.rss_settings_projection_resolve_active()",
                )
                .fetch_optional(&mut *tx.conn)
                .await?;
                Ok(row.map(
                    |(
                        generation,
                        definition_version,
                        definition_schema_digest,
                        input_generation,
                        promoted_high_water_lsn,
                        token,
                    )| ActiveProjectionStoredRow {
                        generation,
                        definition_version,
                        definition_schema_digest,
                        input_generation,
                        promoted_high_water_lsn,
                        token,
                    },
                ))
            })
        })
        .await
    }

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
        if !self.lane.matches_scope(&scope) {
            return LocalTxAttempt::unsettled(
                SettingsProjectionTxError::DefinitionIdentityMismatch,
            );
        }
        let tenant_scope = scope.tenant_scope();
        self.write_attempt(
            tenant_scope,
            move |tx| {
                Box::pin(async move {
                    let outcome = SettingsProjectionWriteTx {
                        conn: &mut *tx.conn,
                        tenant: tx.tenant,
                    }
                    .apply(L::APPLY_SQL, &scope, &mutation)
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

    #[test]
    fn rejects_split_settlement_sql_bait() {
        let bait = r#"
            const APPLY_SQL: &str = "SELECT public.rss_settings_projection_apply_worker(...)";
            const DEDUPE_SQL: &str = "INSERT INTO settings_projection_dedupe_receipts ...";
            const HIGH_WATER_SQL: &str = "UPDATE settings_projection_high_water ...";
        "#;
        assert!(
            bait.matches("rss_settings_projection_apply").count()
                + bait.matches("dedupe_receipts").count()
                + bait.matches("high_water").count()
                > 1,
            "bait must look like a split settlement surface"
        );
    }

    #[test]
    fn facade_exposes_single_settlement_sql_per_lane() {
        let source = include_str!("settings_projection.rs");
        let production: String = source
            .lines()
            .take_while(|line| !line.contains("#[cfg(test)]"))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(
            production
                .matches("rss_settings_projection_apply_worker")
                .count(),
            1,
            "worker lane must expose exactly one settlement SQL"
        );
        assert_eq!(
            production
                .matches("rss_settings_projection_apply_operator")
                .count(),
            1,
            "operator lane must expose exactly one settlement SQL"
        );
        assert!(
            !production.contains("settings_projection_dedupe_receipts")
                && !production.contains("INSERT INTO"),
            "facade must not open a second write path beside the settlement SQL"
        );
    }

    #[test]
    fn rejects_unlocked_ordering_check_bait() {
        let bait = "check LSN ordering after releasing generation row lock";
        assert!(
            bait.contains("after releasing") && bait.contains("ordering"),
            "bait must describe unlocked ordering checks"
        );
    }

    #[test]
    fn facade_keeps_ordering_checks_on_locked_apply_path() {
        let source = include_str!("settings_projection.rs");
        let production: String = source
            .lines()
            .take_while(|line| !line.contains("#[cfg(test)]"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            production.contains("rss_settings_projection_apply_worker")
                && production.contains("rss_settings_projection_apply_operator"),
            "ordering/identity checks remain inside the locked apply SQL path"
        );
        assert!(
            !production.to_lowercase().contains("for update")
                || production.contains("rss_settings_projection_apply"),
            "no unlocked ordering helper outside apply"
        );
    }
}
