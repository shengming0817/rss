//! Settings v3 projection replay / active-generation control helpers.
//!
//! The active pointer is a typed, generation-bound database row. The only mutation seam is one
//! fixed SQL function that checks source catch-up, target identity, quarantine, and pointer CAS in
//! the same transaction.

use std::sync::Arc;

use authn::{ProjectionMaintenanceAction, ProjectionMaintenanceReceipt};
use eventexec::{ProjectionSelector, ProjectionVersion};

use crate::PgStore;
use crate::projection_events::PgProjectionSourceReader;

/// Explicit active-generation swap precondition. Callers must choose one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectionPointerPrecondition {
    ExpectUnset,
    ExpectedActiveGeneration(ProjectionVersion),
}

/// Current active Settings projection status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionPointerStatus {
    active_generation: Option<ProjectionVersion>,
    token: Option<vocab::Epoch>,
    promoted_high_water_lsn: Option<consistency::Lsn>,
    selected_generation_high_water_lsn: Option<consistency::Lsn>,
    source_high_water_lsn: Option<consistency::Lsn>,
}

impl ProjectionPointerStatus {
    pub fn active_generation(&self) -> Option<&ProjectionVersion> {
        self.active_generation.as_ref()
    }

    pub fn token(&self) -> Option<vocab::Epoch> {
        self.token
    }

    pub fn promoted_high_water_lsn(&self) -> Option<consistency::Lsn> {
        self.promoted_high_water_lsn
    }

    pub fn selected_generation_high_water_lsn(&self) -> Option<consistency::Lsn> {
        self.selected_generation_high_water_lsn
    }

    pub fn source_high_water_lsn(&self) -> Option<consistency::Lsn> {
        self.source_high_water_lsn
    }
}

/// Successful active-generation swap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionSwapOutcome {
    previous_generation: Option<ProjectionVersion>,
    active_generation: ProjectionVersion,
    token: vocab::Epoch,
    promoted_high_water_lsn: consistency::Lsn,
}

impl ProjectionSwapOutcome {
    pub fn previous_generation(&self) -> Option<&ProjectionVersion> {
        self.previous_generation.as_ref()
    }

    pub fn active_generation(&self) -> &ProjectionVersion {
        &self.active_generation
    }

    pub fn token(&self) -> vocab::Epoch {
        self.token
    }

    pub fn promoted_high_water_lsn(&self) -> consistency::Lsn {
        self.promoted_high_water_lsn
    }
}

/// Closed set returned by the fixed SQL swap carrier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionSwapRejection {
    SourceMissing,
    CheckpointMissing,
    CheckpointStale,
    CheckpointAhead,
    GenerationMissing,
    DefinitionMismatch,
    InputGenerationMismatch,
    GenerationHighWaterMismatch,
    TargetQuarantined,
}

impl ProjectionSwapRejection {
    fn parse(raw: &str) -> Option<Self> {
        Some(match raw {
            "source_missing" => Self::SourceMissing,
            "checkpoint_missing" => Self::CheckpointMissing,
            "checkpoint_stale" => Self::CheckpointStale,
            "checkpoint_ahead" => Self::CheckpointAhead,
            "generation_missing" => Self::GenerationMissing,
            "definition_mismatch" => Self::DefinitionMismatch,
            "input_generation_mismatch" => Self::InputGenerationMismatch,
            "generation_high_water_mismatch" => Self::GenerationHighWaterMismatch,
            "target_quarantined" => Self::TargetQuarantined,
            _ => return None,
        })
    }
}

#[derive(Debug)]
struct ActivePointerRow {
    generation: ProjectionVersion,
    promoted_high_water_lsn: consistency::Lsn,
    token: vocab::Epoch,
}

#[derive(Debug, sqlx::FromRow)]
struct ProjectionSwapSqlRow {
    outcome: String,
    reason: Option<String>,
    previous_generation: Option<String>,
    active_generation: Option<String>,
    result_token: Option<i64>,
    promoted_high_water_lsn: Option<i64>,
}

/// Crate-private Projection control store backed by exact operator and scoped-source lanes.
pub(crate) struct PgProjectionControl<'a> {
    store: Arc<PgStore>,
    receipt: &'a ProjectionMaintenanceReceipt,
    source: &'a PgProjectionSourceReader,
}

impl<'a> PgProjectionControl<'a> {
    pub(crate) fn new(
        store: Arc<PgStore>,
        receipt: &'a ProjectionMaintenanceReceipt,
        source: &'a PgProjectionSourceReader,
    ) -> Self {
        Self {
            store,
            receipt,
            source,
        }
    }

    pub(crate) async fn status(
        &self,
        selector: &ProjectionSelector,
    ) -> Result<ProjectionPointerStatus, ProjectionControlError> {
        authorize_receipt(self.receipt, ProjectionMaintenanceAction::Status, selector)?;
        let active = self.read_active(selector).await?;
        let selected_generation_high_water_lsn = self.read_checkpoint_optional(selector).await?;
        let source_high_water_lsn = self.read_projection_source_high_water().await?;
        Ok(ProjectionPointerStatus {
            active_generation: active.as_ref().map(|row| row.generation.clone()),
            token: active.as_ref().map(|row| row.token),
            promoted_high_water_lsn: active.as_ref().map(|row| row.promoted_high_water_lsn),
            selected_generation_high_water_lsn,
            source_high_water_lsn,
        })
    }

    pub(crate) async fn swap_active(
        &self,
        selector: &ProjectionSelector,
        precondition: ProjectionPointerPrecondition,
    ) -> Result<ProjectionSwapOutcome, ProjectionControlError> {
        authorize_receipt(self.receipt, ProjectionMaintenanceAction::Swap, selector)?;
        let (expected_generation, expected_token) = match precondition {
            ProjectionPointerPrecondition::ExpectUnset => (None, None),
            ProjectionPointerPrecondition::ExpectedActiveGeneration(expected) => {
                let current = self
                    .read_active(selector)
                    .await?
                    .ok_or(ProjectionControlError::PreconditionFailed)?;
                if current.generation != expected {
                    return Err(ProjectionControlError::PreconditionFailed);
                }
                (Some(expected), Some(current.token))
            }
        };
        let expected_token = expected_token
            .map(|token| i64::try_from(token.get()))
            .transpose()
            .map_err(ProjectionControlError::Int)?;
        let definition = settings_projection_identity()?;
        let row: ProjectionSwapSqlRow = sqlx::query_as(
            r#"
            SELECT outcome, reason, previous_generation, active_generation,
                   result_token, promoted_high_water_lsn
            FROM public.rss_projection_operator_swap_active(
                $1::uuid, $2, $3, $4::bigint, $5, $6, $7
            )
            "#,
        )
        .bind(selector.tenant().to_string())
        .bind(selector.version().as_str())
        .bind(expected_generation.as_ref().map(ProjectionVersion::as_str))
        .bind(expected_token)
        .bind(definition.projection_definition_version())
        .bind(definition.projection_definition_schema_digest())
        .bind(postgres_migration_inventory::projection_input_generation())
        .fetch_one(&self.store.pool)
        .await
        .map_err(ProjectionControlError::Sql)?;

        map_swap_row(row)
    }

    async fn read_checkpoint_optional(
        &self,
        selector: &ProjectionSelector,
    ) -> Result<Option<consistency::Lsn>, ProjectionControlError> {
        let row: Option<(i64,)> = sqlx::query_as(
            r#"
            SELECT offset_lsn
            FROM public.rss_projection_operator_get_checkpoint($1::uuid, $2, $3)
            "#,
        )
        .bind(selector.tenant().to_string())
        .bind(selector.projection().as_str())
        .bind(selector.version().as_str())
        .fetch_optional(&self.store.pool)
        .await
        .map_err(ProjectionControlError::Sql)?;
        row.map(|(offset,)| {
            u64::try_from(offset)
                .map(consistency::Lsn::new)
                .map_err(ProjectionControlError::Int)
        })
        .transpose()
    }

    async fn read_projection_source_high_water(
        &self,
    ) -> Result<Option<consistency::Lsn>, ProjectionControlError> {
        self.source
            .source_high_water()
            .await
            .map_err(|error| match error {
                crate::projection_events::ProjectionSourceReadError::ScopeInvalid => {
                    ProjectionControlError::SourceScopeInvalid
                }
                other => ProjectionControlError::SourceRead(other.into_engine()),
            })
    }

    async fn read_active(
        &self,
        selector: &ProjectionSelector,
    ) -> Result<Option<ActivePointerRow>, ProjectionControlError> {
        let definition = settings_projection_identity()?;
        if selector.projection().as_str() != definition.projection_id() {
            return Err(ProjectionControlError::SourceTargetMismatch);
        }
        let row: Option<(String, i64, i64)> = sqlx::query_as(
            r#"
            SELECT generation, promoted_high_water_lsn, token
            FROM public.rss_projection_operator_status_active($1::uuid)
            "#,
        )
        .bind(selector.tenant().to_string())
        .fetch_optional(&self.store.pool)
        .await
        .map_err(ProjectionControlError::Sql)?;
        row.map(|(generation, high_water, token)| {
            Ok(ActivePointerRow {
                generation: ProjectionVersion::parse(&generation)
                    .map_err(ProjectionControlError::InvalidGeneration)?,
                promoted_high_water_lsn: consistency::Lsn::new(
                    u64::try_from(high_water).map_err(ProjectionControlError::Int)?,
                ),
                token: vocab::Epoch::new(
                    u64::try_from(token).map_err(ProjectionControlError::Int)?,
                ),
            })
        })
        .transpose()
    }
}

fn settings_projection_identity()
-> Result<postgres_migration_inventory::ProjectionInputIdentity, ProjectionControlError> {
    postgres_migration_inventory::projection_inputs()
        .iter()
        .copied()
        .find(|identity| identity.projection_id() == crate::SETTINGS_PROJECTION_ID)
        .ok_or(ProjectionControlError::SettingsIdentityMissing)
}

impl PgStore {
    pub(crate) fn projection_control<'a>(
        store: Arc<PgStore>,
        receipt: &'a ProjectionMaintenanceReceipt,
        source: &'a PgProjectionSourceReader,
    ) -> PgProjectionControl<'a> {
        PgProjectionControl::new(store, receipt, source)
    }
}

pub(crate) fn authorize_receipt(
    receipt: &ProjectionMaintenanceReceipt,
    action: ProjectionMaintenanceAction,
    selector: &ProjectionSelector,
) -> Result<(), ProjectionControlError> {
    if receipt.authorizes(action, selector.tenant(), selector.projection().as_str()) {
        Ok(())
    } else {
        Err(ProjectionControlError::ReceiptTargetMismatch)
    }
}

fn map_swap_row(
    row: ProjectionSwapSqlRow,
) -> Result<ProjectionSwapOutcome, ProjectionControlError> {
    let ProjectionSwapSqlRow {
        outcome,
        reason,
        previous_generation,
        active_generation,
        result_token,
        promoted_high_water_lsn,
    } = row;
    match outcome.as_str() {
        "applied" => Ok(ProjectionSwapOutcome {
            previous_generation: previous_generation
                .map(|value| ProjectionVersion::parse(&value))
                .transpose()
                .map_err(ProjectionControlError::InvalidGeneration)?,
            active_generation: ProjectionVersion::parse(
                active_generation
                    .as_deref()
                    .ok_or(ProjectionControlError::InvalidOperatorOutcome)?,
            )
            .map_err(ProjectionControlError::InvalidGeneration)?,
            token: vocab::Epoch::new(
                u64::try_from(result_token.ok_or(ProjectionControlError::InvalidOperatorOutcome)?)
                    .map_err(ProjectionControlError::Int)?,
            ),
            promoted_high_water_lsn: consistency::Lsn::new(
                u64::try_from(
                    promoted_high_water_lsn
                        .ok_or(ProjectionControlError::InvalidOperatorOutcome)?,
                )
                .map_err(ProjectionControlError::Int)?,
            ),
        }),
        "rejected" => Err(ProjectionControlError::SwapRejected(
            reason
                .as_deref()
                .and_then(ProjectionSwapRejection::parse)
                .ok_or(ProjectionControlError::InvalidOperatorOutcome)?,
        )),
        "conflict" => Err(ProjectionControlError::CasConflict),
        "fenced" => Err(ProjectionControlError::CasFenced),
        _ => Err(ProjectionControlError::InvalidOperatorOutcome),
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProjectionControlError {
    #[error("projection maintenance receipt does not authorize the requested action and target")]
    ReceiptTargetMismatch,
    #[error("projection source scope does not match the Settings v3 operator target")]
    SourceTargetMismatch,
    #[error("projection source authority or scope is invalid")]
    SourceScopeInvalid,
    #[error("projection active-generation precondition failed")]
    PreconditionFailed,
    #[error("projection active-generation swap was rejected: {0:?}")]
    SwapRejected(ProjectionSwapRejection),
    #[error("projection active-generation CAS conflict")]
    CasConflict,
    #[error("projection active-generation CAS token was fenced")]
    CasFenced,
    #[error("projection operator returned an invalid fixed-function outcome")]
    InvalidOperatorOutcome,
    #[error("generated Settings projection identity is missing from the migration inventory")]
    SettingsIdentityMissing,
    #[error("projection operator returned a non-canonical generation")]
    InvalidGeneration(#[source] eventexec::ProjectionSelectorError),
    #[error("projection active-generation SQL operation failed")]
    Sql(#[source] sqlx::Error),
    #[error("projection source high-water read failed")]
    SourceRead(#[source] consistency::EngineError),
    #[error("projection active-generation integer conversion failed")]
    Int(#[source] std::num::TryFromIntError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_swap_outcomes_are_closed_and_typed() -> Result<(), Box<dyn std::error::Error>> {
        let applied = map_swap_row(ProjectionSwapSqlRow {
            outcome: "applied".to_owned(),
            reason: None,
            previous_generation: Some("blue".to_owned()),
            active_generation: Some("green".to_owned()),
            result_token: Some(7),
            promoted_high_water_lsn: Some(11),
        })?;
        assert_eq!(
            applied.previous_generation().map(ProjectionVersion::as_str),
            Some("blue")
        );
        assert_eq!(applied.active_generation().as_str(), "green");
        assert_eq!(applied.token(), vocab::Epoch::new(7));

        for (reason, expected) in [
            ("source_missing", ProjectionSwapRejection::SourceMissing),
            (
                "checkpoint_missing",
                ProjectionSwapRejection::CheckpointMissing,
            ),
            ("checkpoint_stale", ProjectionSwapRejection::CheckpointStale),
            ("checkpoint_ahead", ProjectionSwapRejection::CheckpointAhead),
            (
                "generation_missing",
                ProjectionSwapRejection::GenerationMissing,
            ),
            (
                "definition_mismatch",
                ProjectionSwapRejection::DefinitionMismatch,
            ),
            (
                "input_generation_mismatch",
                ProjectionSwapRejection::InputGenerationMismatch,
            ),
            (
                "generation_high_water_mismatch",
                ProjectionSwapRejection::GenerationHighWaterMismatch,
            ),
            (
                "target_quarantined",
                ProjectionSwapRejection::TargetQuarantined,
            ),
        ] {
            assert_eq!(ProjectionSwapRejection::parse(reason), Some(expected));
            assert!(matches!(
                map_swap_row(ProjectionSwapSqlRow {
                    outcome: "rejected".to_owned(),
                    reason: Some(reason.to_owned()),
                    previous_generation: None,
                    active_generation: None,
                    result_token: None,
                    promoted_high_water_lsn: None,
                }),
                Err(ProjectionControlError::SwapRejected(actual)) if actual == expected
            ));
        }
        assert!(matches!(
            map_swap_row(ProjectionSwapSqlRow {
                outcome: "fenced".to_owned(),
                reason: None,
                previous_generation: None,
                active_generation: None,
                result_token: Some(8),
                promoted_high_water_lsn: None,
            }),
            Err(ProjectionControlError::CasFenced)
        ));
        Ok(())
    }
}
