//! Projection replay / shadow-swap control helpers.
//!
//! This module deliberately reuses existing durable primitives:
//! `checkpoint` stores shadow replay high-water, and `distributed_cas` stores the active pointer.

use std::sync::Arc;

use authn::{ProjectionMaintenanceAction, ProjectionMaintenanceReceipt};
use consistency::ProjectionBatchLimit;
use diport::{CasStore as _, CasStoreKey, CasStoreOutcome, CasStoreRequest, RedactedBytes};
use eventexec::{ProjectionActivePointer, ProjectionSelector, ProjectionVersion};

use crate::PgStore;

/// Explicit swap precondition. Callers must choose one; there is no weak default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectionPointerPrecondition {
    ExpectUnset,
    ExpectedActiveVersion(ProjectionVersion),
}

/// Current active projection pointer status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionPointerStatus {
    pointer: Option<ProjectionActivePointer>,
    token: Option<vocab::Epoch>,
    selected_shadow_high_water_lsn: Option<consistency::Lsn>,
    source_high_water_lsn: Option<consistency::Lsn>,
}

impl ProjectionPointerStatus {
    pub fn pointer(&self) -> Option<&ProjectionActivePointer> {
        self.pointer.as_ref()
    }

    pub fn token(&self) -> Option<vocab::Epoch> {
        self.token
    }

    pub fn selected_shadow_high_water_lsn(&self) -> Option<consistency::Lsn> {
        self.selected_shadow_high_water_lsn
    }

    pub fn source_high_water_lsn(&self) -> Option<consistency::Lsn> {
        self.source_high_water_lsn
    }
}

/// Successful active pointer promotion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionPromoteOutcome {
    previous: Option<ProjectionActivePointer>,
    active: ProjectionActivePointer,
    token: vocab::Epoch,
}

impl ProjectionPromoteOutcome {
    pub fn previous(&self) -> Option<&ProjectionActivePointer> {
        self.previous.as_ref()
    }

    pub fn active(&self) -> &ProjectionActivePointer {
        &self.active
    }

    pub fn token(&self) -> vocab::Epoch {
        self.token
    }
}

/// Projection control store backed by Postgres.
pub struct PgProjectionControl<'a> {
    store: Arc<PgStore>,
    receipt: &'a ProjectionMaintenanceReceipt,
}

impl<'a> PgProjectionControl<'a> {
    pub(crate) fn new(store: Arc<PgStore>, receipt: &'a ProjectionMaintenanceReceipt) -> Self {
        Self { store, receipt }
    }

    pub async fn status(
        &self,
        selector: &ProjectionSelector,
    ) -> Result<ProjectionPointerStatus, ProjectionControlError> {
        authorize_receipt(self.receipt, ProjectionMaintenanceAction::Status, selector)?;
        let raw = self.read_pointer(selector).await?;
        let selected_shadow_high_water_lsn = self.read_shadow_checkpoint_optional(selector).await?;
        let source_high_water_lsn = self.read_projection_source_high_water().await?;
        Ok(raw.into_public(selected_shadow_high_water_lsn, source_high_water_lsn))
    }

    pub async fn promote(
        &self,
        selector: &ProjectionSelector,
        precondition: ProjectionPointerPrecondition,
    ) -> Result<ProjectionPromoteOutcome, ProjectionControlError> {
        authorize_receipt(self.receipt, ProjectionMaintenanceAction::Swap, selector)?;
        let high_water = self.read_shadow_checkpoint(selector).await?;
        let source_high_water = self.read_projection_source_high_water().await?;
        verify_shadow_caught_up(high_water, source_high_water)?;
        let active = ProjectionActivePointer::new(selector, Some(high_water));
        let new_value = active
            .to_canonical_bytes()
            .map_err(ProjectionControlError::Encode)?;
        let current = self.read_pointer(selector).await?;
        verify_precondition(&current.pointer, &precondition)?;

        let outcome = self
            .store
            .cas_store()
            .compare_and_swap(CasStoreRequest {
                key: CasStoreKey::new(selector.active_pointer_key()),
                expected: current.raw.clone().map(RedactedBytes::new),
                new_value: RedactedBytes::new(new_value),
                expected_token: current.token,
            })
            .await
            .map_err(ProjectionControlError::Cas)?;

        map_promote_cas_outcome(outcome, current.pointer, active)
    }

    async fn read_shadow_checkpoint(
        &self,
        selector: &ProjectionSelector,
    ) -> Result<consistency::Lsn, ProjectionControlError> {
        self.read_shadow_checkpoint_optional(selector)
            .await?
            .ok_or(ProjectionControlError::ShadowCheckpointMissing)
    }

    async fn read_shadow_checkpoint_optional(
        &self,
        selector: &ProjectionSelector,
    ) -> Result<Option<consistency::Lsn>, ProjectionControlError> {
        let row: Option<(i64,)> = sqlx::query_as(
            r#"
            SELECT offset_lsn
            FROM checkpoint
            WHERE owner = $1 AND checkpoint_id = $2
            "#,
        )
        .bind(selector.shadow_checkpoint_owner().as_str())
        .bind(selector.shadow_checkpoint_id().as_str())
        .fetch_optional(&self.store.pool)
        .await
        .map_err(ProjectionControlError::Sql)?;

        let Some((offset,)) = row else {
            return Ok(None);
        };
        let offset = u64::try_from(offset).map_err(ProjectionControlError::Int)?;
        Ok(Some(consistency::Lsn::new(offset)))
    }

    async fn read_projection_source_high_water(
        &self,
    ) -> Result<Option<consistency::Lsn>, ProjectionControlError> {
        let source = self.store.projection_events();
        let mut after = None;
        let mut high_water = None;
        loop {
            let events = source
                .read_from(after, ProjectionBatchLimit::MAX)
                .await
                .map_err(ProjectionControlError::SourceRead)?;
            let Some(last) = events.last() else {
                return Ok(high_water);
            };
            high_water = Some(last.lsn());
            if events.len() < ProjectionBatchLimit::MAX.get() as usize {
                return Ok(high_water);
            }
            after = high_water;
        }
    }

    async fn read_pointer(
        &self,
        selector: &ProjectionSelector,
    ) -> Result<RawProjectionPointerStatus, ProjectionControlError> {
        let row: Option<(Vec<u8>, i64)> = sqlx::query_as(
            r#"
            SELECT value, token
            FROM distributed_cas
            WHERE cas_key = $1
            "#,
        )
        .bind(selector.active_pointer_key())
        .fetch_optional(&self.store.pool)
        .await
        .map_err(ProjectionControlError::Sql)?;

        let Some((raw, token)) = row else {
            return Ok(RawProjectionPointerStatus {
                pointer: None,
                raw: None,
                token: None,
            });
        };
        let pointer = serde_json::from_slice::<ProjectionActivePointer>(&raw)
            .map_err(ProjectionControlError::Decode)?;
        let token = vocab::Epoch::new(u64::try_from(token).map_err(ProjectionControlError::Int)?);
        Ok(RawProjectionPointerStatus {
            pointer: Some(pointer),
            raw: Some(raw),
            token: Some(token),
        })
    }
}

impl PgStore {
    pub(crate) fn projection_control(
        store: Arc<PgStore>,
        receipt: &ProjectionMaintenanceReceipt,
    ) -> PgProjectionControl<'_> {
        PgProjectionControl::new(store, receipt)
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

#[derive(Debug)]
struct RawProjectionPointerStatus {
    pointer: Option<ProjectionActivePointer>,
    raw: Option<Vec<u8>>,
    token: Option<vocab::Epoch>,
}

impl RawProjectionPointerStatus {
    fn into_public(
        self,
        selected_shadow_high_water_lsn: Option<consistency::Lsn>,
        source_high_water_lsn: Option<consistency::Lsn>,
    ) -> ProjectionPointerStatus {
        ProjectionPointerStatus {
            pointer: self.pointer,
            token: self.token,
            selected_shadow_high_water_lsn,
            source_high_water_lsn,
        }
    }
}

fn verify_precondition(
    current: &Option<ProjectionActivePointer>,
    precondition: &ProjectionPointerPrecondition,
) -> Result<(), ProjectionControlError> {
    match (current, precondition) {
        (None, ProjectionPointerPrecondition::ExpectUnset) => Ok(()),
        (Some(_), ProjectionPointerPrecondition::ExpectUnset) => {
            Err(ProjectionControlError::PreconditionFailed)
        }
        (Some(pointer), ProjectionPointerPrecondition::ExpectedActiveVersion(expected))
            if pointer.version() == expected =>
        {
            Ok(())
        }
        _ => Err(ProjectionControlError::PreconditionFailed),
    }
}

fn verify_shadow_caught_up(
    shadow_high_water: consistency::Lsn,
    source_high_water: Option<consistency::Lsn>,
) -> Result<(), ProjectionControlError> {
    if let Some(source_high_water) = source_high_water
        && shadow_high_water < source_high_water
    {
        return Err(ProjectionControlError::ShadowCheckpointStale {
            shadow_high_water,
            source_high_water,
        });
    }
    Ok(())
}

fn map_promote_cas_outcome(
    outcome: CasStoreOutcome,
    previous: Option<ProjectionActivePointer>,
    active: ProjectionActivePointer,
) -> Result<ProjectionPromoteOutcome, ProjectionControlError> {
    match outcome {
        CasStoreOutcome::Applied { token } => Ok(ProjectionPromoteOutcome {
            previous,
            active,
            token,
        }),
        CasStoreOutcome::Conflict { .. } => Err(ProjectionControlError::CasConflict),
        CasStoreOutcome::Fenced { .. } => Err(ProjectionControlError::CasConflict),
        _ => Err(ProjectionControlError::CasConflict),
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProjectionControlError {
    #[error("projection maintenance receipt does not authorize the requested action and target")]
    ReceiptTargetMismatch,
    #[error("projection shadow checkpoint is missing")]
    ShadowCheckpointMissing,
    #[error(
        "projection shadow checkpoint is behind source high-water: shadow={shadow_high_water:?} source={source_high_water:?}"
    )]
    ShadowCheckpointStale {
        shadow_high_water: consistency::Lsn,
        source_high_water: consistency::Lsn,
    },
    #[error("projection active pointer precondition failed")]
    PreconditionFailed,
    #[error("projection active pointer CAS conflict")]
    CasConflict,
    #[error("projection active pointer encode failed")]
    Encode(#[source] serde_json::Error),
    #[error("projection active pointer decode failed")]
    Decode(#[source] serde_json::Error),
    #[error("projection active pointer SQL operation failed")]
    Sql(#[source] sqlx::Error),
    #[error("projection active pointer CAS operation failed")]
    Cas(#[source] diport::CasStoreError),
    #[error("projection source high-water read failed")]
    SourceRead(#[source] consistency::EngineError),
    #[error("projection active pointer integer conversion failed")]
    Int(#[source] std::num::TryFromIntError),
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;

    use super::*;

    fn selector(version: &str) -> Result<ProjectionSelector, Box<dyn std::error::Error>> {
        Ok(ProjectionSelector::new(
            vocab::TenantId::parse("00000000-0000-4000-8000-000000000002")?,
            eventexec::ProjectionId::parse("audit.session-projection")?,
            ProjectionVersion::parse(version)?,
        ))
    }

    fn active_pointer(
        version: &str,
    ) -> Result<ProjectionActivePointer, Box<dyn std::error::Error>> {
        Ok(ProjectionActivePointer::new(
            &selector(version)?,
            Some(consistency::Lsn::new(7)),
        ))
    }

    #[test]
    fn promote_cas_outcome_maps_applied_conflict_and_fenced()
    -> Result<(), Box<dyn std::error::Error>> {
        let previous = Some(active_pointer("v1")?);
        let active = active_pointer("v2")?;
        let applied = map_promote_cas_outcome(
            CasStoreOutcome::Applied {
                token: vocab::Epoch::new(11),
            },
            previous.clone(),
            active.clone(),
        )?;
        assert_eq!(applied.previous(), previous.as_ref());
        assert_eq!(applied.active(), &active);
        assert_eq!(applied.token(), vocab::Epoch::new(11));

        let conflict = map_promote_cas_outcome(
            CasStoreOutcome::Conflict { current: None },
            None,
            active.clone(),
        );
        assert!(matches!(conflict, Err(ProjectionControlError::CasConflict)));

        let fenced = map_promote_cas_outcome(
            CasStoreOutcome::Fenced {
                current_token: vocab::Epoch::new(12),
            },
            None,
            active,
        );
        assert!(matches!(fenced, Err(ProjectionControlError::CasConflict)));
        Ok(())
    }

    #[test]
    fn shadow_checkpoint_must_catch_up_to_source_high_water() {
        assert!(verify_shadow_caught_up(consistency::Lsn::new(7), None).is_ok());
        assert!(
            verify_shadow_caught_up(consistency::Lsn::new(7), Some(consistency::Lsn::new(7)))
                .is_ok()
        );
        let stale =
            verify_shadow_caught_up(consistency::Lsn::new(6), Some(consistency::Lsn::new(7)));
        assert!(matches!(
            stale,
            Err(ProjectionControlError::ShadowCheckpointStale { .. })
        ));
    }

    #[test]
    fn projection_control_error_preserves_wrapped_sources() {
        let encode =
            ProjectionControlError::Encode(serde_json::Error::io(std::io::Error::other("encode")));
        assert!(encode.source().is_some());

        let decode =
            ProjectionControlError::Decode(serde_json::Error::io(std::io::Error::other("decode")));
        assert!(decode.source().is_some());

        let sql = ProjectionControlError::Sql(sqlx::Error::RowNotFound);
        assert!(sql.source().is_some());

        let cas =
            ProjectionControlError::Cas(diport::CasStoreError::new(std::io::Error::other("cas")));
        assert!(cas.source().is_some());

        let source_read = ProjectionControlError::SourceRead(consistency::EngineError::new(
            consistency::EngineErrorKind::Transient,
        ));
        assert!(source_read.source().is_some());
    }
}
