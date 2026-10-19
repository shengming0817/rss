use crate::*;
use serde::Serialize;
use std::num::NonZeroU32;

/// Lifecycle facts apply to the exact returned selection, not to batch admission.
#[derive(Clone, Debug, Default)]
pub struct Availability {
    pub excluded: Vec<UnavailableRange>,
}
#[derive(Clone, Debug)]
pub struct UnavailableRange {
    pub selection: Selection,
    pub window: Interval,
    pub reason: UnavailableReason,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnavailableReason {
    Deleted,
    Pruned,
}

/// Every variant carries only its own required inputs. Products choose all policy times.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "operation", rename_all = "camelCase")]
pub enum MaintenanceAction {
    Recompute {
        spec: SummarySpec,
        window: Interval,
    },
    AdvanceCutoff {
        selection: Selection,
        before: Timestamp,
    },
    Prune {
        selection: Selection,
        raw_before: Timestamp,
        summaries_before: Timestamp,
    },
    ExpireReceipts {
        stream: Stream,
        before: Timestamp,
    },
    Delete {
        selection: Selection,
        window: Interval,
        restore_until: Timestamp,
    },
    Restore {
        selection: Selection,
        window: Interval,
        deletion_fence: Id,
    },
    CloseStream {
        stream: Stream,
    },
    /// Reclaim closed-stream identities after raw, summaries, receipts and restore dependencies end.
    Reclaim {
        stream: Stream,
    },
}
impl MaintenanceAction {
    pub fn scope(&self) -> &Scope {
        match self {
            Self::Recompute { spec, .. } => spec.stream().scope(),
            Self::AdvanceCutoff { selection, .. }
            | Self::Prune { selection, .. }
            | Self::Delete { selection, .. }
            | Self::Restore { selection, .. } => selection.scope(),
            Self::CloseStream { stream }
            | Self::Reclaim { stream }
            | Self::ExpireReceipts { stream, .. } => stream.scope(),
        }
    }
    fn validate(&self) -> Result<(), Error> {
        match self {
            Self::Recompute { spec, window } => {
                spec.validate()?;
                positive(*window)
            }
            Self::Delete {
                selection, window, ..
            }
            | Self::Restore {
                selection, window, ..
            } => {
                selection.validate()?;
                positive(*window)
            }
            Self::AdvanceCutoff { selection, .. } => selection.validate(),
            Self::Prune { selection, .. } => selection.validate(),
            Self::CloseStream { .. } | Self::Reclaim { .. } | Self::ExpireReceipts { .. } => Ok(()),
        }
    }
}
fn positive(window: Interval) -> Result<(), Error> {
    if window.width_micros() == 0 {
        Err(Error::InvalidInput)
    } else {
        Ok(())
    }
}
/// Explicit per-step work ceilings. Rows bound source/projection mutations; buckets
/// bound native materialization work, whose scan is bounded by the caller deadline.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MaintenanceBudget {
    pub rows: NonZeroU32,
    pub buckets: NonZeroU32,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MaintenanceRequest {
    id: Id,
    action: MaintenanceAction,
    budget: MaintenanceBudget,
}
impl MaintenanceRequest {
    pub fn new(
        id: Id,
        action: MaintenanceAction,
        budget: MaintenanceBudget,
    ) -> Result<Self, Error> {
        action.validate()?;
        Ok(Self { id, action, budget })
    }
    pub const fn id(&self) -> &Id {
        &self.id
    }
    pub const fn action(&self) -> &MaintenanceAction {
        &self.action
    }
    pub const fn budget(&self) -> MaintenanceBudget {
        self.budget
    }
    pub fn scope(&self) -> &Scope {
        self.action.scope()
    }
    pub fn binding(&self) -> Result<Digest, Error> {
        digest(b"maintenance", self)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, serde::Deserialize)]
pub enum MaintenanceBlock {
    Cutoff,
    DirtySummary,
    RestoreWindow,
    ReplayGuarantee,
    StreamOpen,
    RetainedData,
}
#[derive(Clone, Debug)]
pub enum MaintenanceProgress {
    More { processed: u32, next: Continuation },
    Complete { processed: u32, fence: Id },
    Blocked { reason: MaintenanceBlock },
}
