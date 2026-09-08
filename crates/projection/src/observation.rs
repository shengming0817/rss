//! Per-invocation observation; the sole publisher is owned by the execution future.
//! ref: arc-swap src/lib.rs@147d6c0319d389a0aaa134a67abaa00106122f7d
use crate::{DefinitionIdentity, Position, ProjectionScope, Report};
use arc_swap::ArcSwap;
use std::sync::Arc;

/// Last acknowledged coordinate and counts for this invocation, excluding uncertain effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfirmedProgress {
    /// Initial checkpoint or last acknowledged event; None precedes the first event.
    pub position: Option<Position>,
    /// Newly committed effects during this invocation.
    pub applied: u64,
    /// Previously committed facts acknowledged during this invocation.
    pub duplicates: u64,
    /// Intentionally ignored events acknowledged during this invocation.
    pub filtered: u64,
}
impl ConfirmedProgress {
    fn from_report(report: &Report) -> Self {
        Self {
            position: report.position,
            applied: report.applied,
            duplicates: report.duplicates,
            filtered: report.filtered,
        }
    }
}

/// Latest local execution stage, not a lease check, health signal or durable snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObservationStatus {
    /// No checkpoint has been successfully read, including before the first poll.
    Pending,
    /// Last confirmed progress; the invocation has not produced a terminal observation.
    Running(ConfirmedProgress),
    /// Exact final report. This terminal state cannot be overwritten.
    Stopped(Report),
    /// The future was dropped or unwound before producing a report. Effects may be unknown.
    /// This terminal state does not prove rollback or termination of remote work.
    Unavailable {
        /// None means the initial checkpoint was never acknowledged.
        last_confirmed: Option<ConfirmedProgress>,
    },
}

#[derive(Debug)]
struct State {
    scope: ProjectionScope,
    definition: DefinitionIdentity,
    status: ArcSwap<ObservationStatus>,
}

/// Read-only handle bound to one exact invocation. Clones compare equal; separate runs do not,
/// even with identical scopes. Possession grants no authentication, fencing or control rights.
#[derive(Debug, Clone)]
pub struct RunObservation {
    state: Arc<State>,
}
impl PartialEq for RunObservation {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.state, &other.state)
    }
}
impl Eq for RunObservation {}
impl RunObservation {
    /// Copy one complete latest observation. Retaining the value cannot hold up publication.
    /// A previously returned value is historical; read again to observe a later transition.
    pub fn read(&self) -> ObservationStatus {
        self.state.status.load_full().as_ref().clone()
    }
    /// Immutable tenant/source/projection/generation selected by the execution session.
    pub fn scope(&self) -> &ProjectionScope {
        &self.state.scope
    }
    /// Definition declared by the bound execution session; not authentication evidence.
    pub fn definition_identity(&self) -> &DefinitionIdentity {
        &self.state.definition
    }
}

/// Unique publication authority. Construct synchronously so even an unpolled future owns it.
pub(crate) struct Publisher {
    state: Arc<State>,
}
impl Publisher {
    pub(crate) fn new(scope: ProjectionScope, definition: DefinitionIdentity) -> Self {
        Self {
            state: Arc::new(State {
                scope,
                definition,
                status: ArcSwap::from_pointee(ObservationStatus::Pending),
            }),
        }
    }
    pub(crate) fn observation(&self) -> RunObservation {
        RunObservation {
            state: Arc::clone(&self.state),
        }
    }
    pub(crate) fn confirmed(&mut self, report: &Report) {
        self.state.status.store(Arc::new(ObservationStatus::Running(
            ConfirmedProgress::from_report(report),
        )));
    }
    // Consume the sole writer: no subsequent progress publication can overwrite this terminal.
    pub(crate) fn finish(self, report: &Report) {
        self.state
            .status
            .store(Arc::new(ObservationStatus::Stopped(report.clone())));
    }
}
impl Drop for Publisher {
    fn drop(&mut self) {
        let last_confirmed = match self.state.status.load_full().as_ref() {
            ObservationStatus::Pending => None,
            ObservationStatus::Running(progress) => Some(*progress),
            ObservationStatus::Stopped(_) | ObservationStatus::Unavailable { .. } => return,
        };
        self.state
            .status
            .store(Arc::new(ObservationStatus::Unavailable { last_confirmed }));
    }
}
