//! Provider-neutral, plan-bound projection worker observation.

use std::sync::{Arc, RwLock};

use crate::ProjectionVersion;

/// Selected-generation posture across one complete tenant sweep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectionSelectedGeneration {
    /// No tenant selected an executable generation during the complete sweep.
    None,
    /// Every tenant with a selected generation used the same generation.
    Uniform(ProjectionVersion),
    /// Tenants selected different generations, or selected and uninitialized tenants coexisted.
    Mixed,
}

/// Retryable worker reasons. Raw provider errors never cross this boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProjectionRetryableReason {
    /// The worker could not read the durable checkpoint.
    CheckpointUnread,
    /// The worker processed input but could not save the durable checkpoint.
    CheckpointUnsaved,
    /// A rejected event could not be written to the dead-letter store.
    DeadLetterUnsaved,
    /// Applying an event failed with a retryable provider outcome.
    ApplyTransient,
    /// The apply commit outcome is unknown and must be reconciled before retrying.
    CommitUnknown,
    /// Reading the projection source failed transiently.
    SourceTransient,
    /// Persisting a durable tenant quarantine failed transiently.
    QuarantinePersistence,
}

/// Durable tenant-fatal reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProjectionQuarantineReason {
    /// The selected target definition differs from the durable definition identity.
    TargetDefinitionDrift,
    /// The selected input bindings differ from the durable binding identity.
    InputBindingDrift,
    /// Provider state belongs to a different tenant identity.
    TenantDrift,
    /// An input payload could not be decoded.
    PayloadMalformed,
    /// A decoded input payload violated its value constraints.
    PayloadValueInvalid,
    /// An input attempted to move the projection version backwards.
    VersionRegression,
    /// The provider violated a projection invariant.
    ProviderInvariant,
    /// The provider rejected the operation permanently.
    ProviderPermanent,
    /// Applying the event conflicted with durable state.
    Conflict,
    /// The apply store observed an out-of-order write.
    ApplyOutOfOrder,
    /// Compensating a failed apply could not restore durable state.
    RollbackFailed,
    /// The source delivered an event behind the accepted coordinate.
    SourceOutOfOrder,
}

/// Fixed-size aggregation which cannot disclose tenant identities or unbounded reason sets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectionReasonPosture<R> {
    /// Every tenant reporting this posture produced the same closed reason.
    Uniform(R),
    /// Multiple closed reasons occurred; individual tenant facts remain private.
    Mixed,
}

/// Observation failures that suppress potentially stale sweep values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionUnavailableReason {
    /// The initial source/checkpoint observation has not completed successfully.
    StartupObservation,
    /// The tenant sweep ended before every selected tenant was observed.
    SweepIncomplete,
    /// At least one tenant's generation, lag, or quarantine facts could not be observed.
    TenantObservation,
}

/// Process-fatal worker reasons. This is process-local; durable tenant quarantine is separate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionStoppedReason {
    /// The dedicated Tokio runtime could not be constructed.
    RuntimeBuildFailed,
    /// The projection worker unwound while being polled.
    WorkerPanicked,
    /// The worker cannot enumerate the tenant catalog.
    TenantCatalogUnavailable,
    /// The worker cannot resolve the selected generation.
    SelectedGenerationUnavailable,
    /// The resolved generation identity is invalid.
    SelectedGenerationIdentityInvalid,
    /// The tenant catalog returned an invalid tenant identity.
    InvalidTenant,
    /// Durable tenant quarantine cannot be read or written.
    TenantQuarantineUnavailable,
    /// The initial projection source cannot be observed.
    StartupSourceUnavailable,
    /// A projection run returned an internally inconsistent outcome.
    ProjectionOutcomeInvalid,
    /// A provider coordinate cannot be represented by the projection runtime.
    CoordinateOverflow,
    /// The plan-issued projection target configuration is invalid.
    TargetConfigInvalid,
}

/// Current process-wide projection worker status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectionWorkerStatus {
    /// The worker has not completed its first reportable observation.
    Starting,
    /// A complete sweep observed no retryable or quarantined tenants.
    Healthy {
        /// Aggregated selected-generation posture for the complete sweep.
        selected_generation: ProjectionSelectedGeneration,
        /// Maximum per-tenant `source_high_water - checkpoint`, in provider offset units.
        max_lag: u64,
    },
    /// A complete sweep observed retryable work but no durable quarantine.
    Retryable {
        /// Aggregated selected-generation posture for the complete sweep.
        selected_generation: ProjectionSelectedGeneration,
        /// Maximum paired per-tenant lag in provider offset units.
        max_lag: u64,
        /// Bounded aggregate of retryable reasons.
        reasons: ProjectionReasonPosture<ProjectionRetryableReason>,
    },
    /// A complete sweep observed durable quarantine but no retryable work.
    Quarantined {
        /// Aggregated selected-generation posture for the complete sweep.
        selected_generation: ProjectionSelectedGeneration,
        /// Maximum paired per-tenant lag in provider offset units.
        max_lag: u64,
        /// Bounded aggregate of durable quarantine reasons.
        reasons: ProjectionReasonPosture<ProjectionQuarantineReason>,
    },
    /// A complete sweep observed both retryable work and durable quarantine.
    Mixed {
        /// Aggregated selected-generation posture for the complete sweep.
        selected_generation: ProjectionSelectedGeneration,
        /// Maximum paired per-tenant lag in provider offset units.
        max_lag: u64,
        /// Bounded aggregate of retryable reasons.
        retryable_reasons: ProjectionReasonPosture<ProjectionRetryableReason>,
        /// Bounded aggregate of durable quarantine reasons.
        quarantine_reasons: ProjectionReasonPosture<ProjectionQuarantineReason>,
    },
    /// No complete, current sweep snapshot is available; stale generation and lag are suppressed.
    Unavailable(ProjectionUnavailableReason),
    /// The worker stopped fatally; this terminal state cannot be overwritten.
    Stopped(ProjectionStoppedReason),
}

#[derive(Debug)]
struct ProjectionObservationState {
    status: RwLock<ProjectionWorkerStatus>,
}

/// Read-only handle retained by the exact plan-issued runtime.
#[derive(Debug, Clone)]
pub struct ProjectionObservationReader {
    state: Arc<ProjectionObservationState>,
}

impl PartialEq for ProjectionObservationReader {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.state, &other.state)
    }
}

impl Eq for ProjectionObservationReader {}

impl ProjectionObservationReader {
    /// Clone the latest bounded worker status without exposing tenant-level observations.
    pub fn read(&self) -> ProjectionWorkerStatus {
        self.state
            .status
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

/// Publisher handed only to the worker launcher issued from the same runtime binding.
#[derive(Debug, Clone)]
pub struct ProjectionObservationPublisher {
    state: Arc<ProjectionObservationState>,
}

impl ProjectionObservationPublisher {
    /// Publish a complete bounded status unless a fatal stop was already latched.
    pub fn publish(&self, status: ProjectionWorkerStatus) {
        let mut current = self
            .state
            .status
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !matches!(*current, ProjectionWorkerStatus::Stopped(_)) {
            *current = status;
        }
    }

    /// Latch a process-fatal stop so later sweep publications cannot overwrite it.
    pub fn stop(&self, reason: ProjectionStoppedReason) {
        self.publish(ProjectionWorkerStatus::Stopped(reason));
    }
}

pub(crate) fn projection_observation_channel()
-> (ProjectionObservationPublisher, ProjectionObservationReader) {
    let state = Arc::new(ProjectionObservationState {
        status: RwLock::new(ProjectionWorkerStatus::Starting),
    });
    (
        ProjectionObservationPublisher {
            state: Arc::clone(&state),
        },
        ProjectionObservationReader { state },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stopped_is_terminal() {
        let (publisher, reader) = projection_observation_channel();
        publisher.stop(ProjectionStoppedReason::InvalidTenant);
        publisher.publish(ProjectionWorkerStatus::Starting);
        assert_eq!(
            reader.read(),
            ProjectionWorkerStatus::Stopped(ProjectionStoppedReason::InvalidTenant)
        );
    }
}
