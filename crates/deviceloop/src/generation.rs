//! Desired/reported generation authority for the device convergence loop.
//!
//! ref: kube-rs kube-runtime/src/controller/mod.rs@b60b81c88d37ab1f1f0d1ff7d42ab0ca268b4221
//! ref: mdeloof/statig statig/src/lib.rs@3780eecdbcf4326051c38676d592c6c2b4a3bab5

use crate::command::DeviceCommandScope;

const MAX_COORDINATE: u64 = i64::MAX as u64;

/// A generation or fence coordinate was outside the persistent signed-integer range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("generation coordinate must be in 1..=i64::MAX")]
pub struct InvalidGenerationCoordinate;

macro_rules! positive_coordinate {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(u64);

        impl $name {
            /// Validate a raw persisted or reported coordinate.
            pub fn try_new(raw: u64) -> Result<Self, InvalidGenerationCoordinate> {
                if (1..=MAX_COORDINATE).contains(&raw) {
                    Ok(Self(raw))
                } else {
                    Err(InvalidGenerationCoordinate)
                }
            }

            /// Return the validated coordinate.
            pub fn get(self) -> u64 {
                self.0
            }
        }
    };
}

positive_coordinate!(
    DesiredGeneration,
    "A validated desired-state generation owned by [`GenerationTracker`]."
);
positive_coordinate!(
    ObservedGeneration,
    "A validated generation reported by a device."
);
positive_coordinate!(
    FenceEpoch,
    "A validated fencing epoch for one desired-state authority."
);

/// The generation and epoch that jointly identify the current write authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FenceCoordinate {
    generation: DesiredGeneration,
    epoch: FenceEpoch,
}

impl FenceCoordinate {
    /// Construct a coordinate from independently validated values.
    pub fn new(generation: DesiredGeneration, epoch: FenceEpoch) -> Self {
        Self { generation, epoch }
    }

    /// Desired generation held by this fence.
    pub fn generation(self) -> DesiredGeneration {
        self.generation
    }

    /// Authority epoch held by this fence.
    pub fn epoch(self) -> FenceEpoch {
        self.epoch
    }
}

/// A desired-state update did not strictly advance both authority coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DesiredAdvanceError {
    /// The proposed generation was not newer.
    #[error("desired generation must strictly advance")]
    GenerationNotNewer,
    /// The proposed fence epoch was not newer.
    #[error("fence epoch must strictly advance")]
    FenceNotNewer,
}

/// A persisted generation snapshot violated an authority invariant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GenerationRestoreError {
    /// A raw coordinate was zero or exceeded `i64::MAX`.
    #[error("generation snapshot contains an invalid coordinate")]
    InvalidCoordinate,
    /// The fence was issued for a generation other than the desired generation.
    #[error("generation snapshot fence does not belong to desired generation")]
    FenceGenerationMismatch,
    /// The reported high-water mark was ahead of desired state.
    #[error("reported generation is ahead of desired generation")]
    ReportedAheadOfDesired,
    /// A report at the desired generation carried a different state.
    #[error("reported state conflicts with desired state at the same generation")]
    ReportedStateConflict,
    /// The accepted report was issued under a different fencing epoch.
    #[error("reported fence epoch is not current")]
    ReportedFenceMismatch,
    /// Current-fence report exists without the same historical high-water observation.
    #[error("current-fence report does not match observed high-water")]
    CurrentReportMismatch,
}

impl From<InvalidGenerationCoordinate> for GenerationRestoreError {
    fn from(_: InvalidGenerationCoordinate) -> Self {
        Self::InvalidCoordinate
    }
}

/// Raw, owned historical observed high-water accepted by the restore funnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedHighWaterRestore<T> {
    generation: u64,
    state: T,
}

impl<T> ObservedHighWaterRestore<T> {
    /// Build restore input. Validation happens atomically in [`GenerationTracker::restore`].
    pub fn new(generation: u64, state: T) -> Self {
        Self { generation, state }
    }
}

/// Raw, owned report retained for matching under the current fence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentFenceReportRestore {
    generation: u64,
    fence_epoch: u64,
}

impl CurrentFenceReportRestore {
    /// Build restore input. Validation happens atomically in [`GenerationTracker::restore`].
    pub fn new(generation: u64, fence_epoch: u64) -> Self {
        Self {
            generation,
            fence_epoch,
        }
    }
}

/// Raw, owned tracker state accepted by the restore funnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerationRestore<T> {
    scope: DeviceCommandScope,
    desired_generation: u64,
    desired_state: T,
    fence_generation: u64,
    fence_epoch: u64,
    observed_high_water: Option<ObservedHighWaterRestore<T>>,
    current_report: Option<CurrentFenceReportRestore>,
}

impl<T> GenerationRestore<T> {
    /// Build restore input. No field is trusted until [`GenerationTracker::restore`] succeeds.
    pub fn new(
        scope: DeviceCommandScope,
        desired_generation: u64,
        desired_state: T,
        fence_generation: u64,
        fence_epoch: u64,
        observed_high_water: Option<ObservedHighWaterRestore<T>>,
        current_report: Option<CurrentFenceReportRestore>,
    ) -> Self {
        Self {
            scope,
            desired_generation,
            desired_state,
            fence_generation,
            fence_epoch,
            observed_high_water,
            current_report,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ObservedHighWater<T> {
    generation: ObservedGeneration,
    state: T,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CurrentFenceReport {
    generation: ObservedGeneration,
    fence_epoch: FenceEpoch,
}

/// Owned persistence snapshot. Its fields remain private so mutation must pass through restore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerationSnapshot<T> {
    scope: DeviceCommandScope,
    desired_generation: DesiredGeneration,
    desired_state: T,
    fence: FenceCoordinate,
    observed_high_water: Option<ObservedHighWater<T>>,
    current_report: Option<CurrentFenceReport>,
}

impl<T> GenerationSnapshot<T> {
    /// Tenant/device authority owned by this snapshot.
    pub fn scope(&self) -> DeviceCommandScope {
        self.scope
    }

    /// Desired generation in the snapshot.
    pub fn desired_generation(&self) -> DesiredGeneration {
        self.desired_generation
    }

    /// Desired state in the snapshot.
    pub fn desired_state(&self) -> &T {
        &self.desired_state
    }

    /// Current fencing coordinate in the snapshot.
    pub fn fence(&self) -> FenceCoordinate {
        self.fence
    }

    /// Highest generation ever accepted from this device.
    pub fn observed_high_water_generation(&self) -> Option<ObservedGeneration> {
        self.observed_high_water
            .as_ref()
            .map(|report| report.generation)
    }

    /// State carried by the highest generation ever accepted from this device.
    pub fn observed_high_water_state(&self) -> Option<&T> {
        self.observed_high_water
            .as_ref()
            .map(|report| &report.state)
    }

    /// Generation retained for matching under the current fence.
    pub fn current_report_generation(&self) -> Option<ObservedGeneration> {
        self.current_report.as_ref().map(|report| report.generation)
    }

    /// Fencing epoch attached to the current-fence report.
    pub fn current_report_fence_epoch(&self) -> Option<FenceEpoch> {
        self.current_report
            .as_ref()
            .map(|report| report.fence_epoch)
    }
}

impl<T> From<GenerationSnapshot<T>> for GenerationRestore<T> {
    fn from(snapshot: GenerationSnapshot<T>) -> Self {
        let observed_high_water = snapshot
            .observed_high_water
            .map(|report| ObservedHighWaterRestore::new(report.generation.get(), report.state));
        let current_report = snapshot.current_report.map(|report| {
            CurrentFenceReportRestore::new(report.generation.get(), report.fence_epoch.get())
        });
        Self::new(
            snapshot.scope,
            snapshot.desired_generation.get(),
            snapshot.desired_state,
            snapshot.fence.generation().get(),
            snapshot.fence.epoch().get(),
            observed_high_water,
            current_report,
        )
    }
}

/// Move-only proof that an operation is fenced by the tracker's current authority.
///
/// Evidence cannot be assembled outside the authority funnel:
///
/// ```compile_fail
/// use deviceloop::{CurrentFence, DesiredGeneration, FenceCoordinate, FenceEpoch};
/// let coordinate = FenceCoordinate::new(
///     DesiredGeneration::try_new(1).unwrap(),
///     FenceEpoch::try_new(1).unwrap(),
/// );
/// let _ = CurrentFence { coordinate };
/// ```
///
/// Evidence is deliberately move-only:
///
/// ```compile_fail
/// use deviceloop::CurrentFence;
/// fn duplicate(evidence: CurrentFence) {
///     let _copy = evidence.clone();
/// }
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct CurrentFence {
    scope: DeviceCommandScope,
    coordinate: FenceCoordinate,
}

impl CurrentFence {
    pub(crate) fn scope(&self) -> DeviceCommandScope {
        self.scope
    }

    pub(crate) fn coordinate(&self) -> FenceCoordinate {
        self.coordinate
    }
}

/// Move-only proof that the current fence supersedes one supplied command coordinate.
///
/// ```compile_fail
/// use deviceloop::{DeviceCommandScope, FenceCoordinate, SupersedingFence};
/// fn forge(scope: DeviceCommandScope, coordinate: FenceCoordinate) {
///     let _ = SupersedingFence {
///         scope,
///         previous_coordinate: coordinate,
///         current_coordinate: coordinate,
///     };
/// }
/// ```
///
/// ```compile_fail
/// use deviceloop::SupersedingFence;
/// fn duplicate(evidence: SupersedingFence) {
///     let _copy = evidence.clone();
/// }
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct SupersedingFence {
    scope: DeviceCommandScope,
    previous_coordinate: FenceCoordinate,
    current_coordinate: FenceCoordinate,
}

impl SupersedingFence {
    pub(crate) fn scope(&self) -> DeviceCommandScope {
        self.scope
    }

    pub(crate) fn previous_coordinate(&self) -> FenceCoordinate {
        self.previous_coordinate
    }

    pub(crate) fn coordinate(&self) -> FenceCoordinate {
        self.current_coordinate
    }
}

/// Move-only proof that current desired and reported state match under the current fence.
///
/// ```compile_fail
/// use deviceloop::{DeviceCommandScope, FenceCoordinate, MatchingReportedState};
/// fn forge(scope: DeviceCommandScope, coordinate: FenceCoordinate) {
///     let _ = MatchingReportedState { scope, coordinate };
/// }
/// ```
///
/// ```compile_fail
/// use deviceloop::MatchingReportedState;
/// fn duplicate(evidence: MatchingReportedState) {
///     let _copy = evidence.clone();
/// }
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct MatchingReportedState {
    scope: DeviceCommandScope,
    coordinate: FenceCoordinate,
}

impl MatchingReportedState {
    pub(crate) fn scope(&self) -> DeviceCommandScope {
        self.scope
    }

    pub(crate) fn coordinate(&self) -> FenceCoordinate {
        self.coordinate
    }
}

/// Closed, low-cardinality classification of a reported-state observation.
#[derive(Debug, PartialEq, Eq)]
pub enum ReportOutcome {
    /// A newer high-water report was accepted but has not reached desired generation.
    Accepted,
    /// The accepted report exactly matches desired state and current fence.
    Matching(MatchingReportedState),
    /// The report was below the accepted high-water generation.
    Stale,
    /// The report exactly repeated the accepted high-water report.
    Duplicate,
    /// The report claimed a generation beyond desired state.
    AheadOfDesired,
    /// The report reused a generation with a different state.
    StateConflict,
    /// The report was produced under a non-current fencing epoch.
    StaleFence,
}

impl ReportOutcome {
    /// Stable low-cardinality label for decisions and telemetry at outer layers.
    pub fn as_label(&self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Matching(_) => "matching",
            Self::Stale => "stale",
            Self::Duplicate => "duplicate",
            Self::AheadOfDesired => "ahead_of_desired",
            Self::StateConflict => "state_conflict",
            Self::StaleFence => "stale_fence",
        }
    }

    /// Consume a matching outcome into its unforgeable command evidence.
    pub fn into_matching(self) -> Option<MatchingReportedState> {
        match self {
            Self::Matching(evidence) => Some(evidence),
            Self::Accepted
            | Self::Stale
            | Self::Duplicate
            | Self::AheadOfDesired
            | Self::StateConflict
            | Self::StaleFence => None,
        }
    }
}

/// Sole owner of desired, reported, and fencing generation authority.
#[derive(Debug, PartialEq, Eq)]
pub struct GenerationTracker<T> {
    scope: DeviceCommandScope,
    desired_generation: DesiredGeneration,
    desired_state: T,
    fence: FenceCoordinate,
    observed_high_water: Option<ObservedHighWater<T>>,
    current_report: Option<CurrentFenceReport>,
}

impl<T: Eq> GenerationTracker<T> {
    /// Start tracking a desired state. Reported state is always initially absent.
    pub fn new(
        scope: DeviceCommandScope,
        generation: DesiredGeneration,
        desired_state: T,
        fence_epoch: FenceEpoch,
    ) -> Self {
        Self {
            scope,
            desired_generation: generation,
            desired_state,
            fence: FenceCoordinate::new(generation, fence_epoch),
            observed_high_water: None,
            current_report: None,
        }
    }

    /// Restore owned state after validating every raw coordinate and cross-field invariant.
    pub fn restore(input: GenerationRestore<T>) -> Result<Self, GenerationRestoreError> {
        let desired_generation = DesiredGeneration::try_new(input.desired_generation)?;
        let fence_generation = DesiredGeneration::try_new(input.fence_generation)?;
        let fence_epoch = FenceEpoch::try_new(input.fence_epoch)?;
        if fence_generation != desired_generation {
            return Err(GenerationRestoreError::FenceGenerationMismatch);
        }

        let observed_high_water = input
            .observed_high_water
            .map(|report| {
                let generation = ObservedGeneration::try_new(report.generation)?;
                if generation.get() > desired_generation.get() {
                    return Err(GenerationRestoreError::ReportedAheadOfDesired);
                }
                if generation.get() == desired_generation.get()
                    && report.state != input.desired_state
                {
                    return Err(GenerationRestoreError::ReportedStateConflict);
                }
                Ok(ObservedHighWater {
                    generation,
                    state: report.state,
                })
            })
            .transpose()?;

        let current_report = input
            .current_report
            .map(|report| {
                let generation = ObservedGeneration::try_new(report.generation)?;
                let report_epoch = FenceEpoch::try_new(report.fence_epoch)?;
                if generation.get() > desired_generation.get() {
                    return Err(GenerationRestoreError::ReportedAheadOfDesired);
                }
                if report_epoch != fence_epoch {
                    return Err(GenerationRestoreError::ReportedFenceMismatch);
                }
                Ok(CurrentFenceReport {
                    generation,
                    fence_epoch: report_epoch,
                })
            })
            .transpose()?;

        if let Some(current) = &current_report {
            let matches_high_water = observed_high_water
                .as_ref()
                .is_some_and(|high_water| high_water.generation == current.generation);
            if !matches_high_water {
                return Err(GenerationRestoreError::CurrentReportMismatch);
            }
        }
        Ok(Self {
            scope: input.scope,
            desired_generation,
            desired_state: input.desired_state,
            fence: FenceCoordinate::new(desired_generation, fence_epoch),
            observed_high_water,
            current_report,
        })
    }

    /// Current desired generation.
    pub fn desired_generation(&self) -> DesiredGeneration {
        self.desired_generation
    }

    /// Tenant/device authority owned by this tracker.
    pub fn scope(&self) -> DeviceCommandScope {
        self.scope
    }

    /// Current desired state.
    pub fn desired_state(&self) -> &T {
        &self.desired_state
    }

    /// Current fencing coordinate without authority evidence.
    pub fn fence_coordinate(&self) -> FenceCoordinate {
        self.fence
    }

    /// Mint one move-only proof for a command mutation under the current fence.
    pub fn current_fence(&self) -> CurrentFence {
        CurrentFence {
            scope: self.scope,
            coordinate: self.fence,
        }
    }

    /// Re-mint matching evidence for a received command during resync.
    ///
    /// This keeps duplicate reports as classified no-ops while allowing a report that arrived
    /// before command acknowledgement to be re-evaluated after the command reaches `Received`.
    pub fn matching_reported_state(&self) -> Option<MatchingReportedState> {
        self.current_report.as_ref().and_then(|report| {
            (report.generation.get() == self.desired_generation.get()
                && report.fence_epoch == self.fence.epoch()
                && self
                    .observed_high_water
                    .as_ref()
                    .is_some_and(|high_water| high_water.state == self.desired_state))
            .then_some(MatchingReportedState {
                scope: self.scope,
                coordinate: self.fence,
            })
        })
    }

    /// Strictly advance desired generation and fencing epoch atomically.
    pub fn advance_desired(
        &mut self,
        generation: DesiredGeneration,
        desired_state: T,
        fence_epoch: FenceEpoch,
    ) -> Result<(), DesiredAdvanceError> {
        if generation <= self.desired_generation {
            return Err(DesiredAdvanceError::GenerationNotNewer);
        }
        if fence_epoch <= self.fence.epoch() {
            return Err(DesiredAdvanceError::FenceNotNewer);
        }
        self.desired_generation = generation;
        self.desired_state = desired_state;
        self.fence = FenceCoordinate::new(generation, fence_epoch);
        self.current_report = None;
        Ok(())
    }

    /// Move ownership to a strictly newer epoch without changing desired state or generation.
    pub fn take_over(&mut self, fence_epoch: FenceEpoch) -> Result<(), DesiredAdvanceError> {
        if fence_epoch <= self.fence.epoch() {
            return Err(DesiredAdvanceError::FenceNotNewer);
        }
        self.fence = FenceCoordinate::new(self.desired_generation, fence_epoch);
        self.current_report = None;
        Ok(())
    }

    /// Mint one move-only supersession proof bound to a command's exact old coordinate.
    pub fn supersedes(&self, coordinate: FenceCoordinate) -> Option<SupersedingFence> {
        (self.desired_generation >= coordinate.generation()
            && self.fence.epoch() > coordinate.epoch())
        .then_some(SupersedingFence {
            scope: self.scope,
            previous_coordinate: coordinate,
            current_coordinate: self.fence,
        })
    }

    /// Observe device state through the only report mutation funnel.
    pub fn report(
        &mut self,
        generation: ObservedGeneration,
        fence_epoch: FenceEpoch,
        state: T,
    ) -> ReportOutcome {
        if fence_epoch != self.fence.epoch() {
            return ReportOutcome::StaleFence;
        }
        if generation.get() > self.desired_generation.get() {
            return ReportOutcome::AheadOfDesired;
        }
        if let Some(high_water) = &self.observed_high_water {
            if generation < high_water.generation {
                return ReportOutcome::Stale;
            }
            if generation == high_water.generation {
                if state != high_water.state {
                    return ReportOutcome::StateConflict;
                }
                if self.current_report.as_ref().is_some_and(|report| {
                    report.generation == generation && report.fence_epoch == fence_epoch
                }) {
                    return ReportOutcome::Duplicate;
                }
                self.current_report = Some(CurrentFenceReport {
                    generation,
                    fence_epoch,
                });
                return if generation.get() == self.desired_generation.get() {
                    ReportOutcome::Matching(MatchingReportedState {
                        scope: self.scope,
                        coordinate: self.fence,
                    })
                } else {
                    ReportOutcome::Accepted
                };
            }
        }
        if generation.get() == self.desired_generation.get() && state != self.desired_state {
            return ReportOutcome::StateConflict;
        }

        self.observed_high_water = Some(ObservedHighWater { generation, state });
        self.current_report = Some(CurrentFenceReport {
            generation,
            fence_epoch,
        });
        if generation.get() == self.desired_generation.get() {
            ReportOutcome::Matching(MatchingReportedState {
                scope: self.scope,
                coordinate: self.fence,
            })
        } else {
            ReportOutcome::Accepted
        }
    }
}

impl<T: Eq + Clone> GenerationTracker<T> {
    /// Take an owned persistence snapshot without exposing mutable fields.
    pub fn snapshot(&self) -> GenerationSnapshot<T> {
        GenerationSnapshot {
            scope: self.scope,
            desired_generation: self.desired_generation,
            desired_state: self.desired_state.clone(),
            fence: self.fence,
            observed_high_water: self.observed_high_water.clone(),
            current_report: self.current_report.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    fn scope() -> DeviceCommandScope {
        DeviceCommandScope::new(
            vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("tenant"),
            ids::DeviceId::parse("550e8400-e29b-41d4-a716-446655440000").expect("device"),
        )
    }

    fn desired(raw: u64) -> DesiredGeneration {
        DesiredGeneration::try_new(raw).expect("valid desired generation")
    }

    fn observed(raw: u64) -> ObservedGeneration {
        ObservedGeneration::try_new(raw).expect("valid observed generation")
    }

    fn epoch(raw: u64) -> FenceEpoch {
        FenceEpoch::try_new(raw).expect("valid fence epoch")
    }

    #[test]
    fn positive_coordinates_close_signed_persistence_range() {
        for raw in [0, MAX_COORDINATE + 1, u64::MAX] {
            assert!(DesiredGeneration::try_new(raw).is_err());
            assert!(ObservedGeneration::try_new(raw).is_err());
            assert!(FenceEpoch::try_new(raw).is_err());
        }
        assert_eq!(DesiredGeneration::try_new(1).unwrap().get(), 1);
        assert_eq!(
            ObservedGeneration::try_new(MAX_COORDINATE).unwrap().get(),
            MAX_COORDINATE
        );
        assert_eq!(
            FenceEpoch::try_new(MAX_COORDINATE).unwrap().get(),
            MAX_COORDINATE
        );
    }

    #[test]
    fn desired_and_fence_only_advance_together() {
        let mut tracker = GenerationTracker::new(scope(), desired(2), "two", epoch(4));
        assert_eq!(
            tracker.report(observed(2), epoch(4), "two"),
            ReportOutcome::Matching(MatchingReportedState {
                scope: scope(),
                coordinate: FenceCoordinate::new(desired(2), epoch(4))
            })
        );
        let before = tracker.snapshot();
        assert_eq!(
            tracker.advance_desired(desired(2), "duplicate", epoch(5)),
            Err(DesiredAdvanceError::GenerationNotNewer)
        );
        assert_eq!(tracker.snapshot(), before);
        assert_eq!(
            tracker.advance_desired(desired(3), "three", epoch(4)),
            Err(DesiredAdvanceError::FenceNotNewer)
        );
        assert_eq!(tracker.snapshot(), before);

        tracker
            .advance_desired(desired(3), "three", epoch(5))
            .expect("strict advance");
        let proof = tracker
            .supersedes(FenceCoordinate::new(desired(2), epoch(4)))
            .expect("old coordinate is superseded");
        assert_eq!(
            proof.coordinate(),
            FenceCoordinate::new(desired(3), epoch(5))
        );
        assert_eq!(
            proof.previous_coordinate(),
            FenceCoordinate::new(desired(2), epoch(4))
        );
        assert_eq!(tracker.desired_state(), &"three");
        assert_eq!(
            tracker.snapshot().observed_high_water_generation(),
            Some(observed(2))
        );
        assert_eq!(tracker.snapshot().current_report_generation(), None);
        assert!(tracker.matching_reported_state().is_none());
    }

    #[test]
    fn takeover_preserves_desired_and_high_water_but_rebinds_current_report() {
        let mut tracker = GenerationTracker::new(scope(), desired(2), "two", epoch(4));
        assert!(matches!(
            tracker.report(observed(2), epoch(4), "two"),
            ReportOutcome::Matching(_)
        ));
        let old_coordinate = tracker.fence_coordinate();

        tracker.take_over(epoch(5)).expect("strictly newer epoch");

        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.desired_generation(), desired(2));
        assert_eq!(snapshot.desired_state(), &"two");
        assert_eq!(snapshot.observed_high_water_generation(), Some(observed(2)));
        assert_eq!(snapshot.observed_high_water_state(), Some(&"two"));
        assert_eq!(snapshot.current_report_generation(), None);
        assert_eq!(snapshot.current_report_fence_epoch(), None);
        assert_eq!(snapshot.fence(), FenceCoordinate::new(desired(2), epoch(5)));
        assert!(tracker.supersedes(old_coordinate).is_some());
        assert!(tracker.supersedes(tracker.fence_coordinate()).is_none());
        assert_eq!(
            GenerationTracker::restore(snapshot.clone().into())
                .expect("takeover snapshot restores")
                .snapshot(),
            snapshot
        );
        assert!(matches!(
            tracker.report(observed(2), epoch(5), "two"),
            ReportOutcome::Matching(_)
        ));
    }

    #[test]
    fn takeover_rejects_non_newer_epoch_without_mutation() {
        let mut tracker = GenerationTracker::new(scope(), desired(2), "two", epoch(4));
        let before = tracker.snapshot();
        for proposed in [epoch(3), epoch(4)] {
            assert_eq!(
                tracker.take_over(proposed),
                Err(DesiredAdvanceError::FenceNotNewer)
            );
            assert_eq!(tracker.snapshot(), before);
        }
    }

    #[test]
    fn report_outcomes_are_high_water_and_noops_do_not_mutate() {
        let mut tracker = GenerationTracker::new(scope(), desired(3), "three", epoch(7));
        assert_eq!(
            tracker.report(observed(1), epoch(7), "one"),
            ReportOutcome::Accepted
        );

        let cases = [
            (observed(1), epoch(7), "one", "duplicate"),
            (observed(1), epoch(7), "other", "state_conflict"),
            (observed(4), epoch(7), "four", "ahead_of_desired"),
            (observed(2), epoch(6), "two", "stale_fence"),
        ];
        for (generation, report_epoch, state, label) in cases {
            let before = tracker.snapshot();
            let outcome = tracker.report(generation, report_epoch, state);
            assert_eq!(outcome.as_label(), label);
            assert_eq!(tracker.snapshot(), before);
        }

        assert_eq!(
            tracker.report(observed(2), epoch(7), "two"),
            ReportOutcome::Accepted
        );
        let before = tracker.snapshot();
        assert_eq!(
            tracker.report(observed(1), epoch(7), "one"),
            ReportOutcome::Stale
        );
        assert_eq!(tracker.snapshot(), before);
    }

    #[test]
    fn observed_high_water_survives_desired_fence_advance() {
        let mut tracker = GenerationTracker::new(scope(), desired(2), "two", epoch(4));
        assert!(matches!(
            tracker.report(observed(2), epoch(4), "two"),
            ReportOutcome::Matching(_)
        ));

        tracker
            .advance_desired(desired(3), "three", epoch(5))
            .expect("strict advance");
        let before = tracker.snapshot();
        assert_eq!(
            tracker.report(observed(1), epoch(5), "one"),
            ReportOutcome::Stale
        );
        assert_eq!(tracker.snapshot(), before);
        assert_eq!(
            tracker.snapshot().observed_high_water_generation(),
            Some(observed(2))
        );
        assert!(tracker.matching_reported_state().is_none());

        let snapshot = tracker.snapshot();
        let restored = GenerationTracker::restore(snapshot.clone().into())
            .expect("historical-only high-water restores");
        assert_eq!(restored.snapshot(), snapshot);
    }

    #[test]
    fn matching_evidence_requires_exact_generation_epoch_and_state() {
        let mut tracker = GenerationTracker::new(scope(), desired(3), "three", epoch(7));
        for (generation, report_epoch, state) in [
            (observed(2), epoch(7), "three"),
            (observed(3), epoch(6), "three"),
            (observed(3), epoch(7), "other"),
        ] {
            assert!(
                tracker
                    .report(generation, report_epoch, state)
                    .into_matching()
                    .is_none()
            );
        }
        let evidence = tracker
            .report(observed(3), epoch(7), "three")
            .into_matching()
            .expect("exact report mints evidence");
        assert_eq!(evidence.coordinate(), tracker.fence_coordinate());
        assert_eq!(
            tracker
                .matching_reported_state()
                .expect("stored exact report can be re-evaluated")
                .coordinate(),
            tracker.fence_coordinate()
        );
        assert_eq!(
            tracker.report(observed(3), epoch(7), "three"),
            ReportOutcome::Duplicate
        );
        assert!(tracker.matching_reported_state().is_some());
    }

    #[test]
    fn snapshot_round_trip_is_exact() {
        let mut tracker =
            GenerationTracker::new(scope(), desired(3), String::from("three"), epoch(7));
        assert_eq!(
            tracker.report(observed(2), epoch(7), String::from("two")),
            ReportOutcome::Accepted
        );
        let snapshot = tracker.snapshot();
        let restored = GenerationTracker::restore(snapshot.clone().into()).expect("valid restore");
        assert_eq!(restored.snapshot(), snapshot);
    }

    #[test]
    fn restore_fails_closed_for_invalid_cross_field_state() {
        let cases = [
            (
                GenerationRestore::new(scope(), 0, "desired", 1, 1, None, None),
                GenerationRestoreError::InvalidCoordinate,
            ),
            (
                GenerationRestore::new(scope(), 2, "desired", 1, 1, None, None),
                GenerationRestoreError::FenceGenerationMismatch,
            ),
            (
                GenerationRestore::new(
                    scope(),
                    2,
                    "desired",
                    2,
                    1,
                    Some(ObservedHighWaterRestore::new(3, "reported")),
                    None,
                ),
                GenerationRestoreError::ReportedAheadOfDesired,
            ),
            (
                GenerationRestore::new(
                    scope(),
                    2,
                    "desired",
                    2,
                    1,
                    Some(ObservedHighWaterRestore::new(2, "conflict")),
                    None,
                ),
                GenerationRestoreError::ReportedStateConflict,
            ),
            (
                GenerationRestore::new(
                    scope(),
                    2,
                    "desired",
                    2,
                    2,
                    Some(ObservedHighWaterRestore::new(1, "old")),
                    Some(CurrentFenceReportRestore::new(1, 1)),
                ),
                GenerationRestoreError::ReportedFenceMismatch,
            ),
            (
                GenerationRestore::new(
                    scope(),
                    2,
                    "desired",
                    2,
                    1,
                    None,
                    Some(CurrentFenceReportRestore::new(1, 1)),
                ),
                GenerationRestoreError::CurrentReportMismatch,
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(GenerationTracker::restore(input), Err(expected));
        }
    }

    #[test]
    fn authority_proofs_are_scoped_to_tracker_checks() {
        let tracker = GenerationTracker::new(scope(), desired(3), "three", epoch(7));
        assert_eq!(
            tracker.current_fence().coordinate(),
            tracker.fence_coordinate()
        );
        assert_eq!(tracker.current_fence().scope(), scope());
        assert!(
            tracker
                .supersedes(FenceCoordinate::new(desired(2), epoch(6)))
                .is_some()
        );
        assert!(tracker.supersedes(tracker.fence_coordinate()).is_none());
        assert!(
            tracker
                .supersedes(FenceCoordinate::new(desired(2), epoch(8)))
                .is_none(),
            "a newer generation cannot override a later fence epoch"
        );
    }
}
