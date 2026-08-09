//! Provider-neutral projection target conformance contract (#1917).
//!
//! This API carries only closed enums and aggregate counts. Provider messages, tenant IDs,
//! projection keys, payloads, and digests never cross the observation boundary.
//! The sealed exact tuple is a Hard compile-time enrollment guard; behavioral assertions are a
//! Medium test gate over externally observable transaction and replay facts.
//!
//! ref: serverlesstechnology/cqrs persistence/postgres-es/src/view_repository.rs@5097326888cdb8848eb36d0ad3decd470879b61c
//! INVARIANT: PROJECTION-TARGET-CONFORMANCE-01 { level = "Hard", exec = "native-compile", source = "code", native = "sealed exact tuple rejects missing, duplicate, reordered, or unknown projection scenarios and fixes the behavior output type" }.
//! INVARIANT: PROJECTION-CONFORMANCE-FIXTURE-01 { level = "Hard", exec = "native-compile", source = "code", native = "private fields and no raw constructor limit external carriers to the canonical primary and foreign test identities" }.

use crate::ConformanceErrorCategory;

/// One complete provider-neutral Projection input identity.
///
/// Private fields and the absence of a public constructor prevent consumers from expressing a
/// half-populated binding or recombining canonical scalar parts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectionConformanceBinding {
    source_domain: &'static str,
    contract_id: &'static str,
    contract_version: &'static str,
    schema_hash: &'static str,
    topic: &'static str,
}

impl ProjectionConformanceBinding {
    pub const fn source_domain(self) -> &'static str {
        self.source_domain
    }

    pub const fn contract_id(self) -> &'static str {
        self.contract_id
    }

    pub const fn contract_version(self) -> &'static str {
        self.contract_version
    }

    pub const fn schema_hash(self) -> &'static str {
        self.schema_hash
    }

    pub const fn topic(self) -> &'static str {
        self.topic
    }
}

/// Closed, provider-neutral identity used by Projection T2 conformance carriers.
///
/// The fields deliberately remain private and there is no configurable constructor. Consumers
/// can only lower one of the two canonical identities into their own production-shaped types.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectionConformanceFixture {
    definition_domain: &'static str,
    projection_id: &'static str,
    definition_version: &'static str,
    definition_schema_hash: &'static str,
    binding: ProjectionConformanceBinding,
    secondary_binding: Option<ProjectionConformanceBinding>,
    input_generation: &'static str,
    target_generation: &'static str,
}

impl ProjectionConformanceFixture {
    const INPUT_GENERATION: &'static str =
        "sha256:6adc35264f4f118f40d0b42f71260433dcc53b99b1355f82c4bcd821e002dd3b";

    const PRIMARY: Self = Self {
        definition_domain: "test.projection-conformance",
        projection_id: "test.projection-conformance.primary",
        definition_version: "v1",
        definition_schema_hash: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        binding: ProjectionConformanceBinding {
            source_domain: "test.projection-source",
            contract_id: "test.projection-source.primary",
            contract_version: "v1",
            schema_hash: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            topic: "test.projection-source.primary",
        },
        secondary_binding: Some(ProjectionConformanceBinding {
            source_domain: "test.projection-source",
            contract_id: "test.projection-source.primary-secondary",
            contract_version: "v1",
            schema_hash: "sha256:5555555555555555555555555555555555555555555555555555555555555555",
            topic: "test.projection-source.primary-secondary",
        }),
        input_generation: Self::INPUT_GENERATION,
        target_generation: "t2-primary-v1",
    };

    const FOREIGN: Self = Self {
        definition_domain: "test.projection-conformance",
        projection_id: "test.projection-conformance.foreign",
        definition_version: "v1",
        definition_schema_hash: "sha256:3333333333333333333333333333333333333333333333333333333333333333",
        binding: ProjectionConformanceBinding {
            source_domain: "test.projection-source",
            contract_id: "test.projection-source.foreign",
            contract_version: "v1",
            schema_hash: "sha256:4444444444444444444444444444444444444444444444444444444444444444",
            topic: "test.projection-source.foreign",
        },
        secondary_binding: None,
        input_generation: Self::INPUT_GENERATION,
        target_generation: "t2-foreign-v1",
    };

    pub const fn primary() -> Self {
        Self::PRIMARY
    }

    pub const fn foreign() -> Self {
        Self::FOREIGN
    }

    pub const fn definition_domain(self) -> &'static str {
        self.definition_domain
    }

    pub const fn projection_id(self) -> &'static str {
        self.projection_id
    }

    pub const fn definition_version(self) -> &'static str {
        self.definition_version
    }

    pub const fn definition_schema_hash(self) -> &'static str {
        self.definition_schema_hash
    }

    pub const fn binding(self) -> ProjectionConformanceBinding {
        self.binding
    }

    pub const fn secondary_binding(self) -> Option<ProjectionConformanceBinding> {
        self.secondary_binding
    }

    pub const fn input_generation(self) -> &'static str {
        self.input_generation
    }

    pub const fn target_generation(self) -> &'static str {
        self.target_generation
    }
}

/// Canonical projection target scenarios in required enrollment order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectionCase {
    AtomicApply,
    SameFactDuplicate,
    SameKeyConflict,
    PersistentOutOfOrder,
    IdentityMismatch,
    ConfirmedRollback,
    CommitUnknownReplay,
    RollbackFailed,
}

impl ProjectionCase {
    pub const ALL: [Self; 8] = [
        Self::AtomicApply,
        Self::SameFactDuplicate,
        Self::SameKeyConflict,
        Self::PersistentOutOfOrder,
        Self::IdentityMismatch,
        Self::ConfirmedRollback,
        Self::CommitUnknownReplay,
        Self::RollbackFailed,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AtomicApply => "atomic-apply",
            Self::SameFactDuplicate => "same-fact-duplicate",
            Self::SameKeyConflict => "same-key-conflict",
            Self::PersistentOutOfOrder => "persistent-out-of-order",
            Self::IdentityMismatch => "identity-mismatch",
            Self::ConfirmedRollback => "confirmed-rollback",
            Self::CommitUnknownReplay => "commit-unknown-replay",
            Self::RollbackFailed => "rollback-failed",
        }
    }
}

/// Successful runtime result for one target attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectionAttemptOutcome {
    Applied,
    Duplicate,
}

/// Closed runtime error facts relevant to target conformance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectionAttemptError {
    Conflict,
    OutOfOrder,
    IdentityMismatch,
    Permanent,
    CommitUnknown,
    RollbackFailed,
}

/// One target attempt and its checkpoint decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectionAttemptObservation {
    result: Result<ProjectionAttemptOutcome, ProjectionAttemptError>,
    checkpoint_advanced: bool,
}

impl ProjectionAttemptObservation {
    pub const fn succeeded(outcome: ProjectionAttemptOutcome, checkpoint_advanced: bool) -> Self {
        Self {
            result: Ok(outcome),
            checkpoint_advanced,
        }
    }

    pub const fn failed(error: ProjectionAttemptError, checkpoint_advanced: bool) -> Self {
        Self {
            result: Err(error),
            checkpoint_advanced,
        }
    }

    pub const fn result(self) -> Result<ProjectionAttemptOutcome, ProjectionAttemptError> {
        self.result
    }

    pub const fn checkpoint_advanced(self) -> bool {
        self.checkpoint_advanced
    }
}

/// Aggregate low-sensitivity facts returned by a canonical behavior.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionObservation {
    attempts: Vec<ProjectionAttemptObservation>,
    store_apply_calls: u64,
    business_effects: u64,
    receipts: u64,
}

impl ProjectionObservation {
    pub fn new(
        attempts: impl Into<Vec<ProjectionAttemptObservation>>,
        store_apply_calls: u64,
        business_effects: u64,
        receipts: u64,
    ) -> Self {
        Self {
            attempts: attempts.into(),
            store_apply_calls,
            business_effects,
            receipts,
        }
    }

    pub fn attempts(&self) -> &[ProjectionAttemptObservation] {
        &self.attempts
    }

    pub const fn store_apply_calls(&self) -> u64 {
        self.store_apply_calls
    }

    pub const fn business_effects(&self) -> u64 {
        self.business_effects
    }

    pub const fn receipts(&self) -> u64 {
        self.receipts
    }
}

/// Low-cardinality conformance failure with no provider-controlled message.
#[derive(Debug, thiserror::Error)]
pub enum ProjectionConformanceError {
    #[error("projection conformance provider failure at {stage}: {category}")]
    Provider {
        stage: &'static str,
        category: ConformanceErrorCategory,
    },
    #[error(
        "projection conformance {case} violated {invariant}: expected {expected}, got {actual}"
    )]
    Mismatch {
        case: &'static str,
        invariant: &'static str,
        expected: String,
        actual: String,
    },
}

impl ProjectionConformanceError {
    pub const fn provider(stage: &'static str, category: ConformanceErrorCategory) -> Self {
        Self::Provider { stage, category }
    }
}

/// Verifies all observable facts for one canonical scenario.
pub fn verify_projection_case(
    case: ProjectionCase,
    observation: &ProjectionObservation,
) -> Result<(), ProjectionConformanceError> {
    let expected_attempts: &[ProjectionAttemptObservation] = match case {
        ProjectionCase::AtomicApply => &[ProjectionAttemptObservation::succeeded(
            ProjectionAttemptOutcome::Applied,
            true,
        )],
        ProjectionCase::SameFactDuplicate => &[
            ProjectionAttemptObservation::succeeded(ProjectionAttemptOutcome::Applied, true),
            ProjectionAttemptObservation::succeeded(ProjectionAttemptOutcome::Applied, true),
            ProjectionAttemptObservation::succeeded(ProjectionAttemptOutcome::Duplicate, true),
        ],
        ProjectionCase::SameKeyConflict => &[
            ProjectionAttemptObservation::succeeded(ProjectionAttemptOutcome::Applied, true),
            ProjectionAttemptObservation::failed(ProjectionAttemptError::Conflict, false),
        ],
        ProjectionCase::PersistentOutOfOrder => &[
            ProjectionAttemptObservation::succeeded(ProjectionAttemptOutcome::Applied, true),
            ProjectionAttemptObservation::failed(ProjectionAttemptError::OutOfOrder, false),
        ],
        ProjectionCase::IdentityMismatch => &[ProjectionAttemptObservation::failed(
            ProjectionAttemptError::IdentityMismatch,
            false,
        )],
        ProjectionCase::ConfirmedRollback => &[ProjectionAttemptObservation::failed(
            ProjectionAttemptError::Permanent,
            false,
        )],
        ProjectionCase::CommitUnknownReplay => &[
            ProjectionAttemptObservation::failed(ProjectionAttemptError::CommitUnknown, false),
            ProjectionAttemptObservation::succeeded(ProjectionAttemptOutcome::Duplicate, true),
        ],
        ProjectionCase::RollbackFailed => &[ProjectionAttemptObservation::failed(
            ProjectionAttemptError::RollbackFailed,
            false,
        )],
    };
    let expected_counts = match case {
        ProjectionCase::AtomicApply => (1, 1, 1),
        ProjectionCase::SameFactDuplicate => (3, 2, 2),
        ProjectionCase::SameKeyConflict
        | ProjectionCase::PersistentOutOfOrder
        | ProjectionCase::CommitUnknownReplay => (2, 1, 1),
        ProjectionCase::IdentityMismatch => (0, 0, 0),
        ProjectionCase::ConfirmedRollback | ProjectionCase::RollbackFailed => (1, 0, 0),
    };

    ensure(
        case,
        "attempt-sequence",
        format!("{expected_attempts:?}"),
        format!("{:?}", observation.attempts()),
        observation.attempts() == expected_attempts,
    )?;
    ensure_count(
        case,
        "store-apply-calls",
        expected_counts.0,
        observation.store_apply_calls(),
    )?;
    ensure_count(
        case,
        "business-effects",
        expected_counts.1,
        observation.business_effects(),
    )?;
    ensure_count(case, "receipts", expected_counts.2, observation.receipts())
}

fn ensure_count(
    case: ProjectionCase,
    invariant: &'static str,
    expected: u64,
    actual: u64,
) -> Result<(), ProjectionConformanceError> {
    ensure(
        case,
        invariant,
        expected.to_string(),
        actual.to_string(),
        expected == actual,
    )
}

fn ensure(
    case: ProjectionCase,
    invariant: &'static str,
    expected: String,
    actual: String,
    matches: bool,
) -> Result<(), ProjectionConformanceError> {
    if matches {
        Ok(())
    } else {
        Err(ProjectionConformanceError::Mismatch {
            case: case.as_str(),
            invariant,
            expected,
            actual,
        })
    }
}

/// Exported-macro implementation details, sealed against external complete-set implementations.
#[doc(hidden)]
pub mod __catalog {
    pub enum AtomicApply {}
    pub enum SameFactDuplicate {}
    pub enum SameKeyConflict {}
    pub enum PersistentOutOfOrder {}
    pub enum IdentityMismatch {}
    pub enum ConfirmedRollback {}
    pub enum CommitUnknownReplay {}
    pub enum RollbackFailed {}

    mod private {
        pub trait SealedCompleteSet {}

        impl SealedCompleteSet
            for (
                super::AtomicApply,
                super::SameFactDuplicate,
                super::SameKeyConflict,
                super::PersistentOutOfOrder,
                super::IdentityMismatch,
                super::ConfirmedRollback,
                super::CommitUnknownReplay,
                super::RollbackFailed,
            )
        {
        }
    }

    pub trait CompleteSet: private::SealedCompleteSet {}
    impl<Set> CompleteSet for Set where Set: private::SealedCompleteSet {}

    pub fn assert_complete<Set: CompleteSet>() {}

    pub fn assert_behavior<Behavior, BehaviorFuture>(_behavior: Behavior)
    where
        Behavior: FnOnce() -> BehaviorFuture,
        BehaviorFuture: std::future::Future<
                Output = Result<super::ProjectionObservation, super::ProjectionConformanceError>,
            >,
    {
    }
}

/// Atomically enrolls the exact canonical scenario set and generates selectable async runners.
#[macro_export]
macro_rules! projection_target_conformance {
    (@case atomic_apply) => { $crate::projection_conformance::__catalog::AtomicApply };
    (@case same_fact_duplicate) => { $crate::projection_conformance::__catalog::SameFactDuplicate };
    (@case same_key_conflict) => { $crate::projection_conformance::__catalog::SameKeyConflict };
    (@case persistent_out_of_order) => { $crate::projection_conformance::__catalog::PersistentOutOfOrder };
    (@case identity_mismatch) => { $crate::projection_conformance::__catalog::IdentityMismatch };
    (@case confirmed_rollback) => { $crate::projection_conformance::__catalog::ConfirmedRollback };
    (@case commit_unknown_replay) => { $crate::projection_conformance::__catalog::CommitUnknownReplay };
    (@case rollback_failed) => { $crate::projection_conformance::__catalog::RollbackFailed };
    (@case_id atomic_apply) => { $crate::projection_conformance::ProjectionCase::AtomicApply };
    (@case_id same_fact_duplicate) => { $crate::projection_conformance::ProjectionCase::SameFactDuplicate };
    (@case_id same_key_conflict) => { $crate::projection_conformance::ProjectionCase::SameKeyConflict };
    (@case_id persistent_out_of_order) => { $crate::projection_conformance::ProjectionCase::PersistentOutOfOrder };
    (@case_id identity_mismatch) => { $crate::projection_conformance::ProjectionCase::IdentityMismatch };
    (@case_id confirmed_rollback) => { $crate::projection_conformance::ProjectionCase::ConfirmedRollback };
    (@case_id commit_unknown_replay) => { $crate::projection_conformance::ProjectionCase::CommitUnknownReplay };
    (@case_id rollback_failed) => { $crate::projection_conformance::ProjectionCase::RollbackFailed };
    (
        cases: {
            $(
                $case:ident => {
                    $(#[$test_attr:meta])*
                    $runner:ident => $behavior:path
                }
            ),+ $(,)?
        }
    ) => {
        const _: () = {
            #[allow(dead_code)]
            fn __rss_projection_target_conformance_compile_guard() {
                $crate::projection_conformance::__catalog::assert_complete::<(
                    $($crate::projection_target_conformance!(@case $case),)+
                )>();
                $($crate::projection_conformance::__catalog::assert_behavior($behavior);)+
            }
        };
        $(
            $(#[$test_attr])*
            async fn $runner() -> Result<
                (),
                $crate::projection_conformance::ProjectionConformanceError,
            > {
                let observation = $behavior().await?;
                $crate::projection_conformance::verify_projection_case(
                    $crate::projection_target_conformance!(@case_id $case),
                    &observation,
                )
            }
        )+
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_primary_fixture_pins_the_complete_neutral_tuple() -> Result<(), &'static str> {
        let primary = ProjectionConformanceFixture::primary();

        assert_eq!(primary.definition_domain(), "test.projection-conformance");
        assert_eq!(
            primary.projection_id(),
            "test.projection-conformance.primary"
        );
        let binding = primary.binding();
        assert_eq!(binding.source_domain(), "test.projection-source");
        assert_eq!(binding.contract_id(), "test.projection-source.primary");
        assert_eq!(binding.topic(), "test.projection-source.primary");
        assert_eq!(primary.definition_version(), "v1");
        assert_eq!(binding.contract_version(), "v1");
        assert_eq!(primary.target_generation(), "t2-primary-v1");
        let secondary = primary
            .secondary_binding()
            .ok_or("primary fixture must seal one complete secondary binding")?;
        assert_eq!(
            secondary.contract_id(),
            "test.projection-source.primary-secondary"
        );
        assert_eq!(
            secondary.topic(),
            "test.projection-source.primary-secondary"
        );
        assert_eq!(
            secondary.schema_hash(),
            "sha256:5555555555555555555555555555555555555555555555555555555555555555"
        );
        assert_eq!(
            primary.definition_schema_hash(),
            "sha256:1111111111111111111111111111111111111111111111111111111111111111"
        );
        assert_eq!(
            binding.schema_hash(),
            "sha256:2222222222222222222222222222222222222222222222222222222222222222"
        );
        Ok(())
    }

    #[test]
    fn canonical_foreign_fixture_pins_the_complete_neutral_tuple() {
        let foreign = ProjectionConformanceFixture::foreign();

        assert_eq!(foreign.definition_domain(), "test.projection-conformance");
        assert_eq!(
            foreign.projection_id(),
            "test.projection-conformance.foreign"
        );
        let binding = foreign.binding();
        assert_eq!(binding.source_domain(), "test.projection-source");
        assert_eq!(binding.contract_id(), "test.projection-source.foreign");
        assert_eq!(binding.topic(), "test.projection-source.foreign");
        assert_eq!(foreign.definition_version(), "v1");
        assert_eq!(binding.contract_version(), "v1");
        assert_eq!(foreign.target_generation(), "t2-foreign-v1");
        assert_eq!(foreign.secondary_binding(), None);
        assert_eq!(
            foreign.definition_schema_hash(),
            "sha256:3333333333333333333333333333333333333333333333333333333333333333"
        );
        assert_eq!(
            binding.schema_hash(),
            "sha256:4444444444444444444444444444444444444444444444444444444444444444"
        );
    }

    #[test]
    fn canonical_fixtures_are_distinct_members_of_one_input_generation() {
        let primary = ProjectionConformanceFixture::primary();
        let foreign = ProjectionConformanceFixture::foreign();

        assert_ne!(primary, foreign);
        assert_ne!(
            primary.definition_schema_hash(),
            foreign.definition_schema_hash()
        );
        assert_ne!(
            primary.binding().schema_hash(),
            foreign.binding().schema_hash()
        );
        assert_eq!(primary.input_generation(), foreign.input_generation());
    }

    fn canonical(case: ProjectionCase) -> ProjectionObservation {
        match case {
            ProjectionCase::AtomicApply => ProjectionObservation::new(
                [ProjectionAttemptObservation::succeeded(
                    ProjectionAttemptOutcome::Applied,
                    true,
                )],
                1,
                1,
                1,
            ),
            ProjectionCase::SameFactDuplicate => ProjectionObservation::new(
                [
                    ProjectionAttemptObservation::succeeded(
                        ProjectionAttemptOutcome::Applied,
                        true,
                    ),
                    ProjectionAttemptObservation::succeeded(
                        ProjectionAttemptOutcome::Applied,
                        true,
                    ),
                    ProjectionAttemptObservation::succeeded(
                        ProjectionAttemptOutcome::Duplicate,
                        true,
                    ),
                ],
                3,
                2,
                2,
            ),
            ProjectionCase::SameKeyConflict => failed_after_apply(ProjectionAttemptError::Conflict),
            ProjectionCase::PersistentOutOfOrder => {
                failed_after_apply(ProjectionAttemptError::OutOfOrder)
            }
            ProjectionCase::IdentityMismatch => ProjectionObservation::new(
                [ProjectionAttemptObservation::failed(
                    ProjectionAttemptError::IdentityMismatch,
                    false,
                )],
                0,
                0,
                0,
            ),
            ProjectionCase::ConfirmedRollback => ProjectionObservation::new(
                [ProjectionAttemptObservation::failed(
                    ProjectionAttemptError::Permanent,
                    false,
                )],
                1,
                0,
                0,
            ),
            ProjectionCase::CommitUnknownReplay => ProjectionObservation::new(
                [
                    ProjectionAttemptObservation::failed(
                        ProjectionAttemptError::CommitUnknown,
                        false,
                    ),
                    ProjectionAttemptObservation::succeeded(
                        ProjectionAttemptOutcome::Duplicate,
                        true,
                    ),
                ],
                2,
                1,
                1,
            ),
            ProjectionCase::RollbackFailed => ProjectionObservation::new(
                [ProjectionAttemptObservation::failed(
                    ProjectionAttemptError::RollbackFailed,
                    false,
                )],
                1,
                0,
                0,
            ),
        }
    }

    fn failed_after_apply(error: ProjectionAttemptError) -> ProjectionObservation {
        ProjectionObservation::new(
            [
                ProjectionAttemptObservation::succeeded(ProjectionAttemptOutcome::Applied, true),
                ProjectionAttemptObservation::failed(error, false),
            ],
            2,
            1,
            1,
        )
    }

    async fn atomic_apply_behavior() -> Result<ProjectionObservation, ProjectionConformanceError> {
        Ok(canonical(ProjectionCase::AtomicApply))
    }

    async fn same_fact_duplicate_behavior()
    -> Result<ProjectionObservation, ProjectionConformanceError> {
        Ok(canonical(ProjectionCase::SameFactDuplicate))
    }

    async fn same_key_conflict_behavior()
    -> Result<ProjectionObservation, ProjectionConformanceError> {
        Ok(canonical(ProjectionCase::SameKeyConflict))
    }

    async fn persistent_out_of_order_behavior()
    -> Result<ProjectionObservation, ProjectionConformanceError> {
        Ok(canonical(ProjectionCase::PersistentOutOfOrder))
    }

    async fn identity_mismatch_behavior()
    -> Result<ProjectionObservation, ProjectionConformanceError> {
        Ok(canonical(ProjectionCase::IdentityMismatch))
    }

    async fn confirmed_rollback_behavior()
    -> Result<ProjectionObservation, ProjectionConformanceError> {
        Ok(canonical(ProjectionCase::ConfirmedRollback))
    }

    async fn commit_unknown_replay_behavior()
    -> Result<ProjectionObservation, ProjectionConformanceError> {
        Ok(canonical(ProjectionCase::CommitUnknownReplay))
    }

    async fn rollback_failed_behavior() -> Result<ProjectionObservation, ProjectionConformanceError>
    {
        Ok(canonical(ProjectionCase::RollbackFailed))
    }

    crate::projection_target_conformance! {
        cases: {
            atomic_apply => {
                #[tokio::test]
                macro_runner_atomic_apply => atomic_apply_behavior
            },
            same_fact_duplicate => {
                #[tokio::test]
                macro_runner_same_fact_duplicate => same_fact_duplicate_behavior
            },
            same_key_conflict => {
                #[tokio::test]
                macro_runner_same_key_conflict => same_key_conflict_behavior
            },
            persistent_out_of_order => {
                #[tokio::test]
                macro_runner_persistent_out_of_order => persistent_out_of_order_behavior
            },
            identity_mismatch => {
                #[tokio::test]
                macro_runner_identity_mismatch => identity_mismatch_behavior
            },
            confirmed_rollback => {
                #[tokio::test]
                macro_runner_confirmed_rollback => confirmed_rollback_behavior
            },
            commit_unknown_replay => {
                #[tokio::test]
                macro_runner_commit_unknown_replay => commit_unknown_replay_behavior
            },
            rollback_failed => {
                #[tokio::test]
                macro_runner_rollback_failed => rollback_failed_behavior
            },
        }
    }

    #[test]
    fn canonical_observations_pass_all_cases() -> Result<(), ProjectionConformanceError> {
        for case in ProjectionCase::ALL {
            verify_projection_case(case, &canonical(case))?;
        }
        Ok(())
    }

    #[test]
    fn every_observation_dimension_has_a_synthetic_red() {
        let mut attempts = canonical(ProjectionCase::AtomicApply);
        attempts.attempts[0] =
            ProjectionAttemptObservation::succeeded(ProjectionAttemptOutcome::Applied, false);
        assert!(verify_projection_case(ProjectionCase::AtomicApply, &attempts).is_err());

        let mut calls = canonical(ProjectionCase::AtomicApply);
        calls.store_apply_calls = 0;
        assert!(verify_projection_case(ProjectionCase::AtomicApply, &calls).is_err());

        let mut effects = canonical(ProjectionCase::AtomicApply);
        effects.business_effects = 0;
        assert!(verify_projection_case(ProjectionCase::AtomicApply, &effects).is_err());

        let mut receipts = canonical(ProjectionCase::AtomicApply);
        receipts.receipts = 0;
        assert!(verify_projection_case(ProjectionCase::AtomicApply, &receipts).is_err());

        let failed_checkpoint = ProjectionObservation::new(
            [ProjectionAttemptObservation::failed(
                ProjectionAttemptError::Permanent,
                true,
            )],
            1,
            0,
            0,
        );
        assert!(
            verify_projection_case(ProjectionCase::ConfirmedRollback, &failed_checkpoint).is_err()
        );
    }

    #[test]
    fn duplicate_contract_survives_high_water_and_checkpoint_loss()
    -> Result<(), ProjectionConformanceError> {
        let observation = ProjectionObservation::new(
            [
                ProjectionAttemptObservation::succeeded(ProjectionAttemptOutcome::Applied, true),
                ProjectionAttemptObservation::succeeded(ProjectionAttemptOutcome::Applied, true),
                ProjectionAttemptObservation::succeeded(ProjectionAttemptOutcome::Duplicate, true),
            ],
            3,
            2,
            2,
        );
        verify_projection_case(ProjectionCase::SameFactDuplicate, &observation)
    }
}
