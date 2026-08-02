#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use consistency::{
    Lsn, PartitionSerialDelivery, ProjectionApplyErrorReason, ProjectionEventMetadata,
    ProjectionEventRecord, SerialInOrder,
};
use diport::{
    Checkpoint, CheckpointId, CheckpointOwner, CheckpointStoreError, CheckpointVersion,
    DeadLetterRecord, DeadLetterStore, DeadLetterStoreError, OwnerCheckpointStore, SaveOutcome,
};
use eventexec::{
    ConformingProjectionTarget, ProjectionHarness, ProjectionId, ProjectionProjector,
    ProjectionSelector, ProjectionStop, ProjectionTarget, ProjectionTargetDefinition,
    ProjectionTargetStore, ProjectionTargetStoreError, ProjectionTargetStoreErrorKind,
    ProjectionTargetStoreOutcome, ProjectionVersion, ValidatedProjectionApply,
};
use futures::future::BoxFuture;
use testkit::projection_conformance::{
    ProjectionAttemptError, ProjectionAttemptObservation, ProjectionAttemptOutcome,
    ProjectionConformanceError, ProjectionObservation,
};

const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const PROJECTION: &str = "audit.session-projection";
const TOPIC: &str = "identity.session.created";
const CONTRACT: &str = "identity.session-created";
const SCHEMA: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[derive(Clone, Copy)]
enum Fault {
    None,
    ConfirmedRollback,
    CommitUnknownOnce,
    RollbackFailed,
    OrderingBeforeReceipt,
    MutationWithoutReceipt,
    AcceptConflict,
    AcceptOutOfOrder,
    RollbackLeaks,
    CommitUnknownWithoutCommit,
    RollbackFailedAsPermanent,
}

struct StoreState {
    receipts: BTreeMap<String, [u8; 32]>,
    high_water: Option<Lsn>,
    calls: u64,
    effects: u64,
    commit_unknown_fired: bool,
    staged_mutations: u64,
    rollback_attempts: u64,
}

struct ReferenceStore {
    state: Mutex<StoreState>,
    fault: Fault,
}

#[derive(Debug, thiserror::Error)]
#[error("reference projection store fault")]
struct ReferenceStoreFault;

fn store_error(kind: ProjectionTargetStoreErrorKind) -> ProjectionTargetStoreError {
    let reason = match kind {
        ProjectionTargetStoreErrorKind::Invariant => ProjectionApplyErrorReason::ProviderInvariant,
        ProjectionTargetStoreErrorKind::Conflict => ProjectionApplyErrorReason::Conflict,
        ProjectionTargetStoreErrorKind::OutOfOrder => ProjectionApplyErrorReason::OutOfOrder,
        ProjectionTargetStoreErrorKind::Transient => ProjectionApplyErrorReason::Transient,
        ProjectionTargetStoreErrorKind::Permanent => {
            ProjectionApplyErrorReason::PayloadValueInvalid
        }
        ProjectionTargetStoreErrorKind::CommitUnknown => ProjectionApplyErrorReason::CommitUnknown,
        ProjectionTargetStoreErrorKind::RollbackFailed => {
            ProjectionApplyErrorReason::RollbackFailed
        }
    };
    ProjectionTargetStoreError::new(reason, ReferenceStoreFault)
}

impl ReferenceStore {
    fn new(fault: Fault) -> Self {
        Self {
            state: Mutex::new(StoreState {
                receipts: BTreeMap::new(),
                high_water: None,
                calls: 0,
                effects: 0,
                commit_unknown_fired: false,
                staged_mutations: 0,
                rollback_attempts: 0,
            }),
            fault,
        }
    }

    fn counts(&self) -> (u64, u64, u64) {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        (state.calls, state.effects, state.receipts.len() as u64)
    }

    fn transaction_counts(&self) -> (u64, u64) {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        (state.staged_mutations, state.rollback_attempts)
    }
}

impl ProjectionTargetStore for ReferenceStore {
    fn apply<'a>(
        &'a self,
        input: &'a ValidatedProjectionApply,
    ) -> BoxFuture<'a, Result<ProjectionTargetStoreOutcome, ProjectionTargetStoreError>> {
        Box::pin(async move {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            state.calls += 1;
            let key = format!(
                "{}:{}:{}:{}",
                input.key().tenant(),
                input.key().projection().as_str(),
                input.key().generation().as_str(),
                input.key().event_id()
            );

            if matches!(self.fault, Fault::OrderingBeforeReceipt)
                && state.high_water.is_some_and(|high| input.lsn() < high)
            {
                return Err(store_error(ProjectionTargetStoreErrorKind::OutOfOrder));
            }

            // Receipt lookup deliberately precedes persistent ordering: checkpoint loss replay of
            // an old, already committed fact must be Duplicate rather than OutOfOrder.
            if let Some(existing) = state.receipts.get(&key) {
                return if existing == input.fact_digest() {
                    Ok(ProjectionTargetStoreOutcome::Duplicate)
                } else if matches!(self.fault, Fault::AcceptConflict) {
                    state.receipts.insert(key, *input.fact_digest());
                    state.effects += 1;
                    Ok(ProjectionTargetStoreOutcome::Applied)
                } else {
                    Err(store_error(ProjectionTargetStoreErrorKind::Conflict))
                };
            }
            if !matches!(self.fault, Fault::AcceptOutOfOrder)
                && state.high_water.is_some_and(|high| input.lsn() < high)
            {
                return Err(store_error(ProjectionTargetStoreErrorKind::OutOfOrder));
            }

            // Stage mutation + receipt together, exactly as a provider transaction would. Faults
            // below decide whether that staged transaction becomes durable, is rolled back, or
            // has an unknowable acknowledgement.
            let mut staged_receipts = state.receipts.clone();
            staged_receipts.insert(key, *input.fact_digest());
            let staged_effects = state.effects + 1;
            let staged_high_water = Some(input.lsn());
            state.staged_mutations += 1;

            match self.fault {
                Fault::ConfirmedRollback => {
                    state.rollback_attempts += 1;
                    return Err(store_error(ProjectionTargetStoreErrorKind::Permanent));
                }
                Fault::RollbackFailed => {
                    state.rollback_attempts += 1;
                    return Err(store_error(ProjectionTargetStoreErrorKind::RollbackFailed));
                }
                Fault::RollbackFailedAsPermanent => {
                    state.rollback_attempts += 1;
                    return Err(store_error(ProjectionTargetStoreErrorKind::Permanent));
                }
                Fault::CommitUnknownWithoutCommit if !state.commit_unknown_fired => {
                    state.commit_unknown_fired = true;
                    return Err(store_error(ProjectionTargetStoreErrorKind::CommitUnknown));
                }
                Fault::MutationWithoutReceipt => {
                    state.effects = staged_effects;
                    state.high_water = staged_high_water;
                    return Ok(ProjectionTargetStoreOutcome::Applied);
                }
                Fault::RollbackLeaks => {
                    state.receipts = staged_receipts;
                    state.effects = staged_effects;
                    state.high_water = staged_high_water;
                    state.rollback_attempts += 1;
                    return Err(store_error(ProjectionTargetStoreErrorKind::Permanent));
                }
                Fault::None
                | Fault::CommitUnknownOnce
                | Fault::OrderingBeforeReceipt
                | Fault::AcceptConflict
                | Fault::AcceptOutOfOrder
                | Fault::CommitUnknownWithoutCommit => {}
            }

            state.receipts = staged_receipts;
            state.effects = staged_effects;
            state.high_water = staged_high_water;
            if matches!(self.fault, Fault::CommitUnknownOnce) && !state.commit_unknown_fired {
                state.commit_unknown_fired = true;
                return Err(store_error(ProjectionTargetStoreErrorKind::CommitUnknown));
            }
            Ok(ProjectionTargetStoreOutcome::Applied)
        })
    }
}

#[derive(Default)]
struct CheckpointStore {
    state: Mutex<Option<(Lsn, CheckpointVersion)>>,
}

impl CheckpointStore {
    fn offset(&self) -> Option<Lsn> {
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .map(|(offset, _)| offset)
    }
}

impl OwnerCheckpointStore for CheckpointStore {
    async fn get_checkpoint(
        &self,
        _owner: &CheckpointOwner,
        _id: &CheckpointId,
    ) -> Result<Option<Checkpoint>, CheckpointStoreError> {
        Ok(self
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .map(|(offset, version)| Checkpoint { offset, version }))
    }

    async fn save_checkpoint(
        &self,
        _owner: &CheckpointOwner,
        _id: &CheckpointId,
        offset: Lsn,
        expected: CheckpointVersion,
    ) -> Result<SaveOutcome, CheckpointStoreError> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        match *state {
            None if expected == CheckpointVersion::INITIAL => {
                *state = Some((offset, expected.next()));
                Ok(SaveOutcome::Saved)
            }
            Some((_, version)) if version == expected => {
                *state = Some((offset, expected.next()));
                Ok(SaveOutcome::Saved)
            }
            _ => Ok(SaveOutcome::StaleVersion),
        }
    }

    async fn shutdown(&self) -> Result<(), CheckpointStoreError> {
        Ok(())
    }
}

struct DeadLetters;

impl DeadLetterStore for DeadLetters {
    async fn write_dead_letter(
        &self,
        _record: DeadLetterRecord,
    ) -> Result<(), DeadLetterStoreError> {
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), DeadLetterStoreError> {
        Ok(())
    }
}

struct SerialSource;
impl PartitionSerialDelivery for SerialSource {}

fn selector() -> ProjectionSelector {
    ProjectionSelector::new(
        vocab::TenantId::parse(TENANT).expect("canonical tenant"),
        ProjectionId::parse(PROJECTION).expect("canonical projection"),
        ProjectionVersion::parse("v2").expect("canonical generation"),
    )
}

fn record(lsn: u64, event_id: &str, payload: &[u8], schema: &str) -> ProjectionEventRecord {
    ProjectionEventRecord::with_metadata(
        Lsn::new(lsn),
        consistency::EventTopic::parse(TOPIC).expect("canonical topic"),
        payload.to_vec(),
        ProjectionEventMetadata::new(
            vocab::TenantId::parse(TENANT).expect("canonical tenant"),
            event_id,
            "identity",
            CONTRACT,
            "v1",
            schema,
            serde_json::json!({"tenantId": TENANT}),
            None,
            None,
        ),
    )
}

fn target(store: Arc<ReferenceStore>) -> Arc<dyn ProjectionTarget> {
    Arc::new(
        ConformingProjectionTarget::new(
            ProjectionTargetDefinition::new(
                vocab::ContractBinding::from_static(
                    "audit",
                    PROJECTION,
                    "v2",
                    "sha256:8750ef9b30912c837637ee30ee712e1572903fdaa59514fd486f2d0ab15fa071",
                ),
                generated::event::PROJECTION_INPUT_GENERATION,
            )
            .expect("canonical target definition"),
            vec![vocab::ProjectionInputBinding::from_static(
                PROJECTION, "identity", CONTRACT, "v1", SCHEMA, TOPIC,
            )],
            store,
        )
        .expect("canonical target configuration"),
    )
}

async fn attempt(
    target: Arc<dyn ProjectionTarget>,
    checkpoint: Arc<CheckpointStore>,
    event: ProjectionEventRecord,
) -> ProjectionAttemptObservation {
    let before = checkpoint.offset();
    let selector = selector();
    let execution =
        eventexec::WorkflowRuntimePlan::generated_projection_operator_execution_fixture(
            selector.projection(),
            selector.tenant(),
        )
        .expect("generated conformance projection execution");
    let harness = ProjectionHarness::new(
        Arc::new(
            ProjectionProjector::with_execution(execution, selector.clone(), target)
                .expect("conformance execution tenant matches selector"),
        ),
        Arc::clone(&checkpoint),
        selector.shadow_checkpoint_owner(),
        selector.shadow_checkpoint_id(),
        Arc::new(DeadLetters),
        SerialInOrder::from_source(&SerialSource),
    );
    let run = harness.run(&[event]).await;
    let advanced = checkpoint.offset() != before;
    if run.applied == 1 {
        ProjectionAttemptObservation::succeeded(ProjectionAttemptOutcome::Applied, advanced)
    } else if run.duplicates == 1 {
        ProjectionAttemptObservation::succeeded(ProjectionAttemptOutcome::Duplicate, advanced)
    } else {
        let error = match run.stop {
            ProjectionStop::ApplyFailed {
                reason: ProjectionApplyErrorReason::Conflict,
                ..
            } => ProjectionAttemptError::Conflict,
            ProjectionStop::ApplyFailed {
                reason: ProjectionApplyErrorReason::OutOfOrder,
                ..
            } => ProjectionAttemptError::OutOfOrder,
            ProjectionStop::ApplyFailed {
                reason:
                    ProjectionApplyErrorReason::TargetDefinitionDrift
                    | ProjectionApplyErrorReason::InputBindingDrift
                    | ProjectionApplyErrorReason::TenantDrift
                    | ProjectionApplyErrorReason::ProviderInvariant,
                ..
            } => ProjectionAttemptError::IdentityMismatch,
            ProjectionStop::ApplyFailed {
                reason:
                    ProjectionApplyErrorReason::PayloadMalformed
                    | ProjectionApplyErrorReason::PayloadValueInvalid
                    | ProjectionApplyErrorReason::VersionRegression
                    | ProjectionApplyErrorReason::ProviderPermanent,
                ..
            } => ProjectionAttemptError::Permanent,
            ProjectionStop::ApplyFailed {
                reason: ProjectionApplyErrorReason::CommitUnknown,
                ..
            } => ProjectionAttemptError::CommitUnknown,
            ProjectionStop::ApplyFailed {
                reason: ProjectionApplyErrorReason::RollbackFailed,
                ..
            } => ProjectionAttemptError::RollbackFailed,
            other => panic!("unexpected projection stop: {other:?}"),
        };
        ProjectionAttemptObservation::failed(error, advanced)
    }
}

fn observation(
    attempts: Vec<ProjectionAttemptObservation>,
    store: &ReferenceStore,
) -> Result<ProjectionObservation, ProjectionConformanceError> {
    let (calls, effects, receipts) = store.counts();
    Ok(ProjectionObservation::new(
        attempts, calls, effects, receipts,
    ))
}

fn rollback_observation(
    attempts: Vec<ProjectionAttemptObservation>,
    store: &ReferenceStore,
) -> Result<ProjectionObservation, ProjectionConformanceError> {
    let actual = store.transaction_counts();
    if actual != (1, 1) {
        return Err(ProjectionConformanceError::Mismatch {
            case: "transaction-fault-fixture",
            invariant: "mutation-receipt-staged-before-rollback",
            expected: "(1, 1)".to_string(),
            actual: format!("{actual:?}"),
        });
    }
    observation(attempts, store)
}

async fn atomic_apply() -> Result<ProjectionObservation, ProjectionConformanceError> {
    atomic_apply_with(Fault::None).await
}

async fn atomic_apply_with(
    fault: Fault,
) -> Result<ProjectionObservation, ProjectionConformanceError> {
    let store = Arc::new(ReferenceStore::new(fault));
    let result = attempt(
        target(Arc::clone(&store)),
        Arc::new(CheckpointStore::default()),
        record(1, "event-1", b"one", SCHEMA),
    )
    .await;
    observation(vec![result], &store)
}

async fn same_fact_duplicate() -> Result<ProjectionObservation, ProjectionConformanceError> {
    same_fact_duplicate_with(Fault::None).await
}

async fn same_fact_duplicate_with(
    fault: Fault,
) -> Result<ProjectionObservation, ProjectionConformanceError> {
    let store = Arc::new(ReferenceStore::new(fault));
    let checkpoint = Arc::new(CheckpointStore::default());
    let first = attempt(
        target(Arc::clone(&store)),
        Arc::clone(&checkpoint),
        record(1, "event-1", b"one", SCHEMA),
    )
    .await;
    let second = attempt(
        target(Arc::clone(&store)),
        checkpoint,
        record(2, "event-2", b"two", SCHEMA),
    )
    .await;
    // Simulate loss of the local checkpoint after the target committed a newer high-water.
    let replay = attempt(
        target(Arc::clone(&store)),
        Arc::new(CheckpointStore::default()),
        record(1, "event-1", b"one", SCHEMA),
    )
    .await;
    observation(vec![first, second, replay], &store)
}

async fn same_key_conflict() -> Result<ProjectionObservation, ProjectionConformanceError> {
    same_key_conflict_with(Fault::None).await
}

async fn same_key_conflict_with(
    fault: Fault,
) -> Result<ProjectionObservation, ProjectionConformanceError> {
    let store = Arc::new(ReferenceStore::new(fault));
    let first = attempt(
        target(Arc::clone(&store)),
        Arc::new(CheckpointStore::default()),
        record(1, "event-1", b"one", SCHEMA),
    )
    .await;
    let second = attempt(
        target(Arc::clone(&store)),
        Arc::new(CheckpointStore::default()),
        record(2, "event-1", b"changed", SCHEMA),
    )
    .await;
    observation(vec![first, second], &store)
}

async fn persistent_out_of_order() -> Result<ProjectionObservation, ProjectionConformanceError> {
    persistent_out_of_order_with(Fault::None).await
}

async fn persistent_out_of_order_with(
    fault: Fault,
) -> Result<ProjectionObservation, ProjectionConformanceError> {
    let store = Arc::new(ReferenceStore::new(fault));
    let first = attempt(
        target(Arc::clone(&store)),
        Arc::new(CheckpointStore::default()),
        record(2, "event-2", b"two", SCHEMA),
    )
    .await;
    let second = attempt(
        target(Arc::clone(&store)),
        Arc::new(CheckpointStore::default()),
        record(1, "event-1", b"one", SCHEMA),
    )
    .await;
    observation(vec![first, second], &store)
}

async fn identity_mismatch() -> Result<ProjectionObservation, ProjectionConformanceError> {
    identity_mismatch_with("sha256:identity-drift").await
}

async fn identity_mismatch_with(
    schema: &str,
) -> Result<ProjectionObservation, ProjectionConformanceError> {
    let store = Arc::new(ReferenceStore::new(Fault::None));
    let result = attempt(
        target(Arc::clone(&store)),
        Arc::new(CheckpointStore::default()),
        record(1, "event-1", b"one", schema),
    )
    .await;
    observation(vec![result], &store)
}

async fn confirmed_rollback() -> Result<ProjectionObservation, ProjectionConformanceError> {
    confirmed_rollback_with(Fault::ConfirmedRollback).await
}

async fn confirmed_rollback_with(
    fault: Fault,
) -> Result<ProjectionObservation, ProjectionConformanceError> {
    let store = Arc::new(ReferenceStore::new(fault));
    let result = attempt(
        target(Arc::clone(&store)),
        Arc::new(CheckpointStore::default()),
        record(1, "event-1", b"one", SCHEMA),
    )
    .await;
    rollback_observation(vec![result], &store)
}

async fn commit_unknown_replay() -> Result<ProjectionObservation, ProjectionConformanceError> {
    commit_unknown_replay_with(Fault::CommitUnknownOnce).await
}

async fn commit_unknown_replay_with(
    fault: Fault,
) -> Result<ProjectionObservation, ProjectionConformanceError> {
    let store = Arc::new(ReferenceStore::new(fault));
    let checkpoint = Arc::new(CheckpointStore::default());
    let first = attempt(
        target(Arc::clone(&store)),
        Arc::clone(&checkpoint),
        record(1, "event-1", b"one", SCHEMA),
    )
    .await;
    let second = attempt(
        target(Arc::clone(&store)),
        checkpoint,
        record(1, "event-1", b"one", SCHEMA),
    )
    .await;
    observation(vec![first, second], &store)
}

async fn rollback_failed() -> Result<ProjectionObservation, ProjectionConformanceError> {
    rollback_failed_with(Fault::RollbackFailed).await
}

async fn rollback_failed_with(
    fault: Fault,
) -> Result<ProjectionObservation, ProjectionConformanceError> {
    let store = Arc::new(ReferenceStore::new(fault));
    let result = attempt(
        target(Arc::clone(&store)),
        Arc::new(CheckpointStore::default()),
        record(1, "event-1", b"one", SCHEMA),
    )
    .await;
    rollback_observation(vec![result], &store)
}

#[tokio::test]
async fn broken_store_fixtures_are_rejected_through_runtime_path() {
    let cases = [
        (
            testkit::projection_conformance::ProjectionCase::AtomicApply,
            atomic_apply_with(Fault::MutationWithoutReceipt).await,
        ),
        (
            testkit::projection_conformance::ProjectionCase::SameFactDuplicate,
            same_fact_duplicate_with(Fault::OrderingBeforeReceipt).await,
        ),
        (
            testkit::projection_conformance::ProjectionCase::SameKeyConflict,
            same_key_conflict_with(Fault::AcceptConflict).await,
        ),
        (
            testkit::projection_conformance::ProjectionCase::PersistentOutOfOrder,
            persistent_out_of_order_with(Fault::AcceptOutOfOrder).await,
        ),
        (
            testkit::projection_conformance::ProjectionCase::IdentityMismatch,
            identity_mismatch_with(SCHEMA).await,
        ),
        (
            testkit::projection_conformance::ProjectionCase::ConfirmedRollback,
            confirmed_rollback_with(Fault::RollbackLeaks).await,
        ),
        (
            testkit::projection_conformance::ProjectionCase::CommitUnknownReplay,
            commit_unknown_replay_with(Fault::CommitUnknownWithoutCommit).await,
        ),
        (
            testkit::projection_conformance::ProjectionCase::RollbackFailed,
            rollback_failed_with(Fault::RollbackFailedAsPermanent).await,
        ),
    ];
    for (case, observation) in cases {
        let observation = observation.expect("broken fixture must complete its runtime probe");
        assert!(
            testkit::projection_conformance::verify_projection_case(case, &observation).is_err(),
            "broken {} fixture must be rejected",
            case.as_str()
        );
    }
}

testkit::projection_target_conformance! {
    cases: {
        atomic_apply => { #[tokio::test] reference_atomic_apply => atomic_apply },
        same_fact_duplicate => { #[tokio::test] reference_same_fact_duplicate => same_fact_duplicate },
        same_key_conflict => { #[tokio::test] reference_same_key_conflict => same_key_conflict },
        persistent_out_of_order => { #[tokio::test] reference_persistent_out_of_order => persistent_out_of_order },
        identity_mismatch => { #[tokio::test] reference_identity_mismatch => identity_mismatch },
        confirmed_rollback => { #[tokio::test] reference_confirmed_rollback => confirmed_rollback },
        commit_unknown_replay => { #[tokio::test] reference_commit_unknown_replay => commit_unknown_replay },
        rollback_failed => { #[tokio::test] reference_rollback_failed => rollback_failed },
    }
}
