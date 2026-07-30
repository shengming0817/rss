#![allow(clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use consistency::outbox::EventTopic;
use consistency::{
    EngineError, Lsn, PartitionSerialDelivery, ProjectionApplyError, ProjectionApplyOutcome,
    ProjectionBatchLimit, ProjectionEvent, ProjectionEventMetadata, ProjectionEventRecord,
    ProjectionEventSource, Projector,
};
use diport::{
    Checkpoint, CheckpointId, CheckpointOwner, CheckpointStoreError, CheckpointVersion,
    DeadLetterRecord, DeadLetterStore, DeadLetterStoreError, ManagedResource as _,
    OwnerCheckpointStore, SaveOutcome,
};
use eventexec::{
    ProjectionHarness, ProjectionPoisonPolicy, ProjectionRunnerConfig, WorkerHealth,
    spawn_projection_worker,
};
use tokio_util::sync::CancellationToken;

const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

#[derive(Clone)]
struct SharedProjectionSource {
    events: Arc<Vec<ProjectionEventRecord>>,
}

impl SharedProjectionSource {
    fn new(start: u64, end: u64) -> Self {
        Self {
            events: Arc::new((start..=end).map(record).collect()),
        }
    }
}

impl PartitionSerialDelivery for SharedProjectionSource {}

impl ProjectionEventSource for SharedProjectionSource {
    async fn read_from(
        &self,
        after: Option<Lsn>,
        limit: ProjectionBatchLimit,
    ) -> Result<Vec<ProjectionEventRecord>, EngineError> {
        Ok(self
            .events
            .iter()
            .filter(|event| after.is_none_or(|after| event.lsn() > after))
            .take(limit.get() as usize)
            .cloned()
            .collect())
    }
}

struct IdempotentProjector {
    unique: std::sync::Mutex<BTreeSet<u64>>,
    attempts: std::sync::Mutex<Vec<u64>>,
}

impl IdempotentProjector {
    fn new() -> Self {
        Self {
            unique: std::sync::Mutex::new(BTreeSet::new()),
            attempts: std::sync::Mutex::new(vec![]),
        }
    }

    fn unique_lsns(&self) -> Vec<u64> {
        self.unique
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .copied()
            .collect()
    }

    fn attempts(&self) -> Vec<u64> {
        self.attempts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

impl Projector for IdempotentProjector {
    async fn apply<E: ProjectionEvent>(
        &self,
        event: &E,
    ) -> Result<ProjectionApplyOutcome, ProjectionApplyError> {
        let lsn = event.lsn().get();
        self.attempts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(lsn);
        self.unique
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(lsn);
        Ok(ProjectionApplyOutcome::Applied)
    }
}

struct SharedCheckpointStore {
    state: std::sync::Mutex<Option<(Lsn, CheckpointVersion)>>,
    fail_saves_remaining: AtomicUsize,
}

impl SharedCheckpointStore {
    fn new() -> Self {
        Self {
            state: std::sync::Mutex::new(None),
            fail_saves_remaining: AtomicUsize::new(0),
        }
    }

    fn fail_first_save() -> Self {
        Self {
            fail_saves_remaining: AtomicUsize::new(1),
            ..Self::new()
        }
    }

    fn current(&self) -> Option<Checkpoint> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .map(|(offset, version)| Checkpoint { offset, version })
    }
}

#[derive(Debug, thiserror::Error)]
#[error("checkpoint unavailable")]
struct TestCheckpointError;

impl OwnerCheckpointStore for SharedCheckpointStore {
    async fn get_checkpoint(
        &self,
        _owner: &CheckpointOwner,
        _id: &CheckpointId,
    ) -> Result<Option<Checkpoint>, CheckpointStoreError> {
        Ok(self.current())
    }

    async fn save_checkpoint(
        &self,
        _owner: &CheckpointOwner,
        _id: &CheckpointId,
        offset: Lsn,
        expected: CheckpointVersion,
    ) -> Result<SaveOutcome, CheckpointStoreError> {
        if self.fail_saves_remaining.load(Ordering::Acquire) > 0 {
            self.fail_saves_remaining.fetch_sub(1, Ordering::AcqRel);
            return Err(CheckpointStoreError::new(TestCheckpointError));
        }
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        match *state {
            None if expected == CheckpointVersion::INITIAL => {
                *state = Some((offset, expected.next()));
                Ok(SaveOutcome::Saved)
            }
            Some((_, current)) if current == expected => {
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

struct NoopDlx;

impl DeadLetterStore for NoopDlx {
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

#[tokio::test(flavor = "multi_thread")]
async fn projection_worker_restart_resumes_from_checkpoint_without_reapplying_committed_prefix() {
    let projector = Arc::new(IdempotentProjector::new());
    let checkpoint = Arc::new(SharedCheckpointStore::new());
    let dlx = Arc::new(NoopDlx);

    let first_source = SharedProjectionSource::new(1, 2);
    let first_worker = spawn_test_worker(
        "projection-restart-a",
        first_source,
        Arc::clone(&projector),
        Arc::clone(&checkpoint),
        Arc::clone(&dlx),
    );
    assert!(
        wait_for_checkpoint(&checkpoint, 2).await,
        "checkpoint did not reach 2"
    );
    first_worker
        .shutdown()
        .await
        .expect("first worker shutdown");

    let second_source = SharedProjectionSource::new(1, 4);
    let second_worker = spawn_test_worker(
        "projection-restart-b",
        second_source,
        Arc::clone(&projector),
        Arc::clone(&checkpoint),
        Arc::clone(&dlx),
    );
    assert!(
        wait_for_checkpoint(&checkpoint, 4).await,
        "checkpoint did not reach 4"
    );
    second_worker
        .shutdown()
        .await
        .expect("second worker shutdown");

    assert_eq!(projector.unique_lsns(), vec![1, 2, 3, 4]);
    assert_eq!(projector.attempts(), vec![1, 2, 3, 4]);
}

#[tokio::test(flavor = "multi_thread")]
async fn projection_worker_replays_safely_after_apply_before_checkpoint_commit_failure() {
    let projector = Arc::new(IdempotentProjector::new());
    let checkpoint = Arc::new(SharedCheckpointStore::fail_first_save());
    let dlx = Arc::new(NoopDlx);
    let worker = spawn_test_worker(
        "projection-retry",
        SharedProjectionSource::new(1, 3),
        Arc::clone(&projector),
        Arc::clone(&checkpoint),
        Arc::clone(&dlx),
    );

    assert!(
        wait_for_checkpoint(&checkpoint, 3).await,
        "checkpoint did not reach 3"
    );
    worker.shutdown().await.expect("worker shutdown");

    assert_eq!(projector.unique_lsns(), vec![1, 2, 3]);
    assert!(
        projector.attempts().len() > projector.unique_lsns().len(),
        "checkpoint failure should cause at least one replay attempt"
    );
}

fn spawn_test_worker(
    name: &str,
    source: SharedProjectionSource,
    projector: Arc<IdempotentProjector>,
    checkpoint: Arc<SharedCheckpointStore>,
    dlx: Arc<NoopDlx>,
) -> eventexec::ManagedBlockingWorker {
    let harness = ProjectionHarness::new(
        projector,
        checkpoint,
        CheckpointOwner::new("test-owner"),
        CheckpointId::new("test-proj"),
        dlx,
        consistency::SerialInOrder::from_source(&source),
    );
    spawn_projection_worker(
        name.to_string(),
        source,
        harness,
        runner_config(),
        CancellationToken::new(),
        Arc::new(WorkerHealth::starting()),
    )
}

fn runner_config() -> ProjectionRunnerConfig {
    ProjectionRunnerConfig::new(
        ProjectionBatchLimit::new(10).expect("valid batch limit"),
        Duration::from_millis(100),
        ProjectionPoisonPolicy::Isolate,
    )
    .expect("valid runner config")
}

async fn wait_for_checkpoint(store: &SharedCheckpointStore, expected: u64) -> bool {
    for _ in 0..100 {
        if store
            .current()
            .is_some_and(|checkpoint| checkpoint.offset == Lsn::new(expected))
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

fn record(seq: u64) -> ProjectionEventRecord {
    ProjectionEventRecord::with_metadata(
        Lsn::new(seq),
        EventTopic::parse("proj.test").expect("valid topic"),
        vec![],
        ProjectionEventMetadata::new(
            vocab::TenantId::parse(TENANT).expect("canonical tenant"),
            format!("projection-test-event-{seq}"),
            "test",
            "test.projection-event",
            "v1",
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            serde_json::json!({ diport::KEY_TENANT_ID: TENANT }),
            None,
            None,
        ),
    )
}
