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
    ProjectionHarness, ProjectionPoisonPolicy, ProjectionRun, ProjectionRunnerConfig,
    ProjectionStop, WorkerHealth, projection_runner_once, spawn_projection_worker,
};
use tokio::sync::Barrier;
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
        let inserted = self
            .unique
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(lsn);
        if inserted {
            Ok(ProjectionApplyOutcome::Applied)
        } else {
            Ok(ProjectionApplyOutcome::Duplicate)
        }
    }
}

/// Barrier-gated source：两 runner 都进入 `read_from`（已读完同一 baseline）后才返回同一批事件。
/// 仅用于 multi-worker fencing 测试；现有 worker-loop 测试继续用 [`SharedProjectionSource`]。
#[derive(Clone)]
struct BarrierProjectionSource {
    events: Arc<Vec<ProjectionEventRecord>>,
    barrier: Arc<Barrier>,
}

impl BarrierProjectionSource {
    fn new(start: u64, end: u64, parties: usize) -> Self {
        Self {
            events: Arc::new((start..=end).map(record).collect()),
            barrier: Arc::new(Barrier::new(parties)),
        }
    }
}

impl PartitionSerialDelivery for BarrierProjectionSource {}

impl ProjectionEventSource for BarrierProjectionSource {
    async fn read_from(
        &self,
        after: Option<Lsn>,
        limit: ProjectionBatchLimit,
    ) -> Result<Vec<ProjectionEventRecord>, EngineError> {
        self.barrier.wait().await;
        Ok(self
            .events
            .iter()
            .filter(|event| after.is_none_or(|after| event.lsn() > after))
            .take(limit.get() as usize)
            .cloned()
            .collect())
    }
}

struct CountingDlx {
    writes: AtomicUsize,
}

impl CountingDlx {
    fn new() -> Self {
        Self {
            writes: AtomicUsize::new(0),
        }
    }

    fn write_count(&self) -> usize {
        self.writes.load(Ordering::Acquire)
    }
}

impl DeadLetterStore for CountingDlx {
    async fn write_dead_letter(
        &self,
        _record: DeadLetterRecord,
    ) -> Result<(), DeadLetterStoreError> {
        self.writes.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), DeadLetterStoreError> {
        Ok(())
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
async fn projection_workers_competing_for_same_generation_checkpoint_converge_and_fence_stale_writer()
 {
    const EVENT_END: u64 = 3;
    let projector = Arc::new(IdempotentProjector::new());
    let checkpoint = Arc::new(SharedCheckpointStore::new());
    let dlx = Arc::new(CountingDlx::new());
    let source = BarrierProjectionSource::new(1, EVENT_END, 2);
    let owner = CheckpointOwner::new("settings-meta-projection");
    let checkpoint_id = CheckpointId::new(format!(
        "tenant:{TENANT}:plan:settings-meta:target:v3:gen:1:shadow"
    ));

    let harness_a = competing_harness(
        Arc::clone(&projector),
        Arc::clone(&checkpoint),
        owner.clone(),
        checkpoint_id.clone(),
        Arc::clone(&dlx),
        &source,
    );
    let harness_b = competing_harness(
        Arc::clone(&projector),
        Arc::clone(&checkpoint),
        owner,
        checkpoint_id,
        Arc::clone(&dlx),
        &source,
    );

    let (run_a, run_b) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            projection_runner_once(&source, &harness_a, runner_config()),
            projection_runner_once(&source, &harness_b, runner_config()),
        )
    })
    .await
    .expect("competing projection runners must rendezvous and finish before timeout");

    assert_competing_stops(&run_a, &run_b);

    let expected: Vec<u64> = (1..=EVENT_END).collect();
    assert_eq!(projector.unique_lsns(), expected);
    assert_eq!(projector.attempts().len(), expected.len() * 2);

    let total_applied = run_a.applied + run_b.applied;
    let total_duplicates = run_a.duplicates + run_b.duplicates;
    assert_eq!(total_applied, expected.len());
    assert_eq!(total_duplicates, expected.len());
    assert_eq!(total_applied + total_duplicates, projector.attempts().len());

    let final_checkpoint = checkpoint
        .current()
        .expect("shared generation shadow checkpoint must converge");
    assert_eq!(final_checkpoint.offset, Lsn::new(EVENT_END));
    assert_eq!(
        final_checkpoint.version,
        CheckpointVersion::INITIAL.next(),
        "exactly one successful CAS advance; fenced stale writer must not bump version"
    );
    assert_eq!(
        dlx.write_count(),
        0,
        "fencing path must not write error DLQ"
    );
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

fn competing_harness(
    projector: Arc<IdempotentProjector>,
    checkpoint: Arc<SharedCheckpointStore>,
    owner: CheckpointOwner,
    checkpoint_id: CheckpointId,
    dlx: Arc<CountingDlx>,
    source: &BarrierProjectionSource,
) -> ProjectionHarness<IdempotentProjector, SharedCheckpointStore, CountingDlx> {
    ProjectionHarness::new(
        projector,
        checkpoint,
        owner,
        checkpoint_id,
        dlx,
        consistency::SerialInOrder::from_source(source),
    )
}

fn assert_competing_stops(run_a: &ProjectionRun, run_b: &ProjectionRun) {
    let stops = [&run_a.stop, &run_b.stop];
    let completed = stops
        .iter()
        .filter(|stop| matches!(stop, ProjectionStop::Completed))
        .count();
    let fenced = stops
        .iter()
        .filter(|stop| matches!(stop, ProjectionStop::Fenced))
        .count();
    assert_eq!(
        (completed, fenced),
        (1, 1),
        "exactly one Completed winner and one Fenced stale writer, got {stops:?}"
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
    testkit::await_map(Duration::from_secs(2), async || {
        store
            .current()
            .is_some_and(|checkpoint| checkpoint.offset == Lsn::new(expected))
            .then_some(())
    })
    .await
    .is_ok()
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
