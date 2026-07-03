//! saga 执行器单测：验收三场景（journal 顺序 / 逆序补偿 / checkpoint resume）+ 补偿失败 dead-letter
//! observability（T009.1 / T009.6）+ 冻结接缝 smoke。
//!
//! `compensation_failure_logs_fields` 使用 current-thread runtime + scoped subscriber 捕获 tracing 字段，
//! 避免单进程 `cargo test` 下多个全局 subscriber 竞争。

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use super::{
    SagaAction, SagaActionCtx, SagaActionError, SagaActionFactory, SagaCommand, SagaExecStatus,
    SagaExecutor, SagaExecutorConfig, SagaExecutorDeps, SagaExecutorImpl, SagaOutcome, SagaTailer,
};
use consistency::{Lsn, SagaJournalAppendRecord, SagaJournalRecord, SagaJournalStatus, StepName};
use consistency::{
    SagaId, SagaInstanceRecord, SagaInstanceRef, SagaInstanceStatus, SagaInterruption,
    SagaJournalAppendOutcome, SagaLease, SagaLeaseOutcome,
};
use diport::{
    Checkpoint, CheckpointId, CheckpointOwner, CheckpointStoreError, CheckpointVersion,
    DeadLetterRecord, DeadLetterStore, DeadLetterStoreError, OwnerCheckpointStore,
    SagaInstanceRegistration, SagaInstanceStore, SagaInstanceStoreError, SagaJournal,
    SagaJournalError, SaveOutcome,
};
use futures::future::BoxFuture;
use std::sync::Arc;

const OWNER: &str = "billing";
const CONTRACT: &str = "billing.checkout";
const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

#[allow(clippy::unwrap_used)]
fn tenant() -> vocab::TenantId {
    vocab::TenantId::parse(TENANT).unwrap()
}

fn saga_id() -> SagaId {
    SagaId::new(uuid::Uuid::from_u128(0x1121))
}

#[allow(clippy::unwrap_used)]
fn instance() -> SagaInstanceRef {
    SagaInstanceRef::new(tenant(), saga_id()).unwrap()
}

fn checkpoint_id_str() -> String {
    format!("{}:{}", TENANT, saga_id().as_uuid())
}

// ── FakeAction ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct FakeAction {
    name: String,
    do_count: Arc<AtomicU32>,
    undo_count: Arc<AtomicU32>,
    do_fails: bool,
    undo_fails: bool,
}

impl SagaAction for FakeAction {
    fn name(&self) -> &str {
        &self.name
    }
    fn do_it(&self, _ctx: SagaActionCtx) -> BoxFuture<'static, Result<Vec<u8>, SagaActionError>> {
        let count = self.do_count.clone();
        let fails = self.do_fails;
        let name = self.name.clone();
        Box::pin(async move {
            count.fetch_add(1, Ordering::SeqCst);
            if fails {
                Err(SagaActionError::ActionFailed)
            } else {
                Ok(format!("{name}-out").into_bytes())
            }
        })
    }
    fn undo_it(&self, _ctx: SagaActionCtx) -> BoxFuture<'static, Result<(), SagaActionError>> {
        let count = self.undo_count.clone();
        let fails = self.undo_fails;
        Box::pin(async move {
            count.fetch_add(1, Ordering::SeqCst);
            if fails {
                Err(SagaActionError::ActionFailed)
            } else {
                Ok(())
            }
        })
    }
}

/// 计数器句柄（测试持，断言调用次数）。
#[derive(Clone)]
struct Counts {
    do_count: Arc<AtomicU32>,
    undo_count: Arc<AtomicU32>,
}

impl Counts {
    fn dos(&self) -> u32 {
        self.do_count.load(Ordering::SeqCst)
    }
    fn undos(&self) -> u32 {
        self.undo_count.load(Ordering::SeqCst)
    }
}

// ── FakeFactory（resume 重物化 action 序，counters 与测试共享）────────────────────

struct StepSpec {
    name: String,
    do_fails: bool,
    undo_fails: bool,
    counts: Counts,
}

struct FakeFactory {
    steps: Vec<StepSpec>,
}

impl FakeFactory {
    fn linear(names: &[&str]) -> (Arc<Self>, Vec<Counts>) {
        let specs = names
            .iter()
            .map(|name| (*name, false, false))
            .collect::<Vec<_>>();
        Self::steps(&specs)
    }

    fn steps(specs: &[(&str, bool, bool)]) -> (Arc<Self>, Vec<Counts>) {
        let mut steps = Vec::new();
        let mut counts = Vec::new();
        for (name, do_fails, undo_fails) in specs {
            let c = Counts {
                do_count: Arc::new(AtomicU32::new(0)),
                undo_count: Arc::new(AtomicU32::new(0)),
            };
            counts.push(c.clone());
            steps.push(StepSpec {
                name: (*name).to_string(),
                do_fails: *do_fails,
                undo_fails: *undo_fails,
                counts: c,
            });
        }
        (Arc::new(Self { steps }), counts)
    }
}

impl SagaActionFactory for FakeFactory {
    fn build(&self) -> Vec<Box<dyn SagaAction>> {
        self.steps
            .iter()
            .map(|s| {
                Box::new(FakeAction {
                    name: s.name.clone(),
                    do_count: s.counts.do_count.clone(),
                    undo_count: s.counts.undo_count.clone(),
                    do_fails: s.do_fails,
                    undo_fails: s.undo_fails,
                }) as Box<dyn SagaAction>
            })
            .collect()
    }
}

// ── FakeJournal ───────────────────────────────────────────────────────────────

#[derive(Default)]
struct FakeJournal {
    rows: Mutex<Vec<(SagaInstanceRef, SagaJournalAppendRecord)>>,
}

impl FakeJournal {
    #[allow(clippy::unwrap_used)] // reason: 测试 Mutex，item-level carve-out
    fn seed(&self, seq: u64, step: &str, status: SagaJournalStatus) {
        let step = StepName::parse(step).unwrap();
        let entry = match status {
            SagaJournalStatus::Executing => SagaJournalAppendRecord::executing(seq, step),
            SagaJournalStatus::Completed => SagaJournalAppendRecord::completed(seq, step),
            SagaJournalStatus::Compensating => SagaJournalAppendRecord::compensating(seq, step),
            SagaJournalStatus::Compensated => SagaJournalAppendRecord::compensated(seq, step),
            SagaJournalStatus::Failed => SagaJournalAppendRecord::failed(seq, step, "failed"),
            _ => unreachable!("test only seeds known journal statuses"),
        };
        self.rows.lock().unwrap().push((instance(), entry));
    }
    /// seq 序的 (step_name, status)，供顺序断言。
    #[allow(clippy::unwrap_used)] // reason: 测试 Mutex，item-level carve-out
    fn log(&self) -> Vec<(String, SagaJournalStatus)> {
        let mut rows: Vec<_> = self.rows.lock().unwrap().clone();
        rows.sort_by_key(|(_, entry)| entry.seq());
        rows.into_iter()
            .map(|(_, entry)| (entry.step_name().as_str().to_string(), entry.status()))
            .collect()
    }
}

impl SagaJournal for FakeJournal {
    #[allow(clippy::unwrap_used)] // reason: 测试 Mutex，item-level carve-out
    async fn append(
        &self,
        lease: &SagaLease,
        entry: SagaJournalAppendRecord,
    ) -> Result<SagaJournalAppendOutcome, SagaJournalError> {
        let mut rows = self.rows.lock().unwrap();
        let instance = lease.instance();
        let key = (instance, entry.seq());
        if let Some((_, existing)) = rows
            .iter()
            .find(|(stored, record)| (*stored, record.seq()) == key)
        {
            return if *existing == entry {
                Ok(SagaJournalAppendOutcome::IdempotentDuplicate)
            } else {
                Ok(SagaJournalAppendOutcome::AppendConflict)
            };
        }
        rows.push((instance, entry));
        Ok(SagaJournalAppendOutcome::Appended)
    }
    #[allow(clippy::unwrap_used)] // reason: 测试 Mutex + 字面 step 名合法，item-level carve-out
    async fn read(
        &self,
        instance: &SagaInstanceRef,
    ) -> Result<Vec<SagaJournalRecord>, SagaJournalError> {
        let mut rows: Vec<_> = self
            .rows
            .lock()
            .unwrap()
            .iter()
            .filter(|r| &r.0 == instance)
            .cloned()
            .collect();
        rows.sort_by_key(|(_, entry)| entry.seq());
        let entries = rows
            .into_iter()
            .map(|(_, entry)| {
                SagaJournalRecord::replayed(entry.seq(), entry.step_name().clone(), entry.status())
            })
            .collect();
        Ok(entries)
    }
    async fn shutdown(&self) -> Result<(), SagaJournalError> {
        Ok(())
    }
}

// ── FakeCheckpointStore（CAS）─────────────────────────────────────────────────

#[derive(Default)]
struct FakeCheckpointStore {
    map: Mutex<HashMap<(String, String), (Lsn, CheckpointVersion)>>,
    /// F2 测试注入：true ⇒ `save_checkpoint` 恒返 `StaleVersion`（模拟并发执行器 fence）。
    force_stale: std::sync::atomic::AtomicBool,
}

impl FakeCheckpointStore {
    fn fence(&self) {
        self.force_stale.store(true, Ordering::SeqCst);
    }
    #[allow(clippy::unwrap_used)] // reason: 测试 Mutex，item-level carve-out
    fn seed(&self, id: &str, offset: u64, version: u64) {
        self.map.lock().unwrap().insert(
            (OWNER.to_string(), id.to_string()),
            (Lsn::new(offset), CheckpointVersion::new(version)),
        );
    }
    #[allow(clippy::unwrap_used)] // reason: 测试 Mutex，item-level carve-out
    fn offset(&self, id: &str) -> Option<u64> {
        self.map
            .lock()
            .unwrap()
            .get(&(OWNER.to_string(), id.to_string()))
            .map(|(o, _)| o.get())
    }
}

impl OwnerCheckpointStore for FakeCheckpointStore {
    #[allow(clippy::unwrap_used)] // reason: 测试 Mutex，item-level carve-out
    async fn get_checkpoint(
        &self,
        owner: &CheckpointOwner,
        id: &CheckpointId,
    ) -> Result<Option<Checkpoint>, CheckpointStoreError> {
        let m = self.map.lock().unwrap();
        Ok(
            m.get(&(owner.as_str().to_string(), id.as_str().to_string()))
                .map(|(o, v)| Checkpoint {
                    offset: *o,
                    version: *v,
                }),
        )
    }
    #[allow(clippy::unwrap_used)] // reason: 测试 Mutex，item-level carve-out
    async fn save_checkpoint(
        &self,
        owner: &CheckpointOwner,
        id: &CheckpointId,
        offset: Lsn,
        expected: CheckpointVersion,
    ) -> Result<SaveOutcome, CheckpointStoreError> {
        if self.force_stale.load(Ordering::SeqCst) {
            return Ok(SaveOutcome::StaleVersion);
        }
        let mut m = self.map.lock().unwrap();
        let key = (owner.as_str().to_string(), id.as_str().to_string());
        let outcome = match m.get(&key) {
            None if expected == CheckpointVersion::INITIAL => {
                m.insert(key, (offset, CheckpointVersion::new(1)));
                SaveOutcome::Saved
            }
            None => SaveOutcome::StaleVersion,
            Some((_, v)) if *v == expected => {
                m.insert(key, (offset, expected.next()));
                SaveOutcome::Saved
            }
            Some(_) => SaveOutcome::StaleVersion,
        };
        Ok(outcome)
    }
    async fn shutdown(&self) -> Result<(), CheckpointStoreError> {
        Ok(())
    }
}

// ── FakeDeadLetterStore ───────────────────────────────────────────────────────

/// 捕获的 DLX 记录字段：(tenant_id, message_id, domain, contract_id, topic, payload, error_summary, num_attempts)。
type DlxRecord = (String, String, String, String, String, String, String, u32);

#[derive(Default)]
struct FakeDeadLetterStore {
    written: Mutex<Vec<DlxRecord>>,
}

impl FakeDeadLetterStore {
    #[allow(clippy::unwrap_used)] // reason: 测试 Mutex，item-level carve-out
    fn records(&self) -> Vec<DlxRecord> {
        self.written.lock().unwrap().clone()
    }
}

impl DeadLetterStore for FakeDeadLetterStore {
    #[allow(clippy::unwrap_used)] // reason: 测试 Mutex，item-level carve-out
    async fn write_dead_letter(
        &self,
        record: DeadLetterRecord,
    ) -> Result<(), DeadLetterStoreError> {
        self.written.lock().unwrap().push((
            record.tenant().to_string(),
            record.message_id().to_string(),
            record.domain().to_string(),
            record.contract_id().to_string(),
            record.topic().to_string(),
            String::from_utf8_lossy(record.original_payload()).to_string(),
            record.error_summary().to_string(),
            record.num_attempts(),
        ));
        Ok(())
    }
    async fn shutdown(&self) -> Result<(), DeadLetterStoreError> {
        Ok(())
    }
}

// ── FakeInstanceStore（lease/CAS）──────────────────────────────────────────────

#[derive(Default)]
struct FakeInstanceStore {
    registered: Mutex<HashMap<SagaInstanceRef, SagaInstanceStatus>>,
    lease_lost: std::sync::atomic::AtomicBool,
    releases: AtomicU32,
}

impl FakeInstanceStore {
    fn lose_lease(&self) {
        self.lease_lost.store(true, Ordering::SeqCst);
    }

    #[allow(clippy::unwrap_used)]
    fn seed_status(&self, instance: SagaInstanceRef, status: SagaInstanceStatus) {
        self.registered.lock().unwrap().insert(instance, status);
    }

    #[allow(clippy::unwrap_used)]
    fn status(&self, instance: SagaInstanceRef) -> Option<SagaInstanceStatus> {
        self.registered.lock().unwrap().get(&instance).copied()
    }

    fn release_count(&self) -> u32 {
        self.releases.load(Ordering::SeqCst)
    }
}

impl SagaInstanceStore for FakeInstanceStore {
    #[allow(clippy::unwrap_used)]
    async fn register(
        &self,
        registration: SagaInstanceRegistration,
    ) -> Result<SagaInstanceRecord, SagaInstanceStoreError> {
        let mut rows = self.registered.lock().unwrap();
        let status = *rows
            .entry(registration.instance())
            .or_insert(SagaInstanceStatus::Ready);
        Ok(SagaInstanceRecord::new(registration.instance(), status))
    }

    #[allow(clippy::unwrap_used)]
    async fn get(
        &self,
        instance: &SagaInstanceRef,
    ) -> Result<Option<SagaInstanceRecord>, SagaInstanceStoreError> {
        Ok(self
            .registered
            .lock()
            .unwrap()
            .get(instance)
            .copied()
            .map(|status| SagaInstanceRecord::new(*instance, status)))
    }

    #[allow(clippy::unwrap_used)]
    async fn acquire_lease(
        &self,
        instance: &SagaInstanceRef,
        holder_id: &str,
        _ttl: Duration,
    ) -> Result<Option<SagaLease>, SagaInstanceStoreError> {
        if self.lease_lost.load(Ordering::SeqCst) {
            return Ok(None);
        }
        let mut rows = self.registered.lock().unwrap();
        let Some(status) = rows.get_mut(instance) else {
            return Ok(None);
        };
        *status = SagaInstanceStatus::Running;
        SagaLease::new(*instance, holder_id, uuid::Uuid::from_u128(1632), 1)
            .map(Some)
            .map_err(SagaInstanceStoreError::new)
    }

    async fn extend_lease(
        &self,
        _lease: &SagaLease,
        _ttl: Duration,
    ) -> Result<SagaLeaseOutcome, SagaInstanceStoreError> {
        if self.lease_lost.load(Ordering::SeqCst) {
            Ok(SagaLeaseOutcome::Lost)
        } else {
            Ok(SagaLeaseOutcome::Held)
        }
    }

    async fn release_lease(
        &self,
        _lease: &SagaLease,
    ) -> Result<SagaLeaseOutcome, SagaInstanceStoreError> {
        self.releases.fetch_add(1, Ordering::SeqCst);
        Ok(SagaLeaseOutcome::Held)
    }

    #[allow(clippy::unwrap_used)]
    async fn mark_status(
        &self,
        lease: &SagaLease,
        status: SagaInstanceStatus,
    ) -> Result<SagaLeaseOutcome, SagaInstanceStoreError> {
        self.registered
            .lock()
            .unwrap()
            .insert(lease.instance(), status);
        Ok(SagaLeaseOutcome::Held)
    }

    async fn shutdown(&self) -> Result<(), SagaInstanceStoreError> {
        Ok(())
    }
}

// ── executor 构造 helper ──────────────────────────────────────────────────────

type Exec =
    SagaExecutorImpl<FakeJournal, FakeCheckpointStore, FakeDeadLetterStore, FakeInstanceStore>;

fn executor_config() -> SagaExecutorConfig {
    SagaExecutorConfig::new(
        CheckpointOwner::new(OWNER),
        CONTRACT,
        "runner-a",
        Duration::from_secs(30),
    )
}

fn ready_instance_store() -> Arc<FakeInstanceStore> {
    let store = Arc::new(FakeInstanceStore::default());
    store.seed_status(instance(), SagaInstanceStatus::Ready);
    store
}

fn executor_with_store<J>(
    journal: Arc<J>,
    instance_store: Arc<FakeInstanceStore>,
    cp: Arc<FakeCheckpointStore>,
    dlx: Arc<FakeDeadLetterStore>,
    factory: Arc<dyn SagaActionFactory>,
) -> SagaExecutorImpl<J, FakeCheckpointStore, FakeDeadLetterStore, FakeInstanceStore>
where
    J: SagaJournal + Send + Sync + 'static,
{
    SagaExecutorImpl::new(
        SagaExecutorDeps::new(journal, instance_store, cp, dlx, factory),
        executor_config(),
    )
}

fn executor(
    journal: Arc<FakeJournal>,
    cp: Arc<FakeCheckpointStore>,
    dlx: Arc<FakeDeadLetterStore>,
    factory: Arc<dyn SagaActionFactory>,
) -> Exec {
    executor_with_store(journal, ready_instance_store(), cp, dlx, factory)
}

// ── FakeJournalFailing（append 注入失败）──────────────────────────────────────────

use std::sync::atomic::AtomicBool;

/// append 可注入失败的 journal（测试 best-effort 降级语义）。
struct FakeJournalFailing {
    inner: FakeJournal,
    append_fails: AtomicBool,
    read_fails: AtomicBool,
    fail_status: Option<SagaJournalStatus>,
    conflict_status: Option<SagaJournalStatus>,
}

impl FakeJournalFailing {
    fn new(fail: bool) -> Self {
        Self {
            inner: FakeJournal::default(),
            append_fails: AtomicBool::new(fail),
            read_fails: AtomicBool::new(false),
            fail_status: None,
            conflict_status: None,
        }
    }

    fn read_failing() -> Self {
        Self {
            inner: FakeJournal::default(),
            append_fails: AtomicBool::new(false),
            read_fails: AtomicBool::new(true),
            fail_status: None,
            conflict_status: None,
        }
    }

    fn fail_on_status(status: SagaJournalStatus) -> Self {
        Self {
            inner: FakeJournal::default(),
            append_fails: AtomicBool::new(false),
            read_fails: AtomicBool::new(false),
            fail_status: Some(status),
            conflict_status: None,
        }
    }

    fn conflict_on_status(status: SagaJournalStatus) -> Self {
        Self {
            inner: FakeJournal::default(),
            append_fails: AtomicBool::new(false),
            read_fails: AtomicBool::new(false),
            fail_status: None,
            conflict_status: Some(status),
        }
    }

    fn log(&self) -> Vec<(String, SagaJournalStatus)> {
        self.inner.log()
    }
}

impl SagaJournal for FakeJournalFailing {
    async fn append(
        &self,
        lease: &SagaLease,
        entry: SagaJournalAppendRecord,
    ) -> Result<SagaJournalAppendOutcome, SagaJournalError> {
        if self.append_fails.load(Ordering::SeqCst) || self.fail_status == Some(entry.status()) {
            Err(SagaJournalError::new(std::io::Error::other("inject")))
        } else if self.conflict_status == Some(entry.status()) {
            Ok(SagaJournalAppendOutcome::AppendConflict)
        } else {
            self.inner.append(lease, entry).await
        }
    }
    async fn read(
        &self,
        instance: &SagaInstanceRef,
    ) -> Result<Vec<SagaJournalRecord>, SagaJournalError> {
        if self.read_fails.load(Ordering::SeqCst) {
            return Err(SagaJournalError::new(std::io::Error::other("read inject")));
        }
        self.inner.read(instance).await
    }
    async fn shutdown(&self) -> Result<(), SagaJournalError> {
        Ok(())
    }
}

// ── T009.1 #1：3-step 全成 → journal 顺序 ──────────────────────────────────────

#[tokio::test]
async fn run_three_steps_all_succeed_journal_order() {
    let journal = Arc::new(FakeJournal::default());
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, counts) = FakeFactory::linear(&["step1", "step2", "step3"]);
    let exec = executor(journal.clone(), cp.clone(), dlx.clone(), factory);

    let outcome = exec.run(instance()).await;

    assert!(
        matches!(outcome, SagaOutcome::Succeeded { .. }),
        "{outcome:?}"
    );
    use SagaJournalStatus::{Completed, Executing};
    assert_eq!(
        journal.log(),
        vec![
            ("step1".to_string(), Executing),
            ("step1".to_string(), Completed),
            ("step2".to_string(), Executing),
            ("step2".to_string(), Completed),
            ("step3".to_string(), Executing),
            ("step3".to_string(), Completed),
        ]
    );
    // checkpoint 推进到已完成 3 步。
    assert_eq!(cp.offset(&checkpoint_id_str()), Some(3));
    assert_eq!(
        (counts[0].dos(), counts[1].dos(), counts[2].dos()),
        (1, 1, 1)
    );
    assert_eq!(
        (counts[0].undos(), counts[1].undos(), counts[2].undos()),
        (0, 0, 0)
    );
    assert!(dlx.records().is_empty());
}

// ── T009.1 #2：step2 失败 → 逆序补偿 step1（step2 未完成不补偿）────────────────

#[tokio::test]
#[allow(clippy::panic)] // reason: 测试断言分支，item-level carve-out
async fn step2_failure_reverse_compensates_step1_only() {
    let journal = Arc::new(FakeJournal::default());
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, counts) = FakeFactory::steps(&[
        ("step1", false, false),
        ("step2", true, false),
        ("step3", false, false),
    ]);
    let exec = executor(journal.clone(), cp.clone(), dlx.clone(), factory);

    let outcome = exec.run(instance()).await;

    match outcome {
        SagaOutcome::Failed { failed_node, .. } => assert_eq!(failed_node, "step2"),
        other => panic!("expected Failed, got {other:?}"),
    }
    use SagaJournalStatus::{Compensated, Compensating, Completed, Executing};
    assert_eq!(
        journal.log(),
        vec![
            ("step1".to_string(), Executing),
            ("step1".to_string(), Completed),
            ("step2".to_string(), Executing),
            ("step1".to_string(), Compensating),
            ("step1".to_string(), Compensated),
        ]
    );
    // anti-vacuity：step2 未完成 → 无 Compensating 行；step3 从未跑。
    assert!(
        !journal
            .log()
            .iter()
            .any(|(n, s)| n == "step2" && *s == Compensating),
        "step2 失败步不应被补偿"
    );
    assert_eq!(
        (counts[0].dos(), counts[1].dos(), counts[2].dos()),
        (1, 1, 0)
    );
    assert_eq!(
        (counts[0].undos(), counts[1].undos(), counts[2].undos()),
        (1, 0, 0)
    );
}

// ── T009.1 #3：从 step2 checkpoint resume → 跳过 step1 ──────────────────────────

#[tokio::test]
async fn resume_from_step2_checkpoint_skips_step1() {
    let journal = Arc::new(FakeJournal::default());
    journal.seed(0, "step1", SagaJournalStatus::Executing);
    journal.seed(1, "step1", SagaJournalStatus::Completed);
    let cp = Arc::new(FakeCheckpointStore::default());
    cp.seed(&checkpoint_id_str(), 1, 1);
    let dlx = Arc::new(FakeDeadLetterStore::default());

    let (factory, counts) = FakeFactory::linear(&["step1", "step2", "step3"]);
    let exec = executor(journal.clone(), cp.clone(), dlx.clone(), factory);

    let outcome = exec.resume(instance()).await;

    assert!(
        matches!(outcome, SagaOutcome::Succeeded { .. }),
        "{outcome:?}"
    );
    // step1 不再执行（已完成）；step2/step3 续跑。
    assert_eq!(counts[0].dos(), 0, "step1 应被跳过");
    assert_eq!(counts[1].dos(), 1, "step2 应续跑");
    assert_eq!(counts[2].dos(), 1, "step3 应续跑");
    // 续跑后 journal 含 step2/step3 完成，checkpoint 推进到 3。
    use SagaJournalStatus::Completed;
    let log = journal.log();
    assert!(log.contains(&("step2".to_string(), Completed)));
    assert!(log.contains(&("step3".to_string(), Completed)));
    assert_eq!(cp.offset(&checkpoint_id_str()), Some(3));
}

// ── T009.6：补偿失败 → 写 dead-letter（domain/contract_id 取 saga owner）─────────

#[tokio::test]
#[allow(clippy::panic)] // reason: 测试断言分支，item-level carve-out
async fn compensation_failure_writes_dead_letter() {
    let journal = Arc::new(FakeJournal::default());
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, _counts) = FakeFactory::steps(&[("step1", false, true), ("step2", true, false)]);
    let exec = executor(journal.clone(), cp.clone(), dlx.clone(), factory);
    // step1 do ok / undo FAILS；step2 do FAILS → 触发对 step1 的补偿，补偿失败 → dead-letter。

    let outcome = exec.run(instance()).await;

    match outcome {
        // failed_node = 补偿失败的步（step1），非原始前向失败步（step2）——见 compensate() 语义。
        SagaOutcome::Failed { failed_node, .. } => assert_eq!(failed_node, "step1"),
        other => panic!("expected Failed, got {other:?}"),
    }
    let records = dlx.records();
    assert_eq!(records.len(), 1, "应写恰一条 dead-letter");
    let (tenant_id, message_id, domain, contract_id, topic, payload, summary, attempts) =
        &records[0];
    assert_eq!(tenant_id, TENANT, "DLX tenant_id = executor tenant");
    assert_eq!(
        message_id,
        &saga_id().as_uuid().to_string(),
        "DLX message_id = saga_id"
    );
    assert_eq!(domain, OWNER, "DLX domain = saga owner（SC-006）");
    assert_eq!(
        contract_id, CONTRACT,
        "DLX contract_id = saga 契约（SC-006）"
    );
    // F5：topic = saga_id；payload 携原始前向失败步(step2) + 补偿失败步(step1)，诊断闭环。
    assert_eq!(
        topic,
        &saga_id().as_uuid().to_string(),
        "DLX topic = saga_id"
    );
    assert!(payload.contains("step2"), "payload 缺前向失败步: {payload}");
    assert!(payload.contains("step1"), "payload 缺补偿失败步: {payload}");
    assert!(
        payload.contains(&saga_id().as_uuid().to_string()),
        "payload 缺 saga_id: {payload}"
    );
    assert!(!summary.is_empty(), "error_summary 非空");
    assert_eq!(*attempts, 1);
    // journal 末尾有 step1 Failed 行（durable 审计）。
    assert!(
        journal
            .log()
            .iter()
            .any(|(n, s)| n == "step1" && *s == SagaJournalStatus::Failed),
        "journal 缺 step1 Failed 审计行"
    );
}

// ── resume 已注册但空 journal → 从 step0 继续（unknown 只由实例行缺失表达）──────────────

#[tokio::test]
#[allow(clippy::panic)] // reason: 测试断言分支，item-level carve-out
async fn resume_ready_instance_with_empty_journal_runs_from_step_zero() {
    let journal = Arc::new(FakeJournal::default());
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, counts) = FakeFactory::linear(&["step1", "step2"]);
    // executor(...) seed Ready 实例行；空 journal 表示 first append 前崩溃，不是 unknown saga。
    let exec = executor(journal.clone(), cp, dlx, factory);

    let outcome = exec.resume(instance()).await;

    assert!(
        matches!(outcome, SagaOutcome::Succeeded { .. }),
        "registered saga with empty journal should resume from step0: {outcome:?}"
    );
    assert_eq!(
        counts[0].dos(),
        1,
        "step1 should run on empty-journal resume"
    );
    assert_eq!(
        counts[1].dos(),
        1,
        "step2 should run on empty-journal resume"
    );
    assert_eq!(
        journal.log(),
        vec![
            ("step1".to_string(), SagaJournalStatus::Executing),
            ("step1".to_string(), SagaJournalStatus::Completed),
            ("step2".to_string(), SagaJournalStatus::Executing),
            ("step2".to_string(), SagaJournalStatus::Completed),
        ]
    );
}

// ── F1：Executing journal append 失败 → fail-closed（不执行副作用）─────────────────

#[tokio::test]
async fn run_with_executing_append_failure_fails_closed() {
    // F1：journal 写是执行状态机一等边。Executing append 失败 ⇒ do_it **不执行**、返回 Failed
    // （无 journal 无法 durable 恢复，副作用不能在无记录下发生）。修正原 best-effort 误设计。
    let journal = Arc::new(FakeJournalFailing::new(true));
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, counts) = FakeFactory::linear(&["step1", "step2"]);

    let exec = executor_with_store(
        journal,
        Arc::new(FakeInstanceStore::default()),
        cp,
        dlx,
        factory,
    );

    let outcome = exec.run(instance()).await;

    assert!(
        matches!(outcome, SagaOutcome::Failed { .. }),
        "Executing append 失败必 fail-closed: {outcome:?}"
    );
    // 副作用从未发生：step1.do_it 未被调用。
    assert_eq!(counts[0].dos(), 0, "step1.do_it 不应执行（fail-closed）");
    assert_eq!(counts[1].dos(), 0, "step2 从未到达");
}

#[tokio::test]
async fn run_returns_interrupted_when_lease_busy() {
    let journal = Arc::new(FakeJournal::default());
    let instance_store = Arc::new(FakeInstanceStore::default());
    instance_store.lose_lease();
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, counts) = FakeFactory::linear(&["step1"]);
    let exec = executor_with_store(journal, instance_store, cp, dlx, factory);

    let outcome = exec.run(instance()).await;

    assert!(
        matches!(
            outcome,
            SagaOutcome::Interrupted {
                reason: SagaInterruption::LeaseBusy
            }
        ),
        "busy lease must not be a business failure: {outcome:?}"
    );
    assert_eq!(counts[0].dos(), 0, "action must not run without lease");
}

#[tokio::test]
async fn run_terminal_releases_lease_and_rejects_restart() {
    let journal = Arc::new(FakeJournal::default());
    let store = ready_instance_store();
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, counts) = FakeFactory::linear(&["step1"]);
    let exec = executor_with_store(journal, store.clone(), cp, dlx, factory);

    let outcome = exec.run(instance()).await;
    assert!(
        matches!(outcome, SagaOutcome::Succeeded { .. }),
        "{outcome:?}"
    );
    assert_eq!(
        store.status(instance()),
        Some(SagaInstanceStatus::Succeeded)
    );
    assert_eq!(
        store.release_count(),
        1,
        "terminal success must release lease"
    );

    let resumed = exec.resume(instance()).await;
    assert!(
        matches!(resumed, SagaOutcome::Succeeded { .. }),
        "terminal resume should not wait for old TTL: {resumed:?}"
    );
    let restarted = exec.run(instance()).await;
    assert!(
        matches!(
            restarted,
            SagaOutcome::Interrupted {
                reason: SagaInterruption::AlreadyStarted
            }
        ),
        "run must not restart terminal instance: {restarted:?}"
    );
    assert_eq!(counts[0].dos(), 1, "terminal run must not redo action");
}

#[tokio::test]
async fn resume_unknown_instance_does_not_register() {
    let journal = Arc::new(FakeJournal::default());
    let store = Arc::new(FakeInstanceStore::default());
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, _counts) = FakeFactory::linear(&["step1"]);
    let exec = executor_with_store(journal, store.clone(), cp, dlx, factory);

    let outcome = exec.resume(instance()).await;

    assert!(matches!(outcome, SagaOutcome::Failed { .. }), "{outcome:?}");
    assert_eq!(
        store.status(instance()),
        None,
        "resume of unknown instance must not create saga_instances row"
    );
}

#[tokio::test]
async fn executing_append_conflict_interrupts_and_marks_degraded() {
    let journal = Arc::new(FakeJournalFailing::conflict_on_status(
        SagaJournalStatus::Executing,
    ));
    let store = ready_instance_store();
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, counts) = FakeFactory::linear(&["step1"]);
    let exec = executor_with_store(journal, store.clone(), cp, dlx, factory);

    let outcome = exec.run(instance()).await;

    assert!(
        matches!(
            outcome,
            SagaOutcome::Interrupted {
                reason: SagaInterruption::JournalConflict
            }
        ),
        "append conflict must be non-business interruption: {outcome:?}"
    );
    assert_eq!(
        counts[0].dos(),
        0,
        "action must not run after Executing conflict"
    );
    assert_eq!(store.status(instance()), Some(SagaInstanceStatus::Degraded));
    assert_eq!(
        store.release_count(),
        1,
        "degraded instance must release lease"
    );
}

#[tokio::test]
async fn resume_append_conflict_interrupts_and_marks_degraded() {
    let journal = Arc::new(FakeJournalFailing::conflict_on_status(
        SagaJournalStatus::Executing,
    ));
    journal.inner.seed(0, "step1", SagaJournalStatus::Completed);
    let store = ready_instance_store();
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, counts) = FakeFactory::linear(&["step1", "step2"]);
    let exec = executor_with_store(journal, store.clone(), cp, dlx, factory);

    let outcome = exec.resume(instance()).await;

    assert!(
        matches!(
            outcome,
            SagaOutcome::Interrupted {
                reason: SagaInterruption::JournalConflict
            }
        ),
        "resume append conflict must be non-business interruption: {outcome:?}"
    );
    assert_eq!(counts[0].dos(), 0, "completed step must stay skipped");
    assert_eq!(
        counts[1].dos(),
        0,
        "step2 must not run after Executing conflict"
    );
    assert_eq!(store.status(instance()), Some(SagaInstanceStatus::Degraded));
}

#[tokio::test]
async fn run_with_completed_append_failure_compensates_current_step() {
    let journal = Arc::new(FakeJournalFailing::fail_on_status(
        SagaJournalStatus::Completed,
    ));
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, counts) = FakeFactory::linear(&["step1", "step2"]);

    let exec = executor_with_store(
        journal.clone(),
        Arc::new(FakeInstanceStore::default()),
        cp,
        dlx.clone(),
        factory,
    );

    let outcome = exec.run(instance()).await;

    assert!(
        matches!(outcome, SagaOutcome::Failed { .. }),
        "Completed append 失败须进入补偿: {outcome:?}"
    );
    assert_eq!(counts[0].dos(), 1, "step1 副作用已发生");
    assert_eq!(
        counts[0].undos(),
        1,
        "step1 Completed append 失败后须补偿当前步"
    );
    assert_eq!(counts[1].dos(), 0, "step2 不应继续执行");
    assert!(
        !journal
            .log()
            .contains(&("step1".to_string(), SagaJournalStatus::Completed)),
        "Completed append 被注入失败，不应落入 journal"
    );
    assert!(
        journal
            .log()
            .contains(&("step1".to_string(), SagaJournalStatus::Compensated)),
        "补偿完成应落 journal"
    );

    let (factory, replay_counts) = FakeFactory::linear(&["step1", "step2"]);
    let resume_exec = executor_with_store(
        journal.clone(),
        ready_instance_store(),
        Arc::new(FakeCheckpointStore::default()),
        Arc::new(FakeDeadLetterStore::default()),
        factory,
    );
    assert_eq!(
        resume_exec.status(instance()).await,
        Some(SagaExecStatus::Done),
        "Executing -> Compensated journal must replay as terminal compensated"
    );
    let replay_outcome = resume_exec.resume(instance()).await;
    assert!(
        matches!(replay_outcome, SagaOutcome::Failed { .. }),
        "compensated saga resumes as terminal failed outcome: {replay_outcome:?}"
    );
    assert_eq!(replay_counts[0].dos(), 0, "terminal resume must not redo");
    assert_eq!(
        replay_counts[0].undos(),
        0,
        "terminal resume must not re-undo"
    );
    assert!(
        dlx.records().is_empty(),
        "terminal resume must not write DLX"
    );
}

#[tokio::test]
async fn run_with_compensating_append_failure_stops_before_undo() {
    let journal = Arc::new(FakeJournalFailing::fail_on_status(
        SagaJournalStatus::Compensating,
    ));
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, counts) = FakeFactory::steps(&[("step1", false, false), ("step2", true, false)]);
    let exec = executor_with_store(
        journal.clone(),
        Arc::new(FakeInstanceStore::default()),
        cp,
        dlx.clone(),
        factory,
    );

    let outcome = exec.run(instance()).await;

    assert!(
        matches!(outcome, SagaOutcome::Failed { .. }),
        "Compensating append 失败须 fail-closed: {outcome:?}"
    );
    assert_eq!(
        counts[0].undos(),
        0,
        "undo 不应在 Compensating 未落库时执行"
    );
    assert!(
        !journal
            .log()
            .iter()
            .any(|(_, status)| *status == SagaJournalStatus::Compensating),
        "Compensating append 被注入失败，不应落入 journal"
    );
    assert!(dlx.records().is_empty(), "未进入 undo，不应写 DLX");
}

#[tokio::test]
async fn run_with_failed_append_failure_does_not_deadletter() {
    let journal = Arc::new(FakeJournalFailing::fail_on_status(
        SagaJournalStatus::Failed,
    ));
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, counts) = FakeFactory::steps(&[("step1", false, true), ("step2", true, false)]);
    let exec = executor_with_store(
        journal,
        Arc::new(FakeInstanceStore::default()),
        cp,
        dlx.clone(),
        factory,
    );

    let outcome = exec.run(instance()).await;

    assert!(
        matches!(outcome, SagaOutcome::Failed { .. }),
        "Failed append 失败须 fail-closed: {outcome:?}"
    );
    assert_eq!(counts[0].undos(), 1, "补偿动作已尝试并失败");
    assert!(
        dlx.records().is_empty(),
        "Failed journal 未落库时不应产生 DLX 外部副作用"
    );
}

#[tokio::test]
async fn run_with_compensated_append_failure_marks_terminal_failed() {
    let journal = Arc::new(FakeJournalFailing::fail_on_status(
        SagaJournalStatus::Compensated,
    ));
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, counts) = FakeFactory::steps(&[("step1", false, false), ("step2", true, false)]);
    let exec = executor_with_store(
        journal.clone(),
        Arc::new(FakeInstanceStore::default()),
        cp,
        dlx.clone(),
        factory,
    );

    let outcome = exec.run(instance()).await;

    assert!(matches!(outcome, SagaOutcome::Failed { .. }), "{outcome:?}");
    assert_eq!(counts[0].undos(), 1, "补偿动作已成功执行一次");
    assert!(
        journal
            .log()
            .contains(&("step1".to_string(), SagaJournalStatus::Failed)),
        "Compensated append 失败后须留下 terminal Failed 事实，避免 resume 静默重试 undo"
    );
    assert_eq!(
        dlx.records().len(),
        1,
        "terminal Failed 事实落库后须进入人工介入 DLX"
    );

    let (factory, replay_counts) = FakeFactory::linear(&["step1", "step2"]);
    let resume_exec = executor_with_store(
        journal.clone(),
        ready_instance_store(),
        Arc::new(FakeCheckpointStore::default()),
        Arc::new(FakeDeadLetterStore::default()),
        factory,
    );

    assert_eq!(
        resume_exec.status(instance()).await,
        Some(SagaExecStatus::Done)
    );
    let replay_outcome = resume_exec.resume(instance()).await;
    assert!(
        matches!(replay_outcome, SagaOutcome::Failed { .. }),
        "{replay_outcome:?}"
    );
    assert_eq!(
        replay_counts[0].undos(),
        0,
        "terminal Failed resume must not re-undo"
    );
}

// ── F2：checkpoint StaleVersion fence → 停跑（不续后续 step）──────────────────────

#[tokio::test]
async fn run_stops_on_checkpoint_fence() {
    // F2：step1 do_it 成功后 advance_checkpoint 返 StaleVersion（并发执行器 fence）⇒ 停跑、Failed；
    // step2.do_it 不应执行。
    let journal = Arc::new(FakeJournal::default());
    let cp = Arc::new(FakeCheckpointStore::default());
    cp.fence();
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, counts) = FakeFactory::linear(&["step1", "step2"]);
    let exec = executor(journal, cp, dlx, factory);

    let outcome = exec.run(instance()).await;

    assert!(
        matches!(outcome, SagaOutcome::Failed { .. }),
        "checkpoint fence 须停跑: {outcome:?}"
    );
    assert_eq!(
        counts[0].dos(),
        1,
        "step1 已执行（fence 发生在其 checkpoint 推进时）"
    );
    assert_eq!(counts[1].dos(), 0, "step2 不应执行（已 fence 停跑）");
}

#[tokio::test]
#[allow(clippy::panic)] // reason: 测试断言分支，item-level carve-out
async fn run_fails_fast_on_duplicate_action_names() {
    let journal = Arc::new(FakeJournal::default());
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, counts) = FakeFactory::linear(&["step1", "step1"]);
    let exec = executor(journal.clone(), cp, dlx, factory);

    let outcome = exec.run(instance()).await;

    match outcome {
        SagaOutcome::Failed { failed_node, error } => {
            assert_eq!(failed_node, "step1");
            assert!(matches!(error, SagaActionError::SerializeFailed));
        }
        other => panic!("expected duplicate name fail-fast, got {other:?}"),
    }
    assert!(journal.log().is_empty(), "fail-fast 不应写 journal");
    assert_eq!(counts[0].dos(), 0);
    assert_eq!(counts[1].dos(), 0);
}

// ── F7：resume 对未知 step 名 fail-fast（不静默跳过）────────────────────────────────

#[tokio::test]
#[allow(clippy::panic)] // reason: 测试断言分支，item-level carve-out
async fn resume_fails_on_unknown_journal_step() {
    let journal = Arc::new(FakeJournal::default());
    journal.seed(0, "step1", SagaJournalStatus::Completed);
    // journal 含一个 factory 不产出的 step（陈旧 / 错配）——resume 须 fail-fast，不静默跳过。
    journal.seed(1, "ghoststep", SagaJournalStatus::Completed);
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, counts) = FakeFactory::linear(&["step1", "step2"]);
    let exec = executor(journal, cp, dlx, factory);

    let outcome = exec.resume(instance()).await;

    match outcome {
        SagaOutcome::Failed { failed_node, .. } => assert_eq!(failed_node, "ghoststep"),
        other => panic!("expected fail-fast Failed on unknown step, got {other:?}"),
    }
    // 未知 step 触发 fail-fast，任何 action 都不应被续跑。
    assert_eq!(counts[0].dos(), 0);
    assert_eq!(counts[1].dos(), 0);
}

#[tokio::test]
async fn resume_retries_step_with_only_executing_journal_record() {
    let journal = Arc::new(FakeJournal::default());
    journal.seed(0, "step1", SagaJournalStatus::Executing);
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, counts) = FakeFactory::linear(&["step1", "step2"]);
    let exec = executor(journal.clone(), cp, dlx, factory);

    let outcome = exec.resume(instance()).await;

    assert!(
        matches!(outcome, SagaOutcome::Succeeded { .. }),
        "executing-only resume should rerun from step1: {outcome:?}"
    );
    assert_eq!(counts[0].dos(), 1, "step1 should be retried");
    assert_eq!(counts[1].dos(), 1, "step2 should continue after step1");
    assert_eq!(
        journal.log(),
        vec![
            ("step1".to_string(), SagaJournalStatus::Executing),
            ("step1".to_string(), SagaJournalStatus::Executing),
            ("step1".to_string(), SagaJournalStatus::Completed),
            ("step2".to_string(), SagaJournalStatus::Executing),
            ("step2".to_string(), SagaJournalStatus::Completed),
        ]
    );
}

// ── F8：从补偿中崩溃恢复 —— 续补偿剩余已完成步 ─────────────────────────────────────

#[tokio::test]
async fn resume_continues_compensation_after_crash() {
    let journal = Arc::new(FakeJournal::default());
    // step1/step2 均已完成，step2 补偿中崩溃（Compensating 无 Compensated）。
    journal.seed(0, "step1", SagaJournalStatus::Completed);
    journal.seed(1, "step2", SagaJournalStatus::Completed);
    journal.seed(2, "step2", SagaJournalStatus::Compensating);
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, counts) = FakeFactory::linear(&["step1", "step2"]);
    let exec = executor(journal, cp, dlx, factory);

    let outcome = exec.resume(instance()).await;

    // 续补偿：逆序对 step2、step1 调 undo_it；终态 Failed（补偿后）。
    assert!(matches!(outcome, SagaOutcome::Failed { .. }), "{outcome:?}");
    assert_eq!(counts[0].undos(), 1, "step1 应被补偿");
    assert_eq!(counts[1].undos(), 1, "step2 应续补偿");
    assert_eq!(counts[0].dos(), 0, "补偿恢复不重跑前向");
    assert_eq!(counts[1].dos(), 0, "补偿恢复不重跑前向");
}

#[tokio::test]
async fn resume_compensation_failure_deadletter_keeps_forward_failed_step() {
    let journal = Arc::new(FakeJournal::default());
    journal.seed(0, "step1", SagaJournalStatus::Completed);
    journal.seed(1, "step2", SagaJournalStatus::Executing);
    journal.seed(2, "step1", SagaJournalStatus::Compensating);
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, _counts) = FakeFactory::steps(&[("step1", false, true), ("step2", false, false)]);
    let exec = executor(journal, cp, dlx.clone(), factory);

    let outcome = exec.resume(instance()).await;

    assert!(matches!(outcome, SagaOutcome::Failed { .. }), "{outcome:?}");
    let records = dlx.records();
    assert_eq!(records.len(), 1, "补偿恢复失败应写一条 DLX");
    let payload = &records[0].5;
    assert!(
        payload.contains("step2"),
        "DLX payload 应保留原始 forward 失败步: {payload}"
    );
    assert!(
        !payload.contains("<unknown-saga>"),
        "DLX payload 不应退化成 UNKNOWN_SAGA: {payload}"
    );
}

// ── F8：已 dead-letter（Failed 行）的 saga resume → 终态直返，不重跑 ─────────────────

#[tokio::test]
async fn resume_terminal_failed_does_not_rerun() {
    let journal = Arc::new(FakeJournal::default());
    journal.seed(0, "step1", SagaJournalStatus::Completed);
    journal.seed(1, "step1", SagaJournalStatus::Failed); // 补偿失败终态（dead-letter）
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, counts) = FakeFactory::linear(&["step1", "step2"]);
    let exec = executor(journal, cp, dlx.clone(), factory);

    let outcome = exec.resume(instance()).await;

    assert!(matches!(outcome, SagaOutcome::Failed { .. }), "{outcome:?}");
    // 终态：既不前向也不补偿。
    assert_eq!(counts[0].dos(), 0);
    assert_eq!(counts[0].undos(), 0);
    assert_eq!(counts[1].dos(), 0);
    // 未写新 dead-letter（已是终态）。
    assert!(dlx.records().is_empty());
}

#[tokio::test]
async fn resume_terminal_compensated_does_not_rerun_or_deadletter() {
    let journal = Arc::new(FakeJournal::default());
    journal.seed(0, "step1", SagaJournalStatus::Completed);
    journal.seed(1, "step1", SagaJournalStatus::Compensating);
    journal.seed(2, "step1", SagaJournalStatus::Compensated);
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, counts) = FakeFactory::linear(&["step1"]);
    let exec = executor(journal, cp, dlx.clone(), factory);

    let outcome = exec.resume(instance()).await;

    assert!(matches!(outcome, SagaOutcome::Failed { .. }), "{outcome:?}");
    assert_eq!(counts[0].dos(), 0);
    assert_eq!(counts[0].undos(), 0);
    assert!(dlx.records().is_empty());
}

// ── T009.6：补偿失败 tracing error! 含 saga_id / step_name / error_summary ───────

#[test]
#[allow(clippy::expect_used)] // reason: 测试断言（缺事件即失败），item-level carve-out
#[allow(clippy::unwrap_used)] // reason: 测试 runtime/Mutex 构造，item-level carve-out
fn compensation_failure_logs_fields() {
    use tracing::field::{Field, Visit};
    use tracing::{Event, Subscriber};
    use tracing_subscriber::layer::{Context, Layer};
    use tracing_subscriber::prelude::*;

    struct CaptureLayer {
        events: Arc<Mutex<Vec<HashMap<String, String>>>>,
    }

    struct CapVisit {
        current: HashMap<String, String>,
    }

    impl Visit for CapVisit {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.current
                .insert(field.name().to_string(), format!("{value:?}"));
        }
        fn record_str(&mut self, field: &Field, value: &str) {
            self.current
                .insert(field.name().to_string(), value.to_string());
        }
    }

    impl<S> Layer<S> for CaptureLayer
    where
        S: Subscriber,
    {
        fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
            if *event.metadata().level() != tracing::Level::ERROR {
                return;
            }
            let mut visitor = CapVisit {
                current: HashMap::new(),
            };
            event.record(&mut visitor);
            self.events.lock().unwrap().push(visitor.current);
        }
    }

    let events = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::registry().with(CaptureLayer {
        events: Arc::clone(&events),
    });
    tracing::subscriber::with_default(subscriber, || {
        tracing::callsite::rebuild_interest_cache();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let journal = Arc::new(FakeJournal::default());
            let cp = Arc::new(FakeCheckpointStore::default());
            let dlx = Arc::new(FakeDeadLetterStore::default());
            let (factory, _counts) =
                FakeFactory::steps(&[("step1", false, true), ("step2", true, false)]);
            let exec = executor(journal, cp, dlx, factory);
            let _ = exec.run(instance()).await;
        });
        tracing::callsite::rebuild_interest_cache();
    });

    let events = events.lock().unwrap().clone();
    let comp = events
        .iter()
        .find(|e| e.get("error_summary").is_some_and(|v| !v.is_empty()))
        .expect("compensation failure error event must be captured");
    assert!(
        comp.get("saga_id").is_some_and(|v| !v.is_empty()),
        "缺 saga_id: {comp:?}"
    );
    assert_eq!(comp.get("step_name").map(String::as_str), Some("step1"));
    assert!(comp.get("error_summary").is_some_and(|v| !v.is_empty()));
}

// ── SagaTailer 状态 ────────────────────────────────────────────────────────────

#[tokio::test]
async fn status_reports_none_running_done() {
    let journal = Arc::new(FakeJournal::default());
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, _counts) = FakeFactory::linear(&["step1"]);
    let store = Arc::new(FakeInstanceStore::default());
    let exec = executor_with_store(journal.clone(), store.clone(), cp, dlx, factory);

    // 未知 saga（无 instance row、空 journal）→ None。
    assert_eq!(exec.status(instance()).await, None);
    store.seed_status(instance(), SagaInstanceStatus::Ready);
    assert_eq!(exec.status(instance()).await, Some(SagaExecStatus::Ready));

    // 在飞（step1 Executing 未完成）→ Running。
    journal.seed(0, "step1", SagaJournalStatus::Executing);
    assert_eq!(exec.status(instance()).await, Some(SagaExecStatus::Running));

    // step1 Completed → Done（无在飞）。
    journal.seed(1, "step1", SagaJournalStatus::Completed);
    assert_eq!(exec.status(instance()).await, Some(SagaExecStatus::Done));
}

#[tokio::test]
async fn status_reports_done_after_forward_failure_is_fully_compensated() {
    let journal = Arc::new(FakeJournal::default());
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, _counts) = FakeFactory::linear(&["step1", "step2"]);
    let exec = executor(journal.clone(), cp, dlx, factory);

    journal.seed(0, "step1", SagaJournalStatus::Completed);
    journal.seed(1, "step2", SagaJournalStatus::Executing);
    journal.seed(2, "step1", SagaJournalStatus::Compensating);
    journal.seed(3, "step1", SagaJournalStatus::Compensated);

    assert_eq!(exec.status(instance()).await, Some(SagaExecStatus::Done));
}

#[tokio::test]
async fn status_reports_degraded_for_definition_or_replay_errors() {
    let duplicate_factory_journal = Arc::new(FakeJournal::default());
    duplicate_factory_journal.seed(0, "step1", SagaJournalStatus::Executing);
    let (duplicate_factory, _counts) = FakeFactory::linear(&["step1", "step1"]);
    let duplicate_exec = executor(
        duplicate_factory_journal,
        Arc::new(FakeCheckpointStore::default()),
        Arc::new(FakeDeadLetterStore::default()),
        duplicate_factory,
    );
    assert_eq!(
        duplicate_exec.status(instance()).await,
        Some(SagaExecStatus::Degraded)
    );

    let unknown_step_journal = Arc::new(FakeJournal::default());
    unknown_step_journal.seed(0, "ghoststep", SagaJournalStatus::Completed);
    let (factory, _counts) = FakeFactory::linear(&["step1"]);
    let unknown_exec = executor(
        unknown_step_journal,
        Arc::new(FakeCheckpointStore::default()),
        Arc::new(FakeDeadLetterStore::default()),
        factory,
    );
    assert_eq!(
        unknown_exec.status(instance()).await,
        Some(SagaExecStatus::Degraded)
    );

    let duplicate_seq_journal = Arc::new(FakeJournal::default());
    duplicate_seq_journal.seed(0, "step1", SagaJournalStatus::Executing);
    duplicate_seq_journal.seed(0, "step1", SagaJournalStatus::Completed);
    let (factory, _counts) = FakeFactory::linear(&["step1"]);
    let duplicate_seq_exec = executor(
        duplicate_seq_journal,
        Arc::new(FakeCheckpointStore::default()),
        Arc::new(FakeDeadLetterStore::default()),
        factory,
    );
    assert_eq!(
        duplicate_seq_exec.status(instance()).await,
        Some(SagaExecStatus::Degraded)
    );
}

#[tokio::test]
async fn status_reports_degraded_on_journal_read_error() {
    let journal = Arc::new(FakeJournalFailing::read_failing());
    let (factory, _counts) = FakeFactory::linear(&["step1"]);
    let exec = executor_with_store(
        journal,
        Arc::new(FakeInstanceStore::default()),
        Arc::new(FakeCheckpointStore::default()),
        Arc::new(FakeDeadLetterStore::default()),
        factory,
    );

    assert_eq!(
        exec.status(instance()).await,
        Some(SagaExecStatus::Degraded)
    );
}

#[tokio::test]
async fn status_reports_degraded_from_instance_status_without_journal() {
    let journal = Arc::new(FakeJournal::default());
    let store = ready_instance_store();
    store.seed_status(instance(), SagaInstanceStatus::Degraded);
    let (factory, _counts) = FakeFactory::linear(&["step1"]);
    let exec = executor_with_store(
        journal,
        store,
        Arc::new(FakeCheckpointStore::default()),
        Arc::new(FakeDeadLetterStore::default()),
        factory,
    );

    assert_eq!(
        exec.status(instance()).await,
        Some(SagaExecStatus::Degraded)
    );
}

// ── 冻结接缝 smoke（自 lib.rs 迁入，升级为实测）────────────────────────────────

fn assert_send_sync<T: Send + Sync + ?Sized>() {}

#[test]
fn executor_and_tailer_object_safe_send_sync() {
    assert_send_sync::<dyn SagaExecutor>();
    assert_send_sync::<dyn SagaTailer>();
    assert_send_sync::<dyn SagaActionFactory>();
}

#[test]
fn saga_action_ctx_funnel_round_trips() {
    let ctx = SagaActionCtx::new(instance(), "reserve_funds");
    assert_eq!(ctx.tenant(), tenant());
    assert_eq!(ctx.instance(), instance());
    assert_eq!(ctx.saga_id().as_uuid(), saga_id().as_uuid());
    assert_eq!(ctx.node_name(), "reserve_funds");
}

#[test]
fn saga_outcome_and_command_and_status_exhaustive() {
    let out = SagaOutcome::Failed {
        failed_node: "n".to_string(),
        error: SagaActionError::ActionFailed,
    };
    let _ = match out {
        SagaOutcome::Succeeded { .. } => "ok",
        SagaOutcome::Failed { .. } => "fail",
        SagaOutcome::Interrupted { .. } => "interrupted",
    };
    let cmd = SagaCommand::Cancel { saga_id: saga_id() };
    let _ = match cmd {
        SagaCommand::Start { .. } => "start",
        SagaCommand::Cancel { .. } => "cancel",
    };
    let _ = match SagaExecStatus::Done {
        SagaExecStatus::Ready => 0,
        SagaExecStatus::Running => 1,
        SagaExecStatus::Done => 2,
        SagaExecStatus::Degraded => 3,
    };
}
