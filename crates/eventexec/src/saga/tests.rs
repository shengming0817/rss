//! saga 执行器单测：验收三场景（journal 顺序 / 逆序补偿 / checkpoint resume）+ 补偿失败 dead-letter
//! observability（T009.1 / T009.6）+ 冻结接缝 smoke。
//!
//! 须经 `cargo nextest`（进程隔离）跑：`compensation_failure_logs_fields` 用 `set_global_default`
//! 捕获 tracing 字段，与 `consumer.rs` TC5 同款——单进程（裸 `cargo test`）下多个全局 subscriber 会冲突。

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

use super::{
    SagaAction, SagaActionCtx, SagaActionError, SagaActionFactory, SagaCommand, SagaExecStatus,
    SagaExecutor, SagaExecutorImpl, SagaId, SagaOutcome, SagaTailer,
};
use consistency::{Lsn, StepName};
use diport::{
    Checkpoint, CheckpointId, CheckpointOwner, CheckpointStoreError, CheckpointVersion,
    DeadLetterRecord, DeadLetterStore, DeadLetterStoreError, JournalEntry, JournalStatus,
    OwnerCheckpointStore, SagaJournal, SagaJournalError, SaveOutcome,
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

fn checkpoint_id_str() -> String {
    saga_id().as_uuid().to_string()
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

fn mk_action(name: &str, do_fails: bool, undo_fails: bool) -> (Box<dyn SagaAction>, Counts) {
    let do_count = Arc::new(AtomicU32::new(0));
    let undo_count = Arc::new(AtomicU32::new(0));
    let action = FakeAction {
        name: name.to_string(),
        do_count: do_count.clone(),
        undo_count: undo_count.clone(),
        do_fails,
        undo_fails,
    };
    (
        Box::new(action),
        Counts {
            do_count,
            undo_count,
        },
    )
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
        let mut steps = Vec::new();
        let mut counts = Vec::new();
        for n in names {
            let c = Counts {
                do_count: Arc::new(AtomicU32::new(0)),
                undo_count: Arc::new(AtomicU32::new(0)),
            };
            counts.push(c.clone());
            steps.push(StepSpec {
                name: (*n).to_string(),
                do_fails: false,
                undo_fails: false,
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

/// 空 factory（run-only 测试不用 resume，但构造器必填）。
struct EmptyFactory;
impl SagaActionFactory for EmptyFactory {
    fn build(&self) -> Vec<Box<dyn SagaAction>> {
        Vec::new()
    }
}

// ── FakeJournal ───────────────────────────────────────────────────────────────

#[derive(Default)]
struct FakeJournal {
    rows: Mutex<Vec<(uuid::Uuid, u64, String, JournalStatus)>>,
}

impl FakeJournal {
    #[allow(clippy::unwrap_used)] // reason: 测试 Mutex，item-level carve-out
    fn seed(&self, seq: u64, step: &str, status: JournalStatus) {
        self.rows
            .lock()
            .unwrap()
            .push((saga_id().as_uuid(), seq, step.to_string(), status));
    }
    /// seq 序的 (step_name, status)，供顺序断言。
    #[allow(clippy::unwrap_used)] // reason: 测试 Mutex，item-level carve-out
    fn log(&self) -> Vec<(String, JournalStatus)> {
        let mut rows: Vec<_> = self.rows.lock().unwrap().clone();
        rows.sort_by_key(|r| r.1);
        rows.into_iter().map(|r| (r.2, r.3)).collect()
    }
}

impl SagaJournal for FakeJournal {
    #[allow(clippy::unwrap_used)] // reason: 测试 Mutex，item-level carve-out
    async fn append(&self, sid: &SagaId, entry: JournalEntry) -> Result<(), SagaJournalError> {
        let mut rows = self.rows.lock().unwrap();
        let key = (sid.as_uuid(), entry.seq);
        if !rows.iter().any(|r| (r.0, r.1) == key) {
            rows.push((
                sid.as_uuid(),
                entry.seq,
                entry.step_name.as_str().to_string(),
                entry.status,
            ));
        }
        Ok(())
    }
    #[allow(clippy::unwrap_used)] // reason: 测试 Mutex + 字面 step 名合法，item-level carve-out
    async fn read(&self, sid: &SagaId) -> Result<Vec<JournalEntry>, SagaJournalError> {
        let mut rows: Vec<_> = self
            .rows
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.0 == sid.as_uuid())
            .cloned()
            .collect();
        rows.sort_by_key(|r| r.1);
        let entries = rows
            .into_iter()
            .map(|r| JournalEntry {
                seq: r.1,
                step_name: StepName::parse(&r.2).unwrap(),
                status: r.3,
                output: None,
                error_summary: None,
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

// ── executor 构造 helper ──────────────────────────────────────────────────────

type Exec = SagaExecutorImpl<FakeJournal, FakeCheckpointStore, FakeDeadLetterStore>;

fn executor(
    journal: Arc<FakeJournal>,
    cp: Arc<FakeCheckpointStore>,
    dlx: Arc<FakeDeadLetterStore>,
    factory: Arc<dyn SagaActionFactory>,
) -> Exec {
    SagaExecutorImpl::new(
        journal,
        cp,
        dlx,
        factory,
        tenant(),
        CheckpointOwner::new(OWNER),
        CONTRACT,
    )
}

// ── FakeJournalFailing（append 注入失败）──────────────────────────────────────────

use std::sync::atomic::AtomicBool;

/// append 可注入失败的 journal（测试 best-effort 降级语义）。
struct FakeJournalFailing {
    inner: FakeJournal,
    append_fails: AtomicBool,
}

impl FakeJournalFailing {
    fn new(fail: bool) -> Self {
        Self {
            inner: FakeJournal::default(),
            append_fails: AtomicBool::new(fail),
        }
    }
}

impl SagaJournal for FakeJournalFailing {
    async fn append(&self, sid: &SagaId, entry: JournalEntry) -> Result<(), SagaJournalError> {
        if self.append_fails.load(Ordering::SeqCst) {
            Err(SagaJournalError::new(std::io::Error::other("inject")))
        } else {
            self.inner.append(sid, entry).await
        }
    }
    async fn read(&self, sid: &SagaId) -> Result<Vec<JournalEntry>, SagaJournalError> {
        self.inner.read(sid).await
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
    let exec = executor(
        journal.clone(),
        cp.clone(),
        dlx.clone(),
        Arc::new(EmptyFactory),
    );

    let (a1, c1) = mk_action("step1", false, false);
    let (a2, c2) = mk_action("step2", false, false);
    let (a3, c3) = mk_action("step3", false, false);

    let outcome = exec.run(saga_id(), vec![a1, a2, a3]).await;

    assert!(
        matches!(outcome, SagaOutcome::Succeeded { .. }),
        "{outcome:?}"
    );
    use JournalStatus::{Completed, Executing};
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
    assert_eq!((c1.dos(), c2.dos(), c3.dos()), (1, 1, 1));
    assert_eq!((c1.undos(), c2.undos(), c3.undos()), (0, 0, 0));
    assert!(dlx.records().is_empty());
}

// ── T009.1 #2：step2 失败 → 逆序补偿 step1（step2 未完成不补偿）────────────────

#[tokio::test]
#[allow(clippy::panic)] // reason: 测试断言分支，item-level carve-out
async fn step2_failure_reverse_compensates_step1_only() {
    let journal = Arc::new(FakeJournal::default());
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let exec = executor(
        journal.clone(),
        cp.clone(),
        dlx.clone(),
        Arc::new(EmptyFactory),
    );

    let (a1, c1) = mk_action("step1", false, false);
    let (a2, c2) = mk_action("step2", /* do_fails */ true, false);
    let (a3, c3) = mk_action("step3", false, false);

    let outcome = exec.run(saga_id(), vec![a1, a2, a3]).await;

    match outcome {
        SagaOutcome::Failed { failed_node, .. } => assert_eq!(failed_node, "step2"),
        other => panic!("expected Failed, got {other:?}"),
    }
    use JournalStatus::{Compensated, Compensating, Completed, Executing};
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
    assert_eq!((c1.dos(), c2.dos(), c3.dos()), (1, 1, 0));
    assert_eq!((c1.undos(), c2.undos(), c3.undos()), (1, 0, 0));
}

// ── T009.1 #3：从 step2 checkpoint resume → 跳过 step1 ──────────────────────────

#[tokio::test]
async fn resume_from_step2_checkpoint_skips_step1() {
    let journal = Arc::new(FakeJournal::default());
    journal.seed(0, "step1", JournalStatus::Executing);
    journal.seed(1, "step1", JournalStatus::Completed);
    let cp = Arc::new(FakeCheckpointStore::default());
    cp.seed(&checkpoint_id_str(), 1, 1);
    let dlx = Arc::new(FakeDeadLetterStore::default());

    let (factory, counts) = FakeFactory::linear(&["step1", "step2", "step3"]);
    let exec = executor(journal.clone(), cp.clone(), dlx.clone(), factory);

    let outcome = exec.resume(saga_id()).await;

    assert!(
        matches!(outcome, SagaOutcome::Succeeded { .. }),
        "{outcome:?}"
    );
    // step1 不再执行（已完成）；step2/step3 续跑。
    assert_eq!(counts[0].dos(), 0, "step1 应被跳过");
    assert_eq!(counts[1].dos(), 1, "step2 应续跑");
    assert_eq!(counts[2].dos(), 1, "step3 应续跑");
    // 续跑后 journal 含 step2/step3 完成，checkpoint 推进到 3。
    use JournalStatus::Completed;
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
    let exec = executor(
        journal.clone(),
        cp.clone(),
        dlx.clone(),
        Arc::new(EmptyFactory),
    );

    // step1 do ok / undo FAILS；step2 do FAILS → 触发对 step1 的补偿，补偿失败 → dead-letter。
    let (a1, _c1) = mk_action("step1", false, /* undo_fails */ true);
    let (a2, _c2) = mk_action("step2", /* do_fails */ true, false);

    let outcome = exec.run(saga_id(), vec![a1, a2]).await;

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
            .any(|(n, s)| n == "step1" && *s == JournalStatus::Failed),
        "journal 缺 step1 Failed 审计行"
    );
}

// ── resume 空 journal → Failed（UNKNOWN_SAGA），非 error 日志（无 journal = 未知 saga）──────

#[tokio::test]
#[allow(clippy::panic)] // reason: 测试断言分支，item-level carve-out
async fn resume_with_empty_journal_returns_failed() {
    let journal = Arc::new(FakeJournal::default());
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    // 不 seed 任何 journal 条目（空 journal = 未知 saga）。
    let exec = executor(journal.clone(), cp, dlx, Arc::new(EmptyFactory));

    let outcome = exec.resume(saga_id()).await;

    match outcome {
        SagaOutcome::Failed { failed_node, .. } => {
            assert!(
                failed_node.contains("unknown"),
                "empty journal should produce unknown failed_node, got: {failed_node}"
            );
        }
        other => panic!("expected Failed for empty journal, got {other:?}"),
    }
}

// ── F1：Executing journal append 失败 → fail-closed（不执行副作用）─────────────────

#[tokio::test]
async fn run_with_executing_append_failure_fails_closed() {
    // F1：journal 写是执行状态机一等边。Executing append 失败 ⇒ do_it **不执行**、返回 Failed
    // （无 journal 无法 durable 恢复，副作用不能在无记录下发生）。修正原 best-effort 误设计。
    let journal = Arc::new(FakeJournalFailing::new(true));
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());

    let exec = SagaExecutorImpl::new(
        journal,
        cp,
        dlx,
        Arc::new(EmptyFactory),
        tenant(),
        CheckpointOwner::new(OWNER),
        CONTRACT,
    );

    let (a1, c1) = mk_action("step1", false, false);
    let (a2, c2) = mk_action("step2", false, false);

    let outcome = exec.run(saga_id(), vec![a1, a2]).await;

    assert!(
        matches!(outcome, SagaOutcome::Failed { .. }),
        "Executing append 失败必 fail-closed: {outcome:?}"
    );
    // 副作用从未发生：step1.do_it 未被调用。
    assert_eq!(c1.dos(), 0, "step1.do_it 不应执行（fail-closed）");
    assert_eq!(c2.dos(), 0, "step2 从未到达");
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
    let exec = executor(journal, cp, dlx, Arc::new(EmptyFactory));

    let (a1, c1) = mk_action("step1", false, false);
    let (a2, c2) = mk_action("step2", false, false);

    let outcome = exec.run(saga_id(), vec![a1, a2]).await;

    assert!(
        matches!(outcome, SagaOutcome::Failed { .. }),
        "checkpoint fence 须停跑: {outcome:?}"
    );
    assert_eq!(
        c1.dos(),
        1,
        "step1 已执行（fence 发生在其 checkpoint 推进时）"
    );
    assert_eq!(c2.dos(), 0, "step2 不应执行（已 fence 停跑）");
}

// ── F7：resume 对未知 step 名 fail-fast（不静默跳过）────────────────────────────────

#[tokio::test]
#[allow(clippy::panic)] // reason: 测试断言分支，item-level carve-out
async fn resume_fails_on_unknown_journal_step() {
    let journal = Arc::new(FakeJournal::default());
    journal.seed(0, "step1", JournalStatus::Completed);
    // journal 含一个 factory 不产出的 step（陈旧 / 错配）——resume 须 fail-fast，不静默跳过。
    journal.seed(1, "ghoststep", JournalStatus::Completed);
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, counts) = FakeFactory::linear(&["step1", "step2"]);
    let exec = executor(journal, cp, dlx, factory);

    let outcome = exec.resume(saga_id()).await;

    match outcome {
        SagaOutcome::Failed { failed_node, .. } => assert_eq!(failed_node, "ghoststep"),
        other => panic!("expected fail-fast Failed on unknown step, got {other:?}"),
    }
    // 未知 step 触发 fail-fast，任何 action 都不应被续跑。
    assert_eq!(counts[0].dos(), 0);
    assert_eq!(counts[1].dos(), 0);
}

// ── F8：从补偿中崩溃恢复 —— 续补偿剩余已完成步 ─────────────────────────────────────

#[tokio::test]
async fn resume_continues_compensation_after_crash() {
    let journal = Arc::new(FakeJournal::default());
    // step1/step2 均已完成，step2 补偿中崩溃（Compensating 无 Compensated）。
    journal.seed(0, "step1", JournalStatus::Completed);
    journal.seed(1, "step2", JournalStatus::Completed);
    journal.seed(2, "step2", JournalStatus::Compensating);
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, counts) = FakeFactory::linear(&["step1", "step2"]);
    let exec = executor(journal, cp, dlx, factory);

    let outcome = exec.resume(saga_id()).await;

    // 续补偿：逆序对 step2、step1 调 undo_it；终态 Failed（补偿后）。
    assert!(matches!(outcome, SagaOutcome::Failed { .. }), "{outcome:?}");
    assert_eq!(counts[0].undos(), 1, "step1 应被补偿");
    assert_eq!(counts[1].undos(), 1, "step2 应续补偿");
    assert_eq!(counts[0].dos(), 0, "补偿恢复不重跑前向");
    assert_eq!(counts[1].dos(), 0, "补偿恢复不重跑前向");
}

// ── F8：已 dead-letter（Failed 行）的 saga resume → 终态直返，不重跑 ─────────────────

#[tokio::test]
async fn resume_terminal_failed_does_not_rerun() {
    let journal = Arc::new(FakeJournal::default());
    journal.seed(0, "step1", JournalStatus::Completed);
    journal.seed(1, "step1", JournalStatus::Failed); // 补偿失败终态（dead-letter）
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, counts) = FakeFactory::linear(&["step1", "step2"]);
    let exec = executor(journal, cp, dlx.clone(), factory);

    let outcome = exec.resume(saga_id()).await;

    assert!(matches!(outcome, SagaOutcome::Failed { .. }), "{outcome:?}");
    // 终态：既不前向也不补偿。
    assert_eq!(counts[0].dos(), 0);
    assert_eq!(counts[0].undos(), 0);
    assert_eq!(counts[1].dos(), 0);
    // 未写新 dead-letter（已是终态）。
    assert!(dlx.records().is_empty());
}

// ── T009.6：补偿失败 tracing error! 含 saga_id / step_name / error_summary ───────

#[test]
#[allow(clippy::expect_used)] // reason: 测试断言（缺事件即失败），item-level carve-out
fn compensation_failure_logs_fields() {
    use tracing::field::{Field, Visit};
    use tracing::{Event, Id, Metadata, span};

    struct Captured {
        events: Mutex<Vec<HashMap<String, String>>>,
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
    struct CapSubscriber {
        captured: Arc<Captured>,
    }
    impl tracing::Subscriber for CapSubscriber {
        fn enabled(&self, _meta: &Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _span: &span::Attributes<'_>) -> Id {
            Id::from_u64(1)
        }
        fn record(&self, _span: &Id, _values: &span::Record<'_>) {}
        fn record_follows_from(&self, _span: &Id, _follows: &Id) {}
        fn enter(&self, _span: &Id) {}
        fn exit(&self, _span: &Id) {}
        #[allow(clippy::unwrap_used)] // reason: 测试 Mutex，item-level carve-out
        fn event(&self, event: &Event<'_>) {
            if *event.metadata().level() != tracing::Level::ERROR {
                return;
            }
            let mut visitor = CapVisit {
                current: HashMap::new(),
            };
            event.record(&mut visitor);
            self.captured.events.lock().unwrap().push(visitor.current);
        }
    }

    let captured = Arc::new(Captured {
        events: Mutex::new(vec![]),
    });
    let subscriber = CapSubscriber {
        captured: captured.clone(),
    };
    let dispatch = tracing::Dispatch::new(subscriber);

    #[allow(clippy::unwrap_used)] // reason: 测试 runtime 构造，item-level carve-out
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    tracing::dispatcher::with_default(&dispatch, || {
        rt.block_on(async {
            let journal = Arc::new(FakeJournal::default());
            let cp = Arc::new(FakeCheckpointStore::default());
            let dlx = Arc::new(FakeDeadLetterStore::default());
            let exec = executor(journal, cp, dlx, Arc::new(EmptyFactory));
            let (a1, _c1) = mk_action("step1", false, true);
            let (a2, _c2) = mk_action("step2", true, false);
            let _ = exec.run(saga_id(), vec![a1, a2]).await;
        });
    });

    #[allow(clippy::unwrap_used)] // reason: 测试 Mutex，item-level carve-out
    let events = captured.events.lock().unwrap().clone();
    let comp = events
        .iter()
        .find(|e| e.get("error_summary").is_some_and(|v| !v.is_empty()))
        .expect("缺补偿失败 error 事件");
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
    let exec = executor(journal.clone(), cp, dlx, Arc::new(EmptyFactory));

    // 未知 saga（空 journal）→ None。
    assert_eq!(exec.status(saga_id()).await, None);

    // 在飞（step1 Executing 未完成）→ Running。
    journal.seed(0, "step1", JournalStatus::Executing);
    assert_eq!(exec.status(saga_id()).await, Some(SagaExecStatus::Running));

    // step1 Completed → Done（无在飞）。
    journal.seed(1, "step1", JournalStatus::Completed);
    assert_eq!(exec.status(saga_id()).await, Some(SagaExecStatus::Done));
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
    let ctx = SagaActionCtx::new(saga_id().as_uuid(), "reserve_funds");
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
    };
}
