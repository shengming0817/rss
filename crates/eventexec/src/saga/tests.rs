//! saga 执行器单测：验收三场景（journal 顺序 / 逆序补偿 / checkpoint resume）+ 补偿失败 dead-letter
//! observability（T009.1 / T009.6）+ 冻结接缝 smoke。
//!
//! `compensation_failure_logs_fields` 使用 current-thread runtime + scoped subscriber 捕获 tracing 字段，
//! 避免单进程 `cargo test` 下多个全局 subscriber 竞争。

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};
use std::time::Duration;

use super::{
    ReceiptFailureLogKind, SagaAction, SagaActionCtx, SagaActionError, SagaActionFactory,
    SagaActionReceipt, SagaCommand, SagaCompensationContext, SagaDefinitionRegistry,
    SagaExecStatus, SagaExecutor, SagaExecutorConfig, SagaExecutorDeps, SagaExecutorImpl,
    SagaForwardContext, SagaOutcome, SagaPolicy, SagaRuntimeLock, SagaTailer,
};
use consistency::{
    Lsn, SagaEffectPhase, SagaJournalAppendRecord, SagaJournalRecord, SagaJournalStatus,
    SagaReceiptScope, StepName,
};
use consistency::{
    SagaId, SagaInstanceRecord, SagaInstanceRef, SagaInstanceStatus, SagaInterruption,
    SagaJournalAppendOutcome, SagaLease, SagaLeaseOutcome,
};
use diport::{
    Checkpoint, CheckpointId, CheckpointOwner, CheckpointStoreError, CheckpointVersion,
    DeadLetterRecord, DeadLetterStore, DeadLetterStoreError, DynSagaReceiptStore,
    LockAcquireOutcome, LockRenewOutcome, LockStore, LockStoreError, LockStoreKey,
    OwnerCheckpointStore, SagaContractId, SagaInstanceRegistration, SagaInstanceStore,
    SagaInstanceStoreError, SagaJournal, SagaJournalError, SagaReceiptCommitOutcome,
    SagaReceiptStore, SagaReceiptStoreError, SagaReceiptStoreErrorKind, SagaRunnableInstance,
    SagaStepCompletion, SagaWorkerIdentity, SaveOutcome, StoredSagaReceipt,
};
use futures::future::BoxFuture;
use std::sync::Arc;
use tokio::sync::Notify;

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

#[allow(clippy::unwrap_used)]
fn instance_with_id(raw: u128) -> SagaInstanceRef {
    SagaInstanceRef::new(tenant(), SagaId::new(uuid::Uuid::from_u128(raw))).unwrap()
}

fn checkpoint_id_str() -> String {
    format!("{}:{}", TENANT, saga_id().as_uuid())
}

fn definition_identity() -> consistency::SagaDefinitionIdentity {
    consistency::SagaDefinitionIdentity::from_binding(generated::saga::billing_v1::SPEC)
}

#[allow(clippy::unwrap_used)]
fn worker_identity() -> SagaWorkerIdentity {
    SagaWorkerIdentity::new(OWNER, SagaContractId::parse(CONTRACT).unwrap()).unwrap()
}

// ── FakeAction ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct FakeAction {
    name: String,
    do_count: Arc<AtomicU32>,
    undo_count: Arc<AtomicU32>,
    do_behavior: FakeBehavior,
    undo_behavior: FakeBehavior,
    retry_class: vocab::SagaRetryClass,
    binding: Option<vocab::SagaStepBinding>,
    observed_keys: Option<Arc<Mutex<Vec<String>>>>,
}

#[derive(Debug, Clone, Copy)]
enum FakeBehavior {
    Succeed,
    Fail,
    SerializeFail,
    PostEffectSerializeFail,
    FailTimes(u32),
    Hang,
}

impl FakeBehavior {
    fn from_fails(fails: bool) -> Self {
        if fails { Self::Fail } else { Self::Succeed }
    }
}

impl SagaAction for FakeAction {
    fn name(&self) -> &str {
        &self.name
    }
    fn retry_class(&self) -> vocab::SagaRetryClass {
        self.retry_class
    }
    fn binding(&self) -> Option<vocab::SagaStepBinding> {
        self.binding
    }
    fn do_it(
        &self,
        ctx: SagaActionCtx,
    ) -> BoxFuture<'static, Result<SagaActionReceipt, SagaActionError>> {
        let count = self.do_count.clone();
        let behavior = self.do_behavior;
        let name = self.name.clone();
        let observed_keys = self.observed_keys.clone();
        let idempotency_key = ctx.idempotency_key.to_hex();
        Box::pin(async move {
            if let Some(keys) = observed_keys {
                keys.lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .push(idempotency_key);
            }
            let attempt = count.fetch_add(1, Ordering::SeqCst) + 1;
            match behavior {
                FakeBehavior::Succeed => {
                    let output = format!("{name}-out").into_bytes();
                    Ok(SagaActionReceipt::new(output.clone(), output))
                }
                FakeBehavior::Fail => Err(SagaActionError::ActionFailed),
                FakeBehavior::SerializeFail => Err(SagaActionError::SerializeFailed),
                FakeBehavior::PostEffectSerializeFail => {
                    let receipt = format!("{name}-typed-receipt").into_bytes();
                    Ok(SagaActionReceipt::post_effect_failure(
                        SagaActionError::InvariantViolation,
                        receipt,
                    ))
                }
                FakeBehavior::FailTimes(failures) if attempt <= failures => {
                    Err(SagaActionError::ActionFailed)
                }
                FakeBehavior::FailTimes(_) => {
                    let output = format!("{name}-out").into_bytes();
                    Ok(SagaActionReceipt::new(output.clone(), output))
                }
                FakeBehavior::Hang => {
                    std::future::pending::<Result<SagaActionReceipt, SagaActionError>>().await
                }
            }
        })
    }
    fn undo_it(
        &self,
        _ctx: SagaActionCtx,
        _receipt: Arc<dyn std::any::Any + Send + Sync>,
    ) -> BoxFuture<'static, Result<(), SagaActionError>> {
        let count = self.undo_count.clone();
        let behavior = self.undo_behavior;
        Box::pin(async move {
            let attempt = count.fetch_add(1, Ordering::SeqCst) + 1;
            match behavior {
                FakeBehavior::Succeed => Ok(()),
                FakeBehavior::Fail => Err(SagaActionError::ActionFailed),
                FakeBehavior::SerializeFail | FakeBehavior::PostEffectSerializeFail => {
                    Err(SagaActionError::SerializeFailed)
                }
                FakeBehavior::FailTimes(failures) if attempt <= failures => {
                    Err(SagaActionError::ActionFailed)
                }
                FakeBehavior::FailTimes(_) => Ok(()),
                FakeBehavior::Hang => std::future::pending::<Result<(), SagaActionError>>().await,
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
    do_behavior: FakeBehavior,
    undo_behavior: FakeBehavior,
    retry_class: vocab::SagaRetryClass,
    binding: Option<vocab::SagaStepBinding>,
    observed_keys: Option<Arc<Mutex<Vec<String>>>>,
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
        let specs = specs
            .iter()
            .map(|(name, do_fails, undo_fails)| {
                (
                    *name,
                    FakeBehavior::from_fails(*do_fails),
                    FakeBehavior::from_fails(*undo_fails),
                )
            })
            .collect::<Vec<_>>();
        Self::behaviors(&specs)
    }

    fn behaviors(specs: &[(&str, FakeBehavior, FakeBehavior)]) -> (Arc<Self>, Vec<Counts>) {
        let specs = specs
            .iter()
            .map(|(name, do_behavior, undo_behavior)| {
                (
                    *name,
                    *do_behavior,
                    *undo_behavior,
                    vocab::SagaRetryClass::Transient,
                )
            })
            .collect::<Vec<_>>();
        Self::behaviors_with_retry_class(&specs)
    }

    fn behaviors_with_retry_class(
        specs: &[(&str, FakeBehavior, FakeBehavior, vocab::SagaRetryClass)],
    ) -> (Arc<Self>, Vec<Counts>) {
        let mut steps = Vec::new();
        let mut counts = Vec::new();
        for (name, do_behavior, undo_behavior, retry_class) in specs {
            let c = Counts {
                do_count: Arc::new(AtomicU32::new(0)),
                undo_count: Arc::new(AtomicU32::new(0)),
            };
            counts.push(c.clone());
            steps.push(StepSpec {
                name: (*name).to_string(),
                do_behavior: *do_behavior,
                undo_behavior: *undo_behavior,
                retry_class: *retry_class,
                binding: None,
                observed_keys: None,
                counts: c,
            });
        }
        (Arc::new(Self { steps }), counts)
    }

    fn retry_key_probe() -> (Arc<Self>, Vec<Counts>, Arc<Mutex<Vec<String>>>) {
        let observed_keys = Arc::new(Mutex::new(Vec::new()));
        let counts = Counts {
            do_count: Arc::new(AtomicU32::new(0)),
            undo_count: Arc::new(AtomicU32::new(0)),
        };
        let step = StepSpec {
            name: generated::saga::billing_v1::STEP_0.name().to_string(),
            do_behavior: FakeBehavior::FailTimes(2),
            undo_behavior: FakeBehavior::Succeed,
            retry_class: vocab::SagaRetryClass::Transient,
            binding: Some(generated::saga::billing_v1::STEP_0),
            observed_keys: Some(Arc::clone(&observed_keys)),
            counts: counts.clone(),
        };
        (
            Arc::new(Self { steps: vec![step] }),
            vec![counts],
            observed_keys,
        )
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
                    do_behavior: s.do_behavior,
                    undo_behavior: s.undo_behavior,
                    retry_class: s.retry_class,
                    binding: s.binding,
                    observed_keys: s.observed_keys.clone(),
                }) as Box<dyn SagaAction>
            })
            .collect()
    }
}

// ── FakeJournal ───────────────────────────────────────────────────────────────

#[derive(Clone, PartialEq, Eq)]
struct FakeJournalRow {
    seq: u64,
    step_name: StepName,
    status: SagaJournalStatus,
    error_summary: Option<&'static str>,
}

impl FakeJournalRow {
    fn from_append(entry: SagaJournalAppendRecord) -> Self {
        Self {
            seq: entry.seq(),
            step_name: entry.step_name().clone(),
            status: entry.status(),
            error_summary: entry.error_summary(),
        }
    }

    fn completed(seq: u64, step_name: StepName) -> Self {
        Self {
            seq,
            step_name,
            status: SagaJournalStatus::Completed,
            error_summary: None,
        }
    }
}

#[derive(Default)]
struct FakeJournal {
    rows: Mutex<Vec<(SagaInstanceRef, FakeJournalRow)>>,
}

impl FakeJournal {
    #[allow(clippy::unwrap_used)] // reason: 测试 Mutex，item-level carve-out
    fn seed(&self, seq: u64, step: &str, status: SagaJournalStatus) {
        let step = StepName::parse(step).unwrap();
        let entry = FakeJournalRow {
            seq,
            step_name: step,
            status,
            error_summary: (status == SagaJournalStatus::Failed).then_some("failed"),
        };
        self.rows.lock().unwrap().push((instance(), entry));
    }
    /// seq 序的 (step_name, status)，供顺序断言。
    #[allow(clippy::unwrap_used)] // reason: 测试 Mutex，item-level carve-out
    fn log(&self) -> Vec<(String, SagaJournalStatus)> {
        let mut rows: Vec<_> = self.rows.lock().unwrap().clone();
        rows.sort_by_key(|(_, entry)| entry.seq);
        rows.into_iter()
            .map(|(_, entry)| (entry.step_name.as_str().to_string(), entry.status))
            .collect()
    }

    #[allow(clippy::unwrap_used)]
    fn commit_completed(
        &self,
        instance: SagaInstanceRef,
        seq: u64,
        step_name: StepName,
    ) -> SagaReceiptCommitOutcome {
        let mut rows = self.rows.lock().unwrap();
        let candidate = FakeJournalRow::completed(seq, step_name);
        if let Some((_, existing)) = rows
            .iter()
            .find(|(stored, record)| *stored == instance && record.seq == seq)
        {
            return if *existing == candidate {
                SagaReceiptCommitOutcome::IdempotentDuplicate
            } else {
                SagaReceiptCommitOutcome::Conflict
            };
        }
        rows.push((instance, candidate));
        SagaReceiptCommitOutcome::Committed
    }
}

impl SagaJournal for FakeJournal {
    #[allow(clippy::unwrap_used)] // reason: 测试 Mutex，item-level carve-out
    async fn append(
        &self,
        lease: &SagaLease,
        entry: SagaJournalAppendRecord,
    ) -> Result<SagaJournalAppendOutcome, SagaJournalError> {
        let entry = FakeJournalRow::from_append(entry);
        let mut rows = self.rows.lock().unwrap();
        let instance = lease.instance();
        let key = (instance, entry.seq);
        if let Some((_, existing)) = rows
            .iter()
            .find(|(stored, record)| (*stored, record.seq) == key)
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
        rows.sort_by_key(|(_, entry)| entry.seq);
        let entries = rows
            .into_iter()
            .map(|(_, entry)| SagaJournalRecord::replayed(entry.seq, entry.step_name, entry.status))
            .collect();
        Ok(entries)
    }
    async fn shutdown(&self) -> Result<(), SagaJournalError> {
        Ok(())
    }
}

trait FakeReceiptJournal: SagaJournal {
    fn commit_receipt_completed(
        &self,
        instance: SagaInstanceRef,
        seq: u64,
        step_name: StepName,
    ) -> Result<SagaReceiptCommitOutcome, SagaReceiptStoreError>;
}

impl FakeReceiptJournal for FakeJournal {
    fn commit_receipt_completed(
        &self,
        instance: SagaInstanceRef,
        seq: u64,
        step_name: StepName,
    ) -> Result<SagaReceiptCommitOutcome, SagaReceiptStoreError> {
        Ok(self.commit_completed(instance, seq, step_name))
    }
}

#[derive(Default)]
struct FakeReceiptState {
    successful_attempts: Mutex<Vec<u32>>,
    commit_unknown_after_commit: AtomicU8,
    precommit_failure: Mutex<Option<SagaReceiptStoreErrorKind>>,
    precommit_outcome: Mutex<Option<SagaReceiptCommitOutcome>>,
}

impl FakeReceiptState {
    #[allow(clippy::unwrap_used)]
    fn successful_attempts(&self) -> Vec<u32> {
        self.successful_attempts.lock().unwrap().clone()
    }

    fn fail_commit_acknowledgement(&self) {
        self.commit_unknown_after_commit.store(1, Ordering::SeqCst);
    }

    fn fail_before_commit(&self, kind: SagaReceiptStoreErrorKind) {
        *self
            .precommit_failure
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(kind);
    }

    fn return_before_commit(&self, outcome: SagaReceiptCommitOutcome) {
        *self
            .precommit_outcome
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(outcome);
    }
}

struct FakeReceiptStore<J> {
    journal: Arc<J>,
    state: Arc<FakeReceiptState>,
}

impl<J> SagaReceiptStore for FakeReceiptStore<J>
where
    J: FakeReceiptJournal + Send + Sync + 'static,
{
    #[allow(clippy::unwrap_used)]
    async fn commit_completed(
        &self,
        lease: &SagaLease,
        completion: SagaStepCompletion,
    ) -> Result<SagaReceiptCommitOutcome, SagaReceiptStoreError> {
        let (scope, attempt, _format, _plaintext, completed_seq) = completion.into_parts();
        if lease.instance() != scope.instance() {
            return Err(SagaReceiptStoreError::new(
                SagaReceiptStoreErrorKind::Integrity,
                std::io::Error::other("synthetic receipt lease mismatch"),
            ));
        }
        if let Some(kind) = *self
            .state
            .precommit_failure
            .lock()
            .unwrap_or_else(|error| error.into_inner())
        {
            return Err(SagaReceiptStoreError::new(
                kind,
                std::io::Error::other("synthetic receipt pre-commit failure"),
            ));
        }
        if let Some(outcome) = *self
            .state
            .precommit_outcome
            .lock()
            .unwrap_or_else(|error| error.into_inner())
        {
            return Ok(outcome);
        }
        let outcome = self.journal.commit_receipt_completed(
            scope.instance(),
            completed_seq,
            scope.step_name().clone(),
        )?;
        if matches!(
            outcome,
            SagaReceiptCommitOutcome::Committed | SagaReceiptCommitOutcome::IdempotentDuplicate
        ) {
            self.state
                .successful_attempts
                .lock()
                .unwrap()
                .push(attempt.get());
        }
        if self
            .state
            .commit_unknown_after_commit
            .load(Ordering::SeqCst)
            == 1
        {
            return Err(SagaReceiptStoreError::new(
                SagaReceiptStoreErrorKind::CommitUnknown,
                std::io::Error::other("synthetic lost commit acknowledgement"),
            ));
        }
        Ok(outcome)
    }

    async fn load_exact(
        &self,
        _scope: &SagaReceiptScope,
    ) -> Result<Option<StoredSagaReceipt>, SagaReceiptStoreError> {
        Ok(None)
    }

    async fn shutdown(&self) -> Result<(), SagaReceiptStoreError> {
        Ok(())
    }
}

fn fake_receipt_store<J>(
    journal: Arc<J>,
    state: Arc<FakeReceiptState>,
) -> Box<DynSagaReceiptStore<'static>>
where
    J: FakeReceiptJournal + Send + Sync + 'static,
{
    DynSagaReceiptStore::new_box(FakeReceiptStore { journal, state })
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

/// 捕获的 DLX 记录字段：(tenant_id, message_id, producer_domain, contract_id, topic, payload, error_summary, num_attempts)。
type DlxRecord = (String, String, String, String, String, String, String, u32);

#[derive(Default)]
struct FakeDeadLetterStore {
    written: Mutex<Vec<DlxRecord>>,
    fail_writes: AtomicBool,
}

impl FakeDeadLetterStore {
    #[allow(clippy::unwrap_used)] // reason: 测试 Mutex，item-level carve-out
    fn records(&self) -> Vec<DlxRecord> {
        self.written.lock().unwrap().clone()
    }

    fn fail_writes(&self) {
        self.fail_writes.store(true, Ordering::SeqCst);
    }
}

impl DeadLetterStore for FakeDeadLetterStore {
    #[allow(clippy::unwrap_used)] // reason: 测试 Mutex，item-level carve-out
    async fn write_dead_letter(
        &self,
        record: DeadLetterRecord,
    ) -> Result<(), DeadLetterStoreError> {
        if self.fail_writes.load(Ordering::SeqCst) {
            return Err(DeadLetterStoreError::new(std::io::Error::other(
                "dlx inject",
            )));
        }
        self.written.lock().unwrap().push((
            record.tenant().to_string(),
            record.message_id().to_string(),
            record.producer_domain().to_string(),
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
    definitions: Mutex<HashMap<SagaInstanceRef, consistency::SagaDefinitionIdentity>>,
    identities: Mutex<HashMap<SagaInstanceRef, SagaWorkerIdentity>>,
    lease_lost: std::sync::atomic::AtomicBool,
    lose_after_extensions: AtomicU32,
    extensions: AtomicU32,
    releases: AtomicU32,
}

impl FakeInstanceStore {
    fn lose_lease(&self) {
        self.lease_lost.store(true, Ordering::SeqCst);
    }

    fn lose_after_extensions(&self, successful_extensions: u32) {
        self.lose_after_extensions
            .store(successful_extensions, Ordering::SeqCst);
    }

    fn extension_count(&self) -> u32 {
        self.extensions.load(Ordering::SeqCst)
    }

    #[allow(clippy::unwrap_used)]
    fn seed_status(&self, instance: SagaInstanceRef, status: SagaInstanceStatus) {
        self.registered.lock().unwrap().insert(instance, status);
    }

    #[allow(clippy::unwrap_used)]
    fn seed_definition(
        &self,
        instance: SagaInstanceRef,
        definition: consistency::SagaDefinitionIdentity,
    ) {
        self.definitions
            .lock()
            .unwrap()
            .insert(instance, definition);
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
        let existing_identity = self
            .identities
            .lock()
            .unwrap()
            .get(&registration.instance())
            .cloned();
        let existing_definition = self
            .definitions
            .lock()
            .unwrap()
            .get(&registration.instance())
            .cloned();
        if existing_identity
            .as_ref()
            .is_some_and(|identity| identity != registration.identity())
            || existing_definition
                .as_ref()
                .is_some_and(|definition| definition != registration.definition())
        {
            return Err(SagaInstanceStoreError::identity_conflict(
                std::io::Error::other("synthetic identity conflict"),
            ));
        }
        let mut rows = self.registered.lock().unwrap();
        let status = *rows
            .entry(registration.instance())
            .or_insert(SagaInstanceStatus::Ready);
        self.definitions
            .lock()
            .unwrap()
            .entry(registration.instance())
            .or_insert_with(|| registration.definition().clone());
        self.identities
            .lock()
            .unwrap()
            .entry(registration.instance())
            .or_insert_with(|| registration.identity().clone());
        SagaInstanceRecord::new(
            registration.instance(),
            status,
            registration.identity().clone(),
            registration.definition().clone(),
        )
        .map_err(SagaInstanceStoreError::new)
    }

    #[allow(clippy::unwrap_used)]
    async fn get(
        &self,
        instance: &SagaInstanceRef,
    ) -> Result<Option<SagaInstanceRecord>, SagaInstanceStoreError> {
        let status = self.registered.lock().unwrap().get(instance).copied();
        let definition = self
            .definitions
            .lock()
            .unwrap()
            .get(instance)
            .cloned()
            .unwrap_or_else(definition_identity);
        let identity = self
            .identities
            .lock()
            .unwrap()
            .get(instance)
            .cloned()
            .unwrap_or_else(worker_identity);
        status
            .map(|status| SagaInstanceRecord::new(*instance, status, identity, definition))
            .transpose()
            .map_err(SagaInstanceStoreError::new)
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
        let extension = self.extensions.fetch_add(1, Ordering::SeqCst) + 1;
        let lose_after = self.lose_after_extensions.load(Ordering::SeqCst);
        if self.lease_lost.load(Ordering::SeqCst) || (lose_after > 0 && extension > lose_after) {
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

    #[allow(clippy::unwrap_used)]
    async fn list_runnable(
        &self,
        _identity: &SagaWorkerIdentity,
        tenant: vocab::TenantId,
        limit: NonZeroUsize,
    ) -> Result<Vec<SagaRunnableInstance>, SagaInstanceStoreError> {
        let rows = self.registered.lock().unwrap();
        Ok(rows
            .iter()
            .filter(|(instance, status)| {
                instance.tenant() == tenant
                    && matches!(
                        status,
                        SagaInstanceStatus::Ready
                            | SagaInstanceStatus::Running
                            | SagaInstanceStatus::Compensating
                    )
            })
            .take(limit.get())
            .map(|(instance, status)| {
                let identity = self
                    .identities
                    .lock()
                    .unwrap()
                    .get(instance)
                    .cloned()
                    .unwrap_or_else(worker_identity);
                let definition = self
                    .definitions
                    .lock()
                    .unwrap()
                    .get(instance)
                    .cloned()
                    .unwrap_or_else(definition_identity);
                SagaRunnableInstance::new(*instance, *status, identity, definition).unwrap()
            })
            .collect())
    }

    async fn shutdown(&self) -> Result<(), SagaInstanceStoreError> {
        Ok(())
    }
}

// ── FakeRuntimeLockStore ─────────────────────────────────────────────────────

#[derive(Clone, Default)]
struct FakeRuntimeLockStore {
    held: Arc<AtomicBool>,
    fail_acquire: Arc<AtomicBool>,
    lose_on_renew: Arc<AtomicBool>,
    fail_renew: Arc<AtomicBool>,
    fail_release: Arc<AtomicBool>,
    block_first_acquire: Arc<AtomicBool>,
    first_acquire_entered: Arc<Notify>,
    release_blocked_acquire: Arc<Notify>,
    acquisitions: Arc<AtomicU32>,
    renewals: Arc<AtomicU32>,
    releases: Arc<AtomicU32>,
    keys: Arc<Mutex<Vec<String>>>,
}

impl FakeRuntimeLockStore {
    fn held() -> Self {
        let store = Self::default();
        store.held.store(true, Ordering::SeqCst);
        store
    }

    fn fail_acquire() -> Self {
        let store = Self::default();
        store.fail_acquire.store(true, Ordering::SeqCst);
        store
    }

    fn lose_on_renew() -> Self {
        let store = Self::default();
        store.lose_on_renew.store(true, Ordering::SeqCst);
        store
    }

    fn fail_renew() -> Self {
        let store = Self::default();
        store.fail_renew.store(true, Ordering::SeqCst);
        store
    }

    fn fail_release() -> Self {
        let store = Self::default();
        store.fail_release.store(true, Ordering::SeqCst);
        store
    }

    fn block_first_acquire() -> Self {
        let store = Self::default();
        store.block_first_acquire.store(true, Ordering::SeqCst);
        store
    }

    async fn wait_first_acquire_entered(&self) {
        self.first_acquire_entered.notified().await;
    }

    fn unblock_first_acquire(&self) {
        self.release_blocked_acquire.notify_one();
    }

    fn acquisition_count(&self) -> u32 {
        self.acquisitions.load(Ordering::SeqCst)
    }

    fn renewal_count(&self) -> u32 {
        self.renewals.load(Ordering::SeqCst)
    }

    fn release_count(&self) -> u32 {
        self.releases.load(Ordering::SeqCst)
    }

    #[allow(clippy::unwrap_used)]
    fn keys(&self) -> Vec<String> {
        self.keys.lock().unwrap().clone()
    }
}

impl LockStore for FakeRuntimeLockStore {
    #[allow(clippy::unwrap_used)]
    async fn acquire(
        &self,
        key: LockStoreKey,
        _ttl: Duration,
    ) -> Result<LockAcquireOutcome, LockStoreError> {
        self.acquisitions.fetch_add(1, Ordering::SeqCst);
        self.keys.lock().unwrap().push(key.as_str().to_string());
        if self.fail_acquire.load(Ordering::SeqCst) {
            return Err(LockStoreError::new(std::io::Error::other(
                "runtime lock acquire inject",
            )));
        }
        if self.block_first_acquire.swap(false, Ordering::SeqCst) {
            self.first_acquire_entered.notify_one();
            self.release_blocked_acquire.notified().await;
        }
        if self.held.load(Ordering::SeqCst) {
            Ok(LockAcquireOutcome::Held)
        } else {
            Ok(LockAcquireOutcome::Acquired {
                token: vocab::Epoch::new(1),
            })
        }
    }

    async fn renew(
        &self,
        _key: LockStoreKey,
        token: vocab::Epoch,
        _ttl: Duration,
    ) -> Result<LockRenewOutcome, LockStoreError> {
        self.renewals.fetch_add(1, Ordering::SeqCst);
        if self.fail_renew.load(Ordering::SeqCst) {
            return Err(LockStoreError::new(std::io::Error::other(
                "runtime lock renew inject",
            )));
        }
        if self.lose_on_renew.load(Ordering::SeqCst) {
            Ok(LockRenewOutcome::Lost)
        } else {
            Ok(LockRenewOutcome::Renewed { token })
        }
    }

    async fn release(
        &self,
        _key: LockStoreKey,
        _token: vocab::Epoch,
    ) -> Result<(), LockStoreError> {
        self.releases.fetch_add(1, Ordering::SeqCst);
        if self.fail_release.load(Ordering::SeqCst) {
            return Err(LockStoreError::new(std::io::Error::other(
                "runtime lock release inject",
            )));
        }
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), LockStoreError> {
        Ok(())
    }
}

// ── executor 构造 helper ──────────────────────────────────────────────────────

type Exec =
    SagaExecutorImpl<FakeJournal, FakeCheckpointStore, FakeDeadLetterStore, FakeInstanceStore>;

#[allow(clippy::panic)] // reason: 测试常量策略，失败表示 helper 输入写错
fn policy_from_millis(retry_millis: u64, timeout_millis: u64) -> SagaPolicy {
    let spec = vocab::SagaRuntimePolicySpec::from_static(
        if retry_millis == 0 { 1 } else { 1_000 },
        if timeout_millis == 0 {
            30_000
        } else {
            timeout_millis
        },
        vocab::SagaBackoff::Fixed,
        retry_millis,
        retry_millis,
        vocab::SagaJitter::None,
    );
    match SagaPolicy::try_from(spec) {
        Ok(policy) => policy,
        Err(err) => panic!("invalid test saga policy: {err}"),
    }
}

#[allow(clippy::expect_used)] // reason: table-driven tests provide statically valid policy values
fn policy_with_max_attempts(max_attempts: u32) -> SagaPolicy {
    SagaPolicy::try_from(vocab::SagaRuntimePolicySpec::from_static(
        max_attempts,
        30_000,
        vocab::SagaBackoff::Fixed,
        0,
        0,
        vocab::SagaJitter::None,
    ))
    .expect("valid synthetic saga policy")
}

fn disabled_policy() -> SagaPolicy {
    policy_from_millis(0, 0)
}

#[allow(clippy::expect_used)] // reason: 测试常量必须能构造合法 executor config
fn executor_config_with_policy_and_lease_ttl(
    _policy: SagaPolicy,
    lease_ttl: Duration,
) -> SagaExecutorConfig {
    SagaExecutorConfig::new(
        CheckpointOwner::new(OWNER),
        generated::saga::billing_v1::SPEC,
        "runner-a",
        lease_ttl,
    )
    .expect("valid test saga executor config")
}

#[test]
#[allow(clippy::expect_used)] // reason: invalid generated spec is the assertion failure
fn executor_config_from_contract_spec_derives_contract_and_policy() {
    let config = SagaExecutorConfig::from_contract_spec(
        CheckpointOwner::new(OWNER),
        "runner-a",
        Duration::from_secs(30),
        generated::saga::billing_v1::SPEC,
    )
    .expect("generated test spec is valid");

    assert_eq!(config.identity().contract_id().as_str(), CONTRACT);
    assert_eq!(config.definition(), &definition_identity());
}

fn ready_instance_store() -> Arc<FakeInstanceStore> {
    let store = Arc::new(FakeInstanceStore::default());
    store.seed_status(instance(), SagaInstanceStatus::Ready);
    store
}

fn runtime_lock_from(store: FakeRuntimeLockStore) -> SagaRuntimeLock {
    SagaRuntimeLock::new(store)
}

fn runtime_lock() -> SagaRuntimeLock {
    runtime_lock_from(FakeRuntimeLockStore::default())
}

struct ExecOptions {
    policy: SagaPolicy,
    lease_ttl: Duration,
    runtime_lock: SagaRuntimeLock,
    receipt_state: Arc<FakeReceiptState>,
}

impl ExecOptions {
    fn new(policy: SagaPolicy, lease_ttl: Duration, runtime_lock: SagaRuntimeLock) -> Self {
        Self {
            policy,
            lease_ttl,
            runtime_lock,
            receipt_state: Arc::new(FakeReceiptState::default()),
        }
    }

    fn with_receipt_state(mut self, receipt_state: Arc<FakeReceiptState>) -> Self {
        self.receipt_state = receipt_state;
        self
    }
}

fn executor_with_store_and_policy<J>(
    journal: Arc<J>,
    instance_store: Arc<FakeInstanceStore>,
    cp: Arc<FakeCheckpointStore>,
    dlx: Arc<FakeDeadLetterStore>,
    factory: Arc<dyn SagaActionFactory>,
    policy: SagaPolicy,
) -> SagaExecutorImpl<J, FakeCheckpointStore, FakeDeadLetterStore, FakeInstanceStore>
where
    J: FakeReceiptJournal + Send + Sync + 'static,
{
    executor_with_store_options(
        journal,
        instance_store,
        cp,
        dlx,
        factory,
        ExecOptions::new(policy, Duration::from_secs(30), runtime_lock()),
    )
}

#[allow(clippy::expect_used)]
fn executor_with_store_options<J>(
    journal: Arc<J>,
    instance_store: Arc<FakeInstanceStore>,
    cp: Arc<FakeCheckpointStore>,
    dlx: Arc<FakeDeadLetterStore>,
    factory: Arc<dyn SagaActionFactory>,
    options: ExecOptions,
) -> SagaExecutorImpl<J, FakeCheckpointStore, FakeDeadLetterStore, FakeInstanceStore>
where
    J: FakeReceiptJournal + Send + Sync + 'static,
{
    let receipt_store = fake_receipt_store(Arc::clone(&journal), options.receipt_state);
    let registry =
        SagaDefinitionRegistry::from_erased(definition_identity(), factory, options.policy);
    SagaExecutorImpl::new(
        SagaExecutorDeps::new(
            journal,
            receipt_store,
            instance_store,
            cp,
            dlx,
            registry,
            options.runtime_lock,
        ),
        executor_config_with_policy_and_lease_ttl(options.policy, options.lease_ttl),
    )
    .expect("test definition is registered")
}

fn executor_with_store_policy_and_lease_ttl<J>(
    journal: Arc<J>,
    instance_store: Arc<FakeInstanceStore>,
    cp: Arc<FakeCheckpointStore>,
    dlx: Arc<FakeDeadLetterStore>,
    factory: Arc<dyn SagaActionFactory>,
    policy: SagaPolicy,
    lease_ttl: Duration,
) -> SagaExecutorImpl<J, FakeCheckpointStore, FakeDeadLetterStore, FakeInstanceStore>
where
    J: FakeReceiptJournal + Send + Sync + 'static,
{
    executor_with_store_options(
        journal,
        instance_store,
        cp,
        dlx,
        factory,
        ExecOptions::new(policy, lease_ttl, runtime_lock()),
    )
}

fn executor_with_store<J>(
    journal: Arc<J>,
    instance_store: Arc<FakeInstanceStore>,
    cp: Arc<FakeCheckpointStore>,
    dlx: Arc<FakeDeadLetterStore>,
    factory: Arc<dyn SagaActionFactory>,
) -> SagaExecutorImpl<J, FakeCheckpointStore, FakeDeadLetterStore, FakeInstanceStore>
where
    J: FakeReceiptJournal + Send + Sync + 'static,
{
    executor_with_store_and_policy(journal, instance_store, cp, dlx, factory, disabled_policy())
}

fn executor_with_policy(
    journal: Arc<FakeJournal>,
    cp: Arc<FakeCheckpointStore>,
    dlx: Arc<FakeDeadLetterStore>,
    factory: Arc<dyn SagaActionFactory>,
    policy: SagaPolicy,
) -> Exec {
    executor_with_store_and_policy(journal, ready_instance_store(), cp, dlx, factory, policy)
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

impl FakeReceiptJournal for FakeJournalFailing {
    fn commit_receipt_completed(
        &self,
        instance: SagaInstanceRef,
        seq: u64,
        step_name: StepName,
    ) -> Result<SagaReceiptCommitOutcome, SagaReceiptStoreError> {
        if self.append_fails.load(Ordering::SeqCst)
            || self.fail_status == Some(SagaJournalStatus::Completed)
        {
            Err(SagaReceiptStoreError::new(
                SagaReceiptStoreErrorKind::Storage,
                std::io::Error::other("synthetic receipt commit failure"),
            ))
        } else if self.conflict_status == Some(SagaJournalStatus::Completed) {
            Ok(SagaReceiptCommitOutcome::Conflict)
        } else {
            Ok(self.inner.commit_completed(instance, seq, step_name))
        }
    }
}

#[allow(clippy::unwrap_used)] // reason: tracing capture test harness owns runtime/Mutex setup
fn capture_tracing_events<F, Fut>(
    level: tracing::Level,
    start_paused: bool,
    f: F,
) -> Vec<HashMap<String, String>>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    use tracing::field::{Field, Visit};
    use tracing::{Event, Subscriber};
    use tracing_subscriber::layer::{Context, Layer};
    use tracing_subscriber::prelude::*;

    struct CaptureLayer {
        events: Arc<Mutex<Vec<HashMap<String, String>>>>,
        level: tracing::Level,
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
            if *event.metadata().level() != self.level {
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
        level,
    });
    tracing::subscriber::with_default(subscriber, || {
        tracing::callsite::rebuild_interest_cache();
        let mut builder = tokio::runtime::Builder::new_current_thread();
        builder.enable_all();
        if start_paused {
            builder.start_paused(true);
        }
        let rt = builder.build().unwrap();
        rt.block_on(f());
        tracing::callsite::rebuild_interest_cache();
    });
    events.lock().unwrap().clone()
}

// ── T009.1 #1：3-step 全成 → journal 顺序 ──────────────────────────────────────

#[tokio::test]
async fn run_three_steps_all_succeed_journal_order() {
    let journal = Arc::new(FakeJournal::default());
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, counts) = FakeFactory::linear(&["step1", "step2", "step3"]);
    let exec = executor(journal.clone(), cp.clone(), dlx.clone(), factory);

    let outcome = exec.run(instance(), definition_identity()).await;

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

#[tokio::test]
async fn runtime_lock_busy_interrupts_before_instance_registration_or_journal() {
    let lock_store = FakeRuntimeLockStore::held();
    let runtime_lock = runtime_lock_from(lock_store.clone());
    let journal = Arc::new(FakeJournal::default());
    let store = Arc::new(FakeInstanceStore::default());
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, counts) = FakeFactory::linear(&["step1"]);
    let exec = executor_with_store_options(
        journal.clone(),
        store.clone(),
        cp,
        dlx.clone(),
        factory,
        ExecOptions::new(disabled_policy(), Duration::from_secs(30), runtime_lock),
    );

    let outcome = exec.run(instance(), definition_identity()).await;

    assert!(
        matches!(
            outcome,
            SagaOutcome::Interrupted {
                reason: SagaInterruption::RuntimeLockBusy
            }
        ),
        "runtime lock contention must interrupt without side effects: {outcome:?}"
    );
    assert_eq!(counts[0].dos(), 0, "action must not start");
    assert!(
        store.status(instance()).is_none(),
        "instance must not register"
    );
    assert!(journal.log().is_empty(), "journal must stay empty");
    assert!(dlx.records().is_empty(), "lock interruption must not DLX");
    assert_eq!(lock_store.acquisition_count(), 1);
    assert_eq!(
        lock_store.keys(),
        vec![format!("saga/{TENANT}/{}", saga_id().as_uuid())]
    );
}

#[tokio::test]
async fn runtime_lock_acquire_error_interrupts_without_journal() {
    let lock_store = FakeRuntimeLockStore::fail_acquire();
    let runtime_lock = runtime_lock_from(lock_store.clone());
    let journal = Arc::new(FakeJournal::default());
    let store = ready_instance_store();
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, counts) = FakeFactory::linear(&["step1"]);
    let exec = executor_with_store_options(
        journal.clone(),
        store,
        cp,
        dlx.clone(),
        factory,
        ExecOptions::new(disabled_policy(), Duration::from_secs(30), runtime_lock),
    );

    let outcome = exec.run(instance(), definition_identity()).await;

    assert!(
        matches!(
            outcome,
            SagaOutcome::Interrupted {
                reason: SagaInterruption::RuntimeLockUnavailable
            }
        ),
        "runtime lock infra failure must fail closed: {outcome:?}"
    );
    assert_eq!(counts[0].dos(), 0, "action must not start");
    assert!(journal.log().is_empty(), "journal must stay empty");
    assert!(dlx.records().is_empty(), "lock interruption must not DLX");
    assert_eq!(lock_store.release_count(), 0, "no grant to release");
}

#[tokio::test]
#[allow(clippy::expect_used)] // reason: WaitTimeout means distinct-key concurrency regressed
async fn runtime_lock_allows_different_saga_keys_to_enter_provider_concurrently() {
    let lock_store = FakeRuntimeLockStore::block_first_acquire();
    let runtime_lock = runtime_lock_from(lock_store.clone());
    let journal = Arc::new(FakeJournal::default());
    let store = Arc::new(FakeInstanceStore::default());
    store.seed_status(instance_with_id(0x1121), SagaInstanceStatus::Ready);
    store.seed_status(instance_with_id(0x1122), SagaInstanceStatus::Ready);
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, _counts) = FakeFactory::linear(&["step1"]);
    let exec = Arc::new(executor_with_store_options(
        journal,
        store,
        cp,
        dlx,
        factory,
        ExecOptions::new(disabled_policy(), Duration::from_secs(30), runtime_lock),
    ));

    let first = {
        let exec = Arc::clone(&exec);
        tokio::spawn(async move {
            exec.run(instance_with_id(0x1121), definition_identity())
                .await
        })
    };
    lock_store.wait_first_acquire_entered().await;
    let second = {
        let exec = Arc::clone(&exec);
        tokio::spawn(async move {
            exec.run(instance_with_id(0x1122), definition_identity())
                .await
        })
    };
    testkit::await_condition(Duration::from_secs(1), || {
        lock_store.acquisition_count() >= 2
    })
    .await
    .expect("second saga must acquire a distinct runtime lock within 1s");

    assert_eq!(
        lock_store.acquisition_count(),
        2,
        "different saga keys must not queue behind an executor-global runtime lock mutex"
    );
    lock_store.unblock_first_acquire();
    assert!(matches!(first.await, Ok(SagaOutcome::Succeeded { .. })));
    assert!(matches!(second.await, Ok(SagaOutcome::Succeeded { .. })));
}

#[tokio::test]
async fn runtime_lock_released_after_success() {
    let lock_store = FakeRuntimeLockStore::default();
    let runtime_lock = runtime_lock_from(lock_store.clone());
    let journal = Arc::new(FakeJournal::default());
    let store = ready_instance_store();
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, _counts) = FakeFactory::linear(&["step1"]);
    let exec = executor_with_store_options(
        journal,
        store,
        cp,
        dlx,
        factory,
        ExecOptions::new(disabled_policy(), Duration::from_secs(30), runtime_lock),
    );

    let outcome = exec.run(instance(), definition_identity()).await;

    assert!(
        matches!(outcome, SagaOutcome::Succeeded { .. }),
        "{outcome:?}"
    );
    assert_eq!(lock_store.release_count(), 1, "grant must be released");
}

#[test]
#[allow(clippy::expect_used)] // reason: missing event is the assertion failure
fn runtime_lock_busy_logs_context_fields() {
    let events = capture_tracing_events(tracing::Level::WARN, false, || async {
        let lock_store = FakeRuntimeLockStore::held();
        let runtime_lock = runtime_lock_from(lock_store);
        let journal = Arc::new(FakeJournal::default());
        let store = ready_instance_store();
        let cp = Arc::new(FakeCheckpointStore::default());
        let dlx = Arc::new(FakeDeadLetterStore::default());
        let (factory, _counts) = FakeFactory::linear(&["step1"]);
        let exec = executor_with_store_options(
            journal,
            store,
            cp,
            dlx,
            factory,
            ExecOptions::new(disabled_policy(), Duration::from_secs(30), runtime_lock),
        );

        let outcome = exec.run(instance(), definition_identity()).await;
        assert!(matches!(
            outcome,
            SagaOutcome::Interrupted {
                reason: SagaInterruption::RuntimeLockBusy
            }
        ));
    });

    let event = events
        .iter()
        .find(|event| {
            event
                .get("message")
                .is_some_and(|message| message.contains("saga: runtime lock interrupted"))
        })
        .expect("runtime lock interruption warning must be captured");
    let saga_id_string = saga_id().as_uuid().to_string();
    assert_eq!(event.get("tenant_id").map(String::as_str), Some(TENANT));
    assert_eq!(
        event.get("saga_id").map(String::as_str),
        Some(saga_id_string.as_str())
    );
    assert_eq!(event.get("contract_id").map(String::as_str), Some(CONTRACT));
    assert_eq!(event.get("operation").map(String::as_str), Some("run"));
    assert_eq!(
        event.get("reason").map(String::as_str),
        Some("runtime_lock_busy")
    );
}

#[tokio::test(start_paused = true)]
#[allow(clippy::expect_used)] // reason: timeout means runtime lock renewal is not wired
async fn runtime_lock_lost_interrupts_in_flight_action_and_releases_best_effort() {
    let lock_store = FakeRuntimeLockStore::lose_on_renew();
    let runtime_lock = runtime_lock_from(lock_store.clone());
    let journal = Arc::new(FakeJournal::default());
    let store = ready_instance_store();
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, counts) =
        FakeFactory::behaviors(&[("step1", FakeBehavior::Hang, FakeBehavior::Succeed)]);
    let exec = executor_with_store_options(
        journal.clone(),
        store,
        cp,
        dlx.clone(),
        factory,
        ExecOptions::new(disabled_policy(), Duration::from_millis(10), runtime_lock),
    );

    let outcome = tokio::time::timeout(
        Duration::from_millis(50),
        exec.run(instance(), definition_identity()),
    )
    .await
    .expect("runtime lock loss must interrupt a hanging action");

    assert!(
        matches!(
            outcome,
            SagaOutcome::Interrupted {
                reason: SagaInterruption::RuntimeLockLost
            }
        ),
        "runtime lock loss must interrupt without compensation: {outcome:?}"
    );
    assert_eq!(counts[0].dos(), 1, "forward action should start once");
    assert!(lock_store.renewal_count() >= 1);
    assert_eq!(
        lock_store.release_count(),
        1,
        "lost grant still attempts best-effort release"
    );
    assert!(
        journal
            .log()
            .contains(&("step1".to_string(), SagaJournalStatus::Executing)),
        "in-flight interrupted action keeps the Executing edge"
    );
    assert!(
        !journal
            .log()
            .contains(&("step1".to_string(), SagaJournalStatus::Completed)),
        "interrupted action must not be marked completed"
    );
    assert!(dlx.records().is_empty(), "lock interruption must not DLX");
}

#[test]
#[allow(clippy::expect_used)] // reason: missing event is the assertion failure
fn runtime_lock_release_failure_logs_context_fields() {
    let events = capture_tracing_events(tracing::Level::WARN, false, || async {
        let lock_store = FakeRuntimeLockStore::fail_release();
        let runtime_lock = runtime_lock_from(lock_store);
        let journal = Arc::new(FakeJournal::default());
        let store = ready_instance_store();
        let cp = Arc::new(FakeCheckpointStore::default());
        let dlx = Arc::new(FakeDeadLetterStore::default());
        let (factory, _counts) = FakeFactory::linear(&["step1"]);
        let exec = executor_with_store_options(
            journal,
            store,
            cp,
            dlx,
            factory,
            ExecOptions::new(disabled_policy(), Duration::from_secs(30), runtime_lock),
        );

        let outcome = exec.run(instance(), definition_identity()).await;
        assert!(matches!(outcome, SagaOutcome::Succeeded { .. }));
    });

    let event = events
        .iter()
        .find(|event| {
            event
                .get("message")
                .is_some_and(|message| message.contains("saga: runtime lock release failed"))
        })
        .expect("runtime lock release warning must be captured");
    let saga_id_string = saga_id().as_uuid().to_string();
    assert_eq!(event.get("tenant_id").map(String::as_str), Some(TENANT));
    assert_eq!(
        event.get("saga_id").map(String::as_str),
        Some(saga_id_string.as_str())
    );
    assert_eq!(event.get("contract_id").map(String::as_str), Some(CONTRACT));
    assert_eq!(event.get("operation").map(String::as_str), Some("run"));
    assert_eq!(
        event.get("reason").map(String::as_str),
        Some("runtime_lock_release_failed")
    );
}

#[tokio::test(start_paused = true)]
#[allow(clippy::expect_used)] // reason: timeout means runtime lock renewal error is not wired
async fn runtime_lock_renew_error_interrupts_as_unavailable_and_releases_best_effort() {
    let lock_store = FakeRuntimeLockStore::fail_renew();
    let runtime_lock = runtime_lock_from(lock_store.clone());
    let journal = Arc::new(FakeJournal::default());
    let store = ready_instance_store();
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, counts) =
        FakeFactory::behaviors(&[("step1", FakeBehavior::Hang, FakeBehavior::Succeed)]);
    let exec = executor_with_store_options(
        journal.clone(),
        store,
        cp,
        dlx.clone(),
        factory,
        ExecOptions::new(disabled_policy(), Duration::from_millis(10), runtime_lock),
    );

    let outcome = tokio::time::timeout(
        Duration::from_millis(50),
        exec.run(instance(), definition_identity()),
    )
    .await
    .expect("runtime lock renewal error must interrupt a hanging action");

    assert!(
        matches!(
            outcome,
            SagaOutcome::Interrupted {
                reason: SagaInterruption::RuntimeLockUnavailable
            }
        ),
        "runtime lock renewal infra error must fail closed: {outcome:?}"
    );
    assert_eq!(counts[0].dos(), 1, "forward action should start once");
    assert!(lock_store.renewal_count() >= 1);
    assert_eq!(lock_store.release_count(), 1, "grant release is attempted");
    assert!(
        journal
            .log()
            .contains(&("step1".to_string(), SagaJournalStatus::Executing)),
        "in-flight interrupted action keeps the Executing edge"
    );
    assert!(
        !journal
            .log()
            .contains(&("step1".to_string(), SagaJournalStatus::Completed)),
        "interrupted action must not be marked completed"
    );
    assert!(dlx.records().is_empty(), "lock interruption must not DLX");
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

    let outcome = exec.run(instance(), definition_identity()).await;

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

#[tokio::test]
async fn post_effect_serialization_failure_uses_same_run_typed_receipt_for_compensation() {
    let journal = Arc::new(FakeJournal::default());
    let store = ready_instance_store();
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, counts) = FakeFactory::behaviors(&[(
        "step1",
        FakeBehavior::PostEffectSerializeFail,
        FakeBehavior::Succeed,
    )]);
    let exec = executor_with_store(journal.clone(), store, cp, dlx, factory);

    let outcome = exec.run(instance(), definition_identity()).await;

    assert!(
        matches!(
            outcome,
            SagaOutcome::Failed {
                error: SagaActionError::InvariantViolation,
                ..
            }
        ),
        "post-effect invariant must be reported after compensation: {outcome:?}"
    );
    assert_eq!(counts[0].dos(), 1);
    assert_eq!(
        counts[0].undos(),
        1,
        "same-run typed receipt must be retained"
    );
    assert!(
        journal
            .log()
            .contains(&("step1".to_string(), SagaJournalStatus::Compensated))
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

    let outcome = exec.resume(instance(), definition_identity()).await;

    assert!(
        matches!(
            outcome,
            SagaOutcome::Interrupted {
                reason: SagaInterruption::ReceiptUnavailable
            }
        ),
        "{outcome:?}"
    );
    // 崩溃前完成的 step1 没有 durable receipt；#1924 前不得继续任何后续 effect。
    assert_eq!(counts[0].dos(), 0, "step1 应被跳过");
    assert_eq!(counts[1].dos(), 0, "receipt 缺失时 step2 不得执行");
    assert_eq!(counts[2].dos(), 0, "receipt 缺失时 step3 不得执行");
    let log = journal.log();
    assert!(
        !log.iter()
            .any(|(step, _)| step == "step2" || step == "step3")
    );
    assert_eq!(cp.offset(&checkpoint_id_str()), Some(1));
}

// ── #1651：runtime retry/timeout policy ───────────────────────────────────────

#[test]
fn saga_policy_rejects_zero_time_budget() {
    let spec = vocab::SagaRuntimePolicySpec::from_static(
        2,
        0,
        vocab::SagaBackoff::Fixed,
        5,
        5,
        vocab::SagaJitter::None,
    );
    assert!(
        SagaPolicy::try_from(spec).is_err(),
        "zero time budget must be invalid"
    );
}

#[test]
fn saga_idempotency_key_is_stable_phase_scoped_and_redacted() {
    let definition = definition_identity();
    let forward = super::SagaIdempotencyKey::derive(
        instance(),
        &definition,
        generated::saga::billing_v1::STEP_0,
        SagaEffectPhase::Forward,
    );
    let repeated = super::SagaIdempotencyKey::derive(
        instance(),
        &definition,
        generated::saga::billing_v1::STEP_0,
        SagaEffectPhase::Forward,
    );
    let compensation = super::SagaIdempotencyKey::derive(
        instance(),
        &definition,
        generated::saga::billing_v1::STEP_0,
        SagaEffectPhase::Compensation,
    );
    assert_eq!(forward, repeated);
    assert_ne!(forward, compensation);
    assert_eq!(
        forward.to_hex(),
        "81073854e3aaf07ca4383210de3d8ee75423db9bcf47b3c9f000293bad8e312f"
    );
    assert!(!format!("{forward:?}").contains(&forward.to_hex()));
}

#[test]
#[allow(clippy::expect_used)] // reason: synthetic vectors must be structurally valid
fn saga_idempotency_key_changes_for_every_effect_identity_dimension() {
    const OTHER_SCHEMA: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const OTHER_GENERATION: &str =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let definition = definition_identity();
    let step = generated::saga::billing_v1::STEP_0;
    let base =
        super::SagaIdempotencyKey::derive(instance(), &definition, step, SagaEffectPhase::Forward);
    let other_tenant = vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d480")
        .expect("valid alternate tenant");
    let tenant_instance =
        SagaInstanceRef::new(other_tenant, saga_id()).expect("valid alternate-tenant instance");

    let identity_variants = [
        consistency::SagaDefinitionIdentity::new(
            "billing.checkout-alt",
            definition.version(),
            definition.schema_digest(),
            definition.action_registry_generation(),
        )
        .expect("valid alternate contract identity"),
        consistency::SagaDefinitionIdentity::new(
            definition.contract_id(),
            "v999",
            definition.schema_digest(),
            definition.action_registry_generation(),
        )
        .expect("valid alternate version identity"),
        consistency::SagaDefinitionIdentity::new(
            definition.contract_id(),
            definition.version(),
            OTHER_SCHEMA,
            definition.action_registry_generation(),
        )
        .expect("valid alternate schema identity"),
        consistency::SagaDefinitionIdentity::new(
            definition.contract_id(),
            definition.version(),
            definition.schema_digest(),
            OTHER_GENERATION,
        )
        .expect("valid alternate action identity"),
    ];
    for changed in identity_variants {
        assert_ne!(
            base,
            super::SagaIdempotencyKey::derive(instance(), &changed, step, SagaEffectPhase::Forward,),
            "every pinned definition component must affect the key"
        );
    }

    let changed_step = vocab::SagaStepBinding::from_static(
        generated::saga::billing_v1::CONTRACT,
        "reserve_funds_alt",
        step.receipt_schema(),
        step.effect_scope(),
        step.compensation_effect_scope(),
        step.retry_class(),
    );
    let changed_forward_scope = vocab::SagaStepBinding::from_static(
        generated::saga::billing_v1::CONTRACT,
        step.name(),
        step.receipt_schema(),
        "billing.reserve-funds-alt",
        step.compensation_effect_scope(),
        step.retry_class(),
    );
    let changed_compensation_scope = vocab::SagaStepBinding::from_static(
        generated::saga::billing_v1::CONTRACT,
        step.name(),
        step.receipt_schema(),
        step.effect_scope(),
        "billing.release-funds-alt",
        step.retry_class(),
    );
    for changed in [changed_step, changed_forward_scope] {
        assert_ne!(
            base,
            super::SagaIdempotencyKey::derive(
                instance(),
                &definition,
                changed,
                SagaEffectPhase::Forward,
            )
        );
    }
    assert_ne!(
        base,
        super::SagaIdempotencyKey::derive(
            tenant_instance,
            &definition,
            step,
            SagaEffectPhase::Forward,
        )
    );
    assert_ne!(
        base,
        super::SagaIdempotencyKey::derive(
            instance_with_id(0x1122),
            &definition,
            step,
            SagaEffectPhase::Forward,
        )
    );

    let compensation = super::SagaIdempotencyKey::derive(
        instance(),
        &definition,
        step,
        SagaEffectPhase::Compensation,
    );
    assert_ne!(base, compensation, "phase must affect the key");
    assert_ne!(
        compensation,
        super::SagaIdempotencyKey::derive(
            instance(),
            &definition,
            changed_compensation_scope,
            SagaEffectPhase::Compensation,
        ),
        "phase-specific compensation scope must affect the key"
    );
}

#[tokio::test(start_paused = true)]
async fn saga_idempotency_key_is_constant_across_retry_attempts() {
    let journal = Arc::new(FakeJournal::default());
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let receipt_state = Arc::new(FakeReceiptState::default());
    let (factory, counts, observed_keys) = FakeFactory::retry_key_probe();
    let exec = executor_with_store_options(
        journal,
        ready_instance_store(),
        cp,
        dlx,
        factory,
        ExecOptions::new(
            policy_with_max_attempts(3),
            Duration::from_secs(30),
            runtime_lock(),
        )
        .with_receipt_state(Arc::clone(&receipt_state)),
    );

    let outcome = exec.run(instance(), definition_identity()).await;

    assert!(
        matches!(outcome, SagaOutcome::Succeeded { .. }),
        "{outcome:?}"
    );
    assert_eq!(counts[0].dos(), 3);
    let keys = observed_keys
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    assert_eq!(keys.len(), 3);
    assert!(keys.iter().all(|key| key == &keys[0]));
    assert_eq!(
        receipt_state.successful_attempts(),
        vec![3],
        "receipt metadata must retain the successful retry attempt"
    );
}

#[tokio::test(start_paused = true)]
async fn receipt_commit_unknown_never_compensates_or_replays_the_effect() {
    let journal = Arc::new(FakeJournal::default());
    let store = ready_instance_store();
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let receipt_state = Arc::new(FakeReceiptState::default());
    receipt_state.fail_commit_acknowledgement();
    let (factory, counts) = FakeFactory::linear(&["step1"]);
    let exec = executor_with_store_options(
        Arc::clone(&journal),
        Arc::clone(&store),
        cp,
        dlx,
        factory,
        ExecOptions::new(disabled_policy(), Duration::from_secs(30), runtime_lock())
            .with_receipt_state(receipt_state),
    );

    let outcome = exec.run(instance(), definition_identity()).await;

    assert!(
        matches!(
            outcome,
            SagaOutcome::Failed {
                error: SagaActionError::OutcomeUnknown,
                ..
            }
        ),
        "{outcome:?}"
    );
    assert_eq!(counts[0].dos(), 1, "the effect must execute exactly once");
    assert_eq!(counts[0].undos(), 0, "unknown commit must never compensate");
    assert_eq!(store.status(instance()), Some(SagaInstanceStatus::Degraded));
    assert!(
        journal
            .log()
            .iter()
            .any(|(_, status)| *status == SagaJournalStatus::Completed),
        "the provider may have committed before its acknowledgement was lost"
    );
}

#[test]
fn saga_failure_classification_is_closed_and_engine_invariant_stays_invariant() {
    use super::SagaFailureClass;

    for (error, expected) in [
        (SagaActionError::ActionFailed, SagaFailureClass::Transient),
        (
            SagaActionError::NonRetryableActionFailed,
            SagaFailureClass::Permanent,
        ),
        (
            SagaActionError::InvariantViolation,
            SagaFailureClass::Invariant,
        ),
        (
            SagaActionError::OutcomeUnknown,
            SagaFailureClass::OutcomeUnknown,
        ),
        (
            SagaActionError::OwnershipLost,
            SagaFailureClass::OwnershipLost,
        ),
    ] {
        assert_eq!(error.classification(), expected);
    }
    let mapped = super::engine_error_to_action_error(consistency::EngineError::new(
        consistency::EngineErrorKind::Invariant,
    ));
    assert!(matches!(mapped, SagaActionError::InvariantViolation));
    assert_eq!(mapped.classification(), SagaFailureClass::Invariant);
}

#[tokio::test(start_paused = true)]
async fn saga_retry_attempt_cap_includes_first_call_and_never_class_disables_retry() {
    for (max_attempts, expected_calls) in [(1, 1), (3, 3)] {
        let journal = Arc::new(FakeJournal::default());
        let cp = Arc::new(FakeCheckpointStore::default());
        let dlx = Arc::new(FakeDeadLetterStore::default());
        let (factory, counts) =
            FakeFactory::behaviors(&[("step1", FakeBehavior::Fail, FakeBehavior::Succeed)]);
        let exec = executor_with_policy(
            journal,
            cp,
            dlx,
            factory,
            policy_with_max_attempts(max_attempts),
        );

        let outcome = exec.run(instance(), definition_identity()).await;

        assert!(matches!(outcome, SagaOutcome::Failed { .. }), "{outcome:?}");
        assert_eq!(
            counts[0].dos(),
            expected_calls,
            "maxAttempts includes the first call"
        );
    }

    let journal = Arc::new(FakeJournal::default());
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, counts) = FakeFactory::behaviors_with_retry_class(&[(
        "step1",
        FakeBehavior::FailTimes(1),
        FakeBehavior::Succeed,
        vocab::SagaRetryClass::Never,
    )]);
    let exec = executor_with_policy(journal, cp, dlx, factory, policy_with_max_attempts(3));

    let outcome = exec.run(instance(), definition_identity()).await;

    assert!(matches!(outcome, SagaOutcome::Failed { .. }), "{outcome:?}");
    assert_eq!(
        counts[0].dos(),
        1,
        "Never steps must not retry transient errors"
    );
}

#[test]
#[allow(clippy::expect_used)]
fn saga_policy_backoff_saturates_and_full_jitter_stays_inclusive() {
    let exponential = SagaPolicy::try_from(vocab::SagaRuntimePolicySpec::from_static(
        u32::MAX,
        u64::MAX,
        vocab::SagaBackoff::Exponential,
        u64::MAX,
        u64::MAX,
        vocab::SagaJitter::None,
    ))
    .expect("valid saturated policy");
    assert_eq!(
        exponential.delay_for(u32::MAX, 0),
        Duration::from_millis(u64::MAX)
    );

    let jitter = SagaPolicy::try_from(vocab::SagaRuntimePolicySpec::from_static(
        2,
        100,
        vocab::SagaBackoff::Fixed,
        10,
        10,
        vocab::SagaJitter::Full,
    ))
    .expect("valid jitter policy");
    assert!(jitter.delay_for(1, u64::MAX) <= Duration::from_millis(10));
}

#[test]
fn retry_entropy_test_seam_is_deterministic_but_attempt_scoped() {
    let first = super::saga_retry_entropy(
        instance(),
        "reserve_funds",
        super::SagaActionPhase::Forward,
        1,
    );
    assert_eq!(
        first,
        super::saga_retry_entropy(
            instance(),
            "reserve_funds",
            super::SagaActionPhase::Forward,
            1,
        )
    );
    assert_ne!(
        first,
        super::saga_retry_entropy(
            instance(),
            "reserve_funds",
            super::SagaActionPhase::Forward,
            2,
        )
    );
}

#[test]
fn registry_error_preserves_invalid_policy_kind() {
    let error = super::SagaDefinitionRegistryError::from(super::SagaPolicyError::ZeroAttempts);
    assert!(matches!(
        error,
        super::SagaDefinitionRegistryError::InvalidPolicy(super::SagaPolicyError::ZeroAttempts)
    ));
}

#[tokio::test(start_paused = true)]
async fn policy_retries_forward_action_until_success_within_budget() {
    let journal = Arc::new(FakeJournal::default());
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, counts) =
        FakeFactory::behaviors(&[("step1", FakeBehavior::FailTimes(2), FakeBehavior::Succeed)]);
    let exec = executor_with_policy(
        journal.clone(),
        cp.clone(),
        dlx.clone(),
        factory,
        policy_from_millis(5, 50),
    );

    let outcome = exec.run(instance(), definition_identity()).await;

    assert!(
        matches!(outcome, SagaOutcome::Succeeded { .. }),
        "{outcome:?}"
    );
    assert_eq!(counts[0].dos(), 3, "forward action should be retried twice");
    assert_eq!(counts[0].undos(), 0);
    assert_eq!(
        journal.log(),
        vec![
            ("step1".to_string(), SagaJournalStatus::Executing),
            ("step1".to_string(), SagaJournalStatus::Completed),
        ],
        "per-attempt retry must not duplicate durable step journal"
    );
    assert_eq!(cp.offset(&checkpoint_id_str()), Some(1));
    assert!(dlx.records().is_empty());
}

#[tokio::test(start_paused = true)]
#[allow(clippy::panic)] // reason: 测试断言分支，item-level carve-out
async fn policy_forward_timeout_fails_closed_without_compensating_prefix() {
    let journal = Arc::new(FakeJournal::default());
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, counts) = FakeFactory::behaviors(&[
        ("step1", FakeBehavior::Succeed, FakeBehavior::Succeed),
        ("step2", FakeBehavior::Hang, FakeBehavior::Succeed),
        ("step3", FakeBehavior::Succeed, FakeBehavior::Succeed),
    ]);
    let store = ready_instance_store();
    let exec = executor_with_store_and_policy(
        journal.clone(),
        store.clone(),
        cp,
        dlx.clone(),
        factory,
        policy_from_millis(0, 10),
    );

    let outcome = exec.run(instance(), definition_identity()).await;

    match outcome {
        SagaOutcome::Failed { failed_node, error } => {
            assert_eq!(failed_node, "step2");
            assert!(
                matches!(error, SagaActionError::ActionTimedOut),
                "expected forward timeout, got {error:?}"
            );
        }
        other => panic!("expected Failed, got {other:?}"),
    }
    assert_eq!(counts[0].dos(), 1);
    assert_eq!(
        counts[0].undos(),
        0,
        "unknown outcome must not trigger compensation"
    );
    assert_eq!(counts[1].dos(), 1);
    assert_eq!(
        counts[2].dos(),
        0,
        "steps after timed-out step must not run"
    );
    assert!(
        dlx.records().is_empty(),
        "forward timeout alone must not DLX"
    );
    assert!(
        !journal.log().iter().any(|(_, status)| matches!(
            status,
            SagaJournalStatus::Compensating | SagaJournalStatus::Compensated
        )),
        "unknown outcome must not write compensation journal rows"
    );
    assert_eq!(store.status(instance()), Some(SagaInstanceStatus::Degraded));
}

#[tokio::test(start_paused = true)]
#[allow(clippy::panic)] // reason: 测试断言分支，item-level carve-out
async fn policy_time_budget_exhaustion_fails_closed() {
    let journal = Arc::new(FakeJournal::default());
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, counts) = FakeFactory::behaviors(&[
        ("step1", FakeBehavior::Succeed, FakeBehavior::Succeed),
        ("step2", FakeBehavior::Fail, FakeBehavior::Succeed),
    ]);
    let store = ready_instance_store();
    let exec = executor_with_store_and_policy(
        journal,
        store.clone(),
        cp,
        dlx.clone(),
        factory,
        policy_from_millis(5, 12),
    );

    let outcome = exec.run(instance(), definition_identity()).await;

    match outcome {
        SagaOutcome::Failed { failed_node, error } => {
            assert_eq!(failed_node, "step2");
            assert!(
                matches!(error, SagaActionError::ActionTimedOut),
                "retry budget exhaustion should surface as timeout, got {error:?}"
            );
        }
        other => panic!("expected Failed, got {other:?}"),
    }
    assert!(
        counts[1].dos() > 1,
        "step2 should retry before budget expires"
    );
    assert_eq!(
        counts[0].undos(),
        0,
        "unknown outcome must not be compensated"
    );
    assert!(dlx.records().is_empty());
    assert_eq!(store.status(instance()), Some(SagaInstanceStatus::Degraded));
}

#[tokio::test(start_paused = true)]
#[allow(clippy::panic)] // reason: 测试断言分支，item-level carve-out
async fn policy_retries_compensation_action_until_success_within_budget() {
    let journal = Arc::new(FakeJournal::default());
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, counts) = FakeFactory::behaviors(&[
        ("step1", FakeBehavior::Succeed, FakeBehavior::FailTimes(2)),
        ("step2", FakeBehavior::SerializeFail, FakeBehavior::Succeed),
    ]);
    let exec = executor_with_policy(
        journal.clone(),
        cp,
        dlx.clone(),
        factory,
        policy_from_millis(5, 50),
    );

    let outcome = exec.run(instance(), definition_identity()).await;

    match outcome {
        SagaOutcome::Failed { failed_node, error } => {
            assert_eq!(failed_node, "step2");
            assert!(
                matches!(error, SagaActionError::SerializeFailed),
                "original non-retryable forward error must be preserved, got {error:?}"
            );
        }
        other => panic!("expected Failed, got {other:?}"),
    }
    assert_eq!(
        counts[0].undos(),
        3,
        "compensation should retry twice then succeed"
    );
    assert!(
        journal
            .log()
            .contains(&("step1".to_string(), SagaJournalStatus::Compensated)),
        "successful compensation retry must write Compensated"
    );
    assert!(
        !journal
            .log()
            .contains(&("step1".to_string(), SagaJournalStatus::Failed)),
        "successful compensation retry must not write Failed"
    );
    assert!(dlx.records().is_empty());
}

#[tokio::test(start_paused = true)]
#[allow(clippy::panic)] // reason: 测试断言分支，item-level carve-out
async fn policy_compensation_timeout_fails_closed_without_dead_letter() {
    let journal = Arc::new(FakeJournal::default());
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, counts) = FakeFactory::behaviors(&[
        ("step1", FakeBehavior::Succeed, FakeBehavior::Hang),
        ("step2", FakeBehavior::SerializeFail, FakeBehavior::Succeed),
    ]);
    let store = ready_instance_store();
    let exec = executor_with_store_and_policy(
        journal.clone(),
        store.clone(),
        cp,
        dlx.clone(),
        factory,
        policy_from_millis(0, 10),
    );

    let outcome = exec.run(instance(), definition_identity()).await;

    match outcome {
        SagaOutcome::Failed { failed_node, error } => {
            assert_eq!(failed_node, "step1");
            assert!(
                matches!(error, SagaActionError::ActionTimedOut),
                "expected compensation timeout, got {error:?}"
            );
        }
        other => panic!("expected Failed, got {other:?}"),
    }
    assert_eq!(counts[0].undos(), 1, "hung compensation is attempted once");
    assert!(
        dlx.records().is_empty(),
        "unknown compensation outcome must not DLX"
    );
    assert!(
        !journal
            .log()
            .contains(&("step1".to_string(), SagaJournalStatus::Failed)),
        "unknown compensation outcome must not assert a known Failed result"
    );
    assert_eq!(store.status(instance()), Some(SagaInstanceStatus::Degraded));
}

#[tokio::test(start_paused = true)]
async fn policy_renews_lease_during_forward_action_and_interrupts_on_loss() {
    let journal = Arc::new(FakeJournal::default());
    let store = ready_instance_store();
    store.lose_after_extensions(1);
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, counts) =
        FakeFactory::behaviors(&[("step1", FakeBehavior::Hang, FakeBehavior::Succeed)]);
    let exec = executor_with_store_policy_and_lease_ttl(
        journal.clone(),
        store.clone(),
        cp,
        dlx.clone(),
        factory,
        policy_from_millis(0, 100),
        Duration::from_millis(10),
    );

    let outcome = exec.run(instance(), definition_identity()).await;

    assert!(
        matches!(
            outcome,
            SagaOutcome::Interrupted {
                reason: SagaInterruption::LeaseLost
            }
        ),
        "bounded action must stop when in-phase lease renewal is lost: {outcome:?}"
    );
    assert_eq!(counts[0].dos(), 1, "forward action should start once");
    assert!(
        store.extension_count() >= 2,
        "pre-step refresh plus in-phase renewal should be attempted"
    );
    assert!(
        journal
            .log()
            .contains(&("step1".to_string(), SagaJournalStatus::Executing)),
        "interrupted in-flight action keeps only the durable Executing edge"
    );
    assert!(
        !journal
            .log()
            .contains(&("step1".to_string(), SagaJournalStatus::Completed)),
        "lease-lost action must not be marked completed"
    );
    assert!(dlx.records().is_empty(), "lease interruption must not DLX");
}

#[tokio::test(start_paused = true)]
#[allow(clippy::expect_used)] // reason: timeout means the lease-loss interrupt regressed
async fn disabled_policy_renews_lease_during_forward_action_and_interrupts_on_loss() {
    let journal = Arc::new(FakeJournal::default());
    let store = ready_instance_store();
    store.lose_after_extensions(1);
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, counts) =
        FakeFactory::behaviors(&[("step1", FakeBehavior::Hang, FakeBehavior::Succeed)]);
    let exec = executor_with_store_policy_and_lease_ttl(
        journal.clone(),
        store.clone(),
        cp,
        dlx.clone(),
        factory,
        disabled_policy(),
        Duration::from_millis(10),
    );

    let outcome = tokio::time::timeout(
        Duration::from_millis(50),
        exec.run(instance(), definition_identity()),
    )
    .await
    .expect("disabled policy must stop when in-phase lease renewal is lost");

    assert!(
        matches!(
            outcome,
            SagaOutcome::Interrupted {
                reason: SagaInterruption::LeaseLost
            }
        ),
        "disabled action must stop on lease loss: {outcome:?}"
    );
    assert_eq!(counts[0].dos(), 1, "forward action should start once");
    assert!(
        store.extension_count() >= 2,
        "pre-step refresh plus disabled in-phase renewal should be attempted"
    );
    assert!(
        !journal
            .log()
            .contains(&("step1".to_string(), SagaJournalStatus::Completed)),
        "lease-lost disabled action must not be marked completed"
    );
    assert!(dlx.records().is_empty(), "lease interruption must not DLX");
}

#[tokio::test(start_paused = true)]
#[allow(clippy::expect_used)] // reason: timeout means the lease-loss interrupt regressed
async fn disabled_policy_renews_lease_during_compensation_action_and_interrupts_on_loss() {
    let journal = Arc::new(FakeJournal::default());
    let store = ready_instance_store();
    store.lose_after_extensions(4);
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, counts) = FakeFactory::behaviors(&[
        ("step1", FakeBehavior::Succeed, FakeBehavior::Hang),
        ("step2", FakeBehavior::SerializeFail, FakeBehavior::Succeed),
    ]);
    let exec = executor_with_store_policy_and_lease_ttl(
        journal.clone(),
        store.clone(),
        cp,
        dlx.clone(),
        factory,
        disabled_policy(),
        Duration::from_millis(10),
    );

    let outcome = tokio::time::timeout(
        Duration::from_millis(50),
        exec.run(instance(), definition_identity()),
    )
    .await
    .expect("disabled compensation must stop when in-phase lease renewal is lost");

    assert!(
        matches!(
            outcome,
            SagaOutcome::Interrupted {
                reason: SagaInterruption::LeaseLost
            }
        ),
        "disabled compensation must stop on lease loss: {outcome:?}"
    );
    assert_eq!(counts[0].undos(), 1, "compensation should start once");
    assert!(
        store.extension_count() >= 5,
        "forward refreshes, compensation pre-action refreshes, and in-phase renewal should be attempted"
    );
    assert!(
        !journal
            .log()
            .contains(&("step1".to_string(), SagaJournalStatus::Failed)),
        "lease-lost compensation must not write Failed journal row"
    );
    assert!(dlx.records().is_empty(), "lease interruption must not DLX");
}

#[test]
#[allow(clippy::expect_used)] // reason: missing event is the assertion failure
fn policy_forward_timeout_logs_structured_warning() {
    let events = capture_tracing_events(tracing::Level::WARN, true, || async {
        let journal = Arc::new(FakeJournal::default());
        let cp = Arc::new(FakeCheckpointStore::default());
        let dlx = Arc::new(FakeDeadLetterStore::default());
        let (factory, _counts) =
            FakeFactory::behaviors(&[("step1", FakeBehavior::Hang, FakeBehavior::Succeed)]);
        let exec = executor_with_policy(journal, cp, dlx, factory, policy_from_millis(0, 10));

        let outcome = exec.run(instance(), definition_identity()).await;
        assert!(
            matches!(
                outcome,
                SagaOutcome::Failed {
                    error: SagaActionError::ActionTimedOut,
                    ..
                }
            ),
            "test must drive the timeout path: {outcome:?}"
        );
    });

    let timeout = events
        .iter()
        .find(|event| {
            event
                .get("message")
                .is_some_and(|message| message.contains("saga: action timed out"))
        })
        .expect("action timeout warning event must be captured");
    assert!(
        timeout
            .get("tenant_id")
            .is_some_and(|value| !value.is_empty()),
        "缺 tenant_id: {timeout:?}"
    );
    assert!(
        timeout
            .get("saga_id")
            .is_some_and(|value| !value.is_empty()),
        "缺 saga_id: {timeout:?}"
    );
    assert_eq!(
        timeout.get("contract_id").map(String::as_str),
        Some(CONTRACT)
    );
    assert_eq!(timeout.get("step_name").map(String::as_str), Some("step1"));
    assert_eq!(timeout.get("phase").map(String::as_str), Some("forward"));
    assert_eq!(
        timeout.get("step_timeout_ms").map(String::as_str),
        Some("10")
    );
    assert_eq!(timeout.get("max_attempts").map(String::as_str), Some("1"));
}

#[test]
#[allow(clippy::expect_used)] // reason: missing event is the assertion failure
fn policy_retry_debug_logs_error_kind_without_warning_amplification() {
    let events = capture_tracing_events(tracing::Level::DEBUG, true, || async {
        let journal = Arc::new(FakeJournal::default());
        let cp = Arc::new(FakeCheckpointStore::default());
        let dlx = Arc::new(FakeDeadLetterStore::default());
        let (factory, _counts) =
            FakeFactory::behaviors(&[("step1", FakeBehavior::FailTimes(1), FakeBehavior::Succeed)]);
        let exec = executor_with_policy(journal, cp, dlx, factory, policy_from_millis(1, 20));

        let outcome = exec.run(instance(), definition_identity()).await;
        assert!(
            matches!(outcome, SagaOutcome::Succeeded { .. }),
            "test must drive one retry then success: {outcome:?}"
        );
    });

    let retry = events
        .iter()
        .find(|event| {
            event
                .get("message")
                .is_some_and(|message| message.contains("saga: action failed, retrying"))
        })
        .expect("action retry debug event must be captured");
    assert_eq!(retry.get("phase").map(String::as_str), Some("forward"));
    assert_eq!(
        retry.get("error_kind").map(String::as_str),
        Some("action_failed")
    );
}

#[test]
#[allow(clippy::expect_used)] // reason: missing event is the assertion failure
fn policy_non_retryable_warning_logs_not_retrying() {
    let events = capture_tracing_events(tracing::Level::WARN, true, || async {
        let journal = Arc::new(FakeJournal::default());
        let cp = Arc::new(FakeCheckpointStore::default());
        let dlx = Arc::new(FakeDeadLetterStore::default());
        let (factory, _counts) = FakeFactory::behaviors(&[(
            "step1",
            FakeBehavior::SerializeFail,
            FakeBehavior::Succeed,
        )]);
        let exec = executor_with_policy(journal, cp, dlx, factory, policy_from_millis(1, 20));

        let outcome = exec.run(instance(), definition_identity()).await;
        assert!(
            matches!(
                outcome,
                SagaOutcome::Failed {
                    error: SagaActionError::SerializeFailed,
                    ..
                }
            ),
            "test must drive non-retryable forward failure: {outcome:?}"
        );
    });

    let not_retrying = events
        .iter()
        .find(|event| {
            event
                .get("message")
                .is_some_and(|message| message.contains("saga: action failed, not retrying"))
        })
        .expect("non-retryable action warning event must be captured");
    assert_eq!(
        not_retrying.get("phase").map(String::as_str),
        Some("forward")
    );
    assert_eq!(
        not_retrying.get("error_kind").map(String::as_str),
        Some("serialize_failed")
    );
    assert!(
        events.iter().all(|event| {
            !event
                .get("message")
                .is_some_and(|message| message.contains("saga: action failed, retrying"))
        }),
        "non-retryable error must not emit retrying warning: {events:?}"
    );
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

    let outcome = exec.run(instance(), definition_identity()).await;

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

#[test]
#[allow(clippy::expect_used)] // reason: missing metric is the assertion failure
#[allow(clippy::unwrap_used)] // reason: test runtime construction
fn compensation_failure_emits_dead_letter_metric() {
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    metrics::with_local_recorder(&recorder, || {
        rt.block_on(async {
            let journal = Arc::new(FakeJournal::default());
            let cp = Arc::new(FakeCheckpointStore::default());
            let dlx = Arc::new(FakeDeadLetterStore::default());
            let (factory, _counts) =
                FakeFactory::steps(&[("step1", false, true), ("step2", true, false)]);
            let exec = executor(journal, cp, dlx, factory);

            let outcome = exec.run(instance(), definition_identity()).await;
            assert!(
                matches!(outcome, SagaOutcome::Failed { .. }),
                "test must drive compensation DLX: {outcome:?}"
            );
        });
    });

    let rendered = handle.render();
    assert!(
        rendered.contains("saga_dead_letters_total"),
        "缺 saga DLX metric: {rendered}"
    );
    assert!(rendered.contains("domain=\"billing\""), "{rendered}");
    assert!(
        rendered.contains("contract_id=\"billing.checkout\""),
        "{rendered}"
    );
    assert!(rendered.contains("outcome=\"written\""), "{rendered}");
}

#[test]
#[allow(clippy::expect_used)] // reason: missing event/metric is the assertion failure
fn compensation_dead_letter_write_error_logs_fields() {
    let events = capture_tracing_events(tracing::Level::ERROR, false, || async {
        let journal = Arc::new(FakeJournal::default());
        let cp = Arc::new(FakeCheckpointStore::default());
        let dlx = Arc::new(FakeDeadLetterStore::default());
        dlx.fail_writes();
        let (factory, _counts) =
            FakeFactory::steps(&[("step1", false, true), ("step2", true, false)]);
        let exec = executor(journal, cp, dlx, factory);

        let outcome = exec.run(instance(), definition_identity()).await;
        assert!(
            matches!(outcome, SagaOutcome::Failed { .. }),
            "test must drive compensation DLX write error: {outcome:?}"
        );
    });

    let write_error = events
        .iter()
        .find(|event| {
            event
                .get("message")
                .is_some_and(|message| message.contains("saga: dead-letter write failed"))
        })
        .expect("dlx write failure error event must be captured");
    assert_eq!(write_error.get("domain").map(String::as_str), Some(OWNER));
    assert_eq!(
        write_error.get("contract_id").map(String::as_str),
        Some(CONTRACT)
    );
    assert_eq!(
        write_error.get("error").map(String::as_str),
        Some("dead letter write failed")
    );
}

#[test]
#[allow(clippy::expect_used)] // reason: missing metric is the assertion failure
#[allow(clippy::unwrap_used)] // reason: test runtime construction
fn compensation_dead_letter_write_error_emits_metric() {
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    metrics::with_local_recorder(&recorder, || {
        rt.block_on(async {
            let journal = Arc::new(FakeJournal::default());
            let cp = Arc::new(FakeCheckpointStore::default());
            let dlx = Arc::new(FakeDeadLetterStore::default());
            dlx.fail_writes();
            let (factory, _counts) =
                FakeFactory::steps(&[("step1", false, true), ("step2", true, false)]);
            let exec = executor(journal, cp, dlx, factory);

            let outcome = exec.run(instance(), definition_identity()).await;
            assert!(
                matches!(outcome, SagaOutcome::Failed { .. }),
                "test must drive compensation DLX write error: {outcome:?}"
            );
        });
    });

    let rendered = handle.render();
    assert!(
        rendered.contains("saga_dead_letters_total"),
        "缺 saga DLX metric: {rendered}"
    );
    assert!(rendered.contains("outcome=\"write_error\""), "{rendered}");
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

    let outcome = exec.resume(instance(), definition_identity()).await;

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

    let outcome = exec.run(instance(), definition_identity()).await;

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

    let outcome = exec.run(instance(), definition_identity()).await;

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

    let outcome = exec.run(instance(), definition_identity()).await;
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

    let resumed = exec.resume(instance(), definition_identity()).await;
    assert!(
        matches!(resumed, SagaOutcome::Succeeded { .. }),
        "terminal resume should not wait for old TTL: {resumed:?}"
    );
    let restarted = exec.run(instance(), definition_identity()).await;
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

    let outcome = exec.resume(instance(), definition_identity()).await;

    assert!(matches!(outcome, SagaOutcome::Failed { .. }), "{outcome:?}");
    assert_eq!(
        store.status(instance()),
        None,
        "resume of unknown instance must not create saga_instances row"
    );
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn resume_unknown_pinned_definition_fails_closed_without_running_actions() {
    const OTHER_SCHEMA: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const OTHER_GENERATION: &str =
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let selected = definition_identity();
    let unsupported = [
        (
            "version",
            consistency::SagaDefinitionIdentity::new(
                CONTRACT,
                "v999",
                selected.schema_digest(),
                selected.action_registry_generation(),
            )
            .expect("synthetic unsupported version is structurally valid"),
        ),
        (
            "schema",
            consistency::SagaDefinitionIdentity::new(
                CONTRACT,
                selected.version(),
                OTHER_SCHEMA,
                selected.action_registry_generation(),
            )
            .expect("synthetic unsupported schema is structurally valid"),
        ),
        (
            "action generation",
            consistency::SagaDefinitionIdentity::new(
                CONTRACT,
                selected.version(),
                selected.schema_digest(),
                OTHER_GENERATION,
            )
            .expect("synthetic unsupported action generation is structurally valid"),
        ),
    ];

    for (dimension, pinned) in unsupported {
        let journal = Arc::new(FakeJournal::default());
        let store = Arc::new(FakeInstanceStore::default());
        store.seed_status(instance(), SagaInstanceStatus::Ready);
        store.seed_definition(instance(), pinned);
        let cp = Arc::new(FakeCheckpointStore::default());
        let dlx = Arc::new(FakeDeadLetterStore::default());
        let (factory, counts) = FakeFactory::linear(&["step1"]);
        let exec = executor_with_store(journal, store.clone(), cp, dlx, factory);

        let outcome = exec.resume(instance(), selected.clone()).await;

        assert!(
            matches!(
                outcome,
                SagaOutcome::Interrupted {
                    reason: SagaInterruption::UnsupportedDefinition
                }
            ),
            "unknown pinned {dimension} must fail closed: {outcome:?}"
        );
        assert_eq!(counts[0].dos(), 0, "unsupported {dimension} must not run");
        assert_eq!(
            counts[0].undos(),
            0,
            "unsupported {dimension} must not compensate"
        );
        assert_eq!(store.status(instance()), Some(SagaInstanceStatus::Degraded));
    }
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn resume_registered_old_definition_uses_its_exact_factory_and_policy() {
    let journal = Arc::new(FakeJournal::default());
    let store = Arc::new(FakeInstanceStore::default());
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let old_definition = consistency::SagaDefinitionIdentity::new(
        CONTRACT,
        "v2",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    )
    .unwrap();
    let registration = SagaInstanceRegistration::new(
        instance(),
        SagaWorkerIdentity::new("billing", SagaContractId::parse(CONTRACT).unwrap()).unwrap(),
        old_definition.clone(),
    )
    .unwrap();
    store.register(registration).await.unwrap();
    store.seed_status(instance(), SagaInstanceStatus::Running);

    let (selected_factory, selected_counts) = FakeFactory::linear(&["step1"]);
    let (old_factory, old_counts) = FakeFactory::linear(&["step1"]);
    let registry = SagaDefinitionRegistry::from_erased(
        definition_identity(),
        selected_factory,
        disabled_policy(),
    )
    .with_erased(old_definition.clone(), old_factory, disabled_policy());
    let receipt_store =
        fake_receipt_store(Arc::clone(&journal), Arc::new(FakeReceiptState::default()));
    let deps = SagaExecutorDeps::new(
        journal,
        receipt_store,
        store,
        cp,
        dlx,
        registry,
        runtime_lock(),
    );
    let exec = SagaExecutorImpl::new(
        deps,
        executor_config_with_policy_and_lease_ttl(disabled_policy(), Duration::from_secs(30)),
    )
    .unwrap();

    let outcome = exec.resume(instance(), old_definition).await;

    assert!(
        matches!(outcome, SagaOutcome::Succeeded { .. }),
        "{outcome:?}"
    );
    assert_eq!(
        old_counts[0].dos(),
        1,
        "old definition factory must execute"
    );
    assert_eq!(
        selected_counts[0].dos(),
        0,
        "selected start factory must not leak into resume"
    );
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn run_existing_ready_validates_owner_through_typed_registration_conflict() {
    let journal = Arc::new(FakeJournal::default());
    let store = Arc::new(FakeInstanceStore::default());
    let foreign_registration = SagaInstanceRegistration::new(
        instance(),
        SagaWorkerIdentity::new("foreign-owner", SagaContractId::parse(CONTRACT).unwrap()).unwrap(),
        definition_identity(),
    )
    .unwrap();
    store.register(foreign_registration).await.unwrap();
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, counts) = FakeFactory::linear(&["step1"]);
    let exec = executor_with_store(journal, store, cp, dlx, factory);

    let outcome = exec.run(instance(), definition_identity()).await;

    assert!(
        matches!(
            outcome,
            SagaOutcome::Interrupted {
                reason: SagaInterruption::UnsupportedDefinition
            }
        ),
        "owner conflict must fail closed: {outcome:?}"
    );
    assert_eq!(counts[0].dos(), 0);
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn resume_rejects_foreign_owner_with_same_contract_and_definition() {
    let journal = Arc::new(FakeJournal::default());
    let store = Arc::new(FakeInstanceStore::default());
    let foreign_registration = SagaInstanceRegistration::new(
        instance(),
        SagaWorkerIdentity::new("foreign-owner", SagaContractId::parse(CONTRACT).unwrap()).unwrap(),
        definition_identity(),
    )
    .unwrap();
    store.register(foreign_registration).await.unwrap();
    store.seed_status(instance(), SagaInstanceStatus::Running);
    let (factory, counts) = FakeFactory::linear(&["step1"]);
    let exec = executor_with_store(
        journal,
        store.clone(),
        Arc::new(FakeCheckpointStore::default()),
        Arc::new(FakeDeadLetterStore::default()),
        factory,
    );

    let outcome = exec.resume(instance(), definition_identity()).await;

    assert!(matches!(
        outcome,
        SagaOutcome::Interrupted {
            reason: SagaInterruption::UnsupportedDefinition
        }
    ));
    assert_eq!(counts[0].dos(), 0);
    assert_eq!(counts[0].undos(), 0);
    assert_eq!(
        store.status(instance()),
        Some(SagaInstanceStatus::Running),
        "foreign owner must not mutate the durable row"
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

    let outcome = exec.run(instance(), definition_identity()).await;

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
    journal.inner.seed(0, "step1", SagaJournalStatus::Executing);
    let store = ready_instance_store();
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, counts) = FakeFactory::linear(&["step1", "step2"]);
    let exec = executor_with_store(journal, store.clone(), cp, dlx, factory);

    let outcome = exec.resume(instance(), definition_identity()).await;

    assert!(
        matches!(
            outcome,
            SagaOutcome::Interrupted {
                reason: SagaInterruption::JournalConflict
            }
        ),
        "resume append conflict must be non-business interruption: {outcome:?}"
    );
    assert_eq!(counts[0].dos(), 0, "conflicted executing step must not run");
    assert_eq!(
        counts[1].dos(),
        0,
        "step2 must not run after Executing conflict"
    );
    assert_eq!(store.status(instance()), Some(SagaInstanceStatus::Degraded));
}

#[tokio::test]
async fn receipt_storage_precommit_failure_compensates_and_surfaces_store_unavailable() {
    let journal = Arc::new(FakeJournalFailing::fail_on_status(
        SagaJournalStatus::Completed,
    ));
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, counts) = FakeFactory::linear(&["step1", "step2"]);

    let store = Arc::new(FakeInstanceStore::default());
    let exec = executor_with_store(
        journal.clone(),
        Arc::clone(&store),
        cp,
        dlx.clone(),
        factory,
    );

    let outcome = exec.run(instance(), definition_identity()).await;

    assert!(
        matches!(
            outcome,
            SagaOutcome::Interrupted {
                reason: SagaInterruption::StoreUnavailable
            }
        ),
        "receipt storage pre-commit failure must degrade the worker after compensation: {outcome:?}"
    );
    assert_eq!(counts[0].dos(), 1, "step1 副作用已发生");
    assert_eq!(
        counts[0].undos(),
        1,
        "step1 Completed append 失败后须补偿当前步"
    );
    assert_eq!(counts[1].dos(), 0, "step2 不应继续执行");
    assert_eq!(
        store.status(instance()),
        Some(SagaInstanceStatus::Compensated),
        "durable saga state must remain compensated"
    );
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
    let replay_outcome = resume_exec.resume(instance(), definition_identity()).await;
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

#[test]
fn receipt_precommit_failure_logs_only_safe_closed_fields() {
    for (kind, expected_kind) in [
        (SagaReceiptStoreErrorKind::Protection, "protection"),
        (SagaReceiptStoreErrorKind::Storage, "storage"),
    ] {
        let events = capture_tracing_events(tracing::Level::ERROR, false, || async move {
            let receipt_state = Arc::new(FakeReceiptState::default());
            receipt_state.fail_before_commit(kind);
            let (factory, counts) = FakeFactory::linear(&["step1"]);
            let exec = executor_with_store_options(
                Arc::new(FakeJournal::default()),
                ready_instance_store(),
                Arc::new(FakeCheckpointStore::default()),
                Arc::new(FakeDeadLetterStore::default()),
                factory,
                ExecOptions::new(disabled_policy(), Duration::from_secs(30), runtime_lock())
                    .with_receipt_state(receipt_state),
            );

            let outcome = exec.run(instance(), definition_identity()).await;
            assert!(matches!(
                outcome,
                SagaOutcome::Interrupted {
                    reason: SagaInterruption::StoreUnavailable
                }
            ));
            assert_eq!(counts[0].dos(), 1);
            assert_eq!(counts[0].undos(), 1);
        });

        let event = events.iter().find(|event| {
            event
                .get("message")
                .is_some_and(|message| message.contains("receipt completion failed"))
        });
        assert!(event.is_some(), "missing receipt failure event: {events:?}");
        let Some(event) = event else {
            continue;
        };
        assert_eq!(
            event.get("receipt_error_kind").map(String::as_str),
            Some(expected_kind)
        );
        assert_eq!(event.get("tenant_id").map(String::as_str), Some(TENANT));
        assert_eq!(event.get("contract_id").map(String::as_str), Some(CONTRACT));
        assert_eq!(event.get("step").map(String::as_str), Some("step1"));
        assert_eq!(event.get("completed_seq").map(String::as_str), Some("1"));
        assert!(event.get("saga_id").is_some_and(|value| !value.is_empty()));
        let mut fields = event.keys().map(String::as_str).collect::<Vec<_>>();
        fields.sort_unstable();
        assert_eq!(
            fields,
            vec![
                "completed_seq",
                "contract_id",
                "message",
                "receipt_error_kind",
                "saga_id",
                "step",
                "tenant_id",
            ]
        );
    }
}

#[test]
fn receipt_failure_log_kinds_are_closed_labels() {
    for (kind, expected) in [
        (ReceiptFailureLogKind::LeaseLost, "lease_lost"),
        (ReceiptFailureLogKind::Conflict, "conflict"),
        (ReceiptFailureLogKind::CommitUnknown, "commit_unknown"),
        (ReceiptFailureLogKind::Protection, "protection"),
        (ReceiptFailureLogKind::Storage, "storage"),
        (ReceiptFailureLogKind::Integrity, "integrity"),
        (
            ReceiptFailureLogKind::UnsupportedFormat,
            "unsupported_format",
        ),
        (
            ReceiptFailureLogKind::UnexpectedOutcome,
            "unexpected_outcome",
        ),
        (
            ReceiptFailureLogKind::UnknownErrorKind,
            "unknown_error_kind",
        ),
    ] {
        assert_eq!(kind.as_str(), expected);
    }
}

#[test]
fn receipt_terminal_failures_interrupt_without_compensation_and_log_closed_kind() {
    #[derive(Clone, Copy)]
    enum Fault {
        Error(SagaReceiptStoreErrorKind),
        Outcome(SagaReceiptCommitOutcome),
    }

    for (fault, expected_reason, expected_kind) in [
        (
            Fault::Error(SagaReceiptStoreErrorKind::Integrity),
            SagaInterruption::JournalConflict,
            "integrity",
        ),
        (
            Fault::Error(SagaReceiptStoreErrorKind::UnsupportedFormat),
            SagaInterruption::JournalConflict,
            "unsupported_format",
        ),
        (
            Fault::Outcome(SagaReceiptCommitOutcome::Conflict),
            SagaInterruption::JournalConflict,
            "conflict",
        ),
        (
            Fault::Outcome(SagaReceiptCommitOutcome::LeaseLost),
            SagaInterruption::LeaseLost,
            "lease_lost",
        ),
    ] {
        let events = capture_tracing_events(tracing::Level::ERROR, false, || async move {
            let receipt_state = Arc::new(FakeReceiptState::default());
            match fault {
                Fault::Error(kind) => receipt_state.fail_before_commit(kind),
                Fault::Outcome(outcome) => receipt_state.return_before_commit(outcome),
            }
            let (factory, counts) = FakeFactory::linear(&["step1"]);
            let exec = executor_with_store_options(
                Arc::new(FakeJournal::default()),
                ready_instance_store(),
                Arc::new(FakeCheckpointStore::default()),
                Arc::new(FakeDeadLetterStore::default()),
                factory,
                ExecOptions::new(disabled_policy(), Duration::from_secs(30), runtime_lock())
                    .with_receipt_state(receipt_state),
            );

            let outcome = exec.run(instance(), definition_identity()).await;
            assert!(
                matches!(&outcome, SagaOutcome::Interrupted { .. }),
                "expected interruption, got {outcome:?}"
            );
            if let SagaOutcome::Interrupted { reason } = outcome {
                assert_eq!(reason, expected_reason);
            }
            assert_eq!(counts[0].dos(), 1);
            assert_eq!(counts[0].undos(), 0);
        });

        let event = events.iter().find(|event| {
            event
                .get("message")
                .is_some_and(|message| message.contains("receipt completion failed"))
        });
        assert!(event.is_some(), "missing receipt failure event: {events:?}");
        if let Some(event) = event {
            assert_eq!(
                event.get("receipt_error_kind").map(String::as_str),
                Some(expected_kind)
            );
        }
    }
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

    let outcome = exec.run(instance(), definition_identity()).await;

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

    let outcome = exec.run(instance(), definition_identity()).await;

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

    let outcome = exec.run(instance(), definition_identity()).await;

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
    let replay_outcome = resume_exec.resume(instance(), definition_identity()).await;
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

    let outcome = exec.run(instance(), definition_identity()).await;

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

    let outcome = exec.run(instance(), definition_identity()).await;

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

    let outcome = exec.resume(instance(), definition_identity()).await;

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

    let outcome = exec.resume(instance(), definition_identity()).await;

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

#[tokio::test]
async fn resume_post_effect_failure_without_receipt_fails_closed() {
    let journal = Arc::new(FakeJournal::default());
    journal.seed(0, "step1", SagaJournalStatus::Executing);
    journal.seed(1, "step1", SagaJournalStatus::Compensating);
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, counts) = FakeFactory::linear(&["step1", "step2"]);
    let exec = executor(journal.clone(), cp, dlx, factory);

    let outcome = exec.resume(instance(), definition_identity()).await;

    assert!(
        matches!(
            outcome,
            SagaOutcome::Interrupted {
                reason: SagaInterruption::ReceiptUnavailable
            }
        ),
        "missing durable receipt must fail closed: {outcome:?}"
    );
    assert_eq!(counts[0].dos(), 0, "step1 forward must not rerun");
    assert_eq!(
        counts[0].undos(),
        0,
        "step1 must not compensate without its receipt"
    );
    assert_eq!(counts[1].dos(), 0, "later steps must not run");
    assert_eq!(counts[1].undos(), 0, "later steps were never completed");
    assert_eq!(
        journal.log(),
        vec![
            ("step1".to_string(), SagaJournalStatus::Executing),
            ("step1".to_string(), SagaJournalStatus::Compensating),
            ("step1".to_string(), SagaJournalStatus::Compensating),
        ]
    );
}

// ── F8：从补偿中崩溃恢复 —— 续补偿剩余已完成步 ─────────────────────────────────────

#[tokio::test]
async fn resume_compensation_without_receipts_fails_closed() {
    let journal = Arc::new(FakeJournal::default());
    // step1/step2 均已完成，step2 补偿中崩溃（Compensating 无 Compensated）。
    journal.seed(0, "step1", SagaJournalStatus::Completed);
    journal.seed(1, "step2", SagaJournalStatus::Completed);
    journal.seed(2, "step2", SagaJournalStatus::Compensating);
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, counts) = FakeFactory::linear(&["step1", "step2"]);
    let exec = executor(journal, cp, dlx, factory);

    let outcome = exec.resume(instance(), definition_identity()).await;

    // 续补偿：逆序对 step2、step1 调 undo_it；终态 Failed（补偿后）。
    assert!(
        matches!(
            outcome,
            SagaOutcome::Interrupted {
                reason: SagaInterruption::ReceiptUnavailable
            }
        ),
        "{outcome:?}"
    );
    assert_eq!(counts[0].undos(), 0, "receipt 缺失时不得补偿 step1");
    assert_eq!(counts[1].undos(), 0, "receipt 缺失时不得补偿 step2");
    assert_eq!(counts[0].dos(), 0, "补偿恢复不重跑前向");
    assert_eq!(counts[1].dos(), 0, "补偿恢复不重跑前向");
}

#[tokio::test]
async fn resume_compensation_missing_receipt_does_not_deadletter_or_execute() {
    let journal = Arc::new(FakeJournal::default());
    journal.seed(0, "step1", SagaJournalStatus::Completed);
    journal.seed(1, "step2", SagaJournalStatus::Executing);
    journal.seed(2, "step1", SagaJournalStatus::Compensating);
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, _counts) = FakeFactory::steps(&[("step1", false, true), ("step2", false, false)]);
    let exec = executor(journal, cp, dlx.clone(), factory);

    let outcome = exec.resume(instance(), definition_identity()).await;

    assert!(
        matches!(
            outcome,
            SagaOutcome::Interrupted {
                reason: SagaInterruption::ReceiptUnavailable
            }
        ),
        "{outcome:?}"
    );
    let records = dlx.records();
    assert!(records.is_empty(), "receipt 缺失不是业务失败，不得写 DLX");
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

    let outcome = exec.resume(instance(), definition_identity()).await;

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

    let outcome = exec.resume(instance(), definition_identity()).await;

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
            let _ = exec.run(instance(), definition_identity()).await;
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
async fn status_does_not_acquire_runtime_lock() {
    let lock_store = FakeRuntimeLockStore::fail_acquire();
    let runtime_lock = runtime_lock_from(lock_store.clone());
    let journal = Arc::new(FakeJournal::default());
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, _counts) = FakeFactory::linear(&["step1"]);
    let store = ready_instance_store();
    let exec = executor_with_store_options(
        journal,
        store,
        cp,
        dlx,
        factory,
        ExecOptions::new(disabled_policy(), Duration::from_secs(30), runtime_lock),
    );

    assert_eq!(exec.status(instance()).await, Some(SagaExecStatus::Ready));
    assert_eq!(
        lock_store.acquisition_count(),
        0,
        "status must stay a read-only journal/instance query"
    );
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

#[tokio::test]
#[allow(clippy::expect_used)]
async fn status_reports_degraded_when_durable_definition_is_absent_from_registry() {
    let journal = Arc::new(FakeJournal::default());
    let store = ready_instance_store();
    let unknown = consistency::SagaDefinitionIdentity::new(
        CONTRACT,
        "v999",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    )
    .expect("valid unknown definition");
    store.seed_definition(instance(), unknown);
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
fn typed_phase_context_accessors_preserve_instance_step_and_scoped_key() {
    let instance = instance();
    let definition = definition_identity();
    let binding = generated::saga::billing_v1::STEP_0;
    let step_name = StepName::parse(binding.name());
    assert!(step_name.is_ok(), "generated step name must be valid");
    let Ok(step_name) = step_name else {
        return;
    };
    let forward_key =
        super::SagaIdempotencyKey::derive(instance, &definition, binding, SagaEffectPhase::Forward);
    let compensation_key = super::SagaIdempotencyKey::derive(
        instance,
        &definition,
        binding,
        SagaEffectPhase::Compensation,
    );
    let forward = SagaForwardContext {
        instance,
        step_name: step_name.clone(),
        idempotency_key: forward_key.clone(),
    };
    let compensation = SagaCompensationContext {
        instance,
        step_name: step_name.clone(),
        idempotency_key: compensation_key.clone(),
    };

    assert_eq!(forward.instance(), instance);
    assert_eq!(forward.tenant(), instance.tenant());
    assert_eq!(forward.saga_id(), instance.saga_id());
    assert_eq!(forward.step_name(), &step_name);
    assert_eq!(forward.idempotency_key(), &forward_key);
    assert_eq!(compensation.instance(), instance);
    assert_eq!(compensation.tenant(), instance.tenant());
    assert_eq!(compensation.saga_id(), instance.saga_id());
    assert_eq!(compensation.step_name(), &step_name);
    assert_eq!(compensation.idempotency_key(), &compensation_key);
    assert_ne!(forward.idempotency_key(), compensation.idempotency_key());
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
