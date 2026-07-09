//! saga 执行器单测：验收三场景（journal 顺序 / 逆序补偿 / checkpoint resume）+ 补偿失败 dead-letter
//! observability（T009.1 / T009.6）+ 冻结接缝 smoke。
//!
//! `compensation_failure_logs_fields` 使用 current-thread runtime + scoped subscriber 捕获 tracing 字段，
//! 避免单进程 `cargo test` 下多个全局 subscriber 竞争。

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

use super::{
    SagaAction, SagaActionCtx, SagaActionError, SagaActionFactory, SagaCommand, SagaExecStatus,
    SagaExecutor, SagaExecutorConfig, SagaExecutorDeps, SagaExecutorImpl, SagaOutcome, SagaPolicy,
    SagaRuntimeLock, SagaTailer, TypedSagaActionFactory, TypedSagaFactoryError,
    is_saga_action_retryable,
};
use consistency::{
    CompensationOutcome, EngineError, EngineErrorKind, Lsn, SagaJournalAppendRecord,
    SagaJournalRecord, SagaJournalStatus, SagaStep, SagaStepCtx, StepName,
};
use consistency::{
    SagaId, SagaInstanceRecord, SagaInstanceRef, SagaInstanceStatus, SagaInterruption,
    SagaJournalAppendOutcome, SagaLease, SagaLeaseOutcome,
};
use diport::{
    Checkpoint, CheckpointId, CheckpointOwner, CheckpointStoreError, CheckpointVersion,
    DeadLetterRecord, DeadLetterStore, DeadLetterStoreError, LockAcquireOutcome, LockRenewOutcome,
    LockStore, LockStoreError, LockStoreKey, OwnerCheckpointStore, SagaInstanceRegistration,
    SagaInstanceStore, SagaInstanceStoreError, SagaJournal, SagaJournalError, SagaRunnableInstance,
    SagaWorkerIdentity, SaveOutcome,
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

// ── FakeAction ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct FakeAction {
    name: String,
    do_count: Arc<AtomicU32>,
    undo_count: Arc<AtomicU32>,
    do_behavior: FakeBehavior,
    undo_behavior: FakeBehavior,
}

#[derive(Debug, Clone, Copy)]
enum FakeBehavior {
    Succeed,
    Fail,
    SerializeFail,
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
    fn do_it(&self, _ctx: SagaActionCtx) -> BoxFuture<'static, Result<Vec<u8>, SagaActionError>> {
        let count = self.do_count.clone();
        let behavior = self.do_behavior;
        let name = self.name.clone();
        Box::pin(async move {
            let attempt = count.fetch_add(1, Ordering::SeqCst) + 1;
            match behavior {
                FakeBehavior::Succeed => Ok(format!("{name}-out").into_bytes()),
                FakeBehavior::Fail => Err(SagaActionError::ActionFailed),
                FakeBehavior::SerializeFail => Err(SagaActionError::SerializeFailed),
                FakeBehavior::FailTimes(failures) if attempt <= failures => {
                    Err(SagaActionError::ActionFailed)
                }
                FakeBehavior::FailTimes(_) => Ok(format!("{name}-out").into_bytes()),
                FakeBehavior::Hang => {
                    std::future::pending::<Result<Vec<u8>, SagaActionError>>().await
                }
            }
        })
    }
    fn undo_it(&self, _ctx: SagaActionCtx) -> BoxFuture<'static, Result<(), SagaActionError>> {
        let count = self.undo_count.clone();
        let behavior = self.undo_behavior;
        Box::pin(async move {
            let attempt = count.fetch_add(1, Ordering::SeqCst) + 1;
            match behavior {
                FakeBehavior::Succeed => Ok(()),
                FakeBehavior::Fail => Err(SagaActionError::ActionFailed),
                FakeBehavior::SerializeFail => Err(SagaActionError::SerializeFailed),
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
        let mut steps = Vec::new();
        let mut counts = Vec::new();
        for (name, do_behavior, undo_behavior) in specs {
            let c = Counts {
                do_count: Arc::new(AtomicU32::new(0)),
                undo_count: Arc::new(AtomicU32::new(0)),
            };
            counts.push(c.clone());
            steps.push(StepSpec {
                name: (*name).to_string(),
                do_behavior: *do_behavior,
                undo_behavior: *undo_behavior,
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
                    do_behavior: s.do_behavior,
                    undo_behavior: s.undo_behavior,
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
            .map(|(instance, status)| SagaRunnableInstance::new(*instance, *status).unwrap())
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
    let spec = vocab::SagaRuntimePolicySpec::from_millis(retry_millis, timeout_millis);
    match SagaPolicy::try_from(spec) {
        Ok(policy) => policy,
        Err(err) => panic!("invalid test saga policy: {err}"),
    }
}

fn disabled_policy() -> SagaPolicy {
    policy_from_millis(0, 0)
}

#[allow(clippy::expect_used)] // reason: 测试常量必须能构造合法 executor config
fn executor_config_with_policy_and_lease_ttl(
    policy: SagaPolicy,
    lease_ttl: Duration,
) -> SagaExecutorConfig {
    SagaExecutorConfig::new(
        CheckpointOwner::new(OWNER),
        CONTRACT,
        "runner-a",
        lease_ttl,
        policy,
    )
    .expect("valid test saga executor config")
}

#[test]
#[allow(clippy::expect_used)] // reason: invalid generated spec is the assertion failure
fn executor_config_from_contract_spec_derives_contract_and_policy() {
    const CONTRACT_BINDING: vocab::ContractBinding = vocab::ContractBinding::from_static(
        OWNER,
        CONTRACT,
        "v1",
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );
    const POLICY_SPEC: vocab::SagaRuntimePolicySpec =
        vocab::SagaRuntimePolicySpec::from_millis(5000, 30000);
    const STEPS: &[vocab::SagaStepBinding] = &[vocab::SagaStepBinding::from_static(
        CONTRACT_BINDING,
        "step1",
        "step1.schema.json",
    )];
    const SPEC: vocab::SagaContractBinding =
        vocab::SagaContractBinding::from_parts(CONTRACT_BINDING, POLICY_SPEC, STEPS);

    let config = SagaExecutorConfig::from_contract_spec(
        CheckpointOwner::new(OWNER),
        "runner-a",
        Duration::from_secs(30),
        SPEC,
    )
    .expect("generated test spec is valid");

    assert_eq!(config.identity().contract_id().as_str(), CONTRACT);
    assert!(matches!(config.policy, SagaPolicy::Bounded(_)));
}

const TYPED_CONTRACT: vocab::ContractBinding = vocab::ContractBinding::from_static(
    OWNER,
    CONTRACT,
    "v1",
    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
);
const TYPED_STEP_RESERVE: vocab::SagaStepBinding =
    vocab::SagaStepBinding::from_static(TYPED_CONTRACT, "reserve_funds", "reserve.schema.json");
const TYPED_STEP_CAPTURE: vocab::SagaStepBinding =
    vocab::SagaStepBinding::from_static(TYPED_CONTRACT, "capture", "capture.schema.json");
const TYPED_STEPS_ONE: &[vocab::SagaStepBinding] = &[TYPED_STEP_RESERVE];
const TYPED_STEPS_TWO: &[vocab::SagaStepBinding] = &[TYPED_STEP_RESERVE, TYPED_STEP_CAPTURE];
const TYPED_POLICY: vocab::SagaRuntimePolicySpec = vocab::SagaRuntimePolicySpec::from_millis(0, 0);
const TYPED_SPEC_ONE: vocab::SagaContractBinding =
    vocab::SagaContractBinding::from_parts(TYPED_CONTRACT, TYPED_POLICY, TYPED_STEPS_ONE);
const TYPED_SPEC_TWO: vocab::SagaContractBinding =
    vocab::SagaContractBinding::from_parts(TYPED_CONTRACT, TYPED_POLICY, TYPED_STEPS_TWO);
const OTHER_TYPED_CONTRACT: vocab::ContractBinding = vocab::ContractBinding::from_static(
    "orders",
    "orders.checkout",
    "v1",
    "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
);
const OTHER_TYPED_STEP_RESERVE: vocab::SagaStepBinding = vocab::SagaStepBinding::from_static(
    OTHER_TYPED_CONTRACT,
    "reserve_funds",
    "reserve.schema.json",
);

#[derive(Debug, serde::Serialize)]
struct TypedReserveOutput {
    step: &'static str,
    saga_id: String,
}

impl vocab::SagaStepOutputBinding for TypedReserveOutput {
    const BINDING: vocab::SagaStepBinding = TYPED_STEP_RESERVE;
}

#[derive(Debug, serde::Serialize)]
struct TypedCaptureOutput {
    step: &'static str,
    saga_id: String,
}

impl vocab::SagaStepOutputBinding for TypedCaptureOutput {
    const BINDING: vocab::SagaStepBinding = TYPED_STEP_CAPTURE;
}

#[derive(Debug)]
struct TypedReserveStep {
    execute_count: Arc<AtomicU32>,
    compensate_count: Arc<AtomicU32>,
    execute_error: Option<EngineErrorKind>,
    compensate_failed: bool,
}

impl SagaStep for TypedReserveStep {
    const BINDING: vocab::SagaStepBinding = TYPED_STEP_RESERVE;

    type Output = TypedReserveOutput;

    async fn execute(&self, ctx: SagaStepCtx) -> Result<Self::Output, EngineError> {
        let count = self.execute_count.clone();
        let execute_error = self.execute_error;
        count.fetch_add(1, Ordering::SeqCst);
        if let Some(kind) = execute_error {
            return Err(EngineError::new(kind));
        }
        Ok(TypedReserveOutput {
            step: "reserve_funds",
            saga_id: ctx.saga_id().as_uuid().to_string(),
        })
    }

    async fn compensate(&self, _ctx: SagaStepCtx) -> Result<CompensationOutcome, EngineError> {
        let count = self.compensate_count.clone();
        let compensate_failed = self.compensate_failed;
        count.fetch_add(1, Ordering::SeqCst);
        if compensate_failed {
            Ok(CompensationOutcome::Failed)
        } else {
            Ok(CompensationOutcome::Compensated)
        }
    }
}

#[derive(Debug)]
struct TypedCaptureStep;

impl SagaStep for TypedCaptureStep {
    const BINDING: vocab::SagaStepBinding = TYPED_STEP_CAPTURE;

    type Output = TypedCaptureOutput;

    async fn execute(&self, ctx: SagaStepCtx) -> Result<Self::Output, EngineError> {
        Ok(TypedCaptureOutput {
            step: "capture",
            saga_id: ctx.saga_id().as_uuid().to_string(),
        })
    }

    async fn compensate(&self, _ctx: SagaStepCtx) -> Result<CompensationOutcome, EngineError> {
        Ok(CompensationOutcome::Compensated)
    }
}

#[derive(Debug)]
struct TypedFailingCaptureStep;

impl SagaStep for TypedFailingCaptureStep {
    const BINDING: vocab::SagaStepBinding = TYPED_STEP_CAPTURE;

    type Output = TypedCaptureOutput;

    async fn execute(&self, _ctx: SagaStepCtx) -> Result<Self::Output, EngineError> {
        Err(EngineError::new(EngineErrorKind::Transient))
    }

    async fn compensate(&self, _ctx: SagaStepCtx) -> Result<CompensationOutcome, EngineError> {
        Ok(CompensationOutcome::Compensated)
    }
}

struct FailingSerialize;

impl vocab::SagaStepOutputBinding for FailingSerialize {
    const BINDING: vocab::SagaStepBinding = TYPED_STEP_RESERVE;
}

impl serde::Serialize for FailingSerialize {
    fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Err(serde::ser::Error::custom("intentional serialize failure"))
    }
}

#[derive(Debug)]
struct SerializeFailStep;

impl SagaStep for SerializeFailStep {
    const BINDING: vocab::SagaStepBinding = TYPED_STEP_RESERVE;

    type Output = FailingSerialize;

    async fn execute(&self, _ctx: SagaStepCtx) -> Result<Self::Output, EngineError> {
        Ok(FailingSerialize)
    }

    async fn compensate(&self, _ctx: SagaStepCtx) -> Result<CompensationOutcome, EngineError> {
        Ok(CompensationOutcome::Compensated)
    }
}

#[derive(Debug)]
struct CountingSerializeFailStep {
    compensate_count: Arc<AtomicU32>,
}

impl SagaStep for CountingSerializeFailStep {
    const BINDING: vocab::SagaStepBinding = TYPED_STEP_RESERVE;

    type Output = FailingSerialize;

    async fn execute(&self, _ctx: SagaStepCtx) -> Result<Self::Output, EngineError> {
        Ok(FailingSerialize)
    }

    async fn compensate(&self, _ctx: SagaStepCtx) -> Result<CompensationOutcome, EngineError> {
        self.compensate_count.fetch_add(1, Ordering::SeqCst);
        Ok(CompensationOutcome::Compensated)
    }
}

#[derive(Debug, serde::Serialize)]
struct WrongStepOutput;

impl vocab::SagaStepOutputBinding for WrongStepOutput {
    const BINDING: vocab::SagaStepBinding = TYPED_STEP_CAPTURE;
}

#[derive(Debug, serde::Serialize)]
struct OtherContractReserveOutput;

impl vocab::SagaStepOutputBinding for OtherContractReserveOutput {
    const BINDING: vocab::SagaStepBinding = OTHER_TYPED_STEP_RESERVE;
}

#[derive(Debug)]
struct WrongOutputReserveStep;

impl SagaStep for WrongOutputReserveStep {
    const BINDING: vocab::SagaStepBinding = TYPED_STEP_RESERVE;

    type Output = WrongStepOutput;

    async fn execute(&self, _ctx: SagaStepCtx) -> Result<Self::Output, EngineError> {
        Ok(WrongStepOutput)
    }

    async fn compensate(&self, _ctx: SagaStepCtx) -> Result<CompensationOutcome, EngineError> {
        Ok(CompensationOutcome::Compensated)
    }
}

#[derive(Debug)]
struct OtherContractReserveStep;

impl SagaStep for OtherContractReserveStep {
    const BINDING: vocab::SagaStepBinding = OTHER_TYPED_STEP_RESERVE;

    type Output = OtherContractReserveOutput;

    async fn execute(&self, _ctx: SagaStepCtx) -> Result<Self::Output, EngineError> {
        Ok(OtherContractReserveOutput)
    }

    async fn compensate(&self, _ctx: SagaStepCtx) -> Result<CompensationOutcome, EngineError> {
        Ok(CompensationOutcome::Compensated)
    }
}

#[tokio::test]
#[allow(clippy::expect_used)] // reason: typed wrapper regression test setup
async fn typed_saga_action_wraps_execute_compensate_and_serializes_output() {
    let execute_count = Arc::new(AtomicU32::new(0));
    let compensate_count = Arc::new(AtomicU32::new(0));
    let mut builder = TypedSagaActionFactory::builder(TYPED_SPEC_ONE);
    builder
        .register_step::<TypedReserveStep, _>({
            let execute_count = execute_count.clone();
            let compensate_count = compensate_count.clone();
            move || TypedReserveStep {
                execute_count: execute_count.clone(),
                compensate_count: compensate_count.clone(),
                execute_error: None,
                compensate_failed: false,
            }
        })
        .expect("register typed step");
    let factory = builder.finish().expect("typed factory");
    let actions = factory.build();
    assert_eq!(actions.len(), 1);

    let output = actions[0]
        .do_it(SagaActionCtx::new(instance(), "reserve_funds"))
        .await
        .expect("typed execute succeeds");
    let json: serde_json::Value = serde_json::from_slice(&output).expect("json output");
    assert_eq!(json["step"], "reserve_funds");
    assert_eq!(execute_count.load(Ordering::SeqCst), 1);

    actions[0]
        .undo_it(SagaActionCtx::new(instance(), "reserve_funds"))
        .await
        .expect("typed compensate succeeds");
    assert_eq!(compensate_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
#[allow(clippy::expect_used)] // reason: typed wrapper regression test setup
async fn typed_saga_action_maps_engine_errors_and_serialization_failures() {
    let mut transient = TypedSagaActionFactory::builder(TYPED_SPEC_ONE);
    transient
        .register_step::<TypedReserveStep, _>(|| TypedReserveStep {
            execute_count: Arc::new(AtomicU32::new(0)),
            compensate_count: Arc::new(AtomicU32::new(0)),
            execute_error: Some(EngineErrorKind::Transient),
            compensate_failed: false,
        })
        .expect("register transient step");
    let transient_factory = transient.finish().expect("factory");
    let transient_actions = transient_factory.build();
    let err = transient_actions[0]
        .do_it(SagaActionCtx::new(instance(), "reserve_funds"))
        .await
        .expect_err("transient should fail action");
    assert!(matches!(err, SagaActionError::ActionFailed));
    assert!(is_saga_action_retryable(&err));

    let mut permanent = TypedSagaActionFactory::builder(TYPED_SPEC_ONE);
    permanent
        .register_step::<TypedReserveStep, _>(|| TypedReserveStep {
            execute_count: Arc::new(AtomicU32::new(0)),
            compensate_count: Arc::new(AtomicU32::new(0)),
            execute_error: Some(EngineErrorKind::Permanent),
            compensate_failed: false,
        })
        .expect("register permanent step");
    let permanent_factory = permanent.finish().expect("factory");
    let permanent_actions = permanent_factory.build();
    let err = permanent_actions[0]
        .do_it(SagaActionCtx::new(instance(), "reserve_funds"))
        .await
        .expect_err("permanent should fail action");
    assert!(matches!(err, SagaActionError::NonRetryableActionFailed));
    assert!(!is_saga_action_retryable(&err));

    let mut serialize = TypedSagaActionFactory::builder(TYPED_SPEC_ONE);
    serialize
        .register_step::<SerializeFailStep, _>(|| SerializeFailStep)
        .expect("register serialize step");
    let serialize_factory = serialize.finish().expect("factory");
    let serialize_actions = serialize_factory.build();
    let err = serialize_actions[0]
        .do_it(SagaActionCtx::new(instance(), "reserve_funds"))
        .await
        .expect_err("serialization should fail action");
    assert!(matches!(err, SagaActionError::SerializeFailed));
    assert!(!is_saga_action_retryable(&err));
}

#[tokio::test]
#[allow(clippy::expect_used)] // reason: typed executor regression test setup
async fn typed_saga_output_serialize_failure_compensates_current_step() {
    let compensate_count = Arc::new(AtomicU32::new(0));
    let mut builder = TypedSagaActionFactory::builder(TYPED_SPEC_ONE);
    builder
        .register_step::<CountingSerializeFailStep, _>({
            let compensate_count = compensate_count.clone();
            move || CountingSerializeFailStep {
                compensate_count: compensate_count.clone(),
            }
        })
        .expect("register serialize-failing step");
    let factory = builder.finish().expect("typed factory");
    let journal = Arc::new(FakeJournal::default());
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let exec = SagaExecutorImpl::new(
        SagaExecutorDeps::new(
            journal.clone(),
            ready_instance_store(),
            cp,
            dlx,
            factory,
            runtime_lock(),
        ),
        executor_config_with_policy_and_lease_ttl(disabled_policy(), Duration::from_secs(30)),
    );

    let outcome = exec.run(instance()).await;

    assert!(
        matches!(
            outcome,
            SagaOutcome::Failed {
                error: SagaActionError::SerializeFailed,
                ..
            }
        ),
        "output serialization must fail the saga: {outcome:?}"
    );
    assert_eq!(
        compensate_count.load(Ordering::SeqCst),
        1,
        "post-execute serialization failure must compensate the current step"
    );
    let log = journal.log();
    assert_eq!(
        log,
        vec![
            ("reserve_funds".to_string(), SagaJournalStatus::Executing),
            ("reserve_funds".to_string(), SagaJournalStatus::Compensating),
            ("reserve_funds".to_string(), SagaJournalStatus::Compensated),
        ],
        "serialization failure must persist compensation intent before completion"
    );
}

#[tokio::test]
#[allow(clippy::expect_used)] // reason: typed executor regression test setup
#[allow(clippy::panic)] // reason: explicit outcome branch assertion
async fn typed_saga_compensation_failed_writes_failed_journal_and_dead_letter() {
    let execute_count = Arc::new(AtomicU32::new(0));
    let compensate_count = Arc::new(AtomicU32::new(0));
    let mut builder = TypedSagaActionFactory::builder(TYPED_SPEC_TWO);
    builder
        .register_step::<TypedReserveStep, _>({
            let execute_count = execute_count.clone();
            let compensate_count = compensate_count.clone();
            move || TypedReserveStep {
                execute_count: execute_count.clone(),
                compensate_count: compensate_count.clone(),
                execute_error: None,
                compensate_failed: true,
            }
        })
        .expect("register reserve step");
    builder
        .register_step::<TypedFailingCaptureStep, _>(|| TypedFailingCaptureStep)
        .expect("register failing capture step");
    let factory = builder.finish().expect("typed factory");
    let journal = Arc::new(FakeJournal::default());
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let exec = SagaExecutorImpl::new(
        SagaExecutorDeps::new(
            journal.clone(),
            ready_instance_store(),
            cp,
            dlx.clone(),
            factory,
            runtime_lock(),
        ),
        executor_config_with_policy_and_lease_ttl(disabled_policy(), Duration::from_secs(30)),
    );

    let outcome = exec.run(instance()).await;

    match outcome {
        SagaOutcome::Failed { failed_node, error } => {
            assert_eq!(failed_node, "reserve_funds");
            assert!(matches!(error, SagaActionError::NonRetryableActionFailed));
        }
        other => panic!("expected typed compensation failure, got {other:?}"),
    }
    assert_eq!(execute_count.load(Ordering::SeqCst), 1);
    assert_eq!(compensate_count.load(Ordering::SeqCst), 1);
    let log = journal.log();
    assert!(
        log.contains(&("reserve_funds".to_string(), SagaJournalStatus::Failed)),
        "typed compensation failure must write Failed journal row: {log:?}"
    );
    let records = dlx.records();
    assert_eq!(
        records.len(),
        1,
        "typed compensation failure must write DLX"
    );
    let payload = &records[0].5;
    assert!(
        payload.contains("capture"),
        "DLX payload must keep original forward failure step: {payload}"
    );
    assert!(
        payload.contains("reserve_funds"),
        "DLX payload must keep failed compensation step: {payload}"
    );
}

#[test]
#[allow(clippy::expect_used)] // reason: typed factory regression test setup
fn typed_saga_factory_finish_rejects_missing_extra_and_reordered_steps() {
    let missing = TypedSagaActionFactory::builder(TYPED_SPEC_ONE).finish();
    assert!(matches!(
        missing,
        Err(TypedSagaFactoryError::StepCountMismatch {
            expected: 1,
            actual: 0
        })
    ));

    let mut extra = TypedSagaActionFactory::builder(TYPED_SPEC_ONE);
    extra
        .register_step::<TypedReserveStep, _>(|| TypedReserveStep {
            execute_count: Arc::new(AtomicU32::new(0)),
            compensate_count: Arc::new(AtomicU32::new(0)),
            execute_error: None,
            compensate_failed: false,
        })
        .expect("register reserve");
    extra
        .register_step::<TypedCaptureStep, _>(|| TypedCaptureStep)
        .expect("register capture");
    let extra = extra.finish();
    assert!(matches!(
        extra,
        Err(TypedSagaFactoryError::StepCountMismatch {
            expected: 1,
            actual: 2
        })
    ));

    let mut reordered = TypedSagaActionFactory::builder(TYPED_SPEC_TWO);
    reordered
        .register_step::<TypedCaptureStep, _>(|| TypedCaptureStep)
        .expect("register capture first");
    reordered
        .register_step::<TypedReserveStep, _>(|| TypedReserveStep {
            execute_count: Arc::new(AtomicU32::new(0)),
            compensate_count: Arc::new(AtomicU32::new(0)),
            execute_error: None,
            compensate_failed: false,
        })
        .expect("register reserve second");
    let reordered = reordered.finish();
    assert!(matches!(
        reordered,
        Err(TypedSagaFactoryError::StepBindingMismatch { index: 0, .. })
    ));

    let mut wrong_output = TypedSagaActionFactory::builder(TYPED_SPEC_ONE);
    let err = wrong_output
        .register_step::<WrongOutputReserveStep, _>(|| WrongOutputReserveStep)
        .expect_err("wrong output binding must fail registration");
    assert!(matches!(
        err,
        TypedSagaFactoryError::StepOutputBindingMismatch { .. }
    ));
}

#[test]
#[allow(clippy::expect_used)] // reason: typed factory regression test setup
fn typed_saga_factory_rejects_cross_contract_step_binding() {
    assert_ne!(OTHER_TYPED_CONTRACT, TYPED_CONTRACT);

    let mut builder = TypedSagaActionFactory::builder(TYPED_SPEC_ONE);
    builder
        .register_step::<OtherContractReserveStep, _>(|| OtherContractReserveStep)
        .expect("register same-shaped foreign step");

    assert!(matches!(
        builder.finish(),
        Err(TypedSagaFactoryError::StepBindingMismatch { index: 0, .. })
    ));
}

#[test]
fn typed_saga_factory_error_display_includes_diagnostic_context() {
    let count = TypedSagaFactoryError::StepCountMismatch {
        expected: 1,
        actual: 2,
    }
    .to_string();
    assert!(count.contains("expected=1"), "{count}");
    assert!(count.contains("actual=2"), "{count}");

    let binding = TypedSagaFactoryError::StepBindingMismatch {
        index: 0,
        expected: Box::new(TYPED_STEP_RESERVE),
        actual: Box::new(TYPED_STEP_CAPTURE),
    }
    .to_string();
    assert!(binding.contains("index=0"), "{binding}");
    assert!(binding.contains("reserve_funds"), "{binding}");
    assert!(binding.contains("capture.schema.json"), "{binding}");

    let output = TypedSagaFactoryError::StepOutputBindingMismatch {
        step: Box::new(TYPED_STEP_RESERVE),
        output: Box::new(TYPED_STEP_CAPTURE),
    }
    .to_string();
    assert!(output.contains("reserve.schema.json"), "{output}");
    assert!(output.contains("capture.schema.json"), "{output}");

    let invalid = TypedSagaFactoryError::InvalidStepName { name: "not-valid!" }.to_string();
    assert!(invalid.contains("not-valid!"), "{invalid}");
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
}

impl ExecOptions {
    fn new(policy: SagaPolicy, lease_ttl: Duration, runtime_lock: SagaRuntimeLock) -> Self {
        Self {
            policy,
            lease_ttl,
            runtime_lock,
        }
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
    J: SagaJournal + Send + Sync + 'static,
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

fn executor_with_store_options<J>(
    journal: Arc<J>,
    instance_store: Arc<FakeInstanceStore>,
    cp: Arc<FakeCheckpointStore>,
    dlx: Arc<FakeDeadLetterStore>,
    factory: Arc<dyn SagaActionFactory>,
    options: ExecOptions,
) -> SagaExecutorImpl<J, FakeCheckpointStore, FakeDeadLetterStore, FakeInstanceStore>
where
    J: SagaJournal + Send + Sync + 'static,
{
    SagaExecutorImpl::new(
        SagaExecutorDeps::new_erased(
            journal,
            instance_store,
            cp,
            dlx,
            factory,
            options.runtime_lock,
        ),
        executor_config_with_policy_and_lease_ttl(options.policy, options.lease_ttl),
    )
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
    J: SagaJournal + Send + Sync + 'static,
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
    J: SagaJournal + Send + Sync + 'static,
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

    let outcome = exec.run(instance()).await;

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

    let outcome = exec.run(instance()).await;

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
        tokio::spawn(async move { exec.run(instance_with_id(0x1121)).await })
    };
    lock_store.wait_first_acquire_entered().await;
    let second = {
        let exec = Arc::clone(&exec);
        tokio::spawn(async move { exec.run(instance_with_id(0x1122)).await })
    };
    tokio::time::sleep(Duration::from_millis(10)).await;

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

    let outcome = exec.run(instance()).await;

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

        let outcome = exec.run(instance()).await;
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

    let outcome = tokio::time::timeout(Duration::from_millis(50), exec.run(instance()))
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

        let outcome = exec.run(instance()).await;
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

    let outcome = tokio::time::timeout(Duration::from_millis(50), exec.run(instance()))
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

// ── #1651：runtime retry/timeout policy ───────────────────────────────────────

#[test]
fn saga_policy_rejects_retry_without_timeout() {
    let spec = vocab::SagaRuntimePolicySpec::from_millis(5, 0);
    assert!(
        SagaPolicy::try_from(spec).is_err(),
        "retryMillis > 0 with timeoutMillis = 0 must be invalid"
    );
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

    let outcome = exec.run(instance()).await;

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
async fn policy_forward_timeout_compensates_completed_prefix() {
    let journal = Arc::new(FakeJournal::default());
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, counts) = FakeFactory::behaviors(&[
        ("step1", FakeBehavior::Succeed, FakeBehavior::Succeed),
        ("step2", FakeBehavior::Hang, FakeBehavior::Succeed),
        ("step3", FakeBehavior::Succeed, FakeBehavior::Succeed),
    ]);
    let exec = executor_with_policy(
        journal.clone(),
        cp,
        dlx.clone(),
        factory,
        policy_from_millis(0, 10),
    );

    let outcome = exec.run(instance()).await;

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
    assert_eq!(counts[0].undos(), 1, "completed prefix must be compensated");
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
        journal
            .log()
            .contains(&("step1".to_string(), SagaJournalStatus::Compensated)),
        "step1 compensation completion must be journaled"
    );
}

#[tokio::test(start_paused = true)]
#[allow(clippy::panic)] // reason: 测试断言分支，item-level carve-out
async fn policy_retry_budget_exhaustion_compensates_completed_prefix() {
    let journal = Arc::new(FakeJournal::default());
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, counts) = FakeFactory::behaviors(&[
        ("step1", FakeBehavior::Succeed, FakeBehavior::Succeed),
        ("step2", FakeBehavior::Fail, FakeBehavior::Succeed),
    ]);
    let exec = executor_with_policy(journal, cp, dlx.clone(), factory, policy_from_millis(5, 12));

    let outcome = exec.run(instance()).await;

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
    assert_eq!(counts[0].undos(), 1, "completed prefix must be compensated");
    assert!(dlx.records().is_empty());
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

    let outcome = exec.run(instance()).await;

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
async fn policy_compensation_timeout_writes_dead_letter() {
    let journal = Arc::new(FakeJournal::default());
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, counts) = FakeFactory::behaviors(&[
        ("step1", FakeBehavior::Succeed, FakeBehavior::Hang),
        ("step2", FakeBehavior::SerializeFail, FakeBehavior::Succeed),
    ]);
    let exec = executor_with_policy(
        journal.clone(),
        cp,
        dlx.clone(),
        factory,
        policy_from_millis(0, 10),
    );

    let outcome = exec.run(instance()).await;

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
    assert_eq!(dlx.records().len(), 1, "compensation timeout must DLX");
    assert!(
        journal
            .log()
            .contains(&("step1".to_string(), SagaJournalStatus::Failed)),
        "compensation timeout must write Failed journal row"
    );
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

    let outcome = exec.run(instance()).await;

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

    let outcome = tokio::time::timeout(Duration::from_millis(50), exec.run(instance()))
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

    let outcome = tokio::time::timeout(Duration::from_millis(50), exec.run(instance()))
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

        let outcome = exec.run(instance()).await;
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
    assert_eq!(timeout.get("retry_delay_ms").map(String::as_str), Some("0"));
}

#[test]
#[allow(clippy::expect_used)] // reason: missing event is the assertion failure
fn policy_retry_warning_logs_error_kind() {
    let events = capture_tracing_events(tracing::Level::WARN, true, || async {
        let journal = Arc::new(FakeJournal::default());
        let cp = Arc::new(FakeCheckpointStore::default());
        let dlx = Arc::new(FakeDeadLetterStore::default());
        let (factory, _counts) =
            FakeFactory::behaviors(&[("step1", FakeBehavior::FailTimes(1), FakeBehavior::Succeed)]);
        let exec = executor_with_policy(journal, cp, dlx, factory, policy_from_millis(1, 20));

        let outcome = exec.run(instance()).await;
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
        .expect("action retry warning event must be captured");
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

        let outcome = exec.run(instance()).await;
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

            let outcome = exec.run(instance()).await;
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

        let outcome = exec.run(instance()).await;
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

            let outcome = exec.run(instance()).await;
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

#[tokio::test]
async fn resume_compensates_post_effect_failure_intent_without_rerunning_forward() {
    let journal = Arc::new(FakeJournal::default());
    journal.seed(0, "step1", SagaJournalStatus::Executing);
    journal.seed(1, "step1", SagaJournalStatus::Compensating);
    let cp = Arc::new(FakeCheckpointStore::default());
    let dlx = Arc::new(FakeDeadLetterStore::default());
    let (factory, counts) = FakeFactory::linear(&["step1", "step2"]);
    let exec = executor(journal.clone(), cp, dlx, factory);

    let outcome = exec.resume(instance()).await;

    assert!(
        matches!(outcome, SagaOutcome::Failed { .. }),
        "post-effect compensation intent should resume compensation: {outcome:?}"
    );
    assert_eq!(counts[0].dos(), 0, "step1 forward must not rerun");
    assert_eq!(counts[0].undos(), 1, "step1 compensation must resume");
    assert_eq!(counts[1].dos(), 0, "later steps must not run");
    assert_eq!(counts[1].undos(), 0, "later steps were never completed");
    assert_eq!(
        journal.log(),
        vec![
            ("step1".to_string(), SagaJournalStatus::Executing),
            ("step1".to_string(), SagaJournalStatus::Compensating),
            ("step1".to_string(), SagaJournalStatus::Compensating),
            ("step1".to_string(), SagaJournalStatus::Compensated),
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
