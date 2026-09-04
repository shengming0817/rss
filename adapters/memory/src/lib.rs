//! Provider-neutral in-memory coordination and consistency test doubles.
//!
//! This crate is test/demo infrastructure only. Durable deployments use external providers.
//!
//! Transactional messaging stores, publishers, settlements, and clocks live in the dedicated
//! `rss-transactional-messaging-testkit` package.

use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use consistency::{
    Lsn, SagaCompensationCause, SagaIdempotencyKey, SagaInstanceRecord, SagaInstanceRef,
    SagaInstanceStatus, SagaJournalRecord, SagaJournalStatus, SagaLease, SagaLeaseOutcome,
    SagaOperatorReason, SagaReceiptScope,
};
use diport::{
    CasStore, CasStoreError, CasStoreOutcome, CasStoreRequest, Checkpoint, CheckpointId,
    CheckpointOwner, CheckpointStoreError, CheckpointVersion, FencedWriteKey, FencedWriteRequest,
    FencedWriter, FencedWriterError, GlobalCasStoreKey, LeaderElector, LeaderElectorError,
    LeaderId, LeaseToken, LockAcquireOutcome, LockRenewOutcome, LockStore, LockStoreError,
    LockStoreKey, OwnerCheckpointStore, SagaClaimOutcome, SagaClaimRequest,
    SagaCompensationProgress, SagaDurableMutation, SagaDurableMutationOutcome, SagaDurableStore,
    SagaDurableStoreError, SagaDurableStoreErrorKind, SagaForwardProgress,
    SagaInstanceRegistration, SagaLeaseHolder, SagaLeaseTtl, SagaOperatorAuthorization,
    SagaOperatorCasOutcome, SagaOperatorClaimOutcome, SagaOperatorJournalExpectation,
    SagaOperatorRepair, SagaOperatorRepairClaim, SagaOperatorRepairReason,
    SagaOperatorStatusOutcome, SagaOperatorStatusSnapshot, SagaOperatorStore, SagaRecoveryOutcome,
    SagaRecoveryRequest, SagaRecoverySnapshot, SagaRunnableInstance, SagaTenantCursor,
    SagaTenantPage, SagaTenantSource, SagaTerminalReceiptOutcome, SagaTerminalReceiptRequest,
    SagaUnresolvedObservation, SagaVerifiedTerminalReceipt, SagaWorkerIdentity, SaveOutcome,
    SecretCoordinate, SecretMaterial, SecretResolver, SecretResolverError, StoredSagaReceipt,
    WriteOutcome, saga_operator_action,
};
// 锁中毒（仅当持锁线程 panic 时发生）恢复 guard 而非 panic：in-mem 替身不在持锁时 panic，
// 且 lib 代码禁 unwrap/expect（clippy deny）。`unwrap_or_else(into_inner)` 取回 guard，clippy-clean。

// ── MemLeaseStore / MemLeaderElector：进程内 leader 选举替身（reconcile harness 测试 / demo）──────────

/// 共享 lease 底座：多个 [`MemLeaderElector`]（模拟多副本）克隆共享同一底座竞争 leadership。
///
/// 确定性、无时钟（不触 clippy disallowed-methods）：lease TTL 过期 / holder crash 由测试显式
/// [`MemLeaseStore::evict`] 模拟；生产替身走真实 redis/pg leader-elect adapter。
#[derive(Default)]
struct LeaseInner {
    /// 当前持有者 + 其任期 epoch；`None` = 无人持有（可被首个 acquire 接管）。
    holder: Option<(LeaderId, vocab::Epoch)>,
    /// 下一个**全新**任期 epoch（每次易手 / 首次获得单调 `+1`；同一持有者续租不动）。
    next_epoch: u64,
}

/// in-mem leader 选举底座（克隆共享同一底座）。经 [`MemLeaseStore::elector`] 取每个副本的端口。
#[derive(Clone, Default)]
pub struct MemLeaseStore {
    inner: Arc<Mutex<LeaseInner>>,
}

impl MemLeaseStore {
    /// 新建空底座（无人持有 leadership，next_epoch 从 0 起）。
    pub fn new() -> Self {
        Self::default()
    }

    /// 取一个副本的 [`MemLeaderElector`]（`id` = 该副本 holder identity，须经 `LeaderId::parse` canonical 校验）。
    pub fn elector(&self, id: LeaderId) -> MemLeaderElector {
        MemLeaderElector {
            store: self.clone(),
            id,
        }
    }

    /// 测试钩子：模拟 lease TTL 过期 / holder crash——清当前持有者，使他副本下次 `acquire` 可接管
    /// （接管获**新**任期 epoch，单调递增）。不重置 `next_epoch`（保跨任期单调）。
    pub fn evict(&self) {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).holder = None;
    }
}

/// 单副本 in-mem leader 选举端口（impl [`diport::LeaderElector`]）。
pub struct MemLeaderElector {
    store: MemLeaseStore,
    id: LeaderId,
}

impl LeaderElector for MemLeaderElector {
    async fn acquire(&self, _lease: Duration) -> Result<Option<LeaseToken>, LeaderElectorError> {
        // reason: in-mem 无 TTL，`lease` 时长被忽略（过期由测试 evict 模拟）；锁内同步无 await。
        let mut g = self.store.inner.lock().unwrap_or_else(|e| e.into_inner());
        match &g.holder {
            // 无人持有 → 接管全新任期（epoch 单调 +1）。
            None => {
                let epoch = vocab::Epoch::new(g.next_epoch);
                g.next_epoch = g.next_epoch.saturating_add(1);
                g.holder = Some((self.id.clone(), epoch));
                Ok(Some(LeaseToken {
                    holder: self.id.clone(),
                    epoch,
                }))
            }
            // 本副本续租 → 同任期 epoch 不变。
            Some((holder, epoch)) if *holder == self.id => Ok(Some(LeaseToken {
                holder: holder.clone(),
                epoch: *epoch,
            })),
            // 他副本持有 → 本副本非 leader。
            Some(_) => Ok(None),
        }
    }

    async fn release(&self, token: LeaseToken) -> Result<(), LeaderElectorError> {
        let mut g = self.store.inner.lock().unwrap_or_else(|e| e.into_inner());
        // 仅当 token 是**当前任期**持有者时让出：holder + epoch **双校验**（已易手或旧任期 stale token
        // 则幂等 no-op）。仅校验 holder 不够——同 holder 重启后持旧 epoch token 会误让出自己续租后的新任期。
        if matches!(&g.holder, Some((holder, epoch)) if *holder == token.holder && *epoch == token.epoch)
        {
            g.holder = None;
        }
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), LeaderElectorError> {
        // reason: in-mem 无 infra 资源，关闭无需释放。
        Ok(())
    }
}

// ── MemFencedWriter：进程内防护写替身（单调 epoch CAS）─────────────────────────────────────────────

/// in-mem 防护写端口（impl [`diport::FencedWriter`]）：**按 `key` 各自**记已接受 epoch 高水位，
/// `epoch < 该 key 高水位` 的写被 [`WriteOutcome::Fenced`]（旧 leader 跨任期 stale 写被挡）；`epoch ≥` 提交并
/// 推进该 key 高水位（**同任期多写 / 不同 key 互不 fence**，幂等由消费方负责）。
///
/// 仅校验 fencing CAS 语义，不持久化 `data`。INVARIANT: RECONCILE-FENCE-MONO-01 { level = "Medium", exec = "manual/opt-in", source = "code" }（per-key 单调，回归见本 crate 单测）。
#[derive(Clone, Default)]
pub struct MemFencedWriter {
    high_water: Arc<Mutex<HashMap<FencedWriteKey, vocab::Epoch>>>,
}

impl MemFencedWriter {
    /// 新建空 writer（各 key 高水位未设，每个 key 首写恒提交）。
    pub fn new() -> Self {
        Self::default()
    }
}

impl FencedWriter for MemFencedWriter {
    async fn write(&self, request: FencedWriteRequest) -> Result<WriteOutcome, FencedWriterError> {
        let mut hw = self.high_water.lock().unwrap_or_else(|e| e.into_inner());
        // per-key 单调：该 key 首写（absent）或 epoch ≥ 该 key 高水位 → 提交并推进；否则 fence（跨任期 stale）。
        match hw.get(&request.key) {
            Some(&seen) if request.epoch < seen => Ok(WriteOutcome::Fenced),
            _ => {
                hw.insert(request.key, request.epoch);
                Ok(WriteOutcome::Committed)
            }
        }
    }

    async fn shutdown(&self) -> Result<(), FencedWriterError> {
        // reason: in-mem 无 infra 资源，关闭无需释放。
        Ok(())
    }
}

// ── MemCasStore：in-mem state-CAS 替身（etcd-revision 条件写）──────────────────────────────────────

/// `MemCasStore` 内部 HashMap 类型别名（规避 clippy::type_complexity）。
type CasStateMap = HashMap<GlobalCasStoreKey, (Vec<u8>, vocab::Epoch)>;

/// in-mem state-CAS 替身（impl [`diport::CasStore`]）：per-key `(value, revision token)`，etcd-revision 条件写。
/// 生产替身走 etcd/redis/postgres adapter；本 crate 仅测试/demo 用。
/// INVARIANT: CAS-REVISION-MONO-01 { level = "Medium", exec = "manual/opt-in", source = "code" }（per-key token 单调 + etcd-revision CAS；回归见本 crate 单测）。
#[derive(Clone, Default)]
pub struct MemCasStore {
    state: Arc<Mutex<CasStateMap>>,
}

impl MemCasStore {
    /// 新建空 store（各 key 无值无 token，首写 create-if-absent 恒 Applied）。
    pub fn new() -> Self {
        Self::default()
    }
}

impl CasStore for MemCasStore {
    async fn compare_and_swap(
        &self,
        request: CasStoreRequest,
    ) -> Result<CasStoreOutcome, CasStoreError> {
        let mut map = self.state.lock().unwrap_or_else(|e| e.into_inner());
        // 克隆现有条目（释放不可变借用），避免与后续 map.insert 的可变借用冲突。
        let existing = map.get(&request.key).map(|(v, t)| (v.clone(), *t));
        match existing {
            None => {
                // 仅 expected==None（create-if-absent）命中；否则期望某值但键不存在 → Conflict{None}。
                if request.expected.is_none() {
                    let token = vocab::Epoch::new(1);
                    map.insert(request.key, (request.new_value.into_bytes(), token));
                    Ok(CasStoreOutcome::Applied { token })
                } else {
                    Ok(CasStoreOutcome::Conflict { current: None })
                }
            }
            Some((current, current_token)) => {
                // 先判 fencing：expected_token 低于当前 token → stale，拒写。
                if matches!(request.expected_token, Some(t) if t < current_token) {
                    return Ok(CasStoreOutcome::Fenced { current_token });
                }
                // 再判值：匹配 → 写入 + token.next()；不符 → Conflict{当前值}。
                if request.expected.as_ref().map(|b| b.as_bytes()) == Some(current.as_slice()) {
                    let token = current_token.next();
                    map.insert(request.key, (request.new_value.into_bytes(), token));
                    Ok(CasStoreOutcome::Applied { token })
                } else {
                    Ok(CasStoreOutcome::Conflict {
                        current: Some(current.into()),
                    })
                }
            }
        }
    }

    async fn shutdown(&self) -> Result<(), CasStoreError> {
        // reason: in-mem 无 infra 资源，关闭无需释放。
        Ok(())
    }
}

// ── MemLockStore：in-mem 分布式互斥锁替身（per-key 单调 fencing token）────────────────────────────────

/// `MemLockStore` 内部 per-key 锁条目：`held`=当前持有 token（`None`=空闲），`minted`=该 key 已发最高
/// token（单调；下次授予 = `minted+1`，跨 acquire/release/evict **不回退**）。
#[derive(Default)]
struct LockEntry {
    held: Option<vocab::Epoch>,
    minted: u64,
}

/// in-mem 分布式互斥锁替身（impl [`diport::LockStore`]）：per-key fencing token、token-as-capability 互斥。
/// **无时钟**——`ttl` 入参被忽略（TTL 过期 / holder crash 由 [`MemLockStore::evict`] 显式模拟，照
/// [`MemLeaseStore::evict`] 先例，不触 clippy disallowed-methods 系统时钟）。生产替身走 etcd/redis/consul
/// adapter；本 crate 仅测试/demo 用。INVARIANT: DISTLOCK-FENCE-MONO-01 { level = "Medium", exec = "manual/opt-in", source = "code" }（per-key token 单调 + 互斥；回归见本 crate 单测）。
#[derive(Clone, Default)]
pub struct MemLockStore {
    state: Arc<Mutex<HashMap<LockStoreKey, LockEntry>>>,
}

impl MemLockStore {
    /// 新建空 store（各 key 无持有者、minted 从 0 起，首 acquire 授 token=1）。
    pub fn new() -> Self {
        Self::default()
    }

    /// 测试钩子：模拟 lock TTL 过期 / holder crash——清该 key 持有者，使下次 `acquire` 可接管
    /// （接管获**新**单调 token，不回退 `minted`）。照 [`MemLeaseStore::evict`]；生产走真实 TTL 过期。
    pub fn evict(&self, key: &LockStoreKey) {
        if let Some(entry) = self
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(key)
        {
            entry.held = None;
        }
    }
}

impl LockStore for MemLockStore {
    async fn acquire(
        &self,
        key: LockStoreKey,
        _ttl: Duration,
    ) -> Result<LockAcquireOutcome, LockStoreError> {
        // reason: in-mem 无 TTL，`ttl` 被忽略（过期由测试 evict 模拟）；锁内同步无 await。
        let mut map = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let entry = map.entry(key).or_default();
        if entry.held.is_some() {
            Ok(LockAcquireOutcome::Held)
        } else {
            let token = vocab::Epoch::new(entry.minted.saturating_add(1));
            entry.minted = token.get();
            entry.held = Some(token);
            Ok(LockAcquireOutcome::Acquired { token })
        }
    }

    async fn renew(
        &self,
        key: LockStoreKey,
        token: vocab::Epoch,
        _ttl: Duration,
    ) -> Result<LockRenewOutcome, LockStoreError> {
        let map = self.state.lock().unwrap_or_else(|e| e.into_inner());
        // 仅当 token 是当前持有者才续租（同任期 token 不变）；否则已易手 / 过期被接管 → Lost。
        match map.get(&key) {
            Some(entry) if entry.held == Some(token) => Ok(LockRenewOutcome::Renewed { token }),
            _ => Ok(LockRenewOutcome::Lost),
        }
    }

    async fn release(&self, key: LockStoreKey, token: vocab::Epoch) -> Result<(), LockStoreError> {
        let mut map = self.state.lock().unwrap_or_else(|e| e.into_inner());
        // 仅当 token 是当前持有者才放锁（幂等：stale / 已释放 → no-op，不误释他人锁）。
        if let Some(entry) = map.get_mut(&key)
            && entry.held == Some(token)
        {
            entry.held = None;
        }
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), LockStoreError> {
        // reason: in-mem 无 infra 资源，关闭无需释放。
        Ok(())
    }
}

// ── MemSagaDurableStore：closed saga durable aggregate ────────────────────────

#[derive(Clone)]
struct MemSagaInstanceState {
    status: SagaInstanceStatus,
    identity: SagaWorkerIdentity,
    definition: consistency::SagaDefinitionIdentity,
    holder_id: Option<String>,
    lease_token: Option<uuid::Uuid>,
    epoch: u64,
    expires_at: Option<SystemTime>,
    operator_reason: Option<SagaOperatorReason>,
    compensation_cause: Option<SagaCompensationCause>,
}

impl MemSagaInstanceState {
    fn record(
        &self,
        instance: SagaInstanceRef,
    ) -> Result<SagaInstanceRecord, SagaDurableStoreError> {
        let record = SagaInstanceRecord::new(
            instance,
            self.status,
            self.identity.clone(),
            self.definition.clone(),
        )
        .map_err(|error| mem_saga_error(SagaDurableStoreErrorKind::Integrity, error))?;
        match (self.status, self.operator_reason) {
            (SagaInstanceStatus::OperatorRequired, Some(reason)) => record
                .with_operator_reason(reason)
                .map_err(|error| mem_saga_error(SagaDurableStoreErrorKind::Integrity, error)),
            (SagaInstanceStatus::OperatorRequired, None) => Err(mem_saga_error(
                SagaDurableStoreErrorKind::Integrity,
                MemSagaInvariant("operator-required saga has no reason"),
            )),
            (_, Some(_)) => Err(mem_saga_error(
                SagaDurableStoreErrorKind::Integrity,
                MemSagaInvariant("non-operator saga retains an operator reason"),
            )),
            (_, None) => Ok(record),
        }
    }

    fn lease_is_free(&self, now: SystemTime) -> bool {
        self.lease_token.is_none() || self.expires_at.is_some_and(|expires| expires <= now)
    }

    fn is_runnable(&self, now: SystemTime) -> bool {
        matches!(
            self.status,
            SagaInstanceStatus::Ready
                | SagaInstanceStatus::Running
                | SagaInstanceStatus::Compensating
        ) && self.lease_is_free(now)
    }

    fn lease_matches(&self, lease: &SagaLease, now: SystemTime) -> bool {
        self.lease_token == Some(lease.lease_token())
            && self.epoch == lease.epoch()
            && self.holder_id.as_deref() == Some(lease.holder_id())
            && self.expires_at.is_some_and(|expires| expires > now)
    }
}

type SagaInstanceMap = HashMap<(String, uuid::Uuid), MemSagaInstanceState>;

#[derive(Clone, PartialEq, Eq)]
struct MemSagaJournalEntry {
    seq: u64,
    step_name: vocab::StepName,
    status: SagaJournalStatus,
    attempt: consistency::SagaAttempt,
    effect_key: SagaIdempotencyKey,
    error_summary: Option<&'static str>,
    compensation_cause: Option<consistency::SagaCompensationCause>,
}

impl MemSagaJournalEntry {
    fn new(
        seq: u64,
        step_name: vocab::StepName,
        status: SagaJournalStatus,
        attempt: consistency::SagaAttempt,
        effect_key: SagaIdempotencyKey,
        error_summary: Option<&'static str>,
        compensation_cause: Option<consistency::SagaCompensationCause>,
    ) -> Self {
        Self {
            seq,
            step_name,
            status,
            attempt,
            effect_key,
            error_summary,
            compensation_cause,
        }
    }
}

struct MemSagaReceiptRow {
    scope: SagaReceiptScope,
    attempt: consistency::SagaAttempt,
    format: consistency::SagaReceiptFormatVersion,
    plaintext: zeroize::Zeroizing<Vec<u8>>,
    completed_seq: u64,
}

#[derive(Default)]
struct MemSagaState {
    instances: SagaInstanceMap,
    journal: Vec<(SagaInstanceRef, MemSagaJournalEntry)>,
    receipts: Vec<MemSagaReceiptRow>,
    operator_decisions: Vec<MemSagaOperatorDecision>,
}

// The in-memory adapter persists the complete audit tuple; adapter conformance tests inspect it
// directly because this provider intentionally exposes no production audit-query surface.
#[allow(dead_code)]
struct MemSagaOperatorDecision {
    instance: SagaInstanceRef,
    reason: Option<SagaOperatorReason>,
    reason_text: String,
    decision: &'static str,
    actor: String,
    change_ticket: String,
    start_audit_id: String,
    seq: Option<u64>,
}

/// In-memory implementation of the single closed durable Saga writer boundary.
#[derive(Clone, Default)]
pub struct MemSagaDurableStore {
    inner: Arc<Mutex<MemSagaState>>,
}

impl MemSagaDurableStore {
    /// Construct an empty durable Saga aggregate.
    pub fn new() -> Self {
        Self::default()
    }
}

impl SagaDurableStore for MemSagaDurableStore {
    async fn register(
        &self,
        authorization: diport::SagaStartAuthorization,
        registration: SagaInstanceRegistration,
    ) -> Result<SagaInstanceRecord, SagaDurableStoreError> {
        let instance = registration.instance();
        if authorization.instance() != instance
            || authorization.identity() != registration.identity()
        {
            return Err(mem_saga_error(
                SagaDurableStoreErrorKind::IdentityConflict,
                MemSagaInvariant("saga start authorization target mismatch"),
            ));
        }
        let key = saga_instance_key(instance);
        let mut durable = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(state) = durable.instances.get(&key) {
            if state.identity != *registration.identity()
                || state.definition != *registration.definition()
            {
                return Err(mem_saga_error(
                    SagaDurableStoreErrorKind::IdentityConflict,
                    MemSagaInvariant("saga instance definition identity conflict"),
                ));
            }
            return state.record(instance);
        }
        let state = durable
            .instances
            .entry(key)
            .or_insert_with(|| MemSagaInstanceState {
                status: SagaInstanceStatus::Ready,
                identity: registration.identity().clone(),
                definition: registration.definition().clone(),
                holder_id: None,
                lease_token: None,
                epoch: 0,
                expires_at: None,
                operator_reason: None,
                compensation_cause: None,
            });
        state.record(instance)
    }

    async fn get(
        &self,
        instance: &SagaInstanceRef,
    ) -> Result<Option<SagaInstanceRecord>, SagaDurableStoreError> {
        let durable = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        durable
            .instances
            .get(&saga_instance_key(*instance))
            .map(|state| state.record(*instance))
            .transpose()
    }

    async fn list_runnable(
        &self,
        identity: &SagaWorkerIdentity,
        tenant: rss_request_context::TenantId,
        limit: NonZeroUsize,
    ) -> Result<Vec<SagaRunnableInstance>, SagaDurableStoreError> {
        let now = saga_now();
        let tenant_key = tenant.to_string();
        let durable = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut rows = Vec::new();
        for ((row_tenant, saga_id), state) in &durable.instances {
            if row_tenant != &tenant_key || state.identity != *identity || !state.is_runnable(now) {
                continue;
            }
            let instance = SagaInstanceRef::new(tenant, consistency::SagaId::new(*saga_id))
                .map_err(|error| mem_saga_error(SagaDurableStoreErrorKind::Integrity, error))?;
            rows.push(
                SagaRunnableInstance::new(
                    instance,
                    state.status,
                    state.identity.clone(),
                    state.definition.clone(),
                )
                .map_err(|error| mem_saga_error(SagaDurableStoreErrorKind::Integrity, error))?,
            );
        }
        rows.sort_by_key(|row| row.instance().saga_id().as_uuid());
        rows.truncate(limit.get());
        Ok(rows)
    }

    async fn claim(
        &self,
        request: SagaClaimRequest,
    ) -> Result<SagaClaimOutcome, SagaDurableStoreError> {
        let now = saga_now();
        let expires_at = checked_expiry(now, request.ttl().as_duration())?;
        let expected = request.expected();
        let instance = expected.instance();
        let mut durable = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(state) = durable.instances.get_mut(&saga_instance_key(instance)) else {
            return Ok(SagaClaimOutcome::Missing);
        };
        if state.identity != *expected.identity() || state.definition != *expected.definition() {
            return Ok(SagaClaimOutcome::IdentityConflict);
        }
        match state.status {
            SagaInstanceStatus::OperatorRequired => {
                return state
                    .operator_reason
                    .map(SagaClaimOutcome::OperatorRequired)
                    .ok_or_else(|| {
                        mem_saga_error(
                            SagaDurableStoreErrorKind::Integrity,
                            MemSagaInvariant("operator-required saga has no reason"),
                        )
                    });
            }
            SagaInstanceStatus::Degraded => return Ok(SagaClaimOutcome::Degraded),
            status @ (SagaInstanceStatus::Succeeded
            | SagaInstanceStatus::Compensated
            | SagaInstanceStatus::Expired
            | SagaInstanceStatus::Terminated) => {
                return Ok(SagaClaimOutcome::Terminal(status));
            }
            SagaInstanceStatus::CompensationFailed => return Ok(SagaClaimOutcome::Degraded),
            _ => {}
        }
        if !state.lease_is_free(now) {
            return Ok(SagaClaimOutcome::Busy);
        }
        if state.status != expected.status() {
            return Ok(SagaClaimOutcome::Stale(state.status));
        }
        let token = uuid::Uuid::new_v4();
        state.epoch = state.epoch.saturating_add(1);
        state.lease_token = Some(token);
        state.holder_id = Some(request.holder_id().to_string());
        state.expires_at = Some(expires_at);
        if state.status == SagaInstanceStatus::Ready {
            state.status = SagaInstanceStatus::Running;
        }
        SagaLease::new(instance, request.holder_id(), token, state.epoch)
            .map(SagaClaimOutcome::Acquired)
            .map_err(|error| mem_saga_error(SagaDurableStoreErrorKind::Integrity, error))
    }

    async fn renew(
        &self,
        lease: &SagaLease,
        ttl: SagaLeaseTtl,
    ) -> Result<SagaLeaseOutcome, SagaDurableStoreError> {
        let now = saga_now();
        let expires_at = checked_expiry(now, ttl.as_duration())?;
        let mut durable = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(state) = durable
            .instances
            .get_mut(&saga_instance_key(lease.instance()))
        else {
            return Ok(SagaLeaseOutcome::Lost);
        };
        if !state.lease_matches(lease, now) {
            return Ok(SagaLeaseOutcome::Lost);
        }
        state.expires_at = Some(expires_at);
        Ok(SagaLeaseOutcome::Held)
    }

    async fn release(&self, lease: &SagaLease) -> Result<SagaLeaseOutcome, SagaDurableStoreError> {
        let now = saga_now();
        let mut durable = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(state) = durable
            .instances
            .get_mut(&saga_instance_key(lease.instance()))
        else {
            return Ok(SagaLeaseOutcome::Lost);
        };
        if !state.lease_matches(lease, now) {
            return Ok(SagaLeaseOutcome::Lost);
        }
        clear_saga_lease(state);
        Ok(SagaLeaseOutcome::Held)
    }

    async fn recovery_snapshot(
        &self,
        request: SagaRecoveryRequest,
    ) -> Result<SagaRecoveryOutcome, SagaDurableStoreError> {
        let now = saga_now();
        let (lease, scopes) = request.into_parts();
        let durable = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(state) = durable.instances.get(&saga_instance_key(lease.instance())) else {
            return Ok(SagaRecoveryOutcome::LeaseLost);
        };
        if !state.lease_matches(&lease, now) {
            return Ok(SagaRecoveryOutcome::LeaseLost);
        }
        let instance = state.record(lease.instance())?;
        let mut journal = durable
            .journal
            .iter()
            .filter(|(stored, _)| *stored == lease.instance())
            .map(|(_, entry)| {
                SagaJournalRecord::replayed(entry.seq, entry.step_name.clone(), entry.status)
            })
            .collect::<Vec<_>>();
        journal.sort_by_key(SagaJournalRecord::seq);
        let mut receipts = Vec::new();
        for scope in scopes {
            if let Some(row) = durable.receipts.iter().find(|row| row.scope == scope) {
                receipts.push(StoredSagaReceipt::new(
                    row.scope.clone(),
                    row.attempt,
                    row.format,
                    rss_data_protection::Plaintext::new(row.plaintext.to_vec()),
                    row.completed_seq,
                ));
            }
        }
        Ok(SagaRecoveryOutcome::Available(SagaRecoverySnapshot::new(
            instance,
            journal,
            receipts,
            state.operator_reason,
            state.compensation_cause,
        )))
    }

    async fn terminal_receipt(
        &self,
        request: SagaTerminalReceiptRequest,
    ) -> Result<SagaTerminalReceiptOutcome, SagaDurableStoreError> {
        let scope = request.into_scope();
        let instance = scope.instance();
        let durable = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(state) = durable.instances.get(&saga_instance_key(instance)) else {
            return Ok(SagaTerminalReceiptOutcome::Missing);
        };
        if state.status != SagaInstanceStatus::Succeeded {
            return Ok(SagaTerminalReceiptOutcome::NotSucceeded(state.status));
        }
        let record = state.record(instance)?;
        if record.identity() != scope.worker() || record.definition() != scope.definition() {
            return Err(mem_saga_error(
                SagaDurableStoreErrorKind::Integrity,
                MemSagaInvariant("terminal saga receipt identity mismatch"),
            ));
        }
        let mut journal = durable
            .journal
            .iter()
            .filter(|(stored, _)| *stored == instance)
            .map(|(_, entry)| {
                SagaJournalRecord::replayed(entry.seq, entry.step_name.clone(), entry.status)
            })
            .collect::<Vec<_>>();
        journal.sort_by_key(SagaJournalRecord::seq);
        let Some(last) = journal.last() else {
            return Err(mem_saga_error(
                SagaDurableStoreErrorKind::Integrity,
                MemSagaInvariant("succeeded saga has no journal"),
            ));
        };
        let Some(row) = durable.receipts.iter().find(|row| row.scope == scope) else {
            return Err(mem_saga_error(
                SagaDurableStoreErrorKind::Integrity,
                MemSagaInvariant("succeeded saga final receipt is missing"),
            ));
        };
        if last.status() != SagaJournalStatus::ForwardCompleted
            || last.seq() != row.completed_seq
            || last.step_name() != scope.step_name()
        {
            return Err(mem_saga_error(
                SagaDurableStoreErrorKind::Integrity,
                MemSagaInvariant("succeeded saga final receipt is not the terminal transition"),
            ));
        }
        let receipt = StoredSagaReceipt::new(
            row.scope.clone(),
            row.attempt,
            row.format,
            rss_data_protection::Plaintext::new(row.plaintext.to_vec()),
            row.completed_seq,
        );
        Ok(SagaTerminalReceiptOutcome::Verified(Box::new(
            SagaVerifiedTerminalReceipt::new(record, journal, receipt),
        )))
    }

    async fn mutate(
        &self,
        lease: &SagaLease,
        mutation: SagaDurableMutation,
    ) -> Result<SagaDurableMutationOutcome, SagaDurableStoreError> {
        let now = saga_now();
        let instance = lease.instance();
        let mut durable = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if !durable
            .instances
            .get(&saga_instance_key(instance))
            .is_some_and(|state| state.lease_matches(lease, now))
        {
            return Ok(SagaDurableMutationOutcome::LeaseLost);
        }
        match mutation {
            SagaDurableMutation::ForwardIntent(intent) => {
                if durable.instances[&saga_instance_key(instance)].status
                    != SagaInstanceStatus::Running
                {
                    return Ok(SagaDurableMutationOutcome::Conflict);
                }
                let entry = MemSagaJournalEntry::new(
                    intent.seq(),
                    intent.step().clone(),
                    SagaJournalStatus::ForwardIntent,
                    intent.attempt(),
                    intent.effect_key().clone(),
                    None,
                    None,
                );
                Ok(insert_mem_intent(&mut durable, instance, entry))
            }
            SagaDurableMutation::ForwardCompleted(completed) => {
                if durable.instances[&saga_instance_key(instance)].status
                    != SagaInstanceStatus::Running
                {
                    return Ok(SagaDurableMutationOutcome::Conflict);
                }
                let progress = completed.progress();
                let (completion, _) = completed.into_parts();
                let (scope, attempt, format, plaintext, completed_seq) = completion.into_parts();
                if scope.instance() != instance {
                    return Err(mem_saga_error(
                        SagaDurableStoreErrorKind::Integrity,
                        MemSagaInvariant("memory saga receipt lease scope mismatch"),
                    ));
                }
                if !has_exact_prior_mem_intent(
                    &durable,
                    instance,
                    completed_seq,
                    scope.step_name(),
                    SagaJournalStatus::ForwardIntent,
                    attempt,
                    scope.effect_key(),
                    None,
                ) {
                    return Ok(SagaDurableMutationOutcome::Conflict);
                }
                let plaintext = zeroize::Zeroizing::new(plaintext.expose().to_vec());
                let journal_entry = MemSagaJournalEntry::new(
                    completed_seq,
                    scope.step_name().clone(),
                    SagaJournalStatus::ForwardCompleted,
                    attempt,
                    scope.effect_key().clone(),
                    None,
                    None,
                );
                let journal_match = durable
                    .journal
                    .iter()
                    .find(|(stored, row)| *stored == instance && row.seq == completed_seq)
                    .map(|(_, row)| row == &journal_entry);
                let receipt_match =
                    durable
                        .receipts
                        .iter()
                        .find(|row| row.scope == scope)
                        .map(|row| {
                            row.attempt == attempt
                                && row.format == format
                                && row.completed_seq == completed_seq
                                && primitives::constant_time_eq(&row.plaintext, &plaintext)
                        });
                if journal_match == Some(true) && receipt_match == Some(true) {
                    return Ok(if progress == SagaForwardProgress::Continue {
                        SagaDurableMutationOutcome::IdempotentDuplicate
                    } else {
                        SagaDurableMutationOutcome::Conflict
                    });
                }
                if journal_match.is_some() || receipt_match.is_some() {
                    return Ok(SagaDurableMutationOutcome::Conflict);
                }
                if durable.receipts.iter().any(|row| {
                    row.scope.instance().tenant() == scope.instance().tenant()
                        && primitives::constant_time_eq(
                            row.scope.effect_key().as_bytes(),
                            scope.effect_key().as_bytes(),
                        )
                }) {
                    return Ok(SagaDurableMutationOutcome::Conflict);
                }
                durable.journal.push((instance, journal_entry));
                durable.receipts.push(MemSagaReceiptRow {
                    scope,
                    attempt,
                    format,
                    plaintext,
                    completed_seq,
                });
                if progress == SagaForwardProgress::Succeeded {
                    let state = durable
                        .instances
                        .get_mut(&saga_instance_key(instance))
                        .ok_or_else(|| {
                            mem_saga_error(
                                SagaDurableStoreErrorKind::Integrity,
                                MemSagaInvariant("memory saga instance disappeared"),
                            )
                        })?;
                    state.status = SagaInstanceStatus::Succeeded;
                    clear_saga_lease(state);
                }
                Ok(SagaDurableMutationOutcome::Applied)
            }
            SagaDurableMutation::CompensationIntent(intent) => {
                let state = durable
                    .instances
                    .get(&saga_instance_key(instance))
                    .ok_or_else(|| {
                        mem_saga_error(
                            SagaDurableStoreErrorKind::Integrity,
                            MemSagaInvariant("memory saga instance disappeared"),
                        )
                    })?;
                if !matches!(
                    state.status,
                    SagaInstanceStatus::Running | SagaInstanceStatus::Compensating
                ) || state
                    .compensation_cause
                    .is_some_and(|cause| cause != intent.cause())
                {
                    return Ok(SagaDurableMutationOutcome::Conflict);
                }
                let entry = MemSagaJournalEntry::new(
                    intent.seq(),
                    intent.step().clone(),
                    SagaJournalStatus::CompensationIntent,
                    intent.attempt(),
                    intent.effect_key().clone(),
                    None,
                    Some(intent.cause()),
                );
                let outcome = insert_mem_intent(&mut durable, instance, entry);
                if outcome == SagaDurableMutationOutcome::Conflict {
                    return Ok(outcome);
                }
                let state = durable
                    .instances
                    .get_mut(&saga_instance_key(instance))
                    .ok_or_else(|| {
                        mem_saga_error(
                            SagaDurableStoreErrorKind::Integrity,
                            MemSagaInvariant("memory saga instance disappeared"),
                        )
                    })?;
                state.status = SagaInstanceStatus::Compensating;
                state.compensation_cause = Some(intent.cause());
                Ok(outcome)
            }
            SagaDurableMutation::CompensationCompleted(completed) => {
                if durable.instances[&saga_instance_key(instance)].status
                    != SagaInstanceStatus::Compensating
                {
                    return Ok(SagaDurableMutationOutcome::Conflict);
                }
                let cause = durable.instances[&saga_instance_key(instance)].compensation_cause;
                if !has_exact_prior_mem_intent(
                    &durable,
                    instance,
                    completed.seq(),
                    completed.step(),
                    SagaJournalStatus::CompensationIntent,
                    completed.attempt(),
                    completed.effect_key(),
                    cause,
                ) {
                    return Ok(SagaDurableMutationOutcome::Conflict);
                }
                let progress = completed.progress();
                let entry = MemSagaJournalEntry::new(
                    completed.seq(),
                    completed.step().clone(),
                    SagaJournalStatus::CompensationCompleted,
                    completed.attempt(),
                    completed.effect_key().clone(),
                    None,
                    None,
                );
                let outcome = insert_mem_journal(&mut durable, instance, entry);
                if outcome != SagaDurableMutationOutcome::Applied {
                    return Ok(
                        if outcome == SagaDurableMutationOutcome::IdempotentDuplicate
                            && progress != SagaCompensationProgress::Continue
                        {
                            SagaDurableMutationOutcome::Conflict
                        } else {
                            outcome
                        },
                    );
                }
                if progress != SagaCompensationProgress::Continue {
                    let state = durable
                        .instances
                        .get_mut(&saga_instance_key(instance))
                        .ok_or_else(|| {
                            mem_saga_error(
                                SagaDurableStoreErrorKind::Integrity,
                                MemSagaInvariant("memory saga instance disappeared"),
                            )
                        })?;
                    state.status = match progress {
                        SagaCompensationProgress::Continue => SagaInstanceStatus::Compensating,
                        SagaCompensationProgress::Compensated => SagaInstanceStatus::Compensated,
                        SagaCompensationProgress::Expired => SagaInstanceStatus::Expired,
                        _ => return Ok(SagaDurableMutationOutcome::Conflict),
                    };
                    clear_saga_lease(state);
                }
                Ok(SagaDurableMutationOutcome::Applied)
            }
            SagaDurableMutation::CompensationFailed(failure) => {
                if durable.instances[&saga_instance_key(instance)].status
                    != SagaInstanceStatus::Compensating
                {
                    return Ok(SagaDurableMutationOutcome::Conflict);
                }
                let cause = durable.instances[&saga_instance_key(instance)].compensation_cause;
                if !has_exact_prior_mem_intent(
                    &durable,
                    instance,
                    failure.seq(),
                    failure.step(),
                    SagaJournalStatus::CompensationIntent,
                    failure.attempt(),
                    failure.effect_key(),
                    cause,
                ) {
                    return Ok(SagaDurableMutationOutcome::Conflict);
                }
                let entry = MemSagaJournalEntry::new(
                    failure.seq(),
                    failure.step().clone(),
                    SagaJournalStatus::CompensationFailed,
                    failure.attempt(),
                    failure.effect_key().clone(),
                    Some(failure.error_summary()),
                    None,
                );
                let outcome = insert_mem_journal(&mut durable, instance, entry);
                if outcome != SagaDurableMutationOutcome::Applied {
                    return Ok(outcome);
                }
                let state = durable
                    .instances
                    .get_mut(&saga_instance_key(instance))
                    .ok_or_else(|| {
                        mem_saga_error(
                            SagaDurableStoreErrorKind::Integrity,
                            MemSagaInvariant("memory saga instance disappeared"),
                        )
                    })?;
                state.status = SagaInstanceStatus::CompensationFailed;
                clear_saga_lease(state);
                Ok(SagaDurableMutationOutcome::Applied)
            }
            SagaDurableMutation::OperatorRequired(reason) => {
                let state = durable
                    .instances
                    .get_mut(&saga_instance_key(instance))
                    .ok_or_else(|| {
                        mem_saga_error(
                            SagaDurableStoreErrorKind::Integrity,
                            MemSagaInvariant("memory saga instance disappeared"),
                        )
                    })?;
                if reason.preserves_compensation_cause()
                    && (state.status != SagaInstanceStatus::Compensating
                        || state.compensation_cause.is_none())
                {
                    return Ok(SagaDurableMutationOutcome::Conflict);
                }
                state.status = SagaInstanceStatus::OperatorRequired;
                state.operator_reason = Some(reason);
                if !reason.preserves_compensation_cause() {
                    state.compensation_cause = None;
                }
                clear_saga_lease(state);
                Ok(SagaDurableMutationOutcome::Applied)
            }
            SagaDurableMutation::Degraded => {
                let state = durable
                    .instances
                    .get_mut(&saga_instance_key(instance))
                    .ok_or_else(|| {
                        mem_saga_error(
                            SagaDurableStoreErrorKind::Integrity,
                            MemSagaInvariant("memory saga instance disappeared"),
                        )
                    })?;
                state.status = SagaInstanceStatus::Degraded;
                state.operator_reason = None;
                state.compensation_cause = None;
                clear_saga_lease(state);
                Ok(SagaDurableMutationOutcome::Applied)
            }
            _ => Ok(SagaDurableMutationOutcome::Conflict),
        }
    }

    async fn shutdown(&self) -> Result<(), SagaDurableStoreError> {
        Ok(())
    }
}

/// Move-only operator claim minted exclusively by [`MemSagaDurableStore`].
pub struct MemSagaOperatorClaim {
    lease: SagaLease,
    authorization: SagaOperatorAuthorization<saga_operator_action::Repair>,
}

impl SagaOperatorRepairClaim for MemSagaOperatorClaim {
    fn instance(&self) -> SagaInstanceRef {
        self.authorization.instance()
    }

    fn expected_reason(&self) -> SagaOperatorRepairReason {
        self.authorization.evidence().reason()
    }
}

impl SagaOperatorStore for MemSagaDurableStore {
    type RepairClaim = MemSagaOperatorClaim;

    async fn operator_status(
        &self,
        authorization: SagaOperatorAuthorization<saga_operator_action::Status>,
    ) -> Result<SagaOperatorStatusOutcome, SagaDurableStoreError> {
        let instance = authorization.instance();
        let durable = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(state) = durable.instances.get(&saga_instance_key(instance)) else {
            return Ok(SagaOperatorStatusOutcome::Missing);
        };
        if state.identity != *authorization.identity() {
            return Ok(SagaOperatorStatusOutcome::IdentityConflict);
        }
        let latest = durable
            .journal
            .iter()
            .filter(|(stored, _)| *stored == instance)
            .map(|(_, entry)| entry)
            .max_by_key(|entry| entry.seq)
            .map(|entry| {
                SagaOperatorJournalExpectation::new(
                    SagaJournalRecord::replayed(entry.seq, entry.step_name.clone(), entry.status),
                    entry.attempt,
                    entry.effect_key.clone(),
                )
                .map_err(|error| mem_saga_error(SagaDurableStoreErrorKind::Integrity, error))
            })
            .transpose()?;
        let has_effect_intent = durable.journal.iter().any(|(stored, entry)| {
            *stored == instance
                && matches!(
                    entry.status,
                    SagaJournalStatus::ForwardIntent | SagaJournalStatus::CompensationIntent
                )
        });
        Ok(SagaOperatorStatusOutcome::Found(Box::new(
            SagaOperatorStatusSnapshot::new(
                state.record(instance)?,
                latest,
                has_effect_intent,
                None,
            ),
        )))
    }

    async fn retry_compensation(
        &self,
        authorization: SagaOperatorAuthorization<saga_operator_action::RetryCompensation>,
    ) -> Result<SagaOperatorCasOutcome, SagaDurableStoreError> {
        let now = saga_now();
        let instance = authorization.instance();
        let expected = authorization.evidence().journal();
        let mut durable = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(state) = durable.instances.get(&saga_instance_key(instance)) else {
            return Ok(SagaOperatorCasOutcome::Missing);
        };
        if state.identity != *authorization.identity() {
            return Ok(SagaOperatorCasOutcome::IdentityConflict);
        }
        if state.status != SagaInstanceStatus::CompensationFailed {
            return Ok(SagaOperatorCasOutcome::StaleStatus(state.status));
        }
        if !state.lease_is_free(now) {
            return Ok(SagaOperatorCasOutcome::Busy);
        }
        let latest = durable
            .journal
            .iter()
            .filter(|(stored, _)| *stored == instance)
            .map(|(_, entry)| entry)
            .max_by_key(|entry| entry.seq);
        if !latest.is_some_and(|entry| {
            entry.seq == expected.record().seq()
                && entry.step_name == *expected.record().step_name()
                && entry.status == expected.record().status()
                && entry.attempt == expected.attempt()
                && entry.effect_key == *expected.effect_key()
        }) {
            return Ok(SagaOperatorCasOutcome::StaleJournal);
        }
        let state = durable
            .instances
            .get_mut(&saga_instance_key(instance))
            .ok_or_else(|| {
                mem_saga_error(
                    SagaDurableStoreErrorKind::Integrity,
                    MemSagaInvariant("memory saga instance disappeared"),
                )
            })?;
        state.status = SagaInstanceStatus::Compensating;
        state.operator_reason = None;
        clear_saga_lease(state);
        durable.operator_decisions.push(MemSagaOperatorDecision {
            instance,
            reason: None,
            reason_text: authorization.evidence().reason_text().as_str().to_owned(),
            decision: "retry_compensation",
            actor: authorization.caller().as_str().to_owned(),
            change_ticket: authorization.evidence().change_ticket().as_str().to_owned(),
            start_audit_id: authorization.start_audit_id().as_str().to_owned(),
            seq: Some(expected.record().seq()),
        });
        Ok(SagaOperatorCasOutcome::Applied)
    }

    async fn claim_repair(
        &self,
        authorization: SagaOperatorAuthorization<saga_operator_action::Repair>,
        holder: SagaLeaseHolder,
        ttl: SagaLeaseTtl,
    ) -> Result<SagaOperatorClaimOutcome<Self::RepairClaim>, SagaDurableStoreError> {
        let now = saga_now();
        let expires_at = checked_expiry(now, ttl.as_duration())?;
        let instance = authorization.instance();
        let holder_id = holder.as_str().to_string();
        let mut durable = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(state) = durable.instances.get_mut(&saga_instance_key(instance)) else {
            return Ok(SagaOperatorClaimOutcome::Missing);
        };
        if state.status != SagaInstanceStatus::OperatorRequired {
            return Ok(SagaOperatorClaimOutcome::StaleStatus(state.status));
        }
        let reason = state.operator_reason.ok_or_else(|| {
            mem_saga_error(
                SagaDurableStoreErrorKind::Integrity,
                MemSagaInvariant("operator-required saga has no reason"),
            )
        })?;
        if state.identity != *authorization.identity() {
            return Ok(SagaOperatorClaimOutcome::StaleReason(reason));
        }
        if reason != authorization.evidence().reason().as_operator_reason() {
            return Ok(SagaOperatorClaimOutcome::StaleReason(reason));
        }
        if !state.lease_is_free(now) {
            return Ok(SagaOperatorClaimOutcome::Busy);
        }
        let token = uuid::Uuid::new_v4();
        state.epoch = state.epoch.saturating_add(1);
        state.lease_token = Some(token);
        state.holder_id = Some(holder_id.clone());
        state.expires_at = Some(expires_at);
        let lease = SagaLease::new(instance, holder_id, token, state.epoch)
            .map_err(|error| mem_saga_error(SagaDurableStoreErrorKind::Integrity, error))?;
        Ok(SagaOperatorClaimOutcome::Acquired(MemSagaOperatorClaim {
            lease,
            authorization,
        }))
    }

    async fn repair_snapshot(
        &self,
        claim: &Self::RepairClaim,
        scopes: Vec<SagaReceiptScope>,
    ) -> Result<SagaRecoveryOutcome, SagaDurableStoreError> {
        let request = SagaRecoveryRequest::new(claim.lease.clone(), scopes)
            .map_err(|error| mem_saga_error(SagaDurableStoreErrorKind::Integrity, error))?;
        SagaDurableStore::recovery_snapshot(self, request).await
    }

    async fn release_repair(
        &self,
        claim: Self::RepairClaim,
    ) -> Result<SagaLeaseOutcome, SagaDurableStoreError> {
        SagaDurableStore::release(self, &claim.lease).await
    }

    async fn commit_repair(
        &self,
        operator: Self::RepairClaim,
        decision: SagaOperatorRepair,
    ) -> Result<SagaOperatorCasOutcome, SagaDurableStoreError> {
        let now = saga_now();
        let lease = &operator.lease;
        let instance = lease.instance();
        let mut durable = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(state) = durable.instances.get(&saga_instance_key(instance)) else {
            return Ok(SagaOperatorCasOutcome::LeaseLost);
        };
        if !state.lease_matches(lease, now)
            || state.status != SagaInstanceStatus::OperatorRequired
            || state.operator_reason != Some(operator.expected_reason().as_operator_reason())
            || state.identity != *operator.authorization.identity()
        {
            return Ok(SagaOperatorCasOutcome::LeaseLost);
        }
        let reason = operator.expected_reason().as_operator_reason();
        let actor = operator.authorization.caller().as_str().to_owned();
        let reason_text = operator
            .authorization
            .evidence()
            .reason_text()
            .as_str()
            .to_owned();
        let ticket = operator
            .authorization
            .evidence()
            .change_ticket()
            .as_str()
            .to_owned();
        let start_audit_id = operator.authorization.start_audit_id().as_str().to_owned();
        let (outcome, label, seq) = match decision {
            SagaOperatorRepair::ForwardApplied(completed) => {
                if !matches!(
                    reason,
                    SagaOperatorReason::ForwardOutcomeUnknown
                        | SagaOperatorReason::CompletionCommitUnknown
                ) {
                    return Ok(SagaOperatorCasOutcome::StaleReason(reason));
                }
                let progress = completed.progress();
                let (completion, _) = completed.into_parts();
                let (scope, attempt, format, plaintext, completed_seq) = completion.into_parts();
                if scope.instance() != instance
                    || !has_exact_prior_mem_intent(
                        &durable,
                        instance,
                        completed_seq,
                        scope.step_name(),
                        SagaJournalStatus::ForwardIntent,
                        attempt,
                        scope.effect_key(),
                        None,
                    )
                {
                    return Ok(SagaOperatorCasOutcome::StaleJournal);
                }
                let entry = MemSagaJournalEntry::new(
                    completed_seq,
                    scope.step_name().clone(),
                    SagaJournalStatus::ForwardCompleted,
                    attempt,
                    scope.effect_key().clone(),
                    None,
                    None,
                );
                let journal_conflict = durable
                    .journal
                    .iter()
                    .any(|(stored, row)| *stored == instance && row.seq == completed_seq);
                let receipt_conflict = durable.receipts.iter().any(|row| {
                    row.scope == scope
                        || (row.scope.instance().tenant() == scope.instance().tenant()
                            && primitives::constant_time_eq(
                                row.scope.effect_key().as_bytes(),
                                scope.effect_key().as_bytes(),
                            ))
                });
                if journal_conflict || receipt_conflict {
                    return Ok(SagaOperatorCasOutcome::StaleJournal);
                }
                durable.journal.push((instance, entry));
                durable.receipts.push(MemSagaReceiptRow {
                    scope,
                    attempt,
                    format,
                    plaintext: zeroize::Zeroizing::new(plaintext.expose().to_vec()),
                    completed_seq,
                });
                let state = durable
                    .instances
                    .get_mut(&saga_instance_key(instance))
                    .ok_or_else(|| {
                        mem_saga_error(
                            SagaDurableStoreErrorKind::Integrity,
                            MemSagaInvariant("memory saga instance disappeared"),
                        )
                    })?;
                state.status = if progress == SagaForwardProgress::Succeeded {
                    SagaInstanceStatus::Succeeded
                } else {
                    SagaInstanceStatus::Running
                };
                state.operator_reason = None;
                clear_saga_lease(state);
                (
                    SagaOperatorCasOutcome::Applied,
                    "confirmed_applied",
                    completed_seq,
                )
            }
            SagaOperatorRepair::ForwardNotApplied(not_applied) => {
                if !matches!(
                    reason,
                    SagaOperatorReason::ForwardOutcomeUnknown
                        | SagaOperatorReason::CompletionCommitUnknown
                ) || !has_exact_prior_mem_intent(
                    &durable,
                    instance,
                    not_applied.seq(),
                    not_applied.step(),
                    SagaJournalStatus::ForwardIntent,
                    not_applied.attempt(),
                    not_applied.effect_key(),
                    None,
                ) {
                    return Ok(SagaOperatorCasOutcome::StaleJournal);
                }
                let seq = not_applied.seq();
                let entry = MemSagaJournalEntry::new(
                    seq,
                    not_applied.step().clone(),
                    SagaJournalStatus::ForwardNotApplied,
                    not_applied.attempt(),
                    not_applied.effect_key().clone(),
                    None,
                    None,
                );
                if insert_mem_journal(&mut durable, instance, entry)
                    != SagaDurableMutationOutcome::Applied
                {
                    return Ok(SagaOperatorCasOutcome::StaleJournal);
                }
                let state = durable
                    .instances
                    .get_mut(&saga_instance_key(instance))
                    .ok_or_else(|| {
                        mem_saga_error(
                            SagaDurableStoreErrorKind::Integrity,
                            MemSagaInvariant("memory saga instance disappeared"),
                        )
                    })?;
                state.status = SagaInstanceStatus::Running;
                state.operator_reason = None;
                clear_saga_lease(state);
                (
                    SagaOperatorCasOutcome::Applied,
                    "confirmed_not_applied",
                    seq,
                )
            }
            SagaOperatorRepair::CompensationApplied(completed) => {
                if reason != SagaOperatorReason::CompensationOutcomeUnknown {
                    return Ok(SagaOperatorCasOutcome::StaleReason(reason));
                }
                let cause = durable.instances[&saga_instance_key(instance)].compensation_cause;
                if !has_exact_prior_mem_intent(
                    &durable,
                    instance,
                    completed.seq(),
                    completed.step(),
                    SagaJournalStatus::CompensationIntent,
                    completed.attempt(),
                    completed.effect_key(),
                    cause,
                ) {
                    return Ok(SagaOperatorCasOutcome::StaleJournal);
                }
                let seq = completed.seq();
                let progress = completed.progress();
                let target_status = match progress {
                    SagaCompensationProgress::Continue => SagaInstanceStatus::Compensating,
                    SagaCompensationProgress::Compensated => SagaInstanceStatus::Compensated,
                    SagaCompensationProgress::Expired => SagaInstanceStatus::Expired,
                    _ => return Ok(SagaOperatorCasOutcome::StaleJournal),
                };
                let entry = MemSagaJournalEntry::new(
                    seq,
                    completed.step().clone(),
                    SagaJournalStatus::CompensationCompleted,
                    completed.attempt(),
                    completed.effect_key().clone(),
                    None,
                    None,
                );
                if insert_mem_journal(&mut durable, instance, entry)
                    != SagaDurableMutationOutcome::Applied
                {
                    return Ok(SagaOperatorCasOutcome::StaleJournal);
                }
                let state = durable
                    .instances
                    .get_mut(&saga_instance_key(instance))
                    .ok_or_else(|| {
                        mem_saga_error(
                            SagaDurableStoreErrorKind::Integrity,
                            MemSagaInvariant("memory saga instance disappeared"),
                        )
                    })?;
                state.status = target_status;
                state.operator_reason = None;
                clear_saga_lease(state);
                (SagaOperatorCasOutcome::Applied, "confirmed_applied", seq)
            }
            SagaOperatorRepair::CompensationNotApplied(not_applied) => {
                if reason != SagaOperatorReason::CompensationOutcomeUnknown
                    || durable.instances[&saga_instance_key(instance)].compensation_cause
                        != Some(not_applied.cause())
                    || !has_exact_prior_mem_intent(
                        &durable,
                        instance,
                        not_applied.seq(),
                        not_applied.step(),
                        SagaJournalStatus::CompensationIntent,
                        not_applied.attempt(),
                        not_applied.effect_key(),
                        Some(not_applied.cause()),
                    )
                {
                    return Ok(SagaOperatorCasOutcome::StaleJournal);
                }
                let seq = not_applied.seq();
                let entry = MemSagaJournalEntry::new(
                    seq,
                    not_applied.step().clone(),
                    SagaJournalStatus::CompensationNotApplied,
                    not_applied.attempt(),
                    not_applied.effect_key().clone(),
                    None,
                    Some(not_applied.cause()),
                );
                if insert_mem_journal(&mut durable, instance, entry)
                    != SagaDurableMutationOutcome::Applied
                {
                    return Ok(SagaOperatorCasOutcome::StaleJournal);
                }
                let state = durable
                    .instances
                    .get_mut(&saga_instance_key(instance))
                    .ok_or_else(|| {
                        mem_saga_error(
                            SagaDurableStoreErrorKind::Integrity,
                            MemSagaInvariant("memory saga instance disappeared"),
                        )
                    })?;
                state.status = SagaInstanceStatus::Compensating;
                state.operator_reason = None;
                clear_saga_lease(state);
                (
                    SagaOperatorCasOutcome::Applied,
                    "confirmed_not_applied",
                    seq,
                )
            }
            _ => return Ok(SagaOperatorCasOutcome::StaleJournal),
        };
        durable.operator_decisions.push(MemSagaOperatorDecision {
            instance,
            reason: Some(reason),
            reason_text,
            decision: label,
            actor,
            change_ticket: ticket,
            start_audit_id,
            seq: Some(seq),
        });
        Ok(outcome)
    }
}

impl MemSagaDurableStore {
    /// Apply the in-memory control-plane termination used by tests and local tooling.
    pub async fn terminate(
        &self,
        authorization: SagaOperatorAuthorization<saga_operator_action::Terminate>,
    ) -> Result<SagaOperatorCasOutcome, SagaDurableStoreError> {
        let now = saga_now();
        let instance = authorization.instance();
        let mut durable = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(state) = durable.instances.get(&saga_instance_key(instance)) else {
            return Ok(SagaOperatorCasOutcome::Missing);
        };
        if state.identity != *authorization.identity() {
            return Ok(SagaOperatorCasOutcome::IdentityConflict);
        }
        if state.status != SagaInstanceStatus::Ready {
            return Ok(SagaOperatorCasOutcome::StaleStatus(state.status));
        }
        if !state.lease_is_free(now) {
            return Ok(SagaOperatorCasOutcome::Busy);
        }
        if durable.journal.iter().any(|(stored, entry)| {
            *stored == instance
                && matches!(
                    entry.status,
                    SagaJournalStatus::ForwardIntent | SagaJournalStatus::CompensationIntent
                )
        }) {
            return Ok(SagaOperatorCasOutcome::EffectAlreadyStarted);
        }
        let state = durable
            .instances
            .get_mut(&saga_instance_key(instance))
            .ok_or_else(|| {
                mem_saga_error(
                    SagaDurableStoreErrorKind::Integrity,
                    MemSagaInvariant("memory saga instance disappeared"),
                )
            })?;
        state.status = SagaInstanceStatus::Terminated;
        state.operator_reason = None;
        state.compensation_cause = None;
        clear_saga_lease(state);
        durable.operator_decisions.push(MemSagaOperatorDecision {
            instance,
            reason: None,
            reason_text: authorization.evidence().reason_text().as_str().to_owned(),
            decision: "terminate",
            actor: authorization.caller().as_str().to_owned(),
            change_ticket: authorization.evidence().change_ticket().as_str().to_owned(),
            start_audit_id: authorization.start_audit_id().as_str().to_owned(),
            seq: None,
        });
        Ok(SagaOperatorCasOutcome::Applied)
    }
}

impl SagaTenantSource for MemSagaDurableStore {
    async fn list_runnable_tenants(
        &self,
        identity: &SagaWorkerIdentity,
        cursor: Option<SagaTenantCursor>,
        limit: NonZeroUsize,
    ) -> Result<SagaTenantPage, SagaDurableStoreError> {
        let now = saga_now();
        let durable = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut seen = HashSet::new();
        let mut tenants = Vec::new();
        for ((tenant, _), state) in &durable.instances {
            if state.identity != *identity
                || !state.is_runnable(now)
                || !seen.insert(tenant.clone())
            {
                continue;
            }
            tenants.push(
                rss_request_context::TenantId::parse(tenant)
                    .map_err(|error| mem_saga_error(SagaDurableStoreErrorKind::Integrity, error))?,
            );
        }
        tenants.sort_by_key(|tenant| tenant.to_string());
        if let Some(cursor) = cursor {
            let after = cursor.tenant().to_string();
            tenants.retain(|tenant| tenant.to_string() > after);
        }
        let has_more = tenants.len() > limit.get();
        tenants.truncate(limit.get());
        let next = has_more
            .then(|| tenants.last().copied().map(SagaTenantCursor::new))
            .flatten();
        Ok(SagaTenantPage::new(tenants, next))
    }

    async fn observe_unresolved(
        &self,
        identity: &SagaWorkerIdentity,
    ) -> Result<SagaUnresolvedObservation, SagaDurableStoreError> {
        let durable = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut operator_required = 0;
        let mut degraded = 0;
        let mut compensation_failed = 0;
        for state in durable
            .instances
            .values()
            .filter(|state| state.identity == *identity)
        {
            match state.status {
                SagaInstanceStatus::OperatorRequired => operator_required += 1,
                SagaInstanceStatus::Degraded => degraded += 1,
                SagaInstanceStatus::CompensationFailed => compensation_failed += 1,
                _ => {}
            }
        }
        let present = operator_required + degraded + compensation_failed > 0;
        Ok(SagaUnresolvedObservation::new(
            operator_required,
            degraded,
            compensation_failed,
            present.then(saga_now),
        ))
    }
}

fn saga_instance_key(instance: SagaInstanceRef) -> (String, uuid::Uuid) {
    (instance.tenant().to_string(), instance.saga_id().as_uuid())
}

fn checked_expiry(now: SystemTime, ttl: Duration) -> Result<SystemTime, SagaDurableStoreError> {
    if ttl.is_zero() {
        return Err(mem_saga_error(
            SagaDurableStoreErrorKind::Integrity,
            MemSagaInvariant("saga lease ttl is zero"),
        ));
    }
    now.checked_add(ttl).ok_or_else(|| {
        mem_saga_error(
            SagaDurableStoreErrorKind::Integrity,
            MemSagaInvariant("saga lease ttl overflow"),
        )
    })
}

fn saga_now() -> SystemTime {
    // reason: memory saga store owns an ephemeral process-local lease clock; durable PG uses DB/CAS.
    #[allow(clippy::disallowed_methods)]
    {
        SystemTime::now()
    }
}

#[derive(Debug)]
struct MemSagaInvariant(&'static str);

impl std::fmt::Display for MemSagaInvariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl Error for MemSagaInvariant {}

fn clear_saga_lease(state: &mut MemSagaInstanceState) {
    state.lease_token = None;
    state.holder_id = None;
    state.expires_at = None;
}

fn insert_mem_journal(
    durable: &mut MemSagaState,
    instance: SagaInstanceRef,
    entry: MemSagaJournalEntry,
) -> SagaDurableMutationOutcome {
    if let Some((_, existing)) = durable
        .journal
        .iter()
        .find(|(stored, row)| *stored == instance && row.seq == entry.seq)
    {
        return if existing == &entry {
            SagaDurableMutationOutcome::IdempotentDuplicate
        } else {
            SagaDurableMutationOutcome::Conflict
        };
    }
    durable.journal.push((instance, entry));
    SagaDurableMutationOutcome::Applied
}

fn insert_mem_intent(
    durable: &mut MemSagaState,
    instance: SagaInstanceRef,
    entry: MemSagaJournalEntry,
) -> SagaDurableMutationOutcome {
    if let Some((_, existing)) = durable
        .journal
        .iter()
        .find(|(stored, row)| *stored == instance && row.seq == entry.seq)
    {
        return if existing == &entry {
            SagaDurableMutationOutcome::IdempotentDuplicate
        } else {
            SagaDurableMutationOutcome::Conflict
        };
    }
    let prior_attempts = durable
        .journal
        .iter()
        .filter(|(stored, row)| {
            *stored == instance
                && row.seq < entry.seq
                && row.step_name == entry.step_name
                && row.status == entry.status
        })
        .count();
    let attempt_already_used = durable.journal.iter().any(|(stored, row)| {
        *stored == instance
            && row.step_name == entry.step_name
            && row.status == entry.status
            && row.attempt == entry.attempt
    });
    if attempt_already_used
        || usize::try_from(entry.attempt.get()).ok() != prior_attempts.checked_add(1)
    {
        return SagaDurableMutationOutcome::Conflict;
    }
    durable.journal.push((instance, entry));
    SagaDurableMutationOutcome::Applied
}

#[allow(clippy::too_many_arguments)]
fn has_exact_prior_mem_intent(
    durable: &MemSagaState,
    instance: SagaInstanceRef,
    before_seq: u64,
    step: &vocab::StepName,
    status: SagaJournalStatus,
    attempt: consistency::SagaAttempt,
    effect_key: &SagaIdempotencyKey,
    compensation_cause: Option<consistency::SagaCompensationCause>,
) -> bool {
    compensation_cause.is_some() == (status == SagaJournalStatus::CompensationIntent)
        && durable.journal.iter().any(|(stored, row)| {
            *stored == instance
                && row.seq.checked_add(1) == Some(before_seq)
                && row.step_name == *step
                && row.status == status
                && row.attempt == attempt
                && primitives::constant_time_eq(row.effect_key.as_bytes(), effect_key.as_bytes())
                && row.compensation_cause == compensation_cause
        })
}

fn mem_saga_error<E>(kind: SagaDurableStoreErrorKind, error: E) -> SagaDurableStoreError
where
    E: Error + Send + Sync + 'static,
{
    SagaDurableStoreError::new(kind, error)
}

// ── MemCheckpointStore：owner 断点续投 in-mem 替身 ─────────────────────────────

/// checkpoint store 内部 HashMap 类型别名（规避 clippy::type_complexity）。
type CheckpointMap = HashMap<(String, String), (Lsn, CheckpointVersion)>;

/// in-mem owner checkpoint store（impl [`diport::OwnerCheckpointStore`]）：
/// `(owner, id)` 主键 + `(offset, version)` CAS——`expected` 版本不符即 [`SaveOutcome::StaleVersion`]。
///
/// 对标 oxidecomputer/steno saga checkpoint，并复用 `crates/consistency` 的中立语义。
/// 生产替身走 postgres adapter；本 crate 仅测试/demo 用。
#[derive(Clone, Default)]
pub struct MemCheckpointStore {
    // key: (owner.as_str(), id.as_str())；value: (offset, current_version)
    inner: Arc<Mutex<CheckpointMap>>,
}

impl MemCheckpointStore {
    /// 新建空 store。
    pub fn new() -> Self {
        Self::default()
    }
}

impl OwnerCheckpointStore for MemCheckpointStore {
    async fn get_checkpoint(
        &self,
        owner: &CheckpointOwner,
        id: &CheckpointId,
    ) -> Result<Option<Checkpoint>, CheckpointStoreError> {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let key = (owner.as_str().to_string(), id.as_str().to_string());
        Ok(g.get(&key)
            .map(|&(offset, version)| Checkpoint { offset, version }))
    }

    async fn save_checkpoint(
        &self,
        owner: &CheckpointOwner,
        id: &CheckpointId,
        offset: Lsn,
        expected: CheckpointVersion,
    ) -> Result<SaveOutcome, CheckpointStoreError> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let key = (owner.as_str().to_string(), id.as_str().to_string());
        match g.get(&key) {
            // 首存：仅当 expected == version 0 时插入（约定「期望无既存行」用 version 0 表达）。
            None if expected == CheckpointVersion::new(0) => {
                g.insert(key, (offset, CheckpointVersion::new(1)));
                Ok(SaveOutcome::Saved)
            }
            // 版本 CAS 成功：存储版本 == expected → 存 offset 并推进版本。
            Some(&(_, stored_ver)) if stored_ver == expected => {
                g.insert(key, (offset, expected.next()));
                Ok(SaveOutcome::Saved)
            }
            // 其余（首存但 expected != 0，或版本失配）→ StaleVersion。
            _ => Ok(SaveOutcome::StaleVersion),
        }
    }

    async fn shutdown(&self) -> Result<(), CheckpointStoreError> {
        // reason: in-mem 无 infra 资源，关闭无需释放。
        Ok(())
    }
}

// ── MemSecretResolver：in-mem secret 解析替身（journey / e2e / 单测用）─────────────────────────

/// `MemSecretResolver` 内部 store 类型别名（key = (tenant_uuid_str, store_id, key)；value = raw bytes）。
type SecretStoreMap = std::collections::HashMap<(String, String, String), Vec<u8>>;

/// in-mem secret 解析端口（impl [`diport::SecretResolver`]）：按 `(tenant_uuid, store_id, key)` 命中
/// 返 [`SecretMaterial`]，未命中返 [`SecretResolverError::NotFound`]。
///
/// 仅供测试 / journey 使用——不在生产组合根注入（provider 为 Vault / AWS SM 等 adapter）。
///
/// 附调试旋钮（[`MemSecretResolver::set_unreachable`]）：置位后所有 resolve 返回
/// [`SecretResolverError::StoreUnreachable`]，用于验证 fail-closed 路径。
///
/// 附调试旋钮（[`MemSecretResolver::set_forbidden`]）：置位后所有 resolve 返回
/// [`SecretResolverError::Forbidden`]，用于验证 IAM 拒绝路径。
///
/// # 安全语义
///
/// 设计与 [`diport::SecretMaterial`] 同边界：材料字节写入 store 后不存在 owned clone 路径（HashMap
/// 存储 `Vec<u8>`，`resolve` 经 `SecretMaterial::new(bytes.clone())` 新建，drop 触发 `ZeroizeOnDrop`）。
#[derive(Default)]
pub struct MemSecretResolver {
    /// key = (tenant_uuid_str, store_id, secret_key)；value = raw bytes。
    store: Arc<Mutex<SecretStoreMap>>,
    /// 旋钮：置位后所有 resolve 返 `StoreUnreachable`。
    unreachable: Arc<std::sync::atomic::AtomicBool>,
    /// 旋钮：置位后所有 resolve 返 `Forbidden`。
    forbidden: Arc<std::sync::atomic::AtomicBool>,
}

impl MemSecretResolver {
    /// 新建空 resolver（无预设 secret，默认可达且未 forbidden）。
    pub fn new() -> Self {
        Self::default()
    }

    /// 向 store 注入一条 secret（覆盖写）。调用方持有字节，resolver 存 clone。
    ///
    /// `tenant`：租户隔离键（`store_id` + `key` 同 tenant 不同值互不干扰）。
    pub fn insert(
        &self,
        tenant: rss_request_context::TenantId,
        store_id: &str,
        key: &str,
        bytes: Vec<u8>,
    ) {
        self.store.lock().unwrap_or_else(|e| e.into_inner()).insert(
            (tenant.to_string(), store_id.to_string(), key.to_string()),
            bytes,
        );
    }

    /// 打开 `StoreUnreachable` 旋钮（置位后所有 resolve 返 Err）。
    pub fn set_unreachable(&self, v: bool) {
        self.unreachable
            .store(v, std::sync::atomic::Ordering::Relaxed);
    }

    /// 打开 `Forbidden` 旋钮（置位后所有 resolve 返 Err）。
    pub fn set_forbidden(&self, v: bool) {
        self.forbidden
            .store(v, std::sync::atomic::Ordering::Relaxed);
    }
}

impl SecretResolver for MemSecretResolver {
    async fn resolve(
        &self,
        tenant: rss_request_context::TenantId,
        coord: &SecretCoordinate,
    ) -> Result<SecretMaterial, SecretResolverError> {
        // 旋钮检查（fail-closed 优先于命中查询）。
        if self.unreachable.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(SecretResolverError::store_unreachable(
                std::io::Error::other("mem-resolver: store marked unreachable"),
            ));
        }
        if self.forbidden.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(SecretResolverError::Forbidden);
        }
        let g = self.store.lock().unwrap_or_else(|e| e.into_inner());
        let lookup_key = (
            tenant.to_string(),
            coord.store_id().to_string(),
            coord.key().to_string(),
        );
        match g.get(&lookup_key) {
            Some(bytes) => Ok(SecretMaterial::new(bytes.clone())),
            None => Err(SecretResolverError::NotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neutral_consistency_doubles_construct_without_domain_state() {
        let _ = MemFencedWriter::new();
        let _ = MemCasStore::new();
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn checkpoint_compare_and_set_rejects_stale_version() {
        let store = MemCheckpointStore::new();
        let owner = CheckpointOwner::new("neutral-worker");
        let id = CheckpointId::new("partition-1");
        let v0 = CheckpointVersion::new(0);
        assert_eq!(
            store
                .save_checkpoint(&owner, &id, Lsn::new(10), v0)
                .await
                .expect("save"),
            SaveOutcome::Saved
        );
        assert_eq!(
            store
                .save_checkpoint(&owner, &id, Lsn::new(20), v0)
                .await
                .expect("save"),
            SaveOutcome::StaleVersion
        );
        let current = store
            .get_checkpoint(&owner, &id)
            .await
            .expect("read")
            .expect("present");
        assert_eq!(current.offset, Lsn::new(10));
        assert_eq!(current.version, CheckpointVersion::new(1));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn secret_resolver_is_tenant_scoped_and_fail_closed() {
        let a = rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
            .expect("tenant");
        let b = rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d480")
            .expect("tenant");
        let coordinate = SecretCoordinate::new("neutral-store", "service/key", None);
        let resolver = MemSecretResolver::new();
        resolver.insert(a, "neutral-store", "service/key", b"value".to_vec());
        assert_eq!(
            resolver
                .resolve(a, &coordinate)
                .await
                .expect("resolve")
                .expose(),
            b"value"
        );
        assert!(matches!(
            resolver.resolve(b, &coordinate).await,
            Err(SecretResolverError::NotFound)
        ));
        resolver.set_forbidden(true);
        assert!(matches!(
            resolver.resolve(a, &coordinate).await,
            Err(SecretResolverError::Forbidden)
        ));
    }
}
