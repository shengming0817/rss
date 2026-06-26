//! CQRS 投影 harness（L3）—— 断点续投 + CAS checkpoint。
//!
//! 对标 saga `advance_checkpoint`：apply + checkpoint CAS 分开两次 await，
//! 靠 `Projector::apply` 幂等（同 lsn no-op）+ checkpoint CAS 保证 effectively-once。
//! 源不注入（待投影事件批由 caller/durable wiring 经 `PgProjectionEvents::read_from` 拉取后入参，本 PR 外）。
//!
//! ref: oxidecomputer/steno（saga 进度 checkpoint）+ docs/rules/eventbus.md §Projection。
//!
//! INVARIANT 备注：apply 幂等由 `Projector` impl 保证（trait doc 已声明）；
//! CAS 由 `diport::OwnerCheckpointStore::save_checkpoint` 的 `expected` 版本参数保证（infra 层）。
//!
//! ## 故障语义与恢复
//!
//! - **apply 失败**：fail-closed 停批；checkpoint 仅到失败前 high-water。
//! - **Transient** 错误：建议 caller 限速重试，下轮从 checkpoint 续投（幂等重投 no-op）。
//! - **Permanent / Invariant** 错误：harness 每次停在同一 lsn（head-of-line blocking），须人工介入：
//!   手动推进 checkpoint 越过 poison 事件，或修复 projector。
//! - **当前无 DLX 注入**：poison 事件头阻塞无自动旁路；DLX 接入待 follow-up（GitHub issue 待建）。
//! - **checkpoint 读失败**：fail-closed（[`ProjectionStop::CheckpointUnread`]）——**不** apply 任何事件、
//!   **不**降级为空 baseline 盲目重放；checkpoint 是恢复坐标，读失败让 caller 退避 / 报警 / 重试。
//! - **checkpoint 写失败**：apply 已生效（[`ProjectionStop::CheckpointUnsaved`]），幂等可重跑、不丢数据。

use std::sync::Arc;

use consistency::{EngineErrorKind, Lsn, ProjectionEvent, Projector};
use diport::{CheckpointId, CheckpointOwner, CheckpointVersion, OwnerCheckpointStore, SaveOutcome};

// ── 公开结果类型 ──────────────────────────────────────────────────────────────

/// 单次 [`ProjectionHarness::run`] 的执行结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionRun {
    /// 本轮成功 apply 的事件数（不含已跳过 / 失败事件）。
    pub applied: usize,
    /// 本轮跳过的事件数（lsn ≤ checkpoint baseline，已投过）。
    pub skipped: usize,
    /// 本轮停止原因。
    pub stop: ProjectionStop,
}

/// 投影批次停止原因。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProjectionStop {
    /// 全批完成，checkpoint 已推进（或无可推进事件）。
    Completed,
    /// apply 失败，fail-closed 停批（`failed_at` = 失败事件 lsn，`kind` = 错误种类）。
    ///
    /// 已成功 apply 的前缀已推进 checkpoint（high-water 到失败前一条）。
    ///
    /// - **Transient**：瞬时错误，建议 caller 限速重试（harness 下轮从 checkpoint 续投）。
    /// - **Permanent / Invariant**：harness 每次停在同一 lsn（head-of-line blocking），
    ///   须人工介入：手动推进 checkpoint 越过 poison 事件，或修复 projector。
    ///   当前无 DLX 注入，poison 头将持续阻塞，须人工干预。
    ApplyFailed {
        /// 失败事件的 lsn。
        failed_at: Lsn,
        /// 引擎错误种类。
        kind: EngineErrorKind,
    },
    /// checkpoint CAS `StaleVersion`——并发投影实例已推进，本实例被 fence，停批。
    Fenced,
    /// apply 生效但 checkpoint 写 infra 故障（幂等可重跑，不丢数据）。
    CheckpointUnsaved,
    /// checkpoint **读** infra 故障——**fail-closed，不 apply 任何事件**。
    ///
    /// checkpoint 是恢复坐标：读失败时绝不降级为「空 baseline 从头重放」（会盲目全量重投、
    /// 掩盖 infra 故障），而是停批让 caller 退避 / 报警 / 重试（DB 恢复后重读得正确 offset 续投）。
    CheckpointUnread,
}

// ── ProjectionHarness ────────────────────────────────────────────────────────

/// CQRS 投影 harness：据 checkpoint 断点续投，apply 已按 lsn 升序排好的事件批，CAS 推进 offset。
///
/// `P: Projector` 必须保证 `apply` 幂等（同 lsn 重投 no-op）；`C: OwnerCheckpointStore` 提供
/// `(owner, projection_id)` 维度的断点续投 CAS。
pub struct ProjectionHarness<P, C> {
    projector: Arc<P>,
    checkpoint: Arc<C>,
    owner: CheckpointOwner,
    projection_id: CheckpointId,
}

impl<P, C> ProjectionHarness<P, C>
where
    P: Projector + Send + Sync + 'static,
    C: OwnerCheckpointStore + Send + Sync + 'static,
{
    /// 构造投影 harness（必填参，缺失即编译错）。
    pub fn new(
        projector: Arc<P>,
        checkpoint: Arc<C>,
        owner: CheckpointOwner,
        projection_id: CheckpointId,
    ) -> Self {
        Self {
            projector,
            checkpoint,
            owner,
            projection_id,
        }
    }

    /// 投影一批已按 lsn 升序排好的事件（前置：caller `read_from ORDER BY id ASC` 保证）。
    ///
    /// 流程：读 baseline → apply 批次（跳过 lsn ≤ baseline）→ 整批一次 CAS 到 high_water。
    /// apply 与 checkpoint CAS **分开两次 await**，靠幂等 + CAS 保证 effectively-once（对标 saga）。
    pub async fn run<E: ProjectionEvent>(&self, events: &[E]) -> ProjectionRun {
        // checkpoint 读失败 → fail-closed：不 apply，返回 CheckpointUnread 让 caller 退避 / 重试。
        let Some((baseline, version)) = self.read_baseline().await else {
            return ProjectionRun {
                applied: 0,
                skipped: 0,
                stop: ProjectionStop::CheckpointUnread,
            };
        };
        let progress = self.apply_batch(events, baseline).await;
        let advance = match progress.high_water {
            // 仅当 high_water 存在且 > baseline 时 CAS（有新进展才写 checkpoint）。
            Some(hw) if baseline != Some(hw) => self.advance_checkpoint(hw, version).await,
            // reason: 无新进展（空批 / 全跳过 / 首条即失败），不写 checkpoint（避免无效 CAS）。
            _ => Advance::NoChange,
        };
        let result = ProjectionRun {
            applied: progress.applied,
            skipped: progress.skipped,
            stop: stop_of(advance, progress.failure),
        };
        // debug 级 run 完成摘要（生产默认关闭）。
        tracing::debug!(
            owner = self.owner.as_str(),
            projection_id = self.projection_id.as_str(),
            applied = result.applied,
            skipped = result.skipped,
            stop = ?result.stop,
            "projection run complete"
        );
        result
    }

    /// 读当前 checkpoint baseline。返回 `Some((baseline, version))` 进入 apply；`None` = 读 infra 故障，
    /// caller fail-closed 不 apply（[`ProjectionStop::CheckpointUnread`]）。
    ///
    /// - `Ok(Some(cp))` → `Some((Some(offset), version))`（续投）。
    /// - `Ok(None)`（从未保存，首轮）→ `Some((None, INITIAL))`（全量 replay，非故障）。
    /// - `Err(_)`（infra 故障）→ `None`：**不**降级为空 baseline 盲目重放——checkpoint 是恢复坐标，
    ///   读失败须 fail-closed 让 caller 退避 / 报警（DB 恢复后重读得正确 offset）。
    async fn read_baseline(&self) -> Option<(Option<Lsn>, CheckpointVersion)> {
        match self
            .checkpoint
            .get_checkpoint(&self.owner, &self.projection_id)
            .await
        {
            Ok(Some(cp)) => Some((Some(cp.offset), cp.version)),
            Ok(None) => Some((None, CheckpointVersion::INITIAL)),
            Err(_) => {
                self.error("projection: checkpoint read failed, fail-closed (no apply)");
                None
            }
        }
    }

    /// apply 事件批：跳过 lsn ≤ baseline；遇第一个失败即 fail-closed 停批。
    ///
    /// 前置条件：`events` 已按 lsn 升序排好（caller 保证，`debug_assert!` 防 footgun）。
    async fn apply_batch<E: ProjectionEvent>(
        &self,
        events: &[E],
        baseline: Option<Lsn>,
    ) -> BatchProgress {
        let mut progress = BatchProgress::default();
        let mut prev_lsn: Option<Lsn> = None;
        for event in events {
            let lsn = event.lsn();
            // 单调递增 footgun 防护（仅 debug build；caller 语义前置保证）。
            debug_assert!(
                prev_lsn.is_none_or(|p| lsn >= p),
                "projection: events must be in ascending lsn order"
            );
            prev_lsn = Some(lsn);
            // 已在 baseline 以内的事件：已投过，跳过（断点续投语义）。
            if baseline.is_some_and(|b| lsn <= b) {
                progress.skipped += 1;
                continue;
            }
            match self.projector.apply(event).await {
                Ok(()) => {
                    progress.applied += 1;
                    progress.high_water = Some(lsn);
                }
                Err(e) => {
                    // fail-closed：仅记元数据（绝不记 payload/PII），停批（不计入 applied）。
                    tracing::warn!(
                        owner = self.owner.as_str(),
                        projection_id = self.projection_id.as_str(),
                        lsn = lsn.get(),
                        kind = ?e.kind(),
                        topic = event.topic().as_str(),
                        "projection: apply failed, stopping batch"
                    );
                    progress.failure = Some((lsn, e.kind()));
                    break;
                }
            }
        }
        progress
    }

    /// CAS 推进 checkpoint 到 `hw`：`Saved` → Advanced；`StaleVersion` → warn + Fenced；
    /// infra 故障 → warn + Unsaved（apply 已生效，幂等可重跑）。
    async fn advance_checkpoint(&self, hw: Lsn, expected: CheckpointVersion) -> Advance {
        match self
            .checkpoint
            .save_checkpoint(&self.owner, &self.projection_id, hw, expected)
            .await
        {
            Ok(SaveOutcome::Saved) => Advance::Advanced,
            Ok(SaveOutcome::StaleVersion) => {
                self.warn("projection: checkpoint fenced by concurrent projector");
                Advance::Fenced
            }
            // reason: #[non_exhaustive] 未来变体——apply 已生效，保守记日志报 Unsaved（可重跑）。
            Ok(_) => {
                self.warn("projection: checkpoint not saved (unsupported outcome)");
                Advance::Unsaved
            }
            Err(_) => {
                // reason: projection checkpoint 是主要进度记录，持久化写失败 = error 级（observability.md
                // 持久化失败分级）；区别于 saga（checkpoint 仅快进游标非权威），projection 进度持久化失败
                // 需更高级别告警。
                self.error("projection: checkpoint save failed, replay is safe");
                Advance::Unsaved
            }
        }
    }

    /// checkpoint 告警收口（结构化 tracing，控制各 caller 认知复杂度 ≤15）。
    fn warn(&self, msg: &'static str) {
        tracing::warn!(
            owner = self.owner.as_str(),
            projection_id = self.projection_id.as_str(),
            "{msg}"
        );
    }

    /// checkpoint 持久化错误收口（error 级；各 caller 认知复杂度 ≤15）。
    fn error(&self, msg: &'static str) {
        tracing::error!(
            owner = self.owner.as_str(),
            projection_id = self.projection_id.as_str(),
            "{msg}"
        );
    }
}

// ── 内部辅助类型（crate 私有）────────────────────────────────────────────────

/// advance_checkpoint 结论（内部控制流；不出公开 API）。
enum Advance {
    /// CAS 成功，checkpoint 已推进。
    Advanced,
    /// 无新进展（空批 / 全跳过 / 首条即失败），不写 checkpoint。
    NoChange,
    /// 并发实例 fence（StaleVersion）。
    Fenced,
    /// infra 故障未保存（apply 已生效，幂等可重跑）。
    Unsaved,
}

/// apply_batch 进度（内部；不出公开 API）。
#[derive(Default)]
struct BatchProgress {
    applied: usize,
    skipped: usize,
    /// 已成功 apply 的最高 lsn（None = 无任何新 apply）。
    high_water: Option<Lsn>,
    /// 第一个失败位点（lsn, kind）；None = 全批成功。
    failure: Option<(Lsn, EngineErrorKind)>,
}

/// 把 advance 结论 + failure 组合成对外 `ProjectionStop`。
fn stop_of(advance: Advance, failure: Option<(Lsn, EngineErrorKind)>) -> ProjectionStop {
    match advance {
        Advance::Fenced => ProjectionStop::Fenced,
        Advance::Unsaved => ProjectionStop::CheckpointUnsaved,
        Advance::Advanced | Advance::NoChange => match failure {
            Some((failed_at, kind)) => ProjectionStop::ApplyFailed { failed_at, kind },
            None => ProjectionStop::Completed,
        },
    }
}

// ── 测试 ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use consistency::outbox::Topic;
    use consistency::{EngineError, EngineErrorKind, Lsn, ProjectionEvent, Projector};
    use diport::{
        Checkpoint, CheckpointId, CheckpointOwner, CheckpointStoreError, CheckpointVersion,
        OwnerCheckpointStore, SaveOutcome,
    };

    use super::{ProjectionHarness, ProjectionRun, ProjectionStop};

    // ── FakeEvent ─────────────────────────────────────────────────────────────

    /// 测试用 fake 投影事件。
    struct FakeEvent {
        lsn: Lsn,
        topic: Topic,
        payload: Vec<u8>,
    }

    impl ProjectionEvent for FakeEvent {
        fn topic(&self) -> &Topic {
            &self.topic
        }
        fn lsn(&self) -> Lsn {
            self.lsn
        }
        fn payload(&self) -> &[u8] {
            &self.payload
        }
    }

    /// 构造 seq 号 fake 事件（topic="proj.test"，payload=[]）。
    // reason: "proj.test" 是编译期常量，parse 必然成功，expect 用于测试断言。
    #[allow(clippy::expect_used)]
    fn ev(seq: u64) -> FakeEvent {
        FakeEvent {
            lsn: Lsn::new(seq),
            topic: Topic::parse("proj.test").expect("proj.test is valid topic"),
            payload: vec![],
        }
    }

    /// 构造 seq 号批次 `start..=end`。
    fn evs(start: u64, end: u64) -> Vec<FakeEvent> {
        (start..=end).map(ev).collect()
    }

    // ── RecordingProjector ────────────────────────────────────────────────────

    /// 记录收到事件 lsn；可注入单点失败。
    struct RecordingProjector {
        applied: Arc<Mutex<Vec<u64>>>,
        /// 命中 `(lsn, kind)` 时返回 Err；None = 全成功。
        fail_at: Option<(u64, EngineErrorKind)>,
    }

    impl RecordingProjector {
        fn new() -> Self {
            Self {
                applied: Arc::new(Mutex::new(vec![])),
                fail_at: None,
            }
        }
        fn failing_at(lsn: u64, kind: EngineErrorKind) -> Self {
            Self {
                applied: Arc::new(Mutex::new(vec![])),
                fail_at: Some((lsn, kind)),
            }
        }
        fn applied_lsns(&self) -> Vec<u64> {
            // reason: Mutex 毒化只在 test panic 时触发，into_inner 安全恢复（MemCheckpointStore 同范式）。
            self.applied
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }
    }

    impl Projector for RecordingProjector {
        async fn apply<E: ProjectionEvent>(&self, event: &E) -> Result<(), EngineError> {
            let lsn = event.lsn().get();
            // if-let chain 消除嵌套 if（collapsible_if 修复）。
            if let Some((_, kind)) = self.fail_at.filter(|&(fl, _)| fl == lsn) {
                return Err(EngineError::new(kind));
            }
            self.applied
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(lsn);
            Ok(())
        }
    }

    // ── FakeCheckpointStore ───────────────────────────────────────────────────

    /// 内联 fake checkpoint store（复刻 MemCheckpointStore CAS 语义）。
    struct FakeCheckpointStore {
        /// `(offset, current_version)` 或 `None`（无记录）。
        state: Mutex<Option<(Lsn, CheckpointVersion)>>,
        /// 置 true → save 恒 StaleVersion（并发 fence 测试）。
        force_stale: bool,
        /// 置 true → get_checkpoint 返 Err（infra 故障测试）。
        fail_get: bool,
        /// 置 true → save_checkpoint 返 Err（infra 故障测试）。
        fail_save: bool,
    }

    impl FakeCheckpointStore {
        /// 空 store（无记录）。
        fn empty() -> Self {
            Self {
                state: Mutex::new(None),
                force_stale: false,
                fail_get: false,
                fail_save: false,
            }
        }

        /// 预置 offset + version（模拟前一轮已保存）。
        fn preset(offset: Lsn, version: CheckpointVersion) -> Self {
            Self {
                state: Mutex::new(Some((offset, version))),
                force_stale: false,
                fail_get: false,
                fail_save: false,
            }
        }

        /// 强制 save 返 StaleVersion。
        fn force_stale() -> Self {
            Self {
                force_stale: true,
                ..Self::empty()
            }
        }

        /// get 返 Err（infra 故障）。
        fn fail_get() -> Self {
            Self {
                fail_get: true,
                ..Self::empty()
            }
        }

        /// save 返 Err（infra 故障）。
        fn fail_save() -> Self {
            Self {
                fail_save: true,
                ..Self::empty()
            }
        }

        /// 读当前 checkpoint（测试断言用）。
        fn current(&self) -> Option<Checkpoint> {
            // reason: Mutex 毒化仅 test panic，into_inner 安全恢复。
            self.state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .map(|(offset, version)| Checkpoint { offset, version })
        }
    }

    /// FakeCheckpointStore 内部 Err 源（infra 故障 stub）。
    #[derive(Debug, thiserror::Error)]
    #[error("fake store error")]
    struct FakeStoreError;

    impl OwnerCheckpointStore for FakeCheckpointStore {
        async fn get_checkpoint(
            &self,
            _owner: &CheckpointOwner,
            _id: &CheckpointId,
        ) -> Result<Option<Checkpoint>, CheckpointStoreError> {
            if self.fail_get {
                return Err(CheckpointStoreError::new(FakeStoreError));
            }
            // reason: Mutex 毒化仅 test panic，into_inner 安全恢复。
            let g = self.state.lock().unwrap_or_else(|e| e.into_inner());
            Ok(g.map(|(offset, version)| Checkpoint { offset, version }))
        }

        async fn save_checkpoint(
            &self,
            _owner: &CheckpointOwner,
            _id: &CheckpointId,
            offset: Lsn,
            expected: CheckpointVersion,
        ) -> Result<SaveOutcome, CheckpointStoreError> {
            if self.fail_save {
                return Err(CheckpointStoreError::new(FakeStoreError));
            }
            if self.force_stale {
                return Ok(SaveOutcome::StaleVersion);
            }
            // reason: Mutex 毒化仅 test panic，into_inner 安全恢复。
            let mut g = self.state.lock().unwrap_or_else(|e| e.into_inner());
            match *g {
                // 首存：expected == INITIAL（0）= 期望无既存行。
                None if expected == CheckpointVersion::INITIAL => {
                    *g = Some((offset, CheckpointVersion::INITIAL.next()));
                    Ok(SaveOutcome::Saved)
                }
                // CAS 更新：stored_version == expected → 推进版本。
                Some((_, stored_ver)) if stored_ver == expected => {
                    *g = Some((offset, expected.next()));
                    Ok(SaveOutcome::Saved)
                }
                // 其余：版本失配（并发写或不匹配首存）→ StaleVersion。
                _ => Ok(SaveOutcome::StaleVersion),
            }
        }

        async fn shutdown(&self) -> Result<(), CheckpointStoreError> {
            // reason: fake store 无 infra 资源，关闭无需操作。
            Ok(())
        }
    }

    // ── 测试辅助 ──────────────────────────────────────────────────────────────

    fn harness(
        projector: RecordingProjector,
        store: FakeCheckpointStore,
    ) -> (
        ProjectionHarness<RecordingProjector, FakeCheckpointStore>,
        Arc<RecordingProjector>,
        Arc<FakeCheckpointStore>,
    ) {
        let p = Arc::new(projector);
        let c = Arc::new(store);
        let h = ProjectionHarness::new(
            Arc::clone(&p),
            Arc::clone(&c),
            CheckpointOwner::new("test-owner"),
            CheckpointId::new("test-proj"),
        );
        (h, p, c)
    }

    // ── 用例 ──────────────────────────────────────────────────────────────────

    /// 1. 无 ckpt 全量重放：events 1..=100 全部 apply，checkpoint 从 None 推进到 offset=100。
    // reason: 测试断言用 expect，checkpoint 必须存在（逻辑断言，非生产 error handling）。
    #[allow(clippy::expect_used)]
    #[tokio::test]
    async fn fresh_replay_applies_all() {
        let (h, p, c) = harness(RecordingProjector::new(), FakeCheckpointStore::empty());
        let events = evs(1, 100);
        let result = h.run(&events).await;

        assert_eq!(result.applied, 100);
        assert_eq!(result.skipped, 0);
        assert_eq!(result.stop, ProjectionStop::Completed);

        let ckpt = c.current().expect("checkpoint should be saved");
        assert_eq!(ckpt.offset, Lsn::new(100));
        assert_eq!(ckpt.version, CheckpointVersion::new(1));

        let lsns = p.applied_lsns();
        assert_eq!(lsns, (1u64..=100).collect::<Vec<_>>());
    }

    /// 2. 断点续投：预置 ckpt offset=50，跑 1..=100 → 跳过前 50，apply 51..=100。
    // reason: 测试断言用 expect。
    #[allow(clippy::expect_used)]
    #[tokio::test]
    async fn resume_skips_consumed_prefix() {
        let (h, p, c) = harness(
            RecordingProjector::new(),
            FakeCheckpointStore::preset(Lsn::new(50), CheckpointVersion::new(1)),
        );
        let events = evs(1, 100);
        let result = h.run(&events).await;

        assert_eq!(result.applied, 50);
        assert_eq!(result.skipped, 50);
        assert_eq!(result.stop, ProjectionStop::Completed);

        let ckpt = c.current().expect("checkpoint should be updated");
        assert_eq!(ckpt.offset, Lsn::new(100));
        assert_eq!(ckpt.version, CheckpointVersion::new(2));

        let lsns = p.applied_lsns();
        assert_eq!(lsns, (51u64..=100).collect::<Vec<_>>());
    }

    /// 3. 全量重跑 no-op：预置 ckpt offset=100，再跑 1..=100 → 全跳过，checkpoint 不变。
    // reason: 测试断言用 expect。
    #[allow(clippy::expect_used)]
    #[tokio::test]
    async fn rerun_full_window_is_noop() {
        let (h, p, c) = harness(
            RecordingProjector::new(),
            FakeCheckpointStore::preset(Lsn::new(100), CheckpointVersion::new(2)),
        );
        let events = evs(1, 100);
        let result = h.run(&events).await;

        assert_eq!(result.applied, 0);
        assert_eq!(result.skipped, 100);
        assert_eq!(result.stop, ProjectionStop::Completed);

        // checkpoint 未变（无 CAS 写）。
        let ckpt = c.current().expect("checkpoint should still exist");
        assert_eq!(ckpt.offset, Lsn::new(100));
        assert_eq!(ckpt.version, CheckpointVersion::new(2));

        assert!(
            p.applied_lsns().is_empty(),
            "projector should not be called"
        );
    }

    /// 4. lsn=0 首事件不跳过（None baseline 下 lsn=0 不满足 lsn<=b）。
    #[tokio::test]
    async fn lsn_zero_first_event_not_skipped() {
        let (h, _p, _c) = harness(RecordingProjector::new(), FakeCheckpointStore::empty());
        let events = vec![ev(0), ev(1), ev(2)];
        let result = h.run(&events).await;

        assert_eq!(result.applied, 3, "lsn=0 must not be skipped");
        assert_eq!(result.skipped, 0);
        assert_eq!(result.stop, ProjectionStop::Completed);
    }

    /// 5. 空批：applied=0, skipped=0, Completed，checkpoint 未写。
    #[tokio::test]
    async fn empty_batch_noop() {
        let (h, _p, c) = harness(RecordingProjector::new(), FakeCheckpointStore::empty());
        let result = h.run::<FakeEvent>(&[]).await;

        assert_eq!(
            result,
            ProjectionRun {
                applied: 0,
                skipped: 0,
                stop: ProjectionStop::Completed,
            }
        );
        assert!(c.current().is_none(), "no checkpoint should be written");
    }

    /// 6. 瞬时失败在第 3 条：apply 1,2 成功，3 失败停批；ckpt offset=2；projector 见 [1,2]。
    // reason: 测试断言用 expect。
    #[allow(clippy::expect_used)]
    #[tokio::test]
    async fn transient_failure_stops_keeps_prefix() {
        let (h, p, c) = harness(
            RecordingProjector::failing_at(3, EngineErrorKind::Transient),
            FakeCheckpointStore::empty(),
        );
        let events = evs(1, 5);
        let result = h.run(&events).await;

        assert_eq!(result.applied, 2);
        assert_eq!(
            result.stop,
            ProjectionStop::ApplyFailed {
                failed_at: Lsn::new(3),
                kind: EngineErrorKind::Transient,
            }
        );

        let ckpt = c.current().expect("prefix checkpoint should be saved");
        assert_eq!(ckpt.offset, Lsn::new(2));

        assert_eq!(p.applied_lsns(), vec![1u64, 2]);
    }

    /// 7. 永久失败：同样 fail-closed，kind=Permanent。
    // reason: 测试断言用 expect。
    #[allow(clippy::expect_used)]
    #[tokio::test]
    async fn permanent_failure_stops_no_dlx() {
        let (h, _p, c) = harness(
            RecordingProjector::failing_at(3, EngineErrorKind::Permanent),
            FakeCheckpointStore::empty(),
        );
        let result = h.run(&evs(1, 5)).await;

        assert_eq!(
            result.stop,
            ProjectionStop::ApplyFailed {
                failed_at: Lsn::new(3),
                kind: EngineErrorKind::Permanent,
            }
        );
        let ckpt = c.current().expect("prefix checkpoint should be saved");
        assert_eq!(ckpt.offset, Lsn::new(2));
    }

    /// 8. Invariant 失败：stop=ApplyFailed{kind:Invariant}。
    #[tokio::test]
    async fn invariant_failure_stops() {
        let (h, _p, _c) = harness(
            RecordingProjector::failing_at(3, EngineErrorKind::Invariant),
            FakeCheckpointStore::empty(),
        );
        let result = h.run(&evs(1, 5)).await;

        assert_eq!(
            result.stop,
            ProjectionStop::ApplyFailed {
                failed_at: Lsn::new(3),
                kind: EngineErrorKind::Invariant,
            }
        );
    }

    /// 9. 首条即失败：applied=0, checkpoint 未写（high_water=None → NoChange）。
    #[tokio::test]
    async fn first_event_fails_no_checkpoint_write() {
        let (h, _p, c) = harness(
            RecordingProjector::failing_at(1, EngineErrorKind::Transient),
            FakeCheckpointStore::empty(),
        );
        let result = h.run(&evs(1, 3)).await;

        assert_eq!(result.applied, 0);
        assert!(
            matches!(result.stop, ProjectionStop::ApplyFailed { .. }),
            "stop should be ApplyFailed"
        );
        assert!(c.current().is_none(), "checkpoint must not be written");
    }

    /// 10. CAS StaleVersion：projector 全部投完但 checkpoint 被 fence → Fenced。
    #[tokio::test]
    async fn stale_version_reports_fenced() {
        let (h, p, _c) = harness(
            RecordingProjector::new(),
            FakeCheckpointStore::force_stale(),
        );
        let result = h.run(&evs(1, 3)).await;

        assert_eq!(result.stop, ProjectionStop::Fenced);
        // apply 已发生（投影写已生效）。
        assert_eq!(p.applied_lsns(), vec![1u64, 2, 3]);
    }

    /// 11. checkpoint save infra 故障：stop=CheckpointUnsaved，applied 计数正常。
    #[tokio::test]
    async fn checkpoint_save_infra_error_reports_unsaved() {
        let (h, p, _c) = harness(RecordingProjector::new(), FakeCheckpointStore::fail_save());
        let result = h.run(&evs(1, 5)).await;

        assert_eq!(result.stop, ProjectionStop::CheckpointUnsaved);
        assert_eq!(result.applied, 5);
        assert_eq!(p.applied_lsns(), (1u64..=5).collect::<Vec<_>>());
    }

    /// 12. checkpoint get infra 故障：**fail-closed**——不 apply 任何事件，stop = CheckpointUnread
    ///     （不降级为空 baseline 盲目重放；caller 据此退避 / 报警 / 重试）。
    #[tokio::test]
    async fn checkpoint_read_infra_error_fails_closed() {
        let (h, p, _c) = harness(RecordingProjector::new(), FakeCheckpointStore::fail_get());
        let events = evs(1, 5);
        let result = h.run(&events).await;

        // read 失败 → 零 apply、零 skip、CheckpointUnread；投影器从未被调用。
        assert_eq!(result.stop, ProjectionStop::CheckpointUnread);
        assert_eq!(result.applied, 0);
        assert_eq!(result.skipped, 0);
        assert!(
            p.applied_lsns().is_empty(),
            "fail-closed：checkpoint 读失败时投影器不应收到任何事件"
        );
    }

    /// 13. apply 失败 + checkpoint 被 fence：advance 主导，stop = Fenced（非 ApplyFailed）。
    ///
    /// lsn=1,2 成功，lsn=3 失败（high_water=2）→ CAS 推进到 2，但 force_stale → Fenced。
    /// stop_of(Fenced, Some(...)) = Fenced（fence 优先，advance 优先于 failure）。
    #[tokio::test]
    async fn apply_failure_during_fence_reports_fenced() {
        let (h, p, _c) = harness(
            RecordingProjector::failing_at(3, EngineErrorKind::Transient),
            FakeCheckpointStore::force_stale(),
        );
        let result = h.run(&evs(1, 5)).await;

        assert_eq!(
            result.stop,
            ProjectionStop::Fenced,
            "fence 优先于 apply 失败"
        );
        assert_eq!(result.applied, 2, "lsn=1,2 已成功 apply");
        assert_eq!(p.applied_lsns(), vec![1u64, 2]);
    }

    /// 14. apply 失败 + checkpoint save infra 故障：advance 主导，stop = CheckpointUnsaved。
    ///
    /// lsn=1,2 成功，lsn=3 失败（high_water=2）→ CAS 推进到 2，但 fail_save → Unsaved。
    /// stop_of(Unsaved, Some(...)) = CheckpointUnsaved（advance 优先于 failure）。
    #[tokio::test]
    async fn apply_failure_during_unsaved_reports_unsaved() {
        let (h, p, _c) = harness(
            RecordingProjector::failing_at(3, EngineErrorKind::Transient),
            FakeCheckpointStore::fail_save(),
        );
        let result = h.run(&evs(1, 5)).await;

        assert_eq!(
            result.stop,
            ProjectionStop::CheckpointUnsaved,
            "checkpoint save 故障优先于 apply 失败"
        );
        assert_eq!(result.applied, 2, "lsn=1,2 已成功 apply");
        assert_eq!(p.applied_lsns(), vec![1u64, 2]);
    }

    /// 15. 乱序事件在 debug build 触发 debug_assert!（单调递增 footgun 防护）。
    ///
    /// 传入 [ev(5), ev(3)]：apply ev(5) 后 prev_lsn=5，ev(3) lsn < prev → panic。
    /// 仅编译 debug_assertions 时触发（production release build 不影响）。
    #[cfg(debug_assertions)]
    #[tokio::test]
    #[should_panic(expected = "projection: events must be in ascending lsn order")]
    async fn out_of_order_events_panic_in_debug() {
        let (h, _p, _c) = harness(RecordingProjector::new(), FakeCheckpointStore::empty());
        // ev(5) → ev(3) 乱序：prev_lsn=5, lsn=3 → debug_assert!(3 >= 5) 触发 panic。
        let events = vec![ev(5), ev(3)];
        h.run(&events).await;
    }
}
