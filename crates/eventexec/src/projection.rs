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
//! - **Permanent / Invariant** 错误：写入统一 DLQ 后停在 poison lsn；不自动 skip，须人工介入。
//! - **OutOfOrder**：写入统一 DLQ 后停批，不把 checkpoint 推过乱序 poison lsn。
//! - **checkpoint 读失败**：fail-closed（[`ProjectionStop::CheckpointUnread`]）——**不** apply 任何事件、
//!   **不**降级为空 baseline 盲目重放；checkpoint 是恢复坐标，读失败让 caller 退避 / 报警 / 重试。
//! - **checkpoint 写失败**：apply 已生效（[`ProjectionStop::CheckpointUnsaved`]），幂等可重跑、不丢数据。

use std::sync::Arc;

use consistency::{
    EngineErrorKind, Lsn, ProjectionDeadLetterReason, ProjectionEvent, ProjectionEventMetadata,
    Projector, SerialInOrderGuarantor,
};
use diport::{
    CheckpointId, CheckpointOwner, CheckpointVersion, DeadLetterRecord, DeadLetterStore,
    DeadLetterSummary, EnvelopeMetadata, MetadataError, OwnerCheckpointStore, SaveOutcome,
    WritableDeadLetterSource,
};

const SUMMARY_PROJECTION_APPLY_PERMANENT: DeadLetterSummary =
    DeadLetterSummary::new("projection apply permanent");
const SUMMARY_PROJECTION_APPLY_INVARIANT: DeadLetterSummary =
    DeadLetterSummary::new("projection apply invariant");
const SUMMARY_PROJECTION_OUT_OF_ORDER: DeadLetterSummary =
    DeadLetterSummary::new("projection out of order");
const SUMMARY_PROJECTION_POISON: DeadLetterSummary = DeadLetterSummary::new("projection poison");

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
    /// - **Permanent / Invariant**：写 projection DLQ 后停在同一 lsn（head-of-line blocking），
    ///   不自动 skip；须人工介入修复 projector 或显式处理 poison 事件。
    ApplyFailed {
        /// 失败事件的 lsn。
        failed_at: Lsn,
        /// 引擎错误种类。
        kind: EngineErrorKind,
    },
    /// 事件 lsn 非升序——**release 也 fail-closed** 停批（`failed_at` = 首个乱序事件 lsn）。
    ///
    /// `SerialInOrderGuarantor` witness 只门禁 harness **构造**（编译期证上游声明串行）；运行期 batch
    /// 的实际顺序由此守：遇到 `lsn < 前一已处理 lsn` 即停，乱序事件**不 apply、不推进 checkpoint**
    /// 越过它（已成功前缀的 high-water 保留）。这把 witness 的「串行有序」声明从构造期延伸到 apply 期，
    /// 使非串行 source（伪造 witness 或乱序拼 slice）无法静默乱序投影（F1，#1211 review）。
    /// INVARIANT: PROJECTION-SERIAL-WITNESS-01 { level = "Medium", exec = "manual/opt-in", source = "code" }（运行期半段）。
    OutOfOrder {
        /// 首个乱序事件的 lsn。
        failed_at: Lsn,
    },
    /// checkpoint CAS `StaleVersion`——并发投影实例已推进，本实例被 fence，停批。
    Fenced,
    /// apply 生效但 checkpoint 写 infra 故障（幂等可重跑，不丢数据）。
    CheckpointUnsaved,
    /// projection poison DLQ 写失败；本轮不推进 checkpoint，caller 应报警/退避后重试。
    DeadLetterUnsaved {
        /// DLQ 写失败对应的 poison lsn。
        failed_at: Lsn,
    },
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
pub struct ProjectionHarness<P, C, D> {
    projector: Arc<P>,
    checkpoint: Arc<C>,
    dlx: Arc<D>,
    owner: CheckpointOwner,
    projection_id: CheckpointId,
}

impl<P, C, D> ProjectionHarness<P, C, D>
where
    P: Projector + Send + Sync + 'static,
    C: OwnerCheckpointStore + Send + Sync + 'static,
    D: DeadLetterStore + Send + Sync + 'static,
{
    /// 构造投影 harness（必填参，缺失即编译错）。
    ///
    /// `_guarantor` 是串行有序 witness（[`consistency::SerialInOrderGuarantor`]）：非串行投递路径拿不到
    /// 此 witness ⇒ **编译期**挂不上 projection（fail-closed by absence，
    /// INVARIANT: PROJECTION-SERIAL-WITNESS-01 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" }）。witness 是 ZST，不占运行期成本（不存入 struct 字段，
    /// `run()` 签名不变）。唯一获取入口是 [`consistency::SerialInOrder::from_source`]，须传一个
    /// [`consistency::PartitionSerialDelivery`] source——非串行投递路径无该 impl ⇒ 编译期拒绝。
    ///
    /// ref: serverlesstechnology/cqrs src/cqrs.rs（events applied in order）
    pub fn new(
        projector: Arc<P>,
        checkpoint: Arc<C>,
        owner: CheckpointOwner,
        projection_id: CheckpointId,
        dlx: Arc<D>,
        _guarantor: impl SerialInOrderGuarantor,
    ) -> Self {
        Self {
            projector,
            checkpoint,
            dlx,
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
        let advance =
            if progress.dead_letter_write_failed.is_some() || progress.out_of_order.is_some() {
                Advance::NoChange
            } else {
                match progress.high_water {
                    // 仅当 high_water 存在且 > baseline 时 CAS（有新进展才写 checkpoint）。
                    Some(hw) if baseline != Some(hw) => self.advance_checkpoint(hw, version).await,
                    // reason: 无新进展（空批 / 全跳过 / 首条即失败），不写 checkpoint（避免无效 CAS）。
                    _ => Advance::NoChange,
                }
            };
        let result = ProjectionRun {
            applied: progress.applied,
            skipped: progress.skipped,
            stop: stop_of(
                advance,
                progress.failure,
                progress.out_of_order,
                progress.dead_letter_write_failed,
            ),
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
            Err(err) => {
                self.error(
                    "projection: checkpoint read failed, fail-closed (no apply)",
                    &err,
                );
                None
            }
        }
    }

    /// apply 事件批：乱序 / 跳过 lsn ≤ baseline / 遇第一个失败均 fail-closed 停批。
    ///
    /// 顺序由运行期 `lsn < prev` 检查守（**release 也生效**，F1 #1211 review）——非仅前置假设。
    async fn apply_batch<E: ProjectionEvent>(
        &self,
        events: &[E],
        baseline: Option<Lsn>,
    ) -> BatchProgress {
        let mut progress = BatchProgress::default();
        let mut prev_lsn: Option<Lsn> = None;
        for event in events {
            let lsn = event.lsn();
            // 单调递增 release fail-closed：witness 只证构造期串行，运行期顺序由此守（INVARIANT PROJECTION-SERIAL-WITNESS-01）。
            if prev_lsn.is_some_and(|p| lsn < p) {
                self.log_out_of_order(lsn);
                if self
                    .write_projection_dead_letter(event, ProjectionDeadLetterReason::OutOfOrder)
                    .await
                    .is_err()
                {
                    progress.dead_letter_write_failed = Some(lsn);
                    break;
                }
                progress.out_of_order = Some(lsn);
                break;
            }
            prev_lsn = Some(lsn);
            // 已在 baseline 以内的事件：已投过，跳过（断点续投语义）。
            if baseline.is_some_and(|b| lsn <= b) {
                progress.skipped += 1;
                continue;
            }
            if let Err(e) = self.projector.apply(event).await {
                self.log_apply_failed(lsn, e.kind(), event.topic().as_str());
                if let Some(reason) = ProjectionDeadLetterReason::from_engine_error_kind(e.kind())
                    && self
                        .write_projection_dead_letter(event, reason)
                        .await
                        .is_err()
                {
                    progress.dead_letter_write_failed = Some(lsn);
                    break;
                }
                progress.failure = Some((lsn, e.kind()));
                break;
            }
            progress.applied += 1;
            progress.high_water = Some(lsn);
        }
        progress
    }

    /// 结构化 warn：乱序 lsn 致 fail-closed 停批（仅元数据，无 payload/PII）。
    fn log_out_of_order(&self, lsn: Lsn) {
        tracing::warn!(
            owner = self.owner.as_str(),
            projection_id = self.projection_id.as_str(),
            lsn = lsn.get(),
            "projection: out-of-order lsn, stopping batch fail-closed"
        );
    }

    /// 结构化 warn：apply 失败致 fail-closed 停批（仅元数据，无 payload/PII）。
    fn log_apply_failed(&self, lsn: Lsn, kind: EngineErrorKind, topic: &str) {
        tracing::warn!(
            owner = self.owner.as_str(),
            projection_id = self.projection_id.as_str(),
            lsn = lsn.get(),
            kind = ?kind,
            topic = topic,
            "projection: apply failed, stopping batch"
        );
    }

    async fn write_projection_dead_letter<E: ProjectionEvent>(
        &self,
        event: &E,
        reason: ProjectionDeadLetterReason,
    ) -> Result<(), ()> {
        let metadata = event.metadata();
        let record = DeadLetterRecord::new(
            metadata.tenant(),
            projection_dead_letter_message_id(&self.owner, &self.projection_id, event.lsn()),
            metadata.domain(),
            metadata.contract_id(),
            event.topic().as_str(),
            Some(self.projection_id.as_str().to_string()),
            event.payload().to_vec(),
            projection_dead_letter_summary(reason),
            1,
            WritableDeadLetterSource::Projection,
            projection_dead_letter_metadata(metadata),
        );
        self.dlx.write_dead_letter(record).await.map_err(|err| {
            tracing::error!(
                owner = self.owner.as_str(),
                projection_id = self.projection_id.as_str(),
                lsn = event.lsn().get(),
                reason = reason.as_label(),
                error = %err,
                "projection: dead-letter write failed, stopping without checkpoint advance"
            );
        })
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
            Err(err) => {
                // reason: projection checkpoint 是主要进度记录，持久化写失败 = error 级（observability.md
                // 持久化失败分级）；区别于 saga（checkpoint 仅快进游标非权威），projection 进度持久化失败
                // 需更高级别告警。
                self.error("projection: checkpoint save failed, replay is safe", &err);
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
    fn error(&self, msg: &'static str, err: &impl std::fmt::Display) {
        tracing::error!(
            owner = self.owner.as_str(),
            projection_id = self.projection_id.as_str(),
            error = %err,
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
    /// 首个乱序事件 lsn（release fail-closed）；None = 顺序合法。与 `failure` 互斥（break 于首个命中）。
    out_of_order: Option<Lsn>,
    /// projection DLQ 写失败的 poison lsn；命中后不推进 checkpoint。
    dead_letter_write_failed: Option<Lsn>,
}

/// 把 advance 结论 + failure + 乱序停因组合成对外 `ProjectionStop`。
fn stop_of(
    advance: Advance,
    failure: Option<(Lsn, EngineErrorKind)>,
    out_of_order: Option<Lsn>,
    dead_letter_write_failed: Option<Lsn>,
) -> ProjectionStop {
    if let Some(failed_at) = dead_letter_write_failed {
        return ProjectionStop::DeadLetterUnsaved { failed_at };
    }
    match advance {
        Advance::Fenced => ProjectionStop::Fenced,
        Advance::Unsaved => ProjectionStop::CheckpointUnsaved,
        // out_of_order 与 failure 互斥（apply_batch break 于首个命中）；乱序优先报 OutOfOrder。
        Advance::Advanced | Advance::NoChange => match (out_of_order, failure) {
            (Some(failed_at), _) => ProjectionStop::OutOfOrder { failed_at },
            (None, Some((failed_at, kind))) => ProjectionStop::ApplyFailed { failed_at, kind },
            (None, None) => ProjectionStop::Completed,
        },
    }
}

fn projection_dead_letter_message_id(
    owner: &CheckpointOwner,
    projection_id: &CheckpointId,
    lsn: Lsn,
) -> String {
    format!(
        "projection:{}:{}:{}",
        owner.as_str(),
        projection_id.as_str(),
        lsn.get()
    )
}

fn projection_dead_letter_summary(reason: ProjectionDeadLetterReason) -> DeadLetterSummary {
    match reason {
        ProjectionDeadLetterReason::ApplyPermanent => SUMMARY_PROJECTION_APPLY_PERMANENT,
        ProjectionDeadLetterReason::ApplyInvariant => SUMMARY_PROJECTION_APPLY_INVARIANT,
        ProjectionDeadLetterReason::OutOfOrder => SUMMARY_PROJECTION_OUT_OF_ORDER,
        _ => SUMMARY_PROJECTION_POISON,
    }
}

fn projection_dead_letter_metadata(metadata: &ProjectionEventMetadata) -> EnvelopeMetadata {
    let mut out = EnvelopeMetadata::empty();
    if let serde_json::Value::Object(map) = metadata.metadata_json() {
        for (key, value) in map {
            if let Some(value) = projection_metadata_value(value) {
                insert_projection_dead_letter_metadata(&mut out, key.as_str(), value);
            }
        }
    }
    if let Some(partition_key) = metadata.partition_key() {
        insert_projection_dead_letter_metadata(&mut out, "partitionKey", partition_key.to_string());
    }
    if let Some(causation_id) = metadata.causation_id() {
        insert_projection_dead_letter_metadata(&mut out, "causationId", causation_id.to_string());
    }
    out
}

fn insert_projection_dead_letter_metadata(
    metadata: &mut EnvelopeMetadata,
    key: impl Into<String>,
    value: impl Into<String>,
) {
    match metadata.try_insert(key, value) {
        Ok(()) | Err(MetadataError::ReservedKey) => {}
    }
}

fn projection_metadata_value(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

// ── 测试 ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use consistency::outbox::Topic;
    use consistency::{
        EngineError, EngineErrorKind, Lsn, ProjectionEvent, ProjectionEventMetadata, Projector,
    };
    use diport::{
        Checkpoint, CheckpointId, CheckpointOwner, CheckpointStoreError, CheckpointVersion,
        DeadLetterRecord, DeadLetterSource, DeadLetterStore, DeadLetterStoreError,
        OwnerCheckpointStore, SaveOutcome,
    };

    use consistency::PartitionSerialDelivery;

    use super::{ProjectionHarness, ProjectionRun, ProjectionStop};

    type HarnessParts = (
        ProjectionHarness<RecordingProjector, FakeCheckpointStore, FakeDeadLetterStore>,
        Arc<RecordingProjector>,
        Arc<FakeCheckpointStore>,
        Arc<FakeDeadLetterStore>,
    );

    // ── FakeEvent ─────────────────────────────────────────────────────────────

    /// 测试用 fake 投影事件。
    struct FakeEvent {
        lsn: Lsn,
        topic: Topic,
        payload: Vec<u8>,
        metadata: ProjectionEventMetadata,
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
        fn metadata(&self) -> &ProjectionEventMetadata {
            &self.metadata
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
            metadata: projection_metadata(),
        }
    }

    #[allow(clippy::expect_used)]
    // reason: test fixture literals are canonical; panic indicates fixture drift.
    fn projection_metadata() -> ProjectionEventMetadata {
        ProjectionEventMetadata::new(
            vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
                .expect("canonical test tenant"),
            "projection-test-event",
            "test",
            "test.projection-event",
            "v1",
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            serde_json::json!({ "tenantId": "f47ac10b-58cc-4372-a567-0e02b2c3d479" }),
            None,
            None,
        )
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

    // ── FakeDeadLetterStore ──────────────────────────────────────────────────

    #[derive(Default)]
    struct FakeDeadLetterStore {
        records: Mutex<Vec<DeadLetterRecord>>,
        fail_write: bool,
    }

    impl FakeDeadLetterStore {
        fn new() -> Self {
            Self::default()
        }

        fn fail_write() -> Self {
            Self {
                fail_write: true,
                ..Self::default()
            }
        }

        fn records(&self) -> Vec<DeadLetterRecord> {
            self.records
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }
    }

    impl DeadLetterStore for FakeDeadLetterStore {
        async fn write_dead_letter(
            &self,
            record: DeadLetterRecord,
        ) -> Result<(), DeadLetterStoreError> {
            if self.fail_write {
                return Err(DeadLetterStoreError::new(std::io::Error::other(
                    "fake dlq unavailable",
                )));
            }
            let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
            if !records
                .iter()
                .any(|existing| existing.message_id() == record.message_id())
            {
                records.push(record);
            }
            Ok(())
        }

        async fn shutdown(&self) -> Result<(), DeadLetterStoreError> {
            Ok(())
        }
    }

    // ── 测试辅助 ──────────────────────────────────────────────────────────────

    fn harness(projector: RecordingProjector, store: FakeCheckpointStore) -> HarnessParts {
        harness_with_dlx(projector, store, FakeDeadLetterStore::new())
    }

    fn harness_with_dlx(
        projector: RecordingProjector,
        store: FakeCheckpointStore,
        dlx: FakeDeadLetterStore,
    ) -> HarnessParts {
        // 测试 fake 串行 source（#[cfg(test)] 豁免 rss_partition_serial_allowlist dylint，
        // `cargo dylint --all` 默认不扫 test targets）。
        struct SerialFake;
        impl PartitionSerialDelivery for SerialFake {}

        let p = Arc::new(projector);
        let c = Arc::new(store);
        let d = Arc::new(dlx);
        let h = ProjectionHarness::new(
            Arc::clone(&p),
            Arc::clone(&c),
            CheckpointOwner::new("test-owner"),
            CheckpointId::new("test-proj"),
            Arc::clone(&d),
            consistency::SerialInOrder::from_source(&SerialFake),
        );
        (h, p, c, d)
    }

    fn assert_projection_dlx(record: &DeadLetterRecord, lsn: u64, summary: &str) {
        assert_eq!(record.source(), DeadLetterSource::Projection);
        assert_eq!(
            record.message_id(),
            format!("projection:test-owner:test-proj:{lsn}")
        );
        assert_eq!(record.consumer_group(), Some("test-proj"));
        assert_eq!(record.domain(), "test");
        assert_eq!(record.contract_id(), "test.projection-event");
        assert_eq!(record.topic(), "proj.test");
        assert_eq!(record.error_summary(), summary);
        assert_eq!(record.num_attempts(), 1);
    }

    // ── 用例 ──────────────────────────────────────────────────────────────────

    /// 1. 无 ckpt 全量重放：events 1..=100 全部 apply，checkpoint 从 None 推进到 offset=100。
    // reason: 测试断言用 expect，checkpoint 必须存在（逻辑断言，非生产 error handling）。
    #[allow(clippy::expect_used)]
    #[tokio::test]
    async fn fresh_replay_applies_all() {
        let (h, p, c, _d) = harness(RecordingProjector::new(), FakeCheckpointStore::empty());
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
        let (h, p, c, _d) = harness(
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
        let (h, p, c, _d) = harness(
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
        let (h, _p, _c, _d) = harness(RecordingProjector::new(), FakeCheckpointStore::empty());
        let events = vec![ev(0), ev(1), ev(2)];
        let result = h.run(&events).await;

        assert_eq!(result.applied, 3, "lsn=0 must not be skipped");
        assert_eq!(result.skipped, 0);
        assert_eq!(result.stop, ProjectionStop::Completed);
    }

    /// 5. 空批：applied=0, skipped=0, Completed，checkpoint 未写。
    #[tokio::test]
    async fn empty_batch_noop() {
        let (h, _p, c, _d) = harness(RecordingProjector::new(), FakeCheckpointStore::empty());
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
        let (h, p, c, d) = harness(
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
        assert!(
            d.records().is_empty(),
            "transient projection failure must not write DLQ"
        );
    }

    /// 7. 永久失败：写 projection DLQ 后 fail-closed，不自动 skip。
    // reason: 测试断言用 expect。
    #[allow(clippy::expect_used)]
    #[tokio::test]
    async fn permanent_failure_writes_projection_dlx_and_stops_without_auto_skip() {
        let (h, _p, c, d) = harness(
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
        let records = d.records();
        assert_eq!(records.len(), 1);
        assert_projection_dlx(&records[0], 3, "projection apply permanent");

        let rerun = h.run(&evs(1, 5)).await;
        assert_eq!(
            rerun.stop,
            ProjectionStop::ApplyFailed {
                failed_at: Lsn::new(3),
                kind: EngineErrorKind::Permanent,
            }
        );
        assert_eq!(
            d.records().len(),
            1,
            "projection DLQ message id must be idempotent"
        );
    }

    /// 8. Invariant 失败：写 projection DLQ，stop=ApplyFailed{kind:Invariant}。
    #[tokio::test]
    async fn invariant_failure_writes_projection_dlx_and_stops() {
        let (h, _p, _c, d) = harness(
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
        let records = d.records();
        assert_eq!(records.len(), 1);
        assert_projection_dlx(&records[0], 3, "projection apply invariant");
    }

    /// 8b. poison DLQ 写失败：不推进 checkpoint。
    #[tokio::test]
    async fn projection_dlx_write_failure_does_not_advance_checkpoint() {
        let (h, _p, c, _d) = harness_with_dlx(
            RecordingProjector::failing_at(3, EngineErrorKind::Permanent),
            FakeCheckpointStore::empty(),
            FakeDeadLetterStore::fail_write(),
        );
        let result = h.run(&evs(1, 5)).await;

        assert_eq!(
            result.stop,
            ProjectionStop::DeadLetterUnsaved {
                failed_at: Lsn::new(3)
            }
        );
        assert_eq!(result.applied, 2);
        assert!(
            c.current().is_none(),
            "DLQ write failure must not advance checkpoint"
        );
    }

    /// 9. 首条即失败：applied=0, checkpoint 未写（high_water=None → NoChange）。
    #[tokio::test]
    async fn first_event_fails_no_checkpoint_write() {
        let (h, _p, c, _d) = harness(
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
        let (h, p, _c, _d) = harness(
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
        let (h, p, _c, _d) = harness(RecordingProjector::new(), FakeCheckpointStore::fail_save());
        let result = h.run(&evs(1, 5)).await;

        assert_eq!(result.stop, ProjectionStop::CheckpointUnsaved);
        assert_eq!(result.applied, 5);
        assert_eq!(p.applied_lsns(), (1u64..=5).collect::<Vec<_>>());
    }

    /// 12. checkpoint get infra 故障：**fail-closed**——不 apply 任何事件，stop = CheckpointUnread
    ///     （不降级为空 baseline 盲目重放；caller 据此退避 / 报警 / 重试）。
    #[tokio::test]
    async fn checkpoint_read_infra_error_fails_closed() {
        let (h, p, _c, _d) = harness(RecordingProjector::new(), FakeCheckpointStore::fail_get());
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

    #[test]
    #[allow(clippy::unwrap_used)]
    // reason: tracing capture test uses Mutex/runtime construction as test assertions.
    fn checkpoint_infra_errors_log_redacted_error_field() {
        use std::collections::HashMap;
        use tracing::field::{Field, Visit};
        use tracing::subscriber::Interest;
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
            fn register_callsite(&self, _metadata: &'static Metadata<'static>) -> Interest {
                Interest::always()
            }

            fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
                true
            }

            fn new_span(&self, _span: &span::Attributes<'_>) -> Id {
                Id::from_u64(1)
            }

            fn record(&self, _span: &Id, _values: &span::Record<'_>) {}
            fn record_follows_from(&self, _span: &Id, _follows: &Id) {}
            fn enter(&self, _span: &Id) {}
            fn exit(&self, _span: &Id) {}

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
            captured: Arc::clone(&captured),
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        tracing::subscriber::with_default(subscriber, || {
            rt.block_on(async {
                let (read_harness, _p, _c, _d) =
                    harness(RecordingProjector::new(), FakeCheckpointStore::fail_get());
                let _ = read_harness.run(&evs(1, 1)).await;

                let (save_harness, _p, _c, _d) =
                    harness(RecordingProjector::new(), FakeCheckpointStore::fail_save());
                let _ = save_harness.run(&evs(1, 1)).await;
            });
        });

        let events = captured.events.lock().unwrap();
        let error_fields: Vec<&str> = events
            .iter()
            .filter_map(|event| event.get("error").map(String::as_str))
            .collect();

        assert_eq!(
            error_fields.len(),
            2,
            "read and save checkpoint infra errors must both log an error field: {events:?}"
        );
        assert!(
            error_fields
                .iter()
                .all(|value| value.contains("checkpoint store operation failed")),
            "checkpoint logs must preserve safe error summary: {error_fields:?}"
        );
        assert!(
            error_fields
                .iter()
                .all(|value| !value.contains("fake store")),
            "checkpoint logs must not expose redacted inner source: {error_fields:?}"
        );
    }

    /// 13. apply 失败 + checkpoint 被 fence：advance 主导，stop = Fenced（非 ApplyFailed）。
    ///
    /// lsn=1,2 成功，lsn=3 失败（high_water=2）→ CAS 推进到 2，但 force_stale → Fenced。
    /// stop_of(Fenced, Some(...)) = Fenced（fence 优先，advance 优先于 failure）。
    #[tokio::test]
    async fn apply_failure_during_fence_reports_fenced() {
        let (h, p, _c, _d) = harness(
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
        let (h, p, _c, _d) = harness(
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

    /// 15. 乱序事件 **release 也 fail-closed**（F1，#1211 review）：不 panic、不静默 apply 越过。
    ///
    /// 传入 [ev(1), ev(2), ev(5), ev(3)]：apply 1/2/5（high_water=5）后 ev(3) lsn < prev=5 →
    /// 停批，ev(3) 不 apply；stop=OutOfOrder{failed_at=3}，不把 checkpoint 推过 poison lsn=3。
    #[tokio::test]
    async fn out_of_order_events_stop_fail_closed() {
        let (h, p, c, d) = harness(RecordingProjector::new(), FakeCheckpointStore::empty());
        let events = vec![ev(1), ev(2), ev(5), ev(3)];
        let result = h.run(&events).await;

        assert_eq!(
            result.stop,
            ProjectionStop::OutOfOrder {
                failed_at: Lsn::new(3)
            },
            "乱序 release 也 fail-closed 停批，报 OutOfOrder"
        );
        assert_eq!(result.applied, 3, "仅 lsn=1,2,5 已 apply（ev(3) 未 apply）");
        assert_eq!(p.applied_lsns(), vec![1u64, 2, 5], "ev(3) 不被 apply");
        assert!(
            c.current().is_none(),
            "out-of-order poison must not advance checkpoint past failed lsn"
        );
        let records = d.records();
        assert_eq!(records.len(), 1);
        assert_projection_dlx(&records[0], 3, "projection out of order");
        // anti-vacuity：合法升序批不触发 OutOfOrder（全 apply、Completed）。
        let (h2, p2, _c2, _d2) = harness(RecordingProjector::new(), FakeCheckpointStore::empty());
        let ok = h2.run(&evs(1, 4)).await;
        assert_eq!(ok.stop, ProjectionStop::Completed, "升序批正常完成");
        assert_eq!(p2.applied_lsns(), vec![1u64, 2, 3, 4]);
    }
}
