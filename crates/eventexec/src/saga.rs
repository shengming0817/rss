//! saga 执行与编排 —— 接缝类型 + 执行器实现（前向 append journal + 失败逆序补偿 + checkpoint resume）。
//!
//! 两个 step 抽象的关系（reviewer 常问）：
//! - [`SagaAction`]（本模块，object-safe `BoxFuture`）= **erased 运行时动作栈**——执行器
//!   ([`SagaExecutorImpl`]) 驱动 `Vec<Box<dyn SagaAction>>`，前向 `do_it` / 逆序 `undo_it`。
//! - `consistency::saga::SagaStep`（native AFIT，`execute`/`compensate`）= **typed authoring / codegen
//!   目标** trait。P9 执行器**不**消费它（待 codegen 把 typed step wrap 成 `SagaAction`）。
//!
//! resume 真正崩溃恢复：journal 只存 step 名，执行器经注入的 [`SagaActionFactory`]（saga 模板，对标
//! steno saga template registry）按声明序重物化整个 action 序，再据 journal 已完成前缀跳过、续跑或续补偿。
//!
//! 本 executor 无 background worker、不注册 readyz probe（on-demand 调用）；若未来封装为 worker 形态
//! 须补 `WorkerHealth` + probe，参考 `relay.rs`（见 issue #1247）。
//!
//! ref: oxidecomputer/steno src/saga_action_generic.rs@main（`Action::do_it`/`undo_it`/`name` + 逆序补偿）。

use std::collections::HashMap;
use std::sync::Arc;

use futures::future::BoxFuture;

use consistency::{Lsn, StepName};
use diport::{
    CheckpointId, CheckpointOwner, CheckpointVersion, DeadLetterRecord, DeadLetterStore,
    DeadLetterSummary, JournalEntry, JournalStatus, OwnerCheckpointStore, SagaJournal, SaveOutcome,
};

/// saga 实例标识（uuid newtype）。下沉 `diport`（journal/checkpoint 端口签名引用），本模块 re-export
/// 供域 / 组合根经 `eventexec::SagaId` 命名（层序：diport 不依赖 eventexec）。
pub use diport::SagaId;

// ── 冻结接缝类型（do/undo 动作 + 结论 + 命令 + 执行状态）─────────────────────────

/// saga 动作上下文：标识动作运行所在的 saga + 节点。私有字段（F6 funnel，外部不可字面构造，只经
/// [`SagaActionCtx::new`]）。journal / checkpoint 句柄归执行器，**不**入 ctx（保单写者不变式）。
pub struct SagaActionCtx {
    saga_id: SagaId,
    node_name: String,
}

impl SagaActionCtx {
    /// 受控构造（执行器在每次 `do_it`/`undo_it` 前构造并移交动作）。
    pub fn new(saga_id: uuid::Uuid, node_name: impl Into<String>) -> Self {
        Self {
            saga_id: SagaId::new(saga_id),
            node_name: node_name.into(),
        }
    }

    /// 所属 saga 实例。
    pub fn saga_id(&self) -> SagaId {
        self.saga_id
    }

    /// 当前节点（step）名。
    pub fn node_name(&self) -> &str {
        &self.node_name
    }
}

/// saga 动作（erased 运行时接口；用户 / codegen 实现，执行器以 `Vec<Box<dyn SagaAction>>` 驱动）。
///
/// 对标 steno `Action`：`do_it` 前向（返回输出字节），`undo_it` 补偿（幂等，逆序调用）。
pub trait SagaAction: std::fmt::Debug + Send + Sync {
    /// step 名（须为合法 Rust 标识符；执行器据此落 journal + resume 时由 factory 重物化）。
    fn name(&self) -> &str;

    /// 前向执行；`Ok(output)` 完成（output 入 journal + 末步 output 即 saga 结果）。
    fn do_it(&self, ctx: SagaActionCtx) -> BoxFuture<'static, Result<Vec<u8>, SagaActionError>>;

    /// 补偿（撤销 `do_it` 副作用）；仅对**已完成**步逆序调用。
    fn undo_it(&self, ctx: SagaActionCtx) -> BoxFuture<'static, Result<(), SagaActionError>>;
}

/// saga 执行结论。
#[derive(Debug)]
#[non_exhaustive]
pub enum SagaOutcome {
    /// 全步成功；`output` = 末步 `do_it` 输出（`run` 路径）。
    /// resume 路径终态成功时 `output` 恒为空字节——journal `read` 不回传 output，consumer 不得依赖。
    Succeeded { output: Vec<u8> },
    /// 失败（前向某步失败 → 已完成步逆序补偿后返回原失败，或补偿失败 → dead-letter）。
    Failed {
        failed_node: String,
        error: SagaActionError,
    },
}

/// saga 编排控制命令（saga-orchestration control 接缝，非通用命令分发）。
///
/// **F14：crate-internal（`pub(crate)`）**——P9 无 saga 控制命令执行路径（`Start`/`Cancel` 均无
/// executor 入口），故不暴露公开 API（避免「公开命令面暗示 runtime 已支持」）。
///
/// **注意**：此枚举是 saga Start/Cancel 编排控制的未来接缝，与 #1124 交付的**通用 outbox-topic 命令
/// 分发机制**（`eventexec::command` + `generated::command`）无关。通用命令 dispatch 已落地；此枚举
/// 待 saga 控制面（中断语义 / leader-elect 等后续 issue）消费时再公开。
#[allow(dead_code)]
// reason: 冻结 saga 编排控制接缝占位（#997 saga seam）；P9 无 saga 控制命令消费者，pub(crate) 隐藏
// 未实现命令面（F14），待 saga 控制面后续 issue 消费（与通用 command dispatch #1124 无关）
#[derive(Debug)]
#[non_exhaustive]
pub(crate) enum SagaCommand {
    /// 启动新 saga。
    Start { saga_id: SagaId },
    /// 取消 saga（P9：无中断实现，待 P11 落地）。
    Cancel { saga_id: SagaId },
}

/// saga 执行状态（[`SagaTailer`] 粗粒度 liveness；细分结论在 [`SagaOutcome`]）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaExecStatus {
    /// 已登记未起（保留——当前 journal 驱动的 tailer **不产出**此变体，待 registry-aware tailer）。
    Ready,
    /// 执行 / 补偿在飞。
    Running,
    /// 终态（成功 / 已补偿 / dead-letter）。
    Done,
}

/// saga 动作错误（`#[non_exhaustive]`；执行器对各变体同样处理——任一 `do_it` 错 → 补偿，任一 `undo_it`
/// 错 → dead-letter；变体保留进 [`SagaOutcome::Failed`] 供调用方）。
///
/// 各变体均可出现在 [`SagaOutcome::Failed`]`.error`；consumer 若需区分是否已触发补偿，须查 journal 是否有
/// `Compensating`/`Compensated` 行（`SerializeFailed` = step 名非法 → fail-fast 未 journal、未补偿）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SagaActionError {
    /// 动作执行失败。
    #[error("action failed")]
    ActionFailed,
    /// 输出 / 标识序列化失败（含 step 名非法标识符）——fail-fast，不 journal、不补偿。
    #[error("serialize failed")]
    SerializeFailed,
    /// 子 saga 创建失败。
    #[error("subsaga create failed")]
    SubsagaCreateFailed,
}

// ── 执行器 / 进度跟踪接缝 ──────────────────────────────────────────────────────

/// Saga 执行器接缝：驱动 [`SagaAction`] 栈（前向执行 + 失败逆序补偿）。对标 steno SEC。
pub trait SagaExecutor: Send + Sync {
    /// 执行 saga：顺序 `do_it`，失败逆序 `undo_it`。
    ///
    /// `run` 接收调用方构造的 action 序；[`resume`](SagaExecutor::resume) 经注入的
    /// [`SagaActionFactory`] 重物化（不依赖调用方提供 action 序）。
    ///
    /// **WARNING**: 多副本并发 `run` 同一 `saga_id` 的互斥由调用方负责；P9 不提供
    /// multi-replica guard，P11 leader-elect 落地后由 executor 保证。journal `(saga_id,seq)` PK
    /// + checkpoint CAS 只防数据竞争，不防重复副作用执行。
    fn run(
        &self,
        saga_id: SagaId,
        actions: Vec<Box<dyn SagaAction>>,
    ) -> BoxFuture<'static, SagaOutcome>;

    /// 从 journal 恢复（crash recovery；经注入 [`SagaActionFactory`] 重物化 action 序续跑 / 续补偿）。
    ///
    /// resume 终态成功时 [`SagaOutcome::Succeeded`]`.output` 恒为空字节——journal `read` 不回传
    /// output；末步 output 仅 `run` 路径可信。consumer 不得依赖 resume 的 output 字节。
    fn resume(&self, saga_id: SagaId) -> BoxFuture<'static, SagaOutcome>;
}

/// Saga 进度跟踪接缝：查询执行状态。对标 steno saga status。
pub trait SagaTailer: Send + Sync {
    /// 查 saga 当前粗粒度状态（`None` = 未知 saga）。
    ///
    /// 当前 journal-driven 实现**不产出** [`SagaExecStatus::Ready`]（保留给 registry-aware tailer）；
    /// 只返回 `None` / `Running` / `Done`。
    fn status(&self, saga_id: SagaId) -> BoxFuture<'static, Option<SagaExecStatus>>;
}

/// saga 模板：按声明序产出全部 [`SagaAction`]。resume 用——执行器仅持 `saga_id`，须经此重物化整个
/// action 序（journal 只存 step 名，无法重建闭包）。对标 steno saga template / dag registry。
pub trait SagaActionFactory: Send + Sync {
    /// 构造该 saga 类型的有序 action 序（每次新建实例；执行器据 journal 已完成前缀决定跳过 / 续跑）。
    ///
    /// 实现必须每次返回**相同的完整有序 action 序**（与 `run` 传入序的 step 名 + 顺序一致）。
    /// resume 靠 journal step 名与 action index 一一对应重建状态，缺步 / 重排即导致错跳 / 补偿错乱。
    fn build(&self) -> Vec<Box<dyn SagaAction>>;
}

/// 补偿失败安全摘要（`&'static str` const literal；进 journal `Failed` 行 + DLX 摘要 + tracing，不携 runtime
/// 数据，INVARIANT: DIPORT-DLX-SUMMARY-STATIC-01）。
const SAGA_COMPENSATION_FAILED: &str = "saga compensation step failed";

/// resume 未知 saga（空 journal）占位 failed_node。
const UNKNOWN_SAGA: &str = "<unknown-saga>";

// ── SagaExecutorImpl ──────────────────────────────────────────────────────────

/// saga 执行器实现：必填依赖走构造器**位置参**（saga.md §构造器，缺失即编译错误）。泛型静态分发 +
/// `Arc<S>`（`run`/`resume` 返回 `'static` future，须 clone 句柄进 future；对齐 diport 注入形态表
/// spawn/Send-'static 行）。
///
/// **retry/timeout 策略（F11，未实现）**：`kind:saga` 契约声明 `retryMillis`/`timeoutMillis`（saga 策略
/// 元数据），但 P9 executor 直接 `action.do_it(ctx).await`，**未实现** retry budget / timeout→超时触发补偿
/// 的 runtime（T009 未要求；属 future scope，见 issue 跟踪）。consumer 不应依赖契约声明的 retry/timeout
/// 在 P9 生效。
pub struct SagaExecutorImpl<J, C, D> {
    journal: Arc<J>,
    checkpoint: Arc<C>,
    dead_letter: Arc<D>,
    factory: Arc<dyn SagaActionFactory>,
    tenant: vocab::TenantId,
    owner: CheckpointOwner,
    contract_id: String,
}

impl<J, C, D> SagaExecutorImpl<J, C, D>
where
    J: SagaJournal + Send + Sync + 'static,
    C: OwnerCheckpointStore + Send + Sync + 'static,
    D: DeadLetterStore + Send + Sync + 'static,
{
    /// 构造（全依赖必填位置参）。
    ///
    /// 第 5 参 `owner` = DLX domain（如 `"billing"`）；第 6 参 `contract_id` = 契约 id（如
    /// `"billing.checkout"`）。二者同进 DLX 记录（SC-006），勿传反。
    pub fn new(
        journal: Arc<J>,
        checkpoint: Arc<C>,
        dead_letter: Arc<D>,
        factory: Arc<dyn SagaActionFactory>,
        tenant: vocab::TenantId,
        owner: CheckpointOwner,
        contract_id: impl Into<String>,
    ) -> Self {
        Self {
            journal,
            checkpoint,
            dead_letter,
            factory,
            tenant,
            owner,
            contract_id: contract_id.into(),
        }
    }
}

impl<J, C, D> SagaExecutor for SagaExecutorImpl<J, C, D>
where
    J: SagaJournal + Send + Sync + 'static,
    C: OwnerCheckpointStore + Send + Sync + 'static,
    D: DeadLetterStore + Send + Sync + 'static,
{
    fn run(
        &self,
        saga_id: SagaId,
        actions: Vec<Box<dyn SagaAction>>,
    ) -> BoxFuture<'static, SagaOutcome> {
        let journal = self.journal.clone();
        let checkpoint = self.checkpoint.clone();
        let dead_letter = self.dead_letter.clone();
        let tenant = self.tenant;
        let owner = self.owner.clone();
        let contract_id = self.contract_id.clone();
        Box::pin(async move {
            let ctx = ExecCtx {
                journal: &*journal,
                checkpoint: &*checkpoint,
                dead_letter: &*dead_letter,
                tenant,
                owner: &owner,
                contract_id: &contract_id,
                saga_id,
                checkpoint_id: CheckpointId::new(saga_id.as_uuid().to_string()),
            };
            ctx.run_forward(&actions, 0, Cursor::new()).await
        })
    }

    fn resume(&self, saga_id: SagaId) -> BoxFuture<'static, SagaOutcome> {
        let journal = self.journal.clone();
        let checkpoint = self.checkpoint.clone();
        let dead_letter = self.dead_letter.clone();
        let tenant = self.tenant;
        let owner = self.owner.clone();
        let contract_id = self.contract_id.clone();
        let factory = self.factory.clone();
        Box::pin(async move {
            let actions = factory.build();
            let ctx = ExecCtx {
                journal: &*journal,
                checkpoint: &*checkpoint,
                dead_letter: &*dead_letter,
                tenant,
                owner: &owner,
                contract_id: &contract_id,
                saga_id,
                checkpoint_id: CheckpointId::new(saga_id.as_uuid().to_string()),
            };
            ctx.resume(&actions).await
        })
    }
}

impl<J, C, D> SagaTailer for SagaExecutorImpl<J, C, D>
where
    J: SagaJournal + Send + Sync + 'static,
    C: OwnerCheckpointStore + Send + Sync + 'static,
    D: DeadLetterStore + Send + Sync + 'static,
{
    fn status(&self, saga_id: SagaId) -> BoxFuture<'static, Option<SagaExecStatus>> {
        let journal = self.journal.clone();
        Box::pin(async move { status_of(&*journal, saga_id).await })
    }
}

// ── 执行上下文（持运行时句柄引用，方法实现前向 / 补偿 / checkpoint）─────────────

/// 前向游标：journal append 序号 + 已完成步栈（index + StepName）+ 末步输出。
struct Cursor {
    seq: u64,
    completed: Vec<(usize, StepName)>,
    last_output: Option<Vec<u8>>,
}

impl Cursor {
    fn new() -> Self {
        Self {
            seq: 0,
            completed: Vec::new(),
            last_output: None,
        }
    }
}

struct ExecCtx<'a, J, C, D> {
    journal: &'a J,
    checkpoint: &'a C,
    dead_letter: &'a D,
    tenant: vocab::TenantId,
    owner: &'a CheckpointOwner,
    contract_id: &'a str,
    saga_id: SagaId,
    checkpoint_id: CheckpointId,
}

impl<J, C, D> ExecCtx<'_, J, C, D>
where
    J: SagaJournal,
    C: OwnerCheckpointStore,
    D: DeadLetterStore,
{
    /// append 一条 journal，返回是否成功（失败记结构化日志）。
    ///
    /// F1：journal 写是执行状态机**一等边**，不再 best-effort 吞错——前向路径据返回值 fail-closed
    /// （`Executing` 写失败 ⇒ 不执行副作用；`Completed` 写失败 ⇒ 补偿含本步在内的栈）。补偿路径忽略返回
    /// （已在失败态，journal `Failed` 行 + dead-letter 是 durable 兜底）。
    async fn append(&self, entry: JournalEntry) -> bool {
        let seq = entry.seq;
        let status = entry.status.as_str();
        if self.journal.append(&self.saga_id, entry).await.is_err() {
            tracing::error!(saga_id = %self.saga_id.as_uuid(), seq, status, "saga: journal append failed");
            return false;
        }
        true
    }

    /// CAS 推进 checkpoint，返回是否可继续前向。
    ///
    /// F2：`StaleVersion` = 并发执行器已推进 checkpoint = 本 runner **失 fence** ⇒ 返 `false`（停跑，不续后续
    /// step）；infra 读/写错误 ⇒ 记日志续跑（`true`，journal 为权威，checkpoint 仅快进游标，不因瞬时故障停
    /// saga）。日志收口到 [`ExecCtx::warn_checkpoint`] 控制认知复杂度 ≤15。
    async fn advance_checkpoint(&self, offset: Lsn) -> bool {
        let expected = match self
            .checkpoint
            .get_checkpoint(self.owner, &self.checkpoint_id)
            .await
        {
            Ok(Some(cp)) => cp.version,
            Ok(None) => CheckpointVersion::INITIAL,
            Err(_) => {
                self.warn_checkpoint("saga: checkpoint read failed");
                return true;
            }
        };
        match self
            .checkpoint
            .save_checkpoint(self.owner, &self.checkpoint_id, offset, expected)
            .await
        {
            Ok(SaveOutcome::Saved) => true,
            // StaleVersion：并发执行器 fence 本 runner ⇒ 停跑（F2）。
            Ok(SaveOutcome::StaleVersion) => {
                self.warn_checkpoint("saga: checkpoint fenced by concurrent executor, stopping");
                false
            }
            // 未来 #[non_exhaustive] 变体：journal 权威，记日志续跑。
            Ok(_) => {
                self.warn_checkpoint("saga: checkpoint not saved (unsupported outcome)");
                true
            }
            Err(_) => {
                self.warn_checkpoint("saga: checkpoint save failed");
                true
            }
        }
    }

    /// checkpoint 推进告警收口（tracing 宏出 [`ExecCtx::advance_checkpoint`]，控制其复杂度）。
    fn warn_checkpoint(&self, msg: &'static str) {
        tracing::warn!(saga_id = %self.saga_id.as_uuid(), "{msg}");
    }

    /// 前向执行 `actions[start..]`；失败逆序补偿 `cursor.completed`（含 resume 预填前缀）。
    async fn run_forward(
        &self,
        actions: &[Box<dyn SagaAction>],
        start: usize,
        mut cursor: Cursor,
    ) -> SagaOutcome {
        for (i, action) in actions.iter().enumerate().skip(start) {
            let action = action.as_ref();
            let Ok(step) = StepName::parse(action.name()) else {
                // step 名非法标识符 = Invariant（动作未受治理约束）：fail-fast，不 journal。
                return SagaOutcome::Failed {
                    failed_node: action.name().to_string(),
                    error: SagaActionError::SerializeFailed,
                };
            };
            // F1：Executing append fail-closed —— 写失败则**不执行副作用**（无 journal 无法 durable 恢复）。
            if !self
                .append(JournalEntry::executing(cursor.seq, step.clone()))
                .await
            {
                return SagaOutcome::Failed {
                    failed_node: action.name().to_string(),
                    error: SagaActionError::ActionFailed,
                };
            }
            cursor.seq += 1;
            let ctx = SagaActionCtx::new(self.saga_id.as_uuid(), action.name());
            let output = match action.do_it(ctx).await {
                Ok(o) => o,
                Err(err) => {
                    return self
                        .compensate(actions, &cursor.completed, cursor.seq, action.name(), err)
                        .await;
                }
            };
            // 副作用已发生：先入已完成栈（含本步），再写 Completed；写失败 ⇒ 补偿含本步在内的栈（F1）。
            cursor.completed.push((i, step.clone()));
            let completed_ok = self
                .append(JournalEntry::completed(cursor.seq, step, output.clone()))
                .await;
            cursor.seq += 1;
            if !completed_ok {
                return self
                    .compensate(
                        actions,
                        &cursor.completed,
                        cursor.seq,
                        action.name(),
                        SagaActionError::ActionFailed,
                    )
                    .await;
            }
            cursor.last_output = Some(output);
            // F2：checkpoint fence —— StaleVersion 表并发执行器已接管 ⇒ 停跑。
            if !self.advance_checkpoint(Lsn::new(i as u64 + 1)).await {
                return SagaOutcome::Failed {
                    failed_node: action.name().to_string(),
                    error: SagaActionError::ActionFailed,
                };
            }
        }
        SagaOutcome::Succeeded {
            output: cursor.last_output.unwrap_or_default(),
        }
    }

    /// 逆序补偿已完成步；补偿失败 → journal `Failed` + dead-letter + 终态 `Failed`。
    ///
    /// 首个 `undo_it` 失败即终止（写 `Failed` journal 行 + dead-letter），**剩余已完成步不再补偿**
    /// （steno 语义，须人工介入）。
    async fn compensate(
        &self,
        actions: &[Box<dyn SagaAction>],
        completed: &[(usize, StepName)],
        mut seq: u64,
        failed_node: &str,
        original_error: SagaActionError,
    ) -> SagaOutcome {
        for (i, step) in completed.iter().rev() {
            let action = actions[*i].as_ref();
            self.append(JournalEntry::compensating(seq, step.clone()))
                .await;
            seq += 1;
            let ctx = SagaActionCtx::new(self.saga_id.as_uuid(), action.name());
            match action.undo_it(ctx).await {
                Ok(()) => {
                    self.append(JournalEntry::compensated(seq, step.clone()))
                        .await;
                    seq += 1;
                }
                Err(undo_err) => {
                    self.append(JournalEntry::failed(
                        seq,
                        step.clone(),
                        SAGA_COMPENSATION_FAILED,
                    ))
                    .await;
                    // F5：DLX 携 saga_id + 原始前向失败步（failed_node）+ 补偿失败步，诊断闭环。
                    self.dead_letter_compensation_failure(action.name(), failed_node)
                        .await;
                    return SagaOutcome::Failed {
                        failed_node: action.name().to_string(),
                        error: undo_err,
                    };
                }
            }
        }
        SagaOutcome::Failed {
            failed_node: failed_node.to_string(),
            error: original_error,
        }
    }

    /// 补偿失败 → 结构化 error 日志（saga_id / step_name / error_summary）+ 写 dead-letter
    /// （domain / contract_id 取 saga owner，SC-006）。DLX 写失败：记日志，journal `Failed` 行是 durable 审计。
    /// tracing 宏收口到 [`ExecCtx::error_compensation_failed`] / [`ExecCtx::error_dlx_write_failed`]，
    /// 控制本函数认知复杂度 ≤15（同 consumer.rs 日志 helper 范式）。
    async fn dead_letter_compensation_failure(&self, comp_step: &str, forward_step: &str) {
        self.error_compensation_failed(comp_step, forward_step);
        // F5：DLX 记录 topic = saga_id（诊断闭环）；original_payload = 失败步标识 JSON（uuid + step 名均为
        // identifier，非 PII；Debug 仍按 DeadLetterRecord 脱敏，运维经 DLX store 查询取用）。
        let payload = format!(
            "{{\"sagaId\":\"{}\",\"failedForwardStep\":\"{forward_step}\",\"failedCompensationStep\":\"{comp_step}\"}}",
            self.saga_id.as_uuid()
        )
        .into_bytes();
        let record = DeadLetterRecord::new(
            self.tenant,
            self.saga_id.as_uuid().to_string(),
            self.owner.as_str(),
            self.contract_id,
            self.saga_id.as_uuid().to_string(),
            payload,
            DeadLetterSummary::new(SAGA_COMPENSATION_FAILED),
            1,
        );
        if self.dead_letter.write_dead_letter(record).await.is_err() {
            self.error_dlx_write_failed(comp_step);
        }
    }

    /// 补偿失败结构化 error 日志（saga_id / step_name / failed_forward_step / error_summary，T009.6 / SC-006）。
    fn error_compensation_failed(&self, comp_step: &str, forward_step: &str) {
        tracing::error!(
            saga_id = %self.saga_id.as_uuid(),
            step_name = comp_step,
            failed_forward_step = forward_step,
            error_summary = SAGA_COMPENSATION_FAILED,
            "saga: compensation failed, writing dead-letter (manual intervention required)"
        );
    }

    /// DLX 写失败 error 日志（journal `Failed` 行是 durable 审计兜底）。
    fn error_dlx_write_failed(&self, node_name: &str) {
        tracing::error!(
            saga_id = %self.saga_id.as_uuid(),
            step_name = node_name,
            "saga: dead-letter write failed (journal Failed row is durable audit)"
        );
    }

    /// resume journal 读失败 error 日志（存储故障，与空 journal = 未知 saga 区分）。
    fn error_resume_read_failed(&self) {
        tracing::error!(saga_id = %self.saga_id.as_uuid(), "saga: resume journal read failed");
    }

    /// resume：读 journal 重建状态，续前向 / 续补偿 / 终态直返。
    async fn resume(&self, actions: &[Box<dyn SagaAction>]) -> SagaOutcome {
        let entries = match self.journal.read(&self.saga_id).await {
            Ok(e) => e,
            Err(_) => {
                self.error_resume_read_failed();
                return SagaOutcome::Failed {
                    failed_node: UNKNOWN_SAGA.to_string(),
                    error: SagaActionError::ActionFailed,
                };
            }
        };
        if entries.is_empty() {
            return SagaOutcome::Failed {
                failed_node: UNKNOWN_SAGA.to_string(),
                error: SagaActionError::ActionFailed,
            };
        }
        // F7：resume 一致性校验——action 名须唯一、journal 每个 step 须匹配某 action；违规 fail-fast，
        // 不静默跳过异常 journal（防重复名被 HashMap 覆盖 / 未知 step 被丢弃）。
        if let Some(bad) = validate_resume_actions(&entries, actions) {
            tracing::error!(saga_id = %self.saga_id.as_uuid(), step_name = %bad, "saga: resume action/journal step mismatch");
            return SagaOutcome::Failed {
                failed_node: bad,
                error: SagaActionError::SerializeFailed,
            };
        }
        match rebuild_resume_state(&entries, actions) {
            ResumeState::Forward { start, cursor } => {
                self.run_forward(actions, start, cursor).await
            }
            ResumeState::Compensating { seq, pending } => {
                self.compensate(
                    actions,
                    &pending,
                    seq,
                    UNKNOWN_SAGA,
                    SagaActionError::ActionFailed,
                )
                .await
            }
            ResumeState::Terminal(outcome) => outcome,
        }
    }
}

// ── resume 重建（pure）────────────────────────────────────────────────────────

/// resume 重建状态。
enum ResumeState {
    /// 续前向：从 `start` 续跑，`cursor` 预填已完成前缀。
    Forward { start: usize, cursor: Cursor },
    /// 续补偿：`pending`（逆序待补偿的已完成步）从 `seq` 续。
    Compensating {
        seq: u64,
        pending: Vec<(usize, StepName)>,
    },
    /// 终态（已 dead-letter / 全成 / 全补偿）。
    Terminal(SagaOutcome),
}

/// F7：resume 一致性校验——action 名须唯一、journal 每个 step 名须匹配某 action。返回首个违规标识
/// （重复 action 名 / journal 未知 step），`None` = 通过。防 resume 静默跳过异常 journal（HashMap 覆盖
/// 重复名 / `filter` 丢弃未知 step）。
fn validate_resume_actions(
    entries: &[JournalEntry],
    actions: &[Box<dyn SagaAction>],
) -> Option<String> {
    let mut names = std::collections::HashSet::new();
    for a in actions {
        if !names.insert(a.name()) {
            return Some(a.name().to_string());
        }
    }
    entries
        .iter()
        .find(|e| !names.contains(e.step_name.as_str()))
        .map(|e| e.step_name.as_str().to_string())
}

/// 据 journal 条目 + action 序重建 resume 状态。entries 按 seq 序；step 名匹配 action index。
fn rebuild_resume_state(entries: &[JournalEntry], actions: &[Box<dyn SagaAction>]) -> ResumeState {
    let latest = latest_status_by_index(entries, actions);
    let next_seq = entries.iter().map(|e| e.seq).max().map_or(0, |m| m + 1);

    // 已 dead-letter（某步补偿失败）→ 终态 Failed。
    if let Some(idx) = latest
        .iter()
        .find(|(_, s)| **s == JournalStatus::Failed)
        .map(|(i, _)| *i)
    {
        return ResumeState::Terminal(SagaOutcome::Failed {
            failed_node: actions[idx].name().to_string(),
            error: SagaActionError::ActionFailed,
        });
    }

    // 补偿已开始 → 续补偿 pending（latest ∈ {Completed, Compensating} 逆序）。
    let compensating = latest
        .values()
        .any(|s| matches!(s, JournalStatus::Compensating | JournalStatus::Compensated));
    if compensating {
        let pending = pending_compensations(&latest, actions);
        return ResumeState::Compensating {
            seq: next_seq,
            pending,
        };
    }

    // 纯前向。
    let completed = completed_in_order(&latest, actions);
    if completed.len() == actions.len() {
        return ResumeState::Terminal(SagaOutcome::Succeeded { output: Vec::new() });
    }
    ResumeState::Forward {
        start: completed.len(),
        cursor: Cursor {
            seq: next_seq,
            completed,
            last_output: None,
        },
    }
}

/// 每个 action index 的最新 journal 状态（entries 按 seq 序，后覆前 = latest）。无匹配 action 的陈旧
/// step 名跳过。
fn latest_status_by_index(
    entries: &[JournalEntry],
    actions: &[Box<dyn SagaAction>],
) -> HashMap<usize, JournalStatus> {
    let index_of: HashMap<&str, usize> = actions
        .iter()
        .enumerate()
        .map(|(i, a)| (a.name(), i))
        .collect();
    let mut latest = HashMap::new();
    for e in entries {
        if let Some(&i) = index_of.get(e.step_name.as_str()) {
            latest.insert(i, e.status);
        }
    }
    latest
}

/// latest == Completed 的 index（升序，附 StepName）—— 续前向预填的已完成前缀。
fn completed_in_order(
    latest: &HashMap<usize, JournalStatus>,
    actions: &[Box<dyn SagaAction>],
) -> Vec<(usize, StepName)> {
    actions
        .iter()
        .enumerate()
        .filter(|(i, _)| latest.get(i) == Some(&JournalStatus::Completed))
        .filter_map(|(i, a)| StepName::parse(a.name()).ok().map(|s| (i, s)))
        .collect()
}

/// latest ∈ {Completed, Compensating} 的 index（逆序，附 StepName）—— 续补偿待撤销集。
fn pending_compensations(
    latest: &HashMap<usize, JournalStatus>,
    actions: &[Box<dyn SagaAction>],
) -> Vec<(usize, StepName)> {
    let mut pending: Vec<(usize, StepName)> = actions
        .iter()
        .enumerate()
        .filter(|(i, _)| {
            matches!(
                latest.get(i),
                Some(JournalStatus::Completed | JournalStatus::Compensating)
            )
        })
        .filter_map(|(i, a)| StepName::parse(a.name()).ok().map(|s| (i, s)))
        .collect();
    pending.reverse();
    pending
}

/// SagaTailer 粗粒度状态（无 action 序，按 step 名聚合最新状态）。
async fn status_of<J: SagaJournal>(journal: &J, saga_id: SagaId) -> Option<SagaExecStatus> {
    let entries = journal
        .read(&saga_id)
        .await
        .inspect_err(
            |_| tracing::warn!(saga_id = %saga_id.as_uuid(), "saga: status journal read failed"),
        )
        .ok()?;
    if entries.is_empty() {
        return None;
    }
    let mut latest: HashMap<&str, JournalStatus> = HashMap::new();
    for e in &entries {
        latest.insert(e.step_name.as_str(), e.status);
    }
    let in_flight = latest
        .values()
        .any(|s| matches!(s, JournalStatus::Executing | JournalStatus::Compensating));
    Some(if in_flight {
        SagaExecStatus::Running
    } else {
        SagaExecStatus::Done
    })
}

#[cfg(test)]
mod tests;
