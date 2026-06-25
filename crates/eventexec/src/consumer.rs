//! ConsumerBase —— 幂等消费驱动（claim→handle→commit/dlx）。
//!
//! 单消息流程：`IdemKey::parse` → `idempotency.check` → handler bounded 重投 →
//! `Ack` commit / `Reject` dlx / `Requeue` 预算耗尽后 dlx。
//! DLX 路径对标 watermill PoisonQueue：原消息 ack 收口，死信另写持久化。
//!
//! ref: watermill message/router/middleware/poison.go（PoisonQueue=DLX）
//!      watermill message/router/middleware/retry.go（重投预算 MaxRetries+1 次尝试）

use std::sync::Arc;

use futures::StreamExt;

use consistency::HandleResult;
use consistency::idempotency::{IdemKey, SeenState};
use diport::dead_letter_store::{
    DeadLetterRecord, DeadLetterStore as _, DeadLetterStoreError, DeadLetterSummary,
    DynDeadLetterStore,
};
use diport::{Message, MessageStream};

use crate::MAX_REDELIVERY;

// ── DLX 摘要 fallback 常量（仅 None 防御；正常路径走 HandleResult::error_summary，#1125）──────────

/// DLX 摘要 fallback：requeue 耗尽但 `HandleResult::error_summary()` 为 `None`——仅防御未来 non_exhaustive
/// `Disposition` 新变体（被 `_ => {}` 保守当 Requeue 却从不 set 摘要）。正常 requeue 路径用 handler 的 error
/// kind 摘要（#1125），此 fallback 不可达于现有变体，非死代码（`// reason:` 见 call-site）。
const SUMMARY_REQUEUE_EXHAUSTED: &str = "requeue budget exhausted";

/// DLX 摘要 fallback：reject 但 `HandleResult::error_summary()` 为 `None`（类型层 ack 形 `None` 防御）。
/// 正常 reject 路径用 handler 的 PermanentError kind 摘要（#1125）。
const SUMMARY_PERMANENT_REJECTION: &str = "permanent rejection";

// ── ConsumerMeta（消费契约元数据）─────────────────────────────────────────────

/// 消费契约元数据（注册期绑定；私有字段 + `new()` funnel）。
///
/// 用于 DLX 记录与结构化日志归因（domain / contract_id / topic 三元组稳定标识消费场景）。
pub struct ConsumerMeta {
    domain: String,
    contract_id: String,
    topic: String,
}

impl ConsumerMeta {
    /// 构造消费契约元数据。
    pub fn new(
        domain: impl Into<String>,
        contract_id: impl Into<String>,
        topic: impl Into<String>,
    ) -> Self {
        Self {
            domain: domain.into(),
            contract_id: contract_id.into(),
            topic: topic.into(),
        }
    }

    pub(crate) fn domain(&self) -> &str {
        &self.domain
    }

    pub(crate) fn contract_id(&self) -> &str {
        &self.contract_id
    }

    pub(crate) fn topic(&self) -> &str {
        &self.topic
    }
}

// ── run_consumer（消费驱动入口）─────────────────────────────────────────────

/// 消费驱动：逐条 claim→handle→commit/dlx（bounded 重投，幂等去重）。
///
/// `group` 参数仅用于结构化日志归因（`IdempotencyStore` 实现在构造时已绑 group，
/// check/commit/release 以 `IdemKey` 为维度；group 重复传参会破坏简洁，故此处仅日志用）。
/// 下游事件经 handler 自持 Publisher 发，不经本驱动中转（对齐 RSS DI port 隔离）。
///
/// **重投次数**：handler 最多被调用 [`MAX_REDELIVERY`] 次（含首投），耗尽后消息进 DLX
/// 而非再次 Requeue，防无限重投。
///
/// **类型形态差异**：
/// - `idempotency: Arc<S>`：check/commit/release 可被多次调用（bounded 循环），
///   `Arc` 允许跨 spawn 共享同一 store 实例。
/// - `dlx: Box<DynDeadLetterStore>`：每条消息至多调用一次 write_dead_letter，
///   one-shot 写入语义不需要共享，owned 注入更自然（类型层明确消费权）。
///
/// **worker 生命周期豁免**：本驱动是 plain async fn（对齐 `run_dispatch` 范式），
/// `ManagedResource` / probe / `ShutdownStack` 两阶段关闭接入随组合根 spawn（T008）落地，
/// 属 follow-up；与 relay.rs 的 `RelayWorker` 不同，T007 只交付驱动函数本体。
///
/// ref: watermill message/router/middleware/poison.go（DLX ack 收口）
///      watermill message/router/middleware/retry.go（MaxRetries+1 次尝试首投）
pub async fn run_consumer<S, H>(
    mut stream: MessageStream,
    idempotency: Arc<S>,
    dlx: Box<DynDeadLetterStore<'static>>,
    meta: ConsumerMeta,
    handler: H,
) where
    S: consistency::idempotency::IdempotencyStore + Send + Sync + 'static,
    H: Fn(Message) -> futures::future::BoxFuture<'static, HandleResult> + Send + Sync,
{
    while let Some(msg) = stream.next().await {
        consume_one(&idempotency, &dlx, &meta, &handler, msg).await;
    }
}

/// 处理单条消息：parse key → check → handle_fresh 或幂等短路。
/// 从 `run_consumer` 抽出，控制各自认知复杂度 ≤15（rust-standards §工程护栏）。
async fn consume_one<S, H>(
    idempotency: &Arc<S>,
    dlx: &DynDeadLetterStore<'static>,
    meta: &ConsumerMeta,
    handler: &H,
    msg: Message,
) where
    S: consistency::idempotency::IdempotencyStore + Send + Sync + 'static,
    H: Fn(Message) -> futures::future::BoxFuture<'static, HandleResult> + Send + Sync,
{
    // parse 失败 → 结构化 warn + 丢弃（不 panic；key 漂移即等价新消费者，fail-closed）。
    let key = match IdemKey::parse(msg.id.as_str()) {
        Ok(k) => k,
        Err(_) => {
            log_parse_failed(&msg);
            return;
        }
    };

    // 日志收口到 helper 控制本函数认知复杂度 ≤15（tracing 宏展开计入复杂度，同 lib.rs::dispatch_one 范式）。
    match idempotency.check(&key).await {
        // 瞬态后端故障：结构化 warn，不 commit（下次重投）。
        Err(e) => log_check_failed(&msg, &e),
        // 幂等短路：不调 handler、不 commit。
        Ok(SeenState::Duplicate) => log_duplicate(&msg, meta),
        Ok(SeenState::Fresh) => handle_fresh(idempotency, dlx, meta, handler, msg, &key).await,
        // reason: SeenState 是 #[non_exhaustive]，兜底臂保守丢弃（对齐 relay.rs 非 Ack 处置保守降级）。
        Ok(_) => log_unknown_seen_state(&msg),
    }
}

/// 首见消息：bounded 重投循环 → `Ack` commit / `Reject` dlx / `Requeue` 耗尽后 dlx。
/// 从 `consume_one` 抽出，控制各自认知复杂度 ≤15（rust-standards §工程护栏）。
async fn handle_fresh<S, H>(
    idempotency: &Arc<S>,
    dlx: &DynDeadLetterStore<'static>,
    meta: &ConsumerMeta,
    handler: &H,
    msg: Message,
    key: &IdemKey,
) where
    S: consistency::idempotency::IdempotencyStore + Send + Sync + 'static,
    H: Fn(Message) -> futures::future::BoxFuture<'static, HandleResult> + Send + Sync,
{
    // requeue 路径记下最近一次 error kind 摘要，耗尽时随 DLX 落日志（#1125）。
    let mut last_requeue_summary: Option<&'static str> = None;
    // 含首投在内至多 MAX_REDELIVERY 次（bounded，对齐 watermill retry.go MaxRetries+1 次尝试）。
    for attempt in 1..=MAX_REDELIVERY {
        let result = handler(msg.clone()).await;
        match result.disposition() {
            consistency::outbox::Disposition::Ack => {
                commit_key(idempotency, key, msg.id.as_str()).await;
                return;
            }
            consistency::outbox::Disposition::Reject => {
                dead_letter(
                    dlx,
                    idempotency,
                    key,
                    meta,
                    &msg,
                    attempt,
                    // reject 构造器恒携 Some(kind 摘要，#1125)；unwrap_or 是对 `None` 的防御
                    // （类型层 ack 形 None），非死代码——正常路径取真实 error kind 摘要。
                    result
                        .error_summary()
                        .unwrap_or(SUMMARY_PERMANENT_REJECTION),
                )
                .await;
                return;
            }
            consistency::outbox::Disposition::Requeue => {
                // 记下本轮 requeue 的 error kind 摘要；耗尽时随 DLX 落日志（#1125）。
                last_requeue_summary = result.error_summary();
            }
            // reason: Disposition 是 #[non_exhaustive]，未知变体保守 continue（非终态，对齐 Requeue 的循环
            // 续命，防误判终态后进 DLX）；但**不** set last_requeue_summary，故耗尽时摘要走
            // SUMMARY_REQUEUE_EXHAUSTED fallback（无 kind 摘要可取）。
            _ => {}
        }
    }
    // Requeue 预算耗尽 → DLX（num_attempts = MAX_REDELIVERY 次全部尝试）。
    dead_letter(
        dlx,
        idempotency,
        key,
        meta,
        &msg,
        MAX_REDELIVERY,
        // 正常 requeue 路径恒 Some(kind 摘要)；unwrap_or 仅防御未来未知 Disposition 变体经 `_ => {}`
        // 未 set 摘要时的 `None`（非死代码，见 SUMMARY_REQUEUE_EXHAUSTED 注释）。
        last_requeue_summary.unwrap_or(SUMMARY_REQUEUE_EXHAUSTED),
    )
    .await;
}

/// commit key（claimed→done）：错误结构化 error 日志（不 panic）。
async fn commit_key<S>(idempotency: &Arc<S>, key: &IdemKey, message_id: &str)
where
    S: consistency::idempotency::IdempotencyStore + Send + Sync + 'static,
{
    if let Err(e) = idempotency.commit(key).await {
        tracing::error!(
            message_id,
            error = %e,
            "consumer: idempotency commit failed"
        );
    }
}

/// release key（claimed→absent）：dlx 写失败时调用，使 broker 重投时 check 回 Fresh。
/// 错误结构化 error 日志（不 panic）。
async fn release_key<S>(idempotency: &Arc<S>, key: &IdemKey, message_id: &str)
where
    S: consistency::idempotency::IdempotencyStore + Send + Sync + 'static,
{
    if let Err(e) = idempotency.release(key).await {
        tracing::error!(
            message_id,
            error = %e,
            "consumer: idempotency release failed after dlx write error"
        );
    }
}

/// 死信路径：
/// 1. 结构化 `error!`（T007.5：domain/contract_id/topic/num_attempts/error_summary 五字段，含 message_id）。
/// 2. `dlx.write_dead_letter(record)`。
/// 3. dlx **写成功** → `idempotency.commit(key)`（标记 done，终态收口）；
///    dlx **写失败** → `idempotency.release(key)`（claimed→absent，使 broker 重投时 check 回 Fresh、
///    重新尝试 DLX），避免静默丢失（消息永久消失 + 死信未落 DB）。
///
/// 各步错误结构化 error 日志（不 panic）。
///
/// `error_summary` 是安全摘要：`&'static str` const（来自 handler 的 error kind message，经
/// `HandleResult::error_summary()` 流到此处，#1125），不含 handler error/payload 原文。PII-safe（const
/// literal，无 runtime 数据），下游 `DeadLetterSummary::new` 仍强制 const 收口。
async fn dead_letter<S>(
    dlx: &DynDeadLetterStore<'static>,
    idempotency: &Arc<S>,
    key: &IdemKey,
    meta: &ConsumerMeta,
    msg: &Message,
    num_attempts: u32,
    error_summary: &'static str,
) where
    S: consistency::idempotency::IdempotencyStore + Send + Sync + 'static,
{
    // T007.5：结构化 error，五字段全部出现（domain/contract_id/topic/num_attempts/error_summary）；
    // message_id 额外提供关联维度（DLX 表无该列，log 是唯一关联路径）。
    // 日志收口到 helper 控制本函数认知复杂度 ≤15（tracing 宏展开计入复杂度，同 lib.rs 范式）。
    log_dead_lettered(meta, num_attempts, error_summary, msg.id.as_str());

    let record = DeadLetterRecord::new(
        meta.domain(),
        meta.contract_id(),
        meta.topic(),
        msg.payload.clone(),
        // 类型层收口：摘要只能是编译期 const literal（SUMMARY_* 常量），不可由 runtime 数据伪造
        // （review #216 F7，INVARIANT DIPORT-DLX-SUMMARY-STATIC-01）。
        DeadLetterSummary::new(error_summary),
        num_attempts,
    );

    match dlx.write_dead_letter(record).await {
        Ok(()) => {
            // dlx 写成功 → commit（标记 done，终态收口，ack 原消息语义）。
            commit_key(idempotency, key, msg.id.as_str()).await;
        }
        Err(e) => {
            // dlx 写失败 → release（claimed→absent），使 broker 重投时 check 回 Fresh、
            // 重新尝试 DLX，避免静默丢失（消息进 done + 死信未落 DB = 不可恢复审计盲点）。
            log_dlx_write_failed(meta, &e);
            release_key(idempotency, key, msg.id.as_str()).await;
        }
    }
}

// ── 日志 helper（tracing 宏收口，控制调用方认知复杂度 ≤15；同 lib.rs::log_dropped_* 范式）──

/// IdemKey parse 失败（key 漂移 fail-closed 丢弃）。
fn log_parse_failed(msg: &Message) {
    tracing::warn!(
        message_id = msg.id.as_str(),
        "consumer: IdemKey parse failed, message dropped"
    );
}

/// 幂等 check 瞬态后端故障（不 commit，下次重投）。
///
/// `error = %error` 安全前提：`consistency::EngineError` 的 `Display` 实现恒为 const literal
/// （不携 runtime 数据，见 `consistency::error` invariant）。若未来 `EngineError` 新增携
/// runtime 数据的变体，此处须改走 `secure::redact_error` funnel。
fn log_check_failed(msg: &Message, error: &consistency::error::EngineError) {
    tracing::warn!(
        message_id = msg.id.as_str(),
        error = %error,
        "consumer: idempotency check failed, will retry on next delivery"
    );
}

/// 幂等短路（已见，跳过）。
fn log_duplicate(msg: &Message, meta: &ConsumerMeta) {
    tracing::debug!(
        message_id = msg.id.as_str(),
        domain = meta.domain(),
        contract_id = meta.contract_id(),
        topic = meta.topic(),
        "consumer: duplicate message, skipping"
    );
}

/// 未知 `SeenState` 变体（#[non_exhaustive] 兜底保守丢弃）。
fn log_unknown_seen_state(msg: &Message) {
    tracing::warn!(
        message_id = msg.id.as_str(),
        "consumer: unknown SeenState variant, message dropped"
    );
}

/// T007.5：死信结构化 error（五字段：domain/contract_id/topic/num_attempts/error_summary；
/// 加 message_id 提供关联维度——DLX 表无该列，log 是唯一关联路径）。
fn log_dead_lettered(
    meta: &ConsumerMeta,
    num_attempts: u32,
    error_summary: &'static str,
    message_id: &str,
) {
    tracing::error!(
        message_id,
        domain = meta.domain(),
        contract_id = meta.contract_id(),
        topic = meta.topic(),
        num_attempts,
        error_summary,
        "consumer: message dead-lettered"
    );
}

/// DLX 写入失败（结构化 error，原始错误经 Display 安全摘要）。
fn log_dlx_write_failed(meta: &ConsumerMeta, error: &DeadLetterStoreError) {
    tracing::error!(
        domain = meta.domain(),
        contract_id = meta.contract_id(),
        topic = meta.topic(),
        error = %error,
        "consumer: dead letter write failed"
    );
}

// ── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};

    use consistency::HandleResult;
    use consistency::idempotency::{IdemKey, IdempotencyStore, SeenState};
    use diport::Message;
    use diport::dead_letter_store::{
        DeadLetterRecord, DeadLetterStore, DeadLetterStoreError, DynDeadLetterStore,
    };

    use super::{ConsumerMeta, run_consumer};
    use crate::MAX_REDELIVERY;

    // ── 工厂 helper ──────────────────────────────────────────────────────────

    /// 构造单条消息流（复用 lib.rs 范式）。
    fn stream_of(payloads: &[(&str, &[u8])]) -> diport::MessageStream {
        let msgs: Vec<Message> = payloads
            .iter()
            .map(|(id, p)| Message::new(*id, p.to_vec()))
            .collect();
        Box::pin(futures::stream::iter(msgs))
    }

    fn meta() -> ConsumerMeta {
        ConsumerMeta::new("identity", "contract-session", "session.created")
    }

    // ── FakeIdempotencyStore ─────────────────────────────────────────────────

    /// 三态 fake store（Arc<Mutex> + Atomic，Send 友好，不跨 await 持锁——relay.rs FakeStore 范式）。
    /// 可配 check 返 Fresh / Duplicate / Err；记录 commit / release / check 调用计数。
    enum CheckResult {
        Fresh,
        Duplicate,
        Err,
    }

    struct FakeIdempotencyStore {
        check_result: CheckResult,
        check_count: AtomicU32,
        commit_count: AtomicU32,
        release_count: AtomicU32,
    }

    impl FakeIdempotencyStore {
        fn fresh() -> Arc<Self> {
            Arc::new(Self {
                check_result: CheckResult::Fresh,
                check_count: AtomicU32::new(0),
                commit_count: AtomicU32::new(0),
                release_count: AtomicU32::new(0),
            })
        }

        fn duplicate() -> Arc<Self> {
            Arc::new(Self {
                check_result: CheckResult::Duplicate,
                check_count: AtomicU32::new(0),
                commit_count: AtomicU32::new(0),
                release_count: AtomicU32::new(0),
            })
        }

        fn err() -> Arc<Self> {
            Arc::new(Self {
                check_result: CheckResult::Err,
                check_count: AtomicU32::new(0),
                commit_count: AtomicU32::new(0),
                release_count: AtomicU32::new(0),
            })
        }

        #[allow(dead_code)]
        // reason: check_count 供需断言 check 调用次数的测试预留；当前 TC6/TC7 只核 commit/release，item-level carve-out。
        fn check_count(&self) -> u32 {
            self.check_count.load(Ordering::Acquire)
        }

        fn commit_count(&self) -> u32 {
            self.commit_count.load(Ordering::Acquire)
        }

        fn release_count(&self) -> u32 {
            self.release_count.load(Ordering::Acquire)
        }
    }

    impl IdempotencyStore for FakeIdempotencyStore {
        async fn check(
            &self,
            _key: &IdemKey,
        ) -> Result<SeenState, consistency::error::EngineError> {
            self.check_count.fetch_add(1, Ordering::Release);
            match self.check_result {
                CheckResult::Fresh => Ok(SeenState::Fresh),
                CheckResult::Duplicate => Ok(SeenState::Duplicate),
                CheckResult::Err => Err(consistency::error::EngineError::new(
                    consistency::error::EngineErrorKind::Transient,
                )),
            }
        }

        async fn commit(&self, _key: &IdemKey) -> Result<(), consistency::error::EngineError> {
            self.commit_count.fetch_add(1, Ordering::Release);
            Ok(())
        }

        async fn release(&self, _key: &IdemKey) -> Result<(), consistency::error::EngineError> {
            self.release_count.fetch_add(1, Ordering::Release);
            Ok(())
        }
    }

    // ── FakeDeadLetterStore ──────────────────────────────────────────────────

    /// fake DLX store：捕获写入的 DeadLetterRecord 字段。
    struct FakeDeadLetterStore {
        written: Mutex<Vec<(String, u32)>>, // (error_summary, num_attempts)
    }

    impl FakeDeadLetterStore {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                written: Mutex::new(vec![]),
            })
        }

        fn write_count(&self) -> usize {
            #[allow(clippy::unwrap_used)]
            // reason: 测试 happy-path，item-level carve-out
            self.written.lock().unwrap().len()
        }

        fn last_record(&self) -> Option<(String, u32)> {
            #[allow(clippy::unwrap_used)]
            // reason: 测试 happy-path，item-level carve-out
            self.written.lock().unwrap().last().cloned()
        }
    }

    impl DeadLetterStore for FakeDeadLetterStore {
        async fn write_dead_letter(
            &self,
            record: DeadLetterRecord,
        ) -> Result<(), DeadLetterStoreError> {
            #[allow(clippy::unwrap_used)]
            // reason: 测试 happy-path，item-level carve-out
            self.written
                .lock()
                .unwrap()
                .push((record.error_summary().to_string(), record.num_attempts()));
            Ok(())
        }

        async fn shutdown(&self) -> Result<(), DeadLetterStoreError> {
            Ok(())
        }
    }

    /// fake DLX store（恒写失败版）：write_dead_letter 总返回 Err。
    struct AlwaysErrDeadLetterStore {
        write_count: AtomicU32,
    }

    impl AlwaysErrDeadLetterStore {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                write_count: AtomicU32::new(0),
            })
        }

        fn write_count(&self) -> u32 {
            self.write_count.load(Ordering::Acquire)
        }
    }

    impl DeadLetterStore for AlwaysErrDeadLetterStore {
        async fn write_dead_letter(
            &self,
            _record: DeadLetterRecord,
        ) -> Result<(), DeadLetterStoreError> {
            self.write_count.fetch_add(1, Ordering::Release);
            Err(DeadLetterStoreError::new(std::io::Error::other(
                "dlx write always fails",
            )))
        }

        async fn shutdown(&self) -> Result<(), DeadLetterStoreError> {
            Ok(())
        }
    }

    /// 构造 DynDeadLetterStore box（注入 always-err fake store）。
    fn fake_dlx_always_err(
        store: Arc<AlwaysErrDeadLetterStore>,
    ) -> Box<DynDeadLetterStore<'static>> {
        struct ArcProxy(Arc<AlwaysErrDeadLetterStore>);
        impl DeadLetterStore for ArcProxy {
            async fn write_dead_letter(
                &self,
                record: DeadLetterRecord,
            ) -> Result<(), DeadLetterStoreError> {
                self.0.write_dead_letter(record).await
            }
            async fn shutdown(&self) -> Result<(), DeadLetterStoreError> {
                Ok(())
            }
        }
        DynDeadLetterStore::new_box(ArcProxy(store))
    }

    /// 构造 DynDeadLetterStore box（注入 fake store）。
    fn fake_dlx(store: Arc<FakeDeadLetterStore>) -> Box<DynDeadLetterStore<'static>> {
        // FakeDeadLetterStore impl DeadLetterStore（Send 变体），可经 DynDeadLetterStore::new_box 装箱。
        // Arc 实现 DeadLetterStore 需要 Arc<T>: DeadLetterStore；用包装 struct 代理。
        struct ArcProxy(Arc<FakeDeadLetterStore>);
        impl DeadLetterStore for ArcProxy {
            async fn write_dead_letter(
                &self,
                record: DeadLetterRecord,
            ) -> Result<(), DeadLetterStoreError> {
                self.0.write_dead_letter(record).await
            }
            async fn shutdown(&self) -> Result<(), DeadLetterStoreError> {
                Ok(())
            }
        }
        DynDeadLetterStore::new_box(ArcProxy(store))
    }

    // ── handler 工厂 ─────────────────────────────────────────────────────────

    /// 恒 Ack handler（计数调用次数）。
    fn handler_ack(
        counter: Arc<AtomicU32>,
    ) -> impl Fn(Message) -> futures::future::BoxFuture<'static, HandleResult> + Send + Sync {
        move |_msg| {
            let counter = counter.clone();
            Box::pin(async move {
                counter.fetch_add(1, Ordering::Relaxed);
                HandleResult::ack()
            })
        }
    }

    /// 恒 Requeue handler（计数调用次数）。
    fn handler_requeue(
        counter: Arc<AtomicU32>,
    ) -> impl Fn(Message) -> futures::future::BoxFuture<'static, HandleResult> + Send + Sync {
        move |_msg| {
            let counter = counter.clone();
            Box::pin(async move {
                counter.fetch_add(1, Ordering::Relaxed);
                HandleResult::requeue(consistency::error::EngineError::new(
                    consistency::error::EngineErrorKind::Transient,
                ))
            })
        }
    }

    /// 恒 Reject handler（计数调用次数）。
    fn handler_reject(
        counter: Arc<AtomicU32>,
    ) -> impl Fn(Message) -> futures::future::BoxFuture<'static, HandleResult> + Send + Sync {
        move |_msg| {
            let counter = counter.clone();
            Box::pin(async move {
                counter.fetch_add(1, Ordering::Relaxed);
                HandleResult::reject(consistency::outbox::PermanentError::new(
                    consistency::outbox::PermanentErrorKind::Permanent,
                ))
            })
        }
    }

    /// 恒 Reject handler（`Invariant` kind；用于核 error kind 摘要随 HandleResult 流到 DLX，#1125）。
    fn handler_reject_invariant(
        counter: Arc<AtomicU32>,
    ) -> impl Fn(Message) -> futures::future::BoxFuture<'static, HandleResult> + Send + Sync {
        move |_msg| {
            let counter = counter.clone();
            Box::pin(async move {
                counter.fetch_add(1, Ordering::Relaxed);
                HandleResult::reject(consistency::outbox::PermanentError::new(
                    consistency::outbox::PermanentErrorKind::Invariant,
                ))
            })
        }
    }

    // ── TC1：handler 恒 Ack ──────────────────────────────────────────────────

    /// TC1：handler 恒 Ack → handler 调 1 次、commit 1 次、无 dlx 写。
    #[tokio::test]
    async fn tc1_handler_ack_commit_once_no_dlx() {
        let idem = FakeIdempotencyStore::fresh();
        let dlx_store = FakeDeadLetterStore::new();
        let dlx = fake_dlx(dlx_store.clone());
        let handler_count = Arc::new(AtomicU32::new(0));

        run_consumer(
            stream_of(&[("msg-1", b"payload")]),
            idem.clone(),
            dlx,
            meta(),
            handler_ack(handler_count.clone()),
        )
        .await;

        assert_eq!(
            handler_count.load(Ordering::Relaxed),
            1,
            "handler 应调 1 次"
        );
        assert_eq!(idem.commit_count(), 1, "commit 应调 1 次");
        assert_eq!(dlx_store.write_count(), 0, "无 dlx 写");
    }

    // ── TC2：handler 恒 Requeue ──────────────────────────────────────────────

    /// TC2：handler 恒 Requeue → handler 调 MAX_REDELIVERY 次、dlx 写 1 次（exhausted）、commit 1 次。
    #[tokio::test]
    async fn tc2_handler_requeue_exhausted_dlx() {
        let idem = FakeIdempotencyStore::fresh();
        let dlx_store = FakeDeadLetterStore::new();
        let dlx = fake_dlx(dlx_store.clone());
        let handler_count = Arc::new(AtomicU32::new(0));

        run_consumer(
            stream_of(&[("msg-requeue", b"payload")]),
            idem.clone(),
            dlx,
            meta(),
            handler_requeue(handler_count.clone()),
        )
        .await;

        assert_eq!(
            handler_count.load(Ordering::Relaxed),
            MAX_REDELIVERY,
            "handler 应调 MAX_REDELIVERY 次"
        );
        assert_eq!(dlx_store.write_count(), 1, "dlx 应写 1 次");
        #[allow(clippy::unwrap_used)]
        // reason: 测试断言前置 assert_eq 已验证 write_count==1，last_record 必然 Some；item-level carve-out。
        let (summary, attempts) = dlx_store.last_record().unwrap();
        // #1125：requeue 耗尽后 DLX 摘要反映 handler 的 EngineError kind（Transient），
        // 而非旧通用常量 "requeue budget exhausted"。
        assert_eq!(
            summary, "transient engine error",
            "summary 应为 requeue kind 的 const message: {summary}"
        );
        assert_eq!(
            attempts, MAX_REDELIVERY,
            "num_attempts 应 == MAX_REDELIVERY"
        );
        assert_eq!(idem.commit_count(), 1, "commit 应调 1 次（dlx 终态收口）");
    }

    // ── TC3：handler 恒 Reject ───────────────────────────────────────────────

    /// TC3：handler 恒 Reject → handler 调 1 次、dlx 写 1 次（permanent rejection）、commit 1 次。
    #[tokio::test]
    async fn tc3_handler_reject_dlx_once() {
        let idem = FakeIdempotencyStore::fresh();
        let dlx_store = FakeDeadLetterStore::new();
        let dlx = fake_dlx(dlx_store.clone());
        let handler_count = Arc::new(AtomicU32::new(0));

        run_consumer(
            stream_of(&[("msg-reject", b"payload")]),
            idem.clone(),
            dlx,
            meta(),
            handler_reject(handler_count.clone()),
        )
        .await;

        assert_eq!(
            handler_count.load(Ordering::Relaxed),
            1,
            "handler 应调 1 次"
        );
        assert_eq!(dlx_store.write_count(), 1, "dlx 应写 1 次");
        #[allow(clippy::unwrap_used)]
        // reason: 测试断言前置 assert_eq 已验证 write_count==1，last_record 必然 Some；item-level carve-out。
        let (summary, _attempts) = dlx_store.last_record().unwrap();
        // #1125：DLX 摘要为 handler 的 PermanentError kind（Permanent）const message，
        // 而非旧通用常量 "permanent rejection"。
        assert_eq!(
            summary, "permanent error",
            "summary 应为 reject kind 的 const message: {summary}"
        );
        assert_eq!(idem.commit_count(), 1, "commit 应调 1 次");
    }

    // ── TC9：reject(Invariant) → DLX 摘要反映 Invariant kind（#1125 anti-vacuity）──

    /// TC9：handler reject(Invariant) → DLX 摘要 == "invariant violated"（≠ TC3 的 "permanent error"），
    /// 证 error kind 真实随 HandleResult 流到 DLX（摘要非硬编码、随 kind 变化）。
    #[tokio::test]
    async fn tc9_reject_invariant_surfaces_kind_summary() {
        let idem = FakeIdempotencyStore::fresh();
        let dlx_store = FakeDeadLetterStore::new();
        let dlx = fake_dlx(dlx_store.clone());
        let handler_count = Arc::new(AtomicU32::new(0));

        run_consumer(
            stream_of(&[("msg-reject-inv", b"payload")]),
            idem.clone(),
            dlx,
            meta(),
            handler_reject_invariant(handler_count.clone()),
        )
        .await;

        assert_eq!(dlx_store.write_count(), 1, "dlx 应写 1 次");
        #[allow(clippy::unwrap_used)]
        // reason: 前置 assert_eq 已验证 write_count==1，last_record 必然 Some；item-level carve-out。
        let (summary, _attempts) = dlx_store.last_record().unwrap();
        assert_eq!(
            summary, "invariant violated",
            "Invariant kind 摘要应为 'invariant violated'（随 kind 变化，非硬编码）: {summary}"
        );
    }

    // ── TC4：check 返 Duplicate ──────────────────────────────────────────────

    /// TC4：check 返 Duplicate → handler 0 次、commit 0 次、dlx 0 次。
    #[tokio::test]
    async fn tc4_duplicate_skips_handler_and_commit() {
        let idem = FakeIdempotencyStore::duplicate();
        let dlx_store = FakeDeadLetterStore::new();
        let dlx = fake_dlx(dlx_store.clone());
        let handler_count = Arc::new(AtomicU32::new(0));

        run_consumer(
            stream_of(&[("msg-dup", b"payload")]),
            idem.clone(),
            dlx,
            meta(),
            handler_ack(handler_count.clone()),
        )
        .await;

        assert_eq!(handler_count.load(Ordering::Relaxed), 0, "handler 应 0 次");
        assert_eq!(idem.commit_count(), 0, "commit 应 0 次");
        assert_eq!(dlx_store.write_count(), 0, "dlx 应 0 次");
    }

    // ── TC6：check 返 Err ────────────────────────────────────────────────────

    /// TC6：check 返 Err（瞬态后端故障）→ handler 0 次、commit 0 次、dlx 0 次（不做任何终态动作）。
    #[tokio::test]
    async fn tc6_check_err_skips_handler_and_commit() {
        let idem = FakeIdempotencyStore::err();
        let dlx_store = FakeDeadLetterStore::new();
        let dlx = fake_dlx(dlx_store.clone());
        let handler_count = Arc::new(AtomicU32::new(0));

        run_consumer(
            stream_of(&[("msg-check-err", b"payload")]),
            idem.clone(),
            dlx,
            meta(),
            handler_ack(handler_count.clone()),
        )
        .await;

        assert_eq!(
            handler_count.load(Ordering::Relaxed),
            0,
            "check Err 时 handler 应 0 次"
        );
        assert_eq!(idem.commit_count(), 0, "check Err 时 commit 应 0 次");
        assert_eq!(dlx_store.write_count(), 0, "check Err 时 dlx 应 0 次");
    }

    // ── TC7：IdemKey parse 失败 ──────────────────────────────────────────────

    /// TC7：IdemKey parse 失败（空 id）→ handler 0 次、commit 0 次、dlx 0 次（fail-closed 丢弃）。
    #[tokio::test]
    async fn tc7_parse_failed_drops_message() {
        let idem = FakeIdempotencyStore::fresh();
        let dlx_store = FakeDeadLetterStore::new();
        let dlx = fake_dlx(dlx_store.clone());
        let handler_count = Arc::new(AtomicU32::new(0));

        // 空 id → IdemKey::parse 失败
        run_consumer(
            stream_of(&[("", b"payload")]),
            idem.clone(),
            dlx,
            meta(),
            handler_ack(handler_count.clone()),
        )
        .await;

        assert_eq!(
            handler_count.load(Ordering::Relaxed),
            0,
            "parse 失败时 handler 应 0 次"
        );
        assert_eq!(idem.commit_count(), 0, "parse 失败时 commit 应 0 次");
        assert_eq!(dlx_store.write_count(), 0, "parse 失败时 dlx 应 0 次");
    }

    // ── TC8：DLX 写失败 → release 而非 commit ───────────────────────────────

    /// TC8：handler reject + DLX 写总失败 → commit 0 次、release 1 次、dlx write 尝试 1 次。
    /// 守住「静默丢失」修复语义：DLX 写失败后 release（而非 commit），使 broker 可重投重试 DLX。
    #[tokio::test]
    async fn tc8_dlx_write_fails_releases_key() {
        let idem = FakeIdempotencyStore::fresh();
        let dlx_store = AlwaysErrDeadLetterStore::new();
        let dlx = fake_dlx_always_err(dlx_store.clone());
        let handler_count = Arc::new(AtomicU32::new(0));

        run_consumer(
            stream_of(&[("msg-dlx-fail", b"payload")]),
            idem.clone(),
            dlx,
            meta(),
            handler_reject(handler_count.clone()),
        )
        .await;

        assert_eq!(
            handler_count.load(Ordering::Relaxed),
            1,
            "reject handler 应调 1 次"
        );
        assert_eq!(dlx_store.write_count(), 1, "dlx write 应尝试 1 次");
        assert_eq!(idem.commit_count(), 0, "dlx 写失败时 commit 应 0 次");
        assert_eq!(idem.release_count(), 1, "dlx 写失败时 release 应 1 次");
    }

    // ── TC5：T007.5 tracing 字段断言 ────────────────────────────────────────

    /// TC5（T007.5）：reject 触发 DLX 时，tracing error! 必须含六字段：
    /// domain / contract_id / topic / num_attempts / error_summary / message_id。
    /// 且字段值不含 payload 字节原文（anti-PII）。
    ///
    /// anti-vacuity 加固：
    /// - 使用唯一 meta（domain="tc5-domain"），与 TC2/TC3 的 "identity" 区分，
    ///   防并发写入污染聚合导致「六字段存在」断言恒真。
    /// - CapVisit 捕获 per-event 字段 map（Vec<HashMap<String,String>>），
    ///   每个 ERROR 事件一条，断言「存在某条 event 其 domain=="tc5-domain" 且含全部六字段」。
    ///
    /// 实现：自定义轻量 `tracing::Subscriber` + `block_on`，set_global_default 消除
    /// callsite interest cache 导致的 flake（nextest 每测试独立进程；cargo test 单进程仅此设全局）。
    #[test]
    fn tc5_dlx_tracing_fields_and_no_payload_leak() {
        use std::collections::HashMap;
        use std::sync::atomic::AtomicBool;
        use tracing::field::{Field, Visit};
        use tracing::{Event, Id, Metadata, span};

        // 每个 ERROR 事件捕获为独立 HashMap<fieldname, value>。
        struct Captured {
            events: Mutex<Vec<HashMap<String, String>>>,
        }

        impl Captured {
            fn new() -> Arc<Self> {
                Arc::new(Self {
                    events: Mutex::new(vec![]),
                })
            }
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

            fn record_u64(&mut self, field: &Field, value: u64) {
                self.current
                    .insert(field.name().to_string(), value.to_string());
            }

            fn record_i64(&mut self, field: &Field, value: i64) {
                self.current
                    .insert(field.name().to_string(), value.to_string());
            }
        }

        // 极简 Subscriber——只捕获 ERROR 事件，其余方法 noop。
        struct CapSubscriber {
            captured: Arc<Captured>,
            enabled: AtomicBool,
        }

        impl tracing::Subscriber for CapSubscriber {
            fn enabled(&self, meta: &Metadata<'_>) -> bool {
                let _ = meta;
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
                let _ = self.enabled.load(Ordering::Relaxed);
                let mut visitor = CapVisit {
                    current: HashMap::new(),
                };
                event.record(&mut visitor);
                #[allow(clippy::unwrap_used)]
                // reason: 测试 Mutex，item-level carve-out
                self.captured.events.lock().unwrap().push(visitor.current);
            }
        }

        let captured = Captured::new();
        let subscriber = CapSubscriber {
            captured: captured.clone(),
            enabled: AtomicBool::new(true),
        };

        // set_global_default 消除 callsite interest cache flake（与旧 TC5 同理，见旧注释）。
        let _ = tracing::subscriber::set_global_default(subscriber);
        #[allow(clippy::unwrap_used)]
        // reason: 测试 runtime 构造，item-level carve-out
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let idem = FakeIdempotencyStore::fresh();
            let dlx_store = FakeDeadLetterStore::new();
            let dlx = fake_dlx(dlx_store.clone());
            let handler_count = Arc::new(AtomicU32::new(0));

            // 唯一 meta（domain="tc5-domain"），与 TC2/TC3 "identity" 区分——anti-vacuity 核心。
            let tc5_meta = ConsumerMeta::new("tc5-domain", "tc5-contract", "tc5-topic");
            let payload = b"SENSITIVE_PAYLOAD_BYTES";
            run_consumer(
                stream_of(&[("msg-t007-tc5", payload.as_ref())]),
                idem,
                dlx,
                tc5_meta,
                handler_reject(handler_count),
            )
            .await;
        });

        // 找到 domain=="tc5-domain" 的 event（排除并发 TC2/TC3 的 "identity" 污染）。
        #[allow(clippy::unwrap_used)]
        // reason: 测试断言，item-level carve-out
        let events = captured.events.lock().unwrap();
        let tc5_event = events
            .iter()
            .find(|ev| ev.get("domain").map(|d| d == "tc5-domain").unwrap_or(false));
        assert!(
            tc5_event.is_some(),
            "未找到 domain==tc5-domain 的 ERROR event；捕获的全部 events: {events:?}"
        );
        #[allow(clippy::unwrap_used)]
        // reason: 上方 assert! 已确保 Some，item-level carve-out
        let ev = tc5_event.unwrap();

        // 断言六字段全部出现（含新增 message_id）。
        let required = [
            "domain",
            "contract_id",
            "topic",
            "num_attempts",
            "error_summary",
            "message_id",
        ];
        for field in &required {
            assert!(
                ev.contains_key(*field),
                "tracing error! 缺字段 {field}；tc5 event 字段集: {ev:?}"
            );
        }

        // 断言 event 字段值不含 payload 原文。
        let all_values: String = ev.values().cloned().collect::<Vec<_>>().join(" ");
        assert!(
            !all_values.contains("SENSITIVE_PAYLOAD_BYTES"),
            "字段值不得含 payload 原文: {all_values}"
        );
    }
}
