//! 命令分发 runtime —— sealed funnel：命令 topic outbox emit + 幂等消费（P12，#1124）。
//!
//! **producer**：[`emit_async`] 是命令 topic [`Entry`] 的**唯一** sanctioned 构造点（seal [`DispatchId`] →
//! [`Entry::new`] → 注入的 [`DynOutboxEmitter`]）。generated `<cmd>::emit_async` wrapper 经组合根 bridge
//! （impl `generated::command::CommandEmit`）委托至此；业务**不直调**本函数（无裸 emit 出口，
//! COMMAND-SYMMETRY-01 Medium 守）。consistencyLevel = OutboxFact（emit-only 单事实，无 co-tx）。
//!
//! **consumer**：[`register_command_handler`] 复用 [`run_consumer`] + [`IdempotencyStore`] claimer 两阶段
//! 去重（同 DispatchId 二次投递 → `Message.id` 同键 → `try_claim` 返 `Duplicate` → handler 不调、幂等短路 =
//! claimer 拒）；零新去重原语。
//!
//! INVARIANT: COMMAND-DISPATCHID-SEAL-01 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" }—— [`DispatchId`] 包私有 [`IdemKey`]、无 public 裸构造（仅
//! [`DispatchId::from_idempotency_key`] funnel），业务不可把任意裸 `IdemKey` 当 DispatchId 伪造。
//!
//! ref: debezium outbox SMT（producer 业务事实 → outbox 行 durable 落库）
//! ref: eventuate-tram-core io.eventuate.tram.consumer.common.DuplicateMessageDetector@master
//!      （message-id 作幂等键，对应命令 DispatchId 的 consumer 侧 claimer）

use std::sync::Arc;

use consistency::HandleResult;
use consistency::idempotency::{IdemKey, IdempotencyStore};
use consistency::outbox::{Entry, OutboxPayload, PermanentError, PermanentErrorKind, Topic};
use diport::dead_letter_store::DynDeadLetterStore;
use diport::{
    DynOutboxEmitter, EnvelopeSubjectId, Message, MessageStream, OutboxActor, OutboxEmitError,
    OutboxEmitter, OutboxEnvelopeParts,
};

use crate::consumer::{ConsumerMeta, LeaseConfig, run_consumer};
use crate::tenant_authority::TenantAuthority;

/// 命令幂等 key（DispatchId）—— producer mint、consumer claim 同源。包私有 [`IdemKey`]；无 public 裸构造，
/// 仅经 [`from_idempotency_key`](Self::from_idempotency_key) funnel（业务无法把任意裸 `IdemKey` 当 DispatchId
/// 伪造绕 generated wrapper）。auto-dispatch 由组合根 bridge 传 `Uuid::new_v4().to_string()`（同 identity 范式）。
///
/// INVARIANT: COMMAND-DISPATCHID-SEAL-01 { level = "Medium", exec = "manual/opt-in", source = "code" }.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchId(IdemKey);

impl DispatchId {
    /// 从稳定幂等 key 构造（拒空，fail-closed）。auto 场景由组合根传 fresh uuid 字符串。
    pub fn from_idempotency_key(raw: &str) -> Result<Self, CommandEmitError> {
        IdemKey::parse(raw)
            .map(Self)
            .map_err(|_| CommandEmitError::DispatchId)
    }

    /// 解封到底层 outbox 幂等 key（仅 runtime funnel 可达；consumer 侧 claimer 以同一 `IdemKey` try_claim）。
    ///
    /// INVARIANT: COMMAND-DISPATCHID-SEAL-01 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" }—— 此方法 `pub(crate)` 封闭，外部 crate 无法取得裸
    /// `IdemKey`（只有 [`emit_async`] funnel 可调用）；与 struct / module 级声明同源。
    pub(crate) fn into_idem_key(self) -> IdemKey {
        self.0
    }
}

/// 命令 emit 失败。`message` 为 const literal（PII 边界，同 [`OutboxEmitError`] 范式：不拼 runtime 数据）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CommandEmitError {
    /// 命令 topic 非 canonical dotted（routing key 形态非法）。
    #[error("command topic is not a canonical dotted name")]
    Topic,
    /// dispatch id 非法（空幂等 key）。
    #[error("command dispatch id is invalid")]
    DispatchId,
    /// 底层 durable outbox 发射失败（source 已经 [`OutboxEmitError`] 脱敏）。
    #[error("command outbox emit failed")]
    Emit(#[source] OutboxEmitError),
}

/// Runtime 命令 emit —— 命令 topic [`Entry`] 的**唯一** sanctioned 构造点。
///
/// mirror 事件 emit 路径：`Topic::parse`（命令 topic 构造收口于此）→ [`Entry::new`]（seal `DispatchId`）→
/// 注入的 [`DynOutboxEmitter`] port。`payload` 已编码（serde 在 generated wrapper / 组合根 bridge 侧；本
/// runtime serde-free 收 `Vec<u8>`）。`subject_id` 是 opaque 主体标识（无 PII，FR-020）。
#[allow(clippy::too_many_arguments)]
pub async fn emit_async(
    emitter: &DynOutboxEmitter<'_>,
    dispatch_id: DispatchId,
    topic: &str,
    contract: vocab::ContractBinding,
    tenant: vocab::TenantId,
    payload: Vec<u8>,
    subject_id: EnvelopeSubjectId,
    actor: OutboxActor,
) -> Result<(), CommandEmitError> {
    let parsed_topic = Topic::parse(topic).map_err(|_| CommandEmitError::Topic)?;
    let entry = Entry::new(
        parsed_topic,
        dispatch_id.into_idem_key(),
        OutboxPayload::from_reviewed_event_bytes(payload),
    );
    let envelope = OutboxEnvelopeParts::new(contract, tenant, subject_id, actor);
    emitter
        .emit(entry, envelope)
        .await
        .map_err(CommandEmitError::Emit)
        .map(|()| {
            // 结构化 debug：domain / contract_id / topic 归因（无 payload 字节、无 subject_id，PII 边界同 DLX log）。
            tracing::debug!(
                domain = contract.domain(),
                contract_id = contract.contract_id(),
                topic,
                "command: emit ok"
            );
        })
}

/// Runtime 命令消费注册 —— 复用 [`run_consumer`] 驱动 + [`IdempotencyStore`] claimer 两阶段去重。
///
/// 消息 `payload` 经 `serde_json` 解码为 typed `R` 后交 `handler`；解码失败 = 永久 `reject`（坏 wire 不可
/// 恢复 → DLX，不 Requeue 无限重投）。同 DispatchId（`Message.id` = dispatch key）二次投递 → claimer
/// `try_claim` 返 `Duplicate` → handler 不调、幂等短路（= claimer 拒）。claim→handle→commit/dlx 全复用
/// `run_consumer`，零新去重原语。`contract` 同时提供 contract id 与 expected schema fingerprint，命令路径
/// 与事件订阅路径共享同一 envelope header gate。
///
/// **生命周期接线（调用方必须遵守）**：本函数 `.await` 后进入无限消费循环（持续驱动 `stream`）；
/// 调用方**必须**将其 spawn 到组合根的 `ManagedResource` / `ShutdownStack` 可取消任务栈，以保证
/// 关闭信号能中断循环。直接 `.await` 会阻塞当前 task 且无法接收 shutdown，属组合根接线错误。
/// 组合根 spawn 接线（ManagedResource / ShutdownStack）随首个真实命令消费者落地。
///
/// 组合根 registrar（impl `generated::command::CommandRegister`）经 spawn 调用本 async 驱动；generated
/// `<cmd>::register_handler` wrapper 锁 typed `R` + baked CONTRACT_ID/TOPIC。
#[allow(clippy::too_many_arguments)]
// reason: 8 参数是命令消费注册的最小必要集（stream/idempotency/dlx/domain/contract_id/topic/handler/lease_cfg
// 各自语义独立）；聚合 struct 增间接层且无复用，item-level carve-out（error-handling.md §Carve-out）。
pub async fn register_command_handler<S, R, H, Fut>(
    stream: MessageStream,
    idempotency: Arc<S>,
    dlx: Box<DynDeadLetterStore<'static>>,
    domain: impl Into<String>,
    contract: vocab::ContractBinding,
    topic: impl Into<String>,
    consumer_group: impl Into<String>,
    tenant_authority: Arc<TenantAuthority>,
    handler: H,
    lease_cfg: LeaseConfig,
) where
    S: IdempotencyStore + Send + Sync + 'static,
    R: for<'de> serde::Deserialize<'de> + Send + 'static,
    H: Fn(R) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = HandleResult> + Send + 'static,
{
    let contract_id_s: Arc<str> = contract.contract_id().into();
    let topic_s: Arc<str> = topic.into().into();
    let meta = ConsumerMeta::new(
        domain.into(),
        topic_owner(&topic_s),
        &*contract_id_s,
        &*topic_s,
        consumer_group,
        tenant_authority,
    )
    .with_expected_schema(contract.version(), contract.schema_hash());
    let handler = Arc::new(handler);
    run_consumer(
        stream,
        idempotency,
        dlx,
        meta,
        move |msg: Message| {
            let handler = Arc::clone(&handler);
            let contract_id_s = Arc::clone(&contract_id_s);
            let topic_s = Arc::clone(&topic_s);
            Box::pin(async move {
                match serde_json::from_slice::<R>(msg.payload.as_bytes()) {
                    Ok(req) => handler(req).await,
                    Err(_) => {
                        // 坏 wire = 永久 reject（不可恢复 → DLX）；warn 记录解码失败原因（无 payload 字节，PII 边界）。
                        log_decode_failed(msg.id.as_str(), &contract_id_s, &topic_s);
                        HandleResult::reject(PermanentError::new(PermanentErrorKind::Permanent))
                    }
                }
            })
        },
        lease_cfg,
    )
    .await;
}

fn topic_owner(topic: &str) -> &str {
    topic.split('.').next().unwrap_or(topic)
}

/// 命令 payload 解码失败结构化 warn（contract_id/topic/message_id 归因；无 payload 字节，PII 边界同 DLX log）。
fn log_decode_failed(message_id: &str, contract_id: &str, topic: &str) {
    tracing::warn!(
        message_id,
        contract_id,
        topic,
        "command: payload decode failed, permanent reject to DLX"
    );
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};

    use consistency::HandleResult;
    use consistency::idempotency::{
        IdemKey, IdempotencyStore, LeaseOutcome, LeaseToken, SeenState,
    };
    use diport::dead_letter_store::{
        DeadLetterRecord, DeadLetterStore, DeadLetterStoreError, DynDeadLetterStore,
    };
    use diport::{
        DynOutboxEmitter, EnvelopeMetadata, EnvelopeSubjectId, KEY_SCHEMA_HASH, KEY_SCHEMA_VERSION,
        KEY_TENANT_AUTHORITY, KEY_TENANT_ID, Message, OpaqueActorId, OutboxActor, OutboxEmitError,
        OutboxEmitter, OutboxEnvelopeParts,
    };
    use primitives::{Mac, MacAlgorithm, MacKey, MacVerifier};

    use super::{DispatchId, LeaseConfig, emit_async, register_command_handler};
    use crate::MAX_REDELIVERY;
    use crate::TenantAuthority;
    use crate::tenant_authority::TenantAuthorityBinding;

    const HASH: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// 测试用 lease 配置（续租间隔大，命令消费测试中续租不触发）。
    fn lease_cfg() -> LeaseConfig {
        LeaseConfig::from_ttl(std::time::Duration::from_secs(60))
    }

    #[allow(clippy::expect_used)]
    fn tenant() -> vocab::TenantId {
        vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("tenant")
    }

    fn command_contract() -> vocab::ContractBinding {
        vocab::ContractBinding::from_static("seed", "seed.do-thing", "v1", HASH)
    }

    #[allow(clippy::expect_used)]
    fn subject(raw: &str) -> EnvelopeSubjectId {
        EnvelopeSubjectId::from_opaque(raw).expect("opaque subject")
    }

    #[allow(clippy::expect_used)]
    fn actor() -> OutboxActor {
        OutboxActor::service(OpaqueActorId::from_opaque("command-test-service").expect("actor"))
    }

    #[derive(Debug)]
    struct TestMac;

    impl MacVerifier for TestMac {
        fn sign(&self, key: &MacKey, _algorithm: MacAlgorithm, message: &[u8]) -> Mac {
            let mut tag = Vec::from(key.as_bytes());
            tag.extend_from_slice(message);
            Mac::from_bytes(tag)
        }

        fn verify(&self, key: &MacKey, algorithm: MacAlgorithm, message: &[u8], tag: &Mac) -> bool {
            self.sign(key, algorithm, message).as_bytes() == tag.as_bytes()
        }
    }

    #[allow(clippy::expect_used)]
    fn tenant_authority() -> Arc<TenantAuthority> {
        Arc::new(
            TenantAuthority::new(
                Arc::new(TestMac),
                MacKey::from_bytes(vec![0x42; 32]),
                60,
                5,
                Arc::new(|| 1_700_000_000),
            )
            .expect("valid tenant authority"),
        )
    }

    // ── producer 侧 fake：捕获 emit 的 Entry topic/idem_key/payload + envelope ──────

    struct CapturedEmit {
        topic: String,
        idem_key: String,
        payload: Vec<u8>,
        contract_id: String,
        tenant_id: String,
        actor_kind: String,
    }

    struct CapturingEmitter {
        captured: Mutex<Vec<CapturedEmit>>,
    }

    impl CapturingEmitter {
        fn new() -> Self {
            Self {
                captured: Mutex::new(Vec::new()),
            }
        }
    }

    impl OutboxEmitter for CapturingEmitter {
        async fn emit(
            &self,
            entry: consistency::Entry,
            envelope: OutboxEnvelopeParts,
        ) -> Result<(), diport::OutboxEmitError> {
            #[allow(clippy::unwrap_used)]
            // reason: 测试 Mutex happy-path，item-level carve-out
            self.captured.lock().unwrap().push(CapturedEmit {
                topic: entry.topic().as_str().to_string(),
                idem_key: entry.idem_key().as_str().to_string(),
                payload: entry.payload().to_vec(),
                contract_id: envelope.contract().contract_id().to_string(),
                tenant_id: envelope.tenant().to_string(),
                actor_kind: envelope
                    .actor()
                    .kind()
                    .as_actor_metadata_label()
                    .to_string(),
            });
            Ok(())
        }
    }

    /// emit_async：seal DispatchId → Entry::new（命令 topic）→ emitter.emit；直接对 fake 断言捕获的
    /// topic / idem_key / payload / contract_id 回显一致（runtime serde-free，payload 透传）。
    #[tokio::test]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    // reason: 测试 happy-path 断言，item-level carve-out
    async fn emit_async_captures_topic_key_payload() {
        let fake = std::sync::Arc::new(CapturingEmitter::new());
        // ArcProxy 让 Arc<CapturingEmitter> 可经 DynOutboxEmitter::new_box 装箱（同 consumer.rs fake_dlx 范式）。
        struct ArcProxy(std::sync::Arc<CapturingEmitter>);
        impl OutboxEmitter for ArcProxy {
            async fn emit(
                &self,
                entry: consistency::Entry,
                envelope: OutboxEnvelopeParts,
            ) -> Result<(), diport::OutboxEmitError> {
                self.0.emit(entry, envelope).await
            }
        }
        let emitter = DynOutboxEmitter::new_box(ArcProxy(fake.clone()));
        let dispatch = DispatchId::from_idempotency_key("dispatch-42").expect("non-empty key");
        emit_async(
            &emitter,
            dispatch,
            "seed.commands.do-thing",
            vocab::ContractBinding::from_static("seed", "seed.do-thing", "v1", HASH),
            tenant(),
            b"{\"amount\":7}".to_vec(),
            subject("subject-opaque"),
            actor(),
        )
        .await
        .expect("emit ok");

        #[allow(clippy::unwrap_used)]
        // reason: 测试断言，item-level carve-out
        let captured = fake.captured.lock().unwrap();
        assert_eq!(captured.len(), 1, "应 emit 1 条");
        let c = &captured[0];
        assert_eq!(c.topic, "seed.commands.do-thing", "命令 topic 回显");
        assert_eq!(c.idem_key, "dispatch-42", "DispatchId → IdemKey 回显");
        assert_eq!(
            c.payload, b"{\"amount\":7}",
            "payload 回显（runtime serde-free）"
        );
        assert_eq!(c.contract_id, "seed.do-thing", "envelope.contract_id 回显");
        assert_eq!(
            c.tenant_id, "f47ac10b-58cc-4372-a567-0e02b2c3d479",
            "envelope tenant 回显"
        );
        assert_eq!(c.actor_kind, "service", "actor kind 回显");
    }

    /// 非 canonical dotted topic → CommandEmitError::Topic（fail-closed，不构造 Entry）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    // reason: 测试 happy-path 构造，item-level carve-out
    async fn emit_async_rejects_non_dotted_topic() {
        let emitter = DynOutboxEmitter::new_box(CapturingEmitter::new());
        let dispatch = DispatchId::from_idempotency_key("k").expect("non-empty key");
        let err = emit_async(
            &emitter,
            dispatch,
            "Not A Topic",
            vocab::ContractBinding::from_static("seed", "seed.do-thing", "v1", HASH),
            tenant(),
            b"{}".to_vec(),
            subject("s"),
            actor(),
        )
        .await;
        assert!(
            matches!(err, Err(super::CommandEmitError::Topic)),
            "{err:?}"
        );
    }

    /// 空 dispatch key → DispatchId::from_idempotency_key 拒（fail-closed）。
    #[test]
    fn dispatch_id_rejects_empty_key() {
        assert!(DispatchId::from_idempotency_key("").is_err());
        assert!(DispatchId::from_idempotency_key("ok").is_ok());
    }

    // ── consumer 侧 fakes ───────────────────────────────────────────────────────

    enum CheckResult {
        Fresh,
        Duplicate,
    }

    struct FakeStore {
        result: CheckResult,
        commit_count: AtomicU32,
    }

    impl FakeStore {
        fn fresh() -> Arc<Self> {
            Arc::new(Self {
                result: CheckResult::Fresh,
                commit_count: AtomicU32::new(0),
            })
        }
        fn duplicate() -> Arc<Self> {
            Arc::new(Self {
                result: CheckResult::Duplicate,
                commit_count: AtomicU32::new(0),
            })
        }
        fn commits(&self) -> u32 {
            self.commit_count.load(Ordering::Acquire)
        }
    }

    impl IdempotencyStore for FakeStore {
        async fn try_claim(
            &self,
            _key: &IdemKey,
            _lease: &LeaseToken,
        ) -> Result<SeenState, consistency::error::EngineError> {
            match self.result {
                CheckResult::Fresh => Ok(SeenState::Fresh),
                CheckResult::Duplicate => Ok(SeenState::Duplicate),
            }
        }
        async fn extend(
            &self,
            _key: &IdemKey,
            _lease: &LeaseToken,
        ) -> Result<LeaseOutcome, consistency::error::EngineError> {
            // 命令消费测试不模拟租约丢失：恒 Held。
            Ok(LeaseOutcome::Held)
        }
        async fn commit(
            &self,
            _key: &IdemKey,
            _lease: &LeaseToken,
        ) -> Result<LeaseOutcome, consistency::error::EngineError> {
            self.commit_count.fetch_add(1, Ordering::Release);
            Ok(LeaseOutcome::Held)
        }
        async fn release(
            &self,
            _key: &IdemKey,
            _lease: &LeaseToken,
        ) -> Result<(), consistency::error::EngineError> {
            Ok(())
        }
    }

    struct FakeDlx {
        writes: Mutex<u32>,
    }
    impl FakeDlx {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                writes: Mutex::new(0),
            })
        }
        fn write_count(&self) -> u32 {
            #[allow(clippy::unwrap_used)]
            // reason: 测试 Mutex，item-level carve-out
            *self.writes.lock().unwrap()
        }
    }
    impl DeadLetterStore for FakeDlx {
        async fn write_dead_letter(
            &self,
            _record: DeadLetterRecord,
        ) -> Result<(), DeadLetterStoreError> {
            #[allow(clippy::unwrap_used)]
            // reason: 测试 Mutex，item-level carve-out
            {
                *self.writes.lock().unwrap() += 1;
            }
            Ok(())
        }
        async fn shutdown(&self) -> Result<(), DeadLetterStoreError> {
            Ok(())
        }
    }

    fn box_dlx(store: Arc<FakeDlx>) -> Box<DynDeadLetterStore<'static>> {
        struct ArcProxy(Arc<FakeDlx>);
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

    #[allow(clippy::expect_used)]
    fn stream_of_with_schema(
        items: &[(&str, &[u8])],
        schema_version: &str,
        schema_hash: &str,
    ) -> diport::MessageStream {
        let msgs: Vec<Message> = items
            .iter()
            .map(|(id, p)| {
                let mut md = EnvelopeMetadata::empty();
                let token = tenant_authority()
                    .sign(TenantAuthorityBinding::new(
                        tenant(),
                        "seed",
                        "seed.do-thing",
                        "seed.commands.do-thing",
                        id,
                    ))
                    .expect("tenant authority test signing cannot fail");
                md.insert_wire_pair(KEY_TENANT_ID, tenant().to_string());
                md.insert_wire_pair(KEY_TENANT_AUTHORITY, token);
                md.insert_wire_pair(KEY_SCHEMA_VERSION, schema_version);
                md.insert_wire_pair(KEY_SCHEMA_HASH, schema_hash);
                Message::new_with_metadata(*id, p.to_vec(), md)
            })
            .collect();
        Box::pin(futures::stream::iter(msgs))
    }

    fn stream_of(items: &[(&str, &[u8])]) -> diport::MessageStream {
        stream_of_with_schema(items, "v1", HASH)
    }

    #[derive(serde::Deserialize)]
    struct DoThing {
        amount: i64,
    }

    /// 合法 wire → typed decode → handler 收到 typed Request；Ack → commit 1 次、无 DLX。
    #[tokio::test]
    async fn register_decodes_typed_and_acks() {
        let idem = FakeStore::fresh();
        let dlx = FakeDlx::new();
        let seen = Arc::new(Mutex::new(Vec::<i64>::new()));
        let seen2 = seen.clone();
        register_command_handler::<_, DoThing, _, _>(
            stream_of(&[("dispatch-1", b"{\"amount\":9}")]),
            idem.clone(),
            box_dlx(dlx.clone()),
            "seed",
            command_contract(),
            "seed.commands.do-thing",
            "seed.do-thing.consumer",
            tenant_authority(),
            move |req: DoThing| {
                let seen2 = seen2.clone();
                async move {
                    #[allow(clippy::unwrap_used)]
                    // reason: 测试 Mutex，item-level carve-out
                    seen2.lock().unwrap().push(req.amount);
                    HandleResult::ack()
                }
            },
            lease_cfg(),
        )
        .await;
        #[allow(clippy::unwrap_used)]
        // reason: 测试断言，item-level carve-out
        let amounts = seen.lock().unwrap().clone();
        assert_eq!(amounts, vec![9], "handler 应收到 typed decode 的 amount");
        assert_eq!(idem.commits(), 1, "Ack → commit 1 次");
        assert_eq!(dlx.write_count(), 0, "无 DLX");
    }

    #[tokio::test]
    async fn register_rejects_schema_hash_mismatch_before_claim() {
        const OTHER_HASH: &str =
            "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let idem = FakeStore::fresh();
        let dlx = FakeDlx::new();
        let calls = Arc::new(AtomicU32::new(0));
        let calls2 = calls.clone();

        register_command_handler::<_, DoThing, _, _>(
            stream_of_with_schema(
                &[("dispatch-wrong-schema", b"{\"amount\":9}")],
                "v1",
                OTHER_HASH,
            ),
            idem.clone(),
            box_dlx(dlx.clone()),
            "seed",
            command_contract(),
            "seed.commands.do-thing",
            "seed.do-thing.consumer",
            tenant_authority(),
            move |_req: DoThing| {
                let calls2 = calls2.clone();
                async move {
                    calls2.fetch_add(1, Ordering::Relaxed);
                    HandleResult::ack()
                }
            },
            lease_cfg(),
        )
        .await;

        assert_eq!(
            calls.load(Ordering::Relaxed),
            0,
            "schema mismatch must be rejected before typed handler"
        );
        assert_eq!(idem.commits(), 0, "schema mismatch must not claim/commit");
        assert_eq!(dlx.write_count(), 0, "header gate must skip app DLX");
    }

    /// 同 DispatchId 二次（claimer 返 Duplicate）→ handler 不调、不 commit（= claimer 拒，两阶段去重）。
    #[tokio::test]
    async fn register_duplicate_dispatch_id_rejected_by_claimer() {
        let idem = FakeStore::duplicate();
        let dlx = FakeDlx::new();
        let calls = Arc::new(AtomicU32::new(0));
        let calls2 = calls.clone();
        register_command_handler::<_, DoThing, _, _>(
            stream_of(&[("dispatch-dup", b"{\"amount\":1}")]),
            idem.clone(),
            box_dlx(dlx.clone()),
            "seed",
            command_contract(),
            "seed.commands.do-thing",
            "seed.do-thing.consumer",
            tenant_authority(),
            move |_req: DoThing| {
                let calls2 = calls2.clone();
                async move {
                    calls2.fetch_add(1, Ordering::Relaxed);
                    HandleResult::ack()
                }
            },
            lease_cfg(),
        )
        .await;
        assert_eq!(
            calls.load(Ordering::Relaxed),
            0,
            "Duplicate → handler 不调（claimer 拒）"
        );
        assert_eq!(idem.commits(), 0, "Duplicate → 不 commit");
    }

    /// 坏 wire（非法 JSON）→ 永久 reject → DLX 写 1 次（坏消息不 Requeue 无限重投）。
    #[tokio::test]
    async fn register_bad_wire_rejected_to_dlx() {
        let idem = FakeStore::fresh();
        let dlx = FakeDlx::new();
        register_command_handler::<_, DoThing, _, _>(
            stream_of(&[("dispatch-bad", b"not json")]),
            idem.clone(),
            box_dlx(dlx.clone()),
            "seed",
            command_contract(),
            "seed.commands.do-thing",
            "seed.do-thing.consumer",
            tenant_authority(),
            move |_req: DoThing| async move { HandleResult::ack() },
            lease_cfg(),
        )
        .await;
        assert_eq!(dlx.write_count(), 1, "坏 wire → 永久 reject → DLX");
    }

    // ── TC-F5a：OutboxEmitter 失败路径 ───────────────────────────────────────

    /// TC-F5a：fake OutboxEmitter 返 Err → emit_async 返 CommandEmitError::Emit（底层 emitter 失败收口）。
    struct FailEmitter;
    impl OutboxEmitter for FailEmitter {
        async fn emit(
            &self,
            _entry: consistency::Entry,
            _envelope: OutboxEnvelopeParts,
        ) -> Result<(), OutboxEmitError> {
            Err(OutboxEmitError::new(std::io::Error::other(
                "injected failure",
            )))
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    // reason: 测试 happy-path 构造，item-level carve-out
    async fn emit_async_propagates_emitter_error() {
        let emitter = DynOutboxEmitter::new_box(FailEmitter);
        let dispatch = DispatchId::from_idempotency_key("dispatch-err").expect("non-empty key");
        let result = emit_async(
            &emitter,
            dispatch,
            "seed.commands.fail",
            vocab::ContractBinding::from_static("seed", "seed.fail", "v1", HASH),
            tenant(),
            b"{}".to_vec(),
            subject("subject-opaque"),
            actor(),
        )
        .await;
        assert!(
            matches!(result, Err(super::CommandEmitError::Emit(_))),
            "底层 emitter 失败应映射为 CommandEmitError::Emit: {result:?}"
        );
    }

    // ── TC-F5c：requeue 路径 → MAX_REDELIVERY 耗尽 → DLX ────────────────────

    /// TC-F5c：handler 恒 Requeue → MAX_REDELIVERY 次后进 DLX（镜像 consumer.rs TC2，经命令 wrapper）。
    #[tokio::test]
    async fn register_requeue_exhausted_to_dlx() {
        let idem = FakeStore::fresh();
        let dlx = FakeDlx::new();
        let calls = Arc::new(AtomicU32::new(0));
        let calls2 = calls.clone();
        register_command_handler::<_, DoThing, _, _>(
            stream_of(&[("dispatch-rq", b"{\"amount\":1}")]),
            idem.clone(),
            box_dlx(dlx.clone()),
            "seed",
            command_contract(),
            "seed.commands.do-thing",
            "seed.do-thing.consumer",
            tenant_authority(),
            move |_req: DoThing| {
                let calls2 = calls2.clone();
                async move {
                    calls2.fetch_add(1, Ordering::Relaxed);
                    HandleResult::requeue(consistency::error::EngineError::new(
                        consistency::error::EngineErrorKind::Transient,
                    ))
                }
            },
            lease_cfg(),
        )
        .await;
        assert_eq!(
            calls.load(Ordering::Relaxed),
            MAX_REDELIVERY,
            "requeue handler 应调 MAX_REDELIVERY 次"
        );
        assert_eq!(dlx.write_count(), 1, "requeue 耗尽 → DLX 写 1 次");
    }
}
