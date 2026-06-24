//! `OutboxEmitter` —— durable outbox 发射 provider DI port（可替换：prod postgres / demo in-mem）。
//!
//! 域 crate 经此 port 把一条 [`consistency::Entry`]（topic + idem_key(EventId) + 编码 payload）落 durable
//! outbox（与契约声明的 L2 OutboxFact 语义同源）。**域不能命名 `PgConnection` / `OutboxEnvelope`**
//! （域→adapter 被 `deny.toml` 禁），故 envelope 字段以 opaque [`OutboxEnvelopeParts`] 传入，由 adapter
//! 组装 provider 私有 envelope（reserved key trace / correlation / occurred_at 在 adapter 受控构造点注入，
//! 业务不得伪造，FR-020 / `docs/rules/observability.md` §Outbox Envelope）。
//!
//! 与 [`crate::Publisher`] 的分工：`Publisher` 是 relay 把**已持久化** entry 直发到 broker 的端口；
//! `OutboxEmitter` 是 producer 把业务事件**持久化进 durable outbox**（含幂等锚点 EventId）的端口——
//! 二者语义正交，故为不同 port（不复用 `Publisher` 的 fire-and-forget 语义）。
//!
//! **单事实 emit 语义**：本 port 保证一条 [`Entry`] 的 durable 落库原子性（单 outbox 写自成事务）——
//! 用于**无 co-located 业务写**的 OutboxFact 事件（纯通知）。与业务写同事务的 **co-tx 原子性**（FR-003
//! 完整 L2，如 session 持久化与 outbox append 同一 `PgTransaction`）**已交付**（#1083/#1192）：经各域**域形
//! Unit-of-Work 端口**（如 `identity::ports::SessionUnitOfWork`，combined 方法把业务写 + `append_outbox`
//! 收进同一事务）承载，与本 emit-only port 语义正交（二者并存：emit-only 路由纯事件、UoW 路由 co-tx）。
//! 本 port 的单事实 emit 语义不变。
//!
//! ref: debezium outbox SMT（业务写 + outbox 行同一本地事务，producer 侧 durable 落库）
//! ref: eventuate-tram-core io.eventuate.tram.consumer.common.DuplicateMessageDetector@master
//!      （message-id 作幂等键，对应 RSS `inbox_dedup(event_id, consumer_group)`）

use dynosaur::dynosaur;

use consistency::Entry;

use crate::redacted::RedactedSource;

/// outbox 发射失败。
///
/// PII 边界（与 [`crate::PublisherError`] 同范式）：`Display` 仅安全摘要常量；source 经
/// [`RedactedSource`] 脱敏（`Debug` / `Display` 固定 `<redacted>`、`Error::source()` 恒 `None`），见
/// INVARIANT: DIPORT-ERR-SOURCE-REDACT-01。
#[derive(Debug, thiserror::Error)]
#[error("outbox emit failed")]
pub struct OutboxEmitError {
    #[source]
    source: RedactedSource,
}

impl OutboxEmitError {
    /// 把 adapter 内部错误包成发射失败。原始错误仅作 internal source 保留，不经 `Display` 暴露（PII 边界）。
    pub fn new<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            source: RedactedSource::new(source),
        }
    }
}

/// outbox envelope 的 **opaque** 字段集（域传，adapter 组装成 provider 私有 envelope）。
///
/// 仅承载非-reserved、可由业务安全提供的字段：`domain` / `contract_id` 是路由归属，`subject_id` 是
/// **opaque** 主体标识（FR-020：不容完整 Principal / email / 姓名等 PII）。reserved envelope key
/// （trace / correlation / occurred_at）**不在此**——由 adapter 在受控构造点注入（runctx + `Clock`）。
///
/// INVARIANT: DIPORT-DTO-PII-DEBUG-REDACT-01 —— `Debug` 仅输出路由元数据（`domain` / `contract_id`），
/// `subject_id` 固定渲染为 `<redacted>`，防主体标识经 `{:?}` 泄漏至日志（回归见 `pii_debug` 单测）。
#[derive(Clone)]
pub struct OutboxEnvelopeParts {
    /// 发布域（如 `"identity"`）。
    pub domain: String,
    /// 契约 ID（如 generated `CONTRACT_ID`）。
    pub contract_id: String,
    /// opaque 主体标识（无 PII）。
    pub subject_id: String,
}

impl std::fmt::Debug for OutboxEnvelopeParts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboxEnvelopeParts")
            .field("domain", &self.domain)
            .field("contract_id", &self.contract_id)
            .field("subject_id", &"<redacted>")
            .finish()
    }
}

/// durable outbox 发射 provider DI port（async）。
///
/// 公开 [`OutboxEmitter`] 是 **Send 变体**（adapters `impl OutboxEmitter for ...`），[`DynOutboxEmitter`]
/// 是其 dyn-compatible wrapper（组合根经 `Box<DynOutboxEmitter>` 注入，必填构造器位置参，缺失即编译错误）。
#[trait_variant::make(OutboxEmitter: Send)]
#[dynosaur(pub DynOutboxEmitter = dyn(box) OutboxEmitter, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: base trait 为非 Send native AFIT；Send 由 trait_variant 生成的 `OutboxEmitter` 变体 +
// dynosaur `DynOutboxEmitter` 承载（DI 注入走 Send wrapper）。ADR-003 既定 dyn-port 范式。
pub trait OutboxEmitterLocal {
    /// 把一条 [`Entry`] 落 durable outbox（envelope 由 [`OutboxEnvelopeParts`] 组装）。
    async fn emit(
        &self,
        entry: Entry,
        envelope: OutboxEnvelopeParts,
    ) -> Result<(), OutboxEmitError>;
}

#[cfg(test)]
mod pii_debug {
    //! `OutboxEnvelopeParts.subject_id` Debug 脱敏回归。
    //! INVARIANT: DIPORT-DTO-PII-DEBUG-REDACT-01.
    use super::OutboxEnvelopeParts;

    #[test]
    fn outbox_envelope_parts_debug_redacts_subject_id() {
        // anti-vacuity：证明 "SECRET-SUBJECT" 会出现在普通 String Debug 中（前提不成立则检测无意义）。
        assert!(
            format!("{:?}", "SECRET-SUBJECT").contains("SECRET-SUBJECT"),
            "前提失效：普通字符串 Debug 未携 marker"
        );
        let parts = OutboxEnvelopeParts {
            domain: "identity".to_string(),
            contract_id: "identity.session-created".to_string(),
            subject_id: "SECRET-SUBJECT".to_string(),
        };
        let dbg = format!("{parts:?}");
        assert!(
            !dbg.contains("SECRET-SUBJECT"),
            "subject_id 泄漏至 Debug: {dbg}"
        );
        assert!(dbg.contains("<redacted>"), "缺 <redacted>: {dbg}");
        assert!(dbg.contains("identity"), "domain 应可见: {dbg}");
    }
}

#[cfg(test)]
mod smoke {
    //! build smoke：证明 async DI port 可 native AFIT impl + 经 `Box<DynOutboxEmitter>` 动态注入（Send）。
    use consistency::{Entry, IdemKey, Topic};

    use super::{DynOutboxEmitter, OutboxEmitError, OutboxEmitter, OutboxEnvelopeParts};

    #[test]
    fn outbox_emit_error_wraps_source() {
        let err = OutboxEmitError::new(std::io::Error::other("leak-marker-emit"));
        assert_eq!(err.to_string(), "outbox emit failed");
        assert!(std::error::Error::source(&err).is_some());
        // anti-vacuity：内层 Debug 确携 marker（前提），wrapper Debug 不得泄漏。
        assert!(
            format!("{:?}", std::io::Error::other("leak-marker-emit")).contains("leak-marker-emit"),
            "前提失效：内层 Debug 未携 marker"
        );
        assert!(
            !format!("{err:?}").contains("leak-marker-emit"),
            "wrapper Debug 泄漏 source: {err:?}"
        );
    }

    #[allow(clippy::expect_used)]
    // reason: 测试构造 Entry 需 parse Topic/IdemKey（合法输入恒 Ok）；item-level carve-out。
    fn sample() -> (Entry, OutboxEnvelopeParts) {
        let entry = Entry::new(
            Topic::parse("identity.session-created").expect("topic"),
            IdemKey::parse("evt-1").expect("idem"),
            b"payload".to_vec(),
        );
        let env = OutboxEnvelopeParts {
            domain: "identity".to_string(),
            contract_id: "identity.session-created".to_string(),
            subject_id: "subject-opaque".to_string(),
        };
        (entry, env)
    }

    struct NoopEmitter;
    impl OutboxEmitter for NoopEmitter {
        async fn emit(
            &self,
            _entry: Entry,
            _env: OutboxEnvelopeParts,
        ) -> Result<(), OutboxEmitError> {
            Ok(())
        }
    }

    // multi_thread + spawn：验证 boxed future Send（trait_variant Send 变体），与真实 spawn 场景对齐。
    #[tokio::test(flavor = "multi_thread")]
    async fn outbox_emitter_is_dyn_injectable() {
        let emitter: Box<DynOutboxEmitter> = DynOutboxEmitter::new_box(NoopEmitter);
        let joined = tokio::spawn(async move {
            let (entry, env) = sample();
            emitter.emit(entry, env).await.is_ok()
        })
        .await;
        assert!(matches!(joined, Ok(true)));
    }
}
