//! Outbox 投递接缝（L1）—— 纯类型 disposition + relay 策略。
//!
//! `Disposition`/`HandleResult`/`PermanentError`/`Entry`/`Topic` 是 **纯态机类型**（sync，穷尽闭值集）；
//! `OutboxRelay` 是 L1 引擎策略 trait（native AFIT，把已持久化 entry 中继到 broker）。
//! 真实 broker I/O（AMQP）与 in-memory bus 在 `eventexec`/adapters，consistency 只冻类型 + 策略接缝。
//! 语义见 `docs/rules/eventbus.md` §Disposition / §ConsumerBase。
//! ref: ThreeDotsLabs/watermill message/router.go@master（Ack/Requeue/Reject disposition 概念对标）。

/// 消费处置（穷尽闭值集，Hard 冻结；漏 case 编不过）。eventbus.md §Disposition 表。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Disposition {
    /// 成功：broker ack + receipt commit。
    Ack,
    /// 瞬态失败：退避重试，预算耗尽后转 Reject。
    Requeue,
    /// 永久失败：broker nack/reject，进入 DLX。
    Reject,
}

impl Disposition {
    /// 稳定 metrics/log label（crate-owned 闭映射；下游无需 match non_exhaustive enum）。
    pub fn as_label(self) -> &'static str {
        match self {
            Disposition::Ack => "ack",
            Disposition::Requeue => "requeue",
            Disposition::Reject => "reject",
        }
    }
}

/// 永久（不可重试）失败种类——**排除** `Transient`（类型层杜绝把瞬态误标永久）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PermanentErrorKind {
    /// 永久失败（重试无意义）。
    Permanent,
    /// 引擎不变量被破坏（编程错误）。
    Invariant,
}

impl PermanentErrorKind {
    /// 稳定 message（`&'static str` const literal）。
    pub fn message(self) -> &'static str {
        match self {
            PermanentErrorKind::Permanent => "permanent error",
            PermanentErrorKind::Invariant => "invariant violated",
        }
    }
}

/// 永久错误标记（私有字段；只是分类，不自动把 Requeue 改 Reject —— eventbus.md）。
///
/// 持 [`PermanentErrorKind`]（排除 `Transient`），类型层杜绝把瞬态误标永久（codex F5）。
#[derive(Debug, thiserror::Error)]
#[error("{}", .0.message())]
pub struct PermanentError(PermanentErrorKind);

impl PermanentError {
    /// 由永久错误种类构造（`Transient` 类型层不可表达）。
    pub fn new(kind: PermanentErrorKind) -> Self {
        Self(kind)
    }

    /// 永久错误种类（供 DLX 细分类）。
    pub fn kind(&self) -> PermanentErrorKind {
        self.0
    }
}

/// 业务 handler 结果（私有字段；禁裸 struct literal，经 `ack`/`requeue`/`reject` 构造器 —— eventbus.md）。
#[derive(Debug)]
pub struct HandleResult {
    disposition: Disposition,
}

impl HandleResult {
    /// 成功。
    pub fn ack() -> Self {
        Self {
            disposition: Disposition::Ack,
        }
    }

    /// 瞬态失败 → 退避重试（携因由进引擎错误通道）。
    #[allow(clippy::needless_pass_by_value)]
    // reason: 签名冻结（ADR-004 C8）——HandleResult 字段集只含 disposition，不能为消 lint 把 `error` 改
    // by-ref（破坏已冻结调用约定）。`error` 由构造 HandleResult 的 relay/subscriber 在丢弃前自行落日志
    // （持有方在 call site 即有 error；adapter 层 T004+ 落地强制日志，见 #1125），本纯态机不接 tracing 依赖。
    pub fn requeue(_error: crate::error::EngineError) -> Self {
        Self {
            disposition: Disposition::Requeue,
        }
    }

    /// 永久失败 → DLX。
    #[allow(clippy::needless_pass_by_value)]
    // reason: 同 `requeue`（签名冻结，by-ref 破坏调用约定）；`error` 由 relay/subscriber 丢弃前落日志（#1125）。
    pub fn reject(_error: PermanentError) -> Self {
        Self {
            disposition: Disposition::Reject,
        }
    }

    /// 处置（subscriber/relay 穷尽 match）。
    pub fn disposition(&self) -> Disposition {
        self.disposition
    }
}

/// 事件 topic newtype（私有字段；稳定 dotted 名称 —— eventbus.md §命名）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Topic(String);

/// `Topic` 解析错误。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TopicError {
    #[error("topic name is empty")]
    Empty,
    #[error("topic name is not a canonical dotted name")]
    Format,
}

impl Topic {
    /// 解析稳定 dotted topic 名；拒绝空/非 canonical（fail-closed）。
    pub fn parse(raw: &str) -> Result<Self, TopicError> {
        if raw.is_empty() {
            return Err(TopicError::Empty);
        }
        if !is_canonical_dotted(raw) {
            return Err(TopicError::Format);
        }
        Ok(Self(raw.to_string()))
    }

    /// 借出底层字符串视图。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// canonical dotted topic 文法：非空、每 `.` 段首字节 `[a-z]`、整段 `[a-z0-9-]`。
///
/// **镜像 contract 单源校验器** `is_dotted_id`（`xtask/src/contract/validate.rs`，R7 IdentSyntax）——
/// topic 是 wire routing key，contract 声明面与运行期 `Topic` 构造面文法必须同形，否则会出现
/// 「contract 能声明但运行期构造拒」的分歧。两侧分属不同层（xtask 在 consistency 之上），暂以镜像 +
/// 注释引用维持单源；统一单源（xtask 反向 delegate 本函数）见 #1126。
fn is_canonical_dotted(s: &str) -> bool {
    !s.is_empty()
        && s.split('.').all(|seg| {
            matches!(seg.bytes().next(), Some(b) if b.is_ascii_lowercase())
                && seg
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// 持久化 outbox 条目（私有字段；payload 是已编码字节，由 emit 期写入 —— eventbus.md §命名与 payload）。
///
/// engine 类型——**不** derive serde（ADR-004 C6）；wire 编解码在 generated/eventexec 边界完成。
#[derive(Debug, Clone)]
pub struct Entry {
    topic: Topic,
    idem_key: crate::idempotency::IdemKey,
    payload: Vec<u8>,
}

impl Entry {
    /// 由 topic + 幂等 key + 已编码 payload 构造（受控 funnel；命令 topic 构造收口于此 —— eventbus.md）。
    pub fn new(topic: Topic, idem_key: crate::idempotency::IdemKey, payload: Vec<u8>) -> Self {
        Self {
            topic,
            idem_key,
            payload,
        }
    }

    /// 目标 topic。
    pub fn topic(&self) -> &Topic {
        &self.topic
    }

    /// 幂等 key。
    pub fn idem_key(&self) -> &crate::idempotency::IdemKey {
        &self.idem_key
    }

    /// 已编码 payload。
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Outbox 中继策略（L1 引擎策略 trait，native AFIT）。
///
/// 把**已持久化**的 outbox entry 中继到 broker（demo=进程内 bus / postgres=真实 broker，eventbus.md
/// topology-gated）。native AFIT ⇒ 非 object-safe，消费方泛型 `<R: OutboxRelay>`，禁 `Box<dyn>`。
#[allow(async_fn_in_trait)]
// reason: native AFIT 引擎策略 trait 仅泛型静态分发消费，无 Send-bound 跨 await 持有问题；这是 ADR-003 既定范式。
pub trait OutboxRelay {
    /// 中继单条已持久化 entry。返回处置驱动 receipt commit / DLX / 退避（穷尽 `Disposition`）。
    async fn relay(&self, entry: &Entry) -> Result<Disposition, crate::error::EngineError>;
}

#[cfg(test)]
mod tests {
    use super::{
        Disposition, Entry, HandleResult, PermanentError, PermanentErrorKind, Topic, TopicError,
    };
    use crate::error::{EngineError, EngineErrorKind};
    use crate::idempotency::IdemKey;

    // 三处置稳定 label 闭映射且互异。
    #[test]
    fn disposition_as_label_distinct() {
        let cases: &[(Disposition, &str)] = &[
            (Disposition::Ack, "ack"),
            (Disposition::Requeue, "requeue"),
            (Disposition::Reject, "reject"),
        ];
        for &(d, expected) in cases {
            assert_eq!(d.as_label(), expected, "disposition={d:?}");
        }
        assert_ne!(Disposition::Ack.as_label(), Disposition::Requeue.as_label());
        assert_ne!(
            Disposition::Requeue.as_label(),
            Disposition::Reject.as_label()
        );
        assert_ne!(Disposition::Ack.as_label(), Disposition::Reject.as_label());
    }

    // PermanentErrorKind message 非空互异（Transient 类型层不可表达）。
    #[test]
    fn permanent_error_kind_message_distinct() {
        let cases: &[(PermanentErrorKind, &str)] = &[
            (PermanentErrorKind::Permanent, "permanent error"),
            (PermanentErrorKind::Invariant, "invariant violated"),
        ];
        for &(kind, expected) in cases {
            assert_eq!(kind.message(), expected, "kind={kind:?}");
            assert!(!kind.message().is_empty(), "empty message kind={kind:?}");
        }
        assert_ne!(
            PermanentErrorKind::Permanent.message(),
            PermanentErrorKind::Invariant.message()
        );
    }

    // PermanentError new → kind 往返 + Display == message。
    #[test]
    fn permanent_error_round_trips_and_displays() {
        for kind in [PermanentErrorKind::Permanent, PermanentErrorKind::Invariant] {
            let e = PermanentError::new(kind);
            assert_eq!(e.kind(), kind, "kind={kind:?}");
            assert_eq!(e.to_string(), kind.message(), "kind={kind:?}");
        }
    }

    // ack/requeue/reject 构造器置正确 disposition（error 参数接收后丢弃，日志在 relay 层）。
    #[test]
    fn handle_result_constructors_set_disposition() {
        assert_eq!(HandleResult::ack().disposition(), Disposition::Ack);
        assert_eq!(
            HandleResult::requeue(EngineError::new(EngineErrorKind::Transient)).disposition(),
            Disposition::Requeue
        );
        assert_eq!(
            HandleResult::reject(PermanentError::new(PermanentErrorKind::Permanent)).disposition(),
            Disposition::Reject
        );
    }

    // canonical dotted 接受（镜像 is_dotted_id，含单段 foo）+ as_str 往返。
    #[test]
    #[allow(clippy::unwrap_used)]
    // reason: 测试 happy-path 断言已 is_ok 的 parse 结果，item-level carve-out（error-handling.md §Carve-out）。
    fn topic_parse_accepts_canonical_dotted_and_round_trips() {
        let cases: &[&str] = &[
            "seed.thing-happened",
            "session.created",
            "a.b",
            "foo",
            "rss.session.created",
            "domain1.event-2.v3",
        ];
        for &raw in cases {
            assert!(Topic::parse(raw).is_ok(), "expected Ok for raw={raw:?}");
            let topic = Topic::parse(raw).unwrap();
            assert_eq!(topic.as_str(), raw, "raw={raw:?}");
        }
    }

    // 空 → Empty。
    #[test]
    fn topic_parse_rejects_empty() {
        assert!(matches!(Topic::parse(""), Err(TopicError::Empty)));
    }

    // 非 canonical dotted → Format（镜像 is_dotted_id 拒绝集：空段/大写/段首数字-连字符/下划线/空格）。
    #[test]
    fn topic_parse_rejects_format() {
        let cases: &[&str] = &[
            ".x",      // 前导点 → 空段
            "x.",      // 尾随点 → 空段
            "a..b",    // 连续点 → 空段
            "Foo",     // 段首大写
            "foo.Bar", // 次段大写
            "1a",      // 段首数字
            "-a",      // 段首连字符
            "a_b",     // 下划线不在 [a-z0-9-]
            "a b",     // 空格
            "a.b ",    // 段含空格
        ];
        for &raw in cases {
            assert!(
                matches!(Topic::parse(raw), Err(TopicError::Format)),
                "expected Format for raw={raw:?}"
            );
        }
    }

    // 私有文法谓词独立语义（`parse` 已前置拒空，此处守 helper 独立调用时空串短路 false 分支，
    // 保持与单源 `is_dotted_id` 同形且文法分支全覆盖）。
    #[test]
    fn is_canonical_dotted_standalone() {
        assert!(!super::is_canonical_dotted(""));
        assert!(super::is_canonical_dotted("a.b"));
        assert!(super::is_canonical_dotted("foo"));
        assert!(!super::is_canonical_dotted("a..b"));
    }

    // Entry::new funnel + 三访问器借出。
    #[test]
    #[allow(clippy::unwrap_used)]
    // reason: 测试 happy-path 断言已 is_ok 的 parse 结果，item-level carve-out（error-handling.md §Carve-out）。
    fn entry_new_exposes_fields() {
        let topic = Topic::parse("session.created").unwrap();
        let key = IdemKey::parse("evt-1").unwrap();
        let payload = vec![1u8, 2, 3];
        let entry = Entry::new(topic.clone(), key.clone(), payload.clone());
        assert_eq!(entry.topic(), &topic);
        assert_eq!(entry.idem_key(), &key);
        assert_eq!(entry.payload(), payload.as_slice());
    }
}
