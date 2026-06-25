//! Outbox 接缝（L1 原子写 + L2 OutboxFact 投递）—— 纯类型 disposition + relay/source/sweep 策略。
//!
//! `Disposition`/`HandleResult`/`PermanentError`/`Entry`/`Topic` 是 **纯态机类型**（sync，穷尽闭值集）；
//! `OutboxRelay`/`OutboxSource`/`OutboxSweeper` 是 L2 OutboxFact 引擎策略 trait（native AFIT：把已持久化
//! entry 中继到 broker / 扫描待发 / 清理已投递）。真实 broker I/O（AMQP）与 in-memory bus 在 `eventexec`/
//! adapters，consistency 只冻类型 + 策略接缝。
//! 语义见 `docs/rules/eventbus.md` §Disposition / §ConsumerBase。
//!
//! # INVARIANT: OUTBOX-ENGINE-PORT-01
//!
//! `OutboxRelay`/`OutboxSource`/`OutboxSweeper`/`OutboxBacklog` 是**引擎策略接缝**（签名引 `Entry`/
//! `Disposition`/`BacklogSample`/`EngineError` 等 consistency 内部类型），按 ADR-005 category line **不能**在
//! `diport` 内编译（否则 diport 反依赖引擎），故正确归属本引擎 crate——非 provider-agnostic 的 diport DI
//! port。native AFIT、不引 dynosaur。
//!
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
///
/// `error_summary` 捕获 `reject`/`requeue` 的 error kind 的 `&'static str` const message（#1125）——error 不再在
/// HandleResult 边界被静默丢弃（构造即捕获，Hard），由消费方 ConsumerBase DLX funnel 落日志。摘要恒为 const
/// literal（来自 `EngineErrorKind`/`PermanentErrorKind::message()`，无 runtime 数据）⇒ PII-safe，对齐
/// `diport::DeadLetterSummary` 的 const 收口（DIPORT-DLX-SUMMARY-STATIC-01）。
///
/// # INVARIANT: OUTBOX-HANDLERESULT-SUMMARY-01
///
/// `error_summary` 只能取 `*ErrorKind::message()` 的 `&'static str` const（reject/requeue 构造器内单源填入，
/// ack 为 `None`）——类型层杜绝 runtime `String` 入摘要（PII-safe，Hard）。
#[derive(Debug)]
pub struct HandleResult {
    disposition: Disposition,
    /// error kind 的 const 摘要（`ack` 无 error ⇒ `None`；`reject`/`requeue` 恒 `Some`）。
    error_summary: Option<&'static str>,
}

impl HandleResult {
    /// 成功（无 error）。
    pub fn ack() -> Self {
        Self {
            disposition: Disposition::Ack,
            error_summary: None,
        }
    }

    /// 瞬态失败 → 退避重试（携因由进引擎错误通道）。
    #[allow(clippy::needless_pass_by_value)]
    // reason: 签名冻结期 by-value 调用约定（caller 交出 error 所有权）；`error` 现被消费为 const-message 摘要
    // （`error_summary`），不再丢弃（#1125）。kind message 是 `&'static str` const，本纯态机不接 tracing 依赖。
    pub fn requeue(error: crate::error::EngineError) -> Self {
        Self {
            disposition: Disposition::Requeue,
            error_summary: Some(error.kind().message()),
        }
    }

    /// 永久失败 → DLX（携永久错误因由）。
    #[allow(clippy::needless_pass_by_value)]
    // reason: 同 `requeue`（签名冻结期 by-value 约定）；`error` 被消费为 const-message 摘要，不再丢弃（#1125）。
    pub fn reject(error: PermanentError) -> Self {
        Self {
            disposition: Disposition::Reject,
            error_summary: Some(error.kind().message()),
        }
    }

    /// 处置（subscriber/relay 穷尽 match）。
    pub fn disposition(&self) -> Disposition {
        self.disposition
    }

    /// error kind 的 const 摘要（`reject`/`requeue` 携 `Some`，`ack` 为 `None`）。
    /// 由消费方 ConsumerBase DLX 落日志（#1125）；恒 `&'static str` const ⇒ PII-safe。
    pub fn error_summary(&self) -> Option<&'static str> {
        self.error_summary
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

/// canonical dotted 文法：非空、每 `.` 段首字节 `[a-z]`、整段 `[a-z0-9-]`。
///
/// 本谓词（经 `Topic::parse`）是 dotted-id / topic 文法的**单一事实源**——topic 是 wire routing key，
/// contract 声明面与运行期 `Topic` 构造面文法必须同形，否则会出现「contract 能声明但运行期构造拒」的分歧。
/// xtask 组合根的 contract 校验器 `is_dotted_id`（R7 IdentSyntax，`xtask/src/contract/validate.rs`）已反向
/// delegate `Topic::parse`（#1126 兑现），两侧不再镜像；漂移结构性不可表达。
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

/// Outbox 扫描源（L1 引擎策略 trait，native AFIT）。
///
/// 按 domain 扫描**待发** entry 批次（status=pending 且到期，含 lease 过期可回收的 in-flight），供
/// relay 环逐条中继。读侧端口，与 [`OutboxRelay`]（写侧中继）同源构成 outbox 引擎接缝——SQL 在 adapter，
/// 本 crate 只冻接缝。native AFIT ⇒ 非 object-safe，消费方泛型 `<S: OutboxSource>`，禁 `Box<dyn>`。
///
/// 返回的 [`Entry`] 是 adapter 内部按行重建（topic/idem_key/payload），**不**携 row id / lease_token——
/// relay 的 CAS settle 以 `entry.idem_key()`（= event_id 幂等锚）为键收口，故扫描与中继解耦无需透传 lease。
#[allow(async_fn_in_trait)]
// reason: native AFIT 引擎策略 trait 仅泛型静态分发消费，无 Send-bound 跨 await 持有问题；这是 ADR-003 既定范式。
pub trait OutboxSource {
    /// 扫描某 `domain` 至多 `limit` 条待发 entry（pending 且 `retry_after` 到期，或 lease 过期的 in-flight
    /// 可回收行）。返回已重建的引擎 [`Entry`]；空 vec ⇒ 当前无待发。`Transient` 错误 ⇒ 本轮退避重扫。
    async fn poll_pending(
        &self,
        domain: &str,
        limit: usize,
    ) -> Result<Vec<Entry>, crate::error::EngineError>;
}

/// Outbox 保留清理端口（L1 引擎策略 trait，native AFIT）。
///
/// 由 sweeper 背景 worker 周期驱动：删除**已终结**（status=published，已成功投递）且超过保留期的
/// outbox 行，防表无界增长。dlx 行保留供运维巡检——不在此删。与 [`OutboxSource`]（扫描）/
/// [`OutboxRelay`]（中继）同源构成 outbox 背景机器的引擎接缝；删除 SQL 在 adapter，本 crate 只冻接缝。
/// native AFIT ⇒ 非 object-safe，消费方泛型 `<S: OutboxSweeper>`，禁 `Box<dyn>`。
#[allow(async_fn_in_trait)]
// reason: native AFIT 引擎策略 trait 仅泛型静态分发消费，无 Send-bound 跨 await 持有问题；这是 ADR-003 既定范式。
pub trait OutboxSweeper {
    /// 删除 `created_at` 早于「现在 − `retain_seconds`」且状态为 published 的行，返回删除条数。
    /// `Transient` 错误 ⇒ 本轮跳过、下轮重试。
    async fn sweep(&self, retain_seconds: u64) -> Result<u64, crate::error::EngineError>;
}

/// 单 domain 的 backlog 采样快照（纯标量值类型，sync 构造；不携 [`Entry`]）。
///
/// 供 outbox 可观测性采样器消费，发射 `outbox_pending_depth` / `outbox_oldest_pending_age_seconds`
/// gauge（#1209）。engine 类型——**不** derive serde（ADR-004 C6）；私有字段 + accessor，仿 [`Entry`]。
///
/// backlog **drain 后**（无 pending 行）规范零值是 [`BacklogSample::empty`]（depth=0, age=0）——
/// 采样器据此把 gauge 置 0（而非缺失），否则 Prometheus 无法区分「积压清空」与「采样器死亡」。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BacklogSample {
    depth: u64,
    oldest_age_seconds: u64,
}

impl BacklogSample {
    /// 由 pending 深度 + 最老 pending 龄（秒）构造。
    pub fn new(depth: u64, oldest_age_seconds: u64) -> Self {
        Self {
            depth,
            oldest_age_seconds,
        }
    }

    /// 空 backlog 规范零值（无 pending 行：depth=0, age=0）。
    pub fn empty() -> Self {
        Self {
            depth: 0,
            oldest_age_seconds: 0,
        }
    }

    /// 当前 pending 深度（status=pending 且到期的行数）。
    pub fn depth(&self) -> u64 {
        self.depth
    }

    /// 最老 pending 行的龄（秒，`now() − min(created_at)`）；无 pending ⇒ 0。
    pub fn oldest_age_seconds(&self) -> u64 {
        self.oldest_age_seconds
    }
}

/// Outbox 积压采样端口（L1 引擎策略 trait，native AFIT）。
///
/// 由可观测性采样背景 worker 周期驱动：聚合某 domain 的 pending 深度 + 最老 pending 龄，发射 backlog
/// gauge（#1209）。与 [`OutboxSource`]（扫描）/ [`OutboxRelay`]（中继）/ [`OutboxSweeper`]（清理）同源
/// 构成 outbox 背景机器的引擎接缝；聚合 SQL 在 adapter，本 crate 只冻接缝。读侧聚合端口，与 `poll_pending`
/// 的行取扫描分离（不同访问形态、不同消费方），故独立 trait 而非扩 [`OutboxSource`]。
/// native AFIT ⇒ 非 object-safe，消费方泛型 `<B: OutboxBacklog>`，禁 `Box<dyn>`。
#[allow(async_fn_in_trait)]
// reason: native AFIT 引擎策略 trait 仅泛型静态分发消费，无 Send-bound 跨 await 持有问题；这是 ADR-003 既定范式。
pub trait OutboxBacklog {
    /// 采样某 `domain` 的**可投递 backlog**（depth + 最老积压龄）。统计集合与 [`OutboxSource::poll_pending`]
    /// 的可重捞集合**同源**：`(pending 且到期) OR (stale publishing，lease 过期可被 relay 重捞)`——stale
    /// publishing 会被重投，属可恢复积压必须计入；只排除 lease 仍有效的正常 in-flight，避免把正常中继中的行
    /// 误计入。无可投递行 ⇒ [`BacklogSample::empty`]。`Transient` 错误 ⇒ 本轮跳过采样。
    async fn sample_backlog(
        &self,
        domain: &str,
    ) -> Result<BacklogSample, crate::error::EngineError>;
}

#[cfg(test)]
mod tests {
    use super::{
        BacklogSample, Disposition, Entry, HandleResult, PermanentError, PermanentErrorKind, Topic,
        TopicError,
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

    // ack/requeue/reject 构造器置正确 disposition（error kind 摘要见 handle_result_carries_error_summary）。
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

    // reject/requeue 把 error kind 的 const message 捕获进 error_summary（#1125）；ack 无 error → None。
    // 摘要恒 `&'static str` const（来自 *ErrorKind::message()），无 runtime 数据 ⇒ PII-safe。
    // INVARIANT: OUTBOX-HANDLERESULT-SUMMARY-01
    #[test]
    fn handle_result_carries_error_summary() {
        // ack 无 error → None。
        assert_eq!(HandleResult::ack().error_summary(), None);

        // requeue：穷举 EngineErrorKind 全部变体 → 各自 const message（kind 增变体时本表须同步）。
        let requeue_cases: &[(EngineErrorKind, &str)] = &[
            (EngineErrorKind::Transient, "transient engine error"),
            (EngineErrorKind::Permanent, "permanent engine error"),
            (EngineErrorKind::Invariant, "engine invariant violated"),
        ];
        for &(kind, expected) in requeue_cases {
            assert_eq!(
                HandleResult::requeue(EngineError::new(kind)).error_summary(),
                Some(expected),
                "requeue kind={kind:?}"
            );
        }

        // reject：穷举 PermanentErrorKind 全部变体 → 各自 const message。
        let reject_cases: &[(PermanentErrorKind, &str)] = &[
            (PermanentErrorKind::Permanent, "permanent error"),
            (PermanentErrorKind::Invariant, "invariant violated"),
        ];
        for &(kind, expected) in reject_cases {
            assert_eq!(
                HandleResult::reject(PermanentError::new(kind)).error_summary(),
                Some(expected),
                "reject kind={kind:?}"
            );
        }

        // anti-vacuity：不同 kind → 不同摘要（摘要随 kind 变化，非硬编码常量）——requeue / reject 各验一次。
        assert_ne!(
            HandleResult::requeue(EngineError::new(EngineErrorKind::Transient)).error_summary(),
            HandleResult::requeue(EngineError::new(EngineErrorKind::Permanent)).error_summary()
        );
        assert_ne!(
            HandleResult::reject(PermanentError::new(PermanentErrorKind::Permanent))
                .error_summary(),
            HandleResult::reject(PermanentError::new(PermanentErrorKind::Invariant))
                .error_summary()
        );
    }

    // canonical dotted 接受（文法单源，xtask is_dotted_id 反向 delegate 此处；含单段 foo）+ as_str 往返。
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

    // 非 canonical dotted → Format（文法单源拒绝集，xtask is_dotted_id 同源：空段/大写/段首数字-连字符/下划线/空格）。
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
    // 文法分支全覆盖；本谓词是 xtask `is_dotted_id` 反向 delegate 的单源被委托方）。
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

    // BacklogSample::new funnel + 两访问器借出（非零值往返）。
    #[test]
    fn backlog_sample_new_exposes_fields() {
        let sample = BacklogSample::new(42, 305);
        assert_eq!(sample.depth(), 42);
        assert_eq!(sample.oldest_age_seconds(), 305);
    }

    // BacklogSample::empty 是 depth=0/age=0 规范零值（drain 后采样器置 0 gauge 的依据）。
    #[test]
    fn backlog_sample_empty_is_zero() {
        let empty = BacklogSample::empty();
        assert_eq!(empty.depth(), 0);
        assert_eq!(empty.oldest_age_seconds(), 0);
        assert_eq!(empty, BacklogSample::new(0, 0));
        // anti-vacuity：非空样本不等于 empty（双向验证 PartialEq）。
        assert_ne!(empty, BacklogSample::new(1, 0));
    }
}
