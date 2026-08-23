//! Outbox 接缝（L1 原子写 + L2 OutboxFact 投递）—— 纯类型 disposition + relay/sweep 策略。
//!
//! `Disposition`/`HandleResult`/`PermanentError`/`EventEntry`/`StoredOutboxEntry` 是
//! **纯态机类型**（sync，穷尽闭值集）；
//! `OutboxRelay` 是 L2 OutboxFact 引擎策略 trait（native AFIT：原子 claim 已持久化 entry 并中继到
//! broker）；`RetentionSweeper` 是同 crate 暂置的通用保留期维护 trait，可驱动 outbox /
//! inbox_receipts / dead_letter 等 durable 表清理。真实 broker I/O（AMQP）与 in-memory bus 在 `eventexec`/
//! adapters，consistency 只冻类型 + 策略接缝。
//! 语义见 `contracts/**/contract.toml`、`generated` 与 `crates/consistency`。
//!
//! # INVARIANT: OUTBOX-ENGINE-PORT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }
//!
//! `OutboxRelay`/`RetentionSweeper`/`OutboxBacklog` 是**引擎策略接缝**（签名引持久化 entry/
//! `Disposition`/`BacklogSample`/`EngineError` 等 consistency 内部类型），按 ADR-005 category line **不能**在
//! `diport` 内编译（否则 diport 反依赖引擎），故正确归属本引擎 crate——非 provider-agnostic 的 diport DI
//! port。native AFIT、不引 dynosaur。
//!
//! ref: ThreeDotsLabs/watermill message/router.go@master（Ack/Requeue/Reject disposition 概念对标）。

use sha2::{Digest, Sha256};

const OUTBOX_FACT_CANONICAL_VERSION: &str = "rss-outbox-fact-v1";
const FACT_TYPE_UTF8: u8 = 1;
const FACT_TYPE_BYTES: u8 = 2;
const FACT_TYPE_JSON: u8 = 3;
const FACT_OPTION_NONE: u8 = 0;
const FACT_OPTION_SOME: u8 = 1;

/// 一条 outbox durable fact 的完整、provider-neutral 身份。
///
/// 所有字段均为私有，唯一构造器要求调用方同时提供完整事实，避免新写路径遗漏某个身份维度。
/// metadata 顶层仅忽略可重试变化的 `occurredAt` / `trace` / `correlation`；嵌套同名键及
/// 其余内容都受 fingerprint 保护。
pub struct OutboxFactIdentity<'a> {
    event_id: &'a str,
    tenant_id: &'a str,
    domain: &'a str,
    topic: &'a str,
    contract_id: &'a str,
    contract_version: &'a str,
    schema_hash: &'a str,
    payload: &'a [u8],
    partition_key: Option<&'a str>,
    causation_id: Option<&'a str>,
    metadata: &'a serde_json::Value,
}

impl std::fmt::Debug for OutboxFactIdentity<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OutboxFactIdentity(<redacted>)")
    }
}

impl<'a> OutboxFactIdentity<'a> {
    /// 收口构造完整 outbox fact identity。
    #[allow(clippy::too_many_arguments)]
    // reason: 这是 AI-HARD 完整性门；将字段分散到可选 builder 会让漏算变成可表达状态。
    pub fn new(
        event_id: &'a str,
        tenant_id: &'a str,
        domain: &'a str,
        topic: &'a str,
        contract_id: &'a str,
        contract_version: &'a str,
        schema_hash: &'a str,
        payload: &'a [u8],
        partition_key: Option<&'a str>,
        causation_id: Option<&'a str>,
        metadata: &'a serde_json::Value,
    ) -> Self {
        Self {
            event_id,
            tenant_id,
            domain,
            topic,
            contract_id,
            contract_version,
            schema_hash,
            payload,
            partition_key,
            causation_id,
            metadata,
        }
    }

    /// 计算版本化 canonical SHA-256 fingerprint。
    pub fn fingerprint(&self) -> OutboxFactFingerprint {
        let mut canonical = Vec::new();
        append_required(
            &mut canonical,
            FACT_TYPE_UTF8,
            OUTBOX_FACT_CANONICAL_VERSION.as_bytes(),
        );
        append_required(&mut canonical, FACT_TYPE_UTF8, self.event_id.as_bytes());
        append_required(&mut canonical, FACT_TYPE_UTF8, self.tenant_id.as_bytes());
        append_required(&mut canonical, FACT_TYPE_UTF8, self.domain.as_bytes());
        append_required(&mut canonical, FACT_TYPE_UTF8, self.topic.as_bytes());
        append_required(&mut canonical, FACT_TYPE_UTF8, self.contract_id.as_bytes());
        append_required(
            &mut canonical,
            FACT_TYPE_UTF8,
            self.contract_version.as_bytes(),
        );
        append_required(&mut canonical, FACT_TYPE_UTF8, self.schema_hash.as_bytes());
        append_required(&mut canonical, FACT_TYPE_BYTES, self.payload);
        append_optional(
            &mut canonical,
            FACT_TYPE_UTF8,
            self.partition_key.map(str::as_bytes),
        );
        append_optional(
            &mut canonical,
            FACT_TYPE_UTF8,
            self.causation_id.map(str::as_bytes),
        );
        let metadata = canonical_metadata(self.metadata);
        append_required(&mut canonical, FACT_TYPE_JSON, &metadata);

        OutboxFactFingerprint(Sha256::digest(canonical).into())
    }
}

fn append_required(target: &mut Vec<u8>, type_tag: u8, value: &[u8]) {
    append_frame(target, type_tag, FACT_OPTION_SOME, value);
}

fn append_optional(target: &mut Vec<u8>, type_tag: u8, value: Option<&[u8]>) {
    match value {
        Some(value) => append_frame(target, type_tag, FACT_OPTION_SOME, value),
        None => append_frame(target, type_tag, FACT_OPTION_NONE, &[]),
    }
}

fn append_frame(target: &mut Vec<u8>, type_tag: u8, option_tag: u8, value: &[u8]) {
    target.push(type_tag);
    target.push(option_tag);
    let length = value.len() as u64;
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(value);
}

fn canonical_metadata(value: &serde_json::Value) -> Vec<u8> {
    let mut encoded = Vec::new();
    match value {
        serde_json::Value::Object(values) => {
            append_canonical_object(&mut encoded, values, true);
        }
        value => append_canonical_json(&mut encoded, value),
    }
    encoded
}

fn append_canonical_json(target: &mut Vec<u8>, value: &serde_json::Value) {
    match value {
        serde_json::Value::Null => target.extend_from_slice(b"null"),
        serde_json::Value::Bool(value) => {
            target.extend_from_slice(if *value { b"true" } else { b"false" });
        }
        serde_json::Value::Number(value) => append_canonical_number(target, value),
        serde_json::Value::String(value) => append_json_string(target, value),
        serde_json::Value::Array(values) => {
            target.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    target.push(b',');
                }
                append_canonical_json(target, value);
            }
            target.push(b']');
        }
        serde_json::Value::Object(values) => append_canonical_object(target, values, false),
    }
}

/// Freeze JSON numbers as an exact base-10 value, independent of parser or database rendering.
///
/// The canonical spelling is a non-zero integer coefficient with no leading/trailing zeroes,
/// followed by a signed base-10 exponent (`<coefficient>e<exponent>`). Zero, including negative
/// zero, is always `0e0`. `serde_json`'s `arbitrary_precision` feature preserves the input decimal
/// before this normalization; PostgreSQL applies the same transform to its exact `numeric` value.
fn append_canonical_number(target: &mut Vec<u8>, value: &serde_json::Number) {
    let rendered = value.to_string();
    let (negative, unsigned) = rendered
        .strip_prefix('-')
        .map_or((false, rendered.as_str()), |value| (true, value));
    let (significand, explicit_exponent) = match unsigned.split_once(['e', 'E']) {
        Some((significand, exponent)) => match exponent.parse::<i64>() {
            Ok(exponent) => (significand, exponent),
            Err(_) => {
                // Outside PostgreSQL numeric's bounded exponent domain. Keep a collision-free,
                // deterministic spelling; persistence fails closed before this can be stored.
                target.extend_from_slice(b"non-pg-number:");
                target.extend_from_slice(rendered.as_bytes());
                return;
            }
        },
        None => (unsigned, 0_i64),
    };
    let (integer, fraction) = significand
        .split_once('.')
        .map_or((significand, ""), |parts| parts);
    let mut digits = String::with_capacity(integer.len() + fraction.len());
    digits.push_str(integer);
    digits.push_str(fraction);
    let first_nonzero = digits.find(|character| character != '0');
    let Some(first_nonzero) = first_nonzero else {
        target.extend_from_slice(b"0e0");
        return;
    };
    let mut coefficient = &digits[first_nonzero..];
    let trailing_zeroes = coefficient.len() - coefficient.trim_end_matches('0').len();
    coefficient = coefficient.trim_end_matches('0');
    let exponent = i64::try_from(fraction.len()).ok().and_then(|fractional| {
        i64::try_from(trailing_zeroes).ok().and_then(|trailing| {
            explicit_exponent
                .checked_sub(fractional)
                .and_then(|exponent| exponent.checked_add(trailing))
        })
    });
    let Some(exponent) = exponent else {
        target.extend_from_slice(b"non-pg-number:");
        target.extend_from_slice(rendered.as_bytes());
        return;
    };
    if negative {
        target.push(b'-');
    }
    target.extend_from_slice(coefficient.as_bytes());
    target.push(b'e');
    target.extend_from_slice(exponent.to_string().as_bytes());
}

fn append_canonical_object(
    target: &mut Vec<u8>,
    values: &serde_json::Map<String, serde_json::Value>,
    filter_root_volatile: bool,
) {
    target.push(b'{');
    let mut keys: Vec<_> = values
        .keys()
        .filter(|key| !filter_root_volatile || !is_volatile_metadata_key(key))
        .collect();
    keys.sort_unstable();
    for (index, key) in keys.into_iter().enumerate() {
        if index != 0 {
            target.push(b',');
        }
        append_json_string(target, key);
        target.push(b':');
        append_canonical_json(target, &values[key]);
    }
    target.push(b'}');
}

fn append_json_string(target: &mut Vec<u8>, value: &str) {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    target.push(b'"');
    for character in value.chars() {
        match character {
            '"' => target.extend_from_slice(br#"\""#),
            '\\' => target.extend_from_slice(br"\\"),
            '\u{08}' => target.extend_from_slice(br"\b"),
            '\u{0c}' => target.extend_from_slice(br"\f"),
            '\n' => target.extend_from_slice(br"\n"),
            '\r' => target.extend_from_slice(br"\r"),
            '\t' => target.extend_from_slice(br"\t"),
            '\u{00}'..='\u{1f}' => {
                let code = character as u8;
                target.extend_from_slice(br"\u00");
                target.push(HEX[usize::from(code >> 4)]);
                target.push(HEX[usize::from(code & 0x0f)]);
            }
            character => {
                let mut buffer = [0_u8; 4];
                target.extend_from_slice(character.encode_utf8(&mut buffer).as_bytes());
            }
        }
    }
    target.push(b'"');
}

fn is_volatile_metadata_key(key: &str) -> bool {
    matches!(key, "occurredAt" | "trace" | "correlation")
}

/// Outbox fact 的不可伪造 SHA-256 fingerprint。
///
/// 无公开原始构造器；只能由 [`OutboxFactIdentity::fingerprint`] 产生。
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct OutboxFactFingerprint([u8; 32]);

impl OutboxFactFingerprint {
    /// 借出持久化/比较所需的 32-byte digest。
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for OutboxFactFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OutboxFactFingerprint(<redacted>)")
    }
}

/// 幂等 outbox append 的成功结果；事实冲突不属于成功结果。
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboxAppendOutcome {
    /// 首次插入 durable fact。
    Inserted,
    /// 相同 event id 已持久化为相同 durable fact。
    SameFact,
}

/// 相同 event id 已绑定到不同 durable fact。
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
#[error("outbox fact conflict")]
pub struct OutboxFactConflict;

/// 消费处置（穷尽闭值集，Hard 冻结；漏 case 编不过）。`contracts/**/contract.toml`、`generated` 与 `crates/consistency`。
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

/// 永久错误标记（私有字段；只是分类，不自动把 Requeue 改 Reject —— `contracts/**/contract.toml`、`generated` 与 `crates/consistency`）。
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

/// 写路径私有形态：`Requeue` 携静态摘要，`Reject` 携闭合 typed kind。
/// 公面仍是 [`HandleResult`] + 三构造器 funnel，禁裸枚举字面量绕过稳定分类。
#[derive(Debug)]
enum HandleInner {
    Ack,
    Requeue { summary: &'static str },
    Reject { kind: PermanentErrorKind },
}

/// 读路径穷尽形态：`Reject` 携 typed kind，`Requeue` 携 kind 摘要（Hard）。
///
/// ConsumerBase 经 [`HandleResult::as_settled`] 取得 DLX 摘要；ConsumerTx 保留 reject kind 的类型身份。
/// Requeue 摘要恒为 `&'static str` const（来自构造器内 `EngineErrorKind::message()`）。
///
/// **闭合值集**（非 `#[non_exhaustive]`）：结算协议三态固定；下游必须穷尽 match，新增变体强制编译失败
/// （对齐 `Cargo.toml`、`xtask/src/layers.rs`、`deny.toml` 与 `cargo xtask layer-deps` 值集冻结 Hard / `std::ops::ControlFlow`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Settled {
    /// 成功：无错误摘要。
    Ack,
    /// 瞬态失败：必携 engine kind 摘要。
    Requeue { summary: &'static str },
    /// 永久失败：携闭合 typed kind，调用方无需从摘要字符串反推分类。
    Reject { kind: PermanentErrorKind },
}

/// 业务 handler 结果（私有字段；禁裸 struct literal，经 `ack`/`requeue`/`reject` 构造器 —— `contracts/**/contract.toml`、`generated` 与 `crates/consistency`）。
///
/// 写路径经构造器把 `requeue` 的静态摘要与 `reject` 的 typed kind 嵌入 [`HandleInner`]；读路径经
/// [`HandleResult::as_settled`] 保留同一分类。ConsumerBase 只在 DLX funnel 将 reject kind 映射为
/// `PermanentErrorKind::message()`；ConsumerTx 可直接映射到规范 reject 类型。
///
/// # INVARIANT: OUTBOX-HANDLERESULT-CLASSIFICATION-01 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary", facet = "handle-inner-settled" }
///
/// `HandleInner`/[`Settled`] 杜绝 runtime `String` 与从字符串反推 reject 分类。
#[derive(Debug)]
pub struct HandleResult {
    inner: HandleInner,
}

impl HandleResult {
    /// 成功（无 error）。
    pub fn ack() -> Self {
        Self {
            inner: HandleInner::Ack,
        }
    }

    /// 瞬态失败 → 退避重试（携因由进引擎错误通道）。
    #[allow(clippy::needless_pass_by_value)]
    // reason: 签名冻结期 by-value 调用约定（caller 交出 error 所有权）；`error` 现被消费为 const-message 摘要
    // （`HandleInner::Requeue`），不再丢弃（#1125）。kind message 是 `&'static str` const，本纯态机不接 tracing 依赖。
    pub fn requeue(error: crate::error::EngineError) -> Self {
        Self {
            inner: HandleInner::Requeue {
                summary: error.kind().message(),
            },
        }
    }

    /// 永久失败 → DLX（携永久错误因由）。
    #[allow(clippy::needless_pass_by_value)]
    // reason: 同 `requeue`（签名冻结期 by-value 约定）；`error` 被消费为 const-message 摘要，不再丢弃（#1125）。
    pub fn reject(error: PermanentError) -> Self {
        Self {
            inner: HandleInner::Reject { kind: error.kind() },
        }
    }

    /// 读路径穷尽形态（失败变体保留稳定分类；ConsumerBase DLX / ConsumerTx 单源）。
    pub fn as_settled(&self) -> Settled {
        match self.inner {
            HandleInner::Ack => Settled::Ack,
            HandleInner::Requeue { summary } => Settled::Requeue { summary },
            HandleInner::Reject { kind } => Settled::Reject { kind },
        }
    }

    /// 处置（subscriber/relay 穷尽 match；由 [`as_settled`](Self::as_settled) 派生）。
    pub fn disposition(&self) -> Disposition {
        match self.as_settled() {
            Settled::Ack => Disposition::Ack,
            Settled::Requeue { .. } => Disposition::Requeue,
            Settled::Reject { .. } => Disposition::Reject,
        }
    }
}

/// 事件 producer topic（私有字段；稳定 dotted 名称且排除 command namespace）。
///
/// `EventTopic` 只存在于事件写路径。命令必须经 `eventexec` 的 reviewed command capability
/// 落库，因而 canonical `<domain>.commands.<name>` 在类型构造边界即被拒绝。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EventTopic(String);

/// `EventTopic` 解析错误。
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EventTopicError {
    #[error("topic name is empty")]
    Empty,
    #[error("topic name is not a canonical dotted name")]
    Format,
    /// Canonical command namespace is not an event authoring surface.
    #[error("command topic cannot be authored as an event")]
    CommandNamespace,
}

impl EventTopic {
    /// 解析稳定事件 topic；拒绝空、非 canonical 和 `<domain>.commands.<name>`。
    pub fn parse(raw: &str) -> Result<Self, EventTopicError> {
        if raw.is_empty() {
            return Err(EventTopicError::Empty);
        }
        if !is_canonical_topic_name(raw) {
            return Err(EventTopicError::Format);
        }
        if is_command_topic(raw) {
            return Err(EventTopicError::CommandNamespace);
        }
        Ok(Self(raw.to_string()))
    }

    /// 借出底层字符串视图。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn is_command_topic(raw: &str) -> bool {
    let mut segments = raw.split('.');
    matches!(
        (segments.next(), segments.next(), segments.next()),
        (Some(_), Some("commands"), Some(_))
    )
}

/// Topic rehydrated from durable storage. It has no public constructor and therefore cannot be
/// used as an event authoring capability.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StoredOutboxTopic(String);

impl StoredOutboxTopic {
    /// Borrow the persisted routing key.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Outbox metric contract id newtype（私有字段；稳定 dotted contract id）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OutboxContractId(String);

/// `OutboxContractId` 解析错误。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OutboxContractIdError {
    #[error("outbox contract id is empty")]
    Empty,
    #[error("outbox contract id is not a canonical dotted name")]
    Format,
}

impl OutboxContractId {
    /// 解析 outbox metric contract id；语法同 contract `id` dotted grammar。
    pub fn parse(raw: &str) -> Result<Self, OutboxContractIdError> {
        if raw.is_empty() {
            return Err(OutboxContractIdError::Empty);
        }
        if !is_canonical_topic_name(raw) {
            return Err(OutboxContractIdError::Format);
        }
        Ok(Self(raw.to_string()))
    }

    /// 借出底层字符串视图。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Canonical dotted topic/contract name predicate.
///
/// Non-empty; every dot-separated segment starts with `[a-z]` and contains only
/// `[a-z0-9-]`. This syntax predicate intentionally does not classify event versus command;
/// [`EventTopic::parse`] adds the event-only namespace rule.
pub fn is_canonical_topic_name(s: &str) -> bool {
    !s.is_empty()
        && s.split('.').all(|seg| {
            matches!(seg.bytes().next(), Some(b) if b.is_ascii_lowercase())
                && seg
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// 有序投递分区键 newtype（私有字段，构造经 fallible funnel）。
///
/// outbox 投递顺序保证的分区维度：设置时同 `(tenant_id, domain, partition_key)` 串行有序投递
///（head-of-partition gating，SQL 侧 `claim_batch` 收口——每 tenant partition 仅放行 min(seq)
/// 未投队头）；不设置（write 路径 `None` ⇒ DB NULL）= 无序要求，并行投递（行为同分区前）。等价
/// Debezium outbox 的 `aggregateid` / projection_events 的 `aggregate_id`——是**不透明聚合根路由键**，
/// 非 dotted topic，故只拒空（fail-closed），不施 dotted 文法。
///
/// tenant scope 由 outbox write 路径的 typed tenant 输入落入 `tenant_id` 列承载；相同 business key
/// 在不同 tenant 下不共享 head-of-partition gate，因此 producer 不需要把 tenant id 再拼入
/// `partition_key`。
///
/// 携带在 **write 路径**（`diport::OutboxEnvelopeParts` → adapter `OutboxEnvelope` → INSERT），**不**进
/// [`EventEntry`]（与 `domain` 同——分区键是投递路由属性，relay 读侧无需透传：顺序由 SQL gating 承载）。
///
/// **PII / 凭据边界**：业务选择的 partition key（如 sessionId）可能含**凭据级** bearer 标识
///（sessionId 即 bearer token），故 `PartitionKey` 的 `Debug` **脱敏为 `<redacted>`**（同
/// `identity::SessionId` 范式），不以明文经 `{:?}` 泄漏至日志 / 断言（F3，#1211 review）。定位 stalled
/// partition 经受控 DB 查询（`SELECT partition_key FROM outbox WHERE event_id=…`），非日志明文。
///
/// ref: debezium/debezium debezium-connect-plugins/src/main/java/io/debezium/transforms/outbox/EventRouterConfigDefinition.java
///   （`aggregateid` → message key → per-aggregate 有序投递）。
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PartitionKey(String);

impl std::fmt::Debug for PartitionKey {
    /// 脱敏 Debug：partition_key 可能凭据级（sessionId），明文经 `{:?}` 会泄漏至日志/断言（F3，#1211 review）。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PartitionKey(<redacted>)")
    }
}

/// `PartitionKey` 解析错误。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PartitionKeyError {
    #[error("partition key is empty")]
    Empty,
    #[error("partition key exceeds 256 bytes")]
    TooLong,
}

impl PartitionKey {
    /// 解析有序投递分区键；拒绝空 key 及超过 256 字节的 key（fail-closed）。
    ///
    /// 空 key 非法：DB 侧 `partition_key IS NULL` 已表达「无序要求」，空字符串会与 NULL 语义混淆
    /// 且让 head-of-partition gating 把所有空 key 行误并成一个 partition。故空经此 funnel 拒。
    ///
    /// 256 字节上限防止超长 key 膨胀 idx_outbox_partition_head 索引条目，同时与 DB `text` 列默认无限制
    /// 之间设置应用层防护（安全/防膨胀）。
    pub fn parse(raw: &str) -> Result<Self, PartitionKeyError> {
        if raw.is_empty() {
            return Err(PartitionKeyError::Empty);
        }
        if raw.len() > 256 {
            return Err(PartitionKeyError::TooLong);
        }
        Ok(Self(raw.to_string()))
    }

    /// 借出底层字符串视图。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 已审查可持久化的 outbox payload 字节。
///
/// 私有字段 + 命名构造器把「裸 `Vec<u8>`」从 [`EventEntry::new`] 公共边界移走；调用方必须在 generated DTO /
/// 领域事件编码完成后显式标记这些字节已过事件 payload 边界审查。`Debug` 恒脱敏，避免 outbox entry
/// 断言 / 日志把 payload 原文带出。
#[derive(Clone, PartialEq, Eq)]
pub struct OutboxPayload(Vec<u8>);

impl OutboxPayload {
    /// 从已审查的事件 payload 字节构造。
    pub fn from_reviewed_event_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// 借出底层字节，仅供存储 / 发布边界使用。
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// 消费式取回底层字节。
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl std::fmt::Debug for OutboxPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboxPayload")
            .field("len", &self.0.len())
            .field("bytes", &"<redacted>")
            .finish()
    }
}

/// 事件 producer 可写 outbox 条目。
///
/// topic 已由 [`EventTopic`] 在类型层排除 command namespace。engine 类型不 derive serde。
#[derive(Debug, Clone)]
pub struct EventEntry {
    topic: EventTopic,
    idem_key: crate::idempotency::IdemKey,
    payload: OutboxPayload,
}

impl EventEntry {
    /// 由事件 topic + 幂等 key + 已编码 payload 构造。
    pub fn new(
        topic: EventTopic,
        idem_key: crate::idempotency::IdemKey,
        payload: OutboxPayload,
    ) -> Self {
        Self {
            topic,
            idem_key,
            payload,
        }
    }

    /// 目标 topic。
    pub fn topic(&self) -> &EventTopic {
        &self.topic
    }

    /// 幂等 key。
    pub fn idem_key(&self) -> &crate::idempotency::IdemKey {
        &self.idem_key
    }

    /// 已编码 payload。
    pub fn payload(&self) -> &[u8] {
        self.payload.as_bytes()
    }
}

/// Durable outbox row reconstructed by an adapter for relay/readback.
///
/// This type is intentionally separate from [`EventEntry`]. There is no conversion from stored
/// data back into the event producer capability, so a command row read from storage cannot be
/// replayed through [`crate::outbox::EventEntry::new`].
#[derive(Debug, Clone)]
pub struct StoredOutboxEntry {
    topic: StoredOutboxTopic,
    idem_key: crate::idempotency::IdemKey,
    payload: OutboxPayload,
}

/// Persisted outbox row failed structural hydration.
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StoredOutboxEntryError {
    /// Persisted routing key is empty or not canonical.
    #[error("stored outbox topic is invalid")]
    Topic,
}

impl StoredOutboxEntry {
    /// Rehydrate a durable row. Command topics are accepted on the read side, but the returned
    /// type cannot enter the event producer port.
    pub fn hydrate(
        topic: impl Into<String>,
        idem_key: crate::idempotency::IdemKey,
        payload: OutboxPayload,
    ) -> Result<Self, StoredOutboxEntryError> {
        let topic = topic.into();
        if !is_canonical_topic_name(&topic) {
            return Err(StoredOutboxEntryError::Topic);
        }
        Ok(Self {
            topic: StoredOutboxTopic(topic),
            idem_key,
            payload,
        })
    }

    /// Borrow the persisted topic.
    pub fn topic(&self) -> &StoredOutboxTopic {
        &self.topic
    }

    /// Borrow the persisted idempotency key.
    pub fn idem_key(&self) -> &crate::idempotency::IdemKey {
        &self.idem_key
    }

    /// Borrow the persisted payload.
    pub fn payload(&self) -> &[u8] {
        self.payload.as_bytes()
    }
}

/// Outbox metric subject：tenant + contract 的低基数路由维度。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxMetricSubject {
    tenant_id: rss_request_context::TenantId,
    contract_id: OutboxContractId,
}

impl OutboxMetricSubject {
    /// 由已解析的 tenant / contract 构造 metric subject。
    pub fn new(tenant_id: rss_request_context::TenantId, contract_id: OutboxContractId) -> Self {
        Self {
            tenant_id,
            contract_id,
        }
    }

    /// 借出租户 id。
    pub fn tenant_id(&self) -> rss_request_context::TenantId {
        self.tenant_id
    }

    /// 借出 contract id。
    pub fn contract_id(&self) -> &OutboxContractId {
        &self.contract_id
    }
}

/// Provider-bound outbox claim + relay 策略（L1 引擎策略 trait，native AFIT）。
///
/// Provider 构造时绑定唯一 domain；调用方只能从该 domain claim **待发** entry 批次（status=pending 且到期，
/// 含 lease 过期可回收的 in-flight），不能在每次调用时注入 raw domain；已 claim entry 随后由同一
/// capability 按值中继到 broker（demo=进程内 bus / postgres=真实 broker，`contracts/**/contract.toml`、`generated` 与 `crates/consistency` topology-gated）。
/// SQL 在 adapter，本 crate 只冻接缝。native AFIT ⇒ 非 object-safe，消费方泛型 `<R: OutboxRelay>`，
/// 禁 `Box<dyn>`。
///
/// `Claim` 是 provider-owned opaque capability：adapter 只公开类型名，不公开构造器或 durable/lease
/// 字段。这样 production relay 只能消费同一 provider 的 `claim_batch` 返回值，调用方无法伪造或重建
/// claim。任一行 hydration 失败须回滚整个事务。
///
/// # INVARIANT: OUTBOX-CLAIM-RELAY-CAPABILITY-01 { level = "Hard", exec = "native-compile", source = "code", native = "single OutboxRelay associated Claim and by-value relay ownership" }
///
/// 单一 trait 在类型层强制 provider 同时提供 claim 与 relay，且两步共享同一个关联 `Claim` 类型；
/// `relay(Self::Claim)` 的按值参数使未声明 `Clone`/`Copy` 的 claim 不能被泛型调用方重复消费；adapter
/// 选用 distinct opaque `Claim` 时，raw [`StoredOutboxEntry`] 也不能冒充该 claim。该 Hard 约束只证明
/// **实现类型级**的 capability 配对与消费所有权：claim 是否确为 opaque、同类型不同 provider 实例间
/// 的 provenance、lease token/deadline CAS 与 broker I/O 语义仍必须由具体 adapter 的封装和行为守卫保证。
#[allow(async_fn_in_trait)]
// reason: native AFIT 引擎策略 trait 仅泛型静态分发消费，无 Send-bound 跨 await 持有问题；这是 ADR-003 既定范式。
pub trait OutboxRelay {
    /// Adapter 私有铸造、按值消费的 claim capability。
    type Claim;

    /// 借出指标 scope；durable relay context 与 lease 仍保持 provider-private。
    fn claim_subject(claim: &Self::Claim) -> &OutboxMetricSubject;

    /// 借出 provider 构造时绑定的唯一 domain；只用于路由/指标观察，不能由调用方改写。
    fn claim_domain(&self) -> &vocab::DomainName;

    /// 从 provider 绑定的 domain 原子 claim 至多 `limit` 条待发 entry（pending 且 `retry_after` 到期，或
    /// deadline 过期的 publishing 可回收行）。空 vec ⇒ 当前无待发。`Transient` 错误 ⇒ 本轮退避重扫。
    ///
    /// 若 adapter 走分区串行投递，须在此实现 head-of-partition gating：同
    /// `(tenant_id, domain, partition_key)` 仅放行 min(seq) 的队头行，确保同 tenant partition 内严格按
    /// seq 顺序投递。参见
    /// `INVARIANT: OUTBOX-PARTITION-ORDER-01` { level = "Medium", exec = "manual/opt-in", source = "code" }（定义在 adapter impl，`adapters/postgres/src/outbox.rs`
    /// `OutboxRelay for PgOutbox`）。
    async fn claim_batch(
        &self,
        limit: usize,
    ) -> Result<Vec<Self::Claim>, crate::error::EngineError>;

    /// 消费式中继单条已 claim entry。返回处置驱动 receipt commit / DLX / 退避（穷尽 `Disposition`）。
    async fn relay(&self, entry: Self::Claim) -> Result<Disposition, crate::error::EngineError>;
}

/// 保留期清理端口（L1 引擎策略 trait，native AFIT）——**跨 durable 表通用**。
///
/// 由 sweeper 背景 worker（`eventexec::sweeper_loop`）周期驱动：删除一张 durable 表中**已终结**且
/// 超过保留期的行，返回删除条数，防表无界增长。「已终结」由各 adapter impl 自行定义谓词——
/// - `outbox`：`status='published'`（已成功投递；dlx 行保留供运维巡检，不删）；
/// - `inbox_receipts`：`status='done'`（provider retention 窗口内的去重记录）；
/// - `dead_letter`：全部行（死信均终结，按 `last_attempt_at` 老化清理）。
///
/// 删除 SQL（含表名 + 终结谓词 + 时间列）在 adapter，本 crate 只冻接缝；时间谓词在 adapter 端用
/// DB `now()`（无跨进程偏移）。native AFIT ⇒ 非 object-safe，消费方泛型 `<S: RetentionSweeper>`，禁 `Box<dyn>`。
#[allow(async_fn_in_trait)]
// reason: native AFIT 引擎策略 trait 仅泛型静态分发消费，无 Send-bound 跨 await 持有问题；这是 ADR-003 既定范式。
pub trait RetentionSweeper {
    /// 删除该表中**已终结且** `<时间列>` 早于「现在 − `retain_seconds`」的行，返回删除条数。
    /// `Transient` 错误 ⇒ 本轮跳过、下轮重试。
    async fn sweep(&self, retain_seconds: u64) -> Result<u64, crate::error::EngineError>;
}

/// 单采样对象的 backlog 快照（纯标量值类型，sync 构造；不携 outbox entry）。
///
/// 供 outbox / inbox backlog 采样端口复用；具体统计集合由各自服务端口定义。
/// engine 类型——**不** derive serde（ADR-004 C6）；
/// 私有字段 + accessor。
///
/// backlog **drain/clear 后**（无可采样积压行）规范零值是 [`BacklogSample::empty`]（depth=0, age=0）——
/// 采样器据此把 gauge 置 0（而非缺失），否则 Prometheus 无法区分「积压清空」与「采样器死亡」。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BacklogSample {
    depth: u64,
    oldest_age_seconds: u64,
}

impl BacklogSample {
    /// 由 backlog 深度 + 最老积压龄（秒）构造。
    pub fn new(depth: u64, oldest_age_seconds: u64) -> Self {
        Self {
            depth,
            oldest_age_seconds,
        }
    }

    /// 空 backlog 规范零值（无可采样积压行：depth=0, age=0）。
    pub fn empty() -> Self {
        Self {
            depth: 0,
            oldest_age_seconds: 0,
        }
    }

    /// 当前 backlog 深度（采样集合内的积压行数）。
    pub fn depth(&self) -> u64 {
        self.depth
    }

    /// 最老积压行的龄（秒）；无可采样积压行 ⇒ 0。
    pub fn oldest_age_seconds(&self) -> u64 {
        self.oldest_age_seconds
    }
}

/// 单个 outbox metric subject 的 backlog 快照。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BacklogMetricSample {
    subject: OutboxMetricSubject,
    sample: BacklogSample,
    partition_blocked_depth: u64,
}

/// Ownership-aware result of one outbox backlog observation.
///
/// `Standby` is deliberately distinct from an active empty sample: only the active maintenance
/// lease holder may replace or clear the process-local gauge set.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "standby must not be interpreted as an active empty backlog sample"]
pub enum BacklogObservation {
    /// This process held the maintenance lease and completed a real provider sample.
    Active(Vec<BacklogMetricSample>),
    /// This process did not hold (or lost) the maintenance lease; no sample was observed.
    Standby,
}

impl BacklogMetricSample {
    /// 由 metric subject + backlog 标量构造 scoped backlog sample。
    pub fn new(subject: OutboxMetricSubject, sample: BacklogSample) -> Self {
        Self {
            subject,
            sample,
            partition_blocked_depth: 0,
        }
    }

    /// 由 metric subject + backlog 标量 + partition head-blocked 行数构造 scoped backlog sample。
    pub fn with_partition_blocked_depth(
        subject: OutboxMetricSubject,
        sample: BacklogSample,
        partition_blocked_depth: u64,
    ) -> Self {
        Self {
            subject,
            sample,
            partition_blocked_depth,
        }
    }

    /// 借出 metric subject。
    pub fn subject(&self) -> &OutboxMetricSubject {
        &self.subject
    }

    /// 借出 backlog 标量。
    pub fn sample(&self) -> BacklogSample {
        self.sample
    }

    /// 同 tenant/domain/contract 下因 partition 队头未 published 而被 head gate 阻塞的行数。
    pub fn partition_blocked_depth(&self) -> u64 {
        self.partition_blocked_depth
    }
}

/// Outbox 积压采样端口（L1 引擎策略 trait，native AFIT）。
///
/// 由可观测性采样背景 worker 周期驱动：聚合某 domain 的 pending 深度 + 最老 pending 龄，发射 backlog
/// gauge（#1209）。与 [`OutboxRelay`]（claim + 中继）/ [`RetentionSweeper`]（清理）同源构成 outbox
/// 背景机器的引擎接缝；聚合 SQL 在 adapter，本 crate 只冻接缝。读侧聚合端口，与 `claim_batch` 的行取
/// 扫描分离（不同访问形态、不同消费方），故独立 trait 而非扩 [`OutboxRelay`]。
/// native AFIT ⇒ 非 object-safe，消费方泛型 `<B: OutboxBacklog>`，禁 `Box<dyn>`。
#[allow(async_fn_in_trait)]
// reason: native AFIT 引擎策略 trait 仅泛型静态分发消费，无 Send-bound 跨 await 持有问题；这是 ADR-003 既定范式。
pub trait OutboxBacklog {
    /// 采样某 `domain` 的**可投递 backlog**（depth + 最老积压龄）。统计集合与 [`OutboxRelay::claim_batch`]
    /// 的可重捞集合**同源**：`(pending 且到期) OR (stale publishing，lease 过期可被 relay 重捞)`——stale
    /// publishing 会被重投，属可恢复积压必须计入；只排除 lease 仍有效的正常 in-flight，避免把正常中继中的行
    /// 误计入。已观测 `(tenant_id, contract_id)` scope 无可投递行 ⇒ [`BacklogObservation::Active`]
    /// 内带 [`BacklogSample::empty`] 的样本；从未出现或已被清理到无历史行的 scope 不返回样本。
    /// 未持有协调 lease 的 wrapper 返回 [`BacklogObservation::Standby`]，不得压成 active 空样本；
    /// `Transient` 错误 ⇒ 本轮跳过采样。
    ///
    /// head-of-partition gate 是 **claim-only by design**——被 gate 的后继仍计入 backlog depth（否则 stalled
    /// partition 对 SLO 失明），故 backlog 谓词刻意不含 head-of-partition gate（#1211）。
    async fn sample_backlog(
        &self,
        domain: &str,
    ) -> Result<BacklogObservation, crate::error::EngineError>;
}

#[cfg(test)]
mod tests {
    use super::{
        BacklogMetricSample, BacklogSample, Disposition, EventEntry, EventTopic, EventTopicError,
        HandleResult, OUTBOX_FACT_CANONICAL_VERSION, OutboxAppendOutcome, OutboxContractId,
        OutboxContractIdError, OutboxFactConflict, OutboxFactIdentity, OutboxMetricSubject,
        OutboxPayload, PartitionKey, PartitionKeyError, PermanentError, PermanentErrorKind,
        Settled, StoredOutboxEntry, append_canonical_json,
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

    // ack/requeue/reject 构造器置正确 disposition（分类保留见 handle_result_preserves_failure_classification）。
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

    // reject/requeue 经 as_settled() 保留 typed kind / 静态摘要；ack → Settled::Ack。
    // Requeue 摘要恒 `&'static str` const，无 runtime 数据 ⇒ PII-safe。
    // Hard 真源见同文件 production INVARIANT OUTBOX-HANDLERESULT-CLASSIFICATION-01（native-compile）。
    #[test]
    fn handle_result_preserves_failure_classification() {
        assert_eq!(HandleResult::ack().as_settled(), Settled::Ack);

        // requeue：穷举 EngineErrorKind 全部变体 → 各自 const message（kind 增变体时本表须同步）。
        let requeue_cases: &[(EngineErrorKind, &str)] = &[
            (EngineErrorKind::Transient, "transient engine error"),
            (EngineErrorKind::Permanent, "permanent engine error"),
            (EngineErrorKind::Invariant, "engine invariant violated"),
        ];
        for &(kind, expected) in requeue_cases {
            assert_eq!(
                HandleResult::requeue(EngineError::new(kind)).as_settled(),
                Settled::Requeue { summary: expected },
                "requeue kind={kind:?}"
            );
        }

        // reject：穷举 PermanentErrorKind 全部变体 → 保留 typed identity。
        let reject_cases = [PermanentErrorKind::Permanent, PermanentErrorKind::Invariant];
        for kind in reject_cases {
            assert_eq!(
                HandleResult::reject(PermanentError::new(kind)).as_settled(),
                Settled::Reject { kind },
                "reject kind={kind:?}"
            );
        }

        // anti-vacuity：不同 kind → 不同摘要（摘要随 kind 变化，非硬编码常量）——requeue / reject 各验一次。
        assert_ne!(
            HandleResult::requeue(EngineError::new(EngineErrorKind::Transient)).as_settled(),
            HandleResult::requeue(EngineError::new(EngineErrorKind::Permanent)).as_settled()
        );
        assert_ne!(
            HandleResult::reject(PermanentError::new(PermanentErrorKind::Permanent)).as_settled(),
            HandleResult::reject(PermanentError::new(PermanentErrorKind::Invariant)).as_settled()
        );
    }

    // canonical dotted 接受（文法单源，xtask is_dotted_id 反向 delegate 此处；含单段 foo）+ as_str 往返。
    #[test]
    #[allow(clippy::unwrap_used)]
    // reason: 测试 happy-path 断言已 is_ok 的 parse 结果，item-level carve-out。
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
            assert!(
                EventTopic::parse(raw).is_ok(),
                "expected Ok for raw={raw:?}"
            );
            let topic = EventTopic::parse(raw).unwrap();
            assert_eq!(topic.as_str(), raw, "raw={raw:?}");
        }
    }

    // 空 → Empty。
    #[test]
    fn topic_parse_rejects_empty() {
        assert!(matches!(EventTopic::parse(""), Err(EventTopicError::Empty)));
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
                matches!(EventTopic::parse(raw), Err(EventTopicError::Format)),
                "expected Format for raw={raw:?}"
            );
        }
    }

    #[test]
    fn event_topic_rejects_command_namespace() {
        assert!(EventTopic::parse("identity.session-created").is_ok());
        assert!(matches!(
            EventTopic::parse("seed.commands.do-thing"),
            Err(EventTopicError::CommandNamespace)
        ));
        assert!(EventTopic::parse("commands.seed.do-thing").is_ok());
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: known canonical persisted row fixtures.
    fn stored_entry_hydrates_commands_without_event_authoring_conversion() {
        let key = IdemKey::parse("command-1").expect("key");
        let stored = StoredOutboxEntry::hydrate(
            "seed.commands.do-thing",
            key,
            OutboxPayload::from_reviewed_event_bytes(vec![1, 2]),
        )
        .expect("canonical persisted command");
        assert_eq!(stored.topic().as_str(), "seed.commands.do-thing");
        assert_eq!(stored.payload(), &[1, 2]);
        assert!(
            StoredOutboxEntry::hydrate(
                "not canonical",
                IdemKey::parse("command-2").expect("key"),
                OutboxPayload::from_reviewed_event_bytes(Vec::new()),
            )
            .is_err()
        );
    }

    // OutboxContractId 复用 canonical dotted grammar：接受 contract id 常见形态并往返。
    #[test]
    #[allow(clippy::unwrap_used)]
    // reason: 测试 happy-path 断言已知合法输入，item-level carve-out。
    fn outbox_contract_id_accepts_canonical_dotted_and_round_trips() {
        let cases: &[&str] = &[
            "identity.session-created",
            "settings.config-version-changed",
            "seed.thing-happened",
            "foo",
        ];
        for &raw in cases {
            let id = OutboxContractId::parse(raw).unwrap();
            assert_eq!(id.as_str(), raw);
        }
    }

    #[test]
    fn outbox_contract_id_rejects_empty() {
        assert!(matches!(
            OutboxContractId::parse(""),
            Err(OutboxContractIdError::Empty)
        ));
    }

    #[test]
    fn outbox_contract_id_rejects_invalid_format() {
        for raw in [
            ".x",
            "x.",
            "a..b",
            "Identity.session-created",
            "identity.SessionCreated",
            "1identity.session-created",
            "identity._session",
            "identity.session created",
        ] {
            assert!(
                matches!(
                    OutboxContractId::parse(raw),
                    Err(OutboxContractIdError::Format)
                ),
                "expected Format for raw={raw:?}"
            );
        }
    }

    // 私有文法谓词独立语义（`parse` 已前置拒空，此处守 helper 独立调用时空串短路 false 分支，
    // 文法分支全覆盖；本谓词是 xtask `is_dotted_id` 反向 delegate 的单源被委托方）。
    #[test]
    fn is_canonical_dotted_standalone() {
        assert!(!super::is_canonical_topic_name(""));
        assert!(super::is_canonical_topic_name("a.b"));
        assert!(super::is_canonical_topic_name("foo"));
        assert!(!super::is_canonical_topic_name("a..b"));
    }

    // EventEntry::new funnel + 三访问器借出。
    #[test]
    #[allow(clippy::unwrap_used)]
    // reason: 测试 happy-path 断言已 is_ok 的 parse 结果，item-level carve-out。
    fn entry_new_exposes_fields() {
        let topic = EventTopic::parse("session.created").unwrap();
        let key = IdemKey::parse("evt-1").unwrap();
        let payload = vec![1u8, 2, 3];
        let entry = EventEntry::new(
            topic.clone(),
            key.clone(),
            OutboxPayload::from_reviewed_event_bytes(payload.clone()),
        );
        assert_eq!(entry.topic(), &topic);
        assert_eq!(entry.idem_key(), &key);
        assert_eq!(entry.payload(), payload.as_slice());
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    // reason: happy-path 构造值均为已知合法常量。
    fn metric_samples_expose_scope() {
        let tenant =
            rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap();
        let contract_id = OutboxContractId::parse("identity.session-created").unwrap();
        let subject = OutboxMetricSubject::new(tenant, contract_id.clone());
        assert_eq!(subject.tenant_id(), tenant);
        assert_eq!(subject.contract_id(), &contract_id);

        let backlog = BacklogMetricSample::new(subject.clone(), BacklogSample::empty());
        assert_eq!(backlog.subject(), &subject);
        assert_eq!(backlog.sample(), BacklogSample::empty());
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    // reason: 测试 happy-path 断言已 is_ok 的 parse 结果，item-level carve-out。
    fn entry_debug_redacts_payload_marker() {
        let topic = EventTopic::parse("session.created").unwrap();
        let key = IdemKey::parse("evt-redact").unwrap();
        let entry = EventEntry::new(
            topic,
            key,
            OutboxPayload::from_reviewed_event_bytes(b"SECRET_PAYLOAD_MARKER".to_vec()),
        );
        let dbg = format!("{entry:?}");
        assert!(
            !dbg.contains("SECRET_PAYLOAD_MARKER"),
            "EventEntry Debug must not leak payload bytes: {dbg}"
        );
        assert!(
            dbg.contains("<redacted>"),
            "redaction marker missing: {dbg}"
        );
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

    // PartitionKey::parse 接受非空键并 as_str 往返（多值表驱动）。
    #[test]
    #[allow(clippy::unwrap_used)]
    // reason: 测试 happy-path 断言已知非空输入的 parse 结果，item-level carve-out。
    fn partition_key_parse_accepts_nonempty_and_round_trips() {
        let cases = ["session-42", "device:abc-123", "聚合根", "a"];
        for raw in cases {
            let key = PartitionKey::parse(raw).unwrap();
            assert_eq!(key.as_str(), raw, "round-trip raw={raw}");
        }
    }

    // PartitionKey::parse 拒空键（fail-closed，避免与 DB NULL「无序」语义混淆）。
    #[test]
    fn partition_key_parse_rejects_empty() {
        assert!(matches!(
            PartitionKey::parse(""),
            Err(PartitionKeyError::Empty)
        ));
    }

    // PartitionKey::parse 拒超过 256 字节的 key（防索引膨胀；256 字节边界：257 拒、256 接受）。
    #[test]
    #[allow(clippy::unwrap_used)]
    // reason: 测试 256 字节边界值的 happy-path，item-level carve-out。
    fn partition_key_parse_rejects_overlong() {
        // 257 字节 → TooLong。
        let overlong = "a".repeat(257);
        assert!(
            matches!(
                PartitionKey::parse(&overlong),
                Err(PartitionKeyError::TooLong)
            ),
            "257 字节 key 应被拒（TooLong）"
        );
        // 256 字节边界 → 接受。
        let exactly_256 = "a".repeat(256);
        assert!(
            PartitionKey::parse(&exactly_256).is_ok(),
            "256 字节 key 应被接受"
        );
        let key = PartitionKey::parse(&exactly_256).unwrap();
        assert_eq!(key.as_str().len(), 256, "as_str 长度应为 256");
    }

    // PartitionKey Eq/Hash：同值相等、异值不等（head-of-partition 同 partition 归并依赖值相等语义）。
    #[test]
    #[allow(clippy::unwrap_used)]
    // reason: 同上，测试已知非空输入。
    fn partition_key_eq_distinguishes_values() {
        let a1 = PartitionKey::parse("p1").unwrap();
        let a2 = PartitionKey::parse("p1").unwrap();
        let b = PartitionKey::parse("p2").unwrap();
        assert_eq!(a1, a2);
        assert_ne!(a1, b);
    }

    // PartitionKey Debug 脱敏：明文值不得经 {:?} 泄漏（F3，#1211 review；同 SessionId 范式）。
    #[test]
    #[allow(clippy::unwrap_used)]
    // reason: 测试已知非空输入。
    fn partition_key_debug_redacts_value() {
        let key = PartitionKey::parse("tenant-7:session-secret").unwrap();
        let dbg = format!("{key:?}");
        assert_eq!(dbg, "PartitionKey(<redacted>)");
        // anti-vacuity：明文值不出现在 Debug 输出。
        assert!(!dbg.contains("session-secret"), "凭据级值不得泄漏: {dbg}");
    }

    fn fact<'a>(
        payload: &'a [u8],
        partition_key: Option<&'a str>,
        causation_id: Option<&'a str>,
        metadata: &'a serde_json::Value,
    ) -> OutboxFactIdentity<'a> {
        OutboxFactIdentity::new(
            "evt-1739",
            "f47ac10b-58cc-4372-a567-0e02b2c3d479",
            "identity",
            "identity.session-created",
            "identity.session-created",
            "v1",
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            payload,
            partition_key,
            causation_id,
            metadata,
        )
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct OutboxFactGoldenFixture {
        schema_version: u32,
        canonical_version: String,
        cases: Vec<OutboxFactGoldenCase>,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct OutboxFactGoldenCase {
        label: String,
        event_id: String,
        tenant_id: String,
        domain: String,
        topic: String,
        contract_id: String,
        contract_version: String,
        schema_hash: String,
        payload: Vec<u8>,
        partition_key: Option<String>,
        causation_id: Option<String>,
        metadata: serde_json::Value,
        expected_digest: [u8; 32],
    }

    #[allow(clippy::expect_used)]
    // reason: committed test fixture parse failure is itself the focused test failure.
    fn outbox_fact_golden_fixture() -> OutboxFactGoldenFixture {
        serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/consistency/outbox-fact-v1-vectors.json"
        )))
        .expect("outbox fact v1 golden fixture must be valid")
    }

    #[test]
    fn outbox_fact_fingerprint_is_canonical_and_unambiguous() {
        let metadata = serde_json::json!({
            "actor": {"kind": "user", "id": "subject-1", "scope": "tenant"},
            "subjectId": "subject-1",
            "tenantId": "f47ac10b-58cc-4372-a567-0e02b2c3d479"
        });
        let base = fact(b"payload", Some("partition-a"), Some("cause-a"), &metadata).fingerprint();
        assert_eq!(base.as_bytes().len(), 32);

        let split_a = fact(b"ab\0c", Some("partition-a"), None, &metadata).fingerprint();
        let split_b = fact(b"a\0bc", Some("partition-a"), None, &metadata).fingerprint();
        assert_ne!(
            split_a, split_b,
            "length framing must prevent concatenation collisions"
        );
        assert_ne!(
            fact(b"payload", None, None, &metadata).fingerprint(),
            fact(b"payload", Some(""), None, &metadata).fingerprint(),
            "None and Some(empty) must have distinct option tags"
        );
    }

    #[test]
    fn outbox_fact_fingerprint_matches_v1_known_vectors() {
        let fixture = outbox_fact_golden_fixture();
        assert_eq!(fixture.schema_version, 1);
        assert_eq!(fixture.canonical_version, OUTBOX_FACT_CANONICAL_VERSION);
        assert!(!fixture.cases.is_empty());
        for case in fixture.cases {
            let actual = OutboxFactIdentity::new(
                &case.event_id,
                &case.tenant_id,
                &case.domain,
                &case.topic,
                &case.contract_id,
                &case.contract_version,
                &case.schema_hash,
                &case.payload,
                case.partition_key.as_deref(),
                case.causation_id.as_deref(),
                &case.metadata,
            )
            .fingerprint();
            assert_eq!(
                actual.as_bytes(),
                &case.expected_digest,
                "fixed digest: {}",
                case.label
            );
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: committed literal JSON numbers are known-valid test inputs.
    fn outbox_fact_numbers_have_frozen_exact_decimal_spelling() {
        let cases = [
            ("1e2", "1e2"),
            ("100.0", "1e2"),
            ("1.2300", "123e-2"),
            ("1.23", "123e-2"),
            ("1e-7", "1e-7"),
            ("-0", "0e0"),
            ("9007199254740993", "9007199254740993e0"),
        ];
        for (raw, expected) in cases {
            let value: serde_json::Value = serde_json::from_str(raw).expect("valid JSON number");
            let mut encoded = Vec::new();
            append_canonical_json(&mut encoded, &value);
            assert_eq!(encoded, expected.as_bytes(), "exact decimal: {raw}");
        }
    }

    #[test]
    fn outbox_fact_fingerprint_ignores_only_volatile_metadata() {
        let first = serde_json::json!({
            "occurredAt": 1,
            "trace": "trace-a",
            "correlation": "corr-a",
            "subjectId": "subject-1",
            "actor": {"kind": "user", "id": "actor-1"}
        });
        let retried = serde_json::json!({
            "actor": {"id": "actor-1", "kind": "user"},
            "subjectId": "subject-1",
            "correlation": "corr-b",
            "trace": "trace-b",
            "occurredAt": 999
        });
        assert_eq!(
            fact(b"payload", Some("partition-a"), None, &first).fingerprint(),
            fact(b"payload", Some("partition-a"), None, &retried).fingerprint()
        );

        let changed_actor = serde_json::json!({
            "subjectId": "subject-1",
            "actor": {"kind": "user", "id": "actor-2"}
        });
        assert_ne!(
            fact(b"payload", Some("partition-a"), None, &first).fingerprint(),
            fact(b"payload", Some("partition-a"), None, &changed_actor).fingerprint()
        );

        let nested_trace_a = serde_json::json!({"actor": {"trace": "stable-a"}});
        let nested_trace_b = serde_json::json!({"actor": {"trace": "stable-b"}});
        assert_ne!(
            fact(b"payload", None, None, &nested_trace_a).fingerprint(),
            fact(b"payload", None, None, &nested_trace_b).fingerprint(),
            "volatile exclusions apply only to metadata root"
        );

        let differently_cased_key = serde_json::json!({"Trace": "stable-a"});
        let differently_cased_key_changed = serde_json::json!({"Trace": "stable-b"});
        assert_ne!(
            fact(b"payload", None, None, &differently_cased_key).fingerprint(),
            fact(b"payload", None, None, &differently_cased_key_changed).fingerprint(),
            "only the three exact root keys are volatile"
        );
    }

    #[test]
    fn outbox_fact_metadata_canonicalizes_nested_objects_but_preserves_array_order_and_types() {
        let sorted_differently = serde_json::json!({
            "nested": {"z": "line\n\"quoted\"", "a": "你好"},
            "items": [1, "1", null, true]
        });
        let same_fact = serde_json::json!({
            "items": [1, "1", null, true],
            "nested": {"a": "你好", "z": "line\n\"quoted\""}
        });
        assert_eq!(
            fact(b"payload", None, None, &sorted_differently).fingerprint(),
            fact(b"payload", None, None, &same_fact).fingerprint()
        );

        let reordered_array = serde_json::json!({
            "nested": {"a": "你好", "z": "line\n\"quoted\""},
            "items": ["1", 1, null, true]
        });
        assert_ne!(
            fact(b"payload", None, None, &same_fact).fingerprint(),
            fact(b"payload", None, None, &reordered_array).fingerprint()
        );
    }

    #[test]
    fn outbox_fact_fingerprint_protects_every_fact_component() {
        let metadata = serde_json::json!({"subjectId": "subject-1"});
        let baseline =
            fact(b"payload", Some("partition-a"), Some("cause-a"), &metadata).fingerprint();
        let changed_metadata = serde_json::json!({"subjectId": "subject-2"});
        let changed = [
            OutboxFactIdentity::new(
                "evt-other",
                "f47ac10b-58cc-4372-a567-0e02b2c3d479",
                "identity",
                "identity.session-created",
                "identity.session-created",
                "v1",
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                b"payload",
                Some("partition-a"),
                Some("cause-a"),
                &metadata,
            )
            .fingerprint(),
            OutboxFactIdentity::new(
                "evt-1739",
                "00000000-0000-4000-8000-000000000abc",
                "identity",
                "identity.session-created",
                "identity.session-created",
                "v1",
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                b"payload",
                Some("partition-a"),
                Some("cause-a"),
                &metadata,
            )
            .fingerprint(),
            OutboxFactIdentity::new(
                "evt-1739",
                "f47ac10b-58cc-4372-a567-0e02b2c3d479",
                "settings",
                "identity.session-created",
                "identity.session-created",
                "v1",
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                b"payload",
                Some("partition-a"),
                Some("cause-a"),
                &metadata,
            )
            .fingerprint(),
            OutboxFactIdentity::new(
                "evt-1739",
                "f47ac10b-58cc-4372-a567-0e02b2c3d479",
                "identity",
                "identity.other",
                "identity.session-created",
                "v1",
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                b"payload",
                Some("partition-a"),
                Some("cause-a"),
                &metadata,
            )
            .fingerprint(),
            OutboxFactIdentity::new(
                "evt-1739",
                "f47ac10b-58cc-4372-a567-0e02b2c3d479",
                "identity",
                "identity.session-created",
                "identity.other",
                "v1",
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                b"payload",
                Some("partition-a"),
                Some("cause-a"),
                &metadata,
            )
            .fingerprint(),
            OutboxFactIdentity::new(
                "evt-1739",
                "f47ac10b-58cc-4372-a567-0e02b2c3d479",
                "identity",
                "identity.session-created",
                "identity.session-created",
                "v2",
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                b"payload",
                Some("partition-a"),
                Some("cause-a"),
                &metadata,
            )
            .fingerprint(),
            OutboxFactIdentity::new(
                "evt-1739",
                "f47ac10b-58cc-4372-a567-0e02b2c3d479",
                "identity",
                "identity.session-created",
                "identity.session-created",
                "v1",
                "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                b"payload",
                Some("partition-a"),
                Some("cause-a"),
                &metadata,
            )
            .fingerprint(),
            fact(
                b"payload-other",
                Some("partition-a"),
                Some("cause-a"),
                &metadata,
            )
            .fingerprint(),
            fact(b"payload", Some("partition-b"), Some("cause-a"), &metadata).fingerprint(),
            fact(b"payload", Some("partition-a"), Some("cause-b"), &metadata).fingerprint(),
            fact(
                b"payload",
                Some("partition-a"),
                Some("cause-a"),
                &changed_metadata,
            )
            .fingerprint(),
        ];
        assert!(changed.iter().all(|candidate| candidate != &baseline));
    }

    #[test]
    fn outbox_fact_types_redact_and_outcomes_are_closed() {
        let metadata = serde_json::json!({"subjectId": "SECRET_SUBJECT_MARKER"});
        let identity = fact(
            b"SECRET_PAYLOAD_MARKER",
            Some("SECRET_PARTITION_MARKER"),
            Some("SECRET_CAUSATION_MARKER"),
            &metadata,
        );
        let fingerprint = identity.fingerprint();
        for rendered in [format!("{identity:?}"), format!("{fingerprint:?}")] {
            assert!(rendered.contains("<redacted>"));
            assert!(!rendered.contains("SECRET_"));
        }
        let conflict = OutboxFactConflict;
        assert_eq!(conflict.to_string(), "outbox fact conflict");
        assert!(!format!("{conflict:?}").contains("SECRET_"));
        assert_ne!(OutboxAppendOutcome::Inserted, OutboxAppendOutcome::SameFact);
    }
}
