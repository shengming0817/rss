//! 统一 delivery envelope metadata —— producer→broker→consumer wire-faithful 元数据袋。
//!
//! [`EnvelopeMetadata`] 双侧共用：[`crate::PublishRequest`]（producer→broker）+ [`crate::Message`]
//! （broker→consumer）。wire-faithful `string→string`（broker header 通用形态：AMQP `FieldTable`
//! LongString / MQTT v5 user-property），key 集随消费域细化（pre-GA 可原地加）。
//!
//! # 两层写面（与 `adapters/postgres` 的 `OUTBOX-METADATA-FUNNEL-01` 同构）
//!
//! - **业务 free-form**（[`EnvelopeMetadata::try_insert`]）：reserved key（[`RESERVED_METADATA_KEYS`]）
//!   fail-closed 拒——业务经此入口伪造 reserved key 从**类型层不可表达**（Hard）。
//! - **adapter 透传**（[`EnvelopeMetadata::insert_wire_pair`]）：relay 从 `outbox.metadata` 列 /
//!   subscriber 从 broker header 逐对 rehydrate（含 reserved），来源已 sealed。`pub`（跨 crate adapter 须调），
//!   调用站点由 dylint `rss_diport_envelope_reserved_writer` 限到 adapter / 组合根（Medium，
//!   INVARIANT: DIPORT-ENVELOPE-WIRE-WRITER-01 { level = "Medium", exec = "manual/opt-in", source = "code" }）。
//!
//! **真正的 Hard 锚点在 emit 层**：域只经 [`crate::OutboxEmitter::emit`]（入参 [`crate::OutboxEnvelopeParts`]
//! 无 reserved 槽）发事件，**永不**构造 wire envelope 的 reserved 面——wire 层 reserved 写仅是 relay /
//! subscriber 从已 sealed 来源透传，故 wire 层只需 Medium 防御性 confine。
//!
//! ref: Debezium Outbox Event Router（outbox 行 id + 附加列 → emitted event header）；CloudEvents binary
//! content-mode（context attributes `id`/`time`/`source` → transport header）；MassTransit envelope headers bag。

use std::collections::BTreeMap;

/// envelope reserved key 单源（producer funnel + wire funnel + adapter 映射共用，消除漂移）。
/// 业务 [`EnvelopeMetadata::try_insert`] 对这些 key fail-closed 拒；只 adapter 受控注入点可写。
pub const RESERVED_METADATA_KEYS: [&str; 10] = [
    KEY_TRACE,
    KEY_CORRELATION,
    KEY_PRINCIPAL,
    KEY_ACTOR,
    KEY_SUBJECT_ID,
    KEY_OCCURRED_AT,
    KEY_TENANT_ID,
    KEY_TENANT_AUTHORITY,
    KEY_SCHEMA_VERSION,
    KEY_SCHEMA_HASH,
];

/// reserved：事件发生时刻（unix 秒，十进制 string）。producer 经注入 `Clock` 必填（#1129）。
pub const KEY_OCCURRED_AT: &str = "occurredAt";
/// reserved：分布式 trace（W3C `traceparent`，含 trace_id；源经 `tracewire::capture` 注入，已接线 #1224）。
pub const KEY_TRACE: &str = "trace";
/// reserved：跨服务关联 id（源经 `diagctx` ambient 注入，已接线 #1160）。
pub const KEY_CORRELATION: &str = "correlation";
/// reserved：opaque principal（源待安全决策，本轮仅留 slot）。
pub const KEY_PRINCIPAL: &str = "principal";
/// reserved：最小化 actor envelope（persisted-only；不进 broker header）。
pub const KEY_ACTOR: &str = "actor";
/// reserved：canonical tenant id（认证 / co-tx 边界盖章，消费 DLX / RLS scope 使用）。
pub const KEY_TENANT_ID: &str = "tenantId";
/// reserved：tenant authority token（relay 签发，consumer 写 DLX 前验签）。
pub const KEY_TENANT_AUTHORITY: &str = "tenantAuthority";
/// reserved：opaque 事件主体标识（persisted-only；业务不能经 free-form metadata 写入）。
pub const KEY_SUBJECT_ID: &str = "subjectId";
/// reserved：契约版本（`v{N}`），由 codegen 契约绑定盖章。
pub const KEY_SCHEMA_VERSION: &str = "schemaVersion";
/// reserved：声明 schema bundle 摘要（`sha256:<64 lowercase hex>`），由 codegen 契约绑定盖章。
pub const KEY_SCHEMA_HASH: &str = "schemaHash";

/// [`EnvelopeMetadata::try_insert`] 失败原因。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MetadataError {
    /// 业务写入口命中 reserved key（[`RESERVED_METADATA_KEYS`]）——只 adapter 受控注入点可写。
    #[error("reserved envelope metadata key is not allowed for business writers")]
    ReservedKey,
}

/// Envelope header 构造 / rehydrate 失败原因。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EnvelopeHeaderError {
    /// transport metadata 缺 canonical tenant id。
    #[error("missing envelope metadata key tenantId")]
    MissingTenantId,
    /// transport metadata 携带的 tenant id 非 canonical UUID。
    #[error("invalid envelope metadata key tenantId")]
    InvalidTenantId,
    /// transport metadata 缺 schema version。
    #[error("missing envelope metadata key schemaVersion")]
    MissingSchemaVersion,
    /// schema version 非 `v{{N}}`。
    #[error("invalid envelope metadata key schemaVersion")]
    InvalidSchemaVersion,
    /// transport metadata 缺 schema hash。
    #[error("missing envelope metadata key schemaHash")]
    MissingSchemaHash,
    /// schema hash 非 `sha256:<64 lowercase hex>`。
    #[error("invalid envelope metadata key schemaHash")]
    InvalidSchemaHash,
    /// schema version 与消费侧期望契约不一致。
    #[error("envelope metadata schemaVersion does not match expected contract")]
    SchemaVersionMismatch,
    /// schema hash 与消费侧期望契约不一致。
    #[error("envelope metadata schemaHash does not match expected contract")]
    SchemaHashMismatch,
}

/// 契约版本 header 值（`v{N}`）。
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct EnvelopeSchemaVersion(String);

impl EnvelopeSchemaVersion {
    /// 解析契约版本；只接受 `v` + 非空 ASCII 数字。
    pub fn parse(raw: impl Into<String>) -> Result<Self, EnvelopeHeaderError> {
        let raw = raw.into();
        if is_schema_version(&raw) {
            Ok(Self(raw))
        } else {
            Err(EnvelopeHeaderError::InvalidSchemaVersion)
        }
    }

    /// 借出 header 字符串。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for EnvelopeSchemaVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("EnvelopeSchemaVersion")
            .field(&self.as_str())
            .finish()
    }
}

impl std::fmt::Display for EnvelopeSchemaVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 声明 schema bundle 摘要 header 值（`sha256:<64 lowercase hex>`）。
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct EnvelopeSchemaHash(String);

impl EnvelopeSchemaHash {
    /// 解析 schema 摘要；只接受 `sha256:` + 64 位小写 hex。
    pub fn parse(raw: impl Into<String>) -> Result<Self, EnvelopeHeaderError> {
        let raw = raw.into();
        if is_schema_hash(&raw) {
            Ok(Self(raw))
        } else {
            Err(EnvelopeHeaderError::InvalidSchemaHash)
        }
    }

    /// 借出 header 字符串。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for EnvelopeSchemaHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("EnvelopeSchemaHash")
            .field(&self.as_str())
            .finish()
    }
}

impl std::fmt::Display for EnvelopeSchemaHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 标准 delivery envelope header。
///
/// `tenantId` / `schemaVersion` / `schemaHash` 缺失或非法时 fail-closed；`trace` / `correlation`
/// 是观测辅助字段，缺失或非标准值均 fail-open 保留为可观测字符串，不阻断业务消费。
#[derive(Clone, PartialEq, Eq)]
pub struct EnvelopeHeader {
    tenant_id: vocab::TenantId,
    schema_version: EnvelopeSchemaVersion,
    schema_hash: EnvelopeSchemaHash,
    occurred_at_secs: Option<i64>,
    trace: Option<String>,
    correlation: Option<String>,
    tenant_authority: Option<String>,
    partition_key: Option<consistency::PartitionKey>,
}

impl EnvelopeHeader {
    /// 由必填 header 字段构造；观测字段与分区键默认为空。
    pub fn new(
        tenant_id: vocab::TenantId,
        schema_version: EnvelopeSchemaVersion,
        schema_hash: EnvelopeSchemaHash,
    ) -> Self {
        Self {
            tenant_id,
            schema_version,
            schema_hash,
            occurred_at_secs: None,
            trace: None,
            correlation: None,
            tenant_authority: None,
            partition_key: None,
        }
    }

    /// 从 wire metadata rehydrate 标准 header。
    pub fn try_from_metadata(
        metadata: &EnvelopeMetadata,
        partition_key: Option<consistency::PartitionKey>,
    ) -> Result<Self, EnvelopeHeaderError> {
        let tenant_raw = metadata
            .get(KEY_TENANT_ID)
            .ok_or(EnvelopeHeaderError::MissingTenantId)?;
        let tenant_id =
            vocab::TenantId::parse(tenant_raw).map_err(|_| EnvelopeHeaderError::InvalidTenantId)?;

        let version_raw = metadata
            .get(KEY_SCHEMA_VERSION)
            .ok_or(EnvelopeHeaderError::MissingSchemaVersion)?;
        let schema_version = EnvelopeSchemaVersion::parse(version_raw.to_string())?;

        let hash_raw = metadata
            .get(KEY_SCHEMA_HASH)
            .ok_or(EnvelopeHeaderError::MissingSchemaHash)?;
        let schema_hash = EnvelopeSchemaHash::parse(hash_raw.to_string())?;

        Ok(Self {
            tenant_id,
            schema_version,
            schema_hash,
            occurred_at_secs: metadata.occurred_at_secs(),
            trace: metadata.get(KEY_TRACE).map(str::to_string),
            correlation: metadata.get(KEY_CORRELATION).map(str::to_string),
            tenant_authority: metadata.get(KEY_TENANT_AUTHORITY).map(str::to_string),
            partition_key,
        })
    }

    /// tenant id。
    pub fn tenant_id(&self) -> vocab::TenantId {
        self.tenant_id
    }

    /// schema version。
    pub fn schema_version(&self) -> &EnvelopeSchemaVersion {
        &self.schema_version
    }

    /// schema hash。
    pub fn schema_hash(&self) -> &EnvelopeSchemaHash {
        &self.schema_hash
    }

    /// occurredAt unix 秒；缺失或非法时为 `None`。
    pub fn occurred_at_secs(&self) -> Option<i64> {
        self.occurred_at_secs
    }

    /// trace header（fail-open，可为非 W3C 字符串）。
    pub fn trace(&self) -> Option<&str> {
        self.trace.as_deref()
    }

    /// correlation header（fail-open，可为任意诊断字符串）。
    pub fn correlation(&self) -> Option<&str> {
        self.correlation.as_deref()
    }

    /// tenant authority token（值只供验签，不应 Debug 明文输出）。
    pub fn tenant_authority(&self) -> Option<&str> {
        self.tenant_authority.as_deref()
    }

    /// 可选分区键；来自 outbox row / adapter 上下文，不经 broker header。
    pub fn partition_key(&self) -> Option<&consistency::PartitionKey> {
        self.partition_key.as_ref()
    }
}

impl std::fmt::Debug for EnvelopeHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnvelopeHeader")
            .field("tenant_id", &self.tenant_id)
            .field("schema_version", &self.schema_version)
            .field("schema_hash", &self.schema_hash)
            .field("occurred_at_secs", &self.occurred_at_secs)
            .field("trace", &self.trace)
            .field("correlation", &self.correlation)
            .field(
                "tenant_authority",
                &self.tenant_authority.as_ref().map(|_| "<redacted>"),
            )
            .field("partition_key", &self.partition_key)
            .finish()
    }
}

/// 标准 delivery envelope：typed header + 原始 metadata + payload。
#[derive(Clone, PartialEq, Eq)]
pub struct MessageEnvelope {
    header: EnvelopeHeader,
    metadata: EnvelopeMetadata,
    payload: crate::redacted_bytes::RedactedBytes,
}

impl MessageEnvelope {
    /// 由已校验 header、原始 metadata 与 payload 构造。
    pub fn new(header: EnvelopeHeader, payload: Vec<u8>, metadata: EnvelopeMetadata) -> Self {
        Self {
            header,
            metadata,
            payload: crate::redacted_bytes::RedactedBytes::new(payload),
        }
    }

    /// 从 wire metadata + payload rehydrate 标准 envelope。
    pub fn try_from_metadata(
        payload: Vec<u8>,
        metadata: EnvelopeMetadata,
        partition_key: Option<consistency::PartitionKey>,
    ) -> Result<Self, EnvelopeHeaderError> {
        let header = EnvelopeHeader::try_from_metadata(&metadata, partition_key)?;
        Ok(Self::new(header, payload, metadata))
    }

    /// typed header。
    pub fn header(&self) -> &EnvelopeHeader {
        &self.header
    }

    /// 原始 metadata bag。
    pub fn metadata(&self) -> &EnvelopeMetadata {
        &self.metadata
    }

    /// 原始 payload bytes。
    pub fn payload(&self) -> &[u8] {
        self.payload.as_bytes()
    }

    /// move 出 payload。
    pub fn into_payload(self) -> Vec<u8> {
        self.payload.into_bytes()
    }
}

impl std::fmt::Debug for MessageEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessageEnvelope")
            .field("header", &self.header)
            .field("metadata", &self.metadata)
            .field("payload", &self.payload)
            .finish()
    }
}

/// 统一 delivery envelope metadata bag——私有内层 [`BTreeMap`]（确定性序，便于 golden / 断言），
/// 唯一写入口受控（见模块 rustdoc 两层写面）。
#[derive(Clone, Default, PartialEq, Eq)]
pub struct EnvelopeMetadata(BTreeMap<String, String>);

impl EnvelopeMetadata {
    /// 空 bag（无 metadata 路径：`PublishRequest::new` / `Message::new` 默认）。
    pub fn empty() -> Self {
        Self::default()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// 键值对数。
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// 取元数据值（只读）。消费侧 handler / publisher 映射经此读。
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }

    /// broker transport-safe 视图（确定性序）。
    ///
    /// 只允许诊断 / 租户权威元数据进入 broker headers/user-properties。`subjectId` / `principal` / `actor`
    /// 以及所有业务 free-form metadata 均为 persisted-only，避免新 publisher 误把完整 metadata 外发。
    pub fn iter_transport_headers(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0
            .iter()
            .filter(|(k, _)| is_transport_header_key(k.as_str()))
            .map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// 判断单个 metadata key 是否允许进入 broker transport headers/user-properties。
    ///
    /// 入站 subscriber 在 rehydrate 前也必须使用同一 allowlist，避免外部 producer 伪造 persisted-only
    /// `subjectId` / `principal` / `actor` 字段进入消费侧 [`Message`](crate::Message) metadata。
    pub fn is_transport_header_key(key: &str) -> bool {
        is_transport_header_key(key)
    }

    /// persisted-only 全量视图（确定性序）。
    ///
    /// 仅供持久化边界（如 dead-letter metadata JSON）使用；broker publisher 必须使用
    /// [`EnvelopeMetadata::iter_transport_headers`]。
    pub fn iter_persisted_metadata(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// 便捷 typed 读：`occurred_at` unix 秒（解析失败 → `None`）。AMQP `timestamp` 映射 + 消费观测用。
    pub fn occurred_at_secs(&self) -> Option<i64> {
        self.get(KEY_OCCURRED_AT)?.parse().ok()
    }

    /// typed 读：canonical tenant id。缺失或非 canonical 值均 fail-closed 为 `None`。
    pub fn tenant_id(&self) -> Option<vocab::TenantId> {
        vocab::TenantId::parse(self.get(KEY_TENANT_ID)?).ok()
    }

    /// typed 读：schema version。缺失或非法均 fail-closed 为 `None`。
    pub fn schema_version(&self) -> Option<EnvelopeSchemaVersion> {
        EnvelopeSchemaVersion::parse(self.get(KEY_SCHEMA_VERSION)?.to_string()).ok()
    }

    /// typed 读：schema hash。缺失或非法均 fail-closed 为 `None`。
    pub fn schema_hash(&self) -> Option<EnvelopeSchemaHash> {
        EnvelopeSchemaHash::parse(self.get(KEY_SCHEMA_HASH)?.to_string()).ok()
    }

    /// **业务 free-form 写入口**——命中 [`RESERVED_METADATA_KEYS`] fail-closed 拒（Hard：业务经此伪造
    /// reserved key 类型层不可表达）。
    pub fn try_insert(
        &mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<(), MetadataError> {
        let key = key.into();
        if RESERVED_METADATA_KEYS.contains(&key.as_str()) {
            return Err(MetadataError::ReservedKey);
        }
        self.0.insert(key, value.into());
        Ok(())
    }

    /// **adapter 透传写入口**——relay 从 `outbox.metadata` 列 / subscriber 从 broker header 逐对 rehydrate
    /// （含 reserved key，来源已 sealed）。仅 adapter / 组合根可调（Medium：dylint
    /// `rss_diport_envelope_reserved_writer` 限站点；真正 Hard 锚点在 emit 层，见模块 rustdoc）。
    /// INVARIANT: DIPORT-ENVELOPE-WIRE-WRITER-01 { level = "Medium", exec = "manual/opt-in", source = "code" }.
    pub fn insert_wire_pair(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.0.insert(key.into(), value.into());
    }
}

fn is_transport_header_key(key: &str) -> bool {
    matches!(
        key,
        KEY_TRACE
            | KEY_CORRELATION
            | KEY_OCCURRED_AT
            | KEY_TENANT_ID
            | KEY_TENANT_AUTHORITY
            | KEY_SCHEMA_VERSION
            | KEY_SCHEMA_HASH
    )
}

fn is_schema_version(raw: &str) -> bool {
    raw.strip_prefix('v')
        .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
}

fn is_schema_hash(raw: &str) -> bool {
    raw.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// PII / authority 边界（类型层，对标 [`crate::OutboxEnvelopeParts`]）：手写 `Debug` 对 `subjectId` /
/// `principal` / `tenantAuthority`（opaque 主体或授权材料）值输出 `<redacted>`；`occurred_at` / `trace` /
/// `correlation` 是路由 / 观测元数据，可观测。INVARIANT: DIPORT-DTO-PII-DEBUG-REDACT-01 { level =
/// "Medium", exec = "manual/opt-in", source = "code" }（回归见 `pii_debug` 单测）。
impl std::fmt::Debug for EnvelopeMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut m = f.debug_map();
        for (k, v) in self.0.iter() {
            if k == KEY_SUBJECT_ID
                || k == KEY_PRINCIPAL
                || k == KEY_ACTOR
                || k == KEY_TENANT_AUTHORITY
            {
                m.entry(&k, &"<redacted>");
            } else {
                m.entry(&k, &v);
            }
        }
        m.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EnvelopeHeader, EnvelopeHeaderError, EnvelopeMetadata, EnvelopeSchemaHash,
        EnvelopeSchemaVersion, KEY_ACTOR, KEY_CORRELATION, KEY_OCCURRED_AT, KEY_PRINCIPAL,
        KEY_SCHEMA_HASH, KEY_SCHEMA_VERSION, KEY_SUBJECT_ID, KEY_TENANT_AUTHORITY, KEY_TENANT_ID,
        KEY_TRACE, MessageEnvelope, MetadataError, RESERVED_METADATA_KEYS,
    };

    const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const HASH: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn complete_metadata() -> EnvelopeMetadata {
        let mut md = EnvelopeMetadata::empty();
        md.insert_wire_pair(KEY_TENANT_ID, TENANT);
        md.insert_wire_pair(KEY_SCHEMA_VERSION, "v1");
        md.insert_wire_pair(KEY_SCHEMA_HASH, HASH);
        md
    }

    #[allow(clippy::expect_used)]
    fn tenant() -> vocab::TenantId {
        vocab::TenantId::parse(TENANT).expect("canonical tenant")
    }

    #[test]
    fn try_insert_accepts_non_reserved() {
        let mut md = EnvelopeMetadata::empty();
        assert_eq!(md.try_insert("requestPath", "/login"), Ok(()));
        assert_eq!(md.get("requestPath"), Some("/login"));
        assert_eq!(md.try_insert("requestPath", "/profile"), Ok(()));
        assert_eq!(md.get("requestPath"), Some("/profile"));
    }

    #[test]
    fn try_insert_rejects_every_reserved_key() {
        // reserved key 全覆盖 fail-closed（anti-vacuity：上面 accepts 证明非恒拒）。
        for key in RESERVED_METADATA_KEYS {
            let mut md = EnvelopeMetadata::empty();
            assert_eq!(
                md.try_insert(key, "x"),
                Err(MetadataError::ReservedKey),
                "业务写 reserved key 应拒: {key}"
            );
            assert_eq!(md.get(key), None, "拒后不应写入: {key}");
        }
    }

    #[test]
    fn insert_wire_pair_allows_reserved_rehydrate() {
        // adapter 透传：从已 sealed 来源 rehydrate reserved key（relay / subscriber 路径）。
        let mut md = EnvelopeMetadata::empty();
        md.insert_wire_pair(KEY_CORRELATION, "corr-9");
        md.insert_wire_pair(KEY_OCCURRED_AT, "1700000000");
        md.insert_wire_pair(KEY_SCHEMA_VERSION, "v1");
        md.insert_wire_pair(KEY_SCHEMA_HASH, HASH);
        assert_eq!(md.get(KEY_CORRELATION), Some("corr-9"));
        assert_eq!(md.occurred_at_secs(), Some(1_700_000_000));
        assert_eq!(
            md.schema_version().map(|v| v.to_string()).as_deref(),
            Some("v1")
        );
        assert_eq!(
            md.schema_hash().map(|v| v.to_string()).as_deref(),
            Some(HASH)
        );
    }

    #[test]
    fn occurred_at_secs_parses_or_none() {
        let mut md = EnvelopeMetadata::empty();
        assert_eq!(md.occurred_at_secs(), None);
        md.insert_wire_pair(KEY_OCCURRED_AT, "not-a-number");
        assert_eq!(md.occurred_at_secs(), None);
        md.insert_wire_pair(KEY_OCCURRED_AT, "42");
        assert_eq!(md.occurred_at_secs(), Some(42));
    }

    #[test]
    fn iter_persisted_and_len_reflect_contents() {
        let mut md = EnvelopeMetadata::empty();
        assert!(md.is_empty());
        md.insert_wire_pair(KEY_OCCURRED_AT, "1");
        md.insert_wire_pair(KEY_CORRELATION, "c");
        md.insert_wire_pair(KEY_SUBJECT_ID, "subj");
        md.insert_wire_pair(KEY_ACTOR, "actor-json");
        let _ = md.try_insert("requestPath", "/login");
        assert_eq!(md.len(), 5);
        // BTreeMap 确定性序：correlation < occurredAt（字典序）。
        let pairs: Vec<(&str, &str)> = md.iter_persisted_metadata().collect();
        assert_eq!(
            pairs,
            vec![
                (KEY_ACTOR, "actor-json"),
                (KEY_CORRELATION, "c"),
                (KEY_OCCURRED_AT, "1"),
                ("requestPath", "/login"),
                (KEY_SUBJECT_ID, "subj")
            ]
        );
    }

    #[test]
    fn iter_transport_headers_is_allowlist_and_excludes_sensitive_metadata() {
        let mut md = EnvelopeMetadata::empty();
        md.insert_wire_pair(KEY_TRACE, "trace-1");
        md.insert_wire_pair(KEY_CORRELATION, "corr-1");
        md.insert_wire_pair(KEY_OCCURRED_AT, "1700000000");
        md.insert_wire_pair(KEY_TENANT_ID, TENANT);
        md.insert_wire_pair(KEY_TENANT_AUTHORITY, "signed-authority");
        md.insert_wire_pair(KEY_SCHEMA_VERSION, "v1");
        md.insert_wire_pair(KEY_SCHEMA_HASH, HASH);
        md.insert_wire_pair(KEY_SUBJECT_ID, "SECRET_SUBJECT");
        md.insert_wire_pair(KEY_PRINCIPAL, "SECRET_PRINCIPAL");
        md.insert_wire_pair(KEY_ACTOR, "SECRET_ACTOR");
        let _ = md.try_insert("requestPath", "/login");

        let pairs: Vec<(&str, &str)> = md.iter_transport_headers().collect();
        assert_eq!(
            pairs,
            vec![
                (KEY_CORRELATION, "corr-1"),
                (KEY_OCCURRED_AT, "1700000000"),
                (KEY_SCHEMA_HASH, HASH),
                (KEY_SCHEMA_VERSION, "v1"),
                (KEY_TENANT_AUTHORITY, "signed-authority"),
                (KEY_TENANT_ID, TENANT),
                (KEY_TRACE, "trace-1"),
            ]
        );
        assert!(
            pairs.iter().all(|(k, v)| *k != KEY_SUBJECT_ID
                && *k != KEY_PRINCIPAL
                && *k != KEY_ACTOR
                && *v != "SECRET_SUBJECT"
                && *v != "SECRET_PRINCIPAL"
                && *v != "SECRET_ACTOR"),
            "transport view leaked sensitive metadata: {pairs:?}"
        );
    }

    #[test]
    fn reserved_keys_single_source_is_exactly_ten() {
        // drift-lock：reserved 集与 postgres OutboxMetadata funnel 同源；下游 import 本 const，不另立第二真源。
        assert_eq!(
            RESERVED_METADATA_KEYS,
            [
                KEY_TRACE,
                KEY_CORRELATION,
                KEY_PRINCIPAL,
                KEY_ACTOR,
                KEY_SUBJECT_ID,
                KEY_OCCURRED_AT,
                KEY_TENANT_ID,
                KEY_TENANT_AUTHORITY,
                KEY_SCHEMA_VERSION,
                KEY_SCHEMA_HASH,
            ]
        );
    }

    #[test]
    fn tenant_id_parses_canonical_wire_value() {
        let mut md = EnvelopeMetadata::empty();
        md.insert_wire_pair(KEY_TENANT_ID, TENANT);
        assert_eq!(
            md.tenant_id().map(|t| t.to_string()).as_deref(),
            Some(TENANT)
        );
        md.insert_wire_pair(KEY_TENANT_ID, "F47AC10B-58CC-4372-A567-0E02B2C3D479");
        assert!(
            md.tenant_id().is_none(),
            "non-canonical tenant must fail closed"
        );
    }

    #[test]
    fn envelope_schema_newtypes_validate_wire_shape() {
        assert_eq!(
            EnvelopeSchemaVersion::parse("v12")
                .map(|v| v.to_string())
                .as_deref(),
            Ok("v12")
        );
        assert_eq!(
            EnvelopeSchemaVersion::parse("1"),
            Err(EnvelopeHeaderError::InvalidSchemaVersion)
        );
        assert_eq!(
            EnvelopeSchemaVersion::parse("v"),
            Err(EnvelopeHeaderError::InvalidSchemaVersion)
        );
        assert_eq!(
            EnvelopeSchemaHash::parse(HASH)
                .map(|h| h.to_string())
                .as_deref(),
            Ok(HASH)
        );
        assert_eq!(
            EnvelopeSchemaHash::parse(HASH.to_ascii_uppercase()),
            Err(EnvelopeHeaderError::InvalidSchemaHash)
        );
    }

    #[test]
    fn envelope_header_rehydrates_required_schema_fields() -> Result<(), EnvelopeHeaderError> {
        let mut md = complete_metadata();
        md.insert_wire_pair(KEY_OCCURRED_AT, "1700000000");
        md.insert_wire_pair(KEY_TRACE, "not a w3c traceparent");
        md.insert_wire_pair(KEY_CORRELATION, "corr 1");
        md.insert_wire_pair(KEY_TENANT_AUTHORITY, "SECRET_AUTHORITY");
        let partition_key = consistency::PartitionKey::parse("partition-1").ok();

        let header = EnvelopeHeader::try_from_metadata(&md, partition_key)?;
        assert_eq!(header.tenant_id(), tenant());
        assert_eq!(header.schema_version().as_str(), "v1");
        assert_eq!(header.schema_hash().as_str(), HASH);
        assert_eq!(header.occurred_at_secs(), Some(1_700_000_000));
        assert_eq!(header.trace(), Some("not a w3c traceparent"));
        assert_eq!(header.correlation(), Some("corr 1"));
        assert!(header.partition_key().is_some());

        let dbg = format!("{header:?}");
        assert!(
            !dbg.contains("SECRET_AUTHORITY"),
            "tenantAuthority leaked in Debug: {dbg}"
        );
        assert!(
            dbg.contains("<redacted>"),
            "Debug should mark redaction: {dbg}"
        );
        Ok(())
    }

    #[test]
    fn envelope_header_rejects_missing_and_invalid_required_fields() {
        let mut missing_tenant = complete_metadata();
        missing_tenant.insert_wire_pair(KEY_TENANT_ID, "");
        assert_eq!(
            EnvelopeHeader::try_from_metadata(&missing_tenant, None),
            Err(EnvelopeHeaderError::InvalidTenantId)
        );

        let missing_version = {
            let mut md = EnvelopeMetadata::empty();
            md.insert_wire_pair(KEY_TENANT_ID, TENANT);
            md.insert_wire_pair(KEY_SCHEMA_HASH, HASH);
            md
        };
        assert_eq!(
            EnvelopeHeader::try_from_metadata(&missing_version, None),
            Err(EnvelopeHeaderError::MissingSchemaVersion)
        );

        let mut invalid_version = complete_metadata();
        invalid_version.insert_wire_pair(KEY_SCHEMA_VERSION, "1");
        assert_eq!(
            EnvelopeHeader::try_from_metadata(&invalid_version, None),
            Err(EnvelopeHeaderError::InvalidSchemaVersion)
        );

        let missing_hash = {
            let mut md = EnvelopeMetadata::empty();
            md.insert_wire_pair(KEY_TENANT_ID, TENANT);
            md.insert_wire_pair(KEY_SCHEMA_VERSION, "v1");
            md
        };
        assert_eq!(
            EnvelopeHeader::try_from_metadata(&missing_hash, None),
            Err(EnvelopeHeaderError::MissingSchemaHash)
        );

        let mut invalid_hash = complete_metadata();
        invalid_hash.insert_wire_pair(KEY_SCHEMA_HASH, "sha256:ABC");
        assert_eq!(
            EnvelopeHeader::try_from_metadata(&invalid_hash, None),
            Err(EnvelopeHeaderError::InvalidSchemaHash)
        );
    }

    #[test]
    fn envelope_header_missing_tenant_is_distinct_from_invalid_tenant() {
        let mut md = EnvelopeMetadata::empty();
        md.insert_wire_pair(KEY_SCHEMA_VERSION, "v1");
        md.insert_wire_pair(KEY_SCHEMA_HASH, HASH);
        assert_eq!(
            EnvelopeHeader::try_from_metadata(&md, None),
            Err(EnvelopeHeaderError::MissingTenantId)
        );
    }

    #[test]
    fn message_envelope_keeps_private_typed_header_and_redacts_debug_payload()
    -> Result<(), EnvelopeHeaderError> {
        let md = complete_metadata();
        let env = MessageEnvelope::try_from_metadata(vec![0xde, 0xad], md, None)?;

        assert_eq!(env.header().tenant_id(), tenant());
        assert_eq!(env.payload(), &[0xde, 0xad]);
        assert_eq!(env.metadata().get(KEY_SCHEMA_VERSION), Some("v1"));

        let dbg = format!("{env:?}");
        assert!(!dbg.contains("222"), "payload leaked in Debug: {dbg}");
        assert!(
            dbg.contains("<redacted>"),
            "payload redaction missing: {dbg}"
        );
        Ok(())
    }
}

#[cfg(test)]
mod pii_debug {
    //! `EnvelopeMetadata` 的 `subjectId` / `principal` / `tenantAuthority` 值 Debug 脱敏回归。
    //! INVARIANT: DIPORT-DTO-PII-DEBUG-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }.
    use super::{
        EnvelopeMetadata, KEY_ACTOR, KEY_CORRELATION, KEY_OCCURRED_AT, KEY_PRINCIPAL,
        KEY_SUBJECT_ID, KEY_TENANT_AUTHORITY,
    };

    #[test]
    fn debug_redacts_subject_principal_and_tenant_authority_shows_observable() {
        let mut md = EnvelopeMetadata::empty();
        // anti-vacuity：subjectId 值若不脱敏会出现在普通 map Debug 中。
        md.insert_wire_pair(KEY_SUBJECT_ID, "SECRET_SUBJECT");
        md.insert_wire_pair(KEY_PRINCIPAL, "SECRET_PRINCIPAL");
        md.insert_wire_pair(KEY_ACTOR, "SECRET_ACTOR");
        md.insert_wire_pair(KEY_TENANT_AUTHORITY, "SECRET_TENANT_AUTHORITY");
        md.insert_wire_pair(KEY_CORRELATION, "corr-observable");
        md.insert_wire_pair(KEY_OCCURRED_AT, "1700000000");
        let dbg = format!("{md:?}");
        assert!(!dbg.contains("SECRET_SUBJECT"), "subjectId 值泄漏: {dbg}");
        assert!(!dbg.contains("SECRET_PRINCIPAL"), "principal 值泄漏: {dbg}");
        assert!(
            !dbg.contains("SECRET_TENANT_AUTHORITY"),
            "tenantAuthority 值泄漏: {dbg}"
        );
        assert!(!dbg.contains("SECRET_ACTOR"), "actor 值泄漏: {dbg}");
        assert!(dbg.contains("<redacted>"), "缺 <redacted>: {dbg}");
        // 路由 / 观测元数据可见。
        assert!(dbg.contains("corr-observable"), "correlation 应可见: {dbg}");
        assert!(dbg.contains("1700000000"), "occurred_at 应可见: {dbg}");
    }
}
