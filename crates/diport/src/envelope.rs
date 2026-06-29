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
pub const RESERVED_METADATA_KEYS: [&str; 6] = [
    KEY_TRACE,
    KEY_CORRELATION,
    KEY_PRINCIPAL,
    KEY_OCCURRED_AT,
    KEY_TENANT_ID,
    KEY_TENANT_AUTHORITY,
];

/// reserved：事件发生时刻（unix 秒，十进制 string）。producer 经注入 `Clock` 必填（#1129）。
pub const KEY_OCCURRED_AT: &str = "occurredAt";
/// reserved：分布式 trace（W3C `traceparent`，含 trace_id；源经 `tracewire::capture` 注入，已接线 #1224）。
pub const KEY_TRACE: &str = "trace";
/// reserved：跨服务关联 id（源经 `diagctx` ambient 注入，已接线 #1160）。
pub const KEY_CORRELATION: &str = "correlation";
/// reserved：opaque principal（源待安全决策，本轮仅留 slot）。
pub const KEY_PRINCIPAL: &str = "principal";
/// reserved：canonical tenant id（认证 / co-tx 边界盖章，消费 DLX / RLS scope 使用）。
pub const KEY_TENANT_ID: &str = "tenantId";
/// reserved：tenant authority token（relay 签发，consumer 写 DLX 前验签）。
pub const KEY_TENANT_AUTHORITY: &str = "tenantAuthority";
/// 非-reserved 但 PII：opaque 主体标识（业务可经 envelope 携带；`Debug` 脱敏）。
pub const KEY_SUBJECT_ID: &str = "subjectId";

/// [`EnvelopeMetadata::try_insert`] 失败原因。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MetadataError {
    /// 业务写入口命中 reserved key（[`RESERVED_METADATA_KEYS`]）——只 adapter 受控注入点可写。
    #[error("reserved envelope metadata key is not allowed for business writers")]
    ReservedKey,
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

    /// 遍历全部键值对（确定性序）。adapter publisher 映射进 broker header 经此。
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
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

/// PII / authority 边界（类型层，对标 [`crate::OutboxEnvelopeParts`]）：手写 `Debug` 对 `subjectId` /
/// `principal` / `tenantAuthority`（opaque 主体或授权材料）值输出 `<redacted>`；`occurred_at` / `trace` /
/// `correlation` 是路由 / 观测元数据，可观测。INVARIANT: DIPORT-DTO-PII-DEBUG-REDACT-01 { level =
/// "Medium", exec = "manual/opt-in", source = "code" }（回归见 `pii_debug` 单测）。
impl std::fmt::Debug for EnvelopeMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut m = f.debug_map();
        for (k, v) in self.0.iter() {
            if k == KEY_SUBJECT_ID || k == KEY_PRINCIPAL || k == KEY_TENANT_AUTHORITY {
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
        EnvelopeMetadata, KEY_CORRELATION, KEY_OCCURRED_AT, KEY_PRINCIPAL, KEY_SUBJECT_ID,
        KEY_TENANT_AUTHORITY, KEY_TENANT_ID, KEY_TRACE, MetadataError, RESERVED_METADATA_KEYS,
    };

    #[test]
    fn try_insert_accepts_non_reserved() {
        let mut md = EnvelopeMetadata::empty();
        assert_eq!(md.try_insert("requestPath", "/login"), Ok(()));
        assert_eq!(md.get("requestPath"), Some("/login"));
        // subjectId 非 reserved（业务可携 opaque 主体）。
        assert_eq!(md.try_insert(KEY_SUBJECT_ID, "user-7"), Ok(()));
        assert_eq!(md.get(KEY_SUBJECT_ID), Some("user-7"));
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
        assert_eq!(md.get(KEY_CORRELATION), Some("corr-9"));
        assert_eq!(md.occurred_at_secs(), Some(1_700_000_000));
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
    fn iter_and_len_reflect_contents() {
        let mut md = EnvelopeMetadata::empty();
        assert!(md.is_empty());
        md.insert_wire_pair(KEY_OCCURRED_AT, "1");
        md.insert_wire_pair(KEY_CORRELATION, "c");
        assert_eq!(md.len(), 2);
        // BTreeMap 确定性序：correlation < occurredAt（字典序）。
        let pairs: Vec<(&str, &str)> = md.iter().collect();
        assert_eq!(pairs, vec![(KEY_CORRELATION, "c"), (KEY_OCCURRED_AT, "1")]);
    }

    #[test]
    fn reserved_keys_single_source_is_exactly_six() {
        // drift-lock：reserved 集恰为 trace/correlation/principal/occurredAt/tenantId（与 postgres OutboxMetadata
        // funnel + migration CHECK 同源；下游 import 本 const，不另立第二真源）。
        assert_eq!(
            RESERVED_METADATA_KEYS,
            [
                KEY_TRACE,
                KEY_CORRELATION,
                KEY_PRINCIPAL,
                KEY_OCCURRED_AT,
                KEY_TENANT_ID,
                KEY_TENANT_AUTHORITY,
            ]
        );
    }

    #[test]
    fn tenant_id_parses_canonical_wire_value() {
        let mut md = EnvelopeMetadata::empty();
        md.insert_wire_pair(KEY_TENANT_ID, "f47ac10b-58cc-4372-a567-0e02b2c3d479");
        assert_eq!(
            md.tenant_id().map(|t| t.to_string()).as_deref(),
            Some("f47ac10b-58cc-4372-a567-0e02b2c3d479")
        );
        md.insert_wire_pair(KEY_TENANT_ID, "F47AC10B-58CC-4372-A567-0E02B2C3D479");
        assert!(
            md.tenant_id().is_none(),
            "non-canonical tenant must fail closed"
        );
    }
}

#[cfg(test)]
mod pii_debug {
    //! `EnvelopeMetadata` 的 `subjectId` / `principal` / `tenantAuthority` 值 Debug 脱敏回归。
    //! INVARIANT: DIPORT-DTO-PII-DEBUG-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }.
    use super::{
        EnvelopeMetadata, KEY_CORRELATION, KEY_OCCURRED_AT, KEY_PRINCIPAL, KEY_SUBJECT_ID,
        KEY_TENANT_AUTHORITY,
    };

    #[test]
    fn debug_redacts_subject_principal_and_tenant_authority_shows_observable() {
        let mut md = EnvelopeMetadata::empty();
        // anti-vacuity：subjectId 值若不脱敏会出现在普通 map Debug 中。
        let _ = md.try_insert(KEY_SUBJECT_ID, "SECRET_SUBJECT");
        md.insert_wire_pair(KEY_PRINCIPAL, "SECRET_PRINCIPAL");
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
        assert!(dbg.contains("<redacted>"), "缺 <redacted>: {dbg}");
        // 路由 / 观测元数据可见。
        assert!(dbg.contains("corr-observable"), "correlation 应可见: {dbg}");
        assert!(dbg.contains("1700000000"), "occurred_at 应可见: {dbg}");
    }
}
