//! MQTT v5 user-properties ↔ [`diport::EnvelopeMetadata`] 相互转换纯函数（非 integration-gated）。
//!
//! MQTT v5 `PublishProperties.user_properties: Vec<(String, String)>` 是通用 string-pair 向量，
//! 与 [`diport::EnvelopeMetadata`] 的 BTreeMap 语义一致。全部 reserved key（`occurred_at` /
//! `correlation` 等）经 [`diport::EnvelopeMetadata::insert_wire_pair`] 透传（adapter 受控注入点）。
//!
//! 这些函数不依赖 rumqttc 类型，默认 build 即可单测，与 `integration` feature 无关。
use diport::EnvelopeMetadata;

/// [`EnvelopeMetadata`] → MQTT v5 `user_properties` 向量（每对 key-value 一条 user property）。
/// `occurred_at` 等 reserved key 与业务 free-form key 均透传——broker user_properties 是通用 bag。
// reason: 函数仅由 integration-gated publisher/subscriber 调用；默认 build（无 integration feature）
// 未看见调用点，rustc 报 dead_code warning，用 cfg_attr 在非 integration build 静默。
#[cfg_attr(not(feature = "integration"), allow(dead_code))]
pub(crate) fn to_user_properties(md: &EnvelopeMetadata) -> Vec<(String, String)> {
    md.iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// MQTT v5 `user_properties` 切片 → [`EnvelopeMetadata`]（逐对 `insert_wire_pair` rehydrate）。
/// 重复 key 后者覆盖前者（MQTT spec 允许重复 user property；取最后一对与 BTreeMap 覆盖语义一致）。
// reason: 同上——仅 integration-gated subscriber 调用；默认 build 报 dead_code，cfg_attr 静默。
#[cfg_attr(not(feature = "integration"), allow(dead_code))]
pub(crate) fn from_user_properties(props: &[(String, String)]) -> EnvelopeMetadata {
    let mut md = EnvelopeMetadata::empty();
    for (k, v) in props {
        md.insert_wire_pair(k, v);
    }
    md
}

#[cfg(test)]
mod tests {
    use diport::{EnvelopeMetadata, KEY_CORRELATION, KEY_OCCURRED_AT, KEY_SUBJECT_ID};

    use super::{from_user_properties, to_user_properties};

    #[test]
    fn empty_roundtrip() {
        let md = EnvelopeMetadata::empty();
        let props = to_user_properties(&md);
        assert!(props.is_empty());
        let md2 = from_user_properties(&props);
        assert!(md2.is_empty());
    }

    #[test]
    fn roundtrip_preserves_all_pairs() {
        let mut md = EnvelopeMetadata::empty();
        md.insert_wire_pair(KEY_OCCURRED_AT, "1700000000");
        md.insert_wire_pair(KEY_CORRELATION, "corr-9");
        let _ = md.try_insert(KEY_SUBJECT_ID, "user-42");

        let props = to_user_properties(&md);
        assert_eq!(props.len(), 3);

        let md2 = from_user_properties(&props);
        assert_eq!(md2.occurred_at_secs(), Some(1_700_000_000_i64));
        assert_eq!(md2.get(KEY_CORRELATION), Some("corr-9"));
        assert_eq!(md2.get(KEY_SUBJECT_ID), Some("user-42"));
    }

    #[test]
    fn from_user_props_accepts_reserved_keys() {
        // adapter 透传路径须能写入 reserved key（insert_wire_pair 受控入口）。
        let props = vec![
            (KEY_OCCURRED_AT.to_string(), "1700000001".to_string()),
            (KEY_CORRELATION.to_string(), "corr-r".to_string()),
        ];
        let md = from_user_properties(&props);
        assert_eq!(md.occurred_at_secs(), Some(1_700_000_001_i64));
        assert_eq!(md.get(KEY_CORRELATION), Some("corr-r"));
    }

    #[test]
    fn occurred_at_invalid_parses_as_none() {
        // occurred_at 值非数字 → occurred_at_secs() 返回 None（不 panic）。
        let props = vec![(KEY_OCCURRED_AT.to_string(), "not-a-number".to_string())];
        let md = from_user_properties(&props);
        assert_eq!(md.occurred_at_secs(), None);
    }
}
