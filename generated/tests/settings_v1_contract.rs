//! settings config-publish v1 contract roundtrip 回归（#1430 graduate draft→active 配套）：锁 generated
//! wire 类型的 serde 契约——必填字段、`deny_unknown_fields`、response `data.version` 类型。
//!
//! 分工：key 长度 / 字符集 / 敏感词等**语义校验**由 domain newtype（`SettingKey::parse`，Hard funnel）权威守——
//! 不在 wire 层重复。本测试只锁 wire **serde 形状**（generated 行为），与 codegen golden 互补。
//!
//! 注意：request `value` 字段 schema 标 `x-redaction=secret` → codegen 派生安全 `secure::Redact` Debug；
//! 脱敏断言见 `redaction_debug.rs`，此处只验 serde roundtrip。

use generated::http::settings_v1::{
    SettingsConfigPublishData, SettingsConfigPublishRequest, SettingsConfigPublishResponse,
};

/// 合法请求反序列化 + 序列化回值等值（key / value 必填）。
#[test]
#[allow(clippy::expect_used)]
fn request_valid_roundtrip() {
    let json = r#"{"key":"app.timeout","value":"30s"}"#;
    let req: SettingsConfigPublishRequest =
        serde_json::from_str(json).expect("合法请求应反序列化成功");
    assert_eq!(req.key, "app.timeout");
    assert_eq!(req.value, "30s");

    let value = serde_json::to_value(&req).expect("序列化");
    let obj = value.as_object().expect("object");
    assert!(obj.contains_key("key"), "key 字段保留");
    assert!(obj.contains_key("value"), "value 字段保留");
}

/// 缺必填字段（value）→ 反序列化失败。
#[test]
fn request_missing_required_field_is_err() {
    let json = r#"{"key":"app.timeout"}"#;
    assert!(
        serde_json::from_str::<SettingsConfigPublishRequest>(json).is_err(),
        "缺必填 value 应反序列化失败"
    );
}

/// 额外未知字段 → `deny_unknown_fields` 拒（反序列化失败）。
#[test]
fn request_unknown_field_is_rejected() {
    let json = r#"{"key":"app.timeout","value":"30s","extra":"x"}"#;
    assert!(
        serde_json::from_str::<SettingsConfigPublishRequest>(json).is_err(),
        "额外字段应被 deny_unknown_fields 拒"
    );
}

/// response `data.version` 是 i64（int64 wire 语义锁定）。
#[test]
#[allow(clippy::expect_used)]
fn response_data_version_is_i64() {
    let json = r#"{"data":{"key":"app.timeout","version":42}}"#;
    let resp: SettingsConfigPublishResponse =
        serde_json::from_str(json).expect("合法 response 应反序列化");
    assert_eq!(resp.data.key, "app.timeout");
    let v: i64 = resp.data.version;
    assert_eq!(v, 42);
}

/// response 额外字段拒 + data roundtrip（构造 → 序列化 → 反序列化等值）。
#[test]
#[allow(clippy::expect_used)]
fn response_data_roundtrip_and_denies_unknown() {
    let data = SettingsConfigPublishData {
        key: "app.k".to_string(),
        version: 7,
    };
    let json = serde_json::to_string(&data).expect("序列化");
    let back: SettingsConfigPublishData = serde_json::from_str(&json).expect("反序列化");
    assert_eq!(back.key, "app.k");
    assert_eq!(back.version, 7);

    assert!(
        serde_json::from_str::<SettingsConfigPublishResponse>(
            r#"{"data":{"key":"app.k","version":1},"extra":true}"#
        )
        .is_err(),
        "response 额外字段应被 deny_unknown_fields 拒"
    );
}
