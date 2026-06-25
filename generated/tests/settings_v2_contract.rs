//! settings secret-publish v2 contract roundtrip 回归（F7）：锁 generated wire 类型的 serde 契约
//! ——必填 / 可选字段、camelCase rename、`deny_unknown_fields`、response `data.version` 类型。
//!
//! 分工：长度 / 字符集 / 路径穿越等**语义校验**由 domain newtype（`SecretKey` / `StoreId` /
//! `SecretRef::parse`，Hard funnel）权威守——不在 wire 层重复（schema 仅以 `description` 文档化约束）。
//! 本测试只锁 wire **serde 形状**（generated 行为），与 codegen golden 互补。
//!
//! 注意：`SettingsSecretPublishRequest` 经 codegen `x-sensitive` 去 `Debug`（F6）——本测试不 `{:?}`
//! 该类型，断言走具体字段（`String` 自带 `PartialEq`）。

use generated::http::settings_v2::{
    SettingsSecretPublishData, SettingsSecretPublishRequest, SettingsSecretPublishResponse,
};

/// 合法请求反序列化 + camelCase rename 锁定（storeId / refKey / refVersion）。
#[test]
#[allow(clippy::expect_used)]
fn request_valid_roundtrip_camel_case() {
    let json =
        r#"{"key":"vault.db","storeId":"vault","refKey":"myapp/db-password","refVersion":"v3"}"#;
    let req: SettingsSecretPublishRequest =
        serde_json::from_str(json).expect("合法请求应反序列化成功");
    assert_eq!(req.key, "vault.db");
    assert_eq!(req.store_id, "vault");
    assert_eq!(req.ref_key, "myapp/db-password");
    assert_eq!(req.ref_version.as_deref(), Some("v3"));

    // 序列化回 camelCase（rename 锁定；不得出现 snake_case）。
    let value = serde_json::to_value(&req).expect("序列化");
    let obj = value.as_object().expect("object");
    assert!(obj.contains_key("storeId"), "storeId camelCase 锁定");
    assert!(obj.contains_key("refKey"), "refKey camelCase 锁定");
    assert!(obj.contains_key("refVersion"), "refVersion camelCase 锁定");
    assert!(
        !obj.contains_key("store_id"),
        "不得出现 snake_case store_id"
    );
}

/// refVersion 可选：缺省 → `None`，且 `None` 序列化时省略（`skip_serializing_if`）。
#[test]
#[allow(clippy::expect_used)]
fn request_refversion_optional_absent_is_none() {
    let json = r#"{"key":"vault.db","storeId":"vault","refKey":"myapp/db-password"}"#;
    let req: SettingsSecretPublishRequest = serde_json::from_str(json).expect("refVersion 可缺省");
    assert!(req.ref_version.is_none(), "缺省 refVersion → None");

    let value = serde_json::to_value(&req).expect("序列化");
    assert!(
        !value
            .as_object()
            .expect("object")
            .contains_key("refVersion"),
        "None refVersion 不应序列化"
    );
}

/// 缺必填字段（storeId）→ 反序列化失败。
#[test]
fn request_missing_required_field_is_err() {
    let json = r#"{"key":"vault.db","refKey":"myapp/db-password"}"#;
    assert!(
        serde_json::from_str::<SettingsSecretPublishRequest>(json).is_err(),
        "缺必填 storeId 应反序列化失败"
    );
}

/// 额外未知字段 → `deny_unknown_fields` 拒（反序列化失败）。
#[test]
fn request_unknown_field_is_rejected() {
    let json = r#"{"key":"vault.db","storeId":"vault","refKey":"k","extra":"x"}"#;
    assert!(
        serde_json::from_str::<SettingsSecretPublishRequest>(json).is_err(),
        "额外字段应被 deny_unknown_fields 拒"
    );
}

/// response `data.version` 是 i64（int64 wire 语义锁定）。
#[test]
#[allow(clippy::expect_used)]
fn response_data_version_is_i64() {
    let json = r#"{"data":{"key":"vault.db","version":42}}"#;
    let resp: SettingsSecretPublishResponse =
        serde_json::from_str(json).expect("合法 response 应反序列化");
    assert_eq!(resp.data.key, "vault.db");
    let v: i64 = resp.data.version;
    assert_eq!(v, 42);
}

/// response 额外字段拒 + data roundtrip（构造 → 序列化 → 反序列化等值）。
#[test]
#[allow(clippy::expect_used)]
fn response_data_roundtrip_and_denies_unknown() {
    let data = SettingsSecretPublishData {
        key: "ns.k".to_string(),
        version: 7,
    };
    let json = serde_json::to_string(&data).expect("序列化");
    let back: SettingsSecretPublishData = serde_json::from_str(&json).expect("反序列化");
    assert_eq!(back.key, "ns.k");
    assert_eq!(back.version, 7);

    assert!(
        serde_json::from_str::<SettingsSecretPublishResponse>(
            r#"{"data":{"key":"ns.k","version":1},"extra":true}"#
        )
        .is_err(),
        "response 额外字段应被 deny_unknown_fields 拒"
    );
}
