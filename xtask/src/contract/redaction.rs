//! JSON Schema 字段级 redaction 扩展单源（#1358）。
//!
//! `x-pii` / `x-redaction` 是 contract → generated 安全 `Debug` 的唯一 authoring 面；
//! validate、breaking、codegen 均从本模块读取同一套枚举、默认值与高风险字段规则。

use serde_json::Value;
use std::collections::BTreeMap;

pub(crate) const X_PII: &str = "x-pii";
pub(crate) const X_REDACTION: &str = "x-redaction";
pub(crate) const X_SENSITIVE: &str = "x-sensitive";

const PROPS: &str = "properties";
const MAP_SUBSCHEMA_KEYS: &[&str] = &["properties", "patternProperties"];
const NAMED_SUBSCHEMA_KEYS: &[&str] = &["definitions", "$defs"];
const VALUE_SUBSCHEMA_KEYS: &[&str] = &[
    "items",
    "additionalProperties",
    "not",
    "allOf",
    "anyOf",
    "oneOf",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PiiKind {
    Generic,
    Email,
    Phone,
    Name,
    Address,
}

impl PiiKind {
    pub(crate) fn as_sensitivity(self) -> &'static str {
        match self {
            Self::Generic => "pii",
            Self::Email => "pii_email",
            Self::Phone => "pii_phone",
            Self::Name => "pii_name",
            Self::Address => "pii_address",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Sensitivity {
    Public,
    Internal,
    Secret,
    Pii(PiiKind),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RedactionMode {
    Fixed,
    Last4,
    EmailMask,
    Drop,
}

impl RedactionMode {
    pub(crate) fn as_wire(self) -> &'static str {
        match self {
            Self::Fixed => "fixed",
            Self::Last4 => "last4",
            Self::EmailMask => "email_mask",
            Self::Drop => "drop",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FieldPolicy {
    pub(crate) sensitivity: Sensitivity,
    pub(crate) mode: Option<RedactionMode>,
}

impl Default for FieldPolicy {
    fn default() -> Self {
        Self {
            sensitivity: Sensitivity::Public,
            mode: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Violation {
    pub(crate) pointer: String,
    pub(crate) detail: String,
}

pub(crate) type StructPolicies = BTreeMap<String, BTreeMap<String, FieldPolicy>>;

pub(crate) fn collect_struct_policies(schema: &Value) -> Result<StructPolicies, Vec<Violation>> {
    let violations = validate_schema(schema);
    if !violations.is_empty() {
        return Err(violations);
    }
    let mut out = BTreeMap::new();
    collect_struct_policies_node(schema, &mut out);
    Ok(out)
}

fn collect_struct_policies_node(schema: &Value, out: &mut StructPolicies) {
    let Value::Object(map) = schema else {
        return;
    };

    if let Some(title) = map.get("title").and_then(Value::as_str) {
        collect_properties_for_type(title, map, out);
    }
    // typify names definitions from their map key, even when an authored `title` is longer.
    // Preserve both aliases so `$ref` sibling policies reach the actual generated Rust struct.
    for definitions_key in NAMED_SUBSCHEMA_KEYS {
        if let Some(definitions) = map.get(*definitions_key).and_then(Value::as_object) {
            for (name, definition) in definitions {
                if let Some(definition) = definition.as_object() {
                    collect_properties_for_type(&definition_type_name(name), definition, out);
                }
            }
        }
    }

    for value in map.values() {
        recurse_schema_value(value, out);
    }
}

fn collect_properties_for_type(
    type_name: &str,
    schema: &serde_json::Map<String, Value>,
    out: &mut StructPolicies,
) {
    let Some(props) = schema.get(PROPS).and_then(Value::as_object) else {
        return;
    };
    let fields = out.entry(type_name.to_string()).or_default();
    for (name, prop_schema) in props {
        if let Ok(policy) = parse_policy(name, prop_schema) {
            fields.insert(name.clone(), policy);
        }
    }
}

fn definition_type_name(name: &str) -> String {
    let mut output = String::new();
    for segment in name.split(['-', '_']).filter(|segment| !segment.is_empty()) {
        let mut chars = segment.chars();
        if let Some(first) = chars.next() {
            output.push(first.to_ascii_uppercase());
            output.extend(chars);
        }
    }
    output
}

fn recurse_schema_value(value: &Value, out: &mut StructPolicies) {
    match value {
        Value::Object(_) => collect_struct_policies_node(value, out),
        Value::Array(values) => {
            for value in values {
                recurse_schema_value(value, out);
            }
        }
        _ => {}
    }
}

pub(crate) fn validate_schema(schema: &Value) -> Vec<Violation> {
    let mut out = Vec::new();
    validate_schema_node(schema, "", &mut out);
    out
}

fn validate_schema_node(schema: &Value, path: &str, out: &mut Vec<Violation>) {
    let Value::Object(map) = schema else {
        return;
    };

    if map.contains_key(X_SENSITIVE) {
        out.push(Violation {
            pointer: show_path(path).to_string(),
            detail: format!("{X_SENSITIVE} 已废弃；请在字段 property 上声明 {X_PII}/{X_REDACTION}"),
        });
    }

    if let Some(props) = map.get(PROPS).and_then(Value::as_object) {
        for (name, prop_schema) in props {
            let field_path = child(path, name);
            if let Err(detail) = parse_policy(name, prop_schema) {
                out.push(Violation {
                    pointer: field_path.clone(),
                    detail,
                });
            }
            validate_schema_node(prop_schema, &field_path, out);
        }
    }

    for key in [
        "items",
        "additionalProperties",
        "not",
        "allOf",
        "anyOf",
        "oneOf",
        "definitions",
        "$defs",
    ] {
        if let Some(value) = map.get(key) {
            validate_schema_value(value, &child(path, key), out);
        }
    }
}

fn validate_schema_value(value: &Value, path: &str, out: &mut Vec<Violation>) {
    match value {
        Value::Object(_) => validate_schema_node(value, path, out),
        Value::Array(values) => {
            for (idx, value) in values.iter().enumerate() {
                validate_schema_value(value, &format!("{path}[{idx}]"), out);
            }
        }
        _ => {}
    }
}

pub(crate) fn compare_policy_changes(old: &Value, new: &Value) -> Vec<Violation> {
    let mut out = Vec::new();
    compare_policy_node(old, new, "", &mut out);
    out
}

fn compare_policy_node(old: &Value, new: &Value, path: &str, out: &mut Vec<Violation>) {
    if !path.is_empty() {
        let old_policy = raw_policy_tuple(old);
        let new_policy = raw_policy_tuple(new);
        if old_policy != new_policy {
            out.push(Violation {
                pointer: path.to_string(),
                detail: format!(
                    "字段 `{}` redaction policy 改变：旧 {:?}，新 {:?}",
                    show_path(path),
                    old_policy,
                    new_policy
                ),
            });
        }
    }

    for key in MAP_SUBSCHEMA_KEYS {
        compare_map_subschemas(old, new, key, path, out);
    }
    for key in NAMED_SUBSCHEMA_KEYS {
        let container_path = child(path, key);
        compare_map_subschemas(old, new, key, &container_path, out);
    }
    for key in VALUE_SUBSCHEMA_KEYS {
        compare_value_subschema(old, new, key, path, out);
    }
}

fn compare_map_subschemas(
    old: &Value,
    new: &Value,
    key: &str,
    pointer_base: &str,
    out: &mut Vec<Violation>,
) {
    let (Some(old_children), Some(new_children)) = (
        old.get(key).and_then(Value::as_object),
        new.get(key).and_then(Value::as_object),
    ) else {
        return;
    };

    for (name, old_child) in old_children {
        let Some(new_child) = new_children.get(name) else {
            continue;
        };
        let child_path = child(pointer_base, name);
        compare_policy_node(old_child, new_child, &child_path, out);
    }
}

fn compare_value_subschema(
    old: &Value,
    new: &Value,
    key: &str,
    path: &str,
    out: &mut Vec<Violation>,
) {
    let (Some(old_value), Some(new_value)) = (old.get(key), new.get(key)) else {
        return;
    };

    match key {
        "items" => compare_items(old_value, new_value, path, out),
        "additionalProperties" => {
            compare_schema_value(old_value, new_value, &format!("{path}{{}}"), out);
        }
        "not" => compare_schema_value(old_value, new_value, &child(path, key), out),
        "allOf" | "anyOf" | "oneOf" => compare_schema_array(old_value, new_value, path, out),
        _ => {}
    }
}

fn compare_items(old: &Value, new: &Value, path: &str, out: &mut Vec<Violation>) {
    match (old, new) {
        (Value::Object(_), Value::Object(_)) => {
            compare_policy_node(old, new, &format!("{path}[]"), out);
        }
        (Value::Array(old_values), Value::Array(new_values)) => {
            for (idx, old_value) in old_values.iter().enumerate() {
                let Some(new_value) = new_values.get(idx) else {
                    continue;
                };
                compare_schema_value(old_value, new_value, &format!("{path}[{idx}]"), out);
            }
        }
        _ => {}
    }
}

fn compare_schema_array(old: &Value, new: &Value, path: &str, out: &mut Vec<Violation>) {
    match (old, new) {
        (Value::Array(old_values), Value::Array(new_values)) => {
            for (idx, old_value) in old_values.iter().enumerate() {
                let Some(new_value) = new_values.get(idx) else {
                    continue;
                };
                compare_schema_value(old_value, new_value, &format!("{path}[{idx}]"), out);
            }
        }
        (Value::Object(_), Value::Object(_)) => compare_schema_value(old, new, path, out),
        _ => {}
    }
}

fn compare_schema_value(old: &Value, new: &Value, path: &str, out: &mut Vec<Violation>) {
    if old.is_object() && new.is_object() {
        compare_policy_node(old, new, path, out);
    }
}

fn raw_policy_tuple(schema: &Value) -> (Option<String>, Option<String>) {
    let pii = schema
        .get(X_PII)
        .and_then(Value::as_str)
        .map(str::to_string);
    let redaction = schema
        .get(X_REDACTION)
        .and_then(Value::as_str)
        .map(str::to_string);
    (pii, redaction)
}

fn parse_policy(field_name: &str, schema: &Value) -> Result<FieldPolicy, String> {
    let Some(map) = schema.as_object() else {
        return Ok(FieldPolicy::default());
    };

    let pii = match map.get(X_PII) {
        Some(Value::String(value)) => Some(parse_pii(value)?),
        Some(_) => return Err(format!("{X_PII} 必须是 string enum")),
        None => None,
    };
    let redaction = match map.get(X_REDACTION) {
        Some(Value::String(value)) => Some(parse_redaction(value)?),
        Some(_) => return Err(format!("{X_REDACTION} 必须是 string enum")),
        None => None,
    };

    if is_high_risk_field(field_name) && pii.is_none() && !is_protective_redaction(redaction) {
        return Err(format!(
            "高风险字段 `{field_name}` 必须显式声明 {X_PII} 或非 public 的 {X_REDACTION}"
        ));
    }

    match (pii, redaction) {
        (Some(kind), None) => Ok(FieldPolicy {
            sensitivity: Sensitivity::Pii(kind),
            mode: None,
        }),
        (
            Some(kind),
            Some(RedactionToken::Mode(
                mode @ (RedactionMode::Fixed
                | RedactionMode::Last4
                | RedactionMode::EmailMask
                | RedactionMode::Drop),
            )),
        ) => Ok(FieldPolicy {
            sensitivity: Sensitivity::Pii(kind),
            mode: Some(mode),
        }),
        (Some(_), Some(RedactionToken::Sensitivity(_))) => Err(format!(
            "{X_PII} 已声明 sensitivity，不得再用 {X_REDACTION}=public/internal/secret 改写 sensitivity"
        )),
        (None, None) => Ok(FieldPolicy::default()),
        (None, Some(RedactionToken::Sensitivity(sensitivity))) => Ok(FieldPolicy {
            sensitivity,
            mode: None,
        }),
        (None, Some(RedactionToken::Mode(mode))) => Ok(FieldPolicy {
            sensitivity: Sensitivity::Internal,
            mode: Some(mode),
        }),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RedactionToken {
    Sensitivity(Sensitivity),
    Mode(RedactionMode),
}

fn parse_pii(value: &str) -> Result<PiiKind, String> {
    match value {
        "generic" => Ok(PiiKind::Generic),
        "email" => Ok(PiiKind::Email),
        "phone" => Ok(PiiKind::Phone),
        "name" => Ok(PiiKind::Name),
        "address" => Ok(PiiKind::Address),
        other => Err(format!(
            "未知 {X_PII}={other:?}；支持 generic/email/phone/name/address"
        )),
    }
}

fn parse_redaction(value: &str) -> Result<RedactionToken, String> {
    match value {
        "public" => Ok(RedactionToken::Sensitivity(Sensitivity::Public)),
        "internal" => Ok(RedactionToken::Sensitivity(Sensitivity::Internal)),
        "secret" => Ok(RedactionToken::Sensitivity(Sensitivity::Secret)),
        "fixed" => Ok(RedactionToken::Mode(RedactionMode::Fixed)),
        "last4" => Ok(RedactionToken::Mode(RedactionMode::Last4)),
        "email_mask" => Ok(RedactionToken::Mode(RedactionMode::EmailMask)),
        "drop" => Ok(RedactionToken::Mode(RedactionMode::Drop)),
        "hash" => Err(format!(
            "{X_REDACTION}=hash 已移除；contract redaction 不再生成关联令牌，需要在运行时代码中使用 secure::redact_hash(value, &RedactionHashKey)"
        )),
        other => Err(format!(
            "未知 {X_REDACTION}={other:?}；支持 public/internal/secret/fixed/last4/email_mask/drop"
        )),
    }
}

fn is_protective_redaction(redaction: Option<RedactionToken>) -> bool {
    !matches!(
        redaction,
        None | Some(RedactionToken::Sensitivity(Sensitivity::Public))
    )
}

/// 「高风险敏感字段名」判据——observe 面（R16 redaction 强制策略）与 storage 面（R17 `x-at-rest`
/// 强制 `x-protection` 覆盖，`protection.rs`）共用同一判据，避免关键词表两处漂移（DRY，ADR-011 D1
/// 两面正交但「哪些字段名敏感」是同一概念）。
pub(crate) fn is_high_risk_field(field_name: &str) -> bool {
    let lower = field_name.to_ascii_lowercase();
    [
        "password",
        "passwd",
        "secret",
        "token",
        "credential",
        "apikey",
        "api_key",
        "key",
        "authorization",
        "cookie",
        "jwt",
        "session",
        "bearer",
        "salt",
        "private",
    ]
    .iter()
    .any(|kw| lower.contains(kw))
        || matches!(
            lower.as_str(),
            "subject"
                | "subjectid"
                | "principal"
                | "principalid"
                | "payload"
                | "metadata"
                | "actor"
        )
}

fn child(path: &str, seg: &str) -> String {
    if path.is_empty() {
        seg.to_string()
    } else {
        format!("{path}.{seg}")
    }
}

fn show_path(path: &str) -> &str {
    if path.is_empty() { "(root)" } else { path }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn validate_rejects_legacy_x_sensitive() {
        let schema = json!({"title":"T","type":"object","x-sensitive":true});
        let findings = validate_schema(&schema);
        assert!(findings.iter().any(|f| f.detail.contains(X_SENSITIVE)));
    }

    #[test]
    fn validate_rejects_invalid_enums_and_hash_redaction() {
        let schema = json!({
            "title":"T",
            "type":"object",
            "properties": {
                "email": {"type":"string", "x-pii":"bogus"},
                "phone": {"type":"string", "x-pii":"phone", "x-redaction":"hash"},
                "other": {"type":"string", "x-redaction":"show"}
            }
        });
        let findings = validate_schema(&schema);
        assert_eq!(findings.len(), 3, "{findings:?}");
    }

    #[test]
    fn validate_rejects_high_risk_field_without_policy() {
        let schema = json!({
            "title":"T",
            "type":"object",
            "properties": {
                "password": {"type":"string"},
                "subject": {"type":"string", "x-pii":"generic"}
            }
        });
        let findings = validate_schema(&schema);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].detail.contains("password"));
    }

    #[test]
    fn definition_key_alias_preserves_ref_sibling_redaction_for_typify_name() {
        let policies = collect_struct_policies(&json!({
            "title": "Root",
            "definitions": {
                "desired": {
                    "title": "LongDesiredTitle",
                    "type": "object",
                    "properties": {
                        "authorizationReceiptId": {
                            "$ref": "#/definitions/authorizationReceiptId",
                            "x-redaction": "internal"
                        }
                    }
                }
            }
        }))
        .expect("valid policies");
        assert_eq!(
            policies["Desired"]["authorizationReceiptId"].sensitivity,
            Sensitivity::Internal
        );
    }

    #[test]
    fn validate_rejects_secure_key_high_risk_fields_without_policy() {
        let schema = json!({
            "title":"T",
            "type":"object",
            "properties": {
                "sessionId": {"type":"string"},
                "apiKey": {"type":"string"},
                "Authorization": {"type":"string"},
                "cookie": {"type":"string"},
                "jwt": {"type":"string"},
                "bearer": {"type":"string"},
                "salt": {"type":"string"},
                "privateKey": {"type":"string"},
                "publicName": {"type":"string"}
            }
        });
        let findings = validate_schema(&schema);
        assert_eq!(findings.len(), 8, "{findings:?}");
        assert!(findings.iter().all(|f| !f.detail.contains("publicName")));
    }

    #[test]
    fn collect_struct_policies_defaults_public_and_recurses() -> anyhow::Result<()> {
        let schema = json!({
            "title":"Outer",
            "type":"object",
            "properties": {
                "id": {"type":"string"},
                "data": {
                    "title":"Inner",
                    "type":"object",
                    "properties": {
                        "subject": {"type":"string", "x-pii":"generic"}
                    }
                }
            }
        });
        let policies = match collect_struct_policies(&schema) {
            Ok(policies) => policies,
            Err(findings) => anyhow::bail!("valid redaction policy should collect: {findings:?}"),
        };
        assert_eq!(
            policies["Outer"]["id"],
            FieldPolicy {
                sensitivity: Sensitivity::Public,
                mode: None
            }
        );
        assert_eq!(
            policies["Inner"]["subject"],
            FieldPolicy {
                sensitivity: Sensitivity::Pii(PiiKind::Generic),
                mode: None
            }
        );
        Ok(())
    }

    #[test]
    fn collect_struct_policies_rejects_invalid_policy() -> anyhow::Result<()> {
        let schema = json!({
            "title":"T",
            "type":"object",
            "properties": {
                "apiKey": {"type":"string"}
            }
        });
        let findings = match collect_struct_policies(&schema) {
            Ok(policies) => {
                anyhow::bail!("invalid redaction policy should fail closed: {policies:?}")
            }
            Err(findings) => findings,
        };
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].pointer, "apiKey");
        Ok(())
    }

    #[test]
    fn compare_policy_changes_reports_existing_field_drift() {
        let old = json!({"properties":{"subject":{"type":"string","x-pii":"generic"}}});
        let new = json!({"properties":{"subject":{"type":"string","x-redaction":"public"}}});
        let findings = compare_policy_changes(&old, &new);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].pointer, "subject");
    }
}
