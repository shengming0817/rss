//! JSON Schema 字段级 storage-protection 扩展单源（#1468）。
//!
//! `x-protection`（字段级 object）+ `x-at-rest`（schema 级 bool opt-in）声明 at-rest 加密保护语义，
//! 是 contract authoring → validate/breaking 的唯一 storage-encryption **声明面**——与 observe-time 的
//! `x-pii`/`x-redaction`（`redaction.rs`，#1358）**正交、不混用**（ADR-011 D1）。framework 底座只立声明层、
//! 不接真实加解密（ADR-011 D1b）；真实 AAD/AEAD-v2 类型与 KeyProvider 归 #1465/#1466。
//!
//! 语义单源 = `docs/architecture/202606271536-011-field-protection-boundary.md`（ADR-011 D2 AAD 维度 /
//! D4 deterministic 稳定子集）。本模块只做 schema 内容校验与漂移比对（Medium）；遍历范式镜像 `redaction.rs`
//! （同形递归，刻意不抽共享 walker 以保两面正交）。
//!
//! INVARIANT: CONTRACT-PROTECTION-POLICY-01 — `x-protection`/`x-at-rest` 声明合法且完整（消费见 validate.rs R17）。
//! validate 与 breaking 同形遍历 `properties`/`patternProperties`/`items`/`$defs`/oneOf... 子 schema 容器，两路径对称。

use super::redaction::is_high_risk_field;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub(crate) const X_PROTECTION: &str = "x-protection";
pub(crate) const X_AT_REST: &str = "x-at-rest";

const PROPS: &str = "properties";
const PATTERN_PROPS: &str = "patternProperties";
const REF: &str = "$ref";

/// `x-protection` block 字段名（DRY：各在解析路径出现 ≥3 次，rust-standards「同义字符串重复三次抽 const」）。
const KEY_AT_REST: &str = "atRest";
const KEY_MODE: &str = "mode";
const KEY_KEY_SCOPE: &str = "keyScope";
const KEY_AAD: &str = "aad";
const KEY_REASON: &str = "reason";

/// `x-protection` block 允许的字段（deny-unknown，因 `serde_json::Value` 无 `deny_unknown_fields`）。
const KNOWN_KEYS: &[&str] = &[KEY_AT_REST, KEY_MODE, KEY_KEY_SCOPE, KEY_AAD, KEY_REASON];

/// AAD 复合域坐标维度（ADR-011 D2，camelCase wire）。
const AAD_TENANT: &str = "tenant";
const AAD_CONFIG_KEY: &str = "configKey";
const AAD_FIELD: &str = "field";
const AAD_SCHEMA_VERSION: &str = "schemaVersion";
const KNOWN_AAD_DIMS: &[&str] = &[AAD_TENANT, AAD_CONFIG_KEY, AAD_FIELD, AAD_SCHEMA_VERSION];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AtRest {
    Plain,
    Encrypt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProtectionMode {
    Randomized,
    Deterministic,
    BlindIndex,
}

impl ProtectionMode {
    pub(crate) fn as_wire(self) -> &'static str {
        match self {
            Self::Randomized => "randomized",
            Self::Deterministic => "deterministic",
            Self::BlindIndex => "blindIndex",
        }
    }
    /// deterministic / blindIndex 暴露明文相等性（pattern leak），须显式 reason + 稳定子集 AAD（D4）。
    fn is_equality_revealing(self) -> bool {
        matches!(self, Self::Deterministic | Self::BlindIndex)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AadDim {
    Tenant,
    ConfigKey,
    Field,
    SchemaVersion,
}

impl AadDim {
    pub(crate) fn as_wire(self) -> &'static str {
        match self {
            Self::Tenant => AAD_TENANT,
            Self::ConfigKey => AAD_CONFIG_KEY,
            Self::Field => AAD_FIELD,
            Self::SchemaVersion => AAD_SCHEMA_VERSION,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FieldProtectionPolicy {
    pub(crate) at_rest: AtRest,
    pub(crate) mode: Option<ProtectionMode>,
    pub(crate) key_scope: Option<String>,
    pub(crate) aad: Vec<AadDim>,
    pub(crate) reason: Option<String>,
}

pub(crate) type StructProtectionPolicies =
    BTreeMap<String, BTreeMap<String, FieldProtectionPolicy>>;

/// 一处校验/漂移违例：JSON 路径（dotted，root = ""）+ 详情。与 `redaction::Violation` 同形但独立，
/// 保两面模块互不耦合（ADR-011 D1）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Violation {
    pub(crate) pointer: String,
    pub(crate) detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ScalarShape {
    Absent,
    Single(String),
    NonScalar,
}

impl ScalarShape {
    fn combine(self, other: Self) -> Self {
        match (self, other) {
            (Self::NonScalar, _) | (_, Self::NonScalar) => Self::NonScalar,
            (Self::Absent, shape) | (shape, Self::Absent) => shape,
            (Self::Single(left), Self::Single(right)) if left == right => Self::Single(left),
            (Self::Single(_), Self::Single(_)) => Self::NonScalar,
        }
    }

    fn is_single_scalar(&self) -> bool {
        matches!(self, Self::Single(_))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SchemaShape {
    declares_null: bool,
    scalar: ScalarShape,
}

pub(crate) fn collect_struct_policies(
    schema: &Value,
) -> Result<StructProtectionPolicies, Vec<Violation>> {
    let violations = validate_schema(schema);
    if !violations.is_empty() {
        return Err(violations);
    }
    let mut out = BTreeMap::new();
    let mut metadata_violations = Vec::new();
    collect_struct_policies_node(schema, schema, "", &mut out, &mut metadata_violations);
    if metadata_violations.is_empty() {
        Ok(out)
    } else {
        Err(metadata_violations)
    }
}

fn collect_struct_policies_node(
    schema: &Value,
    root: &Value,
    path: &str,
    out: &mut StructProtectionPolicies,
    violations: &mut Vec<Violation>,
) {
    let Value::Object(map) = schema else {
        return;
    };
    reject_pattern_property_metadata(map, root, path, violations);

    if let Some(title) = map.get("title").and_then(Value::as_str)
        && let Some(props) = map.get(PROPS).and_then(Value::as_object)
    {
        let fields = out.entry(title.to_string()).or_default();
        for (name, prop_schema) in props {
            collect_property_metadata(prop_schema, root, name, fields, violations, &mut Vec::new());
        }
    }

    for map_key in [PROPS, PATTERN_PROPS] {
        if let Some(children) = map.get(map_key).and_then(Value::as_object) {
            for (name, child_schema) in children {
                collect_struct_policies_node(
                    child_schema,
                    root,
                    &child(path, name),
                    out,
                    violations,
                );
            }
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
            collect_schema_value(value, root, &child(path, key), out, violations);
        }
    }
}

fn collect_property_metadata(
    schema: &Value,
    root: &Value,
    field_path: &str,
    fields: &mut BTreeMap<String, FieldProtectionPolicy>,
    violations: &mut Vec<Violation>,
    ref_stack: &mut Vec<String>,
) {
    let Value::Object(map) = schema else {
        return;
    };

    if let Some(reference) = map.get(REF).and_then(Value::as_str) {
        collect_ref_property_metadata(reference, root, field_path, fields, violations, ref_stack);
        return;
    }

    if map.contains_key(X_PROTECTION)
        && let Ok(policy) = parse_protection(map)
    {
        fields.insert(field_path.to_string(), policy);
    }

    if let Some(props) = map.get(PROPS).and_then(Value::as_object) {
        for (name, child_schema) in props {
            collect_property_metadata(
                child_schema,
                root,
                &child(field_path, name),
                fields,
                violations,
                ref_stack,
            );
        }
    }
    for (key, suffix) in [
        ("items", "[]"),
        ("additionalProperties", ".*"),
        ("not", ""),
        ("allOf", ""),
        ("anyOf", ""),
        ("oneOf", ""),
    ] {
        if let Some(value) = map.get(key) {
            collect_property_metadata_value(
                value,
                root,
                &format!("{field_path}{suffix}"),
                fields,
                violations,
                ref_stack,
            );
        }
    }
}

fn collect_ref_property_metadata(
    reference: &str,
    root: &Value,
    field_path: &str,
    fields: &mut BTreeMap<String, FieldProtectionPolicy>,
    violations: &mut Vec<Violation>,
    ref_stack: &mut Vec<String>,
) {
    if ref_stack.iter().any(|seen| seen == reference) {
        violations.push(Violation {
            pointer: show_path(field_path).to_string(),
            detail: format!("{REF} cycle in FieldProtectionMetadata collector: {reference}"),
        });
        return;
    }
    let Some(target) = resolve_local_ref(root, reference) else {
        violations.push(Violation {
            pointer: show_path(field_path).to_string(),
            detail: format!(
                "{REF} {reference:?} cannot be resolved for FieldProtectionMetadata; only local JSON Pointer refs are supported"
            ),
        });
        return;
    };
    ref_stack.push(reference.to_string());
    collect_property_metadata(target, root, field_path, fields, violations, ref_stack);
    ref_stack.pop();
}

fn resolve_local_ref<'a>(root: &'a Value, reference: &str) -> Option<&'a Value> {
    if reference == "#" {
        return Some(root);
    }
    root.pointer(reference.strip_prefix('#')?)
}

fn collect_property_metadata_value(
    value: &Value,
    root: &Value,
    field_path: &str,
    fields: &mut BTreeMap<String, FieldProtectionPolicy>,
    violations: &mut Vec<Violation>,
    ref_stack: &mut Vec<String>,
) {
    match value {
        Value::Object(_) => {
            collect_property_metadata(value, root, field_path, fields, violations, ref_stack)
        }
        Value::Array(values) => {
            for value in values {
                collect_property_metadata_value(
                    value, root, field_path, fields, violations, ref_stack,
                );
            }
        }
        _ => {}
    }
}

fn reject_pattern_property_metadata(
    map: &Map<String, Value>,
    root: &Value,
    path: &str,
    violations: &mut Vec<Violation>,
) {
    let Some(patterns) = map.get(PATTERN_PROPS).and_then(Value::as_object) else {
        return;
    };
    for (pattern, schema) in patterns {
        if contains_protection(schema, root, &mut Vec::new()) {
            violations.push(Violation {
                pointer: show_path(&child(path, pattern)).to_string(),
                detail: format!(
                    "{X_PROTECTION} under patternProperties cannot be emitted as stable FieldProtectionMetadata; use explicit properties"
                ),
            });
        }
    }
}

fn contains_protection(value: &Value, root: &Value, ref_stack: &mut Vec<String>) -> bool {
    match value {
        Value::Object(map) => {
            if map.contains_key(X_PROTECTION) {
                return true;
            }
            if let Some(reference) = map.get(REF).and_then(Value::as_str) {
                if ref_stack.iter().any(|seen| seen == reference) {
                    return false;
                }
                if let Some(target) = resolve_local_ref(root, reference) {
                    ref_stack.push(reference.to_string());
                    let found = contains_protection(target, root, ref_stack);
                    ref_stack.pop();
                    if found {
                        return true;
                    }
                }
            }
            map.values()
                .any(|value| contains_protection(value, root, ref_stack))
        }
        Value::Array(values) => values
            .iter()
            .any(|value| contains_protection(value, root, ref_stack)),
        _ => false,
    }
}

fn collect_schema_value(
    value: &Value,
    root: &Value,
    path: &str,
    out: &mut StructProtectionPolicies,
    violations: &mut Vec<Violation>,
) {
    match value {
        Value::Object(_) => collect_struct_policies_node(value, root, path, out, violations),
        Value::Array(values) => {
            for (idx, value) in values.iter().enumerate() {
                collect_schema_value(value, root, &format!("{path}[{idx}]"), out, violations);
            }
        }
        _ => {}
    }
}

// ───────────────────────────── validate（R17 单源）─────────────────────────────

/// 校验整棵 schema 的 `x-protection` / `x-at-rest` 声明合法且完整。空 = 全过。
pub(crate) fn validate_schema(schema: &Value) -> Vec<Violation> {
    let mut out = Vec::new();
    validate_schema_node(schema, schema, "", None, false, &mut out);
    out
}

/// `field_name` = 本节点作为命名字段的名字（root / 非命名容器子 schema 为 `None`）；`at_rest` = 祖先链上
/// 是否已 opt-in 持久化（`x-at-rest:true` **递归传播**进整棵子树，fail-closed）。覆盖检查在**本节点**做
/// （而非父循环），故字段自身 `x-at-rest:true` 经 (2) 并入 `at_rest` 后亦触发自检，不绕过（F2）。
fn validate_schema_node(
    schema: &Value,
    root: &Value,
    path: &str,
    field_name: Option<&str>,
    at_rest: bool,
    out: &mut Vec<Violation>,
) {
    let Value::Object(map) = schema else {
        return;
    };

    // (1) 本节点 `x-protection` block 内部一致性（字段级 property 或任意带 block 的子 schema）。
    if map.contains_key(X_PROTECTION) {
        match parse_protection(map) {
            Ok(policy) => validate_schema_shape_for_policy(map, root, path, &policy, out),
            Err(detail) => out.push(Violation {
                pointer: show_path(path).to_string(),
                detail,
            }),
        }
    }

    // (2) 解析本节点 `x-at-rest`（含类型校验），与祖先 opt-in 合取——一旦 opt-in 子树内保持 opt-in。
    let at_rest = resolve_at_rest(map, path, at_rest, out);

    // (3) 本节点自身覆盖：opt-in 子树内、本节点是高风险命名字段、且缺 `x-protection` → 拒。
    if at_rest
        && let Some(name) = field_name
        && is_high_risk_field(name)
        && !map.contains_key(X_PROTECTION)
    {
        out.push(Violation {
            pointer: show_path(path).to_string(),
            detail: format!(
                "schema 标记 {X_AT_REST}:true，高风险持久化字段 `{name}` 必须显式声明 {X_PROTECTION}（atRest: plain|encrypt）"
            ),
        });
    }

    // (4) 递归 properties / patternProperties（传子字段名，与 breaking 遍历对称，F3）。
    for map_key in [PROPS, PATTERN_PROPS] {
        if let Some(children) = map.get(map_key).and_then(Value::as_object) {
            for (name, child_schema) in children {
                validate_schema_node(
                    child_schema,
                    root,
                    &child(path, name),
                    Some(name),
                    at_rest,
                    out,
                );
            }
        }
    }
    // (5) 其它子 schema 容器（非命名字段，field_name=None）。
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
            validate_schema_value(value, root, &child(path, key), at_rest, out);
        }
    }
}

fn validate_schema_value(
    value: &Value,
    root: &Value,
    path: &str,
    at_rest: bool,
    out: &mut Vec<Violation>,
) {
    match value {
        Value::Object(_) => validate_schema_node(value, root, path, None, at_rest, out),
        Value::Array(values) => {
            for (idx, value) in values.iter().enumerate() {
                validate_schema_value(value, root, &format!("{path}[{idx}]"), at_rest, out);
            }
        }
        _ => {}
    }
}

/// `x-protection` 与 JSON Schema 形态之间的跨字段不变式（#1476）。
///
/// 这些约束不能放进 [`parse_protection`]，因为它只解析 `x-protection` block 本身；nullable / scalar
/// 语义取自同一 schema object 的 `type` / `oneOf` / `anyOf` 等 JSON Schema 字段。
fn validate_schema_shape_for_policy(
    map: &Map<String, Value>,
    root: &Value,
    path: &str,
    policy: &FieldProtectionPolicy,
    out: &mut Vec<Violation>,
) {
    if policy.at_rest != AtRest::Encrypt {
        return;
    }

    let shape = match analyze_schema_shape(map, root, &mut Vec::new()) {
        Ok(shape) => shape,
        Err(detail) => {
            out.push(Violation {
                pointer: show_path(path).to_string(),
                detail,
            });
            return;
        }
    };

    if shape.declares_null {
        out.push(Violation {
            pointer: show_path(path).to_string(),
            detail: format!(
                "{X_PROTECTION} atRest:encrypt 不支持 nullable schema（null 会泄漏明文空值状态）；\
                 当前无显式 null-policy，须改为非 null 字段或另行设计加密 null sentinel"
            ),
        });
    }

    if policy.mode == Some(ProtectionMode::BlindIndex) && !shape.scalar.is_single_scalar() {
        out.push(Violation {
            pointer: show_path(path).to_string(),
            detail: format!(
                "{X_PROTECTION} mode:blindIndex 只支持非 nullable scalar 字段（string/number/integer/boolean）的等值索引"
            ),
        });
    }
}

/// 保守判定：当前 schema 与本地 `$ref` 目标任一声明了 `null`，即视为 nullable leakage 风险；
/// `blindIndex` 则要求当前 schema 与 `$ref` 目标合并后仍是单一 scalar 类型。
fn analyze_schema_shape(
    map: &Map<String, Value>,
    root: &Value,
    ref_stack: &mut Vec<String>,
) -> Result<SchemaShape, String> {
    let mut shape = SchemaShape {
        declares_null: schema_direct_declares_null(map),
        scalar: schema_direct_scalar_shape(map),
    };

    for key in ["oneOf", "anyOf", "allOf"] {
        if let Some(items) = map.get(key).and_then(Value::as_array) {
            for item in items {
                let nested = analyze_schema_shape_value(item, root, ref_stack)?;
                shape.declares_null |= nested.declares_null;
            }
        }
    }

    if let Some(reference) = map.get(REF).and_then(Value::as_str) {
        let referenced = analyze_ref_shape(reference, root, ref_stack)?;
        shape.declares_null |= referenced.declares_null;
        shape.scalar = shape.scalar.combine(referenced.scalar);
    }

    Ok(shape)
}

fn analyze_schema_shape_value(
    value: &Value,
    root: &Value,
    ref_stack: &mut Vec<String>,
) -> Result<SchemaShape, String> {
    match value {
        Value::Object(map) => analyze_schema_shape(map, root, ref_stack),
        Value::Array(items) => {
            let mut shape = SchemaShape {
                declares_null: false,
                scalar: ScalarShape::Absent,
            };
            for item in items {
                let nested = analyze_schema_shape_value(item, root, ref_stack)?;
                shape.declares_null |= nested.declares_null;
                shape.scalar = shape.scalar.combine(nested.scalar);
            }
            Ok(shape)
        }
        _ => Ok(SchemaShape {
            declares_null: false,
            scalar: ScalarShape::Absent,
        }),
    }
}

fn analyze_ref_shape(
    reference: &str,
    root: &Value,
    ref_stack: &mut Vec<String>,
) -> Result<SchemaShape, String> {
    if ref_stack.iter().any(|seen| seen == reference) {
        return Err(format!(
            "{REF} cycle in {X_PROTECTION} schema shape validation: {reference}"
        ));
    }
    let Some(target) = resolve_local_ref(root, reference) else {
        return Err(format!(
            "{REF} {reference:?} cannot be resolved for {X_PROTECTION} schema shape validation; only local JSON Pointer refs are supported"
        ));
    };
    ref_stack.push(reference.to_string());
    let shape = analyze_schema_shape_value(target, root, ref_stack);
    ref_stack.pop();
    shape
}

fn schema_direct_declares_null(map: &Map<String, Value>) -> bool {
    type_declares_null(map.get("type"))
        || matches!(map.get("const"), Some(Value::Null))
        || map
            .get("enum")
            .and_then(Value::as_array)
            .is_some_and(|items| items.iter().any(Value::is_null))
}

fn type_declares_null(value: Option<&Value>) -> bool {
    match value {
        Some(Value::String(s)) => s == "null",
        Some(Value::Array(types)) => types.iter().any(|t| t.as_str() == Some("null")),
        _ => false,
    }
}

fn schema_direct_scalar_shape(map: &Map<String, Value>) -> ScalarShape {
    match map.get("type") {
        Some(Value::String(s)) if is_scalar_type(s) => ScalarShape::Single(s.clone()),
        Some(Value::String(_)) => ScalarShape::NonScalar,
        Some(Value::Array(types)) => match types.as_slice() {
            [only] => only
                .as_str()
                .filter(|value| is_scalar_type(value))
                .map(|value| ScalarShape::Single(value.to_string()))
                .unwrap_or(ScalarShape::NonScalar),
            _ => ScalarShape::NonScalar,
        },
        Some(_) => ScalarShape::NonScalar,
        None if map.contains_key(PROPS)
            || map.contains_key(PATTERN_PROPS)
            || map.contains_key("items") =>
        {
            ScalarShape::NonScalar
        }
        None => ScalarShape::Absent,
    }
}

fn is_scalar_type(value: &str) -> bool {
    matches!(value, "string" | "number" | "integer" | "boolean")
}

/// 解析本节点 `x-at-rest` 标记并与祖先 opt-in 合取。非 bool → 推违例、保持祖先值（不丢覆盖）。
fn resolve_at_rest(
    map: &Map<String, Value>,
    path: &str,
    inherited: bool,
    out: &mut Vec<Violation>,
) -> bool {
    match map.get(X_AT_REST) {
        None => inherited,
        Some(Value::Bool(b)) => inherited || *b,
        Some(_) => {
            out.push(Violation {
                pointer: show_path(path).to_string(),
                detail: format!("{X_AT_REST} 必须是 bool（持久化 schema opt-in 标记）"),
            });
            inherited
        }
    }
}

/// 解析并校验一个 `x-protection` block（调用方已确认 `X_PROTECTION` 键在场）。
fn parse_protection(map: &Map<String, Value>) -> Result<FieldProtectionPolicy, String> {
    let Some(obj) = map.get(X_PROTECTION).and_then(Value::as_object) else {
        return Err(format!(
            "{X_PROTECTION} 必须是 object（含 atRest 等字段），不是裸 string/其它"
        ));
    };
    for key in obj.keys() {
        if !KNOWN_KEYS.contains(&key.as_str()) {
            return Err(format!(
                "{X_PROTECTION} 含未知字段 `{key}`；支持 {}",
                KNOWN_KEYS.join("/")
            ));
        }
    }

    let at_rest = match obj.get(KEY_AT_REST) {
        Some(Value::String(s)) => parse_at_rest(s)?,
        Some(_) => return Err(format!("{X_PROTECTION}.atRest 必须是 string enum")),
        None => return Err(format!("{X_PROTECTION} 缺 atRest（plain|encrypt）")),
    };
    let mode = match obj.get(KEY_MODE) {
        Some(Value::String(s)) => Some(parse_mode(s)?),
        Some(_) => return Err(format!("{X_PROTECTION}.mode 必须是 string enum")),
        None => None,
    };

    match at_rest {
        AtRest::Plain => parse_plain(obj),
        AtRest::Encrypt => parse_encrypt(obj, mode),
    }
}

/// `atRest:plain` 不得携带 encrypt 参数（plain 携带 mode/keyScope/aad/reason = 语义不一致）。
fn parse_plain(obj: &Map<String, Value>) -> Result<FieldProtectionPolicy, String> {
    for key in [KEY_MODE, KEY_KEY_SCOPE, KEY_AAD, KEY_REASON] {
        if obj.contains_key(key) {
            return Err(format!(
                "{X_PROTECTION} atRest:plain 不得携带 `{key}`（plain 无加密参数）"
            ));
        }
    }
    Ok(FieldProtectionPolicy {
        at_rest: AtRest::Plain,
        mode: None,
        key_scope: None,
        aad: Vec::new(),
        reason: None,
    })
}

/// `atRest:encrypt`：keyScope 必填 + aad 完整 + deterministic/blindIndex 须 reason（D2/D4）。
fn parse_encrypt(
    obj: &Map<String, Value>,
    mode: Option<ProtectionMode>,
) -> Result<FieldProtectionPolicy, String> {
    let key_scope = match obj.get(KEY_KEY_SCOPE) {
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        _ => return Err(format!("{X_PROTECTION} atRest:encrypt 须声明非空 keyScope")),
    };
    let dims = parse_aad(obj.get(KEY_AAD))?;
    let mode = mode.unwrap_or(ProtectionMode::Randomized);
    validate_aad_for_mode(mode, &dims)?;
    if mode.is_equality_revealing() && !has_reason(obj) {
        return Err(format!(
            "{X_PROTECTION} mode:{} 须声明非空 reason（deterministic/blindIndex 暴露明文相等性，须文档化权衡）",
            mode.as_wire()
        ));
    }
    Ok(FieldProtectionPolicy {
        at_rest: AtRest::Encrypt,
        mode: Some(mode),
        key_scope: Some(key_scope),
        aad: dims,
        reason: obj
            .get(KEY_REASON)
            .and_then(Value::as_str)
            .map(str::to_owned),
    })
}

fn has_reason(obj: &Map<String, Value>) -> bool {
    obj.get(KEY_REASON)
        .and_then(Value::as_str)
        .is_some_and(|s| !s.trim().is_empty())
}

/// aad 必须是非空 string 数组，元素 ∈ 已知维度集（未知维度 fail-closed）。返回去重前的维度列表。
fn parse_aad(aad: Option<&Value>) -> Result<Vec<AadDim>, String> {
    let Some(Value::Array(items)) = aad else {
        return Err(format!(
            "{X_PROTECTION} atRest:encrypt 须声明非空 aad 数组（AAD 维度绑定）"
        ));
    };
    if items.is_empty() {
        return Err(format!("{X_PROTECTION}.aad 不得为空数组"));
    }
    let mut dims = Vec::with_capacity(items.len());
    for item in items {
        let Some(dim) = item.as_str() else {
            return Err(format!("{X_PROTECTION}.aad 元素必须是 string 维度名"));
        };
        if !KNOWN_AAD_DIMS.contains(&dim) {
            return Err(format!(
                "{X_PROTECTION} 未知 aad 维度 `{dim}`；支持 {}",
                KNOWN_AAD_DIMS.join("/")
            ));
        }
        dims.push(parse_aad_dim(dim)?);
    }
    Ok(dims)
}

fn parse_aad_dim(value: &str) -> Result<AadDim, String> {
    match value {
        AAD_TENANT => Ok(AadDim::Tenant),
        AAD_CONFIG_KEY => Ok(AadDim::ConfigKey),
        AAD_FIELD => Ok(AadDim::Field),
        AAD_SCHEMA_VERSION => Ok(AadDim::SchemaVersion),
        other => Err(format!(
            "{X_PROTECTION} 未知 aad 维度 `{other}`；支持 {}",
            KNOWN_AAD_DIMS.join("/")
        )),
    }
}

/// AAD 维度按 mode 的 required / forbidden 集合（**ADR-011 D2/D4 单源**，required+forbidden 同处声明，
/// 杜绝文案与校验分叉）：
/// - randomized：required = 完整复合域坐标 tenant/configKey/field/schemaVersion（D2 跨上下文绑定，含 schemaVersion → 跨版本密文不可解）。
/// - deterministic/blindIndex：required = 稳定子集 tenant/configKey/field；forbidden = schemaVersion（D4，否则 schema 演进后等值查询静默失效）。
///
/// configKey 是 D2 复合坐标的必备维度（防跨 entry replay），**不**降级为可选——ADR 是设计单源，偏离须改 ADR 而非局部放宽。
fn aad_required_dims(mode: ProtectionMode) -> &'static [&'static str] {
    if mode.is_equality_revealing() {
        &[AAD_TENANT, AAD_CONFIG_KEY, AAD_FIELD]
    } else {
        &[AAD_TENANT, AAD_CONFIG_KEY, AAD_FIELD, AAD_SCHEMA_VERSION]
    }
}

fn aad_forbidden_dims(mode: ProtectionMode) -> &'static [&'static str] {
    if mode.is_equality_revealing() {
        &[AAD_SCHEMA_VERSION]
    } else {
        &[]
    }
}

fn validate_aad_for_mode(mode: ProtectionMode, dims: &[AadDim]) -> Result<(), String> {
    let has = |d: &str| dims.iter().any(|x| x.as_wire() == d);
    for req in aad_required_dims(mode) {
        if !has(req) {
            return Err(format!(
                "{X_PROTECTION} mode:{} 的 aad 须含 {req}（ADR-011 D2 复合域坐标 {}）",
                mode.as_wire(),
                aad_required_dims(mode).join("/")
            ));
        }
    }
    for forbidden in aad_forbidden_dims(mode) {
        if has(forbidden) {
            return Err(format!(
                "{X_PROTECTION} mode:{} 的 aad 不得含 {forbidden}（D4 稳定子集，schema 演进后等值查询会静默失效）",
                mode.as_wire()
            ));
        }
    }
    Ok(())
}

fn parse_at_rest(value: &str) -> Result<AtRest, String> {
    match value {
        "plain" => Ok(AtRest::Plain),
        "encrypt" => Ok(AtRest::Encrypt),
        other => Err(format!(
            "未知 {X_PROTECTION}.atRest={other:?}；支持 plain/encrypt"
        )),
    }
}

fn parse_mode(value: &str) -> Result<ProtectionMode, String> {
    match value {
        "randomized" => Ok(ProtectionMode::Randomized),
        "deterministic" => Ok(ProtectionMode::Deterministic),
        "blindIndex" => Ok(ProtectionMode::BlindIndex),
        other => Err(format!(
            "未知 {X_PROTECTION}.mode={other:?}；支持 randomized/deterministic/blindIndex"
        )),
    }
}

// ───────────────────────────── breaking（protection 漂移比对）─────────────────────────────

/// 比对两版 schema：既有节点的 `x-protection` block 或 `x-at-rest` 标记任一改变 → 审查材料。
/// 遍历镜像 `redaction::compare_policy_changes`（同形递归 properties/items/$defs/allOf...）。
pub(crate) fn compare_policy_changes(old: &Value, new: &Value) -> Vec<Violation> {
    let mut out = Vec::new();
    compare_policy_node(old, new, "", &mut out);
    out
}

fn compare_policy_node(old: &Value, new: &Value, path: &str, out: &mut Vec<Violation>) {
    // root（path=""）也比对：`x-at-rest` 在 schema 根节点声明，撤销整棵 schema 的持久化 opt-in
    // 是保护降级、须作审查材料（不可像 redaction 那样跳 root——后者策略只在字段级、根上无策略）。
    let old_policy = raw_protection_tuple(old);
    let new_policy = raw_protection_tuple(new);
    if old_policy != new_policy {
        out.push(Violation {
            pointer: show_path(path).to_string(),
            detail: format!(
                "字段 `{}` protection policy 改变：旧 {:?}，新 {:?}",
                show_path(path),
                old_policy,
                new_policy
            ),
        });
    }

    for key in [PROPS, PATTERN_PROPS] {
        compare_map_subschemas(old, new, key, path, out);
    }
    for key in ["definitions", "$defs"] {
        let container_path = child(path, key);
        compare_map_subschemas(old, new, key, &container_path, out);
    }
    for key in [
        "items",
        "additionalProperties",
        "not",
        "allOf",
        "anyOf",
        "oneOf",
    ] {
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
        compare_policy_node(old_child, new_child, &child(pointer_base, name), out);
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

/// 既有字段的 protection 身份元组：(x-protection block, x-at-rest 标记)。任一改变即漂移。
fn raw_protection_tuple(schema: &Value) -> (Option<&Value>, Option<&Value>) {
    (schema.get(X_PROTECTION), schema.get(X_AT_REST))
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

    /// 合法 encrypt+randomized block 基线，`extra` 覆盖其字段以构造红用例变体（无 unwrap，clippy 友好）。
    fn encrypt_field(extra: Value) -> Value {
        let mut block = serde_json::Map::new();
        block.insert("atRest".to_string(), json!("encrypt"));
        block.insert("keyScope".to_string(), json!("tenant"));
        block.insert(
            "aad".to_string(),
            json!(["tenant", "configKey", "field", "schemaVersion"]),
        );
        if let Value::Object(obj) = extra {
            for (k, v) in obj {
                block.insert(k, v);
            }
        }
        json!({ "type": "string", "x-protection": Value::Object(block) })
    }

    fn schema_with(field: &str, prop: Value) -> Value {
        json!({
            "title": "ConfigEntry",
            "type": "object",
            "properties": { field: prop }
        })
    }

    // ── green ──────────────────────────────────────────────────────────────

    #[test]
    fn green_encrypt_randomized_full_aad() {
        let schema = schema_with("value", encrypt_field(json!({})));
        assert!(
            validate_schema(&schema).is_empty(),
            "{:?}",
            validate_schema(&schema)
        );
    }

    #[test]
    fn green_blind_index_stable_subset_with_reason() {
        let schema = schema_with(
            "ssn",
            json!({
                "type": "string",
                "x-protection": {
                    "atRest": "encrypt",
                    "mode": "blindIndex",
                    "keyScope": "tenant",
                    "aad": ["tenant", "configKey", "field"],
                    "reason": "ssn dedup equality lookup"
                }
            }),
        );
        assert!(
            validate_schema(&schema).is_empty(),
            "{:?}",
            validate_schema(&schema)
        );
    }

    #[test]
    fn green_plain_and_unprotected_default() {
        let schema = json!({
            "title": "T",
            "type": "object",
            "properties": {
                "note": {"type": "string"},
                "blob": {"type": "string", "x-protection": {"atRest": "plain"}}
            }
        });
        assert!(
            validate_schema(&schema).is_empty(),
            "{:?}",
            validate_schema(&schema)
        );
    }

    #[test]
    fn green_at_rest_high_risk_field_declared() {
        let schema = json!({
            "title": "Stored",
            "type": "object",
            "x-at-rest": true,
            "properties": {
                "secret": {"type": "string", "x-protection": {"atRest": "encrypt", "keyScope": "tenant", "aad": ["tenant","configKey","field","schemaVersion"]}},
                "label": {"type": "string"}
            }
        });
        assert!(
            validate_schema(&schema).is_empty(),
            "{:?}",
            validate_schema(&schema)
        );
    }

    // ── red：block 内部一致性 ─────────────────────────────────────────────

    #[test]
    fn red_block_not_object() {
        let schema = schema_with(
            "value",
            json!({"type": "string", "x-protection": "encrypt"}),
        );
        let v = validate_schema(&schema);
        assert_eq!(v.len(), 1, "{v:?}");
        assert!(v[0].detail.contains("必须是 object"));
    }

    #[test]
    fn red_unknown_block_key() {
        let schema = schema_with("value", encrypt_field(json!({"bogus": 1})));
        let v = validate_schema(&schema);
        assert!(v.iter().any(|f| f.detail.contains("未知字段")), "{v:?}");
    }

    #[test]
    fn red_unknown_at_rest_enum() {
        let schema = schema_with(
            "value",
            json!({"type": "string", "x-protection": {"atRest": "wrap"}}),
        );
        let v = validate_schema(&schema);
        assert!(v.iter().any(|f| f.detail.contains("atRest")), "{v:?}");
    }

    #[test]
    fn red_unknown_mode_enum() {
        let schema = schema_with("value", encrypt_field(json!({"mode": "convergent"})));
        let v = validate_schema(&schema);
        assert!(v.iter().any(|f| f.detail.contains("mode")), "{v:?}");
    }

    #[test]
    fn red_encrypt_missing_key_scope() {
        let schema = schema_with(
            "value",
            json!({"type": "string", "x-protection": {"atRest": "encrypt", "aad": ["tenant","field","schemaVersion"]}}),
        );
        let v = validate_schema(&schema);
        assert!(v.iter().any(|f| f.detail.contains("keyScope")), "{v:?}");
    }

    #[test]
    fn red_encrypt_missing_aad() {
        let schema = schema_with(
            "value",
            json!({"type": "string", "x-protection": {"atRest": "encrypt", "keyScope": "tenant"}}),
        );
        let v = validate_schema(&schema);
        assert!(v.iter().any(|f| f.detail.contains("aad")), "{v:?}");
    }

    #[test]
    fn red_randomized_aad_missing_schema_version() {
        let schema = schema_with(
            "value",
            json!({"type": "string", "x-protection": {"atRest": "encrypt", "keyScope": "tenant", "aad": ["tenant","configKey","field"]}}),
        );
        let v = validate_schema(&schema);
        assert!(
            v.iter().any(|f| f.detail.contains("schemaVersion")),
            "{v:?}"
        );
    }

    #[test]
    fn red_unknown_aad_dim() {
        let schema = schema_with("value", encrypt_field(json!({"aad": ["tenant", "device"]})));
        let v = validate_schema(&schema);
        assert!(v.iter().any(|f| f.detail.contains("device")), "{v:?}");
    }

    #[test]
    fn red_deterministic_without_reason() {
        let schema = schema_with(
            "value",
            json!({"type": "string", "x-protection": {"atRest": "encrypt", "mode": "deterministic", "keyScope": "tenant", "aad": ["tenant","configKey","field"]}}),
        );
        let v = validate_schema(&schema);
        assert!(v.iter().any(|f| f.detail.contains("reason")), "{v:?}");
    }

    #[test]
    fn red_blind_index_aad_contains_schema_version() {
        let schema = schema_with(
            "value",
            json!({"type": "string", "x-protection": {"atRest": "encrypt", "mode": "blindIndex", "keyScope": "tenant", "aad": ["tenant","configKey","field","schemaVersion"], "reason": "lookup"}}),
        );
        let v = validate_schema(&schema);
        assert!(
            v.iter().any(|f| f.detail.contains("schemaVersion")),
            "{v:?}"
        );
    }

    #[test]
    fn red_plain_carries_encrypt_params() {
        let schema = schema_with(
            "value",
            json!({"type": "string", "x-protection": {"atRest": "plain", "keyScope": "tenant"}}),
        );
        let v = validate_schema(&schema);
        assert!(v.iter().any(|f| f.detail.contains("plain")), "{v:?}");
    }

    // ── red：x-at-rest 强制覆盖 ───────────────────────────────────────────

    #[test]
    fn red_at_rest_high_risk_field_missing_protection() {
        let schema = json!({
            "title": "Stored",
            "type": "object",
            "x-at-rest": true,
            "properties": {
                "password": {"type": "string"},
                "label": {"type": "string"}
            }
        });
        let v = validate_schema(&schema);
        assert_eq!(v.len(), 1, "{v:?}");
        assert_eq!(v[0].pointer, "password");
    }

    #[test]
    fn red_at_rest_not_bool() {
        let schema = json!({"title": "T", "type": "object", "x-at-rest": "yes", "properties": {}});
        let v = validate_schema(&schema);
        assert!(v.iter().any(|f| f.detail.contains(X_AT_REST)), "{v:?}");
    }

    #[test]
    fn validate_recurses_into_nested_and_defs() {
        let schema = json!({
            "title": "Outer",
            "type": "object",
            "properties": {
                "inner": {
                    "type": "object",
                    "properties": {
                        "bad": {"type": "string", "x-protection": "encrypt"}
                    }
                }
            }
        });
        let v = validate_schema(&schema);
        assert_eq!(v.len(), 1, "{v:?}");
        assert_eq!(v[0].pointer, "inner.bad");
    }

    // ── breaking：漂移比对 ────────────────────────────────────────────────

    #[test]
    fn compare_reports_plain_to_encrypt() {
        let old =
            json!({"properties": {"v": {"type": "string", "x-protection": {"atRest": "plain"}}}});
        let new = json!({"properties": {"v": {"type": "string", "x-protection": {"atRest": "encrypt", "keyScope": "tenant", "aad": ["tenant","field","schemaVersion"]}}}});
        let v = compare_policy_changes(&old, &new);
        assert_eq!(v.len(), 1, "{v:?}");
        assert_eq!(v[0].pointer, "v");
    }

    #[test]
    fn compare_reports_at_rest_flip_at_root() {
        // x-at-rest 在 schema 根节点声明：撤销整棵 schema 的持久化 opt-in 必须报漂移（root 也比对）。
        let old = json!({"title": "T", "x-at-rest": true, "properties": {"v": {"type": "string"}}});
        let new =
            json!({"title": "T", "x-at-rest": false, "properties": {"v": {"type": "string"}}});
        let v = compare_policy_changes(&old, &new);
        assert!(v.iter().any(|f| f.pointer == "(root)"), "{v:?}");
    }

    #[test]
    fn compare_clean_when_unchanged_and_additive() {
        let old =
            json!({"properties": {"v": {"type": "string", "x-protection": {"atRest": "plain"}}}});
        assert!(compare_policy_changes(&old, &old).is_empty());
        // 新增字段不报漂移（既有字段未变）。
        let added = json!({"properties": {"v": {"type": "string", "x-protection": {"atRest": "plain"}}, "w": {"type": "string"}}});
        assert!(compare_policy_changes(&old, &added).is_empty());
    }

    #[test]
    fn compare_recurses_schema_containers() {
        let old = json!({"$defs": {"s": {"type": "string", "x-protection": {"atRest": "plain"}}}});
        let new = json!({"$defs": {"s": {"type": "string", "x-protection": {"atRest": "encrypt", "keyScope": "tenant", "aad": ["tenant","field","schemaVersion"]}}}});
        let v = compare_policy_changes(&old, &new);
        assert!(v.iter().any(|f| f.pointer == "$defs.s"), "{v:?}");
    }

    // ── red：补全分支覆盖（reviewer A/B/C findings）────────────────────────

    #[test]
    fn red_aad_not_array() {
        let schema = schema_with("value", encrypt_field(json!({"aad": "tenant"})));
        let v = validate_schema(&schema);
        assert!(
            v.iter().any(|f| f.detail.contains("非空 aad 数组")),
            "{v:?}"
        );
    }

    #[test]
    fn red_aad_empty_array() {
        let schema = schema_with("value", encrypt_field(json!({"aad": []})));
        let v = validate_schema(&schema);
        assert!(v.iter().any(|f| f.detail.contains("不得为空数组")), "{v:?}");
    }

    #[test]
    fn red_at_rest_wrong_type() {
        // atRest 是 bool 而非 string enum → 拒（区别于 red_unknown_at_rest_enum 的错误 string）。
        let schema = schema_with(
            "value",
            json!({"type": "string", "x-protection": {"atRest": true}}),
        );
        let v = validate_schema(&schema);
        assert!(
            v.iter().any(|f| f.detail.contains("必须是 string enum")),
            "{v:?}"
        );
    }

    #[test]
    fn red_deterministic_aad_contains_schema_version() {
        // deterministic 与 blindIndex 同走 is_equality_revealing 分支，独立红用例自文档化（D4）。
        let schema = schema_with(
            "value",
            json!({"type": "string", "x-protection": {"atRest": "encrypt", "mode": "deterministic", "keyScope": "tenant", "aad": ["tenant","configKey","field","schemaVersion"], "reason": "eq lookup"}}),
        );
        let v = validate_schema(&schema);
        assert!(
            v.iter().any(|f| f.detail.contains("schemaVersion")),
            "{v:?}"
        );
    }

    #[test]
    fn red_at_rest_covers_nested_high_risk_field() {
        // x-at-rest 递归传播：root opt-in 后嵌套对象的高风险字段缺 x-protection 仍被拒（fail-closed）。
        let schema = json!({
            "title": "Stored",
            "type": "object",
            "x-at-rest": true,
            "properties": {
                "profile": {
                    "type": "object",
                    "properties": {
                        "password": {"type": "string"}
                    }
                }
            }
        });
        let v = validate_schema(&schema);
        assert!(v.iter().any(|f| f.pointer == "profile.password"), "{v:?}");
    }

    #[test]
    fn green_at_rest_nested_high_risk_declared() {
        // 嵌套高风险字段显式声明 x-protection → 递归覆盖通过（anti-vacuity 正向）。
        let schema = json!({
            "title": "Stored",
            "type": "object",
            "x-at-rest": true,
            "properties": {
                "profile": {
                    "type": "object",
                    "properties": {
                        "password": {"type": "string", "x-protection": {"atRest": "encrypt", "keyScope": "tenant", "aad": ["tenant","configKey","field","schemaVersion"]}}
                    }
                }
            }
        });
        assert!(
            validate_schema(&schema).is_empty(),
            "{:?}",
            validate_schema(&schema)
        );
    }

    // ── red：外部 review（codex）findings F1/F2/F3 ────────────────────────

    /// F1：encrypt 缺 configKey（ADR-011 D2 复合域坐标必备维度，防跨 entry replay）→ 拒。
    #[test]
    fn red_encrypt_missing_config_key() {
        let schema = schema_with(
            "value",
            json!({"type": "string", "x-protection": {"atRest": "encrypt", "keyScope": "tenant", "aad": ["tenant","field","schemaVersion"]}}),
        );
        let v = validate_schema(&schema);
        assert!(v.iter().any(|f| f.detail.contains("configKey")), "{v:?}");
    }

    /// F1：blindIndex 缺 configKey（稳定子集仍须 tenant/configKey/field）→ 拒。
    #[test]
    fn red_blind_index_missing_config_key() {
        let schema = schema_with(
            "value",
            json!({"type": "string", "x-protection": {"atRest": "encrypt", "mode": "blindIndex", "keyScope": "tenant", "aad": ["tenant","field"], "reason": "lookup"}}),
        );
        let v = validate_schema(&schema);
        assert!(v.iter().any(|f| f.detail.contains("configKey")), "{v:?}");
    }

    /// F2：字段自身 `x-at-rest:true` 不再绕过自检——高风险字段自 opt-in 且缺 x-protection → 拒。
    #[test]
    fn red_field_self_opt_in_high_risk_missing_protection() {
        let schema = json!({
            "title": "T",
            "type": "object",
            "properties": {
                "password": {"type": "string", "x-at-rest": true}
            }
        });
        let v = validate_schema(&schema);
        assert!(v.iter().any(|f| f.pointer == "password"), "{v:?}");
    }

    /// F3：validate 下钻 `patternProperties`——其下非法 x-protection block 被捕获（与 breaking 对称）。
    #[test]
    fn red_pattern_properties_block_validated() {
        let schema = json!({
            "title": "T",
            "type": "object",
            "patternProperties": {
                "^x_": {"type": "string", "x-protection": {"atRest": "encrypt"}}
            }
        });
        let v = validate_schema(&schema);
        assert!(v.iter().any(|f| f.detail.contains("keyScope")), "{v:?}");
    }

    /// #1476：加密字段若允许 JSON null，会把「是否为空」作为明文存储形态泄漏；当前无显式 null-policy，
    /// 因此直接 fail-closed，直到未来单独设计加密 null sentinel。
    #[test]
    fn red_encrypt_rejects_nullable_type_union() {
        let schema = schema_with(
            "value",
            json!({
                "type": ["string", "null"],
                "x-protection": {
                    "atRest": "encrypt",
                    "keyScope": "tenant",
                    "aad": ["tenant", "configKey", "field", "schemaVersion"]
                }
            }),
        );
        let v = validate_schema(&schema);
        assert!(
            v.iter().any(|f| f.detail.contains("null")),
            "encrypted nullable field must be rejected: {v:?}"
        );
    }

    #[test]
    fn red_encrypt_rejects_direct_null_type() {
        let schema = schema_with(
            "value",
            json!({
                "type": "null",
                "x-protection": {
                    "atRest": "encrypt",
                    "keyScope": "tenant",
                    "aad": ["tenant", "configKey", "field", "schemaVersion"]
                }
            }),
        );
        let v = validate_schema(&schema);
        assert!(
            v.iter().any(|f| f.detail.contains("null")),
            "encrypted direct null type must be rejected: {v:?}"
        );
    }

    /// #1476：nullable leakage 不能只看顶层 `type`；JSON Schema 组合子里出现 null arm 也应拒绝。
    #[test]
    fn red_encrypt_rejects_any_of_null_arm() {
        let schema = schema_with(
            "value",
            json!({
                "anyOf": [{"type": "string"}, {"type": "null"}],
                "x-protection": {
                    "atRest": "encrypt",
                    "keyScope": "tenant",
                    "aad": ["tenant", "configKey", "field", "schemaVersion"]
                }
            }),
        );
        let v = validate_schema(&schema);
        assert!(
            v.iter().any(|f| f.detail.contains("null")),
            "encrypted anyOf null arm must be rejected: {v:?}"
        );
    }

    /// #1476：blindIndex 是 HMAC 等值索引，只适用于非 nullable scalar 字段；object/array 没有稳定等值语义。
    #[test]
    fn red_blind_index_rejects_object_schema() {
        let schema = schema_with(
            "value",
            json!({
                "type": "object",
                "properties": {"inner": {"type": "string"}},
                "x-protection": {
                    "atRest": "encrypt",
                    "mode": "blindIndex",
                    "keyScope": "tenant",
                    "aad": ["tenant", "configKey", "field"],
                    "reason": "lookup"
                }
            }),
        );
        let v = validate_schema(&schema);
        assert!(
            v.iter().any(|f| f.detail.contains("scalar")),
            "blindIndex object schema must be rejected: {v:?}"
        );
    }

    #[test]
    fn red_blind_index_rejects_array_schema() {
        let schema = schema_with(
            "value",
            json!({
                "type": "array",
                "items": {"type": "string"},
                "x-protection": {
                    "atRest": "encrypt",
                    "mode": "blindIndex",
                    "keyScope": "tenant",
                    "aad": ["tenant", "configKey", "field"],
                    "reason": "lookup"
                }
            }),
        );
        let v = validate_schema(&schema);
        assert!(
            v.iter().any(|f| f.detail.contains("scalar")),
            "blindIndex array schema must be rejected: {v:?}"
        );
    }

    #[test]
    fn red_blind_index_rejects_multi_scalar_union() {
        let schema = schema_with(
            "value",
            json!({
                "type": ["string", "number"],
                "x-protection": {
                    "atRest": "encrypt",
                    "mode": "blindIndex",
                    "keyScope": "tenant",
                    "aad": ["tenant", "configKey", "field"],
                    "reason": "lookup"
                }
            }),
        );
        let v = validate_schema(&schema);
        assert!(
            v.iter().any(|f| f.detail.contains("scalar")),
            "blindIndex multi-scalar union schema must be rejected: {v:?}"
        );
    }

    #[test]
    fn red_encrypt_rejects_ref_nullable_schema() {
        let schema = json!({
            "title": "ConfigEntry",
            "type": "object",
            "$defs": {
                "NullableSecret": {"type": ["string", "null"]}
            },
            "properties": {
                "value": {
                    "$ref": "#/$defs/NullableSecret",
                    "x-protection": {
                        "atRest": "encrypt",
                        "keyScope": "tenant",
                        "aad": ["tenant", "configKey", "field", "schemaVersion"]
                    }
                }
            }
        });
        let v = validate_schema(&schema);
        assert!(
            v.iter().any(|f| f.detail.contains("null")),
            "encrypted $ref nullable field must be rejected: {v:?}"
        );
    }

    #[test]
    fn red_blind_index_rejects_ref_object_schema() {
        let schema = json!({
            "title": "ConfigEntry",
            "type": "object",
            "$defs": {
                "ObjectSecret": {
                    "type": "object",
                    "properties": {"inner": {"type": "string"}}
                }
            },
            "properties": {
                "value": {
                    "$ref": "#/$defs/ObjectSecret",
                    "type": "string",
                    "x-protection": {
                        "atRest": "encrypt",
                        "mode": "blindIndex",
                        "keyScope": "tenant",
                        "aad": ["tenant", "configKey", "field"],
                        "reason": "lookup"
                    }
                }
            }
        });
        let v = validate_schema(&schema);
        assert!(
            v.iter().any(|f| f.detail.contains("scalar")),
            "blindIndex $ref object schema must be rejected: {v:?}"
        );
    }

    #[test]
    fn red_encrypt_rejects_unresolved_ref_schema() {
        let schema = json!({
            "title": "ConfigEntry",
            "type": "object",
            "properties": {
                "value": {
                    "$ref": "#/$defs/Missing",
                    "x-protection": {
                        "atRest": "encrypt",
                        "keyScope": "tenant",
                        "aad": ["tenant", "configKey", "field", "schemaVersion"]
                    }
                }
            }
        });
        let v = validate_schema(&schema);
        assert!(
            v.iter().any(|f| f.detail.contains("$ref")),
            "encrypted unresolved $ref schema must fail closed: {v:?}"
        );
    }

    #[test]
    fn green_blind_index_accepts_non_nullable_scalar() {
        let schema = schema_with(
            "value",
            json!({
                "type": "string",
                "x-protection": {
                    "atRest": "encrypt",
                    "mode": "blindIndex",
                    "keyScope": "tenant",
                    "aad": ["tenant", "configKey", "field"],
                    "reason": "lookup"
                }
            }),
        );
        assert!(
            validate_schema(&schema).is_empty(),
            "{:?}",
            validate_schema(&schema)
        );
    }

    #[test]
    fn green_blind_index_accepts_ref_non_nullable_scalar() {
        let schema = json!({
            "title": "ConfigEntry",
            "type": "object",
            "$defs": {
                "LookupSecret": {"type": "string"}
            },
            "properties": {
                "value": {
                    "$ref": "#/$defs/LookupSecret",
                    "x-protection": {
                        "atRest": "encrypt",
                        "mode": "blindIndex",
                        "keyScope": "tenant",
                        "aad": ["tenant", "configKey", "field"],
                        "reason": "lookup"
                    }
                }
            }
        });
        assert!(
            validate_schema(&schema).is_empty(),
            "{:?}",
            validate_schema(&schema)
        );
    }
}
