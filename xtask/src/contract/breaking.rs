//! wire 破坏式变更检测门（`cargo xtask contract breaking [--against <git-ref>]`，ADR-008 落地）。
//!
//! 轴 B（wire JSON Schema）跨版本破坏检测：对 `contracts/{kind}/{domain}/{version}/*.schema.json` 做
//! base-ref ↔ working-tree 的递归 JSON-Schema diff，对标 Buf WIRE_JSON 规则分类（借规则思想、不迁 protobuf）。
//! 与 R1–R15（manifest 元数据 + schema 存在性 = 结构）、`cargo-semver-checks`（轴 A Rust 符号）互补无重叠
//! ——本门只校验 schema **内容跨版本 diff**（语义破坏）。
//!
//! ref: bufbuild/buf docs/breaking/rules@main —— WIRE_JSON：FIELD_NO_DELETE_UNLESS_NAME_RESERVED /
//!   ENUM_VALUE_NO_DELETE_UNLESS_NAME_RESERVED / FIELD_WIRE_JSON_COMPATIBLE_TYPE / MESSAGE_SAME_REQUIRED_FIELDS。
//! ref: oasdiff/oasdiff docs/breaking-changes@main —— request-property-removed / new-required-request-property /
//!   request-property-type-changed / enum-value-removed / became-not-nullable。
//! ref: getsentry/json-schema-diff@main —— 集合论 permissive/restrictive：type 收紧 = newType 须为 oldType 超集。
//!
//! INVARIANT: WIRE-BREAKING-01 { level = "Medium", exec = "verify", source = "code" }—— 9 条规则（FIELD_NO_DELETE / REQUIRED_FIELD_ADDED / FIELD_TYPE_CHANGED /
//!   FIELD_FORMAT_CHANGED / ENUM_VALUE_DELETED / ADDITIONAL_PROPS_TIGHTENED / NULLABLE_REMOVED /
//!   REDACTION_POLICY_CHANGED / PROTECTION_POLICY_CHANGED）对 base↔working
//!   两版 schema 递归 diff，**只报既有字段的删除 / 收紧 / 隐私·保护策略漂移**（新增可选字段不报，向后兼容语义）。
//!   manifest wire 投影另覆盖 HTTP、L2 topology、subscription 与 lifecycle 降级规则。当前不覆盖
//!   `oneOf`/`anyOf`/`$ref` 嵌套构造（ADR §8 增量补）。
//! INVARIANT: WIRE-BREAKING-WINDOW-01 { level = "Medium", exec = "verify", source = "code" }——
//!   lifecycle 固定分级：active 默认 deny，deprecated warn，draft 跳过；仅下列 consistency/effect
//!   review 规则固定 warn；active 未携精确 review ack 时 fail-closed，deprecated 仍为非阻断 warn。
//!   既有契约以 base lifecycle 分级，working 降级不得绕过。
//! INVARIANT: CONSISTENCY-EFFECT-BREAKING-REVIEW-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "working_rejects_legacy_tokens_and_breaking_preserves_base_identity", anti_vacuity = "effect_reorder_is_clean" }——
//!   LocalOnly 边界与 HTTP effect 集合漂移生成固定 review-only finding；base commit + 排序后的
//!   rule/subject/detail 派生 SHA-256，Git commit trailer 提供机器确认。其余 breaking 规则仍按 lifecycle
//!   fail-closed。base/working HTTP effectProfile 均严格投影，缺失、空集或重复值拒绝执行。
//!
//! anti-vacuity（ai-robust 第 4 档强制，守卫不恒真）：每条规则配 synthetic red（破坏→finding）+ green
//! （兼容→无），并含「≥1 active 契约破坏」red（防恒真）+ draft 跳过 red（draft 删字段→无 finding）。

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Output;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::discover;
use super::manifest::{
    ConsistencyLevel, ContractKind, ContractManifest, Delivery, EffectKind, EffectProfile,
    ExternalEffectPolicy, HttpAuthMode, HttpIdempotency, HttpMethod, HttpResourceSharingMode,
    Lifecycle, OutboxAtomicity, OutboxRole, PartitionKeyStrategy, SubscriberReadiness,
    SubscriptionEffect, SubscriptionExecution,
};
use super::protection;
use super::redaction;

/// base ref 默认值（`--against` 缺省）：与 ADR-008 §3.2 一致（PR 基准分支）。
pub(crate) const DEFAULT_AGAINST: &str = "origin/develop";

const REVIEW_ACK_PREFIX: &str = "Contract-Review-Ack: sha256:";
const BREAKING_AUTHORIZATION_PREFIX: &str = "Contract-Breaking-Authorization: sha256:";

/// JSON Schema `properties` 键名（DRY：compare_node + check_field_deletions 多处引用）。
const PROPS: &str = "properties";

/// 首版破坏规则（对标 Buf WIRE_JSON，适配 JSON Schema）。`id()` = 稳定大写蛇形 ID（输出 + 测试断言用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BreakingRule {
    /// `properties` 中已有字段被删除（旧有新无）。删 optional 也算破坏（旧客户端仍可能发该字段）。
    FieldNoDelete,
    /// `required` 数组新增旧无的字段（旧请求缺该字段即破坏）。仅顶层 `required` add-only。
    RequiredFieldAdded,
    /// `type` 收紧：newType **非** oldType 超集（忽略 `"null"`，交 [`BreakingRule::NullableRemoved`]）。
    FieldTypeChanged,
    /// `format` 删除或变更（解码语义变化）；从无加有不报（收紧但向前兼容）。
    FieldFormatChanged,
    /// `enum` 数组已有值被移除（set-diff(old−new) 非空）；新增 enum 值不报。
    EnumValueDeleted,
    /// `additionalProperties` 由宽（`true`/缺省）收紧到严（`false`/schema）。
    AdditionalPropsTightened,
    /// 字段 `type` 由含 `"null"` 收紧到不含（旧客户端发 null 失败）。优先于 `FieldTypeChanged`（同变化不重复报）。
    NullableRemoved,
    NullableAdded,
    RequiredFieldRemoved,
    EnumValueAdded,
    EnumConstraintRemoved,
    FieldAddedToOutput,
    AdditionalPropsLoosened,
    /// 既有字段的 `x-pii` / `x-redaction` 隐私语义改变。
    RedactionPolicyChanged,
    /// 既有字段的 `x-protection`（at-rest 加密）或 schema 级 `x-at-rest` 保护语义改变（#1468，
    /// ADR-011 D1b：保护策略漂移须作审查材料，防 wire 隐私语义静默漂移）。
    ProtectionPolicyChanged,
    HttpStatusCodeChanged,
    HttpPathChanged,
    HttpMethodChanged,
    AuthRequirementChanged,
    AuthScopeChanged,
    ResourceSharingChanged,
    IdempotencyLevelChanged,
    TopicChanged,
    DeliveryChanged,
    ConsistencyLevelChanged,
    LocalOnlyBoundaryChanged,
    EffectAdded,
    EffectRemoved,
    OutboxRoleChanged,
    OutboxAtomicityChanged,
    OutboxEmitsChanged,
    SubscriptionSetChanged,
    SubscriptionConsumerChanged,
    SubscriptionGroupChanged,
    SubscriptionTopologyChanged,
    SubscriptionExecutionChanged,
    SubscriptionEffectChanged,
    SubscriptionExternalEffectPolicyChanged,
    LifecycleDowngraded,
    ContractRemoved,
}

const REVIEW_ONLY_RULES: [BreakingRule; 3] = [
    BreakingRule::LocalOnlyBoundaryChanged,
    BreakingRule::EffectAdded,
    BreakingRule::EffectRemoved,
];

impl BreakingRule {
    /// 稳定大写蛇形 ID（输出行 + 测试断言单源）。
    pub(crate) fn id(self) -> &'static str {
        match self {
            BreakingRule::FieldNoDelete => "FIELD_NO_DELETE",
            BreakingRule::RequiredFieldAdded => "REQUIRED_FIELD_ADDED",
            BreakingRule::FieldTypeChanged => "FIELD_TYPE_CHANGED",
            BreakingRule::FieldFormatChanged => "FIELD_FORMAT_CHANGED",
            BreakingRule::EnumValueDeleted => "ENUM_VALUE_DELETED",
            BreakingRule::AdditionalPropsTightened => "ADDITIONAL_PROPS_TIGHTENED",
            BreakingRule::NullableRemoved => "NULLABLE_REMOVED",
            BreakingRule::NullableAdded => "NULLABLE_ADDED",
            BreakingRule::RequiredFieldRemoved => "REQUIRED_FIELD_REMOVED",
            BreakingRule::EnumValueAdded => "ENUM_VALUE_ADDED",
            BreakingRule::EnumConstraintRemoved => "ENUM_CONSTRAINT_REMOVED",
            BreakingRule::FieldAddedToOutput => "FIELD_ADDED_TO_OUTPUT",
            BreakingRule::AdditionalPropsLoosened => "ADDITIONAL_PROPS_LOOSENED",
            BreakingRule::RedactionPolicyChanged => "REDACTION_POLICY_CHANGED",
            BreakingRule::ProtectionPolicyChanged => "PROTECTION_POLICY_CHANGED",
            BreakingRule::HttpStatusCodeChanged => "HTTP_STATUS_CODE_CHANGED",
            BreakingRule::HttpPathChanged => "HTTP_PATH_CHANGED",
            BreakingRule::HttpMethodChanged => "HTTP_METHOD_CHANGED",
            BreakingRule::AuthRequirementChanged => "AUTH_REQUIREMENT_CHANGED",
            BreakingRule::AuthScopeChanged => "AUTH_SCOPE_CHANGED",
            BreakingRule::ResourceSharingChanged => "RESOURCE_SHARING_CHANGED",
            BreakingRule::IdempotencyLevelChanged => "IDEMPOTENCY_LEVEL_CHANGED",
            BreakingRule::TopicChanged => "TOPIC_CHANGED",
            BreakingRule::DeliveryChanged => "DELIVERY_CHANGED",
            BreakingRule::ConsistencyLevelChanged => "CONSISTENCY_LEVEL_CHANGED",
            BreakingRule::LocalOnlyBoundaryChanged => "LOCAL_ONLY_BOUNDARY_CHANGED",
            BreakingRule::EffectAdded => "EFFECT_ADDED",
            BreakingRule::EffectRemoved => "EFFECT_REMOVED",
            BreakingRule::OutboxRoleChanged => "OUTBOX_ROLE_CHANGED",
            BreakingRule::OutboxAtomicityChanged => "OUTBOX_ATOMICITY_CHANGED",
            BreakingRule::OutboxEmitsChanged => "OUTBOX_EMITS_CHANGED",
            BreakingRule::SubscriptionSetChanged => "SUBSCRIPTION_SET_CHANGED",
            BreakingRule::SubscriptionConsumerChanged => "SUBSCRIPTION_CONSUMER_CHANGED",
            BreakingRule::SubscriptionGroupChanged => "SUBSCRIPTION_GROUP_CHANGED",
            BreakingRule::SubscriptionTopologyChanged => "SUBSCRIPTION_TOPOLOGY_CHANGED",
            BreakingRule::SubscriptionExecutionChanged => "SUBSCRIPTION_EXECUTION_CHANGED",
            BreakingRule::SubscriptionEffectChanged => "SUBSCRIPTION_EFFECT_CHANGED",
            BreakingRule::SubscriptionExternalEffectPolicyChanged => {
                "SUBSCRIPTION_EXTERNAL_EFFECT_POLICY_CHANGED"
            }
            BreakingRule::LifecycleDowngraded => "LIFECYCLE_DOWNGRADED",
            BreakingRule::ContractRemoved => "CONTRACT_REMOVED",
        }
    }
}

/// 单条 finding 的处置：`Warn`（退出码 0，在场即记录）/ `Deny`（退出码 1，在场即拦截）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Disposition {
    Warn,
    Deny,
}

impl Disposition {
    fn label(self) -> &'static str {
        match self {
            Disposition::Warn => "warn",
            Disposition::Deny => "deny",
        }
    }
}

/// lifecycle 分级核心：active 契约破坏阻断，deprecated 仅告警；draft 在 [`evaluate`]
/// 前被滤除，此处对其返回 `Warn` 以保持函数总性。
pub(crate) fn disposition(lifecycle: Lifecycle) -> Disposition {
    match lifecycle {
        Lifecycle::Active => Disposition::Deny,
        Lifecycle::Deprecated | Lifecycle::Draft => Disposition::Warn,
    }
}

fn rule_disposition(rule: BreakingRule, lifecycle: Lifecycle) -> Disposition {
    if is_review_only_rule(rule) {
        Disposition::Warn
    } else {
        disposition(lifecycle)
    }
}

fn is_review_only_rule(rule: BreakingRule) -> bool {
    REVIEW_ONLY_RULES.contains(&rule)
}

/// 是否对该 lifecycle 的契约做 diff：`active` + `deprecated` 检（draft 跳过）。
fn is_checked(lifecycle: Lifecycle) -> bool {
    matches!(lifecycle, Lifecycle::Active | Lifecycle::Deprecated)
}

// ───────────────────────────── 递归 diff 核心（纯函数）─────────────────────────────

/// 单条原始破坏（未分级）：规则 + JSON 路径（dotted，root = ""）+ 详情。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RawBreak {
    pub(crate) rule: BreakingRule,
    pub(crate) pointer: String,
    pub(crate) detail: String,
}

/// 比对两版 schema 树（base `old` → working `new`），返回全部破坏（首版 7 规则；递归 `properties`）。
/// 纯函数——不触 IO，便于表驱动红/绿单测。
#[cfg(test)]
pub(crate) fn compare_schemas(old: &Value, new: &Value) -> Vec<RawBreak> {
    compare_schemas_for_direction(old, new, SchemaDirection::Input)
}

fn compare_schemas_for_direction(
    old: &Value,
    new: &Value,
    direction: SchemaDirection,
) -> Vec<RawBreak> {
    let mut out = Vec::new();
    match direction {
        SchemaDirection::Input => compare_node(old, new, "", &mut out),
        SchemaDirection::Output => compare_output_node(old, new, "", &mut out),
    }
    check_redaction_policy(old, new, &mut out);
    check_protection_policy(old, new, &mut out);
    out
}

fn child(path: &str, seg: &str) -> String {
    if path.is_empty() {
        seg.to_string()
    } else {
        format!("{path}.{seg}")
    }
}

/// 路径展示：root 空串显示为 `(root)`，便于读 finding。
fn show(path: &str) -> &str {
    if path.is_empty() { "(root)" } else { path }
}

fn compare_node(old: &Value, new: &Value, path: &str, out: &mut Vec<RawBreak>) {
    check_field_deletions(old, new, path, out);
    check_required_added(old, new, path, out);
    check_type_and_nullable(old, new, path, out);
    check_format(old, new, path, out);
    check_enum(old, new, path, out);
    check_additional_props(old, new, path, out);

    // 递归两版共有的对象 properties（嵌套字段删除 / 收紧）。首版不下探 oneOf/anyOf/$ref（ADR §8）。
    if let (Some(op), Some(np)) = (
        old.get(PROPS).and_then(Value::as_object),
        new.get(PROPS).and_then(Value::as_object),
    ) {
        for (k, ov) in op {
            if let Some(nv) = np.get(k) {
                compare_node(ov, nv, &child(path, k), out);
            }
        }
    }

    // 递归两版共有的数组元素 schema `items`（单 schema 形态）——列表元素字段删除 / 收紧亦是 wire 破坏（C2）。
    // tuple 形（items 为数组）/ bool 形首版不下探（同 oneOf/$ref，ADR §8 增量）。
    if let (Some(oi), Some(ni)) = (
        old.get("items").filter(|v| v.is_object()),
        new.get("items").filter(|v| v.is_object()),
    ) {
        compare_node(oi, ni, &item_path(path), out);
    }
}

/// Producer output must remain a subset of the values accepted by the old schema. This is the
/// opposite variance from request/input schemas, but retains the same recursive traversal.
fn compare_output_node(old: &Value, new: &Value, path: &str, out: &mut Vec<RawBreak>) {
    check_field_deletions(old, new, path, out);
    check_output_fields_added(old, new, path, out);
    check_required_removed(old, new, path, out);
    check_output_type_and_nullable(old, new, path, out);
    check_format(old, new, path, out);
    check_output_enum(old, new, path, out);
    check_additional_props_loosened(old, new, path, out);

    if let (Some(op), Some(np)) = (
        old.get(PROPS).and_then(Value::as_object),
        new.get(PROPS).and_then(Value::as_object),
    ) {
        for (key, old_property) in op {
            if let Some(new_property) = np.get(key) {
                compare_output_node(old_property, new_property, &child(path, key), out);
            }
        }
    }
    if let (Some(old_items), Some(new_items)) = (
        old.get("items").filter(|value| value.is_object()),
        new.get("items").filter(|value| value.is_object()),
    ) {
        compare_output_node(old_items, new_items, &item_path(path), out);
    }
}

fn check_output_fields_added(old: &Value, new: &Value, path: &str, out: &mut Vec<RawBreak>) {
    let Some(old_properties) = old.get(PROPS).and_then(Value::as_object) else {
        return;
    };
    let Some(new_properties) = new.get(PROPS).and_then(Value::as_object) else {
        return;
    };
    if old.get("additionalProperties").and_then(Value::as_bool) != Some(false) {
        return;
    }
    for key in new_properties.keys() {
        if !old_properties.contains_key(key) {
            out.push(RawBreak {
                rule: BreakingRule::FieldAddedToOutput,
                pointer: child(path, key),
                detail: format!("输出新增旧 schema 禁止的字段 `{key}`"),
            });
        }
    }
}

fn check_required_removed(old: &Value, new: &Value, path: &str, out: &mut Vec<RawBreak>) {
    let old_required = string_set(old.get("required"));
    let new_required = string_set(new.get("required"));
    for field in old_required.difference(&new_required) {
        out.push(RawBreak {
            rule: BreakingRule::RequiredFieldRemoved,
            pointer: child(path, field),
            detail: format!("输出字段 `{field}` 不再保证 required"),
        });
    }
}

fn check_output_type_and_nullable(old: &Value, new: &Value, path: &str, out: &mut Vec<RawBreak>) {
    let old_types = type_set(old.get("type"));
    let new_types = type_set(new.get("type"));
    if old_types.is_empty() || new_types.is_empty() {
        return;
    }
    const NULL: &str = "null";
    if !old_types.contains(NULL) && new_types.contains(NULL) {
        out.push(RawBreak {
            rule: BreakingRule::NullableAdded,
            pointer: path.to_string(),
            detail: format!("{} 输出由不可空扩大为可空", show(path)),
        });
    }
    let old_non_null: BTreeSet<&str> = old_types
        .iter()
        .map(String::as_str)
        .filter(|value| *value != NULL)
        .collect();
    let new_non_null: BTreeSet<&str> = new_types
        .iter()
        .map(String::as_str)
        .filter(|value| *value != NULL)
        .collect();
    let added: Vec<&str> = new_non_null
        .iter()
        .copied()
        .filter(|value| !type_accepted(value, &old_non_null))
        .collect();
    if !added.is_empty() {
        out.push(RawBreak {
            rule: BreakingRule::FieldTypeChanged,
            pointer: path.to_string(),
            detail: format!(
                "{} 输出类型扩大：旧 {:?} → 新 {:?}（新增 {:?}）",
                show(path),
                sorted(&old_types),
                sorted(&new_types),
                added
            ),
        });
    }
}

fn check_output_enum(old: &Value, new: &Value, path: &str, out: &mut Vec<RawBreak>) {
    let old_enum = old.get("enum").and_then(Value::as_array);
    let new_enum = new.get("enum").and_then(Value::as_array);
    match (old_enum, new_enum) {
        (Some(_), None) => out.push(RawBreak {
            rule: BreakingRule::EnumConstraintRemoved,
            pointer: path.to_string(),
            detail: format!("{} 输出 enum 约束被删除", show(path)),
        }),
        (Some(old_values), Some(new_values)) => {
            for value in new_values {
                if !old_values.contains(value) {
                    out.push(RawBreak {
                        rule: BreakingRule::EnumValueAdded,
                        pointer: path.to_string(),
                        detail: format!("{} 输出新增 enum 值 {value}", show(path)),
                    });
                }
            }
        }
        (None, _) => {}
    }
}

fn check_additional_props_loosened(old: &Value, new: &Value, path: &str, out: &mut Vec<RawBreak>) {
    let old_restrictive = old
        .get("additionalProperties")
        .is_some_and(|value| value.as_bool() == Some(false) || value.is_object());
    let new_permissive = new
        .get("additionalProperties")
        .is_none_or(|value| value.as_bool() == Some(true));
    if old_restrictive && new_permissive {
        out.push(RawBreak {
            rule: BreakingRule::AdditionalPropsLoosened,
            pointer: path.to_string(),
            detail: format!("{} 输出 additionalProperties 由受限扩大为宽松", show(path)),
        });
    }
}

fn check_redaction_policy(old: &Value, new: &Value, out: &mut Vec<RawBreak>) {
    for violation in redaction::compare_policy_changes(old, new) {
        out.push(RawBreak {
            rule: BreakingRule::RedactionPolicyChanged,
            pointer: violation.pointer,
            detail: violation.detail,
        });
    }
}

/// `x-protection` / `x-at-rest` 既有字段保护策略漂移（#1468，与 redaction 同款但走 `protection` 模块）。
fn check_protection_policy(old: &Value, new: &Value, out: &mut Vec<RawBreak>) {
    for violation in protection::compare_policy_changes(old, new) {
        out.push(RawBreak {
            rule: BreakingRule::ProtectionPolicyChanged,
            pointer: violation.pointer,
            detail: violation.detail,
        });
    }
}

/// 数组元素路径展示：`data` → `data[]`；root → `[]`。
fn item_path(path: &str) -> String {
    format!("{path}[]")
}

/// FIELD_NO_DELETE：old `properties` 某 key 在 new 中缺失。
fn check_field_deletions(old: &Value, new: &Value, path: &str, out: &mut Vec<RawBreak>) {
    let Some(op) = old.get(PROPS).and_then(Value::as_object) else {
        return;
    };
    let np = new.get(PROPS).and_then(Value::as_object);
    for key in op.keys() {
        let missing = np.is_none_or(|m| !m.contains_key(key));
        if missing {
            out.push(RawBreak {
                rule: BreakingRule::FieldNoDelete,
                pointer: child(path, key),
                detail: format!("字段 `{key}` 被删除（旧 schema 有、新 schema 无）"),
            });
        }
    }
}

/// REQUIRED_FIELD_ADDED：new `required` 含 old `required` 没有的字段（顶层 add-only）。
fn check_required_added(old: &Value, new: &Value, path: &str, out: &mut Vec<RawBreak>) {
    let old_req = string_set(old.get("required"));
    let new_req = string_set(new.get("required"));
    for f in new_req.difference(&old_req) {
        out.push(RawBreak {
            rule: BreakingRule::RequiredFieldAdded,
            pointer: child(path, f),
            detail: format!("字段 `{f}` 新增进 required（旧请求缺该字段即破坏）"),
        });
    }
}

/// FIELD_TYPE_CHANGED + NULLABLE_REMOVED：type 收紧。两版均须有显式 type 才判（new 无 type = 最宽松，不报；
/// old 无 type 跳过避免 object 节点噪音）。非 null 类型 newType 非 oldType 超集 → 收紧；null 单独由 nullable 判。
fn check_type_and_nullable(old: &Value, new: &Value, path: &str, out: &mut Vec<RawBreak>) {
    let ot = type_set(old.get("type"));
    let nt = type_set(new.get("type"));
    if ot.is_empty() || nt.is_empty() {
        return; // 任一侧无显式 type 约束 → 不判收紧（新无 type = 最宽松；旧无 type = 跳过 object 噪音）
    }
    const NULL: &str = "null";
    if ot.contains(NULL) && !nt.contains(NULL) {
        out.push(RawBreak {
            rule: BreakingRule::NullableRemoved,
            pointer: path.to_string(),
            detail: format!("{} 由可空（含 \"null\"）收紧为不可空", show(path)),
        });
    }
    let old_nn: BTreeSet<&str> = ot
        .iter()
        .map(String::as_str)
        .filter(|t| *t != NULL)
        .collect();
    let new_nn: BTreeSet<&str> = nt
        .iter()
        .map(String::as_str)
        .filter(|t| *t != NULL)
        .collect();
    // 收紧 = 旧标量类型不被新类型集接受（按 JSON Schema 类型包含关系，非裸字符串集合差——
    // integer ⊆ number 是放宽，不算破坏，C3）。
    let removed: Vec<&str> = old_nn
        .iter()
        .copied()
        .filter(|&t| !type_accepted(t, &new_nn))
        .collect();
    if !removed.is_empty() {
        out.push(RawBreak {
            rule: BreakingRule::FieldTypeChanged,
            pointer: path.to_string(),
            detail: format!(
                "{} 类型收紧：旧 {:?} → 新 {:?}（移除 {:?}）",
                show(path),
                sorted(&ot),
                sorted(&nt),
                removed
            ),
        });
    }
}

/// 新类型集是否接受旧标量类型：直接包含，或 `integer ⊆ number`（JSON Schema 数值放宽，向后兼容，C3）。
/// 其余跨类（如 `string`→`integer`）不接受 = 收紧破坏。
fn type_accepted(old: &str, new_set: &BTreeSet<&str>) -> bool {
    new_set.contains(old) || (old == "integer" && new_set.contains("number"))
}

/// FIELD_FORMAT_CHANGED：old 有 `format` 而 new 删除或改为不同值。从无加有不报。
fn check_format(old: &Value, new: &Value, path: &str, out: &mut Vec<RawBreak>) {
    let Some(of) = old.get("format").and_then(Value::as_str) else {
        return;
    };
    match new.get("format").and_then(Value::as_str) {
        None => out.push(RawBreak {
            rule: BreakingRule::FieldFormatChanged,
            pointer: path.to_string(),
            detail: format!("{} format `{of}` 被删除", show(path)),
        }),
        Some(nf) if nf != of => out.push(RawBreak {
            rule: BreakingRule::FieldFormatChanged,
            pointer: path.to_string(),
            detail: format!("{} format 由 `{of}` 变更为 `{nf}`", show(path)),
        }),
        Some(_) => {}
    }
}

/// ENUM_VALUE_DELETED：两版均有 `enum`，old 某值不在 new（set-diff）。enum 整体删除（new 无 enum）= 放宽，不报。
fn check_enum(old: &Value, new: &Value, path: &str, out: &mut Vec<RawBreak>) {
    let (Some(oe), Some(ne)) = (
        old.get("enum").and_then(Value::as_array),
        new.get("enum").and_then(Value::as_array),
    ) else {
        return;
    };
    for v in oe {
        if !ne.contains(v) {
            out.push(RawBreak {
                rule: BreakingRule::EnumValueDeleted,
                pointer: path.to_string(),
                detail: format!("{} enum 值 {v} 被删除", show(path)),
            });
        }
    }
}

/// ADDITIONAL_PROPS_TIGHTENED：old 宽（`true`/缺省）→ new 严（`false`/schema 对象）。只判明确收紧，
/// 不做 minLength/maxLength 等模糊 schema-vs-schema 启发式（避免误报）。
fn check_additional_props(old: &Value, new: &Value, path: &str, out: &mut Vec<RawBreak>) {
    let oa = old.get("additionalProperties");
    let na = new.get("additionalProperties");
    // 缺省（None）= JSON Schema 默认允许额外字段 = 宽松（true）。
    let old_permissive = oa.is_none_or(|v| v.as_bool() == Some(true));
    let new_restrictive = na.is_some_and(|v| v.as_bool() == Some(false) || v.is_object());
    if old_permissive && new_restrictive {
        out.push(RawBreak {
            rule: BreakingRule::AdditionalPropsTightened,
            pointer: path.to_string(),
            detail: format!(
                "{} additionalProperties 由宽松收紧为受限（拒旧 payload 扩展字段）",
                show(path)
            ),
        });
    }
}

/// `type` 字段归一化为字符串集（`"string"` → {string}；`["string","null"]` → {string,null}；其它 → 空）。
fn type_set(v: Option<&Value>) -> BTreeSet<String> {
    match v {
        Some(Value::String(s)) => BTreeSet::from([s.clone()]),
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|t| t.as_str().map(str::to_string))
            .collect(),
        _ => BTreeSet::new(),
    }
}

/// `required` / 字符串数组归一化为集合。
fn string_set(v: Option<&Value>) -> BTreeSet<String> {
    match v.and_then(Value::as_array) {
        Some(a) => a
            .iter()
            .filter_map(|t| t.as_str().map(str::to_string))
            .collect(),
        None => BTreeSet::new(),
    }
}

fn sorted(s: &BTreeSet<String>) -> Vec<&str> {
    s.iter().map(String::as_str).collect()
}

// ───────────────────────────── 分级 + 编排（IO 在边界）─────────────────────────────

/// 已分级 finding（diff + lifecycle + disposition 后）。lifecycle 保留到 IO gate，避免后续确认门
/// 把 deprecated warning 错误升级为阻断。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GradedFinding {
    pub(crate) lifecycle: Lifecycle,
    pub(crate) disposition: Disposition,
    pub(crate) rule: BreakingRule,
    /// `{label} {schema_file} ({pointer})`。
    pub(crate) subject: String,
    pub(crate) detail: String,
}

/// Manifest 中真正影响 wire/runtime 兼容性的窄投影。它与 JSON Schema slot 独立，避免把
/// metadata 伪装成 schema；集合字段在构造时归一化为 `BTreeSet`，比较与声明顺序无关。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ManifestProjection {
    http: Option<HttpWireProjection>,
    topic: Option<String>,
    delivery: Option<String>,
    consistency: Option<String>,
    effects: BTreeSet<EffectIdentity>,
    outbox: Option<OutboxProjection>,
    subscriptions: BTreeSet<SubscriptionProjection>,
}

/// Authoring spelling identity used only by the base↔working breaking diff.
///
/// Runtime code never sees the legacy variants: the strict working parser only constructs the
/// business-qualified identities. Keeping the historical spelling here is what lets an active
/// vocabulary rename produce the required removal/addition review evidence before semantics are
/// interpreted by runtime consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum EffectIdentity {
    Read,
    Auth,
    Projection,
    Write,
    Transaction,
    BusinessWrite,
    BusinessTransaction,
    Outbox,
    Publish,
    Workflow,
    Saga,
    Reconcile,
    Worker,
    CrossTenantAudit,
}

impl EffectIdentity {
    fn as_wire(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Auth => "auth",
            Self::Projection => "projection",
            Self::Write => "write",
            Self::Transaction => "transaction",
            Self::BusinessWrite => "business-write",
            Self::BusinessTransaction => "business-transaction",
            Self::Outbox => "outbox",
            Self::Publish => "publish",
            Self::Workflow => "workflow",
            Self::Saga => "saga",
            Self::Reconcile => "reconcile",
            Self::Worker => "worker",
            Self::CrossTenantAudit => "cross-tenant-audit",
        }
    }
}

impl From<EffectKind> for EffectIdentity {
    fn from(effect: EffectKind) -> Self {
        match effect {
            EffectKind::Read => Self::Read,
            EffectKind::Auth => Self::Auth,
            EffectKind::Projection => Self::Projection,
            EffectKind::BusinessWrite => Self::BusinessWrite,
            EffectKind::BusinessTransaction => Self::BusinessTransaction,
            EffectKind::Outbox => Self::Outbox,
            EffectKind::Publish => Self::Publish,
            EffectKind::Workflow => Self::Workflow,
            EffectKind::Saga => Self::Saga,
            EffectKind::Reconcile => Self::Reconcile,
            EffectKind::Worker => Self::Worker,
            EffectKind::CrossTenantAudit => Self::CrossTenantAudit,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HttpWireProjection {
    path: Option<String>,
    method: Option<String>,
    success_status: Option<u16>,
    auth: Option<AuthProjection>,
    auth_scope: AuthScopeProjection,
    resource_sharing: String,
    idempotency: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthProjection {
    mode: String,
    permission: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct AuthScopeProjection {
    resource: Option<String>,
    self_scoped: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OutboxProjection {
    role: String,
    atomicity: Option<String>,
    emits: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SubscriptionProjection {
    consumer: String,
    group: String,
    partition: String,
    readiness: String,
    execution: Option<String>,
    effect: Option<String>,
    external_effect_policy: String,
}

fn changed(
    rule: BreakingRule,
    pointer: &str,
    old: &impl std::fmt::Debug,
    new: &impl std::fmt::Debug,
) -> RawBreak {
    RawBreak {
        rule,
        pointer: pointer.to_string(),
        detail: format!("wire 声明由 {old:?} 变更为 {new:?}"),
    }
}

fn compare_optional<T: PartialEq + std::fmt::Debug>(
    out: &mut Vec<RawBreak>,
    rule: BreakingRule,
    pointer: &str,
    old: &Option<T>,
    new: &Option<T>,
) {
    // 历史 manifest 尚无当前 carrier 时不追溯阻断；working parser 始终严格。
    if old.is_some() && old != new {
        out.push(changed(rule, pointer, old, new));
    }
}

pub(crate) fn compare_manifests(
    old: &ManifestProjection,
    new: &ManifestProjection,
) -> Vec<RawBreak> {
    let mut out = Vec::new();
    match (&old.http, &new.http) {
        (Some(a), Some(b)) => {
            compare_optional(
                &mut out,
                BreakingRule::HttpPathChanged,
                "path",
                &a.path,
                &b.path,
            );
            compare_optional(
                &mut out,
                BreakingRule::HttpMethodChanged,
                "method",
                &a.method,
                &b.method,
            );
            compare_optional(
                &mut out,
                BreakingRule::HttpStatusCodeChanged,
                "endpoints.http.successStatus",
                &a.success_status,
                &b.success_status,
            );
            compare_optional(
                &mut out,
                BreakingRule::IdempotencyLevelChanged,
                "endpoints.http.idempotency",
                &a.idempotency,
                &b.idempotency,
            );
            if a.auth != b.auth {
                out.push(changed(
                    BreakingRule::AuthRequirementChanged,
                    "endpoints.http.auth",
                    &a.auth,
                    &b.auth,
                ));
            }
            if a.auth_scope != b.auth_scope {
                out.push(changed(
                    BreakingRule::AuthScopeChanged,
                    "endpoints.http.authorizationScope",
                    &a.auth_scope,
                    &b.auth_scope,
                ));
            }
            if a.resource_sharing != b.resource_sharing {
                out.push(changed(
                    BreakingRule::ResourceSharingChanged,
                    "endpoints.http.resourceSharing.mode",
                    &a.resource_sharing,
                    &b.resource_sharing,
                ));
            }
        }
        (Some(a), None) => {
            compare_optional(
                &mut out,
                BreakingRule::HttpPathChanged,
                "path",
                &a.path,
                &None::<String>,
            );
            compare_optional(
                &mut out,
                BreakingRule::HttpMethodChanged,
                "method",
                &a.method,
                &None::<String>,
            );
            compare_optional(
                &mut out,
                BreakingRule::HttpStatusCodeChanged,
                "endpoints.http.successStatus",
                &a.success_status,
                &None::<u16>,
            );
            if a.auth.is_some() {
                out.push(changed(
                    BreakingRule::AuthRequirementChanged,
                    "endpoints.http.auth",
                    &a.auth,
                    &None::<AuthProjection>,
                ));
            }
            compare_optional(
                &mut out,
                BreakingRule::IdempotencyLevelChanged,
                "endpoints.http.idempotency",
                &a.idempotency,
                &None::<String>,
            );
            if a.auth_scope != AuthScopeProjection::default() {
                out.push(changed(
                    BreakingRule::AuthScopeChanged,
                    "endpoints.http.authorizationScope",
                    &a.auth_scope,
                    &AuthScopeProjection::default(),
                ));
            }
        }
        (None, _) => {}
    }
    compare_optional(
        &mut out,
        BreakingRule::TopicChanged,
        "topic",
        &old.topic,
        &new.topic,
    );
    compare_optional(
        &mut out,
        BreakingRule::DeliveryChanged,
        "delivery",
        &old.delivery,
        &new.delivery,
    );
    compare_consistency(&mut out, &old.consistency, &new.consistency);
    compare_effects(&mut out, &old.effects, &new.effects);
    compare_outbox(&mut out, &old.outbox, &new.outbox);
    compare_subscriptions(&mut out, &old.subscriptions, &new.subscriptions);
    out
}

fn compare_consistency(out: &mut Vec<RawBreak>, old: &Option<String>, new: &Option<String>) {
    if old.is_none() || old == new {
        return;
    }
    let local_only_boundary =
        old.as_deref() == Some("LocalOnly") || new.as_deref() == Some("LocalOnly");
    out.push(changed(
        if local_only_boundary {
            BreakingRule::LocalOnlyBoundaryChanged
        } else {
            BreakingRule::ConsistencyLevelChanged
        },
        "consistencyLevel",
        old,
        new,
    ));
}

fn compare_effects(
    out: &mut Vec<RawBreak>,
    old: &BTreeSet<EffectIdentity>,
    new: &BTreeSet<EffectIdentity>,
) {
    for effect in old.difference(new) {
        out.push(RawBreak {
            rule: BreakingRule::EffectRemoved,
            pointer: "effectProfile.effects".to_string(),
            detail: format!("HTTP effect `{}` 被移除", effect.as_wire()),
        });
    }
    for effect in new.difference(old) {
        out.push(RawBreak {
            rule: BreakingRule::EffectAdded,
            pointer: "effectProfile.effects".to_string(),
            detail: format!("HTTP effect `{}` 被新增", effect.as_wire()),
        });
    }
}

fn compare_outbox(
    out: &mut Vec<RawBreak>,
    old: &Option<OutboxProjection>,
    new: &Option<OutboxProjection>,
) {
    let Some(a) = old else { return };
    let Some(b) = new else {
        out.push(changed(
            BreakingRule::OutboxRoleChanged,
            "capabilities.outbox",
            old,
            new,
        ));
        if a.atomicity.is_some() {
            out.push(changed(
                BreakingRule::OutboxAtomicityChanged,
                "capabilities.outbox.atomicity",
                &a.atomicity,
                &None::<String>,
            ));
        }
        if !a.emits.is_empty() {
            out.push(changed(
                BreakingRule::OutboxEmitsChanged,
                "capabilities.outbox.emits",
                &a.emits,
                &BTreeSet::<String>::new(),
            ));
        }
        return;
    };
    if a.role != b.role {
        out.push(changed(
            BreakingRule::OutboxRoleChanged,
            "capabilities.outbox.role",
            &a.role,
            &b.role,
        ));
    }
    if a.atomicity != b.atomicity {
        out.push(changed(
            BreakingRule::OutboxAtomicityChanged,
            "capabilities.outbox.atomicity",
            &a.atomicity,
            &b.atomicity,
        ));
    }
    if a.emits != b.emits {
        out.push(changed(
            BreakingRule::OutboxEmitsChanged,
            "capabilities.outbox.emits",
            &a.emits,
            &b.emits,
        ));
    }
}

fn compare_subscriptions(
    out: &mut Vec<RawBreak>,
    old: &BTreeSet<SubscriptionProjection>,
    new: &BTreeSet<SubscriptionProjection>,
) {
    if old == new {
        return;
    }
    let old_identities = subscription_identities(old);
    let new_identities = subscription_identities(new);
    if old_identities != new_identities {
        let old_consumers = subscription_consumers(old);
        let new_consumers = subscription_consumers(new);
        let old_groups = subscription_groups(old);
        let new_groups = subscription_groups(new);
        if old.len() == new.len() && old_groups == new_groups {
            out.push(changed(
                BreakingRule::SubscriptionConsumerChanged,
                "subscriptions.consumer",
                old,
                new,
            ));
            return;
        }
        if old.len() == new.len() && old_consumers == new_consumers {
            out.push(changed(
                BreakingRule::SubscriptionGroupChanged,
                "subscriptions.group",
                old,
                new,
            ));
            return;
        }
        out.push(changed(
            BreakingRule::SubscriptionSetChanged,
            "subscriptions",
            old,
            new,
        ));
        return;
    }
    let new_by_identity: BTreeMap<(&str, &str), &SubscriptionProjection> = new
        .iter()
        .map(|s| ((s.consumer.as_str(), s.group.as_str()), s))
        .collect();
    for a in old {
        let identity = (a.consumer.as_str(), a.group.as_str());
        let b = new_by_identity[&identity];
        if a.partition != b.partition || a.readiness != b.readiness {
            out.push(changed(
                BreakingRule::SubscriptionTopologyChanged,
                "subscriptions.topology",
                a,
                b,
            ));
        }
        compare_optional(
            out,
            BreakingRule::SubscriptionExecutionChanged,
            "subscriptions.execution",
            &a.execution,
            &b.execution,
        );
        // execution 在历史 base 缺失时一并忽略当前 carrier；一旦存在，effect 的
        // None↔Some 也是语义变化，不能使用 `compare_optional` 的 legacy 宽限。
        if a.execution.is_some() && a.effect != b.effect {
            out.push(changed(
                BreakingRule::SubscriptionEffectChanged,
                "subscriptions.effect",
                &a.effect,
                &b.effect,
            ));
        }
        if a.external_effect_policy != b.external_effect_policy {
            out.push(changed(
                BreakingRule::SubscriptionExternalEffectPolicyChanged,
                "subscriptions.externalEffectPolicy",
                &a.external_effect_policy,
                &b.external_effect_policy,
            ));
        }
    }
}

fn subscription_identities(
    subscriptions: &BTreeSet<SubscriptionProjection>,
) -> BTreeSet<(&str, &str)> {
    subscriptions
        .iter()
        .map(|s| (s.consumer.as_str(), s.group.as_str()))
        .collect()
}

fn subscription_consumers(subscriptions: &BTreeSet<SubscriptionProjection>) -> BTreeSet<&str> {
    subscriptions.iter().map(|s| s.consumer.as_str()).collect()
}

fn subscription_groups(subscriptions: &BTreeSet<SubscriptionProjection>) -> BTreeSet<&str> {
    subscriptions.iter().map(|s| s.group.as_str()).collect()
}

/// 一个待 diff 的契约投影（从 [`DiscoveredContract`](super::DiscoveredContract) + git/fs 读取派生，
/// 便于 [`evaluate`] 不依赖真 git 单测）。
#[derive(Debug, Clone)]
pub(crate) struct ContractDiff {
    /// 契约 label `{kind}/{domain}/{version}`。
    pub(crate) label: String,
    pub(crate) lifecycle: Lifecycle,
    /// working tree lifecycle；与 base 分级值分开保留，用于显式识别降级。
    pub(crate) working_lifecycle: Option<Lifecycle>,
    pub(crate) schemas: Vec<SchemaVersions>,
    pub(crate) manifest: ManifestVersions,
    pub(crate) removed: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct ManifestVersions {
    pub(crate) old: Option<ManifestProjection>,
    pub(crate) new: Option<ManifestProjection>,
}

/// 单个 logical schema slot 的两版本：`old=None` ⇒ base ref 无此 slot（新契约 / 新 slot，不报）；
/// slot/契约在 working 侧被删 ⇒ `new` 为空 schema（base 字段全报删除）。`file` 携 slot 名（request/response/payload/saga:step）。
#[derive(Debug, Clone)]
pub(crate) struct SchemaVersions {
    pub(crate) file: String,
    direction: SchemaDirection,
    removed: bool,
    pub(crate) old: Option<Value>,
    pub(crate) new: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SchemaDirection {
    Input,
    Output,
}

/// 一侧（base 或 working）的契约投影：label + lifecycle + slot→已解析 schema JSON。
/// base/working 两侧同形，[`plan_diffs`] 按 (identity, slot) 取并集对齐（C1：删除类破坏须从 base 侧进入比较）。
#[derive(Debug, Clone)]
pub(crate) struct ContractSide {
    /// 稳定契约身份。来自 manifest `id`，不随 flat/nested 目录迁移漂移。
    pub(crate) identity: ContractIdentity,
    /// 人读诊断 label，保留来源路径形态。
    pub(crate) label: String,
    pub(crate) lifecycle: Lifecycle,
    pub(crate) slots: BTreeMap<String, (SchemaDirection, Value)>,
    pub(crate) manifest: ManifestProjection,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ContractIdentity {
    id: String,
    version: String,
}

/// 按 (identity, slot) 构造 base ∪ working 并集（纯函数，C1）：
/// - lifecycle：base 在场恒用 base lifecycle，否则使用 working（降级不得绕过 active gate）。
/// - `old` = base slot schema（`None` ⇒ base 无此 slot ⇒ 新契约/新 slot，[`evaluate`] 跳过不报）。
/// - `new` = working slot schema；base 有而 working 无（slot/契约被删）⇒ 空 schema ⇒ compare 报 base 字段全删。
///
/// 这修复「只遍历 working 侧」漏检删除整个 active 契约 / 删 schema slot / slot 改名丢字段（对标 Buf
/// FILE_NO_DELETE / MESSAGE_NO_DELETE：基准侧存在而当前侧缺失须进入比较）。
pub(crate) fn plan_diffs(
    base: &[ContractSide],
    working: &[ContractSide],
) -> Result<Vec<ContractDiff>> {
    let base_idx = index_sides("base", base)?;
    let work_idx = index_sides("working", working)?;
    let identities: BTreeSet<&ContractIdentity> =
        base_idx.keys().chain(work_idx.keys()).copied().collect();

    let mut diffs = Vec::new();
    for identity in identities {
        let b = base_idx.get(identity).copied();
        let w = work_idx.get(identity).copied();
        // 既有契约一律以 base lifecycle 分级，working 降级不得绕过 active gate。
        let lifecycle = match b.or(w) {
            Some(s) => s.lifecycle,
            None => continue,
        };
        let label = w
            .or(b)
            .map(|s| s.label.as_str())
            .unwrap_or(identity.id.as_str())
            .to_string();
        let mut slot_keys: BTreeSet<&str> = BTreeSet::new();
        if let Some(s) = b {
            slot_keys.extend(s.slots.keys().map(String::as_str));
        }
        if let Some(s) = w {
            slot_keys.extend(s.slots.keys().map(String::as_str));
        }
        let mut schemas = Vec::new();
        for slot in slot_keys {
            let base_slot = b.and_then(|side| side.slots.get(slot));
            let working_slot = w.and_then(|side| side.slots.get(slot));
            let direction = match (base_slot, working_slot) {
                (Some((base_direction, _)), Some((working_direction, _))) => {
                    if base_direction != working_direction {
                        bail!(
                            "contract breaking: schema slot `{slot}` direction 由 {base_direction:?} 变为 {working_direction:?}"
                        );
                    }
                    *base_direction
                }
                (Some((direction, _)), None) | (None, Some((direction, _))) => *direction,
                (None, None) => continue,
            };
            let old = base_slot.map(|(_, schema)| schema.clone());
            let new = working_slot
                .map(|(_, schema)| schema.clone())
                .unwrap_or_else(empty_schema);
            schemas.push(SchemaVersions {
                file: slot.to_string(),
                direction,
                removed: working_slot.is_none(),
                old,
                new,
            });
        }
        diffs.push(ContractDiff {
            label,
            lifecycle,
            working_lifecycle: w.map(|s| s.lifecycle),
            schemas,
            manifest: ManifestVersions {
                old: b.map(|s| s.manifest.clone()),
                new: w.map(|s| s.manifest.clone()),
            },
            removed: b.is_some() && w.is_none(),
        });
    }
    Ok(diffs)
}

fn index_sides<'a>(
    side: &str,
    sides: &'a [ContractSide],
) -> Result<BTreeMap<&'a ContractIdentity, &'a ContractSide>> {
    let mut index = BTreeMap::new();
    for contract in sides {
        if index.insert(&contract.identity, contract).is_some() {
            bail!(
                "contract breaking: {side} 存在重复 contract identity `{}@{}`",
                contract.identity.id,
                contract.identity.version,
            );
        }
    }
    Ok(index)
}

/// 空 JSON Schema（`{}`，无 properties）——working 侧删除的 slot 用此作 `new`，使 compare 报 base 字段全删。
fn empty_schema() -> Value {
    Value::Object(serde_json::Map::new())
}

/// 评估结果：分级 finding 列表 + 是否含 `Deny`（决定退出码）。
#[derive(Debug, Default)]
pub(crate) struct EvalResult {
    pub(crate) findings: Vec<GradedFinding>,
    pub(crate) any_deny: bool,
}

/// 纯评估（无 IO）：过滤 active/deprecated（draft 跳过）→ 逐 schema diff → 按 [`disposition`] 分级。
/// 这是 gate 的可测核心 seam——run 只负责 discover + git/fs 读取 + 打印 + 退出码。
pub(crate) fn evaluate(contracts: &[ContractDiff]) -> EvalResult {
    let mut result = EvalResult::default();
    for c in contracts {
        if !is_checked(c.lifecycle) {
            continue; // draft：seed/前瞻原地演进豁免（WIRE-BREAKING-WINDOW-01）
        }
        let disp = disposition(c.lifecycle);
        if c.lifecycle == Lifecycle::Active
            && let Some(working @ (Lifecycle::Draft | Lifecycle::Deprecated)) = c.working_lifecycle
        {
            push_finding(
                &mut result,
                c.lifecycle,
                disp,
                BreakingRule::LifecycleDowngraded,
                format!("{} manifest (lifecycle)", c.label),
                format!("active 契约 lifecycle 降级为 {working:?}"),
            );
        }
        if c.removed {
            push_finding(
                &mut result,
                c.lifecycle,
                disp,
                BreakingRule::ContractRemoved,
                c.label.clone(),
                "base 契约在 working tree 中被删除".to_string(),
            );
        }
        if let (Some(old), Some(new)) = (&c.manifest.old, &c.manifest.new) {
            for b in compare_manifests(old, new) {
                push_finding(
                    &mut result,
                    c.lifecycle,
                    rule_disposition(b.rule, c.lifecycle),
                    b.rule,
                    format!("{} manifest ({})", c.label, b.pointer),
                    b.detail,
                );
            }
        }
        for sv in &c.schemas {
            let Some(old) = &sv.old else {
                continue; // base ref 无此 schema：新契约 / 新版本，不报
            };
            let breaks = if sv.removed {
                compare_schemas_for_direction(old, &sv.new, SchemaDirection::Input)
            } else {
                compare_schemas_for_direction(old, &sv.new, sv.direction)
            };
            for b in breaks {
                push_finding(
                    &mut result,
                    c.lifecycle,
                    disp,
                    b.rule,
                    format!("{} {} ({})", c.label, sv.file, show(&b.pointer)),
                    b.detail,
                );
            }
        }
    }
    result
}

fn push_finding(
    result: &mut EvalResult,
    lifecycle: Lifecycle,
    disposition: Disposition,
    rule: BreakingRule,
    subject: String,
    detail: String,
) {
    result.any_deny |= disposition == Disposition::Deny;
    result.findings.push(GradedFinding {
        lifecycle,
        disposition,
        rule,
        subject,
        detail,
    });
}

/// gate 入口：discover working-tree 契约 → 读 base schema（`git show {against}:...`）→ [`evaluate`] →
/// 打印分级 finding → 有 `Deny` 即 `bail`（退出码 1），否则 `Ok`（退出码 0）。
/// base ref 不可解析或 Git 基线命令失败均 fail-closed。
pub(crate) fn run(against: &str) -> Result<()> {
    let root = crate::workspace_root()?;
    match read_ref(&root, against) {
        GitRead::Found(()) => {}
        GitRead::Missing => return unresolved_ref(against),
        GitRead::CommandFailed(failure) => return Err(failure.into()),
    }
    let contracts_root = root.join("contracts");
    let working = working_sides(&contracts_root)?;
    let base = base_sides(&root, against)?;
    let diffs = plan_diffs(&base, &working)?;
    let result = evaluate(&diffs);
    print_result(against, &result);
    enforce_breaking_authorization(&root, against, &result.findings)?;
    enforce_review_ack(&root, against, &result.findings)?;
    Ok(())
}

fn enforce_breaking_authorization(
    root: &Path,
    against: &str,
    findings: &[GradedFinding],
) -> Result<()> {
    let denied: Vec<GradedFinding> = findings
        .iter()
        .filter(|finding| finding.disposition == Disposition::Deny)
        .cloned()
        .collect();
    if denied.is_empty() {
        return Ok(());
    }
    let base_oid = git_stdout(
        root,
        &["rev-parse", "--verify", &format!("{against}^{{commit}}")],
    )?;
    let range = format!("{against}..HEAD");
    let messages = git_stdout(root, &["log", "--format=%B%x00", &range])?;
    verify_breaking_authorization(base_oid.trim(), &denied, &messages)
}

fn verify_breaking_authorization(
    base_oid: &str,
    findings: &[GradedFinding],
    commit_messages: &str,
) -> Result<()> {
    let fingerprint = breaking_authorization_fingerprint(base_oid, findings);
    let expected = format!("{BREAKING_AUTHORIZATION_PREFIX}{fingerprint}");
    if !commit_messages_contain_review_ack(commit_messages, &expected) {
        bail!(
            "contract breaking: {} 项 active 契约 wire 破坏未经精确授权（fingerprint={fingerprint}）。确认 intentional breaking 后，在承载变更或后续 commit body 中加入精确 trailer：\n{expected}",
            findings.len()
        );
    }
    Ok(())
}

fn enforce_review_ack(root: &Path, against: &str, findings: &[GradedFinding]) -> Result<()> {
    let review_findings: Vec<GradedFinding> = findings
        .iter()
        .filter(|finding| {
            finding.lifecycle == Lifecycle::Active && is_review_only_rule(finding.rule)
        })
        .cloned()
        .collect();
    if review_findings.is_empty() {
        return Ok(());
    }

    let base_oid = git_stdout(
        root,
        &["rev-parse", "--verify", &format!("{against}^{{commit}}")],
    )?;
    let range = format!("{against}..HEAD");
    let messages = git_stdout(root, &["log", "--format=%B%x00", &range])?;
    verify_review_ack(base_oid.trim(), &review_findings, &messages)
}

fn verify_review_ack(
    base_oid: &str,
    findings: &[GradedFinding],
    commit_messages: &str,
) -> Result<()> {
    let fingerprint = review_ack_fingerprint(base_oid, findings);
    let expected = format!("{REVIEW_ACK_PREFIX}{fingerprint}");
    if !commit_messages_contain_review_ack(commit_messages, &expected) {
        bail!(
            "contract breaking: review-only findings 尚未确认（fingerprint={fingerprint}）。审阅 rule/subject/detail 后，在承载变更或后续 commit body 中加入精确 trailer：\n{expected}"
        );
    }
    Ok(())
}

fn git_stdout(root: &Path, args: &[&str]) -> Result<String> {
    let output = git_output(root, args)?;
    if !output.status.success() {
        return Err(command_failure(args, &output).into());
    }
    String::from_utf8(output.stdout)
        .map_err(|error| anyhow::anyhow!("contract breaking: git output is not UTF-8: {error}"))
}

fn review_ack_fingerprint(base_oid: &str, findings: &[GradedFinding]) -> String {
    findings_fingerprint(b"rss-contract-review-ack-v1\0", base_oid, findings)
}

fn breaking_authorization_fingerprint(base_oid: &str, findings: &[GradedFinding]) -> String {
    findings_fingerprint(
        b"rss-contract-breaking-authorization-v1\0",
        base_oid,
        findings,
    )
}

fn findings_fingerprint(domain: &[u8], base_oid: &str, findings: &[GradedFinding]) -> String {
    let mut canonical: Vec<(&str, &str, &str)> = findings
        .iter()
        .map(|finding| {
            (
                finding.rule.id(),
                finding.subject.as_str(),
                finding.detail.as_str(),
            )
        })
        .collect();
    canonical.sort_unstable();

    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(base_oid.as_bytes());
    digest.update([0]);
    for (rule, subject, detail) in canonical {
        for field in [rule, subject, detail] {
            digest.update(field.as_bytes());
            digest.update([0]);
        }
    }
    format!("{:x}", digest.finalize())
}

fn commit_messages_contain_review_ack(messages: &str, expected: &str) -> bool {
    messages
        .split('\0')
        .flat_map(str::lines)
        .any(|line| line.trim() == expected)
}

/// base ref 不可解析时 fail-closed；无法读基准 wire 就不能判定兼容性。
fn unresolved_ref(against: &str) -> Result<()> {
    let hint = fetch_hint(against);
    bail!(
        "contract breaking: base ref `{against}` 不可解析，fail-closed——无法读基准 wire。先 `{hint}`，或 `--against <本地 ref>`（如 HEAD~1）。"
    )
}

/// 由 base ref 推 fetch 指引：含 `/`（如 `origin/develop`）→ `git fetch origin develop`；无 `/` → `git fetch`。
fn fetch_hint(against: &str) -> String {
    match against.split_once('/') {
        Some((remote, branch)) => format!("git fetch {remote} {branch}"),
        None => "git fetch".to_string(),
    }
}

/// 打印分级 finding（warn / deny 前缀 + 规则 ID + subject + detail）。
fn print_result(against: &str, result: &EvalResult) {
    if result.findings.is_empty() {
        eprintln!("contract breaking（against {against}）：无 wire 破坏");
    } else {
        for f in &result.findings {
            eprintln!(
                "  [{}] {} {}: {}",
                f.disposition.label(),
                f.rule.id(),
                f.subject,
                f.detail
            );
        }
        let denies = result
            .findings
            .iter()
            .filter(|f| f.disposition == Disposition::Deny)
            .count();
        eprintln!(
            "contract breaking（against {against}）：{} 项破坏（{denies} deny / {} warn）",
            result.findings.len(),
            result.findings.len() - denies
        );
    }
}

#[derive(Debug)]
enum GitRead<T> {
    Found(T),
    Missing,
    CommandFailed(GitCommandFailure),
}

#[derive(Debug)]
struct GitCommandFailure {
    command: String,
    status: Option<i32>,
    stderr: String,
}

impl std::fmt::Display for GitCommandFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "contract breaking: `{}` 失败（status={:?}, stderr={}），fail-closed",
            self.command, self.status, self.stderr
        )
    }
}

impl std::error::Error for GitCommandFailure {}

fn git_output(root: &Path, args: &[&str]) -> std::result::Result<Output, GitCommandFailure> {
    crate::cmd::external_cmd(
        crate::cmd::ExternalProgram::SystemGit,
        args,
        &[],
        Some(root),
    )
    .output()
    .map_err(|error| GitCommandFailure {
        command: format!("git {}", args.join(" ")),
        status: None,
        stderr: sanitize_git_stderr(&error.to_string()),
    })
}

fn command_failure(args: &[&str], output: &Output) -> GitCommandFailure {
    GitCommandFailure {
        command: format!("git {}", args.join(" ")),
        status: output.status.code(),
        stderr: sanitize_git_stderr(&String::from_utf8_lossy(&output.stderr)),
    }
}

fn sanitize_git_stderr(stderr: &str) -> String {
    let collapsed = stderr.split_whitespace().collect::<Vec<_>>().join(" ");
    let sanitized = if collapsed.is_empty() {
        "<empty>"
    } else {
        collapsed.as_str()
    };
    sanitized.chars().take(1024).collect()
}

/// 明确区分 ref 不存在与 Git 命令失败。
fn read_ref(root: &Path, git_ref: &str) -> GitRead<()> {
    let args = ["rev-parse", "--verify", "--quiet", git_ref];
    let output = match git_output(root, &args) {
        Ok(output) => output,
        Err(failure) => return GitRead::CommandFailed(failure),
    };
    if output.status.success() {
        GitRead::Found(())
    } else if output.stderr.is_empty() {
        GitRead::Missing
    } else {
        GitRead::CommandFailed(command_failure(&args, &output))
    }
}

/// 读 working-tree schema 文件并解析为 `Value`。
fn read_working_schema(dir: &Path, file: &str) -> Result<Value> {
    let path = dir.join(file);
    let text = std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("读取 {} 失败: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| anyhow::anyhow!("解析 {} 失败: {e}", path.display()))
}

/// manifest 的 logical schema slot → 文件名映射（DRY，base/working 两侧同源构造 [`ContractSide`]）。
/// slot 名：`request`/`response`/`payload` + 每个 saga step `saga:{name}`——按 slot（非文件名）对齐，
/// 使「slot 改名」按内容比对（文件名非 wire，重命名本身不破坏；内容丢字段才破坏）。
fn slot_files(m: &ContractManifest) -> Vec<(String, String, SchemaDirection)> {
    let mut v = Vec::new();
    for (slot, file, direction) in [
        (
            "request",
            m.schemas.request.as_deref(),
            SchemaDirection::Input,
        ),
        (
            "response",
            m.schemas.response.as_deref(),
            SchemaDirection::Output,
        ),
        (
            "payload",
            m.schemas.payload.as_deref(),
            payload_direction(m.kind),
        ),
    ] {
        if let Some(f) = file {
            v.push((slot.to_string(), f.to_string(), direction));
        }
    }
    if let Some(saga) = &m.saga {
        for s in &saga.steps {
            v.push((
                format!("saga:{}", s.name),
                s.output_schema.clone(),
                SchemaDirection::Output,
            ));
        }
    }
    v
}

fn payload_direction(kind: ContractKind) -> SchemaDirection {
    match kind {
        ContractKind::Event => SchemaDirection::Output,
        ContractKind::Http | ContractKind::Command | ContractKind::Saga => SchemaDirection::Input,
    }
}

#[derive(Debug, Deserialize)]
struct BaseContractManifest {
    id: String,
    kind: ContractKind,
    version: String,
    lifecycle: Lifecycle,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    method: Option<HttpMethod>,
    #[serde(default, rename = "consistencyLevel")]
    consistency_level: Option<ConsistencyLevel>,
    #[serde(default, rename = "effectProfile")]
    effect_profile: Option<BaseEffectProfile>,
    #[serde(default)]
    endpoints: Option<BaseEndpoints>,
    #[serde(default)]
    topic: Option<String>,
    #[serde(default)]
    delivery: Option<Delivery>,
    #[serde(default)]
    capabilities: BaseCapabilities,
    #[serde(default)]
    subscriptions: Vec<BaseSubscription>,
    #[serde(default)]
    schemas: BaseSchemas,
    #[serde(default)]
    saga: Option<BaseSagaBlock>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BaseEffectProfile {
    effects: Vec<BaseEffectKind>,
}

/// Historical-only parser vocabulary for immutable Git base manifests.
///
/// The parser accepts both generations, while the breaking projection preserves their spelling
/// identity until the review diff. This type is private and is never used by working-tree
/// validation, code generation, or runtime metadata.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum BaseEffectKind {
    Read,
    Auth,
    Projection,
    Write,
    Transaction,
    BusinessWrite,
    BusinessTransaction,
    Outbox,
    Publish,
    Workflow,
    Saga,
    Reconcile,
    Worker,
    CrossTenantAudit,
}

impl BaseEffectKind {
    fn semantic(self) -> EffectKind {
        match self {
            Self::Read => EffectKind::Read,
            Self::Auth => EffectKind::Auth,
            Self::Projection => EffectKind::Projection,
            Self::Write | Self::BusinessWrite => EffectKind::BusinessWrite,
            Self::Transaction | Self::BusinessTransaction => EffectKind::BusinessTransaction,
            Self::Outbox => EffectKind::Outbox,
            Self::Publish => EffectKind::Publish,
            Self::Workflow => EffectKind::Workflow,
            Self::Saga => EffectKind::Saga,
            Self::Reconcile => EffectKind::Reconcile,
            Self::Worker => EffectKind::Worker,
            Self::CrossTenantAudit => EffectKind::CrossTenantAudit,
        }
    }

    fn identity(self) -> EffectIdentity {
        match self {
            Self::Read => EffectIdentity::Read,
            Self::Auth => EffectIdentity::Auth,
            Self::Projection => EffectIdentity::Projection,
            Self::Write => EffectIdentity::Write,
            Self::Transaction => EffectIdentity::Transaction,
            Self::BusinessWrite => EffectIdentity::BusinessWrite,
            Self::BusinessTransaction => EffectIdentity::BusinessTransaction,
            Self::Outbox => EffectIdentity::Outbox,
            Self::Publish => EffectIdentity::Publish,
            Self::Workflow => EffectIdentity::Workflow,
            Self::Saga => EffectIdentity::Saga,
            Self::Reconcile => EffectIdentity::Reconcile,
            Self::Worker => EffectIdentity::Worker,
            Self::CrossTenantAudit => EffectIdentity::CrossTenantAudit,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
struct BaseEndpoints {
    #[serde(default)]
    http: Option<BaseHttpEndpoint>,
}

#[derive(Debug, Deserialize)]
struct BaseHttpEndpoint {
    #[serde(default, rename = "successStatus")]
    success_status: Option<u16>,
    #[serde(default)]
    idempotency: Option<HttpIdempotency>,
    #[serde(default)]
    auth: Option<BaseHttpAuth>,
    #[serde(default)]
    resource: Option<String>,
    #[serde(default, rename = "selfScoped")]
    self_scoped: bool,
    #[serde(default, rename = "resourceSharing")]
    resource_sharing: Option<BaseHttpResourceSharing>,
}

#[derive(Debug, Deserialize)]
struct BaseHttpResourceSharing {
    mode: HttpResourceSharingMode,
}

#[derive(Debug, Deserialize)]
struct BaseHttpAuth {
    mode: HttpAuthMode,
    #[serde(default)]
    permission: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct BaseCapabilities {
    #[serde(default)]
    outbox: Option<BaseOutbox>,
}

#[derive(Debug, Deserialize)]
struct BaseOutbox {
    role: OutboxRole,
    #[serde(default)]
    atomicity: Option<OutboxAtomicity>,
    #[serde(default)]
    emits: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct BaseSubscription {
    consumer: String,
    group: String,
    #[serde(default)]
    execution: Option<SubscriptionExecution>,
    #[serde(default)]
    effect: Option<SubscriptionEffect>,
    #[serde(default, rename = "externalEffectPolicy")]
    external_effect_policy: Option<ExternalEffectPolicy>,
    topology: BaseSubscriptionTopology,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BaseSubscriptionTopology {
    partition_key: PartitionKeyStrategy,
    readiness: SubscriberReadiness,
}

#[derive(Debug, Default, Deserialize)]
struct BaseSchemas {
    #[serde(default)]
    request: Option<String>,
    #[serde(default)]
    response: Option<String>,
    #[serde(default)]
    payload: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BaseSagaBlock {
    #[serde(default)]
    steps: Vec<BaseSagaStep>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BaseSagaStep {
    name: String,
    output_schema: String,
}

/// Base refs may carry an older authoring schema. Wire-breaking only needs
/// identity, lifecycle and schema slot filenames, so keep this projection narrow
/// instead of accepting legacy manifests in the current full manifest parser.
fn base_slot_files(m: &BaseContractManifest) -> Vec<(String, String, SchemaDirection)> {
    let mut v = Vec::new();
    for (slot, file, direction) in [
        (
            "request",
            m.schemas.request.as_deref(),
            SchemaDirection::Input,
        ),
        (
            "response",
            m.schemas.response.as_deref(),
            SchemaDirection::Output,
        ),
        (
            "payload",
            m.schemas.payload.as_deref(),
            payload_direction(m.kind),
        ),
    ] {
        if let Some(f) = file {
            v.push((slot.to_string(), f.to_string(), direction));
        }
    }
    if let Some(saga) = &m.saga {
        for s in &saga.steps {
            v.push((
                format!("saga:{}", s.name),
                s.output_schema.clone(),
                SchemaDirection::Output,
            ));
        }
    }
    v
}

fn manifest_projection(m: &ContractManifest) -> Result<ManifestProjection> {
    let http = m
        .endpoints
        .as_ref()
        .and_then(|e| e.http.as_ref())
        .map(|h| HttpWireProjection {
            path: m.path.clone(),
            method: m.method.map(http_method).map(str::to_string),
            success_status: Some(h.success_status),
            auth: h.auth.as_ref().map(|a| AuthProjection {
                mode: auth_mode(a.mode).to_string(),
                permission: a.permission.clone(),
            }),
            auth_scope: AuthScopeProjection {
                resource: h.resource.clone(),
                self_scoped: h.self_scoped,
            },
            resource_sharing: h
                .resource_sharing
                .as_ref()
                .map(|sharing| resource_sharing_mode(sharing.mode))
                .unwrap_or("tenantScoped")
                .to_string(),
            idempotency: Some(idempotency(h.idempotency).to_string()),
        });
    Ok(ManifestProjection {
        http,
        topic: m.topic.clone(),
        delivery: m.delivery.map(delivery).map(str::to_string),
        consistency: Some(consistency(m.consistency_level).to_string()),
        effects: strict_http_effects(m.kind, m.effect_profile.as_ref(), &m.id)?,
        outbox: m.capabilities.outbox.as_ref().map(|o| OutboxProjection {
            role: outbox_role(o.role).to_string(),
            atomicity: o.atomicity.map(outbox_atomicity).map(str::to_string),
            emits: o.emits.iter().cloned().collect(),
        }),
        subscriptions: m
            .subscriptions
            .iter()
            .map(|s| SubscriptionProjection {
                consumer: s.consumer.clone(),
                group: s.group.clone(),
                partition: partition(s.topology.partition_key).to_string(),
                readiness: readiness(s.topology.readiness).to_string(),
                execution: Some(execution(s.execution).to_string()),
                effect: s.effect.map(effect).map(str::to_string),
                external_effect_policy: external_effect_policy(s.external_effect_policy)
                    .to_string(),
            })
            .collect(),
    })
}

fn base_manifest_projection(m: &BaseContractManifest) -> Result<ManifestProjection> {
    let http = m
        .endpoints
        .as_ref()
        .and_then(|e| e.http.as_ref())
        .map(|h| HttpWireProjection {
            path: m.path.clone(),
            method: m.method.map(http_method).map(str::to_string),
            success_status: h.success_status,
            auth: h.auth.as_ref().map(|a| AuthProjection {
                mode: auth_mode(a.mode).to_string(),
                permission: a.permission.clone(),
            }),
            auth_scope: AuthScopeProjection {
                resource: h.resource.clone(),
                self_scoped: h.self_scoped,
            },
            resource_sharing: h
                .resource_sharing
                .as_ref()
                .map(|sharing| resource_sharing_mode(sharing.mode))
                .unwrap_or("tenantScoped")
                .to_string(),
            idempotency: h.idempotency.map(idempotency).map(str::to_string),
        });
    Ok(ManifestProjection {
        http,
        topic: m.topic.clone(),
        delivery: m.delivery.map(delivery).map(str::to_string),
        consistency: m.consistency_level.map(consistency).map(str::to_string),
        effects: strict_base_http_effects(m.kind, m.effect_profile.as_ref(), &m.id)?,
        outbox: m.capabilities.outbox.as_ref().map(|o| OutboxProjection {
            role: outbox_role(o.role).to_string(),
            atomicity: o.atomicity.map(outbox_atomicity).map(str::to_string),
            emits: o.emits.iter().cloned().collect(),
        }),
        subscriptions: m
            .subscriptions
            .iter()
            .map(|s| {
                Ok(SubscriptionProjection {
                    consumer: s.consumer.clone(),
                    group: s.group.clone(),
                    partition: partition(s.topology.partition_key).to_string(),
                    readiness: readiness(s.topology.readiness).to_string(),
                    execution: s.execution.map(execution).map(str::to_string),
                    effect: s.effect.map(effect).map(str::to_string),
                    external_effect_policy: base_external_effect_policy(s)?,
                })
            })
            .collect::<Result<BTreeSet<_>>>()?,
    })
}

fn base_external_effect_policy(subscription: &BaseSubscription) -> Result<String> {
    let policy = match subscription.external_effect_policy {
        Some(policy) => policy,
        None => match (subscription.execution, subscription.effect) {
            (Some(SubscriptionExecution::AdapterNative), None) => {
                ExternalEffectPolicy::TransactionalOnly
            }
            (
                Some(SubscriptionExecution::DomainEffect),
                Some(SubscriptionEffect::SettingsConfigVersionRefresh),
            ) => ExternalEffectPolicy::Reconcile,
            _ => bail!(
                "legacy subscription {}/{} 缺 externalEffectPolicy，且 execution/effect 无法唯一推导策略",
                subscription.consumer,
                subscription.group
            ),
        },
    };
    Ok(external_effect_policy(policy).to_string())
}

fn strict_http_effects(
    kind: ContractKind,
    profile: Option<&EffectProfile>,
    id: &str,
) -> Result<BTreeSet<EffectIdentity>> {
    if kind != ContractKind::Http {
        return Ok(BTreeSet::new());
    }
    let effects = &profile
        .ok_or_else(|| anyhow::anyhow!("HTTP contract `{id}` missing effectProfile"))?
        .effects;
    if effects.is_empty() {
        bail!("HTTP contract `{id}` effectProfile.effects must not be empty");
    }
    let unique: BTreeSet<EffectKind> = effects.iter().copied().collect();
    if unique.len() != effects.len() {
        bail!("HTTP contract `{id}` effectProfile.effects contains duplicate values");
    }
    Ok(unique.into_iter().map(EffectIdentity::from).collect())
}

fn strict_base_http_effects(
    kind: ContractKind,
    profile: Option<&BaseEffectProfile>,
    id: &str,
) -> Result<BTreeSet<EffectIdentity>> {
    if kind != ContractKind::Http {
        return Ok(BTreeSet::new());
    }
    let effects = &profile
        .ok_or_else(|| anyhow::anyhow!("HTTP contract `{id}` missing effectProfile"))?
        .effects;
    if effects.is_empty() {
        bail!("HTTP contract `{id}` effectProfile.effects must not be empty");
    }
    let semantic_unique: BTreeSet<EffectKind> = effects
        .iter()
        .copied()
        .map(BaseEffectKind::semantic)
        .collect();
    if semantic_unique.len() != effects.len() {
        bail!("HTTP contract `{id}` effectProfile.effects contains duplicate semantic values");
    }
    Ok(effects
        .iter()
        .copied()
        .map(BaseEffectKind::identity)
        .collect())
}

fn consistency(value: ConsistencyLevel) -> &'static str {
    match value {
        ConsistencyLevel::LocalOnly => "LocalOnly",
        ConsistencyLevel::LocalTx => "LocalTx",
        ConsistencyLevel::OutboxFact => "OutboxFact",
        ConsistencyLevel::WorkflowEventual => "WorkflowEventual",
        ConsistencyLevel::DeviceLatent => "DeviceLatent",
    }
}
fn delivery(value: Delivery) -> &'static str {
    value.as_wire()
}
fn auth_mode(value: HttpAuthMode) -> &'static str {
    value.as_wire()
}
fn http_method(value: HttpMethod) -> &'static str {
    value.as_wire()
}
fn resource_sharing_mode(value: HttpResourceSharingMode) -> &'static str {
    match value {
        HttpResourceSharingMode::TenantScoped => "tenantScoped",
        HttpResourceSharingMode::Global => "global",
    }
}
fn idempotency(value: HttpIdempotency) -> &'static str {
    match value {
        HttpIdempotency::Idempotent => "idempotent",
        HttpIdempotency::NonIdempotent => "non-idempotent",
    }
}
fn outbox_role(value: OutboxRole) -> &'static str {
    match value {
        OutboxRole::Producer => "producer",
        OutboxRole::Fact => "fact",
        OutboxRole::Command => "command",
    }
}
fn outbox_atomicity(value: OutboxAtomicity) -> &'static str {
    match value {
        OutboxAtomicity::SameTransaction => "same-transaction",
    }
}
fn partition(value: PartitionKeyStrategy) -> &'static str {
    match value {
        PartitionKeyStrategy::None => "none",
        PartitionKeyStrategy::Aggregate => "aggregate",
    }
}
fn readiness(value: SubscriberReadiness) -> &'static str {
    match value {
        SubscriberReadiness::Required => "required",
    }
}
fn execution(value: SubscriptionExecution) -> &'static str {
    match value {
        SubscriptionExecution::AdapterNative => "adapter-native",
        SubscriptionExecution::DomainEffect => "domain-effect",
    }
}
fn effect(value: SubscriptionEffect) -> &'static str {
    match value {
        SubscriptionEffect::SettingsConfigVersionRefresh => "settings-config-version-refresh",
    }
}
fn external_effect_policy(value: ExternalEffectPolicy) -> &'static str {
    match value {
        ExternalEffectPolicy::TransactionalOnly => "transactional-only",
        ExternalEffectPolicy::IdempotencyKey => "idempotency-key",
        ExternalEffectPolicy::Reconcile => "reconcile",
        ExternalEffectPolicy::Compensated => "compensated",
    }
}

/// working-tree 侧契约投影：discover + 逐 slot 读磁盘 schema。
fn working_sides(contracts_root: &Path) -> Result<Vec<ContractSide>> {
    let discovered = discover(contracts_root)?;
    let mut sides = Vec::with_capacity(discovered.len());
    for c in &discovered {
        let label = contract_label(c);
        let identity = contract_identity(&c.manifest);
        let mut slots = BTreeMap::new();
        for (slot, file, direction) in slot_files(&c.manifest) {
            slots.insert(slot, (direction, read_working_schema(&c.dir, &file)?));
        }
        sides.push(ContractSide {
            identity,
            label,
            lifecycle: c.manifest.lifecycle,
            slots,
            manifest: manifest_projection(&c.manifest).with_context(|| {
                format!(
                    "project working contract {}",
                    c.dir.join("contract.toml").display()
                )
            })?,
        });
    }
    Ok(sides)
}

/// base 侧契约投影：`git ls-tree` 枚举 base 契约 → 逐个 `git show` contract.toml + 各 slot schema。
fn base_sides(root: &Path, against: &str) -> Result<Vec<ContractSide>> {
    let mut sides = Vec::new();
    for manifest_rel in base_contract_manifests(root, against)? {
        let text = require_git_text(
            read_text_at_ref(root, against, &manifest_rel),
            format!("base 已枚举 manifest `{manifest_rel}` 但路径不存在，fail-closed"),
        )?;
        let manifest = toml::from_str::<BaseContractManifest>(&text)
            .map_err(|e| anyhow::anyhow!("解析 base {manifest_rel} 失败: {e}"))?;
        let Some(label) = label_from_manifest_path(&manifest_rel) else {
            continue; // 非 contracts/{kind}/{domain}/{version}/contract.toml 形态
        };
        let Some(dir_rel) = manifest_rel.strip_suffix("/contract.toml") else {
            continue;
        };
        let mut slots = BTreeMap::new();
        for (slot, file, direction) in base_slot_files(&manifest) {
            let schema_rel = format!("{dir_rel}/{file}");
            let schema_text = require_git_text(
                read_text_at_ref(root, against, &schema_rel),
                format!("base manifest 引用 schema `{schema_rel}` 不存在，fail-closed"),
            )?;
            let v = serde_json::from_str(&schema_text)
                .map_err(|e| anyhow::anyhow!("解析 base schema {schema_rel} 失败: {e}"))?;
            slots.insert(slot, (direction, v));
        }
        sides.push(ContractSide {
            identity: ContractIdentity {
                id: manifest.id.clone(),
                version: manifest.version.clone(),
            },
            label,
            lifecycle: manifest.lifecycle,
            slots,
            manifest: base_manifest_projection(&manifest)
                .with_context(|| format!("project base contract {against}:{manifest_rel}"))?,
        });
    }
    Ok(sides)
}

/// `git ls-tree -r --name-only {ref} -- contracts/` 列 base 侧所有 `contract.toml` 路径。
/// 经 [`external_cmd`](crate::cmd::external_cmd)（CMD-FUNNEL-01）。ref 无 contracts/ → 空（非错）。
fn base_contract_manifests(root: &Path, against: &str) -> Result<Vec<String>> {
    let args = ["ls-tree", "-r", "--name-only", against, "--", "contracts/"];
    let out = git_output(root, &args)?;
    if !out.status.success() {
        return Err(command_failure(&args, &out).into());
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.ends_with("/contract.toml"))
        .map(str::to_string)
        .collect())
}

/// `git show {ref}:{rel}` 读文本；先以 `ls-tree` 明确判定 path missing，任何其它 non-zero
/// 均携 status/stderr 返回 [`GitRead::CommandFailed`]。
fn read_text_at_ref(root: &Path, git_ref: &str, rel: &str) -> GitRead<String> {
    match path_at_ref(root, git_ref, rel) {
        GitRead::Found(()) => {}
        GitRead::Missing => return GitRead::Missing,
        GitRead::CommandFailed(failure) => return GitRead::CommandFailed(failure),
    }
    let spec = format!("{git_ref}:{rel}");
    let args = ["show", &spec];
    let out = match git_output(root, &args) {
        Ok(output) => output,
        Err(failure) => return GitRead::CommandFailed(failure),
    };
    if !out.status.success() {
        return GitRead::CommandFailed(command_failure(&args, &out));
    }
    GitRead::Found(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn path_at_ref(root: &Path, git_ref: &str, rel: &str) -> GitRead<()> {
    let args = ["ls-tree", "--name-only", git_ref, "--", rel];
    let out = match git_output(root, &args) {
        Ok(output) => output,
        Err(failure) => return GitRead::CommandFailed(failure),
    };
    if !out.status.success() {
        return GitRead::CommandFailed(command_failure(&args, &out));
    }
    let found = String::from_utf8_lossy(&out.stdout)
        .lines()
        .any(|candidate| candidate == rel);
    if found {
        GitRead::Found(())
    } else {
        GitRead::Missing
    }
}

fn require_git_text(read: GitRead<String>, missing: String) -> Result<String> {
    match read {
        GitRead::Found(text) => Ok(text),
        GitRead::Missing => bail!(missing),
        GitRead::CommandFailed(failure) => Err(failure.into()),
    }
}

/// `contracts/{kind}/{domain}/{version}[/<slug>]/contract.toml` → label
/// `{kind}/{domain}/{version}[/<slug>]`（与 working 同源）。
fn label_from_manifest_path(rel: &str) -> Option<String> {
    let inner = rel
        .strip_prefix("contracts/")?
        .strip_suffix("/contract.toml")?;
    let count = inner.split('/').count();
    matches!(count, 3 | 4).then(|| inner.to_string())
}

fn contract_identity(m: &ContractManifest) -> ContractIdentity {
    ContractIdentity {
        id: m.id.clone(),
        version: m.version.clone(),
    }
}

/// 契约诊断 label：嵌套契约必须带 slug，否则同一 `{kind}/{domain}/{version}` 下的 sibling 会互相覆盖。
fn contract_label(c: &super::DiscoveredContract) -> String {
    match &c.slug {
        Some(slug) => format!(
            "{}/{}/{}/{}",
            c.path_kind, c.path_domain, c.path_version, slug
        ),
        None => format!("{}/{}/{}", c.path_kind, c.path_domain, c.path_version),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use serde_json::json;

    fn rules(breaks: &[RawBreak]) -> Vec<BreakingRule> {
        breaks.iter().map(|b| b.rule).collect()
    }

    // ─────────── 各规则 red（破坏→finding）+ green（兼容→无）───────────

    /// FIELD_NO_DELETE：删字段 red；保留 / 新增字段 green。
    #[test]
    fn field_no_delete_red_and_green() {
        let old = json!({"properties": {"id": {"type": "string"}, "name": {"type": "string"}}});
        let new_del = json!({"properties": {"id": {"type": "string"}}});
        assert_eq!(
            rules(&compare_schemas(&old, &new_del)),
            vec![BreakingRule::FieldNoDelete]
        );

        // green：新增字段（id+name+extra）不报。
        let new_add = json!({"properties": {"id": {"type":"string"}, "name": {"type":"string"}, "extra": {"type":"string"}}});
        assert!(compare_schemas(&old, &new_add).is_empty());

        // red 边界：new 整体移除 `properties` 键 → 旧两字段均报删除（check_field_deletions 的 np=None 分支）。
        let new_no_props = json!({"type": "object"});
        let mut got = rules(&compare_schemas(&old, &new_no_props));
        got.sort_by_key(|r| r.id());
        assert_eq!(
            got,
            vec![BreakingRule::FieldNoDelete, BreakingRule::FieldNoDelete]
        );
    }

    /// REQUIRED_FIELD_ADDED：新增 required red；已有 required 不变 green。
    #[test]
    fn required_field_added_red_and_green() {
        let old = json!({"properties": {"email": {"type":"string"}}, "required": []});
        let new = json!({"properties": {"email": {"type":"string"}}, "required": ["email"]});
        assert_eq!(
            rules(&compare_schemas(&old, &new)),
            vec![BreakingRule::RequiredFieldAdded]
        );

        // green：required 不变。
        assert!(compare_schemas(&old, &old).is_empty());
    }

    /// FIELD_TYPE_CHANGED：union 收紧 single red；single 扩 union green。
    #[test]
    fn field_type_changed_red_and_green() {
        let old = json!({"properties": {"count": {"type": ["integer","string"]}}});
        let new_narrow = json!({"properties": {"count": {"type": "integer"}}});
        assert_eq!(
            rules(&compare_schemas(&old, &new_narrow)),
            vec![BreakingRule::FieldTypeChanged]
        );

        // green：single→union（扩容）不报。
        let single = json!({"properties": {"count": {"type": "integer"}}});
        let widen = json!({"properties": {"count": {"type": ["integer","string"]}}});
        assert!(compare_schemas(&single, &widen).is_empty());
    }

    /// FIELD_FORMAT_CHANGED：format 变更 / 删除 red；新增 format green。
    #[test]
    fn field_format_changed_red_and_green() {
        let old = json!({"properties": {"ts": {"type":"string","format":"date"}}});
        let changed = json!({"properties": {"ts": {"type":"string","format":"date-time"}}});
        assert_eq!(
            rules(&compare_schemas(&old, &changed)),
            vec![BreakingRule::FieldFormatChanged]
        );
        let removed = json!({"properties": {"ts": {"type":"string"}}});
        assert_eq!(
            rules(&compare_schemas(&old, &removed)),
            vec![BreakingRule::FieldFormatChanged]
        );

        // green：从无 format 加 format（向前兼容）不报。
        let no_fmt = json!({"properties": {"ts": {"type":"string"}}});
        let add_fmt = json!({"properties": {"ts": {"type":"string","format":"date"}}});
        assert!(compare_schemas(&no_fmt, &add_fmt).is_empty());
    }

    /// ENUM_VALUE_DELETED：删 enum 值 red；新增 enum 值 green。
    #[test]
    fn enum_value_deleted_red_and_green() {
        let old = json!({"properties": {"state": {"enum": ["a","b","c"]}}});
        let del = json!({"properties": {"state": {"enum": ["a","b"]}}});
        assert_eq!(
            rules(&compare_schemas(&old, &del)),
            vec![BreakingRule::EnumValueDeleted]
        );

        // green：新增 enum 值不报。
        let add = json!({"properties": {"state": {"enum": ["a","b","c","d"]}}});
        assert!(compare_schemas(&old, &add).is_empty());

        // green 边界：enum 整体删除（new 无 enum）= 放宽（接受更多值），不报。
        let no_enum = json!({"properties": {"state": {"type": "string"}}});
        assert!(compare_schemas(&old, &no_enum).is_empty());
    }

    /// ADDITIONAL_PROPS_TIGHTENED：true→false red；false→true（放宽）green；缺省→false red。
    #[test]
    fn additional_props_tightened_red_and_green() {
        let old = json!({"type":"object","additionalProperties": true});
        let new = json!({"type":"object","additionalProperties": false});
        assert_eq!(
            rules(&compare_schemas(&old, &new)),
            vec![BreakingRule::AdditionalPropsTightened]
        );

        // green：false→true 放宽不报。
        assert!(compare_schemas(&new, &old).is_empty());

        // red：缺省（宽松默认）→ false。
        let absent = json!({"type":"object"});
        let to_false = json!({"type":"object","additionalProperties": false});
        assert_eq!(
            rules(&compare_schemas(&absent, &to_false)),
            vec![BreakingRule::AdditionalPropsTightened]
        );
    }

    /// NULLABLE_REMOVED：[T,null]→T red（且不重复报 FIELD_TYPE_CHANGED）；T→[T,null] green。
    #[test]
    fn nullable_removed_red_and_green() {
        let old = json!({"properties": {"mid": {"type": ["string","null"]}}});
        let new = json!({"properties": {"mid": {"type": "string"}}});
        // 仅 NULLABLE_REMOVED——非 null 类型集 {string} 不变，不触 FIELD_TYPE_CHANGED。
        assert_eq!(
            rules(&compare_schemas(&old, &new)),
            vec![BreakingRule::NullableRemoved]
        );

        // green：T→[T,null] 加 null 向前兼容不报。
        assert!(compare_schemas(&new, &old).is_empty());
    }

    /// nullable + 类型同时变：[string,null]→integer 同报 NULLABLE_REMOVED + FIELD_TYPE_CHANGED（两个真实破坏）。
    #[test]
    fn nullable_and_type_both_change() {
        let old = json!({"properties": {"x": {"type": ["string","null"]}}});
        let new = json!({"properties": {"x": {"type": "integer"}}});
        let mut got = rules(&compare_schemas(&old, &new));
        got.sort_by_key(|r| r.id());
        assert_eq!(
            got,
            vec![
                BreakingRule::FieldTypeChanged,
                BreakingRule::NullableRemoved
            ]
        );
    }

    /// 嵌套对象 properties 递归：内层字段删除被捕获。
    #[test]
    fn nested_properties_recurse() {
        let old = json!({"properties": {"user": {"type":"object","properties": {"name": {"type":"string"}, "age": {"type":"integer"}}}}});
        let new = json!({"properties": {"user": {"type":"object","properties": {"name": {"type":"string"}}}}});
        let breaks = compare_schemas(&old, &new);
        assert_eq!(rules(&breaks), vec![BreakingRule::FieldNoDelete]);
        assert_eq!(breaks[0].pointer, "user.age");
    }

    /// C2：递归数组元素 schema `items`——列表元素字段删除被捕获，路径 `data[]`。
    #[test]
    fn array_items_recurse() {
        let old = json!({"properties": {"data": {"type":"array","items": {"type":"object","properties": {"a": {"type":"string"}, "b": {"type":"string"}}}}}});
        let new = json!({"properties": {"data": {"type":"array","items": {"type":"object","properties": {"a": {"type":"string"}}}}}});
        let breaks = compare_schemas(&old, &new);
        assert_eq!(rules(&breaks), vec![BreakingRule::FieldNoDelete]);
        assert_eq!(breaks[0].pointer, "data[].b");
    }

    /// REDACTION_POLICY_CHANGED：既有字段的隐私语义变更须被捕获；新增字段策略不报。
    #[test]
    fn redaction_policy_changed_red_and_green() {
        let old = json!({"properties": {"subject": {"type":"string","x-pii":"generic"}}});
        let changed = json!({"properties": {"subject": {"type":"string","x-redaction":"public"}}});
        let breaks = compare_schemas(&old, &changed);
        assert_eq!(rules(&breaks), vec![BreakingRule::RedactionPolicyChanged]);
        assert_eq!(breaks[0].pointer, "subject");

        let add = json!({
            "properties": {
                "subject": {"type":"string","x-pii":"generic"},
                "actor": {"type":"string","x-pii":"generic"}
            }
        });
        assert!(compare_schemas(&old, &add).is_empty());
    }

    #[test]
    fn redaction_policy_changed_recurses_schema_containers() {
        let cases = [
            (
                "$defs.secret",
                json!({"$defs":{"secret":{"type":"string","x-redaction":"secret"}}}),
                json!({"$defs":{"secret":{"type":"string","x-redaction":"internal"}}}),
            ),
            (
                "choice[0].token",
                json!({"properties":{"choice":{"oneOf":[{"type":"object","properties":{"token":{"type":"string","x-redaction":"secret"}}}]}}}),
                json!({"properties":{"choice":{"oneOf":[{"type":"object","properties":{"token":{"type":"string","x-redaction":"internal"}}}]}}}),
            ),
            (
                "metadata{}",
                json!({"properties":{"metadata":{"type":"object","additionalProperties":{"type":"string","x-redaction":"secret"}}}}),
                json!({"properties":{"metadata":{"type":"object","additionalProperties":{"type":"string","x-redaction":"internal"}}}}),
            ),
        ];

        for (want_pointer, old, new) in cases {
            let breaks = compare_schemas(&old, &new);
            assert!(
                breaks.iter().any(|b| {
                    b.rule == BreakingRule::RedactionPolicyChanged && b.pointer == want_pointer
                }),
                "redaction policy drift under {want_pointer} should be reported: {breaks:?}"
            );
        }
    }

    /// PROTECTION_POLICY_CHANGED：既有字段 `x-protection` 漂移报破坏；纯新增字段不报（细粒度语义在
    /// `protection.rs` 单测，此处验装配进 `compare_schemas`）。
    #[test]
    fn protection_policy_changed_reports_drift() {
        let old = json!({"properties": {"v": {"type":"string","x-protection":{"atRest":"plain"}}}});
        let changed = json!({"properties": {"v": {"type":"string","x-protection":{"atRest":"encrypt","keyScope":"tenant","aad":["tenant","field","schemaVersion"]}}}});
        let breaks = compare_schemas(&old, &changed);
        assert_eq!(rules(&breaks), vec![BreakingRule::ProtectionPolicyChanged]);
        assert_eq!(breaks[0].pointer, "v");

        let add = json!({
            "properties": {
                "v": {"type":"string","x-protection":{"atRest":"plain"}},
                "w": {"type":"string"}
            }
        });
        assert!(compare_schemas(&old, &add).is_empty());
    }

    /// PROTECTION_POLICY_CHANGED id 稳定（输出行 + 断言单源）。
    #[test]
    fn protection_policy_changed_id_stable() {
        assert_eq!(
            BreakingRule::ProtectionPolicyChanged.id(),
            "PROTECTION_POLICY_CHANGED"
        );
    }

    /// 既有字段首次获得 x-protection（旧无→新有）亦是保护策略漂移（审查材料）。
    #[test]
    fn protection_policy_changed_detects_first_time_declaration() {
        let old = json!({"properties": {"v": {"type": "string"}}});
        let new =
            json!({"properties": {"v": {"type": "string", "x-protection": {"atRest": "plain"}}}});
        let breaks = compare_schemas(&old, &new);
        assert_eq!(rules(&breaks), vec![BreakingRule::ProtectionPolicyChanged]);
        assert_eq!(breaks[0].pointer, "v");
    }

    /// root 级 x-at-rest 翻转（撤销 schema 持久化 opt-in）经 compare_schemas 汇合到 PROTECTION_POLICY_CHANGED。
    #[test]
    fn protection_policy_changed_from_root_at_rest_flip() {
        let old = json!({"title": "T", "x-at-rest": true, "properties": {"v": {"type": "string"}}});
        let new =
            json!({"title": "T", "x-at-rest": false, "properties": {"v": {"type": "string"}}});
        let breaks = compare_schemas(&old, &new);
        assert!(
            breaks
                .iter()
                .any(|b| b.rule == BreakingRule::ProtectionPolicyChanged),
            "{breaks:?}"
        );
    }

    /// C3：JSON Schema 类型包含关系——`integer → number`（放宽）green；`number → integer`（收紧）red。
    #[test]
    fn integer_number_type_lattice() {
        let int_to_num = compare_schemas(
            &json!({"properties": {"n": {"type": "integer"}}}),
            &json!({"properties": {"n": {"type": "number"}}}),
        );
        assert!(
            int_to_num.is_empty(),
            "integer→number 是放宽，不应报破坏: {int_to_num:?}"
        );

        let num_to_int = compare_schemas(
            &json!({"properties": {"n": {"type": "number"}}}),
            &json!({"properties": {"n": {"type": "integer"}}}),
        );
        assert_eq!(rules(&num_to_int), vec![BreakingRule::FieldTypeChanged]);
    }

    /// type_accepted 纯判定：直接包含、integer⊆number、跨类不接受。
    #[rstest]
    #[case("integer", &["integer"], true)]
    #[case("integer", &["number"], true)]
    #[case("number", &["integer"], false)]
    #[case("string", &["integer"], false)]
    #[case("string", &["string", "null"], true)]
    fn type_accepted_cases(#[case] old: &str, #[case] new: &[&str], #[case] want: bool) {
        let set: BTreeSet<&str> = new.iter().copied().collect();
        assert_eq!(type_accepted(old, &set), want);
    }

    /// anti-vacuity green：identical schema / 纯新增可选字段 → 零 finding（守卫非恒真——它真会沉默）。
    #[test]
    fn anti_vacuity_additive_only_is_clean() {
        let s = json!({
            "type":"object",
            "properties": {"a": {"type":"string"}},
            "required": ["a"],
            "additionalProperties": false
        });
        assert!(compare_schemas(&s, &s).is_empty());

        // 新增可选字段 b（不进 required）。
        let added = json!({
            "type":"object",
            "properties": {"a": {"type":"string"}, "b": {"type":"integer"}},
            "required": ["a"],
            "additionalProperties": false
        });
        assert!(compare_schemas(&s, &added).is_empty());
    }

    // ─────────── disposition 真值表 ───────────

    #[rstest]
    #[case(Lifecycle::Active, Disposition::Deny)]
    #[case(Lifecycle::Deprecated, Disposition::Warn)]
    #[case(Lifecycle::Draft, Disposition::Warn)]
    fn disposition_truth_table(#[case] lifecycle: Lifecycle, #[case] want: Disposition) {
        assert_eq!(disposition(lifecycle), want);
    }

    // ─────────── evaluate seam（含「≥1 active 契约破坏」防恒真 + draft 跳过）───────────

    fn diff(label: &str, lifecycle: Lifecycle, old: Value, new: Value) -> ContractDiff {
        ContractDiff {
            label: label.to_string(),
            lifecycle,
            working_lifecycle: Some(lifecycle),
            schemas: vec![SchemaVersions {
                file: "request.schema.json".to_string(),
                direction: SchemaDirection::Input,
                removed: false,
                old: Some(old),
                new,
            }],
            manifest: ManifestVersions {
                old: None,
                new: None,
            },
            removed: false,
        }
    }

    /// ADR §3.2 防恒真：active 契约删字段恒置 any_deny=true（gate 真会拦截）。
    #[test]
    fn active_breaking_is_deny() {
        let c = diff(
            "http/identity/v1",
            Lifecycle::Active,
            json!({"properties": {"id": {"type":"string"}, "name": {"type":"string"}}}),
            json!({"properties": {"id": {"type":"string"}}}),
        );
        let r = evaluate(&[c]);
        assert!(r.any_deny, "active 破坏须恒为 Deny");
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].disposition, Disposition::Deny);
    }

    /// draft 跳过 red：draft 契约删字段 → 零 finding。
    #[test]
    fn draft_breaking_is_skipped() {
        let c = diff(
            "http/_seed/v1",
            Lifecycle::Draft,
            json!({"properties": {"id": {"type":"string"}, "name": {"type":"string"}}}),
            json!({"properties": {"id": {"type":"string"}}}),
        );
        let r = evaluate(&[c]);
        assert!(r.findings.is_empty(), "draft 契约应整体跳过");
        assert!(!r.any_deny);
    }

    /// deprecated 破坏恒 warn（退出码 0）。
    #[test]
    fn deprecated_breaking_is_warn_only() {
        let c = diff(
            "http/legacy/v1",
            Lifecycle::Deprecated,
            json!({"properties": {"id": {"type":"string"}, "name": {"type":"string"}}}),
            json!({"properties": {"id": {"type":"string"}}}),
        );
        let r = evaluate(&[c]);
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].disposition, Disposition::Warn);
        assert!(!r.any_deny);
    }

    /// base 无该 schema（old=None）= 新契约 → 不报。
    #[test]
    fn new_schema_no_base_is_skipped() {
        let c = ContractDiff {
            label: "http/identity/v2".to_string(),
            lifecycle: Lifecycle::Active,
            working_lifecycle: Some(Lifecycle::Active),
            schemas: vec![SchemaVersions {
                file: "request.schema.json".to_string(),
                direction: SchemaDirection::Input,
                removed: false,
                old: None,
                new: json!({"properties": {"id": {"type":"string"}}}),
            }],
            manifest: ManifestVersions {
                old: None,
                new: None,
            },
            removed: false,
        };
        let r = evaluate(&[c]);
        assert!(r.findings.is_empty());
        assert!(!r.any_deny);
    }

    // ─────────── C1：base ∪ working 并集（删除类破坏不漏检）───────────

    fn side(label: &str, lifecycle: Lifecycle, slots: &[(&str, Value)]) -> ContractSide {
        side_with_identity(label, label, lifecycle, slots)
    }

    fn side_with_identity(
        identity: &str,
        label: &str,
        lifecycle: Lifecycle,
        slots: &[(&str, Value)],
    ) -> ContractSide {
        let version = label
            .split('/')
            .find(|segment| segment.starts_with('v'))
            .unwrap_or("v1");
        ContractSide {
            identity: ContractIdentity {
                id: identity.to_string(),
                version: version.to_string(),
            },
            label: label.to_string(),
            lifecycle,
            slots: slots
                .iter()
                .map(|(k, v)| {
                    let direction = if *k == "response" || k.starts_with("saga:") {
                        SchemaDirection::Output
                    } else {
                        SchemaDirection::Input
                    };
                    ((*k).to_string(), (direction, v.clone()))
                })
                .collect(),
            manifest: ManifestProjection::default(),
        }
    }

    #[test]
    fn base_manifest_label_accepts_flat_and_nested_paths() {
        assert_eq!(
            label_from_manifest_path("contracts/http/identity/v1/contract.toml"),
            Some("http/identity/v1".to_string())
        );
        assert_eq!(
            label_from_manifest_path("contracts/http/identity/v1/roles-revoke/contract.toml"),
            Some("http/identity/v1/roles-revoke".to_string())
        );
        assert_eq!(
            label_from_manifest_path("contracts/http/identity/v1/a/b/contract.toml"),
            None,
            "五段嵌套不是合法 contract path"
        );
    }

    #[test]
    fn base_manifest_projection_accepts_legacy_authoring_shape() -> anyhow::Result<()> {
        let manifest: BaseContractManifest = toml::from_str(
            r#"
id = "identity.logout"
kind = "http"
domain = "identity"
version = "v1"
owner = "identity"
consistencyLevel = "LocalTx"
lifecycle = "active"

[capabilities.localTx]
boundary = "single-domain"

[schemas]
request = "request.schema.json"
response = "response.schema.json"
"#,
        )?;
        assert_eq!(manifest.id, "identity.logout");
        assert_eq!(manifest.lifecycle, Lifecycle::Active);
        assert_eq!(
            base_slot_files(&manifest),
            vec![
                (
                    "request".to_string(),
                    "request.schema.json".to_string(),
                    SchemaDirection::Input
                ),
                (
                    "response".to_string(),
                    "response.schema.json".to_string(),
                    SchemaDirection::Output
                ),
            ]
        );
        let saga: BaseContractManifest = toml::from_str(
            r#"
id = "billing.checkout"
kind = "saga"
domain = "billing"
version = "v1"
owner = "billing"
consistencyLevel = "WorkflowEventual"
lifecycle = "draft"

[schemas]
payload = "payload.schema.json"

[saga]
compensationOrder = "reverse"
retryMillis = 5000
timeoutMillis = 30000
steps = [
    { name = "reserve_funds", outputSchema = "reserve.schema.json" },
    { name = "capture", outputSchema = "capture.schema.json" },
]
"#,
        )?;
        assert_eq!(
            base_slot_files(&saga),
            vec![
                (
                    "payload".to_string(),
                    "payload.schema.json".to_string(),
                    SchemaDirection::Input
                ),
                (
                    "saga:reserve_funds".to_string(),
                    "reserve.schema.json".to_string(),
                    SchemaDirection::Output
                ),
                (
                    "saga:capture".to_string(),
                    "capture.schema.json".to_string(),
                    SchemaDirection::Output
                ),
            ]
        );
        Ok(())
    }

    #[test]
    fn working_manifest_label_includes_nested_slug() -> anyhow::Result<()> {
        let manifest = ContractManifest::from_toml_str(
            r#"
id = "identity.roles-revoke"
kind = "http"
domain = "identity"
version = "v1"
owner = "identity"
consistencyLevel = "LocalOnly"
lifecycle = "active"
"#,
        )?;
        let c = super::super::DiscoveredContract {
            dir: std::path::PathBuf::from("contracts/http/identity/v1/roles-revoke"),
            path_kind: "http".to_string(),
            path_domain: "identity".to_string(),
            path_version: "v1".to_string(),
            slug: Some("roles-revoke".to_string()),
            manifest,
        };
        assert_eq!(contract_label(&c), "http/identity/v1/roles-revoke");
        Ok(())
    }

    #[test]
    fn nested_identity_v1_siblings_do_not_collapse_to_three_segment_label() -> anyhow::Result<()> {
        let slugs = [
            "login",
            "refresh",
            "roles-assign",
            "roles-revoke",
            "roles-list",
            "profile",
            "password-change",
            "logout",
        ];
        let base: Vec<_> = slugs
            .iter()
            .map(|slug| {
                side(
                    &format!("http/identity/v1/{slug}"),
                    Lifecycle::Active,
                    &[(
                        "response",
                        json!({"properties": {"data": {"type": "object"}}}),
                    )],
                )
            })
            .collect();
        let working = base.clone();

        let diffs = plan_diffs(&base, &working)?;
        let labels: BTreeSet<&str> = diffs.iter().map(|d| d.label.as_str()).collect();
        assert_eq!(diffs.len(), 8, "8 个 sibling 必须逐个参与 breaking diff");
        assert_eq!(
            labels.len(),
            8,
            "nested sibling label 不能折叠成单个 http/identity/v1"
        );
        assert!(labels.contains("http/identity/v1/roles-revoke"));
        Ok(())
    }

    #[test]
    fn flat_to_nested_same_contract_id_is_not_treated_as_delete_and_add() -> anyhow::Result<()> {
        let schema = json!({"properties": {"username": {"type":"string"}}});
        let base = vec![side_with_identity(
            "identity.login",
            "http/identity/v1",
            Lifecycle::Active,
            &[("request", schema.clone())],
        )];
        let working = vec![side_with_identity(
            "identity.login",
            "http/identity/v1/login",
            Lifecycle::Active,
            &[("request", schema)],
        )];

        let diffs = plan_diffs(&base, &working)?;
        let r = evaluate(&diffs);
        assert!(
            r.findings.is_empty(),
            "flat -> nested path migration must not look like a contract deletion: {:?}",
            r.findings
        );
        assert!(!r.any_deny);
        Ok(())
    }

    #[test]
    fn same_id_moved_to_new_version_does_not_replace_old_identity() -> anyhow::Result<()> {
        let schema = json!({"properties": {"id": {"type":"string"}}});
        let base = vec![side_with_identity(
            "identity.profile",
            "http/identity/v1/profile",
            Lifecycle::Active,
            &[("response", schema.clone())],
        )];
        let working = vec![side_with_identity(
            "identity.profile",
            "http/identity/v2/profile",
            Lifecycle::Active,
            &[("response", schema)],
        )];

        let result = evaluate(&plan_diffs(&base, &working)?);
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.rule == BreakingRule::ContractRemoved),
            "moving the same id from v1 to v2 must report deletion of the v1 identity: {:?}",
            result.findings
        );
        Ok(())
    }

    /// 删除整个 active 契约（base 有、working 无）→ base 各字段报 FIELD_NO_DELETE（经 plan_diffs empty-new）。
    #[test]
    fn deleted_active_contract_reports_field_deletions() -> anyhow::Result<()> {
        let base = vec![side(
            "http/x/v1",
            Lifecycle::Active,
            &[(
                "request",
                json!({"properties": {"id": {"type":"string"}, "name": {"type":"string"}}}),
            )],
        )];
        let diffs = plan_diffs(&base, &[])?;
        let r = evaluate(&diffs);
        assert_eq!(
            r.findings.len(),
            3,
            "删契约应报显式删除 + 两字段删除: {:?}",
            r.findings
        );
        assert!(
            r.findings
                .iter()
                .any(|f| f.rule == BreakingRule::ContractRemoved)
        );
        assert!(r.any_deny);
        Ok(())
    }

    /// 删除一个 schema slot（base 有 response、working 无）→ 该 slot base 字段报删除。
    #[test]
    fn removed_schema_slot_reports_deletions() -> anyhow::Result<()> {
        let base = vec![side(
            "http/x/v1",
            Lifecycle::Active,
            &[
                ("request", json!({"properties": {"id": {"type":"string"}}})),
                (
                    "response",
                    json!({"properties": {"ok": {"type":"boolean"}}}),
                ),
            ],
        )];
        let working = vec![side(
            "http/x/v1",
            Lifecycle::Active,
            &[("request", json!({"properties": {"id": {"type":"string"}}}))],
        )];
        let diffs = plan_diffs(&base, &working)?;
        let r = evaluate(&diffs);
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].rule, BreakingRule::FieldNoDelete);
        assert!(r.findings[0].subject.contains("response"));
        Ok(())
    }

    /// slot 改名（文件名变、slot 不变）按内容比对——丢字段才报，文件名变化本身不报。
    #[test]
    fn renamed_slot_compares_by_content() -> anyhow::Result<()> {
        // 两侧同 slot "request"，working 丢了 name 字段（文件名是否改无关）。
        let base = vec![side(
            "http/x/v1",
            Lifecycle::Active,
            &[(
                "request",
                json!({"properties": {"id": {"type":"string"}, "name": {"type":"string"}}}),
            )],
        )];
        let working = vec![side(
            "http/x/v1",
            Lifecycle::Active,
            &[("request", json!({"properties": {"id": {"type":"string"}}}))],
        )];
        let diffs = plan_diffs(&base, &working)?;
        let r = evaluate(&diffs);
        assert_eq!(rules_of(&r), vec![BreakingRule::FieldNoDelete]);
        Ok(())
    }

    /// 新契约（working 有、base 无）→ old=None → 不报（向后兼容）。
    #[test]
    fn new_contract_not_reported_via_plan() -> anyhow::Result<()> {
        let working = vec![side(
            "http/x/v2",
            Lifecycle::Active,
            &[("request", json!({"properties": {"id": {"type":"string"}}}))],
        )];
        let diffs = plan_diffs(&[], &working)?;
        let r = evaluate(&diffs);
        assert!(r.findings.is_empty());
        assert!(!r.any_deny);
        Ok(())
    }

    /// 删除 draft 契约 → 跳过（lifecycle 由 base 决定，draft 豁免）。
    #[test]
    fn deleted_draft_contract_skipped_via_plan() -> anyhow::Result<()> {
        let base = vec![side(
            "http/_seed/v1",
            Lifecycle::Draft,
            &[(
                "request",
                json!({"properties": {"id": {"type":"string"}, "name": {"type":"string"}}}),
            )],
        )];
        let diffs = plan_diffs(&base, &[])?;
        let r = evaluate(&diffs);
        assert!(r.findings.is_empty(), "draft 删契约应跳过");
        Ok(())
    }

    fn rules_of(r: &EvalResult) -> Vec<BreakingRule> {
        r.findings.iter().map(|f| f.rule).collect()
    }

    // ─────────── fail-closed：base ref / Git 命令诊断（B-F1）───────────

    /// fetch_hint：含 `/` 的 ref → `git fetch <remote> <branch>`；无 `/` → 裸 `git fetch`。
    #[rstest]
    #[case("origin/develop", "git fetch origin develop")]
    #[case("upstream/main", "git fetch upstream main")]
    #[case("HEAD~1", "git fetch")]
    fn fetch_hint_cases(#[case] against: &str, #[case] want: &str) {
        assert_eq!(fetch_hint(against), want);
    }

    /// base ref 不可解析恒 fail-closed。
    #[test]
    fn unresolved_ref_fails_closed() {
        const BOGUS: &str = "zzz-rss-wire-breaking-bogus-ref-xyz";
        assert!(run(BOGUS).is_err());
    }

    #[test]
    fn git_absence_is_distinct_from_command_failure() -> anyhow::Result<()> {
        let root = crate::testutil::unique_tmp("breaking-repo");
        std::fs::create_dir_all(&root)?;
        let run_git = |args: &[&str]| -> anyhow::Result<()> {
            let output = crate::cmd::external_cmd(
                crate::cmd::ExternalProgram::SystemGit,
                args,
                &[],
                Some(&root),
            )
            .output()?;
            anyhow::ensure!(
                output.status.success(),
                "git test setup failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            Ok(())
        };
        run_git(&["init", "--quiet"])?;
        std::fs::write(root.join("contract.toml"), "id = \"seed.test\"\n")?;
        run_git(&["add", "contract.toml"])?;
        run_git(&[
            "-c",
            "user.name=RSS Test",
            "-c",
            "user.email=rss-test@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "fixture",
        ])?;
        let GitRead::Found(text) = read_text_at_ref(&root, "HEAD", "contract.toml") else {
            anyhow::bail!("committed path must be found")
        };
        assert!(text.contains("seed.test"));
        assert!(matches!(
            read_text_at_ref(&root, "HEAD", "contracts/definitely-absent.toml"),
            GitRead::Missing
        ));

        let not_a_repo = crate::testutil::unique_tmp("breaking-not-repo");
        std::fs::create_dir_all(&not_a_repo)?;
        let failure = read_text_at_ref(&not_a_repo, "HEAD", "contract.toml");
        let GitRead::CommandFailed(failure) = failure else {
            anyhow::bail!("not-a-repository must be a command failure")
        };
        assert!(failure.status.is_some());
        assert!(failure.stderr.contains("repository"));

        assert!(matches!(
            read_ref(&root, "zzz-rss-wire-breaking-bogus-ref-xyz"),
            GitRead::Missing
        ));
        assert!(matches!(
            read_ref(&not_a_repo, "HEAD"),
            GitRead::CommandFailed(_)
        ));
        let ls_tree_error =
            match base_contract_manifests(&root, "zzz-rss-wire-breaking-bogus-ref-xyz") {
                Ok(_) => anyhow::bail!("invalid ref must fail"),
                Err(error) => error.to_string(),
            };
        assert!(ls_tree_error.contains("status="));
        assert!(ls_tree_error.contains("stderr="));
        std::fs::remove_dir_all(not_a_repo)?;
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    fn full_projection() -> ManifestProjection {
        ManifestProjection {
            http: Some(HttpWireProjection {
                path: Some("/api/v1/identity/profile".into()),
                method: Some("GET".into()),
                success_status: Some(200),
                auth: Some(AuthProjection {
                    mode: "permission".into(),
                    permission: Some("identity:read".into()),
                }),
                auth_scope: AuthScopeProjection {
                    resource: None,
                    self_scoped: true,
                },
                resource_sharing: "tenantScoped".into(),
                idempotency: Some("idempotent".into()),
            }),
            topic: Some("identity.session-created.v1".into()),
            delivery: Some("at-least-once".into()),
            consistency: Some("OutboxFact".into()),
            effects: BTreeSet::from([EffectIdentity::Auth, EffectIdentity::Read]),
            outbox: Some(OutboxProjection {
                role: "producer".into(),
                atomicity: Some("same-transaction".into()),
                emits: BTreeSet::from(["identity.session-created.v1".into()]),
            }),
            subscriptions: BTreeSet::from([SubscriptionProjection {
                consumer: "audit".into(),
                group: "audit.sessions".into(),
                partition: "aggregate".into(),
                readiness: "required".into(),
                execution: Some("adapter-native".into()),
                effect: None,
                external_effect_policy: "transactional-only".into(),
            }]),
        }
    }

    fn manifest_diff(
        lifecycle: Lifecycle,
        old: ManifestProjection,
        new: ManifestProjection,
    ) -> ContractDiff {
        ContractDiff {
            label: "http/identity/v1".to_string(),
            lifecycle,
            working_lifecycle: Some(lifecycle),
            schemas: Vec::new(),
            manifest: ManifestVersions {
                old: Some(old),
                new: Some(new),
            },
            removed: false,
        }
    }

    #[test]
    fn local_only_boundary_is_review_only_but_non_l0_drift_is_denied() {
        for non_l0 in ["LocalTx", "OutboxFact", "WorkflowEventual", "DeviceLatent"] {
            for (old_level, new_level) in [("LocalOnly", non_l0), (non_l0, "LocalOnly")] {
                for lifecycle in [Lifecycle::Active, Lifecycle::Deprecated] {
                    let mut old = full_projection();
                    old.consistency = Some(old_level.to_string());
                    let mut new = old.clone();
                    new.consistency = Some(new_level.to_string());
                    let result = evaluate(&[manifest_diff(lifecycle, old, new)]);
                    assert_eq!(result.findings.len(), 1);
                    assert_eq!(
                        result.findings[0].rule,
                        BreakingRule::LocalOnlyBoundaryChanged
                    );
                    assert_eq!(result.findings[0].disposition, Disposition::Warn);
                    assert!(!result.any_deny);
                }
            }
        }

        let mut draft_old = full_projection();
        draft_old.consistency = Some("LocalOnly".to_string());
        let mut draft_new = draft_old.clone();
        draft_new.consistency = Some("LocalTx".to_string());
        assert!(
            evaluate(&[manifest_diff(Lifecycle::Draft, draft_old, draft_new)])
                .findings
                .is_empty()
        );

        let mut old = full_projection();
        old.consistency = Some("LocalTx".to_string());
        let mut new = old.clone();
        new.consistency = Some("OutboxFact".to_string());
        let result = evaluate(&[manifest_diff(Lifecycle::Active, old, new)]);
        assert_eq!(
            result.findings[0].rule,
            BreakingRule::ConsistencyLevelChanged
        );
        assert_eq!(result.findings[0].disposition, Disposition::Deny);
        assert!(result.any_deny);
    }

    #[test]
    fn effect_set_diff_is_review_only_deterministic_and_lifecycle_aware() {
        let old = full_projection();
        let mut new = old.clone();
        new.effects = BTreeSet::from([EffectIdentity::Projection, EffectIdentity::BusinessWrite]);

        for lifecycle in [Lifecycle::Active, Lifecycle::Deprecated] {
            let result = evaluate(&[manifest_diff(lifecycle, old.clone(), new.clone())]);
            assert_eq!(
                result
                    .findings
                    .iter()
                    .map(|finding| (finding.rule, finding.detail.as_str()))
                    .collect::<Vec<_>>(),
                vec![
                    (BreakingRule::EffectRemoved, "HTTP effect `read` 被移除"),
                    (BreakingRule::EffectRemoved, "HTTP effect `auth` 被移除"),
                    (BreakingRule::EffectAdded, "HTTP effect `projection` 被新增"),
                    (
                        BreakingRule::EffectAdded,
                        "HTTP effect `business-write` 被新增",
                    ),
                ]
            );
            assert!(
                result
                    .findings
                    .iter()
                    .all(|finding| finding.disposition == Disposition::Warn)
            );
            assert!(!result.any_deny);
        }

        assert!(
            evaluate(&[manifest_diff(Lifecycle::Draft, old, new)])
                .findings
                .is_empty()
        );
    }

    #[test]
    fn effect_reorder_is_clean() {
        let mut old = full_projection();
        old.effects = [
            EffectIdentity::BusinessWrite,
            EffectIdentity::Read,
            EffectIdentity::Auth,
        ]
        .into_iter()
        .collect();
        let mut new = old.clone();
        new.effects = [
            EffectIdentity::Auth,
            EffectIdentity::BusinessWrite,
            EffectIdentity::Read,
        ]
        .into_iter()
        .collect();
        assert!(compare_manifests(&old, &new).is_empty());
    }

    #[test]
    fn review_ack_fingerprint_is_deterministic_and_change_sensitive() {
        let finding = |detail: &str| GradedFinding {
            lifecycle: Lifecycle::Active,
            disposition: Disposition::Warn,
            rule: BreakingRule::EffectAdded,
            subject: "http/identity/v1 manifest (effectProfile.effects)".to_string(),
            detail: detail.to_string(),
        };
        let first =
            review_ack_fingerprint("base-oid", &[finding("business-write"), finding("publish")]);
        let reordered =
            review_ack_fingerprint("base-oid", &[finding("publish"), finding("business-write")]);
        assert_eq!(first, reordered);
        assert_ne!(
            first,
            review_ack_fingerprint(
                "other-base",
                &[finding("business-write"), finding("publish")]
            )
        );
        assert_ne!(
            first,
            review_ack_fingerprint("base-oid", &[finding("outbox"), finding("publish")])
        );
    }

    #[test]
    fn review_ack_requires_an_exact_commit_trailer() -> anyhow::Result<()> {
        let expected = "Contract-Review-Ack: sha256:abc123";
        assert!(!commit_messages_contain_review_ack("", expected));
        assert!(commit_messages_contain_review_ack(
            "subject\n\nContract-Review-Ack: sha256:abc123\n\0",
            expected
        ));
        assert!(!commit_messages_contain_review_ack(
            "subject\n\nContract-Review-Ack: sha256:abc12\n\0",
            expected
        ));
        assert!(!commit_messages_contain_review_ack(
            "subject\n\nnot Contract-Review-Ack: sha256:abc123 suffix\n\0",
            expected
        ));

        let findings = [GradedFinding {
            lifecycle: Lifecycle::Active,
            disposition: Disposition::Warn,
            rule: BreakingRule::EffectAdded,
            subject: "http/identity/v1 manifest (effectProfile.effects)".to_string(),
            detail: "HTTP effect `business-write` 被新增".to_string(),
        }];
        assert!(verify_review_ack("base-oid", &findings, "").is_err());
        assert!(
            verify_review_ack("base-oid", &findings, "Contract-Review-Ack: sha256:wrong").is_err()
        );
        let fingerprint = review_ack_fingerprint("base-oid", &findings);
        verify_review_ack(
            "base-oid",
            &findings,
            &format!("subject\n\n{REVIEW_ACK_PREFIX}{fingerprint}\n"),
        )?;
        Ok(())
    }

    #[test]
    fn breaking_authorization_is_exact_and_domain_separated() -> anyhow::Result<()> {
        let findings = [GradedFinding {
            lifecycle: Lifecycle::Active,
            disposition: Disposition::Deny,
            rule: BreakingRule::FieldNoDelete,
            subject: "http/identity/v1 request (sessionId)".to_string(),
            detail: "字段被删除".to_string(),
        }];
        let fingerprint = breaking_authorization_fingerprint("base-oid", &findings);
        assert_ne!(fingerprint, review_ack_fingerprint("base-oid", &findings));
        assert!(verify_breaking_authorization("base-oid", &findings, "").is_err());
        assert!(
            verify_breaking_authorization(
                "base-oid",
                &findings,
                "Contract-Breaking-Authorization: sha256:wrong",
            )
            .is_err()
        );
        verify_breaking_authorization(
            "base-oid",
            &findings,
            &format!("subject\n\n{BREAKING_AUTHORIZATION_PREFIX}{fingerprint}\n"),
        )?;
        assert!(
            verify_breaking_authorization(
                "other-base",
                &findings,
                &format!("{BREAKING_AUTHORIZATION_PREFIX}{fingerprint}"),
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn review_acknowledgement_preserves_the_lifecycle_boundary() {
        let review_warning = |lifecycle| GradedFinding {
            lifecycle,
            disposition: Disposition::Warn,
            rule: BreakingRule::EffectAdded,
            subject: "http/identity/v1 manifest (effectProfile.effects)".to_string(),
            detail: "HTTP effect `business-write` 被新增".to_string(),
        };

        // A deprecated warning must return before touching Git. The deliberately missing
        // repository makes an accidental acknowledgement requirement fail deterministically.
        assert!(
            enforce_review_ack(
                Path::new("/definitely/missing/rss-contract-breaking-test"),
                "missing-base",
                &[review_warning(Lifecycle::Deprecated)],
            )
            .is_ok(),
            "deprecated review warnings must remain non-blocking"
        );

        assert!(
            enforce_review_ack(
                Path::new("/definitely/missing/rss-contract-breaking-test"),
                "missing-base",
                &[review_warning(Lifecycle::Active)],
            )
            .is_err(),
            "active review warnings must still enter the fail-closed acknowledgement path"
        );
    }

    #[test]
    fn effect_diff_is_not_hidden_by_missing_http_endpoint_projection() {
        let old = ManifestProjection {
            consistency: Some("LocalTx".to_string()),
            effects: BTreeSet::from([EffectIdentity::Read]),
            ..ManifestProjection::default()
        };
        let mut new = old.clone();
        new.effects = BTreeSet::from([EffectIdentity::BusinessWrite]);

        let result = evaluate(&[manifest_diff(Lifecycle::Deprecated, old, new)]);
        assert_eq!(
            rules_of(&result),
            vec![BreakingRule::EffectRemoved, BreakingRule::EffectAdded]
        );
        assert!(
            result
                .findings
                .iter()
                .all(|finding| finding.disposition == Disposition::Warn)
        );

        let non_http = ManifestProjection::default();
        assert!(compare_manifests(&non_http, &non_http).is_empty());
    }

    #[test]
    fn review_warning_does_not_mask_schema_deny() {
        let old = full_projection();
        let mut new = old.clone();
        new.effects.insert(EffectIdentity::BusinessWrite);
        let mut contract = manifest_diff(Lifecycle::Active, old, new);
        contract.schemas.push(SchemaVersions {
            file: "request".to_string(),
            direction: SchemaDirection::Input,
            removed: false,
            old: Some(json!({"properties": {"id": {"type": "string"}}})),
            new: json!({"properties": {}}),
        });

        let result = evaluate(&[contract]);
        assert_eq!(result.findings.len(), 2);
        assert!(result.findings.iter().any(|finding| {
            finding.rule == BreakingRule::EffectAdded && finding.disposition == Disposition::Warn
        }));
        assert!(result.findings.iter().any(|finding| {
            finding.rule == BreakingRule::FieldNoDelete && finding.disposition == Disposition::Deny
        }));
        assert!(result.any_deny);
    }

    #[test]
    fn http_effect_profile_projection_is_strict_on_both_sides() -> anyhow::Result<()> {
        let working = |effects: &str| {
            format!(
                r#"
id = "identity.profile"
kind = "http"
domain = "identity"
version = "v1"
owner = "identity"
consistencyLevel = "LocalOnly"
lifecycle = "active"
path = "/api/v1/identity/profile"
method = "GET"
[endpoints.http]
successStatus = 200
idempotency = "idempotent"
{effects}
"#
            )
        };
        let base = |effects: &str| {
            working(effects)
                .replace("domain = \"identity\"\n", "")
                .replace("owner = \"identity\"\n", "")
        };

        for invalid in [
            "",
            "[effectProfile]\neffects = []",
            "[effectProfile]\neffects = [\"read\", \"read\"]",
        ] {
            let current = ContractManifest::from_toml_str(&working(invalid))?;
            assert!(
                manifest_projection(&current).is_err(),
                "working accepted `{invalid}`"
            );
            let historical: BaseContractManifest = toml::from_str(&base(invalid))?;
            assert!(
                base_manifest_projection(&historical).is_err(),
                "base accepted `{invalid}`"
            );
        }

        assert!(
            toml::from_str::<BaseContractManifest>(&base(
                "[effectProfile]\neffects = [\"network\"]"
            ))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn base_effect_profile_rejects_unknown_nested_fields_but_keeps_top_level_history_tolerance()
    -> anyhow::Result<()> {
        let manifest = |nested: &str| {
            format!(
                r#"
id = "identity.profile"
kind = "http"
version = "v1"
lifecycle = "active"
historicalNote = "retained by top-level history projection"
consistencyLevel = "LocalOnly"
path = "/api/v1/identity/profile"
method = "GET"
[endpoints.http]
successStatus = 200
idempotency = "idempotent"
[effectProfile]
effects = ["read"]
{nested}
"#
            )
        };

        assert!(toml::from_str::<BaseContractManifest>(&manifest("")).is_ok());
        assert!(
            toml::from_str::<BaseContractManifest>(&manifest("legacyEffect = true")).is_err(),
            "historical effectProfile must remain fail-closed on unknown nested fields"
        );
        Ok(())
    }

    #[test]
    fn working_rejects_legacy_tokens_and_breaking_preserves_base_identity() -> anyhow::Result<()> {
        let manifest = |lifecycle: &str, effects: &str| {
            format!(
                r#"
id = "identity.profile"
kind = "http"
domain = "identity"
version = "v1"
owner = "identity"
consistencyLevel = "LocalTx"
lifecycle = "{lifecycle}"
path = "/api/v1/identity/profile"
method = "POST"
[endpoints.http]
successStatus = 200
idempotency = "idempotent"
[effectProfile]
effects = [{effects}]
"#
            )
        };

        for lifecycle in ["active", "deprecated", "draft"] {
            for legacy in ["\"write\"", "\"transaction\""] {
                assert!(
                    ContractManifest::from_toml_str(&manifest(lifecycle, legacy)).is_err(),
                    "working parser accepted `{legacy}` in lifecycle `{lifecycle}`"
                );
            }
        }

        let historical: BaseContractManifest =
            toml::from_str(&manifest("active", "\"write\", \"transaction\""))?;
        let current_base: BaseContractManifest = toml::from_str(&manifest(
            "active",
            "\"business-write\", \"business-transaction\"",
        ))?;
        let current_working = ContractManifest::from_toml_str(&manifest(
            "active",
            "\"business-write\", \"business-transaction\"",
        ))?;
        let historical_projection = base_manifest_projection(&historical)?;
        let current_projection = manifest_projection(&current_working)?;
        assert_eq!(
            base_manifest_projection(&current_base)?,
            current_projection,
            "current base spelling and strict working parser must share one identity"
        );

        let result = evaluate(&[manifest_diff(
            Lifecycle::Active,
            historical_projection,
            current_projection,
        )]);
        assert_eq!(
            result
                .findings
                .iter()
                .map(|finding| (finding.rule, finding.detail.as_str()))
                .collect::<Vec<_>>(),
            vec![
                (BreakingRule::EffectRemoved, "HTTP effect `write` 被移除"),
                (
                    BreakingRule::EffectRemoved,
                    "HTTP effect `transaction` 被移除",
                ),
                (
                    BreakingRule::EffectAdded,
                    "HTTP effect `business-write` 被新增",
                ),
                (
                    BreakingRule::EffectAdded,
                    "HTTP effect `business-transaction` 被新增",
                ),
            ],
            "authoring token rename must remain visible to the review gate"
        );
        assert!(
            verify_review_ack("base-oid", &result.findings, "").is_err(),
            "active rename findings must require an exact review acknowledgement"
        );
        Ok(())
    }

    #[test]
    fn projection_errors_identify_working_and_base_manifest_sources() -> anyhow::Result<()> {
        let root = crate::testutil::unique_tmp("breaking-projection-context");
        let contracts_root = root.join("contracts");
        let manifest_rel = "contracts/http/identity/v1/contract.toml";
        let manifest_path = root.join(manifest_rel);
        std::fs::create_dir_all(
            manifest_path
                .parent()
                .ok_or_else(|| anyhow::anyhow!("fixture manifest missing parent"))?,
        )?;
        std::fs::write(
            &manifest_path,
            r#"
id = "identity.profile"
kind = "http"
domain = "identity"
version = "v1"
owner = "identity"
consistencyLevel = "LocalTx"
lifecycle = "active"
[effectProfile]
effects = []
"#,
        )?;

        let working_error = working_sides(&contracts_root)
            .err()
            .ok_or_else(|| anyhow::anyhow!("empty working effect profile unexpectedly passed"))?
            .to_string();
        assert!(working_error.contains("working"), "{working_error}");
        assert!(
            working_error.contains(&manifest_path.display().to_string()),
            "{working_error}"
        );

        let run_git = |args: &[&str]| -> anyhow::Result<()> {
            let output = crate::cmd::external_cmd(
                crate::cmd::ExternalProgram::SystemGit,
                args,
                &[],
                Some(&root),
            )
            .output()?;
            anyhow::ensure!(
                output.status.success(),
                "git test setup failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            Ok(())
        };
        run_git(&["init", "--quiet"])?;
        run_git(&["add", manifest_rel])?;
        run_git(&[
            "-c",
            "user.name=RSS Test",
            "-c",
            "user.email=rss-test@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "fixture",
        ])?;

        let base_error = base_sides(&root, "HEAD")
            .err()
            .ok_or_else(|| anyhow::anyhow!("empty base effect profile unexpectedly passed"))?
            .to_string();
        assert!(
            base_error.contains(&format!("HEAD:{manifest_rel}")),
            "{base_error}"
        );
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    type ManifestMutation = Box<dyn Fn(&mut ManifestProjection)>;
    type SubscriptionMutation = Box<dyn Fn(&mut SubscriptionProjection)>;

    fn manifest_rules(old: &ManifestProjection, new: &ManifestProjection) -> Vec<BreakingRule> {
        compare_manifests(old, new)
            .into_iter()
            .map(|b| b.rule)
            .collect()
    }

    #[test]
    fn manifest_projection_unchanged_and_set_order_are_green() -> anyhow::Result<()> {
        let old = full_projection();
        let mut new = old.clone();
        let new_outbox = new
            .outbox
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("missing outbox fixture"))?;
        new_outbox.emits = [
            "z.topic".to_string(),
            "identity.session-created.v1".to_string(),
        ]
        .into_iter()
        .collect();
        let mut old_with_two = old;
        let old_outbox = old_with_two
            .outbox
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("missing outbox fixture"))?;
        old_outbox.emits = [
            "identity.session-created.v1".to_string(),
            "z.topic".to_string(),
        ]
        .into_iter()
        .collect();
        assert!(compare_manifests(&old_with_two, &new).is_empty());
        Ok(())
    }

    #[test]
    fn http_manifest_rules_are_non_vacuous() -> anyhow::Result<()> {
        let old = full_projection();
        let mut status = old.clone();
        status
            .http
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("missing HTTP fixture"))?
            .success_status = Some(201);
        assert_eq!(
            manifest_rules(&old, &status),
            vec![BreakingRule::HttpStatusCodeChanged]
        );

        let mut auth = old.clone();
        auth.http
            .as_mut()
            .and_then(|http| http.auth.as_mut())
            .ok_or_else(|| anyhow::anyhow!("missing auth fixture"))?
            .permission = Some("identity:write".into());
        assert_eq!(
            manifest_rules(&old, &auth),
            vec![BreakingRule::AuthRequirementChanged]
        );

        let mut idempotency = old.clone();
        idempotency
            .http
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("missing HTTP fixture"))?
            .idempotency = Some("non-idempotent".into());
        assert_eq!(
            manifest_rules(&old, &idempotency),
            vec![BreakingRule::IdempotencyLevelChanged]
        );
        Ok(())
    }

    #[test]
    fn http_route_and_authorization_scope_are_wire_identity() -> anyhow::Result<()> {
        let manifest = |path: &str,
                        method: &str,
                        resource: Option<&str>,
                        self_scoped: bool,
                        sharing: Option<(&str, &str)>| {
            let resource = resource
                .map(|value| format!("resource = \"{value}\"\n"))
                .unwrap_or_default();
            let self_scoped = if self_scoped {
                "selfScoped = true\n"
            } else {
                ""
            };
            let sharing = sharing
                .map(|(mode, reason)| {
                    format!(
                        "[endpoints.http.resourceSharing]\nmode = \"{mode}\"\nreason = \"{reason}\"\n"
                    )
                })
                .unwrap_or_default();
            format!(
                r#"
id = "identity.profile"
kind = "http"
version = "v1"
lifecycle = "active"
path = "{path}"
method = "{method}"
consistencyLevel = "LocalOnly"
[endpoints.http]
successStatus = 200
idempotency = "idempotent"
{resource}{self_scoped}[endpoints.http.auth]
mode = "permission"
permission = "identity:profile:read"
{sharing}
[effectProfile]
effects = ["read"]
"#
            )
        };
        let base: BaseContractManifest = toml::from_str(&manifest(
            "/api/v1/identity/profile",
            "GET",
            None,
            true,
            Some(("tenantScoped", "old prose")),
        ))?;
        let old = base_manifest_projection(&base)?;

        for changed in [
            manifest(
                "/api/v2/identity/profile",
                "GET",
                None,
                true,
                Some(("tenantScoped", "old prose")),
            ),
            manifest(
                "/api/v1/identity/profile",
                "POST",
                None,
                true,
                Some(("tenantScoped", "old prose")),
            ),
            manifest(
                "/api/v1/identity/profile",
                "GET",
                None,
                false,
                Some(("tenantScoped", "old prose")),
            ),
            manifest(
                "/api/v1/identity/profile",
                "GET",
                Some("subject"),
                false,
                Some(("tenantScoped", "old prose")),
            ),
            manifest(
                "/api/v1/identity/profile",
                "GET",
                None,
                true,
                Some(("global", "approved exception")),
            ),
        ] {
            let changed: BaseContractManifest = toml::from_str(&changed)?;
            assert!(
                !compare_manifests(&old, &base_manifest_projection(&changed)?).is_empty(),
                "route/scope semantic changes must be breaking"
            );
        }

        let reason_only: BaseContractManifest = toml::from_str(&manifest(
            "/api/v1/identity/profile",
            "GET",
            None,
            true,
            Some(("tenantScoped", "new prose")),
        ))?;
        assert!(
            compare_manifests(&old, &base_manifest_projection(&reason_only)?).is_empty(),
            "resourceSharing.reason is prose, not wire identity"
        );
        Ok(())
    }

    #[test]
    fn response_type_expansion_is_breaking_while_request_expansion_is_compatible() {
        let old = json!({"properties": {"n": {"type": "integer"}}});
        let new = json!({"properties": {"n": {"type": "number"}}});

        let request = diff("http/x/v1", Lifecycle::Active, old.clone(), new.clone());
        assert!(evaluate(&[request]).findings.is_empty());

        let mut response = diff("http/x/v1", Lifecycle::Active, old, new);
        response.schemas[0].file = "response".to_string();
        response.schemas[0].direction = SchemaDirection::Output;
        let result = evaluate(&[response]);
        assert!(result.any_deny, "response output expansion must be denied");
        assert_eq!(
            rules(
                &result
                    .findings
                    .iter()
                    .map(|f| RawBreak {
                        rule: f.rule,
                        pointer: String::new(),
                        detail: String::new(),
                    })
                    .collect::<Vec<_>>()
            ),
            vec![BreakingRule::FieldTypeChanged]
        );
    }

    #[test]
    fn output_variance_covers_nullable_required_enum_and_field_removal() {
        let cases = [
            (
                json!({"type": "string"}),
                json!({"type": ["string", "null"]}),
                BreakingRule::NullableAdded,
            ),
            (
                json!({"required": ["value"], "properties": {"value": {"type": "string"}}}),
                json!({"required": [], "properties": {"value": {"type": "string"}}}),
                BreakingRule::RequiredFieldRemoved,
            ),
            (
                json!({"enum": ["a"]}),
                json!({"enum": ["a", "b"]}),
                BreakingRule::EnumValueAdded,
            ),
            (
                json!({"properties": {"value": {"type": "string"}}}),
                json!({"properties": {}}),
                BreakingRule::FieldNoDelete,
            ),
        ];

        for (old, new, expected) in cases {
            let breaks = compare_schemas_for_direction(&old, &new, SchemaDirection::Output);
            assert!(
                rules(&breaks).contains(&expected),
                "output expansion/removal must report {expected:?}: {breaks:?}"
            );
            assert!(
                compare_schemas_for_direction(&new, &old, SchemaDirection::Output)
                    .iter()
                    .all(|finding| finding.rule != expected),
                "opposite output narrowing must not report {expected:?}"
            );
        }
    }

    #[test]
    fn auth_reason_is_not_part_of_wire_projection() -> anyhow::Result<()> {
        let template = |reason: &str| {
            format!(
                r#"
id = "identity.profile.v1"
kind = "http"
version = "v1"
lifecycle = "active"
consistencyLevel = "LocalOnly"
[endpoints.http]
successStatus = 200
idempotency = "idempotent"
[endpoints.http.auth]
mode = "permission"
permission = "identity:profile:read"
reason = "{reason}"
[effectProfile]
effects = ["read"]
"#
            )
        };
        let old: BaseContractManifest = toml::from_str(&template("old prose"))?;
        let new: BaseContractManifest = toml::from_str(&template("new prose"))?;
        assert!(
            compare_manifests(
                &base_manifest_projection(&old)?,
                &base_manifest_projection(&new)?
            )
            .is_empty()
        );
        Ok(())
    }

    #[test]
    fn l2_manifest_scalar_and_outbox_rules_are_non_vacuous() {
        let old = full_projection();
        let cases: Vec<(BreakingRule, ManifestMutation)> = vec![
            (
                BreakingRule::TopicChanged,
                Box::new(|p| p.topic = Some("renamed".into())),
            ),
            (
                BreakingRule::DeliveryChanged,
                Box::new(|p| p.delivery = Some("exactly-once".into())),
            ),
            (
                BreakingRule::ConsistencyLevelChanged,
                Box::new(|p| p.consistency = Some("WorkflowEventual".into())),
            ),
            (
                BreakingRule::OutboxRoleChanged,
                Box::new(|p| {
                    if let Some(outbox) = p.outbox.as_mut() {
                        outbox.role = "fact".into();
                    }
                }),
            ),
            (
                BreakingRule::OutboxAtomicityChanged,
                Box::new(|p| {
                    if let Some(outbox) = p.outbox.as_mut() {
                        outbox.atomicity = None;
                    }
                }),
            ),
            (
                BreakingRule::OutboxEmitsChanged,
                Box::new(|p| {
                    if let Some(outbox) = p.outbox.as_mut() {
                        outbox.emits.insert("new.topic".into());
                    }
                }),
            ),
        ];
        for (rule, mutate) in cases {
            let mut new = old.clone();
            mutate(&mut new);
            assert_eq!(manifest_rules(&old, &new), vec![rule]);
        }
    }

    #[test]
    fn subscription_rules_are_non_vacuous() -> anyhow::Result<()> {
        let old = full_projection();
        let cases: Vec<(BreakingRule, SubscriptionMutation)> = vec![
            (
                BreakingRule::SubscriptionConsumerChanged,
                Box::new(|s| s.consumer = "settings".into()),
            ),
            (
                BreakingRule::SubscriptionGroupChanged,
                Box::new(|s| s.group = "audit.renamed".into()),
            ),
            (
                BreakingRule::SubscriptionTopologyChanged,
                Box::new(|s| s.partition = "none".into()),
            ),
            (
                BreakingRule::SubscriptionExecutionChanged,
                Box::new(|s| s.execution = Some("domain-effect".into())),
            ),
            (
                BreakingRule::SubscriptionEffectChanged,
                Box::new(|s| s.effect = Some("settings-config-version-refresh".into())),
            ),
            (
                BreakingRule::SubscriptionExternalEffectPolicyChanged,
                Box::new(|s| {
                    s.external_effect_policy = "reconcile".into();
                }),
            ),
        ];
        for (rule, mutate) in cases {
            let mut new = old.clone();
            let mut subscription = new
                .subscriptions
                .pop_first()
                .ok_or_else(|| anyhow::anyhow!("missing subscription fixture"))?;
            mutate(&mut subscription);
            new.subscriptions.insert(subscription);
            assert_eq!(manifest_rules(&old, &new), vec![rule]);
        }
        let mut added = old.clone();
        let mut extra = added
            .subscriptions
            .pop_first()
            .ok_or_else(|| anyhow::anyhow!("missing subscription fixture"))?;
        added.subscriptions.insert(extra.clone());
        extra.consumer = "settings".into();
        extra.group = "settings.sessions".into();
        added.subscriptions.insert(extra);
        assert_eq!(
            manifest_rules(&old, &added),
            vec![BreakingRule::SubscriptionSetChanged]
        );
        Ok(())
    }

    #[test]
    fn subscription_policy_rollout_normalizes_legacy_semantics() -> anyhow::Result<()> {
        let mut legacy = BaseSubscription {
            consumer: "audit".into(),
            group: "audit.sessions".into(),
            execution: Some(SubscriptionExecution::AdapterNative),
            effect: None,
            external_effect_policy: None,
            topology: BaseSubscriptionTopology {
                partition_key: PartitionKeyStrategy::Aggregate,
                readiness: SubscriberReadiness::Required,
            },
        };
        assert_eq!(base_external_effect_policy(&legacy)?, "transactional-only");

        legacy.consumer = "settings".into();
        legacy.group = "settings.config-version-changed".into();
        legacy.execution = Some(SubscriptionExecution::DomainEffect);
        legacy.effect = Some(SubscriptionEffect::SettingsConfigVersionRefresh);
        assert_eq!(base_external_effect_policy(&legacy)?, "reconcile");

        legacy.execution = Some(SubscriptionExecution::AdapterNative);
        assert!(
            base_external_effect_policy(&legacy).is_err(),
            "legacy policy must not be inferred from an invalid execution/effect shape"
        );

        let old = full_projection();
        let mut new = old.clone();
        let mut subscription = new
            .subscriptions
            .pop_first()
            .ok_or_else(|| anyhow::anyhow!("missing subscription fixture"))?;
        subscription.external_effect_policy = "reconcile".into();
        new.subscriptions.insert(subscription);
        assert_eq!(
            manifest_rules(&old, &new),
            vec![BreakingRule::SubscriptionExternalEffectPolicyChanged],
            "legacy inferred policy must still reject semantic drift"
        );
        Ok(())
    }

    fn subscription(
        consumer: &str,
        group: &str,
        partition: &str,
        readiness: &str,
        execution: &str,
        effect: Option<&str>,
    ) -> SubscriptionProjection {
        SubscriptionProjection {
            consumer: consumer.into(),
            group: group.into(),
            partition: partition.into(),
            readiness: readiness.into(),
            execution: Some(execution.into()),
            effect: effect.map(str::to_string),
            external_effect_policy: "transactional-only".into(),
        }
    }

    #[test]
    fn same_consumer_multi_group_is_compared_without_loss() -> anyhow::Result<()> {
        let old = BTreeSet::from([
            subscription(
                "audit",
                "audit.g1",
                "aggregate",
                "required",
                "adapter-native",
                None,
            ),
            subscription(
                "audit",
                "audit.g2",
                "none",
                "required",
                "adapter-native",
                None,
            ),
        ]);
        let first = old
            .iter()
            .next()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("missing g1 fixture"))?;
        let last = old
            .iter()
            .next_back()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("missing g2 fixture"))?;

        let mut reordered = BTreeSet::new();
        reordered.insert(last.clone());
        reordered.insert(first.clone());
        let mut findings = Vec::new();
        compare_subscriptions(&mut findings, &old, &reordered);
        assert!(
            findings.is_empty(),
            "declaration order is not wire semantics"
        );

        let mut added = old.clone();
        added.insert(subscription(
            "audit",
            "audit.g3",
            "none",
            "required",
            "adapter-native",
            None,
        ));
        let mut findings = Vec::new();
        compare_subscriptions(&mut findings, &old, &added);
        assert_eq!(rules(&findings), vec![BreakingRule::SubscriptionSetChanged]);

        let removed = BTreeSet::from([first]);
        let mut findings = Vec::new();
        compare_subscriptions(&mut findings, &old, &removed);
        assert_eq!(rules(&findings), vec![BreakingRule::SubscriptionSetChanged]);

        for (expected, changed) in [
            (
                BreakingRule::SubscriptionTopologyChanged,
                subscription(
                    "audit",
                    "audit.g1",
                    "none",
                    "required",
                    "adapter-native",
                    None,
                ),
            ),
            (
                BreakingRule::SubscriptionTopologyChanged,
                subscription(
                    "audit",
                    "audit.g1",
                    "aggregate",
                    "optional",
                    "adapter-native",
                    None,
                ),
            ),
            (
                BreakingRule::SubscriptionExecutionChanged,
                subscription(
                    "audit",
                    "audit.g1",
                    "aggregate",
                    "required",
                    "domain-effect",
                    None,
                ),
            ),
            (
                BreakingRule::SubscriptionEffectChanged,
                subscription(
                    "audit",
                    "audit.g1",
                    "aggregate",
                    "required",
                    "adapter-native",
                    Some("settings-config-version-refresh"),
                ),
            ),
        ] {
            let new = BTreeSet::from([changed, last.clone()]);
            let mut findings = Vec::new();
            compare_subscriptions(&mut findings, &old, &new);
            assert_eq!(rules(&findings), vec![expected]);
        }
        Ok(())
    }

    #[test]
    fn plan_diffs_rejects_duplicate_identity_and_reports_lifecycle_downgrade() -> anyhow::Result<()>
    {
        let schema = json!({"properties": {"id": {"type":"string"}}});
        let active = side("same", Lifecycle::Active, &[("request", schema.clone())]);
        assert!(plan_diffs(&[active.clone(), active.clone()], &[]).is_err());

        for lifecycle in [Lifecycle::Draft, Lifecycle::Deprecated] {
            let downgraded = side("same", lifecycle, &[("request", schema.clone())]);
            let diffs = plan_diffs(std::slice::from_ref(&active), &[downgraded])?;
            assert_eq!(diffs[0].lifecycle, Lifecycle::Active);
            assert_eq!(diffs[0].working_lifecycle, Some(lifecycle));
            let result = evaluate(&diffs);
            assert!(result.any_deny, "active lifecycle 降级不得绕过");
            assert_eq!(result.findings.len(), 1);
            assert_eq!(result.findings[0].rule, BreakingRule::LifecycleDowngraded);
            assert_eq!(result.findings[0].rule.id(), "LIFECYCLE_DOWNGRADED");
        }
        Ok(())
    }

    /// 规则 ID 稳定（输出 + 治理断言单源，防漂移）。
    #[test]
    fn rule_ids_stable() {
        assert_eq!(BreakingRule::FieldNoDelete.id(), "FIELD_NO_DELETE");
        assert_eq!(
            BreakingRule::RequiredFieldAdded.id(),
            "REQUIRED_FIELD_ADDED"
        );
        assert_eq!(BreakingRule::FieldTypeChanged.id(), "FIELD_TYPE_CHANGED");
        assert_eq!(
            BreakingRule::FieldFormatChanged.id(),
            "FIELD_FORMAT_CHANGED"
        );
        assert_eq!(BreakingRule::EnumValueDeleted.id(), "ENUM_VALUE_DELETED");
        assert_eq!(
            BreakingRule::AdditionalPropsTightened.id(),
            "ADDITIONAL_PROPS_TIGHTENED"
        );
        assert_eq!(BreakingRule::NullableRemoved.id(), "NULLABLE_REMOVED");
        assert_eq!(
            BreakingRule::LocalOnlyBoundaryChanged.id(),
            "LOCAL_ONLY_BOUNDARY_CHANGED"
        );
        assert_eq!(BreakingRule::EffectAdded.id(), "EFFECT_ADDED");
        assert_eq!(BreakingRule::EffectRemoved.id(), "EFFECT_REMOVED");
    }
}
