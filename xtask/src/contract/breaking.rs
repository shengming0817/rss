//! wire 破坏式变更检测门（`cargo xtask contract breaking [--against <git-ref>] [--deny]`，ADR-008 落地）。
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
//!   两版 schema 递归 diff，**只报既有字段的删除 / 收紧 / 隐私·保护策略漂移**（新增可选字段不报，向后兼容语义）。后 3 条
//!   manifest 依赖规则（HTTP_STATUS_CODE_CHANGED / AUTH_REQUIREMENT_CHANGED / IDEMPOTENCY_LEVEL_CHANGED）依赖
//!   扩 manifest schema，登记第三期（ADR-008 §3.1）。首版不覆盖 `oneOf`/`anyOf`/`$ref` 嵌套构造（ADR §8 增量补）。
//! INVARIANT: WIRE-BREAKING-WINDOW-01 { level = "Medium", exec = "verify", source = "code" }—— 窗口分级 **配置驱动、不读墙上时钟**（clippy 全 workspace 禁
//!   `SystemTime::now`/`chrono::Utc::now`）：默认 [`EnforcementMode::Warn`]（pre-GA，至 2026-12-31，退出码 0）；
//!   env `RSS_WIRE_BREAKING=deny` 或 standalone `--deny` 升 [`EnforcementMode::Deny`]（窗口到期 / GA / 外部
//!   wire 消费方提前收紧）。[`disposition`] 纯函数：仅 `(Deny, active)` → `Deny`（退出码 1），余 `Warn`（退出码 0）。
//!   gate 只对 **active + deprecated** 契约 diff（draft = seed/前瞻原地演进豁免，对齐 ADR §3.2「只检 active」）。
//!
//! anti-vacuity（ai-robust 第 4 档强制，守卫不恒真）：每条规则配 synthetic red（破坏→finding）+ green
//! （兼容→无），并含「≥1 active 契约破坏」red（防恒真）+ draft 跳过 red（draft 删字段→无 finding）。

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Stdio;

use anyhow::{Result, bail};
use serde::Deserialize;
use serde_json::Value;

use super::discover;
use super::manifest::{ContractManifest, Lifecycle};
use super::protection;
use super::redaction;

/// base ref 默认值（`--against` 缺省）：与 ADR-008 §3.2 一致（PR 基准分支）。
pub(crate) const DEFAULT_AGAINST: &str = "origin/develop";

/// 窗口分级开关 env 名（单一事实源）。值 `deny`（大小写不敏感）升 [`EnforcementMode::Deny`]。
pub(crate) const ENFORCE_ENV: &str = "RSS_WIRE_BREAKING";

/// JSON Schema `properties` 键名（DRY：compare_node + check_field_deletions 多处引用）。
const PROPS: &str = "properties";

/// 第三期规则缺口透明化注脚（每次运行打印）：后 3 条 manifest 依赖规则尚未实现，gate 不检测——
/// 防用户误以为已全覆盖（B-F3 / ADR-008 §3.1 第二期表）。
const THIRD_PHASE_NOTE: &str = "  注：HTTP_STATUS_CODE_CHANGED / AUTH_REQUIREMENT_CHANGED / IDEMPOTENCY_LEVEL_CHANGED 依赖 manifest schema 扩展，第三期落地前不检测（ADR-008 §3.1）。";

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
    /// 既有字段的 `x-pii` / `x-redaction` 隐私语义改变。
    RedactionPolicyChanged,
    /// 既有字段的 `x-protection`（at-rest 加密）或 schema 级 `x-at-rest` 保护语义改变（#1468，
    /// ADR-011 D1b：保护策略漂移须作审查材料，防 wire 隐私语义静默漂移）。
    ProtectionPolicyChanged,
}

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
            BreakingRule::RedactionPolicyChanged => "REDACTION_POLICY_CHANGED",
            BreakingRule::ProtectionPolicyChanged => "PROTECTION_POLICY_CHANGED",
        }
    }
}

/// 窗口分级 enforcement 模式（WIRE-BREAKING-WINDOW-01）。默认 `Warn`（pre-GA）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EnforcementMode {
    /// pre-GA：所有 finding 仅记录（退出码 0），不阻断 verify。
    Warn,
    /// 窗口到期 / 提前收紧：active 契约破坏升 deny（退出码 1）。
    Deny,
}

impl EnforcementMode {
    /// 从 env [`ENFORCE_ENV`] 解析；`deny`（大小写不敏感）→ `Deny`，缺省 / 其它 → `Warn`。
    /// **不读墙上时钟**——窗口到期由人改 env/默认或 `--deny`，与 clock 纪律一致（WIRE-BREAKING-WINDOW-01）。
    pub(crate) fn from_env() -> Self {
        Self::from_raw(std::env::var(ENFORCE_ENV).ok().as_deref())
    }

    /// 纯解析（与 env 读取分离，便于单测——不触 `std::env`，避 edition-2024 `set_var` unsafe）。
    fn from_raw(raw: Option<&str>) -> Self {
        match raw {
            Some(v) if v.trim().eq_ignore_ascii_case("deny") => EnforcementMode::Deny,
            _ => EnforcementMode::Warn,
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

/// 窗口分级核心（纯函数，WIRE-BREAKING-WINDOW-01）：仅 `Deny` 模式下 active 契约破坏升 `Deny`，
/// 余皆 `Warn`。`draft` 在 [`evaluate`] 前已被滤除，此处对其返回 `Warn`（总性，不应被调用到）。
pub(crate) fn disposition(mode: EnforcementMode, lifecycle: Lifecycle) -> Disposition {
    match (mode, lifecycle) {
        (EnforcementMode::Deny, Lifecycle::Active) => Disposition::Deny,
        _ => Disposition::Warn,
    }
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
pub(crate) fn compare_schemas(old: &Value, new: &Value) -> Vec<RawBreak> {
    let mut out = Vec::new();
    compare_node(old, new, "", &mut out);
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

/// 已分级 finding（diff + disposition 后）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GradedFinding {
    pub(crate) disposition: Disposition,
    pub(crate) rule: BreakingRule,
    /// `{label} {schema_file} ({pointer})`。
    pub(crate) subject: String,
    pub(crate) detail: String,
}

/// 一个待 diff 的契约投影（从 [`DiscoveredContract`](super::DiscoveredContract) + git/fs 读取派生，
/// 便于 [`evaluate`] 不依赖真 git 单测）。
#[derive(Debug, Clone)]
pub(crate) struct ContractDiff {
    /// 契约 label `{kind}/{domain}/{version}`。
    pub(crate) label: String,
    pub(crate) lifecycle: Lifecycle,
    pub(crate) schemas: Vec<SchemaVersions>,
}

/// 单个 logical schema slot 的两版本：`old=None` ⇒ base ref 无此 slot（新契约 / 新 slot，不报）；
/// slot/契约在 working 侧被删 ⇒ `new` 为空 schema（base 字段全报删除）。`file` 携 slot 名（request/response/payload/saga:step）。
#[derive(Debug, Clone)]
pub(crate) struct SchemaVersions {
    pub(crate) file: String,
    pub(crate) old: Option<Value>,
    pub(crate) new: Value,
}

/// 一侧（base 或 working）的契约投影：label + lifecycle + slot→已解析 schema JSON。
/// base/working 两侧同形，[`plan_diffs`] 按 (identity, slot) 取并集对齐（C1：删除类破坏须从 base 侧进入比较）。
#[derive(Debug, Clone)]
pub(crate) struct ContractSide {
    /// 稳定契约身份。来自 manifest `id`，不随 flat/nested 目录迁移漂移。
    pub(crate) identity: String,
    /// 人读诊断 label，保留来源路径形态。
    pub(crate) label: String,
    pub(crate) lifecycle: Lifecycle,
    pub(crate) slots: BTreeMap<String, Value>,
}

/// 按 (identity, slot) 构造 base ∪ working 并集（纯函数，C1）：
/// - lifecycle：working 在场用其 lifecycle，否则用 base 的（删整个契约 = base lifecycle 决定是否检）。
/// - `old` = base slot schema（`None` ⇒ base 无此 slot ⇒ 新契约/新 slot，[`evaluate`] 跳过不报）。
/// - `new` = working slot schema；base 有而 working 无（slot/契约被删）⇒ 空 schema ⇒ compare 报 base 字段全删。
///
/// 这修复「只遍历 working 侧」漏检删除整个 active 契约 / 删 schema slot / slot 改名丢字段（对标 Buf
/// FILE_NO_DELETE / MESSAGE_NO_DELETE：基准侧存在而当前侧缺失须进入比较）。
pub(crate) fn plan_diffs(base: &[ContractSide], working: &[ContractSide]) -> Vec<ContractDiff> {
    let base_idx: BTreeMap<&str, &ContractSide> =
        base.iter().map(|s| (s.identity.as_str(), s)).collect();
    let work_idx: BTreeMap<&str, &ContractSide> =
        working.iter().map(|s| (s.identity.as_str(), s)).collect();
    let identities: BTreeSet<&str> = base_idx.keys().chain(work_idx.keys()).copied().collect();

    let mut diffs = Vec::new();
    for identity in identities {
        let b = base_idx.get(identity).copied();
        let w = work_idx.get(identity).copied();
        // working 在场优先用其 lifecycle，否则 base 的；label 取自并集，至少一侧在场。
        let lifecycle = match w.or(b) {
            Some(s) => s.lifecycle,
            None => continue,
        };
        let label = w
            .or(b)
            .map(|s| s.label.as_str())
            .unwrap_or(identity)
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
            let old = b.and_then(|s| s.slots.get(slot)).cloned();
            let new = w
                .and_then(|s| s.slots.get(slot))
                .cloned()
                .unwrap_or_else(empty_schema);
            schemas.push(SchemaVersions {
                file: slot.to_string(),
                old,
                new,
            });
        }
        diffs.push(ContractDiff {
            label,
            lifecycle,
            schemas,
        });
    }
    diffs
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
pub(crate) fn evaluate(contracts: &[ContractDiff], mode: EnforcementMode) -> EvalResult {
    let mut result = EvalResult::default();
    for c in contracts {
        if !is_checked(c.lifecycle) {
            continue; // draft：seed/前瞻原地演进豁免（WIRE-BREAKING-WINDOW-01）
        }
        let disp = disposition(mode, c.lifecycle);
        for sv in &c.schemas {
            let Some(old) = &sv.old else {
                continue; // base ref 无此 schema：新契约 / 新版本，不报
            };
            for b in compare_schemas(old, &sv.new) {
                if disp == Disposition::Deny {
                    result.any_deny = true;
                }
                result.findings.push(GradedFinding {
                    disposition: disp,
                    rule: b.rule,
                    subject: format!("{} {} ({})", c.label, sv.file, show(&b.pointer)),
                    detail: b.detail,
                });
            }
        }
    }
    result
}

/// gate 入口：discover working-tree 契约 → 读 base schema（`git show {against}:...`）→ [`evaluate`] →
/// 打印分级 finding → 有 `Deny` 即 `bail`（退出码 1），否则 `Ok`（退出码 0）。
/// base ref 不可解析（如未 fetch `origin/develop`）→ 按模式分级处置（见 [`unresolved_ref`]）。
pub(crate) fn run(against: &str, mode: EnforcementMode) -> Result<()> {
    let root = crate::workspace_root()?;
    if !ref_exists(&root, against) {
        return unresolved_ref(against, mode);
    }
    let contracts_root = root.join("contracts");
    let working = working_sides(&contracts_root)?;
    let base = base_sides(&root, against)?;
    let diffs = plan_diffs(&base, &working);
    let result = evaluate(&diffs, mode);
    print_result(against, mode, &result);
    if result.any_deny {
        bail!(
            "contract breaking: {} 项 active 契约 wire 破坏（deny 模式 fail-closed）",
            result
                .findings
                .iter()
                .filter(|f| f.disposition == Disposition::Deny)
                .count()
        );
    }
    Ok(())
}

/// base ref 不可解析时的窗口分级处置（WIRE-BREAKING-WINDOW-01）：`warn` → 跳过（`Ok`，pre-GA advisory）；
/// `deny` → **fail-closed**（`Err`）——无法读基准 schema 即无法判定破坏，enforce 模式不可静默放行
/// （浅克隆 / CI 漏 fetch 场景，B-F1 fail-closed 缺口）。
fn unresolved_ref(against: &str, mode: EnforcementMode) -> Result<()> {
    let hint = fetch_hint(against);
    match mode {
        EnforcementMode::Deny => bail!(
            "contract breaking: base ref `{against}` 不可解析，deny 模式 fail-closed——\
             无法读基准 schema 即无法判定 wire 破坏。先 `{hint}`，或 `--against <本地 ref>`（如 HEAD~1）。"
        ),
        EnforcementMode::Warn => {
            eprintln!(
                "contract breaking: [跳过] base ref `{against}` 不可解析（未 fetch？）。\
                 warn 模式不阻断；先 `{hint}`，或 `--against <本地 ref>`（如 HEAD~1）。"
            );
            Ok(())
        }
    }
}

/// 由 base ref 推 fetch 指引：含 `/`（如 `origin/develop`）→ `git fetch origin develop`；无 `/` → `git fetch`。
fn fetch_hint(against: &str) -> String {
    match against.split_once('/') {
        Some((remote, branch)) => format!("git fetch {remote} {branch}"),
        None => "git fetch".to_string(),
    }
}

/// 打印分级 finding（warn / deny 前缀 + 规则 ID + subject + detail）+ 第三期缺口注脚（恒打印）。
fn print_result(against: &str, mode: EnforcementMode, result: &EvalResult) {
    let mode_label = match mode {
        EnforcementMode::Warn => "warn",
        EnforcementMode::Deny => "deny",
    };
    if result.findings.is_empty() {
        eprintln!("contract breaking（against {against}，{mode_label} 模式）：无 wire 破坏");
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
            "contract breaking（against {against}，{mode_label} 模式）：{} 项破坏（{denies} deny / {} warn）",
            result.findings.len(),
            result.findings.len() - denies
        );
    }
    eprintln!("{THIRD_PHASE_NOTE}");
}

/// `git rev-parse --verify --quiet {ref}` 退出 0 ⇒ ref 可解析。经 [`clean_cmd`](crate::cmd::clean_cmd)（CMD-FUNNEL-01）。
fn ref_exists(root: &Path, git_ref: &str) -> bool {
    crate::cmd::clean_cmd(
        "git",
        &["rev-parse", "--verify", "--quiet", git_ref],
        &[],
        Some(root),
    )
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .status()
    .map(|s| s.success())
    .unwrap_or(false)
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
fn slot_files(m: &ContractManifest) -> Vec<(String, String)> {
    let mut v = Vec::new();
    for (slot, file) in [
        ("request", m.schemas.request.as_deref()),
        ("response", m.schemas.response.as_deref()),
        ("payload", m.schemas.payload.as_deref()),
    ] {
        if let Some(f) = file {
            v.push((slot.to_string(), f.to_string()));
        }
    }
    if let Some(saga) = &m.saga {
        for s in &saga.steps {
            v.push((format!("saga:{}", s.name), s.output_schema.clone()));
        }
    }
    v
}

#[derive(Debug, Deserialize)]
struct BaseContractManifest {
    id: String,
    lifecycle: Lifecycle,
    #[serde(default)]
    schemas: BaseSchemas,
    #[serde(default)]
    saga: Option<BaseSagaBlock>,
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
fn base_slot_files(m: &BaseContractManifest) -> Vec<(String, String)> {
    let mut v = Vec::new();
    for (slot, file) in [
        ("request", m.schemas.request.as_deref()),
        ("response", m.schemas.response.as_deref()),
        ("payload", m.schemas.payload.as_deref()),
    ] {
        if let Some(f) = file {
            v.push((slot.to_string(), f.to_string()));
        }
    }
    if let Some(saga) = &m.saga {
        for s in &saga.steps {
            v.push((format!("saga:{}", s.name), s.output_schema.clone()));
        }
    }
    v
}

/// working-tree 侧契约投影：discover + 逐 slot 读磁盘 schema。
fn working_sides(contracts_root: &Path) -> Result<Vec<ContractSide>> {
    let discovered = discover(contracts_root)?;
    let mut sides = Vec::with_capacity(discovered.len());
    for c in &discovered {
        let label = contract_label(c);
        let identity = contract_identity(&c.manifest);
        let mut slots = BTreeMap::new();
        for (slot, file) in slot_files(&c.manifest) {
            slots.insert(slot, read_working_schema(&c.dir, &file)?);
        }
        sides.push(ContractSide {
            identity,
            label,
            lifecycle: c.manifest.lifecycle,
            slots,
        });
    }
    Ok(sides)
}

/// base 侧契约投影：`git ls-tree` 枚举 base 契约 → 逐个 `git show` contract.toml + 各 slot schema。
fn base_sides(root: &Path, against: &str) -> Result<Vec<ContractSide>> {
    let mut sides = Vec::new();
    for manifest_rel in base_contract_manifests(root, against)? {
        let Some(text) = read_text_at_ref(root, against, &manifest_rel)? else {
            continue; // 竞态 / 罕见：ls-tree 列了但 show 不到，跳过
        };
        let manifest = toml::from_str::<BaseContractManifest>(&text)
            .map_err(|e| anyhow::anyhow!("解析 base {manifest_rel} 失败: {e}"))?;
        let Some(label) = label_from_manifest_path(&manifest_rel) else {
            continue; // 非 contracts/{kind}/{domain}/{version}/contract.toml 形态
        };
        let Some(dir_rel) = manifest_rel.strip_suffix("/contract.toml") else {
            continue;
        };
        let mut slots = BTreeMap::new();
        for (slot, file) in base_slot_files(&manifest) {
            let schema_rel = format!("{dir_rel}/{file}");
            if let Some(schema_text) = read_text_at_ref(root, against, &schema_rel)? {
                let v = serde_json::from_str(&schema_text)
                    .map_err(|e| anyhow::anyhow!("解析 base schema {schema_rel} 失败: {e}"))?;
                slots.insert(slot, v);
            }
        }
        sides.push(ContractSide {
            identity: manifest.id,
            label,
            lifecycle: manifest.lifecycle,
            slots,
        });
    }
    Ok(sides)
}

/// `git ls-tree -r --name-only {ref} -- contracts/` 列 base 侧所有 `contract.toml` 路径。
/// 经 [`clean_cmd`](crate::cmd::clean_cmd)（CMD-FUNNEL-01）。ref 无 contracts/ → 空（非错）。
fn base_contract_manifests(root: &Path, against: &str) -> Result<Vec<String>> {
    let out = crate::cmd::clean_cmd(
        "git",
        &["ls-tree", "-r", "--name-only", against, "--", "contracts/"],
        &[],
        Some(root),
    )
    .stderr(Stdio::null())
    .output()
    .map_err(|e| anyhow::anyhow!("git ls-tree {against} 失败: {e}"))?;
    if !out.status.success() {
        return Ok(Vec::new());
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.ends_with("/contract.toml"))
        .map(str::to_string)
        .collect())
}

/// `git show {ref}:{rel}` 读文本；rel 不在该 ref → `Ok(None)`。经 [`clean_cmd`](crate::cmd::clean_cmd)（CMD-FUNNEL-01）。
fn read_text_at_ref(root: &Path, git_ref: &str, rel: &str) -> Result<Option<String>> {
    let spec = format!("{git_ref}:{rel}");
    let out = crate::cmd::clean_cmd("git", &["show", &spec], &[], Some(root))
        .stderr(Stdio::null())
        .output()
        .map_err(|e| anyhow::anyhow!("git show {spec} 失败: {e}"))?;
    if !out.status.success() {
        return Ok(None);
    }
    Ok(Some(String::from_utf8_lossy(&out.stdout).into_owned()))
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

fn contract_identity(m: &ContractManifest) -> String {
    m.id.clone()
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
    #[case(EnforcementMode::Warn, Lifecycle::Active, Disposition::Warn)]
    #[case(EnforcementMode::Warn, Lifecycle::Deprecated, Disposition::Warn)]
    #[case(EnforcementMode::Warn, Lifecycle::Draft, Disposition::Warn)]
    #[case(EnforcementMode::Deny, Lifecycle::Active, Disposition::Deny)]
    #[case(EnforcementMode::Deny, Lifecycle::Deprecated, Disposition::Warn)]
    #[case(EnforcementMode::Deny, Lifecycle::Draft, Disposition::Warn)]
    fn disposition_truth_table(
        #[case] mode: EnforcementMode,
        #[case] lifecycle: Lifecycle,
        #[case] want: Disposition,
    ) {
        assert_eq!(disposition(mode, lifecycle), want);
    }

    // ─────────── evaluate seam（含「≥1 active 契约破坏」防恒真 + draft 跳过）───────────

    fn diff(label: &str, lifecycle: Lifecycle, old: Value, new: Value) -> ContractDiff {
        ContractDiff {
            label: label.to_string(),
            lifecycle,
            schemas: vec![SchemaVersions {
                file: "request.schema.json".to_string(),
                old: Some(old),
                new,
            }],
        }
    }

    /// ADR §3.2 防恒真：active 契约删字段 + Deny 模式 → any_deny=true（gate 真会拦截）。
    #[test]
    fn active_breaking_under_deny_is_deny() {
        let c = diff(
            "http/identity/v1",
            Lifecycle::Active,
            json!({"properties": {"id": {"type":"string"}, "name": {"type":"string"}}}),
            json!({"properties": {"id": {"type":"string"}}}),
        );
        let r = evaluate(&[c], EnforcementMode::Deny);
        assert!(r.any_deny, "active 破坏在 deny 模式须升 Deny");
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].disposition, Disposition::Deny);
    }

    /// 同样 active 破坏在 Warn 模式 → finding 在但不 deny（退出码 0）。
    #[test]
    fn active_breaking_under_warn_is_warn_only() {
        let c = diff(
            "http/identity/v1",
            Lifecycle::Active,
            json!({"properties": {"id": {"type":"string"}, "name": {"type":"string"}}}),
            json!({"properties": {"id": {"type":"string"}}}),
        );
        let r = evaluate(&[c], EnforcementMode::Warn);
        assert!(!r.any_deny);
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].disposition, Disposition::Warn);
    }

    /// draft 跳过 red：draft 契约删字段 → 零 finding（即便 Deny 模式）。
    #[test]
    fn draft_breaking_is_skipped() {
        let c = diff(
            "http/_seed/v1",
            Lifecycle::Draft,
            json!({"properties": {"id": {"type":"string"}, "name": {"type":"string"}}}),
            json!({"properties": {"id": {"type":"string"}}}),
        );
        let r = evaluate(&[c], EnforcementMode::Deny);
        assert!(r.findings.is_empty(), "draft 契约应整体跳过");
        assert!(!r.any_deny);
    }

    /// deprecated 破坏恒 warn（即便 Deny 模式，退出码 0）。
    #[test]
    fn deprecated_breaking_is_warn_only() {
        let c = diff(
            "http/legacy/v1",
            Lifecycle::Deprecated,
            json!({"properties": {"id": {"type":"string"}, "name": {"type":"string"}}}),
            json!({"properties": {"id": {"type":"string"}}}),
        );
        let r = evaluate(&[c], EnforcementMode::Deny);
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
            schemas: vec![SchemaVersions {
                file: "request.schema.json".to_string(),
                old: None,
                new: json!({"properties": {"id": {"type":"string"}}}),
            }],
        };
        let r = evaluate(&[c], EnforcementMode::Deny);
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
        ContractSide {
            identity: identity.to_string(),
            label: label.to_string(),
            lifecycle,
            slots: slots
                .iter()
                .map(|(k, v)| ((*k).to_string(), v.clone()))
                .collect(),
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
                ("request".to_string(), "request.schema.json".to_string()),
                ("response".to_string(), "response.schema.json".to_string()),
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
                ("payload".to_string(), "payload.schema.json".to_string()),
                (
                    "saga:reserve_funds".to_string(),
                    "reserve.schema.json".to_string()
                ),
                (
                    "saga:capture".to_string(),
                    "capture.schema.json".to_string()
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
    fn nested_identity_v1_siblings_do_not_collapse_to_three_segment_label() {
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

        let diffs = plan_diffs(&base, &working);
        let labels: BTreeSet<&str> = diffs.iter().map(|d| d.label.as_str()).collect();
        assert_eq!(diffs.len(), 8, "8 个 sibling 必须逐个参与 breaking diff");
        assert_eq!(
            labels.len(),
            8,
            "nested sibling label 不能折叠成单个 http/identity/v1"
        );
        assert!(labels.contains("http/identity/v1/roles-revoke"));
    }

    #[test]
    fn flat_to_nested_same_contract_id_is_not_treated_as_delete_and_add() {
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

        let diffs = plan_diffs(&base, &working);
        let r = evaluate(&diffs, EnforcementMode::Deny);
        assert!(
            r.findings.is_empty(),
            "flat -> nested path migration must not look like a contract deletion: {:?}",
            r.findings
        );
        assert!(!r.any_deny);
    }

    /// 删除整个 active 契约（base 有、working 无）→ base 各字段报 FIELD_NO_DELETE（经 plan_diffs empty-new）。
    #[test]
    fn deleted_active_contract_reports_field_deletions() {
        let base = vec![side(
            "http/x/v1",
            Lifecycle::Active,
            &[(
                "request",
                json!({"properties": {"id": {"type":"string"}, "name": {"type":"string"}}}),
            )],
        )];
        let diffs = plan_diffs(&base, &[]);
        let r = evaluate(&diffs, EnforcementMode::Deny);
        assert_eq!(
            r.findings.len(),
            2,
            "删契约应报两字段删除: {:?}",
            r.findings
        );
        assert!(
            r.findings
                .iter()
                .all(|f| f.rule == BreakingRule::FieldNoDelete)
        );
        assert!(r.any_deny);
    }

    /// 删除一个 schema slot（base 有 response、working 无）→ 该 slot base 字段报删除。
    #[test]
    fn removed_schema_slot_reports_deletions() {
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
        let diffs = plan_diffs(&base, &working);
        let r = evaluate(&diffs, EnforcementMode::Warn);
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].rule, BreakingRule::FieldNoDelete);
        assert!(r.findings[0].subject.contains("response"));
    }

    /// slot 改名（文件名变、slot 不变）按内容比对——丢字段才报，文件名变化本身不报。
    #[test]
    fn renamed_slot_compares_by_content() {
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
        let diffs = plan_diffs(&base, &working);
        let r = evaluate(&diffs, EnforcementMode::Warn);
        assert_eq!(rules_of(&r), vec![BreakingRule::FieldNoDelete]);
    }

    /// 新契约（working 有、base 无）→ old=None → 不报（向后兼容）。
    #[test]
    fn new_contract_not_reported_via_plan() {
        let working = vec![side(
            "http/x/v2",
            Lifecycle::Active,
            &[("request", json!({"properties": {"id": {"type":"string"}}}))],
        )];
        let diffs = plan_diffs(&[], &working);
        let r = evaluate(&diffs, EnforcementMode::Deny);
        assert!(r.findings.is_empty());
        assert!(!r.any_deny);
    }

    /// 删除 draft 契约 → 跳过（lifecycle 由 base 决定，draft 豁免）。
    #[test]
    fn deleted_draft_contract_skipped_via_plan() {
        let base = vec![side(
            "http/_seed/v1",
            Lifecycle::Draft,
            &[(
                "request",
                json!({"properties": {"id": {"type":"string"}, "name": {"type":"string"}}}),
            )],
        )];
        let diffs = plan_diffs(&base, &[]);
        let r = evaluate(&diffs, EnforcementMode::Deny);
        assert!(r.findings.is_empty(), "draft 删契约应跳过");
    }

    fn rules_of(r: &EvalResult) -> Vec<BreakingRule> {
        r.findings.iter().map(|f| f.rule).collect()
    }

    // ─────────── fail-closed：base ref 不可解析的窗口分级处置（B-F1）───────────

    /// fetch_hint：含 `/` 的 ref → `git fetch <remote> <branch>`；无 `/` → 裸 `git fetch`。
    #[rstest]
    #[case("origin/develop", "git fetch origin develop")]
    #[case("upstream/main", "git fetch upstream main")]
    #[case("HEAD~1", "git fetch")]
    fn fetch_hint_cases(#[case] against: &str, #[case] want: &str) {
        assert_eq!(fetch_hint(against), want);
    }

    /// deny 模式 + base ref 不可解析 → fail-closed（`Err`）；warn 模式 → 跳过（`Ok`）。
    /// 用确定性不存在的 ref（经真实 git rev-parse，bogus ref 恒不可解析），验 [`unresolved_ref`] 分级。
    #[test]
    fn unresolved_ref_deny_fails_warn_skips() {
        const BOGUS: &str = "zzz-rss-wire-breaking-bogus-ref-xyz";
        assert!(
            run(BOGUS, EnforcementMode::Deny).is_err(),
            "deny 模式下不可解析 base ref 须 fail-closed（Err）"
        );
        assert!(
            run(BOGUS, EnforcementMode::Warn).is_ok(),
            "warn 模式下不可解析 base ref 跳过（Ok）"
        );
    }

    // ─────────── EnforcementMode::from_env（env 解析，非墙钟）───────────

    /// from_raw（纯解析，无 env 触碰）：缺省 / 非 deny 值 → Warn；`deny`（大小写不敏感、容空白）→ Deny。
    #[rstest]
    #[case(None, EnforcementMode::Warn)]
    #[case(Some(""), EnforcementMode::Warn)]
    #[case(Some("warn"), EnforcementMode::Warn)]
    #[case(Some("bogus"), EnforcementMode::Warn)]
    #[case(Some("deny"), EnforcementMode::Deny)]
    #[case(Some("DENY"), EnforcementMode::Deny)]
    #[case(Some(" deny "), EnforcementMode::Deny)]
    fn enforcement_mode_from_raw(#[case] raw: Option<&str>, #[case] want: EnforcementMode) {
        assert_eq!(EnforcementMode::from_raw(raw), want);
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
    }
}
