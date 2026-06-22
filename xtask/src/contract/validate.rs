//! 契约元数据校验（规则集见下方执行顺序 + `Rule` 枚举单源）——`cargo xtask contract validate`。
//!
//! INVARIANT: CONTRACT-FANOUT-01 — schema 引用完整性 + kind→形态一致（R4/R5，含 saga step `outputSchema`）。
//! INVARIANT: CONTRACT-FREEZE-01（运行期部分）— 跨字段不变式（R1 saga⇒L3 / R2 framework⇒http|event）、
//! 路径↔字段一致（R3）、authoring 标识符语法（R7：domain/version/id/owner 在拼进派生路径 / module 名前先收口）、
//! per-kind 字段（#1035）的 active 发布接线必填（R8）/ 跨 kind 卫生（R9）/ saga block 结构语义（R10）/
//! active event 投递语义可兑现性（R11）。
//! Medium（CI 门）；每条规则配 synthetic red case（见 `#[cfg(test)]`），
//! anti-vacuity：全合法绿用例必过、各红用例必失。
//! Hard 类型层部分（字段集冻结、枚举解析拒绝、`u64` 非负、嵌套 `deny_unknown_fields`）见 `manifest.rs`
//! （CONTRACT-FREEZE-01）；R8–R11 是条件化跨字段不变式（依赖 lifecycle/kind/值 组合），类型层无法免费表达，
//! 故与 R1–R7 同属 Medium——「能 Hard 则 Hard、余下 Medium」的正确分层。
//!
//! 规则执行顺序（注释编号 = 执行先后）：
//!   R1 SagaConsistency → R2 FrameworkKind → R3 PathMismatch → R4 SchemaShape → R5 MissingSchema
//!   → R6 UnsafeSchemaPath → R7 IdentSyntax → R8 PerKindActiveFields → R9 PerKindFieldScope
//!   → R10 SagaBlock → R11 ActiveDeliverySupported

use anyhow::Result;
use std::collections::BTreeSet;
use std::path::Path;

use super::manifest::{
    ConsistencyLevel, ContractKind, ContractManifest, ContractOwner, Delivery, FIELD_DELIVERY,
    FIELD_METHOD, FIELD_PATH, FIELD_SAGA, FIELD_TOPIC, Lifecycle, SCHEMA_KEY_PAYLOAD,
    SCHEMA_KEY_REQUEST, SCHEMA_KEY_RESPONSE,
};
use super::{DiscoveredContract, discover};
use crate::diagnostic::{self, GovernanceCheck, finding};
use crate::pathsafe;

pub(crate) type Finding = diagnostic::Finding<Rule>;

/// 被违反的规则（供测试精确断言）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    /// R1：`kind = saga` ⇒ `consistencyLevel = WorkflowEventual`。
    SagaConsistency,
    /// R2：`owner = _framework` ⇒ `kind ∈ {http, event}`。
    FrameworkKind,
    /// R3：磁盘段 `{kind}/{domain}/{version}` 须等于 manifest 字段。
    PathMismatch,
    /// R4：kind→schema 形态须一致（http 需 request+response、event/saga 需 payload、command 需 request）。
    SchemaShape,
    /// R5：声明的每个 schema 文件须存在于契约目录。
    MissingSchema,
    /// R6：schema 文件名须为纯文件名，不得含路径分量（防 `../` 逃逸）。
    UnsafeSchemaPath,
    /// R7：authoring 标识符（domain/version/id/owner）+ per-kind 字符串字段（http `path` / event `topic`）
    /// 语法须先收口（拼进派生路径 / module 名 / 鉴权挂载点 / wire routing key 前）。
    IdentSyntax,
    /// R8：`lifecycle=active` ⇒ 按 kind 必填 active 发布接线字段（http path+method / event topic+delivery）。
    PerKindActiveFields,
    /// R9：per-kind 字段只允许出现在匹配 kind（错配 silently-ignored，须拒）。
    PerKindFieldScope,
    /// R10：`kind=saga` ⇒ 须有非空 `[saga]` block（无条件）+ block 内部良构（≥1 step、step name 合法
    /// 唯一、outputSchema 非空）。
    SagaBlock,
    /// R11：`lifecycle=active` 的 event 只能声明当前可兑现的投递语义（仅 `at-least-once`）；
    /// `at-most-once`/`exactly-once` 当前 broker 链路无运行时保证，能力落地前限 draft/deprecated。
    ActiveDeliverySupported,
}

/// `cargo xtask contract validate` 校验器（issue #1058：经 [`GovernanceCheck`] 统一编排）。
pub(crate) struct ContractValidate;

impl GovernanceCheck for ContractValidate {
    type Rule = Rule;
    fn name(&self) -> &'static str {
        "contract validate"
    }
    fn check(&self) -> Result<(String, Vec<Finding>)> {
        let contracts_root = crate::workspace_root()?.join("contracts");
        let (count, findings) = validate_root(&contracts_root)?;
        Ok((format!("{count} 契约全部通过"), findings))
    }
}

/// 校验给定根下全部契约，返回（契约数, findings）。根可注入便于测试。
pub(crate) fn validate_root(contracts_root: &Path) -> Result<(usize, Vec<Finding>)> {
    let contracts = discover(contracts_root)?;
    let mut findings = Vec::new();
    for c in &contracts {
        findings.extend(validate_contract(c));
    }
    Ok((contracts.len(), findings))
}

/// 对单契约跑全部规则（执行顺序 = 下方 `extend` 调用序 = `Rule` 声明序；编号见 `Rule` 枚举）。
pub(crate) fn validate_contract(c: &DiscoveredContract) -> Vec<Finding> {
    // label 用相对 `{kind}/{domain}/{version}` 三段（机器稳定、跨机一致），不用绝对磁盘路径
    // ——CI / 多开发机的 finding 输出须可对应 repo 路径，便于定位。
    let label = format!("{}/{}/{}", c.path_kind, c.path_domain, c.path_version);
    let mut findings = Vec::new();
    findings.extend(rule_saga_consistency(&c.manifest, &label));
    findings.extend(rule_framework_kind(&c.manifest, &label));
    findings.extend(rule_path_match(c, &label));
    findings.extend(rule_schema_shape(&c.manifest, &label));
    findings.extend(rule_schema_files_exist(c, &label));
    findings.extend(rule_unsafe_schema_path(&c.manifest, &label));
    findings.extend(rule_ident_syntax(&c.manifest, &label));
    findings.extend(rule_perkind_active_fields(&c.manifest, &label));
    findings.extend(rule_perkind_field_scope(&c.manifest, &label));
    findings.extend(rule_saga_block(&c.manifest, &label));
    findings.extend(rule_active_delivery_supported(&c.manifest, &label));
    findings
}

/// R1：saga ⇒ WorkflowEventual。
fn rule_saga_consistency(m: &ContractManifest, label: &str) -> Option<Finding> {
    if m.kind == ContractKind::Saga && m.consistency_level != ConsistencyLevel::WorkflowEventual {
        return Some(finding(
            Rule::SagaConsistency,
            label,
            format!(
                "kind=saga 须 consistencyLevel=WorkflowEventual，实为 {:?}",
                m.consistency_level
            ),
        ));
    }
    None
}

/// R2：framework owner ⇒ kind ∈ {http, event}。
fn rule_framework_kind(m: &ContractManifest, label: &str) -> Option<Finding> {
    let framework = matches!(m.owner, ContractOwner::Framework);
    let kind_ok = matches!(m.kind, ContractKind::Http | ContractKind::Event);
    if framework && !kind_ok {
        return Some(finding(
            Rule::FrameworkKind,
            label,
            format!(
                "owner=_framework 仅允许 kind ∈ {{http,event}}，实为 {:?}",
                m.kind
            ),
        ));
    }
    None
}

/// R3：磁盘段须等于 manifest 字段。
fn rule_path_match(c: &DiscoveredContract, label: &str) -> Option<Finding> {
    let want_kind = c.manifest.kind.as_dir();
    let mut diffs = Vec::new();
    if c.path_kind != want_kind {
        diffs.push(format!("kind 段 {} ≠ 字段 {}", c.path_kind, want_kind));
    }
    if c.path_domain != c.manifest.domain {
        diffs.push(format!(
            "domain 段 {} ≠ 字段 {}",
            c.path_domain, c.manifest.domain
        ));
    }
    if c.path_version != c.manifest.version {
        diffs.push(format!(
            "version 段 {} ≠ 字段 {}",
            c.path_version, c.manifest.version
        ));
    }
    if diffs.is_empty() {
        return None;
    }
    Some(finding(Rule::PathMismatch, label, diffs.join("；")))
}

/// R4：kind→schema 形态一致。返回缺失的必需 schema 声明（可多条）。
fn rule_schema_shape(m: &ContractManifest, label: &str) -> Vec<Finding> {
    let s = &m.schemas;
    let required: &[(&str, bool)] = match m.kind {
        ContractKind::Http => &[
            (SCHEMA_KEY_REQUEST, s.request.is_some()),
            (SCHEMA_KEY_RESPONSE, s.response.is_some()),
        ],
        ContractKind::Event | ContractKind::Saga => &[(SCHEMA_KEY_PAYLOAD, s.payload.is_some())],
        ContractKind::Command => &[(SCHEMA_KEY_REQUEST, s.request.is_some())],
    };
    required
        .iter()
        .filter(|(_, present)| !present)
        .map(|(key, _)| {
            finding(
                Rule::SchemaShape,
                label,
                format!("kind={:?} 缺必需 schema 声明 [schemas].{key}", m.kind),
            )
        })
        .collect()
}

/// R5：声明的每个 schema 文件须存在（含 saga step `outputSchema`，经 `declared_schema_files()` 聚合）。
fn rule_schema_files_exist(c: &DiscoveredContract, label: &str) -> Vec<Finding> {
    c.manifest
        .declared_schema_files()
        .into_iter()
        .filter(|file| !c.dir.join(file).is_file())
        .map(|file| {
            finding(
                Rule::MissingSchema,
                label,
                format!("声明的 schema 文件不存在: {file}"),
            )
        })
        .collect()
}

/// R6：schema 文件名须为纯文件名（不含 `/`、`\`、`..` 分量或绝对路径），防路径逃逸。
/// 防逃逸判定单源见 `crate::pathsafe`（codegen 写盘守卫同源）；含 saga step `outputSchema`。
fn rule_unsafe_schema_path(m: &ContractManifest, label: &str) -> Vec<Finding> {
    m.declared_schema_files()
        .into_iter()
        .filter(|file| pathsafe::is_unsafe_segment(file))
        .map(|file| {
            finding(
                Rule::UnsafeSchemaPath,
                label,
                format!("schema 文件名含路径分量（防逃逸）: {file}"),
            )
        })
        .collect()
}

/// R7：authoring 标识符 / per-kind 字符串字段语法。domain/version/id 拼进派生 module 名 / 文件路径
/// （见 codegen），owner 决定契约归属，http `path` 是鉴权挂载点、event `topic` 是 wire routing key
/// ——均须先收口形态，杜绝坏值流入生成路径 / 归属解析 / 路由注册。与 codegen 写盘前防逃逸守卫互为表里。
fn rule_ident_syntax(m: &ContractManifest, label: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if !is_safe_segment(&m.domain) {
        out.push(finding(
            Rule::IdentSyntax,
            label,
            format!(
                "domain 非法：须 [a-z0-9_]+、首字符 a-z 或 _、无路径分量，实为 {:?}",
                m.domain
            ),
        ));
    }
    if !is_version(&m.version) {
        out.push(finding(
            Rule::IdentSyntax,
            label,
            format!("version 非法：须 v{{N}}（如 v1），实为 {:?}", m.version),
        ));
    }
    if !is_dotted_id(&m.id) {
        out.push(finding(
            Rule::IdentSyntax,
            label,
            format!(
                "id 非法：须点分小写名（如 seed.echo / config.entry-upserted），实为 {:?}",
                m.id
            ),
        ));
    }
    if let ContractOwner::Domain(name) = &m.owner
        && !is_domain_name(name)
    {
        out.push(finding(
            Rule::IdentSyntax,
            label,
            format!(
                "owner 非法：须合法域名（[a-z][a-z0-9_]*，不可空 / 不可 _ 前缀保留段）或 _framework，实为 {name:?}"
            ),
        ));
    }
    // http `path`（若声明）：收口注入 / 逃逸面（鉴权挂载点）。
    if let Some(path) = &m.path
        && !is_safe_http_path(path)
    {
        out.push(finding(
            Rule::IdentSyntax,
            label,
            format!(
                "path 非法：须绝对路径（/ 开头、非 // 协议相对、非裸 /、无 .. 逃逸、无空白 / 控制符），实为 {path:?}"
            ),
        ));
    }
    // event `topic`（若声明）：是 wire routing key，须与 id 同点分小写形态。
    if let Some(topic) = &m.topic
        && !is_dotted_id(topic)
    {
        out.push(finding(
            Rule::IdentSyntax,
            label,
            format!("topic 非法：须点分小写名（如 seed.thing-happened），实为 {topic:?}"),
        ));
    }
    out
}

/// http path（per-kind）安全形态：绝对路径、非协议相对（`//`）、非裸 `/`、无 `..` 逃逸、无空白 / 控制符。
/// 不锁定 `/api/v{N}/{domain}` vs `/internal/v{N}` 命名空间（route 注册期管），仅收口注入 / 逃逸面。
fn is_safe_http_path(s: &str) -> bool {
    s.starts_with('/')
        && !s.starts_with("//")
        && s.len() > 1
        && !s.contains("..")
        && !s
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
}

/// R8：`lifecycle=active` ⇒ 按 kind 必填 **active 发布接线**字段（http path+method / event topic+delivery）。
/// draft/deprecated 豁免（种子 draft 不受约束）；command 无 per-kind 必填（request schema 由 R4 守）。
/// 每缺一项一条 finding。字段值形态由 R7 守。
///
/// **saga 不在此**：`[saga]` block 是 saga 契约的**结构语义**（saga.md governance），非「仅 active 生效的
/// 发布接线字段」，故 `kind=saga` 无条件必填（不论 lifecycle）由 R10 守——不混进本 active-only 集。
fn rule_perkind_active_fields(m: &ContractManifest, label: &str) -> Vec<Finding> {
    if m.lifecycle != Lifecycle::Active {
        return Vec::new();
    }
    let required: &[(&str, bool)] = match m.kind {
        ContractKind::Http => &[
            (FIELD_PATH, m.path.is_some()),
            (FIELD_METHOD, m.method.is_some()),
        ],
        ContractKind::Event => &[
            (FIELD_TOPIC, m.topic.is_some()),
            (FIELD_DELIVERY, m.delivery.is_some()),
        ],
        // saga block 无条件必填（R10）；command 无 per-kind 必填（R4）。
        ContractKind::Saga | ContractKind::Command => &[],
    };
    required
        .iter()
        .filter(|(_, present)| !present)
        .map(|(field, _)| {
            finding(
                Rule::PerKindActiveFields,
                label,
                format!(
                    "lifecycle=active 的 kind={} 契约缺 per-kind 必填字段 {field}（见 contracts/README.md §contract.toml 字段）",
                    m.kind.as_dir()
                ),
            )
        })
        .collect()
}

/// R9：per-kind 字段只允许出现在匹配 kind——错配（如 event 带 `path`、http 带 `[saga]`）会被
/// 后续派生 silently-ignored，故拒。不沿用 `Schemas`「只查必填、放任 stray」旧惯例（彻底性）。
fn rule_perkind_field_scope(m: &ContractManifest, label: &str) -> Vec<Finding> {
    // （字段名, 是否出现, 唯一合法 kind）
    let checks: [(&str, bool, ContractKind); 5] = [
        (FIELD_PATH, m.path.is_some(), ContractKind::Http),
        (FIELD_METHOD, m.method.is_some(), ContractKind::Http),
        (FIELD_TOPIC, m.topic.is_some(), ContractKind::Event),
        (FIELD_DELIVERY, m.delivery.is_some(), ContractKind::Event),
        (FIELD_SAGA, m.saga.is_some(), ContractKind::Saga),
    ];
    checks
        .iter()
        .filter(|(_, present, allowed)| *present && m.kind != *allowed)
        .map(|(field, _, allowed)| {
            finding(
                Rule::PerKindFieldScope,
                label,
                format!(
                    "per-kind 字段 {field} 仅允许 kind={}，实为 kind={}",
                    allowed.as_dir(),
                    m.kind.as_dir()
                ),
            )
        })
        .collect()
}

/// R10：saga 契约的 `[saga]` block 结构语义（saga.md governance，**无条件、不论 lifecycle**）：
/// `kind=saga` ⇒ 须有非空 block；block 存在即查良构——≥1 step、step name 合法非关键字 Rust 标识符
/// （`syn`，拒 raw `r#`）且唯一、outputSchema 非空。retry/timeout 非负与 compensationOrder 取值由
/// `manifest.rs` 类型层守（Hard），R10 不重复；step outputSchema 文件完整性由 R5/R6 经
/// `declared_schema_files()` 覆盖。非-saga kind 误带 `[saga]` 由 R9 拒（本规则只校验 block 内部）。
fn rule_saga_block(m: &ContractManifest, label: &str) -> Vec<Finding> {
    let Some(saga) = &m.saga else {
        // saga 契约缺 block：saga.md 要求 kind:saga 必有非空 saga block（无条件、不论 lifecycle）。
        if m.kind == ContractKind::Saga {
            return vec![finding(
                Rule::SagaBlock,
                label,
                "kind=saga 须声明非空 [saga] block（saga.md governance，无条件、不论 lifecycle）"
                    .to_string(),
            )];
        }
        return Vec::new();
    };
    let mut out = Vec::new();
    if saga.steps.is_empty() {
        out.push(finding(
            Rule::SagaBlock,
            label,
            "saga block 须至少声明一个 step".to_string(),
        ));
    }
    let mut seen = BTreeSet::new();
    for step in &saga.steps {
        let name = step.name.as_str();
        // `syn` 拒裸关键字 / 坏语法；额外拒 raw identifier（`r#fn`）——它是合法 `syn::Ident` 但
        // 不是干净的 step 名（流入 codegen 生成符号会带 `r#` 前缀歧义）。
        if name.starts_with("r#") || syn::parse_str::<syn::Ident>(name).is_err() {
            out.push(finding(
                Rule::SagaBlock,
                label,
                format!(
                    "saga step name 须为合法非关键字 Rust 标识符（拒 raw `r#`），实为 {name:?}"
                ),
            ));
        }
        if !seen.insert(name) {
            out.push(finding(
                Rule::SagaBlock,
                label,
                format!("saga step name 重复: {name:?}"),
            ));
        }
        if step.output_schema.is_empty() {
            out.push(finding(
                Rule::SagaBlock,
                label,
                format!("saga step {name:?} 的 outputSchema 不可为空"),
            ));
        }
    }
    out
}

/// R11：`lifecycle=active` 的 event 契约只能声明当前**可兑现**的投递语义。RSS outbox + 幂等消费者
/// 当前仅兑现 `at-least-once`（见 docs/rules/eventbus.md）；`at-most-once`/`exactly-once` broker 链路
/// 无运行时保证——active 契约声明它们会虚开语义承诺，故拒（能力落地前限 draft/deprecated 表达前瞻设计）。
/// 把 manifest.rs / README 的「不建议」升级为机器强制（对齐 cert-manager/k8s：active 资源不得声明系统不能兑现的能力）。
fn rule_active_delivery_supported(m: &ContractManifest, label: &str) -> Option<Finding> {
    if m.lifecycle != Lifecycle::Active || m.kind != ContractKind::Event {
        return None;
    }
    match m.delivery {
        Some(d) if d != Delivery::AtLeastOnce => Some(finding(
            Rule::ActiveDeliverySupported,
            label,
            format!(
                "active event 当前仅支持 delivery=at-least-once（outbox + 幂等消费者）；{} 暂无运行时保证，能力落地前限 draft/deprecated",
                d.as_wire()
            ),
        )),
        _ => None,
    }
}

/// 路径段（domain 用）：非空、全 `[a-z0-9_]`、首字符 `a-z` 或 `_`（容 `_seed` 等保留段，
/// 拒数字开头 / 大写 / `.`、`/`、`\` 等路径分量）。
fn is_safe_segment(s: &str) -> bool {
    matches!(s.bytes().next(), Some(b) if b.is_ascii_lowercase() || b == b'_')
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// 版本段：`v{N}`，N 为非空数字串。
fn is_version(s: &str) -> bool {
    matches!(s.strip_prefix('v'), Some(n) if !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// 点分 id：每段首字符 `a-z`、余 `[a-z0-9-]`（如 `seed.echo`、`config.entry-upserted`）。
/// 小写连字符同 RSS 事件命名约定（见 CLAUDE.md：`session.created` / `config.entry-upserted`），拒 camelCase。
fn is_dotted_id(s: &str) -> bool {
    !s.is_empty()
        && s.split('.').all(|seg| {
            matches!(seg.bytes().next(), Some(b) if b.is_ascii_lowercase())
                && seg
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// 域名（owner 用）：`[a-z][a-z0-9_]*`，非空、首字符字母（拒 `_` 前缀保留段与空串）。
fn is_domain_name(s: &str) -> bool {
    matches!(s.bytes().next(), Some(b) if b.is_ascii_lowercase())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::manifest::{
        CompensationOrder, Delivery, HttpMethod, Lifecycle, SagaBlock, SagaStep, Schemas,
    };
    use crate::testutil::unique_tmp;
    use rstest::rstest;
    use std::path::PathBuf;

    fn manifest(
        kind: ContractKind,
        level: ConsistencyLevel,
        owner: ContractOwner,
        schemas: Schemas,
    ) -> ContractManifest {
        ContractManifest {
            id: "seed.x".to_string(),
            kind,
            domain: "_seed".to_string(),
            version: "v1".to_string(),
            owner,
            consistency_level: level,
            lifecycle: Lifecycle::Draft,
            schemas,
            path: None,
            method: None,
            topic: None,
            delivery: None,
            saga: None,
        }
    }

    fn http_schemas() -> Schemas {
        Schemas {
            request: Some("request.schema.json".to_string()),
            response: Some("response.schema.json".to_string()),
            payload: None,
        }
    }

    fn payload_schemas() -> Schemas {
        Schemas {
            payload: Some("payload.schema.json".to_string()),
            ..Schemas::default()
        }
    }

    /// 合法 saga block（1 step、reverse、非负 duration）——R10 绿基线，红用例在其上变异。
    fn valid_saga_block() -> SagaBlock {
        SagaBlock {
            steps: vec![SagaStep {
                name: "reserve_funds".to_string(),
                output_schema: "reserve.schema.json".to_string(),
            }],
            compensation_order: CompensationOrder::Reverse,
            retry_millis: 1000,
            timeout_millis: 5000,
        }
    }

    /// saga 契约骨架（kind=saga / L3 / domain owner / payload schema），按需挂 saga block。
    fn saga_manifest(block: Option<SagaBlock>) -> ContractManifest {
        let mut m = manifest(
            ContractKind::Saga,
            ConsistencyLevel::WorkflowEventual,
            ContractOwner::Domain("billing".to_string()),
            payload_schemas(),
        );
        m.domain = "billing".to_string();
        m.id = "billing.checkout".to_string();
        m.saga = block;
        m
    }

    fn discovered(m: ContractManifest, dir: PathBuf) -> DiscoveredContract {
        DiscoveredContract {
            path_kind: m.kind.as_dir().to_string(),
            path_domain: m.domain.clone(),
            path_version: m.version.clone(),
            dir,
            manifest: m,
        }
    }

    #[test]
    fn green_http_contract_has_no_findings() -> anyhow::Result<()> {
        // anti-vacuity（正向）：全合法契约不产生任何 finding。
        let dir = unique_tmp("validate");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("request.schema.json"), "{}")?;
        std::fs::write(dir.join("response.schema.json"), "{}")?;
        let m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        let findings = validate_contract(&discovered(m, dir.clone()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(findings.is_empty(), "{findings:?}");
        Ok(())
    }

    #[test]
    fn r1_saga_must_be_workflow_eventual() {
        let m = manifest(
            ContractKind::Saga,
            ConsistencyLevel::LocalTx,
            ContractOwner::Domain("identity".to_string()),
            Schemas {
                payload: Some("payload.schema.json".to_string()),
                ..Schemas::default()
            },
        );
        let f = rule_saga_consistency(&m, "x");
        assert_eq!(f.as_ref().map(|f| f.rule), Some(Rule::SagaConsistency));
        assert_eq!(
            f.map(|f| f.subject),
            Some("x".to_string()),
            "subject 须为传入 label"
        );
    }

    #[test]
    fn r1_saga_l3_ok() {
        let m = manifest(
            ContractKind::Saga,
            ConsistencyLevel::WorkflowEventual,
            ContractOwner::Domain("identity".to_string()),
            Schemas {
                payload: Some("payload.schema.json".to_string()),
                ..Schemas::default()
            },
        );
        assert!(rule_saga_consistency(&m, "x").is_none());
    }

    #[test]
    fn r2_framework_command_rejected() {
        let m = manifest(
            ContractKind::Command,
            ConsistencyLevel::LocalTx,
            ContractOwner::Framework,
            Schemas {
                request: Some("request.schema.json".to_string()),
                ..Schemas::default()
            },
        );
        assert_eq!(
            rule_framework_kind(&m, "x").map(|f| f.rule),
            Some(Rule::FrameworkKind)
        );
    }

    /// R2 新增：kind=Saga + owner=Framework → 应触发 FrameworkKind。
    #[test]
    fn r2_framework_saga_rejected() {
        let m = manifest(
            ContractKind::Saga,
            ConsistencyLevel::WorkflowEventual,
            ContractOwner::Framework,
            Schemas {
                payload: Some("payload.schema.json".to_string()),
                ..Schemas::default()
            },
        );
        assert_eq!(
            rule_framework_kind(&m, "x").map(|f| f.rule),
            Some(Rule::FrameworkKind)
        );
    }

    #[test]
    fn r2_framework_http_ok_and_domain_command_ok() {
        let http = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        assert!(rule_framework_kind(&http, "x").is_none());
        let cmd = manifest(
            ContractKind::Command,
            ConsistencyLevel::LocalTx,
            ContractOwner::Domain("identity".to_string()),
            Schemas {
                request: Some("request.schema.json".to_string()),
                ..Schemas::default()
            },
        );
        assert!(rule_framework_kind(&cmd, "x").is_none());
    }

    /// R3 参数化：各段不符 / 三段全符。
    /// 每 case：(path_kind, path_domain, path_version, manifest_domain, manifest_version, expect_finding)
    #[rstest]
    // 全符 → 无 finding
    #[case("http", "_seed", "v1", "_seed", "v1", false)]
    // kind 段不符
    #[case("event", "_seed", "v1", "_seed", "v1", true)]
    // domain 段不符
    #[case("http", "other", "v1", "_seed", "v1", true)]
    // version 段不符
    #[case("http", "_seed", "v2", "_seed", "v1", true)]
    fn r3_path_match_parametrized(
        #[case] path_kind: &str,
        #[case] path_domain: &str,
        #[case] path_version: &str,
        #[case] manifest_domain: &str,
        #[case] manifest_version: &str,
        #[case] expect_finding: bool,
    ) {
        let m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        let mut c = discovered(m, PathBuf::from("/x"));
        c.manifest.domain = manifest_domain.to_string();
        c.manifest.version = manifest_version.to_string();
        c.path_kind = path_kind.to_string();
        c.path_domain = path_domain.to_string();
        c.path_version = path_version.to_string();
        let result = rule_path_match(&c, "x");
        assert_eq!(
            result.map(|f| f.rule),
            if expect_finding {
                Some(Rule::PathMismatch)
            } else {
                None
            }
        );
    }

    #[test]
    fn r4_command_needs_request() {
        let m = manifest(
            ContractKind::Command,
            ConsistencyLevel::LocalTx,
            ContractOwner::Domain("identity".to_string()),
            Schemas::default(), // 无 request
        );
        let findings = rule_schema_shape(&m, "x");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::SchemaShape);
        assert_eq!(findings[0].subject, "x", "subject 须为传入 label");
    }

    #[test]
    fn r4_saga_needs_payload() {
        let m = manifest(
            ContractKind::Saga,
            ConsistencyLevel::WorkflowEventual,
            ContractOwner::Domain("identity".to_string()),
            Schemas::default(), // 无 payload
        );
        let findings = rule_schema_shape(&m, "x");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::SchemaShape);
    }

    #[test]
    fn r4_http_missing_response_shape() {
        let m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            Schemas {
                request: Some("request.schema.json".to_string()),
                ..Schemas::default()
            },
        );
        let findings = rule_schema_shape(&m, "x");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::SchemaShape);
    }

    #[test]
    fn r4_event_needs_payload() {
        let m = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            ContractOwner::Framework,
            Schemas::default(),
        );
        let findings = rule_schema_shape(&m, "x");
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.rule == Rule::SchemaShape)
                .count(),
            1
        );
    }

    #[test]
    fn r5_missing_schema_file_detected() -> anyhow::Result<()> {
        let dir = unique_tmp("validate");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("request.schema.json"), "{}")?; // 只建 request，缺 response
        let m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        let findings = rule_schema_files_exist(&discovered(m, dir.clone()), "x");
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::MissingSchema);
        assert_eq!(findings[0].subject, "x", "subject 须为传入 label");
        Ok(())
    }

    #[test]
    fn r6_unsafe_schema_path_dotdot_rejected() {
        let m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            Schemas {
                request: Some("../x/request.schema.json".to_string()),
                response: Some("response.schema.json".to_string()),
                ..Schemas::default()
            },
        );
        let findings = rule_unsafe_schema_path(&m, "x");
        assert!(!findings.is_empty());
        assert!(findings.iter().all(|f| f.rule == Rule::UnsafeSchemaPath));
    }

    #[test]
    fn r6_safe_schema_path_ok() {
        let m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        let findings = rule_unsafe_schema_path(&m, "x");
        assert!(findings.is_empty());
    }

    /// R7 参数化红用例：domain/version/id 各非法形态须触发 IdentSyntax。
    /// case：(domain, version, id)
    #[rstest]
    #[case("../evil", "v1", "seed.echo")] // domain 含路径分量
    #[case("Bad", "v1", "seed.echo")] // domain 大写
    #[case("9x", "v1", "seed.echo")] // domain 数字开头
    #[case("_seed", "1", "seed.echo")] // version 非 v{N}
    #[case("_seed", "v", "seed.echo")] // version 缺数字
    #[case("_seed", "v1", "Seed.Echo")] // id 大写
    #[case("_seed", "v1", "")] // id 空
    #[case("_seed", "v1", "seed.")] // id 尾段空
    fn r7_ident_syntax_rejects_malformed(
        #[case] domain: &str,
        #[case] version: &str,
        #[case] id: &str,
    ) {
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        m.domain = domain.to_string();
        m.version = version.to_string();
        m.id = id.to_string();
        let findings = rule_ident_syntax(&m, "x");
        assert!(!findings.is_empty(), "应触发 IdentSyntax");
        assert!(findings.iter().all(|f| f.rule == Rule::IdentSyntax));
    }

    /// R7 owner 红用例：Domain 空串 / `_` 前缀保留段 / 大写须触发 IdentSyntax。
    #[rstest]
    #[case("")]
    #[case("_seed")]
    #[case("_framework")] // 作为 Domain 出现（非 sentinel 解析路径）须拒
    #[case("Bad")]
    fn r7_owner_domain_rejects_malformed(#[case] owner: &str) {
        let m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Domain(owner.to_string()),
            http_schemas(),
        );
        let findings = rule_ident_syntax(&m, "x");
        assert!(findings.iter().any(|f| f.rule == Rule::IdentSyntax));
    }

    /// R7 anti-vacuity（正向）：合法 framework / domain 契约不产生 IdentSyntax finding。
    #[test]
    fn r7_valid_fields_ok() {
        let fw = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        assert!(rule_ident_syntax(&fw, "x").is_empty());
        let dom = manifest(
            ContractKind::Command,
            ConsistencyLevel::LocalTx,
            ContractOwner::Domain("identity".to_string()),
            Schemas {
                request: Some("request.schema.json".to_string()),
                ..Schemas::default()
            },
        );
        assert!(rule_ident_syntax(&dom, "x").is_empty());
        // 连字符 id（RSS 事件命名约定，如 config.entry-upserted）须合法。
        let mut hyphen = dom.clone();
        hyphen.id = "config.entry-upserted".to_string();
        assert!(
            rule_ident_syntax(&hyphen, "x").is_empty(),
            "连字符 id 应合法"
        );
    }

    /// R7 path 红用例：非法 http path 形态须触发 IdentSyntax（收口注入 / 逃逸面）。
    #[rstest]
    #[case("")] // 空
    #[case("/")] // 裸 /
    #[case("relative/x")] // 非绝对
    #[case("//evil.com/x")] // 协议相对 URL
    #[case("/api/v1/../secret")] // .. 逃逸
    #[case("/api/v1/ x")] // 含空白
    fn r7_bad_path_rejected(#[case] path: &str) {
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        m.path = Some(path.to_string());
        let findings = rule_ident_syntax(&m, "x");
        assert!(
            findings.iter().any(|f| f.rule == Rule::IdentSyntax),
            "path {path:?} 应触发 IdentSyntax"
        );
    }

    /// R7 topic 红用例：非点分小写 topic 须触发 IdentSyntax（wire routing key 收口）。
    #[rstest]
    #[case("UPPER.case")]
    #[case("../evil")]
    #[case("trailing.")]
    fn r7_bad_topic_rejected(#[case] topic: &str) {
        let mut m = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            ContractOwner::Framework,
            payload_schemas(),
        );
        m.topic = Some(topic.to_string());
        let findings = rule_ident_syntax(&m, "x");
        assert!(
            findings.iter().any(|f| f.rule == Rule::IdentSyntax),
            "topic {topic:?} 应触发 IdentSyntax"
        );
    }

    /// R7 anti-vacuity：合法 path / topic 不触发。
    #[test]
    fn r7_valid_path_topic_ok() {
        let mut http = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        http.path = Some("/api/v1/_seed/echo".to_string());
        assert!(rule_ident_syntax(&http, "x").is_empty());
        let mut event = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            ContractOwner::Framework,
            payload_schemas(),
        );
        event.topic = Some("seed.thing-happened".to_string());
        assert!(rule_ident_syntax(&event, "x").is_empty());
    }

    // ── R8 PerKindActiveFields（active 必填）──────────────────────────────

    #[test]
    fn r8_active_http_missing_path_method() {
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        m.lifecycle = Lifecycle::Active; // 无 path/method
        let findings = rule_perkind_active_fields(&m, "x");
        assert_eq!(findings.len(), 2, "应缺 path + method 两项");
        assert!(findings.iter().all(|f| f.rule == Rule::PerKindActiveFields));
        assert!(
            findings.iter().all(|f| f.subject == "x"),
            "subject 须为 label"
        );
    }

    #[test]
    fn r8_active_event_missing_topic_delivery() {
        let mut m = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            ContractOwner::Framework,
            payload_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        let findings = rule_perkind_active_fields(&m, "x");
        assert_eq!(findings.len(), 2, "应缺 topic + delivery 两项");
        assert!(findings.iter().all(|f| f.rule == Rule::PerKindActiveFields));
    }

    #[test]
    fn r8_saga_block_not_active_field_but_r10_requires() {
        // F1：saga block 是结构语义、非「active 发布接线字段」——R8 不管（不论 lifecycle）；
        // 无条件必填由 R10 守。active saga 缺 block ⇒ R8 空、R10 报。
        let mut m = saga_manifest(None);
        m.lifecycle = Lifecycle::Active;
        assert!(
            rule_perkind_active_fields(&m, "x").is_empty(),
            "saga block 不应在 R8 active 集"
        );
        let r10 = rule_saga_block(&m, "x");
        assert_eq!(r10.len(), 1, "R10 应无条件要求 saga block");
        assert_eq!(r10[0].rule, Rule::SagaBlock);
    }

    #[test]
    fn r8_active_full_ok_and_draft_exempt() {
        // active http 全填 → 无 finding。
        let mut active = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        active.lifecycle = Lifecycle::Active;
        active.path = Some("/api/v1/_seed/echo".to_string());
        active.method = Some(HttpMethod::Post);
        assert!(rule_perkind_active_fields(&active, "x").is_empty());
        // draft 缺字段 → 豁免（种子 draft 不受约束）。
        let draft = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        assert!(rule_perkind_active_fields(&draft, "x").is_empty());
        // deprecated 缺字段 → 同豁免（注释声明的 deprecated 豁免须有 synthetic 绿证明）。
        let mut deprecated = draft.clone();
        deprecated.lifecycle = Lifecycle::Deprecated;
        assert!(rule_perkind_active_fields(&deprecated, "x").is_empty());
        // command active 无 per-kind 必填（request schema 由 R4 守）。
        let mut cmd = manifest(
            ContractKind::Command,
            ConsistencyLevel::LocalTx,
            ContractOwner::Domain("identity".to_string()),
            Schemas {
                request: Some("request.schema.json".to_string()),
                ..Schemas::default()
            },
        );
        cmd.lifecycle = Lifecycle::Active;
        assert!(rule_perkind_active_fields(&cmd, "x").is_empty());
    }

    #[test]
    fn r8_active_event_full_ok() {
        // anti-vacuity：active event 全填 topic+delivery → 无 finding。
        let mut m = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            ContractOwner::Framework,
            payload_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.topic = Some("seed.thing-happened".to_string());
        m.delivery = Some(Delivery::AtLeastOnce);
        assert!(rule_perkind_active_fields(&m, "x").is_empty());
    }

    #[test]
    fn r8_active_saga_full_ok() {
        // anti-vacuity：active saga 带 block → 无 finding（block 良构由 R10 单独守）。
        let mut m = saga_manifest(Some(valid_saga_block()));
        m.lifecycle = Lifecycle::Active;
        assert!(rule_perkind_active_fields(&m, "x").is_empty());
    }

    // ── R9 PerKindFieldScope（跨 kind 卫生）──────────────────────────────

    #[test]
    fn r9_event_with_http_field_rejected() {
        let mut m = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            ContractOwner::Framework,
            payload_schemas(),
        );
        m.path = Some("/api/v1/_seed/echo".to_string()); // path 仅 http 合法
        let findings = rule_perkind_field_scope(&m, "x");
        assert!(findings.iter().any(|f| f.rule == Rule::PerKindFieldScope));
    }

    #[test]
    fn r9_http_with_saga_block_rejected() {
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        m.saga = Some(valid_saga_block()); // [saga] 仅 saga 合法
        let findings = rule_perkind_field_scope(&m, "x");
        assert!(findings.iter().any(|f| f.rule == Rule::PerKindFieldScope));
    }

    #[test]
    fn r9_fields_in_right_kind_ok() {
        let mut http = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        http.path = Some("/api/v1/_seed/echo".to_string());
        http.method = Some(HttpMethod::Post);
        assert!(rule_perkind_field_scope(&http, "x").is_empty());
        let mut event = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            ContractOwner::Framework,
            payload_schemas(),
        );
        event.topic = Some("seed.thing-happened".to_string());
        event.delivery = Some(Delivery::AtLeastOnce);
        assert!(rule_perkind_field_scope(&event, "x").is_empty());
        assert!(rule_perkind_field_scope(&saga_manifest(Some(valid_saga_block())), "x").is_empty());
    }

    /// R9 参数化：per-kind 字段出现在错 kind 须触发 PerKindFieldScope。case：(kind, 字段名)
    #[rstest]
    #[case(ContractKind::Event, "method")]
    #[case(ContractKind::Saga, "method")]
    #[case(ContractKind::Command, "method")]
    #[case(ContractKind::Http, "topic")]
    #[case(ContractKind::Saga, "topic")]
    #[case(ContractKind::Command, "delivery")]
    #[case(ContractKind::Saga, "path")]
    #[case(ContractKind::Event, "[saga]")]
    #[case(ContractKind::Command, "[saga]")]
    fn r9_field_on_wrong_kind_rejected(#[case] kind: ContractKind, #[case] field: &str) {
        let mut m = manifest(
            kind,
            ConsistencyLevel::WorkflowEventual,
            ContractOwner::Domain("billing".to_string()),
            payload_schemas(),
        );
        match field {
            "path" => m.path = Some("/api/v1/billing/x".to_string()),
            "method" => m.method = Some(HttpMethod::Post),
            "topic" => m.topic = Some("billing.thing".to_string()),
            "delivery" => m.delivery = Some(Delivery::AtLeastOnce),
            "[saga]" => m.saga = Some(valid_saga_block()),
            _ => {} // 未知字段：不设 → 下方断言失败暴露（self-protecting，不 panic）
        }
        let findings = rule_perkind_field_scope(&m, "x");
        assert!(
            findings.iter().any(|f| f.rule == Rule::PerKindFieldScope),
            "{field} on {kind:?} 应触发 PerKindFieldScope"
        );
    }

    // ── R10 SagaBlock（内部良构）──────────────────────────────────────────

    #[test]
    fn r10_saga_zero_steps_rejected() {
        let mut b = valid_saga_block();
        b.steps.clear();
        let findings = rule_saga_block(&saga_manifest(Some(b)), "x");
        assert!(findings.iter().any(|f| f.rule == Rule::SagaBlock));
    }

    #[test]
    fn r10_saga_duplicate_step_rejected() {
        let mut b = valid_saga_block();
        b.steps.push(SagaStep {
            name: "reserve_funds".to_string(), // 与首 step 重名
            output_schema: "other.schema.json".to_string(),
        });
        let findings = rule_saga_block(&saga_manifest(Some(b)), "x");
        assert!(findings.iter().any(|f| f.rule == Rule::SagaBlock));
    }

    #[rstest]
    #[case("9bad")] // 数字开头
    #[case("bad-name")] // 连字符非 Rust 标识符
    #[case("")] // 空
    #[case("fn")] // Rust 关键字
    #[case("r#fn")] // raw identifier（合法 syn::Ident 但须拒）
    fn r10_saga_bad_ident_step_rejected(#[case] name: &str) {
        let mut b = valid_saga_block();
        b.steps[0].name = name.to_string();
        let findings = rule_saga_block(&saga_manifest(Some(b)), "x");
        assert!(
            findings.iter().any(|f| f.rule == Rule::SagaBlock),
            "step name {name:?} 应触发 SagaBlock"
        );
    }

    #[test]
    fn r10_saga_empty_output_schema_rejected() {
        let mut b = valid_saga_block();
        b.steps[0].output_schema = String::new();
        let findings = rule_saga_block(&saga_manifest(Some(b)), "x");
        assert!(findings.iter().any(|f| f.rule == Rule::SagaBlock));
    }

    #[test]
    fn r10_multiple_violations_each_reported() {
        // 同一 step 多重违规（非法 ident + 空 outputSchema）各报一条，互不吞没。
        let mut b = valid_saga_block();
        b.steps[0].name = "9bad".to_string();
        b.steps[0].output_schema = String::new();
        let findings = rule_saga_block(&saga_manifest(Some(b)), "x");
        assert_eq!(
            findings.len(),
            2,
            "非法 ident + 空 outputSchema 应各报一条，实得 {findings:?}"
        );
        assert!(findings.iter().all(|f| f.rule == Rule::SagaBlock));
    }

    #[test]
    fn r10_valid_saga_block_ok() {
        // anti-vacuity：合法 saga block 不产生 finding。
        assert!(rule_saga_block(&saga_manifest(Some(valid_saga_block())), "x").is_empty());
    }

    #[test]
    fn r10_saga_kind_requires_block_even_draft() {
        // F1：kind=saga 无条件须有 block（saga.md，不论 lifecycle）——draft saga 缺 block 也拒。
        let m = saga_manifest(None); // saga_manifest 默认 lifecycle=draft
        assert_eq!(m.lifecycle, Lifecycle::Draft);
        let findings = rule_saga_block(&m, "x");
        assert_eq!(findings.len(), 1, "draft saga 缺 block 也须报");
        assert_eq!(findings[0].rule, Rule::SagaBlock);
    }

    #[test]
    fn r10_non_saga_absent_block_ok() {
        // 非-saga kind 无 [saga] block → R10 不查（saga 结构语义只约束 saga kind；误带 block 由 R9 拒）。
        let http = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        assert!(rule_saga_block(&http, "x").is_empty());
    }

    // ── R11 ActiveDeliverySupported（active event 投递语义可兑现性）────────

    #[rstest]
    #[case(Delivery::AtMostOnce)]
    #[case(Delivery::ExactlyOnce)]
    fn r11_active_event_unsupported_delivery_rejected(#[case] delivery: Delivery) {
        let mut m = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            ContractOwner::Framework,
            payload_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.topic = Some("seed.thing-happened".to_string());
        m.delivery = Some(delivery);
        let f = rule_active_delivery_supported(&m, "x");
        assert_eq!(
            f.map(|f| f.rule),
            Some(Rule::ActiveDeliverySupported),
            "active event {delivery:?} 应被拒"
        );
    }

    #[test]
    fn r11_active_event_atleastonce_ok() {
        let mut m = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            ContractOwner::Framework,
            payload_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.topic = Some("seed.thing-happened".to_string());
        m.delivery = Some(Delivery::AtLeastOnce);
        assert!(rule_active_delivery_supported(&m, "x").is_none());
    }

    #[test]
    fn r11_draft_event_unsupported_delivery_ok() {
        // draft 可表达前瞻投递语义（R11 只管 active）。
        let mut m = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            ContractOwner::Framework,
            payload_schemas(),
        );
        m.delivery = Some(Delivery::ExactlyOnce); // 默认 draft
        assert!(rule_active_delivery_supported(&m, "x").is_none());
    }

    #[test]
    fn r11_non_event_active_ok() {
        // 非 event kind 不受 R11 约束。
        let mut http = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        http.lifecycle = Lifecycle::Active;
        http.path = Some("/api/v1/_seed/echo".to_string());
        http.method = Some(HttpMethod::Post);
        assert!(rule_active_delivery_supported(&http, "x").is_none());
    }

    // ── R5/R6 扩展：saga step outputSchema 纳入 schema 文件完整性 ──────────

    #[test]
    fn r5_saga_step_schema_missing_detected() -> anyhow::Result<()> {
        let dir = unique_tmp("validate");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("payload.schema.json"), "{}")?; // 建 payload，缺 saga step schema
        let m = saga_manifest(Some(valid_saga_block()));
        let findings = rule_schema_files_exist(&discovered(m, dir.clone()), "x");
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(findings.len(), 1, "缺 reserve.schema.json 一条");
        assert_eq!(findings[0].rule, Rule::MissingSchema);
        Ok(())
    }

    #[test]
    fn r6_saga_step_unsafe_schema_rejected() {
        let mut b = valid_saga_block();
        b.steps[0].output_schema = "../evil.schema.json".to_string();
        let findings = rule_unsafe_schema_path(&saga_manifest(Some(b)), "x");
        assert!(findings.iter().any(|f| f.rule == Rule::UnsafeSchemaPath));
    }

    // ── 全契约绿（active 全填）：anti-vacuity 正向 ────────────────────────

    #[test]
    fn green_active_http_contract_has_no_findings() -> anyhow::Result<()> {
        let dir = unique_tmp("validate");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("request.schema.json"), "{}")?;
        std::fs::write(dir.join("response.schema.json"), "{}")?;
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.path = Some("/api/v1/_seed/echo".to_string());
        m.method = Some(HttpMethod::Post);
        let findings = validate_contract(&discovered(m, dir.clone()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(findings.is_empty(), "{findings:?}");
        Ok(())
    }
}
