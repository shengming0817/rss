//! 契约元数据校验（R1–R5）——`cargo xtask contract validate`。
//!
//! INVARIANT: CONTRACT-FANOUT-01 — schema 引用完整性 + kind→形态一致（R4/R5）。
//! INVARIANT: CONTRACT-FREEZE-01（运行期部分）— 跨字段不变式（R1 saga⇒L3 / R2 framework⇒http|event）、
//! 路径↔字段一致（R3）、authoring 标识符语法（R7：domain/version/id/owner 在拼进派生路径 / module 名前先收口）。
//! Medium（CI 门）；每条规则配 synthetic red case（见 `#[cfg(test)]`），
//! anti-vacuity：全合法绿用例必过、各红用例必失。
//! Hard 类型层部分（字段集冻结、枚举解析拒绝）见 `manifest.rs`（CONTRACT-FREEZE-01）。
//!
//! 规则执行顺序（注释编号 = 执行先后）：
//!   R1 SagaConsistency → R2 FrameworkKind → R3 PathMismatch → R4 SchemaShape → R5 MissingSchema → R6 UnsafeSchemaPath → R7 IdentSyntax

use anyhow::Result;
use std::path::Path;

use super::manifest::{
    ConsistencyLevel, ContractKind, ContractManifest, ContractOwner, SCHEMA_KEY_PAYLOAD,
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
    /// R7：authoring 标识符（domain/version/id/owner）语法须先收口（拼进派生路径 / module 名前）。
    IdentSyntax,
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

/// 对单契约跑 R1–R6（执行顺序即编号顺序）。
pub(crate) fn validate_contract(c: &DiscoveredContract) -> Vec<Finding> {
    let label = c.dir.display().to_string();
    let mut findings = Vec::new();
    findings.extend(rule_saga_consistency(&c.manifest, &label));
    findings.extend(rule_framework_kind(&c.manifest, &label));
    findings.extend(rule_path_match(c, &label));
    findings.extend(rule_schema_shape(&c.manifest, &label));
    findings.extend(rule_schema_files_exist(c, &label));
    findings.extend(rule_unsafe_schema_path(&c.manifest, &label));
    findings.extend(rule_ident_syntax(&c.manifest, &label));
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

/// R5：声明的每个 schema 文件须存在。
fn rule_schema_files_exist(c: &DiscoveredContract, label: &str) -> Vec<Finding> {
    c.manifest
        .schemas
        .declared_files()
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
/// 防逃逸判定单源见 `crate::pathsafe`（codegen 写盘守卫同源）。
fn rule_unsafe_schema_path(m: &ContractManifest, label: &str) -> Vec<Finding> {
    m.schemas
        .declared_files()
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

/// R7：authoring 标识符语法。domain/version/id 拼进派生 module 名 / 文件路径（见 codegen），
/// owner 决定契约归属——四者须先收口形态，杜绝坏标识符流入生成路径或归属解析。
/// 与 codegen 写盘前防逃逸守卫互为表里（author 端报友好错，codegen 端兜底自守）。
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
    out
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
    use crate::contract::manifest::{Lifecycle, Schemas};
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
        }
    }

    fn http_schemas() -> Schemas {
        Schemas {
            request: Some("request.schema.json".to_string()),
            response: Some("response.schema.json".to_string()),
            payload: None,
        }
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
}
