//! 契约元数据校验（R1–R5）——`cargo xtask contract validate`。
//!
//! INVARIANT: CONTRACT-FANOUT-01 — schema 引用完整性 + kind→形态一致（R4/R5）。
//! INVARIANT: CONTRACT-FREEZE-01（运行期部分）— 跨字段不变式（R1 saga⇒L3 / R2 framework⇒http|event）
//! 与路径↔字段一致（R3）。Medium（CI 门）；每条规则配 synthetic red case（见 `#[cfg(test)]`），
//! anti-vacuity：全合法绿用例必过、各红用例必失。

use anyhow::{Result, bail};
use std::path::Path;

use super::manifest::{ConsistencyLevel, ContractKind, ContractManifest, ContractOwner};
use super::{DiscoveredContract, discover};

/// 被违反的规则（供测试精确断言）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// R1：`kind = saga` ⇒ `consistencyLevel = WorkflowEventual`。
    SagaConsistency,
    /// R2：`owner = _framework` ⇒ `kind ∈ {http, event}`。
    FrameworkKind,
    /// R3：磁盘段 `{kind}/{domain}/{version}` 须等于 manifest 字段。
    PathMismatch,
    /// R4：声明的每个 schema 文件须存在于契约目录。
    MissingSchema,
    /// R5：kind→schema 形态须一致（http 需 request+response、event/saga 需 payload、command 需 request）。
    SchemaShape,
}

/// 单条校验失败。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub rule: Rule,
    pub contract: String,
    pub detail: String,
}

/// 入口：校验真实仓 `contracts/`，有失败则 `bail`。
pub fn run() -> Result<()> {
    let contracts_root = crate::workspace_root()?.join("contracts");
    let (count, findings) = validate_root(&contracts_root)?;
    if findings.is_empty() {
        eprintln!("contract validate: {count} 契约全部通过");
        return Ok(());
    }
    for f in &findings {
        eprintln!("  [{:?}] {}: {}", f.rule, f.contract, f.detail);
    }
    bail!("contract validate: {} 项校验失败", findings.len());
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

/// 对单契约跑 R1–R5。
pub(crate) fn validate_contract(c: &DiscoveredContract) -> Vec<Finding> {
    let label = c.dir.display().to_string();
    let mut findings = Vec::new();
    findings.extend(rule_saga_consistency(&c.manifest, &label));
    findings.extend(rule_framework_kind(&c.manifest, &label));
    findings.extend(rule_path_match(c, &label));
    findings.extend(rule_schema_shape(&c.manifest, &label));
    findings.extend(rule_schema_files_exist(c, &label));
    findings
}

fn finding(rule: Rule, label: &str, detail: impl Into<String>) -> Finding {
    Finding {
        rule,
        contract: label.to_string(),
        detail: detail.into(),
    }
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

/// R5：kind→schema 形态一致。返回缺失的必需 schema 声明（可多条）。
fn rule_schema_shape(m: &ContractManifest, label: &str) -> Vec<Finding> {
    let s = &m.schemas;
    let required: &[(&str, bool)] = match m.kind {
        ContractKind::Http => &[
            ("request", s.request.is_some()),
            ("response", s.response.is_some()),
        ],
        ContractKind::Event | ContractKind::Saga => &[("payload", s.payload.is_some())],
        ContractKind::Command => &[("request", s.request.is_some())],
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

/// R4：声明的每个 schema 文件须存在。
fn rule_schema_files_exist(c: &DiscoveredContract, label: &str) -> Vec<Finding> {
    declared_schema_files(&c.manifest.schemas)
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

fn declared_schema_files(s: &super::manifest::Schemas) -> Vec<&str> {
    [
        s.request.as_deref(),
        s.response.as_deref(),
        s.payload.as_deref(),
    ]
    .into_iter()
    .flatten()
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::manifest::{Lifecycle, Schemas};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    fn unique_tmp() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("rss-xtask-validate-{}-{n}", std::process::id()))
    }

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
        let dir = unique_tmp();
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
        assert_eq!(f.map(|f| f.rule), Some(Rule::SagaConsistency));
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

    #[test]
    fn r3_path_mismatch_detected() {
        let m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        let mut c = discovered(m, PathBuf::from("/x"));
        c.path_domain = "other".to_string(); // 段 ≠ 字段 _seed
        assert_eq!(
            rule_path_match(&c, "x").map(|f| f.rule),
            Some(Rule::PathMismatch)
        );
    }

    #[test]
    fn r4_missing_schema_file_detected() -> anyhow::Result<()> {
        let dir = unique_tmp();
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
        Ok(())
    }

    #[test]
    fn r5_http_missing_response_shape() {
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
    fn r5_event_needs_payload() {
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
}
