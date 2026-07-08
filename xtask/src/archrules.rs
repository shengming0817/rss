//! ArchRules 派生索引：从真实 carrier 的 `INVARIANT:` 锚点反推出 rule → carrier → evidence → gate。
//!
//! INVARIANT: ARCHRULES-DERIVED-INDEX-01 { level = "Medium", exec = "verify", source = "code" } —— 本模块只扫描真实 carrier（代码 / 配置 / UI golden /
//! baseline），不引入手写规则目录；文档仅作为 `doc_ref`。
//! INVARIANT: ARCHRULES-VERIFY-GATE-01 { level = "Medium", exec = "verify", source = "code" } —— [`ArchRules`] 作为 no-compile governance gate 接入 verify/ci，
//! 缺 carrier / fixture / gate 证据时 fail-closed。

use crate::diagnostic::{Finding, GovernanceCheck, finding};
use crate::workspace_root;
use anyhow::{Context, Result};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    EmptyIndex,
    InvalidInvariantId,
    DocsOnlyInvariant,
    DylintRegistryDrift,
    MissingCarrier,
    MissingInvariant,
    MissingUiGolden,
    OrphanUiGolden,
    MissingGate,
    MissingAntiVacuity,
    MissingInvariantMetadata,
    InvalidInvariantMetadata,
    CarrierBindingMismatch,
    MissingNativeHardSource,
}

pub(crate) struct ArchRules;

impl GovernanceCheck for ArchRules {
    type Rule = Rule;

    fn name(&self) -> &'static str {
        "archrules"
    }

    fn check(&self) -> Result<(String, Vec<Finding<Rule>>)> {
        check_root(&workspace_root()?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuleRecord {
    id: String,
    level: RuleLevel,
    exec: ExecutionLevel,
    source_kind: SourceKind,
    carrier: String,
    source: String,
    evidence: String,
    gate: String,
    status: String,
}

#[derive(Debug, Default)]
struct Index {
    records: Vec<RuleRecord>,
    findings: Vec<Finding<Rule>>,
}

pub(crate) fn list() -> Result<()> {
    let root = workspace_root()?;
    let index = build_index(&root)?;
    println!("id | level | exec | source_kind | carrier | source | evidence | gate | status");
    for record in &index.records {
        println!(
            "{} | {} | {} | {} | {} | {} | {} | {} | {}",
            record.id,
            record.level.as_str(),
            record.exec.as_str(),
            record.source_kind.as_str(),
            record.carrier,
            record.source,
            record.evidence,
            record.gate,
            record.status
        );
    }
    if !index.findings.is_empty() {
        eprintln!(
            "archrules: {} 项诊断（list 仅展示，verify 会失败）",
            index.findings.len()
        );
        crate::diagnostic::print_findings(&index.findings);
    }
    Ok(())
}

fn check_root(root: &Path) -> Result<(String, Vec<Finding<Rule>>)> {
    let index = build_index(root)?;
    let summary = format!("{} 条规则索引", index.records.len());
    Ok((summary, index.findings))
}

fn build_index(root: &Path) -> Result<Index> {
    let mut index = Index::default();
    scan_xtask(root, &mut index)?;
    scan_dylint(root, &mut index)?;
    scan_config(root, &mut index, "deny.toml", "deny", "verify,ci,audit")?;
    scan_config(root, &mut index, "clippy.toml", "clippy", "verify,ci")?;
    scan_public_api(root, &mut index)?;
    scan_source_invariants(root, &mut index)?;
    scan_trybuild_and_native(root, &mut index)?;
    check_docs_only(root, &mut index)?;
    require_anti_vacuity(&mut index);
    if index.records.is_empty() {
        index.findings.push(finding(
            Rule::EmptyIndex,
            rel(root, root),
            "未从真实 carrier 派生出任何规则",
        ));
    }
    index.records.sort_by(|a, b| {
        a.id.cmp(&b.id)
            .then_with(|| a.carrier.cmp(&b.carrier))
            .then_with(|| a.source.cmp(&b.source))
    });
    Ok(index)
}

fn scan_xtask(root: &Path, index: &mut Index) -> Result<()> {
    let src = root.join("xtask/src");
    for path in rust_files_under(&src)? {
        if path.ends_with("xtask/src/publicapi.rs") {
            continue;
        }
        let gate = xtask_gate(root, &path);
        scan_invariant_file(root, index, &path, "xtask", xtask_evidence(&path), gate)?;
    }
    Ok(())
}

fn scan_public_api(root: &Path, index: &mut Index) -> Result<()> {
    let baseline_dir = root.join("public-api");
    let target_crates = crate::publicapi::target_crates(None);
    let mut missing = Vec::new();
    for krate in &target_crates {
        if !baseline_dir.join(format!("{krate}.txt")).exists() {
            missing.push(*krate);
        }
    }
    if !missing.is_empty() {
        index.findings.push(finding(
            Rule::MissingCarrier,
            "public-api",
            format!("缺 public-api baseline: {}", missing.join(", ")),
        ));
        return Ok(());
    }
    let path = root.join("xtask/src/publicapi.rs");
    scan_invariant_file(
        root,
        index,
        &path,
        "public-api",
        format!("{} baseline", target_crates.len()),
        Some("ci,standalone"),
    )
}

fn scan_source_invariants(root: &Path, index: &mut Index) -> Result<()> {
    for base in ["crates", "adapters", "assemblies", "bins", "journeys"] {
        let dir = root.join(base);
        if !dir.exists() {
            continue;
        }
        for path in rust_files_under(&dir)? {
            let path_str = rel(root, &path);
            if path_str.contains("/tests/ui/") || path_str.contains("/tests/trybuild") {
                continue;
            }
            let gate = if path_str == "assemblies/runtime/src/module.rs" {
                // Carries both native no-handoff and runtime-deps verify invariants.
                Some("verify,ci,manual/opt-in,native-compile")
            } else if path_str.contains("/tests/") {
                Some("verify,ci")
            } else {
                Some("manual/opt-in,native-compile")
            };
            scan_source_invariant_file(
                root,
                index,
                &path,
                "native-hard",
                "source invariant",
                gate,
            )?;
        }
    }
    Ok(())
}

fn scan_config(
    root: &Path,
    index: &mut Index,
    rel_path: &str,
    carrier: &str,
    gate: &'static str,
) -> Result<()> {
    let path = root.join(rel_path);
    if !path.exists() {
        index.findings.push(finding(
            Rule::MissingCarrier,
            rel_path,
            "配置 carrier 不存在",
        ));
        return Ok(());
    }
    scan_invariant_file(root, index, &path, carrier, "config", Some(gate))
}

fn scan_dylint(root: &Path, index: &mut Index) -> Result<()> {
    let registered = dylint_registered(root)?;
    let members = dylint_members(root)?;
    let registered_set = path_set(&registered);
    let member_set = path_set(&members);
    if registered_set != member_set {
        index.findings.push(finding(
            Rule::DylintRegistryDrift,
            "lints",
            format!(
                "root metadata {:?} != lints workspace {:?}",
                registered_set, member_set
            ),
        ));
    }

    for lint_path in registered {
        let lint_dir = root.join(&lint_path);
        let lint_name = lint_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("<invalid>");
        let manifest = lint_dir.join("Cargo.toml");
        let lib = lint_dir.join("src/lib.rs");
        if !manifest.exists() || !lib.exists() {
            index.findings.push(finding(
                Rule::MissingCarrier,
                rel(root, &lint_dir),
                "registered dylint 缺 Cargo.toml 或 src/lib.rs",
            ));
            continue;
        }

        let before = index.records.len();
        scan_invariant_file(
            root,
            index,
            &lib,
            "dylint",
            lint_name.to_string(),
            Some("verify,ci"),
        )?;
        if index.records.len() == before {
            index.findings.push(finding(
                Rule::MissingInvariant,
                rel(root, &lib),
                "registered dylint 缺 INVARIANT 锚点",
            ));
        }

        let ui_dir = lint_dir.join("ui");
        let ui_rs = list_files_with_ext(&ui_dir, "rs")?;
        let ui_stderr = list_files_with_ext(&ui_dir, "stderr")?;
        if ui_rs.is_empty() || ui_stderr.is_empty() {
            index.findings.push(finding(
                Rule::MissingUiGolden,
                rel(root, &ui_dir),
                "dylint UI fixture/golden 缺失",
            ));
            continue;
        }
        let rs_stems = stems(&ui_rs);
        let stderr_stems = stems(&ui_stderr);
        for stem in rs_stems.difference(&stderr_stems) {
            index.findings.push(finding(
                Rule::MissingUiGolden,
                rel(root, &ui_dir.join(format!("{stem}.rs"))),
                "UI fixture 缺同名 .stderr golden",
            ));
        }
        for stem in stderr_stems.difference(&rs_stems) {
            index.findings.push(finding(
                Rule::OrphanUiGolden,
                rel(root, &ui_dir.join(format!("{stem}.stderr"))),
                "orphan .stderr golden 缺同名 .rs",
            ));
        }
    }
    Ok(())
}

fn scan_trybuild_and_native(root: &Path, index: &mut Index) -> Result<()> {
    let fixtures = trybuild_fixtures(root)?;
    for base in ["crates", "adapters", "assemblies", "bins", "journeys"] {
        let dir = root.join(base);
        if !dir.exists() {
            continue;
        }
        for path in rust_files_under(&dir)? {
            let path_str = rel(root, &path);
            let has_trybuild_harness = file_contains(&path, "trybuild::TestCases")?;
            let is_trybuild = path_str.contains("/tests/ui/")
                || path_str.contains("/tests/trybuild")
                || has_trybuild_harness;
            let is_compile_fail_doc = !is_trybuild && file_contains(&path, "compile_fail")?;
            if !is_trybuild && !is_compile_fail_doc {
                continue;
            }
            let evidence = if is_trybuild {
                trybuild_evidence(root, index, &fixtures, &path)?
            } else {
                "compile_fail doctest".to_string()
            };
            let gate = if is_trybuild {
                Some("verify,ci")
            } else {
                Some("native-compile")
            };
            if is_trybuild {
                scan_invariant_file(root, index, &path, "native-hard", evidence, gate)?;
            } else {
                scan_native_compile_invariant_file(
                    root,
                    index,
                    &path,
                    "native-hard",
                    evidence,
                    gate,
                )?;
            }
        }
    }
    for stderr in fixtures.orphan_stderr {
        index.findings.push(finding(
            Rule::OrphanUiGolden,
            rel(root, &stderr),
            "trybuild orphan .stderr 缺同名 compile_fail fixture",
        ));
    }
    Ok(())
}

fn check_docs_only(root: &Path, index: &mut Index) -> Result<()> {
    let primary_ids: BTreeSet<String> = index.records.iter().map(|r| r.id.clone()).collect();
    for dir in [
        root.join("docs/rules"),
        root.join("docs/architecture"),
        root.join(".claude/rules/rss"),
    ] {
        if !dir.exists() {
            continue;
        }
        for path in markdown_files_under(&dir)? {
            for found in extract_invariants(root, &path)? {
                for rule in found.rules {
                    let id = rule.id;
                    if !primary_ids.contains(&id) {
                        index.findings.push(finding(
                            Rule::DocsOnlyInvariant,
                            found.source.clone(),
                            format!("文档 INVARIANT `{id}` 缺真实 carrier 锚点"),
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

fn require_anti_vacuity(index: &mut Index) {
    let has_dylint = index.records.iter().any(|r| r.carrier == "dylint");
    let has_xtask = index.records.iter().any(|r| r.carrier == "xtask");
    let has_config = index
        .records
        .iter()
        .any(|r| r.carrier == "deny" || r.carrier == "clippy");
    let has_public_or_native = index
        .records
        .iter()
        .any(|r| r.carrier == "public-api" || r.carrier == "native-hard");
    for (ok, subject, detail) in [
        (has_dylint, "dylint", "索引缺 dylint carrier"),
        (has_xtask, "xtask", "索引缺 xtask governance carrier"),
        (has_config, "config", "索引缺 deny/clippy 配置 carrier"),
        (
            has_public_or_native,
            "public-api/native-hard",
            "索引缺 public-api 或 native hard carrier",
        ),
    ] {
        if !ok {
            index
                .findings
                .push(finding(Rule::MissingAntiVacuity, subject, detail));
        }
    }
}

fn scan_invariant_file(
    root: &Path,
    index: &mut Index,
    path: &Path,
    carrier: &str,
    evidence: impl Into<String>,
    gate: Option<&'static str>,
) -> Result<()> {
    scan_invariant_file_filtered(root, index, path, carrier, evidence, gate, |_| true)
}

fn scan_native_compile_invariant_file(
    root: &Path,
    index: &mut Index,
    path: &Path,
    carrier: &str,
    evidence: impl Into<String>,
    gate: Option<&'static str>,
) -> Result<()> {
    scan_invariant_file_filtered(root, index, path, carrier, evidence, gate, |rule| {
        rule.metadata
            .as_ref()
            .is_none_or(|metadata| metadata.exec == ExecutionLevel::NativeCompile)
    })
}

fn scan_invariant_file_filtered(
    root: &Path,
    index: &mut Index,
    path: &Path,
    carrier: &str,
    evidence: impl Into<String>,
    gate: Option<&'static str>,
    mut include_rule: impl FnMut(&FoundRule) -> bool,
) -> Result<()> {
    if !path.exists() {
        index.findings.push(finding(
            Rule::MissingCarrier,
            rel(root, path),
            "carrier 文件不存在",
        ));
        return Ok(());
    }
    let evidence = evidence.into();
    let gate_text = gate.unwrap_or("missing").to_string();
    let status = if gate.is_some() { "ok" } else { "missing-gate" }.to_string();
    let found_invariants = extract_invariants(root, path)?;
    for found in &found_invariants {
        for invalid in &found.invalid {
            let rule = if invalid.starts_with("metadata-") {
                Rule::InvalidInvariantMetadata
            } else {
                Rule::InvalidInvariantId
            };
            index.findings.push(finding(
                rule,
                found.source.clone(),
                if invalid.starts_with("metadata-") {
                    format!("非法 INVARIANT metadata `{invalid}`")
                } else {
                    format!("非法 INVARIANT id `{invalid}`")
                },
            ));
        }
        for rule in found.rules.iter().filter(|rule| include_rule(rule)) {
            let Some(metadata) = validated_metadata(index, &found.source, carrier, gate, rule)
            else {
                continue;
            };
            index.records.push(RuleRecord {
                id: rule.id.clone(),
                level: metadata.level,
                exec: metadata.exec,
                source_kind: metadata.source_kind,
                carrier: carrier.to_string(),
                source: found.source.clone(),
                evidence: evidence.clone(),
                gate: gate_text.clone(),
                status: status.clone(),
            });
        }
    }
    if gate.is_none() && !found_invariants.is_empty() {
        index.findings.push(finding(
            Rule::MissingGate,
            rel(root, path),
            "carrier 缺 gate 证据",
        ));
    }
    Ok(())
}

fn scan_source_invariant_file(
    root: &Path,
    index: &mut Index,
    path: &Path,
    carrier: &str,
    evidence: impl Into<String>,
    gate: Option<&'static str>,
) -> Result<()> {
    if !path.exists() {
        index.findings.push(finding(
            Rule::MissingCarrier,
            rel(root, path),
            "carrier 文件不存在",
        ));
        return Ok(());
    }
    let evidence = evidence.into();
    let gate_text = gate.unwrap_or("missing").to_string();
    let status = if gate.is_some() { "ok" } else { "missing-gate" }.to_string();
    let found_invariants = extract_source_invariants(root, path)?;
    for found in &found_invariants {
        for invalid in &found.invalid {
            let rule = if invalid.starts_with("metadata-") {
                Rule::InvalidInvariantMetadata
            } else {
                Rule::InvalidInvariantId
            };
            index.findings.push(finding(
                rule,
                found.source.clone(),
                if invalid.starts_with("metadata-") {
                    format!("非法 INVARIANT metadata `{invalid}`")
                } else {
                    format!("非法 INVARIANT id `{invalid}`")
                },
            ));
        }
        for rule in &found.rules {
            let Some(metadata) = validated_metadata(index, &found.source, carrier, gate, rule)
            else {
                continue;
            };
            index.records.push(RuleRecord {
                id: rule.id.clone(),
                level: metadata.level,
                exec: metadata.exec,
                source_kind: metadata.source_kind,
                carrier: carrier.to_string(),
                source: found.source.clone(),
                evidence: evidence.clone(),
                gate: gate_text.clone(),
                status: status.clone(),
            });
        }
    }
    if gate.is_none() && !found_invariants.is_empty() {
        index.findings.push(finding(
            Rule::MissingGate,
            rel(root, path),
            "carrier 缺 gate 证据",
        ));
    }
    Ok(())
}

fn validated_metadata(
    index: &mut Index,
    source: &str,
    carrier: &str,
    gate: Option<&str>,
    rule: &FoundRule,
) -> Option<InvariantMetadata> {
    let Some(metadata) = rule.metadata.clone() else {
        index.findings.push(finding(
            Rule::MissingInvariantMetadata,
            source.to_string(),
            format!("INVARIANT `{}` 缺结构化 metadata", rule.id),
        ));
        return None;
    };
    if !metadata.exec.is_bound_to_gate(gate) {
        index.findings.push(finding(
            Rule::CarrierBindingMismatch,
            source.to_string(),
            format!(
                "INVARIANT `{}` exec `{}` 未绑定到 gate `{}`",
                rule.id,
                metadata.exec.as_str(),
                gate.unwrap_or("missing")
            ),
        ));
    }
    if !metadata.source_kind.is_valid_for_carrier(carrier) {
        index.findings.push(finding(
            Rule::CarrierBindingMismatch,
            source.to_string(),
            format!(
                "INVARIANT `{}` source `{}` 与 carrier `{}` 不匹配",
                rule.id,
                metadata.source_kind.as_str(),
                carrier
            ),
        ));
    }
    if !metadata.level.is_valid_for_binding(&metadata, carrier) {
        index.findings.push(finding(
            Rule::CarrierBindingMismatch,
            source.to_string(),
            format!(
                "INVARIANT `{}` level `{}` 不能由 carrier `{}` exec `{}` source `{}` 声明",
                rule.id,
                metadata.level.as_str(),
                carrier,
                metadata.exec.as_str(),
                metadata.source_kind.as_str()
            ),
        ));
    }
    if metadata.level == RuleLevel::Hard
        && metadata.exec == ExecutionLevel::NativeCompile
        && !metadata.source_kind.is_native_compile_source()
    {
        index.findings.push(finding(
            Rule::MissingNativeHardSource,
            source.to_string(),
            format!(
                "INVARIANT `{}` native-compile Hard 只能声明 code/rustdoc source",
                rule.id
            ),
        ));
    }
    if metadata.level == RuleLevel::Hard
        && metadata.exec == ExecutionLevel::NativeCompile
        && metadata
            .native
            .as_ref()
            .is_none_or(|value| value.trim().is_empty())
    {
        index.findings.push(finding(
            Rule::MissingNativeHardSource,
            source.to_string(),
            format!(
                "INVARIANT `{}` native-compile Hard 缺 native 证明说明",
                rule.id
            ),
        ));
    }
    Some(metadata)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FoundInvariant {
    source: String,
    rules: Vec<FoundRule>,
    invalid: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FoundRule {
    id: String,
    metadata: Option<InvariantMetadata>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleLevel {
    Hard,
    Medium,
}

impl RuleLevel {
    fn as_str(self) -> &'static str {
        match self {
            Self::Hard => "Hard",
            Self::Medium => "Medium",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "Hard" => Some(Self::Hard),
            "Medium" => Some(Self::Medium),
            _ => None,
        }
    }

    fn is_valid_for_binding(self, metadata: &InvariantMetadata, carrier: &str) -> bool {
        match self {
            Self::Medium => true,
            Self::Hard => {
                carrier == "native-hard"
                    && matches!(
                        (metadata.exec, metadata.source_kind),
                        (
                            ExecutionLevel::NativeCompile,
                            SourceKind::Code | SourceKind::Rustdoc
                        ) | (ExecutionLevel::Verify, SourceKind::Trybuild)
                    )
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecutionLevel {
    Verify,
    CiOnly,
    Integration,
    ManualOptIn,
    NativeCompile,
}

impl ExecutionLevel {
    fn as_str(self) -> &'static str {
        match self {
            Self::Verify => "verify",
            Self::CiOnly => "ci-only",
            Self::Integration => "integration",
            Self::ManualOptIn => "manual/opt-in",
            Self::NativeCompile => "native-compile",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "verify" => Some(Self::Verify),
            "ci-only" => Some(Self::CiOnly),
            "integration" => Some(Self::Integration),
            "manual/opt-in" => Some(Self::ManualOptIn),
            "native-compile" => Some(Self::NativeCompile),
            _ => None,
        }
    }

    fn is_bound_to_gate(self, gate: Option<&str>) -> bool {
        match self {
            Self::NativeCompile => gate_has(gate, "native-compile"),
            Self::ManualOptIn => gate_has(gate, "manual/opt-in"),
            Self::Verify => gate_has(gate, "verify"),
            Self::CiOnly => gate_has(gate, "ci"),
            Self::Integration => gate_has(gate, "integration"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceKind {
    Code,
    Rustdoc,
    Config,
    Dylint,
    Trybuild,
    PublicApi,
    Codegen,
}

impl SourceKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Code => "code",
            Self::Rustdoc => "rustdoc",
            Self::Config => "config",
            Self::Dylint => "dylint",
            Self::Trybuild => "trybuild",
            Self::PublicApi => "public-api",
            Self::Codegen => "codegen",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "code" => Some(Self::Code),
            "rustdoc" => Some(Self::Rustdoc),
            "config" => Some(Self::Config),
            "dylint" => Some(Self::Dylint),
            "trybuild" => Some(Self::Trybuild),
            "public-api" => Some(Self::PublicApi),
            "codegen" => Some(Self::Codegen),
            _ => None,
        }
    }

    fn is_native_compile_source(self) -> bool {
        matches!(self, Self::Code | Self::Rustdoc)
    }

    fn is_valid_for_carrier(self, carrier: &str) -> bool {
        match carrier {
            "xtask" => matches!(self, Self::Code | Self::Codegen),
            "dylint" => self == Self::Dylint,
            "deny" | "clippy" => self == Self::Config,
            "public-api" => self == Self::PublicApi,
            "native-hard" => matches!(self, Self::Code | Self::Rustdoc | Self::Trybuild),
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InvariantMetadata {
    level: RuleLevel,
    exec: ExecutionLevel,
    source_kind: SourceKind,
    native: Option<String>,
}

fn extract_invariants(root: &Path, path: &Path) -> Result<Vec<FoundInvariant>> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("读取 INVARIANT carrier `{}`", path.display()))?;
    let mut out = Vec::new();
    for (line_idx, line) in text.lines().enumerate() {
        let Some(rest) = declarative_invariant_rest(path, line) else {
            continue;
        };
        push_found_invariant(root, path, line_idx, rest, &mut out);
    }
    Ok(out)
}

fn extract_source_invariants(root: &Path, path: &Path) -> Result<Vec<FoundInvariant>> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("读取 source INVARIANT carrier `{}`", path.display()))?;
    let mut out = Vec::new();
    for (line_idx, line) in text.lines().enumerate() {
        let Some(rest) = declarative_source_invariant_rest(path, line) else {
            continue;
        };
        if source_invariant_is_future_marker(rest) {
            push_future_marker_metadata_finding(root, path, line_idx, rest, &mut out);
            continue;
        }
        push_found_invariant(root, path, line_idx, rest, &mut out);
    }
    Ok(out)
}

fn push_found_invariant(
    root: &Path,
    path: &Path,
    line_idx: usize,
    rest: &str,
    out: &mut Vec<FoundInvariant>,
) {
    let (id_part, metadata_result) = split_metadata(rest);
    let tokens = invariant_tokens(id_part);
    let mut ids = Vec::new();
    let mut invalid = Vec::new();
    for token in tokens {
        if is_valid_rule_id(&token) {
            ids.push(token);
        } else if looks_like_rule_id(&token) {
            invalid.push(token);
        }
    }
    ids.sort();
    ids.dedup();
    invalid.sort();
    invalid.dedup();
    if ids.is_empty() && invalid.is_empty() {
        return;
    }
    let metadata = match &metadata_result {
        Ok(metadata) => metadata.clone(),
        Err(_) => None,
    };
    let mut rules: Vec<_> = ids
        .into_iter()
        .map(|id| FoundRule {
            id,
            metadata: metadata.clone(),
        })
        .collect();
    if let Err(invalid_metadata) = metadata_result {
        invalid.push(invalid_metadata);
    }
    rules.sort_by(|a, b| a.id.cmp(&b.id));
    out.push(FoundInvariant {
        source: format!("{}:{}", rel(root, path), line_idx + 1),
        rules,
        invalid,
    });
}

fn push_future_marker_metadata_finding(
    root: &Path,
    path: &Path,
    line_idx: usize,
    rest: &str,
    out: &mut Vec<FoundInvariant>,
) {
    let (id_part, metadata_result) = split_metadata(rest);
    let has_rule_id = invariant_tokens(id_part)
        .into_iter()
        .any(|token| is_valid_rule_id(&token) || looks_like_rule_id(&token));
    if !has_rule_id {
        return;
    }
    let invalid = match metadata_result {
        Ok(Some(_)) => Some("metadata-future-marker".to_string()),
        Ok(None) => None,
        Err(invalid) => Some(invalid),
    };
    let Some(invalid) = invalid else {
        return;
    };
    out.push(FoundInvariant {
        source: format!("{}:{}", rel(root, path), line_idx + 1),
        rules: Vec::new(),
        invalid: vec![invalid],
    });
}

fn split_metadata(rest: &str) -> (&str, Result<Option<InvariantMetadata>, String>) {
    let Some(start) = rest.find('{') else {
        return (rest, Ok(None));
    };
    let Some(end) = rest[start..].find('}').map(|offset| start + offset) else {
        return (
            &rest[..start],
            Err("metadata-missing-closing-brace".to_string()),
        );
    };
    let id_part = &rest[..start];
    let metadata = &rest[start + 1..end];
    (id_part, parse_metadata(metadata).map(Some))
}

fn parse_metadata(metadata: &str) -> Result<InvariantMetadata, String> {
    let value = format!("metadata = {{{metadata}}}")
        .parse::<toml::Value>()
        .map_err(|_| "metadata-invalid-toml".to_string())?;
    let table = value
        .get("metadata")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| "metadata-not-inline-table".to_string())?;
    let field = |name: &str| {
        table
            .get(name)
            .and_then(toml::Value::as_str)
            .ok_or_else(|| format!("metadata-missing-{name}"))
    };
    let level =
        RuleLevel::parse(field("level")?).ok_or_else(|| "metadata-invalid-level".to_string())?;
    let exec =
        ExecutionLevel::parse(field("exec")?).ok_or_else(|| "metadata-invalid-exec".to_string())?;
    let source_kind =
        SourceKind::parse(field("source")?).ok_or_else(|| "metadata-invalid-source".to_string())?;
    let native = table
        .get("native")
        .and_then(toml::Value::as_str)
        .map(str::to_string);
    Ok(InvariantMetadata {
        level,
        exec,
        source_kind,
        native,
    })
}

fn gate_has(gate: Option<&str>, lane: &str) -> bool {
    gate.unwrap_or_default()
        .split(',')
        .any(|token| token.trim() == lane)
}

fn declarative_source_invariant_rest<'a>(path: &Path, line: &'a str) -> Option<&'a str> {
    if path.extension().and_then(|s| s.to_str()) != Some("rs") {
        return None;
    }
    let mut trimmed = line.trim_start();
    for prefix in ["//!", "///", "//", "*"] {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            trimmed = rest.trim_start();
            break;
        }
    }
    let trimmed = trimmed
        .trim_start_matches('#')
        .trim_start_matches('-')
        .trim_start()
        .trim_start_matches('*')
        .trim_start();
    let trimmed = trimmed.strip_prefix('`').unwrap_or(trimmed);
    trimmed.strip_prefix("INVARIANT:")
}

fn source_invariant_is_future_marker(rest: &str) -> bool {
    let markers = [
        "当前无机器门",
        "follow-up",
        "落地后",
        "随 ",
        " PR 落地",
        "待 ",
        "留 W",
    ];
    markers.iter().any(|marker| rest.contains(marker))
}

fn invariant_tokens(rest: &str) -> Vec<String> {
    rest.split(|c: char| {
        c.is_whitespace()
            || matches!(
                c,
                ',' | '，'
                    | '、'
                    | '/'
                    | '+'
                    | '·'
                    | '('
                    | ')'
                    | '（'
                    | '）'
                    | '['
                    | ']'
                    | '【'
                    | '】'
                    | '`'
                    | ':'
                    | '：'
                    | ';'
                    | '；'
                    | '—'
                    | '–'
            )
    })
    .map(|s| {
        s.trim_matches(|c: char| {
            matches!(
                c,
                '.' | '。'
                    | ','
                    | '，'
                    | '、'
                    | '\''
                    | '"'
                    | '“'
                    | '”'
                    | '*'
                    | '!'
                    | '！'
                    | '?'
                    | '？'
            )
        })
    })
    .filter(|s| !s.is_empty())
    .map(ToOwned::to_owned)
    .collect()
}

fn is_valid_rule_id(token: &str) -> bool {
    if token.starts_with("ADR-") {
        return false;
    }
    let Some((prefix, suffix)) = token.rsplit_once('-') else {
        return false;
    };
    suffix.len() == 2
        && suffix.bytes().all(|b| b.is_ascii_digit())
        && !prefix.is_empty()
        && prefix
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-')
        && prefix.bytes().any(|b| b.is_ascii_uppercase())
}

fn looks_like_rule_id(token: &str) -> bool {
    if token.starts_with("ADR-") {
        return false;
    }
    token.bytes().any(|b| b.is_ascii_uppercase())
        && token.contains('-')
        && token
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || matches!(c, '-' | '\'' | '′'))
}

fn declarative_invariant_rest<'a>(path: &Path, line: &'a str) -> Option<&'a str> {
    match path.extension().and_then(|s| s.to_str()) {
        Some("rs") => declarative_source_invariant_rest(path, line),
        Some("toml") => declarative_comment_invariant_rest(line, &["#"]),
        Some("sql") => declarative_comment_invariant_rest(line, &["--"]),
        Some("md") => line
            .find("INVARIANT:")
            .map(|pos| &line[pos + "INVARIANT:".len()..]),
        _ => declarative_comment_invariant_rest(line, &[]),
    }
}

fn declarative_comment_invariant_rest<'a>(line: &'a str, prefixes: &[&str]) -> Option<&'a str> {
    let mut trimmed = line.trim_start();
    if !prefixes.is_empty() {
        let mut matched = false;
        for prefix in prefixes {
            if let Some(rest) = trimmed.strip_prefix(prefix) {
                trimmed = rest.trim_start();
                matched = true;
                break;
            }
        }
        if !matched {
            return None;
        }
    }
    let trimmed = trimmed
        .trim_start_matches('#')
        .trim_start_matches('-')
        .trim_start()
        .trim_start_matches('*')
        .trim_start();
    let trimmed = trimmed.strip_prefix('`').unwrap_or(trimmed);
    trimmed.strip_prefix("INVARIANT:")
}

fn xtask_gate(root: &Path, path: &Path) -> Option<&'static str> {
    match rel(root, path).as_str() {
        "xtask/src/archrules.rs"
        | "xtask/src/assembly.rs"
        | "xtask/src/codegen.rs"
        | "xtask/src/command_symmetry.rs"
        | "xtask/src/contract_binding_guard.rs"
        | "xtask/src/consistency_fixtures.rs"
        | "xtask/src/defergate.rs"
        | "xtask/src/doc_contracts.rs"
        | "xtask/src/event_transport_guard.rs"
        | "xtask/src/inbox_cutover_guard.rs"
        | "xtask/src/layers.rs"
        | "xtask/src/layerdeps.rs"
        | "xtask/src/migrations.rs"
        | "xtask/src/pdpallow.rs"
        | "xtask/src/pg_tenant_tx_guard.rs"
        | "xtask/src/reconcile_outbox_command_guard.rs"
        | "xtask/src/runtime_baseline.rs"
        | "xtask/src/runtime_deps_guard.rs"
        | "xtask/src/schema_rls.rs"
        | "xtask/src/setlocal_funnel.rs"
        | "xtask/src/src_scan.rs"
        | "xtask/src/tenancy_closeout.rs"
        | "xtask/src/wsdeps.rs"
        | "xtask/src/contract/breaking.rs"
        | "xtask/src/contract/manifest.rs"
        | "xtask/src/contract/protection.rs"
        | "xtask/src/contract/redaction.rs"
        | "xtask/src/contract/validate.rs"
        | "xtask/src/pathsafe.rs" => Some("verify,ci"),
        "xtask/src/coverage.rs" | "xtask/src/diffcov.rs" => Some("ci"),
        "xtask/src/publicapi.rs" => Some("ci,standalone"),
        "xtask/src/verify.rs" => Some("verify,ci,audit"),
        "xtask/src/cmd.rs" | "xtask/src/diagnostic.rs" => Some("manual/opt-in"),
        _ => None,
    }
}

fn xtask_evidence(path: &Path) -> String {
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown");
    format!("xtask module {name}")
}

#[derive(Debug, Default)]
struct TrybuildFixtures {
    compile_fail: BTreeSet<PathBuf>,
    pass: BTreeSet<PathBuf>,
    orphan_stderr: Vec<PathBuf>,
}

fn trybuild_fixtures(root: &Path) -> Result<TrybuildFixtures> {
    let mut fixtures = TrybuildFixtures::default();
    for base in ["crates", "adapters", "assemblies", "bins", "journeys"] {
        let dir = root.join(base);
        if !dir.exists() {
            continue;
        }
        for path in rust_files_under(&dir)? {
            let path_str = rel(root, &path);
            if !path_str.contains("/tests/") || !file_contains(&path, "trybuild::TestCases")? {
                continue;
            }
            let Some(crate_root) = crate_root_for_test_harness(&path) else {
                continue;
            };
            for call in trybuild_calls(&path)? {
                let expanded = expand_trybuild_pattern(&crate_root, &call.pattern)?;
                match call.kind {
                    TrybuildKind::CompileFail => fixtures.compile_fail.extend(expanded),
                    TrybuildKind::Pass => fixtures.pass.extend(expanded),
                }
            }
        }
    }
    let mut ui_dirs = BTreeSet::new();
    for path in fixtures.compile_fail.iter().chain(fixtures.pass.iter()) {
        if let Some(parent) = path.parent() {
            ui_dirs.insert(parent.to_path_buf());
        }
    }
    for dir in ui_dirs {
        for stderr in list_files_with_ext(&dir, "stderr")? {
            let rs = stderr.with_extension("rs");
            if !fixtures.compile_fail.contains(&rs) {
                fixtures.orphan_stderr.push(stderr);
            }
        }
    }
    fixtures.orphan_stderr.sort();
    Ok(fixtures)
}

#[derive(Debug, Clone, Copy)]
enum TrybuildKind {
    CompileFail,
    Pass,
}

#[derive(Debug)]
struct TrybuildCall {
    kind: TrybuildKind,
    pattern: String,
}

fn trybuild_calls(path: &Path) -> Result<Vec<TrybuildCall>> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("读取 trybuild harness `{}`", path.display()))?;
    let mut calls = Vec::new();
    for line in text.lines() {
        for (needle, kind) in [
            (".compile_fail(\"", TrybuildKind::CompileFail),
            (".pass(\"", TrybuildKind::Pass),
        ] {
            let Some(start) = line.find(needle) else {
                continue;
            };
            let rest = &line[start + needle.len()..];
            let Some(end) = rest.find('"') else {
                continue;
            };
            calls.push(TrybuildCall {
                kind,
                pattern: rest[..end].to_string(),
            });
        }
    }
    Ok(calls)
}

fn crate_root_for_test_harness(path: &Path) -> Option<PathBuf> {
    let components: Vec<_> = path.components().collect();
    let tests_pos = components
        .iter()
        .position(|c| c.as_os_str().to_str() == Some("tests"))?;
    let mut out = PathBuf::new();
    for component in &components[..tests_pos] {
        out.push(component.as_os_str());
    }
    Some(out)
}

fn expand_trybuild_pattern(crate_root: &Path, pattern: &str) -> Result<Vec<PathBuf>> {
    let path = crate_root.join(pattern);
    if !pattern.contains('*') {
        return Ok(vec![path]);
    }
    let Some(parent) = path.parent() else {
        return Ok(Vec::new());
    };
    let Some(file_pattern) = path.file_name().and_then(|s| s.to_str()) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    if file_pattern == "*.rs" {
        out.extend(list_files_with_ext(parent, "rs")?);
    }
    out.sort();
    Ok(out)
}

fn trybuild_evidence(
    root: &Path,
    index: &mut Index,
    fixtures: &TrybuildFixtures,
    path: &Path,
) -> Result<String> {
    if fixtures.compile_fail.contains(path) && !path.with_extension("stderr").exists() {
        index.findings.push(finding(
            Rule::MissingUiGolden,
            rel(root, path),
            "trybuild compile_fail fixture 缺同名 .stderr golden",
        ));
    }
    let stderr = path.with_extension("stderr");
    let evidence = if fixtures.compile_fail.contains(path) && stderr.exists() {
        format!("trybuild stderr {}", rel(root, &stderr))
    } else if fixtures.pass.contains(path) {
        "trybuild pass".to_string()
    } else {
        "trybuild pass/harness".to_string()
    };
    Ok(evidence)
}

fn dylint_registered(root: &Path) -> Result<Vec<PathBuf>> {
    let value = parse_toml(&root.join("Cargo.toml"))?;
    let Some(libraries) = value
        .get("workspace")
        .and_then(|v| v.get("metadata"))
        .and_then(|v| v.get("dylint"))
        .and_then(|v| v.get("libraries"))
        .and_then(toml::Value::as_array)
    else {
        return Ok(Vec::new());
    };
    Ok(libraries
        .iter()
        .filter_map(|v| v.get("path").and_then(toml::Value::as_str))
        .map(PathBuf::from)
        .collect())
}

fn dylint_members(root: &Path) -> Result<Vec<PathBuf>> {
    let value = parse_toml(&root.join("lints/Cargo.toml"))?;
    let Some(members) = value
        .get("workspace")
        .and_then(|v| v.get("members"))
        .and_then(toml::Value::as_array)
    else {
        return Ok(Vec::new());
    };
    Ok(members
        .iter()
        .filter_map(toml::Value::as_str)
        .map(|s| PathBuf::from("lints").join(s))
        .collect())
}

fn parse_toml(path: &Path) -> Result<toml::Value> {
    fs::read_to_string(path)
        .with_context(|| format!("读取 TOML `{}`", path.display()))?
        .parse::<toml::Value>()
        .with_context(|| format!("解析 TOML `{}`", path.display()))
}

fn path_set(paths: &[PathBuf]) -> BTreeSet<String> {
    paths
        .iter()
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .collect()
}

fn list_files_with_ext(dir: &Path, ext: &str) -> Result<Vec<PathBuf>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).with_context(|| format!("读取目录 `{}`", dir.display()))? {
        let path = entry?.path();
        if path.extension().and_then(|s| s.to_str()) == Some(ext) {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

fn stems(paths: &[PathBuf]) -> BTreeSet<String> {
    paths
        .iter()
        .filter_map(|p| p.file_stem().and_then(|s| s.to_str()))
        .map(ToOwned::to_owned)
        .collect()
}

fn rust_files_under(dir: &Path) -> Result<Vec<PathBuf>> {
    files_under(dir, "rs")
}

fn markdown_files_under(dir: &Path) -> Result<Vec<PathBuf>> {
    files_under(dir, "md")
}

fn files_under(dir: &Path, ext: &str) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    collect_files(dir, ext, &mut out)?;
    out.sort();
    Ok(out)
}

fn collect_files(dir: &Path, ext: &str, out: &mut Vec<PathBuf>) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(dir).with_context(|| format!("读取目录 `{}`", dir.display()))? {
        let path = entry?.path();
        let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if file_name == "target" || file_name == ".git" || file_name == "worktrees" {
            continue;
        }
        if path.is_dir() {
            collect_files(&path, ext, out)?;
        } else if path.extension().and_then(|s| s.to_str()) == Some(ext) {
            out.push(path);
        }
    }
    Ok(())
}

fn file_contains(path: &Path, needle: &str) -> Result<bool> {
    Ok(fs::read_to_string(path)
        .with_context(|| format!("读取 `{}`", path.display()))?
        .contains(needle))
}

fn rel(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::unique_tmp;
    use anyhow::Result;

    fn write(path: &Path, text: &str) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, text)?;
        Ok(())
    }

    fn rule_ids(found: &FoundInvariant) -> Vec<String> {
        found.rules.iter().map(|rule| rule.id.clone()).collect()
    }

    #[test]
    fn invariant_parser_extracts_multiple_ids_and_flags_bad_uppercase() -> Result<()> {
        let root = unique_tmp("archrules-ids");
        let file = root.join("xtask/src/demo.rs");
        write(
            &file,
            "//! INVARIANT: FOO-BAR-01 · BAZ-QUX-02 / BAD-ID-1 { level = \"Medium\", exec = \"verify\", source = \"code\" }\n",
        )?;
        let found = extract_invariants(&root, &file)?;
        assert_eq!(rule_ids(&found[0]), vec!["BAZ-QUX-02", "FOO-BAR-01"]);
        assert_eq!(found[0].invalid, vec!["BAD-ID-1"]);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn invariant_parser_ignores_adr_tokens() -> Result<()> {
        let root = unique_tmp("archrules-adr-token");
        let file = root.join("xtask/src/demo.rs");
        write(
            &file,
            "//! INVARIANT: LAYER-DEPS-ROUTE-FUNNEL-01，ADR-009 { level = \"Medium\", exec = \"verify\", source = \"code\" }\n",
        )?;
        let found = extract_invariants(&root, &file)?;
        assert_eq!(rule_ids(&found[0]), vec!["LAYER-DEPS-ROUTE-FUNNEL-01"]);
        assert!(found[0].invalid.is_empty(), "{:?}", found[0].invalid);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn invariant_parser_rejects_inline_reference_as_carrier_anchor() -> Result<()> {
        let root = unique_tmp("archrules-inline-reference");
        let file = root.join("lints/rss_demo/src/lib.rs");
        write(
            &file,
            "//! 上游类型系统保证（INVARIANT: REF-ONLY-01 { level = \"Medium\", exec = \"verify\", source = \"dylint\" }`crates/demo/src/lib.rs`）。\n",
        )?;
        let found = extract_invariants(&root, &file)?;
        assert!(found.is_empty(), "{found:?}");
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn invariant_parser_requires_structured_metadata_for_records() -> Result<()> {
        let root = unique_tmp("archrules-metadata");
        let file = root.join("xtask/src/demo.rs");
        write(&file, "//! INVARIANT: DEMO-MISSING-01\n")?;
        let mut index = Index::default();
        scan_invariant_file(&root, &mut index, &file, "xtask", "demo", Some("verify"))?;
        assert!(index.records.is_empty());
        assert!(
            index
                .findings
                .iter()
                .any(|f| f.rule == Rule::MissingInvariantMetadata),
            "{:?}",
            index.findings
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn invariant_parser_rejects_invalid_metadata_fields() -> Result<()> {
        let root = unique_tmp("archrules-bad-metadata");
        let file = root.join("xtask/src/demo.rs");
        write(
            &file,
            "//! INVARIANT: DEMO-BAD-01 { level = \"Soft\", exec = \"verify\", source = \"code\" }\n",
        )?;
        let found = extract_invariants(&root, &file)?;
        assert!(
            found[0]
                .invalid
                .contains(&"metadata-invalid-level".to_string()),
            "{:?}",
            found
        );
        let mut index = Index::default();
        scan_invariant_file(&root, &mut index, &file, "xtask", "demo", Some("verify"))?;
        assert!(
            index
                .findings
                .iter()
                .any(|f| f.rule == Rule::InvalidInvariantMetadata),
            "{:?}",
            index.findings
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn invariant_parser_rejects_exec_without_matching_gate() -> Result<()> {
        let root = unique_tmp("archrules-exec-binding");
        let file = root.join("xtask/src/demo.rs");
        write(
            &file,
            "//! INVARIANT: DEMO-CI-01 { level = \"Medium\", exec = \"ci-only\", source = \"code\" }\n",
        )?;
        let mut index = Index::default();
        scan_invariant_file(&root, &mut index, &file, "xtask", "demo", Some("verify"))?;
        assert!(
            index
                .findings
                .iter()
                .any(|f| f.rule == Rule::CarrierBindingMismatch),
            "{:?}",
            index.findings
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn hard_level_requires_native_or_trybuild_carrier() -> Result<()> {
        let root = unique_tmp("archrules-hard-binding");
        let file = root.join("xtask/src/demo.rs");
        write(
            &file,
            "//! INVARIANT: DEMO-HARD-01 { level = \"Hard\", exec = \"verify\", source = \"code\" }\n",
        )?;
        let mut index = Index::default();
        scan_invariant_file(&root, &mut index, &file, "xtask", "demo", Some("verify"))?;
        assert!(
            index
                .findings
                .iter()
                .any(|f| f.rule == Rule::CarrierBindingMismatch),
            "{:?}",
            index.findings
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn manual_opt_in_requires_manual_gate_binding() -> Result<()> {
        let root = unique_tmp("archrules-manual-binding");
        let file = root.join("xtask/src/demo.rs");
        write(
            &file,
            "//! INVARIANT: DEMO-MANUAL-01 { level = \"Medium\", exec = \"manual/opt-in\", source = \"code\" }\n",
        )?;
        let mut index = Index::default();
        scan_invariant_file(&root, &mut index, &file, "xtask", "demo", Some("verify"))?;
        assert!(
            index
                .findings
                .iter()
                .any(|f| f.rule == Rule::CarrierBindingMismatch),
            "{:?}",
            index.findings
        );

        let mut index = Index::default();
        scan_invariant_file(
            &root,
            &mut index,
            &file,
            "xtask",
            "demo",
            Some("manual/opt-in"),
        )?;
        assert!(index.findings.is_empty(), "{:?}", index.findings);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn native_compile_hard_requires_native_source_explanation() -> Result<()> {
        let root = unique_tmp("archrules-native-source");
        let file = root.join("crates/demo/src/lib.rs");
        write(
            &file,
            "//! INVARIANT: DEMO-HARD-01 { level = \"Hard\", exec = \"native-compile\", source = \"code\" }\n",
        )?;
        let mut index = Index::default();
        scan_source_invariant_file(
            &root,
            &mut index,
            &file,
            "native-hard",
            "source",
            Some("standalone"),
        )?;
        assert!(
            index
                .findings
                .iter()
                .any(|f| f.rule == Rule::MissingNativeHardSource),
            "{:?}",
            index.findings
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn invariant_parser_ignores_natural_language_after_marker() -> Result<()> {
        let root = unique_tmp("archrules-natural");
        let file = root.join("xtask/src/demo.rs");
        write(&file, "//! INVARIANT: 此处是解释，不是规则 ID。\n")?;
        assert!(extract_invariants(&root, &file)?.is_empty());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn dylint_registry_members_and_ui_golden_fail_closed() -> Result<()> {
        let root = unique_tmp("archrules-dylint");
        write(
            &root.join("Cargo.toml"),
            r#"
[workspace.metadata.dylint]
libraries = [{ path = "lints/rss_demo" }]
"#,
        )?;
        write(
            &root.join("lints/Cargo.toml"),
            r#"
[workspace]
members = ["rss_demo", "rss_orphan"]
"#,
        )?;
        write(
            &root.join("lints/rss_demo/Cargo.toml"),
            "[package]\nname = \"rss_demo\"\n",
        )?;
        write(
            &root.join("lints/rss_demo/src/lib.rs"),
            "//! INVARIANT: DEMO-LINT-01 { level = \"Medium\", exec = \"verify\", source = \"dylint\" }\n",
        )?;
        write(&root.join("lints/rss_demo/ui/main.rs"), "fn main() {}\n")?;
        let mut index = Index::default();
        scan_dylint(&root, &mut index)?;
        assert!(
            index
                .findings
                .iter()
                .any(|f| f.rule == Rule::DylintRegistryDrift)
        );
        assert!(
            index
                .findings
                .iter()
                .any(|f| f.rule == Rule::MissingUiGolden)
        );
        write(&root.join("lints/rss_demo/ui/main.stderr"), "error\n")?;
        write(&root.join("lints/rss_demo/ui/orphan.stderr"), "error\n")?;
        let mut index = Index::default();
        scan_dylint(&root, &mut index)?;
        assert!(
            index
                .findings
                .iter()
                .any(|f| f.rule == Rule::OrphanUiGolden)
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn docs_only_invariant_is_finding() -> Result<()> {
        let root = unique_tmp("archrules-docs-only");
        write(
            &root.join("docs/rules/demo.md"),
            "INVARIANT: DOCS-ONLY-01\n",
        )?;
        let mut index = Index::default();
        check_docs_only(&root, &mut index)?;
        assert_eq!(index.findings[0].rule, Rule::DocsOnlyInvariant);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn ordinary_source_invariant_does_not_satisfy_doc_reference() -> Result<()> {
        let root = unique_tmp("archrules-docs-primary-only");
        write(
            &root.join("crates/demo/src/lib.rs"),
            "//! INVARIANT: ORDINARY-SOURCE-01\n",
        )?;
        write(
            &root.join("docs/rules/demo.md"),
            "INVARIANT: ORDINARY-SOURCE-01\n",
        )?;
        let mut index = Index::default();
        check_docs_only(&root, &mut index)?;
        assert_eq!(index.findings[0].rule, Rule::DocsOnlyInvariant);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn source_invariants_ignore_prose_future_markers() -> Result<()> {
        let root = unique_tmp("archrules-source-future");
        let file = root.join("assemblies/runtime/src/module.rs");
        write(
            &file,
            "/// follow-up #1448，落地后再以 `INVARIANT: WIRING-DEPS-INFRA-ONLY-01` 收口。\n",
        )?;
        let mut index = Index::default();
        scan_source_invariants(&root, &mut index)?;
        assert!(index.records.is_empty(), "{:?}", index.records);
        assert!(index.findings.is_empty(), "{:?}", index.findings);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn source_invariants_require_declarative_carrier_line() -> Result<()> {
        let root = unique_tmp("archrules-source-declarative");
        let file = root.join("crates/primitives/src/crypto.rs");
        write(
            &file,
            "/// INVARIANT: CRYPTO-CONST-TIME-01 { level = \"Medium\", exec = \"manual/opt-in\", source = \"code\" } —— 实现必须常数时间。\n",
        )?;
        let mut index = Index::default();
        scan_source_invariants(&root, &mut index)?;
        assert!(
            index.records.iter().any(|r| r.id == "CRYPTO-CONST-TIME-01"),
            "{:?}",
            index.records
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn source_invariants_ignore_declarative_future_markers() -> Result<()> {
        let root = unique_tmp("archrules-source-future-declarative");
        let file = root.join("crates/primitives/src/crypto.rs");
        write(
            &file,
            "/// INVARIANT: CRYPTO-CONST-TIME-01 —— Medium 守卫随 crypto W 行为 PR 落地。\n",
        )?;
        let mut index = Index::default();
        scan_source_invariants(&root, &mut index)?;
        assert!(index.records.is_empty(), "{:?}", index.records);
        assert!(index.findings.is_empty(), "{:?}", index.findings);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn source_future_marker_with_structured_metadata_fails_closed() -> Result<()> {
        let root = unique_tmp("archrules-source-future-metadata");
        let file = root.join("crates/primitives/src/crypto.rs");
        write(
            &file,
            "/// INVARIANT: CRYPTO-CONST-TIME-01 { level = \"Medium\", exec = \"manual/opt-in\", source = \"code\" } —— Medium 守卫随 crypto W 行为 PR 落地。\n",
        )?;
        let mut index = Index::default();
        scan_source_invariants(&root, &mut index)?;
        assert!(index.records.is_empty(), "{:?}", index.records);
        assert!(
            index
                .findings
                .iter()
                .any(|f| f.rule == Rule::InvalidInvariantMetadata),
            "{:?}",
            index.findings
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn nested_xtask_contract_modules_have_verify_gate() {
        let root = Path::new("/repo");
        assert_eq!(
            xtask_gate(root, &root.join("xtask/src/contract/validate.rs")),
            Some("verify,ci")
        );
        assert_eq!(
            xtask_gate(root, &root.join("xtask/src/contract/breaking.rs")),
            Some("verify,ci")
        );
    }

    #[test]
    fn assembly_carrier_has_verify_ci_gate() {
        // assembly validate 在 verify.rs 的 verify 与 ci step 列表中均运行 ⇒ assembly.rs
        // 的 INVARIANT 锚点（ASSEMBLY-PROVIDER-CRATE-01）必须登记 `verify,ci` gate，否则
        // archrules 判 MissingGate（#1572）。gate 字符串 ↔ plan 实际成员的双向绑定由下方
        // `gate_strings_bound_to_verify_ci_plan_membership` 机器守（review F2 / #1574）。
        let root = Path::new("/repo");
        assert_eq!(
            xtask_gate(root, &root.join("xtask/src/assembly.rs")),
            Some("verify,ci")
        );
    }

    /// INVARIANT: ARCHRULES-GATE-PLAN-BIND-01 { level = "Medium", exec = "verify", source = "code" }—— `xtask_gate` 的 gate 字符串与 verify plan 成员资格
    /// 机器绑定：`full_plan` / `ci_plan` 中每个 in-process carrier 步（`Internal` / `ToolGatedInternal`），
    /// 其 carrier 文件的 `xtask_gate` 必须 token-含对应 lane（full→`verify`、ci→`ci`）。闭合 #1574——
    /// gate 字符串原为无机器校验的自由文本，既可相对 plan 漂移（plan 删步但 gate 仍声明），也可拼写错
    /// （如 `verfy`）；本绑定使二者皆门红。carrier→文件 由 verify.rs `InternalCheck::carrier_file` 穷举
    /// match 守（缺登记即编译失败）；gate 缺/错即 token 不含 lane 而红。anti-vacuity：断言至少校验过一个 carrier。
    /// 注：audit lane 不在此绑定——`audit_plan` 无 in-process carrier 步（仅外部 deny/audit `Tool`），
    /// gate 的 `audit` token 表「模块与 audit lane 相关」（如 verify.rs 自身），非精确 plan 成员，语义不同。
    #[test]
    fn gate_strings_bound_to_verify_ci_plan_membership() {
        let root = Path::new("/repo");
        let gate_has_lane = |file: &str, lane: &str| -> bool {
            xtask_gate(root, &root.join(file))
                .unwrap_or_default()
                .split(',')
                .any(|tok| tok.trim() == lane)
        };
        let mut checked = 0usize;
        for (plan, lane) in [
            (crate::verify::full_plan(), "verify"),
            (crate::verify::ci_plan(), "ci"),
        ] {
            for step in &plan {
                let Some(file) = step.carrier_file() else {
                    continue;
                };
                checked += 1;
                assert!(
                    gate_has_lane(file, lane),
                    "{file} 在 `{lane}` plan 中，但其 xtask_gate 未声明 `{lane}` lane（gate↔plan 漂移或拼写错）"
                );
            }
        }
        assert!(
            checked > 0,
            "未校验任何 carrier——plan 内省失效（anti-vacuity）"
        );
    }

    #[test]
    fn unknown_xtask_invariant_is_missing_gate() -> Result<()> {
        let root = unique_tmp("archrules-unknown-xtask");
        let file = root.join("xtask/src/new_guard.rs");
        write(
            &file,
            "//! INVARIANT: NEW-GUARD-01 { level = \"Medium\", exec = \"verify\", source = \"code\" }\n",
        )?;
        let mut index = Index::default();
        scan_xtask(&root, &mut index)?;
        assert!(
            index.findings.iter().any(|f| f.rule == Rule::MissingGate),
            "{:?}",
            index.findings
        );
        let record = index
            .records
            .iter()
            .find(|r| r.id == "NEW-GUARD-01")
            .ok_or_else(|| anyhow::anyhow!("NEW-GUARD-01 record missing"))?;
        assert_eq!(record.gate, "missing");
        assert_eq!(record.status, "missing-gate");
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn public_api_requires_every_target_baseline() -> Result<()> {
        let root = unique_tmp("archrules-public-api");
        for krate in crate::publicapi::target_crates(None).into_iter().skip(1) {
            write(&root.join(format!("public-api/{krate}.txt")), "baseline\n")?;
        }
        let mut index = Index::default();
        scan_public_api(&root, &mut index)?;
        assert!(
            index
                .findings
                .iter()
                .any(|f| f.rule == Rule::MissingCarrier),
            "{:?}",
            index.findings
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn trybuild_compile_fail_requires_stderr_but_pass_does_not() -> Result<()> {
        let root = unique_tmp("archrules-trybuild-golden");
        write(
            &root.join("crates/demo/tests/trybuild.rs"),
            r#"
fn ui() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/fail.rs");
    t.pass("tests/ui/pass.rs");
}
"#,
        )?;
        write(
            &root.join("crates/demo/tests/ui/fail.rs"),
            "//! INVARIANT: TRYBUILD-FAIL-01 { level = \"Hard\", exec = \"verify\", source = \"trybuild\" }\n",
        )?;
        write(
            &root.join("crates/demo/tests/ui/pass.rs"),
            "//! INVARIANT: TRYBUILD-PASS-01 { level = \"Hard\", exec = \"verify\", source = \"trybuild\" }\n",
        )?;
        let mut index = Index::default();
        scan_trybuild_and_native(&root, &mut index)?;
        assert!(
            index
                .findings
                .iter()
                .any(|f| f.rule == Rule::MissingUiGolden),
            "{:?}",
            index.findings
        );
        assert!(
            index
                .records
                .iter()
                .any(|r| r.id == "TRYBUILD-PASS-01" && r.evidence == "trybuild pass")
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn compile_fail_doctest_indexes_only_native_compile_rules() -> Result<()> {
        let root = unique_tmp("archrules-doctest-native-only");
        let file = root.join("crates/demo/src/lib.rs");
        let fixture = [
            "//! ```compile_fail\n",
            "//! demo::sealed::Hidden;\n",
            "//! ```\n",
            "//! INV",
            "ARIANT: DEMO-MANUAL-01 { level = \"Medium\", exec = \"manual/opt-in\", source = \"code\" }\n",
            "//! INV",
            "ARIANT: DEMO-NATIVE-01 { level = \"Hard\", exec = \"native-compile\", source = \"code\", native = \"private type boundary\" }\n",
        ]
        .concat();
        write(&file, &fixture)?;
        let mut index = Index::default();
        scan_trybuild_and_native(&root, &mut index)?;
        assert!(index.findings.is_empty(), "{:?}", index.findings);
        assert!(index.records.iter().any(|r| r.id == "DEMO-NATIVE-01"));
        assert!(
            index.records.iter().all(|r| r.id != "DEMO-MANUAL-01"),
            "{:?}",
            index.records
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn synthetic_root_derives_index_without_inventory() -> Result<()> {
        let root = unique_tmp("archrules-derived");
        write(
            &root.join("Cargo.toml"),
            r#"
[workspace.metadata.dylint]
libraries = [{ path = "lints/rss_demo" }]
"#,
        )?;
        write(
            &root.join("lints/Cargo.toml"),
            r#"
[workspace]
members = ["rss_demo"]
"#,
        )?;
        write(
            &root.join("deny.toml"),
            "# INVARIANT: DENY-DEMO-01 { level = \"Medium\", exec = \"verify\", source = \"config\" }\n",
        )?;
        write(&root.join("clippy.toml"), "# synthetic clippy carrier\n")?;
        write(
            &root.join("xtask/src/layerdeps.rs"),
            "//! INVARIANT: XTASK-DEMO-01 { level = \"Medium\", exec = \"verify\", source = \"code\" }\n",
        )?;
        write(
            &root.join("xtask/src/publicapi.rs"),
            "//! INVARIANT: PUBLICAPI-DEMO-01 { level = \"Medium\", exec = \"ci-only\", source = \"public-api\" }\n",
        )?;
        for krate in crate::publicapi::target_crates(None) {
            write(&root.join(format!("public-api/{krate}.txt")), "demo\n")?;
        }
        write(
            &root.join("lints/rss_demo/Cargo.toml"),
            "[package]\nname = \"rss_demo\"\n",
        )?;
        write(
            &root.join("lints/rss_demo/src/lib.rs"),
            "//! INVARIANT: LINT-DEMO-01 { level = \"Medium\", exec = \"verify\", source = \"dylint\" }\n",
        )?;
        write(&root.join("lints/rss_demo/ui/main.rs"), "fn main() {}\n")?;
        write(&root.join("lints/rss_demo/ui/main.stderr"), "error\n")?;
        let index = build_index(&root)?;
        assert!(index.findings.is_empty(), "{:?}", index.findings);
        for id in [
            "DENY-DEMO-01",
            "LINT-DEMO-01",
            "PUBLICAPI-DEMO-01",
            "XTASK-DEMO-01",
        ] {
            assert!(index.records.iter().any(|r| r.id == id), "missing {id}");
        }
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
