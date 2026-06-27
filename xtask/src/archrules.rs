//! ArchRules 派生索引：从真实 carrier 的 `INVARIANT:` 锚点反推出 rule → carrier → evidence → gate。
//!
//! INVARIANT: ARCHRULES-DERIVED-INDEX-01 —— 本模块只扫描真实 carrier（代码 / 配置 / UI golden /
//! baseline），不引入手写规则目录；文档仅作为 `doc_ref`。
//! INVARIANT: ARCHRULES-VERIFY-GATE-01 —— [`ArchRules`] 作为 no-compile governance gate 接入 verify/ci，
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
    println!("id | carrier | source | evidence | gate | status");
    for record in &index.records {
        println!(
            "{} | {} | {} | {} | {} | {}",
            record.id, record.carrier, record.source, record.evidence, record.gate, record.status
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
            scan_source_invariant_file(
                root,
                index,
                &path,
                "native-hard",
                "source invariant",
                Some("standalone"),
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
            let is_trybuild =
                path_str.contains("/tests/ui/") || path_str.contains("/tests/trybuild");
            let is_compile_fail_doc = file_contains(&path, "compile_fail")?;
            if !is_trybuild && !is_compile_fail_doc {
                continue;
            }
            let evidence = if is_trybuild {
                trybuild_evidence(root, index, &fixtures, &path)?
            } else {
                "compile_fail doctest".to_string()
            };
            scan_invariant_file(
                root,
                index,
                &path,
                "native-hard",
                evidence,
                Some("standalone"),
            )?;
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
                for id in found.ids {
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
            index.findings.push(finding(
                Rule::InvalidInvariantId,
                found.source.clone(),
                format!("非法 INVARIANT id `{invalid}`"),
            ));
        }
        for id in &found.ids {
            index.records.push(RuleRecord {
                id: id.clone(),
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
            index.findings.push(finding(
                Rule::InvalidInvariantId,
                found.source.clone(),
                format!("非法 INVARIANT id `{invalid}`"),
            ));
        }
        for id in &found.ids {
            index.records.push(RuleRecord {
                id: id.clone(),
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct FoundInvariant {
    source: String,
    ids: Vec<String>,
    invalid: Vec<String>,
}

fn extract_invariants(root: &Path, path: &Path) -> Result<Vec<FoundInvariant>> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("读取 INVARIANT carrier `{}`", path.display()))?;
    let mut out = Vec::new();
    for (line_idx, line) in text.lines().enumerate() {
        if !is_invariant_carrier_line(path, line) {
            continue;
        }
        let Some(pos) = line.find("INVARIANT:") else {
            continue;
        };
        let rest = &line[pos + "INVARIANT:".len()..];
        let tokens = invariant_tokens(rest);
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
        if !ids.is_empty() || !invalid.is_empty() {
            out.push(FoundInvariant {
                source: format!("{}:{}", rel(root, path), line_idx + 1),
                ids,
                invalid,
            });
        }
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
            continue;
        }
        let tokens = invariant_tokens(rest);
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
        if !ids.is_empty() || !invalid.is_empty() {
            out.push(FoundInvariant {
                source: format!("{}:{}", rel(root, path), line_idx + 1),
                ids,
                invalid,
            });
        }
    }
    Ok(out)
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

fn is_invariant_carrier_line(path: &Path, line: &str) -> bool {
    let trimmed = line.trim_start();
    match path.extension().and_then(|s| s.to_str()) {
        Some("md") => true,
        Some("toml") => trimmed.starts_with('#'),
        Some("sql") => trimmed.starts_with("--"),
        Some("rs") => {
            trimmed.starts_with("//")
                || trimmed.starts_with("///")
                || trimmed.starts_with("//!")
                || trimmed.starts_with("*")
        }
        _ => true,
    }
}

fn xtask_gate(root: &Path, path: &Path) -> Option<&'static str> {
    match rel(root, path).as_str() {
        "xtask/src/archrules.rs"
        | "xtask/src/assembly.rs"
        | "xtask/src/codegen.rs"
        | "xtask/src/command_symmetry.rs"
        | "xtask/src/defergate.rs"
        | "xtask/src/doc_contracts.rs"
        | "xtask/src/layers.rs"
        | "xtask/src/layerdeps.rs"
        | "xtask/src/migrations.rs"
        | "xtask/src/pdpallow.rs"
        | "xtask/src/schema_rls.rs"
        | "xtask/src/setlocal_funnel.rs"
        | "xtask/src/src_scan.rs"
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
        "xtask/src/cmd.rs" | "xtask/src/diagnostic.rs" => Some("standalone"),
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

    #[test]
    fn invariant_parser_extracts_multiple_ids_and_flags_bad_uppercase() -> Result<()> {
        let root = unique_tmp("archrules-ids");
        let file = root.join("xtask/src/demo.rs");
        write(
            &file,
            "//! INVARIANT: FOO-BAR-01（说明）· BAZ-QUX-02 / BAD-ID-1\n",
        )?;
        let found = extract_invariants(&root, &file)?;
        assert_eq!(found[0].ids, vec!["BAZ-QUX-02", "FOO-BAR-01"]);
        assert_eq!(found[0].invalid, vec!["BAD-ID-1"]);
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
            "//! INVARIANT: DEMO-LINT-01\n",
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
            "/// INVARIANT: CRYPTO-CONST-TIME-01 —— 实现必须常数时间。\n",
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
        // archrules 判 MissingGate（#1572）。
        // 互补侧（gate 字符串声明的 plan 成员资格）由 verify.rs 的 full_plan_order_and_count /
        // ci_plan_order_and_count 守——删 assembly-validate plan 步即那两测试红；合起来覆盖
        // 「gate 字符串 ↔ plan 实际成员」双向漂移（review F2）。
        let root = Path::new("/repo");
        assert_eq!(
            xtask_gate(root, &root.join("xtask/src/assembly.rs")),
            Some("verify,ci")
        );
    }

    #[test]
    fn unknown_xtask_invariant_is_missing_gate() -> Result<()> {
        let root = unique_tmp("archrules-unknown-xtask");
        let file = root.join("xtask/src/new_guard.rs");
        write(&file, "//! INVARIANT: NEW-GUARD-01\n")?;
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
            "//! INVARIANT: TRYBUILD-FAIL-01\n",
        )?;
        write(
            &root.join("crates/demo/tests/ui/pass.rs"),
            "//! INVARIANT: TRYBUILD-PASS-01\n",
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
        write(&root.join("deny.toml"), "# INVARIANT: DENY-DEMO-01\n")?;
        write(&root.join("clippy.toml"), "# synthetic clippy carrier\n")?;
        write(
            &root.join("xtask/src/layerdeps.rs"),
            "//! INVARIANT: XTASK-DEMO-01\n",
        )?;
        write(
            &root.join("xtask/src/publicapi.rs"),
            "//! INVARIANT: PUBLICAPI-DEMO-01\n",
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
            "//! INVARIANT: LINT-DEMO-01\n",
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
