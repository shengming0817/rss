//! Production Rust source and rustdoc semantic guard.
//!
//! This gate deliberately scans only `.rs` source files. Human-authored Markdown is outside its
//! enforcement boundary and is handled by periodic, non-blocking advisory searches.
//!
//! INVARIANT: SOURCE-RUSTDOC-SEMANTICS-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::outbox_localonly_and_saga_rustdoc_semantics_reject_legacy_claims", anti_vacuity = "tests::workspace_production_rustdoc_semantics_are_current" } -- production rustdoc must not overstate outbox delivery, claim exactly-once Saga execution, or restore legacy LocalOnly effect semantics.

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

use crate::diagnostic::{self, GovernanceCheck, finding};

pub(crate) type Finding = diagnostic::Finding<Rule>;

const SOURCE_ROOTS: &[&str] = &["crates", "adapters"];

const TOKEN_PROFILE_RUSTDOC_CONTRACTS: &[(&str, &[&[&str]])] = &[];

const TOKEN_PROFILE_RUSTDOC_FORBIDDEN: &[&str] = &[
    "`StaticKeySource`",
    "#1109",
    "生产接线留",
    "真实 crypto verifier adapter 留",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Rule {
    OutboxDeliverySemantics,
    SagaExecutionSemantics,
    LocalOnlyBusinessEffects,
    TokenProfileRustdoc,
}

pub(crate) struct SourceSemanticGuard;

impl GovernanceCheck for SourceSemanticGuard {
    type Rule = Rule;

    fn name(&self) -> &'static str {
        "source-semantic-guard"
    }

    fn check(&self) -> Result<(String, Vec<Finding>)> {
        let root = crate::workspace_root()?;
        let mut files = Vec::new();
        for source_root in SOURCE_ROOTS {
            files.extend(rust_files(&root.join(source_root))?);
        }
        files.sort();
        files.dedup();
        if files.is_empty() {
            bail!("source-semantic-guard: production Rust source universe is empty");
        }

        let mut findings = Vec::new();
        for path in &files {
            let content = std::fs::read_to_string(path)
                .map_err(|error| anyhow::anyhow!("read {} failed: {error}", path.display()))?;
            let relative = path.strip_prefix(&root).unwrap_or(path);
            findings.extend(scan_false_outbox_delivery_guarantees(relative, &content));
            findings.extend(scan_false_saga_execution_guarantees(relative, &content));
            findings.extend(scan_localonly_business_effect_semantics(relative, &content));
        }
        for (carrier, _) in TOKEN_PROFILE_RUSTDOC_CONTRACTS {
            let path = root.join(carrier);
            if !path.is_file() {
                bail!("source-semantic-guard: rustdoc carrier {carrier} missing");
            }
            let content = std::fs::read_to_string(&path)
                .map_err(|error| anyhow::anyhow!("read {carrier} failed: {error}"))?;
            findings.extend(scan_token_profile_rustdoc_carrier(
                Path::new(carrier),
                &content,
            ));
        }
        Ok((
            format!(
                "{} production Rust source files and {} token-profile rustdoc carriers checked",
                files.len(),
                TOKEN_PROFILE_RUSTDOC_CONTRACTS.len()
            ),
            findings,
        ))
    }
}

fn rust_files(root: &Path) -> Result<Vec<PathBuf>> {
    if !root.is_dir() {
        bail!(
            "source-semantic-guard: source root {} missing",
            root.display()
        );
    }
    let mut files = Vec::new();
    collect_rust_files(root, &mut files)?;
    Ok(files)
}

fn collect_rust_files(root: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(root)
        .map_err(|error| anyhow::anyhow!("read directory {} failed: {error}", root.display()))?
    {
        let path = entry?.path();
        if path.is_dir() {
            collect_rust_files(&path, files)?;
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
    Ok(())
}

fn scan_token_profile_rustdoc_carrier(path: &Path, content: &str) -> Vec<Finding> {
    let Some((_, groups)) = TOKEN_PROFILE_RUSTDOC_CONTRACTS
        .iter()
        .find(|(carrier, _)| path == Path::new(carrier))
    else {
        return Vec::new();
    };
    let prose = rustdoc_prose_lines(content)
        .into_iter()
        .map(|(_, line)| line)
        .collect::<Vec<_>>()
        .join("\n");
    let mut findings = Vec::new();
    for alternatives in *groups {
        if !alternatives.iter().any(|anchor| prose.contains(anchor)) {
            findings.push(finding(
                Rule::TokenProfileRustdoc,
                path.display().to_string(),
                format!(
                    "profile rustdoc missing required anchor group [{}]",
                    alternatives.join(" | ")
                ),
            ));
        }
    }
    for forbidden in TOKEN_PROFILE_RUSTDOC_FORBIDDEN {
        if prose.contains(forbidden) {
            findings.push(finding(
                Rule::TokenProfileRustdoc,
                path.display().to_string(),
                format!("profile rustdoc retains forbidden legacy phrase `{forbidden}`"),
            ));
        }
    }
    findings
}

fn scan_localonly_business_effect_semantics(path: &Path, content: &str) -> Vec<Finding> {
    let mut findings = rustdoc_prose_lines(content)
        .into_iter()
        .filter(|(_, line)| contains_legacy_localonly_effect_term(path, line))
        .map(|(line, _)| {
            finding(
                Rule::LocalOnlyBusinessEffects,
                format!("{}:{line}", path.display()),
                "use business-qualified LocalOnly effect vocabulary; legacy write/transaction effect APIs are retired",
            )
        })
        .collect::<Vec<_>>();
    findings.extend(
        rustdoc_clauses(content)
            .into_iter()
            .filter(|clause| contains_false_localonly_transaction_claim(&clause.text))
            .map(|clause| {
                finding(
                    Rule::LocalOnlyBusinessEffects,
                    format!("{}:{}", path.display(), clause.line),
                    "LocalOnly excludes business persistence/outbox/publish but permits provider-owned read-path transactions",
                )
            }),
    );
    findings.sort_by(|left, right| left.subject.cmp(&right.subject));
    findings.dedup_by(|left, right| left.subject == right.subject && left.rule == right.rule);
    findings
}

fn contains_legacy_localonly_effect_term(path: &Path, line: &str) -> bool {
    const LEGACY: &[&str] = &[
        "diport::WriteEffect",
        "testkit::local_only::Write",
        "ProviderCounter::write",
        "ForbiddenEffects.writes",
        "EffectKind::Write",
        "EffectKind::Transaction",
        "HttpEffectKind::Write",
        "HttpEffectKind::Transaction",
    ];
    if LEGACY.iter().any(|pattern| line.contains(pattern)) || contains_symbol(line, "WriteEffect") {
        return true;
    }
    let lower = line.to_lowercase();
    let carrier = lower.contains("localonly")
        || lower.contains("local only")
        || path.to_string_lossy().to_lowercase().contains("local_only")
        || path.to_string_lossy().to_lowercase().contains("local-only");
    carrier
        && (line.contains("`Write`")
            || line.contains("`write`")
            || line.contains("`transaction`")
            || contains_legacy_writes_field(line))
}

fn contains_symbol(line: &str, symbol: &str) -> bool {
    line.match_indices(symbol).any(|(offset, matched)| {
        let left = offset == 0
            || line[..offset]
                .chars()
                .next_back()
                .is_none_or(|character| !character.is_ascii_alphanumeric() && character != '_');
        let right = line[offset + matched.len()..]
            .chars()
            .next()
            .is_none_or(|character| !character.is_ascii_alphanumeric() && character != '_');
        left && right
    })
}

fn contains_legacy_writes_field(line: &str) -> bool {
    line.match_indices("writes").any(|(offset, word)| {
        let left = offset == 0
            || line[..offset]
                .chars()
                .next_back()
                .is_none_or(|character| !character.is_ascii_alphanumeric() && character != '_');
        left && line[offset + word.len()..].trim_start().starts_with('=')
    })
}

fn contains_false_localonly_transaction_claim(text: &str) -> bool {
    let normalized = normalize(text);
    let compact = normalized
        .chars()
        .filter(|character| !character.is_whitespace() && !"`*_".contains(*character))
        .collect::<String>();
    (compact.contains("localonly") || compact.starts_with("l0"))
        && [
            "完全没有事务",
            "没有事务",
            "无事务",
            "不启动本地事务边界",
            "等同纯函数",
            "是纯函数",
            "本地纯计算",
            "pure local",
            "pure function",
            "no local transaction boundary",
        ]
        .iter()
        .any(|claim| normalized.contains(claim) && !claim_is_denied(&normalized, claim))
}

fn scan_false_outbox_delivery_guarantees(path: &Path, content: &str) -> Vec<Finding> {
    let source_path_context = {
        let display = path.to_string_lossy().to_lowercase();
        display.contains("outbox") || display.contains("relay")
    };
    let mut paragraph_context = false;
    rustdoc_clauses(content)
        .into_iter()
        .filter_map(|clause| {
            if clause.starts_paragraph {
                paragraph_context = false;
            }
            let normalized = normalize(&clause.text);
            if source_path_context
                || ["outbox", "relay", "broker publish", "broker delivery"]
                    .iter()
                    .any(|context| normalized.contains(context))
                || normalized.contains("acquire lease")
                || (normalized.contains("settle") && normalized.contains("cas"))
            {
                paragraph_context = true;
            }
            if !paragraph_context {
                return None;
            }
            let guarantee = false_delivery_guarantees(&normalized)
                .find(|guarantee| !claim_is_denied(&normalized, guarantee))?;
            Some(finding(
                Rule::OutboxDeliverySemantics,
                format!("{}:{}", path.display(), clause.line),
                format!("outbox transport cannot claim `{guarantee}`; publish-before-settle permits duplicates"),
            ))
        })
        .collect()
}

fn scan_false_saga_execution_guarantees(path: &Path, content: &str) -> Vec<Finding> {
    let source_path_context = path
        .to_string_lossy()
        .to_lowercase()
        .split(['/', '_', '-'])
        .any(|segment| segment == "saga" || segment == "sagas");
    let mut paragraph_context = false;
    rustdoc_clauses(content)
        .into_iter()
        .filter_map(|clause| {
            if clause.starts_paragraph {
                paragraph_context = false;
            }
            let normalized = normalize(&clause.text);
            if source_path_context
                || [
                    "saga",
                    "workflow step",
                    "orchestrated step",
                    "补偿事务",
                    "编排步骤",
                ]
                .iter()
                .any(|context| normalized.contains(context))
            {
                paragraph_context = true;
            }
            if !paragraph_context {
                return None;
            }
            let guarantee = false_saga_execution_guarantees(&normalized)
                .find(|guarantee| !claim_is_denied(&normalized, guarantee))?;
            Some(finding(
                Rule::SagaExecutionSemantics,
                format!("{}:{}", path.display(), clause.line),
                format!(
                    "Saga execution cannot claim `{guarantee}`; the runtime boundary is at-least-once with scoped idempotent effects"
                ),
            ))
        })
        .collect()
}

fn false_saga_execution_guarantees(text: &str) -> impl Iterator<Item = &'static str> + '_ {
    const GUARANTEES: &[&str] = &[
        "exactly once",
        "exactly once execution",
        "exactly once effect",
        "exactly once saga",
        "executes exactly once",
        "effects exactly once",
        "恰好执行一次",
        "只执行一次",
        "仅执行一次",
        "精确执行一次",
        "精确一次",
        "effect 精确一次",
        "saga 精确一次",
    ];
    GUARANTEES
        .iter()
        .copied()
        .filter(move |guarantee| text.contains(guarantee))
}

fn false_delivery_guarantees(text: &str) -> impl Iterator<Item = &'static str> + '_ {
    const GUARANTEES: &[&str] = &[
        "at most once",
        "exactly once",
        "至多 publish 一次",
        "只 publish 一次",
        "仅 publish 一次",
        "恰好 publish 一次",
        "至多发布一次",
        "只发布一次",
        "仅发布一次",
        "恰好发布一次",
        "至多投递一次",
        "只投递一次",
        "仅投递一次",
        "只会投递一次",
        "仅会投递一次",
        "恰好投递一次",
        "精确一次",
    ];
    GUARANTEES
        .iter()
        .copied()
        .filter(move |guarantee| text.contains(guarantee))
}

fn claim_is_denied(text: &str, claim: &str) -> bool {
    text.match_indices(claim).all(|(offset, _)| {
        let prefix = &text[..offset];
        let local_prefix = local_claim_prefix(prefix);
        [
            "不提供",
            "不保证",
            "不能保证",
            "不承诺",
            "不得声称",
            "禁止声称",
            "拒绝",
            "禁止",
            "并非",
            "不是",
            "不等同",
            "does not guarantee",
            "doesn't guarantee",
            "does not provide",
            "is not",
            "isn't",
            "no guarantee",
            "must not claim",
            "cannot guarantee",
            "never guarantees",
            "never claims",
            "rejects",
            "forbids",
        ]
        .iter()
        .any(|denial| local_prefix.contains(denial))
    })
}

/// Restrict a denial to the current side of an adversative conjunction. Without this boundary,
/// `does not guarantee A, but guarantees B` incorrectly treats the affirmative `B` as denied.
fn local_claim_prefix(prefix: &str) -> &str {
    const ADVERSATIVE_BOUNDARIES: &[&str] = &[
        ", but ",
        " but ",
        ", yet ",
        " yet ",
        ", however ",
        " however ",
        "但是",
        "但",
        "而是",
    ];
    let start = ADVERSATIVE_BOUNDARIES
        .iter()
        .filter_map(|boundary| prefix.rfind(boundary).map(|offset| offset + boundary.len()))
        .max()
        .unwrap_or(0);
    &prefix[start..]
}

#[derive(Debug)]
struct Clause {
    line: usize,
    text: String,
    starts_paragraph: bool,
}

fn rustdoc_clauses(content: &str) -> Vec<Clause> {
    let mut clauses = Vec::new();
    let mut paragraph_start = true;
    for (line, prose) in rustdoc_prose_lines(content) {
        let prose = prose.trim();
        if prose.is_empty() {
            paragraph_start = true;
            continue;
        }
        for fragment in prose.split_inclusive(['。', '；', ';', '！', '!', '？', '?', '.']) {
            let text = fragment.trim();
            if !text.is_empty() {
                clauses.push(Clause {
                    line,
                    text: text.to_owned(),
                    starts_paragraph: paragraph_start,
                });
                paragraph_start = false;
            }
        }
    }
    clauses
}

fn normalize(text: &str) -> String {
    text.to_lowercase()
        .chars()
        .map(|character| match character {
            '-' | '_' | '\u{2010}' | '\u{2011}' | '\u{2012}' | '\u{2013}' | '\u{2014}'
            | '\u{2015}' | '\u{2212}' => ' ',
            character => character,
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn rustdoc_prose_lines(content: &str) -> Vec<(usize, String)> {
    let mut output = Vec::new();
    let mut in_block_doc = false;
    for (index, raw) in content.lines().enumerate() {
        let line = index + 1;
        let trimmed = raw.trim_start();
        if in_block_doc {
            let prose = trimmed.strip_prefix('*').unwrap_or(trimmed).trim_start();
            if let Some((before, _)) = prose.split_once("*/") {
                output.push((line, before.trim().to_owned()));
                in_block_doc = false;
            } else {
                output.push((line, prose.to_owned()));
            }
            continue;
        }
        if let Some(rest) = trimmed
            .strip_prefix("/*!")
            .or_else(|| trimmed.strip_prefix("/**"))
        {
            if let Some((before, _)) = rest.split_once("*/") {
                output.push((line, before.trim().to_owned()));
            } else {
                output.push((line, rest.trim().to_owned()));
                in_block_doc = true;
            }
        } else if let Some(prose) = trimmed
            .strip_prefix("//!")
            .or_else(|| trimmed.strip_prefix("///"))
        {
            output.push((line, prose.to_owned()));
        } else if let Some(prose) = parse_doc_attribute(trimmed) {
            output.push((line, prose));
        }
    }
    output
}

fn parse_doc_attribute(line: &str) -> Option<String> {
    let value = line
        .strip_prefix("#[doc")?
        .trim_start()
        .strip_prefix('=')?
        .trim_start();
    let (prose, remainder) = split_rust_string_literal(value)?;
    remainder.trim_start().starts_with(']').then_some(prose)
}

fn split_rust_string_literal(input: &str) -> Option<(String, &str)> {
    if let Some(raw) = input.strip_prefix('r') {
        let hashes = raw
            .chars()
            .take_while(|character| *character == '#')
            .count();
        let body = raw[hashes..].strip_prefix('"')?;
        let closer = format!("\"{}", "#".repeat(hashes));
        let end = body.find(&closer)?;
        return Some((body[..end].to_owned(), &body[end + closer.len()..]));
    }
    let mut body = input.strip_prefix('"')?;
    let mut prose = String::new();
    while let Some(character) = body.chars().next() {
        body = &body[character.len_utf8()..];
        match character {
            '"' => return Some((prose, body)),
            '\\' => {
                let escaped = body.chars().next()?;
                body = &body[escaped.len_utf8()..];
                prose.push(match escaped {
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    '\\' | '\'' | '"' => escaped,
                    other => other,
                });
            }
            other => prose.push(other),
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outbox_localonly_and_saga_rustdoc_semantics_reject_legacy_claims() {
        let outbox = "//! Outbox relay uses CAS and guarantees exactly-once delivery.";
        assert!(
            !scan_false_outbox_delivery_guarantees(
                Path::new("crates/eventexec/src/relay.rs"),
                outbox
            )
            .is_empty()
        );
        let localonly = "/// LocalOnly is pure local and has no local transaction boundary.";
        assert!(
            !scan_localonly_business_effect_semantics(
                Path::new("crates/testkit/src/local_only.rs"),
                localonly
            )
            .is_empty()
        );
        assert!(
            scan_false_outbox_delivery_guarantees(
                Path::new("crates/eventexec/src/relay.rs"),
                "//! Outbox is at-least-once and does not guarantee exactly-once delivery."
            )
            .is_empty()
        );
        let mixed =
            "//! Outbox does not guarantee at-most-once, but guarantees exactly-once delivery.";
        let findings = scan_false_outbox_delivery_guarantees(
            Path::new("crates/eventexec/src/relay.rs"),
            mixed,
        );
        assert_eq!(
            findings.len(),
            1,
            "mixed claim must reject the affirmative guarantee"
        );
        assert!(findings[0].detail.contains("exactly once"));

        for claim in [
            "//! Saga guarantees exactly-once execution across crashes.",
            "/// 编排步骤只执行一次。",
            "#[doc = \"Saga effects exactly-once\"]",
        ] {
            assert!(
                !scan_false_saga_execution_guarantees(
                    Path::new("crates/eventexec/src/saga.rs"),
                    claim,
                )
                .is_empty(),
                "affirmative Saga guarantee escaped: {claim}"
            );
        }
        for permitted in [
            "//! Saga does not guarantee exactly-once execution.",
            "//! Saga is at-least-once with scoped idempotent effects.",
            "//! Exactly one typed receipt marker exists per generated step.",
            "const BAIT: &str = \"Saga guarantees exactly-once execution\";",
        ] {
            assert!(
                scan_false_saga_execution_guarantees(
                    Path::new("crates/eventexec/src/saga.rs"),
                    permitted,
                )
                .is_empty(),
                "permitted or non-rustdoc text was rejected: {permitted}"
            );
        }
    }

    #[test]
    fn rustdoc_semantic_scan_covers_attributes_and_block_docs_only() {
        for rustdoc in [
            "#[doc = \"Outbox guarantees exactly-once delivery\"]",
            "#[doc = r#\"Outbox guarantees exactly-once delivery\"#]",
            "/** Outbox guarantees exactly-once delivery. */",
            "/*! Outbox guarantees exactly-once delivery. */",
        ] {
            assert!(
                !scan_false_outbox_delivery_guarantees(
                    Path::new("crates/eventexec/src/relay.rs"),
                    rustdoc
                )
                .is_empty(),
                "rustdoc surface escaped: {rustdoc}"
            );
        }
        for non_rustdoc in [
            "// Outbox guarantees exactly-once delivery",
            "const BAIT: &str = \"Outbox guarantees exactly-once delivery\";",
        ] {
            assert!(
                scan_false_outbox_delivery_guarantees(
                    Path::new("crates/eventexec/src/relay.rs"),
                    non_rustdoc
                )
                .is_empty(),
                "non-rustdoc bait must not be enforced: {non_rustdoc}"
            );
        }
    }

    #[test]
    fn workspace_production_rustdoc_semantics_are_current() -> Result<()> {
        let (summary, findings) = SourceSemanticGuard.check()?;
        assert!(
            summary.contains("production Rust source files"),
            "{summary}"
        );
        assert!(findings.is_empty(), "{findings:?}");
        Ok(())
    }
}
