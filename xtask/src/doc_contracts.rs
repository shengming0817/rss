//! `doc-contracts` —— 文档契约片段漂移门（AI-robust Medium 内容扫描门）。
//!
//! INVARIANT: DOC-CONTRACTS-01 { level = "Medium", exec = "verify", source = "code" }—— tenant + actor aware command /
//! outbox envelope 签名已经进入 codegen 与 runtime；规则 / spec 文档不得残留 tenantless / actorless 旧片段。
//! 该门只锁已知高风险签名片段，避免宽泛词扫描误伤历史散文。

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

use crate::diagnostic::{self, GovernanceCheck, finding};

pub(crate) type Finding = diagnostic::Finding<Rule>;

const DOC_ROOTS: &[&str] = &["docs/rules", "docs/spec"];

const FORBIDDEN: &[ForbiddenPattern] = &[
    ForbiddenPattern {
        rule: Rule::CommandWrapper,
        needle: "emit_async(emitter, request, subject_id, idempotency_key)",
        detail: "command wrapper 必须显式接收 tenant + actor: emit_async(emitter, request, tenant, subject_id, actor, idempotency_key)",
    },
    ForbiddenPattern {
        rule: Rule::CommandWrapper,
        needle: "emit_async(emitter, request, tenant, subject_id, idempotency_key)",
        detail: "command wrapper 必须显式接收 actor: emit_async(emitter, request, tenant, subject_id, actor, idempotency_key)",
    },
    ForbiddenPattern {
        rule: Rule::RuntimeCommandEmit,
        needle: "eventexec::command::emit_async(emitter, dispatch_id, topic, contract_id, payload, subject)",
        detail: "runtime command emit 必须透传 typed contract + tenant + actor: emit_async(..., contract, tenant, payload, subject_id, actor)",
    },
    ForbiddenPattern {
        rule: Rule::RuntimeCommandEmit,
        needle: "eventexec::command::emit_async(emitter, dispatch_id, topic, contract, tenant, payload, subject_id)",
        detail: "runtime command emit 必须透传 actor: emit_async(..., contract, tenant, payload, subject_id, actor)",
    },
    ForbiddenPattern {
        rule: Rule::OutboxEnvelope,
        needle: "OutboxEnvelopeParts::new(CONTRACT, subject)",
        detail: "outbox envelope parts 必须显式接收 tenant + actor: OutboxEnvelopeParts::new(CONTRACT, tenant, subject, actor)",
    },
    ForbiddenPattern {
        rule: Rule::OutboxEnvelope,
        needle: "OutboxEnvelopeParts::new(CONTRACT, tenant, subject)",
        detail: "outbox envelope parts 必须显式接收 actor: OutboxEnvelopeParts::new(CONTRACT, tenant, subject, actor)",
    },
    ForbiddenPattern {
        rule: Rule::ProducerSignature,
        needle: "request: <Cmd>Request, subject_id: String, idempotency_key: Option<String>",
        detail: "producer wrapper spec 必须使用 typed subject/actor，不得暴露 String subject_id 旧签名",
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Rule {
    CommandWrapper,
    RuntimeCommandEmit,
    OutboxEnvelope,
    ProducerSignature,
}

#[derive(Debug, Clone, Copy)]
struct ForbiddenPattern {
    rule: Rule,
    needle: &'static str,
    detail: &'static str,
}

pub(crate) struct DocContracts;

impl GovernanceCheck for DocContracts {
    type Rule = Rule;

    fn name(&self) -> &'static str {
        "doc-contracts"
    }

    fn check(&self) -> Result<(String, Vec<Finding>)> {
        let root = crate::workspace_root()?;
        let (scanned, findings) = scan_docs(&root)?;
        if scanned < 3 {
            bail!(
                "doc-contracts: 仅扫到 {scanned} 个文档文件，疑似 docs/rules 或 docs/spec 结构异常"
            );
        }
        Ok((
            format!("{scanned} docs 文件扫描，command/outbox tenant-aware 片段无漂移"),
            findings,
        ))
    }
}

fn scan_docs(root: &Path) -> Result<(usize, Vec<Finding>)> {
    let mut files = Vec::new();
    for dir in DOC_ROOTS {
        let mut found = md_files(&root.join(dir))?;
        if found.is_empty() {
            bail!("doc-contracts: {dir} 下无 .md 文件，fail-closed");
        }
        files.append(&mut found);
    }
    files.sort();

    let mut findings = Vec::new();
    for path in &files {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("doc-contracts: 读 {} 失败: {e}", path.display()))?;
        let rel = path.strip_prefix(root).unwrap_or(path);
        findings.extend(scan_content(rel, &content));
    }
    Ok((files.len(), findings))
}

fn md_files(dir: &Path) -> Result<Vec<PathBuf>> {
    if !dir.is_dir() {
        bail!("doc-contracts: 目录 {} 缺失，fail-closed", dir.display());
    }
    let mut out = Vec::new();
    collect_md(dir, &mut out)?;
    Ok(out)
}

fn collect_md(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir)
        .map_err(|e| anyhow::anyhow!("doc-contracts: 读目录 {} 失败: {e}", dir.display()))?
    {
        let entry = entry.map_err(|e| anyhow::anyhow!("doc-contracts: 遍历目录项失败: {e}"))?;
        let path = entry.path();
        if path.is_dir() {
            collect_md(&path, out)?;
        } else if path.extension().is_some_and(|ext| ext == "md") {
            out.push(path);
        }
    }
    Ok(())
}

fn scan_content(path: &Path, content: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        for p in FORBIDDEN {
            if line.contains(p.needle) {
                findings.push(finding(
                    p.rule,
                    format!("{}:{}", path.display(), idx + 1),
                    p.detail,
                ));
            }
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_content_reports_tenantless_command_and_envelope_fragments() {
        let src = "\
generated::command::<cmd>::emit_async(emitter, request, subject_id, idempotency_key)
OutboxEnvelopeParts::new(CONTRACT, subject)
";
        let findings = scan_content(Path::new("docs/rules/eventbus.md"), src);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].rule, Rule::CommandWrapper);
        assert_eq!(findings[1].rule, Rule::OutboxEnvelope);
    }

    #[test]
    fn scan_content_reports_actorless_command_and_envelope_fragments() {
        let src = "\
generated::command::<cmd>::emit_async(emitter, request, tenant, subject_id, idempotency_key)
eventexec::command::emit_async(emitter, dispatch_id, topic, contract, tenant, payload, subject_id)
OutboxEnvelopeParts::new(CONTRACT, tenant, subject)
";
        let findings = scan_content(Path::new("docs/rules/eventbus.md"), src);
        assert_eq!(findings.len(), 3);
        assert_eq!(findings[0].rule, Rule::CommandWrapper);
        assert_eq!(findings[1].rule, Rule::RuntimeCommandEmit);
        assert_eq!(findings[2].rule, Rule::OutboxEnvelope);
    }

    #[test]
    fn scan_content_accepts_actor_aware_fragments() {
        let src = "\
generated::command::<cmd>::emit_async(emitter, request, tenant, subject_id, actor, idempotency_key)
eventexec::command::emit_async(emitter, dispatch_id, topic, contract, tenant, payload, subject_id, actor)
OutboxEnvelopeParts::new(CONTRACT, tenant, subject, actor)
";
        assert!(scan_content(Path::new("docs/rules/eventbus.md"), src).is_empty());
    }
}
