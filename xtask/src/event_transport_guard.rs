//! runtime event transport source guard.
//!
//! INVARIANT: EVENT-TRANSPORT-PG-INBOX-01 { level = "Medium", exec = "verify", source = "code" }——
//! `assemblies/runtime/src/event_transport.rs` 的 consumer idempotency must come from PG inbox, not Redis.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};

use crate::diagnostic::{Finding, GovernanceCheck, finding};
use crate::layers::DOMAIN_CRATES;
use crate::workspace_root;

const TARGET: &str = "assemblies/runtime/src/event_transport.rs";
const RUNTIME_FORBIDDEN: &[&str] = &[
    "RedisIdempotencyStore",
    "RSS_REDIS_CLAIM_TTL_MS",
    "redis_claim_ttl",
    "replaydeps::IdempotencyConfig",
    "redis idempotency",
    "Redis 幂等",
];
const RUNTIME_REQUIRED: &[&str] = &[
    "fn wire_consumer_resource_bundle(",
    "let inbox = pg.infra().inbox(group);",
    "let lease_cfg = LeaseConfig::from_ttl(inbox.lease_ttl());",
    "let dlx = DynDeadLetterStore::new_box(pg.infra().dead_letter());",
    "spawn_consumer_ackable_subscriber(",
    "wire_inbox_sweeper(pg, timing, module)?;",
];
const DOMAIN_FORBIDDEN: &[&str] = &[
    "PgInboxStore",
    "RedisIdempotencyStore",
    "ConsumerWorker",
    "spawn_consumer(",
    "spawn_consumer_ackable(",
    "spawn_consumer_ackable_subscriber(",
    "pg.infra().inbox(",
    "pg.infra().dead_letter(",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    RedisConsumerClaimer,
    MissingBundleFragment,
    DomainConsumerBundleBypass,
}

pub(crate) struct EventTransportGuard;

impl GovernanceCheck for EventTransportGuard {
    type Rule = Rule;

    fn name(&self) -> &'static str {
        "event-transport-guard"
    }

    fn check(&self) -> Result<(String, Vec<Finding<Self::Rule>>)> {
        let root = workspace_root()?;
        let path = root.join(TARGET);
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("event-transport-guard: read {}", path.display()))?;
        let mut findings = scan_runtime_content(Path::new(TARGET), &content);
        findings.extend(scan_domain_crates(&root)?);
        Ok((
            format!("{TARGET} 经 PG inbox consumer bundle 接线，域 crate 无散装 consumer bundle"),
            findings,
        ))
    }
}

fn scan_runtime_content(path: &Path, content: &str) -> Vec<Finding<Rule>> {
    let mut findings = Vec::new();
    for forbidden in RUNTIME_FORBIDDEN {
        if content.contains(forbidden) {
            findings.push(finding(
                Rule::RedisConsumerClaimer,
                path.display().to_string(),
                format!("禁止 runtime event consumer 重新接入 Redis claimer: `{forbidden}`"),
            ));
        }
    }
    for required in RUNTIME_REQUIRED {
        if !content.contains(required) {
            findings.push(finding(
                Rule::MissingBundleFragment,
                path.display().to_string(),
                format!("runtime consumer bundle 缺少必备接线片段: `{required}`"),
            ));
        }
    }
    findings
}

fn scan_domain_crates(root: &Path) -> Result<Vec<Finding<Rule>>> {
    let mut findings = Vec::new();
    for crate_root in domain_crate_roots() {
        let abs_root = root.join(crate_root);
        if !abs_root.exists() {
            continue;
        }
        for path in rust_files_under(&abs_root)? {
            let content = std::fs::read_to_string(&path).with_context(|| {
                format!("event-transport-guard: read domain file {}", path.display())
            })?;
            findings.extend(scan_domain_content(&rel_path(root, &path), &content));
        }
    }
    Ok(findings)
}

fn domain_crate_roots() -> Vec<String> {
    DOMAIN_CRATES
        .iter()
        .map(|crate_name| format!("crates/{crate_name}"))
        .collect()
}

fn rust_files_under(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(path) = stack.pop() {
        for entry in std::fs::read_dir(&path)
            .with_context(|| format!("event-transport-guard: read dir {}", path.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
                files.push(path);
            }
        }
    }
    Ok(files)
}

fn scan_domain_content(path: &Path, content: &str) -> Vec<Finding<Rule>> {
    let mut findings = Vec::new();
    for forbidden in DOMAIN_FORBIDDEN {
        if content.contains(forbidden) {
            findings.push(finding(
                Rule::DomainConsumerBundleBypass,
                path.display().to_string(),
                format!("consumer inbox/DLX/worker 只能经 runtime bundle 接线，域 crate 禁止片段: `{forbidden}`"),
            ));
        }
    }
    findings
}

fn rel_path(root: &Path, path: &Path) -> PathBuf {
    path.strip_prefix(root).unwrap_or(path).to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_content_rejects_redis_consumer_claimer_needles() {
        let findings = scan_runtime_content(
            Path::new(TARGET),
            "let _: RedisIdempotencyStore; let _ = \"RSS_REDIS_CLAIM_TTL_MS\";",
        );
        assert!(
            findings
                .iter()
                .filter(|f| f.rule == Rule::RedisConsumerClaimer)
                .count()
                == 2
        );
    }

    #[test]
    fn scan_content_accepts_pg_inbox_bundle() {
        let findings = scan_runtime_content(
            Path::new(TARGET),
            r#"
            fn wire_consumer_resource_bundle() {
                let inbox = pg.infra().inbox(group);
                let lease_cfg = LeaseConfig::from_ttl(inbox.lease_ttl());
                let dlx = DynDeadLetterStore::new_box(pg.infra().dead_letter());
                spawn_consumer_ackable_subscriber();
                wire_inbox_sweeper(pg, timing, module)?;
            }
            "#,
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_content_rejects_missing_pg_bundle_fragment() {
        let findings =
            scan_runtime_content(Path::new(TARGET), "fn wire_consumer_resource_bundle()");
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::MissingBundleFragment)
        );
    }

    #[test]
    fn scan_domain_content_rejects_consumer_bundle_bypass() {
        let findings = scan_domain_content(
            Path::new("crates/identity/src/lib.rs"),
            "let _ = PgInboxStore; spawn_consumer_ackable_subscriber();",
        );
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn domain_roots_include_all_layer_domain_crates() {
        let roots = domain_crate_roots();
        assert_eq!(
            roots,
            vec![
                "crates/identity",
                "crates/settings",
                "crates/audit",
                "crates/contractreg",
                "crates/syshealth",
            ]
        );
    }

    #[test]
    fn scan_domain_content_rejects_bypass_in_contractreg_and_syshealth() {
        for path in [
            Path::new("crates/contractreg/src/lib.rs"),
            Path::new("crates/syshealth/src/lib.rs"),
        ] {
            let findings = scan_domain_content(path, "let _ = pg.infra().inbox(group);");
            assert_eq!(findings.len(), 1, "{path:?}");
            assert_eq!(findings[0].rule, Rule::DomainConsumerBundleBypass);
        }
    }
}
