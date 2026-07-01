//! `tenancy-closeout` -- tenancy/AuthZ/projection closeout reverse self-check.
//!
//! INVARIANT: TENANCY-CLOSEOUT-REVERSE-01 { level = "Medium", exec = "verify", source = "code" } -- final
//! tenancy governance facts must stay machine-visible in verify/ci membership, dylint registration,
//! projection wiring, and governed closeout docs.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Result, bail};
use toml::Value;

use crate::diagnostic::{self, GovernanceCheck, finding};

pub(crate) type Finding = diagnostic::Finding<Rule>;

const VERIFY_CI_REQUIRED_GATES: &[&str] = &[
    "contract-validate",
    "codegen-check",
    "schema-rls",
    "setlocal-funnel",
    "pg-tenant-tx-guard",
    "pdp-allow-guard",
    "tenancy-closeout",
    "dylint",
];

const TENANCY_DYLINTS: &[&str] = &[
    "rss_crosstenant_callsite",
    "rss_principal_facet_impl_allowlist",
    "rss_authplan_callsite",
    "rss_authenticated_callsite",
    "rss_handler_local_principal_authz",
    "rss_pdp_impl_adapter_only",
    "rss_projection_append_only",
];

const REGISTRY_FILES: &[&str] = &[
    "Cargo.toml",
    "lints/Cargo.toml",
    "docs/rules/architecture.md",
    "lints/README.md",
];

const REQUIRED_ANCHORS: &[RequiredAnchor] = &[
    RequiredAnchor {
        rule: Rule::DocAnchor,
        path: "docs/rules/tenancy.md",
        needle: "cargo xtask tenancy-closeout",
        detail: "tenancy rule doc must name the closeout reverse self-check",
    },
    RequiredAnchor {
        rule: Rule::DocAnchor,
        path: "docs/rules/tenancy.md",
        needle: "verify_rls_capability",
        detail: "tenancy rule doc must keep the RLS capability anchor",
    },
    RequiredAnchor {
        rule: Rule::DocAnchor,
        path: "docs/rules/tenancy.md",
        needle: "schema-rls",
        detail: "tenancy rule doc must keep the RLS schema guard anchor",
    },
    RequiredAnchor {
        rule: Rule::DocAnchor,
        path: "docs/rules/tenancy.md",
        needle: "setlocal-funnel",
        detail: "tenancy rule doc must keep the SET LOCAL funnel guard anchor",
    },
    RequiredAnchor {
        rule: Rule::DocAnchor,
        path: "docs/rules/tenancy.md",
        needle: "pg-tenant-tx-guard",
        detail: "tenancy rule doc must keep the tenant Tx guard anchor",
    },
    RequiredAnchor {
        rule: Rule::DocAnchor,
        path: "docs/rules/tenancy.md",
        needle: "RouteAuthorizer",
        detail: "tenancy rule doc must keep the RouteAuthorizer anchor",
    },
    RequiredAnchor {
        rule: Rule::DocAnchor,
        path: "docs/rules/tenancy.md",
        needle: "AuthorizedSubject",
        detail: "tenancy rule doc must keep the AuthorizedSubject anchor",
    },
    RequiredAnchor {
        rule: Rule::DocAnchor,
        path: "docs/rules/tenancy.md",
        needle: "ResourceProjection",
        detail: "tenancy rule doc must keep the ResourceProjection anchor",
    },
];

const ADR_CLOSEOUT_COVERAGE: &[AdrCloseoutCoverage] = &[
    AdrCloseoutCoverage {
        path: "docs/architecture/202606232318-006-pdp-internal-authplan-vs-external-opa.md",
        historical_needles: &["#1109 未落地", "验签空窗", "未来 `diport::Pdp`"],
        closeout_needles: &[
            "Closeout addendum（#1584 / #1586）",
            "RawCredential",
            "VerifiedClaims",
            "VerifiedJwt",
            "rss_pdp_impl_adapter_only",
        ],
        detail: "ADR 006 historical PDP/verifier future wording must be covered by final closeout addendum",
    },
    AdrCloseoutCoverage {
        path: "docs/architecture/202606232319-007-service-identity-service-token-vs-spiffe-mtls.md",
        historical_needles: &[
            "MAC verifier 随 #1109",
            "service-token 验签空窗",
            "MAC binding 尚未实装",
        ],
        closeout_needles: &[
            "Closeout addendum（#1577 / #1586）",
            "ServiceTokenTenantBinding",
            "service_token_mac_input",
            "service_token_tenant_binding",
        ],
        detail: "ADR 007 historical service-token/MAC future wording must be covered by final closeout addendum",
    },
];

const AUDIT_PROJECTION_FIELDS: &[AuditProjectionField] = &[
    AuditProjectionField {
        toml_field: "auditActor",
        rust_variant: "AuditActor",
        permission: "audit:field:actor",
        obligation_key: "audit.actor",
        wire_field: "actor",
    },
    AuditProjectionField {
        toml_field: "auditResourceId",
        rust_variant: "AuditResourceId",
        permission: "audit:field:resource_id",
        obligation_key: "audit.resource_id",
        wire_field: "resource_id",
    },
];

const STALE_CLOSEOUT_PATTERNS: &[ForbiddenPattern] = &[
    ForbiddenPattern {
        path: "docs/architecture/202606271400-011-durable-tenant-scope-unblocker.md",
        needle: "dual-pool bootstrap 接线",
        detail: "tenant dual-pool bootstrap closeout is complete; ADR must not keep it as follow-up",
    },
    ForbiddenPattern {
        path: "docs/architecture/202606271400-011-durable-tenant-scope-unblocker.md",
        needle: "full-path ledger + CI 门随后续 RLS PR 落地",
        detail: "RLS full-path ledger and CI gates are complete; ADR must state final status",
    },
    ForbiddenPattern {
        path: "docs/rules/architecture.md",
        needle: "tenant/AuthZ/projection lint 待补",
        detail: "tenant/AuthZ/projection dylints are registered; architecture rules must not describe them as pending",
    },
    ForbiddenPattern {
        path: "lints/README.md",
        needle: "tenant/AuthZ/projection lint 待补",
        detail: "tenant/AuthZ/projection dylints are registered; lint README must not describe them as pending",
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Rule {
    VerifyGate,
    DylintRegistry,
    ProjectionAnchor,
    DocAnchor,
    StaleCloseoutWording,
}

#[derive(Debug, Clone, Copy)]
struct RequiredAnchor {
    rule: Rule,
    path: &'static str,
    needle: &'static str,
    detail: &'static str,
}

#[derive(Debug, Clone, Copy)]
struct ForbiddenPattern {
    path: &'static str,
    needle: &'static str,
    detail: &'static str,
}

#[derive(Debug, Clone, Copy)]
struct AdrCloseoutCoverage {
    path: &'static str,
    historical_needles: &'static [&'static str],
    closeout_needles: &'static [&'static str],
    detail: &'static str,
}

#[derive(Debug, Clone, Copy)]
struct AuditProjectionField {
    toml_field: &'static str,
    rust_variant: &'static str,
    permission: &'static str,
    obligation_key: &'static str,
    wire_field: &'static str,
}

pub(crate) struct TenancyCloseout;

impl GovernanceCheck for TenancyCloseout {
    type Rule = Rule;

    fn name(&self) -> &'static str {
        "tenancy-closeout"
    }

    fn check(&self) -> Result<(String, Vec<Finding>)> {
        let root = crate::workspace_root()?;
        let mut findings = Vec::new();

        findings.extend(check_verify_ci_membership());
        findings.extend(check_required_lint_registry(&root)?);
        findings.extend(check_audit_projection_wiring(&root)?);
        findings.extend(check_required_anchors(&root)?);
        findings.extend(check_stale_closeout_wording(&root)?);

        Ok((
            format!(
                "{} verify/ci gates, {} dylints, {} doc anchors, {} projection fields checked",
                VERIFY_CI_REQUIRED_GATES.len(),
                TENANCY_DYLINTS.len(),
                REQUIRED_ANCHORS.len(),
                AUDIT_PROJECTION_FIELDS.len()
            ),
            findings,
        ))
    }
}

fn check_verify_ci_membership() -> Vec<Finding> {
    let full_labels: Vec<_> = crate::verify::full_plan()
        .iter()
        .map(crate::verify::Step::label)
        .collect();
    let ci_labels: Vec<_> = crate::verify::ci_plan()
        .iter()
        .map(crate::verify::Step::label)
        .collect();
    let mut findings = Vec::new();
    findings.extend(scan_plan_membership("verify", &full_labels));
    findings.extend(scan_plan_membership("ci", &ci_labels));
    findings
}

fn scan_plan_membership(lane: &str, labels: &[&str]) -> Vec<Finding> {
    VERIFY_CI_REQUIRED_GATES
        .iter()
        .filter(|required| !labels.contains(required))
        .map(|required| {
            finding(
                Rule::VerifyGate,
                format!("{lane}:{required}"),
                "verify/ci plan must include the tenant/RLS/AuthZ closeout gate set",
            )
        })
        .collect()
}

fn check_required_lint_registry(root: &Path) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    for path in REGISTRY_FILES {
        let content = read_required(root, path)?;
        findings.extend(scan_lint_registry(path, &content));
    }
    findings.extend(check_lint_directories(root));
    Ok(findings)
}

fn scan_lint_registry(path: &str, content: &str) -> Vec<Finding> {
    match path {
        "Cargo.toml" => scan_root_dylint_registry(path, content),
        "lints/Cargo.toml" => scan_lints_workspace_registry(path, content),
        _ => scan_text_lint_registry(path, content),
    }
}

fn scan_text_lint_registry(path: &str, content: &str) -> Vec<Finding> {
    TENANCY_DYLINTS
        .iter()
        .filter(|lint| !content.contains(**lint))
        .map(|lint| {
            finding(
                Rule::DylintRegistry,
                format!("{path}:{lint}"),
                "tenant/AuthZ/projection dylint must be registered and documented consistently",
            )
        })
        .collect()
}

fn scan_root_dylint_registry(path: &str, content: &str) -> Vec<Finding> {
    let Some(value) = parse_toml(path, content) else {
        return vec![finding(
            Rule::DylintRegistry,
            path.to_string(),
            "tenant/AuthZ/projection dylint registry TOML must parse",
        )];
    };
    let Some(libraries) = value
        .get("workspace")
        .and_then(|workspace| workspace.get("metadata"))
        .and_then(|metadata| metadata.get("dylint"))
        .and_then(|dylint| dylint.get("libraries"))
        .and_then(Value::as_array)
    else {
        return vec![finding(
            Rule::DylintRegistry,
            format!("{path}:workspace.metadata.dylint.libraries"),
            "root Cargo.toml must register dylints in [workspace.metadata.dylint].libraries",
        )];
    };

    let registered = libraries
        .iter()
        .filter_map(|library| library.get("path").and_then(Value::as_str))
        .filter_map(|path| path.strip_prefix("lints/"))
        .collect::<BTreeSet<_>>();
    missing_lint_findings(path, &registered)
}

fn scan_lints_workspace_registry(path: &str, content: &str) -> Vec<Finding> {
    let Some(value) = parse_toml(path, content) else {
        return vec![finding(
            Rule::DylintRegistry,
            path.to_string(),
            "lints workspace registry TOML must parse",
        )];
    };
    let Some(members) = value
        .get("workspace")
        .and_then(|workspace| workspace.get("members"))
        .and_then(Value::as_array)
    else {
        return vec![finding(
            Rule::DylintRegistry,
            format!("{path}:workspace.members"),
            "lints/Cargo.toml must register dylints in [workspace].members",
        )];
    };

    let registered = members
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    missing_lint_findings(path, &registered)
}

fn parse_toml(path: &str, content: &str) -> Option<Value> {
    content
        .parse::<Value>()
        .map_err(|e| {
            eprintln!("tenancy-closeout: parse {path} failed: {e}");
            e
        })
        .ok()
}

fn missing_lint_findings(path: &str, registered: &BTreeSet<&str>) -> Vec<Finding> {
    TENANCY_DYLINTS
        .iter()
        .filter(|lint| !registered.contains(**lint))
        .map(|lint| {
            finding(
                Rule::DylintRegistry,
                format!("{path}:{lint}"),
                "tenant/AuthZ/projection dylint must be structurally registered, not merely mentioned",
            )
        })
        .collect()
}

fn check_lint_directories(root: &Path) -> Vec<Finding> {
    TENANCY_DYLINTS
        .iter()
        .filter(|lint| !root.join("lints").join(lint).is_dir())
        .map(|lint| {
            finding(
                Rule::DylintRegistry,
                format!("lints/{lint}"),
                "registered tenant/AuthZ/projection dylint directory must exist",
            )
        })
        .collect()
}

fn check_audit_projection_wiring(root: &Path) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    findings.extend(scan_audit_contract_projection(&read_required(
        root,
        "contracts/http/audit/v1/contract.toml",
    )?));
    findings.extend(scan_generated_projection_fields(&read_required(
        root,
        "generated/src/http/audit_v1.rs",
    )?));
    findings.extend(scan_httpserve_projection_carrier(&read_required(
        root,
        "crates/httpserve/src/auth.rs",
    )?));
    findings.extend(scan_audit_rendering_projection(&read_required(
        root,
        "crates/audit/src/application.rs",
    )?));
    Ok(findings)
}

fn scan_audit_contract_projection(content: &str) -> Vec<Finding> {
    let Some(value) = parse_toml("contracts/http/audit/v1/contract.toml", content) else {
        return vec![finding(
            Rule::ProjectionAnchor,
            "contracts/http/audit/v1/contract.toml".to_string(),
            "audit contract TOML must parse for projection closeout validation",
        )];
    };
    let Some(fields) = value
        .get("endpoints")
        .and_then(|endpoints| endpoints.get("http"))
        .and_then(|http| http.get("projection"))
        .and_then(|projection| projection.get("fields"))
        .and_then(Value::as_array)
    else {
        return AUDIT_PROJECTION_FIELDS
            .iter()
            .map(|field| missing_projection(field, "contracts/http/audit/v1/contract.toml"))
            .collect();
    };

    AUDIT_PROJECTION_FIELDS
        .iter()
        .filter(|expected| {
            !fields.iter().any(|field| {
                field.get("field").and_then(Value::as_str) == Some(expected.toml_field)
                    && field.get("permission").and_then(Value::as_str) == Some(expected.permission)
                    && field.get("obligationKey").and_then(Value::as_str)
                        == Some(expected.obligation_key)
            })
        })
        .map(|field| missing_projection(field, "contracts/http/audit/v1/contract.toml"))
        .collect()
}

fn scan_generated_projection_fields(content: &str) -> Vec<Finding> {
    let stripped = strip_rust_line_comments(content);
    let Some(block) = slice_from_marker_until(&stripped, "pub const PROJECTION_FIELDS", "];")
    else {
        return AUDIT_PROJECTION_FIELDS
            .iter()
            .map(|field| missing_projection(field, "generated/src/http/audit_v1.rs"))
            .collect();
    };

    AUDIT_PROJECTION_FIELDS
        .iter()
        .filter(|expected| {
            let variant = format!("ProjectionField::{}", expected.rust_variant);
            let Some(entry) = slice_from_marker_until(block, &variant, "}") else {
                return true;
            };
            !(entry.contains(&format!("permission: \"{}\"", expected.permission))
                && entry.contains(&format!("obligation_key: \"{}\"", expected.obligation_key)))
        })
        .map(|field| missing_projection(field, "generated/src/http/audit_v1.rs"))
        .collect()
}

fn scan_httpserve_projection_carrier(content: &str) -> Vec<Finding> {
    let stripped = strip_rust_line_comments(content);
    let mut findings = Vec::new();
    if !stripped.contains("pub struct ResourceProjection") {
        findings.push(finding(
            Rule::ProjectionAnchor,
            "crates/httpserve/src/auth.rs:ResourceProjection",
            "http auth layer must expose ResourceProjection carrier",
        ));
    }

    let resource_impl = slice_from_marker_until(
        &stripped,
        "impl ResourceProjection",
        "pub enum RouteAuthorizationDecision",
    )
    .unwrap_or_default();
    if !(resource_impl.contains("pub fn default_masked()")
        && resource_impl.contains("FieldMask::default_masked()")
        && resource_impl.contains("pub fn render(")
        && resource_impl.contains("Self::MASKED"))
    {
        findings.push(finding(
            Rule::ProjectionAnchor,
            "crates/httpserve/src/auth.rs:ResourceProjection::default_masked/render",
            "ResourceProjection must default masked and own render masking",
        ));
    }

    let decision_enum = slice_from_marker_until(
        &stripped,
        "pub enum RouteAuthorizationDecision",
        "impl RouteAuthorizationDecision",
    )
    .unwrap_or_default();
    if !decision_enum.contains("AllowWithProjection(ResourceProjection)") {
        findings.push(finding(
            Rule::ProjectionAnchor,
            "crates/httpserve/src/auth.rs:AllowWithProjection",
            "route authorization must keep projection-bearing allow decision",
        ));
    }

    let decision_impl = compact_ws(
        slice_from_marker_until(
            &stripped,
            "impl RouteAuthorizationDecision",
            "impl RouteAuthorizer",
        )
        .unwrap_or_default(),
    );
    if !(decision_impl.contains("Self::Allow => Some(ResourceProjection::default_masked())")
        && decision_impl.contains("Self::AllowWithProjection(projection) => Some(projection)"))
    {
        findings.push(finding(
            Rule::ProjectionAnchor,
            "crates/httpserve/src/auth.rs:RouteAuthorizationDecision::projection",
            "allow decisions must carry default-masked or explicit ResourceProjection into auth context",
        ));
    }
    findings
}

fn scan_audit_rendering_projection(content: &str) -> Vec<Finding> {
    let stripped = strip_rust_line_comments(content);
    let Some(to_view) = slice_from_marker_until(&stripped, "fn to_view(", "fn to_response") else {
        return AUDIT_PROJECTION_FIELDS
            .iter()
            .map(|field| missing_projection(field, "crates/audit/src/application.rs"))
            .collect();
    };

    AUDIT_PROJECTION_FIELDS
        .iter()
        .filter(|expected| {
            let assignment = format!("{}: projection.render(", expected.wire_field);
            let Some(window) = slice_from_marker_with_len(to_view, &assignment, 320) else {
                return true;
            };
            !window.contains(&format!("ProjectionField::{}", expected.rust_variant))
        })
        .map(|field| missing_projection(field, "crates/audit/src/application.rs"))
        .collect()
}

fn missing_projection(field: &AuditProjectionField, path: &str) -> Finding {
    finding(
        Rule::ProjectionAnchor,
        format!("{path}:{}", field.rust_variant),
        format!(
            "audit projection chain must keep {} / {} / {} wired structurally",
            field.toml_field, field.permission, field.obligation_key
        ),
    )
}

fn check_required_anchors(root: &Path) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    for anchor in REQUIRED_ANCHORS {
        let content = read_required(root, anchor.path)?;
        findings.extend(scan_required_anchor(anchor, &content));
    }
    Ok(findings)
}

fn scan_required_anchor(anchor: &RequiredAnchor, content: &str) -> Vec<Finding> {
    if content.contains(anchor.needle) {
        Vec::new()
    } else {
        vec![finding(
            anchor.rule,
            format!("{}:{}", anchor.path, anchor.needle),
            anchor.detail,
        )]
    }
}

fn check_stale_closeout_wording(root: &Path) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    for pattern in STALE_CLOSEOUT_PATTERNS {
        let content = read_required(root, pattern.path)?;
        findings.extend(scan_forbidden_pattern(pattern, &content));
    }
    for coverage in ADR_CLOSEOUT_COVERAGE {
        let content = read_required(root, coverage.path)?;
        findings.extend(scan_adr_closeout_coverage(coverage, &content));
    }
    Ok(findings)
}

fn scan_forbidden_pattern(pattern: &ForbiddenPattern, content: &str) -> Vec<Finding> {
    content
        .lines()
        .enumerate()
        .filter(|(_, line)| line.contains(pattern.needle))
        .map(|(idx, _)| {
            finding(
                Rule::StaleCloseoutWording,
                format!("{}:{}", pattern.path, idx + 1),
                pattern.detail,
            )
        })
        .collect()
}

fn scan_adr_closeout_coverage(coverage: &AdrCloseoutCoverage, content: &str) -> Vec<Finding> {
    let has_historical_future = coverage
        .historical_needles
        .iter()
        .any(|needle| content.contains(needle));
    if !has_historical_future {
        return Vec::new();
    }

    let missing = coverage
        .closeout_needles
        .iter()
        .filter(|needle| !content.contains(**needle))
        .copied()
        .collect::<Vec<_>>();
    if missing.is_empty() {
        Vec::new()
    } else {
        vec![finding(
            Rule::StaleCloseoutWording,
            format!("{}:closeout-addendum", coverage.path),
            format!("{}; missing {}", coverage.detail, missing.join(", ")),
        )]
    }
}

fn strip_rust_line_comments(content: &str) -> String {
    content
        .lines()
        .map(|line| line.split_once("//").map_or(line, |(code, _)| code))
        .collect::<Vec<_>>()
        .join("\n")
}

fn slice_from_marker_until<'a>(
    content: &'a str,
    marker: &str,
    terminator: &str,
) -> Option<&'a str> {
    let start = content.find(marker)?;
    let rest = &content[start..];
    let end = rest
        .find(terminator)
        .map_or(rest.len(), |idx| idx + terminator.len());
    Some(&rest[..end])
}

fn slice_from_marker_with_len<'a>(content: &'a str, marker: &str, len: usize) -> Option<&'a str> {
    let start = content.find(marker)?;
    let end = content.len().min(start + len);
    Some(&content[start..end])
}

fn compact_ws(content: &str) -> String {
    content.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn read_required(root: &Path, rel: &str) -> Result<String> {
    let path = root.join(rel);
    if !path.is_file() {
        bail!("tenancy-closeout: required file {rel} missing");
    }
    std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("tenancy-closeout: read {rel} failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_verify_step_is_reported() {
        let findings = scan_plan_membership("verify", &["contract-validate", "codegen-check"]);
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::VerifyGate
                    && finding.subject == "verify:tenancy-closeout"),
            "{findings:?}"
        );
    }

    #[test]
    fn missing_lint_registration_is_reported() {
        let content = TENANCY_DYLINTS
            .iter()
            .copied()
            .filter(|lint| *lint != "rss_projection_append_only")
            .collect::<Vec<_>>()
            .join("\n");
        let findings = scan_lint_registry("lints/README.md", &content);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].rule, Rule::DylintRegistry);
        assert!(
            findings[0].subject.contains("rss_projection_append_only"),
            "{findings:?}"
        );
    }

    #[test]
    fn root_lint_registry_ignores_comment_only_lint() {
        let content = r#"
[workspace.metadata.dylint]
libraries = [
  { path = "lints/rss_crosstenant_callsite" },
  { path = "lints/rss_principal_facet_impl_allowlist" },
  { path = "lints/rss_authplan_callsite" },
  { path = "lints/rss_authenticated_callsite" },
  { path = "lints/rss_handler_local_principal_authz" },
  { path = "lints/rss_pdp_impl_adapter_only" },
]
# rss_projection_append_only appears only in a comment.
"#;
        let findings = scan_lint_registry("Cargo.toml", content);
        assert!(
            findings
                .iter()
                .any(|finding| finding.subject.contains("rss_projection_append_only")),
            "{findings:?}"
        );
    }

    #[test]
    fn lints_workspace_registry_ignores_comment_only_member() {
        let content = r#"
[workspace]
members = [
  "rss_crosstenant_callsite",
  "rss_principal_facet_impl_allowlist",
  "rss_authplan_callsite",
  "rss_authenticated_callsite",
  "rss_handler_local_principal_authz",
  "rss_pdp_impl_adapter_only",
]
# rss_projection_append_only appears only in a comment.
"#;
        let findings = scan_lint_registry("lints/Cargo.toml", content);
        assert!(
            findings
                .iter()
                .any(|finding| finding.subject.contains("rss_projection_append_only")),
            "{findings:?}"
        );
    }

    #[test]
    fn missing_projection_anchor_is_reported() {
        let anchor = RequiredAnchor {
            rule: Rule::ProjectionAnchor,
            path: "generated/src/http/audit_v1.rs",
            needle: "ProjectionField::AuditActor",
            detail: "must exist",
        };
        let findings = scan_required_anchor(&anchor, "ProjectionField::Other");
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].rule, Rule::ProjectionAnchor);
    }

    #[test]
    fn audit_rendering_projection_comment_only_is_reported() {
        let content = r#"
fn to_view() -> AuditEntryView {
    // actor: projection.render(vocab::ProjectionField::AuditActor, raw)
    AuditEntryView {
        actor: entry.actor().as_uuid().to_string(),
        resource_id: entry.resource().id().to_string(),
    }
}
"#;
        let findings = scan_audit_rendering_projection(content);
        assert!(
            findings.iter().any(|finding| {
                finding.rule == Rule::ProjectionAnchor && finding.subject.contains("AuditActor")
            }),
            "{findings:?}"
        );
    }

    #[test]
    fn contract_projection_requires_exact_toml_mapping() {
        let content = r#"
[endpoints.http.projection]
fields = [
  { field = "auditActor", permission = "audit:field:actor" },
  { field = "auditResourceId", permission = "audit:field:resource_id", obligationKey = "audit.resource_id" },
]
"#;
        let findings = scan_audit_contract_projection(content);
        assert!(
            findings.iter().any(|finding| {
                finding.rule == Rule::ProjectionAnchor && finding.subject.contains("AuditActor")
            }),
            "{findings:?}"
        );
    }

    #[test]
    fn generated_projection_requires_permission_and_obligation_same_entry() {
        let content = r#"
pub const PROJECTION_FIELDS: &[super::HttpProjectionFieldSpec] = &[
    super::HttpProjectionFieldSpec {
        field: ::vocab::ProjectionField::AuditActor,
    },
    super::HttpProjectionFieldSpec {
        field: ::vocab::ProjectionField::AuditResourceId,
        permission: "audit:field:resource_id",
        obligation_key: "audit.resource_id",
    },
];
"#;
        let findings = scan_generated_projection_fields(content);
        assert!(
            findings.iter().any(|finding| {
                finding.rule == Rule::ProjectionAnchor && finding.subject.contains("AuditActor")
            }),
            "{findings:?}"
        );
    }

    #[test]
    fn stale_closeout_wording_is_reported() {
        let pattern = ForbiddenPattern {
            path: "docs/architecture/adr.md",
            needle: "dual-pool bootstrap 接线",
            detail: "stale",
        };
        let findings = scan_forbidden_pattern(&pattern, "后续 dual-pool bootstrap 接线 另行处理");
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].rule, Rule::StaleCloseoutWording);
    }

    #[test]
    fn adr_historical_future_wording_requires_closeout_addendum() {
        let coverage = AdrCloseoutCoverage {
            path: "docs/architecture/adr-006.md",
            historical_needles: &["#1109 未落地", "验签空窗"],
            closeout_needles: &["Closeout addendum", "VerifiedClaims"],
            detail: "ADR historical future wording must be covered by closeout addendum",
        };
        let findings = scan_adr_closeout_coverage(&coverage, "#1109 未落地期间存在验签空窗。");
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].rule, Rule::StaleCloseoutWording);
    }

    #[test]
    fn green_fixture_has_no_findings() {
        assert!(scan_plan_membership("ci", VERIFY_CI_REQUIRED_GATES).is_empty());

        let root_lint_fixture = format!(
            "[workspace.metadata.dylint]\nlibraries = [{}]\n",
            TENANCY_DYLINTS
                .iter()
                .map(|lint| format!("{{ path = \"lints/{lint}\" }}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
        assert!(scan_lint_registry("Cargo.toml", &root_lint_fixture).is_empty());

        let lints_workspace_fixture = format!(
            "[workspace]\nmembers = [{}]\n",
            TENANCY_DYLINTS
                .iter()
                .map(|lint| format!("\"{lint}\""))
                .collect::<Vec<_>>()
                .join(", ")
        );
        assert!(scan_lint_registry("lints/Cargo.toml", &lints_workspace_fixture).is_empty());

        let lint_doc_fixture = TENANCY_DYLINTS.join("\n");
        assert!(scan_lint_registry("lints/README.md", &lint_doc_fixture).is_empty());

        let anchor = RequiredAnchor {
            rule: Rule::DocAnchor,
            path: "docs/rules/tenancy.md",
            needle: "ResourceProjection",
            detail: "must exist",
        };
        assert!(scan_required_anchor(&anchor, "ResourceProjection").is_empty());

        let pattern = ForbiddenPattern {
            path: "docs/architecture/adr.md",
            needle: "future work",
            detail: "stale",
        };
        assert!(scan_forbidden_pattern(&pattern, "final status").is_empty());
    }
}
