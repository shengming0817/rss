//! `tenancy-closeout` -- tenancy/AuthZ/projection closeout reverse self-check.
//!
//! INVARIANT: TENANCY-CLOSEOUT-REVERSE-01 { level = "Medium", exec = "check", source = "code" } -- final
//! tenancy governance facts must stay machine-visible in verify/ci membership, dylint registration,
//! projection wiring, and code/config carriers.
//! INVARIANT: TENANCY-SERVICE-IDENTITY-SCOPE-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::missing_service_token_claim_bound_e2e_carrier_is_reported", anti_vacuity = "tests::required_code_carriers_anchor_service_token_claim_bound_e2e" } -- service-token
//! claim-bound canonical tenant headers and mTLS/SPIFFE tenantless service identity must remain locked by reverse
//! closeout anchors.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Result, bail};
use toml::Value;

use crate::contract::governance::ContractGovernanceIr;
use crate::contract::manifest::HttpProjectionFieldName;
use crate::diagnostic::{self, GovernanceCheck, finding};

pub(crate) type Finding = diagnostic::Finding<Rule>;

const VERIFY_CI_REQUIRED_GATES: &[&str] = &[
    "contract-validate",
    "codegen-check",
    "schema-rls",
    "pg-tenant-tx-guard",
    "repo-scope-guard",
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

const REGISTRY_FILES: &[&str] = &["Cargo.toml", "lints/Cargo.toml"];
const TENANCY_CONSUMER_EXAMPLE_PATH: &str = "examples/tenancy-consumer/src/main.rs";
const TENANCY_CONSUMER_GENERATED_SPEC_TEST_PATH: &str =
    "xtask/tests/tenancy_closeout_generated_specs.rs";
const AUTH_E2E_TEST_PATH: &str = "assemblies/runtime/tests/auth_e2e.rs";

/// Code carriers bind governance facts to **code/config** only.
///
/// Markdown checks are not enforcement: they duplicate constraints that real gates already own
/// and force prose to restate implementation detail. Constraints that earlier doc anchors named
/// are carried by their own gates (`schema-rls`, `pg-tenant-tx-guard`,
/// `PgStore::verify_rls_capability`, `TENANCY-PG-CATALOG-PROOF-01` /
/// `TENANCY-PG-BEHAVIOR-PROOF-01`, the tenancy dylints, and the projection chain checks below).
const REQUIRED_CODE_CARRIERS: &[RequiredCodeCarrier] = &[
    RequiredCodeCarrier {
        rule: Rule::CodeCarrier,
        path: "Cargo.toml",
        needle: "\"examples/tenancy-consumer\"",
        detail: "tenancy consumer example must be a workspace member",
    },
    RequiredCodeCarrier {
        rule: Rule::CodeCarrier,
        path: AUTH_E2E_TEST_PATH,
        needle: "internal_mtls_verified_peer_remains_tenantless_scope",
        detail: "runtime auth e2e must lock mTLS service principal as tenantless",
    },
    RequiredCodeCarrier {
        rule: Rule::CodeCarrier,
        path: AUTH_E2E_TEST_PATH,
        needle: "service_token_missing_or_wrong_tenant_header_is_401",
        detail: "runtime auth e2e must lock missing/wrong service-token tenant header as 401",
    },
    RequiredCodeCarrier {
        rule: Rule::CodeCarrier,
        path: AUTH_E2E_TEST_PATH,
        needle: "service_token_duplicate_tenant_header_is_401",
        detail: "runtime auth e2e must lock duplicate service-token tenant header as 401",
    },
    RequiredCodeCarrier {
        rule: Rule::CodeCarrier,
        path: AUTH_E2E_TEST_PATH,
        needle: "service_token_establishes_scope_from_claim_bound_tenant",
        detail: "runtime auth e2e must lock claim-bound service-token ambient tenant scope",
    },
    RequiredCodeCarrier {
        rule: Rule::CodeCarrier,
        path: AUTH_E2E_TEST_PATH,
        needle: "service_token_missing_tenant_claim_is_401",
        detail: "runtime auth e2e must lock missing signed tenant_id claim as 401",
    },
    RequiredCodeCarrier {
        rule: Rule::CodeCarrier,
        path: AUTH_E2E_TEST_PATH,
        needle: "service_token_tampered_signature_is_401",
        detail: "runtime auth e2e must lock tampered standard JWS HS256 signature as 401",
    },
    RequiredCodeCarrier {
        rule: Rule::CodeCarrier,
        path: AUTH_E2E_TEST_PATH,
        needle: "VerifiedMtlsPeer",
        detail: "runtime auth e2e must inject verified mTLS evidence",
    },
    RequiredCodeCarrier {
        rule: Rule::CodeCarrier,
        path: AUTH_E2E_TEST_PATH,
        needle: "body, SCOPE_MISSING",
        detail: "runtime auth e2e must assert mTLS does not establish ambient tenant scope",
    },
    RequiredCodeCarrier {
        rule: Rule::CodeCarrier,
        path: TENANCY_CONSUMER_GENERATED_SPEC_TEST_PATH,
        needle: "generated::http::identity_v1::login::SPEC",
        detail: "tenancy closeout generated-spec smoke test must compile against generated login spec",
    },
    RequiredCodeCarrier {
        rule: Rule::CodeCarrier,
        path: TENANCY_CONSUMER_EXAMPLE_PATH,
        needle: "GeneratedPrimaryEndpoint::new",
        detail: "consumer example must compile against generated Primary endpoint wiring",
    },
    RequiredCodeCarrier {
        rule: Rule::CodeCarrier,
        path: TENANCY_CONSUMER_EXAMPLE_PATH,
        needle: "evidence.self_scoped()",
        detail: "consumer example must read generated self-scoped route evidence",
    },
    RequiredCodeCarrier {
        rule: Rule::CodeCarrier,
        path: TENANCY_CONSUMER_EXAMPLE_PATH,
        needle: "ProjectionField::AuditActor",
        detail: "consumer example must compile against projection field vocabulary",
    },
];

const AUDIT_PROJECTION_FIELDS: &[HttpProjectionFieldName] = &[
    HttpProjectionFieldName::AuditTenantId,
    HttpProjectionFieldName::AuditActor,
    HttpProjectionFieldName::AuditResourceId,
];

const IDENTITY_PROFILE_PROJECTION_FIELDS: &[HttpProjectionFieldName] = &[
    HttpProjectionFieldName::IdentityProfileSubject,
    HttpProjectionFieldName::IdentityProfileTenantId,
];

const PROJECTION_ENDPOINTS: &[ProjectionEndpoint] = &[
    ProjectionEndpoint {
        chain_name: "audit scoped read",
        contract_path: "contracts/http/audit/v1/list-entries/contract.toml",
        generated_path: "generated/src/http/audit_v1.rs",
        generated_start: "pub mod list_entries {",
        generated_end: "pub mod list_tenant_entries {",
        rendering_path: "crates/audit/src/application.rs",
        rendering_start: "fn project_audit_entry(",
        rendering_end: "fn to_response",
        render_callee: "projection",
        fields: AUDIT_PROJECTION_FIELDS,
    },
    ProjectionEndpoint {
        chain_name: "audit target-tenant read",
        contract_path: "contracts/http/audit/v1/list-tenant-entries/contract.toml",
        generated_path: "generated/src/http/audit_v1.rs",
        generated_start: "pub mod list_tenant_entries {",
        generated_end: "pub const SPEC: super::super::HttpSpec = super::super::HttpSpec {",
        rendering_path: "crates/audit/src/application.rs",
        rendering_start: "fn project_audit_entry(",
        rendering_end: "fn to_view(",
        render_callee: "projection",
        fields: AUDIT_PROJECTION_FIELDS,
    },
    ProjectionEndpoint {
        chain_name: "identity profile",
        contract_path: "contracts/http/identity/v1/profile/contract.toml",
        generated_path: "generated/src/http/identity_v1.rs",
        generated_start: "pub mod profile {",
        generated_end: "pub mod refresh {",
        rendering_path: "crates/identity/src/application/mod.rs",
        rendering_start: "async fn profile_handler",
        rendering_end: "async fn password_change_handler",
        render_callee: "auth.projection",
        fields: IDENTITY_PROFILE_PROJECTION_FIELDS,
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Rule {
    VerifyGate,
    DylintRegistry,
    ProjectionAnchor,
    CodeCarrier,
}

#[derive(Debug, Clone, Copy)]
struct RequiredCodeCarrier {
    rule: Rule,
    path: &'static str,
    needle: &'static str,
    detail: &'static str,
}

#[derive(Debug, Clone, Copy)]
struct ProjectionEndpoint {
    chain_name: &'static str,
    contract_path: &'static str,
    generated_path: &'static str,
    generated_start: &'static str,
    generated_end: &'static str,
    rendering_path: &'static str,
    rendering_start: &'static str,
    rendering_end: &'static str,
    render_callee: &'static str,
    fields: &'static [HttpProjectionFieldName],
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
        findings.extend(check_projection_wiring(&root)?);
        findings.extend(check_required_code_carriers(&root)?);
        Ok((
            format!(
                "{} verify/ci gates, {} dylints, {} code carriers, {} projection fields checked",
                VERIFY_CI_REQUIRED_GATES.len(),
                TENANCY_DYLINTS.len(),
                REQUIRED_CODE_CARRIERS.len(),
                projection_field_count()
            ),
            findings,
        ))
    }
}

fn projection_field_count() -> usize {
    PROJECTION_ENDPOINTS
        .iter()
        .map(|endpoint| endpoint.fields.len())
        .sum()
}

fn check_verify_ci_membership() -> Vec<Finding> {
    let full_labels: Vec<_> = crate::verify::plan_for(crate::verify::PlanProjection::Verify)
        .iter()
        .map(crate::verify::Step::label)
        .collect();
    let ci_labels: Vec<_> = crate::verify::plan_for(crate::verify::PlanProjection::Profile(
        crate::execution_profiles::ExecutionProfile::ReleaseCheck,
    ))
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
        _ => Vec::new(),
    }
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

fn check_projection_wiring(root: &Path) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    findings.extend(scan_httpserve_projection_carrier(&read_required(
        root,
        "crates/httpserve/src/auth.rs",
    )?));
    findings.extend(check_projection_endpoint_coverage(root)?);
    for endpoint in PROJECTION_ENDPOINTS {
        findings.extend(scan_contract_projection(
            endpoint,
            &read_required(root, endpoint.contract_path)?,
        ));
        findings.extend(scan_generated_projection_fields(
            endpoint,
            &read_required(root, endpoint.generated_path)?,
        ));
        findings.extend(scan_rendering_projection(
            endpoint,
            &read_required(root, endpoint.rendering_path)?,
        ));
    }
    Ok(findings)
}

fn check_projection_endpoint_coverage(root: &Path) -> Result<Vec<Finding>> {
    let governance = ContractGovernanceIr::load_consumer_workspace(root)?;
    let projection_contracts = governance.read(|contracts| {
        Ok(contracts
            .iter()
            .filter(|contract| {
                contract
                    .manifest()
                    .endpoints
                    .as_ref()
                    .and_then(|endpoints| endpoints.http.as_ref())
                    .and_then(|http| http.projection.as_ref())
                    .is_some_and(|projection| !projection.fields.is_empty())
            })
            .map(|contract| relative_contract_path(root, contract.dir()))
            .collect::<Vec<_>>())
    })?;
    Ok(scan_projection_endpoint_coverage(projection_contracts))
}

fn relative_contract_path(root: &Path, dir: &Path) -> String {
    let manifest_path = dir.join("contract.toml");
    manifest_path
        .strip_prefix(root)
        .unwrap_or(&manifest_path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn scan_projection_endpoint_coverage(projection_contracts: Vec<String>) -> Vec<Finding> {
    let covered = PROJECTION_ENDPOINTS
        .iter()
        .map(|endpoint| endpoint.contract_path)
        .collect::<BTreeSet<_>>();
    projection_contracts
        .into_iter()
        .filter(|path| !covered.contains(path.as_str()))
        .map(|path| {
            finding(
                Rule::ProjectionAnchor,
                path,
                "projection contract must have a tenancy-closeout rendering anchor",
            )
        })
        .collect()
}

fn scan_contract_projection(endpoint: &ProjectionEndpoint, content: &str) -> Vec<Finding> {
    let Some(value) = parse_toml(endpoint.contract_path, content) else {
        return vec![finding(
            Rule::ProjectionAnchor,
            endpoint.contract_path.to_string(),
            "projection contract TOML must parse for closeout validation",
        )];
    };
    let Some(fields) = value
        .get("endpoints")
        .and_then(|endpoints| endpoints.get("http"))
        .and_then(|http| http.get("projection"))
        .and_then(|projection| projection.get("fields"))
        .and_then(Value::as_array)
    else {
        return endpoint
            .fields
            .iter()
            .map(|field| missing_projection(endpoint, field, endpoint.contract_path))
            .collect();
    };

    endpoint
        .fields
        .iter()
        .filter(|expected| {
            let expected = expected.spec();
            !fields.iter().any(|field| {
                field.get("field").and_then(Value::as_str) == Some(expected.wire)
                    && field.get("permission").and_then(Value::as_str) == Some(expected.permission)
                    && field.get("obligationKey").and_then(Value::as_str)
                        == Some(expected.obligation_key)
                    && field.get("responsePath").and_then(Value::as_str)
                        == Some(expected.response_path)
            })
        })
        .map(|field| missing_projection(endpoint, field, endpoint.contract_path))
        .collect()
}

fn scan_generated_projection_fields(endpoint: &ProjectionEndpoint, content: &str) -> Vec<Finding> {
    let stripped = strip_rust_line_comments(content);
    let scope = if endpoint.generated_start.is_empty() {
        stripped.as_str()
    } else {
        slice_from_marker_until(&stripped, endpoint.generated_start, endpoint.generated_end)
            .unwrap_or_default()
    };
    let Some(block) = slice_from_marker_until(scope, "pub const PROJECTION_FIELDS", "];") else {
        return endpoint
            .fields
            .iter()
            .map(|field| missing_projection(endpoint, field, endpoint.generated_path))
            .collect();
    };

    endpoint
        .fields
        .iter()
        .filter(|expected| {
            let expected = expected.spec();
            let variant = format!("ProjectionField::{}", expected.vocab_variant);
            let Some(entry) = slice_from_marker_until(block, &variant, "}") else {
                return true;
            };
            let Ok(permission) = vocab::RoutePermissionId::parse(expected.permission) else {
                return true;
            };
            !(entry.contains(&format!(
                "permission: ::vocab::RoutePermissionId::{}",
                permission.variant_name()
            )) && entry.contains(&format!("obligation_key: \"{}\"", expected.obligation_key))
                && entry.contains(&format!("response_path: \"{}\"", expected.response_path)))
        })
        .map(|field| missing_projection(endpoint, field, endpoint.generated_path))
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

fn scan_rendering_projection(endpoint: &ProjectionEndpoint, content: &str) -> Vec<Finding> {
    let stripped = strip_rust_line_comments(content);
    let Some(rendering) =
        slice_from_marker_until(&stripped, endpoint.rendering_start, endpoint.rendering_end)
    else {
        return endpoint
            .fields
            .iter()
            .map(|field| missing_projection(endpoint, field, endpoint.rendering_path))
            .collect();
    };

    endpoint
        .fields
        .iter()
        .filter(|expected| {
            let expected = expected.spec();
            let assignment = format!(
                "{}: {}.render(",
                rust_field_from_response_path(expected.response_path),
                endpoint.render_callee
            );
            let Some(window) = slice_from_marker_with_len(rendering, &assignment, 360) else {
                return true;
            };
            !window.contains(&format!("ProjectionField::{}", expected.vocab_variant))
        })
        .map(|field| missing_projection(endpoint, field, endpoint.rendering_path))
        .collect()
}

fn rust_field_from_response_path(response_path: &str) -> String {
    let field = response_path
        .rsplit_once('.')
        .map_or(response_path, |(_, field)| field)
        .trim_end_matches("[]");
    camel_to_snake(field)
}

fn camel_to_snake(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        if ch.is_ascii_uppercase() {
            if !out.is_empty() {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

fn missing_projection(
    endpoint: &ProjectionEndpoint,
    field: &HttpProjectionFieldName,
    path: &str,
) -> Finding {
    let spec = field.spec();
    finding(
        Rule::ProjectionAnchor,
        format!("{path}:{}", spec.vocab_variant),
        format!(
            "{} projection chain must keep {} / {} / {} wired structurally",
            endpoint.chain_name, spec.wire, spec.permission, spec.obligation_key
        ),
    )
}

fn check_required_code_carriers(root: &Path) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    for carrier in REQUIRED_CODE_CARRIERS {
        let content = read_required(root, carrier.path)?;
        findings.extend(scan_required_code_carrier(carrier, &content));
    }
    Ok(findings)
}

fn scan_required_code_carrier(carrier: &RequiredCodeCarrier, content: &str) -> Vec<Finding> {
    let stripped;
    let searchable = if carrier.path.ends_with(".rs") {
        stripped = strip_rust_line_comments(content);
        stripped.as_str()
    } else {
        content
    };
    if searchable.contains(carrier.needle) {
        Vec::new()
    } else {
        vec![finding(
            carrier.rule,
            format!("{}:{}", carrier.path, carrier.needle),
            carrier.detail,
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
    let end = rest.find(terminator)? + terminator.len();
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
        let content = format!(
            "[workspace]\nmembers = [{}]\n",
            TENANCY_DYLINTS
                .iter()
                .filter(|lint| **lint != "rss_projection_append_only")
                .map(|lint| format!("\"{lint}\""))
                .collect::<Vec<_>>()
                .join(", ")
        );
        let findings = scan_lint_registry("lints/Cargo.toml", &content);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].rule, Rule::DylintRegistry);
        assert!(
            findings[0].subject.contains("rss_projection_append_only"),
            "{findings:?}"
        );
    }

    /// RED anti-vacuity for TENANCY-SERVICE-IDENTITY-SCOPE-01: reverse closeout must
    /// structurally pin the claim-bound service-token runtime e2e carriers (not merely mTLS).
    #[test]
    fn required_code_carriers_anchor_service_token_claim_bound_e2e() {
        const REQUIRED: &[&str] = &[
            "service_token_missing_or_wrong_tenant_header_is_401",
            "service_token_duplicate_tenant_header_is_401",
            "service_token_establishes_scope_from_claim_bound_tenant",
            "service_token_missing_tenant_claim_is_401",
            "service_token_tampered_signature_is_401",
        ];
        for needle in REQUIRED {
            assert!(
                REQUIRED_CODE_CARRIERS.iter().any(|carrier| {
                    carrier.path == AUTH_E2E_TEST_PATH && carrier.needle == *needle
                }),
                "TENANCY-SERVICE-IDENTITY-SCOPE-01 reverse closeout must anchor {needle}"
            );
        }
    }

    #[test]
    fn missing_service_identity_scope_carrier_is_reported() {
        let carrier = RequiredCodeCarrier {
            rule: Rule::CodeCarrier,
            path: AUTH_E2E_TEST_PATH,
            needle: "internal_mtls_verified_peer_remains_tenantless_scope",
            detail: "must exist",
        };
        let findings = scan_required_code_carrier(&carrier, "async fn unrelated_case() {}");
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].rule, Rule::CodeCarrier);
        assert!(
            findings[0]
                .subject
                .contains("internal_mtls_verified_peer_remains_tenantless_scope"),
            "{findings:?}"
        );
    }

    #[test]
    fn missing_service_token_claim_bound_e2e_carrier_is_reported() {
        let carrier = RequiredCodeCarrier {
            rule: Rule::CodeCarrier,
            path: AUTH_E2E_TEST_PATH,
            needle: "service_token_establishes_scope_from_claim_bound_tenant",
            detail: "must exist",
        };
        let findings = scan_required_code_carrier(
            &carrier,
            "// service_token_establishes_scope_from_claim_bound_tenant documented only\n\
             async fn internal_mtls_verified_peer_remains_tenantless_scope() {}",
        );
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].rule, Rule::CodeCarrier);
        assert!(
            findings[0]
                .subject
                .contains("service_token_establishes_scope_from_claim_bound_tenant"),
            "{findings:?}"
        );
    }

    #[test]
    fn missing_mtls_tenantless_e2e_carrier_is_reported() {
        let carrier = RequiredCodeCarrier {
            rule: Rule::CodeCarrier,
            path: AUTH_E2E_TEST_PATH,
            needle: "internal_mtls_verified_peer_remains_tenantless_scope",
            detail: "must exist",
        };
        let findings = scan_required_code_carrier(
            &carrier,
            "// internal_mtls_verified_peer_remains_tenantless_scope documented only\n\
             async fn service_token_establishes_scope_from_claim_bound_tenant() {}",
        );
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].rule, Rule::CodeCarrier);
        assert!(
            findings[0]
                .subject
                .contains("internal_mtls_verified_peer_remains_tenantless_scope"),
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
    fn missing_projection_carrier_is_reported() {
        let carrier = RequiredCodeCarrier {
            rule: Rule::ProjectionAnchor,
            path: "generated/src/http/audit_v1.rs",
            needle: "ProjectionField::AuditActor",
            detail: "must exist",
        };
        let findings = scan_required_code_carrier(&carrier, "ProjectionField::Other");
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].rule, Rule::ProjectionAnchor);
    }

    #[test]
    fn rust_source_required_code_carrier_ignores_line_comment_only() {
        let carrier = RequiredCodeCarrier {
            rule: Rule::CodeCarrier,
            path: TENANCY_CONSUMER_EXAMPLE_PATH,
            needle: "GeneratedPrimaryEndpoint::new",
            detail: "must exist",
        };
        let findings = scan_required_code_carrier(
            &carrier,
            r#"
fn main() {
    // GeneratedPrimaryEndpoint::new
}
"#,
        );
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(
            findings[0]
                .subject
                .contains("GeneratedPrimaryEndpoint::new"),
            "{findings:?}"
        );
    }

    #[test]
    fn audit_rendering_projection_comment_only_is_reported() {
        let content = r#"
fn project_audit_entry() -> ProjectedAuditEntry {
    // actor: projection.render(vocab::ProjectionField::AuditActor, raw)
    ProjectedAuditEntry {
        actor: entry.actor().as_uuid().to_string(),
        resource_id: entry.resource().id().to_string(),
    }
}
"#;
        let findings = scan_rendering_projection(&PROJECTION_ENDPOINTS[0], content);
        assert!(
            findings.iter().any(|finding| {
                finding.rule == Rule::ProjectionAnchor && finding.subject.contains("AuditActor")
            }),
            "{findings:?}"
        );
    }

    #[test]
    fn profile_rendering_projection_comment_only_is_reported() {
        let content = r#"
async fn profile_handler(req: Request<Body>) -> Response {
    // subject: auth.projection.render(vocab::ProjectionField::IdentityProfileSubject, raw)
    Json(IdentityProfileResponse {
        data: IdentityProfileData {
            subject: auth.subject,
            tenant_id: auth.tenant.to_string(),
        },
    })
}
async fn password_change_handler() {}
"#;
        let findings = scan_rendering_projection(&PROJECTION_ENDPOINTS[2], content);
        assert!(
            findings.iter().any(|finding| {
                finding.rule == Rule::ProjectionAnchor
                    && finding.subject.contains("IdentityProfileSubject")
            }),
            "{findings:?}"
        );
    }

    #[test]
    fn projection_contract_without_closeout_endpoint_is_reported() {
        let findings = scan_projection_endpoint_coverage(vec![
            "contracts/http/audit/v1/list-entries/contract.toml".to_string(),
            "contracts/http/audit/v1/list-tenant-entries/contract.toml".to_string(),
            "contracts/http/identity/v1/profile/contract.toml".to_string(),
            "contracts/http/example/v1/contract.toml".to_string(),
        ]);
        assert!(
            findings.iter().any(|finding| {
                finding.rule == Rule::ProjectionAnchor
                    && finding
                        .subject
                        .contains("contracts/http/example/v1/contract.toml")
            }),
            "{findings:?}"
        );
    }

    #[test]
    fn response_path_last_segment_maps_to_rust_field_name() {
        assert_eq!(
            rust_field_from_response_path("data[].tenantId"),
            "tenant_id"
        );
        assert_eq!(
            rust_field_from_response_path("data[].resourceId"),
            "resource_id"
        );
        assert_eq!(rust_field_from_response_path("data.subject"), "subject");
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
        let findings = scan_contract_projection(&PROJECTION_ENDPOINTS[0], content);
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
        permission: ::vocab::RoutePermissionId::AuditFieldResourceId,
        obligation_key: "audit.resource_id",
        },
];
"#;
        let findings = scan_generated_projection_fields(&PROJECTION_ENDPOINTS[0], content);
        assert!(
            findings.iter().any(|finding| {
                finding.rule == Rule::ProjectionAnchor && finding.subject.contains("AuditActor")
            }),
            "{findings:?}"
        );
    }

    #[test]
    fn generated_projection_missing_end_marker_does_not_scan_later_module() {
        let endpoint = ProjectionEndpoint {
            chain_name: "synthetic target",
            contract_path: "contracts/http/synthetic/v1/contract.toml",
            generated_path: "generated/src/http/synthetic_v1.rs",
            generated_start: "pub mod target {",
            generated_end: "pub const SPEC: super::super::HttpSpec = super::super::HttpSpec {",
            rendering_path: "crates/synthetic/src/application.rs",
            rendering_start: "fn target_handler(",
            rendering_end: "fn unrelated_handler(",
            render_callee: "projection",
            fields: AUDIT_PROJECTION_FIELDS,
        };
        let content = r#"
pub mod target {
}

pub mod unrelated {
    pub const PROJECTION_FIELDS: &[super::super::HttpProjectionFieldSpec] = &[
        super::super::HttpProjectionFieldSpec {
            field: ::vocab::ProjectionField::AuditTenantId,
            permission: ::vocab::RoutePermissionId::AuditFieldTenantId,
            obligation_key: "audit.tenant_id",
            response_path: "data[].tenantId",
        },
        super::super::HttpProjectionFieldSpec {
            field: ::vocab::ProjectionField::AuditActor,
            permission: ::vocab::RoutePermissionId::AuditFieldActor,
            obligation_key: "audit.actor",
            response_path: "data[].actor",
        },
        super::super::HttpProjectionFieldSpec {
            field: ::vocab::ProjectionField::AuditResourceId,
            permission: ::vocab::RoutePermissionId::AuditFieldResourceId,
            obligation_key: "audit.resource_id",
            response_path: "data[].resourceId",
        },
    ];
}
"#;

        let findings = scan_generated_projection_fields(&endpoint, content);
        assert_eq!(
            findings.len(),
            AUDIT_PROJECTION_FIELDS.len(),
            "{findings:?}"
        );
    }

    #[test]
    fn green_fixture_has_no_findings() {
        assert!(scan_plan_membership("ci", VERIFY_CI_REQUIRED_GATES).is_empty());
        assert!(
            VERIFY_CI_REQUIRED_GATES.contains(&"repo-scope-guard"),
            "tenancy closeout required gate set must include repo-scope-guard"
        );

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

        let carrier = RequiredCodeCarrier {
            rule: Rule::CodeCarrier,
            path: AUTH_E2E_TEST_PATH,
            needle: "VerifiedMtlsPeer",
            detail: "must exist",
        };
        assert!(scan_required_code_carrier(&carrier, "VerifiedMtlsPeer").is_empty());
    }
}
