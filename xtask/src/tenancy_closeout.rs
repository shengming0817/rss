//! `tenancy-closeout` -- tenancy/AuthZ/projection closeout reverse self-check.
//!
//! INVARIANT: TENANCY-CLOSEOUT-REVERSE-01 { level = "Medium", exec = "verify", source = "code" } -- final
//! tenancy governance facts must stay machine-visible in verify/ci membership, dylint registration,
//! projection wiring, and governed closeout docs.
//! INVARIANT: TENANCY-SERVICE-IDENTITY-SCOPE-01 { level = "Medium", exec = "verify", source = "code" } -- service-token
//! MAC-bound canonical tenant headers and mTLS/SPIFFE tenantless service identity must remain locked by reverse
//! closeout anchors.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Result, bail};
use toml::Value;

use crate::contract;
use crate::contract::manifest::HttpProjectionFieldName;
use crate::diagnostic::{self, GovernanceCheck, finding};

pub(crate) type Finding = diagnostic::Finding<Rule>;

const VERIFY_CI_REQUIRED_GATES: &[&str] = &[
    "contract-validate",
    "codegen-check",
    "schema-rls",
    "setlocal-funnel",
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

const REGISTRY_FILES: &[&str] = &[
    "Cargo.toml",
    "lints/Cargo.toml",
    "docs/rules/architecture.md",
    "lints/README.md",
];

const AUTHZ_PARITY_ADR_PATH: &str =
    "docs/architecture/202607021958-014-authz-open-source-parity-boundary.md";

const AUTHZ_PARITY_DOCS: &[&str] = &[
    AUTHZ_PARITY_ADR_PATH,
    "docs/rules/tenancy.md",
    "docs/architecture/202606232318-006-pdp-internal-authplan-vs-external-opa.md",
    TENANCY_CONSUMER_GUIDE_PATH,
    "docs/spec/005-tenancy-abac-dataperm-closeout/research.md",
    "docs/spec/005-tenancy-abac-dataperm-closeout/tasks.md",
    "docs/spec/005-tenancy-abac-dataperm-closeout/quickstart.md",
];

const AUTHZ_PARITY_FRAMEWORKS: &[&str] = &[
    "OPA",
    "Cedar",
    "SpiceDB",
    "OpenFGA",
    "Casbin",
    "PostgreSQL RLS",
    "RSS",
];

const AUTHZ_PARITY_DIMENSIONS: &[&str] = &[
    "policy model",
    "decision evaluation",
    "relationship/attribute source",
    "tenant isolation",
    "row/field obligation",
    "auditability",
    "governance gate",
    "operational tradeoff",
    "rss position",
];

const AUTHZ_PARITY_REQUIRED_CLAIMS: &[&str] = &[
    "same security objective carried by RSS typed/in-process mechanisms",
    "no external PDP process",
    "no Rego runtime",
    "no Cedar/Casbin DSL runtime",
    "no SpiceDB/OpenFGA tuple graph service",
    "RLS does not replace RouteAuthorizer",
    "ABAC is not the tenant boundary",
];

const AUTHZ_PARITY_RSS_ROW_REQUIRED_ANCHORS: &[&str] = &[
    "credential verification",
    "RouteAuthorizer",
    "service-token tenant binding",
    "SET LOCAL rss.tenant_id",
    "FORCE RLS",
    "non-bypass serving role",
    "RowVisibility",
    "ResourceProjection",
];

const AUTHZ_PARITY_FORBIDDEN_CLAIMS: &[&str] = &[
    "full parity",
    "drop-in replacement",
    "OPA/Rego compatible",
    "tenant isolation is ABAC policy",
    "RLS alone solves tenancy",
    "FieldMask equals encryption",
];

const TENANCY_CONSUMER_GUIDE_PATH: &str =
    "docs/guides/202607090202-1596-tenancy-consumer-migration.md";
const TENANCY_CONSUMER_EXAMPLE_PATH: &str = "examples/tenancy-consumer/src/main.rs";
const TENANCY_CONSUMER_GENERATED_SPEC_TEST_PATH: &str =
    "xtask/tests/tenancy_closeout_generated_specs.rs";
const AUTH_E2E_TEST_PATH: &str = "assemblies/runtime/tests/auth_e2e.rs";
const SERVICE_IDENTITY_SCOPE_INVARIANT: &str = "TENANCY-SERVICE-IDENTITY-SCOPE-01";
const MTLS_NOT_TENANT_SOURCE_ANCHOR: &str = "mTLS/SPIFFE service identity is not a tenant source";
const SERVICE_TOKEN_MAC_SCOPE_ANCHOR: &str =
    "service-token MAC-bound tenant scope is the only service identity tenant assertion";

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
    RequiredAnchor {
        rule: Rule::DocAnchor,
        path: "docs/rules/tenancy.md",
        needle: SERVICE_IDENTITY_SCOPE_INVARIANT,
        detail: "tenancy rule doc must lock the service identity tenant-scope invariant",
    },
    RequiredAnchor {
        rule: Rule::DocAnchor,
        path: "docs/rules/tenancy.md",
        needle: SERVICE_TOKEN_MAC_SCOPE_ANCHOR,
        detail: "tenancy rule doc must state the service-token MAC-bound tenant assertion",
    },
    RequiredAnchor {
        rule: Rule::DocAnchor,
        path: "docs/rules/tenancy.md",
        needle: MTLS_NOT_TENANT_SOURCE_ANCHOR,
        detail: "tenancy rule doc must state mTLS/SPIFFE does not mint tenant scope",
    },
    RequiredAnchor {
        rule: Rule::DocAnchor,
        path: "Cargo.toml",
        needle: "\"examples/tenancy-consumer\"",
        detail: "tenancy consumer example must be a workspace member",
    },
    RequiredAnchor {
        rule: Rule::DocAnchor,
        path: "docs/rules/tenancy.md",
        needle: TENANCY_CONSUMER_GUIDE_PATH,
        detail: "tenancy rule doc must link the consumer migration guide",
    },
    RequiredAnchor {
        rule: Rule::DocAnchor,
        path: AUTHZ_PARITY_ADR_PATH,
        needle: TENANCY_CONSUMER_GUIDE_PATH,
        detail: "authz parity ADR must link the consumer migration guide",
    },
    RequiredAnchor {
        rule: Rule::DocAnchor,
        path: "docs/spec/005-tenancy-abac-dataperm-closeout/tasks.md",
        needle: "#1596",
        detail: "tenancy closeout tasks must track the consumer migration guide",
    },
    RequiredAnchor {
        rule: Rule::DocAnchor,
        path: "docs/spec/005-tenancy-abac-dataperm-closeout/tasks.md",
        needle: "#1597",
        detail: "tenancy closeout tasks must track service identity integration closeout",
    },
    RequiredAnchor {
        rule: Rule::DocAnchor,
        path: "docs/spec/005-tenancy-abac-dataperm-closeout/quickstart.md",
        needle: "cargo check -p tenancyconsumer",
        detail: "tenancy closeout quickstart must include the compilable consumer example check",
    },
    RequiredAnchor {
        rule: Rule::DocAnchor,
        path: "docs/spec/005-tenancy-abac-dataperm-closeout/quickstart.md",
        needle: "cargo test -p xtask tenancy_closeout",
        detail: "tenancy closeout quickstart must include the generated-spec smoke test lane",
    },
    RequiredAnchor {
        rule: Rule::DocAnchor,
        path: TENANCY_CONSUMER_GUIDE_PATH,
        needle: "service-token-tenant-bound",
        detail: "consumer guide must document service-token tenant binding",
    },
    RequiredAnchor {
        rule: Rule::DocAnchor,
        path: TENANCY_CONSUMER_GUIDE_PATH,
        needle: SERVICE_TOKEN_MAC_SCOPE_ANCHOR,
        detail: "consumer guide must document service-token MAC-bound tenant scope",
    },
    RequiredAnchor {
        rule: Rule::DocAnchor,
        path: TENANCY_CONSUMER_GUIDE_PATH,
        needle: MTLS_NOT_TENANT_SOURCE_ANCHOR,
        detail: "consumer guide must document mTLS/SPIFFE as tenantless service identity",
    },
    RequiredAnchor {
        rule: Rule::DocAnchor,
        path: AUTH_E2E_TEST_PATH,
        needle: "internal_mtls_verified_peer_remains_tenantless_scope",
        detail: "runtime auth e2e must lock mTLS service principal as tenantless",
    },
    RequiredAnchor {
        rule: Rule::DocAnchor,
        path: AUTH_E2E_TEST_PATH,
        needle: "VerifiedMtlsPeer",
        detail: "runtime auth e2e must inject verified mTLS evidence",
    },
    RequiredAnchor {
        rule: Rule::DocAnchor,
        path: AUTH_E2E_TEST_PATH,
        needle: "body, SCOPE_MISSING",
        detail: "runtime auth e2e must assert mTLS does not establish ambient tenant scope",
    },
    RequiredAnchor {
        rule: Rule::DocAnchor,
        path: TENANCY_CONSUMER_GUIDE_PATH,
        needle: "populate-only",
        detail: "consumer guide must document populate-only tenant header mode",
    },
    RequiredAnchor {
        rule: Rule::DocAnchor,
        path: TENANCY_CONSUMER_GUIDE_PATH,
        needle: "RouteAuthorizer",
        detail: "consumer guide must document route authorization entrypoint",
    },
    RequiredAnchor {
        rule: Rule::DocAnchor,
        path: TENANCY_CONSUMER_GUIDE_PATH,
        needle: "AuthorizedSubject",
        detail: "consumer guide must document handler authorization evidence",
    },
    RequiredAnchor {
        rule: Rule::DocAnchor,
        path: TENANCY_CONSUMER_GUIDE_PATH,
        needle: "RowVisibility",
        detail: "consumer guide must document row visibility consumption",
    },
    RequiredAnchor {
        rule: Rule::DocAnchor,
        path: TENANCY_CONSUMER_GUIDE_PATH,
        needle: "ResourceProjection",
        detail: "consumer guide must document field projection consumption",
    },
    RequiredAnchor {
        rule: Rule::DocAnchor,
        path: TENANCY_CONSUMER_GUIDE_PATH,
        needle: "audit.list-entries",
        detail: "consumer guide must document audit admin read semantics",
    },
    RequiredAnchor {
        rule: Rule::DocAnchor,
        path: TENANCY_CONSUMER_GUIDE_PATH,
        needle: "request body `tenantId`",
        detail: "consumer guide must reject request-body tenant source",
    },
    RequiredAnchor {
        rule: Rule::DocAnchor,
        path: TENANCY_CONSUMER_GENERATED_SPEC_TEST_PATH,
        needle: "generated::http::identity_v1::login::SPEC",
        detail: "tenancy closeout generated-spec smoke test must compile against generated login spec",
    },
    RequiredAnchor {
        rule: Rule::DocAnchor,
        path: TENANCY_CONSUMER_EXAMPLE_PATH,
        needle: "PrimaryRoute::permission",
        detail: "consumer example must compile against PrimaryRoute permission wiring",
    },
    RequiredAnchor {
        rule: Rule::DocAnchor,
        path: TENANCY_CONSUMER_EXAMPLE_PATH,
        needle: "RouteResourceScope::SelfSubject",
        detail: "consumer example must compile against self-scoped route declaration",
    },
    RequiredAnchor {
        rule: Rule::DocAnchor,
        path: TENANCY_CONSUMER_EXAMPLE_PATH,
        needle: "ProjectionField::AuditActor",
        detail: "consumer example must compile against projection field vocabulary",
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
            "`AuthScheme::Mtls` 仅作类型层接缝预留",
            "无 verifier 实现",
        ],
        closeout_needles: &[
            "Closeout addendum（#1500 / #1577 / #1586 / #1597）",
            "ServiceTokenTenantBinding",
            "service_token_mac_input",
            "service_token_tenant_binding",
            "VerifiedMtlsPeer",
            "MtlsRouteAuthorizer",
            SERVICE_IDENTITY_SCOPE_INVARIANT,
        ],
        detail: "ADR 007 historical service-token/MAC future wording must be covered by final closeout addendum",
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
        chain_name: "audit",
        contract_path: "contracts/http/audit/v1/contract.toml",
        generated_path: "generated/src/http/audit_v1.rs",
        generated_start: "",
        generated_end: "",
        rendering_path: "crates/audit/src/application.rs",
        rendering_start: "fn to_view(",
        rendering_end: "fn to_response",
        render_callee: "projection",
        fields: AUDIT_PROJECTION_FIELDS,
    },
    ProjectionEndpoint {
        chain_name: "identity profile",
        contract_path: "contracts/http/identity/v1/profile/contract.toml",
        generated_path: "generated/src/http/identity_v1.rs",
        generated_start: "pub mod profile {",
        generated_end: "pub mod password_change {",
        rendering_path: "crates/identity/src/application/mod.rs",
        rendering_start: "async fn profile_handler",
        rendering_end: "async fn password_change_handler",
        render_callee: "auth.projection",
        fields: IDENTITY_PROFILE_PROJECTION_FIELDS,
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
    ForbiddenPattern {
        path: "docs/architecture/202606232319-007-service-identity-service-token-vs-spiffe-mtls.md",
        needle: "内部 svc-to-svc 现阶段用 service-token",
        detail: "ADR 007 is superseded: Internal svc-to-svc production default is mTLS/SPIFFE",
    },
    ForbiddenPattern {
        path: "docs/architecture/202606232319-007-service-identity-service-token-vs-spiffe-mtls.md",
        needle: "`AuthScheme::Mtls` 仅作类型层接缝预留",
        detail: "ADR 007 must not describe mTLS as only a reserved seam after #1500/#1597",
    },
    ForbiddenPattern {
        path: "docs/architecture/202606232319-007-service-identity-service-token-vs-spiffe-mtls.md",
        needle: "无 verifier 实现",
        detail: "ADR 007 must not describe mTLS verifier implementation as absent after #1500/#1597",
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Rule {
    VerifyGate,
    DylintRegistry,
    ProjectionAnchor,
    DocAnchor,
    AuthzParityBoundary,
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
        findings.extend(check_required_anchors(&root)?);
        findings.extend(check_authz_parity_boundary(&root)?);
        findings.extend(check_stale_closeout_wording(&root)?);

        Ok((
            format!(
                "{} verify/ci gates, {} dylints, {} doc anchors, {} authz parity frameworks, {} projection fields checked",
                VERIFY_CI_REQUIRED_GATES.len(),
                TENANCY_DYLINTS.len(),
                REQUIRED_ANCHORS.len(),
                AUTHZ_PARITY_FRAMEWORKS.len(),
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
    let contracts_root = root.join("contracts");
    let projection_contracts = contract::discover(&contracts_root)?
        .into_iter()
        .filter(|contract| {
            contract
                .manifest
                .endpoints
                .as_ref()
                .and_then(|endpoints| endpoints.http.as_ref())
                .and_then(|http| http.projection.as_ref())
                .is_some_and(|projection| !projection.fields.is_empty())
        })
        .map(|contract| relative_contract_path(root, &contract.dir))
        .collect::<Vec<_>>();
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

fn check_required_anchors(root: &Path) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    for anchor in REQUIRED_ANCHORS {
        let content = read_required(root, anchor.path)?;
        findings.extend(scan_required_anchor(anchor, &content));
    }
    Ok(findings)
}

fn scan_required_anchor(anchor: &RequiredAnchor, content: &str) -> Vec<Finding> {
    let stripped;
    let searchable = if anchor.path.ends_with(".rs") {
        stripped = strip_rust_line_comments(content);
        stripped.as_str()
    } else {
        content
    };
    if searchable.contains(anchor.needle) {
        Vec::new()
    } else {
        vec![finding(
            anchor.rule,
            format!("{}:{}", anchor.path, anchor.needle),
            anchor.detail,
        )]
    }
}

fn check_authz_parity_boundary(root: &Path) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let adr = read_required(root, AUTHZ_PARITY_ADR_PATH)?;
    findings.extend(scan_authz_parity_adr(&adr));

    for path in AUTHZ_PARITY_DOCS {
        let content = read_required(root, path)?;
        findings.extend(scan_authz_forbidden_claims(path, &content));
    }

    findings.extend(scan_authz_required_reference(
        "docs/rules/tenancy.md",
        &read_required(root, "docs/rules/tenancy.md")?,
    ));
    findings.extend(scan_authz_required_reference(
        "docs/architecture/202606232318-006-pdp-internal-authplan-vs-external-opa.md",
        &read_required(
            root,
            "docs/architecture/202606232318-006-pdp-internal-authplan-vs-external-opa.md",
        )?,
    ));

    Ok(findings)
}

fn scan_authz_parity_adr(content: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let matrix = find_authz_parity_matrix(content);

    findings.extend(scan_authz_parity_matrix_rows(matrix.as_ref()));
    findings.extend(scan_authz_parity_matrix_headers(matrix.as_ref()));
    findings.extend(scan_authz_parity_rss_row(matrix.as_ref()));

    for claim in AUTHZ_PARITY_REQUIRED_CLAIMS {
        if !content.contains(claim) {
            findings.push(finding(
                Rule::AuthzParityBoundary,
                format!("{AUTHZ_PARITY_ADR_PATH}:claim:{claim}"),
                "authz parity ADR must state the in-scope boundary and explicit deviations",
            ));
        }
    }

    findings
}

#[derive(Debug, Clone)]
struct MarkdownTable {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
}

fn find_authz_parity_matrix(content: &str) -> Option<MarkdownTable> {
    parse_markdown_tables(content).into_iter().find(|table| {
        table
            .headers
            .first()
            .is_some_and(|header| same_cell(header, "framework"))
    })
}

fn scan_authz_parity_matrix_rows(matrix: Option<&MarkdownTable>) -> Vec<Finding> {
    AUTHZ_PARITY_FRAMEWORKS
        .iter()
        .filter(|framework| {
            !matrix.is_some_and(|table| {
                table
                    .rows
                    .iter()
                    .any(|row| row.first().is_some_and(|cell| same_cell(cell, framework)))
            })
        })
        .map(|framework| {
            finding(
                Rule::AuthzParityBoundary,
                format!("{AUTHZ_PARITY_ADR_PATH}:matrix-row:{framework}"),
                "authz parity matrix must keep a structured row for each comparison target",
            )
        })
        .collect()
}

fn scan_authz_parity_matrix_headers(matrix: Option<&MarkdownTable>) -> Vec<Finding> {
    AUTHZ_PARITY_DIMENSIONS
        .iter()
        .filter(|dimension| {
            !matrix.is_some_and(|table| {
                table
                    .headers
                    .iter()
                    .any(|header| same_cell(header, dimension))
            })
        })
        .map(|dimension| {
            finding(
                Rule::AuthzParityBoundary,
                format!("{AUTHZ_PARITY_ADR_PATH}:matrix-header:{dimension}"),
                "authz parity matrix header must keep every required comparison dimension",
            )
        })
        .collect()
}

fn scan_authz_parity_rss_row(matrix: Option<&MarkdownTable>) -> Vec<Finding> {
    let Some(rss_row) = matrix.and_then(|table| {
        table
            .rows
            .iter()
            .find(|row| row.first().is_some_and(|cell| same_cell(cell, "RSS")))
    }) else {
        return Vec::new();
    };
    let row_text = rss_row.join(" ");
    AUTHZ_PARITY_RSS_ROW_REQUIRED_ANCHORS
        .iter()
        .filter(|anchor| !row_text.contains(**anchor))
        .map(|anchor| {
            finding(
                Rule::AuthzParityBoundary,
                format!("{AUTHZ_PARITY_ADR_PATH}:rss-boundary:{anchor}"),
                "authz parity RSS matrix row must keep the concrete RSS tenant/AuthZ safety boundary",
            )
        })
        .collect()
}

fn parse_markdown_tables(content: &str) -> Vec<MarkdownTable> {
    let lines = content.lines().collect::<Vec<_>>();
    let mut tables = Vec::new();
    let mut idx = 0;
    while idx + 1 < lines.len() {
        if !is_markdown_table_row(lines[idx]) || !is_markdown_separator_row(lines[idx + 1]) {
            idx += 1;
            continue;
        }

        let headers = split_markdown_table_row(lines[idx]);
        let mut rows = Vec::new();
        idx += 2;
        while idx < lines.len() && is_markdown_table_row(lines[idx]) {
            rows.push(split_markdown_table_row(lines[idx]));
            idx += 1;
        }
        tables.push(MarkdownTable { headers, rows });
    }
    tables
}

fn is_markdown_table_row(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.starts_with('|') && trimmed.ends_with('|')
}

fn is_markdown_separator_row(line: &str) -> bool {
    is_markdown_table_row(line)
        && split_markdown_table_row(line).iter().all(|cell| {
            let trimmed = cell.trim();
            trimmed.contains('-') && trimmed.chars().all(|ch| matches!(ch, '-' | ':' | ' '))
        })
}

fn split_markdown_table_row(line: &str) -> Vec<String> {
    line.trim()
        .trim_matches('|')
        .split('|')
        .map(|cell| compact_ws(cell.trim()))
        .collect()
}

fn same_cell(actual: &str, expected: &str) -> bool {
    compact_ws(&actual.to_ascii_lowercase()) == compact_ws(&expected.to_ascii_lowercase())
}

fn scan_authz_required_reference(path: &str, content: &str) -> Vec<Finding> {
    if content.contains(AUTHZ_PARITY_ADR_PATH) {
        Vec::new()
    } else {
        vec![finding(
            Rule::AuthzParityBoundary,
            format!("{path}:{AUTHZ_PARITY_ADR_PATH}"),
            "tenancy and PDP ADR docs must link to the authz parity boundary ADR",
        )]
    }
}

fn scan_authz_forbidden_claims(path: &str, content: &str) -> Vec<Finding> {
    AUTHZ_PARITY_FORBIDDEN_CLAIMS
        .iter()
        .map(|claim| (*claim, normalize_claim_text(claim)))
        .flat_map(|claim| {
            content
                .lines()
                .enumerate()
                .filter(move |(_, line)| normalize_claim_text(line).contains(&claim.1))
                .map(move |(idx, _)| {
                    finding(
                        Rule::StaleCloseoutWording,
                        format!("{path}:{}", idx + 1),
                        format!(
                            "authz parity docs must avoid misleading product/API compatibility claim: {}",
                            claim.0
                        ),
                    )
                })
        })
        .collect()
}

fn normalize_claim_text(content: &str) -> String {
    let mut normalized = String::new();
    let mut previous_space = true;
    for ch in content.chars() {
        if ch.is_alphanumeric() {
            for lower in ch.to_lowercase() {
                normalized.push(lower);
            }
            previous_space = false;
        } else if !previous_space {
            normalized.push(' ');
            previous_space = true;
        }
    }
    normalized.trim().to_string()
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
    fn missing_service_identity_scope_anchor_is_reported() {
        let anchor = RequiredAnchor {
            rule: Rule::DocAnchor,
            path: "docs/rules/tenancy.md",
            needle: SERVICE_IDENTITY_SCOPE_INVARIANT,
            detail: "must exist",
        };
        let findings = scan_required_anchor(&anchor, "service-token tenant binding");
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].rule, Rule::DocAnchor);
        assert!(
            findings[0]
                .subject
                .contains(SERVICE_IDENTITY_SCOPE_INVARIANT),
            "{findings:?}"
        );
    }

    #[test]
    fn missing_mtls_tenantless_e2e_anchor_is_reported() {
        let anchor = RequiredAnchor {
            rule: Rule::DocAnchor,
            path: AUTH_E2E_TEST_PATH,
            needle: "internal_mtls_verified_peer_remains_tenantless_scope",
            detail: "must exist",
        };
        let findings = scan_required_anchor(
            &anchor,
            "// internal_mtls_verified_peer_remains_tenantless_scope documented only\n\
             async fn service_token_establishes_scope_from_mac_bound_tenant() {}",
        );
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].rule, Rule::DocAnchor);
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
    fn rust_source_required_anchor_ignores_line_comment_only() {
        let anchor = RequiredAnchor {
            rule: Rule::DocAnchor,
            path: TENANCY_CONSUMER_EXAMPLE_PATH,
            needle: "PrimaryRoute::permission",
            detail: "must exist",
        };
        let findings = scan_required_anchor(
            &anchor,
            r#"
fn main() {
    // PrimaryRoute::permission
}
"#,
        );
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(
            findings[0].subject.contains("PrimaryRoute::permission"),
            "{findings:?}"
        );
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
        let findings = scan_rendering_projection(&PROJECTION_ENDPOINTS[1], content);
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
            "contracts/http/audit/v1/contract.toml".to_string(),
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
    fn stale_service_identity_mtls_reserved_wording_is_reported() {
        let pattern = ForbiddenPattern {
            path: "docs/architecture/202606232319-007-service-identity-service-token-vs-spiffe-mtls.md",
            needle: "`AuthScheme::Mtls` 仅作类型层接缝预留",
            detail: "stale service identity wording",
        };
        let findings =
            scan_forbidden_pattern(&pattern, "当前 `AuthScheme::Mtls` 仅作类型层接缝预留");
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].rule, Rule::StaleCloseoutWording);
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
    fn authz_parity_adr_requires_matrix_dimensions_and_claims() {
        let findings = scan_authz_parity_adr("OPA\nCedar\nSpiceDB\nOpenFGA\nCasbin\nRSS\n");
        assert!(
            findings.iter().any(|finding| {
                finding.rule == Rule::AuthzParityBoundary
                    && finding.subject.contains("PostgreSQL RLS")
            }),
            "{findings:?}"
        );
        assert!(
            findings.iter().any(|finding| {
                finding.rule == Rule::AuthzParityBoundary
                    && finding.subject.contains("policy model")
            }),
            "{findings:?}"
        );
        assert!(
            findings.iter().any(|finding| {
                finding.rule == Rule::AuthzParityBoundary
                    && finding.subject.contains(
                        "same security objective carried by RSS typed/in-process mechanisms",
                    )
            }),
            "{findings:?}"
        );
    }

    #[test]
    fn authz_parity_adr_requires_structured_matrix_rows() {
        let content = format!(
            "{}\n{}\n{}\n",
            AUTHZ_PARITY_FRAMEWORKS.join("\n"),
            AUTHZ_PARITY_DIMENSIONS.join("\n"),
            AUTHZ_PARITY_REQUIRED_CLAIMS.join("\n"),
        );
        let findings = scan_authz_parity_adr(&content);
        assert!(
            findings
                .iter()
                .any(|finding| finding.subject.contains("matrix-row:OPA")),
            "{findings:?}"
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.subject.contains("matrix-header:policy model")),
            "{findings:?}"
        );
    }

    #[test]
    fn authz_parity_adr_requires_rss_row_security_boundaries() {
        let matrix_without_service_token_binding = r#"
same security objective carried by RSS typed/in-process mechanisms
no external PDP process
no Rego runtime
no Cedar/Casbin DSL runtime
no SpiceDB/OpenFGA tuple graph service
RLS does not replace RouteAuthorizer
ABAC is not the tenant boundary

| framework | policy model | decision evaluation | relationship/attribute source | tenant isolation | row/field obligation | auditability | governance gate | operational tradeoff | rss position |
|-----------|--------------|---------------------|-------------------------------|------------------|----------------------|--------------|-----------------|----------------------|--------------|
| OPA | Rego | sidecar | data | context | structured data | decision log | tests | infra | ref |
| Cedar | PARC | embedded | entities | context | diagnostics | response | schema | DSL | ref |
| SpiceDB | graph | check | tuples | namespace | caveats | tokens | schema | service | ref |
| OpenFGA | model | check | tuples | store | conditions | history | validation | service | ref |
| Casbin | PERM | enforcer | adapter | domain | boolean | logs | syntax | matcher | ref |
| PostgreSQL RLS | SQL policy | database | rows | FORCE RLS | rows only | database audit | schema-rls | data only | ref |
| RSS | typed permission | RouteAuthorizer and diport::Pdp | verified principal | typed TenantId, SET LOCAL rss.tenant_id, FORCE RLS, non-bypass serving role | RowVisibility and ResourceProjection | durable audit | codegen and xtask | typed local boundary | reference implementation |
"#;
        let findings = scan_authz_parity_adr(matrix_without_service_token_binding);
        assert!(
            findings.iter().any(|finding| {
                finding
                    .subject
                    .contains("rss-boundary:service-token tenant binding")
            }),
            "{findings:?}"
        );
    }

    #[test]
    fn authz_parity_docs_must_link_boundary_adr() {
        let findings = scan_authz_required_reference("docs/rules/tenancy.md", "RouteAuthorizer");
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].rule, Rule::AuthzParityBoundary);
    }

    #[test]
    fn authz_parity_forbidden_claims_are_reported() {
        let findings = scan_authz_forbidden_claims(
            "docs/architecture/adr.md",
            "This is an OPA/Rego compatible drop-in replacement.",
        );
        assert_eq!(findings.len(), 2, "{findings:?}");
        assert!(
            findings
                .iter()
                .all(|finding| finding.rule == Rule::StaleCloseoutWording),
            "{findings:?}"
        );
    }

    #[test]
    fn authz_parity_forbidden_claim_variants_are_reported() {
        let findings = scan_authz_forbidden_claims(
            "docs/architecture/adr.md",
            "Full parity. OPA Rego compatible. RLS-alone solves Tenancy.",
        );
        assert_eq!(findings.len(), 3, "{findings:?}");
        assert!(
            findings
                .iter()
                .all(|finding| finding.rule == Rule::StaleCloseoutWording),
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

        let authz_adr_fixture = format!(
            r#"{}

| framework | policy model | decision evaluation | relationship/attribute source | tenant isolation | row/field obligation | auditability | governance gate | operational tradeoff | rss position |
|-----------|--------------|---------------------|-------------------------------|------------------|----------------------|--------------|-----------------|----------------------|--------------|
| OPA | Rego | sidecar/server | input/data | context convention | structured result | decision log | policy tests | extra infra | reference |
| Cedar | PARC | embedded authorizer | entities | context convention | diagnostics | response | schema | policy runtime | reference |
| SpiceDB | relationship graph | graph check | tuples | namespace convention | caveats | tracing | schema | graph service | reference |
| OpenFGA | authorization model | API check | tuples | store convention | conditions | history | model validation | service dependency | reference |
| Casbin | PERM | enforcer | adapter | domain convention | boolean | logs | model syntax | matcher DSL | reference |
| PostgreSQL RLS | SQL policy | database | rows | FORCE RLS and SET LOCAL rss.tenant_id | row filtering | database audit | schema-rls | data boundary only | reference |
| RSS | typed permission | RouteAuthorizer and credential verification via diport::Pdp | verified principal and route metadata | typed TenantId, service-token tenant binding, SET LOCAL rss.tenant_id, FORCE RLS, non-bypass serving role | RowVisibility and ResourceProjection | durable audit | codegen and xtask | typed local boundary | reference implementation |
"#,
            AUTHZ_PARITY_REQUIRED_CLAIMS.join("\n"),
        );
        assert!(scan_authz_parity_adr(&authz_adr_fixture).is_empty());
        assert!(
            scan_authz_required_reference("docs/rules/tenancy.md", AUTHZ_PARITY_ADR_PATH)
                .is_empty()
        );
        assert!(
            scan_authz_forbidden_claims("docs/architecture/adr.md", "explicit deviation")
                .is_empty()
        );
    }
}
