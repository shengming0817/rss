//! ArchRules 派生索引：从真实 carrier 的 `INVARIANT:` 锚点反推出 rule → carrier → evidence → gate。
//!
//! INVARIANT: ARCHRULES-DERIVED-INDEX-01 { level = "Medium", exec = "check", source = "code" } —— 本模块只扫描真实 carrier（代码 / 配置 / UI golden /
//! baseline），不引入手写规则目录；文档仅作为 `doc_ref`。
//! INVARIANT: ARCHRULES-VERIFY-GATE-01 { level = "Medium", exec = "check", source = "code" } —— [`ArchRules`] 作为 no-compile governance gate 接入 verify/ci，
//! 缺 carrier / fixture / gate 证据时 fail-closed。
//! INVARIANT: APPLICATION-DELIVERY-BOUNDARY-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "archrules::tests::application_delivery_boundary_rejects_synthetic_red", anti_vacuity = "archrules::tests::application_delivery_boundary_accepts_real_workspace" } —— application production/default-CI carriers reject repository-owned deployment protocols and Kubernetes delivery projections.
//! INVARIANT: PERSISTENCE-FUNNEL-MATRIX-01 { level = "Medium", exec = "check", source = "code", facet = "derived-matrix" } —— 持久化 funnel 固定集合仅引用真实 rule key，强度和证明从 carrier 反向派生。

use crate::diagnostic::{Finding, GovernanceCheck, finding};
use crate::workspace_root;
use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use syn::parse::Parser;
use syn::visit::Visit;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    EmptyIndex,
    InvalidInvariantId,
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
    MissingCodegenHardProof,
    ConflictingInvariantFacet,
    MatrixCoverage,
    MatrixMissingBoundary,
    MatrixMissingInvariant,
    MatrixEvidence,
    MatrixResidual,
    MatrixDocDrift,
    ApplicationDeliveryResidual,
}

pub(crate) struct ArchRules;

impl GovernanceCheck for ArchRules {
    type Rule = Rule;

    fn name(&self) -> &'static str {
        "archrules"
    }

    fn check(&self) -> Result<(String, Vec<Finding<Rule>>)> {
        let root = workspace_root()?;
        let index = build_index(&root)?;
        let mut findings = index.findings;
        findings.extend(validate_matrix(
            &root,
            &index.records,
            &index.test_evidence,
            true,
        )?);
        findings.extend(application_delivery_boundary_findings(&root)?);
        Ok((
            format!(
                "{} 条规则索引 + {} 行持久化 funnel",
                index.records.len(),
                FUNNELS.len()
            ),
            findings,
        ))
    }
}

const DELIVERY_GUARD_CARRIER: &str = "xtask/src/archrules.rs";

fn application_delivery_boundary_findings(root: &Path) -> Result<Vec<Finding<Rule>>> {
    let output = Command::new("/usr/bin/git")
        .args(["-C", root.to_string_lossy().as_ref(), "ls-files", "-z"])
        .output()
        .context("list tracked files for application delivery boundary")?;
    if !output.status.success() {
        bail!(
            "git ls-files failed for application delivery boundary: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let mut records = Vec::new();
    for raw in output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|raw| !raw.is_empty())
    {
        let path = std::str::from_utf8(raw)
            .context("tracked application delivery path is not UTF-8")?
            .to_owned();
        let absolute = root.join(&path);
        if !absolute.is_file() {
            continue;
        }
        let source = if scans_application_delivery_content(&path) {
            Some(
                String::from_utf8_lossy(
                    &fs::read(&absolute)
                        .with_context(|| format!("read application delivery carrier {path}"))?,
                )
                .into_owned(),
            )
        } else {
            None
        };
        records.push((path, source));
    }
    Ok(application_delivery_records_findings(&records))
}

fn application_delivery_records_findings(
    records: &[(String, Option<String>)],
) -> Vec<Finding<Rule>> {
    const FORBIDDEN_PREFIXES: &[&str] = &[
        "deploy/helm/",
        "deploy/generated/",
        "deploy/rendered/",
        "deploy/schemas/",
        "docs/spec/007-runtime-deployment-executable-plan/",
    ];
    const FORBIDDEN_FILES: &[&str] = &[
        "crates/assembly-schema/src/deployment.rs",
        "xtask/src/deployment_plan.rs",
        "xtask/src/deployment_policy.rs",
        "xtask/src/runtime_deployment_spec.rs",
        ".specify/feature.json",
    ];
    const FORBIDDEN_TOKENS: &[&str] = &[
        "DeploymentPlan",
        "ParsedDeploymentPlan",
        "BUNDLED_DEPLOYMENT_PLAN",
        "deployment_facts",
        "deploymentFingerprint",
        "deployment_fingerprint",
        "SecretProviderClass",
        "deployment-plan",
        "deployment-policy",
        "runtime-deployment-spec",
        "install-download",
        "--backend download",
        ".download/bin",
        "Helm",
        "helm",
        "kubeconform",
        "kubeform",
    ];

    let mut findings = Vec::new();
    for (path, source) in records {
        let forbidden_path = FORBIDDEN_PREFIXES
            .iter()
            .any(|prefix| path.starts_with(prefix))
            || FORBIDDEN_FILES.contains(&path.as_str())
            || path.ends_with(".deployment-plan.json");
        if forbidden_path {
            findings.push(finding(
                Rule::ApplicationDeliveryResidual,
                path,
                "repository-owned delivery projection path is forbidden",
            ));
        }
        if path == DELIVERY_GUARD_CARRIER {
            continue;
        }
        if let Some(source) = source {
            for token in application_delivery_content_tokens(path, source, FORBIDDEN_TOKENS) {
                findings.push(finding(
                    Rule::ApplicationDeliveryResidual,
                    path,
                    format!("application/default-CI carrier contains removed token `{token}`"),
                ));
            }
        }
    }
    findings
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApplicationDeliveryCarrier {
    RustSource,
    ExecutableText,
    TestEvidence,
    HumanProse,
    Other,
}

fn application_delivery_carrier(path: &str) -> ApplicationDeliveryCarrier {
    let path = Path::new(path);
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    let extension = path.extension().and_then(|extension| extension.to_str());
    let is_test_evidence = path.components().any(|component| {
        matches!(
            component.as_os_str().to_str(),
            Some("tests" | "fixtures" | "golden" | "testdata")
        )
    }) || file_name.ends_with("_test.rs")
        || file_name.ends_with("_tests.rs");

    if is_test_evidence {
        ApplicationDeliveryCarrier::TestEvidence
    } else if extension == Some("md") {
        ApplicationDeliveryCarrier::HumanProse
    } else if path.to_string_lossy() == DELIVERY_GUARD_CARRIER {
        ApplicationDeliveryCarrier::Other
    } else if extension == Some("rs") {
        ApplicationDeliveryCarrier::RustSource
    } else if matches!(
        extension,
        Some("toml" | "json" | "yaml" | "yml" | "sh" | "bash" | "zsh" | "env")
    ) || matches!(file_name, "Cargo.lock" | "Dockerfile" | "Makefile")
        || file_name.starts_with("Dockerfile.")
        || file_name.ends_with(".env.example")
        || path.to_string_lossy() == ".github/scripts/ci-tool-catalog.txt"
    {
        ApplicationDeliveryCarrier::ExecutableText
    } else {
        ApplicationDeliveryCarrier::Other
    }
}

fn scans_application_delivery_content(path: &str) -> bool {
    matches!(
        application_delivery_carrier(path),
        ApplicationDeliveryCarrier::RustSource | ApplicationDeliveryCarrier::ExecutableText
    )
}

fn application_delivery_content_tokens<'a>(
    path: &str,
    source: &str,
    tokens: &'a [&'a str],
) -> Vec<&'a str> {
    match application_delivery_carrier(path) {
        ApplicationDeliveryCarrier::RustSource => rust_source_delivery_tokens(source, tokens),
        ApplicationDeliveryCarrier::ExecutableText => tokens
            .iter()
            .copied()
            .filter(|token| source.contains(token))
            .collect(),
        ApplicationDeliveryCarrier::TestEvidence
        | ApplicationDeliveryCarrier::HumanProse
        | ApplicationDeliveryCarrier::Other => Vec::new(),
    }
}

fn rust_source_delivery_tokens<'a>(source: &str, tokens: &'a [&'a str]) -> Vec<&'a str> {
    let Ok(file) = syn::parse_file(source) else {
        return tokens
            .iter()
            .copied()
            .filter(|token| source.contains(token))
            .collect();
    };
    let mut visitor = ApplicationDeliveryTokenVisitor {
        tokens,
        found: vec![false; tokens.len()],
    };
    visitor.visit_file(&file);
    tokens
        .iter()
        .copied()
        .zip(visitor.found)
        .filter_map(|(token, found)| found.then_some(token))
        .collect()
}

struct ApplicationDeliveryTokenVisitor<'a> {
    tokens: &'a [&'a str],
    found: Vec<bool>,
}

impl ApplicationDeliveryTokenVisitor<'_> {
    fn observe(&mut self, value: &str) {
        for (index, token) in self.tokens.iter().enumerate() {
            self.found[index] |= value.contains(token);
        }
    }
}

impl<'ast> Visit<'ast> for ApplicationDeliveryTokenVisitor<'_> {
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if item.attrs.iter().any(attribute_is_test_only) {
            return;
        }
        syn::visit::visit_item_mod(self, item);
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if item.attrs.iter().any(attribute_is_test_only) {
            return;
        }
        syn::visit::visit_item_fn(self, item);
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if item.attrs.iter().any(attribute_is_test_only) {
            return;
        }
        syn::visit::visit_impl_item_fn(self, item);
    }

    fn visit_attribute(&mut self, attribute: &'ast syn::Attribute) {
        if attribute.path().is_ident("doc") || attribute.path().is_ident("cfg") {
            return;
        }
        syn::visit::visit_attribute(self, attribute);
    }

    fn visit_ident(&mut self, ident: &'ast proc_macro2::Ident) {
        self.observe(&ident.to_string());
    }

    fn visit_lit_str(&mut self, literal: &'ast syn::LitStr) {
        self.observe(&literal.value());
    }
}

fn attribute_is_test_only(attribute: &syn::Attribute) -> bool {
    attribute.path().is_ident("test")
        || (attribute.path().is_ident("cfg")
            && attribute
                .meta
                .require_list()
                .is_ok_and(|list| list.tokens.to_string().replace(' ', "") == "test"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MatrixAction {
    Print,
    Write,
    Check,
}

const MATRIX_DOC: &str =
    "docs/architecture/202607091830-015-persistence-funnel-ai-robust-matrix.md";
const FUNNEL_ISSUE_RANGE_START: u32 = 1422;
const FUNNEL_ISSUE_RANGE_END: u32 = 1442;
const ISSUE_PG_RUNTIME_CUTOVER: u32 = 1677;
const ISSUE_EVENT_TRANSPORT_OUTPUT: u32 = 1678;
const ISSUE_OUTBOX_CLAIM_CAPABILITY: u32 = 1741;
const ISSUE_SAME_ID_DELIVERY: u32 = 1742;
const ISSUE_OUTBOX_CLAIM_RELAY_CUTOVER: u32 = 1743;
const ISSUE_PROVIDER_PLAN_OUTPUT_BIJECTION: u32 = 1792;
const ISSUE_SAGA_RECEIPT_STORE: u32 = 1924;
const EXTRA_FUNNEL_ISSUES: &[u32] = &[
    ISSUE_PG_RUNTIME_CUTOVER,
    ISSUE_EVENT_TRANSPORT_OUTPUT,
    ISSUE_OUTBOX_CLAIM_CAPABILITY,
    ISSUE_SAME_ID_DELIVERY,
    ISSUE_OUTBOX_CLAIM_RELAY_CUTOVER,
    ISSUE_PROVIDER_PLAN_OUTPUT_BIJECTION,
    ISSUE_SAGA_RECEIPT_STORE,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct InvariantKey {
    id: &'static str,
    facet: Option<&'static str>,
}

const fn invariant(id: &'static str) -> InvariantKey {
    InvariantKey { id, facet: None }
}

const fn invariant_facet(id: &'static str, facet: &'static str) -> InvariantKey {
    InvariantKey {
        id,
        facet: Some(facet),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResidualDisposition {
    None,
    AcceptedMedium {
        risk: &'static str,
        why_no_low_cost_hardening: &'static str,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FunnelSpec {
    key: &'static str,
    source_issues: &'static [u32],
    upstream: &'static [InvariantKey],
    downstream: &'static [InvariantKey],
    residual: ResidualDisposition,
}

const FUNNELS: &[FunnelSpec] = &[
    FunnelSpec {
        key: "runtime-wiring",
        source_issues: &[1422, 1425, 1430, 1431, 1432],
        upstream: &[invariant("WIRING-DEPS-INFRA-ONLY-01")],
        downstream: &[invariant("RUNTIME-BASELINE-DRIFT-01")],
        residual: ResidualDisposition::AcceptedMedium {
            risk: "跨文件 runtime 装配集合仍可能出现未识别的新语法形态",
            why_no_low_cost_hardening: "Rust 类型系统无法表达 workspace 级依赖集合；AST 守卫与 baseline 已覆盖已知入口",
        },
    },
    FunnelSpec {
        key: "pg-runtime-lifecycle",
        source_issues: &[
            ISSUE_PG_RUNTIME_CUTOVER,
            ISSUE_PROVIDER_PLAN_OUTPUT_BIJECTION,
        ],
        upstream: &[
            invariant("PG-RUNTIME-OWNER-01"),
            invariant("PG-RUNTIME-HANDLE-02"),
        ],
        downstream: &[
            invariant("PG-RUNTIME-OUTPUT-03"),
            invariant("RUNTIME-PROVIDER-BIJECTION-LIVE-01"),
        ],
        residual: ResidualDisposition::AcceptedMedium {
            risk: "跨文件 plan/catalog/output exact set 与 Launch 注册顺序仍可能出现 AST visitor 未识别的新语法形态",
            why_no_low_cost_hardening: "Rust 类型系统锁定 permit/owner 单次消费，Medium 门以真实 workspace green 和 catalog/permit/finish/rollback synthetic red 补齐跨文件集合事实",
        },
    },
    FunnelSpec {
        key: "event-transport-output",
        source_issues: &[ISSUE_EVENT_TRANSPORT_OUTPUT],
        upstream: &[invariant("EVENT-TRANSPORT-OUTPUT-TYPE-01")],
        downstream: &[invariant("EVENT-TRANSPORT-OUTPUT-FUNNEL-01")],
        residual: ResidualDisposition::AcceptedMedium {
            risk: "跨文件 event output 唯一 merge 与 launch 相对顺序仍可能出现 AST visitor 未识别的新语法形态",
            why_no_low_cost_hardening: "Rust 类型系统已锁定 owned DomainModuleResult 返回形状，但无法表达跨文件唯一调用与 LIFO 相对顺序；synthetic-red/green AST 门覆盖已知旁路",
        },
    },
    FunnelSpec {
        key: "pg-capability",
        source_issues: &[1423, 1436],
        upstream: &[invariant("PG-TX-CAPABILITY-SEAL-01")],
        downstream: &[invariant("PG-BUNDLE-DOMAIN-02")],
        residual: ResidualDisposition::None,
    },
    FunnelSpec {
        key: "adapter-bundle",
        source_issues: &[1424],
        upstream: &[invariant("PG-BUNDLE-FUNNEL-01")],
        downstream: &[invariant("PG-BUNDLE-POOL-03")],
        residual: ResidualDisposition::None,
    },
    FunnelSpec {
        key: "rls",
        source_issues: &[1437],
        upstream: &[invariant("TENANCY-RLS-FORCE-01")],
        downstream: &[invariant("TENANCY-PG-TX-FUNNEL-01")],
        residual: ResidualDisposition::AcceptedMedium {
            risk: "SQL policy 与运行时 catalog 属于跨文件、跨后端集合事实",
            why_no_low_cost_hardening: "schema AST 守卫与运行时 catalog 验证已覆盖 canonical tenant predicate",
        },
    },
    FunnelSpec {
        key: "repo-uow",
        source_issues: &[1426, 1427, 1428],
        upstream: &[invariant("TENANCY-REPO-SCOPE-SIGNATURE-01")],
        downstream: &[invariant("OUTBOX-COTX-BINDING-API-01")],
        residual: ResidualDisposition::AcceptedMedium {
            risk: "仓库 trait 集合与调用面需要 workspace AST 枚举",
            why_no_low_cost_hardening: "单个事务绑定由类型 Hard，集合完整性由 synthetic-red AST 守卫补足",
        },
    },
    FunnelSpec {
        key: "event-topology",
        source_issues: &[1438],
        upstream: &[invariant("EVENT-ACTIVE-SUB-01")],
        downstream: &[invariant_facet(
            "EVENT-TOPOLOGY-GENERATED-01",
            "single-registry",
        )],
        residual: ResidualDisposition::AcceptedMedium {
            risk: "active contract 集合完整性需要跨 manifest 校验",
            why_no_low_cost_hardening: "单注册表由 codegen Hard；manifest 集合事实只能由 verify AST/TOML 守卫表达",
        },
    },
    FunnelSpec {
        key: "consumer-bundle",
        source_issues: &[1429, 1433, 1434, 1435],
        upstream: &[invariant("EVENT-TRANSPORT-PG-INBOX-01")],
        downstream: &[invariant("INBOX-RECEIPTS-CUTOVER-01")],
        residual: ResidualDisposition::AcceptedMedium {
            risk: "consumer provider 与历史 token 禁用是跨 crate 集合事实",
            why_no_low_cost_hardening: "AST 守卫拒绝 bypass、alias 与字符串注释伪证据，并保留真实绿路径",
        },
    },
    FunnelSpec {
        key: "generated-runtime-bridge",
        source_issues: &[1442],
        upstream: &[invariant_facet(
            "EVENT-TOPOLOGY-GENERATED-01",
            "single-registry",
        )],
        downstream: &[invariant("EVENT-TRANSPORT-PG-INBOX-01")],
        residual: ResidualDisposition::AcceptedMedium {
            risk: "真实 producer 调用点集合无法由单 crate 类型系统证明完整",
            why_no_low_cost_hardening: "生成注册表由 Hard codegen 固定，调用集合由 event transport AST red/green 守卫验证",
        },
    },
    FunnelSpec {
        key: "retry",
        source_issues: &[1439],
        upstream: &[invariant("TENANCY-PG-TX-FUNNEL-01")],
        downstream: &[invariant("OUTBOX-COTX-BINDING-API-01")],
        residual: ResidualDisposition::AcceptedMedium {
            risk: "任意手写 retry loop 无法静态完备识别",
            why_no_low_cost_hardening: "retry primitive 与 sanctioned callsite 已由 AST 守卫收口；事务 API 由类型 Hard",
        },
    },
    FunnelSpec {
        key: "saga-receipt-completion",
        source_issues: &[ISSUE_SAGA_RECEIPT_STORE],
        upstream: &[invariant("SAGA-RECEIPT-COMPLETION-TYPE-01")],
        downstream: &[invariant("SAGA-RECEIPT-CATALOG-GATE-01")],
        residual: ResidualDisposition::AcceptedMedium {
            risk: "数据库 catalog 与 Rust receipt capability 是跨编译单元、跨后端的集合事实",
            why_no_low_cost_hardening: "Completed 构造面由 trybuild Hard 封闭；真实 PostgreSQL catalog 的 trigger、RLS、ACL 与函数体只能由启动期 exact fingerprint 和正反集成测试验证",
        },
    },
    FunnelSpec {
        key: "redrive",
        source_issues: &[1440],
        upstream: &[invariant("INBOX-RECEIPTS-CUTOVER-01")],
        downstream: &[invariant("EVENT-TRANSPORT-PG-INBOX-01")],
        residual: ResidualDisposition::AcceptedMedium {
            risk: "redrive worker 与 durable inbox 连接属于运行时集合事实",
            why_no_low_cost_hardening: "现有 transport/cutover AST 守卫同时覆盖拒绝路径与真实装配路径",
        },
    },
    FunnelSpec {
        key: "outbox-relay-claim",
        source_issues: &[
            ISSUE_OUTBOX_CLAIM_CAPABILITY,
            ISSUE_OUTBOX_CLAIM_RELAY_CUTOVER,
        ],
        upstream: &[invariant("OUTBOX-CLAIM-RELAY-CAPABILITY-01")],
        downstream: &[invariant("OUTBOX-RELAY-CLAIM-CUTOVER-01")],
        residual: ResidualDisposition::AcceptedMedium {
            risk: "跨 crate provider 集合、eventexec/runtime 调用图与 migration 退役序列仍可能出现 AST/SQL 扫描未识别的新语法形态",
            why_no_low_cost_hardening: "类型系统已 Hard 锁定关联 Claim 与按值消费，但无法表达 workspace exact provider、跨文件调用图和 SQL 历史序列；synthetic-red/anti-vacuity 守卫覆盖 canonical seam",
        },
    },
    FunnelSpec {
        key: "same-id-delivery",
        source_issues: &[ISSUE_SAME_ID_DELIVERY],
        upstream: &[invariant("OUTBOX-SAME-ID-WINDOW-01")],
        downstream: &[invariant("INBOX-RECEIPTS-CUTOVER-01")],
        residual: ResidualDisposition::AcceptedMedium {
            risk: "automatic retry、operator redrive 与 receipt retention 跨 SQL/Rust/ops 的载体集合属于运行时事实",
            why_no_low_cost_hardening: "DB CHECK/ACL 与 Rust 闭枚举各自为 Hard；跨语言闭包由 same-ID synthetic-red/anti-vacuity 守卫表达",
        },
    },
    FunnelSpec {
        key: "command-journal",
        source_issues: &[1441],
        upstream: &[invariant_facet(
            "COMMAND-JOURNAL-GENERATED-01",
            "manifest-policy",
        )],
        downstream: &[invariant_facet("COMMAND-IMPL-ALLOWLIST-01", "provider-set")],
        residual: ResidualDisposition::AcceptedMedium {
            risk: "生产 provider impl 与 callsite 集合无法完全由可见性表达",
            why_no_low_cost_hardening: "authoring seam 由私有字段/构造器 Hard 封闭，仅剩集合事实由 AST red/green 守卫承担",
        },
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuleRecord {
    id: String,
    facet: Option<String>,
    level: RuleLevel,
    exec: ExecutionLevel,
    source_kind: SourceKind,
    carrier: String,
    source: String,
    evidence: String,
    gate: String,
    status: String,
    native: Option<String>,
    golden: Option<String>,
    synthetic_red: Option<String>,
    anti_vacuity: Option<String>,
}

#[derive(Debug, Default)]
struct Index {
    records: Vec<RuleRecord>,
    findings: Vec<Finding<Rule>>,
    test_evidence: TestEvidenceIndex,
}

type FacetKey = (String, String, Option<String>);
type RuleBinding = (RuleLevel, ExecutionLevel, SourceKind);

pub(crate) fn list() -> Result<()> {
    let root = workspace_root()?;
    let index = build_index(&root)?;
    println!(
        "id | facet | level | exec | source_kind | carrier | source | evidence | gate | status"
    );
    for record in &index.records {
        println!(
            "{} | {} | {} | {} | {} | {} | {} | {} | {} | {}",
            record.id,
            record.facet.as_deref().unwrap_or("-"),
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

pub(crate) fn matrix(action: MatrixAction) -> Result<()> {
    let root = workspace_root()?;
    let index = build_index(&root)?;
    let mut findings = index.findings;
    findings.extend(validate_matrix(
        &root,
        &index.records,
        &index.test_evidence,
        action == MatrixAction::Check,
    )?);
    if !findings.is_empty() {
        crate::diagnostic::print_findings(&findings);
        bail!("archrules matrix: {} 项校验失败", findings.len());
    }
    let rendered = render_matrix(&index.records)?;
    match action {
        MatrixAction::Print => print!("{rendered}"),
        MatrixAction::Write => {
            let path = root.join(MATRIX_DOC);
            fs::write(&path, rendered)
                .with_context(|| format!("写入 matrix `{}`", path.display()))?;
            eprintln!("archrules matrix: 已写入 {MATRIX_DOC}");
        }
        MatrixAction::Check => {
            eprintln!(
                "archrules matrix: {} 行与 committed 文档一致",
                FUNNELS.len()
            )
        }
    }
    Ok(())
}

fn expected_issue_partition(range_separator: &str) -> String {
    let extras = EXTRA_FUNNEL_ISSUES
        .iter()
        .map(|issue| format!("#{issue}"))
        .collect::<Vec<_>>()
        .join("/");
    format!("#{FUNNEL_ISSUE_RANGE_START}{range_separator}#{FUNNEL_ISSUE_RANGE_END} + {extras}")
}

fn expected_source_issues() -> BTreeSet<u32> {
    let mut issues = (FUNNEL_ISSUE_RANGE_START..=FUNNEL_ISSUE_RANGE_END).collect::<BTreeSet<_>>();
    issues.extend(EXTRA_FUNNEL_ISSUES);
    issues
}

fn validate_funnel_catalog(funnels: &[FunnelSpec]) -> Vec<Finding<Rule>> {
    let expected_issues = expected_source_issues();
    let mut actual_issues = BTreeSet::new();
    let mut seen_issues = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let mut findings = Vec::new();

    for funnel in funnels {
        if !keys.insert(funnel.key) {
            findings.push(finding(Rule::MatrixCoverage, funnel.key, "funnel key 重复"));
        }
        for issue in funnel.source_issues {
            actual_issues.insert(*issue);
            if !seen_issues.insert(*issue) {
                findings.push(finding(
                    Rule::MatrixCoverage,
                    funnel.key,
                    format!("来源 issue #{issue} 重复归属"),
                ));
            }
        }
    }

    if actual_issues != expected_issues {
        findings.push(finding(
            Rule::MatrixCoverage,
            "source issues",
            format!(
                "来源 issue 并集必须恰为 {}；missing={:?}, extra={:?}",
                expected_issue_partition(".."),
                expected_issues
                    .difference(&actual_issues)
                    .collect::<Vec<_>>(),
                actual_issues
                    .difference(&expected_issues)
                    .collect::<Vec<_>>()
            ),
        ));
    }

    findings
}

fn validate_matrix(
    root: &Path,
    records: &[RuleRecord],
    test_evidence: &TestEvidenceIndex,
    check_doc_drift: bool,
) -> Result<Vec<Finding<Rule>>> {
    let mut findings = validate_funnel_catalog(FUNNELS);
    for funnel in FUNNELS {
        if funnel.upstream.is_empty() || funnel.downstream.is_empty() {
            findings.push(finding(
                Rule::MatrixMissingBoundary,
                funnel.key,
                "upstream/downstream 必须均非空",
            ));
        }
        let mut has_medium = false;
        for key in funnel.upstream.iter().chain(funnel.downstream) {
            let Some(record) = select_record(records, *key) else {
                findings.push(finding(
                    Rule::MatrixMissingInvariant,
                    funnel.key,
                    format!(
                        "真实索引缺 invariant `{}` facet `{}`",
                        key.id,
                        key.facet.unwrap_or("-")
                    ),
                ));
                continue;
            };
            match record.level {
                RuleLevel::Hard => {
                    validate_hard_evidence(root, test_evidence, funnel.key, record, &mut findings)?
                }
                RuleLevel::Medium => {
                    has_medium = true;
                    validate_medium_evidence(
                        root,
                        test_evidence,
                        funnel.key,
                        record,
                        &mut findings,
                    )?;
                }
            }
        }
        match (has_medium, funnel.residual) {
            (true, ResidualDisposition::None) => findings.push(finding(
                Rule::MatrixResidual,
                funnel.key,
                "含 Medium 边界却未声明 AcceptedMedium residual",
            )),
            (
                _,
                ResidualDisposition::AcceptedMedium {
                    risk,
                    why_no_low_cost_hardening,
                },
            ) if risk.trim().is_empty() || why_no_low_cost_hardening.trim().is_empty() => {
                findings.push(finding(
                    Rule::MatrixResidual,
                    funnel.key,
                    "AcceptedMedium 必须说明 risk 与无低成本 Hard 化原因",
                ));
            }
            _ => {}
        }
    }
    if check_doc_drift && findings.is_empty() {
        let path = root.join(MATRIX_DOC);
        let expected = render_matrix(records)?;
        let actual = fs::read_to_string(&path).unwrap_or_default();
        if actual != expected {
            findings.push(finding(
                Rule::MatrixDocDrift,
                MATRIX_DOC,
                "generated matrix 漂移；运行 `cargo xtask archrules matrix --write`",
            ));
        }
    }
    Ok(findings)
}

fn select_record(records: &[RuleRecord], key: InvariantKey) -> Option<&RuleRecord> {
    records
        .iter()
        .filter(|record| record.id == key.id && record.facet.as_deref() == key.facet)
        .max_by_key(|record| {
            (
                usize::from(record.level == RuleLevel::Hard),
                usize::from(
                    record.exec
                        == ExecutionLevel::Profile(
                            crate::execution_profiles::ExecutionProfile::Check,
                        ),
                ),
                usize::from(record.carrier == "xtask"),
            )
        })
}

fn validate_hard_evidence(
    root: &Path,
    test_evidence: &TestEvidenceIndex,
    funnel: &str,
    record: &RuleRecord,
    findings: &mut Vec<Finding<Rule>>,
) -> Result<()> {
    let valid = match record.source_kind {
        SourceKind::Codegen => {
            let Some(golden) = record.golden.as_deref() else {
                return push_matrix_evidence(findings, funnel, record, "codegen Hard 缺 golden");
            };
            let red = record.synthetic_red.as_deref();
            let green = record.anti_vacuity.as_deref();
            root.join(golden).is_file()
                && red.is_some_and(|symbol| test_evidence.contains(root, record, symbol))
                && green.is_some_and(|symbol| test_evidence.contains(root, record, symbol))
        }
        SourceKind::Code | SourceKind::Rustdoc | SourceKind::Trybuild => {
            record
                .native
                .as_deref()
                .is_some_and(|native| !native.trim().is_empty())
                || record.source_kind == SourceKind::Trybuild
        }
        _ => false,
    };
    if !valid {
        push_matrix_evidence(
            findings,
            funnel,
            record,
            "Hard carrier 缺真实 native/golden/synthetic-red/anti-vacuity 证明",
        )?;
    }
    Ok(())
}

fn push_matrix_evidence(
    findings: &mut Vec<Finding<Rule>>,
    funnel: &str,
    record: &RuleRecord,
    detail: &str,
) -> Result<()> {
    findings.push(finding(
        Rule::MatrixEvidence,
        funnel,
        format!("{}: {detail}", record.id),
    ));
    Ok(())
}

fn validate_medium_evidence(
    root: &Path,
    test_evidence: &TestEvidenceIndex,
    funnel: &str,
    record: &RuleRecord,
    findings: &mut Vec<Finding<Rule>>,
) -> Result<()> {
    let red = record.synthetic_red.as_deref();
    let green = record.anti_vacuity.as_deref();
    let explicitly_bound = red.zip(green).is_some_and(|(red, green)| {
        red != green
            && test_evidence.contains(root, record, red)
            && test_evidence.contains(root, record, green)
    });
    if !explicitly_bound {
        push_matrix_evidence(
            findings,
            funnel,
            record,
            &format!(
                "Medium invariant 必须用 metadata 显式绑定同载体真实 AST test；synthetic_red={red:?}, anti_vacuity={green:?}"
            ),
        )?;
    }
    Ok(())
}

fn collect_test_names(path: &Path) -> Result<Vec<String>> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("读取 evidence source `{}`", path.display()))?;
    let file = syn::parse_file(&text)
        .with_context(|| format!("解析 evidence source `{}`", path.display()))?;
    let context = TestCfgContext::for_source(path)?;
    Ok(collect_test_names_from_file(&file, &context))
}

#[derive(Debug, Default)]
struct TestCfgContext {
    features: BTreeSet<String>,
}

impl TestCfgContext {
    fn for_source(path: &Path) -> Result<Self> {
        Self::for_source_execution(
            path,
            ExecutionLevel::Profile(crate::execution_profiles::ExecutionProfile::Test),
        )
    }

    fn for_source_execution(path: &Path, execution: ExecutionLevel) -> Result<Self> {
        let Some(manifest) = path
            .ancestors()
            .skip(1)
            .map(|directory| directory.join("Cargo.toml"))
            .find(|manifest| manifest.is_file())
        else {
            return Ok(Self::default());
        };
        let value = parse_toml(&manifest)?;
        let Some(features) = value.get("features").and_then(toml::Value::as_table) else {
            return Ok(Self::default());
        };
        let mut enabled = BTreeSet::new();
        let mut pending = features
            .contains_key("default")
            .then(|| "default".to_string())
            .into_iter()
            .collect::<Vec<_>>();
        if execution
            == ExecutionLevel::Profile(
                crate::execution_profiles::ExecutionProfile::IntegrationCritical,
            )
            && features.contains_key("integration")
        {
            pending.push("integration".to_string());
        }
        while let Some(raw) = pending.pop() {
            if raw.starts_with("dep:") || raw.contains("?/") {
                continue;
            }
            let feature = raw.split('/').next().unwrap_or(&raw).to_string();
            if !enabled.insert(feature.clone()) {
                continue;
            }
            if let Some(children) = features.get(&feature).and_then(toml::Value::as_array) {
                pending.extend(
                    children
                        .iter()
                        .filter_map(toml::Value::as_str)
                        .map(str::to_string),
                );
            }
        }
        Ok(Self { features: enabled })
    }
}

fn collect_test_names_from_file(file: &syn::File, context: &TestCfgContext) -> Vec<String> {
    struct Collector<'a> {
        module: Vec<String>,
        names: Vec<String>,
        disabled: usize,
        context: &'a TestCfgContext,
    }
    impl<'ast> Visit<'ast> for Collector<'_> {
        fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
            let disabled = !attrs_prove_test_execution(&node.attrs, self.context);
            self.disabled += usize::from(disabled);
            self.module.push(node.ident.to_string());
            if node.content.is_some() {
                syn::visit::visit_item_mod(self, node);
            }
            self.module.pop();
            self.disabled -= usize::from(disabled);
        }

        fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
            let is_test = node.attrs.iter().any(|attr| {
                attr.path().segments.last().is_some_and(|segment| {
                    matches!(segment.ident.to_string().as_str(), "test" | "rstest")
                })
            });
            if self.disabled == 0
                && is_test
                && attrs_prove_test_execution(&node.attrs, self.context)
                && !node.block.stmts.is_empty()
            {
                let mut name = self.module.join("::");
                if !name.is_empty() {
                    name.push_str("::");
                }
                name.push_str(&node.sig.ident.to_string());
                self.names.push(name);
            }
        }
    }
    if !attrs_prove_test_execution(&file.attrs, context) {
        return Vec::new();
    }
    let mut collector = Collector {
        module: Vec::new(),
        names: Vec::new(),
        disabled: 0,
        context,
    };
    collector.visit_file(file);
    collector.names.sort();
    collector.names.dedup();
    collector.names
}

/// Cached runnable-test inventory used by every matrix evidence query in one
/// ArchRules build. Cargo module graphs and source ASTs are parsed once, then
/// red/green lookups are exact set membership checks.
#[derive(Debug, Default)]
struct TestEvidenceIndex {
    symbols_by_source: BTreeMap<(PathBuf, ExecutionLevel), BTreeSet<String>>,
    parse_counts: BTreeMap<PathBuf, usize>,
}

impl TestEvidenceIndex {
    fn build(root: &Path, records: &[RuleRecord]) -> Result<Self> {
        let mut manifests = BTreeMap::<PathBuf, BTreeSet<ExecutionLevel>>::new();
        for record in records {
            if record.synthetic_red.is_none() && record.anti_vacuity.is_none() {
                continue;
            }
            let relative = record.source.split(':').next().unwrap_or(&record.source);
            if let Some(manifest) = nearest_package_manifest(root, &root.join(relative)) {
                manifests.entry(manifest).or_default().insert(record.exec);
            }
        }

        let mut asts = SourceAstCache::default();
        let mut symbols_by_source = BTreeMap::<(PathBuf, ExecutionLevel), BTreeSet<String>>::new();
        for (manifest, executions) in manifests {
            let crate_root = manifest.parent().unwrap_or(root);
            for execution in executions {
                let context = TestCfgContext::for_source_execution(&manifest, execution)?;
                let mut visited = BTreeSet::new();
                for target in cargo_target_roots(crate_root, &manifest)? {
                    collect_target_test_symbols(
                        &target,
                        Vec::new(),
                        &mut visited,
                        &mut asts,
                        &mut symbols_by_source,
                        execution,
                        &context,
                    )?;
                }
            }
        }
        Ok(Self {
            symbols_by_source,
            parse_counts: asts.parse_counts,
        })
    }

    fn contains(&self, root: &Path, record: &RuleRecord, symbol: &str) -> bool {
        debug_assert!(self.parse_counts.values().all(|count| *count == 1));
        let relative = record.source.split(':').next().unwrap_or(&record.source);
        self.symbols_by_source
            .get(&(root.join(relative), record.exec))
            .is_some_and(|symbols| symbols.contains(symbol))
    }

    #[cfg(test)]
    fn parse_count(&self, path: &Path) -> usize {
        self.parse_counts.get(path).copied().unwrap_or(0)
    }
}

#[cfg(test)]
fn record_source_has_test_symbol(root: &Path, record: &RuleRecord, symbol: &str) -> Result<bool> {
    let mut query = record.clone();
    query.synthetic_red = Some(symbol.to_string());
    Ok(
        TestEvidenceIndex::build(root, std::slice::from_ref(&query))?
            .contains(root, record, symbol),
    )
}

fn cargo_source_has_test_symbols(
    root: &Path,
    path: &Path,
    execution: ExecutionLevel,
) -> Result<bool> {
    let Some(manifest) = nearest_package_manifest(root, path) else {
        return Ok(false);
    };
    let crate_root = manifest.parent().unwrap_or(root);
    let context = TestCfgContext::for_source_execution(&manifest, execution)?;
    let mut visited = BTreeSet::new();
    let mut asts = SourceAstCache::default();
    let mut symbols = BTreeMap::new();
    for target in cargo_target_roots(crate_root, &manifest)? {
        collect_target_test_symbols(
            &target,
            Vec::new(),
            &mut visited,
            &mut asts,
            &mut symbols,
            execution,
            &context,
        )?;
    }
    Ok(symbols
        .get(&(path.to_path_buf(), execution))
        .is_some_and(|names| !names.is_empty()))
}

#[derive(Default)]
struct SourceAstCache {
    files: BTreeMap<PathBuf, std::rc::Rc<syn::File>>,
    parse_counts: BTreeMap<PathBuf, usize>,
}

impl SourceAstCache {
    fn parse(&mut self, path: &Path) -> Result<std::rc::Rc<syn::File>> {
        if let Some(file) = self.files.get(path) {
            return Ok(std::rc::Rc::clone(file));
        }
        let text = fs::read_to_string(path)
            .with_context(|| format!("读取 Cargo test module `{}`", path.display()))?;
        let file = std::rc::Rc::new(
            syn::parse_file(&text)
                .with_context(|| format!("解析 Cargo test module `{}`", path.display()))?,
        );
        self.files
            .insert(path.to_path_buf(), std::rc::Rc::clone(&file));
        *self.parse_counts.entry(path.to_path_buf()).or_default() += 1;
        Ok(file)
    }
}

fn collect_target_test_symbols(
    module_file: &Path,
    identity: Vec<String>,
    visited: &mut BTreeSet<(PathBuf, Vec<String>)>,
    asts: &mut SourceAstCache,
    symbols_by_source: &mut BTreeMap<(PathBuf, ExecutionLevel), BTreeSet<String>>,
    execution: ExecutionLevel,
    context: &TestCfgContext,
) -> Result<()> {
    if !visited.insert((module_file.to_path_buf(), identity.clone())) {
        return Ok(());
    }
    let file = asts.parse(module_file)?;
    if !attrs_prove_test_execution(&file.attrs, context) {
        return Ok(());
    }
    let symbols = symbols_by_source
        .entry((module_file.to_path_buf(), execution))
        .or_default();
    for local in collect_test_names_from_file(&file, context) {
        symbols.insert(local.clone());
        if !identity.is_empty() {
            symbols.insert(format!("{}::{local}", identity.join("::")));
        }
    }
    collect_target_test_symbol_items(
        &module_search_base(module_file),
        module_file.parent().unwrap_or(Path::new("")),
        &file.items,
        identity,
        visited,
        asts,
        symbols_by_source,
        execution,
        context,
    )
}

#[allow(clippy::too_many_arguments)]
fn collect_target_test_symbol_items(
    search_base: &Path,
    path_attr_base: &Path,
    items: &[syn::Item],
    identity: Vec<String>,
    visited: &mut BTreeSet<(PathBuf, Vec<String>)>,
    asts: &mut SourceAstCache,
    symbols_by_source: &mut BTreeMap<(PathBuf, ExecutionLevel), BTreeSet<String>>,
    execution: ExecutionLevel,
    context: &TestCfgContext,
) -> Result<()> {
    for item in items {
        let syn::Item::Mod(module) = item else {
            continue;
        };
        if !attrs_prove_test_execution(&module.attrs, context) {
            continue;
        }
        let mut child_identity = identity.clone();
        child_identity.push(module.ident.to_string());
        if let Some((_, child_items)) = &module.content {
            let inline_base = search_base.join(module.ident.to_string());
            collect_target_test_symbol_items(
                &inline_base,
                &inline_base,
                child_items,
                child_identity,
                visited,
                asts,
                symbols_by_source,
                execution,
                context,
            )?;
        } else {
            let external = external_module_path(search_base, path_attr_base, module);
            if external.is_file() {
                collect_target_test_symbols(
                    &external,
                    child_identity,
                    visited,
                    asts,
                    symbols_by_source,
                    execution,
                    context,
                )?;
            }
        }
    }
    Ok(())
}

pub(crate) fn attrs_statically_disabled(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("cfg")
            && attr
                .meta
                .require_list()
                .ok()
                .and_then(|list| syn::parse2::<syn::Meta>(list.tokens.clone()).ok())
                .is_some_and(|meta| cfg_truth(&meta) == CfgTruth::False)
    })
}

/// Test evidence is valid only when the canonical default test context can
/// prove that every execution-affecting attribute enables the item. Unknown
/// conditions and ignored tests fail closed.
fn attrs_prove_test_execution(attrs: &[syn::Attribute], context: &TestCfgContext) -> bool {
    attrs
        .iter()
        .all(|attribute| attribute_proves_test_execution(attribute, context))
}

fn attribute_proves_test_execution(attr: &syn::Attribute, context: &TestCfgContext) -> bool {
    if attr.path().is_ident("ignore") {
        return false;
    }
    if attr.path().is_ident("cfg") {
        return attr
            .meta
            .require_list()
            .ok()
            .and_then(|list| syn::parse2::<syn::Meta>(list.tokens.clone()).ok())
            .is_some_and(|meta| cfg_truth_for_test(&meta, context) == CfgTruth::True);
    }
    if !attr.path().is_ident("cfg_attr") {
        return true;
    }
    let Ok(list) = attr.meta.require_list() else {
        return false;
    };
    let Ok(items) = syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated
        .parse2(list.tokens.clone())
    else {
        return false;
    };
    let Some(condition) = items.first() else {
        return false;
    };
    match cfg_truth_for_test(condition, context) {
        CfgTruth::False => true,
        CfgTruth::Unknown => false,
        CfgTruth::True => items
            .iter()
            .skip(1)
            .all(|meta| meta_proves_test_execution(meta, context)),
    }
}

fn meta_proves_test_execution(meta: &syn::Meta, context: &TestCfgContext) -> bool {
    if meta.path().is_ident("ignore") {
        return false;
    }
    if meta.path().is_ident("cfg") {
        return meta
            .require_list()
            .ok()
            .and_then(|list| syn::parse2::<syn::Meta>(list.tokens.clone()).ok())
            .is_some_and(|condition| cfg_truth_for_test(&condition, context) == CfgTruth::True);
    }
    true
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CfgTruth {
    True,
    False,
    Unknown,
}

fn cfg_truth_for_test(meta: &syn::Meta, context: &TestCfgContext) -> CfgTruth {
    match meta {
        syn::Meta::Path(path) if path.is_ident("test") => CfgTruth::True,
        syn::Meta::Path(path) if path.is_ident("unix") => truth(cfg!(unix)),
        syn::Meta::Path(path) if path.is_ident("windows") => truth(cfg!(windows)),
        syn::Meta::Path(_) => CfgTruth::Unknown,
        syn::Meta::NameValue(name_value) => {
            let syn::Expr::Lit(value) = &name_value.value else {
                return CfgTruth::Unknown;
            };
            let syn::Lit::Str(value) = &value.lit else {
                return CfgTruth::Unknown;
            };
            if name_value.path.is_ident("feature") {
                truth(context.features.contains(&value.value()))
            } else if name_value.path.is_ident("target_os") {
                truth(value.value() == std::env::consts::OS)
            } else if name_value.path.is_ident("target_arch") {
                truth(value.value() == std::env::consts::ARCH)
            } else if name_value.path.is_ident("target_family") {
                truth(
                    (cfg!(unix) && value.value() == "unix")
                        || (cfg!(windows) && value.value() == "windows"),
                )
            } else {
                CfgTruth::Unknown
            }
        }
        syn::Meta::List(list) => cfg_list_truth_for_test(list, context),
    }
}

fn cfg_list_truth_for_test(list: &syn::MetaList, context: &TestCfgContext) -> CfgTruth {
    let Ok(items) = syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated
        .parse2(list.tokens.clone())
    else {
        return CfgTruth::Unknown;
    };
    let evaluate = |item: &syn::Meta| cfg_truth_for_test(item, context);
    if list.path.is_ident("all") {
        if items.iter().any(|item| evaluate(item) == CfgTruth::False) {
            CfgTruth::False
        } else if items.iter().all(|item| evaluate(item) == CfgTruth::True) {
            CfgTruth::True
        } else {
            CfgTruth::Unknown
        }
    } else if list.path.is_ident("any") {
        if items.iter().any(|item| evaluate(item) == CfgTruth::True) {
            CfgTruth::True
        } else if items.iter().all(|item| evaluate(item) == CfgTruth::False) {
            CfgTruth::False
        } else {
            CfgTruth::Unknown
        }
    } else if list.path.is_ident("not") && items.len() == 1 {
        match evaluate(&items[0]) {
            CfgTruth::True => CfgTruth::False,
            CfgTruth::False => CfgTruth::True,
            CfgTruth::Unknown => CfgTruth::Unknown,
        }
    } else {
        CfgTruth::Unknown
    }
}

const fn truth(value: bool) -> CfgTruth {
    if value {
        CfgTruth::True
    } else {
        CfgTruth::False
    }
}

fn cfg_truth(meta: &syn::Meta) -> CfgTruth {
    match meta {
        syn::Meta::Path(path) if path.is_ident("test") => CfgTruth::True,
        syn::Meta::Path(_) | syn::Meta::NameValue(_) => CfgTruth::Unknown,
        syn::Meta::List(list) => cfg_list_truth(list, cfg_truth),
    }
}

fn cfg_list_truth(list: &syn::MetaList, evaluate: fn(&syn::Meta) -> CfgTruth) -> CfgTruth {
    let Ok(items) = syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated
        .parse2(list.tokens.clone())
    else {
        return CfgTruth::Unknown;
    };
    if list.path.is_ident("all") {
        if items.iter().any(|item| evaluate(item) == CfgTruth::False) {
            CfgTruth::False
        } else if items.iter().all(|item| evaluate(item) == CfgTruth::True) {
            CfgTruth::True
        } else {
            CfgTruth::Unknown
        }
    } else if list.path.is_ident("any") {
        if items.iter().any(|item| evaluate(item) == CfgTruth::True) {
            CfgTruth::True
        } else if items.iter().all(|item| evaluate(item) == CfgTruth::False) {
            CfgTruth::False
        } else {
            CfgTruth::Unknown
        }
    } else if list.path.is_ident("not") && items.len() == 1 {
        match evaluate(&items[0]) {
            CfgTruth::True => CfgTruth::False,
            CfgTruth::False => CfgTruth::True,
            CfgTruth::Unknown => CfgTruth::Unknown,
        }
    } else {
        CfgTruth::Unknown
    }
}

#[cfg(test)]
fn cargo_target_reaches(root: &Path, path: &Path) -> Result<bool> {
    let Some(manifest) = nearest_package_manifest(root, path) else {
        return Ok(false);
    };
    let crate_root = manifest.parent().unwrap_or(root);
    for target in cargo_target_roots(crate_root, &manifest)? {
        let mut visited = BTreeSet::new();
        if rust_module_reaches(&target, path, &mut visited)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn cargo_reachable_files(manifest: &Path) -> Result<BTreeSet<PathBuf>> {
    let crate_root = manifest.parent().unwrap_or(Path::new(""));
    let mut reachable = BTreeSet::new();
    for target in cargo_target_roots(crate_root, manifest)? {
        collect_reachable_modules(&target, &mut reachable)?;
    }
    Ok(reachable)
}

/// Canonical Cargo target classification shared by source-governance checks.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum CargoTargetClass {
    Lib,
    Bin,
    Test,
    Example,
    Bench,
}

impl CargoTargetClass {
    pub(crate) const fn is_production_scan(self) -> bool {
        !matches!(self, Self::Test)
    }
}

/// One Cargo-declared or Cargo-auto-discovered target root.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct CargoTargetRoot {
    pub(crate) path: PathBuf,
    pub(crate) class: CargoTargetClass,
}

/// Returns the same closed target inventory used by archrules reachability, including custom and
/// automatic lib/bin/test/example/bench targets and their `auto*` switches.
pub(crate) fn cargo_target_inventory(
    crate_root: &Path,
    manifest: &Path,
) -> Result<BTreeSet<CargoTargetRoot>> {
    let value = parse_toml(manifest)?;
    let mut roots = BTreeSet::new();
    let explicit_path = |target: &toml::Value| {
        target
            .get("path")
            .and_then(toml::Value::as_str)
            .map(|path| crate_root.join(path))
    };

    if let Some(lib) = value.get("lib") {
        roots.insert(CargoTargetRoot {
            path: explicit_path(lib).unwrap_or_else(|| crate_root.join("src/lib.rs")),
            class: CargoTargetClass::Lib,
        });
    } else if crate_root.join("src/lib.rs").is_file() {
        roots.insert(CargoTargetRoot {
            path: crate_root.join("src/lib.rs"),
            class: CargoTargetClass::Lib,
        });
    }
    for (kind, default_dir, class) in [
        ("bin", "src/bin", CargoTargetClass::Bin),
        ("test", "tests", CargoTargetClass::Test),
        ("example", "examples", CargoTargetClass::Example),
        ("bench", "benches", CargoTargetClass::Bench),
    ] {
        if let Some(targets) = value.get(kind).and_then(toml::Value::as_array) {
            roots.extend(targets.iter().filter_map(|target| {
                explicit_target_path(crate_root, kind, target)
                    .map(|path| CargoTargetRoot { path, class })
            }));
        }
        let automatic = value
            .get("package")
            .and_then(|package| package.get(format!("auto{kind}s")))
            .and_then(toml::Value::as_bool)
            .unwrap_or(true);
        let dir = crate_root.join(default_dir);
        if automatic && dir.is_dir() {
            for entry in fs::read_dir(&dir)? {
                let path = entry?.path();
                if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
                    roots.insert(CargoTargetRoot { path, class });
                } else if path.is_dir() && path.join("main.rs").is_file() {
                    roots.insert(CargoTargetRoot {
                        path: path.join("main.rs"),
                        class,
                    });
                }
            }
        }
    }
    if value
        .get("package")
        .and_then(|package| package.get("autobins"))
        .and_then(toml::Value::as_bool)
        .unwrap_or(true)
        && crate_root.join("src/main.rs").is_file()
    {
        roots.insert(CargoTargetRoot {
            path: crate_root.join("src/main.rs"),
            class: CargoTargetClass::Bin,
        });
    }
    roots.retain(|target| target.path.is_file());
    Ok(roots)
}

/// Resolves the complete Rust module closure for one canonical Cargo target root.
pub(crate) fn cargo_target_reachable_files(target: &CargoTargetRoot) -> Result<BTreeSet<PathBuf>> {
    let mut reachable = BTreeSet::new();
    collect_reachable_modules(&target.path, &mut reachable)?;
    Ok(reachable)
}

fn collect_reachable_modules(module_file: &Path, reachable: &mut BTreeSet<PathBuf>) -> Result<()> {
    if !reachable.insert(module_file.to_path_buf()) {
        return Ok(());
    }
    let text = fs::read_to_string(module_file)
        .with_context(|| format!("读取 Cargo target module `{}`", module_file.display()))?;
    let file = syn::parse_file(&text)
        .with_context(|| format!("解析 Cargo target module `{}`", module_file.display()))?;
    collect_reachable_items(
        &module_search_base(module_file),
        module_file.parent().unwrap_or(Path::new("")),
        &file.items,
        reachable,
    )
}

fn collect_reachable_items(
    search_base: &Path,
    path_attr_base: &Path,
    items: &[syn::Item],
    reachable: &mut BTreeSet<PathBuf>,
) -> Result<()> {
    for item in items {
        let syn::Item::Mod(module) = item else {
            continue;
        };
        if attrs_statically_disabled(&module.attrs) {
            continue;
        }
        if let Some((_, items)) = &module.content {
            let inline_base = search_base.join(module.ident.to_string());
            collect_reachable_items(&inline_base, &inline_base, items, reachable)?;
        } else {
            let external = external_module_path(search_base, path_attr_base, module);
            if external.is_file() {
                collect_reachable_modules(&external, reachable)?;
            }
        }
    }
    Ok(())
}

fn nearest_package_manifest(root: &Path, path: &Path) -> Option<PathBuf> {
    let mut current = path.parent()?;
    loop {
        let manifest = current.join("Cargo.toml");
        if manifest.is_file()
            && parse_toml(&manifest)
                .ok()
                .is_some_and(|value| value.get("package").is_some())
        {
            return Some(manifest);
        }
        if current == root {
            return None;
        }
        current = current.parent()?;
        if !current.starts_with(root) {
            return None;
        }
    }
}

fn cargo_target_roots(crate_root: &Path, manifest: &Path) -> Result<BTreeSet<PathBuf>> {
    Ok(cargo_target_inventory(crate_root, manifest)?
        .into_iter()
        .map(|target| target.path)
        .collect())
}

fn explicit_target_path(crate_root: &Path, kind: &str, target: &toml::Value) -> Option<PathBuf> {
    if let Some(path) = target.get("path").and_then(toml::Value::as_str) {
        return Some(crate_root.join(path));
    }
    let name = target.get("name").and_then(toml::Value::as_str)?;
    let directory = match kind {
        "bin" => "src/bin",
        "test" => "tests",
        "example" => "examples",
        "bench" => "benches",
        _ => return None,
    };
    let direct = crate_root.join(directory).join(format!("{name}.rs"));
    if direct.is_file() {
        Some(direct)
    } else {
        Some(crate_root.join(directory).join(name).join("main.rs"))
    }
}

#[cfg(test)]
fn rust_module_reaches(
    module_file: &Path,
    wanted: &Path,
    visited: &mut BTreeSet<PathBuf>,
) -> Result<bool> {
    if module_file == wanted {
        return Ok(true);
    }
    if !visited.insert(module_file.to_path_buf()) {
        return Ok(false);
    }
    let text = fs::read_to_string(module_file)
        .with_context(|| format!("读取 Cargo target module `{}`", module_file.display()))?;
    let file = syn::parse_file(&text)
        .with_context(|| format!("解析 Cargo target module `{}`", module_file.display()))?;
    reachable_items(
        &module_search_base(module_file),
        module_file.parent().unwrap_or(Path::new("")),
        &file.items,
        wanted,
        visited,
    )
}

#[cfg(test)]
fn reachable_items(
    search_base: &Path,
    path_attr_base: &Path,
    items: &[syn::Item],
    wanted: &Path,
    visited: &mut BTreeSet<PathBuf>,
) -> Result<bool> {
    for item in items {
        let syn::Item::Mod(module) = item else {
            continue;
        };
        if attrs_statically_disabled(&module.attrs) {
            continue;
        }
        if let Some((_, items)) = &module.content {
            let inline_base = search_base.join(module.ident.to_string());
            if reachable_items(&inline_base, &inline_base, items, wanted, visited)? {
                return Ok(true);
            }
            continue;
        }
        let external = external_module_path(search_base, path_attr_base, module);
        if external.is_file() && rust_module_reaches(&external, wanted, visited)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn external_module_path(
    search_base: &Path,
    path_attr_base: &Path,
    module: &syn::ItemMod,
) -> PathBuf {
    if let Some(path) = module.attrs.iter().find_map(|attr| {
        if !attr.path().is_ident("path") {
            return None;
        }
        let syn::Meta::NameValue(value) = &attr.meta else {
            return None;
        };
        let syn::Expr::Lit(expr) = &value.value else {
            return None;
        };
        let syn::Lit::Str(path) = &expr.lit else {
            return None;
        };
        Some(path.value())
    }) {
        return lexical_normalize(&path_attr_base.join(path));
    }
    let direct = search_base.join(format!("{}.rs", module.ident));
    if direct.is_file() {
        direct
    } else {
        search_base.join(module.ident.to_string()).join("mod.rs")
    }
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            _ => normalized.push(component.as_os_str()),
        }
    }
    normalized
}

fn module_search_base(module_file: &Path) -> PathBuf {
    let parent = module_file.parent().unwrap_or(Path::new(""));
    match module_file.file_name().and_then(|name| name.to_str()) {
        Some("lib.rs" | "main.rs" | "mod.rs") => parent.to_path_buf(),
        _ => parent.join(module_file.file_stem().unwrap_or_default()),
    }
}

fn render_matrix(records: &[RuleRecord]) -> Result<String> {
    let mut out = String::from(
        "<!-- GENERATED by `cargo xtask archrules matrix --write`; DO NOT EDIT. -->\n\
# Persistence Funnel AI-Robust Matrix\n\n\
本矩阵只引用真实 `INVARIANT` carrier；level、carrier、gate、source 与 evidence 均由 ArchRules 索引派生。\n\n\
| Funnel | Issues | Upstream | Downstream | Residual |\n\
|---|---|---|---|---|\n",
    );
    for funnel in FUNNELS {
        let issues = funnel
            .source_issues
            .iter()
            .map(|issue| format!("#{issue}"))
            .collect::<Vec<_>>()
            .join(", ");
        let upstream = render_boundaries(records, funnel.upstream)?;
        let downstream = render_boundaries(records, funnel.downstream)?;
        let residual = match funnel.residual {
            ResidualDisposition::None => "None (Hard)".to_string(),
            ResidualDisposition::AcceptedMedium {
                risk,
                why_no_low_cost_hardening,
            } => format!("AcceptedMedium: {risk}；{why_no_low_cost_hardening}"),
        };
        out.push_str(&format!(
            "| `{}` | {} | {} | {} | {} |\n",
            funnel.key, issues, upstream, downstream, residual
        ));
    }
    out.push_str(&format!(
        "\n## Verification\n\n\
`cargo xtask archrules matrix --check` 校验 source issue stable-ID {} 精确覆盖、key 唯一、边界非空、无 Soft、Hard carrier 证明、Medium synthetic-red/anti-vacuity 与文档漂移。当前行数由 catalog 动态派生：{}。该检查随 `archrules` 进入 `verify`/`ci`。\n",
        expected_issue_partition("–"),
        FUNNELS.len()
    ));
    Ok(out)
}

fn render_boundaries(records: &[RuleRecord], keys: &[InvariantKey]) -> Result<String> {
    keys.iter()
        .map(|key| {
            let record = select_record(records, *key)
                .with_context(|| format!("matrix 缺 invariant {}", key.id))?;
            let proof = match record.level {
                RuleLevel::Hard if record.source_kind == SourceKind::Codegen => format!(
                    "golden={}, red={}, green={}",
                    record.golden.as_deref().unwrap_or("-"),
                    record.synthetic_red.as_deref().unwrap_or("-"),
                    record.anti_vacuity.as_deref().unwrap_or("-")
                ),
                RuleLevel::Hard => record.native.as_deref().unwrap_or("trybuild").to_string(),
                RuleLevel::Medium => format!(
                    "red={}, green={}",
                    record.synthetic_red.as_deref().unwrap_or("-"),
                    record.anti_vacuity.as_deref().unwrap_or("-")
                ),
            };
            Ok(format!(
                "`{}{}` {} / {} / {} / {} / evidence={} ({})",
                key.id,
                key.facet.map_or(String::new(), |facet| format!("#{facet}")),
                record.level.as_str(),
                record.carrier,
                record.gate,
                record.source,
                record.evidence,
                proof
            ))
        })
        .collect::<Result<Vec<_>>>()
        .map(|parts| parts.join("<br>"))
}

fn build_index(root: &Path) -> Result<Index> {
    let mut index = Index::default();
    scan_xtask(root, &mut index)?;
    scan_dylint(root, &mut index)?;
    scan_config(root, &mut index, "deny.toml", "deny", "check")?;
    scan_config(root, &mut index, "clippy.toml", "clippy", "check")?;
    scan_config(
        root,
        &mut index,
        "xtask/runtime-deps-guard.toml",
        "runtime-deps-config",
        "check",
    )?;
    scan_config(
        root,
        &mut index,
        "xtask/runtime-root-ratchet.toml",
        "runtime-root-ratchet-config",
        "check",
    )?;
    scan_public_api(root, &mut index)?;
    scan_source_invariants(root, &mut index)?;
    scan_trybuild_and_native(root, &mut index)?;
    reject_conflicting_facets(&mut index);
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
            .then_with(|| a.facet.cmp(&b.facet))
            .then_with(|| a.carrier.cmp(&b.carrier))
            .then_with(|| a.source.cmp(&b.source))
    });
    index.test_evidence = TestEvidenceIndex::build(root, &index.records)?;
    Ok(index)
}

fn scan_xtask(root: &Path, index: &mut Index) -> Result<()> {
    let src = root.join("xtask/src");
    for path in rust_files_under(&src)? {
        if path.ends_with("xtask/src/publicapi.rs") {
            continue;
        }
        if scan_record_granular_xtask_invariants(root, index, &path)? {
            continue;
        }
        let gate = xtask_gate(root, &path)?;
        scan_invariant_file(
            root,
            index,
            &path,
            "xtask",
            xtask_evidence(&path),
            gate.as_deref(),
        )?;
    }
    Ok(())
}

fn scan_record_granular_xtask_invariants(
    root: &Path,
    index: &mut Index,
    path: &Path,
) -> Result<bool> {
    let relative = rel(root, path);
    if relative == "xtask/src/cmd.rs" {
        scan_compiler_cache_invariants(root, index, path)?;
        return Ok(true);
    }
    let bindings = match relative.as_str() {
        "xtask/src/ci_lanes.rs" => CI_LANE_INVARIANT_BINDINGS,
        "xtask/src/integration_shards.rs" => INTEGRATION_SHARD_INVARIANT_BINDINGS,
        "xtask/src/nextest.rs" => NEXTEST_INVARIANT_BINDINGS,
        "xtask/src/ci_slo.rs" => CI_SLO_INVARIANT_BINDINGS,
        "xtask/src/ci_impact.rs" => CI_IMPACT_INVARIANT_BINDINGS,
        "xtask/src/ci_gate.rs" => CI_GATE_INVARIANT_BINDINGS,
        "xtask/src/localtx_coverage.rs" => LOCALTX_COVERAGE_INVARIANT_BINDINGS,
        "xtask/src/localtx_evidence.rs" => LOCALTX_EVIDENCE_INVARIANT_BINDINGS,
        "xtask/src/localonly_evidence.rs" => LOCALONLY_EVIDENCE_INVARIANT_BINDINGS,
        "xtask/src/assembly_lock.rs" => ASSEMBLY_LOCK_INVARIANT_BINDINGS,
        "xtask/src/l2_assurance.rs" => L2_ASSURANCE_INVARIANT_BINDINGS,
        "xtask/src/provider_capabilities.rs" => PROVIDER_CAPABILITIES_INVARIANT_BINDINGS,
        "xtask/src/producer_assurance.rs" => PRODUCER_ASSURANCE_INVARIANT_BINDINGS,
        "xtask/src/production_composition.rs" => PRODUCTION_COMPOSITION_INVARIANT_BINDINGS,
        _ => return Ok(false),
    };
    let found_invariants = extract_invariants(root, path)?;
    record_invalid_invariants(index, &found_invariants);
    validate_closed_invariant_bindings(index, path, &found_invariants, bindings);
    for binding in bindings {
        debug_assert_eq!(binding.path, relative);
        scan_extracted_invariant_rules_filtered(
            root,
            index,
            &found_invariants,
            binding.carrier,
            binding.evidence,
            Some(binding.binding.token()),
            |rule| binding.matches(rule) && binding.accepts(rule),
        )?;
    }
    Ok(true)
}

fn scan_compiler_cache_invariants(root: &Path, index: &mut Index, path: &Path) -> Result<()> {
    let found_invariants = extract_invariants(root, path)?;
    record_invalid_invariants(index, &found_invariants);
    let compiler_cache_invariants = found_invariants
        .iter()
        .filter_map(|found| {
            let rules = found
                .rules
                .iter()
                .filter(|rule| rule.id.starts_with("COMPILER-CACHE-POLICY-"))
                .cloned()
                .collect::<Vec<_>>();
            (!rules.is_empty()).then(|| FoundInvariant {
                source: found.source.clone(),
                rules,
                invalid: Vec::new(),
            })
        })
        .collect::<Vec<_>>();
    validate_closed_invariant_bindings(
        index,
        path,
        &compiler_cache_invariants,
        COMPILER_CACHE_INVARIANT_BINDINGS,
    );
    for binding in COMPILER_CACHE_INVARIANT_BINDINGS {
        scan_extracted_invariant_rules_filtered(
            root,
            index,
            &compiler_cache_invariants,
            binding.carrier,
            binding.evidence,
            Some(binding.binding.token()),
            |rule| binding.matches(rule) && binding.accepts(rule),
        )?;
    }
    let gate = xtask_gate(root, path)?;
    scan_extracted_invariant_rules_filtered(
        root,
        index,
        &found_invariants,
        "xtask",
        xtask_evidence(path),
        gate.as_deref(),
        |rule| !rule.id.starts_with("COMPILER-CACHE-POLICY-"),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InvariantCarrierBinding {
    path: &'static str,
    id: &'static str,
    facet: Option<&'static str>,
    carrier: &'static str,
    evidence: &'static str,
    binding: CarrierExecutionBinding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CarrierExecutionBinding {
    Unit(crate::execution_profiles::ExecutionUnitId),
    ManualOptIn,
    NativeCompile,
}

impl CarrierExecutionBinding {
    const fn token(self) -> &'static str {
        match self {
            Self::Unit(unit) => unit.primary_owner().as_str(),
            Self::ManualOptIn => "manual/opt-in",
            Self::NativeCompile => "native-compile",
        }
    }
}

const CHECK_UNIT_BINDING: CarrierExecutionBinding = CarrierExecutionBinding::Unit(
    crate::execution_profiles::ExecutionUnitId::Gate(crate::ci_lanes::GateId::ArchRules),
);
const TEST_UNIT_BINDING: CarrierExecutionBinding = CarrierExecutionBinding::Unit(
    crate::execution_profiles::ExecutionUnitId::Gate(crate::ci_lanes::GateId::DefaultNextest),
);
const RELEASE_UNIT_BINDING: CarrierExecutionBinding = CarrierExecutionBinding::Unit(
    crate::execution_profiles::ExecutionUnitId::Gate(crate::ci_lanes::GateId::Coverage),
);

impl InvariantCarrierBinding {
    fn matches(self, rule: &FoundRule) -> bool {
        rule.id == self.id
            && rule
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.facet.as_deref())
                == self.facet
    }

    fn accepts(self, rule: &FoundRule) -> bool {
        let Some(metadata) = rule.metadata.as_ref() else {
            return false;
        };
        !(metadata.level == RuleLevel::Medium
            && metadata.synthetic_red.is_some()
            && self.carrier == "native-hard")
    }
}

const CI_LANE_INVARIANT_BINDINGS: &[InvariantCarrierBinding] = &[
    InvariantCarrierBinding {
        path: "xtask/src/ci_lanes.rs",
        id: "CI-LANE-REGISTRY-01",
        facet: None,
        carrier: "native-hard",
        evidence: "gate_catalog generated closed enum and registry",
        binding: CarrierExecutionBinding::NativeCompile,
    },
    InvariantCarrierBinding {
        path: "xtask/src/ci_lanes.rs",
        id: "CI-LANE-PLAN-01",
        facet: None,
        carrier: "xtask",
        evidence: "bound synthetic red and anti-vacuity tests",
        binding: CHECK_UNIT_BINDING,
    },
    InvariantCarrierBinding {
        path: "xtask/src/ci_lanes.rs",
        id: "CI-SLO-JOB-TYPE-01",
        facet: None,
        carrier: "native-hard",
        evidence: "closed exhaustive CI SLO job enum and workflow-parts constructor",
        binding: CarrierExecutionBinding::NativeCompile,
    },
    InvariantCarrierBinding {
        path: "xtask/src/ci_lanes.rs",
        id: "CI-IMPACT-CATALOG-01",
        facet: None,
        carrier: "native-hard",
        evidence: "ci_job_catalog generated closed enum, matrix identity, and artifact identity",
        binding: CarrierExecutionBinding::NativeCompile,
    },
    InvariantCarrierBinding {
        path: "xtask/src/ci_lanes.rs",
        id: "CI-REQUIRED-EVIDENCE-OWNER-01",
        facet: None,
        carrier: "native-hard",
        evidence: "closed required-evidence kind and exact-one-owner const proof",
        binding: CarrierExecutionBinding::NativeCompile,
    },
];

const CI_IMPACT_INVARIANT_BINDINGS: &[InvariantCarrierBinding] = &[
    InvariantCarrierBinding {
        path: "xtask/src/ci_impact.rs",
        id: "CI-IMPACT-PLAN-01",
        facet: None,
        carrier: "native-hard",
        evidence: "private validated plan constructor over the exact typed job catalog",
        binding: CarrierExecutionBinding::NativeCompile,
    },
    InvariantCarrierBinding {
        path: "xtask/src/ci_impact.rs",
        id: "CI-IMPACT-POLICY-01",
        facet: None,
        carrier: "xtask",
        evidence: "diff and impact synthetic reds with workspace policy anti-vacuity",
        binding: CHECK_UNIT_BINDING,
    },
    InvariantCarrierBinding {
        path: "xtask/src/ci_impact.rs",
        id: "CI-IMPACT-PROJECTION-01",
        facet: None,
        carrier: "native-hard",
        evidence: "private ImpactSet and exhaustive local/remote/coverage projection matches",
        binding: CarrierExecutionBinding::NativeCompile,
    },
    InvariantCarrierBinding {
        path: "xtask/src/ci_impact.rs",
        id: "CI-IMPACT-REQUIRED-EVIDENCE-01",
        facet: None,
        carrier: "xtask",
        evidence: "adaptive-plan owner synthetic reds with required-owner anti-vacuity",
        binding: CHECK_UNIT_BINDING,
    },
    InvariantCarrierBinding {
        path: "xtask/src/ci_impact.rs",
        id: "COVERAGE-SCOPE-PROJECTION-01",
        facet: None,
        carrier: "native-hard",
        evidence: "CoverageDecision Skip|Scope exhaustively projected from private ImpactSet",
        binding: CarrierExecutionBinding::NativeCompile,
    },
];

const CI_GATE_INVARIANT_BINDINGS: &[InvariantCarrierBinding] = &[
    InvariantCarrierBinding {
        path: "xtask/src/ci_gate.rs",
        id: "CI-GATE-RECEIPT-01",
        facet: None,
        carrier: "xtask",
        evidence: "receipt identity synthetic reds with exact-set anti-vacuity",
        binding: CHECK_UNIT_BINDING,
    },
    InvariantCarrierBinding {
        path: "xtask/src/ci_gate.rs",
        id: "LOCALTX-REQUIRED-EVIDENCE-01",
        facet: None,
        carrier: "xtask",
        evidence: "LocalTx receipt disk-matrix synthetic reds with exact-set anti-vacuity",
        binding: CHECK_UNIT_BINDING,
    },
    InvariantCarrierBinding {
        path: "xtask/src/ci_gate.rs",
        id: "LOCAL-ONLY-REQUIRED-EVIDENCE-01",
        facet: None,
        carrier: "xtask",
        evidence: "LocalOnly report disk-matrix synthetic reds with exact-set anti-vacuity",
        binding: CHECK_UNIT_BINDING,
    },
];

const LOCALTX_COVERAGE_INVARIANT_BINDINGS: &[InvariantCarrierBinding] = &[
    InvariantCarrierBinding {
        path: "xtask/src/localtx_coverage.rs",
        id: "LOCALTX-COVERAGE-CLOSURE-01",
        facet: None,
        carrier: "xtask",
        evidence: "workspace inventory synthetic reds with non-empty closure anti-vacuity",
        binding: CHECK_UNIT_BINDING,
    },
    InvariantCarrierBinding {
        path: "xtask/src/localtx_coverage.rs",
        id: "LOCALTX-BACKEND-PROFILE-CLOSURE-01",
        facet: None,
        carrier: "xtask",
        evidence: "backend profile AST synthetic reds with real-workspace anti-vacuity",
        binding: CHECK_UNIT_BINDING,
    },
    InvariantCarrierBinding {
        path: "xtask/src/localtx_coverage.rs",
        id: "LOCALTX-JOURNEY-CLOSURE-01",
        facet: None,
        carrier: "xtask",
        evidence: "journey inventory synthetic reds with real-workspace anti-vacuity",
        binding: CHECK_UNIT_BINDING,
    },
    InvariantCarrierBinding {
        path: "xtask/src/localtx_coverage.rs",
        id: "LOCALTX-REQUIRED-EVIDENCE-EXACTSET-01",
        facet: None,
        carrier: "xtask",
        evidence: "carrier/exact-set synthetic reds with canonical workspace anti-vacuity",
        binding: RELEASE_UNIT_BINDING,
    },
];

const LOCALTX_EVIDENCE_INVARIANT_BINDINGS: &[InvariantCarrierBinding] = &[
    InvariantCarrierBinding {
        path: "xtask/src/localtx_evidence.rs",
        id: "LOCALTX-REQUIRED-EVIDENCE-FUNNEL-01",
        facet: None,
        carrier: "native-hard",
        evidence: "private success capabilities and sole receipt publication constructor",
        binding: CarrierExecutionBinding::NativeCompile,
    },
    InvariantCarrierBinding {
        path: "xtask/src/localtx_evidence.rs",
        id: "LOCALTX-REQUIRED-EVIDENCE-WIRE-01",
        facet: None,
        carrier: "native-hard",
        evidence: "closed private receipt DTO and typed fixed wire values",
        binding: CarrierExecutionBinding::NativeCompile,
    },
];

const LOCALONLY_EVIDENCE_INVARIANT_BINDINGS: &[InvariantCarrierBinding] = &[
    InvariantCarrierBinding {
        path: "xtask/src/localonly_evidence.rs",
        id: "LOCAL-ONLY-EXECUTION-FUNNEL-01",
        facet: None,
        carrier: "native-hard",
        evidence: "private suite and exact-set capabilities gate the sole report publisher",
        binding: CarrierExecutionBinding::NativeCompile,
    },
    InvariantCarrierBinding {
        path: "xtask/src/localonly_evidence.rs",
        id: "LOCAL-ONLY-EXECUTION-EXACTSET-01",
        facet: None,
        carrier: "xtask",
        evidence: "marker and set synthetic reds with real workspace non-empty anti-vacuity",
        binding: CHECK_UNIT_BINDING,
    },
    InvariantCarrierBinding {
        path: "xtask/src/localonly_evidence.rs",
        id: "LOCAL-ONLY-EXECUTION-WIRE-01",
        facet: None,
        carrier: "native-hard",
        evidence: "private deny-unknown-fields v1 DTO and closed typed owner",
        binding: CarrierExecutionBinding::NativeCompile,
    },
];

const CI_SLO_INVARIANT_BINDINGS: &[InvariantCarrierBinding] = &[
    InvariantCarrierBinding {
        path: "xtask/src/ci_slo.rs",
        id: "CI-SLO-CONFIG-SCHEMA-01",
        facet: None,
        carrier: "xtask",
        evidence: "strict config synthetic reds and committed complete catalog anti-vacuity",
        binding: CHECK_UNIT_BINDING,
    },
    InvariantCarrierBinding {
        path: "xtask/src/ci_slo.rs",
        id: "CI-SLO-EVALUATION-01",
        facet: None,
        carrier: "xtask",
        evidence: "strict config and evidence synthetic reds with committed fixture and summary golden",
        binding: CHECK_UNIT_BINDING,
    },
];

const INTEGRATION_SHARD_INVARIANT_BINDINGS: &[InvariantCarrierBinding] = &[
    InvariantCarrierBinding {
        path: "xtask/src/integration_shards.rs",
        id: "INTEGRATION-SHARD-REGISTRY-01",
        facet: None,
        carrier: "native-hard",
        evidence: "catalog macro generated closed enum, registry, and exhaustive lookup",
        binding: CarrierExecutionBinding::NativeCompile,
    },
    InvariantCarrierBinding {
        path: "xtask/src/integration_shards.rs",
        id: "INTEGRATION-SHARD-SELECTOR-01",
        facet: None,
        carrier: "native-hard",
        evidence: "typed execution units are the only filterset construction path",
        binding: CarrierExecutionBinding::NativeCompile,
    },
    InvariantCarrierBinding {
        path: "xtask/src/integration_shards.rs",
        id: "INTEGRATION-SHARD-COVERAGE-01",
        facet: None,
        carrier: "xtask",
        evidence: "Cargo metadata closure with synthetic red and real-workspace anti-vacuity",
        binding: RELEASE_UNIT_BINDING,
    },
    InvariantCarrierBinding {
        path: "xtask/src/integration_shards.rs",
        id: "INTEGRATION-SHARD-SCHEDULING-01",
        facet: None,
        carrier: "xtask",
        evidence: "exact resource and target scheduling plan with rendered argv proof",
        binding: RELEASE_UNIT_BINDING,
    },
];

const NEXTEST_INVARIANT_BINDINGS: &[InvariantCarrierBinding] = &[
    InvariantCarrierBinding {
        path: "xtask/src/nextest.rs",
        id: "NEXTEST-PROFILE-REGISTRY-01",
        facet: None,
        carrier: "native-hard",
        evidence: "closed profile enum",
        binding: CarrierExecutionBinding::NativeCompile,
    },
    InvariantCarrierBinding {
        path: "xtask/src/nextest.rs",
        id: "NEXTEST-PARTITION-TYPE-01",
        facet: None,
        carrier: "native-hard",
        evidence: "validated partition newtype",
        binding: CarrierExecutionBinding::NativeCompile,
    },
    InvariantCarrierBinding {
        path: "xtask/src/nextest.rs",
        id: "NEXTEST-EVIDENCE-DTO-01",
        facet: None,
        carrier: "native-hard",
        evidence: "typed serde DTO and committed golden",
        binding: CarrierExecutionBinding::NativeCompile,
    },
    InvariantCarrierBinding {
        path: "xtask/src/nextest.rs",
        id: "NEXTEST-EVIDENCE-SCHEMA-01",
        facet: None,
        carrier: "xtask",
        evidence: "serde wire synthetic red and committed golden anti-vacuity",
        binding: TEST_UNIT_BINDING,
    },
    InvariantCarrierBinding {
        path: "xtask/src/nextest.rs",
        id: "NEXTEST-CONFIG-POLICY-01",
        facet: None,
        carrier: "xtask",
        evidence: "parsed config synthetic red and committed anti-vacuity",
        binding: TEST_UNIT_BINDING,
    },
    InvariantCarrierBinding {
        path: "xtask/src/nextest.rs",
        id: "NEXTEST-EXECUTION-FUNNEL-01",
        facet: None,
        carrier: "xtask",
        evidence: "direct-call synthetic red and production source anti-vacuity",
        binding: TEST_UNIT_BINDING,
    },
    InvariantCarrierBinding {
        path: "xtask/src/nextest.rs",
        id: "NEXTEST-TRYBUILD-SCHEDULING-01",
        facet: None,
        carrier: "xtask",
        evidence: "AST plus Cargo metadata exact-set synthetic red and workspace anti-vacuity",
        binding: TEST_UNIT_BINDING,
    },
    InvariantCarrierBinding {
        path: "xtask/src/nextest.rs",
        id: "COVERAGE-SCOPE-NONEMPTY-01",
        facet: None,
        carrier: "native-hard",
        evidence: "CoverageScope::packages returns None for empty lists; execution accepts only CoverageScope",
        binding: CarrierExecutionBinding::NativeCompile,
    },
    InvariantCarrierBinding {
        path: "xtask/src/nextest.rs",
        id: "COVERAGE-ARGV-SCOPE-01",
        facet: None,
        carrier: "native-hard",
        evidence: "Packages argv uses -p exclusively; Workspace uses --workspace exclusively",
        binding: CarrierExecutionBinding::NativeCompile,
    },
    InvariantCarrierBinding {
        path: "xtask/src/nextest.rs",
        id: "COVERAGE-REPLAY-SCOPE-01",
        facet: None,
        carrier: "xtask",
        evidence: "coverage argv scope synthetic red with workspace replay anti-vacuity",
        binding: RELEASE_UNIT_BINDING,
    },
];

const COMPILER_CACHE_INVARIANT_BINDINGS: &[InvariantCarrierBinding] = &[
    InvariantCarrierBinding {
        path: "xtask/src/cmd.rs",
        id: "COMPILER-CACHE-POLICY-01",
        facet: None,
        carrier: "native-hard",
        evidence: "closed CompilerCachePolicy enum and private validated constructor",
        binding: CarrierExecutionBinding::NativeCompile,
    },
    InvariantCarrierBinding {
        path: "xtask/src/cmd.rs",
        id: "COMPILER-CACHE-POLICY-02",
        facet: None,
        carrier: "xtask",
        evidence: "canonical-path/version synthetic red and enabled-policy anti-vacuity",
        binding: CarrierExecutionBinding::ManualOptIn,
    },
];

const ASSEMBLY_LOCK_INVARIANT_BINDINGS: &[InvariantCarrierBinding] = &[
    InvariantCarrierBinding {
        path: "xtask/src/assembly_lock.rs",
        id: "ASSEMBLY-LOCK-GOLDEN-01",
        facet: None,
        carrier: "xtask",
        evidence: "repository compiler golden drift with synthetic red and three real locks",
        binding: CHECK_UNIT_BINDING,
    },
    InvariantCarrierBinding {
        path: "xtask/src/assembly_lock.rs",
        id: "ASSEMBLY-LOCK-DIAGNOSTIC-01",
        facet: None,
        carrier: "native-hard",
        evidence: "closed safe diagnostic enums and private escaped repository path",
        binding: CarrierExecutionBinding::NativeCompile,
    },
    InvariantCarrierBinding {
        path: "xtask/src/assembly_lock.rs",
        id: "ASSEMBLY-LOCK-LF-CHECKOUT-01",
        facet: None,
        carrier: "xtask",
        evidence: "effective git attribute synthetic reds and real-lock anti-vacuity",
        binding: CHECK_UNIT_BINDING,
    },
    InvariantCarrierBinding {
        path: "xtask/src/assembly_lock.rs",
        id: "ASSEMBLY-LOCK-VERIFY-GATE-01",
        facet: None,
        carrier: "xtask",
        evidence: "typed exact-once aggregate plan synthetic reds",
        binding: CHECK_UNIT_BINDING,
    },
];

const L2_ASSURANCE_INVARIANT_BINDINGS: &[InvariantCarrierBinding] = &[
    InvariantCarrierBinding {
        path: "xtask/src/l2_assurance.rs",
        id: "L2-ASSURANCE-TYPE-01",
        facet: None,
        carrier: "native-hard",
        evidence: "closed private assurance record and complete-evidence construction types",
        binding: CarrierExecutionBinding::NativeCompile,
    },
    InvariantCarrierBinding {
        path: "xtask/src/l2_assurance.rs",
        id: "L2-ASSURANCE-CONSUMER-POLICY-01",
        facet: None,
        carrier: "xtask",
        evidence: "generated handler ID exact-set across registration-plan-handler-executor carriers with non-empty and raw-callsite synthetic reds",
        binding: CHECK_UNIT_BINDING,
    },
    InvariantCarrierBinding {
        path: "xtask/src/l2_assurance.rs",
        id: "L2-ASSURANCE-WIRE-01",
        facet: None,
        carrier: "xtask",
        evidence: "typed committed JSON golden with byte-drift synthetic red and real inventory anti-vacuity",
        binding: CHECK_UNIT_BINDING,
    },
    InvariantCarrierBinding {
        path: "xtask/src/l2_assurance.rs",
        id: "L2-ASSURANCE-CLOSURE-01",
        facet: None,
        carrier: "xtask",
        evidence: "generated producer/fact ID bidirectional exact-set with non-empty workspace anti-vacuity",
        binding: CHECK_UNIT_BINDING,
    },
    InvariantCarrierBinding {
        path: "xtask/src/l2_assurance.rs",
        id: "L2-ASSURANCE-PATH-01",
        facet: None,
        carrier: "xtask",
        evidence: "path escape and symlink synthetic red with real repository carriers",
        binding: CHECK_UNIT_BINDING,
    },
];

const PROVIDER_CAPABILITIES_INVARIANT_BINDINGS: &[InvariantCarrierBinding] = &[
    InvariantCarrierBinding {
        path: "xtask/src/provider_capabilities.rs",
        id: "L2-PROVIDER-CAPABILITY-ENROLLMENT-01",
        facet: None,
        carrier: "xtask",
        evidence: "exact provider declaration, live runner, owner target, and typed integration shard closure",
        binding: CHECK_UNIT_BINDING,
    },
    InvariantCarrierBinding {
        path: "xtask/src/provider_capabilities.rs",
        id: "L2-PROVIDER-CAPABILITY-WIRE-01",
        facet: None,
        carrier: "xtask",
        evidence: "typed schema v1 capability receipts with raw-byte golden drift and no-write synthetic reds",
        binding: CHECK_UNIT_BINDING,
    },
];

const PRODUCER_ASSURANCE_INVARIANT_BINDINGS: &[InvariantCarrierBinding] = &[
    InvariantCarrierBinding {
        path: "xtask/src/producer_assurance.rs",
        id: "L2-PRODUCER-EXECUTION-CLOSURE-01",
        facet: None,
        carrier: "xtask",
        evidence: "generated producer ID exact-set over mounted-handler transaction closures with non-empty synthetic red",
        binding: CHECK_UNIT_BINDING,
    },
];

const PRODUCTION_COMPOSITION_INVARIANT_BINDINGS: &[InvariantCarrierBinding] =
    &[InvariantCarrierBinding {
        path: "xtask/src/production_composition.rs",
        id: "L2-PRODUCER-PRODUCTION-COMPOSITION-01",
        facet: None,
        carrier: "xtask",
        evidence: "wrong-injection synthetic reds and exact four-port production composition",
        binding: CHECK_UNIT_BINDING,
    }];

fn invariant_key(rule: &FoundRule) -> (String, Option<String>) {
    (
        rule.id.clone(),
        rule.metadata
            .as_ref()
            .and_then(|metadata| metadata.facet.clone()),
    )
}

fn binding_key(binding: InvariantCarrierBinding) -> (String, Option<String>) {
    (binding.id.to_string(), binding.facet.map(str::to_string))
}

fn invariant_key_label((id, facet): &(String, Option<String>)) -> String {
    format!("{id}#{}", facet.as_deref().unwrap_or("<default>"))
}

fn validate_closed_invariant_bindings(
    index: &mut Index,
    path: &Path,
    found_invariants: &[FoundInvariant],
    bindings: &[InvariantCarrierBinding],
) {
    let mut source_counts = BTreeMap::new();
    for rule in found_invariants
        .iter()
        .flat_map(|invariant| &invariant.rules)
    {
        *source_counts.entry(invariant_key(rule)).or_insert(0usize) += 1;
    }
    let mut binding_counts = BTreeMap::new();
    for binding in bindings {
        *binding_counts
            .entry(binding_key(*binding))
            .or_insert(0usize) += 1;
    }
    let subject = path.to_string_lossy();
    for (key, count) in &source_counts {
        if *count > 1 {
            index.findings.push(finding(
                Rule::ConflictingInvariantFacet,
                subject.as_ref(),
                format!(
                    "源码 invariant key `{}` 重复 {count} 次",
                    invariant_key_label(key)
                ),
            ));
        }
        if !binding_counts.contains_key(key) {
            index.findings.push(finding(
                Rule::MissingInvariant,
                subject.as_ref(),
                format!(
                    "源码 invariant key `{}` 缺 carrier binding",
                    invariant_key_label(key)
                ),
            ));
        }
    }
    for (key, count) in &binding_counts {
        if *count > 1 {
            index.findings.push(finding(
                Rule::CarrierBindingMismatch,
                subject.as_ref(),
                format!(
                    "carrier binding key `{}` 重复 {count} 次",
                    invariant_key_label(key)
                ),
            ));
        }
        if !source_counts.contains_key(key) {
            index.findings.push(finding(
                Rule::MissingInvariant,
                subject.as_ref(),
                format!(
                    "carrier binding key `{}` 缺源码 invariant",
                    invariant_key_label(key)
                ),
            ));
        }
        let Some(binding) = bindings
            .iter()
            .find(|binding| binding_key(**binding) == *key)
        else {
            continue;
        };
        if !path.ends_with(binding.path) {
            index.findings.push(finding(
                Rule::CarrierBindingMismatch,
                subject.as_ref(),
                format!(
                    "carrier binding key `{}` 声明路径 `{}` 与源码不符",
                    invariant_key_label(key),
                    binding.path
                ),
            ));
        }
        for rule in found_invariants
            .iter()
            .flat_map(|invariant| &invariant.rules)
            .filter(|rule| invariant_key(rule) == *key)
        {
            if !binding.accepts(rule) {
                index.findings.push(finding(
                    Rule::CarrierBindingMismatch,
                    subject.as_ref(),
                    format!(
                        "carrier binding key `{}` 与 invariant metadata 不兼容",
                        invariant_key_label(key)
                    ),
                ));
            }
        }
    }
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
    let gate = xtask_gate(root, &path)?;
    scan_invariant_file(
        root,
        index,
        &path,
        "public-api",
        format!("{} baseline", target_crates.len()),
        gate.as_deref(),
    )
}

fn scan_source_invariants(root: &Path, index: &mut Index) -> Result<()> {
    let trybuild = trybuild_fixtures(root)?;
    let mut reachable_by_manifest = BTreeMap::<PathBuf, BTreeSet<PathBuf>>::new();
    for base in ["crates", "adapters", "assemblies", "bins", "journeys"] {
        let dir = root.join(base);
        if !dir.exists() {
            continue;
        }
        for path in rust_files_under(&dir)? {
            if trybuild.compile_fail.contains(&path)
                || trybuild.pass.contains(&path)
                || trybuild.harnesses.contains(&path)
            {
                continue;
            }
            let reachable = if let Some(manifest) = nearest_package_manifest(root, &path) {
                if !reachable_by_manifest.contains_key(&manifest) {
                    let files = cargo_reachable_files(&manifest)?;
                    reachable_by_manifest.insert(manifest.clone(), files);
                }
                reachable_by_manifest
                    .get(&manifest)
                    .is_some_and(|files| files.contains(&path))
            } else {
                false
            };
            scan_source_invariant_file_with_reachability(
                root,
                index,
                &path,
                "native-hard",
                "source invariant",
                reachable,
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
    let root_inventory = machine_dylint_inventory("Cargo.toml", &registered);
    let member_inventory = machine_dylint_inventory("lints/Cargo.toml", &members);
    let inventories = [
        ("root metadata", root_inventory),
        ("lints members", member_inventory),
    ];
    let canonical = inventories[0].1.names.clone();
    for (label, inventory) in &inventories {
        if !inventory.anchor_found
            || inventory.names.is_empty()
            || inventory.invalid_entries != 0
            || inventory.entry_count != inventory.names.len()
            || inventory.names != canonical
        {
            index.findings.push(finding(
                Rule::DylintRegistryDrift,
                inventory.path,
                format!(
                    "{label} must be present, non-empty, unique, and exactly match root metadata; \
                     anchor={} entries={} unique={} invalid={} names={:?} canonical={canonical:?}",
                    inventory.anchor_found,
                    inventory.entry_count,
                    inventory.names.len(),
                    inventory.invalid_entries,
                    inventory.names,
                ),
            ));
        }
    }
    if inventories
        .iter()
        .map(|(_, inventory)| &inventory.names)
        .collect::<BTreeSet<_>>()
        .len()
        != 1
    {
        index.findings.push(finding(
            Rule::DylintRegistryDrift,
            "lints",
            "machine dylint inventories are not exact",
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
            Some("check"),
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

#[derive(Debug)]
struct DylintInventory {
    path: &'static str,
    anchor_found: bool,
    entry_count: usize,
    invalid_entries: usize,
    names: BTreeSet<String>,
}

fn machine_dylint_inventory(path: &'static str, paths: &[PathBuf]) -> DylintInventory {
    let mut names = BTreeSet::new();
    let mut invalid_entries = 0;
    for path in paths {
        let mut components = path.components();
        match (components.next(), components.next(), components.next()) {
            (
                Some(std::path::Component::Normal(parent)),
                Some(std::path::Component::Normal(name)),
                None,
            ) if parent == "lints" && name.to_str().is_some_and(valid_dylint_name) => {
                names.insert(name.to_string_lossy().into_owned());
            }
            _ => invalid_entries += 1,
        }
    }
    DylintInventory {
        path,
        anchor_found: true,
        entry_count: paths.len(),
        invalid_entries,
        names,
    }
}

fn valid_dylint_name(name: &str) -> bool {
    name.starts_with("rss_")
        && name.len() > "rss_".len()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn scan_trybuild_and_native(root: &Path, index: &mut Index) -> Result<()> {
    let fixtures = trybuild_fixtures(root)?;
    for base in ["crates", "adapters", "assemblies", "bins", "journeys"] {
        let dir = root.join(base);
        if !dir.exists() {
            continue;
        }
        for path in rust_files_under(&dir)? {
            let is_trybuild = fixtures.compile_fail.contains(&path)
                || fixtures.pass.contains(&path)
                || fixtures.harnesses.contains(&path);
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
                Some("test")
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
    gate: Option<&str>,
) -> Result<()> {
    scan_invariant_file_filtered(root, index, path, carrier, evidence, gate, |_| true)
}

fn scan_native_compile_invariant_file(
    root: &Path,
    index: &mut Index,
    path: &Path,
    carrier: &str,
    evidence: impl Into<String>,
    gate: Option<&str>,
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
    gate: Option<&str>,
    include_rule: impl FnMut(&FoundRule) -> bool,
) -> Result<()> {
    if !path.exists() {
        index.findings.push(finding(
            Rule::MissingCarrier,
            rel(root, path),
            "carrier 文件不存在",
        ));
        return Ok(());
    }
    let found_invariants = extract_invariants(root, path)?;
    record_invalid_invariants(index, &found_invariants);
    scan_extracted_invariant_rules_filtered(
        root,
        index,
        &found_invariants,
        carrier,
        evidence,
        gate,
        include_rule,
    )?;
    if gate.is_none() && !found_invariants.is_empty() {
        index.findings.push(finding(
            Rule::MissingGate,
            rel(root, path),
            "carrier 缺 gate 证据",
        ));
    }
    Ok(())
}

fn record_invalid_invariants(index: &mut Index, found_invariants: &[FoundInvariant]) {
    for found in found_invariants {
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
    }
}

fn scan_extracted_invariant_rules_filtered(
    root: &Path,
    index: &mut Index,
    found_invariants: &[FoundInvariant],
    carrier: &str,
    evidence: impl Into<String>,
    gate: Option<&str>,
    mut include_rule: impl FnMut(&FoundRule) -> bool,
) -> Result<()> {
    let evidence = evidence.into();
    let gate_text = gate.unwrap_or("missing").to_string();
    let status = if gate.is_some() { "ok" } else { "missing-gate" }.to_string();
    for found in found_invariants {
        for rule in found.rules.iter().filter(|rule| include_rule(rule)) {
            let Some(metadata) =
                validated_metadata(root, index, &found.source, carrier, gate, rule)
            else {
                continue;
            };
            index.records.push(RuleRecord {
                id: rule.id.clone(),
                facet: metadata.facet.clone(),
                level: metadata.level,
                exec: metadata.exec,
                source_kind: metadata.source_kind,
                carrier: carrier.to_string(),
                source: found.source.clone(),
                evidence: evidence.clone(),
                gate: gate_text.clone(),
                status: status.clone(),
                native: metadata.native.clone(),
                golden: metadata.golden.clone(),
                synthetic_red: metadata.synthetic_red.clone(),
                anti_vacuity: metadata.anti_vacuity.clone(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
fn scan_source_invariant_file(
    root: &Path,
    index: &mut Index,
    path: &Path,
    carrier: &str,
    evidence: impl Into<String>,
) -> Result<()> {
    let reachable = cargo_target_reaches(root, path)?;
    scan_source_invariant_file_with_reachability(root, index, path, carrier, evidence, reachable)
}

fn scan_source_invariant_file_with_reachability(
    root: &Path,
    index: &mut Index,
    path: &Path,
    carrier: &str,
    evidence: impl Into<String>,
    cargo_reachable: bool,
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
    let found_invariants = extract_source_invariants(root, path)?;
    // Source membership follows typed/stable evidence, never directory names. Native/manual are
    // intrinsic source carriers; real Rust test symbols enroll the carrier in the exact Cargo
    // execution context that reaches them, while the cross-file wiring guard is identified by its
    // stable invariant ID.
    let mut bindings = BTreeSet::from(["manual/opt-in", "native-compile"]);
    let declares_integration_evidence = found_invariants
        .iter()
        .flat_map(|invariant| &invariant.rules)
        .filter_map(|rule| rule.metadata.as_ref())
        .any(|metadata| {
            metadata.exec
                == ExecutionLevel::Profile(
                    crate::execution_profiles::ExecutionProfile::IntegrationCritical,
                )
        });
    if cargo_reachable && !declares_integration_evidence && !collect_test_names(path)?.is_empty() {
        bindings.insert(crate::execution_profiles::ExecutionProfile::Test.as_str());
    }
    if cargo_reachable
        && declares_integration_evidence
        && cargo_source_has_test_symbols(
            root,
            path,
            ExecutionLevel::Profile(
                crate::execution_profiles::ExecutionProfile::IntegrationCritical,
            ),
        )?
    {
        bindings.insert(crate::execution_profiles::ExecutionProfile::IntegrationCritical.as_str());
    }
    if found_invariants
        .iter()
        .flat_map(|invariant| &invariant.rules)
        .any(|rule| rule.id == "WIRING-DEPS-INFRA-ONLY-01")
    {
        bindings.insert(crate::execution_profiles::ExecutionProfile::Check.as_str());
    }
    let gate_text = bindings.into_iter().collect::<Vec<_>>().join(",");
    let gate = Some(gate_text.as_str());
    let status = "ok".to_string();
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
            let Some(metadata) =
                validated_metadata(root, index, &found.source, carrier, gate, rule)
            else {
                continue;
            };
            index.records.push(RuleRecord {
                id: rule.id.clone(),
                facet: metadata.facet.clone(),
                level: metadata.level,
                exec: metadata.exec,
                source_kind: metadata.source_kind,
                carrier: carrier.to_string(),
                source: found.source.clone(),
                evidence: evidence.clone(),
                gate: gate_text.clone(),
                status: status.clone(),
                native: metadata.native.clone(),
                golden: metadata.golden.clone(),
                synthetic_red: metadata.synthetic_red.clone(),
                anti_vacuity: metadata.anti_vacuity.clone(),
            });
        }
    }
    Ok(())
}

fn validated_metadata(
    root: &Path,
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
    if metadata.level == RuleLevel::Hard && metadata.source_kind == SourceKind::Codegen {
        let complete = metadata
            .golden
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty() && root.join(value).is_file())
            && metadata
                .synthetic_red
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty())
            && metadata
                .anti_vacuity
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty());
        if !complete {
            index.findings.push(finding(
                Rule::MissingCodegenHardProof,
                source.to_string(),
                format!(
                    "INVARIANT `{}` codegen Hard 缺 committed golden / synthetic_red / anti_vacuity 证明",
                    rule.id
                ),
            ));
        }
    }
    Some(metadata)
}

fn reject_conflicting_facets(index: &mut Index) {
    let mut seen: BTreeMap<FacetKey, RuleBinding> = BTreeMap::new();
    for record in &index.records {
        let file = record
            .source
            .rsplit_once(':')
            .map_or(record.source.as_str(), |(file, _)| file)
            .to_string();
        let key = (file, record.id.clone(), record.facet.clone());
        let binding = (record.level, record.exec, record.source_kind);
        if seen.get(&key).is_some_and(|prior| *prior != binding) {
            index.findings.push(finding(
                Rule::ConflictingInvariantFacet,
                record.source.clone(),
                format!(
                    "INVARIANT `{}` facet `{}` 在同一 carrier 文件声明冲突强度/载体",
                    record.id,
                    record.facet.as_deref().unwrap_or("<default>")
                ),
            ));
        } else {
            seen.insert(key, binding);
        }
    }
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
                (carrier == "native-hard"
                    && matches!(
                        (metadata.exec, metadata.source_kind),
                        (
                            ExecutionLevel::NativeCompile,
                            SourceKind::Code | SourceKind::Rustdoc
                        ) | (
                            ExecutionLevel::Profile(
                                crate::execution_profiles::ExecutionProfile::Test
                            ),
                            SourceKind::Trybuild
                        )
                    ))
                    || (carrier == "xtask"
                        && metadata.exec
                            == ExecutionLevel::Profile(
                                crate::execution_profiles::ExecutionProfile::Check,
                            )
                        && metadata.source_kind == SourceKind::Codegen)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ExecutionLevel {
    Profile(crate::execution_profiles::ExecutionProfile),
    ManualOptIn,
    NativeCompile,
}

impl ExecutionLevel {
    fn as_str(self) -> &'static str {
        match self {
            Self::Profile(profile) => profile.as_str(),
            Self::ManualOptIn => "manual/opt-in",
            Self::NativeCompile => "native-compile",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "manual/opt-in" => Some(Self::ManualOptIn),
            "native-compile" => Some(Self::NativeCompile),
            _ => crate::execution_profiles::ExecutionProfile::from_str(value)
                .ok()
                .map(Self::Profile),
        }
    }

    fn is_bound_to_gate(self, gate: Option<&str>) -> bool {
        match self {
            Self::NativeCompile => gate_has(gate, "native-compile"),
            Self::ManualOptIn => gate_has(gate, "manual/opt-in"),
            Self::Profile(profile) => gate_has(gate, profile.as_str()),
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
            "deny" | "clippy" | "runtime-deps-config" | "runtime-root-ratchet-config" => {
                self == Self::Config
            }
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
    facet: Option<String>,
    golden: Option<String>,
    synthetic_red: Option<String>,
    anti_vacuity: Option<String>,
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
    let optional = |name: &str| {
        table
            .get(name)
            .and_then(toml::Value::as_str)
            .map(str::to_string)
    };
    Ok(InvariantMetadata {
        level,
        exec,
        source_kind,
        native,
        facet: optional("facet"),
        golden: optional("golden"),
        synthetic_red: optional("synthetic_red"),
        anti_vacuity: optional("anti_vacuity"),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SupportCarrierBinding {
    Profile(crate::execution_profiles::ExecutionProfile),
    ManualOptIn,
}

const XTASK_SUPPORT_CARRIERS: &[(&str, SupportCarrierBinding)] = &[
    (
        "xtask/src/verify.rs",
        SupportCarrierBinding::Profile(crate::execution_profiles::ExecutionProfile::Check),
    ),
    (
        "xtask/src/layers.rs",
        SupportCarrierBinding::Profile(crate::execution_profiles::ExecutionProfile::Check),
    ),
    (
        "xtask/src/src_scan.rs",
        SupportCarrierBinding::Profile(crate::execution_profiles::ExecutionProfile::Check),
    ),
    (
        "xtask/src/contract/manifest.rs",
        SupportCarrierBinding::Profile(crate::execution_profiles::ExecutionProfile::Check),
    ),
    (
        "xtask/src/contract/protection.rs",
        SupportCarrierBinding::Profile(crate::execution_profiles::ExecutionProfile::Check),
    ),
    (
        "xtask/src/contract/redaction.rs",
        SupportCarrierBinding::Profile(crate::execution_profiles::ExecutionProfile::Check),
    ),
    (
        "xtask/src/pathsafe.rs",
        SupportCarrierBinding::Profile(crate::execution_profiles::ExecutionProfile::Check),
    ),
    (
        "xtask/src/diffcov.rs",
        SupportCarrierBinding::Profile(crate::execution_profiles::ExecutionProfile::ReleaseCheck),
    ),
    ("xtask/src/cmd.rs", SupportCarrierBinding::ManualOptIn),
    (
        "xtask/src/diagnostic.rs",
        SupportCarrierBinding::ManualOptIn,
    ),
];

fn xtask_gate(root: &Path, path: &Path) -> Result<Option<String>> {
    let relative = rel(root, path);
    let mut bindings = BTreeSet::new();
    for unit in crate::execution_profiles::ExecutionUnitSpec::all() {
        if let crate::execution_profiles::ExecutionUnitSpec::Gate(gate) = unit
            && gate.id().carrier_file() == Some(relative.as_str())
        {
            bindings.insert(unit.primary_owner().as_str());
        }
    }
    if let Some((_, binding)) = XTASK_SUPPORT_CARRIERS
        .iter()
        .find(|(carrier, _)| *carrier == relative)
    {
        bindings.insert(match binding {
            SupportCarrierBinding::Profile(profile) => profile.as_str(),
            SupportCarrierBinding::ManualOptIn => "manual/opt-in",
        });
    }
    if !collect_test_names(path)?.is_empty() {
        bindings.insert(crate::execution_profiles::ExecutionProfile::Test.as_str());
    }
    Ok((!bindings.is_empty()).then(|| bindings.into_iter().collect::<Vec<_>>().join(",")))
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
    harnesses: BTreeSet<PathBuf>,
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
            if !file_contains(&path, "trybuild::TestCases")?
                || !cargo_test_target_roots(root, &path)?.contains(&path)
            {
                continue;
            }
            let calls = trybuild_calls(&path)?;
            if calls.is_empty() {
                continue;
            }
            let Some(manifest) = nearest_package_manifest(root, &path) else {
                continue;
            };
            fixtures.harnesses.insert(path.clone());
            let crate_root = manifest.parent().unwrap_or(root).to_path_buf();
            for call in calls {
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
    let file = syn::parse_file(&text)
        .with_context(|| format!("解析 trybuild harness `{}`", path.display()))?;
    let context = TestCfgContext::for_source(path)?;
    if !attrs_prove_test_execution(&file.attrs, &context) {
        return Ok(Vec::new());
    }
    struct HarnessCollector<'a> {
        disabled: usize,
        calls: Vec<TrybuildCall>,
        context: &'a TestCfgContext,
    }
    impl<'ast> Visit<'ast> for HarnessCollector<'_> {
        fn visit_item_mod(&mut self, module: &'ast syn::ItemMod) {
            let disabled = !attrs_prove_test_execution(&module.attrs, self.context);
            self.disabled += usize::from(disabled);
            if module.content.is_some() {
                syn::visit::visit_item_mod(self, module);
            }
            self.disabled -= usize::from(disabled);
        }

        fn visit_item_fn(&mut self, function: &'ast syn::ItemFn) {
            let is_test = function.attrs.iter().any(|attr| {
                attr.path().segments.last().is_some_and(|segment| {
                    matches!(segment.ident.to_string().as_str(), "test" | "rstest")
                })
            });
            if self.disabled == 0
                && is_test
                && attrs_prove_test_execution(&function.attrs, self.context)
                && !function.block.stmts.is_empty()
            {
                self.calls
                    .extend(trybuild_calls_in_test(function, self.context));
            }
        }
    }
    let mut collector = HarnessCollector {
        disabled: 0,
        calls: Vec::new(),
        context: &context,
    };
    collector.visit_file(&file);
    Ok(collector.calls)
}

fn trybuild_calls_in_test(function: &syn::ItemFn, context: &TestCfgContext) -> Vec<TrybuildCall> {
    let mut calls = Vec::new();
    walk_trybuild_block(&function.block, BTreeSet::new(), &mut calls, context);
    calls
}

fn walk_trybuild_block(
    block: &syn::Block,
    mut constructors: BTreeSet<String>,
    calls: &mut Vec<TrybuildCall>,
    context: &TestCfgContext,
) {
    for statement in &block.stmts {
        match statement {
            syn::Stmt::Local(local) if attrs_prove_test_execution(&local.attrs, context) => {
                if let Some(init) = &local.init {
                    collect_trybuild_expr_calls(&init.expr, &constructors, calls, context);
                }
                if let syn::Pat::Ident(binding) = &local.pat {
                    if local
                        .init
                        .as_ref()
                        .is_some_and(|init| is_trybuild_constructor(&init.expr))
                    {
                        constructors.insert(binding.ident.to_string());
                    } else {
                        constructors.remove(&binding.ident.to_string());
                    }
                }
            }
            syn::Stmt::Expr(expression, _) if !expr_statically_disabled(expression, context) => {
                collect_trybuild_expr_calls(expression, &constructors, calls, context);
            }
            // Nested items are declarations, not proof that their bodies execute in this test.
            syn::Stmt::Item(_)
            | syn::Stmt::Macro(_)
            | syn::Stmt::Local(_)
            | syn::Stmt::Expr(_, _) => {}
        }
    }
}

fn collect_trybuild_expr_calls(
    expression: &syn::Expr,
    constructors: &BTreeSet<String>,
    calls: &mut Vec<TrybuildCall>,
    context: &TestCfgContext,
) {
    struct LiveCalls<'a> {
        constructors: &'a BTreeSet<String>,
        calls: &'a mut Vec<TrybuildCall>,
        context: &'a TestCfgContext,
    }
    impl<'ast> Visit<'ast> for LiveCalls<'_> {
        fn visit_block(&mut self, block: &'ast syn::Block) {
            walk_trybuild_block(block, self.constructors.clone(), self.calls, self.context);
        }

        fn visit_item_fn(&mut self, _function: &'ast syn::ItemFn) {}

        fn visit_expr_closure(&mut self, _closure: &'ast syn::ExprClosure) {}

        fn visit_expr_async(&mut self, _async_block: &'ast syn::ExprAsync) {}

        fn visit_expr_const(&mut self, _const_block: &'ast syn::ExprConst) {}

        fn visit_expr_block(&mut self, block: &'ast syn::ExprBlock) {
            if attrs_prove_test_execution(&block.attrs, self.context) {
                walk_trybuild_block(
                    &block.block,
                    self.constructors.clone(),
                    self.calls,
                    self.context,
                );
            }
        }

        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if !attrs_prove_test_execution(&call.attrs, self.context) {
                return;
            }
            let receiver_is_cases = is_trybuild_constructor(&call.receiver)
                || matches!(call.receiver.as_ref(), syn::Expr::Path(path)
                    if path.path.get_ident().is_some_and(|ident| self.constructors.contains(&ident.to_string())));
            let kind = match call.method.to_string().as_str() {
                "compile_fail" => Some(TrybuildKind::CompileFail),
                "pass" => Some(TrybuildKind::Pass),
                _ => None,
            };
            if receiver_is_cases
                && let Some(kind) = kind
                && let Some(syn::Expr::Lit(argument)) = call.args.first()
                && let syn::Lit::Str(pattern) = &argument.lit
            {
                self.calls.push(TrybuildCall {
                    kind,
                    pattern: pattern.value(),
                });
            }
            syn::visit::visit_expr_method_call(self, call);
        }
    }
    if expr_statically_disabled(expression, context) {
        return;
    }
    let mut visitor = LiveCalls {
        constructors,
        calls,
        context,
    };
    visitor.visit_expr(expression);
}

fn expr_statically_disabled(expression: &syn::Expr, context: &TestCfgContext) -> bool {
    let attrs = match expression {
        syn::Expr::Array(expr) => &expr.attrs,
        syn::Expr::Assign(expr) => &expr.attrs,
        syn::Expr::Async(expr) => &expr.attrs,
        syn::Expr::Await(expr) => &expr.attrs,
        syn::Expr::Binary(expr) => &expr.attrs,
        syn::Expr::Block(expr) => &expr.attrs,
        syn::Expr::Break(expr) => &expr.attrs,
        syn::Expr::Call(expr) => &expr.attrs,
        syn::Expr::Cast(expr) => &expr.attrs,
        syn::Expr::Closure(expr) => &expr.attrs,
        syn::Expr::Const(expr) => &expr.attrs,
        syn::Expr::Continue(expr) => &expr.attrs,
        syn::Expr::Field(expr) => &expr.attrs,
        syn::Expr::ForLoop(expr) => &expr.attrs,
        syn::Expr::Group(expr) => &expr.attrs,
        syn::Expr::If(expr) => &expr.attrs,
        syn::Expr::Index(expr) => &expr.attrs,
        syn::Expr::Infer(expr) => &expr.attrs,
        syn::Expr::Let(expr) => &expr.attrs,
        syn::Expr::Lit(expr) => &expr.attrs,
        syn::Expr::Loop(expr) => &expr.attrs,
        syn::Expr::Macro(expr) => &expr.attrs,
        syn::Expr::Match(expr) => &expr.attrs,
        syn::Expr::MethodCall(expr) => &expr.attrs,
        syn::Expr::Paren(expr) => &expr.attrs,
        syn::Expr::Path(expr) => &expr.attrs,
        syn::Expr::Range(expr) => &expr.attrs,
        syn::Expr::RawAddr(expr) => &expr.attrs,
        syn::Expr::Reference(expr) => &expr.attrs,
        syn::Expr::Repeat(expr) => &expr.attrs,
        syn::Expr::Return(expr) => &expr.attrs,
        syn::Expr::Struct(expr) => &expr.attrs,
        syn::Expr::Try(expr) => &expr.attrs,
        syn::Expr::TryBlock(expr) => &expr.attrs,
        syn::Expr::Tuple(expr) => &expr.attrs,
        syn::Expr::Unary(expr) => &expr.attrs,
        syn::Expr::Unsafe(expr) => &expr.attrs,
        syn::Expr::Verbatim(_) => return false,
        syn::Expr::While(expr) => &expr.attrs,
        syn::Expr::Yield(expr) => &expr.attrs,
        _ => return false,
    };
    !attrs_prove_test_execution(attrs, context)
}

fn is_trybuild_constructor(expression: &syn::Expr) -> bool {
    let syn::Expr::Call(call) = expression else {
        return false;
    };
    let syn::Expr::Path(function) = call.func.as_ref() else {
        return false;
    };
    let segments = function
        .path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>();
    segments.ends_with(&[
        "trybuild".to_string(),
        "TestCases".to_string(),
        "new".to_string(),
    ])
}

fn cargo_test_target_roots(root: &Path, path: &Path) -> Result<BTreeSet<PathBuf>> {
    let Some(manifest) = nearest_package_manifest(root, path) else {
        return Ok(BTreeSet::new());
    };
    let crate_root = manifest.parent().unwrap_or(root);
    let value = parse_toml(&manifest)?;
    let mut targets = BTreeSet::new();
    if let Some(explicit) = value.get("test").and_then(toml::Value::as_array) {
        for target in explicit {
            if let Some(target_path) = explicit_target_path(crate_root, "test", target) {
                targets.insert(target_path);
            }
        }
    }
    let automatic = value
        .get("package")
        .and_then(|package| package.get("autotests"))
        .and_then(toml::Value::as_bool)
        .unwrap_or(true);
    let tests = crate_root.join("tests");
    if automatic && tests.is_dir() {
        for entry in fs::read_dir(tests)? {
            let candidate = entry?.path();
            if candidate.extension().and_then(|ext| ext.to_str()) == Some("rs") {
                targets.insert(candidate);
            } else if candidate.is_dir() && candidate.join("main.rs").is_file() {
                targets.insert(candidate.join("main.rs"));
            }
        }
    }
    targets.retain(|target| target.is_file());
    Ok(targets)
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
        .map(|value| {
            value
                .get("path")
                .and_then(toml::Value::as_str)
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("__invalid_dylint_library__"))
        })
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
        .map(|value| {
            value
                .as_str()
                .map(|member| PathBuf::from("lints").join(member))
                .unwrap_or_else(|| PathBuf::from("__invalid_dylint_member__"))
        })
        .collect())
}

fn parse_toml(path: &Path) -> Result<toml::Value> {
    fs::read_to_string(path)
        .with_context(|| format!("读取 TOML `{}`", path.display()))?
        .parse::<toml::Value>()
        .with_context(|| format!("解析 TOML `{}`", path.display()))
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
    fn application_delivery_boundary_rejects_synthetic_red() {
        let cases = [
            ("deploy/helm/rss/Chart.yaml", "apiVersion: v2"),
            ("deploy/generated/runtime.json", "{}"),
            (".specify/feature.json", "{}"),
            ("crates/demo/src/lib.rs", "struct DeploymentPlan;"),
            ("hack/check.sh", "cargo xtask deployment-plan"),
            ("hack/check.sh", "cargo xtask deployment-policy"),
            ("hack/check.sh", "cargo xtask runtime-deployment-spec"),
            (".github/actions/setup/action.yml", "--backend download"),
            (".github/actions/setup/action.yml", "install-download"),
            (".github/actions/setup/action.yml", ".download/bin"),
            ("hack/check.sh", "helm template"),
            ("hack/check.sh", "kubeconform -strict"),
        ];
        for (path, source) in cases {
            let findings = application_delivery_records_findings(&[(
                path.to_owned(),
                Some(source.to_owned()),
            )]);
            assert!(
                findings
                    .iter()
                    .any(|finding| { finding.rule == Rule::ApplicationDeliveryResidual }),
                "synthetic residual escaped: {path} => {source}"
            );
        }
        assert!(
            application_delivery_records_findings(&[(
                "generated/tests/runtime_inventory.rs".to_owned(),
                Some("deploymentFingerprint buildIdentity".to_owned()),
            )])
            .is_empty()
        );
    }

    #[test]
    fn application_delivery_content_scope_excludes_prose_and_keeps_executable_carriers() {
        let findings_for = |path: &str, source: &str| {
            application_delivery_records_findings(&[(
                path.to_owned(),
                scans_application_delivery_content(path).then(|| source.to_owned()),
            )])
        };

        for path in ["README.md", "docs/architecture/delivery-notes.md"] {
            assert!(
                findings_for(path, "Helm DeploymentPlan deploymentFingerprint").is_empty(),
                "human prose must not become a blocking carrier: {path}"
            );
        }
        for (path, source) in [
            ("crates/demo/src/lib.rs", "struct DeploymentPlan;"),
            ("hack/check.sh", "helm template deploy/helm/rss"),
            (".github/workflows/ci.yml", "run: kubeconform -strict"),
        ] {
            assert!(
                findings_for(path, source)
                    .iter()
                    .any(|finding| finding.rule == Rule::ApplicationDeliveryResidual),
                "executable delivery residual escaped: {path}"
            );
        }

        assert!(
            findings_for(
                "crates/runtimeexec/src/inventory.rs",
                "BuildIdentity buildIdentity RSS_BUILD_SOURCE_SHA RSS_BUILD_IMAGE_DIGEST \
                 BuildMetadata buildMetadata RSS_BUILD_SOURCE_REVISION \
                 RSS_DECLARED_IMAGE_DIGEST"
            )
            .is_empty(),
            "provider-independent build metadata is an application-owned carrier"
        );
    }

    #[test]
    fn application_delivery_boundary_accepts_real_workspace() -> Result<()> {
        let root = workspace_root()?;
        let findings = application_delivery_boundary_findings(&root)?;
        assert!(findings.is_empty(), "{findings:?}");
        Ok(())
    }

    #[test]
    fn invariant_parser_extracts_multiple_ids_and_flags_bad_uppercase() -> Result<()> {
        let root = unique_tmp("archrules-ids");
        let file = root.join("xtask/src/demo.rs");
        write(
            &file,
            "//! INVARIANT: FOO-BAR-01 · BAZ-QUX-02 / BAD-ID-1 { level = \"Medium\", exec = \"check\", source = \"code\" }\n",
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
            "//! INVARIANT: LAYER-DEPS-ROUTE-FUNNEL-01，ADR-009 { level = \"Medium\", exec = \"check\", source = \"code\" }\n",
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
            "//! 上游类型系统保证（INVARIANT: REF-ONLY-01 { level = \"Medium\", exec = \"check\", source = \"dylint\" }`crates/demo/src/lib.rs`）。\n",
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
        scan_invariant_file(&root, &mut index, &file, "xtask", "demo", Some("check"))?;
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
            "//! INVARIANT: DEMO-BAD-01 { level = \"Soft\", exec = \"check\", source = \"code\" }\n",
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
        scan_invariant_file(&root, &mut index, &file, "xtask", "demo", Some("check"))?;
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
    fn invariant_parser_preserves_facet_and_codegen_hard_proof() -> Result<()> {
        let metadata = parse_metadata(
            r#"level = "Hard", exec = "check", source = "codegen", facet = "producer", golden = "generated/src/event/mod.rs", synthetic_red = "codegen::tests::event_red", anti_vacuity = "codegen::tests::event_green""#,
        )
        .map_err(anyhow::Error::msg)?;
        assert_eq!(metadata.facet.as_deref(), Some("producer"));
        assert_eq!(
            metadata.golden.as_deref(),
            Some("generated/src/event/mod.rs")
        );
        assert_eq!(
            metadata.synthetic_red.as_deref(),
            Some("codegen::tests::event_red")
        );
        assert_eq!(
            metadata.anti_vacuity.as_deref(),
            Some("codegen::tests::event_green")
        );
        Ok(())
    }

    #[test]
    fn codegen_hard_requires_committed_complete_proof() -> Result<()> {
        let root = unique_tmp("archrules-codegen-hard-proof");
        let file = root.join("xtask/src/demo.rs");
        write(
            &file,
            "//! INVARIANT: DEMO-CODEGEN-01 { level = \"Hard\", exec = \"check\", source = \"codegen\", facet = \"wire\", golden = \"generated/demo.rs\", synthetic_red = \"tests::red\", anti_vacuity = \"tests::green\" }\n",
        )?;
        write(&root.join("generated/demo.rs"), "// golden\n")?;
        let mut index = Index::default();
        scan_invariant_file(&root, &mut index, &file, "xtask", "demo", Some("check"))?;
        assert!(
            !index
                .findings
                .iter()
                .any(|finding| finding.rule == Rule::MissingCodegenHardProof),
            "{:?}",
            index.findings
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn conflicting_same_file_id_facet_is_rejected() {
        let record = |level| RuleRecord {
            id: "DEMO-CONFLICT-01".to_string(),
            facet: Some("wire".to_string()),
            level,
            exec: ExecutionLevel::Profile(crate::execution_profiles::ExecutionProfile::Check),
            source_kind: SourceKind::Code,
            carrier: "xtask".to_string(),
            source: "xtask/src/demo.rs:1".to_string(),
            evidence: "test".to_string(),
            gate: "check".to_string(),
            status: "ok".to_string(),
            native: None,
            golden: None,
            synthetic_red: None,
            anti_vacuity: None,
        };
        let mut index = Index {
            records: vec![record(RuleLevel::Medium), record(RuleLevel::Hard)],
            findings: Vec::new(),
            test_evidence: TestEvidenceIndex::default(),
        };
        reject_conflicting_facets(&mut index);
        assert!(
            index
                .findings
                .iter()
                .any(|finding| finding.rule == Rule::ConflictingInvariantFacet)
        );
    }

    #[test]
    fn invariant_parser_rejects_exec_without_matching_gate() -> Result<()> {
        let root = unique_tmp("archrules-exec-binding");
        let file = root.join("xtask/src/demo.rs");
        write(
            &file,
            "//! INVARIANT: DEMO-CI-01 { level = \"Medium\", exec = \"release-check\", source = \"code\" }\n",
        )?;
        let mut index = Index::default();
        scan_invariant_file(&root, &mut index, &file, "xtask", "demo", Some("check"))?;
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
            "//! INVARIANT: DEMO-HARD-01 { level = \"Hard\", exec = \"check\", source = \"code\" }\n",
        )?;
        let mut index = Index::default();
        scan_invariant_file(&root, &mut index, &file, "xtask", "demo", Some("check"))?;
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
        scan_invariant_file(&root, &mut index, &file, "xtask", "demo", Some("check"))?;
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
        scan_source_invariant_file(&root, &mut index, &file, "native-hard", "source")?;
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
            "//! INVARIANT: DEMO-LINT-01 { level = \"Medium\", exec = \"check\", source = \"dylint\" }\n",
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
    fn source_invariants_ignore_prose_future_markers() -> Result<()> {
        let root = unique_tmp("archrules-source-future");
        let file = root.join("assemblies/runtime/src/module.rs");
        write(
            &file,
            "/// follow-up #1448，落地后再以 `INVARIANT: WIRING-DEPS-INFRA-ONLY-01` 收口。\npub fn carrier() {}\n",
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
            "/// INVARIANT: CRYPTO-CONST-TIME-01 { level = \"Medium\", exec = \"manual/opt-in\", source = \"code\" } —— 实现必须常数时间。\npub fn carrier() {}\n",
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
            "/// INVARIANT: CRYPTO-CONST-TIME-01 —— Medium 守卫随 crypto W 行为 PR 落地。\npub fn carrier() {}\n",
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
            "/// INVARIANT: CRYPTO-CONST-TIME-01 { level = \"Medium\", exec = \"manual/opt-in\", source = \"code\" } —— Medium 守卫随 crypto W 行为 PR 落地。\npub fn carrier() {}\n",
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
    fn xtask_gate_membership_is_derived_from_the_canonical_gate_catalog() -> Result<()> {
        let root = crate::workspace_root()?;
        let mut seen = BTreeSet::new();
        for gate in crate::ci_lanes::GateId::ALL {
            let Some(carrier) = gate.carrier_file() else {
                continue;
            };
            let membership = xtask_gate(&root, &root.join(carrier))?
                .with_context(|| format!("missing typed carrier membership for {carrier}"))?;
            assert!(
                gate_has(Some(&membership), gate.spec().primary_owner().as_str()),
                "{carrier} must project {}: {membership}",
                gate.spec().primary_owner()
            );
            seen.insert(carrier);
        }
        assert!(
            !seen.is_empty(),
            "canonical gate carrier projection is vacuous"
        );
        Ok(())
    }

    #[test]
    fn source_test_membership_is_path_independent() -> Result<()> {
        let root = unique_tmp("archrules-source-membership-path-independent");
        write(
            &root.join("crates/demo/Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
        )?;
        write(&root.join("crates/demo/src/lib.rs"), "mod guard;\n")?;
        let source = "//! INVARIANT: DEMO-TEST-01 { level = \"Medium\", exec = \"test\", source = \"code\", synthetic_red = \"tests::red\", anti_vacuity = \"tests::green\" }\n#[cfg(test)] mod tests { #[test] fn red() { assert!(true); } #[test] fn green() { assert!(true); } }\n";
        let src = root.join("crates/demo/src/guard.rs");
        let tests = root.join("crates/demo/tests/guard.rs");
        write(&src, source)?;
        write(&tests, source)?;
        let mut src_index = Index::default();
        scan_source_invariant_file(
            &root,
            &mut src_index,
            &src,
            "native-hard",
            "source invariant",
        )?;
        let mut test_index = Index::default();
        scan_source_invariant_file(
            &root,
            &mut test_index,
            &tests,
            "native-hard",
            "source invariant",
        )?;
        let src_membership = &src_index.records[0].gate;
        let test_membership = &test_index.records[0].gate;
        assert_eq!(src_membership, test_membership);
        assert!(gate_has(Some(src_membership), "test"));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn cfg_test_in_src_binds_test_profile_without_a_path_exception() -> Result<()> {
        let root = unique_tmp("archrules-cfg-test-profile");
        write(
            &root.join("adapters/demo/Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
        )?;
        write(&root.join("adapters/demo/src/lib.rs"), "mod conn_events;\n")?;
        let file = root.join("adapters/demo/src/conn_events.rs");
        write(
            &file,
            "//! INVARIANT: EVENTTRANSPORT-CRED-REDACT-01 { level = \"Medium\", exec = \"test\", source = \"code\", synthetic_red = \"cred_redact_tests::red\", anti_vacuity = \"cred_redact_tests::green\" }\n#[cfg(test)] mod cred_redact_tests { #[test] fn red() { assert!(true); } #[test] fn green() { assert!(true); } }\n",
        )?;
        let mut index = Index::default();
        scan_source_invariant_file(&root, &mut index, &file, "native-hard", "source invariant")?;
        assert!(index.findings.is_empty(), "{:?}", index.findings);
        assert!(index.records.iter().any(|record| {
            record.id == "EVENTTRANSPORT-CRED-REDACT-01"
                && record.exec
                    == ExecutionLevel::Profile(crate::execution_profiles::ExecutionProfile::Test)
        }));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn orphan_rust_file_cannot_claim_test_profile() -> Result<()> {
        let root = unique_tmp("archrules-orphan-source");
        write(
            &root.join("crates/demo/Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
        )?;
        write(&root.join("crates/demo/src/lib.rs"), "pub fn live() {}\n")?;
        let orphan = root.join("crates/demo/src/orphan.rs");
        write(
            &orphan,
            "//! INVARIANT: ORPHAN-TEST-01 { level = \"Medium\", exec = \"test\", source = \"code\", synthetic_red = \"tests::red\", anti_vacuity = \"tests::green\" }\n#[cfg(test)] mod tests { #[test] fn red() { assert!(true); } #[test] fn green() { assert!(true); } }\n",
        )?;
        let mut index = Index::default();
        scan_source_invariant_file(&root, &mut index, &orphan, "native-hard", "source")?;
        assert!(
            index
                .findings
                .iter()
                .any(|finding| finding.rule == Rule::CarrierBindingMismatch),
            "orphan source claimed executable test evidence: {:?}",
            index.findings
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn cfg_unreachable_and_module_mismatched_test_symbols_fail_closed() -> Result<()> {
        let root = unique_tmp("archrules-test-symbol-identity");
        let file = root.join("crates/demo/tests/identity.rs");
        write(
            &root.join("crates/demo/Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
        )?;
        write(
            &file,
            "#[cfg(any())] #[test] fn unreachable() { assert!(true); }\nmod first { #[test] fn same() { assert!(true); } }\nmod second { #[test] fn same() { assert!(true); } }\n",
        )?;
        assert_eq!(
            collect_test_names(&file)?,
            ["first::same".to_string(), "second::same".to_string()]
        );
        let record = RuleRecord {
            id: "IDENTITY-TEST-01".to_string(),
            facet: None,
            level: RuleLevel::Medium,
            exec: ExecutionLevel::Profile(crate::execution_profiles::ExecutionProfile::Test),
            source_kind: SourceKind::Code,
            carrier: "native-hard".to_string(),
            source: "crates/demo/tests/identity.rs:1".to_string(),
            evidence: "source".to_string(),
            gate: "test".to_string(),
            status: "ok".to_string(),
            native: None,
            golden: None,
            synthetic_red: None,
            anti_vacuity: None,
        };
        assert!(!record_source_has_test_symbol(&root, &record, "same")?);
        assert!(!record_source_has_test_symbol(
            &root,
            &record,
            "unreachable"
        )?);
        assert!(record_source_has_test_symbol(
            &root,
            &record,
            "first::same"
        )?);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn ignored_and_unproven_cfg_tests_are_not_executable_evidence() -> Result<()> {
        let root = unique_tmp("archrules-non-runnable-test-evidence");
        let file = root.join("crates/demo/tests/evidence.rs");
        write(
            &root.join("crates/demo/Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\
             [features]\ndefault = [\"enabled\"]\nenabled = []\n",
        )?;
        write(
            &file,
            &format!(
                "#[test] #[ignore] fn ignored() {{ assert!(true); }}\n\
                 #[test] #[cfg_attr(all(), ignore)] fn cfg_ignored() {{ assert!(true); }}\n\
                 #[cfg(feature = \"not-executed\")] #[test] fn feature_disabled() {{ assert!(true); }}\n\
                 #[cfg(unproven_runner_flag)] #[test] fn unknown_disabled() {{ assert!(true); }}\n\
                 #[cfg(feature = \"enabled\")] #[test] fn default_enabled() {{ assert!(true); }}\n\
                 #[cfg(target_os = \"definitely-not-a-target\")] #[test] fn target_disabled() {{ assert!(true); }}\n\
                 #[cfg(target_os = \"{}\")] #[test] fn target_enabled() {{ assert!(true); }}\n",
                std::env::consts::OS
            ),
        )?;
        assert_eq!(
            collect_test_names(&file)?,
            ["default_enabled".to_string(), "target_enabled".to_string()],
            "only default-feature and current-target runnable tests prove execution"
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn integration_critical_evidence_uses_only_the_declared_integration_feature() -> Result<()> {
        let root = unique_tmp("archrules-integration-critical-test-evidence");
        write(
            &root.join("crates/demo/Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\
             [features]\ndefault = []\nintegration = []\nnot-executed = []\n",
        )?;
        write(
            &root.join("crates/demo/src/lib.rs"),
            "#[cfg(all(test, feature = \"integration\"))] mod integration_tests;\n\
             #[cfg(all(test, feature = \"not-executed\"))] mod unowned_tests;\n",
        )?;
        let evidence = root.join("crates/demo/src/integration_tests.rs");
        write(
            &evidence,
            "#[test] fn red() { assert!(true); }\n#[test] fn green() { assert!(true); }\n",
        )?;
        write(
            &root.join("crates/demo/src/unowned_tests.rs"),
            "#[test] fn must_stay_invisible() { assert!(true); }\n",
        )?;
        let mut record = RuleRecord {
            id: "INTEGRATION-EVIDENCE-01".to_string(),
            facet: None,
            level: RuleLevel::Medium,
            exec: ExecutionLevel::Profile(
                crate::execution_profiles::ExecutionProfile::IntegrationCritical,
            ),
            source_kind: SourceKind::Code,
            carrier: "native-hard".to_string(),
            source: "crates/demo/src/integration_tests.rs:1".to_string(),
            evidence: "source".to_string(),
            gate: "test".to_string(),
            status: "ok".to_string(),
            native: None,
            golden: None,
            synthetic_red: None,
            anti_vacuity: None,
        };
        assert!(record_source_has_test_symbol(
            &root,
            &record,
            "integration_tests::red"
        )?);
        assert!(!record_source_has_test_symbol(
            &root,
            &record,
            "unowned_tests::must_stay_invisible"
        )?);

        record.exec = ExecutionLevel::Profile(crate::execution_profiles::ExecutionProfile::Test);
        assert!(!record_source_has_test_symbol(
            &root,
            &record,
            "integration_tests::red"
        )?);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn nested_constant_cfg_and_inline_external_modules_fail_closed() -> Result<()> {
        let root = unique_tmp("archrules-nested-cfg-inline-module");
        write(
            &root.join("crates/demo/Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
        )?;
        write(
            &root.join("crates/demo/src/lib.rs"),
            "mod outer { mod guard; }\n",
        )?;
        let guard = root.join("crates/demo/src/outer/guard.rs");
        write(
            &guard,
            "#[cfg(all(any(), feature = \"x\"))] #[test] fn dead_nested() { assert!(true); }\n#[cfg(not(all()))] #[test] fn dead_not_all() { assert!(true); }\n#[cfg(not(any()))] mod tests { #[test] fn live() { assert!(true); } }\n",
        )?;
        assert!(cargo_target_reaches(&root, &guard)?);
        assert_eq!(collect_test_names(&guard)?, ["tests::live".to_string()]);
        let record = RuleRecord {
            id: "INLINE-MODULE-01".to_string(),
            facet: None,
            level: RuleLevel::Medium,
            exec: ExecutionLevel::Profile(crate::execution_profiles::ExecutionProfile::Test),
            source_kind: SourceKind::Code,
            carrier: "native-hard".to_string(),
            source: "crates/demo/src/outer/guard.rs:1".to_string(),
            evidence: "source".to_string(),
            gate: "test".to_string(),
            status: "ok".to_string(),
            native: None,
            golden: None,
            synthetic_red: None,
            anti_vacuity: None,
        };
        assert!(record_source_has_test_symbol(
            &root,
            &record,
            "outer::guard::tests::live"
        )?);
        assert!(!record_source_has_test_symbol(
            &root,
            &record,
            "dead_nested"
        )?);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn path_attribute_uses_source_directory_and_inline_module_directory() -> Result<()> {
        let root = unique_tmp("archrules-path-attribute-resolution");
        write(
            &root.join("journeys/demo/Cargo.toml"),
            "[package]\nname = \"demo-journey\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
        )?;
        let journey = root.join("journeys/demo/tests/localtx_validation.rs");
        write(&journey, "#[path = \"../common/mod.rs\"] mod common;\n")?;
        let common = root.join("journeys/demo/common/mod.rs");
        write(
            &common,
            "#[cfg(test)] mod tests { #[test] fn live() { assert!(true); } }\n",
        )?;
        assert!(cargo_target_reaches(&root, &common)?);
        let journey_record = RuleRecord {
            id: "PATH-JOURNEY-01".to_string(),
            facet: None,
            level: RuleLevel::Medium,
            exec: ExecutionLevel::Profile(crate::execution_profiles::ExecutionProfile::Test),
            source_kind: SourceKind::Code,
            carrier: "native-hard".to_string(),
            source: "journeys/demo/common/mod.rs:1".to_string(),
            evidence: "source".to_string(),
            gate: "test".to_string(),
            status: "ok".to_string(),
            native: None,
            golden: None,
            synthetic_red: None,
            anti_vacuity: None,
        };
        assert!(record_source_has_test_symbol(
            &root,
            &journey_record,
            "common::tests::live"
        )?);

        write(
            &root.join("crates/inline/Cargo.toml"),
            "[package]\nname = \"inline\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
        )?;
        write(
            &root.join("crates/inline/src/lib.rs"),
            "mod outer { #[path = \"custom.rs\"] mod guard; }\n",
        )?;
        let inline = root.join("crates/inline/src/outer/custom.rs");
        write(&inline, "#[test] fn live() { assert!(true); }\n")?;
        assert!(cargo_target_reaches(&root, &inline)?);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn legacy_execution_tokens_are_rejected_without_aliases() {
        for legacy in ["verify", "ci-only", "integration"] {
            assert_eq!(ExecutionLevel::parse(legacy), None, "{legacy}");
        }
        for current in [
            "check",
            "test",
            "integration-critical",
            "release-check",
            "native-compile",
            "manual/opt-in",
        ] {
            assert!(ExecutionLevel::parse(current).is_some(), "{current}");
        }
    }

    #[test]
    fn unknown_xtask_invariant_is_missing_gate() -> Result<()> {
        let root = unique_tmp("archrules-unknown-xtask");
        let file = root.join("xtask/src/new_guard.rs");
        write(
            &file,
            "//! INVARIANT: NEW-GUARD-01 { level = \"Medium\", exec = \"check\", source = \"code\" }\n",
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
            &root.join("crates/demo/Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
        )?;
        write(
            &root.join("crates/demo/tests/trybuild.rs"),
            r#"
#[test]
fn ui() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/fail.rs");
    t.pass("tests/ui/pass.rs");
}
"#,
        )?;
        write(
            &root.join("crates/demo/tests/ui/fail.rs"),
            "//! INVARIANT: TRYBUILD-FAIL-01 { level = \"Hard\", exec = \"test\", source = \"trybuild\" }\n",
        )?;
        write(
            &root.join("crates/demo/tests/ui/pass.rs"),
            "//! INVARIANT: TRYBUILD-PASS-01 { level = \"Hard\", exec = \"test\", source = \"trybuild\" }\n",
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
    fn unreferenced_trybuild_fixture_is_not_executable_evidence() -> Result<()> {
        let root = unique_tmp("archrules-trybuild-unreferenced");
        write(
            &root.join("crates/demo/Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
        )?;
        write(
            &root.join("crates/demo/tests/trybuild.rs"),
            "#[test] fn ui() { let t = trybuild::TestCases::new(); t.pass(\"tests/ui/used.rs\"); }\n",
        )?;
        write(
            &root.join("crates/demo/tests/ui/used.rs"),
            "//! INVARIANT: TRYBUILD-USED-01 { level = \"Hard\", exec = \"test\", source = \"trybuild\" }\n",
        )?;
        write(
            &root.join("crates/demo/tests/ui/orphan.rs"),
            "//! INVARIANT: TRYBUILD-ORPHAN-01 { level = \"Hard\", exec = \"test\", source = \"trybuild\" }\n",
        )?;
        let fixtures = trybuild_fixtures(&root)?;
        assert!(
            fixtures
                .pass
                .contains(&root.join("crates/demo/tests/ui/used.rs"))
        );
        assert!(
            !fixtures
                .pass
                .contains(&root.join("crates/demo/tests/ui/orphan.rs"))
        );
        let mut index = Index::default();
        scan_source_invariants(&root, &mut index)?;
        assert!(
            index.findings.iter().any(|finding| {
                finding.rule == Rule::CarrierBindingMismatch
                    && finding.subject.contains("orphan.rs")
            }),
            "unreferenced fixture escaped closed membership: {:?}",
            index.findings
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn trybuild_harness_requires_live_test_ast_and_explicit_target_default_path() -> Result<()> {
        let root = unique_tmp("archrules-trybuild-harness-ast");
        write(
            &root.join("crates/demo/Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"0.0.0\"\nedition = \"2024\"\nautotests = false\n\n[[test]]\nname = \"trybuild\"\n",
        )?;
        let harness = root.join("crates/demo/tests/trybuild.rs");
        write(
            &harness,
            r##"
// #[test] fn bait() { trybuild::TestCases::new().pass("tests/ui/comment.rs"); }
const BAIT: &str = "trybuild::TestCases::new().pass(\"tests/ui/string.rs\")";
fn not_a_test() { trybuild::TestCases::new().pass("tests/ui/non_test.rs"); }
#[test]
#[ignore]
fn ignored() { trybuild::TestCases::new().pass("tests/ui/ignored.rs"); }
#[test]
#[cfg_attr(all(), ignore)]
fn cfg_ignored() { trybuild::TestCases::new().pass("tests/ui/cfg_ignored.rs"); }
#[cfg(feature = "not-executed")]
#[test]
fn feature_disabled() { trybuild::TestCases::new().pass("tests/ui/feature.rs"); }
#[cfg(all(any(), feature = "x"))]
#[test]
fn dead() { trybuild::TestCases::new().pass("tests/ui/dead.rs"); }
#[test]
fn live() {
    let cases = trybuild::TestCases::new();
    fn nested_bait() {
        trybuild::TestCases::new().pass("tests/ui/nested.rs");
    }
    #[cfg(any())]
    {
        cases.pass("tests/ui/dead_block.rs");
    }
    cases.pass("tests/ui/live.rs");
}
"##,
        )?;
        write(&root.join("crates/demo/tests/ui/live.rs"), "fn main() {}\n")?;
        assert!(cargo_test_target_roots(&root, &harness)?.contains(&harness));
        let calls = trybuild_calls(&harness)?;
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].pattern, "tests/ui/live.rs");
        let fixtures = trybuild_fixtures(&root)?;
        assert_eq!(fixtures.harnesses, BTreeSet::from([harness]));
        assert_eq!(
            fixtures.pass,
            BTreeSet::from([root.join("crates/demo/tests/ui/live.rs")])
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
            "# INVARIANT: DENY-DEMO-01 { level = \"Medium\", exec = \"check\", source = \"config\" }\n",
        )?;
        write(&root.join("clippy.toml"), "# synthetic clippy carrier\n")?;
        write(
            &root.join("xtask/runtime-deps-guard.toml"),
            "# INVARIANT: RUNTIME-DEPS-CONFIG-DEMO-01 { level = \"Medium\", exec = \"check\", source = \"config\" }\n",
        )?;
        write(
            &root.join("xtask/runtime-root-ratchet.toml"),
            "# INVARIANT: RUNTIME-ROOT-CONFIG-DEMO-01 { level = \"Medium\", exec = \"check\", source = \"config\" }\n",
        )?;
        write(
            &root.join("xtask/src/layerdeps.rs"),
            "//! INVARIANT: XTASK-DEMO-01 { level = \"Medium\", exec = \"check\", source = \"code\" }\n",
        )?;
        write(
            &root.join("xtask/src/publicapi.rs"),
            "//! INVARIANT: PUBLICAPI-DEMO-01 { level = \"Medium\", exec = \"release-check\", source = \"public-api\" }\n",
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
            "//! INVARIANT: LINT-DEMO-01 { level = \"Medium\", exec = \"check\", source = \"dylint\" }\n",
        )?;
        write(&root.join("lints/rss_demo/ui/main.rs"), "fn main() {}\n")?;
        write(&root.join("lints/rss_demo/ui/main.stderr"), "error\n")?;
        let index = build_index(&root)?;
        assert!(index.findings.is_empty(), "{:?}", index.findings);
        for id in [
            "DENY-DEMO-01",
            "LINT-DEMO-01",
            "PUBLICAPI-DEMO-01",
            "RUNTIME-DEPS-CONFIG-DEMO-01",
            "RUNTIME-ROOT-CONFIG-DEMO-01",
            "XTASK-DEMO-01",
        ] {
            assert!(index.records.iter().any(|r| r.id == id), "missing {id}");
        }
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn funnel_matrix_has_exact_source_issue_partition() -> Result<()> {
        let findings = validate_funnel_catalog(FUNNELS);
        assert!(findings.is_empty(), "{findings:?}");
        let issues = FUNNELS
            .iter()
            .flat_map(|funnel| funnel.source_issues.iter().copied())
            .collect::<Vec<_>>();
        assert_eq!(
            issues.iter().copied().collect::<BTreeSet<_>>(),
            expected_source_issues()
        );
        let pg_runtime = FUNNELS
            .iter()
            .find(|funnel| {
                funnel.source_issues
                    == [
                        ISSUE_PG_RUNTIME_CUTOVER,
                        ISSUE_PROVIDER_PLAN_OUTPUT_BIJECTION,
                    ]
            })
            .with_context(|| format!("#{ISSUE_PG_RUNTIME_CUTOVER} lifecycle funnel"))?;
        assert_eq!(
            pg_runtime.upstream,
            [
                invariant("PG-RUNTIME-OWNER-01"),
                invariant("PG-RUNTIME-HANDLE-02")
            ]
        );
        assert_eq!(
            pg_runtime.downstream,
            [
                invariant("PG-RUNTIME-OUTPUT-03"),
                invariant("RUNTIME-PROVIDER-BIJECTION-LIVE-01")
            ]
        );
        assert!(matches!(
            pg_runtime.residual,
            ResidualDisposition::AcceptedMedium { .. }
        ));
        let outbox_relay = FUNNELS
            .iter()
            .find(|funnel| {
                funnel.source_issues
                    == [
                        ISSUE_OUTBOX_CLAIM_CAPABILITY,
                        ISSUE_OUTBOX_CLAIM_RELAY_CUTOVER,
                    ]
            })
            .with_context(|| {
                format!(
                    "#{}/#{} claimed relay funnel",
                    ISSUE_OUTBOX_CLAIM_CAPABILITY, ISSUE_OUTBOX_CLAIM_RELAY_CUTOVER
                )
            })?;
        assert_eq!(
            outbox_relay.upstream,
            [invariant("OUTBOX-CLAIM-RELAY-CAPABILITY-01")]
        );
        assert_eq!(
            outbox_relay.downstream,
            [invariant("OUTBOX-RELAY-CLAIM-CUTOVER-01")]
        );
        assert!(matches!(
            outbox_relay.residual,
            ResidualDisposition::AcceptedMedium { .. }
        ));
        let event_output = FUNNELS
            .iter()
            .find(|funnel| funnel.source_issues == [ISSUE_EVENT_TRANSPORT_OUTPUT])
            .with_context(|| {
                format!("#{ISSUE_EVENT_TRANSPORT_OUTPUT} event transport output funnel")
            })?;
        assert_eq!(
            event_output.upstream,
            [invariant("EVENT-TRANSPORT-OUTPUT-TYPE-01")]
        );
        assert_eq!(
            event_output.downstream,
            [invariant("EVENT-TRANSPORT-OUTPUT-FUNNEL-01")]
        );
        assert!(
            FUNNELS
                .iter()
                .all(|funnel| !funnel.upstream.is_empty() && !funnel.downstream.is_empty())
        );
        Ok(())
    }

    #[test]
    fn funnel_catalog_rejects_equal_cardinality_wrong_id_duplicate_missing_extra_and_key_drift()
    -> Result<()> {
        let base = FUNNELS.to_vec();
        let single_issue_index = base
            .iter()
            .position(|funnel| funnel.source_issues == [1437])
            .context("fixture needs one stable single-issue funnel")?;

        let mut equal_cardinality_wrong_id = base.clone();
        equal_cardinality_wrong_id[single_issue_index].source_issues = &[999_999];
        let findings = validate_funnel_catalog(&equal_cardinality_wrong_id);
        assert!(findings.iter().any(|finding| {
            finding.subject == "source issues"
                && finding.detail.contains("missing=[1437]")
                && finding.detail.contains("extra=[999999]")
        }));

        let mut duplicate_issue = base.clone();
        duplicate_issue[single_issue_index].source_issues = &[1437, 1437];
        let findings = validate_funnel_catalog(&duplicate_issue);
        assert!(
            findings
                .iter()
                .any(|finding| finding.detail == "来源 issue #1437 重复归属")
        );

        let mut missing_issue = base.clone();
        missing_issue[single_issue_index].source_issues = &[];
        let findings = validate_funnel_catalog(&missing_issue);
        assert!(findings.iter().any(|finding| {
            finding.subject == "source issues"
                && finding.detail.contains("missing=[1437]")
                && finding.detail.contains("extra=[]")
        }));

        let mut extra_issue = base.clone();
        extra_issue[single_issue_index].source_issues = &[1437, 999_999];
        let findings = validate_funnel_catalog(&extra_issue);
        assert!(findings.iter().any(|finding| {
            finding.subject == "source issues"
                && finding.detail.contains("missing=[]")
                && finding.detail.contains("extra=[999999]")
        }));

        let mut duplicate_key = base;
        duplicate_key[1].key = duplicate_key[0].key;
        let findings = validate_funnel_catalog(&duplicate_key);
        assert!(findings.iter().any(|finding| {
            finding.subject == duplicate_key[0].key && finding.detail == "funnel key 重复"
        }));
        Ok(())
    }

    #[test]
    fn funnel_matrix_configuration_is_single_source() {
        let source = include_str!("archrules.rs");
        for scattered in [
            ["EXPECTED_FUNNEL", "_COUNT"].concat(),
            format!("({FUNNEL_ISSUE_RANGE_START}_u32..={FUNNEL_ISSUE_RANGE_END})"),
            format!("expected.extend({EXTRA_FUNNEL_ISSUES:?})"),
            ["EXTRA_FUNNEL_ISSUES", "["].concat(),
        ] {
            assert!(
                !source.contains(&scattered),
                "matrix configuration remains duplicated: {scattered}"
            );
        }
    }

    #[test]
    fn real_workspace_archrules_and_derived_matrix_pass() -> Result<()> {
        let (summary, findings) = ArchRules.check()?;
        assert!(findings.is_empty(), "{findings:?}");
        assert!(
            summary.contains(&format!("{} 行持久化 funnel", FUNNELS.len())),
            "{summary}"
        );
        matrix(MatrixAction::Check)?;
        Ok(())
    }

    #[test]
    fn ast_evidence_rejects_comment_string_and_empty_test_spoofs() -> Result<()> {
        let root = unique_tmp("archrules-matrix-evidence-spoof");
        let file = root.join("spoof.rs");
        write(
            &file,
            r##"
// #[test] fn red_rejected() { panic!() }
const BAIT: &str = "#[test] fn green_accepted() {}";
#[test]
fn empty_red_rejected() {}
#[test]
fn real_red_rejected() { assert!(true); }
#[test]
fn real_green_accepted() { assert!(true); }
"##,
        )?;
        let tests = collect_test_names(&file)?;
        assert_eq!(
            tests,
            vec![
                "real_green_accepted".to_string(),
                "real_red_rejected".to_string()
            ]
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn medium_evidence_must_be_explicitly_bound_to_its_invariant() -> Result<()> {
        let root = unique_tmp("archrules-medium-evidence-binding");
        write(
            &root.join("xtask/Cargo.toml"),
            "[package]\nname = \"xtask-demo\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
        )?;
        write(&root.join("xtask/src/main.rs"), "mod demo;\n")?;
        write(
            &root.join("xtask/src/demo.rs"),
            r#"
mod tests {
#[test]
fn unrelated_red_rejected() { assert!(true); }
#[test]
fn unrelated_green_accepted() { assert!(true); }
}
"#,
        )?;
        let mut record = RuleRecord {
            id: "DEMO-MEDIUM-01".to_string(),
            facet: None,
            level: RuleLevel::Medium,
            exec: ExecutionLevel::Profile(crate::execution_profiles::ExecutionProfile::Check),
            source_kind: SourceKind::Code,
            carrier: "xtask".to_string(),
            source: "xtask/src/demo.rs:1".to_string(),
            evidence: "xtask module demo.rs".to_string(),
            gate: "check".to_string(),
            status: "ok".to_string(),
            native: None,
            golden: None,
            synthetic_red: None,
            anti_vacuity: None,
        };
        let mut findings = Vec::new();
        let mut test_evidence = TestEvidenceIndex::build(&root, std::slice::from_ref(&record))?;
        validate_medium_evidence(&root, &test_evidence, "demo", &record, &mut findings)?;
        assert_eq!(
            findings.len(),
            1,
            "同文件无关 red/green 测试不能替代 invariant 自己声明的证据"
        );
        record.synthetic_red = Some("tests::unrelated_red_rejected".to_string());
        record.anti_vacuity = Some("tests::unrelated_green_accepted".to_string());
        test_evidence = TestEvidenceIndex::build(&root, std::slice::from_ref(&record))?;
        findings.clear();
        validate_medium_evidence(&root, &test_evidence, "demo", &record, &mut findings)?;
        assert!(
            findings.is_empty(),
            "显式绑定的真实测试应通过: {findings:?}"
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn test_evidence_index_parses_each_source_once_for_all_symbol_queries() -> Result<()> {
        let root = unique_tmp("archrules-test-evidence-cache");
        write(
            &root.join("xtask/Cargo.toml"),
            "[package]\nname = \"xtask-demo\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
        )?;
        write(&root.join("xtask/src/main.rs"), "mod demo;\n")?;
        let source = root.join("xtask/src/demo.rs");
        write(
            &source,
            "#[cfg(test)] mod tests { #[test] fn red() { assert!(true); } #[test] fn green() { assert!(true); } }\n",
        )?;
        let record = RuleRecord {
            id: "DEMO-CACHE-01".to_string(),
            facet: None,
            level: RuleLevel::Medium,
            exec: ExecutionLevel::Profile(crate::execution_profiles::ExecutionProfile::Check),
            source_kind: SourceKind::Code,
            carrier: "xtask".to_string(),
            source: "xtask/src/demo.rs:1".to_string(),
            evidence: "source".to_string(),
            gate: "check".to_string(),
            status: "ok".to_string(),
            native: None,
            golden: None,
            synthetic_red: Some("demo::tests::red".to_string()),
            anti_vacuity: Some("demo::tests::green".to_string()),
        };
        let mut second = record.clone();
        second.id = "DEMO-CACHE-02".to_string();
        let evidence = TestEvidenceIndex::build(&root, &[record.clone(), second])?;
        assert_eq!(
            evidence.parse_count(&source),
            1,
            "one build must parse a shared evidence source exactly once"
        );
        assert!(evidence.contains(&root, &record, "demo::tests::red"));
        assert!(evidence.contains(&root, &record, "demo::tests::green"));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn ci_lane_invariants_use_record_granular_carriers() -> Result<()> {
        let index = build_index(&crate::workspace_root()?)?;
        let Some(registry) = index.records.iter().find(|record| {
            record.id == "CI-LANE-REGISTRY-01" && record.source.contains("ci_lanes.rs")
        }) else {
            bail!("missing CI-LANE-REGISTRY-01")
        };
        assert_eq!(registry.carrier, "native-hard");
        assert_eq!(registry.gate, "native-compile");

        let Some(plan) = index
            .records
            .iter()
            .find(|record| record.id == "CI-LANE-PLAN-01" && record.source.contains("ci_lanes.rs"))
        else {
            bail!("missing CI-LANE-PLAN-01")
        };
        assert_eq!(plan.carrier, "xtask");
        assert_eq!(plan.gate, "check");

        let source = crate::workspace_root()?.join("xtask/src/ci_lanes.rs");
        let found = extract_invariants(&crate::workspace_root()?, &source)?;
        let Some(plan_rule) = found
            .iter()
            .flat_map(|invariant| &invariant.rules)
            .find(|rule| rule.id == "CI-LANE-PLAN-01")
        else {
            bail!("missing CI-LANE-PLAN-01 source declaration")
        };
        let invalid = InvariantCarrierBinding {
            carrier: "native-hard",
            ..CI_LANE_INVARIANT_BINDINGS[1]
        };
        assert!(invalid.matches(plan_rule));
        assert!(
            !invalid.accepts(plan_rule),
            "Medium synthetic-red invariant must not masquerade as native-hard"
        );
        let invalid_bindings = [CI_LANE_INVARIANT_BINDINGS[0], invalid];
        let mut invalid_index = Index::default();
        validate_closed_invariant_bindings(&mut invalid_index, &source, &found, &invalid_bindings);
        assert!(invalid_index.findings.iter().any(|finding| {
            finding.rule == Rule::CarrierBindingMismatch
                && finding.detail.contains("metadata 不兼容")
        }));
        Ok(())
    }

    #[test]
    fn compiler_cache_invariants_use_record_granular_carriers() -> Result<()> {
        let index = build_index(&crate::workspace_root()?)?;
        let policy = index
            .records
            .iter()
            .find(|record| record.id == "COMPILER-CACHE-POLICY-01")
            .context("missing COMPILER-CACHE-POLICY-01")?;
        assert_eq!(policy.level, RuleLevel::Hard);
        assert_eq!(policy.carrier, "native-hard");
        assert_eq!(policy.gate, "native-compile");

        let validation = index
            .records
            .iter()
            .find(|record| record.id == "COMPILER-CACHE-POLICY-02")
            .context("missing COMPILER-CACHE-POLICY-02")?;
        assert_eq!(validation.level, RuleLevel::Medium);
        assert_eq!(validation.carrier, "xtask");
        assert_eq!(validation.gate, "manual/opt-in");
        assert_eq!(
            validation.synthetic_red.as_deref(),
            Some("compiler_cache_validates_canonical_absolute_exact_version")
        );
        assert_eq!(
            validation.anti_vacuity.as_deref(),
            Some("enabled_policy_overrides_ambient_wrapper_and_incremental")
        );
        Ok(())
    }

    #[test]
    fn ci_slo_config_schema_uses_runtime_validation_carrier() -> Result<()> {
        let index = build_index(&crate::workspace_root()?)?;
        let config = index
            .records
            .iter()
            .find(|record| {
                record.id == "CI-SLO-CONFIG-SCHEMA-01" && record.source.contains("ci_slo.rs")
            })
            .context("missing CI-SLO-CONFIG-SCHEMA-01")?;
        assert_eq!(config.level, RuleLevel::Medium);
        assert_eq!(config.carrier, "xtask");
        assert_eq!(config.gate, "check");
        assert_eq!(
            config.synthetic_red.as_deref(),
            Some("config_rejects_schema_drift_and_incomplete_catalog")
        );
        assert_eq!(
            config.anti_vacuity.as_deref(),
            Some("ci_slo_config_is_complete_and_has_expected_limits")
        );
        Ok(())
    }

    #[test]
    fn ci_lane_invariant_binding_rejects_unregistered_source_record_red() -> Result<()> {
        let root = unique_tmp("archrules-ci-lane-binding-closed-set");
        let fixture = [
            "//! INVAR",
            "IANT: CI-LANE-REGISTRY-01 { level = \"Hard\", exec = \"native-compile\", source = \"code\", native = \"closed enum\" }\n",
            "//! INVAR",
            "IANT: CI-LANE-PLAN-01 { level = \"Medium\", exec = \"check\", source = \"code\" }\n",
            "//! INVAR",
            "IANT: CI-LANE-UNREGISTERED-01 { level = \"Medium\", exec = \"check\", source = \"code\" }\n",
        ]
        .concat();
        write(&root.join("xtask/src/ci_lanes.rs"), &fixture)?;
        let mut index = Index::default();
        scan_xtask(&root, &mut index)?;
        assert!(
            index
                .findings
                .iter()
                .any(|finding| finding.rule == Rule::MissingInvariant),
            "unregistered source invariant must fail closed: {:?}",
            index.findings
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn ci_lane_invariant_binding_closed_set_rejects_missing_duplicate_and_orphan_red() -> Result<()>
    {
        let root = unique_tmp("archrules-ci-lane-binding-drift");
        let path = root.join("xtask/src/ci_lanes.rs");
        let fixture = [
            "//! INVAR",
            "IANT: CI-LANE-REGISTRY-01 { level = \"Hard\", exec = \"native-compile\", source = \"code\", native = \"closed enum\" }\n",
            "//! INVAR",
            "IANT: CI-LANE-PLAN-01 { level = \"Medium\", exec = \"check\", source = \"code\" }\n",
        ]
        .concat();
        write(&path, &fixture)?;
        let found = extract_invariants(&root, &path)?;

        let mut missing = Index::default();
        validate_closed_invariant_bindings(
            &mut missing,
            &path,
            &found,
            &CI_LANE_INVARIANT_BINDINGS[..1],
        );
        assert!(missing.findings.iter().any(|finding| {
            finding.rule == Rule::MissingInvariant && finding.detail.contains("缺 carrier binding")
        }));

        let duplicate_bindings = [
            CI_LANE_INVARIANT_BINDINGS[0],
            CI_LANE_INVARIANT_BINDINGS[0],
            CI_LANE_INVARIANT_BINDINGS[1],
        ];
        let mut duplicate = Index::default();
        validate_closed_invariant_bindings(&mut duplicate, &path, &found, &duplicate_bindings);
        assert!(duplicate.findings.iter().any(|finding| {
            finding.rule == Rule::CarrierBindingMismatch && finding.detail.contains("重复 2 次")
        }));

        let orphan_binding = InvariantCarrierBinding {
            id: "CI-LANE-ORPHAN-01",
            ..CI_LANE_INVARIANT_BINDINGS[1]
        };
        let orphan_bindings = [
            CI_LANE_INVARIANT_BINDINGS[0],
            CI_LANE_INVARIANT_BINDINGS[1],
            orphan_binding,
        ];
        let mut orphan = Index::default();
        validate_closed_invariant_bindings(&mut orphan, &path, &found, &orphan_bindings);
        assert!(orphan.findings.iter().any(|finding| {
            finding.rule == Rule::MissingInvariant && finding.detail.contains("缺源码 invariant")
        }));

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn assembly_lock_binding_rejects_omission_and_wrong_carrier_red() -> Result<()> {
        let root = crate::workspace_root()?;
        let path = root.join("xtask/src/assembly_lock.rs");
        let found = extract_invariants(&root, &path)?;

        let omitted = ASSEMBLY_LOCK_INVARIANT_BINDINGS
            .iter()
            .copied()
            .filter(|binding| binding.id != "ASSEMBLY-LOCK-VERIFY-GATE-01")
            .collect::<Vec<_>>();
        let mut missing = Index::default();
        validate_closed_invariant_bindings(&mut missing, &path, &found, &omitted);
        assert!(missing.findings.iter().any(|finding| {
            finding.rule == Rule::MissingInvariant && finding.detail.contains("缺 carrier binding")
        }));

        let mut wrong = ASSEMBLY_LOCK_INVARIANT_BINDINGS.to_vec();
        wrong
            .iter_mut()
            .find(|binding| binding.id == "ASSEMBLY-LOCK-DIAGNOSTIC-01")
            .context("diagnostic binding missing")?
            .carrier = "xtask";
        let mut invalid = Index::default();
        for binding in wrong {
            scan_extracted_invariant_rules_filtered(
                &root,
                &mut invalid,
                &found,
                binding.carrier,
                binding.evidence,
                Some(binding.binding.token()),
                |rule| binding.matches(rule) && binding.accepts(rule),
            )?;
        }
        assert!(invalid.findings.iter().any(|finding| {
            finding.rule == Rule::CarrierBindingMismatch
                && finding.subject.contains("assembly_lock.rs")
                && finding.detail.contains("ASSEMBLY-LOCK-DIAGNOSTIC-01")
        }));
        Ok(())
    }

    #[test]
    fn l2_assurance_binding_rejects_omission_and_wrong_carrier_red() -> Result<()> {
        let root = crate::workspace_root()?;
        let path = root.join("xtask/src/l2_assurance.rs");
        let found = extract_invariants(&root, &path)?;

        let omitted = L2_ASSURANCE_INVARIANT_BINDINGS
            .iter()
            .copied()
            .filter(|binding| binding.id != "L2-ASSURANCE-PATH-01")
            .collect::<Vec<_>>();
        let mut missing = Index::default();
        validate_closed_invariant_bindings(&mut missing, &path, &found, &omitted);
        assert!(missing.findings.iter().any(|finding| {
            finding.rule == Rule::MissingInvariant && finding.detail.contains("缺 carrier binding")
        }));

        let mut wrong = L2_ASSURANCE_INVARIANT_BINDINGS.to_vec();
        wrong
            .iter_mut()
            .find(|binding| binding.id == "L2-ASSURANCE-TYPE-01")
            .context("L2 assurance type binding missing")?
            .carrier = "xtask";
        let mut invalid = Index::default();
        for binding in wrong {
            scan_extracted_invariant_rules_filtered(
                &root,
                &mut invalid,
                &found,
                binding.carrier,
                binding.evidence,
                Some(binding.binding.token()),
                |rule| binding.matches(rule) && binding.accepts(rule),
            )?;
        }
        assert!(invalid.findings.iter().any(|finding| {
            finding.rule == Rule::CarrierBindingMismatch
                && finding.subject.contains("l2_assurance.rs")
                && finding.detail.contains("L2-ASSURANCE-TYPE-01")
        }));
        Ok(())
    }

    #[test]
    fn producer_assurance_binding_rejects_omission_red() -> Result<()> {
        let root = crate::workspace_root()?;
        let path = root.join("xtask/src/producer_assurance.rs");
        let found = extract_invariants(&root, &path)?;
        let mut missing = Index::default();
        validate_closed_invariant_bindings(&mut missing, &path, &found, &[]);
        assert!(missing.findings.iter().any(|finding| {
            finding.rule == Rule::MissingInvariant
                && finding.detail.contains("L2-PRODUCER-EXECUTION-CLOSURE-01")
                && finding.detail.contains("缺 carrier binding")
        }));
        Ok(())
    }

    #[test]
    fn production_composition_binding_rejects_omission_red() -> Result<()> {
        let root = crate::workspace_root()?;
        let path = root.join("xtask/src/production_composition.rs");
        let found = extract_invariants(&root, &path)?;
        let mut missing = Index::default();
        validate_closed_invariant_bindings(&mut missing, &path, &found, &[]);
        assert!(missing.findings.iter().any(|finding| {
            finding.rule == Rule::MissingInvariant
                && finding
                    .detail
                    .contains("L2-PRODUCER-PRODUCTION-COMPOSITION-01")
                && finding.detail.contains("缺 carrier binding")
        }));
        Ok(())
    }

    #[test]
    fn codegen_hard_symbol_must_be_nonempty_real_ast_test() -> Result<()> {
        let root = unique_tmp("archrules-matrix-codegen-symbol");
        write(&root.join("generated/demo.rs"), "// committed golden\n")?;
        write(
            &root.join("xtask/src/demo.rs"),
            r##"
// #[test] fn fake_red() { panic!() }
const BAIT: &str = "#[test] fn fake_red() { panic!() }";
#[test]
fn real_green() { assert!(true); }
"##,
        )?;
        let record = RuleRecord {
            id: "DEMO-CODEGEN-01".to_string(),
            facet: Some("wire".to_string()),
            level: RuleLevel::Hard,
            exec: ExecutionLevel::Profile(crate::execution_profiles::ExecutionProfile::Check),
            source_kind: SourceKind::Codegen,
            carrier: "xtask".to_string(),
            source: "xtask/src/demo.rs:1".to_string(),
            evidence: "codegen".to_string(),
            gate: "check".to_string(),
            status: "ok".to_string(),
            native: None,
            golden: Some("generated/demo.rs".to_string()),
            synthetic_red: Some("demo::tests::fake_red".to_string()),
            anti_vacuity: Some("demo::tests::real_green".to_string()),
        };
        let mut findings = Vec::new();
        let test_evidence = TestEvidenceIndex::build(&root, std::slice::from_ref(&record))?;
        validate_hard_evidence(&root, &test_evidence, "demo", &record, &mut findings)?;
        assert_eq!(
            findings.len(),
            1,
            "comment/string symbol 不得充当 test 证明"
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
