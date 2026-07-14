//! ArchRules 派生索引：从真实 carrier 的 `INVARIANT:` 锚点反推出 rule → carrier → evidence → gate。
//!
//! INVARIANT: ARCHRULES-DERIVED-INDEX-01 { level = "Medium", exec = "verify", source = "code" } —— 本模块只扫描真实 carrier（代码 / 配置 / UI golden /
//! baseline），不引入手写规则目录；文档仅作为 `doc_ref`。
//! INVARIANT: ARCHRULES-VERIFY-GATE-01 { level = "Medium", exec = "verify", source = "code" } —— [`ArchRules`] 作为 no-compile governance gate 接入 verify/ci，
//! 缺 carrier / fixture / gate 证据时 fail-closed。
//! INVARIANT: PERSISTENCE-FUNNEL-MATRIX-01 { level = "Medium", exec = "verify", source = "code", facet = "derived-matrix" } —— 持久化 funnel 固定集合仅引用真实 rule key，强度和证明从 carrier 反向派生。

use crate::diagnostic::{Finding, GovernanceCheck, finding};
use crate::workspace_root;
use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use syn::visit::Visit;

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
    MissingCodegenHardProof,
    ConflictingInvariantFacet,
    MatrixCoverage,
    MatrixMissingBoundary,
    MatrixMissingInvariant,
    MatrixEvidence,
    MatrixResidual,
    MatrixDocDrift,
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
        findings.extend(validate_matrix(&root, &index.records, true)?);
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MatrixAction {
    Print,
    Write,
    Check,
}

const MATRIX_DOC: &str =
    "docs/architecture/202607091830-015-persistence-funnel-ai-robust-matrix.md";
const EXPECTED_FUNNEL_COUNT: usize = 15;
const FUNNEL_ISSUE_RANGE_START: u32 = 1422;
const FUNNEL_ISSUE_RANGE_END: u32 = 1442;
const ISSUE_PG_RUNTIME_CUTOVER: u32 = 1677;
const ISSUE_EVENT_TRANSPORT_OUTPUT: u32 = 1678;
const ISSUE_OUTBOX_CLAIM_CAPABILITY: u32 = 1741;
const ISSUE_SAME_ID_DELIVERY: u32 = 1742;
const ISSUE_OUTBOX_CLAIM_RELAY_CUTOVER: u32 = 1743;
const EXTRA_FUNNEL_ISSUES: &[u32] = &[
    ISSUE_PG_RUNTIME_CUTOVER,
    ISSUE_EVENT_TRANSPORT_OUTPUT,
    ISSUE_OUTBOX_CLAIM_CAPABILITY,
    ISSUE_SAME_ID_DELIVERY,
    ISSUE_OUTBOX_CLAIM_RELAY_CUTOVER,
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
        source_issues: &[ISSUE_PG_RUNTIME_CUTOVER],
        upstream: &[
            invariant("PG-RUNTIME-OWNER-01"),
            invariant("PG-RUNTIME-HANDLE-02"),
        ],
        downstream: &[
            invariant("PG-RUNTIME-OUTPUT-03"),
            invariant("RUNTIME-PROVIDER-OUTPUTS-LIVE-01"),
        ],
        residual: ResidualDisposition::AcceptedMedium {
            risk: "跨文件 PG lifecycle 消费与 Launch 注册顺序仍可能出现 AST visitor 未识别的新语法形态",
            why_no_low_cost_hardening: "Rust 类型系统可锁定 owner/factory 单次消费，但无法表达跨文件唯一生产调用与相对注册顺序；synthetic-red/green AST 门覆盖已知入口",
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
            eprintln!("archrules matrix: {EXPECTED_FUNNEL_COUNT} 行与 committed 文档一致")
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

fn validate_matrix(
    root: &Path,
    records: &[RuleRecord],
    check_doc_drift: bool,
) -> Result<Vec<Finding<Rule>>> {
    let mut findings = Vec::new();
    let mut expected_issues =
        (FUNNEL_ISSUE_RANGE_START..=FUNNEL_ISSUE_RANGE_END).collect::<BTreeSet<_>>();
    expected_issues.extend(EXTRA_FUNNEL_ISSUES);
    let mut actual_issues = BTreeSet::new();
    let mut seen_issues = BTreeSet::new();
    let mut keys = BTreeSet::new();
    if FUNNELS.len() != EXPECTED_FUNNEL_COUNT {
        findings.push(finding(
            Rule::MatrixCoverage,
            "FUNNELS",
            format!(
                "必须恰好 {EXPECTED_FUNNEL_COUNT} 行，实际 {} 行",
                FUNNELS.len()
            ),
        ));
    }
    for funnel in FUNNELS {
        if !keys.insert(funnel.key) {
            findings.push(finding(Rule::MatrixCoverage, funnel.key, "funnel key 重复"));
        }
        if funnel.upstream.is_empty() || funnel.downstream.is_empty() {
            findings.push(finding(
                Rule::MatrixMissingBoundary,
                funnel.key,
                "upstream/downstream 必须均非空",
            ));
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
                RuleLevel::Hard => validate_hard_evidence(root, funnel.key, record, &mut findings)?,
                RuleLevel::Medium => {
                    has_medium = true;
                    validate_medium_evidence(root, funnel.key, record, &mut findings)?;
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
                usize::from(record.exec == ExecutionLevel::Verify),
                usize::from(record.carrier == "xtask"),
            )
        })
}

fn validate_hard_evidence(
    root: &Path,
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
                && red.is_some_and(|symbol| {
                    record_source_has_test_symbol(root, record, symbol).unwrap_or(false)
                })
                && green.is_some_and(|symbol| {
                    record_source_has_test_symbol(root, record, symbol).unwrap_or(false)
                })
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
    funnel: &str,
    record: &RuleRecord,
    findings: &mut Vec<Finding<Rule>>,
) -> Result<()> {
    let red = record.synthetic_red.as_deref();
    let green = record.anti_vacuity.as_deref();
    let explicitly_bound = red.zip(green).is_some_and(|(red, green)| {
        red != green
            && record_source_has_test_symbol(root, record, red).unwrap_or(false)
            && record_source_has_test_symbol(root, record, green).unwrap_or(false)
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

fn record_test_names(root: &Path, record: &RuleRecord) -> Result<Vec<String>> {
    let relative = record.source.split(':').next().unwrap_or(&record.source);
    collect_test_names(&root.join(relative))
}

fn collect_test_names(path: &Path) -> Result<Vec<String>> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("读取 evidence source `{}`", path.display()))?;
    let file = syn::parse_file(&text)
        .with_context(|| format!("解析 evidence source `{}`", path.display()))?;
    #[derive(Default)]
    struct Collector(Vec<String>);
    impl<'ast> Visit<'ast> for Collector {
        fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
            let is_test = node.attrs.iter().any(|attr| {
                attr.path().segments.last().is_some_and(|segment| {
                    matches!(segment.ident.to_string().as_str(), "test" | "rstest")
                })
            });
            if is_test && !node.block.stmts.is_empty() {
                self.0.push(node.sig.ident.to_string());
            }
            syn::visit::visit_item_fn(self, node);
        }
    }
    let mut collector = Collector::default();
    collector.visit_file(&file);
    collector.0.sort();
    collector.0.dedup();
    Ok(collector.0)
}

fn record_source_has_test_symbol(root: &Path, record: &RuleRecord, symbol: &str) -> Result<bool> {
    let name = symbol.rsplit("::").next().unwrap_or(symbol);
    Ok(record_test_names(root, record)?
        .iter()
        .any(|candidate| candidate == name))
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
`cargo xtask archrules matrix --check` 校验固定 {EXPECTED_FUNNEL_COUNT} 行、{} 精确覆盖、边界非空、无 Soft、Hard carrier 证明、Medium synthetic-red/anti-vacuity 与文档漂移。该检查随 `archrules` 进入 `verify`/`ci`。\n",
        expected_issue_partition("–")
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
    scan_config(root, &mut index, "deny.toml", "deny", "verify,ci,audit")?;
    scan_config(root, &mut index, "clippy.toml", "clippy", "verify,ci")?;
    scan_config(
        root,
        &mut index,
        "xtask/runtime-deps-guard.toml",
        "runtime-deps-config",
        "verify,ci",
    )?;
    scan_public_api(root, &mut index)?;
    scan_source_invariants(root, &mut index)?;
    scan_trybuild_and_native(root, &mut index)?;
    reject_conflicting_facets(&mut index);
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
            .then_with(|| a.facet.cmp(&b.facet))
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
        if scan_record_granular_xtask_invariants(root, index, &path)? {
            continue;
        }
        let gate = xtask_gate(root, &path);
        scan_invariant_file(root, index, &path, "xtask", xtask_evidence(&path), gate)?;
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
            Some(binding.gates),
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
            Some(binding.gates),
            |rule| binding.matches(rule) && binding.accepts(rule),
        )?;
    }
    scan_extracted_invariant_rules_filtered(
        root,
        index,
        &found_invariants,
        "xtask",
        xtask_evidence(path),
        xtask_gate(root, path),
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
    gates: &'static str,
}

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
        gates: "native-compile",
    },
    InvariantCarrierBinding {
        path: "xtask/src/ci_lanes.rs",
        id: "CI-LANE-PLAN-01",
        facet: None,
        carrier: "xtask",
        evidence: "bound synthetic red and anti-vacuity tests",
        gates: "verify,ci,ci-core,ci-coverage",
    },
    InvariantCarrierBinding {
        path: "xtask/src/ci_lanes.rs",
        id: "CI-SLO-JOB-TYPE-01",
        facet: None,
        carrier: "native-hard",
        evidence: "closed exhaustive CI SLO job enum and workflow-parts constructor",
        gates: "native-compile",
    },
    InvariantCarrierBinding {
        path: "xtask/src/ci_lanes.rs",
        id: "CI-IMPACT-CATALOG-01",
        facet: None,
        carrier: "native-hard",
        evidence: "ci_job_catalog generated closed enum, matrix identity, and artifact identity",
        gates: "native-compile",
    },
];

const CI_IMPACT_INVARIANT_BINDINGS: &[InvariantCarrierBinding] = &[
    InvariantCarrierBinding {
        path: "xtask/src/ci_impact.rs",
        id: "CI-IMPACT-PLAN-01",
        facet: None,
        carrier: "native-hard",
        evidence: "private validated plan constructor over the exact typed job catalog",
        gates: "native-compile",
    },
    InvariantCarrierBinding {
        path: "xtask/src/ci_impact.rs",
        id: "CI-IMPACT-POLICY-01",
        facet: None,
        carrier: "xtask",
        evidence: "diff and impact synthetic reds with workspace policy anti-vacuity",
        gates: "verify,ci,ci-meta,ci-core,ci-security,ci-coverage,audit,integration",
    },
];

const CI_GATE_INVARIANT_BINDINGS: &[InvariantCarrierBinding] = &[InvariantCarrierBinding {
    path: "xtask/src/ci_gate.rs",
    id: "CI-GATE-RECEIPT-01",
    facet: None,
    carrier: "xtask",
    evidence: "receipt identity synthetic reds with exact-set anti-vacuity",
    gates: "verify,ci,ci-meta,ci-core,ci-security,ci-coverage,audit,integration",
}];

const CI_SLO_INVARIANT_BINDINGS: &[InvariantCarrierBinding] = &[
    InvariantCarrierBinding {
        path: "xtask/src/ci_slo.rs",
        id: "CI-SLO-CONFIG-SCHEMA-01",
        facet: None,
        carrier: "xtask",
        evidence: "strict config synthetic reds and committed complete catalog anti-vacuity",
        gates: "verify,ci,ci-meta,ci-core,ci-security,ci-coverage,audit,integration",
    },
    InvariantCarrierBinding {
        path: "xtask/src/ci_slo.rs",
        id: "CI-SLO-EVALUATION-01",
        facet: None,
        carrier: "xtask",
        evidence: "strict config and evidence synthetic reds with committed fixture and summary golden",
        gates: "verify,ci,ci-meta,ci-core,ci-security,ci-coverage,audit,integration",
    },
];

const INTEGRATION_SHARD_INVARIANT_BINDINGS: &[InvariantCarrierBinding] = &[
    InvariantCarrierBinding {
        path: "xtask/src/integration_shards.rs",
        id: "INTEGRATION-SHARD-REGISTRY-01",
        facet: None,
        carrier: "native-hard",
        evidence: "catalog macro generated closed enum, registry, and exhaustive lookup",
        gates: "native-compile",
    },
    InvariantCarrierBinding {
        path: "xtask/src/integration_shards.rs",
        id: "INTEGRATION-SHARD-SELECTOR-01",
        facet: None,
        carrier: "native-hard",
        evidence: "typed execution units are the only filterset construction path",
        gates: "native-compile",
    },
    InvariantCarrierBinding {
        path: "xtask/src/integration_shards.rs",
        id: "INTEGRATION-SHARD-COVERAGE-01",
        facet: None,
        carrier: "xtask",
        evidence: "Cargo metadata closure with synthetic red and real-workspace anti-vacuity",
        gates: "integration",
    },
    InvariantCarrierBinding {
        path: "xtask/src/integration_shards.rs",
        id: "INTEGRATION-SHARD-SCHEDULING-01",
        facet: None,
        carrier: "xtask",
        evidence: "exact resource and target scheduling plan with rendered argv proof",
        gates: "integration",
    },
];

const NEXTEST_INVARIANT_BINDINGS: &[InvariantCarrierBinding] = &[
    InvariantCarrierBinding {
        path: "xtask/src/nextest.rs",
        id: "NEXTEST-PROFILE-REGISTRY-01",
        facet: None,
        carrier: "native-hard",
        evidence: "closed profile enum",
        gates: "native-compile",
    },
    InvariantCarrierBinding {
        path: "xtask/src/nextest.rs",
        id: "NEXTEST-PARTITION-TYPE-01",
        facet: None,
        carrier: "native-hard",
        evidence: "validated partition newtype",
        gates: "native-compile",
    },
    InvariantCarrierBinding {
        path: "xtask/src/nextest.rs",
        id: "NEXTEST-EVIDENCE-DTO-01",
        facet: None,
        carrier: "native-hard",
        evidence: "typed serde DTO and committed golden",
        gates: "native-compile",
    },
    InvariantCarrierBinding {
        path: "xtask/src/nextest.rs",
        id: "NEXTEST-EVIDENCE-SCHEMA-01",
        facet: None,
        carrier: "xtask",
        evidence: "serde wire synthetic red and committed golden anti-vacuity",
        gates: "verify,ci-core,integration",
    },
    InvariantCarrierBinding {
        path: "xtask/src/nextest.rs",
        id: "NEXTEST-CONFIG-POLICY-01",
        facet: None,
        carrier: "xtask",
        evidence: "parsed config synthetic red and committed anti-vacuity",
        gates: "verify,ci-core,integration",
    },
    InvariantCarrierBinding {
        path: "xtask/src/nextest.rs",
        id: "NEXTEST-EXECUTION-FUNNEL-01",
        facet: None,
        carrier: "xtask",
        evidence: "direct-call synthetic red and production source anti-vacuity",
        gates: "verify,ci-core,integration",
    },
];

const COMPILER_CACHE_INVARIANT_BINDINGS: &[InvariantCarrierBinding] = &[
    InvariantCarrierBinding {
        path: "xtask/src/cmd.rs",
        id: "COMPILER-CACHE-POLICY-01",
        facet: None,
        carrier: "native-hard",
        evidence: "closed CompilerCachePolicy enum and private validated constructor",
        gates: "native-compile",
    },
    InvariantCarrierBinding {
        path: "xtask/src/cmd.rs",
        id: "COMPILER-CACHE-POLICY-02",
        facet: None,
        carrier: "xtask",
        evidence: "canonical-path/version synthetic red and enabled-policy anti-vacuity",
        gates: "manual/opt-in",
    },
];

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
    let gate = xtask_gate(root, &path);
    scan_invariant_file(
        root,
        index,
        &path,
        "public-api",
        format!("{} baseline", target_crates.len()),
        gate,
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
    gate: Option<&'static str>,
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
                        ) | (ExecutionLevel::Verify, SourceKind::Trybuild)
                    ))
                    || (carrier == "xtask"
                        && metadata.exec == ExecutionLevel::Verify
                        && metadata.source_kind == SourceKind::Codegen)
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
            "deny" | "clippy" | "runtime-deps-config" => self == Self::Config,
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
enum OrchestratorReason {
    RegistryAndPlanDerivation,
    PlanExecution,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SupportReason {
    SharedGateImplementation,
    CommandInfrastructure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GateDeclarationRole {
    PlanStep,
    Orchestrator(OrchestratorReason),
    Support(SupportReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GateDeclaration {
    path: &'static str,
    tokens: &'static str,
    role: GateDeclarationRole,
}

const META_TOKENS: &str = "verify,ci,ci-meta";
const COVERAGE_TOKENS: &str = "ci,ci-coverage";
const XTASK_GATE_DECLARATIONS: &[GateDeclaration] = &[
    GateDeclaration {
        path: "xtask/src/ci_lanes.rs",
        tokens: "native-compile,verify,ci,ci-meta,ci-core,ci-security,ci-coverage,audit,integration",
        role: GateDeclarationRole::Orchestrator(OrchestratorReason::RegistryAndPlanDerivation),
    },
    GateDeclaration {
        path: "xtask/src/integration_shards.rs",
        tokens: "native-compile,integration",
        role: GateDeclarationRole::Orchestrator(OrchestratorReason::RegistryAndPlanDerivation),
    },
    GateDeclaration {
        path: "xtask/src/nextest.rs",
        tokens: "native-compile,verify,ci-core,integration",
        role: GateDeclarationRole::Orchestrator(OrchestratorReason::PlanExecution),
    },
    GateDeclaration {
        path: "xtask/src/verify.rs",
        tokens: "verify,ci,ci-meta,ci-core,ci-security,ci-coverage,audit,integration",
        role: GateDeclarationRole::Orchestrator(OrchestratorReason::PlanExecution),
    },
    GateDeclaration {
        path: "xtask/src/archrules.rs",
        tokens: META_TOKENS,
        role: GateDeclarationRole::PlanStep,
    },
    GateDeclaration {
        path: "xtask/src/assembly.rs",
        tokens: META_TOKENS,
        role: GateDeclarationRole::PlanStep,
    },
    GateDeclaration {
        path: "xtask/src/assembly_codegen.rs",
        tokens: META_TOKENS,
        role: GateDeclarationRole::PlanStep,
    },
    GateDeclaration {
        path: "xtask/src/graph.rs",
        tokens: META_TOKENS,
        role: GateDeclarationRole::PlanStep,
    },
    GateDeclaration {
        path: "xtask/src/codegen.rs",
        tokens: META_TOKENS,
        role: GateDeclarationRole::PlanStep,
    },
    GateDeclaration {
        path: "xtask/src/localtx_coverage.rs",
        tokens: META_TOKENS,
        role: GateDeclarationRole::PlanStep,
    },
    GateDeclaration {
        path: "xtask/src/command_symmetry.rs",
        tokens: META_TOKENS,
        role: GateDeclarationRole::PlanStep,
    },
    GateDeclaration {
        path: "xtask/src/consistency_effects.rs",
        tokens: META_TOKENS,
        role: GateDeclarationRole::PlanStep,
    },
    GateDeclaration {
        path: "xtask/src/contract_binding_guard.rs",
        tokens: META_TOKENS,
        role: GateDeclarationRole::PlanStep,
    },
    GateDeclaration {
        path: "xtask/src/consistency_fixtures.rs",
        tokens: META_TOKENS,
        role: GateDeclarationRole::PlanStep,
    },
    GateDeclaration {
        path: "xtask/src/defergate.rs",
        tokens: META_TOKENS,
        role: GateDeclarationRole::PlanStep,
    },
    GateDeclaration {
        path: "xtask/src/doc_contracts.rs",
        tokens: META_TOKENS,
        role: GateDeclarationRole::PlanStep,
    },
    GateDeclaration {
        path: "xtask/src/promtool.rs",
        tokens: META_TOKENS,
        role: GateDeclarationRole::PlanStep,
    },
    GateDeclaration {
        path: "xtask/src/outbox_same_id_guard.rs",
        tokens: META_TOKENS,
        role: GateDeclarationRole::PlanStep,
    },
    GateDeclaration {
        path: "xtask/src/event_transport_guard.rs",
        tokens: META_TOKENS,
        role: GateDeclarationRole::PlanStep,
    },
    GateDeclaration {
        path: "xtask/src/inbox_cutover_guard.rs",
        tokens: META_TOKENS,
        role: GateDeclarationRole::PlanStep,
    },
    GateDeclaration {
        path: "xtask/src/dlx_lifecycle_funnel.rs",
        tokens: META_TOKENS,
        role: GateDeclarationRole::PlanStep,
    },
    GateDeclaration {
        path: "xtask/src/layerdeps.rs",
        tokens: META_TOKENS,
        role: GateDeclarationRole::PlanStep,
    },
    GateDeclaration {
        path: "xtask/src/migrations.rs",
        tokens: META_TOKENS,
        role: GateDeclarationRole::PlanStep,
    },
    GateDeclaration {
        path: "xtask/src/pdpallow.rs",
        tokens: META_TOKENS,
        role: GateDeclarationRole::PlanStep,
    },
    GateDeclaration {
        path: "xtask/src/pg_tenant_tx_guard.rs",
        tokens: META_TOKENS,
        role: GateDeclarationRole::PlanStep,
    },
    GateDeclaration {
        path: "xtask/src/reconcile_outbox_command_guard.rs",
        tokens: META_TOKENS,
        role: GateDeclarationRole::PlanStep,
    },
    GateDeclaration {
        path: "xtask/src/repo_scope_guard.rs",
        tokens: META_TOKENS,
        role: GateDeclarationRole::PlanStep,
    },
    GateDeclaration {
        path: "xtask/src/runtime_baseline.rs",
        tokens: META_TOKENS,
        role: GateDeclarationRole::PlanStep,
    },
    GateDeclaration {
        path: "xtask/src/runtime_deps_guard.rs",
        tokens: META_TOKENS,
        role: GateDeclarationRole::PlanStep,
    },
    GateDeclaration {
        path: "xtask/src/schema_rls.rs",
        tokens: META_TOKENS,
        role: GateDeclarationRole::PlanStep,
    },
    GateDeclaration {
        path: "xtask/src/setlocal_funnel.rs",
        tokens: META_TOKENS,
        role: GateDeclarationRole::PlanStep,
    },
    GateDeclaration {
        path: "xtask/src/shipped_feature_guard.rs",
        tokens: META_TOKENS,
        role: GateDeclarationRole::PlanStep,
    },
    GateDeclaration {
        path: "xtask/src/tenancy_closeout.rs",
        tokens: META_TOKENS,
        role: GateDeclarationRole::PlanStep,
    },
    GateDeclaration {
        path: "xtask/src/wsdeps.rs",
        tokens: META_TOKENS,
        role: GateDeclarationRole::PlanStep,
    },
    GateDeclaration {
        path: "xtask/src/contract/breaking.rs",
        tokens: META_TOKENS,
        role: GateDeclarationRole::PlanStep,
    },
    GateDeclaration {
        path: "xtask/src/contract/validate.rs",
        tokens: META_TOKENS,
        role: GateDeclarationRole::PlanStep,
    },
    GateDeclaration {
        path: "xtask/src/coverage.rs",
        tokens: COVERAGE_TOKENS,
        role: GateDeclarationRole::PlanStep,
    },
    GateDeclaration {
        path: "xtask/src/publicapi.rs",
        tokens: "ci,ci-coverage,standalone",
        role: GateDeclarationRole::PlanStep,
    },
    GateDeclaration {
        path: "xtask/src/layers.rs",
        tokens: META_TOKENS,
        role: GateDeclarationRole::Support(SupportReason::SharedGateImplementation),
    },
    GateDeclaration {
        path: "xtask/src/src_scan.rs",
        tokens: META_TOKENS,
        role: GateDeclarationRole::Support(SupportReason::SharedGateImplementation),
    },
    GateDeclaration {
        path: "xtask/src/contract/manifest.rs",
        tokens: META_TOKENS,
        role: GateDeclarationRole::Support(SupportReason::SharedGateImplementation),
    },
    GateDeclaration {
        path: "xtask/src/contract/protection.rs",
        tokens: META_TOKENS,
        role: GateDeclarationRole::Support(SupportReason::SharedGateImplementation),
    },
    GateDeclaration {
        path: "xtask/src/contract/redaction.rs",
        tokens: META_TOKENS,
        role: GateDeclarationRole::Support(SupportReason::SharedGateImplementation),
    },
    GateDeclaration {
        path: "xtask/src/pathsafe.rs",
        tokens: META_TOKENS,
        role: GateDeclarationRole::Support(SupportReason::SharedGateImplementation),
    },
    GateDeclaration {
        path: "xtask/src/diffcov.rs",
        tokens: COVERAGE_TOKENS,
        role: GateDeclarationRole::Support(SupportReason::SharedGateImplementation),
    },
    GateDeclaration {
        path: "xtask/src/cmd.rs",
        tokens: "manual/opt-in",
        role: GateDeclarationRole::Support(SupportReason::CommandInfrastructure),
    },
    GateDeclaration {
        path: "xtask/src/diagnostic.rs",
        tokens: "manual/opt-in",
        role: GateDeclarationRole::Support(SupportReason::CommandInfrastructure),
    },
];

fn xtask_gate_declarations() -> &'static [GateDeclaration] {
    XTASK_GATE_DECLARATIONS
}

fn xtask_gate(root: &Path, path: &Path) -> Option<&'static str> {
    let relative = rel(root, path);
    xtask_gate_declarations()
        .iter()
        .find(|declaration| declaration.path == relative)
        .map(|declaration| declaration.tokens)
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
    fn invariant_parser_preserves_facet_and_codegen_hard_proof() -> Result<()> {
        let metadata = parse_metadata(
            r#"level = "Hard", exec = "verify", source = "codegen", facet = "producer", golden = "generated/src/event/mod.rs", synthetic_red = "codegen::tests::event_red", anti_vacuity = "codegen::tests::event_green""#,
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
            "//! INVARIANT: DEMO-CODEGEN-01 { level = \"Hard\", exec = \"verify\", source = \"codegen\", facet = \"wire\", golden = \"generated/demo.rs\", synthetic_red = \"tests::red\", anti_vacuity = \"tests::green\" }\n",
        )?;
        write(&root.join("generated/demo.rs"), "// golden\n")?;
        let mut index = Index::default();
        scan_invariant_file(&root, &mut index, &file, "xtask", "demo", Some("verify"))?;
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
            exec: ExecutionLevel::Verify,
            source_kind: SourceKind::Code,
            carrier: "xtask".to_string(),
            source: "xtask/src/demo.rs:1".to_string(),
            evidence: "test".to_string(),
            gate: "verify".to_string(),
            status: "ok".to_string(),
            native: None,
            golden: None,
            synthetic_red: None,
            anti_vacuity: None,
        };
        let mut index = Index {
            records: vec![record(RuleLevel::Medium), record(RuleLevel::Hard)],
            findings: Vec::new(),
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
            Some("verify,ci,ci-meta")
        );
        assert_eq!(
            xtask_gate(root, &root.join("xtask/src/contract/breaking.rs")),
            Some("verify,ci,ci-meta")
        );
    }

    #[test]
    fn assembly_carrier_has_verify_ci_gate() {
        // assembly validate 在 verify.rs 的 verify 与 ci step 列表中均运行 ⇒ assembly.rs
        // 的 INVARIANT 锚点（ASSEMBLY-PROVIDER-CRATE-01）必须登记 `verify,ci` gate，否则
        // archrules 判 MissingGate（#1572）。gate 字符串 ↔ plan 实际成员的双向绑定由下方
        // `gate_strings_bound_to_registry_plan_membership` 机器守（review F2 / #1574）。
        let root = Path::new("/repo");
        assert_eq!(
            xtask_gate(root, &root.join("xtask/src/assembly.rs")),
            Some("verify,ci,ci-meta")
        );
    }

    #[test]
    fn local_only_effects_carrier_has_verify_ci_gate() {
        let root = Path::new("/repo");
        assert_eq!(
            xtask_gate(root, &root.join("xtask/src/consistency_effects.rs")),
            Some("verify,ci,ci-meta")
        );
    }

    fn carrier_set_drift(
        planned: &BTreeSet<String>,
        declared: &BTreeSet<String>,
    ) -> (BTreeSet<String>, BTreeSet<String>) {
        (
            planned.difference(declared).cloned().collect(),
            declared.difference(planned).cloned().collect(),
        )
    }

    #[test]
    fn gate_plan_binding_rejects_extra_stale_token_red() {
        // Simulates deleting the coverage step from every plan while leaving its declaration.
        let planned = BTreeSet::new();
        let declared = BTreeSet::from(["xtask/src/coverage.rs".to_string()]);
        let (missing, extra) = carrier_set_drift(&planned, &declared);
        assert!(missing.is_empty());
        assert_eq!(extra, BTreeSet::from(["xtask/src/coverage.rs".to_string()]));
    }

    #[test]
    fn gate_declarations_are_enumerable_and_role_classified() {
        let declarations = xtask_gate_declarations();
        assert!(!declarations.is_empty());
        let unique_paths: BTreeSet<_> = declarations
            .iter()
            .map(|declaration| declaration.path)
            .collect();
        assert_eq!(unique_paths.len(), declarations.len());
        let role_for = |path: &str| {
            declarations
                .iter()
                .find(|declaration| declaration.path == path)
                .map(|declaration| declaration.role)
        };
        assert_eq!(
            role_for("xtask/src/verify.rs"),
            Some(GateDeclarationRole::Orchestrator(
                OrchestratorReason::PlanExecution
            ))
        );
        assert_eq!(
            role_for("xtask/src/ci_lanes.rs"),
            Some(GateDeclarationRole::Orchestrator(
                OrchestratorReason::RegistryAndPlanDerivation
            ))
        );
        assert_eq!(
            role_for("xtask/src/diffcov.rs"),
            Some(GateDeclarationRole::Support(
                SupportReason::SharedGateImplementation
            ))
        );
        assert_eq!(
            role_for("xtask/src/coverage.rs"),
            Some(GateDeclarationRole::PlanStep)
        );
    }

    /// INVARIANT: ARCHRULES-GATE-PLAN-BIND-01 { level = "Medium", exec = "verify", source = "code" }——
    /// every real plan's in-process carrier set equals the files declaring that lane token. This
    /// rejects both missing bindings and stale/extra tokens across aggregate and split lanes.
    #[test]
    fn gate_strings_bound_to_registry_plan_membership() {
        let gate_has_lane =
            |tokens: &str, lane: &str| tokens.split(',').any(|tok| tok.trim() == lane);
        let plans = [
            (
                crate::verify::plan_for(crate::verify::PlanTarget::Verify),
                "verify",
            ),
            (
                crate::verify::plan_for(crate::verify::PlanTarget::CompatibilityCi),
                "ci",
            ),
            (
                crate::verify::plan_for(crate::verify::PlanTarget::Lane(
                    crate::ci_lanes::CiLane::Meta,
                )),
                "ci-meta",
            ),
            (
                crate::verify::plan_for(crate::verify::PlanTarget::Lane(
                    crate::ci_lanes::CiLane::Coverage,
                )),
                "ci-coverage",
            ),
            (
                crate::verify::plan_for(crate::verify::PlanTarget::Lane(
                    crate::ci_lanes::CiLane::Core,
                )),
                "ci-core",
            ),
            (
                crate::verify::plan_for(crate::verify::PlanTarget::Lane(
                    crate::ci_lanes::CiLane::Security,
                )),
                "ci-security",
            ),
        ];
        let mut nonempty_lanes = 0usize;
        for (plan, lane) in plans {
            let planned: BTreeSet<String> = plan
                .iter()
                .filter_map(|step| step.carrier_file())
                .map(str::to_string)
                .collect();
            let declared: BTreeSet<String> = xtask_gate_declarations()
                .iter()
                .filter(|declaration| declaration.role == GateDeclarationRole::PlanStep)
                .filter(|declaration| gate_has_lane(declaration.tokens, lane))
                .map(|declaration| declaration.path.to_string())
                .collect();
            let (missing, extra) = carrier_set_drift(&planned, &declared);
            assert!(
                missing.is_empty() && extra.is_empty(),
                "`{lane}` carrier binding drift: missing={missing:?}, stale/extra={extra:?}"
            );
            nonempty_lanes += usize::from(!planned.is_empty());
        }
        assert!(
            nonempty_lanes >= 2,
            "真实 carrier lane 未被校验（anti-vacuity）"
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
            &root.join("xtask/runtime-deps-guard.toml"),
            "# INVARIANT: RUNTIME-DEPS-CONFIG-DEMO-01 { level = \"Medium\", exec = \"verify\", source = \"config\" }\n",
        )?;
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
            "RUNTIME-DEPS-CONFIG-DEMO-01",
            "XTASK-DEMO-01",
        ] {
            assert!(index.records.iter().any(|r| r.id == id), "missing {id}");
        }
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn funnel_matrix_has_exact_rows_and_issue_partition() -> Result<()> {
        assert_eq!(FUNNELS.len(), EXPECTED_FUNNEL_COUNT);
        let issues = FUNNELS
            .iter()
            .flat_map(|funnel| funnel.source_issues.iter().copied())
            .collect::<Vec<_>>();
        let expected_issue_count = (FUNNEL_ISSUE_RANGE_END - FUNNEL_ISSUE_RANGE_START + 1) as usize
            + EXTRA_FUNNEL_ISSUES.len();
        assert_eq!(
            issues.len(),
            expected_issue_count,
            "每个来源 issue 必须且只能归属一行"
        );
        let mut expected =
            (FUNNEL_ISSUE_RANGE_START..=FUNNEL_ISSUE_RANGE_END).collect::<BTreeSet<_>>();
        expected.extend(EXTRA_FUNNEL_ISSUES);
        assert_eq!(issues.iter().copied().collect::<BTreeSet<_>>(), expected);
        let pg_runtime = FUNNELS
            .iter()
            .find(|funnel| funnel.source_issues == [ISSUE_PG_RUNTIME_CUTOVER])
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
                invariant("RUNTIME-PROVIDER-OUTPUTS-LIVE-01")
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
    fn funnel_matrix_configuration_is_single_source() {
        let source = include_str!("archrules.rs");
        for scattered in [
            format!("FUNNELS.len() != {EXPECTED_FUNNEL_COUNT}"),
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
            summary.contains(&format!("{EXPECTED_FUNNEL_COUNT} 行持久化 funnel")),
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
            &root.join("xtask/src/demo.rs"),
            r#"
#[test]
fn unrelated_red_rejected() { assert!(true); }
#[test]
fn unrelated_green_accepted() { assert!(true); }
"#,
        )?;
        let mut record = RuleRecord {
            id: "DEMO-MEDIUM-01".to_string(),
            facet: None,
            level: RuleLevel::Medium,
            exec: ExecutionLevel::Verify,
            source_kind: SourceKind::Code,
            carrier: "xtask".to_string(),
            source: "xtask/src/demo.rs:1".to_string(),
            evidence: "xtask module demo.rs".to_string(),
            gate: "verify".to_string(),
            status: "ok".to_string(),
            native: None,
            golden: None,
            synthetic_red: None,
            anti_vacuity: None,
        };
        let mut findings = Vec::new();
        validate_medium_evidence(&root, "demo", &record, &mut findings)?;
        assert_eq!(
            findings.len(),
            1,
            "同文件无关 red/green 测试不能替代 invariant 自己声明的证据"
        );
        record.synthetic_red = Some("tests::unrelated_red_rejected".to_string());
        record.anti_vacuity = Some("tests::unrelated_green_accepted".to_string());
        findings.clear();
        validate_medium_evidence(&root, "demo", &record, &mut findings)?;
        assert!(
            findings.is_empty(),
            "显式绑定的真实测试应通过: {findings:?}"
        );
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
        assert_eq!(plan.gate, "verify,ci,ci-core,ci-coverage");
        assert!(!plan.gate.contains("ci-security"));
        assert!(!plan.gate.contains("integration"));

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
        assert_eq!(
            config.gate,
            "verify,ci,ci-meta,ci-core,ci-security,ci-coverage,audit,integration"
        );
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
            "IANT: CI-LANE-PLAN-01 { level = \"Medium\", exec = \"verify\", source = \"code\" }\n",
            "//! INVAR",
            "IANT: CI-LANE-UNREGISTERED-01 { level = \"Medium\", exec = \"verify\", source = \"code\" }\n",
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
            "IANT: CI-LANE-PLAN-01 { level = \"Medium\", exec = \"verify\", source = \"code\" }\n",
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
            exec: ExecutionLevel::Verify,
            source_kind: SourceKind::Codegen,
            carrier: "xtask".to_string(),
            source: "xtask/src/demo.rs:1".to_string(),
            evidence: "codegen".to_string(),
            gate: "verify".to_string(),
            status: "ok".to_string(),
            native: None,
            golden: Some("generated/demo.rs".to_string()),
            synthetic_red: Some("demo::tests::fake_red".to_string()),
            anti_vacuity: Some("demo::tests::real_green".to_string()),
        };
        let mut findings = Vec::new();
        validate_hard_evidence(&root, "demo", &record, &mut findings)?;
        assert_eq!(
            findings.len(),
            1,
            "comment/string symbol 不得充当 test 证明"
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
