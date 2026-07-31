//! xtask — RSS 治理 / codegen 入口。见 docs/rules/architecture.md §xtask、§Rust 原生强制（三档载体）。
//!
//! 子命令：
//!   `cargo xtask codegen [--check]`     契约 schema → committed `generated/`（--check 为 CI 漂移门）
//!   `cargo xtask cdc-config debezium`   输出 Debezium PostgreSQL outbox_log CDC connector JSON skeleton（只读）
//!   `cargo xtask contract validate`     契约元数据校验（多规则，编号见 `contract::validate` 的 `Rule`，CI 门）
//!   `cargo xtask assembly validate`     assembly-level DI provider 声明校验（RevocationStore 持久 provider 门）
//!   `cargo xtask assembly artifacts check`
//!                                      assembly lifecycle 与应用 artifact exact closure 门
//!   `cargo xtask assembly generate-modules [--check]`
//!                                      assembly.toml domains → committed modules_gen.rs（--check 为漂移门）
//!   `cargo xtask assembly generate-providers [--check]`
//!                                      assembly.toml providers → committed typed provider catalog
//!   `cargo xtask assembly generate-runtime-plans [--check]`
//!                                      manifest + lock → committed typed runtime-plan.json
//!   `cargo xtask assembly lock generate|check`
//!                                      全仓 v1 assembly.lock.json 原子生成 / raw-byte 漂移门
//!   `cargo xtask graph assembly [--assembly <name>] [--format mermaid|json] [--check]`
//!                                      assembly 静态声明图；runtime 双格式 committed，--check 守漂移
//!   `cargo xtask archrules list|verify|matrix [--write|--check]`
//!                                      ArchRules 派生索引与持久化 funnel 单源矩阵；verify/matrix --check 为 CI 门
//!   `cargo xtask contract breaking [--against <git-ref>]`
//!                                      wire JSON-Schema 跨版本破坏检测门（ADR-008，对标 Buf WIRE_JSON）：base ref
//!                                      （默认 origin/develop）↔ working-tree schema/manifest wire diff；active
//!                                      破坏退出码 1，deprecated 仅告警，draft 跳过。详见 `contract::breaking`。
//!   `cargo xtask layer-deps`            source-centric 分层依赖 lint（成员 Cargo.toml [dependencies] → §分层 矩阵，CI 门）
//!   `cargo xtask wsdeps-drift`          workspace.dependencies pin↔lock 漂移门（#1185，CI 门）
//!   `cargo xtask promtool-rules`         固定摘要 promtool 规则 + consumer test 门（CI 门）
//!   `cargo xtask outbox-same-id-guard`   same-ID SQL/Rust/ops 完整闭包门（CI 门）
//!   `cargo xtask consistency-fixtures`  consistency crash matrix fixture/DSL 治理门（#1616，CI 门）
//!   `cargo xtask consistency local-only-effects`
//!                                      active LocalOnly HTTP effect profile 治理门（#1689，CI 门）
//!   `cargo xtask consistency report --format json|md`
//!                                      active HTTP consistency/effect posture 确定性报告（只读）
//!   `cargo xtask localtx-coverage`       active LocalTx manifest/generated/route/test closure 门（CI 门）
//!   `cargo xtask localtx report --format json|markdown`
//!                                      active LocalTx static proof inventory（只读）
//!   `cargo xtask l2-assurance [--check]`
//!                                      deterministic active L2 producer/fact assurance inventory
//!   `cargo xtask provider-capabilities [--check]`
//!                                      deterministic L2 provider conformance enrollment matrix
//!   `cargo xtask runtime-baseline list|verify`
//!                                      runtime assembly baseline 清单 / 漂移门（#1656，CI 门）
//!   `cargo xtask runtime-root guard`    runtime composition-root 单调职责 ratchet（RUNTIME-ROOT-RATCHET-01）
//!   `cargo xtask runtime-deps guard`    SharedRuntimeDeps infra-only 字段类型守卫（WIRING-DEPS-INFRA-ONLY-01）
//!   `cargo xtask runtime-env guard`     runtime ambient environment single-funnel guard（RUNTIME-ENV-FUNNEL-01）
//!   `cargo xtask migrations`            migration 文件序号唯一性 + 连续性守卫（INVARIANT MIGRATION-SERIAL-UNIQUE-01，CI 门）
//!   `cargo xtask inbox-cutover-guard`    inbox receipt cutover 旧 token 回流守卫（CI 门）
//!   `cargo xtask dlx-lifecycle-funnel`   DLX verified WORM archive-before-purge 单漏斗守卫（CI 门）
//!   `cargo xtask pg-tenant-tx-guard`    Postgres tenant 表 raw-pool / TxManager bypass 守卫（CI 门）
//!   `cargo xtask repo-scope-guard`      domain repo port 禁裸 TenantId / RowVisibility / RowScope 签名守卫（CI 门）
//!   `cargo xtask reconcile-outbox-command-guard`
//!                                      reconcile scheduler transactional command outbox seam 守卫（CI 门）
//!   `cargo xtask tenancy-closeout`      tenancy/AuthZ/projection closeout 反向自检（CI 门）
//!   `cargo xtask verify [--fast] [--fresh] [--allow-missing-tools] [--fail-fast] [--only <gate>]...`
//!                                      本地全量治理门聚合入口（GitHub Actions 与本地共用同一门）：fmt + meta（contract
//!                                      validate / assembly validate / layer-deps / codegen --check）+ build + Postgres
//!                                      feature compile matrix + clippy + nextest + deny + dylint；
//!                                      `--fast` 只跑 registry 显式 Always 的 9 个本地 meta 门；`--fresh` 清空
//!                                      当前分支断点；`--allow-missing-tools` 缺外部
//!                                      工具时显式宽限（默认 fail-closed）。详见 `verify.rs`。
//!   `cargo xtask public-api [--layer basis|engine|curated] [--check] [--allow-missing]`
//!                                      封装面 baseline（包装 cargo-public-api，需 nightly rustdoc-json；无
//!                                      --layer 时检查 basis + engine + curated extras）；
//!                                      --check 缺 baseline 默认 fail-fast，--allow-missing 显式宽限（PR-0 自检）
//!   `cargo xtask ci local --base <ref> [--fresh] [--fail-fast] [--only <stage>]...`
//!                                      仅分析 `<ref>...HEAD` 已提交差异，经 typed ImpactSet 生成本地 preflight。
//!   `cargo xtask ci full [--allow-missing-tools] [--fail-fast]`
//!                                      原本地 CI lane 超集聚合（coverage/public-api/audit 等完整门集）。
//!   `cargo xtask ci plan --event-path <json> --policy <toml> --output <json> --github-output <file>`
//!                                      GitHub event/diff → typed 16-job impact plan 与动态 matrix。
//!   `cargo xtask ci run --job <CiJobKey>`
//!                                      唯一远端 typed executor；闭合 job key 穷举分派至 lane/shard/partition。
//!   `cargo xtask ci gate --plan <json> --receipts <dir> --planner-result <result> --matrix-result <result> --metrics-output <json>`
//!                                      稳定聚合 planner、matrix outcome 与 evidence v4 精确回执集。
//!   `cargo xtask ci-slo evaluate --lane <lane> [--shard <shard>] [--partition M/N]
//!      --run-id <N> --run-attempt <N> --upload-outcome <success|failure|cancelled|skipped>
//!      [--github-summary]`
//!                                      严格消费 staged evidence；本地输出 Markdown，GitHub 模式把 annotation
//!                                      写 stdout、Markdown 写 runner 的 Job Summary 文件。
mod archrules;
mod assembly;
mod assembly_artifacts;
mod assembly_codegen;
mod assembly_governance;
mod assembly_lock;
mod assembly_runtime_plan;
mod cdc_config;
mod ci_entry_guard;
mod ci_evidence;
mod ci_gate;
mod ci_identity;
mod ci_impact;
mod ci_lanes;
mod ci_slo;
mod cmd;
pub(crate) use cmd::nextest;
mod codegen;
mod command_symmetry;
mod consistency_effects;
mod consistency_fixtures;
mod contract;
mod contract_binding_guard;
mod coverage;
mod defergate;
mod diagnostic;
mod diffcov;
mod dlx_lifecycle_funnel;
mod event_transport_guard;
mod execution_profiles;
mod generated_file;
mod graph;
mod inbox_cutover_guard;
mod integration_shards;
mod l2_assurance;
mod layerdeps;
mod layers;
mod local_run_ledger;
mod localonly_evidence;
mod localtx_coverage;
mod localtx_evidence;
mod localtx_report;
mod migrations;
mod outbox_same_id_guard;
mod pathsafe;
mod pdpallow;
mod pg_tenant_tx_guard;
mod phase_helper_expand;
mod postgres_feature_matrix;
mod producer_assurance;
mod production_composition;
mod projection_target_enrollment;
mod promtool;
mod provider_capabilities;
mod publicapi;
mod reconcile_outbox_command_guard;
mod repo_scope_guard;
mod runtime_baseline;
mod runtime_deps_guard;
mod runtime_env_guard;
mod runtime_root_guard;
mod schema_rls;
mod setlocal_funnel;
mod shipped_feature_guard;
mod source_semantic_guard;
mod src_scan;
mod tenancy_closeout;
#[cfg(test)]
mod testutil;
mod verify;
mod wsdeps;

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    dispatch(&args)
}

/// 可测纯枚举：命令解析结果，与 IO 执行分离。
#[derive(Debug, PartialEq, Eq)]
enum Command {
    Codegen {
        check: bool,
    },
    CdcConfigDebezium,
    ContractValidate,
    AssemblyValidate,
    AssemblyArtifactsCheck,
    AssemblyGenerateModules {
        check: bool,
    },
    AssemblyGenerateProviders {
        check: bool,
    },
    AssemblyGenerateRuntimePlans {
        check: bool,
    },
    AssemblyLock(assembly_lock::AssemblyLockAction),
    GraphAssembly(graph::Options),
    ArchRulesList,
    ArchRulesVerify,
    ArchRulesMatrix(archrules::MatrixAction),
    RuntimeBaselineList,
    RuntimeBaselineVerify,
    RuntimeRootGuard,
    RuntimeDepsGuard,
    RuntimeEnvGuard,
    ContractBreaking {
        /// base git-ref（缺省 = `contract::breaking::DEFAULT_AGAINST`）。
        against: Option<String>,
    },
    LayerDeps,
    WsDepsDrift,
    SourceSemanticGuard,
    PromtoolRules,
    OutboxSameIdGuard,
    ConsistencyFixtures,
    ConsistencyLocalOnlyEffects,
    ConsistencyReport {
        format: ReportFormat,
    },
    LocalTxCoverage,
    LocalTxReport {
        format: ReportFormat,
    },
    L2Assurance {
        check: bool,
    },
    ProviderCapabilities {
        check: bool,
    },
    Verify {
        fast: bool,
        fresh: bool,
        allow_missing_tools: bool,
        against: Option<String>,
        fail_fast: bool,
        only: Vec<String>,
    },
    PublicApi {
        check: bool,
        allow_missing: bool,
        layer: Option<publicapi::Layer>,
    },
    CiFull {
        allow_missing_tools: bool,
        fail_fast: bool,
    },
    CiLocal(ci_impact::LocalOptions),
    CiRun {
        job: ci_lanes::CiJobKey,
        required_evidence_output: Option<PathBuf>,
    },
    CiSloEvaluate {
        job: ci_lanes::CiJobKey,
        run_id: String,
        run_attempt: String,
        upload_outcome: ci_slo::UploadOutcome,
        summary_mode: ci_slo::SummaryMode,
    },
    CiPlan(ci_impact::Options),
    CiGate(ci_gate::Options),
    NextestEvidenceStage,
    NextestEvidenceInspect {
        artifact_root: PathBuf,
    },
    NextestEvidenceReplay {
        sidecar: PathBuf,
    },
    SchemaRls,
    /// inbox receipt runtime cutover old-token guard（INBOX-RECEIPTS-CUTOVER-01）。
    InboxCutoverGuard,
    /// DLX verified WORM archive-before-purge 单漏斗守卫（DLX-LIFECYCLE-FUNNEL-01）。
    DlxLifecycleFunnel,
    /// tenant-scope SET-LOCAL 单漏斗守卫（TENANCY-SETLOCAL-FUNNEL-01）。
    SetLocalFunnel,
    /// Postgres tenant-table raw-pool / TxManager bypass guard（TENANCY-PG-TX-FUNNEL-01）。
    PgTenantTxGuard,
    /// domain repo port scope handle signature guard（TENANCY-REPO-SCOPE-SIGNATURE-01）。
    RepoScopeGuard,
    /// reconcile scheduler transactional command outbox seam guard（RECONCILE-COMMAND-OUTBOX-SEAM-01）。
    ReconcileOutboxCommandGuard,
    /// tenancy/AuthZ/projection closeout reverse self-check（TENANCY-CLOSEOUT-REVERSE-01）。
    TenancyCloseout,
    DeferGate,
    Migrations,
}

/// Consistency posture report wire format. Closed on purpose: no aliases or implicit default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReportFormat {
    Json,
    Markdown,
}

/// 从参数列表解析命令，不执行任何 IO。
///
/// 精确 argv 匹配（fail-closed）：合法子命令后出现任何未声明尾参即 `Err`——杜绝
/// `verify --bogus` / `contract validate --typo` 被静默吞掉而仍返回成功。
fn parse_command(args: &[String]) -> Result<Command> {
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    match argv.as_slice() {
        ["codegen"] => Ok(Command::Codegen { check: false }),
        ["codegen", "--check"] => Ok(Command::Codegen { check: true }),
        ["cdc-config", rest @ ..] => parse_cdc_config(rest),
        ["archrules", rest @ ..] => parse_archrules(rest),
        ["runtime-baseline", rest @ ..] => parse_runtime_baseline(rest),
        ["runtime-root", rest @ ..] => parse_runtime_root(rest),
        ["runtime-deps", rest @ ..] => parse_runtime_deps(rest),
        ["runtime-env", rest @ ..] => parse_runtime_env(rest),
        ["contract", rest @ ..] => parse_contract(rest),
        ["assembly", rest @ ..] => parse_assembly(rest),
        ["graph", rest @ ..] => graph::parse(rest).map(Command::GraphAssembly),
        ["layer-deps"] => Ok(Command::LayerDeps),
        ["wsdeps-drift"] => Ok(Command::WsDepsDrift),
        ["source-semantic-guard"] => Ok(Command::SourceSemanticGuard),
        ["promtool-rules"] => Ok(Command::PromtoolRules),
        ["outbox-same-id-guard"] => Ok(Command::OutboxSameIdGuard),
        ["consistency-fixtures"] => Ok(Command::ConsistencyFixtures),
        ["consistency", rest @ ..] => parse_consistency(rest),
        ["localtx", rest @ ..] => parse_localtx(rest),
        ["localtx-coverage"] => Ok(Command::LocalTxCoverage),
        ["l2-assurance"] => Ok(Command::L2Assurance { check: false }),
        ["l2-assurance", "--check"] => Ok(Command::L2Assurance { check: true }),
        ["l2-assurance", ..] => {
            bail!(
                "invalid l2-assurance arguments; use `./hack/cargo.sh xtask l2-assurance [--check]`"
            )
        }
        ["provider-capabilities"] => Ok(Command::ProviderCapabilities { check: false }),
        ["provider-capabilities", "--check"] => Ok(Command::ProviderCapabilities { check: true }),
        ["provider-capabilities", ..] => {
            bail!(
                "invalid provider-capabilities arguments; use `./hack/cargo.sh xtask provider-capabilities [--check]`"
            )
        }
        ["verify", rest @ ..] => parse_verify(rest),
        ["public-api", rest @ ..] => parse_public_api(rest),
        ["ci", rest @ ..] => parse_ci(rest),
        ["ci-slo", rest @ ..] => parse_ci_slo(rest),
        ["nextest-evidence", "stage"] => Ok(Command::NextestEvidenceStage),
        ["nextest-evidence", "inspect", artifact_root] => Ok(Command::NextestEvidenceInspect {
            artifact_root: PathBuf::from(artifact_root),
        }),
        ["nextest-evidence", "replay", sidecar] => Ok(Command::NextestEvidenceReplay {
            sidecar: PathBuf::from(sidecar),
        }),
        ["schema-rls"] => Ok(Command::SchemaRls),
        ["inbox-cutover-guard"] => Ok(Command::InboxCutoverGuard),
        ["dlx-lifecycle-funnel"] => Ok(Command::DlxLifecycleFunnel),
        ["setlocal-funnel"] => Ok(Command::SetLocalFunnel),
        ["pg-tenant-tx-guard"] => Ok(Command::PgTenantTxGuard),
        ["repo-scope-guard"] => Ok(Command::RepoScopeGuard),
        ["reconcile-outbox-command-guard"] => Ok(Command::ReconcileOutboxCommandGuard),
        ["tenancy-closeout"] => Ok(Command::TenancyCloseout),
        ["defer-gate"] => Ok(Command::DeferGate),
        ["migrations"] => Ok(Command::Migrations),
        other => {
            bail!(
                "未知命令: {other:?}；用法含 graph assembly | localtx-coverage | localtx report --format <json|markdown> | ci <local|full|plan|run|gate> | nextest-evidence <stage|inspect|replay>；收到 {other:?}"
            )
        }
    }
}

/// 解析闭合 CI SLO evaluator CLI；路径固定在 workspace 内，不接受路径参数。
fn parse_ci_slo(args: &[&str]) -> Result<Command> {
    let ["evaluate", rest @ ..] = args else {
        bail!(
            "未知 ci-slo 子命令；用法: cargo xtask ci-slo evaluate --lane <lane> [--shard <shard>] [--partition M/N] --run-id <N> --run-attempt <N> --upload-outcome <outcome> [--github-summary]"
        );
    };
    let mut lane = None;
    let mut shard = None;
    let mut partition = None;
    let mut run_id = None;
    let mut run_attempt = None;
    let mut upload_outcome = None;
    let mut summary_mode = ci_slo::SummaryMode::Stdout;
    let mut iter = rest.iter().copied();
    while let Some(flag) = iter.next() {
        if flag == "--github-summary" {
            if summary_mode == ci_slo::SummaryMode::Github {
                bail!("ci-slo 未知或重复参数: {flag}");
            }
            summary_mode = ci_slo::SummaryMode::Github;
            continue;
        }
        let value = iter
            .next()
            .ok_or_else(|| anyhow::anyhow!("ci-slo 参数 {flag} 缺少值"))?;
        match flag {
            "--lane" if lane.is_none() => lane = Some(value),
            "--shard" if shard.is_none() => shard = Some(value.parse()?),
            "--partition" if partition.is_none() => partition = Some(value.parse()?),
            "--run-id" if run_id.is_none() => {
                validate_decimal_cli(value, "--run-id")?;
                run_id = Some(value.to_owned());
            }
            "--run-attempt" if run_attempt.is_none() => {
                validate_decimal_cli(value, "--run-attempt")?;
                run_attempt = Some(value.to_owned());
            }
            "--upload-outcome" if upload_outcome.is_none() => {
                upload_outcome = Some(value.parse()?);
            }
            _ => bail!("ci-slo 未知或重复参数: {flag}"),
        }
    }
    let lane = lane.context("ci-slo 缺少 --lane")?;
    let job = ci_lanes::CiJobKey::from_workflow_parts(lane, shard, partition)?;
    Ok(Command::CiSloEvaluate {
        job,
        run_id: run_id.context("ci-slo 缺少 --run-id")?,
        run_attempt: run_attempt.context("ci-slo 缺少 --run-attempt")?,
        upload_outcome: upload_outcome.context("ci-slo 缺少 --upload-outcome")?,
        summary_mode,
    })
}

fn validate_decimal_cli(value: &str, flag: &str) -> Result<()> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("{flag} 必须是十进制整数");
    }
    value
        .parse::<u64>()
        .with_context(|| format!("{flag} 超出 u64 范围"))?;
    Ok(())
}

/// 解析 `consistency <sub>`（fail-closed：无 alias、默认值或尾参）。
fn parse_consistency(args: &[&str]) -> Result<Command> {
    match args {
        ["local-only-effects"] => Ok(Command::ConsistencyLocalOnlyEffects),
        ["report", "--format", "json"] => Ok(Command::ConsistencyReport {
            format: ReportFormat::Json,
        }),
        ["report", "--format", "md"] => Ok(Command::ConsistencyReport {
            format: ReportFormat::Markdown,
        }),
        other => bail!(
            "未知 consistency 子命令: {other:?}；用法: cargo xtask consistency local-only-effects | cargo xtask consistency report --format <json|md>"
        ),
    }
}

/// 解析 `localtx <sub>`（fail-closed：无 alias、默认值、输出路径或尾参）。
fn parse_localtx(args: &[&str]) -> Result<Command> {
    match args {
        ["report", "--format", "json"] => Ok(Command::LocalTxReport {
            format: ReportFormat::Json,
        }),
        ["report", "--format", "markdown"] => Ok(Command::LocalTxReport {
            format: ReportFormat::Markdown,
        }),
        other => bail!(
            "未知 localtx 子命令: {other:?}；用法: cargo xtask localtx report --format <json|markdown>"
        ),
    }
}

/// 解析 `cdc-config <provider>` 子命令（fail-closed：当前只接受 `debezium`）。
fn parse_cdc_config(args: &[&str]) -> Result<Command> {
    match args {
        ["debezium"] => Ok(Command::CdcConfigDebezium),
        other => bail!("未知 cdc-config 子命令: {other:?}；用法: cargo xtask cdc-config debezium"),
    }
}

/// 解析 `archrules <sub>` 子命令（fail-closed：只接受 positional list/verify，不提供 --list 兼容形态）。
fn parse_archrules(args: &[&str]) -> Result<Command> {
    match args {
        ["list"] => Ok(Command::ArchRulesList),
        ["verify"] => Ok(Command::ArchRulesVerify),
        ["matrix"] => Ok(Command::ArchRulesMatrix(archrules::MatrixAction::Print)),
        ["matrix", "--write"] => Ok(Command::ArchRulesMatrix(archrules::MatrixAction::Write)),
        ["matrix", "--check"] => Ok(Command::ArchRulesMatrix(archrules::MatrixAction::Check)),
        other => {
            bail!(
                "未知 archrules 子命令: {other:?}；用法: cargo xtask archrules <list | verify | matrix [--write|--check]>"
            )
        }
    }
}

/// 解析 `runtime-baseline <sub>` 子命令（fail-closed：只接受 positional list/verify，不提供兼容别名）。
fn parse_runtime_baseline(args: &[&str]) -> Result<Command> {
    match args {
        ["list"] => Ok(Command::RuntimeBaselineList),
        ["verify"] => Ok(Command::RuntimeBaselineVerify),
        other => bail!(
            "未知 runtime-baseline 子命令: {other:?}；用法: cargo xtask runtime-baseline <list | verify>"
        ),
    }
}

/// 解析 `runtime-root guard` 子命令（fail-closed：只接受 guard，不提供 alias/尾参）。
fn parse_runtime_root(args: &[&str]) -> Result<Command> {
    match args {
        ["guard"] => Ok(Command::RuntimeRootGuard),
        other => bail!("未知 runtime-root 子命令: {other:?}；用法: cargo xtask runtime-root guard"),
    }
}

/// 解析 `runtime-deps guard` 子命令（fail-closed：只接受 guard，不提供兼容别名）。
fn parse_runtime_deps(args: &[&str]) -> Result<Command> {
    match args {
        ["guard"] => Ok(Command::RuntimeDepsGuard),
        other => bail!("未知 runtime-deps 子命令: {other:?}；用法: cargo xtask runtime-deps guard"),
    }
}

fn parse_runtime_env(args: &[&str]) -> Result<Command> {
    match args {
        ["guard"] => Ok(Command::RuntimeEnvGuard),
        other => bail!("未知 runtime-env 子命令: {other:?}；用法: cargo xtask runtime-env guard"),
    }
}

/// 解析 `contract <sub>` 子命令（fail-closed：未知子命令即 `Err`）。
fn parse_contract(args: &[&str]) -> Result<Command> {
    match args {
        ["validate"] => Ok(Command::ContractValidate),
        ["breaking", rest @ ..] => parse_contract_breaking(rest),
        other => bail!(
            "未知 contract 子命令: {other:?}；用法: cargo xtask contract <validate | breaking [--against <git-ref>]>"
        ),
    }
}

/// 解析 `assembly <sub>` 子命令（fail-closed：未知子命令即 `Err`）。
fn parse_assembly(args: &[&str]) -> Result<Command> {
    match args {
        ["validate"] => Ok(Command::AssemblyValidate),
        ["artifacts", "check"] => Ok(Command::AssemblyArtifactsCheck),
        ["generate-modules"] => Ok(Command::AssemblyGenerateModules { check: false }),
        ["generate-modules", "--check"] => Ok(Command::AssemblyGenerateModules { check: true }),
        ["generate-providers"] => Ok(Command::AssemblyGenerateProviders { check: false }),
        ["generate-providers", "--check"] => Ok(Command::AssemblyGenerateProviders { check: true }),
        ["generate-runtime-plans"] => Ok(Command::AssemblyGenerateRuntimePlans { check: false }),
        ["generate-runtime-plans", "--check"] => {
            Ok(Command::AssemblyGenerateRuntimePlans { check: true })
        }
        ["lock", "generate"] => Ok(Command::AssemblyLock(
            assembly_lock::AssemblyLockAction::Generate,
        )),
        ["lock", "check"] => Ok(Command::AssemblyLock(
            assembly_lock::AssemblyLockAction::Check,
        )),
        _ => bail!(
            "未知 assembly 子命令；用法: cargo xtask assembly <validate | artifacts check | generate-modules [--check] | generate-providers [--check] | generate-runtime-plans [--check] | lock <generate|check>>"
        ),
    }
}

/// 解析 `contract breaking` 的可选 flag（fail-closed：未知 flag / `--against` 缺值即 `Err`）。
fn parse_contract_breaking(args: &[&str]) -> Result<Command> {
    let mut against = None;
    let mut it = args.iter();
    while let Some(&tok) = it.next() {
        match tok {
            "--against" => {
                let val = it.next().ok_or_else(|| {
                    anyhow::anyhow!("--against 缺少值；用法: --against <git-ref>")
                })?;
                against = Some((*val).to_string());
            }
            other => {
                bail!("contract breaking 未知参数: {other}；用法: --against <git-ref>")
            }
        }
    }
    Ok(Command::ContractBreaking { against })
}

/// 解析 `verify` 的可选 flag（fail-closed：未知 flag 即 `Err`）。
fn parse_verify(args: &[&str]) -> Result<Command> {
    let mut fast = false;
    let mut fresh = false;
    let mut allow_missing_tools = false;
    let mut against = None;
    let mut fail_fast = false;
    let mut only = Vec::new();
    let mut iter = args.iter().copied();
    while let Some(tok) = iter.next() {
        match tok {
            "--fast" if !fast => fast = true,
            "--fast" => bail!("verify 重复参数: --fast"),
            "--fresh" if !fresh => fresh = true,
            "--fresh" => bail!("verify 重复参数: --fresh"),
            "--allow-missing-tools" => allow_missing_tools = true,
            "--fail-fast" if !fail_fast => fail_fast = true,
            "--fail-fast" => bail!("verify 重复参数: --fail-fast"),
            "--only" => {
                let value = iter.next().context("verify 参数 --only 缺少值")?;
                if value.is_empty() || value.starts_with("--") {
                    bail!("verify 参数 --only 必须是非空 gate label，不能是 flag");
                }
                if only.iter().any(|selected| selected == value) {
                    bail!("verify 重复 gate: {value}");
                }
                only.push(value.to_owned());
            }
            "--against" => {
                let value = iter.next().context("verify 参数 --against 缺少值")?;
                if value.is_empty() || value.starts_with("--") {
                    bail!("verify 参数 --against 必须是非空 git ref，不能是 flag");
                }
                if against.replace(value.to_owned()).is_some() {
                    bail!("verify 重复参数: --against");
                }
            }
            other => bail!(
                "verify 未知参数: {other}；用法: cargo xtask verify [--fast] [--fresh] [--allow-missing-tools] [--against <git-ref>] [--fail-fast] [--only <gate-label>]..."
            ),
        }
    }
    if fresh && !fast {
        bail!("verify --fresh 只允许与 --fast 同用");
    }
    Ok(Command::Verify {
        fast,
        fresh,
        allow_missing_tools,
        against,
        fail_fast,
        only,
    })
}

/// 解析闭合 CI 命令族。空命令与旧平铺入口均 fail-closed。
fn parse_ci(args: &[&str]) -> Result<Command> {
    let Some((subcommand, rest)) = args.split_first() else {
        bail!("ci 缺少子命令；用法: cargo xtask ci <local|full|plan|run|gate>");
    };
    match *subcommand {
        "full" => parse_ci_full(rest),
        "local" => ci_impact::parse_local_options(rest).map(Command::CiLocal),
        "plan" => ci_impact::parse_options(rest).map(Command::CiPlan),
        "run" => parse_ci_run(rest),
        "gate" => ci_gate::parse_options(rest).map(Command::CiGate),
        other => bail!("ci 未知子命令: {other}；用法: cargo xtask ci <local|full|plan|run|gate>"),
    }
}

fn parse_ci_full(args: &[&str]) -> Result<Command> {
    let mut allow_missing_tools = false;
    let mut fail_fast = false;
    for &tok in args {
        match tok {
            "--allow-missing-tools" if !allow_missing_tools => allow_missing_tools = true,
            "--fail-fast" if !fail_fast => fail_fast = true,
            other => {
                bail!(
                    "ci full 未知或重复参数: {other}；用法: cargo xtask ci full [--allow-missing-tools] [--fail-fast]"
                )
            }
        }
    }
    Ok(Command::CiFull {
        allow_missing_tools,
        fail_fast,
    })
}

fn parse_ci_run(args: &[&str]) -> Result<Command> {
    let mut job = None;
    let mut required_evidence_output = None;
    let mut iter = args.iter().copied();
    while let Some(token) = iter.next() {
        match token {
            "--job" if job.is_none() => {
                job = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("ci run --job 缺少 CiJobKey"))?
                        .parse()?,
                )
            }
            "--required-evidence-output" if required_evidence_output.is_none() => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("ci run --required-evidence-output 缺少路径"))?;
                let path = PathBuf::from(value);
                if value.is_empty() || value.starts_with("--") || path.file_name().is_none() {
                    bail!(
                        "ci run --required-evidence-output 必须是含文件名的非空路径，不能是 flag"
                    );
                }
                required_evidence_output = Some(path);
            }
            other => {
                bail!(
                    "ci run 未知或重复参数: {other}；用法: cargo xtask ci run --job <CiJobKey> [--required-evidence-output <path>]"
                )
            }
        }
    }
    Ok(Command::CiRun {
        job: job.context("ci run 缺少 --job")?,
        required_evidence_output,
    })
}

/// 解析 `public-api` 的可选 flag（fail-closed：未知 flag / 缺 layer 值 / 非法 layer 即 `Err`）。
fn parse_public_api(args: &[&str]) -> Result<Command> {
    let mut check = false;
    let mut allow_missing = false;
    let mut layer = None;
    let mut it = args.iter();
    while let Some(&tok) = it.next() {
        match tok {
            "--check" => check = true,
            "--allow-missing" => allow_missing = true,
            "--layer" => {
                let val = it.next().ok_or_else(|| {
                    anyhow::anyhow!("--layer 缺少值；用法: --layer basis|engine|curated")
                })?;
                layer = Some(match *val {
                    "basis" => publicapi::Layer::Basis,
                    "engine" => publicapi::Layer::Engine,
                    "curated" => publicapi::Layer::Curated,
                    other => bail!("未知 layer: {other}；用法: --layer basis|engine|curated"),
                });
            }
            other => bail!(
                "public-api 未知参数: {other}；用法: --layer basis|engine|curated | --check | --allow-missing"
            ),
        }
    }
    Ok(Command::PublicApi {
        check,
        allow_missing,
        layer,
    })
}

fn dispatch(args: &[String]) -> Result<()> {
    match parse_command(args)? {
        Command::Codegen { check } => codegen::run(check),
        Command::CdcConfigDebezium => cdc_config::run_debezium(),
        Command::ContractValidate => diagnostic::run_check(&contract::validate::ContractValidate),
        Command::AssemblyValidate => diagnostic::run_check(&assembly::AssemblyValidate),
        Command::AssemblyArtifactsCheck => assembly_artifacts::run(),
        Command::AssemblyGenerateModules { check } => assembly_codegen::run(check),
        Command::AssemblyGenerateProviders { check } => assembly_codegen::run_providers(check),
        Command::AssemblyGenerateRuntimePlans { check } => assembly_runtime_plan::run(check),
        Command::AssemblyLock(action) => assembly_lock::run(action),
        Command::GraphAssembly(options) => graph::run(&options),
        Command::ArchRulesList => archrules::list(),
        Command::ArchRulesVerify => diagnostic::run_check(&archrules::ArchRules),
        Command::ArchRulesMatrix(action) => archrules::matrix(action),
        Command::RuntimeBaselineList => runtime_baseline::list(),
        Command::RuntimeBaselineVerify => diagnostic::run_check(&runtime_baseline::RuntimeBaseline),
        Command::RuntimeRootGuard => diagnostic::run_check(&runtime_root_guard::RuntimeRootGuard),
        Command::RuntimeDepsGuard => diagnostic::run_check(&runtime_deps_guard::RuntimeDepsGuard),
        Command::RuntimeEnvGuard => diagnostic::run_check(&runtime_env_guard::RuntimeEnvGuard),
        Command::ContractBreaking { against } => {
            let against =
                against.unwrap_or_else(|| contract::breaking::DEFAULT_AGAINST.to_string());
            contract::breaking::run(&against)
        }
        Command::LayerDeps => diagnostic::run_check(&layerdeps::LayerDeps),
        Command::WsDepsDrift => diagnostic::run_check(&wsdeps::WsDepsDrift),
        Command::SourceSemanticGuard => {
            diagnostic::run_check(&source_semantic_guard::SourceSemanticGuard)
        }
        Command::PromtoolRules => promtool::run(),
        Command::OutboxSameIdGuard => {
            diagnostic::run_check(&outbox_same_id_guard::OutboxSameIdGuard)
        }
        Command::ConsistencyFixtures => {
            diagnostic::run_check(&consistency_fixtures::ConsistencyFixtures)
        }
        Command::ConsistencyLocalOnlyEffects => {
            diagnostic::run_check(&consistency_effects::LocalOnlyEffects)
        }
        Command::ConsistencyReport { format } => consistency_effects::run_report(format),
        Command::LocalTxReport { format } => localtx_report::run_report(format),
        Command::LocalTxCoverage => diagnostic::run_check(&localtx_coverage::LocalTxCoverage),
        Command::L2Assurance { check } => l2_assurance::run(check),
        Command::ProviderCapabilities { check } => provider_capabilities::run(check),
        Command::Verify {
            fast,
            fresh,
            allow_missing_tools,
            against,
            fail_fast,
            only,
        } => verify::run(
            fast,
            fresh,
            allow_missing_tools,
            against.as_deref(),
            fail_fast,
            &only,
        ),
        Command::PublicApi {
            check,
            allow_missing,
            layer,
        } => publicapi::run(check, allow_missing, layer),
        Command::CiFull {
            allow_missing_tools,
            fail_fast,
        } => verify::run_ci(allow_missing_tools, fail_fast),
        Command::CiLocal(options) => ci_impact::run_local(&workspace_root()?, &options),
        Command::CiRun {
            job,
            required_evidence_output,
        } => verify::run_job(job, required_evidence_output.as_deref()),
        Command::CiSloEvaluate {
            job,
            run_id,
            run_attempt,
            upload_outcome,
            summary_mode,
        } => complete_ci_slo(
            ci_slo::run_with_mode(
                &workspace_root()?,
                job,
                &run_id,
                &run_attempt,
                upload_outcome,
                summary_mode,
            ),
            job,
            &run_id,
            &run_attempt,
            upload_outcome,
            summary_mode,
        ),
        Command::CiPlan(options) => ci_impact::run(&workspace_root()?, &options),
        Command::CiGate(options) => ci_gate::run(&options),
        Command::NextestEvidenceStage => nextest::stage(&workspace_root()?),
        Command::NextestEvidenceInspect { artifact_root } => nextest::inspect(&artifact_root),
        Command::NextestEvidenceReplay { sidecar } => nextest::replay(&sidecar, &workspace_root()?),
        Command::SchemaRls => diagnostic::run_check(&schema_rls::SchemaRlsGuard),
        Command::InboxCutoverGuard => {
            diagnostic::run_check(&inbox_cutover_guard::InboxCutoverGuard)
        }
        Command::DlxLifecycleFunnel => {
            diagnostic::run_check(&dlx_lifecycle_funnel::DlxLifecycleFunnel)
        }
        Command::SetLocalFunnel => diagnostic::run_check(&setlocal_funnel::SetLocalFunnelGuard),
        Command::PgTenantTxGuard => diagnostic::run_check(&pg_tenant_tx_guard::PgTenantTxGuard),
        Command::RepoScopeGuard => diagnostic::run_check(&repo_scope_guard::RepoScopeGuard),
        Command::ReconcileOutboxCommandGuard => {
            diagnostic::run_check(&reconcile_outbox_command_guard::ReconcileOutboxCommandGuard)
        }
        Command::TenancyCloseout => diagnostic::run_check(&tenancy_closeout::TenancyCloseout),
        Command::DeferGate => diagnostic::run_check(&defergate::DeferGate),
        Command::Migrations => diagnostic::run_check(&migrations::MigrationSerialGuard),
    }
}

fn complete_ci_slo(
    result: std::result::Result<ci_slo::Verdict, ci_slo::OperationalFailure>,
    job: ci_lanes::CiJobKey,
    run_id: &str,
    run_attempt: &str,
    upload: ci_slo::UploadOutcome,
    summary_mode: ci_slo::SummaryMode,
) -> Result<()> {
    match result {
        Ok(ci_slo::Verdict::Pass | ci_slo::Verdict::Warn) => Ok(()),
        Ok(ci_slo::Verdict::Fail) => bail!("CI SLO critical disk budget failed"),
        Err(error) => {
            let summary =
                ci_slo::render_operational_error(job, run_id, run_attempt, upload, error.kind());
            ci_slo::emit_summary(&summary, summary_mode)?;
            Err(error.into())
        }
    }
}

/// workspace 根 = xtask manifest 目录的父目录。取编译期 `CARGO_MANIFEST_DIR`，
/// **不**用运行期 `current_dir`——防 nextest 进程隔离 / 不同 cwd 下漂移。
pub(crate) fn workspace_root() -> Result<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow::anyhow!("xtask manifest 目录无父目录"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_command_codegen_no_check() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["codegen"]))?,
            Command::Codegen { check: false }
        );
        Ok(())
    }

    #[test]
    fn parse_command_codegen_with_check() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["codegen", "--check"]))?,
            Command::Codegen { check: true }
        );
        Ok(())
    }

    #[test]
    fn parse_command_localtx_coverage_is_exact() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["localtx-coverage"]))?,
            Command::LocalTxCoverage
        );
        assert!(parse_command(&s(&["localtx-coverage", "--check"])).is_err());
        assert!(parse_command(&s(&["localtx_coverage"])).is_err());
        Ok(())
    }

    #[test]
    fn parse_command_localtx_report_requires_exact_format() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["localtx", "report", "--format", "json"]))?,
            Command::LocalTxReport {
                format: ReportFormat::Json,
            }
        );
        assert_eq!(
            parse_command(&s(&["localtx", "report", "--format", "markdown"]))?,
            Command::LocalTxReport {
                format: ReportFormat::Markdown,
            }
        );
        for bad in [
            s(&["localtx", "report"]),
            s(&["localtx", "report", "--format"]),
            s(&["localtx", "report", "--format", "md"]),
            s(&["localtx", "report", "--format", "json", "extra"]),
            s(&[
                "localtx", "report", "--format", "json", "--format", "markdown",
            ]),
            s(&["localtx", "report", "--output", "report.json"]),
        ] {
            assert!(
                parse_command(&bad).is_err(),
                "unexpectedly accepted {bad:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn parse_same_id_and_promtool_gates_are_exact() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["outbox-same-id-guard"]))?,
            Command::OutboxSameIdGuard
        );
        assert_eq!(
            parse_command(&s(&["promtool-rules"]))?,
            Command::PromtoolRules
        );
        assert!(parse_command(&s(&["outbox-same-id-guard", "extra"])).is_err());
        assert!(parse_command(&s(&["promtool-rules", "--allow-missing"])).is_err());
        Ok(())
    }

    #[test]
    fn parse_command_usage_lists_localtx_coverage() -> anyhow::Result<()> {
        let error = match parse_command(&s(&[])) {
            Ok(command) => anyhow::bail!("empty argv unexpectedly parsed as {command:?}"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("localtx-coverage"), "{error}");
        assert!(error.to_string().contains("graph assembly"), "{error}");
        Ok(())
    }

    #[test]
    fn parse_command_cdc_config_debezium() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["cdc-config", "debezium"]))?,
            Command::CdcConfigDebezium
        );
        Ok(())
    }

    #[test]
    fn parse_command_cdc_config_rejects_bad_args() {
        assert!(parse_command(&s(&["cdc-config"])).is_err());
        assert!(parse_command(&s(&["cdc-config", "kafka"])).is_err());
        assert!(parse_command(&s(&["cdc-config", "debezium", "--bogus"])).is_err());
    }

    #[test]
    fn parse_command_contract_validate() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["contract", "validate"]))?,
            Command::ContractValidate
        );
        Ok(())
    }

    #[test]
    fn parse_command_assembly_validate() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["assembly", "validate"]))?,
            Command::AssemblyValidate
        );
        Ok(())
    }

    #[test]
    fn assembly_artifacts_cli_is_exact_and_fail_closed() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["assembly", "artifacts", "check"]))?,
            Command::AssemblyArtifactsCheck
        );
        for invalid in [
            vec!["assembly", "artifacts"],
            vec!["assembly", "artifacts", "check", "--format", "json"],
            vec!["assembly", "artifacts", "check", "extra"],
            vec!["assembly", "artifact", "check"],
            vec!["assembly-artifacts", "check"],
        ] {
            assert!(
                parse_command(&s(&invalid)).is_err(),
                "unexpected compatibility surface accepted: {invalid:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn parse_command_assembly_generate_modules() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["assembly", "generate-modules"]))?,
            Command::AssemblyGenerateModules { check: false }
        );
        assert_eq!(
            parse_command(&s(&["assembly", "generate-modules", "--check"]))?,
            Command::AssemblyGenerateModules { check: true }
        );
        Ok(())
    }

    #[test]
    fn parse_command_assembly_generate_modules_rejects_bad_args() {
        assert!(parse_command(&s(&["assembly", "generate-modules", "--bogus"])).is_err());
        assert!(parse_command(&s(&["assembly", "generate-modules", "--check", "extra"])).is_err());
    }

    #[test]
    fn assembly_provider_codegen_cli_is_exact_and_fail_closed() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["assembly", "generate-providers"]))?,
            Command::AssemblyGenerateProviders { check: false }
        );
        assert_eq!(
            parse_command(&s(&["assembly", "generate-providers", "--check"]))?,
            Command::AssemblyGenerateProviders { check: true }
        );
        for invalid in [
            vec!["assembly", "generate-providers", "--bogus"],
            vec!["assembly", "generate-providers", "--check", "--check"],
            vec!["assembly", "generate-providers", "--check", "extra"],
            vec!["assembly", "generate-providers", "SECRET_BAIT"],
        ] {
            assert!(
                parse_command(&s(&invalid)).is_err(),
                "invalid provider codegen argv accepted: {invalid:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn assembly_runtime_plan_codegen_cli_is_exact_and_fail_closed() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["assembly", "generate-runtime-plans"]))?,
            Command::AssemblyGenerateRuntimePlans { check: false }
        );
        assert_eq!(
            parse_command(&s(&["assembly", "generate-runtime-plans", "--check"]))?,
            Command::AssemblyGenerateRuntimePlans { check: true }
        );
        for invalid in [
            vec!["assembly", "generate-runtime-plans", "--bogus"],
            vec!["assembly", "generate-runtime-plans", "--check", "--check"],
            vec!["assembly", "generate-runtime-plan"],
            vec!["assembly", "runtime-plans", "generate"],
        ] {
            assert!(
                parse_command(&s(&invalid)).is_err(),
                "invalid runtime-plan codegen argv accepted: {invalid:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn parse_command_assembly_lock_is_exact_and_fail_closed() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["assembly", "lock", "generate"]))?,
            Command::AssemblyLock(assembly_lock::AssemblyLockAction::Generate)
        );
        assert_eq!(
            parse_command(&s(&["assembly", "lock", "check"]))?,
            Command::AssemblyLock(assembly_lock::AssemblyLockAction::Check)
        );
        for invalid in [
            vec!["assembly", "lock"],
            vec!["assembly", "lock", "--check"],
            vec!["assembly", "lock", "generate", "runtime"],
            vec!["assembly", "lock", "check", "SECRET_BAIT"],
        ] {
            let error = match parse_command(&s(&invalid)) {
                Ok(command) => anyhow::bail!("invalid lock argv parsed as {command:?}"),
                Err(error) => error,
            };
            assert!(!error.to_string().contains("SECRET_BAIT"));
        }
        Ok(())
    }

    #[test]
    fn parse_command_graph_assembly_is_exact_and_fail_closed() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["graph", "assembly"]))?,
            Command::GraphAssembly(graph::Options::default())
        );
        assert_eq!(
            parse_command(&s(&["graph", "assembly", "--check"]))?,
            Command::GraphAssembly(graph::Options::check_runtime())
        );
        assert!(parse_command(&s(&["graph"])).is_err());
        assert!(parse_command(&s(&["graph", "assembly", "--format"])).is_err());
        assert!(parse_command(&s(&["graph", "assembly", "--format", "--check"])).is_err());
        assert!(parse_command(&s(&["graph", "assembly", "--assembly", "--check"])).is_err());
        assert!(parse_command(&s(&["graph", "assembly", "--assembly", "../runtime"])).is_err());
        Ok(())
    }

    #[test]
    fn parse_command_archrules_list_verify() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["archrules", "list"]))?,
            Command::ArchRulesList
        );
        assert_eq!(
            parse_command(&s(&["archrules", "verify"]))?,
            Command::ArchRulesVerify
        );
        assert_eq!(
            parse_command(&s(&["archrules", "matrix"]))?,
            Command::ArchRulesMatrix(archrules::MatrixAction::Print)
        );
        assert_eq!(
            parse_command(&s(&["archrules", "matrix", "--write"]))?,
            Command::ArchRulesMatrix(archrules::MatrixAction::Write)
        );
        assert_eq!(
            parse_command(&s(&["archrules", "matrix", "--check"]))?,
            Command::ArchRulesMatrix(archrules::MatrixAction::Check)
        );
        Ok(())
    }

    #[test]
    fn parse_command_archrules_rejects_bad() {
        assert!(parse_command(&s(&["archrules"])).is_err());
        assert!(parse_command(&s(&["archrules", "--list"])).is_err());
        assert!(parse_command(&s(&["archrules", "list", "extra"])).is_err());
        assert!(parse_command(&s(&["archrules", "bogus"])).is_err());
        assert!(parse_command(&s(&["archrules", "matrix", "--bogus"])).is_err());
    }

    #[test]
    fn parse_command_runtime_baseline() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["runtime-baseline", "list"]))?,
            Command::RuntimeBaselineList
        );
        assert_eq!(
            parse_command(&s(&["runtime-baseline", "verify"]))?,
            Command::RuntimeBaselineVerify
        );
        assert!(parse_command(&s(&["runtime-baseline"])).is_err());
        assert!(parse_command(&s(&["runtime-baseline", "--list"])).is_err());
        assert!(parse_command(&s(&["runtime-baseline", "list", "extra"])).is_err());
        assert!(parse_command(&s(&["runtime-baseline", "bogus"])).is_err());
        Ok(())
    }

    #[test]
    fn parse_command_runtime_deps_guard() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["runtime-deps", "guard"]))?,
            Command::RuntimeDepsGuard
        );
        assert!(parse_command(&s(&["runtime-deps"])).is_err());
        assert!(parse_command(&s(&["runtime-deps", "--guard"])).is_err());
        assert!(parse_command(&s(&["runtime-deps", "guard", "extra"])).is_err());
        assert!(parse_command(&s(&["runtime-deps", "bogus"])).is_err());
        Ok(())
    }

    #[test]
    fn parse_command_runtime_root_guard_is_exact() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["runtime-root", "guard"]))?,
            Command::RuntimeRootGuard
        );
        for bad in [
            s(&["runtime-root"]),
            s(&["runtime-root", "--guard"]),
            s(&["runtime-root", "guard", "extra"]),
            s(&["runtime_root", "guard"]),
        ] {
            assert!(parse_command(&bad).is_err(), "accepted {bad:?}");
        }
        Ok(())
    }

    #[test]
    fn parse_command_runtime_env_guard() {
        assert!(matches!(
            parse_command(&s(&["runtime-env", "guard"])),
            Ok(Command::RuntimeEnvGuard)
        ));
        assert!(parse_command(&s(&["runtime-env"])).is_err());
        assert!(parse_command(&s(&["runtime-env", "guard", "extra"])).is_err());
        assert!(parse_command(&s(&["runtime_env", "guard"])).is_err());
    }

    #[test]
    fn parse_command_contract_breaking_bare() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["contract", "breaking"]))?,
            Command::ContractBreaking { against: None }
        );
        Ok(())
    }

    #[test]
    fn parse_command_contract_breaking_flags() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["contract", "breaking", "--against", "HEAD~1"]))?,
            Command::ContractBreaking {
                against: Some("HEAD~1".to_string())
            }
        );
        assert!(parse_command(&s(&["contract", "breaking", "--deny"])).is_err());
        Ok(())
    }

    /// contract 子命令 fail-closed：未知子命令 / 未知 flag / `--against` 缺值均 `Err`。
    #[test]
    fn parse_command_contract_rejects_bad() {
        assert!(parse_command(&s(&["contract", "bogus"])).is_err());
        assert!(parse_command(&s(&["contract", "validate", "--bogus"])).is_err());
        assert!(parse_command(&s(&["contract", "breaking", "--bogus"])).is_err());
        assert!(parse_command(&s(&["contract", "breaking", "--against"])).is_err()); // 缺值
        assert!(parse_command(&s(&["assembly", "bogus"])).is_err());
        assert!(parse_command(&s(&["assembly", "validate", "--bogus"])).is_err());
    }

    #[test]
    fn contract_usage_does_not_advertise_removed_deny_flag() -> anyhow::Result<()> {
        let error = match parse_command(&s(&["contract", "bogus"])) {
            Ok(_) => anyhow::bail!("unknown contract subcommand must fail"),
            Err(error) => error.to_string(),
        };
        assert_eq!(
            error,
            "未知 contract 子命令: [\"bogus\"]；用法: cargo xtask contract <validate | breaking [--against <git-ref>]>"
        );
        assert!(!error.contains("--deny"));
        Ok(())
    }

    #[test]
    fn parse_command_layer_deps() -> anyhow::Result<()> {
        assert_eq!(parse_command(&s(&["layer-deps"]))?, Command::LayerDeps);
        Ok(())
    }

    #[test]
    fn parse_command_wsdeps_drift() -> anyhow::Result<()> {
        assert_eq!(parse_command(&s(&["wsdeps-drift"]))?, Command::WsDepsDrift);
        Ok(())
    }

    #[test]
    fn parse_command_reconcile_outbox_command_guard() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["reconcile-outbox-command-guard"]))?,
            Command::ReconcileOutboxCommandGuard
        );
        Ok(())
    }

    #[test]
    fn removed_doc_contracts_command_is_rejected() {
        assert!(parse_command(&s(&["doc-contracts"])).is_err());
    }

    #[test]
    fn parse_command_source_semantic_guard() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["source-semantic-guard"]))?,
            Command::SourceSemanticGuard
        );
        assert!(parse_command(&s(&["source-semantic-guard", "extra"])).is_err());
        Ok(())
    }

    #[test]
    fn parse_command_consistency_fixtures() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["consistency-fixtures"]))?,
            Command::ConsistencyFixtures
        );
        Ok(())
    }

    /// wsdeps-drift fail-closed：未知尾参即 `Err`。
    #[test]
    fn parse_command_wsdeps_drift_rejects_trailing_args() {
        assert!(parse_command(&s(&["wsdeps-drift", "--bogus"])).is_err());
        assert!(parse_command(&s(&["wsdeps-drift", "extra"])).is_err());
    }

    #[test]
    fn parse_command_consistency_fixtures_rejects_trailing_args() {
        assert!(parse_command(&s(&["consistency-fixtures", "--bogus"])).is_err());
        assert!(parse_command(&s(&["consistency-fixtures", "extra"])).is_err());
    }

    #[test]
    fn parse_command_consistency_local_only_effects_is_exact() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["consistency", "local-only-effects"]))?,
            Command::ConsistencyLocalOnlyEffects
        );
        for bad in [
            s(&["consistency"]),
            s(&["consistency", "effects"]),
            s(&["consistency", "local-only-effects", "extra"]),
            s(&["consistency", "local-only-effects", "--bogus"]),
        ] {
            assert!(
                parse_command(&bad).is_err(),
                "unexpectedly accepted {bad:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn parse_command_consistency_report_requires_exact_format() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["consistency", "report", "--format", "json"]))?,
            Command::ConsistencyReport {
                format: ReportFormat::Json,
            }
        );
        assert_eq!(
            parse_command(&s(&["consistency", "report", "--format", "md"]))?,
            Command::ConsistencyReport {
                format: ReportFormat::Markdown,
            }
        );
        for bad in [
            s(&["consistency", "report"]),
            s(&["consistency", "report", "--format"]),
            s(&["consistency", "report", "--format", "markdown"]),
            s(&["consistency", "report", "--format", "json", "extra"]),
            s(&[
                "consistency",
                "report",
                "--format",
                "json",
                "--format",
                "md",
            ]),
            s(&["consistency", "report", "--output", "report.json"]),
        ] {
            assert!(
                parse_command(&bad).is_err(),
                "unexpectedly accepted {bad:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn parse_command_verify_bare() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["verify"]))?,
            Command::Verify {
                fast: false,
                fresh: false,
                allow_missing_tools: false,
                against: None,
                fail_fast: false,
                only: Vec::new(),
            }
        );
        Ok(())
    }

    #[test]
    fn parse_command_verify_flags() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["verify", "--fast", "--fresh"]))?,
            Command::Verify {
                fast: true,
                fresh: true,
                allow_missing_tools: false,
                against: None,
                fail_fast: false,
                only: Vec::new(),
            }
        );
        assert_eq!(
            parse_command(&s(&["verify", "--fast"]))?,
            Command::Verify {
                fast: true,
                fresh: false,
                allow_missing_tools: false,
                against: None,
                fail_fast: false,
                only: Vec::new(),
            }
        );
        assert_eq!(
            parse_command(&s(&["verify", "--allow-missing-tools"]))?,
            Command::Verify {
                fast: false,
                fresh: false,
                allow_missing_tools: true,
                against: None,
                fail_fast: false,
                only: Vec::new(),
            }
        );
        assert_eq!(
            parse_command(&s(&["verify", "--fast", "--allow-missing-tools"]))?,
            Command::Verify {
                fast: true,
                fresh: false,
                allow_missing_tools: true,
                against: None,
                fail_fast: false,
                only: Vec::new(),
            }
        );
        assert_eq!(
            parse_command(&s(&[
                "verify",
                "--fail-fast",
                "--only",
                "clippy",
                "--only",
                "build",
            ]))?,
            Command::Verify {
                fast: false,
                fresh: false,
                allow_missing_tools: false,
                against: None,
                fail_fast: true,
                only: vec!["clippy".to_owned(), "build".to_owned()],
            }
        );
        Ok(())
    }

    /// verify flag fail-closed：未知 flag 即 `Err`（不被静默吞掉）。
    #[test]
    fn parse_command_verify_rejects_unknown_flag() {
        assert!(parse_command(&s(&["verify", "--bogus"])).is_err());
        assert!(parse_command(&s(&["verify", "--fast", "extra"])).is_err());
        assert!(parse_command(&s(&["verify", "--only"])).is_err());
        assert!(parse_command(&s(&["verify", "--only", "--fast"])).is_err());
        assert!(parse_command(&s(&["verify", "--only", "fmt", "--only", "fmt"])).is_err());
        assert!(parse_command(&s(&["verify", "--fail-fast", "--fail-fast"])).is_err());
        assert!(parse_command(&s(&["verify", "--fresh"])).is_err());
        assert!(parse_command(&s(&["verify", "--fast", "--fresh", "--fresh"])).is_err());
    }

    #[test]
    fn parse_verify_accepts_one_explicit_contract_base() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&[
                "verify",
                "--fast",
                "--against",
                "0123456789abcdef0123456789abcdef01234567",
            ]))?,
            Command::Verify {
                fast: true,
                fresh: false,
                allow_missing_tools: false,
                against: Some("0123456789abcdef0123456789abcdef01234567".to_owned()),
                fail_fast: false,
                only: Vec::new(),
            }
        );
        for args in [
            vec!["verify", "--against"],
            vec!["verify", "--against", "base", "--against", "other"],
            vec!["verify", "--against", "--fast"],
        ] {
            assert!(parse_command(&s(&args)).is_err(), "accepted {args:?}");
        }
        Ok(())
    }

    #[test]
    fn parse_command_public_api_bare() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["public-api"]))?,
            Command::PublicApi {
                check: false,
                allow_missing: false,
                layer: None
            }
        );
        Ok(())
    }

    #[test]
    fn parse_command_public_api_check_allow_missing() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["public-api", "--check", "--allow-missing"]))?,
            Command::PublicApi {
                check: true,
                allow_missing: true,
                layer: None
            }
        );
        Ok(())
    }

    #[test]
    fn parse_command_public_api_layer_basis() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["public-api", "--layer", "basis"]))?,
            Command::PublicApi {
                check: false,
                allow_missing: false,
                layer: Some(publicapi::Layer::Basis)
            }
        );
        Ok(())
    }

    #[test]
    fn parse_command_public_api_layer_engine_check() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["public-api", "--layer", "engine", "--check"]))?,
            Command::PublicApi {
                check: true,
                allow_missing: false,
                layer: Some(publicapi::Layer::Engine)
            }
        );
        Ok(())
    }

    #[test]
    fn parse_command_public_api_layer_curated_check() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["public-api", "--layer", "curated", "--check"]))?,
            Command::PublicApi {
                check: true,
                allow_missing: false,
                layer: Some(publicapi::Layer::Curated)
            }
        );
        Ok(())
    }

    /// public-api flag fail-closed：非法 layer 值 / 缺 layer 值 / 未知 flag 均 `Err`。
    #[test]
    fn parse_command_public_api_rejects_bad_flags() {
        assert!(parse_command(&s(&["public-api", "--layer", "bogus"])).is_err());
        assert!(parse_command(&s(&["public-api", "--layer"])).is_err()); // 缺值
        assert!(parse_command(&s(&["public-api", "--bogus"])).is_err());
    }

    #[test]
    fn parse_command_ci_is_closed_and_fail_closed() -> anyhow::Result<()> {
        assert!(parse_command(&s(&["ci"])).is_err());
        assert_eq!(
            parse_command(&s(&["ci", "full"]))?,
            Command::CiFull {
                allow_missing_tools: false,
                fail_fast: false,
            }
        );
        assert_eq!(
            parse_command(&s(&["ci", "full", "--allow-missing-tools"]))?,
            Command::CiFull {
                allow_missing_tools: true,
                fail_fast: false,
            }
        );
        assert_eq!(
            parse_command(&s(&["ci", "full", "--fail-fast"]))?,
            Command::CiFull {
                allow_missing_tools: false,
                fail_fast: true,
            }
        );
        assert!(matches!(
            parse_command(&s(&["ci", "local", "--base", "origin/develop"]))?,
            Command::CiLocal(_)
        ));
        assert_eq!(
            parse_command(&s(&["ci", "run", "--job", "ci-meta"]))?,
            Command::CiRun {
                job: ci_lanes::CiJobKey::CiMeta,
                required_evidence_output: None,
            }
        );
        for args in [
            vec!["ci", "--allow-missing-tools"],
            vec![
                "ci",
                "full",
                "--allow-missing-tools",
                "--allow-missing-tools",
            ],
            vec!["ci", "local"],
            vec!["ci", "local", "--base"],
            vec!["ci", "local", "--base", "develop", "--base", "main"],
            vec!["ci", "local", "--working-tree"],
            vec!["ci", "run"],
            vec!["ci", "run", "--job", "unknown"],
            vec!["ci", "run", "--job", "ci-meta", "--job", "audit"],
            vec!["ci", "wat"],
        ] {
            assert!(parse_command(&s(&args)).is_err(), "must reject {args:?}");
        }
        for old in [
            "ci-meta",
            "ci-core",
            "ci-core-prerequisites",
            "ci-core-tests",
            "ci-security",
            "ci-coverage",
            "ci-integration",
            "ci-plan",
            "ci-gate",
            "audit",
        ] {
            assert!(
                parse_command(&s(&[old])).is_err(),
                "legacy {old} must be removed"
            );
        }
        Ok(())
    }

    #[test]
    fn parse_ci_run_accepts_explicit_localtx_required_evidence_output_red() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&[
                "ci",
                "run",
                "--job",
                "integration/postgres-domain",
                "--required-evidence-output",
                "/tmp/localtx-required.json",
            ]))?,
            Command::CiRun {
                job: ci_lanes::CiJobKey::IntegrationPostgresDomain,
                required_evidence_output: Some(PathBuf::from("/tmp/localtx-required.json")),
            }
        );
        for args in [
            vec![
                "ci",
                "run",
                "--job",
                "integration/postgres-domain",
                "--required-evidence-output",
            ],
            vec![
                "ci",
                "run",
                "--job",
                "integration/postgres-domain",
                "--required-evidence-output",
                "a",
                "--required-evidence-output",
                "b",
            ],
            vec![
                "ci",
                "run",
                "--job",
                "integration/postgres-domain",
                "--required-evidence-output",
                "",
            ],
            vec![
                "ci",
                "run",
                "--job",
                "integration/postgres-domain",
                "--required-evidence-output",
                "--not-a-path",
            ],
            vec![
                "ci",
                "run",
                "--job",
                "integration/postgres-domain",
                "--required-evidence-output",
                "/",
            ],
        ] {
            assert!(parse_command(&s(&args)).is_err(), "must reject {args:?}");
        }
        Ok(())
    }

    #[test]
    fn removed_integration_entrypoints_fail_closed() {
        assert!(parse_command(&s(&["consistency-fault-matrix"])).is_err());
        assert!(parse_command(&s(&["consistency-fault-matrix", "--bogus"])).is_err());
        assert!(parse_command(&s(&["integration"])).is_err());
    }

    #[test]
    fn nextest_evidence_commands_are_exact_and_fail_closed() {
        assert_eq!(
            parse_command(&s(&["nextest-evidence", "stage"])).ok(),
            Some(Command::NextestEvidenceStage)
        );
        assert!(matches!(
            parse_command(&s(&["nextest-evidence", "inspect", "artifact"])),
            Ok(Command::NextestEvidenceInspect { .. })
        ));
        assert!(matches!(
            parse_command(&s(&["nextest-evidence", "replay", "sidecar.json"])),
            Ok(Command::NextestEvidenceReplay { .. })
        ));
        for args in [
            vec!["nextest-evidence"],
            vec!["nextest-evidence", "stage", "extra"],
            vec!["nextest-evidence", "inspect"],
            vec!["nextest-evidence", "replay", "a", "b"],
            vec!["nextest-replay", "--coverage"],
        ] {
            assert!(parse_command(&s(&args)).is_err());
        }
    }

    #[test]
    fn ci_slo_command_is_exact_typed_and_fail_closed() {
        let meta = parse_command(&s(&[
            "ci-slo",
            "evaluate",
            "--lane",
            "ci-meta",
            "--run-id",
            "42",
            "--run-attempt",
            "3",
            "--upload-outcome",
            "success",
        ]));
        assert!(matches!(
            meta,
            Ok(Command::CiSloEvaluate {
                job: ci_lanes::CiJobKey::CiMeta,
                ..
            })
        ));
        let integration = parse_command(&s(&[
            "ci-slo",
            "evaluate",
            "--lane",
            "integration",
            "--shard",
            "event-transport",
            "--partition",
            "1/2",
            "--run-id",
            "42",
            "--run-attempt",
            "3",
            "--upload-outcome",
            "failure",
            "--github-summary",
        ]));
        assert!(matches!(
            integration,
            Ok(Command::CiSloEvaluate {
                job: ci_lanes::CiJobKey::IntegrationEventTransport1Of2,
                summary_mode: ci_slo::SummaryMode::Github,
                ..
            })
        ));
        for args in [
            vec!["ci-slo"],
            vec!["ci-slo", "evaluate"],
            vec![
                "ci-slo",
                "evaluate",
                "--lane",
                "ci-meta",
                "--run-id",
                "x",
                "--run-attempt",
                "3",
                "--upload-outcome",
                "success",
            ],
            vec![
                "ci-slo",
                "evaluate",
                "--lane",
                "ci-meta",
                "--run-id",
                "42",
                "--run-attempt",
                "3",
                "--upload-outcome",
                "success",
                "--github-summary",
                "--github-summary",
            ],
            vec![
                "ci-slo",
                "evaluate",
                "--lane",
                "ci-meta",
                "--shard",
                "postgres-domain",
                "--run-id",
                "42",
                "--run-attempt",
                "3",
                "--upload-outcome",
                "success",
            ],
            vec![
                "ci-slo",
                "evaluate",
                "--lane",
                "integration",
                "--shard",
                "event-transport",
                "--run-id",
                "42",
                "--run-attempt",
                "3",
                "--upload-outcome",
                "success",
            ],
            vec![
                "ci-slo",
                "evaluate",
                "--lane",
                "ci-meta",
                "--run-id",
                "42",
                "--run-id",
                "43",
                "--run-attempt",
                "3",
                "--upload-outcome",
                "success",
            ],
            vec![
                "ci-slo",
                "evaluate",
                "--lane",
                "ci-meta",
                "--run-id",
                "42",
                "--run-attempt",
                "3",
                "--upload-outcome",
                "unknown",
            ],
            vec![
                "ci-slo",
                "evaluate",
                "--lane",
                "ci-meta",
                "--run-id",
                "42",
                "--run-attempt",
                "3",
                "--upload-outcome",
                "success",
                "--config",
                "other.toml",
            ],
        ] {
            assert!(parse_command(&s(&args)).is_err(), "must reject {args:?}");
        }
    }

    #[test]
    fn ci_plan_and_gate_commands_are_exact_and_fail_closed() {
        assert!(matches!(
            parse_command(&s(&[
                "ci",
                "plan",
                "--event-path",
                "event.json",
                "--policy",
                ".config/ci-impact.toml",
                "--output",
                "plan.json",
                "--github-output",
                "github-output",
            ])),
            Ok(Command::CiPlan(_))
        ));
        assert!(matches!(
            parse_command(&s(&[
                "ci",
                "gate",
                "--plan",
                "plan.json",
                "--receipts",
                "receipts",
                "--planner-result",
                "success",
                "--matrix-result",
                "success",
                "--metrics-output",
                "metrics.json",
            ])),
            Ok(Command::CiGate(_))
        ));
        for args in [
            vec!["ci", "plan"],
            vec![
                "ci",
                "plan",
                "--event-path",
                "event.json",
                "--event-path",
                "other",
            ],
            vec!["ci", "gate"],
            vec![
                "ci",
                "gate",
                "--plan",
                "plan.json",
                "--receipts",
                "receipts",
                "--planner-result",
                "neutral",
                "--matrix-result",
                "success",
                "--metrics-output",
                "metrics.json",
            ],
        ] {
            assert!(parse_command(&s(&args)).is_err(), "must reject {args:?}");
        }
    }

    #[test]
    fn ci_slo_dispatch_and_operational_summary_cover_all_outcomes() {
        let job = ci_lanes::CiJobKey::CiMeta;
        for verdict in [ci_slo::Verdict::Pass, ci_slo::Verdict::Warn] {
            assert!(
                complete_ci_slo(
                    Ok(verdict),
                    job,
                    "42",
                    "3",
                    ci_slo::UploadOutcome::Success,
                    ci_slo::SummaryMode::Stdout,
                )
                .is_ok()
            );
        }
        assert!(
            complete_ci_slo(
                Ok(ci_slo::Verdict::Fail),
                job,
                "42",
                "3",
                ci_slo::UploadOutcome::Success,
                ci_slo::SummaryMode::Stdout,
            )
            .is_err()
        );
        assert!(
            complete_ci_slo(
                Err(ci_slo::OperationalFailure::new(
                    ci_slo::OperationalErrorKind::Evidence,
                    anyhow::anyhow!("synthetic operational failure"),
                )),
                job,
                "42",
                "3",
                ci_slo::UploadOutcome::Failure,
                ci_slo::SummaryMode::Stdout,
            )
            .is_err()
        );

        for outcome in [
            ci_slo::UploadOutcome::Failure,
            ci_slo::UploadOutcome::Cancelled,
            ci_slo::UploadOutcome::Skipped,
        ] {
            let summary = ci_slo::render_operational_error(
                job,
                "42",
                "3",
                outcome,
                ci_slo::OperationalErrorKind::Evidence,
            );
            assert!(summary.contains("Evidence artifact: unavailable"));
            assert!(!summary.contains("ci-evidence-ci-meta"));
        }
        let uploaded = ci_slo::render_operational_error(
            job,
            "42",
            "3",
            ci_slo::UploadOutcome::Success,
            ci_slo::OperationalErrorKind::Evidence,
        );
        assert!(
            uploaded
                .contains("Evidence artifact: `ci-evidence-ci-meta-workspace-unpartitioned-42-3`")
        );
    }

    #[test]
    fn parse_command_unknown_returns_err() {
        assert!(parse_command(&[]).is_err());
        assert!(parse_command(&s(&["bogus"])).is_err());
        assert!(parse_command(&s(&["contract"])).is_err()); // 缺 validate
        assert!(parse_command(&s(&["contract", "bogus"])).is_err());
        assert!(parse_command(&s(&["assembly"])).is_err()); // 缺 validate
        assert!(parse_command(&s(&["assembly", "bogus"])).is_err());
    }

    #[test]
    fn parse_command_l2_assurance_is_closed() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["l2-assurance"]))?,
            Command::L2Assurance { check: false }
        );
        assert_eq!(
            parse_command(&s(&["l2-assurance", "--check"]))?,
            Command::L2Assurance { check: true }
        );
        for invalid in [
            vec!["l2-assurance", "--check", "--check"],
            vec!["l2-assurance", "--output", "inventory.json"],
            vec!["l2-assurance", "--bogus"],
            vec!["l2-assurance", "extra"],
        ] {
            let Err(error) = parse_command(&s(&invalid)) else {
                anyhow::bail!("accepted invalid l2-assurance argv: {invalid:?}");
            };
            assert!(
                error
                    .to_string()
                    .contains("./hack/cargo.sh xtask l2-assurance [--check]"),
                "missing dedicated recovery hint for {invalid:?}: {error}"
            );
        }
        Ok(())
    }

    #[test]
    fn parse_command_provider_capabilities_is_closed() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["provider-capabilities"]))?,
            Command::ProviderCapabilities { check: false }
        );
        assert_eq!(
            parse_command(&s(&["provider-capabilities", "--check"]))?,
            Command::ProviderCapabilities { check: true }
        );
        for invalid in [
            vec!["provider-capabilities", "--check", "--check"],
            vec!["provider-capabilities", "--output", "matrix.json"],
            vec!["provider-capabilities", "--bogus"],
            vec!["provider-capabilities", "extra"],
        ] {
            let Err(error) = parse_command(&s(&invalid)) else {
                anyhow::bail!("accepted invalid provider-capabilities argv: {invalid:?}");
            };
            assert!(
                error
                    .to_string()
                    .contains("./hack/cargo.sh xtask provider-capabilities [--check]"),
                "missing dedicated recovery hint for {invalid:?}: {error}"
            );
        }
        Ok(())
    }

    /// 合法子命令后的未知尾参必须 fail-closed（不被静默吞掉）。
    #[test]
    fn parse_command_rejects_trailing_unknown_args() {
        assert!(parse_command(&s(&["verify", "--bogus"])).is_err());
        assert!(parse_command(&s(&["layer-deps", "--bogus"])).is_err());
        assert!(parse_command(&s(&["contract", "validate", "--bogus"])).is_err());
        assert!(parse_command(&s(&["assembly", "validate", "--bogus"])).is_err());
        assert!(parse_command(&s(&["codegen", "--bogus"])).is_err());
        assert!(parse_command(&s(&["codegen", "--check", "--bogus"])).is_err());
        assert!(parse_command(&s(&["codegen", "--check", "extra"])).is_err());
        assert!(parse_command(&s(&["public-api", "--bogus"])).is_err());
        assert!(parse_command(&s(&["public-api", "--check", "extra"])).is_err());
    }

    #[test]
    fn dispatch_rejects_unknown_and_incomplete() {
        assert!(dispatch(&[]).is_err());
        assert!(dispatch(&["bogus".to_string()]).is_err());
        assert!(dispatch(&["contract".to_string()]).is_err()); // 缺 validate 子命令
        assert!(dispatch(&["contract".to_string(), "bogus".to_string()]).is_err());
        // 尾参 fail-closed（dispatch 经 parse_command）。
        assert!(dispatch(&["verify".to_string(), "--bogus".to_string()]).is_err());
    }

    #[test]
    fn workspace_root_is_repo_root_with_contracts() -> anyhow::Result<()> {
        let root = workspace_root()?;
        assert!(root.join("contracts").is_dir());
        assert!(root.join("generated").is_dir());
        Ok(())
    }

    #[test]
    fn parse_command_schema_rls() -> anyhow::Result<()> {
        assert_eq!(parse_command(&s(&["schema-rls"]))?, Command::SchemaRls);
        Ok(())
    }

    /// schema-rls fail-closed：尾参即 `Err`。
    #[test]
    fn parse_command_schema_rls_rejects_trailing_args() {
        assert!(parse_command(&s(&["schema-rls", "--bogus"])).is_err());
        assert!(parse_command(&s(&["schema-rls", "extra"])).is_err());
    }

    #[test]
    fn parse_command_inbox_cutover_guard() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["inbox-cutover-guard"]))?,
            Command::InboxCutoverGuard
        );
        Ok(())
    }

    /// inbox-cutover-guard fail-closed：尾参即 `Err`。
    #[test]
    fn parse_command_inbox_cutover_guard_rejects_trailing_args() {
        assert!(parse_command(&s(&["inbox-cutover-guard", "--bogus"])).is_err());
        assert!(parse_command(&s(&["inbox-cutover-guard", "extra"])).is_err());
    }

    #[test]
    fn parse_command_dlx_lifecycle_funnel() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["dlx-lifecycle-funnel"]))?,
            Command::DlxLifecycleFunnel
        );
        Ok(())
    }

    #[test]
    fn parse_command_dlx_lifecycle_funnel_rejects_trailing_args() {
        assert!(parse_command(&s(&["dlx-lifecycle-funnel", "--bogus"])).is_err());
        assert!(parse_command(&s(&["dlx-lifecycle-funnel", "extra"])).is_err());
    }

    #[test]
    fn parse_command_setlocal_funnel() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["setlocal-funnel"]))?,
            Command::SetLocalFunnel
        );
        Ok(())
    }

    /// setlocal-funnel fail-closed：尾参即 `Err`。
    #[test]
    fn parse_command_setlocal_funnel_rejects_trailing_args() {
        assert!(parse_command(&s(&["setlocal-funnel", "--bogus"])).is_err());
        assert!(parse_command(&s(&["setlocal-funnel", "extra"])).is_err());
    }

    #[test]
    fn parse_command_pg_tenant_tx_guard() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["pg-tenant-tx-guard"]))?,
            Command::PgTenantTxGuard
        );
        Ok(())
    }

    /// pg-tenant-tx-guard fail-closed：尾参即 `Err`。
    #[test]
    fn parse_command_pg_tenant_tx_guard_rejects_trailing_args() {
        assert!(parse_command(&s(&["pg-tenant-tx-guard", "--bogus"])).is_err());
        assert!(parse_command(&s(&["pg-tenant-tx-guard", "extra"])).is_err());
    }

    #[test]
    fn parse_command_repo_scope_guard() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["repo-scope-guard"]))?,
            Command::RepoScopeGuard
        );
        Ok(())
    }

    /// repo-scope-guard fail-closed：尾参即 `Err`。
    #[test]
    fn parse_command_repo_scope_guard_rejects_trailing_args() {
        assert!(parse_command(&s(&["repo-scope-guard", "--bogus"])).is_err());
        assert!(parse_command(&s(&["repo-scope-guard", "extra"])).is_err());
    }

    #[test]
    fn parse_command_tenancy_closeout() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["tenancy-closeout"]))?,
            Command::TenancyCloseout
        );
        Ok(())
    }

    /// tenancy-closeout fail-closed：尾参即 `Err`。
    #[test]
    fn parse_command_tenancy_closeout_rejects_trailing_args() {
        assert!(parse_command(&s(&["tenancy-closeout", "--bogus"])).is_err());
        assert!(parse_command(&s(&["tenancy-closeout", "extra"])).is_err());
    }

    #[test]
    fn parse_command_defer_gate() -> anyhow::Result<()> {
        assert_eq!(parse_command(&s(&["defer-gate"]))?, Command::DeferGate);
        Ok(())
    }

    /// defer-gate fail-closed：尾参即 `Err`。
    #[test]
    fn parse_command_defer_gate_rejects_trailing_args() {
        assert!(parse_command(&s(&["defer-gate", "--bogus"])).is_err());
        assert!(parse_command(&s(&["defer-gate", "extra"])).is_err());
    }

    #[test]
    fn parse_command_migrations() -> anyhow::Result<()> {
        assert_eq!(parse_command(&s(&["migrations"]))?, Command::Migrations);
        Ok(())
    }

    /// migrations fail-closed：尾参即 `Err`。
    #[test]
    fn parse_command_migrations_rejects_trailing_args() {
        assert!(parse_command(&s(&["migrations", "--bogus"])).is_err());
        assert!(parse_command(&s(&["migrations", "extra"])).is_err());
    }
}
