//! xtask — RSS 治理 / codegen 入口。见 docs/rules/architecture.md §xtask、§Rust 原生强制（三档载体）。
//!
//! 子命令：
//!   `cargo xtask codegen [--check]`     契约 schema → committed `generated/`（--check 为 CI 漂移门）
//!   `cargo xtask cdc-config debezium`   输出 Debezium PostgreSQL outbox_log CDC connector JSON skeleton（只读）
//!   `cargo xtask contract validate`     契约元数据校验（多规则，编号见 `contract::validate` 的 `Rule`，CI 门）
//!   `cargo xtask assembly validate`     assembly-level DI provider 声明校验（RevocationStore 持久 provider 门）
//!   `cargo xtask assembly generate-modules [--check]`
//!                                      assembly.toml domains → committed modules_gen.rs（--check 为漂移门）
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
//!   `cargo xtask doc-contracts`         文档契约片段漂移门（command/outbox tenant-aware 签名，CI 门）
//!   `cargo xtask consistency-fixtures`  consistency crash matrix fixture/DSL 治理门（#1616，CI 门）
//!   `cargo xtask consistency local-only-effects`
//!                                      active LocalOnly HTTP effect profile 治理门（#1689，CI 门）
//!   `cargo xtask consistency report --format json|md`
//!                                      active HTTP consistency/effect posture 确定性报告（只读）
//!   `cargo xtask localtx-coverage`       active LocalTx manifest/generated/route/test closure 门（CI 门）
//!   `cargo xtask runtime-baseline list|verify`
//!                                      runtime assembly baseline 清单 / 漂移门（#1656，CI 门）
//!   `cargo xtask runtime-deps guard`    SharedRuntimeDeps infra-only 字段类型守卫（WIRING-DEPS-INFRA-ONLY-01）
//!   `cargo xtask migrations`            migration 文件序号唯一性 + 连续性守卫（INVARIANT MIGRATION-SERIAL-UNIQUE-01，CI 门）
//!   `cargo xtask inbox-cutover-guard`    inbox receipt cutover 旧 token 回流守卫（CI 门）
//!   `cargo xtask pg-tenant-tx-guard`    Postgres tenant 表 raw-pool / TxManager bypass 守卫（CI 门）
//!   `cargo xtask repo-scope-guard`      domain repo port 禁裸 TenantId / RowVisibility / RowScope 签名守卫（CI 门）
//!   `cargo xtask reconcile-outbox-command-guard`
//!                                      reconcile scheduler transactional command outbox seam 守卫（CI 门）
//!   `cargo xtask tenancy-closeout`      tenancy/AuthZ/projection closeout 反向自检（CI 门）
//!   `cargo xtask verify [--fast] [--allow-missing-tools]`
//!                                      本地全量治理门聚合入口（GitHub Actions 与本地共用同一门）：fmt + meta（contract
//!                                      validate / assembly validate / layer-deps / codegen --check）+ build + Postgres
//!                                      feature compile matrix + clippy + nextest + deny + dylint；
//!                                      `--fast` 只跑无需编译的步（fmt+meta+deny）；`--allow-missing-tools` 缺外部
//!                                      工具时显式宽限（默认 fail-closed）。详见 `verify.rs`。
//!   `cargo xtask public-api [--layer basis|engine|curated] [--check] [--allow-missing]`
//!                                      封装面 baseline（包装 cargo-public-api，需 nightly rustdoc-json；无
//!                                      --layer 时检查 basis + engine + curated extras）；
//!                                      --check 缺 baseline 默认 fail-fast，--allow-missing 显式宽限（PR-0 自检）
//!   `cargo xtask ci [--allow-missing-tools]`
//!                                      CI lane **超集**聚合（issue #1132，GitHub Actions 薄壳唯一调用入口）：
//!                                      verify 全门（build/clippy 升 `--all-features --all-targets`）+ 覆盖率门
//!                                      （`cargo llvm-cov nextest` 替 nextest，单跑两子门：basis/engine ≥90% 绝对
//!                                      地板 + 本 PR diff 增量 ≥80%，见 `coverage.rs`/`diffcov.rs`）+ public-api
//!                                      --check（轴 A）+ cargo-audit（供应链漏洞，#1133）。verify 仍是本地 stable-only 快门，ci 是 CI 全工具超集。详见 `verify.rs`。
//!   `cargo xtask ci-meta|ci-core|ci-security|ci-coverage [--allow-missing-tools]`
//!                                      registry 派生的独立 CI lanes；参数精确匹配、缺工具默认 fail-closed。
//!   `cargo xtask audit [--allow-missing-tools]`
//!                                      供应链漏洞**定时刷新** lane（issue #1133，GitHub Actions `schedule:`
//!                                      cron 调用入口）：advisory-scoped `cargo deny check advisories` + `cargo audit`
//!                                      两门（皆 no-compile、快），捕获「未变依赖」新披露 CVE。详见 `verify.rs`。
//!   `cargo xtask ci-integration --shard <name> [--partition M/N] [--allow-missing-tools]`
//!                                      按 capability shard 运行真集成 target；typed registry 单源派生
//!                                      target filter、资源门与串/并行批次。
//!   `cargo xtask ci-slo evaluate --lane <lane> [--shard <shard>] [--partition M/N]
//!      --run-id <N> --run-attempt <N> --upload-outcome <success|failure|cancelled|skipped>
//!      [--github-summary]`
//!                                      严格消费 staged evidence；本地输出 Markdown，GitHub 模式把 annotation
//!                                      写 stdout、Markdown 写 runner 的 Job Summary 文件。
mod archrules;
mod assembly;
mod assembly_codegen;
mod cdc_config;
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
mod doc_contracts;
mod event_transport_guard;
mod graph;
mod inbox_cutover_guard;
mod integration_shards;
mod layerdeps;
mod layers;
mod localtx_coverage;
mod migrations;
mod pathsafe;
mod pdpallow;
mod pg_tenant_tx_guard;
mod postgres_feature_matrix;
mod publicapi;
mod reconcile_outbox_command_guard;
mod repo_scope_guard;
mod runtime_baseline;
mod runtime_deps_guard;
mod schema_rls;
mod setlocal_funnel;
mod shipped_feature_guard;
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
    AssemblyGenerateModules {
        check: bool,
    },
    GraphAssembly(graph::Options),
    ArchRulesList,
    ArchRulesVerify,
    ArchRulesMatrix(archrules::MatrixAction),
    RuntimeBaselineList,
    RuntimeBaselineVerify,
    RuntimeDepsGuard,
    ContractBreaking {
        /// base git-ref（缺省 = `contract::breaking::DEFAULT_AGAINST`）。
        against: Option<String>,
    },
    LayerDeps,
    WsDepsDrift,
    DocContracts,
    ConsistencyFixtures,
    ConsistencyLocalOnlyEffects,
    ConsistencyReport {
        format: ReportFormat,
    },
    LocalTxCoverage,
    Verify {
        fast: bool,
        allow_missing_tools: bool,
    },
    PublicApi {
        check: bool,
        allow_missing: bool,
        layer: Option<publicapi::Layer>,
    },
    Ci {
        allow_missing_tools: bool,
    },
    CiLane {
        lane: ci_lanes::CiLane,
        allow_missing_tools: bool,
    },
    CoreExecution {
        execution: verify::CoreExecution,
        allow_missing_tools: bool,
        partition: Option<nextest::HashPartition>,
    },
    Audit {
        allow_missing_tools: bool,
    },
    CiIntegration {
        shard: integration_shards::IntegrationShard,
        allow_missing_tools: bool,
        partition: Option<nextest::HashPartition>,
    },
    CiSloEvaluate {
        job: ci_lanes::CiJobKey,
        run_id: String,
        run_attempt: String,
        upload_outcome: ci_slo::UploadOutcome,
        summary_mode: ci_slo::SummaryMode,
    },
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
        ["runtime-deps", rest @ ..] => parse_runtime_deps(rest),
        ["contract", rest @ ..] => parse_contract(rest),
        ["assembly", rest @ ..] => parse_assembly(rest),
        ["graph", rest @ ..] => graph::parse(rest).map(Command::GraphAssembly),
        ["layer-deps"] => Ok(Command::LayerDeps),
        ["wsdeps-drift"] => Ok(Command::WsDepsDrift),
        ["doc-contracts"] => Ok(Command::DocContracts),
        ["consistency-fixtures"] => Ok(Command::ConsistencyFixtures),
        ["consistency", rest @ ..] => parse_consistency(rest),
        ["localtx-coverage"] => Ok(Command::LocalTxCoverage),
        ["verify", rest @ ..] => parse_verify(rest),
        ["public-api", rest @ ..] => parse_public_api(rest),
        ["ci", rest @ ..] => parse_ci(rest),
        ["ci-meta", rest @ ..] => parse_ci_lane(ci_lanes::CiLane::Meta, rest),
        ["ci-core", rest @ ..] => parse_ci_lane(ci_lanes::CiLane::Core, rest),
        ["ci-core-prerequisites", rest @ ..] => {
            parse_core_execution(verify::CoreExecution::Prerequisites, rest)
        }
        ["ci-core-tests", rest @ ..] => parse_core_execution(verify::CoreExecution::Tests, rest),
        ["ci-security", rest @ ..] => parse_ci_lane(ci_lanes::CiLane::Security, rest),
        ["ci-coverage", rest @ ..] => parse_ci_lane(ci_lanes::CiLane::Coverage, rest),
        ["audit", rest @ ..] => parse_audit(rest),
        ["ci-integration", rest @ ..] => parse_ci_integration(rest),
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
        ["setlocal-funnel"] => Ok(Command::SetLocalFunnel),
        ["pg-tenant-tx-guard"] => Ok(Command::PgTenantTxGuard),
        ["repo-scope-guard"] => Ok(Command::RepoScopeGuard),
        ["reconcile-outbox-command-guard"] => Ok(Command::ReconcileOutboxCommandGuard),
        ["tenancy-closeout"] => Ok(Command::TenancyCloseout),
        ["defer-gate"] => Ok(Command::DeferGate),
        ["migrations"] => Ok(Command::Migrations),
        other => {
            bail!(
                "未知命令: {other:?}；用法含 graph assembly | localtx-coverage | ci-core | ci-core-prerequisites | ci-core-tests --partition M/N | nextest-evidence <stage|inspect|replay>；收到 {other:?}"
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

/// 解析 `runtime-deps guard` 子命令（fail-closed：只接受 guard，不提供兼容别名）。
fn parse_runtime_deps(args: &[&str]) -> Result<Command> {
    match args {
        ["guard"] => Ok(Command::RuntimeDepsGuard),
        other => bail!("未知 runtime-deps 子命令: {other:?}；用法: cargo xtask runtime-deps guard"),
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
        ["generate-modules"] => Ok(Command::AssemblyGenerateModules { check: false }),
        ["generate-modules", "--check"] => Ok(Command::AssemblyGenerateModules { check: true }),
        other => bail!(
            "未知 assembly 子命令: {other:?}；用法: cargo xtask assembly <validate | generate-modules [--check]>"
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
    let mut allow_missing_tools = false;
    for &tok in args {
        match tok {
            "--fast" => fast = true,
            "--allow-missing-tools" => allow_missing_tools = true,
            other => bail!(
                "verify 未知参数: {other}；用法: cargo xtask verify [--fast] [--allow-missing-tools]"
            ),
        }
    }
    Ok(Command::Verify {
        fast,
        allow_missing_tools,
    })
}

/// 解析 `ci` 的可选 flag（fail-closed：未知 flag 即 `Err`）。`ci` 无 `--fast`——CI 超集恒全量跑。
fn parse_ci(args: &[&str]) -> Result<Command> {
    let mut allow_missing_tools = false;
    for &tok in args {
        match tok {
            "--allow-missing-tools" => allow_missing_tools = true,
            other => {
                bail!("ci 未知参数: {other}；用法: cargo xtask ci [--allow-missing-tools]")
            }
        }
    }
    Ok(Command::Ci {
        allow_missing_tools,
    })
}

fn parse_ci_lane(lane: ci_lanes::CiLane, args: &[&str]) -> Result<Command> {
    let mut allow_missing_tools = false;
    for &token in args {
        match token {
            "--allow-missing-tools" if !allow_missing_tools => allow_missing_tools = true,
            other => {
                let command = lane.command_name();
                bail!(
                    "{command} 未知或重复参数: {other}；用法: cargo xtask {command} [--allow-missing-tools]"
                )
            }
        }
    }
    Ok(Command::CiLane {
        lane,
        allow_missing_tools,
    })
}

fn parse_core_execution(execution: verify::CoreExecution, args: &[&str]) -> Result<Command> {
    let mut allow_missing_tools = false;
    let mut partition = None;
    let mut iter = args.iter().copied();
    while let Some(token) = iter.next() {
        match token {
            "--allow-missing-tools" if !allow_missing_tools => allow_missing_tools = true,
            "--partition" if execution == verify::CoreExecution::Tests && partition.is_none() => {
                partition = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--partition 缺 M/N"))?
                        .parse()?,
                );
            }
            other => bail!("core execution 未知或重复参数: {other}"),
        }
    }
    if execution == verify::CoreExecution::Tests && partition.is_none() {
        bail!("ci-core-tests 必须传 --partition M/N");
    }
    Ok(Command::CoreExecution {
        execution,
        allow_missing_tools,
        partition,
    })
}

/// 解析 `audit` 的可选 flag（fail-closed：未知 flag 即 `Err`）。`audit` 无 `--fast`——供应链 lane 恒全量跑。
fn parse_audit(args: &[&str]) -> Result<Command> {
    let mut allow_missing_tools = false;
    for &tok in args {
        match tok {
            "--allow-missing-tools" => allow_missing_tools = true,
            other => {
                bail!("audit 未知参数: {other}；用法: cargo xtask audit [--allow-missing-tools]")
            }
        }
    }
    Ok(Command::Audit {
        allow_missing_tools,
    })
}

/// 解析闭合 `ci-integration --shard <name>`；未知、缺失、重复或尾参均 fail-closed。
fn parse_ci_integration(args: &[&str]) -> Result<Command> {
    let mut shard: Option<integration_shards::IntegrationShard> = None;
    let mut partition = None;
    let mut allow_missing_tools = false;
    let mut iter = args.iter().copied();
    while let Some(tok) = iter.next() {
        match tok {
            "--allow-missing-tools" if !allow_missing_tools => allow_missing_tools = true,
            "--shard" if shard.is_none() => {
                let raw = iter.next().ok_or_else(|| {
                    anyhow::anyhow!("--shard 缺少值；用法: cargo xtask ci-integration --shard <name> [--partition M/N] [--allow-missing-tools]")
                })?;
                shard = Some(raw.parse()?);
            }
            "--partition" if partition.is_none() => {
                let raw = iter
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--partition 缺少 M/N"))?;
                partition = Some(raw.parse()?);
            }
            other => {
                bail!(
                    "ci-integration 未知或重复参数: {other}；用法: cargo xtask ci-integration --shard <name> [--partition M/N] [--allow-missing-tools]"
                )
            }
        }
    }
    let shard = shard.ok_or_else(|| {
        anyhow::anyhow!("ci-integration 缺少 --shard；用法: cargo xtask ci-integration --shard <name> [--partition M/N] [--allow-missing-tools]")
    })?;
    shard.validate_partition(partition)?;
    Ok(Command::CiIntegration {
        shard,
        allow_missing_tools,
        partition,
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
        Command::AssemblyGenerateModules { check } => assembly_codegen::run(check),
        Command::GraphAssembly(options) => graph::run(&options),
        Command::ArchRulesList => archrules::list(),
        Command::ArchRulesVerify => diagnostic::run_check(&archrules::ArchRules),
        Command::ArchRulesMatrix(action) => archrules::matrix(action),
        Command::RuntimeBaselineList => runtime_baseline::list(),
        Command::RuntimeBaselineVerify => diagnostic::run_check(&runtime_baseline::RuntimeBaseline),
        Command::RuntimeDepsGuard => diagnostic::run_check(&runtime_deps_guard::RuntimeDepsGuard),
        Command::ContractBreaking { against } => {
            let against =
                against.unwrap_or_else(|| contract::breaking::DEFAULT_AGAINST.to_string());
            contract::breaking::run(&against)
        }
        Command::LayerDeps => diagnostic::run_check(&layerdeps::LayerDeps),
        Command::WsDepsDrift => diagnostic::run_check(&wsdeps::WsDepsDrift),
        Command::DocContracts => diagnostic::run_check(&doc_contracts::DocContracts),
        Command::ConsistencyFixtures => {
            diagnostic::run_check(&consistency_fixtures::ConsistencyFixtures)
        }
        Command::ConsistencyLocalOnlyEffects => {
            diagnostic::run_check(&consistency_effects::LocalOnlyEffects)
        }
        Command::ConsistencyReport { format } => consistency_effects::run_report(format),
        Command::LocalTxCoverage => diagnostic::run_check(&localtx_coverage::LocalTxCoverage),
        Command::Verify {
            fast,
            allow_missing_tools,
        } => verify::run(fast, allow_missing_tools),
        Command::PublicApi {
            check,
            allow_missing,
            layer,
        } => publicapi::run(check, allow_missing, layer),
        Command::Ci {
            allow_missing_tools,
        } => verify::run_ci(allow_missing_tools),
        Command::CiLane {
            lane,
            allow_missing_tools,
        } => verify::run_lane(lane, allow_missing_tools, None),
        Command::CoreExecution {
            execution,
            allow_missing_tools,
            partition,
        } => verify::run_core_execution(execution, allow_missing_tools, partition),
        Command::Audit {
            allow_missing_tools,
        } => verify::run_audit(allow_missing_tools),
        Command::CiIntegration {
            shard,
            allow_missing_tools,
            partition,
        } => verify::run_ci_integration(shard, allow_missing_tools, partition),
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
        Command::NextestEvidenceStage => nextest::stage(&workspace_root()?),
        Command::NextestEvidenceInspect { artifact_root } => nextest::inspect(&artifact_root),
        Command::NextestEvidenceReplay { sidecar } => nextest::replay(&sidecar, &workspace_root()?),
        Command::SchemaRls => diagnostic::run_check(&schema_rls::SchemaRlsGuard),
        Command::InboxCutoverGuard => {
            diagnostic::run_check(&inbox_cutover_guard::InboxCutoverGuard)
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
    fn parse_command_doc_contracts() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["doc-contracts"]))?,
            Command::DocContracts
        );
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
    fn parse_command_doc_contracts_rejects_trailing_args() {
        assert!(parse_command(&s(&["doc-contracts", "--bogus"])).is_err());
        assert!(parse_command(&s(&["doc-contracts", "extra"])).is_err());
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
                allow_missing_tools: false
            }
        );
        Ok(())
    }

    #[test]
    fn parse_command_verify_flags() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["verify", "--fast"]))?,
            Command::Verify {
                fast: true,
                allow_missing_tools: false
            }
        );
        assert_eq!(
            parse_command(&s(&["verify", "--allow-missing-tools"]))?,
            Command::Verify {
                fast: false,
                allow_missing_tools: true
            }
        );
        assert_eq!(
            parse_command(&s(&["verify", "--fast", "--allow-missing-tools"]))?,
            Command::Verify {
                fast: true,
                allow_missing_tools: true
            }
        );
        Ok(())
    }

    /// verify flag fail-closed：未知 flag 即 `Err`（不被静默吞掉）。
    #[test]
    fn parse_command_verify_rejects_unknown_flag() {
        assert!(parse_command(&s(&["verify", "--bogus"])).is_err());
        assert!(parse_command(&s(&["verify", "--fast", "extra"])).is_err());
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
    fn parse_command_ci_bare() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["ci"]))?,
            Command::Ci {
                allow_missing_tools: false
            }
        );
        Ok(())
    }

    #[test]
    fn parse_command_ci_allow_missing_tools() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["ci", "--allow-missing-tools"]))?,
            Command::Ci {
                allow_missing_tools: true
            }
        );
        Ok(())
    }

    /// ci flag fail-closed：未知 flag / 尾参 / 误用 `--fast`（ci 无此 flag）均 `Err`。
    #[test]
    fn parse_command_ci_rejects_unknown_flag() {
        assert!(parse_command(&s(&["ci", "--bogus"])).is_err());
        assert!(parse_command(&s(&["ci", "--fast"])).is_err()); // ci 无 --fast
        assert!(parse_command(&s(&["ci", "extra"])).is_err());
    }

    #[test]
    fn ci_lane_commands_parse_exactly_and_fail_closed() -> anyhow::Result<()> {
        for (name, lane) in [
            ("ci-meta", ci_lanes::CiLane::Meta),
            ("ci-core", ci_lanes::CiLane::Core),
            ("ci-security", ci_lanes::CiLane::Security),
            ("ci-coverage", ci_lanes::CiLane::Coverage),
        ] {
            assert_eq!(
                parse_command(&s(&[name]))?,
                Command::CiLane {
                    lane,
                    allow_missing_tools: false,
                }
            );
            assert_eq!(
                parse_command(&s(&[name, "--allow-missing-tools"]))?,
                Command::CiLane {
                    lane,
                    allow_missing_tools: true,
                }
            );
            for invalid in ["--bogus", "extra"] {
                let Err(error) = parse_command(&s(&[name, invalid])) else {
                    bail!("split lane unknown arguments must fail closed")
                };
                let error = error.to_string();
                assert!(error.contains(name), "missing command in `{error}`");
                assert!(
                    error.contains(&format!("用法: cargo xtask {name} [--allow-missing-tools]")),
                    "missing copyable usage in `{error}`"
                );
            }
        }
        assert!(parse_command(&s(&["ci-nightly"])).is_err());
        assert!(parse_command(&s(&["ci-integration"])).is_err());
        assert!(parse_command(&s(&["ci-core-tests", "--partition", "1/2"])).is_ok());
        assert!(parse_command(&s(&["ci-core-prerequisites"])).is_ok());
        for args in [
            vec!["ci-core", "--partition", "1/2"],
            vec!["ci-core-tests"],
            vec!["ci-core-tests", "--partition"],
            vec!["ci-core-tests", "--partition", "hash:1/2"],
            vec!["ci-core-tests", "--partition", "1/2", "--partition", "2/2"],
            vec!["ci-core-prerequisites", "--partition", "1/2"],
            vec!["ci-meta", "--partition", "1/2"],
        ] {
            assert!(parse_command(&s(&args)).is_err());
        }
        Ok(())
    }

    #[test]
    fn parse_command_audit_bare() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["audit"]))?,
            Command::Audit {
                allow_missing_tools: false
            }
        );
        Ok(())
    }

    #[test]
    fn parse_command_audit_allow_missing_tools() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["audit", "--allow-missing-tools"]))?,
            Command::Audit {
                allow_missing_tools: true
            }
        );
        Ok(())
    }

    /// audit flag fail-closed：未知 flag / 尾参 / 误用 `--fast`（audit 无此 flag）均 `Err`。
    #[test]
    fn parse_command_audit_rejects_unknown_flag() {
        assert!(parse_command(&s(&["audit", "--bogus"])).is_err());
        assert!(parse_command(&s(&["audit", "--fast"])).is_err());
        assert!(parse_command(&s(&["audit", "extra"])).is_err());
    }

    #[test]
    fn parse_command_ci_integration_shards_and_fail_closed() {
        for shard in [
            "postgres-domain",
            "event-transport",
            "runtime-http-auth",
            "consistency-fault",
            "cdc-projection-saga",
        ] {
            assert!(
                parse_command(&s(&["ci-integration", "--shard", shard])).is_ok(),
                "valid shard {shard} must parse"
            );
            assert!(
                parse_command(&s(&[
                    "ci-integration",
                    "--allow-missing-tools",
                    "--shard",
                    shard,
                ]))
                .is_ok(),
                "local missing-tool allowance must compose with {shard}"
            );
            let partitioned = parse_command(&s(&[
                "ci-integration",
                "--shard",
                shard,
                "--partition",
                "1/2",
            ]));
            assert_eq!(
                partitioned.is_ok(),
                matches!(shard, "event-transport" | "runtime-http-auth")
            );
        }

        assert!(parse_command(&s(&["ci-integration"])).is_err());
        assert!(parse_command(&s(&["ci-integration", "--shard"])).is_err());
        assert!(parse_command(&s(&["ci-integration", "--all"])).is_err());
        assert!(
            parse_command(&s(&[
                "ci-integration",
                "--shard",
                "event-transport",
                "--partition",
                "hash:1/2"
            ]))
            .is_err()
        );
        assert!(parse_command(&s(&["ci-integration", "--shard", "POSTGRES-DOMAIN"])).is_err());
        assert!(
            parse_command(&s(&[
                "ci-integration",
                "--shard",
                "postgres-domain",
                "--shard",
                "event-transport",
            ]))
            .is_err()
        );
        assert!(parse_command(&s(&["integration"])).is_err());
        assert!(parse_command(&s(&["integration", "--bogus"])).is_err());
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
