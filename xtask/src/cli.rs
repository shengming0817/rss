//! xtask CLI 表层：单一 clap derive ADT（`Xtask` + `Command`）。
//!
//! 跨字段业务前置（如 `verify --fresh` 必须配 `--fast`）在 [`Command::validate`] 中 fail-closed；
//! 不假装 clap 属性可表达全部 RSS 约束。
//!
//! clap 语法错误与 argv 业务 validate 均脱敏/固定出口（help → exit 0；其余 exit 2）；
//! 解析失败诊断不得回显 unexpected argv 原文（SECRET_BAIT）。
//!
//! ref: clap-rs/clap examples/derive_ref

use crate::assembly_lock::AssemblyLockAction;
use crate::ci_impact::{self, LocalOptions, SelectionPlan};
use crate::ci_lanes::{FixedCiInvocation, FixedCiJob};
use crate::graph;
use crate::integration_shards::IntegrationJobGroup;
use crate::publicapi;
use crate::report_format::ReportFormat;
use anyhow::{Result, bail};
use clap::error::ErrorKind;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// RSS 本地治理与 codegen 入口（契约 / assembly / CI / verify）。
#[derive(Debug, Parser, PartialEq, Eq)]
#[command(
    name = "xtask",
    about = "RSS 本地治理与 codegen 入口",
    arg_required_else_help = true
)]
struct Xtask {
    #[command(subcommand)]
    command: Command,
}

/// 唯一命令 ADT：解析结果与 IO 执行分离。
#[derive(Debug, Subcommand, PartialEq, Eq)]
pub(crate) enum Command {
    /// 契约 schema → committed `generated/`（`--check` 为 CI 漂移门）。
    Codegen {
        /// 只校验 generated 是否与 schema 一致（CI 漂移门）。
        #[arg(long)]
        check: bool,
    },
    /// Build a real `.crate` and prove it from an independent offline local-registry consumer.
    PackageProof,
    /// Debezium / CDC connector skeleton。
    #[command(subcommand)]
    CdcConfig(CdcConfigCommand),
    /// 契约元数据校验与 breaking 检测。
    #[command(subcommand)]
    Contract(ContractCommand),
    /// assembly 校验、产物与 lock。
    #[command(subcommand)]
    Assembly(AssemblyCommand),
    /// assembly 静态声明图。
    #[command(subcommand)]
    Graph(GraphCommand),
    /// ArchRules 派生索引与 funnel 矩阵。
    #[command(subcommand)]
    Archrules(ArchrulesCommand),
    /// runtime assembly baseline。
    #[command(subcommand)]
    RuntimeBaseline(RuntimeBaselineCommand),
    /// runtime composition-root 单调职责。
    #[command(subcommand)]
    RuntimeRoot(RuntimeRootCommand),
    /// SharedRuntimeDeps infra-only 字段守卫。
    #[command(subcommand)]
    RuntimeDeps(RuntimeDepsCommand),
    /// runtime ambient environment 单漏斗。
    #[command(subcommand)]
    RuntimeEnv(RuntimeEnvCommand),
    /// source-centric 分层依赖 lint。
    LayerDeps,
    /// workspace.dependencies pin↔lock 漂移门。
    WsdepsDrift,
    /// source semantic 守卫。
    SourceSemanticGuard,
    /// Saga durable recovery 守卫。
    SagaDurableRecoveryGuard,
    /// 固定摘要 promtool 规则门。
    PromtoolRules,
    /// same-ID SQL/Rust/ops 完整闭包门。
    OutboxSameIdGuard,
    /// consistency crash matrix fixture/DSL 治理门。
    ConsistencyFixtures,
    /// consistency / effect 治理与报告。
    #[command(subcommand)]
    Consistency(ConsistencyCommand),
    /// LocalTx 静态证明报告。
    #[command(subcommand)]
    Localtx(LocaltxCommand),
    /// active LocalTx manifest/generated/route/test closure 门。
    LocaltxCoverage,
    /// deterministic active L2 producer/fact assurance inventory。
    L2Assurance {
        #[arg(long)]
        check: bool,
    },
    /// deterministic L2 provider conformance enrollment matrix。
    ProviderCapabilities {
        #[arg(long)]
        check: bool,
    },
    /// 本地全量治理门聚合入口。
    Verify {
        /// 只跑 registry 显式 Always 的本地 meta 门。
        #[arg(long)]
        fast: bool,
        /// 清空当前分支断点；须与 `--fast` 同用。
        #[arg(long)]
        fresh: bool,
        /// 缺外部工具时显式宽限（默认 fail-closed）。
        #[arg(long)]
        allow_missing_tools: bool,
        /// 对比的 git base ref（可选）。
        #[arg(long)]
        against: Option<String>,
        /// 首个失败门即退出。
        #[arg(long)]
        fail_fast: bool,
        /// 只跑指定 gate label（可重复；非空、不可重复）。
        #[arg(long = "only", action = clap::ArgAction::Append)]
        only: Vec<String>,
    },
    /// Internal signature / Release API baseline（包装 cargo-public-api）。
    #[command(subcommand)]
    PublicApi(publicapi::Command),
    /// CI plan / run / gate / local preflight。
    #[command(subcommand)]
    Ci(CiCommand),
    /// nextest evidence stage / inspect / replay。
    #[command(subcommand)]
    NextestEvidence(NextestEvidenceCommand),
    /// schema RLS + LocalOnly reader ACL 终态 meta 守卫（合入前无 PG Medium 门）。
    SchemaRls,
    /// inbox receipt cutover 旧 token 回流守卫（CI 门）。
    InboxCutoverGuard,
    /// DLX verified WORM archive-before-purge 单漏斗守卫（CI 门）。
    DlxLifecycleFunnel,
    /// Postgres tenant 表 raw-pool / TxManager bypass 守卫（CI 门）。
    PgTenantTxGuard,
    /// domain repo port 禁裸 TenantId / RowVisibility / RowScope 签名守卫（CI 门）。
    RepoScopeGuard,
    /// reconcile scheduler transactional command outbox seam 守卫（CI 门）。
    ReconcileOutboxCommandGuard,
    /// tenancy/AuthZ/projection closeout 反向自检（CI 门）。
    TenancyCloseout,
    /// governed 高风险路径结构化 defer 完整性 + 经典注解治理门（CI 门）。
    DeferGate,
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
pub(crate) enum CdcConfigCommand {
    /// 输出 Debezium PostgreSQL outbox_log CDC connector JSON skeleton。
    Debezium,
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
pub(crate) enum ContractCommand {
    /// 契约元数据多规则校验。
    Validate,
    /// wire JSON-Schema 跨版本破坏检测。
    Breaking {
        #[arg(long)]
        against: Option<String>,
    },
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
pub(crate) enum AssemblyCommand {
    /// 校验 assembly manifest、Cargo closure 与 production governance residual。
    Validate,
    /// assembly lifecycle 与应用 artifact exact closure。
    #[command(subcommand)]
    Artifacts(AssemblyArtifactsCommand),
    /// assembly.toml domains → committed modules_gen.rs。
    GenerateModules {
        #[arg(long)]
        check: bool,
    },
    /// assembly.toml providers → committed typed provider catalog。
    GenerateProviders {
        #[arg(long)]
        check: bool,
    },
    /// manifest + lock → committed typed runtime-plan.json。
    GenerateRuntimePlans {
        #[arg(long)]
        check: bool,
    },
    /// 全仓 v1 assembly.lock.json 原子生成 / raw-byte 漂移门。
    #[command(subcommand)]
    Lock(AssemblyLockAction),
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
pub(crate) enum AssemblyArtifactsCommand {
    /// assembly lifecycle 与应用 artifact exact closure 门。
    Check,
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
pub(crate) enum GraphCommand {
    /// assembly 静态声明图；`--check` 守 runtime 双格式漂移。
    Assembly(graph::Options),
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
pub(crate) enum ArchrulesCommand {
    /// 列出 ArchRules 派生索引。
    List,
    /// ArchRules 漂移门（CI 门）。
    Verify,
    /// 持久化 funnel 单源矩阵；`--write` / `--check` 互斥。
    Matrix {
        #[arg(long, conflicts_with = "check")]
        write: bool,
        #[arg(long, conflicts_with = "write")]
        check: bool,
    },
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
pub(crate) enum RuntimeBaselineCommand {
    /// 原子更新 committed runtime assembly baseline。
    Update,
    /// runtime assembly baseline 漂移门（CI 门）。
    Verify,
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
pub(crate) enum RuntimeRootCommand {
    /// runtime composition-root 单调职责 ratchet。
    Guard,
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
pub(crate) enum RuntimeDepsCommand {
    /// SharedRuntimeDeps infra-only 字段类型守卫。
    Guard,
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
pub(crate) enum RuntimeEnvCommand {
    /// runtime ambient environment 单漏斗守卫。
    Guard,
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
pub(crate) enum ConsistencyCommand {
    /// active LocalOnly HTTP effect profile 治理门。
    LocalOnlyEffects,
    /// active HTTP consistency/effect posture 确定性报告。
    Report {
        /// Append + validate 拒绝重复（clap Set 默认为 last-wins）。
        #[arg(long, value_enum, required = true, action = clap::ArgAction::Append)]
        format: Vec<ReportFormat>,
    },
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
pub(crate) enum LocaltxCommand {
    /// active LocalTx static proof inventory。
    Report {
        /// Append + validate 拒绝重复。
        #[arg(long, value_enum, required = true, action = clap::ArgAction::Append)]
        format: Vec<ReportFormat>,
    },
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
pub(crate) enum CiCommand {
    /// 原本地 CI lane 超集聚合。
    Full {
        #[arg(long)]
        allow_missing_tools: bool,
        #[arg(long)]
        fail_fast: bool,
    },
    /// 仅分析已提交差异的本地 preflight。
    Local(LocalOptions),
    /// GitHub event/diff → fixed-job SelectionPlan。
    Plan(ci_impact::Options),
    /// 固定远端 typed executor。
    Run {
        #[arg(long, value_parser = parse_fixed_ci_job, required = true)]
        job: FixedCiJob,
        #[arg(long, value_parser = parse_selection_plan, required = true)]
        selection: Box<SelectionPlan>,
        #[arg(long, value_parser = parse_integration_job_group)]
        integration_group: Option<IntegrationJobGroup>,
    },
    /// 有界远端编译与治理前置门。
    Preflight {
        #[arg(long, value_parser = parse_selection_plan, required = true)]
        selection: Box<SelectionPlan>,
    },
    /// 严格校验 required-evidence，并发布不可替换的上传快照。
    ValidateEvidence {
        #[arg(long, value_enum, required = true)]
        kind: RequiredEvidenceKind,
        #[arg(long, required = true)]
        input: PathBuf,
        #[arg(long, required = true)]
        output: PathBuf,
    },
    /// cargo-audit 门。
    Audit,
    /// LocalOnly required evidence producer。
    LocalonlyEvidence {
        #[arg(long, required = true)]
        output: PathBuf,
    },
}

#[derive(Clone, Copy, Debug, clap::ValueEnum, PartialEq, Eq)]
pub(crate) enum RequiredEvidenceKind {
    Localonly,
    Localtx,
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
pub(crate) enum NextestEvidenceCommand {
    /// 暂存 nextest evidence artifact。
    Stage,
    /// 检查已暂存 evidence 根目录。
    Inspect { artifact_root: PathBuf },
    /// 回放 evidence sidecar。
    Replay { sidecar: PathBuf },
}

impl Command {
    /// RSS 跨字段业务前置；clap 已表达的结构约束不再重复。
    pub(crate) fn validate(&self) -> Result<()> {
        match self {
            Self::Verify {
                fast, fresh, only, ..
            } => {
                if *fresh && !*fast {
                    bail!("verify --fresh 只允许与 --fast 同用");
                }
                let mut seen = std::collections::BTreeSet::new();
                for gate in only {
                    if gate.is_empty() {
                        bail!("verify 参数 --only 必须是非空 gate label");
                    }
                    if !seen.insert(gate.as_str()) {
                        bail!("verify 重复 gate: {gate}");
                    }
                }
                Ok(())
            }
            Self::Graph(GraphCommand::Assembly(options)) => options.validate(),
            Self::Ci(CiCommand::Local(options)) => options.validate(),
            Self::Ci(CiCommand::Run {
                job,
                integration_group,
                ..
            }) => {
                FixedCiInvocation::new(*job, *integration_group)?;
                Ok(())
            }
            Self::Consistency(ConsistencyCommand::Report { format }) => {
                if format.len() != 1 {
                    bail!("consistency report 重复参数: --format");
                }
                Ok(())
            }
            Self::Localtx(LocaltxCommand::Report { format }) => {
                if format.len() != 1 {
                    bail!("localtx report 重复参数: --format");
                }
                Ok(())
            }
            Self::Ci(CiCommand::LocalonlyEvidence { output }) => {
                if output.file_name().is_none() {
                    bail!("ci localonly-evidence --output 必须包含文件名");
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

/// 进程入口：clap 语法错误与 argv validate 均固定 exit；其余仍返回 Result。
pub(crate) fn parse_or_exit() -> Result<Command> {
    match Xtask::try_parse_from(std::env::args_os()) {
        Ok(cli) => {
            if let Err(err) = cli.command.validate() {
                eprintln!("error: {err}");
                std::process::exit(2);
            }
            Ok(cli.command)
        }
        Err(err) => exit_clap(err),
    }
}

fn exit_clap(err: clap::Error) -> ! {
    match err.kind() {
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => {
            let _ = err.print();
            std::process::exit(0);
        }
        kind => {
            eprintln!("{}", sanitized_clap_message(kind));
            std::process::exit(2);
        }
    }
}

/// 可测入口：`try_parse_from` + [`Command::validate`]。
///
/// unexpected argv 映射为不含原 token 的通用错误（SECRET_BAIT）；不测 help 出口。
#[cfg(test)]
pub(crate) fn parse_from<I, T>(args: I) -> Result<Command>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    match Xtask::try_parse_from(args) {
        Ok(cli) => {
            cli.command.validate()?;
            Ok(cli.command)
        }
        Err(err) => Err(map_clap_parse_error(err)),
    }
}

/// 统一脱敏漏斗：凡可能夹带 argv 原文的 kind 均不回显 token。
fn sanitized_clap_message(kind: ErrorKind) -> &'static str {
    match kind {
        ErrorKind::InvalidSubcommand => "error: unknown subcommand; see --help",
        ErrorKind::UnknownArgument => "error: unexpected argument; see --help",
        ErrorKind::InvalidValue | ErrorKind::TooManyValues | ErrorKind::ValueValidation => {
            "error: invalid value; see --help"
        }
        _ => "error: invalid arguments; see --help",
    }
}

#[cfg(test)]
fn map_clap_parse_error(err: clap::Error) -> anyhow::Error {
    anyhow::anyhow!("{}", sanitized_clap_message(err.kind()))
}

fn parse_fixed_ci_job(value: &str) -> std::result::Result<FixedCiJob, String> {
    value.parse().map_err(|err: anyhow::Error| err.to_string())
}

fn parse_integration_job_group(value: &str) -> std::result::Result<IntegrationJobGroup, String> {
    value.parse().map_err(|err: anyhow::Error| err.to_string())
}

fn parse_selection_plan(value: &str) -> std::result::Result<Box<SelectionPlan>, String> {
    value
        .parse()
        .map(Box::new)
        .map_err(|err: anyhow::Error| err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assembly_lock;
    use crate::graph;
    use crate::publicapi;
    use crate::report_format::ReportFormat;

    fn parse(args: &[&str]) -> Result<Command> {
        let mut full = vec!["xtask"];
        full.extend(args);
        parse_from(&full)
    }

    #[test]
    fn try_parse_codegen_shapes() -> Result<()> {
        assert_eq!(parse(&["codegen"])?, Command::Codegen { check: false });
        assert_eq!(
            parse(&["codegen", "--check"])?,
            Command::Codegen { check: true }
        );
        assert!(parse(&["codegen", "extra"]).is_err());
        Ok(())
    }

    #[test]
    fn try_parse_rejects_empty_and_unknown() {
        assert!(parse(&[]).is_err());
        assert!(parse(&["no-such-command"]).is_err());
        assert!(parse(&["contract", "bogus"]).is_err());
    }

    #[test]
    fn try_parse_zero_arg_guards_reject_trailing() -> Result<()> {
        for cmd in [
            "layer-deps",
            "wsdeps-drift",
            "localtx-coverage",
            "outbox-same-id-guard",
            "promtool-rules",
            "consistency-fixtures",
            "source-semantic-guard",
            "saga-durable-recovery-guard",
            "schema-rls",
            "inbox-cutover-guard",
            "dlx-lifecycle-funnel",
            "pg-tenant-tx-guard",
            "repo-scope-guard",
            "reconcile-outbox-command-guard",
            "tenancy-closeout",
            "defer-gate",
        ] {
            assert!(parse(&[cmd]).is_ok(), "expected ok: {cmd}");
            assert!(
                parse(&[cmd, "extra"]).is_err(),
                "expected trailing reject: {cmd}"
            );
        }
        let err = parse(&["setlocal-funnel"]).expect_err("retired subcommand must fail");
        assert!(
            err.to_string().contains("unknown subcommand"),
            "retired `setlocal-funnel` must be unknown subcommand, got: {err}"
        );
        Ok(())
    }

    #[test]
    fn try_parse_nested_exact_shapes() -> Result<()> {
        assert_eq!(
            parse(&["cdc-config", "debezium"])?,
            Command::CdcConfig(CdcConfigCommand::Debezium)
        );
        assert!(parse(&["cdc-config"]).is_err());
        assert_eq!(
            parse(&["contract", "validate"])?,
            Command::Contract(ContractCommand::Validate)
        );
        assert_eq!(
            parse(&["contract", "breaking"])?,
            Command::Contract(ContractCommand::Breaking { against: None })
        );
        assert_eq!(
            parse(&["contract", "breaking", "--against", "HEAD~1"])?,
            Command::Contract(ContractCommand::Breaking {
                against: Some("HEAD~1".into()),
            })
        );
        assert!(parse(&["contract", "breaking", "--against"]).is_err());
        assert_eq!(
            parse(&["assembly", "validate"])?,
            Command::Assembly(AssemblyCommand::Validate)
        );
        assert_eq!(
            parse(&["assembly", "artifacts", "check"])?,
            Command::Assembly(AssemblyCommand::Artifacts(AssemblyArtifactsCommand::Check))
        );
        assert!(parse(&["assembly", "artifacts"]).is_err());
        assert_eq!(
            parse(&["assembly", "generate-modules", "--check"])?,
            Command::Assembly(AssemblyCommand::GenerateModules { check: true })
        );
        assert_eq!(
            parse(&["assembly", "lock", "generate"])?,
            Command::Assembly(AssemblyCommand::Lock(
                assembly_lock::AssemblyLockAction::Generate
            ))
        );
        assert_eq!(
            parse(&["graph", "assembly"])?,
            Command::Graph(GraphCommand::Assembly(graph::Options::default()))
        );
        assert_eq!(
            parse(&["graph", "assembly", "--check"])?,
            Command::Graph(GraphCommand::Assembly(graph::Options::check_runtime()))
        );
        assert!(parse(&["graph"]).is_err());
        assert!(parse(&["graph", "assembly", "--check", "--format", "json"]).is_err());
        assert!(parse(&["graph", "assembly", "--assembly", "../x"]).is_err());
        Ok(())
    }

    #[test]
    fn try_parse_archrules_and_runtime_guards() -> Result<()> {
        assert_eq!(
            parse(&["archrules", "list"])?,
            Command::Archrules(ArchrulesCommand::List)
        );
        assert_eq!(
            parse(&["archrules", "matrix", "--check"])?,
            Command::Archrules(ArchrulesCommand::Matrix {
                write: false,
                check: true,
            })
        );
        assert!(parse(&["archrules", "matrix", "--write", "--check"]).is_err());
        assert_eq!(
            parse(&["runtime-baseline", "update"])?,
            Command::RuntimeBaseline(RuntimeBaselineCommand::Update)
        );
        assert_eq!(
            parse(&["runtime-baseline", "verify"])?,
            Command::RuntimeBaseline(RuntimeBaselineCommand::Verify)
        );
        assert_eq!(
            parse(&["runtime-root", "guard"])?,
            Command::RuntimeRoot(RuntimeRootCommand::Guard)
        );
        assert_eq!(
            parse(&["runtime-deps", "guard"])?,
            Command::RuntimeDeps(RuntimeDepsCommand::Guard)
        );
        assert_eq!(
            parse(&["runtime-env", "guard"])?,
            Command::RuntimeEnv(RuntimeEnvCommand::Guard)
        );
        for bad in [
            &["archrules"][..],
            &["runtime-baseline"][..],
            &["runtime-baseline", "list"][..],
            &["runtime-baseline", "write"][..],
            &["runtime-baseline", "update", "extra"][..],
            &["runtime-root"][..],
            &["runtime-deps", "guard", "extra"][..],
        ] {
            assert!(parse(bad).is_err(), "accepted {bad:?}");
        }
        Ok(())
    }

    #[test]
    fn try_parse_report_formats_are_closed() -> Result<()> {
        assert_eq!(
            parse(&["consistency", "report", "--format", "json"])?,
            Command::Consistency(ConsistencyCommand::Report {
                format: vec![ReportFormat::Json],
            })
        );
        assert_eq!(
            parse(&["consistency", "report", "--format", "markdown"])?,
            Command::Consistency(ConsistencyCommand::Report {
                format: vec![ReportFormat::Markdown],
            })
        );
        assert_eq!(
            parse(&["localtx", "report", "--format", "markdown"])?,
            Command::Localtx(LocaltxCommand::Report {
                format: vec![ReportFormat::Markdown],
            })
        );
        assert!(parse(&["consistency", "report"]).is_err());
        assert!(parse(&["localtx", "report", "--format"]).is_err());
        assert!(parse(&["localtx", "report", "--format", "json", "extra"]).is_err());
        assert!(
            parse(&[
                "consistency",
                "report",
                "--format",
                "json",
                "--format",
                "markdown",
            ])
            .is_err()
        );
        assert!(parse(&["consistency", "report", "--output", "out.json"]).is_err());
        Ok(())
    }

    #[test]
    fn try_parse_verify_business_rules() -> Result<()> {
        assert_eq!(
            parse(&["verify"])?,
            Command::Verify {
                fast: false,
                fresh: false,
                allow_missing_tools: false,
                against: None,
                fail_fast: false,
                only: vec![],
            }
        );
        assert_eq!(
            parse(&[
                "verify",
                "--fast",
                "--fresh",
                "--allow-missing-tools",
                "--fail-fast",
                "--against",
                "origin/develop",
                "--only",
                "fmt",
                "--only",
                "clippy",
            ])?,
            Command::Verify {
                fast: true,
                fresh: true,
                allow_missing_tools: true,
                against: Some("origin/develop".into()),
                fail_fast: true,
                only: vec!["fmt".into(), "clippy".into()],
            }
        );
        assert!(parse(&["verify", "--fresh"]).is_err());
        assert!(parse(&["verify", "--only", "fmt", "--only", "fmt"]).is_err());
        assert!(parse(&["verify", "--only", ""]).is_err());
        assert!(parse(&["verify", "--bogus"]).is_err());
        assert!(parse(&["verify", "--against"]).is_err());
        assert!(parse(&["verify", "trailing"]).is_err());
        Ok(())
    }

    #[test]
    fn try_parse_public_api_and_ci_surface() -> Result<()> {
        assert_eq!(
            parse(&["public-api", "internal"])?,
            Command::PublicApi(publicapi::Command::Internal {
                check: false,
                layer: None,
            })
        );
        assert_eq!(
            parse(&["public-api", "internal", "--layer", "basis", "--check"])?,
            Command::PublicApi(publicapi::Command::Internal {
                check: true,
                layer: Some(publicapi::InternalLayer::Basis),
            })
        );
        assert_eq!(
            parse(&["public-api", "release", "--check"])?,
            Command::PublicApi(publicapi::Command::Release { check: true })
        );
        assert!(parse(&["public-api"]).is_err());
        assert!(parse(&["public-api", "--check"]).is_err());
        assert!(parse(&["public-api", "internal", "--allow-missing"]).is_err());
        assert!(parse(&["public-api", "release", "--layer", "basis"]).is_err());
        assert!(parse(&["public-api", "internal", "--layer", "nope"]).is_err());
        assert!(parse(&["ci"]).is_err());
        assert_eq!(
            parse(&["ci", "full", "--fail-fast"])?,
            Command::Ci(CiCommand::Full {
                allow_missing_tools: false,
                fail_fast: true,
            })
        );
        assert_eq!(parse(&["ci", "audit"])?, Command::Ci(CiCommand::Audit));
        assert!(parse(&["ci", "local"]).is_err());
        assert!(matches!(
            parse(&["ci", "local", "--base", "origin/develop"])?,
            Command::Ci(CiCommand::Local(_))
        ));
        assert!(
            parse(&[
                "ci",
                "local",
                "--base",
                "origin/develop",
                "--only",
                "test",
                "--only",
                "test"
            ])
            .is_err()
        );
        assert!(parse(&["ci", "plan"]).is_err());
        assert!(parse(&["ci", "gate"]).is_err());
        assert!(parse(&["ci", "preflight"]).is_err());
        assert!(parse(&["ci", "run"]).is_err());
        assert!(parse(&["ci", "run", "--job", "check"]).is_err());
        let selection = serde_json::to_string(&crate::ci_impact::test_selection_plan()?)?;
        assert!(matches!(
            parse(&["ci", "preflight", "--selection", &selection])?,
            Command::Ci(CiCommand::Preflight { .. })
        ));
        assert!(
            parse(&[
                "ci",
                "run",
                "--job",
                "integration-critical",
                "--selection",
                &selection,
            ])
            .is_err()
        );
        assert!(
            parse(&[
                "ci",
                "run",
                "--job",
                "check",
                "--selection",
                &selection,
                "--integration-group",
                "postgres",
            ])
            .is_err()
        );
        assert!(matches!(
            parse(&[
                "ci",
                "run",
                "--job",
                "integration-critical",
                "--selection",
                &selection,
                "--integration-group",
                "postgres",
            ])?,
            Command::Ci(CiCommand::Run {
                integration_group: Some(IntegrationJobGroup::Postgres),
                ..
            })
        ));
        assert!(
            parse(&[
                "ci",
                "run",
                "--job",
                "integration-critical",
                "--selection",
                &selection,
                "--integration-group",
                "all",
            ])
            .is_err()
        );
        // legacy 平铺 argv（无 subcommand）必须拒绝。
        assert!(parse(&["ci", "--base", "origin/develop"]).is_err());
        assert!(parse(&["ci", "localonly-evidence"]).is_err());
        assert!(matches!(
            parse(&["ci", "localonly-evidence", "--output", "out.json"])?,
            Command::Ci(CiCommand::LocalonlyEvidence { .. })
        ));
        assert!(parse(&["ci", "localonly-evidence", "--output", "/"]).is_err());
        assert_eq!(
            parse(&["nextest-evidence", "stage"])?,
            Command::NextestEvidence(NextestEvidenceCommand::Stage)
        );
        assert!(matches!(
            parse(&["nextest-evidence", "inspect", "/tmp/a"])?,
            Command::NextestEvidence(NextestEvidenceCommand::Inspect { .. })
        ));
        Ok(())
    }

    #[test]
    fn try_parse_l2_and_provider_flags() -> Result<()> {
        assert_eq!(
            parse(&["l2-assurance"])?,
            Command::L2Assurance { check: false }
        );
        assert_eq!(
            parse(&["provider-capabilities", "--check"])?,
            Command::ProviderCapabilities { check: true }
        );
        assert!(parse(&["l2-assurance", "extra"]).is_err());
        Ok(())
    }

    #[test]
    #[allow(non_snake_case)] // 验收过滤名含 SECRET_BAIT
    fn try_parse_assembly_lock_rejects_SECRET_BAIT_without_echo() -> Result<()> {
        for invalid in [
            vec!["assembly", "lock"],
            vec!["assembly", "lock", "--check"],
            vec!["assembly", "lock", "generate", "runtime"],
            vec!["assembly", "lock", "check", "SECRET_BAIT"],
        ] {
            let error = match parse(&invalid) {
                Ok(command) => bail!("invalid lock argv parsed as {command:?}"),
                Err(error) => error,
            };
            assert!(
                !error.to_string().contains("SECRET_BAIT"),
                "diagnostic leaked SECRET_BAIT: {error}"
            );
        }
        Ok(())
    }

    #[test]
    #[allow(non_snake_case)] // 验收过滤名含 SECRET_BAIT
    fn try_parse_SECRET_BAIT_never_echoes_and_distinguishes_kinds() -> Result<()> {
        for args in [
            &["SECRET_BAIT"][..],
            &["codegen", "SECRET_BAIT"][..],
            &["codegen", "--SECRET_BAIT"][..],
            &["consistency", "report", "--format", "SECRET_BAIT"][..],
            &["localtx", "report", "--format", "SECRET_BAIT"][..],
        ] {
            let error = match parse(args) {
                Ok(command) => bail!("bait argv parsed as {command:?}"),
                Err(error) => error,
            };
            let message = error.to_string();
            assert!(
                !message.contains("SECRET_BAIT"),
                "diagnostic leaked SECRET_BAIT for {args:?}: {message}"
            );
        }

        let unknown_sub = parse(&["SECRET_BAIT"])
            .expect_err("unknown subcommand")
            .to_string();
        assert!(
            unknown_sub.contains("unknown subcommand"),
            "subcommand path: {unknown_sub}"
        );
        let unknown_flag = parse(&["codegen", "--SECRET_BAIT"])
            .expect_err("unknown flag")
            .to_string();
        assert!(
            unknown_flag.contains("unexpected argument"),
            "flag path: {unknown_flag}"
        );
        let invalid_value = parse(&["consistency", "report", "--format", "SECRET_BAIT"])
            .expect_err("invalid value")
            .to_string();
        assert!(
            invalid_value.contains("invalid value"),
            "value path: {invalid_value}"
        );
        let trailing = parse(&["codegen", "SECRET_BAIT"])
            .expect_err("trailing unknown")
            .to_string();
        assert!(
            !trailing.contains("SECRET_BAIT"),
            "trailing leaked bait: {trailing}"
        );
        Ok(())
    }
}
