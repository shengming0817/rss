//! xtask CLI 表层：单一 clap derive ADT（`Xtask` + `Command`）。
//!
//! 跨字段业务前置在 [`Command::validate`] 中 fail-closed；
//! 不假装 clap 属性可表达全部 RSS 约束。
//!
//! clap 语法错误与 argv 业务 validate 均脱敏/固定出口（help → exit 0；其余 exit 2）；
//! 解析失败诊断不得回显 unexpected argv 原文（SECRET_BAIT）。
//!
//! ref: clap-rs/clap examples/derive_ref

use crate::ci_impact::{self, LocalOptions, SelectionPlan};
use crate::ci_lanes::{FixedCiInvocation, FixedCiJob};
use crate::integration_shards::IntegrationJobGroup;
use crate::publicapi;
use anyhow::{Result, bail};
use clap::error::ErrorKind;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// RSS 本地治理与验证入口。
#[derive(Debug, Parser, PartialEq, Eq)]
#[command(
    name = "xtask",
    about = "RSS 本地治理与验证入口",
    arg_required_else_help = true
)]
struct Xtask {
    #[command(subcommand)]
    command: Command,
}

/// 唯一命令 ADT：解析结果与 IO 执行分离。
#[derive(Debug, Subcommand, PartialEq, Eq)]
pub(crate) enum Command {
    /// Build a real `.crate` and prove it from an independent offline local-registry consumer.
    PackageProof {
        /// Atomically export the proven Release Surface as a portable candidate bundle.
        #[arg(long, value_name = "ABSENT_ABSOLUTE_DIR")]
        export_candidate_bundle: Option<PathBuf>,
    },
    /// Debezium / CDC connector skeleton。
    #[command(subcommand)]
    CdcConfig(CdcConfigCommand),
    /// ArchRules 派生索引与 funnel 矩阵。
    #[command(subcommand)]
    Archrules(ArchrulesCommand),
    /// source-centric 分层依赖 lint。
    LayerDeps,
    /// workspace.dependencies pin↔lock 漂移门。
    WsdepsDrift,
    /// source semantic 守卫。
    SourceSemanticGuard,
    /// L2 provider conformance 语义校验；裸命令按需生成 target 诊断报告。
    ProviderCapabilities {
        #[arg(long)]
        check: bool,
    },
    /// 本地全量治理门聚合入口。
    Verify {
        /// 列出 registry 派生的合法 gate label 后退出。
        #[arg(long, conflicts_with_all = ["fast", "allow_missing_tools", "against", "fail_fast", "only"])]
        list_gates: bool,
        /// 只跑 registry 显式 Always 的本地 meta 门。
        #[arg(long)]
        fast: bool,
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
    /// governed 高风险路径结构化 defer 完整性 + 经典注解治理门（CI 门）。
    DeferGate,
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
pub(crate) enum CdcConfigCommand {
    /// 输出 Debezium PostgreSQL outbox_log CDC connector JSON skeleton。
    Debezium,
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
pub(crate) enum ArchrulesCommand {
    /// 列出 ArchRules 派生索引。
    List,
    /// ArchRules 语义 closure 门（CI 门）。
    Verify,
    /// 按需生成持久化 funnel 报告到 target/xtask。
    Matrix,
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
    /// cargo-audit 门。
    Audit,
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
            Self::PackageProof {
                export_candidate_bundle: Some(output),
            } => {
                if !output.is_absolute() || output.file_name().is_none() {
                    bail!("package-proof --export-candidate-bundle 必须是带目录名的绝对路径");
                }
                Ok(())
            }
            Self::Verify { only, .. } => {
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
            Self::Ci(CiCommand::Local(options)) => options.validate(),
            Self::Ci(CiCommand::Run {
                job,
                integration_group,
                ..
            }) => {
                FixedCiInvocation::new(*job, *integration_group)?;
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
    use crate::publicapi;

    fn parse(args: &[&str]) -> Result<Command> {
        let mut full = vec!["xtask"];
        full.extend(args);
        parse_from(&full)
    }

    #[test]
    fn try_parse_package_proof_export_is_closed() -> Result<()> {
        assert_eq!(
            parse(&["package-proof"])?,
            Command::PackageProof {
                export_candidate_bundle: None,
            }
        );
        assert_eq!(
            parse(&[
                "package-proof",
                "--export-candidate-bundle",
                "/tmp/rss-candidate-bundle",
            ])?,
            Command::PackageProof {
                export_candidate_bundle: Some("/tmp/rss-candidate-bundle".into()),
            }
        );
        assert!(parse(&["package-proof", "--export-candidate-bundle", "relative",]).is_err());
        assert!(parse(&["package-proof", "--diag-version", "0.1.0"]).is_err());
        Ok(())
    }

    #[test]
    fn try_parse_rejects_empty_and_unknown() {
        assert!(parse(&[]).is_err());
        assert!(parse(&["no-such-command"]).is_err());
        assert!(parse(&["contract", "bogus"]).is_err());
        assert!(parse(&["promtool-rules"]).is_err());
        assert!(parse(&["localtx", "report", "--format", "json"]).is_err());
    }

    #[test]
    fn try_parse_zero_arg_guards_reject_trailing() -> Result<()> {
        for cmd in [
            "layer-deps",
            "wsdeps-drift",
            "source-semantic-guard",
            "defer-gate",
        ] {
            assert!(parse(&[cmd]).is_ok(), "expected ok: {cmd}");
            assert!(
                parse(&[cmd, "extra"]).is_err(),
                "expected trailing reject: {cmd}"
            );
        }
        let Err(err) = parse(&["setlocal-funnel"]) else {
            bail!("retired subcommand must fail")
        };
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
        Ok(())
    }

    #[test]
    fn try_parse_archrules_and_runtime_guards() -> Result<()> {
        assert_eq!(
            parse(&["archrules", "list"])?,
            Command::Archrules(ArchrulesCommand::List)
        );
        assert_eq!(
            parse(&["archrules", "matrix"])?,
            Command::Archrules(ArchrulesCommand::Matrix)
        );
        for bad in [
            &["archrules", "matrix", "--write"][..],
            &["archrules", "matrix", "--check"][..],
            &["archrules", "matrix", "--write", "--check"][..],
        ] {
            assert!(
                parse(bad).is_err(),
                "legacy matrix flags must be rejected: {bad:?}"
            );
        }
        for bad in [
            &["archrules"][..],
            &["runtime-baseline", "verify"][..],
            &["runtime-baseline", "update"][..],
            &["runtime-deps", "guard", "extra"][..],
        ] {
            assert!(parse(bad).is_err(), "accepted {bad:?}");
        }
        Ok(())
    }

    #[test]
    fn try_parse_verify_business_rules() -> Result<()> {
        assert_eq!(
            parse(&["verify", "--list-gates"])?,
            Command::Verify {
                list_gates: true,
                fast: false,
                allow_missing_tools: false,
                against: None,
                fail_fast: false,
                only: vec![],
            }
        );
        assert_eq!(
            parse(&["verify"])?,
            Command::Verify {
                list_gates: false,
                fast: false,
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
                list_gates: false,
                fast: true,
                allow_missing_tools: true,
                against: Some("origin/develop".into()),
                fail_fast: true,
                only: vec!["fmt".into(), "clippy".into()],
            }
        );
        assert!(parse(&["verify", "--only", "fmt", "--only", "fmt"]).is_err());
        assert!(parse(&["verify", "--only", ""]).is_err());
        assert!(parse(&["verify", "--bogus"]).is_err());
        assert!(parse(&["verify", "--against"]).is_err());
        assert!(parse(&["verify", "trailing"]).is_err());
        Ok(())
    }

    fn assert_public_api_parse_surface() -> Result<()> {
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
        Ok(())
    }

    fn assert_ci_local_parse_surface() -> Result<()> {
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
        Ok(())
    }

    fn assert_ci_fixed_parse_surface(selection: &str) -> Result<()> {
        assert!(matches!(
            parse(&["ci", "preflight", "--selection", selection])?,
            Command::Ci(CiCommand::Preflight { .. })
        ));
        assert!(
            parse(&[
                "ci",
                "run",
                "--job",
                "integration-critical",
                "--selection",
                selection,
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
                selection,
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
                selection,
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
                selection,
                "--integration-group",
                "all",
            ])
            .is_err()
        );
        Ok(())
    }

    fn assert_ci_evidence_parse_surface() -> Result<()> {
        // legacy 平铺 argv（无 subcommand）必须拒绝。
        assert!(parse(&["ci", "--base", "origin/develop"]).is_err());
        assert!(parse(&["ci", "localonly-evidence"]).is_err());
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

    fn assert_ci_parse_surface() -> Result<()> {
        assert_ci_local_parse_surface()?;
        let selection = serde_json::to_string(&crate::ci_impact::test_selection_plan()?)?;
        assert_ci_fixed_parse_surface(&selection)?;
        assert_ci_evidence_parse_surface()
    }

    #[test]
    fn try_parse_public_api_and_ci_surface() -> Result<()> {
        assert_public_api_parse_surface()?;
        assert_ci_parse_surface()
    }

    #[test]
    fn try_parse_provider_flags() -> Result<()> {
        assert_eq!(
            parse(&["provider-capabilities", "--check"])?,
            Command::ProviderCapabilities { check: true }
        );
        assert_eq!(
            parse(&["provider-capabilities"])?,
            Command::ProviderCapabilities { check: false }
        );
        for invalid in [
            &["provider-capabilities", "extra"][..],
            &["provider-capabilities", "--output", "report.json"][..],
            &["provider-capabilities", "--check", "--check"][..],
        ] {
            assert!(
                parse(invalid).is_err(),
                "provider capability CLI must reject {invalid:?}"
            );
        }
        Ok(())
    }

    #[test]
    #[allow(non_snake_case)] // 验收过滤名含 SECRET_BAIT
    fn try_parse_SECRET_BAIT_never_echoes() -> Result<()> {
        for args in [
            &["SECRET_BAIT"][..],
            &["package-proof", "SECRET_BAIT"][..],
            &["package-proof", "--SECRET_BAIT"][..],
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

        let Err(unknown_sub) = parse(&["SECRET_BAIT"]) else {
            bail!("unknown subcommand")
        };
        let unknown_sub = unknown_sub.to_string();
        assert!(
            unknown_sub.contains("unknown subcommand"),
            "subcommand path: {unknown_sub}"
        );
        let Err(unknown_flag) = parse(&["package-proof", "--SECRET_BAIT"]) else {
            bail!("unknown flag")
        };
        let unknown_flag = unknown_flag.to_string();
        assert!(
            unknown_flag.contains("unexpected argument"),
            "flag path: {unknown_flag}"
        );
        let Err(trailing) = parse(&["package-proof", "SECRET_BAIT"]) else {
            bail!("trailing unknown")
        };
        let trailing = trailing.to_string();
        assert!(
            !trailing.contains("SECRET_BAIT"),
            "trailing leaked bait: {trailing}"
        );
        Ok(())
    }
}
