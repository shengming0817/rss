//! xtask — RSS 治理与验证入口。见 `Cargo.toml`、`xtask/src/layers.rs`、`deny.toml` 与 `cargo xtask layer-deps`）。
//!
//! 命令目录以 clap `--help` / [`cli`] 为单源；此处不维护长命令清单。

#![deny(clippy::unreachable)]

mod archrules;
mod cdc_config;
mod ci_entry_guard;
mod ci_impact;
mod ci_lanes;
mod cli;
mod cmd;
pub(crate) use cmd::nextest;
mod coverage;
mod defergate;
mod diagnostic;
mod diffcov;
mod execution_profiles;
mod generated_file;
mod integration_shards;
mod layerdeps;
mod layers;
mod package_proof;
mod pdpallow;
mod provider_capabilities;
mod publicapi;
mod release_surface;
mod source_semantic_guard;
mod src_scan;
#[cfg(test)]
mod testutil;
mod verify;
mod workspace_facts;
mod wsdeps;

use anyhow::Result;
use cli::{ArchrulesCommand, CdcConfigCommand, CiCommand, Command, NextestEvidenceCommand};
use std::path::{Path, PathBuf};

fn main() -> Result<()> {
    dispatch(cli::parse_or_exit()?)
}

fn dispatch(command: Command) -> Result<()> {
    match command {
        Command::PackageProof {
            export_candidate_bundle,
        } => package_proof::run_command(export_candidate_bundle.as_deref()),
        Command::CdcConfig(CdcConfigCommand::Debezium) => cdc_config::run_debezium(),
        Command::Archrules(ArchrulesCommand::List) => {
            let root = workspace_root()?;
            let command_facts = workspace_facts::CommandWorkspaceFacts::new(&root);
            archrules::list(command_facts.get()?)
        }
        Command::Archrules(ArchrulesCommand::Verify) => {
            let root = workspace_root()?;
            let command_facts = workspace_facts::CommandWorkspaceFacts::new(&root);
            diagnostic::run_check(&archrules::ArchRules::new(command_facts.get()?))
        }
        Command::Archrules(ArchrulesCommand::Matrix) => {
            let root = workspace_root()?;
            let command_facts = workspace_facts::CommandWorkspaceFacts::new(&root);
            archrules::matrix(command_facts.get()?)
        }
        Command::LayerDeps => diagnostic::run_check(&layerdeps::LayerDeps),
        Command::WsdepsDrift => diagnostic::run_check(&wsdeps::WsDepsDrift),
        Command::SourceSemanticGuard => {
            diagnostic::run_check(&source_semantic_guard::SourceSemanticGuard)
        }
        Command::ProviderCapabilities { check } => provider_capabilities::run(check),
        Command::Verify {
            list_gates,
            fast,
            allow_missing_tools,
            against,
            fail_fast,
            only,
        } => verify::run(
            list_gates,
            fast,
            allow_missing_tools,
            against.as_deref(),
            fail_fast,
            &only,
        ),
        Command::PublicApi(command) => publicapi::run(command),
        Command::Ci(CiCommand::Full {
            allow_missing_tools,
            fail_fast,
        }) => verify::run_ci(allow_missing_tools, fail_fast),
        Command::Ci(CiCommand::Local(options)) => {
            ci_impact::run_local(&workspace_root()?, &options)
        }
        Command::Ci(CiCommand::Run {
            job,
            selection,
            integration_group,
        }) => {
            let invocation = ci_lanes::FixedCiInvocation::new(job, integration_group)?;
            verify::run_fixed_job(invocation, selection.as_ref())
        }
        Command::Ci(CiCommand::Preflight { selection }) => {
            verify::run_remote_preflight(selection.as_ref())
        }
        Command::Ci(CiCommand::Audit) => verify::run_audit(false),
        Command::Ci(CiCommand::Plan(options)) => ci_impact::run(&workspace_root()?, &options),
        Command::NextestEvidence(NextestEvidenceCommand::Stage) => {
            nextest::stage(&workspace_root()?)
        }
        Command::NextestEvidence(NextestEvidenceCommand::Inspect { artifact_root }) => {
            nextest::inspect(&artifact_root)
        }
        Command::NextestEvidence(NextestEvidenceCommand::Replay { sidecar }) => {
            nextest::replay(&sidecar, &workspace_root()?)
        }
        Command::DeferGate => diagnostic::run_check(&defergate::DeferGate),
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
