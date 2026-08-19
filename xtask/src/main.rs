//! xtask — RSS 治理 / codegen 入口。见 docs/rules/architecture.md §xtask、§Rust 原生强制（三档载体）。
//!
//! 命令目录以 clap `--help` / [`cli`] 为单源；此处不维护长命令清单。

#![deny(clippy::unreachable)]

mod archrules;
mod assembly;
mod assembly_artifacts;
mod assembly_codegen;
mod assembly_governance;
mod assembly_lock;
mod assembly_runtime_plan;
mod cdc_config;
mod ci_entry_guard;
mod ci_impact;
mod ci_lanes;
mod cli;
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
mod evidence_file;
mod execution_profiles;
mod generated_file;
mod graph;
mod inbox_cutover_guard;
mod integration_shards;
mod l2_assurance;
mod layerdeps;
mod layers;
mod localonly_evidence;
mod localtx_coverage;
mod localtx_evidence;
mod localtx_report;
mod outbox_same_id_guard;
mod package_proof;
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
mod release_surface;
mod repo_scope_guard;
mod report_format;
mod runtime_assembly_residual;
mod runtime_deps_guard;
mod runtime_env_guard;
mod runtime_root_guard;
mod saga_durable_recovery_guard;
mod schema_rls;
mod shipped_feature_guard;
mod source_semantic_guard;
mod src_scan;
mod tenancy_closeout;
mod tenant_migration_tables;
#[cfg(test)]
mod testutil;
mod verify;
mod workspace_facts;
mod wsdeps;

use anyhow::{Context, Result, bail};
use cli::{
    ArchrulesCommand, AssemblyArtifactsCommand, AssemblyCommand, CdcConfigCommand, CiCommand,
    Command, ConsistencyCommand, ContractCommand, GraphCommand, LocaltxCommand,
    NextestEvidenceCommand, RuntimeDepsCommand, RuntimeEnvCommand, RuntimeRootCommand,
};
pub(crate) use report_format::ReportFormat;
use std::path::{Path, PathBuf};

fn main() -> Result<()> {
    dispatch(cli::parse_or_exit()?)
}

fn dispatch(command: Command) -> Result<()> {
    match command {
        Command::Codegen { check } => codegen::run(check),
        Command::PackageProof {
            export_candidate_bundle,
        } => package_proof::run_command(export_candidate_bundle.as_deref()),
        Command::CdcConfig(CdcConfigCommand::Debezium) => cdc_config::run_debezium(),
        Command::Contract(ContractCommand::Validate) => {
            diagnostic::run_check(&contract::validate::ContractValidate)
        }
        Command::Contract(ContractCommand::Breaking { against }) => {
            let against =
                against.unwrap_or_else(|| contract::breaking::DEFAULT_AGAINST.to_string());
            contract::breaking::run(&against)
        }
        Command::Assembly(AssemblyCommand::Validate) => {
            let root = workspace_root()?;
            let command_facts = workspace_facts::CommandWorkspaceFacts::new(&root);
            let facts = command_facts
                .get()
                .context("assembly validate: load command-scoped workspace facts")?;
            diagnostic::run_check(&assembly::AssemblyValidate::new(&root, facts))
        }
        Command::Assembly(AssemblyCommand::Artifacts(AssemblyArtifactsCommand::Check)) => {
            let root = workspace_root()?;
            let prepared = assembly_artifacts::prepare(&root)?;
            let command_facts = workspace_facts::CommandWorkspaceFacts::new(&root);
            let facts = match command_facts.get() {
                Ok(facts) => facts,
                Err(error) => {
                    assembly_artifacts::report_workspace_facts_failure();
                    return Err(error)
                        .context("assembly artifacts: load command-scoped workspace facts");
                }
            };
            assembly_artifacts::run_prepared(&root, facts, prepared)
        }
        Command::Assembly(AssemblyCommand::GenerateModules { check }) => {
            assembly_codegen::run(check)
        }
        Command::Assembly(AssemblyCommand::GenerateProviders { check }) => {
            assembly_codegen::run_providers(check)
        }
        Command::Assembly(AssemblyCommand::GenerateRuntimePlans { check }) => {
            assembly_runtime_plan::run(check)
        }
        Command::Assembly(AssemblyCommand::Lock(action)) => {
            let root = workspace_root()?;
            let command_facts = workspace_facts::CommandWorkspaceFacts::new(&root);
            let facts = command_facts
                .get()
                .context("assembly lock: load command-scoped workspace facts")?;
            assembly_lock::run(&root, action, facts)
        }
        Command::Graph(GraphCommand::Assembly(options)) => {
            let root = workspace_root()?;
            let command_facts = workspace_facts::CommandWorkspaceFacts::new(&root);
            let facts = command_facts
                .get()
                .context("assembly graph: load command-scoped workspace facts")?;
            graph::run(&root, &options, facts)
        }
        Command::Archrules(ArchrulesCommand::List) => archrules::list(),
        Command::Archrules(ArchrulesCommand::Verify) => {
            diagnostic::run_check(&archrules::ArchRules)
        }
        Command::Archrules(ArchrulesCommand::Matrix { write, check }) => {
            let action = match (write, check) {
                (false, false) => archrules::MatrixAction::Print,
                (true, false) => archrules::MatrixAction::Write,
                (false, true) => archrules::MatrixAction::Check,
                (true, true) => bail!("matrix write and check are mutually exclusive"),
            };
            archrules::matrix(action)
        }
        Command::RuntimeRoot(RuntimeRootCommand::Guard) => {
            diagnostic::run_check(&runtime_root_guard::RuntimeRootGuard)
        }
        Command::RuntimeDeps(RuntimeDepsCommand::Guard) => {
            diagnostic::run_check(&runtime_deps_guard::RuntimeDepsGuard)
        }
        Command::RuntimeEnv(RuntimeEnvCommand::Guard) => {
            diagnostic::run_check(&runtime_env_guard::RuntimeEnvGuard)
        }
        Command::LayerDeps => diagnostic::run_check(&layerdeps::LayerDeps),
        Command::WsdepsDrift => diagnostic::run_check(&wsdeps::WsDepsDrift),
        Command::SourceSemanticGuard => {
            diagnostic::run_check(&source_semantic_guard::SourceSemanticGuard)
        }
        Command::SagaDurableRecoveryGuard => {
            diagnostic::run_check(&saga_durable_recovery_guard::SagaDurableRecoveryGuard)
        }
        Command::PromtoolRules => promtool::run(),
        Command::OutboxSameIdGuard => {
            diagnostic::run_check(&outbox_same_id_guard::OutboxSameIdGuard)
        }
        Command::ConsistencyFixtures => {
            diagnostic::run_check(&consistency_fixtures::ConsistencyFixtures)
        }
        Command::Consistency(ConsistencyCommand::LocalOnlyEffects) => {
            let root = workspace_root()?;
            let command_facts = workspace_facts::CommandWorkspaceFacts::new(&root);
            let facts = command_facts
                .get()
                .context("local-only-effects: load command-scoped workspace facts")?;
            diagnostic::run_check(&consistency_effects::LocalOnlyEffects::new(&root, facts))
        }
        Command::Consistency(ConsistencyCommand::Report { format }) => {
            let root = workspace_root()?;
            let command_facts = workspace_facts::CommandWorkspaceFacts::new(&root);
            let facts = command_facts
                .get()
                .context("consistency report: load command-scoped workspace facts")?;
            consistency_effects::run_report(&root, facts, format[0])
        }
        Command::Localtx(LocaltxCommand::Report { format }) => {
            localtx_report::run_report(format[0])
        }
        Command::LocaltxCoverage => {
            let root = workspace_root()?;
            let command_facts = workspace_facts::CommandWorkspaceFacts::new(&root);
            let facts = command_facts
                .get()
                .context("localtx-coverage: load command-scoped workspace facts")?;
            diagnostic::run_check(&localtx_coverage::LocalTxCoverage::new(&root, facts))
        }
        Command::L2Assurance { check } => {
            let root = workspace_root()?;
            let command_facts = workspace_facts::CommandWorkspaceFacts::new(&root);
            let facts = command_facts
                .get()
                .context("l2-assurance: load command-scoped workspace facts")?;
            l2_assurance::run(&root, facts, check)
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
        Command::Ci(CiCommand::ValidateEvidence {
            kind,
            input,
            output,
        }) => {
            let root = workspace_root()?;
            let command_facts = workspace_facts::CommandWorkspaceFacts::new(&root);
            let facts = command_facts
                .get()
                .context("validate-evidence: load command-scoped workspace facts")?;
            match kind {
                cli::RequiredEvidenceKind::Localonly => {
                    localonly_evidence::validate_upload_snapshot(&input, &output, &root, facts)
                }
                cli::RequiredEvidenceKind::Localtx => {
                    localtx_evidence::validate_upload_snapshot(&input, &output, &root, facts)
                }
            }
        }
        Command::Ci(CiCommand::LocalonlyEvidence { output }) => {
            let root = workspace_root()?;
            let command_facts = workspace_facts::CommandWorkspaceFacts::new(&root);
            let facts = command_facts
                .get()
                .context("localonly-evidence: load command-scoped workspace facts")?;
            let request = localonly_evidence::prepare_request(
                ci_lanes::FixedCiJob::TestAffected,
                Some(&output),
                &root,
            )?
            .context("LocalOnly evidence owner must prepare a request")?;
            localonly_evidence::execute(&root, facts, request, cmd::ExecutionPolicy::FailFast)?;
            Ok(())
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
        Command::SchemaRls => diagnostic::run_check(&schema_rls::SchemaRlsGuard),
        Command::InboxCutoverGuard => {
            diagnostic::run_check(&inbox_cutover_guard::InboxCutoverGuard)
        }
        Command::DlxLifecycleFunnel => {
            diagnostic::run_check(&dlx_lifecycle_funnel::DlxLifecycleFunnel)
        }
        Command::PgTenantTxGuard => diagnostic::run_check(&pg_tenant_tx_guard::PgTenantTxGuard),
        Command::RepoScopeGuard => diagnostic::run_check(&repo_scope_guard::RepoScopeGuard),
        Command::ReconcileOutboxCommandGuard => {
            diagnostic::run_check(&reconcile_outbox_command_guard::ReconcileOutboxCommandGuard)
        }
        Command::TenancyCloseout => diagnostic::run_check(&tenancy_closeout::TenancyCloseout),
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
