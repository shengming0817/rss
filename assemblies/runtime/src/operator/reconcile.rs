// `forbid(clippy::wildcard_imports)` 与 clap derive 的 `allow(clippy::pedantic)` 冲突（E0453）；
// unused_imports 可保持 forbid；wildcard_imports 用 deny。
#![forbid(unused_imports)]
#![deny(clippy::wildcard_imports)]

use super::build_operator_service_token_provider;
use super::projection::{
    service_maintenance_operator_audit_subject, verified_service_maintenance_operator,
};
use super::service_token::OperatorServiceToken;
use anyhow::Context as _;
use eventexec::{OperatorReconcileCapability, ReconcileOperatorStore, ReconcileTargetSummary};
use postgres::{
    MaintenanceAuditOutcome, PgMaintenanceDeps, PgMaintenanceReconcileStore, PgRuntimeDeps,
};

use crate::infra::pg::build_pg_migrator_config;
use crate::phase::OperatorRuntimeCapability;
#[cfg(feature = "operator-cli")]
use crate::phase::OperatorRuntimeInputs;

/// Whether the rss binary was invoked for reconcile target inspection or recovery.
///
/// Namespace probe only — not a second argv parser.
#[must_use]
pub fn is_reconcile_target_command(args: &[String]) -> bool {
    matches!(args, [cmd, ..] if cmd == "reconcile-target")
}

pub(super) const RECONCILE_OPERATOR_GRANTS_ENV: &str = "RSS_RECONCILE_OPERATOR_GRANTS";
pub(super) const UNVERIFIED_RECONCILE_OPERATOR: &str = "unverified-service-token";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReconcileMaintenanceAction {
    Inspect,
    Resume,
}

impl ReconcileMaintenanceAction {
    fn parse(raw: &str) -> anyhow::Result<Self> {
        match raw {
            "inspect" => Ok(Self::Inspect),
            "resume" => Ok(Self::Resume),
            other => anyhow::bail!(
                "unknown reconcile target action in {RECONCILE_OPERATOR_GRANTS_ENV}: {other}"
            ),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Inspect => "inspect",
            Self::Resume => "resume",
        }
    }
}

#[derive(Debug)]
pub(super) struct ReconcileTargetCliArgs {
    action: ReconcileMaintenanceAction,
    operator_service_token: OperatorServiceToken,
    operator_tenant: vocab::TenantId,
    tenant: vocab::TenantId,
    target_id: String,
}

/// Opaque command whose argv and stdin token were validated before runtime setup.
#[cfg(feature = "operator-cli")]
pub struct PreparedReconcileTargetCommand(ReconcileTargetCliArgs);

/// Pure CLI preparation result. Help performs no stdin / environment / provider access beyond
/// clap's own help/version render (already printed when this variant is returned).
#[cfg(feature = "operator-cli")]
pub enum ReconcileTargetCommandPreparation {
    /// Help or version text was already written; caller returns `Ok(())` without runtime.
    Help,
    Execute(PreparedReconcileTargetCommand),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ReconcileMaintenanceGrant {
    action: ReconcileMaintenanceAction,
    tenant: vocab::TenantId,
}

#[cfg(feature = "operator-cli")]
mod clap_cli {
    use super::{
        PreparedReconcileTargetCommand, ReconcileMaintenanceAction, ReconcileTargetCliArgs,
        ReconcileTargetCommandPreparation,
    };
    use crate::operator::cli_clap::{
        ClapHelpPrinted, OperatorAuthSharedArgs, map_clap_parse_error,
    };
    use crate::operator::service_token::read_operator_service_token_stdin;
    use clap::{Args, Parser, Subcommand};

    const FAMILY: &str = "reconcile-target";

    // Token material is never accepted on argv: `--operator-service-token-stdin` is presence-only;
    // the opaque token is read from stdin after parse succeeds. Help/version → Help (exit 0);
    // other syntax errors → fixed family-bucketed diagnostic (never echo argv).
    #[derive(Debug, Parser)]
    #[command(
        name = "reconcile-target",
        bin_name = "rss reconcile-target",
        about = "Inspect or resume a tenant-scoped reconcile target",
        long_about = "Operator commands for reconcile-target inspect and resume. \
The operator service token is read from stdin after argv validation \
(--operator-service-token-stdin).",
        disable_help_subcommand = true,
        disable_version_flag = true
    )]
    struct ReconcileTargetCli {
        #[command(subcommand)]
        action: ReconcileTargetSubcommand,
    }

    #[derive(Debug, Subcommand)]
    enum ReconcileTargetSubcommand {
        /// Inspect a reconcile target (read-only).
        Inspect(ReconcileTargetSharedArgs),
        /// Resume a disabled or stuck reconcile target.
        Resume(ReconcileTargetSharedArgs),
    }

    impl ReconcileTargetSubcommand {
        const fn as_action(&self) -> ReconcileMaintenanceAction {
            match self {
                Self::Inspect(_) => ReconcileMaintenanceAction::Inspect,
                Self::Resume(_) => ReconcileMaintenanceAction::Resume,
            }
        }

        fn into_shared(self) -> ReconcileTargetSharedArgs {
            match self {
                Self::Inspect(shared) | Self::Resume(shared) => shared,
            }
        }
    }

    #[derive(Debug, Args)]
    struct ReconcileTargetSharedArgs {
        #[command(flatten)]
        auth: OperatorAuthSharedArgs,

        /// Reconcile target id (UUID).
        #[arg(long, value_parser = parse_target_id_cli)]
        target_id: String,
    }

    fn parse_target_id_cli(raw: &str) -> Result<String, String> {
        uuid::Uuid::parse_str(raw)
            .map(|id| id.to_string())
            .map_err(|_| "--target-id must be a UUID".to_owned())
    }

    #[cfg(test)]
    pub(in crate::operator) fn parse_reconcile_target_args(
        args: &[String],
        stdin: &mut impl std::io::BufRead,
    ) -> anyhow::Result<ReconcileTargetCliArgs> {
        match prepare_reconcile_target_command_with_stdin(args, stdin)? {
            ReconcileTargetCommandPreparation::Execute(PreparedReconcileTargetCommand(parsed)) => {
                Ok(parsed)
            }
            ReconcileTargetCommandPreparation::Help => {
                anyhow::bail!("test expected executable reconcile-target command, got help")
            }
        }
    }

    pub(in crate::operator) fn prepare_reconcile_target_command_with_stdin(
        args: &[String],
        stdin: &mut impl std::io::BufRead,
    ) -> anyhow::Result<ReconcileTargetCommandPreparation> {
        let cli = match ReconcileTargetCli::try_parse_from(args) {
            Ok(cli) => cli,
            Err(err) => {
                let ClapHelpPrinted = map_clap_parse_error(err, FAMILY)?;
                return Ok(ReconcileTargetCommandPreparation::Help);
            }
        };
        let action = cli.action.as_action();
        let shared = cli.action.into_shared();
        // Presence is enforced by clap (`required = true`); token never enters argv.
        debug_assert!(shared.auth.operator_service_token_stdin);
        let operator_service_token = read_operator_service_token_stdin(stdin)?;
        Ok(ReconcileTargetCommandPreparation::Execute(
            PreparedReconcileTargetCommand(ReconcileTargetCliArgs {
                action,
                operator_service_token,
                operator_tenant: shared.auth.operator_tenant,
                tenant: shared.auth.tenant,
                target_id: shared.target_id,
            }),
        ))
    }
}

#[cfg(all(test, feature = "operator-cli"))]
pub(super) use clap_cli::parse_reconcile_target_args;

/// Validate reconcile-target argv and consume stdin before any runtime / environment / provider prep.
#[cfg(feature = "operator-cli")]
pub fn prepare_reconcile_target_command(
    args: &[String],
) -> anyhow::Result<ReconcileTargetCommandPreparation> {
    let stdin = std::io::stdin();
    clap_cli::prepare_reconcile_target_command_with_stdin(args, &mut stdin.lock())
}

pub(super) fn parse_reconcile_operator_grants(
    raw: &str,
) -> anyhow::Result<Vec<ReconcileMaintenanceGrant>> {
    let raw = raw.trim();
    anyhow::ensure!(
        !raw.is_empty(),
        "{RECONCILE_OPERATOR_GRANTS_ENV} must not be empty"
    );
    let mut grants = Vec::new();
    for entry in raw.split(',') {
        let parts: Vec<_> = entry.split('|').map(str::trim).collect();
        anyhow::ensure!(
            parts.len() == 2,
            "{RECONCILE_OPERATOR_GRANTS_ENV} entries must be action|tenant"
        );
        let [action, tenant] = parts.as_slice() else {
            unreachable!("length checked");
        };
        grants.push(ReconcileMaintenanceGrant {
            action: ReconcileMaintenanceAction::parse(action)?,
            tenant: vocab::TenantId::parse(tenant).with_context(|| {
                format!("{RECONCILE_OPERATOR_GRANTS_ENV} tenant must be a UUID: {tenant}")
            })?,
        });
    }
    Ok(grants)
}

pub(super) fn load_reconcile_operator_grants_from_command_env(
    _operator: OperatorRuntimeCapability<'_>,
) -> anyhow::Result<Vec<ReconcileMaintenanceGrant>> {
    let raw = std::env::var(RECONCILE_OPERATOR_GRANTS_ENV)
        .with_context(|| format!("{RECONCILE_OPERATOR_GRANTS_ENV} is required"))?;
    parse_reconcile_operator_grants(&raw)
}

pub(super) fn authorize_reconcile_operator(
    parsed: &ReconcileTargetCliArgs,
    grants: &[ReconcileMaintenanceGrant],
) -> anyhow::Result<()> {
    anyhow::ensure!(
        grants
            .iter()
            .any(|grant| grant.action == parsed.action && grant.tenant == parsed.tenant),
        "reconcile target operator is not authorized for action={} tenant={}",
        parsed.action.as_str(),
        parsed.tenant
    );
    Ok(())
}

pub(super) async fn record_reconcile_audit(
    pg: &PgMaintenanceDeps,
    subject: &str,
    action: &str,
    outcome: MaintenanceAuditOutcome<'_>,
    resource_id: &str,
) -> anyhow::Result<()> {
    pg.record_reconcile_maintenance_audit(subject, action, outcome, resource_id)
        .await
        .context("record reconcile target maintenance audit")
}

pub(super) fn reconcile_summary_json(summary: &ReconcileTargetSummary) -> anyhow::Result<String> {
    serde_json::to_string(&serde_json::json!({
        "tenant": summary.tenant().to_string(),
        "targetId": summary.target_id(),
        "reconcilerId": summary.reconciler_id(),
        "resourceKind": summary.resource_kind(),
        "status": summary.status().as_label(),
        "disabledReason": summary.disabled_reason().map(|reason| reason.as_label()),
    }))
    .context("render reconcile target summary")
}

pub(super) async fn execute_reconcile_target_command(
    store: &PgMaintenanceReconcileStore,
    parsed: &ReconcileTargetCliArgs,
    capability: OperatorReconcileCapability,
) -> anyhow::Result<ReconcileTargetSummary> {
    match parsed.action {
        ReconcileMaintenanceAction::Inspect => ReconcileOperatorStore::inspect_target(
            store,
            parsed.tenant,
            &parsed.target_id,
            capability,
        )
        .await
        .map_err(anyhow::Error::new),
        ReconcileMaintenanceAction::Resume => ReconcileOperatorStore::resume_target(
            store,
            parsed.tenant,
            &parsed.target_id,
            capability,
        )
        .await
        .map_err(anyhow::Error::new),
    }
}

pub(super) fn issue_authorized_reconcile_capability() -> OperatorReconcileCapability {
    OperatorReconcileCapability::issue_for_authorized_operator()
}

/// Execute an authenticated, audited tenant-scoped reconcile target operator command.
///
/// Callers must finish [`prepare_reconcile_target_command`] before opening runtime inputs.
#[cfg(feature = "operator-cli")]
pub async fn run_reconcile_target_command(
    prepared: PreparedReconcileTargetCommand,
    runtime_inputs: &OperatorRuntimeInputs,
) -> anyhow::Result<()> {
    let parsed = prepared.0;
    let config = runtime_inputs.config();
    let resource_id = format!("tenant={} target_id={}", parsed.tenant, parsed.target_id);
    let start_action = format!("reconcile.target.{}.start", parsed.action.as_str());
    let finish_action = format!("reconcile.target.{}.finish", parsed.action.as_str());
    let pg = PgRuntimeDeps::connect_maintenance(&build_pg_migrator_config(config)?)
        .await
        .context("setup postgres maintenance deps")?;
    if let Err(error) = record_reconcile_audit(
        &pg,
        UNVERIFIED_RECONCILE_OPERATOR,
        &start_action,
        MaintenanceAuditOutcome::Success,
        &resource_id,
    )
    .await
    {
        pg.shutdown().await.ok();
        return Err(error);
    }
    let operator = runtime_inputs.operator_capability();
    let provider = match build_operator_service_token_provider(config, operator, &pg) {
        Ok(provider) => provider,
        Err(error) => {
            record_reconcile_audit(
                &pg,
                UNVERIFIED_RECONCILE_OPERATOR,
                &finish_action,
                MaintenanceAuditOutcome::Failure {
                    reason: "operator_provider_config",
                },
                &resource_id,
            )
            .await?;
            pg.shutdown().await.ok();
            return Err(error).context("reconcile target operator verifier");
        }
    };
    let subject = match verified_service_maintenance_operator(
        parsed.operator_service_token.as_str(),
        parsed.operator_tenant,
        diport::DynPdp::from_ref(provider.as_ref()),
        "reconcile target maintenance",
    )
    .await
    {
        Ok(proof) => service_maintenance_operator_audit_subject(&proof).to_owned(),
        Err(error) => {
            record_reconcile_audit(
                &pg,
                UNVERIFIED_RECONCILE_OPERATOR,
                &finish_action,
                MaintenanceAuditOutcome::Failure {
                    reason: "operator_auth",
                },
                &resource_id,
            )
            .await?;
            pg.shutdown().await.ok();
            return Err(error);
        }
    };
    let authorization = load_reconcile_operator_grants_from_command_env(operator)
        .and_then(|grants| authorize_reconcile_operator(&parsed, &grants));
    if let Err(error) = authorization {
        record_reconcile_audit(
            &pg,
            &subject,
            &finish_action,
            MaintenanceAuditOutcome::Failure {
                reason: "operator_authorization",
            },
            &resource_id,
        )
        .await?;
        pg.shutdown().await.ok();
        return Err(error);
    }
    let command_result = execute_reconcile_target_command(
        &pg.reconcile_store(),
        &parsed,
        issue_authorized_reconcile_capability(),
    )
    .await;
    let outcome = if command_result.is_ok() {
        MaintenanceAuditOutcome::Success
    } else {
        MaintenanceAuditOutcome::Failure {
            reason: "run_error",
        }
    };
    let audit_result =
        record_reconcile_audit(&pg, &subject, &finish_action, outcome, &resource_id).await;
    pg.shutdown().await.ok();
    audit_result?;
    let summary = command_result?;
    println!("{}", reconcile_summary_json(&summary)?);
    Ok(())
}
