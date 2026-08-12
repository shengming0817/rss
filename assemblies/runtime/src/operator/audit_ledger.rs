// `forbid(clippy::wildcard_imports)` 与 clap derive 的 `allow(clippy::pedantic)` 冲突（E0453）；
// unused_imports 可保持 forbid；wildcard_imports 用 deny。
#![forbid(unused_imports)]
#![deny(clippy::wildcard_imports)]

use anyhow::Context as _;
use audit::ports::{AuditAdminRepo as _, AuditLedgerVerifyReport};
use postgres::{MaintenanceAuditOutcome, PgMaintenanceDeps, PgRuntimeDeps};

use super::projection::{
    service_maintenance_operator_audit_subject, verified_service_maintenance_operator,
};
use super::service_token::OperatorServiceToken;
use super::{build_operator_service_token_provider, parse_positive_usize};
use crate::config::SnapshotConfig;
use crate::domains;
use crate::infra::pg::build_pg_audit_maintenance_config;
use crate::phase::OperatorRuntimeCapability;
#[cfg(feature = "operator-cli")]
use crate::phase::OperatorRuntimeInputs;

const COMMAND_NAMESPACE: &str = "audit-ledger";

/// Whether the rss binary was invoked for audit-ledger operator commands.
///
/// Namespace probe only — not a second argv parser.
#[must_use]
pub fn is_audit_ledger_command(args: &[String]) -> bool {
    matches!(args, [namespace, ..] if namespace == COMMAND_NAMESPACE)
}

pub(super) const AUDIT_LEDGER_VERIFY_OPERATOR_GRANTS_ENV: &str =
    "RSS_AUDIT_LEDGER_VERIFY_OPERATOR_GRANTS";
pub(super) const UNVERIFIED_AUDIT_LEDGER_VERIFY_OPERATOR: &str = "unverified-service-token";

#[derive(Debug)]
pub(super) struct AuditLedgerVerifyArgs {
    pub(super) operator_service_token: OperatorServiceToken,
    pub(super) operator_tenant: rss_request_context::TenantId,
    pub(super) tenant: rss_request_context::TenantId,
    pub(super) batch: vocab::Limit,
}

/// Opaque command whose argv and stdin token were validated before runtime setup.
#[cfg(feature = "operator-cli")]
pub struct PreparedAuditLedgerVerifyCommand(AuditLedgerVerifyArgs);

/// Pure CLI preparation result. Help performs no stdin / environment / provider access beyond
/// clap's own help/version render (already printed when this variant is returned).
#[cfg(feature = "operator-cli")]
pub enum AuditLedgerVerifyCommandPreparation {
    /// Help or version text was already written; caller returns `Ok(())` without runtime.
    Help,
    Execute(PreparedAuditLedgerVerifyCommand),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AuditLedgerVerifyGrant {
    pub(super) tenant: rss_request_context::TenantId,
}

pub(super) fn parse_audit_ledger_verify_batch(raw: &str) -> anyhow::Result<vocab::Limit> {
    let value = parse_positive_usize(raw, "--batch-size")?;
    let value = u16::try_from(value).context("--batch-size exceeds u16")?;
    vocab::Limit::new(value).context("--batch-size must be <= 500")
}

#[cfg(feature = "operator-cli")]
mod clap_cli {
    use super::{
        AuditLedgerVerifyArgs, AuditLedgerVerifyCommandPreparation, COMMAND_NAMESPACE,
        PreparedAuditLedgerVerifyCommand,
    };
    use crate::operator::cli_clap::{
        ClapHelpPrinted, OperatorAuthSharedArgs, map_clap_parse_error,
    };
    use crate::operator::service_token::read_operator_service_token_stdin;
    use clap::{Args, Parser, Subcommand};

    const FAMILY: &str = COMMAND_NAMESPACE;

    // Token material is never accepted on argv: `--operator-service-token-stdin` is presence-only;
    // the opaque token is read from stdin after parse succeeds. Help/version → Help (exit 0);
    // other syntax errors → fixed family-bucketed diagnostic (never echo argv).
    #[derive(Debug, Parser)]
    #[command(
        name = COMMAND_NAMESPACE,
        bin_name = "rss audit-ledger",
        about = "Verify a tenant-scoped audit ledger chain",
        long_about = "Operator commands for per-tenant audit ledger full-chain verify. \
The operator service token is read from stdin after argv validation \
(--operator-service-token-stdin). The help subcommand is disabled; use --help.",
        disable_help_subcommand = true,
        disable_version_flag = true
    )]
    struct AuditLedgerCli {
        #[command(subcommand)]
        action: AuditLedgerSubcommand,
    }

    #[derive(Debug, Subcommand)]
    enum AuditLedgerSubcommand {
        /// Verify the full audit ledger chain for one tenant.
        Verify(AuditLedgerVerifyCliArgs),
    }

    #[derive(Debug, Args)]
    struct AuditLedgerVerifyCliArgs {
        #[command(flatten)]
        auth: OperatorAuthSharedArgs,

        /// Entries scanned per batch (1..=500; default 500).
        #[arg(
            long = "batch-size",
            default_value = "500",
            value_parser = parse_audit_ledger_verify_batch_cli
        )]
        batch_size: vocab::Limit,
    }

    fn parse_audit_ledger_verify_batch_cli(raw: &str) -> Result<vocab::Limit, String> {
        super::parse_audit_ledger_verify_batch(raw).map_err(|err| err.to_string())
    }

    #[cfg(test)]
    pub(in crate::operator) fn parse_audit_ledger_verify_args(
        args: &[String],
        stdin: &mut impl std::io::BufRead,
    ) -> anyhow::Result<AuditLedgerVerifyArgs> {
        match prepare_audit_ledger_verify_command_with_stdin(args, stdin)? {
            AuditLedgerVerifyCommandPreparation::Execute(PreparedAuditLedgerVerifyCommand(
                parsed,
            )) => Ok(parsed),
            AuditLedgerVerifyCommandPreparation::Help => {
                anyhow::bail!("test expected executable audit-ledger command, got help")
            }
        }
    }

    pub(in crate::operator) fn prepare_audit_ledger_verify_command_with_stdin(
        args: &[String],
        stdin: &mut impl std::io::BufRead,
    ) -> anyhow::Result<AuditLedgerVerifyCommandPreparation> {
        let cli = match AuditLedgerCli::try_parse_from(args) {
            Ok(cli) => cli,
            Err(err) => {
                let ClapHelpPrinted = map_clap_parse_error(err, FAMILY)?;
                return Ok(AuditLedgerVerifyCommandPreparation::Help);
            }
        };
        let AuditLedgerSubcommand::Verify(shared) = cli.action;
        // Presence is enforced by clap (`required = true`); token never enters argv.
        debug_assert!(shared.auth.token_stdin.operator_service_token_stdin);
        let operator_service_token = read_operator_service_token_stdin(stdin)?;
        Ok(AuditLedgerVerifyCommandPreparation::Execute(
            PreparedAuditLedgerVerifyCommand(AuditLedgerVerifyArgs {
                operator_service_token,
                operator_tenant: shared.auth.operator_tenant,
                tenant: shared.auth.tenant,
                batch: shared.batch_size,
            }),
        ))
    }
}

#[cfg(all(test, feature = "operator-cli"))]
pub(super) use clap_cli::parse_audit_ledger_verify_args;

/// Validate audit-ledger argv and consume stdin before any runtime / environment / provider prep.
#[cfg(feature = "operator-cli")]
pub fn prepare_audit_ledger_verify_command(
    args: &[String],
) -> anyhow::Result<AuditLedgerVerifyCommandPreparation> {
    let stdin = std::io::stdin();
    clap_cli::prepare_audit_ledger_verify_command_with_stdin(args, &mut stdin.lock())
}

pub(super) fn audit_ledger_verify_resource_id(parsed: &AuditLedgerVerifyArgs) -> String {
    format!("tenant={} batch_size={}", parsed.tenant, parsed.batch.get())
}

pub(super) fn parse_audit_ledger_verify_grants(
    raw: &str,
) -> anyhow::Result<Vec<AuditLedgerVerifyGrant>> {
    let raw = raw.trim();
    anyhow::ensure!(
        !raw.is_empty(),
        "{AUDIT_LEDGER_VERIFY_OPERATOR_GRANTS_ENV} must not be empty"
    );
    let mut grants = Vec::new();
    for entry in raw.split(',') {
        let entry = entry.trim();
        anyhow::ensure!(
            !entry.is_empty(),
            "{AUDIT_LEDGER_VERIFY_OPERATOR_GRANTS_ENV} must not contain empty entries"
        );
        let parts: Vec<&str> = entry.split('|').map(str::trim).collect();
        anyhow::ensure!(
            parts.len() == 1,
            "{AUDIT_LEDGER_VERIFY_OPERATOR_GRANTS_ENV} entries must be tenant"
        );
        let [tenant] = parts.as_slice() else {
            unreachable!("len checked");
        };
        grants.push(AuditLedgerVerifyGrant {
            tenant: rss_request_context::TenantId::parse(tenant).with_context(|| {
                format!("{AUDIT_LEDGER_VERIFY_OPERATOR_GRANTS_ENV} tenant must be a UUID: {tenant}")
            })?,
        });
    }
    anyhow::ensure!(
        !grants.is_empty(),
        "{AUDIT_LEDGER_VERIFY_OPERATOR_GRANTS_ENV} must contain at least one grant"
    );
    Ok(grants)
}

pub(super) fn load_audit_ledger_verify_grants_from_command_env(
    _operator: OperatorRuntimeCapability<'_>,
) -> anyhow::Result<Vec<AuditLedgerVerifyGrant>> {
    let raw = std::env::var(AUDIT_LEDGER_VERIFY_OPERATOR_GRANTS_ENV)
        .with_context(|| format!("{AUDIT_LEDGER_VERIFY_OPERATOR_GRANTS_ENV} is required"))?;
    parse_audit_ledger_verify_grants(&raw)
}

pub(super) fn authorize_audit_ledger_verify_operator(
    parsed: &AuditLedgerVerifyArgs,
    grants: &[AuditLedgerVerifyGrant],
) -> anyhow::Result<()> {
    let allowed = grants.iter().any(|grant| grant.tenant == parsed.tenant);
    anyhow::ensure!(
        allowed,
        "audit ledger verify operator is not authorized for tenant={}",
        parsed.tenant
    );
    Ok(())
}

pub(super) async fn verified_audit_ledger_verify_operator(
    service_token: &str,
    operator_tenant: rss_request_context::TenantId,
    pdp: &diport::DynPdp<'_>,
) -> anyhow::Result<authn::VerifiedMaintenanceServiceOperator> {
    verified_service_maintenance_operator(
        service_token,
        operator_tenant,
        pdp,
        "audit ledger verify",
    )
    .await
}

pub(super) async fn record_audit_ledger_verify_finish_audit(
    pg: &PgMaintenanceDeps,
    operator_subject: &str,
    resource_id: &str,
    outcome: MaintenanceAuditOutcome<'_>,
) -> anyhow::Result<()> {
    pg.record_audit_ledger_verify_audit(
        operator_subject,
        "audit.ledger.verify.finish",
        outcome,
        resource_id,
    )
    .await
    .context("record audit ledger verify finish audit")
}

pub(super) async fn authenticate_audit_ledger_verify_operator(
    pg: &PgMaintenanceDeps,
    operator_pdp: &diport::DynPdp<'_>,
    parsed: &AuditLedgerVerifyArgs,
    resource_id: &str,
) -> anyhow::Result<String> {
    let subject = match verified_audit_ledger_verify_operator(
        parsed.operator_service_token.as_str(),
        parsed.operator_tenant,
        operator_pdp,
    )
    .await
    {
        Ok(proof) => service_maintenance_operator_audit_subject(&proof).to_owned(),
        Err(err) => {
            record_audit_ledger_verify_finish_audit(
                pg,
                UNVERIFIED_AUDIT_LEDGER_VERIFY_OPERATOR,
                resource_id,
                MaintenanceAuditOutcome::Failure {
                    reason: "operator_auth",
                },
            )
            .await?;
            return Err(err);
        }
    };
    Ok(subject)
}

pub(super) async fn audit_ledger_verify_operator_subject(
    pg: &PgMaintenanceDeps,
    parsed: &AuditLedgerVerifyArgs,
    resource_id: &str,
    subject: String,
    operator: OperatorRuntimeCapability<'_>,
) -> anyhow::Result<String> {
    let grants = match load_audit_ledger_verify_grants_from_command_env(operator) {
        Ok(grants) => grants,
        Err(err) => {
            record_audit_ledger_verify_finish_audit(
                pg,
                &subject,
                resource_id,
                MaintenanceAuditOutcome::Failure {
                    reason: "operator_grants",
                },
            )
            .await?;
            return Err(err);
        }
    };
    if let Err(err) = authorize_audit_ledger_verify_operator(parsed, &grants) {
        record_audit_ledger_verify_finish_audit(
            pg,
            &subject,
            resource_id,
            MaintenanceAuditOutcome::Failure {
                reason: "operator_authorization",
            },
        )
        .await?;
        return Err(err);
    }
    Ok(subject)
}

#[allow(async_fn_in_trait)]
pub(super) trait AuditLedgerVerifyRuntime {
    type Session;

    async fn connect_maintenance(&self) -> anyhow::Result<Self::Session>;

    async fn record_audit_ledger_verify_audit(
        &self,
        session: &Self::Session,
        operator_subject: &str,
        action: &str,
        outcome: MaintenanceAuditOutcome<'_>,
        resource_id: &str,
    ) -> anyhow::Result<()>;

    async fn operator_subject(
        &self,
        session: &Self::Session,
        parsed: &AuditLedgerVerifyArgs,
        resource_id: &str,
    ) -> anyhow::Result<String>;

    async fn verify_tenant(
        &self,
        session: &Self::Session,
        parsed: &AuditLedgerVerifyArgs,
    ) -> anyhow::Result<AuditLedgerVerifyReport>;

    async fn shutdown(&self, session: Self::Session);
}

pub(super) struct ProductionAuditLedgerVerifyRuntime<'a> {
    config: SnapshotConfig<'a>,
    operator: OperatorRuntimeCapability<'a>,
}

impl AuditLedgerVerifyRuntime for ProductionAuditLedgerVerifyRuntime<'_> {
    type Session = PgMaintenanceDeps;

    async fn connect_maintenance(&self) -> anyhow::Result<Self::Session> {
        let (migrator_config, audit_admin_config) = build_pg_audit_maintenance_config(self.config)
            .context("build audit maintenance postgres config")?;
        match audit_admin_config.as_ref() {
            Some(config) => {
                PgRuntimeDeps::connect_maintenance_with_audit_admin_config(&migrator_config, config)
                    .await
                    .context("setup postgres maintenance deps with audit admin")
            }
            None => PgRuntimeDeps::connect_maintenance(&migrator_config)
                .await
                .context("setup postgres maintenance deps"),
        }
    }

    async fn record_audit_ledger_verify_audit(
        &self,
        session: &Self::Session,
        operator_subject: &str,
        action: &str,
        outcome: MaintenanceAuditOutcome<'_>,
        resource_id: &str,
    ) -> anyhow::Result<()> {
        session
            .record_audit_ledger_verify_audit(operator_subject, action, outcome, resource_id)
            .await
            .context("record audit ledger verify audit")
    }

    async fn operator_subject(
        &self,
        session: &Self::Session,
        parsed: &AuditLedgerVerifyArgs,
        resource_id: &str,
    ) -> anyhow::Result<String> {
        let provider =
            match build_operator_service_token_provider(self.config, self.operator, session) {
                Ok(provider) => provider,
                Err(err) => {
                    record_audit_ledger_verify_finish_audit(
                        session,
                        UNVERIFIED_AUDIT_LEDGER_VERIFY_OPERATOR,
                        resource_id,
                        MaintenanceAuditOutcome::Failure {
                            reason: "operator_provider_config",
                        },
                    )
                    .await?;
                    return Err(err).context("audit ledger verify operator verifier");
                }
            };
        let subject = authenticate_audit_ledger_verify_operator(
            session,
            diport::DynPdp::from_ref(provider.as_ref()),
            parsed,
            resource_id,
        )
        .await?;
        audit_ledger_verify_operator_subject(session, parsed, resource_id, subject, self.operator)
            .await
    }

    async fn verify_tenant(
        &self,
        session: &Self::Session,
        parsed: &AuditLedgerVerifyArgs,
    ) -> anyhow::Result<AuditLedgerVerifyReport> {
        let hasher = domains::audit::build_audit_hasher_from_snapshot(self.config)
            .context("audit chain key")?;
        let repo = session.audit_admin_repo(hasher).context(
            "audit ledger verify requires RSS_PG_AUDIT_ADMIN_USERNAME/RSS_PG_AUDIT_ADMIN_PASSWORD_FILE",
        )?;
        repo.verify_tenant(parsed.tenant, parsed.batch)
            .await
            .context("verify audit ledger")
    }

    async fn shutdown(&self, session: Self::Session) {
        session.shutdown().await.ok();
    }
}

pub(super) async fn run_audit_ledger_verify_command_with_runtime<R>(
    parsed: AuditLedgerVerifyArgs,
    runtime: &R,
) -> anyhow::Result<()>
where
    R: AuditLedgerVerifyRuntime,
{
    let resource_id = audit_ledger_verify_resource_id(&parsed);
    let session = runtime.connect_maintenance().await?;
    if let Err(err) = runtime
        .record_audit_ledger_verify_audit(
            &session,
            UNVERIFIED_AUDIT_LEDGER_VERIFY_OPERATOR,
            "audit.ledger.verify.start",
            MaintenanceAuditOutcome::Success,
            &resource_id,
        )
        .await
        .context("record audit ledger verify start audit")
    {
        runtime.shutdown(session).await;
        return Err(err);
    }

    let operator_subject = match runtime
        .operator_subject(&session, &parsed, &resource_id)
        .await
    {
        Ok(subject) => subject,
        Err(err) => {
            runtime.shutdown(session).await;
            return Err(err);
        }
    };
    let command_result = runtime.verify_tenant(&session, &parsed).await;
    let finish_outcome = if command_result.is_ok() {
        MaintenanceAuditOutcome::Success
    } else {
        MaintenanceAuditOutcome::Failure {
            reason: "run_error",
        }
    };
    let audit_result = runtime
        .record_audit_ledger_verify_audit(
            &session,
            &operator_subject,
            "audit.ledger.verify.finish",
            finish_outcome,
            &resource_id,
        )
        .await
        .context("record audit ledger verify finish audit");
    runtime.shutdown(session).await;
    audit_result?;
    let report = command_result?;
    println!(
        "operation=verify tenant={} batch_size={} checked_entries={}",
        report.tenant,
        parsed.batch.get(),
        report.checked_entries
    );
    Ok(())
}

/// Execute an authenticated, audited tenant-scoped audit ledger verify command.
///
/// Callers must finish [`prepare_audit_ledger_verify_command`] before opening runtime inputs.
#[cfg(feature = "operator-cli")]
pub async fn run_audit_ledger_verify_command(
    prepared: PreparedAuditLedgerVerifyCommand,
    runtime_inputs: &OperatorRuntimeInputs,
) -> anyhow::Result<()> {
    let runtime = ProductionAuditLedgerVerifyRuntime {
        config: runtime_inputs.config(),
        operator: runtime_inputs.operator_capability(),
    };
    run_audit_ledger_verify_command_with_runtime(prepared.0, &runtime).await
}
