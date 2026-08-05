//! Closed L2 DR recovery operator command.
//!
//! Parsing and stdin consumption complete before runtime preparation. The provider mutation is
//! reachable only after service-token authentication, exact tenant grant authorization and a
//! durable start audit. Publication remains owned by the normal outbox relay.
//!
//! ref: oxidecomputer/steno src/lib.rs@main (typed operator recovery); RSS narrows this command to
//! one tenant-scoped apply action and binds it to a canonical same-ID recovery plan.
//! ref: clap derive (reconcile.rs clap_cli)

use anyhow::Context as _;
use eventexec::L2DrRecoveryStore as _;
use postgres::{MaintenanceAuditOutcome, PgL2DrRecoveryDeps};

use super::build_operator_service_token_provider;
use super::projection::{
    service_maintenance_operator_audit_subject, verified_service_maintenance_operator,
};
use super::service_token::OperatorServiceToken;
use crate::infra::pg::build_pg_l2_dr_recovery_configs;
use crate::phase::OperatorRuntimeCapability;
#[cfg(feature = "operator-cli")]
use crate::phase::OperatorRuntimeInputs;

pub(super) const L2_DR_RECOVERY_OPERATOR_GRANTS_ENV: &str = "RSS_L2_DR_RECOVERY_OPERATOR_GRANTS";
const COMMAND_NAMESPACE: &str = "l2-dr-recovery";
const COMPONENT: &str = "l2_dr_recovery";
const IDENTICAL_PLAN_RETRY_HINT: &str =
    "retry the same epoch with the identical plan and keep admission paused";
const STOP_RECONCILE_CONTEXT: &str =
    "apply L2 DR recovery plan failed; stop and reconcile frozen inputs before retrying";
const IDENTICAL_PLAN_RETRY_CONTEXT: &str = "apply L2 DR recovery plan; retry the same epoch with the identical plan and keep admission paused";

/// Whether argv selects the sole closed L2 DR operator command.
///
/// Namespace probe only — not a second argv parser.
#[must_use]
pub fn is_l2_dr_recovery_command(args: &[String]) -> bool {
    matches!(args, [namespace, ..] if namespace == COMMAND_NAMESPACE)
}

#[derive(Debug)]
pub(super) struct L2DrRecoveryCliArgs {
    operator_service_token: OperatorServiceToken,
    operator_tenant: vocab::TenantId,
    plan: eventexec::L2DrRecoveryPlan,
}

/// Opaque command whose argv and stdin token have been validated before runtime setup.
#[cfg(feature = "operator-cli")]
pub struct PreparedL2DrRecoveryCommand(L2DrRecoveryCliArgs);

/// Pure CLI preparation result. Help performs no stdin / environment / provider access beyond
/// clap's own help/version render (already printed when this variant is returned).
#[cfg(feature = "operator-cli")]
pub enum L2DrRecoveryCommandPreparation {
    /// Help or version text was already written; caller returns `Ok(())` without runtime.
    Help,
    Execute(PreparedL2DrRecoveryCommand),
}

#[cfg(feature = "operator-cli")]
mod clap_cli {
    // `forbid(clippy::wildcard_imports)` 与 clap derive 的 `allow(clippy::pedantic)` 冲突（E0453）；
    // unused_imports 可保持 forbid；wildcard_imports 用 deny。
    #![forbid(unused_imports)]
    #![deny(clippy::wildcard_imports)]

    use super::{
        COMMAND_NAMESPACE, L2DrRecoveryCliArgs, L2DrRecoveryCommandPreparation,
        PreparedL2DrRecoveryCommand,
    };
    use crate::operator::cli_clap::{
        ClapHelpPrinted, OperatorAuthSharedArgs, map_clap_parse_error,
    };
    use crate::operator::service_token::read_operator_service_token_stdin;
    use anyhow::Context as _;
    use clap::{Args, Parser, Subcommand};

    const FAMILY: &str = COMMAND_NAMESPACE;

    // Token material is never accepted on argv: `--operator-service-token-stdin` is presence-only;
    // the opaque token is read from stdin after parse succeeds. Help/version → Help (exit 0);
    // other syntax errors → fixed family-bucketed diagnostic (never echo argv).
    //
    // `L2DrRecoveryPlan::new` stays after stdin (RSS owns divergent-plan precondition).
    #[derive(Debug, Parser)]
    #[command(
        name = COMMAND_NAMESPACE,
        bin_name = "rss l2-dr-recovery",
        about = "Apply one authorized, start-audited L2 recovery plan",
        long_about = "Operator command for closed L2 DR recovery apply. \
The operator service token is read from stdin after argv validation \
(--operator-service-token-stdin). The help subcommand is disabled; use --help.",
        disable_help_subcommand = true,
        disable_version_flag = true
    )]
    struct L2DrRecoveryCli {
        #[command(subcommand)]
        action: L2DrRecoverySubcommand,
    }

    #[derive(Debug, Subcommand)]
    enum L2DrRecoverySubcommand {
        /// Apply one authorized, start-audited L2 recovery plan.
        Apply(L2DrRecoveryApplyArgs),
    }

    #[derive(Debug, Args)]
    struct L2DrRecoveryApplyArgs {
        #[command(flatten)]
        auth: OperatorAuthSharedArgs,

        /// Canonical non-nil recovery epoch id (UUID).
        #[arg(long, value_parser = parse_epoch_id_cli)]
        epoch_id: eventexec::RecoveryEpochId,

        /// Change ticket (1..=128 printable ASCII).
        #[arg(long, value_parser = parse_change_ticket_cli)]
        change_ticket: eventexec::RecoveryChangeTicket,

        /// PostgreSQL restore point (positive UTC epoch micros).
        #[arg(long, value_parser = parse_pg_restore_point_cli)]
        pg_restore_point_micros: eventexec::UtcEpochMicros,

        /// RabbitMQ restore point (positive UTC epoch micros).
        #[arg(long, value_parser = parse_rabbitmq_restore_point_cli)]
        rabbitmq_restore_point_micros: eventexec::UtcEpochMicros,

        /// Stable event id; repeat 1..=500 unique values.
        #[arg(
            long = "event-id",
            required = true,
            action = clap::ArgAction::Append,
            value_parser = parse_event_id_cli
        )]
        event_ids: Vec<consistency::IdemKey>,
    }

    fn parse_epoch_id_cli(raw: &str) -> Result<eventexec::RecoveryEpochId, String> {
        eventexec::RecoveryEpochId::parse(raw)
            .map_err(|_| "--epoch-id must be a canonical non-nil UUID".to_owned())
    }

    fn parse_change_ticket_cli(raw: &str) -> Result<eventexec::RecoveryChangeTicket, String> {
        eventexec::RecoveryChangeTicket::parse(raw)
            .map_err(|_| "--change-ticket is invalid".to_owned())
    }

    fn parse_restore_point_cli(
        raw: &str,
        flag: &'static str,
    ) -> Result<eventexec::UtcEpochMicros, String> {
        let value = raw
            .parse::<i64>()
            .map_err(|_| format!("{flag} must be a positive i64"))?;
        eventexec::UtcEpochMicros::new(value).map_err(|_| format!("{flag} must be positive"))
    }

    fn parse_pg_restore_point_cli(raw: &str) -> Result<eventexec::UtcEpochMicros, String> {
        parse_restore_point_cli(raw, "--pg-restore-point-micros")
    }

    fn parse_rabbitmq_restore_point_cli(raw: &str) -> Result<eventexec::UtcEpochMicros, String> {
        parse_restore_point_cli(raw, "--rabbitmq-restore-point-micros")
    }

    fn parse_event_id_cli(raw: &str) -> Result<consistency::IdemKey, String> {
        consistency::IdemKey::parse(raw).map_err(|_| "--event-id must be non-empty".to_owned())
    }

    #[cfg(test)]
    pub(in crate::operator) fn parse_l2_dr_recovery_args(
        args: &[String],
        stdin: &mut impl std::io::BufRead,
    ) -> anyhow::Result<L2DrRecoveryCliArgs> {
        match prepare_l2_dr_recovery_command_with_stdin(args, stdin)? {
            L2DrRecoveryCommandPreparation::Execute(PreparedL2DrRecoveryCommand(parsed)) => {
                Ok(parsed)
            }
            L2DrRecoveryCommandPreparation::Help => {
                anyhow::bail!("test expected an executable L2 DR recovery command")
            }
        }
    }

    pub(in crate::operator) fn prepare_l2_dr_recovery_command_with_stdin(
        args: &[String],
        stdin: &mut impl std::io::BufRead,
    ) -> anyhow::Result<L2DrRecoveryCommandPreparation> {
        debug_assert_eq!(
            args.first().map(String::as_str),
            Some(COMMAND_NAMESPACE),
            "family prepare expects argv[0] == {COMMAND_NAMESPACE}"
        );
        let cli = match L2DrRecoveryCli::try_parse_from(args) {
            Ok(cli) => cli,
            Err(err) => {
                let ClapHelpPrinted = map_clap_parse_error(err, FAMILY)?;
                return Ok(L2DrRecoveryCommandPreparation::Help);
            }
        };
        let L2DrRecoverySubcommand::Apply(shared) = cli.action;
        // Presence is enforced by clap (`required = true`); token never enters argv.
        debug_assert!(shared.auth.token_stdin.operator_service_token_stdin);
        // Event-set cardinality/uniqueness fails closed before stdin.
        let events = eventexec::RecoveryEventSet::new(shared.event_ids)
            .context("--event-id must contain 1..=500 unique stable IDs")?;
        let operator_service_token = read_operator_service_token_stdin(stdin)?;
        // Plan divergence / restore-point ordering stays after token (RSS owns).
        let plan = eventexec::L2DrRecoveryPlan::new(
            shared.epoch_id,
            shared.auth.tenant,
            shared.pg_restore_point_micros,
            shared.rabbitmq_restore_point_micros,
            events,
            shared.change_ticket,
        )
        .context("invalid divergent L2 DR recovery plan")?;
        Ok(L2DrRecoveryCommandPreparation::Execute(
            PreparedL2DrRecoveryCommand(L2DrRecoveryCliArgs {
                operator_service_token,
                operator_tenant: shared.auth.operator_tenant,
                plan,
            }),
        ))
    }
}

#[cfg(all(test, feature = "operator-cli"))]
pub(super) use clap_cli::parse_l2_dr_recovery_args;

/// Validate exact argv and consume the one stdin token before any provider is prepared.
#[cfg(feature = "operator-cli")]
pub fn prepare_l2_dr_recovery_command(
    args: &[String],
) -> anyhow::Result<L2DrRecoveryCommandPreparation> {
    let stdin = std::io::stdin();
    clap_cli::prepare_l2_dr_recovery_command_with_stdin(args, &mut stdin.lock())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct L2DrRecoveryOperatorGrant {
    tenant: vocab::TenantId,
}

fn parse_l2_dr_recovery_operator_grants(
    raw: &str,
) -> anyhow::Result<Vec<L2DrRecoveryOperatorGrant>> {
    anyhow::ensure!(
        !raw.trim().is_empty(),
        "{L2_DR_RECOVERY_OPERATOR_GRANTS_ENV} is empty"
    );
    raw.split(',')
        .map(|entry| {
            let parts = entry.split('|').map(str::trim).collect::<Vec<_>>();
            anyhow::ensure!(
                matches!(parts.as_slice(), ["apply", _]),
                "{L2_DR_RECOVERY_OPERATOR_GRANTS_ENV} entries must be exact apply|tenant"
            );
            let tenant = vocab::TenantId::parse(parts[1])
                .context("L2 DR recovery grant tenant must be a UUID")?;
            Ok(L2DrRecoveryOperatorGrant { tenant })
        })
        .collect()
}

/// Load the immutable exact grant set through the closed runtime snapshot.
pub(super) fn load_l2_dr_recovery_operator_grants_from_snapshot(
    config: crate::config::SnapshotConfig<'_>,
    _operator: OperatorRuntimeCapability<'_>,
) -> anyhow::Result<Vec<L2DrRecoveryOperatorGrant>> {
    let raw = config
        .value(L2_DR_RECOVERY_OPERATOR_GRANTS_ENV)
        .with_context(|| format!("{L2_DR_RECOVERY_OPERATOR_GRANTS_ENV} is required"))?;
    parse_l2_dr_recovery_operator_grants(raw)
}

fn authorize_l2_dr_recovery_operator(
    parsed: &L2DrRecoveryCliArgs,
    grants: &[L2DrRecoveryOperatorGrant],
) -> anyhow::Result<()> {
    anyhow::ensure!(
        grants
            .iter()
            .any(|grant| grant.tenant == parsed.plan.tenant()),
        "L2 DR recovery operator is not authorized for action=apply tenant={}",
        parsed.plan.tenant()
    );
    Ok(())
}

#[allow(async_fn_in_trait)]
trait L2DrRecoveryCommandRuntime {
    type Session;

    async fn connect(&self) -> anyhow::Result<Self::Session>;
    async fn authenticate(
        &self,
        session: &Self::Session,
        parsed: &L2DrRecoveryCliArgs,
    ) -> anyhow::Result<eventexec::L2DrRecoveryOperatorSubject>;
    fn authorize(&self, parsed: &L2DrRecoveryCliArgs) -> anyhow::Result<()>;
    async fn audit_start(
        &self,
        session: &Self::Session,
        parsed: &L2DrRecoveryCliArgs,
        subject: &eventexec::L2DrRecoveryOperatorSubject,
        start_audit_id: uuid::Uuid,
    ) -> anyhow::Result<eventexec::L2DrRecoveryDurableStartProof>;
    async fn audit_finish(
        &self,
        session: &Self::Session,
        parsed: &L2DrRecoveryCliArgs,
        subject: &eventexec::L2DrRecoveryOperatorSubject,
        start_audit_id: uuid::Uuid,
        outcome: MaintenanceAuditOutcome<'_>,
    ) -> anyhow::Result<()>;
    async fn apply(
        &self,
        session: &Self::Session,
        authorized: eventexec::AuthorizedL2DrRecoveryPlan,
        capability: eventexec::OperatorL2DrRecoveryCapability,
    ) -> Result<eventexec::L2DrRecoveryReceipt, eventexec::L2DrRecoveryError>;
    async fn shutdown(&self, session: Self::Session) -> anyhow::Result<()>;
}

struct ProductionL2DrRecoveryRuntime<'a> {
    operator_config: crate::config::SnapshotConfig<'a>,
    l2_dr_config: crate::config::SnapshotConfig<'a>,
    operator: OperatorRuntimeCapability<'a>,
    grants: Vec<L2DrRecoveryOperatorGrant>,
}

impl L2DrRecoveryCommandRuntime for ProductionL2DrRecoveryRuntime<'_> {
    type Session = PgL2DrRecoveryDeps;

    async fn connect(&self) -> anyhow::Result<Self::Session> {
        let (audit_config, executor_config) = build_pg_l2_dr_recovery_configs(self.l2_dr_config)?;
        PgL2DrRecoveryDeps::connect(&audit_config, &executor_config)
            .await
            .context("setup L2 DR recovery postgres capability")
    }

    async fn authenticate(
        &self,
        session: &Self::Session,
        parsed: &L2DrRecoveryCliArgs,
    ) -> anyhow::Result<eventexec::L2DrRecoveryOperatorSubject> {
        let provider =
            build_operator_service_token_provider(self.operator_config, self.operator, session)
                .context("L2 DR recovery operator verifier")?;
        verified_service_maintenance_operator(
            parsed.operator_service_token.as_str(),
            parsed.operator_tenant,
            diport::DynPdp::from_ref(provider.as_ref()),
            "L2 DR recovery maintenance",
        )
        .await
        .and_then(|proof| {
            eventexec::L2DrRecoveryOperatorSubject::parse(
                service_maintenance_operator_audit_subject(&proof),
            )
            .context("validate L2 DR recovery operator audit subject")
        })
    }

    fn authorize(&self, parsed: &L2DrRecoveryCliArgs) -> anyhow::Result<()> {
        authorize_l2_dr_recovery_operator(parsed, &self.grants)
    }

    async fn audit_start(
        &self,
        session: &Self::Session,
        parsed: &L2DrRecoveryCliArgs,
        subject: &eventexec::L2DrRecoveryOperatorSubject,
        start_audit_id: uuid::Uuid,
    ) -> anyhow::Result<eventexec::L2DrRecoveryDurableStartProof> {
        session
            .record_l2_dr_recovery_start_audit_subject(subject, &parsed.plan, start_audit_id)
            .await
            .context("record L2 DR recovery operator start audit")
    }

    async fn audit_finish(
        &self,
        session: &Self::Session,
        parsed: &L2DrRecoveryCliArgs,
        subject: &eventexec::L2DrRecoveryOperatorSubject,
        start_audit_id: uuid::Uuid,
        outcome: MaintenanceAuditOutcome<'_>,
    ) -> anyhow::Result<()> {
        session
            .record_l2_dr_recovery_finish_audit_subject(
                subject,
                parsed.plan.tenant(),
                parsed.plan.epoch_id().as_uuid(),
                start_audit_id,
                outcome,
            )
            .await
            .context("record L2 DR recovery operator finish audit")
    }

    async fn apply(
        &self,
        session: &Self::Session,
        authorized: eventexec::AuthorizedL2DrRecoveryPlan,
        capability: eventexec::OperatorL2DrRecoveryCapability,
    ) -> Result<eventexec::L2DrRecoveryReceipt, eventexec::L2DrRecoveryError> {
        if authorized.capability() != capability {
            return Err(eventexec::L2DrRecoveryError::InvalidOperatorCaller);
        }
        session.apply_l2_dr_recovery(authorized).await
    }

    async fn shutdown(&self, session: Self::Session) -> anyhow::Result<()> {
        session
            .shutdown()
            .await
            .context("shutdown L2 DR recovery postgres capability")
    }
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct L2DrRecoveryCommandOutput {
    epoch_id: String,
    tenant: String,
    direction: &'static str,
    pg_restore_point_micros: i64,
    rabbitmq_restore_point_micros: i64,
    digest: String,
    event_ids: Vec<String>,
    policy_revision: String,
    first_start_audit_id: String,
    applied_at: i64,
    outcome: &'static str,
}

impl L2DrRecoveryCommandOutput {
    fn from_receipt(receipt: &eventexec::L2DrRecoveryReceipt) -> Self {
        Self {
            epoch_id: receipt.epoch_id().as_uuid().to_string(),
            tenant: receipt.tenant().to_string(),
            direction: receipt.direction().as_label(),
            pg_restore_point_micros: receipt.database_restore_point().get(),
            rabbitmq_restore_point_micros: receipt.broker_restore_point().get(),
            digest: format!("sha256:{}", receipt.plan_digest().to_hex()),
            event_ids: receipt
                .events()
                .iter()
                .map(|event| event.as_str().to_owned())
                .collect(),
            policy_revision: receipt.policy_revision().to_owned(),
            first_start_audit_id: receipt.start_audit_id().to_string(),
            applied_at: receipt.applied_at().get(),
            outcome: receipt.outcome().as_label(),
        }
    }

    #[cfg(test)]
    fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_else(|_| {
            serde_json::json!({
                "outcome": "serialization_error"
            })
        })
    }
}

pub(super) fn issue_authorized_l2_dr_recovery_capability()
-> eventexec::OperatorL2DrRecoveryCapability {
    eventexec::OperatorL2DrRecoveryCapability::issue_for_authorized_operator()
}

fn apply_failure_context(error: eventexec::L2DrRecoveryError) -> &'static str {
    match error {
        eventexec::L2DrRecoveryError::ApplyLostLock
        | eventexec::L2DrRecoveryError::StoreUnavailable => IDENTICAL_PLAN_RETRY_CONTEXT,
        _ => STOP_RECONCILE_CONTEXT,
    }
}

async fn finish_audit_after_apply<R: L2DrRecoveryCommandRuntime>(
    runtime: &R,
    session: &R::Session,
    parsed: &L2DrRecoveryCliArgs,
    subject: &eventexec::L2DrRecoveryOperatorSubject,
    start_audit_id: uuid::Uuid,
    receipt: &eventexec::L2DrRecoveryReceipt,
) -> anyhow::Result<()> {
    if let Err(audit_error) = runtime
        .audit_finish(
            session,
            parsed,
            subject,
            start_audit_id,
            MaintenanceAuditOutcome::Success,
        )
        .await
    {
        tracing::error!(
            component = COMPONENT,
            operation = "finish_audit_after_apply",
            secondary_failure = "finish_audit",
            recovery_outcome = receipt.outcome().as_label(),
            error = %secure::redact_error(audit_error.as_ref()),
            "L2 DR recovery finish audit failed after a durable apply"
        );
        anyhow::bail!(
            "L2 DR recovery apply committed but finish audit failed; {IDENTICAL_PLAN_RETRY_HINT}"
        );
    }
    Ok(())
}

async fn finish_audit_after_rejection<R: L2DrRecoveryCommandRuntime>(
    runtime: &R,
    session: &R::Session,
    parsed: &L2DrRecoveryCliArgs,
    subject: &eventexec::L2DrRecoveryOperatorSubject,
    start_audit_id: uuid::Uuid,
    error: eventexec::L2DrRecoveryError,
) {
    if let Err(audit_error) = runtime
        .audit_finish(
            session,
            parsed,
            subject,
            start_audit_id,
            MaintenanceAuditOutcome::Failure {
                reason: error.audit_reason(),
            },
        )
        .await
    {
        tracing::error!(
            component = COMPONENT,
            operation = "finish_audit_after_rejection",
            secondary_failure = "finish_audit",
            recovery_error = error.as_label(),
            error = %secure::redact_error(audit_error.as_ref()),
            "L2 DR recovery finish audit failed after an apply failure"
        );
    }
}

async fn execute_connected_l2_dr_recovery<R: L2DrRecoveryCommandRuntime>(
    parsed: &L2DrRecoveryCliArgs,
    runtime: &R,
    session: &R::Session,
) -> anyhow::Result<L2DrRecoveryCommandOutput> {
    let subject = runtime
        .authenticate(session, parsed)
        .await
        .context("authenticate L2 DR recovery operator")?;
    runtime
        .authorize(parsed)
        .context("authorize L2 DR recovery operator")?;
    let capability = issue_authorized_l2_dr_recovery_capability();
    let start_audit_id = uuid::Uuid::new_v4();
    let proof = runtime
        .audit_start(session, parsed, &subject, start_audit_id)
        .await
        .context("persist L2 DR recovery start audit")?;
    let authorized = eventexec::AuthorizedL2DrRecoveryPlan::from_authenticated_and_authorized(
        parsed.plan.clone(),
        proof,
        capability,
    )
    .context("bind L2 DR recovery authorization")?;
    match runtime.apply(session, authorized, capability).await {
        Ok(receipt) => {
            finish_audit_after_apply(runtime, session, parsed, &subject, start_audit_id, &receipt)
                .await?;
            Ok(L2DrRecoveryCommandOutput::from_receipt(&receipt))
        }
        Err(error) => {
            finish_audit_after_rejection(runtime, session, parsed, &subject, start_audit_id, error)
                .await;
            Err(anyhow::Error::new(error).context(apply_failure_context(error)))
        }
    }
}

#[derive(Debug)]
struct CommittedCleanupFailure {
    kind: &'static str,
    output: L2DrRecoveryCommandOutput,
}

impl std::fmt::Display for CommittedCleanupFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "L2 DR recovery apply committed but {} failed; outcome={} epoch_id={} tenant={}; {IDENTICAL_PLAN_RETRY_HINT}",
            self.kind, self.output.outcome, self.output.epoch_id, self.output.tenant
        )
    }
}

impl std::error::Error for CommittedCleanupFailure {}

fn committed_cleanup_error(
    kind: &'static str,
    output: &L2DrRecoveryCommandOutput,
) -> anyhow::Error {
    anyhow::Error::new(CommittedCleanupFailure {
        kind,
        output: output.clone(),
    })
}

fn emit_committed_output(error: &anyhow::Error) -> anyhow::Result<()> {
    if let Some(failure) = error.downcast_ref::<CommittedCleanupFailure>() {
        println!("{}", serde_json::to_string(&failure.output)?);
    }
    Ok(())
}

fn log_postgres_cleanup_after_failure(shutdown_error: anyhow::Error) {
    tracing::error!(
        component = COMPONENT,
        operation = "postgres_shutdown_after_failure",
        secondary_failure = "postgres_cleanup",
        error = %secure::redact_error(shutdown_error.as_ref()),
        "L2 DR recovery postgres cleanup failed after command failure"
    );
}

fn log_postgres_cleanup_after_commit(
    output: &L2DrRecoveryCommandOutput,
    shutdown_error: anyhow::Error,
) {
    tracing::error!(
        component = COMPONENT,
        operation = "postgres_shutdown_after_commit",
        secondary_failure = "postgres_cleanup",
        recovery_outcome = output.outcome,
        error = %secure::redact_error(shutdown_error.as_ref()),
        "L2 DR recovery postgres cleanup failed after a committed apply"
    );
}

fn log_runtime_cleanup_after_failure(cleanup_error: anyhow::Error) {
    tracing::error!(
        component = COMPONENT,
        operation = "runtime_shutdown_after_failure",
        secondary_failure = "runtime_cleanup",
        error = %secure::redact_error(cleanup_error.as_ref()),
        "L2 DR recovery runtime cleanup failed after command failure"
    );
}

fn log_runtime_cleanup_after_commit(
    output: &L2DrRecoveryCommandOutput,
    cleanup_error: anyhow::Error,
) {
    tracing::error!(
        component = COMPONENT,
        operation = "runtime_shutdown_after_commit",
        secondary_failure = "runtime_cleanup",
        recovery_outcome = output.outcome,
        error = %secure::redact_error(cleanup_error.as_ref()),
        "L2 DR recovery runtime cleanup failed after a committed apply"
    );
}

fn combine_command_and_postgres_shutdown(
    command_result: anyhow::Result<L2DrRecoveryCommandOutput>,
    shutdown_result: anyhow::Result<()>,
) -> anyhow::Result<L2DrRecoveryCommandOutput> {
    match (command_result, shutdown_result) {
        (Ok(output), Ok(())) => Ok(output),
        (Ok(output), Err(shutdown_error)) => {
            log_postgres_cleanup_after_commit(&output, shutdown_error);
            Err(committed_cleanup_error("postgres cleanup", &output))
        }
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(shutdown_error)) => {
            log_postgres_cleanup_after_failure(shutdown_error);
            Err(error)
        }
    }
}

fn emit_command_output_after_runtime_cleanup(
    command_result: anyhow::Result<L2DrRecoveryCommandOutput>,
    runtime_cleanup: anyhow::Result<()>,
) -> anyhow::Result<()> {
    match (command_result, runtime_cleanup) {
        (Ok(output), Ok(())) => {
            println!("{}", serde_json::to_string(&output)?);
            Ok(())
        }
        (Ok(output), Err(cleanup_error)) => {
            println!("{}", serde_json::to_string(&output)?);
            log_runtime_cleanup_after_commit(&output, cleanup_error);
            Err(committed_cleanup_error("runtime cleanup", &output))
        }
        (Err(error), Ok(())) => {
            emit_committed_output(&error)?;
            Err(error)
        }
        (Err(error), Err(cleanup_error)) => {
            emit_committed_output(&error)?;
            log_runtime_cleanup_after_failure(cleanup_error);
            Err(error)
        }
    }
}

async fn execute_l2_dr_recovery_with_runtime<R: L2DrRecoveryCommandRuntime>(
    parsed: L2DrRecoveryCliArgs,
    runtime: &R,
) -> anyhow::Result<L2DrRecoveryCommandOutput> {
    let session = runtime.connect().await?;
    let command_result = execute_connected_l2_dr_recovery(&parsed, runtime, &session).await;
    let shutdown_result = runtime.shutdown(session).await;
    combine_command_and_postgres_shutdown(command_result, shutdown_result)
}

/// Execute the prepared command and print exactly one safe JSON result on success.
#[cfg(feature = "operator-cli")]
pub async fn run_l2_dr_recovery_command(
    command: PreparedL2DrRecoveryCommand,
    runtime_inputs: OperatorRuntimeInputs,
) -> anyhow::Result<()> {
    let l2_dr_snapshot =
        crate::config::RuntimeConfigSnapshot::capture_l2_dr_operator_process_snapshot()
            .context("capture L2 DR recovery operator configuration")?;
    let command_result = {
        let config = l2_dr_snapshot.view();
        let operator = runtime_inputs.operator_capability();
        let grants = load_l2_dr_recovery_operator_grants_from_snapshot(config, operator)?;
        execute_l2_dr_recovery_with_runtime(
            command.0,
            &ProductionL2DrRecoveryRuntime {
                operator_config: runtime_inputs.config(),
                l2_dr_config: config,
                operator,
                grants,
            },
        )
        .await
    };
    let runtime_cleanup = super::shutdown_runtime(runtime_inputs).await;
    emit_command_output_after_runtime_cleanup(command_result, runtime_cleanup)
}

#[cfg(all(test, feature = "operator-cli"))]
mod tests {
    use super::*;
    use crate::operator::cli_clap::assert_operator_cli_err;
    use std::io::Cursor;
    use std::sync::Mutex;

    const OPERATOR_TENANT: &str = "018f5d8a-7b6c-7d2e-8a1b-1234567890aa";
    const TENANT: &str = "018f5d8a-7b6c-7d2e-8a1b-1234567890ab";
    const EPOCH: &str = "018f5d8a-7b6c-7d2e-8a1b-1234567890ac";

    fn argv(events: &[&str]) -> Vec<String> {
        let mut args = [
            COMMAND_NAMESPACE,
            "apply",
            "--operator-service-token-stdin",
            "--operator-tenant",
            OPERATOR_TENANT,
            "--tenant",
            TENANT,
            "--epoch-id",
            EPOCH,
            "--change-ticket",
            "CHG-1837",
            "--pg-restore-point-micros",
            "1700000000000200",
            "--rabbitmq-restore-point-micros",
            "1700000000000100",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        for event in events {
            args.push("--event-id".to_owned());
            args.push((*event).to_owned());
        }
        args
    }

    #[allow(clippy::expect_used)]
    // reason: test helpers must panic loudly when the closed argv fixture cannot be prepared.
    fn parse(args: &[String]) -> anyhow::Result<L2DrRecoveryCliArgs> {
        parse_l2_dr_recovery_args(args, &mut Cursor::new(b"opaque-token\n"))
    }

    #[allow(clippy::expect_used)]
    // reason: flag mutation fixtures must panic loudly when the closed argv shape drifts.
    fn replace_flag_value(args: &mut [String], flag: &str, value: &str) {
        let index = args
            .iter()
            .position(|candidate| candidate == flag)
            .expect("flag exists");
        args[index + 1] = value.to_owned();
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: positive-path CLI fixtures must panic loudly on parse regression.
    fn dr_recovery_cli_builds_one_canonical_plan_and_keeps_token_redacted() {
        let parsed = parse(&argv(&["event-b", "event-a"])).expect("valid command");
        assert_eq!(parsed.operator_tenant.to_string(), OPERATOR_TENANT);
        assert_eq!(parsed.plan.tenant().to_string(), TENANT);
        assert_eq!(parsed.plan.epoch_id().as_uuid().to_string(), EPOCH);
        assert_eq!(
            parsed
                .plan
                .events()
                .iter()
                .map(consistency::IdemKey::as_str)
                .collect::<Vec<_>>(),
            ["event-a", "event-b"]
        );
        assert_eq!(
            format!("{:?}", parsed.operator_service_token),
            "OperatorServiceToken(<redacted>)"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: help fixtures must panic loudly when preparation unexpectedly fails.
    fn dr_recovery_namespace_and_apply_help_do_not_consume_stdin() {
        for args in [
            vec![COMMAND_NAMESPACE, "--help"],
            vec![COMMAND_NAMESPACE, "apply", "--help"],
        ] {
            let args = args.into_iter().map(str::to_owned).collect::<Vec<_>>();
            let mut stdin = Cursor::new(b"must-remain-unread\n");
            let L2DrRecoveryCommandPreparation::Help =
                clap_cli::prepare_l2_dr_recovery_command_with_stdin(&args, &mut stdin)
                    .expect("help preparation")
            else {
                panic!("expected help");
            };
            assert_eq!(stdin.position(), 0);
        }
    }

    #[test]
    fn dr_recovery_cli_rejects_unknown_duplicate_and_invalid_evidence_before_stdin() {
        let clap_invalid = [
            vec!["--unknown".to_owned(), "value".to_owned()],
            vec!["--tenant".to_owned(), TENANT.to_owned()],
            vec![
                "--rabbitmq-restore-point-micros".to_owned(),
                "1700000000000200".to_owned(),
            ],
        ];
        for tail in clap_invalid {
            let mut candidate = argv(&["event-a"]);
            candidate.extend(tail);
            let mut stdin = Cursor::new(b"must-remain-unread\n");
            let Err(err) =
                clap_cli::prepare_l2_dr_recovery_command_with_stdin(&candidate, &mut stdin)
            else {
                panic!("invalid argv must fail closed");
            };
            assert_eq!(stdin.position(), 0);
            assert_operator_cli_err(&err, "l2-dr-recovery");
        }

        // Event-set uniqueness is RSS-owned (before stdin), not a clap family bucket.
        let mut duplicate_event = argv(&["same", "same"]);
        let mut stdin = Cursor::new(b"must-remain-unread\n");
        assert!(
            clap_cli::prepare_l2_dr_recovery_command_with_stdin(&duplicate_event, &mut stdin)
                .is_err()
        );
        assert_eq!(stdin.position(), 0);

        duplicate_event.retain(|value| value != "--operator-service-token-stdin");
        let mut stdin = Cursor::new(b"must-remain-unread\n");
        let Err(err) =
            clap_cli::prepare_l2_dr_recovery_command_with_stdin(&duplicate_event, &mut stdin)
        else {
            panic!("missing stdin flag must fail closed");
        };
        assert_eq!(stdin.position(), 0);
        assert_operator_cli_err(&err, "l2-dr-recovery");

        let mut stdin = Cursor::new(b"must-remain-unread\n");
        let Err(err) = clap_cli::prepare_l2_dr_recovery_command_with_stdin(
            &[COMMAND_NAMESPACE.to_owned(), "status".to_owned()],
            &mut stdin,
        ) else {
            panic!("unknown subcommand must fail closed");
        };
        assert_eq!(stdin.position(), 0);
        assert_operator_cli_err(&err, "l2-dr-recovery");

        let mut equal_points = argv(&["event-a"]);
        replace_flag_value(
            &mut equal_points,
            "--rabbitmq-restore-point-micros",
            "1700000000000200",
        );
        assert!(parse(&equal_points).is_err());

        let mut non_positive = argv(&["event-a"]);
        replace_flag_value(&mut non_positive, "--pg-restore-point-micros", "0");
        let mut stdin = Cursor::new(b"must-remain-unread\n");
        let Err(err) =
            clap_cli::prepare_l2_dr_recovery_command_with_stdin(&non_positive, &mut stdin)
        else {
            panic!("non-positive restore point must fail closed");
        };
        assert_eq!(stdin.position(), 0);
        assert_operator_cli_err(&err, "l2-dr-recovery");
    }

    #[test]
    #[allow(non_snake_case)] // 验收过滤名含 SECRET_BAIT
    fn dr_recovery_args_SECRET_BAIT_assignment_is_redacted() {
        let mut stdin = Cursor::new(b"must-remain-unread\n");
        let mut args = argv(&["event-a"]);
        let flag = args
            .iter()
            .position(|value| value == "--operator-service-token-stdin")
            .expect("stdin flag");
        args[flag] = "--operator-service-token-stdin=SECRET_BAIT".to_owned();
        let Err(err) = clap_cli::prepare_l2_dr_recovery_command_with_stdin(&args, &mut stdin)
        else {
            panic!("TooManyValues must fail closed");
        };
        assert_eq!(stdin.position(), 0);
        assert_operator_cli_err(&err, "l2-dr-recovery");
    }

    #[test]
    fn dr_recovery_cli_enforces_the_repeated_event_cardinality_bound() {
        let command = |count: usize| {
            let mut candidate = argv(&[]);
            for index in 0..count {
                candidate.push("--event-id".to_owned());
                candidate.push(format!("event-{index:03}"));
            }
            candidate
        };
        assert!(parse(&command(500)).is_ok());
        assert!(parse(&command(501)).is_err());
        // Missing --event-id and empty event set fail closed before stdin.
        let missing_event = argv(&[]);
        let mut stdin = Cursor::new(b"must-remain-unread\n");
        assert!(
            clap_cli::prepare_l2_dr_recovery_command_with_stdin(&missing_event, &mut stdin)
                .is_err()
        );
        assert_eq!(stdin.position(), 0);
        assert!(parse(&command(0)).is_err());
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: grant fixtures must panic loudly when the closed grant parser regresses.
    fn dr_recovery_grants_are_exact_action_and_tenant_only() {
        let grants =
            parse_l2_dr_recovery_operator_grants(&format!("apply|{TENANT}")).expect("exact grant");
        let parsed = parse(&argv(&["event-a"])).expect("valid command");
        assert!(authorize_l2_dr_recovery_operator(&parsed, &grants).is_ok());
        for invalid in [
            format!("*|{TENANT}"),
            "apply|*".to_owned(),
            format!("apply|{OPERATOR_TENANT}"),
            format!("apply|{TENANT}|extra"),
            String::new(),
        ] {
            let result = parse_l2_dr_recovery_operator_grants(&invalid)
                .and_then(|candidate| authorize_l2_dr_recovery_operator(&parsed, &candidate));
            assert!(result.is_err(), "grant must fail closed: {invalid:?}");
        }
    }

    #[derive(Default)]
    struct FakeRuntime {
        calls: Mutex<Vec<&'static str>>,
        audit_subjects: Mutex<Vec<String>>,
        apply_subjects: Mutex<Vec<String>>,
        finish_reasons: Mutex<Vec<Option<String>>>,
        fail_authenticate: bool,
        fail_authorize: bool,
        fail_start_audit: bool,
        fail_finish_audit: bool,
        fail_apply: bool,
        apply_error: Option<eventexec::L2DrRecoveryError>,
        fail_shutdown: bool,
    }

    #[allow(async_fn_in_trait)]
    impl L2DrRecoveryCommandRuntime for FakeRuntime {
        type Session = ();

        async fn connect(&self) -> anyhow::Result<Self::Session> {
            #[allow(clippy::expect_used)]
            // reason: FakeRuntime call log is a single-threaded test fixture.
            self.calls.lock().expect("calls").push("connect");
            Ok(())
        }

        async fn authenticate(
            &self,
            _session: &Self::Session,
            _parsed: &L2DrRecoveryCliArgs,
        ) -> anyhow::Result<eventexec::L2DrRecoveryOperatorSubject> {
            #[allow(clippy::expect_used)]
            // reason: FakeRuntime call log is a single-threaded test fixture.
            self.calls.lock().expect("calls").push("authenticate");
            if self.fail_authenticate {
                anyhow::bail!("authenticate failed")
            }
            eventexec::L2DrRecoveryOperatorSubject::parse("service:l2-dr-runtime")
                .map_err(anyhow::Error::from)
        }

        fn authorize(&self, _parsed: &L2DrRecoveryCliArgs) -> anyhow::Result<()> {
            #[allow(clippy::expect_used)]
            // reason: FakeRuntime call log is a single-threaded test fixture.
            self.calls.lock().expect("calls").push("authorize");
            if self.fail_authorize {
                anyhow::bail!("authorize failed")
            }
            Ok(())
        }

        async fn audit_start(
            &self,
            _session: &Self::Session,
            parsed: &L2DrRecoveryCliArgs,
            subject: &eventexec::L2DrRecoveryOperatorSubject,
            start_audit_id: uuid::Uuid,
        ) -> anyhow::Result<eventexec::L2DrRecoveryDurableStartProof> {
            #[allow(clippy::expect_used)]
            // reason: FakeRuntime call log is a single-threaded test fixture.
            self.calls.lock().expect("calls").push("audit_start");
            #[allow(clippy::expect_used)]
            // reason: FakeRuntime subject log is a single-threaded test fixture.
            self.audit_subjects
                .lock()
                .expect("audit subjects")
                .push(subject.as_str().to_owned());
            if self.fail_start_audit {
                anyhow::bail!("start audit failed")
            }
            eventexec::L2DrRecoveryDurableStartProof::from_store(
                vocab::ServiceCallerDomain::MaintenanceOperator,
                subject.clone(),
                parsed.plan.tenant(),
                parsed.plan.epoch_id(),
                *parsed.plan.digest(),
                start_audit_id,
            )
            .map_err(anyhow::Error::from)
        }

        async fn audit_finish(
            &self,
            _session: &Self::Session,
            _parsed: &L2DrRecoveryCliArgs,
            subject: &eventexec::L2DrRecoveryOperatorSubject,
            _start_audit_id: uuid::Uuid,
            outcome: MaintenanceAuditOutcome<'_>,
        ) -> anyhow::Result<()> {
            #[allow(clippy::expect_used)]
            // reason: FakeRuntime call log is a single-threaded test fixture.
            self.calls.lock().expect("calls").push("audit_finish");
            #[allow(clippy::expect_used)]
            // reason: FakeRuntime subject log is a single-threaded test fixture.
            self.audit_subjects
                .lock()
                .expect("audit subjects")
                .push(subject.as_str().to_owned());
            #[allow(clippy::expect_used)]
            // reason: FakeRuntime finish-reason log is a single-threaded test fixture.
            self.finish_reasons
                .lock()
                .expect("finish reasons")
                .push(match outcome {
                    MaintenanceAuditOutcome::Success => None,
                    MaintenanceAuditOutcome::Failure { reason } => Some(reason.to_owned()),
                });
            if self.fail_finish_audit {
                anyhow::bail!("sensitive finish audit failure")
            }
            Ok(())
        }

        async fn apply(
            &self,
            _session: &Self::Session,
            authorized: eventexec::AuthorizedL2DrRecoveryPlan,
            capability: eventexec::OperatorL2DrRecoveryCapability,
        ) -> Result<eventexec::L2DrRecoveryReceipt, eventexec::L2DrRecoveryError> {
            #[allow(clippy::expect_used)]
            // reason: FakeRuntime call log is a single-threaded test fixture.
            self.calls.lock().expect("calls").push("apply");
            if authorized.capability() != capability {
                return Err(eventexec::L2DrRecoveryError::InvalidOperatorCaller);
            }
            #[allow(clippy::expect_used)]
            // reason: FakeRuntime apply-subject log is a single-threaded test fixture.
            self.apply_subjects
                .lock()
                .expect("apply subjects")
                .push(authorized.operator_subject().as_str().to_owned());
            if let Some(error) = self.apply_error {
                return Err(error);
            }
            if self.fail_apply {
                return Err(eventexec::L2DrRecoveryError::ApplyLostLock);
            }
            #[allow(clippy::expect_used)]
            // reason: FakeRuntime receipt timestamp is a fixed positive fixture.
            let applied_at =
                eventexec::UtcEpochMicros::new(1_700_000_000_000_300).expect("valid timestamp");
            let durable = eventexec::L2DrRecoveryDurableReceipt::from_store(
                authorized.plan().epoch_id(),
                authorized.plan().tenant(),
                authorized.plan().database_restore_point(),
                authorized.plan().broker_restore_point(),
                *authorized.plan().digest(),
                authorized.plan().direction(),
                authorized.plan().events().clone(),
                "same-id-delivery-v1".to_owned(),
                authorized.operator_subject().clone(),
                authorized.start_audit_id(),
                applied_at,
                eventexec::L2DrRecoveryOutcome::Applied,
            )?;
            eventexec::L2DrRecoveryReceipt::from_store(&authorized, durable)
        }

        async fn shutdown(&self, _session: Self::Session) -> anyhow::Result<()> {
            #[allow(clippy::expect_used)]
            // reason: FakeRuntime call log is a single-threaded test fixture.
            self.calls.lock().expect("calls").push("shutdown");
            if self.fail_shutdown {
                anyhow::bail!("sensitive shutdown failure")
            }
            Ok(())
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    // reason: authn failure ordering fixtures must panic loudly on call-log races.
    async fn dr_recovery_authenticate_failure_performs_zero_recovery_side_effects() {
        let runtime = FakeRuntime {
            fail_authenticate: true,
            ..FakeRuntime::default()
        };
        let parsed = parse(&argv(&["event-a"])).expect("valid command");
        assert!(
            execute_l2_dr_recovery_with_runtime(parsed, &runtime)
                .await
                .is_err()
        );
        assert_eq!(
            *runtime.calls.lock().expect("calls"),
            ["connect", "authenticate", "shutdown"]
        );
        assert!(
            runtime
                .audit_subjects
                .lock()
                .expect("audit subjects")
                .is_empty()
        );
        assert!(
            runtime
                .apply_subjects
                .lock()
                .expect("apply subjects")
                .is_empty()
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    // reason: authz failure ordering fixtures must panic loudly on call-log races.
    async fn dr_recovery_authorize_failure_performs_zero_recovery_side_effects() {
        let runtime = FakeRuntime {
            fail_authorize: true,
            ..FakeRuntime::default()
        };
        let parsed = parse(&argv(&["event-a"])).expect("valid command");
        assert!(
            execute_l2_dr_recovery_with_runtime(parsed, &runtime)
                .await
                .is_err()
        );
        assert_eq!(
            *runtime.calls.lock().expect("calls"),
            ["connect", "authenticate", "authorize", "shutdown"]
        );
        assert!(
            runtime
                .audit_subjects
                .lock()
                .expect("audit subjects")
                .is_empty()
        );
        assert!(
            runtime
                .apply_subjects
                .lock()
                .expect("apply subjects")
                .is_empty()
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    // reason: start-audit failure fixtures must panic loudly on call-log races.
    async fn dr_recovery_start_audit_failure_performs_zero_recovery_mutation() {
        let runtime = FakeRuntime {
            fail_start_audit: true,
            ..FakeRuntime::default()
        };
        let parsed = parse(&argv(&["event-a"])).expect("valid command");
        assert!(
            execute_l2_dr_recovery_with_runtime(parsed, &runtime)
                .await
                .is_err()
        );
        assert_eq!(
            *runtime.calls.lock().expect("calls"),
            [
                "connect",
                "authenticate",
                "authorize",
                "audit_start",
                "shutdown"
            ]
        );
        assert_eq!(
            *runtime.audit_subjects.lock().expect("audit subjects"),
            ["service:l2-dr-runtime"]
        );
        assert!(
            runtime
                .apply_subjects
                .lock()
                .expect("apply subjects")
                .is_empty()
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    // reason: success-path fixtures must panic loudly when FakeRuntime invariants drift.
    async fn dr_recovery_success_is_audited_and_emits_only_safe_plan_fields() {
        let runtime = FakeRuntime::default();
        let parsed = parse(&argv(&["event-b", "event-a"])).expect("valid command");
        let output = execute_l2_dr_recovery_with_runtime(parsed, &runtime)
            .await
            .expect("successful recovery");
        assert_eq!(
            *runtime.calls.lock().expect("calls"),
            [
                "connect",
                "authenticate",
                "authorize",
                "audit_start",
                "apply",
                "audit_finish",
                "shutdown"
            ]
        );
        assert_eq!(
            *runtime.audit_subjects.lock().expect("audit subjects"),
            ["service:l2-dr-runtime", "service:l2-dr-runtime"]
        );
        assert_eq!(
            *runtime.apply_subjects.lock().expect("apply subjects"),
            ["service:l2-dr-runtime"]
        );
        let json = output.to_json();
        assert_eq!(json["epochId"], EPOCH);
        assert_eq!(json["tenant"], TENANT);
        assert_eq!(json["direction"], "database_ahead_broker_earlier");
        assert_eq!(json["pgRestorePointMicros"], 1_700_000_000_000_200_i64);
        assert_eq!(
            json["rabbitmqRestorePointMicros"],
            1_700_000_000_000_100_i64
        );
        assert_eq!(json["eventIds"], serde_json::json!(["event-a", "event-b"]));
        assert_eq!(json["policyRevision"], "same-id-delivery-v1");
        assert_eq!(json["appliedAt"], 1_700_000_000_000_300_i64);
        assert!(uuid::Uuid::parse_str(json["firstStartAuditId"].as_str().unwrap_or("")).is_ok());
        assert_eq!(json["outcome"], "applied");
        assert!(
            json["digest"]
                .as_str()
                .is_some_and(|value| value.starts_with("sha256:"))
        );
        let rendered = serde_json::to_string(&json).expect("JSON");
        assert!(!rendered.contains("opaque-token"));
        assert!(!rendered.contains("payload"));
        assert!(!rendered.contains("service:l2-dr-runtime"));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    // reason: apply-failure fixtures must panic loudly when secondary failures leak.
    async fn dr_recovery_apply_failure_keeps_primary_when_finish_audit_and_shutdown_fail() {
        let runtime = FakeRuntime {
            fail_apply: true,
            fail_finish_audit: true,
            fail_shutdown: true,
            ..FakeRuntime::default()
        };
        let parsed = parse(&argv(&["event-a"])).expect("valid command");
        let error = execute_l2_dr_recovery_with_runtime(parsed, &runtime)
            .await
            .expect_err("apply must fail");
        let rendered = format!("{error:#}");
        assert!(rendered.contains("lost a selected row lock"));
        assert!(rendered.contains("identical plan"));
        assert!(!rendered.contains("sensitive finish audit failure"));
        assert!(!rendered.contains("sensitive shutdown failure"));
        assert_eq!(
            *runtime.calls.lock().expect("calls"),
            [
                "connect",
                "authenticate",
                "authorize",
                "audit_start",
                "apply",
                "audit_finish",
                "shutdown"
            ]
        );
        assert_eq!(
            *runtime.finish_reasons.lock().expect("finish reasons"),
            [Some("execution".to_owned())]
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    // reason: epoch-conflict fixtures must panic loudly when retry wording regresses.
    async fn dr_recovery_epoch_conflict_does_not_suggest_identical_plan_retry() {
        let runtime = FakeRuntime {
            apply_error: Some(eventexec::L2DrRecoveryError::EpochConflict),
            ..FakeRuntime::default()
        };
        let parsed = parse(&argv(&["event-a"])).expect("valid command");
        let error = execute_l2_dr_recovery_with_runtime(parsed, &runtime)
            .await
            .expect_err("epoch conflict must fail");
        let rendered = format!("{error:#}");
        assert!(rendered.contains("epoch conflicts"));
        assert!(rendered.contains(STOP_RECONCILE_CONTEXT));
        assert!(!rendered.contains("identical plan"));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    // reason: committed finish-audit failure fixtures must panic loudly on wording drift.
    async fn dr_recovery_committed_apply_with_finish_audit_failure_has_closed_retry_error() {
        let runtime = FakeRuntime {
            fail_finish_audit: true,
            ..FakeRuntime::default()
        };
        let parsed = parse(&argv(&["event-a"])).expect("valid command");
        let error = execute_l2_dr_recovery_with_runtime(parsed, &runtime)
            .await
            .expect_err("finish audit must fail closed");
        let rendered = format!("{error:#}");
        assert!(rendered.contains("apply committed but finish audit failed"));
        assert!(rendered.contains("identical plan"));
        assert!(!rendered.contains("sensitive finish audit failure"));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    // reason: committed shutdown-failure fixtures must panic loudly when receipt evidence is dropped.
    async fn dr_recovery_committed_apply_with_shutdown_failure_keeps_committed_error() {
        let runtime = FakeRuntime {
            fail_shutdown: true,
            ..FakeRuntime::default()
        };
        let parsed = parse(&argv(&["event-a"])).expect("valid command");
        let error = execute_l2_dr_recovery_with_runtime(parsed, &runtime)
            .await
            .expect_err("shutdown after commit must fail closed");
        let committed = error
            .downcast_ref::<CommittedCleanupFailure>()
            .expect("shutdown failure must retain the safe committed receipt");
        assert_eq!(committed.output.outcome, "applied");
        assert_eq!(committed.output.epoch_id, EPOCH);
        assert_eq!(committed.output.tenant, TENANT);
        let rendered = format!("{error:#}");
        assert!(rendered.contains("apply committed but postgres cleanup failed"));
        assert!(rendered.contains("outcome=applied"));
        assert!(rendered.contains(&format!("epoch_id={EPOCH}")));
        assert!(rendered.contains(&format!("tenant={TENANT}")));
        assert!(!rendered.contains("sensitive shutdown failure"));
        assert_eq!(
            *runtime.calls.lock().expect("calls"),
            [
                "connect",
                "authenticate",
                "authorize",
                "audit_start",
                "apply",
                "audit_finish",
                "shutdown"
            ]
        );
    }
}
