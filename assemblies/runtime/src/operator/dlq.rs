// `forbid(clippy::wildcard_imports)` 与 clap derive 的 `allow(clippy::pedantic)` 冲突（E0453）；
// unused_imports 可保持 forbid；wildcard_imports 用 deny。
#![forbid(unused_imports)]
#![deny(clippy::wildcard_imports)]

use anyhow::Context as _;
use consistency::IdemKey;
use diport::{DlqOperatorAuthorization, DlqOperatorStartAuditId, dlq_operator_action};
use eventexec::{
    DeadLetterId, DlqCursor, DlqEntrySummary, DlqInspectRequest, DlqInspectTarget, DlqListQuery,
    DlqRedriveOutcome, DlqRedriveRequest, DlqReplayRequest, DlqStore, OutboxExpiredResolutionKind,
    OutboxExpiredResolutionOutcome, OutboxExpiredResolutionRequest, OutboxResolutionChangeTicket,
    ProjectionCaptureView,
};
use postgres::{MaintenanceAuditOutcome, PgDlqStore, PgMaintenanceDeps, PgRuntimeDeps};

use super::build_operator_service_token_provider;
use super::parse_positive_usize;
use super::service_token::OperatorServiceToken;
use crate::config::SnapshotConfig;
use crate::event_transport;
use crate::infra::pg::build_pg_migrator_config;
use crate::phase::OperatorRuntimeCapability;
#[cfg(feature = "operator-cli")]
use crate::phase::OperatorRuntimeInputs;

const COMMAND_NAMESPACE: &str = "dlq";

/// `rss` binary 是否请求 DLQ inspection / replay / redrive 控制命令。
///
/// Namespace probe only — not a second argv parser.
#[must_use]
pub fn is_dlq_command(args: &[String]) -> bool {
    matches!(args, [namespace, ..] if namespace == COMMAND_NAMESPACE)
}

pub(super) const DLQ_OPERATOR_GRANTS_ENV: &str = "RSS_DLQ_OPERATOR_GRANTS";
/// Identity-neutral actor used for the durable attempt record created before token verification.
pub(super) const UNAUTHENTICATED_DLQ_ATTEMPT: &str = "unauthenticated-dlq-attempt";

#[derive(Debug)]
pub(super) struct DlqCliArgs {
    pub(super) command: DlqCliCommand,
    pub(super) operator_service_token: OperatorServiceToken,
    pub(super) operator_tenant: rss_request_context::TenantId,
    pub(super) tenant: rss_request_context::TenantId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum DlqCliCommand {
    List {
        source: Option<diport::DeadLetterSource>,
        producer_domain: Option<String>,
        consumer_domain: Option<String>,
        contract_id: Option<String>,
        limit: u32,
        cursor: Option<DlqCursor>,
    },
    Inspect {
        target: DlqInspectTarget,
    },
    ReplayDeadLetter {
        dead_letter_id: DeadLetterId,
        replay_id: IdemKey,
    },
    RedriveOutbox {
        event_id: IdemKey,
    },
    ResolveExpiredOutbox {
        event_id: IdemKey,
        change_ticket: OutboxResolutionChangeTicket,
        resolution_kind: OutboxExpiredResolutionKind,
        evidence_event_id: Option<IdemKey>,
    },
}

/// Opaque command whose argv and stdin token were validated before runtime setup.
#[cfg(feature = "operator-cli")]
pub struct PreparedDlqCommand(DlqCliArgs);

/// Pure CLI preparation result. Help performs no stdin / environment / provider access beyond
/// clap's own help/version render (already printed when this variant is returned).
#[cfg(feature = "operator-cli")]
pub enum DlqCommandPreparation {
    /// Help or version text was already written; caller returns `Ok(())` without runtime.
    Help,
    Execute(PreparedDlqCommand),
}

pub(super) use diport::DlqOperatorActionKind as DlqMaintenanceAction;

impl DlqCliCommand {
    pub(super) fn action(&self) -> DlqMaintenanceAction {
        match self {
            Self::List { .. } => DlqMaintenanceAction::List,
            Self::Inspect { .. } => DlqMaintenanceAction::Inspect,
            Self::ReplayDeadLetter { .. } => DlqMaintenanceAction::ReplayDeadLetter,
            Self::RedriveOutbox { .. } => DlqMaintenanceAction::RedriveOutbox,
            Self::ResolveExpiredOutbox { .. } => DlqMaintenanceAction::ResolveExpiredOutbox,
        }
    }

    pub(super) fn requires_payload_protector(&self) -> bool {
        matches!(self, Self::ReplayDeadLetter { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DlqMaintenanceGrant {
    pub(super) action: DlqMaintenanceAction,
    pub(super) tenant: rss_request_context::TenantId,
}

pub(super) fn parse_dlq_limit(raw: &str) -> anyhow::Result<u32> {
    let value = parse_positive_usize(raw, "--limit")?;
    let value = u32::try_from(value).context("--limit exceeds u32")?;
    anyhow::ensure!(value <= 500, "--limit must be <= 500");
    Ok(value)
}

pub(super) fn parse_dlq_source(raw: &str) -> anyhow::Result<diport::DeadLetterSource> {
    diport::DeadLetterSource::parse(raw)
        .ok_or_else(|| anyhow::anyhow!("--source must be consumer|outbox_relay|saga|projection"))
}

#[cfg(feature = "operator-cli")]
pub(super) fn parse_dlq_kind_target(kind: &str, id: &str) -> anyhow::Result<DlqInspectTarget> {
    // Never embed `{id}` / `{kind}` / `{raw}` — diagnostics must stay argv-free (SECRET_BAIT).
    let invalid = || {
        anyhow::anyhow!(
            "{}",
            crate::operator::cli_clap::operator_cli_invalid_value(COMMAND_NAMESPACE)
        )
    };
    match kind {
        "dead-letter" => Ok(DlqInspectTarget::DeadLetter(
            DeadLetterId::parse(id).map_err(|_| invalid())?,
        )),
        "outbox-dlx" => Ok(DlqInspectTarget::OutboxDlx(
            IdemKey::parse(id).map_err(|_| invalid())?,
        )),
        _ => Err(invalid()),
    }
}

/// RSS business ensure for resolve-expired-outbox evidence coupling (not expressible in clap alone).
pub(super) fn ensure_resolve_expired_outbox_evidence(
    resolution_kind: OutboxExpiredResolutionKind,
    evidence_event_id: Option<&IdemKey>,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        matches!(
            (resolution_kind, evidence_event_id.is_some()),
            (OutboxExpiredResolutionKind::AcceptedGap, false)
                | (OutboxExpiredResolutionKind::Compensated, true)
        ),
        "accepted_gap forbids --evidence-event-id; compensated requires it"
    );
    Ok(())
}

#[cfg(feature = "operator-cli")]
mod clap_cli {
    use super::{
        COMMAND_NAMESPACE, DlqCliArgs, DlqCliCommand, DlqCommandPreparation, PreparedDlqCommand,
        ensure_resolve_expired_outbox_evidence, parse_dlq_kind_target, parse_dlq_limit,
        parse_dlq_source,
    };
    use crate::operator::cli_clap::{
        ClapHelpPrinted, OperatorAuthSharedArgs, map_clap_parse_error,
    };
    use crate::operator::service_token::read_operator_service_token_stdin;
    use clap::{Args, Parser, Subcommand};
    use consistency::IdemKey;
    use eventexec::{
        DeadLetterId, DlqCursor, OutboxExpiredResolutionKind, OutboxResolutionChangeTicket,
    };

    const FAMILY: &str = COMMAND_NAMESPACE;

    // Token material is never accepted on argv: `--operator-service-token-stdin` is presence-only;
    // the opaque token is read from stdin after parse succeeds. Help/version → Help (exit 0);
    // other syntax errors → fixed family-bucketed diagnostic (never echo argv).
    // The `help` subcommand is disabled — use `--help` / `-h`.
    #[derive(Debug, Parser)]
    #[command(
        name = COMMAND_NAMESPACE,
        bin_name = "rss dlq",
        about = "Inspect, replay, or redrive tenant-scoped DLQ / outbox DLX entries",
        long_about = "Operator commands for DLQ list/inspect and closed mutation actions \
(replay-dead-letter, redrive-outbox, resolve-expired-outbox). The operator service token is read \
from stdin after argv validation (--operator-service-token-stdin). \
The help subcommand is disabled; use --help.",
        disable_help_subcommand = true,
        disable_version_flag = true
    )]
    struct DlqCli {
        #[command(subcommand)]
        action: DlqSubcommand,
    }

    #[derive(Debug, Subcommand)]
    enum DlqSubcommand {
        /// List DLQ / outbox DLX summaries for one tenant.
        List(DlqListArgs),
        /// Inspect one dead-letter or outbox-dlx entry.
        Inspect(DlqInspectArgs),
        /// Replay a dead letter with a fresh idempotency key.
        #[command(name = "replay-dead-letter")]
        ReplayDeadLetter(DlqReplayDeadLetterArgs),
        /// Redrive an outbox DLX event back onto the publish path.
        #[command(name = "redrive-outbox")]
        RedriveOutbox(DlqRedriveOutboxArgs),
        /// Resolve an expired outbox DLX head with operator evidence.
        #[command(name = "resolve-expired-outbox")]
        ResolveExpiredOutbox(DlqResolveExpiredOutboxArgs),
    }

    #[derive(Debug, Args)]
    struct DlqListArgs {
        #[command(flatten)]
        auth: OperatorAuthSharedArgs,

        /// Dead-letter source filter.
        #[arg(long, value_parser = parse_dlq_source_cli)]
        source: Option<diport::DeadLetterSource>,

        /// Producer domain filter (non-empty).
        #[arg(long, value_parser = parse_nonempty_domain_cli)]
        producer_domain: Option<String>,

        /// Consumer domain filter (non-empty).
        #[arg(long, value_parser = parse_nonempty_domain_cli)]
        consumer_domain: Option<String>,

        /// Contract id filter (non-empty).
        #[arg(long = "contract-id", value_parser = parse_nonempty_domain_cli)]
        contract_id: Option<String>,

        /// Max rows to return (1..=500; default 100).
        #[arg(long, default_value = "100", value_parser = parse_dlq_limit_cli)]
        limit: u32,

        /// Opaque list cursor from a prior page.
        #[arg(long, value_parser = parse_dlq_cursor_cli)]
        cursor: Option<DlqCursor>,
    }

    #[derive(Debug, Args)]
    struct DlqInspectArgs {
        #[command(flatten)]
        auth: OperatorAuthSharedArgs,

        /// Inspect target kind (`dead-letter` or `outbox-dlx`).
        #[arg(long)]
        kind: String,

        /// Target id (dead_letter UUID or outbox event id).
        #[arg(long, value_parser = parse_nonempty_id_cli)]
        id: String,
    }

    #[derive(Debug, Args)]
    struct DlqReplayDeadLetterArgs {
        #[command(flatten)]
        auth: OperatorAuthSharedArgs,

        /// Dead letter id to replay (UUID).
        #[arg(long, value_parser = parse_dead_letter_id_cli)]
        dead_letter_id: DeadLetterId,

        /// Fresh idempotency key for the replay insert.
        #[arg(long, value_parser = parse_idem_key_cli)]
        replay_id: IdemKey,
    }

    #[derive(Debug, Args)]
    struct DlqRedriveOutboxArgs {
        #[command(flatten)]
        auth: OperatorAuthSharedArgs,

        /// Outbox DLX event id to redrive.
        #[arg(long, value_parser = parse_idem_key_cli)]
        event_id: IdemKey,
    }

    #[derive(Debug, Args)]
    struct DlqResolveExpiredOutboxArgs {
        #[command(flatten)]
        auth: OperatorAuthSharedArgs,

        /// Expired outbox DLX event id.
        #[arg(long, value_parser = parse_idem_key_cli)]
        event_id: IdemKey,

        /// Change-ticket evidence authorizing the resolution.
        #[arg(long, value_parser = parse_change_ticket_cli)]
        change_ticket: OutboxResolutionChangeTicket,

        /// Resolution kind (`accepted_gap` or `compensated`).
        #[arg(long, value_parser = parse_resolution_kind_cli)]
        resolution_kind: OutboxExpiredResolutionKind,

        /// Compensation evidence event id (required for `compensated`; forbidden for `accepted_gap`).
        #[arg(long, value_parser = parse_idem_key_cli)]
        evidence_event_id: Option<IdemKey>,
    }

    fn parse_dlq_limit_cli(raw: &str) -> Result<u32, String> {
        // Static parser text only — never interpolate `{raw}` (SECRET_BAIT).
        parse_dlq_limit(raw).map_err(|_| "--limit must be 1..=500".to_owned())
    }

    fn parse_dlq_source_cli(raw: &str) -> Result<diport::DeadLetterSource, String> {
        parse_dlq_source(raw)
            .map_err(|_| "--source must be consumer|outbox_relay|saga|projection".to_owned())
    }

    fn parse_nonempty_domain_cli(raw: &str) -> Result<String, String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err("value must be non-empty".to_owned());
        }
        Ok(trimmed.to_owned())
    }

    fn parse_nonempty_id_cli(raw: &str) -> Result<String, String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err("--id must be non-empty".to_owned());
        }
        Ok(trimmed.to_owned())
    }

    fn parse_dlq_cursor_cli(raw: &str) -> Result<DlqCursor, String> {
        DlqCursor::parse(raw).map_err(|_| "--cursor is invalid".to_owned())
    }

    fn parse_dead_letter_id_cli(raw: &str) -> Result<DeadLetterId, String> {
        DeadLetterId::parse(raw).map_err(|_| "--dead-letter-id must be a UUID".to_owned())
    }

    fn parse_idem_key_cli(raw: &str) -> Result<IdemKey, String> {
        IdemKey::parse(raw).map_err(|_| "idempotency key is invalid".to_owned())
    }

    fn parse_change_ticket_cli(raw: &str) -> Result<OutboxResolutionChangeTicket, String> {
        OutboxResolutionChangeTicket::parse(raw)
            .map_err(|_| "--change-ticket is invalid".to_owned())
    }

    fn parse_resolution_kind_cli(raw: &str) -> Result<OutboxExpiredResolutionKind, String> {
        OutboxExpiredResolutionKind::parse(raw)
            .map_err(|_| "--resolution-kind must be accepted_gap|compensated".to_owned())
    }

    fn command_from_cli(cli: DlqCli) -> anyhow::Result<(OperatorAuthSharedArgs, DlqCliCommand)> {
        match cli.action {
            DlqSubcommand::List(args) => Ok((
                args.auth,
                DlqCliCommand::List {
                    source: args.source,
                    producer_domain: args.producer_domain,
                    consumer_domain: args.consumer_domain,
                    contract_id: args.contract_id,
                    limit: args.limit,
                    cursor: args.cursor,
                },
            )),
            DlqSubcommand::Inspect(args) => Ok((
                args.auth,
                DlqCliCommand::Inspect {
                    target: parse_dlq_kind_target(&args.kind, &args.id)?,
                },
            )),
            DlqSubcommand::ReplayDeadLetter(args) => Ok((
                args.auth,
                DlqCliCommand::ReplayDeadLetter {
                    dead_letter_id: args.dead_letter_id,
                    replay_id: args.replay_id,
                },
            )),
            DlqSubcommand::RedriveOutbox(args) => Ok((
                args.auth,
                DlqCliCommand::RedriveOutbox {
                    event_id: args.event_id,
                },
            )),
            DlqSubcommand::ResolveExpiredOutbox(args) => {
                ensure_resolve_expired_outbox_evidence(
                    args.resolution_kind,
                    args.evidence_event_id.as_ref(),
                )?;
                Ok((
                    args.auth,
                    DlqCliCommand::ResolveExpiredOutbox {
                        event_id: args.event_id,
                        change_ticket: args.change_ticket,
                        resolution_kind: args.resolution_kind,
                        evidence_event_id: args.evidence_event_id,
                    },
                ))
            }
        }
    }

    #[cfg(test)]
    pub(in crate::operator) fn parse_dlq_args(
        args: &[String],
        stdin: &mut impl std::io::BufRead,
    ) -> anyhow::Result<DlqCliArgs> {
        match prepare_dlq_command_with_stdin(args, stdin)? {
            DlqCommandPreparation::Execute(PreparedDlqCommand(parsed)) => Ok(parsed),
            DlqCommandPreparation::Help => {
                anyhow::bail!("test expected executable dlq command, got help")
            }
        }
    }

    pub(in crate::operator) fn prepare_dlq_command_with_stdin(
        args: &[String],
        stdin: &mut impl std::io::BufRead,
    ) -> anyhow::Result<DlqCommandPreparation> {
        let cli = match DlqCli::try_parse_from(args) {
            Ok(cli) => cli,
            Err(err) => {
                let ClapHelpPrinted = map_clap_parse_error(err, FAMILY)?;
                return Ok(DlqCommandPreparation::Help);
            }
        };
        let (auth, command) = command_from_cli(cli)?;
        // Presence is enforced by clap (`required = true`); token never enters argv.
        debug_assert!(auth.token_stdin.operator_service_token_stdin);
        let operator_service_token = read_operator_service_token_stdin(stdin)?;
        Ok(DlqCommandPreparation::Execute(PreparedDlqCommand(
            DlqCliArgs {
                command,
                operator_service_token,
                operator_tenant: auth.operator_tenant,
                tenant: auth.tenant,
            },
        )))
    }
}

#[cfg(all(test, feature = "operator-cli"))]
pub(super) use clap_cli::parse_dlq_args;

/// Validate DLQ argv and consume stdin before any runtime / environment / provider prep.
#[cfg(feature = "operator-cli")]
pub fn prepare_dlq_command(args: &[String]) -> anyhow::Result<DlqCommandPreparation> {
    let stdin = std::io::stdin();
    clap_cli::prepare_dlq_command_with_stdin(args, &mut stdin.lock())
}

pub(super) fn parse_dlq_operator_grants(raw: &str) -> anyhow::Result<Vec<DlqMaintenanceGrant>> {
    let raw = raw.trim();
    anyhow::ensure!(
        !raw.is_empty(),
        "{DLQ_OPERATOR_GRANTS_ENV} must not be empty"
    );
    let mut grants = Vec::new();
    for entry in raw.split(',') {
        let entry = entry.trim();
        anyhow::ensure!(
            !entry.is_empty(),
            "{DLQ_OPERATOR_GRANTS_ENV} must not contain empty entries"
        );
        let parts: Vec<_> = entry.split('|').map(str::trim).collect();
        anyhow::ensure!(
            parts.len() == 2,
            "{DLQ_OPERATOR_GRANTS_ENV} entries must be action|tenant"
        );
        let [action, tenant] = parts.as_slice() else {
            unreachable!("len checked");
        };
        grants.push(DlqMaintenanceGrant {
            action: DlqMaintenanceAction::parse(action).ok_or_else(|| {
                anyhow::anyhow!(
                    "unknown DLQ maintenance action in {DLQ_OPERATOR_GRANTS_ENV}: {action}"
                )
            })?,
            tenant: rss_request_context::TenantId::parse(tenant).with_context(|| {
                format!("{DLQ_OPERATOR_GRANTS_ENV} tenant must be a UUID: {tenant}")
            })?,
        });
    }
    anyhow::ensure!(
        !grants.is_empty(),
        "{DLQ_OPERATOR_GRANTS_ENV} must contain at least one grant"
    );
    Ok(grants)
}

pub(super) fn load_dlq_operator_grants_from_command_env(
    _operator: OperatorRuntimeCapability<'_>,
) -> anyhow::Result<Vec<DlqMaintenanceGrant>> {
    let raw = std::env::var(DLQ_OPERATOR_GRANTS_ENV)
        .with_context(|| format!("{DLQ_OPERATOR_GRANTS_ENV} is required"))?;
    parse_dlq_operator_grants(&raw)
}

pub(super) fn authorize_dlq_operator(
    parsed: &DlqCliArgs,
    grants: &[DlqMaintenanceGrant],
) -> anyhow::Result<()> {
    let action = parsed.command.action();
    let allowed = grants
        .iter()
        .any(|grant| grant.action == action && grant.tenant == parsed.tenant);
    anyhow::ensure!(
        allowed,
        "DLQ operator is not authorized for action={} tenant={}",
        action.as_str(),
        parsed.tenant
    );
    Ok(())
}

pub(super) fn dlq_command_resource_id(parsed: &DlqCliArgs) -> String {
    let target = match &parsed.command {
        DlqCliCommand::List {
            source,
            producer_domain,
            consumer_domain,
            contract_id,
            ..
        } => format!(
            "source={} producer_domain={} consumer_domain={} contract_id={}",
            source.map(|source| source.as_str()).unwrap_or("all"),
            producer_domain.as_deref().unwrap_or("all"),
            consumer_domain.as_deref().unwrap_or("all"),
            contract_id.as_deref().unwrap_or("all")
        ),
        DlqCliCommand::Inspect { target } => match target {
            DlqInspectTarget::DeadLetter(dead_letter_id) => {
                format!("kind=dead_letter dead_letter_id={dead_letter_id}")
            }
            DlqInspectTarget::OutboxDlx(event_id) => {
                format!("kind=outbox_dlx event_id={}", event_id.as_str())
            }
        },
        DlqCliCommand::ReplayDeadLetter {
            dead_letter_id,
            replay_id,
        } => {
            format!(
                "dead_letter_id={dead_letter_id} replay_id={}",
                replay_id.as_str()
            )
        }
        DlqCliCommand::RedriveOutbox { event_id } => format!("event_id={}", event_id.as_str()),
        DlqCliCommand::ResolveExpiredOutbox {
            event_id,
            resolution_kind,
            ..
        } => format!(
            "event_id={} resolution_kind={}",
            event_id.as_str(),
            resolution_kind.as_label()
        ),
    };
    format!(
        "operation={} tenant={} {}",
        parsed.command.action().as_str(),
        parsed.tenant,
        target
    )
}

pub(super) async fn authenticate_dlq_operator_principal(
    service_token: &str,
    operator_tenant: rss_request_context::TenantId,
    pdp: &diport::DynPdp<'_>,
) -> anyhow::Result<authn::Principal> {
    let (_token, principal) = authn::verify_service_token(
        service_token,
        diport::ServiceTokenTenantBinding::new(operator_tenant),
        pdp,
    )
    .await
    .context("verify DLQ maintenance operator service token")?;
    anyhow::ensure!(
        principal.service_caller_domain() == Some(vocab::ServiceCallerDomain::MaintenanceOperator),
        "DLQ maintenance operator must be the maintenance operator"
    );
    Ok(principal)
}

pub(super) async fn record_dlq_maintenance_finish_audit(
    pg: &PgMaintenanceDeps,
    operator_subject: &str,
    tenant: rss_request_context::TenantId,
    start_audit_id: &DlqOperatorStartAuditId,
    action: &str,
    resource_id: &str,
    outcome: MaintenanceAuditOutcome<'_>,
) -> anyhow::Result<()> {
    pg.record_dlq_maintenance_audit(
        operator_subject,
        tenant,
        start_audit_id,
        action,
        outcome,
        resource_id,
    )
    .await
    .context("record DLQ maintenance finish audit")
}

pub(super) async fn authenticate_dlq_operator(
    pg: &PgMaintenanceDeps,
    operator_pdp: &diport::DynPdp<'_>,
    parsed: &DlqCliArgs,
    resource_id: &str,
    start_audit_id: &DlqOperatorStartAuditId,
) -> anyhow::Result<authn::Principal> {
    let principal = match authenticate_dlq_operator_principal(
        parsed.operator_service_token.as_str(),
        parsed.operator_tenant,
        operator_pdp,
    )
    .await
    {
        Ok(principal) => principal,
        Err(err) => {
            record_dlq_maintenance_finish_audit(
                pg,
                UNAUTHENTICATED_DLQ_ATTEMPT,
                parsed.tenant,
                start_audit_id,
                &format!("dlq.{}.finish", parsed.command.action().as_str()),
                resource_id,
                MaintenanceAuditOutcome::Failure {
                    reason: "operator_auth",
                },
            )
            .await?;
            return Err(err);
        }
    };
    Ok(principal)
}

pub(super) async fn authorize_dlq_operator_principal(
    pg: &PgMaintenanceDeps,
    parsed: &DlqCliArgs,
    resource_id: &str,
    principal: authn::Principal,
    operator: OperatorRuntimeCapability<'_>,
    start_audit_id: &DlqOperatorStartAuditId,
) -> anyhow::Result<AuthorizedDlqOperator> {
    let subject = principal.audit_subject().to_owned();
    let grants = match load_dlq_operator_grants_from_command_env(operator) {
        Ok(grants) => grants,
        Err(err) => {
            record_dlq_maintenance_finish_audit(
                pg,
                &subject,
                parsed.tenant,
                start_audit_id,
                &format!("dlq.{}.finish", parsed.command.action().as_str()),
                resource_id,
                MaintenanceAuditOutcome::Failure {
                    reason: "operator_grants",
                },
            )
            .await?;
            return Err(err);
        }
    };
    if let Err(err) = authorize_dlq_operator(parsed, &grants) {
        record_dlq_maintenance_finish_audit(
            pg,
            &subject,
            parsed.tenant,
            start_audit_id,
            &format!("dlq.{}.finish", parsed.command.action().as_str()),
            resource_id,
            MaintenanceAuditOutcome::Failure {
                reason: "operator_authorization",
            },
        )
        .await?;
        return Err(err);
    }
    let caller = principal
        .service_caller_domain()
        .filter(|caller| *caller == vocab::ServiceCallerDomain::MaintenanceOperator)
        .ok_or_else(|| anyhow::anyhow!("DLQ operator caller binding lost"))?;
    Ok(AuthorizedDlqOperator { caller, subject })
}

pub(super) fn dlq_summary_json_line(summary: &DlqEntrySummary) -> anyhow::Result<String> {
    let value = serde_json::json!({
        "kind": summary.kind().as_label(),
        "id": summary.id(),
        "source": summary.source().as_str(),
        "tenant": summary.tenant().to_string(),
        "messageId": summary.message_id(),
        "producerDomain": summary.producer_domain(),
        "consumerDomain": summary.consumer_domain(),
        "contractId": summary.contract_id(),
        "topic": summary.topic(),
        "consumerGroup": summary.consumer_group(),
        "payloadLen": summary.payload_len(),
        "errorSummary": summary.error_summary(),
        "numAttempts": summary.num_attempts(),
        "lastAttemptEpochSecs": summary.last_attempt_epoch_secs(),
    });
    serde_json::to_string(&value).context("render DLQ summary json")
}

pub(super) fn print_dlq_summary(summary: &DlqEntrySummary) -> anyhow::Result<()> {
    println!("{}", dlq_summary_json_line(summary)?);
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DlqCommandOutcome {
    Completed,
    Expired,
    Rejected(&'static str),
}

struct DlqCommandExecution {
    outcome: DlqCommandOutcome,
    finish_audit_durable: bool,
}

impl DlqCommandExecution {
    const fn runtime_audited(outcome: DlqCommandOutcome) -> Self {
        Self {
            outcome,
            finish_audit_durable: false,
        }
    }

    const fn mutation_audited(outcome: DlqCommandOutcome) -> Self {
        Self {
            outcome,
            finish_audit_durable: true,
        }
    }
}

pub(super) fn dlq_redrive_result_line(
    tenant: rss_request_context::TenantId,
    event_id: &IdemKey,
    outcome: DlqRedriveOutcome,
) -> String {
    format!(
        "operation=redrive-outbox tenant={tenant} event_id={} outcome={}",
        event_id.as_str(),
        outcome.as_label()
    )
}

pub(super) fn dlq_audit_correlation_line(start_audit_id: &DlqOperatorStartAuditId) -> String {
    format!("audit_id={}", start_audit_id.as_str())
}

pub(super) async fn run_expired_outbox_resolution<S: DlqStore>(
    store: &S,
    request: OutboxExpiredResolutionRequest,
) -> anyhow::Result<DlqCommandOutcome> {
    let tenant = request.tenant();
    let event_id = request.event_id().clone();
    let resolution_kind = request.kind();
    let outcome = store.resolve_expired_outbox(request).await?.into_outcome();
    println!(
        "operation=resolve-expired-outbox tenant={} event_id={} resolution_kind={} outcome={}",
        tenant,
        event_id.as_str(),
        resolution_kind.as_label(),
        outcome.as_label()
    );
    match outcome {
        OutboxExpiredResolutionOutcome::Resolved => Ok(DlqCommandOutcome::Completed),
        OutboxExpiredResolutionOutcome::NotFound => Ok(DlqCommandOutcome::Rejected("not_found")),
        OutboxExpiredResolutionOutcome::NotExpired => {
            Ok(DlqCommandOutcome::Rejected("not_expired"))
        }
        OutboxExpiredResolutionOutcome::EvidenceRejected => {
            Ok(DlqCommandOutcome::Rejected("evidence_rejected"))
        }
    }
}

enum AuthorizedDlqRequest {
    List(DlqListQuery),
    Inspect(DlqInspectRequest),
    Replay(DlqReplayRequest),
    Redrive(DlqRedriveRequest),
    Resolve(OutboxExpiredResolutionRequest),
}

pub(super) struct DlqMaintenanceAuditContext {
    operator_subject: String,
    tenant: rss_request_context::TenantId,
    start_audit_id: DlqOperatorStartAuditId,
    action: String,
    resource_id: String,
}

impl DlqMaintenanceAuditContext {
    #[cfg(test)]
    pub(super) fn for_test(
        operator_subject: impl Into<String>,
        tenant: rss_request_context::TenantId,
        start_audit_id: DlqOperatorStartAuditId,
        action: impl Into<String>,
        resource_id: impl Into<String>,
    ) -> Self {
        Self {
            operator_subject: operator_subject.into(),
            tenant,
            start_audit_id,
            action: action.into(),
            resource_id: resource_id.into(),
        }
    }

    #[cfg(test)]
    pub(super) fn test_parts(
        &self,
    ) -> (
        &str,
        rss_request_context::TenantId,
        &DlqOperatorStartAuditId,
        &str,
        &str,
    ) {
        (
            &self.operator_subject,
            self.tenant,
            &self.start_audit_id,
            &self.action,
            &self.resource_id,
        )
    }
}

pub(super) struct AuthorizedDlqCommand {
    request: AuthorizedDlqRequest,
    finish_audit: DlqMaintenanceAuditContext,
}

pub(super) struct AuthorizedDlqOperator {
    caller: vocab::ServiceCallerDomain,
    subject: String,
}

#[cfg(test)]
pub(super) fn authorized_dlq_operator_for_test(
    subject: impl Into<String>,
) -> AuthorizedDlqOperator {
    AuthorizedDlqOperator {
        caller: vocab::ServiceCallerDomain::MaintenanceOperator,
        subject: subject.into(),
    }
}

fn issue_dlq_authorization<A: diport::DlqOperatorAction>(
    operator: &AuthorizedDlqOperator,
    tenant: rss_request_context::TenantId,
    start_audit_id: DlqOperatorStartAuditId,
) -> DlqOperatorAuthorization<A> {
    DlqOperatorAuthorization::issue(
        dlqauthmint::DlqOperatorMint::capability(),
        operator.caller,
        operator.subject.clone(),
        tenant,
        start_audit_id,
    )
}

fn authorize_dlq_command(
    parsed: DlqCliArgs,
    operator: &AuthorizedDlqOperator,
    start_audit_id: DlqOperatorStartAuditId,
    resource_id: String,
) -> AuthorizedDlqCommand {
    let tenant = parsed.tenant;
    let (request, finish_audit) = match parsed.command {
        DlqCliCommand::List {
            source,
            producer_domain,
            consumer_domain,
            contract_id,
            limit,
            cursor,
        } => {
            let authorization = issue_dlq_authorization::<dlq_operator_action::List>(
                operator,
                tenant,
                start_audit_id.clone(),
            );
            let finish_audit =
                finish_audit_context::<dlq_operator_action::List>(&authorization, resource_id);
            let mut query = DlqListQuery::new(authorization).with_limit(limit);
            if let Some(source) = source {
                query = query.with_source(source);
            }
            if let Some(domain) = producer_domain {
                query = query.with_producer_domain(domain);
            }
            if let Some(domain) = consumer_domain {
                query = query.with_consumer_domain(domain);
            }
            if let Some(contract_id) = contract_id {
                query = query.with_contract_id(contract_id);
            }
            if let Some(cursor) = cursor {
                query = query.with_cursor(cursor);
            }
            (AuthorizedDlqRequest::List(query), finish_audit)
        }
        DlqCliCommand::Inspect { target } => {
            let authorization = issue_dlq_authorization::<dlq_operator_action::Inspect>(
                operator,
                tenant,
                start_audit_id,
            );
            let finish_audit =
                finish_audit_context::<dlq_operator_action::Inspect>(&authorization, resource_id);
            (
                AuthorizedDlqRequest::Inspect(DlqInspectRequest::new(authorization, target)),
                finish_audit,
            )
        }
        DlqCliCommand::ReplayDeadLetter {
            dead_letter_id,
            replay_id,
        } => {
            let authorization = issue_dlq_authorization::<dlq_operator_action::ReplayDeadLetter>(
                operator,
                tenant,
                start_audit_id,
            );
            let finish_audit = finish_audit_context::<dlq_operator_action::ReplayDeadLetter>(
                &authorization,
                resource_id,
            );
            (
                AuthorizedDlqRequest::Replay(DlqReplayRequest::new(
                    authorization,
                    dead_letter_id,
                    replay_id,
                )),
                finish_audit,
            )
        }
        DlqCliCommand::RedriveOutbox { event_id } => {
            let authorization = issue_dlq_authorization::<dlq_operator_action::RedriveOutbox>(
                operator,
                tenant,
                start_audit_id,
            );
            let finish_audit = finish_audit_context::<dlq_operator_action::RedriveOutbox>(
                &authorization,
                resource_id,
            );
            (
                AuthorizedDlqRequest::Redrive(DlqRedriveRequest::new(authorization, event_id)),
                finish_audit,
            )
        }
        DlqCliCommand::ResolveExpiredOutbox {
            event_id,
            change_ticket,
            resolution_kind,
            evidence_event_id,
        } => {
            let authorization = issue_dlq_authorization::<dlq_operator_action::ResolveExpiredOutbox>(
                operator,
                tenant,
                start_audit_id,
            );
            let finish_audit = finish_audit_context::<dlq_operator_action::ResolveExpiredOutbox>(
                &authorization,
                resource_id,
            );
            let request = match resolution_kind {
                OutboxExpiredResolutionKind::AcceptedGap => {
                    OutboxExpiredResolutionRequest::accepted_gap(
                        authorization,
                        event_id,
                        change_ticket,
                    )
                }
                OutboxExpiredResolutionKind::Compensated => {
                    let Some(evidence_event_id) = evidence_event_id else {
                        unreachable!("DLQ parser requires compensated evidence")
                    };
                    OutboxExpiredResolutionRequest::compensated(
                        authorization,
                        event_id,
                        evidence_event_id,
                        change_ticket,
                    )
                }
            };
            (AuthorizedDlqRequest::Resolve(request), finish_audit)
        }
    };
    AuthorizedDlqCommand {
        request,
        finish_audit,
    }
}

fn finish_audit_context<A: diport::DlqOperatorAction>(
    authorization: &DlqOperatorAuthorization<A>,
    resource_id: String,
) -> DlqMaintenanceAuditContext {
    DlqMaintenanceAuditContext {
        operator_subject: authorization.operator_subject().to_owned(),
        tenant: authorization.tenant(),
        start_audit_id: authorization.start_audit_id().clone(),
        action: format!("dlq.{}.finish", A::LABEL),
        resource_id,
    }
}

async fn run_dlq_command_inner<S: DlqStore>(
    store: &S,
    command: AuthorizedDlqRequest,
) -> anyhow::Result<DlqCommandExecution> {
    match command {
        AuthorizedDlqRequest::List(query) => {
            let tenant = query.tenant();
            let result = store.list_dlq(query).await?;
            for summary in result.data() {
                print_dlq_summary(summary)?;
            }
            println!(
                "operation=list tenant={} count={} has_more={} next_cursor={}",
                tenant,
                result.data().len(),
                result.has_more(),
                result.next_cursor().unwrap_or("none")
            );
            Ok(DlqCommandExecution::runtime_audited(
                DlqCommandOutcome::Completed,
            ))
        }
        AuthorizedDlqRequest::Inspect(request) => {
            let tenant = request.tenant();
            let target = request.target().clone();
            let summary = store.inspect_dlq(request).await?;
            print_dlq_summary(&summary)?;
            match target {
                DlqInspectTarget::DeadLetter(dead_letter_id) => println!(
                    "operation=inspect tenant={} kind=dead_letter dead_letter_id={}",
                    tenant, dead_letter_id
                ),
                DlqInspectTarget::OutboxDlx(event_id) => println!(
                    "operation=inspect tenant={} kind=outbox_dlx event_id={}",
                    tenant,
                    event_id.as_str()
                ),
            }
            Ok(DlqCommandExecution::runtime_audited(
                DlqCommandOutcome::Completed,
            ))
        }
        AuthorizedDlqRequest::Replay(request) => {
            let tenant = request.tenant();
            let dead_letter_id = request.dead_letter_id().clone();
            let replay_id = request.replay_id().clone();
            let outcome = store.replay_dead_letter(request).await?.into_outcome();
            println!(
                "operation=replay-dead-letter tenant={} dead_letter_id={} replay_id={} outcome={}",
                tenant,
                dead_letter_id,
                replay_id.as_str(),
                outcome.as_label()
            );
            Ok(DlqCommandExecution::mutation_audited(
                DlqCommandOutcome::Completed,
            ))
        }
        AuthorizedDlqRequest::Redrive(request) => {
            let tenant = request.tenant();
            let event_id = request.event_id().clone();
            let outcome = store.redrive_outbox(request).await?.into_outcome();
            println!("{}", dlq_redrive_result_line(tenant, &event_id, outcome));
            let command_outcome = match outcome {
                DlqRedriveOutcome::Expired => DlqCommandOutcome::Expired,
                DlqRedriveOutcome::Redriven => DlqCommandOutcome::Completed,
                DlqRedriveOutcome::NotFound => DlqCommandOutcome::Rejected("not_found"),
            };
            Ok(DlqCommandExecution::mutation_audited(command_outcome))
        }
        AuthorizedDlqRequest::Resolve(request) => run_expired_outbox_resolution(store, request)
            .await
            .map(DlqCommandExecution::mutation_audited),
    }
}

#[allow(async_fn_in_trait)]
pub(super) trait DlqControlRuntime {
    type Session;
    type Store: DlqStore;

    async fn connect_maintenance(&self) -> anyhow::Result<Self::Session>;

    async fn record_dlq_maintenance_audit(
        &self,
        session: &Self::Session,
        context: &DlqMaintenanceAuditContext,
        outcome: MaintenanceAuditOutcome<'_>,
    ) -> anyhow::Result<()>;

    async fn record_dlq_finish_audit(
        &self,
        session: &Self::Session,
        context: &DlqMaintenanceAuditContext,
        outcome: MaintenanceAuditOutcome<'_>,
    ) -> anyhow::Result<()> {
        self.record_dlq_maintenance_audit(session, context, outcome)
            .await
    }

    async fn authorized_operator(
        &self,
        session: &Self::Session,
        parsed: &DlqCliArgs,
        resource_id: &str,
        start_audit_id: &DlqOperatorStartAuditId,
    ) -> anyhow::Result<AuthorizedDlqOperator>;

    fn dlq_store(
        &self,
        session: &Self::Session,
        command: &DlqCliCommand,
    ) -> anyhow::Result<Self::Store>;

    async fn shutdown(&self, session: Self::Session);
}

pub(super) struct ProductionDlqControlRuntime<'a> {
    config: SnapshotConfig<'a>,
    operator: OperatorRuntimeCapability<'a>,
    projection_capture: ProjectionCaptureView<'a>,
}

impl DlqControlRuntime for ProductionDlqControlRuntime<'_> {
    type Session = PgMaintenanceDeps;
    type Store = PgDlqStore;

    async fn connect_maintenance(&self) -> anyhow::Result<Self::Session> {
        PgRuntimeDeps::connect_maintenance(&build_pg_migrator_config(self.config)?)
            .await
            .context("setup postgres maintenance deps")
    }

    async fn record_dlq_maintenance_audit(
        &self,
        session: &Self::Session,
        context: &DlqMaintenanceAuditContext,
        outcome: MaintenanceAuditOutcome<'_>,
    ) -> anyhow::Result<()> {
        session
            .record_dlq_maintenance_audit(
                &context.operator_subject,
                context.tenant,
                &context.start_audit_id,
                &context.action,
                outcome,
                &context.resource_id,
            )
            .await
            .context("record DLQ maintenance audit")
    }

    async fn authorized_operator(
        &self,
        session: &Self::Session,
        parsed: &DlqCliArgs,
        resource_id: &str,
        start_audit_id: &DlqOperatorStartAuditId,
    ) -> anyhow::Result<AuthorizedDlqOperator> {
        let provider =
            match build_operator_service_token_provider(self.config, self.operator, session) {
                Ok(provider) => provider,
                Err(err) => {
                    record_dlq_maintenance_finish_audit(
                        session,
                        UNAUTHENTICATED_DLQ_ATTEMPT,
                        parsed.tenant,
                        start_audit_id,
                        &format!("dlq.{}.finish", parsed.command.action().as_str()),
                        resource_id,
                        MaintenanceAuditOutcome::Failure {
                            reason: "operator_provider_config",
                        },
                    )
                    .await?;
                    return Err(err).context("DLQ maintenance operator verifier");
                }
            };
        let principal = authenticate_dlq_operator(
            session,
            diport::DynPdp::from_ref(provider.as_ref()),
            parsed,
            resource_id,
            start_audit_id,
        )
        .await?;
        authorize_dlq_operator_principal(
            session,
            parsed,
            resource_id,
            principal,
            self.operator,
            start_audit_id,
        )
        .await
    }

    fn dlq_store(
        &self,
        session: &Self::Session,
        command: &DlqCliCommand,
    ) -> anyhow::Result<Self::Store> {
        if command.requires_payload_protector() {
            let dlx_payload_protector = event_transport::build_dlx_payload_protector(self.config)
                .context("build DLQ payload protector")?;
            Ok(session.dlq_store(dlx_payload_protector, self.projection_capture))
        } else {
            Ok(session.dlq_store_without_payload_replay())
        }
    }

    async fn shutdown(&self, session: Self::Session) {
        session.shutdown().await.ok();
    }
}

pub(super) async fn run_dlq_control_command_with_runtime<R>(
    parsed: DlqCliArgs,
    runtime: &R,
) -> anyhow::Result<()>
where
    R: DlqControlRuntime,
{
    let resource_id = dlq_command_resource_id(&parsed);
    let tenant = parsed.tenant;
    let start_audit_id =
        DlqOperatorStartAuditId::parse(format!("dlq-operator-{}", uuid::Uuid::new_v4()))
            .context("build DLQ operator start audit id")?;
    let session = runtime.connect_maintenance().await?;
    let start_action = format!("dlq.{}.start", parsed.command.action().as_str());
    let start_audit = DlqMaintenanceAuditContext {
        operator_subject: UNAUTHENTICATED_DLQ_ATTEMPT.to_owned(),
        tenant,
        start_audit_id: start_audit_id.clone(),
        action: start_action,
        resource_id: resource_id.clone(),
    };
    if let Err(err) = runtime
        .record_dlq_maintenance_audit(&session, &start_audit, MaintenanceAuditOutcome::Success)
        .await
        .context("record DLQ maintenance start audit")
    {
        runtime.shutdown(session).await;
        return Err(err);
    }
    eprintln!("{}", dlq_audit_correlation_line(&start_audit_id));

    let operator = match runtime
        .authorized_operator(&session, &parsed, &resource_id, &start_audit_id)
        .await
    {
        Ok(subject) => subject,
        Err(err) => {
            runtime.shutdown(session).await;
            return Err(err);
        }
    };
    let command_kind = parsed.command.clone();
    let authorized = authorize_dlq_command(
        parsed,
        &operator,
        start_audit_id.clone(),
        resource_id.clone(),
    );
    let AuthorizedDlqCommand {
        request,
        finish_audit,
    } = authorized;
    let command_result = match runtime.dlq_store(&session, &command_kind) {
        Ok(store) => run_dlq_command_inner(&store, request).await,
        Err(err) => Err(err),
    };
    let finish_outcome = match &command_result {
        Ok(DlqCommandExecution {
            outcome: DlqCommandOutcome::Completed,
            ..
        }) => MaintenanceAuditOutcome::Success,
        Ok(DlqCommandExecution {
            outcome: DlqCommandOutcome::Expired,
            ..
        }) => MaintenanceAuditOutcome::Failure { reason: "expired" },
        Ok(DlqCommandExecution {
            outcome: DlqCommandOutcome::Rejected(reason),
            ..
        }) => MaintenanceAuditOutcome::Failure { reason },
        Err(_) => MaintenanceAuditOutcome::Failure {
            reason: "run_error",
        },
    };
    let audit_result = if command_result
        .as_ref()
        .is_ok_and(|execution| execution.finish_audit_durable)
    {
        Ok(())
    } else {
        runtime
            .record_dlq_finish_audit(&session, &finish_audit, finish_outcome)
            .await
            .context("record DLQ maintenance finish audit")
    };
    runtime.shutdown(session).await;
    audit_result?;
    match command_result
        .with_context(|| format!("DLQ command failed: {resource_id}"))?
        .outcome
    {
        DlqCommandOutcome::Completed => Ok(()),
        DlqCommandOutcome::Expired => {
            anyhow::bail!("DLQ command failed: {resource_id}: redrive horizon expired")
        }
        DlqCommandOutcome::Rejected(reason) => {
            anyhow::bail!("DLQ command failed: {resource_id}: {reason}")
        }
    }
}

/// Execute an authenticated, audited DLQ operator command.
///
/// Callers must finish [`prepare_dlq_command`] before opening runtime inputs.
#[cfg(feature = "operator-cli")]
pub async fn run_dlq_control_command(
    prepared: PreparedDlqCommand,
    runtime_inputs: &OperatorRuntimeInputs,
) -> anyhow::Result<()> {
    let plan = crate::plan::RuntimePlan::bundled(runtime_inputs.config())
        .context("compile bundled runtime plan for DLQ operator")?;
    let runtime = ProductionDlqControlRuntime {
        config: runtime_inputs.config(),
        operator: runtime_inputs.operator_capability(),
        projection_capture: plan.projection_capture(),
    };
    run_dlq_control_command_with_runtime(prepared.0, &runtime).await
}
