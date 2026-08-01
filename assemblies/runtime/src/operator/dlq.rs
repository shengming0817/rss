#![forbid(unused_imports)]
#![forbid(clippy::wildcard_imports)]

use anyhow::Context as _;
use consistency::IdemKey;
use eventexec::{
    AuthorizedDlqOperatorReceipt, DeadLetterId, DlqCursor, DlqEntrySummary, DlqInspectRequest,
    DlqInspectTarget, DlqListQuery, DlqRedriveOutcome, DlqRedriveRequest, DlqReplayRequest,
    DlqStore, OperatorDlqCapability, OutboxExpiredResolutionKind, OutboxExpiredResolutionOutcome,
    OutboxExpiredResolutionRequest, OutboxResolutionChangeTicket, ProjectionCaptureView,
    VerifiedOperatorSubject,
};
use postgres::{MaintenanceAuditOutcome, PgDlqStore, PgMaintenanceDeps, PgRuntimeDeps};

use super::projection::{next_cli_value, set_cli_arg_once};
use super::service_token::{
    OperatorServiceToken, parse_operator_service_token_stdin_args,
    read_operator_service_token_stdin,
};
use super::{build_operator_service_token_provider, parse_positive_usize};
use crate::config::SnapshotConfig;
use crate::event_transport;
use crate::infra::pg::build_pg_migrator_config;
use crate::phase::{OperatorRuntimeCapability, OperatorRuntimeInputs};

/// `rss` binary 是否请求 DLQ inspection / replay / redrive 控制命令。
#[must_use]
pub fn is_dlq_command(args: &[String]) -> bool {
    matches!(args, [cmd, ..] if cmd == "dlq")
}

pub(super) const DLQ_OPERATOR_GRANTS_ENV: &str = "RSS_DLQ_OPERATOR_GRANTS";
pub(super) const UNVERIFIED_DLQ_OPERATOR: &str = "unverified-service-token";

#[derive(Debug)]
pub(super) struct DlqCliArgs {
    pub(super) command: DlqCliCommand,
    pub(super) operator_service_token: OperatorServiceToken,
    pub(super) operator_tenant: vocab::TenantId,
    pub(super) tenant: vocab::TenantId,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DlqMaintenanceAction {
    List,
    Inspect,
    ReplayDeadLetter,
    RedriveOutbox,
    ResolveExpiredOutbox,
}

impl DlqMaintenanceAction {
    pub(super) fn parse(raw: &str) -> anyhow::Result<Self> {
        match raw {
            "list" => Ok(Self::List),
            "inspect" => Ok(Self::Inspect),
            "replay-dead-letter" => Ok(Self::ReplayDeadLetter),
            "redrive-outbox" => Ok(Self::RedriveOutbox),
            "resolve-expired-outbox" => Ok(Self::ResolveExpiredOutbox),
            other => anyhow::bail!(
                "unknown DLQ maintenance action in {DLQ_OPERATOR_GRANTS_ENV}: {other}"
            ),
        }
    }

    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::List => "list",
            Self::Inspect => "inspect",
            Self::ReplayDeadLetter => "replay-dead-letter",
            Self::RedriveOutbox => "redrive-outbox",
            Self::ResolveExpiredOutbox => "resolve-expired-outbox",
        }
    }
}

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
    pub(super) tenant: vocab::TenantId,
}

pub(super) fn dlq_cli_usage() -> &'static str {
    "usage: rss dlq list|inspect|replay-dead-letter|redrive-outbox|resolve-expired-outbox --operator-service-token-stdin --operator-tenant <uuid> --tenant <uuid> [--producer-domain <domain>] [--consumer-domain <domain>] ..."
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

pub(super) fn parse_dlq_kind_target(kind: &str, id: &str) -> anyhow::Result<DlqInspectTarget> {
    match kind {
        "dead-letter" => Ok(DlqInspectTarget::DeadLetter(
            DeadLetterId::parse(id)
                .with_context(|| format!("--id must be a dead_letter UUID: {id}"))?,
        )),
        "outbox-dlx" => Ok(DlqInspectTarget::OutboxDlx(
            IdemKey::parse(id).with_context(|| format!("--id must be an outbox event id: {id}"))?,
        )),
        other => anyhow::bail!("--kind must be dead-letter|outbox-dlx, got {other}"),
    }
}

#[derive(Debug)]
pub(super) struct DlqRawArgs {
    operator_tenant: Option<vocab::TenantId>,
    tenant: Option<vocab::TenantId>,
    source: Option<diport::DeadLetterSource>,
    producer_domain: Option<String>,
    consumer_domain: Option<String>,
    contract_id: Option<String>,
    limit: u32,
    limit_seen: bool,
    cursor: Option<DlqCursor>,
    kind: Option<String>,
    id: Option<String>,
    dead_letter_id: Option<DeadLetterId>,
    replay_id: Option<IdemKey>,
    event_id: Option<IdemKey>,
    change_ticket: Option<OutboxResolutionChangeTicket>,
    resolution_kind: Option<OutboxExpiredResolutionKind>,
    evidence_event_id: Option<IdemKey>,
}

impl Default for DlqRawArgs {
    fn default() -> Self {
        Self {
            operator_tenant: None,
            tenant: None,
            source: None,
            producer_domain: None,
            consumer_domain: None,
            contract_id: None,
            limit: 100,
            limit_seen: false,
            cursor: None,
            kind: None,
            id: None,
            dead_letter_id: None,
            replay_id: None,
            event_id: None,
            change_ticket: None,
            resolution_kind: None,
            evidence_event_id: None,
        }
    }
}

pub(super) fn parse_dlq_raw_args(args: &[String]) -> anyhow::Result<DlqRawArgs> {
    let mut parsed = DlqRawArgs::default();
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--operator-tenant" => {
                let value = next_cli_value(&mut it, "--operator-tenant")?;
                let tenant = vocab::TenantId::parse(value)
                    .with_context(|| format!("--operator-tenant must be a tenant UUID: {value}"))?;
                set_cli_arg_once(&mut parsed.operator_tenant, "--operator-tenant", tenant)?;
            }
            "--tenant" => {
                let value = next_cli_value(&mut it, "--tenant")?;
                let tenant = vocab::TenantId::parse(value)
                    .with_context(|| format!("--tenant must be a tenant UUID: {value}"))?;
                set_cli_arg_once(&mut parsed.tenant, "--tenant", tenant)?;
            }
            "--source" => {
                let value = next_cli_value(&mut it, "--source")?;
                set_cli_arg_once(&mut parsed.source, "--source", parse_dlq_source(value)?)?;
            }
            "--producer-domain" => {
                let value = next_cli_value(&mut it, "--producer-domain")?;
                anyhow::ensure!(
                    !value.trim().is_empty(),
                    "--producer-domain must be non-empty"
                );
                set_cli_arg_once(
                    &mut parsed.producer_domain,
                    "--producer-domain",
                    value.trim().to_owned(),
                )?;
            }
            "--consumer-domain" => {
                let value = next_cli_value(&mut it, "--consumer-domain")?;
                anyhow::ensure!(
                    !value.trim().is_empty(),
                    "--consumer-domain must be non-empty"
                );
                set_cli_arg_once(
                    &mut parsed.consumer_domain,
                    "--consumer-domain",
                    value.trim().to_owned(),
                )?;
            }
            "--contract-id" => {
                let value = next_cli_value(&mut it, "--contract-id")?;
                anyhow::ensure!(!value.trim().is_empty(), "--contract-id must be non-empty");
                set_cli_arg_once(
                    &mut parsed.contract_id,
                    "--contract-id",
                    value.trim().to_owned(),
                )?;
            }
            "--limit" => {
                anyhow::ensure!(!parsed.limit_seen, "--limit must not be repeated");
                let value = next_cli_value(&mut it, "--limit")?;
                parsed.limit = parse_dlq_limit(value)?;
                parsed.limit_seen = true;
            }
            "--cursor" => {
                let value = next_cli_value(&mut it, "--cursor")?;
                set_cli_arg_once(
                    &mut parsed.cursor,
                    "--cursor",
                    DlqCursor::parse(value).context("--cursor is invalid")?,
                )?;
            }
            "--kind" => {
                let value = next_cli_value(&mut it, "--kind")?;
                set_cli_arg_once(&mut parsed.kind, "--kind", value.to_owned())?;
            }
            "--id" => {
                let value = next_cli_value(&mut it, "--id")?;
                anyhow::ensure!(!value.trim().is_empty(), "--id must be non-empty");
                set_cli_arg_once(&mut parsed.id, "--id", value.trim().to_owned())?;
            }
            "--dead-letter-id" => {
                let value = next_cli_value(&mut it, "--dead-letter-id")?;
                set_cli_arg_once(
                    &mut parsed.dead_letter_id,
                    "--dead-letter-id",
                    DeadLetterId::parse(value)
                        .with_context(|| format!("--dead-letter-id must be a UUID: {value}"))?,
                )?;
            }
            "--replay-id" => {
                let value = next_cli_value(&mut it, "--replay-id")?;
                set_cli_arg_once(
                    &mut parsed.replay_id,
                    "--replay-id",
                    IdemKey::parse(value).with_context(|| {
                        format!("--replay-id must be an idempotency key: {value}")
                    })?,
                )?;
            }
            "--event-id" => {
                let value = next_cli_value(&mut it, "--event-id")?;
                set_cli_arg_once(
                    &mut parsed.event_id,
                    "--event-id",
                    IdemKey::parse(value).with_context(|| {
                        format!("--event-id must be an idempotency key: {value}")
                    })?,
                )?;
            }
            "--change-ticket" => {
                let value = next_cli_value(&mut it, "--change-ticket")?;
                set_cli_arg_once(
                    &mut parsed.change_ticket,
                    "--change-ticket",
                    OutboxResolutionChangeTicket::parse(value)
                        .context("--change-ticket is invalid")?,
                )?;
            }
            "--resolution-kind" => {
                let value = next_cli_value(&mut it, "--resolution-kind")?;
                set_cli_arg_once(
                    &mut parsed.resolution_kind,
                    "--resolution-kind",
                    OutboxExpiredResolutionKind::parse(value)
                        .context("--resolution-kind must be accepted_gap|compensated")?,
                )?;
            }
            "--evidence-event-id" => {
                let value = next_cli_value(&mut it, "--evidence-event-id")?;
                set_cli_arg_once(
                    &mut parsed.evidence_event_id,
                    "--evidence-event-id",
                    IdemKey::parse(value)
                        .with_context(|| format!("--evidence-event-id is invalid: {value}"))?,
                )?;
            }
            other => anyhow::bail!("unknown dlq command argument: {other}"),
        }
    }
    Ok(parsed)
}

pub(super) fn parse_dlq_args(
    args: &[String],
    stdin: &mut impl std::io::BufRead,
) -> anyhow::Result<DlqCliArgs> {
    let args = parse_operator_service_token_stdin_args(args)?;
    anyhow::ensure!(is_dlq_command(&args), dlq_cli_usage());
    let subcommand = args
        .get(1)
        .map(String::as_str)
        .ok_or_else(|| anyhow::anyhow!(dlq_cli_usage()))?;
    anyhow::ensure!(
        matches!(
            subcommand,
            "list" | "inspect" | "replay-dead-letter" | "redrive-outbox" | "resolve-expired-outbox"
        ),
        "unknown dlq subcommand: {subcommand}; {}",
        dlq_cli_usage()
    );
    let mut raw = parse_dlq_raw_args(&args[2..])?;

    let command = match subcommand {
        "list" => {
            anyhow::ensure!(
                raw.kind.is_none() && raw.id.is_none(),
                "list does not accept --kind or --id"
            );
            anyhow::ensure!(
                raw.dead_letter_id.is_none()
                    && raw.replay_id.is_none()
                    && raw.event_id.is_none()
                    && raw.change_ticket.is_none()
                    && raw.resolution_kind.is_none()
                    && raw.evidence_event_id.is_none(),
                "list does not accept mutation target flags"
            );
            DlqCliCommand::List {
                source: raw.source.take(),
                producer_domain: raw.producer_domain.take(),
                consumer_domain: raw.consumer_domain.take(),
                contract_id: raw.contract_id.take(),
                limit: raw.limit,
                cursor: raw.cursor.take(),
            }
        }
        "inspect" => {
            anyhow::ensure!(
                raw.source.is_none()
                    && raw.producer_domain.is_none()
                    && raw.consumer_domain.is_none()
                    && raw.contract_id.is_none()
                    && raw.cursor.is_none()
                    && !raw.limit_seen,
                "inspect does not accept list filters"
            );
            anyhow::ensure!(
                raw.dead_letter_id.is_none()
                    && raw.replay_id.is_none()
                    && raw.event_id.is_none()
                    && raw.change_ticket.is_none()
                    && raw.resolution_kind.is_none()
                    && raw.evidence_event_id.is_none(),
                "inspect does not accept mutation target flags"
            );
            let kind = raw
                .kind
                .take()
                .ok_or_else(|| anyhow::anyhow!("--kind is required"))?;
            let id = raw
                .id
                .take()
                .ok_or_else(|| anyhow::anyhow!("--id is required"))?;
            DlqCliCommand::Inspect {
                target: parse_dlq_kind_target(&kind, &id)?,
            }
        }
        "replay-dead-letter" => {
            anyhow::ensure!(
                raw.source.is_none()
                    && raw.producer_domain.is_none()
                    && raw.consumer_domain.is_none()
                    && raw.contract_id.is_none()
                    && raw.cursor.is_none()
                    && !raw.limit_seen
                    && raw.kind.is_none()
                    && raw.id.is_none()
                    && raw.event_id.is_none()
                    && raw.change_ticket.is_none()
                    && raw.resolution_kind.is_none()
                    && raw.evidence_event_id.is_none(),
                "replay-dead-letter only accepts --dead-letter-id and --replay-id target flags"
            );
            DlqCliCommand::ReplayDeadLetter {
                dead_letter_id: raw
                    .dead_letter_id
                    .take()
                    .ok_or_else(|| anyhow::anyhow!("--dead-letter-id is required"))?,
                replay_id: raw
                    .replay_id
                    .take()
                    .ok_or_else(|| anyhow::anyhow!("--replay-id is required"))?,
            }
        }
        "redrive-outbox" => {
            anyhow::ensure!(
                raw.source.is_none()
                    && raw.producer_domain.is_none()
                    && raw.consumer_domain.is_none()
                    && raw.contract_id.is_none()
                    && raw.cursor.is_none()
                    && !raw.limit_seen
                    && raw.kind.is_none()
                    && raw.id.is_none()
                    && raw.dead_letter_id.is_none()
                    && raw.replay_id.is_none()
                    && raw.change_ticket.is_none()
                    && raw.resolution_kind.is_none()
                    && raw.evidence_event_id.is_none(),
                "redrive-outbox only accepts --event-id target flag"
            );
            DlqCliCommand::RedriveOutbox {
                event_id: raw
                    .event_id
                    .take()
                    .ok_or_else(|| anyhow::anyhow!("--event-id is required"))?,
            }
        }
        "resolve-expired-outbox" => {
            anyhow::ensure!(
                raw.source.is_none()
                    && raw.producer_domain.is_none()
                    && raw.consumer_domain.is_none()
                    && raw.contract_id.is_none()
                    && raw.cursor.is_none()
                    && !raw.limit_seen
                    && raw.kind.is_none()
                    && raw.id.is_none()
                    && raw.dead_letter_id.is_none()
                    && raw.replay_id.is_none(),
                "resolve-expired-outbox only accepts resolution target flags"
            );
            let event_id = raw
                .event_id
                .take()
                .ok_or_else(|| anyhow::anyhow!("--event-id is required"))?;
            let change_ticket = raw
                .change_ticket
                .take()
                .ok_or_else(|| anyhow::anyhow!("--change-ticket is required"))?;
            let resolution_kind = raw
                .resolution_kind
                .take()
                .ok_or_else(|| anyhow::anyhow!("--resolution-kind is required"))?;
            let evidence_event_id = raw.evidence_event_id.take();
            anyhow::ensure!(
                matches!(
                    (resolution_kind, evidence_event_id.is_some()),
                    (OutboxExpiredResolutionKind::AcceptedGap, false)
                        | (OutboxExpiredResolutionKind::Compensated, true)
                ),
                "accepted_gap forbids --evidence-event-id; compensated requires it"
            );
            DlqCliCommand::ResolveExpiredOutbox {
                event_id,
                change_ticket,
                resolution_kind,
                evidence_event_id,
            }
        }
        _ => unreachable!("subcommand checked"),
    };

    let operator_tenant = raw
        .operator_tenant
        .take()
        .ok_or_else(|| anyhow::anyhow!("--operator-tenant is required"))?;
    let tenant = raw
        .tenant
        .take()
        .ok_or_else(|| anyhow::anyhow!("--tenant is required"))?;
    let operator_service_token = read_operator_service_token_stdin(stdin)?;
    Ok(DlqCliArgs {
        command,
        operator_service_token,
        operator_tenant,
        tenant,
    })
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
            action: DlqMaintenanceAction::parse(action)?,
            tenant: vocab::TenantId::parse(tenant).with_context(|| {
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
    operator_tenant: vocab::TenantId,
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
    action: &str,
    resource_id: &str,
    outcome: MaintenanceAuditOutcome<'_>,
) -> anyhow::Result<()> {
    pg.record_dlq_maintenance_audit(operator_subject, action, outcome, resource_id)
        .await
        .context("record DLQ maintenance finish audit")
}

pub(super) async fn authenticate_dlq_operator(
    pg: &PgMaintenanceDeps,
    operator_pdp: &diport::DynPdp<'_>,
    parsed: &DlqCliArgs,
    resource_id: &str,
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
                UNVERIFIED_DLQ_OPERATOR,
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

pub(super) async fn dlq_operator_receipt(
    pg: &PgMaintenanceDeps,
    parsed: &DlqCliArgs,
    resource_id: &str,
    principal: authn::Principal,
    operator: OperatorRuntimeCapability<'_>,
) -> anyhow::Result<AuthorizedDlqOperatorReceipt> {
    let subject = principal.audit_subject().to_owned();
    let grants = match load_dlq_operator_grants_from_command_env(operator) {
        Ok(grants) => grants,
        Err(err) => {
            record_dlq_maintenance_finish_audit(
                pg,
                &subject,
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
    Ok(AuthorizedDlqOperatorReceipt::from_authenticated_and_authorized(caller))
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

pub(super) fn dlq_redrive_result_line(
    tenant: vocab::TenantId,
    event_id: &IdemKey,
    outcome: DlqRedriveOutcome,
) -> String {
    format!(
        "operation=redrive-outbox tenant={tenant} event_id={} outcome={}",
        event_id.as_str(),
        outcome.as_label()
    )
}

#[allow(clippy::too_many_arguments)]
// reason: the helper receives one closed CLI command's typed fields plus its authorized witnesses.
pub(super) async fn run_expired_outbox_resolution<S: DlqStore>(
    store: &S,
    tenant: vocab::TenantId,
    event_id: &IdemKey,
    change_ticket: &OutboxResolutionChangeTicket,
    resolution_kind: OutboxExpiredResolutionKind,
    evidence_event_id: Option<&IdemKey>,
    capability: OperatorDlqCapability,
    operator_subject: &VerifiedOperatorSubject,
) -> anyhow::Result<DlqCommandOutcome> {
    let request = match resolution_kind {
        OutboxExpiredResolutionKind::AcceptedGap => OutboxExpiredResolutionRequest::accepted_gap(
            tenant,
            event_id.clone(),
            change_ticket.clone(),
            operator_subject.clone(),
            capability,
        ),
        OutboxExpiredResolutionKind::Compensated => {
            let evidence_event_id = evidence_event_id
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("compensated evidence invariant"))?;
            OutboxExpiredResolutionRequest::compensated(
                tenant,
                event_id.clone(),
                evidence_event_id,
                change_ticket.clone(),
                operator_subject.clone(),
                capability,
            )
        }
    };
    let outcome = store.resolve_expired_outbox(request).await?;
    println!(
        "operation=resolve-expired-outbox tenant={} event_id={} resolution_kind={} outcome={}",
        tenant,
        event_id.as_str(),
        resolution_kind.as_label(),
        outcome.as_label()
    );
    match outcome {
        OutboxExpiredResolutionOutcome::Resolved | OutboxExpiredResolutionOutcome::NotFound => {
            Ok(DlqCommandOutcome::Completed)
        }
        OutboxExpiredResolutionOutcome::NotExpired => {
            Ok(DlqCommandOutcome::Rejected("not_expired"))
        }
        OutboxExpiredResolutionOutcome::EvidenceRejected => {
            Ok(DlqCommandOutcome::Rejected("evidence_rejected"))
        }
    }
}

pub(super) async fn run_dlq_command_inner<S: DlqStore>(
    store: &S,
    parsed: &DlqCliArgs,
    capability: OperatorDlqCapability,
    operator_subject: &VerifiedOperatorSubject,
) -> anyhow::Result<DlqCommandOutcome> {
    match &parsed.command {
        DlqCliCommand::List {
            source,
            producer_domain,
            consumer_domain,
            contract_id,
            limit,
            cursor,
        } => {
            let mut query = DlqListQuery::new(parsed.tenant).with_limit(*limit);
            if let Some(source) = source {
                query = query.with_source(*source);
            }
            if let Some(domain) = producer_domain {
                query = query.with_producer_domain(domain.clone());
            }
            if let Some(domain) = consumer_domain {
                query = query.with_consumer_domain(domain.clone());
            }
            if let Some(contract_id) = contract_id {
                query = query.with_contract_id(contract_id.clone());
            }
            if let Some(cursor) = cursor {
                query = query.with_cursor(cursor.clone());
            }
            let result = store.list_dlq(query).await?;
            for summary in result.data() {
                print_dlq_summary(summary)?;
            }
            println!(
                "operation=list tenant={} count={} has_more={} next_cursor={}",
                parsed.tenant,
                result.data().len(),
                result.has_more(),
                result.next_cursor().unwrap_or("none")
            );
            Ok(DlqCommandOutcome::Completed)
        }
        DlqCliCommand::Inspect { target } => {
            let summary = store
                .inspect_dlq(DlqInspectRequest::new(parsed.tenant, target.clone()))
                .await?;
            print_dlq_summary(&summary)?;
            match target {
                DlqInspectTarget::DeadLetter(dead_letter_id) => println!(
                    "operation=inspect tenant={} kind=dead_letter dead_letter_id={}",
                    parsed.tenant, dead_letter_id
                ),
                DlqInspectTarget::OutboxDlx(event_id) => println!(
                    "operation=inspect tenant={} kind=outbox_dlx event_id={}",
                    parsed.tenant,
                    event_id.as_str()
                ),
            }
            Ok(DlqCommandOutcome::Completed)
        }
        DlqCliCommand::ReplayDeadLetter {
            dead_letter_id,
            replay_id,
        } => {
            let outcome = store
                .replay_dead_letter(DlqReplayRequest::new(
                    parsed.tenant,
                    dead_letter_id.clone(),
                    replay_id.clone(),
                    capability,
                ))
                .await?;
            println!(
                "operation=replay-dead-letter tenant={} dead_letter_id={} replay_id={} outcome={}",
                parsed.tenant,
                dead_letter_id,
                replay_id.as_str(),
                outcome.as_label()
            );
            Ok(DlqCommandOutcome::Completed)
        }
        DlqCliCommand::RedriveOutbox { event_id } => {
            let outcome = store
                .redrive_outbox(DlqRedriveRequest::new(
                    parsed.tenant,
                    event_id.clone(),
                    capability,
                ))
                .await?;
            println!(
                "{}",
                dlq_redrive_result_line(parsed.tenant, event_id, outcome)
            );
            match outcome {
                DlqRedriveOutcome::Expired => Ok(DlqCommandOutcome::Expired),
                DlqRedriveOutcome::Redriven | DlqRedriveOutcome::NotFound => {
                    Ok(DlqCommandOutcome::Completed)
                }
            }
        }
        DlqCliCommand::ResolveExpiredOutbox {
            event_id,
            change_ticket,
            resolution_kind,
            evidence_event_id,
        } => {
            run_expired_outbox_resolution(
                store,
                parsed.tenant,
                event_id,
                change_ticket,
                *resolution_kind,
                evidence_event_id.as_ref(),
                capability,
                operator_subject,
            )
            .await
        }
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
        operator_subject: &str,
        action: &str,
        outcome: MaintenanceAuditOutcome<'_>,
        resource_id: &str,
    ) -> anyhow::Result<()>;

    async fn operator_subject(
        &self,
        session: &Self::Session,
        parsed: &DlqCliArgs,
        resource_id: &str,
    ) -> anyhow::Result<VerifiedOperatorSubject>;

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
        operator_subject: &str,
        action: &str,
        outcome: MaintenanceAuditOutcome<'_>,
        resource_id: &str,
    ) -> anyhow::Result<()> {
        session
            .record_dlq_maintenance_audit(operator_subject, action, outcome, resource_id)
            .await
            .context("record DLQ maintenance audit")
    }

    async fn operator_subject(
        &self,
        session: &Self::Session,
        parsed: &DlqCliArgs,
        resource_id: &str,
    ) -> anyhow::Result<VerifiedOperatorSubject> {
        let provider =
            match build_operator_service_token_provider(self.config, self.operator, session) {
                Ok(provider) => provider,
                Err(err) => {
                    record_dlq_maintenance_finish_audit(
                        session,
                        UNVERIFIED_DLQ_OPERATOR,
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
        )
        .await?;
        let receipt =
            dlq_operator_receipt(session, parsed, resource_id, principal, self.operator).await?;
        Ok(VerifiedOperatorSubject::from_authorized_receipt(receipt))
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
    args: &[String],
    stdin: &mut impl std::io::BufRead,
    runtime: &R,
) -> anyhow::Result<()>
where
    R: DlqControlRuntime,
{
    let parsed = parse_dlq_args(args, stdin)?;
    let resource_id = dlq_command_resource_id(&parsed);
    let session = runtime.connect_maintenance().await?;
    let start_action = format!("dlq.{}.start", parsed.command.action().as_str());
    if let Err(err) = runtime
        .record_dlq_maintenance_audit(
            &session,
            UNVERIFIED_DLQ_OPERATOR,
            &start_action,
            MaintenanceAuditOutcome::Success,
            &resource_id,
        )
        .await
        .context("record DLQ maintenance start audit")
    {
        runtime.shutdown(session).await;
        return Err(err);
    }

    let finish_action = format!("dlq.{}.finish", parsed.command.action().as_str());
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
    let capability = issue_authorized_dlq_capability();
    let command_result = match runtime.dlq_store(&session, &parsed.command) {
        Ok(store) => run_dlq_command_inner(&store, &parsed, capability, &operator_subject).await,
        Err(err) => Err(err),
    };
    let finish_outcome = match &command_result {
        Ok(DlqCommandOutcome::Completed) => MaintenanceAuditOutcome::Success,
        Ok(DlqCommandOutcome::Expired) => MaintenanceAuditOutcome::Failure { reason: "expired" },
        Ok(DlqCommandOutcome::Rejected(reason)) => MaintenanceAuditOutcome::Failure { reason },
        Err(_) => MaintenanceAuditOutcome::Failure {
            reason: "run_error",
        },
    };
    let audit_result = runtime
        .record_dlq_maintenance_audit(
            &session,
            operator_subject.as_str(),
            &finish_action,
            finish_outcome,
            &resource_id,
        )
        .await
        .context("record DLQ maintenance finish audit");
    runtime.shutdown(session).await;
    audit_result?;
    match command_result.with_context(|| format!("DLQ command failed: {resource_id}"))? {
        DlqCommandOutcome::Completed => Ok(()),
        DlqCommandOutcome::Expired => {
            anyhow::bail!("DLQ command failed: {resource_id}: redrive horizon expired")
        }
        DlqCommandOutcome::Rejected(reason) => {
            anyhow::bail!("DLQ command failed: {resource_id}: {reason}")
        }
    }
}

pub(super) fn issue_authorized_dlq_capability() -> OperatorDlqCapability {
    OperatorDlqCapability::issue_for_authorized_operator()
}

/// 执行 `rss dlq ...`。
pub async fn run_dlq_control_command(
    args: &[String],
    runtime_inputs: &OperatorRuntimeInputs,
) -> anyhow::Result<()> {
    let plan = crate::plan::RuntimePlan::bundled(runtime_inputs.config())
        .context("compile bundled runtime plan for DLQ operator")?;
    let runtime = ProductionDlqControlRuntime {
        config: runtime_inputs.config(),
        operator: runtime_inputs.operator_capability(),
        projection_capture: plan.projection_capture(),
    };
    let stdin = std::io::stdin();
    run_dlq_control_command_with_runtime(args, &mut stdin.lock(), &runtime).await
}
