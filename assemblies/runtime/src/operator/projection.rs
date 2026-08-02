#![forbid(unused_imports)]
#![forbid(clippy::wildcard_imports)]

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use consistency::{
    EngineErrorKind, ProjectionApplyErrorKind, ProjectionApplyErrorReason, ProjectionBatchLimit,
};
use eventexec::{
    ProjectionId, ProjectionSelector, ProjectionStop, ProjectionTargetRegistry,
    ProjectionTargetView, ProjectionVersion,
};
use postgres::{MaintenanceAuditOutcome, PgProjectionOperatorDeps, ProjectionPointerPrecondition};

use super::service_token::{
    OperatorServiceToken, parse_operator_service_token_stdin_args,
    read_operator_service_token_stdin,
};
use super::{build_projection_operator_token_provider, parse_positive_usize};
use crate::config::SnapshotConfig;
use crate::event_transport;
use crate::infra::pg::build_pg_projection_operator_config;
use crate::phase::{OperatorRuntimeCapability, OperatorRuntimeInputs};
use crate::support::SystemClock;

/// `rss` binary 是否请求 projection replay / shadow-swap 控制命令。
#[must_use]
pub fn is_projection_command(args: &[String]) -> bool {
    matches!(args, [cmd, ..] if cmd == "projections")
}

pub(super) const PROJECTION_MAINTENANCE_OPERATOR_GRANTS_ENV: &str =
    "RSS_PROJECTION_MAINTENANCE_OPERATOR_GRANTS";
#[derive(Debug)]
pub(super) struct ProjectionCliArgs {
    pub(super) selector: ProjectionSelector,
    pub(super) command: ProjectionCliCommand,
    pub(super) operator_service_token: OperatorServiceToken,
    pub(super) operator_tenant: vocab::TenantId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ProjectionCliCommand {
    Replay {
        batch_limit: ProjectionBatchLimit,
    },
    Status,
    Swap {
        precondition: ProjectionPointerPrecondition,
    },
}

impl ProjectionCliCommand {
    pub(super) fn action(&self) -> ProjectionMaintenanceAction {
        match self {
            Self::Replay { .. } => ProjectionMaintenanceAction::Replay,
            Self::Status => ProjectionMaintenanceAction::Status,
            Self::Swap { .. } => ProjectionMaintenanceAction::Swap,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProjectionMaintenanceAction {
    Replay,
    Status,
    Swap,
}

impl ProjectionMaintenanceAction {
    pub(super) fn parse(raw: &str) -> anyhow::Result<Self> {
        match raw {
            "replay" => Ok(Self::Replay),
            "status" => Ok(Self::Status),
            "swap" => Ok(Self::Swap),
            other => anyhow::bail!(
                "unknown projection maintenance action in {PROJECTION_MAINTENANCE_OPERATOR_GRANTS_ENV}: {other}"
            ),
        }
    }

    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Replay => "replay",
            Self::Status => "status",
            Self::Swap => "swap",
        }
    }

    pub(super) fn authorized_action(self) -> authn::ProjectionMaintenanceAction {
        match self {
            Self::Replay => authn::ProjectionMaintenanceAction::Replay,
            Self::Status => authn::ProjectionMaintenanceAction::Status,
            Self::Swap => authn::ProjectionMaintenanceAction::Swap,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ProjectionSwapPreconditionArg {
    ExpectUnset,
    ExpectedActiveVersion(ProjectionVersion),
}

pub(super) fn parse_projection_batch_limit(raw: &str) -> anyhow::Result<ProjectionBatchLimit> {
    let raw = parse_positive_usize(raw, "--batch-size")?;
    let raw = u32::try_from(raw).context("--batch-size exceeds u32")?;
    ProjectionBatchLimit::new(raw).context("--batch-size is outside projection batch bounds")
}

pub(super) fn projection_cli_usage() -> &'static str {
    "usage: rss projections replay|status|swap --operator-service-token-stdin --operator-tenant <uuid> --tenant <uuid> --projection <id> --version <id> [--batch-size <n>] [--expected-active-version <id>|--expect-unset]"
}

pub(super) fn set_cli_arg_once<T>(
    slot: &mut Option<T>,
    flag: &str,
    value: T,
) -> anyhow::Result<()> {
    anyhow::ensure!(slot.is_none(), "{flag} must not be repeated");
    *slot = Some(value);
    Ok(())
}

pub(super) fn next_cli_value<'a>(
    it: &mut std::slice::Iter<'a, String>,
    flag: &str,
) -> anyhow::Result<&'a str> {
    it.next()
        .map(String::as_str)
        .ok_or_else(|| anyhow::anyhow!("{flag} requires a value"))
}

pub(super) fn parse_projection_args(
    args: &[String],
    stdin: &mut impl std::io::BufRead,
) -> anyhow::Result<ProjectionCliArgs> {
    let args = parse_operator_service_token_stdin_args(args)?;
    anyhow::ensure!(is_projection_command(&args), projection_cli_usage());
    let subcommand = args
        .get(1)
        .map(String::as_str)
        .ok_or_else(|| anyhow::anyhow!(projection_cli_usage()))?;
    anyhow::ensure!(
        matches!(subcommand, "replay" | "status" | "swap"),
        "unknown projection subcommand: {subcommand}; {}",
        projection_cli_usage()
    );
    let mut operator_tenant = None;
    let mut tenant = None;
    let mut projection = None;
    let mut version = None;
    let mut batch_limit = ProjectionBatchLimit::MAX;
    let mut batch_limit_seen = false;
    let mut precondition = None;

    let mut it = args[2..].iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--operator-tenant" => {
                let raw = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--operator-tenant requires a value"))?;
                let parsed = vocab::TenantId::parse(raw)
                    .with_context(|| format!("--operator-tenant must be a tenant UUID: {raw}"))?;
                set_cli_arg_once(&mut operator_tenant, "--operator-tenant", parsed)?;
            }
            "--tenant" => {
                let raw = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--tenant requires a value"))?;
                let parsed = vocab::TenantId::parse(raw)
                    .with_context(|| format!("--tenant must be a tenant UUID: {raw}"))?;
                set_cli_arg_once(&mut tenant, "--tenant", parsed)?;
            }
            "--projection" => {
                let raw = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--projection requires a value"))?;
                let parsed = ProjectionId::parse(raw)
                    .with_context(|| format!("--projection must be canonical: {raw}"))?;
                set_cli_arg_once(&mut projection, "--projection", parsed)?;
            }
            "--version" => {
                let raw = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--version requires a value"))?;
                let parsed = ProjectionVersion::parse(raw)
                    .with_context(|| format!("--version must be canonical: {raw}"))?;
                set_cli_arg_once(&mut version, "--version", parsed)?;
            }
            "--batch-size" => {
                anyhow::ensure!(!batch_limit_seen, "--batch-size must not be repeated");
                let raw = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--batch-size requires a value"))?;
                batch_limit = parse_projection_batch_limit(raw)?;
                batch_limit_seen = true;
            }
            "--expected-active-version" => {
                let raw = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--expected-active-version requires a value"))?;
                let expected = ProjectionVersion::parse(raw).with_context(|| {
                    format!("--expected-active-version must be canonical: {raw}")
                })?;
                anyhow::ensure!(
                    precondition.is_none(),
                    "swap requires exactly one active-version precondition"
                );
                precondition = Some(ProjectionSwapPreconditionArg::ExpectedActiveVersion(
                    expected,
                ));
            }
            "--expect-unset" => {
                anyhow::ensure!(
                    precondition.is_none(),
                    "swap requires exactly one active-version precondition"
                );
                precondition = Some(ProjectionSwapPreconditionArg::ExpectUnset);
            }
            other => anyhow::bail!("unknown projection command argument: {other}"),
        }
    }

    let selector = ProjectionSelector::new(
        tenant.ok_or_else(|| anyhow::anyhow!("--tenant is required"))?,
        projection.ok_or_else(|| anyhow::anyhow!("--projection is required"))?,
        version.ok_or_else(|| anyhow::anyhow!("--version is required"))?,
    );
    let command = match subcommand {
        "replay" => {
            anyhow::ensure!(
                precondition.is_none(),
                "replay does not accept active-version preconditions"
            );
            ProjectionCliCommand::Replay { batch_limit }
        }
        "status" => {
            anyhow::ensure!(!batch_limit_seen, "status does not accept --batch-size");
            anyhow::ensure!(
                precondition.is_none(),
                "status does not accept active-version preconditions"
            );
            ProjectionCliCommand::Status
        }
        "swap" => {
            anyhow::ensure!(!batch_limit_seen, "swap does not accept --batch-size");
            let precondition = match precondition.ok_or_else(|| {
                anyhow::anyhow!("swap requires exactly one active-version precondition")
            })? {
                ProjectionSwapPreconditionArg::ExpectUnset => {
                    ProjectionPointerPrecondition::ExpectUnset
                }
                ProjectionSwapPreconditionArg::ExpectedActiveVersion(version) => {
                    ProjectionPointerPrecondition::ExpectedActiveVersion(version)
                }
            };
            ProjectionCliCommand::Swap { precondition }
        }
        _ => unreachable!("is_projection_command restricts subcommands"),
    };
    let operator_tenant =
        operator_tenant.ok_or_else(|| anyhow::anyhow!("--operator-tenant is required"))?;
    let operator_service_token = read_operator_service_token_stdin(stdin)?;
    Ok(ProjectionCliArgs {
        selector,
        command,
        operator_service_token,
        operator_tenant,
    })
}

pub(super) fn build_projection_target_registry(
    view: ProjectionTargetView<'_>,
) -> anyhow::Result<ProjectionTargetRegistry> {
    let registry = ProjectionTargetRegistry::from_view(view)
        .context("build assembly-plan projection target registry")?;
    registry
        .validate_coverage()
        .context("validate assembly-plan projection target registry coverage")?;
    Ok(registry)
}

pub(super) fn projection_command_requires_registered_target(
    command: &ProjectionCliCommand,
) -> bool {
    matches!(
        command,
        ProjectionCliCommand::Replay { .. } | ProjectionCliCommand::Swap { .. }
    )
}

pub(super) fn ensure_projection_command_supported_by_registry(
    registry: &ProjectionTargetRegistry,
    parsed: &ProjectionCliArgs,
) -> anyhow::Result<()> {
    registry
        .bindings_for(parsed.selector.projection())
        .context("projection is not activated by the assembly plan")?;
    if projection_command_requires_registered_target(&parsed.command) {
        registry
            .target(parsed.selector.projection())
            .context("projection target is not activated by the assembly plan")?;
    }
    Ok(())
}

pub(super) fn projection_command_resource_id(parsed: &ProjectionCliArgs) -> String {
    format!(
        "operation={} tenant={} projection={} version={}",
        parsed.command.action().as_str(),
        parsed.selector.tenant(),
        parsed.selector.projection().as_str(),
        parsed.selector.version().as_str()
    )
}

pub(super) async fn verified_service_maintenance_operator(
    service_token: &str,
    operator_tenant: vocab::TenantId,
    pdp: &diport::DynPdp<'_>,
    maintenance_context: &str,
) -> anyhow::Result<authn::VerifiedMaintenanceServiceOperator> {
    let (token, _principal) = authn::verify_service_token(
        service_token,
        diport::ServiceTokenTenantBinding::new(operator_tenant),
        pdp,
    )
    .await
    .with_context(|| format!("verify {maintenance_context} operator service token"))?;
    authn::VerifiedMaintenanceServiceOperator::try_from_verified_service_token(&token).with_context(
        || {
            format!(
                "{maintenance_context} operator must be a verified maintenance service-token operator"
            )
        },
    )
}

/// Allowlisted Principal → audit subject downshift for verified maintenance operators.
pub(super) fn service_maintenance_operator_audit_subject(
    proof: &authn::VerifiedMaintenanceServiceOperator,
) -> &str {
    proof.principal().audit_subject()
}

pub(super) async fn verified_projection_maintenance_operator_subject(
    service_token: &str,
    operator_tenant: vocab::TenantId,
    pdp: &diport::DynPdp<'_>,
) -> anyhow::Result<authn::Principal> {
    let (token, principal) = authn::verify_projection_operator_token(service_token, pdp)
        .await
        .context("verify projection maintenance operator token")?;
    anyhow::ensure!(
        token.tenant()? == operator_tenant,
        "projection maintenance operator token tenant does not match --operator-tenant"
    );
    anyhow::ensure!(
        principal.kind() == vocab::PrincipalKind::Service,
        "projection maintenance operator must be a service principal"
    );
    anyhow::ensure!(
        principal.service_caller_domain() == Some(vocab::ServiceCallerDomain::MaintenanceOperator),
        "projection maintenance operator must be the maintenance operator"
    );
    Ok(principal)
}

pub(super) async fn record_projection_maintenance_finish_audit(
    pg: &PgProjectionOperatorDeps,
    operator_subject: &str,
    action: &str,
    resource_id: &str,
    outcome: MaintenanceAuditOutcome<'_>,
) -> anyhow::Result<()> {
    pg.record_projection_maintenance_audit(operator_subject, action, outcome, resource_id)
        .await
        .context("record projection maintenance finish audit")
}

pub(super) const UNVERIFIED_PROJECTION_MAINTENANCE_OPERATOR: &str = "unverified-service-token";

pub(super) fn parse_projection_maintenance_grants(
    raw: &str,
) -> anyhow::Result<authn::ProjectionMaintenanceGrantSet> {
    let raw = raw.trim();
    anyhow::ensure!(
        !raw.is_empty(),
        "{PROJECTION_MAINTENANCE_OPERATOR_GRANTS_ENV} must not be empty"
    );
    let mut grants = Vec::new();
    for entry in raw.split(',') {
        let entry = entry.trim();
        anyhow::ensure!(
            !entry.is_empty(),
            "{PROJECTION_MAINTENANCE_OPERATOR_GRANTS_ENV} must not contain empty entries"
        );
        let parts: Vec<&str> = entry.split('|').map(str::trim).collect();
        anyhow::ensure!(
            parts.len() == 3,
            "{PROJECTION_MAINTENANCE_OPERATOR_GRANTS_ENV} entries must be action|tenant|projection"
        );
        let [action, tenant, projection] = parts.as_slice() else {
            unreachable!("len checked");
        };
        let action = ProjectionMaintenanceAction::parse(action)?.authorized_action();
        let tenant = vocab::TenantId::parse(tenant).with_context(|| {
            format!("{PROJECTION_MAINTENANCE_OPERATOR_GRANTS_ENV} tenant must be a UUID: {tenant}")
        })?;
        let projection = ProjectionId::parse(projection).with_context(|| {
                format!("{PROJECTION_MAINTENANCE_OPERATOR_GRANTS_ENV} projection must be canonical: {projection}")
        })?;
        grants.push(authn::ProjectionMaintenanceGrant::new(
            vocab::ServiceCallerDomain::MaintenanceOperator,
            action,
            tenant,
            projection.as_str(),
        )?);
    }
    anyhow::ensure!(
        !grants.is_empty(),
        "{PROJECTION_MAINTENANCE_OPERATOR_GRANTS_ENV} must contain at least one grant"
    );
    authn::ProjectionMaintenanceGrantSet::new(grants).map_err(Into::into)
}

pub(super) fn load_projection_maintenance_grants_from_snapshot(
    config: SnapshotConfig<'_>,
    _operator: OperatorRuntimeCapability<'_>,
) -> anyhow::Result<authn::ProjectionMaintenanceGrantSet> {
    let raw = config
        .value(PROJECTION_MAINTENANCE_OPERATOR_GRANTS_ENV)
        .with_context(|| format!("{PROJECTION_MAINTENANCE_OPERATOR_GRANTS_ENV} is required"))?;
    parse_projection_maintenance_grants(raw)
}

pub(super) async fn authenticate_projection_maintenance_operator(
    pg: &PgProjectionOperatorDeps,
    operator_pdp: &diport::DynPdp<'_>,
    parsed: &ProjectionCliArgs,
    resource_id: &str,
) -> anyhow::Result<authn::Principal> {
    let principal = match verified_projection_maintenance_operator_subject(
        parsed.operator_service_token.as_str(),
        parsed.operator_tenant,
        operator_pdp,
    )
    .await
    {
        Ok(principal) => principal,
        Err(err) => {
            record_projection_maintenance_finish_audit(
                pg,
                UNVERIFIED_PROJECTION_MAINTENANCE_OPERATOR,
                &format!("projection.{}.finish", parsed.command.action().as_str()),
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

pub(super) async fn projection_maintenance_operator_receipt(
    pg: &PgProjectionOperatorDeps,
    config: SnapshotConfig<'_>,
    parsed: &ProjectionCliArgs,
    resource_id: &str,
    principal: authn::Principal,
    operator: OperatorRuntimeCapability<'_>,
) -> anyhow::Result<authn::ProjectionMaintenanceReceipt> {
    let subject = principal.audit_subject().to_owned();
    let grants = match load_projection_maintenance_grants_from_snapshot(config, operator) {
        Ok(grants) => grants,
        Err(err) => {
            record_projection_maintenance_finish_audit(
                pg,
                &subject,
                &format!("projection.{}.finish", parsed.command.action().as_str()),
                resource_id,
                MaintenanceAuditOutcome::Failure {
                    reason: "operator_grants",
                },
            )
            .await?;
            return Err(err);
        }
    };
    match grants.authorize(
        &principal,
        parsed.command.action().authorized_action(),
        parsed.selector.tenant(),
        parsed.selector.projection().as_str(),
    ) {
        Ok(receipt) => Ok(receipt),
        Err(err) => {
            record_projection_maintenance_finish_audit(
                pg,
                &subject,
                &format!("projection.{}.finish", parsed.command.action().as_str()),
                resource_id,
                MaintenanceAuditOutcome::Failure {
                    reason: "operator_authorization",
                },
            )
            .await?;
            Err(err.into())
        }
    }
}

pub(super) fn format_optional_lsn(lsn: Option<consistency::Lsn>) -> String {
    lsn.map(|value| value.get().to_string())
        .unwrap_or_else(|| "none".to_owned())
}

pub(super) fn format_optional_epoch(epoch: Option<vocab::Epoch>) -> String {
    epoch
        .map(|value| value.get().to_string())
        .unwrap_or_else(|| "none".to_owned())
}

pub(super) fn format_optional_engine_kind(kind: Option<&'static str>) -> &'static str {
    kind.unwrap_or("none")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ProjectionStopCliFields {
    pub(super) stop: &'static str,
    pub(super) failed_at_lsn: Option<consistency::Lsn>,
    pub(super) skipped_at_lsn: Option<consistency::Lsn>,
    pub(super) kind: Option<&'static str>,
    pub(super) reason: Option<&'static str>,
}

pub(super) fn projection_engine_kind_cli(kind: EngineErrorKind) -> &'static str {
    match kind {
        EngineErrorKind::Transient => "transient",
        EngineErrorKind::Permanent => "permanent",
        EngineErrorKind::Invariant => "invariant",
        _ => "unknown",
    }
}

pub(super) fn projection_apply_kind_cli(kind: ProjectionApplyErrorKind) -> &'static str {
    match kind {
        ProjectionApplyErrorKind::Transient => "transient",
        ProjectionApplyErrorKind::Permanent => "permanent",
        ProjectionApplyErrorKind::Invariant => "invariant",
        ProjectionApplyErrorKind::CommitUnknown => "commit_unknown",
        ProjectionApplyErrorKind::RollbackFailed => "rollback_failed",
    }
}

pub(super) fn projection_apply_reason_cli(reason: ProjectionApplyErrorReason) -> &'static str {
    reason.as_label()
}

pub(super) fn projection_stop_cli_fields(stop: &ProjectionStop) -> ProjectionStopCliFields {
    match stop {
        ProjectionStop::Completed => ProjectionStopCliFields {
            stop: "completed",
            failed_at_lsn: None,
            skipped_at_lsn: None,
            kind: None,
            reason: None,
        },
        ProjectionStop::ApplyFailed {
            failed_at,
            kind,
            reason,
        } => ProjectionStopCliFields {
            stop: "apply_failed",
            failed_at_lsn: Some(*failed_at),
            skipped_at_lsn: None,
            kind: Some(projection_apply_kind_cli(*kind)),
            reason: Some(projection_apply_reason_cli(*reason)),
        },
        ProjectionStop::OutOfOrder { failed_at } => ProjectionStopCliFields {
            stop: "out_of_order",
            failed_at_lsn: Some(*failed_at),
            skipped_at_lsn: None,
            kind: None,
            reason: None,
        },
        ProjectionStop::Fenced => ProjectionStopCliFields {
            stop: "fenced",
            failed_at_lsn: None,
            skipped_at_lsn: None,
            kind: None,
            reason: None,
        },
        ProjectionStop::CheckpointUnsaved => ProjectionStopCliFields {
            stop: "checkpoint_unsaved",
            failed_at_lsn: None,
            skipped_at_lsn: None,
            kind: None,
            reason: None,
        },
        ProjectionStop::DeadLetterUnsaved { failed_at } => ProjectionStopCliFields {
            stop: "dead_letter_unsaved",
            failed_at_lsn: Some(*failed_at),
            skipped_at_lsn: None,
            kind: None,
            reason: None,
        },
        ProjectionStop::PoisonSkipped {
            skipped_at,
            kind,
            reason,
        } => ProjectionStopCliFields {
            stop: "poison_skipped",
            failed_at_lsn: None,
            skipped_at_lsn: Some(*skipped_at),
            kind: Some(projection_apply_kind_cli(*kind)),
            reason: Some(projection_apply_reason_cli(*reason)),
        },
        ProjectionStop::SourceReadFailed { kind } => ProjectionStopCliFields {
            stop: "source_read_failed",
            failed_at_lsn: None,
            skipped_at_lsn: None,
            kind: Some(projection_engine_kind_cli(*kind)),
            reason: None,
        },
        ProjectionStop::CheckpointUnread => ProjectionStopCliFields {
            stop: "checkpoint_unread",
            failed_at_lsn: None,
            skipped_at_lsn: None,
            kind: None,
            reason: None,
        },
    }
}

pub(super) fn projection_replay_batch_is_full(
    scanned: usize,
    batch_limit: ProjectionBatchLimit,
) -> bool {
    scanned >= batch_limit.get() as usize
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ProjectionReplayCliRun {
    scanned: usize,
    applied: usize,
    duplicates: usize,
    filtered: usize,
    skipped: usize,
    dead_lettered: usize,
    stop: ProjectionStop,
}

pub(super) async fn run_projection_status(
    pg: &PgProjectionOperatorDeps,
    registry: &ProjectionTargetRegistry,
    selector: &ProjectionSelector,
    receipt: authn::ProjectionMaintenanceReceipt,
) -> anyhow::Result<()> {
    registry
        .bindings_for(selector.projection())
        .context("projection is not generated for this runtime")?;
    let scope = registry
        .source_scope(selector.projection(), selector.tenant())
        .context("bind projection source scope")?;
    let capability =
        pg.authorize_projection_target(receipt, postgres::ProjectionStatusAction, selector, scope)?;
    let status = capability.status().await?;
    let active_version = status
        .pointer()
        .map(|pointer| pointer.version().as_str().to_owned())
        .unwrap_or_else(|| "none".to_owned());
    let high_water = status
        .pointer()
        .and_then(|pointer| pointer.high_water_lsn());
    println!(
        "operation=status tenant={} projection={} selector_version={} active_version={} high_water_lsn={} selected_shadow_high_water_lsn={} source_high_water_lsn={} token={}",
        selector.tenant(),
        selector.projection().as_str(),
        selector.version().as_str(),
        active_version,
        format_optional_lsn(high_water),
        format_optional_lsn(status.selected_shadow_high_water_lsn()),
        format_optional_lsn(status.source_high_water_lsn()),
        format_optional_epoch(status.token())
    );
    Ok(())
}

pub(super) async fn run_projection_swap(
    pg: &PgProjectionOperatorDeps,
    registry: &ProjectionTargetRegistry,
    selector: &ProjectionSelector,
    precondition: ProjectionPointerPrecondition,
    receipt: authn::ProjectionMaintenanceReceipt,
) -> anyhow::Result<()> {
    registry
        .target(selector.projection())
        .context("projection target is not swappable by this runtime")?;
    let scope = registry
        .source_scope(selector.projection(), selector.tenant())
        .context("bind projection source scope")?;
    let capability =
        pg.authorize_projection_target(receipt, postgres::ProjectionSwapAction, selector, scope)?;
    let outcome = capability
        .promote(precondition)
        .await
        .context("promote projection active pointer")?;
    let previous = outcome
        .previous()
        .map(|pointer| pointer.version().as_str().to_owned())
        .unwrap_or_else(|| "none".to_owned());
    println!(
        "operation=swap tenant={} projection={} active_version={} previous_version={} high_water_lsn={} token={}",
        selector.tenant(),
        selector.projection().as_str(),
        outcome.active().version().as_str(),
        previous,
        format_optional_lsn(outcome.active().high_water_lsn()),
        outcome.token().get()
    );
    Ok(())
}

pub(super) async fn run_projection_replay(
    pg: &PgProjectionOperatorDeps,
    registry: &ProjectionTargetRegistry,
    selector: &ProjectionSelector,
    batch_limit: ProjectionBatchLimit,
    receipt: authn::ProjectionMaintenanceReceipt,
    dlx_payload_protector: postgres::DlxPayloadProtector,
) -> anyhow::Result<ProjectionReplayCliRun> {
    let target = registry
        .target(selector.projection())
        .context("projection target is not replayable by this runtime")?;
    let scope = registry
        .source_scope(selector.projection(), selector.tenant())
        .context("bind projection source scope")?;
    let capability =
        pg.authorize_projection_target(receipt, postgres::ProjectionReplayAction, selector, scope)?;
    let execution = registry
        .operator_execution_context(selector.projection(), selector.tenant())
        .context("bind projection operator execution identity")?;
    let replay = capability
        .into_replay_stores(execution, target, dlx_payload_protector)
        .context("bind projection replay stores")?;
    let config = eventexec::ProjectionRunnerConfig::new(
        batch_limit,
        Duration::from_secs(1),
        eventexec::ProjectionPoisonPolicy::Isolate,
    )?;
    let mut scanned = 0usize;
    let mut applied = 0usize;
    let mut duplicates = 0usize;
    let mut filtered = 0usize;
    let mut skipped = 0usize;
    let mut dead_lettered = 0usize;
    loop {
        let run = replay.run_once(config).await;
        scanned = scanned.saturating_add(run.scanned);
        applied = applied.saturating_add(run.applied);
        duplicates = duplicates.saturating_add(run.duplicates);
        filtered = filtered.saturating_add(run.filtered);
        skipped = skipped.saturating_add(run.skipped);
        dead_lettered = dead_lettered.saturating_add(run.dead_lettered);
        let full_batch = projection_replay_batch_is_full(run.scanned, batch_limit);
        let stop = run.stop;
        if matches!(stop, ProjectionStop::Completed) && full_batch {
            continue;
        }
        return Ok(ProjectionReplayCliRun {
            scanned,
            applied,
            duplicates,
            filtered,
            skipped,
            dead_lettered,
            stop,
        });
    }
}

pub(super) async fn run_projection_command_inner(
    pg: &PgProjectionOperatorDeps,
    registry: &ProjectionTargetRegistry,
    parsed: &ProjectionCliArgs,
    receipt: authn::ProjectionMaintenanceReceipt,
    replay_payload_protector: Option<postgres::DlxPayloadProtector>,
) -> anyhow::Result<()> {
    match &parsed.command {
        ProjectionCliCommand::Status => {
            run_projection_status(pg, registry, &parsed.selector, receipt).await
        }
        ProjectionCliCommand::Swap { precondition } => {
            run_projection_swap(
                pg,
                registry,
                &parsed.selector,
                precondition.clone(),
                receipt,
            )
            .await
        }
        ProjectionCliCommand::Replay { batch_limit } => {
            let payload_protector = replay_payload_protector
                .context("projection replay DLQ payload protector missing")?;
            let run = run_projection_replay(
                pg,
                registry,
                &parsed.selector,
                *batch_limit,
                receipt,
                payload_protector,
            )
            .await?;
            let stop = projection_stop_cli_fields(&run.stop);
            println!(
                "operation=replay tenant={} projection={} version={} scanned={} matched={} applied={} duplicates={} filtered={} skipped={} dlq={} stop={} failed_at_lsn={} skipped_at_lsn={} kind={} reason={}",
                parsed.selector.tenant(),
                parsed.selector.projection().as_str(),
                parsed.selector.version().as_str(),
                run.scanned,
                run.applied.saturating_add(run.duplicates),
                run.applied,
                run.duplicates,
                run.filtered,
                run.skipped,
                run.dead_lettered,
                stop.stop,
                format_optional_lsn(stop.failed_at_lsn),
                format_optional_lsn(stop.skipped_at_lsn),
                format_optional_engine_kind(stop.kind),
                format_optional_engine_kind(stop.reason)
            );
            anyhow::ensure!(
                matches!(run.stop, ProjectionStop::Completed),
                "projection replay stopped before completion: stop={} failed_at_lsn={} skipped_at_lsn={} kind={} reason={}",
                stop.stop,
                format_optional_lsn(stop.failed_at_lsn),
                format_optional_lsn(stop.skipped_at_lsn),
                format_optional_engine_kind(stop.kind),
                format_optional_engine_kind(stop.reason)
            );
            Ok(())
        }
    }
}

#[allow(async_fn_in_trait)]
pub(super) trait ProjectionControlRuntime {
    type Session;
    type Registry;

    fn build_registry(&self) -> anyhow::Result<Self::Registry>;

    fn ensure_command_supported(
        &self,
        registry: &Self::Registry,
        parsed: &ProjectionCliArgs,
    ) -> anyhow::Result<()>;

    async fn connect_maintenance(&self) -> anyhow::Result<Self::Session>;

    async fn record_projection_maintenance_audit(
        &self,
        session: &Self::Session,
        operator_subject: &str,
        action: &str,
        outcome: MaintenanceAuditOutcome<'_>,
        resource_id: &str,
    ) -> anyhow::Result<()>;

    async fn operator_receipt(
        &self,
        session: &Self::Session,
        parsed: &ProjectionCliArgs,
        resource_id: &str,
    ) -> anyhow::Result<authn::ProjectionMaintenanceReceipt>;

    async fn run_projection_command(
        &self,
        session: &Self::Session,
        registry: &Self::Registry,
        parsed: &ProjectionCliArgs,
        receipt: authn::ProjectionMaintenanceReceipt,
    ) -> anyhow::Result<()>;

    async fn shutdown(&self, session: Self::Session);
}

pub(super) struct ProductionProjectionControlRuntime<'a> {
    config: SnapshotConfig<'a>,
    operator: OperatorRuntimeCapability<'a>,
}

impl ProjectionControlRuntime for ProductionProjectionControlRuntime<'_> {
    type Session = PgProjectionOperatorDeps;
    type Registry = ProjectionTargetRegistry;

    fn build_registry(&self) -> anyhow::Result<ProjectionTargetRegistry> {
        let mut plan = crate::plan::RuntimePlan::bundled(self.config)
            .context("compile bundled runtime plan for projection operator")?;
        plan.bind_workflow_runtime(std::iter::empty())?;
        build_projection_target_registry(plan.workflow_runtime().projection_targets())
    }

    fn ensure_command_supported(
        &self,
        registry: &Self::Registry,
        parsed: &ProjectionCliArgs,
    ) -> anyhow::Result<()> {
        ensure_projection_command_supported_by_registry(registry, parsed)
    }

    async fn connect_maintenance(&self) -> anyhow::Result<Self::Session> {
        let (operator, source) = build_pg_projection_operator_config(self.config)?;
        PgProjectionOperatorDeps::connect(&operator, &source, Arc::new(SystemClock))
            .await
            .context("setup postgres projection operator deps")
    }

    async fn record_projection_maintenance_audit(
        &self,
        session: &Self::Session,
        operator_subject: &str,
        action: &str,
        outcome: MaintenanceAuditOutcome<'_>,
        resource_id: &str,
    ) -> anyhow::Result<()> {
        session
            .record_projection_maintenance_audit(operator_subject, action, outcome, resource_id)
            .await
            .context("record projection maintenance audit")
    }

    async fn operator_receipt(
        &self,
        session: &Self::Session,
        parsed: &ProjectionCliArgs,
        resource_id: &str,
    ) -> anyhow::Result<authn::ProjectionMaintenanceReceipt> {
        let provider_runtime =
            match build_projection_operator_token_provider(self.config, self.operator, session) {
                Ok(provider) => provider,
                Err(err) => {
                    record_projection_maintenance_finish_audit(
                        session,
                        UNVERIFIED_PROJECTION_MAINTENANCE_OPERATOR,
                        &format!("projection.{}.finish", parsed.command.action().as_str()),
                        resource_id,
                        MaintenanceAuditOutcome::Failure {
                            reason: "operator_provider_config",
                        },
                    )
                    .await?;
                    return Err(err).context("projection maintenance operator verifier");
                }
            };
        let provider = provider_runtime.provider();
        let authentication = authenticate_projection_maintenance_operator(
            session,
            diport::DynPdp::from_ref(provider.as_ref()),
            parsed,
            resource_id,
        )
        .await;
        provider_runtime
            .shutdown()
            .await
            .context("shutdown Projection operator token JWKS verifier")?;
        let principal = authentication?;
        projection_maintenance_operator_receipt(
            session,
            self.config,
            parsed,
            resource_id,
            principal,
            self.operator,
        )
        .await
    }

    async fn run_projection_command(
        &self,
        session: &Self::Session,
        registry: &ProjectionTargetRegistry,
        parsed: &ProjectionCliArgs,
        receipt: authn::ProjectionMaintenanceReceipt,
    ) -> anyhow::Result<()> {
        let replay_payload_protector =
            matches!(&parsed.command, ProjectionCliCommand::Replay { .. })
                .then(|| {
                    event_transport::build_projection_replay_dlx_payload_protector(self.config)
                })
                .transpose()
                .context("build projection replay DLQ payload protector")?;
        run_projection_command_inner(session, registry, parsed, receipt, replay_payload_protector)
            .await
    }

    async fn shutdown(&self, session: Self::Session) {
        session.shutdown().await.ok();
    }
}

pub(super) async fn run_projection_control_command_with_runtime<R>(
    args: &[String],
    stdin: &mut impl std::io::BufRead,
    runtime: &R,
) -> anyhow::Result<()>
where
    R: ProjectionControlRuntime,
{
    let parsed = parse_projection_args(args, stdin)?;
    let registry = runtime.build_registry()?;
    runtime.ensure_command_supported(&registry, &parsed)?;
    let resource_id = projection_command_resource_id(&parsed);
    let session = runtime.connect_maintenance().await?;
    let start_action = format!("projection.{}.start", parsed.command.action().as_str());
    if let Err(err) = runtime
        .record_projection_maintenance_audit(
            &session,
            UNVERIFIED_PROJECTION_MAINTENANCE_OPERATOR,
            &start_action,
            MaintenanceAuditOutcome::Success,
            &resource_id,
        )
        .await
        .context("record projection maintenance start audit")
    {
        runtime.shutdown(session).await;
        return Err(err);
    }

    let finish_action = format!("projection.{}.finish", parsed.command.action().as_str());
    let receipt = match runtime
        .operator_receipt(&session, &parsed, &resource_id)
        .await
    {
        Ok(receipt) => receipt,
        Err(err) => {
            runtime.shutdown(session).await;
            return Err(err);
        }
    };
    let operator_subject = receipt.operator_caller().as_str().to_owned();
    let command_result = runtime
        .run_projection_command(&session, &registry, &parsed, receipt)
        .await;
    let finish_outcome = if command_result.is_ok() {
        MaintenanceAuditOutcome::Success
    } else {
        MaintenanceAuditOutcome::Failure {
            reason: "run_error",
        }
    };
    let audit_result = runtime
        .record_projection_maintenance_audit(
            &session,
            &operator_subject,
            &finish_action,
            finish_outcome,
            &resource_id,
        )
        .await
        .context("record projection maintenance finish audit");
    runtime.shutdown(session).await;
    audit_result?;
    command_result
}

/// 执行 `rss projections replay|status|swap`。
pub async fn run_projection_control_command(
    args: &[String],
    runtime_inputs: &OperatorRuntimeInputs,
) -> anyhow::Result<()> {
    let runtime = ProductionProjectionControlRuntime {
        config: runtime_inputs.config(),
        operator: runtime_inputs.operator_capability(),
    };
    let stdin = std::io::stdin();
    run_projection_control_command_with_runtime(args, &mut stdin.lock(), &runtime).await
}
