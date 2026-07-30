#![forbid(unused_imports)]
#![forbid(clippy::wildcard_imports)]

use super::build_operator_service_token_provider;
use super::projection::{
    next_cli_value, set_cli_arg_once, verified_service_maintenance_operator_subject,
};
use anyhow::Context as _;
use eventexec::{OperatorReconcileCapability, ReconcileOperatorStore, ReconcileTargetSummary};
use postgres::{
    MaintenanceAuditOutcome, PgMaintenanceDeps, PgMaintenanceReconcileStore, PgRuntimeDeps,
};

use crate::infra::pg::build_pg_migrator_config;
use crate::phase::{OperatorRuntimeCapability, OperatorRuntimeInputs};

/// Whether the rss binary was invoked for reconcile target inspection or recovery.
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ReconcileTargetCliArgs {
    action: ReconcileMaintenanceAction,
    operator_service_token: String,
    operator_tenant: vocab::TenantId,
    tenant: vocab::TenantId,
    target_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ReconcileMaintenanceGrant {
    action: ReconcileMaintenanceAction,
    tenant: vocab::TenantId,
}

pub(super) fn reconcile_target_usage() -> &'static str {
    "usage: rss reconcile-target inspect|resume --operator-service-token <token> --operator-tenant <uuid> --tenant <uuid> --target-id <uuid>"
}

pub(super) fn parse_reconcile_target_args(
    args: &[String],
) -> anyhow::Result<ReconcileTargetCliArgs> {
    anyhow::ensure!(is_reconcile_target_command(args), reconcile_target_usage());
    let action = args
        .get(1)
        .ok_or_else(|| anyhow::anyhow!(reconcile_target_usage()))
        .and_then(|raw| ReconcileMaintenanceAction::parse(raw))?;
    let mut operator_service_token = None;
    let mut operator_tenant = None;
    let mut tenant = None;
    let mut target_id = None;
    let mut it = args[2..].iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--operator-service-token" => {
                let value = next_cli_value(&mut it, "--operator-service-token")?;
                let value = value.trim();
                anyhow::ensure!(
                    !value.is_empty(),
                    "--operator-service-token must be non-empty"
                );
                set_cli_arg_once(
                    &mut operator_service_token,
                    "--operator-service-token",
                    value.to_owned(),
                )?;
            }
            "--operator-tenant" => {
                let value = next_cli_value(&mut it, "--operator-tenant")?;
                set_cli_arg_once(
                    &mut operator_tenant,
                    "--operator-tenant",
                    vocab::TenantId::parse(value).with_context(|| {
                        format!("--operator-tenant must be a tenant UUID: {value}")
                    })?,
                )?;
            }
            "--tenant" => {
                let value = next_cli_value(&mut it, "--tenant")?;
                set_cli_arg_once(
                    &mut tenant,
                    "--tenant",
                    vocab::TenantId::parse(value)
                        .with_context(|| format!("--tenant must be a tenant UUID: {value}"))?,
                )?;
            }
            "--target-id" => {
                let value = next_cli_value(&mut it, "--target-id")?;
                let parsed = uuid::Uuid::parse_str(value)
                    .with_context(|| format!("--target-id must be a UUID: {value}"))?;
                set_cli_arg_once(&mut target_id, "--target-id", parsed.to_string())?;
            }
            other => anyhow::bail!("unknown reconcile target argument: {other}"),
        }
    }
    Ok(ReconcileTargetCliArgs {
        action,
        operator_service_token: operator_service_token
            .ok_or_else(|| anyhow::anyhow!("--operator-service-token is required"))?,
        operator_tenant: operator_tenant
            .ok_or_else(|| anyhow::anyhow!("--operator-tenant is required"))?,
        tenant: tenant.ok_or_else(|| anyhow::anyhow!("--tenant is required"))?,
        target_id: target_id.ok_or_else(|| anyhow::anyhow!("--target-id is required"))?,
    })
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
pub async fn run_reconcile_target_command(
    args: &[String],
    runtime_inputs: &OperatorRuntimeInputs,
) -> anyhow::Result<()> {
    let config = runtime_inputs.config();
    let parsed = parse_reconcile_target_args(args)?;
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
    let subject = match verified_service_maintenance_operator_subject(
        &parsed.operator_service_token,
        parsed.operator_tenant,
        diport::DynPdp::from_ref(provider.as_ref()),
        "reconcile target maintenance",
    )
    .await
    {
        Ok(subject) => subject,
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
