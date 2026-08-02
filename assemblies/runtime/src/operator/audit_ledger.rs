#![forbid(unused_imports)]
#![forbid(clippy::wildcard_imports)]

use anyhow::Context as _;
use audit::ports::{AuditAdminRepo as _, AuditLedgerVerifyReport};
use postgres::{MaintenanceAuditOutcome, PgMaintenanceDeps, PgRuntimeDeps};

use super::projection::{
    next_cli_value, service_maintenance_operator_audit_subject, set_cli_arg_once,
    verified_service_maintenance_operator,
};
use super::service_token::{
    OperatorServiceToken, parse_operator_service_token_stdin_args,
    read_operator_service_token_stdin,
};
use super::{build_operator_service_token_provider, parse_positive_usize};
use crate::config::SnapshotConfig;
use crate::domains;
use crate::infra::pg::build_pg_audit_maintenance_config;
use crate::phase::{OperatorRuntimeCapability, OperatorRuntimeInputs};

/// `rss` binary 是否请求 per-tenant audit ledger full-chain verify。
#[must_use]
pub fn is_audit_ledger_verify_command(args: &[String]) -> bool {
    matches!(
        args,
        [cmd, sub, ..] if cmd == "audit-ledger" && sub == "verify"
    )
}

pub(super) const AUDIT_LEDGER_VERIFY_OPERATOR_GRANTS_ENV: &str =
    "RSS_AUDIT_LEDGER_VERIFY_OPERATOR_GRANTS";
pub(super) const UNVERIFIED_AUDIT_LEDGER_VERIFY_OPERATOR: &str = "unverified-service-token";

#[derive(Debug)]
pub(super) struct AuditLedgerVerifyArgs {
    pub(super) operator_service_token: OperatorServiceToken,
    pub(super) operator_tenant: vocab::TenantId,
    pub(super) tenant: vocab::TenantId,
    pub(super) batch: vocab::Limit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AuditLedgerVerifyGrant {
    pub(super) tenant: vocab::TenantId,
}

pub(super) fn audit_ledger_verify_usage() -> &'static str {
    "usage: rss audit-ledger verify --operator-service-token-stdin --operator-tenant <uuid> --tenant <uuid> [--batch-size <1..500>]"
}

pub(super) fn parse_audit_ledger_verify_batch(raw: &str) -> anyhow::Result<vocab::Limit> {
    let value = parse_positive_usize(raw, "--batch-size")?;
    let value = u16::try_from(value).context("--batch-size exceeds u16")?;
    vocab::Limit::new(value).context("--batch-size must be <= 500")
}

pub(super) fn parse_audit_ledger_verify_args(
    args: &[String],
    stdin: &mut impl std::io::BufRead,
) -> anyhow::Result<AuditLedgerVerifyArgs> {
    let args = parse_operator_service_token_stdin_args(args)?;
    anyhow::ensure!(
        is_audit_ledger_verify_command(&args),
        audit_ledger_verify_usage()
    );
    let mut operator_tenant = None;
    let mut tenant = None;
    let mut batch = vocab::Limit::new(500).context("default audit ledger verify batch")?;
    let mut batch_seen = false;

    let mut it = args[2..].iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--operator-tenant" => {
                let raw = next_cli_value(&mut it, "--operator-tenant")?;
                let parsed = vocab::TenantId::parse(raw)
                    .with_context(|| format!("--operator-tenant must be a tenant UUID: {raw}"))?;
                set_cli_arg_once(&mut operator_tenant, "--operator-tenant", parsed)?;
            }
            "--tenant" => {
                let raw = next_cli_value(&mut it, "--tenant")?;
                let parsed = vocab::TenantId::parse(raw)
                    .with_context(|| format!("--tenant must be a tenant UUID: {raw}"))?;
                set_cli_arg_once(&mut tenant, "--tenant", parsed)?;
            }
            "--batch-size" => {
                anyhow::ensure!(!batch_seen, "--batch-size must not be repeated");
                let raw = next_cli_value(&mut it, "--batch-size")?;
                batch = parse_audit_ledger_verify_batch(raw)?;
                batch_seen = true;
            }
            "--all-tenants" => {
                anyhow::bail!("audit ledger verify does not support --all-tenants")
            }
            "--namespace" => {
                anyhow::bail!("audit ledger verify does not support --namespace")
            }
            other => anyhow::bail!("unknown audit ledger verify argument: {other}"),
        }
    }

    let operator_tenant =
        operator_tenant.ok_or_else(|| anyhow::anyhow!("--operator-tenant is required"))?;
    let tenant = tenant.ok_or_else(|| anyhow::anyhow!("--tenant is required"))?;
    let operator_service_token = read_operator_service_token_stdin(stdin)?;
    Ok(AuditLedgerVerifyArgs {
        operator_service_token,
        operator_tenant,
        tenant,
        batch,
    })
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
            tenant: vocab::TenantId::parse(tenant).with_context(|| {
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
    operator_tenant: vocab::TenantId,
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
    args: &[String],
    stdin: &mut impl std::io::BufRead,
    runtime: &R,
) -> anyhow::Result<()>
where
    R: AuditLedgerVerifyRuntime,
{
    let parsed = parse_audit_ledger_verify_args(args, stdin)?;
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

/// 执行 `rss audit-ledger verify`。
pub async fn run_audit_ledger_verify_command(
    args: &[String],
    runtime_inputs: &OperatorRuntimeInputs,
) -> anyhow::Result<()> {
    let runtime = ProductionAuditLedgerVerifyRuntime {
        config: runtime_inputs.config(),
        operator: runtime_inputs.operator_capability(),
    };
    let stdin = std::io::stdin();
    run_audit_ledger_verify_command_with_runtime(args, &mut stdin.lock(), &runtime).await
}
