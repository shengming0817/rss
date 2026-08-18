//! Closed Saga operator CLI and typed runtime dispatch.
//!
//! The parser binds every request to an exact tenant, instance, owner, contract and action. The
//! production assembly supplies only plan-bound [`eventexec::SagaRuntimeOperatorTarget`] values;
//! no raw durable store is reachable from this module.
//!
//! ref: oxidecomputer/steno src/lib.rs@main (operator recovery remains owned by the typed Saga
//! runtime; RSS additionally requires authenticated, audited, tenant-fenced action proofs).

use anyhow::Context as _;
use diport::ManagedResource as _;
use postgres::{MaintenanceAuditOutcome, PgRuntimeDeps, PgSagaOperatorDeps};

use super::build_operator_service_token_provider;
use super::projection::{
    service_maintenance_operator_audit_subject, verified_service_maintenance_operator,
};
use super::service_token::OperatorServiceToken;
use crate::infra::pg::{build_pg_saga_operator_config, build_pg_saga_serving_configs};
use crate::phase::OperatorRuntimeCapability;
#[cfg(feature = "operator-cli")]
use crate::phase::OperatorRuntimeInputs;

const SAGA_OPERATOR_GRANTS_ENV: &str = "RSS_SAGA_OPERATOR_GRANTS";
const UNVERIFIED_SAGA_OPERATOR: &str = "unverified-service-token";

const COMMAND_NAMESPACE: &str = "sagas";

/// Whether argv selects the closed Saga operator namespace.
#[must_use]
pub fn is_saga_command(args: &[String]) -> bool {
    matches!(args, [namespace, ..] if namespace == COMMAND_NAMESPACE)
}

#[derive(Debug, Clone, Copy)]
struct SagaOperatorActionDescriptor {
    name: &'static str,
    start_action: &'static str,
    finish_action: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SagaOperatorCliAction {
    Status,
    RetryCompensation,
    Repair,
    Terminate,
}

impl SagaOperatorCliAction {
    // Hand-written (not macro_rules) so runtime-env-guard's composed-path detector does not
    // false-positive on flattened `$(Self::$variant)` tokens looking like `$Ident::$Ident`.
    const ALL: &'static [Self] = &[
        Self::Status,
        Self::RetryCompensation,
        Self::Repair,
        Self::Terminate,
    ];

    const fn descriptor(self) -> SagaOperatorActionDescriptor {
        match self {
            Self::Status => SagaOperatorActionDescriptor {
                name: "status",
                start_action: "saga.operator.status.start",
                finish_action: "saga.operator.status.finish",
            },
            Self::RetryCompensation => SagaOperatorActionDescriptor {
                name: "retry-compensation",
                start_action: "saga.operator.retry-compensation.start",
                finish_action: "saga.operator.retry-compensation.finish",
            },
            Self::Repair => SagaOperatorActionDescriptor {
                name: "repair",
                start_action: "saga.operator.repair.start",
                finish_action: "saga.operator.repair.finish",
            },
            Self::Terminate => SagaOperatorActionDescriptor {
                name: "terminate",
                start_action: "saga.operator.terminate.start",
                finish_action: "saga.operator.terminate.finish",
            },
        }
    }

    fn parse(raw: &str) -> anyhow::Result<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|action| action.as_str() == raw)
            .ok_or_else(|| anyhow::anyhow!("unknown Saga operator action: {raw}"))
    }

    const fn as_str(self) -> &'static str {
        self.descriptor().name
    }

    const fn start_action(self) -> &'static str {
        self.descriptor().start_action
    }

    const fn finish_action(self) -> &'static str {
        self.descriptor().finish_action
    }
}

#[derive(Debug)]
pub(super) struct SagaCliRequest {
    action: SagaOperatorCliAction,
    operator_tenant: rss_request_context::TenantId,
    identity: diport::SagaWorkerIdentity,
    instance: consistency::SagaInstanceRef,
    expected_journal_position: Option<u64>,
    expected_reason: Option<diport::SagaOperatorRepairReason>,
    reason_text: Option<diport::SagaOperatorReasonText>,
    change_ticket: Option<diport::SagaOperatorChangeTicket>,
}

#[derive(Debug)]
pub(super) struct SagaCliArgs {
    request: SagaCliRequest,
    operator_service_token: OperatorServiceToken,
}

impl std::ops::Deref for SagaCliArgs {
    type Target = SagaCliRequest;

    fn deref(&self) -> &Self::Target {
        &self.request
    }
}

/// Opaque, fully validated Saga command whose stdin token has already been consumed.
#[cfg(feature = "operator-cli")]
pub struct PreparedSagaCommand(SagaCliArgs);

/// Pure CLI preparation result. Help performs no stdin / environment / provider access beyond
/// clap's own help/version render (already printed when this variant is returned).
#[cfg(feature = "operator-cli")]
pub enum SagaCommandPreparation {
    /// Help or version text was already written; caller returns `Ok(())` without runtime.
    Help,
    Execute(PreparedSagaCommand),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SagaOperatorGrant {
    action: SagaOperatorCliAction,
    tenant: rss_request_context::TenantId,
    identity: diport::SagaWorkerIdentity,
}

#[cfg(feature = "operator-cli")]
mod clap_cli {
    use super::{
        COMMAND_NAMESPACE, PreparedSagaCommand, SagaCliArgs, SagaCliRequest,
        SagaCommandPreparation, SagaOperatorCliAction,
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
    #[derive(Debug, Parser)]
    #[command(
        name = COMMAND_NAMESPACE,
        bin_name = "rss sagas",
        about = "Inspect or recover a plan-bound Saga instance",
        long_about = "Operator commands for Saga status inspection and closed recovery actions \
(retry-compensation, repair, terminate). The operator service token is read from stdin after \
argv validation (--operator-service-token-stdin). The help subcommand is disabled; use --help.",
        disable_help_subcommand = true,
        disable_version_flag = true
    )]
    struct SagaCli {
        #[command(subcommand)]
        action: SagaSubcommand,
    }

    #[derive(Debug, Subcommand)]
    enum SagaSubcommand {
        /// Read Saga status (no mutation evidence).
        Status(SagaSharedArgs),
        /// Retry compensation from an exact journal position.
        #[command(name = "retry-compensation")]
        RetryCompensation(SagaRetryCompensationArgs),
        /// Repair a Saga stuck on a closed repairable reason.
        Repair(SagaRepairArgs),
        /// Terminate a Saga with operator evidence.
        Terminate(SagaTerminateArgs),
    }

    #[derive(Debug, Args)]
    struct SagaSharedArgs {
        #[command(flatten)]
        auth: OperatorAuthSharedArgs,

        /// Saga owner domain.
        #[arg(long, value_parser = parse_owner_cli)]
        owner: String,

        /// Saga contract id.
        #[arg(long, value_parser = parse_contract_cli)]
        contract: diport::SagaContractId,

        /// Saga instance id (UUID).
        #[arg(long, value_parser = parse_saga_id_cli)]
        saga_id: consistency::SagaId,
    }

    #[derive(Debug, Args)]
    struct SagaMutationEvidenceArgs {
        /// Operator-authored reason text for this mutation (non-empty evidence).
        #[arg(long, value_parser = parse_reason_text_cli)]
        reason_text: diport::SagaOperatorReasonText,

        /// Change-ticket id that authorizes this mutation (non-empty evidence).
        #[arg(long, value_parser = parse_change_ticket_cli)]
        change_ticket: diport::SagaOperatorChangeTicket,
    }

    #[derive(Debug, Args)]
    struct SagaRetryCompensationArgs {
        #[command(flatten)]
        shared: SagaSharedArgs,

        /// Exact journal position that compensation must resume from.
        #[arg(long)]
        expected_journal_position: u64,

        #[command(flatten)]
        evidence: SagaMutationEvidenceArgs,
    }

    #[derive(Debug, Args)]
    struct SagaRepairArgs {
        #[command(flatten)]
        shared: SagaSharedArgs,

        /// Closed repairable Saga reason that must still be current.
        #[arg(long, value_parser = parse_expected_reason_cli)]
        expected_reason: diport::SagaOperatorRepairReason,

        #[command(flatten)]
        evidence: SagaMutationEvidenceArgs,
    }

    #[derive(Debug, Args)]
    struct SagaTerminateArgs {
        #[command(flatten)]
        shared: SagaSharedArgs,

        #[command(flatten)]
        evidence: SagaMutationEvidenceArgs,
    }

    fn parse_owner_cli(raw: &str) -> Result<String, String> {
        if raw.trim() == raw && !raw.is_empty() {
            Ok(raw.to_owned())
        } else {
            Err("--owner is invalid".to_owned())
        }
    }

    fn parse_contract_cli(raw: &str) -> Result<diport::SagaContractId, String> {
        diport::SagaContractId::parse(raw).map_err(|_| "--contract is invalid".to_owned())
    }

    fn parse_saga_id_cli(raw: &str) -> Result<consistency::SagaId, String> {
        uuid::Uuid::parse_str(raw)
            .map(consistency::SagaId::new)
            .map_err(|_| "--saga-id must be a UUID".to_owned())
    }

    fn parse_reason_text_cli(raw: &str) -> Result<diport::SagaOperatorReasonText, String> {
        diport::SagaOperatorReasonText::parse(raw.to_owned())
            .map_err(|_| "--reason-text is invalid".to_owned())
    }

    fn parse_change_ticket_cli(raw: &str) -> Result<diport::SagaOperatorChangeTicket, String> {
        diport::SagaOperatorChangeTicket::parse(raw.to_owned())
            .map_err(|_| "--change-ticket is invalid".to_owned())
    }

    fn parse_expected_reason_cli(raw: &str) -> Result<diport::SagaOperatorRepairReason, String> {
        let reason = consistency::SagaOperatorReason::parse(raw)
            .ok_or_else(|| "--expected-reason is not a closed Saga reason".to_owned())?;
        diport::SagaOperatorRepairReason::try_from(reason)
            .map_err(|_| "--expected-reason is not repairable".to_owned())
    }

    fn into_request(
        action: SagaOperatorCliAction,
        shared: SagaSharedArgs,
        expected_journal_position: Option<u64>,
        expected_reason: Option<diport::SagaOperatorRepairReason>,
        reason_text: Option<diport::SagaOperatorReasonText>,
        change_ticket: Option<diport::SagaOperatorChangeTicket>,
    ) -> anyhow::Result<SagaCliRequest> {
        debug_assert!(shared.auth.token_stdin.operator_service_token_stdin);
        let identity = diport::SagaWorkerIdentity::new(shared.owner, shared.contract)
            .context("Saga identity invalid")?;
        let instance = consistency::SagaInstanceRef::new(shared.auth.tenant, shared.saga_id)
            .context("Saga instance invalid")?;
        Ok(SagaCliRequest {
            action,
            operator_tenant: shared.auth.operator_tenant,
            identity,
            instance,
            expected_journal_position,
            expected_reason,
            reason_text,
            change_ticket,
        })
    }

    fn request_from_cli(cli: SagaCli) -> anyhow::Result<SagaCliRequest> {
        match cli.action {
            SagaSubcommand::Status(shared) => into_request(
                SagaOperatorCliAction::Status,
                shared,
                None,
                None,
                None,
                None,
            ),
            SagaSubcommand::RetryCompensation(args) => into_request(
                SagaOperatorCliAction::RetryCompensation,
                args.shared,
                Some(args.expected_journal_position),
                None,
                Some(args.evidence.reason_text),
                Some(args.evidence.change_ticket),
            ),
            SagaSubcommand::Repair(args) => into_request(
                SagaOperatorCliAction::Repair,
                args.shared,
                None,
                Some(args.expected_reason),
                Some(args.evidence.reason_text),
                Some(args.evidence.change_ticket),
            ),
            SagaSubcommand::Terminate(args) => into_request(
                SagaOperatorCliAction::Terminate,
                args.shared,
                None,
                None,
                Some(args.evidence.reason_text),
                Some(args.evidence.change_ticket),
            ),
        }
    }

    #[cfg(test)]
    pub(in crate::operator) fn parse_saga_args(
        args: &[String],
        stdin: &mut impl std::io::BufRead,
    ) -> anyhow::Result<SagaCliArgs> {
        match prepare_saga_command_with_stdin(args, stdin)? {
            SagaCommandPreparation::Execute(PreparedSagaCommand(parsed)) => Ok(parsed),
            SagaCommandPreparation::Help => {
                anyhow::bail!("test expected executable Saga command, got help")
            }
        }
    }

    pub(in crate::operator) fn prepare_saga_command_with_stdin(
        args: &[String],
        stdin: &mut impl std::io::BufRead,
    ) -> anyhow::Result<SagaCommandPreparation> {
        let cli = match SagaCli::try_parse_from(args) {
            Ok(cli) => cli,
            Err(err) => {
                let ClapHelpPrinted = map_clap_parse_error(err, FAMILY)?;
                return Ok(SagaCommandPreparation::Help);
            }
        };
        let request = request_from_cli(cli)?;
        let operator_service_token = read_operator_service_token_stdin(stdin)?;
        Ok(SagaCommandPreparation::Execute(PreparedSagaCommand(
            SagaCliArgs {
                request,
                operator_service_token,
            },
        )))
    }
}

#[cfg(all(test, feature = "operator-cli"))]
pub(super) use clap_cli::parse_saga_args;

/// Validate Saga argv and consume stdin before any runtime/environment/provider preparation.
#[cfg(feature = "operator-cli")]
pub fn prepare_saga_command(args: &[String]) -> anyhow::Result<SagaCommandPreparation> {
    let stdin = std::io::stdin();
    clap_cli::prepare_saga_command_with_stdin(args, &mut stdin.lock())
}

fn parse_saga_operator_grants(raw: &str) -> anyhow::Result<Vec<SagaOperatorGrant>> {
    anyhow::ensure!(
        !raw.trim().is_empty(),
        "{SAGA_OPERATOR_GRANTS_ENV} must not be empty"
    );
    raw.split(',')
        .map(|entry| {
            let parts = entry.split('|').map(str::trim).collect::<Vec<_>>();
            anyhow::ensure!(
                parts.len() == 4,
                "{SAGA_OPERATOR_GRANTS_ENV} entries must be action|tenant|owner|contract"
            );
            let action = SagaOperatorCliAction::parse(parts[0])?;
            let tenant = rss_request_context::TenantId::parse(parts[1])
                .context("Saga operator grant tenant must be a UUID")?;
            let contract = diport::SagaContractId::parse(parts[3])
                .context("Saga operator grant contract is invalid")?;
            let identity = diport::SagaWorkerIdentity::new(parts[2], contract)
                .context("Saga operator grant identity is invalid")?;
            Ok(SagaOperatorGrant {
                action,
                tenant,
                identity,
            })
        })
        .collect()
}

/// Load the exact Saga grant set from the immutable operator configuration generation.
///
/// The operator capability keeps this purpose-bound reader out of serving call sites. The
/// `RUNTIME-ENV-FUNNEL-01` carrier owns the exact signature, key and sole caller.
pub(super) fn load_saga_operator_grants_from_snapshot(
    config: crate::config::SnapshotConfig<'_>,
    _operator: OperatorRuntimeCapability<'_>,
) -> anyhow::Result<Vec<SagaOperatorGrant>> {
    let raw = config
        .value(SAGA_OPERATOR_GRANTS_ENV)
        .with_context(|| format!("{SAGA_OPERATOR_GRANTS_ENV} is required"))?;
    parse_saga_operator_grants(raw)
}

fn authorize_saga_operator(
    parsed: &SagaCliArgs,
    grants: &[SagaOperatorGrant],
) -> anyhow::Result<()> {
    anyhow::ensure!(
        grants.iter().any(|grant| {
            grant.action == parsed.action
                && grant.tenant == parsed.instance.tenant()
                && grant.identity == parsed.identity
        }),
        "Saga operator is not authorized for action={} tenant={} owner={} contract={}",
        parsed.action.as_str(),
        parsed.instance.tenant(),
        parsed.identity.owner(),
        parsed.identity.contract_id().as_str(),
    );
    Ok(())
}

fn select_saga_operator_target(
    runtime: eventexec::SagaRuntimeView<'_>,
    identity: &diport::SagaWorkerIdentity,
) -> anyhow::Result<eventexec::SagaRuntimeOperatorTarget> {
    let mut matches = runtime
        .entries()
        .filter(|entry| entry.operator_target().identity() == identity)
        .map(|entry| entry.operator_target());
    let target = matches.next().with_context(|| {
        format!(
            "Saga is not active in the assembly plan: owner={} contract={}",
            identity.owner(),
            identity.contract_id().as_str()
        )
    })?;
    anyhow::ensure!(
        matches.next().is_none(),
        "multiple active Saga operator targets match owner={} contract={}",
        identity.owner(),
        identity.contract_id().as_str()
    );
    Ok(target)
}

fn saga_resource_id(parsed: &SagaCliArgs) -> String {
    format!(
        "tenant={} owner={} contract={} saga_id={}",
        parsed.instance.tenant(),
        parsed.identity.owner(),
        parsed.identity.contract_id().as_str(),
        parsed.instance.saga_id().as_uuid(),
    )
}

#[allow(async_fn_in_trait)]
trait SagaCommandRuntime {
    type ControlSession;
    type ActionTarget;

    fn now(&self) -> std::time::SystemTime;
    async fn connect_control(&self) -> anyhow::Result<Self::ControlSession>;
    async fn prepare_target(&self, parsed: &SagaCliArgs) -> anyhow::Result<Self::ActionTarget>;
    #[allow(clippy::too_many_arguments)]
    async fn audit(
        &self,
        session: &Self::ControlSession,
        target_tenant: rss_request_context::TenantId,
        subject: &str,
        action: &'static str,
        outcome: MaintenanceAuditOutcome<'_>,
        resource_id: &str,
        start_audit_id: &diport::SagaOperatorStartAuditId,
    ) -> anyhow::Result<()>;
    async fn authenticate(
        &self,
        session: &Self::ControlSession,
        parsed: &SagaCliArgs,
    ) -> anyhow::Result<String>;
    fn authorize(&self, parsed: &SagaCliArgs) -> anyhow::Result<()>;
    async fn status(
        &self,
        target: &Self::ActionTarget,
        authorization: diport::SagaOperatorAuthorization<diport::saga_operator_action::Status>,
    ) -> anyhow::Result<diport::SagaOperatorStatusOutcome>;
    async fn retry_compensation(
        &self,
        session: &Self::ControlSession,
        target: &Self::ActionTarget,
        authorization: diport::SagaOperatorAuthorization<
            diport::saga_operator_action::RetryCompensation,
        >,
    ) -> anyhow::Result<diport::SagaOperatorCasOutcome>;
    async fn repair(
        &self,
        target: &Self::ActionTarget,
        authorization: diport::SagaOperatorAuthorization<diport::saga_operator_action::Repair>,
    ) -> anyhow::Result<eventexec::SagaOperatorRecoveryOutcome>;
    async fn terminate(
        &self,
        session: &Self::ControlSession,
        target: &Self::ActionTarget,
        authorization: diport::SagaOperatorAuthorization<diport::saga_operator_action::Terminate>,
    ) -> anyhow::Result<diport::SagaOperatorCasOutcome>;
    async fn shutdown_target(&self, target: Self::ActionTarget) -> anyhow::Result<()>;
    async fn shutdown_control(&self, session: Self::ControlSession) -> anyhow::Result<()>;
}

struct ProductionSagaCommandRuntime<'a> {
    config: crate::config::SnapshotConfig<'a>,
    operator: OperatorRuntimeCapability<'a>,
    grants: Vec<SagaOperatorGrant>,
}

struct ProductionSagaTarget {
    target: eventexec::SagaRuntimeOperatorTarget,
    resources: Vec<Box<diport::DynManagedResource<'static>>>,
}

impl SagaCommandRuntime for ProductionSagaCommandRuntime<'_> {
    type ControlSession = PgSagaOperatorDeps;
    type ActionTarget = ProductionSagaTarget;

    fn now(&self) -> std::time::SystemTime {
        diport::Clock::now(&crate::support::SystemClock)
    }

    async fn connect_control(&self) -> anyhow::Result<Self::ControlSession> {
        PgSagaOperatorDeps::connect(&build_pg_saga_operator_config(self.config)?)
            .await
            .context("setup Saga operator postgres capability")
    }

    async fn prepare_target(&self, parsed: &SagaCliArgs) -> anyhow::Result<Self::ActionTarget> {
        let (writer, reader, audit_admin) = build_pg_saga_serving_configs(self.config)?;
        let mut plan = crate::plan::RuntimePlan::bundled(self.config)?;
        let serving = PgRuntimeDeps::connect_serving(
            &writer,
            &reader,
            audit_admin.as_ref(),
            plan.projection_capture(),
        )
        .await
        .context("setup plan-selected Saga operator serving capabilities")?;
        plan.bind_workflow_runtime(std::iter::empty())
            .context("bind plan-selected Saga operator targets")?;
        let target =
            select_saga_operator_target(plan.workflow_runtime().sagas(), &parsed.identity)?;
        let config = postgres::PgRuntimeMonitorConfig::new(
            postgres::PgReadinessInterval::try_new(std::time::Duration::from_secs(30))
                .map_err(anyhow::Error::msg)
                .context("build Saga operator postgres readiness interval")?,
            postgres::PgRlsAttestationInterval::default(),
        );
        let (resources, _sampler) = serving.into_runtime_parts(config);
        Ok(ProductionSagaTarget { target, resources })
    }

    #[allow(clippy::too_many_arguments)]
    async fn audit(
        &self,
        session: &Self::ControlSession,
        target_tenant: rss_request_context::TenantId,
        subject: &str,
        action: &'static str,
        outcome: MaintenanceAuditOutcome<'_>,
        resource_id: &str,
        start_audit_id: &diport::SagaOperatorStartAuditId,
    ) -> anyhow::Result<()> {
        session
            .record_saga_maintenance_audit(
                subject,
                target_tenant,
                action,
                outcome,
                resource_id,
                start_audit_id.as_str(),
            )
            .await
            .context("record Saga operator audit")
    }

    async fn authenticate(
        &self,
        session: &Self::ControlSession,
        parsed: &SagaCliArgs,
    ) -> anyhow::Result<String> {
        let provider = build_operator_service_token_provider(self.config, self.operator, session)
            .context("Saga operator verifier")?;
        verified_service_maintenance_operator(
            parsed.operator_service_token.as_str(),
            parsed.operator_tenant,
            diport::DynPdp::from_ref(provider.as_ref()),
            "Saga maintenance",
        )
        .await
        .map(|proof| service_maintenance_operator_audit_subject(&proof).to_owned())
    }

    fn authorize(&self, parsed: &SagaCliArgs) -> anyhow::Result<()> {
        authorize_saga_operator(parsed, &self.grants)
    }

    async fn status(
        &self,
        target: &Self::ActionTarget,
        authorization: diport::SagaOperatorAuthorization<diport::saga_operator_action::Status>,
    ) -> anyhow::Result<diport::SagaOperatorStatusOutcome> {
        target
            .target
            .status(authorization)
            .await
            .map_err(Into::into)
    }

    async fn retry_compensation(
        &self,
        session: &Self::ControlSession,
        _target: &Self::ActionTarget,
        authorization: diport::SagaOperatorAuthorization<
            diport::saga_operator_action::RetryCompensation,
        >,
    ) -> anyhow::Result<diport::SagaOperatorCasOutcome> {
        session
            .retry_compensation(authorization)
            .await
            .map_err(Into::into)
    }

    async fn repair(
        &self,
        target: &Self::ActionTarget,
        authorization: diport::SagaOperatorAuthorization<diport::saga_operator_action::Repair>,
    ) -> anyhow::Result<eventexec::SagaOperatorRecoveryOutcome> {
        Ok(target.target.repair(authorization).await)
    }

    async fn terminate(
        &self,
        session: &Self::ControlSession,
        _target: &Self::ActionTarget,
        authorization: diport::SagaOperatorAuthorization<diport::saga_operator_action::Terminate>,
    ) -> anyhow::Result<diport::SagaOperatorCasOutcome> {
        session.terminate(authorization).await.map_err(Into::into)
    }

    async fn shutdown_target(&self, target: Self::ActionTarget) -> anyhow::Result<()> {
        let mut first_error = None;
        for resource in target.resources.iter().rev() {
            if let Err(error) = resource.shutdown().await
                && first_error.is_none()
            {
                first_error = Some(anyhow::Error::new(error));
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    async fn shutdown_control(&self, session: Self::ControlSession) -> anyhow::Result<()> {
        session
            .shutdown()
            .await
            .context("shutdown Saga operator control session")
    }
}

fn issue_authorization<A: diport::SagaOperatorAction>(
    parsed: &SagaCliArgs,
    evidence: A::Evidence,
    start_audit_id: diport::SagaOperatorStartAuditId,
) -> diport::SagaOperatorAuthorization<A> {
    diport::SagaOperatorAuthorization::issue(
        sagaauthmint::SagaOperatorMint::capability(),
        vocab::ServiceCallerDomain::MaintenanceOperator,
        parsed.identity.clone(),
        parsed.instance,
        evidence,
        start_audit_id,
    )
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SagaStatusTargetDto {
    tenant: String,
    owner: String,
    contract: String,
    saga_id: String,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SagaStatusDto {
    outcome: &'static str,
    target: SagaStatusTargetDto,
    status: Option<String>,
    operator_reason: Option<String>,
    definition_version: Option<String>,
    schema_digest: Option<String>,
    action_registry_generation: Option<String>,
    latest_journal_position: Option<u64>,
    has_effect_intent: Option<bool>,
    unresolved_at: Option<u64>,
    unresolved_age_seconds: Option<u64>,
    unresolved_age_state: Option<&'static str>,
}

fn status_target(parsed: &SagaCliArgs) -> SagaStatusTargetDto {
    SagaStatusTargetDto {
        tenant: parsed.instance.tenant().to_string(),
        owner: parsed.identity.owner().to_owned(),
        contract: parsed.identity.contract_id().as_str().to_owned(),
        saga_id: parsed.instance.saga_id().as_uuid().to_string(),
    }
}

fn status_summary(
    parsed: &SagaCliArgs,
    outcome: &diport::SagaOperatorStatusOutcome,
    now: std::time::SystemTime,
) -> anyhow::Result<serde_json::Value> {
    let target = status_target(parsed);
    let dto = match outcome {
        diport::SagaOperatorStatusOutcome::Found(snapshot) => {
            let record = snapshot.record();
            anyhow::ensure!(
                record.instance() == parsed.instance && record.identity() == &parsed.identity,
                "Saga status snapshot target drifted"
            );
            let unresolved_at = snapshot
                .unresolved_at()
                .map(|at| at.duration_since(std::time::UNIX_EPOCH))
                .transpose()
                .context("Saga unresolved_at predates the Unix epoch")?;
            let (unresolved_age_seconds, unresolved_age_state) = match snapshot.unresolved_at() {
                Some(at) => match now.duration_since(at) {
                    Ok(age) => (Some(age.as_secs()), Some("available")),
                    Err(_) => (None, Some("clock_skew")),
                },
                None => (None, None),
            };
            SagaStatusDto {
                outcome: "found",
                target,
                status: Some(record.status().as_str().to_owned()),
                operator_reason: record
                    .operator_reason()
                    .map(|reason| reason.as_str().to_owned()),
                definition_version: Some(record.definition().version().to_owned()),
                schema_digest: Some(record.definition().schema_digest().to_owned()),
                action_registry_generation: Some(
                    record.definition().action_registry_generation().to_owned(),
                ),
                latest_journal_position: snapshot
                    .latest_journal()
                    .map(|journal| journal.record().seq()),
                has_effect_intent: Some(snapshot.has_effect_intent()),
                unresolved_at: unresolved_at.map(|duration| duration.as_secs()),
                unresolved_age_seconds,
                unresolved_age_state,
            }
        }
        diport::SagaOperatorStatusOutcome::Missing => SagaStatusDto {
            outcome: "missing",
            target,
            status: None,
            operator_reason: None,
            definition_version: None,
            schema_digest: None,
            action_registry_generation: None,
            latest_journal_position: None,
            has_effect_intent: None,
            unresolved_at: None,
            unresolved_age_seconds: None,
            unresolved_age_state: None,
        },
        diport::SagaOperatorStatusOutcome::IdentityConflict => SagaStatusDto {
            outcome: "identity_conflict",
            target,
            status: None,
            operator_reason: None,
            definition_version: None,
            schema_digest: None,
            action_registry_generation: None,
            latest_journal_position: None,
            has_effect_intent: None,
            unresolved_at: None,
            unresolved_age_seconds: None,
            unresolved_age_state: None,
        },
        _ => anyhow::bail!("unsupported Saga status outcome"),
    };
    serde_json::to_value(dto).context("serialize Saga status DTO")
}

struct SagaActionSummary {
    value: serde_json::Value,
    accepted: bool,
}

impl SagaActionSummary {
    fn accepted(value: serde_json::Value) -> Self {
        Self {
            value,
            accepted: true,
        }
    }
}

fn cas_summary(outcome: diport::SagaOperatorCasOutcome) -> anyhow::Result<SagaActionSummary> {
    let accepted = outcome == diport::SagaOperatorCasOutcome::Applied;
    let label = match outcome {
        diport::SagaOperatorCasOutcome::Applied => "applied",
        diport::SagaOperatorCasOutcome::Busy => "busy",
        diport::SagaOperatorCasOutcome::Missing => "missing",
        diport::SagaOperatorCasOutcome::IdentityConflict => "identity_conflict",
        diport::SagaOperatorCasOutcome::StaleStatus(_) => "stale_status",
        diport::SagaOperatorCasOutcome::StaleReason(_) => "stale_reason",
        diport::SagaOperatorCasOutcome::StaleJournal => "stale_journal",
        diport::SagaOperatorCasOutcome::EffectAlreadyStarted => "effect_already_started",
        diport::SagaOperatorCasOutcome::LeaseLost => "lease_lost",
        _ => anyhow::bail!("unsupported Saga operator CAS outcome"),
    };
    Ok(SagaActionSummary {
        value: serde_json::json!({"outcome": label}),
        accepted,
    })
}

fn recovery_summary(
    outcome: eventexec::SagaOperatorRecoveryOutcome,
) -> anyhow::Result<SagaActionSummary> {
    let accepted = outcome == eventexec::SagaOperatorRecoveryOutcome::Repaired;
    let label = match outcome {
        eventexec::SagaOperatorRecoveryOutcome::Repaired => "repaired",
        eventexec::SagaOperatorRecoveryOutcome::StillUnknown => "still_unknown",
        eventexec::SagaOperatorRecoveryOutcome::Busy => "busy",
        eventexec::SagaOperatorRecoveryOutcome::Missing => "missing",
        eventexec::SagaOperatorRecoveryOutcome::IdentityConflict => "identity_conflict",
        eventexec::SagaOperatorRecoveryOutcome::StaleStatus(_) => "stale_status",
        eventexec::SagaOperatorRecoveryOutcome::StaleReason(_) => "stale_reason",
        eventexec::SagaOperatorRecoveryOutcome::Interrupted { .. } => "interrupted",
        _ => anyhow::bail!("unsupported Saga operator recovery outcome"),
    };
    Ok(SagaActionSummary {
        value: serde_json::json!({"outcome": label}),
        accepted,
    })
}

async fn execute_saga_action<R: SagaCommandRuntime>(
    runtime: &R,
    session: &R::ControlSession,
    target: &R::ActionTarget,
    parsed: &SagaCliArgs,
    start_audit_id: &diport::SagaOperatorStartAuditId,
) -> anyhow::Result<SagaActionSummary> {
    match parsed.action {
        SagaOperatorCliAction::Status => {
            let authorization = issue_authorization::<diport::saga_operator_action::Status>(
                parsed,
                (),
                start_audit_id.clone(),
            );
            let outcome = runtime.status(target, authorization).await?;
            status_summary(parsed, &outcome, runtime.now()).map(SagaActionSummary::accepted)
        }
        SagaOperatorCliAction::RetryCompensation => {
            let status_authorization = issue_authorization::<diport::saga_operator_action::Status>(
                parsed,
                (),
                start_audit_id.clone(),
            );
            let status = runtime.status(target, status_authorization).await?;
            let diport::SagaOperatorStatusOutcome::Found(snapshot) = status else {
                anyhow::bail!("retry-compensation cannot hydrate the exact Saga journal basis")
            };
            anyhow::ensure!(
                snapshot.record().instance() == parsed.instance
                    && snapshot.record().identity() == &parsed.identity,
                "Saga status snapshot target drifted before retry-compensation"
            );
            let journal = snapshot
                .latest_journal()
                .context("Saga has no latest journal basis")?;
            anyhow::ensure!(
                Some(journal.record().seq()) == parsed.expected_journal_position,
                "Saga latest journal position does not match --expected-journal-position"
            );
            let evidence = diport::SagaRetryCompensationExpectation::new(
                journal.clone(),
                parsed
                    .reason_text
                    .clone()
                    .context("--reason-text is required")?,
                parsed
                    .change_ticket
                    .clone()
                    .context("--change-ticket is required")?,
            )?;
            let authorization = issue_authorization::<
                diport::saga_operator_action::RetryCompensation,
            >(parsed, evidence, start_audit_id.clone());
            cas_summary(
                runtime
                    .retry_compensation(session, target, authorization)
                    .await?,
            )
        }
        SagaOperatorCliAction::Repair => {
            let evidence = diport::SagaOperatorRepairExpectation::new(
                parsed
                    .expected_reason
                    .context("--expected-reason is required")?,
                parsed
                    .reason_text
                    .clone()
                    .context("--reason-text is required")?,
                parsed
                    .change_ticket
                    .clone()
                    .context("--change-ticket is required")?,
            );
            let authorization = issue_authorization::<diport::saga_operator_action::Repair>(
                parsed,
                evidence,
                start_audit_id.clone(),
            );
            recovery_summary(runtime.repair(target, authorization).await?)
        }
        SagaOperatorCliAction::Terminate => {
            let evidence = diport::SagaTerminateExpectation::new(
                parsed
                    .reason_text
                    .clone()
                    .context("--reason-text is required")?,
                parsed
                    .change_ticket
                    .clone()
                    .context("--change-ticket is required")?,
            );
            let authorization = issue_authorization::<diport::saga_operator_action::Terminate>(
                parsed,
                evidence,
                start_audit_id.clone(),
            );
            cas_summary(runtime.terminate(session, target, authorization).await?)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SagaExitDisposition {
    Success,
    Failure,
}

impl SagaExitDisposition {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
        }
    }
}

/// Closed report that preserves the action fact independently from audit and cleanup facts.
pub struct SagaCommandReport {
    action: &'static str,
    summary: serde_json::Value,
    action_accepted: bool,
    audit_recorded: bool,
    cleanup_succeeded: bool,
    runtime_cleanup_succeeded: Option<bool>,
    diagnostic: Option<anyhow::Error>,
}

impl SagaCommandReport {
    fn from_action(action: SagaOperatorCliAction, summary: SagaActionSummary) -> Self {
        Self {
            action: action.as_str(),
            summary: summary.value,
            action_accepted: summary.accepted,
            audit_recorded: false,
            cleanup_succeeded: false,
            runtime_cleanup_succeeded: None,
            diagnostic: None,
        }
    }

    fn record_diagnostic(&mut self, error: anyhow::Error) {
        if self.diagnostic.is_none() {
            self.diagnostic = Some(error);
        }
    }

    fn settle_runtime_cleanup(&mut self, result: anyhow::Result<()>) {
        self.runtime_cleanup_succeeded = Some(result.is_ok());
        if let Err(error) = result {
            self.record_diagnostic(error);
        }
    }

    fn exit_disposition(&self) -> SagaExitDisposition {
        if self.action_accepted
            && self.audit_recorded
            && self.cleanup_succeeded
            && self.runtime_cleanup_succeeded != Some(false)
        {
            SagaExitDisposition::Success
        } else {
            SagaExitDisposition::Failure
        }
    }

    fn to_json(&self) -> serde_json::Value {
        let mut report = match &self.summary {
            serde_json::Value::Object(fields) => fields.clone(),
            summary => serde_json::Map::from_iter([("summary".to_owned(), summary.clone())]),
        };
        report.insert("action".to_owned(), self.action.into());
        report.insert(
            "auditOutcome".to_owned(),
            if self.audit_recorded {
                "recorded"
            } else {
                "failed"
            }
            .into(),
        );
        report.insert(
            "cleanupOutcome".to_owned(),
            if self.cleanup_succeeded {
                "success"
            } else {
                "failure"
            }
            .into(),
        );
        report.insert(
            "runtimeCleanupOutcome".to_owned(),
            match self.runtime_cleanup_succeeded {
                Some(true) => "success",
                Some(false) => "failure",
                None => "notRun",
            }
            .into(),
        );
        report.insert(
            "exitDisposition".to_owned(),
            self.exit_disposition().as_str().into(),
        );
        serde_json::Value::Object(report)
    }

    fn exit_result(&self) -> anyhow::Result<()> {
        if self.exit_disposition() == SagaExitDisposition::Success {
            return Ok(());
        }
        let detail = self.diagnostic.as_ref().map_or_else(
            || "action was rejected".to_owned(),
            |error| format!("{error:#}"),
        );
        anyhow::bail!(
            "Saga operator {} failed after reporting outcome: {detail}",
            self.action
        )
    }
}

#[allow(clippy::cognitive_complexity)]
async fn execute_prepared_saga_command_with_runtime<R: SagaCommandRuntime>(
    parsed: SagaCliArgs,
    runtime: &R,
) -> anyhow::Result<SagaCommandReport> {
    let start_audit_id =
        diport::SagaOperatorStartAuditId::parse(format!("saga-operator-{}", uuid::Uuid::new_v4()))?;
    let resource_id = saga_resource_id(&parsed);
    let session = runtime.connect_control().await?;
    if let Err(error) = runtime
        .audit(
            &session,
            parsed.instance.tenant(),
            UNVERIFIED_SAGA_OPERATOR,
            parsed.action.start_action(),
            MaintenanceAuditOutcome::Success,
            &resource_id,
            &start_audit_id,
        )
        .await
    {
        let _ = runtime.shutdown_control(session).await;
        return Err(error);
    }
    let subject = match runtime.authenticate(&session, &parsed).await {
        Ok(subject) => subject,
        Err(error) => {
            let audit = runtime
                .audit(
                    &session,
                    parsed.instance.tenant(),
                    UNVERIFIED_SAGA_OPERATOR,
                    parsed.action.finish_action(),
                    MaintenanceAuditOutcome::Failure {
                        reason: "operator_auth",
                    },
                    &resource_id,
                    &start_audit_id,
                )
                .await;
            let cleanup = runtime.shutdown_control(session).await;
            let _ = audit;
            let _ = cleanup;
            return Err(error).context("authenticate Saga operator");
        }
    };
    if let Err(error) = runtime.authorize(&parsed) {
        let audit = runtime
            .audit(
                &session,
                parsed.instance.tenant(),
                &subject,
                parsed.action.finish_action(),
                MaintenanceAuditOutcome::Failure {
                    reason: "operator_authorization",
                },
                &resource_id,
                &start_audit_id,
            )
            .await;
        let cleanup = runtime.shutdown_control(session).await;
        let _ = audit;
        let _ = cleanup;
        return Err(error).context("authorize Saga operator");
    }
    let target = match runtime.prepare_target(&parsed).await {
        Ok(target) => target,
        Err(error) => {
            let audit = runtime
                .audit(
                    &session,
                    parsed.instance.tenant(),
                    &subject,
                    parsed.action.finish_action(),
                    MaintenanceAuditOutcome::Failure {
                        reason: "operator_provider_config",
                    },
                    &resource_id,
                    &start_audit_id,
                )
                .await;
            let cleanup = runtime.shutdown_control(session).await;
            let _ = audit;
            let _ = cleanup;
            return Err(error).context("prepare Saga operator target");
        }
    };
    let action = parsed.action;
    let command_result =
        execute_saga_action(runtime, &session, &target, &parsed, &start_audit_id).await;
    let mut report = match command_result {
        Ok(summary) => SagaCommandReport::from_action(action, summary),
        Err(error) => {
            let mut report = SagaCommandReport::from_action(
                action,
                SagaActionSummary {
                    value: serde_json::json!({"outcome": "execution_error"}),
                    accepted: false,
                },
            );
            report.record_diagnostic(error);
            report
        }
    };
    let outcome = if report.action_accepted {
        MaintenanceAuditOutcome::Success
    } else {
        MaintenanceAuditOutcome::Failure {
            reason: "run_error",
        }
    };
    let audit_result = runtime
        .audit(
            &session,
            parsed.instance.tenant(),
            &subject,
            parsed.action.finish_action(),
            outcome,
            &resource_id,
            &start_audit_id,
        )
        .await;
    report.audit_recorded = audit_result.is_ok();
    if let Err(error) = audit_result {
        report.record_diagnostic(error);
    }
    let target_cleanup = runtime.shutdown_target(target).await;
    let control_cleanup = runtime.shutdown_control(session).await;
    report.cleanup_succeeded = target_cleanup.is_ok() && control_cleanup.is_ok();
    if let Err(error) = target_cleanup {
        report.record_diagnostic(error);
    }
    if let Err(error) = control_cleanup {
        report.record_diagnostic(error);
    }
    Ok(report)
}

/// Dispatch through the exact plan-selected typed Saga operator target.
#[cfg(feature = "operator-cli")]
pub async fn run_saga_command(
    command: PreparedSagaCommand,
    runtime_inputs: OperatorRuntimeInputs,
) -> anyhow::Result<()> {
    let command_result = {
        let config = runtime_inputs.config();
        let operator = runtime_inputs.operator_capability();
        // Keep grant-load failures inside command_result so shutdown_runtime still runs.
        match load_saga_operator_grants_from_snapshot(config, operator) {
            Ok(grants) => {
                let runtime = ProductionSagaCommandRuntime {
                    config,
                    operator,
                    grants,
                };
                execute_prepared_saga_command_with_runtime(command.0, &runtime).await
            }
            Err(error) => Err(error),
        }
    };
    let runtime_cleanup = super::shutdown_runtime(runtime_inputs).await;
    let mut report = match command_result {
        Ok(report) => report,
        Err(error) => {
            runtime_cleanup?;
            return Err(error);
        }
    };
    report.settle_runtime_cleanup(runtime_cleanup);
    println!("{}", serde_json::to_string(&report.to_json())?);
    report.exit_result()
}

#[cfg(all(test, feature = "operator-cli"))]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::operator::cli_clap::assert_operator_cli_err;
    use std::io::Cursor;
    use std::sync::Mutex;

    const OPERATOR_TENANT: &str = "018f5d8a-7b6c-7d2e-8a1b-1234567890aa";
    const TENANT: &str = "018f5d8a-7b6c-7d2e-8a1b-1234567890ab";
    const SAGA_ID: &str = "018f5d8a-7b6c-7d2e-8a1b-1234567890ac";

    fn argv(action: &str, tail: &[&str]) -> Vec<String> {
        let mut args = vec![
            "sagas",
            action,
            "--operator-service-token-stdin",
            "--operator-tenant",
            OPERATOR_TENANT,
            "--tenant",
            TENANT,
            "--owner",
            "orders",
            "--contract",
            "orders.checkout",
            "--saga-id",
            SAGA_ID,
        ];
        args.extend_from_slice(tail);
        args.into_iter().map(str::to_owned).collect()
    }

    #[derive(Default)]
    struct MockRuntime {
        status: Mutex<Option<diport::SagaOperatorStatusOutcome>>,
        retry_outcome: Mutex<Option<diport::SagaOperatorCasOutcome>>,
        repair_outcome: Mutex<Option<eventexec::SagaOperatorRecoveryOutcome>>,
        terminate_outcome: Mutex<Option<diport::SagaOperatorCasOutcome>>,
        calls: Mutex<Vec<String>>,
        audits: Mutex<Vec<(String, &'static str)>>,
        authorized: bool,
        target_prepare_fails: bool,
        finish_audit_fails: bool,
        target_shutdown_fails: bool,
    }

    impl SagaCommandRuntime for MockRuntime {
        type ControlSession = ();
        type ActionTarget = ();

        fn now(&self) -> std::time::SystemTime {
            std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(145)
        }

        async fn connect_control(&self) -> anyhow::Result<Self::ControlSession> {
            self.calls
                .lock()
                .unwrap()
                .push("connect_control".to_owned());
            Ok(())
        }

        async fn prepare_target(
            &self,
            _parsed: &SagaCliArgs,
        ) -> anyhow::Result<Self::ActionTarget> {
            self.calls.lock().unwrap().push("prepare_target".to_owned());
            anyhow::ensure!(!self.target_prepare_fails, "target provider failed");
            Ok(())
        }

        async fn audit(
            &self,
            _session: &Self::ControlSession,
            target_tenant: rss_request_context::TenantId,
            _subject: &str,
            action: &'static str,
            outcome: MaintenanceAuditOutcome<'_>,
            _resource_id: &str,
            _start_audit_id: &diport::SagaOperatorStartAuditId,
        ) -> anyhow::Result<()> {
            assert_eq!(target_tenant.to_string(), TENANT);
            self.calls.lock().unwrap().push(action.to_owned());
            let outcome = match outcome {
                MaintenanceAuditOutcome::Success => "success",
                MaintenanceAuditOutcome::Failure { .. } => "failure",
            };
            self.audits
                .lock()
                .unwrap()
                .push((action.to_owned(), outcome));
            anyhow::ensure!(
                !(self.finish_audit_fails && action.ends_with(".finish")),
                "finish audit failed"
            );
            Ok(())
        }

        async fn authenticate(
            &self,
            _session: &Self::ControlSession,
            _parsed: &SagaCliArgs,
        ) -> anyhow::Result<String> {
            self.calls.lock().unwrap().push("authenticate".to_owned());
            Ok("maintenance-operator".to_owned())
        }

        fn authorize(&self, _parsed: &SagaCliArgs) -> anyhow::Result<()> {
            anyhow::ensure!(self.authorized, "denied");
            self.calls.lock().unwrap().push("authorize".to_owned());
            Ok(())
        }

        async fn status(
            &self,
            _target: &Self::ActionTarget,
            authorization: diport::SagaOperatorAuthorization<diport::saga_operator_action::Status>,
        ) -> anyhow::Result<diport::SagaOperatorStatusOutcome> {
            assert_eq!(authorization.instance().tenant().to_string(), TENANT);
            self.calls.lock().unwrap().push("status".to_owned());
            Ok(self
                .status
                .lock()
                .unwrap()
                .clone()
                .unwrap_or(diport::SagaOperatorStatusOutcome::Missing))
        }

        async fn retry_compensation(
            &self,
            _session: &Self::ControlSession,
            _target: &Self::ActionTarget,
            authorization: diport::SagaOperatorAuthorization<
                diport::saga_operator_action::RetryCompensation,
            >,
        ) -> anyhow::Result<diport::SagaOperatorCasOutcome> {
            assert_eq!(authorization.evidence().journal().record().seq(), 9);
            assert_eq!(
                authorization.evidence().reason_text().as_str(),
                "dependency restored"
            );
            assert_eq!(
                authorization.evidence().change_ticket().as_str(),
                "CHG-1926"
            );
            self.calls.lock().unwrap().push("retry".to_owned());
            Ok(self
                .retry_outcome
                .lock()
                .unwrap()
                .take()
                .unwrap_or(diport::SagaOperatorCasOutcome::Applied))
        }

        async fn repair(
            &self,
            _target: &Self::ActionTarget,
            authorization: diport::SagaOperatorAuthorization<diport::saga_operator_action::Repair>,
        ) -> anyhow::Result<eventexec::SagaOperatorRecoveryOutcome> {
            assert_eq!(
                authorization.evidence().reason(),
                diport::SagaOperatorRepairReason::ForwardOutcomeUnknown
            );
            self.calls.lock().unwrap().push("repair".to_owned());
            Ok(self
                .repair_outcome
                .lock()
                .unwrap()
                .take()
                .unwrap_or(eventexec::SagaOperatorRecoveryOutcome::Repaired))
        }

        async fn terminate(
            &self,
            _session: &Self::ControlSession,
            _target: &Self::ActionTarget,
            authorization: diport::SagaOperatorAuthorization<
                diport::saga_operator_action::Terminate,
            >,
        ) -> anyhow::Result<diport::SagaOperatorCasOutcome> {
            assert_eq!(
                authorization.evidence().reason_text().as_str(),
                "request withdrawn"
            );
            self.calls.lock().unwrap().push("terminate".to_owned());
            Ok(self
                .terminate_outcome
                .lock()
                .unwrap()
                .take()
                .unwrap_or(diport::SagaOperatorCasOutcome::Applied))
        }

        async fn shutdown_target(&self, _target: Self::ActionTarget) -> anyhow::Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push("shutdown_target".to_owned());
            anyhow::ensure!(!self.target_shutdown_fails, "target shutdown failed");
            Ok(())
        }

        async fn shutdown_control(&self, _session: Self::ControlSession) -> anyhow::Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push("shutdown_control".to_owned());
            Ok(())
        }
    }

    async fn run_saga_command_with_runtime<R: SagaCommandRuntime>(
        args: &[String],
        stdin: &mut impl std::io::BufRead,
        runtime: &R,
    ) -> anyhow::Result<SagaCommandReport> {
        execute_prepared_saga_command_with_runtime(parse_saga_args(args, stdin)?, runtime).await
    }

    fn compensation_failed_status() -> anyhow::Result<diport::SagaOperatorStatusOutcome> {
        let tenant = rss_request_context::TenantId::parse(TENANT)?;
        let instance = consistency::SagaInstanceRef::new(
            tenant,
            consistency::SagaId::new(uuid::Uuid::parse_str(SAGA_ID)?),
        )?;
        let identity = diport::SagaWorkerIdentity::new(
            "orders",
            diport::SagaContractId::parse("orders.checkout")?,
        )?;
        let definition = consistency::SagaDefinitionIdentity::new(
            "orders.checkout",
            "v1",
            format!("sha256:{}", "1".repeat(64)),
            format!("sha256:{}", "2".repeat(64)),
        )?;
        let record = consistency::SagaInstanceRecord::new(
            instance,
            consistency::SagaInstanceStatus::CompensationFailed,
            identity,
            definition,
        )?;
        let journal = diport::SagaOperatorJournalExpectation::new(
            consistency::SagaJournalRecord::replayed(
                9,
                vocab::StepName::parse("charge")?,
                consistency::SagaJournalStatus::CompensationFailed,
            ),
            consistency::SagaAttempt::new(2)?,
            consistency::SagaIdempotencyKey::from_storage(
                [7; 32],
                consistency::SagaEffectPhase::Compensation,
            ),
        )?;
        Ok(diport::SagaOperatorStatusOutcome::Found(Box::new(
            diport::SagaOperatorStatusSnapshot::new(
                record,
                Some(journal),
                true,
                Some(std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(100)),
            ),
        )))
    }

    #[test]
    fn parses_closed_status_and_mutation_evidence() -> anyhow::Result<()> {
        let status = parse_saga_args(&argv("status", &[]), &mut Cursor::new("secret\n"))?;
        assert_eq!(status.action, SagaOperatorCliAction::Status);
        assert_eq!(status.operator_tenant.to_string(), OPERATOR_TENANT);

        let retry = parse_saga_args(
            &argv(
                "retry-compensation",
                &[
                    "--expected-journal-position",
                    "9",
                    "--reason-text",
                    "dependency restored",
                    "--change-ticket",
                    "CHG-1926",
                ],
            ),
            &mut Cursor::new("secret\n"),
        )?;
        assert_eq!(retry.expected_journal_position, Some(9));
        assert_eq!(
            retry.reason_text.as_ref().map(|reason| reason.as_str()),
            Some("dependency restored")
        );

        let repair = parse_saga_args(
            &argv(
                "repair",
                &[
                    "--expected-reason",
                    "forward_outcome_unknown",
                    "--reason-text",
                    "provider evidence reviewed",
                    "--change-ticket",
                    "CHG-1926",
                ],
            ),
            &mut Cursor::new("secret\n"),
        )?;
        assert_eq!(
            repair.expected_reason,
            Some(diport::SagaOperatorRepairReason::ForwardOutcomeUnknown)
        );

        parse_saga_args(
            &argv(
                "terminate",
                &[
                    "--reason-text",
                    "request withdrawn",
                    "--change-ticket",
                    "CHG-1926",
                ],
            ),
            &mut Cursor::new("secret\n"),
        )?;
        Ok(())
    }

    #[test]
    fn rejects_legacy_or_open_ended_commands_and_token_carriers() {
        for candidate in [
            argv("start", &[]),
            argv("cancel", &[]),
            argv("resume", &[]),
            argv("list", &[]),
            argv("delete", &[]),
            argv("redrive", &[]),
            vec!["saga".to_owned(), "status".to_owned()],
            argv("status", &["--operator-service-token", "secret"]),
        ] {
            let err = parse_saga_args(&candidate, &mut Cursor::new("secret\n"))
                .err()
                .unwrap_or_else(|| unreachable!("legacy/open-ended argv must fail closed"));
            assert_operator_cli_err(&err, "sagas");
            let message = err.to_string();
            assert!(
                !message.contains("secret"),
                "diagnostic leaked token material: {message}"
            );
        }
    }

    #[test]
    fn action_set_audit_names_are_exact() {
        let expected = [
            (
                "status",
                "saga.operator.status.start",
                "saga.operator.status.finish",
            ),
            (
                "retry-compensation",
                "saga.operator.retry-compensation.start",
                "saga.operator.retry-compensation.finish",
            ),
            (
                "repair",
                "saga.operator.repair.start",
                "saga.operator.repair.finish",
            ),
            (
                "terminate",
                "saga.operator.terminate.start",
                "saga.operator.terminate.finish",
            ),
        ];
        assert_eq!(SagaOperatorCliAction::ALL.len(), expected.len());
        for (name, start, finish) in expected {
            let action = SagaOperatorCliAction::parse(name).unwrap();
            let descriptor = action.descriptor();
            assert_eq!(descriptor.name, name);
            assert_eq!(descriptor.start_action, start);
            assert_eq!(descriptor.finish_action, finish);
        }
        // Evidence requirements are clap-owned: status rejects mutation flags; mutations require them.
        assert!(
            parse_saga_args(
                &argv("status", &["--reason-text", "why"]),
                &mut Cursor::new("secret\n")
            )
            .is_err()
        );
        assert!(
            parse_saga_args(
                &argv(
                    "terminate",
                    &[
                        "--reason-text",
                        "request withdrawn",
                        "--change-ticket",
                        "CHG-1926"
                    ],
                ),
                &mut Cursor::new("secret\n"),
            )
            .is_ok()
        );
    }

    #[test]
    fn help_and_invalid_argv_do_not_consume_stdin() -> anyhow::Result<()> {
        for args in [
            vec!["sagas".to_owned(), "--help".to_owned()],
            vec![
                "sagas".to_owned(),
                "terminate".to_owned(),
                "--help".to_owned(),
            ],
        ] {
            let mut stdin = Cursor::new("must-not-be-read\n");
            let SagaCommandPreparation::Help =
                clap_cli::prepare_saga_command_with_stdin(&args, &mut stdin)?
            else {
                panic!("help argv must not execute");
            };
            assert_eq!(stdin.position(), 0);
        }

        for args in [
            vec!["sagas".to_owned(), "unknown".to_owned()],
            argv("status", &["--unknown"]),
            argv("terminate", &["--reason-text", "why"]),
        ] {
            let mut stdin = Cursor::new("must-not-be-read\n");
            let Err(err) = clap_cli::prepare_saga_command_with_stdin(&args, &mut stdin) else {
                panic!("invalid argv must fail closed");
            };
            assert_eq!(stdin.position(), 0);
            assert_operator_cli_err(&err, "sagas");
        }
        Ok(())
    }

    #[test]
    #[allow(non_snake_case)] // 验收过滤名含 SECRET_BAIT
    fn saga_args_SECRET_BAIT_too_many_values_is_redacted() {
        let mut stdin = Cursor::new("must-not-be-read\n");
        let Err(err) = clap_cli::prepare_saga_command_with_stdin(
            &[
                "sagas".to_owned(),
                "status".to_owned(),
                "--operator-service-token-stdin=SECRET_BAIT".to_owned(),
                "--operator-tenant".to_owned(),
                OPERATOR_TENANT.to_owned(),
                "--tenant".to_owned(),
                TENANT.to_owned(),
                "--owner".to_owned(),
                "orders".to_owned(),
                "--contract".to_owned(),
                "orders.checkout".to_owned(),
                "--saga-id".to_owned(),
                SAGA_ID.to_owned(),
            ],
            &mut stdin,
        ) else {
            panic!("TooManyValues must fail closed");
        };
        assert_eq!(stdin.position(), 0);
        assert_operator_cli_err(&err, "sagas");
    }

    #[test]
    #[allow(non_snake_case)] // 验收过滤名含 SECRET_BAIT
    fn saga_args_SECRET_BAIT_invalid_value_is_redacted() {
        let err = parse_saga_args(
            &[
                "sagas".to_owned(),
                "status".to_owned(),
                "--operator-service-token-stdin".to_owned(),
                "--operator-tenant=SECRET_BAIT".to_owned(),
                "--tenant".to_owned(),
                TENANT.to_owned(),
                "--owner".to_owned(),
                "orders".to_owned(),
                "--contract".to_owned(),
                "orders.checkout".to_owned(),
                "--saga-id".to_owned(),
                SAGA_ID.to_owned(),
            ],
            &mut Cursor::new("must-not-be-read\n"),
        )
        .err()
        .unwrap_or_else(|| unreachable!("InvalidValue must fail closed"));
        assert_operator_cli_err(&err, "sagas");
    }

    #[test]
    fn saga_args_clap_outcomes_are_action_specific() {
        // status rejects mutation evidence; mutations require their evidence flags.
        let status_rejects_reason = parse_saga_args(
            &argv("status", &["--reason-text", "why"]),
            &mut Cursor::new("secret\n"),
        )
        .err()
        .unwrap_or_else(|| unreachable!("status must reject --reason-text"));
        assert_operator_cli_err(&status_rejects_reason, "sagas");

        assert!(
            parse_saga_args(
                &argv(
                    "terminate",
                    &[
                        "--reason-text",
                        "request withdrawn",
                        "--change-ticket",
                        "CHG-1926"
                    ],
                ),
                &mut Cursor::new("secret\n"),
            )
            .is_ok(),
            "terminate with evidence must parse"
        );

        let retry_missing_position = parse_saga_args(
            &argv(
                "retry-compensation",
                &["--reason-text", "why", "--change-ticket", "CHG-1"],
            ),
            &mut Cursor::new("secret\n"),
        )
        .err()
        .unwrap_or_else(|| unreachable!("retry-compensation requires --expected-journal-position"));
        assert_operator_cli_err(&retry_missing_position, "sagas");

        let repair_missing_reason_text = parse_saga_args(
            &argv(
                "repair",
                &[
                    "--expected-reason",
                    "forward_outcome_unknown",
                    "--change-ticket",
                    "CHG-1",
                ],
            ),
            &mut Cursor::new("secret\n"),
        )
        .err()
        .unwrap_or_else(|| unreachable!("repair requires --reason-text"));
        assert_operator_cli_err(&repair_missing_reason_text, "sagas");

        let terminate_missing_ticket = parse_saga_args(
            &argv("terminate", &["--reason-text", "why"]),
            &mut Cursor::new("secret\n"),
        )
        .err()
        .unwrap_or_else(|| unreachable!("terminate requires --change-ticket"));
        assert_operator_cli_err(&terminate_missing_ticket, "sagas");

        let unknown = parse_saga_args(
            &{
                let mut args = argv("status", &[]);
                args[1] = "bogus".to_owned();
                args
            },
            &mut Cursor::new("secret\n"),
        )
        .err()
        .unwrap_or_else(|| unreachable!("unknown subcommand must fail"));
        assert_operator_cli_err(&unknown, "sagas");
    }

    #[test]
    fn saga_args_fail_closed_on_missing_invalid_or_unknown_flags() {
        let cases = [
            ("missing subcommand", vec!["sagas".to_owned()]),
            ("unknown subcommand", {
                let mut args = argv("status", &[]);
                args[1] = "bogus".to_owned();
                args
            }),
            (
                "missing operator token",
                vec![
                    "sagas".to_owned(),
                    "status".to_owned(),
                    "--operator-tenant".to_owned(),
                    OPERATOR_TENANT.to_owned(),
                    "--tenant".to_owned(),
                    TENANT.to_owned(),
                    "--owner".to_owned(),
                    "orders".to_owned(),
                    "--contract".to_owned(),
                    "orders.checkout".to_owned(),
                    "--saga-id".to_owned(),
                    SAGA_ID.to_owned(),
                ],
            ),
            ("missing operator tenant", {
                let mut args = argv("status", &[]);
                let pos = args.iter().position(|a| a == "--operator-tenant").unwrap();
                args.drain(pos..=pos + 1);
                args
            }),
            ("invalid tenant", {
                let mut args = argv("status", &[]);
                let pos = args.iter().position(|a| a == "--tenant").unwrap();
                args[pos + 1] = "not-a-uuid".to_owned();
                args
            }),
            ("unknown flag", argv("status", &["--bogus"])),
            ("duplicate token flag", {
                let mut args = argv("status", &[]);
                args.insert(3, "--operator-service-token-stdin".to_owned());
                args
            }),
            (
                "terminate missing change-ticket",
                argv("terminate", &["--reason-text", "why"]),
            ),
        ];

        for (name, candidate) in cases {
            let err = parse_saga_args(&candidate, &mut Cursor::new("secret\n"))
                .err()
                .unwrap_or_else(|| unreachable!("case must fail: {name}"));
            assert_operator_cli_err(&err, "sagas");
        }
    }

    #[test]
    fn status_dto_is_camel_case_target_bound_and_preserves_unresolved_age() -> anyhow::Result<()> {
        let parsed = parse_saga_args(&argv("status", &[]), &mut Cursor::new("secret\n"))?;
        let summary = status_summary(
            &parsed,
            &compensation_failed_status()?,
            std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(145),
        )?;
        assert_eq!(summary["outcome"], "found");
        assert_eq!(summary["target"]["tenant"], TENANT);
        assert_eq!(summary["target"]["owner"], "orders");
        assert_eq!(summary["target"]["contract"], "orders.checkout");
        assert_eq!(summary["target"]["sagaId"], SAGA_ID);
        assert_eq!(summary["latestJournalPosition"], 9);
        assert_eq!(summary["hasEffectIntent"], true);
        assert_eq!(summary["unresolvedAt"], 100);
        assert_eq!(summary["unresolvedAgeSeconds"], 45);
        assert_eq!(summary["unresolvedAgeState"], "available");
        for snake_case in [
            "operator_reason",
            "latest_journal_position",
            "has_effect_intent",
            "unresolved_at",
            "unresolved_age_seconds",
            "unresolved_age_state",
        ] {
            assert!(summary.get(snake_case).is_none());
        }
        Ok(())
    }

    #[test]
    fn future_unresolved_timestamp_is_a_closed_clock_skew_observation() -> anyhow::Result<()> {
        let parsed = parse_saga_args(&argv("status", &[]), &mut Cursor::new("secret\n"))?;
        let summary = status_summary(
            &parsed,
            &compensation_failed_status()?,
            std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(99),
        )?;
        assert_eq!(summary["unresolvedAgeState"], "clock_skew");
        assert!(summary["unresolvedAgeSeconds"].is_null());
        Ok(())
    }

    #[test]
    fn rejects_missing_or_cross_action_mutation_evidence() {
        for candidate in [
            argv(
                "retry-compensation",
                &["--reason-text", "why", "--change-ticket", "CHG-1"],
            ),
            argv(
                "repair",
                &[
                    "--expected-reason",
                    "receipt_missing",
                    "--reason-text",
                    "why",
                    "--change-ticket",
                    "CHG-1",
                ],
            ),
            argv(
                "repair",
                &[
                    "--expected-reason",
                    "forward_outcome_unknown",
                    "--change-ticket",
                    "CHG-1",
                ],
            ),
            argv("terminate", &["--reason-text", "why"]),
            argv("status", &["--reason-text", "why"]),
        ] {
            assert!(parse_saga_args(&candidate, &mut Cursor::new("secret\n")).is_err());
        }
    }

    #[tokio::test]
    async fn retry_executes_typed_status_hydration_and_audited_action() -> anyhow::Result<()> {
        let runtime = MockRuntime {
            status: Mutex::new(Some(compensation_failed_status()?)),
            authorized: true,
            ..MockRuntime::default()
        };
        let report = run_saga_command_with_runtime(
            &argv(
                "retry-compensation",
                &[
                    "--expected-journal-position",
                    "9",
                    "--reason-text",
                    "dependency restored",
                    "--change-ticket",
                    "CHG-1926",
                ],
            ),
            &mut Cursor::new("secret\n"),
            &runtime,
        )
        .await?;
        let output = report.to_json();
        assert_eq!(output["outcome"], "applied");
        assert_eq!(output["exitDisposition"], "success");
        assert_eq!(
            *runtime.calls.lock().unwrap(),
            [
                "connect_control",
                "saga.operator.retry-compensation.start",
                "authenticate",
                "authorize",
                "prepare_target",
                "status",
                "retry",
                "saga.operator.retry-compensation.finish",
                "shutdown_target",
                "shutdown_control",
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn target_provider_failure_after_control_connect_is_finish_audited() {
        let runtime = MockRuntime {
            target_prepare_fails: true,
            authorized: true,
            ..MockRuntime::default()
        };
        let result = run_saga_command_with_runtime(
            &argv("status", &[]),
            &mut Cursor::new("secret\n"),
            &runtime,
        )
        .await;

        assert!(result.is_err());
        assert_eq!(
            *runtime.audits.lock().unwrap(),
            [
                ("saga.operator.status.start".to_owned(), "success"),
                ("saga.operator.status.finish".to_owned(), "failure"),
            ]
        );
        assert_eq!(
            *runtime.calls.lock().unwrap(),
            [
                "connect_control",
                "saga.operator.status.start",
                "authenticate",
                "authorize",
                "prepare_target",
                "saga.operator.status.finish",
                "shutdown_control",
            ]
        );
    }

    #[tokio::test]
    async fn non_applied_cas_and_recovery_fail_exit_and_finish_audit() -> anyhow::Result<()> {
        let terminate = MockRuntime {
            terminate_outcome: Mutex::new(Some(diport::SagaOperatorCasOutcome::Busy)),
            authorized: true,
            ..MockRuntime::default()
        };
        let terminate_report = run_saga_command_with_runtime(
            &argv(
                "terminate",
                &[
                    "--reason-text",
                    "request withdrawn",
                    "--change-ticket",
                    "CHG-1926",
                ],
            ),
            &mut Cursor::new("secret\n"),
            &terminate,
        )
        .await?;
        let terminate_result = terminate_report.to_json();
        assert_eq!(terminate_result["outcome"], "busy");
        assert_eq!(terminate_result["exitDisposition"], "failure");
        assert!(terminate_report.exit_result().is_err());
        {
            let terminate_audits = terminate.audits.lock().unwrap();
            assert!(
                terminate_audits
                    .contains(&("saga.operator.terminate.finish".to_owned(), "failure"))
            );
            assert!(
                !terminate_audits
                    .contains(&("saga.operator.terminate.finish".to_owned(), "success"))
            );
        }

        let repair = MockRuntime {
            repair_outcome: Mutex::new(Some(eventexec::SagaOperatorRecoveryOutcome::StillUnknown)),
            authorized: true,
            ..MockRuntime::default()
        };
        let repair_report = run_saga_command_with_runtime(
            &argv(
                "repair",
                &[
                    "--expected-reason",
                    "forward_outcome_unknown",
                    "--reason-text",
                    "provider evidence reviewed",
                    "--change-ticket",
                    "CHG-1926",
                ],
            ),
            &mut Cursor::new("secret\n"),
            &repair,
        )
        .await?;
        let repair_result = repair_report.to_json();
        assert_eq!(repair_result["outcome"], "still_unknown");
        assert_eq!(repair_result["exitDisposition"], "failure");
        assert!(repair_report.exit_result().is_err());
        let repair_audits = repair.audits.lock().unwrap();
        assert!(repair_audits.contains(&("saga.operator.repair.finish".to_owned(), "failure")));
        assert!(!repair_audits.contains(&("saga.operator.repair.finish".to_owned(), "success")));
        Ok(())
    }

    #[tokio::test]
    async fn applied_outcome_survives_finish_audit_and_cleanup_failure() -> anyhow::Result<()> {
        let runtime = MockRuntime {
            finish_audit_fails: true,
            target_shutdown_fails: true,
            authorized: true,
            ..MockRuntime::default()
        };
        let report = run_saga_command_with_runtime(
            &argv(
                "terminate",
                &[
                    "--reason-text",
                    "request withdrawn",
                    "--change-ticket",
                    "CHG-1926",
                ],
            ),
            &mut Cursor::new("secret\n"),
            &runtime,
        )
        .await?;
        let output = report.to_json();
        assert_eq!(output["outcome"], "applied");
        assert_eq!(output["auditOutcome"], "failed");
        assert_eq!(output["cleanupOutcome"], "failure");
        assert_eq!(output["exitDisposition"], "failure");
        assert!(report.exit_result().is_err());
        Ok(())
    }

    #[test]
    fn grants_fence_action_tenant_owner_and_contract() -> anyhow::Result<()> {
        let parsed = parse_saga_args(&argv("status", &[]), &mut Cursor::new("secret\n"))?;
        let exact = parse_saga_operator_grants(&format!("status|{TENANT}|orders|orders.checkout"))?;
        authorize_saga_operator(&parsed, &exact)?;
        for raw in [
            format!("repair|{TENANT}|orders|orders.checkout"),
            format!("status|{OPERATOR_TENANT}|orders|orders.checkout"),
            format!("status|{TENANT}|billing|orders.checkout"),
            format!("status|{TENANT}|orders|orders.other"),
        ] {
            assert!(authorize_saga_operator(&parsed, &parse_saga_operator_grants(&raw)?).is_err());
        }
        Ok(())
    }

    #[test]
    fn inactive_assembly_has_no_saga_operator_target() -> anyhow::Result<()> {
        let snapshot = crate::config::test_snapshot(&[
            ("RSS_PRIMARY_TOKEN_PROFILE", "rss-access"),
            ("RSS_ADMIN_TOKEN_PROFILE", "rss-access"),
            ("RSS_INTERNAL_AUTH_SCHEME", "mtls"),
        ])?;
        let mut plan = crate::plan::RuntimePlan::bundled(snapshot.view())?;
        plan.bind_workflow_runtime(std::iter::empty())?;
        let identity = diport::SagaWorkerIdentity::new(
            "orders",
            diport::SagaContractId::parse("orders.checkout")?,
        )?;
        let Err(error) = select_saga_operator_target(plan.workflow_runtime().sagas(), &identity)
        else {
            panic!("disabled Saga must not expose an operator target");
        };
        assert!(format!("{error:#}").contains("not active in the assembly plan"));
        Ok(())
    }
}
