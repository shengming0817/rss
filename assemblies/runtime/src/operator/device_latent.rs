#![forbid(unused_imports)]
#![forbid(clippy::wildcard_imports)]

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use super::build_operator_service_token_provider;
use super::projection::{
    next_cli_value, service_maintenance_operator_audit_subject, set_cli_arg_once,
    verified_service_maintenance_operator,
};
use super::service_token::{
    OperatorServiceToken, parse_operator_service_token_stdin_args,
    read_operator_service_token_stdin,
};
use diport::{ManagedResource as _, MetricsExporter as _};
use identity::ports::device_certificate::{
    AuthorizedDeviceCertificateStatusRead, DeviceCertificateStatusStore as _,
};
use postgres::{
    DeviceLatentInspectionAuditOutcome, PgDeviceLatentInspectionDeps, PgDeviceLatentOperatorDeps,
    UNVERIFIED_DEVICE_LATENT_OPERATOR,
};

use crate::infra::pg::{build_pg_device_latent_read_config, build_pg_migrator_config};
use crate::phase::OperatorRuntimeInputs;

const STATUS_CONTRACT_ID: &str =
    generated::http::identity_v2::device_certificate_status_get::CONTRACT_ID;
const STATUS_PERMISSION: vocab::RoutePermissionId =
    vocab::RoutePermissionId::IdentityDeviceCertificateStatusRead;
/// Whether `rss` was invoked for the read-only DeviceLatent inspection surface.
#[must_use]
pub fn is_device_latent_inspection_command(args: &[String]) -> bool {
    matches!(args, [namespace, action, ..]
        if namespace == "device-latent" && (action == "inspect" || action == "--help"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeviceLatentInspectionOutput {
    Json,
    Prometheus,
}

#[derive(Debug)]
struct DeviceLatentInspectionArgv {
    tenant: vocab::TenantId,
    device_id: ids::DeviceId,
    output: DeviceLatentInspectionOutput,
}

/// Fully validated and secret-bearing input for one DeviceLatent inspection.
#[derive(Debug)]
pub struct DeviceLatentInspectionCommand {
    operator_service_token: OperatorServiceToken,
    tenant: vocab::TenantId,
    device_id: ids::DeviceId,
    output: DeviceLatentInspectionOutput,
}

/// Local preparation result resolved before runtime configuration or providers are opened.
pub enum DeviceLatentCommandPreparation {
    /// Stable command usage requested without consuming stdin.
    Help(&'static str),
    /// Exact command whose complete argv was validated before stdin was consumed.
    Execute(DeviceLatentInspectionCommand),
}

pub(super) fn device_latent_inspection_usage() -> &'static str {
    "usage: rss device-latent inspect --operator-service-token-stdin --tenant <uuid> --device-id <lowercase-hyphenated-non-nil-uuid> [--output json|prometheus]"
}

fn parse_device_latent_inspection_argv(
    args: &[String],
) -> anyhow::Result<DeviceLatentInspectionArgv> {
    let args = parse_operator_service_token_stdin_args(args)?;
    anyhow::ensure!(
        matches!(args.as_slice(), [namespace, action, ..] if namespace == "device-latent" && action == "inspect"),
        device_latent_inspection_usage()
    );
    let mut tenant = None;
    let mut device_id = None;
    let mut output = None;
    let mut it = args[2..].iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--tenant" => {
                let value = next_cli_value(&mut it, "--tenant")?;
                let parsed = vocab::TenantId::parse(value)
                    .map_err(|_| anyhow::anyhow!("--tenant must be a canonical tenant UUID"))?;
                set_cli_arg_once(&mut tenant, "--tenant", parsed)?;
            }
            "--device-id" => {
                let value = next_cli_value(&mut it, "--device-id")?;
                let parsed = ids::DeviceId::parse(value).map_err(|_| {
                    anyhow::anyhow!("--device-id must be a lowercase hyphenated non-nil UUID")
                })?;
                anyhow::ensure!(
                    !parsed.as_uuid().is_nil()
                        && parsed.as_uuid().hyphenated().to_string() == value,
                    "--device-id must be a lowercase hyphenated non-nil UUID"
                );
                set_cli_arg_once(&mut device_id, "--device-id", parsed)?;
            }
            "--output" => {
                let value = next_cli_value(&mut it, "--output")?;
                let parsed = match value {
                    "json" => DeviceLatentInspectionOutput::Json,
                    "prometheus" => DeviceLatentInspectionOutput::Prometheus,
                    _ => anyhow::bail!("--output must be json or prometheus"),
                };
                set_cli_arg_once(&mut output, "--output", parsed)?;
            }
            _ => anyhow::bail!(device_latent_inspection_usage()),
        }
    }
    Ok(DeviceLatentInspectionArgv {
        tenant: tenant.ok_or_else(|| anyhow::anyhow!("--tenant is required"))?,
        device_id: device_id.ok_or_else(|| anyhow::anyhow!("--device-id is required"))?,
        output: output.unwrap_or(DeviceLatentInspectionOutput::Json),
    })
}

fn prepare_device_latent_command_with_reader(
    args: &[String],
    stdin: &mut impl std::io::BufRead,
) -> anyhow::Result<DeviceLatentCommandPreparation> {
    if matches!(args, [namespace, help] if namespace == "device-latent" && help == "--help")
        || matches!(args, [namespace, action, help]
            if namespace == "device-latent" && action == "inspect" && help == "--help")
    {
        return Ok(DeviceLatentCommandPreparation::Help(
            device_latent_inspection_usage(),
        ));
    }
    let parsed = parse_device_latent_inspection_argv(args)?;
    let operator_service_token = read_operator_service_token_stdin(stdin)?;
    Ok(DeviceLatentCommandPreparation::Execute(
        DeviceLatentInspectionCommand {
            operator_service_token,
            tenant: parsed.tenant,
            device_id: parsed.device_id,
            output: parsed.output,
        },
    ))
}

/// Validate the complete DeviceLatent command and consume stdin only after argv is closed.
pub fn prepare_device_latent_command(
    args: &[String],
) -> anyhow::Result<DeviceLatentCommandPreparation> {
    let stdin = std::io::stdin();
    prepare_device_latent_command_with_reader(args, &mut stdin.lock())
}

struct ExactDeviceCertificateStatusAuthorizer {
    tenant: vocab::TenantId,
    device_id: String,
}

impl httpserve::RouteAuthorizer for ExactDeviceCertificateStatusAuthorizer {
    fn authorize<'a>(
        &'a self,
        request: httpserve::RouteAuthorizationRequest,
    ) -> Pin<Box<dyn Future<Output = httpserve::RouteAuthorizationDecision> + Send + 'a>> {
        Box::pin(async move {
            let exact = request.contract_id == STATUS_CONTRACT_ID
                && request.permission == STATUS_PERMISSION
                && request.tenant_id == Some(self.tenant)
                && request.principal_kind == vocab::PrincipalKind::Service
                && request.principal_id == vocab::ServiceCallerDomain::MaintenanceOperator.as_str()
                && request.federated_permissions.is_none()
                && request
                    .resource
                    .as_ref()
                    .is_some_and(|resource| resource.id() == self.device_id);
            if exact {
                httpserve::RouteAuthorizationDecision::Allow
            } else {
                httpserve::RouteAuthorizationDecision::Deny
            }
        })
    }
}

pub(super) async fn authorize_device_certificate_status_read(
    parsed: &DeviceLatentInspectionCommand,
    operator: &authn::VerifiedMaintenanceServiceOperator,
) -> anyhow::Result<AuthorizedDeviceCertificateStatusRead> {
    anyhow::ensure!(
        operator.principal().kind() == vocab::PrincipalKind::Service
            && operator.principal().service_caller_domain()
                == Some(vocab::ServiceCallerDomain::MaintenanceOperator),
        "device-latent inspection requires a verified maintenance service operator"
    );
    let device_id = parsed.device_id.as_uuid().hyphenated().to_string();
    let resource = httpserve::RouteResource::new(device_id.clone())
        .ok_or_else(|| anyhow::anyhow!("device-latent inspection resource is invalid"))?;
    let evidence = httpserve::Authenticated::new_service(
        authmint::AuthenticatedMint::capability(),
        parsed.tenant,
        vocab::ServiceCallerDomain::MaintenanceOperator,
    );
    let authorizer: Arc<dyn httpserve::RouteAuthorizer> =
        Arc::new(ExactDeviceCertificateStatusAuthorizer {
            tenant: parsed.tenant,
            device_id,
        });
    let subject = httpserve::authorize_subject_for_permission(
        Some(authorizer),
        Some(&evidence),
        STATUS_CONTRACT_ID,
        STATUS_PERMISSION,
        parsed.tenant,
        Some(resource),
    )
    .await
    .ok_or_else(|| anyhow::anyhow!("device-latent inspection authorization failed"))?;
    AuthorizedDeviceCertificateStatusRead::from_authorized_subject(&subject, parsed.device_id)
        .map_err(|_| anyhow::anyhow!("device-latent inspection authorization failed"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(super) enum DeviceLatentInspectionError {
    #[error("device-latent inspection failed: configuration")]
    Configuration,
    #[error("device-latent inspection failed: storage")]
    Storage,
    #[error("device-latent inspection failed: operator provider")]
    OperatorProvider,
    #[error("device-latent inspection failed: operator authentication")]
    OperatorAuthentication,
    #[error("device-latent inspection failed: operator authorization")]
    OperatorAuthorization,
    #[error("device-latent inspection failed: status not found")]
    NotFound,
    #[error("device-latent inspection failed: status projection")]
    Projection,
    #[error("device-latent inspection failed: output")]
    Output,
    #[error("device-latent inspection failed: audit")]
    Audit,
    #[error("device-latent inspection failed: shutdown")]
    Shutdown,
}

fn close_error<T, E>(
    result: Result<T, E>,
    closed: DeviceLatentInspectionError,
) -> Result<T, DeviceLatentInspectionError> {
    result.map_err(|_| closed)
}

const fn audit_outcome_for(
    error: DeviceLatentInspectionError,
) -> DeviceLatentInspectionAuditOutcome {
    match error {
        DeviceLatentInspectionError::Configuration
        | DeviceLatentInspectionError::Storage
        | DeviceLatentInspectionError::Audit => DeviceLatentInspectionAuditOutcome::Storage,
        DeviceLatentInspectionError::OperatorProvider => {
            DeviceLatentInspectionAuditOutcome::OperatorProviderConfig
        }
        DeviceLatentInspectionError::OperatorAuthentication => {
            DeviceLatentInspectionAuditOutcome::OperatorAuthentication
        }
        DeviceLatentInspectionError::OperatorAuthorization => {
            DeviceLatentInspectionAuditOutcome::OperatorAuthorization
        }
        DeviceLatentInspectionError::NotFound => DeviceLatentInspectionAuditOutcome::NotFound,
        DeviceLatentInspectionError::Projection => DeviceLatentInspectionAuditOutcome::Projection,
        DeviceLatentInspectionError::Output => DeviceLatentInspectionAuditOutcome::Output,
        DeviceLatentInspectionError::Shutdown => DeviceLatentInspectionAuditOutcome::Shutdown,
    }
}

fn resolve_finish_audit_outcome(
    command_result: &Result<
        String,
        (
            DeviceLatentInspectionAuditOutcome,
            DeviceLatentInspectionError,
        ),
    >,
    reader_shutdown_ok: bool,
) -> (
    DeviceLatentInspectionAuditOutcome,
    Result<String, DeviceLatentInspectionError>,
) {
    if !reader_shutdown_ok {
        return (
            DeviceLatentInspectionAuditOutcome::Shutdown,
            Err(DeviceLatentInspectionError::Shutdown),
        );
    }
    match command_result {
        Ok(output) => (
            DeviceLatentInspectionAuditOutcome::Success,
            Ok(output.clone()),
        ),
        Err((outcome, error)) => (*outcome, Err(*error)),
    }
}

/// Prepare the one-shot runtime behind a fixed, source-free DeviceLatent error surface.
pub fn prepare_device_latent_runtime() -> anyhow::Result<OperatorRuntimeInputs> {
    close_error(
        super::prepare_runtime(),
        DeviceLatentInspectionError::Configuration,
    )
    .map_err(anyhow::Error::from)
}

/// Flush one-shot runtime resources behind the same fixed shutdown error surface.
pub async fn shutdown_device_latent_runtime(
    runtime_inputs: OperatorRuntimeInputs,
) -> anyhow::Result<()> {
    close_error(
        super::shutdown_runtime(runtime_inputs).await,
        DeviceLatentInspectionError::Shutdown,
    )
    .map_err(anyhow::Error::from)
}

async fn render_device_latent_output(
    output: DeviceLatentInspectionOutput,
    evidence: &identity::ports::device_certificate::DeviceCertificateStatusEvidence,
) -> Result<String, DeviceLatentInspectionError> {
    match output {
        DeviceLatentInspectionOutput::Json => {
            let response = close_error(
                evidence.to_wire_response(),
                DeviceLatentInspectionError::Projection,
            )?;
            render_device_latent_json(&response)
        }
        DeviceLatentInspectionOutput::Prometheus => {
            let observation = close_error(
                evidence.observation(),
                DeviceLatentInspectionError::Projection,
            )?;
            render_device_latent_prometheus(observation).await
        }
    }
}

fn render_device_latent_json(
    response: &generated::http::identity_v2::device_certificate_status_get::IdentityDeviceCertificateStatusGetResponse,
) -> Result<String, DeviceLatentInspectionError> {
    close_error(
        serde_json::to_string(response),
        DeviceLatentInspectionError::Output,
    )
}

async fn render_device_latent_prometheus(
    observation: observ::DeviceLatentObservation,
) -> Result<String, DeviceLatentInspectionError> {
    let exporter = close_error(
        prometheus::PromExporter::install(),
        DeviceLatentInspectionError::Output,
    )?;
    observation.record();
    let rendered = exporter.render();
    close_error(
        exporter.shutdown().await,
        DeviceLatentInspectionError::Shutdown,
    )?;
    Ok(rendered)
}

/// Test seam for DeviceLatent inspection orchestration.
#[allow(async_fn_in_trait)]
pub(super) trait DeviceLatentInspectionRuntime {
    type OperatorSession;
    type ReaderSession;

    /// Connect the maintenance operator owner used for durable audit.
    async fn connect_operator(
        &self,
    ) -> Result<Self::OperatorSession, DeviceLatentInspectionError>;

    /// Connect the dedicated tenant-scoped status reader.
    async fn connect_reader(&self) -> Result<Self::ReaderSession, DeviceLatentInspectionError>;

    /// Record the fixed, identifier-free start audit.
    async fn record_start_audit(
        &self,
        operator: &Self::OperatorSession,
    ) -> Result<(), DeviceLatentInspectionError>;

    /// Record the fixed, identifier-free terminal audit.
    async fn record_finish_audit(
        &self,
        operator: &Self::OperatorSession,
        operator_subject: &str,
        outcome: DeviceLatentInspectionAuditOutcome,
    ) -> Result<(), DeviceLatentInspectionError>;

    /// Authenticate, authorize, inspect, and render one closed payload-free output.
    async fn inspect_and_render(
        &self,
        operator: &Self::OperatorSession,
        reader: &Self::ReaderSession,
        parsed: &DeviceLatentInspectionCommand,
        audit_subject: &mut String,
    ) -> Result<
        String,
        (
            DeviceLatentInspectionAuditOutcome,
            DeviceLatentInspectionError,
        ),
    >;

    /// Close the dedicated tenant-reader session.
    async fn shutdown_reader(
        &self,
        reader: Self::ReaderSession,
    ) -> Result<(), DeviceLatentInspectionError>;

    /// Close the maintenance operator session.
    async fn shutdown_operator(
        &self,
        operator: Self::OperatorSession,
    ) -> Result<(), DeviceLatentInspectionError>;
}

struct ProductionDeviceLatentInspectionRuntime<'a> {
    runtime_inputs: &'a OperatorRuntimeInputs,
}

impl DeviceLatentInspectionRuntime for ProductionDeviceLatentInspectionRuntime<'_> {
    type OperatorSession = PgDeviceLatentOperatorDeps;
    type ReaderSession = PgDeviceLatentInspectionDeps;

    async fn connect_operator(
        &self,
    ) -> Result<Self::OperatorSession, DeviceLatentInspectionError> {
        let migrator_config = close_error(
            build_pg_migrator_config(self.runtime_inputs.config()),
            DeviceLatentInspectionError::Configuration,
        )?;
        close_error(
            PgDeviceLatentOperatorDeps::connect(&migrator_config).await,
            DeviceLatentInspectionError::Storage,
        )
    }

    async fn connect_reader(&self) -> Result<Self::ReaderSession, DeviceLatentInspectionError> {
        let reader_config = close_error(
            build_pg_device_latent_read_config(self.runtime_inputs.config()),
            DeviceLatentInspectionError::Configuration,
        )?;
        close_error(
            PgDeviceLatentInspectionDeps::connect(&reader_config).await,
            DeviceLatentInspectionError::Storage,
        )
    }

    async fn record_start_audit(
        &self,
        operator: &Self::OperatorSession,
    ) -> Result<(), DeviceLatentInspectionError> {
        close_error(
            operator.record_start_audit().await,
            DeviceLatentInspectionError::Audit,
        )
    }

    async fn record_finish_audit(
        &self,
        operator: &Self::OperatorSession,
        operator_subject: &str,
        outcome: DeviceLatentInspectionAuditOutcome,
    ) -> Result<(), DeviceLatentInspectionError> {
        close_error(
            operator
                .record_finish_audit(operator_subject, outcome)
                .await,
            DeviceLatentInspectionError::Audit,
        )
    }

    async fn inspect_and_render(
        &self,
        operator: &Self::OperatorSession,
        reader: &Self::ReaderSession,
        parsed: &DeviceLatentInspectionCommand,
        audit_subject: &mut String,
    ) -> Result<
        String,
        (
            DeviceLatentInspectionAuditOutcome,
            DeviceLatentInspectionError,
        ),
    > {
        let provider = close_error(
            build_operator_service_token_provider(
                self.runtime_inputs.config(),
                self.runtime_inputs.operator_capability(),
                operator,
            ),
            DeviceLatentInspectionError::OperatorProvider,
        )
        .map_err(|error| (audit_outcome_for(error), error))?;
        let proof = verified_service_maintenance_operator(
            parsed.operator_service_token.as_str(),
            parsed.tenant,
            diport::DynPdp::from_ref(provider.as_ref()),
            "DeviceLatent inspection",
        )
        .await
        .map_err(|_| {
            (
                DeviceLatentInspectionAuditOutcome::OperatorAuthentication,
                DeviceLatentInspectionError::OperatorAuthentication,
            )
        })?;
        *audit_subject = service_maintenance_operator_audit_subject(&proof).to_owned();
        let authorization = authorize_device_certificate_status_read(parsed, &proof)
            .await
            .map_err(|_| {
                (
                    DeviceLatentInspectionAuditOutcome::OperatorAuthorization,
                    DeviceLatentInspectionError::OperatorAuthorization,
                )
            })?;
        let evidence = reader
            .status_store()
            .inspect(authorization)
            .await
            .map_err(|_| {
                (
                    DeviceLatentInspectionAuditOutcome::Storage,
                    DeviceLatentInspectionError::Storage,
                )
            })?
            .ok_or((
                DeviceLatentInspectionAuditOutcome::NotFound,
                DeviceLatentInspectionError::NotFound,
            ))?;
        render_device_latent_output(parsed.output, &evidence)
            .await
            .map_err(|error| (audit_outcome_for(error), error))
    }

    async fn shutdown_reader(
        &self,
        reader: Self::ReaderSession,
    ) -> Result<(), DeviceLatentInspectionError> {
        close_error(reader.shutdown().await, DeviceLatentInspectionError::Shutdown)
    }

    async fn shutdown_operator(
        &self,
        operator: Self::OperatorSession,
    ) -> Result<(), DeviceLatentInspectionError> {
        close_error(
            operator.shutdown().await,
            DeviceLatentInspectionError::Shutdown,
        )
    }
}

/// Execute the exact authenticated, audited, read-only DeviceLatent inspection command.
pub async fn run_device_latent_inspection_command(
    parsed: DeviceLatentInspectionCommand,
    runtime_inputs: &OperatorRuntimeInputs,
) -> anyhow::Result<()> {
    let runtime = ProductionDeviceLatentInspectionRuntime { runtime_inputs };
    run_device_latent_inspection_command_with_runtime(parsed, &runtime)
        .await
        .map_err(anyhow::Error::from)
}

/// Runtime-injected DeviceLatent inspection orchestration used by production and tests.
pub(super) async fn run_device_latent_inspection_command_with_runtime<R>(
    parsed: DeviceLatentInspectionCommand,
    runtime: &R,
) -> Result<(), DeviceLatentInspectionError>
where
    R: DeviceLatentInspectionRuntime,
{
    let operator = runtime.connect_operator().await?;
    if runtime.record_start_audit(&operator).await.is_err() {
        runtime.shutdown_operator(operator).await.ok();
        return Err(DeviceLatentInspectionError::Audit);
    }
    let reader = match runtime.connect_reader().await {
        Ok(reader) => reader,
        Err(error) => {
            let outcome = audit_outcome_for(error);
            let audit_result = runtime
                .record_finish_audit(&operator, UNVERIFIED_DEVICE_LATENT_OPERATOR, outcome)
                .await;
            let shutdown_result = runtime.shutdown_operator(operator).await;
            close_error(audit_result, DeviceLatentInspectionError::Audit)?;
            close_error(shutdown_result, DeviceLatentInspectionError::Shutdown)?;
            return Err(error);
        }
    };

    let mut audit_subject = UNVERIFIED_DEVICE_LATENT_OPERATOR.to_owned();
    let command_result = runtime
        .inspect_and_render(&operator, &reader, &parsed, &mut audit_subject)
        .await;

    let reader_shutdown_ok = runtime.shutdown_reader(reader).await.is_ok();
    let (audit_outcome, output) =
        resolve_finish_audit_outcome(&command_result, reader_shutdown_ok);
    let audit_result = runtime
        .record_finish_audit(&operator, &audit_subject, audit_outcome)
        .await;
    let operator_shutdown = runtime.shutdown_operator(operator).await;
    close_error(audit_result, DeviceLatentInspectionError::Audit)?;
    match output {
        Ok(rendered) => {
            // Durable Success already required reader shutdown; operator teardown is best-effort.
            let _ = operator_shutdown;
            println!("{}", rendered.trim_end());
            Ok(())
        }
        Err(error) => {
            close_error(operator_shutdown, DeviceLatentInspectionError::Shutdown)?;
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::time::Duration;

    use super::{
        DeviceLatentCommandPreparation, DeviceLatentInspectionError, DeviceLatentInspectionOutput,
        audit_outcome_for, authorize_device_certificate_status_read, close_error,
        is_device_latent_inspection_command, prepare_device_latent_command_with_reader,
        render_device_latent_json, render_device_latent_prometheus, resolve_finish_audit_outcome,
    };
    use postgres::DeviceLatentInspectionAuditOutcome;

    const TARGET_TENANT: &str = "2f1c34ce-4a95-4c6e-b8ab-01bc28cc6f71";
    const DEVICE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| (*part).to_owned()).collect()
    }

    fn inspect_args(output: Option<&str>) -> Vec<String> {
        let mut argv = vec![
            "device-latent".to_owned(),
            "inspect".to_owned(),
            "--operator-service-token-stdin".to_owned(),
            "--tenant".to_owned(),
            TARGET_TENANT.to_owned(),
            "--device-id".to_owned(),
            DEVICE.to_owned(),
        ];
        if let Some(output) = output {
            argv.extend(["--output".to_owned(), output.to_owned()]);
        }
        argv
    }

    fn execute(argv: &[String]) -> anyhow::Result<super::DeviceLatentInspectionCommand> {
        let prepared = prepare_device_latent_command_with_reader(
            argv,
            &mut Cursor::new(b"opaque-service-token\n"),
        )?;
        match prepared {
            DeviceLatentCommandPreparation::Execute(command) => Ok(command),
            DeviceLatentCommandPreparation::Help(_) => {
                anyhow::bail!("expected executable command")
            }
        }
    }

    #[test]
    fn classifier_and_help_are_closed_before_runtime_preparation() -> anyhow::Result<()> {
        assert!(is_device_latent_inspection_command(&inspect_args(None)));
        assert!(is_device_latent_inspection_command(&args(&[
            "device-latent",
            "--help"
        ])));
        for rejected in [
            args(&["device-latent"]),
            args(&["device-latent", "resume"]),
            args(&["device-latent", "activate"]),
        ] {
            assert!(!is_device_latent_inspection_command(&rejected));
        }

        for help in [
            args(&["device-latent", "--help"]),
            args(&["device-latent", "inspect", "--help"]),
        ] {
            let mut stdin = Cursor::new(b"must-not-be-consumed");
            let prepared = prepare_device_latent_command_with_reader(&help, &mut stdin)?;
            assert!(matches!(prepared, DeviceLatentCommandPreparation::Help(_)));
            assert_eq!(stdin.position(), 0);
        }
        Ok(())
    }

    #[test]
    fn parser_defaults_to_json_and_accepts_the_closed_output_set() -> anyhow::Result<()> {
        for (requested, expected) in [
            (None, DeviceLatentInspectionOutput::Json),
            (Some("json"), DeviceLatentInspectionOutput::Json),
            (Some("prometheus"), DeviceLatentInspectionOutput::Prometheus),
        ] {
            let parsed = execute(&inspect_args(requested))?;
            assert_eq!(parsed.tenant.to_string(), TARGET_TENANT);
            assert_eq!(parsed.device_id.as_uuid().hyphenated().to_string(), DEVICE);
            assert_eq!(parsed.output, expected);
            assert!(!format!("{parsed:?}").contains("opaque-service-token"));
        }
        Ok(())
    }

    #[test]
    fn every_argv_failure_precedes_stdin_consumption() {
        let duplicate_tenant = {
            let mut argv = inspect_args(None);
            argv.extend(["--tenant".to_owned(), TARGET_TENANT.to_owned()]);
            argv
        };
        let duplicate_output = {
            let mut argv = inspect_args(Some("json"));
            argv.extend(["--output".to_owned(), "prometheus".to_owned()]);
            argv
        };
        let cases = [
            args(&["device-latent", "resume"]),
            args(&["device-latent", "inspect", "--operator-service-token-stdin"]),
            args(&[
                "device-latent",
                "inspect",
                "--operator-service-token-stdin",
                "--tenant",
                TARGET_TENANT,
                "--device-id",
                "550E8400-E29B-41D4-A716-446655440000",
            ]),
            args(&[
                "device-latent",
                "inspect",
                "--operator-service-token-stdin",
                "--tenant",
                TARGET_TENANT,
                "--device-id",
                "550e8400e29b41d4a716446655440000",
            ]),
            args(&[
                "device-latent",
                "inspect",
                "--operator-service-token-stdin",
                "--tenant",
                TARGET_TENANT,
                "--device-id",
                "00000000-0000-0000-0000-000000000000",
            ]),
            args(&[
                "device-latent",
                "inspect",
                "--operator-service-token-stdin",
                "--operator-tenant",
                TARGET_TENANT,
                "--tenant",
                TARGET_TENANT,
                "--device-id",
                DEVICE,
            ]),
            args(&[
                "device-latent",
                "inspect",
                "--operator-service-token-stdin",
                "--tenant",
                TARGET_TENANT,
                "--device-id",
                DEVICE,
                "--output",
                "text",
            ]),
            duplicate_tenant,
            duplicate_output,
        ];
        for invalid in cases {
            let mut stdin = Cursor::new(b"secret-must-remain-unread");
            assert!(prepare_device_latent_command_with_reader(&invalid, &mut stdin).is_err());
            assert_eq!(stdin.position(), 0, "stdin consumed for argv {invalid:?}");
        }
    }

    #[tokio::test]
    async fn exact_status_authorization_mints_the_single_tenant_device_receipt()
    -> anyhow::Result<()> {
        let proof = authn::test_support::maintenance_service_operator_proof();
        let parsed = execute(&inspect_args(None))?;
        let receipt = authorize_device_certificate_status_read(&parsed, &proof).await?;
        assert_eq!(receipt.scope().tenant().to_string(), TARGET_TENANT);
        assert_eq!(
            receipt.scope().device().as_uuid().hyphenated().to_string(),
            DEVICE
        );
        Ok(())
    }

    #[test]
    fn provider_failures_are_closed_without_source_or_target_text() {
        const SECRET: &str =
            "postgres://operator:password@db.internal/tenant 550e8400-e29b-41d4-a716-446655440000";
        for closed in [
            DeviceLatentInspectionError::Configuration,
            DeviceLatentInspectionError::Storage,
            DeviceLatentInspectionError::OperatorProvider,
            DeviceLatentInspectionError::OperatorAuthentication,
            DeviceLatentInspectionError::OperatorAuthorization,
            DeviceLatentInspectionError::NotFound,
            DeviceLatentInspectionError::Projection,
            DeviceLatentInspectionError::Output,
            DeviceLatentInspectionError::Audit,
            DeviceLatentInspectionError::Shutdown,
        ] {
            let closed_result = close_error::<(), _>(Err(anyhow::anyhow!(SECRET)), closed);
            assert!(closed_result.is_err(), "sentinel failure must stay failed");
            let Err(error) = closed_result else {
                continue;
            };
            let rendered = format!("{error:?} {error}");
            assert!(!rendered.contains(SECRET), "leaked source: {rendered}");
            assert!(!rendered.contains("postgres://"), "leaked DSN: {rendered}");
            assert!(!rendered.contains(DEVICE), "leaked target: {rendered}");
        }
    }

    #[tokio::test]
    async fn real_json_and_prometheus_outputs_are_closed_and_identifier_free() -> anyhow::Result<()>
    {
        use generated::http::identity_v2::device_certificate_status_get::{
            IdentityDeviceCertificateStatusGetData, IdentityDeviceCertificateStatusGetResponse,
        };

        let json = render_device_latent_json(&IdentityDeviceCertificateStatusGetResponse {
            data: IdentityDeviceCertificateStatusGetData {
                active_command: None,
                conditions: Vec::new(),
                desired_generation: 7,
                observed_generation: 4,
            },
        })?;
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&json)?,
            serde_json::json!({
                "data": {
                    "conditions": [],
                    "desiredGeneration": 7,
                    "observedGeneration": 4
                }
            })
        );

        let prometheus = render_device_latent_prometheus(observ::DeviceLatentObservation::new(
            3,
            Some(Duration::from_secs(11)),
            Some(Duration::from_secs(7)),
            Some(Duration::from_millis(250)),
        ))
        .await?;
        for family in observ::DeviceLatentMetric::ALL {
            assert!(prometheus.contains(family.name()), "missing {family:?}");
        }
        for output in [&json, &prometheus] {
            for forbidden in [
                "tenantId",
                "deviceId",
                "commandId",
                "command_id",
                "payload",
                "certificate",
                TARGET_TENANT,
                DEVICE,
            ] {
                assert!(!output.contains(forbidden), "leaked {forbidden}: {output}");
            }
        }
        Ok(())
    }

    #[test]
    fn closed_errors_map_to_exact_audit_outcomes() {
        let cases = [
            (
                DeviceLatentInspectionError::Configuration,
                DeviceLatentInspectionAuditOutcome::Storage,
            ),
            (
                DeviceLatentInspectionError::Storage,
                DeviceLatentInspectionAuditOutcome::Storage,
            ),
            (
                DeviceLatentInspectionError::OperatorProvider,
                DeviceLatentInspectionAuditOutcome::OperatorProviderConfig,
            ),
            (
                DeviceLatentInspectionError::OperatorAuthentication,
                DeviceLatentInspectionAuditOutcome::OperatorAuthentication,
            ),
            (
                DeviceLatentInspectionError::OperatorAuthorization,
                DeviceLatentInspectionAuditOutcome::OperatorAuthorization,
            ),
            (
                DeviceLatentInspectionError::NotFound,
                DeviceLatentInspectionAuditOutcome::NotFound,
            ),
            (
                DeviceLatentInspectionError::Projection,
                DeviceLatentInspectionAuditOutcome::Projection,
            ),
            (
                DeviceLatentInspectionError::Output,
                DeviceLatentInspectionAuditOutcome::Output,
            ),
            (
                DeviceLatentInspectionError::Audit,
                DeviceLatentInspectionAuditOutcome::Storage,
            ),
            (
                DeviceLatentInspectionError::Shutdown,
                DeviceLatentInspectionAuditOutcome::Shutdown,
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(audit_outcome_for(error), expected);
        }
    }

    #[test]
    fn finish_audit_success_requires_reader_shutdown_and_preserves_failure_outcomes() {
        let ok = Ok("payload".to_owned());
        let (outcome, result) = resolve_finish_audit_outcome(&ok, true);
        assert_eq!(outcome, DeviceLatentInspectionAuditOutcome::Success);
        assert_eq!(result.unwrap(), "payload");

        let (outcome, result) = resolve_finish_audit_outcome(&ok, false);
        assert_eq!(outcome, DeviceLatentInspectionAuditOutcome::Shutdown);
        assert!(matches!(result, Err(DeviceLatentInspectionError::Shutdown)));

        let failed = Err((
            DeviceLatentInspectionAuditOutcome::NotFound,
            DeviceLatentInspectionError::NotFound,
        ));
        let (outcome, result) = resolve_finish_audit_outcome(&failed, true);
        assert_eq!(outcome, DeviceLatentInspectionAuditOutcome::NotFound);
        assert!(matches!(result, Err(DeviceLatentInspectionError::NotFound)));

        let output_failed = Err((
            DeviceLatentInspectionAuditOutcome::Output,
            DeviceLatentInspectionError::Output,
        ));
        let (outcome, result) = resolve_finish_audit_outcome(&output_failed, false);
        assert_eq!(outcome, DeviceLatentInspectionAuditOutcome::Shutdown);
        assert!(matches!(result, Err(DeviceLatentInspectionError::Shutdown)));
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct FakeFinishAudit {
        subject: String,
        outcome: DeviceLatentInspectionAuditOutcome,
    }

    struct FakeDeviceLatentInspectionRuntime {
        start_audit: Result<(), DeviceLatentInspectionError>,
        connect_reader: Result<(), DeviceLatentInspectionError>,
        command: Result<
            String,
            (
                DeviceLatentInspectionAuditOutcome,
                DeviceLatentInspectionError,
            ),
        >,
        reader_shutdown: Result<(), DeviceLatentInspectionError>,
        operator_shutdown: Result<(), DeviceLatentInspectionError>,
        finish_audits: std::sync::Mutex<Vec<FakeFinishAudit>>,
        reader_shutdowns: std::sync::atomic::AtomicUsize,
        operator_shutdowns: std::sync::atomic::AtomicUsize,
        verified_subject: &'static str,
    }

    impl FakeDeviceLatentInspectionRuntime {
        fn success() -> Self {
            Self {
                start_audit: Ok(()),
                connect_reader: Ok(()),
                command: Ok(r#"{"data":{"conditions":[],"desiredGeneration":1,"observedGeneration":0}}"#.to_owned()),
                reader_shutdown: Ok(()),
                operator_shutdown: Ok(()),
                finish_audits: std::sync::Mutex::new(Vec::new()),
                reader_shutdowns: std::sync::atomic::AtomicUsize::new(0),
                operator_shutdowns: std::sync::atomic::AtomicUsize::new(0),
                verified_subject: "verified-device-latent-operator",
            }
        }

        fn with_command(
            command: Result<
                String,
                (
                    DeviceLatentInspectionAuditOutcome,
                    DeviceLatentInspectionError,
                ),
            >,
        ) -> Self {
            let mut runtime = Self::success();
            runtime.command = command;
            runtime
        }

        fn finish_audits(&self) -> Vec<FakeFinishAudit> {
            match self.finish_audits.lock() {
                Ok(records) => records.clone(),
                Err(poisoned) => poisoned.into_inner().clone(),
            }
        }
    }

    impl super::DeviceLatentInspectionRuntime for FakeDeviceLatentInspectionRuntime {
        type OperatorSession = ();
        type ReaderSession = ();

        async fn connect_operator(&self) -> Result<Self::OperatorSession, DeviceLatentInspectionError> {
            Ok(())
        }

        async fn connect_reader(&self) -> Result<Self::ReaderSession, DeviceLatentInspectionError> {
            self.connect_reader
        }

        async fn record_start_audit(
            &self,
            _operator: &Self::OperatorSession,
        ) -> Result<(), DeviceLatentInspectionError> {
            self.start_audit
        }

        async fn record_finish_audit(
            &self,
            _operator: &Self::OperatorSession,
            operator_subject: &str,
            outcome: DeviceLatentInspectionAuditOutcome,
        ) -> Result<(), DeviceLatentInspectionError> {
            let record = FakeFinishAudit {
                subject: operator_subject.to_owned(),
                outcome,
            };
            match self.finish_audits.lock() {
                Ok(mut records) => records.push(record),
                Err(poisoned) => poisoned.into_inner().push(record),
            }
            Ok(())
        }

        async fn inspect_and_render(
            &self,
            _operator: &Self::OperatorSession,
            _reader: &Self::ReaderSession,
            _parsed: &super::DeviceLatentInspectionCommand,
            audit_subject: &mut String,
        ) -> Result<
            String,
            (
                DeviceLatentInspectionAuditOutcome,
                DeviceLatentInspectionError,
            ),
        > {
            match &self.command {
                Ok(output) => {
                    *audit_subject = self.verified_subject.to_owned();
                    Ok(output.clone())
                }
                Err(error) => Err(*error),
            }
        }

        async fn shutdown_reader(
            &self,
            _reader: Self::ReaderSession,
        ) -> Result<(), DeviceLatentInspectionError> {
            self.reader_shutdowns
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.reader_shutdown
        }

        async fn shutdown_operator(
            &self,
            _operator: Self::OperatorSession,
        ) -> Result<(), DeviceLatentInspectionError> {
            self.operator_shutdowns
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.operator_shutdown
        }
    }

    async fn run_fake(
        runtime: &FakeDeviceLatentInspectionRuntime,
    ) -> Result<(), DeviceLatentInspectionError> {
        let parsed = execute(&inspect_args(None)).expect("fixture argv");
        super::run_device_latent_inspection_command_with_runtime(parsed, runtime).await
    }

    #[tokio::test]
    async fn fake_runtime_success_finishes_success_and_always_shuts_down() {
        let runtime = FakeDeviceLatentInspectionRuntime::success();
        assert!(run_fake(&runtime).await.is_ok());
        assert_eq!(
            runtime.finish_audits(),
            vec![FakeFinishAudit {
                subject: "verified-device-latent-operator".to_owned(),
                outcome: DeviceLatentInspectionAuditOutcome::Success,
            }]
        );
        assert_eq!(
            runtime
                .reader_shutdowns
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(
            runtime
                .operator_shutdowns
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn fake_runtime_not_found_finishes_not_found_and_shuts_down() {
        let runtime = FakeDeviceLatentInspectionRuntime::with_command(Err((
            DeviceLatentInspectionAuditOutcome::NotFound,
            DeviceLatentInspectionError::NotFound,
        )));
        assert!(matches!(
            run_fake(&runtime).await,
            Err(DeviceLatentInspectionError::NotFound)
        ));
        assert_eq!(
            runtime.finish_audits(),
            vec![FakeFinishAudit {
                subject: postgres::UNVERIFIED_DEVICE_LATENT_OPERATOR.to_owned(),
                outcome: DeviceLatentInspectionAuditOutcome::NotFound,
            }]
        );
        assert_eq!(
            runtime
                .reader_shutdowns
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(
            runtime
                .operator_shutdowns
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn fake_runtime_auth_and_storage_failures_finish_exact_outcomes() {
        for (command, expected) in [
            (
                Err((
                    DeviceLatentInspectionAuditOutcome::OperatorAuthentication,
                    DeviceLatentInspectionError::OperatorAuthentication,
                )),
                DeviceLatentInspectionError::OperatorAuthentication,
            ),
            (
                Err((
                    DeviceLatentInspectionAuditOutcome::OperatorAuthorization,
                    DeviceLatentInspectionError::OperatorAuthorization,
                )),
                DeviceLatentInspectionError::OperatorAuthorization,
            ),
            (
                Err((
                    DeviceLatentInspectionAuditOutcome::Storage,
                    DeviceLatentInspectionError::Storage,
                )),
                DeviceLatentInspectionError::Storage,
            ),
        ] {
            let runtime = FakeDeviceLatentInspectionRuntime::with_command(command);
            assert!(matches!(run_fake(&runtime).await, Err(error) if error == expected));
            assert_eq!(runtime.finish_audits()[0].outcome, audit_outcome_for(expected));
            assert_eq!(
                runtime
                    .reader_shutdowns
                    .load(std::sync::atomic::Ordering::Relaxed),
                1
            );
            assert_eq!(
                runtime
                    .operator_shutdowns
                    .load(std::sync::atomic::Ordering::Relaxed),
                1
            );
        }
    }

    #[tokio::test]
    async fn fake_runtime_start_audit_failure_shuts_down_without_finish() {
        let mut runtime = FakeDeviceLatentInspectionRuntime::success();
        runtime.start_audit = Err(DeviceLatentInspectionError::Audit);
        assert!(matches!(
            run_fake(&runtime).await,
            Err(DeviceLatentInspectionError::Audit)
        ));
        assert!(runtime.finish_audits().is_empty());
        assert_eq!(
            runtime
                .reader_shutdowns
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert_eq!(
            runtime
                .operator_shutdowns
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn fake_runtime_reader_connect_failure_finishes_storage_and_shuts_down_operator() {
        let mut runtime = FakeDeviceLatentInspectionRuntime::success();
        runtime.connect_reader = Err(DeviceLatentInspectionError::Storage);
        assert!(matches!(
            run_fake(&runtime).await,
            Err(DeviceLatentInspectionError::Storage)
        ));
        assert_eq!(
            runtime.finish_audits(),
            vec![FakeFinishAudit {
                subject: postgres::UNVERIFIED_DEVICE_LATENT_OPERATOR.to_owned(),
                outcome: DeviceLatentInspectionAuditOutcome::Storage,
            }]
        );
        assert_eq!(
            runtime
                .reader_shutdowns
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert_eq!(
            runtime
                .operator_shutdowns
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn fake_runtime_reader_shutdown_failure_overrides_success_with_shutdown() {
        let mut runtime = FakeDeviceLatentInspectionRuntime::success();
        runtime.reader_shutdown = Err(DeviceLatentInspectionError::Shutdown);
        assert!(matches!(
            run_fake(&runtime).await,
            Err(DeviceLatentInspectionError::Shutdown)
        ));
        assert_eq!(
            runtime.finish_audits(),
            vec![FakeFinishAudit {
                subject: "verified-device-latent-operator".to_owned(),
                outcome: DeviceLatentInspectionAuditOutcome::Shutdown,
            }]
        );
        assert_eq!(
            runtime
                .reader_shutdowns
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(
            runtime
                .operator_shutdowns
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }
}
