#![allow(clippy::expect_used)]

use std::io::Cursor;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use audit::ports::AuditLedgerVerifyReport;
use base64::Engine as _;
use consistency::{
    IdemKey, ProjectionApplyErrorKind, ProjectionApplyErrorReason, ProjectionBatchLimit,
};
use eventexec::{
    AuthorizedDlqOperatorReceipt, DeadLetterId, DlqCursor, DlqEntrySummary, DlqError,
    DlqInspectRequest, DlqInspectTarget, DlqListQuery, DlqRedriveOutcome, DlqRedriveRequest,
    DlqReplayRequest, DlqStore, OutboxExpiredResolutionKind, OutboxExpiredResolutionOutcome,
    OutboxExpiredResolutionRequest, ProjectionRun, ProjectionStop, VerifiedOperatorSubject,
};
use postgres::{MaintenanceAuditOutcome, ProjectionPointerPrecondition};

use super::audit_ledger::{
    AuditLedgerVerifyArgs, AuditLedgerVerifyRuntime, UNVERIFIED_AUDIT_LEDGER_VERIFY_OPERATOR,
    authorize_audit_ledger_verify_operator,
    parse_audit_ledger_verify_args as parse_audit_ledger_verify_args_with_stdin,
    parse_audit_ledger_verify_grants,
    run_audit_ledger_verify_command_with_runtime as run_audit_ledger_verify_command_with_parsed,
};
use super::cli_clap::{assert_operator_cli_err, assert_operator_cli_err_bucket};
use super::dlq::{
    DlqCliArgs, DlqCliCommand, DlqControlRuntime, DlqMaintenanceAction, UNVERIFIED_DLQ_OPERATOR,
    authorize_dlq_operator, dlq_redrive_result_line, dlq_summary_json_line,
    parse_dlq_args as parse_dlq_args_with_stdin, parse_dlq_operator_grants,
    run_dlq_control_command_with_runtime as run_dlq_control_command_with_parsed,
};
use super::projection::{
    PROJECTION_MAINTENANCE_OPERATOR_GRANTS_ENV, ProjectionCliArgs, ProjectionCliCommand,
    ProjectionCommandPreparation, ProjectionControlRuntime, ProjectionMaintenanceAction,
    ProjectionOperatorAuditContext, ProjectionReplayStop, ReplayWorkBudget,
    UNVERIFIED_PROJECTION_MAINTENANCE_OPERATOR, build_projection_target_registry,
    ensure_projection_command_supported_by_registry, fold_projection_replay_batches,
    load_projection_maintenance_grants_from_snapshot,
    parse_projection_args as parse_projection_args_with_stdin, parse_projection_maintenance_grants,
    prepare_projection_command_with_stdin, projection_replay_batch_is_full,
    projection_replay_decide_stop, projection_replay_effective_batch_limit,
    projection_replay_stop_cli_fields, projection_stop_cli_fields, projection_swap_result_line,
    run_projection_control_command_with_runtime as run_projection_control_command_with_parsed,
};
use super::reconcile::{
    authorize_reconcile_operator, parse_reconcile_operator_grants,
    parse_reconcile_target_args as parse_reconcile_target_args_with_stdin, reconcile_summary_json,
};
use super::service_token::{
    OPERATOR_SERVICE_TOKEN_STDIN_FLAG, OperatorServiceToken, read_operator_service_token_stdin,
};
use super::settings::{
    parse_settings_config_value_maintenance_args as parse_settings_config_value_maintenance_args_with_stdin,
    settings_config_value_maintenance_vault_failure, verified_config_value_maintenance_operator,
};
use super::{is_audit_ledger_command, is_projection_command};
use crate::phase::test_support::{
    COMMAND_IDEMPOTENCY_KEYS_ENV, build_command_idempotency_keyring_from,
};
use crate::phase::{OperatorRuntimeInputs, PreparedRuntimeInputs};

static_assertions::assert_not_impl_any!(OperatorServiceToken: Clone);

fn args(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_string()).collect()
}

fn operator_service_token_stdin() -> Cursor<&'static [u8]> {
    Cursor::new(b"opaque-token\n")
}

fn parse_projection_args(args: &[String]) -> anyhow::Result<ProjectionCliArgs> {
    parse_projection_args_with_stdin(args, &mut operator_service_token_stdin())
}

fn parse_audit_ledger_verify_args(args: &[String]) -> anyhow::Result<AuditLedgerVerifyArgs> {
    parse_audit_ledger_verify_args_with_stdin(args, &mut operator_service_token_stdin())
}

fn parse_dlq_args(args: &[String]) -> anyhow::Result<DlqCliArgs> {
    parse_dlq_args_with_stdin(args, &mut operator_service_token_stdin())
}

fn parse_reconcile_target_args(
    args: &[String],
) -> anyhow::Result<super::reconcile::ReconcileTargetCliArgs> {
    parse_reconcile_target_args_with_stdin(args, &mut operator_service_token_stdin())
}

fn parse_settings_config_value_maintenance_args(
    args: &[String],
) -> anyhow::Result<super::settings::SettingsConfigValueMaintenanceArgs> {
    parse_settings_config_value_maintenance_args_with_stdin(
        args,
        &mut operator_service_token_stdin(),
    )
}

async fn run_projection_control_command_with_runtime<R: ProjectionControlRuntime>(
    args: &[String],
    runtime: &R,
) -> anyhow::Result<()> {
    let parsed = parse_projection_args(args)?;
    run_projection_control_command_with_parsed(parsed, runtime).await
}

async fn run_audit_ledger_verify_command_with_runtime<R: AuditLedgerVerifyRuntime>(
    args: &[String],
    runtime: &R,
) -> anyhow::Result<()> {
    let parsed = parse_audit_ledger_verify_args(args)?;
    run_audit_ledger_verify_command_with_parsed(parsed, runtime).await
}

async fn run_dlq_control_command_with_runtime<R: DlqControlRuntime>(
    args: &[String],
    runtime: &R,
) -> anyhow::Result<()> {
    let parsed = parse_dlq_args(args)?;
    run_dlq_control_command_with_parsed(parsed, runtime).await
}

#[test]
fn operator_service_token_stdin_is_single_redacted_bounded_carrier() -> anyhow::Result<()> {
    // Presence is enforced by family clap prepare (not the retired argv shim).
    let list = parse_dlq_args(&dlq_control_args("list", &[]))?;
    assert_eq!(list.operator_service_token.as_str(), "opaque-token");
    let debug = format!("{:?}", list.operator_service_token);
    assert_eq!(debug, "OperatorServiceToken(<redacted>)");
    assert!(!debug.contains("opaque-token"));

    for raw in ["opaque-token\n", "opaque-token\r\n", "opaque-token"] {
        let token = read_operator_service_token_stdin(&mut Cursor::new(raw.as_bytes()))?;
        assert_eq!(token.as_str(), "opaque-token");
        let debug = format!("{token:?}");
        assert_eq!(debug, "OperatorServiceToken(<redacted>)");
        assert!(!debug.contains("opaque-token"));
    }

    for raw in [
        "",
        "\n",
        " \n",
        " opaque-token\n",
        "opaque-token \n",
        "opaque-token\nextra",
        "opaque-token\r\nextra",
        "opaque-token\n\n",
        "opaque-token\r\n\r\n",
        "opaque-token\r",
    ] {
        assert!(
            read_operator_service_token_stdin(&mut Cursor::new(raw.as_bytes())).is_err(),
            "stdin token must reject {raw:?}"
        );
    }

    let oversized = vec![b'x'; 16 * 1024 + 1];
    assert!(read_operator_service_token_stdin(&mut Cursor::new(oversized)).is_err());
    Ok(())
}

#[test]
fn operator_service_token_stdin_flag_hard_rejects_missing_duplicate_and_argv_secret() {
    // Family prepare / clap presence — not the retired parse_operator_service_token_stdin_args shim.
    for (name, candidate) in [
        (
            "missing stdin flag",
            args(&[
                "dlq",
                "list",
                "--operator-tenant",
                DLQ_FIXTURE_OPERATOR_TENANT,
                "--tenant",
                DLQ_FIXTURE_TENANT,
            ]),
        ),
        (
            "duplicate stdin flag",
            args(&[
                "dlq",
                "list",
                OPERATOR_SERVICE_TOKEN_STDIN_FLAG,
                OPERATOR_SERVICE_TOKEN_STDIN_FLAG,
                "--operator-tenant",
                DLQ_FIXTURE_OPERATOR_TENANT,
                "--tenant",
                DLQ_FIXTURE_TENANT,
            ]),
        ),
        (
            "argv secret flag rejected",
            args(&[
                "dlq",
                "list",
                "--operator-service-token",
                "argv-secret",
                "--operator-tenant",
                DLQ_FIXTURE_OPERATOR_TENANT,
                "--tenant",
                DLQ_FIXTURE_TENANT,
            ]),
        ),
    ] {
        let err = parse_dlq_args(&candidate).expect_err(name);
        assert_operator_cli_err(&err, "dlq");
        assert!(
            !err.to_string().contains("argv-secret"),
            "{name} leaked argv secret"
        );
    }
}

#[test]
fn invalid_operator_args_do_not_consume_stdin() {
    let mut stdin = Cursor::new(b"must-remain-unread\n".as_slice());
    let candidate = args(&["projections", "status", OPERATOR_SERVICE_TOKEN_STDIN_FLAG]);
    assert!(parse_projection_args_with_stdin(&candidate, &mut stdin).is_err());
    assert_eq!(stdin.position(), 0);
}

const PROJECTION_FIXTURE_OPERATOR_TENANT: &str = "00000000-0000-4000-8000-000000000001";
const PROJECTION_FIXTURE_TENANT: &str = "00000000-0000-4000-8000-000000000002";
const PROJECTION_FIXTURE_ID: &str = "audit.session-projection";
const PROJECTION_FIXTURE_VERSION: &str = "v2";
const PROJECTION_FIXTURE_OPERATOR: &str = "rss-maintenance-operator";
const PROJECTION_OPERATOR_TEST_SECRET_BUNDLE: &str = r#"{
    "pgProjectionReaderPasswordFile":"/run/secrets/projection-reader",
    "pgProjectionOperatorPasswordFile":"/run/secrets/projection-operator",
    "replayVaultToken":"projection-replay-vault-token"
}"#;

struct ProjectionGrantConfigSource(&'static str);

impl crate::config::RuntimeConfigSource for ProjectionGrantConfigSource {
    fn read(
        &mut self,
        key: &crate::config::RuntimeConfigKey,
    ) -> crate::config::CapturedConfigValue {
        if key.as_str() == PROJECTION_MAINTENANCE_OPERATOR_GRANTS_ENV {
            crate::config::CapturedConfigValue::Present(secure::SecretText::from_string(
                self.0.to_owned(),
            ))
        } else {
            crate::config::CapturedConfigValue::Missing
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FakeProjectionAuditOutcome {
    Success,
    Failure { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FakeProjectionAuditRecord {
    command_id: uuid::Uuid,
    subject: String,
    action: String,
    outcome: FakeProjectionAuditOutcome,
    resource_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FakeProjectionCommandRecord {
    action: ProjectionMaintenanceAction,
    operator_subject: String,
    registry_has_targets: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FakeProjectionOperator {
    Verified(&'static str),
    AuthFailure,
    ProviderConfigFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FakeProjectionCommandResult {
    Success,
    Failure(&'static str),
}

struct FakeProjectionControlRuntime {
    target_registered: bool,
    operator: FakeProjectionOperator,
    command_result: FakeProjectionCommandResult,
    audits: Mutex<Vec<FakeProjectionAuditRecord>>,
    commands: Mutex<Vec<FakeProjectionCommandRecord>>,
    setup_count: AtomicUsize,
    shutdown_count: AtomicUsize,
}

impl FakeProjectionControlRuntime {
    fn registered(command_result: FakeProjectionCommandResult) -> Self {
        Self::new(
            true,
            FakeProjectionOperator::Verified(PROJECTION_FIXTURE_OPERATOR),
            command_result,
        )
    }

    fn unsupported(command_result: FakeProjectionCommandResult) -> Self {
        Self::new(
            false,
            FakeProjectionOperator::Verified(PROJECTION_FIXTURE_OPERATOR),
            command_result,
        )
    }

    fn auth_failure() -> Self {
        Self::new(
            true,
            FakeProjectionOperator::AuthFailure,
            FakeProjectionCommandResult::Success,
        )
    }

    fn provider_config_failure() -> Self {
        Self::new(
            true,
            FakeProjectionOperator::ProviderConfigFailure,
            FakeProjectionCommandResult::Success,
        )
    }

    fn new(
        target_registered: bool,
        operator: FakeProjectionOperator,
        command_result: FakeProjectionCommandResult,
    ) -> Self {
        Self {
            target_registered,
            operator,
            command_result,
            audits: Mutex::new(Vec::new()),
            commands: Mutex::new(Vec::new()),
            setup_count: AtomicUsize::new(0),
            shutdown_count: AtomicUsize::new(0),
        }
    }

    fn audit_records(&self) -> Vec<FakeProjectionAuditRecord> {
        match self.audits.lock() {
            Ok(records) => records.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    fn command_records(&self) -> Vec<FakeProjectionCommandRecord> {
        match self.commands.lock() {
            Ok(records) => records.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    fn setup_count(&self) -> usize {
        self.setup_count.load(Ordering::Relaxed)
    }

    fn shutdown_count(&self) -> usize {
        self.shutdown_count.load(Ordering::Relaxed)
    }
}

fn fake_projection_receipt(
    _subject: &str,
    parsed: &ProjectionCliArgs,
) -> anyhow::Result<authn::ProjectionMaintenanceReceipt> {
    let principal =
        authn::test_support::service_principal(vocab::ServiceCallerDomain::MaintenanceOperator);
    let grants =
        authn::ProjectionMaintenanceGrantSet::new(vec![authn::ProjectionMaintenanceGrant::new(
            vocab::ServiceCallerDomain::MaintenanceOperator,
            parsed.command.action().authorized_action(),
            parsed.selector.tenant(),
            parsed.selector.projection().as_str(),
        )?])?;
    grants
        .authorize(
            &principal,
            parsed.command.action().authorized_action(),
            parsed.selector.tenant(),
            parsed.selector.projection().as_str(),
        )
        .map_err(Into::into)
}

impl ProjectionControlRuntime for FakeProjectionControlRuntime {
    type Session = ();
    type Registry = bool;

    fn build_registry(&self, _session: &Self::Session) -> anyhow::Result<Self::Registry> {
        Ok(self.target_registered)
    }

    fn ensure_command_supported(
        &self,
        registry: &Self::Registry,
        _parsed: &ProjectionCliArgs,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            *registry,
            "projection is not activated by the assembly plan"
        );
        Ok(())
    }

    async fn connect_maintenance(&self) -> anyhow::Result<Self::Session> {
        self.setup_count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    async fn record_projection_maintenance_audit(
        &self,
        _session: &Self::Session,
        audit: ProjectionOperatorAuditContext,
        operator_subject: &str,
        action: &str,
        outcome: MaintenanceAuditOutcome<'_>,
        resource_id: &str,
    ) -> anyhow::Result<()> {
        let outcome = match outcome {
            MaintenanceAuditOutcome::Success => FakeProjectionAuditOutcome::Success,
            MaintenanceAuditOutcome::Failure { reason } => FakeProjectionAuditOutcome::Failure {
                reason: reason.to_owned(),
            },
        };
        let record = FakeProjectionAuditRecord {
            command_id: audit.command_id(),
            subject: operator_subject.to_owned(),
            action: action.to_owned(),
            outcome,
            resource_id: resource_id.to_owned(),
        };
        match self.audits.lock() {
            Ok(mut records) => records.push(record),
            Err(poisoned) => poisoned.into_inner().push(record),
        }
        Ok(())
    }

    async fn operator_receipt(
        &self,
        session: &Self::Session,
        audit: ProjectionOperatorAuditContext,
        parsed: &ProjectionCliArgs,
        resource_id: &str,
    ) -> anyhow::Result<authn::ProjectionMaintenanceReceipt> {
        match self.operator {
            FakeProjectionOperator::Verified(subject) => fake_projection_receipt(subject, parsed),
            FakeProjectionOperator::AuthFailure => {
                let finish_action =
                    format!("projection.{}.finish", parsed.command.action().as_str());
                self.record_projection_maintenance_audit(
                    session,
                    audit,
                    UNVERIFIED_PROJECTION_MAINTENANCE_OPERATOR,
                    &finish_action,
                    MaintenanceAuditOutcome::Failure {
                        reason: "operator_auth",
                    },
                    resource_id,
                )
                .await?;
                anyhow::bail!("projection maintenance operator auth failed");
            }
            FakeProjectionOperator::ProviderConfigFailure => {
                let finish_action =
                    format!("projection.{}.finish", parsed.command.action().as_str());
                self.record_projection_maintenance_audit(
                    session,
                    audit,
                    UNVERIFIED_PROJECTION_MAINTENANCE_OPERATOR,
                    &finish_action,
                    MaintenanceAuditOutcome::Failure {
                        reason: "operator_provider_config",
                    },
                    resource_id,
                )
                .await?;
                anyhow::bail!("projection maintenance operator verifier");
            }
        }
    }

    async fn run_projection_command(
        &self,
        _session: &Self::Session,
        registry: &Self::Registry,
        parsed: &ProjectionCliArgs,
        receipt: authn::ProjectionMaintenanceReceipt,
    ) -> anyhow::Result<()> {
        let record = FakeProjectionCommandRecord {
            action: parsed.command.action(),
            operator_subject: receipt.operator_caller().as_str().to_owned(),
            registry_has_targets: *registry,
        };
        match self.commands.lock() {
            Ok(mut records) => records.push(record),
            Err(poisoned) => poisoned.into_inner().push(record),
        }
        match self.command_result {
            FakeProjectionCommandResult::Success => Ok(()),
            FakeProjectionCommandResult::Failure(reason) => anyhow::bail!(reason),
        }
    }

    async fn shutdown(&self, _session: Self::Session) {
        self.shutdown_count.fetch_add(1, Ordering::Relaxed);
    }
}

fn projection_control_args(subcommand: &str, extra: &[&str]) -> Vec<String> {
    let mut parts = vec![
        "projections",
        subcommand,
        "--operator-service-token-stdin",
        "--operator-tenant",
        PROJECTION_FIXTURE_OPERATOR_TENANT,
        "--tenant",
        PROJECTION_FIXTURE_TENANT,
        "--projection",
        PROJECTION_FIXTURE_ID,
        "--version",
        PROJECTION_FIXTURE_VERSION,
    ];
    parts.extend_from_slice(extra);
    args(&parts)
}

fn projection_fixture_resource_id(action: ProjectionMaintenanceAction) -> String {
    format!(
        "operation={} tenant={} projection={} version={}",
        action.as_str(),
        PROJECTION_FIXTURE_TENANT,
        PROJECTION_FIXTURE_ID,
        PROJECTION_FIXTURE_VERSION
    )
}

fn assert_projection_lifecycle_audit(
    runtime: &FakeProjectionControlRuntime,
    action: ProjectionMaintenanceAction,
    expected_finish: FakeProjectionAuditOutcome,
) -> uuid::Uuid {
    let audits = runtime.audit_records();
    assert_eq!(audits.len(), 2);
    let resource_id = projection_fixture_resource_id(action);
    assert!(!audits[0].command_id.is_nil());
    assert_eq!(audits[0].command_id, audits[1].command_id);
    assert_eq!(
        audits[0].subject,
        UNVERIFIED_PROJECTION_MAINTENANCE_OPERATOR
    );
    assert_eq!(
        audits[0].action,
        format!("projection.{}.start", action.as_str())
    );
    assert_eq!(audits[0].outcome, FakeProjectionAuditOutcome::Success);
    assert_eq!(audits[0].resource_id, resource_id);
    assert_eq!(audits[1].subject, PROJECTION_FIXTURE_OPERATOR);
    assert_eq!(
        audits[1].action,
        format!("projection.{}.finish", action.as_str())
    );
    assert_eq!(audits[1].outcome, expected_finish);
    assert_eq!(audits[1].resource_id, resource_id);
    audits[0].command_id
}

fn assert_projection_failure_audit_command_ids(runtime: &FakeProjectionControlRuntime) {
    let audits = runtime.audit_records();
    assert_eq!(audits.len(), 2);
    assert!(!audits[0].command_id.is_nil());
    assert_eq!(audits[0].command_id, audits[1].command_id);
}

#[test]
fn projection_args_parse_replay_with_typed_selector() -> anyhow::Result<()> {
    let parsed = parse_projection_args(&args(&[
        "projections",
        "replay",
        "--operator-service-token-stdin",
        "--operator-tenant",
        "00000000-0000-4000-8000-000000000001",
        "--tenant",
        "00000000-0000-4000-8000-000000000002",
        "--projection",
        "audit.session-projection",
        "--version",
        "v2",
        "--batch-size",
        "7",
        "--max-events",
        "42",
    ]))?;

    assert_eq!(parsed.operator_service_token.as_str(), "opaque-token");
    assert_eq!(
        parsed.operator_tenant,
        vocab::TenantId::parse("00000000-0000-4000-8000-000000000001")?
    );
    assert_eq!(
        parsed.selector.tenant(),
        vocab::TenantId::parse("00000000-0000-4000-8000-000000000002")?
    );
    assert_eq!(
        parsed.selector.projection().as_str(),
        "audit.session-projection"
    );
    assert_eq!(parsed.selector.version().as_str(), "v2");
    assert!(matches!(
        parsed.command,
        ProjectionCliCommand::Replay {
            batch_limit,
            work_budget,
        } if batch_limit.get() == 7 && work_budget.get() == 42
    ));
    Ok(())
}

#[test]
fn projection_args_reject_max_events_missing_duplicate_zero_and_invalid() {
    assert!(
        parse_projection_args(&args(&[
            "projections",
            "replay",
            "--operator-service-token-stdin",
            "--operator-tenant",
            "00000000-0000-4000-8000-000000000001",
            "--tenant",
            "00000000-0000-4000-8000-000000000002",
            "--projection",
            "audit.session-projection",
            "--version",
            "v2",
            "--batch-size",
            "7",
        ]))
        .is_err(),
        "missing --max-events must fail"
    );
    assert!(
        parse_projection_args(&args(&[
            "projections",
            "replay",
            "--operator-service-token-stdin",
            "--operator-tenant",
            "00000000-0000-4000-8000-000000000001",
            "--tenant",
            "00000000-0000-4000-8000-000000000002",
            "--projection",
            "audit.session-projection",
            "--version",
            "v2",
            "--max-events",
            "10",
            "--max-events",
            "11",
        ]))
        .is_err(),
        "duplicate --max-events must fail"
    );
    assert!(
        parse_projection_args(&args(&[
            "projections",
            "replay",
            "--operator-service-token-stdin",
            "--operator-tenant",
            "00000000-0000-4000-8000-000000000001",
            "--tenant",
            "00000000-0000-4000-8000-000000000002",
            "--projection",
            "audit.session-projection",
            "--version",
            "v2",
            "--max-events",
            "0",
        ]))
        .is_err(),
        "zero --max-events must fail"
    );
    assert!(
        parse_projection_args(&args(&[
            "projections",
            "replay",
            "--operator-service-token-stdin",
            "--operator-tenant",
            "00000000-0000-4000-8000-000000000001",
            "--tenant",
            "00000000-0000-4000-8000-000000000002",
            "--projection",
            "audit.session-projection",
            "--version",
            "v2",
            "--max-events",
            "not-a-number",
        ]))
        .is_err(),
        "invalid --max-events must fail"
    );
    assert!(
        parse_projection_args(&args(&[
            "projections",
            "replay",
            "--operator-service-token-stdin",
            "--operator-tenant",
            "00000000-0000-4000-8000-000000000001",
            "--tenant",
            "00000000-0000-4000-8000-000000000002",
            "--projection",
            "audit.session-projection",
            "--version",
            "v2",
            "--max-events",
            "999999999999999999999999999",
        ]))
        .is_err(),
        "overflow --max-events must fail"
    );
}

#[test]
fn projection_args_parse_swap_requires_exact_precondition() -> anyhow::Result<()> {
    let parsed = parse_projection_args(&args(&[
        "projections",
        "swap",
        "--operator-service-token-stdin",
        "--operator-tenant",
        "00000000-0000-4000-8000-000000000001",
        "--tenant",
        "00000000-0000-4000-8000-000000000002",
        "--projection",
        "audit.session-projection",
        "--version",
        "v2",
        "--expected-active-generation",
        "v1",
    ]))?;
    assert!(matches!(
        parsed.command,
        ProjectionCliCommand::Swap {
            precondition: ProjectionPointerPrecondition::ExpectedActiveGeneration(ref version),
        } if version.as_str() == "v1"
    ));

    let parsed = parse_projection_args(&args(&[
        "projections",
        "swap",
        "--operator-service-token-stdin",
        "--operator-tenant",
        "00000000-0000-4000-8000-000000000001",
        "--tenant",
        "00000000-0000-4000-8000-000000000002",
        "--projection",
        "audit.session-projection",
        "--version",
        "v2",
        "--expect-unset",
    ]))?;
    assert!(matches!(
        parsed.command,
        ProjectionCliCommand::Swap {
            precondition: ProjectionPointerPrecondition::ExpectUnset,
        }
    ));

    assert!(
        parse_projection_args(&args(&[
            "projections",
            "swap",
            "--operator-service-token-stdin",
            "--operator-tenant",
            "00000000-0000-4000-8000-000000000001",
            "--tenant",
            "00000000-0000-4000-8000-000000000002",
            "--projection",
            "audit.session-projection",
            "--version",
            "v2",
        ]))
        .is_err()
    );
    assert!(
        parse_projection_args(&args(&[
            "projections",
            "swap",
            "--operator-service-token-stdin",
            "--operator-tenant",
            "00000000-0000-4000-8000-000000000001",
            "--tenant",
            "00000000-0000-4000-8000-000000000002",
            "--projection",
            "audit.session-projection",
            "--version",
            "v2",
            "--expected-active-generation",
            "v1",
            "--expect-unset",
        ]))
        .is_err()
    );
    Ok(())
}

#[test]
fn projection_swap_output_names_the_promoted_high_water_exactly() -> anyhow::Result<()> {
    let parsed = parse_projection_args(&args(&[
        "projections",
        "swap",
        "--operator-service-token-stdin",
        "--operator-tenant",
        "00000000-0000-4000-8000-000000000001",
        "--tenant",
        "00000000-0000-4000-8000-000000000002",
        "--projection",
        "settings.config-projection",
        "--version",
        "green",
        "--expected-active-generation",
        "blue",
    ]))?;
    let active = eventexec::ProjectionVersion::parse("green")?;
    let previous = eventexec::ProjectionVersion::parse("blue")?;

    assert_eq!(
        projection_swap_result_line(
            &parsed.selector,
            &active,
            Some(&previous),
            consistency::Lsn::new(42),
            vocab::Epoch::new(7),
        ),
        "operation=swap tenant=00000000-0000-4000-8000-000000000002 projection=settings.config-projection active_version=green previous_version=blue promoted_high_water_lsn=42 token=7"
    );
    Ok(())
}

#[test]
fn projection_args_fail_closed_on_missing_invalid_or_unknown_flags() {
    let valid_status = [
        "projections",
        "status",
        "--operator-service-token-stdin",
        "--operator-tenant",
        "00000000-0000-4000-8000-000000000001",
        "--tenant",
        "00000000-0000-4000-8000-000000000002",
        "--projection",
        "audit.session-projection",
        "--version",
        "v2",
    ];
    assert!(parse_projection_args(&args(&valid_status)).is_ok());
    assert!(is_projection_command(&args(&["projections"])));
    assert!(is_projection_command(&args(&["projections", "bogus"])));

    let cases = vec![
        ("missing namespace", args(&[])),
        ("missing subcommand", args(&["projections"])),
        ("unknown subcommand", args(&["projections", "bogus"])),
        (
            "missing operator token",
            args(&[
                "projections",
                "status",
                "--operator-tenant",
                "00000000-0000-4000-8000-000000000001",
                "--tenant",
                "00000000-0000-4000-8000-000000000002",
                "--projection",
                "audit.session-projection",
                "--version",
                "v2",
            ]),
        ),
        (
            "missing operator tenant",
            args(&[
                "projections",
                "status",
                "--operator-service-token-stdin",
                "--tenant",
                "00000000-0000-4000-8000-000000000002",
                "--projection",
                "audit.session-projection",
                "--version",
                "v2",
            ]),
        ),
        (
            "missing tenant",
            args(&[
                "projections",
                "status",
                "--operator-service-token-stdin",
                "--operator-tenant",
                "00000000-0000-4000-8000-000000000001",
                "--projection",
                "audit.session-projection",
                "--version",
                "v2",
            ]),
        ),
        (
            "missing projection",
            args(&[
                "projections",
                "status",
                "--operator-service-token-stdin",
                "--operator-tenant",
                "00000000-0000-4000-8000-000000000001",
                "--tenant",
                "00000000-0000-4000-8000-000000000002",
                "--version",
                "v2",
            ]),
        ),
        (
            "missing version",
            args(&[
                "projections",
                "status",
                "--operator-service-token-stdin",
                "--operator-tenant",
                "00000000-0000-4000-8000-000000000001",
                "--tenant",
                "00000000-0000-4000-8000-000000000002",
                "--projection",
                "audit.session-projection",
            ]),
        ),
        (
            "invalid operator tenant",
            args(&[
                "projections",
                "status",
                "--operator-service-token-stdin",
                "--operator-tenant",
                "not-a-tenant",
                "--tenant",
                "00000000-0000-4000-8000-000000000002",
                "--projection",
                "audit.session-projection",
                "--version",
                "v2",
            ]),
        ),
        (
            "invalid projection",
            args(&[
                "projections",
                "status",
                "--operator-service-token-stdin",
                "--operator-tenant",
                "00000000-0000-4000-8000-000000000001",
                "--tenant",
                "00000000-0000-4000-8000-000000000002",
                "--projection",
                "Audit.SessionProjection",
                "--version",
                "v2",
            ]),
        ),
        (
            "invalid version",
            args(&[
                "projections",
                "replay",
                "--operator-service-token-stdin",
                "--operator-tenant",
                "00000000-0000-4000-8000-000000000001",
                "--tenant",
                "00000000-0000-4000-8000-000000000002",
                "--projection",
                "audit.session-projection",
                "--version",
                "v 2",
            ]),
        ),
        (
            "unknown flag",
            args(&[
                "projections",
                "status",
                "--operator-service-token-stdin",
                "--operator-tenant",
                "00000000-0000-4000-8000-000000000001",
                "--tenant",
                "00000000-0000-4000-8000-000000000002",
                "--projection",
                "audit.session-projection",
                "--version",
                "v2",
                "--bogus",
            ]),
        ),
        (
            "status rejects precondition",
            args(&[
                "projections",
                "status",
                "--operator-service-token-stdin",
                "--operator-tenant",
                "00000000-0000-4000-8000-000000000001",
                "--tenant",
                "00000000-0000-4000-8000-000000000002",
                "--projection",
                "audit.session-projection",
                "--version",
                "v2",
                "--expected-active-generation",
                "v1",
            ]),
        ),
        (
            "status rejects batch",
            args(&[
                "projections",
                "status",
                "--operator-service-token-stdin",
                "--operator-tenant",
                "00000000-0000-4000-8000-000000000001",
                "--tenant",
                "00000000-0000-4000-8000-000000000002",
                "--projection",
                "audit.session-projection",
                "--version",
                "v2",
                "--batch-size",
                "7",
            ]),
        ),
        (
            "swap rejects batch",
            args(&[
                "projections",
                "swap",
                "--operator-service-token-stdin",
                "--operator-tenant",
                "00000000-0000-4000-8000-000000000001",
                "--tenant",
                "00000000-0000-4000-8000-000000000002",
                "--projection",
                "audit.session-projection",
                "--version",
                "v2",
                "--expect-unset",
                "--batch-size",
                "7",
            ]),
        ),
        (
            "replay rejects precondition",
            args(&[
                "projections",
                "replay",
                "--operator-service-token-stdin",
                "--operator-tenant",
                "00000000-0000-4000-8000-000000000001",
                "--tenant",
                "00000000-0000-4000-8000-000000000002",
                "--projection",
                "audit.session-projection",
                "--version",
                "v2",
                "--max-events",
                "10",
                "--expected-active-generation",
                "v1",
            ]),
        ),
        (
            "invalid batch zero",
            args(&[
                "projections",
                "replay",
                "--operator-service-token-stdin",
                "--operator-tenant",
                "00000000-0000-4000-8000-000000000001",
                "--tenant",
                "00000000-0000-4000-8000-000000000002",
                "--projection",
                "audit.session-projection",
                "--version",
                "v2",
                "--batch-size",
                "0",
                "--max-events",
                "10",
            ]),
        ),
        (
            "invalid batch string",
            args(&[
                "projections",
                "replay",
                "--operator-service-token-stdin",
                "--operator-tenant",
                "00000000-0000-4000-8000-000000000001",
                "--tenant",
                "00000000-0000-4000-8000-000000000002",
                "--projection",
                "audit.session-projection",
                "--version",
                "v2",
                "--batch-size",
                "not-a-number",
                "--max-events",
                "10",
            ]),
        ),
        (
            "status rejects max-events",
            args(&[
                "projections",
                "status",
                "--operator-service-token-stdin",
                "--operator-tenant",
                "00000000-0000-4000-8000-000000000001",
                "--tenant",
                "00000000-0000-4000-8000-000000000002",
                "--projection",
                "audit.session-projection",
                "--version",
                "v2",
                "--max-events",
                "10",
            ]),
        ),
        (
            "missing flag value",
            args(&[
                "projections",
                "status",
                "--operator-service-token-stdin",
                "--operator-tenant",
                "00000000-0000-4000-8000-000000000001",
                "--tenant",
            ]),
        ),
        (
            "duplicate singleton flag",
            args(&[
                "projections",
                "status",
                "--operator-service-token-stdin",
                "--operator-service-token-stdin",
                "--operator-tenant",
                "00000000-0000-4000-8000-000000000001",
                "--tenant",
                "00000000-0000-4000-8000-000000000002",
                "--projection",
                "audit.session-projection",
                "--version",
                "v2",
            ]),
        ),
    ];

    for (name, candidate) in cases {
        let err = parse_projection_args(&candidate).expect_err(&format!("case must fail: {name}"));
        assert_operator_cli_err(&err, "projections");
    }
}

#[test]
#[allow(non_snake_case)] // 验收过滤名含 SECRET_BAIT
fn projection_args_SECRET_BAIT_invalid_value_is_redacted() {
    let err = parse_projection_args(&args(&[
        "projections",
        "status",
        "--operator-service-token-stdin",
        "--operator-tenant=SECRET_BAIT",
        "--tenant",
        "00000000-0000-4000-8000-000000000002",
        "--projection",
        "audit.session-projection",
        "--version",
        "v2",
    ]))
    .expect_err("InvalidValue must fail closed");
    assert_operator_cli_err(&err, "projections");
}

#[test]
fn projection_args_clap_outcomes_are_action_specific() {
    // replay requires --max-events; status/swap reject it; swap requires exactly one precondition.
    assert!(
        parse_projection_args(&args(&[
            "projections",
            "replay",
            "--operator-service-token-stdin",
            "--operator-tenant",
            "00000000-0000-4000-8000-000000000001",
            "--tenant",
            "00000000-0000-4000-8000-000000000002",
            "--projection",
            "audit.session-projection",
            "--version",
            "v2",
        ]))
        .is_err(),
        "replay without --max-events must fail"
    );
    assert!(
        parse_projection_args(&projection_control_args(
            "replay",
            &["--max-events", "21", "--batch-size", "7"],
        ))
        .is_ok()
    );
    assert!(
        parse_projection_args(&projection_control_args("status", &["--max-events", "1"])).is_err()
    );
    assert!(
        parse_projection_args(&projection_control_args("swap", &[])).is_err(),
        "swap without precondition must fail"
    );
    assert!(
        parse_projection_args(&projection_control_args(
            "swap",
            &["--expected-active-generation", "v1", "--expect-unset"],
        ))
        .is_err(),
        "swap with both preconditions must fail"
    );
    let unknown = parse_projection_args(&args(&[
        "projections",
        "bogus",
        "--operator-service-token-stdin",
        "--operator-tenant",
        "00000000-0000-4000-8000-000000000001",
        "--tenant",
        "00000000-0000-4000-8000-000000000002",
        "--projection",
        "audit.session-projection",
        "--version",
        "v2",
    ]))
    .expect_err("unknown subcommand must fail");
    assert_operator_cli_err(&unknown, "projections");
}

#[test]
#[allow(non_snake_case)] // 验收过滤名含 SECRET_BAIT
fn projection_args_SECRET_BAIT_too_many_values_is_redacted() {
    let err = parse_projection_args(&args(&[
        "projections",
        "status",
        "--operator-service-token-stdin=SECRET_BAIT",
        "--operator-tenant",
        "00000000-0000-4000-8000-000000000001",
        "--tenant",
        "00000000-0000-4000-8000-000000000002",
        "--projection",
        "audit.session-projection",
        "--version",
        "v2",
    ]))
    .expect_err("TooManyValues must fail closed");
    assert_operator_cli_err(&err, "projections");
}

#[test]
fn bundled_disabled_projection_is_absent_from_operator_registry() -> anyhow::Result<()> {
    let snapshot = crate::config::test_snapshot(&[
        ("RSS_PRIMARY_TOKEN_PROFILE", "rss-access"),
        ("RSS_ADMIN_TOKEN_PROFILE", "rss-access"),
        ("RSS_INTERNAL_AUTH_SCHEME", "mtls"),
    ])?;
    let mut plan = crate::plan::RuntimePlan::bundled(snapshot.view())?;
    plan.bind_workflow_runtime(std::iter::empty())?;
    let registry = build_projection_target_registry(plan.workflow_runtime().projection_targets())?;
    assert!(registry.is_empty());
    registry.validate_coverage()?;

    let parsed = parse_projection_args(&projection_control_args("status", &[]))?;
    let error = ensure_projection_command_supported_by_registry(&registry, &parsed)
        .expect_err("disabled projection must be absent from the operator registry");
    assert!(format!("{error:#}").contains("projection is not activated by the assembly plan"));
    Ok(())
}

#[test]
fn command_idempotency_keyring_config_is_required_rotatable_and_independently_keyed()
-> anyhow::Result<()> {
    let encode = |byte: u8| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vec![byte; 32]);
    let raw = serde_json::json!({
        "current": {"id": "k2", "key": encode(0x42)},
        "previous": [{"id": "k1", "key": encode(0x24)}]
    })
    .to_string();
    let keyring = build_command_idempotency_keyring_from(|name| {
        (name == COMMAND_IDEMPOTENCY_KEYS_ENV).then(|| raw.clone())
    })?;
    assert_eq!(
        format!("{keyring:?}"),
        "CommandIdempotencyKeyring(<redacted>)"
    );

    assert!(build_command_idempotency_keyring_from(|_| None).is_err());
    let short = serde_json::json!({
        "current": {"id": "k2", "key": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7_u8; 16])}
    })
    .to_string();
    assert!(
        build_command_idempotency_keyring_from(|name| {
            (name == COMMAND_IDEMPOTENCY_KEYS_ENV).then(|| short.clone())
        })
        .is_err()
    );

    let reused = encode(0x42);
    assert!(
        build_command_idempotency_keyring_from(|name| match name {
            COMMAND_IDEMPOTENCY_KEYS_ENV => Some(raw.clone()),
            "RSS_AUDIT_CHAIN_KEY_B64URL" => Some(reused.clone()),
            _ => None,
        })
        .is_err()
    );
    Ok(())
}

#[test]
fn projection_maintenance_grants_authorize_exact_action_tenant_and_projection() -> anyhow::Result<()>
{
    let parsed = parse_projection_args(&args(&[
        "projections",
        "status",
        "--operator-service-token-stdin",
        "--operator-tenant",
        "00000000-0000-4000-8000-000000000001",
        "--tenant",
        "00000000-0000-4000-8000-000000000002",
        "--projection",
        "audit.session-projection",
        "--version",
        "v2",
    ]))?;
    let snapshot = crate::config::RuntimeConfigSnapshot::capture_projection_operator_test(
        ProjectionGrantConfigSource(
            "status|00000000-0000-4000-8000-000000000002|audit.session-projection",
        ),
        PROJECTION_OPERATOR_TEST_SECRET_BUNDLE,
    )?;
    let runtime_inputs = OperatorRuntimeInputs::new(PreparedRuntimeInputs::new(snapshot, None))?;
    let grants = load_projection_maintenance_grants_from_snapshot(
        runtime_inputs.config(),
        runtime_inputs.operator_capability(),
    )?;
    let principal =
        authn::test_support::service_principal(vocab::ServiceCallerDomain::MaintenanceOperator);
    grants.authorize(
        &principal,
        parsed.command.action().authorized_action(),
        parsed.selector.tenant(),
        parsed.selector.projection().as_str(),
    )?;

    let replay_grants = parse_projection_maintenance_grants(
        "replay|00000000-0000-4000-8000-000000000002|audit.session-projection",
    )?;
    assert!(
        replay_grants
            .authorize(
                &principal,
                parsed.command.action().authorized_action(),
                parsed.selector.tenant(),
                parsed.selector.projection().as_str(),
            )
            .is_err()
    );
    let wrong_tenant_grants = parse_projection_maintenance_grants(
        "status|00000000-0000-4000-8000-000000000003|audit.session-projection",
    )?;
    assert!(
        wrong_tenant_grants
            .authorize(
                &principal,
                parsed.command.action().authorized_action(),
                parsed.selector.tenant(),
                parsed.selector.projection().as_str(),
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn projection_replay_cli_fields_and_budget_stop_are_stable() -> anyhow::Result<()> {
    for reason in [
        ProjectionApplyErrorReason::TargetDefinitionDrift,
        ProjectionApplyErrorReason::TenantDrift,
        ProjectionApplyErrorReason::PayloadMalformed,
        ProjectionApplyErrorReason::VersionRegression,
    ] {
        let fields = projection_stop_cli_fields(&ProjectionStop::ApplyFailed {
            failed_at: consistency::Lsn::new(42),
            kind: reason.kind(),
            reason,
        });
        assert_eq!(fields.stop, "apply_failed");
        assert_eq!(fields.failed_at_lsn, Some(consistency::Lsn::new(42)));
        assert_eq!(
            fields.kind,
            Some(super::projection::projection_apply_kind_cli(reason.kind()))
        );
        assert_eq!(fields.reason, Some(reason.as_label()));
    }

    let skipped = projection_stop_cli_fields(&ProjectionStop::PoisonSkipped {
        skipped_at: consistency::Lsn::new(43),
        kind: ProjectionApplyErrorKind::Permanent,
        reason: ProjectionApplyErrorReason::PayloadMalformed,
    });
    assert_eq!(skipped.reason, Some("payload_malformed"));

    let batch_limit = ProjectionBatchLimit::new(10)?;
    assert!(projection_replay_batch_is_full(10, batch_limit));
    assert!(!projection_replay_batch_is_full(9, batch_limit));
    assert_eq!(
        projection_replay_stop_cli_fields(&ProjectionReplayStop::BudgetExhausted).stop,
        "budget_exhausted"
    );
    assert_eq!(
        projection_replay_stop_cli_fields(&ProjectionReplayStop::Engine(ProjectionStop::Completed))
            .stop,
        "completed"
    );
    Ok(())
}

#[tokio::test]
async fn projection_replay_budget_bounds_full_batches_and_distinguishes_stops() -> anyhow::Result<()>
{
    let batch_limit = ProjectionBatchLimit::new(4)?;
    let work_budget = ReplayWorkBudget::new(10)?;
    let mut effective_seen = Vec::new();
    let run = fold_projection_replay_batches(batch_limit, work_budget, async |effective| {
        effective_seen.push(effective.get());
        let scanned = effective.get() as usize;
        Ok(ProjectionRun {
            scanned,
            applied: scanned,
            duplicates: 0,
            filtered: 0,
            skipped: 0,
            dead_lettered: 0,
            stop: ProjectionStop::Completed,
        })
    })
    .await?;
    assert_eq!(effective_seen, vec![4, 4, 2]);
    assert_eq!(run.scanned, 10);
    assert_eq!(run.stop, ProjectionReplayStop::BudgetExhausted);

    let narrowed = projection_replay_effective_batch_limit(batch_limit, 2)?;
    assert_eq!(narrowed.get(), 2);

    let mut remaining = 10usize;
    remaining = remaining.saturating_sub(4);
    assert!(matches!(
        projection_replay_decide_stop(remaining, batch_limit, 4, ProjectionStop::Completed),
        std::ops::ControlFlow::Continue(())
    ));
    remaining = 0;
    assert_eq!(
        projection_replay_decide_stop(remaining, batch_limit, 4, ProjectionStop::Completed),
        std::ops::ControlFlow::Break(ProjectionReplayStop::BudgetExhausted)
    );
    assert_eq!(
        projection_replay_decide_stop(3, batch_limit, 2, ProjectionStop::Completed),
        std::ops::ControlFlow::Break(ProjectionReplayStop::Engine(ProjectionStop::Completed))
    );
    assert_eq!(
        projection_replay_decide_stop(8, batch_limit, 4, ProjectionStop::Fenced),
        std::ops::ControlFlow::Break(ProjectionReplayStop::Engine(ProjectionStop::Fenced))
    );

    let tail =
        fold_projection_replay_batches(batch_limit, ReplayWorkBudget::new(20)?, async |_| {
            Ok(ProjectionRun {
                scanned: 2,
                applied: 2,
                duplicates: 0,
                filtered: 0,
                skipped: 0,
                dead_lettered: 0,
                stop: ProjectionStop::Completed,
            })
        })
        .await?;
    assert_eq!(
        tail.stop,
        ProjectionReplayStop::Engine(ProjectionStop::Completed)
    );

    let failed =
        fold_projection_replay_batches(batch_limit, ReplayWorkBudget::new(20)?, async |_| {
            Ok(ProjectionRun {
                scanned: 4,
                applied: 1,
                duplicates: 0,
                filtered: 0,
                skipped: 0,
                dead_lettered: 0,
                stop: ProjectionStop::ApplyFailed {
                    failed_at: consistency::Lsn::new(9),
                    kind: ProjectionApplyErrorKind::Permanent,
                    reason: ProjectionApplyErrorReason::PayloadMalformed,
                },
            })
        })
        .await?;
    assert!(matches!(
        failed.stop,
        ProjectionReplayStop::Engine(ProjectionStop::ApplyFailed { .. })
    ));
    Ok(())
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn projection_control_entrypoint_rejects_bad_args_before_runtime_setup() {
    // prepare-first: bad argv fails before any ProjectionOperatorRuntimeInputs is constructed.
    let Err(err) = prepare_projection_command_with_stdin(
        &args(&["projections"]),
        &mut operator_service_token_stdin(),
    ) else {
        panic!("missing subcommand must fail before runtime setup");
    };
    assert_operator_cli_err(&err, "projections");
    // Help must not consume stdin and must not require runtime.
    let mut stdin = Cursor::new(b"must-not-be-read\n");
    let ProjectionCommandPreparation::Help =
        prepare_projection_command_with_stdin(&args(&["projections", "--help"]), &mut stdin)
            .expect("help is local")
    else {
        panic!("help argv must not execute");
    };
    assert_eq!(stdin.position(), 0);
}

#[tokio::test]
async fn projection_control_lifecycle_dispatches_status_replay_and_swap_with_audit()
-> anyhow::Result<()> {
    let cases = [
        (
            ProjectionMaintenanceAction::Status,
            projection_control_args("status", &[]),
        ),
        (
            ProjectionMaintenanceAction::Replay,
            projection_control_args("replay", &["--batch-size", "7", "--max-events", "21"]),
        ),
        (
            ProjectionMaintenanceAction::Swap,
            projection_control_args("swap", &["--expected-active-generation", "v1"]),
        ),
    ];

    let mut command_ids = Vec::new();
    for (action, command_args) in cases {
        let runtime =
            FakeProjectionControlRuntime::registered(FakeProjectionCommandResult::Success);
        run_projection_control_command_with_runtime(&command_args, &runtime).await?;

        assert_eq!(runtime.setup_count(), 1);
        assert_eq!(runtime.shutdown_count(), 1);
        command_ids.push(assert_projection_lifecycle_audit(
            &runtime,
            action,
            FakeProjectionAuditOutcome::Success,
        ));
        assert_eq!(
            runtime.command_records(),
            vec![FakeProjectionCommandRecord {
                action,
                operator_subject: PROJECTION_FIXTURE_OPERATOR.to_owned(),
                registry_has_targets: true,
            }]
        );
    }
    assert_ne!(command_ids[0], command_ids[1]);
    assert_ne!(command_ids[1], command_ids[2]);
    assert_ne!(command_ids[0], command_ids[2]);

    Ok(())
}

#[tokio::test]
async fn projection_control_lifecycle_records_replay_dlx_failure_audit() -> anyhow::Result<()> {
    let runtime = FakeProjectionControlRuntime::registered(FakeProjectionCommandResult::Failure(
        "projection replay stopped before completion: stop=dead_letter_unsaved failed_at_lsn=42",
    ));
    let result = run_projection_control_command_with_runtime(
        &projection_control_args("replay", &["--batch-size", "1", "--max-events", "3"]),
        &runtime,
    )
    .await;
    let Err(err) = result else {
        anyhow::bail!("replay DLQ failure must fail the control command");
    };
    assert!(
        format!("{err:#}").contains("dead_letter_unsaved"),
        "unexpected error: {err:#}"
    );

    assert_eq!(runtime.setup_count(), 1);
    assert_eq!(runtime.shutdown_count(), 1);
    assert_projection_lifecycle_audit(
        &runtime,
        ProjectionMaintenanceAction::Replay,
        FakeProjectionAuditOutcome::Failure {
            reason: "run_error".to_owned(),
        },
    );
    assert_eq!(
        runtime.command_records(),
        vec![FakeProjectionCommandRecord {
            action: ProjectionMaintenanceAction::Replay,
            operator_subject: PROJECTION_FIXTURE_OPERATOR.to_owned(),
            registry_has_targets: true,
        }]
    );
    Ok(())
}

#[tokio::test]
async fn projection_control_lifecycle_records_stale_swap_refusal_audit() -> anyhow::Result<()> {
    let runtime = FakeProjectionControlRuntime::registered(FakeProjectionCommandResult::Failure(
        "projection shadow checkpoint is behind source high-water",
    ));
    let result = run_projection_control_command_with_runtime(
        &projection_control_args("swap", &["--expected-active-generation", "v1"]),
        &runtime,
    )
    .await;
    let Err(err) = result else {
        anyhow::bail!("stale swap must fail the control command");
    };
    assert!(
        format!("{err:#}").contains("source high-water"),
        "unexpected error: {err:#}"
    );

    assert_eq!(runtime.setup_count(), 1);
    assert_eq!(runtime.shutdown_count(), 1);
    assert_projection_lifecycle_audit(
        &runtime,
        ProjectionMaintenanceAction::Swap,
        FakeProjectionAuditOutcome::Failure {
            reason: "run_error".to_owned(),
        },
    );
    assert_eq!(
        runtime.command_records(),
        vec![FakeProjectionCommandRecord {
            action: ProjectionMaintenanceAction::Swap,
            operator_subject: PROJECTION_FIXTURE_OPERATOR.to_owned(),
            registry_has_targets: true,
        }]
    );
    Ok(())
}

#[tokio::test]
async fn projection_control_lifecycle_preserves_operator_auth_failure_audit() -> anyhow::Result<()>
{
    let runtime = FakeProjectionControlRuntime::auth_failure();
    let result = run_projection_control_command_with_runtime(
        &projection_control_args("status", &[]),
        &runtime,
    )
    .await;
    let Err(err) = result else {
        anyhow::bail!("operator auth failure must fail the control command");
    };
    assert!(
        format!("{err:#}").contains("operator auth"),
        "unexpected error: {err:#}"
    );

    assert_eq!(runtime.setup_count(), 1);
    assert_eq!(runtime.shutdown_count(), 1);
    assert!(runtime.command_records().is_empty());
    assert_projection_failure_audit_command_ids(&runtime);
    let audits = runtime.audit_records();
    assert_eq!(
        audits[0].subject,
        UNVERIFIED_PROJECTION_MAINTENANCE_OPERATOR
    );
    assert_eq!(audits[0].action, "projection.status.start");
    assert_eq!(audits[0].outcome, FakeProjectionAuditOutcome::Success);
    assert_eq!(
        audits[0].resource_id,
        projection_fixture_resource_id(ProjectionMaintenanceAction::Status)
    );
    assert_eq!(
        audits[1].subject,
        UNVERIFIED_PROJECTION_MAINTENANCE_OPERATOR
    );
    assert_eq!(audits[1].action, "projection.status.finish");
    assert_eq!(
        audits[1].outcome,
        FakeProjectionAuditOutcome::Failure {
            reason: "operator_auth".to_owned(),
        }
    );
    assert_eq!(
        audits[1].resource_id,
        projection_fixture_resource_id(ProjectionMaintenanceAction::Status)
    );
    Ok(())
}

#[tokio::test]
async fn projection_control_lifecycle_preserves_provider_config_failure_audit() -> anyhow::Result<()>
{
    let runtime = FakeProjectionControlRuntime::provider_config_failure();
    let result = run_projection_control_command_with_runtime(
        &projection_control_args("status", &[]),
        &runtime,
    )
    .await;
    let Err(err) = result else {
        anyhow::bail!("provider config failure must fail the control command");
    };
    assert!(
        format!("{err:#}").contains("operator verifier"),
        "unexpected error: {err:#}"
    );
    assert_projection_failure_audit_command_ids(&runtime);
    let audits = runtime.audit_records();
    assert_eq!(
        audits[1].outcome,
        FakeProjectionAuditOutcome::Failure {
            reason: "operator_provider_config".to_owned(),
        }
    );
    Ok(())
}

#[tokio::test]
async fn projection_control_lifecycle_closes_session_when_registry_gate_rejects()
-> anyhow::Result<()> {
    let runtime = FakeProjectionControlRuntime::unsupported(FakeProjectionCommandResult::Success);
    let result = run_projection_control_command_with_runtime(
        &projection_control_args("status", &[]),
        &runtime,
    )
    .await;
    let Err(err) = result else {
        anyhow::bail!("status for a disabled or omitted projection must fail");
    };
    assert!(
        format!("{err:#}").contains("projection is not activated by the assembly plan"),
        "unexpected error: {err:#}"
    );

    assert_eq!(runtime.setup_count(), 1);
    assert_eq!(runtime.shutdown_count(), 1);
    assert!(runtime.audit_records().is_empty());
    assert!(runtime.command_records().is_empty());
    Ok(())
}

const AUDIT_LEDGER_FIXTURE_OPERATOR_TENANT: &str = "00000000-0000-4000-8000-000000000001";
const AUDIT_LEDGER_FIXTURE_TENANT: &str = "00000000-0000-4000-8000-000000000002";
const AUDIT_LEDGER_FIXTURE_OTHER_TENANT: &str = "00000000-0000-4000-8000-000000000003";
const AUDIT_LEDGER_FIXTURE_OPERATOR: &str = "verified-audit-ledger-operator";

#[derive(Debug, Clone, PartialEq, Eq)]
enum FakeAuditLedgerVerifyAuditOutcome {
    Success,
    Failure { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FakeAuditLedgerVerifyAuditRecord {
    subject: String,
    action: String,
    outcome: FakeAuditLedgerVerifyAuditOutcome,
    resource_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FakeAuditLedgerVerifyCommandRecord {
    tenant: vocab::TenantId,
    batch: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FakeAuditLedgerVerifyOperator {
    Verified(&'static str),
    AuthFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FakeAuditLedgerVerifyResult {
    Success { checked_entries: u64 },
    Failure(&'static str),
}

struct FakeAuditLedgerVerifyRuntime {
    operator: FakeAuditLedgerVerifyOperator,
    verify_result: FakeAuditLedgerVerifyResult,
    audits: Mutex<Vec<FakeAuditLedgerVerifyAuditRecord>>,
    commands: Mutex<Vec<FakeAuditLedgerVerifyCommandRecord>>,
    setup_count: AtomicUsize,
    shutdown_count: AtomicUsize,
}

impl FakeAuditLedgerVerifyRuntime {
    fn success(checked_entries: u64) -> Self {
        Self::new(
            FakeAuditLedgerVerifyOperator::Verified(AUDIT_LEDGER_FIXTURE_OPERATOR),
            FakeAuditLedgerVerifyResult::Success { checked_entries },
        )
    }

    fn failure(reason: &'static str) -> Self {
        Self::new(
            FakeAuditLedgerVerifyOperator::Verified(AUDIT_LEDGER_FIXTURE_OPERATOR),
            FakeAuditLedgerVerifyResult::Failure(reason),
        )
    }

    fn auth_failure() -> Self {
        Self::new(
            FakeAuditLedgerVerifyOperator::AuthFailure,
            FakeAuditLedgerVerifyResult::Success { checked_entries: 0 },
        )
    }

    fn new(
        operator: FakeAuditLedgerVerifyOperator,
        verify_result: FakeAuditLedgerVerifyResult,
    ) -> Self {
        Self {
            operator,
            verify_result,
            audits: Mutex::new(Vec::new()),
            commands: Mutex::new(Vec::new()),
            setup_count: AtomicUsize::new(0),
            shutdown_count: AtomicUsize::new(0),
        }
    }

    fn audit_records(&self) -> Vec<FakeAuditLedgerVerifyAuditRecord> {
        match self.audits.lock() {
            Ok(records) => records.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    fn command_records(&self) -> Vec<FakeAuditLedgerVerifyCommandRecord> {
        match self.commands.lock() {
            Ok(records) => records.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    fn setup_count(&self) -> usize {
        self.setup_count.load(Ordering::Relaxed)
    }

    fn shutdown_count(&self) -> usize {
        self.shutdown_count.load(Ordering::Relaxed)
    }
}

impl AuditLedgerVerifyRuntime for FakeAuditLedgerVerifyRuntime {
    type Session = ();

    async fn connect_maintenance(&self) -> anyhow::Result<Self::Session> {
        self.setup_count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    async fn record_audit_ledger_verify_audit(
        &self,
        _session: &Self::Session,
        operator_subject: &str,
        action: &str,
        outcome: MaintenanceAuditOutcome<'_>,
        resource_id: &str,
    ) -> anyhow::Result<()> {
        let outcome = match outcome {
            MaintenanceAuditOutcome::Success => FakeAuditLedgerVerifyAuditOutcome::Success,
            MaintenanceAuditOutcome::Failure { reason } => {
                FakeAuditLedgerVerifyAuditOutcome::Failure {
                    reason: reason.to_owned(),
                }
            }
        };
        let record = FakeAuditLedgerVerifyAuditRecord {
            subject: operator_subject.to_owned(),
            action: action.to_owned(),
            outcome,
            resource_id: resource_id.to_owned(),
        };
        match self.audits.lock() {
            Ok(mut records) => records.push(record),
            Err(poisoned) => poisoned.into_inner().push(record),
        }
        Ok(())
    }

    async fn operator_subject(
        &self,
        session: &Self::Session,
        _parsed: &AuditLedgerVerifyArgs,
        resource_id: &str,
    ) -> anyhow::Result<String> {
        match self.operator {
            FakeAuditLedgerVerifyOperator::Verified(subject) => Ok(subject.to_owned()),
            FakeAuditLedgerVerifyOperator::AuthFailure => {
                self.record_audit_ledger_verify_audit(
                    session,
                    UNVERIFIED_AUDIT_LEDGER_VERIFY_OPERATOR,
                    "audit.ledger.verify.finish",
                    MaintenanceAuditOutcome::Failure {
                        reason: "operator_auth",
                    },
                    resource_id,
                )
                .await?;
                anyhow::bail!("audit ledger verify operator auth failed");
            }
        }
    }

    async fn verify_tenant(
        &self,
        _session: &Self::Session,
        parsed: &AuditLedgerVerifyArgs,
    ) -> anyhow::Result<AuditLedgerVerifyReport> {
        let record = FakeAuditLedgerVerifyCommandRecord {
            tenant: parsed.tenant,
            batch: parsed.batch.get(),
        };
        match self.commands.lock() {
            Ok(mut records) => records.push(record),
            Err(poisoned) => poisoned.into_inner().push(record),
        }
        match self.verify_result {
            FakeAuditLedgerVerifyResult::Success { checked_entries } => {
                Ok(AuditLedgerVerifyReport {
                    tenant: parsed.tenant,
                    checked_entries,
                })
            }
            FakeAuditLedgerVerifyResult::Failure(reason) => anyhow::bail!(reason),
        }
    }

    async fn shutdown(&self, _session: Self::Session) {
        self.shutdown_count.fetch_add(1, Ordering::Relaxed);
    }
}

fn audit_ledger_verify_args(extra: &[&str]) -> Vec<String> {
    let mut parts = vec![
        "audit-ledger",
        "verify",
        "--operator-service-token-stdin",
        "--operator-tenant",
        AUDIT_LEDGER_FIXTURE_OPERATOR_TENANT,
        "--tenant",
        AUDIT_LEDGER_FIXTURE_TENANT,
    ];
    parts.extend_from_slice(extra);
    args(&parts)
}

fn audit_ledger_fixture_resource_id(batch: u16) -> String {
    format!(
        "tenant={} batch_size={}",
        AUDIT_LEDGER_FIXTURE_TENANT, batch
    )
}

fn assert_audit_ledger_verify_lifecycle_audit(
    runtime: &FakeAuditLedgerVerifyRuntime,
    batch: u16,
    expected_finish: FakeAuditLedgerVerifyAuditOutcome,
) {
    let audits = runtime.audit_records();
    assert_eq!(audits.len(), 2);
    let resource_id = audit_ledger_fixture_resource_id(batch);
    assert_eq!(
        audits[0],
        FakeAuditLedgerVerifyAuditRecord {
            subject: UNVERIFIED_AUDIT_LEDGER_VERIFY_OPERATOR.to_owned(),
            action: "audit.ledger.verify.start".to_owned(),
            outcome: FakeAuditLedgerVerifyAuditOutcome::Success,
            resource_id: resource_id.clone(),
        }
    );
    assert_eq!(
        audits[1],
        FakeAuditLedgerVerifyAuditRecord {
            subject: AUDIT_LEDGER_FIXTURE_OPERATOR.to_owned(),
            action: "audit.ledger.verify.finish".to_owned(),
            outcome: expected_finish,
            resource_id,
        }
    );
}

#[test]
fn audit_ledger_verify_args_parse_typed_and_fail_closed() -> anyhow::Result<()> {
    let parsed = parse_audit_ledger_verify_args(&audit_ledger_verify_args(&["--batch-size", "7"]))?;
    assert_eq!(parsed.operator_service_token.as_str(), "opaque-token");
    assert_eq!(
        parsed.operator_tenant,
        vocab::TenantId::parse(AUDIT_LEDGER_FIXTURE_OPERATOR_TENANT)?
    );
    assert_eq!(
        parsed.tenant,
        vocab::TenantId::parse(AUDIT_LEDGER_FIXTURE_TENANT)?
    );
    assert_eq!(parsed.batch.get(), 7);
    assert!(is_audit_ledger_command(&args(&["audit-ledger", "verify"])));
    assert!(is_audit_ledger_command(&args(&["audit-ledger"])));
    let default_batch = parse_audit_ledger_verify_args(&audit_ledger_verify_args(&[]))?;
    assert_eq!(default_batch.batch.get(), 500);

    let cases = vec![
        ("missing namespace", args(&[])),
        ("missing subcommand", args(&["audit-ledger"])),
        ("unknown subcommand", args(&["audit-ledger", "tail"])),
        (
            "missing operator token",
            args(&[
                "audit-ledger",
                "verify",
                "--operator-tenant",
                AUDIT_LEDGER_FIXTURE_OPERATOR_TENANT,
                "--tenant",
                AUDIT_LEDGER_FIXTURE_TENANT,
            ]),
        ),
        (
            "missing tenant",
            args(&[
                "audit-ledger",
                "verify",
                "--operator-service-token-stdin",
                "--operator-tenant",
                AUDIT_LEDGER_FIXTURE_OPERATOR_TENANT,
            ]),
        ),
        (
            "missing flag value",
            args(&[
                "audit-ledger",
                "verify",
                "--operator-service-token-stdin",
                "--operator-tenant",
            ]),
        ),
        (
            "invalid batch zero",
            audit_ledger_verify_args(&["--batch-size", "0"]),
        ),
        (
            "invalid batch over max",
            audit_ledger_verify_args(&["--batch-size", "501"]),
        ),
        (
            "unsupported all tenants",
            audit_ledger_verify_args(&["--all-tenants"]),
        ),
        (
            "unsupported namespace",
            audit_ledger_verify_args(&["--namespace", "prod"]),
        ),
        ("unknown flag", audit_ledger_verify_args(&["--bogus"])),
        (
            "duplicate singleton flag",
            args(&[
                "audit-ledger",
                "verify",
                "--operator-service-token-stdin",
                "--operator-service-token-stdin",
                "--operator-tenant",
                AUDIT_LEDGER_FIXTURE_OPERATOR_TENANT,
                "--tenant",
                AUDIT_LEDGER_FIXTURE_TENANT,
            ]),
        ),
        (
            "duplicate tenant",
            audit_ledger_verify_args(&["--tenant", AUDIT_LEDGER_FIXTURE_TENANT]),
        ),
        // TooManyValues：presence flag 被赋 token 值时不得回显 SECRET_BAIT
        (
            "token assignment",
            args(&[
                "audit-ledger",
                "verify",
                "--operator-service-token-stdin=SECRET_BAIT",
                "--operator-tenant",
                AUDIT_LEDGER_FIXTURE_OPERATOR_TENANT,
                "--tenant",
                AUDIT_LEDGER_FIXTURE_TENANT,
            ]),
        ),
    ];

    for (name, candidate) in cases {
        let err = parse_audit_ledger_verify_args(&candidate)
            .expect_err(&format!("case must fail: {name}"));
        assert_operator_cli_err(&err, "audit-ledger");
        if name == "missing subcommand" {
            assert_operator_cli_err_bucket(&err, "audit-ledger", Some("missing subcommand"));
        }
    }
    Ok(())
}

#[test]
#[allow(non_snake_case)] // 验收过滤名含 SECRET_BAIT
fn audit_ledger_verify_args_SECRET_BAIT_too_many_values_is_redacted() {
    let err = parse_audit_ledger_verify_args(&args(&[
        "audit-ledger",
        "verify",
        "--operator-service-token-stdin=SECRET_BAIT",
        "--operator-tenant",
        AUDIT_LEDGER_FIXTURE_OPERATOR_TENANT,
        "--tenant",
        AUDIT_LEDGER_FIXTURE_TENANT,
    ]))
    .expect_err("assignment onto presence flag must fail closed");
    assert_operator_cli_err(&err, "audit-ledger");
}

#[test]
fn audit_ledger_verify_grants_authorize_exact_tenant() -> anyhow::Result<()> {
    let parsed = parse_audit_ledger_verify_args(&audit_ledger_verify_args(&[]))?;
    let grants = parse_audit_ledger_verify_grants(AUDIT_LEDGER_FIXTURE_TENANT)?;
    authorize_audit_ledger_verify_operator(&parsed, &grants)?;

    let wrong_tenant = parse_audit_ledger_verify_grants(AUDIT_LEDGER_FIXTURE_OTHER_TENANT)?;
    assert!(authorize_audit_ledger_verify_operator(&parsed, &wrong_tenant).is_err());
    assert!(parse_audit_ledger_verify_grants("").is_err());
    assert!(parse_audit_ledger_verify_grants("operator|tenant").is_err());
    assert!(parse_audit_ledger_verify_grants("operator|not-a-tenant").is_err());
    Ok(())
}

#[tokio::test]
async fn audit_ledger_verify_lifecycle_records_success_audit() -> anyhow::Result<()> {
    let runtime = FakeAuditLedgerVerifyRuntime::success(3);
    run_audit_ledger_verify_command_with_runtime(
        &audit_ledger_verify_args(&["--batch-size", "7"]),
        &runtime,
    )
    .await?;

    assert_eq!(runtime.setup_count(), 1);
    assert_eq!(runtime.shutdown_count(), 1);
    assert_audit_ledger_verify_lifecycle_audit(
        &runtime,
        7,
        FakeAuditLedgerVerifyAuditOutcome::Success,
    );
    assert_eq!(
        runtime.command_records(),
        vec![FakeAuditLedgerVerifyCommandRecord {
            tenant: vocab::TenantId::parse(AUDIT_LEDGER_FIXTURE_TENANT)?,
            batch: 7,
        }]
    );
    Ok(())
}

#[tokio::test]
async fn audit_ledger_verify_lifecycle_records_run_error_audit() -> anyhow::Result<()> {
    let runtime =
        FakeAuditLedgerVerifyRuntime::failure("audit ledger verify requires audit admin pool");
    let result =
        run_audit_ledger_verify_command_with_runtime(&audit_ledger_verify_args(&[]), &runtime)
            .await;
    let Err(err) = result else {
        anyhow::bail!("verify failure must fail the command");
    };
    assert!(
        format!("{err:#}").contains("audit admin pool"),
        "unexpected error: {err:#}"
    );

    assert_eq!(runtime.setup_count(), 1);
    assert_eq!(runtime.shutdown_count(), 1);
    assert_audit_ledger_verify_lifecycle_audit(
        &runtime,
        500,
        FakeAuditLedgerVerifyAuditOutcome::Failure {
            reason: "run_error".to_owned(),
        },
    );
    assert_eq!(runtime.command_records().len(), 1);
    Ok(())
}

#[tokio::test]
async fn audit_ledger_verify_lifecycle_preserves_operator_auth_failure_audit() -> anyhow::Result<()>
{
    let runtime = FakeAuditLedgerVerifyRuntime::auth_failure();
    let result =
        run_audit_ledger_verify_command_with_runtime(&audit_ledger_verify_args(&[]), &runtime)
            .await;
    let Err(err) = result else {
        anyhow::bail!("operator auth failure must fail the command");
    };
    assert!(
        format!("{err:#}").contains("operator auth"),
        "unexpected error: {err:#}"
    );

    assert_eq!(runtime.setup_count(), 1);
    assert_eq!(runtime.shutdown_count(), 1);
    assert!(runtime.command_records().is_empty());
    assert_eq!(
        runtime.audit_records(),
        vec![
            FakeAuditLedgerVerifyAuditRecord {
                subject: UNVERIFIED_AUDIT_LEDGER_VERIFY_OPERATOR.to_owned(),
                action: "audit.ledger.verify.start".to_owned(),
                outcome: FakeAuditLedgerVerifyAuditOutcome::Success,
                resource_id: audit_ledger_fixture_resource_id(500),
            },
            FakeAuditLedgerVerifyAuditRecord {
                subject: UNVERIFIED_AUDIT_LEDGER_VERIFY_OPERATOR.to_owned(),
                action: "audit.ledger.verify.finish".to_owned(),
                outcome: FakeAuditLedgerVerifyAuditOutcome::Failure {
                    reason: "operator_auth".to_owned(),
                },
                resource_id: audit_ledger_fixture_resource_id(500),
            },
        ]
    );
    Ok(())
}

const DLQ_FIXTURE_OPERATOR_TENANT: &str = "00000000-0000-4000-8000-000000000001";
const DLQ_FIXTURE_TENANT: &str = "00000000-0000-4000-8000-000000000002";
const DLQ_FIXTURE_OTHER_TENANT: &str = "00000000-0000-4000-8000-000000000003";
const DLQ_FIXTURE_OPERATOR: &str = "rss-maintenance-operator";
const DLQ_FIXTURE_DEAD_LETTER_ID: &str = "11111111-1111-4111-8111-111111111111";
const DLQ_FIXTURE_REPLAY_ID: &str = "evt-dlq-replay";
const DLQ_FIXTURE_EVENT_ID: &str = "evt-outbox-dlx";
const DLQ_FIXTURE_EVIDENCE_EVENT_ID: &str = "evt-outbox-compensation";
const DLQ_FIXTURE_CHANGE_TICKET: &str = "CHG-1742";

#[derive(Debug, Clone, PartialEq, Eq)]
enum FakeDlqAuditOutcome {
    Success,
    Failure { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FakeDlqAuditRecord {
    subject: String,
    action: String,
    outcome: FakeDlqAuditOutcome,
    resource_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FakeDlqCommandRecord {
    List {
        tenant: vocab::TenantId,
        source: Option<diport::DeadLetterSource>,
        producer_domain: Option<String>,
        consumer_domain: Option<String>,
        contract_id: Option<String>,
        limit: u32,
        cursor: Option<String>,
    },
    Inspect {
        tenant: vocab::TenantId,
        target: DlqInspectTarget,
    },
    ReplayDeadLetter {
        tenant: vocab::TenantId,
        dead_letter_id: String,
        replay_id: String,
    },
    RedriveOutbox {
        tenant: vocab::TenantId,
        event_id: String,
    },
    ResolveExpiredOutbox {
        tenant: vocab::TenantId,
        event_id: String,
        resolution_kind: OutboxExpiredResolutionKind,
        evidence_event_id: Option<String>,
        operator_subject: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FakeDlqOperator {
    Verified,
    AuthFailure,
    GrantFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FakeDlqStoreMode {
    Success,
    NotFound,
    Expired,
    EvidenceRejected,
    StoreFailure,
}

#[derive(Clone)]
struct FakeDlqStore {
    mode: FakeDlqStoreMode,
    commands: Arc<Mutex<Vec<FakeDlqCommandRecord>>>,
}

impl FakeDlqStore {
    fn new(mode: FakeDlqStoreMode, commands: Arc<Mutex<Vec<FakeDlqCommandRecord>>>) -> Self {
        Self { mode, commands }
    }

    fn push(&self, record: FakeDlqCommandRecord) {
        match self.commands.lock() {
            Ok(mut records) => records.push(record),
            Err(poisoned) => poisoned.into_inner().push(record),
        }
    }

    fn maybe_fail(&self) -> Result<(), DlqError> {
        match self.mode {
            FakeDlqStoreMode::Success
            | FakeDlqStoreMode::NotFound
            | FakeDlqStoreMode::Expired
            | FakeDlqStoreMode::EvidenceRejected => Ok(()),
            FakeDlqStoreMode::StoreFailure => Err(DlqError::Store),
        }
    }
}

impl DlqStore for FakeDlqStore {
    async fn list_dlq(&self, query: DlqListQuery) -> Result<eventexec::DlqListResult, DlqError> {
        self.push(FakeDlqCommandRecord::List {
            tenant: query.tenant(),
            source: query.source(),
            producer_domain: query.producer_domain().map(ToOwned::to_owned),
            consumer_domain: query.consumer_domain().map(ToOwned::to_owned),
            contract_id: query.contract_id().map(ToOwned::to_owned),
            limit: query.limit(),
            cursor: query.cursor().map(DlqCursor::encode),
        });
        self.maybe_fail()?;
        let rows = vec![dlq_summary(
            query.tenant(),
            eventexec::DlqEntryKind::DeadLetter,
        )];
        Ok(eventexec::DlqListResult::from_sorted_rows(&query, rows))
    }

    async fn inspect_dlq(&self, request: DlqInspectRequest) -> Result<DlqEntrySummary, DlqError> {
        self.push(FakeDlqCommandRecord::Inspect {
            tenant: request.tenant(),
            target: request.target().clone(),
        });
        self.maybe_fail()?;
        Ok(dlq_summary(request.tenant(), request.target().kind()))
    }

    async fn replay_dead_letter(
        &self,
        request: DlqReplayRequest,
    ) -> Result<eventexec::DlqReplayOutcome, DlqError> {
        self.push(FakeDlqCommandRecord::ReplayDeadLetter {
            tenant: request.tenant(),
            dead_letter_id: request.dead_letter_id().as_str().to_owned(),
            replay_id: request.replay_id().as_str().to_owned(),
        });
        self.maybe_fail()?;
        Ok(eventexec::DlqReplayOutcome::Inserted)
    }

    async fn redrive_outbox(
        &self,
        request: DlqRedriveRequest,
    ) -> Result<eventexec::DlqRedriveOutcome, DlqError> {
        self.push(FakeDlqCommandRecord::RedriveOutbox {
            tenant: request.tenant(),
            event_id: request.event_id().as_str().to_owned(),
        });
        match self.mode {
            FakeDlqStoreMode::Success => Ok(eventexec::DlqRedriveOutcome::Redriven),
            FakeDlqStoreMode::NotFound => Ok(eventexec::DlqRedriveOutcome::NotFound),
            FakeDlqStoreMode::Expired => Ok(eventexec::DlqRedriveOutcome::Expired),
            FakeDlqStoreMode::EvidenceRejected | FakeDlqStoreMode::StoreFailure => {
                Err(DlqError::Store)
            }
        }
    }

    async fn resolve_expired_outbox(
        &self,
        request: OutboxExpiredResolutionRequest,
    ) -> Result<OutboxExpiredResolutionOutcome, DlqError> {
        self.push(FakeDlqCommandRecord::ResolveExpiredOutbox {
            tenant: request.tenant(),
            event_id: request.event_id().as_str().to_owned(),
            resolution_kind: request.kind(),
            evidence_event_id: request
                .evidence_event_id()
                .map(|event_id| event_id.as_str().to_owned()),
            operator_subject: request.operator_subject().as_str().to_owned(),
        });
        match self.mode {
            FakeDlqStoreMode::Success => Ok(OutboxExpiredResolutionOutcome::Resolved),
            FakeDlqStoreMode::NotFound => Ok(OutboxExpiredResolutionOutcome::NotFound),
            FakeDlqStoreMode::Expired => Ok(OutboxExpiredResolutionOutcome::NotExpired),
            FakeDlqStoreMode::EvidenceRejected => {
                Ok(OutboxExpiredResolutionOutcome::EvidenceRejected)
            }
            FakeDlqStoreMode::StoreFailure => Err(DlqError::Store),
        }
    }
}

struct FakeDlqControlRuntime {
    operator: FakeDlqOperator,
    store_mode: FakeDlqStoreMode,
    audits: Mutex<Vec<FakeDlqAuditRecord>>,
    commands: Arc<Mutex<Vec<FakeDlqCommandRecord>>>,
    setup_count: AtomicUsize,
    shutdown_count: AtomicUsize,
}

impl FakeDlqControlRuntime {
    fn verified(store_mode: FakeDlqStoreMode) -> Self {
        Self::new(FakeDlqOperator::Verified, store_mode)
    }

    fn auth_failure() -> Self {
        Self::new(FakeDlqOperator::AuthFailure, FakeDlqStoreMode::Success)
    }

    fn grant_failure() -> Self {
        Self::new(FakeDlqOperator::GrantFailure, FakeDlqStoreMode::Success)
    }

    fn new(operator: FakeDlqOperator, store_mode: FakeDlqStoreMode) -> Self {
        Self {
            operator,
            store_mode,
            audits: Mutex::new(Vec::new()),
            commands: Arc::new(Mutex::new(Vec::new())),
            setup_count: AtomicUsize::new(0),
            shutdown_count: AtomicUsize::new(0),
        }
    }

    fn audit_records(&self) -> Vec<FakeDlqAuditRecord> {
        match self.audits.lock() {
            Ok(records) => records.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    fn command_records(&self) -> Vec<FakeDlqCommandRecord> {
        match self.commands.lock() {
            Ok(records) => records.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    fn setup_count(&self) -> usize {
        self.setup_count.load(Ordering::Relaxed)
    }

    fn shutdown_count(&self) -> usize {
        self.shutdown_count.load(Ordering::Relaxed)
    }
}

impl DlqControlRuntime for FakeDlqControlRuntime {
    type Session = ();
    type Store = FakeDlqStore;

    async fn connect_maintenance(&self) -> anyhow::Result<Self::Session> {
        self.setup_count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    async fn record_dlq_maintenance_audit(
        &self,
        _session: &Self::Session,
        operator_subject: &str,
        action: &str,
        outcome: MaintenanceAuditOutcome<'_>,
        resource_id: &str,
    ) -> anyhow::Result<()> {
        let outcome = match outcome {
            MaintenanceAuditOutcome::Success => FakeDlqAuditOutcome::Success,
            MaintenanceAuditOutcome::Failure { reason } => FakeDlqAuditOutcome::Failure {
                reason: reason.to_owned(),
            },
        };
        let record = FakeDlqAuditRecord {
            subject: operator_subject.to_owned(),
            action: action.to_owned(),
            outcome,
            resource_id: resource_id.to_owned(),
        };
        match self.audits.lock() {
            Ok(mut records) => records.push(record),
            Err(poisoned) => poisoned.into_inner().push(record),
        }
        Ok(())
    }

    async fn operator_subject(
        &self,
        session: &Self::Session,
        parsed: &DlqCliArgs,
        resource_id: &str,
    ) -> anyhow::Result<VerifiedOperatorSubject> {
        match self.operator {
            FakeDlqOperator::Verified => Ok(VerifiedOperatorSubject::from_authorized_receipt(
                AuthorizedDlqOperatorReceipt::from_authenticated_and_authorized(
                    vocab::ServiceCallerDomain::MaintenanceOperator,
                ),
            )),
            FakeDlqOperator::AuthFailure => {
                self.record_dlq_maintenance_audit(
                    session,
                    UNVERIFIED_DLQ_OPERATOR,
                    &format!("dlq.{}.finish", parsed.command.action().as_str()),
                    MaintenanceAuditOutcome::Failure {
                        reason: "operator_auth",
                    },
                    resource_id,
                )
                .await?;
                anyhow::bail!("DLQ operator auth failed");
            }
            FakeDlqOperator::GrantFailure => {
                self.record_dlq_maintenance_audit(
                    session,
                    DLQ_FIXTURE_OPERATOR,
                    &format!("dlq.{}.finish", parsed.command.action().as_str()),
                    MaintenanceAuditOutcome::Failure {
                        reason: "operator_authorization",
                    },
                    resource_id,
                )
                .await?;
                anyhow::bail!("DLQ operator grant failed");
            }
        }
    }

    fn dlq_store(
        &self,
        _session: &Self::Session,
        _command: &DlqCliCommand,
    ) -> anyhow::Result<Self::Store> {
        Ok(FakeDlqStore::new(
            self.store_mode,
            Arc::clone(&self.commands),
        ))
    }

    async fn shutdown(&self, _session: Self::Session) {
        self.shutdown_count.fetch_add(1, Ordering::Relaxed);
    }
}

fn dlq_summary(tenant: vocab::TenantId, kind: eventexec::DlqEntryKind) -> DlqEntrySummary {
    DlqEntrySummary::new(
        kind,
        "dlq-row-1",
        diport::DeadLetterSource::Consumer,
        tenant,
        "msg-1",
        "identity",
        Some("audit".to_owned()),
        "identity.session-created",
        "identity.session.created",
        Some("identity.session.consumer".to_owned()),
        12,
        "max retries exhausted",
        3,
        1_700_000_000,
    )
}

fn dlq_control_args(subcommand: &str, extra: &[&str]) -> Vec<String> {
    let mut parts = vec![
        "dlq",
        subcommand,
        "--operator-service-token-stdin",
        "--operator-tenant",
        DLQ_FIXTURE_OPERATOR_TENANT,
        "--tenant",
        DLQ_FIXTURE_TENANT,
    ];
    parts.extend_from_slice(extra);
    args(&parts)
}

fn dlq_fixture_resource_id(action: DlqMaintenanceAction, target: &str) -> String {
    format!(
        "operation={} tenant={} {}",
        action.as_str(),
        DLQ_FIXTURE_TENANT,
        target
    )
}

fn assert_dlq_lifecycle_audit(
    runtime: &FakeDlqControlRuntime,
    action: DlqMaintenanceAction,
    target: &str,
    expected_finish: FakeDlqAuditOutcome,
) {
    let audits = runtime.audit_records();
    assert_eq!(audits.len(), 2);
    let resource_id = dlq_fixture_resource_id(action, target);
    assert_eq!(
        audits[0],
        FakeDlqAuditRecord {
            subject: UNVERIFIED_DLQ_OPERATOR.to_owned(),
            action: format!("dlq.{}.start", action.as_str()),
            outcome: FakeDlqAuditOutcome::Success,
            resource_id: resource_id.clone(),
        }
    );
    assert_eq!(
        audits[1],
        FakeDlqAuditRecord {
            subject: DLQ_FIXTURE_OPERATOR.to_owned(),
            action: format!("dlq.{}.finish", action.as_str()),
            outcome: expected_finish,
            resource_id,
        }
    );
}

#[test]
fn dlq_args_parse_list_and_inspect() -> anyhow::Result<()> {
    let default_list = parse_dlq_args(&dlq_control_args("list", &[]))?;
    assert!(matches!(
        default_list.command,
        DlqCliCommand::List { limit: 100, .. }
    ));

    let list = parse_dlq_args(&dlq_control_args(
        "list",
        &[
            "--source",
            "consumer",
            "--producer-domain",
            "identity",
            "--consumer-domain",
            "audit",
            "--contract-id",
            "identity.session-created",
            "--limit",
            "7",
            "--cursor",
            "1700000000:dead_letter:row-1",
        ],
    ))?;
    assert_eq!(list.operator_service_token.as_str(), "opaque-token");
    assert_eq!(
        list.operator_tenant,
        vocab::TenantId::parse(DLQ_FIXTURE_OPERATOR_TENANT)?
    );
    assert_eq!(list.tenant, vocab::TenantId::parse(DLQ_FIXTURE_TENANT)?);
    assert!(matches!(
        list.command,
        DlqCliCommand::List {
            source: Some(diport::DeadLetterSource::Consumer),
            ref producer_domain,
            ref consumer_domain,
            ref contract_id,
            limit: 7,
            ref cursor,
        } if producer_domain.as_deref() == Some("identity")
            && consumer_domain.as_deref() == Some("audit")
            && contract_id.as_deref() == Some("identity.session-created")
            && cursor.as_ref().map(DlqCursor::encode).as_deref()
                == Some("1700000000:dead_letter:row-1")
    ));

    let inspect = parse_dlq_args(&dlq_control_args(
        "inspect",
        &["--kind", "outbox-dlx", "--id", DLQ_FIXTURE_EVENT_ID],
    ))?;
    assert!(matches!(
        inspect.command,
        DlqCliCommand::Inspect {
            target: DlqInspectTarget::OutboxDlx(ref event_id),
        } if event_id.as_str() == DLQ_FIXTURE_EVENT_ID
    ));
    Ok(())
}

#[test]
fn dlq_args_parse_replay_redrive_and_expired_resolution() -> anyhow::Result<()> {
    let replay = parse_dlq_args(&dlq_control_args(
        "replay-dead-letter",
        &[
            "--dead-letter-id",
            DLQ_FIXTURE_DEAD_LETTER_ID,
            "--replay-id",
            DLQ_FIXTURE_REPLAY_ID,
        ],
    ))?;
    assert!(matches!(
        replay.command,
        DlqCliCommand::ReplayDeadLetter {
            ref dead_letter_id,
            ref replay_id,
        } if dead_letter_id.as_str() == DLQ_FIXTURE_DEAD_LETTER_ID
            && replay_id.as_str() == DLQ_FIXTURE_REPLAY_ID
    ));

    let redrive = parse_dlq_args(&dlq_control_args(
        "redrive-outbox",
        &["--event-id", DLQ_FIXTURE_EVENT_ID],
    ))?;
    assert!(matches!(
        redrive.command,
        DlqCliCommand::RedriveOutbox { ref event_id }
            if event_id.as_str() == DLQ_FIXTURE_EVENT_ID
    ));

    let accepted_gap = parse_dlq_args(&dlq_control_args(
        "resolve-expired-outbox",
        &[
            "--event-id",
            DLQ_FIXTURE_EVENT_ID,
            "--change-ticket",
            DLQ_FIXTURE_CHANGE_TICKET,
            "--resolution-kind",
            "accepted_gap",
        ],
    ))?;
    assert!(matches!(
        accepted_gap.command,
        DlqCliCommand::ResolveExpiredOutbox {
            ref event_id,
            ref change_ticket,
            resolution_kind: OutboxExpiredResolutionKind::AcceptedGap,
            evidence_event_id: None,
        } if event_id.as_str() == DLQ_FIXTURE_EVENT_ID
            && change_ticket.as_str() == DLQ_FIXTURE_CHANGE_TICKET
    ));

    let compensated = parse_dlq_args(&dlq_control_args(
        "resolve-expired-outbox",
        &[
            "--event-id",
            DLQ_FIXTURE_EVENT_ID,
            "--change-ticket",
            DLQ_FIXTURE_CHANGE_TICKET,
            "--resolution-kind",
            "compensated",
            "--evidence-event-id",
            DLQ_FIXTURE_EVIDENCE_EVENT_ID,
        ],
    ))?;
    assert!(matches!(
        compensated.command,
        DlqCliCommand::ResolveExpiredOutbox {
            resolution_kind: OutboxExpiredResolutionKind::Compensated,
            evidence_event_id: Some(ref evidence_event_id),
            ..
        } if evidence_event_id.as_str() == DLQ_FIXTURE_EVIDENCE_EVENT_ID
    ));
    Ok(())
}

#[test]
fn dlq_args_fail_closed_on_missing_invalid_duplicate_or_unknown_flags() {
    let clap_cases = [
        ("missing namespace", args(&[])),
        ("missing subcommand", args(&["dlq"])),
        ("unknown subcommand", args(&["dlq", "skip"])),
        (
            "missing operator token",
            args(&[
                "dlq",
                "list",
                "--operator-tenant",
                DLQ_FIXTURE_OPERATOR_TENANT,
                "--tenant",
                DLQ_FIXTURE_TENANT,
            ]),
        ),
        (
            "invalid tenant",
            args(&[
                "dlq",
                "list",
                "--operator-service-token-stdin",
                "--operator-tenant",
                DLQ_FIXTURE_OPERATOR_TENANT,
                "--tenant",
                "not-a-uuid",
            ]),
        ),
        (
            "invalid cursor",
            dlq_control_args("list", &["--cursor", "not-a-cursor"]),
        ),
        (
            "duplicate tenant",
            dlq_control_args("list", &["--tenant", DLQ_FIXTURE_TENANT]),
        ),
        (
            "duplicate stdin flag",
            args(&[
                "dlq",
                "list",
                "--operator-service-token-stdin",
                "--operator-service-token-stdin",
                "--operator-tenant",
                DLQ_FIXTURE_OPERATOR_TENANT,
                "--tenant",
                DLQ_FIXTURE_TENANT,
            ]),
        ),
        (
            "unknown flag",
            dlq_control_args(
                "redrive-outbox",
                &["--event-id", DLQ_FIXTURE_EVENT_ID, "--bogus"],
            ),
        ),
        (
            "wrong flag for subcommand",
            dlq_control_args(
                "redrive-outbox",
                &["--event-id", DLQ_FIXTURE_EVENT_ID, "--limit", "1"],
            ),
        ),
        (
            "dirty change ticket is rejected",
            dlq_control_args(
                "resolve-expired-outbox",
                &[
                    "--event-id",
                    DLQ_FIXTURE_EVENT_ID,
                    "--change-ticket",
                    " CHG-1742",
                    "--resolution-kind",
                    "accepted_gap",
                ],
            ),
        ),
        ("limit zero", dlq_control_args("list", &["--limit", "0"])),
        (
            "limit over max",
            dlq_control_args("list", &["--limit", "501"]),
        ),
        // TooManyValues：presence flag 被赋 token 值时不得回显 SECRET_BAIT
        (
            "token assignment",
            args(&[
                "dlq",
                "list",
                "--operator-service-token-stdin=SECRET_BAIT",
                "--operator-tenant",
                DLQ_FIXTURE_OPERATOR_TENANT,
                "--tenant",
                DLQ_FIXTURE_TENANT,
            ]),
        ),
    ];

    for (name, candidate) in clap_cases {
        let err = parse_dlq_args(&candidate).expect_err(&format!("case must fail closed: {name}"));
        assert_operator_cli_err(&err, "dlq");
        if name == "missing subcommand" {
            assert_operator_cli_err_bucket(&err, "dlq", Some("missing subcommand"));
        }
    }

    // Post-clap RSS ensures / typed binding (not fully expressible as clap ValueValidation alone).
    let ensure_cases = [
        (
            "invalid inspect id",
            dlq_control_args("inspect", &["--kind", "dead-letter", "--id", "not-a-uuid"]),
        ),
        (
            "accepted gap rejects evidence",
            dlq_control_args(
                "resolve-expired-outbox",
                &[
                    "--event-id",
                    DLQ_FIXTURE_EVENT_ID,
                    "--change-ticket",
                    DLQ_FIXTURE_CHANGE_TICKET,
                    "--resolution-kind",
                    "accepted_gap",
                    "--evidence-event-id",
                    DLQ_FIXTURE_EVIDENCE_EVENT_ID,
                ],
            ),
        ),
        (
            "compensated requires evidence",
            dlq_control_args(
                "resolve-expired-outbox",
                &[
                    "--event-id",
                    DLQ_FIXTURE_EVENT_ID,
                    "--change-ticket",
                    DLQ_FIXTURE_CHANGE_TICKET,
                    "--resolution-kind",
                    "compensated",
                ],
            ),
        ),
    ];
    for (name, candidate) in ensure_cases {
        let err = parse_dlq_args(&candidate).expect_err(&format!("case must fail closed: {name}"));
        let message = err.to_string();
        match name {
            "invalid inspect id" => {
                assert_eq!(message, "dlq: invalid value; see --help");
            }
            "accepted gap rejects evidence" => {
                assert!(
                    message.contains("accepted_gap forbids"),
                    "case {name}: {message}"
                );
            }
            "compensated requires evidence" => {
                assert!(
                    message.contains("compensated requires"),
                    "case {name}: {message}"
                );
            }
            _ => panic!("unexpected ensure case: {name}"),
        }
        assert!(
            !message.contains("SECRET_BAIT"),
            "case {name} leaked SECRET_BAIT: {message}"
        );
    }
}

#[test]
#[allow(non_snake_case)] // 验收过滤名含 SECRET_BAIT
fn dlq_args_SECRET_BAIT_inspect_kind_and_id_are_redacted() {
    let kind_err = parse_dlq_args(&dlq_control_args(
        "inspect",
        &["--kind", "SECRET_BAIT", "--id", DLQ_FIXTURE_EVENT_ID],
    ))
    .expect_err("SECRET_BAIT kind must fail closed");
    assert_eq!(kind_err.to_string(), "dlq: invalid value; see --help");
    assert!(!kind_err.to_string().contains("SECRET_BAIT"));

    let id_err = parse_dlq_args(&dlq_control_args(
        "inspect",
        &["--kind", "dead-letter", "--id", "SECRET_BAIT"],
    ))
    .expect_err("SECRET_BAIT id must fail closed");
    assert_eq!(id_err.to_string(), "dlq: invalid value; see --help");
    assert!(!id_err.to_string().contains("SECRET_BAIT"));
}

#[test]
#[allow(non_snake_case)] // 验收过滤名含 SECRET_BAIT
fn dlq_args_SECRET_BAIT_too_many_values_is_redacted() {
    let err = parse_dlq_args(&args(&[
        "dlq",
        "list",
        "--operator-service-token-stdin=SECRET_BAIT",
        "--operator-tenant",
        DLQ_FIXTURE_OPERATOR_TENANT,
        "--tenant",
        DLQ_FIXTURE_TENANT,
    ]))
    .expect_err("assignment onto presence flag must fail closed");
    assert_operator_cli_err(&err, "dlq");
}

#[test]
fn dlq_operator_grants_authorize_exact_action_and_tenant() -> anyhow::Result<()> {
    let parsed = parse_dlq_args(&dlq_control_args(
        "redrive-outbox",
        &["--event-id", DLQ_FIXTURE_EVENT_ID],
    ))?;
    let grants = parse_dlq_operator_grants(&format!("redrive-outbox|{DLQ_FIXTURE_TENANT}"))?;
    authorize_dlq_operator(&parsed, &grants)?;

    let wrong_action = parse_dlq_operator_grants(&format!("list|{DLQ_FIXTURE_TENANT}"))?;
    assert!(authorize_dlq_operator(&parsed, &wrong_action).is_err());

    let wrong_tenant =
        parse_dlq_operator_grants(&format!("redrive-outbox|{DLQ_FIXTURE_OTHER_TENANT}"))?;
    assert!(authorize_dlq_operator(&parsed, &wrong_tenant).is_err());

    let resolution = parse_dlq_args(&dlq_control_args(
        "resolve-expired-outbox",
        &[
            "--event-id",
            DLQ_FIXTURE_EVENT_ID,
            "--change-ticket",
            DLQ_FIXTURE_CHANGE_TICKET,
            "--resolution-kind",
            "accepted_gap",
        ],
    ))?;
    let resolution_grant =
        parse_dlq_operator_grants(&format!("resolve-expired-outbox|{DLQ_FIXTURE_TENANT}"))?;
    authorize_dlq_operator(&resolution, &resolution_grant)?;
    assert!(authorize_dlq_operator(&resolution, &grants).is_err());

    assert!(parse_dlq_operator_grants("").is_err());
    assert!(parse_dlq_operator_grants("subject|skip|tenant").is_err());
    Ok(())
}

#[test]
fn reconcile_operator_args_and_grants_are_exactly_tenant_scoped() -> anyhow::Result<()> {
    let tenant = "018f5d8a-7b6c-7d2e-8a1b-1234567890ab";
    let target = "018f5d8a-7b6c-7d2e-8a1b-1234567890ac";
    let parsed = parse_reconcile_target_args(&args(&[
        "reconcile-target",
        "resume",
        "--operator-service-token-stdin",
        "--operator-tenant",
        tenant,
        "--tenant",
        tenant,
        "--target-id",
        target,
    ]))?;
    let grants = parse_reconcile_operator_grants(&format!("resume|{tenant}"))?;
    authorize_reconcile_operator(&parsed, &grants)?;
    assert!(
        authorize_reconcile_operator(
            &parsed,
            &parse_reconcile_operator_grants(&format!("inspect|{tenant}"))?,
        )
        .is_err()
    );
    assert!(parse_reconcile_operator_grants("operator|resume|tenant").is_err());
    assert!(parse_reconcile_operator_grants("resume|not-a-uuid").is_err());
    Ok(())
}

#[test]
fn reconcile_operator_args_fail_closed() {
    let tenant = "018f5d8a-7b6c-7d2e-8a1b-1234567890ab";
    let target = "018f5d8a-7b6c-7d2e-8a1b-1234567890ac";
    // Clap path: missing subcommand / missing required flags / unknown action all fail-closed.
    // Do not assert on clap usage text — only parse Outcome.
    for candidate in [
        args(&["reconcile-target"]),
        args(&[
            "reconcile-target",
            "resume",
            "--operator-service-token-stdin",
            "--operator-tenant",
            tenant,
            "--tenant",
            tenant,
        ]),
        args(&[
            "reconcile-target",
            "resume",
            "--operator-tenant",
            tenant,
            "--tenant",
            tenant,
            "--target-id",
            target,
        ]),
        // 缺 --operator-tenant
        args(&[
            "reconcile-target",
            "resume",
            "--operator-service-token-stdin",
            "--tenant",
            tenant,
            "--target-id",
            target,
        ]),
        // 缺 --tenant
        args(&[
            "reconcile-target",
            "resume",
            "--operator-service-token-stdin",
            "--operator-tenant",
            tenant,
            "--target-id",
            target,
        ]),
        // 非法 --tenant
        args(&[
            "reconcile-target",
            "resume",
            "--operator-service-token-stdin",
            "--operator-tenant",
            tenant,
            "--tenant",
            "not-a-uuid",
            "--target-id",
            target,
        ]),
        args(&[
            "reconcile-target",
            "unknown",
            "--operator-service-token-stdin",
            "--operator-tenant",
            tenant,
            "--tenant",
            tenant,
            "--target-id",
            target,
        ]),
        args(&[
            "reconcile-target",
            "resume",
            "--operator-service-token-stdin",
            "--operator-tenant",
            "not-a-uuid",
            "--tenant",
            tenant,
            "--target-id",
            target,
        ]),
        args(&[
            "reconcile-target",
            "resume",
            "--operator-service-token-stdin",
            "--operator-tenant",
            tenant,
            "--tenant",
            tenant,
            "--target-id",
            "not-a-uuid",
        ]),
        // 未知 flag
        args(&[
            "reconcile-target",
            "resume",
            "--operator-service-token-stdin",
            "--operator-tenant",
            tenant,
            "--tenant",
            tenant,
            "--target-id",
            target,
            "--bogus",
        ]),
        // TooManyValues：presence flag 被赋 token 值时不得回显 SECRET_BAIT
        args(&[
            "reconcile-target",
            "resume",
            "--operator-service-token-stdin=SECRET_BAIT",
            "--operator-tenant",
            tenant,
            "--tenant",
            tenant,
            "--target-id",
            target,
        ]),
    ] {
        let err = parse_reconcile_target_args(&candidate).expect_err("expected clap fail-closed");
        assert_operator_cli_err(&err, "reconcile-target");
    }
}

#[test]
#[allow(non_snake_case)] // 验收过滤名含 SECRET_BAIT
fn reconcile_operator_args_SECRET_BAIT_too_many_values_is_redacted() {
    let err = parse_reconcile_target_args(&args(&[
        "reconcile-target",
        "resume",
        "--operator-service-token-stdin=SECRET_BAIT",
        "--operator-tenant",
        "018f5d8a-7b6c-7d2e-8a1b-1234567890ab",
        "--tenant",
        "018f5d8a-7b6c-7d2e-8a1b-1234567890ab",
        "--target-id",
        "018f5d8a-7b6c-7d2e-8a1b-1234567890ac",
    ]))
    .expect_err("TooManyValues must fail closed");
    assert_operator_cli_err(&err, "reconcile-target");
}

#[test]
fn reconcile_operator_summary_is_payload_free() -> anyhow::Result<()> {
    let tenant = vocab::TenantId::parse("018f5d8a-7b6c-7d2e-8a1b-1234567890ab")?;
    let summary = eventexec::ReconcileTargetSummary::new(
        tenant,
        "018f5d8a-7b6c-7d2e-8a1b-1234567890ac".to_owned(),
        "device".to_owned(),
        "device".to_owned(),
        eventexec::ReconcileTargetStatus::Disabled,
        Some(eventexec::ReconcileQuarantineReason::FactConflict),
    )?;
    let rendered = reconcile_summary_json(&summary)?;
    assert!(rendered.contains("\"disabledReason\":\"fact_conflict\""));
    for forbidden in ["payload", "metadata", "fingerprint", "resourceId"] {
        assert!(!rendered.contains(forbidden), "must not expose {forbidden}");
    }
    Ok(())
}

#[tokio::test]
async fn dlq_control_lifecycle_dispatches_commands_with_audit() -> anyhow::Result<()> {
    let cases = [
        (
            DlqMaintenanceAction::List,
            dlq_control_args(
                "list",
                &[
                    "--source",
                    "consumer",
                    "--producer-domain",
                    "identity",
                    "--consumer-domain",
                    "audit",
                    "--contract-id",
                    "identity.session-created",
                    "--limit",
                    "7",
                    "--cursor",
                    "1700000000:dead_letter:row-1",
                ],
            ),
            "source=consumer producer_domain=identity consumer_domain=audit contract_id=identity.session-created",
            FakeDlqCommandRecord::List {
                tenant: vocab::TenantId::parse(DLQ_FIXTURE_TENANT)?,
                source: Some(diport::DeadLetterSource::Consumer),
                producer_domain: Some("identity".to_owned()),
                consumer_domain: Some("audit".to_owned()),
                contract_id: Some("identity.session-created".to_owned()),
                limit: 7,
                cursor: Some("1700000000:dead_letter:row-1".to_owned()),
            },
        ),
        (
            DlqMaintenanceAction::Inspect,
            dlq_control_args(
                "inspect",
                &["--kind", "dead-letter", "--id", DLQ_FIXTURE_DEAD_LETTER_ID],
            ),
            "kind=dead_letter dead_letter_id=11111111-1111-4111-8111-111111111111",
            FakeDlqCommandRecord::Inspect {
                tenant: vocab::TenantId::parse(DLQ_FIXTURE_TENANT)?,
                target: DlqInspectTarget::DeadLetter(DeadLetterId::parse(
                    DLQ_FIXTURE_DEAD_LETTER_ID,
                )?),
            },
        ),
        (
            DlqMaintenanceAction::ReplayDeadLetter,
            dlq_control_args(
                "replay-dead-letter",
                &[
                    "--dead-letter-id",
                    DLQ_FIXTURE_DEAD_LETTER_ID,
                    "--replay-id",
                    DLQ_FIXTURE_REPLAY_ID,
                ],
            ),
            "dead_letter_id=11111111-1111-4111-8111-111111111111 replay_id=evt-dlq-replay",
            FakeDlqCommandRecord::ReplayDeadLetter {
                tenant: vocab::TenantId::parse(DLQ_FIXTURE_TENANT)?,
                dead_letter_id: DLQ_FIXTURE_DEAD_LETTER_ID.to_owned(),
                replay_id: DLQ_FIXTURE_REPLAY_ID.to_owned(),
            },
        ),
        (
            DlqMaintenanceAction::RedriveOutbox,
            dlq_control_args("redrive-outbox", &["--event-id", DLQ_FIXTURE_EVENT_ID]),
            "event_id=evt-outbox-dlx",
            FakeDlqCommandRecord::RedriveOutbox {
                tenant: vocab::TenantId::parse(DLQ_FIXTURE_TENANT)?,
                event_id: DLQ_FIXTURE_EVENT_ID.to_owned(),
            },
        ),
        (
            DlqMaintenanceAction::ResolveExpiredOutbox,
            dlq_control_args(
                "resolve-expired-outbox",
                &[
                    "--event-id",
                    DLQ_FIXTURE_EVENT_ID,
                    "--change-ticket",
                    DLQ_FIXTURE_CHANGE_TICKET,
                    "--resolution-kind",
                    "accepted_gap",
                ],
            ),
            "event_id=evt-outbox-dlx resolution_kind=accepted_gap",
            FakeDlqCommandRecord::ResolveExpiredOutbox {
                tenant: vocab::TenantId::parse(DLQ_FIXTURE_TENANT)?,
                event_id: DLQ_FIXTURE_EVENT_ID.to_owned(),
                resolution_kind: OutboxExpiredResolutionKind::AcceptedGap,
                evidence_event_id: None,
                operator_subject: DLQ_FIXTURE_OPERATOR.to_owned(),
            },
        ),
    ];

    for (action, command_args, target, expected_command) in cases {
        let runtime = FakeDlqControlRuntime::verified(FakeDlqStoreMode::Success);
        run_dlq_control_command_with_runtime(&command_args, &runtime).await?;

        assert_eq!(runtime.setup_count(), 1);
        assert_eq!(runtime.shutdown_count(), 1);
        assert_dlq_lifecycle_audit(&runtime, action, target, FakeDlqAuditOutcome::Success);
        assert_eq!(runtime.command_records(), vec![expected_command]);
    }

    Ok(())
}

#[tokio::test]
async fn dlq_control_lifecycle_audits_command_failure() -> anyhow::Result<()> {
    let runtime = FakeDlqControlRuntime::verified(FakeDlqStoreMode::StoreFailure);
    let result = run_dlq_control_command_with_runtime(
        &dlq_control_args("redrive-outbox", &["--event-id", DLQ_FIXTURE_EVENT_ID]),
        &runtime,
    )
    .await;
    let Err(err) = result else {
        anyhow::bail!("store failure must fail");
    };
    assert!(
        format!("{err:#}").contains("operation=redrive-outbox tenant="),
        "DLQ command failure must include operation and tenant context: {err:#}"
    );
    assert_eq!(runtime.setup_count(), 1);
    assert_eq!(runtime.shutdown_count(), 1);
    assert_dlq_lifecycle_audit(
        &runtime,
        DlqMaintenanceAction::RedriveOutbox,
        "event_id=evt-outbox-dlx",
        FakeDlqAuditOutcome::Failure {
            reason: "run_error".to_owned(),
        },
    );
    assert!(matches!(
        runtime.command_records().as_slice(),
        [FakeDlqCommandRecord::RedriveOutbox { .. }]
    ));
    Ok(())
}

#[tokio::test]
async fn dlq_control_lifecycle_audits_expired_redrive_and_returns_error() -> anyhow::Result<()> {
    let tenant = vocab::TenantId::parse(DLQ_FIXTURE_TENANT)?;
    let event_id = IdemKey::parse(DLQ_FIXTURE_EVENT_ID)?;
    let output = dlq_redrive_result_line(tenant, &event_id, DlqRedriveOutcome::Expired);
    assert_eq!(
        output,
        format!(
            "operation=redrive-outbox tenant={DLQ_FIXTURE_TENANT} \
             event_id={DLQ_FIXTURE_EVENT_ID} outcome=expired"
        )
    );

    let runtime = FakeDlqControlRuntime::verified(FakeDlqStoreMode::Expired);
    let result = run_dlq_control_command_with_runtime(
        &dlq_control_args("redrive-outbox", &["--event-id", DLQ_FIXTURE_EVENT_ID]),
        &runtime,
    )
    .await;
    let Err(err) = result else {
        anyhow::bail!("expired same-ID redrive must fail");
    };
    let error_text = format!("{err:#}");
    assert!(
        error_text.contains("expired"),
        "expired redrive must remain distinguishable from a store failure: {error_text}"
    );
    assert!(
        !error_text.to_ascii_lowercase().contains("store"),
        "expired redrive must not be disguised as a store error: {error_text}"
    );
    assert_eq!(runtime.setup_count(), 1);
    assert_eq!(runtime.shutdown_count(), 1);
    assert_dlq_lifecycle_audit(
        &runtime,
        DlqMaintenanceAction::RedriveOutbox,
        "event_id=evt-outbox-dlx",
        FakeDlqAuditOutcome::Failure {
            reason: "expired".to_owned(),
        },
    );
    for audit in runtime.audit_records() {
        for forbidden in ["payload", "metadata", "partition", "error"] {
            assert!(
                !audit.resource_id.contains(forbidden),
                "audit resource must exclude {forbidden}: {}",
                audit.resource_id
            );
        }
    }
    assert!(matches!(
        runtime.command_records().as_slice(),
        [FakeDlqCommandRecord::RedriveOutbox { .. }]
    ));
    Ok(())
}

#[tokio::test]
async fn dlq_verified_subject_is_injected_and_resolution_rejections_are_safely_audited()
-> anyhow::Result<()> {
    let command = dlq_control_args(
        "resolve-expired-outbox",
        &[
            "--event-id",
            DLQ_FIXTURE_EVENT_ID,
            "--change-ticket",
            DLQ_FIXTURE_CHANGE_TICKET,
            "--resolution-kind",
            "accepted_gap",
        ],
    );
    for (mode, reason) in [
        (FakeDlqStoreMode::Expired, "not_expired"),
        (FakeDlqStoreMode::EvidenceRejected, "evidence_rejected"),
    ] {
        let runtime = FakeDlqControlRuntime::verified(mode);
        let result = run_dlq_control_command_with_runtime(&command, &runtime).await;
        let Err(error) = result else {
            anyhow::bail!("terminal resolution rejection must return a non-zero outcome");
        };
        assert!(format!("{error:#}").contains(reason));
        assert_eq!(
            runtime.command_records(),
            vec![FakeDlqCommandRecord::ResolveExpiredOutbox {
                tenant: vocab::TenantId::parse(DLQ_FIXTURE_TENANT)?,
                event_id: DLQ_FIXTURE_EVENT_ID.to_owned(),
                resolution_kind: OutboxExpiredResolutionKind::AcceptedGap,
                evidence_event_id: None,
                operator_subject: DLQ_FIXTURE_OPERATOR.to_owned(),
            }],
            "the typed request subject must come from the verified runtime principal"
        );
        assert_dlq_lifecycle_audit(
            &runtime,
            DlqMaintenanceAction::ResolveExpiredOutbox,
            "event_id=evt-outbox-dlx resolution_kind=accepted_gap",
            FakeDlqAuditOutcome::Failure {
                reason: reason.to_owned(),
            },
        );
        for audit in runtime.audit_records() {
            assert!(!audit.resource_id.contains(DLQ_FIXTURE_CHANGE_TICKET));
            for forbidden in ["payload", "metadata", "partition", "error"] {
                assert!(!audit.resource_id.contains(forbidden));
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn dlq_control_lifecycle_keeps_not_found_redrive_successful() -> anyhow::Result<()> {
    let runtime = FakeDlqControlRuntime::verified(FakeDlqStoreMode::NotFound);
    run_dlq_control_command_with_runtime(
        &dlq_control_args("redrive-outbox", &["--event-id", DLQ_FIXTURE_EVENT_ID]),
        &runtime,
    )
    .await?;

    assert_eq!(runtime.setup_count(), 1);
    assert_eq!(runtime.shutdown_count(), 1);
    assert_dlq_lifecycle_audit(
        &runtime,
        DlqMaintenanceAction::RedriveOutbox,
        "event_id=evt-outbox-dlx",
        FakeDlqAuditOutcome::Success,
    );
    assert!(matches!(
        runtime.command_records().as_slice(),
        [FakeDlqCommandRecord::RedriveOutbox { .. }]
    ));
    Ok(())
}

#[tokio::test]
async fn dlq_control_lifecycle_does_not_call_store_before_auth_or_grant_success()
-> anyhow::Result<()> {
    for runtime in [
        FakeDlqControlRuntime::auth_failure(),
        FakeDlqControlRuntime::grant_failure(),
    ] {
        let result = run_dlq_control_command_with_runtime(
            &dlq_control_args("redrive-outbox", &["--event-id", DLQ_FIXTURE_EVENT_ID]),
            &runtime,
        )
        .await;
        assert!(result.is_err());
        assert_eq!(runtime.setup_count(), 1);
        assert_eq!(runtime.shutdown_count(), 1);
        assert!(runtime.command_records().is_empty());
    }
    Ok(())
}

#[test]
fn dlq_summary_renders_json_line_without_space_delimited_free_text() -> anyhow::Result<()> {
    let tenant = vocab::TenantId::parse(DLQ_FIXTURE_TENANT)?;
    let summary = DlqEntrySummary::new(
        eventexec::DlqEntryKind::DeadLetter,
        "dlq-row-1",
        diport::DeadLetterSource::Consumer,
        tenant,
        "msg-1",
        "identity",
        Some("audit".to_owned()),
        "identity.session-created",
        "identity.session.created",
        Some("identity.session.consumer".to_owned()),
        12,
        "max retries exhausted with spaces",
        3,
        1_700_000_000,
    );

    let rendered = dlq_summary_json_line(&summary)?;
    let parsed: serde_json::Value = serde_json::from_str(&rendered)?;
    assert_eq!(parsed["errorSummary"], "max retries exhausted with spaces");
    assert_eq!(parsed["contractId"], "identity.session-created");
    assert!(
        !rendered.contains("error_summary=max retries exhausted"),
        "free text must not be emitted in space-delimited key=value form: {rendered}"
    );
    Ok(())
}

#[test]
fn settings_config_value_maintenance_args_default_to_both() -> anyhow::Result<()> {
    let parsed = parse_settings_config_value_maintenance_args(&args(&[
        "settings-config-values",
        "maintenance",
        "--operator-service-token-stdin",
        "--operator-tenant",
        "00000000-0000-4000-8000-000000000001",
        "--all-tenants",
    ]))?;
    assert_eq!(parsed.operator_service_token.as_str(), "opaque-token");
    assert_eq!(
        parsed.operator_tenant,
        vocab::TenantId::parse("00000000-0000-4000-8000-000000000001")?
    );
    assert_eq!(
        parsed.options.operation(),
        postgres::ConfigValueMaintenanceOperation::Both
    );
    assert_eq!(parsed.options.batch_size(), 500);
    assert_eq!(parsed.options.max_rows(), None);
    assert!(parsed.options.tenant_opt().is_none());
    assert!(!parsed.options.dry_run());
    Ok(())
}

#[test]
fn settings_config_value_maintenance_args_parse_flags() -> anyhow::Result<()> {
    let parsed = parse_settings_config_value_maintenance_args(&args(&[
        "settings-config-values",
        "maintenance",
        "--operator-service-token-stdin",
        "--operator-tenant",
        "00000000-0000-4000-8000-000000000001",
        "--operation",
        "backfill",
        "--tenant",
        "00000000-0000-4000-8000-000000000001",
        "--batch-size",
        "7",
        "--max-rows",
        "9",
        "--dry-run",
    ]))?;
    assert_eq!(parsed.operator_service_token.as_str(), "opaque-token");
    assert_eq!(
        parsed.options.operation(),
        postgres::ConfigValueMaintenanceOperation::Backfill
    );
    assert_eq!(parsed.options.batch_size(), 7);
    assert_eq!(parsed.options.max_rows(), Some(9));
    assert_eq!(
        parsed.options.tenant_opt(),
        Some(vocab::TenantId::parse(
            "00000000-0000-4000-8000-000000000001"
        )?)
    );
    assert!(parsed.options.dry_run());
    Ok(())
}

#[test]
fn settings_config_value_maintenance_args_fail_closed() {
    let cases: &[(&str, Vec<String>)] = &[
        (
            "unknown flag",
            args(&[
                "settings-config-values",
                "maintenance",
                "--operator-service-token-stdin",
                "--operator-tenant",
                "00000000-0000-4000-8000-000000000001",
                "--all-tenants",
                "--bogus",
            ]),
        ),
        (
            "invalid operation",
            args(&[
                "settings-config-values",
                "maintenance",
                "--operator-service-token-stdin",
                "--operator-tenant",
                "00000000-0000-4000-8000-000000000001",
                "--all-tenants",
                "--operation",
                "decrypt",
            ]),
        ),
        (
            "batch size zero",
            args(&[
                "settings-config-values",
                "maintenance",
                "--operator-service-token-stdin",
                "--operator-tenant",
                "00000000-0000-4000-8000-000000000001",
                "--all-tenants",
                "--batch-size",
                "0",
            ]),
        ),
        (
            "invalid tenant",
            args(&[
                "settings-config-values",
                "maintenance",
                "--operator-service-token-stdin",
                "--operator-tenant",
                "00000000-0000-4000-8000-000000000001",
                "--tenant",
                "not-a-uuid",
            ]),
        ),
        (
            "missing auth flags",
            args(&["settings-config-values", "maintenance"]),
        ),
        (
            "missing operator tenant",
            args(&[
                "settings-config-values",
                "maintenance",
                "--operator-service-token-stdin",
                "--all-tenants",
            ]),
        ),
        (
            "missing tenant scope",
            args(&[
                "settings-config-values",
                "maintenance",
                "--operator-service-token-stdin",
                "--operator-tenant",
                "00000000-0000-4000-8000-000000000001",
            ]),
        ),
        (
            "tenant and all-tenants conflict",
            args(&[
                "settings-config-values",
                "maintenance",
                "--operator-service-token-stdin",
                "--operator-tenant",
                "00000000-0000-4000-8000-000000000001",
                "--tenant",
                "00000000-0000-4000-8000-000000000001",
                "--all-tenants",
            ]),
        ),
        (
            "unknown operator-subject",
            args(&[
                "settings-config-values",
                "maintenance",
                "--operator-subject",
                "ops@example.com",
            ]),
        ),
        // TooManyValues：presence flag 被赋 token 值时不得回显 SECRET_BAIT
        (
            "token assignment",
            args(&[
                "settings-config-values",
                "maintenance",
                "--operator-service-token-stdin=SECRET_BAIT",
                "--operator-tenant",
                "00000000-0000-4000-8000-000000000001",
                "--all-tenants",
            ]),
        ),
    ];

    for (name, candidate) in cases {
        let err = parse_settings_config_value_maintenance_args(candidate)
            .expect_err(&format!("case must fail: {name}"));
        assert_operator_cli_err(&err, "settings-config-values");
    }
}

#[test]
#[allow(non_snake_case)] // 验收过滤名含 SECRET_BAIT
fn settings_config_value_maintenance_args_SECRET_BAIT_too_many_values_is_redacted() {
    let err = parse_settings_config_value_maintenance_args(&args(&[
        "settings-config-values",
        "maintenance",
        "--operator-service-token-stdin=SECRET_BAIT",
        "--operator-tenant",
        "00000000-0000-4000-8000-000000000001",
        "--all-tenants",
    ]))
    .expect_err("assignment onto presence flag must fail closed");
    assert_operator_cli_err(&err, "settings-config-values");
}

#[test]
fn settings_config_value_maintenance_config_failures_keep_exact_audit_and_context() {
    let key_name_error = crate::infra::vault::VaultKeyProviderConfigError::SettingsKeyName(
        anyhow::anyhow!("invalid key name"),
    );
    assert_eq!(
        settings_config_value_maintenance_vault_failure(&key_name_error),
        ("key_name_config", "settings config value key name")
    );

    let client_error = crate::infra::vault::VaultKeyProviderConfigError::VaultClient(
        anyhow::anyhow!("invalid Vault client"),
    );
    assert_eq!(
        settings_config_value_maintenance_vault_failure(&client_error),
        (
            "key_provider_config",
            "settings config value maintenance key provider"
        )
    );
}

struct StubPdp {
    result: Result<diport::VerifiedClaims, diport::PdpError>,
}

impl diport::Pdp for StubPdp {
    async fn verify(
        &self,
        _raw: &diport::RawCredential,
    ) -> Result<diport::VerifiedClaims, diport::PdpError> {
        self.result.clone()
    }
}

fn stub_pdp(
    result: Result<diport::VerifiedClaims, diport::PdpError>,
) -> Box<diport::DynPdp<'static>> {
    diport::DynPdp::new_box(StubPdp { result })
}

#[tokio::test]
async fn settings_config_value_maintenance_operator_comes_from_verified_service_token()
-> anyhow::Result<()> {
    let pdp = stub_pdp(Ok(diport::VerifiedClaims::service_token(
        vocab::ServiceCallerDomain::MaintenanceOperator,
        vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("tenant"),
    )));
    let proof = verified_config_value_maintenance_operator(
        "opaque-token",
        vocab::TenantId::parse("00000000-0000-4000-8000-000000000001")?,
        &pdp,
    )
    .await?;

    assert_eq!(proof.principal().kind(), vocab::PrincipalKind::Service);
    assert!(
        proof
            .principal()
            .matches_subject(vocab::ServiceCallerDomain::MaintenanceOperator.as_str())
    );
    Ok(())
}

#[tokio::test]
async fn settings_config_value_maintenance_operator_token_failure_is_fail_closed()
-> anyhow::Result<()> {
    let pdp = stub_pdp(Err(diport::PdpError::InvalidSignature));
    let result = verified_config_value_maintenance_operator(
        "opaque-token",
        vocab::TenantId::parse("00000000-0000-4000-8000-000000000001")?,
        &pdp,
    )
    .await;

    assert!(result.is_err());
    Ok(())
}

#[test]
fn operator_clap_bucket_kinds_for_missing_required_vs_subcommand() {
    let missing_sub = parse_dlq_args(&args(&["dlq"])).expect_err("missing sub");
    assert_operator_cli_err_bucket(&missing_sub, "dlq", Some("missing subcommand"));

    let missing_required = parse_dlq_args(&args(&[
        "dlq",
        "list",
        "--operator-service-token-stdin",
        "--operator-tenant",
        DLQ_FIXTURE_OPERATOR_TENANT,
    ]))
    .expect_err("missing tenant");
    assert_operator_cli_err_bucket(&missing_required, "dlq", Some("missing required argument"));
}
