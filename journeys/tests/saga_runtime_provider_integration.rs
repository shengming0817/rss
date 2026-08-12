//! T2 Saga provider/runtime integration carrier. The neutral definition is omitted from every
//! production assembly; this fixture creates a test-profile RuntimePlan to exercise the real
//! PostgreSQL provider and runtime lifecycle seam without claiming production activation.

use std::fs;
use std::num::{NonZeroU64, NonZeroUsize};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result, ensure};
use assembly_schema::{
    AssemblyDomain, AssemblyListenerKind, ListenerAuth, RepositoryAssemblyManifestV2,
    RepositoryVerifiedAssemblyLock, RuntimePlan, RuntimePlanV3Input,
};
use consistency::{SagaInstanceRef, SagaInstanceStatus};
use diport::{
    ManagedResource as _, SagaOperatorCasOutcome, SagaOperatorChangeTicket, SagaOperatorReasonText,
    SagaOperatorRepairExpectation, SagaOperatorRepairReason, SagaOperatorStartAuditId,
    SagaStartAuditId, SagaTerminateExpectation, saga_operator_action,
};
use eventexec::{SagaOperatorRecoveryOutcome, SagaStartRequest, SagaWorkerConfig};
use postgres::{PgConfig, PgPassword, PgRuntimeDeps, PgSslMode, PgTenantReadConfig};

mod common;

const CONTRACT_ID: &str = eventexec::saga_test_support::primary::CONTRACT_ID;
const FIXTURE_ASSEMBLY_ID: &str = runtime::test_support::SAGA_CONFORMANCE_ASSEMBLY_ID;
const RECEIPT_INTEGRITY_KEY_B64URL: &str = "UVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVE";
const RUNTIME_MANIFEST: &str = include_str!("../../assemblies/runtime/assembly.toml");
const RUNTIME_PLAN: &str = include_str!("../../assemblies/runtime/runtime-plan.json");
const APP_ROLE: &str = "rss_app";
const APP_PASSWORD: &str = "saga-app-password";
const READ_ROLE: &str = "rss_app_read";
const READ_PASSWORD: &str = "saga-read-password";
const OPERATOR_ROLE: &str = "rss_saga_operator";
const OPERATOR_PASSWORD: &str = "saga-operator-password";

struct FixtureRepository {
    root: PathBuf,
}

fn pg_config(params: &testkit::PgConnParams) -> PgConfig {
    PgConfig::new(
        params.host.clone(),
        params.port,
        params.database.clone(),
        params.username.clone(),
        PgPassword::new(params.password.clone()),
    )
    .with_ssl_mode(PgSslMode::Prefer)
    .with_acquire_timeout(Duration::from_secs(5))
}

fn instance(value: u128) -> Result<SagaInstanceRef> {
    Ok(SagaInstanceRef::new(
        rss_request_context::TenantId::parse(common::CANON_TENANT)?,
        consistency::SagaId::new(uuid::Uuid::from_u128(value)),
    )?)
}

fn saga_worker_config() -> Result<SagaWorkerConfig> {
    Ok(SagaWorkerConfig::new(
        NonZeroU64::new(10).context("poll interval")?,
        NonZeroUsize::new(8).context("tenant batch")?,
        NonZeroUsize::new(8).context("instance batch")?,
    ))
}

async fn wait_for_status(
    operator: &eventexec::SagaRuntimeOperatorTarget,
    instance: SagaInstanceRef,
    expected: SagaInstanceStatus,
) -> Result<()> {
    let identity = operator.identity().clone();
    let mut last_status = None;
    let reached = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let authorization =
                diport::test_support::saga_operator_authorization::<saga_operator_action::Status>(
                    vocab::ServiceCallerDomain::MaintenanceOperator,
                    identity.clone(),
                    instance,
                    (),
                    SagaOperatorStartAuditId::parse(format!(
                        "saga-t2-status-{}",
                        uuid::Uuid::new_v4()
                    ))?,
                );
            if let diport::SagaOperatorStatusOutcome::Found(snapshot) =
                operator.status(authorization).await?
            {
                last_status = Some(snapshot.record().status());
                if snapshot.record().status() == expected {
                    return Ok::<_, anyhow::Error>(());
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    match reached {
        Ok(result) => result,
        Err(_) => anyhow::bail!(
            "Saga worker did not reach expected durable status {expected:?}; last status={last_status:?}"
        ),
    }
}

async fn wait_for_readiness(
    reporter: &bootstrap::HealthReporter,
    expected: primitives::HealthStatus,
) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if reporter.report().overall() == expected {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .context("Saga lifecycle did not reach expected readiness")?;
    Ok(())
}

impl FixtureRepository {
    fn create() -> Result<Self> {
        let root = std::env::temp_dir().join(format!(
            "rss-saga-provider-integration-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(root.join("assemblies").join(FIXTURE_ASSEMBLY_ID))?;
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .context("journeys repository root")?;
        copy_tree(&workspace.join("contracts"), &root.join("contracts"))?;
        copy_tree(&workspace.join("generated"), &root.join("generated"))?;
        copy_tree(
            &workspace.join("assemblies/runtime/src"),
            &root
                .join("assemblies")
                .join(FIXTURE_ASSEMBLY_ID)
                .join("src"),
        )?;
        let manifest = RUNTIME_MANIFEST
            .replacen(
                "name = \"runtime\"",
                &format!("name = \"{FIXTURE_ASSEMBLY_ID}\""),
                1,
            )
            .replacen("profile = \"production\"", "profile = \"test\"", 1);
        fs::write(
            root.join("assemblies")
                .join(FIXTURE_ASSEMBLY_ID)
                .join("assembly.toml"),
            manifest,
        )?;
        Ok(Self {
            root: fs::canonicalize(root)?,
        })
    }

    fn runtime_plan(&self) -> Result<RuntimePlan> {
        let assembly = self.root.join("assemblies").join(FIXTURE_ASSEMBLY_ID);
        let manifest = RepositoryAssemblyManifestV2::discover_v2(&self.root, &assembly)?;
        let lock = RepositoryVerifiedAssemblyLock::compile_v2(&manifest)?;
        let mut input = RuntimePlanV3Input::from_manifest(manifest.canonical());
        input.listener(
            AssemblyListenerKind::Admin,
            ListenerAuth::RssAccessToken,
            vec![AssemblyDomain::Audit],
        );
        input.listener(
            AssemblyListenerKind::Health,
            ListenerAuth::NoAuth,
            Vec::new(),
        );
        input.listener(
            AssemblyListenerKind::Internal,
            ListenerAuth::Mtls,
            Vec::new(),
        );
        input.listener(
            AssemblyListenerKind::Primary,
            ListenerAuth::RssAccessToken,
            vec![AssemblyDomain::Settings, AssemblyDomain::Identity],
        );
        for domain in [
            AssemblyDomain::Settings,
            AssemblyDomain::Identity,
            AssemblyDomain::Audit,
        ] {
            input.domain(domain);
        }
        for domain in [
            AssemblyDomain::Audit,
            AssemblyDomain::Identity,
            AssemblyDomain::Settings,
        ] {
            input.placement(domain, FIXTURE_ASSEMBLY_ID);
        }
        Ok(RuntimePlan::compile_v3(manifest.canonical(), &lock, input)?)
    }
}

impl Drop for FixtureRepository {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn copy_tree(source: &Path, target: &Path) -> Result<()> {
    fs::create_dir_all(target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let source = entry.path();
        let target = target.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&source, &target)?;
        } else {
            fs::copy(&source, &target)?;
        }
    }
    Ok(())
}

#[test]
fn neutral_active_plan_is_exact_and_production_remains_omitted() -> Result<()> {
    ensure!(!RUNTIME_MANIFEST.contains(CONTRACT_ID));
    ensure!(!RUNTIME_PLAN.contains(CONTRACT_ID));
    ensure!(!RUNTIME_MANIFEST.contains("billing.checkout"));
    ensure!(!RUNTIME_PLAN.contains("billing.checkout"));

    let fixture = FixtureRepository::create()?;
    let plan = fixture.runtime_plan()?;
    let mut production = eventexec::WorkflowActivationPlan::select(&plan)?;
    ensure!(production.take_saga_permit(CONTRACT_ID).is_err());
    production.bind(std::iter::empty(), std::iter::empty())?;
    let mut activation =
        eventexec::WorkflowActivationPlan::select_saga_conformance_for_test(&plan)?;
    let _permit = activation.take_saga_permit(CONTRACT_ID)?;
    ensure!(activation.take_saga_permit(CONTRACT_ID).is_err());
    let error = match activation.bind(std::iter::empty(), std::iter::empty()) {
        Ok(_) => anyhow::bail!("active Saga without its returned capability must fail closed"),
        Err(error) => error,
    };
    ensure!(matches!(
        error,
        eventexec::WorkflowRuntimeError::MissingCapability { ref workflow, .. }
            if workflow == CONTRACT_ID
    ));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn neutral_saga_joins_postgres_worker_readiness_and_operator_fencing() -> Result<()> {
    let fixture_repo = FixtureRepository::create()?;
    let runtime_plan = fixture_repo.runtime_plan()?;
    let success_runtime_plan = fixture_repo.runtime_plan()?;
    let projection_activation =
        eventexec::WorkflowActivationPlan::select_saga_conformance_for_test(&runtime_plan)?;

    let pg = testkit::env_or_postgres().await?;
    let [app, reader, operator] = pg
        .resolve_app_roles([
            testkit::PgAppRoleSpec::new(APP_ROLE, APP_PASSWORD),
            testkit::PgAppRoleSpec::new(READ_ROLE, READ_PASSWORD),
            testkit::PgAppRoleSpec::new(OPERATOR_ROLE, OPERATOR_PASSWORD),
        ])
        .await?;
    let serving_config = pg_config(app.params());
    let tenant_read_config = PgTenantReadConfig::new(pg_config(reader.params()));
    let deps = match &pg {
        testkit::PgFixture::Owned(owned) => {
            PgRuntimeDeps::setup_owned_test_fixture(
                &pg_config(owned.owner_params()),
                &serving_config,
                &tenant_read_config,
                None,
                projection_activation.projection_capture(),
            )
            .await?
        }
        testkit::PgFixture::External(_) => {
            PgRuntimeDeps::connect_prepared_test_fixture(
                &serving_config,
                &tenant_read_config,
                None,
                projection_activation.projection_capture(),
            )
            .await?
        }
    };
    let pg_handle = deps.handle();
    let (pg_resources, _readiness_sampler) = deps.into_runtime_parts(Duration::from_secs(1));
    let operator_deps = postgres::PgSagaOperatorDeps::connect(
        &postgres::PgSagaOperatorConfig::new(pg_config(operator.params())),
    )
    .await?;

    let verdict: Result<()> = async {
        let activation = runtime::test_support::bind_saga_provider_integration(
            runtime_plan,
            eventexec::saga_test_support::ConformanceExecution::RequirePrepareRepair,
            &pg_handle,
            common::journey_key_provider(),
            RECEIPT_INTEGRITY_KEY_B64URL.to_owned(),
            common::dlx_payload_protector(),
            saga_worker_config()?,
        )?;
        let start = activation.start_target();
        let operator = activation.operator_target();
        let identity = start.identity().clone();

        let terminated = instance(1926001)?;
        start
            .start(
                diport::test_support::saga_start_authorization(
                    vocab::ServiceCallerDomain::MaintenanceOperator,
                    identity.clone(),
                    terminated,
                    SagaStartAuditId::parse("saga-t2-start-terminate")?,
                ),
                SagaStartRequest::new(terminated),
            )
            .await?;
        let terminate =
            diport::test_support::saga_operator_authorization::<saga_operator_action::Terminate>(
                vocab::ServiceCallerDomain::MaintenanceOperator,
                identity.clone(),
                terminated,
                SagaTerminateExpectation::new(
                    SagaOperatorReasonText::parse("neutral T2 termination fence")?,
                    SagaOperatorChangeTicket::parse("RSS-2064-T2")?,
                ),
                SagaOperatorStartAuditId::parse("saga-t2-operator-terminate")?,
            );
        ensure!(operator_deps.terminate(terminate).await? == SagaOperatorCasOutcome::Applied);
        wait_for_status(&operator, terminated, SagaInstanceStatus::Terminated)
            .await
            .context("terminated instance did not reach Terminated")?;

        let compensating = instance(1926002)?;
        let drained_reporter = runtime::test_support::run_saga_provider_integration(
            activation,
            move |reporter, start, operator| async move {
                start
                    .start(
                        diport::test_support::saga_start_authorization(
                            vocab::ServiceCallerDomain::MaintenanceOperator,
                            identity,
                            compensating,
                            SagaStartAuditId::parse("saga-t2-start-compensation")?,
                        ),
                        SagaStartRequest::new(compensating),
                    )
                    .await?;
                wait_for_status(
                    &operator,
                    compensating,
                    SagaInstanceStatus::OperatorRequired,
                )
                .await
                .context("unknown prepare did not reach OperatorRequired")?;
                Ok(reporter)
            },
        )
        .await?;
        ensure!(drained_reporter.report().overall() == primitives::HealthStatus::Unhealthy);

        let recovery_runtime_plan = fixture_repo.runtime_plan()?;
        let activation = runtime::test_support::bind_saga_provider_integration(
            recovery_runtime_plan,
            eventexec::saga_test_support::ConformanceExecution::FailCommit,
            &pg_handle,
            common::journey_key_provider(),
            RECEIPT_INTEGRITY_KEY_B64URL.to_owned(),
            common::dlx_payload_protector(),
            saga_worker_config()?,
        )?;
        let operator = activation.operator_target();
        let repaired = operator
            .repair(diport::test_support::saga_operator_authorization::<
                saga_operator_action::Repair,
            >(
                vocab::ServiceCallerDomain::MaintenanceOperator,
                operator.identity().clone(),
                compensating,
                SagaOperatorRepairExpectation::new(
                    SagaOperatorRepairReason::ForwardOutcomeUnknown,
                    SagaOperatorReasonText::parse("neutral T2 provider outcome reviewed")?,
                    SagaOperatorChangeTicket::parse("RSS-2064-T2")?,
                ),
                SagaOperatorStartAuditId::parse("saga-t2-operator-repair")?,
            ))
            .await;
        ensure!(repaired == SagaOperatorRecoveryOutcome::Repaired);
        let drained_reporter = runtime::test_support::run_saga_provider_integration(
            activation,
            move |reporter, _start, operator| async move {
                wait_for_status(&operator, compensating, SagaInstanceStatus::Compensated)
                    .await
                    .context("repaired instance did not reach Compensated")?;
                wait_for_readiness(&reporter, primitives::HealthStatus::Healthy).await?;
                Ok(reporter)
            },
        )
        .await?;
        ensure!(drained_reporter.report().overall() == primitives::HealthStatus::Unhealthy);

        let activation = runtime::test_support::bind_saga_provider_integration(
            success_runtime_plan,
            eventexec::saga_test_support::ConformanceExecution::Complete,
            &pg_handle,
            common::journey_key_provider(),
            RECEIPT_INTEGRITY_KEY_B64URL.to_owned(),
            common::dlx_payload_protector(),
            saga_worker_config()?,
        )?;
        let start = activation.start_target();
        let identity = start.identity().clone();
        let runnable = instance(1926003)?;
        let drained_reporter = runtime::test_support::run_saga_provider_integration(
            activation,
            move |reporter, start, operator| async move {
                start
                    .start(
                        diport::test_support::saga_start_authorization(
                            vocab::ServiceCallerDomain::MaintenanceOperator,
                            identity,
                            runnable,
                            SagaStartAuditId::parse("saga-t2-start-worker")?,
                        ),
                        SagaStartRequest::new(runnable),
                    )
                    .await?;
                wait_for_status(&operator, runnable, SagaInstanceStatus::Succeeded)
                    .await
                    .context("complete instance did not reach Succeeded")?;
                wait_for_readiness(&reporter, primitives::HealthStatus::Healthy).await?;
                Ok(reporter)
            },
        )
        .await?;
        ensure!(drained_reporter.report().overall() == primitives::HealthStatus::Unhealthy);
        Ok(())
    }
    .await;

    for resource in pg_resources.iter().rev() {
        resource.shutdown().await?;
    }
    operator_deps.shutdown().await?;
    verdict
}
