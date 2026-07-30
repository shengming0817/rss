//! Settings-only DLX HOT -> verified WORM -> COLD lifecycle assembly.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use bootstrap::{DomainModuleResult, WorkerSpec};
use diport::{Clock as _, DynManagedResource};
use eventexec::{
    DlxArchiveKeyName, DlxHotKeyName, DlxLifecycle, DlxLifecycleHealth, WorkerHealth,
    apply_dlx_lifecycle_health, spawn_on_dedicated_runtime_with_build_failure,
};

const DLX_LIFECYCLE_INTERVAL: Duration = Duration::from_secs(60);
const DLX_LIFECYCLE_TICK_TIMEOUT: Duration = Duration::from_secs(45);
const DLX_ARCHIVE_KEY_READINESS_INTERVAL: Duration = Duration::from_secs(30);
const DLX_ARCHIVE_KEY_READINESS_TIMEOUT: Duration = Duration::from_secs(10);
const DLX_WORKER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(45);
const DLX_LIFECYCLE_WORKER_NAME: &str = "settingsonly-dlx-lifecycle";
const DLX_ARCHIVE_READINESS_WORKER_NAME: &str = "settingsonly-dlx-archive-readiness";
const DLX_ARCHIVE_KEY_READINESS_WORKER_NAME: &str = "settingsonly-dlx-archive-key-readiness";
const DLX_HOT_KEY_READINESS_WORKER_NAME: &str = "settingsonly-dlx-hot-key-readiness";
const DLX_LIFECYCLE_PROBE: &str = crate::readiness::DLX_LIFECYCLE;
const DLX_ARCHIVE_READINESS_PROBE: &str = crate::readiness::DLX_ARCHIVE;
const DLX_ARCHIVE_KEY_READINESS_PROBE: &str = crate::readiness::DLX_ARCHIVE_KEY;
const DLX_HOT_KEY_READINESS_PROBE: &str = crate::readiness::DLX_HOT_KEY;
const DLX_ARCHIVE_KEY_CANARY_TENANT: &str = "00000000-0000-4000-8000-000000001836";
const DLX_ARCHIVE_KEY_CANARY_PLAINTEXT: &[u8] = b"settingsonly-dlx-archive-readiness-v1";

/// Complete verified inputs for the Settings DLX lifecycle.
pub(crate) struct DlxInputs {
    pg_owner: postgres::PgDlxLifecycleRuntime,
    archive_store: s3::VerifiedS3DlxArchiveStore,
    hot_key_provider: Arc<vault::VaultKeyProvider>,
    hot_key: DlxHotKeyName,
    archive_key_provider: Arc<vault::VaultKeyProvider>,
    archive_key: DlxArchiveKeyName,
    readiness_interval: Duration,
}

impl DlxInputs {
    #[must_use]
    pub(crate) fn new(
        pg_owner: postgres::PgDlxLifecycleRuntime,
        archive_store: s3::VerifiedS3DlxArchiveStore,
        hot_key_provider: Arc<vault::VaultKeyProvider>,
        hot_key: DlxHotKeyName,
        archive_key_provider: Arc<vault::VaultKeyProvider>,
        archive_key: DlxArchiveKeyName,
        readiness_interval: Duration,
    ) -> Self {
        Self {
            pg_owner,
            archive_store,
            hot_key_provider,
            hot_key,
            archive_key_provider,
            archive_key,
            readiness_interval,
        }
    }
}

/// Exact generated provider-role outputs for DLX activation.
pub(crate) struct DlxRoleOutputs {
    pub(crate) dlx_lifecycle_repository: DomainModuleResult,
    pub(crate) dlx_archive_store: DomainModuleResult,
    pub(crate) dlx_hot_key_provider: DomainModuleResult,
    pub(crate) dlx_archive_key_provider: DomainModuleResult,
}

/// Build the lifecycle and readiness workers without constructing or revalidating providers.
pub(crate) fn wire(inputs: DlxInputs) -> anyhow::Result<DlxRoleOutputs> {
    let lifecycle_probe_name = primitives::ProbeName::parse(DLX_LIFECYCLE_PROBE)
        .context("build settingsonly DLX lifecycle probe name")?;
    let archive_probe_name = primitives::ProbeName::parse(DLX_ARCHIVE_READINESS_PROBE)
        .context("build settingsonly DLX archive readiness probe name")?;
    let archive_key_probe_name = primitives::ProbeName::parse(DLX_ARCHIVE_KEY_READINESS_PROBE)
        .context("build settingsonly DLX archive key readiness probe name")?;
    let hot_key_probe_name = primitives::ProbeName::parse(DLX_HOT_KEY_READINESS_PROBE)
        .context("build settingsonly DLX hot key readiness probe name")?;

    let repository = inputs.pg_owner.repository();
    let archive_key = inputs.archive_key.clone();
    let lifecycle = DlxLifecycle::new(
        repository,
        inputs.archive_store.clone(),
        SharedKeyProvider(Arc::clone(&inputs.archive_key_provider)),
        inputs.archive_key,
    );
    let lifecycle_health = Arc::new(WorkerHealth::starting());
    let archive_health = Arc::new(WorkerHealth::starting());
    let archive_key_health = Arc::new(WorkerHealth::starting());
    let hot_key_health = Arc::new(WorkerHealth::starting());

    let dlx_lifecycle_repository = DomainModuleResult {
        probes: vec![(
            lifecycle_probe_name.clone(),
            Box::new(WorkerProbe::new(
                lifecycle_probe_name,
                Arc::clone(&lifecycle_health),
            )),
        )],
        resources: vec![DynManagedResource::new_box(inputs.pg_owner)],
        workers: vec![lifecycle_worker(lifecycle, lifecycle_health)],
    };
    let dlx_archive_store = DomainModuleResult {
        probes: vec![(
            archive_probe_name.clone(),
            Box::new(WorkerProbe::new(
                archive_probe_name,
                Arc::clone(&archive_health),
            )),
        )],
        workers: vec![archive_readiness_worker(
            inputs.archive_store,
            archive_health,
            inputs.readiness_interval,
        )],
        ..Default::default()
    };

    let dlx_hot_key_provider = DomainModuleResult {
        probes: vec![(
            hot_key_probe_name.clone(),
            Box::new(WorkerProbe::new(
                hot_key_probe_name,
                Arc::clone(&hot_key_health),
            )),
        )],
        workers: vec![key_readiness_worker(
            inputs.hot_key_provider,
            inputs.hot_key.as_key_name().clone(),
            KeyReadinessSpec::hot(),
            hot_key_health,
        )?],
        ..Default::default()
    };

    let dlx_archive_key_provider = DomainModuleResult {
        probes: vec![(
            archive_key_probe_name.clone(),
            Box::new(WorkerProbe::new(
                archive_key_probe_name,
                Arc::clone(&archive_key_health),
            )),
        )],
        workers: vec![archive_key_readiness_worker(
            inputs.archive_key_provider,
            archive_key,
            archive_key_health,
        )?],
        ..Default::default()
    };
    Ok(DlxRoleOutputs {
        dlx_lifecycle_repository,
        dlx_archive_store,
        dlx_hot_key_provider,
        dlx_archive_key_provider,
    })
}

fn lifecycle_worker(
    lifecycle: DlxLifecycle<
        postgres::PgDlxLifecycleRepository,
        s3::VerifiedS3DlxArchiveStore,
        SharedKeyProvider,
    >,
    health: Arc<WorkerHealth>,
) -> WorkerSpec {
    WorkerSpec::phase_one(move |token| {
        let build_failure_health = Arc::clone(&health);
        DynManagedResource::new_box(spawn_on_dedicated_runtime_with_build_failure(
            DLX_LIFECYCLE_WORKER_NAME,
            token,
            Arc::clone(&health),
            DLX_WORKER_SHUTDOWN_TIMEOUT,
            move |_error| {
                record_health_transition(
                    &build_failure_health,
                    DlxLifecycleHealth::Unhealthy,
                    "dlx-lifecycle",
                    "runtime",
                    "runtime-build",
                    "runtime_build",
                );
            },
            move |thread_token| async move {
                lifecycle_loop(lifecycle, thread_token, health).await;
                Ok(())
            },
        ))
    })
}

async fn lifecycle_loop(
    lifecycle: DlxLifecycle<
        postgres::PgDlxLifecycleRepository,
        s3::VerifiedS3DlxArchiveStore,
        SharedKeyProvider,
    >,
    token: tokio_util::sync::CancellationToken,
    health: Arc<WorkerHealth>,
) {
    let mut ticker = tokio::time::interval(DLX_LIFECYCLE_INTERVAL);
    loop {
        tokio::select! {
            biased;
            () = token.cancelled() => break,
            _ = ticker.tick() => {
                let now = epoch_seconds(crate::SystemClock.now());
                match tokio::time::timeout(DLX_LIFECYCLE_TICK_TIMEOUT, lifecycle.tick(now)).await {
                    Ok(report) => record_health_transition(
                        &health,
                        report.health(),
                        "dlx-lifecycle",
                        "tick",
                        "sample",
                        "none",
                    ),
                    Err(_) => {
                        record_health_transition(
                            &health,
                            DlxLifecycleHealth::Degraded,
                            "dlx-lifecycle",
                            "tick",
                            "timeout",
                            "dlx_lifecycle_timeout",
                        );
                    }
                }
            }
        }
    }
}

struct SharedKeyProvider(Arc<vault::VaultKeyProvider>);

impl diport::KeyProvider for SharedKeyProvider {
    async fn encrypt(
        &self,
        key: diport::KeyName,
        plaintext: secure::Plaintext,
        aad: secure::DerivedAad,
    ) -> Result<diport::EncryptOutput, diport::KeyProviderError> {
        diport::KeyProvider::encrypt(self.0.as_ref(), key, plaintext, aad).await
    }

    async fn decrypt(
        &self,
        ciphertext: diport::RedactedBytes,
        key: diport::KeyRef,
        aad: secure::DerivedAad,
    ) -> Result<secure::Plaintext, diport::KeyProviderError> {
        diport::KeyProvider::decrypt(self.0.as_ref(), ciphertext, key, aad).await
    }

    async fn rewrap(
        &self,
        ciphertext: diport::RedactedBytes,
        key: diport::KeyRef,
        aad: secure::DerivedAad,
    ) -> Result<diport::EncryptOutput, diport::KeyProviderError> {
        diport::KeyProvider::rewrap(self.0.as_ref(), ciphertext, key, aad).await
    }

    async fn shutdown(&self) -> Result<(), diport::KeyProviderError> {
        diport::KeyProvider::shutdown(self.0.as_ref()).await
    }
}

fn archive_key_readiness_worker(
    provider: Arc<vault::VaultKeyProvider>,
    key: DlxArchiveKeyName,
    health: Arc<WorkerHealth>,
) -> anyhow::Result<WorkerSpec> {
    key_readiness_worker(
        provider,
        key.as_key_name().clone(),
        KeyReadinessSpec::archive(),
        health,
    )
}

#[derive(Clone, Copy)]
struct KeyReadinessSpec {
    worker_name: &'static str,
    aad_scope: &'static str,
}

impl KeyReadinessSpec {
    const fn archive() -> Self {
        Self {
            worker_name: DLX_ARCHIVE_KEY_READINESS_WORKER_NAME,
            aad_scope: "settingsonly/dlx/archive",
        }
    }

    const fn hot() -> Self {
        Self {
            worker_name: DLX_HOT_KEY_READINESS_WORKER_NAME,
            aad_scope: "settingsonly/dlx/hot",
        }
    }
}

fn key_readiness_worker(
    provider: Arc<vault::VaultKeyProvider>,
    key: diport::KeyName,
    spec: KeyReadinessSpec,
    health: Arc<WorkerHealth>,
) -> anyhow::Result<WorkerSpec> {
    let aad = key_canary_aad(spec.aad_scope)?;
    Ok(WorkerSpec::phase_one(move |token| {
        DynManagedResource::new_box(spawn_on_dedicated_runtime_with_build_failure(
            spec.worker_name,
            token,
            Arc::clone(&health),
            DLX_WORKER_SHUTDOWN_TIMEOUT,
            move |_error| {
                tracing::error!(
                    event = "settingsonly.readiness",
                    component = "dlx-key",
                    operation = "runtime",
                    outcome = "unhealthy",
                    reason = "runtime-build",
                    error_type = "runtime_build",
                    "settingsonly readiness worker failed"
                );
            },
            move |thread_token| async move {
                key_readiness_loop(provider, key, aad, thread_token, health).await;
                Ok(())
            },
        ))
    }))
}

fn key_canary_aad(scope: &'static str) -> anyhow::Result<secure::DerivedAad> {
    let tenant = vocab::TenantId::parse(DLX_ARCHIVE_KEY_CANARY_TENANT)
        .context("parse settingsonly DLX archive key readiness tenant")?;
    Ok(
        secure::ProtectionContext::authorized_maintenance(tenant, scope, "readiness-canary", 1)
            .context("derive settingsonly DLX archive key readiness AAD")?
            .derive(),
    )
}

async fn key_readiness_loop(
    provider: Arc<vault::VaultKeyProvider>,
    key: diport::KeyName,
    aad: secure::DerivedAad,
    token: tokio_util::sync::CancellationToken,
    health: Arc<WorkerHealth>,
) {
    let mut ticker = tokio::time::interval(DLX_ARCHIVE_KEY_READINESS_INTERVAL);
    loop {
        tokio::select! {
            biased;
            () = token.cancelled() => break,
            _ = ticker.tick() => {
                let sample = tokio::time::timeout(
                    DLX_ARCHIVE_KEY_READINESS_TIMEOUT,
                    verify_key_canary(provider.as_ref(), &key, aad.clone()),
                ).await;
                apply_key_readiness(&health, sample);
            }
        }
    }
}

fn apply_key_readiness(
    health: &WorkerHealth,
    sample: Result<anyhow::Result<()>, tokio::time::error::Elapsed>,
) {
    match sample {
        Ok(result) => apply_key_provider_result(health, result),
        Err(_) => {
            record_health_transition(
                health,
                DlxLifecycleHealth::Degraded,
                "dlx-key",
                "canary",
                "timeout",
                "dlx_key_timeout",
            );
        }
    }
}

fn apply_key_provider_result(health: &WorkerHealth, result: anyhow::Result<()>) {
    match result {
        Ok(()) => record_health_transition(
            health,
            DlxLifecycleHealth::Healthy,
            "dlx-key",
            "canary",
            "ready",
            "none",
        ),
        Err(_) => record_health_transition(
            health,
            DlxLifecycleHealth::Degraded,
            "dlx-key",
            "canary",
            "provider",
            "dlx_key_provider",
        ),
    }
}

async fn verify_key_canary(
    provider: &vault::VaultKeyProvider,
    key: &diport::KeyName,
    aad: secure::DerivedAad,
) -> anyhow::Result<()> {
    let encrypted = diport::KeyProvider::encrypt(
        provider,
        key.clone(),
        secure::Plaintext::new(DLX_ARCHIVE_KEY_CANARY_PLAINTEXT.to_vec()),
        aad.clone(),
    )
    .await
    .map_err(|_| anyhow::anyhow!("settingsonly DLX archive key encrypt canary failed"))?;
    let opened = diport::KeyProvider::decrypt(
        provider,
        diport::RedactedBytes::new(encrypted.ciphertext().to_vec()),
        encrypted.key().clone(),
        aad,
    )
    .await
    .map_err(|_| anyhow::anyhow!("settingsonly DLX archive key decrypt canary failed"))?;
    anyhow::ensure!(
        opened.expose() == DLX_ARCHIVE_KEY_CANARY_PLAINTEXT,
        "settingsonly DLX archive key canary plaintext mismatch"
    );
    Ok(())
}

fn archive_readiness_worker(
    store: s3::VerifiedS3DlxArchiveStore,
    health: Arc<WorkerHealth>,
    readiness_interval: Duration,
) -> WorkerSpec {
    WorkerSpec::phase_one(move |token| {
        let build_failure_health = Arc::clone(&health);
        DynManagedResource::new_box(spawn_on_dedicated_runtime_with_build_failure(
            DLX_ARCHIVE_READINESS_WORKER_NAME,
            token,
            Arc::clone(&health),
            DLX_WORKER_SHUTDOWN_TIMEOUT,
            move |_error| {
                record_health_transition(
                    &build_failure_health,
                    DlxLifecycleHealth::Unhealthy,
                    "dlx-archive",
                    "runtime",
                    "runtime-build",
                    "runtime_build",
                );
            },
            move |thread_token| async move {
                archive_readiness_loop(store, thread_token, health, readiness_interval).await;
                Ok(())
            },
        ))
    })
}

async fn archive_readiness_loop(
    store: s3::VerifiedS3DlxArchiveStore,
    token: tokio_util::sync::CancellationToken,
    health: Arc<WorkerHealth>,
    readiness_interval: Duration,
) {
    let mut ticker = tokio::time::interval(readiness_interval);
    loop {
        tokio::select! {
            biased;
            () = token.cancelled() => break,
            _ = ticker.tick() => {
                let sample = tokio::time::timeout(
                    readiness_interval,
                    store.probe_readiness(),
                ).await;
                apply_archive_readiness(&health, sample);
            }
        }
    }
}

fn apply_archive_readiness(
    health: &WorkerHealth,
    result: Result<Result<(), s3::S3DlxArchiveCapabilityError>, tokio::time::error::Elapsed>,
) {
    let (state, reason, error_type) = match result {
        Ok(Ok(())) => (DlxLifecycleHealth::Healthy, "ready", "none"),
        Ok(Err(s3::S3DlxArchiveCapabilityError::Provider)) => {
            (DlxLifecycleHealth::Degraded, "provider", "s3_provider")
        }
        Err(_) => (DlxLifecycleHealth::Degraded, "timeout", "s3_timeout"),
        Ok(Err(
            s3::S3DlxArchiveCapabilityError::VersioningRequired
            | s3::S3DlxArchiveCapabilityError::ObjectLockRequired
            | s3::S3DlxArchiveCapabilityError::ComplianceRequired
            | s3::S3DlxArchiveCapabilityError::RetentionTooShort
            | s3::S3DlxArchiveCapabilityError::LifecycleRequired
            | s3::S3DlxArchiveCapabilityError::CanaryInvariant,
        )) => (
            DlxLifecycleHealth::Unhealthy,
            "invariant",
            "s3_capability_invariant",
        ),
    };
    record_health_transition(
        health,
        state,
        "dlx-archive",
        "capability-probe",
        reason,
        error_type,
    );
}

fn record_health_transition(
    health: &WorkerHealth,
    state: DlxLifecycleHealth,
    component: &'static str,
    operation: &'static str,
    reason: &'static str,
    error_type: &'static str,
) {
    let previous = health.status();
    apply_dlx_lifecycle_health(health, state);
    let outcome = health.status();
    if previous != outcome {
        tracing::warn!(
            event = "settingsonly.readiness",
            component,
            operation,
            outcome = outcome.as_label(),
            reason,
            error_type,
            "settingsonly readiness transitioned"
        );
    }
}

fn epoch_seconds(now: SystemTime) -> i64 {
    now.duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .unwrap_or(i64::MAX)
}

struct WorkerProbe {
    name: primitives::ProbeName,
    health: Arc<WorkerHealth>,
}

impl WorkerProbe {
    fn new(name: primitives::ProbeName, health: Arc<WorkerHealth>) -> Self {
        Self { name, health }
    }
}

impl bootstrap::HealthProbe for WorkerProbe {
    fn check(&self) -> primitives::HealthCheck {
        primitives::HealthCheck::new(
            self.name.clone(),
            required_health_status(self.health.status()),
            self.health.detail(),
        )
    }
}

fn required_health_status(status: primitives::HealthStatus) -> primitives::HealthStatus {
    match status {
        primitives::HealthStatus::Healthy => primitives::HealthStatus::Healthy,
        primitives::HealthStatus::Degraded | primitives::HealthStatus::Unhealthy => {
            primitives::HealthStatus::Unhealthy
        }
        _ => primitives::HealthStatus::Unhealthy,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn archive_readiness_fails_closed_for_provider_timeout_and_invariant()
    -> anyhow::Result<()> {
        let provider = Arc::new(WorkerHealth::starting());
        apply_archive_readiness(
            &provider,
            Ok(Err(s3::S3DlxArchiveCapabilityError::Provider)),
        );
        assert_eq!(provider.status(), primitives::HealthStatus::Degraded);
        let provider_probe = WorkerProbe::new(
            primitives::ProbeName::parse("settingsonly_s3_provider_test")?,
            Arc::clone(&provider),
        );
        assert_eq!(
            bootstrap::HealthProbe::check(&provider_probe).status(),
            primitives::HealthStatus::Unhealthy
        );

        let timeout = tokio::time::timeout(
            Duration::from_millis(1),
            std::future::pending::<Result<(), s3::S3DlxArchiveCapabilityError>>(),
        )
        .await;
        let elapsed = Arc::new(WorkerHealth::starting());
        apply_archive_readiness(&elapsed, timeout);
        assert_eq!(elapsed.status(), primitives::HealthStatus::Degraded);
        let elapsed_probe = WorkerProbe::new(
            primitives::ProbeName::parse("settingsonly_s3_timeout_test")?,
            Arc::clone(&elapsed),
        );
        assert_eq!(
            bootstrap::HealthProbe::check(&elapsed_probe).status(),
            primitives::HealthStatus::Unhealthy
        );
        apply_archive_readiness(&elapsed, Ok(Ok(())));
        assert_eq!(
            bootstrap::HealthProbe::check(&elapsed_probe).status(),
            primitives::HealthStatus::Healthy
        );

        let invariant = Arc::new(WorkerHealth::starting());
        apply_archive_readiness(
            &invariant,
            Ok(Err(s3::S3DlxArchiveCapabilityError::ObjectLockRequired)),
        );
        assert_eq!(invariant.status(), primitives::HealthStatus::Unhealthy);
        Ok(())
    }

    #[test]
    fn dlx_probe_names_and_epoch_conversion_are_closed() -> anyhow::Result<()> {
        assert_eq!(
            primitives::ProbeName::parse(DLX_LIFECYCLE_PROBE)?.as_str(),
            DLX_LIFECYCLE_PROBE
        );
        assert_eq!(
            primitives::ProbeName::parse(DLX_ARCHIVE_READINESS_PROBE)?.as_str(),
            DLX_ARCHIVE_READINESS_PROBE
        );
        assert_eq!(epoch_seconds(UNIX_EPOCH + Duration::from_secs(7)), 7);
        assert!(primitives::ProbeName::parse(DLX_ARCHIVE_KEY_READINESS_PROBE).is_ok());
        assert!(primitives::ProbeName::parse(DLX_HOT_KEY_READINESS_PROBE).is_ok());
        let aad = key_canary_aad("settingsonly/dlx/archive")?;
        assert!(!aad.as_canonical_bytes().is_empty());
        Ok(())
    }
}
