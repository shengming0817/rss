//! Runtime-local provider output adaptation.
//!
//! Adapter bundles own their `diport`-only managed-resource primitives and intentionally do not
//! depend on `bootstrap`. This module is the composition-root seam that converts those primitives
//! into the sole runtime lifecycle output, [`DomainModuleResult`], before the normal merge path.
//! Private one-shot permits join the generated catalog to `RuntimePlan`; the consuming transaction
//! prevents construction receipts or lifecycle ownership from leaking back into adapter crates.
//!
//! INVARIANT: PG-RUNTIME-OUTPUT-03 { level = "Hard", exec = "native-compile", source = "code", native = "private PgReadinessSamplerFactory fields and consuming spawn self; owned PgRuntimeDeps conversion into the existing DomainModuleResult output" }
//!
//! `ref: oxidecomputer/omicron nexus/src/context.rs@8eb92537bd12598dfd2c861f897a88962fabf684`

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use anyhow::Context as _;
use assembly_schema::{
    LifecycleChannel, ProviderCatalogEntry, ProviderFactorySymbol, ProviderPlan, ProviderRole,
};
use bootstrap::{DomainModuleResult, WorkerSpec};
use diport::{DynManagedResource, ManagedResource, ShutdownError};
use postgres::{PgRuntimeDeps, PgRuntimeHandle};
use tokio_util::sync::CancellationToken;

use crate::providers_gen::ListenerPdpJwksLifecycle;

const IDENTITY_SIGNER_READINESS_PERIOD: Duration = Duration::from_secs(30);
const IDENTITY_SIGNER_READINESS_PROBE: &str = "identity_signer_ready";
const IDENTITY_SIGNER_READINESS_WORKER: &str = "identity-signer-readiness";
const IDENTITY_SIGNER_READINESS_MESSAGE: &[u8] = b"rss-runtime-identity-signer-readiness-v1";

/// Consumes the postgres lifecycle owner into the runtime's sole lifecycle output type.
pub(crate) fn build_pg_runtime_module(
    owner: PgRuntimeDeps,
    period: Duration,
) -> DomainModuleResult {
    let (resources, sampler_factory) = owner.into_runtime_parts(period);
    let readiness_sampler = WorkerSpec::phase_one(move |token| {
        DynManagedResource::new_box(sampler_factory.spawn(token))
    });
    DomainModuleResult {
        resources,
        workers: vec![readiness_sampler],
        ..DomainModuleResult::default()
    }
}

pub(crate) fn identity_signer_resource(
    signer: Arc<vault::VaultSigner>,
) -> Box<DynManagedResource<'static>> {
    DynManagedResource::new_box(IdentitySignerGuard { signer })
}

pub(crate) async fn identity_signer_module(
    signer: Arc<vault::VaultSigner>,
    key: diport::KeyId,
) -> anyhow::Result<DomainModuleResult> {
    verify_identity_signer(&signer, key.clone()).await?;
    let health = Arc::new(IdentitySignerHealth::healthy());
    let probe_name = primitives::ProbeName::parse(IDENTITY_SIGNER_READINESS_PROBE)
        .context("parse identity signer readiness probe")?;
    let worker_signer = Arc::clone(&signer);
    let worker_health = Arc::clone(&health);
    let worker = WorkerSpec::phase_one(move |token| {
        DynManagedResource::new_box(IdentitySignerReadinessWorker::spawn(
            token,
            worker_signer,
            key,
            worker_health,
        ))
    });
    Ok(DomainModuleResult {
        probes: vec![(
            probe_name.clone(),
            Box::new(IdentitySignerProbe {
                name: probe_name,
                health,
            }),
        )],
        resources: vec![identity_signer_resource(signer)],
        workers: vec![worker],
    })
}

async fn verify_identity_signer(
    signer: &vault::VaultSigner,
    key: diport::KeyId,
) -> anyhow::Result<()> {
    use diport::Signer as _;
    signer
        .sign(diport::SignRequest {
            key,
            purpose: diport::SigningPurpose::new("auth.rss-access"),
            message: diport::RedactedBytes::new(IDENTITY_SIGNER_READINESS_MESSAGE.to_vec()),
        })
        .await
        .context("verify runtime identity signer capability")?;
    Ok(())
}

struct IdentitySignerHealth(AtomicU8);

impl IdentitySignerHealth {
    const fn healthy() -> Self {
        Self(AtomicU8::new(0))
    }

    fn record(&self, healthy: bool) {
        self.0.store(u8::from(!healthy), Ordering::Release);
    }

    fn stopped(&self) {
        self.0.store(2, Ordering::Release);
    }
}

struct IdentitySignerProbe {
    name: primitives::ProbeName,
    health: Arc<IdentitySignerHealth>,
}

impl bootstrap::HealthProbe for IdentitySignerProbe {
    fn check(&self) -> primitives::HealthCheck {
        match self.health.0.load(Ordering::Acquire) {
            0 => primitives::HealthCheck::new(
                self.name.clone(),
                primitives::HealthStatus::Healthy,
                "signer",
            ),
            1 => primitives::HealthCheck::new(
                self.name.clone(),
                primitives::HealthStatus::Degraded,
                "signer-unavailable",
            ),
            _ => primitives::HealthCheck::new(
                self.name.clone(),
                primitives::HealthStatus::Unhealthy,
                "worker-stopped",
            ),
        }
    }
}

struct IdentitySignerReadinessWorker {
    handle: tokio::sync::Mutex<Option<diport::OwnedTask<()>>>,
    token: CancellationToken,
}

impl IdentitySignerReadinessWorker {
    fn spawn(
        parent: CancellationToken,
        signer: Arc<vault::VaultSigner>,
        key: diport::KeyId,
        health: Arc<IdentitySignerHealth>,
    ) -> Self {
        let token = parent.child_token();
        let worker_token = token.clone();
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(IDENTITY_SIGNER_READINESS_PERIOD);
            loop {
                tokio::select! {
                    _ = worker_token.cancelled() => break,
                    _ = interval.tick() => {
                        health.record(verify_identity_signer(&signer, key.clone()).await.is_ok());
                    }
                }
            }
            health.stopped();
        });
        Self {
            handle: tokio::sync::Mutex::new(Some(diport::OwnedTask::new(handle))),
            token,
        }
    }
}

impl ManagedResource for IdentitySignerReadinessWorker {
    fn name(&self) -> &str {
        IDENTITY_SIGNER_READINESS_WORKER
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.token.cancel();
        if let Some(handle) = self.handle.lock().await.take() {
            handle
                .join()
                .await
                .map_err(ShutdownError::from_join_error)?;
        }
        Ok(())
    }
}

struct IdentitySignerGuard {
    signer: Arc<vault::VaultSigner>,
}

/// Non-forgeable store half of the active device-revocation provider construction.
///
/// The wrapper can only be minted together with [`DeviceRevocationProviderOutput`], so production
/// shared dependencies and catalog evidence consume two halves of the same PostgreSQL handle build.
pub(crate) struct ReceiptBackedRevocationStore(postgres::PgRevocationStore);

impl ReceiptBackedRevocationStore {
    pub(crate) fn into_inner(self) -> postgres::PgRevocationStore {
        self.0
    }
}

/// The dedicated lifecycle half of a device-revocation provider construction.
///
/// Private fields prevent an aggregate PostgreSQL module plus a raw catalog permit from standing
/// in for the required revocation probe and retention worker.
pub(crate) struct DeviceRevocationProviderOutput {
    module: DomainModuleResult,
    permit: DeviceRevocationStorePermit,
}

/// Atomic construction result for the persistent store and its retention lifecycle.
pub(crate) struct BuiltDeviceRevocationProvider {
    store: ReceiptBackedRevocationStore,
    output: DeviceRevocationProviderOutput,
}

impl BuiltDeviceRevocationProvider {
    pub(crate) fn build(
        pg: &PgRuntimeHandle,
        permit: DeviceRevocationStorePermit,
    ) -> anyhow::Result<Self> {
        let module = crate::phase::wire_revocation_sweeper(pg)
            .context("wire certificate revocation sweeper")?;
        Self::from_module(pg, permit, module).map_err(anyhow::Error::new)
    }

    fn from_module(
        pg: &PgRuntimeHandle,
        permit: DeviceRevocationStorePermit,
        module: DomainModuleResult,
    ) -> Result<Self, ProviderBuildError> {
        let actual = module_channels(&module);
        if !same_channels(&actual, CHANNELS_PROBES_WORKERS) {
            return Err(ProviderBuildError::ProviderBatchChannelsMismatch {
                batch: "device-revocation-store",
                expected: CHANNELS_PROBES_WORKERS,
                actual,
            });
        }
        Ok(Self {
            store: ReceiptBackedRevocationStore(pg.infra().revocation_store()),
            output: DeviceRevocationProviderOutput { module, permit },
        })
    }

    pub(crate) fn into_parts(
        self,
    ) -> (ReceiptBackedRevocationStore, DeviceRevocationProviderOutput) {
        (self.store, self.output)
    }
}

impl ManagedResource for IdentitySignerGuard {
    fn name(&self) -> &str {
        "vault-signer"
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.signer.shutdown().await
    }
}

/// One live provider construction output plus the exact generated factory receipts it satisfies.
///
/// Private fields prevent runtime wiring from fabricating a receipt without first consuming the
/// unique permit minted by [`ProviderBuild::claim`].
pub(crate) struct ProviderOutput {
    batches: Vec<ProviderBatch>,
}

struct ProviderBatch {
    module: DomainModuleResult,
    receipts: Vec<ProviderReceipt>,
    batch: &'static str,
    expected_channels: &'static [LifecycleChannel],
}

impl ProviderOutput {
    fn new(
        module: DomainModuleResult,
        receipts: Vec<ProviderReceipt>,
        batch: &'static str,
        expected_channels: &'static [LifecycleChannel],
    ) -> Self {
        Self {
            batches: vec![ProviderBatch {
                module,
                receipts,
                batch,
                expected_channels,
            }],
        }
    }

    pub(crate) fn listener_rate_limiter(permit: ListenerRateLimiterPermit) -> Self {
        Self::new(
            DomainModuleResult::default(),
            vec![ProviderReceipt::ListenerRateLimiter(permit.0)],
            "listener-rate-limiter",
            CHANNELS_NONE,
        )
    }

    fn listener_pdp(
        constructor: ListenerPdpConstructor,
        lifecycle: ListenerPdpJwksLifecycle,
    ) -> Self {
        Self::new(
            lifecycle.into_output(),
            vec![ProviderReceipt::ListenerPdp(constructor.0)],
            "listener-pdp",
            CHANNELS_PROBES_RESOURCES,
        )
    }

    pub(crate) fn redis(module: DomainModuleResult, permit: DistributedLockStorePermit) -> Self {
        Self::new(
            module,
            vec![ProviderReceipt::DistributedLockStore(permit.0)],
            "redis",
            CHANNELS_ALL,
        )
    }

    pub(crate) fn s3(module: DomainModuleResult, permit: RuntimeObjectStorePermit) -> Self {
        Self::new(
            module,
            vec![ProviderReceipt::RuntimeObjectStore(permit.0)],
            "s3",
            CHANNELS_RESOURCES,
        )
    }

    pub(crate) fn vault(
        identity_signer_module: DomainModuleResult,
        settings_key_provider_module: DomainModuleResult,
        settings_secret_resolver_module: DomainModuleResult,
        identity_signer: IdentitySignerPermit,
        settings_key_provider: SettingsKeyProviderPermit,
        settings_secret_resolver: SettingsSecretResolverPermit,
    ) -> Self {
        Self {
            batches: vec![
                ProviderBatch {
                    module: identity_signer_module,
                    receipts: vec![ProviderReceipt::IdentitySigner(identity_signer.0)],
                    batch: "identity-signer",
                    expected_channels: CHANNELS_ALL,
                },
                ProviderBatch {
                    module: settings_key_provider_module,
                    receipts: vec![ProviderReceipt::SettingsKeyProvider(
                        settings_key_provider.0,
                    )],
                    batch: "vault-settings-key-provider",
                    expected_channels: CHANNELS_ALL,
                },
                ProviderBatch {
                    module: settings_secret_resolver_module,
                    receipts: vec![ProviderReceipt::SettingsSecretResolver(
                        settings_secret_resolver.0,
                    )],
                    batch: "vault-settings-secret-resolver",
                    expected_channels: CHANNELS_ALL,
                },
            ],
        }
    }

    pub(crate) fn postgres(
        mut module: DomainModuleResult,
        device_revocation_store: DeviceRevocationProviderOutput,
        auth_audit_sink: AuthAuditSinkPermit,
        distributed_cas_store: DistributedCasStorePermit,
        service_token_replay_store: ServiceTokenReplayStorePermit,
    ) -> Self {
        let DeviceRevocationProviderOutput {
            module: revocation_module,
            permit: device_revocation_store,
        } = device_revocation_store;
        module.merge(revocation_module);
        Self::new(
            module,
            vec![
                ProviderReceipt::DeviceRevocationStore(device_revocation_store.0),
                ProviderReceipt::AuthAuditSink(auth_audit_sink.0),
                ProviderReceipt::DistributedCasStore(distributed_cas_store.0),
                ProviderReceipt::ServiceTokenReplayStore(service_token_replay_store.0),
            ],
            "postgres",
            CHANNELS_ALL,
        )
    }

    pub(crate) fn dlx(
        lifecycle_module: DomainModuleResult,
        archive_store_module: DomainModuleResult,
        archive_key_module: DomainModuleResult,
        lifecycle_repository: DlxLifecycleRepositoryPermit,
        archive_store: DlxArchiveStorePermit,
        archive_key_provider: DlxArchiveKeyProviderPermit,
    ) -> Self {
        Self {
            batches: vec![
                ProviderBatch {
                    module: lifecycle_module,
                    receipts: vec![ProviderReceipt::DlxLifecycleRepository(
                        lifecycle_repository.0,
                    )],
                    batch: "dlx-lifecycle-repository",
                    expected_channels: CHANNELS_ALL,
                },
                ProviderBatch {
                    module: archive_store_module,
                    receipts: vec![ProviderReceipt::DlxArchiveStore(archive_store.0)],
                    batch: "dlx-archive-store",
                    expected_channels: CHANNELS_PROBES_WORKERS,
                },
                ProviderBatch {
                    module: archive_key_module,
                    receipts: vec![ProviderReceipt::DlxArchiveKeyProvider(
                        archive_key_provider.0,
                    )],
                    batch: "dlx-archive-key-provider",
                    expected_channels: CHANNELS_ALL,
                },
            ],
        }
    }

    pub(crate) fn event(
        module: DomainModuleResult,
        publisher: EventPublisherPermit,
        subscriber: EventSubscriberPermit,
    ) -> Self {
        Self::new(
            module,
            vec![
                ProviderReceipt::EventPublisher(publisher.0),
                ProviderReceipt::EventSubscriber(subscriber.0),
            ],
            "event",
            CHANNELS_ALL,
        )
    }
}

pub(crate) fn commit_listener_pdp_jwks_lifecycle(
    constructor: ListenerPdpConstructor,
    lifecycle: ListenerPdpJwksLifecycle,
) -> ProviderOutput {
    ProviderOutput::listener_pdp(constructor, lifecycle)
}

struct ProviderFactoryPermit {
    factory: ProviderFactorySymbol,
    role: ProviderRole,
    expected_channels: &'static [LifecycleChannel],
}

const CHANNELS_NONE: &[LifecycleChannel] = &[];
const CHANNELS_PROBES_RESOURCES: &[LifecycleChannel] =
    &[LifecycleChannel::Probes, LifecycleChannel::Resources];
const CHANNELS_PROBES_WORKERS: &[LifecycleChannel] =
    &[LifecycleChannel::Probes, LifecycleChannel::Workers];
const CHANNELS_RESOURCES: &[LifecycleChannel] = &[LifecycleChannel::Resources];
const CHANNELS_ALL: &[LifecycleChannel] = &[
    LifecycleChannel::Probes,
    LifecycleChannel::Resources,
    LifecycleChannel::Workers,
];

/// Single declaration surface for typed one-shot factory permits.
///
/// Generates permit newtypes, receipts, dispatch fields, catalog join, completeness checks, and
/// consuming accessors so expanding the active catalog cannot Soft-drift across three hand sites.
macro_rules! provider_permits {
    (
        $(
            $permit:ident {
                field: $field:ident,
                factory: $factory:ident,
                receipt: $receipt:ident,
                channels: $channels:expr $(,)?
            }
        ),+ $(,)?
    ) => {
        $(pub(crate) struct $permit(ProviderFactoryPermit);)+

        enum ProviderReceipt {
            $($receipt(ProviderFactoryPermit),)+
        }

        impl ProviderReceipt {
            fn permit(&self) -> &ProviderFactoryPermit {
                match self {
                    // Leading path segment / `arm @` keeps flattened repetition tokens from looking
                    // like `$root::$module` to runtime-env composed-path scanner.
                    $(arm @ Self::$receipt(_) => match arm {
                        Self::$receipt(permit) => permit,
                        _ => unreachable!("provider receipt arm is closed"),
                    },)+
                }
            }

            fn sealed_channels(&self) -> &'static [LifecycleChannel] {
                match self {
                    $(arm @ Self::$receipt(_) => {
                        let _ = arm;
                        $channels
                    },)+
                }
            }
        }

        /// Closed, generated-catalog-derived dispatch capability.
        ///
        /// Each named accessor consumes exactly one permit. There is no string lookup, generic
        /// service locator, fallback constructor, or way to mint a permit outside this module.
        pub(crate) struct ProviderFactoryDispatch {
            $($field: Option<$permit>,)+
        }

        impl ProviderFactoryDispatch {
            pub(crate) fn from_catalog(
                build: &mut ProviderBuild,
                catalog: &[ProviderCatalogEntry],
            ) -> Result<Self, ProviderBuildError> {
                let mut dispatch = Self {
                    $($field: None,)+
                };
                for entry in catalog {
                    if let Some(detail) = foreign_runtime_catalog_drift(entry.factory()) {
                        return Err(ProviderBuildError::PlanCatalogDrift { detail });
                    }
                    let permit = build.claim(entry.factory())?;
                    // Leading `::` keeps flattened `$(::Path::$meta)` from matching runtime-env
                    // composed-path (`$ident::$ident`) while preserving exhaustive match Hardness.
                    let duplicate = match entry.factory() {
                        $(::assembly_schema::ProviderFactorySymbol::$factory => dispatch
                            .$field
                            .replace($permit(permit))
                            .is_some(),)+
                        other => {
                            return Err(ProviderBuildError::PlanCatalogDrift {
                                detail: format!(
                                    "runtime catalog contains unsupported factory '{}'",
                                    other.as_str()
                                ),
                            });
                        }
                    };
                    if duplicate {
                        return Err(ProviderBuildError::DuplicateFactory {
                            factory: entry.factory(),
                        });
                    }
                }
                dispatch.require_complete()?;
                Ok(dispatch)
            }

            fn require_complete(&self) -> Result<(), ProviderBuildError> {
                for (factory, present) in [
                    $((::assembly_schema::ProviderFactorySymbol::$factory, self.$field.is_some()),)+
                ] {
                    if !present {
                        return Err(ProviderBuildError::PlanCatalogDrift {
                            detail: format!(
                                "generated active catalog omits factory '{}'",
                                factory.as_str()
                            ),
                        });
                    }
                }
                Ok(())
            }

            fn take<T>(
                slot: &mut Option<T>,
                factory: ProviderFactorySymbol,
            ) -> Result<T, ProviderBuildError> {
                slot.take()
                    .ok_or(ProviderBuildError::FactoryPermitAlreadyConsumed { factory })
            }

            $(
                pub(crate) fn $field(&mut self) -> Result<$permit, ProviderBuildError> {
                    Self::take(
                        &mut self.$field,
                        ::assembly_schema::ProviderFactorySymbol::$factory,
                    )
                }
            )+
        }
    };
}

provider_permits! {
    DeviceRevocationStorePermit {
        field: device_revocation_store,
        factory: DeviceloopPostgresRevocationStore,
        receipt: DeviceRevocationStore,
        channels: CHANNELS_PROBES_WORKERS,
    },
    AuthAuditSinkPermit {
        field: auth_audit_sink,
        factory: HttpservePostgresAuthAuditSink,
        receipt: AuthAuditSink,
        channels: CHANNELS_ALL,
    },
    DistributedCasStorePermit {
        field: distributed_cas_store,
        factory: DistributedPostgresCasStore,
        receipt: DistributedCasStore,
        channels: CHANNELS_ALL,
    },
    DistributedLockStorePermit {
        field: distributed_lock_store,
        factory: DistributedRedisLockStore,
        receipt: DistributedLockStore,
        channels: CHANNELS_ALL,
    },
    DlxArchiveKeyProviderPermit {
        field: dlx_archive_key_provider,
        factory: EventexecVaultArchiveKeyProvider,
        receipt: DlxArchiveKeyProvider,
        channels: CHANNELS_ALL,
    },
    DlxArchiveStorePermit {
        field: dlx_archive_store,
        factory: EventexecS3DlxArchiveStore,
        receipt: DlxArchiveStore,
        channels: CHANNELS_PROBES_WORKERS,
    },
    DlxLifecycleRepositoryPermit {
        field: dlx_lifecycle_repository,
        factory: EventexecPostgresDlxLifecycleRepository,
        receipt: DlxLifecycleRepository,
        channels: CHANNELS_ALL,
    },
    EventPublisherPermit {
        field: event_publisher,
        factory: EventexecAmqpPublisher,
        receipt: EventPublisher,
        channels: CHANNELS_ALL,
    },
    EventSubscriberPermit {
        field: event_subscriber,
        factory: EventexecAmqpSubscriber,
        receipt: EventSubscriber,
        channels: CHANNELS_ALL,
    },
    IdentitySignerPermit {
        field: identity_signer,
        factory: IdentityVaultSigner,
        receipt: IdentitySigner,
        channels: CHANNELS_ALL,
    },
    ListenerPdpConstructor {
        field: listener_pdp,
        factory: HttpserveOidcPdp,
        receipt: ListenerPdp,
        channels: CHANNELS_PROBES_RESOURCES,
    },
    ListenerRateLimiterPermit {
        field: listener_rate_limiter,
        factory: HttpserveGovernorRateLimiter,
        receipt: ListenerRateLimiter,
        channels: CHANNELS_NONE,
    },
    RuntimeObjectStorePermit {
        field: runtime_object_store,
        factory: RuntimeS3ObjectStore,
        receipt: RuntimeObjectStore,
        channels: CHANNELS_RESOURCES,
    },
    ServiceTokenReplayStorePermit {
        field: service_token_replay_store,
        factory: OidcPostgresServiceTokenReplayStore,
        receipt: ServiceTokenReplayStore,
        channels: CHANNELS_ALL,
    },
    SettingsKeyProviderPermit {
        field: settings_key_provider,
        factory: SettingsVaultKeyProvider,
        receipt: SettingsKeyProvider,
        channels: CHANNELS_ALL,
    },
    SettingsSecretResolverPermit {
        field: settings_secret_resolver,
        factory: SettingsVaultSecretResolver,
        receipt: SettingsSecretResolver,
        channels: CHANNELS_ALL,
    },
}

#[derive(Clone, Copy)]
struct ExpectedProvider {
    role: ProviderRole,
    channels: &'static [LifecycleChannel],
}

/// Factories that belong to other assemblies and must never appear in runtime's catalog.
fn foreign_runtime_catalog_drift(factory: ProviderFactorySymbol) -> Option<String> {
    match factory {
        ProviderFactorySymbol::EventexecVaultHotKeyProvider => {
            Some("runtime catalog contains settingsonly-only DLX hot-key factory".to_owned())
        }
        ProviderFactorySymbol::IdentityPostgresDeviceCertificateStore
        | ProviderFactorySymbol::IdentityPostgresDeviceCommandStore
        | ProviderFactorySymbol::IdentityDraftArtifactSimulator
        | ProviderFactorySymbol::IdentityMqttSession => Some(format!(
            "runtime catalog contains device-identity-only factory '{}'",
            factory.as_str()
        )),
        _ => None,
    }
}

/// Transactional owner for all active provider construction during startup.
///
/// INVARIANT: RUNTIME-PROVIDER-BIJECTION-01 { level = "Hard", exec = "native-compile", source = "code", native = "private receipt permits, exhaustive generated catalog join, consuming finish, and non-Clone lifecycle owner" } -- every active generated factory is claimable exactly once, every claim must return an exact-channel receipt, and only a completed build can release lifecycle output to launch.
/// INVARIANT: RUNTIME-PROVIDER-BIJECTION-LIVE-01 { level = "Medium", exec = "test", source = "code", synthetic_red = "tests::provider_plan_active_catalog_claims_all_factories_exactly_once + tests::provider_plan_rejects_missing_extra_duplicate_and_draft_production + tests::provider_plan_rejects_duplicate_factory_receipts + tests::provider_output_partial_build_abort_is_lifo_once_and_preserves_primary_error + tests::provider_factory_dispatch_rejects_second_permit_consumption", anti_vacuity = "tests::provider_plan_active_catalog_claims_all_factories_exactly_once + tests::provider_factory_permits_are_non_copyable_and_non_interchangeable" } -- catalog exact join, receipt completeness, one-shot permit consumption, partial rollback, and primary-error preservation are behavior-owned beside the transactional provider owner; cross-file raw construction and receipt bypass risk remains in `RUNTIME-PROVIDER-BYPASS-01`.
pub(crate) struct ProviderBuild {
    expected: BTreeMap<ProviderFactorySymbol, ExpectedProvider>,
    claimed: BTreeSet<ProviderFactorySymbol>,
    produced: BTreeSet<ProviderFactorySymbol>,
    probe_bindings: BTreeMap<ProviderRole, Vec<primitives::ProbeName>>,
    provider_module: DomainModuleResult,
    domain_module: DomainModuleResult,
}

impl ProviderBuild {
    pub(crate) fn from_plan(
        provider_plans: &[ProviderPlan],
        catalog: &[ProviderCatalogEntry],
    ) -> Result<Self, ProviderBuildError> {
        let mut expected = BTreeMap::new();
        let mut roles = BTreeSet::new();
        for entry in catalog {
            if !roles.insert(entry.role()) {
                return Err(ProviderBuildError::PlanCatalogDrift {
                    detail: format!(
                        "generated catalog repeats provider role '{}'",
                        entry.role().as_str()
                    ),
                });
            }
            if expected
                .insert(
                    entry.factory(),
                    ExpectedProvider {
                        role: entry.role(),
                        channels: entry.evidence().outputs(),
                    },
                )
                .is_some()
            {
                return Err(ProviderBuildError::PlanCatalogDrift {
                    detail: format!(
                        "generated catalog repeats factory '{}'",
                        entry.factory().as_str()
                    ),
                });
            }

            let matching = provider_plans
                .iter()
                .filter(|plan| plan.id() == entry.role().as_str())
                .collect::<Vec<_>>();
            let [plan] = matching.as_slice() else {
                return Err(ProviderBuildError::PlanCatalogDrift {
                    detail: format!(
                        "active provider role '{}' has {} RuntimePlan declarations",
                        entry.role().as_str(),
                        matching.len()
                    ),
                });
            };
            if plan.constructor() != entry.evidence().constructor()
                || !same_channels(plan.outputs(), entry.evidence().outputs())
            {
                return Err(ProviderBuildError::PlanCatalogDrift {
                    detail: format!(
                        "RuntimePlan declaration for '{}' disagrees with generated catalog",
                        entry.role().as_str()
                    ),
                });
            }
        }
        if expected.is_empty() {
            return Err(ProviderBuildError::PlanCatalogDrift {
                detail: "generated active provider catalog is empty".to_owned(),
            });
        }

        Ok(Self {
            expected,
            claimed: BTreeSet::new(),
            produced: BTreeSet::new(),
            probe_bindings: BTreeMap::new(),
            provider_module: DomainModuleResult::default(),
            domain_module: DomainModuleResult::default(),
        })
    }

    fn claim(
        &mut self,
        factory: ProviderFactorySymbol,
    ) -> Result<ProviderFactoryPermit, ProviderBuildError> {
        let expected = self
            .expected
            .get(&factory)
            .copied()
            .ok_or(ProviderBuildError::UndeclaredFactory { factory })?;
        if !self.claimed.insert(factory) {
            return Err(ProviderBuildError::DuplicateFactory { factory });
        }
        Ok(ProviderFactoryPermit {
            factory,
            role: expected.role,
            expected_channels: expected.channels,
        })
    }

    pub(crate) fn record(&mut self, output: ProviderOutput) -> Result<(), ProviderBuildError> {
        let mut validation = Ok(());
        let mut batch_factories = BTreeSet::new();
        let mut factories = Vec::new();
        let mut probe_bindings = Vec::new();
        for batch in &output.batches {
            let actual_channels = module_channels(&batch.module);
            if validation.is_ok() && !same_channels(&actual_channels, batch.expected_channels) {
                validation = Err(ProviderBuildError::ProviderBatchChannelsMismatch {
                    batch: batch.batch,
                    expected: batch.expected_channels,
                    actual: actual_channels,
                });
            }
            let probe_names = batch
                .module
                .probes
                .iter()
                .map(|(name, _)| name.clone())
                .collect::<Vec<_>>();
            for receipt in &batch.receipts {
                let permit = receipt.permit();
                if validation.is_ok()
                    && !same_channels(permit.expected_channels, receipt.sealed_channels())
                {
                    validation = Err(ProviderBuildError::PlanCatalogDrift {
                        detail: format!(
                            "generated catalog channels for '{}' disagree with sealed factory output",
                            permit.role.as_str()
                        ),
                    });
                }
                if validation.is_ok()
                    && (self.produced.contains(&permit.factory)
                        || !batch_factories.insert(permit.factory))
                {
                    validation = Err(ProviderBuildError::DuplicateFactory {
                        factory: permit.factory,
                    });
                }
                factories.push(permit.factory);
                probe_bindings.push((permit.role, probe_names.clone()));
            }
        }
        // Ownership transfer precedes validation propagation: even a bad receipt/channel batch
        // remains inside the startup transaction and therefore receives async rollback.
        for batch in output.batches {
            self.provider_module.merge(batch.module);
        }
        validation?;
        for factory in factories {
            if !self.produced.insert(factory) {
                return Err(ProviderBuildError::DuplicateFactory { factory });
            }
        }
        for (role, probe_names) in probe_bindings {
            if self.probe_bindings.insert(role, probe_names).is_some() {
                return Err(ProviderBuildError::PlanCatalogDrift {
                    detail: format!(
                        "provider role '{}' produced more than one probe binding",
                        role.as_str()
                    ),
                });
            }
        }
        Ok(())
    }

    pub(crate) fn record_domain(&mut self, module: DomainModuleResult) {
        self.domain_module.merge(module);
    }

    pub(crate) async fn abort_with(
        mut self,
        module: DomainModuleResult,
        primary: anyhow::Error,
    ) -> anyhow::Error {
        self.provider_module.merge(module);
        self.abort(primary).await
    }

    pub(crate) fn finish(self) -> Result<CompletedProviderBuild, ProviderBuildFailure> {
        let missing = self
            .expected
            .iter()
            .filter(|(factory, _)| !self.produced.contains(factory))
            .map(|(factory, expected)| {
                if expected.channels.is_empty() {
                    format!(
                        "{} ({}) missing construction receipt; outputs=[]",
                        expected.role.as_str(),
                        factory.as_str()
                    )
                } else {
                    format!(
                        "{} ({}) missing channels {:?}",
                        expected.role.as_str(),
                        factory.as_str(),
                        expected.channels
                    )
                }
            })
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            let error = ProviderBuildError::MissingProviderReceipts {
                missing: missing.join("; "),
            };
            return Err(ProviderBuildFailure {
                build: Box::new(self),
                error,
            });
        }
        let probe_bindings = match self
            .probe_bindings
            .iter()
            .map(|(role, probes)| {
                runtimeexec::inventory::ProviderProbeBinding::new(role.as_str(), probes.clone())
                    .map_err(|_| ProviderBuildError::PlanCatalogDrift {
                        detail: format!(
                            "provider role '{}' produced an invalid probe binding",
                            role.as_str()
                        ),
                    })
            })
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(bindings) => bindings,
            Err(error) => {
                return Err(ProviderBuildFailure {
                    build: Box::new(self),
                    error,
                });
            }
        };
        Ok(CompletedProviderBuild {
            provider_module: self.provider_module,
            domain_module: self.domain_module,
            inventory_receipt: Some(ProviderInventoryReceipt(probe_bindings)),
        })
    }

    pub(crate) async fn abort(self, primary: anyhow::Error) -> anyhow::Error {
        abort_modules(self.provider_module, self.domain_module, primary).await
    }
}

pub(crate) async fn abort_uncommitted(
    module: DomainModuleResult,
    primary: anyhow::Error,
) -> anyhow::Error {
    abort_modules(module, DomainModuleResult::default(), primary).await
}

async fn abort_modules(
    provider_module: DomainModuleResult,
    domain_module: DomainModuleResult,
    primary: anyhow::Error,
) -> anyhow::Error {
    let mut stack =
        bootstrap::shutdown::ShutdownStack::new(tokio_util::sync::CancellationToken::new());
    for resource in provider_module.resources {
        stack.register_detached(resource);
    }
    for resource in domain_module.resources {
        stack.register_detached(resource);
    }
    for failure in stack.shutdown().await {
        tracing::error!(
            cleanup_error = %failure,
            "partial runtime assembly cleanup failed; preserving primary startup error"
        );
    }
    primary
}

fn same_channels(actual: &[LifecycleChannel], expected: &[LifecycleChannel]) -> bool {
    actual.len() == expected.len()
        && actual.iter().all(|channel| expected.contains(channel))
        && expected.iter().all(|channel| actual.contains(channel))
}

fn module_channels(module: &DomainModuleResult) -> Vec<LifecycleChannel> {
    let mut channels = Vec::with_capacity(3);
    if !module.probes.is_empty() {
        channels.push(LifecycleChannel::Probes);
    }
    if !module.resources.is_empty() {
        channels.push(LifecycleChannel::Resources);
    }
    if !module.workers.is_empty() {
        channels.push(LifecycleChannel::Workers);
    }
    channels
}

pub(crate) struct CompletedProviderBuild {
    provider_module: DomainModuleResult,
    domain_module: DomainModuleResult,
    inventory_receipt: Option<ProviderInventoryReceipt>,
}

impl CompletedProviderBuild {
    pub(crate) fn take_inventory_receipt(&mut self) -> anyhow::Result<ProviderInventoryReceipt> {
        self.inventory_receipt.take().ok_or_else(|| {
            anyhow::anyhow!("provider inventory receipt was consumed more than once")
        })
    }
    pub(crate) fn register_probes(
        &mut self,
        registry: &mut bootstrap::Registry,
    ) -> anyhow::Result<()> {
        for (source, probes) in [
            ("provider", std::mem::take(&mut self.provider_module.probes)),
            ("domain", std::mem::take(&mut self.domain_module.probes)),
        ] {
            for (name, probe) in probes {
                let probe_label = name.as_str().to_owned();
                registry
                    .probe(name, probe)
                    .with_context(|| format!("register {source} probe '{probe_label}'"))?;
            }
        }
        Ok(())
    }

    pub(crate) fn into_launch_batches(self) -> runtimeexec::LaunchLifecycleBatches {
        runtimeexec::LaunchLifecycleBatches::new(
            runtimeexec::ProviderLifecycleBatch::from_provider_output(self.provider_module),
            runtimeexec::DomainLifecycleBatch::from_domain_output(self.domain_module),
        )
    }

    pub(crate) async fn abort(self, primary: anyhow::Error) -> anyhow::Error {
        abort_modules(self.provider_module, self.domain_module, primary).await
    }
}

pub(crate) struct ProviderInventoryReceipt(Vec<runtimeexec::inventory::ProviderProbeBinding>);

impl ProviderInventoryReceipt {
    pub(crate) fn into_probe_bindings(self) -> Vec<runtimeexec::inventory::ProviderProbeBinding> {
        self.0
    }
}

pub(crate) struct ProviderBuildFailure {
    build: Box<ProviderBuild>,
    error: ProviderBuildError,
}

impl std::fmt::Debug for ProviderBuildFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProviderBuildFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl ProviderBuildFailure {
    #[cfg(test)]
    pub(crate) fn error(&self) -> &ProviderBuildError {
        &self.error
    }

    pub(crate) async fn abort(self) -> anyhow::Error {
        let Self { build, error } = self;
        (*build).abort(anyhow::Error::new(error)).await
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ProviderBuildError {
    #[error("RuntimePlan/generated provider catalog drift: {detail}")]
    PlanCatalogDrift { detail: String },
    #[error("provider factory '{factory}' is not declared by the active generated catalog")]
    UndeclaredFactory { factory: ProviderFactorySymbol },
    #[error("provider factory '{factory}' was constructed more than once")]
    DuplicateFactory { factory: ProviderFactorySymbol },
    #[error("provider factory permit '{factory}' was consumed more than once")]
    FactoryPermitAlreadyConsumed { factory: ProviderFactorySymbol },
    #[error(
        "provider batch '{batch}' lifecycle channels drift: expected {expected:?}, actual {actual:?}"
    )]
    ProviderBatchChannelsMismatch {
        batch: &'static str,
        expected: &'static [LifecycleChannel],
        actual: Vec<LifecycleChannel>,
    },
    #[error("active providers are missing construction receipts: {missing}")]
    MissingProviderReceipts { missing: String },
}

#[cfg(test)]
mod tests {
    use super::{
        BuiltDeviceRevocationProvider, CHANNELS_ALL, CHANNELS_PROBES_WORKERS, CHANNELS_RESOURCES,
        DeviceRevocationStorePermit, DistributedLockStorePermit, IdentitySignerReadinessWorker,
        ListenerPdpConstructor, ProviderBuild, ProviderBuildError, ProviderFactoryDispatch,
        ProviderFactoryPermit, ProviderOutput, ProviderReceipt, RuntimeObjectStorePermit,
        build_pg_runtime_module, commit_listener_pdp_jwks_lifecycle,
    };
    use crate::providers_gen::ListenerPdpJwksLifecycle;

    use assembly_schema::{
        LifecycleChannel as PlannedLifecycleChannel, ProviderFactorySymbol, ProviderRole,
    };
    use bootstrap::{DomainModuleResult, HealthProbe, WorkerSpec};
    use diport::{DynManagedResource, ManagedResource, ShutdownError};
    use primitives::{HealthCheck, HealthStatus, ProbeName};
    use std::collections::BTreeSet;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use crate::providers_gen::PROVIDER_CATALOG;

    const LISTENER_PDP_CHANNELS: &[PlannedLifecycleChannel] = &[
        PlannedLifecycleChannel::Probes,
        PlannedLifecycleChannel::Resources,
    ];
    const LISTENER_PDP_JWKS_PROBE_NAME: &str = "rss_access_token_jwks_ready";

    #[tokio::test]
    #[allow(clippy::expect_used, clippy::panic)]
    async fn identity_signer_readiness_worker_propagates_join_failures() {
        const MARKER: &str = "identity-signer-readiness-plain-panic-secret";
        let panicked = IdentitySignerReadinessWorker {
            handle: tokio::sync::Mutex::new(Some(diport::OwnedTask::new(tokio::spawn(async {
                panic!("{MARKER}");
            })))),
            token: tokio_util::sync::CancellationToken::new(),
        };
        let panic_error = ManagedResource::shutdown(&panicked)
            .await
            .expect_err("panic join must propagate");
        assert_eq!(panic_error.kind(), diport::ShutdownErrorKind::TaskPanicked);
        assert!(!format!("{panic_error:?}").contains(MARKER));

        let cancelled_handle = tokio::spawn(std::future::pending::<()>());
        cancelled_handle.abort();
        let cancelled = IdentitySignerReadinessWorker {
            handle: tokio::sync::Mutex::new(Some(diport::OwnedTask::new(cancelled_handle))),
            token: tokio_util::sync::CancellationToken::new(),
        };
        let cancelled_error = ManagedResource::shutdown(&cancelled)
            .await
            .expect_err("cancelled join must propagate");
        assert_eq!(
            cancelled_error.kind(),
            diport::ShutdownErrorKind::TaskCancelled
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn provider_plan_active_catalog_claims_all_factories_exactly_once() {
        let (mut build, mut dispatch) = provider_build_and_dispatch();
        record_all_batches(&mut build, &mut dispatch, true, true);
        let mut completed = build
            .finish()
            .expect("all active factories produced exact receipts");
        // finish() already required one receipt per active catalog factory; pin occupancy shape.
        assert!(!PROVIDER_CATALOG.is_empty());
        assert_eq!(completed.provider_module.probes.len(), 11);
        assert_eq!(completed.provider_module.resources.len(), 10);
        assert_eq!(completed.provider_module.workers.len(), 10);
        assert!(completed.domain_module.probes.is_empty());
        assert!(completed.domain_module.resources.is_empty());
        assert!(completed.domain_module.workers.is_empty());
        let receipt = completed
            .take_inventory_receipt()
            .expect("inventory receipt is present exactly once");
        let bindings = receipt.into_probe_bindings();
        assert_eq!(bindings.len(), PROVIDER_CATALOG.len());
        let provider_binding = |provider_id| {
            bindings
                .iter()
                .find(|binding| binding.provider_id() == provider_id)
                .unwrap_or_else(|| unreachable!("missing {provider_id} binding"))
        };
        assert_eq!(
            provider_binding("listener-pdp")
                .probe_names()
                .iter()
                .map(ProbeName::as_str)
                .collect::<Vec<_>>(),
            [LISTENER_PDP_JWKS_PROBE_NAME],
            "listener PDP receipt must bind its exact JWKS readiness probe"
        );
        assert_eq!(
            provider_binding("dlx-lifecycle-repository").probe_names()[0].as_str(),
            "dlx-lifecycle"
        );
        assert_eq!(
            provider_binding("dlx-archive-store").probe_names()[0].as_str(),
            "dlx-archive-store"
        );
        assert_eq!(
            provider_binding("dlx-archive-key-provider").probe_names()[0].as_str(),
            "dlx-archive-key"
        );
        assert!(
            completed.take_inventory_receipt().is_err(),
            "inventory completion receipt must be move-only"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn provider_plan_rejects_missing_extra_duplicate_and_draft_production()
    -> anyhow::Result<()> {
        let plan = bundled_provider_plan();
        let plans = plan.as_typed().provider_plans();

        let mut missing_zero_output =
            ProviderBuild::from_plan(plans, PROVIDER_CATALOG).expect("bundled provider build");
        let mut missing_dispatch =
            ProviderFactoryDispatch::from_catalog(&mut missing_zero_output, PROVIDER_CATALOG)
                .expect("dispatch");
        record_all_batches(
            &mut missing_zero_output,
            &mut missing_dispatch,
            false,
            false,
        );
        let missing_zero_output_failure = missing_zero_output
            .finish()
            .err()
            .ok_or_else(|| anyhow::anyhow!("outputs=[] still requires a provider receipt"))?;
        let ProviderBuildError::MissingProviderReceipts { missing } =
            missing_zero_output_failure.error()
        else {
            anyhow::bail!("expected missing provider receipts");
        };
        assert!(missing.contains("listener-rate-limiter"));
        assert!(missing.contains("missing construction receipt; outputs=[]"));
        assert!(missing.contains("listener-pdp"));
        assert!(missing.contains("missing channels [Probes, Resources]"));
        Ok(())
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn provider_plan_rejects_duplicate_factory_receipts() -> anyhow::Result<()> {
        let (mut duplicate, mut duplicate_dispatch) = provider_build_and_dispatch();
        duplicate
            .record(commit_listener_pdp_jwks_lifecycle(
                duplicate_dispatch
                    .listener_pdp()
                    .expect("listener PDP permit"),
                listener_pdp_lifecycle_for_test("first-pdp"),
            ))
            .expect("first listener PDP output");
        let entry = PROVIDER_CATALOG
            .iter()
            .find(|entry| entry.factory() == ProviderFactorySymbol::HttpserveOidcPdp)
            .expect("listener PDP catalog entry");
        let forged_duplicate = ListenerPdpConstructor(ProviderFactoryPermit {
            factory: entry.factory(),
            role: entry.role(),
            expected_channels: entry.evidence().outputs(),
        });
        let duplicate_error = duplicate
            .record(commit_listener_pdp_jwks_lifecycle(
                forged_duplicate,
                listener_pdp_lifecycle_for_test("second-pdp"),
            ))
            .expect_err("release builds must reject a duplicate receipt");
        let ProviderBuildError::DuplicateFactory { factory: actual } = duplicate_error else {
            anyhow::bail!("expected duplicate factory");
        };
        assert_eq!(actual, ProviderFactorySymbol::HttpserveOidcPdp);
        Ok(())
    }

    #[test]
    fn provider_plan_keeps_remaining_draft_role_out_of_active_dispatch() {
        let plan = bundled_provider_plan();
        let plans = plan.as_typed().provider_plans();
        let plan_ids = plans
            .iter()
            .map(assembly_schema::ProviderPlan::id)
            .collect::<BTreeSet<_>>();
        let draft = ProviderRole::DistributedCasStoreAlternative;
        assert!(!plan_ids.contains(draft.as_str()));
        assert!(
            draft.factory_symbol().is_none(),
            "draft provider must not expose a claimable factory permit"
        );
        assert!(
            PROVIDER_CATALOG.iter().all(|entry| entry.role() != draft),
            "draft provider must not enter active dispatch"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn provider_output_partial_build_abort_is_lifo_once_and_preserves_primary_error() {
        let (mut build, mut dispatch) = provider_build_and_dispatch();
        let shutdowns = Arc::new(Mutex::new(Vec::new()));
        let worker_starts = Arc::new(AtomicUsize::new(0));

        build
            .record(ProviderOutput::redis(
                recording_module_all("first-resource", Arc::clone(&shutdowns)),
                dispatch.distributed_lock_store().expect("redis permit"),
            ))
            .expect("record redis");
        build
            .record(ProviderOutput::s3(
                recording_module("second-resource", Arc::clone(&shutdowns)),
                dispatch.runtime_object_store().expect("S3 permit"),
            ))
            .expect("record S3");
        build.record_domain(recording_module("domain-resource", Arc::clone(&shutdowns)));
        let invalid = DomainModuleResult {
            resources: vec![DynManagedResource::new_box(RecordingResource {
                name: "invalid-resource",
                shutdowns: Arc::clone(&shutdowns),
            })],
            workers: vec![counting_worker(
                "invalid-worker",
                Arc::clone(&worker_starts),
            )],
            ..DomainModuleResult::default()
        };
        let constructor = dispatch.listener_pdp().expect("PDP constructor");
        let primary = build
            .record(ProviderOutput::new(
                invalid,
                vec![ProviderReceipt::ListenerPdp(constructor.0)],
                "listener-pdp",
                super::CHANNELS_PROBES_RESOURCES,
            ))
            .expect_err("invalid PDP batch");

        let returned = build.abort(anyhow::Error::new(primary)).await;

        assert!(
            returned.downcast_ref::<ProviderBuildError>().is_some(),
            "rollback diagnostics must not replace the primary factory error"
        );
        assert_eq!(
            *shutdowns.lock().expect("shutdown recording mutex"),
            [
                "domain-resource",
                "invalid-resource",
                "second-resource",
                "first-resource",
            ],
            "domain and invalid-batch resources must be shut down once in LIFO order"
        );
        assert_eq!(
            worker_starts.load(Ordering::SeqCst),
            0,
            "partial-build rollback must never start workers"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn provider_plan_rejects_catalog_plan_drift_variants() -> anyhow::Result<()> {
        let plan = bundled_provider_plan();
        let plans = plan.as_typed().provider_plans();

        let Err(empty) = ProviderBuild::from_plan(plans, &[]) else {
            anyhow::bail!("empty generated catalog must fail closed");
        };
        assert!(matches!(
            empty,
            ProviderBuildError::PlanCatalogDrift { detail } if detail.contains("empty")
        ));

        let duplicated = [PROVIDER_CATALOG[0], PROVIDER_CATALOG[0]];
        let Err(duplicated) = ProviderBuild::from_plan(plans, &duplicated) else {
            anyhow::bail!("duplicate catalog factory must fail closed");
        };
        assert!(matches!(
            duplicated,
            ProviderBuildError::PlanCatalogDrift { detail }
                if detail.contains("repeats factory") || detail.contains("repeats provider role")
        ));

        let Err(missing_plans) = ProviderBuild::from_plan(&[], PROVIDER_CATALOG) else {
            anyhow::bail!("catalog without RuntimePlan declarations must fail closed");
        };
        assert!(matches!(
            missing_plans,
            ProviderBuildError::PlanCatalogDrift { detail }
                if detail.contains("RuntimePlan declarations")
        ));

        let subset = &PROVIDER_CATALOG[..1];
        let mut incomplete = ProviderBuild::from_plan(plans, subset).expect("single-entry join");
        let Err(incomplete) = ProviderFactoryDispatch::from_catalog(&mut incomplete, subset) else {
            anyhow::bail!("incomplete catalog must fail require_complete");
        };
        assert!(matches!(
            incomplete,
            ProviderBuildError::PlanCatalogDrift { detail }
                if detail.contains("omits factory")
        ));

        let (mut sealed, _sealed_dispatch) = provider_build_and_dispatch();
        let entry = PROVIDER_CATALOG
            .iter()
            .find(|entry| entry.factory() == ProviderFactorySymbol::HttpserveOidcPdp)
            .expect("listener PDP catalog entry");
        let forged = ListenerPdpConstructor(ProviderFactoryPermit {
            factory: entry.factory(),
            role: entry.role(),
            expected_channels: CHANNELS_ALL,
        });
        let Err(sealed_err) = sealed.record(commit_listener_pdp_jwks_lifecycle(
            forged,
            listener_pdp_lifecycle_for_test("pdp"),
        )) else {
            anyhow::bail!("sealed-channel disagree must fail closed");
        };
        assert!(
            matches!(sealed_err, ProviderBuildError::PlanCatalogDrift { .. }),
            "unexpected sealed-channel failure: {sealed_err:?}"
        );

        for factory in [
            ProviderFactorySymbol::IdentityMqttSession,
            ProviderFactorySymbol::IdentityPostgresDeviceCertificateStore,
            ProviderFactorySymbol::IdentityPostgresDeviceCommandStore,
            ProviderFactorySymbol::IdentityDraftArtifactSimulator,
        ] {
            let Some(detail) = super::foreign_runtime_catalog_drift(factory) else {
                anyhow::bail!("expected device-identity-only drift for {factory:?}");
            };
            assert!(
                detail.contains("device-identity-only"),
                "unexpected drift detail for {factory:?}: {detail}"
            );
            assert!(detail.contains(factory.as_str()));
        }
        let hot = super::foreign_runtime_catalog_drift(
            ProviderFactorySymbol::EventexecVaultHotKeyProvider,
        )
        .expect("settingsonly-only hot-key must drift");
        assert!(hot.contains("settingsonly-only"));
        Ok(())
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn provider_factory_dispatch_rejects_second_permit_consumption() -> anyhow::Result<()> {
        let (_build, mut dispatch) = provider_build_and_dispatch();
        dispatch.listener_pdp().expect("first PDP permit");
        let Err(err) = dispatch.listener_pdp() else {
            anyhow::bail!("second PDP accessor must fail closed");
        };
        assert!(matches!(
            err,
            ProviderBuildError::FactoryPermitAlreadyConsumed {
                factory: ProviderFactorySymbol::HttpserveOidcPdp
            }
        ));
        Ok(())
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn provider_finish_failure_abort_is_lifo_and_preserves_missing_receipts() {
        let (mut build, mut dispatch) = provider_build_and_dispatch();
        let shutdowns = Arc::new(Mutex::new(Vec::new()));
        build
            .record(ProviderOutput::redis(
                recording_module_all("first-resource", Arc::clone(&shutdowns)),
                dispatch.distributed_lock_store().expect("redis permit"),
            ))
            .expect("record redis");
        build
            .record(ProviderOutput::s3(
                recording_module("second-resource", Arc::clone(&shutdowns)),
                dispatch.runtime_object_store().expect("S3 permit"),
            ))
            .expect("record S3");
        let failure = build
            .finish()
            .err()
            .expect("partial receipts must fail finish");
        assert!(matches!(
            failure.error(),
            ProviderBuildError::MissingProviderReceipts { .. }
        ));
        let returned = failure.abort().await;
        let missing = returned
            .downcast_ref::<ProviderBuildError>()
            .expect("primary MissingProviderReceipts must survive abort");
        assert!(matches!(
            missing,
            ProviderBuildError::MissingProviderReceipts { .. }
        ));
        assert_eq!(
            *shutdowns.lock().expect("shutdown recording mutex"),
            ["second-resource", "first-resource"],
            "finish-failure abort must shut down recorded resources in LIFO order"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn provider_abort_preserves_primary_when_cleanup_shutdown_fails() {
        let (mut build, mut dispatch) = provider_build_and_dispatch();
        build
            .record(ProviderOutput::redis(
                DomainModuleResult {
                    probes: vec![probe("failing-cleanup")],
                    resources: vec![DynManagedResource::new_box(FailingShutdownResource {
                        name: "failing-cleanup",
                    })],
                    workers: vec![worker("failing-cleanup")],
                },
                dispatch.distributed_lock_store().expect("redis permit"),
            ))
            .expect("record redis");
        let primary = anyhow::anyhow!("primary startup failure");
        let returned = build.abort(primary).await;
        assert_eq!(
            returned.to_string(),
            "primary startup failure",
            "cleanup shutdown failures must not replace the primary error"
        );
    }

    #[test]
    fn provider_factory_permits_are_non_copyable_and_non_interchangeable() {
        static_assertions::assert_not_impl_any!(ListenerPdpConstructor: Clone, Copy);
        static_assertions::assert_not_impl_any!(ListenerPdpJwksLifecycle: Clone, Copy, Default);
        static_assertions::assert_type_ne_all!(
            ListenerPdpConstructor,
            DeviceRevocationStorePermit,
            DistributedLockStorePermit,
            RuntimeObjectStorePermit
        );
    }

    #[test]
    fn pg_runtime_module_keeps_guards_before_sampler_channel() {
        fn assert_builder(
            _: fn(postgres::PgRuntimeDeps, std::time::Duration) -> DomainModuleResult,
        ) {
        }
        assert_builder(build_pg_runtime_module);
        let output = DomainModuleResult {
            resources: vec![resource("postgres")],
            workers: vec![worker("postgres-readiness-sampler")],
            ..DomainModuleResult::default()
        };

        assert_eq!(resource_names(&output), ["postgres"]);
        assert_eq!(worker_names(output), ["postgres-readiness-sampler"]);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn provider_resource_registration_names_stay_stable() {
        let redis_pool = deadpool_redis::Config::from_url("redis://127.0.0.1:6379")
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("lazy redis pool construction does not connect");
        let redis = redis::RedisRuntimeDeps::setup(redis_pool);
        let ca_path = {
            let path = std::env::temp_dir().join(format!(
                "rss-provider-output-s3-ca-{}.pem",
                std::process::id()
            ));
            std::fs::write(&path, crate::infra::TEST_PRIVATE_CA_PEM.as_bytes())
                .expect("write provider-output S3 CA");
            path
        };
        let ca_path = ca_path.to_str().expect("utf-8 path");
        let snapshot = crate::config::test_snapshot(&[
            ("RSS_S3_ENDPOINT_URL", "https://s3.us-east-1.amazonaws.com"),
            ("RSS_S3_BUCKET", "rss-provider-output-test"),
            ("RSS_S3_CA_CERT_PEM_PATH", ca_path),
            ("RSS_S3_ACCESS_KEY_ID", "access-key"),
            ("RSS_S3_SECRET_ACCESS_KEY", "secret-key"),
            ("RSS_DLX_ARCHIVE_S3_BUCKET", "rss-provider-output-archive"),
            ("RSS_VAULT_ADDR", "https://vault.example:8200"),
            ("RSS_VAULT_TOKEN", "s.testtoken"),
            ("RSS_VAULT_TRANSIT_MOUNT", "transit"),
            (
                "RSS_VAULT_TENANT_STORE_ALLOWLIST_JSON",
                r#"{"bindings":[{"tenantId":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","storeId":"vault","mount":"secret","kvPathPrefix":"tenants/a"}]}"#,
            ),
            ("RSS_SETTINGS_CONFIG_VALUE_KEY_NAME", "settings-config"),
        ])
        .expect("snapshot");
        let crate::infra::s3::S3RuntimeConfigParts { general, .. } =
            crate::infra::s3::S3RuntimeConfig::from_snapshot(snapshot.view())
                .expect("valid hermetic s3 provider configuration")
                .into_parts();
        let s3 =
            crate::infra::s3::build_s3_runtime_deps(general).expect("valid hermetic s3 provider");
        let (vault, _signer, _) =
            crate::infra::vault::VaultRuntimeConfig::from_snapshot(snapshot.view())
                .expect("valid hermetic vault provider configuration")
                .into_runtime()
                .expect("valid hermetic vault providers");

        let mut module = DomainModuleResult::default();
        module.resources.extend(redis.runtime_resources());
        module.resources.extend(s3.runtime_resources());
        module.resources.extend(vault.runtime_resources());

        assert!(module.probes.is_empty());
        assert!(module.workers.is_empty());
        let registration = resource_names(&module);
        assert_eq!(
            registration,
            ["redis", "s3", "vault-secret-resolver", "vault-key-provider",]
        );
    }

    #[allow(clippy::expect_used)]
    fn probe(name: &'static str) -> (ProbeName, Box<dyn HealthProbe>) {
        let name = ProbeName::parse(name).expect("test provider names are valid probe names");
        (name.clone(), Box::new(LabeledProbe(name)))
    }

    fn resource(name: &'static str) -> Box<DynManagedResource<'static>> {
        DynManagedResource::new_box(LabeledResource(name))
    }

    fn worker(name: &'static str) -> WorkerSpec {
        WorkerSpec::phase_one(move |_| resource(name))
    }

    fn counting_worker(name: &'static str, starts: Arc<AtomicUsize>) -> WorkerSpec {
        WorkerSpec::phase_one(move |_| {
            starts.fetch_add(1, Ordering::SeqCst);
            resource(name)
        })
    }

    #[allow(clippy::expect_used)]
    fn provider_build_and_dispatch() -> (ProviderBuild, ProviderFactoryDispatch) {
        let plan = bundled_provider_plan();
        let mut build =
            ProviderBuild::from_plan(plan.as_typed().provider_plans(), PROVIDER_CATALOG)
                .expect("bundled provider build");
        let dispatch = ProviderFactoryDispatch::from_catalog(&mut build, PROVIDER_CATALOG)
            .expect("generated provider dispatch");
        (build, dispatch)
    }

    #[allow(clippy::expect_used)]
    fn record_all_batches(
        build: &mut ProviderBuild,
        dispatch: &mut ProviderFactoryDispatch,
        include_rate_limiter: bool,
        include_listener_pdp: bool,
    ) {
        if include_rate_limiter {
            build
                .record(ProviderOutput::listener_rate_limiter(
                    dispatch
                        .listener_rate_limiter()
                        .expect("rate-limiter permit"),
                ))
                .expect("rate-limiter output");
        }
        if include_listener_pdp {
            build
                .record(commit_listener_pdp_jwks_lifecycle(
                    dispatch.listener_pdp().expect("PDP permit"),
                    listener_pdp_lifecycle_for_test(LISTENER_PDP_JWKS_PROBE_NAME),
                ))
                .expect("PDP output");
        }
        build
            .record(ProviderOutput::redis(
                module_for_channels("redis", CHANNELS_ALL),
                dispatch.distributed_lock_store().expect("redis permit"),
            ))
            .expect("redis output");
        build
            .record(ProviderOutput::s3(
                module_for_channels("s3", CHANNELS_RESOURCES),
                dispatch.runtime_object_store().expect("S3 permit"),
            ))
            .expect("S3 output");
        build
            .record(ProviderOutput::vault(
                module_for_channels("identity-signer", CHANNELS_ALL),
                module_for_channels("vault-key", CHANNELS_ALL),
                module_for_channels("vault-resolver", CHANNELS_ALL),
                dispatch.identity_signer().expect("identity signer permit"),
                dispatch
                    .settings_key_provider()
                    .expect("settings key-provider permit"),
                dispatch
                    .settings_secret_resolver()
                    .expect("settings secret-resolver permit"),
            ))
            .expect("vault output");
        let pg = postgres::PgRuntimeHandle::for_module_test();
        let built_revocation = BuiltDeviceRevocationProvider::build(
            &pg,
            dispatch
                .device_revocation_store()
                .expect("device revocation-store permit"),
        )
        .expect("typed device revocation provider");
        let (_store, revocation_output) = built_revocation.into_parts();
        build
            .record(ProviderOutput::postgres(
                module_for_channels("postgres", CHANNELS_ALL),
                revocation_output,
                dispatch.auth_audit_sink().expect("audit sink permit"),
                dispatch
                    .distributed_cas_store()
                    .expect("distributed CAS permit"),
                dispatch
                    .service_token_replay_store()
                    .expect("service-token replay permit"),
            ))
            .expect("postgres output");
        build
            .record(ProviderOutput::dlx(
                module_for_channels("dlx-lifecycle", CHANNELS_ALL),
                module_for_channels("dlx-archive-store", CHANNELS_PROBES_WORKERS),
                module_for_channels("dlx-archive-key", CHANNELS_ALL),
                dispatch
                    .dlx_lifecycle_repository()
                    .expect("DLX repository permit"),
                dispatch.dlx_archive_store().expect("DLX store permit"),
                dispatch
                    .dlx_archive_key_provider()
                    .expect("DLX key-provider permit"),
            ))
            .expect("DLX output");
        build
            .record(ProviderOutput::event(
                module_for_channels("event", CHANNELS_ALL),
                dispatch.event_publisher().expect("publisher permit"),
                dispatch.event_subscriber().expect("subscriber permit"),
            ))
            .expect("event output");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn device_revocation_funnel_rejects_aggregate_module_as_dedicated_evidence() {
        let (build, mut dispatch) = provider_build_and_dispatch();
        let pg = postgres::PgRuntimeHandle::for_module_test();
        let error = BuiltDeviceRevocationProvider::from_module(
            &pg,
            dispatch
                .device_revocation_store()
                .expect("device revocation-store permit"),
            module_for_channels("aggregate-postgres", CHANNELS_ALL),
        )
        .err()
        .expect("aggregate module must not satisfy dedicated revocation lifecycle");

        assert!(matches!(
            error,
            ProviderBuildError::ProviderBatchChannelsMismatch {
                batch: "device-revocation-store",
                expected: super::CHANNELS_PROBES_WORKERS,
                actual,
            } if actual == CHANNELS_ALL
        ));
        assert!(
            build.finish().is_err(),
            "rejected permit cannot mint a receipt"
        );
    }

    fn listener_pdp_lifecycle_for_test(name: &'static str) -> ListenerPdpJwksLifecycle {
        let mut module = module_for_channels(name, LISTENER_PDP_CHANNELS);
        let probe = module.probes.pop().expect("listener PDP test probe");
        let resource = module.resources.pop().expect("listener PDP test resource");
        ListenerPdpJwksLifecycle::single(probe, resource)
    }

    fn module_for_channels(
        name: &'static str,
        channels: &[PlannedLifecycleChannel],
    ) -> DomainModuleResult {
        DomainModuleResult {
            probes: channels
                .contains(&PlannedLifecycleChannel::Probes)
                .then(|| probe(name))
                .into_iter()
                .collect(),
            resources: channels
                .contains(&PlannedLifecycleChannel::Resources)
                .then(|| resource(name))
                .into_iter()
                .collect(),
            workers: channels
                .contains(&PlannedLifecycleChannel::Workers)
                .then(|| worker(name))
                .into_iter()
                .collect(),
        }
    }

    fn recording_module(
        name: &'static str,
        shutdowns: Arc<Mutex<Vec<&'static str>>>,
    ) -> DomainModuleResult {
        DomainModuleResult {
            resources: vec![DynManagedResource::new_box(RecordingResource {
                name,
                shutdowns,
            })],
            ..DomainModuleResult::default()
        }
    }

    fn recording_module_all(
        name: &'static str,
        shutdowns: Arc<Mutex<Vec<&'static str>>>,
    ) -> DomainModuleResult {
        let mut module = recording_module(name, shutdowns);
        module.probes.push(probe(name));
        module.workers.push(worker(name));
        module
    }

    #[allow(clippy::expect_used)]
    fn bundled_provider_plan() -> crate::plan::RuntimePlan {
        let snapshot = crate::config::test_snapshot(&[
            ("RSS_PRIMARY_TOKEN_PROFILE", "rss-access"),
            ("RSS_ADMIN_TOKEN_PROFILE", "rss-access"),
            ("RSS_INTERNAL_AUTH_SCHEME", "mtls"),
        ])
        .expect("valid provider-plan profile snapshot");
        crate::plan::RuntimePlan::bundled(snapshot.view()).expect("bundled provider plan")
    }

    fn resource_names(module: &DomainModuleResult) -> Vec<&str> {
        module
            .resources
            .iter()
            .map(|resource| resource.name())
            .collect()
    }

    fn worker_names(module: DomainModuleResult) -> Vec<String> {
        let token = tokio_util::sync::CancellationToken::new();
        module
            .workers
            .into_iter()
            .map(|worker| match worker {
                WorkerSpec::PhaseOne(make) | WorkerSpec::Deferred(make) => {
                    make(token.clone()).name().to_owned()
                }
            })
            .collect()
    }

    struct LabeledProbe(ProbeName);

    impl HealthProbe for LabeledProbe {
        fn check(&self) -> HealthCheck {
            HealthCheck::new(self.0.clone(), HealthStatus::Healthy, "ready")
        }
    }

    struct LabeledResource(&'static str);

    impl ManagedResource for LabeledResource {
        fn name(&self) -> &str {
            self.0
        }

        async fn shutdown(&self) -> Result<(), ShutdownError> {
            Ok(())
        }
    }

    struct FailingShutdownResource {
        name: &'static str,
    }

    impl ManagedResource for FailingShutdownResource {
        fn name(&self) -> &str {
            self.name
        }

        async fn shutdown(&self) -> Result<(), ShutdownError> {
            Err(ShutdownError::new(std::io::Error::other("cleanup failed")))
        }
    }

    struct RecordingResource {
        name: &'static str,
        shutdowns: Arc<Mutex<Vec<&'static str>>>,
    }

    impl ManagedResource for RecordingResource {
        fn name(&self) -> &str {
            self.name
        }

        async fn shutdown(&self) -> Result<(), ShutdownError> {
            let mut shutdowns = self.shutdowns.lock().map_err(|_| {
                ShutdownError::new(std::io::Error::other("test shutdown log poisoned"))
            })?;
            shutdowns.push(self.name);
            Ok(())
        }
    }
}
