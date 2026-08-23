//! Integration-only seams for exercising typed domain wiring with hermetic providers.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use base64::Engine as _;

use super::{DistributedRuntimeDeps, SharedRuntimeDeps};

/// Exact assembly identity shared by the neutral Saga conformance plan and its journey carrier.
pub const SAGA_CONFORMANCE_ASSEMBLY_ID: &str = "sagat2conformance";

/// Output of the same plan-selected provider join consumed by production `WireDomains`.
pub struct SagaProviderIntegration {
    module: bootstrap::DomainModuleResult,
    start: eventexec::SagaRuntimeStartTarget,
    operator: eventexec::SagaRuntimeOperatorTarget,
    activation_listener: crate::plan::ListenerExecutionSpec,
}

impl SagaProviderIntegration {
    pub fn start_target(&self) -> eventexec::SagaRuntimeStartTarget {
        self.start.clone()
    }

    pub fn operator_target(&self) -> eventexec::SagaRuntimeOperatorTarget {
        self.operator.clone()
    }
}

pub fn bind_saga_provider_integration(
    typed_plan: assembly_schema::RuntimePlan,
    execution: eventexec::saga_test_support::ConformanceExecution,
    pg: &postgres::PgRuntimeHandle,
    receipt_key_provider: Box<diport::DynKeyProvider<'static>>,
    receipt_integrity_key_b64url: String,
    dead_letter_protector: postgres::DlxPayloadProtector,
    worker_config: eventexec::SagaWorkerConfig,
) -> anyhow::Result<SagaProviderIntegration> {
    let mut plan = crate::plan::RuntimePlan::from_saga_conformance_typed(
        typed_plan,
        SAGA_CONFORMANCE_ASSEMBLY_ID,
    )?;
    let mut activation_listeners = plan
        .listener_execution_plan()
        .into_listeners()
        .into_iter()
        .filter(|listener| listener.kind() == primitives::ListenerKind::Health);
    let activation_listener = activation_listeners
        .next()
        .ok_or_else(|| anyhow::anyhow!("Saga provider fixture has no Health listener"))?;
    anyhow::ensure!(
        activation_listeners.next().is_none(),
        "Saga provider fixture must select exactly one Health listener"
    );
    let permit = plan
        .take_saga_conformance_permit()
        .context("select neutral Saga conformance permit")?;
    let capability = bind_saga_conformance_provider(
        permit,
        execution,
        pg,
        receipt_key_provider,
        receipt_integrity_key_b64url,
        dead_letter_protector,
        worker_config,
    )?;
    plan.bind_workflow_runtime([capability])?;
    let (control, _relay, _consumer, write_admission) =
        primitives::prepare_dr_admission_controls().into_parts();
    control.start_running()?;
    let mut module = bootstrap::DomainModuleResult::default();
    crate::saga_runtime::wire_saga_worker(
        plan.workflow_runtime().sagas(),
        &write_admission,
        &mut module,
    )?;
    let active_count = plan.workflow_runtime().sagas().entries().len();
    module.merge(crate::phase::maintenance::wire_saga_terminal_sweeper(
        pg,
        active_count,
        &write_admission,
    )?);
    let mut entries = plan.workflow_runtime().sagas().entries();
    let entry = entries
        .next()
        .ok_or_else(|| anyhow::anyhow!("active Saga provider was not reachable"))?;
    anyhow::ensure!(
        entries.next().is_none(),
        "expected one active Saga provider"
    );
    Ok(SagaProviderIntegration {
        module,
        start: entry.start_target(),
        operator: entry.operator_target(),
        activation_listener,
    })
}

fn bind_saga_conformance_provider(
    permit: eventexec::SagaActivationPermit,
    execution: eventexec::saga_test_support::ConformanceExecution,
    pg: &postgres::PgRuntimeHandle,
    receipt_key_provider: Box<diport::DynKeyProvider<'static>>,
    receipt_integrity_key_b64url: String,
    dead_letter_protector: postgres::DlxPayloadProtector,
    worker_config: eventexec::SagaWorkerConfig,
) -> anyhow::Result<eventexec::SagaRuntimeCapability> {
    let integrity_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(receipt_integrity_key_b64url.as_bytes())
        .context("Saga conformance receipt key must be base64url")?;
    let integrity = secure::SagaReceiptIntegrityKeyring::new(
        secure::VersionedSagaReceiptIntegrityKey::new(
            secure::SagaReceiptIntegrityKeyId::parse("saga-receipt-v1")?,
            secure::RedactionHashKey::from_bytes(integrity_bytes)
                .context("Saga conformance receipt key must decode to at least 32 bytes")?,
        ),
        Vec::new(),
    )?;
    let infra = pg.infra();
    let store = Arc::new(
        infra.saga_durable_store(postgres::PgSagaReceiptProtection::new(
            receipt_key_provider,
            integrity,
        )),
    );
    let dead_letter = Arc::new(infra.dead_letter(dead_letter_protector));
    let factory = eventexec::saga_test_support::conformance_factory(execution);
    let config = eventexec::SagaExecutorConfig::from_typed_factory(
        diport::CheckpointOwner::new("test"),
        "runtime-saga-conformance-primary",
        Duration::from_secs(30),
        &factory,
    )?;
    let identity = config.identity().clone();
    let registry = eventexec::SagaDefinitionRegistry::builder()
        .register(factory)?
        .finish();
    let executor = Arc::new(eventexec::SagaExecutorImpl::new(
        eventexec::SagaExecutorDeps::new(Arc::clone(&store), dead_letter, registry),
        config,
    )?);
    let operator = executor.operator_service();
    eventexec::SagaRuntimeCapability::bind_worker(
        permit,
        identity,
        Arc::clone(&store),
        store,
        executor,
        Arc::new(crate::support::SystemClock),
        worker_config,
        operator,
    )
    .map_err(Into::into)
}

struct SagaJourneyMetrics;

impl diport::MetricsExporter for SagaJourneyMetrics {
    fn render(&self) -> String {
        "# saga-provider-integration\n".to_owned()
    }
}

/// Run the Saga provider fixture through the real runtimeexec listener/lifecycle/drain kernel.
pub async fn run_saga_provider_integration<T, Assert, Fut>(
    activation: SagaProviderIntegration,
    assertion: Assert,
) -> anyhow::Result<T>
where
    T: Send + 'static,
    Assert: FnOnce(
            Arc<bootstrap::HealthReporter>,
            eventexec::SagaRuntimeStartTarget,
            eventexec::SagaRuntimeOperatorTarget,
        ) -> Fut
        + Send
        + 'static,
    Fut: std::future::Future<Output = anyhow::Result<T>> + Send + 'static,
{
    let SagaProviderIntegration {
        mut module,
        start,
        operator,
        activation_listener,
    } = activation;
    let mut registry = bootstrap::Registry::new();
    let mut retained = bootstrap::DomainModuleResult::default();
    for output in module.drain_outputs() {
        match output {
            bootstrap::DomainLifecycleOutput::Probe(name, probe) => {
                registry.probe(name, probe)?;
            }
            bootstrap::DomainLifecycleOutput::Resource(resource) => {
                retained.push_resource(resource);
            }
            bootstrap::DomainLifecycleOutput::Worker(worker) => retained.push_worker(worker),
        }
    }
    module = retained;
    let listener_probe = runtimeexec::ListenerLifecycleRegistration::install(&mut registry)?;
    let reporter = Arc::clone(listener_probe.assembly_receipt());
    let metrics: Arc<dyn diport::MetricsExporter> = Arc::new(SagaJourneyMetrics);
    let (listeners, receipt) = crate::routes::FinalizedListenerSet::for_saga_journey(
        activation_listener,
        Arc::clone(&reporter),
        metrics,
    )?;
    let adapter = crate::launch::RuntimeLaunchAdapter::without_inventory(
        listeners,
        httpserve::ServerRequestBudget::from_millis(std::num::NonZeroU64::MIN),
        |_, _| "127.0.0.1:0".parse().map_err(anyhow::Error::from),
    );
    let expected_workers = bootstrap::ExpectedWorkerInventory::closed(
        module
            .workers()
            .map(bootstrap::WorkerSpec::descriptor)
            .filter(|descriptor| descriptor.lane != bootstrap::WorkerAdmissionLane::Observational),
    )?;
    let (completion, controlled) = runtimeexec::test_support::controlled();
    let launch = runtimeexec::LaunchPlan::new(
        adapter,
        listener_probe,
        move |_| async move {
            let result = assertion(reporter, start, operator).await;
            completion.complete(result)
        },
        None,
        runtimeexec::LaunchLifecycleBatches::new(
            runtimeexec::ProviderLifecycleBatch::from_provider_output(
                bootstrap::DomainModuleResult::default(),
            ),
            runtimeexec::DomainLifecycleBatch::from_domain_output(module),
            Some(expected_workers),
        ),
        crate::launch::total_drain_budget()?,
    );
    controlled.run(launch).await
}

pub use crate::domains::identity::IdentityTestValues;
pub use crate::event_transport::{EventTransportTestValues, EventWorkerTestValues};
pub use crate::runtime_inventory::test_support as runtime_inventory;

/// Move-only evidence that a write-admitted integration registry has installed the production
/// process security-root authorizer.
///
/// INVARIANT: RUNTIME-FIXTURE-SECURITY-ROOT-01 { level = "Hard", exec = "native-compile", source = "code", native = "private-field SecurityRootWiredRegistry is minted only by wire_runtime_security_root; access-listener finalizers consume it by value and cannot accept a raw WriteAdmittedRegistry" }.
#[must_use = "the security-root-wired registry must be consumed by an access-listener finalizer"]
pub struct SecurityRootWiredRegistry {
    registry: bootstrap::WriteAdmittedRegistry,
    authorizer: Arc<dyn httpserve::RouteAuthorizer>,
}

impl SecurityRootWiredRegistry {
    /// Clone the exact registered production authorizer for focused policy assertions.
    #[must_use]
    pub fn authorizer(&self) -> Arc<dyn httpserve::RouteAuthorizer> {
        Arc::clone(&self.authorizer)
    }
}

/// Install the same durable process authorizer used by production before listener finalization.
pub fn wire_runtime_security_root(
    mut registry: bootstrap::WriteAdmittedRegistry,
    pg: &postgres::PgRuntimeHandle,
    clock: Arc<dyn diport::Clock>,
) -> anyhow::Result<SecurityRootWiredRegistry> {
    let authorizer =
        crate::phase::register_runtime_security_root_authorizer(&mut registry, pg, clock)?;
    Ok(SecurityRootWiredRegistry {
        registry,
        authorizer,
    })
}

/// Finalize one closed listener selected from the committed, fingerprint-verified RuntimePlan
/// fixture through the production auth finalization core.
pub fn finalize_rss_listener(
    mut registry: SecurityRootWiredRegistry,
    provider: Arc<oidc::OidcProvider<diport::RssAccessProfile>>,
    grants: Arc<identity::AuthGrantValidationService>,
    audit_sink: httpserve::AuditSinkHandle,
    audit_clock: Arc<dyn diport::Clock>,
    kind: assembly_schema::AssemblyListenerKind,
) -> anyhow::Result<httpserve::AuthenticatedRoutes> {
    crate::routes::finalize_rss_fixture_listener(
        &mut registry.registry,
        provider,
        grants,
        audit_sink,
        audit_clock,
        kind,
    )
}

/// Wrap an explicit integration validator in the same request-time service used by production.
pub fn access_grant_validation_service<V>(validator: V) -> Arc<identity::AuthGrantValidationService>
where
    V: identity::ports::AuthGrantValidator + 'static,
{
    Arc::new(identity::AuthGrantValidationService::new(
        identity::ports::DynAuthGrantValidator::new_arc(validator),
        Box::new(crate::support::SystemClock),
    ))
}

/// Hermetic current-state validator for tests whose target is token mint/crypto rather than the
/// durable request fence. Grant-fence behavior tests inject their own provider instead.
pub struct AlwaysCurrentAccessGrant;

impl identity::ports::AuthGrantValidator for AlwaysCurrentAccessGrant {
    async fn is_current(
        &self,
        _scope: identity::ports::TenantRepoScope,
        _input: &authn::AccessGrantValidationInput,
        _observed_at: std::time::SystemTime,
    ) -> Result<bool, identity::ports::IdentityError> {
        Ok(true)
    }
}

pub fn always_current_access_grants() -> Arc<identity::AuthGrantValidationService> {
    access_grant_validation_service(AlwaysCurrentAccessGrant)
}

/// Finalize one access-listener fixture through the production Federated auth core.
///
/// The closed function selects Federated Access without accepting a raw profile value. It is for
/// integration tests of Device/Admin/SuperAdmin principals, which local RSS no longer represents.
pub fn finalize_federated_listener(
    mut registry: SecurityRootWiredRegistry,
    provider: Arc<oidc::OidcProvider<diport::FederatedAccessProfile>>,
    audit_sink: httpserve::AuditSinkHandle,
    audit_clock: Arc<dyn diport::Clock>,
    kind: assembly_schema::AssemblyListenerKind,
) -> anyhow::Result<httpserve::AuthenticatedRoutes> {
    crate::routes::finalize_federated_fixture_listener(
        &mut registry.registry,
        provider,
        audit_sink,
        audit_clock,
        kind,
    )
}

/// Finalize the plan-declared `Health + NoAuth` fixture through the production Health core.
pub fn finalize_health_listener(
    reporter: Arc<bootstrap::HealthReporter>,
    metrics: Arc<dyn diport::MetricsExporter>,
) -> anyhow::Result<httpserve::HealthRoutes> {
    crate::routes::finalize_health_fixture(reporter, metrics)
}

/// Build the exact production service-token verifier from explicit integration-test values.
///
/// The seam exists only with the `integration` feature and delegates to the production
/// constructor, so HTTP/PG tests cannot rebuild or weaken replay policy.
pub fn build_service_token_provider_from_values(
    issuer: &str,
    audience: &str,
    key_id: &str,
    secret: &[u8],
    pg_owner: &postgres::PgRuntimeDeps,
    replay_timeout: Duration,
    clock: Box<dyn diport::Clock>,
) -> anyhow::Result<Arc<oidc::OidcProvider<diport::ServiceTokenProfile>>> {
    crate::infra::oidc::build_service_token_provider_from_values_for_test(
        issuer,
        audience,
        key_id,
        secret,
        pg_owner.service_token_replay_store(),
        replay_timeout,
        clock,
    )
}

/// Builds the production S3 capability bundle from explicit integration-test values.
pub fn build_s3_runtime_deps_from_values(
    endpoint_url: String,
    bucket: String,
    access_key_id: String,
    secret_access_key: String,
    force_path_style: bool,
    ca_cert_pem: Vec<u8>,
) -> anyhow::Result<s3::S3RuntimeDeps> {
    crate::infra::s3::build_s3_runtime_deps_from_values(
        endpoint_url,
        bucket,
        access_key_id,
        secret_access_key,
        force_path_style,
        ca_cert_pem,
    )
}

/// Builds the production Vault capability bundle from explicit integration-test values.
pub fn build_vault_runtime_from_values(
    addr: String,
    token: String,
    transit_mount: String,
    signing_key_id: String,
    settings_key_name: String,
    tenant_store_allowlist_json: String,
) -> anyhow::Result<(
    vault::VaultRuntimeDeps,
    Arc<vault::VaultSigner>,
    diport::KeyName,
)> {
    crate::infra::vault::build_vault_runtime_from_values(
        addr,
        token,
        transit_mount,
        signing_key_id,
        settings_key_name,
        tenant_store_allowlist_json,
    )
}

/// Builds the production Redis capability bundle from explicit integration-test values.
///
/// The default production API exposes only the snapshot-backed typed constructor; this seam is
/// compiled solely for the container-backed integration lane.
pub async fn build_redis_runtime_deps_from_values(
    url: String,
    ca_cert_pem: Vec<u8>,
) -> anyhow::Result<redis::RedisRuntimeDeps> {
    crate::infra::redis::build_redis_runtime_deps_from_values(url, ca_cert_pem).await
}

/// Build a lazy Redis bundle for focused wiring tests which do not exercise Redis operations.
/// Pool construction is hermetic and performs no network I/O; any accidental Redis use still
/// fails closed when the caller attempts to check out a connection.
pub fn build_unused_redis_runtime_deps() -> anyhow::Result<redis::RedisRuntimeDeps> {
    let endpoint = secure::RedisEndpoint::parse(
        "rediss://127.0.0.1:1",
        secure::PlaintextEndpointPolicy::Deny,
    )
    .context("build unused typed Redis endpoint")?;
    let ca = redis::RedisPrivateCa::from_pem(test_private_ca_pem())
        .context("build unused typed Redis private CA")?;
    redis::RedisRuntimeDeps::connect_with_private_ca(&endpoint, ca)
        .context("build unused typed Redis integration-test pool")
}

/// Stable private CA bait for integration-only client construction which performs no I/O.
#[must_use]
pub fn test_private_ca_pem() -> Vec<u8> {
    crate::infra::TEST_PRIVATE_CA_PEM.as_bytes().to_vec()
}

/// Builds the shared parameter object for focused integration wiring tests.
///
/// This seam is compiled only with the `integration` feature. Live runtime construction remains
/// confined to the provider build transaction and its typed lifecycle output.
#[allow(clippy::too_many_arguments)]
pub fn build_shared_runtime_deps(
    password_blocklist: Arc<secure::DigestPasswordBlocklist>,
    pg: postgres::PgRuntimeHandle,
    redis: redis::RedisRuntimeDeps,
    s3: s3::S3RuntimeDeps,
    vault: vault::VaultRuntimeDeps,
    identity_signer: Arc<vault::VaultSigner>,
    settings_config_value_key_name: diport::KeyName,
    domain_transport: Arc<dyn distributed::HttpContractTransport>,
) -> IntegrationRuntimeDeps {
    let settings_readiness = settings_composition::test_support::readiness(pg.readiness_handle());
    shared_runtime_deps_from_parts(
        password_blocklist,
        pg,
        redis,
        s3,
        vault,
        identity_signer,
        settings_config_value_key_name,
        settings_readiness,
        domain_transport,
    )
}

/// Integration-only pairing of process-shared infrastructure and local-domain provider capability.
pub struct IntegrationRuntimeDeps {
    shared: SharedRuntimeDeps,
    local: crate::LocalDomainProviderCatalog,
}

impl std::ops::Deref for IntegrationRuntimeDeps {
    type Target = SharedRuntimeDeps;

    fn deref(&self) -> &Self::Target {
        &self.shared
    }
}

/// Purpose-bound Settings fixture which preserves the three non-interchangeable provider outputs.
///
/// The fixture is consumed once; it neither merges lifecycle carriers nor recreates the production
/// provider transaction's record order.
pub struct SettingsWireFixture {
    deps: IntegrationRuntimeDeps,
    postgres_output: settings_composition::SettingsPostgresReadinessOutput,
    key_provider_output: settings_composition::SettingsKeyProviderReadinessOutput,
    secret_resolver_output: settings_composition::SettingsSecretResolverReadinessOutput,
}

impl SettingsWireFixture {
    /// Consume the fixture into domain inputs and the exact typed provider outputs.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        IntegrationRuntimeDeps,
        settings_composition::SettingsPostgresReadinessOutput,
        settings_composition::SettingsKeyProviderReadinessOutput,
        settings_composition::SettingsSecretResolverReadinessOutput,
    ) {
        (
            self.deps,
            self.postgres_output,
            self.key_provider_output,
            self.secret_resolver_output,
        )
    }
}

/// Build the Settings domain inputs and its PG/Vault readiness outputs from one generation.
#[allow(clippy::too_many_arguments)]
pub async fn build_settings_wire_fixture(
    password_blocklist: Arc<secure::DigestPasswordBlocklist>,
    pg: postgres::PgRuntimeHandle,
    redis: redis::RedisRuntimeDeps,
    s3: s3::S3RuntimeDeps,
    vault: vault::VaultRuntimeDeps,
    identity_signer: Arc<vault::VaultSigner>,
    settings_config_value_key_name: diport::KeyName,
    domain_transport: Arc<dyn distributed::HttpContractTransport>,
) -> anyhow::Result<SettingsWireFixture> {
    let generation = settings_composition::SettingsProviderReadiness::new(
        &vault.for_domain::<vault::caps::Settings>(),
        settings_config_value_key_name.clone(),
        settings_composition::KeyProviderReadinessInterval::default(),
    )
    .await?;
    let (pending_postgres, key_provider_output, secret_resolver_output) =
        generation.into_vault_parts();
    let (settings_readiness, postgres_output) =
        pending_postgres.bind_postgres(pg.readiness_handle())?;
    let deps = shared_runtime_deps_from_parts(
        password_blocklist,
        pg,
        redis,
        s3,
        vault,
        identity_signer,
        settings_config_value_key_name,
        settings_readiness,
        domain_transport,
    );
    Ok(SettingsWireFixture {
        deps,
        postgres_output,
        key_provider_output,
        secret_resolver_output,
    })
}

#[allow(clippy::too_many_arguments)]
fn shared_runtime_deps_from_parts(
    password_blocklist: Arc<secure::DigestPasswordBlocklist>,
    pg: postgres::PgRuntimeHandle,
    redis: redis::RedisRuntimeDeps,
    s3: s3::S3RuntimeDeps,
    vault: vault::VaultRuntimeDeps,
    identity_signer: Arc<vault::VaultSigner>,
    settings_config_value_key_name: diport::KeyName,
    settings_readiness: settings_composition::SettingsReadinessDeps,
    domain_transport: Arc<dyn distributed::HttpContractTransport>,
) -> IntegrationRuntimeDeps {
    let shared = SharedRuntimeDeps::from_integration_parts(pg, redis, s3, domain_transport);
    let local = crate::LocalDomainProviderCatalog::IdentitySettings {
        password_blocklist,
        signer: identity_signer,
        vault,
        key_name: settings_config_value_key_name,
        readiness: settings_readiness,
    };
    IntegrationRuntimeDeps { shared, local }
}

/// Wires the production event transport through an integration-only seam.
pub async fn wire_event_transport(
    pg: &postgres::PgRuntimeHandle,
    distributed: DistributedRuntimeDeps,
    subscribers: crate::event_transport::BridgedSubscriptions,
    cfg: crate::event_transport::EventTransportConfig,
    worker: crate::event_transport::EventWorkerConfig,
    audit_key: primitives::MacKey,
) -> anyhow::Result<bootstrap::DomainModuleResult> {
    wire_event_transport_with_admission(
        pg,
        distributed,
        subscribers,
        cfg,
        worker,
        audit_key,
        primitives::prepare_dr_admission_controls().into_parts(),
        None,
    )
    .await
}

/// Wires the production event transport with one caller-owned process admission authority.
///
/// This integration-only seam lets a T2 route fixture and the durable workers share the exact
/// three production lanes. Production composition still obtains the bundle from its sealed
/// provider phase and does not consume this helper.
#[allow(clippy::too_many_arguments)]
pub async fn wire_event_transport_with_admission(
    pg: &postgres::PgRuntimeHandle,
    distributed: DistributedRuntimeDeps,
    subscribers: crate::event_transport::BridgedSubscriptions,
    cfg: crate::event_transport::EventTransportConfig,
    worker: crate::event_transport::EventWorkerConfig,
    audit_key: primitives::MacKey,
    admission: (
        primitives::ProcessAdmissionControl,
        primitives::RelayAdmission,
        primitives::ConsumerAdmission,
        primitives::WriteAdmission,
    ),
    required_admission_epoch: Option<primitives::AdmissionEpochId>,
) -> anyhow::Result<bootstrap::DomainModuleResult> {
    let (admission_control, relay_admission, consumer_admission, write_admission) = admission;
    let retain_controller = cfg.topology() != bootstrap::Topology::Demo;
    let identity = eventexec::DrAdmissionProcessIdentity::new(
        "runtime",
        "sha256:runtime-integration-plan",
        uuid::Uuid::from_u128(0x2009),
        uuid::Uuid::new_v4(),
        required_admission_epoch,
    )?;
    let mut module = crate::event_transport::wire_event_transport(
        crate::event_transport::EventTransportWiring::new(
            pg,
            distributed,
            subscribers,
            cfg,
            worker,
            Some(audit_key),
            crate::event_transport::EventAdmissions::new(
                relay_admission,
                consumer_admission,
                write_admission,
            ),
        ),
    )
    .await?;
    if retain_controller {
        crate::event_transport::retain_admission_authority(
            pg.clone(),
            admission_control,
            identity,
            &mut module,
        )?;
    }
    Ok(module)
}

/// Wires distributed providers with the canonical non-configurable worker timing.
pub fn wire_distributed(deps: &SharedRuntimeDeps) -> anyhow::Result<DistributedRuntimeDeps> {
    crate::distributed_runtime::wire_distributed(
        deps,
        crate::distributed_runtime::DistributedWorkerConfig::canonical(),
    )
}

/// Builds the settings binding for container-backed integration tests.
pub async fn wire_settings(
    deps: &IntegrationRuntimeDeps,
) -> anyhow::Result<bootstrap::DomainBinding> {
    crate::domains::settings::integration_binding(
        deps,
        &deps.local,
        crate::domains::settings::SettingsModuleInput::new(
            settings_composition::KeyProviderReadinessInterval::default(),
        ),
    )
    .await
}

/// Builds the identity binding from explicit hermetic values for integration tests.
pub fn wire_identity_with(
    deps: &IntegrationRuntimeDeps,
    values: IdentityTestValues,
) -> anyhow::Result<bootstrap::DomainBinding> {
    crate::domains::identity::wire_identity_with(deps, &deps.local, values)
}

/// Builds the identity binding with a deterministic password producer transaction rendezvous.
pub fn wire_identity_with_password_change_barrier(
    deps: &IntegrationRuntimeDeps,
    values: IdentityTestValues,
    barrier: Arc<tokio::sync::Barrier>,
) -> anyhow::Result<bootstrap::DomainBinding> {
    crate::domains::identity::wire_identity_with_password_change_barrier(
        deps,
        &deps.local,
        values,
        barrier,
    )
}
