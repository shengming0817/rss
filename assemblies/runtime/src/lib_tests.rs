use eventexec::event::ReviewedEvent;
use std::sync::Arc;

use super::{
    CONFIGS_READY_PROBE_NAME, EnvSecret, FEDERATED_ACCESS_TOKEN_JWKS_READY_PROBE_NAME,
    KEYPROVIDER_READY_PROBE_NAME, MacKey, OTEL_ENDPOINT_ENV, REDIS_READY_PROBE_NAME,
    RSS_ACCESS_TOKEN_JWKS_READY_PROBE_NAME, RuntimeLifecycleOwner, RuntimePhase,
    RustCryptoMacVerifier, S3RuntimeConfig, S3RuntimeConfigParts, ServingRuntimeInputs,
    after_required_preflight, build_trace_export, build_trace_export_from_value, domains,
    event_transport, plan, prepare_local_before_external, prepare_operator_local,
    prepare_serving_local, routes, run, safe_process_error_line, validate_domain_listener_evidence,
};
use crate::config::DOMAIN_TRANSPORT_SHARED_URL_ENV;
use crate::infra::s3::S3DlxArchiveConfig;
use crate::phase::PreparedRuntimeInputs;
use crate::phase::test_support::{
    AUTH_GRANT_SWEEPER_PROBE_NAME, AUTH_GRANT_SWEEPER_WORKER_NAME, AuthGrantSweepFuture,
    AuthGrantSweepRunner, DOMAIN_TRANSPORT_LOCAL_SPIFFE_ID_ENV, DOMAIN_TRANSPORT_READY_PROBE_NAME,
    DomainTransportRuntime, DomainTransportRuntimeInner, InProcHttpContractTransport,
    REVOCATION_SWEEPER_PROBE_NAME, REVOCATION_SWEEPER_WORKER_NAME, RLS_READY_PROBE_NAME,
    RevocationSweepFuture, RevocationSweepObservation, RevocationSweepRunner, RlsReadyProbe,
    RuntimeHttpContractTransport, SERVICE_TOKEN_REPLAY_SWEEPER_PROBE_NAME,
    SERVICE_TOKEN_REPLAY_SWEEPER_WORKER_NAME, SPIFFE_ENDPOINT_SOCKET_ENV, SweeperHealth,
    build_dlx_lifecycle_bootstrap_config_from, build_domain_transport_targets_from,
    required_spiffe_endpoint_from_value, run_auth_grant_sweeper_loop, run_revocation_sweeper_loop,
    sweeper_module_result, wire_revocation_sweeper,
};
use crate::support::{SystemClock, TracingAuthAuditSink};
use anyhow::Context as _;
use settings_composition::SECRET_RESOLVER_READY_PROBE_NAME;

use audit::ports::TenantRepoScope as AuditTenantRepoScope;
use axum::http::Method;
use base64::Engine as _;
use bootstrap::DomainModuleResult;
use diport::{DynManagedResource, ManagedResource, ShutdownError};
use identity::ports::TenantRepoScope as IdentityTenantRepoScope;
use oidc::OidcProvider;
use primitives::{HealthCheck, HealthStatus, ListenerKind, ProbeName};
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};
use tokio_util::sync::CancellationToken;

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

#[test]
fn pre_runtime_process_error_is_one_safe_line() {
    let error = anyhow::anyhow!("failed\nnext\rline postgres://user:SECRET_BAIT@db/rss");
    let rendered = safe_process_error_line(&error);

    assert!(!rendered.contains(['\r', '\n']));
    assert!(!rendered.contains("user:SECRET_BAIT"));
    assert_eq!(rendered, "failed next line postgres://<redacted>@db/rss");
}

struct FixedDlxBootstrapClock;

impl diport::Clock for FixedDlxBootstrapClock {
    fn now(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000)
    }
}

fn test_password_blocklist() -> Arc<secure::DigestPasswordBlocklist> {
    Arc::new(
        crypto::load_password_blocklist_from_reader(std::io::Cursor::new(include_bytes!(
            "../../../deploy/password-blocklist.demo.sha256"
        )))
        .unwrap_or_else(|_| unreachable!()),
    )
}

#[test]
fn production_prepare_runtime_loads_policy_before_otlp_and_subscriber_setup() {
    let external_calls = AtomicUsize::new(0);
    let missing = crate::config::test_snapshot(&[]).unwrap_or_else(|_| unreachable!());
    let error = prepare_local_before_external(missing.view(), prepare_serving_local, || {
        external_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    })
    .err()
    .unwrap_or_else(|| unreachable!());
    assert_eq!(external_calls.load(Ordering::SeqCst), 0);
    assert!(
        error
            .to_string()
            .contains(domains::identity::PASSWORD_BLOCKLIST_PATH_ENV)
    );

    let valid = crate::config::test_snapshot(&[(
        domains::identity::PASSWORD_BLOCKLIST_PATH_ENV,
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../deploy/password-blocklist.demo.sha256"
        ),
    )])
    .unwrap_or_else(|_| unreachable!());
    let (blocklist, ()) =
        prepare_local_before_external(valid.view(), prepare_serving_local, || {
            external_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
        .unwrap_or_else(|_| unreachable!());
    assert_eq!(external_calls.load(Ordering::SeqCst), 1);
    assert_eq!(Arc::strong_count(&blocklist), 1);
}

#[test]
fn operator_preparation_does_not_require_serving_password_policy() {
    let external_calls = AtomicUsize::new(0);
    let missing = crate::config::test_snapshot(&[]).unwrap_or_else(|_| unreachable!());
    let ((), ()) = prepare_local_before_external(missing.view(), prepare_operator_local, || {
        external_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    })
    .unwrap_or_else(|_| unreachable!());
    assert_eq!(external_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn env_secret_is_opaque_compared_and_owned_by_the_shared_funnel() {
    let first = EnvSecret::required(
        &|name| (name == "SECRET").then(|| "secret-value".to_owned()),
        "SECRET",
    )
    .unwrap_or_else(|_| unreachable!());
    let second = EnvSecret::required(
        &|name| (name == "SECRET").then(|| "secret-value".to_owned()),
        "SECRET",
    )
    .unwrap_or_else(|_| unreachable!());
    let different = EnvSecret::required(
        &|name| (name == "SECRET").then(|| "different-value".to_owned()),
        "SECRET",
    )
    .unwrap_or_else(|_| unreachable!());
    assert!(!first.differs_from(&second));
    assert!(first.differs_from(&different));
    assert_eq!(format!("{first:?}"), "EnvSecret(<redacted>)");
    assert!(!format!("{second:?}").contains("secret-value"));
    assert!(!format!("{different:?}").contains("different-value"));
}

fn full_dlx_bootstrap_env(name: &str) -> Option<String> {
    match name {
        "RSS_S3_ENDPOINT_URL" => Some("https://s3.example.test".to_owned()),
        "RSS_DLX_ARCHIVE_S3_BUCKET" => Some("rss-dlx-archive".to_owned()),
        "RSS_VAULT_ADDR" => Some("https://vault.example.test".to_owned()),
        "RSS_VAULT_TOKEN" => Some("vault-token".to_owned()),
        "RSS_DLX_HOT_VAULT_TOKEN" => Some("dlx-hot-vault-token".to_owned()),
        "RSS_DLX_ARCHIVE_VAULT_TOKEN" => Some("dlx-archive-vault-token".to_owned()),
        "RSS_VAULT_TRANSIT_MOUNT" => Some("transit".to_owned()),
        "RSS_DLX_PAYLOAD_KEY_NAME" => Some("dlx-hot".to_owned()),
        "RSS_DLX_ARCHIVE_KEY_NAME" => Some("dlx-archive".to_owned()),
        _ => None,
    }
}

fn test_dlx_pg_config(username: &str) -> ::postgres::PgConfig {
    ::postgres::PgConfig::new(
        "postgres.internal",
        5432,
        "rss",
        username,
        ::postgres::PgPassword::new("test-only-password"),
    )
    .with_ssl_mode(::postgres::PgSslMode::Disable)
}

#[allow(clippy::expect_used)]
fn test_s3_ca_pem_path() -> String {
    static PATH: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    PATH.get_or_init(|| {
        let path = std::env::temp_dir().join(format!(
            "rss-runtime-lib-test-s3-ca-{}.pem",
            std::process::id()
        ));
        std::fs::write(&path, crate::infra::TEST_PRIVATE_CA_PEM.as_bytes())
            .expect("write lib test S3 CA");
        path
    })
    .display()
    .to_string()
}

#[allow(clippy::expect_used)]
fn test_s3_dlx_archive_config() -> S3DlxArchiveConfig {
    let ca = test_s3_ca_pem_path();
    let snapshot = crate::config::test_snapshot(&[
        ("RSS_S3_ENDPOINT_URL", "https://s3.example.test"),
        ("RSS_S3_BUCKET", "rss-general"),
        ("RSS_S3_CA_CERT_PEM_PATH", ca.as_str()),
        ("RSS_S3_ACCESS_KEY_ID", "general-access-key"),
        ("RSS_S3_SECRET_ACCESS_KEY", "general-secret-key"),
        ("RSS_DLX_ARCHIVE_S3_BUCKET", "rss-dlx-archive"),
    ])
    .expect("snapshot");
    let S3RuntimeConfigParts { dlx_archive, .. } = S3RuntimeConfig::from_snapshot(snapshot.view())
        .expect("valid S3 DLX archive config")
        .into_parts();
    dlx_archive
}

#[tokio::test]
async fn dlx_bootstrap_config_requires_independent_key_domains() {
    let reused_key = build_dlx_lifecycle_bootstrap_config_from(
        test_dlx_pg_config("rss_dlx_archiver"),
        test_dlx_pg_config("rss_dlx_verifier"),
        test_dlx_pg_config("rss_dlx_purger"),
        test_s3_dlx_archive_config(),
        |name| match name {
            "RSS_DLX_ARCHIVE_KEY_NAME" => Some("dlx-hot".to_owned()),
            _ => full_dlx_bootstrap_env(name),
        },
        Arc::new(FixedDlxBootstrapClock),
    )
    .await;
    assert!(
        reused_key
            .err()
            .is_some_and(|error| format!("{error:#}").contains("must differ"))
    );
}

#[tokio::test]
async fn failed_dlx_preflight_never_enters_destructive_migration_phase() {
    let migration_calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&migration_calls);
    let result = after_required_preflight(
        async { anyhow::bail!("preflight failed") },
        move |(): ()| async move {
            observed.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    )
    .await;

    assert!(result.is_err());
    assert_eq!(migration_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn generated_graph_evidence_matches_live_runtime_carriers() {
    let snapshot = crate::config::test_snapshot(&[
        ("RSS_PRIMARY_TOKEN_PROFILE", "rss-access"),
        ("RSS_ADMIN_TOKEN_PROFILE", "rss-access"),
        ("RSS_INTERNAL_AUTH_SCHEME", "mtls"),
    ])
    .unwrap_or_else(|_| unreachable!());
    let runtime_plan =
        plan::RuntimePlan::bundled(snapshot.view()).unwrap_or_else(|_| unreachable!());
    let listener_plan = runtime_plan.listener_execution_plan();
    let placement_plan = runtime_plan.placement_execution_plan(snapshot.view());
    assert!(validate_domain_listener_evidence(&listener_plan, &placement_plan, &[]).is_err());
}

#[test]
fn runtime_module_output_harness_captures_merge_and_probe_drain_order() {
    assert_eq!(
        runtime_module_harness_transcript(),
        [
            "phase-order: build_provider -> build_infra -> wire_domains -> finalize -> launch",
            "module-probes: configs_ready, keyprovider_ready, vault_secret_resolver_ready, auth_grant_sweeper, service_token_replay_sweeper, certificate_revocation_sweeper, s3_object_store_ready, domain_transport_ready, outbox_relay_identity, outbox_relay_settings, outbox_sampler, outbox_sweeper, event_consumer:settings_config-version-changed__settings__settings_config-version-changed, event_consumer:identity_session-created__audit__audit_session-created, event_consumer:identity_role-assigned__audit__audit_role-assigned, event_consumer:identity_role-revoked__audit__audit_role-revoked, event_consumer:identity_policy-updated__audit__audit_policy-updated, inbox_sweeper, dlx_lifecycle, dlx_archive_ready",
            "module-resources: redis, s3, vault-secret-resolver, vault-key-provider, rss_access_token_verifier, federated_access_token_verifier, service_token_verifier, domain-http-transport, identity-pub, identity-sub, settings-pub, settings-sub, postgres-dlx-lifecycle",
            "module-workers: keyprovider-readiness-sampler, vault-secret-resolver-readiness-sampler, auth-grant-sweeper, service-token-replay-sweeper, certificate-revocation-sweeper, s3-canary-sampler, outbox-relay-identity, outbox-relay-settings, outbox-sampler, outbox-sweeper, event-consumer:settings:settings.config-version-changed, event-consumer:audit:identity.session-created, event-consumer:audit:identity.role-assigned, event-consumer:audit:identity.role-revoked, event-consumer:audit:identity.policy-updated, inbox-sweeper, dlx-lifecycle, dlx-archive-readiness, redis-readiness-sampler",
            "readyz-probes-before-reporter: rls_ready, redis_ready, rss_access_token_jwks_ready, federated_access_token_jwks_ready, configs_ready, keyprovider_ready, vault_secret_resolver_ready, auth_grant_sweeper, service_token_replay_sweeper, certificate_revocation_sweeper, s3_object_store_ready, domain_transport_ready, outbox_relay_identity, outbox_relay_settings, outbox_sampler, outbox_sweeper, event_consumer:settings_config-version-changed__settings__settings_config-version-changed, event_consumer:identity_session-created__audit__audit_session-created, event_consumer:identity_role-assigned__audit__audit_role-assigned, event_consumer:identity_role-revoked__audit__audit_role-revoked, event_consumer:identity_policy-updated__audit__audit_policy-updated, inbox_sweeper, dlx_lifecycle, dlx_archive_ready",
            "reporter-probe-count: 24",
            "registry-probe-count-after-take: 0",
        ]
        .join("\n")
    );
}

fn runtime_module_harness_transcript() -> String {
    let mut module = runtime_module_output_harness();
    let module_probes = probe_names(&module.probes);
    let module_resources = resource_names(&module.resources);
    let module_workers = worker_names(module.workers);

    let mut registry = bootstrap::Registry::new();
    for name in [
        RLS_READY_PROBE_NAME,
        REDIS_READY_PROBE_NAME,
        RSS_ACCESS_TOKEN_JWKS_READY_PROBE_NAME,
        FEDERATED_ACCESS_TOKEN_JWKS_READY_PROBE_NAME,
    ] {
        register_probe(&mut registry, name);
    }
    for (name, probe) in module.probes.drain(..) {
        let result = registry.probe(name, probe);
        assert!(result.is_ok(), "module probe drains");
    }
    let readyz_probe_names = registry
        .readyz_report()
        .checks()
        .iter()
        .map(|check| check.name().as_str().to_owned())
        .collect::<Vec<_>>();
    let reporter = registry.take_health_reporter();

    [
        format!("phase-order: {}", phase_order_transcript_for_harness()),
        format!("module-probes: {}", module_probes.join(", ")),
        format!("module-resources: {}", module_resources.join(", ")),
        format!("module-workers: {}", module_workers.join(", ")),
        format!(
            "readyz-probes-before-reporter: {}",
            readyz_probe_names.join(", ")
        ),
        format!("reporter-probe-count: {}", reporter.probe_count()),
        format!(
            "registry-probe-count-after-take: {}",
            registry.probe_count()
        ),
    ]
    .join("\n")
}

fn runtime_module_output_harness() -> DomainModuleResult {
    let mut module = DomainModuleResult::default();
    module.merge(harness_module(
        &[
            CONFIGS_READY_PROBE_NAME,
            KEYPROVIDER_READY_PROBE_NAME,
            SECRET_RESOLVER_READY_PROBE_NAME,
        ],
        &[],
        &[
            "keyprovider-readiness-sampler",
            "vault-secret-resolver-readiness-sampler",
        ],
    ));
    module.merge(harness_module(
        &[AUTH_GRANT_SWEEPER_PROBE_NAME],
        &[],
        &[AUTH_GRANT_SWEEPER_WORKER_NAME],
    ));
    module.merge(harness_module(
        &[SERVICE_TOKEN_REPLAY_SWEEPER_PROBE_NAME],
        &[],
        &[SERVICE_TOKEN_REPLAY_SWEEPER_WORKER_NAME],
    ));
    module.merge(harness_module(
        &[REVOCATION_SWEEPER_PROBE_NAME],
        &[],
        &[REVOCATION_SWEEPER_WORKER_NAME],
    ));
    module.merge(harness_module(
        &[crate::infra::s3::S3_READY_PROBE_NAME],
        &[],
        &["s3-canary-sampler"],
    ));
    module.merge(harness_module(
        &[],
        &["redis", "s3", "vault-secret-resolver", "vault-key-provider"],
        &[],
    ));
    module.resources.extend([
        harness_resource("rss_access_token_verifier"),
        harness_resource("federated_access_token_verifier"),
        harness_resource("service_token_verifier"),
    ]);
    module.merge(harness_module(
        &[DOMAIN_TRANSPORT_READY_PROBE_NAME],
        &["domain-http-transport"],
        &[],
    ));
    module.merge(event_transport_harness_module());
    module.merge(harness_module(
        &[
            event_transport::DLX_LIFECYCLE_PROBE,
            event_transport::DLX_ARCHIVE_READINESS_PROBE,
        ],
        &["postgres-dlx-lifecycle"],
        &[
            event_transport::DLX_LIFECYCLE_WORKER_NAME,
            event_transport::DLX_ARCHIVE_READINESS_WORKER_NAME,
        ],
    ));
    module
        .workers
        .push(harness_worker("redis-readiness-sampler"));
    module
}

fn event_transport_harness_module() -> DomainModuleResult {
    let mut module = DomainModuleResult::default();
    for domain in ["identity", "settings"] {
        module
            .resources
            .push(harness_resource_owned(format!("{domain}-pub")));
        module
            .resources
            .push(harness_resource_owned(format!("{domain}-sub")));
    }
    for domain in ["identity", "settings"] {
        module.probes.push(harness_probe_owned(format!(
            "{}_{domain}",
            eventexec::OUTBOX_RELAY_PROBE
        )));
        module
            .workers
            .push(harness_worker_owned(format!("outbox-relay-{domain}")));
    }
    module
        .probes
        .push(harness_probe(eventexec::OUTBOX_SAMPLER_PROBE));
    module.workers.push(harness_worker("outbox-sampler"));
    module
        .probes
        .push(harness_probe(eventexec::OUTBOX_SWEEPER_PROBE));
    module
        .workers
        .push(harness_worker(eventexec::SWEEPER_WORKER_NAME));
    for (topic, consumer, group) in [
        (
            "settings.config-version-changed",
            "settings",
            "settings.config-version-changed",
        ),
        ("identity.session-created", "audit", "audit.session-created"),
        ("identity.role-assigned", "audit", "audit.role-assigned"),
        ("identity.role-revoked", "audit", "audit.role-revoked"),
        ("identity.policy-updated", "audit", "audit.policy-updated"),
    ] {
        module.probes.push(harness_probe_owned(format!(
            "{}:{}__{}__{}",
            eventexec::EVENT_CONSUMER_PROBE,
            topic.replace('.', "_"),
            consumer.replace('.', "_"),
            group.replace('.', "_")
        )));
        module.workers.push(harness_worker_owned(format!(
            "event-consumer:{consumer}:{topic}"
        )));
    }
    module
        .probes
        .push(harness_probe(crate::event_transport::INBOX_SWEEPER_PROBE));
    module.workers.push(harness_worker(
        crate::event_transport::INBOX_SWEEPER_WORKER_NAME,
    ));
    module
}

fn harness_module(
    probes: &[&'static str],
    resources: &[&'static str],
    workers: &[&'static str],
) -> DomainModuleResult {
    DomainModuleResult {
        probes: probes.iter().copied().map(harness_probe).collect(),
        resources: resources.iter().copied().map(harness_resource).collect(),
        workers: workers.iter().copied().map(harness_worker).collect(),
    }
}

#[allow(clippy::expect_used)]
fn harness_probe(name: &'static str) -> (ProbeName, Box<dyn bootstrap::HealthProbe>) {
    harness_probe_owned(name.to_owned())
}

#[allow(clippy::expect_used)]
fn harness_probe_owned(name: String) -> (ProbeName, Box<dyn bootstrap::HealthProbe>) {
    let name = ProbeName::parse(&name).expect("harness probe names are valid");
    (
        name.clone(),
        Box::new(HarnessProbe {
            name,
            status: HealthStatus::Healthy,
        }),
    )
}

#[allow(clippy::expect_used)]
fn register_probe(registry: &mut bootstrap::Registry, name: &'static str) {
    let (name, probe) = harness_probe(name);
    registry.probe(name, probe).expect("direct probe registers");
}

fn probe_names(probes: &[(ProbeName, Box<dyn bootstrap::HealthProbe>)]) -> Vec<String> {
    probes
        .iter()
        .map(|(name, _)| name.as_str().to_owned())
        .collect()
}

fn resource_names(resources: &[Box<DynManagedResource<'static>>]) -> Vec<String> {
    resources
        .iter()
        .map(|resource| resource.name().to_owned())
        .collect()
}

fn worker_names(workers: Vec<bootstrap::WorkerSpec>) -> Vec<String> {
    let token = CancellationToken::new();
    workers
        .into_iter()
        .map(|worker| match worker {
            bootstrap::WorkerSpec::PhaseOne(make) | bootstrap::WorkerSpec::Deferred(make) => {
                make(token.clone()).name().to_owned()
            }
        })
        .collect()
}

fn harness_resource(name: &'static str) -> Box<DynManagedResource<'static>> {
    harness_resource_owned(name.to_owned())
}

fn harness_resource_owned(name: String) -> Box<DynManagedResource<'static>> {
    DynManagedResource::new_box(HarnessResource { name })
}

fn harness_worker(name: &'static str) -> bootstrap::WorkerSpec {
    harness_worker_owned(name.to_owned())
}

fn harness_worker_owned(name: String) -> bootstrap::WorkerSpec {
    bootstrap::WorkerSpec::phase_one(move |_token| harness_resource_owned(name.clone()))
}

fn phase_order_transcript_for_harness() -> String {
    RuntimePhase::ALL
        .iter()
        .copied()
        .map(RuntimePhase::as_str)
        .collect::<Vec<_>>()
        .join(" -> ")
}

struct HarnessProbe {
    name: ProbeName,
    status: HealthStatus,
}

impl bootstrap::HealthProbe for HarnessProbe {
    fn check(&self) -> HealthCheck {
        HealthCheck::new(self.name.clone(), self.status, "ready")
    }
}

struct HarnessResource {
    name: String,
}

impl diport::ManagedResource for HarnessResource {
    fn name(&self) -> &str {
        &self.name
    }

    async fn shutdown(&self) -> Result<(), diport::ShutdownError> {
        Ok(())
    }
}

fn identity_storage_error(message: &'static str) -> identity::ports::IdentityError {
    identity::ports::IdentityError::Storage(Box::new(std::io::Error::other(message)))
}

#[derive(Clone)]
struct StaticRoleRepo {
    roles: Arc<std::collections::BTreeMap<String, identity::ports::Role>>,
}

impl StaticRoleRepo {
    fn new(roles: Vec<identity::ports::Role>) -> Self {
        Self {
            roles: Arc::new(
                roles
                    .into_iter()
                    .map(|role| (role.id().as_str().to_string(), role))
                    .collect(),
            ),
        }
    }
}

impl identity::ports::RoleReadRepo for StaticRoleRepo {
    async fn find(
        &self,
        _scope: IdentityTenantRepoScope,
        id: identity::ports::RoleId,
    ) -> Result<Option<identity::ports::Role>, identity::ports::IdentityError> {
        Ok(self.roles.get(id.as_str()).cloned())
    }

    async fn list(
        &self,
        _scope: IdentityTenantRepoScope,
        _page: identity::ports::RolePage,
    ) -> Result<identity::ports::RoleListResult, identity::ports::IdentityError> {
        Ok(identity::ports::RoleListResult {
            roles: self.roles.values().cloned().collect(),
            has_more: false,
        })
    }
}

#[derive(Clone)]
struct StaticRoleBindings {
    bindings: Arc<Vec<(vocab::TenantId, String, String)>>,
}

impl StaticRoleBindings {
    fn new(bindings: Vec<(vocab::TenantId, String, String)>) -> Self {
        Self {
            bindings: Arc::new(bindings),
        }
    }
}

impl identity::ports::RoleBindingLifecycle for StaticRoleBindings {
    async fn assign_and_emit(
        &self,
        _receipt: identity::ports::RolesAssignProducerReceipt,
        _scope: IdentityTenantRepoScope,
        _binding: identity::ports::RoleBinding,
        _event: ReviewedEvent,
    ) -> Result<(), diport::OutboxEmitError> {
        Err(diport::OutboxEmitError::new(std::io::Error::other(
            "runtime test binding lifecycle is read-only",
        )))
    }

    async fn revoke_and_emit(
        &self,
        _receipt: identity::ports::RolesRevokeProducerReceipt,
        _scope: IdentityTenantRepoScope,
        _role_id: identity::ports::RoleId,
        _subject: String,
        _event: ReviewedEvent,
    ) -> Result<bool, diport::OutboxEmitError> {
        Err(diport::OutboxEmitError::new(std::io::Error::other(
            "runtime test binding lifecycle is read-only",
        )))
    }
}

impl identity::ports::RoleBindingReadRepo for StaticRoleBindings {
    async fn list_for_subject(
        &self,
        scope: IdentityTenantRepoScope,
        subject: String,
    ) -> Result<Vec<identity::ports::RoleBinding>, identity::ports::IdentityError> {
        let tenant = scope.tenant();
        self.bindings
            .iter()
            .filter(|(binding_tenant, binding_subject, _)| {
                *binding_tenant == tenant && *binding_subject == subject
            })
            .map(|(_, binding_subject, role_id)| {
                identity::ports::RoleBinding::hydrate(binding_subject.clone(), role_id, tenant)
            })
            .collect()
    }
}

struct EmptyPolicyRepo;

impl identity::ports::PolicyRepo for EmptyPolicyRepo {
    async fn find(
        &self,
        _scope: IdentityTenantRepoScope,
        _id: identity::ports::PolicyId,
    ) -> Result<Option<identity::ports::Policy>, identity::ports::IdentityError> {
        Ok(None)
    }

    async fn list_active(
        &self,
        _scope: IdentityTenantRepoScope,
        _page: identity::ports::PolicyPage,
    ) -> Result<identity::ports::PolicyListResult, identity::ports::IdentityError> {
        Ok(identity::ports::PolicyListResult {
            policies: Vec::new(),
            has_more: false,
        })
    }

    async fn list_effective(
        &self,
        _tenant_scope: IdentityTenantRepoScope,
        _scope: identity::ports::PolicyRouteScope,
        _at: SystemTime,
    ) -> Result<Vec<identity::ports::Policy>, identity::ports::IdentityError> {
        Ok(Vec::new())
    }
}

struct EmptyResourceAttributeRepo;

impl identity::ports::ResourceAttributeReadRepo for EmptyResourceAttributeRepo {
    async fn resolve_effective(
        &self,
        _tenant_scope: IdentityTenantRepoScope,
        _scope: identity::ports::PolicyRouteScope,
        _resource_id: identity::ports::ResourceAttributeResourceId,
        _required_keys: Vec<identity::ports::ResourceAttributeKey>,
        _at: SystemTime,
    ) -> Result<identity::ports::ResourceAttributeResolution, identity::ports::IdentityError> {
        Ok(identity::ports::ResourceAttributeResolution::Known(
            Vec::new(),
        ))
    }
}

struct EmptyPolicyLifecycle;

impl identity::ports::PolicyLifecycle for EmptyPolicyLifecycle {
    async fn create_and_emit(
        &self,
        _receipt: identity::ports::PoliciesCreateProducerReceipt,
        _scope: IdentityTenantRepoScope,
        _policy: identity::ports::Policy,
        _event: ReviewedEvent,
    ) -> Result<identity::ports::Policy, identity::ports::IdentityError> {
        Err(identity_storage_error(
            "runtime test policy lifecycle must not be called",
        ))
    }

    async fn update_and_emit(
        &self,
        _receipt: identity::ports::PoliciesUpdateProducerReceipt,
        _scope: IdentityTenantRepoScope,
        _policy: identity::ports::Policy,
        _expected: identity::ports::PolicyVersion,
        _event: ReviewedEvent,
    ) -> Result<identity::ports::Policy, identity::ports::IdentityError> {
        Err(identity_storage_error(
            "runtime test policy lifecycle must not be called",
        ))
    }

    async fn deactivate_and_emit(
        &self,
        _receipt: identity::ports::PoliciesDeactivateProducerReceipt,
        _scope: IdentityTenantRepoScope,
        _id: identity::ports::PolicyId,
        _expected: identity::ports::PolicyVersion,
        _event: ReviewedEvent,
    ) -> Result<bool, identity::ports::IdentityError> {
        Err(identity_storage_error(
            "runtime test policy lifecycle must not be called",
        ))
    }
}

struct UnusedCredentialRepo;

impl identity::ports::CredentialRepo for UnusedCredentialRepo {
    async fn find_by_user_id(
        &self,
        _scope: IdentityTenantRepoScope,
        _user_id: ids::UserId,
    ) -> Result<Option<identity::ports::Credential>, identity::ports::IdentityError> {
        Ok(None)
    }

    async fn authenticate(
        &self,
        _scope: IdentityTenantRepoScope,
        _login: identity::ports::LoginIdentifier,
        _candidate: secure::RawPassword,
        _now: SystemTime,
    ) -> Result<identity::ports::AuthOutcome, identity::ports::IdentityError> {
        Err(identity_storage_error(
            "runtime test credential repo must not be called",
        ))
    }

    async fn insert(
        &self,
        _scope: IdentityTenantRepoScope,
        _credential: identity::ports::Credential,
    ) -> Result<(), identity::ports::IdentityError> {
        Err(identity_storage_error(
            "runtime test credential repo is read-only",
        ))
    }
}

struct UnusedAccountSecurityRepo;

impl identity::ports::AccountSecurityReadRepo for UnusedAccountSecurityRepo {
    async fn find(
        &self,
        _scope: IdentityTenantRepoScope,
        _user_id: ids::UserId,
    ) -> Result<Option<identity::ports::AccountSecurityState>, identity::ports::IdentityError> {
        Ok(None)
    }
}

struct FailingIdentitySecurityLifecycle;

impl identity::ports::IdentitySecurityLifecycle for FailingIdentitySecurityLifecycle {
    async fn execute_refresh(
        &self,
        _receipt: identity::ports::RefreshProducerReceipt,
        _scope: IdentityTenantRepoScope,
        _command: identity::ports::RefreshExecutionCommand,
    ) -> Result<identity::ports::RefreshExecutionOutcome, identity::ports::IdentityError> {
        Err(identity_storage_error(
            "runtime test identity security lifecycle must not be called",
        ))
    }

    async fn execute_password_change(
        &self,
        _receipt: identity::ports::PasswordChangeProducerReceipt,
        _scope: IdentityTenantRepoScope,
        _command: identity::ports::PasswordChangeCommand,
    ) -> Result<identity::ports::CredentialSecurityReceipt, identity::ports::IdentityError> {
        Err(identity_storage_error(
            "runtime test identity security lifecycle must not be called",
        ))
    }

    async fn execute_account_status_set(
        &self,
        _receipt: identity::ports::AccountStatusSetProducerReceipt,
        _scope: IdentityTenantRepoScope,
        _command: identity::ports::AccountStatusSetCommand,
    ) -> Result<identity::ports::CredentialSecurityReceipt, identity::ports::IdentityError> {
        Err(identity_storage_error(
            "runtime test identity security lifecycle must not be called",
        ))
    }

    async fn execute_logout_current(
        &self,
        _receipt: identity::ports::LogoutCurrentProducerReceipt,
        _scope: IdentityTenantRepoScope,
        _command: identity::ports::LogoutCurrentCommand,
    ) -> Result<identity::ports::CredentialSecurityReceipt, identity::ports::IdentityError> {
        Err(identity_storage_error(
            "runtime test identity security lifecycle must not be called",
        ))
    }

    async fn execute_logout_all(
        &self,
        _receipt: identity::ports::LogoutAllProducerReceipt,
        _scope: IdentityTenantRepoScope,
        _command: identity::ports::LogoutAllCommand,
    ) -> Result<identity::ports::CredentialSecurityReceipt, identity::ports::IdentityError> {
        Err(identity_storage_error(
            "runtime test identity security lifecycle must not be called",
        ))
    }
}

impl identity::ports::AccountReactivationLifecycle for FailingIdentitySecurityLifecycle {
    async fn execute_reactivation(
        &self,
        _scope: IdentityTenantRepoScope,
        _command: identity::ports::ReactivateAccountCommand,
    ) -> Result<identity::ports::AccountSecurityState, identity::ports::IdentityError> {
        Err(identity_storage_error(
            "runtime test identity security lifecycle must not be called",
        ))
    }
}

#[derive(Clone, Copy)]
struct UnusedAuthGrantProvider;

impl identity::ports::AuthGrantLifecycle for UnusedAuthGrantProvider {
    async fn persist_login_grant(
        &self,
        _receipt: identity::ports::LoginProducerReceipt,
        _scope: IdentityTenantRepoScope,
        _mutation: identity::ports::LoginGrantMutation,
        _event: ReviewedEvent,
    ) -> Result<identity::ports::PersistedLoginGrantReceipt, diport::OutboxEmitError> {
        Err(diport::OutboxEmitError::new(std::io::Error::other(
            "runtime test auth-grant lifecycle must not be called",
        )))
    }

    async fn find_active(
        &self,
        _scope: IdentityTenantRepoScope,
        _grant_id: authn::AuthGrantId,
        _observed_at: SystemTime,
    ) -> Result<Option<authn::AuthGrant>, identity::ports::IdentityError> {
        Ok(None)
    }
}

impl identity::ports::RefreshTokenStore for UnusedAuthGrantProvider {
    async fn find_by_hash(
        &self,
        _scope: IdentityTenantRepoScope,
        _hash: identity::ports::RefreshTokenHash,
    ) -> Result<Option<identity::ports::RefreshTokenRecord>, identity::ports::IdentityError> {
        Ok(None)
    }
}

impl identity::ports::IdentitySecurityLifecycle for UnusedAuthGrantProvider {
    async fn execute_refresh(
        &self,
        _receipt: identity::ports::RefreshProducerReceipt,
        _scope: IdentityTenantRepoScope,
        _command: identity::ports::RefreshExecutionCommand,
    ) -> Result<identity::ports::RefreshExecutionOutcome, identity::ports::IdentityError> {
        Err(identity_storage_error("unused refresh lifecycle invoked"))
    }

    async fn execute_password_change(
        &self,
        _receipt: identity::ports::PasswordChangeProducerReceipt,
        _scope: IdentityTenantRepoScope,
        _command: identity::ports::PasswordChangeCommand,
    ) -> Result<identity::ports::CredentialSecurityReceipt, identity::ports::IdentityError> {
        Err(identity_storage_error("unused security lifecycle invoked"))
    }

    async fn execute_account_status_set(
        &self,
        _receipt: identity::ports::AccountStatusSetProducerReceipt,
        _scope: IdentityTenantRepoScope,
        _command: identity::ports::AccountStatusSetCommand,
    ) -> Result<identity::ports::CredentialSecurityReceipt, identity::ports::IdentityError> {
        Err(identity_storage_error("unused security lifecycle invoked"))
    }

    async fn execute_logout_current(
        &self,
        _receipt: identity::ports::LogoutCurrentProducerReceipt,
        _scope: IdentityTenantRepoScope,
        _command: identity::ports::LogoutCurrentCommand,
    ) -> Result<identity::ports::CredentialSecurityReceipt, identity::ports::IdentityError> {
        Err(identity_storage_error("unused security lifecycle invoked"))
    }

    async fn execute_logout_all(
        &self,
        _receipt: identity::ports::LogoutAllProducerReceipt,
        _scope: IdentityTenantRepoScope,
        _command: identity::ports::LogoutAllCommand,
    ) -> Result<identity::ports::CredentialSecurityReceipt, identity::ports::IdentityError> {
        Err(identity_storage_error("unused security lifecycle invoked"))
    }
}

#[derive(Clone)]
struct TestSigner;

impl diport::Signer for TestSigner {
    async fn sign(
        &self,
        _req: diport::SignRequest,
    ) -> Result<diport::Signature, diport::SignerError> {
        Ok(diport::Signature::new(vec![0x5a; 64]))
    }

    async fn shutdown(&self) -> Result<(), diport::SignerError> {
        Ok(())
    }
}

struct DelegatingAuditAdminRepo {
    repo: Arc<audit::ports::DynAuditReadRepo<'static>>,
}

impl audit::ports::AuditAdminRepo for DelegatingAuditAdminRepo {
    async fn list_tenant(
        &self,
        scope: audit::ports::CrossTenantReadScope,
        page: audit::ports::AuditPage,
    ) -> Result<audit::ports::AuditListResult, audit::ports::AuditError> {
        use audit::ports::AuditReadRepo as _;

        let tenant = scope.target();

        self.repo
            .list(AuditTenantRepoScope::for_test(tenant), page)
            .await
    }

    async fn verify_tenant(
        &self,
        tenant: vocab::TenantId,
        batch: vocab::Limit,
    ) -> Result<audit::ports::AuditLedgerVerifyReport, audit::ports::AuditError> {
        use audit::ports::AuditReadRepo as _;

        let mut cursor = None;
        let mut checked_entries = 0u64;
        loop {
            let result = self
                .repo
                .list(
                    AuditTenantRepoScope::for_test(tenant),
                    audit::ports::AuditPage {
                        limit: batch,
                        cursor,
                    },
                )
                .await?;
            checked_entries = checked_entries
                .checked_add(
                    u64::try_from(result.entries.len())
                        .map_err(audit::ports::AuditError::storage)?,
                )
                .ok_or(audit::ports::AuditError::SequenceGap)?;
            if !result.has_more {
                break;
            }
            cursor = result.next_cursor;
            if cursor.is_none() {
                return Err(audit::ports::AuditError::SequenceGap);
            }
        }
        Ok(audit::ports::AuditLedgerVerifyReport {
            tenant,
            checked_entries,
        })
    }
}

#[allow(clippy::expect_used)]
fn test_identity_domain_with_audit_role(
    tenant: vocab::TenantId,
) -> identity::IdentityDomain<TestSigner> {
    let audit_role = identity::ports::Role::hydrate(
        "audit-reader",
        "Audit reader",
        &[vocab::AUDIT_READ_PERMISSION.to_string()],
    )
    .expect("audit role");
    let inventory_role = identity::ports::Role::hydrate(
        "runtime-inventory-reader",
        "Runtime inventory reader",
        &[vocab::RoutePermissionId::RuntimeInventoryRead
            .as_str()
            .to_string()],
    )
    .expect("runtime inventory role");
    let roles = Arc::from(identity::ports::DynRoleReadRepo::new_box(
        StaticRoleRepo::new(vec![audit_role, inventory_role]),
    ));
    let binding_provider = StaticRoleBindings::new(vec![
        (
            tenant,
            "11111111-2222-4333-8444-555555555555".to_string(),
            "audit-reader".to_string(),
        ),
        (
            tenant,
            "11111111-2222-4333-8444-555555555555".to_string(),
            "runtime-inventory-reader".to_string(),
        ),
    ]);
    let binding_lifecycle = Arc::from(identity::ports::DynRoleBindingLifecycle::new_box(
        binding_provider.clone(),
    ));
    let binding_reads = Arc::from(identity::ports::DynRoleBindingReadRepo::new_box(
        binding_provider,
    ));
    let issuer = Arc::new(
        authn::JwtIssuer::<diport::RssAccessProfile, _>::new(
            Arc::new(TestSigner),
            Box::new(SystemClock),
            authn::JwtIssuerConfig::rss_access(
                authn::SigningKeyRing::single(diport::KeyId::new("runtime-test-key"))
                    .expect("non-empty signing key id"),
                diport::SigningPurpose::new("runtime-test"),
                "https://issuer.test",
                "rss-test",
                Duration::from_secs(900),
            ),
        )
        .expect("jwt issuer"),
    );
    let auth_grants = identity::AuthGrantServices::from_provider(
        UnusedAuthGrantProvider,
        identity::ports::DynAccountSecurityReadRepo::new_box(UnusedAccountSecurityRepo),
        issuer,
        Box::new(SystemClock),
        Duration::from_secs(900),
    );
    let refresh = auth_grants.refresh_service();
    let credential_security_grants = auth_grants.lifecycle();
    let credentials = Arc::from(identity::ports::DynCredentialRepo::new_box(
        UnusedCredentialRepo,
    ));
    let login = Arc::new(identity::LoginService::new(
        Arc::clone(&credentials),
        auth_grants,
        Box::new(SystemClock),
        Duration::from_secs(900),
    ));
    let rbac_admin = Arc::new(identity::RbacAdminService::new(
        Arc::clone(&roles),
        binding_lifecycle,
        Box::new(SystemClock),
    ));
    let policies = Arc::from(identity::ports::DynPolicyRepo::new_box(EmptyPolicyRepo));
    let resource_attribute_reads = Arc::from(
        identity::ports::DynResourceAttributeReadRepo::new_box(EmptyResourceAttributeRepo),
    );
    let policy_lifecycle = Arc::from(identity::ports::DynPolicyLifecycle::new_box(
        EmptyPolicyLifecycle,
    ));
    let policy_manage = Arc::new(identity::PolicyManageService::new(
        Arc::clone(&policies),
        policy_lifecycle,
        Box::new(SystemClock),
    ));
    let credential_security = Arc::new(identity::CredentialSecurityService::new(
        credentials,
        credential_security_grants,
        identity::ports::DynAccountSecurityReadRepo::new_box(UnusedAccountSecurityRepo),
        FailingIdentitySecurityLifecycle,
        FailingIdentitySecurityLifecycle,
        secure::PasswordPolicy::new(Arc::new(
            crypto::load_password_blocklist_from_reader(std::io::Cursor::new(include_bytes!(
                "../../../deploy/password-blocklist.demo.sha256"
            )))
            .expect("embedded runtime test blocklist"),
        )),
        Box::new(SystemClock),
    ));
    identity::IdentityDomain::new(identity::IdentityDomainDeps {
        login,
        refresh,
        credential_security,
        rbac_admin,
        policy_manage,
        roles,
        binding_reads,
        policies,
        resource_attribute_reads,
        clock: Arc::new(SystemClock),
    })
}

struct TestAuditRepos {
    read: Arc<audit::ports::DynAuditReadRepo<'static>>,
    write: Arc<audit::ports::DynAuditWriteRepo<'static>>,
}

#[allow(clippy::expect_used)]
fn test_audit_repo() -> TestAuditRepos {
    let hasher = audit::ports::AuditChainHasher::new(
        RustCryptoMacVerifier,
        MacKey::from_bytes(vec![0x5a; 32]),
    )
    .expect("audit chain hasher");
    let provider = Arc::new(audit::InMemAuditRepo::new(hasher));
    TestAuditRepos {
        read: Arc::from(audit::ports::DynAuditReadRepo::new_box(Arc::clone(
            &provider,
        ))),
        write: Arc::from(audit::ports::DynAuditWriteRepo::new_box(provider)),
    }
}

fn test_audit_admin_repo(
    repo: Arc<audit::ports::DynAuditReadRepo<'static>>,
) -> Arc<audit::ports::DynAuditAdminRepo<'static>> {
    Arc::from(audit::ports::DynAuditAdminRepo::new_box(
        DelegatingAuditAdminRepo { repo },
    ))
}

#[allow(clippy::expect_used)]
async fn append_sensitive_audit_record(
    repo: &Arc<audit::ports::DynAuditWriteRepo<'static>>,
    tenant: vocab::TenantId,
) {
    use audit::ports::AuditWriteRepo as _;

    repo.append(
        AuditTenantRepoScope::for_test(tenant),
        audit::ports::AuditRecord {
            tenant,
            actor: ids::UserId::parse("11111111-2222-4333-8444-555555555555").expect("actor"),
            actor_kind: vocab::PrincipalKind::Admin,
            action: vocab::Action::parse("audit:read").expect("action"),
            resource: audit::ports::ResourceRef::new(
                "session",
                "99999999-8888-4777-8666-555555555555",
            ),
            outcome: audit::ports::AuditOutcome::Success,
            recorded_at: SystemTime::UNIX_EPOCH,
        },
    )
    .await
    .expect("append audit record");
}

struct RuntimeTestClock;

impl diport::Clock for RuntimeTestClock {
    fn now(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(4_102_444_000)
    }
}

// Static P-256 scalar and closed verifier inputs are compile-time test fixtures.
#[allow(clippy::expect_used)]
fn runtime_test_provider() -> Arc<OidcProvider<diport::FederatedAccessProfile>> {
    use p256::ecdsa::SigningKey;

    let key = SigningKey::from_slice(&[7u8; 32]).expect("signing key");
    let keys = oidc::AccessStaticKeySource::builder()
        .add_es256_sec1(
            "runtime-test-federated",
            key.verifying_key().to_encoded_point(false).as_bytes(),
        )
        .expect("federated keyed ES256 public key")
        .build();
    let permissions = oidc::FederatedPermissionUniverse::try_new([vocab::GrantPermission::route(
        vocab::RoutePermissionId::AuditRead,
    )])
    .expect("non-empty federated permission universe");
    let config = oidc::VerifierConfigBuilder::<diport::FederatedAccessProfile>::new(
        "https://issuer.test",
        "rss-test",
        permissions,
    )
    .keys_static(keys)
    .trust_kind("admin")
    .trust_kind("superAdmin")
    .build()
    .expect("federated verifier config");
    Arc::new(OidcProvider::new(config, Box::new(RuntimeTestClock)))
}

#[allow(clippy::expect_used)]
fn runtime_test_jwt(kind: &str, tenant: Option<vocab::TenantId>) -> String {
    use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};

    let key = SigningKey::from_slice(&[7u8; 32]).expect("signing key");
    let header = B64.encode(br#"{"alg":"ES256","typ":"at+jwt","kid":"runtime-test-federated"}"#);
    let tenant_claim = tenant
        .map(|tenant| format!(r#","tenant_id":"{tenant}""#))
        .unwrap_or_default();
    let payload = format!(
        r#"{{"sub":"11111111-2222-4333-8444-555555555555","iat":4102443900,"exp":4102444800,"iss":"https://issuer.test","aud":"rss-test","token_use":"access","kind":"{kind}","permissions":["{}"]{tenant_claim}}}"#,
        vocab::RoutePermissionId::AuditRead.as_str(),
    );
    let body = B64.encode(payload.as_bytes());
    let signing_input = format!("{header}.{body}");
    let sig: Signature = key.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", B64.encode(sig.to_bytes()))
}

fn extract_admin_router(assembled: routes::FinalizedListenerSet) -> anyhow::Result<axum::Router> {
    assembled
        .into_listeners()
        .into_iter()
        .find_map(|assembled| {
            let (listener, routes) = assembled.into_parts();
            (listener == ListenerKind::Admin).then(|| routes.into_plaintext_router_for_test())
        })
        .context("admin router")
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn assembled_admin_audit_read_uses_identity_authorizer_and_masks_sensitive_fields()
-> anyhow::Result<()> {
    use tower::ServiceExt as _;

    let tenant = vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("tenant");
    let audit_repo = test_audit_repo();
    append_sensitive_audit_record(&audit_repo.write, tenant).await;
    let identity_domain = test_identity_domain_with_audit_role(tenant);
    let audit_domain = audit::AuditDomain::new(
        Arc::clone(&audit_repo.read),
        Some(test_audit_admin_repo(Arc::clone(&audit_repo.read))),
        TracingAuthAuditSink,
        Arc::new(SystemClock),
    );
    let domains: [&dyn bootstrap::Domain; 2] = [&identity_domain, &audit_domain];
    let mut registry = bootstrap::compose(&domains)?;
    let providers =
        routes::TokenProviderBindings::new(None, None, Some(runtime_test_provider()), None);
    let snapshot = crate::config::test_snapshot(&[
        ("RSS_PRIMARY_TOKEN_PROFILE", "federated-access"),
        ("RSS_ADMIN_TOKEN_PROFILE", "federated-access"),
        ("RSS_INTERNAL_AUTH_SCHEME", "mtls"),
        (
            routes::INTERNAL_MTLS_SPIFFE_ALLOW_SET_ENV,
            "spiffe://example.org/ns/rss/sa/internal",
        ),
        (SPIFFE_ENDPOINT_SOCKET_ENV, "unix:///run/spire/test.sock"),
    ])?;
    let execution_plan = plan::RuntimePlan::bundled(snapshot.view())?.listener_execution_plan();
    #[derive(Clone)]
    struct NoopMetrics;
    impl diport::MetricsExporter for NoopMetrics {
        fn render(&self) -> String {
            String::new()
        }
    }
    let metrics: Arc<dyn diport::MetricsExporter> = Arc::new(NoopMetrics);
    let framework_routes =
        crate::runtime_inventory::RuntimeInventoryRoutes::unpublished_fixture(snapshot.view())?;
    let finalized = routes::finalize_listener_plan(routes::FinalizeListenerPlanInputs {
        execution_plan,
        config: snapshot.view(),
        registry: &mut registry,
        providers: &providers,
        audit_sink: httpserve::AuditSinkHandle::new(TracingAuthAuditSink),
        audit_clock: Arc::new(SystemClock),
        rate_limiter: routes::build_runtime_rate_limiter(),
        metrics,
        framework_routes,
    })?;
    let app = extract_admin_router(finalized.into_parts().0)?;

    let scoped_response = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method(Method::GET)
                .uri(generated::http::audit_v1::list_entries::SPEC.route.path())
                .header(
                    axum::http::header::AUTHORIZATION,
                    format!("Bearer {}", runtime_test_jwt("admin", Some(tenant))),
                )
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert_eq!(scoped_response.status(), axum::http::StatusCode::OK);
    let scoped_body = axum::body::to_bytes(scoped_response.into_body(), usize::MAX).await?;
    let scoped_json: serde_json::Value = serde_json::from_slice(&scoped_body)?;
    assert_eq!(scoped_json["data"][0]["actor"], "<redacted>");
    assert_eq!(scoped_json["data"][0]["resourceId"], "<redacted>");

    let target_response = app
        .oneshot(
            axum::http::Request::builder()
                .method(Method::GET)
                .uri(
                    generated::http::audit_v1::list_tenant_entries::SPEC
                        .route
                        .path()
                        .replace("{tenantId}", &tenant.to_string()),
                )
                .header(
                    axum::http::header::AUTHORIZATION,
                    format!("Bearer {}", runtime_test_jwt("superAdmin", None)),
                )
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert_eq!(target_response.status(), axum::http::StatusCode::OK);
    let target_body = axum::body::to_bytes(target_response.into_body(), usize::MAX).await?;
    let target_json: serde_json::Value = serde_json::from_slice(&target_body)?;
    assert_eq!(target_json["data"][0]["actor"], "<redacted>");
    assert_eq!(target_json["data"][0]["resourceId"], "<redacted>");
    Ok(())
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn runtime_inventory_admin_uses_rss_user_and_identity_durable_grant_policy()
-> anyhow::Result<()> {
    let tenant = vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")?;
    let bound_subject = "11111111-2222-4333-8444-555555555555";
    let identity_domain = test_identity_domain_with_audit_role(tenant);
    let mut registry = bootstrap::compose(&[&identity_domain])?;
    let authorizer = registry.take_primary_authorizer()?;
    let snapshot = crate::config::test_snapshot(&[
        ("RSS_PRIMARY_TOKEN_PROFILE", "rss-access"),
        ("RSS_ADMIN_TOKEN_PROFILE", "rss-access"),
        ("RSS_INTERNAL_AUTH_SCHEME", "mtls"),
    ])?;
    let admin = plan::RuntimePlan::bundled(snapshot.view())?
        .listener_execution_plan()
        .into_listeners()
        .into_iter()
        .find(|listener| listener.kind() == primitives::ListenerKind::Admin)
        .context("runtime Admin listener")?;
    assert_eq!(admin.auth_scheme(), primitives::AuthScheme::RssAccessToken);

    let request = |subject: &str| httpserve::RouteAuthorizationRequest {
        contract_id: generated::http::runtime_v1::inventory::SPEC
            .route
            .contract_id(),
        permission: vocab::RoutePermissionId::RuntimeInventoryRead,
        tenant_id: Some(tenant),
        principal_kind: vocab::PrincipalKind::User,
        principal_id: subject.to_string(),
        federated_permissions: None,
        resource: None,
    };
    assert_eq!(
        authorizer.authorize(request(bound_subject)).await,
        httpserve::RouteAuthorizationDecision::Allow
    );
    assert_eq!(
        authorizer.authorize(request("unbound-rss-user")).await,
        httpserve::RouteAuthorizationDecision::Deny
    );
    Ok(())
}

#[test]
#[allow(clippy::expect_used)]
fn identity_maintenance_module_emits_auth_grant_sweeper_probe_and_worker() {
    struct NoopResource;
    impl diport::ManagedResource for NoopResource {
        fn name(&self) -> &str {
            "noop-auth-grant-sweeper"
        }

        async fn shutdown(&self) -> Result<(), diport::ShutdownError> {
            Ok(())
        }
    }

    let health = Arc::new(SweeperHealth::starting());
    let worker =
        bootstrap::WorkerSpec::phase_one(|_| diport::DynManagedResource::new_box(NoopResource));
    let result = sweeper_module_result(worker, health, AUTH_GRANT_SWEEPER_PROBE_NAME)
        .expect("auth-grant sweeper module result");
    assert_eq!(result.probes.len(), 1);
    assert_eq!(result.probes[0].0.as_str(), AUTH_GRANT_SWEEPER_PROBE_NAME);
    assert!(result.resources.is_empty());
    assert_eq!(
        result.workers.len(),
        1,
        "auth-grant sweeper must be registered as a managed worker"
    );
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn revocation_provider_module_registers_exact_probe_and_managed_worker() {
    let pg = ::postgres::PgRuntimeHandle::for_module_test();
    let mut result =
        wire_revocation_sweeper(&pg).expect("receipt-backed revocation sweeper module result");
    assert_eq!(result.probes.len(), 1);
    assert_eq!(result.probes[0].0.as_str(), REVOCATION_SWEEPER_PROBE_NAME);
    assert!(result.resources.is_empty());
    assert_eq!(result.workers.len(), 1);

    let worker = result.workers.pop().expect("one revocation worker");
    let root = CancellationToken::new();
    let resource = match worker {
        bootstrap::WorkerSpec::PhaseOne(make) | bootstrap::WorkerSpec::Deferred(make) => {
            make(root.clone())
        }
    };
    assert_eq!(resource.name(), REVOCATION_SWEEPER_WORKER_NAME);
    root.cancel();
    assert!(resource.shutdown().await.is_ok());
}

struct ScriptedAuthGrantSweeper {
    calls: Arc<AtomicUsize>,
    outcomes: VecDeque<tokio::sync::oneshot::Receiver<Result<u64, consistency::EngineError>>>,
}

struct ScriptedRevocationSweeper {
    calls: Arc<AtomicUsize>,
    outcomes: VecDeque<
        tokio::sync::oneshot::Receiver<
            Result<RevocationSweepObservation, consistency::EngineError>,
        >,
    >,
}

fn revocation_retention_report(deleted: u64) -> RevocationSweepObservation {
    RevocationSweepObservation::new(deleted, eventexec::RetentionBacklog::new(0, 0))
}

impl RevocationSweepRunner for ScriptedRevocationSweeper {
    fn sweep(
        &mut self,
        _deadline: ::postgres::RevocationSweepDeadline,
    ) -> RevocationSweepFuture<'_> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let receiver = self.outcomes.pop_front();
        Box::pin(async move {
            let Some(receiver) = receiver else {
                return Err(consistency::EngineError::new(
                    consistency::EngineErrorKind::Invariant,
                ));
            };
            receiver.await.unwrap_or_else(|_| {
                Err(consistency::EngineError::new(
                    consistency::EngineErrorKind::Invariant,
                ))
            })
        })
    }
}

impl AuthGrantSweepRunner for ScriptedAuthGrantSweeper {
    fn sweep(&mut self, _deadline: ::postgres::AuthGrantSweepDeadline) -> AuthGrantSweepFuture<'_> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let receiver = self.outcomes.pop_front();
        Box::pin(async move {
            let Some(receiver) = receiver else {
                return Err(consistency::EngineError::new(
                    consistency::EngineErrorKind::Invariant,
                ));
            };
            receiver.await.unwrap_or_else(|_| {
                Err(consistency::EngineError::new(
                    consistency::EngineErrorKind::Invariant,
                ))
            })
        })
    }
}

async fn wait_for_sweeper_calls(calls: &AtomicUsize, expected: usize) {
    for _ in 0..32 {
        if calls.load(Ordering::SeqCst) >= expected {
            return;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        expected,
        "sweeper loop did not reach expected call count"
    );
}

async fn wait_for_sweeper_health(health: &SweeperHealth, expected: (HealthStatus, &'static str)) {
    for _ in 0..32 {
        if health.status_detail() == expected {
            return;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(
        health.status_detail(),
        expected,
        "sweeper loop did not reach expected health state"
    );
}

#[tokio::test(start_paused = true)]
async fn auth_grant_sweeper_health_tracks_first_success_error_and_exit() {
    let (first_tx, first_rx) = tokio::sync::oneshot::channel();
    let (second_tx, second_rx) = tokio::sync::oneshot::channel();
    let calls = Arc::new(AtomicUsize::new(0));
    let health = Arc::new(SweeperHealth::starting());
    let token = CancellationToken::new();
    let handle = tokio::spawn(run_auth_grant_sweeper_loop(
        ScriptedAuthGrantSweeper {
            calls: Arc::clone(&calls),
            outcomes: VecDeque::from([first_rx, second_rx]),
        },
        Duration::from_secs(10),
        Duration::from_secs(100),
        token.clone(),
        Arc::clone(&health),
    ));

    wait_for_sweeper_calls(&calls, 1).await;
    assert_eq!(
        health.status_detail(),
        (HealthStatus::Unhealthy, "starting"),
        "readiness must fail closed while the first sweep is in flight"
    );
    assert!(first_tx.send(Ok(1)).is_ok());
    wait_for_sweeper_health(&health, (HealthStatus::Healthy, "worker")).await;

    tokio::time::advance(Duration::from_secs(10)).await;
    wait_for_sweeper_calls(&calls, 2).await;
    assert!(
        second_tx
            .send(Err(consistency::EngineError::new(
                consistency::EngineErrorKind::Transient,
            )))
            .is_ok()
    );
    wait_for_sweeper_health(&health, (HealthStatus::Degraded, "degraded")).await;

    token.cancel();
    assert!(handle.await.is_ok());
    assert_eq!(health.status_detail(), (HealthStatus::Unhealthy, "stopped"));
}

#[tokio::test(start_paused = true)]
async fn auth_grant_sweeper_delays_missed_ticks_instead_of_bursting() {
    let (first_tx, first_rx) = tokio::sync::oneshot::channel();
    let (_second_tx, second_rx) = tokio::sync::oneshot::channel();
    let calls = Arc::new(AtomicUsize::new(0));
    let health = Arc::new(SweeperHealth::starting());
    let token = CancellationToken::new();
    let handle = tokio::spawn(run_auth_grant_sweeper_loop(
        ScriptedAuthGrantSweeper {
            calls: Arc::clone(&calls),
            outcomes: VecDeque::from([first_rx, second_rx]),
        },
        Duration::from_secs(10),
        Duration::from_secs(100),
        token.clone(),
        Arc::clone(&health),
    ));

    wait_for_sweeper_calls(&calls, 1).await;
    tokio::time::advance(Duration::from_secs(30)).await;
    assert!(first_tx.send(Ok(1)).is_ok());
    tokio::task::yield_now().await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "Delay policy must not issue a catch-up burst after a long sweep"
    );

    tokio::time::advance(Duration::from_secs(9)).await;
    tokio::task::yield_now().await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    tokio::time::advance(Duration::from_secs(1)).await;
    wait_for_sweeper_calls(&calls, 2).await;

    token.cancel();
    assert!(handle.await.is_ok());
    assert_eq!(health.status_detail(), (HealthStatus::Unhealthy, "stopped"));
}

#[tokio::test(start_paused = true)]
async fn revocation_sweeper_health_tracks_success_error_recovery_and_exit() {
    let (first_tx, first_rx) = tokio::sync::oneshot::channel();
    let (second_tx, second_rx) = tokio::sync::oneshot::channel();
    let (third_tx, third_rx) = tokio::sync::oneshot::channel();
    let (_fourth_tx, fourth_rx) = tokio::sync::oneshot::channel();
    let calls = Arc::new(AtomicUsize::new(0));
    let health = Arc::new(SweeperHealth::starting());
    let token = CancellationToken::new();
    let handle = tokio::spawn(run_revocation_sweeper_loop(
        ScriptedRevocationSweeper {
            calls: Arc::clone(&calls),
            outcomes: VecDeque::from([first_rx, second_rx, third_rx, fourth_rx]),
        },
        Duration::from_secs(10),
        Duration::from_secs(100),
        token.clone(),
        Arc::clone(&health),
    ));

    wait_for_sweeper_calls(&calls, 1).await;
    assert_eq!(
        health.status_detail(),
        (HealthStatus::Unhealthy, "starting"),
        "readiness must fail closed while the initial retention sweep is in flight"
    );
    assert!(first_tx.send(Ok(revocation_retention_report(1))).is_ok());
    wait_for_sweeper_health(&health, (HealthStatus::Healthy, "worker")).await;

    tokio::time::advance(Duration::from_secs(10)).await;
    wait_for_sweeper_calls(&calls, 2).await;
    assert!(
        second_tx
            .send(Err(consistency::EngineError::new(
                consistency::EngineErrorKind::Transient,
            )))
            .is_ok()
    );
    wait_for_sweeper_health(&health, (HealthStatus::Degraded, "degraded")).await;

    tokio::time::advance(Duration::from_secs(10)).await;
    wait_for_sweeper_calls(&calls, 3).await;
    assert!(third_tx.send(Ok(revocation_retention_report(2))).is_ok());
    wait_for_sweeper_health(&health, (HealthStatus::Healthy, "worker")).await;

    tokio::time::advance(Duration::from_secs(10)).await;
    wait_for_sweeper_calls(&calls, 4).await;
    token.cancel();
    assert!(handle.await.is_ok());
    assert_eq!(health.status_detail(), (HealthStatus::Unhealthy, "stopped"));
}

#[tokio::test(start_paused = true)]
async fn revocation_sweeper_delays_missed_ticks_instead_of_bursting() {
    let (first_tx, first_rx) = tokio::sync::oneshot::channel();
    let (_second_tx, second_rx) = tokio::sync::oneshot::channel();
    let calls = Arc::new(AtomicUsize::new(0));
    let health = Arc::new(SweeperHealth::starting());
    let token = CancellationToken::new();
    let handle = tokio::spawn(run_revocation_sweeper_loop(
        ScriptedRevocationSweeper {
            calls: Arc::clone(&calls),
            outcomes: VecDeque::from([first_rx, second_rx]),
        },
        Duration::from_secs(10),
        Duration::from_secs(100),
        token.clone(),
        Arc::clone(&health),
    ));

    wait_for_sweeper_calls(&calls, 1).await;
    tokio::time::advance(Duration::from_secs(30)).await;
    assert!(first_tx.send(Ok(revocation_retention_report(1))).is_ok());
    tokio::task::yield_now().await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "Delay policy must not issue a catch-up burst after a long retention sweep"
    );

    tokio::time::advance(Duration::from_secs(9)).await;
    tokio::task::yield_now().await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    tokio::time::advance(Duration::from_secs(1)).await;
    wait_for_sweeper_calls(&calls, 2).await;

    token.cancel();
    assert!(handle.await.is_ok());
    assert_eq!(health.status_detail(), (HealthStatus::Unhealthy, "stopped"));
}

#[test]
fn maintenance_sweepers_share_one_control_loop() {
    let source = include_str!("phase/maintenance.rs");
    assert_eq!(
        source.matches("tokio::time::interval(").count(),
        1,
        "maintenance sweepers must share one interval/cancellation/health control loop"
    );
    assert_eq!(
        source
            .matches("set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay)")
            .count(),
        1,
        "the shared control loop must own the single Delay policy"
    );
}

/// RlsReadyProbe：`true → Healthy("ready")` / `false → Unhealthy("not-enforced")`（fail-closed）。
#[test]
fn rls_ready_probe_maps_flag_to_health() {
    use bootstrap::HealthProbe;
    use std::sync::atomic::{AtomicBool, Ordering};

    let flag = Arc::new(AtomicBool::new(true));
    let probe = RlsReadyProbe::new(Arc::clone(&flag));
    let ready = probe.check();
    assert_eq!(ready.status(), HealthStatus::Healthy);
    assert_eq!(ready.detail(), "ready");
    assert_eq!(ready.name().as_str(), RLS_READY_PROBE_NAME);

    flag.store(false, Ordering::Release);
    let down = probe.check();
    assert_eq!(down.status(), HealthStatus::Unhealthy);
    assert_eq!(down.detail(), "not-enforced");
}

#[test]
#[allow(clippy::expect_used)]
fn domain_transport_empty_remote_set_resolves_without_targets() {
    let targets =
        build_domain_transport_targets_from(bootstrap::Topology::DurableShared, &[], |_| None)
            .expect("empty remote set is InProc-compatible");
    assert!(targets.is_empty());
}

#[test]
#[allow(clippy::expect_used)]
fn domain_transport_per_domain_allow_set_is_required() {
    let remotes = vec!["IDENTITY".to_owned()];
    let err =
        build_domain_transport_targets_from(bootstrap::Topology::DurableShared, &remotes, |name| {
            match name {
                "RSS_IDENTITY_DOMAIN_TRANSPORT_URL" => {
                    Some("https://identity.internal/rpc".to_string())
                }
                DOMAIN_TRANSPORT_LOCAL_SPIFFE_ID_ENV => {
                    Some("spiffe://example.org/ns/rss/sa/runtime".to_string())
                }
                _ => None,
            }
        })
        .expect_err("remote target requires exact server SPIFFE allow-set");
    assert!(
        err.to_string()
            .contains("RSS_IDENTITY_DOMAIN_TRANSPORT_MTLS_SPIFFE_ALLOW_SET"),
        "error should name per-domain allow-set env: {err}"
    );
}

#[test]
#[allow(clippy::expect_used)]
fn domain_transport_isolated_topology_forbids_shared_fallback() {
    let remotes = vec!["IDENTITY".to_owned()];
    let err = build_domain_transport_targets_from(
        bootstrap::Topology::DurableIsolated,
        &remotes,
        |name| match name {
            DOMAIN_TRANSPORT_SHARED_URL_ENV => Some("https://gateway.internal/rpc".to_string()),
            _ => None,
        },
    )
    .expect_err("isolated topology must not use shared domain transport fallback");
    assert!(
        format!("{err:#}").contains(DOMAIN_TRANSPORT_SHARED_URL_ENV),
        "error should name shared fallback env: {err}"
    );
}

#[test]
#[allow(clippy::expect_used)]
fn domain_transport_targets_build_typed_outbound_mtls_policy() {
    let remotes = vec!["IDENTITY".to_owned()];
    let targets =
        build_domain_transport_targets_from(bootstrap::Topology::DurableShared, &remotes, |name| {
            match name {
                DOMAIN_TRANSPORT_SHARED_URL_ENV => Some("https://gateway.internal/rpc".to_string()),
                DOMAIN_TRANSPORT_LOCAL_SPIFFE_ID_ENV => {
                    Some("spiffe://example.org/ns/rss/sa/runtime".to_string())
                }
                "RSS_IDENTITY_DOMAIN_TRANSPORT_MTLS_SPIFFE_ALLOW_SET" => {
                    Some("spiffe://example.org/ns/rss/sa/identity".to_string())
                }
                _ => None,
            }
        })
        .expect("valid domain transport target config");
    assert_eq!(targets.len(), 1);
}

#[test]
fn domain_transport_snapshot_requires_explicit_spiffe_endpoint() {
    assert!(matches!(
        required_spiffe_endpoint_from_value(None),
        Err(error) if error.to_string() == "missing required env var: SPIFFE_ENDPOINT_SOCKET"
    ));
}

#[derive(Clone)]
struct NoopRuntimeDomainTransport {
    ready: Arc<std::sync::atomic::AtomicBool>,
}

impl distributed::HttpContractTransport for NoopRuntimeDomainTransport {
    fn dispatch(
        &self,
        _request: distributed::HttpContractRequest,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        distributed::HttpContractResponse,
                        distributed::HttpContractTransportError,
                    >,
                > + Send
                + '_,
        >,
    > {
        Box::pin(async { distributed::HttpContractResponse::try_new(204, Vec::new()) })
    }
}

impl ManagedResource for NoopRuntimeDomainTransport {
    fn name(&self) -> &str {
        "domain-http-transport"
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        Ok(())
    }
}

impl RuntimeHttpContractTransport for NoopRuntimeDomainTransport {
    fn owned_readiness(&self) -> httpd::DomainHttpOwnedReadiness {
        if self.ready.load(std::sync::atomic::Ordering::Acquire) {
            httpd::DomainHttpOwnedReadiness::Ready
        } else {
            httpd::DomainHttpOwnedReadiness::MtlsSourceUnavailable
        }
    }
}

#[test]
#[allow(clippy::expect_used)]
fn domain_transport_runtime_exports_dispatch_resource_and_readyz() {
    let ready = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let runtime = DomainTransportRuntime::InProc(DomainTransportRuntimeInner::new(
        InProcHttpContractTransport,
        ProbeName::parse(DOMAIN_TRANSPORT_READY_PROBE_NAME).expect("valid domain transport probe"),
        distributed::TransportMode::InProc,
    ));
    // Keep a remote-shaped readiness probe path covered via the Noop adapter below.
    let _ = ready;
    let _dispatch = runtime.dispatch_handle();
    let module = runtime.module_result();

    assert_eq!(module.resources.len(), 1);
    assert_eq!(module.resources[0].name(), "domain-transport-inproc");
    assert_eq!(module.probes.len(), 1);
    let healthy = module.probes[0].1.check();
    assert_eq!(healthy.name().as_str(), DOMAIN_TRANSPORT_READY_PROBE_NAME);
    assert_eq!(healthy.status(), HealthStatus::Healthy);
    assert_eq!(healthy.detail(), "ready");

    let ready = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let runtime = DomainTransportRuntimeInner::new(
        NoopRuntimeDomainTransport {
            ready: Arc::clone(&ready),
        },
        ProbeName::parse(DOMAIN_TRANSPORT_READY_PROBE_NAME).expect("valid domain transport probe"),
        distributed::TransportMode::Remote,
    );
    let module = runtime.module_result();
    let healthy = module.probes[0].1.check();
    assert_eq!(healthy.status(), HealthStatus::Healthy);
    ready.store(false, std::sync::atomic::Ordering::Release);
    let unhealthy = module.probes[0].1.check();
    assert_eq!(unhealthy.status(), HealthStatus::Unhealthy);
    assert_eq!(unhealthy.detail(), "mtls-source-unavailable");
}

#[test]
fn system_clock_now_is_after_epoch() {
    use diport::Clock as _;
    // 覆盖组合根生产时钟读点（disallowed_methods item-level 解禁线）。
    assert!(SystemClock.now() > SystemTime::UNIX_EPOCH);
}

/// `RLS_READY_PROBE_NAME` 是合法 `ProbeName`；真实 `RlsReadyProbe` 可注册 + 重名拒绝（与 configs_ready 对称）。
#[test]
#[allow(clippy::expect_used)]
fn rls_ready_registers_and_is_unique() {
    use std::sync::atomic::AtomicBool;
    // reason: RLS_READY_PROBE_NAME 是 const literal，parse 只可能在字符非法时失败。
    let name_a =
        primitives::ProbeName::parse(RLS_READY_PROBE_NAME).expect("valid probe name const");
    let name_b =
        primitives::ProbeName::parse(RLS_READY_PROBE_NAME).expect("valid probe name const");
    let mut registry = bootstrap::compose(&[]).expect("empty compose");
    let flag = Arc::new(AtomicBool::new(true));

    registry
        .probe(name_a, Box::new(RlsReadyProbe::new(Arc::clone(&flag))))
        .expect("first register ok");
    let result = registry.probe(name_b, Box::new(RlsReadyProbe::new(flag)));
    assert!(
        result.is_err(),
        "duplicate rls_ready probe name should be rejected"
    );
}

// ── build_trace_export_from_value：endpoint typed 安全边界（fail-fast）─────────────
// 显式 raw value（不读真实 env）覆盖 None / TLS / loopback-http / 非 loopback 明文 / 非法 scheme 五态。

fn test_telemetry_resource() -> otel::TelemetryResource {
    otel::TelemetryResource::try_new("runtime", "assembly-fp", "plan-fp")
        .expect("non-empty telemetry resource")
}

#[test]
#[allow(clippy::expect_used)] // reason: 测试断言失败路径用 expect 直观定位（error-handling §Carve-out item-level）
fn build_trace_export_unset_endpoint_is_none() {
    // 未配 RSS_OTEL_ENDPOINT → 仅 fmt 日志、不导出 trace（按需开启），且非 Err。
    let out = build_trace_export_from_value(None, &test_telemetry_resource())
        .expect("unset endpoint is Ok(None)");
    assert!(out.is_none(), "unset endpoint must yield None");
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn build_trace_export_uses_the_captured_endpoint_mapping() {
    let snapshot = crate::config::test_snapshot(&[(OTEL_ENDPOINT_ENV, "http://localhost:4317")])
        .expect("capture trace endpoint");

    let out = build_trace_export(snapshot.view(), &test_telemetry_resource())
        .expect("snapshot-backed loopback endpoint builds exporter");
    assert!(out.is_some(), "captured endpoint must enable exporting");
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn run_pre_handoff_failure_explicitly_shuts_down_trace_exporter() {
    let snapshot = crate::config::test_snapshot(&[
        (
            domains::identity::PASSWORD_BLOCKLIST_PATH_ENV,
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../deploy/password-blocklist.demo.sha256"
            ),
        ),
        ("RSS_PRIMARY_TOKEN_PROFILE", "rss-access"),
        ("RSS_ADMIN_TOKEN_PROFILE", "rss-access"),
        ("RSS_INTERNAL_AUTH_SCHEME", "mtls"),
    ])
    .expect("capture runtime config with local password policy");
    let endpoint = otel::OtelEndpoint::insecure_localhost("http://localhost:4317")
        .expect("hermetic loopback endpoint");
    let telemetry_plan =
        crate::phase::PreparedTelemetryPlan::prepare(snapshot.view()).expect("bundled RuntimePlan");
    let provider = otel::build_otlp_provider(endpoint, telemetry_plan.resource())
        .expect("build lazy hermetic provider");
    let shutdown_witness = provider.clone();
    let inputs = ServingRuntimeInputs::new(
        PreparedRuntimeInputs::new(snapshot, Some(otel::OtelExporter::new(provider))),
        test_password_blocklist(),
        telemetry_plan,
    );

    let err = run(inputs)
        .await
        .expect_err("missing token profile config must fail before launch handoff");
    assert!(!format!("{err:#}").is_empty());
    assert!(
        shutdown_witness.shutdown().is_err(),
        "pre-handoff failure must explicitly shut down the shared provider"
    );
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn runtime_lifecycle_owner_does_not_shutdown_exporter_after_handoff() {
    let snapshot = crate::config::test_snapshot(&[
        ("RSS_PRIMARY_TOKEN_PROFILE", "rss-access"),
        ("RSS_ADMIN_TOKEN_PROFILE", "rss-access"),
        ("RSS_INTERNAL_AUTH_SCHEME", "mtls"),
    ])
    .expect("capture runtime plan config");
    let endpoint = otel::OtelEndpoint::insecure_localhost("http://localhost:4317")
        .expect("hermetic loopback endpoint");
    let telemetry_plan =
        crate::phase::PreparedTelemetryPlan::prepare(snapshot.view()).expect("bundled RuntimePlan");
    let provider = otel::build_otlp_provider(endpoint, telemetry_plan.resource())
        .expect("build lazy hermetic provider");
    let handoff_witness = provider.clone();
    let inputs = ServingRuntimeInputs::new(
        PreparedRuntimeInputs::new(snapshot, Some(otel::OtelExporter::new(provider))),
        test_password_blocklist(),
        telemetry_plan,
    );
    let mut owner = RuntimeLifecycleOwner::new(inputs);
    let handed_off = owner
        .inputs
        .take_trace_export()
        .expect("exporter must move into launch ownership");

    owner
        .finish(Ok(()))
        .await
        .expect("empty outer owner must finish without a second shutdown");
    assert!(
        handoff_witness.force_flush().is_ok(),
        "provider must remain live after exporter handoff"
    );
    diport::ManagedResource::shutdown(&handed_off)
        .await
        .expect("launch owner shuts exporter down");
    assert!(
        handoff_witness.shutdown().is_err(),
        "launch shutdown must be visible through the shared provider"
    );
}

#[tokio::test]
#[allow(clippy::expect_used)] // reason: 测试断言失败路径用 expect 直观定位（error-handling §Carve-out item-level）
async fn build_trace_export_loopback_http_builds_exporter() {
    // 明文 http 指向 loopback → 显式 opt-in，构建出 exporter（connect_lazy，不连真实 collector）。
    let out =
        build_trace_export_from_value(Some("http://localhost:4317"), &test_telemetry_resource())
            .expect("loopback http endpoint builds exporter");
    assert!(out.is_some(), "loopback http must build Some(exporter)");
}

#[tokio::test]
#[allow(clippy::expect_used)] // reason: 测试断言失败路径用 expect 直观定位（error-handling §Carve-out item-level）
async fn build_trace_export_tls_https_builds_exporter() {
    let out = build_trace_export_from_value(
        Some("https://collector.internal:4317"),
        &test_telemetry_resource(),
    )
    .expect("https TLS endpoint builds exporter");
    assert!(out.is_some(), "https endpoint must build Some(exporter)");
}

#[test]
#[allow(clippy::expect_used)] // reason: 测试断言失败路径用 expect 直观定位（error-handling §Carve-out item-level）
fn build_trace_export_nonloopback_http_is_err() {
    // 明文 http 指向非 loopback host → fail-closed Err（不静默放行明文导出到远端）。
    let err = build_trace_export_from_value(
        Some("http://collector.internal:4317"),
        &test_telemetry_resource(),
    )
    .map(|_| ()) // OtelExporter 非 Debug，expect_err 前把 Ok 臂折叠成 ()
    .expect_err("non-loopback plaintext must fail-fast");
    assert!(
        format!("{err:#}").contains("loopback"),
        "err 应提示 loopback 约束: {err:#}"
    );
}

#[test]
#[allow(clippy::expect_used)] // reason: 测试断言失败路径用 expect 直观定位（error-handling §Carve-out item-level）
fn build_trace_export_bad_scheme_is_err() {
    // 非 http(s) scheme → fail-fast（误配在接线期暴露，不静默退回 fmt）。
    const SECRET_FRAGMENT: &str = "collector-token";
    let err = build_trace_export_from_value(
        Some("grpc://user:collector-token@collector.internal:4317"),
        &test_telemetry_resource(),
    )
    .map(|_| ()) // OtelExporter 非 Debug，expect_err 前把 Ok 臂折叠成 ()
    .expect_err("non http(s) scheme must fail-fast");
    let error = format!("{err:#}");
    assert!(
        error.contains(OTEL_ENDPOINT_ENV),
        "err 应含 env 变量名: {err}"
    );
    assert!(
        !error.contains(SECRET_FRAGMENT),
        "trace endpoint errors must not expose configured credentials"
    );
}
