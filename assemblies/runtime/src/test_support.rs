//! Integration-only seams for exercising typed domain wiring with hermetic providers.

use std::sync::Arc;
use std::time::Duration;

use super::{DistributedRuntimeDeps, SharedRuntimeDeps};

pub use crate::domains::identity::IdentityTestValues;
pub use crate::event_transport::{EventTransportTestValues, EventWorkerTestValues};

/// Finalize one closed listener selected from the committed, fingerprint-verified RuntimePlan
/// fixture through the production auth finalization core.
pub fn finalize_rss_listener(
    registry: &mut bootstrap::Registry,
    provider: Arc<oidc::OidcProvider<diport::RssAccessProfile>>,
    audit_sink: httpserve::AuditSinkHandle,
    audit_clock: Arc<dyn diport::Clock>,
    kind: assembly_schema::AssemblyListenerKind,
) -> anyhow::Result<httpserve::AuthenticatedRoutes> {
    crate::routes::finalize_rss_fixture_listener(registry, provider, audit_sink, audit_clock, kind)
}

/// Finalize the plan-declared `Health + NoAuth` fixture through the production Health core.
pub fn finalize_health_listener(
    reporter: Arc<bootstrap::HealthReporter>,
    metrics: Arc<dyn diport::MetricsExporter>,
) -> anyhow::Result<httpserve::AuthenticatedRoutes> {
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
    allow_plaintext: bool,
    force_path_style: bool,
) -> anyhow::Result<s3::S3RuntimeDeps> {
    crate::infra::s3::build_s3_runtime_deps_from_values(
        endpoint_url,
        bucket,
        access_key_id,
        secret_access_key,
        allow_plaintext,
        force_path_style,
    )
}

/// Builds the production Vault capability bundle from explicit integration-test values.
pub fn build_vault_runtime_from_values(
    addr: String,
    token: String,
    transit_mount: String,
    settings_key_name: String,
) -> anyhow::Result<(
    vault::VaultRuntimeDeps,
    Arc<vault::VaultSigner>,
    diport::KeyName,
)> {
    crate::infra::vault::build_vault_runtime_from_values(
        addr,
        token,
        transit_mount,
        settings_key_name,
    )
}

/// Builds the production Redis capability bundle from explicit integration-test values.
///
/// The default production API exposes only the snapshot-backed typed constructor; this seam is
/// compiled solely for the container-backed integration lane.
pub async fn build_redis_runtime_deps_from_values(
    url: String,
    allow_plaintext: Option<&str>,
) -> anyhow::Result<redis::RedisRuntimeDeps> {
    crate::infra::redis::build_redis_runtime_deps_from_values(url, allow_plaintext).await
}

/// Wires the production event transport through an integration-only seam.
pub async fn wire_event_transport(
    pg: &postgres::PgRuntimeHandle,
    distributed: DistributedRuntimeDeps,
    subscribers: Vec<crate::event_transport::BridgedSubscription>,
    cfg: crate::event_transport::EventTransportConfig,
    worker: crate::event_transport::EventWorkerConfig,
    audit_key: primitives::MacKey,
) -> anyhow::Result<bootstrap::DomainModuleResult> {
    crate::event_transport::wire_event_transport(
        pg,
        distributed,
        subscribers,
        cfg,
        worker,
        audit_key,
    )
    .await
}

/// Wires distributed providers with the canonical non-configurable worker timing.
pub fn wire_distributed(deps: &SharedRuntimeDeps) -> anyhow::Result<DistributedRuntimeDeps> {
    crate::distributed_runtime::wire_distributed(
        deps,
        crate::distributed_runtime::DistributedWorkerConfig::canonical(),
    )
}

/// Builds the settings binding for container-backed integration tests.
pub async fn wire_settings(deps: &SharedRuntimeDeps) -> anyhow::Result<bootstrap::DomainBinding> {
    crate::domains::settings::integration_binding(
        deps,
        crate::domains::settings::SettingsModuleInput::new(
            settings_composition::KeyProviderReadinessInterval::default(),
        ),
    )
    .await
}

/// Builds the identity binding from explicit hermetic values for integration tests.
pub fn wire_identity_with(
    deps: &SharedRuntimeDeps,
    values: IdentityTestValues,
) -> anyhow::Result<bootstrap::DomainBinding> {
    crate::domains::identity::wire_identity_with(deps, values)
}
