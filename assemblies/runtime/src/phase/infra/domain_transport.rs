//! Placement-owned outbound domain transport construction.

use crate::config::{
    DOMAIN_TRANSPORT_SHARED_URL_ENV, ServingConfigMapper, domain_transport_mtls_allow_set_env,
    domain_transport_url_env,
};
use crate::routes;
use crate::support::SystemClock;
use anyhow::Context as _;
use bootstrap::DomainModuleResult;
use diport::{DynManagedResource, ManagedResource, ShutdownError};
use primitives::{HealthCheck, HealthStatus, ProbeName};
use std::collections::BTreeMap;
use std::sync::Arc;

/// SPIFFE Workload API endpoint env var consumed by the upstream `spiffe` source.
pub(crate) const SPIFFE_ENDPOINT_SOCKET_ENV: &str = "SPIFFE_ENDPOINT_SOCKET";
/// Local workload SPIFFE ID expected from the outbound SPIRE source.
pub(crate) const DOMAIN_TRANSPORT_LOCAL_SPIFFE_ID_ENV: &str =
    "RSS_DOMAIN_TRANSPORT_MTLS_LOCAL_SPIFFE_ID";

pub(crate) fn topology_label(topology: bootstrap::Topology) -> &'static str {
    match topology {
        bootstrap::Topology::Demo => "demo",
        bootstrap::Topology::DurableShared => "durable-shared",
        bootstrap::Topology::DurableIsolated => "durable-isolated",
        _ => "unknown",
    }
}

pub(crate) fn required_spiffe_endpoint_from_value(raw: Option<&str>) -> anyhow::Result<String> {
    let raw = raw
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {SPIFFE_ENDPOINT_SOCKET_ENV}"))?;
    let endpoint = raw.trim();
    anyhow::ensure!(
        !endpoint.is_empty(),
        "{SPIFFE_ENDPOINT_SOCKET_ENV} must be a non-empty explicit endpoint"
    );
    anyhow::ensure!(
        endpoint == raw
            && !endpoint.chars().any(char::is_control)
            && !endpoint.chars().any(char::is_whitespace),
        "{SPIFFE_ENDPOINT_SOCKET_ENV} must not contain whitespace or control characters"
    );
    Ok(endpoint.to_owned())
}

fn domain_transport_config_from(
    remote_domains: &[String],
    get: &impl Fn(&str) -> Option<String>,
) -> bootstrap::DomainTransportConfig {
    let mut per_domain = BTreeMap::new();
    for domain in remote_domains {
        let env = domain_transport_url_env(domain);
        if let Some(url) = get(&env) {
            per_domain.insert(domain.clone(), bootstrap::DomainTransportUrl::new(url));
        }
    }
    let shared = get(DOMAIN_TRANSPORT_SHARED_URL_ENV).map(bootstrap::DomainTransportUrl::new);
    bootstrap::DomainTransportConfig::new(per_domain, shared)
}

fn outbound_mtls_policy_for_domain_from(
    domain: &str,
    get: &impl Fn(&str) -> Option<String>,
) -> anyhow::Result<authn::OutboundMtlsPolicy> {
    let local_raw = get(DOMAIN_TRANSPORT_LOCAL_SPIFFE_ID_ENV).ok_or_else(|| {
        anyhow::anyhow!("missing required env var: {DOMAIN_TRANSPORT_LOCAL_SPIFFE_ID_ENV}")
    })?;
    let local = authn::SpiffeId::parse(local_raw.trim())
        .map_err(|e| anyhow::anyhow!("{DOMAIN_TRANSPORT_LOCAL_SPIFFE_ID_ENV} invalid: {e}"))?;
    let allow_env = domain_transport_mtls_allow_set_env(domain);
    let raw_allow_set =
        get(&allow_env).ok_or_else(|| anyhow::anyhow!("missing required env var: {allow_env}"))?;
    let server_allow_set = routes::mtls_allow_set_from_csv_for_env(&raw_allow_set, &allow_env)?;
    let trust_domain_names = server_allow_set
        .iter()
        .map(|id| id.trust_domain().as_str().to_owned())
        .collect::<Vec<_>>();
    let trust_domains = authn::MtlsTrustDomainAllowSet::new(trust_domain_names)
        .map_err(|e| anyhow::anyhow!("{allow_env} trust domains invalid: {e}"))?;
    authn::OutboundMtlsPolicy::new(local, server_allow_set, trust_domains)
        .map_err(|e| anyhow::anyhow!("{allow_env} outbound mTLS policy invalid: {e}"))
}

pub(crate) fn build_domain_transport_targets_from(
    topology: bootstrap::Topology,
    remote_domains: &[String],
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<Vec<httpd::DomainHttpTargetConfig>> {
    let cfg = domain_transport_config_from(remote_domains, &get);
    let required_refs = remote_domains
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let resolved = bootstrap::domaintransport::resolve(topology, cfg, &required_refs)
        .context("resolve domain transport topology")?;
    let bootstrap::ResolvedDomainTransport::Remote { per_domain } = resolved else {
        return Ok(Vec::new());
    };
    let mut targets = Vec::with_capacity(per_domain.len());
    for (domain, url) in per_domain {
        let policy = outbound_mtls_policy_for_domain_from(&domain, &get)?;
        targets.push(
            httpd::DomainHttpTargetConfig::new(&domain, url.expose(), policy)
                .with_context(|| format!("build outbound domain transport target {domain}"))?,
        );
    }
    Ok(targets)
}

pub(crate) enum DomainTransportConfig {
    Remote {
        targets: Vec<httpd::DomainHttpTargetConfig>,
        spiffe_endpoint: String,
    },
    InProc,
}

impl DomainTransportConfig {
    pub(crate) fn from_placement(
        topology: bootstrap::Topology,
        placement: &crate::plan::PlacementExecutionPlan,
        mapper: &ServingConfigMapper<'_>,
    ) -> anyhow::Result<Self> {
        let config = mapper.config();
        let get = |name: &str| config.value(name).map(str::to_owned);
        let remote_domains = placement
            .remote_domains()
            .map(|domain| domain.as_str().to_ascii_uppercase())
            .collect::<Vec<_>>();
        let targets = build_domain_transport_targets_from(topology, &remote_domains, get)?;
        if targets.is_empty() {
            // Demo (and any topology that resolves to InProc) must not silently collapse Remote
            // placements into the InProc stub — fail closed when remotes were declared.
            if !remote_domains.is_empty() {
                if matches!(topology, bootstrap::Topology::Demo) {
                    anyhow::bail!(
                        "demo topology does not support remote-placed domains; remotes={}",
                        remote_domains.join(",")
                    );
                }
                anyhow::bail!(
                    "remote-placed domains require outbound transport targets (topology={}); remotes={}",
                    topology_label(topology),
                    remote_domains.join(",")
                );
            }
            return Ok(Self::InProc);
        }
        let spiffe_endpoint =
            required_spiffe_endpoint_from_value(config.value(SPIFFE_ENDPOINT_SOCKET_ENV))?;
        Ok(Self::Remote {
            targets,
            spiffe_endpoint,
        })
    }
}

pub(crate) trait RuntimeDomainTransport:
    distributed::DomainTransport + ManagedResource + Clone + Send + Sync + 'static
{
    fn readiness(&self) -> httpd::DomainHttpReadiness;
}

impl RuntimeDomainTransport for httpd::SharedDomainHttpTransport {
    fn readiness(&self) -> httpd::DomainHttpReadiness {
        httpd::SharedDomainHttpTransport::readiness(self)
    }
}

/// Fail-closed in-process stub used when every domain is Local (no remote transport targets).
#[derive(Clone, Default)]
pub(crate) struct InProcDomainTransport;

impl distributed::DomainTransport for InProcDomainTransport {
    fn dispatch(
        &self,
        _request: distributed::DomainRequest,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<distributed::DomainResponse, distributed::DomainTransportError>,
                > + Send
                + '_,
        >,
    > {
        Box::pin(async {
            Err(distributed::DomainTransportError::new(
                distributed::DomainTransportErrorKind::Dispatch,
            ))
        })
    }
}

impl ManagedResource for InProcDomainTransport {
    fn name(&self) -> &str {
        "domain-transport-inproc"
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        Ok(())
    }
}

impl RuntimeDomainTransport for InProcDomainTransport {
    fn readiness(&self) -> httpd::DomainHttpReadiness {
        httpd::DomainHttpReadiness::Ready
    }
}

pub(crate) struct DomainTransportRuntimeInner<T> {
    transport: T,
    probe_name: ProbeName,
    mode: distributed::TransportMode,
}

impl<T> DomainTransportRuntimeInner<T>
where
    T: RuntimeDomainTransport,
{
    pub(crate) fn new(
        transport: T,
        probe_name: ProbeName,
        mode: distributed::TransportMode,
    ) -> Self {
        Self {
            transport,
            probe_name,
            mode,
        }
    }

    pub(crate) fn dispatch_handle(&self) -> Arc<dyn distributed::DomainTransport> {
        Arc::new(distributed::InstrumentedDomainTransport::new(
            self.transport.clone(),
            self.mode,
            Box::new(SystemClock),
        ))
    }

    pub(crate) fn module_result(&self) -> DomainModuleResult {
        DomainModuleResult {
            probes: vec![(
                self.probe_name.clone(),
                Box::new(DomainTransportReadyProbe::new(
                    self.transport.clone(),
                    self.probe_name.clone(),
                )),
            )],
            resources: vec![DynManagedResource::new_box(self.transport.clone())],
            workers: Vec::new(),
        }
    }
}

pub(crate) enum DomainTransportRuntime {
    Remote(DomainTransportRuntimeInner<httpd::SharedDomainHttpTransport>),
    InProc(DomainTransportRuntimeInner<InProcDomainTransport>),
}

impl DomainTransportRuntime {
    pub(crate) fn dispatch_handle(&self) -> Arc<dyn distributed::DomainTransport> {
        match self {
            Self::Remote(inner) => inner.dispatch_handle(),
            Self::InProc(inner) => inner.dispatch_handle(),
        }
    }

    pub(crate) fn module_result(&self) -> DomainModuleResult {
        match self {
            Self::Remote(inner) => inner.module_result(),
            Self::InProc(inner) => inner.module_result(),
        }
    }
}

pub(crate) const DOMAIN_TRANSPORT_READY_PROBE_NAME: &str = "domain_transport_ready";

pub(crate) struct DomainTransportReadyProbe<T> {
    transport: T,
    name: ProbeName,
}

impl<T> DomainTransportReadyProbe<T>
where
    T: RuntimeDomainTransport,
{
    pub(crate) fn new(transport: T, name: ProbeName) -> Self {
        Self { transport, name }
    }
}

impl<T> bootstrap::HealthProbe for DomainTransportReadyProbe<T>
where
    T: RuntimeDomainTransport,
{
    fn check(&self) -> HealthCheck {
        let readiness = self.transport.readiness();
        let status = if readiness.is_ready() {
            HealthStatus::Healthy
        } else {
            HealthStatus::Unhealthy
        };
        HealthCheck::new(self.name.clone(), status, readiness.detail())
    }
}

pub(crate) async fn wire_domain_transport(
    config: DomainTransportConfig,
) -> anyhow::Result<DomainTransportRuntime> {
    let probe_name = ProbeName::parse(DOMAIN_TRANSPORT_READY_PROBE_NAME)
        .context("parse domain_transport_ready probe name")?;
    match config {
        DomainTransportConfig::InProc => Ok(DomainTransportRuntime::InProc(
            DomainTransportRuntimeInner::new(
                InProcDomainTransport,
                probe_name,
                distributed::TransportMode::InProc,
            ),
        )),
        DomainTransportConfig::Remote {
            targets,
            spiffe_endpoint,
        } => {
            let transport = httpd::DomainHttpTransport::from_spire(targets, Some(&spiffe_endpoint))
                .await
                .context("build outbound domain transport mTLS client from captured endpoint")?;
            Ok(DomainTransportRuntime::Remote(
                DomainTransportRuntimeInner::new(
                    httpd::SharedDomainHttpTransport::new(transport),
                    probe_name,
                    distributed::TransportMode::Remote,
                ),
            ))
        }
    }
}
