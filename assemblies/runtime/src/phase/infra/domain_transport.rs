//! Placement-owned outbound domain transport construction.

use crate::config::{ServingConfigMapper, domain_transport_mtls_allow_set_env};
use crate::routes;
use crate::support::SystemClock;
use anyhow::Context as _;
use bootstrap::DomainModuleResult;
use diport::{DynManagedResource, ManagedResource, ShutdownError};
use primitives::{HealthCheck, HealthStatus, ProbeName};
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
    placement: &crate::plan::PlacementExecutionPlan,
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<Vec<httpd::DomainHttpTargetConfig>> {
    let mut targets = Vec::new();
    for (domain, endpoint) in placement.remote_targets() {
        let domain = domain.as_str().to_ascii_uppercase();
        let policy = outbound_mtls_policy_for_domain_from(&domain, &get)?;
        targets.push(
            httpd::DomainHttpTargetConfig::new(&domain, endpoint.clone(), policy)
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
        placement: &crate::plan::PlacementExecutionPlan,
        mapper: &ServingConfigMapper<'_>,
    ) -> anyhow::Result<Self> {
        let config = mapper.config();
        let get = |name: &str| config.value(name).map(str::to_owned);
        let targets = build_domain_transport_targets_from(placement, get)?;
        if targets.is_empty() {
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

pub(crate) trait RuntimeHttpContractTransport:
    distributed::HttpContractTransport + ManagedResource + Clone + Send + Sync + 'static
{
    fn owned_readiness(&self) -> httpd::DomainHttpOwnedReadiness;
}

impl RuntimeHttpContractTransport for httpd::SharedDomainHttpTransport {
    fn owned_readiness(&self) -> httpd::DomainHttpOwnedReadiness {
        httpd::SharedDomainHttpTransport::owned_readiness(self)
    }
}

/// Fail-closed in-process stub used when every domain is Local (no remote transport targets).
#[derive(Clone, Default)]
pub(crate) struct InProcHttpContractTransport;

impl distributed::HttpContractTransport for InProcHttpContractTransport {
    fn dispatch(
        &self,
        _request: distributed::HttpContractRequest,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<
                        distributed::HttpContractResponse,
                        distributed::HttpContractTransportError,
                    >,
                > + Send
                + '_,
        >,
    > {
        Box::pin(async {
            Err(distributed::HttpContractTransportError::new(
                distributed::HttpContractTransportErrorKind::Dispatch,
            ))
        })
    }
}

impl ManagedResource for InProcHttpContractTransport {
    fn name(&self) -> &str {
        "domain-transport-inproc"
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        Ok(())
    }
}

impl RuntimeHttpContractTransport for InProcHttpContractTransport {
    fn owned_readiness(&self) -> httpd::DomainHttpOwnedReadiness {
        httpd::DomainHttpOwnedReadiness::Ready
    }
}

pub(crate) struct DomainTransportRuntimeInner<T> {
    transport: T,
    probe_name: ProbeName,
    mode: distributed::TransportMode,
}

impl<T> DomainTransportRuntimeInner<T>
where
    T: RuntimeHttpContractTransport,
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

    pub(crate) fn dispatch_handle(&self) -> Arc<dyn distributed::HttpContractTransport> {
        Arc::new(distributed::InstrumentedHttpContractTransport::new(
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
    InProc(DomainTransportRuntimeInner<InProcHttpContractTransport>),
}

impl DomainTransportRuntime {
    pub(crate) fn dispatch_handle(&self) -> Arc<dyn distributed::HttpContractTransport> {
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

    pub(crate) fn readiness_sampler(&self) -> runtimeexec::inventory::PlacementReadinessSampler {
        match self {
            Self::Remote(inner) => {
                let transport = inner.transport.clone();
                Arc::new(move || inventory_readiness(transport.owned_readiness()))
            }
            Self::InProc(inner) => {
                let transport = inner.transport.clone();
                Arc::new(move || inventory_readiness(transport.owned_readiness()))
            }
        }
    }
}

fn inventory_readiness(
    readiness: httpd::DomainHttpOwnedReadiness,
) -> runtimeexec::inventory::InventoryPlacementReadiness {
    match readiness {
        httpd::DomainHttpOwnedReadiness::Ready => {
            runtimeexec::inventory::InventoryPlacementReadiness::Ready
        }
        httpd::DomainHttpOwnedReadiness::MtlsSourceUnavailable => {
            runtimeexec::inventory::InventoryPlacementReadiness::MtlsSourceUnavailable
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
    T: RuntimeHttpContractTransport,
{
    pub(crate) fn new(transport: T, name: ProbeName) -> Self {
        Self { transport, name }
    }
}

impl<T> bootstrap::HealthProbe for DomainTransportReadyProbe<T>
where
    T: RuntimeHttpContractTransport,
{
    fn check(&self) -> HealthCheck {
        let readiness = self.transport.owned_readiness();
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
                InProcHttpContractTransport,
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
