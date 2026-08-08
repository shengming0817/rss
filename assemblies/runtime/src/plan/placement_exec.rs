//! Placement execution projection minted solely from [`super::RuntimePlan`].

use crate::config::{DOMAIN_TRANSPORT_SHARED_URL_ENV, SnapshotConfig};
use assembly_schema::AssemblyDomain;

const TOPOLOGY_ENV: &str = "RSS_TOPOLOGY";

/// Exclusive local composition vs remote contract-transport binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PlacementMode {
    Local,
    Remote,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlacementEndpoint {
    scheme: String,
    host: String,
    port: u16,
}

impl PlacementEndpoint {
    #[allow(dead_code)] // reason: inventory DTO accessors for remote posture projection.
    pub(crate) fn scheme(&self) -> &str {
        &self.scheme
    }

    #[allow(dead_code)] // reason: inventory DTO accessors for remote posture projection.
    pub(crate) fn host(&self) -> &str {
        &self.host
    }

    #[allow(dead_code)] // reason: inventory DTO accessors for remote posture projection.
    pub(crate) const fn port(&self) -> u16 {
        self.port
    }
}

/// One domain's placement execution fact.
///
/// Remote `endpoint` is minted from the same URL family as outbound transport resolve
/// (per-domain first; `RSS_DOMAIN_TRANSPORT_URL` shared fallback only when
/// `RSS_TOPOLOGY=durable-shared`). Mint-time remote `readiness` is fail-closed until the live
/// outbound transport-owned readiness sampler is published.
///
/// `spiffe_identity` is reserved for a future peer (server) SPIFFE projection; mint does not
/// store the local outbound client SPIFFE id here (that material stays on the mTLS policy /
/// `RSS_DOMAIN_TRANSPORT_MTLS_LOCAL_SPIFFE_ID` path). Until peer allow-set projection lands with
/// tests, this field remains `None`.
///
/// INVARIANT: RUNTIME-PLACEMENT-PLAN-EXECUTION-01 { level = "Hard", exec = "native-compile", source = "code", native = "private execution fields plus RuntimePlan-only mint and exclusive Local composition or Remote transport binding" } -- domain placement crosses the composition root only through this plan-derived capability; Local domains compose in-process modules, Remote domains bind outbound contract transport and must not mount on local listeners.
pub(crate) struct PlacementExecutionSpec {
    domain: AssemblyDomain,
    mode: PlacementMode,
    #[allow(dead_code)] // reason: inventory DTO field; read via workload() for posture projection.
    workload: String,
    endpoint: Option<PlacementEndpoint>,
    spiffe_identity: Option<String>,
    readiness: Option<runtimeexec::inventory::InventoryPlacementReadiness>,
}

impl PlacementExecutionSpec {
    pub(crate) const fn domain(&self) -> AssemblyDomain {
        self.domain
    }

    #[allow(dead_code)] // reason: inventory DTO accessors for remote posture projection.
    pub(crate) const fn mode(&self) -> PlacementMode {
        self.mode
    }

    #[allow(dead_code)] // reason: inventory DTO accessors for remote posture projection.
    pub(crate) fn workload(&self) -> &str {
        &self.workload
    }

    #[allow(dead_code)] // reason: inventory DTO accessors for remote posture projection.
    pub(crate) fn endpoint(&self) -> Option<&PlacementEndpoint> {
        self.endpoint.as_ref()
    }

    #[allow(dead_code)] // reason: inventory DTO accessors for remote posture projection.
    pub(crate) fn spiffe_identity(&self) -> Option<&str> {
        self.spiffe_identity.as_deref()
    }

    #[allow(dead_code)] // reason: inventory DTO accessors for remote posture projection.
    pub(crate) fn readiness(&self) -> Option<runtimeexec::inventory::InventoryPlacementReadiness> {
        self.readiness
    }

    pub(crate) const fn is_local(&self) -> bool {
        matches!(self.mode, PlacementMode::Local)
    }

    pub(crate) const fn is_remote(&self) -> bool {
        matches!(self.mode, PlacementMode::Remote)
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        domain: AssemblyDomain,
        mode: PlacementMode,
        workload: impl Into<String>,
    ) -> Self {
        Self {
            domain,
            mode,
            workload: workload.into(),
            endpoint: None,
            spiffe_identity: None,
            readiness: mode.is_remote().then_some(
                runtimeexec::inventory::InventoryPlacementReadiness::MtlsSourceUnavailable,
            ),
        }
    }
}

impl PlacementMode {
    pub(crate) const fn is_remote(self) -> bool {
        matches!(self, Self::Remote)
    }
}

/// Validated placement projection that can only be minted from [`super::RuntimePlan`].
///
/// INVARIANT: RUNTIME-PLACEMENT-PLAN-EXECUTION-01 { level = "Hard", exec = "native-compile", source = "code", native = "private execution fields plus RuntimePlan-only mint and exclusive Local composition or Remote transport binding" } -- runtime domain placement and remote transport required-domain set cross the composition root only through this plan-derived capability.
pub(crate) struct PlacementExecutionPlan {
    placements: Vec<PlacementExecutionSpec>,
}

impl PlacementExecutionPlan {
    #[allow(dead_code)] // reason: inventory DTO accessors for remote posture projection.
    pub(crate) fn placements(&self) -> &[PlacementExecutionSpec] {
        &self.placements
    }

    pub(crate) fn is_local(&self, domain: AssemblyDomain) -> bool {
        self.placements
            .iter()
            .find(|spec| spec.domain() == domain)
            .is_some_and(PlacementExecutionSpec::is_local)
    }

    pub(crate) fn remote_domains(&self) -> impl Iterator<Item = AssemblyDomain> + '_ {
        self.placements
            .iter()
            .filter(|spec| spec.is_remote())
            .map(PlacementExecutionSpec::domain)
    }

    pub(crate) fn inventory_observations(
        &self,
    ) -> Result<
        Vec<runtimeexec::inventory::PlacementObservation>,
        runtimeexec::inventory::InventoryError,
    > {
        self.placements
            .iter()
            .map(|placement| match placement.mode() {
                PlacementMode::Local => Ok(runtimeexec::inventory::PlacementObservation::local(
                    placement.domain(),
                    placement.workload(),
                )),
                PlacementMode::Remote => {
                    let endpoint = placement
                        .endpoint()
                        .map(|endpoint| {
                            let scheme = match endpoint.scheme() {
                                "https" => runtimeexec::inventory::InventoryEndpointScheme::Https,
                                _ => return Err(runtimeexec::inventory::InventoryError::Endpoint),
                            };
                            runtimeexec::inventory::PlacementEndpoint::from_typed_parts(
                                scheme,
                                endpoint.host(),
                                endpoint.port(),
                            )
                        })
                        .transpose()?;
                    let readiness = placement.readiness().unwrap_or(
                        runtimeexec::inventory::InventoryPlacementReadiness::MtlsSourceUnavailable,
                    );
                    runtimeexec::inventory::PlacementObservation::remote(
                        placement.domain(),
                        placement.workload(),
                        endpoint,
                        placement.spiffe_identity().map(str::to_owned),
                        readiness,
                    )
                }
            })
            .collect()
    }

    pub(crate) fn reject_remote_on_local_listeners(
        &self,
        listeners: &super::ListenerExecutionPlan,
    ) -> anyhow::Result<()> {
        for listener in listeners.listeners() {
            for domain in listener.domains() {
                if !self.is_local(*domain) {
                    let domain_name = domain.as_str();
                    let env = format!(
                        "RSS_{}_DOMAIN_PLACEMENT_WORKLOAD",
                        domain_name.to_ascii_uppercase()
                    );
                    anyhow::bail!(
                        "remote-placed domain '{domain_name}' cannot mount on local listener '{}'; set {env} to this assembly identity, or remove '{domain_name}' from the listener",
                        listener.id(),
                    );
                }
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn from_specs_for_test(placements: Vec<PlacementExecutionSpec>) -> Self {
        Self { placements }
    }
}

pub(super) fn mint(
    plan: &assembly_schema::RuntimePlan,
    assembly_identity: &str,
    config: SnapshotConfig<'_>,
) -> PlacementExecutionPlan {
    let topology = config
        .value(TOPOLOGY_ENV)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .and_then(|raw| crate::event_transport::parse_topology(raw).ok());
    let placements = plan
        .placement_plans()
        .iter()
        .map(|placement| {
            let domain = placement.domain();
            let workload = placement.workload().to_owned();
            let mode = if workload == assembly_identity {
                PlacementMode::Local
            } else {
                PlacementMode::Remote
            };
            let (endpoint, readiness) = if mode.is_remote() {
                let endpoint = resolve_remote_endpoint(domain, topology, config);
                // Remote seed is fail-closed until the local outbound mTLS sampler is published.
                (
                    endpoint,
                    Some(
                        runtimeexec::inventory::InventoryPlacementReadiness::MtlsSourceUnavailable,
                    ),
                )
            } else {
                (None, None)
            };
            PlacementExecutionSpec {
                domain,
                mode,
                workload,
                endpoint,
                spiffe_identity: None,
                readiness,
            }
        })
        .collect();
    PlacementExecutionPlan { placements }
}

fn resolve_remote_endpoint(
    domain: AssemblyDomain,
    topology: Option<bootstrap::Topology>,
    config: SnapshotConfig<'_>,
) -> Option<PlacementEndpoint> {
    let url_env = crate::config::domain_transport_url_env(domain.as_str());
    if let Some(endpoint) = config
        .value(&url_env)
        .and_then(parse_endpoint_without_credentials)
    {
        return Some(endpoint);
    }
    // Mirror bootstrap::domaintransport::resolve: shared URL only for DurableShared.
    if matches!(topology, Some(bootstrap::Topology::DurableShared)) {
        return config
            .value(DOMAIN_TRANSPORT_SHARED_URL_ENV)
            .and_then(parse_endpoint_without_credentials);
    }
    None
}

/// Parse a remote peer endpoint for inventory posture.
///
/// Aligns with `httpd::parse_target_endpoint`: `https` only; reject userinfo, query, and
/// fragment (return `None` — do not silently strip credentials into host/port).
fn parse_endpoint_without_credentials(raw: &str) -> Option<PlacementEndpoint> {
    let parsed = reqwest::Url::parse(raw.trim()).ok()?;
    if parsed.scheme() != "https" {
        return None;
    }
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return None;
    }
    let host = parsed.host_str()?.to_owned();
    let port = parsed.port_or_known_default()?;
    Some(PlacementEndpoint {
        scheme: "https".to_owned(),
        host,
        port,
    })
}
