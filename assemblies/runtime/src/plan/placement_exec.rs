//! Placement execution projection minted solely from [`super::RuntimePlan`].

use crate::config::{DOMAIN_TRANSPORT_SHARED_URL_ENV, SnapshotConfig};
use anyhow::Context as _;
use assembly_schema::AssemblyDomain;
use secure::DomainHttpEndpoint;
use std::collections::BTreeMap;

#[derive(Clone, PartialEq, Eq)]
enum PlacementState {
    Local,
    Remote {
        endpoint: DomainHttpEndpoint,
        spiffe_identity: Option<String>,
        readiness: runtimeexec::inventory::InventoryPlacementReadiness,
    },
}

/// One domain's placement execution fact.
///
/// Remote state owns the validated endpoint selected by the bootstrap topology resolver. Because
/// the state enum and all fields are private, a remote placement without an endpoint is
/// unrepresentable. Inventory and the live HTTP adapter consume this same typed value.
///
/// INVARIANT: RUNTIME-PLACEMENT-PLAN-EXECUTION-01 { level = "Hard", exec = "native-compile", source = "code", native = "private closed placement state with mandatory secure::DomainHttpEndpoint plus RuntimePlan-only fallible mint" } -- domain placement crosses the composition root only through this plan-derived capability; Local domains compose in-process modules, Remote domains bind outbound contract transport and must not mount on local listeners.
pub(crate) struct PlacementExecutionSpec {
    domain: AssemblyDomain,
    workload: String,
    state: PlacementState,
}

impl PlacementExecutionSpec {
    pub(crate) const fn domain(&self) -> AssemblyDomain {
        self.domain
    }

    pub(crate) fn workload(&self) -> &str {
        &self.workload
    }

    pub(crate) fn endpoint(&self) -> Option<&DomainHttpEndpoint> {
        match &self.state {
            PlacementState::Local => None,
            PlacementState::Remote { endpoint, .. } => Some(endpoint),
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn spiffe_identity(&self) -> Option<&str> {
        match &self.state {
            PlacementState::Local => None,
            PlacementState::Remote {
                spiffe_identity, ..
            } => spiffe_identity.as_deref(),
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn readiness(&self) -> Option<runtimeexec::inventory::InventoryPlacementReadiness> {
        match self.state {
            PlacementState::Local => None,
            PlacementState::Remote { readiness, .. } => Some(readiness),
        }
    }

    pub(crate) const fn is_local(&self) -> bool {
        matches!(self.state, PlacementState::Local)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) const fn is_remote(&self) -> bool {
        matches!(self.state, PlacementState::Remote { .. })
    }

    #[cfg(test)]
    pub(crate) fn remote_for_test(
        domain: AssemblyDomain,
        workload: impl Into<String>,
        endpoint: DomainHttpEndpoint,
    ) -> Self {
        Self {
            domain,
            workload: workload.into(),
            state: PlacementState::Remote {
                endpoint,
                spiffe_identity: None,
                readiness:
                    runtimeexec::inventory::InventoryPlacementReadiness::MtlsSourceUnavailable,
            },
        }
    }
}

/// Validated placement projection that can only be minted from [`super::RuntimePlan`].
///
/// INVARIANT: RUNTIME-PLACEMENT-PLAN-EXECUTION-01 { level = "Hard", exec = "native-compile", source = "code", native = "private closed placement state with mandatory secure::DomainHttpEndpoint plus RuntimePlan-only fallible mint" } -- runtime domain placement and remote transport required-domain set cross the composition root only through this plan-derived capability.
pub(crate) struct PlacementExecutionPlan {
    placements: Vec<PlacementExecutionSpec>,
}

impl PlacementExecutionPlan {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn placements(&self) -> &[PlacementExecutionSpec] {
        &self.placements
    }

    pub(crate) fn is_local(&self, domain: AssemblyDomain) -> bool {
        self.placements
            .iter()
            .find(|spec| spec.domain() == domain)
            .is_some_and(PlacementExecutionSpec::is_local)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn remote_domains(&self) -> impl Iterator<Item = AssemblyDomain> + '_ {
        self.placements
            .iter()
            .filter(|spec| spec.is_remote())
            .map(PlacementExecutionSpec::domain)
    }

    pub(crate) fn remote_targets(
        &self,
    ) -> impl Iterator<Item = (AssemblyDomain, &DomainHttpEndpoint)> + '_ {
        self.placements
            .iter()
            .filter_map(|spec| spec.endpoint().map(|endpoint| (spec.domain(), endpoint)))
    }

    pub(crate) fn inventory_observations(
        &self,
    ) -> Result<
        Vec<runtimeexec::inventory::PlacementObservation>,
        runtimeexec::inventory::InventoryError,
    > {
        self.placements
            .iter()
            .map(|placement| match &placement.state {
                PlacementState::Local => Ok(runtimeexec::inventory::PlacementObservation::local(
                    placement.domain(),
                    placement.workload(),
                )),
                PlacementState::Remote {
                    endpoint,
                    spiffe_identity,
                    readiness,
                } => {
                    let endpoint = runtimeexec::inventory::PlacementEndpoint::from_typed_parts(
                        runtimeexec::inventory::InventoryEndpointScheme::Https,
                        endpoint.host(),
                        endpoint.port().get(),
                    )?;
                    runtimeexec::inventory::PlacementObservation::remote(
                        placement.domain(),
                        placement.workload(),
                        Some(endpoint),
                        spiffe_identity.clone(),
                        *readiness,
                    )
                }
            })
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn from_specs_for_test(placements: Vec<PlacementExecutionSpec>) -> Self {
        Self { placements }
    }
}

pub(super) fn mint(
    plan: &assembly_schema::RuntimePlan,
    assembly_identity: &str,
    topology: bootstrap::Topology,
    config: SnapshotConfig<'_>,
) -> anyhow::Result<PlacementExecutionPlan> {
    let declared = plan
        .placement_plans()
        .iter()
        .map(|placement| {
            (
                placement.domain(),
                placement.workload().to_owned(),
                placement.workload() == assembly_identity,
            )
        })
        .collect::<Vec<_>>();
    let remote_domains = declared
        .iter()
        .filter(|(_, _, local)| !local)
        .map(|(domain, _, _)| domain.as_str().to_ascii_uppercase())
        .collect::<Vec<_>>();

    if remote_domains.is_empty() {
        return Ok(PlacementExecutionPlan {
            placements: declared
                .into_iter()
                .map(|(domain, workload, _)| PlacementExecutionSpec {
                    domain,
                    workload,
                    state: PlacementState::Local,
                })
                .collect(),
        });
    }

    let mut per_domain = BTreeMap::new();
    for domain in &remote_domains {
        let env = crate::config::domain_transport_url_env(domain);
        if let Some(raw) = config.value(&env) {
            let endpoint = DomainHttpEndpoint::parse(raw)
                .with_context(|| format!("{env} is not a valid domain HTTP endpoint"))?;
            per_domain.insert(domain.clone(), endpoint);
        }
    }
    let shared_endpoint = config
        .value(DOMAIN_TRANSPORT_SHARED_URL_ENV)
        .map(|raw| {
            DomainHttpEndpoint::parse(raw).with_context(|| {
                format!("{DOMAIN_TRANSPORT_SHARED_URL_ENV} is not a valid domain HTTP endpoint")
            })
        })
        .transpose()?;
    let transport = bootstrap::DomainTransportConfig::new(per_domain, shared_endpoint);
    let required = remote_domains
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let resolved = bootstrap::domaintransport::resolve(topology, transport, &required)?;
    let bootstrap::ResolvedDomainTransport::Remote {
        per_domain: mut endpoints,
    } = resolved
    else {
        anyhow::bail!(
            "demo topology does not support remote-placed domains; remotes={}",
            remote_domains.join(",")
        );
    };

    let placements = declared
        .into_iter()
        .map(|(domain, workload, local)| -> anyhow::Result<_> {
            let state = if local {
                PlacementState::Local
            } else {
                let key = domain.as_str().to_ascii_uppercase();
                let endpoint = endpoints.remove(&key).ok_or_else(|| {
                    anyhow::anyhow!(
                        "resolved domain transport omitted required placement domain {key}"
                    )
                })?;
                PlacementState::Remote {
                    endpoint,
                    spiffe_identity: None,
                    readiness:
                        runtimeexec::inventory::InventoryPlacementReadiness::MtlsSourceUnavailable,
                }
            };
            Ok(PlacementExecutionSpec {
                domain,
                workload,
                state,
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(PlacementExecutionPlan { placements })
}
