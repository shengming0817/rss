//! domaintransport —— topology-gated synchronous domain RPC transport selection.
//!
//! This resolver is intentionally pure and adapter-free, mirroring [`crate::eventtransport`] while
//! using a separate typed config. Event transport URLs must not be reusable as synchronous domain
//! transport URLs by accident.

use std::collections::BTreeMap;

use crate::topology::Topology;
use secure::DomainHttpEndpoint;

/// Typed config for synchronous domain transport endpoints.
#[derive(Debug, Default)]
pub struct DomainTransportConfig {
    per_domain_endpoints: BTreeMap<String, DomainHttpEndpoint>,
    shared_endpoint: Option<DomainHttpEndpoint>,
}

impl DomainTransportConfig {
    /// Construct from per-domain endpoint map plus optional shared fallback. Domain keys normalize to
    /// uppercase to match `RSS_<DOMAIN>_DOMAIN_TRANSPORT_URL` style env naming.
    pub fn new(
        per_domain_endpoints: BTreeMap<String, DomainHttpEndpoint>,
        shared_endpoint: Option<DomainHttpEndpoint>,
    ) -> Self {
        Self {
            per_domain_endpoints: per_domain_endpoints
                .into_iter()
                .map(|(domain, endpoint)| (domain.to_uppercase(), endpoint))
                .collect(),
            shared_endpoint,
        }
    }

    /// Add one per-domain endpoint; domain is normalized to uppercase.
    #[must_use]
    pub fn with_domain_endpoint(mut self, domain: &str, endpoint: DomainHttpEndpoint) -> Self {
        self.per_domain_endpoints
            .insert(domain.to_uppercase(), endpoint);
        self
    }
}

/// Resolved synchronous transport decision.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResolvedDomainTransport {
    /// Demo topology: composition root uses the existing in-process domain transport seam.
    InProc,
    /// Durable topology: per-domain remote endpoints.
    Remote {
        /// Required domains mapped to validated endpoints.
        per_domain: BTreeMap<String, DomainHttpEndpoint>,
    },
}

/// Domain transport topology resolution failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DomainTransportResolveError {
    /// Durable topology lacks a required domain endpoint.
    #[error(
        "durable domain transport requires an endpoint url for domain {domain} (set RSS_{domain}_DOMAIN_TRANSPORT_URL)"
    )]
    MissingEndpoint {
        /// Missing uppercase domain name.
        domain: String,
    },
    /// Isolated topology cannot use the shared endpoint fallback.
    #[error(
        "isolated topology must not be configured with a shared domain transport url (RSS_DOMAIN_TRANSPORT_URL)"
    )]
    IsolatedFallbackForbidden,
}

/// Resolve the synchronous domain transport decision from the shared deployment [`Topology`].
///
/// - [`Topology::Demo`] -> [`ResolvedDomainTransport::InProc`].
/// - [`Topology::DurableShared`] -> per-domain URL, falling back to the shared URL.
/// - [`Topology::DurableIsolated`] -> per-domain URL only; shared fallback is a fail-closed error.
pub fn resolve(
    topo: Topology,
    cfg: DomainTransportConfig,
    required_domains: &[&str],
) -> Result<ResolvedDomainTransport, DomainTransportResolveError> {
    match topo {
        Topology::Demo => Ok(ResolvedDomainTransport::InProc),
        Topology::DurableShared => {
            resolve_remote(&cfg, required_domains, cfg.shared_endpoint.as_ref())
        }
        Topology::DurableIsolated => {
            if cfg.shared_endpoint.is_some() {
                return Err(DomainTransportResolveError::IsolatedFallbackForbidden);
            }
            resolve_remote(&cfg, required_domains, None)
        }
    }
}

fn resolve_remote(
    cfg: &DomainTransportConfig,
    required_domains: &[&str],
    fallback: Option<&DomainHttpEndpoint>,
) -> Result<ResolvedDomainTransport, DomainTransportResolveError> {
    let mut per_domain = BTreeMap::new();
    for domain in required_domains {
        let key = domain.to_uppercase();
        let endpoint = cfg.per_domain_endpoints.get(&key).or(fallback).ok_or(
            DomainTransportResolveError::MissingEndpoint {
                domain: key.clone(),
            },
        )?;
        per_domain.insert(key, endpoint.clone());
    }
    Ok(ResolvedDomainTransport::Remote { per_domain })
}

#[cfg(test)]
mod tests {
    use super::{
        DomainTransportConfig, DomainTransportResolveError, ResolvedDomainTransport, Topology,
        resolve,
    };
    use crate::eventtransport::{AmqpUrl, ResolvedTransport, TransportConfig};
    use secure::DomainHttpEndpoint;
    use std::collections::BTreeMap;

    const URL_IDENTITY: &str = "https://identity.internal/rpc";
    const URL_SHARED: &str = "https://gateway.internal/rpc";

    #[allow(clippy::expect_used)] // reason: test-only helper parses fixed valid HTTPS fixture constants
    fn endpoint(raw: &str) -> DomainHttpEndpoint {
        DomainHttpEndpoint::parse(raw).expect("valid domain HTTP endpoint fixture")
    }

    fn cfg_with(domain_key: &str, url: &str) -> DomainTransportConfig {
        let mut m = BTreeMap::new();
        m.insert(domain_key.to_string(), endpoint(url));
        DomainTransportConfig::new(m, None)
    }

    #[allow(clippy::unwrap_used, clippy::panic)]
    fn remote_map(
        got: Result<ResolvedDomainTransport, DomainTransportResolveError>,
    ) -> BTreeMap<String, DomainHttpEndpoint> {
        match got.unwrap() {
            ResolvedDomainTransport::Remote { per_domain } => per_domain,
            other => panic!("expected Remote, got {other:?}"),
        }
    }

    #[test]
    fn demo_resolves_to_in_proc() {
        let got = resolve(
            Topology::Demo,
            DomainTransportConfig::default(),
            &["identity"],
        );
        assert!(matches!(got, Ok(ResolvedDomainTransport::InProc)));
    }

    #[test]
    fn durable_shared_resolves_per_domain_url() {
        let map = remote_map(resolve(
            Topology::DurableShared,
            cfg_with("IDENTITY", URL_IDENTITY),
            &["identity"],
        ));
        assert_eq!(map["IDENTITY"], endpoint(URL_IDENTITY));
    }

    #[test]
    fn durable_shared_missing_url_fails_closed() {
        let got = resolve(
            Topology::DurableShared,
            DomainTransportConfig::default(),
            &["identity"],
        );
        assert!(matches!(
            got,
            Err(DomainTransportResolveError::MissingEndpoint { domain }) if domain == "IDENTITY"
        ));
    }

    #[test]
    fn durable_shared_falls_back_to_shared_url() {
        let cfg = DomainTransportConfig::new(BTreeMap::new(), Some(endpoint(URL_SHARED)));
        let map = remote_map(resolve(
            Topology::DurableShared,
            cfg,
            &["identity", "audit"],
        ));
        assert_eq!(map["IDENTITY"], endpoint(URL_SHARED));
        assert_eq!(map["AUDIT"], endpoint(URL_SHARED));
    }

    #[test]
    fn per_domain_url_preferred_over_shared() {
        let cfg = DomainTransportConfig::default()
            .with_domain_endpoint("identity", endpoint(URL_IDENTITY));
        let cfg = DomainTransportConfig::new(cfg.per_domain_endpoints, Some(endpoint(URL_SHARED)));
        let map = remote_map(resolve(Topology::DurableShared, cfg, &["identity"]));
        assert_eq!(map["IDENTITY"], endpoint(URL_IDENTITY));
    }

    #[test]
    fn required_domains_case_insensitive() {
        let got = resolve(
            Topology::DurableShared,
            cfg_with("identity", URL_IDENTITY),
            &["IdEnTiTy"],
        );
        assert!(matches!(got, Ok(ResolvedDomainTransport::Remote { .. })));
    }

    #[test]
    fn isolated_requires_per_domain_urls() {
        let cfg = DomainTransportConfig::default()
            .with_domain_endpoint("identity", endpoint(URL_IDENTITY))
            .with_domain_endpoint("audit", endpoint("https://audit.internal/rpc"));
        let map = remote_map(resolve(
            Topology::DurableIsolated,
            cfg,
            &["identity", "audit"],
        ));
        assert_eq!(map["IDENTITY"], endpoint(URL_IDENTITY));
    }

    #[test]
    fn isolated_missing_per_domain_fails_closed_no_fallback() {
        let cfg = DomainTransportConfig::default()
            .with_domain_endpoint("identity", endpoint(URL_IDENTITY));
        let got = resolve(Topology::DurableIsolated, cfg, &["identity", "audit"]);
        assert!(matches!(
            got,
            Err(DomainTransportResolveError::MissingEndpoint { domain }) if domain == "AUDIT"
        ));
    }

    #[test]
    fn isolated_with_shared_url_fails_closed() {
        let cfg = DomainTransportConfig::new(BTreeMap::new(), Some(endpoint(URL_SHARED)));
        let got = resolve(Topology::DurableIsolated, cfg, &["identity"]);
        assert!(matches!(
            got,
            Err(DomainTransportResolveError::IsolatedFallbackForbidden)
        ));
    }

    #[test]
    fn error_messages_are_redacted_and_actionable() {
        let missing = DomainTransportResolveError::MissingEndpoint {
            domain: "IDENTITY".to_string(),
        };
        assert_eq!(
            missing.to_string(),
            "durable domain transport requires an endpoint url for domain IDENTITY (set RSS_IDENTITY_DOMAIN_TRANSPORT_URL)"
        );
        assert_eq!(
            DomainTransportResolveError::IsolatedFallbackForbidden.to_string(),
            "isolated topology must not be configured with a shared domain transport url (RSS_DOMAIN_TRANSPORT_URL)"
        );
    }

    #[test]
    #[allow(clippy::panic)]
    fn shares_topology_semantics_with_eventtransport_but_not_config_types() {
        let domain_cfg = DomainTransportConfig::new(BTreeMap::new(), Some(endpoint(URL_SHARED)));
        let event_url = match AmqpUrl::parse(
            "amqps://user:pass@broker/shared",
            secure::PlaintextEndpointPolicy::Deny,
        ) {
            Ok(url) => url,
            Err(err) => panic!("valid amqps url: {err}"),
        };
        let event_cfg = TransportConfig::new(BTreeMap::new(), Some(event_url));

        let domain = resolve(Topology::DurableShared, domain_cfg, &["identity"]);
        let events =
            crate::eventtransport::resolve(Topology::DurableShared, event_cfg, &["identity"]);

        assert!(matches!(
            domain,
            Ok(ResolvedDomainTransport::Remote { ref per_domain }) if per_domain.contains_key("IDENTITY")
        ));
        assert!(matches!(
            events,
            Ok(ResolvedTransport::Durable { ref per_domain }) if per_domain.contains_key("IDENTITY")
        ));
    }
}
