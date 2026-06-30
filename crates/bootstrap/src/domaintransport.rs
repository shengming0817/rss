//! domaintransport —— topology-gated synchronous domain RPC transport selection.
//!
//! This resolver is intentionally pure and adapter-free, mirroring [`crate::eventtransport`] while
//! using a separate typed config. Event transport URLs must not be reusable as synchronous domain
//! transport URLs by accident.

use std::collections::BTreeMap;

use crate::topology::Topology;

/// Per-domain synchronous transport endpoint URL.
///
/// `Debug` / `Display` redact userinfo; raw access is limited to [`DomainTransportUrl::expose`]
/// for composition roots that construct a future remote HTTP/RPC adapter.
#[derive(Clone, PartialEq, Eq)]
pub struct DomainTransportUrl(String);

impl DomainTransportUrl {
    /// Construct from the raw endpoint URL.
    pub fn new(url: impl Into<String>) -> Self {
        Self(url.into())
    }

    /// Expose the raw URL for adapter connection only. Do not log this value.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Render for diagnostics. Drops `?query`/`#fragment` first (an endpoint URL's diagnostic value
    /// is `scheme://host:port/path`; credentials may also ride in `?token=`/`#secret`, and
    /// [`secure::redact_url_credentials`] only strips authority userinfo, not query/fragment), then
    /// redacts authority userinfo. Raw value stays available via [`expose`](Self::expose) for the
    /// adapter connection only (#332 F5).
    fn render_redacted(&self) -> String {
        let without_query_fragment = self.0.split(['?', '#']).next().unwrap_or(&self.0);
        secure::redact_url_credentials(without_query_fragment).to_string()
    }
}

impl std::fmt::Debug for DomainTransportUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DomainTransportUrl({})", self.render_redacted())
    }
}

impl std::fmt::Display for DomainTransportUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.render_redacted())
    }
}

/// Typed config for synchronous domain transport endpoints.
#[derive(Debug, Default)]
pub struct DomainTransportConfig {
    per_domain_urls: BTreeMap<String, DomainTransportUrl>,
    shared_url: Option<DomainTransportUrl>,
}

impl DomainTransportConfig {
    /// Construct from per-domain URL map plus optional shared fallback. Domain keys normalize to
    /// uppercase to match `RSS_<DOMAIN>_DOMAIN_TRANSPORT_URL` style env naming.
    pub fn new(
        per_domain_urls: BTreeMap<String, DomainTransportUrl>,
        shared_url: Option<DomainTransportUrl>,
    ) -> Self {
        Self {
            per_domain_urls: per_domain_urls
                .into_iter()
                .map(|(domain, url)| (domain.to_uppercase(), url))
                .collect(),
            shared_url,
        }
    }

    /// Add one per-domain endpoint URL; domain is normalized to uppercase.
    #[must_use]
    pub fn with_domain_url(mut self, domain: &str, url: DomainTransportUrl) -> Self {
        self.per_domain_urls.insert(domain.to_uppercase(), url);
        self
    }
}

/// Resolved synchronous transport decision.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResolvedDomainTransport {
    /// Demo topology: composition root uses the existing in-process domain transport seam.
    InProc,
    /// Durable topology: per-domain remote endpoints. This PR only resolves the topology decision;
    /// it does not introduce a remote HTTP client adapter.
    Remote {
        /// Required domains mapped to validated endpoint URLs.
        per_domain: BTreeMap<String, DomainTransportUrl>,
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
    MissingEndpointUrl {
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
        Topology::DurableShared => resolve_remote(&cfg, required_domains, cfg.shared_url.as_ref()),
        Topology::DurableIsolated => {
            if cfg.shared_url.is_some() {
                return Err(DomainTransportResolveError::IsolatedFallbackForbidden);
            }
            resolve_remote(&cfg, required_domains, None)
        }
    }
}

fn resolve_remote(
    cfg: &DomainTransportConfig,
    required_domains: &[&str],
    fallback: Option<&DomainTransportUrl>,
) -> Result<ResolvedDomainTransport, DomainTransportResolveError> {
    let mut per_domain = BTreeMap::new();
    for domain in required_domains {
        let key = domain.to_uppercase();
        let url = cfg.per_domain_urls.get(&key).or(fallback).ok_or(
            DomainTransportResolveError::MissingEndpointUrl {
                domain: key.clone(),
            },
        )?;
        per_domain.insert(key, url.clone());
    }
    Ok(ResolvedDomainTransport::Remote { per_domain })
}

#[cfg(test)]
mod tests {
    use super::{
        DomainTransportConfig, DomainTransportResolveError, DomainTransportUrl,
        ResolvedDomainTransport, Topology, resolve,
    };
    use crate::eventtransport::{AmqpUrl, ResolvedTransport, TransportConfig};
    use std::collections::BTreeMap;

    const URL_IDENTITY: &str = "https://idu:idp@identity.internal/rpc";
    const URL_SHARED: &str = "https://su:sp@gateway.internal/rpc";
    const URL_QUERY_FRAGMENT_CREDS: &str =
        "https://identity.internal/rpc?token=supersecret#frag=topsecret";

    fn cfg_with(domain_key: &str, url: &str) -> DomainTransportConfig {
        let mut m = BTreeMap::new();
        m.insert(domain_key.to_string(), DomainTransportUrl::new(url));
        DomainTransportConfig::new(m, None)
    }

    #[allow(clippy::unwrap_used, clippy::panic)]
    fn remote_map(
        got: Result<ResolvedDomainTransport, DomainTransportResolveError>,
    ) -> BTreeMap<String, DomainTransportUrl> {
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
        assert_eq!(map["IDENTITY"], DomainTransportUrl::new(URL_IDENTITY));
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
            Err(DomainTransportResolveError::MissingEndpointUrl { domain }) if domain == "IDENTITY"
        ));
    }

    #[test]
    fn durable_shared_falls_back_to_shared_url() {
        let cfg =
            DomainTransportConfig::new(BTreeMap::new(), Some(DomainTransportUrl::new(URL_SHARED)));
        let map = remote_map(resolve(
            Topology::DurableShared,
            cfg,
            &["identity", "audit"],
        ));
        assert_eq!(map["IDENTITY"], DomainTransportUrl::new(URL_SHARED));
        assert_eq!(map["AUDIT"], DomainTransportUrl::new(URL_SHARED));
    }

    #[test]
    fn per_domain_url_preferred_over_shared() {
        let cfg = DomainTransportConfig::default()
            .with_domain_url("identity", DomainTransportUrl::new(URL_IDENTITY));
        let cfg = DomainTransportConfig::new(
            cfg.per_domain_urls,
            Some(DomainTransportUrl::new(URL_SHARED)),
        );
        let map = remote_map(resolve(Topology::DurableShared, cfg, &["identity"]));
        assert_eq!(map["IDENTITY"], DomainTransportUrl::new(URL_IDENTITY));
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
            .with_domain_url("identity", DomainTransportUrl::new(URL_IDENTITY))
            .with_domain_url(
                "audit",
                DomainTransportUrl::new("https://audit.internal/rpc"),
            );
        let map = remote_map(resolve(
            Topology::DurableIsolated,
            cfg,
            &["identity", "audit"],
        ));
        assert_eq!(map["IDENTITY"], DomainTransportUrl::new(URL_IDENTITY));
    }

    #[test]
    fn isolated_missing_per_domain_fails_closed_no_fallback() {
        let cfg = DomainTransportConfig::default()
            .with_domain_url("identity", DomainTransportUrl::new(URL_IDENTITY));
        let got = resolve(Topology::DurableIsolated, cfg, &["identity", "audit"]);
        assert!(matches!(
            got,
            Err(DomainTransportResolveError::MissingEndpointUrl { domain }) if domain == "AUDIT"
        ));
    }

    #[test]
    fn isolated_with_shared_url_fails_closed() {
        let cfg =
            DomainTransportConfig::new(BTreeMap::new(), Some(DomainTransportUrl::new(URL_SHARED)));
        let got = resolve(Topology::DurableIsolated, cfg, &["identity"]);
        assert!(matches!(
            got,
            Err(DomainTransportResolveError::IsolatedFallbackForbidden)
        ));
    }

    #[test]
    #[allow(clippy::disallowed_methods)]
    fn credentials_not_in_domain_transport_url_debug_or_display() {
        let url = DomainTransportUrl::new(URL_IDENTITY);
        let dbg = format!("{url:?}");
        let disp = format!("{url}");
        for rendered in [&dbg, &disp] {
            assert!(
                rendered.contains("<redacted>"),
                "expected redaction in {rendered}"
            );
            assert!(!rendered.contains("idu"), "leaked user in {rendered}");
            assert!(!rendered.contains("idp"), "leaked password in {rendered}");
        }
        assert_eq!(url.expose(), URL_IDENTITY);
    }

    #[test]
    #[allow(clippy::disallowed_methods)]
    fn query_or_fragment_credentials_not_in_debug_or_display() {
        // redact_url_credentials 只剥 authority userinfo；token 内联在 query/fragment 时仅靠它会泄漏，
        // DomainTransportUrl 渲染前须先裁掉 query/fragment（#332 F5）。
        let url = DomainTransportUrl::new(URL_QUERY_FRAGMENT_CREDS);
        let dbg = format!("{url:?}");
        let disp = format!("{url}");
        for rendered in [&dbg, &disp] {
            assert!(
                !rendered.contains("supersecret"),
                "leaked query token in {rendered}"
            );
            assert!(
                !rendered.contains("topsecret"),
                "leaked fragment secret in {rendered}"
            );
            assert!(!rendered.contains('?'), "query retained in {rendered}");
            assert!(!rendered.contains('#'), "fragment retained in {rendered}");
        }
        // 原始值仍可经 expose 取回供 adapter 连接（裁剪只发生在渲染侧）。
        assert_eq!(url.expose(), URL_QUERY_FRAGMENT_CREDS);
    }

    #[test]
    fn error_messages_are_redacted_and_actionable() {
        let missing = DomainTransportResolveError::MissingEndpointUrl {
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
        let domain_cfg =
            DomainTransportConfig::new(BTreeMap::new(), Some(DomainTransportUrl::new(URL_SHARED)));
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
