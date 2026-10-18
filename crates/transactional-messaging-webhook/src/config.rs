use crate::{Error, Publication, SigningKeys, Target};
use ipnet::IpNet;
use rss_request_context::TenantId;
use rss_transactional_messaging::policy::OperationDeadline;
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

/// Bounded publication resources. All limits must be explicitly chosen by the host.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub(crate) concurrent: usize,
    pub(crate) body_bytes: usize,
    pub(crate) addresses: usize,
    pub(crate) headers: usize,
    pub(crate) header_bytes: usize,
}
impl Limits {
    /// Reject zero limits and a Hyper header buffer smaller than 8192 bytes.
    pub fn new(
        concurrent: usize,
        body_bytes: usize,
        addresses: usize,
        headers: usize,
        header_bytes: usize,
    ) -> Result<Self, Error> {
        if concurrent == 0
            || concurrent > tokio::sync::Semaphore::MAX_PERMITS
            || body_bytes == 0
            || addresses == 0
            || headers == 0
            || header_bytes < 8192
        {
            return Err(Error::Config);
        }
        Ok(Self {
            concurrent,
            body_bytes,
            addresses,
            headers,
            header_bytes,
        })
    }
}
/// Host-selected certificate authorities. There is no custom verifier or insecure mode.
#[derive(Clone)]
pub struct TrustRoots(pub(crate) Arc<rustls::ClientConfig>);
impl TrustRoots {
    /// Build an exclusive trust store from DER CA certificates, including private CAs.
    pub fn from_der(certificates: impl IntoIterator<Item = Vec<u8>>) -> Result<Self, Error> {
        let mut roots = rustls::RootCertStore::empty();
        for cert in certificates {
            roots.add(cert.into()).map_err(|_| Error::Config)?;
        }
        if roots.is_empty() {
            return Err(Error::Config);
        }
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| Error::Config)?
        .with_root_certificates(roots)
        .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        config.enable_early_data = false;
        Ok(Self(Arc::new(config)))
    }
}
/// Explicit address snapshot and network allowlist supplied by the host.
/// No implicit public/private network policy or DNS lookup is performed.
pub struct NetworkAccess {
    pub(crate) addresses: Vec<SocketAddr>,
    allowed: Vec<IpNet>,
}
impl NetworkAccess {
    /// Reject empty snapshots, empty allowlists and any address outside the allowlist.
    /// IPv4-mapped IPv6 addresses are normalized before policy evaluation and connection.
    pub fn new(addresses: Vec<SocketAddr>, allowed: Vec<IpNet>) -> Result<Self, Error> {
        let addresses = addresses
            .into_iter()
            .map(|a| SocketAddr::new(normalize(a.ip()), a.port()))
            .collect();
        let value = Self { addresses, allowed };
        if value.addresses.is_empty()
            || value.allowed.is_empty()
            || !value.addresses.iter().all(|a| value.permits(a.ip()))
        {
            return Err(Error::Config);
        }
        Ok(value)
    }
    pub(crate) fn permits(&self, address: IpAddr) -> bool {
        self.allowed
            .iter()
            .any(|network| network.contains(&normalize(address)))
    }
}
fn normalize(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(address, IpAddr::V4),
        _ => address,
    }
}
/// Host authorization/configuration input, never proof of HTTP acceptance.
/// The host must keep `(tenant, target)` bound to the same endpoint across attempts.
pub struct AuthorizedTarget {
    pub(crate) tenant: TenantId,
    pub(crate) target: Target,
    pub(crate) url: url::Url,
    pub(crate) network: NetworkAccess,
    pub(crate) trust: TrustRoots,
    pub(crate) keys: SigningKeys,
}
impl AuthorizedTarget {
    /// Validate an authorized endpoint and bind its port to every approved address.
    pub fn new(
        tenant: TenantId,
        target: Target,
        endpoint: &str,
        network: NetworkAccess,
        trust: TrustRoots,
        keys: SigningKeys,
    ) -> Result<Self, Error> {
        if endpoint.len() > 8192 {
            return Err(Error::Config);
        }
        let url = url::Url::parse(endpoint).map_err(|_| Error::Config)?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || url.host().is_none()
        {
            return Err(Error::Config);
        }
        let port = url.port_or_known_default().ok_or(Error::Config)?;
        if network.addresses.iter().any(|a| a.port() != port) {
            return Err(Error::Config);
        }
        Ok(Self {
            tenant,
            target,
            url,
            network,
            trust,
            keys,
        })
    }
}
impl std::fmt::Debug for AuthorizedTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthorizedTarget(<redacted>)")
    }
}
/// Closed failure from the trusted host authorization boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationFailure {
    /// Current tenant/resource/target authorization is denied, including retired versions.
    Denied,
    /// Authorization or bounded address resolution is temporarily unavailable.
    Unavailable,
}
/// Trusted product authorization, DNS and key-store seam, called anew for every attempt.
/// Implementations must be bounded, nonblocking and cancel-safe: dropping the future must not
/// leave unowned work. In particular, a timeout around blocking system DNS is insufficient.
pub trait TargetAuthorizer: Send + Sync {
    /// Reauthorize exactly this publication and return a fresh endpoint/address/key snapshot.
    fn authorize(
        &self,
        publication: &Publication<'_>,
        deadline: OperationDeadline,
    ) -> impl Future<Output = Result<AuthorizedTarget, AuthorizationFailure>> + Send;
}
