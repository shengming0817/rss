use std::net::IpAddr;
use std::task::{Context, Poll};

use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Request};
use ipnet::IpNet;
use tower::{Layer, Service};

const X_FORWARDED_FOR: &str = "x-forwarded-for";
const X_REAL_IP: &str = "x-real-ip";
const MAX_FORWARD_HEADER_BYTES: usize = 4 * 1024;
const MAX_FORWARDED_HOPS: usize = 32;

/// A client address resolved from the transport peer and an explicitly trusted proxy chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedClientIp(IpAddr);

impl ResolvedClientIp {
    #[must_use]
    pub const fn get(self) -> IpAddr {
        self.0
    }
}

#[derive(Clone)]
enum TrustedProxyMode {
    Disabled,
    Trusted(Vec<IpNet>),
}

/// Closed proxy-trust policy. Missing configuration is represented explicitly as `Disabled`;
/// trusted mode cannot be constructed with an invalid CIDR.
#[derive(Clone)]
pub struct TrustedProxyConfig {
    mode: TrustedProxyMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("trusted proxy CIDR is invalid")]
pub struct TrustedProxyConfigError;

impl TrustedProxyConfig {
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            mode: TrustedProxyMode::Disabled,
        }
    }

    /// Parse the deployment-owned JSON array exactly once into the closed runtime policy.
    pub fn try_from_json(raw: Option<&str>) -> Result<Self, TrustedProxyConfigError> {
        let Some(raw) = raw else {
            return Ok(Self::disabled());
        };
        let cidrs: Vec<String> = serde_json::from_str(raw).map_err(|_| TrustedProxyConfigError)?;
        let networks = cidrs
            .iter()
            .map(|cidr| cidr.parse::<IpNet>().map_err(|_| TrustedProxyConfigError))
            .collect::<Result<Vec<_>, _>>()?;
        if networks.is_empty() {
            return Ok(Self::disabled());
        }
        if networks.iter().any(|network| network.prefix_len() == 0) {
            return Err(TrustedProxyConfigError);
        }
        Ok(Self {
            mode: TrustedProxyMode::Trusted(networks),
        })
    }

    /// Resolve one request. Any untrusted or ambiguous input deterministically falls back to the
    /// immediate transport peer; a missing peer produces no resolved address.
    pub fn resolve<B>(&self, request: &Request<B>) -> Option<ResolvedClientIp> {
        let peer = request
            .extensions()
            .get::<ConnectInfo<std::net::SocketAddr>>()?
            .0
            .ip();
        let TrustedProxyMode::Trusted(networks) = &self.mode else {
            return Some(ResolvedClientIp(peer));
        };
        if !contains(networks, peer) {
            return Some(ResolvedClientIp(peer));
        }

        match unique_header(request.headers(), X_FORWARDED_FOR) {
            HeaderState::Absent => match unique_header(request.headers(), X_REAL_IP) {
                HeaderState::One(raw) => parse_single_ip(raw)
                    .filter(|address| !contains(networks, *address))
                    .map(ResolvedClientIp)
                    .or(Some(ResolvedClientIp(peer))),
                HeaderState::Absent | HeaderState::Ambiguous => Some(ResolvedClientIp(peer)),
            },
            HeaderState::One(raw) => resolve_forwarded(raw, networks)
                .map(ResolvedClientIp)
                .or(Some(ResolvedClientIp(peer))),
            HeaderState::Ambiguous => Some(ResolvedClientIp(peer)),
        }
    }
}

fn contains(networks: &[IpNet], address: IpAddr) -> bool {
    networks.iter().any(|network| network.contains(&address))
}

enum HeaderState<'a> {
    Absent,
    One(&'a axum::http::HeaderValue),
    Ambiguous,
}

fn unique_header<'a>(headers: &'a HeaderMap, name: &str) -> HeaderState<'a> {
    let mut values = headers.get_all(name).iter();
    match (values.next(), values.next()) {
        (None, _) => HeaderState::Absent,
        (Some(value), None) => HeaderState::One(value),
        (Some(_), Some(_)) => HeaderState::Ambiguous,
    }
}

fn parse_single_ip(value: &axum::http::HeaderValue) -> Option<IpAddr> {
    if value.as_bytes().len() > MAX_FORWARD_HEADER_BYTES {
        return None;
    }
    let raw = value.to_str().ok()?;
    if raw.trim() != raw || raw.is_empty() {
        return None;
    }
    raw.parse().ok()
}

fn resolve_forwarded(value: &axum::http::HeaderValue, networks: &[IpNet]) -> Option<IpAddr> {
    if value.as_bytes().len() > MAX_FORWARD_HEADER_BYTES {
        return None;
    }
    let raw = value.to_str().ok()?;
    let mut addresses = Vec::new();
    for token in raw.split(',') {
        if addresses.len() == MAX_FORWARDED_HOPS {
            return None;
        }
        let token = token.trim();
        if token.is_empty() {
            return None;
        }
        addresses.push(token.parse::<IpAddr>().ok()?);
    }
    addresses
        .into_iter()
        .rev()
        .find(|address| !contains(networks, *address))
}

/// Tower layer that always applies the closed client-IP resolution policy.
#[derive(Clone)]
pub struct RealIpLayer {
    config: TrustedProxyConfig,
}

impl RealIpLayer {
    #[must_use]
    pub const fn new(config: TrustedProxyConfig) -> Self {
        Self { config }
    }
}

impl<S> Layer<S> for RealIpLayer {
    type Service = RealIpService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RealIpService {
            inner,
            config: self.config.clone(),
        }
    }
}

#[derive(Clone)]
pub struct RealIpService<S> {
    inner: S,
    config: TrustedProxyConfig,
}

impl<S, B> Service<Request<B>> for RealIpService<S>
where
    S: Service<Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context)
    }

    fn call(&mut self, mut request: Request<B>) -> Self::Future {
        if let Some(client_ip) = self.config.resolve(&request) {
            request.extensions_mut().insert(client_ip);
        }
        self.inner.call(request)
    }
}
