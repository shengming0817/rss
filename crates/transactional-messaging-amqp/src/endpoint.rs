//! Adapter-owned endpoint validation. Role types prevent accidental credential slot swaps.
use std::net::IpAddr;
use url::{Host, Url};

/// Invalid AMQP endpoint; diagnostics never contain the supplied URL.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AmqpEndpointError {
    /// The URL cannot be parsed without normalization of whitespace/control characters.
    #[error("invalid AMQP endpoint URL")]
    InvalidUrl,
    /// Production endpoints require authenticated TLS.
    #[error("AMQP endpoint requires amqps://")]
    TlsRequired,
    /// A test-only plaintext endpoint must name a loopback host.
    #[error("plaintext AMQP is limited to loopback test fixtures")]
    PlaintextNotLoopback,
    /// The broker host must be explicit.
    #[error("AMQP endpoint requires an explicit host")]
    HostRequired,
    /// The vhost must be explicit; /%2f selects the default vhost.
    #[error("AMQP endpoint requires an explicit vhost")]
    VhostRequired,
    /// Production authentication must explicitly supply both username and password.
    #[error("AMQP endpoint requires explicit non-empty credentials")]
    CredentialsRequired,
    /// URI query/fragment must not override the adapter's authentication or connection policy.
    #[error("AMQP endpoint does not accept query parameters or fragments")]
    UnsupportedParameters,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Endpoint(String);
impl Endpoint {
    pub(crate) fn parse(
        raw: impl Into<String>,
        allow_loopback: bool,
    ) -> Result<Self, AmqpEndpointError> {
        let raw = raw.into();
        if raw.trim() != raw || raw.chars().any(char::is_control) {
            return Err(AmqpEndpointError::InvalidUrl);
        }
        let parsed = Url::parse(&raw).map_err(|_| AmqpEndpointError::InvalidUrl)?;
        if parsed.host().is_none() {
            return Err(AmqpEndpointError::HostRequired);
        }
        match parsed.scheme() {
            "amqps" => {}
            "amqp" if allow_loopback => {
                let loopback = match parsed.host() {
                    Some(Host::Domain(host)) => {
                        host.eq_ignore_ascii_case("localhost")
                            || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
                    }
                    Some(Host::Ipv4(ip)) => ip.is_loopback(),
                    Some(Host::Ipv6(ip)) => ip.is_loopback(),
                    None => false,
                };
                if !loopback {
                    return Err(AmqpEndpointError::PlaintextNotLoopback);
                }
            }
            _ => return Err(AmqpEndpointError::TlsRequired),
        }
        if parsed.path().is_empty() || parsed.path() == "/" {
            return Err(AmqpEndpointError::VhostRequired);
        }
        if !allow_loopback
            && (parsed.username().is_empty() || parsed.password().is_none_or(str::is_empty))
        {
            return Err(AmqpEndpointError::CredentialsRequired);
        }
        if parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(AmqpEndpointError::UnsupportedParameters);
        }
        Ok(Self(raw))
    }
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}
impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let raw = self.0.split(['?', '#']).next().unwrap_or(&self.0);
        write!(f, "{}", rss_redact::redact_url_credentials(raw))
    }
}
impl std::fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Endpoint({self})")
    }
}
macro_rules! role_endpoint {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Debug)]
        pub struct $name(pub(crate) Endpoint);
        impl $name {
            /// Parse AMQPS with explicit host, vhost and non-empty username/password; query and fragment are rejected.
            pub fn parse(raw: impl Into<String>) -> Result<Self, AmqpEndpointError> {
                Endpoint::parse(raw, false).map(Self)
            }
            /// Accept plaintext only on loopback, for explicitly enabled test fixtures.
            #[cfg(feature = "test-support")]
            pub fn for_test(raw: impl Into<String>) -> Result<Self, AmqpEndpointError> {
                Endpoint::parse(raw, true).map(Self)
            }
        }
    };
}
role_endpoint!(
    AmqpPublisherEndpoint,
    "Broker endpoint in the publisher credential slot; broker ACLs enforce its authority."
);
role_endpoint!(
    AmqpSubscriberEndpoint,
    "Broker endpoint in the subscriber credential slot; broker ACLs enforce its authority."
);

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn plaintext_is_explicit_and_loopback_only() {
        for raw in ["amqp://localhost/v", "amqp://127.0.0.1/v", "amqp://[::1]/v"] {
            assert!(Endpoint::parse(raw, true).is_ok());
            assert!(Endpoint::parse(raw, false).is_err());
        }
        for raw in [
            "amqp://rabbitmq/v",
            "amqp://localhost@evil/v",
            "amqp://broker.internal/v",
            " amqps://broker/v",
        ] {
            assert!(Endpoint::parse(raw, true).is_err());
        }
    }
    #[test]
    fn endpoint_and_errors_do_not_expose_credentials() -> Result<(), AmqpEndpointError> {
        let endpoint = Endpoint::parse("amqps://alice:secretpass@broker/v", false)?;
        for rendered in [format!("{endpoint:?}"), endpoint.to_string()] {
            for secret in [
                "alice",
                "secretpass",
                "supersecret",
                "fragmentsecret",
                "?",
                "#",
            ] {
                assert!(!rendered.contains(secret));
            }
        }
        Ok(())
    }
}
