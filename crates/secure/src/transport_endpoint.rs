use std::net::IpAddr;

use url::{Host, Url};

/// 明文 transport endpoint 策略。
///
/// 默认生产路径使用 [`PlaintextEndpointPolicy::Deny`]；dev/test 需要明文 fixture 时必须显式选择
/// [`PlaintextEndpointPolicy::AllowLoopback`]，且 endpoint host 仍必须是 loopback。compose/dev-container
/// 演示栈需要经组合根显式选择 [`PlaintextEndpointPolicy::AllowDevContainer`]。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaintextEndpointPolicy {
    Deny,
    AllowLoopback,
    AllowDevContainer,
}

/// AMQP/Redis/S3 transport endpoint 构造失败。
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransportEndpointError {
    #[error("transport endpoint url is invalid")]
    InvalidUrl,
    #[error("{kind} endpoint must use {secure_scheme}:// transport")]
    InsecureScheme {
        kind: &'static str,
        secure_scheme: &'static str,
    },
    #[error("{kind} plaintext endpoint must target a loopback host when explicitly allowed")]
    PlaintextNotLoopback { kind: &'static str },
    #[error(
        "{kind} plaintext endpoint must target loopback or the demo compose service host when dev-container policy is explicitly allowed"
    )]
    PlaintextNotDevContainer { kind: &'static str },
    #[error("{kind} endpoint scheme is unsupported")]
    UnsupportedScheme { kind: &'static str },
    #[error("redis TLS endpoint must not use URL fragments such as #insecure")]
    RedisFragmentUnsupported,
    #[error("amqp endpoint must include an explicit host")]
    AmqpHostRequired,
    #[error("amqp endpoint must include an explicit vhost path")]
    AmqpVhostRequired,
    #[error("{kind} endpoint must include an explicit host")]
    HostRequired { kind: &'static str },
    #[error("{kind} endpoint must not include URL userinfo")]
    UserInfoUnsupported { kind: &'static str },
    #[error("{kind} endpoint must not include URL query")]
    QueryUnsupported { kind: &'static str },
    #[error("{kind} endpoint must not include URL fragment")]
    FragmentUnsupported { kind: &'static str },
}

/// 已校验 AMQP endpoint。默认生产路径只接受 `amqps://`。
#[derive(Clone, PartialEq, Eq)]
pub struct AmqpEndpoint(String);

impl AmqpEndpoint {
    pub fn parse(
        endpoint: impl Into<String>,
        policy: PlaintextEndpointPolicy,
    ) -> Result<Self, TransportEndpointError> {
        let endpoint = endpoint.into();
        let parsed = Url::parse(&endpoint).map_err(|_| TransportEndpointError::InvalidUrl)?;
        validate_endpoint_url(&parsed, "amqp", "amqp", "amqps", policy)?;
        validate_amqp_endpoint_url(&parsed)?;
        Ok(Self(endpoint))
    }

    /// 暴露原始 URL 给 AMQP driver。不要记录该值。
    pub fn expose(&self) -> &str {
        &self.0
    }

    fn render_redacted(&self) -> String {
        render_redacted_url(&self.0)
    }
}

impl std::fmt::Debug for AmqpEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AmqpEndpoint({})", self.render_redacted())
    }
}

impl std::fmt::Display for AmqpEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.render_redacted())
    }
}

/// 已校验 Redis endpoint。默认生产路径只接受 `rediss://`。
#[derive(Clone, PartialEq, Eq)]
pub struct RedisEndpoint(String);

impl RedisEndpoint {
    pub fn parse(
        endpoint: impl Into<String>,
        policy: PlaintextEndpointPolicy,
    ) -> Result<Self, TransportEndpointError> {
        let endpoint = endpoint.into();
        let parsed = Url::parse(&endpoint).map_err(|_| TransportEndpointError::InvalidUrl)?;
        if parsed.fragment().is_some() {
            return Err(TransportEndpointError::RedisFragmentUnsupported);
        }
        validate_endpoint_url(&parsed, "redis", "redis", "rediss", policy)?;
        Ok(Self(endpoint))
    }

    /// 暴露原始 URL 给 Redis driver。不要记录该值。
    pub fn expose(&self) -> &str {
        &self.0
    }

    fn render_redacted(&self) -> String {
        render_redacted_url(&self.0)
    }
}

impl std::fmt::Debug for RedisEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RedisEndpoint({})", self.render_redacted())
    }
}

impl std::fmt::Display for RedisEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.render_redacted())
    }
}

/// 已校验 S3 endpoint。默认生产路径只接受 `https://`；明文 `http://` 仅允许显式 dev/test opt-in。
#[derive(Clone, PartialEq, Eq)]
pub struct S3Endpoint(String);

impl S3Endpoint {
    pub fn parse(
        endpoint: impl Into<String>,
        policy: PlaintextEndpointPolicy,
    ) -> Result<Self, TransportEndpointError> {
        let endpoint = endpoint.into();
        let parsed = Url::parse(&endpoint).map_err(|_| TransportEndpointError::InvalidUrl)?;
        validate_s3_endpoint_url(&parsed)?;
        validate_endpoint_url(&parsed, "s3", "http", "https", policy)?;
        Ok(Self(endpoint))
    }

    /// 暴露原始 URL 给 AWS SDK。不要记录该值。
    pub fn expose(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn is_plaintext(&self) -> bool {
        self.0
            .get(..("http://".len()))
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("http://"))
    }

    fn render_redacted(&self) -> String {
        render_redacted_url(&self.0)
    }
}

impl std::fmt::Debug for S3Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "S3Endpoint({})", self.render_redacted())
    }
}

impl std::fmt::Display for S3Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.render_redacted())
    }
}

fn validate_endpoint_url(
    parsed: &Url,
    kind: &'static str,
    plaintext_scheme: &'static str,
    secure_scheme: &'static str,
    policy: PlaintextEndpointPolicy,
) -> Result<(), TransportEndpointError> {
    match parsed.scheme() {
        scheme if scheme == secure_scheme => Ok(()),
        scheme if scheme == plaintext_scheme => match policy {
            PlaintextEndpointPolicy::Deny => Err(TransportEndpointError::InsecureScheme {
                kind,
                secure_scheme,
            }),
            PlaintextEndpointPolicy::AllowLoopback => {
                if is_loopback_host(parsed) {
                    Ok(())
                } else {
                    Err(TransportEndpointError::PlaintextNotLoopback { kind })
                }
            }
            PlaintextEndpointPolicy::AllowDevContainer => {
                if is_dev_container_host(parsed, plaintext_scheme) {
                    Ok(())
                } else {
                    Err(TransportEndpointError::PlaintextNotDevContainer { kind })
                }
            }
        },
        _ => Err(TransportEndpointError::UnsupportedScheme { kind }),
    }
}

fn validate_amqp_endpoint_url(parsed: &Url) -> Result<(), TransportEndpointError> {
    if parsed.host().is_none() {
        return Err(TransportEndpointError::AmqpHostRequired);
    }
    if parsed.path().is_empty() || parsed.path() == "/" {
        return Err(TransportEndpointError::AmqpVhostRequired);
    }
    Ok(())
}

fn validate_s3_endpoint_url(parsed: &Url) -> Result<(), TransportEndpointError> {
    if parsed.host().is_none() {
        return Err(TransportEndpointError::HostRequired { kind: "s3" });
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(TransportEndpointError::UserInfoUnsupported { kind: "s3" });
    }
    if parsed.query().is_some() {
        return Err(TransportEndpointError::QueryUnsupported { kind: "s3" });
    }
    if parsed.fragment().is_some() {
        return Err(TransportEndpointError::FragmentUnsupported { kind: "s3" });
    }
    Ok(())
}

fn is_loopback_host(parsed: &Url) -> bool {
    match parsed.host() {
        Some(Host::Domain(host)) => {
            host.eq_ignore_ascii_case("localhost")
                || host.parse::<IpAddr>().is_ok_and(|addr| addr.is_loopback())
        }
        Some(Host::Ipv4(addr)) => addr.is_loopback(),
        Some(Host::Ipv6(addr)) => addr.is_loopback(),
        None => false,
    }
}

fn is_dev_container_host(parsed: &Url, plaintext_scheme: &str) -> bool {
    if is_loopback_host(parsed) {
        return true;
    }
    match (plaintext_scheme, parsed.host()) {
        ("amqp", Some(Host::Domain(host))) => host.eq_ignore_ascii_case("rabbitmq"),
        ("redis", Some(Host::Domain(host))) => host.eq_ignore_ascii_case("redis"),
        ("http", Some(Host::Domain(host))) => host.eq_ignore_ascii_case("minio"),
        _ => false,
    }
}

fn render_redacted_url(raw: &str) -> String {
    let without_query_fragment = raw.split(['?', '#']).next().unwrap_or(raw);
    crate::redact_url_credentials(without_query_fragment).to_string()
}

#[cfg(test)]
mod tests {
    use super::{AmqpEndpoint, PlaintextEndpointPolicy, RedisEndpoint, S3Endpoint};

    #[test]
    fn amqp_endpoint_requires_amqps_by_default() {
        assert!(
            AmqpEndpoint::parse(
                "amqps://user:pass@broker/vhost",
                PlaintextEndpointPolicy::Deny
            )
            .is_ok()
        );
        let result = AmqpEndpoint::parse(
            "amqp://user:pass@broker/vhost",
            PlaintextEndpointPolicy::Deny,
        );
        let err = result
            .as_ref()
            .err()
            .map(ToString::to_string)
            .unwrap_or_default();
        assert!(err.contains("amqps://"), "{result:?}");
    }

    #[test]
    fn amqp_plaintext_opt_in_is_loopback_only() {
        assert!(
            AmqpEndpoint::parse(
                "amqp://user:pass@127.0.0.1:5672/vhost",
                PlaintextEndpointPolicy::AllowLoopback,
            )
            .is_ok()
        );
        assert!(
            AmqpEndpoint::parse(
                "amqp://user:pass@broker.internal:5672/vhost",
                PlaintextEndpointPolicy::AllowLoopback,
            )
            .is_err()
        );
    }

    #[test]
    fn amqp_plaintext_dev_container_policy_is_explicit() {
        assert!(
            AmqpEndpoint::parse(
                "amqp://user:pass@rabbitmq:5672/vhost",
                PlaintextEndpointPolicy::AllowDevContainer,
            )
            .is_ok()
        );
        assert!(
            AmqpEndpoint::parse(
                "amqp://user:pass@rabbitmq:5672/vhost",
                PlaintextEndpointPolicy::AllowLoopback,
            )
            .is_err()
        );
        assert!(
            AmqpEndpoint::parse(
                "amqp://user:pass@broker.internal:5672/vhost",
                PlaintextEndpointPolicy::AllowDevContainer,
            )
            .is_err()
        );
    }

    #[test]
    fn amqp_endpoint_requires_host_and_explicit_vhost() {
        assert!(AmqpEndpoint::parse("amqps://broker/%2f", PlaintextEndpointPolicy::Deny).is_ok());
        assert!(
            AmqpEndpoint::parse("amqps://broker", PlaintextEndpointPolicy::Deny).is_err(),
            "missing vhost path must not silently fall back to /"
        );
        assert!(
            AmqpEndpoint::parse("amqps://broker/", PlaintextEndpointPolicy::Deny).is_err(),
            "empty vhost path must not silently fall back to /"
        );
        assert!(
            AmqpEndpoint::parse("amqps:///vhost", PlaintextEndpointPolicy::Deny).is_err(),
            "missing host must not silently fall back to localhost"
        );
    }

    #[test]
    fn redis_endpoint_requires_rediss_by_default_and_rejects_insecure_fragment() {
        assert!(
            RedisEndpoint::parse(
                "rediss://user:pass@cache:6379/0",
                PlaintextEndpointPolicy::Deny
            )
            .is_ok()
        );
        assert!(
            RedisEndpoint::parse(
                "redis://user:pass@cache:6379/0",
                PlaintextEndpointPolicy::Deny
            )
            .is_err()
        );
        assert!(
            RedisEndpoint::parse(
                "rediss://user:pass@cache:6379/0#insecure",
                PlaintextEndpointPolicy::Deny
            )
            .is_err()
        );
    }

    #[test]
    fn redis_plaintext_opt_in_is_loopback_only() {
        assert!(
            RedisEndpoint::parse(
                "redis://user:pass@localhost:6379/0",
                PlaintextEndpointPolicy::AllowLoopback,
            )
            .is_ok()
        );
        assert!(
            RedisEndpoint::parse(
                "redis://user:pass@cache.internal:6379/0",
                PlaintextEndpointPolicy::AllowLoopback,
            )
            .is_err()
        );
    }

    #[test]
    fn redis_plaintext_dev_container_policy_is_explicit() {
        assert!(
            RedisEndpoint::parse(
                "redis://redis:6379/0",
                PlaintextEndpointPolicy::AllowDevContainer,
            )
            .is_ok()
        );
        assert!(
            RedisEndpoint::parse(
                "redis://redis:6379/0",
                PlaintextEndpointPolicy::AllowLoopback
            )
            .is_err()
        );
        assert!(
            RedisEndpoint::parse(
                "redis://cache.internal:6379/0",
                PlaintextEndpointPolicy::AllowDevContainer,
            )
            .is_err()
        );
    }

    #[test]
    fn s3_endpoint_requires_https_by_default() {
        assert!(
            S3Endpoint::parse(
                "https://s3.us-east-1.amazonaws.com",
                PlaintextEndpointPolicy::Deny
            )
            .is_ok()
        );
        let result = S3Endpoint::parse("http://127.0.0.1:9000", PlaintextEndpointPolicy::Deny);
        let err = result
            .as_ref()
            .err()
            .map(ToString::to_string)
            .unwrap_or_default();
        assert!(err.contains("https://"), "{result:?}");
    }

    #[test]
    fn s3_endpoint_plaintext_detection_is_case_insensitive() {
        let result = S3Endpoint::parse(
            "HTTP://127.0.0.1:9000",
            PlaintextEndpointPolicy::AllowLoopback,
        );
        assert!(result.is_ok(), "{result:?}");
        if let Ok(endpoint) = result {
            assert!(endpoint.is_plaintext());
        }
    }

    #[test]
    fn s3_plaintext_opt_in_is_loopback_only() {
        assert!(
            S3Endpoint::parse(
                "http://127.0.0.1:9000",
                PlaintextEndpointPolicy::AllowLoopback,
            )
            .is_ok()
        );
        assert!(
            S3Endpoint::parse(
                "http://minio.internal:9000",
                PlaintextEndpointPolicy::AllowLoopback,
            )
            .is_err()
        );
    }

    #[test]
    fn s3_plaintext_dev_container_policy_is_explicit() {
        assert!(
            S3Endpoint::parse(
                "http://minio:9000",
                PlaintextEndpointPolicy::AllowDevContainer,
            )
            .is_ok()
        );
        assert!(
            S3Endpoint::parse("http://minio:9000", PlaintextEndpointPolicy::AllowLoopback).is_err()
        );
        assert!(
            S3Endpoint::parse(
                "http://object-store.internal:9000",
                PlaintextEndpointPolicy::AllowDevContainer,
            )
            .is_err()
        );
    }

    #[test]
    fn s3_endpoint_rejects_userinfo_query_and_fragment() {
        for endpoint in [
            "https://user:pass@s3.us-east-1.amazonaws.com",
            "https://s3.us-east-1.amazonaws.com?token=secret",
            "https://s3.us-east-1.amazonaws.com#frag",
        ] {
            assert!(
                S3Endpoint::parse(endpoint, PlaintextEndpointPolicy::Deny).is_err(),
                "{endpoint} must fail closed"
            );
        }
    }

    #[test]
    fn endpoint_debug_and_display_drop_credentials_query_and_fragment() {
        let result = AmqpEndpoint::parse(
            "amqps://user:pass@broker/vhost?token=supersecret#frag",
            PlaintextEndpointPolicy::Deny,
        );
        assert!(result.is_ok(), "{result:?}");
        if let Ok(endpoint) = result {
            for rendered in [format!("{endpoint:?}"), format!("{endpoint}")] {
                assert!(!rendered.contains("user"), "{rendered}");
                assert!(!rendered.contains("pass"), "{rendered}");
                assert!(!rendered.contains("supersecret"), "{rendered}");
                assert!(!rendered.contains('?'), "{rendered}");
                assert!(!rendered.contains('#'), "{rendered}");
            }
        }
    }
}
