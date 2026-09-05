use std::{net::IpAddr, num::NonZeroU16};

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

/// Transport endpoint 构造失败。
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
    #[error("{kind} endpoint must include an explicit host")]
    HostRequired { kind: &'static str },
    #[error("{kind} endpoint must not include URL userinfo")]
    UserInfoUnsupported { kind: &'static str },
    #[error("{kind} endpoint must not include URL query")]
    QueryUnsupported { kind: &'static str },
    #[error("{kind} endpoint must not include URL fragment")]
    FragmentUnsupported { kind: &'static str },
    #[error("{kind} endpoint must include a valid non-zero port")]
    InvalidPort { kind: &'static str },
}

/// 已校验的 domain-to-domain HTTP endpoint。
///
/// 该类型是 domain HTTP endpoint 合法性的唯一 owner：只接受无 userinfo、query、fragment 的
/// HTTPS URL，并保留 transport 所需的 base path。字段保持私有，消费方只能从已验证实例读取。
#[derive(Clone, PartialEq, Eq)]
pub struct DomainHttpEndpoint {
    url: Url,
    port: NonZeroU16,
}

impl DomainHttpEndpoint {
    /// Parse one canonical domain HTTP endpoint.
    ///
    /// The URL must use the lowercase `https://` prefix, contain a host and a valid non-zero port
    /// (defaulting to 443), and must not contain userinfo, query, fragment, surrounding whitespace,
    /// or control characters. The parsed URL retains its complete base path.
    ///
    /// # Errors
    ///
    /// Returns [`TransportEndpointError`] for malformed or unsupported endpoint syntax. Errors
    /// never include the raw endpoint value.
    pub fn parse(raw: impl AsRef<str>) -> Result<Self, TransportEndpointError> {
        const KIND: &str = "domain-http";
        let raw = raw.as_ref();
        if raw.trim() != raw || raw.chars().any(char::is_control) {
            return Err(TransportEndpointError::InvalidUrl);
        }

        let url = Url::parse(raw).map_err(|_| TransportEndpointError::InvalidUrl)?;
        if url.scheme() != "https" {
            return Err(TransportEndpointError::InsecureScheme {
                kind: KIND,
                secure_scheme: "https",
            });
        }
        let canonical = raw
            .strip_prefix("https://")
            .ok_or(TransportEndpointError::InvalidUrl)?;
        let authority = canonical
            .split(['/', '?', '#'])
            .next()
            .filter(|authority| !authority.is_empty())
            .ok_or(TransportEndpointError::HostRequired { kind: KIND })?;
        if authority.ends_with(':') {
            return Err(TransportEndpointError::InvalidPort { kind: KIND });
        }
        if url.host_str().is_none() {
            return Err(TransportEndpointError::HostRequired { kind: KIND });
        }
        if authority.contains('@') {
            return Err(TransportEndpointError::UserInfoUnsupported { kind: KIND });
        }
        if url.query().is_some() {
            return Err(TransportEndpointError::QueryUnsupported { kind: KIND });
        }
        if url.fragment().is_some() {
            return Err(TransportEndpointError::FragmentUnsupported { kind: KIND });
        }
        let port = url
            .port_or_known_default()
            .and_then(NonZeroU16::new)
            .ok_or(TransportEndpointError::InvalidPort { kind: KIND })?;

        Ok(Self { url, port })
    }

    #[must_use]
    /// Return the canonical host projected by the URL parser.
    pub fn host(&self) -> &str {
        self.url
            .host_str()
            .unwrap_or_else(|| unreachable!("validated domain HTTP endpoint always has a host"))
    }

    #[must_use]
    /// Return the explicit port, or the HTTPS default port 443 when omitted.
    pub fn port(&self) -> NonZeroU16 {
        self.port
    }

    #[must_use]
    /// Borrow the validated URL for transport construction.
    ///
    /// The returned URL may contain a deployment-sensitive host and path. Do not log or render it
    /// in diagnostics; use this endpoint's redacted [`Debug`](std::fmt::Debug) implementation.
    pub fn as_url(&self) -> &Url {
        &self.url
    }

    #[must_use]
    /// Consume the endpoint into its validated URL at the transport driver boundary.
    ///
    /// The returned URL may contain a deployment-sensitive host and path. Do not log or render it
    /// in diagnostics.
    pub fn into_url(self) -> Url {
        self.url
    }
}

impl std::fmt::Debug for DomainHttpEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DomainHttpEndpoint([REDACTED])")
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
        ("redis", Some(Host::Domain(host))) => host.eq_ignore_ascii_case("redis"),
        ("http", Some(Host::Domain(host))) => host.eq_ignore_ascii_case("minio"),
        _ => false,
    }
}

fn render_redacted_url(raw: &str) -> String {
    let without_query_fragment = raw.split(['?', '#']).next().unwrap_or(raw);
    rss_redact::redact_url_credentials(without_query_fragment).to_string()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::{
        DomainHttpEndpoint, PlaintextEndpointPolicy, RedisEndpoint, S3Endpoint,
        TransportEndpointError,
    };

    #[test]
    fn domain_http_endpoint_accepts_https_and_preserves_transport_path() {
        let cases = [
            ("https://identity.internal/rpc", "identity.internal", 443),
            (
                "https://identity.internal:8443/nested/rpc",
                "identity.internal",
                8443,
            ),
            ("https://127.0.0.1/rpc", "127.0.0.1", 443),
        ];

        for (raw, expected_host, expected_port) in cases {
            let endpoint = DomainHttpEndpoint::parse(raw).expect("valid domain HTTP endpoint");
            assert_eq!(endpoint.host(), expected_host);
            assert_eq!(endpoint.port().get(), expected_port);
            assert_eq!(
                endpoint.as_url().path(),
                url::Url::parse(raw).unwrap().path()
            );
        }
    }

    #[test]
    fn domain_http_endpoint_acceptance_matrix_is_closed() {
        for (raw, expected) in [
            ("", TransportEndpointError::InvalidUrl),
            ("not-a-url", TransportEndpointError::InvalidUrl),
            (
                "http://identity.internal/rpc",
                TransportEndpointError::InsecureScheme {
                    kind: "domain-http",
                    secure_scheme: "https",
                },
            ),
            (
                "HTTPS://identity.internal/rpc",
                TransportEndpointError::InvalidUrl,
            ),
            (
                "https:///rpc",
                TransportEndpointError::HostRequired {
                    kind: "domain-http",
                },
            ),
            (
                "https://identity.internal:/rpc",
                TransportEndpointError::InvalidPort {
                    kind: "domain-http",
                },
            ),
            (
                "https://identity.internal:0/rpc",
                TransportEndpointError::InvalidPort {
                    kind: "domain-http",
                },
            ),
            (
                "https://identity.internal:65536/rpc",
                TransportEndpointError::InvalidUrl,
            ),
            (
                " https://identity.internal/rpc",
                TransportEndpointError::InvalidUrl,
            ),
            (
                "https://identity.internal/rpc ",
                TransportEndpointError::InvalidUrl,
            ),
            (
                "https://user@identity.internal/rpc",
                TransportEndpointError::UserInfoUnsupported {
                    kind: "domain-http",
                },
            ),
            (
                "https://user:pass@identity.internal/rpc",
                TransportEndpointError::UserInfoUnsupported {
                    kind: "domain-http",
                },
            ),
            (
                "https://@identity.internal/rpc",
                TransportEndpointError::UserInfoUnsupported {
                    kind: "domain-http",
                },
            ),
            (
                "https://identity.internal/rpc?",
                TransportEndpointError::QueryUnsupported {
                    kind: "domain-http",
                },
            ),
            (
                "https://identity.internal/rpc?token=secret",
                TransportEndpointError::QueryUnsupported {
                    kind: "domain-http",
                },
            ),
            (
                "https://identity.internal/rpc#",
                TransportEndpointError::FragmentUnsupported {
                    kind: "domain-http",
                },
            ),
            (
                "https://identity.internal/rpc#fragment",
                TransportEndpointError::FragmentUnsupported {
                    kind: "domain-http",
                },
            ),
        ] {
            assert_eq!(
                DomainHttpEndpoint::parse(raw),
                Err(expected),
                "unexpected endpoint error for {raw:?}"
            );
        }
    }

    #[test]
    fn domain_http_endpoint_diagnostics_are_secret_free() {
        let endpoint = DomainHttpEndpoint::parse("https://private.internal/secret/path").unwrap();
        let debug = format!("{endpoint:?}");
        assert!(!debug.contains("private.internal"));
        assert!(!debug.contains("secret/path"));

        let error = DomainHttpEndpoint::parse(
            "https://private.internal/secret/path?access_token=top-secret",
        )
        .unwrap_err()
        .to_string();
        assert!(!error.contains("private.internal"));
        assert!(!error.contains("top-secret"));
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
}
