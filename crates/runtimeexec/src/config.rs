//! Shared typed boundaries for assembly-owned serving configuration.

use std::ffi::OsString;
use std::net::IpAddr;
use std::path::Path;

use serde::de::{DeserializeOwned, Visitor};
use serde::{Deserialize, Deserializer};
use zeroize::Zeroizing;

pub const POD_IP_ENV: &str = "RSS_DEPLOYMENT_POD_IP";
pub const PRIMARY_PORT_ENV: &str = "RSS_DEPLOYMENT_PRIMARY_PORT";
pub const ADMIN_PORT_ENV: &str = "RSS_DEPLOYMENT_ADMIN_PORT";
pub const HEALTH_PORT_ENV: &str = "RSS_DEPLOYMENT_HEALTH_PORT";
pub const TRUSTED_PROXY_CIDRS_ENV: &str = "RSS_DEPLOYMENT_TRUSTED_PROXY_CIDRS";
pub const RATE_LIMIT_PER_SECOND_ENV: &str = "RSS_RATE_LIMIT_PER_SECOND";
pub const RATE_LIMIT_BURST_ENV: &str = "RSS_RATE_LIMIT_BURST";
pub const DEFAULT_RATE_LIMIT_PER_SECOND: u32 = 10;
pub const DEFAULT_RATE_LIMIT_BURST: u32 = 20;

/// Opaque JSON document whose allocation is erased on every success and error path.
///
/// INVARIANT: SECRET-FILE-BOUNDARY-01 { level = "Hard", exec = "native-compile", source = "code", native = "filesystem secret documents enter an opaque ZeroizeOnDrop owner before parsing; parsed secret fields use SecretValue and no environment or plaintext compatibility API exists" }
#[derive(zeroize::ZeroizeOnDrop)]
pub struct SecretDocument(Zeroizing<String>);

impl SecretDocument {
    pub fn new(document: Zeroizing<String>) -> Self {
        Self(document)
    }

    /// Parse without copying the source document. Callers deliberately receive a static error that
    /// cannot retain or render a serde snippet containing secret material.
    pub fn parse<T: DeserializeOwned>(&self) -> Result<T, SecretJsonError> {
        serde_json::from_str(&self.0).map_err(|_| SecretJsonError)
    }
}

/// Read a file directly into the zeroizing secret-document boundary.
pub fn read_secret_document(path: &Path) -> std::io::Result<SecretDocument> {
    std::fs::read_to_string(path).map(|document| SecretDocument(Zeroizing::new(document)))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecretJsonError;

/// A serde string owner that erases its allocation even if parsing or later validation fails.
#[derive(zeroize::ZeroizeOnDrop)]
pub struct SecretValue(String);

impl SecretValue {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn into_zeroizing(mut self) -> Zeroizing<String> {
        Zeroizing::new(std::mem::take(&mut self.0))
    }

    pub fn into_secret_text(mut self) -> rss_redact::SecretText {
        rss_redact::SecretText::from_string(std::mem::take(&mut self.0))
    }
}

impl PartialEq for SecretValue {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for SecretValue {}

impl<'de> Deserialize<'de> for SecretValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SecretValueVisitor;

        impl Visitor<'_> for SecretValueVisitor {
            type Value = SecretValue;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a secret string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
                Ok(SecretValue(value.to_owned()))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
                Ok(SecretValue(value))
            }
        }

        deserializer.deserialize_string(SecretValueVisitor)
    }
}

pub struct ServingFrontendConfig<P> {
    pub pod_ip: IpAddr,
    pub primary_port: u16,
    pub admin_port: u16,
    pub health_port: u16,
    pub trusted_proxy_config: P,
    pub rate_limit_quota: diport::RateLimitQuota,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrontendConfigError {
    Missing(&'static str),
    NonUnicode(&'static str),
    Empty(&'static str),
    Invalid(&'static str),
}

/// Capture the deployment frontend from its closed environment vocabulary exactly once.
pub fn capture_serving_frontend<P>(
    mut read: impl FnMut(&'static str) -> Option<OsString>,
    parse_trusted_proxy: impl FnOnce(Option<&str>) -> Result<P, FrontendConfigError>,
) -> Result<ServingFrontendConfig<P>, FrontendConfigError> {
    let pod_ip = required(&mut read, POD_IP_ENV)?
        .parse()
        .map_err(|_| FrontendConfigError::Invalid(POD_IP_ENV))?;
    let primary_port = port(&mut read, PRIMARY_PORT_ENV)?;
    let admin_port = port(&mut read, ADMIN_PORT_ENV)?;
    let health_port = port(&mut read, HEALTH_PORT_ENV)?;
    if admin_port == primary_port {
        return Err(FrontendConfigError::Invalid(ADMIN_PORT_ENV));
    }
    if health_port == primary_port || health_port == admin_port {
        return Err(FrontendConfigError::Invalid(HEALTH_PORT_ENV));
    }
    let trusted_proxy_raw = optional(&mut read, TRUSTED_PROXY_CIDRS_ENV)?;
    let trusted_proxy_config = parse_trusted_proxy(trusted_proxy_raw.as_deref())?;
    let rate_limit_quota = diport::RateLimitQuota::try_new(
        quota_from_source(
            &mut read,
            RATE_LIMIT_PER_SECOND_ENV,
            DEFAULT_RATE_LIMIT_PER_SECOND,
        ),
        quota_from_source(&mut read, RATE_LIMIT_BURST_ENV, DEFAULT_RATE_LIMIT_BURST),
    )
    .unwrap_or_else(|_| unreachable!("validated rate-limit defaults and values"));
    Ok(ServingFrontendConfig {
        pod_ip,
        primary_port,
        admin_port,
        health_port,
        trusted_proxy_config,
        rate_limit_quota,
    })
}

fn optional(
    read: &mut impl FnMut(&'static str) -> Option<OsString>,
    name: &'static str,
) -> Result<Option<String>, FrontendConfigError> {
    read(name)
        .map(|value| {
            value
                .into_string()
                .map_err(|_| FrontendConfigError::NonUnicode(name))
        })
        .transpose()
}

pub fn rate_limit_quota_from_values(
    per_second: Option<&str>,
    burst: Option<&str>,
) -> diport::RateLimitQuota {
    let per_second = quota_value(
        RATE_LIMIT_PER_SECOND_ENV,
        per_second,
        DEFAULT_RATE_LIMIT_PER_SECOND,
    );
    let burst = quota_value(RATE_LIMIT_BURST_ENV, burst, DEFAULT_RATE_LIMIT_BURST);
    diport::RateLimitQuota::try_new(per_second, burst)
        .unwrap_or_else(|_| unreachable!("validated rate-limit defaults and values"))
}

fn quota_value(name: &'static str, raw: Option<&str>, default: u32) -> u32 {
    let Some(raw) = raw else {
        return default;
    };
    match raw.parse::<u32>() {
        Ok(value) if (1..=diport::MAX_RATE_LIMIT_QUOTA).contains(&value) => value,
        _ => {
            warn_invalid_quota(name, default);
            default
        }
    }
}

fn quota_from_source(
    read: &mut impl FnMut(&'static str) -> Option<OsString>,
    name: &'static str,
    default: u32,
) -> u32 {
    let Some(raw) = read(name) else {
        return default;
    };
    match raw.into_string() {
        Ok(raw) => quota_value(name, Some(&raw), default),
        Err(_) => {
            warn_invalid_quota(name, default);
            default
        }
    }
}

fn warn_invalid_quota(name: &'static str, default: u32) {
    tracing::warn!(
        env = name,
        default,
        max = diport::MAX_RATE_LIMIT_QUOTA,
        "invalid rate-limit quota value; using default"
    );
}

fn required(
    read: &mut impl FnMut(&'static str) -> Option<OsString>,
    name: &'static str,
) -> Result<String, FrontendConfigError> {
    let value = read(name)
        .ok_or(FrontendConfigError::Missing(name))?
        .into_string()
        .map_err(|_| FrontendConfigError::NonUnicode(name))?;
    if value.is_empty() {
        return Err(FrontendConfigError::Empty(name));
    }
    Ok(value)
}

fn port(
    read: &mut impl FnMut(&'static str) -> Option<OsString>,
    name: &'static str,
) -> Result<u16, FrontendConfigError> {
    required(read, name)?
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or(FrontendConfigError::Invalid(name))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;

    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

    #[test]
    fn secret_owners_have_native_zeroize_proofs() {
        assert_zeroize_on_drop::<SecretDocument>();
        assert_zeroize_on_drop::<SecretValue>();
    }

    #[test]
    fn parse_error_is_static_and_does_not_retain_document() {
        let document =
            SecretDocument::new(Zeroizing::new("{\"token\":\"do-not-render\"".to_owned()));
        let error = document.parse::<serde_json::Value>().unwrap_err();
        assert_eq!(format!("{error:?}"), "SecretJsonError");
    }

    #[test]
    fn frontend_error_identifies_the_exact_variable() {
        let mut values = std::collections::BTreeMap::from([
            (POD_IP_ENV, OsString::from("127.0.0.2")),
            (PRIMARY_PORT_ENV, OsString::from("invalid")),
            (ADMIN_PORT_ENV, OsString::from("8081")),
            (HEALTH_PORT_ENV, OsString::from("8083")),
        ]);
        let error = match capture_serving_frontend(|name| values.remove(name), |_| Ok(())) {
            Ok(_) => panic!("invalid port must fail"),
            Err(error) => error,
        };
        assert_eq!(error, FrontendConfigError::Invalid(PRIMARY_PORT_ENV));
    }

    #[test]
    fn quota_defaults_and_invalid_values_fail_soft_independently() {
        let defaults = rate_limit_quota_from_values(None, None);
        assert_eq!(defaults.per_second(), 10);
        assert_eq!(defaults.burst(), 20);

        let mixed = rate_limit_quota_from_values(Some("77"), Some("0"));
        assert_eq!(mixed.per_second(), 77);
        assert_eq!(mixed.burst(), 20);

        let bounded = rate_limit_quota_from_values(Some("1000001"), Some("31"));
        assert_eq!(bounded.per_second(), 10);
        assert_eq!(bounded.burst(), 31);

        let non_numeric = rate_limit_quota_from_values(Some("fast"), Some("1000000"));
        assert_eq!(non_numeric.per_second(), 10);
        assert_eq!(non_numeric.burst(), 1_000_000);
    }

    #[cfg(unix)]
    #[test]
    fn non_unicode_quota_falls_back_without_failing_frontend_capture() {
        use std::os::unix::ffi::OsStringExt as _;

        let mut read = |_| Some(OsString::from_vec(vec![0xff]));
        assert_eq!(
            quota_from_source(
                &mut read,
                RATE_LIMIT_PER_SECOND_ENV,
                DEFAULT_RATE_LIMIT_PER_SECOND,
            ),
            DEFAULT_RATE_LIMIT_PER_SECOND
        );
    }
}
