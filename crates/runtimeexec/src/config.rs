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
pub const MTLS_ALLOW_SET_ENV: &str = "RSS_DEPLOYMENT_MTLS_SPIFFE_ALLOW_SET";
pub const SPIFFE_ENDPOINT_ENV: &str = "SPIFFE_ENDPOINT_SOCKET";

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

    pub fn into_secret_text(mut self) -> secure::SecretText {
        secure::SecretText::from_string(std::mem::take(&mut self.0))
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

pub struct ServingFrontendConfig {
    pub pod_ip: IpAddr,
    pub primary_port: u16,
    pub admin_port: u16,
    pub health_port: u16,
    pub allow_set: authn::MtlsAllowSet,
    pub spiffe_endpoint: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrontendConfigError {
    Missing(&'static str),
    NonUnicode(&'static str),
    Empty(&'static str),
    Invalid(&'static str),
}

/// Capture the deployment frontend from its closed environment vocabulary exactly once.
pub fn capture_serving_frontend(
    mut read: impl FnMut(&'static str) -> Option<OsString>,
) -> Result<ServingFrontendConfig, FrontendConfigError> {
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
    let peers: Vec<String> = serde_json::from_str(&required(&mut read, MTLS_ALLOW_SET_ENV)?)
        .map_err(|_| FrontendConfigError::Invalid(MTLS_ALLOW_SET_ENV))?;
    let allow_set = authn::MtlsAllowSet::new(peers)
        .map_err(|_| FrontendConfigError::Invalid(MTLS_ALLOW_SET_ENV))?;
    let spiffe_endpoint = required(&mut read, SPIFFE_ENDPOINT_ENV)?;
    Ok(ServingFrontendConfig {
        pod_ip,
        primary_port,
        admin_port,
        health_port,
        allow_set,
        spiffe_endpoint,
    })
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
            (MTLS_ALLOW_SET_ENV, OsString::from("[]")),
            (SPIFFE_ENDPOINT_ENV, OsString::from("unix:///spire.sock")),
        ]);
        let error = match capture_serving_frontend(|name| values.remove(name)) {
            Ok(_) => panic!("invalid port must fail"),
            Err(error) => error,
        };
        assert_eq!(error, FrontendConfigError::Invalid(PRIMARY_PORT_ENV));
    }
}
