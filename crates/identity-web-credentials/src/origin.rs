use crate::{CredentialError, unique};
use http::HeaderMap;
use rss_identity_core::session::SessionSecret;
use std::time::{Duration, Instant};
#[derive(Clone)]
pub struct HttpConfig {
    origin: String,
    timeout: Duration,
}
#[derive(Debug, thiserror::Error)]
#[error("Identity requires a canonical HTTPS origin and a nonzero bounded request timeout")]
pub struct HttpConfigError;
impl HttpConfig {
    pub fn timeout(&self) -> Duration {
        self.timeout
    }
    pub fn new(origin: &str, timeout: Duration) -> Result<Self, HttpConfigError> {
        let url = url::Url::parse(origin).map_err(|_| HttpConfigError)?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || url.origin().ascii_serialization() != origin
            || timeout.is_zero()
            || Instant::now().checked_add(timeout).is_none()
        {
            return Err(HttpConfigError);
        }
        Ok(Self {
            origin: origin.into(),
            timeout,
        })
    }
}
pub fn same_origin(headers: &HeaderMap, config: &HttpConfig) -> Result<(), CredentialError> {
    match unique(headers, "origin") {
        Ok(Some(origin)) if origin == config.origin => Ok(()),
        _ => Err(CredentialError::Forbidden),
    }
}
pub fn csrf(headers: &HeaderMap, secret: &SessionSecret) -> Result<(), CredentialError> {
    if !secret.check_csrf(unique(headers, "x-csrf-token")?.ok_or(CredentialError::Forbidden)?) {
        return Err(CredentialError::Forbidden);
    }
    Ok(())
}

pub fn request_marker(headers: &HeaderMap) -> Result<bool, CredentialError> {
    Ok(unique(headers, "x-identity-request")? == Some("1"))
}
