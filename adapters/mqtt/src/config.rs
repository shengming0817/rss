use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::Duration;

use diport::SecretMaterial;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use x509_parser::prelude::{FromDer as _, X509Certificate};

use crate::{BrokerAssertionVerifier, MqttTopicPolicy};

const DEFAULT_MQTTS_PORT: u16 = 8883;
const MIN_SESSION_EXPIRY_SECS: u64 = 60;
const MAX_SESSION_EXPIRY_SECS: u64 = 7 * 24 * 60 * 60;
const MAX_CLIENT_ID_BYTES: usize = 64;
const MAX_DNS_HOST_BYTES: usize = 253;
const MAX_TLS_MATERIAL_BYTES: usize = 256 * 1024;

/// Test-only synchronization point that lets broker T2 stop the transport after a negative
/// PUBACK is queued and before the event loop attempts to write it.
#[cfg(feature = "test-support")]
#[derive(Clone, Default)]
pub struct NegativeAckPollBarrier {
    inner: Arc<NegativeAckPollBarrierInner>,
}

#[cfg(feature = "test-support")]
#[derive(Default)]
struct NegativeAckPollBarrierInner {
    reached: std::sync::atomic::AtomicBool,
    released: std::sync::atomic::AtomicBool,
    reached_notify: tokio::sync::Notify,
    release_notify: tokio::sync::Notify,
}

#[cfg(feature = "test-support")]
impl NegativeAckPollBarrier {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn wait_until_reached(&self) {
        while !self
            .inner
            .reached
            .load(std::sync::atomic::Ordering::Acquire)
        {
            self.inner.reached_notify.notified().await;
        }
    }

    pub fn release(&self) {
        self.inner
            .released
            .store(true, std::sync::atomic::Ordering::Release);
        self.inner.release_notify.notify_waiters();
    }

    pub(crate) async fn wait_before_poll(&self) {
        self.inner
            .reached
            .store(true, std::sync::atomic::Ordering::Release);
        self.inner.reached_notify.notify_waiters();
        while !self
            .inner
            .released
            .load(std::sync::atomic::Ordering::Acquire)
        {
            self.inner.release_notify.notified().await;
        }
    }
}

/// Parsed TLS-only broker authority.
#[derive(Clone, PartialEq, Eq)]
pub struct MqttsEndpoint {
    host: String,
    port: u16,
}

impl MqttsEndpoint {
    pub fn parse(raw: &str) -> Result<Self, MqttConfigError> {
        let parsed = url::Url::parse(raw).map_err(|_| {
            tracing::warn!(target: "mqtt", reason = "endpoint_parse", "mqtt config rejected");
            MqttConfigError::EndpointInvalid
        })?;
        if parsed.scheme() != "mqtts"
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || !matches!(parsed.path(), "" | "/")
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            tracing::warn!(target: "mqtt", reason = "endpoint_components", "mqtt config rejected");
            return Err(MqttConfigError::EndpointInvalid);
        }
        let host = parsed
            .host_str()
            .filter(|host| !host.is_empty() && host.len() <= MAX_DNS_HOST_BYTES)
            .ok_or(MqttConfigError::EndpointInvalid)?;
        let port = parsed.port().unwrap_or(DEFAULT_MQTTS_PORT);
        if port == 0 {
            tracing::warn!(target: "mqtt", reason = "endpoint_port", "mqtt config rejected");
            return Err(MqttConfigError::EndpointInvalid);
        }
        Ok(Self {
            host: host.to_owned(),
            port,
        })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

impl std::fmt::Debug for MqttsEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MqttsEndpoint")
            .field("host", &self.host)
            .field("port", &self.port)
            .finish()
    }
}

/// Owned secret material used exactly once to prepare a rustls client configuration.
pub struct MqttTlsMaterial {
    ca: SecretMaterial,
    certificate: SecretMaterial,
    private_key: SecretMaterial,
}

impl MqttTlsMaterial {
    pub fn new(
        ca: SecretMaterial,
        certificate: SecretMaterial,
        private_key: SecretMaterial,
    ) -> Self {
        Self {
            ca,
            certificate,
            private_key,
        }
    }
}

impl std::fmt::Debug for MqttTlsMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MqttTlsMaterial(<redacted>)")
    }
}

/// MQTT v5 session expiry, bounded to keep signing-key/session drain operationally finite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionExpiry(u32);

impl SessionExpiry {
    pub fn new(value: Duration) -> Result<Self, MqttConfigError> {
        let seconds = value.as_secs();
        if value.subsec_nanos() != 0
            || !(MIN_SESSION_EXPIRY_SECS..=MAX_SESSION_EXPIRY_SECS).contains(&seconds)
        {
            return Err(MqttConfigError::SessionExpiryInvalid);
        }
        Ok(Self(
            u32::try_from(seconds).map_err(|_| MqttConfigError::SessionExpiryInvalid)?,
        ))
    }

    pub fn as_secs(self) -> u32 {
        self.0
    }
}

/// Strictly increasing revision attached to a complete credential bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CredentialRevision(NonZeroU64);

impl CredentialRevision {
    pub fn new(value: u64) -> Result<Self, MqttConfigError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or(MqttConfigError::CredentialRevisionInvalid)
    }

    pub fn get(self) -> u64 {
        self.0.get()
    }
}

/// Complete mandatory configuration for one RSS broker-facing persistent session.
pub struct MqttSessionConfig {
    endpoint: MqttsEndpoint,
    client_id: String,
    tls: Arc<ClientConfig>,
    verifier: BrokerAssertionVerifier,
    policy: MqttTopicPolicy,
    session_expiry: SessionExpiry,
    credential_revision: CredentialRevision,
    #[cfg(feature = "test-support")]
    negative_ack_poll_barrier: Option<NegativeAckPollBarrier>,
}

impl std::fmt::Debug for MqttSessionConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MqttSessionConfig")
            .field("endpoint", &self.endpoint)
            .field("client_id", &"<redacted>")
            .field("tls", &"<redacted>")
            .field("policy", &self.policy)
            .field("session_expiry", &self.session_expiry)
            .field("credential_revision", &self.credential_revision)
            .finish()
    }
}

impl MqttSessionConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        endpoint: MqttsEndpoint,
        client_id: impl Into<String>,
        material: MqttTlsMaterial,
        verifier: BrokerAssertionVerifier,
        policy: MqttTopicPolicy,
        session_expiry: SessionExpiry,
        credential_revision: CredentialRevision,
    ) -> Result<Self, MqttConfigError> {
        let client_id = client_id.into();
        validate_client_id(&client_id)?;
        let tls = prepare_tls(material, &client_id)?;
        Ok(Self {
            endpoint,
            client_id,
            tls,
            verifier,
            policy,
            session_expiry,
            credential_revision,
            #[cfg(feature = "test-support")]
            negative_ack_poll_barrier: None,
        })
    }

    #[cfg(feature = "test-support")]
    pub fn with_negative_ack_poll_barrier(mut self, barrier: NegativeAckPollBarrier) -> Self {
        self.negative_ack_poll_barrier = Some(barrier);
        self
    }

    pub fn endpoint(&self) -> &MqttsEndpoint {
        &self.endpoint
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub fn policy(&self) -> &MqttTopicPolicy {
        &self.policy
    }

    pub fn session_expiry(&self) -> SessionExpiry {
        self.session_expiry
    }

    pub fn credential_revision(&self) -> CredentialRevision {
        self.credential_revision
    }

    pub(crate) fn into_prepared(self) -> PreparedSessionConfig {
        PreparedSessionConfig {
            endpoint: self.endpoint,
            client_id: self.client_id,
            tls: self.tls,
            verifier: self.verifier,
            policy: self.policy,
            session_expiry: self.session_expiry,
            credential_revision: self.credential_revision,
            #[cfg(feature = "test-support")]
            negative_ack_poll_barrier: self.negative_ack_poll_barrier,
        }
    }
}

pub(crate) struct PreparedSessionConfig {
    pub(crate) endpoint: MqttsEndpoint,
    pub(crate) client_id: String,
    pub(crate) tls: Arc<ClientConfig>,
    pub(crate) verifier: BrokerAssertionVerifier,
    pub(crate) policy: MqttTopicPolicy,
    pub(crate) session_expiry: SessionExpiry,
    pub(crate) credential_revision: CredentialRevision,
    #[cfg(feature = "test-support")]
    pub(crate) negative_ack_poll_barrier: Option<NegativeAckPollBarrier>,
}

fn validate_client_id(client_id: &str) -> Result<(), MqttConfigError> {
    let valid = !client_id.is_empty()
        && client_id.len() <= MAX_CLIENT_ID_BYTES
        && client_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'));
    if valid {
        Ok(())
    } else {
        tracing::warn!(target: "mqtt", reason = "client_id_charset", "mqtt config rejected");
        Err(MqttConfigError::ClientIdInvalid)
    }
}

pub(crate) fn prepare_tls(
    material: MqttTlsMaterial,
    expected_client_id: &str,
) -> Result<Arc<ClientConfig>, MqttConfigError> {
    if [
        material.ca.expose().len(),
        material.certificate.expose().len(),
        material.private_key.expose().len(),
    ]
    .into_iter()
    .any(|len| len == 0 || len > MAX_TLS_MATERIAL_BYTES)
    {
        tracing::warn!(target: "mqtt", reason = "tls_material_size", "mqtt config rejected");
        return Err(MqttConfigError::TlsMaterialInvalid);
    }
    let ca = CertificateDer::pem_slice_iter(material.ca.expose())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            tracing::warn!(target: "mqtt", reason = "tls_ca_pem", "mqtt config rejected");
            MqttConfigError::TlsMaterialInvalid
        })?;
    if ca.is_empty() {
        tracing::warn!(target: "mqtt", reason = "tls_ca_empty", "mqtt config rejected");
        return Err(MqttConfigError::TlsMaterialInvalid);
    }
    let certificates = CertificateDer::pem_slice_iter(material.certificate.expose())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            tracing::warn!(target: "mqtt", reason = "tls_cert_pem", "mqtt config rejected");
            MqttConfigError::TlsMaterialInvalid
        })?;
    let leaf = certificates.first().ok_or_else(|| {
        tracing::warn!(target: "mqtt", reason = "tls_cert_empty", "mqtt config rejected");
        MqttConfigError::TlsMaterialInvalid
    })?;
    validate_leaf_identity(leaf.as_ref(), expected_client_id)?;
    let private_key =
        PrivateKeyDer::from_pem_slice(material.private_key.expose()).map_err(|_| {
            tracing::warn!(target: "mqtt", reason = "tls_key_pem", "mqtt config rejected");
            MqttConfigError::TlsMaterialInvalid
        })?;

    let mut roots = RootCertStore::empty();
    for certificate in ca {
        roots.add(certificate).map_err(|_| {
            tracing::warn!(target: "mqtt", reason = "tls_root_add", "mqtt config rejected");
            MqttConfigError::TlsMaterialInvalid
        })?;
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| {
            tracing::warn!(target: "mqtt", reason = "tls_protocol", "mqtt config rejected");
            MqttConfigError::TlsMaterialInvalid
        })?;
    let config = builder
        .with_root_certificates(roots)
        .with_client_auth_cert(certificates, private_key)
        .map_err(|_| {
            tracing::warn!(target: "mqtt", reason = "tls_client_auth", "mqtt config rejected");
            MqttConfigError::TlsMaterialInvalid
        })?;
    Ok(Arc::new(config))
}

fn validate_leaf_identity(der: &[u8], expected_client_id: &str) -> Result<(), MqttConfigError> {
    let (remaining, certificate) = X509Certificate::from_der(der).map_err(|_| {
        tracing::warn!(target: "mqtt", reason = "tls_leaf_der", "mqtt config rejected");
        MqttConfigError::TlsMaterialInvalid
    })?;
    if !remaining.is_empty() {
        tracing::warn!(target: "mqtt", reason = "tls_leaf_trailing", "mqtt config rejected");
        return Err(MqttConfigError::TlsMaterialInvalid);
    }
    let mut common_names = certificate.subject().iter_common_name();
    let common_name = common_names
        .next()
        .ok_or(MqttConfigError::ClientIdMismatch)?
        .as_str()
        .map_err(|_| MqttConfigError::ClientIdMismatch)?;
    if common_names.next().is_some() || common_name != expected_client_id {
        tracing::warn!(target: "mqtt", reason = "client_id_mismatch", "mqtt config rejected");
        return Err(MqttConfigError::ClientIdMismatch);
    }
    let eku = certificate
        .extended_key_usage()
        .map_err(|_| MqttConfigError::TlsMaterialInvalid)?
        .ok_or(MqttConfigError::TlsMaterialInvalid)?;
    if !eku.value.client_auth {
        tracing::warn!(target: "mqtt", reason = "tls_eku", "mqtt config rejected");
        return Err(MqttConfigError::TlsMaterialInvalid);
    }
    Ok(())
}

/// Closed non-PII reasons for rejecting MQTT session configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MqttConfigError {
    #[error("mqtt endpoint is invalid")]
    EndpointInvalid,
    #[error("mqtt client id is invalid")]
    ClientIdInvalid,
    #[error("mqtt client id does not match certificate")]
    ClientIdMismatch,
    #[error("mqtt session expiry is out of range")]
    SessionExpiryInvalid,
    #[error("mqtt credential revision is invalid")]
    CredentialRevisionInvalid,
    #[error("mqtt tls material is invalid")]
    TlsMaterialInvalid,
}
