//! Connection configuration; production verifies server identity.
use crate::PgError;
use rustls::RootCertStore;
use rustls_pki_types::{CertificateDer, pem::PemObject as _};
use sqlx::postgres::{PgConnectOptions, PgSslMode};
use std::sync::Arc;
use std::time::Duration;
const APPLICATION_NAME: &str = "rss-transactional-messaging-postgres";
/// Password material is redacted and has no `Display` implementation.
#[derive(Clone)]
pub struct PgPassword(zeroize::Zeroizing<String>);

impl PgPassword {
    /// Own a credential in zeroizing storage; empty credentials are rejected at connect.
    pub fn new(secret: impl Into<String>) -> Self {
        Self(zeroize::Zeroizing::new(secret.into()))
    }
}

impl std::fmt::Debug for PgPassword {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PgPassword(<redacted>)")
    }
}

/// Validated, non-empty explicit CA bundle appended to SQLx's roots under `VerifyFull`.
#[derive(Clone)]
pub struct PgPrivateCa {
    pem: Arc<[u8]>,
}

#[derive(Debug, thiserror::Error)]
#[error("invalid PostgreSQL private CA PEM")]
/// The PEM bundle is empty, malformed, or contains an unusable certificate.
pub struct PgPrivateCaError;

impl PgPrivateCa {
    /// Validate a non-empty PEM certificate bundle immediately, without connecting.
    pub fn from_pem(pem: Vec<u8>) -> Result<Self, PgPrivateCaError> {
        let certificates = CertificateDer::pem_slice_iter(&pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| PgPrivateCaError)?;
        if certificates.is_empty() {
            return Err(PgPrivateCaError);
        }
        let mut roots = RootCertStore::empty();
        for certificate in certificates {
            roots
                .add(certificate.into_owned())
                .map_err(|_| PgPrivateCaError)?;
        }
        Ok(Self {
            pem: Arc::from(pem),
        })
    }
}

impl std::fmt::Debug for PgPrivateCa {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PgPrivateCa(<redacted>)")
    }
}

#[derive(Clone, Debug)]
enum PgTlsTrust {
    PrivateCa(PgPrivateCa),
    #[cfg(any(test, feature = "test-support"))]
    PlaintextForTest,
}

/// Security-closed PostgreSQL pool configuration. Production always uses `VerifyFull`.
#[derive(Clone, Debug)]
pub struct PgConfig {
    host: String,
    port: u16,
    database: String,
    username: String,
    password: PgPassword,
    tls: PgTlsTrust,
    pub(crate) min_connections: u32,
    pub(crate) max_connections: u32,
    pub(crate) acquire_timeout: Duration,
}

impl PgConfig {
    /// Configure VerifyFull using an explicit CA and the supplied host as server identity.
    /// Defaults: 0 minimum / 10 maximum connections and a 5-second connect/probe budget.
    /// Identity, credential and pool bounds are validated by `PgRuntime::connect`.
    #[must_use]
    pub fn new(
        host: impl Into<String>,
        port: u16,
        database: impl Into<String>,
        username: impl Into<String>,
        password: PgPassword,
        private_ca: PgPrivateCa,
    ) -> Self {
        Self::new_with_tls(
            host,
            port,
            database,
            username,
            password,
            PgTlsTrust::PrivateCa(private_ca),
        )
    }

    /// Disable TLS only for opt-in test fixtures; never use for production credentials.
    /// Pool defaults and deferred validation match `new`.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn new_for_test_plaintext(
        host: impl Into<String>,
        port: u16,
        database: impl Into<String>,
        username: impl Into<String>,
        password: PgPassword,
    ) -> Self {
        Self::new_with_tls(
            host,
            port,
            database,
            username,
            password,
            PgTlsTrust::PlaintextForTest,
        )
    }

    fn new_with_tls(
        host: impl Into<String>,
        port: u16,
        database: impl Into<String>,
        username: impl Into<String>,
        password: PgPassword,
        tls: PgTlsTrust,
    ) -> Self {
        Self {
            host: host.into(),
            port,
            database: database.into(),
            username: username.into(),
            password,
            tls,
            min_connections: 0,
            max_connections: 10,
            acquire_timeout: Duration::from_secs(5),
        }
    }

    #[must_use]
    /// Override pool bounds; connect rejects zero maximum or minimum above maximum.
    pub fn with_pool_limits(mut self, min_connections: u32, max_connections: u32) -> Self {
        self.min_connections = min_connections;
        self.max_connections = max_connections;
        self
    }

    #[must_use]
    /// Override the positive shared connect/probe cutoff and pool acquisition bound.
    /// A zero duration is rejected at connect, before network I/O.
    pub fn with_acquire_timeout(mut self, acquire_timeout: Duration) -> Self {
        self.acquire_timeout = acquire_timeout;
        self
    }

    pub(crate) fn validate(&self) -> Result<(), PgError> {
        if self.host.trim().is_empty()
            || self.database.trim().is_empty()
            || self.username.trim().is_empty()
            || self.password.0.is_empty()
            || self.port == 0
        {
            return Err(PgError::InvalidConnectionConfig);
        }
        if self.max_connections == 0 || self.min_connections > self.max_connections {
            return Err(PgError::InvalidPoolLimits);
        }
        if self.acquire_timeout.is_zero() {
            return Err(PgError::InvalidAcquireTimeout);
        }
        Ok(())
    }

    pub(crate) fn connect_options(&self) -> PgConnectOptions {
        let options = PgConnectOptions::new()
            .host(&self.host)
            .port(self.port)
            .database(&self.database)
            .username(&self.username)
            .password(&self.password.0)
            .application_name(APPLICATION_NAME);
        match &self.tls {
            PgTlsTrust::PrivateCa(ca) => options
                .ssl_mode(PgSslMode::VerifyFull)
                .ssl_root_cert_from_pem(ca.pem.to_vec()),
            #[cfg(any(test, feature = "test-support"))]
            PgTlsTrust::PlaintextForTest => options.ssl_mode(PgSslMode::Disable),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> PgConfig {
        PgConfig::new_for_test_plaintext("localhost", 5432, "rss", "rss", PgPassword::new("secret"))
    }

    #[allow(clippy::expect_used)]
    // reason: generated test certificate must be accepted by the focused constructor assertions.
    fn private_ca_pem() -> Vec<u8> {
        let mut params = rcgen::CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        rcgen::CertifiedIssuer::self_signed(
            params,
            rcgen::KeyPair::generate().expect("generate CA key"),
        )
        .expect("generate CA certificate")
        .pem()
        .into_bytes()
    }

    #[test]
    fn config_validation_is_database_free() {
        assert!(matches!(
            config().with_pool_limits(2, 1).validate(),
            Err(PgError::InvalidPoolLimits)
        ));
        assert!(matches!(
            config().with_acquire_timeout(Duration::ZERO).validate(),
            Err(PgError::InvalidAcquireTimeout)
        ));
    }

    #[test]
    fn private_ca_accepts_ca_certificate_and_rejects_invalid_pem() {
        assert!(PgPrivateCa::from_pem(Vec::new()).is_err());
        assert!(PgPrivateCa::from_pem(b"not a certificate".to_vec()).is_err());
        assert!(PgPrivateCa::from_pem(private_ca_pem()).is_ok());
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: generated PEM is valid UTF-8 and its absence from SQLx options must fail the test.
    fn production_connect_options_force_verify_full_with_explicit_ca() {
        let pem = private_ca_pem();
        let expected_root = String::from_utf8(pem.clone()).expect("PEM is UTF-8");
        let config = PgConfig::new(
            "db.example.test",
            5432,
            "rss",
            "rss",
            PgPassword::new("secret"),
            PgPrivateCa::from_pem(pem).expect("valid CA PEM"),
        );

        let options = config.connect_options();
        assert!(matches!(options.get_ssl_mode(), PgSslMode::VerifyFull));
        let explicit_root = sqlx::ConnectOptions::to_url_lossy(&options)
            .query_pairs()
            .find_map(|(name, value)| (name == "sslrootcert").then(|| value.into_owned()));
        assert_eq!(explicit_root.as_deref(), Some(expected_root.as_str()));
    }
}
