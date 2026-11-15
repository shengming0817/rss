use rss_timeseries::Error;
use rustls_pki_types::pem::PemObject;
use std::num::{NonZeroU32, NonZeroU64};

/// Dedicated credentials. No Debug/serialization surface.
pub struct Credentials {
    pub(crate) user: String,
    password: zeroize::Zeroizing<String>,
}
impl Credentials {
    pub fn new(user: String, password: String) -> Result<Self, Error> {
        if user.is_empty() || password.is_empty() {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            user,
            password: zeroize::Zeroizing::new(password),
        })
    }
}
/// Pure connection inputs: one HTTPS origin, explicit CA and separate service identities.
/// Contains credentials and intentionally has no Debug or serialization surface.
/// Physical resources are created only by `ChOwner::new`.
pub struct ConnectionConfig {
    endpoint: String,
    tls: rustls::ClientConfig,
    writer: Credentials,
    maintenance: Credentials,
}
impl ConnectionConfig {
    pub fn new(
        endpoint: &str,
        ca_pem: &[u8],
        writer: Credentials,
        maintenance: Credentials,
    ) -> Result<Self, Error> {
        let url = url::Url::parse(endpoint).map_err(|_| Error::InvalidInput)?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || url.query().is_some()
            || url.fragment().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
            || !matches!(url.path(), "" | "/")
        {
            return Err(Error::InvalidInput);
        }
        if writer.user == maintenance.user {
            return Err(Error::InvalidInput);
        }
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_pki_types::CertificateDer::pem_slice_iter(ca_pem) {
            roots
                .add(cert.map_err(|_| Error::InvalidInput)?)
                .map_err(|_| Error::InvalidInput)?;
        }
        if roots.is_empty() {
            return Err(Error::InvalidInput);
        }
        let config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| Error::InvalidInput)?
        .with_root_certificates(roots)
        .with_no_client_auth();
        Ok(Self {
            endpoint: endpoint.into(),
            tls: config,
            writer,
            maintenance,
        })
    }
    pub(crate) fn connect(self) -> Connections {
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(self.tls)
            .https_only()
            .enable_http1()
            .build();
        let http =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build(connector);
        let base = clickhouse::Client::with_http_client(http)
            .with_url(&self.endpoint)
            .with_database("rss_ts_ch")
            .with_setting("async_insert", "0")
            .with_setting("insert_deduplicate", "1")
            .with_setting("use_query_cache", "0");
        let writer = authenticated(&base, &self.writer);
        let maintenance = authenticated(&base, &self.maintenance);
        Connections {
            base,
            writer,
            maintenance,
            users: [self.writer.user, self.maintenance.user],
        }
    }
}
// ref: ClickHouse/clickhouse-rs src/lib.rs@v0.15.3
pub(crate) struct Connections {
    base: clickhouse::Client,
    pub(crate) writer: clickhouse::Client,
    pub(crate) maintenance: clickhouse::Client,
    pub(crate) users: [String; 2],
}
impl Connections {
    pub(crate) fn reader(&self, credentials: &Credentials) -> clickhouse::Client {
        authenticated(&self.base, credentials)
    }
}
fn authenticated(base: &clickhouse::Client, credentials: &Credentials) -> clickhouse::Client {
    base.clone()
        .with_user(&credentials.user)
        .with_password(credentials.password.as_str())
}
/// Explicit host caps; there are no unlimited/default budgets.
#[derive(Clone, Debug)]
pub struct Limits {
    /// Shared cap for complete calls and tenant admission on one owner.
    pub max_concurrent_operations: NonZeroU32,
    pub max_points: NonZeroU32,
    pub max_series: NonZeroU32,
    pub max_bytes: NonZeroU32,
    pub max_scan_rows: NonZeroU64,
    pub max_scan_bytes: NonZeroU64,
    pub max_memory_bytes: NonZeroU64,
    pub replay_micros: NonZeroU64,
    pub cursor_micros: NonZeroU64,
}
