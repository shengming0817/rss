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
/// All three clients use one HTTPS origin/database and an explicit CA trust root.
/// No arbitrary Client, alternate endpoint or HTTP fallback can bypass this boundary.
pub struct Connections {
    pub(crate) reader: clickhouse::Client,
    pub(crate) writer: clickhouse::Client,
    pub(crate) maintenance: clickhouse::Client,
    pub(crate) users: [String; 3],
}
impl Connections {
    pub fn new(
        endpoint: &str,
        ca_pem: &[u8],
        reader: Credentials,
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
        if reader.user == writer.user
            || reader.user == maintenance.user
            || writer.user == maintenance.user
        {
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
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(config)
            .https_only()
            .enable_http1()
            .build();
        let http =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build(connector);
        let base = clickhouse::Client::with_http_client(http)
            .with_url(endpoint)
            .with_database("rss_ts_ch")
            .with_setting("async_insert", "0")
            .with_setting("insert_deduplicate", "1")
            .with_setting("use_query_cache", "0");
        let make = |c: &Credentials| {
            base.clone()
                .with_user(&c.user)
                .with_password(c.password.as_str())
        };
        Ok(Self {
            reader: make(&reader),
            writer: make(&writer),
            maintenance: make(&maintenance),
            users: [reader.user, writer.user, maintenance.user],
        })
    }
}
/// Explicit host caps; there are no unlimited/default budgets.
#[derive(Clone, Debug)]
pub struct Limits {
    pub max_points: NonZeroU32,
    pub max_series: NonZeroU32,
    pub max_bytes: NonZeroU32,
    pub max_scan_rows: NonZeroU64,
    pub max_scan_bytes: NonZeroU64,
    pub max_memory_bytes: NonZeroU64,
    pub replay_micros: NonZeroU64,
    pub cursor_micros: NonZeroU64,
}
