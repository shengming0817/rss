use rss_request_context::{Clock, Deadline, ExecutionTimer};
use rss_transactional_messaging::policy::OperationDeadline;
use rumqttc::{PersistedSession, SessionStore, SessionStoreKey};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::{sync::Arc, time::Duration};

pub struct Timer;
impl Timer {
    #[allow(clippy::disallowed_methods)] // reason: sole injected real monotonic clock construction.
    pub fn new() -> Self {
        Self
    }
}
impl Clock for Timer {
    #[allow(clippy::disallowed_methods)] // reason: injected clock owns the time origin.
    fn now(&self) -> std::time::Instant {
        tokio::time::Instant::now().into_std()
    }
}
impl ExecutionTimer for Timer {
    async fn sleep_until(&self, deadline: Deadline) {
        tokio::task::unconstrained(async move {
            tokio::time::sleep(deadline.remaining(self.now()).unwrap_or_default()).await;
        })
        .await;
    }
}
#[allow(clippy::panic)] // reason: bounded constant test deadline cannot overflow a fresh test clock.
pub fn deadline(clock: &impl Clock) -> OperationDeadline {
    Deadline::from_timeout(clock, Duration::from_secs(3))
        .map(|d| OperationDeadline::from_cutoff(d, clock))
        .unwrap_or_else(|_| unreachable!())
}

pub fn ready_generation(
    state: &tokio::sync::watch::Receiver<rss_mqtt::ConnectionState>,
) -> anyhow::Result<u64> {
    match *state.borrow() {
        rss_mqtt::ConnectionState::Ready { generation, .. } => Ok(generation),
        other => anyhow::bail!("fixture connection is not ready: {other:?}"),
    }
}

// Retire is synchronous admission only. Broker replay can arrive before the new SUBACK.
pub async fn wait_reconnected(
    state: &tokio::sync::watch::Receiver<rss_mqtt::ConnectionState>,
    before: u64,
) -> anyhow::Result<()> {
    let mut state = state.clone();
    let ready = tokio::time::timeout(Duration::from_secs(5), state.wait_for(|value| {
        matches!(value, rss_mqtt::ConnectionState::Ready { generation, .. } if *generation > before)
            || matches!(value, rss_mqtt::ConnectionState::Failed(_) | rss_mqtt::ConnectionState::Closed)
    })).await??;
    anyhow::ensure!(
        matches!(*ready, rss_mqtt::ConnectionState::Ready { generation, .. } if generation > before),
        "fixture reconnect failed: {ready:?}"
    );
    Ok(())
}

#[derive(Debug)]
pub struct FileStore {
    dir: tempfile::TempDir,
    gate: tokio::sync::Mutex<()>,
}
impl FileStore {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            dir: tempfile::tempdir()?,
            gate: tokio::sync::Mutex::new(()),
        })
    }
    fn path(&self, key: &SessionStoreKey) -> std::path::PathBuf {
        // Collision-free byte encoding; test backend accepts arbitrary caller scope and client ID.
        let name: String = format!("{}\0{}", key.scope(), key.client_id())
            .bytes()
            .map(|v| format!("{v:02x}"))
            .collect();
        self.dir.path().join(name)
    }
}
impl SessionStore for FileStore {
    fn load<'a>(
        &'a self,
        key: &'a SessionStoreKey,
    ) -> SessionStoreFuture<'a, Option<PersistedSession>> {
        Box::pin(async move {
            let _guard = self.gate.lock().await;
            match tokio::fs::read(self.path(key)).await {
                Ok(bytes) => Ok(Some(PersistedSession::decode(&bytes)?)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e.into()),
            }
        })
    }
    fn save<'a>(
        &'a self,
        key: &'a SessionStoreKey,
        session: &'a PersistedSession,
    ) -> SessionStoreFuture<'a, ()> {
        Box::pin(async move {
            use tokio::io::AsyncWriteExt;
            let _guard = self.gate.lock().await;
            let path = self.path(key);
            let temp = path.with_extension("new");
            let mut file = tokio::fs::File::create(&temp).await?;
            file.write_all(&session.encode()?).await?;
            file.sync_all().await?;
            drop(file);
            tokio::fs::rename(temp, path).await?;
            tokio::fs::File::open(self.dir.path())
                .await?
                .sync_all()
                .await?;
            Ok(())
        })
    }
    fn clear<'a>(&'a self, key: &'a SessionStoreKey) -> SessionStoreFuture<'a, ()> {
        Box::pin(async move {
            let _guard = self.gate.lock().await;
            match tokio::fs::remove_file(self.path(key)).await {
                Ok(()) => {
                    tokio::fs::File::open(self.dir.path())
                        .await?
                        .sync_all()
                        .await?;
                    Ok(())
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e.into()),
            }
        })
    }
}
pub fn tls(
    fixture: &testkit::MqttTlsFixture,
    wrong_ca: bool,
    client_auth: bool,
) -> anyhow::Result<Arc<rustls::ClientConfig>> {
    let ca = if wrong_ca {
        fixture.wrong_ca_pem()
    } else {
        fixture.ca_pem()
    };
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(ca.as_bytes()) {
        roots.add(cert?)?;
    }
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots);
    let config = if client_auth {
        builder.with_client_auth_cert(
            CertificateDer::pem_slice_iter(fixture.client_cert_pem().as_bytes())
                .collect::<Result<Vec<_>, _>>()?,
            PrivateKeyDer::from_pem_slice(fixture.client_key_pem().as_bytes())?,
        )?
    } else {
        builder.with_no_client_auth()
    };
    Ok(Arc::new(config))
}
pub fn config(
    fixture: &testkit::MqttTlsFixture,
    id: &str,
    filters: Vec<String>,
) -> anyhow::Result<rss_mqtt::MqttConfig> {
    Ok(rss_mqtt::MqttConfig::new(
        "localhost",
        fixture.port(),
        format!("rss-{}-{id}", std::process::id()),
        "mqtt-integration",
        tls(fixture, false, true)?,
        rss_mqtt::Limits::new(32, 32, 32, 65536)?,
    )?
    .credentials("mqtt", b"fixture-only".to_vec())?
    .subscriptions(filters)?)
}

pub type SessionStoreFuture<'a, T> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<T, rumqttc::SessionStoreError>> + Send + 'a>,
>;

pub mod wire;

pub mod proxy;
