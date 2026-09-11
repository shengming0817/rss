//! Real TLS consumer fixture. TLS, client verification and admission belong to this consumer.
//! ref: rustls/tokio-rustls src/server.rs@4f913c754aa4171440e50ceb6a160ceebb0d326e
use axum::{Extension, Router, routing::get};
use rss_axum::{
    AcceptedConnectionInfo, ConnectionTransport, EstablishedTransport, Http1ServePolicy,
    ServePolicy,
};
use rss_runtime::{ManagedTaskRegistration, ShutdownStack, TotalDrainBudget};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Notify, OwnedSemaphorePermit, Semaphore},
};
use tokio_rustls::{
    TlsAcceptor, TlsConnector,
    rustls::{
        self,
        pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName},
    },
};

pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub const WAIT: Duration = Duration::from_secs(3);

/// Consumer-private certificate construction, after rustls's real client verifier succeeds.
#[derive(Clone)]
pub struct CertificateEvidence {
    chain: Arc<Vec<CertificateDer<'static>>>,
}
impl CertificateEvidence {
    pub fn chain(&self) -> &[CertificateDer<'static>] {
        &self.chain
    }
}

pub struct TlsTransport {
    acceptor: TlsAcceptor,
    pub slots: Arc<Semaphore>,
    pub entered: Arc<Notify>,
}
impl ConnectionTransport for TlsTransport {
    type Io = tokio_rustls::server::TlsStream<TcpStream>;
    type Metadata = CertificateEvidence;
    type Guard = OwnedSemaphorePermit;
    type Error = std::io::Error;
    async fn prepare(
        &self,
        stream: TcpStream,
        _: SocketAddr,
    ) -> Result<EstablishedTransport<Self::Io, Self::Metadata, Self::Guard>, Self::Error> {
        // Product admission occurs before expensive TLS, and its permit crosses the HTTP lifetime.
        let permit = self
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(std::io::Error::other)?;
        self.entered.notify_one();
        let stream = self.acceptor.accept(stream).await?;
        let chain = stream
            .get_ref()
            .1
            .peer_certificates()
            .ok_or_else(|| std::io::Error::other("client certificate required"))?
            .to_vec();
        Ok(EstablishedTransport::new(
            stream,
            CertificateEvidence {
                chain: Arc::new(chain),
            },
            permit,
        ))
    }
}

pub struct Fixture {
    pub server: Arc<rustls::ServerConfig>,
    pub client: Arc<rustls::ClientConfig>,
    pub anonymous: Arc<rustls::ClientConfig>,
    pub foreign: Arc<rustls::ClientConfig>,
    expected: Vec<CertificateDer<'static>>,
}
impl Fixture {
    pub fn new(protocols: &[&[u8]]) -> Result<Self, Error> {
        let server_cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let client_cert = rcgen::generate_simple_self_signed(vec!["client".into()])?;
        let foreign_cert = rcgen::generate_simple_self_signed(vec!["foreign".into()])?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut clients = rustls::RootCertStore::empty();
        clients.add(client_cert.cert.der().clone())?;
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(clients),
            provider.clone(),
        )
        .build()?;
        let mut server = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()?
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![server_cert.cert.der().clone()],
                PrivatePkcs8KeyDer::from(server_cert.signing_key.serialize_der()).into(),
            )?;
        server.alpn_protocols = protocols.iter().map(|p| p.to_vec()).collect();
        server.send_tls13_tickets = 0;
        server.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        let mut roots = rustls::RootCertStore::empty();
        roots.add(server_cert.cert.der().clone())?;
        let builder = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots);
        let anonymous = builder.clone().with_no_client_auth();
        let foreign = builder.clone().with_client_auth_cert(
            vec![foreign_cert.cert.der().clone()],
            PrivatePkcs8KeyDer::from(foreign_cert.signing_key.serialize_der()).into(),
        )?;
        let expected = vec![client_cert.cert.der().clone()];
        let client = builder.with_client_auth_cert(
            expected.clone(),
            PrivatePkcs8KeyDer::from(client_cert.signing_key.serialize_der()).into(),
        )?;
        Ok(Self {
            server: Arc::new(server),
            client: Arc::new(client),
            anonymous: Arc::new(anonymous),
            foreign: Arc::new(foreign),
            expected,
        })
    }
    pub fn transport(&self) -> TlsTransport {
        TlsTransport {
            acceptor: TlsAcceptor::from(self.server.clone()),
            slots: Arc::new(Semaphore::new(128)),
            entered: Arc::new(Notify::new()),
        }
    }
    pub fn router(&self) -> Router {
        let expected = self.expected.clone();
        Router::new().route(
            "/",
            get(
                move |Extension(info): Extension<AcceptedConnectionInfo<CertificateEvidence>>| {
                    let verified = info.metadata().chain() == expected;
                    async move { format!("{}|{verified}", info.socket_peer()) }
                },
            ),
        )
    }
}

pub fn serve_policy() -> Result<ServePolicy, Error> {
    Ok(ServePolicy::new(
        128,
        Duration::from_secs(8),
        Duration::from_secs(30),
        Duration::from_secs(10),
    )?)
}
pub fn http1_policy() -> Result<Http1ServePolicy, Error> {
    Ok(Http1ServePolicy::new(
        serve_policy()?,
        Duration::from_secs(10),
        64,
        32768,
    )?)
}

pub fn owner(registration: ManagedTaskRegistration) -> Result<ShutdownStack, Error> {
    let mut owner = ShutdownStack::try_new(
        TotalDrainBudget::new(Duration::from_secs(12))?,
        Arc::new(Timer),
    )?;
    let mut startup = owner.startup()?;
    startup.stage_task_with_token(registration);
    startup.commit().finish();
    Ok(owner)
}

pub async fn connect(
    addr: SocketAddr,
    config: Arc<rustls::ClientConfig>,
    protocol: &[u8],
) -> Result<(tokio_rustls::client::TlsStream<TcpStream>, SocketAddr), Error> {
    let mut config = (*config).clone();
    config.alpn_protocols = vec![protocol.to_vec()];
    let stream = TcpStream::connect(addr).await?;
    let local = stream.local_addr()?;
    let tls = TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("localhost")?, stream)
        .await?;
    Ok((tls, local))
}

pub async fn request(addr: SocketAddr, config: Arc<rustls::ClientConfig>) -> Result<(), Error> {
    tokio::time::timeout(WAIT, async {
        let (mut stream, local) = connect(addr, config, b"http/1.1").await?;
        stream.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nForwarded: for=203.0.113.7\r\nX-Forwarded-For: 203.0.113.7\r\nConnection: close\r\n\r\n").await?;
        // Read the complete known response, not TLS close_notify (not a managed HTTP promise).
        let expected = format!("{local}|true");
        let mut response = Vec::new();
        loop {
            response.push(stream.read_u8().await?);
            if response.ends_with(expected.as_bytes()) { break; }
            if response.len() > 4096 { return Err("unbounded or incorrect response".into()); }
        }
        if !response.starts_with(b"HTTP/1.1 200") { return Err("request was not served".into()); }
        Ok::<(), Error>(())
    }).await?
}

pub async fn smoke() -> Result<(), Error> {
    let fixture = Fixture::new(&[b"http/1.1"])?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let transport = fixture.transport();
    let slots = transport.slots.clone();
    let owner = owner(rss_axum::serve_http1_registration(
        listener,
        fixture.router(),
        transport,
        "tls-example",
        http1_policy()?,
    ))?;
    request(address, fixture.client).await?;
    if !owner.shutdown().join().await?.is_clean() || slots.available_permits() != 128 {
        return Err("TLS owner did not drain and release its permit".into());
    }
    if TcpStream::connect(address).await.is_ok() {
        return Err("listener survived shutdown".into());
    }
    println!("TLS_BEHAVIOR_PASS peer=socket certificate=verified guard=released drain=clean");
    Ok(())
}

pub struct Timer;
impl rss_request_context::Clock for Timer {
    #[allow(clippy::disallowed_methods)] // reason: concrete consumer clock owns the Tokio time domain.
    fn now(&self) -> std::time::Instant {
        tokio::time::Instant::now().into_std()
    }
}
impl rss_request_context::ExecutionTimer for Timer {
    async fn sleep_until(&self, deadline: rss_request_context::Deadline) {
        tokio::task::unconstrained(tokio::time::sleep_until(deadline.instant().into())).await;
    }
}
