use anyhow::Context as _;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac as _};
use rss_examples::webhook::{Endpoint, Timer};
use rss_request_context::TenantId;
use rss_transactional_messaging::{outbox::PendingMessage, policy::OperationDeadline};
use rss_transactional_messaging_webhook::*;
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpListener,
    sync::{Mutex, mpsc},
    task::JoinHandle,
};

pub const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
#[derive(Clone)]
pub enum Mode {
    Reply(Vec<u8>),
    KeepAlive(Vec<u8>),
    DropResponse,
    StallHeaders,
    StallTls,
}
pub fn response(status: u16) -> Mode {
    Mode::Reply(
        format!("HTTP/1.1 {status} Fixture\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .into_bytes(),
    )
}
pub struct Received {
    pub connection: usize,
    pub local: std::net::SocketAddr,
    pub sni: Option<String>,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
    pub request_line: String,
}
impl Received {
    pub fn verify(&self, secret: &[u8]) -> anyhow::Result<()> {
        let id = self.headers.get("webhook-id").context("missing id")?;
        let time = self
            .headers
            .get("webhook-timestamp")
            .context("missing timestamp")?;
        let signatures = self
            .headers
            .get("webhook-signature")
            .context("missing signature")?;
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(secret)
            .map_err(|_| anyhow::anyhow!("fixture key"))?;
        mac.update(format!("{id}.{time}.").as_bytes());
        mac.update(&self.body);
        let expected = mac.finalize().into_bytes();
        anyhow::ensure!(
            signatures
                .split(' ')
                .filter_map(|s| s.strip_prefix("v1,"))
                .any(|s| STANDARD
                    .decode(s)
                    .is_ok_and(|bytes| bytes.as_slice() == expected.as_slice())),
            "signature mismatch"
        );
        Ok(())
    }
}
pub struct Receiver {
    pub endpoint: Endpoint,
    pub mode: Arc<Mutex<Mode>>,
    pub connections: Arc<AtomicUsize>,
    pub closed: Arc<AtomicUsize>,
    pub handshakes: Arc<AtomicUsize>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    records: mpsc::Receiver<Received>,
    task: Option<JoinHandle<()>>,
}
impl Receiver {
    pub async fn new(mode: Mode) -> anyhow::Result<Self> {
        Self::on(TcpListener::bind("127.0.0.1:0").await?, mode).await
    }
    pub async fn on(listener: TcpListener, mode: Mode) -> anyhow::Result<Self> {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let address = listener.local_addr()?;
        let endpoint = Endpoint {
            tenant: TENANT.into(),
            url: format!("https://localhost:{}/events?version=1", address.port()),
            address,
            ca: cert.cert.der().to_vec(),
            secret: vec![11; 32],
        };
        let mode = Arc::new(Mutex::new(mode));
        let connections = Arc::new(AtomicUsize::new(0));
        let closed = Arc::new(AtomicUsize::new(0));
        let (tx, records) = mpsc::channel(32);
        let handshakes = Arc::new(AtomicUsize::new(0));
        let server = Server {
            acceptor,
            mode: mode.clone(),
            records: tx,
            closed: closed.clone(),
            handshakes: handshakes.clone(),
        };
        let accepted = connections.clone();
        let (stop, mut stopping) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let mut clients = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    _ = &mut stopping => break,
                    Some(_) = clients.join_next(), if !clients.is_empty() => (),
                    accepted_socket = listener.accept() => {
                        let Ok((stream, _)) = accepted_socket else { break; };
                        let id = accepted.fetch_add(1, Ordering::SeqCst);
                        let server = server.clone();
                        clients.spawn(async move {
                            let _ = tokio::time::timeout(Duration::from_secs(10), server.serve(stream, id)).await;
                        });
                    }
                }
            }
            clients.shutdown().await;
        });
        Ok(Self {
            endpoint,
            stop: Some(stop),
            handshakes,
            mode,
            connections,
            closed,
            records,
            task: Some(task),
        })
    }
    pub fn publisher(&self) -> anyhow::Result<WebhookPublisher<Endpoint, Timer, Timer>> {
        Ok(WebhookPublisher::new(
            self.endpoint.clone(),
            Timer,
            Timer,
            rss_examples::webhook::limits()?,
        ))
    }
    pub fn assert_no_request(&mut self) -> anyhow::Result<()> {
        anyhow::ensure!(
            matches!(
                self.records.try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ),
            "unexpected HTTP request"
        );
        Ok(())
    }
    pub async fn received(&mut self) -> anyhow::Result<Received> {
        tokio::time::timeout(Duration::from_secs(3), self.records.recv())
            .await?
            .context("receiver stopped")
    }
    pub async fn stop(mut self) -> anyhow::Result<()> {
        if let Some(task) = self.task.take() {
            self.stop.take();
            let result = task.await;
            anyhow::ensure!(
                result.is_ok() || result.is_err_and(|e| e.is_cancelled()),
                "receiver panicked"
            );
        }
        Ok(())
    }
}
impl Drop for Receiver {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
#[derive(Clone)]
struct Server {
    acceptor: tokio_rustls::TlsAcceptor,
    mode: Arc<Mutex<Mode>>,
    records: mpsc::Sender<Received>,
    closed: Arc<AtomicUsize>,
    handshakes: Arc<AtomicUsize>,
}
impl Server {
    async fn serve(&self, mut stream: tokio::net::TcpStream, id: usize) -> anyhow::Result<()> {
        let local = stream.local_addr()?;
        if matches!(*self.mode.lock().await, Mode::StallTls) {
            let mut buffer = [0; 4096];
            while stream.read(&mut buffer).await? != 0 {}
            self.closed.fetch_add(1, Ordering::SeqCst);
            return Ok(());
        }
        let mut stream = self.acceptor.accept(stream).await?;
        self.handshakes.fetch_add(1, Ordering::SeqCst);
        let sni = stream.get_ref().1.server_name().map(str::to_owned);
        loop {
            let mut first = [0];
            if !read_peer(&mut stream, &mut first).await? {
                self.closed.fetch_add(1, Ordering::SeqCst);
                return Ok(());
            }
            let record = read_request(&mut stream, first[0], id, local, sni.clone()).await?;
            let mode = self.mode.lock().await.clone();
            self.records
                .send(record)
                .await
                .map_err(|_| anyhow::anyhow!("fixture record channel closed"))?;
            match mode {
                Mode::KeepAlive(bytes) => {
                    stream.write_all(&bytes).await?;
                    stream.flush().await?;
                }
                Mode::Reply(bytes) => {
                    stream.write_all(&bytes).await?;
                    stream.flush().await?;
                    return Ok(());
                }
                Mode::StallHeaders => {
                    anyhow::ensure!(
                        !read_peer(&mut stream, &mut first).await?,
                        "unexpected pipelined request"
                    );
                    self.closed.fetch_add(1, Ordering::SeqCst);
                    return Ok(());
                }
                Mode::DropResponse | Mode::StallTls => return Ok(()),
            }
        }
    }
}
async fn read_peer(
    stream: &mut (impl tokio::io::AsyncRead + Unpin),
    buf: &mut [u8],
) -> std::io::Result<bool> {
    use std::io::ErrorKind;
    match stream.read(buf).await {
        Ok(n) => Ok(n > 0),
        Err(e)
            if matches!(
                e.kind(),
                ErrorKind::UnexpectedEof
                    | ErrorKind::ConnectionReset
                    | ErrorKind::ConnectionAborted
            ) =>
        {
            Ok(false)
        }
        Err(e) => Err(e),
    }
}
async fn read_request(
    stream: &mut (impl tokio::io::AsyncRead + Unpin),
    first: u8,
    connection: usize,
    local: std::net::SocketAddr,
    sni: Option<String>,
) -> anyhow::Result<Received> {
    let mut header = vec![first];
    while !header.ends_with(b"\r\n\r\n") {
        anyhow::ensure!(header.len() < 16384, "fixture header budget");
        header.push(stream.read_u8().await?);
    }
    let text = String::from_utf8(header)?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().context("request line")?.to_owned();
    let headers: BTreeMap<String, String> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    let length: usize = headers.get("content-length").context("length")?.parse()?;
    anyhow::ensure!(length <= 65536, "fixture body budget");
    let mut body = vec![0; length];
    stream.read_exact(&mut body).await?;
    Ok(Received {
        headers,
        body,
        request_line,
        connection,
        local,
        sni,
    })
}
pub fn message(id: &str) -> anyhow::Result<PendingMessage<Vec<u8>>> {
    rss_examples::webhook::message(TenantId::parse(TENANT)?, id)
}
pub fn deadline() -> OperationDeadline {
    OperationDeadline::from_remaining(Duration::from_secs(2))
}
pub async fn wait_count(counter: &AtomicUsize, value: usize) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(2), async {
        while counter.load(Ordering::SeqCst) < value {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    Ok(())
}
