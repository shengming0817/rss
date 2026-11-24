//! Real PostgreSQL frame loss. SQLx receives EOF, never a fabricated provider error.
//! ref: sqlx-postgres/src/transaction.rs@0.9.0; tokio-rustls/src/client.rs@0.26.4
use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject as _};
use std::sync::{
    Arc,
    atomic::{AtomicU8, AtomicUsize, Ordering},
};
use tokio_util::sync::CancellationToken;

pub const LOSE_COMMIT: u8 = 1;
pub const HOLD_RETURN: u8 = 3;
const WAIT_SYNC: u8 = 4;
const WAIT_READY: u8 = 5;

#[derive(Clone, Default)]
pub struct ReturnGate {
    pub held: CancellationToken,
    pub release: CancellationToken,
}
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
};

pub struct Proxy {
    pub gate: ReturnGate,
    pub port: u16,
    pub arm: Arc<AtomicU8>,
    pub lost: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Proxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Proxy {
    pub async fn new(fixture: &testkit::PgTlsFixture) -> anyhow::Result<Self> {
        // Only the private loopback test leg is plaintext; PostgreSQL still requires verified TLS.
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let params = fixture.params().clone();
        let mut roots = rustls::RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(fixture.ca_pem().as_bytes()) {
            roots.add(cert?)?;
        }
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let arm = Arc::new(AtomicU8::new(0));
        let lost = Arc::new(AtomicUsize::new(0));
        let gate = ReturnGate::default();
        let listener_gate = gate.clone();
        let next = arm.clone();
        let losses = lost.clone();
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    incoming=listener.accept()=> {
                        let Ok((client,_))=incoming else { break };
                        let params=params.clone(); let connector=connector.clone();
                        let next=next.clone(); let losses=losses.clone(); let gate=listener_gate.clone();
                        connections.spawn(async move { relay(client,params,connector,next,losses,gate).await });
                    }
                    Some(_) = connections.join_next(), if !connections.is_empty()=> {}
                }
            }
        });
        Ok(Self {
            gate,
            port,
            arm,
            lost,
            task,
        })
    }
}
async fn frame<R: AsyncRead + Unpin>(input: &mut R) -> anyhow::Result<Vec<u8>> {
    let kind = input.read_u8().await?;
    let length = input.read_u32().await?;
    anyhow::ensure!(
        (4..=16 * 1024 * 1024).contains(&length),
        "invalid frame length"
    );
    let mut bytes = vec![0; length as usize + 1];
    bytes[0] = kind;
    bytes[1..5].copy_from_slice(&length.to_be_bytes());
    input.read_exact(&mut bytes[5..]).await?;
    Ok(bytes)
}
async fn relay(
    mut client: TcpStream,
    params: testkit::PgConnParams,
    connector: tokio_rustls::TlsConnector,
    arm: Arc<AtomicU8>,
    lost: Arc<AtomicUsize>,
    gate: ReturnGate,
) -> anyhow::Result<()> {
    let server = connect_upstream(&mut client, params, connector).await?;
    let (mut cr, mut cw) = client.into_split();
    let (mut sr, mut sw) = tokio::io::split(server);
    let active = AtomicU8::new(0);
    let forward = async {
        loop {
            let bytes = match frame(&mut cr).await {
                Ok(bytes) => bytes,
                Err(_) => return Ok::<(), anyhow::Error>(()),
            };
            arm_frame(&bytes, &arm, &active)?;
            sw.write_all(&bytes).await?;
            sw.flush().await?;
        }
    };
    let backward = async {
        loop {
            let bytes = frame(&mut sr).await?;
            if matches!(active.load(Ordering::SeqCst), LOSE_COMMIT | 2) {
                // Consume the real settlement response but never deliver CommandComplete/ReadyForQuery.
                if bytes[0] == b'Z' {
                    lost.fetch_add(1, Ordering::SeqCst);
                    return Ok::<(), anyhow::Error>(());
                }
            } else {
                if bytes.as_slice() == b"Z\0\0\0\x05I" {
                    match active.load(Ordering::SeqCst) {
                        HOLD_RETURN => active.store(WAIT_SYNC, Ordering::SeqCst),
                        WAIT_READY => {
                            gate.held.cancel();
                            gate.release.cancelled().await;
                            active.store(0, Ordering::SeqCst);
                        }
                        _ => {}
                    }
                }
                cw.write_all(&bytes).await?;
                cw.flush().await?;
            }
        }
    };
    tokio::pin!(forward, backward);
    tokio::select! {
        result=&mut backward=>result,
        result=&mut forward=> {
            result?;
            // A client timeout must not silently settle the server transaction. Keep the upstream
            // open until its real ReadyForQuery so recovery has to wait for the outstanding lock.
            if matches!(active.load(Ordering::SeqCst), LOSE_COMMIT | 2) { backward.await } else { Ok(()) }
        }
    }
}

fn arm_frame(bytes: &[u8], arm: &AtomicU8, active: &AtomicU8) -> anyhow::Result<()> {
    let command = if bytes[0] == b'Q' {
        std::str::from_utf8(&bytes[5..])
            .unwrap_or("")
            .trim_end_matches('\0')
    } else {
        ""
    };
    let mode = arm.load(Ordering::SeqCst);
    if ((matches!(mode, LOSE_COMMIT | HOLD_RETURN) && command == "COMMIT")
        || (mode == 2 && command == "ROLLBACK"))
        && arm
            .compare_exchange(mode, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    {
        active.store(mode, Ordering::SeqCst);
    }
    if active.load(Ordering::SeqCst) == WAIT_SYNC {
        anyhow::ensure!(bytes[0] == b'S', "expected standalone SQLx return Sync");
        active.store(WAIT_READY, Ordering::SeqCst);
    }
    Ok(())
}

async fn connect_upstream(
    client: &mut TcpStream,
    params: testkit::PgConnParams,
    connector: tokio_rustls::TlsConnector,
) -> anyhow::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let mut tcp = TcpStream::connect((params.host.as_str(), params.port)).await?;
    tcp.write_all(&[0, 0, 0, 8, 4, 210, 22, 47]).await?;
    anyhow::ensure!(tcp.read_u8().await? == b'S', "upstream TLS required");
    let name = ServerName::try_from(params.host)?;
    let mut server = connector.connect(name, tcp).await?;
    let length = client.read_u32().await?;
    anyhow::ensure!(
        (8..=1024 * 1024).contains(&length),
        "invalid startup length"
    );
    let mut startup = vec![0; length as usize];
    startup[..4].copy_from_slice(&length.to_be_bytes());
    client.read_exact(&mut startup[4..]).await?;
    server.write_all(&startup).await?;
    server.flush().await?;
    Ok(server)
}
