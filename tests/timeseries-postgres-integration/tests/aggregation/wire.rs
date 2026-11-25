//! Byte counters on an opaque TLS stream; no plaintext or credentials are inspected.
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};
pub(super) struct Wire {
    pub port: u16,
    sent: Arc<AtomicU64>,
    received: Arc<AtomicU64>,
    task: JoinHandle<()>,
}
impl Wire {
    pub async fn new(host: String, port: u16) -> anyhow::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let local = listener.local_addr()?.port();
        let sent = Arc::new(AtomicU64::new(0));
        let received = Arc::new(AtomicU64::new(0));
        let counters = (sent.clone(), received.clone());
        let task = tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                let Ok(server) = TcpStream::connect((host.as_str(), port)).await else {
                    break;
                };
                let (sent, received) = counters.clone();
                tokio::spawn(async move {
                    let (cr, cw) = client.into_split();
                    let (sr, sw) = server.into_split();
                    let _ = tokio::try_join!(copy(cr, sw, sent), copy(sr, cw, received));
                });
            }
        });
        Ok(Self {
            port: local,
            sent,
            received,
            task,
        })
    }
    pub fn counts(&self) -> (u64, u64) {
        (
            self.sent.load(Ordering::SeqCst),
            self.received.load(Ordering::SeqCst),
        )
    }
}
impl Drop for Wire {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn copy(
    mut read: impl AsyncRead + Unpin,
    mut write: impl AsyncWrite + Unpin,
    count: Arc<AtomicU64>,
) -> std::io::Result<()> {
    let mut buffer = [0u8; 16384];
    loop {
        let n = read.read(&mut buffer).await?;
        if n == 0 {
            return write.shutdown().await;
        }
        count.fetch_add(n as u64, Ordering::SeqCst);
        write.write_all(&buffer[..n]).await?;
    }
}
