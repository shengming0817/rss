//! Transparent MQTT TLS proxy: only PUBACK frames from the real broker can be withheld.
use super::wire::Peer;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_rustls::TlsConnector;

pub struct AckLossProxy {
    pub peer_tls: Arc<rustls::ClientConfig>,
    pub port: u16,
    pub dropped: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}
impl AckLossProxy {
    pub async fn start(
        broker_port: u16,
        broker_tls: Arc<rustls::ClientConfig>,
    ) -> anyhow::Result<Self> {
        let peer = Peer::new().await?;
        let port = peer.listener.local_addr()?.port();
        let peer_tls = peer.client_tls.clone();
        let dropped = Arc::new(AtomicUsize::new(0));
        let count = dropped.clone();
        let task = tokio::spawn(async move {
            let incoming = peer
                .acceptor
                .accept(peer.listener.accept().await?.0)
                .await?;
            let upstream = TlsConnector::from(broker_tls)
                .connect(
                    rustls_pki_types::ServerName::try_from("localhost")?,
                    tokio::net::TcpStream::connect(("localhost", broker_port)).await?,
                )
                .await?;
            let (mut cr, mut cw) = tokio::io::split(incoming);
            let (mut sr, mut sw) = tokio::io::split(upstream);
            tokio::select! {
                result=tokio::io::copy(&mut cr,&mut sw)=>{ result?; }
                result=forward(&mut sr,&mut cw,count)=>{ result?; }
            }
            Ok(())
        });
        Ok(Self {
            peer_tls,
            port,
            dropped,
            task,
        })
    }
}
impl Drop for AckLossProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn forward(
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    dropped: Arc<AtomicUsize>,
) -> anyhow::Result<()> {
    loop {
        let first = reader.read_u8().await?;
        let mut data = vec![first];
        let mut len = 0;
        let mut multiplier = 1;
        for _ in 0..4 {
            let b = reader.read_u8().await?;
            data.push(b);
            len += (b as usize & 127) * multiplier;
            if b & 128 == 0 {
                break;
            }
            multiplier *= 128;
        }
        anyhow::ensure!(len < 65536, "proxy packet limit");
        let offset = data.len();
        data.resize(offset + len, 0);
        reader.read_exact(&mut data[offset..]).await?;
        if first >> 4 == 4 {
            dropped.fetch_add(1, Ordering::AcqRel);
        } else {
            writer.write_all(&data).await?;
            writer.flush().await?;
        }
    }
}
