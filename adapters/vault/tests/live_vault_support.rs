//! Shared TLS warm-outage helper for the hermetic Vault integration target.

use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::timeout;

const IO_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, thiserror::Error)]
#[error("Vault warm-outage proxy failed")]
pub(crate) struct WarmOutageProxyError;

/// Raw TCP relay preserving end-to-end TLS, with deterministic warm cut.
pub(crate) struct WarmOutageProxy {
    endpoint: String,
    cut_tx: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
}

impl WarmOutageProxy {
    pub(crate) async fn start(addr: &str) -> Result<Self, WarmOutageProxyError> {
        let url = reqwest::Url::parse(addr).map_err(|_| WarmOutageProxyError)?;
        if url.scheme() != "https" || url.username() != "" || url.password().is_some() {
            return Err(WarmOutageProxyError);
        }
        let host = url.host_str().ok_or(WarmOutageProxyError)?.to_owned();
        let port = url.port_or_known_default().ok_or(WarmOutageProxyError)?;
        let listener = timeout(IO_TIMEOUT, TcpListener::bind("127.0.0.1:0"))
            .await
            .map_err(|_| WarmOutageProxyError)?
            .map_err(|_| WarmOutageProxyError)?;
        let local = listener.local_addr().map_err(|_| WarmOutageProxyError)?;
        let endpoint = format!("https://127.0.0.1:{}", local.port());
        let (cut_tx, cut_rx) = watch::channel(false);
        let task = tokio::spawn(run(listener, (host, port), cut_rx));
        Ok(Self {
            endpoint,
            cut_tx,
            task: Some(task),
        })
    }

    pub(crate) fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub(crate) async fn cut(mut self) -> Result<(), WarmOutageProxyError> {
        let _ = self.cut_tx.send(true);
        let mut task = self.task.take().ok_or(WarmOutageProxyError)?;
        match timeout(IO_TIMEOUT, &mut task).await {
            Ok(Ok(())) => Ok(()),
            _ => {
                task.abort();
                Err(WarmOutageProxyError)
            }
        }
    }
}

impl Drop for WarmOutageProxy {
    fn drop(&mut self) {
        let _ = self.cut_tx.send(true);
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn run(listener: TcpListener, upstream: (String, u16), mut cut: watch::Receiver<bool>) {
    let mut relays = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            changed = cut.changed() => if changed.is_err() || *cut.borrow() { break; },
            Some(_) = relays.join_next() => {},
            accepted = listener.accept() => {
                let Ok((mut inbound, _)) = accepted else { break; };
                let upstream = upstream.clone();
                relays.spawn(async move {
                    let Ok(Ok(mut outbound)) = timeout(IO_TIMEOUT, TcpStream::connect(upstream)).await else {
                        let _ = inbound.shutdown().await;
                        return;
                    };
                    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                    let _ = inbound.shutdown().await;
                    let _ = outbound.shutdown().await;
                });
            }
        }
    }
    relays.shutdown().await;
}
