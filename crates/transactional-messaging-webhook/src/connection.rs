use crate::{AuthorizedTarget, Limits};
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Body as _;
use hyper::{Request, Response, body::Incoming, client::conn::http1};
use hyper_util::rt::TokioIo;
use rss_request_context::{Deadline, ExecutionTimer};
use rss_transactional_messaging::policy::within;
use std::{
    collections::HashSet,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll, Waker},
};
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, client::TlsStream};

/// The request future owns both sides of Hyper and the underlying socket.
pub(crate) struct Connection {
    pub(crate) peer: SocketAddr,
    sender: http1::SendRequest<Full<Bytes>>,
    driver: http1::Connection<TokioIo<TlsStream<TcpStream>>, Full<Bytes>>,
}

impl Connection {
    pub(crate) async fn connect(
        target: &AuthorizedTarget,
        limits: Limits,
        timer: &impl ExecutionTimer,
        cutoff: Deadline,
    ) -> Result<Self, ()> {
        let name = match target.url.host().ok_or(())? {
            url::Host::Domain(name) => {
                rustls::pki_types::ServerName::try_from(name.to_owned()).map_err(|_| ())?
            }
            url::Host::Ipv4(ip) => rustls::pki_types::ServerName::IpAddress(ip.into()),
            url::Host::Ipv6(ip) => rustls::pki_types::ServerName::IpAddress(ip.into()),
        };
        let mut seen = HashSet::new();
        let addresses: Vec<_> = target
            .network
            .addresses
            .iter()
            .copied()
            .filter(|a| seen.insert(*a))
            .collect();
        for (index, address) in addresses.iter().enumerate() {
            let now = timer.now();
            let remaining = cutoff.remaining(now).ok_or(())?;
            let count = u32::try_from(addresses.len() - index).map_err(|_| ())?;
            let slice = Deadline::at(now + remaining / count);
            let dial = |_| async {
                let stream = TcpStream::connect(address).await.map_err(|_| ())?;
                let peer = stream.peer_addr().map_err(|_| ())?;
                if peer != *address || !target.network.permits(peer.ip()) {
                    return Err(());
                }
                let tls = TlsConnector::from(target.trust.config.clone())
                    .connect(name.clone(), stream)
                    .await
                    .map_err(|_| ())?;
                let (sender, driver) = http1::Builder::new()
                    .max_headers(limits.headers)
                    .max_buf_size(limits.header_bytes)
                    .handshake(TokioIo::new(tls))
                    .await
                    .map_err(|_| ())?;
                let mut connection = Self {
                    peer,
                    sender,
                    driver,
                };
                tokio::select! {
                    biased;
                    _ = &mut connection.driver => Err(()),
                    ready = connection.sender.ready() => ready.map(|()| connection).map_err(|_| ()),
                }
            };
            if let Ok(Ok(connection)) = within(timer, slice, dial).await {
                return Ok(connection);
            }
        }
        Err(())
    }

    // Poll before checkout to let Hyper notice idle EOF or unsolicited bytes.
    pub(crate) fn ready_now(&mut self) -> bool {
        let mut cx = Context::from_waker(Waker::noop());
        Pin::new(&mut self.driver).poll(&mut cx).is_pending() && self.sender.is_ready()
    }

    // Only use frames already available. Reception of final headers decides the outcome.
    pub(crate) fn finish_response(&mut self, body: &mut Incoming) -> bool {
        const MAX_BYTES: usize = 8192;
        const MAX_FRAMES: usize = 16;
        let mut bytes = 0;
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..MAX_FRAMES {
            if body.is_end_stream() {
                return self.ready_now();
            }
            let mut frame = Pin::new(&mut *body).poll_frame(&mut cx);
            if frame.is_pending() {
                if Pin::new(&mut self.driver).poll(&mut cx).is_ready() {
                    return false;
                }
                frame = Pin::new(&mut *body).poll_frame(&mut cx);
            }
            match frame {
                Poll::Ready(Some(Ok(frame))) => {
                    bytes += frame.data_ref().map_or(0, Bytes::len);
                    if bytes > MAX_BYTES {
                        return false;
                    }
                }
                Poll::Ready(None) => return self.ready_now(),
                _ => return false,
            }
        }
        body.is_end_stream() && self.ready_now()
    }

    /// A completed driver must never be polled again, even if headers were delivered.
    pub(crate) async fn send(
        &mut self,
        request: Request<Full<Bytes>>,
    ) -> Result<(Response<Incoming>, bool), hyper::Error> {
        let response = self.sender.send_request(request);
        tokio::pin!(response);
        tokio::select! {
            biased;
            result = &mut response => result.map(|r| (r, true)),
            _ = &mut self.driver => response.await.map(|r| (r, false)),
        }
    }
}
