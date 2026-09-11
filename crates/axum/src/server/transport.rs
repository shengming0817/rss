//! Product preparation is polled inside the accepted connection's owning future.
use std::{convert::Infallible, future::Future, net::SocketAddr};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};

/// Product-owned preparation of an RSS-accepted socket (for example TLS and admission).
///
/// RSS owns and polls the returned future, bounds its total duration, and drops it on
/// cancellation. Perform admission before expensive handshake work. Keep failure handling
/// inside this future and include it in the preparation budget. Do not spawn detached work:
/// only the returned future and its owned resources belong to the RSS lifecycle.
/// TLS/ALPN, credential verification and product metadata semantics remain the implementer's
/// responsibility. Error values are dropped without formatting; report safe product details
/// inside preparation if needed. Synchronous code and futures must yield cooperatively.
/// ref: tokio-rs/axum axum/src/serve/listener.rs@axum-v0.8.9
/// ref: rustls/tokio-rustls src/server.rs@4f913c754aa4171440e50ceb6a160ceebb0d326e
pub trait ConnectionTransport: Send + Sync + 'static {
    /// IO to be driven by Hyper within the existing connection owner.
    type Io: AsyncRead + AsyncWrite + Unpin + Send + 'static;
    /// Per-connection information copied into requests; never place the ownership guard here.
    type Metadata: Clone + Send + Sync + 'static;
    /// Move-only handoff of connection resources, such as an admission permit.
    /// This type is not required to implement Clone or Sync.
    type Guard: Send + 'static;
    /// A preparation failure affects only this peer. RSS never exports its contents.
    type Error: Send + 'static;

    /// Prepare one socket. The supplied peer came directly from RSS's TCP accept.
    #[allow(
        clippy::type_complexity,
        reason = "explicit IO, evidence and guard avoid another public result abstraction"
    )]
    fn prepare(
        &self,
        stream: TcpStream,
        socket_peer: SocketAddr,
    ) -> impl Future<
        Output = Result<EstablishedTransport<Self::Io, Self::Metadata, Self::Guard>, Self::Error>,
    > + Send;
}

/// Prepared IO and product evidence, with a guard retained through HTTP completion or drop.
/// No peer address can be supplied here: RSS retains the original accepted address.
pub struct EstablishedTransport<I, M, G> {
    pub(super) io: I,
    pub(super) metadata: M,
    pub(super) guard: G,
}

impl<I, M, G> EstablishedTransport<I, M, G> {
    /// Transfer all resources to the RSS connection owner.
    pub fn new(io: I, metadata: M, guard: G) -> Self {
        Self {
            io,
            metadata,
            guard,
        }
    }
}

/// RSS-bound socket peer and product metadata, available via `axum::Extension`.
///
/// INVARIANT: AXUM-ACCEPTED-PEER-01 { level = "Hard", exec = "native-compile", source = "code", native = "private construction binds the TCP accept address to product preparation metadata; no public constructor or deserializer" }.
/// Metadata is only as trustworthy as the product transport that produced it. This boundary
/// prevents network/header construction, not misuse by trusted in-process middleware.
/// Debug/serialization are intentionally absent to avoid exposing credential metadata.
#[derive(Clone)]
pub struct AcceptedConnectionInfo<M> {
    pub(super) socket_peer: SocketAddr,
    pub(super) metadata: M,
}

impl<M> AcceptedConnectionInfo<M> {
    /// Actual socket peer, never derived from forwarding headers.
    pub fn socket_peer(&self) -> SocketAddr {
        self.socket_peer
    }
    /// Product evidence created during successful preparation.
    pub fn metadata(&self) -> &M {
        &self.metadata
    }
}

/// Explicit plain TCP transport, using the same connection owner as prepared transports.
pub struct PlainTransport;

impl ConnectionTransport for PlainTransport {
    type Io = TcpStream;
    type Metadata = ();
    type Guard = ();
    type Error = Infallible;

    async fn prepare(
        &self,
        stream: TcpStream,
        _: SocketAddr,
    ) -> Result<EstablishedTransport<TcpStream, (), ()>, Infallible> {
        // reason: plain TCP has no handshake or product evidence to prepare.
        Ok(EstablishedTransport::new(stream, (), ()))
    }
}
