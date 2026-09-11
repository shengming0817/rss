//! Connection futures owned directly by the one runtime task, never detached.
#[cfg(feature = "http2")]
use std::{future::Future, pin::Pin};
use std::{panic::AssertUnwindSafe, time::Duration};

use axum::Router;
use futures::{FutureExt, StreamExt, stream::FuturesUnordered};
use hyper_util::rt::TokioTimer;
use hyper_util::{rt::TokioIo, service::TowerToHyperService};
use rss_runtime::{ManagedTask, ManagedTaskRegistration, ShutdownError};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

mod policy;
mod transport;
#[cfg(feature = "http1")]
pub use policy::Http1ServePolicy;
pub use policy::{ServePolicy, ServePolicyError};
pub use transport::{
    AcceptedConnectionInfo, ConnectionTransport, EstablishedTransport, PlainTransport,
};

/// Register a prepared HTTP/1 listener without starting work.
/// Products provide TLS/ALPN and admission through `transport`. RSS owns preparation, IO,
/// requests and response bodies. Cancellation stops preparation and gracefully drains HTTP;
/// runtime timeout drops remaining futures. Handlers and preparation must yield.
/// Upgraded IO, product-spawned work and remote effects are outside this owner.
#[cfg(feature = "http1")]
pub fn serve_http1_registration<T: ConnectionTransport>(
    listener: TcpListener,
    router: Router,
    transport: T,
    name: impl Into<String>,
    policy: Http1ServePolicy,
) -> ManagedTaskRegistration {
    registration(listener, router, transport, name, Protocol::Http1(policy))
}

/// Register an HTTP/2-only listener with explicit transport and lifecycle policy.
/// RSS retains ownership of preparation and every H2 stream future, including response bodies.
/// Products choose TLS/ALPN; this constructor always serves HTTP/2. Cancellation requests
/// graceful shutdown; runtime timeout drops remaining futures. All work must yield.
#[cfg(feature = "http2")]
pub fn serve_http2_registration<T: ConnectionTransport>(
    listener: TcpListener,
    router: Router,
    transport: T,
    name: impl Into<String>,
    policy: ServePolicy,
) -> ManagedTaskRegistration {
    registration(listener, router, transport, name, Protocol::Http2(policy))
}

/// Register an HTTP/1 and HTTP/2 listener with explicit transport and lifecycle policy.
/// Hyper-util detects the protocol on prepared IO. Products own TLS/ALPN consistency; RSS
/// does not negotiate ALPN or h2c Upgrade. Preparation is bounded by policy, then the first
/// request must reach the service within 30 seconds. This latter deadline does not limit
/// admitted handlers or response bodies. Cancellation stops detection and drains HTTP;
/// runtime timeout drops remaining work. All work must yield.
#[cfg(feature = "auto-protocol")]
pub fn serve_auto_registration<T: ConnectionTransport>(
    listener: TcpListener,
    router: Router,
    transport: T,
    name: impl Into<String>,
    policy: Http1ServePolicy,
) -> ManagedTaskRegistration {
    registration(listener, router, transport, name, Protocol::Auto(policy))
}

#[cfg(feature = "auto-protocol")]
const ESTABLISHMENT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, PartialEq, Eq)]
enum ConnectionExit {
    Clean,
    PeerError,
    Panic,
    PreparationError,
    PreparationTimeout,
    #[cfg(feature = "auto-protocol")]
    EstablishmentTimeout,
}

fn classify<E: Into<Box<dyn std::error::Error + Send + Sync>>>(
    result: Result<(), E>,
    closing: bool,
) -> ConnectionExit {
    match result {
        Ok(()) => ConnectionExit::Clean,
        Err(error) => {
            let error = error.into();
            // Auto's ReadVersion::cancel deliberately returns Interrupted during drain.
            if closing
                && error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::Interrupted)
            {
                ConnectionExit::Clean
            } else {
                ConnectionExit::PeerError
            }
        }
    }
}

fn record_connection(result: std::thread::Result<ConnectionExit>) {
    record_exit(result.unwrap_or(ConnectionExit::Panic), "connection");
}

fn record_exit(exit: ConnectionExit, scope: &'static str) {
    let outcome = match exit {
        // reason: clean completion is not a failure diagnostic.
        ConnectionExit::Clean => return,
        ConnectionExit::PeerError => "peer_error",
        ConnectionExit::Panic => "panic",
        ConnectionExit::PreparationError => "preparation_error",
        ConnectionExit::PreparationTimeout => "preparation_timeout",
        #[cfg(feature = "auto-protocol")]
        ConnectionExit::EstablishmentTimeout => "establishment_timeout",
    };
    // Only closed, low-cardinality classifications: never error text or panic payloads.
    // ref: tokio-rs/axum axum/src/serve/mod.rs@axum-v0.8.9
    tracing::debug!(target: "rss_axum::server", outcome, scope, "transport work ended");
}

#[derive(Clone, Copy)]
enum Protocol {
    #[cfg(feature = "http1")]
    Http1(Http1ServePolicy),
    #[cfg(feature = "http2")]
    Http2(ServePolicy),
    #[cfg(feature = "auto-protocol")]
    Auto(Http1ServePolicy),
}

impl Protocol {
    fn policy(self) -> ServePolicy {
        match self {
            #[cfg(feature = "http1")]
            Self::Http1(policy) => policy.serve,
            #[cfg(feature = "http2")]
            Self::Http2(policy) => policy,
            #[cfg(feature = "auto-protocol")]
            Self::Auto(policy) => policy.serve,
        }
    }
}

/// INVARIANT: AXUM-CONNECTION-OWNER-01 { level = "Hard", exec = "native-compile", source = "code", native = "private preparation-to-HTTP futures and their guards live in the managed task's one FuturesUnordered; HTTP/2 executor enqueues futures into a private connection-owned set, never a Tokio task or upgraded IO handoff" }.
/// ref: hyperium/hyper src/server/conn/http1.rs@v1.10.1
/// ref: hyperium/hyper src/server/conn/http2.rs@v1.10.1
/// ref: hyperium/hyper-util src/server/conn/auto/mod.rs@v0.1.20
/// ref: rust-lang/futures-rs futures-util/src/stream/futures_unordered/mod.rs@0.3.32
fn registration<T: ConnectionTransport>(
    listener: TcpListener,
    router: Router,
    transport: T,
    name: impl Into<String>,
    protocol: Protocol,
) -> ManagedTaskRegistration {
    let name = name.into();
    let (start, _) = ManagedTask::prepare(name.clone(), protocol.policy().shutdown_timeout);
    start.into_registration(move |token| async move {
        serve_owned(listener, router, transport, token, protocol, &name).await
    })
}

const ACCEPT_RETRY_DELAY: Duration = Duration::from_secs(1);

fn recoverable_accept_error(error: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    matches!(
        error.kind(),
        ErrorKind::ConnectionRefused
            | ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionReset
            | ErrorKind::Interrupted
            | ErrorKind::WouldBlock
            | ErrorKind::TimedOut
            | ErrorKind::NetworkDown
            | ErrorKind::NetworkUnreachable
            | ErrorKind::HostUnreachable
            | ErrorKind::OutOfMemory
    ) || resource_pressure(error.raw_os_error())
}

#[cfg(unix)]
fn resource_pressure(code: Option<i32>) -> bool {
    matches!(
        code,
        Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM)
    )
}

#[cfg(windows)]
fn resource_pressure(code: Option<i32>) -> bool {
    use windows_sys::Win32::Networking::WinSock::{WSAEMFILE, WSAENOBUFS};
    matches!(code, Some(WSAEMFILE | WSAENOBUFS))
}

#[cfg(not(any(unix, windows)))]
fn resource_pressure(_code: Option<i32>) -> bool {
    // reason: no known platform errno mapping; unrecognized errors remain terminal.
    false
}

// Private transport seam: production ownership stays with TcpListener.
trait Accept: Send {
    fn accept(
        &mut self,
    ) -> impl std::future::Future<Output = std::io::Result<(TcpStream, std::net::SocketAddr)>> + Send;
}

impl Accept for TcpListener {
    async fn accept(&mut self) -> std::io::Result<(TcpStream, std::net::SocketAddr)> {
        TcpListener::accept(self).await
    }
}

// Registration names are public operator labels, never tenant/device identifiers or secrets.
struct ListenerLogName<'a>(&'a str);

impl rss_redact::Redact for ListenerLogName<'_> {
    fn redact_scoped(&self, scope: rss_redact::RedactScope) -> String {
        let public_label = !self.0.is_empty()
            && self.0.len() <= 64
            && self
                .0
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
        if matches!(scope, rss_redact::RedactScope::ServerLog) && public_label {
            self.0.into()
        } else {
            "<redacted>".into()
        }
    }
}

impl ListenerLogName<'_> {
    fn recovering(&self) {
        tracing::warn!(target: "rss_axum::server", outcome = "accept_retry", listener = %rss_redact::safe(self, rss_redact::RedactScope::ServerLog), "listener recovering");
    }

    fn recovered(&self) {
        tracing::info!(target: "rss_axum::server", outcome = "accept_recovered", listener = %rss_redact::safe(self, rss_redact::RedactScope::ServerLog), "listener recovered");
    }
}

async fn accept_with_retry(
    listener: &mut impl Accept,
    retry_wait: &mut Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
    name: &ListenerLogName<'_>,
) -> Result<Option<(TcpStream, std::net::SocketAddr)>, ShutdownError> {
    if let Some(delay) = retry_wait {
        delay.as_mut().await;
    }
    match listener.accept().await {
        Ok(accepted) => {
            if retry_wait.take().is_some() {
                name.recovered();
            }
            Ok(Some(accepted))
        }
        Err(error) if recoverable_accept_error(&error) => {
            if retry_wait.is_none() {
                name.recovering();
            }
            // ref: tokio-rs/axum axum/src/serve/listener.rs@axum-v0.8.9
            // Retain this timer across select cancellation by connection completions.
            *retry_wait = Some(Box::pin(tokio::time::sleep(ACCEPT_RETRY_DELAY)));
            Ok(None)
        }
        Err(error) => Err(ShutdownError::new(error)),
    }
}

async fn serve_owned<T: ConnectionTransport>(
    mut listener: impl Accept,
    router: Router,
    transport: T,
    token: CancellationToken,
    protocol: Protocol,
    name: &str,
) -> Result<(), ShutdownError> {
    let name = ListenerLogName(name);
    let transport = std::sync::Arc::new(transport);
    let mut connections = FuturesUnordered::new();
    let mut retry_wait: Option<std::pin::Pin<Box<tokio::time::Sleep>>> = None;
    loop {
        tokio::select! {
            biased;
            () = token.cancelled() => break,
            // Completed/failed peers leave the set without terminating unrelated clients.
            Some(result) = connections.next(), if !connections.is_empty() => {
                record_connection(result);
            },
            accepted = accept_with_retry(&mut listener, &mut retry_wait, &name), if connections.len() < protocol.policy().connection_limit => {
                let Some((stream, peer)) = accepted? else { continue; };
                // H1 handlers run inside the connection future. Isolate their panics too.
                connections.push(AssertUnwindSafe(prepared_connection(
                    stream, router.clone(), peer, transport.clone(), token.clone(), protocol,
                )).catch_unwind());
            }
        }
    }
    drop(listener);
    while let Some(result) = connections.next().await {
        record_connection(result);
    }
    Ok(())
}

async fn prepared_connection<T: ConnectionTransport>(
    stream: TcpStream,
    router: Router,
    peer: std::net::SocketAddr,
    transport: std::sync::Arc<T>,
    token: CancellationToken,
    protocol: Protocol,
) -> ConnectionExit {
    // The factory call also executes inside this async body and its outer catch_unwind.
    let prepared = tokio::select! {
        biased;
        () = token.cancelled() => return ConnectionExit::Clean,
        result = tokio::time::timeout(protocol.policy().preparation_timeout, async { transport.prepare(stream, peer).await }) => {
            match result {
                Ok(Ok(prepared)) => prepared,
                Ok(Err(_)) => return ConnectionExit::PreparationError,
                Err(_) => return ConnectionExit::PreparationTimeout,
            }
        }
    };
    if token.is_cancelled() {
        return ConnectionExit::Clean;
    }
    let EstablishedTransport {
        io,
        metadata,
        guard,
    } = prepared;
    let info = AcceptedConnectionInfo {
        socket_peer: peer,
        metadata,
    };
    let result = connection(io, router, info, token, protocol).await;
    // Keep product permits alive for the complete HTTP lifetime, never in cloned metadata.
    drop(guard);
    result
}

async fn connection<I, M>(
    stream: I,
    router: Router,
    info: AcceptedConnectionInfo<M>,
    token: CancellationToken,
    protocol: Protocol,
) -> ConnectionExit
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    M: Clone + Send + Sync + 'static,
{
    let io = TokioIo::new(stream);
    let service = TowerToHyperService::new(router.layer(axum::Extension(info)));
    match protocol {
        #[cfg(feature = "http1")]
        Protocol::Http1(policy) => {
            let mut builder = hyper::server::conn::http1::Builder::new();
            builder
                .timer(TokioTimer::new())
                .header_read_timeout(policy.header_read_timeout)
                .max_headers(policy.max_headers)
                .max_buf_size(policy.max_buffer_size);
            let connection = builder.serve_connection(io, service);
            tokio::pin!(connection);
            tokio::select! {
                biased;
                () = token.cancelled() => {
                    connection.as_mut().graceful_shutdown();
                    classify(connection.await, true)
                }
                result = &mut connection => classify(result, false)
            }
        }
        #[cfg(feature = "http2")]
        Protocol::Http2(_) => {
            let (sender, pending) = tokio::sync::mpsc::unbounded_channel();
            let mut builder = hyper::server::conn::http2::Builder::new(ConnectionExecutor(sender));
            builder.timer(TokioTimer::new());
            drive_streams(
                builder.serve_connection(io, service),
                pending,
                token,
                |connection| {
                    connection.graceful_shutdown();
                },
            )
            .await
        }
        #[cfg(feature = "auto-protocol")]
        Protocol::Auto(policy) => {
            use hyper::service::Service as _;
            let (sender, pending) = tokio::sync::mpsc::unbounded_channel();
            let mut builder =
                hyper_util::server::conn::auto::Builder::new(ConnectionExecutor(sender));
            builder
                .http1()
                .timer(TokioTimer::new())
                .header_read_timeout(policy.header_read_timeout)
                .max_headers(policy.max_headers)
                .max_buf_size(policy.max_buffer_size);
            builder.http2().timer(TokioTimer::new());
            let admitted = CancellationToken::new();
            let started = admitted.clone();
            let service = hyper::service::service_fn(move |request| {
                started.cancel();
                service.call(request)
            });
            let connection = drive_streams(
                builder.serve_connection(io, service),
                pending,
                token,
                |connection| connection.graceful_shutdown(),
            );
            tokio::pin!(connection);
            // Upstream hides its detection state. Bound establishment until the first service
            // call instead of duplicating the preface parser or timing the entire connection.
            tokio::select! {
                biased;
                result = &mut connection => result,
                () = admitted.cancelled() => connection.await,
                () = tokio::time::sleep(ESTABLISHMENT_TIMEOUT) => ConnectionExit::EstablishmentTimeout,
            }
        }
    }
}

#[cfg(feature = "http2")]
type StreamJob = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Hyper's required executor seam feeds the owning connection, not a runtime spawn API.
#[cfg(feature = "http2")]
#[derive(Clone)]
struct ConnectionExecutor(tokio::sync::mpsc::UnboundedSender<StreamJob>);

#[cfg(feature = "http2")]
impl<F> hyper::rt::Executor<F> for ConnectionExecutor
where
    F: Future<Output = ()> + Send + 'static,
{
    fn execute(&self, future: F) {
        // A failed send drops the future immediately when its connection owner is gone.
        let _ = self.0.send(Box::pin(async move {
            // Isolate a stream panic without allowing its task to escape the connection.
            if AssertUnwindSafe(future).catch_unwind().await.is_err() {
                record_exit(ConnectionExit::Panic, "stream");
            }
        }));
    }
}

#[cfg(feature = "http2")]
async fn drive_streams<C, E>(
    connection: C,
    mut pending: tokio::sync::mpsc::UnboundedReceiver<StreamJob>,
    token: CancellationToken,
    mut shutdown: impl FnMut(Pin<&mut C>),
) -> ConnectionExit
where
    C: Future<Output = Result<(), E>>,
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    tokio::pin!(connection);
    // Active and queued jobs are dropped whenever this driver returns or is cancelled.
    let mut tasks = FuturesUnordered::<StreamJob>::new();
    let mut closing = false;
    loop {
        tokio::select! {
            biased;
            () = token.cancelled(), if !closing => {
                closing = true;
                shutdown(connection.as_mut());
            }
            result = &mut connection => return classify(result, closing),
            Some(task) = pending.recv() => tasks.push(task),
            Some(()) = tasks.next(), if !tasks.is_empty() => {},
        }
    }
}

#[cfg(all(test, feature = "http1"))]
mod accept_tests;

#[cfg(all(test, feature = "http1"))]
mod race_tests;
