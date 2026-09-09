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

/// Register an HTTP/1-only TCP listener without starting work.
///
/// Adoption transfers the listener and all connection/request/response-body futures to one
/// runtime task. Cancellation stops accept and disables keep-alive, allowing active responses
/// to finish. A runtime drain timeout drops the remaining futures and reports a failed drain.
/// Handlers must yield; product-spawned work and remote effects remain outside this owner.
/// Each H1 request header has a 30-second read timeout.
/// TLS/ALPN, WebSocket, CONNECT and upgraded IO are not provided.
#[cfg(feature = "http1")]
pub fn serve_http1_registration(
    listener: TcpListener,
    router: Router,
    name: impl Into<String>,
    shutdown_timeout: Duration,
) -> ManagedTaskRegistration {
    registration(listener, router, name, shutdown_timeout, Protocol::Http1)
}

/// Register an HTTP/2 prior-knowledge TCP listener without starting work.
///
/// This listener remains H2-only even when other protocol features are enabled. Adoption
/// transfers all connections and H2 stream futures to one runtime task. Cancellation stops
/// accept and requests graceful shutdown; a runtime drain timeout drops remaining request and
/// response-body futures and reports a failed drain. Handlers must yield and the runtime must
/// remain driven. Product-spawned work, remote effects, TLS/ALPN and tunnels are outside this owner.
#[cfg(feature = "http2")]
pub fn serve_http2_registration(
    listener: TcpListener,
    router: Router,
    name: impl Into<String>,
    shutdown_timeout: Duration,
) -> ManagedTaskRegistration {
    registration(listener, router, name, shutdown_timeout, Protocol::Http2)
}

/// Register one TCP listener accepting HTTP/1 and HTTP/2 prior knowledge without starting work.
///
/// Hyper-util detects the protocol. This does not perform TLS/ALPN or h2c Upgrade negotiation.
/// Adoption transfers every connection and stream future to one runtime task. Cancellation
/// stops accept, cancels pending protocol detection and drains established connections; a
/// runtime drain timeout drops remaining futures and reports a failed drain. Handlers must
/// yield; product-spawned work, remote effects and upgraded IO are outside this owner.
/// The first decoded request must reach the service within 30 seconds (including protocol
/// detection); that deadline is then disabled, so it does not limit handlers or response bodies.
/// H1 request headers also have their own 30-second read timeout.
#[cfg(feature = "auto-protocol")]
pub fn serve_auto_registration(
    listener: TcpListener,
    router: Router,
    name: impl Into<String>,
    shutdown_timeout: Duration,
) -> ManagedTaskRegistration {
    registration(listener, router, name, shutdown_timeout, Protocol::Auto)
}

#[cfg(feature = "http1")]
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(feature = "auto-protocol")]
const ESTABLISHMENT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, PartialEq, Eq)]
enum ConnectionExit {
    Clean,
    PeerError,
    Panic,
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
    Http1,
    #[cfg(feature = "http2")]
    Http2,
    #[cfg(feature = "auto-protocol")]
    Auto,
}

/// INVARIANT: AXUM-CONNECTION-OWNER-01 { level = "Hard", exec = "native-compile", source = "code", native = "private connection futures live in the managed task's FuturesUnordered; HTTP/2 executor enqueues futures into a private connection-owned set, never a Tokio task or upgraded IO handoff" }.
/// ref: hyperium/hyper src/server/conn/http1.rs@v1.10.1
/// ref: hyperium/hyper src/server/conn/http2.rs@v1.10.1
/// ref: hyperium/hyper-util src/server/conn/auto/mod.rs@v0.1.20
/// ref: rust-lang/futures-rs futures-util/src/stream/futures_unordered/mod.rs@0.3.32
fn registration(
    listener: TcpListener,
    router: Router,
    name: impl Into<String>,
    shutdown_timeout: Duration,
    protocol: Protocol,
) -> ManagedTaskRegistration {
    let (start, _) = ManagedTask::prepare(name, shutdown_timeout);
    start.into_registration(move |token| serve_owned(listener, router, token, protocol))
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

async fn serve_owned(
    mut listener: impl Accept,
    router: Router,
    token: CancellationToken,
    protocol: Protocol,
) -> Result<(), ShutdownError> {
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
            accepted = async {
                if let Some(delay) = &mut retry_wait {
                    delay.as_mut().await;
                }
                listener.accept().await
            } => {
                let (stream, peer) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) if recoverable_accept_error(&error) => {
                        if retry_wait.is_none() {
                            tracing::warn!(target: "rss_axum::server", outcome = "accept_retry", "listener recovering");
                        }
                        // ref: tokio-rs/axum axum/src/serve/listener.rs@axum-v0.8.9
                        // Keep the same timer across connection completions. The outer
                        // select continues polling healthy connections and prioritizes cancellation.
                        retry_wait = Some(Box::pin(tokio::time::sleep(ACCEPT_RETRY_DELAY)));
                        continue;
                    }
                    Err(error) => return Err(ShutdownError::new(error)),
                };
                if retry_wait.take().is_some() {
                    tracing::info!(target: "rss_axum::server", outcome = "accept_recovered", "listener recovered");
                }
                // H1 handlers run inside the connection future. Isolate their panics too.
                connections.push(AssertUnwindSafe(connection(
                    stream, router.clone(), peer, token.clone(), protocol,
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

async fn connection(
    stream: TcpStream,
    router: Router,
    peer: std::net::SocketAddr,
    token: CancellationToken,
    protocol: Protocol,
) -> ConnectionExit {
    let io = TokioIo::new(stream);
    let service =
        TowerToHyperService::new(router.layer(axum::Extension(axum::extract::ConnectInfo(peer))));
    match protocol {
        #[cfg(feature = "http1")]
        Protocol::Http1 => {
            let mut builder = hyper::server::conn::http1::Builder::new();
            builder
                .timer(TokioTimer::new())
                .header_read_timeout(HEADER_READ_TIMEOUT);
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
        Protocol::Http2 => {
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
        Protocol::Auto => {
            use hyper::service::Service as _;
            let (sender, pending) = tokio::sync::mpsc::unbounded_channel();
            let mut builder =
                hyper_util::server::conn::auto::Builder::new(ConnectionExecutor(sender));
            builder
                .http1()
                .timer(TokioTimer::new())
                .header_read_timeout(HEADER_READ_TIMEOUT);
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
