//! HTTP/2 connection futures owned directly by the one runtime task, never detached.
use std::{future::Future, panic::AssertUnwindSafe, pin::Pin, time::Duration};

use axum::Router;
use futures::{FutureExt, StreamExt, stream::FuturesUnordered};
use hyper::server::conn::http2;
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use rss_runtime::{ManagedTask, ManagedTaskRegistration, ShutdownError};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

/// Consume a bound socket and configured Router without starting work.
///
/// The runtime registration owns one task whose future directly contains every HTTP/2
/// connection. Cancellation stops accept, asks connections to finish gracefully, and waits for
/// their completion. A runtime drain timeout cancels this same owner, including all remaining
/// connection/request/response-body futures; there are no independently running connection tasks.
/// As with all Tokio cancellation, handlers must yield; product-spawned work and remote effects
/// are outside this ownership boundary. Keep the originating runtime driven for cancellation.
///
/// This adapter accepts HTTP/2 prior knowledge over the supplied TCP listener. HTTP/1 and
/// upgrade fallback are not supported. TLS/ALPN termination belongs to the product edge;
/// CONNECT/WebSocket tunnels are outside this owner.
///
/// INVARIANT: AXUM-CONNECTION-OWNER-01 { level = "Hard", exec = "native-compile", source = "code", native = "private connection futures live in the managed task's FuturesUnordered; HTTP/2 executor enqueues futures into a private connection-owned set, never a Tokio task or upgraded IO handoff" }.
/// ref: hyperium/hyper src/server/conn/http2.rs@v1.10.1
/// ref: rust-lang/futures-rs futures-util/src/stream/futures_unordered/mod.rs@0.3.32
pub fn serve_registration(
    listener: TcpListener,
    router: Router,
    name: impl Into<String>,
    shutdown_timeout: Duration,
) -> ManagedTaskRegistration {
    let (start, _) = ManagedTask::prepare(name, shutdown_timeout);
    start.into_registration(move |token| serve_owned(listener, router, token))
}

async fn serve_owned(
    listener: TcpListener,
    router: Router,
    token: CancellationToken,
) -> Result<(), ShutdownError> {
    let mut connections = FuturesUnordered::new();
    loop {
        tokio::select! {
            biased;
            () = token.cancelled() => break,
            // Completed/failed peers leave the set without terminating unrelated clients.
            Some(()) = connections.next(), if !connections.is_empty() => {},
            accepted = listener.accept() => {
                let (stream, _) = accepted.map_err(ShutdownError::new)?;
                connections.push(connection(stream, router.clone(), token.clone()));
            }
        }
    }
    drop(listener);
    while connections.next().await.is_some() {}
    Ok(())
}

type StreamJob = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Hyper's required executor seam feeds the owning connection, not a runtime spawn API.
#[derive(Clone)]
struct ConnectionExecutor(tokio::sync::mpsc::UnboundedSender<StreamJob>);

impl<F> hyper::rt::Executor<F> for ConnectionExecutor
where
    F: Future<Output = ()> + Send + 'static,
{
    fn execute(&self, future: F) {
        // A failed send drops the future immediately when its connection owner is gone.
        let _ = self.0.send(Box::pin(async move {
            // Isolate a stream panic without allowing its task to escape the connection.
            let _ = AssertUnwindSafe(future).catch_unwind().await;
        }));
    }
}

async fn connection(stream: TcpStream, router: Router, token: CancellationToken) {
    let (sender, mut pending) = tokio::sync::mpsc::unbounded_channel();
    let mut builder = http2::Builder::new(ConnectionExecutor(sender));
    builder.timer(TokioTimer::new());
    let connection =
        builder.serve_connection(TokioIo::new(stream), TowerToHyperService::new(router));
    tokio::pin!(connection);
    let mut tasks = FuturesUnordered::<StreamJob>::new();
    let mut closing = false;
    loop {
        tokio::select! {
            biased;
            () = token.cancelled(), if !closing => {
                closing = true;
                connection.as_mut().graceful_shutdown();
            }
            _ = &mut connection => break,
            Some(task) = pending.recv() => tasks.push(task),
            Some(()) = tasks.next(), if !tasks.is_empty() => {},
        }
    }
    // Both active and queued jobs are dropped with this connection. Nothing is detached.
}
