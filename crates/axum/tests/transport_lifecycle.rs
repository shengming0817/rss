#![cfg(feature = "http1")]
#[path = "support/timer.rs"]
mod timer;

use axum::{Extension, Router, routing::get};
use rss_axum::{
    AcceptedConnectionInfo, ConnectionTransport, EstablishedTransport, Http1ServePolicy,
    ServePolicy,
};
use rss_runtime::{ShutdownStack, TotalDrainBudget};
use std::{
    cell::Cell,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Notify,
};

const WAIT: Duration = Duration::from_secs(3);

#[derive(Clone, Copy)]
enum First {
    Ready,
    Pending,
    Error,
    FactoryPanic,
    PollPanic,
}

struct Guard {
    active: Arc<AtomicUsize>,
    _not_sync: Cell<()>,
}
impl Drop for Guard {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
}

struct Probe {
    first: First,
    calls: AtomicUsize,
    active: Arc<AtomicUsize>,
    entered: Arc<Notify>,
}
impl ConnectionTransport for Probe {
    type Io = TcpStream;
    type Metadata = usize;
    type Guard = Guard;
    type Error = &'static str;
    #[allow(clippy::panic)] // reason: exercise both factory and poll panic isolation.
    fn prepare(
        &self,
        stream: TcpStream,
        _: SocketAddr,
    ) -> impl Future<Output = Result<EstablishedTransport<TcpStream, usize, Guard>, Self::Error>> + Send
    {
        let id = self.calls.fetch_add(1, Ordering::SeqCst);
        if id == 0 && matches!(self.first, First::FactoryPanic) {
            panic!("private-factory-secret");
        }
        async move {
            self.active.fetch_add(1, Ordering::SeqCst);
            let guard = Guard {
                active: self.active.clone(),
                _not_sync: Cell::new(()),
            };
            self.entered.notify_one();
            if id == 0 {
                match self.first {
                    First::Pending => std::future::pending::<()>().await,
                    First::Error => return Err("private-error-secret"),
                    First::PollPanic => panic!("private-poll-secret"),
                    First::Ready | First::FactoryPanic => {}
                }
            }
            Ok(EstablishedTransport::new(stream, id, guard))
        }
    }
}

#[allow(clippy::unwrap_used)] // reason: bounded fixture setup and valid explicit policies.
async fn start(
    first: First,
    limit: usize,
    preparation: Duration,
    drain: Duration,
    router: Router,
) -> (SocketAddr, ShutdownStack, Arc<AtomicUsize>, Arc<Notify>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let active = Arc::new(AtomicUsize::new(0));
    let entered = Arc::new(Notify::new());
    let probe = Probe {
        first,
        calls: AtomicUsize::new(0),
        active: active.clone(),
        entered: entered.clone(),
    };
    let mut owner = ShutdownStack::try_new(
        TotalDrainBudget::new(WAIT).unwrap(),
        Arc::new(timer::TokioTimer),
    )
    .unwrap();
    let policy = Http1ServePolicy::new(
        ServePolicy::new(limit, preparation, drain).unwrap(),
        WAIT,
        64,
        32768,
    )
    .unwrap();
    owner
        .startup()
        .unwrap()
        .stage_task_with_token(rss_axum::serve_http1_registration(
            listener,
            router,
            probe,
            "transport",
            policy,
        ));
    (addr, owner, active, entered)
}

fn router() -> Router {
    Router::new().route(
        "/",
        get(
            |Extension(info): Extension<AcceptedConnectionInfo<usize>>| async move {
                format!("{}:{}", info.socket_peer(), info.metadata())
            },
        ),
    )
}

#[allow(clippy::unwrap_used)] // reason: real socket request and EOF are bounded assertions.
async fn request(addr: SocketAddr, expected_id: usize) {
    tokio::time::timeout(WAIT, async {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let peer = stream.local_addr().unwrap();
        stream.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nForwarded: for=203.0.113.7\r\nX-Forwarded-For: 203.0.113.7\r\nConnection: close\r\n\r\n").await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.ends_with(&format!("{peer}:{expected_id}")), "{response}");
    }).await.unwrap();
}

#[tokio::test]
#[allow(clippy::unwrap_used)] // reason: wait for actual preparation before asserting cancellation.
async fn slow_preparation_does_not_block_healthy_peer_and_cancels_with_guard() {
    let (addr, owner, active, entered) = start(First::Pending, 2, WAIT, WAIT, router()).await;
    let _slow = TcpStream::connect(addr).await.unwrap();
    tokio::time::timeout(WAIT, entered.notified())
        .await
        .unwrap();
    request(addr, 1).await;
    assert_eq!(active.load(Ordering::SeqCst), 1);
    assert!(owner.shutdown().join().await.unwrap().is_clean());
    assert_eq!(active.load(Ordering::SeqCst), 0);
}

#[tokio::test]
#[allow(clippy::unwrap_used)] // reason: first timeout must free the only connection slot.
async fn capacity_includes_preparation_and_timeout_releases_slot() {
    let (addr, owner, active, entered) = start(
        First::Pending,
        1,
        Duration::from_millis(200),
        WAIT,
        router(),
    )
    .await;
    let _slow = TcpStream::connect(addr).await.unwrap();
    tokio::time::timeout(WAIT, entered.notified())
        .await
        .unwrap();
    let healthy = request(addr, 1);
    tokio::pin!(healthy);
    assert!(
        tokio::time::timeout(Duration::from_millis(30), &mut healthy)
            .await
            .is_err()
    );
    assert_eq!(active.load(Ordering::SeqCst), 1);
    healthy.await;
    assert!(owner.shutdown().join().await.unwrap().is_clean());
    assert_eq!(active.load(Ordering::SeqCst), 0);
}

#[tokio::test]
#[allow(clippy::unwrap_used)] // reason: peer failure must not stop the managed listener.
async fn factory_panic_poll_panic_and_error_isolate_the_peer() {
    for first in [First::FactoryPanic, First::PollPanic, First::Error] {
        let (addr, owner, active, _) = start(first, 1, WAIT, WAIT, router()).await;
        let mut bad = TcpStream::connect(addr).await.unwrap();
        let mut byte = [0];
        let result = tokio::time::timeout(WAIT, bad.read(&mut byte))
            .await
            .unwrap();
        assert!(matches!(result, Ok(0)) || result.is_err());
        request(addr, 1).await;
        assert!(owner.shutdown().join().await.unwrap().is_clean());
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
#[allow(clippy::unwrap_used)] // reason: stalled handler makes guard retention and forced drain observable.
async fn http_timeout_releases_the_non_sync_guard_after_handler_starts() {
    let entered = Arc::new(Notify::new());
    let app = Router::new().route(
        "/",
        get({
            let entered = entered.clone();
            move || async move {
                entered.notify_one();
                std::future::pending::<&'static str>().await
            }
        }),
    );
    let (addr, owner, active, _) =
        start(First::Ready, 1, WAIT, Duration::from_millis(30), app).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    tokio::time::timeout(WAIT, entered.notified())
        .await
        .unwrap();
    assert_eq!(active.load(Ordering::SeqCst), 1);
    let receipt = owner.shutdown().join().await.unwrap();
    assert!(!receipt.is_clean());
    assert_eq!(active.load(Ordering::SeqCst), 0);
}

#[test]
#[allow(clippy::unwrap_used)] // reason: destroying the actual runtime must retire its owned preparation.
fn external_runtime_termination_drops_preparation_and_guard() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (owner, active, _client) = runtime.block_on(async {
        let (addr, owner, active, entered) = start(First::Pending, 1, WAIT, WAIT, router()).await;
        let client = TcpStream::connect(addr).await.unwrap();
        tokio::time::timeout(WAIT, entered.notified())
            .await
            .unwrap();
        (owner, active, client)
    });
    assert_eq!(active.load(Ordering::SeqCst), 1);
    drop(runtime);
    assert_eq!(active.load(Ordering::SeqCst), 0);
    drop(owner);
}
