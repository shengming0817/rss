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
    calls: Arc<AtomicUsize>,
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
) -> (
    SocketAddr,
    ShutdownStack,
    Arc<AtomicUsize>,
    Arc<Notify>,
    Arc<AtomicUsize>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let active = Arc::new(AtomicUsize::new(0));
    let entered = Arc::new(Notify::new());
    let calls = Arc::new(AtomicUsize::new(0));
    let probe = Probe {
        first,
        calls: calls.clone(),
        active: active.clone(),
        entered: entered.clone(),
    };
    let mut owner = ShutdownStack::try_new(
        TotalDrainBudget::new(WAIT).unwrap(),
        Arc::new(timer::TokioTimer),
    )
    .unwrap();
    let policy = Http1ServePolicy::new(
        ServePolicy::new(limit, preparation, Duration::from_secs(30), drain).unwrap(),
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
    (addr, owner, active, entered, calls)
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
    let (addr, owner, active, entered, _) = start(First::Pending, 2, WAIT, WAIT, router()).await;
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
    // Establish the first real socket before pausing; its budget exceeds the test runner limit.
    let (addr, owner, active, entered, calls) =
        start(First::Pending, 1, Duration::from_secs(300), WAIT, router()).await;
    let _slow = TcpStream::connect(addr).await.unwrap();
    tokio::time::timeout(WAIT, entered.notified())
        .await
        .unwrap();
    let mut healthy = TcpStream::connect(addr).await.unwrap();
    healthy
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    tokio::time::pause();
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(active.load(Ordering::SeqCst), 1);
    tokio::time::advance(Duration::from_secs(301)).await;
    tokio::time::resume();
    let mut response = String::new();
    tokio::time::timeout(WAIT, healthy.read_to_string(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(response.ends_with(":1"));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(owner.shutdown().join().await.unwrap().is_clean());
    assert_eq!(active.load(Ordering::SeqCst), 0);
}

#[tokio::test]
#[allow(clippy::unwrap_used)] // reason: peer failure must not stop the managed listener.
async fn factory_panic_poll_panic_and_error_isolate_the_peer() {
    for first in [First::FactoryPanic, First::PollPanic, First::Error] {
        let (addr, owner, active, _, _) = start(first, 1, WAIT, WAIT, router()).await;
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
    let (addr, owner, active, _, _) =
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
        let (addr, owner, active, entered, _) =
            start(First::Pending, 1, WAIT, WAIT, router()).await;
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

struct OrderedDrop {
    event: &'static str,
    events: Arc<std::sync::Mutex<Vec<&'static str>>>,
}
impl Drop for OrderedDrop {
    fn drop(&mut self) {
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(self.event);
    }
}
struct OrderedTransport(Arc<std::sync::Mutex<Vec<&'static str>>>);
impl ConnectionTransport for OrderedTransport {
    type Io = TcpStream;
    type Metadata = ();
    type Guard = OrderedDrop;
    type Error = std::convert::Infallible;
    async fn prepare(
        &self,
        stream: TcpStream,
        _: SocketAddr,
    ) -> Result<EstablishedTransport<TcpStream, (), OrderedDrop>, Self::Error> {
        Ok(EstablishedTransport::new(
            stream,
            (),
            OrderedDrop {
                event: "guard",
                events: self.0.clone(),
            },
        ))
    }
}

#[tokio::test]
#[allow(clippy::unwrap_used)] // reason: observe destructor order at forced drain, not only final states.
async fn forced_drain_drops_body_before_connection_guard() {
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let entered = Arc::new(Notify::new());
    let app = Router::new().route(
        "/",
        get({
            let entered = entered.clone();
            let events = events.clone();
            move || {
                let entered = entered.clone();
                let events = events.clone();
                async move {
                    axum::body::Body::from_stream(futures::stream::once(async move {
                        let _body = OrderedDrop {
                            event: "body",
                            events,
                        };
                        entered.notify_one();
                        std::future::pending::<Result<axum::body::Bytes, std::io::Error>>().await
                    }))
                }
            }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut owner = ShutdownStack::try_new(
        TotalDrainBudget::new(WAIT).unwrap(),
        Arc::new(timer::TokioTimer),
    )
    .unwrap();
    let policy = Http1ServePolicy::new(
        ServePolicy::new(1, WAIT, Duration::from_secs(30), Duration::from_millis(30)).unwrap(),
        WAIT,
        64,
        32768,
    )
    .unwrap();
    let mut startup = owner.startup().unwrap();
    startup.stage_task_with_token(rss_axum::serve_http1_registration(
        listener,
        app,
        OrderedTransport(events.clone()),
        "guard-order",
        policy,
    ));
    startup.commit().finish();
    let mut client = TcpStream::connect(addr).await.unwrap();
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    tokio::time::timeout(WAIT, entered.notified())
        .await
        .unwrap();
    assert!(events.lock().unwrap().is_empty());
    assert!(!owner.shutdown().join().await.unwrap().is_clean());
    assert_eq!(*events.lock().unwrap(), ["body", "guard"]);
}
