#![cfg(feature = "managed-server")]
use axum::{Router, routing::get};
use http_body_util::{BodyExt, Empty};
use hyper::{body::Bytes, client::conn::http2::SendRequest};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rss_axum::serve_registration;
use rss_runtime::{ShutdownFailureKind, ShutdownStack, TaskExit, TaskState, TotalDrainBudget};
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Notify,
};

struct Client {
    sender: SendRequest<Empty<Bytes>>,
    driver: tokio::task::JoinHandle<()>,
}
impl Drop for Client {
    fn drop(&mut self) {
        self.driver.abort();
    }
}
impl Client {
    #[allow(clippy::unwrap_used)]
    async fn connect(addr: SocketAddr) -> Self {
        let stream = TcpStream::connect(addr).await.unwrap();
        let (sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
                .await
                .unwrap();
        Self {
            sender,
            driver: tokio::spawn(async move {
                let _ = connection.await;
            }),
        }
    }
    #[allow(clippy::unwrap_used)]
    fn request(
        &mut self,
        path: &str,
    ) -> impl Future<Output = Result<hyper::Response<hyper::body::Incoming>, hyper::Error>> + use<>
    {
        self.sender.send_request(
            hyper::Request::builder()
                .uri(format!("http://localhost{path}"))
                .version(hyper::Version::HTTP_2)
                .body(Empty::new())
                .unwrap(),
        )
    }
}

#[allow(clippy::unwrap_used)]
async fn start(app: Router, per: Duration, total: Duration) -> (SocketAddr, ShutdownStack) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut owner = ShutdownStack::try_new(TotalDrainBudget::new(total).unwrap()).unwrap();
    owner
        .startup()
        .unwrap()
        .stage_task_with_token(serve_registration(listener, app, "http", per));
    (addr, owner)
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn http2_serves_and_http1_is_not_accepted() {
    let (addr, owner) = start(
        Router::new().route("/", get(|| async { "h2-only" })),
        Duration::from_secs(1),
        Duration::from_secs(2),
    )
    .await;
    let mut client = Client::connect(addr).await;
    let response = tokio::time::timeout(Duration::from_secs(2), client.request("/"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.version(), hyper::Version::HTTP_2);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "h2-only"
    );
    let mut legacy = TcpStream::connect(addr).await.unwrap();
    legacy
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut bytes = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), legacy.read_to_end(&mut bytes))
        .await
        .unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains("h2-only"));
    assert!(!bytes.starts_with(b"HTTP/1"));
    drop(client);
    assert!(owner.shutdown().await.unwrap().is_clean());
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn pending_registration_owns_and_releases_the_bound_socket() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    assert!(TcpListener::bind(addr).await.is_err());
    let registration = serve_registration(listener, Router::new(), "http", Duration::from_secs(1));
    assert_eq!(registration.status().current(), TaskState::Pending);
    drop(registration);
    let _rebound = TcpListener::bind(addr).await.unwrap();
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn cancellation_before_first_poll_releases_listener() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let registration = serve_registration(listener, Router::new(), "http", Duration::from_secs(1));
    let status = registration.status();
    let mut owner =
        ShutdownStack::try_new(TotalDrainBudget::new(Duration::from_secs(2)).unwrap()).unwrap();
    owner.startup().unwrap().stage_task_with_token(registration);
    assert!(owner.shutdown().await.unwrap().is_clean());
    assert_eq!(status.wait_stopped().await, TaskExit::Cancelled);
    let _rebound = TcpListener::bind(addr).await.unwrap();
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn in_flight_http2_stream_can_finish_during_graceful_drain() {
    let entered = Arc::new(Notify::new());
    let app = {
        let entered = entered.clone();
        Router::new().route(
            "/",
            get(move || async move {
                entered.notify_one();
                tokio::time::sleep(Duration::from_millis(15)).await;
                "finished"
            }),
        )
    };
    let (addr, owner) = start(app, Duration::from_secs(1), Duration::from_secs(2)).await;
    let mut client = Client::connect(addr).await;
    let request = client.request("/");
    let (response, receipt) = tokio::join!(request, async {
        tokio::time::timeout(Duration::from_secs(2), entered.notified())
            .await
            .unwrap();
        owner.shutdown().await.unwrap()
    });
    assert!(receipt.is_clean());
    assert_eq!(
        response
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes(),
        "finished"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::unwrap_used)]
async fn all_http2_streams_are_cancelled_before_later_dependency_teardown() {
    struct Dependency {
        release: Arc<Notify>,
        completed: Arc<AtomicUsize>,
    }
    impl rss_runtime::ManagedResource for Dependency {
        fn name(&self) -> &str {
            "dependency"
        }
        async fn shutdown(&self) -> Result<(), rss_runtime::ShutdownError> {
            self.release.notify_waiters();
            tokio::task::yield_now().await;
            if self.completed.load(Ordering::SeqCst) != 0 {
                return Err(rss_runtime::ShutdownError::new(std::io::Error::other(
                    "HTTP escaped teardown",
                )));
            }
            Ok(())
        }
    }
    let entered = Arc::new(tokio::sync::Semaphore::new(0));
    let release = Arc::new(Notify::new());
    let completed = Arc::new(AtomicUsize::new(0));
    let app = {
        let entered = entered.clone();
        let release = release.clone();
        let completed = completed.clone();
        Router::new().route(
            "/",
            get(move || async move {
                let notified = release.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                entered.add_permits(1);
                notified.await;
                completed.fetch_add(1, Ordering::SeqCst);
                "must-not-run"
            }),
        )
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut owner =
        ShutdownStack::try_new(TotalDrainBudget::new(Duration::from_secs(2)).unwrap()).unwrap();
    let mut startup = owner.startup().unwrap();
    startup.stage_resource(rss_runtime::DynManagedResource::new_box(Dependency {
        release,
        completed: completed.clone(),
    }));
    startup.stage_task_with_token(serve_registration(
        listener,
        app,
        "http",
        Duration::from_millis(25),
    ));
    startup.commit().finish();
    let mut clients = [Client::connect(addr).await, Client::connect(addr).await];
    let requests: Vec<_> = (0..4).map(|i| clients[i % 2].request("/")).collect();
    let (responses, receipt) = tokio::join!(futures::future::join_all(requests), async {
        tokio::time::timeout(Duration::from_secs(2), entered.acquire_many(4))
            .await
            .unwrap()
            .unwrap()
            .forget();
        owner.shutdown().await.unwrap()
    });
    assert_eq!(receipt.failures().len(), 1);
    assert_eq!(receipt.failures()[0].name, "http");
    assert!(responses.iter().all(Result::is_err));
    assert_eq!(completed.load(Ordering::SeqCst), 0);
    assert!(TcpStream::connect(addr).await.is_err());
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn total_budget_also_retires_the_http2_response_body() {
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };
    struct PendingBody {
        polled: Arc<Notify>,
        dropped: Arc<AtomicBool>,
    }
    impl http_body::Body for PendingBody {
        type Data = Bytes;
        type Error = std::convert::Infallible;
        fn poll_frame(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
            self.polled.notify_one();
            Poll::Pending
        }
    }
    impl Drop for PendingBody {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }
    let polled = Arc::new(Notify::new());
    let dropped = Arc::new(AtomicBool::new(false));
    let app = {
        let polled = polled.clone();
        let dropped = dropped.clone();
        Router::new().route(
            "/",
            get(move || async move { axum::body::Body::new(PendingBody { polled, dropped }) }),
        )
    };
    let (addr, owner) = start(app, Duration::from_secs(1), Duration::from_millis(20)).await;
    let mut client = Client::connect(addr).await;
    let request = client.request("/");
    let (response, receipt) = tokio::join!(request, async {
        tokio::time::timeout(Duration::from_secs(2), polled.notified())
            .await
            .unwrap();
        owner.shutdown().await.unwrap()
    });
    assert!(
        receipt
            .failures()
            .iter()
            .any(|f| matches!(f.kind, ShutdownFailureKind::BudgetExhausted))
    );
    if let Ok(response) = response {
        assert!(response.into_body().collect().await.is_err());
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        while !dropped.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
#[allow(clippy::unwrap_used, clippy::panic)]
async fn panicking_stream_does_not_detach_or_stop_a_healthy_stream() {
    async fn panics() -> &'static str {
        panic!("HTTP/2 stream fixture")
    }
    let app = Router::new()
        .route("/panic", get(panics))
        .route("/", get(|| async { "healthy" }));
    let (addr, owner) = start(app, Duration::from_secs(1), Duration::from_secs(2)).await;
    let mut client = Client::connect(addr).await;
    let failed = tokio::time::timeout(Duration::from_secs(2), client.request("/panic"))
        .await
        .unwrap();
    assert!(failed.is_err());
    let response = tokio::time::timeout(Duration::from_secs(2), client.request("/"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "healthy"
    );
    drop(client);
    assert!(owner.shutdown().await.unwrap().is_clean());
}
