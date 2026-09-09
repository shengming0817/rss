#![cfg(feature = "http1")]

use axum::{Router, body::Bytes, routing::get};
use http_body_util::{BodyExt as _, Empty};
use hyper_util::rt::TokioIo;
use rss_runtime::{ManagedTaskRegistration, ShutdownStack, TaskState, TotalDrainBudget};
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
    sync::Notify,
};

const WAIT: Duration = Duration::from_secs(2);
type Register = fn(TcpListener, Router, &'static str, Duration) -> ManagedTaskRegistration;

fn constructors() -> Vec<Register> {
    vec![
        rss_axum::serve_http1_registration,
        #[cfg(feature = "auto-protocol")]
        rss_axum::serve_auto_registration,
    ]
}

#[allow(clippy::unwrap_used)]
async fn start(register: Register, router: Router, drain: Duration) -> (SocketAddr, ShutdownStack) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut owner = ShutdownStack::try_new(TotalDrainBudget::new(WAIT).unwrap()).unwrap();
    let mut startup = owner.startup().unwrap();
    startup.stage_task_with_token(register(listener, router, "http", drain));
    startup.commit().finish();
    (addr, owner)
}

struct Client {
    local_addr: SocketAddr,
    sender: hyper::client::conn::http1::SendRequest<Empty<Bytes>>,
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
        let local_addr = stream.local_addr().unwrap();
        let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .unwrap();
        Self {
            local_addr,
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
        let mut request = hyper::Request::new(Empty::new());
        *request.uri_mut() = path.parse().unwrap();
        request
            .headers_mut()
            .insert("host", hyper::header::HeaderValue::from_static("localhost"));
        self.sender.send_request(request)
    }
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn http1_keep_alive_then_idle_drain() {
    for register in constructors() {
        let (addr, owner) = start(
            register,
            Router::new().route("/", get(|| async { "ok" })),
            WAIT,
        )
        .await;
        let mut client = Client::connect(addr).await;
        for _ in 0..2 {
            let response = tokio::time::timeout(WAIT, client.request("/"))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(response.version(), hyper::Version::HTTP_11);
            assert_eq!(
                response.into_body().collect().await.unwrap().to_bytes(),
                "ok"
            );
        }
        assert!(owner.shutdown().join().await.unwrap().is_clean());
        tokio::time::timeout(WAIT, &mut client.driver)
            .await
            .unwrap()
            .unwrap();
        assert!(TcpStream::connect(addr).await.is_err());
    }
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn unadopted_registrations_release_the_socket() {
    for register in constructors() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let registration = register(listener, Router::new(), "http", WAIT);
        assert_eq!(registration.status().current(), TaskState::Pending);
        drop(registration);
        let _listener = TcpListener::bind(addr).await.unwrap();
    }
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn http1_inflight_request_finishes_during_drain() {
    for register in constructors() {
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let router = {
            let entered = entered.clone();
            let release = release.clone();
            Router::new().route(
                "/",
                get(move || async move {
                    entered.notify_one();
                    release.notified().await;
                    "finished"
                }),
            )
        };
        let (addr, owner) = start(register, router, WAIT).await;
        let mut client = Client::connect(addr).await;
        let request = client.request("/");
        let (response, receipt) = tokio::join!(request, async {
            tokio::time::timeout(WAIT, entered.notified())
                .await
                .unwrap();
            let shutdown = owner.shutdown().join();
            tokio::pin!(shutdown);
            // Poll shutdown before releasing the handler, so this exercises drain.
            assert!(futures::poll!(&mut shutdown).is_pending());
            release.notify_one();
            shutdown.await.unwrap()
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
}

struct Dropped(Arc<AtomicBool>);
impl Drop for Dropped {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn http1_timeout_drops_handler_before_dependency_teardown() {
    struct Dependency {
        release: Arc<Notify>,
        dropped: Arc<AtomicBool>,
    }
    impl rss_runtime::ManagedResource for Dependency {
        fn name(&self) -> &str {
            "dependency"
        }
        async fn shutdown(&self) -> Result<(), rss_runtime::ShutdownError> {
            assert!(self.dropped.load(Ordering::SeqCst));
            self.release.notify_one();
            Ok(())
        }
    }
    for register in constructors() {
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let dropped = Arc::new(AtomicBool::new(false));
        let completed = Arc::new(AtomicUsize::new(0));
        let router = {
            let entered = entered.clone();
            let release = release.clone();
            let dropped = dropped.clone();
            let completed = completed.clone();
            Router::new().route(
                "/",
                get(move || async move {
                    let _guard = Dropped(dropped);
                    entered.notify_one();
                    release.notified().await;
                    completed.fetch_add(1, Ordering::SeqCst);
                    "escaped"
                }),
            )
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut owner = ShutdownStack::try_new(TotalDrainBudget::new(WAIT).unwrap()).unwrap();
        let mut startup = owner.startup().unwrap();
        startup.stage_resource(rss_runtime::DynManagedResource::new_box(Dependency {
            release,
            dropped: dropped.clone(),
        }));
        startup.stage_task_with_token(register(
            listener,
            router,
            "http",
            Duration::from_millis(25),
        ));
        startup.commit().finish();
        let mut client = Client::connect(addr).await;
        let (response, receipt) = tokio::join!(client.request("/"), async {
            tokio::time::timeout(WAIT, entered.notified())
                .await
                .unwrap();
            owner.shutdown().join().await.unwrap()
        });
        assert!(response.is_err());
        assert_eq!(receipt.failures().len(), 1);
        assert_eq!(completed.load(Ordering::SeqCst), 0);
        assert!(dropped.load(Ordering::SeqCst));
    }
}

#[derive(Clone)]
struct Diagnostics(
    Arc<std::sync::Mutex<Vec<(String, String)>>>,
    std::thread::ThreadId,
);
impl tracing::field::Visit for Diagnostics {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if let Ok(mut fields) = self.0.lock() {
            fields.push((field.name().into(), format!("{value:?}")));
        }
    }
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if let Ok(mut fields) = self.0.lock() {
            fields.push((field.name().into(), value.into()));
        }
    }
}
impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Diagnostics {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        if event.metadata().target() == "rss_axum::server" && std::thread::current().id() == self.1
        {
            event.record(&mut self.clone());
        }
    }
}

#[tokio::test]
#[allow(clippy::unwrap_used, clippy::panic)]
async fn malformed_or_panicking_http1_peer_does_not_stop_healthy_connections() {
    use tracing_subscriber::prelude::*;
    let diagnostics = Diagnostics(
        Arc::new(std::sync::Mutex::new(Vec::new())),
        std::thread::current().id(),
    );
    let subscriber = tracing_subscriber::registry().with(diagnostics.clone());
    // One global collector in this test binary avoids callsite interest races. Filtering by
    // this current-thread runtime prevents other concurrent tests from supplying evidence.
    tracing::subscriber::set_global_default(subscriber).unwrap();
    for register in constructors() {
        let router = Router::new()
            .route(
                "/panic",
                get(|| async {
                    panic!("handler fixture");
                    #[allow(unreachable_code)]
                    ""
                }),
            )
            .route("/", get(|| async { "healthy" }));
        let (addr, owner) = start(register, router, WAIT).await;
        let mut malformed = TcpStream::connect(addr).await.unwrap();
        malformed.write_all(b"INVALID HTTP\r\n\r\n").await.unwrap();
        let mut bytes = Vec::new();
        let _ = tokio::time::timeout(WAIT, malformed.read_to_end(&mut bytes))
            .await
            .unwrap();
        let mut bad = Client::connect(addr).await;
        assert!(
            tokio::time::timeout(WAIT, bad.request("/panic"))
                .await
                .unwrap()
                .is_err()
        );
        let mut healthy = Client::connect(addr).await;
        let response = tokio::time::timeout(WAIT, healthy.request("/"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "healthy"
        );
        assert!(owner.shutdown().join().await.unwrap().is_clean());
    }
    let fields = diagnostics.0.lock().unwrap();
    for outcome in ["peer_error", "panic"] {
        assert!(
            fields
                .iter()
                .any(|(key, value)| key == "outcome" && value == outcome),
            "missing {outcome}: {fields:?}"
        );
    }
    assert!(fields.iter().all(|(_, value)| !value.contains("handler fixture") && !value.contains("INVALID HTTP")));
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn http1_listener_does_not_dispatch_h2_preface() {
    let calls = Arc::new(AtomicUsize::new(0));
    let router = {
        let calls = calls.clone();
        Router::new().route(
            "/",
            get(move || async move {
                calls.fetch_add(1, Ordering::SeqCst);
                "wrong"
            }),
        )
    };
    let (addr, owner) = start(rss_axum::serve_http1_registration, router, WAIT).await;
    let mut peer = TcpStream::connect(addr).await.unwrap();
    peer.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .await
        .unwrap();
    let mut bytes = Vec::new();
    let _ = tokio::time::timeout(WAIT, peer.read_to_end(&mut bytes))
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(owner.shutdown().join().await.unwrap().is_clean());
}

#[cfg(feature = "auto-protocol")]
#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn auto_accepts_both_protocols_on_one_listener() {
    let (addr, owner) = start(
        rss_axum::serve_auto_registration,
        Router::new().route("/", get(|| async { "auto" })),
        WAIT,
    )
    .await;
    let mut h1 = Client::connect(addr).await;
    let response = h1.request("/").await.unwrap();
    assert_eq!(response.version(), hyper::Version::HTTP_11);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "auto"
    );
    let (mut sender, connection) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        TokioIo::new(TcpStream::connect(addr).await.unwrap()),
    )
    .await
    .unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = hyper::Request::new(Empty::<Bytes>::new());
    let response = tokio::time::timeout(WAIT, sender.send_request(request))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.version(), hyper::Version::HTTP_2);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "auto"
    );
    assert!(owner.shutdown().join().await.unwrap().is_clean());
    tokio::time::timeout(WAIT, driver).await.unwrap().unwrap();
}

#[cfg(feature = "auto-protocol")]
#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn auto_drain_cancels_idle_and_partial_preface_connections() {
    let (addr, owner) = start(rss_axum::serve_auto_registration, Router::new(), WAIT).await;
    let mut idle = TcpStream::connect(addr).await.unwrap();
    let mut partial = TcpStream::connect(addr).await.unwrap();
    partial.write_all(b"PRI * HTTP/2").await.unwrap();
    // A completed request ensures the listener has been driven while these peers are open.
    let mut ready = Client::connect(addr).await;
    let response = ready.request("/").await.unwrap();
    response.into_body().collect().await.unwrap();
    assert!(owner.shutdown().join().await.unwrap().is_clean());
    for peer in [&mut idle, &mut partial] {
        let mut bytes = Vec::new();
        let _ = tokio::time::timeout(WAIT, peer.read_to_end(&mut bytes))
            .await
            .unwrap();
    }
}

struct ControlledBody {
    frames: tokio::sync::mpsc::Receiver<Bytes>,
    polled: Arc<Notify>,
    _guard: Dropped,
}
impl http_body::Body for ControlledBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        self.polled.notify_one();
        self.frames
            .poll_recv(cx)
            .map(|frame| frame.map(|bytes| Ok(http_body::Frame::data(bytes))))
    }
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn http1_response_body_is_drained_or_dropped_on_timeout() {
    for register in constructors() {
        for finish in [true, false] {
            let polled = Arc::new(Notify::new());
            let dropped = Arc::new(AtomicBool::new(false));
            let (sender, frames) = tokio::sync::mpsc::channel(1);
            let body = Arc::new(std::sync::Mutex::new(Some(ControlledBody {
                frames,
                polled: polled.clone(),
                _guard: Dropped(dropped.clone()),
            })));
            let router =
                Router::new().route(
                    "/",
                    get(move || async move {
                        axum::body::Body::new(body.lock().unwrap().take().unwrap())
                    }),
                );
            let (addr, owner) = start(
                register,
                router,
                if finish {
                    WAIT
                } else {
                    Duration::from_millis(25)
                },
            )
            .await;
            let mut client = Client::connect(addr).await;
            let (body_result, receipt) = tokio::join!(
                async {
                    let response = client.request("/").await?;
                    response
                        .into_body()
                        .collect()
                        .await
                        .map(|body| body.to_bytes())
                },
                async {
                    tokio::time::timeout(WAIT, polled.notified()).await.unwrap();
                    let shutdown = owner.shutdown().join();
                    tokio::pin!(shutdown);
                    assert!(futures::poll!(&mut shutdown).is_pending());
                    if finish {
                        sender.send(Bytes::from_static(b"finished")).await.unwrap();
                        drop(sender);
                    }
                    shutdown.await.unwrap()
                }
            );
            assert!(dropped.load(Ordering::SeqCst));
            if finish {
                assert!(receipt.is_clean());
                assert_eq!(body_result.unwrap(), "finished");
            } else {
                assert_eq!(receipt.failures().len(), 1);
                assert!(body_result.is_err());
            }
        }
    }
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn establishment_deadline_closes_partial_headers_without_stopping_listener() {
    for register in constructors() {
        for after_request in [false, true] {
            let (addr, owner) = start(
                register,
                Router::new().route("/", get(|| async { "healthy" })),
                WAIT,
            )
            .await;
            let mut slow = TcpStream::connect(addr).await.unwrap();
            if after_request {
                slow.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    .await
                    .unwrap();
                tokio::time::timeout(WAIT, async {
                    let mut header = Vec::new();
                    while !header.ends_with(b"\r\n\r\n") {
                        header.push(slow.read_u8().await.unwrap());
                    }
                    let mut body = [0; 7];
                    slow.read_exact(&mut body).await.unwrap();
                    assert_eq!(&body, b"healthy");
                })
                .await
                .unwrap();
            }
            slow.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Slow: ")
                .await
                .unwrap();
            let mut ready = Client::connect(addr).await;
            ready
                .request("/")
                .await
                .unwrap()
                .into_body()
                .collect()
                .await
                .unwrap();
            tokio::time::pause();
            tokio::time::advance(Duration::from_secs(31)).await;
            tokio::time::resume(); // Observe real socket closure without auto-advancing its wait budget.
            let mut bytes = Vec::new();
            let _ = tokio::time::timeout(WAIT, slow.read_to_end(&mut bytes))
                .await
                .unwrap();
            let mut healthy = Client::connect(addr).await;
            let response = healthy.request("/").await.unwrap();
            assert_eq!(
                response.into_body().collect().await.unwrap().to_bytes(),
                "healthy"
            );
            assert!(owner.shutdown().join().await.unwrap().is_clean());
        }
    }
}

#[cfg(feature = "auto-protocol")]
#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn establishment_deadline_closes_partial_exact_h2_preface() {
    for prefix in [b"".as_slice(), b"PRI * HTTP/2.0\r\n\r\nSM\r\n".as_slice()] {
        let (addr, owner) = start(rss_axum::serve_auto_registration, Router::new(), WAIT).await;
        let mut slow = TcpStream::connect(addr).await.unwrap();
        slow.write_all(prefix).await.unwrap();
        let mut ready = Client::connect(addr).await;
        ready
            .request("/")
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap();
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(31)).await;
        tokio::time::resume(); // Socket readiness is a real I/O event.
        let mut bytes = Vec::new();
        let _ = tokio::time::timeout(WAIT, slow.read_to_end(&mut bytes))
            .await
            .unwrap();
        assert!(owner.shutdown().join().await.unwrap().is_clean());
    }
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn establishment_deadline_does_not_limit_an_admitted_handler() {
    for register in constructors() {
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let router = {
            let entered = entered.clone();
            let release = release.clone();
            Router::new().route(
                "/",
                get(move || async move {
                    entered.notify_one();
                    release.notified().await;
                    "finished"
                }),
            )
        };
        let (addr, owner) = start(register, router, WAIT).await;
        let mut client = Client::connect(addr).await;
        let (response, ()) = tokio::join!(client.request("/"), async {
            entered.notified().await;
            tokio::time::pause();
            tokio::time::advance(Duration::from_secs(31)).await;
            release.notify_one();
        });
        tokio::time::resume();
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
        assert!(owner.shutdown().join().await.unwrap().is_clean());
    }
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn accepted_peer_is_available_to_standard_extractor() {
    for register in constructors() {
        let app = Router::new().route("/", get(|axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<SocketAddr>| async move { peer.to_string() }));
        let (address, owner) = start(register, app, WAIT).await;
        let mut client = Client::connect(address).await;
        let response = client.request("/").await.unwrap();
        assert!(response.status().is_success());
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            std::str::from_utf8(&bytes).unwrap(),
            client.local_addr.to_string()
        );
        drop(client);
        assert!(owner.shutdown().join().await.unwrap().is_clean());
    }
}
