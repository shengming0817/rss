use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct ScriptedListener {
    listener: TcpListener,
    first: bool,
    failures: Arc<AtomicUsize>,
    attempts: Arc<AtomicUsize>,
    error: fn() -> std::io::Error,
}

impl Accept for ScriptedListener {
    async fn accept(&mut self) -> std::io::Result<(TcpStream, std::net::SocketAddr)> {
        if !self.first
            && self
                .failures
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok()
        {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            return Err((self.error)());
        }
        self.first = false;
        self.listener.accept().await
    }
}

#[allow(clippy::expect_used)] // reason: bounded real TCP round trip is the behavior assertion.
async fn request(stream: &mut TcpStream) {
    // Real socket readiness must not race Tokio's automatic paused-clock advancement.
    tokio::time::resume();
    tokio::time::timeout(Duration::from_secs(2), async {
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .expect("write request");
        let mut response = Vec::new();
        while !response.ends_with(b"\r\n\r\nok") {
            response.push(
                stream
                    .read_u8()
                    .await
                    .expect("healthy connection stays open"),
            );
            assert!(response.len() < 1024, "bounded response");
        }
        assert!(response.starts_with(b"HTTP/1.1 200"));
    })
    .await
    .expect("existing connection progresses during retry");
    tokio::time::pause();
}

#[tokio::test(start_paused = true)]
#[allow(clippy::expect_used)] // reason: TCP setup, failure injection and clean drain are assertions.
async fn accept_pressure_retains_healthy_connection_and_recovers_after_thirty_seconds() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("address");
    let failures = Arc::new(AtomicUsize::new(40));
    let attempts = Arc::new(AtomicUsize::new(0));
    let token = CancellationToken::new();
    let server = tokio::spawn(serve_owned(
        ScriptedListener {
            listener,
            first: true,
            failures: failures.clone(),
            attempts: attempts.clone(),
            error: || std::io::Error::from(std::io::ErrorKind::OutOfMemory),
        },
        Router::new().route("/", axum::routing::get(|| async { "ok" })),
        token.clone(),
        Protocol::Http1,
    ));
    let mut healthy = TcpStream::connect(addr).await.expect("connect");
    request(&mut healthy).await;
    for _ in 0..40 {
        tokio::time::advance(Duration::from_secs(2)).await;
        request(&mut healthy).await;
    }
    assert_eq!(failures.load(Ordering::SeqCst), 0);
    assert_eq!(attempts.load(Ordering::SeqCst), 40);
    let mut newcomer = TcpStream::connect(addr).await.expect("new connection");
    request(&mut newcomer).await;
    drop(newcomer);
    drop(healthy);
    token.cancel();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("bounded drain")
            .expect("server joins")
            .is_ok()
    );
}

#[tokio::test(start_paused = true)]
#[allow(clippy::expect_used)] // reason: repeated injected failures must stay bounded and cancellable.
async fn accept_recovery_has_bounded_attempts_and_cancels_without_waiting_for_retry() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let attempts = Arc::new(AtomicUsize::new(0));
    let token = CancellationToken::new();
    let server = serve_owned(
        ScriptedListener {
            listener,
            first: false,
            failures: Arc::new(AtomicUsize::new(10000)),
            attempts: attempts.clone(),
            error: || std::io::Error::from(std::io::ErrorKind::OutOfMemory),
        },
        Router::new(),
        token.clone(),
        Protocol::Http1,
    );
    tokio::pin!(server);
    for n in 1..=1000 {
        assert!(futures::poll!(&mut server).is_pending());
        assert_eq!(attempts.load(Ordering::SeqCst), n);
        for _ in 0..3 {
            assert!(futures::poll!(&mut server).is_pending());
        }
        assert_eq!(attempts.load(Ordering::SeqCst), n);
        if n < 1000 {
            tokio::time::advance(Duration::from_secs(1)).await;
        }
    }
    token.cancel();
    assert!(matches!(
        futures::poll!(&mut server),
        std::task::Poll::Ready(Ok(()))
    ));
}

#[tokio::test]
#[allow(clippy::expect_used)] // reason: unknown errors must terminate without retry.
async fn unknown_accept_error_is_terminal() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let attempts = Arc::new(AtomicUsize::new(0));
    let error = serve_owned(
        ScriptedListener {
            listener,
            first: false,
            failures: Arc::new(AtomicUsize::new(2)),
            attempts: attempts.clone(),
            error: || std::io::Error::other("private"),
        },
        Router::new(),
        CancellationToken::new(),
        Protocol::Http1,
    )
    .await
    .expect_err("terminal error");
    assert_eq!(error.kind(), rss_runtime::ShutdownErrorKind::Operation);
    assert!(!format!("{error:?}").contains("private"));
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
}

#[test]
fn accept_error_classification_is_closed() {
    use std::io::{Error, ErrorKind};
    for kind in [
        ErrorKind::ConnectionRefused,
        ErrorKind::ConnectionAborted,
        ErrorKind::ConnectionReset,
        ErrorKind::Interrupted,
        ErrorKind::WouldBlock,
        ErrorKind::TimedOut,
        ErrorKind::NetworkDown,
        ErrorKind::NetworkUnreachable,
        ErrorKind::HostUnreachable,
        ErrorKind::OutOfMemory,
    ] {
        assert!(recoverable_accept_error(&Error::from(kind)), "{kind:?}");
    }
    for kind in [
        ErrorKind::PermissionDenied,
        ErrorKind::InvalidInput,
        ErrorKind::InvalidData,
        ErrorKind::AddrInUse,
        ErrorKind::AddrNotAvailable,
        ErrorKind::NotConnected,
        ErrorKind::Unsupported,
        ErrorKind::Other,
    ] {
        assert!(!recoverable_accept_error(&Error::from(kind)), "{kind:?}");
    }
    assert!(!resource_pressure(None));
    assert!(!recoverable_accept_error(&Error::from_raw_os_error(
        -123456
    )));
}

#[cfg(unix)]
#[test]
fn unix_pressure_is_recoverable_but_invalid_listener_is_terminal() {
    for code in [libc::EMFILE, libc::ENFILE, libc::ENOBUFS, libc::ENOMEM] {
        assert!(recoverable_accept_error(
            &std::io::Error::from_raw_os_error(code)
        ));
    }
    for code in [libc::EBADF, libc::ENOTSOCK] {
        assert!(!recoverable_accept_error(
            &std::io::Error::from_raw_os_error(code)
        ));
    }
}

#[cfg(windows)]
#[test]
fn windows_pressure_is_recoverable_but_invalid_listener_is_terminal() {
    use windows_sys::Win32::Networking::WinSock::{WSAEMFILE, WSAENOBUFS, WSAENOTSOCK};
    for code in [WSAEMFILE, WSAENOBUFS] {
        assert!(recoverable_accept_error(
            &std::io::Error::from_raw_os_error(code)
        ));
    }
    assert!(!recoverable_accept_error(
        &std::io::Error::from_raw_os_error(WSAENOTSOCK)
    ));
}

#[tokio::test(start_paused = true)]
#[allow(clippy::expect_used)] // reason: cancellation must drain an existing real connection during backoff.
async fn cancellation_during_accept_recovery_drains_existing_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("address");
    let token = CancellationToken::new();
    let server = tokio::spawn(serve_owned(
        ScriptedListener {
            listener,
            first: true,
            failures: Arc::new(AtomicUsize::new(10000)),
            attempts: Arc::new(AtomicUsize::new(0)),
            error: || std::io::Error::from(std::io::ErrorKind::OutOfMemory),
        },
        Router::new().route("/", axum::routing::get(|| async { "ok" })),
        token.clone(),
        Protocol::Http1,
    ));
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    request(&mut stream).await;
    token.cancel();
    // A deadline shorter than the retry period proves cancellation bypasses backoff.
    assert!(
        tokio::time::timeout(Duration::from_millis(100), server)
            .await
            .expect("prompt shutdown")
            .expect("join")
            .is_ok()
    );
    tokio::time::resume();
    let mut byte = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), stream.read(&mut byte))
            .await
            .expect("EOF bounded")
            .expect("read"),
        0
    );
}
