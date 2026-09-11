#[path = "../../../crates/axum/examples/support/tls.rs"]
pub mod fixture;
use fixture::{Error, Fixture, WAIT};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

#[tokio::test]
async fn tls_public_consumer_serves_verified_metadata_and_drains() -> Result<(), Error> {
    fixture::smoke().await
}

#[tokio::test]
async fn anonymous_and_foreign_certificates_cannot_reach_http() -> Result<(), Error> {
    let fixture = Fixture::new(&[b"http/1.1"])?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let transport = fixture.transport();
    let slots = transport.slots.clone();
    let owner = fixture::owner(rss_axum::serve_http1_registration(
        listener,
        fixture.router(),
        transport,
        "tls-auth",
        fixture::http1_policy()?,
    ))?;
    for client in [fixture.anonymous, fixture.foreign] {
        assert!(fixture::request(address, client).await.is_err());
    }
    fixture::request(address, fixture.client).await?;
    assert!(owner.shutdown().join().await?.is_clean());
    assert_eq!(slots.available_permits(), 128);
    Ok(())
}

#[tokio::test]
async fn real_pending_tls_is_cancelled_and_releases_its_permit() -> Result<(), Error> {
    let fixture = Fixture::new(&[b"http/1.1"])?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let transport = fixture.transport();
    let entered = transport.entered.clone();
    let slots = transport.slots.clone();
    let owner = fixture::owner(rss_axum::serve_http1_registration(
        listener,
        fixture.router(),
        transport,
        "tls-cancel",
        fixture::http1_policy()?,
    ))?;
    let mut slow = TcpStream::connect(address).await?;
    tokio::time::timeout(WAIT, entered.notified()).await?;
    assert_eq!(slots.available_permits(), 127);
    fixture::request(address, fixture.client).await?;
    assert!(owner.shutdown().join().await?.is_clean());
    assert_eq!(slots.available_permits(), 128);
    assert_eq!(
        tokio::time::timeout(WAIT, slow.read_u8())
            .await?
            .err()
            .map(|e| e.kind()),
        Some(std::io::ErrorKind::UnexpectedEof)
    );
    Ok(())
}

#[tokio::test]
async fn real_tls_preparation_timeout_frees_the_only_slot() -> Result<(), Error> {
    let fixture = Fixture::new(&[b"http/1.1"])?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let transport = fixture.transport();
    let entered = transport.entered.clone();
    let slots = transport.slots.clone();
    let policy = rss_axum::Http1ServePolicy::new(
        rss_axum::ServePolicy::new(1, Duration::from_millis(200), Duration::from_secs(30), WAIT)?,
        WAIT,
        64,
        32768,
    )?;
    let owner = fixture::owner(rss_axum::serve_http1_registration(
        listener,
        fixture.router(),
        transport,
        "tls-timeout",
        policy,
    ))?;
    let mut slow = TcpStream::connect(address).await?;
    tokio::time::timeout(WAIT, entered.notified()).await?;
    assert!(tokio::time::timeout(WAIT, slow.read_u8()).await?.is_err());
    fixture::request(address, fixture.client).await?;
    assert!(owner.shutdown().join().await?.is_clean());
    assert_eq!(slots.available_permits(), 128);
    Ok(())
}

async fn h2_request(
    addr: std::net::SocketAddr,
    config: Arc<tokio_rustls::rustls::ClientConfig>,
) -> Result<(), Error> {
    use http_body_util::{BodyExt, Empty};
    let (stream, peer) = fixture::connect(addr, config, b"h2").await?;
    let (mut sender, connection) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        hyper_util::rt::TokioIo::new(stream),
    )
    .await?;
    let request = hyper::Request::builder()
        .uri("https://localhost/")
        .body(Empty::<hyper::body::Bytes>::new())?;
    tokio::pin!(connection);
    tokio::select! {
        result = async {
            let response = sender.send_request(request).await?;
            assert_eq!(response.version(), hyper::Version::HTTP_2);
            let body = response.into_body().collect().await?.to_bytes();
            assert_eq!(body, format!("{peer}|true"));
            Ok::<(), Error>(())
        } => result,
        result = &mut connection => { result?; Err("H2 driver ended early".into()) }
    }
}

#[tokio::test]
async fn tls_http2_and_auto_use_the_same_managed_owner() -> Result<(), Error> {
    for auto in [false, true] {
        let fixture = Fixture::new(&[b"h2", b"http/1.1"])?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let transport = fixture.transport();
        let slots = transport.slots.clone();
        let registration = if auto {
            rss_axum::serve_auto_registration(
                listener,
                fixture.router(),
                transport,
                "tls-auto",
                fixture::http1_policy()?,
            )
        } else {
            rss_axum::serve_http2_registration(
                listener,
                fixture.router(),
                transport,
                "tls-h2",
                fixture::serve_policy()?,
            )
        };
        let owner = fixture::owner(registration)?;
        tokio::time::timeout(WAIT, h2_request(address, fixture.client.clone())).await??;
        if auto {
            fixture::request(address, fixture.client).await?;
        }
        assert!(owner.shutdown().join().await?.is_clean());
        assert_eq!(slots.available_permits(), 128);
    }
    Ok(())
}

#[tokio::test]
async fn tls_slow_http_request_is_dropped_with_its_connection_permit() -> Result<(), Error> {
    let fixture = Fixture::new(&[b"http/1.1"])?;
    let entered = Arc::new(tokio::sync::Notify::new());
    let router = axum::Router::new().route(
        "/",
        axum::routing::get({
            let entered = entered.clone();
            move || async move {
                entered.notify_one();
                std::future::pending::<&'static str>().await
            }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let transport = fixture.transport();
    let slots = transport.slots.clone();
    let policy = rss_axum::Http1ServePolicy::new(
        rss_axum::ServePolicy::new(
            128,
            WAIT,
            Duration::from_secs(30),
            Duration::from_millis(30),
        )?,
        WAIT,
        64,
        32768,
    )?;
    let owner = fixture::owner(rss_axum::serve_http1_registration(
        listener,
        router,
        transport,
        "tls-http-timeout",
        policy,
    ))?;
    let (mut stream, _) = fixture::connect(address, fixture.client, b"http/1.1").await?;
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;
    tokio::time::timeout(WAIT, entered.notified()).await?;
    assert_eq!(slots.available_permits(), 127);
    assert!(!owner.shutdown().join().await?.is_clean());
    assert_eq!(slots.available_permits(), 128);
    Ok(())
}

#[tokio::test]
async fn tls_http1_limits_reject_bad_headers_without_stopping_listener() -> Result<(), Error> {
    let fixture = Fixture::new(&[b"http/1.1"])?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let policy = rss_axum::Http1ServePolicy::new(
        rss_axum::ServePolicy::new(128, WAIT, Duration::from_secs(30), WAIT)?,
        Duration::from_millis(100),
        64,
        32768,
    )?;
    let owner = fixture::owner(rss_axum::serve_http1_registration(
        listener,
        fixture.router(),
        fixture.transport(),
        "tls-limits",
        policy,
    ))?;
    let too_many = format!(
        "GET / HTTP/1.1\r\nHost: localhost\r\n{}\r\n",
        "X-Test: a\r\n".repeat(64)
    );
    let too_large = format!(
        "GET / HTTP/1.1\r\nHost: localhost\r\nX-Large: {}\r\n\r\n",
        "a".repeat(33000)
    );
    for request in [too_many, too_large, "GET / HTTP/1.1\r\nHost:".into()] {
        let (mut stream, _) =
            fixture::connect(address, fixture.client.clone(), b"http/1.1").await?;
        stream.write_all(request.as_bytes()).await?;
        let mut response = Vec::new();
        let _closed = tokio::time::timeout(WAIT, stream.read_to_end(&mut response)).await?;
        assert!(!response.starts_with(b"HTTP/1.1 200"));
        fixture::request(address, fixture.client.clone()).await?;
    }
    assert!(owner.shutdown().join().await?.is_clean());
    Ok(())
}

struct BodyDropped(Arc<std::sync::atomic::AtomicBool>);
impl Drop for BodyDropped {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

#[tokio::test]
async fn tls_response_body_and_connection_guard_are_retired() -> Result<(), Error> {
    let fixture = Fixture::new(&[b"http/1.1"])?;
    let entered = Arc::new(tokio::sync::Notify::new());
    let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let router = axum::Router::new().route(
        "/",
        axum::routing::get({
            let entered = entered.clone();
            let dropped = dropped.clone();
            move || {
                let entered = entered.clone();
                let dropped = dropped.clone();
                async move {
                    axum::body::Body::from_stream(futures::stream::once(async move {
                        let _marker = BodyDropped(dropped);
                        entered.notify_one();
                        std::future::pending::<Result<axum::body::Bytes, std::io::Error>>().await
                    }))
                }
            }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let transport = fixture.transport();
    let slots = transport.slots.clone();
    let policy = rss_axum::Http1ServePolicy::new(
        rss_axum::ServePolicy::new(
            128,
            WAIT,
            Duration::from_secs(30),
            Duration::from_millis(30),
        )?,
        WAIT,
        64,
        32768,
    )?;
    let owner = fixture::owner(rss_axum::serve_http1_registration(
        listener, router, transport, "tls-body", policy,
    ))?;
    let (mut stream, _) = fixture::connect(address, fixture.client, b"http/1.1").await?;
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;
    tokio::time::timeout(WAIT, entered.notified()).await?;
    assert_eq!(slots.available_permits(), 127);
    assert!(!owner.shutdown().join().await?.is_clean());
    assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(slots.available_permits(), 128);
    Ok(())
}

#[tokio::test]
#[allow(clippy::panic)] // reason: real TLS HTTP panic must stay inside its connection owner.
async fn tls_http_panic_does_not_stop_healthy_peer() -> Result<(), Error> {
    let fixture = Fixture::new(&[b"http/1.1"])?;
    let router = fixture.router().route(
        "/panic",
        axum::routing::get(|| async {
            panic!("test HTTP failure");
            #[allow(unreachable_code)]
            ""
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let transport = fixture.transport();
    let slots = transport.slots.clone();
    let owner = fixture::owner(rss_axum::serve_http1_registration(
        listener,
        router,
        transport,
        "tls-panic",
        fixture::http1_policy()?,
    ))?;
    let (mut stream, _) = fixture::connect(address, fixture.client.clone(), b"http/1.1").await?;
    stream
        .write_all(b"GET /panic HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;
    assert!(tokio::time::timeout(WAIT, stream.read_u8()).await?.is_err());
    fixture::request(address, fixture.client).await?;
    assert!(owner.shutdown().join().await?.is_clean());
    assert_eq!(slots.available_permits(), 128);
    Ok(())
}

#[tokio::test]
async fn silent_tls_h2_peer_expires_and_releases_capacity_for_a_healthy_peer() -> Result<(), Error>
{
    let fixture = Fixture::new(&[b"h2"])?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let transport = fixture.transport();
    let slots = transport.slots.clone();
    let policy = rss_axum::ServePolicy::new(1, WAIT, Duration::from_millis(100), WAIT)?;
    let owner = fixture::owner(rss_axum::serve_http2_registration(
        listener,
        fixture.router(),
        transport,
        "tls-h2-establishment",
        policy,
    ))?;
    let (mut silent, _) = fixture::connect(address, fixture.client.clone(), b"h2").await?;
    // Complete TLS but never send the H2 preface. Read any server SETTINGS until it closes.
    let mut server_bytes = Vec::new();
    let closed = tokio::time::timeout(WAIT, silent.read_to_end(&mut server_bytes)).await;
    assert!(
        closed.is_ok(),
        "H2 establishment must not retain a slot indefinitely"
    );
    tokio::time::timeout(WAIT, h2_request(address, fixture.client)).await??;
    assert!(owner.shutdown().join().await?.is_clean());
    assert_eq!(slots.available_permits(), 128);
    Ok(())
}
