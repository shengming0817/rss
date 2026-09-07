//! Run with --features http1, http2, or auto-protocol. Each listener policy is explicit.
#[cfg(any(feature = "http1", feature = "http2"))]
use std::time::Duration;
#[cfg(any(feature = "http1", feature = "http2"))]
use {
    axum::{Router, routing::get},
    http_body_util::{BodyExt as _, Empty},
    hyper::body::Bytes,
    hyper_util::rt::TokioIo,
    rss_runtime::{ManagedTaskRegistration, ShutdownStack, TotalDrainBudget},
    tokio::net::{TcpListener, TcpStream},
};

#[cfg(not(any(feature = "http1", feature = "http2")))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    Err("enable http1, http2, or auto-protocol to run this example".into())
}

#[cfg(any(feature = "http1", feature = "http2"))]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(Duration::from_secs(5), async {
        #[cfg(feature = "http1")]
        smoke(rss_axum::serve_http1_registration, true, false).await?;
        #[cfg(feature = "http2")]
        smoke(rss_axum::serve_http2_registration, false, true).await?;
        #[cfg(feature = "auto-protocol")]
        smoke(rss_axum::serve_auto_registration, true, true).await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })
    .await?
}

#[cfg(any(feature = "http1", feature = "http2"))]
async fn smoke(
    register: fn(TcpListener, Router, &'static str, Duration) -> ManagedTaskRegistration,
    _h1: bool,
    _h2: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let router = Router::new().route("/", get(|| async { "served" }));
    let mut owner = ShutdownStack::try_new(TotalDrainBudget::new(Duration::from_secs(2))?)?;
    let mut startup = owner.startup()?;
    startup.stage_task_with_token(register(listener, router, "http", Duration::from_secs(1)));
    startup.commit().finish();
    #[cfg(feature = "http1")]
    if _h1 {
        http1_request(address).await?;
    }
    #[cfg(feature = "http2")]
    if _h2 {
        http2_request(address).await?;
    }
    assert!(owner.shutdown().await?.is_clean());
    assert!(TcpStream::connect(address).await.is_err());
    Ok(())
}

#[cfg(feature = "http1")]
async fn http1_request(address: std::net::SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    let io = TokioIo::new(TcpStream::connect(address).await?);
    let (mut sender, connection) = hyper::client::conn::http1::handshake(io).await?;
    let request = hyper::Request::builder()
        .uri("/")
        .header("host", "localhost")
        .header("connection", "close")
        .body(Empty::<Bytes>::new())?;
    let (result, connection_result) = tokio::join!(
        async {
            let response = sender.send_request(request).await?;
            assert_eq!(response.version(), hyper::Version::HTTP_11);
            assert_eq!(response.into_body().collect().await?.to_bytes(), "served");
            Ok::<(), hyper::Error>(())
        },
        connection
    );
    result?;
    connection_result?;
    Ok(())
}

#[cfg(feature = "http2")]
async fn http2_request(address: std::net::SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    let io = TokioIo::new(TcpStream::connect(address).await?);
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(hyper_util::rt::TokioExecutor::new(), io).await?;
    let request = hyper::Request::builder()
        .uri("http://localhost/")
        .body(Empty::<Bytes>::new())?;
    // The client driver is scoped to this request, not detached into a task.
    tokio::pin!(connection);
    let response = sender.send_request(request);
    tokio::pin!(response);
    tokio::select! {
        result = async {
            let response = response.await?;
            assert_eq!(response.version(), hyper::Version::HTTP_2);
            assert_eq!(response.into_body().collect().await?.to_bytes(), "served");
            Ok::<(), hyper::Error>(())
        } => result?,
        result = &mut connection => { result?; return Err("client connection ended before response".into()); }
    }
    Ok(())
}
