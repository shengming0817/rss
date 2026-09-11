use super::*;
use std::{
    future::Future,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

struct Metadata(Arc<AtomicUsize>);
impl Clone for Metadata {
    fn clone(&self) -> Self {
        self.0.fetch_add(1, Ordering::SeqCst);
        Self(self.0.clone())
    }
}
struct CancelOnReady {
    token: CancellationToken,
    calls: Arc<AtomicUsize>,
    clones: Arc<AtomicUsize>,
}
impl ConnectionTransport for CancelOnReady {
    type Io = TcpStream;
    type Metadata = Metadata;
    type Guard = ();
    type Error = std::convert::Infallible;
    fn prepare(
        &self,
        stream: TcpStream,
        _: SocketAddr,
    ) -> impl Future<Output = Result<EstablishedTransport<TcpStream, Metadata, ()>, Self::Error>> + Send
    {
        self.calls.fetch_add(1, Ordering::SeqCst);
        async move {
            self.token.cancel();
            Ok(EstablishedTransport::new(
                stream,
                Metadata(self.clones.clone()),
                (),
            ))
        }
    }
}

#[tokio::test]
#[allow(clippy::unwrap_used)] // reason: cancellation races are injected on a real accepted socket.
async fn cancellation_precedes_factory_and_ready_transport_promotion() {
    for precancelled in [true, false] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let _client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (stream, peer) = listener.accept().await.unwrap();
        let token = CancellationToken::new();
        if precancelled {
            token.cancel();
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let clones = Arc::new(AtomicUsize::new(0));
        let transport = Arc::new(CancelOnReady {
            token: token.clone(),
            calls: calls.clone(),
            clones: clones.clone(),
        });
        let policy = Http1ServePolicy::new(
            ServePolicy::new(1, Duration::from_secs(1), Duration::from_secs(1)).unwrap(),
            Duration::from_secs(1),
            64,
            32768,
        )
        .unwrap();
        assert!(matches!(
            prepared_connection(
                stream,
                Router::new(),
                peer,
                transport,
                token,
                Protocol::Http1(policy)
            )
            .await,
            ConnectionExit::Clean
        ));
        assert_eq!(calls.load(Ordering::SeqCst), usize::from(!precancelled));
        assert_eq!(
            clones.load(Ordering::SeqCst),
            0,
            "cancelled preparation never installs HTTP metadata"
        );
    }
}
