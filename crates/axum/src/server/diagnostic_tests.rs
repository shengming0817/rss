use super::*;
use std::collections::BTreeMap;
use std::sync::Mutex;
use tracing_subscriber::prelude::*;

#[derive(Clone, Default)]
struct Events {
    rows: Arc<Mutex<Vec<BTreeMap<String, String>>>>,
    changed: Arc<tokio::sync::Notify>,
}
#[derive(Default)]
struct Fields(BTreeMap<String, String>);
impl tracing::field::Visit for Fields {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.insert(field.name().into(), format!("{value:?}"));
    }
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.insert(field.name().into(), value.into());
    }
}
impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Events {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        if event.metadata().target() == "rss_axum::server" {
            let mut fields = Fields::default();
            event.record(&mut fields);
            self.rows
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(fields.0);
            self.changed.notify_one();
        }
    }
}
impl Events {
    fn rows(&self) -> Vec<BTreeMap<String, String>> {
        self.rows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
    async fn wait_for(&self, outcome: &str) {
        loop {
            let changed = self.changed.notified();
            if self
                .rows()
                .iter()
                .any(|r| r.get("outcome").is_some_and(|s| s == outcome))
            {
                return;
            }
            changed.await;
        }
    }
}

struct PendingThenError {
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}
impl ConnectionTransport for PendingThenError {
    type Io = TcpStream;
    type Metadata = ();
    type Guard = ();
    type Error = &'static str;
    async fn prepare(
        &self,
        _stream: TcpStream,
        _: std::net::SocketAddr,
    ) -> Result<EstablishedTransport<TcpStream, (), ()>, Self::Error> {
        self.entered.notify_one();
        self.release.notified().await;
        Err("credential-secret")
    }
}

#[tokio::test]
#[allow(clippy::unwrap_used)] // reason: actual capacity transitions and diagnostics are bounded assertions.
async fn capacity_transitions_are_deduplicated_and_shutdown_is_not_recovery() {
    use tracing::instrument::WithSubscriber as _;
    for close_full in [false, true] {
        let events = Events::default();
        let subscriber = tracing_subscriber::registry().with(events.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let token = CancellationToken::new();
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let transport = PendingThenError {
            entered: entered.clone(),
            release: release.clone(),
        };
        let policy = Http1ServePolicy::new(
            ServePolicy::new(
                1,
                Duration::from_secs(3),
                Duration::from_secs(3),
                Duration::from_secs(3),
            )
            .unwrap(),
            Duration::from_secs(3),
            64,
            32768,
        )
        .unwrap();
        let server = tokio::spawn(
            serve_owned(
                listener,
                Router::new(),
                transport,
                token.clone(),
                Protocol::Http1(policy),
                "amqps://user:secret@tenant",
            )
            .with_subscriber(subscriber),
        );
        let _client = TcpStream::connect(addr).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), entered.notified())
            .await
            .unwrap();
        assert_eq!(events.rows().len(), 1);
        if !close_full {
            release.notify_one();
            tokio::time::timeout(
                Duration::from_secs(2),
                events.wait_for("capacity_recovered"),
            )
            .await
            .unwrap();
        }
        token.cancel();
        assert!(
            tokio::time::timeout(Duration::from_secs(2), server)
                .await
                .unwrap()
                .unwrap()
                .is_ok()
        );
        let rows = events.rows();
        let transitions: Vec<_> = rows
            .iter()
            .filter_map(|r| r.get("outcome"))
            .filter(|o| o.starts_with("capacity_"))
            .map(String::as_str)
            .collect();
        assert_eq!(
            transitions,
            if close_full {
                vec!["capacity_saturated"]
            } else {
                vec!["capacity_saturated", "capacity_recovered"]
            }
        );
        for row in rows {
            assert_eq!(row.get("listener").map(String::as_str), Some("<redacted>"));
            assert!(!format!("{row:?}").contains("secret"));
        }
    }
}

#[test]
fn connection_and_stream_outcomes_identify_the_safe_listener() {
    let events = Events::default();
    let subscriber = tracing_subscriber::registry().with(events.clone());
    tracing::subscriber::with_default(subscriber, || {
        record_connection(Ok(ConnectionExit::PreparationTimeout), "device");
        record_exit(ConnectionExit::Panic, "stream", "admin");
    });
    let rows = events.rows();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].get("listener").map(String::as_str), Some("device"));
    assert_eq!(rows[1].get("listener").map(String::as_str), Some("admin"));
}
