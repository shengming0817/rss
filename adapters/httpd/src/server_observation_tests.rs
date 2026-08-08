//! Isolated anti-vacuity proof for the adapter-owned SERVER span lifecycle.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use super::{
    TransportService,
    server_observation::{self, TransportScheme},
};
use axum::Router;
use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::routing::get;
use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::Duration;
use tower::ServiceExt as _;

async fn body_handler(headers: HeaderMap) -> axum::response::Response {
    match headers
        .get("x-body-case")
        .and_then(|value| value.to_str().ok())
    {
        Some("error") => {
            axum::response::Response::new(Body::from_stream(futures::stream::once(async {
                tracing::info!(target: "body_span_marker", "body polled");
                Err::<Bytes, _>(std::io::Error::other("closed body error"))
            })))
        }
        Some("pending") => {
            axum::response::Response::new(Body::from_stream(futures::stream::pending::<
                Result<Bytes, std::io::Error>,
            >()))
        }
        _ => axum::response::Response::new(Body::from_stream(futures::stream::once(async {
            tracing::info!(target: "body_span_marker", "body polled");
            Ok::<_, std::io::Error>(Bytes::from_static(b"ok"))
        }))),
    }
}

#[derive(Clone, Debug)]
struct CapturedSpan {
    name: &'static str,
    fields: HashMap<String, String>,
    references: usize,
    closes: usize,
    body_events: usize,
}

#[derive(Default)]
struct LifecycleCapture {
    next_id: AtomicU64,
    spans: Mutex<BTreeMap<u64, CapturedSpan>>,
    entered: Mutex<Vec<u64>>,
}

struct FieldCapture<'a>(&'a mut HashMap<String, String>);

impl tracing::field::Visit for FieldCapture<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.insert(field.name().to_owned(), format!("{value:?}"));
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.insert(field.name().to_owned(), value.to_owned());
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.0.insert(field.name().to_owned(), value.to_string());
    }
}

impl tracing::Subscriber for LifecycleCapture {
    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, attrs: &tracing::span::Attributes<'_>) -> tracing::Id {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let mut fields = HashMap::new();
        attrs.record(&mut FieldCapture(&mut fields));
        self.spans.lock().unwrap().insert(
            id,
            CapturedSpan {
                name: attrs.metadata().name(),
                fields,
                references: 1,
                closes: 0,
                body_events: 0,
            },
        );
        tracing::Id::from_u64(id)
    }

    fn record(&self, span: &tracing::Id, values: &tracing::span::Record<'_>) {
        if let Some(captured) = self.spans.lock().unwrap().get_mut(&span.into_u64()) {
            values.record(&mut FieldCapture(&mut captured.fields));
        }
    }

    fn record_follows_from(&self, _span: &tracing::Id, _follows: &tracing::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        if event.metadata().target() != "body_span_marker" {
            return;
        }
        let Some(id) = self.entered.lock().unwrap().last().copied() else {
            return;
        };
        if let Some(span) = self.spans.lock().unwrap().get_mut(&id)
            && span.name == "http.server.request"
        {
            span.body_events += 1;
        }
    }

    fn enter(&self, span: &tracing::Id) {
        self.entered.lock().unwrap().push(span.into_u64());
    }

    fn exit(&self, span: &tracing::Id) {
        assert_eq!(self.entered.lock().unwrap().pop(), Some(span.into_u64()));
    }

    fn clone_span(&self, id: &tracing::Id) -> tracing::Id {
        self.spans
            .lock()
            .unwrap()
            .get_mut(&id.into_u64())
            .unwrap()
            .references += 1;
        id.clone()
    }

    fn try_close(&self, id: tracing::Id) -> bool {
        let mut spans = self.spans.lock().unwrap();
        let span = spans.get_mut(&id.into_u64()).unwrap();
        span.references -= 1;
        if span.references == 0 {
            span.closes += 1;
            true
        } else {
            false
        }
    }
}

fn server_spans(capture: &LifecycleCapture) -> Vec<CapturedSpan> {
    capture
        .spans
        .lock()
        .unwrap()
        .values()
        .filter(|span| span.name == "http.server.request")
        .cloned()
        .collect()
}

#[test]
fn server_span_settles_once_at_each_body_terminal() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let capture = Arc::new(LifecycleCapture::default());
    let dispatch = tracing::Dispatch::new(Arc::clone(&capture));
    tracing::dispatcher::with_default(&dispatch, || {
        runtime.block_on(async {
            let core = httpserve::ServerService::from_router_for_test(
                axum::Router::new().route("/body-span", get(body_handler)),
                httpserve::ServerRequestBudget::for_test(),
            );
            let service = TransportService {
                inner: core,
                scheme: TransportScheme::Http,
                remote_addr: "127.0.0.1:1".parse().unwrap(),
            };

            for (body_case, expected_outcome, expected_error) in [
                ("eos", "completed", None),
                ("error", "body_error", Some("response_body_error")),
                ("pending", "cancelled", Some("cancelled")),
            ] {
                let response = service
                    .clone()
                    .oneshot(
                        Request::builder()
                            .uri("/body-span")
                            .header("x-body-case", body_case)
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(server_spans(&capture).last().unwrap().closes, 0);

                match body_case {
                    "eos" => {
                        axum::body::to_bytes(response.into_body(), usize::MAX)
                            .await
                            .unwrap();
                    }
                    "error" => assert!(
                        axum::body::to_bytes(response.into_body(), usize::MAX)
                            .await
                            .is_err()
                    ),
                    "pending" => drop(response),
                    _ => unreachable!(),
                }

                let settled = server_spans(&capture).pop().unwrap();
                assert_eq!(settled.closes, 1);
                assert_eq!(
                    settled.fields.get("rss.http.outcome").map(String::as_str),
                    Some(expected_outcome)
                );
                assert_eq!(
                    settled.fields.get("error.type").map(String::as_str),
                    expected_error
                );
                if body_case != "pending" {
                    assert_eq!(settled.body_events, 1, "body poll enters SERVER span");
                }
            }
        });
    });

    let spans = server_spans(&capture);
    assert_eq!(spans.len(), 3);
    assert!(spans.iter().all(|span| span.closes == 1));
}
fn observed_transport(
    service: httpserve::ServerService,
    scheme: server_observation::TransportScheme,
) -> TransportService {
    TransportService {
        inner: service,
        scheme,
        remote_addr: "127.0.0.1:1".parse().expect("test remote address"),
    }
}

async fn poll_with_local_recorder<F>(recorder: &dyn metrics::Recorder, future: F) -> F::Output
where
    F: Future,
{
    let mut future = Box::pin(future);
    std::future::poll_fn(|cx| metrics::with_local_recorder(recorder, || future.as_mut().poll(cx)))
        .await
}

#[derive(Debug, PartialEq, Eq)]
struct MetricSample {
    metric: String,
    labels: Vec<(String, String)>,
    value: String,
}

fn metric_samples(rendered: &str) -> Vec<MetricSample> {
    rendered
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| {
            let (series, value) = line.rsplit_once(' ')?;
            let (metric, labels) = match series.split_once('{') {
                Some((metric, labels)) => (metric, labels.strip_suffix('}')?),
                None => (series, ""),
            };
            let mut labels = labels
                .split(',')
                .filter(|label| !label.is_empty())
                .map(|label| {
                    let (key, value) = label.split_once('=')?;
                    Some((
                        key.to_owned(),
                        value.strip_prefix('"')?.strip_suffix('"')?.to_owned(),
                    ))
                })
                .collect::<Option<Vec<_>>>()?;
            labels.sort_unstable();
            Some(MetricSample {
                metric: metric.to_owned(),
                labels,
                value: value.to_owned(),
            })
        })
        .collect()
}

fn metric_values(samples: &[MetricSample], metric: &str, labels: &[(&str, &str)]) -> Vec<String> {
    let mut labels = labels
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect::<Vec<_>>();
    labels.sort_unstable();
    samples
        .iter()
        .filter(|sample| sample.metric == metric && sample.labels == labels)
        .map(|sample| sample.value.clone())
        .collect()
}

fn stream_service(
    receiver: futures::channel::mpsc::UnboundedReceiver<Result<&'static str, std::io::Error>>,
) -> httpserve::ServerService {
    let receiver = Arc::new(std::sync::Mutex::new(Some(receiver)));
    let router = Router::new().route(
        "/stream/{id}",
        get(move || {
            let receiver = Arc::clone(&receiver);
            async move {
                let stream = receiver
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .take()
                    .expect("single stream request");
                axum::response::Response::new(axum::body::Body::from_stream(stream))
            }
        }),
    );
    httpserve::ServerService::from_router_for_test(
        router,
        httpserve::ServerRequestBudget::for_test(),
    )
}

fn observed_request(path: &str) -> axum::extract::Request {
    axum::http::Request::builder()
        .uri(path)
        .body(axum::body::Body::empty())
        .expect("request")
}

#[allow(clippy::panic)]
async fn observed_panic() -> StatusCode {
    panic!("panic-secret")
}

#[tokio::test(start_paused = true)]
async fn transport_observation_waits_for_body_eos_and_uses_actual_tls_scheme() {
    use http_body_util::BodyExt as _;

    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let (sender, receiver) = futures::channel::mpsc::unbounded();
    let response = poll_with_local_recorder(
        &recorder,
        observed_transport(
            stream_service(receiver),
            server_observation::TransportScheme::Https,
        )
        .oneshot(observed_request("/stream/raw-secret")),
    )
    .await
    .expect("headers");
    let active = [
        ("http_request_method", "GET"),
        ("rss_http_listener", "other"),
        ("url_scheme", "https"),
    ];
    assert_eq!(
        metric_values(
            &metric_samples(&handle.render()),
            "http_server_active_requests",
            &active,
        ),
        vec!["1"]
    );

    tokio::time::advance(Duration::from_secs(2)).await;
    let mut body = response.into_body();
    sender.unbounded_send(Ok("first")).expect("first frame");
    let frame = poll_with_local_recorder(&recorder, body.frame())
        .await
        .expect("frame")
        .expect("frame result");
    assert_eq!(frame.into_data().expect("data"), "first");
    assert!(handle.render().contains("http_server_active_requests"));
    sender.unbounded_send(Ok("last")).expect("last frame");
    drop(sender);
    poll_with_local_recorder(&recorder, axum::body::to_bytes(body, usize::MAX))
        .await
        .expect("body EOS");

    let rendered = handle.render();
    let samples = metric_samples(&rendered);
    let duration = [
        ("http_request_method", "GET"),
        ("http_response_status_code", "200"),
        ("http_route", "/stream/{id}"),
        ("rss_http_listener", "other"),
        ("rss_http_outcome", "completed"),
        ("rss_http_status_class", "success"),
        ("url_scheme", "https"),
    ];
    assert_eq!(
        metric_values(&samples, "http_server_request_duration_count", &duration),
        vec!["1"]
    );
    assert_eq!(
        metric_values(&samples, "http_server_request_duration_sum", &duration),
        vec!["2"]
    );
    assert_eq!(
        metric_values(&samples, "http_server_active_requests", &active),
        vec!["0"]
    );
    assert!(!rendered.contains("raw-secret"));
}

#[tokio::test]
async fn transport_observation_body_error_and_drop_settle_once_with_closed_values() {
    use http_body_util::BodyExt as _;

    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let (error_sender, error_receiver) = futures::channel::mpsc::unbounded();
    let response = poll_with_local_recorder(
        &recorder,
        observed_transport(
            stream_service(error_receiver),
            server_observation::TransportScheme::Http,
        )
        .oneshot(observed_request("/stream/error-secret")),
    )
    .await
    .expect("headers");
    error_sender
        .unbounded_send(Err(std::io::Error::other("body-error-secret")))
        .expect("body error");
    drop(error_sender);
    assert!(
        poll_with_local_recorder(
            &recorder,
            axum::body::to_bytes(response.into_body(), usize::MAX),
        )
        .await
        .is_err()
    );

    let (drop_sender, drop_receiver) = futures::channel::mpsc::unbounded();
    let response = poll_with_local_recorder(
        &recorder,
        observed_transport(
            stream_service(drop_receiver),
            server_observation::TransportScheme::Http,
        )
        .oneshot(observed_request("/stream/drop-secret")),
    )
    .await
    .expect("headers");
    let mut body = response.into_body();
    drop_sender.unbounded_send(Ok("partial")).expect("partial");
    poll_with_local_recorder(&recorder, body.frame())
        .await
        .expect("frame")
        .expect("frame result");
    metrics::with_local_recorder(&recorder, || drop(body));
    drop(drop_sender);

    let rendered = handle.render();
    let samples = metric_samples(&rendered);
    let body_error = [
        ("error_type", "response_body_error"),
        ("http_request_method", "GET"),
        ("http_response_status_code", "200"),
        ("http_route", "/stream/{id}"),
        ("rss_http_listener", "other"),
        ("rss_http_outcome", "body_error"),
        ("rss_http_status_class", "success"),
        ("url_scheme", "http"),
    ];
    let cancelled = [
        ("error_type", "cancelled"),
        ("http_request_method", "GET"),
        ("http_response_status_code", "200"),
        ("http_route", "/stream/{id}"),
        ("rss_http_listener", "other"),
        ("rss_http_outcome", "cancelled"),
        ("rss_http_status_class", "success"),
        ("url_scheme", "http"),
    ];
    assert_eq!(
        metric_values(&samples, "http_server_request_duration_count", &body_error,),
        vec!["1"]
    );
    assert_eq!(
        metric_values(&samples, "http_server_request_duration_count", &cancelled,),
        vec!["1"]
    );
    assert!(!rendered.contains("body-error-secret"));
    assert!(!rendered.contains("error-secret"));
    assert!(!rendered.contains("drop-secret"));
}

#[tokio::test]
async fn transport_observation_request_drop_and_health_policy_are_total() {
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let pending = httpserve::ServerService::from_router_for_test(
        Router::new().route("/pending", get(std::future::pending::<()>)),
        httpserve::ServerRequestBudget::for_test(),
    );
    let mut future = Box::pin(
        observed_transport(pending, server_observation::TransportScheme::Http)
            .oneshot(observed_request("/pending")),
    );
    std::future::poll_fn(|cx| {
        let poll = metrics::with_local_recorder(&recorder, || future.as_mut().poll(cx));
        assert!(poll.is_pending());
        Poll::Ready(())
    })
    .await;
    metrics::with_local_recorder(&recorder, || drop(future));
    let after_cancel = handle.render();
    assert!(after_cancel.contains("rss_http_outcome=\"cancelled\""));
    assert!(!after_cancel.contains("http_response_status_code"));

    let health = httpserve::ServerService::from_health_router_for_test(
        Router::new().route("/healthz", get(|| async { "ok" })),
    );
    let response = poll_with_local_recorder(
        &recorder,
        observed_transport(health, server_observation::TransportScheme::Http)
            .oneshot(observed_request("/healthz")),
    )
    .await
    .expect("health response");
    poll_with_local_recorder(
        &recorder,
        axum::body::to_bytes(response.into_body(), usize::MAX),
    )
    .await
    .expect("health body");
    assert_eq!(after_cancel, handle.render(), "Health emits no SERVER RED");
}

#[tokio::test(start_paused = true)]
async fn transport_observation_distinguishes_timeout_panic_and_ordinary_500() {
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let timeout_service = httpserve::ServerService::from_router_for_test(
        Router::new().route("/timeout", get(std::future::pending::<()>)),
        httpserve::ServerRequestBudget::from_millis(NonZeroU64::new(20).expect("non-zero budget")),
    );
    let timeout = poll_with_local_recorder(
        &recorder,
        observed_transport(timeout_service, server_observation::TransportScheme::Http)
            .oneshot(observed_request("/timeout")),
    )
    .await
    .expect("timeout response");
    poll_with_local_recorder(
        &recorder,
        axum::body::to_bytes(timeout.into_body(), usize::MAX),
    )
    .await
    .expect("timeout body");

    let panic_service = httpserve::ServerService::from_router_for_test(
        Router::new().route("/panic", get(observed_panic)),
        httpserve::ServerRequestBudget::for_test(),
    );
    let panic_response = poll_with_local_recorder(
        &recorder,
        observed_transport(panic_service, server_observation::TransportScheme::Http)
            .oneshot(observed_request("/panic")),
    )
    .await
    .expect("panic response");
    poll_with_local_recorder(
        &recorder,
        axum::body::to_bytes(panic_response.into_body(), usize::MAX),
    )
    .await
    .expect("panic body");

    let ordinary = httpserve::ServerService::from_router_for_test(
        Router::new().route(
            "/ordinary",
            get(|| async { StatusCode::INTERNAL_SERVER_ERROR }),
        ),
        httpserve::ServerRequestBudget::for_test(),
    );
    let ordinary_response = poll_with_local_recorder(
        &recorder,
        observed_transport(ordinary, server_observation::TransportScheme::Http)
            .oneshot(observed_request("/ordinary")),
    )
    .await
    .expect("ordinary response");
    poll_with_local_recorder(
        &recorder,
        axum::body::to_bytes(ordinary_response.into_body(), usize::MAX),
    )
    .await
    .expect("ordinary body");

    let rendered = handle.render();
    assert!(rendered.contains("rss_http_outcome=\"timeout\""));
    assert!(rendered.contains("error_type=\"timeout\""));
    assert!(rendered.contains("rss_http_outcome=\"panic\""));
    assert!(rendered.contains("error_type=\"panic\""));
    assert!(rendered.contains("rss_http_outcome=\"completed\""));
    assert!(rendered.contains("error_type=\"500\""));
    assert!(!rendered.contains("panic-secret"));
}
