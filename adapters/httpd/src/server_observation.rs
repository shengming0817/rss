//! Adapter-private HTTP server observation boundary.
//!
//! The observation type deliberately cannot retain a request, URI, headers, body, authority, or
//! free-form error text. Only closed protocol/method values and axum's matched route template can
//! reach the SERVER span or HTTP RED metrics. One move-only owner settles the span, duration and
//! active-request gauge at response-body EOS, error, cancellation, timeout, or panic.

use axum::body::Body;
use axum::http::{HeaderMap, Method, StatusCode, Version, header::HeaderName};
use axum::response::Response;
use http_body::Body as HttpBody;
use metrics::{Gauge, Label, Unit};
use std::pin::Pin;
use std::task::{Context, Poll};

const REQUEST_DURATION: &str = "http.server.request.duration";
const ACTIVE_REQUESTS: &str = "http.server.active_requests";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TransportScheme {
    Http,
    Https,
}

impl TransportScheme {
    pub(super) const fn as_label(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

const TRACEPARENT: HeaderName = HeaderName::from_static("traceparent");
const TRACESTATE: HeaderName = HeaderName::from_static("tracestate");
const MAX_TRACE_HEADER_BYTES: usize = 512;

pub(super) struct InboundTraceContext {
    traceparent: tracewire::TraceParent,
    tracestate: Option<String>,
}

fn observe_traceparent_rejection(reason: impl std::fmt::Display) {
    tracing::debug!(
        target: "rss.trace_context",
        transport = "http",
        operation = "server.receive",
        reason = %reason,
        "remote trace parent rejected"
    );
}

fn parse_single_traceparent(headers: &HeaderMap) -> Option<tracewire::TraceParent> {
    let mut parents = headers.get_all(&TRACEPARENT).iter();
    let value = match parents.next()?.to_str() {
        Ok(value) => value,
        Err(_) => {
            observe_traceparent_rejection("malformed traceparent");
            return None;
        }
    };
    let traceparent = match tracewire::TraceParent::parse(value) {
        Ok(parent) => parent,
        Err(reason) => {
            observe_traceparent_rejection(reason);
            return None;
        }
    };
    if parents.next().is_some() {
        observe_traceparent_rejection("multiple traceparent headers");
        return None;
    }
    Some(traceparent)
}

impl InboundTraceContext {
    pub(super) fn from_headers(headers: &HeaderMap) -> Option<Self> {
        let traceparent = parse_single_traceparent(headers)?;

        let mut tracestate = String::new();
        for value in headers.get_all(&TRACESTATE) {
            let Ok(value) = value.to_str() else {
                return Some(Self {
                    traceparent,
                    tracestate: None,
                });
            };
            let next_len = tracestate
                .len()
                .saturating_add(usize::from(!tracestate.is_empty()))
                .saturating_add(value.len());
            if next_len > MAX_TRACE_HEADER_BYTES {
                return Some(Self {
                    traceparent,
                    tracestate: None,
                });
            }
            if !tracestate.is_empty() {
                tracestate.push(',');
            }
            tracestate.push_str(value);
        }

        Some(Self {
            traceparent,
            tracestate: (!tracestate.is_empty()).then_some(tracestate),
        })
    }

    pub(super) fn apply_to(&self, span: &tracing::Span) {
        if tracewire::restore_remote_parent(span, &self.traceparent, self.tracestate.as_deref())
            == tracewire::RestoreOutcome::Unavailable
        {
            tracing::debug!(
                target: "rss.trace_context",
                transport = "http",
                operation = "server.receive",
                reason = "attach_unavailable",
                "remote trace parent attach unavailable"
            );
        }
    }
}

#[derive(Clone, Copy)]
enum ObservedHttpMethod {
    Connect,
    Delete,
    Get,
    Head,
    Options,
    Patch,
    Post,
    Put,
    Query,
    Trace,
    Other,
}

impl ObservedHttpMethod {
    fn from_method(method: &Method) -> Self {
        if method.as_str() == "QUERY" {
            return Self::Query;
        }
        match *method {
            Method::CONNECT => Self::Connect,
            Method::DELETE => Self::Delete,
            Method::GET => Self::Get,
            Method::HEAD => Self::Head,
            Method::OPTIONS => Self::Options,
            Method::PATCH => Self::Patch,
            Method::POST => Self::Post,
            Method::PUT => Self::Put,
            Method::TRACE => Self::Trace,
            _ => Self::Other,
        }
    }

    const fn as_label(self) -> &'static str {
        match self {
            Self::Connect => "CONNECT",
            Self::Delete => "DELETE",
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Options => "OPTIONS",
            Self::Patch => "PATCH",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Query => "QUERY",
            Self::Trace => "TRACE",
            Self::Other => "_OTHER",
        }
    }

    const fn name_token(self) -> &'static str {
        match self {
            Self::Other => "HTTP",
            known => known.as_label(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StatusClass {
    Informational,
    Success,
    Redirection,
    ClientError,
    ServerError,
    Other,
    None,
}

impl StatusClass {
    fn from_status(status: Option<StatusCode>) -> Self {
        let Some(status) = status else {
            return Self::None;
        };
        match status.as_u16() / 100 {
            1 => Self::Informational,
            2 => Self::Success,
            3 => Self::Redirection,
            4 => Self::ClientError,
            5 => Self::ServerError,
            _ => Self::Other,
        }
    }

    const fn as_label(self) -> &'static str {
        match self {
            Self::Informational => "informational",
            Self::Success => "success",
            Self::Redirection => "redirection",
            Self::ClientError => "client_error",
            Self::ServerError => "server_error",
            Self::Other => "other",
            Self::None => "none",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TerminalOutcome {
    Completed,
    BodyError,
    Cancelled,
    Timeout,
    Panic,
}

impl TerminalOutcome {
    const fn as_label(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::BodyError => "body_error",
            Self::Cancelled => "cancelled",
            Self::Timeout => "timeout",
            Self::Panic => "panic",
        }
    }

    fn error_type(self, status: Option<StatusCode>) -> Option<String> {
        match self {
            Self::BodyError => Some("response_body_error".to_owned()),
            Self::Cancelled => Some("cancelled".to_owned()),
            Self::Timeout => Some("timeout".to_owned()),
            Self::Panic => Some("panic".to_owned()),
            Self::Completed => status
                .filter(StatusCode::is_server_error)
                .map(|status| status.as_u16().to_string()),
        }
    }

    const fn is_error(self) -> bool {
        !matches!(self, Self::Completed)
    }
}

struct RequestTimer(tokio::time::Instant);

impl RequestTimer {
    #[allow(clippy::disallowed_methods)]
    fn start() -> Self {
        // reason: HTTP operation duration is monotonic runtime time, not a domain timestamp; Tokio's
        // clock also supplies deterministic paused-time tests without introducing a public clock SPI.
        Self(tokio::time::Instant::now())
    }

    #[allow(clippy::disallowed_methods)]
    fn finish(self) -> std::time::Duration {
        // reason: paired with `start`; saturating subtraction keeps the observation total.
        tokio::time::Instant::now().saturating_duration_since(self.0)
    }
}

struct ObservationCore {
    method: ObservedHttpMethod,
    route: Option<String>,
    scheme: TransportScheme,
    listener: httpserve::ServerObservationListener,
    span: tracing::Span,
    timer: RequestTimer,
    active: Gauge,
}

impl ObservationCore {
    fn observe_route(&mut self, route: Option<&str>) {
        let Some(route) = route else {
            return;
        };
        let route = route.to_owned();
        self.span.record("http.route", route.as_str());
        self.span.record(
            "otel.name",
            format!("{} {route}", self.method.name_token()).as_str(),
        );
        self.route = Some(route);
    }

    fn settle(self, status: Option<StatusCode>, outcome: TerminalOutcome) {
        let status_class = StatusClass::from_status(status);
        let error_type = outcome.error_type(status);
        if let Some(status) = status {
            self.span
                .record("http.response.status_code", status.as_u16());
        }
        self.span
            .record("rss.http.status_class", status_class.as_label());
        self.span.record("rss.http.outcome", outcome.as_label());
        if let Some(error_type) = error_type.as_deref() {
            self.span.record("error.type", error_type);
        }
        if outcome.is_error() || status.is_some_and(|value| value.is_server_error()) {
            self.span.record("otel.status_code", "error");
        }

        let mut labels = vec![
            Label::new("http.request.method", self.method.as_label()),
            Label::new("url.scheme", self.scheme.as_label()),
            Label::new("rss.http.listener", self.listener.as_label()),
            Label::new("rss.http.status_class", status_class.as_label()),
            Label::new("rss.http.outcome", outcome.as_label()),
        ];
        if let Some(route) = self.route {
            labels.push(Label::new("http.route", route));
        }
        if let Some(status) = status {
            labels.push(Label::new(
                "http.response.status_code",
                status.as_u16().to_string(),
            ));
        }
        if let Some(error_type) = error_type {
            labels.push(Label::new("error.type", error_type));
        }
        metrics::histogram!(REQUEST_DURATION, labels).record(self.timer.finish());
        self.active.decrement(1.0);
    }
}

pub(super) struct RequestObservation {
    core: Option<ObservationCore>,
}

impl RequestObservation {
    pub(super) fn new(
        method: &Method,
        version: Version,
        scheme: TransportScheme,
        listener: httpserve::ServerObservationListener,
    ) -> Self {
        let method = ObservedHttpMethod::from_method(method);
        let name = method.name_token();
        let protocol = match version {
            Version::HTTP_09 => "0.9",
            Version::HTTP_10 => "1.0",
            Version::HTTP_11 => "1.1",
            Version::HTTP_2 => "2",
            Version::HTTP_3 => "3",
            _ => "_OTHER",
        };
        // Start the monotonic operation clock immediately before creating the SERVER span. Metric
        // descriptor/handle registration below must not inflate the first request's span-relative
        // duration.
        let timer = RequestTimer::start();
        let span = tracing::info_span!(
            parent: None,
            "http.server.request",
            otel.kind = "server",
            otel.name = name,
            "http.request.method" = method.as_label(),
            "url.scheme" = scheme.as_label(),
            "http.route" = tracing::field::Empty,
            "network.protocol.version" = protocol,
            "http.response.status_code" = tracing::field::Empty,
            "error.type" = tracing::field::Empty,
            "rss.http.listener" = listener.as_label(),
            "rss.http.status_class" = tracing::field::Empty,
            "rss.http.outcome" = tracing::field::Empty,
            otel.status_code = tracing::field::Empty,
        );
        metrics::describe_histogram!(
            REQUEST_DURATION,
            Unit::Seconds,
            "HTTP server request duration through response-body termination"
        );
        metrics::describe_gauge!(
            ACTIVE_REQUESTS,
            Unit::Count,
            "HTTP server requests whose response body has not terminated"
        );
        let active = metrics::gauge!(
            ACTIVE_REQUESTS,
            vec![
                Label::new("http.request.method", method.as_label()),
                Label::new("url.scheme", scheme.as_label()),
                Label::new("rss.http.listener", listener.as_label()),
            ]
        );
        active.increment(1.0);
        Self {
            core: Some(ObservationCore {
                method,
                route: None,
                scheme,
                listener,
                span,
                timer,
                active,
            }),
        }
    }

    pub(super) fn span(&self) -> tracing::Span {
        self.core
            .as_ref()
            .map_or_else(tracing::Span::none, |core| core.span.clone())
    }

    pub(super) fn observe_response(mut self, response: httpserve::ServerResponse) -> Response {
        let status = response.response().status();
        if let Some(core) = self.core.as_mut() {
            core.observe_route(response.route());
        }
        let cause = response.cause();
        let response = response.into_response();
        let (parts, body) = response.into_parts();
        let mut observation = ResponseObservation {
            core: self.core.take(),
            status,
            cause,
        };
        if body.is_end_stream() {
            observation.settle_eos();
            return Response::from_parts(parts, body);
        }
        Response::from_parts(parts, Body::new(ObservedBody { body, observation }))
    }
}

impl Drop for RequestObservation {
    fn drop(&mut self) {
        if let Some(core) = self.core.take() {
            let outcome = if std::thread::panicking() {
                TerminalOutcome::Panic
            } else {
                TerminalOutcome::Cancelled
            };
            core.settle(None, outcome);
        }
    }
}

struct ResponseObservation {
    core: Option<ObservationCore>,
    status: StatusCode,
    cause: Option<httpserve::ServerResponseCauseKind>,
}

impl ResponseObservation {
    fn span(&self) -> tracing::Span {
        self.core
            .as_ref()
            .map_or_else(tracing::Span::none, |core| core.span.clone())
    }

    fn settle(&mut self, outcome: TerminalOutcome) {
        if let Some(core) = self.core.take() {
            core.settle(Some(self.status), outcome);
        }
    }

    fn settle_eos(&mut self) {
        let outcome = match self.cause {
            Some(httpserve::ServerResponseCauseKind::Timeout) => TerminalOutcome::Timeout,
            Some(httpserve::ServerResponseCauseKind::Panic) => TerminalOutcome::Panic,
            None => TerminalOutcome::Completed,
        };
        self.settle(outcome);
    }
}

impl Drop for ResponseObservation {
    fn drop(&mut self) {
        let outcome = if std::thread::panicking() {
            TerminalOutcome::Panic
        } else {
            TerminalOutcome::Cancelled
        };
        self.settle(outcome);
    }
}

struct ObservedBody {
    body: Body,
    observation: ResponseObservation,
}

impl HttpBody for ObservedBody {
    type Data = <Body as HttpBody>::Data;
    type Error = <Body as HttpBody>::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        let span = this.observation.span();
        let poll = span.in_scope(|| Pin::new(&mut this.body).poll_frame(cx));
        match &poll {
            Poll::Ready(Some(Err(_))) => this.observation.settle(TerminalOutcome::BodyError),
            Poll::Ready(Some(Ok(_))) if this.body.is_end_stream() => {
                this.observation.settle_eos();
            }
            Poll::Ready(None) => this.observation.settle_eos(),
            Poll::Pending | Poll::Ready(Some(Ok(_))) => {}
        }
        poll
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.body.size_hint()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    const VALID_PARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

    #[test]
    fn http_method_and_status_labels_are_closed() {
        assert_eq!(
            ObservedHttpMethod::from_method(&Method::from_bytes(b"QUERY").unwrap()).as_label(),
            "QUERY"
        );
        assert_eq!(
            ObservedHttpMethod::from_method(&Method::from_bytes(b"CUSTOM").unwrap()).as_label(),
            "_OTHER"
        );
        assert_eq!(
            StatusClass::from_status(Some(StatusCode::CONTINUE)).as_label(),
            "informational"
        );
        assert_eq!(
            StatusClass::from_status(Some(StatusCode::FOUND)).as_label(),
            "redirection"
        );
        assert_eq!(StatusClass::from_status(None).as_label(), "none");
    }

    #[test]
    fn http_server_inbound_traceparent_rejects_invalid_corpus() {
        for value in [
            "",
            "not-w3c",
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
            "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-0g",
            &"a".repeat(MAX_TRACE_HEADER_BYTES + 1),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(&TRACEPARENT, HeaderValue::from_str(value).unwrap());
            assert!(
                InboundTraceContext::from_headers(&headers).is_none(),
                "{value}"
            );
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn http_trace_diagnostics_are_closed_structured_and_raw_free() {
        const RAW: &str = "SENSITIVE-not-a-traceparent";
        let (_, events) = tracewiretest::with_test_event_capture(|| {
            let mut rejected = HeaderMap::new();
            rejected.insert(&TRACEPARENT, HeaderValue::from_static(RAW));
            assert!(InboundTraceContext::from_headers(&rejected).is_none());

            let mut accepted = HeaderMap::new();
            accepted.insert(&TRACEPARENT, HeaderValue::from_static(VALID_PARENT));
            InboundTraceContext::from_headers(&accepted)
                .expect("valid parent")
                .apply_to(&tracing::info_span!("http.trace.test"));
        });

        let trace_events = events
            .iter()
            .filter(|event| event.target == "rss.trace_context")
            .collect::<Vec<_>>();
        assert_eq!(
            trace_events.len(),
            2,
            "one rejection and one attach outcome"
        );
        assert!(trace_events.iter().all(|event| {
            event.fields.get("transport").map(String::as_str) == Some("http")
                && event.fields.get("operation").map(String::as_str) == Some("server.receive")
        }));
        assert!(trace_events.iter().any(|event| {
            event.fields.get("reason").map(String::as_str) == Some("malformed traceparent")
        }));
        assert!(trace_events.iter().any(|event| {
            event.fields.get("reason").map(String::as_str) == Some("attach_unavailable")
        }));
        assert!(
            trace_events
                .iter()
                .flat_map(|event| event.fields.values())
                .all(|value| !value.contains(RAW))
        );
    }

    #[test]
    fn http_server_inbound_traceparent_rejects_non_utf8_and_accepts_512_byte_future_version() {
        let mut non_utf8 = HeaderMap::new();
        non_utf8.insert(&TRACEPARENT, HeaderValue::from_bytes(&[0xff]).unwrap());
        assert!(InboundTraceContext::from_headers(&non_utf8).is_none());

        let prefix = "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extension=";
        let future = format!(
            "{prefix}{}",
            "a".repeat(MAX_TRACE_HEADER_BYTES - prefix.len())
        );
        assert_eq!(future.len(), MAX_TRACE_HEADER_BYTES);
        let mut boundary = HeaderMap::new();
        boundary.insert(&TRACEPARENT, HeaderValue::from_str(&future).unwrap());
        assert!(InboundTraceContext::from_headers(&boundary).is_some());
    }

    #[test]
    fn http_server_inbound_context_requires_exactly_one_parent_and_joins_state_in_wire_order() {
        let mut headers = HeaderMap::new();
        assert!(InboundTraceContext::from_headers(&headers).is_none());
        headers.append(&TRACEPARENT, HeaderValue::from_static(VALID_PARENT));
        headers.append(&TRACESTATE, HeaderValue::from_static("one=1"));
        headers.append(&TRACESTATE, HeaderValue::from_static("two=2"));
        let context = InboundTraceContext::from_headers(&headers).unwrap();
        assert_eq!(context.tracestate.as_deref(), Some("one=1,two=2"));
        headers.append(&TRACEPARENT, HeaderValue::from_static(VALID_PARENT));
        assert!(InboundTraceContext::from_headers(&headers).is_none());
    }

    #[test]
    fn http_server_inbound_context_drops_bad_state_but_keeps_valid_parent() {
        let mut non_utf8 = HeaderMap::new();
        non_utf8.insert(&TRACEPARENT, HeaderValue::from_static(VALID_PARENT));
        non_utf8.insert(&TRACESTATE, HeaderValue::from_bytes(&[0xff]).unwrap());
        let context = InboundTraceContext::from_headers(&non_utf8).unwrap();
        assert_eq!(context.tracestate, None);

        let mut oversized = HeaderMap::new();
        oversized.insert(&TRACEPARENT, HeaderValue::from_static(VALID_PARENT));
        oversized.insert(
            &TRACESTATE,
            HeaderValue::from_str(&"a".repeat(MAX_TRACE_HEADER_BYTES + 1)).unwrap(),
        );
        let context = InboundTraceContext::from_headers(&oversized).unwrap();
        assert_eq!(context.tracestate, None);
    }
}
