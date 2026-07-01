//! Cross-domain synchronous transport seam.
//!
//! `DomainTransport` is the provider-agnostic dispatch seam used by composition roots to route a
//! contract HTTP call either in-process or through a remote transport adapter. This module owns the
//! closed metric label vocab for that seam so `distributed` can emit low-cardinality metrics without
//! depending on `observ`, `httpserve`, or any adapter crate.

use std::time::SystemTime;

use futures::future::BoxFuture;
use tracing::Instrument as _;
use vocab::ContractBinding;

/// HTTP method closed set for cross-domain contract dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl DomainMethod {
    /// Stable wire label for diagnostics.
    pub fn as_str(self) -> &'static str {
        match self {
            DomainMethod::Get => "GET",
            DomainMethod::Post => "POST",
            DomainMethod::Put => "PUT",
            DomainMethod::Patch => "PATCH",
            DomainMethod::Delete => "DELETE",
        }
    }
}

/// Transport mode closed set for `transport_mode` metric label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportMode {
    InProc,
    Remote,
}

impl TransportMode {
    /// Stable low-cardinality metric label.
    pub fn as_label(self) -> &'static str {
        match self {
            TransportMode::InProc => "in_proc",
            TransportMode::Remote => "remote",
        }
    }
}

/// Dispatch outcome closed set for `outcome` metric label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportOutcome {
    Ok,
    Error,
}

impl TransportOutcome {
    /// Stable low-cardinality metric label.
    pub fn as_label(self) -> &'static str {
        match self {
            TransportOutcome::Ok => "ok",
            TransportOutcome::Error => "error",
        }
    }
}

/// Diagnostic / context-propagation headers a caller may author on a cross-domain dispatch.
///
/// Lower-case, fail-closed allowlist. Only correlation and W3C trace-context headers are safe for
/// a caller to supply. Authentication (`authorization`, `cookie`), tenant scope (`x-tenant-id`) and
/// service-to-service credentials are **never** caller-supplied — they are minted from the
/// authenticated channel / contract-derived auth plan by the transport adapter (zero-trust
/// default-deny). `baggage` is intentionally excluded: it can carry arbitrary caller key-values.
const ALLOWED_TRANSPORT_HEADERS: &[&str] = &[
    "correlation-id",
    "x-correlation-id",
    "request-id",
    "x-request-id",
    "traceparent",
    "tracestate",
];

/// Validated header set for a cross-domain dispatch — diagnostic / propagation headers only.
///
/// Newtype funnel: the inner vec is private and [`TransportHeaders::try_new`] is the only
/// fabricating constructor, so a [`DomainRequest`] cannot carry a raw header bag and
/// security-relevant headers are *unrepresentable* past this boundary (no caller self-discipline).
/// Names are matched case-insensitively against [`ALLOWED_TRANSPORT_HEADERS`]; the first disallowed
/// or empty name fails the whole set closed. Mirrors the crate's `LockKey::parse` fail-closed funnel.
///
/// INVARIANT: TRANSPORT-HEADERS-ALLOWLIST-01 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" }(Hard newtype boundary + fail-closed allowlist funnel):
/// `DomainRequest` holds `TransportHeaders`, never `Vec<(String, String)>`, so `authorization` /
/// `cookie` / `x-tenant-id` cannot reach the wire through this seam.
///
/// `Debug` is exposing (not redacted): by construction the entries are diagnostic / trace-context
/// headers only — they exist to be observable. The `DomainRequest.headers` field is nonetheless
/// `#[redact(sensitivity = secret)]` so a full-request Debug stays terse.
#[derive(Debug, Clone, Default)]
pub struct TransportHeaders {
    entries: Vec<(String, String)>,
}

impl TransportHeaders {
    /// Empty header set (no caller-supplied headers).
    pub fn empty() -> Self {
        Self::default()
    }

    /// Build a validated header set. Each name is trimmed and lower-cased, then checked against the
    /// diagnostic allowlist; the first disallowed or empty name fails the whole set closed. Values
    /// are stored verbatim (the adapter forwards them on the wire request).
    pub fn try_new(headers: Vec<(String, String)>) -> Result<Self, TransportHeaderError> {
        for (name, _) in &headers {
            let canonical = name.trim().to_ascii_lowercase();
            if canonical.is_empty() {
                return Err(TransportHeaderError::EmptyName);
            }
            if !ALLOWED_TRANSPORT_HEADERS.contains(&canonical.as_str()) {
                return Err(TransportHeaderError::Forbidden { name: canonical });
            }
        }
        Ok(Self { entries: headers })
    }

    /// Borrow the validated header entries (adapter reads these to build the wire request).
    pub fn as_slice(&self) -> &[(String, String)] {
        &self.entries
    }
}

/// [`TransportHeaders`] construction error (fail-closed allowlist funnel).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransportHeaderError {
    /// A header name was empty or whitespace-only.
    #[error("transport header name is empty")]
    EmptyName,
    /// A caller-supplied header is not on the diagnostic allowlist (e.g. `authorization`, `cookie`,
    /// `x-tenant-id`). The name is a non-secret identifier; values are never echoed.
    #[error("caller-supplied transport header is not allowed: {name}")]
    Forbidden {
        /// Lower-cased rejected header name (non-secret).
        name: String,
    },
}

/// Minimal cross-domain contract HTTP dispatch request.
///
/// `Debug` is derived through `secure::Redact`: adding a field without an explicit `#[redact(...)]`
/// annotation is a compile error. Path, headers, and body may contain tenant/resource identifiers
/// or credentials and are therefore never rendered in clear text.
#[derive(Clone, secure::Redact)]
pub struct DomainRequest {
    #[redact(sensitivity = public, mode = "show")]
    contract: ContractBinding,
    #[redact(sensitivity = public, mode = "show")]
    method: DomainMethod,
    #[redact(sensitivity = secret)]
    path: String,
    #[redact(sensitivity = secret)]
    headers: TransportHeaders,
    #[redact(sensitivity = secret)]
    body: Vec<u8>,
}

impl DomainRequest {
    /// Construct a dispatch request. `contract` binds the target domain and contract id at a single
    /// source (`generated::…::CONTRACT`), so they cannot drift; `headers` is a validated
    /// [`TransportHeaders`] set. The caller passes a contract-derived path; this seam deliberately
    /// does not parse HTTP.
    pub fn new(
        contract: ContractBinding,
        method: DomainMethod,
        path: impl Into<String>,
        headers: TransportHeaders,
        body: Vec<u8>,
    ) -> Self {
        Self {
            contract,
            method,
            path: path.into(),
            headers,
            body,
        }
    }

    /// Contract binding (target domain + contract id + version + schema hash, same-source).
    pub fn contract(&self) -> &ContractBinding {
        &self.contract
    }

    /// HTTP method.
    pub fn method(&self) -> DomainMethod {
        self.method
    }

    /// Request path. This may contain resource identifiers; do not place it in metric labels.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Validated request headers (diagnostic / propagation only).
    pub fn headers(&self) -> &TransportHeaders {
        &self.headers
    }

    /// Request body bytes.
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

/// Minimal cross-domain contract HTTP dispatch response.
#[derive(Clone, secure::Redact)]
pub struct DomainResponse {
    #[redact(sensitivity = public, mode = "show")]
    status_code: u16,
    #[redact(sensitivity = secret)]
    headers: Vec<(String, String)>,
    #[redact(sensitivity = secret)]
    body: Vec<u8>,
}

impl DomainResponse {
    /// Construct a dispatch response.
    pub fn new(status_code: u16, headers: Vec<(String, String)>, body: Vec<u8>) -> Self {
        Self {
            status_code,
            headers,
            body,
        }
    }

    /// HTTP status code returned by the target domain transport.
    pub fn status_code(&self) -> u16 {
        self.status_code
    }

    /// Response headers.
    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    /// Response body bytes.
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

/// Domain transport error kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainTransportErrorKind {
    Dispatch,
    Timeout,
    InvalidResponse,
}

/// Domain transport failure. Display is intentionally constant and never expands raw source text.
#[derive(Debug, Clone)]
pub struct DomainTransportError {
    kind: DomainTransportErrorKind,
    source: Option<secure::LastError>,
}

impl DomainTransportError {
    /// Construct an error without a lower-level source.
    pub fn new(kind: DomainTransportErrorKind) -> Self {
        Self { kind, source: None }
    }

    /// Construct an error with a redacted source summary.
    pub fn with_source(kind: DomainTransportErrorKind, source: &dyn std::error::Error) -> Self {
        Self {
            kind,
            source: Some(secure::LastError::from_error(source)),
        }
    }

    /// Error kind.
    pub fn kind(&self) -> DomainTransportErrorKind {
        self.kind
    }

    /// Redacted source summary, if a source was captured.
    pub fn source_summary(&self) -> Option<&secure::LastError> {
        self.source.as_ref()
    }
}

impl std::fmt::Display for DomainTransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            DomainTransportErrorKind::Dispatch => f.write_str("domain transport dispatch failed"),
            DomainTransportErrorKind::Timeout => f.write_str("domain transport timed out"),
            DomainTransportErrorKind::InvalidResponse => {
                f.write_str("domain transport returned an invalid response")
            }
        }
    }
}

impl std::error::Error for DomainTransportError {}

/// Object-safe cross-domain transport trait.
pub trait DomainTransport: Send + Sync {
    /// Dispatch one contract HTTP request.
    fn dispatch(
        &self,
        request: DomainRequest,
    ) -> BoxFuture<'_, Result<DomainResponse, DomainTransportError>>;
}

/// Metrics/tracing wrapper for a concrete domain transport.
pub struct InstrumentedDomainTransport<T> {
    inner: T,
    mode: TransportMode,
    clock: Box<dyn diport::Clock>,
}

impl<T> InstrumentedDomainTransport<T> {
    /// Construct an instrumented transport. `clock` is injected to satisfy workspace clock
    /// discipline; this crate never calls system time directly.
    pub fn new(inner: T, mode: TransportMode, clock: Box<dyn diport::Clock>) -> Self {
        Self { inner, mode, clock }
    }

    /// Borrow the wrapped transport.
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// Transport mode used for metrics and spans.
    pub fn mode(&self) -> TransportMode {
        self.mode
    }
}

impl<T: DomainTransport> DomainTransport for InstrumentedDomainTransport<T> {
    fn dispatch(
        &self,
        request: DomainRequest,
    ) -> BoxFuture<'_, Result<DomainResponse, DomainTransportError>> {
        Box::pin(async move {
            let mode = self.mode;
            let start = self.clock.now();
            let span = tracing::info_span!(
                "domain_transport.dispatch",
                transport_mode = mode.as_label(),
                domain = request.contract().domain(),
                contract_id = request.contract().contract_id(),
            );
            let result = self.inner.dispatch(request).instrument(span).await;
            let outcome = if result.is_ok() {
                TransportOutcome::Ok
            } else {
                TransportOutcome::Error
            };
            let seconds = elapsed_seconds(start, self.clock.now());
            record_dispatch_metrics(mode, outcome, seconds);
            result
        })
    }
}

fn elapsed_seconds(start: SystemTime, end: SystemTime) -> f64 {
    end.duration_since(start)
        .map(|duration| duration.as_secs_f64())
        .unwrap_or(0.0)
}

fn record_dispatch_metrics(mode: TransportMode, outcome: TransportOutcome, seconds: f64) {
    metrics::counter!(
        "domain_transport_dispatch_total",
        "transport_mode" => mode.as_label(),
        "outcome" => outcome.as_label(),
    )
    .increment(1);
    metrics::histogram!(
        "domain_transport_dispatch_duration_seconds",
        "transport_mode" => mode.as_label(),
        "outcome" => outcome.as_label(),
    )
    .record(seconds);
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::FutureExt as _;
    use std::sync::Mutex;
    use std::time::{Duration, SystemTime};

    struct StepClock {
        next: Mutex<u64>,
    }

    impl StepClock {
        fn new() -> Self {
            Self {
                next: Mutex::new(0),
            }
        }
    }

    impl diport::Clock for StepClock {
        fn now(&self) -> SystemTime {
            let mut next = self.next.lock().unwrap_or_else(|e| e.into_inner());
            let current = *next;
            *next = next.saturating_add(1);
            SystemTime::UNIX_EPOCH + Duration::from_secs(current)
        }
    }

    struct OkTransport;

    impl DomainTransport for OkTransport {
        fn dispatch(
            &self,
            _request: DomainRequest,
        ) -> BoxFuture<'_, Result<DomainResponse, DomainTransportError>> {
            async { Ok(DomainResponse::new(204, Vec::new(), Vec::new())) }.boxed()
        }
    }

    struct FailTransport;

    impl DomainTransport for FailTransport {
        fn dispatch(
            &self,
            _request: DomainRequest,
        ) -> BoxFuture<'_, Result<DomainResponse, DomainTransportError>> {
            async {
                Err(DomainTransportError::with_source(
                    DomainTransportErrorKind::Dispatch,
                    &std::io::Error::other("leak-marker-token"),
                ))
            }
            .boxed()
        }
    }

    #[allow(clippy::expect_used)]
    // reason: 测试用 allowlisted literal 构造 TransportHeaders，item-level carve-out（error-handling.md §Carve-out）。
    fn request() -> DomainRequest {
        const HASH: &str =
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        DomainRequest::new(
            ContractBinding::from_static("identity", "identity.login", "v1", HASH),
            DomainMethod::Post,
            "/api/v1/tenant-123/session",
            TransportHeaders::try_new(vec![("x-correlation-id".to_owned(), "corr-abc".to_owned())])
                .expect("allowlisted diagnostic header"),
            b"password=secret".to_vec(),
        )
    }

    #[test]
    fn closed_labels_are_stable() {
        assert_eq!(TransportMode::InProc.as_label(), "in_proc");
        assert_eq!(TransportMode::Remote.as_label(), "remote");
        assert_eq!(TransportOutcome::Ok.as_label(), "ok");
        assert_eq!(TransportOutcome::Error.as_label(), "error");
        assert_eq!(DomainMethod::Get.as_str(), "GET");
        assert_eq!(DomainMethod::Post.as_str(), "POST");
        assert_eq!(DomainMethod::Put.as_str(), "PUT");
        assert_eq!(DomainMethod::Patch.as_str(), "PATCH");
        assert_eq!(DomainMethod::Delete.as_str(), "DELETE");
    }

    #[test]
    fn domain_request_debug_redacts_sensitive_fields() {
        let dbg = format!("{:?}", request());
        // contract binding is public routing metadata (domain + contract_id shown; schema fields remain typed accessors).
        assert!(dbg.contains("identity.login"), "{dbg}");
        assert!(dbg.contains("Post"), "{dbg}");
        // path / headers / body are secret-redacted: neither resource ids nor header values leak.
        assert!(!dbg.contains("tenant-123"), "{dbg}");
        assert!(!dbg.contains("corr-abc"), "{dbg}");
        assert!(!dbg.contains("password=secret"), "{dbg}");
        assert!(dbg.contains("<redacted>"), "{dbg}");
    }

    #[test]
    fn contract_binding_is_single_source() {
        // F1: domain + contract_id + version + schema_hash derive from one ContractBinding, so they cannot drift.
        let req = request();
        assert_eq!(req.contract().domain(), "identity");
        assert_eq!(req.contract().contract_id(), "identity.login");
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: 测试用 allowlisted literal 构造 TransportHeaders，item-level carve-out（error-handling.md §Carve-out）。
    fn transport_headers_allow_diagnostic_headers_case_insensitively() {
        let headers = TransportHeaders::try_new(vec![
            ("x-correlation-id".to_owned(), "c-1".to_owned()),
            ("Traceparent".to_owned(), "00-trace".to_owned()),
            ("REQUEST-ID".to_owned(), "r-1".to_owned()),
        ])
        .expect("diagnostic headers are allowlisted (case-insensitive)");
        assert_eq!(headers.as_slice().len(), 3);
        // empty() yields no headers.
        assert!(TransportHeaders::empty().as_slice().is_empty());
    }

    #[test]
    fn transport_headers_reject_security_headers_fail_closed() {
        // anti-vacuity: the old raw `Vec` bag accepted these credential/tenant headers verbatim;
        // the funnel now makes them unrepresentable past the seam boundary.
        for name in [
            "authorization",
            "Cookie",
            "set-cookie",
            "x-tenant-id",
            "proxy-authorization",
            "x-api-key",
            "baggage",
        ] {
            let result = TransportHeaders::try_new(vec![(name.to_owned(), "v".to_owned())]);
            assert!(
                matches!(result, Err(TransportHeaderError::Forbidden { .. })),
                "name={name} must be rejected fail-closed"
            );
        }
    }

    #[test]
    fn transport_headers_reject_empty_name() {
        let result = TransportHeaders::try_new(vec![("   ".to_owned(), "v".to_owned())]);
        assert!(matches!(result, Err(TransportHeaderError::EmptyName)));
    }

    #[test]
    fn transport_headers_one_forbidden_fails_whole_set() {
        // a single disallowed header rejects the whole set — no partial acceptance.
        let result = TransportHeaders::try_new(vec![
            ("x-correlation-id".to_owned(), "ok".to_owned()),
            ("authorization".to_owned(), "Bearer leak".to_owned()),
        ]);
        assert!(
            matches!(result, Err(TransportHeaderError::Forbidden { name }) if name == "authorization"),
        );
    }

    #[test]
    fn domain_response_debug_redacts_sensitive_fields() {
        let response = DomainResponse::new(
            200,
            vec![("set-cookie".to_owned(), "session=secret".to_owned())],
            b"secret-body".to_vec(),
        );
        let dbg = format!("{response:?}");
        assert!(dbg.contains("200"), "{dbg}");
        assert!(!dbg.contains("session=secret"), "{dbg}");
        assert!(!dbg.contains("secret-body"), "{dbg}");
        assert!(dbg.contains("<redacted>"), "{dbg}");
    }

    #[test]
    fn error_display_does_not_expand_source_text() {
        let err = DomainTransportError::with_source(
            DomainTransportErrorKind::Dispatch,
            &std::io::Error::other("leak-marker-token"),
        );
        assert_eq!(err.to_string(), "domain transport dispatch failed");
        assert!(!err.to_string().contains("leak-marker-token"));
        assert!(err.source_summary().is_some());
    }

    #[tokio::test]
    async fn instrumentation_emits_success_and_error_metrics() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            futures::executor::block_on(async {
                let ok = InstrumentedDomainTransport::new(
                    OkTransport,
                    TransportMode::InProc,
                    Box::new(StepClock::new()),
                );
                let fail = InstrumentedDomainTransport::new(
                    FailTransport,
                    TransportMode::Remote,
                    Box::new(StepClock::new()),
                );
                let ok_result = ok.dispatch(request()).await;
                assert!(ok_result.is_ok());
                let fail_result = fail.dispatch(request()).await;
                assert!(fail_result.is_err());
            });
        });
        let rendered = handle.render();
        assert!(
            rendered.contains("domain_transport_dispatch_total"),
            "{rendered}"
        );
        assert!(
            rendered.contains("domain_transport_dispatch_duration_seconds"),
            "{rendered}"
        );
        assert!(
            rendered.contains("transport_mode=\"in_proc\""),
            "{rendered}"
        );
        assert!(rendered.contains("transport_mode=\"remote\""), "{rendered}");
        assert!(rendered.contains("outcome=\"ok\""), "{rendered}");
        assert!(rendered.contains("outcome=\"error\""), "{rendered}");
    }
}
