//! Cross-domain synchronous transport seam.
//!
//! `HttpContractTransport` is the provider-agnostic dispatch seam used by composition roots to route a
//! contract HTTP call either in-process or through a remote transport adapter. This module owns the
//! closed metric label vocab for that seam so `distributed` can emit low-cardinality metrics without
//! depending on `observ`, `httpserve`, or any adapter crate.

use std::time::SystemTime;

use futures::future::BoxFuture;
use tracing::Instrument as _;
use vocab::ContractBinding;

/// HTTP method closed set for cross-domain contract dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpContractMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl HttpContractMethod {
    /// Stable wire label for diagnostics.
    pub fn as_str(self) -> &'static str {
        match self {
            HttpContractMethod::Get => "GET",
            HttpContractMethod::Post => "POST",
            HttpContractMethod::Put => "PUT",
            HttpContractMethod::Patch => "PATCH",
            HttpContractMethod::Delete => "DELETE",
        }
    }

    fn from_route_token(method: &str) -> Option<Self> {
        match method {
            "GET" => Some(Self::Get),
            "POST" => Some(Self::Post),
            "PUT" => Some(Self::Put),
            "PATCH" => Some(Self::Patch),
            "DELETE" => Some(Self::Delete),
            _ => None,
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

/// Concrete, contract-bound HTTP origin-form target.
///
/// The fields are private so a static route template cannot cross the transport seam. The only
/// constructor binds every generated path parameter and validates query names against generated
/// request-schema metadata before URL encoding either component.
#[derive(Clone, secure::Redact)]
pub struct HttpContractTarget {
    #[redact(sensitivity = public, mode = "show")]
    contract: ContractBinding,
    #[redact(sensitivity = public, mode = "show")]
    method: HttpContractMethod,
    #[redact(sensitivity = secret)]
    path: String,
    #[redact(sensitivity = secret)]
    query: Option<String>,
}

impl HttpContractTarget {
    /// Bind generated route evidence to concrete path and query parameter values.
    pub fn try_bind(
        route: vocab::HttpRouteEvidence,
        path_parameters: &[(&str, &str)],
        query_parameters: &[(&str, &str)],
    ) -> Result<Self, HttpContractTransportError> {
        let method = HttpContractMethod::from_route_token(route.method())
            .ok_or_else(invalid_contract_target)?;
        reject_duplicate_names(path_parameters)?;
        reject_duplicate_names(query_parameters)?;

        let mut url =
            url::Url::parse("http://contract.invalid/").map_err(|_| invalid_contract_target())?;
        let mut used_path_parameters = 0usize;
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|()| invalid_contract_target())?;
            segments.clear();
            for segment in route.path().trim_start_matches('/').split('/') {
                if let Some(name) = route_parameter_name(segment) {
                    let (_, value) = path_parameters
                        .iter()
                        .find(|(candidate, _)| *candidate == name)
                        .ok_or_else(invalid_contract_target)?;
                    if value.is_empty() {
                        return Err(invalid_contract_target());
                    }
                    used_path_parameters += 1;
                    segments.push(value);
                } else {
                    if segment.contains(['{', '}']) {
                        return Err(invalid_contract_target());
                    }
                    segments.push(segment);
                }
            }
        }
        if used_path_parameters != path_parameters.len() {
            return Err(invalid_contract_target());
        }

        let specs = route.query_parameters();
        if query_parameters
            .iter()
            .any(|(name, _)| !specs.iter().any(|spec| spec.name() == *name))
        {
            return Err(invalid_contract_target());
        }
        {
            let mut pairs = url.query_pairs_mut();
            for spec in specs {
                match query_parameters
                    .iter()
                    .find(|(name, _)| *name == spec.name())
                {
                    Some((_, value)) => {
                        pairs.append_pair(spec.name(), value);
                    }
                    None if spec.required() => return Err(invalid_contract_target()),
                    None => {}
                }
            }
        }

        Ok(Self {
            contract: route.contract(),
            method,
            path: url.path().to_owned(),
            query: url.query().map(str::to_owned),
        })
    }

    /// Contract binding derived from generated route evidence.
    pub fn contract(&self) -> &ContractBinding {
        &self.contract
    }

    /// Closed HTTP method derived from generated route evidence.
    pub fn method(&self) -> HttpContractMethod {
        self.method
    }

    /// Percent-encoded concrete path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Percent-encoded concrete query without the leading `?`.
    pub fn query(&self) -> Option<&str> {
        self.query.as_deref()
    }
}

fn invalid_contract_target() -> HttpContractTransportError {
    HttpContractTransportError::new(HttpContractTransportErrorKind::Dispatch)
}

fn reject_duplicate_names(parameters: &[(&str, &str)]) -> Result<(), HttpContractTransportError> {
    for (index, (name, _)) in parameters.iter().enumerate() {
        if name.is_empty()
            || parameters[index + 1..]
                .iter()
                .any(|(candidate, _)| candidate == name)
        {
            return Err(invalid_contract_target());
        }
    }
    Ok(())
}

fn route_parameter_name(segment: &str) -> Option<&str> {
    segment
        .strip_prefix('{')
        .and_then(|name| name.strip_suffix('}'))
        .filter(|name| !name.is_empty() && !name.contains(['{', '}']))
}

/// Minimal cross-domain contract HTTP dispatch request.
///
/// `Debug` is derived through `secure::Redact`: adding a field without an explicit `#[redact(...)]`
/// annotation is a compile error. Path and body may contain tenant/resource identifiers
/// or credentials and are therefore never rendered in clear text.
#[derive(Clone, secure::Redact)]
pub struct HttpContractRequest {
    #[redact(sensitivity = public, mode = "show")]
    target: HttpContractTarget,
    #[redact(sensitivity = secret)]
    body: Vec<u8>,
}

impl HttpContractRequest {
    /// Construct a dispatch request from one validated concrete target.
    #[must_use]
    pub fn new(target: HttpContractTarget, body: Vec<u8>) -> Self {
        Self { target, body }
    }

    /// Contract binding (target domain + contract id + version + schema hash, same-source).
    pub fn contract(&self) -> &ContractBinding {
        self.target.contract()
    }

    /// HTTP method.
    pub fn method(&self) -> HttpContractMethod {
        self.target.method()
    }

    /// Request path. This may contain resource identifiers; do not place it in metric labels.
    pub fn path(&self) -> &str {
        self.target.path()
    }

    /// Percent-encoded concrete query without the leading `?`.
    pub fn query(&self) -> Option<&str> {
        self.target.query()
    }

    /// Request body bytes.
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

/// Minimal cross-domain contract HTTP dispatch response.
#[derive(Clone, secure::Redact)]
pub struct HttpContractResponse {
    #[redact(sensitivity = public, mode = "show")]
    status_code: u16,
    #[redact(sensitivity = secret)]
    body: Vec<u8>,
}

impl HttpContractResponse {
    /// Maximum response body size accepted across the transport seam.
    pub const MAX_BODY_BYTES: usize = 1024 * 1024;

    /// Construct a bounded dispatch response.
    pub fn try_new(status_code: u16, body: Vec<u8>) -> Result<Self, HttpContractTransportError> {
        if body.len() > Self::MAX_BODY_BYTES {
            return Err(HttpContractTransportError::new(
                HttpContractTransportErrorKind::ResponseTooLarge,
            ));
        }
        Ok(Self { status_code, body })
    }

    /// HTTP status code returned by the target domain transport.
    pub fn status_code(&self) -> u16 {
        self.status_code
    }

    /// Response body bytes.
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

/// Domain transport error kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpContractTransportErrorKind {
    Dispatch,
    Timeout,
    ResponseTooLarge,
    InvalidResponse,
}

impl HttpContractTransportErrorKind {
    /// Stable low-cardinality tracing label.
    pub fn as_label(self) -> &'static str {
        match self {
            Self::Dispatch => "dispatch",
            Self::Timeout => "timeout",
            Self::ResponseTooLarge => "response_too_large",
            Self::InvalidResponse => "invalid_response",
        }
    }
}

/// Domain transport failure. Display is intentionally constant and never expands raw source text.
#[derive(Debug, Clone)]
pub struct HttpContractTransportError {
    kind: HttpContractTransportErrorKind,
    source: Option<secure::LastError>,
}

impl HttpContractTransportError {
    /// Construct an error without a lower-level source.
    pub fn new(kind: HttpContractTransportErrorKind) -> Self {
        Self { kind, source: None }
    }

    /// Construct an error with a redacted source summary.
    pub fn with_source(
        kind: HttpContractTransportErrorKind,
        source: &dyn std::error::Error,
    ) -> Self {
        Self {
            kind,
            source: Some(secure::LastError::from_error(source)),
        }
    }

    /// Error kind.
    pub fn kind(&self) -> HttpContractTransportErrorKind {
        self.kind
    }

    /// Redacted source summary, if a source was captured.
    pub fn source_summary(&self) -> Option<&secure::LastError> {
        self.source.as_ref()
    }
}

impl std::fmt::Display for HttpContractTransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            HttpContractTransportErrorKind::Dispatch => {
                f.write_str("domain transport dispatch failed")
            }
            HttpContractTransportErrorKind::Timeout => f.write_str("domain transport timed out"),
            HttpContractTransportErrorKind::ResponseTooLarge => {
                f.write_str("domain transport response exceeded the size limit")
            }
            HttpContractTransportErrorKind::InvalidResponse => {
                f.write_str("domain transport returned an invalid response")
            }
        }
    }
}

impl std::error::Error for HttpContractTransportError {}

/// Object-safe cross-domain transport trait.
pub trait HttpContractTransport: Send + Sync {
    /// Dispatch one contract HTTP request.
    fn dispatch(
        &self,
        request: HttpContractRequest,
    ) -> BoxFuture<'_, Result<HttpContractResponse, HttpContractTransportError>>;
}

/// Metrics/tracing wrapper for a concrete domain transport.
pub struct InstrumentedHttpContractTransport<T> {
    inner: T,
    mode: TransportMode,
    clock: Box<dyn diport::Clock>,
}

impl<T> InstrumentedHttpContractTransport<T> {
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

impl<T: HttpContractTransport> HttpContractTransport for InstrumentedHttpContractTransport<T> {
    fn dispatch(
        &self,
        request: HttpContractRequest,
    ) -> BoxFuture<'_, Result<HttpContractResponse, HttpContractTransportError>> {
        Box::pin(async move {
            let mode = self.mode;
            let start = self.clock.now();
            let span = tracing::info_span!(
                "domain_transport.dispatch",
                transport_mode = mode.as_label(),
                domain = request.contract().domain(),
                contract_id = request.contract().contract_id(),
                outcome = tracing::field::Empty,
                error_kind = tracing::field::Empty,
            );
            let result = self.inner.dispatch(request).instrument(span.clone()).await;
            let outcome = if result.is_ok() {
                TransportOutcome::Ok
            } else {
                TransportOutcome::Error
            };
            span.record("outcome", outcome.as_label());
            if let Err(error) = &result {
                span.record("error_kind", error.kind().as_label());
            }
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
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::{Duration, SystemTime};

    const TEST_EFFECTS: &[vocab::HttpEffectKind] = &[vocab::HttpEffectKind::Read];

    fn route_evidence(path: &'static str, method: &'static str) -> vocab::HttpRouteEvidence {
        route_evidence_with_query(path, method, &[])
    }

    fn route_evidence_with_query(
        path: &'static str,
        method: &'static str,
        query_parameters: &'static [vocab::http::HttpQueryParameterSpec],
    ) -> vocab::HttpRouteEvidence {
        const HASH: &str =
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        vocab::HttpRouteEvidence::from_static(
            vocab::HttpContractOwner::domain("identity"),
            ContractBinding::from_static("identity", "identity.login", "v1", HASH),
            path,
            method,
            query_parameters,
            vocab::HttpSuccessStatus::new(200),
            vocab::HttpIdempotency::Idempotent,
            vocab::HttpRouteAuth::Public,
            None,
            false,
            vocab::http::HttpResourceSharing::TenantScoped,
            vocab::HttpConsistencyLevel::LocalOnly,
            vocab::HttpEffectProfile::new(TEST_EFFECTS),
        )
    }

    struct StepClock {
        next: Mutex<u64>,
    }

    #[derive(Clone)]
    struct CapturedSpan {
        name: &'static str,
        fields: HashMap<String, String>,
    }

    #[derive(Default)]
    struct SpanCapture {
        spans: Mutex<Vec<CapturedSpan>>,
    }

    struct SpanFields<'a>(&'a mut HashMap<String, String>);

    impl tracing::field::Visit for SpanFields<'_> {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.0.insert(field.name().to_owned(), format!("{value:?}"));
        }

        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.0.insert(field.name().to_owned(), value.to_owned());
        }
    }

    impl tracing::Subscriber for SpanCapture {
        fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
            true
        }

        #[allow(clippy::expect_used)]
        fn new_span(&self, attributes: &tracing::span::Attributes<'_>) -> tracing::Id {
            let mut fields = HashMap::new();
            attributes.record(&mut SpanFields(&mut fields));
            let mut spans = self.spans.lock().expect("span capture lock");
            let id = u64::try_from(spans.len() + 1).unwrap_or(u64::MAX);
            spans.push(CapturedSpan {
                name: attributes.metadata().name(),
                fields,
            });
            tracing::Id::from_u64(id)
        }

        #[allow(clippy::expect_used)]
        fn record(&self, span: &tracing::Id, values: &tracing::span::Record<'_>) {
            let mut fields = HashMap::new();
            values.record(&mut SpanFields(&mut fields));
            let index = usize::try_from(span.into_u64())
                .expect("span id fits usize")
                .saturating_sub(1);
            if let Some(captured) = self.spans.lock().expect("span capture lock").get_mut(index) {
                captured.fields.extend(fields);
            }
        }

        fn record_follows_from(&self, _span: &tracing::Id, _follows: &tracing::Id) {}
        fn event(&self, _event: &tracing::Event<'_>) {}
        fn enter(&self, _span: &tracing::Id) {}
        fn exit(&self, _span: &tracing::Id) {}
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

    impl HttpContractTransport for OkTransport {
        fn dispatch(
            &self,
            _request: HttpContractRequest,
        ) -> BoxFuture<'_, Result<HttpContractResponse, HttpContractTransportError>> {
            async { HttpContractResponse::try_new(204, Vec::new()) }.boxed()
        }
    }

    struct FailTransport;

    impl HttpContractTransport for FailTransport {
        fn dispatch(
            &self,
            _request: HttpContractRequest,
        ) -> BoxFuture<'_, Result<HttpContractResponse, HttpContractTransportError>> {
            async {
                Err(HttpContractTransportError::with_source(
                    HttpContractTransportErrorKind::Dispatch,
                    &std::io::Error::other("leak-marker-token"),
                ))
            }
            .boxed()
        }
    }

    #[allow(clippy::expect_used)]
    fn request() -> HttpContractRequest {
        HttpContractRequest::new(
            HttpContractTarget::try_bind(
                route_evidence("/api/v1/tenant-123/session", "POST"),
                &[],
                &[],
            )
            .expect("concrete contract target"),
            b"password=secret".to_vec(),
        )
    }

    #[test]
    fn closed_labels_are_stable() {
        assert_eq!(TransportMode::InProc.as_label(), "in_proc");
        assert_eq!(TransportMode::Remote.as_label(), "remote");
        assert_eq!(TransportOutcome::Ok.as_label(), "ok");
        assert_eq!(TransportOutcome::Error.as_label(), "error");
        assert_eq!(HttpContractMethod::Get.as_str(), "GET");
        assert_eq!(HttpContractMethod::Post.as_str(), "POST");
        assert_eq!(HttpContractMethod::Put.as_str(), "PUT");
        assert_eq!(HttpContractMethod::Patch.as_str(), "PATCH");
        assert_eq!(HttpContractMethod::Delete.as_str(), "DELETE");
        assert_eq!(
            HttpContractTransportErrorKind::ResponseTooLarge.as_label(),
            "response_too_large"
        );
    }

    #[test]
    fn http_contract_request_rejects_method_outside_closed_set() {
        let error = HttpContractTarget::try_bind(
            route_evidence("/api/v1/tenant-123/session", "TRACE"),
            &[],
            &[],
        )
        .expect_err("generated route method must belong to the transport closed set");
        assert_eq!(error.kind(), HttpContractTransportErrorKind::Dispatch);
    }

    #[test]
    fn unresolved_route_template_cannot_become_a_dispatch_request() {
        let error = HttpContractTarget::try_bind(
            route_evidence("/api/v1/tenants/{tenantId}/entries", "GET"),
            &[],
            &[],
        )
        .expect_err("a static path template is not a concrete HTTP request target");

        assert_eq!(error.kind(), HttpContractTransportErrorKind::Dispatch);
    }

    #[test]
    fn contract_target_binds_and_encodes_path_and_generated_query_parameters() {
        const QUERY: &[vocab::http::HttpQueryParameterSpec] = &[
            vocab::http::HttpQueryParameterSpec::from_static("cursor", false),
            vocab::http::HttpQueryParameterSpec::from_static("limit", true),
        ];
        let route = route_evidence_with_query("/api/v1/tenants/{tenantId}/entries", "GET", QUERY);

        let target = HttpContractTarget::try_bind(
            route,
            &[("tenantId", "tenant/blue")],
            &[("limit", "50"), ("cursor", "next + one")],
        )
        .expect("complete generated target binding");

        assert_eq!(target.path(), "/api/v1/tenants/tenant%2Fblue/entries");
        assert_eq!(target.query(), Some("cursor=next+%2B+one&limit=50"));
        for invalid in [
            vec![("cursor", "next")],
            vec![("limit", "50"), ("unknown", "value")],
            vec![("limit", "50"), ("limit", "51")],
        ] {
            assert!(
                HttpContractTarget::try_bind(route, &[("tenantId", "tenant")], &invalid).is_err()
            );
        }
    }

    #[test]
    fn domain_request_debug_redacts_sensitive_fields() {
        let dbg = format!("{:?}", request());
        // contract binding is public routing metadata (domain + contract_id shown; schema fields remain typed accessors).
        assert!(dbg.contains("identity.login"), "{dbg}");
        assert!(dbg.contains("Post"), "{dbg}");
        // path / body are secret-redacted: neither resource ids nor payload values leak.
        assert!(!dbg.contains("tenant-123"), "{dbg}");
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
    fn domain_response_debug_redacts_sensitive_fields() {
        let response =
            HttpContractResponse::try_new(200, b"secret-body".to_vec()).expect("bounded response");
        let dbg = format!("{response:?}");
        assert!(dbg.contains("200"), "{dbg}");
        assert!(!dbg.contains("secret-body"), "{dbg}");
        assert!(dbg.contains("<redacted>"), "{dbg}");
    }

    #[test]
    fn domain_response_constructor_enforces_body_bound() {
        let exact =
            HttpContractResponse::try_new(200, vec![0; HttpContractResponse::MAX_BODY_BYTES])
                .expect("body at the bound is valid");
        assert_eq!(exact.body().len(), HttpContractResponse::MAX_BODY_BYTES);

        let err =
            HttpContractResponse::try_new(200, vec![0; HttpContractResponse::MAX_BODY_BYTES + 1])
                .expect_err("body above the bound is invalid");
        assert_eq!(err.kind(), HttpContractTransportErrorKind::ResponseTooLarge);
    }

    #[test]
    fn error_display_does_not_expand_source_text() {
        let err = HttpContractTransportError::with_source(
            HttpContractTransportErrorKind::Dispatch,
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
                let ok = InstrumentedHttpContractTransport::new(
                    OkTransport,
                    TransportMode::InProc,
                    Box::new(StepClock::new()),
                );
                let fail = InstrumentedHttpContractTransport::new(
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

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn instrumentation_records_closed_span_outcome_and_error_kind() {
        let subscriber = std::sync::Arc::new(SpanCapture::default());
        let dispatch = tracing::Dispatch::new(std::sync::Arc::clone(&subscriber));
        let _guard = tracing::dispatcher::set_default(&dispatch);
        let ok = InstrumentedHttpContractTransport::new(
            OkTransport,
            TransportMode::InProc,
            Box::new(StepClock::new()),
        );
        let fail = InstrumentedHttpContractTransport::new(
            FailTransport,
            TransportMode::Remote,
            Box::new(StepClock::new()),
        );

        assert!(ok.dispatch(request()).await.is_ok());
        assert!(fail.dispatch(request()).await.is_err());

        let spans = subscriber.spans.lock().expect("span capture lock");
        let dispatches = spans
            .iter()
            .filter(|span| span.name == "domain_transport.dispatch")
            .collect::<Vec<_>>();
        assert_eq!(dispatches.len(), 2);
        assert_eq!(
            dispatches[0].fields.get("outcome").map(String::as_str),
            Some("ok")
        );
        assert!(!dispatches[0].fields.contains_key("error_kind"));
        assert_eq!(
            dispatches[1].fields.get("outcome").map(String::as_str),
            Some("error")
        );
        assert_eq!(
            dispatches[1].fields.get("error_kind").map(String::as_str),
            Some("dispatch")
        );
    }
}
