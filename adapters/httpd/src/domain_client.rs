use std::time::Duration;

use distributed::{
    HttpContractMethod, HttpContractRequest, HttpContractResponse, HttpContractTransportError,
    HttpContractTransportErrorKind,
};
use tracing::Instrument as _;
use vocab::ContractBinding;

pub(super) const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub(super) const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The only holder of the raw HTTP client used for cross-domain dispatch.
///
/// INVARIANT: HTTP-CLIENT-TRACE-FUNNEL-01 { level = "Hard", exec = "native-compile", source = "code", native = "private raw client and sole execute_attempt API" }
#[derive(Clone)]
pub(super) struct ObservedHttpClient {
    inner: reqwest::Client,
}

impl ObservedHttpClient {
    pub(super) fn build_mtls(config: rustls::ClientConfig) -> Result<Self, reqwest::Error> {
        Self::build_sealed(
            reqwest::Client::builder()
                .https_only(true)
                .use_preconfigured_tls(config),
            REQUEST_TIMEOUT,
        )
    }

    fn build_sealed(
        builder: reqwest::ClientBuilder,
        request_timeout: Duration,
    ) -> Result<Self, reqwest::Error> {
        seal_client_builder(builder, request_timeout)
            .build()
            .map(|inner| Self { inner })
    }

    #[cfg(test)]
    pub(super) fn plaintext_for_test() -> Self {
        // reason: the fixed test builder has no fallible runtime input; failure is an environment defect.
        #[allow(clippy::expect_used)]
        Self::build_sealed(reqwest::Client::builder(), REQUEST_TIMEOUT)
            .expect("domain HTTP test client")
    }

    #[cfg(test)]
    pub(super) fn plaintext_with_timeout_for_test(timeout: Duration) -> Self {
        // reason: fixed hermetic test client configuration has no external input.
        #[allow(clippy::expect_used)]
        Self::build_sealed(reqwest::Client::builder(), timeout)
            .expect("timed domain HTTP test client")
    }

    async fn send_once(
        &self,
        url: reqwest::Url,
        method: HttpContractMethod,
        body: Vec<u8>,
        json: bool,
    ) -> HttpAttemptSettlement {
        let mut builder = self.inner.request(reqwest_method(method), url).body(body);
        if json {
            builder = builder.header(reqwest::header::CONTENT_TYPE, "application/json");
        }

        if let Some(context) = tracewire::capture_current() {
            builder = builder.header("traceparent", context.traceparent().as_str());
            if let Some(tracestate) = context.tracestate() {
                builder = builder.header("tracestate", tracestate);
            }
        }
        if let Some(correlation) = diagctx::correlation() {
            builder = builder.header("x-correlation-id", correlation.as_str());
        }

        let response = match builder.send().await {
            Ok(response) => response,
            Err(error) => {
                let kind = classify_send_error(&error);
                return HttpAttemptSettlement::failed(
                    None,
                    HttpContractTransportError::with_source(kind, &error),
                );
            }
        };
        let status = response.status().as_u16();
        match bounded_response_body(response).await {
            Ok(body) => HttpAttemptSettlement::Complete { status, body },
            Err(error) => HttpAttemptSettlement::failed(Some(status), error),
        }
    }

    pub(super) async fn execute_external_csr_json(
        &self,
        url: reqwest::Url,
        body: Vec<u8>,
    ) -> Result<(u16, Vec<u8>), diport::ExternalCsrError> {
        let observation = HttpClientObservation::external_csr_resolve();
        let span = observation.span();
        let guard = HttpAttemptGuard::new(span.clone());
        async move {
            let settlement = self
                .send_once(url, HttpContractMethod::Post, body, true)
                .await;
            let response = guard
                .complete(settlement)
                .map_err(|error| match error.kind() {
                    HttpContractTransportErrorKind::Dispatch
                    | HttpContractTransportErrorKind::Timeout => {
                        diport::ExternalCsrError::Unavailable
                    }
                    HttpContractTransportErrorKind::ResponseTooLarge
                    | HttpContractTransportErrorKind::InvalidResponse => {
                        diport::ExternalCsrError::Rejected
                    }
                })?;
            Ok((response.status_code(), response.body().to_vec()))
        }
        .instrument(span)
        .await
    }

    pub(super) async fn probe_external_csr(&self, url: reqwest::Url) -> bool {
        let settlement = self
            .send_once(url, HttpContractMethod::Get, Vec::new(), false)
            .await;
        matches!(
            settlement,
            HttpAttemptSettlement::Complete {
                status: 200 | 400 | 405,
                ..
            }
        )
    }
}

/// One resolved endpoint and its only legal HTTP-attempt capability.
#[derive(Clone)]
pub(super) struct DomainHttpTarget {
    endpoint: reqwest::Url,
    client: ObservedHttpClient,
}

impl DomainHttpTarget {
    pub(super) fn new(endpoint: reqwest::Url, client: ObservedHttpClient) -> Self {
        Self { endpoint, client }
    }

    pub(super) async fn execute_attempt(
        &self,
        request: HttpContractRequest,
    ) -> Result<HttpContractResponse, HttpContractTransportError> {
        let url = request_url(&self.endpoint, request.path(), request.query())?;
        let observation = HttpClientObservation::contract(*request.contract(), request.method());
        let span = observation.span();
        let guard = HttpAttemptGuard::new(span.clone());
        async move {
            let settlement = self
                .client
                .send_once(url, request.method(), request.body().to_vec(), false)
                .await;
            guard.complete(settlement)
        }
        .instrument(span)
        .await
    }
}

/// Armed while the send future is in flight; cancellation settles the span before it is exported.
struct HttpAttemptGuard {
    span: tracing::Span,
    armed: bool,
}

impl HttpAttemptGuard {
    fn new(span: tracing::Span) -> Self {
        Self { span, armed: true }
    }

    fn complete(
        mut self,
        settlement: HttpAttemptSettlement,
    ) -> Result<HttpContractResponse, HttpContractTransportError> {
        settlement.record(&self.span);
        self.armed = false;
        settlement.into_result()
    }
}

impl Drop for HttpAttemptGuard {
    fn drop(&mut self) {
        if self.armed {
            HttpAttemptSettlement::Cancelled.record(&self.span);
        }
    }
}

/// Safe-by-construction observation input: no URL, headers, body, endpoint, tenant or error text slot.
///
/// INVARIANT: HTTP-CLIENT-OBSERVATION-SURFACE-01 { level = "Hard", exec = "native-compile", source = "code", native = "closed method plus typed contract binding only" }
struct HttpClientObservation {
    method: HttpContractMethod,
    domain: &'static str,
    contract_id: &'static str,
}

impl HttpClientObservation {
    fn contract(contract: ContractBinding, method: HttpContractMethod) -> Self {
        Self {
            method,
            domain: contract.domain(),
            contract_id: contract.contract_id(),
        }
    }

    fn external_csr_resolve() -> Self {
        Self {
            method: HttpContractMethod::Post,
            domain: "external-csr",
            contract_id: "private.external-csr-resolve",
        }
    }

    fn span(&self) -> tracing::Span {
        tracing::info_span!(
            "http.client.request",
            otel.kind = "client",
            otel.name = self.method.as_str(),
            "http.request.method" = self.method.as_str(),
            domain = self.domain,
            contract_id = self.contract_id,
            "http.response.status_code" = tracing::field::Empty,
            outcome = tracing::field::Empty,
            "error.type" = tracing::field::Empty,
            otel.status_code = tracing::field::Empty,
        )
    }
}

/// Closed terminal state; every network attempt is recorded once through [`Self::record`].
///
/// INVARIANT: HTTP-CLIENT-SETTLEMENT-01 { level = "Hard", exec = "native-compile", source = "code", native = "closed terminal enum and centralized recording" }
enum HttpAttemptSettlement {
    Complete {
        status: u16,
        body: Vec<u8>,
    },
    Failed {
        status: Option<u16>,
        error: HttpContractTransportError,
    },
    Cancelled,
}

impl HttpAttemptSettlement {
    fn failed(status: Option<u16>, error: HttpContractTransportError) -> Self {
        Self::Failed { status, error }
    }

    fn record(&self, span: &tracing::Span) {
        match self {
            Self::Complete { status, .. } => {
                span.record("http.response.status_code", *status);
                span.record("outcome", "ok");
                if *status >= 400 {
                    span.record("otel.status_code", "error");
                    span.record("error.type", tracing::field::display(status));
                }
            }
            Self::Failed { status, error } => {
                if let Some(status) = status {
                    span.record("http.response.status_code", *status);
                }
                span.record("outcome", "error");
                span.record("error.type", error.kind().as_label());
                span.record("otel.status_code", "error");
            }
            Self::Cancelled => {
                span.record("outcome", "error");
                span.record("error.type", "dispatch");
                span.record("otel.status_code", "error");
            }
        }
    }

    fn into_result(self) -> Result<HttpContractResponse, HttpContractTransportError> {
        match self {
            Self::Complete { status, body } => HttpContractResponse::try_new(status, body),
            Self::Failed { error, .. } => Err(error),
            Self::Cancelled => Err(HttpContractTransportError::new(
                HttpContractTransportErrorKind::Dispatch,
            )),
        }
    }
}

fn seal_client_builder(
    builder: reqwest::ClientBuilder,
    request_timeout: Duration,
) -> reqwest::ClientBuilder {
    builder
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(request_timeout)
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
}

fn classify_send_error(error: &reqwest::Error) -> HttpContractTransportErrorKind {
    if error.is_timeout() {
        return HttpContractTransportErrorKind::Timeout;
    }
    if error.is_connect() || error.is_builder() || error.is_body() {
        return HttpContractTransportErrorKind::Dispatch;
    }
    HttpContractTransportErrorKind::InvalidResponse
}

fn request_url(
    endpoint: &reqwest::Url,
    path: &str,
    query: Option<&str>,
) -> Result<reqwest::Url, HttpContractTransportError> {
    let url = endpoint.clone();
    let base = endpoint.path().trim_end_matches('/');
    let suffix = path.trim_start_matches('/');
    let joined = if suffix.is_empty() {
        if base.is_empty() { "/" } else { base }
    } else if base.is_empty() {
        let mut url = set_url_path(url, &format!("/{suffix}"));
        url.set_query(query);
        return Ok(url);
    } else {
        let mut url = set_url_path(url, &format!("{base}/{suffix}"));
        url.set_query(query);
        return Ok(url);
    };
    let mut url = set_url_path(url, joined);
    url.set_query(query);
    Ok(url)
}

fn set_url_path(mut url: reqwest::Url, path: &str) -> reqwest::Url {
    url.set_path(path);
    url.set_query(None);
    url.set_fragment(None);
    url
}

fn reqwest_method(method: HttpContractMethod) -> reqwest::Method {
    match method {
        HttpContractMethod::Get => reqwest::Method::GET,
        HttpContractMethod::Post => reqwest::Method::POST,
        HttpContractMethod::Put => reqwest::Method::PUT,
        HttpContractMethod::Patch => reqwest::Method::PATCH,
        HttpContractMethod::Delete => reqwest::Method::DELETE,
    }
}

async fn bounded_response_body(
    mut response: reqwest::Response,
) -> Result<Vec<u8>, HttpContractTransportError> {
    if response
        .content_length()
        .is_some_and(|length| length > HttpContractResponse::MAX_BODY_BYTES as u64)
    {
        return Err(HttpContractTransportError::new(
            HttpContractTransportErrorKind::ResponseTooLarge,
        ));
    }

    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| {
        let kind = if error.is_timeout() {
            HttpContractTransportErrorKind::Timeout
        } else {
            HttpContractTransportErrorKind::InvalidResponse
        };
        HttpContractTransportError::with_source(kind, &error)
    })? {
        let next_len = body.len().checked_add(chunk.len()).ok_or_else(|| {
            HttpContractTransportError::new(HttpContractTransportErrorKind::ResponseTooLarge)
        })?;
        if next_len > HttpContractResponse::MAX_BODY_BYTES {
            return Err(HttpContractTransportError::new(
                HttpContractTransportErrorKind::ResponseTooLarge,
            ));
        }
        body.try_reserve_exact(chunk.len()).map_err(|error| {
            HttpContractTransportError::with_source(
                HttpContractTransportErrorKind::InvalidResponse,
                &error,
            )
        })?;
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}
