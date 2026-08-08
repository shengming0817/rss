//! httpd adapter —— HTTP 传输 adapter（#1320 运行时入口 Join）。
//!
//! 单一 `HttpServer`：bind `TcpListener` → `axum::serve` 已认证 router 的
//! `httpserve::ServerMakeService` →
//! serve task 监听注入的 [`CancellationToken`] 优雅关停；`impl diport::ManagedResource` 经
//! `cancel()` + await JoinHandle 收敛。**精确对标 `adapters/grpc` 的 `GrpcServer`**（transport=adapter）。
//!
//! ConnectInfo 贯通（#1106）：`into_make_service_with_connect_info::<SocketAddr>()` 在 bind 时注入
//! `ConnectInfo<SocketAddr>` extension，供 `httpserve::rate_limit` 中间件读 peer IP 做 per-IP keyed 限流。
//! `ServerMakeService` 同时证明 router 已在唯一 funnel 装入非零全请求预算；plaintext / mTLS 入口均只接受
//! 该 capability，不存在 transport-specific 或无预算 serve 分支（SERVER-REQUEST-BUDGET-01）。
//!
//! # 为何是 adapter（而非 httpserve 服务 crate）
//!
//! `impl diport::ManagedResource` 仅 `adapters/`·`bins/`·`assemblies/` package 可做
//! （`rss_diport_impl_allowlist` dylint，INVARIANT DIPORT-IMPL-ALLOWLIST-01）——`crates/httpserve`
//! 是 Service 层、impl DI port 会被守卫拒。HTTP serve 是 transport 关注点，本就归 adapter。
//!
//! # graceful shutdown：经 ShutdownStack token funnel
//!
//! 后台 serve task 的关闭信号是组合根经 `bootstrap::ShutdownStack::register_with_token` 注入的 child
//! [`CancellationToken`]（SHUTDOWN-TOKEN-FUNNEL-01）：阶段 1 广播 `cancel()` 即 `axum::serve` 的
//! `with_graceful_shutdown` 触发 drain，阶段 2 `shutdown()` await task 收敛。`serve(addr, svc)` 是
//! detached 便捷构造（内部 token，不接外部广播；测试 / 简单 caller 用）。**不**自建 oneshot 绕过 funnel。
//!
//! # 安全：plaintext 或 listener 级 SPIFFE/mTLS
//!
//! `serve` 保持 plaintext 路径；`serve_mtls` 使用 SPIRE Workload API `X509Source` + rustls listener
//! 级 mTLS，并把已验证 SPIFFE peer 作为 `authn::VerifiedMtlsPeer` 注入 request extension。`bind`
//! 的地址由组合根经 env 解析注入（`RSS_<LISTENER>_LISTEN_ADDR`），缺配在组合根 fail-fast。
//!
//! crate 保持 `forbid(unsafe_code)`（继承 workspace lints）。
//! ref: tokio-rs/axum axum/src/serve/mod.rs@v0.8.9（`axum::serve(TcpListener, make_service).with_graceful_shutdown`）
//! ref: 内部对标 adapters/grpc/src/lib.rs（`GrpcServer` = ManagedResource + CancellationToken funnel）

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::serve::{IncomingStream, Listener, ListenerExt};
use diport::{DynManagedResource, ManagedResource, ShutdownError};
use distributed::{
    HttpContractMethod, HttpContractRequest, HttpContractResponse, HttpContractTransport,
    HttpContractTransportError, HttpContractTransportErrorKind,
};
use reqwest::header::{HeaderName, HeaderValue};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_rustls::server::TlsStream;
use tokio_util::sync::CancellationToken;
use tower::Service;

const DEFAULT_DOMAIN_HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_DOMAIN_HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// HTTP 传输 adapter：持有 bind 成功的 listener 地址、graceful-shutdown 的 [`CancellationToken`]
/// 与 serve 任务句柄。每 listener（Primary / Health / …）一个实例，经组合根 `ShutdownStack` 托管。
#[derive(Debug)]
pub struct HttpServer {
    /// ManagedResource 关闭日志的稳定名（如 `http-primary` / `http-health`，组合根注入区分多 listener）。
    name: &'static str,
    local_addr: SocketAddr,
    /// 驱动 serve task 退出的 token：组合根经 funnel 注入（或 [`HttpServer::serve`] 的内部 detached token）。
    /// `shutdown()` `cancel()` 它触发 graceful 退出（幂等：阶段 1 广播已 cancel 则 no-op）。
    token: CancellationToken,
    handle: Mutex<Option<JoinHandle<std::io::Result<()>>>>,
}

/// HTTP server 启动失败（构造期 fail-fast，不静默 noop）。
///
/// message 为 `&'static str` const literal，无 runtime 数据、无 PII（error-handling.md）。
#[derive(Debug, thiserror::Error)]
pub enum HttpServeError {
    /// TCP bind 失败（端口占用 / 权限不足 / 非法地址）。
    #[error("http server bind failed")]
    Bind(#[source] std::io::Error),
    /// listener local_addr 读回失败（bind 后内核返回 EBADF / 类似）。
    #[error("http server local addr unavailable")]
    LocalAddr(#[source] std::io::Error),
    /// SPIFFE Workload API X.509 source could not be initialized.
    #[error("http mtls spiffe source unavailable")]
    SpiffeSource(#[source] spiffe::X509SourceError),
    /// rustls server configuration could not be built from SPIFFE material.
    #[error("http mtls rustls config invalid")]
    Rustls(#[source] spiffe_rustls::Error),
}

/// One remote domain HTTP endpoint plus its SPIFFE/mTLS authorization policy.
#[derive(Clone, Debug)]
pub struct DomainHttpTargetConfig {
    domain: String,
    endpoint: reqwest::Url,
    policy: authn::OutboundMtlsPolicy,
}

impl DomainHttpTargetConfig {
    /// Build one target config. Endpoint must be an HTTPS base URL without inline credentials.
    pub fn new(
        domain: impl AsRef<str>,
        endpoint: impl AsRef<str>,
        policy: authn::OutboundMtlsPolicy,
    ) -> Result<Self, DomainHttpTransportBuildError> {
        let domain = canonical_domain_key(domain.as_ref())?;
        let endpoint = parse_target_endpoint(endpoint.as_ref())?;
        Ok(Self {
            domain,
            endpoint,
            policy,
        })
    }
}

#[derive(Clone)]
struct DomainHttpTarget {
    endpoint: reqwest::Url,
    client: reqwest::Client,
}

/// Outbound synchronous cross-domain HTTP transport backed by SPIFFE/mTLS.
///
/// The transport accepts only [`distributed::HttpContractHeaders`] from callers, which are already a
/// diagnostic-header allowlist. It never accepts caller-provided credential or tenant headers.
pub struct DomainHttpTransport {
    targets: BTreeMap<String, DomainHttpTarget>,
    mtls_source: Option<spiffe::X509Source>,
}

/// Current readiness state for outbound domain HTTP transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainHttpOwnedReadiness {
    Ready,
    MtlsSourceUnavailable,
}

impl DomainHttpOwnedReadiness {
    /// True only when this process owns usable outbound mTLS material.
    pub fn is_ready(self) -> bool {
        matches!(self, Self::Ready)
    }

    /// Stable readyz detail. Must stay static and avoid embedding endpoint values.
    pub fn detail(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::MtlsSourceUnavailable => "mtls-source-unavailable",
        }
    }
}

impl DomainHttpTransport {
    /// Build all remote domain targets from one SPIRE X.509 source. `endpoint=None` uses
    /// `SPIFFE_ENDPOINT_SOCKET`.
    pub async fn from_spire(
        targets: Vec<DomainHttpTargetConfig>,
        endpoint: Option<&str>,
    ) -> Result<Self, DomainHttpTransportBuildError> {
        Self::from_spire_with_initial_sync_timeout(targets, endpoint, Duration::from_secs(5)).await
    }

    async fn from_spire_with_initial_sync_timeout(
        targets: Vec<DomainHttpTargetConfig>,
        endpoint: Option<&str>,
        initial_sync_timeout: Duration,
    ) -> Result<Self, DomainHttpTransportBuildError> {
        if targets.is_empty() {
            return Err(DomainHttpTransportBuildError::EmptyTargets);
        }
        let source = x509_source(endpoint, initial_sync_timeout).await?;
        let (mapped, source) = build_domain_http_targets(
            source,
            targets,
            mtls_reqwest_client,
            shutdown_uncommitted_x509_source,
        )
        .await?;
        Ok(Self {
            targets: mapped,
            mtls_source: Some(source),
        })
    }

    #[cfg(test)]
    fn from_targets(
        targets: BTreeMap<String, DomainHttpTarget>,
    ) -> Result<Self, DomainHttpTransportBuildError> {
        if targets.is_empty() {
            return Err(DomainHttpTransportBuildError::EmptyTargets);
        }
        Ok(Self {
            targets,
            mtls_source: None,
        })
    }

    /// Readiness snapshot for transport state owned by this process.
    ///
    /// Production transports hold an `X509Source`; test-only transports do not. Runtime registers
    /// this as `domain_transport_ready`.
    pub fn owned_readiness(&self) -> DomainHttpOwnedReadiness {
        owned_readiness_from_source_health(
            self.mtls_source
                .as_ref()
                .is_none_or(spiffe::X509Source::is_healthy),
        )
    }

    /// Boolean view of [`DomainHttpTransport::owned_readiness`].
    pub fn is_ready(&self) -> bool {
        self.owned_readiness().is_ready()
    }
}

/// Shared outbound domain HTTP transport handle.
///
/// Runtime needs the same concrete transport as both a callable [`HttpContractTransport`] dependency and
/// a shutdown [`ManagedResource`]. This wrapper keeps those two views pointed at one `Arc`, so the
/// dispatch seam and the `X509Source` lifecycle cannot drift.
#[derive(Clone)]
pub struct SharedDomainHttpTransport {
    inner: Arc<DomainHttpTransport>,
}

impl SharedDomainHttpTransport {
    /// Wrap a constructed domain HTTP transport in a shared handle.
    pub fn new(inner: DomainHttpTransport) -> Self {
        Self {
            inner: Arc::new(inner),
        }
    }

    /// Readiness snapshot of the underlying transport.
    pub fn owned_readiness(&self) -> DomainHttpOwnedReadiness {
        self.inner.owned_readiness()
    }

    /// Boolean view of [`SharedDomainHttpTransport::owned_readiness`].
    pub fn is_ready(&self) -> bool {
        self.owned_readiness().is_ready()
    }
}

impl HttpContractTransport for DomainHttpTransport {
    fn dispatch(
        &self,
        request: HttpContractRequest,
    ) -> std::pin::Pin<
        Box<
            dyn Future<Output = Result<HttpContractResponse, HttpContractTransportError>>
                + Send
                + '_,
        >,
    > {
        Box::pin(async move {
            let domain = request.contract().domain().to_uppercase();
            let target = self.targets.get(&domain).ok_or_else(|| {
                HttpContractTransportError::new(HttpContractTransportErrorKind::Dispatch)
            })?;
            let url = request_url(&target.endpoint, request.path(), request.query())?;
            let method = reqwest_method(request.method());
            let mut builder = target.client.request(method, url);
            for (name, value) in request.headers().as_slice() {
                let header_name = HeaderName::from_bytes(name.trim().as_bytes()).map_err(|e| {
                    HttpContractTransportError::with_source(
                        HttpContractTransportErrorKind::Dispatch,
                        &e,
                    )
                })?;
                let header_value = HeaderValue::from_str(value).map_err(|e| {
                    HttpContractTransportError::with_source(
                        HttpContractTransportErrorKind::Dispatch,
                        &e,
                    )
                })?;
                builder = builder.header(header_name, header_value);
            }
            let response = builder
                .body(request.body().to_vec())
                .send()
                .await
                .map_err(|e| {
                    if e.is_timeout() {
                        HttpContractTransportError::with_source(
                            HttpContractTransportErrorKind::Timeout,
                            &e,
                        )
                    } else {
                        HttpContractTransportError::with_source(
                            HttpContractTransportErrorKind::Dispatch,
                            &e,
                        )
                    }
                })?;
            let status = response.status().as_u16();
            let body = bounded_response_body(response).await?;
            HttpContractResponse::try_new(status, body)
        })
    }
}

impl HttpContractTransport for SharedDomainHttpTransport {
    fn dispatch(
        &self,
        request: HttpContractRequest,
    ) -> std::pin::Pin<
        Box<
            dyn Future<Output = Result<HttpContractResponse, HttpContractTransportError>>
                + Send
                + '_,
        >,
    > {
        self.inner.dispatch(request)
    }
}

impl ManagedResource for DomainHttpTransport {
    fn name(&self) -> &str {
        "domain-http-transport"
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        if let Some(source) = &self.mtls_source {
            source
                .shutdown_configured()
                .await
                .map_err(ShutdownError::new)?;
        }
        Ok(())
    }
}

impl ManagedResource for SharedDomainHttpTransport {
    fn name(&self) -> &str {
        ManagedResource::name(self.inner.as_ref())
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        ManagedResource::shutdown(self.inner.as_ref()).await
    }
}

/// Outbound domain HTTP transport construction failure (startup fail-fast).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DomainHttpTransportBuildError {
    /// No remote targets were configured.
    #[error("domain http transport requires at least one target")]
    EmptyTargets,
    /// Domain key was empty or non-canonical.
    #[error("domain http transport domain is invalid")]
    InvalidDomain,
    /// Endpoint URL was syntactically invalid.
    #[error("domain http transport endpoint url is invalid")]
    InvalidEndpoint(#[source] url::ParseError),
    /// Endpoint must be HTTPS.
    #[error("domain http transport endpoint must use https")]
    InsecureEndpoint,
    /// Endpoint must not carry inline credentials, query, or fragment material.
    #[error("domain http transport endpoint must not include credentials, query, or fragment")]
    EndpointContainsCredentials,
    /// SPIFFE Workload API X.509 source could not be initialized or read.
    #[error("domain http transport spiffe source unavailable")]
    SpiffeSource(#[source] spiffe::X509SourceError),
    /// Current workload SVID does not match the configured local SPIFFE ID.
    #[error("domain http transport local spiffe id does not match current svid")]
    LocalSvidMismatch,
    /// SPIFFE/rustls client configuration failed.
    #[error("domain http transport rustls config invalid")]
    Rustls(#[source] spiffe_rustls::Error),
    /// Trust-domain conversion failed before rustls config construction.
    #[error("domain http transport trust domain invalid")]
    TrustDomain(#[source] spiffe::SpiffeIdError),
    /// reqwest client could not be built from the preconfigured rustls backend.
    #[error("domain http transport client invalid")]
    Client(#[source] reqwest::Error),
}

fn canonical_domain_key(raw: &str) -> Result<String, DomainHttpTransportBuildError> {
    if raw.is_empty() || raw.trim() != raw || raw.chars().any(char::is_control) {
        return Err(DomainHttpTransportBuildError::InvalidDomain);
    }
    Ok(raw.to_uppercase())
}

fn parse_target_endpoint(raw: &str) -> Result<reqwest::Url, DomainHttpTransportBuildError> {
    let url = reqwest::Url::parse(raw).map_err(DomainHttpTransportBuildError::InvalidEndpoint)?;
    if url.scheme() != "https" {
        return Err(DomainHttpTransportBuildError::InsecureEndpoint);
    }
    if url.host_str().is_none() {
        return Err(DomainHttpTransportBuildError::InvalidDomain);
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(DomainHttpTransportBuildError::EndpointContainsCredentials);
    }
    Ok(url)
}

async fn x509_source(
    endpoint: Option<&str>,
    initial_sync_timeout: Duration,
) -> Result<spiffe::X509Source, DomainHttpTransportBuildError> {
    let mut builder = spiffe::X509Source::builder().initial_sync_timeout(initial_sync_timeout);
    if let Some(endpoint) = endpoint {
        builder = builder.endpoint(endpoint);
    }
    builder
        .build()
        .await
        .map_err(DomainHttpTransportBuildError::SpiffeSource)
}

async fn build_domain_http_targets<Source, BuildClient, Rollback, RollbackFuture, CleanupError>(
    source: Source,
    targets: Vec<DomainHttpTargetConfig>,
    mut build_client: BuildClient,
    rollback: Rollback,
) -> Result<(BTreeMap<String, DomainHttpTarget>, Source), DomainHttpTransportBuildError>
where
    BuildClient: FnMut(
        &Source,
        &authn::OutboundMtlsPolicy,
    ) -> Result<reqwest::Client, DomainHttpTransportBuildError>,
    Rollback: FnOnce(Source) -> RollbackFuture,
    RollbackFuture: Future<Output = Result<(), CleanupError>>,
{
    let mut mapped = BTreeMap::new();
    for target in targets {
        let client = match build_client(&source, &target.policy) {
            Ok(client) => client,
            Err(primary) => {
                if rollback(source).await.is_err() {
                    tracing::error!(
                        cleanup_failed = true,
                        "domain HTTP transport X509 source rollback failed; preserving client build error"
                    );
                }
                return Err(primary);
            }
        };
        mapped.insert(
            target.domain,
            DomainHttpTarget {
                endpoint: target.endpoint,
                client,
            },
        );
    }
    Ok((mapped, source))
}

async fn shutdown_uncommitted_x509_source(
    source: spiffe::X509Source,
) -> Result<(), spiffe::X509SourceError> {
    source.shutdown_configured().await
}

fn mtls_reqwest_client(
    source: &spiffe::X509Source,
    policy: &authn::OutboundMtlsPolicy,
) -> Result<reqwest::Client, DomainHttpTransportBuildError> {
    ensure_local_svid(source, policy.local_identity())?;
    let allowed_server_ids: Vec<String> = policy
        .server_allow_set()
        .iter()
        .map(|id| id.as_str().to_owned())
        .collect();
    let mut allowed_trust_domains = BTreeSet::new();
    for domain in policy.trust_domains().iter() {
        allowed_trust_domains.insert(
            spiffe::TrustDomain::new(domain.as_str())
                .map_err(DomainHttpTransportBuildError::TrustDomain)?,
        );
    }
    let config = spiffe_rustls::mtls_client(source.clone())
        .authorize(
            spiffe_rustls::authorizer::exact(allowed_server_ids)
                .map_err(DomainHttpTransportBuildError::Rustls)?,
        )
        .trust_domain_policy(spiffe_rustls::AllowList(allowed_trust_domains))
        .with_alpn_protocols([b"http/1.1"])
        .build()
        .map_err(DomainHttpTransportBuildError::Rustls)?;
    domain_http_client_builder()
        .https_only(true)
        .use_preconfigured_tls(config)
        .build()
        .map_err(DomainHttpTransportBuildError::Client)
}

fn domain_http_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .connect_timeout(DEFAULT_DOMAIN_HTTP_CONNECT_TIMEOUT)
        .timeout(DEFAULT_DOMAIN_HTTP_REQUEST_TIMEOUT)
}

fn owned_readiness_from_source_health(source_healthy: bool) -> DomainHttpOwnedReadiness {
    if source_healthy {
        DomainHttpOwnedReadiness::Ready
    } else {
        DomainHttpOwnedReadiness::MtlsSourceUnavailable
    }
}

fn ensure_local_svid(
    source: &spiffe::X509Source,
    expected: &authn::SpiffeId,
) -> Result<(), DomainHttpTransportBuildError> {
    let current = source
        .svid()
        .map_err(DomainHttpTransportBuildError::SpiffeSource)?;
    if current.spiffe_id().to_string() != expected.as_str() {
        return Err(DomainHttpTransportBuildError::LocalSvidMismatch);
    }
    Ok(())
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
            HttpContractTransportErrorKind::InvalidResponse,
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
            HttpContractTransportError::new(HttpContractTransportErrorKind::InvalidResponse)
        })?;
        if next_len > HttpContractResponse::MAX_BODY_BYTES {
            return Err(HttpContractTransportError::new(
                HttpContractTransportErrorKind::InvalidResponse,
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

/// mTLS acceptor backed by SPIRE Workload API X.509-SVID rotation.
#[derive(Clone)]
pub struct MtlsServerConfig {
    source: Option<spiffe::X509Source>,
    acceptor: spiffe_rustls_tokio::TlsAcceptor,
    allow_set: authn::MtlsAllowSet,
}

/// Prepared mTLS configuration plus the background SPIFFE source lifecycle it started.
///
/// The lifecycle must be staged in the launch transaction before the caller reaches another await.
#[must_use = "mTLS preparation owns a live SPIFFE source and must be staged"]
pub struct MtlsServerPreparation {
    config: MtlsServerConfig,
    lifecycle: Box<DynManagedResource<'static>>,
}

impl MtlsServerPreparation {
    /// Stage the background lifecycle synchronously before releasing the serving configuration.
    pub fn stage_with(
        self,
        stage: impl FnOnce(Box<DynManagedResource<'static>>),
    ) -> MtlsServerConfig {
        stage(self.lifecycle);
        self.config
    }
}

struct MtlsSpiffeSource {
    source: spiffe::X509Source,
}

impl ManagedResource for MtlsSpiffeSource {
    fn name(&self) -> &str {
        "http-mtls-spiffe-source"
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.source
            .shutdown_configured()
            .await
            .map_err(ShutdownError::new)
    }
}

/// Failure to construct hermetic TLS material for an assembly test.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, thiserror::Error)]
pub enum MtlsTestConfigError {
    #[error("hermetic mTLS certificate construction failed")]
    Certificate(#[from] rcgen::Error),
    #[error("hermetic mTLS rustls configuration failed")]
    Rustls(#[from] rustls::Error),
}

impl MtlsServerConfig {
    /// Build from SPIRE Agent Workload API. `endpoint=None` uses `SPIFFE_ENDPOINT_SOCKET`.
    pub async fn from_spire(
        allow_set: authn::MtlsAllowSet,
        endpoint: Option<&str>,
    ) -> Result<MtlsServerPreparation, HttpServeError> {
        Self::from_spire_with_initial_sync_timeout(allow_set, endpoint, Duration::from_secs(5))
            .await
    }

    async fn from_spire_with_initial_sync_timeout(
        allow_set: authn::MtlsAllowSet,
        endpoint: Option<&str>,
        initial_sync_timeout: Duration,
    ) -> Result<MtlsServerPreparation, HttpServeError> {
        let source = match endpoint {
            Some(endpoint) => {
                spiffe::X509Source::builder()
                    .endpoint(endpoint)
                    .initial_sync_timeout(initial_sync_timeout)
                    .build()
                    .await
            }
            None => {
                spiffe::X509Source::builder()
                    .initial_sync_timeout(initial_sync_timeout)
                    .build()
                    .await
            }
        }
        .map_err(HttpServeError::SpiffeSource)?;
        let allowed: Vec<String> = allow_set.iter().map(|id| id.as_str().to_owned()).collect();
        let server_config = spiffe_rustls::mtls_server(source.clone())
            .authorize(spiffe_rustls::authorizer::exact(allowed).map_err(HttpServeError::Rustls)?)
            .with_alpn_protocols([b"http/1.1"])
            .build()
            .map_err(HttpServeError::Rustls)?;
        let config = Self {
            source: Some(source),
            acceptor: spiffe_rustls_tokio::TlsAcceptor::new(std::sync::Arc::new(server_config)),
            allow_set,
        };
        let lifecycle = DynManagedResource::new_box(MtlsSpiffeSource {
            source: config
                .source
                .as_ref()
                .unwrap_or_else(|| unreachable!("SPIFFE config always retains its source"))
                .clone(),
        });
        Ok(MtlsServerPreparation { config, lifecycle })
    }

    /// Runtime readiness signal for readyz wiring.
    pub fn is_healthy(&self) -> bool {
        self.source
            .as_ref()
            .is_some_and(spiffe::X509Source::is_healthy)
    }

    /// Construct hermetic server TLS material for downstream assembly tests.
    ///
    /// This entry point and `rcgen` are absent from the default production artifact. It exists only
    /// to exercise the real `serve_mtls` resource-registration and drain path without a live SPIRE
    /// Agent; no request is accepted by this no-client-auth test certificate configuration.
    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test(allow_set: authn::MtlsAllowSet) -> Result<Self, MtlsTestConfigError> {
        let key = rcgen::KeyPair::generate()?;
        let cert =
            rcgen::CertificateParams::new(vec!["localhost".to_owned()])?.self_signed(&key)?;
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()),
        );
        let mut server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], key)?;
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            source: None,
            acceptor: spiffe_rustls_tokio::TlsAcceptor::new(Arc::new(server_config)),
            allow_set,
        })
    }

    #[cfg(test)]
    fn from_test_acceptor(
        acceptor: spiffe_rustls_tokio::TlsAcceptor,
        allow_set: authn::MtlsAllowSet,
    ) -> Self {
        Self {
            source: None,
            acceptor,
            allow_set,
        }
    }
}

struct VerifiedTlsStream {
    inner: TlsStream<tokio::net::TcpStream>,
    peer: authn::VerifiedMtlsPeer,
}

impl VerifiedTlsStream {
    fn peer(&self) -> &authn::VerifiedMtlsPeer {
        &self.peer
    }
}

impl AsyncRead for VerifiedTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for VerifiedTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct MtlsListener {
    listener: TcpListener,
    local_addr: SocketAddr,
    config: MtlsServerConfig,
}

impl axum::serve::Listener for MtlsListener {
    type Io = VerifiedTlsStream;
    type Addr = SocketAddr;

    // reason: one accept loop must keep TCP accept, TLS handshake, peer SPIFFE extraction, and
    // allow-set minting in order; splitting would scatter the fail-closed log/continue decisions.
    #[allow(clippy::cognitive_complexity)]
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (stream, addr) = match self.listener.accept().await {
                Ok(parts) => parts,
                Err(e) => {
                    tracing::error!(err = %e, "http mtls tcp accept failed");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };
            let (tls, identity) = match self.config.acceptor.accept(stream).await {
                Ok(parts) => parts,
                Err(e) => {
                    tracing::warn!(err = %e, addr = %addr, "http mtls handshake failed");
                    continue;
                }
            };
            let Some(peer_id) = identity.spiffe_id() else {
                tracing::warn!(addr = %addr, "http mtls handshake produced no peer spiffe id");
                continue;
            };
            let peer_id = match authn::SpiffeId::parse(&peer_id.to_string()) {
                Ok(peer_id) => peer_id,
                Err(e) => {
                    tracing::warn!(err = ?e, addr = %addr, "http mtls peer spiffe id rejected");
                    continue;
                }
            };
            let peer = match authn::verify_mtls_peer(peer_id, &self.config.allow_set) {
                Ok(peer) => peer,
                Err(e) => {
                    tracing::warn!(err = ?e, addr = %addr, "http mtls peer not allowed");
                    continue;
                }
            };
            return (VerifiedTlsStream { inner: tls, peer }, addr);
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.local_addr)
    }
}

struct MtlsMakeService<M> {
    inner: M,
}

impl<M> MtlsMakeService<M> {
    fn new(inner: M) -> Self {
        Self { inner }
    }
}

impl<M> Clone for MtlsMakeService<M>
where
    M: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<'a, L, M, S> Service<IncomingStream<'a, L>> for MtlsMakeService<M>
where
    L: Listener<Io = VerifiedTlsStream, Addr = SocketAddr>,
    M: Service<IncomingStream<'a, L>, Error = Infallible, Response = S> + Send,
    M::Future: Send + Unpin,
    S: Send + 'a,
{
    type Response = MtlsPeerService<S>;
    type Error = Infallible;
    type Future = MtlsMakeServiceFuture<M::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, target: IncomingStream<'a, L>) -> Self::Future {
        let peer = target.io().peer().clone();
        let fut = self.inner.call(target);
        MtlsMakeServiceFuture { inner: fut, peer }
    }
}

struct MtlsMakeServiceFuture<F> {
    inner: F,
    peer: authn::VerifiedMtlsPeer,
}

impl<F, S> Future for MtlsMakeServiceFuture<F>
where
    F: Future<Output = Result<S, Infallible>> + Unpin,
{
    type Output = Result<MtlsPeerService<S>, Infallible>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.as_mut().get_mut();
        match Pin::new(&mut this.inner).poll(cx) {
            Poll::Ready(Ok(inner)) => Poll::Ready(Ok(MtlsPeerService {
                inner,
                peer: this.peer.clone(),
            })),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[derive(Clone)]
struct MtlsPeerService<S> {
    inner: S,
    peer: authn::VerifiedMtlsPeer,
}

impl<S> Service<axum::extract::Request> for MtlsPeerService<S>
where
    S: Service<axum::extract::Request> + Send,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: axum::extract::Request) -> Self::Future {
        req.extensions_mut().insert(self.peer.clone());
        self.inner.call(req)
    }
}

/// 已 bind、未 serve 的 HTTP listener（`async bind` 与 `sync serve-spawn` 拆分的中间态）。
///
/// 拆分动机：`bootstrap::ShutdownStack::register_with_token` 的 `make` 闭包是**同步**
/// `FnOnce(CancellationToken) -> Box<DynManagedResource>`，而 bind 是 `async`。故先 [`HttpServer::bind`]
/// 异步 bind（fail-fast，在注册前暴露端口冲突），再在 funnel 闭包内同步 [`BoundHttpServer::serve`]
/// spawn serve task（消费 funnel 注入的 child token，SHUTDOWN-TOKEN-FUNNEL-01）——既 fail-fast 又走 funnel。
#[derive(Debug)]
#[must_use = "BoundHttpServer 须 serve(svc, token) 才真正起服务（否则只 bind 不 serve）"]
pub struct BoundHttpServer {
    name: &'static str,
    listener: TcpListener,
    local_addr: SocketAddr,
}

impl BoundHttpServer {
    /// 返回已绑定地址（含内核分配的 ephemeral 端口）。
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// 同步 spawn serve task（消费已 bind 的 listener + 注入的 `token`），产出托管 [`HttpServer`]。
    ///
    /// **同步**：契合 `ShutdownStack::register_with_token` 的同步 `make` 闭包——funnel 注入 child token，
    /// 本 fn 即时 `tokio::spawn`。serve task 经 `with_graceful_shutdown` 监听 `token`：阶段 1 广播 `cancel()`
    /// 即 drain。
    ///
    /// # Panics
    ///
    /// 须在 **tokio runtime 上下文**调用——内部 `tokio::spawn` 在无 runtime 时 panic。从 async fn
    /// （如 `serve_until_signal`）或 `ShutdownStack::register_with_token` 闭包内调用即满足（组合根均在
    /// `#[tokio::main]` 运行时内）。
    pub fn serve(self, svc: httpserve::ServerMakeService, token: CancellationToken) -> HttpServer {
        let serve_token = token.clone();
        let listener = self.listener;
        let handle = tokio::spawn(async move {
            let svc = svc.into_axum();
            axum::serve(listener, svc)
                .with_graceful_shutdown(async move {
                    // 关闭信号 = 注入 token 的 cancel（阶段 1 广播 / 内部 detached cancel）。
                    serve_token.cancelled().await;
                })
                .await
        });

        tracing::info!(name = self.name, addr = %self.local_addr, "http server started");

        HttpServer {
            name: self.name,
            local_addr: self.local_addr,
            token,
            handle: Mutex::new(Some(handle)),
        }
    }

    /// Spawn an mTLS HTTP serve task. Each accepted request receives both
    /// `ConnectInfo<SocketAddr>` and `authn::VerifiedMtlsPeer` extensions.
    pub fn serve_mtls(
        self,
        svc: httpserve::ServerMakeService,
        mtls: MtlsServerConfig,
        token: CancellationToken,
    ) -> HttpServer {
        let serve_token = token.clone();
        let listener = MtlsListener {
            listener: self.listener,
            local_addr: self.local_addr,
            config: mtls,
        };
        let handle = tokio::spawn(async move {
            let svc = svc.into_axum();
            axum::serve(listener.tap_io(|_io| {}), MtlsMakeService::new(svc))
                .with_graceful_shutdown(async move {
                    serve_token.cancelled().await;
                })
                .await
        });

        tracing::info!(name = self.name, addr = %self.local_addr, "http mtls server started");

        HttpServer {
            name: self.name,
            local_addr: self.local_addr,
            token,
            handle: Mutex::new(Some(handle)),
        }
    }
}

impl HttpServer {
    /// 异步 bind `TcpListener`（**fail-fast**：端口占用 / 权限不足 / 非法地址即 `Err`，不延迟到首请求）。
    ///
    /// 产出 [`BoundHttpServer`]——再经同步 [`BoundHttpServer::serve`] 在 `ShutdownStack::register_with_token`
    /// funnel 闭包内 spawn serve task。传 `127.0.0.1:0` 让内核分配 ephemeral 端口，经
    /// [`BoundHttpServer::local_addr`] 读回（测试用）。`name` 是关闭日志的稳定标识（如 `http-primary`）。
    pub async fn bind(
        name: &'static str,
        addr: SocketAddr,
    ) -> Result<BoundHttpServer, HttpServeError> {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(HttpServeError::Bind)?;
        let local_addr = listener.local_addr().map_err(HttpServeError::LocalAddr)?;
        Ok(BoundHttpServer {
            name,
            listener,
            local_addr,
        })
    }

    /// 便捷构造：bind + serve 一步（监听注入的 `token`）。生产组合根用拆分的 [`HttpServer::bind`] +
    /// [`BoundHttpServer::serve`] 走 funnel；本 fn 供测试 / 简单 caller。
    pub async fn serve_with_token(
        name: &'static str,
        addr: SocketAddr,
        svc: httpserve::ServerMakeService,
        token: CancellationToken,
    ) -> Result<Self, HttpServeError> {
        Ok(Self::bind(name, addr).await?.serve(svc, token))
    }

    /// Convenience constructor for mTLS listener.
    pub async fn serve_mtls_with_token(
        name: &'static str,
        addr: SocketAddr,
        svc: httpserve::ServerMakeService,
        mtls: MtlsServerConfig,
        token: CancellationToken,
    ) -> Result<Self, HttpServeError> {
        Ok(Self::bind(name, addr).await?.serve_mtls(svc, mtls, token))
    }

    /// detached 便捷构造（内部 token，不接外部 ShutdownStack 广播）：测试 / 简单 caller 用。
    /// `shutdown()` 经内部 token 触发退出。
    pub async fn serve(
        name: &'static str,
        addr: SocketAddr,
        svc: httpserve::ServerMakeService,
    ) -> Result<Self, HttpServeError> {
        Self::serve_with_token(name, addr, svc, CancellationToken::new()).await
    }

    /// 返回 server 实际绑定的地址（含内核分配的 ephemeral 端口）。
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl ManagedResource for HttpServer {
    fn name(&self) -> &str {
        self.name
    }

    // reason: 3-arm JoinHandle 结果 match 各臂一条 tracing 宏；宏展开在 cognitive_complexity 计数贡献
    // 额外节点（同 grpc adapter / bootstrap shutdown），实际控制流简单——item-level carve-out（error-handling.md §Carve-out）。
    #[allow(clippy::cognitive_complexity)]
    async fn shutdown(&self) -> Result<(), ShutdownError> {
        // 触发 graceful 退出：cancel token（幂等——若 ShutdownStack 阶段 1 已 cancel 则 no-op）。
        self.token.cancel();
        // await serve task 收敛，映射 JoinHandle / io 错误到 ShutdownError。
        if let Some(handle) = self.handle.lock().await.take() {
            match handle.await {
                Ok(Ok(())) => {
                    tracing::info!(name = self.name, "http server shutdown complete");
                }
                Ok(Err(e)) => {
                    tracing::warn!(name = self.name, err = %e, "http server io error on shutdown");
                    return Err(ShutdownError::new(e));
                }
                Err(e) => {
                    tracing::error!(name = self.name, err = %e, "http server task join error on shutdown");
                    return Err(ShutdownError::new(e));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroU64;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use axum::Router;
    use axum::body::Bytes;
    use axum::http::{HeaderMap, HeaderValue, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::get;
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName,
        ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType,
    };
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use rustls::{ClientConfig, RootCertStore, ServerConfig};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::TlsConnector;

    /// 极简 router → budget-sealed make service，挂一个 GET /healthz 恒 200。
    fn make_svc() -> httpserve::ServerMakeService {
        httpserve::ServerMakeService::from_router_for_test(
            Router::new().route("/healthz", get(|| async { "ok" })),
            httpserve::ServerRequestBudget::for_test(),
        )
    }

    fn make_mtls_svc() -> httpserve::ServerMakeService {
        httpserve::ServerMakeService::from_router_for_test(
            Router::new().route(
                "/mtls-peer",
                get(
                    |axum::extract::Extension(peer): axum::extract::Extension<
                        authn::VerifiedMtlsPeer,
                    >| async move { peer.spiffe_id().as_str().to_owned() },
                ),
            ),
            httpserve::ServerRequestBudget::for_test(),
        )
    }

    fn make_domain_transport_svc() -> httpserve::ServerMakeService {
        httpserve::ServerMakeService::from_router_for_test(
            Router::new()
                .route("/rpc/echo", axum::routing::post(domain_transport_echo))
                .route(
                    "/rpc/tenants/{tenant}/entries",
                    get(|uri: axum::http::Uri| async move {
                        uri.path_and_query()
                            .map(ToString::to_string)
                            .unwrap_or_default()
                    }),
                ),
            httpserve::ServerRequestBudget::for_test(),
        )
    }

    struct HandlerDropSignal(Arc<AtomicBool>);

    impl Drop for HandlerDropSignal {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    #[allow(clippy::expect_used)]
    fn make_pending_svc(dropped: Arc<AtomicBool>) -> httpserve::ServerMakeService {
        let router = Router::new().route(
            "/slow",
            get(move || {
                let dropped = Arc::clone(&dropped);
                async move {
                    let _drop_signal = HandlerDropSignal(dropped);
                    std::future::pending::<()>().await;
                    "unreachable"
                }
            }),
        );
        httpserve::ServerMakeService::from_router_for_test(
            router,
            httpserve::ServerRequestBudget::from_millis(
                NonZeroU64::new(20).expect("non-zero test budget"),
            ),
        )
    }

    async fn domain_transport_echo(headers: HeaderMap, body: Bytes) -> axum::response::Response {
        let correlation_id = headers
            .get("x-correlation-id")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let auth_present = headers.contains_key("authorization");
        let tenant_present = headers.contains_key("x-tenant-id");
        let body = format!(
            "{}|correlation={correlation_id}|auth={auth_present}|tenant={tenant_present}",
            String::from_utf8_lossy(&body)
        );
        let mut response = (StatusCode::CREATED, body).into_response();
        response
            .headers_mut()
            .insert("x-domain-transport", HeaderValue::from_static("ok"));
        response
    }

    #[allow(clippy::expect_used)]
    fn outbound_policy() -> authn::OutboundMtlsPolicy {
        let local = authn::SpiffeId::parse("spiffe://example.org/ns/rss/sa/runtime")
            .expect("local spiffe id");
        let servers = authn::MtlsAllowSet::new(["spiffe://example.org/ns/rss/sa/identity"])
            .expect("server allow-set");
        let trust_domains =
            authn::MtlsTrustDomainAllowSet::new(["example.org"]).expect("trust domains");
        authn::OutboundMtlsPolicy::new(local, servers, trust_domains).expect("outbound policy")
    }

    #[allow(clippy::expect_used)]
    fn domain_request(domain: &'static str) -> HttpContractRequest {
        const HASH: &str =
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        const EFFECTS: &[vocab::HttpEffectKind] = &[vocab::HttpEffectKind::Read];
        let route = vocab::HttpRouteEvidence::from_static(
            vocab::HttpContractOwner::domain(domain),
            vocab::ContractBinding::from_static(domain, "identity.login", "v1", HASH),
            "/echo",
            "POST",
            &[],
            vocab::HttpSuccessStatus::new(200),
            vocab::HttpIdempotency::Idempotent,
            vocab::HttpRouteAuth::Public,
            None,
            false,
            vocab::http::HttpResourceSharing::TenantScoped,
            vocab::HttpConsistencyLevel::LocalOnly,
            vocab::HttpEffectProfile::new(EFFECTS),
        );
        HttpContractRequest::new(
            distributed::HttpContractTarget::try_bind(route, &[], &[])
                .expect("concrete contract target"),
            distributed::HttpContractHeaders::try_new(vec![(
                "x-correlation-id".to_owned(),
                "corr-1500".to_owned(),
            )])
            .expect("diagnostic header"),
            b"payload".to_vec(),
        )
    }

    #[allow(clippy::expect_used)]
    fn parameterized_domain_request(domain: &'static str) -> HttpContractRequest {
        const HASH: &str =
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        const EFFECTS: &[vocab::HttpEffectKind] = &[vocab::HttpEffectKind::Read];
        const QUERY: &[vocab::http::HttpQueryParameterSpec] = &[
            vocab::http::HttpQueryParameterSpec::from_static("cursor", false),
            vocab::http::HttpQueryParameterSpec::from_static("limit", true),
        ];
        let route = vocab::HttpRouteEvidence::from_static(
            vocab::HttpContractOwner::domain(domain),
            vocab::ContractBinding::from_static(domain, "audit.list-entries", "v1", HASH),
            "/tenants/{tenantId}/entries",
            "GET",
            QUERY,
            vocab::HttpSuccessStatus::new(200),
            vocab::HttpIdempotency::Idempotent,
            vocab::HttpRouteAuth::Public,
            None,
            false,
            vocab::http::HttpResourceSharing::TenantScoped,
            vocab::HttpConsistencyLevel::LocalOnly,
            vocab::HttpEffectProfile::new(EFFECTS),
        );
        HttpContractRequest::new(
            distributed::HttpContractTarget::try_bind(
                route,
                &[("tenantId", "blue/team")],
                &[("limit", "50"), ("cursor", "next + one")],
            )
            .expect("bound path and query"),
            distributed::HttpContractHeaders::empty(),
            Vec::new(),
        )
    }

    #[allow(clippy::expect_used)]
    fn test_domain_transport(endpoint: reqwest::Url) -> DomainHttpTransport {
        let mut targets = BTreeMap::new();
        targets.insert(
            "IDENTITY".to_owned(),
            DomainHttpTarget {
                endpoint,
                client: reqwest::Client::new(),
            },
        );
        DomainHttpTransport::from_targets(targets).expect("domain transport")
    }

    #[allow(clippy::expect_used)]
    async fn canned_domain_transport(
        response: Vec<u8>,
        keep_open: bool,
    ) -> (DomainHttpTransport, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind canned response server");
        let addr = listener.local_addr().expect("canned server address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept request");
            let mut request = vec![0; 8192];
            let _ = stream.read(&mut request).await.expect("read request");
            stream.write_all(&response).await.expect("write response");
            if keep_open {
                std::future::pending::<()>().await;
            }
        });
        let endpoint =
            reqwest::Url::parse(&format!("http://{addr}/rpc")).expect("canned server endpoint");
        (test_domain_transport(endpoint), server)
    }

    /// 绑 `127.0.0.1:0` ephemeral → 真 socket 上发 HTTP/1.1 GET，读回完整响应（raw，无 reqwest dep）。
    // 测试断言用 expect：item-level carve-out（error-handling.md §Carve-out）。
    #[allow(clippy::expect_used)]
    async fn raw_get_response(addr: SocketAddr, path: &str) -> String {
        let mut stream = TcpStream::connect(addr)
            .await
            .expect("connect bound socket");
        let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        stream
            .write_all(req.as_bytes())
            .await
            .expect("write request");
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.expect("read response");
        String::from_utf8_lossy(&buf).into_owned()
    }

    async fn raw_get_status_line(addr: SocketAddr, path: &str) -> String {
        raw_get_response(addr, path)
            .await
            .lines()
            .next()
            .unwrap_or_default()
            .to_owned()
    }

    struct TestCert {
        cert: CertificateDer<'static>,
        key_der: Vec<u8>,
    }

    #[allow(clippy::expect_used)]
    fn test_ca() -> CertifiedIssuer<'static, KeyPair> {
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        CertifiedIssuer::self_signed(params, KeyPair::generate().expect("ca key"))
            .expect("self-signed ca")
    }

    #[allow(clippy::expect_used)]
    fn leaf_cert(
        issuer: &CertifiedIssuer<'_, KeyPair>,
        dns_name: Option<&str>,
        spiffe_id: &str,
        eku: ExtendedKeyUsagePurpose,
    ) -> TestCert {
        let signing_key = KeyPair::generate().expect("leaf key");
        let mut params = CertificateParams::default();
        params.subject_alt_names = vec![SanType::URI(spiffe_id.try_into().expect("spiffe uri"))];
        if let Some(name) = dns_name {
            params
                .subject_alt_names
                .push(SanType::DnsName(name.try_into().expect("dns name")));
        }
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![eku];

        let cert = params
            .signed_by(&signing_key, issuer)
            .expect("leaf cert signed");
        TestCert {
            cert: cert.der().clone(),
            key_der: signing_key.serialize_der(),
        }
    }

    #[allow(clippy::expect_used)]
    fn root_store(ca: &CertifiedIssuer<'_, KeyPair>) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(ca.der().clone()).expect("add ca root");
        roots
    }

    fn private_key_der(cert: &TestCert) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_der.clone()))
    }

    #[allow(clippy::expect_used)]
    fn test_mtls_config(
        ca: &CertifiedIssuer<'_, KeyPair>,
        allowed_spiffe_id: &str,
    ) -> MtlsServerConfig {
        let server_cert = leaf_cert(
            ca,
            Some("localhost"),
            "spiffe://example.org/ns/rss/sa/server",
            ExtendedKeyUsagePurpose::ServerAuth,
        );
        let client_verifier =
            rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store(ca)))
                .build()
                .expect("client verifier");
        let mut server_config = ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(
                vec![server_cert.cert.clone()],
                private_key_der(&server_cert),
            )
            .expect("server config");
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

        MtlsServerConfig::from_test_acceptor(
            spiffe_rustls_tokio::TlsAcceptor::new(Arc::new(server_config)),
            authn::MtlsAllowSet::new([allowed_spiffe_id]).expect("allow-set"),
        )
    }

    #[allow(clippy::expect_used)]
    fn client_config(
        ca: &CertifiedIssuer<'_, KeyPair>,
        client_cert: Option<TestCert>,
    ) -> ClientConfig {
        let builder = ClientConfig::builder().with_root_certificates(root_store(ca));
        let mut config = match client_cert {
            Some(cert) => builder
                .with_client_auth_cert(vec![cert.cert.clone()], private_key_der(&cert))
                .expect("client config"),
            None => builder.with_no_client_auth(),
        };
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        config
    }

    #[allow(clippy::expect_used)]
    async fn tls_get_response(
        addr: SocketAddr,
        path: &str,
        config: ClientConfig,
    ) -> Result<String, String> {
        let tcp = TcpStream::connect(addr)
            .await
            .map_err(|e| format!("tcp connect: {e}"))?;
        let connector = TlsConnector::from(Arc::new(config));
        let server_name = ServerName::try_from("localhost").expect("server name");
        let mut stream = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| format!("tls connect: {e}"))?;
        let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        stream
            .write_all(req.as_bytes())
            .await
            .map_err(|e| format!("write request: {e}"))?;
        let mut buf = Vec::new();
        stream
            .read_to_end(&mut buf)
            .await
            .map_err(|e| format!("read response: {e}"))?;
        Ok(String::from_utf8_lossy(&buf).into_owned())
    }

    async fn tls_get_response_with_timeout(
        addr: SocketAddr,
        path: &str,
        config: ClientConfig,
    ) -> Result<String, String> {
        tokio::time::timeout(Duration::from_secs(2), tls_get_response(addr, path, config))
            .await
            .map_err(|_| "tls request timed out".to_owned())?
    }

    /// serve_with_token：bind ephemeral → 真请求 200 → cancel token 后 ManagedResource::shutdown 收敛干净。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn serve_with_token_binds_serves_and_shuts_down() {
        let addr: SocketAddr = "127.0.0.1:0".parse().expect("addr");
        let token = CancellationToken::new();
        let server = HttpServer::serve_with_token("http-test", addr, make_svc(), token.clone())
            .await
            .expect("serve binds");
        let bound = server.local_addr();
        assert_ne!(bound.port(), 0, "ephemeral 端口已分配");

        let status = raw_get_status_line(bound, "/healthz").await;
        assert!(
            status.starts_with("HTTP/1.1 200"),
            "真 socket GET 200: {status}"
        );

        // ManagedResource 名透传（组合根注入的 listener 区分名）。
        assert_eq!(ManagedResource::name(&server), "http-test");

        // 优雅关停：cancel + await serve task 收敛（无失败）。
        let failures = server.shutdown().await;
        assert!(failures.is_ok(), "graceful shutdown 干净: {failures:?}");
    }

    /// serve detached 便捷构造（内部 token）：shutdown 经内部 token 触发退出。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn serve_detached_shuts_down_via_internal_token() {
        let addr: SocketAddr = "127.0.0.1:0".parse().expect("addr");
        let server = HttpServer::serve("http-detached", addr, make_svc())
            .await
            .expect("serve binds");
        let bound = server.local_addr();
        let status = raw_get_status_line(bound, "/healthz").await;
        assert!(
            status.starts_with("HTTP/1.1 200"),
            "detached serve 200: {status}"
        );
        assert!(server.shutdown().await.is_ok(), "detached shutdown 收敛");
    }

    /// bind→serve 拆分（funnel 路径）：async bind 读回端口 → sync serve(svc, token) spawn → 真请求 200 →
    /// token.cancel() 触发 drain → shutdown 收敛。模拟组合根 register_with_token 内的同步 serve。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn bind_then_sync_serve_funnel_path() {
        let addr: SocketAddr = "127.0.0.1:0".parse().expect("addr");
        let bound = HttpServer::bind("http-funnel", addr)
            .await
            .expect("bind ok");
        let local = bound.local_addr();
        assert_ne!(local.port(), 0, "bind 即读回 ephemeral 端口（serve 前）");
        // 同步 serve（funnel 闭包内范式）：在 tokio runtime 上下文 spawn。
        let token = CancellationToken::new();
        let server = bound.serve(make_svc(), token.clone());
        let status = raw_get_status_line(local, "/healthz").await;
        assert!(
            status.starts_with("HTTP/1.1 200"),
            "funnel serve 200: {status}"
        );
        // 阶段 1 广播：cancel token → drain；阶段 2：shutdown await task 收敛。
        token.cancel();
        assert!(server.shutdown().await.is_ok(), "funnel shutdown 收敛");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn plaintext_server_uses_sealed_request_budget_and_drops_handler() {
        let dropped = Arc::new(AtomicBool::new(false));
        let bound = HttpServer::bind(
            "http-budget-plaintext",
            "127.0.0.1:0".parse().expect("ephemeral address"),
        )
        .await
        .expect("bind");
        let local = bound.local_addr();
        let server = bound.serve(
            make_pending_svc(Arc::clone(&dropped)),
            CancellationToken::new(),
        );

        let response = raw_get_response(local, "/slow").await;
        assert!(response.starts_with("HTTP/1.1 503"), "{response}");
        assert!(response.contains("ERR_CORE_UNAVAILABLE"), "{response}");
        assert!(
            dropped.load(Ordering::Acquire),
            "plaintext timeout must drop handler future"
        );
        assert!(server.shutdown().await.is_ok());
    }

    #[test]
    fn domain_transport_requires_at_least_one_target() {
        let result = DomainHttpTransport::from_targets(BTreeMap::new());
        assert!(matches!(
            result,
            Err(DomainHttpTransportBuildError::EmptyTargets)
        ));
    }

    #[test]
    fn domain_http_client_defaults_are_bounded() {
        assert!(DEFAULT_DOMAIN_HTTP_CONNECT_TIMEOUT > Duration::ZERO);
        assert!(DEFAULT_DOMAIN_HTTP_REQUEST_TIMEOUT > DEFAULT_DOMAIN_HTTP_CONNECT_TIMEOUT);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn shared_domain_transport_exposes_dispatch_and_lifecycle_views() {
        let addr: SocketAddr = "127.0.0.1:0".parse().expect("addr");
        let server = HttpServer::serve("domain-transport-ready-peer", addr, make_svc())
            .await
            .expect("serve readiness peer");
        let endpoint =
            reqwest::Url::parse(&format!("http://{}/rpc", server.local_addr())).expect("url");
        let shared = SharedDomainHttpTransport::new(test_domain_transport(endpoint));

        assert_eq!(ManagedResource::name(&shared), "domain-http-transport");
        assert!(shared.is_ready());
        ManagedResource::shutdown(&server)
            .await
            .expect("shutdown readiness peer");
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn domain_transport_owned_readiness_ignores_peer_endpoint_reachability() {
        let endpoint = reqwest::Url::parse("http://peer.invalid/rpc").expect("unresolvable URL");
        let shared = SharedDomainHttpTransport::new(test_domain_transport(endpoint));
        let readiness = shared.owned_readiness();

        assert_eq!(
            readiness,
            DomainHttpOwnedReadiness::Ready,
            "peer reachability is not process-owned readiness"
        );
    }

    #[test]
    fn domain_transport_owned_readiness_maps_local_source_health() {
        assert_eq!(
            owned_readiness_from_source_health(true),
            DomainHttpOwnedReadiness::Ready
        );
        assert_eq!(
            owned_readiness_from_source_health(false),
            DomainHttpOwnedReadiness::MtlsSourceUnavailable
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn domain_transport_target_requires_https_endpoint() {
        let err = DomainHttpTargetConfig::new(
            "identity",
            "http://identity.internal/rpc",
            outbound_policy(),
        )
        .expect_err("production endpoint must be HTTPS");
        assert!(matches!(
            err,
            DomainHttpTransportBuildError::InsecureEndpoint
        ));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn domain_transport_dispatches_request_response_and_diagnostic_headers_only() {
        let addr: SocketAddr = "127.0.0.1:0".parse().expect("addr");
        let server = HttpServer::serve("domain-transport-echo", addr, make_domain_transport_svc())
            .await
            .expect("serve echo");
        let endpoint =
            reqwest::Url::parse(&format!("http://{}/rpc", server.local_addr())).expect("url");
        let transport = SharedDomainHttpTransport::new(test_domain_transport(endpoint));

        let response = transport
            .dispatch(domain_request("identity"))
            .await
            .expect("dispatch");
        assert_eq!(response.status_code(), 201);
        assert_eq!(
            response.body(),
            b"payload|correlation=corr-1500|auth=false|tenant=false"
        );

        assert!(server.shutdown().await.is_ok(), "echo shutdown 收敛");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn domain_transport_dispatches_bound_percent_encoded_path_and_query() {
        let addr: SocketAddr = "127.0.0.1:0".parse().expect("addr");
        let server =
            HttpServer::serve("domain-transport-target", addr, make_domain_transport_svc())
                .await
                .expect("serve target echo");
        let endpoint =
            reqwest::Url::parse(&format!("http://{}/rpc", server.local_addr())).expect("url");
        let transport = SharedDomainHttpTransport::new(test_domain_transport(endpoint));

        let response = transport
            .dispatch(parameterized_domain_request("identity"))
            .await
            .expect("dispatch bound target");

        assert_eq!(
            response.body(),
            b"/rpc/tenants/blue%2Fteam/entries?cursor=next+%2B+one&limit=50"
        );
        assert!(server.shutdown().await.is_ok(), "target echo shutdown");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn domain_transport_rejects_known_oversize_without_reading_body() {
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            HttpContractResponse::MAX_BODY_BYTES + 1
        )
        .into_bytes();
        let (transport, server) = canned_domain_transport(response, true).await;

        let error = tokio::time::timeout(
            Duration::from_millis(250),
            transport.dispatch(domain_request("identity")),
        )
        .await
        .expect("content-length rejection must not wait for the body")
        .expect_err("oversize response is invalid");
        assert_eq!(
            error.kind(),
            HttpContractTransportErrorKind::InvalidResponse
        );
        server.abort();
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn domain_transport_enforces_actual_chunked_body_bound() {
        let body = vec![b'a'; HttpContractResponse::MAX_BODY_BYTES + 1];
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(&body);
        response.extend_from_slice(b"\r\n0\r\n\r\n");
        let (transport, server) = canned_domain_transport(response, false).await;

        let error = transport
            .dispatch(domain_request("identity"))
            .await
            .expect_err("actual chunked body above the bound is invalid");
        assert_eq!(
            error.kind(),
            HttpContractTransportErrorKind::InvalidResponse
        );
        server.await.expect("canned server completes");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn domain_transport_accepts_chunked_body_at_exact_bound() {
        let body = vec![b'a'; HttpContractResponse::MAX_BODY_BYTES];
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(&body);
        response.extend_from_slice(b"\r\n0\r\n\r\n");
        let (transport, server) = canned_domain_transport(response, false).await;

        let response = transport
            .dispatch(domain_request("identity"))
            .await
            .expect("body at the exact bound is valid");
        assert_eq!(response.body().len(), HttpContractResponse::MAX_BODY_BYTES);
        server.await.expect("canned server completes");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn domain_transport_maps_truncated_body_to_invalid_response() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc".to_vec();
        let (transport, server) = canned_domain_transport(response, false).await;

        let error = transport
            .dispatch(domain_request("identity"))
            .await
            .expect_err("truncated response is invalid");
        assert_eq!(
            error.kind(),
            HttpContractTransportErrorKind::InvalidResponse
        );
        server.await.expect("canned server completes");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn domain_transport_missing_target_fails_dispatch() {
        let endpoint = reqwest::Url::parse("http://127.0.0.1:9/rpc").expect("url");
        let transport = test_domain_transport(endpoint);
        let err = transport
            .dispatch(domain_request("audit"))
            .await
            .expect_err("unconfigured target domain fails before network dispatch");
        assert_eq!(err.kind(), HttpContractTransportErrorKind::Dispatch);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn domain_transport_invalid_spiffe_endpoint_fails_fast() {
        let target = DomainHttpTargetConfig::new(
            "identity",
            "https://identity.internal/rpc",
            outbound_policy(),
        )
        .expect("target config");
        let result = DomainHttpTransport::from_spire_with_initial_sync_timeout(
            vec![target],
            Some("tcp://not-an-ip:1"),
            Duration::from_millis(50),
        )
        .await;
        assert!(
            matches!(result, Err(DomainHttpTransportBuildError::SpiffeSource(_))),
            "invalid SPIFFE endpoint must fail before runtime starts"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn domain_transport_target_client_failure_awaits_source_rollback_and_preserves_primary() {
        struct TestSource;
        struct TestCleanupFailure;

        for failure_at in [0, 1] {
            let targets = vec![
                DomainHttpTargetConfig::new(
                    "identity",
                    "https://identity.internal/rpc",
                    outbound_policy(),
                )
                .expect("identity target"),
                DomainHttpTargetConfig::new(
                    "audit",
                    "https://audit.internal/rpc",
                    outbound_policy(),
                )
                .expect("audit target"),
            ];
            let client_builds = Arc::new(AtomicUsize::new(0));
            let rollback_started = Arc::new(AtomicBool::new(false));
            let rollback_completed = Arc::new(AtomicBool::new(false));

            let result = build_domain_http_targets(
                TestSource,
                targets,
                {
                    let client_builds = Arc::clone(&client_builds);
                    move |_, _| {
                        let current = client_builds.fetch_add(1, Ordering::SeqCst);
                        if current == failure_at {
                            Err(DomainHttpTransportBuildError::LocalSvidMismatch)
                        } else {
                            Ok(reqwest::Client::new())
                        }
                    }
                },
                {
                    let rollback_started = Arc::clone(&rollback_started);
                    let rollback_completed = Arc::clone(&rollback_completed);
                    move |_| async move {
                        rollback_started.store(true, Ordering::SeqCst);
                        tokio::task::yield_now().await;
                        rollback_completed.store(true, Ordering::SeqCst);
                        Err(TestCleanupFailure)
                    }
                },
            )
            .await;

            assert!(
                matches!(
                    result,
                    Err(DomainHttpTransportBuildError::LocalSvidMismatch)
                ),
                "cleanup failure must not replace target {failure_at} client error"
            );
            assert_eq!(
                client_builds.load(Ordering::SeqCst),
                failure_at + 1,
                "construction must stop at the failing target"
            );
            assert!(
                rollback_started.load(Ordering::SeqCst),
                "successful source construction must enter rollback"
            );
            assert!(
                rollback_completed.load(Ordering::SeqCst),
                "constructor must await source rollback before returning"
            );
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn serve_mtls_accepts_trusted_client_and_injects_verified_peer() {
        let ca = test_ca();
        let client_id = "spiffe://example.org/ns/rss/sa/internal";
        let mtls = test_mtls_config(&ca, client_id);
        let client_cert = leaf_cert(&ca, None, client_id, ExtendedKeyUsagePurpose::ClientAuth);

        let addr: SocketAddr = "127.0.0.1:0".parse().expect("addr");
        let bound = HttpServer::bind("http-mtls", addr).await.expect("bind ok");
        let local = bound.local_addr();
        let token = CancellationToken::new();
        let server = bound.serve_mtls(make_mtls_svc(), mtls, token.clone());

        let response = tls_get_response_with_timeout(
            local,
            "/mtls-peer",
            client_config(&ca, Some(client_cert)),
        )
        .await
        .expect("trusted mTLS request");
        let status = response.lines().next().unwrap_or_default();
        assert!(
            status.starts_with("HTTP/1.1 200"),
            "trusted client reaches handler with VerifiedMtlsPeer: {status}"
        );
        assert!(
            response.contains(client_id),
            "handler receives the transport-injected peer SPIFFE ID: {response}"
        );

        token.cancel();
        assert!(server.shutdown().await.is_ok(), "mTLS shutdown 收敛");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn mtls_server_uses_same_sealed_request_budget_and_drops_handler() {
        let ca = test_ca();
        let client_id = "spiffe://example.org/ns/rss/sa/internal";
        let mtls = test_mtls_config(&ca, client_id);
        let client_cert = leaf_cert(&ca, None, client_id, ExtendedKeyUsagePurpose::ClientAuth);
        let dropped = Arc::new(AtomicBool::new(false));
        let bound = HttpServer::bind(
            "http-budget-mtls",
            "127.0.0.1:0".parse().expect("ephemeral address"),
        )
        .await
        .expect("bind");
        let local = bound.local_addr();
        let server = bound.serve_mtls(
            make_pending_svc(Arc::clone(&dropped)),
            mtls,
            CancellationToken::new(),
        );

        let response =
            tls_get_response_with_timeout(local, "/slow", client_config(&ca, Some(client_cert)))
                .await
                .expect("mTLS timeout response");
        assert!(response.starts_with("HTTP/1.1 503"), "{response}");
        assert!(response.contains("ERR_CORE_UNAVAILABLE"), "{response}");
        assert!(
            dropped.load(Ordering::Acquire),
            "mTLS timeout must drop handler future"
        );
        assert!(server.shutdown().await.is_ok());
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn serve_mtls_rejects_missing_client_certificate() {
        let ca = test_ca();
        let mtls = test_mtls_config(&ca, "spiffe://example.org/ns/rss/sa/internal");

        let addr: SocketAddr = "127.0.0.1:0".parse().expect("addr");
        let bound = HttpServer::bind("http-mtls-no-client-cert", addr)
            .await
            .expect("bind ok");
        let local = bound.local_addr();
        let token = CancellationToken::new();
        let server = bound.serve_mtls(make_mtls_svc(), mtls, token.clone());

        let result =
            tls_get_response_with_timeout(local, "/mtls-peer", client_config(&ca, None)).await;
        assert!(
            result.is_err(),
            "server must fail closed when client omits a certificate: {result:?}"
        );

        token.cancel();
        assert!(server.shutdown().await.is_ok(), "mTLS shutdown 收敛");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn serve_mtls_rejects_client_certificate_from_wrong_ca() {
        let server_ca = test_ca();
        let wrong_ca = test_ca();
        let client_id = "spiffe://example.org/ns/rss/sa/internal";
        let mtls = test_mtls_config(&server_ca, client_id);
        let wrong_client_cert = leaf_cert(
            &wrong_ca,
            None,
            client_id,
            ExtendedKeyUsagePurpose::ClientAuth,
        );

        let addr: SocketAddr = "127.0.0.1:0".parse().expect("addr");
        let bound = HttpServer::bind("http-mtls-wrong-ca", addr)
            .await
            .expect("bind ok");
        let local = bound.local_addr();
        let token = CancellationToken::new();
        let server = bound.serve_mtls(make_mtls_svc(), mtls, token.clone());

        let result = tls_get_response_with_timeout(
            local,
            "/mtls-peer",
            client_config(&server_ca, Some(wrong_client_cert)),
        )
        .await;
        assert!(
            result.is_err(),
            "server must fail closed for a client certificate outside its trust bundle: {result:?}"
        );

        token.cancel();
        assert!(server.shutdown().await.is_ok(), "mTLS shutdown 收敛");
    }

    /// bind 已占用端口 → fail-fast `HttpServeError::Bind`（不延迟到首请求）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn serve_bind_conflict_fails_fast() {
        // 先占住一个 ephemeral 端口，再用同地址 bind → Bind err。
        let occupied = TcpListener::bind("127.0.0.1:0").await.expect("occupy");
        let addr = occupied.local_addr().expect("addr");
        let err = HttpServer::serve("http-conflict", addr, make_svc())
            .await
            .expect_err("port 占用应 bind 失败");
        assert!(matches!(err, HttpServeError::Bind(_)), "Bind 变体: {err:?}");
        assert_eq!(
            err.to_string(),
            "http server bind failed",
            "安全摘要 message"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn mtls_config_invalid_spiffe_endpoint_fails_fast() {
        let allow_set = authn::MtlsAllowSet::new(["spiffe://example.org/ns/rss/sa/internal"])
            .expect("allow-set");
        let result = MtlsServerConfig::from_spire_with_initial_sync_timeout(
            allow_set,
            Some("tcp://not-an-ip:1"),
            Duration::from_millis(50),
        )
        .await;
        assert!(
            matches!(result, Err(HttpServeError::SpiffeSource(_))),
            "invalid SPIFFE endpoint must fail before listener starts"
        );
    }
}
