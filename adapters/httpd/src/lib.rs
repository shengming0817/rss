//! httpd adapter —— HTTP 传输 adapter（#1320 运行时入口 Join）。
//!
//! 单一 `HttpServer`：bind `TcpListener` → `axum::serve` 已认证 router 的
//! `httpserve::ServerService` →
//! serve task 监听注入的 [`CancellationToken`] 优雅关停；`impl diport::ManagedResource` 经
//! `cancel()` + await JoinHandle 收敛。**精确对标 `adapters/grpc` 的 `GrpcServer`**（transport=adapter）。
//!
//! 私有 make-service 在真实 bind 分支注入 `ConnectInfo<SocketAddr>`，并由同一 adapter-private seam
//! 铸造可信 HTTP/HTTPS observation。`httpserve::ServerService` 不发射 transport evidence；即使外部
//! wrapper 能调用 request core，也不能进入 RSS 的官方 SERVER span/RED owner。
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
    HttpContractRequest, HttpContractResponse, HttpContractTransport, HttpContractTransportError,
    HttpContractTransportErrorKind,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_rustls::server::TlsStream;
use tokio_util::sync::CancellationToken;
use tower::Service;

mod domain_client;
mod server_observation;
#[cfg(test)]
mod server_observation_tests;
use domain_client::{DomainHttpTarget, ObservedHttpClient};

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
    handle: Mutex<Option<diport::OwnedTask<std::io::Result<()>>>>,
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
    endpoint: secure::DomainHttpEndpoint,
    policy: authn::OutboundMtlsPolicy,
}

impl DomainHttpTargetConfig {
    /// Build one target config from the shared, already-validated endpoint type.
    pub fn new(
        domain: impl AsRef<str>,
        endpoint: secure::DomainHttpEndpoint,
        policy: authn::OutboundMtlsPolicy,
    ) -> Result<Self, DomainHttpTransportBuildError> {
        let domain = canonical_domain_key(domain.as_ref())?;
        Ok(Self {
            domain,
            endpoint,
            policy,
        })
    }
}

/// Outbound synchronous cross-domain HTTP transport backed by SPIFFE/mTLS.
///
/// The request type has no header slot. W3C trace context and correlation are minted exclusively from
/// ambient diagnostic context inside the private HTTP-attempt funnel.
pub struct DomainHttpTransport {
    targets: BTreeMap<String, DomainHttpTarget>,
    identity_admission: Option<DomainHttpIdentityAdmission>,
}

struct DomainHttpIdentityAdmission {
    source: DomainHttpIdentitySource,
    expected: authn::SpiffeId,
}

enum DomainHttpIdentitySource {
    Spiffe(spiffe::X509Source),
    #[cfg(test)]
    Fixed {
        healthy: bool,
        current_identity: Option<String>,
    },
}

impl DomainHttpIdentityAdmission {
    fn readiness(&self) -> DomainHttpOwnedReadiness {
        let (healthy, current_identity) = match &self.source {
            DomainHttpIdentitySource::Spiffe(source) => (
                source.is_healthy(),
                source.svid().ok().map(|svid| svid.spiffe_id().to_string()),
            ),
            #[cfg(test)]
            DomainHttpIdentitySource::Fixed {
                healthy,
                current_identity,
            } => (*healthy, current_identity.clone()),
        };
        owned_readiness_from_source_state(
            healthy,
            current_identity.as_deref(),
            Some(self.expected.as_str()),
        )
    }
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
        let expected_local_identity = targets[0].policy.local_identity().clone();
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
            identity_admission: Some(DomainHttpIdentityAdmission {
                source: DomainHttpIdentitySource::Spiffe(source),
                expected: expected_local_identity,
            }),
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
            identity_admission: None,
        })
    }

    #[cfg(test)]
    fn from_targets_with_identity_state(
        targets: BTreeMap<String, DomainHttpTarget>,
        healthy: bool,
        current_identity: Option<&str>,
        expected: authn::SpiffeId,
    ) -> Result<Self, DomainHttpTransportBuildError> {
        let mut transport = Self::from_targets(targets)?;
        transport.identity_admission = Some(DomainHttpIdentityAdmission {
            source: DomainHttpIdentitySource::Fixed {
                healthy,
                current_identity: current_identity.map(str::to_owned),
            },
            expected,
        });
        Ok(transport)
    }

    /// Readiness snapshot for transport state owned by this process.
    ///
    /// Production transports hold an `X509Source`; test-only transports do not. Runtime registers
    /// this as `domain_transport_ready`.
    pub fn owned_readiness(&self) -> DomainHttpOwnedReadiness {
        self.identity_admission.as_ref().map_or(
            DomainHttpOwnedReadiness::Ready,
            DomainHttpIdentityAdmission::readiness,
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
            if self
                .identity_admission
                .as_ref()
                .is_some_and(|admission| !admission.readiness().is_ready())
            {
                return Err(HttpContractTransportError::new(
                    HttpContractTransportErrorKind::Dispatch,
                ));
            }
            let domain = request.contract().domain().to_uppercase();
            let target = self.targets.get(&domain).ok_or_else(|| {
                HttpContractTransportError::new(HttpContractTransportErrorKind::Dispatch)
            })?;
            target.execute_attempt(request).await
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
        if let Some(admission) = &self.identity_admission {
            match &admission.source {
                DomainHttpIdentitySource::Spiffe(source) => source
                    .shutdown_configured()
                    .await
                    .map_err(ShutdownError::new)?,
                #[cfg(test)]
                DomainHttpIdentitySource::Fixed { .. } => {}
            }
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
    ) -> Result<ObservedHttpClient, DomainHttpTransportBuildError>,
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
            DomainHttpTarget::new(target.endpoint.into_url(), client),
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
) -> Result<ObservedHttpClient, DomainHttpTransportBuildError> {
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
    ObservedHttpClient::build_mtls(config).map_err(DomainHttpTransportBuildError::Client)
}

fn owned_readiness_from_source_state(
    source_healthy: bool,
    current_identity: Option<&str>,
    expected_identity: Option<&str>,
) -> DomainHttpOwnedReadiness {
    let identity_matches = match (current_identity, expected_identity) {
        (Some(current), Some(expected)) => current == expected,
        (None, None) => true,
        (Some(_), None) | (None, Some(_)) => false,
    };
    if source_healthy && identity_matches {
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

/// Closed, payload-free observation carrier for every mTLS listener rejection.
///
/// Raw transport/TLS errors and peer addresses deliberately cannot be stored here. Converting at
/// the ownership boundary makes the only rejection logging path safe by construction, including
/// third-party error variants whose `Display` contains certificate text.
///
/// INVARIANT: HTTPD-MTLS-REJECTION-CLOSED-01 { level = "Hard", exec = "native-compile", source = "code", native = "private payload-free enum plus sole record method" }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MtlsRejectionObservation {
    TcpAccept(std::io::ErrorKind),
    TlsRustls,
    CertificateParse,
    MissingSpiffeId,
    TlsIo(std::io::ErrorKind),
    PeerIdMissing,
    PeerIdInvalid,
    PeerNotAllowed,
    Unknown,
}

impl MtlsRejectionObservation {
    fn from_tcp_accept_error(error: &std::io::Error) -> Self {
        Self::TcpAccept(error.kind())
    }

    fn from_handshake_error(error: &spiffe_rustls_tokio::Error) -> Self {
        match error {
            spiffe_rustls_tokio::Error::Rustls(_) => Self::TlsRustls,
            spiffe_rustls_tokio::Error::CertParse(_) => Self::CertificateParse,
            spiffe_rustls_tokio::Error::MissingSpiffeId => Self::MissingSpiffeId,
            spiffe_rustls_tokio::Error::Io(error) => Self::TlsIo(error.kind()),
            _ => Self::Unknown,
        }
    }

    fn stage(self) -> &'static str {
        match self {
            Self::TcpAccept(_) => "tcp_accept",
            Self::TlsRustls
            | Self::CertificateParse
            | Self::MissingSpiffeId
            | Self::TlsIo(_)
            | Self::Unknown => "tls_handshake",
            Self::PeerIdMissing | Self::PeerIdInvalid | Self::PeerNotAllowed => "peer_identity",
        }
    }

    fn reason(self) -> &'static str {
        match self {
            Self::TcpAccept(_) => "tcp_accept",
            Self::TlsRustls => "tls_rustls",
            Self::CertificateParse => "certificate_parse",
            Self::MissingSpiffeId => "missing_spiffe_id",
            Self::TlsIo(_) => "tls_io",
            Self::PeerIdMissing => "peer_id_missing",
            Self::PeerIdInvalid => "peer_id_invalid",
            Self::PeerNotAllowed => "peer_not_allowed",
            Self::Unknown => "unknown",
        }
    }

    fn record(self, listener: &'static str) {
        match self {
            Self::TcpAccept(io_kind) => self.record_tcp_accept(listener, io_kind),
            Self::TlsIo(io_kind) => self.record_connection_with_io(listener, io_kind),
            _ => self.record_connection(listener),
        }
    }

    fn record_tcp_accept(self, listener: &'static str, io_kind: std::io::ErrorKind) {
        let stage = self.stage();
        let reason = self.reason();
        tracing::error!(listener, stage, reason, io_kind = ?io_kind, "http mtls listener rejected transport");
    }

    fn record_connection_with_io(self, listener: &'static str, io_kind: std::io::ErrorKind) {
        let stage = self.stage();
        let reason = self.reason();
        tracing::warn!(listener, stage, reason, io_kind = ?io_kind, "http mtls connection rejected");
    }

    fn record_connection(self, listener: &'static str) {
        let stage = self.stage();
        let reason = self.reason();
        tracing::warn!(listener, stage, reason, "http mtls connection rejected");
    }
}

struct MtlsListener {
    name: &'static str,
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
                    MtlsRejectionObservation::from_tcp_accept_error(&e).record(self.name);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };
            let (tls, identity) = match self.config.acceptor.accept(stream).await {
                Ok(parts) => parts,
                Err(e) => {
                    MtlsRejectionObservation::from_handshake_error(&e).record(self.name);
                    continue;
                }
            };
            let Some(peer_id) = identity.spiffe_id() else {
                MtlsRejectionObservation::PeerIdMissing.record(self.name);
                continue;
            };
            let peer_id = match authn::SpiffeId::parse(&peer_id.to_string()) {
                Ok(peer_id) => peer_id,
                Err(_) => {
                    MtlsRejectionObservation::PeerIdInvalid.record(self.name);
                    continue;
                }
            };
            let peer = match authn::verify_mtls_peer(peer_id, &self.config.allow_set) {
                Ok(peer) => peer,
                Err(_) => {
                    MtlsRejectionObservation::PeerNotAllowed.record(self.name);
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

/// Adapter-private transport truth. The real bind path mints this closed value, so request headers
/// and assembly callers cannot select either the observed scheme or the HSTS wire policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TransportPolicy {
    Plaintext,
    Tls,
}

impl TransportPolicy {
    fn scheme(self) -> server_observation::TransportScheme {
        match self {
            Self::Plaintext => server_observation::TransportScheme::Http,
            Self::Tls => server_observation::TransportScheme::Https,
        }
    }

    fn finalize_response(self, mut response: axum::response::Response) -> axum::response::Response {
        if self == Self::Plaintext {
            response.headers_mut().remove("strict-transport-security");
        }
        response
    }
}

/// Adapter-private bridge from the budget/auth-sealed per-request core to axum's connection
/// make-service contract. Construction is colocated with the actual plaintext/mTLS serve branch.
#[derive(Clone)]
struct TransportMakeService {
    inner: httpserve::ServerService,
    policy: TransportPolicy,
}

impl TransportMakeService {
    fn plaintext(inner: httpserve::ServerService) -> Self {
        Self {
            inner,
            policy: TransportPolicy::Plaintext,
        }
    }

    fn tls(inner: httpserve::ServerService) -> Self {
        Self {
            inner,
            policy: TransportPolicy::Tls,
        }
    }
}

impl<'a, L> Service<IncomingStream<'a, L>> for TransportMakeService
where
    L: Listener<Addr = SocketAddr>,
{
    type Response = TransportService;
    type Error = Infallible;
    type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, target: IncomingStream<'a, L>) -> Self::Future {
        std::future::ready(Ok(TransportService {
            inner: self.inner.clone(),
            policy: self.policy,
            remote_addr: *target.remote_addr(),
        }))
    }
}

#[derive(Clone)]
struct TransportService {
    inner: httpserve::ServerService,
    policy: TransportPolicy,
    remote_addr: SocketAddr,
}

impl Service<axum::extract::Request> for TransportService {
    type Response = axum::response::Response;
    type Error = Infallible;
    type Future = TransportResponseFuture<
        <httpserve::ServerService as Service<axum::extract::Request>>::Future,
    >;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: axum::extract::Request) -> Self::Future {
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(self.remote_addr));
        let observation = match self.inner.observation_policy() {
            httpserve::ServerObservationPolicy::Enabled(listener) => {
                let inbound =
                    server_observation::InboundTraceContext::from_headers(request.headers());
                let observation = server_observation::RequestObservation::new(
                    request.method(),
                    request.version(),
                    self.policy.scheme(),
                    listener,
                );
                if let Some(inbound) = inbound {
                    inbound.apply_to(&observation.span());
                }
                Some(observation)
            }
            httpserve::ServerObservationPolicy::Disabled => None,
        };
        TransportResponseFuture {
            inner: self.inner.call(request),
            observation,
            policy: self.policy,
        }
    }
}

struct TransportResponseFuture<F> {
    inner: F,
    observation: Option<server_observation::RequestObservation>,
    policy: TransportPolicy,
}

impl<F> Future for TransportResponseFuture<F>
where
    F: Future<Output = Result<httpserve::ServerResponse, Infallible>> + Unpin,
{
    type Output = Result<axum::response::Response, Infallible>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let span = self.observation.as_ref().map_or_else(
            tracing::Span::none,
            server_observation::RequestObservation::span,
        );
        let poll = span.in_scope(|| Pin::new(&mut self.inner).poll(cx));
        match poll {
            Poll::Ready(Ok(response)) => {
                let response = match self.observation.take() {
                    Some(observation) => observation.observe_response(response),
                    None => response.into_response(),
                };
                Poll::Ready(Ok(self.policy.finalize_response(response)))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
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
    pub fn serve(self, svc: httpserve::ServerService, token: CancellationToken) -> HttpServer {
        tracing::warn!(
            name = self.name,
            transport = "plaintext",
            hsts_policy = "strip",
            "plaintext listener strips Strict-Transport-Security; the TLS terminator must own HSTS"
        );
        let serve_token = token.clone();
        let listener = self.listener;
        let handle = tokio::spawn(async move {
            let svc = TransportMakeService::plaintext(svc);
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
            handle: Mutex::new(Some(diport::OwnedTask::new(handle))),
        }
    }

    /// Spawn an mTLS HTTP serve task. Each accepted request receives both
    /// `ConnectInfo<SocketAddr>` and `authn::VerifiedMtlsPeer` extensions.
    pub fn serve_mtls(
        self,
        svc: httpserve::ServerService,
        mtls: MtlsServerConfig,
        token: CancellationToken,
    ) -> HttpServer {
        let serve_token = token.clone();
        let listener = MtlsListener {
            name: self.name,
            listener: self.listener,
            local_addr: self.local_addr,
            config: mtls,
        };
        let handle = tokio::spawn(async move {
            let svc = TransportMakeService::tls(svc);
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
            handle: Mutex::new(Some(diport::OwnedTask::new(handle))),
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
        svc: httpserve::ServerService,
        token: CancellationToken,
    ) -> Result<Self, HttpServeError> {
        Ok(Self::bind(name, addr).await?.serve(svc, token))
    }

    /// Convenience constructor for mTLS listener.
    pub async fn serve_mtls_with_token(
        name: &'static str,
        addr: SocketAddr,
        svc: httpserve::ServerService,
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
        svc: httpserve::ServerService,
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

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        // 触发 graceful 退出：cancel token（幂等——若 ShutdownStack 阶段 1 已 cancel 则 no-op）。
        self.token.cancel();
        // await serve task 收敛；失败只经 typed shutdown funnel 上抛，由 ShutdownStack 统一观察。
        if let Some(handle) = self.handle.lock().await.take() {
            let serve_result = handle
                .join()
                .await
                .map_err(ShutdownError::from_join_error)?;
            serve_result.map_err(ShutdownError::new)?;
            tracing::info!(name = self.name, "http server shutdown complete");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::num::NonZeroU64;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

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
    use tracing::Instrument as _;

    #[derive(Default)]
    struct EventCapture {
        next_id: AtomicU64,
        events: std::sync::Mutex<Vec<HashMap<String, String>>>,
    }

    struct EventFieldCapture<'a>(&'a mut HashMap<String, String>);

    impl tracing::field::Visit for EventFieldCapture<'_> {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.0.insert(field.name().to_owned(), format!("{value:?}"));
        }

        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.0.insert(field.name().to_owned(), value.to_owned());
        }
    }

    impl tracing::Subscriber for EventCapture {
        fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, _attrs: &tracing::span::Attributes<'_>) -> tracing::Id {
            tracing::Id::from_u64(self.next_id.fetch_add(1, Ordering::Relaxed) + 1)
        }

        fn record(&self, _span: &tracing::Id, _values: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _span: &tracing::Id, _follows: &tracing::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            let mut fields = HashMap::new();
            fields.insert(
                "level".to_owned(),
                event.metadata().level().as_str().to_owned(),
            );
            event.record(&mut EventFieldCapture(&mut fields));
            self.events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(fields);
        }

        fn enter(&self, _span: &tracing::Id) {}

        fn exit(&self, _span: &tracing::Id) {}
    }

    fn captured_event_surface(capture: &EventCapture) -> String {
        format!(
            "{:?}",
            capture
                .events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        )
    }

    #[allow(clippy::expect_used)]
    fn assert_shutdown_error_redacts(error: &ShutdownError, marker: &str) {
        assert!(!error.to_string().contains(marker));
        assert!(!format!("{error:?}").contains(marker));
        let source = std::error::Error::source(error).expect("redacted source remains visible");
        assert!(!source.to_string().contains(marker));
        assert!(
            source.source().is_none(),
            "source chain stops at redaction boundary"
        );
    }

    #[test]
    fn mtls_rejection_observation_discards_raw_payloads_and_address() {
        const LISTENER: &str = "http-primary-mtls";
        const CERT_MARKER: &str = "certificate-subject-plain-secret";
        const IO_MARKER: &str = "postgres://observer:plain-secret@db.internal:5432/db";
        const RUSTLS_MARKER: &str = "rustls-alert-plain-secret";
        const ADDRESS_MARKER: &str = "127.0.0.1:4545";
        let raw_handshake = spiffe_rustls_tokio::Error::CertParse(CERT_MARKER.to_owned());
        assert!(
            raw_handshake.to_string().contains(CERT_MARKER),
            "anti-vacuity"
        );
        let raw_io = std::io::Error::other(IO_MARKER);
        assert!(raw_io.to_string().contains(IO_MARKER), "anti-vacuity");
        let raw_tls_io = spiffe_rustls_tokio::Error::Io(std::io::Error::other(IO_MARKER));
        let raw_rustls =
            spiffe_rustls_tokio::Error::Rustls(rustls::Error::General(RUSTLS_MARKER.to_owned()));
        let remote_address: SocketAddr = ADDRESS_MARKER.parse().expect("marker address");
        assert_eq!(remote_address.to_string(), ADDRESS_MARKER, "anti-vacuity");

        let capture = Arc::new(EventCapture::default());
        let dispatch = tracing::Dispatch::new(Arc::clone(&capture));
        tracing::dispatcher::with_default(&dispatch, || {
            MtlsRejectionObservation::from_handshake_error(&raw_handshake).record(LISTENER);
            MtlsRejectionObservation::from_tcp_accept_error(&raw_io).record(LISTENER);
            MtlsRejectionObservation::from_handshake_error(&raw_tls_io).record(LISTENER);
            MtlsRejectionObservation::from_handshake_error(&raw_rustls).record(LISTENER);
            MtlsRejectionObservation::MissingSpiffeId.record(LISTENER);
            MtlsRejectionObservation::PeerIdMissing.record(LISTENER);
            MtlsRejectionObservation::PeerIdInvalid.record(LISTENER);
            MtlsRejectionObservation::PeerNotAllowed.record(LISTENER);
            MtlsRejectionObservation::Unknown.record(LISTENER);
        });

        let surface = captured_event_surface(&capture);
        for reason in [
            "certificate_parse",
            "tcp_accept",
            "tls_io",
            "tls_rustls",
            "missing_spiffe_id",
            "peer_id_missing",
            "peer_id_invalid",
            "peer_not_allowed",
            "unknown",
        ] {
            assert!(surface.contains(reason), "missing {reason}: {surface}");
        }
        for marker in [CERT_MARKER, IO_MARKER, RUSTLS_MARKER, ADDRESS_MARKER] {
            assert!(!surface.contains(marker), "raw marker leaked: {surface}");
        }
        let events = capture
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(events.len(), 9);
        for event in events.iter() {
            assert!(event.contains_key("message"));
            assert!(event.contains_key("stage"));
            assert_eq!(event.get("listener").map(String::as_str), Some(LISTENER));
            assert!(event.contains_key("reason"));
            assert!(
                event.keys().all(|key| matches!(
                    key.as_str(),
                    "message" | "listener" | "stage" | "reason" | "io_kind" | "level"
                )),
                "unexpected observation field: {event:?}"
            );
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used, clippy::panic)]
    async fn http_server_shutdown_propagates_redacted_io_and_join_failures() {
        const IO_MARKER: &str = "redis://shutdown:io-secret@cache.internal/0";
        const PANIC_MARKER: &str = "http-worker-plain-panic-secret";

        let io_server = HttpServer {
            name: "http-io-failure",
            local_addr: "127.0.0.1:0".parse().expect("test address"),
            token: CancellationToken::new(),
            handle: Mutex::new(Some(diport::OwnedTask::new(tokio::spawn(async {
                Err(std::io::Error::other(IO_MARKER))
            })))),
        };
        let io_error = ManagedResource::shutdown(&io_server)
            .await
            .expect_err("serve io failure must propagate");
        assert_shutdown_error_redacts(&io_error, IO_MARKER);
        assert_eq!(io_error.kind(), diport::ShutdownErrorKind::Operation);
        assert!(
            ManagedResource::shutdown(&io_server).await.is_ok(),
            "shutdown is idempotent"
        );

        let panic_server = HttpServer {
            name: "http-join-failure",
            local_addr: "127.0.0.1:0".parse().expect("test address"),
            token: CancellationToken::new(),
            handle: Mutex::new(Some(diport::OwnedTask::new(tokio::spawn(async {
                panic!("{PANIC_MARKER}")
            })))),
        };
        let join_error = ManagedResource::shutdown(&panic_server)
            .await
            .expect_err("serve task panic must propagate");
        assert_shutdown_error_redacts(&join_error, PANIC_MARKER);
        assert_eq!(join_error.kind(), diport::ShutdownErrorKind::TaskPanicked);

        let cancelled_handle = tokio::spawn(std::future::pending::<std::io::Result<()>>());
        cancelled_handle.abort();
        let cancelled_server = HttpServer {
            name: "http-cancelled",
            local_addr: "127.0.0.1:0".parse().expect("test address"),
            token: CancellationToken::new(),
            handle: Mutex::new(Some(diport::OwnedTask::new(cancelled_handle))),
        };
        let cancelled_error = ManagedResource::shutdown(&cancelled_server)
            .await
            .expect_err("serve task cancellation must propagate");
        assert_eq!(
            cancelled_error.kind(),
            diport::ShutdownErrorKind::TaskCancelled
        );
    }

    /// 极简 router → budget-sealed server service，挂一个 GET /healthz 恒 200。
    fn make_svc() -> httpserve::ServerService {
        httpserve::ServerService::from_router_for_test(
            Router::new().route("/healthz", get(|| async { "ok" })),
            httpserve::ServerRequestBudget::for_test(),
        )
    }

    #[derive(Default)]
    struct RecordingRateLimiter {
        keys: std::sync::Mutex<Vec<String>>,
    }

    impl diport::RateLimiter for RecordingRateLimiter {
        async fn check(
            &self,
            key: diport::RateLimitKey,
        ) -> Result<diport::RateLimitDecision, diport::RateLimitError> {
            self.keys
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(key.as_str().to_owned());
            Ok(diport::RateLimitDecision::Allowed)
        }

        async fn shutdown(&self) -> Result<(), diport::RateLimitError> {
            Ok(())
        }
    }

    fn make_real_ip_svc(
        config: httpserve::TrustedProxyConfig,
        limiter: Arc<RecordingRateLimiter>,
    ) -> httpserve::ServerService {
        let routes = httpserve::routes::unfinalized_for_test::<httpserve::Admin>(|router| {
            router.mount_raw_for_test(
                httpserve::TestRoute {
                    method: axum::http::Method::GET,
                    path: "/test",
                    contract_id: "test.httpd-real-ip",
                },
                get(|| async { "ok" }),
            )
        })
        .unwrap_or_else(|_| unreachable!("fixed test route is valid"));
        let plan = primitives::AuthPlan::new(
            primitives::ListenerKind::Admin,
            primitives::AuthScheme::RssAccessToken,
        )
        .unwrap_or_else(|_| unreachable!("admin RSS plan is valid"));
        let authed = httpserve::finalize_auth(routes, plan)
            .unwrap_or_else(|_| unreachable!("test route finalizes"));
        httpserve::with_client_rate_limit(authed, limiter, config)
            .into_server_service(httpserve::ServerRequestBudget::for_test())
    }

    fn make_mtls_svc() -> httpserve::ServerService {
        httpserve::ServerService::from_router_for_test(
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

    fn make_hsts_svc() -> httpserve::ServerService {
        httpserve::ServerService::from_router_for_test(
            Router::new().route("/ok", get(|| async { "ok" })),
            httpserve::ServerRequestBudget::for_test(),
        )
    }

    fn make_domain_transport_svc() -> httpserve::ServerService {
        httpserve::ServerService::from_router_for_test(
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

    #[test]
    fn actual_transport_make_service_owns_closed_scheme_selection() {
        assert_eq!(
            TransportMakeService::plaintext(make_svc()).policy.scheme(),
            server_observation::TransportScheme::Http
        );
        assert_eq!(
            TransportMakeService::tls(make_mtls_svc()).policy.scheme(),
            server_observation::TransportScheme::Https
        );
    }

    struct HandlerDropSignal(Arc<AtomicBool>);

    impl Drop for HandlerDropSignal {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    #[allow(clippy::expect_used)]
    fn make_pending_svc(dropped: Arc<AtomicBool>) -> httpserve::ServerService {
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
        httpserve::ServerService::from_router_for_test(
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
        let traceparent = headers
            .get("traceparent")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        let tracestate = headers
            .get("tracestate")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        let body = format!(
            "{}|correlation={correlation_id}|auth={auth_present}|tenant={tenant_present}|traceparent={traceparent}|tracestate={tracestate}",
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
            Vec::new(),
        )
    }

    #[allow(clippy::expect_used)]
    fn test_domain_transport(endpoint: reqwest::Url) -> DomainHttpTransport {
        test_domain_transport_with_client(endpoint, ObservedHttpClient::plaintext_for_test())
    }

    #[allow(clippy::expect_used)]
    fn test_domain_transport_with_client(
        endpoint: reqwest::Url,
        client: ObservedHttpClient,
    ) -> DomainHttpTransport {
        let mut targets = BTreeMap::new();
        targets.insert(
            "IDENTITY".to_owned(),
            DomainHttpTarget::new(endpoint, client),
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
        raw_get_response_with_headers(addr, path, "").await
    }

    #[allow(clippy::expect_used)]
    async fn raw_get_response_with_headers(addr: SocketAddr, path: &str, headers: &str) -> String {
        let mut stream = TcpStream::connect(addr)
            .await
            .expect("connect bound socket");
        let req =
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n{headers}Connection: close\r\n\r\n");
        stream
            .write_all(req.as_bytes())
            .await
            .expect("write request");
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.expect("read response");
        String::from_utf8_lossy(&buf).into_owned()
    }

    #[allow(clippy::expect_used)]
    async fn raw_get_with_xff(addr: SocketAddr, path: &str, xff: &str) -> String {
        let mut stream = TcpStream::connect(addr)
            .await
            .expect("connect bound socket");
        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: {xff}\r\nConnection: close\r\n\r\n"
        );
        stream
            .write_all(req.as_bytes())
            .await
            .expect("write request");
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.expect("read response");
        String::from_utf8(buf).expect("HTTP response is utf-8")
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
    async fn real_socket_rate_limit_uses_trusted_client_and_disabled_peer() {
        for (name, config, expected) in [
            (
                "trusted",
                httpserve::TrustedProxyConfig::try_from_json(Some(r#"["127.0.0.0/8"]"#))
                    .expect("trusted loopback CIDR"),
                "203.0.113.7",
            ),
            (
                "disabled",
                httpserve::TrustedProxyConfig::disabled(),
                "127.0.0.1",
            ),
        ] {
            let limiter = Arc::new(RecordingRateLimiter::default());
            let bound = HttpServer::bind(
                "http-real-ip",
                "127.0.0.1:0".parse().expect("ephemeral address"),
            )
            .await
            .expect("bind");
            let local = bound.local_addr();
            let server = bound.serve(
                make_real_ip_svc(config, Arc::clone(&limiter)),
                CancellationToken::new(),
            );
            let response = raw_get_with_xff(local, "/test", "203.0.113.7, 127.0.0.2").await;
            assert!(response.starts_with("HTTP/1.1 "), "{name}: {response}");
            assert_eq!(
                limiter
                    .keys
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .as_slice(),
                [expected],
                "{name} policy must select the correct bucket key"
            );
            assert!(server.shutdown().await.is_ok(), "{name} shutdown");
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn plaintext_transport_strips_hsts_from_success_and_real_body_limit_response() {
        let bound = HttpServer::bind(
            "http-hsts-strip",
            "127.0.0.1:0".parse().expect("ephemeral address"),
        )
        .await
        .expect("bind");
        let local = bound.local_addr();
        let server = bound.serve(make_hsts_svc(), CancellationToken::new());

        for (response, status, expected_body) in [
            (raw_get_response(local, "/ok").await, "200", "ok"),
            (
                raw_get_response_with_headers(local, "/ok", "Content-Length: 1048577\r\n").await,
                "413",
                "ERR_CORE_PAYLOAD_TOO_LARGE",
            ),
        ] {
            assert!(
                response.starts_with(&format!("HTTP/1.1 {status}")),
                "unexpected response: {response}"
            );
            assert!(response.contains(expected_body), "{response}");
            assert!(
                !response
                    .to_ascii_lowercase()
                    .contains("strict-transport-security:"),
                "plaintext must strip HSTS: {response}"
            );
            assert!(
                response
                    .to_ascii_lowercase()
                    .contains("x-content-type-options: nosniff"),
                "transport guard must preserve other security headers: {response}"
            );
        }

        assert!(server.shutdown().await.is_ok());
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn plaintext_listener_records_one_closed_hsts_warning_at_startup() {
        let bound = HttpServer::bind(
            "http-hsts-warning",
            "127.0.0.1:0".parse().expect("ephemeral address"),
        )
        .await
        .expect("bind");
        let capture = Arc::new(EventCapture::default());
        let dispatch = tracing::Dispatch::new(Arc::clone(&capture));
        let server = tracing::dispatcher::with_default(&dispatch, || {
            bound.serve(make_svc(), CancellationToken::new())
        });

        {
            let events = capture
                .events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let warnings = events
                .iter()
                .filter(|event| event.get("hsts_policy").map(String::as_str) == Some("strip"))
                .collect::<Vec<_>>();
            assert_eq!(warnings.len(), 1, "one policy warning per listener startup");
            assert_eq!(
                warnings[0].get("transport").map(String::as_str),
                Some("plaintext")
            );
            assert_eq!(
                warnings[0].get("name").map(String::as_str),
                Some("http-hsts-warning")
            );
            assert_eq!(warnings[0].get("level").map(String::as_str), Some("WARN"));
            assert!(
                warnings[0].keys().all(|key| matches!(
                    key.as_str(),
                    "message" | "name" | "transport" | "hsts_policy" | "level"
                )),
                "warning must expose only the closed field set: {:?}",
                warnings[0]
            );
        }

        assert!(server.shutdown().await.is_ok());
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
            !response
                .to_ascii_lowercase()
                .contains("strict-transport-security:"),
            "real request-budget 503 must be sanitized: {response}"
        );
        assert!(
            response
                .to_ascii_lowercase()
                .contains("x-content-type-options: nosniff"),
            "other security headers must survive: {response}"
        );
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
        assert!(domain_client::CONNECT_TIMEOUT > Duration::ZERO);
        assert!(domain_client::REQUEST_TIMEOUT > domain_client::CONNECT_TIMEOUT);
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
            owned_readiness_from_source_state(
                true,
                Some("spiffe://example.test/runtime"),
                Some("spiffe://example.test/runtime")
            ),
            DomainHttpOwnedReadiness::Ready
        );
        assert_eq!(
            owned_readiness_from_source_state(
                false,
                Some("spiffe://example.test/runtime"),
                Some("spiffe://example.test/runtime")
            ),
            DomainHttpOwnedReadiness::MtlsSourceUnavailable
        );
        assert_eq!(
            owned_readiness_from_source_state(
                true,
                Some("spiffe://example.test/rotated-wrong-id"),
                Some("spiffe://example.test/runtime")
            ),
            DomainHttpOwnedReadiness::MtlsSourceUnavailable
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn domain_transport_identity_rotation_mismatch_rejects_before_network_attempt() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let endpoint = reqwest::Url::parse(&format!(
            "http://{}/rpc",
            listener.local_addr().expect("address")
        ))
        .expect("url");
        let mut targets = BTreeMap::new();
        targets.insert(
            "IDENTITY".to_owned(),
            DomainHttpTarget::new(endpoint, ObservedHttpClient::plaintext_for_test()),
        );
        let expected = authn::SpiffeId::parse("spiffe://example.org/ns/rss/sa/runtime")
            .expect("expected identity");
        let transport = DomainHttpTransport::from_targets_with_identity_state(
            targets,
            true,
            Some("spiffe://example.org/ns/rss/sa/rotated-wrong-id"),
            expected,
        )
        .expect("transport");

        let error = transport
            .dispatch(domain_request("identity"))
            .await
            .expect_err("identity mismatch must fail closed");
        assert_eq!(error.kind(), HttpContractTransportErrorKind::Dispatch);
        assert_eq!(
            transport.owned_readiness(),
            DomainHttpOwnedReadiness::MtlsSourceUnavailable
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err(),
            "identity mismatch must reject before target connection"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn domain_transport_target_keeps_shared_typed_endpoint() {
        let endpoint =
            secure::DomainHttpEndpoint::parse("https://identity.internal:8443/nested/rpc")
                .expect("valid endpoint");
        let target = DomainHttpTargetConfig::new("identity", endpoint.clone(), outbound_policy())
            .expect("target config");
        assert_eq!(target.endpoint, endpoint);
        assert_eq!(target.endpoint.as_url().path(), "/nested/rpc");
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

        let context = diagctx::DiagnosticCtx::new(
            diagctx::CorrelationId::parse("corr-1500").expect("valid correlation"),
        );
        let response = diagctx::scope(context, transport.dispatch(domain_request("identity")))
            .await
            .expect("dispatch");
        assert_eq!(response.status_code(), 201);
        assert_eq!(
            response.body(),
            b"payload|correlation=corr-1500|auth=false|tenant=false|traceparent=|tracestate="
        );

        assert!(server.shutdown().await.is_ok(), "echo shutdown 收敛");
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn domain_transport_client_span_mints_w3c_and_parents_server_span() {
        const UPSTREAM: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let (response_body, spans) = tracewiretest::with_test_span_capture(async {
            let addr: SocketAddr = "127.0.0.1:0".parse().expect("addr");
            let server = HttpServer::serve("domain-trace", addr, make_domain_transport_svc())
                .await
                .expect("serve echo");
            let endpoint =
                reqwest::Url::parse(&format!("http://{}/rpc", server.local_addr())).expect("url");
            let transport = test_domain_transport(endpoint);
            let ambient = tracing::info_span!(parent: None, "ambient.dispatch");
            let upstream = tracewire::TraceParent::parse(UPSTREAM).expect("fixed traceparent");
            let _ = tracewire::restore_remote_parent(&ambient, &upstream, Some("vendor=value"));
            let context = diagctx::DiagnosticCtx::new(
                diagctx::CorrelationId::parse("corr-t2").expect("valid correlation"),
            );
            let response = diagctx::scope(
                context,
                transport
                    .dispatch(domain_request("identity"))
                    .instrument(ambient),
            )
            .await
            .expect("dispatch");
            server.shutdown().await.expect("shutdown");
            String::from_utf8(response.body().to_vec()).expect("utf8 response")
        });

        let ambient = spans
            .iter()
            .find(|span| span.name == "ambient.dispatch")
            .expect("ambient span");
        let client = spans
            .iter()
            .find(|span| span.kind == "client")
            .expect("one client span");
        let server = spans
            .iter()
            .find(|span| span.kind == "server")
            .expect("one server span");
        assert_eq!(client.trace_id, ambient.trace_id);
        assert_eq!(client.parent_span_id, ambient.span_id);
        assert_eq!(server.trace_id, client.trace_id);
        assert_eq!(server.parent_span_id, client.span_id);
        assert_eq!(client.tracestate, "vendor=value");
        assert_eq!(server.tracestate, "vendor=value");
        assert!(
            response_body.contains(&format!(
                "traceparent=00-{}-{}-01",
                client.trace_id, client.span_id
            )),
            "wire traceparent must be minted from the CLIENT span: {response_body}"
        );
        assert!(response_body.contains("tracestate=vendor=value"));
        assert!(response_body.contains("correlation=corr-t2"));
        let client_surface = format!("{} {:?}", client.name, client.attributes);
        for forbidden in ["/rpc", "payload", "corr-t2", "vendor=value", "127.0.0.1"] {
            assert!(
                !client_surface.contains(forbidden),
                "CLIENT observation leaked forbidden marker {forbidden}: {client_surface}"
            );
        }
        assert_eq!(spans.iter().filter(|span| span.kind == "client").count(), 1);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn domain_transport_without_ambient_parent_starts_client_root_and_injects_it() {
        let (_, spans) = tracewiretest::with_test_span_capture(async {
            let server = HttpServer::serve(
                "domain-root",
                "127.0.0.1:0".parse().expect("addr"),
                make_domain_transport_svc(),
            )
            .await
            .expect("serve");
            let endpoint =
                reqwest::Url::parse(&format!("http://{}/rpc", server.local_addr())).expect("url");
            test_domain_transport(endpoint)
                .dispatch(domain_request("identity"))
                .await
                .expect("dispatch");
            server.shutdown().await.expect("shutdown");
        });
        let client = spans
            .iter()
            .find(|span| span.kind == "client")
            .expect("client span");
        let server = spans
            .iter()
            .find(|span| span.kind == "server")
            .expect("server span");
        assert_eq!(client.parent_span_id, "0000000000000000");
        assert_eq!(server.parent_span_id, client.span_id);
        assert_eq!(server.trace_id, client.trace_id);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn domain_transport_does_not_follow_redirect() {
        let redirected = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("redirect target bind");
        let redirected_addr = redirected.local_addr().expect("target addr");
        let target_task = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_millis(100), redirected.accept())
                .await
                .is_ok()
        });

        let origin = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("redirect origin bind");
        let origin_addr = origin.local_addr().expect("origin addr");
        let origin_task = tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.expect("origin accept");
            let mut request = [0_u8; 2048];
            let _ = stream.read(&mut request).await.expect("read request");
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 302 Found\r\nLocation: http://{redirected_addr}/leak\r\nContent-Length: 0\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .expect("write redirect");
        });
        let endpoint = reqwest::Url::parse(&format!("http://{origin_addr}/rpc")).expect("url");
        let response = test_domain_transport(endpoint)
            .dispatch(domain_request("identity"))
            .await
            .expect("302 is a complete transport response");
        assert_eq!(response.status_code(), 302);
        origin_task.await.expect("origin completes");
        assert!(
            !target_task.await.expect("target task"),
            "redirect target was contacted"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn domain_transport_does_not_retry_incomplete_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("first accept");
            let mut request = [0_u8; 2048];
            let _ = stream.read(&mut request).await.expect("read request");
            drop(stream);
            usize::from(
                tokio::time::timeout(Duration::from_millis(100), listener.accept())
                    .await
                    .is_ok(),
            ) + 1
        });
        let endpoint = reqwest::Url::parse(&format!("http://{addr}/rpc")).expect("url");
        let error = test_domain_transport(endpoint)
            .dispatch(domain_request("identity"))
            .await
            .expect_err("closed response is invalid");
        assert_eq!(
            error.kind(),
            HttpContractTransportErrorKind::InvalidResponse
        );
        assert_eq!(
            server.await.expect("server count"),
            1,
            "one network attempt"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn domain_transport_timeout_settles_one_client_span() {
        let (kind, spans) = tracewiretest::with_test_span_capture(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("addr");
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.expect("accept");
                let mut request = [0_u8; 2048];
                let _ = stream.read(&mut request).await.expect("read");
                std::future::pending::<()>().await;
            });
            let endpoint = reqwest::Url::parse(&format!("http://{addr}/rpc")).expect("url");
            let transport = test_domain_transport_with_client(
                endpoint,
                ObservedHttpClient::plaintext_with_timeout_for_test(Duration::from_millis(20)),
            );
            let error = transport
                .dispatch(domain_request("identity"))
                .await
                .expect_err("request timeout");
            server.abort();
            let _ = server.await;
            error.kind()
        });
        assert_eq!(kind, HttpContractTransportErrorKind::Timeout);
        let clients: Vec<_> = spans.iter().filter(|span| span.kind == "client").collect();
        assert_eq!(clients.len(), 1);
        assert_eq!(
            clients[0].attributes.get("outcome").map(String::as_str),
            Some("error")
        );
        assert_eq!(
            clients[0].attributes.get("error.type").map(String::as_str),
            Some("timeout")
        );
        assert!(clients[0].status.starts_with("error"));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn domain_transport_cancelled_future_settles_one_client_span() {
        let (_, spans) = tracewiretest::with_test_span_capture(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("addr");
            let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.expect("accept");
                let mut request = [0_u8; 2048];
                let _ = stream.read(&mut request).await.expect("read");
                let _ = accepted_tx.send(());
                std::future::pending::<()>().await;
            });
            let endpoint = reqwest::Url::parse(&format!("http://{addr}/rpc")).expect("url");
            let transport = test_domain_transport(endpoint);
            let mut attempt = transport.dispatch(domain_request("identity"));
            tokio::select! {
                result = &mut attempt => {
                    result.expect("pending peer must not complete");
                }
                accepted = accepted_rx => {
                    accepted.expect("server observed request");
                }
            }
            drop(attempt);
            server.abort();
            let _ = server.await;
        });
        let clients: Vec<_> = spans.iter().filter(|span| span.kind == "client").collect();
        assert_eq!(clients.len(), 1);
        assert_eq!(
            clients[0].attributes.get("outcome").map(String::as_str),
            Some("error")
        );
        assert_eq!(
            clients[0].attributes.get("error.type").map(String::as_str),
            Some("dispatch")
        );
        assert!(clients[0].status.starts_with("error"));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn domain_transport_http_error_status_is_transport_ok_and_otel_error() {
        let (statuses, spans) = tracewiretest::with_test_span_capture(async {
            let mut statuses = Vec::new();
            for wire in [
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec(),
                b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n".to_vec(),
            ] {
                let (transport, server) = canned_domain_transport(wire, false).await;
                let response = transport
                    .dispatch(domain_request("identity"))
                    .await
                    .expect("bounded HTTP error is a transport response");
                server.await.expect("server completes");
                statuses.push(response.status_code());
            }
            statuses
        });
        assert_eq!(statuses, [404, 503]);
        let clients: Vec<_> = spans.iter().filter(|span| span.kind == "client").collect();
        assert_eq!(clients.len(), 2);
        let mut error_types = clients
            .iter()
            .map(|span| {
                assert_eq!(
                    span.attributes.get("outcome").map(String::as_str),
                    Some("ok")
                );
                assert!(span.status.starts_with("error"));
                span.attributes
                    .get("error.type")
                    .expect("status error type")
                    .as_str()
            })
            .collect::<Vec<_>>();
        error_types.sort_unstable();
        assert_eq!(error_types, ["404", "503"]);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn domain_transport_failure_taxonomy_settles_exactly_once() {
        let (kinds, spans) = tracewiretest::with_test_span_capture(async {
            let mut kinds = Vec::new();
            let oversized = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                HttpContractResponse::MAX_BODY_BYTES + 1
            )
            .into_bytes();
            let (transport, server) = canned_domain_transport(oversized, true).await;
            kinds.push(
                transport
                    .dispatch(domain_request("identity"))
                    .await
                    .expect_err("oversize")
                    .kind(),
            );
            server.abort();

            let (transport, server) = canned_domain_transport(
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc".to_vec(),
                false,
            )
            .await;
            kinds.push(
                transport
                    .dispatch(domain_request("identity"))
                    .await
                    .expect_err("invalid framing")
                    .kind(),
            );
            server.await.expect("invalid server completes");

            let unused = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = unused.local_addr().expect("addr");
            drop(unused);
            let endpoint = reqwest::Url::parse(&format!("http://{addr}/rpc")).expect("url");
            kinds.push(
                test_domain_transport(endpoint)
                    .dispatch(domain_request("identity"))
                    .await
                    .expect_err("connection refused")
                    .kind(),
            );
            kinds
        });
        assert_eq!(
            kinds,
            [
                HttpContractTransportErrorKind::ResponseTooLarge,
                HttpContractTransportErrorKind::InvalidResponse,
                HttpContractTransportErrorKind::Dispatch,
            ]
        );
        let clients: Vec<_> = spans.iter().filter(|span| span.kind == "client").collect();
        assert_eq!(
            clients.len(),
            3,
            "one CLIENT span per send; captured={:?}",
            spans.iter().map(|span| &span.name).collect::<Vec<_>>()
        );
        let mut error_types = clients
            .iter()
            .map(|span| {
                span.attributes
                    .get("error.type")
                    .expect("closed error type")
                    .as_str()
            })
            .collect::<Vec<_>>();
        error_types.sort_unstable();
        assert_eq!(
            error_types,
            ["dispatch", "invalid_response", "response_too_large"]
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn domain_transport_logical_dispatch_parents_remote_client_and_inproc_emits_no_client() {
        struct FixedClock;
        impl diport::Clock for FixedClock {
            fn now(&self) -> std::time::SystemTime {
                std::time::SystemTime::UNIX_EPOCH
            }
        }
        struct InProc;
        impl HttpContractTransport for InProc {
            fn dispatch(
                &self,
                _request: HttpContractRequest,
            ) -> std::pin::Pin<
                Box<
                    dyn Future<Output = Result<HttpContractResponse, HttpContractTransportError>>
                        + Send
                        + '_,
                >,
            > {
                Box::pin(async { HttpContractResponse::try_new(204, Vec::new()) })
            }
        }

        let (_, remote_spans) = tracewiretest::with_test_span_capture(async {
            let server = HttpServer::serve(
                "logical-parent",
                "127.0.0.1:0".parse().expect("addr"),
                make_domain_transport_svc(),
            )
            .await
            .expect("serve");
            let endpoint =
                reqwest::Url::parse(&format!("http://{}/rpc", server.local_addr())).expect("url");
            let transport = distributed::InstrumentedHttpContractTransport::new(
                test_domain_transport(endpoint),
                distributed::TransportMode::Remote,
                Box::new(FixedClock),
            );
            transport
                .dispatch(domain_request("identity"))
                .await
                .expect("dispatch");
            server.shutdown().await.expect("shutdown");
        });
        let logical = remote_spans
            .iter()
            .find(|span| span.name == "domain_transport.dispatch")
            .expect("logical span");
        let client = remote_spans
            .iter()
            .find(|span| span.kind == "client")
            .expect("client span");
        assert_eq!(client.parent_span_id, logical.span_id);

        let (_, inproc_spans) = tracewiretest::with_test_span_capture(async {
            distributed::InstrumentedHttpContractTransport::new(
                InProc,
                distributed::TransportMode::InProc,
                Box::new(FixedClock),
            )
            .dispatch(domain_request("identity"))
            .await
            .expect("inproc dispatch");
        });
        assert!(inproc_spans.iter().all(|span| span.kind != "client"));
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
            HttpContractTransportErrorKind::ResponseTooLarge
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
            HttpContractTransportErrorKind::ResponseTooLarge
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
    async fn domain_transport_maps_malformed_response_head_to_invalid_response() {
        for response in [
            b"NOT HTTP\r\n\r\n".to_vec(),
            b"HTTP/1.1 200 OK\r\nmalformed header\r\n\r\n".to_vec(),
        ] {
            let (transport, server) = canned_domain_transport(response, false).await;
            let error = transport
                .dispatch(domain_request("identity"))
                .await
                .expect_err("malformed response head is invalid response");
            assert_eq!(
                error.kind(),
                HttpContractTransportErrorKind::InvalidResponse
            );
            server.await.expect("canned server completes");
        }
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
            secure::DomainHttpEndpoint::parse("https://identity.internal/rpc")
                .expect("valid endpoint"),
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
                    secure::DomainHttpEndpoint::parse("https://identity.internal/rpc")
                        .expect("valid endpoint"),
                    outbound_policy(),
                )
                .expect("identity target"),
                DomainHttpTargetConfig::new(
                    "audit",
                    secure::DomainHttpEndpoint::parse("https://audit.internal/rpc")
                        .expect("valid endpoint"),
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
                            Ok(ObservedHttpClient::plaintext_for_test())
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
    async fn one_service_clone_gets_distinct_plaintext_and_mtls_hsts_policies() {
        let ca = test_ca();
        let client_id = "spiffe://example.org/ns/rss/sa/internal";
        let mtls = test_mtls_config(&ca, client_id);
        let client_cert = leaf_cert(&ca, None, client_id, ExtendedKeyUsagePurpose::ClientAuth);
        let shared = make_hsts_svc();
        let plaintext_bound = HttpServer::bind(
            "http-plaintext-shared-hsts",
            "127.0.0.1:0".parse().expect("ephemeral address"),
        )
        .await
        .expect("bind plaintext");
        let plaintext_local = plaintext_bound.local_addr();
        let plaintext_server = plaintext_bound.serve(shared.clone(), CancellationToken::new());
        let plaintext_response = raw_get_response(plaintext_local, "/ok").await;
        assert!(
            !plaintext_response
                .to_ascii_lowercase()
                .contains("strict-transport-security:"),
            "plaintext clone must strip HSTS: {plaintext_response}"
        );

        let mtls_bound = HttpServer::bind(
            "http-mtls-hsts",
            "127.0.0.1:0".parse().expect("ephemeral address"),
        )
        .await
        .expect("bind");
        let mtls_local = mtls_bound.local_addr();
        let mtls_server = mtls_bound.serve_mtls(shared, mtls, CancellationToken::new());

        let response =
            tls_get_response_with_timeout(mtls_local, "/ok", client_config(&ca, Some(client_cert)))
                .await
                .expect("trusted mTLS request");
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(
            response
                .to_ascii_lowercase()
                .contains("strict-transport-security: max-age=63072000; includesubdomains"),
            "mTLS must retain inner HSTS: {response}"
        );

        assert!(plaintext_server.shutdown().await.is_ok());
        assert!(mtls_server.shutdown().await.is_ok());
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
