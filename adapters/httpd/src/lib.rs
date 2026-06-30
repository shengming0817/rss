//! httpd adapter —— HTTP 传输 adapter（#1320 运行时入口 Join）。
//!
//! 单一 `HttpServer`：bind `TcpListener` → `axum::serve` 已认证 router 的
//! `IntoMakeServiceWithConnectInfo<Router, SocketAddr>` →
//! serve task 监听注入的 [`CancellationToken`] 优雅关停；`impl diport::ManagedResource` 经
//! `cancel()` + await JoinHandle 收敛。**精确对标 `adapters/grpc` 的 `GrpcServer`**（transport=adapter）。
//!
//! ConnectInfo 贯通（#1106）：`into_make_service_with_connect_info::<SocketAddr>()` 在 bind 时注入
//! `ConnectInfo<SocketAddr>` extension，供 `httpserve::rate_limit` 中间件读 peer IP 做 per-IP keyed 限流。
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

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::Router;
use axum::extract::connect_info::IntoMakeServiceWithConnectInfo;
use axum::serve::{IncomingStream, Listener, ListenerExt};
use diport::{ManagedResource, ShutdownError};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_rustls::server::TlsStream;
use tokio_util::sync::CancellationToken;
use tower::Service;

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
    mtls_source: Option<spiffe::X509Source>,
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

/// mTLS acceptor backed by SPIRE Workload API X.509-SVID rotation.
#[derive(Clone)]
pub struct MtlsServerConfig {
    source: Option<spiffe::X509Source>,
    acceptor: spiffe_rustls_tokio::TlsAcceptor,
    allow_set: authn::MtlsAllowSet,
}

impl MtlsServerConfig {
    /// Build from SPIRE Agent Workload API. `endpoint=None` uses `SPIFFE_ENDPOINT_SOCKET`.
    pub async fn from_spire(
        allow_set: authn::MtlsAllowSet,
        endpoint: Option<&str>,
    ) -> Result<Self, HttpServeError> {
        Self::from_spire_with_initial_sync_timeout(allow_set, endpoint, Duration::from_secs(5))
            .await
    }

    async fn from_spire_with_initial_sync_timeout(
        allow_set: authn::MtlsAllowSet,
        endpoint: Option<&str>,
        initial_sync_timeout: Duration,
    ) -> Result<Self, HttpServeError> {
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
        Ok(Self {
            source: Some(source),
            acceptor: spiffe_rustls_tokio::TlsAcceptor::new(std::sync::Arc::new(server_config)),
            allow_set,
        })
    }

    /// Runtime readiness signal for readyz wiring.
    pub fn is_healthy(&self) -> bool {
        self.source
            .as_ref()
            .is_some_and(spiffe::X509Source::is_healthy)
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
    pub fn serve(
        self,
        svc: IntoMakeServiceWithConnectInfo<Router, SocketAddr>,
        token: CancellationToken,
    ) -> HttpServer {
        let serve_token = token.clone();
        let listener = self.listener;
        let handle = tokio::spawn(async move {
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
            mtls_source: None,
        }
    }

    /// Spawn an mTLS HTTP serve task. Each accepted request receives both
    /// `ConnectInfo<SocketAddr>` and `authn::VerifiedMtlsPeer` extensions.
    pub fn serve_mtls(
        self,
        svc: IntoMakeServiceWithConnectInfo<Router, SocketAddr>,
        mtls: MtlsServerConfig,
        token: CancellationToken,
    ) -> HttpServer {
        let serve_token = token.clone();
        let listener = MtlsListener {
            listener: self.listener,
            local_addr: self.local_addr,
            config: mtls.clone(),
        };
        let handle = tokio::spawn(async move {
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
            mtls_source: mtls.source,
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
        svc: IntoMakeServiceWithConnectInfo<Router, SocketAddr>,
        token: CancellationToken,
    ) -> Result<Self, HttpServeError> {
        Ok(Self::bind(name, addr).await?.serve(svc, token))
    }

    /// Convenience constructor for mTLS listener.
    pub async fn serve_mtls_with_token(
        name: &'static str,
        addr: SocketAddr,
        svc: IntoMakeServiceWithConnectInfo<Router, SocketAddr>,
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
        svc: IntoMakeServiceWithConnectInfo<Router, SocketAddr>,
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
        if let Some(source) = &self.mtls_source {
            source
                .shutdown_configured()
                .await
                .map_err(ShutdownError::new)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use axum::routing::get;
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName,
        ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType,
    };
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use rustls::{ClientConfig, RootCertStore, ServerConfig};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;

    /// 极简 router → IntoMakeServiceWithConnectInfo（注入 ConnectInfo<SocketAddr>），挂一个 GET /healthz 恒 200。
    fn make_svc() -> IntoMakeServiceWithConnectInfo<Router, std::net::SocketAddr> {
        Router::new()
            .route("/healthz", get(|| async { "ok" }))
            .into_make_service_with_connect_info::<std::net::SocketAddr>()
    }

    fn make_mtls_svc() -> IntoMakeServiceWithConnectInfo<Router, std::net::SocketAddr> {
        Router::new()
            .route(
                "/mtls-peer",
                get(
                    |axum::extract::Extension(peer): axum::extract::Extension<
                        authn::VerifiedMtlsPeer,
                    >| async move { peer.spiffe_id().as_str().to_owned() },
                ),
            )
            .into_make_service_with_connect_info::<std::net::SocketAddr>()
    }

    /// 绑 `127.0.0.1:0` ephemeral → 真 socket 上发 HTTP/1.1 GET，读回状态行（raw，无 reqwest dep）。
    // 测试断言用 expect：item-level carve-out（error-handling.md §Carve-out）。
    #[allow(clippy::expect_used)]
    async fn raw_get_status_line(addr: SocketAddr, path: &str) -> String {
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
        let text = String::from_utf8_lossy(&buf);
        text.lines().next().unwrap_or_default().to_owned()
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
