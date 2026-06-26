//! httpd adapter —— HTTP 传输 adapter（#1320 运行时入口 Join）。
//!
//! 单一 `HttpServer`：bind `TcpListener` → `axum::serve` 已认证 router 的 `IntoMakeService` →
//! serve task 监听注入的 [`CancellationToken`] 优雅关停；`impl diport::ManagedResource` 经
//! `cancel()` + await JoinHandle 收敛。**精确对标 `adapters/grpc` 的 `GrpcServer`**（transport=adapter）。
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
//! # 安全：plaintext（TLS 在 listener 外终结 / 后续）
//!
//! 本切片 listener 为 plaintext HTTP——生产经 ingress / sidecar 终结 TLS。listener 级 TLS（rustls+ring）
//! 是 follow-up（与 pg/vault TLS 同批），不在 #1320 范围。`bind` 的地址由组合根经 env 解析注入
//! （`RSS_<LISTENER>_LISTEN_ADDR`），缺配在组合根 fail-fast。
//!
//! crate 保持 `forbid(unsafe_code)`（继承 workspace lints）。
//! ref: tokio-rs/axum axum/src/serve/mod.rs@v0.8.9（`axum::serve(TcpListener, make_service).with_graceful_shutdown`）
//! ref: 内部对标 adapters/grpc/src/lib.rs（`GrpcServer` = ManagedResource + CancellationToken funnel）

use std::net::SocketAddr;

use axum::Router;
use axum::routing::IntoMakeService;
use diport::{ManagedResource, ShutdownError};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

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
    pub fn serve(self, svc: IntoMakeService<Router>, token: CancellationToken) -> HttpServer {
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
        svc: IntoMakeService<Router>,
        token: CancellationToken,
    ) -> Result<Self, HttpServeError> {
        Ok(Self::bind(name, addr).await?.serve(svc, token))
    }

    /// detached 便捷构造（内部 token，不接外部 ShutdownStack 广播）：测试 / 简单 caller 用。
    /// `shutdown()` 经内部 token 触发退出。
    pub async fn serve(
        name: &'static str,
        addr: SocketAddr,
        svc: IntoMakeService<Router>,
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
    use axum::routing::get;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpStream;

    /// 极简 router → IntoMakeService，挂一个 GET /healthz 恒 200。
    fn make_svc() -> IntoMakeService<Router> {
        Router::new()
            .route("/healthz", get(|| async { "ok" }))
            .into_make_service()
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
}
