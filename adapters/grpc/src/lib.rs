//! grpc adapter —— RSS workspace（W 阶段真身，#1011 gRPC 切片）。
//!
//! 单一 `GrpcServer`：
//! - 始终 `impl diport::ManagedResource`（已冻结，ADAPTER-PORT-FREEZE-02）。
//! - `backend` feature 开时：tonic 0.14 plaintext gRPC server + 标准健康服务（tonic-health）+ graceful shutdown。
//!
//! feature-off（default build）：空壳编译、freeze smoke 类型断言仍有效；不引入 tonic 依赖。
//! feature-on（`--features backend`）：`serve_with_token(addr, token)` bind TcpListener → 托管 tonic Router
//! （health_service）→ serve task 监听注入的 [`CancellationToken`]；`shutdown()` `cancel()` token + await
//! JoinHandle 收敛。
//!
//! # graceful shutdown：经 ShutdownStack token funnel
//!
//! 后台 serve task 的关闭信号是组合根经 `bootstrap::ShutdownStack::register_with_token` 注入的 child
//! [`CancellationToken`]（SHUTDOWN-TOKEN-FUNNEL-01）：阶段 1 广播 `cancel()` 即 serve 退出，阶段 2
//! `shutdown()` await task 收敛。`serve(addr)` 是 detached 便捷构造（内部 token，不接外部广播；测试 /
//! 简单 caller 用）。**不**自建 oneshot 绕过 funnel。
//!
//! # 安全：plaintext fail-closed
//!
//! 本切片 plaintext（无 TLS/auth）。`serve_with_token` **fail-closed**：拒绝绑定非 loopback 地址（返回
//! [`GrpcServeError::NonLoopbackPlaintext`]），安全边界落在类型/Result，不靠注释。生产对外暴露须等 TLS
//! 三模式落地（P2-6）；TLS 落地前确需非 loopback（如容器内跨 pod 明文）只能经显式
//! `serve_insecure_with_token` opt-in（对标 vault `new` / `new_allow_http`）。
//! 见 docs/migration-from-gocell/202606240130-006-gocell-rss-capability-gaps.md P2-6。
//!
//! # gRPC health 语义：liveness-only
//!
//! overall service `""` = SERVING 是 gRPC 健康协议的 server **overall liveness**（进程已起、可服务）——
//! 标准 gRPC liveness 探针查 `""`，故保留。本 scaffold **不**承载 per-service readiness：未注册的业务
//! service 名 Check 返回 NOT_FOUND（不被误报为 SERVING，见 `health_does_not_advertise_unknown_service`
//! 测试锁定）。readiness 聚合（probe 驱动）为 follow-up（P2-6）；**k8s readiness probe 应对接 HTTP
//! HealthListener，不要用本 gRPC `""` 端点判 readiness**。
//!
//! crate 保持 `forbid(unsafe_code)`（继承 workspace lints，不 invoke dynosaur 宏）。
//! ref: hyperium/tonic examples/src/health/server.rs@master

use diport::{ManagedResource, ShutdownError};

#[cfg(feature = "backend")]
type ServeJoinHandle = tokio::task::JoinHandle<Result<(), tonic::transport::Error>>;

/// gRPC 传输 adapter。
///
/// `backend` feature 关时为空壳（仅供 freeze smoke 类型断言）；
/// 开时持有 bind 成功的 TCP listener 地址、graceful-shutdown 的 [`CancellationToken`] 与 serve 任务句柄。
pub struct GrpcServer {
    #[cfg(feature = "backend")]
    local_addr: std::net::SocketAddr,
    /// 驱动 serve task 退出的 token：组合根经 funnel 注入（或 `serve` 的内部 detached token）。
    /// `shutdown()` `cancel()` 它触发 graceful 退出（幂等：阶段 1 广播已 cancel 则 no-op）。
    #[cfg(feature = "backend")]
    token: tokio_util::sync::CancellationToken,
    #[cfg(feature = "backend")]
    handle: tokio::sync::Mutex<Option<ServeJoinHandle>>,
}

/// gRPC server 启动失败（构造期 fail-fast，不静默 noop）。
///
/// message 为 `&'static str` const literal，无 runtime 数据、无 PII（error-handling.md）。
#[cfg(feature = "backend")]
#[derive(Debug, thiserror::Error)]
pub enum GrpcServeError {
    /// TCP bind 失败（端口占用 / 权限不足 / 非法地址）。
    #[error("grpc server bind failed")]
    Bind(#[source] std::io::Error),
    /// listener local_addr 读回失败（bind 后内核返回 EBADF / 类似）。
    #[error("grpc server local addr unavailable")]
    LocalAddr(#[source] std::io::Error),
    /// plaintext scaffold fail-closed 拒绝绑定非 loopback 地址（TLS 落地前用 `serve_insecure_*` 显式 opt-in）。
    #[error(
        "grpc plaintext server refused a non-loopback bind address; use serve_insecure_* until TLS lands"
    )]
    NonLoopbackPlaintext,
}

#[cfg(feature = "backend")]
impl GrpcServer {
    /// 启动 plaintext gRPC server（托管标准健康服务），serve task 监听注入的 `token`。
    ///
    /// 这是**生产路径**：组合根经 `bootstrap::ShutdownStack::register_with_token` 注入 child token，
    /// 阶段 1 关闭广播 `cancel()` 即触发 serve 退出（SHUTDOWN-TOKEN-FUNNEL-01）。
    ///
    /// **fail-closed**：拒绝非 loopback 地址（plaintext 不对外，见 [`GrpcServeError::NonLoopbackPlaintext`]）。
    /// **fail-fast**：bind 失败即 `Err`，不延迟到首次 RPC。传 `"127.0.0.1:0"` 让内核分配 ephemeral 端口，
    /// 经 [`local_addr`](Self::local_addr) 读回。
    pub async fn serve_with_token(
        addr: std::net::SocketAddr,
        token: tokio_util::sync::CancellationToken,
    ) -> Result<Self, GrpcServeError> {
        Self::spawn(addr, token, false).await
    }

    /// 同 [`serve_with_token`](Self::serve_with_token)，但**显式允许非 loopback** plaintext 绑定。
    ///
    /// TLS 三模式落地前的临时 opt-in（如容器内明文 sidecar）；命名即声明 insecure，杜绝静默对外暴露
    /// （对标 vault `new_allow_http`）。生产应等 TLS（P2-6）。
    pub async fn serve_insecure_with_token(
        addr: std::net::SocketAddr,
        token: tokio_util::sync::CancellationToken,
    ) -> Result<Self, GrpcServeError> {
        Self::spawn(addr, token, true).await
    }

    /// detached 便捷构造（内部 token，不接外部 ShutdownStack 广播）：测试 / 简单 caller 用。
    /// `shutdown()` 经内部 token 触发退出。fail-closed 同 [`serve_with_token`](Self::serve_with_token)。
    pub async fn serve(addr: std::net::SocketAddr) -> Result<Self, GrpcServeError> {
        Self::serve_with_token(addr, tokio_util::sync::CancellationToken::new()).await
    }

    /// 共享实现：可选放行非 loopback。fail-closed 检查在 **bind 之前**（非 loopback 时根本不开 socket）。
    async fn spawn(
        addr: std::net::SocketAddr,
        token: tokio_util::sync::CancellationToken,
        allow_non_loopback: bool,
    ) -> Result<Self, GrpcServeError> {
        reject_non_loopback_plaintext(addr, allow_non_loopback)?;
        let (listener, local_addr) = bind_listener(addr).await?;
        warn_non_loopback_insecure_opt_in(local_addr);
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);

        let (reporter, health_service) = tonic_health::server::health_reporter();
        // overall service ("") = SERVING：gRPC 协议的 server overall **liveness**（进程已起、可服务）。
        // 非 readiness——未注册的业务 service Check 返回 NOT_FOUND（见 crate doc § health 语义）。
        reporter
            .set_service_status("", tonic_health::ServingStatus::Serving)
            .await;

        let serve_token = token.clone();
        let handle = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(health_service)
                .serve_with_incoming_shutdown(incoming, async move {
                    // 关闭信号 = 注入 token 的 cancel（阶段 1 广播 / 内部 detached cancel）。
                    serve_token.cancelled().await;
                })
                .await
        });

        tracing::info!(addr = %local_addr, "grpc server started");

        Ok(Self {
            local_addr,
            token,
            handle: tokio::sync::Mutex::new(Some(handle)),
        })
    }

    /// 返回 server 实际绑定的地址（含内核分配的 ephemeral 端口）。
    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.local_addr
    }

    async fn shutdown_backend(&self) -> Result<(), ShutdownError> {
        // 触发 graceful 退出：cancel token（幂等——若 ShutdownStack 阶段 1 已 cancel 则 no-op）。
        self.token.cancel();
        if let Some(handle) = self.handle.lock().await.take() {
            return map_serve_join_result(self.name(), handle.await);
        }
        Ok(())
    }
}

#[cfg(feature = "backend")]
fn reject_non_loopback_plaintext(
    addr: std::net::SocketAddr,
    allow_non_loopback: bool,
) -> Result<(), GrpcServeError> {
    if allow_non_loopback || addr.ip().is_loopback() {
        return Ok(());
    }
    Err(GrpcServeError::NonLoopbackPlaintext)
}

#[cfg(feature = "backend")]
async fn bind_listener(
    addr: std::net::SocketAddr,
) -> Result<(tokio::net::TcpListener, std::net::SocketAddr), GrpcServeError> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(GrpcServeError::Bind)?;
    let local_addr = listener.local_addr().map_err(GrpcServeError::LocalAddr)?;
    Ok((listener, local_addr))
}

#[cfg(feature = "backend")]
fn warn_non_loopback_insecure_opt_in(local_addr: std::net::SocketAddr) {
    if local_addr.ip().is_loopback() {
        return;
    }
    // 只有经 serve_insecure_* opt-in 才到这；warn 让明文对外在 ops 日志可见。
    tracing::warn!(
        addr = %local_addr,
        "grpc plaintext server bound to non-loopback address via insecure opt-in; TLS deferred (P2-6)"
    );
}

#[cfg(feature = "backend")]
fn map_serve_join_result(
    name: &str,
    result: Result<Result<(), tonic::transport::Error>, tokio::task::JoinError>,
) -> Result<(), ShutdownError> {
    match result {
        Ok(transport) => map_transport_shutdown_result(name, transport),
        Err(e) => serve_join_shutdown_error(name, e),
    }
}

#[cfg(feature = "backend")]
fn map_transport_shutdown_result(
    name: &str,
    result: Result<(), tonic::transport::Error>,
) -> Result<(), ShutdownError> {
    if let Err(e) = result {
        return transport_shutdown_error(name, e);
    }
    tracing::info!(name, "grpc server shutdown complete");
    Ok(())
}

#[cfg(feature = "backend")]
fn transport_shutdown_error(name: &str, err: tonic::transport::Error) -> Result<(), ShutdownError> {
    tracing::warn!(name, err = %err, "grpc server transport error on shutdown");
    Err(ShutdownError::new(err))
}

#[cfg(feature = "backend")]
fn serve_join_shutdown_error(name: &str, err: tokio::task::JoinError) -> Result<(), ShutdownError> {
    tracing::error!(name, err = %err, "grpc server task join error on shutdown");
    Err(ShutdownError::new(err))
}

impl ManagedResource for GrpcServer {
    fn name(&self) -> &str {
        "grpc"
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        #[cfg(feature = "backend")]
        {
            self.shutdown_backend().await?;
        }
        // reason（feature-off）: 空壳 GrpcServer 无任何后台资源，shutdown 为 noop，直接 Ok(())。
        Ok(())
    }
}

#[cfg(test)]
mod smoke {
    //! build smoke：编译期断言 sealed-marker 已 impl 冻结的 diport DI port trait
    //! （PhantomData 绑定检查，不构造、不执行 body）。
    //! INVARIANT: ADAPTER-PORT-FREEZE-02 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" }—— sealed-marker impl 冻结的 diport DI port trait；去掉任一 impl 即编译失败（anti-vacuity）。
    use core::marker::PhantomData;

    fn assert_managed_resource<T: diport::ManagedResource>(_: PhantomData<T>) {}

    #[test]
    fn impls_frozen_ports() {
        assert_managed_resource(PhantomData::<super::GrpcServer>);
    }
}

#[cfg(all(test, feature = "backend"))]
mod backend_tests {
    //! gRPC server 行为矩阵（tonic 0.14 + tonic-health，plaintext）：
    //! name / roundtrip / shutdown（idempotent + via token）/ fail-closed 非 loopback / liveness-only。
    use super::GrpcServer;
    use diport::ManagedResource;
    use tokio_util::sync::CancellationToken;

    // parse_addr：测试内 SocketAddr 字面量解析，静态字符串必然成功，item-level expect carve-out。
    #[allow(clippy::expect_used)]
    fn parse_addr(s: &str) -> std::net::SocketAddr {
        s.parse().expect("valid socket addr literal")
    }

    #[tokio::test]
    #[allow(clippy::expect_used)] // reason: 测试断言，失败即 panic 定位问题（error-handling §Carve-out item-level）
    async fn name_is_grpc() {
        let server = GrpcServer::serve(parse_addr("127.0.0.1:0"))
            .await
            .expect("serve ok");
        assert_eq!(server.name(), "grpc");
        server.shutdown().await.expect("shutdown ok");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)] // reason: 测试断言，期望值明确
    async fn health_check_roundtrip() {
        let server = GrpcServer::serve(parse_addr("127.0.0.1:0"))
            .await
            .expect("serve ok");
        let local_addr = server.local_addr();

        // overall "" Check 返回 SERVING（liveness）。
        let mut client = health_client(local_addr).await;
        let resp = client
            .check(tonic_health::pb::HealthCheckRequest {
                service: String::new(),
            })
            .await
            .expect("health check ok");
        assert_eq!(
            resp.into_inner().status,
            tonic_health::pb::health_check_response::ServingStatus::Serving as i32,
            "overall \"\" expected SERVING (liveness)"
        );

        server.shutdown().await.expect("shutdown ok");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)] // reason: 测试断言（F3：readiness 不被误报）
    async fn health_does_not_advertise_unknown_service() {
        // 未注册的业务 service 名 Check 须返回 NOT_FOUND——证明 scaffold 只报 overall liveness、
        // 不把任意 service 误报为 SERVING（readiness 不被冒充）。
        let server = GrpcServer::serve(parse_addr("127.0.0.1:0"))
            .await
            .expect("serve ok");
        let mut client = health_client(server.local_addr()).await;
        let result = client
            .check(tonic_health::pb::HealthCheckRequest {
                service: "rss.bogus.Unregistered".to_string(),
            })
            .await;
        let status = result.expect_err("unknown service must not be advertised as SERVING");
        assert_eq!(
            status.code(),
            tonic::Code::NotFound,
            "unknown service Check expected NOT_FOUND, got {status:?}"
        );
        server.shutdown().await.expect("shutdown ok");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)] // reason: 测试断言
    async fn shutdown_is_ok_and_converges() {
        let server = GrpcServer::serve(parse_addr("127.0.0.1:0"))
            .await
            .expect("serve ok");
        server.shutdown().await.expect("shutdown returns Ok");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)] // reason: 测试断言
    async fn shutdown_is_idempotent() {
        // token.cancel() 幂等 + handle take-once：连续两次 shutdown 均 Ok，不 panic / 不 hang。
        let server = GrpcServer::serve(parse_addr("127.0.0.1:0"))
            .await
            .expect("serve ok");
        server.shutdown().await.expect("first shutdown ok");
        server
            .shutdown()
            .await
            .expect("second shutdown ok (idempotent)");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)] // reason: 测试断言（F2：token funnel 阶段 1 广播即 serve 退出）
    async fn shutdown_via_injected_token_cancel() {
        // 模拟 ShutdownStack 阶段 1：cancel 注入的 token → serve task 自行退出；shutdown() await 收敛。
        let token = CancellationToken::new();
        let server = GrpcServer::serve_with_token(parse_addr("127.0.0.1:0"), token.clone())
            .await
            .expect("serve ok");
        token.cancel(); // 阶段 1 广播（在 shutdown() 之前）
        server
            .shutdown()
            .await
            .expect("shutdown converges after token cancel");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)] // reason: 测试断言（F1：fail-closed 非 loopback）
    async fn serve_rejects_non_loopback_plaintext() {
        // 非 loopback（0.0.0.0）plaintext → fail-closed，bind 前即 Err，不开 socket。
        let result = GrpcServer::serve(parse_addr("0.0.0.0:0")).await;
        assert!(
            matches!(result, Err(super::GrpcServeError::NonLoopbackPlaintext)),
            "non-loopback plaintext must fail-closed"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)] // reason: 测试断言（F1：显式 insecure opt-in 放行非 loopback）
    async fn serve_insecure_allows_non_loopback() {
        let token = CancellationToken::new();
        let server = GrpcServer::serve_insecure_with_token(parse_addr("0.0.0.0:0"), token)
            .await
            .expect("insecure opt-in allows non-loopback");
        server.shutdown().await.expect("shutdown ok");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)] // reason: 测试断言
    async fn serve_fails_fast_on_occupied_port() {
        let server = GrpcServer::serve(parse_addr("127.0.0.1:0"))
            .await
            .expect("first serve ok");
        let occupied = server.local_addr();

        // 第二次 bind 同一已占用端口 → GrpcServeError::Bind（fail-fast）。
        // 取 `.err()`（GrpcServeError: Debug）断言——GrpcServer 不需要 Debug。
        let err = GrpcServer::serve(occupied).await.err();
        assert!(
            matches!(err, Some(super::GrpcServeError::Bind(_))),
            "serve on occupied port must fail-fast, got {err:?}"
        );

        server.shutdown().await.expect("shutdown ok");
    }

    /// 连一个 gRPC health client 到 `addr`（plaintext channel）。
    #[allow(clippy::expect_used)] // reason: 测试 helper，连接失败即 panic 定位
    async fn health_client(
        addr: std::net::SocketAddr,
    ) -> tonic_health::pb::health_client::HealthClient<tonic::transport::Channel> {
        let channel = tonic::transport::Channel::from_shared(format!("http://{addr}"))
            .expect("valid uri")
            .connect()
            .await
            .expect("channel connect ok");
        tonic_health::pb::health_client::HealthClient::new(channel)
    }
}
