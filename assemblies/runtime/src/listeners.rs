//! Runtime health listener and listener bind-address policy.

use crate::infra::plaintext_endpoint_policy_from;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::Context as _;
use axum::http::Method;
use primitives::{AuthPlan, AuthScheme, ListenerKind};
use secure::PlaintextEndpointPolicy;

// ── Health listener（框架/组合根归属：healthz + readyz）─────────────────────────────────────────

/// Health listener 路由组前缀（liveness/readiness 在专用 listener 上；operator 配 k8s probe 路径指向此前缀下）。
const HEALTH_ROUTE_PREFIX: &str = "/health/v1";
/// liveness 端点契约 ID（框架归属基础设施探针，非域 wire 契约）。
const HEALTHZ_CONTRACT_ID: &str = "framework.healthz";
/// readiness 端点契约 ID（框架归属）。
const READYZ_CONTRACT_ID: &str = "framework.readyz";
/// `/metrics` scrape 端点契约 ID（框架归属基础设施导出，非域 wire 契约——同 healthz/readyz 为 inline 常量，
/// 无 `contracts/` 条目 / `frameworkContracts` 声明）。
const METRICS_CONTRACT_ID: &str = "framework.metrics";

/// 构造 Health listener 的已认证路由（`/health/v1/healthz` liveness + `/health/v1/readyz` readiness）。
///
/// Health 是**框架/组合根**归属：域 crate 不声明 health 路由组，组合根在此经公开 funnel
/// （`UnfinalizedRoutes::empty().nest_group::<Health>` → `finalize_auth`）挂载——产物仍是 `AuthenticatedRoutes`
/// （ROUTE-AUTH-FUNNEL：health router 也经 finalize_auth + request_id/correlation 封口；trace 由
/// `httpserve` 的 listener policy 对 Health 禁用，避免 probe/scrape span 噪声）。
/// `NoAuth` plan（Health listener 无验签桥）。readyz handler 闭包持 `Arc<HealthReporter>`（`Send + Sync`，
/// 整体非 `Sync` 的 `Registry` 无法进 handler）每请求 `report`（worst-of 聚合所有已注册探针，含 `configs_ready`）。
///
/// `metrics` 是组合根注入的 `Arc<dyn diport::MetricsExporter>`（生产 = Prometheus，测试 = 替身）——`/metrics`
/// scrape handler 每请求 `render()` 取 exposition body。**必填**（非 `Option`/silent-noop，runtime-api Option 范式）。
///
/// **scrape 路径**：metrics 与 healthz/readyz 同组挂在 [`HEALTH_ROUTE_PREFIX`] 下，完整路径
/// `/health/v1/metrics`（非 Prometheus 默认 `/metrics`）——运维须在 scrape target 显式配
/// `metrics_path: /health/v1/metrics`（否则默认 `/metrics` 抓取得 404、被记空抓取）。挂 Health listener（内部
/// 网络面）而非对外 Primary：scrape 流量与 health probe 同隔离，且非-Primary `Route` 类型层无法降级 Public。
///
/// `pub`：供冒烟 e2e（`tests/runtime_serve_e2e.rs`）经真实 socket 绑定验证 serve + readyz + `/metrics` + 优雅关停闭环。
pub fn health_listener(
    reporter: Arc<bootstrap::HealthReporter>,
    metrics: Arc<dyn diport::MetricsExporter>,
) -> anyhow::Result<(ListenerKind, httpserve::AuthenticatedRoutes)> {
    let routes = httpserve::UnfinalizedRoutes::empty()
        .nest_group::<httpserve::Health, core::convert::Infallible>(
            HEALTH_ROUTE_PREFIX,
            move |rb| {
                Ok(rb
                    .mount(
                        httpserve::Route {
                            method: Method::GET,
                            path: "/healthz",
                            contract_id: HEALTHZ_CONTRACT_ID,
                        },
                        httpserve::health::healthz(),
                    )
                    .mount(
                        httpserve::Route {
                            method: Method::GET,
                            path: "/readyz",
                            contract_id: READYZ_CONTRACT_ID,
                        },
                        httpserve::health::readyz(move || reporter.report()),
                    )
                    .mount(
                        // `/metrics` 在 Health listener（内部网络面）；非-Primary `Route` 无 opt-out 字段 ⇒ 不可降级 Public。
                        httpserve::Route {
                            method: Method::GET,
                            path: "/metrics",
                            contract_id: METRICS_CONTRACT_ID,
                        },
                        httpserve::health::metrics(move || metrics.render()),
                    ))
            },
        )
        .context("nest health route group")?;
    let plan =
        AuthPlan::new(ListenerKind::Health, AuthScheme::NoAuth).context("health auth plan")?;
    let authed = httpserve::finalize_auth(routes, plan).context("finalize_auth health")?;
    Ok((ListenerKind::Health, authed))
}

// ── listener bind 地址（per-listener env，缺配 fail-fast）─────────────────────────────────────────

pub(crate) const LISTENER_ALLOW_PLAINTEXT_ENV: &str = "RSS_LISTENER_ALLOW_PLAINTEXT";

/// listener → bind 地址 env 变量名（`RSS_<LISTENER>_LISTEN_ADDR`，值为 `host:port` SocketAddr 串）。
///
/// `ListenerKind` 为 `non_exhaustive`：未知 listener 无 env、fail-fast（绝不静默 bind 未知 listener）。
pub(crate) fn listener_addr_env(listener: ListenerKind) -> anyhow::Result<&'static str> {
    Ok(match listener {
        ListenerKind::Primary => "RSS_PRIMARY_LISTEN_ADDR",
        ListenerKind::Internal => "RSS_INTERNAL_LISTEN_ADDR",
        ListenerKind::Admin => "RSS_ADMIN_LISTEN_ADDR",
        ListenerKind::Health => "RSS_HEALTH_LISTEN_ADDR",
        other => {
            anyhow::bail!("listener {other:?} has no listen-addr env var (unknown ListenerKind)")
        }
    })
}

/// ShutdownStack 关闭日志的稳定 listener 名（区分多 listener）。
pub(crate) fn listener_name(listener: ListenerKind) -> &'static str {
    match listener {
        ListenerKind::Primary => "http-primary",
        ListenerKind::Internal => "http-internal",
        ListenerKind::Admin => "http-admin",
        ListenerKind::Health => "http-health",
        // ListenerKind non_exhaustive——未知 listener 用 fallback 名 + 配置期 warn 埋点（与 auth_scheme
        // 的未知 listener 处理一致）；实际 bind 时 listener_addr_env 已 fail-fast 拒未知 listener。
        _ => {
            tracing::warn!(listener = ?listener, "unknown ListenerKind; using fallback name 'http-unknown'");
            "http-unknown"
        }
    }
}

/// 由已解析的 listener auth scheme + `std::env` 解析 bind 地址。
///
/// Auth scheme 在 route finalize 阶段解析一次并随 `AssembledListener` 传入；这里只消费 resolved scheme，
/// 避免 bind policy 与 serve strategy 各自重新读 env 后漂移。
pub(crate) fn listener_addr_for_scheme(
    listener: ListenerKind,
    scheme: AuthScheme,
) -> anyhow::Result<SocketAddr> {
    // reason: composition-root startup policy compares operator-provided migration expiry with the
    // process clock. Domain logic still receives clocks by DI; this is env guard evaluation.
    #[allow(clippy::disallowed_methods)]
    let now = SystemTime::now();
    listener_addr_for_scheme_from(listener, scheme, |name| std::env::var(name).ok(), now)
}

pub(crate) fn listener_addr_for_scheme_from(
    listener: ListenerKind,
    scheme: AuthScheme,
    get: impl Fn(&str) -> Option<String>,
    now: SystemTime,
) -> anyhow::Result<SocketAddr> {
    let var = listener_addr_env(listener)?;
    let raw = get(var)
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {var} (listener has routes)"))?;
    let addr = raw
        .parse::<SocketAddr>()
        .with_context(|| format!("{var} must be a valid host:port SocketAddr: {raw}"))?;
    enforce_listener_plaintext_policy(listener, scheme, addr, &get, now)?;
    Ok(addr)
}

fn enforce_listener_plaintext_policy(
    listener: ListenerKind,
    scheme: AuthScheme,
    addr: SocketAddr,
    get: impl Fn(&str) -> Option<String>,
    _now: SystemTime,
) -> anyhow::Result<()> {
    if scheme == AuthScheme::Mtls {
        return Ok(());
    }
    let policy = plaintext_endpoint_policy_from(&get, LISTENER_ALLOW_PLAINTEXT_ENV)?;
    match policy {
        PlaintextEndpointPolicy::Deny => anyhow::bail!(
            "{LISTENER_ALLOW_PLAINTEXT_ENV} must explicitly allow plaintext listener {listener:?} at {addr}"
        ),
        PlaintextEndpointPolicy::AllowLoopback => {
            anyhow::ensure!(
                addr.ip().is_loopback(),
                "{LISTENER_ALLOW_PLAINTEXT_ENV}=true only allows loopback plaintext listener binds"
            );
        }
        PlaintextEndpointPolicy::AllowDevContainer => {
            anyhow::ensure!(
                addr.ip().is_loopback() || addr.ip().is_unspecified(),
                "{LISTENER_ALLOW_PLAINTEXT_ENV}=dev-container only allows loopback or wildcard demo listener binds"
            );
        }
    }
    enforce_internal_service_token_loopback_only(listener, scheme, addr)
}

fn enforce_internal_service_token_loopback_only(
    listener: ListenerKind,
    scheme: AuthScheme,
    addr: SocketAddr,
) -> anyhow::Result<()> {
    if listener != ListenerKind::Internal || scheme != AuthScheme::ServiceToken {
        return Ok(());
    }
    anyhow::ensure!(
        addr.ip().is_loopback(),
        "Internal service-token listener is local-test only; non-loopback Internal listener must use mTLS"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::{
        INTERNAL_AUTH_SCHEME_ENV, INTERNAL_AUTH_SCHEME_SERVICE_TOKEN, auth_scheme_from,
    };
    use crate::{CONFIGS_READY_PROBE_NAME, ConfigsReadyProbe};

    use std::time::Duration;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use postgres::PgDbReadiness;
    use primitives::{HealthCheck, HealthStatus, ProbeName};
    use tower::ServiceExt as _;

    #[allow(clippy::expect_used)]
    fn test_reporter() -> Arc<bootstrap::HealthReporter> {
        let mut reg = bootstrap::compose(&[]).expect("compose");
        Arc::new(reg.take_health_reporter())
    }

    #[derive(Clone)]
    struct FixedMetrics(&'static str);

    impl diport::MetricsExporter for FixedMetrics {
        fn render(&self) -> String {
            self.0.to_owned()
        }
    }

    fn noop_metrics() -> Arc<dyn diport::MetricsExporter> {
        Arc::new(FixedMetrics("# noop\n"))
    }

    fn listener_addr_from(
        listener: ListenerKind,
        get: impl Fn(&str) -> Option<String> + Copy,
    ) -> anyhow::Result<SocketAddr> {
        // reason: test compatibility helper for env-driven cases; production consumes the resolved scheme carrier.
        #[allow(clippy::disallowed_methods)]
        let now = SystemTime::now();
        listener_addr_from_at(listener, get, now)
    }

    fn listener_addr_from_at(
        listener: ListenerKind,
        get: impl Fn(&str) -> Option<String> + Copy,
        now: SystemTime,
    ) -> anyhow::Result<SocketAddr> {
        let scheme =
            auth_scheme_from(listener, get).context("resolve test listener auth scheme")?;
        listener_addr_for_scheme_from(listener, scheme, get, now)
    }

    /// 各标准 listener → 正确 env 变量名（per-listener `RSS_<LISTENER>_LISTEN_ADDR`）。
    #[test]
    #[allow(clippy::expect_used)]
    fn listener_addr_env_maps_each_listener() {
        assert_eq!(
            listener_addr_env(ListenerKind::Primary).expect("primary"),
            "RSS_PRIMARY_LISTEN_ADDR"
        );
        assert_eq!(
            listener_addr_env(ListenerKind::Internal).expect("internal"),
            "RSS_INTERNAL_LISTEN_ADDR"
        );
        assert_eq!(
            listener_addr_env(ListenerKind::Admin).expect("admin"),
            "RSS_ADMIN_LISTEN_ADDR"
        );
        assert_eq!(
            listener_addr_env(ListenerKind::Health).expect("health"),
            "RSS_HEALTH_LISTEN_ADDR"
        );
    }

    /// 有路由的 listener 缺 addr env → fail-fast，错误含 env 变量名（不静默 ready）。
    #[test]
    #[allow(clippy::expect_used)]
    fn listener_addr_missing_env_fails_fast() {
        let err = listener_addr_from(ListenerKind::Primary, |_| None).expect_err("missing addr");
        assert!(
            err.to_string().contains("RSS_PRIMARY_LISTEN_ADDR"),
            "error 含 env 变量名: {err}"
        );
    }

    /// addr env 值非法 SocketAddr → fail-fast，错误含 env 变量名。
    #[test]
    #[allow(clippy::expect_used)]
    fn listener_addr_invalid_value_fails_fast() {
        let err = listener_addr_from(ListenerKind::Health, |_| Some("not-an-addr".to_string()))
            .expect_err("invalid addr");
        assert!(
            err.to_string().contains("RSS_HEALTH_LISTEN_ADDR"),
            "含 env 名: {err}"
        );
    }

    /// 合法 `host:port` → 解析成功。
    #[test]
    #[allow(clippy::expect_used)]
    fn listener_addr_valid_value_parses() {
        let addr = listener_addr_from(ListenerKind::Primary, |name| match name {
            "RSS_PRIMARY_LISTEN_ADDR" => Some("0.0.0.0:8080".to_string()),
            LISTENER_ALLOW_PLAINTEXT_ENV => Some("dev-container".to_string()),
            _ => None,
        })
        .expect("valid dev-container listener addr");
        assert_eq!(addr.port(), 8080);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn listener_plaintext_default_rejects_loopback() {
        let err = listener_addr_from(ListenerKind::Health, |name| {
            (name == "RSS_HEALTH_LISTEN_ADDR").then(|| "127.0.0.1:8083".to_string())
        })
        .expect_err("plaintext listener needs explicit opt-in even on loopback");
        assert!(
            format!("{err:#}").contains(LISTENER_ALLOW_PLAINTEXT_ENV),
            "error must identify plaintext opt-in env: {err:#}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn listener_plaintext_default_rejects_non_loopback() {
        let err = listener_addr_from(ListenerKind::Primary, |name| {
            (name == "RSS_PRIMARY_LISTEN_ADDR").then(|| "0.0.0.0:8080".to_string())
        })
        .expect_err("non-loopback plaintext listener must fail closed by default");
        assert!(
            format!("{err:#}").contains(LISTENER_ALLOW_PLAINTEXT_ENV),
            "error must identify plaintext opt-in env: {err:#}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn listener_plaintext_true_allows_loopback_only() {
        let loopback = listener_addr_from(ListenerKind::Health, |name| match name {
            "RSS_HEALTH_LISTEN_ADDR" => Some("127.0.0.1:8083".to_string()),
            LISTENER_ALLOW_PLAINTEXT_ENV => Some("true".to_string()),
            _ => None,
        })
        .expect("explicit loopback opt-in should allow loopback bind");
        assert!(loopback.ip().is_loopback());

        let err = listener_addr_from(ListenerKind::Health, |name| match name {
            "RSS_HEALTH_LISTEN_ADDR" => Some("10.0.0.8:8083".to_string()),
            LISTENER_ALLOW_PLAINTEXT_ENV => Some("true".to_string()),
            _ => None,
        })
        .expect_err("loopback opt-in must reject fixed non-loopback addresses");
        assert!(format!("{err:#}").contains("loopback"), "{err:#}");
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn listener_plaintext_dev_container_allows_only_loopback_or_unspecified() {
        for raw in ["0.0.0.0:8080", "[::]:8080", "127.0.0.1:8080"] {
            let addr = listener_addr_from(ListenerKind::Primary, |name| match name {
                "RSS_PRIMARY_LISTEN_ADDR" => Some(raw.to_string()),
                LISTENER_ALLOW_PLAINTEXT_ENV => Some("dev-container".to_string()),
                _ => None,
            })
            .expect("dev-container policy allows compose wildcard and loopback binds");
            assert!(addr.ip().is_unspecified() || addr.ip().is_loopback());
        }

        let err = listener_addr_from(ListenerKind::Primary, |name| match name {
            "RSS_PRIMARY_LISTEN_ADDR" => Some("10.0.0.8:8080".to_string()),
            LISTENER_ALLOW_PLAINTEXT_ENV => Some("dev-container".to_string()),
            _ => None,
        })
        .expect_err("dev-container policy must not allow arbitrary non-loopback binds");
        assert!(
            format!("{err:#}").contains("dev-container"),
            "error should mention dev-container policy: {err:#}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn listener_plaintext_invalid_opt_in_fails_fast() {
        let err = listener_addr_from(ListenerKind::Health, |name| match name {
            "RSS_HEALTH_LISTEN_ADDR" => Some("127.0.0.1:8083".to_string()),
            LISTENER_ALLOW_PLAINTEXT_ENV => Some("enabled".to_string()),
            _ => None,
        })
        .expect_err("invalid plaintext opt-in should fail");
        assert!(
            format!("{err:#}").contains(LISTENER_ALLOW_PLAINTEXT_ENV),
            "error must identify opt-in env: {err:#}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn internal_mtls_listener_is_not_plaintext() {
        let addr = listener_addr_from(ListenerKind::Internal, |name| {
            (name == "RSS_INTERNAL_LISTEN_ADDR").then(|| "0.0.0.0:8081".to_string())
        })
        .expect("default Internal listener is mTLS and not gated as plaintext");
        assert!(addr.ip().is_unspecified());
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn listener_addr_policy_consumes_resolved_scheme_without_rereading_auth_env() {
        let addr = listener_addr_for_scheme_from(
            ListenerKind::Internal,
            AuthScheme::Mtls,
            |name| match name {
                "RSS_INTERNAL_LISTEN_ADDR" => Some("0.0.0.0:8081".to_string()),
                INTERNAL_AUTH_SCHEME_ENV => Some(INTERNAL_AUTH_SCHEME_SERVICE_TOKEN.to_string()),
                _ => None,
            },
            SystemTime::UNIX_EPOCH,
        )
        .expect("resolved mTLS scheme bypasses plaintext policy even if env later differs");
        assert!(addr.ip().is_unspecified());
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn internal_service_token_listener_is_plaintext_and_requires_opt_in() {
        let err = listener_addr_from(ListenerKind::Internal, |name| match name {
            "RSS_INTERNAL_LISTEN_ADDR" => Some("0.0.0.0:8081".to_string()),
            "RSS_INTERNAL_AUTH_SCHEME" => Some("service-token".to_string()),
            _ => None,
        })
        .expect_err("Internal service-token mode is plaintext and must be gated");
        assert!(
            format!("{err:#}").contains(LISTENER_ALLOW_PLAINTEXT_ENV),
            "error must identify plaintext opt-in env: {err:#}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn internal_service_token_non_loopback_rejects_even_with_legacy_migration_envs() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000);
        let err = listener_addr_from_at(
            ListenerKind::Internal,
            |name| match name {
                "RSS_INTERNAL_LISTEN_ADDR" => Some("0.0.0.0:8081".to_string()),
                INTERNAL_AUTH_SCHEME_ENV => Some(INTERNAL_AUTH_SCHEME_SERVICE_TOKEN.to_string()),
                LISTENER_ALLOW_PLAINTEXT_ENV => Some("dev-container".to_string()),
                "RSS_INTERNAL_SERVICE_TOKEN_MIGRATION_TICKET" => Some("SEC-1500".to_string()),
                "RSS_INTERNAL_SERVICE_TOKEN_MIGRATION_EXPIRES_AT_UNIX" => Some("3000".to_string()),
                _ => None,
            },
            now,
        )
        .expect_err("non-loopback Internal service-token is no longer a migration path");
        assert!(
            format!("{err:#}").contains("mTLS"),
            "error should require mTLS instead of migration envs: {err:#}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn internal_service_token_loopback_remains_local_test_path() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000);
        let addr = listener_addr_from_at(
            ListenerKind::Internal,
            |name| match name {
                "RSS_INTERNAL_LISTEN_ADDR" => Some("127.0.0.1:8081".to_string()),
                INTERNAL_AUTH_SCHEME_ENV => Some(INTERNAL_AUTH_SCHEME_SERVICE_TOKEN.to_string()),
                LISTENER_ALLOW_PLAINTEXT_ENV => Some("true".to_string()),
                _ => None,
            },
            now,
        )
        .expect("loopback service-token listener remains a local test path");
        assert!(addr.ip().is_loopback());
    }

    /// Health listener 经 funnel 构造（NoAuth）：空探针 → readyz 503（fail-closed）；
    /// 注册一个 Healthy 探针 → readyz 200。
    #[tokio::test]
    #[allow(clippy::expect_used, clippy::unwrap_used)]
    async fn health_listener_readyz_reflects_probes() {
        let mut empty_reg = bootstrap::compose(&[]).expect("compose empty");
        let empty = Arc::new(empty_reg.take_health_reporter());
        let (_, authed) = health_listener(empty, noop_metrics()).expect("health listener");
        let resp = authed
            .into_router_for_test()
            .oneshot(
                Request::builder()
                    .uri("/health/v1/readyz")
                    .body(Body::empty())
                    .expect("req"),
            )
            .await
            .expect("oneshot");
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "空探针 → readyz fail-closed 503"
        );

        struct HealthyProbe;
        impl bootstrap::HealthProbe for HealthyProbe {
            fn check(&self) -> HealthCheck {
                HealthCheck::new(
                    ProbeName::parse("ok").expect("name"),
                    HealthStatus::Healthy,
                    "ready",
                )
            }
        }
        let mut reg = bootstrap::compose(&[]).expect("compose");
        reg.probe(
            ProbeName::parse("ok").expect("name"),
            Box::new(HealthyProbe),
        )
        .expect("register probe");
        let reporter = Arc::new(reg.take_health_reporter());
        let (_, authed) = health_listener(reporter, noop_metrics()).expect("health listener");
        let resp = authed
            .into_router_for_test()
            .oneshot(
                Request::builder()
                    .uri("/health/v1/readyz")
                    .body(Body::empty())
                    .expect("req"),
            )
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK, "Healthy 探针 → readyz 200");
    }

    /// Down 路径（fail-closed，不连 DB）：新建 `PgDbReadiness`（初值 Down）→ readyz 503。
    #[tokio::test]
    #[allow(clippy::expect_used, clippy::unwrap_used)]
    async fn configs_ready_initial_down_readyz_503() {
        let health = Arc::new(PgDbReadiness::new());
        let mut reg = bootstrap::compose(&[]).expect("compose");
        reg.probe(
            ProbeName::parse(CONFIGS_READY_PROBE_NAME).expect("valid probe name"),
            Box::new(ConfigsReadyProbe::new(Arc::clone(&health))),
        )
        .expect("register probe");
        let reporter = Arc::new(reg.take_health_reporter());

        let (_listener, authed) =
            health_listener(reporter, noop_metrics()).expect("health listener");
        let resp = authed
            .into_router_for_test()
            .oneshot(
                Request::builder()
                    .uri("/health/v1/readyz")
                    .body(Body::empty())
                    .expect("req"),
            )
            .await
            .expect("oneshot");
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "初值 Down（未采样）→ readyz fail-closed 503"
        );
    }

    /// Health listener liveness 端点 `/health/v1/healthz` 恒 200（存活即活）。
    #[tokio::test]
    #[allow(clippy::expect_used, clippy::unwrap_used)]
    async fn health_listener_healthz_is_200() {
        let (listener, authed) =
            health_listener(test_reporter(), noop_metrics()).expect("health listener");
        assert_eq!(listener, ListenerKind::Health);
        let resp = authed
            .into_router_for_test()
            .oneshot(
                Request::builder()
                    .uri("/health/v1/healthz")
                    .body(Body::empty())
                    .expect("req"),
            )
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK, "liveness 恒 200");
    }
}
