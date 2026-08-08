//! Runtime listener bind-address and plaintext policy.

use crate::{config::SnapshotConfig, infra::plaintext_endpoint_policy_from_value};

use std::net::SocketAddr;
use std::time::SystemTime;

use anyhow::Context as _;
use primitives::{AuthScheme, ListenerKind};
use secure::PlaintextEndpointPolicy;

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

/// 由已解析的 listener auth scheme + 配置快照解析 bind 地址。
///
/// Auth scheme 在 route finalize 阶段解析一次并随 `AssembledListener` 传入；这里只消费 resolved scheme，
/// 避免 bind policy 与 serve strategy 各自重新解析配置后漂移。
pub(crate) fn listener_addr_for_scheme(
    config: SnapshotConfig<'_>,
    listener: ListenerKind,
    scheme: AuthScheme,
) -> anyhow::Result<SocketAddr> {
    // reason: sample the process clock once at the startup policy boundary; tests use the explicit
    // `_at` entry to keep the decision transcript deterministic.
    #[allow(clippy::disallowed_methods)]
    let now = SystemTime::now();
    listener_addr_for_scheme_at(config, listener, scheme, now)
}

pub(crate) fn listener_addr_for_scheme_at(
    config: SnapshotConfig<'_>,
    listener: ListenerKind,
    scheme: AuthScheme,
    now: SystemTime,
) -> anyhow::Result<SocketAddr> {
    let var = listener_addr_env(listener)?;
    listener_addr_for_scheme_from_values(
        listener,
        scheme,
        var,
        config.value(var),
        config.value(LISTENER_ALLOW_PLAINTEXT_ENV),
        now,
    )
}

fn listener_addr_for_scheme_from_values(
    listener: ListenerKind,
    scheme: AuthScheme,
    addr_env: &str,
    raw_addr: Option<&str>,
    raw_plaintext_policy: Option<&str>,
    now: SystemTime,
) -> anyhow::Result<SocketAddr> {
    let raw = raw_addr.ok_or_else(|| {
        anyhow::anyhow!("missing required env var: {addr_env} (listener has routes)")
    })?;
    let addr = raw
        .parse::<SocketAddr>()
        .with_context(|| format!("{addr_env} must be a valid host:port SocketAddr"))?;
    enforce_listener_plaintext_policy(listener, scheme, addr, raw_plaintext_policy, now)?;
    Ok(addr)
}

fn enforce_listener_plaintext_policy(
    listener: ListenerKind,
    scheme: AuthScheme,
    addr: SocketAddr,
    raw_plaintext_policy: Option<&str>,
    _now: SystemTime,
) -> anyhow::Result<()> {
    if scheme == AuthScheme::Mtls {
        return Ok(());
    }
    let policy =
        plaintext_endpoint_policy_from_value(raw_plaintext_policy, LISTENER_ALLOW_PLAINTEXT_ENV)?;
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
    use crate::{CONFIGS_READY_PROBE_NAME, ConfigsReadyProbe};

    use std::sync::Arc;
    use std::time::Duration;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use postgres::PgDbReadiness;
    use primitives::{HealthCheck, HealthStatus, ProbeName};
    use tower::ServiceExt as _;

    const INTERNAL_AUTH_MTLS: &str = "mtls";
    const INTERNAL_AUTH_SERVICE_TOKEN: &str = "service-token";

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

    #[allow(clippy::expect_used)]
    fn health_routes(reporter: Arc<bootstrap::HealthReporter>) -> httpserve::AuthenticatedRoutes {
        crate::routes::AssembledListener::health_for_test(reporter, noop_metrics())
            .expect("health listener")
            .into_parts()
            .1
    }

    fn listener_addr_from(
        listener: ListenerKind,
        internal_auth_scheme: Option<&str>,
        raw_addr: Option<&str>,
        raw_plaintext_policy: Option<&str>,
    ) -> anyhow::Result<SocketAddr> {
        #[allow(clippy::disallowed_methods)]
        let now = SystemTime::now();
        listener_addr_from_at(
            listener,
            internal_auth_scheme,
            raw_addr,
            raw_plaintext_policy,
            now,
        )
    }

    fn listener_addr_from_at(
        listener: ListenerKind,
        internal_auth_scheme: Option<&str>,
        raw_addr: Option<&str>,
        raw_plaintext_policy: Option<&str>,
        now: SystemTime,
    ) -> anyhow::Result<SocketAddr> {
        let scheme = match listener {
            ListenerKind::Primary | ListenerKind::Admin => AuthScheme::RssAccessToken,
            ListenerKind::Internal => match internal_auth_scheme {
                Some(INTERNAL_AUTH_MTLS) => AuthScheme::Mtls,
                Some(INTERNAL_AUTH_SERVICE_TOKEN) => AuthScheme::ServiceToken,
                _ => anyhow::bail!("test Internal listener requires an explicit auth scheme"),
            },
            ListenerKind::Health => AuthScheme::NoAuth,
            _ => anyhow::bail!("unknown test listener"),
        };
        listener_addr_for_scheme_from_values(
            listener,
            scheme,
            listener_addr_env(listener)?,
            raw_addr,
            raw_plaintext_policy,
            now,
        )
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
        let err =
            listener_addr_from(ListenerKind::Primary, None, None, None).expect_err("missing addr");
        assert!(
            err.to_string().contains("RSS_PRIMARY_LISTEN_ADDR"),
            "error 含 env 变量名: {err}"
        );
    }

    /// addr env 值非法 SocketAddr → fail-fast，错误含 env 变量名。
    #[test]
    #[allow(clippy::expect_used)]
    fn listener_addr_invalid_value_fails_fast() {
        const SECRET_FRAGMENT: &str = "listener-secret-bait";
        let err = listener_addr_from(ListenerKind::Health, None, Some(SECRET_FRAGMENT), None)
            .expect_err("invalid addr");
        let error = err.to_string();
        assert!(error.contains("RSS_HEALTH_LISTEN_ADDR"), "含 env 名: {err}");
        assert!(
            !error.contains(SECRET_FRAGMENT),
            "listener errors must not expose configured values"
        );
    }

    /// 合法 `host:port` → 解析成功。
    #[test]
    #[allow(clippy::expect_used)]
    fn listener_addr_valid_value_parses() {
        let addr = listener_addr_from(
            ListenerKind::Primary,
            None,
            Some("0.0.0.0:8080"),
            Some("dev-container"),
        )
        .expect("valid dev-container listener addr");
        assert_eq!(addr.port(), 8080);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn listener_plaintext_default_rejects_loopback() {
        let err = listener_addr_from(ListenerKind::Health, None, Some("127.0.0.1:8083"), None)
            .expect_err("plaintext listener needs explicit opt-in even on loopback");
        assert!(
            format!("{err:#}").contains(LISTENER_ALLOW_PLAINTEXT_ENV),
            "error must identify plaintext opt-in env: {err:#}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn listener_plaintext_default_rejects_non_loopback() {
        let err = listener_addr_from(ListenerKind::Primary, None, Some("0.0.0.0:8080"), None)
            .expect_err("non-loopback plaintext listener must fail closed by default");
        assert!(
            format!("{err:#}").contains(LISTENER_ALLOW_PLAINTEXT_ENV),
            "error must identify plaintext opt-in env: {err:#}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn listener_plaintext_true_allows_loopback_only() {
        let loopback = listener_addr_from(
            ListenerKind::Health,
            None,
            Some("127.0.0.1:8083"),
            Some("true"),
        )
        .expect("explicit loopback opt-in should allow loopback bind");
        assert!(loopback.ip().is_loopback());

        let err = listener_addr_from(
            ListenerKind::Health,
            None,
            Some("10.0.0.8:8083"),
            Some("true"),
        )
        .expect_err("loopback opt-in must reject fixed non-loopback addresses");
        assert!(format!("{err:#}").contains("loopback"), "{err:#}");
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn listener_plaintext_dev_container_allows_only_loopback_or_unspecified() {
        for raw in ["0.0.0.0:8080", "[::]:8080", "127.0.0.1:8080"] {
            let addr = listener_addr_from(
                ListenerKind::Primary,
                None,
                Some(raw),
                Some("dev-container"),
            )
            .expect("dev-container policy allows compose wildcard and loopback binds");
            assert!(addr.ip().is_unspecified() || addr.ip().is_loopback());
        }

        let err = listener_addr_from(
            ListenerKind::Primary,
            None,
            Some("10.0.0.8:8080"),
            Some("dev-container"),
        )
        .expect_err("dev-container policy must not allow arbitrary non-loopback binds");
        assert!(
            format!("{err:#}").contains("dev-container"),
            "error should mention dev-container policy: {err:#}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn listener_plaintext_invalid_opt_in_fails_fast() {
        let err = listener_addr_from(
            ListenerKind::Health,
            None,
            Some("127.0.0.1:8083"),
            Some("enabled"),
        )
        .expect_err("invalid plaintext opt-in should fail");
        assert!(
            format!("{err:#}").contains(LISTENER_ALLOW_PLAINTEXT_ENV),
            "error must identify opt-in env: {err:#}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn internal_mtls_listener_is_not_plaintext() {
        let addr = listener_addr_from(
            ListenerKind::Internal,
            Some(INTERNAL_AUTH_MTLS),
            Some("0.0.0.0:8081"),
            None,
        )
        .expect("explicit Internal mTLS listener is not gated as plaintext");
        assert!(addr.ip().is_unspecified());
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn listener_addr_policy_consumes_resolved_scheme_without_auth_input() {
        let addr = listener_addr_for_scheme_from_values(
            ListenerKind::Internal,
            AuthScheme::Mtls,
            "RSS_INTERNAL_LISTEN_ADDR",
            Some("0.0.0.0:8081"),
            None,
            SystemTime::UNIX_EPOCH,
        )
        .expect("resolved mTLS scheme bypasses plaintext policy without another auth input");
        assert!(addr.ip().is_unspecified());
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn internal_service_token_listener_is_plaintext_and_requires_opt_in() {
        let err = listener_addr_from(
            ListenerKind::Internal,
            Some(INTERNAL_AUTH_SERVICE_TOKEN),
            Some("0.0.0.0:8081"),
            None,
        )
        .expect_err("Internal service-token mode is plaintext and must be gated");
        assert!(
            format!("{err:#}").contains(LISTENER_ALLOW_PLAINTEXT_ENV),
            "error must identify plaintext opt-in env: {err:#}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn internal_service_token_non_loopback_rejects_even_with_plaintext_opt_in() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000);
        let err = listener_addr_from_at(
            ListenerKind::Internal,
            Some(INTERNAL_AUTH_SERVICE_TOKEN),
            Some("0.0.0.0:8081"),
            Some("dev-container"),
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
            Some(INTERNAL_AUTH_SERVICE_TOKEN),
            Some("127.0.0.1:8081"),
            Some("true"),
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
        let authed = health_routes(empty);
        let resp = authed
            .into_plaintext_router_for_test()
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
        let authed = health_routes(reporter);
        let resp = authed
            .into_plaintext_router_for_test()
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

        let authed = health_routes(reporter);
        let resp = authed
            .into_plaintext_router_for_test()
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
        let authed = health_routes(test_reporter());
        let resp = authed
            .into_plaintext_router_for_test()
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
