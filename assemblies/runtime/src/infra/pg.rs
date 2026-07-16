use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context as _;
use postgres::{LegacyConfigPlaintextPolicy, PgConfig, PgPassword, PgSslMode, PgTenantReadConfig};

// ── postgres 配置 wiring ─────────────────────────────────────────────────────────────────────

pub(crate) const PG_SSL_ROOT_CERT_PATH_ENV: &str = "RSS_PG_SSL_ROOT_CERT_PATH";
pub(crate) const PG_WRITER_MAX_CONNECTIONS_ENV: &str = "RSS_PG_MAX_CONNECTIONS";
pub(crate) const PG_READER_MAX_CONNECTIONS_ENV: &str = "RSS_PG_READ_MAX_CONNECTIONS";
const DEFAULT_SERVING_LANE_MAX_CONNECTIONS: u32 = 5;
const MAX_SERVING_LANE_MAX_CONNECTIONS: u32 = 100;
pub(crate) const SETTINGS_ALLOW_LEGACY_PLAINTEXT_CONFIG_VALUES_ENV: &str =
    "RSS_SETTINGS_ALLOW_LEGACY_PLAINTEXT_CONFIG_VALUES";

/// 从注入的配置读取器构造 serving `PgConfig`（fail-fast：任一必填 env 缺失立即返 `Err`）。
///
/// 必填变量：
/// - `RSS_PG_HOST` — postgres 主机（非空）。
/// - `RSS_PG_PORT` — postgres 端口（非零 u16，默认 5432 需显式声明）。
/// - `RSS_PG_DATABASE` — 数据库名（非空）。
/// - `RSS_PG_USERNAME` — 连接用户（非空）。
/// - `RSS_PG_PASSWORD` — 连接密码（非空）。
///
/// TLS 默认 `VerifyFull`（零信任）；可选 `RSS_PG_SSL_MODE` 经 [`parse_pg_ssl_mode`] 显式降级（容器内连
/// 未启 TLS 的 dev postgres 时用 `prefer` / `disable`）。生产私有 CA 根证书经
/// `RSS_PG_SSL_ROOT_CERT_PATH` → `PgConfig::with_ssl_root_cert` 注入。
/// **禁止 localhost fallback**（生产配置规范，rust-standards §安全检查点）。
pub(crate) fn build_pg_config_from(
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<PgConfig> {
    let config = build_pg_config_with_user_env(&get, "RSS_PG_USERNAME", "RSS_PG_PASSWORD")?;
    apply_serving_lane_pool_limit(config, &get, PG_WRITER_MAX_CONNECTIONS_ENV)
}

fn apply_serving_lane_pool_limit(
    config: PgConfig,
    get: &impl Fn(&str) -> Option<String>,
    env: &'static str,
) -> anyhow::Result<PgConfig> {
    let max = match get(env) {
        Some(raw) => raw.trim().parse::<u32>().with_context(|| {
            format!("{env} must be an integer in 1..={MAX_SERVING_LANE_MAX_CONNECTIONS}")
        })?,
        None => DEFAULT_SERVING_LANE_MAX_CONNECTIONS,
    };
    anyhow::ensure!(
        (1..=MAX_SERVING_LANE_MAX_CONNECTIONS).contains(&max),
        "{env} must be in 1..={MAX_SERVING_LANE_MAX_CONNECTIONS}"
    );
    Ok(config.with_max_connections(max))
}

fn build_pg_config_with_user_env(
    get: &impl Fn(&str) -> Option<String>,
    username_env: &'static str,
    password_env: &'static str,
) -> anyhow::Result<PgConfig> {
    let host = get("RSS_PG_HOST")
        .ok_or_else(|| anyhow::anyhow!("missing required env var: RSS_PG_HOST"))?;
    let port_str = get("RSS_PG_PORT")
        .ok_or_else(|| anyhow::anyhow!("missing required env var: RSS_PG_PORT"))?;
    let port: u16 = port_str.parse().with_context(|| {
        format!("RSS_PG_PORT must be a valid port number (1-65535): {port_str}")
    })?;
    let database = get("RSS_PG_DATABASE")
        .ok_or_else(|| anyhow::anyhow!("missing required env var: RSS_PG_DATABASE"))?;
    let username = get(username_env)
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {username_env}"))?;
    let password = get(password_env)
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {password_env}"))?;

    // PgConfig::new 存储参数；validate 在 PgStore::connect 内调用（pub(crate)）。
    // 这里只做构造，连接时再 fail-fast（组合根在 wire_settings 中 connect）。
    let mut config = PgConfig::new(host, port, database, username, PgPassword::new(password))
        .with_ssl_mode(parse_pg_ssl_mode(get("RSS_PG_SSL_MODE")));
    if let Some(path) = pg_ssl_root_cert_path_from(get)? {
        config = config.with_ssl_root_cert(path);
    }
    Ok(config)
}

fn pg_ssl_root_cert_path_from(
    get: &impl Fn(&str) -> Option<String>,
) -> anyhow::Result<Option<PathBuf>> {
    let Some(raw) = get(PG_SSL_ROOT_CERT_PATH_ENV) else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    anyhow::ensure!(
        !trimmed.is_empty(),
        "{PG_SSL_ROOT_CERT_PATH_ENV} must not be empty"
    );
    let path = PathBuf::from(trimmed);
    let metadata = fs::metadata(&path)
        .with_context(|| format!("{PG_SSL_ROOT_CERT_PATH_ENV} must point to a readable file"))?;
    anyhow::ensure!(
        metadata.is_file(),
        "{PG_SSL_ROOT_CERT_PATH_ENV} must point to a file"
    );
    let _ = fs::File::open(&path)
        .with_context(|| format!("{PG_SSL_ROOT_CERT_PATH_ENV} must point to a readable file"))?;
    Ok(Some(path))
}

/// 解析可选 `RSS_PG_SSL_MODE` → [`PgSslMode`]（libpq 拼写：`disable` / `allow` / `prefer` / `require` /
/// `verify-ca` / `verify-full`，大小写与前后空白不敏感）。
///
/// - 未配置 → `VerifyFull`（零信任默认，强制 TLS + 校验证书链/主机名）。
/// - 显式合法值 → 对应模式（容器内 dev postgres 无 TLS 时经 `prefer` / `disable` 显式降级，不静默）。
/// - 显式非法值 / 空串 → `tracing::warn!` + **fail-closed 回退 `VerifyFull`**（误配不降级安全姿态）。
///
/// 安全姿态非强依赖配置，故误配 fail-soft（warn + 安全默认）而非 fail-fast——与 [`build_readiness_interval_from`]
/// 同范式；但回退方向恒为**更严**的 `VerifyFull`，绝不因误配静默放宽。
pub(crate) fn parse_pg_ssl_mode(raw: Option<String>) -> PgSslMode {
    let Some(raw) = raw else {
        return PgSslMode::VerifyFull;
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "disable" => PgSslMode::Disable,
        "allow" => PgSslMode::Allow,
        "prefer" => PgSslMode::Prefer,
        "require" => PgSslMode::Require,
        "verify-ca" => PgSslMode::VerifyCa,
        "verify-full" => PgSslMode::VerifyFull,
        _ => {
            tracing::warn!(
                env = "RSS_PG_SSL_MODE",
                raw = %raw,
                "invalid pg ssl mode (need disable|allow|prefer|require|verify-ca|verify-full); \
                 falling back to verify-full (zero-trust)"
            );
            PgSslMode::VerifyFull
        }
    }
}

/// 从 `std::env` 构造 `PgConfig`。
pub fn build_pg_config() -> anyhow::Result<PgConfig> {
    build_pg_config_from(|name| std::env::var(name).ok())
}

/// 从注入的配置读取器构造 tenant read-only postgres 配置。
///
/// Host / port / database / TLS / pool tuning 与 serving 连接遵循同一配置面；身份必须来自
/// `RSS_PG_READ_USERNAME` / `RSS_PG_READ_PASSWORD`。两个 reader 凭据均为必填，不回退到 writer
/// 的 `RSS_PG_USERNAME` / `RSS_PG_PASSWORD`。
pub(crate) fn build_pg_read_config_from(
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<PgTenantReadConfig> {
    let config =
        build_pg_config_with_user_env(&get, "RSS_PG_READ_USERNAME", "RSS_PG_READ_PASSWORD")?;
    apply_serving_lane_pool_limit(config, &get, PG_READER_MAX_CONNECTIONS_ENV)
        .map(PgTenantReadConfig::new)
}

/// 从 `std::env` 构造强类型 tenant read-only postgres 配置。
pub fn build_pg_read_config() -> anyhow::Result<PgTenantReadConfig> {
    build_pg_read_config_from(|name| std::env::var(name).ok())
}

pub(crate) fn build_pg_audit_admin_config_from(
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<Option<PgConfig>> {
    let username = get("RSS_PG_AUDIT_ADMIN_USERNAME");
    let password = get("RSS_PG_AUDIT_ADMIN_PASSWORD");
    match (username, password) {
        (None, None) => Ok(None),
        (Some(_), Some(_)) => build_pg_config_with_user_env(
            &get,
            "RSS_PG_AUDIT_ADMIN_USERNAME",
            "RSS_PG_AUDIT_ADMIN_PASSWORD",
        )
        .map(Some),
        (None, Some(_)) => Err(anyhow::anyhow!(
            "missing required env var: RSS_PG_AUDIT_ADMIN_USERNAME"
        )),
        (Some(_), None) => Err(anyhow::anyhow!(
            "missing required env var: RSS_PG_AUDIT_ADMIN_PASSWORD"
        )),
    }
}

pub fn build_pg_audit_admin_config() -> anyhow::Result<Option<PgConfig>> {
    build_pg_audit_admin_config_from(|name| std::env::var(name).ok())
}

/// 从注入的配置读取器构造 migrator `PgConfig`。
///
/// Host / port / database / TLS mode 与 serving 连接一致；用户名和密码必须来自
/// `RSS_PG_MIGRATOR_USERNAME` / `RSS_PG_MIGRATOR_PASSWORD`，避免长期 serving role 继承 DDL 能力。
pub(crate) fn build_pg_migrator_config_from(
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<PgConfig> {
    build_pg_config_with_user_env(&get, "RSS_PG_MIGRATOR_USERNAME", "RSS_PG_MIGRATOR_PASSWORD")
}

/// 从 `std::env` 构造 migrator `PgConfig`。
pub fn build_pg_migrator_config() -> anyhow::Result<PgConfig> {
    build_pg_migrator_config_from(|name| std::env::var(name).ok())
}

/// 从注入的配置读取器构造 DLX lifecycle 专用长期连接配置。
///
/// Host / port / database / TLS 与 serving 连接一致；凭据必须来自窄角色
/// `RSS_PG_DLX_ARCHIVER_USERNAME` / `RSS_PG_DLX_ARCHIVER_PASSWORD`。该 pool 不得复用
/// `rss_app` serving credentials。
pub(crate) fn build_pg_dlx_archiver_config_from(
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<PgConfig> {
    build_pg_config_with_user_env(
        &get,
        "RSS_PG_DLX_ARCHIVER_USERNAME",
        "RSS_PG_DLX_ARCHIVER_PASSWORD",
    )
}

/// 从 `std::env` 构造 DLX lifecycle 专用长期连接配置。
pub fn build_pg_dlx_archiver_config() -> anyhow::Result<PgConfig> {
    build_pg_dlx_archiver_config_from(|name| std::env::var(name).ok())
}

/// Constructs the independently credentialed DLX verification pool configuration.
pub(crate) fn build_pg_dlx_verifier_config_from(
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<PgConfig> {
    build_pg_config_with_user_env(
        &get,
        "RSS_PG_DLX_VERIFIER_USERNAME",
        "RSS_PG_DLX_VERIFIER_PASSWORD",
    )
}

/// Constructs the independently credentialed DLX purge/reconcile pool configuration.
pub(crate) fn build_pg_dlx_purger_config_from(
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<PgConfig> {
    build_pg_config_with_user_env(
        &get,
        "RSS_PG_DLX_PURGER_USERNAME",
        "RSS_PG_DLX_PURGER_PASSWORD",
    )
}

/// 从注入的配置读取器构造 legacy plaintext `ConfigValue` 启动策略。
///
/// `RSS_SETTINGS_ALLOW_LEGACY_PLAINTEXT_CONFIG_VALUES` 是安全豁免开关：缺省为 deny；显式非法值 fail-fast。
pub(crate) fn legacy_config_plaintext_policy_from(
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<LegacyConfigPlaintextPolicy> {
    let Some(raw) = get(SETTINGS_ALLOW_LEGACY_PLAINTEXT_CONFIG_VALUES_ENV) else {
        return Ok(LegacyConfigPlaintextPolicy::Deny);
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" => Ok(LegacyConfigPlaintextPolicy::AllowTemporary),
        "0" | "false" | "no" => Ok(LegacyConfigPlaintextPolicy::Deny),
        _ => anyhow::bail!(
            "{SETTINGS_ALLOW_LEGACY_PLAINTEXT_CONFIG_VALUES_ENV} must be true/false (or 1/0, yes/no)"
        ),
    }
}

pub(crate) fn legacy_config_plaintext_policy() -> anyhow::Result<LegacyConfigPlaintextPolicy> {
    legacy_config_plaintext_policy_from(|name| std::env::var(name).ok())
}

/// 默认 DB readiness 采样周期（5 秒）。
pub(crate) const DEFAULT_READINESS_INTERVAL: Duration = Duration::from_secs(5);
/// 采样间隔上限（秒）：限制 DB 失联后维持旧 Ready 状态的最长时间。
const MAX_READINESS_INTERVAL_SECS: u64 = 300;
/// configs_ready DB 采样周期（env `RSS_PG_READINESS_SAMPLE_INTERVAL_SECS`）。
///
/// - 未配置 → 静默取默认 5s。
/// - 显式配置但解析失败 / 为 0 / 超出上限（300s）→ `tracing::warn!` + 默认 5s。
///
/// 间隔是探针新鲜度 hint 非强依赖，故显式误配 fail-soft（warn+默认）而非 fail-fast。
pub(crate) fn build_readiness_interval_from(get: impl Fn(&str) -> Option<String>) -> Duration {
    match get("RSS_PG_READINESS_SAMPLE_INTERVAL_SECS") {
        None => DEFAULT_READINESS_INTERVAL,
        Some(raw) => match raw.parse::<u64>() {
            Ok(n) if (1..=MAX_READINESS_INTERVAL_SECS).contains(&n) => Duration::from_secs(n),
            _ => {
                tracing::warn!(
                    env = "RSS_PG_READINESS_SAMPLE_INTERVAL_SECS",
                    raw = %raw,
                    max_secs = MAX_READINESS_INTERVAL_SECS,
                    "invalid readiness sample interval (need 1..=300s); using default 5s"
                );
                DEFAULT_READINESS_INTERVAL
            }
        },
    }
}

pub(crate) fn build_readiness_interval() -> Duration {
    build_readiness_interval_from(|n| std::env::var(n).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use postgres::LegacyConfigPlaintextPolicy;
    use std::time::Duration;

    static TEMP_COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    fn unique_temp_path(name: &str) -> std::path::PathBuf {
        let seq = TEMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        std::env::temp_dir().join(format!("rss-runtime-{}-{seq}-{name}", std::process::id()))
    }

    #[allow(clippy::expect_used)]
    fn write_temp_file(name: &str, contents: &[u8]) -> std::path::PathBuf {
        let path = unique_temp_path(name);
        std::fs::write(&path, contents).expect("write temp file");
        path
    }

    #[allow(clippy::expect_used)]
    fn create_temp_dir(name: &str) -> std::path::PathBuf {
        let path = unique_temp_path(name);
        std::fs::create_dir(&path).expect("create temp dir");
        path
    }

    #[cfg(unix)]
    #[allow(clippy::expect_used)]
    fn write_unreadable_temp_file(name: &str, contents: &[u8]) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let path = write_temp_file(name, contents);
        let mut permissions = std::fs::metadata(&path)
            .expect("metadata temp file")
            .permissions();
        permissions.set_mode(0o000);
        std::fs::set_permissions(&path, permissions).expect("make temp file unreadable");
        path
    }

    #[allow(clippy::panic)]
    #[test]
    fn pg_migrator_config_requires_dedicated_credentials() {
        let result = build_pg_migrator_config_from(|name| match name {
            "RSS_PG_HOST" => Some("postgres".to_string()),
            "RSS_PG_PORT" => Some("5432".to_string()),
            "RSS_PG_DATABASE" => Some("rss".to_string()),
            "RSS_PG_USERNAME" => Some("rss_app".to_string()),
            "RSS_PG_PASSWORD" => Some("app_pw".to_string()),
            _ => None,
        });
        match result {
            Ok(_) => panic!("missing migrator username should fail"),
            Err(err) => assert!(err.to_string().contains("RSS_PG_MIGRATOR_USERNAME")),
        }
    }

    #[allow(clippy::panic)]
    #[test]
    fn pg_migrator_config_uses_dedicated_credentials() {
        let cfg = match build_pg_migrator_config_from(|name| match name {
            "RSS_PG_HOST" => Some("postgres".to_string()),
            "RSS_PG_PORT" => Some("5432".to_string()),
            "RSS_PG_DATABASE" => Some("rss".to_string()),
            "RSS_PG_USERNAME" => Some("rss_app".to_string()),
            "RSS_PG_PASSWORD" => Some("app_pw".to_string()),
            "RSS_PG_MIGRATOR_USERNAME" => Some("postgres".to_string()),
            "RSS_PG_MIGRATOR_PASSWORD" => Some("owner_pw".to_string()),
            "RSS_PG_SSL_MODE" => Some("disable".to_string()),
            _ => None,
        }) {
            Ok(cfg) => cfg,
            Err(err) => panic!("migrator config: {err}"),
        };
        let debug = format!("{cfg:?}");
        assert!(debug.contains("postgres"));
        assert!(!debug.contains("rss_app"));
    }

    #[allow(clippy::panic)]
    #[test]
    fn pg_read_config_requires_dedicated_credential_pair_without_writer_fallback() {
        let missing_username = build_pg_read_config_from(full_pg_get);
        match missing_username {
            Ok(_) => panic!("writer credentials must not satisfy the tenant reader"),
            Err(err) => assert!(err.to_string().contains("RSS_PG_READ_USERNAME")),
        }

        let missing_password = build_pg_read_config_from(|name| match name {
            "RSS_PG_READ_USERNAME" => Some("rss_app_read".to_string()),
            _ => full_pg_get(name),
        });
        match missing_password {
            Ok(_) => panic!("reader username without reader password must fail"),
            Err(err) => assert!(err.to_string().contains("RSS_PG_READ_PASSWORD")),
        }
    }

    #[allow(clippy::panic)]
    #[test]
    fn pg_read_config_uses_dedicated_credentials() {
        let cfg = build_pg_read_config_from(|name| match name {
            "RSS_PG_READ_USERNAME" => Some("rss_app_read".to_string()),
            "RSS_PG_READ_PASSWORD" => Some("read_pw".to_string()),
            _ => full_pg_get(name),
        })
        .unwrap_or_else(|err| panic!("tenant reader config: {err}"));
        let debug = format!("{cfg:?}");
        assert!(debug.contains("rss_app_read"));
        assert!(!debug.contains("username: \"rss_app\""));
        assert!(!debug.contains("read_pw"));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn serving_pool_budget_is_split_by_default_and_independently_configurable() {
        let writer = build_pg_config_from(full_pg_get).expect("writer config");
        let reader = build_pg_read_config_from(|name| match name {
            "RSS_PG_READ_USERNAME" => Some("rss_app_read".to_string()),
            "RSS_PG_READ_PASSWORD" => Some("read_pw".to_string()),
            _ => full_pg_get(name),
        })
        .expect("reader config");
        assert!(format!("{writer:?}").contains("max_connections: 5"));
        assert!(format!("{reader:?}").contains("max_connections: 5"));

        let writer = build_pg_config_from(|name| match name {
            PG_WRITER_MAX_CONNECTIONS_ENV => Some("7".to_string()),
            _ => full_pg_get(name),
        })
        .expect("custom writer pool");
        let reader = build_pg_read_config_from(|name| match name {
            "RSS_PG_READ_USERNAME" => Some("rss_app_read".to_string()),
            "RSS_PG_READ_PASSWORD" => Some("read_pw".to_string()),
            PG_READER_MAX_CONNECTIONS_ENV => Some("3".to_string()),
            _ => full_pg_get(name),
        })
        .expect("custom reader pool");
        assert!(format!("{writer:?}").contains("max_connections: 7"));
        assert!(format!("{reader:?}").contains("max_connections: 3"));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn serving_pool_limits_reject_zero_overflow_and_non_numeric_values() {
        for (env, value, reader) in [
            (PG_WRITER_MAX_CONNECTIONS_ENV, "0", false),
            (PG_WRITER_MAX_CONNECTIONS_ENV, "101", false),
            (PG_READER_MAX_CONNECTIONS_ENV, "many", true),
        ] {
            let result = if reader {
                build_pg_read_config_from(|name| match name {
                    "RSS_PG_READ_USERNAME" => Some("rss_app_read".to_string()),
                    "RSS_PG_READ_PASSWORD" => Some("read_pw".to_string()),
                    name if name == env => Some(value.to_string()),
                    _ => full_pg_get(name),
                })
                .map(|_| ())
            } else {
                build_pg_config_from(|name| {
                    (name == env)
                        .then(|| value.to_string())
                        .or_else(|| full_pg_get(name))
                })
                .map(|_| ())
            };
            let error = result.expect_err("invalid serving pool limit must fail");
            assert!(error.to_string().contains(env), "{error:#}");
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn pg_read_config_shares_tls_configuration() {
        let ca = write_temp_file("pg-reader-root-ca.pem", b"test ca");
        let cfg = build_pg_read_config_from(|name| match name {
            "RSS_PG_READ_USERNAME" => Some("rss_app_read".to_string()),
            "RSS_PG_READ_PASSWORD" => Some("read_pw".to_string()),
            "RSS_PG_SSL_MODE" => Some("verify-ca".to_string()),
            PG_SSL_ROOT_CERT_PATH_ENV => Some(ca.display().to_string()),
            _ => full_pg_get(name),
        })
        .expect("reader must share serving TLS configuration");
        let debug = format!("{cfg:?}");
        assert!(debug.contains("VerifyCa"));
        assert!(debug.contains("pg-reader-root-ca.pem"));
    }

    #[allow(clippy::panic)]
    #[test]
    fn pg_dlx_archiver_config_requires_and_uses_dedicated_credentials() {
        let missing = build_pg_dlx_archiver_config_from(full_pg_get);
        match missing {
            Ok(_) => panic!("missing DLX archiver credentials should fail"),
            Err(err) => assert!(err.to_string().contains("RSS_PG_DLX_ARCHIVER_USERNAME")),
        }

        let missing_password = build_pg_dlx_archiver_config_from(|name| match name {
            "RSS_PG_DLX_ARCHIVER_USERNAME" => Some("rss_dlx_archiver".to_string()),
            _ => full_pg_get(name),
        });
        match missing_password {
            Ok(_) => panic!("missing DLX archiver password should fail"),
            Err(err) => assert!(err.to_string().contains("RSS_PG_DLX_ARCHIVER_PASSWORD")),
        }

        let cfg = match build_pg_dlx_archiver_config_from(|name| match name {
            "RSS_PG_DLX_ARCHIVER_USERNAME" => Some("rss_dlx_archiver".to_string()),
            "RSS_PG_DLX_ARCHIVER_PASSWORD" => Some("dlx_pw".to_string()),
            _ => full_pg_get(name),
        }) {
            Ok(cfg) => cfg,
            Err(err) => panic!("DLX archiver config: {err}"),
        };
        let debug = format!("{cfg:?}");
        assert!(debug.contains("rss_dlx_archiver"));
        assert!(!debug.contains("rss_app"));
        assert!(!debug.contains("dlx_pw"));
    }

    #[test]
    #[allow(clippy::panic)]
    fn pg_dlx_verifier_and_purger_configs_require_distinct_credentials() {
        let verifier = build_pg_dlx_verifier_config_from(|name| match name {
            "RSS_PG_DLX_VERIFIER_USERNAME" => Some("rss_dlx_verifier".to_string()),
            "RSS_PG_DLX_VERIFIER_PASSWORD" => Some("verify_pw".to_string()),
            _ => full_pg_get(name),
        })
        .unwrap_or_else(|error| panic!("DLX verifier config: {error}"));
        let purger = build_pg_dlx_purger_config_from(|name| match name {
            "RSS_PG_DLX_PURGER_USERNAME" => Some("rss_dlx_purger".to_string()),
            "RSS_PG_DLX_PURGER_PASSWORD" => Some("purge_pw".to_string()),
            _ => full_pg_get(name),
        })
        .unwrap_or_else(|error| panic!("DLX purger config: {error}"));

        let verifier_debug = format!("{verifier:?}");
        let purger_debug = format!("{purger:?}");
        assert!(verifier_debug.contains("rss_dlx_verifier"));
        assert!(purger_debug.contains("rss_dlx_purger"));
        assert!(!verifier_debug.contains("verify_pw"));
        assert!(!purger_debug.contains("purge_pw"));

        let missing_verifier = match build_pg_dlx_verifier_config_from(full_pg_get) {
            Ok(_) => panic!("verifier credentials are mandatory"),
            Err(error) => error,
        };
        assert!(
            missing_verifier
                .to_string()
                .contains("RSS_PG_DLX_VERIFIER_USERNAME")
        );
        let missing_purger = match build_pg_dlx_purger_config_from(full_pg_get) {
            Ok(_) => panic!("purger credentials are mandatory"),
            Err(error) => error,
        };
        assert!(
            missing_purger
                .to_string()
                .contains("RSS_PG_DLX_PURGER_USERNAME")
        );
    }

    // ── build_pg_config_from 测试 ──────────────────────────────────────────────────────────

    fn full_pg_get(k: &str) -> Option<String> {
        match k {
            "RSS_PG_HOST" => Some("pg.internal".to_string()),
            "RSS_PG_PORT" => Some("5432".to_string()),
            "RSS_PG_DATABASE" => Some("rss_db".to_string()),
            "RSS_PG_USERNAME" => Some("rss_app".to_string()),
            "RSS_PG_PASSWORD" => Some("s3cr3t".to_string()),
            _ => None,
        }
    }

    /// 全必填 env 均有 → 构造成功。
    #[test]
    #[allow(clippy::expect_used)]
    fn build_pg_config_from_happy() {
        let cfg = build_pg_config_from(full_pg_get).expect("all required vars present");
        // 验证 host 被记录（不泄露 password，只断言端口和 host 可 debug 比较）。
        let debug = format!("{cfg:?}");
        assert!(debug.contains("pg.internal"), "host 在 debug 输出中");
        assert!(debug.contains("rss_app"), "serving user 示例为 rss_app");
        assert!(!debug.contains("s3cr3t"), "password 不在 debug 输出中");
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn build_pg_audit_admin_config_absent_is_none() {
        let cfg = build_pg_audit_admin_config_from(full_pg_get).expect("optional admin config");
        assert!(cfg.is_none());
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn build_pg_audit_admin_config_requires_pair() {
        let missing_password = build_pg_audit_admin_config_from(|k| match k {
            "RSS_PG_AUDIT_ADMIN_USERNAME" => Some("rss_audit_admin".to_string()),
            _ => full_pg_get(k),
        })
        .expect_err("missing password must fail");
        assert!(
            missing_password
                .to_string()
                .contains("RSS_PG_AUDIT_ADMIN_PASSWORD")
        );

        let missing_username = build_pg_audit_admin_config_from(|k| match k {
            "RSS_PG_AUDIT_ADMIN_PASSWORD" => Some("admin_pw".to_string()),
            _ => full_pg_get(k),
        })
        .expect_err("missing username must fail");
        assert!(
            missing_username
                .to_string()
                .contains("RSS_PG_AUDIT_ADMIN_USERNAME")
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn build_pg_audit_admin_config_happy() {
        let cfg = build_pg_audit_admin_config_from(|k| match k {
            "RSS_PG_AUDIT_ADMIN_USERNAME" => Some("rss_audit_admin".to_string()),
            "RSS_PG_AUDIT_ADMIN_PASSWORD" => Some("admin_pw".to_string()),
            _ => full_pg_get(k),
        })
        .expect("admin config ok")
        .expect("configured");
        let debug = format!("{cfg:?}");
        assert!(debug.contains("rss_audit_admin"));
        assert!(!debug.contains("admin_pw"));
    }

    /// `RSS_PG_HOST` 缺失 → Err 含变量名（fail-fast）。
    #[test]
    #[allow(clippy::expect_used)]
    fn build_pg_config_from_missing_host() {
        let get = |k: &str| {
            if k == "RSS_PG_HOST" {
                None
            } else {
                full_pg_get(k)
            }
        };
        let err = build_pg_config_from(get).expect_err("host required");
        assert!(
            err.to_string().contains("RSS_PG_HOST"),
            "error contains var name"
        );
    }

    /// `RSS_PG_PASSWORD` 缺失 → Err 含变量名（fail-fast）。
    #[test]
    #[allow(clippy::expect_used)]
    fn build_pg_config_from_missing_password() {
        let get = |k: &str| {
            if k == "RSS_PG_PASSWORD" {
                None
            } else {
                full_pg_get(k)
            }
        };
        let err = build_pg_config_from(get).expect_err("password required");
        assert!(
            err.to_string().contains("RSS_PG_PASSWORD"),
            "error contains var name"
        );
    }

    /// `RSS_PG_PORT` 缺失 → Err 含变量名（fail-fast）。
    #[test]
    #[allow(clippy::expect_used)]
    fn build_pg_config_from_missing_port() {
        let get = |k: &str| {
            if k == "RSS_PG_PORT" {
                None
            } else {
                full_pg_get(k)
            }
        };
        let err = build_pg_config_from(get).expect_err("port required");
        assert!(
            err.to_string().contains("RSS_PG_PORT"),
            "error contains var name"
        );
    }

    /// 默认 TLS 模式 = VerifyFull（零信任；禁 localhost 回退）。
    #[test]
    #[allow(clippy::expect_used)]
    fn build_pg_config_defaults_ssl_verify_full() {
        use postgres::PgSslMode;
        let cfg = build_pg_config_from(full_pg_get).expect("ok");
        // PgConfig 的 ssl_mode 字段私有，经 connect_options() 读取；此处通过 debug 输出检查（适度）。
        // VerifyFull 是安全默认值（rust-standards §安全检查点）。
        let debug = format!("{cfg:?}");
        assert!(
            debug.contains("VerifyFull"),
            "默认 TLS = VerifyFull，但 debug 输出为: {debug}"
        );
        // 通过 fn-pointer smoke 绑定确认 PgSslMode::VerifyFull 变体可构造（Anti-vacuity）。
        let _mode: PgSslMode = PgSslMode::VerifyFull;
    }

    /// `RSS_PG_SSL_MODE` 解析：未配置 / 非法 / 空 → fail-closed VerifyFull；合法 libpq 拼写 → 对应模式。
    ///
    /// `PgSslMode`（sqlx 上游）未实现 `PartialEq`，故表驱动用 `Debug` 变体名断言（fieldless enum 的 derive
    /// `Debug` 恒等于变体名，与 [`build_pg_config_defaults_ssl_verify_full`] 同范式）。
    #[test]
    fn parse_pg_ssl_mode_maps_and_falls_back_to_verify_full() {
        let cases = [
            (None, "VerifyFull"), // 未配置 → 零信任默认（强制 TLS + 校验证书链/主机名）
            (Some("disable"), "Disable"), // 合法 libpq 拼写 → 对应模式
            (Some("PREFER"), "Prefer"), // 大小写不敏感
            (Some("  require "), "Require"), // 前后空白不敏感
            (Some("verify-ca"), "VerifyCa"),
            (Some("verify-full"), "VerifyFull"),
            (Some("allow"), "Allow"),
            (Some("bogus"), "VerifyFull"), // 非法值 → fail-closed 回退（恒向更严）
            (Some(""), "VerifyFull"),      // 空串 → fail-closed 回退
        ];
        for (raw, expected) in cases {
            let got = format!("{:?}", parse_pg_ssl_mode(raw.map(str::to_owned)));
            assert_eq!(got, expected, "RSS_PG_SSL_MODE={raw:?}");
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn build_pg_config_applies_ssl_root_cert_path() {
        let ca = write_temp_file("pg-root-ca.pem", b"test ca");
        let cfg = build_pg_config_from(|name| {
            if name == PG_SSL_ROOT_CERT_PATH_ENV {
                Some(ca.display().to_string())
            } else {
                full_pg_get(name)
            }
        })
        .expect("valid pg config with root cert");
        let debug = format!("{cfg:?}");
        assert!(
            debug.contains("pg-root-ca.pem"),
            "root cert path must be captured in PgConfig: {debug}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn build_pg_migrator_config_applies_ssl_root_cert_path() {
        let ca = write_temp_file("pg-migrator-root-ca.pem", b"test ca");
        let cfg = build_pg_migrator_config_from(|name| match name {
            "RSS_PG_MIGRATOR_USERNAME" => Some("rss_migrator".to_string()),
            "RSS_PG_MIGRATOR_PASSWORD" => Some("migrator-secret".to_string()),
            PG_SSL_ROOT_CERT_PATH_ENV => Some(ca.display().to_string()),
            _ => full_pg_get(name),
        })
        .expect("valid pg migrator config with root cert");
        let debug = format!("{cfg:?}");
        assert!(
            debug.contains("pg-migrator-root-ca.pem"),
            "root cert path must be shared by serving and migrator configs: {debug}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn build_pg_config_rejects_empty_ssl_root_cert_path() {
        let err = build_pg_config_from(|name| {
            if name == PG_SSL_ROOT_CERT_PATH_ENV {
                Some("  ".to_string())
            } else {
                full_pg_get(name)
            }
        })
        .expect_err("empty root cert path is explicit misconfiguration");
        assert!(
            format!("{err:#}").contains(PG_SSL_ROOT_CERT_PATH_ENV),
            "error must identify env var: {err:#}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn build_pg_config_rejects_missing_ssl_root_cert_path() {
        let missing = unique_temp_path("missing-pg-root-ca.pem");
        let err = build_pg_config_from(|name| {
            if name == PG_SSL_ROOT_CERT_PATH_ENV {
                Some(missing.display().to_string())
            } else {
                full_pg_get(name)
            }
        })
        .expect_err("missing root cert path must fail before connect");
        assert!(
            format!("{err:#}").contains(PG_SSL_ROOT_CERT_PATH_ENV),
            "error must identify env var: {err:#}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn build_pg_config_rejects_non_file_ssl_root_cert_path() {
        let dir = create_temp_dir("pg-root-ca-dir");
        let err = build_pg_config_from(|name| {
            if name == PG_SSL_ROOT_CERT_PATH_ENV {
                Some(dir.display().to_string())
            } else {
                full_pg_get(name)
            }
        })
        .expect_err("directory root cert path must fail before connect");
        assert!(
            format!("{err:#}").contains(PG_SSL_ROOT_CERT_PATH_ENV),
            "error must identify env var: {err:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    #[allow(clippy::expect_used)]
    fn build_pg_config_rejects_unreadable_ssl_root_cert_path() {
        use std::os::unix::fs::PermissionsExt;

        let unreadable = write_unreadable_temp_file("unreadable-pg-root-ca.pem", b"test ca");
        let err = build_pg_config_from(|name| {
            if name == PG_SSL_ROOT_CERT_PATH_ENV {
                Some(unreadable.display().to_string())
            } else {
                full_pg_get(name)
            }
        })
        .expect_err("unreadable root cert path must fail before connect");
        let mut permissions = std::fs::metadata(&unreadable)
            .expect("metadata unreadable temp file")
            .permissions();
        permissions.set_mode(0o600);
        std::fs::set_permissions(&unreadable, permissions).expect("restore temp file permissions");
        assert!(
            format!("{err:#}").contains(PG_SSL_ROOT_CERT_PATH_ENV),
            "error must identify env var: {err:#}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn legacy_config_plaintext_policy_defaults_to_deny() {
        let policy = legacy_config_plaintext_policy_from(|_| None).expect("policy");
        assert_eq!(policy, LegacyConfigPlaintextPolicy::Deny);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn legacy_config_plaintext_policy_allows_explicit_temporary_values() {
        for raw in ["true", "1", "yes", " TRUE "] {
            let policy = legacy_config_plaintext_policy_from(|n| {
                (n == SETTINGS_ALLOW_LEGACY_PLAINTEXT_CONFIG_VALUES_ENV).then(|| raw.to_string())
            })
            .expect("policy");
            assert_eq!(
                policy,
                LegacyConfigPlaintextPolicy::AllowTemporary,
                "{SETTINGS_ALLOW_LEGACY_PLAINTEXT_CONFIG_VALUES_ENV}={raw:?}"
            );
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn legacy_config_plaintext_policy_denies_explicit_false_values() {
        for raw in ["false", "0", "no", " FALSE "] {
            let policy = legacy_config_plaintext_policy_from(|n| {
                (n == SETTINGS_ALLOW_LEGACY_PLAINTEXT_CONFIG_VALUES_ENV).then(|| raw.to_string())
            })
            .expect("policy");
            assert_eq!(
                policy,
                LegacyConfigPlaintextPolicy::Deny,
                "{SETTINGS_ALLOW_LEGACY_PLAINTEXT_CONFIG_VALUES_ENV}={raw:?}"
            );
        }
    }

    #[test]
    fn legacy_config_plaintext_policy_rejects_invalid_value() {
        let result = legacy_config_plaintext_policy_from(|n| {
            (n == SETTINGS_ALLOW_LEGACY_PLAINTEXT_CONFIG_VALUES_ENV).then(|| "enabled".to_string())
        });
        let err = result.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(
            err.contains(SETTINGS_ALLOW_LEGACY_PLAINTEXT_CONFIG_VALUES_ENV),
            "error must identify env var: {err}"
        );
    }

    // ── build_readiness_interval_from 测试 ────────────────────────────────────────────────

    /// 未配置 → 静默取默认 5s（非显式误配，不 warn）。
    #[test]
    fn build_readiness_interval_default_when_missing() {
        let d = build_readiness_interval_from(|_| None);
        assert_eq!(d, DEFAULT_READINESS_INTERVAL, "缺省 → 5s");
    }

    /// 合法正整数（在 1..=300 范围内）→ 对应秒数。
    #[test]
    fn build_readiness_interval_custom_value() {
        let d = build_readiness_interval_from(|n| {
            (n == "RSS_PG_READINESS_SAMPLE_INTERVAL_SECS").then(|| "10".to_string())
        });
        assert_eq!(d, Duration::from_secs(10));
    }

    /// 显式非法（非数字 / 0）→ warn + 默认 5s（fail-soft；间隔是 hint 非强依赖）。
    #[test]
    fn build_readiness_interval_invalid_falls_back() {
        let d1 = build_readiness_interval_from(|n| {
            (n == "RSS_PG_READINESS_SAMPLE_INTERVAL_SECS").then(|| "not-a-number".to_string())
        });
        assert_eq!(d1, DEFAULT_READINESS_INTERVAL, "非数字 → warn + 默认");
        let d2 = build_readiness_interval_from(|n| {
            (n == "RSS_PG_READINESS_SAMPLE_INTERVAL_SECS").then(|| "0".to_string())
        });
        assert_eq!(d2, DEFAULT_READINESS_INTERVAL, "0 → warn + 默认");
    }

    /// 越界（> MAX_READINESS_INTERVAL_SECS=300）→ warn + 默认 5s。
    #[test]
    fn build_readiness_interval_above_max_warns_and_defaults() {
        let d = build_readiness_interval_from(|n| {
            (n == "RSS_PG_READINESS_SAMPLE_INTERVAL_SECS").then(|| "999".to_string())
        });
        assert_eq!(d, DEFAULT_READINESS_INTERVAL, "999 > 300 → warn + 默认 5s");
    }

    /// 下边界 1s → 对应（合法最小值）。
    #[test]
    fn build_readiness_interval_boundary_min() {
        let d = build_readiness_interval_from(|n| {
            (n == "RSS_PG_READINESS_SAMPLE_INTERVAL_SECS").then(|| "1".to_string())
        });
        assert_eq!(d, Duration::from_secs(1), "1 → 1s（合法下边界）");
    }

    /// 上边界 300s → 对应（合法最大值）。
    #[test]
    fn build_readiness_interval_boundary_max() {
        let d = build_readiness_interval_from(|n| {
            (n == "RSS_PG_READINESS_SAMPLE_INTERVAL_SECS").then(|| "300".to_string())
        });
        assert_eq!(d, Duration::from_secs(300), "300 → 300s（合法上边界）");
    }
}
