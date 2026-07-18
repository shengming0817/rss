use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context as _;
use postgres::{LegacyConfigPlaintextPolicy, PgConfig, PgPassword, PgSslMode, PgTenantReadConfig};

use crate::config::SnapshotConfig;

// ── postgres 配置 wiring ─────────────────────────────────────────────────────────────────────

const PG_HOST_ENV: &str = "RSS_PG_HOST";
const PG_PORT_ENV: &str = "RSS_PG_PORT";
const PG_DATABASE_ENV: &str = "RSS_PG_DATABASE";
const PG_SSL_MODE_ENV: &str = "RSS_PG_SSL_MODE";
const PG_SSL_ROOT_CERT_PATH_ENV: &str = "RSS_PG_SSL_ROOT_CERT_PATH";
const PG_WRITER_MAX_CONNECTIONS_ENV: &str = "RSS_PG_MAX_CONNECTIONS";
const PG_READER_MAX_CONNECTIONS_ENV: &str = "RSS_PG_READ_MAX_CONNECTIONS";
const PG_READINESS_INTERVAL_ENV: &str = "RSS_PG_READINESS_SAMPLE_INTERVAL_SECS";
const PG_USERNAME_ENV: &str = "RSS_PG_USERNAME";
const PG_PASSWORD_ENV: &str = "RSS_PG_PASSWORD";
const PG_READ_USERNAME_ENV: &str = "RSS_PG_READ_USERNAME";
const PG_READ_PASSWORD_ENV: &str = "RSS_PG_READ_PASSWORD";
const PG_MIGRATOR_USERNAME_ENV: &str = "RSS_PG_MIGRATOR_USERNAME";
const PG_MIGRATOR_PASSWORD_ENV: &str = "RSS_PG_MIGRATOR_PASSWORD";
const PG_AUDIT_ADMIN_USERNAME_ENV: &str = "RSS_PG_AUDIT_ADMIN_USERNAME";
const PG_AUDIT_ADMIN_PASSWORD_ENV: &str = "RSS_PG_AUDIT_ADMIN_PASSWORD";
const PG_DLX_ARCHIVER_USERNAME_ENV: &str = "RSS_PG_DLX_ARCHIVER_USERNAME";
const PG_DLX_ARCHIVER_PASSWORD_ENV: &str = "RSS_PG_DLX_ARCHIVER_PASSWORD";
const PG_DLX_VERIFIER_USERNAME_ENV: &str = "RSS_PG_DLX_VERIFIER_USERNAME";
const PG_DLX_VERIFIER_PASSWORD_ENV: &str = "RSS_PG_DLX_VERIFIER_PASSWORD";
const PG_DLX_PURGER_USERNAME_ENV: &str = "RSS_PG_DLX_PURGER_USERNAME";
const PG_DLX_PURGER_PASSWORD_ENV: &str = "RSS_PG_DLX_PURGER_PASSWORD";
const DEFAULT_SERVING_LANE_MAX_CONNECTIONS: u32 = 5;
const MAX_SERVING_LANE_MAX_CONNECTIONS: u32 = 100;
const SETTINGS_ALLOW_LEGACY_PLAINTEXT_CONFIG_VALUES_ENV: &str =
    "RSS_SETTINGS_ALLOW_LEGACY_PLAINTEXT_CONFIG_VALUES";

#[derive(Clone, Copy)]
struct PgRoleKeys {
    username: &'static str,
    password: &'static str,
}

const PG_SERVING_ROLE_KEYS: PgRoleKeys = PgRoleKeys {
    username: PG_USERNAME_ENV,
    password: PG_PASSWORD_ENV,
};
const PG_TENANT_READ_ROLE_KEYS: PgRoleKeys = PgRoleKeys {
    username: PG_READ_USERNAME_ENV,
    password: PG_READ_PASSWORD_ENV,
};
const PG_MIGRATOR_ROLE_KEYS: PgRoleKeys = PgRoleKeys {
    username: PG_MIGRATOR_USERNAME_ENV,
    password: PG_MIGRATOR_PASSWORD_ENV,
};
const PG_AUDIT_ADMIN_ROLE_KEYS: PgRoleKeys = PgRoleKeys {
    username: PG_AUDIT_ADMIN_USERNAME_ENV,
    password: PG_AUDIT_ADMIN_PASSWORD_ENV,
};
const PG_DLX_ARCHIVER_ROLE_KEYS: PgRoleKeys = PgRoleKeys {
    username: PG_DLX_ARCHIVER_USERNAME_ENV,
    password: PG_DLX_ARCHIVER_PASSWORD_ENV,
};
const PG_DLX_VERIFIER_ROLE_KEYS: PgRoleKeys = PgRoleKeys {
    username: PG_DLX_VERIFIER_USERNAME_ENV,
    password: PG_DLX_VERIFIER_PASSWORD_ENV,
};
const PG_DLX_PURGER_ROLE_KEYS: PgRoleKeys = PgRoleKeys {
    username: PG_DLX_PURGER_USERNAME_ENV,
    password: PG_DLX_PURGER_PASSWORD_ENV,
};

/// One immutable, fully parsed PostgreSQL configuration generation.
///
/// Private fields prevent callers from assembling a mixed-generation bundle. The only production
/// constructor accepts the unforgeable snapshot capability, and [`Self::into_parts`] consumes the
/// bundle before any pool is built.
pub(crate) struct PgRuntimeConfig {
    serving: PgConfig,
    tenant_read: PgTenantReadConfig,
    migrator: PgConfig,
    audit_admin: Option<PgConfig>,
    dlx_archiver: PgConfig,
    dlx_verifier: PgConfig,
    dlx_purger: PgConfig,
    legacy_policy: LegacyConfigPlaintextPolicy,
    readiness_period: Duration,
}

/// Named consumed form; names keep PostgreSQL roles impossible to transpose by tuple position at
/// the composition root.
pub(crate) struct PgRuntimeConfigParts {
    pub(crate) serving: PgConfig,
    pub(crate) tenant_read: PgTenantReadConfig,
    pub(crate) migrator: PgConfig,
    pub(crate) audit_admin: Option<PgConfig>,
    pub(crate) dlx_archiver: PgConfig,
    pub(crate) dlx_verifier: PgConfig,
    pub(crate) dlx_purger: PgConfig,
    pub(crate) legacy_policy: LegacyConfigPlaintextPolicy,
    pub(crate) readiness_period: Duration,
}

struct PgSharedValues {
    host: String,
    port: u16,
    database: String,
    ssl_mode: PgSslMode,
    ssl_root_cert: Option<PathBuf>,
}

impl PgSharedValues {
    fn from_snapshot(config: SnapshotConfig<'_>) -> anyhow::Result<Self> {
        let host = required_value(config, PG_HOST_ENV)?;
        let port_raw = required_value(config, PG_PORT_ENV)?;
        let port = port_raw.parse::<u16>().with_context(|| {
            format!("{PG_PORT_ENV} must be a valid port number (1-65535): {port_raw}")
        })?;
        let database = required_value(config, PG_DATABASE_ENV)?;
        let ssl_mode = parse_pg_ssl_mode(config.value(PG_SSL_MODE_ENV).map(str::to_owned));
        let ssl_root_cert =
            pg_ssl_root_cert_path_from_value(config.value(PG_SSL_ROOT_CERT_PATH_ENV))?;
        Ok(Self {
            host,
            port,
            database,
            ssl_mode,
            ssl_root_cert,
        })
    }

    fn role_config(
        &self,
        config: SnapshotConfig<'_>,
        keys: PgRoleKeys,
    ) -> anyhow::Result<PgConfig> {
        let username = required_value(config, keys.username)?;
        let password = required_value(config, keys.password)?;
        Ok(self.config(username, password))
    }

    fn optional_audit_config(
        &self,
        config: SnapshotConfig<'_>,
    ) -> anyhow::Result<Option<PgConfig>> {
        let username = config.value(PG_AUDIT_ADMIN_ROLE_KEYS.username);
        let password = config.value(PG_AUDIT_ADMIN_ROLE_KEYS.password);
        match (username, password) {
            (None, None) => Ok(None),
            (Some(username), Some(password)) => {
                Ok(Some(self.config(username.to_owned(), password.to_owned())))
            }
            (None, Some(_)) => Err(missing_required_value(PG_AUDIT_ADMIN_ROLE_KEYS.username)),
            (Some(_), None) => Err(missing_required_value(PG_AUDIT_ADMIN_ROLE_KEYS.password)),
        }
    }

    fn config(&self, username: String, password: String) -> PgConfig {
        let mut config = PgConfig::new(
            self.host.clone(),
            self.port,
            self.database.clone(),
            username,
            PgPassword::new(password),
        )
        .with_ssl_mode(self.ssl_mode);
        if let Some(path) = self.ssl_root_cert.clone() {
            config = config.with_ssl_root_cert(path);
        }
        config
    }
}

impl PgRuntimeConfig {
    pub(crate) fn from_snapshot(config: SnapshotConfig<'_>) -> anyhow::Result<Self> {
        let shared = PgSharedValues::from_snapshot(config)?;
        let serving = apply_serving_lane_pool_limit_from_value(
            shared.role_config(config, PG_SERVING_ROLE_KEYS)?,
            config.value(PG_WRITER_MAX_CONNECTIONS_ENV),
            PG_WRITER_MAX_CONNECTIONS_ENV,
        )?;
        let tenant_read = PgTenantReadConfig::new(apply_serving_lane_pool_limit_from_value(
            shared.role_config(config, PG_TENANT_READ_ROLE_KEYS)?,
            config.value(PG_READER_MAX_CONNECTIONS_ENV),
            PG_READER_MAX_CONNECTIONS_ENV,
        )?);
        let migrator = shared.role_config(config, PG_MIGRATOR_ROLE_KEYS)?;
        let audit_admin = shared.optional_audit_config(config)?;
        let dlx_archiver = shared.role_config(config, PG_DLX_ARCHIVER_ROLE_KEYS)?;
        let dlx_verifier = shared.role_config(config, PG_DLX_VERIFIER_ROLE_KEYS)?;
        let dlx_purger = shared.role_config(config, PG_DLX_PURGER_ROLE_KEYS)?;
        let legacy_policy = legacy_config_plaintext_policy_from_value(
            config.value(SETTINGS_ALLOW_LEGACY_PLAINTEXT_CONFIG_VALUES_ENV),
        )?;
        let readiness_period =
            pg_readiness_interval_from_value(config.value(PG_READINESS_INTERVAL_ENV));
        Ok(Self {
            serving,
            tenant_read,
            migrator,
            audit_admin,
            dlx_archiver,
            dlx_verifier,
            dlx_purger,
            legacy_policy,
            readiness_period,
        })
    }

    pub(crate) fn into_parts(self) -> PgRuntimeConfigParts {
        PgRuntimeConfigParts {
            serving: self.serving,
            tenant_read: self.tenant_read,
            migrator: self.migrator,
            audit_admin: self.audit_admin,
            dlx_archiver: self.dlx_archiver,
            dlx_verifier: self.dlx_verifier,
            dlx_purger: self.dlx_purger,
            legacy_policy: self.legacy_policy,
            readiness_period: self.readiness_period,
        }
    }
}

fn apply_serving_lane_pool_limit_from_value(
    config: PgConfig,
    raw: Option<&str>,
    env: &'static str,
) -> anyhow::Result<PgConfig> {
    let max = match raw {
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

/// Build the migration role from the caller's captured process generation.
pub(crate) fn build_pg_migrator_config(config: SnapshotConfig<'_>) -> anyhow::Result<PgConfig> {
    PgSharedValues::from_snapshot(config)?.role_config(config, PG_MIGRATOR_ROLE_KEYS)
}

/// Build the two roles needed by audit-ledger maintenance from one captured generation.
pub(crate) fn build_pg_audit_maintenance_config(
    config: SnapshotConfig<'_>,
) -> anyhow::Result<(PgConfig, Option<PgConfig>)> {
    let shared = PgSharedValues::from_snapshot(config)?;
    let migrator = shared.role_config(config, PG_MIGRATOR_ROLE_KEYS)?;
    let audit_admin = shared.optional_audit_config(config)?;
    Ok((migrator, audit_admin))
}

fn required_value(config: SnapshotConfig<'_>, name: &'static str) -> anyhow::Result<String> {
    config
        .value(name)
        .map(str::to_owned)
        .ok_or_else(|| missing_required_value(name))
}

fn missing_required_value(name: &'static str) -> anyhow::Error {
    anyhow::anyhow!("missing required env var: {name}")
}

fn pg_ssl_root_cert_path_from_value(raw: Option<&str>) -> anyhow::Result<Option<PathBuf>> {
    let Some(raw) = raw else {
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
/// 安全姿态非强依赖配置，故误配 fail-soft（warn + 安全默认）而非 fail-fast——与 readiness value parser
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
                env = PG_SSL_MODE_ENV,
                raw = %raw,
                "invalid pg ssl mode (need disable|allow|prefer|require|verify-ca|verify-full); \
                 falling back to verify-full (zero-trust)"
            );
            PgSslMode::VerifyFull
        }
    }
}

fn legacy_config_plaintext_policy_from_value(
    raw: Option<&str>,
) -> anyhow::Result<LegacyConfigPlaintextPolicy> {
    let Some(raw) = raw else {
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
fn pg_readiness_interval_from_value(raw: Option<&str>) -> Duration {
    match raw {
        None => DEFAULT_READINESS_INTERVAL,
        Some(raw) => match raw.parse::<u64>() {
            Ok(n) if (1..=MAX_READINESS_INTERVAL_SECS).contains(&n) => Duration::from_secs(n),
            _ => {
                tracing::warn!(
                    env = PG_READINESS_INTERVAL_ENV,
                    raw = %raw,
                    max_secs = MAX_READINESS_INTERVAL_SECS,
                    "invalid readiness sample interval (need 1..=300s); using default 5s"
                );
                DEFAULT_READINESS_INTERVAL
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use postgres::LegacyConfigPlaintextPolicy;
    use std::time::Duration;

    struct GetterSource<F>(F);

    impl<F> crate::config::RuntimeConfigSource for GetterSource<F>
    where
        F: Fn(&str) -> Option<String>,
    {
        fn read(
            &mut self,
            key: &crate::config::RuntimeConfigKey,
        ) -> crate::config::CapturedConfigValue {
            (self.0)(key.as_str()).map_or(crate::config::CapturedConfigValue::Missing, |value| {
                crate::config::CapturedConfigValue::Present(secure::SecretText::from_string(value))
            })
        }
    }

    fn snapshot_from_get(
        get: impl Fn(&str) -> Option<String>,
    ) -> anyhow::Result<crate::config::RuntimeConfigSnapshot> {
        Ok(crate::config::RuntimeConfigSnapshot::capture_test(
            GetterSource(get),
        )?)
    }

    fn build_pg_config_from(get: impl Fn(&str) -> Option<String>) -> anyhow::Result<PgConfig> {
        let snapshot = snapshot_from_get(get)?;
        let config = snapshot.view();
        apply_serving_lane_pool_limit_from_value(
            PgSharedValues::from_snapshot(config)?.role_config(config, PG_SERVING_ROLE_KEYS)?,
            config.value(PG_WRITER_MAX_CONNECTIONS_ENV),
            PG_WRITER_MAX_CONNECTIONS_ENV,
        )
    }

    fn build_pg_read_config_from(
        get: impl Fn(&str) -> Option<String>,
    ) -> anyhow::Result<PgTenantReadConfig> {
        let snapshot = snapshot_from_get(get)?;
        let config = snapshot.view();
        apply_serving_lane_pool_limit_from_value(
            PgSharedValues::from_snapshot(config)?.role_config(config, PG_TENANT_READ_ROLE_KEYS)?,
            config.value(PG_READER_MAX_CONNECTIONS_ENV),
            PG_READER_MAX_CONNECTIONS_ENV,
        )
        .map(PgTenantReadConfig::new)
    }

    fn build_pg_audit_admin_config_from(
        get: impl Fn(&str) -> Option<String>,
    ) -> anyhow::Result<Option<PgConfig>> {
        let snapshot = snapshot_from_get(get)?;
        PgSharedValues::from_snapshot(snapshot.view())?.optional_audit_config(snapshot.view())
    }

    macro_rules! role_builder {
        ($name:ident, $keys:expr) => {
            fn $name(get: impl Fn(&str) -> Option<String>) -> anyhow::Result<PgConfig> {
                let snapshot = snapshot_from_get(get)?;
                let config = snapshot.view();
                PgSharedValues::from_snapshot(config)?.role_config(config, $keys)
            }
        };
    }

    role_builder!(build_pg_migrator_config_from, PG_MIGRATOR_ROLE_KEYS);
    role_builder!(build_pg_dlx_archiver_config_from, PG_DLX_ARCHIVER_ROLE_KEYS);
    role_builder!(build_pg_dlx_verifier_config_from, PG_DLX_VERIFIER_ROLE_KEYS);
    role_builder!(build_pg_dlx_purger_config_from, PG_DLX_PURGER_ROLE_KEYS);

    fn legacy_config_plaintext_policy_from(
        get: impl Fn(&str) -> Option<String>,
    ) -> anyhow::Result<LegacyConfigPlaintextPolicy> {
        let snapshot = snapshot_from_get(get)?;
        legacy_config_plaintext_policy_from_value(
            snapshot
                .view()
                .value(SETTINGS_ALLOW_LEGACY_PLAINTEXT_CONFIG_VALUES_ENV),
        )
    }

    #[allow(clippy::expect_used)]
    fn build_readiness_interval_from(get: impl Fn(&str) -> Option<String>) -> Duration {
        let snapshot = snapshot_from_get(get).expect("closed test catalog");
        pg_readiness_interval_from_value(snapshot.view().value(PG_READINESS_INTERVAL_ENV))
    }

    fn full_runtime_get(name: &str) -> Option<String> {
        Some(
            match name {
                PG_HOST_ENV => "pg.snapshot.internal",
                PG_PORT_ENV => "5439",
                PG_DATABASE_ENV => "rss_snapshot",
                PG_SSL_MODE_ENV => "require",
                PG_USERNAME_ENV => "rss_app_snapshot",
                PG_PASSWORD_ENV => "app-snapshot-secret",
                PG_READ_USERNAME_ENV => "rss_app_read_snapshot",
                PG_READ_PASSWORD_ENV => "reader-snapshot-secret",
                PG_MIGRATOR_USERNAME_ENV => "rss_migrator_snapshot",
                PG_MIGRATOR_PASSWORD_ENV => "migrator-snapshot-secret",
                PG_AUDIT_ADMIN_USERNAME_ENV => "rss_audit_admin_snapshot",
                PG_AUDIT_ADMIN_PASSWORD_ENV => "audit-admin-snapshot-secret",
                PG_DLX_ARCHIVER_USERNAME_ENV => "rss_dlx_archiver_snapshot",
                PG_DLX_ARCHIVER_PASSWORD_ENV => "archiver-snapshot-secret",
                PG_DLX_VERIFIER_USERNAME_ENV => "rss_dlx_verifier_snapshot",
                PG_DLX_VERIFIER_PASSWORD_ENV => "verifier-snapshot-secret",
                PG_DLX_PURGER_USERNAME_ENV => "rss_dlx_purger_snapshot",
                PG_DLX_PURGER_PASSWORD_ENV => "purger-snapshot-secret",
                SETTINGS_ALLOW_LEGACY_PLAINTEXT_CONFIG_VALUES_ENV => "true",
                PG_READINESS_INTERVAL_ENV => "19",
                _ => return None,
            }
            .to_owned(),
        )
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn runtime_infra_pg_snapshot_maps_named_roles_policy_readiness_and_redacts_secrets() {
        let snapshot = snapshot_from_get(full_runtime_get).expect("snapshot");
        let parts = PgRuntimeConfig::from_snapshot(snapshot.view())
            .expect("runtime config")
            .into_parts();
        for (config, role) in [
            (&parts.serving, "rss_app_snapshot"),
            (&parts.migrator, "rss_migrator_snapshot"),
            (&parts.dlx_archiver, "rss_dlx_archiver_snapshot"),
            (&parts.dlx_verifier, "rss_dlx_verifier_snapshot"),
            (&parts.dlx_purger, "rss_dlx_purger_snapshot"),
        ] {
            let debug = format!("{config:?}");
            assert!(debug.contains(role), "{debug}");
            assert!(!debug.contains("-snapshot-secret"), "{debug}");
        }
        let reader = format!("{:?}", parts.tenant_read);
        assert!(reader.contains("rss_app_read_snapshot"), "{reader}");
        assert!(!reader.contains("reader-snapshot-secret"), "{reader}");
        let audit = format!("{:?}", parts.audit_admin.expect("audit role"));
        assert!(audit.contains("rss_audit_admin_snapshot"));
        assert!(!audit.contains("audit-admin-snapshot-secret"));
        assert_eq!(
            parts.legacy_policy,
            LegacyConfigPlaintextPolicy::AllowTemporary
        );
        assert_eq!(parts.readiness_period, Duration::from_secs(19));
    }

    #[test]
    #[allow(clippy::expect_used, clippy::panic)]
    fn runtime_infra_pg_snapshot_never_falls_back_and_preserves_optional_audit_pair() {
        for missing in [
            PG_READ_USERNAME_ENV,
            PG_READ_PASSWORD_ENV,
            PG_MIGRATOR_USERNAME_ENV,
            PG_DLX_ARCHIVER_PASSWORD_ENV,
            PG_DLX_VERIFIER_USERNAME_ENV,
            PG_DLX_PURGER_PASSWORD_ENV,
        ] {
            let snapshot = snapshot_from_get(|name| {
                (name != missing).then(|| full_runtime_get(name)).flatten()
            })
            .expect("snapshot");
            let error = match PgRuntimeConfig::from_snapshot(snapshot.view()) {
                Ok(_) => panic!("missing narrow role must fail"),
                Err(error) => error,
            };
            assert!(error.to_string().contains(missing), "{error:#}");
        }

        let snapshot = snapshot_from_get(|name| {
            (name != PG_AUDIT_ADMIN_ROLE_KEYS.username && name != PG_AUDIT_ADMIN_ROLE_KEYS.password)
                .then(|| full_runtime_get(name))
                .flatten()
        })
        .expect("snapshot");
        assert!(
            PgRuntimeConfig::from_snapshot(snapshot.view())
                .expect("absent audit pair")
                .into_parts()
                .audit_admin
                .is_none()
        );
        for missing in [PG_AUDIT_ADMIN_USERNAME_ENV, PG_AUDIT_ADMIN_PASSWORD_ENV] {
            let snapshot = snapshot_from_get(|name| {
                (name != missing).then(|| full_runtime_get(name)).flatten()
            })
            .expect("snapshot");
            let error = match PgRuntimeConfig::from_snapshot(snapshot.view()) {
                Ok(_) => panic!("half audit pair must fail"),
                Err(error) => error,
            };
            assert!(error.to_string().contains(missing), "{error:#}");
        }
    }

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
            PG_HOST_ENV => Some("postgres".to_string()),
            PG_PORT_ENV => Some("5432".to_string()),
            PG_DATABASE_ENV => Some("rss".to_string()),
            PG_USERNAME_ENV => Some("rss_app".to_string()),
            PG_PASSWORD_ENV => Some("app_pw".to_string()),
            _ => None,
        });
        match result {
            Ok(_) => panic!("missing migrator username should fail"),
            Err(err) => assert!(err.to_string().contains(PG_MIGRATOR_USERNAME_ENV)),
        }
    }

    #[allow(clippy::panic)]
    #[test]
    fn pg_migrator_config_uses_dedicated_credentials() {
        let cfg = match build_pg_migrator_config_from(|name| match name {
            PG_HOST_ENV => Some("postgres".to_string()),
            PG_PORT_ENV => Some("5432".to_string()),
            PG_DATABASE_ENV => Some("rss".to_string()),
            PG_USERNAME_ENV => Some("rss_app".to_string()),
            PG_PASSWORD_ENV => Some("app_pw".to_string()),
            PG_MIGRATOR_USERNAME_ENV => Some("postgres".to_string()),
            PG_MIGRATOR_PASSWORD_ENV => Some("owner_pw".to_string()),
            PG_SSL_MODE_ENV => Some("disable".to_string()),
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
            Err(err) => assert!(err.to_string().contains(PG_READ_USERNAME_ENV)),
        }

        let missing_password = build_pg_read_config_from(|name| match name {
            PG_READ_USERNAME_ENV => Some("rss_app_read".to_string()),
            _ => full_pg_get(name),
        });
        match missing_password {
            Ok(_) => panic!("reader username without reader password must fail"),
            Err(err) => assert!(err.to_string().contains(PG_READ_PASSWORD_ENV)),
        }
    }

    #[allow(clippy::panic)]
    #[test]
    fn pg_read_config_uses_dedicated_credentials() {
        let cfg = build_pg_read_config_from(|name| match name {
            PG_READ_USERNAME_ENV => Some("rss_app_read".to_string()),
            PG_READ_PASSWORD_ENV => Some("read_pw".to_string()),
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
            PG_READ_USERNAME_ENV => Some("rss_app_read".to_string()),
            PG_READ_PASSWORD_ENV => Some("read_pw".to_string()),
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
            PG_READ_USERNAME_ENV => Some("rss_app_read".to_string()),
            PG_READ_PASSWORD_ENV => Some("read_pw".to_string()),
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
                    PG_READ_USERNAME_ENV => Some("rss_app_read".to_string()),
                    PG_READ_PASSWORD_ENV => Some("read_pw".to_string()),
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
            PG_READ_USERNAME_ENV => Some("rss_app_read".to_string()),
            PG_READ_PASSWORD_ENV => Some("read_pw".to_string()),
            PG_SSL_MODE_ENV => Some("verify-ca".to_string()),
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
            Err(err) => assert!(err.to_string().contains(PG_DLX_ARCHIVER_USERNAME_ENV)),
        }

        let missing_password = build_pg_dlx_archiver_config_from(|name| match name {
            PG_DLX_ARCHIVER_USERNAME_ENV => Some("rss_dlx_archiver".to_string()),
            _ => full_pg_get(name),
        });
        match missing_password {
            Ok(_) => panic!("missing DLX archiver password should fail"),
            Err(err) => assert!(err.to_string().contains(PG_DLX_ARCHIVER_PASSWORD_ENV)),
        }

        let cfg = match build_pg_dlx_archiver_config_from(|name| match name {
            PG_DLX_ARCHIVER_USERNAME_ENV => Some("rss_dlx_archiver".to_string()),
            PG_DLX_ARCHIVER_PASSWORD_ENV => Some("dlx_pw".to_string()),
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
            PG_DLX_VERIFIER_USERNAME_ENV => Some("rss_dlx_verifier".to_string()),
            PG_DLX_VERIFIER_PASSWORD_ENV => Some("verify_pw".to_string()),
            _ => full_pg_get(name),
        })
        .unwrap_or_else(|error| panic!("DLX verifier config: {error}"));
        let purger = build_pg_dlx_purger_config_from(|name| match name {
            PG_DLX_PURGER_USERNAME_ENV => Some("rss_dlx_purger".to_string()),
            PG_DLX_PURGER_PASSWORD_ENV => Some("purge_pw".to_string()),
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
                .contains(PG_DLX_VERIFIER_USERNAME_ENV)
        );
        let missing_purger = match build_pg_dlx_purger_config_from(full_pg_get) {
            Ok(_) => panic!("purger credentials are mandatory"),
            Err(error) => error,
        };
        assert!(
            missing_purger
                .to_string()
                .contains(PG_DLX_PURGER_USERNAME_ENV)
        );
    }

    // ── build_pg_config_from 测试 ──────────────────────────────────────────────────────────

    fn full_pg_get(k: &str) -> Option<String> {
        match k {
            PG_HOST_ENV => Some("pg.internal".to_string()),
            PG_PORT_ENV => Some("5432".to_string()),
            PG_DATABASE_ENV => Some("rss_db".to_string()),
            PG_USERNAME_ENV => Some("rss_app".to_string()),
            PG_PASSWORD_ENV => Some("s3cr3t".to_string()),
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
            PG_AUDIT_ADMIN_USERNAME_ENV => Some("rss_audit_admin".to_string()),
            _ => full_pg_get(k),
        })
        .expect_err("missing password must fail");
        assert!(
            missing_password
                .to_string()
                .contains(PG_AUDIT_ADMIN_PASSWORD_ENV)
        );

        let missing_username = build_pg_audit_admin_config_from(|k| match k {
            PG_AUDIT_ADMIN_PASSWORD_ENV => Some("admin_pw".to_string()),
            _ => full_pg_get(k),
        })
        .expect_err("missing username must fail");
        assert!(
            missing_username
                .to_string()
                .contains(PG_AUDIT_ADMIN_USERNAME_ENV)
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn build_pg_audit_admin_config_happy() {
        let cfg = build_pg_audit_admin_config_from(|k| match k {
            PG_AUDIT_ADMIN_USERNAME_ENV => Some("rss_audit_admin".to_string()),
            PG_AUDIT_ADMIN_PASSWORD_ENV => Some("admin_pw".to_string()),
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
            if k == PG_HOST_ENV {
                None
            } else {
                full_pg_get(k)
            }
        };
        let err = build_pg_config_from(get).expect_err("host required");
        assert!(
            err.to_string().contains(PG_HOST_ENV),
            "error contains var name"
        );
    }

    /// `RSS_PG_PASSWORD` 缺失 → Err 含变量名（fail-fast）。
    #[test]
    #[allow(clippy::expect_used)]
    fn build_pg_config_from_missing_password() {
        let get = |k: &str| {
            if k == PG_PASSWORD_ENV {
                None
            } else {
                full_pg_get(k)
            }
        };
        let err = build_pg_config_from(get).expect_err("password required");
        assert!(
            err.to_string().contains(PG_PASSWORD_ENV),
            "error contains var name"
        );
    }

    /// `RSS_PG_PORT` 缺失 → Err 含变量名（fail-fast）。
    #[test]
    #[allow(clippy::expect_used)]
    fn build_pg_config_from_missing_port() {
        let get = |k: &str| {
            if k == PG_PORT_ENV {
                None
            } else {
                full_pg_get(k)
            }
        };
        let err = build_pg_config_from(get).expect_err("port required");
        assert!(
            err.to_string().contains(PG_PORT_ENV),
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
            assert_eq!(got, expected, "{PG_SSL_MODE_ENV}={raw:?}");
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
            PG_MIGRATOR_USERNAME_ENV => Some("rss_migrator".to_string()),
            PG_MIGRATOR_PASSWORD_ENV => Some("migrator-secret".to_string()),
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
            (n == PG_READINESS_INTERVAL_ENV).then(|| "10".to_string())
        });
        assert_eq!(d, Duration::from_secs(10));
    }

    /// 显式非法（非数字 / 0）→ warn + 默认 5s（fail-soft；间隔是 hint 非强依赖）。
    #[test]
    fn build_readiness_interval_invalid_falls_back() {
        let d1 = build_readiness_interval_from(|n| {
            (n == PG_READINESS_INTERVAL_ENV).then(|| "not-a-number".to_string())
        });
        assert_eq!(d1, DEFAULT_READINESS_INTERVAL, "非数字 → warn + 默认");
        let d2 = build_readiness_interval_from(|n| {
            (n == PG_READINESS_INTERVAL_ENV).then(|| "0".to_string())
        });
        assert_eq!(d2, DEFAULT_READINESS_INTERVAL, "0 → warn + 默认");
    }

    /// 越界（> MAX_READINESS_INTERVAL_SECS=300）→ warn + 默认 5s。
    #[test]
    fn build_readiness_interval_above_max_warns_and_defaults() {
        let d = build_readiness_interval_from(|n| {
            (n == PG_READINESS_INTERVAL_ENV).then(|| "999".to_string())
        });
        assert_eq!(d, DEFAULT_READINESS_INTERVAL, "999 > 300 → warn + 默认 5s");
    }

    /// 下边界 1s → 对应（合法最小值）。
    #[test]
    fn build_readiness_interval_boundary_min() {
        let d = build_readiness_interval_from(|n| {
            (n == PG_READINESS_INTERVAL_ENV).then(|| "1".to_string())
        });
        assert_eq!(d, Duration::from_secs(1), "1 → 1s（合法下边界）");
    }

    /// 上边界 300s → 对应（合法最大值）。
    #[test]
    fn build_readiness_interval_boundary_max() {
        let d = build_readiness_interval_from(|n| {
            (n == PG_READINESS_INTERVAL_ENV).then(|| "300".to_string())
        });
        assert_eq!(d, Duration::from_secs(300), "300 → 300s（合法上边界）");
    }
}
