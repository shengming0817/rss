use std::fs;
use std::path::{Component, Path};
use std::time::Duration;

use anyhow::Context as _;
use postgres::{
    PgConfig, PgL2DrRecoveryAuditConfig, PgL2DrRecoveryExecutorConfig, PgPassword, PgPrivateCa,
    PgProjectionOperatorConfig, PgProjectionSourceReadConfig, PgSagaOperatorConfig,
    PgTenantReadConfig,
};

use crate::config::{
    BUNDLE_PG_AUDIT_ADMIN_PASSWORD, BUNDLE_PG_DLX_ARCHIVER_PASSWORD, BUNDLE_PG_DLX_PURGER_PASSWORD,
    BUNDLE_PG_DLX_VERIFIER_PASSWORD, BUNDLE_PG_PASSWORD, BUNDLE_PG_READ_PASSWORD, SnapshotConfig,
};

// ── postgres 配置 wiring ─────────────────────────────────────────────────────────────────────

const PG_HOST_ENV: &str = "RSS_PG_HOST";
const PG_PORT_ENV: &str = "RSS_PG_PORT";
const PG_DATABASE_ENV: &str = "RSS_PG_DATABASE";
const PG_SSL_ROOT_CERT_PATH_ENV: &str = "RSS_PG_SSL_ROOT_CERT_PATH";
const PG_WRITER_MAX_CONNECTIONS_ENV: &str = "RSS_PG_MAX_CONNECTIONS";
const PG_READER_MAX_CONNECTIONS_ENV: &str = "RSS_PG_READ_MAX_CONNECTIONS";
const PG_READINESS_INTERVAL_ENV: &str = "RSS_PG_READINESS_SAMPLE_INTERVAL_SECS";
const PG_RLS_ATTESTATION_INTERVAL_ENV: &str = "RSS_PG_RLS_ATTESTATION_INTERVAL_SECS";
const PG_USERNAME_ENV: &str = "RSS_PG_USERNAME";
const PG_PASSWORD_FILE_ENV: &str = "RSS_PG_PASSWORD_FILE";
const PG_REMOVED_PASSWORD_ENV: &str = "RSS_PG_PASSWORD";
const PG_READ_USERNAME_ENV: &str = "RSS_PG_READ_USERNAME";
const PG_READ_PASSWORD_FILE_ENV: &str = "RSS_PG_READ_PASSWORD_FILE";
const PG_READ_REMOVED_PASSWORD_ENV: &str = "RSS_PG_READ_PASSWORD";
const PG_MIGRATOR_USERNAME_ENV: &str = "RSS_PG_MIGRATOR_USERNAME";
const PG_MIGRATOR_PASSWORD_FILE_ENV: &str = "RSS_PG_MIGRATOR_PASSWORD_FILE";
const PG_MIGRATOR_REMOVED_PASSWORD_ENV: &str = "RSS_PG_MIGRATOR_PASSWORD";
const PG_PROJECTION_READER_USERNAME_ENV: &str = "RSS_PG_PROJECTION_READER_USERNAME";
const PG_PROJECTION_READER_PASSWORD_FILE_ENV: &str = "RSS_PG_PROJECTION_READER_PASSWORD_FILE";
const PG_PROJECTION_READER_REMOVED_PASSWORD_ENV: &str = "RSS_PG_PROJECTION_READER_PASSWORD";
const PG_PROJECTION_OPERATOR_USERNAME_ENV: &str = "RSS_PG_PROJECTION_OPERATOR_USERNAME";
const PG_PROJECTION_OPERATOR_PASSWORD_FILE_ENV: &str = "RSS_PG_PROJECTION_OPERATOR_PASSWORD_FILE";
const PG_PROJECTION_OPERATOR_REMOVED_PASSWORD_ENV: &str = "RSS_PG_PROJECTION_OPERATOR_PASSWORD";
const PG_SAGA_OPERATOR_USERNAME_ENV: &str = "RSS_PG_SAGA_OPERATOR_USERNAME";
const PG_SAGA_OPERATOR_PASSWORD_FILE_ENV: &str = "RSS_PG_SAGA_OPERATOR_PASSWORD_FILE";
const PG_SAGA_OPERATOR_REMOVED_PASSWORD_ENV: &str = "RSS_PG_SAGA_OPERATOR_PASSWORD";
const PG_L2_DR_RECOVERY_AUDITOR_USERNAME_ENV: &str = "RSS_PG_L2_DR_RECOVERY_AUDITOR_USERNAME";
const PG_L2_DR_RECOVERY_AUDITOR_PASSWORD_FILE_ENV: &str =
    "RSS_PG_L2_DR_RECOVERY_AUDITOR_PASSWORD_FILE";
const PG_L2_DR_RECOVERY_AUDITOR_REMOVED_PASSWORD_ENV: &str =
    "RSS_PG_L2_DR_RECOVERY_AUDITOR_PASSWORD";
const PG_L2_DR_RECOVERY_EXECUTOR_USERNAME_ENV: &str = "RSS_PG_L2_DR_RECOVERY_EXECUTOR_USERNAME";
const PG_L2_DR_RECOVERY_EXECUTOR_PASSWORD_FILE_ENV: &str =
    "RSS_PG_L2_DR_RECOVERY_EXECUTOR_PASSWORD_FILE";
const PG_L2_DR_RECOVERY_EXECUTOR_REMOVED_PASSWORD_ENV: &str =
    "RSS_PG_L2_DR_RECOVERY_EXECUTOR_PASSWORD";
const PG_AUDIT_ADMIN_USERNAME_ENV: &str = "RSS_PG_AUDIT_ADMIN_USERNAME";
const PG_AUDIT_ADMIN_PASSWORD_FILE_ENV: &str = "RSS_PG_AUDIT_ADMIN_PASSWORD_FILE";
const PG_AUDIT_ADMIN_REMOVED_PASSWORD_ENV: &str = "RSS_PG_AUDIT_ADMIN_PASSWORD";
const PG_DLX_ARCHIVER_USERNAME_ENV: &str = "RSS_PG_DLX_ARCHIVER_USERNAME";
const PG_DLX_ARCHIVER_MAX_CONNECTIONS_ENV: &str = "RSS_PG_DLX_ARCHIVER_MAX_CONNECTIONS";
const PG_DLX_ARCHIVER_PASSWORD_FILE_ENV: &str = "RSS_PG_DLX_ARCHIVER_PASSWORD_FILE";
const PG_DLX_ARCHIVER_REMOVED_PASSWORD_ENV: &str = "RSS_PG_DLX_ARCHIVER_PASSWORD";
const PG_DLX_VERIFIER_USERNAME_ENV: &str = "RSS_PG_DLX_VERIFIER_USERNAME";
const PG_DLX_VERIFIER_MAX_CONNECTIONS_ENV: &str = "RSS_PG_DLX_VERIFIER_MAX_CONNECTIONS";
const PG_DLX_VERIFIER_PASSWORD_FILE_ENV: &str = "RSS_PG_DLX_VERIFIER_PASSWORD_FILE";
const PG_DLX_VERIFIER_REMOVED_PASSWORD_ENV: &str = "RSS_PG_DLX_VERIFIER_PASSWORD";
const PG_DLX_PURGER_USERNAME_ENV: &str = "RSS_PG_DLX_PURGER_USERNAME";
const PG_DLX_PURGER_MAX_CONNECTIONS_ENV: &str = "RSS_PG_DLX_PURGER_MAX_CONNECTIONS";
const PG_DLX_PURGER_PASSWORD_FILE_ENV: &str = "RSS_PG_DLX_PURGER_PASSWORD_FILE";
const PG_DLX_PURGER_REMOVED_PASSWORD_ENV: &str = "RSS_PG_DLX_PURGER_PASSWORD";
const DEFAULT_SERVING_LANE_MAX_CONNECTIONS: u32 = 5;
const MAX_SERVING_LANE_MAX_CONNECTIONS: u32 = 100;

#[derive(Clone, Copy)]
struct PgRoleKeys {
    username: &'static str,
    password_file: &'static str,
    removed_password: &'static str,
    bundle_password: Option<&'static str>,
}

const PG_SERVING_ROLE_KEYS: PgRoleKeys = PgRoleKeys {
    username: PG_USERNAME_ENV,
    password_file: PG_PASSWORD_FILE_ENV,
    removed_password: PG_REMOVED_PASSWORD_ENV,
    bundle_password: Some(BUNDLE_PG_PASSWORD),
};
const PG_TENANT_READ_ROLE_KEYS: PgRoleKeys = PgRoleKeys {
    username: PG_READ_USERNAME_ENV,
    password_file: PG_READ_PASSWORD_FILE_ENV,
    removed_password: PG_READ_REMOVED_PASSWORD_ENV,
    bundle_password: Some(BUNDLE_PG_READ_PASSWORD),
};
const PG_MIGRATOR_ROLE_KEYS: PgRoleKeys = PgRoleKeys {
    username: PG_MIGRATOR_USERNAME_ENV,
    password_file: PG_MIGRATOR_PASSWORD_FILE_ENV,
    removed_password: PG_MIGRATOR_REMOVED_PASSWORD_ENV,
    bundle_password: None,
};
const PG_PROJECTION_READER_ROLE_KEYS: PgRoleKeys = PgRoleKeys {
    username: PG_PROJECTION_READER_USERNAME_ENV,
    password_file: PG_PROJECTION_READER_PASSWORD_FILE_ENV,
    removed_password: PG_PROJECTION_READER_REMOVED_PASSWORD_ENV,
    bundle_password: None,
};
const PG_PROJECTION_OPERATOR_ROLE_KEYS: PgRoleKeys = PgRoleKeys {
    username: PG_PROJECTION_OPERATOR_USERNAME_ENV,
    password_file: PG_PROJECTION_OPERATOR_PASSWORD_FILE_ENV,
    removed_password: PG_PROJECTION_OPERATOR_REMOVED_PASSWORD_ENV,
    bundle_password: None,
};
const PG_SAGA_OPERATOR_ROLE_KEYS: PgRoleKeys = PgRoleKeys {
    username: PG_SAGA_OPERATOR_USERNAME_ENV,
    password_file: PG_SAGA_OPERATOR_PASSWORD_FILE_ENV,
    removed_password: PG_SAGA_OPERATOR_REMOVED_PASSWORD_ENV,
    bundle_password: None,
};
const PG_L2_DR_RECOVERY_AUDITOR_ROLE_KEYS: PgRoleKeys = PgRoleKeys {
    username: PG_L2_DR_RECOVERY_AUDITOR_USERNAME_ENV,
    password_file: PG_L2_DR_RECOVERY_AUDITOR_PASSWORD_FILE_ENV,
    removed_password: PG_L2_DR_RECOVERY_AUDITOR_REMOVED_PASSWORD_ENV,
    bundle_password: None,
};
const PG_L2_DR_RECOVERY_EXECUTOR_ROLE_KEYS: PgRoleKeys = PgRoleKeys {
    username: PG_L2_DR_RECOVERY_EXECUTOR_USERNAME_ENV,
    password_file: PG_L2_DR_RECOVERY_EXECUTOR_PASSWORD_FILE_ENV,
    removed_password: PG_L2_DR_RECOVERY_EXECUTOR_REMOVED_PASSWORD_ENV,
    bundle_password: None,
};
const PG_AUDIT_ADMIN_ROLE_KEYS: PgRoleKeys = PgRoleKeys {
    username: PG_AUDIT_ADMIN_USERNAME_ENV,
    password_file: PG_AUDIT_ADMIN_PASSWORD_FILE_ENV,
    removed_password: PG_AUDIT_ADMIN_REMOVED_PASSWORD_ENV,
    bundle_password: Some(BUNDLE_PG_AUDIT_ADMIN_PASSWORD),
};
const PG_DLX_ARCHIVER_ROLE_KEYS: PgRoleKeys = PgRoleKeys {
    username: PG_DLX_ARCHIVER_USERNAME_ENV,
    password_file: PG_DLX_ARCHIVER_PASSWORD_FILE_ENV,
    removed_password: PG_DLX_ARCHIVER_REMOVED_PASSWORD_ENV,
    bundle_password: Some(BUNDLE_PG_DLX_ARCHIVER_PASSWORD),
};
const PG_DLX_VERIFIER_ROLE_KEYS: PgRoleKeys = PgRoleKeys {
    username: PG_DLX_VERIFIER_USERNAME_ENV,
    password_file: PG_DLX_VERIFIER_PASSWORD_FILE_ENV,
    removed_password: PG_DLX_VERIFIER_REMOVED_PASSWORD_ENV,
    bundle_password: Some(BUNDLE_PG_DLX_VERIFIER_PASSWORD),
};
const PG_DLX_PURGER_ROLE_KEYS: PgRoleKeys = PgRoleKeys {
    username: PG_DLX_PURGER_USERNAME_ENV,
    password_file: PG_DLX_PURGER_PASSWORD_FILE_ENV,
    removed_password: PG_DLX_PURGER_REMOVED_PASSWORD_ENV,
    bundle_password: Some(BUNDLE_PG_DLX_PURGER_PASSWORD),
};

/// Closed serving projection used by profiles that do not activate DLX providers.
pub(crate) struct PgServingRuntimeConfigParts {
    pub(crate) serving: PgConfig,
    pub(crate) tenant_read: PgTenantReadConfig,
    pub(crate) audit_admin: Option<PgConfig>,
    pub(crate) monitor_config: postgres::PgRuntimeMonitorConfig,
}

/// Closed DLX-only projection. It is parsed only after event provider activation is proven.
pub(crate) struct PgDlxRuntimeConfigParts {
    pub(crate) archiver: PgConfig,
    pub(crate) verifier: PgConfig,
    pub(crate) purger: PgConfig,
}

struct PgSharedValues {
    host: String,
    port: u16,
    database: String,
    private_ca: PgPrivateCa,
}

#[cfg(test)]
thread_local! {
    static PRIVATE_CA_FILE_READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

impl PgSharedValues {
    fn from_snapshot(config: SnapshotConfig<'_>) -> anyhow::Result<Self> {
        let host = required_value(config, PG_HOST_ENV)?;
        let port_raw = required_value(config, PG_PORT_ENV)?;
        let port = port_raw.parse::<u16>().with_context(|| {
            format!("{PG_PORT_ENV} must be a valid port number (1-65535): {port_raw}")
        })?;
        let database = required_value(config, PG_DATABASE_ENV)?;
        #[cfg(test)]
        PRIVATE_CA_FILE_READS.with(|reads| reads.set(reads.get() + 1));
        let ca_pem = super::read_required_ca_pem(
            config.value(PG_SSL_ROOT_CERT_PATH_ENV),
            PG_SSL_ROOT_CERT_PATH_ENV,
        )?;
        let private_ca = PgPrivateCa::from_pem(ca_pem)
            .context("parse RSS_PG_SSL_ROOT_CERT_PATH PEM CA bundle")?;
        Ok(Self {
            host,
            port,
            database,
            private_ca,
        })
    }

    fn role_config(
        &self,
        config: SnapshotConfig<'_>,
        keys: PgRoleKeys,
    ) -> anyhow::Result<PgConfig> {
        reject_removed_password(config, keys)?;
        let username = required_value(config, keys.username)?;
        let password = role_password(config, keys)?;
        let role = self.config(username, password);
        let pool_limit = match keys.username {
            PG_DLX_ARCHIVER_USERNAME_ENV => Some(PG_DLX_ARCHIVER_MAX_CONNECTIONS_ENV),
            PG_DLX_VERIFIER_USERNAME_ENV => Some(PG_DLX_VERIFIER_MAX_CONNECTIONS_ENV),
            PG_DLX_PURGER_USERNAME_ENV => Some(PG_DLX_PURGER_MAX_CONNECTIONS_ENV),
            _ => None,
        };
        match pool_limit {
            Some(env) => apply_pool_limit_from_value(role, config.value(env), env),
            None => Ok(role),
        }
    }

    fn optional_audit_config(
        &self,
        config: SnapshotConfig<'_>,
    ) -> anyhow::Result<Option<PgConfig>> {
        reject_removed_password(config, PG_AUDIT_ADMIN_ROLE_KEYS)?;
        let username = config.value(PG_AUDIT_ADMIN_ROLE_KEYS.username);
        let password_file = config.value(PG_AUDIT_ADMIN_ROLE_KEYS.password_file);
        let bundle_password = PG_AUDIT_ADMIN_ROLE_KEYS
            .bundle_password
            .and_then(|key| config.value(key));
        match (username, password_file, bundle_password) {
            (None, None, None) => Ok(None),
            (Some(username), Some(path), None) => Ok(Some(self.config(
                username.to_owned(),
                read_password_file(path.to_owned(), PG_AUDIT_ADMIN_ROLE_KEYS.password_file)?,
            ))),
            (Some(username), None, Some(password)) => {
                Ok(Some(self.config(username.to_owned(), password.to_owned())))
            }
            (None, Some(_), None) | (None, None, Some(_)) => {
                Err(missing_required_value(PG_AUDIT_ADMIN_ROLE_KEYS.username))
            }
            (Some(_), None, None) => Err(missing_required_value(
                PG_AUDIT_ADMIN_ROLE_KEYS.password_file,
            )),
            _ => anyhow::bail!("postgres audit password has multiple sources"),
        }
    }

    fn config(&self, username: String, password: String) -> PgConfig {
        PgConfig::new(
            self.host.clone(),
            self.port,
            self.database.clone(),
            username,
            PgPassword::new(password),
            self.private_ca.clone(),
        )
    }
}

fn role_password(config: SnapshotConfig<'_>, keys: PgRoleKeys) -> anyhow::Result<String> {
    let bundle = keys.bundle_password.and_then(|key| config.value(key));
    let file = config.value(keys.password_file);
    match (bundle, file) {
        (Some(password), None) => Ok(password.to_owned()),
        (None, Some(path)) => read_password_file(path.to_owned(), keys.password_file),
        (None, None) => Err(missing_required_value(keys.password_file)),
        (Some(_), Some(_)) => anyhow::bail!("postgres password has multiple sources"),
    }
}

fn reject_removed_password(config: SnapshotConfig<'_>, keys: PgRoleKeys) -> anyhow::Result<()> {
    if config.value(keys.removed_password).is_some() {
        return Err(anyhow::Error::msg(format!(
            "{} was removed; use {}",
            keys.removed_password, keys.password_file
        )));
    }
    Ok(())
}

fn read_password_file(raw_path: String, key: &'static str) -> anyhow::Result<String> {
    let path = Path::new(&raw_path);
    anyhow::ensure!(
        path.is_absolute()
            && !path
                .components()
                .any(|part| matches!(part, Component::ParentDir)),
        "{key} must be an absolute path without parent traversal"
    );
    let mut password = fs::read_to_string(path)
        .with_context(|| format!("failed to read postgres password file from {key}"))?;
    password.truncate(password.trim_end_matches(['\r', '\n']).len());
    anyhow::ensure!(
        !password.is_empty(),
        "postgres password file from {key} is empty"
    );
    Ok(password)
}

pub(crate) struct PgRuntimeConfig {
    dlx_archiver: PgConfig,
    dlx_verifier: PgConfig,
    dlx_purger: PgConfig,
}

impl PgRuntimeConfig {
    pub(crate) fn serving_from_snapshot(
        config: SnapshotConfig<'_>,
    ) -> anyhow::Result<PgServingRuntimeConfigParts> {
        let shared = PgSharedValues::from_snapshot(config)?;
        let serving = apply_pool_limit_from_value(
            shared.role_config(config, PG_SERVING_ROLE_KEYS)?,
            config.value(PG_WRITER_MAX_CONNECTIONS_ENV),
            PG_WRITER_MAX_CONNECTIONS_ENV,
        )?;
        let tenant_read = PgTenantReadConfig::new(apply_pool_limit_from_value(
            shared.role_config(config, PG_TENANT_READ_ROLE_KEYS)?,
            config.value(PG_READER_MAX_CONNECTIONS_ENV),
            PG_READER_MAX_CONNECTIONS_ENV,
        )?);
        let audit_admin = shared.optional_audit_config(config)?;
        let monitor_config = postgres::PgRuntimeMonitorConfig::new(
            pg_readiness_interval_from_value(config.value(PG_READINESS_INTERVAL_ENV)),
            pg_rls_attestation_interval_from_value(config.value(PG_RLS_ATTESTATION_INTERVAL_ENV))?,
        );
        Ok(PgServingRuntimeConfigParts {
            serving,
            tenant_read,
            audit_admin,
            monitor_config,
        })
    }

    pub(crate) fn from_snapshot(config: SnapshotConfig<'_>) -> anyhow::Result<Self> {
        let shared = PgSharedValues::from_snapshot(config)?;
        let dlx_archiver = shared.role_config(config, PG_DLX_ARCHIVER_ROLE_KEYS)?;
        let dlx_verifier = shared.role_config(config, PG_DLX_VERIFIER_ROLE_KEYS)?;
        let dlx_purger = shared.role_config(config, PG_DLX_PURGER_ROLE_KEYS)?;
        Ok(Self {
            dlx_archiver,
            dlx_verifier,
            dlx_purger,
        })
    }

    pub(crate) fn into_parts(self) -> PgDlxRuntimeConfigParts {
        PgDlxRuntimeConfigParts {
            archiver: self.dlx_archiver,
            verifier: self.dlx_verifier,
            purger: self.dlx_purger,
        }
    }
}

fn apply_pool_limit_from_value(
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

/// DeviceLatent operator credentials derived from one private-CA file snapshot.
pub(crate) struct PgDeviceLatentCommandConfigs {
    pub(crate) operator: PgConfig,
    pub(crate) reader: PgTenantReadConfig,
}

/// Build both DeviceLatent PostgreSQL lanes without rereading the private-CA path.
pub(crate) fn build_pg_device_latent_command_configs(
    config: SnapshotConfig<'_>,
) -> anyhow::Result<PgDeviceLatentCommandConfigs> {
    let shared = PgSharedValues::from_snapshot(config)?;
    let operator = shared.role_config(config, PG_MIGRATOR_ROLE_KEYS)?;
    let reader = apply_pool_limit_from_value(
        shared.role_config(config, PG_TENANT_READ_ROLE_KEYS)?,
        config.value(PG_READER_MAX_CONNECTIONS_ENV),
        PG_READER_MAX_CONNECTIONS_ENV,
    )?;
    Ok(PgDeviceLatentCommandConfigs {
        operator,
        reader: PgTenantReadConfig::new(reader),
    })
}

/// Saga command credentials derived from one private-CA file snapshot.
pub(crate) struct PgSagaCommandConfigs {
    pub(crate) control: PgSagaOperatorConfig,
    pub(crate) writer: PgConfig,
    pub(crate) reader: PgTenantReadConfig,
    pub(crate) audit_admin: Option<PgConfig>,
}

/// Build the Saga control and target lanes without rereading the private-CA path.
pub(crate) fn build_pg_saga_command_configs(
    config: SnapshotConfig<'_>,
) -> anyhow::Result<PgSagaCommandConfigs> {
    let shared = PgSharedValues::from_snapshot(config)?;
    let control =
        PgSagaOperatorConfig::new(shared.role_config(config, PG_SAGA_OPERATOR_ROLE_KEYS)?);
    let writer = apply_pool_limit_from_value(
        shared.role_config(config, PG_SERVING_ROLE_KEYS)?,
        config.value(PG_WRITER_MAX_CONNECTIONS_ENV),
        PG_WRITER_MAX_CONNECTIONS_ENV,
    )?;
    let reader = apply_pool_limit_from_value(
        shared.role_config(config, PG_TENANT_READ_ROLE_KEYS)?,
        config.value(PG_READER_MAX_CONNECTIONS_ENV),
        PG_READER_MAX_CONNECTIONS_ENV,
    )?;
    let audit_admin = shared.optional_audit_config(config)?;
    Ok(PgSagaCommandConfigs {
        control,
        writer,
        reader: PgTenantReadConfig::new(reader),
        audit_admin,
    })
}

/// Build the independent function-only L2 DR audit and executor credentials.
pub(crate) fn build_pg_l2_dr_recovery_configs(
    config: SnapshotConfig<'_>,
) -> anyhow::Result<(PgL2DrRecoveryAuditConfig, PgL2DrRecoveryExecutorConfig)> {
    let shared = PgSharedValues::from_snapshot(config)?;
    reject_removed_password(config, PG_L2_DR_RECOVERY_AUDITOR_ROLE_KEYS)?;
    reject_removed_password(config, PG_L2_DR_RECOVERY_EXECUTOR_ROLE_KEYS)?;
    let auditor_username = required_value(config, PG_L2_DR_RECOVERY_AUDITOR_USERNAME_ENV)?;
    let executor_username = required_value(config, PG_L2_DR_RECOVERY_EXECUTOR_USERNAME_ENV)?;
    anyhow::ensure!(
        auditor_username != executor_username,
        "L2 DR recovery audit and executor usernames must be distinct"
    );
    let auditor_password_file =
        required_value(config, PG_L2_DR_RECOVERY_AUDITOR_PASSWORD_FILE_ENV)?;
    let executor_password_file =
        required_value(config, PG_L2_DR_RECOVERY_EXECUTOR_PASSWORD_FILE_ENV)?;
    anyhow::ensure!(
        auditor_password_file != executor_password_file,
        "L2 DR recovery audit and executor password files must be distinct"
    );
    let auditor_password = role_password(config, PG_L2_DR_RECOVERY_AUDITOR_ROLE_KEYS)?;
    let executor_password = role_password(config, PG_L2_DR_RECOVERY_EXECUTOR_ROLE_KEYS)?;
    anyhow::ensure!(
        auditor_password != executor_password,
        "L2 DR recovery audit and executor passwords must be distinct"
    );
    Ok((
        PgL2DrRecoveryAuditConfig::new(shared.config(auditor_username, auditor_password)),
        PgL2DrRecoveryExecutorConfig::new(shared.config(executor_username, executor_password)),
    ))
}

/// Build the independent Projection operator and scoped source-reader credentials from one
/// immutable configuration generation. Neither lane accepts inline plaintext secrets.
pub(crate) fn build_pg_projection_operator_config(
    config: SnapshotConfig<'_>,
) -> anyhow::Result<(PgProjectionOperatorConfig, PgProjectionSourceReadConfig)> {
    let shared = PgSharedValues::from_snapshot(config)?;
    let operator = shared.role_config(config, PG_PROJECTION_OPERATOR_ROLE_KEYS)?;
    let reader = shared.role_config(config, PG_PROJECTION_READER_ROLE_KEYS)?;
    Ok((
        PgProjectionOperatorConfig::new(operator),
        PgProjectionSourceReadConfig::new(reader),
    ))
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
fn pg_readiness_interval_from_value(raw: Option<&str>) -> postgres::PgReadinessInterval {
    let Some(raw) = raw else {
        return default_pg_readiness_interval();
    };
    let Ok(seconds) = raw.parse::<u64>() else {
        warn_invalid_pg_readiness_interval(raw);
        return default_pg_readiness_interval();
    };
    if !(1..=MAX_READINESS_INTERVAL_SECS).contains(&seconds) {
        warn_invalid_pg_readiness_interval(raw);
        return default_pg_readiness_interval();
    }
    match postgres::PgReadinessInterval::try_new(Duration::from_secs(seconds)) {
        Ok(interval) => interval,
        Err(error) => {
            tracing::warn!(
                env = PG_READINESS_INTERVAL_ENV,
                raw = %raw,
                error = %error,
                "readiness interval rejected by provider; using typed default"
            );
            default_pg_readiness_interval()
        }
    }
}

fn default_pg_readiness_interval() -> postgres::PgReadinessInterval {
    let interval = postgres::PgReadinessInterval::default();
    debug_assert_eq!(interval.get(), DEFAULT_READINESS_INTERVAL);
    interval
}

fn warn_invalid_pg_readiness_interval(raw: &str) {
    tracing::warn!(
        env = PG_READINESS_INTERVAL_ENV,
        raw = %raw,
        max_secs = MAX_READINESS_INTERVAL_SECS,
        "invalid readiness sample interval (need 1..=300s); using default 5s"
    );
}

fn pg_rls_attestation_interval_from_value(
    raw: Option<&str>,
) -> anyhow::Result<postgres::PgRlsAttestationInterval> {
    let seconds = match raw {
        None => return Ok(postgres::PgRlsAttestationInterval::default()),
        Some(raw) => raw.parse::<u64>().with_context(|| {
            format!("{PG_RLS_ATTESTATION_INTERVAL_ENV} must be an integer in 10..=300")
        })?,
    };
    postgres::PgRlsAttestationInterval::try_new(Duration::from_secs(seconds))
        .map_err(|_| anyhow::anyhow!("{PG_RLS_ATTESTATION_INTERVAL_ENV} must be in 10..=300"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::Duration;

    const TEST_PASSWORD_FILE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
    const TEST_SECOND_PASSWORD_FILE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs");

    #[allow(clippy::expect_used)]
    fn test_ssl_root_cert_path() -> String {
        static PATH: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
        PATH.get_or_init(|| {
            let path = unique_temp_path("pg-required-root-ca.pem");
            std::fs::write(&path, crate::infra::TEST_PRIVATE_CA_PEM.as_bytes())
                .expect("write pg test CA");
            path
        })
        .display()
        .to_string()
    }

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
        apply_pool_limit_from_value(
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
        apply_pool_limit_from_value(
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
    role_builder!(
        build_pg_saga_operator_config_from,
        PG_SAGA_OPERATOR_ROLE_KEYS
    );
    fn build_pg_l2_dr_recovery_configs_from(
        get: impl Fn(&str) -> Option<String>,
    ) -> anyhow::Result<(PgL2DrRecoveryAuditConfig, PgL2DrRecoveryExecutorConfig)> {
        let snapshot = snapshot_from_get(get)?;
        build_pg_l2_dr_recovery_configs(snapshot.view())
    }
    role_builder!(build_pg_dlx_archiver_config_from, PG_DLX_ARCHIVER_ROLE_KEYS);
    role_builder!(build_pg_dlx_verifier_config_from, PG_DLX_VERIFIER_ROLE_KEYS);
    role_builder!(build_pg_dlx_purger_config_from, PG_DLX_PURGER_ROLE_KEYS);

    #[allow(clippy::expect_used)]
    fn build_readiness_interval_from(
        get: impl Fn(&str) -> Option<String>,
    ) -> postgres::PgReadinessInterval {
        let snapshot = snapshot_from_get(get).expect("closed test catalog");
        pg_readiness_interval_from_value(snapshot.view().value(PG_READINESS_INTERVAL_ENV))
    }

    fn full_runtime_get(name: &str) -> Option<String> {
        Some(
            match name {
                PG_HOST_ENV => "pg.snapshot.internal",
                PG_PORT_ENV => "5439",
                PG_DATABASE_ENV => "rss_snapshot",
                PG_SSL_ROOT_CERT_PATH_ENV => return Some(test_ssl_root_cert_path()),
                PG_USERNAME_ENV => "rss_app_snapshot",
                PG_PASSWORD_FILE_ENV => TEST_PASSWORD_FILE,
                PG_READ_USERNAME_ENV => "rss_app_read_snapshot",
                PG_READ_PASSWORD_FILE_ENV => TEST_PASSWORD_FILE,
                PG_MIGRATOR_USERNAME_ENV => "rss_migrator_snapshot",
                PG_MIGRATOR_PASSWORD_FILE_ENV => TEST_PASSWORD_FILE,
                PG_AUDIT_ADMIN_USERNAME_ENV => "rss_audit_admin_snapshot",
                PG_AUDIT_ADMIN_PASSWORD_FILE_ENV => TEST_PASSWORD_FILE,
                PG_DLX_ARCHIVER_USERNAME_ENV => "rss_dlx_archiver_snapshot",
                PG_DLX_ARCHIVER_PASSWORD_FILE_ENV => TEST_PASSWORD_FILE,
                PG_DLX_ARCHIVER_MAX_CONNECTIONS_ENV => "7",
                PG_DLX_VERIFIER_USERNAME_ENV => "rss_dlx_verifier_snapshot",
                PG_DLX_VERIFIER_PASSWORD_FILE_ENV => TEST_PASSWORD_FILE,
                PG_DLX_VERIFIER_MAX_CONNECTIONS_ENV => "8",
                PG_DLX_PURGER_USERNAME_ENV => "rss_dlx_purger_snapshot",
                PG_DLX_PURGER_PASSWORD_FILE_ENV => TEST_PASSWORD_FILE,
                PG_DLX_PURGER_MAX_CONNECTIONS_ENV => "9",
                PG_READINESS_INTERVAL_ENV => "19",
                PG_RLS_ATTESTATION_INTERVAL_ENV => "23",
                _ => return None,
            }
            .to_owned(),
        )
    }

    fn reset_private_ca_file_reads() {
        PRIVATE_CA_FILE_READS.with(|reads| reads.set(0));
    }

    fn private_ca_file_reads() -> usize {
        PRIVATE_CA_FILE_READS.with(std::cell::Cell::get)
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn command_pg_lanes_share_exactly_one_private_ca_file_snapshot() {
        reset_private_ca_file_reads();
        let saga_snapshot = snapshot_from_get(|name| match name {
            PG_SAGA_OPERATOR_USERNAME_ENV => Some("rss_saga_operator_snapshot".to_owned()),
            PG_SAGA_OPERATOR_PASSWORD_FILE_ENV => Some(TEST_PASSWORD_FILE.to_owned()),
            _ => full_runtime_get(name),
        })
        .expect("saga snapshot");
        build_pg_saga_command_configs(saga_snapshot.view()).expect("saga command configs");
        assert_eq!(private_ca_file_reads(), 1);

        reset_private_ca_file_reads();
        let device_snapshot = snapshot_from_get(full_runtime_get).expect("device snapshot");
        build_pg_device_latent_command_configs(device_snapshot.view())
            .expect("device latent command configs");
        assert_eq!(private_ca_file_reads(), 1);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn runtime_infra_pg_snapshot_maps_named_roles_policy_readiness_and_redacts_secrets() {
        let snapshot = snapshot_from_get(full_runtime_get).expect("snapshot");
        let parts = PgRuntimeConfig::serving_from_snapshot(snapshot.view())
            .expect("serving runtime config");
        let dlx = PgRuntimeConfig::from_snapshot(snapshot.view())
            .expect("DLX runtime config")
            .into_parts();
        for (config, role, max) in [
            (&parts.serving, "rss_app_snapshot", 5),
            (&dlx.archiver, "rss_dlx_archiver_snapshot", 7),
            (&dlx.verifier, "rss_dlx_verifier_snapshot", 8),
            (&dlx.purger, "rss_dlx_purger_snapshot", 9),
        ] {
            let debug = format!("{config:?}");
            assert!(debug.contains(role), "{debug}");
            assert!(
                debug.contains(&format!("max_connections: {max}")),
                "{debug}"
            );
            assert!(!debug.contains("-snapshot-secret"), "{debug}");
        }
        let reader = format!("{:?}", parts.tenant_read);
        assert!(reader.contains("rss_app_read_snapshot"), "{reader}");
        assert!(!reader.contains("reader-snapshot-secret"), "{reader}");
        let audit = format!("{:?}", parts.audit_admin.expect("audit role"));
        assert!(audit.contains("rss_audit_admin_snapshot"));
        assert!(!audit.contains("audit-admin-snapshot-secret"));
        assert_eq!(
            parts.monitor_config.readiness().get(),
            Duration::from_secs(19)
        );
        assert_eq!(
            parts.monitor_config.rls_attestation().get(),
            Duration::from_secs(23)
        );
    }

    #[test]
    #[allow(clippy::expect_used, clippy::panic)]
    fn runtime_infra_pg_snapshot_never_falls_back_and_preserves_optional_audit_pair() {
        for missing in [
            PG_READ_USERNAME_ENV,
            PG_READ_PASSWORD_FILE_ENV,
            PG_DLX_ARCHIVER_PASSWORD_FILE_ENV,
            PG_DLX_VERIFIER_USERNAME_ENV,
            PG_DLX_PURGER_PASSWORD_FILE_ENV,
        ] {
            let snapshot = snapshot_from_get(|name| {
                (name != missing).then(|| full_runtime_get(name)).flatten()
            })
            .expect("snapshot");
            let result = match missing {
                PG_DLX_ARCHIVER_PASSWORD_FILE_ENV
                | PG_DLX_VERIFIER_USERNAME_ENV
                | PG_DLX_PURGER_PASSWORD_FILE_ENV => {
                    PgRuntimeConfig::from_snapshot(snapshot.view()).map(|_| ())
                }
                _ => PgRuntimeConfig::serving_from_snapshot(snapshot.view()).map(|_| ()),
            };
            let error = match result {
                Ok(_) => panic!("missing narrow role must fail"),
                Err(error) => error,
            };
            assert!(error.to_string().contains(missing), "{error:#}");
        }

        let snapshot = snapshot_from_get(|name| {
            (name != PG_AUDIT_ADMIN_ROLE_KEYS.username
                && name != PG_AUDIT_ADMIN_ROLE_KEYS.password_file)
                .then(|| full_runtime_get(name))
                .flatten()
        })
        .expect("snapshot");
        assert!(
            PgRuntimeConfig::serving_from_snapshot(snapshot.view())
                .expect("absent audit pair")
                .audit_admin
                .is_none()
        );
        for missing in [
            PG_AUDIT_ADMIN_USERNAME_ENV,
            PG_AUDIT_ADMIN_PASSWORD_FILE_ENV,
        ] {
            let snapshot = snapshot_from_get(|name| {
                (name != missing).then(|| full_runtime_get(name)).flatten()
            })
            .expect("snapshot");
            let error = match PgRuntimeConfig::serving_from_snapshot(snapshot.view()) {
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
            PG_SSL_ROOT_CERT_PATH_ENV => Some(test_ssl_root_cert_path()),
            PG_USERNAME_ENV => Some("rss_app".to_string()),
            PG_PASSWORD_FILE_ENV => Some(TEST_PASSWORD_FILE.to_string()),
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
            PG_SSL_ROOT_CERT_PATH_ENV => Some(test_ssl_root_cert_path()),
            PG_USERNAME_ENV => Some("rss_app".to_string()),
            PG_PASSWORD_FILE_ENV => Some(TEST_PASSWORD_FILE.to_string()),
            PG_MIGRATOR_USERNAME_ENV => Some("postgres".to_string()),
            PG_MIGRATOR_PASSWORD_FILE_ENV => Some(TEST_PASSWORD_FILE.to_string()),
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
    fn pg_saga_operator_config_requires_its_dedicated_credentials() {
        let missing = build_pg_saga_operator_config_from(|name| match name {
            PG_HOST_ENV => Some("postgres".to_string()),
            PG_PORT_ENV => Some("5432".to_string()),
            PG_DATABASE_ENV => Some("rss".to_string()),
            PG_SSL_ROOT_CERT_PATH_ENV => Some(test_ssl_root_cert_path()),
            PG_MIGRATOR_USERNAME_ENV => Some("rss_migrator".to_string()),
            PG_MIGRATOR_PASSWORD_FILE_ENV => Some(TEST_PASSWORD_FILE.to_string()),
            _ => None,
        });
        match missing {
            Ok(_) => panic!("migrator credentials must not satisfy the Saga operator lane"),
            Err(error) => assert!(error.to_string().contains(PG_SAGA_OPERATOR_USERNAME_ENV)),
        }

        let config = build_pg_saga_operator_config_from(|name| match name {
            PG_HOST_ENV => Some("postgres".to_string()),
            PG_PORT_ENV => Some("5432".to_string()),
            PG_DATABASE_ENV => Some("rss".to_string()),
            PG_SSL_ROOT_CERT_PATH_ENV => Some(test_ssl_root_cert_path()),
            PG_SAGA_OPERATOR_USERNAME_ENV => Some("rss_saga_operator".to_string()),
            PG_SAGA_OPERATOR_PASSWORD_FILE_ENV => Some(TEST_PASSWORD_FILE.to_string()),
            _ => None,
        });
        assert!(
            config.is_ok(),
            "dedicated Saga operator credentials must parse"
        );
    }

    #[allow(clippy::expect_used, clippy::panic)]
    #[test]
    fn pg_l2_dr_recovery_lane_configs_are_independent_dedicated_and_file_only() {
        let missing = build_pg_l2_dr_recovery_configs_from(|name| match name {
            PG_HOST_ENV => Some("postgres".to_owned()),
            PG_PORT_ENV => Some("5432".to_owned()),
            PG_DATABASE_ENV => Some("rss".to_owned()),
            PG_SSL_ROOT_CERT_PATH_ENV => Some(test_ssl_root_cert_path()),
            PG_SAGA_OPERATOR_USERNAME_ENV => Some("rss_saga_operator".to_owned()),
            PG_SAGA_OPERATOR_PASSWORD_FILE_ENV => Some(TEST_PASSWORD_FILE.to_owned()),
            _ => None,
        });
        match missing {
            Ok(_) => panic!("Saga credentials must not satisfy the L2 DR recovery lane"),
            Err(error) => assert!(
                error
                    .to_string()
                    .contains(PG_L2_DR_RECOVERY_AUDITOR_USERNAME_ENV)
            ),
        }

        let inline = build_pg_l2_dr_recovery_configs_from(|name| match name {
            PG_HOST_ENV => Some("postgres".to_owned()),
            PG_PORT_ENV => Some("5432".to_owned()),
            PG_DATABASE_ENV => Some("rss".to_owned()),
            PG_SSL_ROOT_CERT_PATH_ENV => Some(test_ssl_root_cert_path()),
            PG_L2_DR_RECOVERY_AUDITOR_USERNAME_ENV => Some("rss_l2_dr_recovery_auditor".to_owned()),
            PG_L2_DR_RECOVERY_AUDITOR_PASSWORD_FILE_ENV => Some(TEST_PASSWORD_FILE.to_owned()),
            PG_L2_DR_RECOVERY_AUDITOR_REMOVED_PASSWORD_ENV => Some("forbidden".to_owned()),
            PG_L2_DR_RECOVERY_EXECUTOR_USERNAME_ENV => {
                Some("rss_l2_dr_recovery_executor".to_owned())
            }
            PG_L2_DR_RECOVERY_EXECUTOR_PASSWORD_FILE_ENV => Some(TEST_PASSWORD_FILE.to_owned()),
            _ => None,
        });
        assert!(inline.is_err());

        let shared_file = build_pg_l2_dr_recovery_configs_from(|name| match name {
            PG_HOST_ENV => Some("postgres".to_owned()),
            PG_PORT_ENV => Some("5432".to_owned()),
            PG_DATABASE_ENV => Some("rss".to_owned()),
            PG_SSL_ROOT_CERT_PATH_ENV => Some(test_ssl_root_cert_path()),
            PG_L2_DR_RECOVERY_AUDITOR_USERNAME_ENV => Some("rss_l2_dr_recovery_auditor".to_owned()),
            PG_L2_DR_RECOVERY_AUDITOR_PASSWORD_FILE_ENV => Some(TEST_PASSWORD_FILE.to_owned()),
            PG_L2_DR_RECOVERY_EXECUTOR_USERNAME_ENV => {
                Some("rss_l2_dr_recovery_executor".to_owned())
            }
            PG_L2_DR_RECOVERY_EXECUTOR_PASSWORD_FILE_ENV => Some(TEST_PASSWORD_FILE.to_owned()),
            _ => None,
        });
        assert!(shared_file.is_err());

        let first_same_secret = unique_temp_path("pg-l2-dr-auditor-password");
        let second_same_secret = unique_temp_path("pg-l2-dr-executor-password");
        std::fs::write(&first_same_secret, "same-secret").expect("write auditor password");
        std::fs::write(&second_same_secret, "same-secret").expect("write executor password");
        let same_secret = build_pg_l2_dr_recovery_configs_from(|name| match name {
            PG_HOST_ENV => Some("postgres".to_owned()),
            PG_PORT_ENV => Some("5432".to_owned()),
            PG_DATABASE_ENV => Some("rss".to_owned()),
            PG_SSL_ROOT_CERT_PATH_ENV => Some(test_ssl_root_cert_path()),
            PG_L2_DR_RECOVERY_AUDITOR_USERNAME_ENV => Some("rss_l2_dr_recovery_auditor".to_owned()),
            PG_L2_DR_RECOVERY_AUDITOR_PASSWORD_FILE_ENV => {
                Some(first_same_secret.display().to_string())
            }
            PG_L2_DR_RECOVERY_EXECUTOR_USERNAME_ENV => {
                Some("rss_l2_dr_recovery_executor".to_owned())
            }
            PG_L2_DR_RECOVERY_EXECUTOR_PASSWORD_FILE_ENV => {
                Some(second_same_secret.display().to_string())
            }
            _ => None,
        });
        std::fs::remove_file(&first_same_secret).expect("remove auditor password");
        std::fs::remove_file(&second_same_secret).expect("remove executor password");
        assert!(same_secret.is_err());

        let exact = build_pg_l2_dr_recovery_configs_from(|name| match name {
            PG_HOST_ENV => Some("postgres".to_owned()),
            PG_PORT_ENV => Some("5432".to_owned()),
            PG_DATABASE_ENV => Some("rss".to_owned()),
            PG_SSL_ROOT_CERT_PATH_ENV => Some(test_ssl_root_cert_path()),
            PG_L2_DR_RECOVERY_AUDITOR_USERNAME_ENV => Some("rss_l2_dr_recovery_auditor".to_owned()),
            PG_L2_DR_RECOVERY_AUDITOR_PASSWORD_FILE_ENV => Some(TEST_PASSWORD_FILE.to_owned()),
            PG_L2_DR_RECOVERY_EXECUTOR_USERNAME_ENV => {
                Some("rss_l2_dr_recovery_executor".to_owned())
            }
            PG_L2_DR_RECOVERY_EXECUTOR_PASSWORD_FILE_ENV => {
                Some(TEST_SECOND_PASSWORD_FILE.to_owned())
            }
            _ => None,
        });
        assert!(exact.is_ok());
    }

    fn projection_operator_snapshot(
        get: impl Fn(&str) -> Option<String>,
        bundle_document: &str,
    ) -> Result<crate::config::RuntimeConfigSnapshot, crate::config::RuntimeConfigCaptureError>
    {
        crate::config::RuntimeConfigSnapshot::capture_projection_operator_test(
            GetterSource(get),
            bundle_document,
        )
    }

    const PROJECTION_OPERATOR_TEST_BUNDLE: &str = concat!(
        r#"{"pgProjectionReaderPasswordFile":""#,
        env!("CARGO_MANIFEST_DIR"),
        r#"/Cargo.toml","pgProjectionOperatorPasswordFile":""#,
        env!("CARGO_MANIFEST_DIR"),
        r#"/Cargo.toml","replayVaultToken":"replay-vault-test"}"#
    );

    #[test]
    #[allow(clippy::expect_used)]
    fn projection_operator_config_requires_two_file_only_credentials() {
        let snapshot = projection_operator_snapshot(
            |name| match name {
                PG_HOST_ENV => Some("postgres".to_string()),
                PG_PORT_ENV => Some("5432".to_string()),
                PG_DATABASE_ENV => Some("rss".to_string()),
                PG_SSL_ROOT_CERT_PATH_ENV => Some(test_ssl_root_cert_path()),
                PG_PROJECTION_OPERATOR_USERNAME_ENV => Some("rss_projection_operator".to_string()),
                PG_PROJECTION_READER_USERNAME_ENV => Some("rss_projection_reader".to_string()),
                _ => None,
            },
            PROJECTION_OPERATOR_TEST_BUNDLE,
        )
        .expect("snapshot");
        let (operator, reader) =
            build_pg_projection_operator_config(snapshot.view()).expect("projection config");
        let debug = format!("{operator:?} {reader:?}");
        assert!(debug.contains("rss_projection_operator"));
        assert!(debug.contains("rss_projection_reader"));
        assert!(
            !debug.contains("[package]"),
            "password file contents must be redacted"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn projection_operator_config_rejects_removed_inline_passwords() {
        const INLINE_PASSWORD_BAIT: &str = "inline-operator-password-bait";
        let error = projection_operator_snapshot(
            |name| match name {
                PG_HOST_ENV => Some("postgres".to_string()),
                PG_PORT_ENV => Some("5432".to_string()),
                PG_DATABASE_ENV => Some("rss".to_string()),
                PG_SSL_ROOT_CERT_PATH_ENV => Some(test_ssl_root_cert_path()),
                PG_PROJECTION_OPERATOR_USERNAME_ENV => Some("rss_projection_operator".to_string()),
                PG_PROJECTION_OPERATOR_REMOVED_PASSWORD_ENV => {
                    Some(INLINE_PASSWORD_BAIT.to_string())
                }
                PG_PROJECTION_READER_USERNAME_ENV => Some("rss_projection_reader".to_string()),
                _ => None,
            },
            PROJECTION_OPERATOR_TEST_BUNDLE,
        )
        .expect_err("inline operator password must fail closed at capture");
        let rendered = format!("{error:?}: {error}");
        assert!(
            rendered.contains(PG_PROJECTION_OPERATOR_REMOVED_PASSWORD_ENV),
            "{rendered}"
        );
        assert!(!rendered.contains(INLINE_PASSWORD_BAIT), "{rendered}");
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
            Err(err) => assert!(err.to_string().contains(PG_READ_PASSWORD_FILE_ENV)),
        }
    }

    #[allow(clippy::panic)]
    #[test]
    fn pg_read_config_uses_dedicated_credentials() {
        let cfg = build_pg_read_config_from(|name| match name {
            PG_READ_USERNAME_ENV => Some("rss_app_read".to_string()),
            PG_READ_PASSWORD_FILE_ENV => Some(TEST_PASSWORD_FILE.to_string()),
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
            PG_READ_PASSWORD_FILE_ENV => Some(TEST_PASSWORD_FILE.to_string()),
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
            PG_READ_PASSWORD_FILE_ENV => Some(TEST_PASSWORD_FILE.to_string()),
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
                    PG_READ_PASSWORD_FILE_ENV => Some(TEST_PASSWORD_FILE.to_string()),
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
        let ca = write_temp_file(
            "pg-reader-root-ca.pem",
            crate::infra::TEST_PRIVATE_CA_PEM.as_bytes(),
        );
        let cfg = build_pg_read_config_from(|name| match name {
            PG_READ_USERNAME_ENV => Some("rss_app_read".to_string()),
            PG_READ_PASSWORD_FILE_ENV => Some(TEST_PASSWORD_FILE.to_string()),
            PG_SSL_ROOT_CERT_PATH_ENV => Some(ca.display().to_string()),
            _ => full_pg_get(name),
        })
        .expect("reader must share serving TLS configuration");
        let debug = format!("{cfg:?}");
        assert!(debug.contains("PrivateCa"));
        assert!(
            !debug.contains("pg-reader-root-ca.pem"),
            "private CA path must remain redacted: {debug}"
        );
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
            Err(err) => assert!(err.to_string().contains(PG_DLX_ARCHIVER_PASSWORD_FILE_ENV)),
        }

        let cfg = match build_pg_dlx_archiver_config_from(|name| match name {
            PG_DLX_ARCHIVER_USERNAME_ENV => Some("rss_dlx_archiver".to_string()),
            PG_DLX_ARCHIVER_PASSWORD_FILE_ENV => Some(TEST_PASSWORD_FILE.to_string()),
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
            PG_DLX_VERIFIER_PASSWORD_FILE_ENV => Some(TEST_PASSWORD_FILE.to_string()),
            _ => full_pg_get(name),
        })
        .unwrap_or_else(|error| panic!("DLX verifier config: {error}"));
        let purger = build_pg_dlx_purger_config_from(|name| match name {
            PG_DLX_PURGER_USERNAME_ENV => Some("rss_dlx_purger".to_string()),
            PG_DLX_PURGER_PASSWORD_FILE_ENV => Some(TEST_PASSWORD_FILE.to_string()),
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
            PG_SSL_ROOT_CERT_PATH_ENV => Some(test_ssl_root_cert_path()),
            PG_USERNAME_ENV => Some("rss_app".to_string()),
            PG_PASSWORD_FILE_ENV => Some(TEST_PASSWORD_FILE.to_string()),
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
    fn raw_and_dual_source_passwords_are_rejected_without_secret_diagnostics() {
        const FORBIDDEN: &str = "raw-secret-must-not-leak";
        let error = build_pg_config_from(|key| {
            (key == PG_REMOVED_PASSWORD_ENV)
                .then(|| FORBIDDEN.to_owned())
                .or_else(|| full_pg_get(key))
        })
        .expect_err("raw password presence must reject even when file source also exists");
        let diagnostic = error.to_string();
        assert!(diagnostic.contains(PG_REMOVED_PASSWORD_ENV));
        assert!(diagnostic.contains(PG_PASSWORD_FILE_ENV));
        assert!(!diagnostic.contains(FORBIDDEN));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn relative_or_parent_traversing_password_file_is_rejected_before_read() {
        for path in ["relative/password", "/run/rss/../password"] {
            let error = build_pg_config_from(|key| {
                (key == PG_PASSWORD_FILE_ENV)
                    .then(|| path.to_owned())
                    .or_else(|| full_pg_get(key))
            })
            .expect_err("non-canonical password file path must fail");
            assert!(error.to_string().contains(PG_PASSWORD_FILE_ENV));
        }
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
                .contains(PG_AUDIT_ADMIN_PASSWORD_FILE_ENV)
        );

        let missing_username = build_pg_audit_admin_config_from(|k| match k {
            PG_AUDIT_ADMIN_PASSWORD_FILE_ENV => Some(TEST_PASSWORD_FILE.to_string()),
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
            PG_AUDIT_ADMIN_PASSWORD_FILE_ENV => Some(TEST_PASSWORD_FILE.to_string()),
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

    /// `RSS_PG_PASSWORD_FILE` 缺失 → Err 含变量名（fail-fast）。
    #[test]
    #[allow(clippy::expect_used)]
    fn build_pg_config_from_missing_password() {
        let get = |k: &str| {
            if k == PG_PASSWORD_FILE_ENV {
                None
            } else {
                full_pg_get(k)
            }
        };
        let err = build_pg_config_from(get).expect_err("password required");
        assert!(
            err.to_string().contains(PG_PASSWORD_FILE_ENV),
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

    #[test]
    #[allow(clippy::expect_used)]
    fn build_pg_config_carries_typed_private_ca() {
        let cfg = build_pg_config_from(full_pg_get).expect("ok");
        let debug = format!("{cfg:?}");
        assert!(
            debug.contains("PgPrivateCa(<redacted>)"),
            "production config must carry typed private CA: {debug}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn build_pg_config_requires_ssl_root_cert_path() {
        let err = build_pg_config_from(|name| {
            if name == PG_SSL_ROOT_CERT_PATH_ENV {
                None
            } else {
                full_pg_get(name)
            }
        })
        .expect_err("production serving requires RSS_PG_SSL_ROOT_CERT_PATH");
        assert!(
            format!("{err:#}").contains(PG_SSL_ROOT_CERT_PATH_ENV),
            "error must identify env var: {err:#}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn build_pg_config_applies_ssl_root_cert_path() {
        let ca = write_temp_file(
            "pg-root-ca.pem",
            crate::infra::TEST_PRIVATE_CA_PEM.as_bytes(),
        );
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
            debug.contains("PgPrivateCa(<redacted>)") && !debug.contains("pg-root-ca.pem"),
            "PgConfig must snapshot and redact the configured private CA: {debug}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn build_pg_migrator_config_applies_ssl_root_cert_path() {
        let ca = write_temp_file(
            "pg-migrator-root-ca.pem",
            crate::infra::TEST_PRIVATE_CA_PEM.as_bytes(),
        );
        let cfg = build_pg_migrator_config_from(|name| match name {
            PG_MIGRATOR_USERNAME_ENV => Some("rss_migrator".to_string()),
            PG_MIGRATOR_PASSWORD_FILE_ENV => Some(TEST_PASSWORD_FILE.to_string()),
            PG_SSL_ROOT_CERT_PATH_ENV => Some(ca.display().to_string()),
            _ => full_pg_get(name),
        })
        .expect("valid pg migrator config with root cert");
        let debug = format!("{cfg:?}");
        assert!(
            debug.contains("PgPrivateCa(<redacted>)") && !debug.contains("pg-migrator-root-ca.pem"),
            "migrator config must share the redacted private-CA snapshot: {debug}"
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

        let unreadable = write_unreadable_temp_file(
            "unreadable-pg-root-ca.pem",
            crate::infra::TEST_PRIVATE_CA_PEM.as_bytes(),
        );
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
    fn build_pg_config_rejects_invalid_ssl_root_cert_pem() {
        let bait = write_temp_file("pg-invalid-root-ca.pem", b"test ca");
        let err = build_pg_config_from(|name| {
            if name == PG_SSL_ROOT_CERT_PATH_ENV {
                Some(bait.display().to_string())
            } else {
                full_pg_get(name)
            }
        })
        .expect_err("non-PEM root cert bait must fail before connect");
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains(PG_SSL_ROOT_CERT_PATH_ENV),
            "error must identify env var: {rendered}"
        );
        assert!(
            rendered.contains("PEM"),
            "error must mention PEM parse failure: {rendered}"
        );
    }

    // ── build_readiness_interval_from 测试 ────────────────────────────────────────────────

    /// 未配置 → 静默取默认 5s（非显式误配，不 warn）。
    #[test]
    fn build_readiness_interval_default_when_missing() {
        let d = build_readiness_interval_from(|_| None);
        assert_eq!(d.get(), DEFAULT_READINESS_INTERVAL, "缺省 → 5s");
    }

    /// 合法正整数（在 1..=300 范围内）→ 对应秒数。
    #[test]
    fn build_readiness_interval_custom_value() {
        let d = build_readiness_interval_from(|n| {
            (n == PG_READINESS_INTERVAL_ENV).then(|| "10".to_string())
        });
        assert_eq!(d.get(), Duration::from_secs(10));
    }

    /// 显式非法（非数字 / 0）→ warn + 默认 5s（fail-soft；间隔是 hint 非强依赖）。
    #[test]
    fn build_readiness_interval_invalid_falls_back() {
        let d1 = build_readiness_interval_from(|n| {
            (n == PG_READINESS_INTERVAL_ENV).then(|| "not-a-number".to_string())
        });
        assert_eq!(d1.get(), DEFAULT_READINESS_INTERVAL, "非数字 → warn + 默认");
        let d2 = build_readiness_interval_from(|n| {
            (n == PG_READINESS_INTERVAL_ENV).then(|| "0".to_string())
        });
        assert_eq!(d2.get(), DEFAULT_READINESS_INTERVAL, "0 → warn + 默认");
    }

    /// 越界（> MAX_READINESS_INTERVAL_SECS=300）→ warn + 默认 5s。
    #[test]
    fn build_readiness_interval_above_max_warns_and_defaults() {
        let d = build_readiness_interval_from(|n| {
            (n == PG_READINESS_INTERVAL_ENV).then(|| "999".to_string())
        });
        assert_eq!(
            d.get(),
            DEFAULT_READINESS_INTERVAL,
            "999 > 300 → warn + 默认 5s"
        );
    }

    /// 下边界 1s → 对应（合法最小值）。
    #[test]
    fn build_readiness_interval_boundary_min() {
        let d = build_readiness_interval_from(|n| {
            (n == PG_READINESS_INTERVAL_ENV).then(|| "1".to_string())
        });
        assert_eq!(d.get(), Duration::from_secs(1), "1 → 1s（合法下边界）");
    }

    /// 上边界 300s → 对应（合法最大值）。
    #[test]
    fn build_readiness_interval_boundary_max() {
        let d = build_readiness_interval_from(|n| {
            (n == PG_READINESS_INTERVAL_ENV).then(|| "300".to_string())
        });
        assert_eq!(
            d.get(),
            Duration::from_secs(300),
            "300 → 300s（合法上边界）"
        );
    }

    #[test]
    fn rls_attestation_interval_defaults_and_accepts_boundaries() {
        assert_eq!(
            pg_rls_attestation_interval_from_value(None)
                .unwrap_or_else(|error| unreachable!("default interval: {error}"))
                .get(),
            Duration::from_secs(60)
        );
        for raw in ["10", "300"] {
            assert!(pg_rls_attestation_interval_from_value(Some(raw)).is_ok());
        }
    }

    #[test]
    fn rls_attestation_interval_is_fail_fast_when_explicitly_invalid() {
        for raw in ["0", "9", "301", "not-a-number"] {
            let error = pg_rls_attestation_interval_from_value(Some(raw))
                .err()
                .unwrap_or_else(|| unreachable!("invalid RLS interval must fail closed for {raw}"));
            assert!(
                error.to_string().contains(PG_RLS_ATTESTATION_INTERVAL_ENV),
                "{error:#}"
            );
        }
    }
}
