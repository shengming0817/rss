//! postgres 连接池 + adapter 配置 + 错误类型（eventexec 持久化基座，#1116）。
//!
//! `ref: sqlx sqlx-core/src/pool/options.rs@v0.8.6`（`PgPoolOptions` builder + `connect_with`）。

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use vocab::TenantId;

use crate::PgStore;
use crate::cotx::set_local_tenant;

#[cfg(feature = "domain-settings")]
mod projection_worker;
#[cfg(feature = "domain-settings")]
pub(crate) use projection_worker::ProjectionWorkerMint;
#[cfg(feature = "domain-settings")]
pub use projection_worker::{PgProjectionWorkerConfig, PgProjectionWorkerError};

/// 默认连接池上限（与 sqlx 缺省同值）。tuning 参数（非安全必填依赖），故可有默认。
pub(crate) const DEFAULT_MAX_CONNECTIONS: u32 = 10;
/// 默认获取连接超时（与 sqlx 缺省同值）。
pub(crate) const DEFAULT_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(30);
/// 默认 TLS 模式：`VerifyFull`（零信任 / MDM：强制 TLS **且**校验服务端证书链 + 主机名——杜绝静默明文
/// 回退与 MITM）。sqlx 0.8 仅 `VerifyCa`/`VerifyFull` 拒无效证书、仅 `VerifyFull` 校验主机名；`Require`
/// 只加密不验证身份（可被 MITM），`Prefer`（sqlx 缺省）更会回退明文，故均**不**用作 RSS 默认。内部 /
/// 私有 CA 经 [`PgConfig::with_ssl_root_cert`] 注入根证书；本地无 TLS 开发经 [`PgConfig::with_ssl_mode`]
/// 显式降级——不静默。
pub(crate) const DEFAULT_SSL_MODE: PgSslMode = PgSslMode::VerifyFull;
/// Default `application_name` for explicit maintenance/test connections.
const APPLICATION_NAME: &str = "rss-postgres-maintenance";
const WRITER_APPLICATION_NAME: &str = "rss-postgres-writer";
const READER_APPLICATION_NAME: &str = "rss-postgres-reader";
const PROJECTION_SOURCE_READER_APPLICATION_NAME: &str = "rss-postgres-projection-source-reader";
const PROJECTION_OPERATOR_APPLICATION_NAME: &str = "rss-postgres-projection-operator";
const SAGA_OPERATOR_APPLICATION_NAME: &str = "rss-postgres-saga-operator";
const L2_DR_RECOVERY_AUDITOR_APPLICATION_NAME: &str = "rss-postgres-l2-dr-recovery-auditor";
const L2_DR_RECOVERY_EXECUTOR_APPLICATION_NAME: &str = "rss-postgres-l2-dr-recovery-executor";
const L2_DR_REPLAY_FUNCTION: &str =
    "public.rss_service_token_replay_check_and_record(bytea,timestamp with time zone)";
const L2_DR_START_AUDIT_FUNCTION: &str =
    "public.rss_l2_dr_recovery_record_start_audit(bigint,integer,text,uuid,uuid,bytea,uuid)";
const L2_DR_FINISH_AUDIT_FUNCTION: &str =
    "public.rss_l2_dr_recovery_record_finish_audit(bigint,integer,text,uuid,uuid,text,text,uuid)";
const L2_DR_APPLY_FUNCTION: &str =
    "public.rss_l2_dr_recovery_apply(uuid,uuid,text,bigint,bigint,text,text[],bytea,text,uuid)";
const AUDIT_ADMIN_APPLICATION_NAME: &str = "rss-postgres-audit-admin";

/// postgres adapter 错误（adapter-内部 `thiserror`；**不**映射 HTTP 状态码——域 / handler 才映射）。
///
/// Display 仅 `&'static str` const literal（`error-handling.md` §Message 与 PII）；sqlx 原始错误作
/// `#[source]` 内部保留、不进 Display（PII 边界，与 `diport::SignerError` 同范式）。adapter-内部错误不
/// mint 新 `ERR_` wire 前缀（adapter 不返 wire errcode）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PgError {
    /// 配置校验：host 为空。
    #[error("postgres config: host must not be empty")]
    EmptyHost,
    /// 配置校验：database 为空。
    #[error("postgres config: database must not be empty")]
    EmptyDatabase,
    /// 配置校验：port 为 0（非法端口；否则延后成泛化连接失败）。
    #[error("postgres config: port must not be 0")]
    ZeroPort,
    /// 配置校验：username 为空。
    #[error("postgres config: username must not be empty")]
    EmptyUsername,
    /// 配置校验：password 为空（零信任：DB 连接须带凭据，禁空口令静默连接）。
    #[error("postgres config: password must not be empty")]
    EmptyPassword,
    /// 配置校验：max_connections 为 0。
    #[error("postgres config: max_connections must be >= 1")]
    ZeroMaxConnections,
    /// 建池 / 连接失败。
    #[error("postgres {lane} connection failed")]
    Connect {
        lane: &'static str,
        #[source]
        source: sqlx::Error,
    },
    #[cfg(any(test, feature = "test-support", feature = "fault-matrix-test-support"))]
    #[error("postgres test migration failed")]
    Migrate(#[source] sqlx::migrate::MigrateError),
    /// Serving role cannot read the SQLx ledger.
    #[error("postgres schema ledger probe failed")]
    SchemaLedgerProbe(#[source] sqlx::Error),
    /// The database ledger is not the exact migration identity embedded by this serving binary.
    #[error("postgres schema ledger does not match serving binary")]
    SchemaLedgerMismatch {
        expected_head: Option<i64>,
        actual_head: Option<i64>,
        expected_entries: usize,
        actual_entries: usize,
        first_invalid: Option<i64>,
    },
    /// RLS 能力自检的探测 SQL 失败（acquire / set_config / catalog 查询）。
    #[error("postgres rls capability probe failed")]
    RlsCapability(#[source] sqlx::Error),
    /// RLS 能力门：发现含 `tenant_id` 列却未 FORCE RLS / 缺 policy 的 tenant 表（fail-closed，拒绝启动）。
    /// 具体表名经 `tracing::error!` 输出（PII 边界：Display 仅 const literal）。
    #[error("postgres tenant table missing FORCE RLS or policy")]
    RlsNotEnforced,
    /// RLS 能力门 anti-vacuity：durable 模式下未发现任何 tenant 表（schema 未迁移 / 库不符预期）。
    #[error("postgres rls capability: no tenant tables found")]
    RlsNoTenantTables,
    /// RLS 能力门：`rss.tenant_id` GUC set/current_setting roundtrip 未回显预期值（GUC 基础设施异常）。
    #[error("postgres rls capability: tenant guc roundtrip mismatch")]
    RlsGucRoundtrip,
    /// RLS 能力门：durable serving pool 必须以固定 app-serving role `rss_app` 连接；其它 non-bypass role
    /// 也不得作为生产 serving pool，避免测试替身 / owner-like 角色漂进 bootstrap。
    #[error("postgres rls capability: serving role must be rss_app")]
    RlsUnexpectedServingRole,
    #[error("postgres writer capability: role attributes are not exact")]
    WriterRoleAttributes,
    #[error("postgres writer capability: role membership is not empty")]
    WriterMembership,
    #[error("postgres writer capability: role owns database objects")]
    WriterOwnership,
    #[error("postgres writer capability: effective privileges are not exact")]
    WriterPrivileges { actual_fingerprint: String },
    /// Writer capability gate: custom `pg_default_acl` would implicitly authorize future objects
    /// for the serving writer (directly or via PUBLIC).
    #[error(
        "postgres writer capability: default privileges are not empty (fingerprint={actual_fingerprint})"
    )]
    WriterDefaultPrivileges { actual_fingerprint: String },
    /// Certificate-revocation capability catalog/ACL probe failed.
    #[error("postgres certificate revocation capability probe failed")]
    RevocationCapability(#[source] sqlx::Error),
    /// Certificate-revocation table, constraints, index, or RLS shape is incomplete.
    #[error("postgres certificate revocation schema capability is not exact")]
    RevocationSchema,
    /// Certificate-revocation serving/reader/maintenance ACLs are not the fixed minimum set.
    #[error("postgres certificate revocation privileges are not exact")]
    RevocationPrivileges,
    /// The fixed revocation maintenance role is absent or has widened attributes/membership.
    #[error("postgres certificate revocation maintenance role is not exact")]
    RevocationMaintenanceRole,
    /// The fixed revocation sweeper function is absent or has widened ownership/configuration/ACL.
    #[error("postgres certificate revocation maintenance function is not exact")]
    RevocationMaintenanceFunction,
    /// Saga receipt catalog/ACL capability probe failed.
    #[error("postgres saga receipt capability probe failed")]
    SagaReceiptCapability(#[source] sqlx::Error),
    /// Saga receipt table, pair triggers, retention function or authority surface drifted.
    #[error("postgres saga receipt catalog capability is not exact")]
    SagaReceiptCatalog { actual_fingerprint: String },
    /// tenant reader 能力门 catalog / GUC / ACL 探测失败。
    #[error("postgres tenant reader capability probe failed")]
    TenantReadCapability(#[source] sqlx::Error),
    /// tenant reader 必须直连固定 `rss_app_read` 角色。
    #[error("postgres tenant reader capability: role must be rss_app_read")]
    TenantReadUnexpectedRole,
    /// tenant reader 的 LOGIN / NOINHERIT / 非管理属性不满足精确集合。
    #[error("postgres tenant reader capability: role attributes are not exact")]
    TenantReadRoleAttributes,
    /// tenant reader 必须由 role config 默认开启只读事务，且当前事务必须已经只读。
    #[error("postgres tenant reader capability: default transaction read only is not enforced")]
    TenantReadDefaultTransaction,
    /// tenant reader 必须把 name resolution 固定到 `pg_catalog, public`。
    #[error("postgres tenant reader capability: search path is not exact")]
    TenantReadSearchPath,
    /// tenant reader 不得作为任何角色的成员，也不得拥有成员角色。
    #[error("postgres tenant reader capability: role membership is not empty")]
    TenantReadMembership,
    /// tenant reader 不得拥有数据库对象。
    #[error("postgres tenant reader capability: role owns database objects")]
    TenantReadOwnership,
    /// tenant reader 在当前数据库只能 CONNECT，不得 CREATE 或 TEMPORARY。
    #[error("postgres tenant reader capability: database privileges are not exact")]
    TenantReadDatabasePrivileges,
    /// tenant reader 必须且只能 SELECT 全部 tenant relations。
    #[error("postgres tenant reader capability: relation privileges are not exact")]
    TenantReadRelationPrivileges,
    /// tenant reader capability gate: custom `pg_default_acl` would implicitly authorize future
    /// objects for the serving reader (directly or via PUBLIC).
    #[error(
        "postgres tenant reader capability: default privileges are not empty (fingerprint={actual_fingerprint})"
    )]
    TenantReadDefaultPrivileges { actual_fingerprint: String },
    /// tenant reader 不得拥有 sequence 权限。
    #[error("postgres tenant reader capability: sequence privileges are not empty")]
    TenantReadSequencePrivileges,
    /// tenant reader 只能拥有 public schema USAGE，不得 CREATE 或访问其它业务 schema。
    #[error("postgres tenant reader capability: schema privileges are not exact")]
    TenantReadSchemaPrivileges,
    /// tenant reader 的有效业务函数集合必须且只能包含固定 active resolver。
    #[error("postgres tenant reader capability: function privileges are not exact")]
    TenantReadFunctionPrivileges {
        effective_functions: String,
        effective_exact: bool,
        resolver_security_exact: bool,
        resolver_security_details: String,
    },
    /// tenant reader 所依赖的固定 active resolver 实现发生漂移。
    #[error("postgres tenant reader capability: active resolver definition is not exact")]
    TenantReadFunctionDefinition { actual_fingerprint: String },
    /// tenant reader 不得执行任何会创建、写入、截断或删除 large object 的 pg_catalog 函数。
    #[error(
        "postgres tenant reader capability: large object mutator execute privileges are not empty"
    )]
    TenantReadLargeObjectMutatorPrivileges,
    /// tenant reader 不得读取任何 PostgreSQL large object。
    #[error("postgres tenant reader capability: large object privileges are not empty")]
    TenantReadLargeObjectPrivileges,
    /// `lo_compat_privileges` 必须关闭，否则 large object read 会绕过 ACL。
    #[error("postgres tenant reader capability: large object compatibility privileges are enabled")]
    TenantReadLargeObjectCompatibility,
    /// tenant reader 不得 SET / ALTER SYSTEM server parameters。
    #[error("postgres tenant reader capability: parameter privileges are not empty")]
    TenantReadParameterPrivileges,
    /// Projection source reader role/function/catalog probe failed.
    #[error("postgres projection source reader capability probe failed")]
    ProjectionSourceReadCapability(#[source] sqlx::Error),
    /// Projection source reader must be the exact function-only role.
    #[error("postgres projection source reader capability is not exact")]
    ProjectionSourceReadPrivileges { actual_fingerprint: String },
    /// Projection source reader role attributes or its direct allow-set drifted before the
    /// effective-capability fingerprint could be compared.
    #[error("postgres projection source reader role or direct grants are not exact")]
    ProjectionSourceReadRoleOrGrantMismatch,
    /// Projection source reader must not own any database object class.
    #[error("postgres projection source reader object ownership is not empty")]
    ProjectionSourceReadOwnership,
    /// Projection source reader fixed function implementation drifted.
    #[error("postgres projection source reader function definition is not exact")]
    ProjectionSourceReadFunctionDefinition { actual_fingerprint: String },
    /// Projection source reader may not persist through PostgreSQL large objects or parameter ACLs.
    #[error("postgres projection source reader external persistence capabilities are not empty")]
    ProjectionSourceReadExternalPersistencePrivileges,
    /// Projection operator role/function/catalog probe failed.
    #[error("postgres projection operator capability probe failed")]
    ProjectionOperatorCapability(#[source] sqlx::Error),
    /// Projection operator must be the exact independent control-plane role.
    #[error("postgres projection operator capability is not exact")]
    ProjectionOperatorPrivileges { actual_fingerprint: String },
    /// Projection operator role attributes or its direct allow-set drifted before the
    /// effective-capability fingerprint could be compared.
    #[error("postgres projection operator role or direct grants are not exact")]
    ProjectionOperatorRoleOrGrantMismatch,
    /// Projection operator must not own any database object class.
    #[error("postgres projection operator object ownership is not empty")]
    ProjectionOperatorOwnership,
    /// Projection operator fixed function implementation drifted.
    #[error("postgres projection operator function definitions are not exact")]
    ProjectionOperatorFunctionDefinitions { actual_fingerprint: String },
    /// Projection operator may not persist through PostgreSQL large objects or parameter ACLs.
    #[error("postgres projection operator external persistence capabilities are not empty")]
    ProjectionOperatorExternalPersistencePrivileges,
    /// Saga operator role/function/catalog probe failed.
    #[error("postgres Saga operator capability probe failed")]
    SagaOperatorCapability(#[source] sqlx::Error),
    /// Saga operator must be the exact function-only role and direct grant set.
    #[error("postgres Saga operator role or grants are not exact")]
    SagaOperatorRoleOrGrantMismatch,
    /// Saga operator must not own database objects.
    #[error("postgres Saga operator object ownership is not empty")]
    SagaOperatorOwnership,
    /// Saga operator may not persist through large objects or parameter ACLs.
    #[error("postgres Saga operator external persistence capabilities are not empty")]
    SagaOperatorExternalPersistencePrivileges,
    /// L2 DR lane role/function/catalog probe failed.
    #[error("postgres L2 DR recovery lane capability probe failed")]
    L2DrRecoveryLaneCapability(#[source] sqlx::Error),
    /// L2 DR lane must expose exactly its fixed effective function-only authority.
    #[error("postgres L2 DR recovery lane effective privileges are not exact")]
    L2DrRecoveryLanePrivileges,
    /// L2 DR lane must not own database objects.
    #[error("postgres L2 DR recovery lane object ownership is not empty")]
    L2DrRecoveryLaneOwnership,
    /// L2 DR lane may not persist through large objects or parameter ACLs.
    #[error("postgres L2 DR recovery lane external persistence capabilities are not empty")]
    L2DrRecoveryLaneExternalPersistencePrivileges,
    /// A committed start audit could not be represented as the exact typed proof.
    #[error("postgres L2 DR recovery durable start proof is inconsistent")]
    L2DrRecoveryProofInvariant,
    /// audit admin 能力门：必须直连固定 `rss_audit_admin` 角色。
    #[error("postgres audit admin capability: role must be rss_audit_admin")]
    AuditAdminUnexpectedRole,
    /// audit admin 能力门：admin read pool 不得为 superuser 或 BYPASSRLS。
    #[error(
        "postgres audit admin capability: connection role bypasses RLS (superuser or BYPASSRLS)"
    )]
    AuditAdminBypassRole,
    /// audit admin 能力门：admin read pool 只能拥有 `audit_entries` SELECT，不得有其它 public relation 权限。
    #[error("postgres audit admin capability: audit admin relation privileges are not exact")]
    AuditAdminPrivileges,
    /// settings ConfigValue maintenance durable audit 写入失败（维护入口 fail-closed）。
    #[error("postgres config value maintenance audit failed")]
    MaintenanceAudit(#[source] sqlx::Error),
    /// projection input binding registry 刷新失败（启动关键路径）。
    #[error("postgres projection input binding registry refresh failed")]
    ProjectionBindings(#[source] sqlx::Error),
    /// Frozen same-ID delivery policy could not be loaded from the migrator-owned singleton.
    #[error("postgres event delivery policy probe failed")]
    EventDeliveryPolicyProbe(#[source] sqlx::Error),
    /// The database policy is missing, duplicated, invalid, overflowing, or does not match the
    /// runtime relay budget being activated.
    #[error("postgres event delivery policy is invalid or does not match the runtime")]
    EventDeliveryPolicyMismatch,
    /// A DLX lifecycle pool exact-role/privilege catalog probe failed.
    #[error("postgres DLX lifecycle capability probe failed")]
    DlxLifecycleCapability(#[source] sqlx::Error),
    /// DLX lifecycle pool must connect directly as the fixed workload role.
    #[error("postgres DLX lifecycle capability: unexpected workload role")]
    DlxLifecycleUnexpectedRole,
    /// DLX workload roles may not bypass RLS or own cluster-wide administrative capabilities.
    #[error("postgres DLX lifecycle capability: role bypasses lifecycle confinement")]
    DlxLifecycleBypassRole,
    /// Each DLX workload role must have exactly its fixed function executions.
    #[error("postgres DLX lifecycle capability: privileges are not exact")]
    DlxLifecyclePrivileges,
    /// Audit-chain key pin function could not be executed on the serving writer lane.
    #[error("postgres audit chain key identity probe failed")]
    AuditChainKeyProbe(#[source] sqlx::Error),
    /// Configured key identity or key verification tag disagrees with the durable singleton.
    #[error("postgres audit chain key identity mismatch")]
    AuditChainKeyMismatch,
}

/// postgres 连接密码：私有字段 + redacted `Debug`，杜绝明文进日志 / panic message / `PgConfig` 派生 Debug。
///
/// **故意不实现 `Display`**：任何需要明文的路径只能经 [`PgPassword::expose`]（`pub(crate)`，仅 crate 内喂
/// 给 sqlx），杜绝下游 `format!("{pw}")` 意外泄漏。
#[derive(Clone)]
pub struct PgPassword(zeroize::Zeroizing<String>);

impl PgPassword {
    /// 由密文构造。
    pub fn new(secret: impl Into<String>) -> Self {
        Self(zeroize::Zeroizing::new(secret.into()))
    }

    /// crate 内借出明文，仅用于喂给 sqlx `PgConnectOptions`（外部不可见）。
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for PgPassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // reason: 密码字段 Debug 恒输出占位常量，杜绝明文泄漏（对齐 secure 的 `<redacted>` Debug 范式，如
        // secure::Plaintext / secure::OpaqueToken）。
        f.write_str("PgPassword(<redacted>)")
    }
}

/// postgres adapter 连接 + 连接池配置——adapter 拥有的稳定配置面，组合根据此构造（无需识 sqlx 类型）。
///
/// 连接参数（host / port / database / username / password）必填经 [`PgConfig::new`]；TLS 模式默认
/// [`DEFAULT_SSL_MODE`]（`VerifyFull`，零信任）、池 tuning 取默认，均经 `with_*` 累加调整。最终由
/// `PgStore::connect`（`pub(crate)` funnel，经 [`crate::PgRuntimeDeps::setup`]）调 [`PgConfig::validate`]
/// fail-fast 校验。
#[derive(Clone, Debug)]
pub struct PgConfig {
    host: String,
    port: u16,
    database: String,
    username: String,
    password: PgPassword,
    ssl_mode: PgSslMode,
    ssl_root_cert: Option<PathBuf>,
    max_connections: u32,
    acquire_timeout: Duration,
}

impl PgConfig {
    /// 由必填连接参数构造；TLS 默认 [`DEFAULT_SSL_MODE`]、池 tuning 取默认
    /// （[`DEFAULT_MAX_CONNECTIONS`] / [`DEFAULT_ACQUIRE_TIMEOUT`]）。
    #[must_use]
    pub fn new(
        host: impl Into<String>,
        port: u16,
        database: impl Into<String>,
        username: impl Into<String>,
        password: PgPassword,
    ) -> Self {
        Self {
            host: host.into(),
            port,
            database: database.into(),
            username: username.into(),
            password,
            ssl_mode: DEFAULT_SSL_MODE,
            ssl_root_cert: None,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            acquire_timeout: DEFAULT_ACQUIRE_TIMEOUT,
        }
    }

    /// 调整 TLS 模式（默认 [`DEFAULT_SSL_MODE`] = `VerifyFull`）。本地无 TLS 开发须**显式**降级
    /// （如 `PgSslMode::Prefer`），不静默。
    #[must_use]
    pub fn with_ssl_mode(mut self, mode: PgSslMode) -> Self {
        self.ssl_mode = mode;
        self
    }

    /// 注入服务端证书校验用的根 CA 证书（PEM/DER 路径）。内部 / 私有 CA 部署下，`VerifyFull` 需此才能
    /// 校验非公共 CA 签发的服务端证书（否则只信 webpki-roots 公共根）。
    #[must_use]
    pub fn with_ssl_root_cert(mut self, path: impl Into<PathBuf>) -> Self {
        self.ssl_root_cert = Some(path.into());
        self
    }

    /// 调整连接池上限（累加式 builder；最终由 `PgStore::connect`（`pub(crate)` funnel）validate）。
    #[must_use]
    pub fn with_max_connections(mut self, max: u32) -> Self {
        self.max_connections = max;
        self
    }

    /// 调整获取连接超时。
    #[must_use]
    pub fn with_acquire_timeout(mut self, timeout: Duration) -> Self {
        self.acquire_timeout = timeout;
        self
    }

    /// fail-fast 校验：host / database / username / password 非空、port ≠ 0、max_connections ≥ 1。
    pub(crate) fn validate(&self) -> Result<(), PgError> {
        if self.host.trim().is_empty() {
            return Err(PgError::EmptyHost);
        }
        if self.port == 0 {
            return Err(PgError::ZeroPort);
        }
        if self.database.trim().is_empty() {
            return Err(PgError::EmptyDatabase);
        }
        if self.username.trim().is_empty() {
            return Err(PgError::EmptyUsername);
        }
        if self.password.expose().is_empty() {
            return Err(PgError::EmptyPassword);
        }
        if self.max_connections == 0 {
            return Err(PgError::ZeroMaxConnections);
        }
        Ok(())
    }

    /// 映射为 sqlx 连接描述（密码经 [`PgPassword::expose`] 仅在此传入 sqlx，不外泄；TLS 模式显式注入）。
    #[cfg(test)]
    pub(crate) fn connect_options(&self) -> PgConnectOptions {
        self.connect_options_for(APPLICATION_NAME)
    }

    fn connect_options_for(&self, application_name: &'static str) -> PgConnectOptions {
        let mut opts = PgConnectOptions::new()
            .host(&self.host)
            .port(self.port)
            .database(&self.database)
            .username(&self.username)
            .password(self.password.expose())
            .ssl_mode(self.ssl_mode)
            .application_name(application_name);
        if let Some(ref cert) = self.ssl_root_cert {
            opts = opts.ssl_root_cert(cert);
        }
        opts
    }
}

/// Opaque configuration for the dedicated tenant read lane.
///
/// A distinct public type makes the mandatory reader argument impossible to swap accidentally
/// with the writer [`PgConfig`] at runtime assembly call sites. The contained password keeps the
/// same redacted [`Debug`](std::fmt::Debug) behavior as [`PgConfig`].
#[derive(Clone)]
pub struct PgTenantReadConfig(PgConfig);

impl PgTenantReadConfig {
    /// Explicitly classify a PostgreSQL connection configuration as the tenant reader lane.
    #[must_use]
    pub fn new(config: PgConfig) -> Self {
        Self(config)
    }

    pub(crate) fn as_pg_config(&self) -> &PgConfig {
        &self.0
    }
}

impl std::fmt::Debug for PgTenantReadConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PgTenantReadConfig").field(&self.0).finish()
    }
}

/// Opaque configuration for the tenant/projection/definition-scoped source reader lane.
#[derive(Clone)]
pub struct PgProjectionSourceReadConfig(PgConfig);

impl PgProjectionSourceReadConfig {
    #[must_use]
    pub fn new(config: PgConfig) -> Self {
        Self(config)
    }

    pub(crate) fn as_pg_config(&self) -> &PgConfig {
        &self.0
    }
}

impl std::fmt::Debug for PgProjectionSourceReadConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PgProjectionSourceReadConfig")
            .field(&self.0)
            .finish()
    }
}

/// Opaque configuration for the independent Projection control-plane credential.
#[derive(Clone)]
pub struct PgProjectionOperatorConfig(PgConfig);

impl PgProjectionOperatorConfig {
    #[must_use]
    pub fn new(config: PgConfig) -> Self {
        Self(config)
    }

    pub(crate) fn as_pg_config(&self) -> &PgConfig {
        &self.0
    }
}

/// Opaque configuration for the independent function-only Saga operator credential.
#[derive(Clone)]
pub struct PgSagaOperatorConfig(PgConfig);

impl PgSagaOperatorConfig {
    #[must_use]
    pub fn new(config: PgConfig) -> Self {
        Self(config)
    }

    pub(crate) fn as_pg_config(&self) -> &PgConfig {
        &self.0
    }
}

impl std::fmt::Debug for PgSagaOperatorConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PgSagaOperatorConfig")
            .field(&self.0)
            .finish()
    }
}

/// Opaque configuration for the function-only L2 DR authentication/audit credential.
#[derive(Clone)]
pub struct PgL2DrRecoveryAuditConfig(PgConfig);

impl PgL2DrRecoveryAuditConfig {
    #[must_use]
    pub fn new(config: PgConfig) -> Self {
        Self(config)
    }

    pub(crate) fn as_pg_config(&self) -> &PgConfig {
        &self.0
    }
}

impl std::fmt::Debug for PgL2DrRecoveryAuditConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PgL2DrRecoveryAuditConfig")
            .field(&self.0)
            .finish()
    }
}

/// Opaque configuration for the function-only L2 DR apply executor credential.
#[derive(Clone)]
pub struct PgL2DrRecoveryExecutorConfig(PgConfig);

impl PgL2DrRecoveryExecutorConfig {
    #[must_use]
    pub fn new(config: PgConfig) -> Self {
        Self(config)
    }

    pub(crate) fn as_pg_config(&self) -> &PgConfig {
        &self.0
    }
}

impl std::fmt::Debug for PgL2DrRecoveryExecutorConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PgL2DrRecoveryExecutorConfig")
            .field(&self.0)
            .finish()
    }
}

impl std::fmt::Debug for PgProjectionOperatorConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PgProjectionOperatorConfig")
            .field(&self.0)
            .finish()
    }
}

/// A writer store that has passed the exact serving-role and tenant-RLS startup gate.
#[derive(Clone)]
pub(crate) struct VerifiedPgWriteStore(Arc<PgStore>);

/// A reader store that has passed the exact role, ACL, default-read-only and tenant-RLS gate.
#[derive(Clone)]
pub(crate) struct VerifiedPgReadStore(Arc<PgStore>);

/// A Projection source reader that passed the exact scoped-function-only role gate.
#[derive(Clone)]
pub(crate) struct VerifiedPgProjectionSourceReadStore(Arc<PgStore>);

/// A Projection operator store that passed its exact independent-role gate.
#[derive(Clone)]
pub(crate) struct VerifiedPgProjectionOperatorStore(Arc<PgStore>);

/// A Saga operator store that passed its exact function-only role gate.
#[derive(Clone)]
pub(crate) struct VerifiedPgSagaOperatorStore(Arc<PgStore>);

/// An L2 DR audit store that passed its exact function-only role gate.
#[derive(Clone)]
pub(crate) struct VerifiedPgL2DrRecoveryAuditStore(Arc<PgStore>);

/// An L2 DR executor store that passed its exact function-only role gate.
#[derive(Clone)]
pub(crate) struct VerifiedPgL2DrRecoveryExecutorStore(Arc<PgStore>);

/// An audit-admin store that has passed its independent exact-role and ACL gate.
#[derive(Clone)]
pub(crate) struct VerifiedPgAuditAdminStore(Arc<PgStore>);

/// Explicit capability for migrator/operator maintenance paths that intentionally require both
/// tenant reads and writes without impersonating either serving lane.
#[derive(Clone)]
pub(crate) struct VerifiedPgMaintenanceStore(Arc<PgStore>);

/// Required pair of verified writer and tenant-reader stores used by the durable runtime.
#[derive(Clone)]
pub(crate) struct PgRuntimeStores {
    writer: VerifiedPgWriteStore,
    reader: VerifiedPgReadStore,
}

impl PgRuntimeStores {
    pub(crate) fn new(writer: VerifiedPgWriteStore, reader: VerifiedPgReadStore) -> Self {
        Self { writer, reader }
    }

    pub(crate) fn writer_store_arc(&self) -> Arc<PgStore> {
        Arc::clone(&self.writer.0)
    }

    pub(crate) fn reader_store_arc(&self) -> Arc<PgStore> {
        Arc::clone(&self.reader.0)
    }

    pub(crate) fn writer_capability(&self) -> &VerifiedPgWriteStore {
        &self.writer
    }

    pub(crate) fn reader_capability(&self) -> &VerifiedPgReadStore {
        &self.reader
    }

    #[cfg(any(test, feature = "test-support", feature = "fault-matrix-test-support"))]
    #[allow(dead_code)]
    pub(crate) fn from_unverified_for_test(writer: Arc<PgStore>, reader: Arc<PgStore>) -> Self {
        Self {
            writer: VerifiedPgWriteStore(writer),
            reader: VerifiedPgReadStore(reader),
        }
    }
}

impl VerifiedPgReadStore {
    pub(crate) fn pool(&self) -> &sqlx::PgPool {
        &self.0.pool
    }

    pub(crate) fn store_arc(&self) -> Arc<PgStore> {
        Arc::clone(&self.0)
    }
}

impl VerifiedPgProjectionSourceReadStore {
    pub(crate) fn pool(&self) -> &sqlx::PgPool {
        &self.0.pool
    }

    pub(crate) fn store_arc(&self) -> Arc<PgStore> {
        Arc::clone(&self.0)
    }
}

impl VerifiedPgProjectionOperatorStore {
    pub(crate) fn pool(&self) -> &sqlx::PgPool {
        &self.0.pool
    }

    pub(crate) fn store_arc(&self) -> Arc<PgStore> {
        Arc::clone(&self.0)
    }
}

impl VerifiedPgSagaOperatorStore {
    pub(crate) fn store_arc(&self) -> Arc<PgStore> {
        Arc::clone(&self.0)
    }
}

impl VerifiedPgL2DrRecoveryAuditStore {
    pub(crate) fn store_arc(&self) -> Arc<PgStore> {
        Arc::clone(&self.0)
    }
}

impl VerifiedPgL2DrRecoveryExecutorStore {
    pub(crate) fn store_arc(&self) -> Arc<PgStore> {
        Arc::clone(&self.0)
    }
}

impl VerifiedPgWriteStore {
    pub(crate) fn pool(&self) -> &sqlx::PgPool {
        &self.0.pool
    }

    pub(crate) fn store_arc(&self) -> Arc<PgStore> {
        Arc::clone(&self.0)
    }
}

impl VerifiedPgAuditAdminStore {
    #[allow(dead_code)]
    pub(crate) fn pool(&self) -> &sqlx::PgPool {
        &self.0.pool
    }

    pub(crate) fn store_arc(&self) -> Arc<PgStore> {
        Arc::clone(&self.0)
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn from_unverified_for_test(store: Arc<PgStore>) -> Self {
        Self(store)
    }
}

impl VerifiedPgMaintenanceStore {
    /// Wrap a store only after the maintenance setup path has completed its own connection and
    /// migration/policy verification sequence.
    pub(crate) fn from_maintenance_store(store: Arc<PgStore>) -> Self {
        Self(store)
    }

    pub(crate) fn store_arc(&self) -> Arc<PgStore> {
        Arc::clone(&self.0)
    }

    pub(crate) fn pool(&self) -> &sqlx::PgPool {
        &self.0.pool
    }
}

/// Independent acquire/query deadline. Pool pressure is classified before query liveness so a
/// 30-second configured acquire timeout cannot turn an ordinary full pool into a 2-second Down.
const PROBE_READINESS_TIMEOUT: Duration = Duration::from_secs(2);

/// DB liveness 采样结果三态（#1309 F4 重引 `Saturated`，区分池饱和与 DB 不可达）。
///
/// - `Ready`：`probe_db_liveness` 成功（`SELECT 1` 返回，HTTP 200 Healthy）。
/// - `Saturated`：全部已建连接忙（容量压力；HTTP 200 Degraded，编排器不摘流）。
/// - `Down`：池已关闭、DB 不可达或 `SELECT 1` 失败（HTTP 503 Unhealthy）。
///
/// `#[non_exhaustive]`：未来变体不破坏外部 match 调用方（`_ =>` fallback）。
/// `ConfigsReadyProbe::check` 读 `PgDbReadiness::snapshot()` 经此类型报 readyz 状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PoolReadiness {
    /// `probe_db_liveness` 成功（`SELECT 1` 返回）。
    Ready,
    /// 全部已建连接忙（容量压力）：降级可服务，编排器不应摘流（HTTP 200）。
    Saturated,
    /// 池已关闭、DB 不可达或 `SELECT 1` 失败：不可服务（HTTP 503）。
    Down,
}

async fn db_probe_query(
    conn: &mut sqlx::pool::PoolConnection<sqlx::Postgres>,
    query: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(query).execute(&mut **conn).await.map(|_| ())
}

fn pool_is_saturated(pool: &sqlx::PgPool) -> bool {
    pool.num_idle() == 0 && pool.size() >= pool.options().get_max_connections()
}

fn unavailable_pool_readiness(pool: &sqlx::PgPool) -> PoolReadiness {
    if pool_is_saturated(pool) {
        PoolReadiness::Saturated
    } else {
        PoolReadiness::Down
    }
}

// reason: tracing macro expansion inflates the lint score; the real control flow is three result arms.
#[allow(clippy::cognitive_complexity)]
fn probe_query_result(
    result: Result<Result<(), sqlx::Error>, tokio::time::error::Elapsed>,
) -> PoolReadiness {
    match result {
        Ok(Ok(())) => PoolReadiness::Ready,
        Ok(Err(e)) => {
            tracing::debug!(
                target: "postgres",
                error = %secure::redact_error(&e),
                "postgres readiness sample failed"
            );
            PoolReadiness::Down
        }
        Err(_elapsed) => {
            tracing::debug!(
                target: "postgres",
                timeout_secs = PROBE_READINESS_TIMEOUT.as_secs(),
                "postgres readiness query timed out — treating database lane as down"
            );
            PoolReadiness::Down
        }
    }
}

async fn acquire_probe_connection(
    pool: &sqlx::PgPool,
) -> Result<sqlx::pool::PoolConnection<sqlx::Postgres>, PoolReadiness> {
    if let Some(connection) = pool.try_acquire() {
        return Ok(connection);
    }
    if pool_is_saturated(pool) {
        return Err(PoolReadiness::Saturated);
    }

    let result = tokio::time::timeout(PROBE_READINESS_TIMEOUT, pool.acquire()).await;
    classify_acquire_result(pool, result)
}

fn classify_acquire_result(
    pool: &sqlx::PgPool,
    result: Result<
        Result<sqlx::pool::PoolConnection<sqlx::Postgres>, sqlx::Error>,
        tokio::time::error::Elapsed,
    >,
) -> Result<sqlx::pool::PoolConnection<sqlx::Postgres>, PoolReadiness> {
    match result {
        Ok(Ok(connection)) => Ok(connection),
        Ok(Err(error)) => classify_acquire_error(pool, &error),
        Err(_elapsed) => classify_acquire_timeout(pool),
    }
}

fn classify_acquire_error(
    pool: &sqlx::PgPool,
    error: &sqlx::Error,
) -> Result<sqlx::pool::PoolConnection<sqlx::Postgres>, PoolReadiness> {
    tracing::debug!(
        target: "postgres",
        error = %secure::redact_error(error),
        "postgres readiness connection acquire failed"
    );
    Err(unavailable_pool_readiness(pool))
}

fn classify_acquire_timeout(
    pool: &sqlx::PgPool,
) -> Result<sqlx::pool::PoolConnection<sqlx::Postgres>, PoolReadiness> {
    let readiness = unavailable_pool_readiness(pool);
    tracing::debug!(
        target: "postgres",
        ?readiness,
        timeout_secs = PROBE_READINESS_TIMEOUT.as_secs(),
        "postgres readiness connection acquire timed out"
    );
    Err(readiness)
}

impl PgStore {
    async fn probe_db_liveness_query(&self, query: &str) -> PoolReadiness {
        if self.pool.is_closed() {
            return PoolReadiness::Down;
        }
        let mut connection = match acquire_probe_connection(&self.pool).await {
            Ok(connection) => connection,
            Err(readiness) => return readiness,
        };
        let result = tokio::time::timeout(
            PROBE_READINESS_TIMEOUT,
            db_probe_query(&mut connection, query),
        )
        .await;
        probe_query_result(result)
    }

    /// DB liveness probe with separate capacity and query-liveness stages.
    ///
    /// - `pool.is_closed()` → `PoolReadiness::Down`（快路径，不 acquire）。
    /// - no idle connection and `size == max_connections` → `Saturated` without waiting;
    /// - unused capacity that cannot establish a connection → `Down`;
    /// - an acquired connection whose `SELECT 1` fails or times out → `Down`;
    /// - successful `SELECT 1` → `Ready`.
    ///
    /// 第三方 `sqlx::Error` 经 [`secure::redact_error`] 脱敏后落 `tracing::debug!`，杜绝连接串 / 凭据泄漏。
    /// DB 持续不可达时**不每 tick warn！**——状态转移日志由 [`crate::readiness::pg_readiness_sampling_loop`] 负责。
    ///
    /// 供 [`crate::readiness::pg_readiness_sampling_loop`] 周期调用；同步读采样状态用
    /// [`crate::readiness::PgDbReadiness::snapshot`]——不阻塞 reactor。
    #[must_use]
    pub async fn probe_db_liveness(&self) -> PoolReadiness {
        self.probe_db_liveness_query("SELECT 1").await
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) async fn probe_db_liveness_query_for_test(&self, query: &str) -> PoolReadiness {
        self.probe_db_liveness_query(query).await
    }
}

/// RLS 能力自检的固定探测租户（canonical 非-nil UUID，仅用于 GUC roundtrip；不写任何业务行）。
const RLS_PROBE_TENANT: &str = "00000000-0000-0000-0000-000000000001";
/// durable serving pool 唯一允许的 PostgreSQL role。
const EXPECTED_SERVING_ROLE: &str = "rss_app";
/// tenant read lane 唯一允许的 PostgreSQL role。
const EXPECTED_TENANT_READ_ROLE: &str = "rss_app_read";
/// audit admin read pool 唯一允许的 PostgreSQL role。
const EXPECTED_AUDIT_ADMIN_ROLE: &str = "rss_audit_admin";

/// 不达标 tenant 表查询：动态派生（含 `tenant_id` 列的 public 表）后逐表判不达标——
/// (a) 缺 `relrowsecurity AND relforcerowsecurity`（ENABLE+FORCE）；或
/// (b) 无 permissive policy；或
/// (c) 任一 permissive policy 的 `qual` / `with_check` 不精确等于 canonical tenant predicate。
///     PostgreSQL 会把 permissive policies 以 OR 合并，因此不是“至少一个正确”即可，而是每条 permissive
///     policy 都必须精确绑定 tenant；额外收窄须使用独立 `AS RESTRICTIVE` policy。
/// (d) permissive policy 依赖任何非本表 catalog 对象。内建 `pg_catalog` operator/function 是 pinned
///     dependency，不产生 `pg_depend` 行；同形异义的用户自定义 operator/function 会产生非 `pg_class`
///     dependency，必须 fail-closed，避免 `pg_policies` deparse 文本相同但语义已被 search_path 劫持。
/// 返回不达标表名。不硬编码表清单。每条 permissive policy 的 USING / WITH CHECK 都必须精确等于
/// `tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid` 等值绑定；仅把三个 token 塞进
/// `IS NOT NULL`、`NOT (canonical)` 或 `canonical = false` 等表达式不能通过。
const OFFENDING_TENANT_TABLES_SQL: &str = r#"
SELECT c.relname
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
  AND EXISTS (SELECT 1 FROM pg_attribute a
              WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped)
  AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity
       OR NOT EXISTS (SELECT 1 FROM pg_policies p
                      WHERE p.schemaname = 'public' AND p.tablename = c.relname
                        AND p.permissive = 'PERMISSIVE')
       OR EXISTS (SELECT 1 FROM pg_policies p
                  WHERE p.schemaname = 'public' AND p.tablename = c.relname
                    AND p.permissive = 'PERMISSIVE'
                    AND (coalesce(p.qual, '') !~* '^[[:space:]]*\(*[[:space:]]*tenant_id[[:space:]]*=[[:space:]]*\(*[[:space:]]*nullif[[:space:]]*\([[:space:]]*current_setting[[:space:]]*\([[:space:]]*''rss[.]tenant_id''(::text)?[[:space:]]*,[[:space:]]*true[[:space:]]*\)[[:space:]]*,[[:space:]]*''''(::text)?[[:space:]]*\)[[:space:]]*\)*[[:space:]]*::uuid[[:space:]]*\)*[[:space:]]*$'
                         OR coalesce(p.with_check, '') !~* '^[[:space:]]*\(*[[:space:]]*tenant_id[[:space:]]*=[[:space:]]*\(*[[:space:]]*nullif[[:space:]]*\([[:space:]]*current_setting[[:space:]]*\([[:space:]]*''rss[.]tenant_id''(::text)?[[:space:]]*,[[:space:]]*true[[:space:]]*\)[[:space:]]*,[[:space:]]*''''(::text)?[[:space:]]*\)[[:space:]]*\)*[[:space:]]*::uuid[[:space:]]*\)*[[:space:]]*$'))
       OR EXISTS (SELECT 1
                  FROM pg_policy policy
                  JOIN pg_depend dependency
                    ON dependency.classid = 'pg_policy'::regclass
                   AND dependency.objid = policy.oid
                  WHERE policy.polrelid = c.oid
                    AND policy.polpermissive
                    AND dependency.refclassid <> 'pg_class'::regclass))
"#;

/// 当前连接角色及其 RLS 绕过属性。serving pool 必须直连固定 `rss_app`，且不得 superuser/BYPASSRLS。
const CONNECTION_ROLE_SQL: &str = "\
SELECT session_user, current_user, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user";

const WRITER_ROLE_SQL: &str = r#"
SELECT session_user, current_user, role.rolcanlogin, role.rolsuper, role.rolbypassrls,
       role.rolcreatedb, role.rolcreaterole, role.rolreplication, role.rolinherit
FROM pg_roles AS role
WHERE role.rolname = current_user
"#;

const WRITER_EFFECTIVE_CAPABILITIES_SQL: &str = r#"
WITH capabilities AS (
    SELECT 'database:' || privilege.name AS capability
    FROM (VALUES ('CONNECT'), ('CREATE'), ('TEMPORARY'),
                 ('CONNECT WITH GRANT OPTION'), ('CREATE WITH GRANT OPTION'),
                 ('TEMPORARY WITH GRANT OPTION')) AS privilege(name)
    WHERE has_database_privilege(current_user, current_database(), privilege.name)
    UNION ALL
    SELECT 'schema:' || namespace.nspname || ':' || privilege.name
    FROM pg_namespace AS namespace
    CROSS JOIN (VALUES ('USAGE'), ('CREATE'), ('USAGE WITH GRANT OPTION'),
                       ('CREATE WITH GRANT OPTION')) AS privilege(name)
    WHERE namespace.nspname <> 'information_schema'
      AND namespace.nspname !~ '^pg_'
      AND has_schema_privilege(current_user, namespace.oid, privilege.name)
    UNION ALL
    SELECT 'relation:' || namespace.nspname || '.' || relation.relname || ':' || privilege.name
    FROM pg_class AS relation
    JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
    CROSS JOIN (VALUES ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE'), ('TRUNCATE'),
                       ('REFERENCES'), ('TRIGGER'), ('SELECT WITH GRANT OPTION'),
                       ('INSERT WITH GRANT OPTION'), ('UPDATE WITH GRANT OPTION'),
                       ('DELETE WITH GRANT OPTION'), ('TRUNCATE WITH GRANT OPTION'),
                       ('REFERENCES WITH GRANT OPTION'), ('TRIGGER WITH GRANT OPTION'))
                       AS privilege(name)
    WHERE namespace.nspname <> 'information_schema'
      AND namespace.nspname !~ '^pg_'
      AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
      AND has_table_privilege(current_user, relation.oid, privilege.name)
    UNION ALL
    SELECT 'sequence:' || namespace.nspname || '.' || relation.relname || ':' || privilege.name
    FROM pg_class AS relation
    JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
    CROSS JOIN (VALUES ('USAGE'), ('SELECT'), ('UPDATE'), ('USAGE WITH GRANT OPTION'),
                       ('SELECT WITH GRANT OPTION'), ('UPDATE WITH GRANT OPTION'))
                       AS privilege(name)
    WHERE namespace.nspname <> 'information_schema'
      AND namespace.nspname !~ '^pg_'
      AND relation.relkind = 'S'
      AND has_sequence_privilege(current_user, relation.oid, privilege.name)
    UNION ALL
    SELECT 'column:' || namespace.nspname || '.' || relation.relname || '.' ||
           attribute.attname || ':' || privilege.name
    FROM pg_class AS relation
    JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
    JOIN pg_attribute AS attribute ON attribute.attrelid = relation.oid
    CROSS JOIN (VALUES ('SELECT'), ('INSERT'), ('UPDATE'), ('REFERENCES'),
                       ('SELECT WITH GRANT OPTION'), ('INSERT WITH GRANT OPTION'),
                       ('UPDATE WITH GRANT OPTION'), ('REFERENCES WITH GRANT OPTION'))
                       AS privilege(name)
    WHERE namespace.nspname <> 'information_schema'
      AND namespace.nspname !~ '^pg_'
      AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
      AND attribute.attnum > 0 AND NOT attribute.attisdropped
      AND has_column_privilege(current_user, relation.oid, attribute.attnum, privilege.name)
    UNION ALL
    SELECT 'function:' || namespace.nspname || '.' || procedure.proname ||
           '(' || pg_get_function_identity_arguments(procedure.oid) || '):' || privilege.name
    FROM pg_proc AS procedure
    JOIN pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
    CROSS JOIN (VALUES ('EXECUTE'), ('EXECUTE WITH GRANT OPTION')) AS privilege(name)
    WHERE namespace.nspname <> 'information_schema'
      AND namespace.nspname !~ '^pg_'
      AND has_function_privilege(current_user, procedure.oid, privilege.name)
)
SELECT capability FROM capabilities ORDER BY capability
"#;

// Byte-level golden of the complete effective capability catalog after the committed migration
// head. Any migration that intentionally changes writer authority must update this reviewed value.
const EXPECTED_WRITER_CAPABILITY_FINGERPRINT: &str =
    "sha256:ff14653aea4dad6b5ebcc307152349462400851278b3c1eed3c94679e9ef0cc0";
const EXPECTED_PROJECTION_SOURCE_CAPABILITY_FINGERPRINT: &str =
    "sha256:7f06edc9c68f4a6da2567d5ac74c3a382cf6f0af9629ef5d144908f405781125";
const EXPECTED_PROJECTION_OPERATOR_CAPABILITY_FINGERPRINT: &str =
    "sha256:cad2f8308d618a8228b4eda3aea2404a888ff8f131a8ee5fe7671ce4729bd8cf";
const EXPECTED_PROJECTION_SOURCE_FUNCTION_FINGERPRINT: &str =
    "sha256:bcd85f1793dbd7b52b3b1cf92ed835db90b9866e5f29520520878a061fa3c6d8";
const EXPECTED_PROJECTION_OPERATOR_FUNCTION_FINGERPRINT: &str =
    "sha256:630d472191ed562717aec601d5f32d248e06c23c1b7bd1aa75d7707f4e7bfed7";
const EXPECTED_TENANT_READ_FUNCTION_FINGERPRINT: &str =
    "sha256:a4acf64119c15ed5a836550100fbff32c3c0eac3024b8349ea20c368dc060c9b";

/// Sorted capability rows for custom `pg_default_acl` privileges targeting the current serving
/// role or PUBLIC across all custom object types (`r`/`S`/`f`/`T`/`n`). Empty result set is the
/// exact posture; non-empty rows are hashed before log/error (no raw grantor/schema dumps).
const SERVING_DEFAULT_ACL_SQL: &str = r#"
SELECT CASE defacl.defaclobjtype
           WHEN 'r' THEN 'TABLE'
           WHEN 'S' THEN 'SEQUENCE'
           WHEN 'f' THEN 'FUNCTION'
           WHEN 'T' THEN 'TYPE'
           WHEN 'n' THEN 'SCHEMA'
           ELSE defacl.defaclobjtype::text
       END
       || ':' || CASE
           WHEN defacl.defaclnamespace = 0 THEN '*'
           ELSE COALESCE(namespace.nspname, defacl.defaclnamespace::text)
       END
       || ':' || CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE 'ROLE' END
       || ':' || upper(acl.privilege_type)
       || CASE WHEN acl.is_grantable THEN '_WITH_GRANT_OPTION' ELSE '' END AS capability
FROM pg_catalog.pg_default_acl AS defacl
LEFT JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = defacl.defaclnamespace
CROSS JOIN LATERAL pg_catalog.aclexplode(defacl.defaclacl) AS acl
WHERE defacl.defaclobjtype IN ('r', 'S', 'f', 'T', 'n')
  AND acl.grantee IN (
      0::oid,
      (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user)
  )
ORDER BY capability
"#;

fn effective_capability_fingerprint(capabilities: &[(String,)]) -> String {
    use sha2::{Digest as _, Sha256};

    let mut digest = Sha256::new();
    for (capability,) in capabilities {
        digest.update(capability.as_bytes());
        digest.update([b'\n']);
    }
    format!("sha256:{:x}", digest.finalize())
}

async fn load_effective_capability_fingerprint(pool: &sqlx::PgPool) -> Result<String, sqlx::Error> {
    let capabilities: Vec<(String,)> = sqlx::query_as(WRITER_EFFECTIVE_CAPABILITIES_SQL)
        .fetch_all(pool)
        .await?;
    Ok(effective_capability_fingerprint(&capabilities))
}

/// Capabilities outside the application-schema fingerprint that can still persist cluster state.
///
/// `pg_catalog` functions are deliberately excluded from the fingerprint because ordinary query
/// functions are ambient PostgreSQL API. The fixed large-object mutator universe, large-object
/// ACLs, parameter ACLs and the compatibility override therefore need an explicit negative gate.
async fn has_projection_external_persistence_capabilities(
    pool: &sqlx::PgPool,
) -> Result<bool, sqlx::Error> {
    let large_object_mutators: String =
        sqlx::query_scalar(TENANT_READ_LARGE_OBJECT_MUTATOR_PRIVILEGES_SQL)
            .fetch_one(pool)
            .await?;
    let large_objects: String = sqlx::query_scalar(TENANT_READ_LARGE_OBJECT_PRIVILEGES_SQL)
        .fetch_one(pool)
        .await?;
    let parameters: String = sqlx::query_scalar(TENANT_READ_PARAMETER_PRIVILEGES_SQL)
        .fetch_one(pool)
        .await?;
    let lo_compat_privileges: String =
        sqlx::query_scalar("SELECT current_setting('lo_compat_privileges')")
            .fetch_one(pool)
            .await?;
    Ok(!large_object_mutators.is_empty()
        || !large_objects.is_empty()
        || !parameters.is_empty()
        || lo_compat_privileges != "off")
}

const PROJECTION_SOURCE_FUNCTION_DEFINITIONS_SQL: &str = r#"
SELECT procedure.proname,
       language.lanname,
       procedure.prosrc,
       procedure.provolatile::text,
       procedure.proparallel::text,
       procedure.proleakproof,
       procedure.proisstrict
FROM pg_catalog.pg_proc AS procedure
JOIN pg_catalog.pg_language AS language ON language.oid = procedure.prolang
WHERE procedure.oid IN (
    'public.rss_assert_projection_source_scope(boolean,uuid,uuid,uuid,text,text,text,text)'::regprocedure,
    'public.rss_read_projection_events_scoped(uuid,uuid,uuid,text,text,text,text,bigint,integer)'::regprocedure,
    'public.rss_projection_source_high_water_scoped(uuid,uuid,uuid,text,text,text,text)'::regprocedure
)
ORDER BY procedure.proname
"#;

const PROJECTION_OPERATOR_FUNCTION_DEFINITIONS_SQL: &str = r#"
SELECT procedure.proname,
       language.lanname,
       procedure.prosrc,
       procedure.provolatile::text,
       procedure.proparallel::text,
       procedure.proleakproof,
       procedure.proisstrict
FROM pg_catalog.pg_proc AS procedure
JOIN pg_catalog.pg_language AS language ON language.oid = procedure.prolang
WHERE procedure.oid IN (
    'public.rss_service_token_replay_check_and_record(bytea,timestamp with time zone)'::regprocedure,
    'public.rss_projection_operator_record_audit(bigint,integer,text,text,text,text,text,text,text)'::regprocedure,
    'public.rss_projection_operator_get_checkpoint(uuid,text,text)'::regprocedure,
    'public.rss_projection_operator_save_checkpoint(uuid,text,text,bigint,bigint)'::regprocedure,
    'public.rss_projection_operator_status_active(uuid)'::regprocedure,
    'public.rss_projection_operator_swap_active(uuid,text,text,bigint,text,text,text)'::regprocedure,
    'public.rss_projection_operator_sweep_source_capabilities()'::regprocedure,
    'public.rss_projection_operator_issue_source_capability(uuid,text,text,text,text)'::regprocedure,
    'public.rss_settings_projection_apply_operator(uuid,text,text,text,text,text,text,bigint,text,text,bigint,bigint,bytea)'::regprocedure,
    'public.rss_projection_operator_insert_dead_letter(uuid,text,text,text,text,text,text,jsonb,text,bigint,text,bytea,text,integer,text)'::regprocedure,
    'public.rss_projection_operator_recover_tenant(uuid,text,text,bigint)'::regprocedure
)
ORDER BY procedure.proname
"#;

type FunctionDefinitionRow = (String, String, String, String, String, bool, bool);

fn function_definition_fingerprint(definitions: &[FunctionDefinitionRow]) -> String {
    use sha2::{Digest as _, Sha256};

    let mut digest = Sha256::new();
    for (name, language, body, volatility, parallel, leakproof, strict) in definitions {
        for field in [
            name.as_bytes(),
            language.as_bytes(),
            body.as_bytes(),
            volatility.as_bytes(),
            parallel.as_bytes(),
            if *leakproof { b"true" } else { b"false" },
            if *strict { b"true" } else { b"false" },
        ] {
            digest.update(field);
            digest.update([0]);
        }
    }
    format!("sha256:{:x}", digest.finalize())
}

async fn load_function_definition_fingerprint(
    pool: &sqlx::PgPool,
    query: &str,
) -> Result<String, sqlx::Error> {
    let definitions: Vec<FunctionDefinitionRow> = sqlx::query_as(query).fetch_all(pool).await?;
    Ok(function_definition_fingerprint(&definitions))
}

async fn current_role_owns_database_objects(pool: &sqlx::PgPool) -> Result<bool, sqlx::Error> {
    let count: i64 = sqlx::query_scalar(TENANT_READ_OWNERSHIP_SQL)
        .fetch_one(pool)
        .await?;
    Ok(count != 0)
}

const AUDIT_ADMIN_PRIVILEGES_SQL: &str = r#"
WITH effective AS (
    SELECT c.relname AS relation_name, p.privilege
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    CROSS JOIN (VALUES ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE')) AS p(privilege)
    WHERE n.nspname = 'public'
      AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
      AND has_table_privilege(current_user, format('%I.%I', n.nspname, c.relname), p.privilege)
)
SELECT COALESCE(bool_or(relation_name = 'audit_entries' AND privilege = 'SELECT'), false)
           AS has_audit_entries_select,
       COALESCE(
           string_agg(
               relation_name || ':' || privilege,
               ',' ORDER BY relation_name, privilege
           ) FILTER (WHERE NOT (relation_name = 'audit_entries' AND privilege = 'SELECT')),
           ''
       ) AS extra_privileges
FROM effective
"#;

const TENANT_READ_ROLE_SQL: &str = r#"
SELECT session_user,
       current_user,
       r.rolcanlogin AS can_login,
       r.rolsuper AS superuser,
       r.rolbypassrls AS bypass_rls,
       r.rolcreatedb AS create_db,
       r.rolcreaterole AS create_role,
       r.rolreplication AS replication,
       r.rolinherit AS inherit,
       COALESCE(cardinality(r.rolconfig), 0) = 2
           AND r.rolconfig @> ARRAY['default_transaction_read_only=on']::text[]
           AND EXISTS (
               SELECT 1 FROM unnest(r.rolconfig) AS setting
               WHERE setting LIKE 'search_path=%'
           ) AS exact_role_config,
       COALESCE(
           r.rolconfig @> ARRAY['search_path=pg_catalog, public']::text[],
           false
       )
           AS exact_search_path_config,
       current_setting('search_path') AS current_search_path,
       current_setting('transaction_read_only') = 'on' AS transaction_read_only,
       current_setting('lo_compat_privileges') = 'off' AS lo_compat_privileges_off
FROM pg_roles AS r
WHERE r.rolname = current_user
"#;

const TENANT_READ_MEMBERSHIP_SQL: &str = r#"
SELECT count(*)::bigint
FROM pg_auth_members AS membership
JOIN pg_roles AS reader
  ON reader.oid = membership.roleid OR reader.oid = membership.member
WHERE reader.rolname = current_user
"#;

const TENANT_READ_OWNERSHIP_SQL: &str = r#"
SELECT count(*)::bigint
FROM pg_shdepend AS dependency
JOIN pg_roles AS reader ON reader.oid = dependency.refobjid
WHERE reader.rolname = current_user
  AND dependency.refclassid = 'pg_authid'::regclass
  AND dependency.deptype = 'o'
"#;

const TENANT_READ_RELATION_PRIVILEGES_SQL: &str = r#"
WITH reader AS (
    SELECT oid FROM pg_roles WHERE rolname = current_user
), relations AS (
    SELECT c.oid,
           n.nspname AS schema_name,
           c.relname,
           n.nspname = 'public'
               AND c.relname = 'settings_projection_active_pointer' AS denied_relation,
           n.nspname = 'public'
               AND c.relkind IN ('r', 'p')
               AND c.relname <> 'settings_projection_active_pointer'
               AND EXISTS (
                   SELECT 1
                   FROM pg_attribute AS a
                   WHERE a.attrelid = c.oid
                     AND a.attname = 'tenant_id'
                     AND NOT a.attisdropped
               ) AS tenant_relation
    FROM pg_class AS c
    JOIN pg_namespace AS n ON n.oid = c.relnamespace
    WHERE n.nspname <> 'information_schema'
      AND n.nspname !~ '^pg_'
      AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
), effective AS (
    SELECT relation.schema_name,
           relation.relname,
           relation.denied_relation,
           relation.tenant_relation,
           privilege.name AS privilege
    FROM relations AS relation
    CROSS JOIN (
        VALUES ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE'), ('TRUNCATE'),
               ('REFERENCES'), ('TRIGGER')
    ) AS privilege(name)
    WHERE has_table_privilege(current_user, relation.oid, privilege.name)
), explicit_column_acl AS (
    SELECT relation.schema_name || '.' || relation.relname || '.' || attribute.attname
               || ':COLUMN_' || upper(acl.privilege_type)
               || CASE WHEN acl.is_grantable THEN '_WITH_GRANT_OPTION' ELSE '' END AS privilege
    FROM relations AS relation
    JOIN pg_attribute AS attribute
      ON attribute.attrelid = relation.oid
     AND attribute.attnum > 0
     AND NOT attribute.attisdropped
    CROSS JOIN LATERAL aclexplode(attribute.attacl) AS acl
    CROSS JOIN reader
    WHERE acl.grantee IN (0::oid, reader.oid)
), relation_grant_options AS (
    SELECT relation.schema_name || '.' || relation.relname || ':'
               || upper(acl.privilege_type) || '_WITH_GRANT_OPTION' AS privilege
    FROM relations AS relation
    JOIN pg_class AS relation_acl ON relation_acl.oid = relation.oid
    CROSS JOIN LATERAL aclexplode(relation_acl.relacl) AS acl
    CROSS JOIN reader
    WHERE acl.grantee IN (0::oid, reader.oid)
      AND acl.is_grantable
), extras AS (
    SELECT effective.schema_name || '.' || effective.relname || ':'
               || effective.privilege AS privilege
    FROM effective
    WHERE effective.denied_relation
       OR NOT (
        effective.privilege = 'SELECT'
        AND (
            effective.tenant_relation
            OR (effective.schema_name = 'public' AND effective.relname = '_sqlx_migrations')
        )
    )
    UNION
    SELECT privilege FROM explicit_column_acl
    UNION
    SELECT privilege FROM relation_grant_options
)
SELECT COALESCE(
           (
               SELECT string_agg(
                   relation.schema_name || '.' || relation.relname,
                   ',' ORDER BY relation.schema_name, relation.relname
               )
               FROM relations AS relation
               WHERE relation.tenant_relation
                 AND NOT has_table_privilege(current_user, relation.oid, 'SELECT')
           ),
           ''
       ) AS missing_select,
       COALESCE(
           (
               SELECT string_agg(extras.privilege, ',' ORDER BY extras.privilege)
               FROM extras
           ),
           ''
       ) AS extra_privileges
"#;

const TENANT_READ_DATABASE_PRIVILEGES_SQL: &str = r#"
SELECT has_database_privilege(current_user, current_database(), 'CONNECT'),
       has_database_privilege(current_user, current_database(), 'CREATE'),
       has_database_privilege(current_user, current_database(), 'TEMPORARY'),
       EXISTS (
           SELECT 1
           FROM pg_database AS database
           JOIN pg_roles AS reader ON reader.rolname = current_user
           CROSS JOIN LATERAL aclexplode(
               COALESCE(database.datacl, acldefault('d', database.datdba))
           ) AS acl
           WHERE database.datname = current_database()
             AND acl.grantee IN (0::oid, reader.oid)
             AND acl.privilege_type = 'CONNECT'
             AND acl.is_grantable
       )
"#;

const TENANT_READ_SEQUENCE_PRIVILEGES_SQL: &str = r#"
SELECT COALESCE(
           string_agg(
               c.relname || ':' || privilege.name,
               ',' ORDER BY c.relname, privilege.name
           ),
           ''
       )
FROM pg_class AS c
JOIN pg_namespace AS n ON n.oid = c.relnamespace
CROSS JOIN (VALUES ('USAGE'), ('SELECT'), ('UPDATE')) AS privilege(name)
WHERE n.nspname <> 'information_schema'
  AND n.nspname !~ '^pg_'
  AND c.relkind = 'S'
  AND has_sequence_privilege(current_user, c.oid, privilege.name)
"#;

const TENANT_READ_SCHEMA_PRIVILEGES_SQL: &str = r#"
WITH reader AS (
    SELECT oid FROM pg_roles WHERE rolname = current_user
), effective AS (
    SELECT n.nspname,
           privilege.name AS privilege
    FROM pg_namespace AS n
    CROSS JOIN (VALUES ('USAGE'), ('CREATE')) AS privilege(name)
    WHERE n.nspname <> 'information_schema'
      AND n.nspname !~ '^pg_'
      AND has_schema_privilege(current_user, n.oid, privilege.name)
), grant_options AS (
    SELECT n.nspname,
           upper(acl.privilege_type) || '_WITH_GRANT_OPTION' AS privilege
    FROM pg_namespace AS n
    CROSS JOIN LATERAL aclexplode(
        COALESCE(n.nspacl, acldefault('n', n.nspowner))
    ) AS acl
    CROSS JOIN reader
    WHERE n.nspname <> 'information_schema'
      AND n.nspname !~ '^pg_'
      AND acl.grantee IN (0::oid, reader.oid)
      AND acl.is_grantable
), extras AS (
    SELECT nspname, privilege
    FROM effective
    WHERE NOT (nspname = 'public' AND privilege = 'USAGE')
    UNION
    SELECT nspname, privilege FROM grant_options
)
SELECT COALESCE(
           (SELECT bool_or(nspname = 'public' AND privilege = 'USAGE') FROM effective),
           false
       ),
       COALESCE(
           (
               SELECT string_agg(
                   nspname || ':' || privilege,
                   ',' ORDER BY nspname, privilege
               )
               FROM extras
           ),
           ''
       )
"#;

const TENANT_READ_FUNCTION_PRIVILEGES_SQL: &str = r#"
WITH resolver AS (
    SELECT pg_catalog.to_regprocedure(
               'public.rss_settings_projection_resolve_active()'
           ) AS oid
), effective AS (
    SELECT procedure.oid
    FROM pg_catalog.pg_proc AS procedure
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = procedure.pronamespace
    WHERE namespace.nspname <> 'information_schema'
      AND namespace.nspname !~ '^pg_'
      AND pg_catalog.has_function_privilege(current_user, procedure.oid, 'EXECUTE')
)
SELECT resolver.oid IS NOT NULL
       AND COALESCE(
               (SELECT pg_catalog.array_agg(effective.oid ORDER BY effective.oid)
                FROM effective),
               ARRAY[]::oid[]
           ) = ARRAY[resolver.oid]::oid[] AS exact,
       COALESCE(
           (SELECT pg_catalog.string_agg(
                       effective.oid::regprocedure::text,
                       ',' ORDER BY effective.oid
                   )
            FROM effective),
           ''
       ) AS effective_functions
FROM resolver
"#;

const TENANT_READ_RESOLVER_FUNCTION_DEFINITION_SQL: &str = r#"
SELECT procedure.proname,
       language.lanname,
       procedure.prosrc,
       procedure.provolatile::text,
       procedure.proparallel::text,
       procedure.proleakproof,
       procedure.proisstrict
FROM pg_catalog.pg_proc AS procedure
JOIN pg_catalog.pg_language AS language ON language.oid = procedure.prolang
WHERE procedure.oid =
    'public.rss_settings_projection_resolve_active()'::regprocedure
ORDER BY procedure.proname
"#;

const TENANT_READ_RESOLVER_SECURITY_SQL: &str = r#"
WITH resolver AS (
    SELECT procedure.*, owner.rolname AS owner_name,
           owner.rolcanlogin AS owner_can_login,
           owner.rolsuper AS owner_super,
           owner.rolbypassrls AS owner_bypass_rls,
           owner.rolcreatedb AS owner_create_db,
           owner.rolcreaterole AS owner_create_role,
           owner.rolreplication AS owner_replication,
           owner.rolinherit AS owner_inherit
    FROM pg_catalog.pg_proc AS procedure
    JOIN pg_catalog.pg_roles AS owner ON owner.oid = procedure.proowner
    WHERE procedure.oid =
        'public.rss_settings_projection_resolve_active()'::regprocedure
), acl AS (
    SELECT COALESCE(grantee.rolname, 'PUBLIC') AS grantee,
           privilege.privilege_type,
           privilege.is_grantable
    FROM resolver
    CROSS JOIN LATERAL pg_catalog.aclexplode(
        COALESCE(resolver.proacl, pg_catalog.acldefault('f', resolver.proowner))
    ) AS privilege
    LEFT JOIN pg_catalog.pg_roles AS grantee ON grantee.oid = privilege.grantee
)
SELECT resolver.prokind = 'f'
       AND resolver.prosecdef
       AND resolver.provolatile = 's'
       AND resolver.proparallel = 'u'
       AND NOT resolver.proleakproof
       AND NOT resolver.proisstrict
       AND resolver.proconfig = ARRAY['search_path=pg_catalog, pg_temp']::text[]
       AND resolver.owner_name = 'rss_projection_serving_owner'
       AND NOT resolver.owner_can_login
       AND NOT resolver.owner_super
       AND NOT resolver.owner_bypass_rls
       AND NOT resolver.owner_create_db
       AND NOT resolver.owner_create_role
       AND NOT resolver.owner_replication
       AND NOT resolver.owner_inherit
       AND NOT EXISTS (
           SELECT 1
           FROM pg_catalog.pg_auth_members AS membership
           WHERE membership.member = resolver.proowner
              OR membership.roleid = resolver.proowner
       )
       AND COALESCE(
               (SELECT pg_catalog.array_agg(
                           acl.grantee || ':' || acl.privilege_type || ':' ||
                           acl.is_grantable::text
                           ORDER BY acl.grantee, acl.privilege_type, acl.is_grantable
                       )
                FROM acl),
               ARRAY[]::text[]
           ) = ARRAY[
               'rss_app_read:EXECUTE:false',
               'rss_projection_serving_owner:EXECUTE:false',
               'rss_projection_worker:EXECUTE:false'
           ]::text[]
       AS exact,
       pg_catalog.concat_ws(
           ';',
           'kind=' || resolver.prokind::text,
           'security_definer=' || resolver.prosecdef::text,
           'volatility=' || resolver.provolatile::text,
           'parallel=' || resolver.proparallel::text,
           'leakproof=' || resolver.proleakproof::text,
           'strict=' || resolver.proisstrict::text,
           'config=' || COALESCE(pg_catalog.array_to_string(resolver.proconfig, ','), ''),
           'owner=' || resolver.owner_name,
           'owner_login=' || resolver.owner_can_login::text,
           'owner_super=' || resolver.owner_super::text,
           'owner_bypass_rls=' || resolver.owner_bypass_rls::text,
           'owner_create_db=' || resolver.owner_create_db::text,
           'owner_create_role=' || resolver.owner_create_role::text,
           'owner_replication=' || resolver.owner_replication::text,
           'owner_inherit=' || resolver.owner_inherit::text,
           'memberships=' || (
               SELECT pg_catalog.count(*)::text
               FROM pg_catalog.pg_auth_members AS membership
               WHERE membership.member = resolver.proowner
                  OR membership.roleid = resolver.proowner
           ),
           'acl=' || COALESCE(
               (SELECT pg_catalog.string_agg(
                           acl.grantee || ':' || acl.privilege_type || ':' ||
                           acl.is_grantable::text,
                           ',' ORDER BY acl.grantee, acl.privilege_type, acl.is_grantable
                       )
                FROM acl),
               ''
           )
       ) AS details
FROM resolver
"#;

/// Fixed PostgreSQL 16 large-object mutator universe. These pg_catalog functions are outside the
/// application-function ACL scan; most are PUBLIC EXECUTE by default and can persist state after a
/// caller explicitly starts READ WRITE. Missing signatures also fail closed instead of silently
/// weakening the gate on an unsupported catalog shape.
const TENANT_READ_LARGE_OBJECT_MUTATOR_PRIVILEGES_SQL: &str = r#"
WITH expected(signature) AS (
    VALUES
        ('pg_catalog.lo_creat(integer)'),
        ('pg_catalog.lo_create(oid)'),
        ('pg_catalog.lo_from_bytea(oid,bytea)'),
        ('pg_catalog.lo_put(oid,bigint,bytea)'),
        ('pg_catalog.lo_truncate(integer,integer)'),
        ('pg_catalog.lo_truncate64(integer,bigint)'),
        ('pg_catalog.lo_unlink(oid)'),
        ('pg_catalog.lowrite(integer,bytea)'),
        ('pg_catalog.lo_import(text)'),
        ('pg_catalog.lo_import(text,oid)')
), resolved AS (
    SELECT expected.signature,
           to_regprocedure(expected.signature) AS function_oid
    FROM expected
)
SELECT COALESCE(
           string_agg(
               resolved.signature
                   || CASE WHEN resolved.function_oid IS NULL THEN ':MISSING' ELSE ':EXECUTE' END,
               ',' ORDER BY resolved.signature
           ),
           ''
       )
FROM resolved
WHERE resolved.function_oid IS NULL
   OR has_function_privilege(current_user, resolved.function_oid, 'EXECUTE')
"#;

const TENANT_READ_LARGE_OBJECT_PRIVILEGES_SQL: &str = r#"
WITH reader AS (
    SELECT oid FROM pg_roles WHERE rolname = current_user
)
SELECT COALESCE(
           string_agg(
               object.oid::text || ':' || upper(acl.privilege_type)
                   || CASE WHEN acl.is_grantable THEN '_WITH_GRANT_OPTION' ELSE '' END,
               ',' ORDER BY object.oid, acl.privilege_type, acl.is_grantable
           ),
           ''
       )
FROM pg_largeobject_metadata AS object
CROSS JOIN LATERAL aclexplode(
    COALESCE(object.lomacl, acldefault('L', object.lomowner))
) AS acl
CROSS JOIN reader
WHERE acl.grantee IN (0::oid, reader.oid)
"#;

const TENANT_READ_PARAMETER_PRIVILEGES_SQL: &str = r#"
WITH reader AS (
    SELECT oid FROM pg_roles WHERE rolname = current_user
)
SELECT COALESCE(
           string_agg(
               parameter.parname || ':' || upper(acl.privilege_type)
                   || CASE WHEN acl.is_grantable THEN '_WITH_GRANT_OPTION' ELSE '' END,
               ',' ORDER BY parameter.parname, acl.privilege_type, acl.is_grantable
           ),
           ''
       )
FROM pg_parameter_acl AS parameter
CROSS JOIN LATERAL aclexplode(parameter.paracl) AS acl
CROSS JOIN reader
WHERE acl.grantee IN (0::oid, reader.oid)
"#;

#[derive(sqlx::FromRow)]
struct TenantReadRole {
    session_user: String,
    current_user: String,
    can_login: bool,
    superuser: bool,
    bypass_rls: bool,
    create_db: bool,
    create_role: bool,
    replication: bool,
    inherit: bool,
    exact_role_config: bool,
    exact_search_path_config: bool,
    current_search_path: String,
    transaction_read_only: bool,
    lo_compat_privileges_off: bool,
}

struct ServingRole {
    session_user: String,
    current_user: String,
    superuser: bool,
    bypass_rls: bool,
}

struct WriterRole {
    session_user: String,
    current_user: String,
    can_login: bool,
    superuser: bool,
    bypass_rls: bool,
    create_db: bool,
    create_role: bool,
    replication: bool,
    inherit: bool,
}

/// 含 `tenant_id` 列的 public 表总数（anti-vacuity：durable 库应至少有迁移建出的 tenant 表）。
/// 用 `pg_catalog`（非 `information_schema`——后者按当前角色权限过滤，非 superuser serving 角色会漏看
/// 未授权的 tenant 表导致门控盲区；pg_class/pg_attribute 不受权限过滤，确保门看到全部 tenant 表）。
const TENANT_TABLE_COUNT_SQL: &str = "\
SELECT count(*) FROM pg_class c \
JOIN pg_namespace n ON n.oid = c.relnamespace \
WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') \
  AND EXISTS (SELECT 1 FROM pg_attribute a \
              WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped)";

impl PgStore {
    /// durable 启动 RLS 能力门（schema 门控，**fail-fast**：缺能力即拒绝启动）。
    ///
    /// `TENANCY-PG-CATALOG-PROOF-01`：catalog / ACL fingerprint 证明（与行为证明
    /// `TENANCY-PG-BEHAVIOR-PROOF-01`、合入前 `schema-rls` meta 互补）。校验面（任一不过 → `Err`，
    /// 组合根冒泡使进程不进入服务态）：
    /// 0. **登录会话直连 `rss_app` 且不绕过 RLS**——`session_user = current_user = rss_app`，并且非
    ///    superuser / 非 `BYPASSRLS`；并核验有效 ACL + custom default ACL fingerprint（含
    ///    TABLE/SEQUENCE/FUNCTION/TYPE/SCHEMA，`defaclobjtype` ∈ {r,S,f,T,n}）。
    /// 1. `rss.tenant_id` GUC roundtrip——经统一 funnel [`set_local_tenant`] 注入探测租户后
    ///    `current_setting` 回显比对（验证 GUC 基础设施可用，dogfood funnel）。
    /// 2. anti-vacuity——至少存在一张含 `tenant_id` 列的 tenant 表（否则 schema 未迁移）。
    /// 3. 逐 tenant 表断言 FORCE RLS + 规范 tenant policy + 无 allow-all permissive widening（动态派生，不硬编码）。
    ///
    /// 对标 omicron `DataStore::check_schema_and_access`（对象返回前于构造器级别校验 schema/access；
    /// `ref: oxidecomputer/omicron nexus/db-queries/src/db/datastore/mod.rs@14d89dca`）。偏离：RSS 迁移在
    /// 独立 `run_migrations` 步、不并入本校验的 retry 环。仅供 [`crate::PgRuntimeDeps::setup`] 调用。
    pub(crate) async fn verify_rls_capability(&self) -> Result<(), PgError> {
        // 直线编排：各段校验为低复杂度 helper（任一 Err 经 `?` 冒泡，tx drop 即 rollback 自检事务）。
        let mut tx = self.pool.begin().await.map_err(PgError::RlsCapability)?;
        ensure_serving_role(&mut tx).await?; // 0. 连接角色必须为 rss_app 且不绕过 RLS（最先 fail-fast）
        verify_tenant_guc_roundtrip(&mut tx, PgError::RlsCapability).await?; // 1. GUC roundtrip
        ensure_tenant_tables_present(&mut tx, PgError::RlsCapability).await?; // 2. anti-vacuity
        let offenders = offending_tenant_tables(&mut tx, PgError::RlsCapability).await?; // 3. 逐表 FORCE RLS + 规范 policy + 无 widening
        // 只读 + SET LOCAL 自检事务无副作用，显式 rollback 释放（失败不覆盖判定，仅 best-effort）。
        let _ = tx.rollback().await;
        ensure_no_offenders(offenders)
    }

    /// Dedicated tenant-reader capability gate.
    ///
    /// The gate verifies the direct role and immutable role attributes first, then proves the
    /// external PostgreSQL capability surface is exact: no memberships/ownership, only tenant
    /// relation SELECT, no sequence/function/schema-create privileges, default read-only enabled,
    /// and the same tenant GUC/FORCE-RLS policy closure used by the writer lane.
    pub(crate) async fn verify_tenant_read_capability(&self) -> Result<(), PgError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(PgError::TenantReadCapability)?;
        let role = load_tenant_read_role(&mut tx).await?;
        ensure_tenant_read_direct_role(&role)?;
        ensure_tenant_read_role_attributes(&role)?;
        ensure_tenant_read_default_transaction(&role)?;
        ensure_tenant_read_search_path(&role)?;
        ensure_tenant_read_large_object_compatibility(&role)?;
        ensure_tenant_read_exact_external_capabilities(&mut tx).await?;
        verify_tenant_guc_roundtrip(&mut tx, PgError::TenantReadCapability).await?;
        ensure_tenant_tables_present(&mut tx, PgError::TenantReadCapability).await?;
        let offenders = offending_tenant_tables(&mut tx, PgError::TenantReadCapability).await?;
        let _ = tx.rollback().await;
        ensure_no_offenders(offenders)
    }

    /// Exact capability gate for the dedicated scoped Projection source reader.
    pub(crate) async fn verify_projection_source_read_capability(&self) -> Result<(), PgError> {
        let exact: (bool,) = sqlx::query_as(
            r#"
            SELECT session_user = 'rss_projection_reader'
               AND current_user = 'rss_projection_reader'
               AND role.rolcanlogin
               AND NOT role.rolsuper
               AND NOT role.rolbypassrls
               AND NOT role.rolcreatedb
               AND NOT role.rolcreaterole
               AND NOT role.rolreplication
               AND NOT role.rolinherit
               AND COALESCE(cardinality(role.rolconfig), 0) = 1
               AND role.rolconfig @> ARRAY['search_path=pg_catalog, public']::text[]
               AND has_function_privilege(
                    current_user,
                    'public.rss_read_projection_events_scoped(uuid,uuid,uuid,text,text,text,text,bigint,integer)',
                    'EXECUTE'
               )
               AND has_function_privilege(
                    current_user,
                    'public.rss_projection_source_high_water_scoped(uuid,uuid,uuid,text,text,text,text)',
                    'EXECUTE'
               )
               AND NOT has_function_privilege(
                    current_user,
                    'public.rss_assert_projection_source_scope(boolean,uuid,uuid,uuid,text,text,text,text)',
                    'EXECUTE'
               )
               AND NOT has_function_privilege(
                    current_user,
                    'public.rss_projection_operator_issue_source_capability(uuid,text,text,text,text)',
                    'EXECUTE'
               )
               AND (
                    SELECT count(*) = 3
                       AND pg_catalog.bool_and(
                           procedure.prosecdef
                           AND procedure.proconfig = CASE procedure.proname
                               WHEN 'rss_projection_source_high_water_scoped' THEN ARRAY[
                                   'search_path=pg_catalog, pg_temp',
                                   'plan_cache_mode=force_custom_plan'
                               ]::text[]
                               ELSE ARRAY['search_path=pg_catalog, pg_temp']::text[]
                           END
                           AND function_owner.rolname = 'rss_projection_source_reader_owner'
                           AND NOT function_owner.rolcanlogin
                           AND NOT function_owner.rolsuper
                           AND NOT function_owner.rolbypassrls
                           AND NOT function_owner.rolcreatedb
                           AND NOT function_owner.rolcreaterole
                           AND NOT function_owner.rolreplication
                           AND NOT function_owner.rolinherit
                           AND NOT EXISTS (
                               SELECT 1
                               FROM pg_catalog.pg_auth_members AS membership
                               WHERE membership.member = function_owner.oid
                                  OR membership.roleid = function_owner.oid
                           )
                           AND (
                               SELECT count(*) = 2
                                  AND count(*) FILTER (
                                      WHERE acl.grantor = procedure.proowner
                                        AND acl.grantee = procedure.proowner
                                        AND acl.privilege_type = 'EXECUTE'
                                        AND NOT acl.is_grantable
                                  ) = 1
                                  AND count(*) FILTER (
                                      WHERE acl.grantor = procedure.proowner AND (
                                          (procedure.proname = 'rss_assert_projection_source_scope'
                                           AND acl.grantee = operator_owner.oid)
                                          OR
                                          (procedure.proname <> 'rss_assert_projection_source_scope'
                                           AND acl.grantee = reader_role.oid)
                                      )
                                        AND acl.privilege_type = 'EXECUTE'
                                        AND NOT acl.is_grantable
                                  ) = 1
                               FROM pg_catalog.aclexplode(
                                   COALESCE(
                                       procedure.proacl,
                                       pg_catalog.acldefault('f', procedure.proowner)
                                   )
                               ) AS acl
                           )
                       )
                    FROM pg_catalog.pg_proc AS procedure
                    JOIN pg_catalog.pg_roles AS function_owner
                      ON function_owner.oid = procedure.proowner
                    CROSS JOIN pg_catalog.pg_roles AS reader_role
                    CROSS JOIN pg_catalog.pg_roles AS operator_owner
                    WHERE procedure.oid IN (
                        'public.rss_assert_projection_source_scope(boolean,uuid,uuid,uuid,text,text,text,text)'::regprocedure,
                        'public.rss_read_projection_events_scoped(uuid,uuid,uuid,text,text,text,text,bigint,integer)'::regprocedure,
                        'public.rss_projection_source_high_water_scoped(uuid,uuid,uuid,text,text,text,text)'::regprocedure
                      )
                      AND reader_role.rolname = 'rss_projection_reader'
                      AND operator_owner.rolname = 'rss_projection_operator_owner'
               )
               AND (
                    SELECT capability_table.relkind = 'r'
                       AND table_owner.rolname = 'rss_projection_source_reader_owner'
                       AND (
                           SELECT pg_catalog.array_agg(
                                      attribute.attname || ':'
                                      || pg_catalog.format_type(
                                          attribute.atttypid, attribute.atttypmod
                                      ) || ':' || attribute.attnotnull::text
                                      ORDER BY attribute.attnum
                                  ) = ARRAY[
                                      'capability_digest:bytea:true',
                                      'scope_tenant_id:uuid:true',
                                      'projection_id:text:true',
                                      'projection_definition_version:text:true',
                                      'projection_definition_schema_digest:text:true',
                                      'input_generation:text:true',
                                      'expires_at:timestamp with time zone:true'
                                  ]::text[]
                           FROM pg_catalog.pg_attribute AS attribute
                           WHERE attribute.attrelid = capability_table.oid
                             AND attribute.attnum > 0
                             AND NOT attribute.attisdropped
                       )
                       AND (
                           SELECT count(*) = 6
                              AND pg_catalog.bool_and(constraint_row.convalidated)
                              AND count(*) FILTER (
                                  WHERE constraint_row.contype = 'p'
                              ) = 1
                              AND count(*) FILTER (
                                  WHERE constraint_row.contype = 'c'
                              ) = 5
                           FROM pg_catalog.pg_constraint AS constraint_row
                           WHERE constraint_row.conrelid = capability_table.oid
                       )
                       AND count(*) = 10
                       AND count(*) FILTER (
                           WHERE acl.grantee = capability_table.relowner
                             AND acl.privilege_type IN (
                                 'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE',
                                 'REFERENCES', 'TRIGGER'
                             )
                             AND NOT acl.is_grantable
                       ) = 7
                       AND count(*) FILTER (
                           WHERE acl.grantee = operator_owner.oid
                             AND acl.privilege_type IN ('SELECT', 'INSERT', 'DELETE')
                             AND NOT acl.is_grantable
                       ) = 3
                    FROM pg_catalog.pg_class AS capability_table
                    JOIN pg_catalog.pg_namespace AS capability_namespace
                      ON capability_namespace.oid = capability_table.relnamespace
                    JOIN pg_catalog.pg_roles AS table_owner
                      ON table_owner.oid = capability_table.relowner
                    CROSS JOIN pg_catalog.pg_roles AS operator_owner
                    CROSS JOIN LATERAL pg_catalog.aclexplode(
                        COALESCE(
                            capability_table.relacl,
                            pg_catalog.acldefault('r', capability_table.relowner)
                        )
                    ) AS acl
                    WHERE capability_namespace.nspname = 'public'
                      AND capability_table.relname = 'projection_source_capabilities'
                      AND operator_owner.rolname = 'rss_projection_operator_owner'
                    GROUP BY capability_table.oid, capability_table.relkind, table_owner.rolname
               )
               AND (
                    SELECT count(*) = 1
                       AND pg_catalog.bool_and(
                           index_row.indrelid =
                               'public.projection_source_capabilities'::pg_catalog.regclass
                           AND index_row.indisvalid
                           AND index_row.indisready
                           AND pg_catalog.pg_get_indexdef(index_row.indexrelid) =
                               'CREATE INDEX idx_projection_source_capabilities_expiry ON public.projection_source_capabilities USING btree (expires_at, capability_digest)'
                       )
                    FROM pg_catalog.pg_index AS index_row
                    JOIN pg_catalog.pg_class AS index_relation
                      ON index_relation.oid = index_row.indexrelid
                    JOIN pg_catalog.pg_namespace AS index_namespace
                      ON index_namespace.oid = index_relation.relnamespace
                    WHERE index_namespace.nspname = 'public'
                      AND index_relation.relname =
                          'idx_projection_source_capabilities_expiry'
               )
               AND (
                    SELECT count(*) = 1
                       AND pg_catalog.bool_and(
                           index_row.indrelid = 'public.projection_events'::pg_catalog.regclass
                           AND index_row.indisvalid
                           AND index_row.indisready
                           AND pg_catalog.pg_get_indexdef(index_row.indexrelid) =
                               'CREATE INDEX idx_projection_events_scoped_tail ON public.projection_events USING btree (domain, contract_id, contract_version, schema_hash, event_type, ((metadata ->> ''tenantId''::text)), id DESC)'
                       )
                    FROM pg_catalog.pg_index AS index_row
                    JOIN pg_catalog.pg_class AS index_relation
                      ON index_relation.oid = index_row.indexrelid
                    JOIN pg_catalog.pg_namespace AS index_namespace
                      ON index_namespace.oid = index_relation.relnamespace
                    WHERE index_namespace.nspname = 'public'
                      AND index_relation.relname = 'idx_projection_events_scoped_tail'
               )
               AND has_table_privilege(current_user, 'public._sqlx_migrations', 'SELECT')
               AND NOT EXISTS (
                    SELECT 1
                    FROM information_schema.role_table_grants AS grant_row
                    WHERE grant_row.grantee = current_user
                      AND grant_row.table_schema = 'public'
                      AND NOT (
                          grant_row.table_name = '_sqlx_migrations'
                          AND grant_row.privilege_type = 'SELECT'
                      )
               )
               AND NOT EXISTS (
                    SELECT 1
                    FROM information_schema.role_routine_grants AS grant_row
                    WHERE grant_row.grantee = current_user
                      AND grant_row.specific_schema = 'public'
                      AND grant_row.routine_name NOT IN (
                          'rss_read_projection_events_scoped',
                          'rss_projection_source_high_water_scoped'
                      )
               )
               AND NOT EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_auth_members AS membership
                    WHERE membership.member = role.oid OR membership.roleid = role.oid
               )
            FROM pg_catalog.pg_roles AS role
            WHERE role.rolname = current_user
            "#,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(PgError::ProjectionSourceReadCapability)?;
        ensure_projection_source_role_and_grants(exact.0)?;
        let owns_database_objects = current_role_owns_database_objects(&self.pool)
            .await
            .map_err(PgError::ProjectionSourceReadCapability)?;
        ensure_projection_source_no_ownership(owns_database_objects)?;
        let has_external_persistence = has_projection_external_persistence_capabilities(&self.pool)
            .await
            .map_err(PgError::ProjectionSourceReadCapability)?;
        ensure_projection_source_no_external_persistence(has_external_persistence)?;
        let function_fingerprint = load_function_definition_fingerprint(
            &self.pool,
            PROJECTION_SOURCE_FUNCTION_DEFINITIONS_SQL,
        )
        .await
        .map_err(PgError::ProjectionSourceReadCapability)?;
        ensure_projection_source_function_definition(function_fingerprint)?;
        let actual_fingerprint = load_effective_capability_fingerprint(&self.pool)
            .await
            .map_err(PgError::ProjectionSourceReadCapability)?;
        ensure_projection_source_capability_fingerprint(actual_fingerprint)
    }

    /// Exact capability gate for the independent Projection control-plane role.
    pub(crate) async fn verify_projection_operator_capability(&self) -> Result<(), PgError> {
        let exact: (bool,) = sqlx::query_as(
            r#"
            WITH role_grants AS (
                SELECT grant_row.table_name, grant_row.privilege_type
                FROM information_schema.role_table_grants AS grant_row
                WHERE grant_row.grantee = current_user
                  AND grant_row.table_schema = 'public'
            )
            SELECT session_user = 'rss_projection_operator'
               AND current_user = 'rss_projection_operator'
               AND role.rolcanlogin
               AND NOT role.rolsuper
               AND NOT role.rolbypassrls
               AND NOT role.rolcreatedb
               AND NOT role.rolcreaterole
               AND NOT role.rolreplication
               AND NOT role.rolinherit
               AND COALESCE(cardinality(role.rolconfig), 0) = 1
               AND role.rolconfig @> ARRAY['search_path=pg_catalog, public']::text[]
               AND NOT has_table_privilege(current_user, 'public.projection_events', 'SELECT')
               AND NOT has_table_privilege(current_user, 'public.projection_input_bindings', 'SELECT')
               AND NOT EXISTS (SELECT 1 FROM role_grants)
               AND has_function_privilege(
                    current_user,
                    'public.rss_service_token_replay_check_and_record(bytea,timestamp with time zone)',
                    'EXECUTE'
               )
               AND has_function_privilege(current_user, 'public.rss_projection_operator_record_audit(bigint,integer,text,text,text,text,text,text,text)', 'EXECUTE')
               AND has_function_privilege(current_user, 'public.rss_projection_operator_get_checkpoint(uuid,text,text)', 'EXECUTE')
               AND has_function_privilege(current_user, 'public.rss_projection_operator_save_checkpoint(uuid,text,text,bigint,bigint)', 'EXECUTE')
               AND has_function_privilege(current_user, 'public.rss_projection_operator_status_active(uuid)', 'EXECUTE')
               AND has_function_privilege(current_user, 'public.rss_projection_operator_swap_active(uuid,text,text,bigint,text,text,text)', 'EXECUTE')
               AND has_function_privilege(current_user, 'public.rss_projection_operator_sweep_source_capabilities()', 'EXECUTE')
               AND has_function_privilege(current_user, 'public.rss_projection_operator_issue_source_capability(uuid,text,text,text,text)', 'EXECUTE')
               AND has_function_privilege(current_user, 'public.rss_settings_projection_apply_operator(uuid,text,text,text,text,text,text,bigint,text,text,bigint,bigint,bytea)', 'EXECUTE')
               AND has_function_privilege(current_user, 'public.rss_projection_operator_insert_dead_letter(uuid,text,text,text,text,text,text,jsonb,text,bigint,text,bytea,text,integer,text)', 'EXECUTE')
               AND has_function_privilege(current_user, 'public.rss_projection_operator_recover_tenant(uuid,text,text,bigint)', 'EXECUTE')
               AND (
                    SELECT count(*) = 11
                       AND pg_catalog.bool_and(
                           procedure.prosecdef
                           AND procedure.proconfig =
                               ARRAY['search_path=pg_catalog, pg_temp']::text[]
                           AND function_owner.rolname = CASE
                               WHEN procedure.proname =
                                   'rss_service_token_replay_check_and_record'
                               THEN 'rss_service_token_replay_owner'
                               ELSE 'rss_projection_operator_owner'
                           END
                           AND NOT function_owner.rolcanlogin
                           AND NOT function_owner.rolsuper
                           AND NOT function_owner.rolbypassrls
                           AND NOT function_owner.rolcreatedb
                           AND NOT function_owner.rolcreaterole
                           AND NOT function_owner.rolreplication
                           AND NOT function_owner.rolinherit
                           AND NOT EXISTS (
                               SELECT 1
                               FROM pg_catalog.pg_auth_members AS membership
                               WHERE membership.member = function_owner.oid
                                  OR membership.roleid = function_owner.oid
                           )
                           AND NOT EXISTS (
                               SELECT 1
                               FROM pg_catalog.aclexplode(
                                   COALESCE(
                                       procedure.proacl,
                                       pg_catalog.acldefault('f', procedure.proowner)
                                   )
                               ) AS acl
                               WHERE acl.grantee = 0
                                 AND acl.privilege_type = 'EXECUTE'
                           )
                       )
                    FROM pg_catalog.pg_proc AS procedure
                    JOIN pg_catalog.pg_roles AS function_owner
                      ON function_owner.oid = procedure.proowner
                    WHERE procedure.oid IN (
                        'public.rss_service_token_replay_check_and_record(bytea,timestamp with time zone)'::regprocedure,
                        'public.rss_projection_operator_record_audit(bigint,integer,text,text,text,text,text,text,text)'::regprocedure,
                        'public.rss_projection_operator_get_checkpoint(uuid,text,text)'::regprocedure,
                        'public.rss_projection_operator_save_checkpoint(uuid,text,text,bigint,bigint)'::regprocedure,
                        'public.rss_projection_operator_status_active(uuid)'::regprocedure,
                        'public.rss_projection_operator_swap_active(uuid,text,text,bigint,text,text,text)'::regprocedure,
                        'public.rss_projection_operator_sweep_source_capabilities()'::regprocedure,
                        'public.rss_projection_operator_issue_source_capability(uuid,text,text,text,text)'::regprocedure,
                        'public.rss_settings_projection_apply_operator(uuid,text,text,text,text,text,text,bigint,text,text,bigint,bigint,bytea)'::regprocedure,
                        'public.rss_projection_operator_insert_dead_letter(uuid,text,text,text,text,text,text,jsonb,text,bigint,text,bytea,text,integer,text)'::regprocedure,
                        'public.rss_projection_operator_recover_tenant(uuid,text,text,bigint)'::regprocedure
                    )
               )
               AND NOT EXISTS (
                    SELECT 1
                    FROM information_schema.role_routine_grants AS grant_row
                    WHERE grant_row.grantee = current_user
                      AND grant_row.specific_schema = 'public'
                      AND grant_row.routine_name NOT IN (
                          'rss_service_token_replay_check_and_record',
                          'rss_projection_operator_record_audit',
                          'rss_projection_operator_get_checkpoint',
                          'rss_projection_operator_save_checkpoint',
                          'rss_projection_operator_status_active',
                          'rss_projection_operator_swap_active',
                          'rss_projection_operator_sweep_source_capabilities',
                          'rss_projection_operator_issue_source_capability',
                          'rss_settings_projection_apply_operator',
                          'rss_projection_operator_insert_dead_letter',
                          'rss_projection_operator_recover_tenant'
                      )
               )
               AND NOT EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_auth_members AS membership
                    WHERE membership.member = role.oid OR membership.roleid = role.oid
               )
            FROM pg_catalog.pg_roles AS role
            WHERE role.rolname = current_user
            "#,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(PgError::ProjectionOperatorCapability)?;
        ensure_projection_operator_role_and_grants(exact.0)?;
        let owns_database_objects = current_role_owns_database_objects(&self.pool)
            .await
            .map_err(PgError::ProjectionOperatorCapability)?;
        ensure_projection_operator_no_ownership(owns_database_objects)?;
        let has_external_persistence = has_projection_external_persistence_capabilities(&self.pool)
            .await
            .map_err(PgError::ProjectionOperatorCapability)?;
        ensure_projection_operator_no_external_persistence(has_external_persistence)?;
        let function_fingerprint = load_function_definition_fingerprint(
            &self.pool,
            PROJECTION_OPERATOR_FUNCTION_DEFINITIONS_SQL,
        )
        .await
        .map_err(PgError::ProjectionOperatorCapability)?;
        ensure_projection_operator_function_definitions(function_fingerprint)?;
        let actual_fingerprint = load_effective_capability_fingerprint(&self.pool)
            .await
            .map_err(PgError::ProjectionOperatorCapability)?;
        ensure_projection_operator_capability_fingerprint(actual_fingerprint)
    }

    /// Exact capability gate for the independent function-only Saga operator role.
    pub(crate) async fn verify_saga_operator_capability(&self) -> Result<(), PgError> {
        let exact: (bool,) = sqlx::query_as(
            r#"
            WITH role_grants AS (
                SELECT grant_row.table_name, grant_row.privilege_type
                FROM information_schema.role_table_grants AS grant_row
                WHERE grant_row.grantee = current_user
                  AND grant_row.table_schema = 'public'
            ), expected_relations(table_name, privilege_type) AS (
                VALUES ('_sqlx_migrations', 'SELECT')
            )
            SELECT session_user = 'rss_saga_operator'
               AND current_user = 'rss_saga_operator'
               AND role.rolcanlogin
               AND NOT role.rolsuper
               AND NOT role.rolbypassrls
               AND NOT role.rolcreatedb
               AND NOT role.rolcreaterole
               AND NOT role.rolreplication
               AND NOT role.rolinherit
               AND COALESCE(cardinality(role.rolconfig), 0) = 1
               AND role.rolconfig @> ARRAY['search_path=pg_catalog, public']::text[]
               AND NOT EXISTS (
                    (SELECT * FROM role_grants EXCEPT SELECT * FROM expected_relations)
                    UNION ALL
                    (SELECT * FROM expected_relations EXCEPT SELECT * FROM role_grants)
               )
               AND has_function_privilege(
                    current_user,
                    'public.rss_service_token_replay_check_and_record(bytea,timestamp with time zone)',
                    'EXECUTE'
               )
               AND has_function_privilege(
                    current_user,
                    'public.rss_saga_operator_record_audit(bigint,integer,text,uuid,text,text,text,text,text)',
                    'EXECUTE'
               )
               AND has_function_privilege(
                    current_user,
                    'public.rss_saga_retry_compensation(uuid,text,text,bigint,text,integer,bytea,text,text,text,text)',
                    'EXECUTE'
               )
               AND has_function_privilege(
                    current_user,
                    'public.rss_saga_terminate(uuid,text,text,text,text,text,text)',
                    'EXECUTE'
               )
               AND (
                    SELECT count(*) = 4
                       AND pg_catalog.bool_and(
                           procedure.prosecdef
                           AND procedure.proconfig =
                               ARRAY['search_path=pg_catalog, pg_temp']::text[]
                           AND function_owner.rolname = CASE procedure.proname
                               WHEN 'rss_service_token_replay_check_and_record'
                               THEN 'rss_service_token_replay_owner'
                               WHEN 'rss_saga_operator_record_audit'
                               THEN 'rss_saga_operator_owner'
                               ELSE 'rss_saga_writer'
                           END
                           AND NOT function_owner.rolcanlogin
                           AND NOT function_owner.rolsuper
                           AND function_owner.rolbypassrls = (procedure.proname IN (
                               'rss_saga_retry_compensation', 'rss_saga_terminate'
                           ))
                           AND NOT function_owner.rolcreatedb
                           AND NOT function_owner.rolcreaterole
                           AND NOT function_owner.rolreplication
                           AND NOT function_owner.rolinherit
                           AND NOT EXISTS (
                               SELECT 1 FROM pg_catalog.pg_auth_members AS membership
                               WHERE membership.member = function_owner.oid
                                  OR membership.roleid = function_owner.oid
                           )
                           AND NOT EXISTS (
                               SELECT 1
                               FROM pg_catalog.aclexplode(
                                   COALESCE(
                                       procedure.proacl,
                                       pg_catalog.acldefault('f', procedure.proowner)
                                   )
                               ) AS acl
                               WHERE acl.grantee = 0 AND acl.privilege_type = 'EXECUTE'
                           )
                       )
                    FROM pg_catalog.pg_proc AS procedure
                    JOIN pg_catalog.pg_roles AS function_owner
                      ON function_owner.oid = procedure.proowner
                    WHERE procedure.oid IN (
                        'public.rss_service_token_replay_check_and_record(bytea,timestamp with time zone)'::regprocedure,
                        'public.rss_saga_operator_record_audit(bigint,integer,text,uuid,text,text,text,text,text)'::regprocedure,
                        'public.rss_saga_retry_compensation(uuid,text,text,bigint,text,integer,bytea,text,text,text,text)'::regprocedure,
                        'public.rss_saga_terminate(uuid,text,text,text,text,text,text)'::regprocedure
                    )
               )
               AND NOT EXISTS (
                    SELECT 1
                    FROM information_schema.role_routine_grants AS grant_row
                    WHERE grant_row.grantee = current_user
                      AND grant_row.specific_schema = 'public'
                      AND grant_row.routine_name NOT IN (
                          'rss_service_token_replay_check_and_record',
                          'rss_saga_operator_record_audit',
                          'rss_saga_retry_compensation',
                          'rss_saga_terminate'
                      )
               )
               AND NOT EXISTS (
                    SELECT 1 FROM pg_catalog.pg_auth_members AS membership
                    WHERE membership.member = role.oid OR membership.roleid = role.oid
               )
            FROM pg_catalog.pg_roles AS role
            WHERE role.rolname = current_user
            "#,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(PgError::SagaOperatorCapability)?;
        if !exact.0 {
            return Err(PgError::SagaOperatorRoleOrGrantMismatch);
        }
        if current_role_owns_database_objects(&self.pool)
            .await
            .map_err(PgError::SagaOperatorCapability)?
        {
            return Err(PgError::SagaOperatorOwnership);
        }
        if has_projection_external_persistence_capabilities(&self.pool)
            .await
            .map_err(PgError::SagaOperatorCapability)?
        {
            return Err(PgError::SagaOperatorExternalPersistencePrivileges);
        }
        Ok(())
    }

    /// Exact startup gate for one of the two independent function-only L2 DR lanes.
    async fn verify_l2_dr_recovery_lane_capability(
        &self,
        expected_role: &str,
        expected_routines: &[&str],
    ) -> Result<(), PgError> {
        let expected_routines: Vec<String> = expected_routines
            .iter()
            .map(|signature| (*signature).to_owned())
            .collect();
        let exact: (bool,) = sqlx::query_as(
            r#"
            WITH expected_relations(relation_name, privilege_type) AS (
                VALUES ('_sqlx_migrations', 'SELECT')
            ), relation_privileges(privilege_type) AS (
                VALUES ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE'),
                       ('TRUNCATE'), ('REFERENCES'), ('TRIGGER')
            ), actual_relations(relation_name, privilege_type) AS (
                SELECT relation.relname::text, privilege.privilege_type
                FROM pg_catalog.pg_class AS relation
                JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
                CROSS JOIN relation_privileges AS privilege
                WHERE namespace.nspname = 'public'
                  AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
                  AND pg_catalog.has_table_privilege(
                      current_user, relation.oid, privilege.privilege_type
                  )
            ), expected_routines AS (
                SELECT pg_catalog.to_regprocedure(signature)::oid AS oid
                FROM pg_catalog.unnest($2::text[]) AS signature
            ), actual_routines AS (
                SELECT procedure.oid
                FROM pg_catalog.pg_proc AS procedure
                JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
                WHERE namespace.nspname = 'public'
                  AND pg_catalog.has_function_privilege(current_user, procedure.oid, 'EXECUTE')
            ), expected_catalog(signature, owner_name, required_config) AS (
                VALUES
                    ('public.rss_service_token_replay_check_and_record(bytea,timestamp with time zone)',
                     'rss_service_token_replay_owner', ARRAY['search_path=pg_catalog, pg_temp']::text[]),
                    ('public.rss_l2_dr_recovery_record_start_audit(bigint,integer,text,uuid,uuid,bytea,uuid)',
                     'rss_l2_dr_recovery_owner', ARRAY['search_path=pg_catalog, pg_temp']::text[]),
                    ('public.rss_l2_dr_recovery_record_finish_audit(bigint,integer,text,uuid,uuid,text,text,uuid)',
                     'rss_l2_dr_recovery_owner', ARRAY['search_path=pg_catalog, pg_temp']::text[]),
                    ('public.rss_l2_dr_recovery_apply(uuid,uuid,text,bigint,bigint,text,text[],bytea,text,uuid)',
                     'rss_l2_dr_recovery_owner', ARRAY[
                         'search_path=pg_catalog, pg_temp', 'lock_timeout=5s',
                         'statement_timeout=5min'
                     ]::text[])
            )
            SELECT session_user = $1
               AND current_user = $1
               AND role.rolname = $1
               AND role.rolcanlogin
               AND NOT role.rolsuper
               AND NOT role.rolbypassrls
               AND NOT role.rolcreatedb
               AND NOT role.rolcreaterole
               AND NOT role.rolreplication
               AND NOT role.rolinherit
               AND COALESCE(cardinality(role.rolconfig), 0) = 1
               AND role.rolconfig @> ARRAY['search_path=pg_catalog, public']::text[]
               AND NOT EXISTS (
                    (SELECT * FROM actual_relations EXCEPT SELECT * FROM expected_relations)
                    UNION ALL
                    (SELECT * FROM expected_relations EXCEPT SELECT * FROM actual_relations)
               )
               AND NOT EXISTS (
                    (SELECT oid FROM actual_routines EXCEPT SELECT oid FROM expected_routines)
                    UNION ALL
                    (SELECT oid FROM expected_routines EXCEPT SELECT oid FROM actual_routines)
               )
               AND (SELECT pg_catalog.count(*) FROM expected_routines) =
                   pg_catalog.cardinality($2::text[])
               AND (
                    SELECT pg_catalog.count(*) = pg_catalog.cardinality($2::text[])
                       AND pg_catalog.bool_and(
                           procedure.prosecdef
                           AND procedure.proconfig @> catalog.required_config
                           AND pg_catalog.cardinality(procedure.proconfig) =
                               pg_catalog.cardinality(catalog.required_config)
                           AND function_owner.rolname = catalog.owner_name
                           AND NOT function_owner.rolcanlogin
                           AND NOT function_owner.rolsuper
                           AND function_owner.rolbypassrls =
                               (catalog.owner_name = 'rss_l2_dr_recovery_owner')
                           AND NOT function_owner.rolcreatedb
                           AND NOT function_owner.rolcreaterole
                           AND NOT function_owner.rolreplication
                           AND NOT function_owner.rolinherit
                           AND NOT EXISTS (
                               SELECT 1 FROM pg_catalog.pg_auth_members AS membership
                               WHERE membership.member = function_owner.oid
                                  OR membership.roleid = function_owner.oid
                           )
                           AND NOT EXISTS (
                               SELECT 1
                               FROM pg_catalog.aclexplode(
                                   COALESCE(
                                       procedure.proacl,
                                       pg_catalog.acldefault('f', procedure.proowner)
                                   )
                               ) AS acl
                               WHERE acl.grantee = 0 AND acl.privilege_type = 'EXECUTE'
                           )
                       )
                    FROM expected_catalog AS catalog
                    JOIN expected_routines AS expected
                      ON expected.oid = pg_catalog.to_regprocedure(catalog.signature)::oid
                    JOIN pg_catalog.pg_proc AS procedure ON procedure.oid = expected.oid
                    JOIN pg_catalog.pg_roles AS function_owner
                      ON function_owner.oid = procedure.proowner
                    WHERE catalog.signature = ANY($2::text[])
               )
               AND NOT EXISTS (
                    SELECT 1 FROM pg_catalog.pg_class AS relation
                    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
                    CROSS JOIN LATERAL pg_catalog.aclexplode(
                        COALESCE(relation.relacl, pg_catalog.acldefault('r', relation.relowner))
                    ) AS acl
                    WHERE namespace.nspname = 'public'
                      AND acl.grantee IN (0, role.oid)
                      AND acl.is_grantable
               )
               AND NOT EXISTS (
                    SELECT 1 FROM pg_catalog.pg_attribute AS attribute
                    CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) AS acl
                    WHERE attribute.attrelid IN (
                        SELECT relation.oid FROM pg_catalog.pg_class AS relation
                        JOIN pg_catalog.pg_namespace AS namespace
                          ON namespace.oid = relation.relnamespace
                        WHERE namespace.nspname = 'public'
                    )
                      AND acl.grantee IN (0, role.oid)
               )
               AND NOT EXISTS (
                    SELECT 1 FROM pg_catalog.pg_proc AS procedure
                    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
                    CROSS JOIN LATERAL pg_catalog.aclexplode(
                        COALESCE(procedure.proacl, pg_catalog.acldefault('f', procedure.proowner))
                    ) AS acl
                    WHERE namespace.nspname = 'public'
                      AND acl.grantee IN (0, role.oid)
                      AND acl.is_grantable
               )
               AND NOT EXISTS (
                    SELECT 1 FROM pg_catalog.pg_auth_members AS membership
                    WHERE membership.member = role.oid OR membership.roleid = role.oid
               )
            FROM pg_catalog.pg_roles AS role
            WHERE role.rolname = $1
            "#,
        )
        .bind(expected_role)
        .bind(&expected_routines)
        .fetch_one(&self.pool)
        .await
        .map_err(PgError::L2DrRecoveryLaneCapability)?;
        if !exact.0 {
            return Err(PgError::L2DrRecoveryLanePrivileges);
        }
        if current_role_owns_database_objects(&self.pool)
            .await
            .map_err(PgError::L2DrRecoveryLaneCapability)?
        {
            return Err(PgError::L2DrRecoveryLaneOwnership);
        }
        let (can_connect, can_create, can_temporary, connect_grant_option): (
            bool,
            bool,
            bool,
            bool,
        ) = sqlx::query_as(TENANT_READ_DATABASE_PRIVILEGES_SQL)
            .fetch_one(&self.pool)
            .await
            .map_err(PgError::L2DrRecoveryLaneCapability)?;
        let sequence_privileges: String = sqlx::query_scalar(TENANT_READ_SEQUENCE_PRIVILEGES_SQL)
            .fetch_one(&self.pool)
            .await
            .map_err(PgError::L2DrRecoveryLaneCapability)?;
        let (has_public_usage, schema_extras): (bool, String) =
            sqlx::query_as(TENANT_READ_SCHEMA_PRIVILEGES_SQL)
                .fetch_one(&self.pool)
                .await
                .map_err(PgError::L2DrRecoveryLaneCapability)?;
        if !can_connect
            || can_create
            || can_temporary
            || connect_grant_option
            || !sequence_privileges.is_empty()
            || !has_public_usage
            || !schema_extras.is_empty()
        {
            return Err(PgError::L2DrRecoveryLaneExternalPersistencePrivileges);
        }
        if has_projection_external_persistence_capabilities(&self.pool)
            .await
            .map_err(PgError::L2DrRecoveryLaneCapability)?
        {
            return Err(PgError::L2DrRecoveryLaneExternalPersistencePrivileges);
        }
        Ok(())
    }

    /// audit admin pool 能力门：直连固定 `rss_audit_admin`、不得绕过 RLS、只可 SELECT audit_entries。
    pub(crate) async fn verify_audit_admin_capability(&self) -> Result<(), PgError> {
        let mut tx = self.pool.begin().await.map_err(PgError::RlsCapability)?;
        ensure_audit_admin_role(&mut tx).await?;
        verify_tenant_guc_roundtrip(&mut tx, PgError::RlsCapability).await?;
        ensure_audit_admin_read_only(&mut tx).await?;
        let _ = tx.rollback().await;
        Ok(())
    }
}

fn ensure_projection_source_role_and_grants(exact: bool) -> Result<(), PgError> {
    if exact {
        Ok(())
    } else {
        Err(PgError::ProjectionSourceReadRoleOrGrantMismatch)
    }
}

fn ensure_projection_source_no_ownership(owns_database_objects: bool) -> Result<(), PgError> {
    if owns_database_objects {
        Err(PgError::ProjectionSourceReadOwnership)
    } else {
        Ok(())
    }
}

fn ensure_projection_source_no_external_persistence(
    has_external_persistence: bool,
) -> Result<(), PgError> {
    if has_external_persistence {
        Err(PgError::ProjectionSourceReadExternalPersistencePrivileges)
    } else {
        Ok(())
    }
}

fn ensure_projection_source_function_definition(
    function_fingerprint: String,
) -> Result<(), PgError> {
    if function_fingerprint == EXPECTED_PROJECTION_SOURCE_FUNCTION_FINGERPRINT {
        return Ok(());
    }
    tracing::error!(
        target: "postgres",
        actual_fingerprint = %function_fingerprint,
        "projection source function definition fingerprint mismatch"
    );
    Err(PgError::ProjectionSourceReadFunctionDefinition {
        actual_fingerprint: function_fingerprint,
    })
}

fn ensure_projection_source_capability_fingerprint(
    actual_fingerprint: String,
) -> Result<(), PgError> {
    if actual_fingerprint == EXPECTED_PROJECTION_SOURCE_CAPABILITY_FINGERPRINT {
        return Ok(());
    }
    tracing::error!(
        target: "postgres",
        %actual_fingerprint,
        "projection source effective capability fingerprint mismatch"
    );
    Err(PgError::ProjectionSourceReadPrivileges { actual_fingerprint })
}

fn ensure_projection_operator_role_and_grants(exact: bool) -> Result<(), PgError> {
    if exact {
        Ok(())
    } else {
        Err(PgError::ProjectionOperatorRoleOrGrantMismatch)
    }
}

fn ensure_projection_operator_no_ownership(owns_database_objects: bool) -> Result<(), PgError> {
    if owns_database_objects {
        Err(PgError::ProjectionOperatorOwnership)
    } else {
        Ok(())
    }
}

fn ensure_projection_operator_no_external_persistence(
    has_external_persistence: bool,
) -> Result<(), PgError> {
    if has_external_persistence {
        Err(PgError::ProjectionOperatorExternalPersistencePrivileges)
    } else {
        Ok(())
    }
}

fn ensure_projection_operator_function_definitions(
    function_fingerprint: String,
) -> Result<(), PgError> {
    if function_fingerprint == EXPECTED_PROJECTION_OPERATOR_FUNCTION_FINGERPRINT {
        return Ok(());
    }
    tracing::error!(
        target: "postgres",
        actual_fingerprint = %function_fingerprint,
        "projection operator function definition fingerprint mismatch"
    );
    Err(PgError::ProjectionOperatorFunctionDefinitions {
        actual_fingerprint: function_fingerprint,
    })
}

fn ensure_projection_operator_capability_fingerprint(
    actual_fingerprint: String,
) -> Result<(), PgError> {
    if actual_fingerprint == EXPECTED_PROJECTION_OPERATOR_CAPABILITY_FINGERPRINT {
        return Ok(());
    }
    tracing::error!(
        target: "postgres",
        %actual_fingerprint,
        "projection operator effective capability fingerprint mismatch"
    );
    Err(PgError::ProjectionOperatorPrivileges { actual_fingerprint })
}

async fn ensure_tenant_read_exact_external_capabilities(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), PgError> {
    ensure_tenant_read_no_membership(tx).await?;
    ensure_tenant_read_no_ownership(tx).await?;
    ensure_tenant_read_database_privileges(tx).await?;
    ensure_tenant_read_relation_privileges(tx).await?;
    ensure_tenant_read_no_default_privileges(tx).await?;
    ensure_tenant_read_no_sequence_privileges(tx).await?;
    ensure_tenant_read_schema_privileges(tx).await?;
    ensure_tenant_read_exact_function_privileges(tx).await?;
    ensure_tenant_read_no_large_object_mutator_privileges(tx).await?;
    ensure_tenant_read_no_large_object_privileges(tx).await?;
    ensure_tenant_read_no_parameter_privileges(tx).await
}

/// 0. serving 连接必须直连固定 `rss_app`，且不得绕过 RLS（superuser/BYPASSRLS）→ fail-fast。
///    绕过下 FORCE RLS 与 policy 全失效，后续 schema 校验无意义（PostgreSQL ddl-rowsecurity：
///    superuser/BYPASSRLS 永远绕过含 FORCE 的 RLS）。
async fn ensure_serving_role(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), PgError> {
    let row: (String, String, bool, bool, bool, bool, bool, bool, bool) =
        sqlx::query_as(WRITER_ROLE_SQL)
            .fetch_one(&mut **tx)
            .await
            .map_err(PgError::RlsCapability)?;
    let role = WriterRole {
        session_user: row.0,
        current_user: row.1,
        can_login: row.2,
        superuser: row.3,
        bypass_rls: row.4,
        create_db: row.5,
        create_role: row.6,
        replication: row.7,
        inherit: row.8,
    };
    ensure_expected_serving_role(&role)?;
    ensure_writer_role_attributes(&role)?;
    ensure_writer_no_membership(tx).await?;
    ensure_writer_no_ownership(tx).await?;
    ensure_writer_effective_privileges(tx).await?;
    ensure_writer_no_default_privileges(tx).await?;
    log_serving_role_accepted(&role);
    Ok(())
}

fn ensure_expected_serving_role(role: &WriterRole) -> Result<(), PgError> {
    if role.session_user == EXPECTED_SERVING_ROLE && role.current_user == EXPECTED_SERVING_ROLE {
        return Ok(());
    }
    tracing::error!(
        target: "postgres",
        session_user = %role.session_user,
        current_user = %role.current_user,
        expected_user = EXPECTED_SERVING_ROLE,
        "rls capability gate: durable serving connection must log in directly as rss_app"
    );
    Err(PgError::RlsUnexpectedServingRole)
}

fn ensure_writer_role_attributes(role: &WriterRole) -> Result<(), PgError> {
    if role.can_login
        && !role.superuser
        && !role.bypass_rls
        && !role.create_db
        && !role.create_role
        && !role.replication
        && !role.inherit
    {
        return Ok(());
    }
    log_serving_role_bypass(role);
    Err(PgError::WriterRoleAttributes)
}

async fn ensure_writer_no_membership(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), PgError> {
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint FROM pg_auth_members AS membership \
         JOIN pg_roles AS role ON role.oid = membership.roleid OR role.oid = membership.member \
         WHERE role.rolname = current_user",
    )
    .fetch_one(&mut **tx)
    .await
    .map_err(PgError::RlsCapability)?;
    if count == 0 {
        Ok(())
    } else {
        Err(PgError::WriterMembership)
    }
}

async fn ensure_writer_no_ownership(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), PgError> {
    let count: i64 = sqlx::query_scalar(
        r#"SELECT count(*)::bigint FROM (
               SELECT database.oid FROM pg_database AS database
               JOIN pg_roles AS role ON role.oid = database.datdba
               WHERE role.rolname = current_user
               UNION ALL
               SELECT namespace.oid FROM pg_namespace AS namespace
               JOIN pg_roles AS role ON role.oid = namespace.nspowner
               WHERE role.rolname = current_user AND namespace.nspname !~ '^pg_'
               UNION ALL
               SELECT relation.oid FROM pg_class AS relation
               JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
               JOIN pg_roles AS role ON role.oid = relation.relowner
               WHERE role.rolname = current_user AND namespace.nspname !~ '^pg_'
               UNION ALL
               SELECT procedure.oid FROM pg_proc AS procedure
               JOIN pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
               JOIN pg_roles AS role ON role.oid = procedure.proowner
               WHERE role.rolname = current_user AND namespace.nspname !~ '^pg_'
           ) AS owned"#,
    )
    .fetch_one(&mut **tx)
    .await
    .map_err(PgError::RlsCapability)?;
    if count == 0 {
        Ok(())
    } else {
        Err(PgError::WriterOwnership)
    }
}

async fn ensure_writer_effective_privileges(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), PgError> {
    let capabilities: Vec<(String,)> = sqlx::query_as(WRITER_EFFECTIVE_CAPABILITIES_SQL)
        .fetch_all(&mut **tx)
        .await
        .map_err(PgError::RlsCapability)?;
    if capabilities.is_empty() {
        return Err(PgError::WriterPrivileges {
            actual_fingerprint: "empty".to_owned(),
        });
    }
    let actual_fingerprint = effective_capability_fingerprint(&capabilities);
    if actual_fingerprint == EXPECTED_WRITER_CAPABILITY_FINGERPRINT {
        Ok(())
    } else {
        tracing::error!(target: "postgres", %actual_fingerprint, "writer effective capability fingerprint mismatch");
        Err(PgError::WriterPrivileges { actual_fingerprint })
    }
}

async fn ensure_writer_no_default_privileges(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), PgError> {
    let capabilities: Vec<(String,)> = sqlx::query_as(SERVING_DEFAULT_ACL_SQL)
        .fetch_all(&mut **tx)
        .await
        .map_err(PgError::RlsCapability)?;
    if capabilities.is_empty() {
        return Ok(());
    }
    let actual_fingerprint = effective_capability_fingerprint(&capabilities);
    tracing::error!(
        target: "postgres",
        %actual_fingerprint,
        "writer capability gate: custom default privileges are not empty"
    );
    Err(PgError::WriterDefaultPrivileges { actual_fingerprint })
}

fn log_serving_role_accepted(role: &WriterRole) {
    tracing::info!(
        target: "postgres",
        session_user = %role.session_user,
        current_user = %role.current_user,
        "rls capability gate: serving role accepted"
    );
}

fn log_serving_role_bypass(role: &WriterRole) {
    tracing::error!(
        target: "postgres",
        session_user = %role.session_user,
        current_user = %role.current_user,
        superuser = role.superuser,
        bypass_rls = role.bypass_rls,
        "rls capability gate: connection role is superuser or BYPASSRLS — RLS not enforceable; \
         serving connection must use rss_app as a non-superuser NOBYPASSRLS role (tenancy.md §RLS 与 PG scope)"
    );
}

async fn load_tenant_read_role(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<TenantReadRole, PgError> {
    sqlx::query_as(TENANT_READ_ROLE_SQL)
        .fetch_one(&mut **tx)
        .await
        .map_err(PgError::TenantReadCapability)
}

fn ensure_tenant_read_direct_role(role: &TenantReadRole) -> Result<(), PgError> {
    if role.session_user == EXPECTED_TENANT_READ_ROLE
        && role.current_user == EXPECTED_TENANT_READ_ROLE
    {
        return Ok(());
    }
    tracing::error!(
        target: "postgres",
        session_user = %role.session_user,
        current_user = %role.current_user,
        expected_user = EXPECTED_TENANT_READ_ROLE,
        "tenant reader capability gate: connection must log in directly as rss_app_read"
    );
    Err(PgError::TenantReadUnexpectedRole)
}

fn ensure_tenant_read_role_attributes(role: &TenantReadRole) -> Result<(), PgError> {
    if role.can_login
        && !role.superuser
        && !role.bypass_rls
        && !role.create_db
        && !role.create_role
        && !role.replication
        && !role.inherit
    {
        return Ok(());
    }
    tracing::error!(
        target: "postgres",
        can_login = role.can_login,
        superuser = role.superuser,
        bypass_rls = role.bypass_rls,
        create_db = role.create_db,
        create_role = role.create_role,
        replication = role.replication,
        inherit = role.inherit,
        "tenant reader capability gate: role attributes are not exact"
    );
    Err(PgError::TenantReadRoleAttributes)
}

fn ensure_tenant_read_default_transaction(role: &TenantReadRole) -> Result<(), PgError> {
    if role.exact_role_config && role.transaction_read_only {
        return Ok(());
    }
    tracing::error!(
        target: "postgres",
        exact_role_config = role.exact_role_config,
        transaction_read_only = role.transaction_read_only,
        "tenant reader capability gate: default transaction read-only is not exact"
    );
    Err(PgError::TenantReadDefaultTransaction)
}

fn ensure_tenant_read_search_path(role: &TenantReadRole) -> Result<(), PgError> {
    if role.exact_search_path_config && role.current_search_path == "pg_catalog, public" {
        return Ok(());
    }
    tracing::error!(
        target: "postgres",
        exact_search_path_config = role.exact_search_path_config,
        current_search_path = %role.current_search_path,
        expected_search_path = "pg_catalog, public",
        "tenant reader capability gate: search path is not exact"
    );
    Err(PgError::TenantReadSearchPath)
}

fn ensure_tenant_read_large_object_compatibility(role: &TenantReadRole) -> Result<(), PgError> {
    if role.lo_compat_privileges_off {
        return Ok(());
    }
    tracing::error!(
        target: "postgres",
        "tenant reader capability gate: lo_compat_privileges must be off"
    );
    Err(PgError::TenantReadLargeObjectCompatibility)
}

async fn ensure_tenant_read_no_membership(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), PgError> {
    let membership_count: i64 = sqlx::query_scalar(TENANT_READ_MEMBERSHIP_SQL)
        .fetch_one(&mut **tx)
        .await
        .map_err(PgError::TenantReadCapability)?;
    if membership_count == 0 {
        return Ok(());
    }
    tracing::error!(
        target: "postgres",
        membership_count,
        "tenant reader capability gate: role membership must be empty"
    );
    Err(PgError::TenantReadMembership)
}

async fn ensure_tenant_read_no_ownership(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), PgError> {
    let ownership_count: i64 = sqlx::query_scalar(TENANT_READ_OWNERSHIP_SQL)
        .fetch_one(&mut **tx)
        .await
        .map_err(PgError::TenantReadCapability)?;
    if ownership_count == 0 {
        return Ok(());
    }
    tracing::error!(
        target: "postgres",
        ownership_count,
        "tenant reader capability gate: role must not own database objects"
    );
    Err(PgError::TenantReadOwnership)
}

async fn ensure_tenant_read_relation_privileges(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), PgError> {
    let (missing_select, extra_privileges): (String, String) =
        sqlx::query_as(TENANT_READ_RELATION_PRIVILEGES_SQL)
            .fetch_one(&mut **tx)
            .await
            .map_err(PgError::TenantReadCapability)?;
    if missing_select.is_empty() && extra_privileges.is_empty() {
        return Ok(());
    }
    tracing::error!(
        target: "postgres",
        missing_select = %missing_select,
        extra_privileges = %extra_privileges,
        "tenant reader capability gate: relation privileges are not exact"
    );
    Err(PgError::TenantReadRelationPrivileges)
}

async fn ensure_tenant_read_no_default_privileges(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), PgError> {
    let capabilities: Vec<(String,)> = sqlx::query_as(SERVING_DEFAULT_ACL_SQL)
        .fetch_all(&mut **tx)
        .await
        .map_err(PgError::TenantReadCapability)?;
    if capabilities.is_empty() {
        return Ok(());
    }
    let actual_fingerprint = effective_capability_fingerprint(&capabilities);
    tracing::error!(
        target: "postgres",
        %actual_fingerprint,
        "tenant reader capability gate: custom default privileges are not empty"
    );
    Err(PgError::TenantReadDefaultPrivileges { actual_fingerprint })
}

async fn ensure_tenant_read_database_privileges(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), PgError> {
    let (can_connect, can_create, can_temporary, connect_grant_option): (bool, bool, bool, bool) =
        sqlx::query_as(TENANT_READ_DATABASE_PRIVILEGES_SQL)
            .fetch_one(&mut **tx)
            .await
            .map_err(PgError::TenantReadCapability)?;
    if can_connect && !can_create && !can_temporary && !connect_grant_option {
        return Ok(());
    }
    tracing::error!(
        target: "postgres",
        can_connect,
        can_create,
        can_temporary,
        connect_grant_option,
        "tenant reader capability gate: database privileges are not exact"
    );
    Err(PgError::TenantReadDatabasePrivileges)
}

async fn ensure_tenant_read_no_sequence_privileges(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), PgError> {
    let privileges: String = sqlx::query_scalar(TENANT_READ_SEQUENCE_PRIVILEGES_SQL)
        .fetch_one(&mut **tx)
        .await
        .map_err(PgError::TenantReadCapability)?;
    if privileges.is_empty() {
        return Ok(());
    }
    tracing::error!(
        target: "postgres",
        privileges = %privileges,
        "tenant reader capability gate: sequence privileges must be empty"
    );
    Err(PgError::TenantReadSequencePrivileges)
}

async fn ensure_tenant_read_schema_privileges(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), PgError> {
    let (has_public_usage, extra_privileges): (bool, String) =
        sqlx::query_as(TENANT_READ_SCHEMA_PRIVILEGES_SQL)
            .fetch_one(&mut **tx)
            .await
            .map_err(PgError::TenantReadCapability)?;
    if has_public_usage && extra_privileges.is_empty() {
        return Ok(());
    }
    tracing::error!(
        target: "postgres",
        has_public_usage,
        extra_privileges = %extra_privileges,
        "tenant reader capability gate: schema privileges are not exact"
    );
    Err(PgError::TenantReadSchemaPrivileges)
}

async fn ensure_tenant_read_exact_function_privileges(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), PgError> {
    ensure_tenant_read_resolver_posture(inspect_tenant_read_resolver_posture(tx).await?)?;
    ensure_tenant_read_resolver_definition(tx).await
}

struct TenantReadResolverPosture {
    effective_exact: bool,
    effective_functions: String,
    security_exact: bool,
    security_details: String,
}

async fn inspect_tenant_read_resolver_posture(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<TenantReadResolverPosture, PgError> {
    let (effective_exact, privileges): (bool, String) =
        sqlx::query_as(TENANT_READ_FUNCTION_PRIVILEGES_SQL)
            .fetch_one(&mut **tx)
            .await
            .map_err(PgError::TenantReadCapability)?;
    let (resolver_security_exact, resolver_security_details): (bool, String) =
        sqlx::query_as(TENANT_READ_RESOLVER_SECURITY_SQL)
            .fetch_one(&mut **tx)
            .await
            .map_err(PgError::TenantReadCapability)?;
    Ok(TenantReadResolverPosture {
        effective_exact,
        effective_functions: privileges,
        security_exact: resolver_security_exact,
        security_details: resolver_security_details,
    })
}

fn ensure_tenant_read_resolver_posture(posture: TenantReadResolverPosture) -> Result<(), PgError> {
    if posture.effective_exact && posture.security_exact {
        return Ok(());
    }
    tracing::error!(
        target: "postgres",
        effective_functions = %posture.effective_functions,
        effective_exact = posture.effective_exact,
        resolver_security_exact = posture.security_exact,
        resolver_security_details = %posture.security_details,
        "tenant reader capability gate: active resolver function privileges are not exact"
    );
    Err(PgError::TenantReadFunctionPrivileges {
        effective_functions: posture.effective_functions,
        effective_exact: posture.effective_exact,
        resolver_security_exact: posture.security_exact,
        resolver_security_details: posture.security_details,
    })
}

async fn ensure_tenant_read_resolver_definition(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), PgError> {
    let definitions: Vec<FunctionDefinitionRow> =
        sqlx::query_as(TENANT_READ_RESOLVER_FUNCTION_DEFINITION_SQL)
            .fetch_all(&mut **tx)
            .await
            .map_err(PgError::TenantReadCapability)?;
    let actual_fingerprint = function_definition_fingerprint(&definitions);
    if definitions.len() == 1 && actual_fingerprint == EXPECTED_TENANT_READ_FUNCTION_FINGERPRINT {
        return Ok(());
    }
    tracing::error!(
        target: "postgres",
        %actual_fingerprint,
        "tenant reader capability gate: active resolver definition fingerprint mismatch"
    );
    Err(PgError::TenantReadFunctionDefinition { actual_fingerprint })
}

async fn ensure_tenant_read_no_large_object_mutator_privileges(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), PgError> {
    let privileges: String = sqlx::query_scalar(TENANT_READ_LARGE_OBJECT_MUTATOR_PRIVILEGES_SQL)
        .fetch_one(&mut **tx)
        .await
        .map_err(PgError::TenantReadCapability)?;
    if privileges.is_empty() {
        return Ok(());
    }
    tracing::error!(
        target: "postgres",
        privileges = %privileges,
        "tenant reader capability gate: pg_catalog large-object mutator EXECUTE must be empty"
    );
    Err(PgError::TenantReadLargeObjectMutatorPrivileges)
}

async fn ensure_tenant_read_no_large_object_privileges(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), PgError> {
    let privileges: String = sqlx::query_scalar(TENANT_READ_LARGE_OBJECT_PRIVILEGES_SQL)
        .fetch_one(&mut **tx)
        .await
        .map_err(PgError::TenantReadCapability)?;
    if privileges.is_empty() {
        return Ok(());
    }
    tracing::error!(
        target: "postgres",
        privileges = %privileges,
        "tenant reader capability gate: large object privileges must be empty"
    );
    Err(PgError::TenantReadLargeObjectPrivileges)
}

async fn ensure_tenant_read_no_parameter_privileges(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), PgError> {
    let privileges: String = sqlx::query_scalar(TENANT_READ_PARAMETER_PRIVILEGES_SQL)
        .fetch_one(&mut **tx)
        .await
        .map_err(PgError::TenantReadCapability)?;
    if privileges.is_empty() {
        return Ok(());
    }
    tracing::error!(
        target: "postgres",
        privileges = %privileges,
        "tenant reader capability gate: parameter privileges must be empty"
    );
    Err(PgError::TenantReadParameterPrivileges)
}

async fn ensure_audit_admin_role(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), PgError> {
    let (session_user, current_user, superuser, bypass_rls): (String, String, bool, bool) =
        sqlx::query_as(CONNECTION_ROLE_SQL)
            .fetch_one(&mut **tx)
            .await
            .map_err(PgError::RlsCapability)?;
    let role = ServingRole {
        session_user,
        current_user,
        superuser,
        bypass_rls,
    };
    ensure_audit_admin_direct_role(&role)?;
    ensure_audit_admin_no_bypass(&role)?;
    Ok(())
}

fn ensure_audit_admin_direct_role(role: &ServingRole) -> Result<(), PgError> {
    if role.session_user != EXPECTED_AUDIT_ADMIN_ROLE
        || role.current_user != EXPECTED_AUDIT_ADMIN_ROLE
    {
        tracing::error!(
            target: "postgres",
            session_user = %role.session_user,
            current_user = %role.current_user,
            expected_user = EXPECTED_AUDIT_ADMIN_ROLE,
            "audit admin capability gate: connection must log in directly as rss_audit_admin"
        );
        return Err(PgError::AuditAdminUnexpectedRole);
    }
    Ok(())
}

fn ensure_audit_admin_no_bypass(role: &ServingRole) -> Result<(), PgError> {
    if role.superuser || role.bypass_rls {
        tracing::error!(
            target: "postgres",
            session_user = %role.session_user,
            current_user = %role.current_user,
            superuser = role.superuser,
            bypass_rls = role.bypass_rls,
            "audit admin capability gate: connection role must not bypass RLS"
        );
        return Err(PgError::AuditAdminBypassRole);
    }
    Ok(())
}

async fn ensure_audit_admin_read_only(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), PgError> {
    let (has_audit_entries_select, extra_privileges): (bool, String) =
        sqlx::query_as(AUDIT_ADMIN_PRIVILEGES_SQL)
            .fetch_one(&mut **tx)
            .await
            .map_err(PgError::RlsCapability)?;
    if has_audit_entries_select && extra_privileges.is_empty() {
        return Ok(());
    }
    tracing::error!(
        target: "postgres",
        has_audit_entries_select,
        extra_privileges = %extra_privileges,
        "audit admin capability gate: role must have exactly public.audit_entries SELECT and no other public relation privileges"
    );
    Err(PgError::AuditAdminPrivileges)
}

/// 2. anti-vacuity：至少存在一张含 `tenant_id` 列的 tenant 表（否则 schema 未迁移 / 库不符预期）。
async fn ensure_tenant_tables_present(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    map_probe: fn(sqlx::Error) -> PgError,
) -> Result<(), PgError> {
    let (n,): (i64,) = sqlx::query_as(TENANT_TABLE_COUNT_SQL)
        .fetch_one(&mut **tx)
        .await
        .map_err(map_probe)?;
    if n == 0 {
        return Err(PgError::RlsNoTenantTables);
    }
    Ok(())
}

/// 3 判定：不达标表非空 → `RlsNotEnforced`（记 offender 表名，PII-safe）。
fn ensure_no_offenders(offenders: Vec<String>) -> Result<(), PgError> {
    if offenders.is_empty() {
        return Ok(());
    }
    tracing::error!(
        target: "postgres",
        tables = %offenders.join(","),
        "rls capability gate: tenant tables missing FORCE RLS / 规范 policy 或存在 allow-all permissive widening"
    );
    Err(PgError::RlsNotEnforced)
}

/// GUC roundtrip 自检：经 funnel 注入探测租户 → `current_setting` 回显比对（不等 → `RlsGucRoundtrip`）。
async fn verify_tenant_guc_roundtrip(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    map_probe: fn(sqlx::Error) -> PgError,
) -> Result<(), PgError> {
    let probe = TenantId::parse(RLS_PROBE_TENANT).map_err(|_| PgError::RlsGucRoundtrip)?;
    set_local_tenant(tx, probe).await.map_err(map_probe)?;
    let (echoed,): (Option<String>,) =
        sqlx::query_as("SELECT current_setting('rss.tenant_id', true)")
            .fetch_one(&mut **tx)
            .await
            .map_err(map_probe)?;
    if echoed.as_deref() == Some(RLS_PROBE_TENANT) {
        Ok(())
    } else {
        Err(PgError::RlsGucRoundtrip)
    }
}

/// 不达标（缺 FORCE RLS / 规范 policy 或存在 allow-all permissive widening）的 tenant 表名列表。
async fn offending_tenant_tables(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    map_probe: fn(sqlx::Error) -> PgError,
) -> Result<Vec<String>, PgError> {
    let rows: Vec<(String,)> = sqlx::query_as(OFFENDING_TENANT_TABLES_SQL)
        .fetch_all(&mut **tx)
        .await
        .map_err(map_probe)?;
    Ok(rows.into_iter().map(|(t,)| t).collect())
}

impl PgStore {
    /// Connect and mint the writer capability only after the exact serving/RLS gate succeeds.
    pub(crate) async fn connect_verified_writer(
        config: &PgConfig,
    ) -> Result<VerifiedPgWriteStore, PgError> {
        let store = Arc::new(Self::connect_for(config, "writer", WRITER_APPLICATION_NAME).await?);
        if let Err(error) = store.verify_migration_ledger().await {
            store.pool.close().await;
            return Err(error);
        }
        if let Err(error) = store.verify_rls_capability().await {
            store.pool.close().await;
            return Err(error);
        }
        Ok(VerifiedPgWriteStore(store))
    }

    /// Connect and mint the tenant-reader capability only after its complete exact gate succeeds.
    pub(crate) async fn connect_verified_read(
        config: &PgTenantReadConfig,
    ) -> Result<VerifiedPgReadStore, PgError> {
        let store = Arc::new(
            Self::connect_for(config.as_pg_config(), "reader", READER_APPLICATION_NAME).await?,
        );
        if let Err(error) = store.verify_tenant_read_capability().await {
            store.pool.close().await;
            return Err(error);
        }
        Ok(VerifiedPgReadStore(store))
    }

    /// Connect and mint the scoped Projection source capability after its exact gate succeeds.
    pub(crate) async fn connect_verified_projection_source_read(
        config: &PgProjectionSourceReadConfig,
    ) -> Result<VerifiedPgProjectionSourceReadStore, PgError> {
        let store = Arc::new(
            Self::connect_for(
                config.as_pg_config(),
                "projection-source-reader",
                PROJECTION_SOURCE_READER_APPLICATION_NAME,
            )
            .await?,
        );
        if let Err(error) = store.verify_migration_ledger().await {
            store.pool.close().await;
            return Err(error);
        }
        if let Err(error) = store.verify_projection_source_read_capability().await {
            store.pool.close().await;
            return Err(error);
        }
        Ok(VerifiedPgProjectionSourceReadStore(store))
    }

    /// Connect and mint the Projection operator capability after its exact gate succeeds.
    pub(crate) async fn connect_verified_projection_operator(
        config: &PgProjectionOperatorConfig,
    ) -> Result<VerifiedPgProjectionOperatorStore, PgError> {
        let store = Arc::new(
            Self::connect_for(
                config.as_pg_config(),
                "projection-operator",
                PROJECTION_OPERATOR_APPLICATION_NAME,
            )
            .await?,
        );
        if let Err(error) = store.verify_projection_operator_capability().await {
            store.pool.close().await;
            return Err(error);
        }
        Ok(VerifiedPgProjectionOperatorStore(store))
    }

    /// Connect and mint the function-only Saga operator capability after its exact gate succeeds.
    pub(crate) async fn connect_verified_saga_operator(
        config: &PgSagaOperatorConfig,
    ) -> Result<VerifiedPgSagaOperatorStore, PgError> {
        let store = Arc::new(
            Self::connect_for(
                config.as_pg_config(),
                "saga-operator",
                SAGA_OPERATOR_APPLICATION_NAME,
            )
            .await?,
        );
        if let Err(error) = store.verify_migration_ledger().await {
            store.pool.close().await;
            return Err(error);
        }
        if let Err(error) = store.verify_saga_operator_capability().await {
            store.pool.close().await;
            return Err(error);
        }
        Ok(VerifiedPgSagaOperatorStore(store))
    }

    async fn connect_verified_l2_dr_recovery_lane(
        config: &PgConfig,
        label: &'static str,
        application_name: &'static str,
        expected_role: &'static str,
        expected_routines: &'static [&'static str],
    ) -> Result<Arc<PgStore>, PgError> {
        let store = Arc::new(Self::connect_for(config, label, application_name).await?);
        if let Err(error) = store.verify_migration_ledger().await {
            store.pool.close().await;
            return Err(error);
        }
        if let Err(error) = store
            .verify_l2_dr_recovery_lane_capability(expected_role, expected_routines)
            .await
        {
            store.pool.close().await;
            return Err(error);
        }
        Ok(store)
    }

    /// Connect and mint the authentication/audit lane after its exact effective-ACL gate.
    pub(crate) async fn connect_verified_l2_dr_recovery_auditor(
        config: &PgL2DrRecoveryAuditConfig,
    ) -> Result<VerifiedPgL2DrRecoveryAuditStore, PgError> {
        Self::connect_verified_l2_dr_recovery_lane(
            config.as_pg_config(),
            "l2-dr-recovery-auditor",
            L2_DR_RECOVERY_AUDITOR_APPLICATION_NAME,
            "rss_l2_dr_recovery_auditor",
            &[
                L2_DR_REPLAY_FUNCTION,
                L2_DR_START_AUDIT_FUNCTION,
                L2_DR_FINISH_AUDIT_FUNCTION,
            ],
        )
        .await
        .map(VerifiedPgL2DrRecoveryAuditStore)
    }

    /// Connect and mint the apply-only executor lane after its exact effective-ACL gate.
    pub(crate) async fn connect_verified_l2_dr_recovery_executor(
        config: &PgL2DrRecoveryExecutorConfig,
    ) -> Result<VerifiedPgL2DrRecoveryExecutorStore, PgError> {
        Self::connect_verified_l2_dr_recovery_lane(
            config.as_pg_config(),
            "l2-dr-recovery-executor",
            L2_DR_RECOVERY_EXECUTOR_APPLICATION_NAME,
            "rss_l2_dr_recovery_executor",
            &[L2_DR_APPLY_FUNCTION],
        )
        .await
        .map(VerifiedPgL2DrRecoveryExecutorStore)
    }

    /// Connect and mint the independent audit-admin capability after its exact gate succeeds.
    pub(crate) async fn connect_verified_audit_admin(
        config: &PgConfig,
    ) -> Result<VerifiedPgAuditAdminStore, PgError> {
        let store =
            Arc::new(Self::connect_for(config, "audit-admin", AUDIT_ADMIN_APPLICATION_NAME).await?);
        if let Err(error) = store.verify_audit_admin_capability().await {
            store.pool.close().await;
            return Err(error);
        }
        Ok(VerifiedPgAuditAdminStore(store))
    }

    /// 建池并连接 postgres：先 fail-fast 校验配置，再 `PgPoolOptions::connect_with`。
    ///
    /// `ref: sqlx sqlx-core/src/pool/options.rs@v0.8.6`。
    ///
    /// `pub(crate)`（#1423，PG-BUNDLE-FUNNEL-01）：唯一公开构造路径是 [`crate::PgRuntimeDeps::setup`]，
    /// 外部不能直接 mint `PgStore`、故拿不到 `&PgStore` 散装构造 repo。
    pub(crate) async fn connect(config: &PgConfig) -> Result<Self, PgError> {
        Self::connect_for(config, "maintenance", APPLICATION_NAME).await
    }

    async fn connect_for(
        config: &PgConfig,
        lane: &'static str,
        application_name: &'static str,
    ) -> Result<Self, PgError> {
        config.validate()?;
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .acquire_timeout(config.acquire_timeout)
            .connect_with(config.connect_options_for(application_name))
            .await
            .inspect_err(|err| {
                // reason: 连接（持久化）失败在 adapter 边界记 error!，避免仅 `?` 冒泡时日志链断点（observability.md §日志级别）；
                // 第三方 sqlx::Error 经 secure::redact_error 统一脱敏 funnel，杜绝连接串 / 凭据泄漏。
                tracing::error!(
                    target: "postgres",
                    error = %secure::redact_error(err),
                    host = %config.host,
                    database = %config.database,
                    lane,
                    "postgres pool connect failed"
                );
            })
            .map_err(|source| PgError::Connect { lane, source })?;
        // reason: host/database 是中性运维标识（非租户敏感）。若未来 database 名引入租户标识，须先经
        // secure redaction 清洗再记录——勿在此直接落库名（防漂移护栏）。
        tracing::info!(
            target: "postgres",
            host = %config.host,
            database = %config.database,
            lane,
            "postgres pool connected"
        );
        Ok(Self { pool })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PgConfig {
        PgConfig::new(
            "db.internal",
            5432,
            "rss",
            "rss_app",
            PgPassword::new("s3cr3t-value"),
        )
    }

    fn tenant_reader_role() -> TenantReadRole {
        TenantReadRole {
            session_user: EXPECTED_TENANT_READ_ROLE.to_string(),
            current_user: EXPECTED_TENANT_READ_ROLE.to_string(),
            can_login: true,
            superuser: false,
            bypass_rls: false,
            create_db: false,
            create_role: false,
            replication: false,
            inherit: false,
            exact_role_config: true,
            exact_search_path_config: true,
            current_search_path: "pg_catalog, public".to_string(),
            transaction_read_only: true,
            lo_compat_privileges_off: true,
        }
    }

    #[test]
    fn validate_accepts_well_formed_config() {
        assert!(sample().validate().is_ok());
    }

    #[test]
    fn validate_rejects_empty_host() {
        let cfg = PgConfig::new("", 5432, "rss", "u", PgPassword::new("p"));
        assert!(matches!(cfg.validate(), Err(PgError::EmptyHost)));
    }

    #[test]
    fn validate_rejects_blank_database() {
        let cfg = PgConfig::new("h", 5432, "   ", "u", PgPassword::new("p"));
        assert!(matches!(cfg.validate(), Err(PgError::EmptyDatabase)));
    }

    #[test]
    fn validate_rejects_blank_username() {
        let cfg = PgConfig::new("h", 5432, "rss", "  ", PgPassword::new("p"));
        assert!(matches!(cfg.validate(), Err(PgError::EmptyUsername)));
    }

    #[test]
    fn validate_rejects_empty_password() {
        let cfg = PgConfig::new("h", 5432, "rss", "u", PgPassword::new(""));
        assert!(matches!(cfg.validate(), Err(PgError::EmptyPassword)));
    }

    #[test]
    fn validate_rejects_zero_port() {
        let cfg = PgConfig::new("h", 0, "rss", "u", PgPassword::new("p"));
        assert!(matches!(cfg.validate(), Err(PgError::ZeroPort)));
    }

    #[test]
    fn validate_rejects_zero_max_connections() {
        let cfg = sample().with_max_connections(0);
        assert!(matches!(cfg.validate(), Err(PgError::ZeroMaxConnections)));
    }

    #[test]
    fn password_debug_is_redacted() {
        let rendered = format!("{:?}", PgPassword::new("super-secret-value"));
        assert_eq!(rendered, "PgPassword(<redacted>)");
        assert!(!rendered.contains("super-secret-value"));
    }

    #[test]
    fn config_debug_does_not_leak_password() {
        let rendered = format!("{:?}", sample());
        assert!(!rendered.contains("s3cr3t-value"));
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn tenant_read_config_debug_does_not_leak_password() {
        let rendered = format!("{:?}", PgTenantReadConfig::new(sample()));
        assert!(rendered.contains("PgTenantReadConfig"));
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("s3cr3t-value"));
    }

    #[test]
    fn exact_tenant_reader_role_is_accepted() {
        let role = tenant_reader_role();
        assert!(ensure_tenant_read_direct_role(&role).is_ok());
        assert!(ensure_tenant_read_role_attributes(&role).is_ok());
        assert!(ensure_tenant_read_default_transaction(&role).is_ok());
        assert!(ensure_tenant_read_search_path(&role).is_ok());
    }

    #[test]
    fn tenant_reader_role_rejects_each_attribute_drift() {
        let mut cases: Vec<(&str, TenantReadRole)> = Vec::new();
        let mut superuser = tenant_reader_role();
        superuser.superuser = true;
        cases.push(("superuser", superuser));
        let mut bypass_rls = tenant_reader_role();
        bypass_rls.bypass_rls = true;
        cases.push(("bypass_rls", bypass_rls));
        let mut create_db = tenant_reader_role();
        create_db.create_db = true;
        cases.push(("create_db", create_db));
        let mut create_role = tenant_reader_role();
        create_role.create_role = true;
        cases.push(("create_role", create_role));
        let mut replication = tenant_reader_role();
        replication.replication = true;
        cases.push(("replication", replication));
        let mut inherit = tenant_reader_role();
        inherit.inherit = true;
        cases.push(("inherit", inherit));
        let mut no_login = tenant_reader_role();
        no_login.can_login = false;
        cases.push(("no_login", no_login));

        for (label, role) in cases {
            assert!(
                matches!(
                    ensure_tenant_read_role_attributes(&role),
                    Err(PgError::TenantReadRoleAttributes)
                ),
                "attribute drift must fail closed: {label}"
            );
        }
    }

    #[test]
    fn tenant_reader_role_rejects_identity_and_default_drift() {
        let mut identity = tenant_reader_role();
        identity.current_user = EXPECTED_SERVING_ROLE.to_string();
        assert!(matches!(
            ensure_tenant_read_direct_role(&identity),
            Err(PgError::TenantReadUnexpectedRole)
        ));

        let mut role_config = tenant_reader_role();
        role_config.exact_role_config = false;
        assert!(matches!(
            ensure_tenant_read_default_transaction(&role_config),
            Err(PgError::TenantReadDefaultTransaction)
        ));

        let mut active_transaction = tenant_reader_role();
        active_transaction.transaction_read_only = false;
        assert!(matches!(
            ensure_tenant_read_default_transaction(&active_transaction),
            Err(PgError::TenantReadDefaultTransaction)
        ));

        let mut role_search_path = tenant_reader_role();
        role_search_path.exact_search_path_config = false;
        assert!(matches!(
            ensure_tenant_read_search_path(&role_search_path),
            Err(PgError::TenantReadSearchPath)
        ));

        let mut active_search_path = tenant_reader_role();
        active_search_path.current_search_path = "public".to_string();
        assert!(matches!(
            ensure_tenant_read_search_path(&active_search_path),
            Err(PgError::TenantReadSearchPath)
        ));
    }

    #[test]
    fn connect_options_maps_connection_fields() {
        let opts = sample().connect_options();
        assert_eq!(opts.get_host(), "db.internal");
        assert_eq!(opts.get_port(), 5432);
        assert_eq!(opts.get_database(), Some("rss"));
    }

    #[test]
    fn connect_options_defaults_to_verify_full_tls() {
        // 零信任默认：未显式降级时 ssl_mode = VerifyFull（强制 TLS + 校验证书链/主机名，杜绝明文回退与 MITM）。
        assert!(matches!(
            sample().connect_options().get_ssl_mode(),
            PgSslMode::VerifyFull
        ));
    }

    #[test]
    fn with_ssl_mode_overrides_default() {
        let opts = sample().with_ssl_mode(PgSslMode::Disable).connect_options();
        assert!(matches!(opts.get_ssl_mode(), PgSslMode::Disable));
    }

    #[test]
    fn with_ssl_root_cert_preserves_path_and_verify_full_default() {
        let opts = sample()
            .with_ssl_root_cert("/run/rss/pg-root-ca.pem")
            .connect_options();
        assert!(matches!(opts.get_ssl_mode(), PgSslMode::VerifyFull));
        let rendered = format!("{opts:?}");
        assert!(
            rendered.contains("pg-root-ca.pem"),
            "root cert path must be passed to sqlx connect options: {rendered}"
        );
    }

    #[test]
    fn defaults_applied_on_new() {
        // tuning 默认在 new 时落定（无静默系统默认；显式常量单源）。
        assert!(sample().validate().is_ok());
        assert_eq!(DEFAULT_MAX_CONNECTIONS, 10);
        assert_eq!(DEFAULT_ACQUIRE_TIMEOUT, Duration::from_secs(30));
        assert!(matches!(DEFAULT_SSL_MODE, PgSslMode::VerifyFull));
    }

    #[test]
    fn connection_error_identifies_lane_without_credentials() {
        let error = PgError::Connect {
            lane: "reader",
            source: sqlx::Error::PoolClosed,
        };
        assert_eq!(error.to_string(), "postgres reader connection failed");
    }

    // ---------------------------------------------------------------------------
    // PoolReadiness 单元测试（#1309 F4：三态 Ready/Saturated/Down）
    // ---------------------------------------------------------------------------

    /// `PoolReadiness` 三态（Ready/Saturated/Down）可构造、Copy/Clone/PartialEq 满足。
    #[test]
    #[allow(clippy::clone_on_copy)]
    fn pool_readiness_traits_hold() {
        let a = PoolReadiness::Ready;
        let b = a; // Copy
        assert_eq!(a, b); // PartialEq
        let c = a.clone(); // Clone
        assert_eq!(a, c);
        // Saturated 变体可构造（anti-vacuity）。
        let _saturated = PoolReadiness::Saturated;
        // Down 变体可构造（anti-vacuity）。
        let _down = PoolReadiness::Down;
    }

    // ---------------------------------------------------------------------------
    // acquired-connection query classification（capacity pressure is handled before this stage）
    // ---------------------------------------------------------------------------

    /// Once a connection has been acquired, every query error is liveness failure, not saturation.
    #[test]
    fn acquired_query_error_is_down() {
        assert_eq!(
            super::probe_query_result(Ok(Err(sqlx::Error::PoolTimedOut))),
            PoolReadiness::Down
        );
    }

    /// `PoolClosed` during the acquired query stage is Down.
    #[test]
    fn acquired_query_pool_closed_is_down() {
        assert_eq!(
            super::probe_query_result(Ok(Err(sqlx::Error::PoolClosed))),
            PoolReadiness::Down
        );
    }

    /// 查询 / 协议错误 → `Down`（非池状态错误，视为 DB 不可服务）。
    #[test]
    fn acquired_query_protocol_error_is_down() {
        assert_eq!(
            super::probe_query_result(Ok(Err(sqlx::Error::Protocol("test error".to_string())))),
            PoolReadiness::Down
        );
    }

    /// A query hang after acquiring a connection must fail readiness.
    #[tokio::test]
    async fn probe_outer_timeout_is_down() {
        let timed_out = tokio::time::timeout(
            Duration::ZERO,
            std::future::pending::<Result<(), sqlx::Error>>(),
        )
        .await;
        assert_eq!(super::probe_query_result(timed_out), PoolReadiness::Down);
    }

    // ---------------------------------------------------------------------------
    // probe_db_liveness 失败臂单测（#1309 review T1）
    // ---------------------------------------------------------------------------

    /// `probe_db_liveness` 已关闭 pool 快路径：`is_closed()=true` → `Down`（快路径，不 acquire）。
    ///
    /// 覆盖 `probe_db_liveness` 中的 `is_closed()` 快路径 Down（跨平台可靠）。
    /// Down query/error branches are covered above without relying on platform network behavior.
    #[tokio::test]
    async fn probe_unreachable_pool_returns_down() {
        use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
        let opts = PgConnectOptions::new()
            .host("127.0.0.1")
            .port(5999)
            .database("rss_test")
            .username("u")
            .password("p");
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy_with(opts);
        pool.close().await;
        let store = PgStore { pool };
        // pool.is_closed()=true → probe 快路径直接返回 Down，不经 acquire。
        assert_eq!(
            store.probe_db_liveness().await,
            PoolReadiness::Down,
            "已关闭 pool → probe 返回 Down（is_closed 快路径）"
        );
    }

    #[cfg(feature = "integration")]
    #[tokio::test(flavor = "multi_thread")]
    async fn writer_capability_attests_enrollment_and_rejects_extra_execute()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use diport::ManagedResource as _;

        let (fixture, owner) = crate::test_pg::connect_pg().await?;
        owner.run_migrations().await?;
        let app = crate::test_pg::connect_pg_rss_app_role(&fixture, &owner).await?;
        let capabilities: Vec<(String,)> = sqlx::query_as(WRITER_EFFECTIVE_CAPABILITIES_SQL)
            .fetch_all(&app.pool)
            .await?;
        assert!(
            capabilities.iter().any(|(capability,)| capability
                == "function:public.rss_enroll_device_certificate_reconcile_target(\
                    p_tenant_id uuid, p_device_id uuid, p_initial_due_epoch_micros bigint):EXECUTE"),
            "reviewed inventory must carry the exact 0096 enrollment EXECUTE"
        );
        assert!(
            capabilities.iter().any(|(capability,)| capability
                == "function:public.rss_lock_device_certificate_reconcile_view(\
                    p_tenant_id uuid, p_device_id uuid, p_attempt_id uuid, p_lease_token uuid, \
                    p_epoch bigint, p_wake_version bigint):EXECUTE"),
            "reviewed inventory must carry the exact fenced-view EXECUTE"
        );
        assert_eq!(
            effective_capability_fingerprint(&capabilities),
            EXPECTED_WRITER_CAPABILITY_FINGERPRINT,
            "the committed migration head must match its reviewed writer capability inventory"
        );

        let params = fixture.owner_params();
        let serving_config = PgConfig::new(
            params.host.clone(),
            params.port,
            params.database.clone(),
            "rss_app",
            PgPassword::new("rss_app_test_pw"),
        )
        .with_ssl_mode(PgSslMode::Prefer)
        .with_acquire_timeout(Duration::from_secs(5));
        let verified = PgStore::connect_verified_writer(&serving_config).await?;
        verified.store_arc().shutdown().await?;

        sqlx::raw_sql(
            "CREATE FUNCTION public.rss_test_unreviewed_writer_capability() \
               RETURNS integer LANGUAGE sql SET search_path=pg_catalog,pg_temp AS 'SELECT 1'; \
             REVOKE ALL ON FUNCTION public.rss_test_unreviewed_writer_capability() FROM PUBLIC; \
             GRANT EXECUTE ON FUNCTION public.rss_test_unreviewed_writer_capability() TO rss_app;",
        )
        .execute(&owner.pool)
        .await?;
        let drift = PgStore::connect_verified_writer(&serving_config).await;
        sqlx::query("DROP FUNCTION public.rss_test_unreviewed_writer_capability()")
            .execute(&owner.pool)
            .await?;
        let drift_fingerprint = match drift {
            Err(PgError::WriterPrivileges { actual_fingerprint }) => actual_fingerprint,
            Err(other) => {
                return Err(std::io::Error::other(format!(
                    "an extra function EXECUTE must reject serving startup, got {other:?}"
                ))
                .into());
            }
            Ok(unexpected) => {
                unexpected.store_arc().shutdown().await?;
                return Err(std::io::Error::other(
                    "an extra function EXECUTE unexpectedly passed serving startup",
                )
                .into());
            }
        };
        assert_ne!(drift_fingerprint, EXPECTED_WRITER_CAPABILITY_FINGERPRINT);

        let recovered = PgStore::connect_verified_writer(&serving_config).await?;
        recovered.store_arc().shutdown().await?;
        app.shutdown().await?;
        owner.shutdown().await?;
        Ok(())
    }
}
