//! postgres 连接池 + adapter 配置 + 错误类型（eventexec 持久化基座，#1116）。
//!
//! `ref: sqlx sqlx-core/src/pool/options.rs@v0.8.6`（`PgPoolOptions` builder + `connect_with`）。

use std::path::PathBuf;
use std::time::Duration;

use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use vocab::TenantId;

use crate::PgStore;
use crate::cotx::set_local_tenant;

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
/// 连接 `application_name`（对应 pg_stat_activity.application_name，便于运维归因）。
const APPLICATION_NAME: &str = "rss-postgres";

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
    #[error("postgres connection failed")]
    Connect(#[source] sqlx::Error),
    /// 迁移应用失败。
    #[error("postgres migration failed")]
    Migrate(#[source] sqlx::migrate::MigrateError),
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
    /// RLS 能力门：连接角色为 superuser 或 `BYPASSRLS`——绕过 FORCE RLS，serving 连接须用非 superuser
    /// NOBYPASSRLS 角色（fail-closed，拒绝启动；tenancy.md「生产 owner 须为非 superuser」）。
    #[error("postgres rls capability: connection role bypasses RLS (superuser or BYPASSRLS)")]
    RlsBypassRole,
    /// RLS 能力门：durable serving pool 必须以固定 app-serving role `rss_app` 连接；其它 non-bypass role
    /// 也不得作为生产 serving pool，避免测试替身 / owner-like 角色漂进 bootstrap。
    #[error("postgres rls capability: serving role must be rss_app")]
    RlsUnexpectedServingRole,
    /// config_entries 中仍存在 legacy plaintext `ConfigValue` 行。默认启动 fail-closed；临时兼容只能经显式
    /// `LegacyConfigPlaintextPolicy::AllowTemporary` 放行。
    #[error("postgres legacy plaintext config values are present")]
    LegacyConfigPlaintextPresent { count: i64 },
    /// legacy plaintext 扫描 SQL 失败（启动关键路径）。
    #[error("postgres legacy plaintext config value probe failed")]
    LegacyConfigPlaintextProbe(#[source] sqlx::Error),
    /// settings ConfigValue maintenance durable audit 写入失败（维护入口 fail-closed）。
    #[error("postgres config value maintenance audit failed")]
    MaintenanceAudit(#[source] sqlx::Error),
}

/// 启动期 legacy plaintext `ConfigValue` 行策略。
///
/// 默认 [`Deny`](Self::Deny)：迁移后发现 `protection_scheme = 0` 即拒绝启动。[`AllowTemporary`](Self::AllowTemporary)
/// 仅供 backfill 前的短期人工豁免；新写路径仍只能写 encrypted scheme。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyConfigPlaintextPolicy {
    /// 默认 fail-closed：存在 legacy plaintext 行即启动失败。
    Deny,
    /// 临时放行 legacy plaintext 行，供人工规划 backfill 前短期运行。
    AllowTemporary,
}

/// postgres 连接密码：私有字段 + redacted `Debug`，杜绝明文进日志 / panic message / `PgConfig` 派生 Debug。
///
/// **故意不实现 `Display`**：任何需要明文的路径只能经 [`PgPassword::expose`]（`pub(crate)`，仅 crate 内喂
/// 给 sqlx），杜绝下游 `format!("{pw}")` 意外泄漏。
#[derive(Clone)]
pub struct PgPassword(String);

impl PgPassword {
    /// 由密文构造。
    pub fn new(secret: impl Into<String>) -> Self {
        Self(secret.into())
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
    pub(crate) fn connect_options(&self) -> PgConnectOptions {
        let mut opts = PgConnectOptions::new()
            .host(&self.host)
            .port(self.port)
            .database(&self.database)
            .username(&self.username)
            .password(self.password.expose())
            .ssl_mode(self.ssl_mode)
            .application_name(APPLICATION_NAME);
        if let Some(ref cert) = self.ssl_root_cert {
            opts = opts.ssl_root_cert(cert);
        }
        opts
    }
}

/// per-probe 超时（单次 `SELECT 1` 最长等待；限制 pool acquire_timeout=30s 期间阻塞 → sampler 关停响应 ≤ 此值）。
const PROBE_READINESS_TIMEOUT: Duration = Duration::from_secs(2);

/// DB liveness 采样结果三态（#1309 F4 重引 `Saturated`，区分池饱和与 DB 不可达）。
///
/// - `Ready`：`probe_db_liveness` 成功（`SELECT 1` 返回，HTTP 200 Healthy）。
/// - `Saturated`：池 acquire 超时（容量压力，DB 多半正常；HTTP 200 Degraded，编排器不摘流）。
/// - `Down`：池已关闭、DB 不可达或 `SELECT 1` 失败（HTTP 503 Unhealthy）。
///
/// `#[non_exhaustive]`：未来变体不破坏外部 match 调用方（`_ =>` fallback）。
/// `ConfigsReadyProbe::check` 读 `PgDbReadiness::snapshot()` 经此类型报 readyz 状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PoolReadiness {
    /// `probe_db_liveness` 成功（`SELECT 1` 返回）。
    Ready,
    /// 池 acquire 超时（容量压力，DB 多半正常）：降级可服务，编排器不应摘流（HTTP 200）。
    Saturated,
    /// 池已关闭、DB 不可达或 `SELECT 1` 失败：不可服务（HTTP 503）。
    Down,
}

/// acquire + `SELECT 1` 的纯 I/O 部分（抽出降低 probe_db_liveness 认知复杂度）。
///
/// acquire 失败或 query 失败均经 `?` 返 `Err`；成功返 `Ok(())`。
async fn db_select_one(pool: &sqlx::PgPool) -> Result<(), sqlx::Error> {
    let mut conn = pool.acquire().await?;
    sqlx::query("SELECT 1")
        .execute(&mut *conn)
        .await
        .map(|_| ())
}

/// `sqlx::Error` 分类为 `PoolReadiness`（仅 acquire/query 失败臂使用）。
///
/// - `PoolTimedOut`：池 acquire 排队超时 = 容量压力，DB 多半正常 → `Saturated`（降级可服务）。
/// - 其余（`PoolClosed` / IO 错误 / 查询错误）→ `Down`（不可服务）。
fn classify_probe_error(e: &sqlx::Error) -> PoolReadiness {
    match e {
        sqlx::Error::PoolTimedOut => PoolReadiness::Saturated,
        // reason: PoolClosed / 连接拒绝 / 查询错误均视为 DB 不可达，fail-closed → Down。
        _ => PoolReadiness::Down,
    }
}

/// 超时结果 → `PoolReadiness`（抽出降低 `probe_db_liveness` 认知复杂度）。
///
/// - `Ok(Ok(()))` → `Ready`
/// - `Ok(Err(e))` → [`classify_probe_error`]（`PoolTimedOut`→`Saturated`，其余→`Down`）
/// - `Err(_elapsed)` → `Saturated`（外层超时多为 acquire 排队，fail-open 倾向降级不摘流）
// reason: tracing::debug! 宏展开后 clippy cognitive_complexity 计数偏高（实际 3 分支）——item-level carve-out。
#[allow(clippy::cognitive_complexity)]
fn probe_timeout_result(
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
            classify_probe_error(&e)
        }
        Err(_elapsed) => {
            // reason: 外层 2s timeout 多为 acquire 排队（池饱和），非 DB 不可达
            // （DB down 多走连接拒绝 → Ok(Err) 分支 → classify_probe_error → Down）；
            // fail-open 倾向 Saturated 避免误摘流量。
            tracing::debug!(
                target: "postgres",
                timeout_secs = PROBE_READINESS_TIMEOUT.as_secs(),
                "postgres readiness probe timed out — treating as pool saturated"
            );
            PoolReadiness::Saturated
        }
    }
}

impl PgStore {
    /// DB liveness 探针（async）：acquire 连接后执行 `SELECT 1`（超时 [`PROBE_READINESS_TIMEOUT`]）。
    ///
    /// - `pool.is_closed()` → `PoolReadiness::Down`（快路径，不 acquire）。
    /// - 成功 → `PoolReadiness::Ready`。
    /// - `Ok(Err(e))`（acquire/query 失败）→ [`classify_probe_error`]：`PoolTimedOut`→`Saturated`；其余→`Down`。
    /// - 外层超时（`Err(_elapsed)` > [`PROBE_READINESS_TIMEOUT`]）→ `Saturated`（acquire 排队 = 容量压力）。
    ///
    /// 第三方 `sqlx::Error` 经 [`secure::redact_error`] 脱敏后落 `tracing::debug!`，杜绝连接串 / 凭据泄漏。
    /// DB 持续不可达时**不每 tick warn！**——状态转移日志由 [`crate::readiness::pg_readiness_sampling_loop`] 负责。
    ///
    /// 供 [`crate::readiness::pg_readiness_sampling_loop`] 周期调用；同步读采样状态用
    /// [`crate::readiness::PgDbReadiness::snapshot`]——不阻塞 reactor。
    #[must_use]
    pub async fn probe_db_liveness(&self) -> PoolReadiness {
        if self.pool.is_closed() {
            return PoolReadiness::Down;
        }
        let result = tokio::time::timeout(PROBE_READINESS_TIMEOUT, db_select_one(&self.pool)).await;
        probe_timeout_result(result)
    }
}

/// RLS 能力自检的固定探测租户（canonical 非-nil UUID，仅用于 GUC roundtrip；不写任何业务行）。
const RLS_PROBE_TENANT: &str = "00000000-0000-0000-0000-000000000001";
/// durable serving pool 唯一允许的 PostgreSQL role。
const EXPECTED_SERVING_ROLE: &str = "rss_app";

/// 不达标 tenant 表查询：动态派生（含 `tenant_id` 列的 public 表）后逐表判不达标——
/// (a) 缺 `relrowsecurity AND relforcerowsecurity`（ENABLE+FORCE）；或
/// (b) **无**任一 policy 的 `qual` 形如规范谓词 `tenant_id … current_setting … rss.tenant_id`
///     （`LIKE '%tenant_id%current_setting%rss.tenant_id%'` 要求 tenant_id 与 GUC 在谓词内同现、
///     非仅 "提到 GUC"——`USING (true)` 之类宽泛 policy 不满足）；或
/// (c) **存在** allow-all 的 **PERMISSIVE** policy（`qual` normalize 后 ∈ {`true`,`(true)`}）——PostgreSQL
///     permissive policy 默认 OR 合并，额外 allow-all 会放宽 SELECT（F3：拒 OR-widening）。
/// 返回不达标表名。不硬编码表清单。pg_policies.qual 渲染含 `(tenant_id = (current_setting('rss.tenant_id'::text,
/// ..))::uuid)`，与上述 LIKE 对齐（经真实 PG 直证）。**分工**：本 runtime 门守"实际 DB 有规范 tenant policy +
/// 无 widening"；policy DDL 全文规范性（含 `WITH CHECK` 写侧）由静态 `cargo xtask schema-rls`（TENANCY-RLS-FORCE-01）
/// 守，纵深互补（runtime 不重复全量 normalizer——抽共享 normalizer 是 refactor 档 follow-up）。
const OFFENDING_TENANT_TABLES_SQL: &str = "\
SELECT c.relname \
FROM pg_class c \
JOIN pg_namespace n ON n.oid = c.relnamespace \
WHERE n.nspname = 'public' AND c.relkind = 'r' \
  AND EXISTS (SELECT 1 FROM pg_attribute a \
              WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped) \
  AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity \
       OR NOT EXISTS (SELECT 1 FROM pg_policies p \
                      WHERE p.schemaname = 'public' AND p.tablename = c.relname \
                        AND p.qual LIKE '%tenant_id%current_setting%rss.tenant_id%') \
       OR EXISTS (SELECT 1 FROM pg_policies p \
                  WHERE p.schemaname = 'public' AND p.tablename = c.relname \
                    AND p.permissive = 'PERMISSIVE' \
                    AND btrim(lower(coalesce(p.qual, 'true'))) IN ('true', '(true)')))";

/// 当前连接角色及其 RLS 绕过属性。serving pool 必须直连固定 `rss_app`，且不得 superuser/BYPASSRLS。
const CONNECTION_ROLE_SQL: &str = "\
SELECT session_user, current_user, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user";

struct ServingRole {
    session_user: String,
    current_user: String,
    superuser: bool,
    bypass_rls: bool,
}

/// 含 `tenant_id` 列的 public 表总数（anti-vacuity：durable 库应至少有迁移建出的 tenant 表）。
/// 用 `pg_catalog`（非 `information_schema`——后者按当前角色权限过滤，非 superuser serving 角色会漏看
/// 未授权的 tenant 表导致门控盲区；pg_class/pg_attribute 不受权限过滤，确保门看到全部 tenant 表）。
const TENANT_TABLE_COUNT_SQL: &str = "\
SELECT count(*) FROM pg_class c \
JOIN pg_namespace n ON n.oid = c.relnamespace \
WHERE n.nspname = 'public' AND c.relkind = 'r' \
  AND EXISTS (SELECT 1 FROM pg_attribute a \
              WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped)";

impl PgStore {
    /// durable 启动 RLS 能力门（schema 门控，**fail-fast**：缺能力即拒绝启动）。
    ///
    /// 四段校验（任一不过 → `Err`，组合根冒泡使进程不进入服务态）：
    /// 0. **登录会话直连 `rss_app` 且不绕过 RLS**——`session_user = current_user = rss_app`，并且非
    ///    superuser / 非 `BYPASSRLS`（否则 FORCE RLS / policy 全失效，后续校验形同虚设；tenancy.md
    ///    「生产 owner 须为非 superuser」的运行期强制，最先 fail-fast）。
    /// 1. `rss.tenant_id` GUC roundtrip——经统一 funnel [`set_local_tenant`] 注入探测租户后
    ///    `current_setting` 回显比对（验证 GUC 基础设施可用，dogfood funnel）。
    /// 2. anti-vacuity——至少存在一张含 `tenant_id` 列的 tenant 表（否则 schema 未迁移）。
    /// 3. 逐 tenant 表断言 FORCE RLS + 规范 tenant policy + 无 allow-all permissive widening（动态派生，不硬编码）。
    ///
    /// 对标 omicron `DataStore::check_schema_and_access`（对象返回前于构造器级别校验 schema/access；
    /// `ref: oxidecomputer/omicron nexus/db-queries/src/db/datastore/mod.rs@14d89dca`）。偏离：RSS 迁移在
    /// 独立 `run_migrations` 步、不并入本校验的 retry 环。仅供 [`crate::PgRuntimeDeps::setup`] 调用。
    pub(crate) async fn verify_rls_capability(&self) -> Result<(), PgError> {
        // 直线编排：四段校验各为低复杂度 helper（任一 Err 经 `?` 冒泡，tx drop 即 rollback 自检事务）。
        let mut tx = self.pool.begin().await.map_err(PgError::RlsCapability)?;
        ensure_serving_role(&mut tx).await?; // 0. 连接角色必须为 rss_app 且不绕过 RLS（最先 fail-fast）
        verify_tenant_guc_roundtrip(&mut tx).await?; // 1. GUC roundtrip
        ensure_tenant_tables_present(&mut tx).await?; // 2. anti-vacuity
        let offenders = offending_tenant_tables(&mut tx).await?; // 3. 逐表 FORCE RLS + 规范 policy + 无 widening
        // 只读 + SET LOCAL 自检事务无副作用，显式 rollback 释放（失败不覆盖判定，仅 best-effort）。
        let _ = tx.rollback().await;
        ensure_no_offenders(offenders)
    }
}

/// 0. serving 连接必须直连固定 `rss_app`，且不得绕过 RLS（superuser/BYPASSRLS）→ fail-fast。
///    绕过下 FORCE RLS 与 policy 全失效，后续 schema 校验无意义（PostgreSQL ddl-rowsecurity：
///    superuser/BYPASSRLS 永远绕过含 FORCE 的 RLS）。
async fn ensure_serving_role(
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
    ensure_expected_serving_role(&role)?;
    ensure_serving_role_cannot_bypass_rls(&role)?;
    log_serving_role_accepted(&role);
    Ok(())
}

fn ensure_expected_serving_role(role: &ServingRole) -> Result<(), PgError> {
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

fn ensure_serving_role_cannot_bypass_rls(role: &ServingRole) -> Result<(), PgError> {
    if !role.superuser && !role.bypass_rls {
        return Ok(());
    }
    log_serving_role_bypass(role);
    Err(PgError::RlsBypassRole)
}

fn log_serving_role_accepted(role: &ServingRole) {
    tracing::info!(
        target: "postgres",
        session_user = %role.session_user,
        current_user = %role.current_user,
        "rls capability gate: serving role accepted"
    );
}

fn log_serving_role_bypass(role: &ServingRole) {
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

/// 2. anti-vacuity：至少存在一张含 `tenant_id` 列的 tenant 表（否则 schema 未迁移 / 库不符预期）。
async fn ensure_tenant_tables_present(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), PgError> {
    let (n,): (i64,) = sqlx::query_as(TENANT_TABLE_COUNT_SQL)
        .fetch_one(&mut **tx)
        .await
        .map_err(PgError::RlsCapability)?;
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
) -> Result<(), PgError> {
    let probe = TenantId::parse(RLS_PROBE_TENANT).map_err(|_| PgError::RlsGucRoundtrip)?;
    set_local_tenant(tx, probe)
        .await
        .map_err(PgError::RlsCapability)?;
    let (echoed,): (Option<String>,) =
        sqlx::query_as("SELECT current_setting('rss.tenant_id', true)")
            .fetch_one(&mut **tx)
            .await
            .map_err(PgError::RlsCapability)?;
    if echoed.as_deref() == Some(RLS_PROBE_TENANT) {
        Ok(())
    } else {
        Err(PgError::RlsGucRoundtrip)
    }
}

/// 不达标（缺 FORCE RLS / 规范 policy 或存在 allow-all permissive widening）的 tenant 表名列表。
async fn offending_tenant_tables(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<Vec<String>, PgError> {
    let rows: Vec<(String,)> = sqlx::query_as(OFFENDING_TENANT_TABLES_SQL)
        .fetch_all(&mut **tx)
        .await
        .map_err(PgError::RlsCapability)?;
    Ok(rows.into_iter().map(|(t,)| t).collect())
}

impl PgStore {
    /// 建池并连接 postgres：先 fail-fast 校验配置，再 `PgPoolOptions::connect_with`。
    ///
    /// `ref: sqlx sqlx-core/src/pool/options.rs@v0.8.6`。
    ///
    /// `pub(crate)`（#1423，PG-BUNDLE-FUNNEL-01）：唯一公开构造路径是 [`crate::PgRuntimeDeps::setup`]，
    /// 外部不能直接 mint `PgStore`、故拿不到 `&PgStore` 散装构造 repo。
    pub(crate) async fn connect(config: &PgConfig) -> Result<Self, PgError> {
        config.validate()?;
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .acquire_timeout(config.acquire_timeout)
            .connect_with(config.connect_options())
            .await
            .inspect_err(|err| {
                // reason: 连接（持久化）失败在 adapter 边界记 error!，避免仅 `?` 冒泡时日志链断点（observability.md §日志级别）；
                // 第三方 sqlx::Error 经 secure::redact_error 统一脱敏 funnel，杜绝连接串 / 凭据泄漏。
                tracing::error!(
                    target: "postgres",
                    error = %secure::redact_error(err),
                    host = %config.host,
                    database = %config.database,
                    "postgres pool connect failed"
                );
            })
            .map_err(PgError::Connect)?;
        // reason: host/database 是中性运维标识（非租户敏感）。若未来 database 名引入租户标识，须先经
        // secure redaction 清洗再记录——勿在此直接落库名（防漂移护栏）。
        tracing::info!(
            target: "postgres",
            host = %config.host,
            database = %config.database,
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
    // classify_probe_error 单元测试（#1309 F4：三态分类）
    // ---------------------------------------------------------------------------

    /// `PoolTimedOut` → `Saturated`（池饱和，DB 多半正常，降级可服务）。
    #[test]
    fn classify_probe_error_pool_timed_out_is_saturated() {
        assert_eq!(
            super::classify_probe_error(&sqlx::Error::PoolTimedOut),
            PoolReadiness::Saturated,
            "PoolTimedOut → Saturated（池饱和，不摘流）"
        );
    }

    /// `PoolClosed` → `Down`（池已关闭，不可服务）。
    #[test]
    fn classify_probe_error_pool_closed_is_down() {
        assert_eq!(
            super::classify_probe_error(&sqlx::Error::PoolClosed),
            PoolReadiness::Down,
            "PoolClosed → Down"
        );
    }

    /// 查询 / 协议错误 → `Down`（非池状态错误，视为 DB 不可服务）。
    #[test]
    fn classify_probe_error_query_error_is_down() {
        assert_eq!(
            super::classify_probe_error(&sqlx::Error::Protocol("test error".to_string())),
            PoolReadiness::Down,
            "Protocol 错误 → Down"
        );
    }

    // ---------------------------------------------------------------------------
    // probe_db_liveness 失败臂单测（#1309 review T1）
    // ---------------------------------------------------------------------------

    /// `probe_db_liveness` 已关闭 pool 快路径：`is_closed()=true` → `Down`（快路径，不 acquire）。
    ///
    /// 覆盖 `probe_db_liveness` 中的 `is_closed()` 快路径 Down（跨平台可靠）。
    /// 不可达端口路径在 macOS 下被 pf 过滤（无 RST），acquire 超时 → `PoolTimedOut` → `Saturated`；
    /// Down 的 `classify_probe_error` 路径已由 `classify_probe_error_pool_closed_is_down` 直接覆盖。
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
}
