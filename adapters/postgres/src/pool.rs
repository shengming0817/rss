//! postgres 连接池 + adapter 配置 + 错误类型（eventexec 持久化基座，#1116）。
//!
//! `ref: sqlx sqlx-core/src/pool/options.rs@v0.8.6`（`PgPoolOptions` builder + `connect_with`）。

use std::path::PathBuf;
use std::time::Duration;

use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};

use crate::PgStore;

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
        // reason: 密码字段 Debug 恒输出占位常量，杜绝明文泄漏（对齐 secure::aead::Ciphertext 范式）。
        f.write_str("PgPassword(<redacted>)")
    }
}

/// postgres adapter 连接 + 连接池配置——adapter 拥有的稳定配置面，组合根据此构造（无需识 sqlx 类型）。
///
/// 连接参数（host / port / database / username / password）必填经 [`PgConfig::new`]；TLS 模式默认
/// [`DEFAULT_SSL_MODE`]（`VerifyFull`，零信任）、池 tuning 取默认，均经 `with_*` 累加调整。最终由
/// [`PgStore::connect`] 调 [`PgConfig::validate`] fail-fast 校验。
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

    /// 调整连接池上限（累加式 builder；最终由 [`PgStore::connect`] validate）。
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

impl PgStore {
    /// 建池并连接 postgres：先 fail-fast 校验配置，再 `PgPoolOptions::connect_with`。
    ///
    /// `ref: sqlx sqlx-core/src/pool/options.rs@v0.8.6`。
    pub async fn connect(config: &PgConfig) -> Result<Self, PgError> {
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
