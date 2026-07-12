//! 真容器 fixtures（testcontainers 0.27 + testcontainers-modules 0.15）。
//!
//! `env_or_*` resolver 回传**不透明 fixture guard**（`PgFixture` / `RedisFixture` / `RabbitFixture`）：
//! **默认起容器**（fail-closed 安全语义）；仅当满足显式 opt-in 条件时走外部路径：
//! - postgres：`RSS_TEST_ALLOW_EXTERNAL_POSTGRES` 存在（非空）+ 5 元组 `PGHOST/PGPORT/PGDATABASE/PGUSER/PGPASSWORD` 全在；
//! - redis：`REDIS_TEST_URL` 存在且非空；
//! - rabbitmq：`RSS_AMQP_TEST_URL` 存在且非空（须为 base broker URL，无非空 vhost 段；明文仅 loopback）。
//!
//! **严格库名（单源在 testkit）**：外部 postgres 路径的 `PGDATABASE` 须 `ends_with("_test")` 或 `== "test"`
//! 才被接受；不满足直接报错（防 `prod_contest` 这类 substring 误命中）。
//! **guard 须绑定到测试作用域结束**——其 `Drop` 停容器（提前 drop 后续连接失败）。
//! 不透明 guard 把 `testcontainers` 类型挡在消费方签名外（消费方只 name `testkit::{*Fixture,FixtureError}`）。
//!
//! 测试 fixture 不引 tracing——进度 / 失败经 testcontainers 自身日志 + fail-loud 错误冒泡可见
//! （reason: 引入 tracing 会拉 tracing subscriber 依赖、增加测试体初始化负担；container 日志由
//! testcontainers log_driver 自管，错误路径经 FixtureError 直接冒泡到测试输出）。
//!
//! ref: testcontainers/testcontainers-rs-modules-community modules/{postgres,redis,rabbitmq}

use std::collections::{BTreeMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::net::IpAddr;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use testcontainers::ContainerAsync;
use testcontainers::ImageExt;
use testcontainers::core::logs::LogFrame;
use testcontainers::core::{CmdWaitFor, ExecCommand};
use testcontainers_modules::mosquitto::Mosquitto;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::rabbitmq::RabbitMq;
use testcontainers_modules::redis::{REDIS_PORT, Redis};
use url::{Host, Url};

/// fixture 错误（容器起停 / 坐标解析 / env 解析）——dev/test 用，anyhow 以与任意测试返回类型组合。
pub type FixtureError = anyhow::Error;
type Result<T> = std::result::Result<T, FixtureError>;

/// 容器内固定端口（modules 镜像默认暴露端口）。
const PG_PORT: u16 = 5432;
const AMQP_PORT: u16 = 5672;
const MQTT_PORT: u16 = 1883;
/// 容器路径 postgres db 名：含 `test` 以满足 adapters/postgres 毁灭性-DDL 守卫。
const PG_DB: &str = "rss_test";
const PG_USER: &str = "postgres";
const PG_PASSWORD: &str = "postgres";

/// rabbitmqctl exec 有界重试（broker 起后 rabbitmqctl/epmd 短暂不可用窗口）。
const RABBITMQCTL_MAX_ATTEMPTS: u32 = 12;
const RABBITMQCTL_BACKOFF_MS: u64 = 500;

const CI_SCOPE_ENV: &str = "RSS_CI_CONTAINER_SCOPE";
const CI_SHARD_ENV: &str = "RSS_CI_INTEGRATION_SHARD";
const CI_PARTITION_ENV: &str = "RSS_CI_INTEGRATION_PARTITION";
const CI_LOG_DIR_ENV: &str = "RSS_CI_CONTAINER_LOG_DIR";
const CI_CONTEXT_KEYS: &[&str] = &[CI_SCOPE_ENV, CI_SHARD_ENV, CI_PARTITION_ENV, CI_LOG_DIR_ENV];

const CONTAINER_LOG_LIMIT_BYTES: usize = 1024 * 1024;
const CONTAINER_LOG_TRUNCATION_MARKER: &[u8] = b"\n[rss-testkit: log truncated]\n";
static CONTAINER_LOG_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
struct CiContainerContext {
    scope: String,
    shard: String,
    partition: String,
    log_dir: PathBuf,
}

impl CiContainerContext {
    fn from_env() -> Result<Option<Self>> {
        let values = environment_snapshot(CI_CONTEXT_KEYS)?;
        Self::from_lookup(|key| values.get(key).cloned())
    }

    fn from_lookup<F>(lookup: F) -> Result<Option<Self>>
    where
        F: Fn(&str) -> Option<String>,
    {
        let values: BTreeMap<&str, Option<String>> = CI_CONTEXT_KEYS
            .iter()
            .copied()
            .map(|key| (key, lookup(key)))
            .collect();
        if values.values().all(Option::is_none) {
            return Ok(None);
        }

        let missing: Vec<&str> = values
            .iter()
            .filter_map(|(key, value)| value.is_none().then_some(*key))
            .collect();
        if !missing.is_empty() {
            return Err(anyhow::anyhow!(
                "integration container context 不完整，缺少：{}",
                missing.join(", ")
            ));
        }

        let required = |key| {
            values
                .get(key)
                .and_then(Option::as_deref)
                .ok_or_else(|| anyhow::anyhow!("integration container context 缺少 {key}"))
        };
        let scope = required(CI_SCOPE_ENV)?;
        if !is_safe_label_token(scope) {
            return Err(anyhow::anyhow!(
                "{CI_SCOPE_ENV} 含非法字符，须为非空 ASCII 字母数字/./_/-"
            ));
        }
        let shard = required(CI_SHARD_ENV)?;
        if !is_canonical_shard(shard) {
            return Err(anyhow::anyhow!(
                "{CI_SHARD_ENV} 不是 canonical shard，须为小写字母数字及单个 '-' 分隔"
            ));
        }
        let partition = required(CI_PARTITION_ENV)?;
        if !is_canonical_partition(partition) {
            return Err(anyhow::anyhow!(
                "{CI_PARTITION_ENV} 不是 canonical partition（须为 unpartitioned、1/2 或 2/2）"
            ));
        }
        let log_dir = PathBuf::from(required(CI_LOG_DIR_ENV)?);
        if !log_dir.is_absolute()
            || log_dir
                .components()
                .any(|component| matches!(component, Component::ParentDir))
        {
            return Err(anyhow::anyhow!("{CI_LOG_DIR_ENV} 须为不含 '..' 的绝对路径"));
        }

        Ok(Some(Self {
            scope: scope.to_string(),
            shard: shard.to_string(),
            partition: partition.to_string(),
            log_dir,
        }))
    }
}

fn is_safe_label_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn is_canonical_shard(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && !value.ends_with('-')
        && !value.contains("--")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn is_canonical_partition(value: &str) -> bool {
    matches!(value, "unpartitioned" | "1/2" | "2/2")
}

#[derive(Clone, Copy, Debug)]
enum ContainerService {
    Postgres,
    Redis,
    RabbitMq,
    Mosquitto,
}

impl ContainerService {
    fn name(self) -> &'static str {
        match self {
            Self::Postgres => "postgres",
            Self::Redis => "redis",
            Self::RabbitMq => "rabbitmq",
            Self::Mosquitto => "mosquitto",
        }
    }

    fn labels(self, context: &CiContainerContext) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("io.rss.integration.managed".to_string(), "true".to_string()),
            (
                "io.rss.integration.scope".to_string(),
                context.scope.clone(),
            ),
            (
                "io.rss.integration.shard".to_string(),
                context.shard.clone(),
            ),
            (
                "io.rss.integration.partition".to_string(),
                context.partition.clone(),
            ),
            (
                "io.rss.integration.service".to_string(),
                self.name().to_string(),
            ),
        ])
    }
}

#[derive(Clone)]
struct BoundedFileLogConsumer {
    #[cfg(test)]
    path: PathBuf,
    state: Arc<Mutex<BoundedLogState>>,
}

struct BoundedLogState {
    file: File,
    status: File,
    written: usize,
    truncated: bool,
    writer_failed: bool,
}

impl BoundedFileLogConsumer {
    fn new(log_dir: &Path, service: ContainerService) -> Result<Self> {
        Self::new_with_sequence(log_dir, service, &CONTAINER_LOG_SEQUENCE)
    }

    fn new_with_sequence(
        log_dir: &Path,
        service: ContainerService,
        sequence_source: &AtomicU64,
    ) -> Result<Self> {
        let metadata = std::fs::symlink_metadata(log_dir).map_err(|error| {
            anyhow::anyhow!(
                "integration container log directory {} 不存在或不可访问（须先执行 lifecycle prepare）: {error}",
                log_dir.display()
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(anyhow::anyhow!(
                "integration container log directory {} 须为非 symlink 目录",
                log_dir.display()
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(anyhow::anyhow!(
                    "integration container log directory {} 权限须为 private（group/other 位必须为 0）",
                    log_dir.display()
                ));
            }
        }
        loop {
            let sequence = sequence_source.fetch_add(1, Ordering::Relaxed);
            let path = log_dir.join(format!(
                "{}-{}-{sequence}.log",
                service.name(),
                std::process::id()
            ));
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => {
                    let status_path = path.with_extension("status");
                    let status = OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create_new(true)
                        .open(&status_path)
                        .and_then(|mut status| {
                            status.write_all(b"ok\n")?;
                            status.flush()?;
                            Ok(status)
                        });
                    let status = match status {
                        Ok(status) => status,
                        Err(error) => {
                            drop(file);
                            let _ = std::fs::remove_file(&path);
                            return Err(error.into());
                        }
                    };
                    return Ok(Self {
                        #[cfg(test)]
                        path,
                        state: Arc::new(Mutex::new(BoundedLogState {
                            file,
                            status,
                            written: 0,
                            truncated: false,
                            writer_failed: false,
                        })),
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
    }

    #[cfg(test)]
    fn path(&self) -> &Path {
        &self.path
    }

    fn write_frame(&self, frame: &LogFrame) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|error| anyhow::anyhow!("container log mutex poisoned: {error}"))?;
        if state.truncated || state.writer_failed {
            return Ok(());
        }

        if let Err(error) = state.write_frame(frame) {
            state.writer_failed = true;
            let status_error = state.persist_status(b"writer-error\n").err();
            return match status_error {
                Some(status_error) => Err(anyhow::anyhow!(
                    "container log write failed: {error}; persisting writer-error status also failed: {status_error}"
                )),
                None => Err(error.into()),
            };
        }
        Ok(())
    }
}

impl BoundedLogState {
    fn persist_status(&mut self, token: &[u8]) -> std::io::Result<()> {
        self.status.set_len(0)?;
        self.status.seek(SeekFrom::Start(0))?;
        self.status.write_all(token)?;
        self.status.flush()
    }

    fn write_frame(&mut self, frame: &LogFrame) -> std::io::Result<()> {
        let prefix: &[u8] = match frame {
            LogFrame::StdOut(_) => b"[stdout] ",
            LogFrame::StdErr(_) => b"[stderr] ",
        };
        let bytes = frame.bytes();
        let frame_size = prefix.len().saturating_add(bytes.len());
        let payload_limit = CONTAINER_LOG_LIMIT_BYTES - CONTAINER_LOG_TRUNCATION_MARKER.len();
        if self.written.saturating_add(frame_size) <= payload_limit {
            self.file.write_all(prefix)?;
            self.file.write_all(bytes)?;
            self.written += frame_size;
            self.file.flush()?;
            return Ok(());
        }

        let payload_budget = payload_limit.saturating_sub(self.written);
        let prefix_bytes = prefix.len().min(payload_budget);
        self.file.write_all(&prefix[..prefix_bytes])?;
        let body_budget = payload_budget - prefix_bytes;
        self.file
            .write_all(&bytes[..bytes.len().min(body_budget)])?;
        self.file.write_all(CONTAINER_LOG_TRUNCATION_MARKER)?;
        self.written += payload_budget + CONTAINER_LOG_TRUNCATION_MARKER.len();
        self.truncated = true;
        self.file.flush()?;
        Ok(())
    }
}

fn environment_snapshot(keys: &[&str]) -> Result<BTreeMap<String, String>> {
    let mut values = BTreeMap::new();
    for key in keys {
        if let Some(value) = std::env::var_os(key) {
            let value = value
                .into_string()
                .map_err(|_| anyhow::anyhow!("environment variable {key} 不是合法 UTF-8"))?;
            values.insert((*key).to_string(), value);
        }
    }
    Ok(values)
}

fn non_empty_external_value<F>(lookup: F, key: &str) -> Result<Option<String>>
where
    F: Fn(&str) -> Option<String>,
{
    Ok(lookup(key).filter(|value| !value.is_empty()))
}

fn process_external_value(key: &str) -> Result<Option<String>> {
    let values = environment_snapshot(&[key])?;
    non_empty_external_value(|name| values.get(name).cloned(), key)
}

fn validate_redis_url(value: &str) -> Result<()> {
    let parsed = Url::parse(value)
        .map_err(|_| anyhow::anyhow!("REDIS_TEST_URL 不是合法的 absolute Redis URL"))?;
    if !matches!(parsed.scheme(), "redis" | "rediss") {
        return Err(anyhow::anyhow!(
            "REDIS_TEST_URL scheme 须为 redis:// 或 rediss://"
        ));
    }
    if parsed.host().is_none() {
        return Err(anyhow::anyhow!("REDIS_TEST_URL 须包含合法 host"));
    }
    if !matches!(parsed.port(), Some(1..=u16::MAX)) {
        return Err(anyhow::anyhow!(
            "REDIS_TEST_URL 须包含 1..=65535 的显式 port"
        ));
    }
    Ok(())
}

fn postgres_external_params_from_lookup<F>(lookup: F) -> Result<Option<PgConnParams>>
where
    F: Fn(&str) -> Option<String>,
{
    if non_empty_external_value(&lookup, "RSS_TEST_ALLOW_EXTERNAL_POSTGRES")?.is_none() {
        return Ok(None);
    }

    const PG_KEYS: &[&str] = &["PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD"];
    let values: BTreeMap<&str, Option<String>> = PG_KEYS
        .iter()
        .copied()
        .map(|key| (key, lookup(key).filter(|value| !value.is_empty())))
        .collect();
    let missing: Vec<&str> = values
        .iter()
        .filter_map(|(key, value)| value.is_none().then_some(*key))
        .collect();
    if !missing.is_empty() {
        return Err(anyhow::anyhow!(
            "RSS_TEST_ALLOW_EXTERNAL_POSTGRES 已设，但缺少或为空的 PG env：{}（须同时设全 5 元组）",
            missing.join(", ")
        ));
    }
    let required = |key| {
        values
            .get(key)
            .and_then(Option::as_deref)
            .ok_or_else(|| anyhow::anyhow!("external postgres 缺少 {key}"))
    };
    let port_str = required("PGPORT")?;
    let port = port_str
        .parse()
        .map_err(|_| anyhow::anyhow!("PGPORT='{port_str}' 不是合法 u16 端口"))?;
    let database = required("PGDATABASE")?;
    if !strict_test_db_name(database) {
        return Err(anyhow::anyhow!(
            "PGDATABASE='{database}' 须以 '_test' 结尾或精确等于 'test'（严格库名校验，防破坏性 DDL 误打生产库）"
        ));
    }
    Ok(Some(PgConnParams {
        host: required("PGHOST")?.to_string(),
        port,
        database: database.to_string(),
        username: required("PGUSER")?.to_string(),
        password: required("PGPASSWORD")?.to_string(),
    }))
}

mod owned {
    use super::{
        BoundedFileLogConsumer, CiContainerContext, ContainerAsync, ContainerService, ImageExt,
        Result,
    };
    use testcontainers::runners::AsyncRunner;
    use testcontainers::{ContainerRequest, Image};

    pub(super) async fn start<I, T>(
        image: T,
        service: ContainerService,
    ) -> Result<ContainerAsync<I>>
    where
        I: Image,
        T: Into<ContainerRequest<I>> + Send,
    {
        start_with_context(image, service, CiContainerContext::from_env()?).await
    }

    pub(super) async fn start_with_context<I, T>(
        image: T,
        service: ContainerService,
        context: Option<CiContainerContext>,
    ) -> Result<ContainerAsync<I>>
    where
        I: Image,
        T: Into<ContainerRequest<I>> + Send,
    {
        let Some(context) = context else {
            return Ok(image.start().await?);
        };
        let consumer = BoundedFileLogConsumer::new(&context.log_dir, service)?;
        let request = image
            .into()
            .with_labels(service.labels(&context))
            .with_log_consumer(move |frame: &testcontainers::core::logs::LogFrame| {
                if let Err(error) = consumer.write_frame(frame) {
                    eprintln!("failed to persist integration container log: {error}");
                }
            });
        Ok(request.start().await?)
    }
}

/// postgres 连接参数（与 adapters/postgres `config_from_env` 同形）。
/// password 字段 Debug 输出脱敏（输出 `<redacted>`），防日志泄露凭证。
#[derive(Clone)]
pub struct PgConnParams {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub username: String,
    pub password: String,
}

impl std::fmt::Debug for PgConnParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgConnParams")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("database", &self.database)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

// ── postgres ────────────────────────────────────────────────────────────────

/// postgres fixture guard：持容器句柄（自起路径）到 `Drop` + 连接参数。**须绑定到测试结束**。
pub struct PgFixture {
    // 自起路径持句柄（Drop 停容器）；env 路径为 None。
    _container: Option<Box<ContainerAsync<Postgres>>>,
    params: PgConnParams,
}

impl PgFixture {
    /// postgres 连接参数。
    pub fn params(&self) -> &PgConnParams {
        &self.params
    }
}

/// 严格库名校验：`db` 须以 `_test` 结尾或精确等于 `"test"`。
///
/// 设计意图（fail-closed）：防止 `prod_contest`（substring 命中）之类名称绕过校验；
/// 合法测试库名举例：`rss_test`、`x_test`、`test`。
/// 拒绝举例：`prod_contest`、`testdb`、`test_prod`。
pub fn strict_test_db_name(db: &str) -> bool {
    db == "test" || db.ends_with("_test")
}

/// **默认起容器（fail-closed 安全语义）**。
///
/// 仅当 `RSS_TEST_ALLOW_EXTERNAL_POSTGRES` 存在（非空）时走外部 PG 路径，
/// 防止破坏性 DDL 误打外部库；否则一律 self-provision 容器。
///
/// 外部路径校验：
/// - 读全 5 元组 `PGHOST`/`PGPORT`/`PGDATABASE`/`PGUSER`/`PGPASSWORD`，缺哪个就在错误里列出缺失 key；
/// - `PGPORT` 须为合法 u16；
/// - `PGDATABASE` 须 `ends_with("_test")` 或 `== "test"`（严格库名，单源在 testkit）。
///
/// 容器路径 db 名恒为 `rss_test`（满足严格库名规则）。
///
/// # Example
///
/// ```ignore
/// let pg = testkit::env_or_postgres().await?;
/// // pg.params() 返回 PgConnParams { host, port, database, username, password }
/// ```
pub async fn env_or_postgres() -> Result<PgFixture> {
    if process_external_value("RSS_TEST_ALLOW_EXTERNAL_POSTGRES")?.is_some() {
        const PG_KEYS: &[&str] = &["PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD"];
        let values = environment_snapshot(PG_KEYS)?;
        let params = postgres_external_params_from_lookup(|key| {
            if key == "RSS_TEST_ALLOW_EXTERNAL_POSTGRES" {
                Some("true".to_string())
            } else {
                values.get(key).cloned()
            }
        })?
        .ok_or_else(|| anyhow::anyhow!("external postgres opt-in 丢失"))?;
        return Ok(PgFixture {
            _container: None,
            params,
        });
    }
    // 默认：self-provision 容器（fail-closed）。
    // PG 镜像 tag 固定 16-alpine：迁移刻意要求 PG 13+ core（`0003_create_outbox.sql` 用 `gen_random_uuid()`
    // 无 pgcrypto 扩展）；testcontainers-modules `Postgres::default()` 的默认 tag < 13 缺该内置函数，会令
    // run_migrations 在 0002 处 42883 失败。固定 13+ 让容器与迁移的 PG 版本前提对齐（修 latent 测试 harness
    // 漂移：集成 lane opt-in 不入 CI，此前未暴露）。
    let image = Postgres::default()
        .with_db_name(PG_DB)
        .with_user(PG_USER)
        .with_password(PG_PASSWORD)
        .with_tag("16-alpine");
    let container = owned::start(image, ContainerService::Postgres).await?;
    let host = container.get_host().await?.to_string();
    let port = container.get_host_port_ipv4(PG_PORT).await?;
    Ok(PgFixture {
        _container: Some(Box::new(container)),
        params: PgConnParams {
            host,
            port,
            database: PG_DB.to_string(),
            username: PG_USER.to_string(),
            password: PG_PASSWORD.to_string(),
        },
    })
}

// ── redis ─────────────────────────────────────────────────────────────────-

/// redis fixture guard：持容器句柄（自起路径）到 `Drop` + `redis://` URL。**须绑定到测试结束**。
pub struct RedisFixture {
    _container: Option<Box<ContainerAsync<Redis>>>,
    url: String,
}

impl RedisFixture {
    /// `redis://host:port` 连接 URL。
    pub fn url(&self) -> &str {
        &self.url
    }
}

/// `REDIS_TEST_URL` 非空且为带 host/port 的 `redis://` 或 `rediss://` URL → env 路径；
/// 空或未设置 → self-provision 容器，非法非空值 fail-closed。
///
/// # Example
///
/// ```ignore
/// let redis = testkit::env_or_redis().await?;
/// // redis.url() 返回 "redis://host:port"
/// ```
pub async fn env_or_redis() -> Result<RedisFixture> {
    if let Some(url) = process_external_value("REDIS_TEST_URL")? {
        validate_redis_url(&url)?;
        return Ok(RedisFixture {
            _container: None,
            url,
        });
    }
    let container = owned::start(Redis::default(), ContainerService::Redis).await?;
    let host = container.get_host().await?;
    let port = container.get_host_port_ipv4(REDIS_PORT).await?;
    let url = format!("redis://{host}:{port}");
    Ok(RedisFixture {
        _container: Some(Box::new(container)),
        url,
    })
}

// ── rabbitmq ─────────────────────────────────────────────────────────────---

/// rabbitmq fixture guard：持容器句柄（自起路径）到 `Drop`。**须绑定到测试结束**。
/// per-domain vhost 经 [`RabbitFixture::vhost_url`] 按需创建（同容器可建多 vhost，供跨 vhost 隔离测试）。
pub struct RabbitFixture {
    inner: RabbitInner,
}

enum RabbitInner {
    /// 自起容器：持句柄；`vhost_url` 经 rabbitmqctl 在该 broker 建 vhost。
    Container {
        container: Box<ContainerAsync<RabbitMq>>,
        host: String,
        port: u16,
        /// 已建 vhost 缓存（幂等：同一 vhost 多次 `vhost_url` 不重复调 rabbitmqctl）。
        created: Mutex<HashSet<String>>,
    },
    /// env 长存 broker：base url（不含 vhost）；`vhost_url` 直接拼（caller 须已建该 vhost）。
    Env { base: String },
}

impl RabbitFixture {
    /// 取 `vhost` 的连接 URL `amqp://guest:guest@host:port/<vhost>`。自起路径会先在 broker 建该 vhost
    /// （+ 给 guest 授权）；env 路径假定长存 broker 已建该 vhost。`vhost` 须 URL-safe（字母数字 / `_` / `-`）。
    /// 同一 guard 多次调用不同 `vhost` → 同容器多 vhost（per-domain 隔离测试用）。
    /// 同一 `vhost` 多次调用幂等——不重复调 rabbitmqctl（已建则直接返回 URL）。
    pub async fn vhost_url(&self, vhost: &str) -> Result<String> {
        // URL-safe 校验：仅字母数字 / _ / -，防注入 rabbitmqctl 参数。
        if !vhost
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '_' | '-'))
        {
            return Err(anyhow::anyhow!(
                "vhost '{vhost}' 含不安全字符，须字母数字/_/-"
            ));
        }
        match &self.inner {
            RabbitInner::Container {
                container,
                host,
                port,
                created,
            } => {
                // 幂等：已建则跳过（reason: rabbitmqctl add_vhost 重入会报 already exists；
                // HashSet 缓存避免重复调用，同时省重试开销）。
                let already = {
                    let guard = created
                        .lock()
                        .map_err(|e| anyhow::anyhow!("vhost cache mutex poisoned: {e}"))?;
                    guard.contains(vhost)
                };
                if !already {
                    create_vhost(container, vhost).await?;
                    created
                        .lock()
                        .map_err(|e| anyhow::anyhow!("vhost cache mutex poisoned: {e}"))?
                        .insert(vhost.to_string());
                }
                Ok(format!("amqp://guest:guest@{host}:{port}/{vhost}"))
            }
            RabbitInner::Env { base } => Ok(amqp_url_with_vhost(base, vhost)),
        }
    }
}

/// 校验 AMQP base broker URL（无非空 vhost 段）。
///
/// 合法：`amqps://user:pass@host:port`、`amqp://user:pass@127.0.0.1:port`。
/// 拒绝：`amqp://host:5672`（non-loopback 明文）、`amqp://host:5672/existing_vhost`（含非空 path/vhost 段）。
///
/// `RSS_AMQP_TEST_URL` 须为 base broker URL，vhost 由 testkit 拼接/预建。
fn validate_amqp_base_url(url: &str) -> Result<()> {
    let parsed = Url::parse(url)
        .map_err(|_| anyhow::anyhow!("RSS_AMQP_TEST_URL 不是合法 URL，实际: {url}"))?;
    match parsed.scheme() {
        "amqps" => {}
        "amqp" if is_loopback_url_host(&parsed) => {}
        "amqp" => {
            return Err(anyhow::anyhow!(
                "RSS_AMQP_TEST_URL 明文 amqp:// 仅允许 loopback host；外部长存 broker 须使用 amqps://"
            ));
        }
        _ => {
            return Err(anyhow::anyhow!(
                "RSS_AMQP_TEST_URL 须为 amqps:// 或 loopback amqp://，实际: {url}"
            ));
        }
    }
    if parsed.host().is_none() {
        return Err(anyhow::anyhow!("RSS_AMQP_TEST_URL 须包含 host"));
    }
    let path_has_vhost = !parsed.path().trim_matches('/').is_empty();
    if path_has_vhost {
        return Err(anyhow::anyhow!(
            "RSS_AMQP_TEST_URL='{}' 含非空 path/vhost 段 '{}'——须为 base broker URL（无 vhost），\
             vhost 由 testkit 在测试用 fixture 中拼接/预建",
            url,
            parsed.path().trim_start_matches('/')
        ));
    }
    Ok(())
}

fn is_loopback_url_host(parsed: &Url) -> bool {
    match parsed.host() {
        Some(Host::Domain(host)) => {
            host.eq_ignore_ascii_case("localhost")
                || host.parse::<IpAddr>().is_ok_and(|addr| addr.is_loopback())
        }
        Some(Host::Ipv4(addr)) => addr.is_loopback(),
        Some(Host::Ipv6(addr)) => addr.is_loopback(),
        None => false,
    }
}

/// **默认起容器（fail-closed 安全语义）**。仅当 `RSS_AMQP_TEST_URL` 非空时走外部 broker 路径。
///
/// 外部路径：`RSS_AMQP_TEST_URL` 须为 **base broker URL（无 path/vhost 段）**，如
/// `amqps://user:pass@host:port` 或 loopback `amqp://user:pass@127.0.0.1:port`；含非空 vhost 段则报错。
/// vhost 由 testkit 在 `vhost_url()` 中拼接；env 路径假定 broker 已预建该 vhost（caller 负责）。
///
/// # Example
///
/// ```ignore
/// let rabbit = testkit::env_or_rabbitmq().await?;
/// let url = rabbit.vhost_url("rss_identity").await?;
/// // url = "amqp://guest:guest@host:port/rss_identity"
/// ```
pub async fn env_or_rabbitmq() -> Result<RabbitFixture> {
    if let Some(base) = process_external_value("RSS_AMQP_TEST_URL")? {
        validate_amqp_base_url(&base)?;
        return Ok(RabbitFixture {
            inner: RabbitInner::Env { base },
        });
    }
    let container = owned::start(RabbitMq::default(), ContainerService::RabbitMq).await?;
    let host = container.get_host().await?.to_string();
    let port = container.get_host_port_ipv4(AMQP_PORT).await?;
    Ok(RabbitFixture {
        inner: RabbitInner::Container {
            container: Box::new(container),
            host,
            port,
            created: Mutex::new(HashSet::new()),
        },
    })
}

/// 在运行中的 rabbitmq 容器内建 `vhost` + 给默认 `guest` 用户全权限（per-domain 隔离）。
async fn create_vhost(container: &ContainerAsync<RabbitMq>, vhost: &str) -> Result<()> {
    run_rabbitmqctl(container, &["await_startup"]).await?;
    run_rabbitmqctl(container, &["add_vhost", vhost]).await?;
    run_rabbitmqctl(
        container,
        &["set_permissions", "-p", vhost, "guest", ".*", ".*", ".*"],
    )
    .await?;
    Ok(())
}

/// 给定 base broker URL（`amqps://user:pass@host:port` 或 loopback `amqp://...`）+ vhost 拼出完整 URL（env 路径用）。
fn amqp_url_with_vhost(base: &str, vhost: &str) -> String {
    format!("{}/{vhost}", base.trim_end_matches('/'))
}

/// 容器内执行 `rabbitmqctl <args>`，有界重试（broker 起后 rabbitmqctl 短暂不可用）。
/// 末次 attempt 失败后不再 sleep（节省约 6s 空等）。
/// 错误消息含累计约等待时长以便诊断。
async fn run_rabbitmqctl(container: &ContainerAsync<RabbitMq>, args: &[&str]) -> Result<()> {
    let cmd: Vec<String> = std::iter::once("rabbitmqctl")
        .chain(args.iter().copied())
        .map(str::to_string)
        .collect();
    let mut last: Option<i64> = None;
    for attempt in 0..RABBITMQCTL_MAX_ATTEMPTS {
        let res = container
            .exec(ExecCommand::new(cmd.clone()).with_cmd_ready_condition(CmdWaitFor::exit_code(0)))
            .await?;
        let code = res.exit_code().await?;
        if code == Some(0) {
            return Ok(());
        }
        last = code;
        // 末次失败不再 sleep，直接报错（省末次空等约 6s）。
        if attempt + 1 < RABBITMQCTL_MAX_ATTEMPTS {
            tokio::time::sleep(Duration::from_millis(
                RABBITMQCTL_BACKOFF_MS * u64::from(attempt + 1),
            ))
            .await;
        }
    }
    let total_wait_secs: u64 = (0..RABBITMQCTL_MAX_ATTEMPTS - 1)
        .map(|i| RABBITMQCTL_BACKOFF_MS * u64::from(i + 1))
        .sum::<u64>()
        / 1000;
    Err(anyhow::anyhow!(
        "rabbitmqctl {args:?} 未在 {RABBITMQCTL_MAX_ATTEMPTS} 次（累计约 {total_wait_secs}s）内成功（末次 exit={last:?}）"
    ))
}

// ── mqtt（mosquitto）─────────────────────────────────────────────────────────

/// mqtt fixture guard：持容器句柄（自起路径）到 `Drop` + `mqtt://` base URL。**须绑定到测试结束**。
///
/// MQTT **无 vhost**（不同于 rabbitmq）——跨域隔离经 per-domain broker 凭据 + broker 侧 ACL（operator
/// provision），非命名空间段。故 fixture 只回 base broker URL（无 `vhost_url`），比 [`RabbitFixture`] 简单。
pub struct MqttFixture {
    _container: Option<Box<ContainerAsync<Mosquitto>>>,
    url: String,
}

impl MqttFixture {
    /// `mqtt://host:port` 连接 URL（明文；mosquitto fixture 镜像 anonymous，无凭据段）。
    pub fn url(&self) -> &str {
        &self.url
    }
}

/// 校验 MQTT test URL scheme（须 `mqtt://`——明文，adapter v1 仅支持明文；`mqtts://` / 非 mqtt 协议拒绝）。
///
/// 对齐 [`validate_amqp_base_url`] 的对称 scheme 校验：防 `RSS_MQTT_TEST_URL` 误设非 mqtt 协议在集成测试
/// 中产生难诊断的连接错误。
fn validate_mqtt_url(url: &str) -> Result<()> {
    if url.strip_prefix("mqtt://").is_none() {
        return Err(anyhow::anyhow!(
            "RSS_MQTT_TEST_URL 须以 mqtt:// 开头（adapter v1 仅明文 MQTT），实际: {url}"
        ));
    }
    Ok(())
}

/// **默认起容器（fail-closed 安全语义）**。仅当 `RSS_MQTT_TEST_URL` 非空时走外部 broker 路径。
///
/// 自起路径用 `testcontainers_modules::mosquitto::Mosquitto`（`eclipse-mosquitto`，anonymous，1883）。
/// 外部路径：`RSS_MQTT_TEST_URL` 须为 `mqtt://` base URL（caller 负责 broker 可达 / 鉴权）。
///
/// # Example
///
/// ```ignore
/// let mqtt = testkit::env_or_mosquitto().await?;
/// // mqtt.url() 返回 "mqtt://host:port"
/// ```
pub async fn env_or_mosquitto() -> Result<MqttFixture> {
    if let Some(url) = process_external_value("RSS_MQTT_TEST_URL")? {
        validate_mqtt_url(&url)?;
        return Ok(MqttFixture {
            _container: None,
            url,
        });
    }
    let container = owned::start(Mosquitto::default(), ContainerService::Mosquitto).await?;
    let host = container.get_host().await?.to_string();
    let port = container.get_host_port_ipv4(MQTT_PORT).await?;
    let url = format!("mqtt://{host}:{port}");
    Ok(MqttFixture {
        _container: Some(Box::new(container)),
        url,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    // reason: test setup and assertions use expect/expect_err to retain precise failure context.

    use super::*;

    use std::collections::{BTreeMap, HashMap};
    use std::path::PathBuf;

    use testcontainers::core::logs::LogFrame;

    fn lookup<'a>(
        values: &'a [(&'static str, &'static str)],
    ) -> impl Fn(&str) -> Option<String> + 'a {
        move |key| {
            values
                .iter()
                .find_map(|(candidate, value)| (*candidate == key).then(|| (*value).to_string()))
        }
    }

    fn unique_test_dir(case: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "rss-testkit-{case}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ))
    }

    fn create_private_test_dir(path: &Path) {
        std::fs::create_dir_all(path).expect("test log directory must be creatable");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
                .expect("test log directory must be private");
        }
    }

    /// INVARIANT: INTEGRATION-CONTAINER-CONTEXT-01 { level = "Medium", exec = "manual/opt-in", source = "code", synthetic_red = "ci_container_context_rejects_every_partial_environment_shape", anti_vacuity = "ci_container_context_accepts_complete_or_fully_absent_environment" } — CI context is all-or-nothing:
    /// a complete context constructs the typed value, while no context is the explicit local mode.
    #[test]
    fn ci_container_context_accepts_complete_or_fully_absent_environment() {
        let complete = [
            (
                "RSS_CI_CONTAINER_SCOPE",
                "rss-9001-2-event-transport-1-of-2",
            ),
            ("RSS_CI_INTEGRATION_SHARD", "event-transport"),
            ("RSS_CI_INTEGRATION_PARTITION", "1/2"),
            ("RSS_CI_CONTAINER_LOG_DIR", "/tmp/rss-integration-9001-2"),
        ];

        let context = CiContainerContext::from_lookup(lookup(&complete))
            .expect("complete CI context must parse")
            .expect("complete CI context must select managed mode");
        assert_eq!(context.scope, "rss-9001-2-event-transport-1-of-2");
        assert_eq!(context.shard, "event-transport");
        assert_eq!(context.partition, "1/2");
        assert_eq!(
            context.log_dir,
            PathBuf::from("/tmp/rss-integration-9001-2")
        );

        assert!(
            CiContainerContext::from_lookup(lookup(&[]))
                .expect("fully absent context is valid local mode")
                .is_none(),
            "fully absent CI context must retain hermetic local mode"
        );
    }

    /// Partial context fails closed rather
    /// than silently launching an unowned container in CI.
    #[test]
    fn ci_container_context_rejects_every_partial_environment_shape() {
        let all = [
            (
                "RSS_CI_CONTAINER_SCOPE",
                "rss-9001-2-postgres-domain-unpartitioned",
            ),
            ("RSS_CI_INTEGRATION_SHARD", "postgres-domain"),
            ("RSS_CI_INTEGRATION_PARTITION", "unpartitioned"),
            ("RSS_CI_CONTAINER_LOG_DIR", "/tmp/rss-integration-9001-2"),
        ];

        for missing in all.map(|(key, _)| key) {
            let partial: Vec<_> = all
                .iter()
                .copied()
                .filter(|(key, _)| *key != missing)
                .collect();
            let error = CiContainerContext::from_lookup(lookup(&partial))
                .expect_err("partial CI context must fail closed");
            assert!(
                error.to_string().contains(missing),
                "error must identify missing {missing}: {error}"
            );
        }
    }

    /// Label and filesystem inputs reject
    /// control characters, traversal and malformed canonical partition values.
    #[test]
    fn ci_container_context_rejects_invalid_scope_shard_partition_and_log_dir() {
        let invalid_cases = [
            (
                "scope control character",
                [
                    ("RSS_CI_CONTAINER_SCOPE", "rss-9001\nforged"),
                    ("RSS_CI_INTEGRATION_SHARD", "postgres-domain"),
                    ("RSS_CI_INTEGRATION_PARTITION", "unpartitioned"),
                    ("RSS_CI_CONTAINER_LOG_DIR", "/tmp/rss-integration"),
                ],
            ),
            (
                "shard traversal",
                [
                    ("RSS_CI_CONTAINER_SCOPE", "rss-9001-2-postgres-domain"),
                    ("RSS_CI_INTEGRATION_SHARD", "../postgres-domain"),
                    ("RSS_CI_INTEGRATION_PARTITION", "unpartitioned"),
                    ("RSS_CI_CONTAINER_LOG_DIR", "/tmp/rss-integration"),
                ],
            ),
            (
                "non-canonical partition",
                [
                    ("RSS_CI_CONTAINER_SCOPE", "rss-9001-2-event-transport"),
                    ("RSS_CI_INTEGRATION_SHARD", "event-transport"),
                    ("RSS_CI_INTEGRATION_PARTITION", "01/02"),
                    ("RSS_CI_CONTAINER_LOG_DIR", "/tmp/rss-integration"),
                ],
            ),
            (
                "relative log directory",
                [
                    ("RSS_CI_CONTAINER_SCOPE", "rss-9001-2-postgres-domain"),
                    ("RSS_CI_INTEGRATION_SHARD", "postgres-domain"),
                    ("RSS_CI_INTEGRATION_PARTITION", "unpartitioned"),
                    ("RSS_CI_CONTAINER_LOG_DIR", "target/container-logs"),
                ],
            ),
        ];

        for (case, values) in invalid_cases {
            assert!(
                CiContainerContext::from_lookup(lookup(&values)).is_err(),
                "{case} must fail closed"
            );
        }
    }

    /// Workflow and Rust share an exact closed partition vocabulary. General-looking
    /// fractions are rejected even when numerically well formed.
    #[test]
    fn canonical_integration_partition_is_an_exact_closed_set() {
        for accepted in ["unpartitioned", "1/2", "2/2"] {
            assert!(
                is_canonical_partition(accepted),
                "workflow partition {accepted} must be accepted"
            );
        }
        for rejected in ["", "1/1", "1/3", "2/3", "01/02", "0/2", "3/2"] {
            assert!(
                !is_canonical_partition(rejected),
                "out-of-contract partition {rejected} must fail closed"
            );
        }
    }

    #[test]
    fn invalid_partition_error_lists_the_exact_closed_vocabulary() {
        let values = [
            ("RSS_CI_CONTAINER_SCOPE", "rss-9001-2-event-transport"),
            ("RSS_CI_INTEGRATION_SHARD", "event-transport"),
            ("RSS_CI_INTEGRATION_PARTITION", "1/3"),
            ("RSS_CI_CONTAINER_LOG_DIR", "/tmp/rss-integration"),
        ];

        let error = CiContainerContext::from_lookup(lookup(&values))
            .expect_err("out-of-contract partition must fail closed");
        assert_eq!(
            error.to_string(),
            "RSS_CI_INTEGRATION_PARTITION 不是 canonical partition（须为 unpartitioned、1/2 或 2/2）"
        );
    }

    /// `INTEGRATION-CONTAINER-OWNERSHIP-01` 的正向行为证明：闭合 service enum 产出精确
    /// ownership labels；正式 Medium/verify 声明与 synthetic-red 位于 xtask。
    #[test]
    fn container_service_emits_exact_managed_scope_labels() {
        let values = [
            (
                "RSS_CI_CONTAINER_SCOPE",
                "rss-9001-2-event-transport-1-of-2",
            ),
            ("RSS_CI_INTEGRATION_SHARD", "event-transport"),
            ("RSS_CI_INTEGRATION_PARTITION", "1/2"),
            ("RSS_CI_CONTAINER_LOG_DIR", "/tmp/rss-integration-9001-2"),
        ];
        let context = CiContainerContext::from_lookup(lookup(&values))
            .expect("context must parse")
            .expect("context must be managed");

        for (service, expected_name) in [
            (ContainerService::Postgres, "postgres"),
            (ContainerService::Redis, "redis"),
            (ContainerService::RabbitMq, "rabbitmq"),
            (ContainerService::Mosquitto, "mosquitto"),
        ] {
            let expected = BTreeMap::from([
                ("io.rss.integration.managed".to_string(), "true".to_string()),
                (
                    "io.rss.integration.scope".to_string(),
                    "rss-9001-2-event-transport-1-of-2".to_string(),
                ),
                (
                    "io.rss.integration.shard".to_string(),
                    "event-transport".to_string(),
                ),
                (
                    "io.rss.integration.partition".to_string(),
                    "1/2".to_string(),
                ),
                (
                    "io.rss.integration.service".to_string(),
                    expected_name.to_string(),
                ),
            ]);
            assert_eq!(service.labels(&context), expected);
        }
    }

    /// INVARIANT: INTEGRATION-CONTAINER-LOG-01 { level = "Medium", exec = "manual/opt-in", source = "code", synthetic_red = "bounded_log_consumer_truncates_at_one_mib_with_marker", anti_vacuity = "bounded_log_consumer_uses_unique_names_and_source_prefixes" } — each container gets a collision-free
    /// service-pid-sequence file and every frame retains its Docker stream source.
    #[test]
    fn bounded_log_consumer_uses_unique_names_and_source_prefixes() {
        let dir = unique_test_dir("log-prefix");
        create_private_test_dir(&dir);
        let first = BoundedFileLogConsumer::new(&dir, ContainerService::Postgres)
            .expect("first consumer must construct");
        let second = BoundedFileLogConsumer::new(&dir, ContainerService::Postgres)
            .expect("second consumer must construct");

        assert_ne!(
            first.path(),
            second.path(),
            "sequence must prevent collisions"
        );
        let expected_prefix = format!("postgres-{}-", std::process::id());
        for path in [first.path(), second.path()] {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .expect("log name must be UTF-8");
            assert!(
                name.starts_with(&expected_prefix),
                "unexpected name: {name}"
            );
            assert!(name.ends_with(".log"), "unexpected name: {name}");
        }

        first
            .write_frame(&LogFrame::StdOut(b"ready\n".to_vec().into()))
            .expect("stdout frame must persist");
        first
            .write_frame(&LogFrame::StdErr(b"warning\n".to_vec().into()))
            .expect("stderr frame must persist");
        let output = std::fs::read_to_string(first.path()).expect("persisted log must be readable");
        assert!(
            output.contains("[stdout] ready\n"),
            "stdout source lost: {output:?}"
        );
        assert!(
            output.contains("[stderr] warning\n"),
            "stderr source lost: {output:?}"
        );

        std::fs::remove_dir_all(dir).expect("test log directory cleanup must succeed");
    }

    /// Persisted logs, including the explicit
    /// truncation marker, never exceed the one MiB per-container budget.
    #[test]
    fn bounded_log_consumer_truncates_at_one_mib_with_marker() {
        let dir = unique_test_dir("log-limit");
        create_private_test_dir(&dir);
        let consumer = BoundedFileLogConsumer::new(&dir, ContainerService::Redis)
            .expect("consumer must construct");

        let oversized = vec![b'x'; CONTAINER_LOG_LIMIT_BYTES + 4096];
        consumer
            .write_frame(&LogFrame::StdOut(oversized.into()))
            .expect("oversized frame must be bounded, not rejected");
        consumer
            .write_frame(&LogFrame::StdErr(b"must-not-grow-file".to_vec().into()))
            .expect("frames after truncation must be ignored successfully");

        let bytes = std::fs::read(consumer.path()).expect("persisted log must be readable");
        assert!(
            bytes.len() <= 1024 * 1024,
            "log exceeded one MiB: {} bytes",
            bytes.len()
        );
        assert!(
            bytes.ends_with(CONTAINER_LOG_TRUNCATION_MARKER),
            "bounded log must end with the explicit truncation marker"
        );

        let boundary = BoundedFileLogConsumer::new(&dir, ContainerService::RabbitMq)
            .expect("boundary consumer must construct");
        let payload_limit = CONTAINER_LOG_LIMIT_BYTES - CONTAINER_LOG_TRUNCATION_MARKER.len();
        let almost_full = vec![b'y'; payload_limit - b"[stdout] ".len() - 5];
        boundary
            .write_frame(&LogFrame::StdOut(almost_full.into()))
            .expect("first near-limit frame must persist without truncation");
        boundary
            .write_frame(&LogFrame::StdErr(b"overflow".to_vec().into()))
            .expect("second frame crossing the payload budget must append the marker");
        let boundary_bytes = std::fs::read(boundary.path()).expect("boundary log must be readable");
        assert_eq!(
            boundary_bytes.len(),
            CONTAINER_LOG_LIMIT_BYTES,
            "late truncation must still stay within one MiB"
        );
        assert!(boundary_bytes.ends_with(CONTAINER_LOG_TRUNCATION_MARKER));

        std::fs::remove_dir_all(dir).expect("test log directory cleanup must succeed");
    }

    /// A pre-existing candidate is never overwritten: create_new retries the next sequence.
    #[test]
    fn bounded_log_consumer_retries_a_preoccupied_filename() {
        let dir = unique_test_dir("log-preoccupied");
        create_private_test_dir(&dir);
        let sequence = AtomicU64::new(7);
        let occupied = dir.join(format!("postgres-{}-7.log", std::process::id()));
        std::fs::write(&occupied, b"pre-existing\n").expect("occupied fixture must be writable");

        let consumer =
            BoundedFileLogConsumer::new_with_sequence(&dir, ContainerService::Postgres, &sequence)
                .expect("consumer must retry after create_new collision");

        assert_eq!(
            consumer.path(),
            dir.join(format!("postgres-{}-8.log", std::process::id()))
        );
        assert_eq!(
            std::fs::read(&occupied).expect("occupied fixture must remain readable"),
            b"pre-existing\n"
        );
        std::fs::remove_dir_all(dir).expect("test log directory cleanup must succeed");
    }

    #[test]
    fn bounded_log_consumer_persists_writer_error_status_on_first_io_failure() {
        let dir = unique_test_dir("log-writer-error");
        create_private_test_dir(&dir);
        let consumer = BoundedFileLogConsumer::new(&dir, ContainerService::Redis)
            .expect("consumer must construct");
        let status_path = consumer.path().with_extension("status");

        // A read-only descriptor deterministically rejects write_all without relying on disk state.
        let read_only = File::open(consumer.path()).expect("log fixture must reopen read-only");
        consumer
            .state
            .lock()
            .expect("writer state mutex must remain healthy")
            .file = read_only;
        assert!(
            consumer
                .write_frame(&LogFrame::StdOut(b"must-fail\n".to_vec().into()))
                .is_err(),
            "read-only descriptor must reproduce the writer failure"
        );
        assert_eq!(
            std::fs::read_to_string(&status_path)
                .expect("writer failure must remain machine-readable after stderr is lost"),
            "writer-error\n"
        );

        std::fs::remove_dir_all(dir).expect("test log directory cleanup must succeed");
    }

    #[test]
    fn bounded_log_consumer_requires_a_prepared_private_real_directory() {
        let missing = unique_test_dir("log-missing");
        assert!(
            BoundedFileLogConsumer::new(&missing, ContainerService::Redis).is_err(),
            "consumer must not create lifecycle directories"
        );

        let public = unique_test_dir("log-public");
        std::fs::create_dir_all(&public).expect("public fixture must be creatable");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            std::fs::set_permissions(&public, std::fs::Permissions::from_mode(0o755))
                .expect("public fixture permissions must be settable");
            assert!(
                BoundedFileLogConsumer::new(&public, ContainerService::Redis).is_err(),
                "consumer must reject group/other-accessible directories"
            );
        }
        std::fs::remove_dir_all(public).expect("test log directory cleanup must succeed");

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let real = unique_test_dir("log-real");
            let link = unique_test_dir("log-symlink");
            create_private_test_dir(&real);
            symlink(&real, &link).expect("log directory symlink fixture must be creatable");
            assert!(
                BoundedFileLogConsumer::new(&link, ContainerService::Redis).is_err(),
                "consumer must reject a symlinked log directory"
            );
            std::fs::remove_file(link).expect("symlink fixture cleanup must succeed");
            std::fs::remove_dir_all(real).expect("real directory fixture cleanup must succeed");
        }
    }

    #[test]
    fn redis_external_url_requires_supported_scheme_host_and_explicit_port() {
        for accepted in [
            "redis://localhost:6379",
            "rediss://cache.example.test:6380/0",
            "redis://[::1]:6379",
        ] {
            assert!(
                validate_redis_url(accepted).is_ok(),
                "valid Redis URL rejected: {accepted}"
            );
        }
        for rejected in [
            "",
            "localhost:6379",
            "http://localhost:6379",
            "redis://localhost",
            "redis://:6379",
            "redis://localhost:0",
            "redis://localhost:70000",
        ] {
            assert!(
                validate_redis_url(rejected).is_err(),
                "invalid Redis URL accepted: {rejected}"
            );
        }
    }

    /// Empty external-service variables are absence, never an opt-in. This pure decision
    /// test covers all four resolvers without starting Docker.
    #[test]
    fn empty_external_environment_values_select_self_provision() {
        for key in [
            "RSS_TEST_ALLOW_EXTERNAL_POSTGRES",
            "REDIS_TEST_URL",
            "RSS_AMQP_TEST_URL",
            "RSS_MQTT_TEST_URL",
        ] {
            assert_eq!(
                non_empty_external_value(lookup(&[(key, "")]), key)
                    .expect("UTF-8 test value must parse"),
                None,
                "empty {key} must select self-provision"
            );
        }
    }

    /// A non-empty postgres opt-in with any missing member of the five-value tuple fails
    /// closed and reports every missing key before any network or container operation.
    #[test]
    fn partial_non_empty_postgres_external_environment_fails_closed() {
        let partial = HashMap::from([
            ("RSS_TEST_ALLOW_EXTERNAL_POSTGRES", "1"),
            ("PGHOST", "127.0.0.1"),
            ("PGPORT", "5432"),
            ("PGDATABASE", "rss_test"),
        ]);
        let error = postgres_external_params_from_lookup(|key| {
            partial.get(key).map(|value| (*value).to_string())
        })
        .expect_err("partial external postgres tuple must fail closed");
        let message = error.to_string();
        assert!(
            message.contains("PGUSER"),
            "missing PGUSER not reported: {message}"
        );
        assert!(
            message.contains("PGPASSWORD"),
            "missing PGPASSWORD not reported: {message}"
        );
    }

    /// amqp URL 拼 vhost：去重尾 `/` 后追加，env 路径正确性（不依赖容器）。
    #[test]
    fn amqp_url_with_vhost_appends_after_trimming_slash() {
        assert_eq!(
            amqp_url_with_vhost("amqp://guest:guest@h:5672", "rss_a"),
            "amqp://guest:guest@h:5672/rss_a"
        );
        assert_eq!(
            amqp_url_with_vhost("amqp://guest:guest@h:5672/", "rss_b"),
            "amqp://guest:guest@h:5672/rss_b"
        );
    }

    /// PgConnParams Debug 脱敏：password 输出 `<redacted>`，不泄露凭证。
    #[test]
    fn pg_conn_params_debug_redacts_password() {
        let p = PgConnParams {
            host: "localhost".to_string(),
            port: 5432,
            database: "rss_test".to_string(),
            username: "postgres".to_string(),
            password: "s3cr3t".to_string(),
        };
        let s = format!("{p:?}");
        assert!(s.contains("<redacted>"), "Debug 须含 <redacted>: {s}");
        assert!(!s.contains("s3cr3t"), "Debug 不得含明文密码: {s}");
    }

    /// vhost URL-safe 校验：含不安全字符返回 Err。
    #[test]
    #[allow(clippy::unwrap_used)]
    // reason: 测试体构造 tokio runtime 辅助调 async fn；runtime build 失败属 programmer error，panic 正当。
    fn vhost_url_rejects_unsafe_chars() {
        let fixture = RabbitFixture {
            inner: RabbitInner::Env {
                base: "amqp://guest:guest@h:5672".to_string(),
            },
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let result = rt.block_on(fixture.vhost_url("bad/vhost"));
        assert!(result.is_err(), "含 / 须报错");
        let result2 = rt.block_on(fixture.vhost_url("good-vhost_1"));
        // env 路径无容器，直接拼 URL，不报错（URL-safe）。
        assert!(result2.is_ok(), "合法 vhost 须 Ok");
    }

    /// strict_test_db_name：合法测试库名通过，非测试库名拒绝。
    /// 表驱动覆盖 ends_with("_test") / "test" 精确匹配 / substring 误命中 / 尾缀不符。
    #[test]
    fn strict_test_db_name_table() {
        // 通：以 _test 结尾
        assert!(strict_test_db_name("rss_test"), "rss_test 须通");
        assert!(strict_test_db_name("x_test"), "x_test 须通");
        // 通：精确 "test"
        assert!(strict_test_db_name("test"), "test 须通");
        // 拒：prod 中含 test 但不以 _test 结尾
        assert!(!strict_test_db_name("prod_contest"), "prod_contest 须拒");
        // 拒：以 test 开头但不是 "test" 也不以 _test 结尾
        assert!(!strict_test_db_name("testdb"), "testdb 须拒");
        // 拒：test 在前但以 _prod 结尾
        assert!(!strict_test_db_name("test_prod"), "test_prod 须拒");
    }

    /// validate_mqtt_url：mqtt:// 通过；非 mqtt 协议（http/mqtts）拒绝。
    #[test]
    fn validate_mqtt_url_table() {
        assert!(validate_mqtt_url("mqtt://h:1883").is_ok(), "mqtt:// 须通");
        assert!(
            validate_mqtt_url("mqtt://user:pass@h:1883").is_ok(),
            "含凭据 mqtt:// 须通"
        );
        assert!(
            validate_mqtt_url("mqtts://h:8883").is_err(),
            "mqtts:// 须拒（adapter v1 仅明文）"
        );
        assert!(
            validate_mqtt_url("http://h:1883").is_err(),
            "非 mqtt 协议须拒"
        );
    }

    /// validate_amqp_base_url：base URL（无 vhost）通过；含非空 vhost 段报错。
    #[test]
    fn validate_amqp_base_url_table() {
        // 通：无 path 段
        assert!(
            validate_amqp_base_url("amqp://guest:guest@127.0.0.1:5672").is_ok(),
            "loopback 无 path 须通"
        );
        // 通：尾部空 path（/）
        assert!(
            validate_amqp_base_url("amqp://guest:guest@127.0.0.1:5672/").is_ok(),
            "loopback 尾 / 须通"
        );
        // 拒：外部长存 broker 不允许 non-loopback 明文。
        assert!(
            validate_amqp_base_url("amqp://guest:guest@h:5672").is_err(),
            "non-loopback 明文外部 broker 须拒"
        );
        // 拒：含非空 vhost 段
        assert!(
            validate_amqp_base_url("amqp://guest:guest@h:5672/existing_vhost").is_err(),
            "含 vhost 须拒"
        );
        // 通：loopback 明文保留给本地 fixture。
        assert!(
            validate_amqp_base_url("amqp://guest:guest@127.0.0.1:5672").is_ok(),
            "loopback 明文 fixture 须通"
        );
        // 通：amqps 协议
        assert!(
            validate_amqp_base_url("amqps://user:pass@host:5671").is_ok(),
            "amqps 无 path 须通"
        );
        // 拒：非 amqp 协议
        assert!(
            validate_amqp_base_url("http://h:5672").is_err(),
            "非 amqp 协议须拒"
        );
    }

    #[cfg(feature = "integration")]
    #[tokio::test]
    async fn real_redis_lifecycle_preserves_cross_scope_canary() {
        use std::process::{Command, Output};

        struct Canary(String);
        impl Drop for Canary {
            fn drop(&mut self) {
                let _ = Command::new("docker")
                    .args(["rm", "-fv", self.0.as_str()])
                    .output();
            }
        }

        fn run(program: &str, args: &[&str]) -> Output {
            Command::new(program)
                .args(args)
                .output()
                .unwrap_or_else(|error| panic!("failed to run {program}: {error}"))
        }
        fn assert_success(output: &Output, operation: &str) {
            assert!(
                output.status.success(),
                "{operation} failed: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let script = root.join(".github/scripts/integration-services.sh");
        let temp = unique_test_dir("real-lifecycle");
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).expect("smoke temp directory must be creatable");
        let scope = format!("rss-smoke-{}", std::process::id());
        let other_scope = format!("{scope}-canary");
        let log_dir = temp.join(format!("integration-service-logs-{scope}"));
        let evidence = temp.join("evidence.json");
        let archive = temp.join("logs.tar.gz");
        let script = script.to_string_lossy().into_owned();
        let log_dir_s = log_dir.to_string_lossy().into_owned();
        let evidence_s = evidence.to_string_lossy().into_owned();
        let archive_s = archive.to_string_lossy().into_owned();
        let common = [
            "--scope",
            scope.as_str(),
            "--shard",
            "consistency-fault",
            "--partition",
            "unpartitioned",
            "--log-dir",
            log_dir_s.as_str(),
            "--evidence",
            evidence_s.as_str(),
        ];
        for operation in ["bootstrap", "prepare"] {
            let mut args = vec![operation];
            args.extend(common);
            assert_success(&run(script.as_str(), &args), operation);
        }

        let fixture = owned::start_with_context(
            Redis::default(),
            ContainerService::Redis,
            Some(CiContainerContext {
                scope: scope.clone(),
                shard: "consistency-fault".to_string(),
                partition: "unpartitioned".to_string(),
                log_dir: log_dir.clone(),
            }),
        )
        .await
        .expect("real Redis fixture must self-provision");

        let owned = run(
            "docker",
            &[
                "ps",
                "-aq",
                "--filter",
                "label=io.rss.integration.managed=true",
                "--filter",
                &format!("label=io.rss.integration.scope={scope}"),
            ],
        );
        assert_success(&owned, "discover owned Redis");
        let owned_id = String::from_utf8(owned.stdout)
            .expect("docker id must be UTF-8")
            .trim()
            .to_string();
        assert!(!owned_id.is_empty(), "owned Redis id must be discoverable");
        assert!(!owned_id.contains('\n'), "scope must own exactly one Redis");

        let labels = run(
            "docker",
            &["inspect", "--format", "{{json .Config.Labels}}", &owned_id],
        );
        assert_success(&labels, "inspect owned Redis labels");
        let labels: serde_json::Value =
            serde_json::from_slice(&labels.stdout).expect("Docker labels must be JSON");
        for (key, value) in [
            ("io.rss.integration.managed", "true"),
            ("io.rss.integration.scope", scope.as_str()),
            ("io.rss.integration.shard", "consistency-fault"),
            ("io.rss.integration.partition", "unpartitioned"),
            ("io.rss.integration.service", "redis"),
        ] {
            assert_eq!(labels[key], value, "label {key} drifted");
        }

        let canary = run(
            "docker",
            &[
                "run",
                "-d",
                "--label",
                "io.rss.integration.managed=true",
                "--label",
                &format!("io.rss.integration.scope={other_scope}"),
                "--label",
                "io.rss.integration.shard=consistency-fault",
                "--label",
                "io.rss.integration.partition=unpartitioned",
                "--label",
                "io.rss.integration.service=redis",
                "redis:5.0",
            ],
        );
        assert_success(&canary, "start cross-scope canary");
        let canary = Canary(
            String::from_utf8(canary.stdout)
                .expect("canary id must be UTF-8")
                .trim()
                .to_string(),
        );

        let canonical = std::fs::read_dir(&log_dir)
            .expect("prepared log directory must be readable")
            .map(|entry| entry.expect("log entry must be readable").path())
            .collect::<Vec<_>>();
        assert!(
            canonical.iter().any(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("redis-") && name.ends_with(".log"))
            }),
            "real Redis must create one canonical log"
        );
        assert!(
            canonical.iter().any(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("redis-") && name.ends_with(".status"))
                    && std::fs::read_to_string(path).is_ok_and(|value| value == "ok\n")
            }),
            "real Redis must create a canonical ok writer status"
        );

        let mut collect = vec!["collect"];
        collect.extend(common);
        collect.extend(["--outcome", "failure", "--archive", archive_s.as_str()]);
        assert_success(&run(script.as_str(), &collect), "collect real Redis logs");

        std::mem::forget(fixture);
        let mut cleanup = vec!["cleanup"];
        cleanup.extend(common);
        assert_success(&run(script.as_str(), &cleanup), "cleanup owned Redis");
        assert!(
            !run("docker", &["inspect", &owned_id]).status.success(),
            "exact-scope cleanup must delete owned Redis"
        );
        assert!(
            run("docker", &["inspect", &canary.0]).status.success(),
            "cross-scope canary must survive cleanup"
        );
        let archive_listing = run("tar", &["-tzf", archive_s.as_str()]);
        assert_success(&archive_listing, "inspect lifecycle archive");
        let archive_listing = String::from_utf8_lossy(&archive_listing.stdout);
        assert!(archive_listing.contains("redis-"));
        assert!(archive_listing.contains(".log"));
        assert!(
            !archive_listing.contains(".status"),
            "writer status is evidence metadata, not archive payload"
        );

        drop(canary);
        std::fs::remove_dir_all(temp).expect("smoke temp directory cleanup must succeed");
    }
}
