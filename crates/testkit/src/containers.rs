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

use testcontainers::ImageExt;
use testcontainers::core::logs::LogFrame;
use testcontainers::core::{CmdWaitFor, ExecCommand, IntoContainerPort, WaitFor};
use testcontainers::{ContainerAsync, CopyTargetOptions, GenericImage};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::rabbitmq::RabbitMq;
use testcontainers_modules::redis::{REDIS_PORT, Redis};
use tokio::io::AsyncReadExt as _;
use url::{Host, Url};

/// fixture 错误（容器起停 / 坐标解析 / env 解析）——dev/test 用，anyhow 以与任意测试返回类型组合。
pub type FixtureError = anyhow::Error;
type Result<T> = std::result::Result<T, FixtureError>;

/// 容器内固定端口（modules 镜像默认暴露端口）。
const PG_PORT: u16 = 5432;
const VAULT_PORT: u16 = 8200;
const AMQP_PORT: u16 = 5672;
const AMQPS_PORT: u16 = 5671;
const REDISS_PORT: u16 = 6379;
const PUBLISHED_PORT_MAX_ATTEMPTS: u32 = 3;
const PUBLISHED_PORT_RETRY_BACKOFF_MS: u64 = 100;
/// Vault published-port metadata is flaky under Docker Desktop; poll the same container
/// (do not recreate — fixed `dns_name` == container name would collide).
const VAULT_PORT_MAX_ATTEMPTS: u32 = 20;
const VAULT_PORT_RETRY_BACKOFF_MS: u64 = 500;
const MQTTS_PORT: u16 = 8883;
const MINIO_PORT: u16 = 9000;
const VAULT_IMAGE: &str = "hashicorp/vault";
const VAULT_IMAGE_TAG: &str = "1.17.6";
const VAULT_ROOT_TOKEN: &str = "rss-test-vault-root";
static BRIDGE_NETWORK_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Fixture-owned Docker network membership for TLS provider containers.
///
/// `network` is the user-defined bridge name; `dns_name` becomes the container name and therefore
/// the Docker DNS name on that network. Host-side callers still consume mapped endpoints.
#[derive(Clone, Copy, Debug)]
pub struct NetworkAttachment<'a> {
    pub network: &'a str,
    pub dns_name: &'a str,
}

/// Drop guard for a fixture-owned bridge network created by [`bridge_network`].
#[derive(Debug)]
pub struct BridgeNetwork {
    name: String,
}

impl BridgeNetwork {
    /// Docker network name suitable for [`NetworkAttachment::network`].
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl Drop for BridgeNetwork {
    fn drop(&mut self) {
        match std::process::Command::new("docker")
            .args(["network", "rm", "-f", &self.name])
            .output()
        {
            Ok(output) if output.status.success() => {}
            Ok(output) => eprintln!(
                "testkit: docker network rm -f {} failed: {}",
                self.name,
                String::from_utf8_lossy(&output.stderr)
            ),
            Err(error) => eprintln!(
                "testkit: docker network rm -f {} failed to spawn: {error}",
                self.name
            ),
        }
    }
}

/// Creates a unique user-defined bridge network. Drop removes it.
pub async fn bridge_network(prefix: &str) -> Result<BridgeNetwork> {
    if !is_safe_label_token(prefix) {
        return Err(anyhow::anyhow!(
            "bridge_network prefix 含非法字符，须为非空 ASCII 字母数字/./_/-"
        ));
    }
    let seq = BRIDGE_NETWORK_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let name = format!("{prefix}-{}-{seq}", std::process::id());
    let mut command = tokio::process::Command::new("docker");
    command.args(["network", "create", "--driver", "bridge"]);
    if let Some(context) = CiContainerContext::from_env()? {
        for (key, value) in bridge_network_labels(&context) {
            command.args(["--label", &format!("{key}={value}")]);
        }
    }
    command.arg(&name);
    let output = command
        .output()
        .await
        .map_err(|error| anyhow::anyhow!("docker network create failed to spawn: {error}"))?;
    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "docker network create {name} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(BridgeNetwork { name })
}

fn bridge_network_labels(context: &CiContainerContext) -> BTreeMap<String, String> {
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
            "io.rss.integration.resource-kind".to_string(),
            "network".to_string(),
        ),
        (
            "io.rss.integration.service".to_string(),
            "bridge".to_string(),
        ),
    ])
}

fn validate_network_attachment(attachment: NetworkAttachment<'_>) -> Result<()> {
    if !is_safe_label_token(attachment.network) {
        return Err(anyhow::anyhow!(
            "NetworkAttachment.network 含非法字符，须为非空 ASCII 字母数字/./_/-"
        ));
    }
    if !is_safe_label_token(attachment.dns_name) {
        return Err(anyhow::anyhow!(
            "NetworkAttachment.dns_name 含非法字符，须为非空 ASCII 字母数字/./_/-"
        ));
    }
    Ok(())
}

fn attach_network<I: testcontainers::Image>(
    request: testcontainers::ContainerRequest<I>,
    attachment: NetworkAttachment<'_>,
) -> Result<testcontainers::ContainerRequest<I>> {
    validate_network_attachment(attachment)?;
    Ok(request
        .with_network(attachment.network)
        .with_container_name(attachment.dns_name))
}

fn retry_published_port_resolution(
    error: &testcontainers::TestcontainersError,
    attempt: u32,
) -> bool {
    matches!(
        error,
        testcontainers::TestcontainersError::PortNotExposed { .. }
    ) && attempt < PUBLISHED_PORT_MAX_ATTEMPTS
}

async fn wait_published_port<I: testcontainers::Image>(
    container: &ContainerAsync<I>,
    port: u16,
    max_attempts: u32,
    backoff_ms: u64,
) -> Result<u16> {
    let mut last = None;
    for attempt in 1..=max_attempts {
        match container.get_host_port_ipv4(port).await {
            Ok(mapped) => return Ok(mapped),
            Err(error)
                if matches!(
                    error,
                    testcontainers::TestcontainersError::PortNotExposed { .. }
                ) && attempt < max_attempts =>
            {
                last = Some(error);
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Err(anyhow::anyhow!(
        "container port {port}/tcp was not exposed after {max_attempts} attempts: {last:?}"
    ))
}

async fn force_remove_named_container(name: &str) {
    let _ = tokio::process::Command::new("docker")
        .args(["rm", "-f", "--", name])
        .output()
        .await;
}

fn vault_dev_tls_san_flags(dns_name: &str) -> Vec<String> {
    // Keep host-mapped names (localhost / 127.0.0.1) plus the fixture DNS name. Do not pass `::1`
    // as a bare `-dev-tls-san` token: shell/`vault` flag splitting can truncate the remaining SANs.
    // Caller must validate `dns_name` (see [`validate_network_attachment`]) before shell join.
    ["localhost", "127.0.0.1", dns_name]
        .into_iter()
        .map(|san| format!("-dev-tls-san={san}"))
        .collect()
}
const MINIO_ROOT_USER: &str = "rss-minio-root";
const MINIO_ROOT_PASSWORD: &str = "rss-minio-root-test-password";
const MINIO_WORKLOAD_USER: &str = "rss-settingsonly-workload";
const MINIO_WORKLOAD_PASSWORD: &str = "rss-settingsonly-workload-password";
const MINIO_ARCHIVE_BUCKET: &str = "rss-settingsonly-dlx";
const MINIO_NEIGHBOR_BUCKET: &str = "rss-settingsonly-neighbor";
const MINIO_POLICY_NAME: &str = "rss-settingsonly-archive";
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
const CONTAINER_COMMAND_OUTPUT_LIMIT_BYTES: usize = 8 * 1024;
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContainerService {
    Postgres,
    Redis,
    RabbitMq,
    Mosquitto,
    Minio,
    Vault,
    Server,
}

impl ContainerService {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Postgres => "postgres",
            Self::Redis => "redis",
            Self::RabbitMq => "rabbitmq",
            Self::Mosquitto => "mosquitto",
            Self::Minio => "minio",
            Self::Vault => "vault",
            Self::Server => "server",
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

/// Returns the exact repository integration ownership labels for a self-provisioned container.
/// Local runs without CI lifecycle context remain unmanaged; partial context fails closed.
pub fn integration_container_labels(
    service: ContainerService,
) -> Result<Option<BTreeMap<String, String>>> {
    Ok(CiContainerContext::from_env()?.map(|context| service.labels(&context)))
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
    use testcontainers::runners::AsyncBuilder;
    use testcontainers::runners::AsyncRunner;
    use testcontainers::{ContainerRequest, GenericBuildableImage, GenericImage, Image};

    pub(super) async fn build_mosquitto_mtls_image() -> Result<GenericImage> {
        Ok(
            GenericBuildableImage::new("rss-mosquitto-mtls-fixture", "2.0.22-v4")
                .with_dockerfile_string(include_str!(
                    "../../../adapters/mqtt/mosquitto-plugin/Dockerfile"
                ))
                .with_data(
                    include_str!("../../../adapters/mqtt/mosquitto-plugin/plugin.c"),
                    "plugin.c",
                )
                .build_image()
                .await?,
        )
    }

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

/// A PostgreSQL login role used only by integration-test fixtures.
///
/// Keeping the role and password paired preserves their association across fixture setup. The
/// provisioner exposes no policy knobs and always applies the complete fixed least-privilege
/// attribute set; a structural test rejects consumer-owned role DDL.
#[derive(Clone, Copy)]
pub struct PostgresTestLogin<'a> {
    role: &'a str,
    password: &'a str,
}

impl<'a> PostgresTestLogin<'a> {
    /// Bind a role name to the password used by the corresponding test client.
    pub const fn new(role: &'a str, password: &'a str) -> Self {
        Self { role, password }
    }
}

/// Provision PostgreSQL integration-test login roles with one fixed least-privilege policy.
///
/// # INVARIANT: PG-TEST-LOGIN-POLICY-01 { level = "Hard", exec = "native-compile", source = "code", native = "PostgresTestLogin keeps each role/password pair private and the provision function exposes no policy parameters, so every call applies the same complete least-privilege attributes" }
///
/// Role names and passwords are bind parameters. PostgreSQL's `format('%I', ...)` and
/// `format('%L', ...)` produce the dynamic DDL, so no consumer interpolates credentials. A
/// transaction-scoped advisory lock serializes create-vs-alter for each role. Every invocation
/// enforces `LOGIN PASSWORD NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
/// NOINHERIT`.
pub async fn provision_postgres_test_logins(
    params: &PgConnParams,
    logins: &[PostgresTestLogin<'_>],
) -> Result<()> {
    use sqlx::postgres::{PgConnectOptions, PgSslMode};

    let options = PgConnectOptions::new()
        .host(&params.host)
        .port(params.port)
        .database(&params.database)
        .username(&params.username)
        .password(&params.password)
        .ssl_mode(PgSslMode::Prefer);
    provision_postgres_test_logins_with_options(options, logins).await
}

/// TLS-only counterpart of [`provision_postgres_test_logins`].
pub async fn provision_postgres_test_logins_with_private_ca(
    params: &PgConnParams,
    ca_pem: &[u8],
    logins: &[PostgresTestLogin<'_>],
) -> Result<()> {
    use sqlx::postgres::{PgConnectOptions, PgSslMode};

    let options = PgConnectOptions::new()
        .host(&params.host)
        .port(params.port)
        .database(&params.database)
        .username(&params.username)
        .password(&params.password)
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert_from_pem(ca_pem.to_vec());
    provision_postgres_test_logins_with_options(options, logins).await
}

async fn provision_postgres_test_logins_with_options(
    options: sqlx::postgres::PgConnectOptions,
    logins: &[PostgresTestLogin<'_>],
) -> Result<()> {
    use sqlx::postgres::PgPoolOptions;

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(options)
        .await?;
    let mut tx = pool.begin().await?;

    let mut ordered = logins.to_vec();
    ordered.sort_unstable_by_key(|login| login.role);
    for login in ordered {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(login.role)
            .execute(&mut *tx)
            .await?;
        let ddl: String = sqlx::query_scalar(
            r#"
            SELECT CASE
                WHEN EXISTS (SELECT FROM pg_roles WHERE rolname = $1)
                    THEN format('ALTER ROLE %I LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT', $1, $2)
                ELSE format('CREATE ROLE %I LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT', $1, $2)
            END
            "#,
        )
        .bind(login.role)
        .bind(login.password)
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query(&ddl).execute(&mut *tx).await?;
    }

    tx.commit().await?;
    pool.close().await;
    Ok(())
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
    for attempt in 1..=PUBLISHED_PORT_MAX_ATTEMPTS {
        let container = owned::start(Redis::default(), ContainerService::Redis).await?;
        let host = container.get_host().await?;
        match container.get_host_port_ipv4(REDIS_PORT).await {
            Ok(port) => {
                return Ok(RedisFixture {
                    _container: Some(Box::new(container)),
                    url: format!("redis://{host}:{port}"),
                });
            }
            Err(error) if retry_published_port_resolution(&error, attempt) => {
                drop(container);
                tokio::time::sleep(Duration::from_millis(PUBLISHED_PORT_RETRY_BACKOFF_MS)).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
    unreachable!("bounded Redis container port resolution loop must return")
}

struct TlsMaterial {
    ca_pem: String,
    wrong_ca_pem: String,
    server_cert_pem: String,
    server_key_pem: String,
}

fn tls_dns_names<'a>(dns_name: &'a str) -> [&'a str; 2] {
    ["localhost", dns_name]
}

fn tls_material(dns_name: &str) -> Result<TlsMaterial> {
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa,
        KeyPair, SanType,
    };

    let issuer = |label: &str| -> Result<CertifiedIssuer<'static, KeyPair>> {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, label);
        Ok(CertifiedIssuer::self_signed(params, KeyPair::generate()?)?)
    };
    let ca = issuer("rss-test-private-ca")?;
    let wrong_ca = issuer("rss-test-wrong-private-ca")?;
    let server_key = KeyPair::generate()?;
    let mut server = CertificateParams::default();
    server.is_ca = IsCa::ExplicitNoCa;
    server.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let mut sans = Vec::with_capacity(4);
    for name in tls_dns_names(dns_name) {
        sans.push(SanType::DnsName(name.try_into()?));
    }
    sans.push(SanType::IpAddress("127.0.0.1".parse()?));
    sans.push(SanType::IpAddress("::1".parse()?));
    server.subject_alt_names = sans;
    let server_cert = server.signed_by(&server_key, &ca)?;
    Ok(TlsMaterial {
        ca_pem: ca.pem(),
        wrong_ca_pem: wrong_ca.pem(),
        server_cert_pem: server_cert.pem(),
        server_key_pem: server_key.serialize_pem(),
    })
}

fn copied_tls_image(
    image: GenericImage,
    material: &TlsMaterial,
) -> testcontainers::ContainerRequest<GenericImage> {
    image
        .with_copy_to("/rss-tls/ca.pem", material.ca_pem.as_bytes().to_vec())
        .with_copy_to(
            "/rss-tls/server.pem",
            material.server_cert_pem.as_bytes().to_vec(),
        )
        .with_copy_to(
            // testcontainers archive extraction owns copied files as root, while the official
            // Redis/RabbitMQ images drop privileges before reading their TLS key.
            CopyTargetOptions::new("/rss-tls/server-key.pem").with_mode(0o644),
            material.server_key_pem.as_bytes().to_vec(),
        )
}

/// Hermetic PostgreSQL TLS fixture. Only host-side coordinates and trust material are exposed.
pub struct PgTlsFixture {
    _container: Box<ContainerAsync<GenericImage>>,
    params: PgConnParams,
    ca_pem: String,
    wrong_ca_pem: String,
}

impl PgTlsFixture {
    pub fn params(&self) -> &PgConnParams {
        &self.params
    }

    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    pub fn wrong_ca_pem(&self) -> &str {
        &self.wrong_ca_pem
    }
}

/// Starts PostgreSQL 16 with TLS required for every TCP client.
pub async fn postgres_tls(attachment: NetworkAttachment<'_>) -> Result<PgTlsFixture> {
    let material = tls_material(attachment.dns_name)?;
    let startup = b"#!/bin/sh\nset -eu\nchown postgres:postgres /rss-tls/server-key.pem\nchmod 600 /rss-tls/server-key.pem\nexec /usr/local/bin/docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/rss-tls/server.pem -c ssl_key_file=/rss-tls/server-key.pem -c ssl_min_protocol_version=TLSv1.2\n";
    let require_tls = b"#!/bin/sh\nset -eu\nsed -i -E 's/^host([[:space:]])/hostssl\\1/' \"$PGDATA/pg_hba.conf\"\n";
    let image = GenericImage::new("postgres", "16-alpine")
        .with_exposed_port(PG_PORT.tcp())
        .with_wait_for(WaitFor::message_on_stderr(
            "database system is ready to accept connections",
        ));
    let request = attach_network(
        copied_tls_image(image, &material)
            .with_env_var("POSTGRES_DB", PG_DB)
            .with_env_var("POSTGRES_USER", PG_USER)
            .with_env_var("POSTGRES_PASSWORD", PG_PASSWORD)
            .with_copy_to(
                CopyTargetOptions::new("/rss-tls/start-postgres.sh").with_mode(0o755),
                startup.to_vec(),
            )
            .with_copy_to(
                CopyTargetOptions::new("/docker-entrypoint-initdb.d/00-require-tls.sh")
                    .with_mode(0o755),
                require_tls.to_vec(),
            )
            .with_cmd(["/rss-tls/start-postgres.sh"]),
        attachment,
    )?;
    let container = owned::start(request, ContainerService::Postgres).await?;
    let host = container.get_host().await?.to_string();
    let port = container.get_host_port_ipv4(PG_PORT).await?;
    Ok(PgTlsFixture {
        _container: Box::new(container),
        params: PgConnParams {
            host,
            port,
            database: PG_DB.to_owned(),
            username: PG_USER.to_owned(),
            password: PG_PASSWORD.to_owned(),
        },
        ca_pem: material.ca_pem,
        wrong_ca_pem: material.wrong_ca_pem,
    })
}

/// Hermetic Redis TLS fixture. The guard owns the container until drop and exposes only typed
/// connection/trust material; no ambient TLS environment is consulted.
pub struct RedisTlsFixture {
    _container: Box<ContainerAsync<GenericImage>>,
    url: String,
    ca_pem: String,
    wrong_ca_pem: String,
}

impl RedisTlsFixture {
    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    pub fn wrong_ca_pem(&self) -> &str {
        &self.wrong_ca_pem
    }
}

pub async fn redis_tls(attachment: NetworkAttachment<'_>) -> Result<RedisTlsFixture> {
    let material = tls_material(attachment.dns_name)?;
    for attempt in 1..=PUBLISHED_PORT_MAX_ATTEMPTS {
        let image = GenericImage::new("redis", "7.4-alpine")
            .with_exposed_port(REDISS_PORT.tcp())
            .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"));
        let request = attach_network(
            copied_tls_image(image, &material).with_cmd([
                "redis-server",
                "--port",
                "0",
                "--tls-port",
                "6379",
                "--tls-cert-file",
                "/rss-tls/server.pem",
                "--tls-key-file",
                "/rss-tls/server-key.pem",
                "--tls-ca-cert-file",
                "/rss-tls/ca.pem",
                "--tls-auth-clients",
                "no",
            ]),
            attachment,
        )?;
        let container = owned::start(request, ContainerService::Redis).await?;
        let host = container.get_host().await?;
        match container.get_host_port_ipv4(REDISS_PORT).await {
            Ok(port) => {
                return Ok(RedisTlsFixture {
                    _container: Box::new(container),
                    url: format!("rediss://{host}:{port}"),
                    ca_pem: material.ca_pem,
                    wrong_ca_pem: material.wrong_ca_pem,
                });
            }
            Err(error) if retry_published_port_resolution(&error, attempt) => {
                // Fixed dns_name == container name: force-rm before recreate to avoid name collision.
                drop(container);
                force_remove_named_container(attachment.dns_name).await;
                tokio::time::sleep(Duration::from_millis(PUBLISHED_PORT_RETRY_BACKOFF_MS)).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
    unreachable!("bounded Redis TLS port resolution loop must return")
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
        validate_rabbit_vhost(vhost)?;
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

    /// Ask a managed RabbitMQ broker to close one connection in `vhost` from the broker side.
    ///
    /// This is intentionally unavailable for externally supplied brokers: possessing an AMQP URL
    /// does not imply management authority. Tests requiring a real broker-originated close therefore
    /// fail closed instead of silently substituting a client graceful close.
    pub async fn broker_force_close_one_connection(&self, vhost: &str, reason: &str) -> Result<()> {
        validate_rabbit_vhost(vhost)?;
        if reason.is_empty() || reason.contains('\0') {
            return Err(anyhow::anyhow!(
                "RabbitMQ forced-close reason must be non-empty and contain no NUL"
            ));
        }
        match &self.inner {
            RabbitInner::Container {
                container, created, ..
            } => {
                let exists = created
                    .lock()
                    .map_err(|error| anyhow::anyhow!("vhost cache mutex poisoned: {error}"))?
                    .contains(vhost);
                if !exists {
                    return Err(anyhow::anyhow!(
                        "managed RabbitMQ vhost '{vhost}' must be created before forced close"
                    ));
                }
                run_rabbitmqctl(
                    container,
                    &["close_all_connections", "-p", vhost, "--limit", "1", reason],
                )
                .await
            }
            RabbitInner::Env { .. } => Err(anyhow::anyhow!(
                "broker-originated connection close requires a managed RabbitMQ container"
            )),
        }
    }
}

fn validate_rabbit_vhost(vhost: &str) -> Result<()> {
    if vhost.is_empty()
        || !vhost
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '_' | '-'))
    {
        return Err(anyhow::anyhow!(
            "vhost '{vhost}' 含不安全字符，须为非空字母数字/_/-"
        ));
    }
    Ok(())
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

const TLS_VHOST: &str = "rss_acl";
const TLS_PUBLISHER_USER: &str = "rss_publisher";
const TLS_PUBLISHER_PASSWORD: &str = "rss-publisher-test-password";
const TLS_SUBSCRIBER_USER: &str = "rss_subscriber";
const TLS_SUBSCRIBER_PASSWORD: &str = "rss-subscriber-test-password";
const TLS_SHARED_USER: &str = "rss_shared";
const TLS_SHARED_PASSWORD: &str = "rss-shared-test-password";

/// Hermetic RabbitMQ TLS fixture with distinct least-privilege publisher/subscriber identities.
pub struct RabbitTlsFixture {
    container: Box<ContainerAsync<GenericImage>>,
    publisher_url: String,
    subscriber_url: String,
    shared_url: String,
    ca_pem: String,
    wrong_ca_pem: String,
    queue_pattern: String,
    subscriber_read_pattern: String,
}

impl RabbitTlsFixture {
    pub fn publisher_url(&self) -> &str {
        &self.publisher_url
    }

    pub fn subscriber_url(&self) -> &str {
        &self.subscriber_url
    }

    /// Dual-role `amqps://` URL for DurableShared topology e2e (publish + consume on one identity).
    pub fn shared_url(&self) -> &str {
        &self.shared_url
    }

    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    pub fn wrong_ca_pem(&self) -> &str {
        &self.wrong_ca_pem
    }

    /// Live broker receipt for the topic-exchange and exact-routing-key publisher identity.
    pub async fn publisher_permissions_are_exact(&self) -> Result<bool> {
        let output = run_rabbitmqctl_output(
            &self.container,
            &["list_user_permissions", TLS_PUBLISHER_USER],
        )
        .await?;
        let resource_exact = output.lines().any(|line| {
            line.contains(TLS_VHOST)
                && line.split_whitespace().collect::<Vec<_>>()
                    == [TLS_VHOST, "^$", "^amq\\.topic$", "^$"]
        });
        Ok(resource_exact
            && self
                .topic_permissions_are_exact(TLS_PUBLISHER_USER, &self.queue_pattern, "^$")
                .await?)
    }

    /// Live broker receipt for the exact subscriber queue identity.
    pub async fn subscriber_permissions_are_exact(&self) -> Result<bool> {
        let output = run_rabbitmqctl_output(
            &self.container,
            &["list_user_permissions", TLS_SUBSCRIBER_USER],
        )
        .await?;
        let resource_exact = output.lines().any(|line| {
            line.contains(TLS_VHOST)
                && line.split_whitespace().collect::<Vec<_>>()
                    == [
                        TLS_VHOST,
                        self.queue_pattern.as_str(),
                        self.queue_pattern.as_str(),
                        self.subscriber_read_pattern.as_str(),
                    ]
        });
        Ok(resource_exact
            && self
                .topic_permissions_are_exact(TLS_SUBSCRIBER_USER, "^$", &self.queue_pattern)
                .await?)
    }

    async fn topic_permissions_are_exact(
        &self,
        username: &str,
        write_pattern: &str,
        read_pattern: &str,
    ) -> Result<bool> {
        let output =
            run_rabbitmqctl_output(&self.container, &["list_user_topic_permissions", username])
                .await?;
        Ok(output.lines().any(|line| {
            line.contains(TLS_VHOST)
                && line.split_whitespace().collect::<Vec<_>>()
                    == [TLS_VHOST, "amq.topic", write_pattern, read_pattern]
        }))
    }
}

async fn provision_adjacent_rabbit_queue<I: testcontainers::Image>(
    container: &ContainerAsync<I>,
    adjacent_queue: &str,
) -> Result<()> {
    run_rabbitmqctl(
        container,
        &[
            "set_permissions",
            "-p",
            TLS_VHOST,
            "guest",
            ".*",
            ".*",
            ".*",
        ],
    )
    .await?;
    let queue_arg = format!("name={adjacent_queue}");
    run_container_command(
        container,
        "declare adjacent RabbitMQ queue",
        &[
            "rabbitmqadmin",
            "-V",
            TLS_VHOST,
            "-u",
            "guest",
            "-p",
            "guest",
            "declare",
            "queue",
            queue_arg.as_str(),
            "durable=true",
        ],
    )
    .await?;
    let destination_arg = format!("destination={adjacent_queue}");
    let routing_key_arg = format!("routing_key={adjacent_queue}");
    run_container_command(
        container,
        "bind adjacent RabbitMQ routing key",
        &[
            "rabbitmqadmin",
            "-V",
            TLS_VHOST,
            "-u",
            "guest",
            "-p",
            "guest",
            "declare",
            "binding",
            "source=amq.topic",
            "destination_type=queue",
            destination_arg.as_str(),
            routing_key_arg.as_str(),
        ],
    )
    .await?;
    run_rabbitmqctl(container, &["clear_permissions", "-p", TLS_VHOST, "guest"]).await
}

async fn provision_rabbit_tls_permissions<I: testcontainers::Image>(
    container: &ContainerAsync<I>,
    queue_pattern: &str,
    subscriber_read_pattern: &str,
) -> Result<()> {
    run_rabbitmqctl(
        container,
        &["add_user", TLS_PUBLISHER_USER, TLS_PUBLISHER_PASSWORD],
    )
    .await?;
    run_rabbitmqctl(
        container,
        &[
            "set_permissions",
            "-p",
            TLS_VHOST,
            TLS_PUBLISHER_USER,
            "^$",
            "^amq\\.topic$",
            "^$",
        ],
    )
    .await?;
    run_rabbitmqctl(
        container,
        &[
            "set_topic_permissions",
            "-p",
            TLS_VHOST,
            TLS_PUBLISHER_USER,
            "amq.topic",
            queue_pattern,
            "^$",
        ],
    )
    .await?;
    run_rabbitmqctl(
        container,
        &["add_user", TLS_SUBSCRIBER_USER, TLS_SUBSCRIBER_PASSWORD],
    )
    .await?;
    run_rabbitmqctl(
        container,
        &[
            "set_permissions",
            "-p",
            TLS_VHOST,
            TLS_SUBSCRIBER_USER,
            queue_pattern,
            queue_pattern,
            subscriber_read_pattern,
        ],
    )
    .await?;
    run_rabbitmqctl(
        container,
        &[
            "set_topic_permissions",
            "-p",
            TLS_VHOST,
            TLS_SUBSCRIBER_USER,
            "amq.topic",
            "^$",
            queue_pattern,
        ],
    )
    .await?;
    provision_rabbit_tls_shared_user(container).await
}

async fn provision_rabbit_tls_shared_user<I: testcontainers::Image>(
    container: &ContainerAsync<I>,
) -> Result<()> {
    run_rabbitmqctl(
        container,
        &["add_user", TLS_SHARED_USER, TLS_SHARED_PASSWORD],
    )
    .await?;
    run_rabbitmqctl(
        container,
        &[
            "set_permissions",
            "-p",
            TLS_VHOST,
            TLS_SHARED_USER,
            ".*",
            ".*",
            ".*",
        ],
    )
    .await?;
    run_rabbitmqctl(
        container,
        &[
            "set_topic_permissions",
            "-p",
            TLS_VHOST,
            TLS_SHARED_USER,
            "amq.topic",
            ".*",
            ".*",
        ],
    )
    .await
}

/// Starts RabbitMQ TLS with one caller-owned exact subscriber queue.
pub async fn rabbitmq_tls(
    queue_name: &str,
    attachment: NetworkAttachment<'_>,
) -> Result<RabbitTlsFixture> {
    validate_exact_queue_name(queue_name)?;
    let escaped_queue = queue_name.replace('.', "\\.");
    let queue_pattern = format!("^{escaped_queue}$");
    let subscriber_read_pattern = format!("^(amq\\.topic|{escaped_queue})$");
    let adjacent_queue = format!("{queue_name}.adjacent");
    let material = tls_material(attachment.dns_name)?;
    let config = format!(
        "listeners.tcp = none\nlisteners.ssl.default = {AMQPS_PORT}\nssl_options.cacertfile = /rss-tls/ca.pem\nssl_options.certfile = /rss-tls/server.pem\nssl_options.keyfile = /rss-tls/server-key.pem\nssl_options.verify = verify_none\nssl_options.fail_if_no_peer_cert = false\nloopback_users.guest = false\n"
    );
    let image = GenericImage::new("rabbitmq", "3.13.6-management-alpine")
        .with_exposed_port(AMQPS_PORT.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Server startup complete"));
    let request = attach_network(
        copied_tls_image(image, &material)
            .with_copy_to("/etc/rabbitmq/rabbitmq.conf", config.into_bytes()),
        attachment,
    )?;
    let container = owned::start(request, ContainerService::RabbitMq).await?;
    run_rabbitmqctl(&container, &["await_startup"]).await?;
    run_rabbitmqctl(&container, &["add_vhost", TLS_VHOST]).await?;
    provision_adjacent_rabbit_queue(&container, &adjacent_queue).await?;
    provision_rabbit_tls_permissions(&container, &queue_pattern, &subscriber_read_pattern).await?;
    let host = container.get_host().await?.to_string();
    let port = container.get_host_port_ipv4(AMQPS_PORT).await?;
    Ok(RabbitTlsFixture {
        container: Box::new(container),
        publisher_url: format!(
            "amqps://{TLS_PUBLISHER_USER}:{TLS_PUBLISHER_PASSWORD}@{host}:{port}/{TLS_VHOST}"
        ),
        subscriber_url: format!(
            "amqps://{TLS_SUBSCRIBER_USER}:{TLS_SUBSCRIBER_PASSWORD}@{host}:{port}/{TLS_VHOST}"
        ),
        shared_url: format!(
            "amqps://{TLS_SHARED_USER}:{TLS_SHARED_PASSWORD}@{host}:{port}/{TLS_VHOST}"
        ),
        ca_pem: material.ca_pem,
        wrong_ca_pem: material.wrong_ca_pem,
        queue_pattern,
        subscriber_read_pattern,
    })
}

fn validate_exact_queue_name(queue_name: &str) -> Result<()> {
    if queue_name.is_empty()
        || !queue_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(anyhow::anyhow!(
            "exact RabbitMQ queue name must contain only ASCII alphanumeric/./-/_"
        ));
    }
    Ok(())
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
/// attempts + 线性 backoff：exec I/O **不计入**等待预算；末次失败不再 sleep（省末次空等）。
async fn run_rabbitmqctl<I: testcontainers::Image>(
    container: &ContainerAsync<I>,
    args: &[&str],
) -> Result<()> {
    let cmd: Vec<String> = std::iter::once("rabbitmqctl")
        .chain(args.iter().copied())
        .map(str::to_string)
        .collect();
    let mut last: Option<i64> = None;
    let mut last_exec_err: Option<String> = None;
    for attempt in 0..RABBITMQCTL_MAX_ATTEMPTS {
        match container
            .exec(ExecCommand::new(cmd.clone()).with_cmd_ready_condition(CmdWaitFor::exit_code(0)))
            .await
        {
            Ok(res) => match res.exit_code().await {
                Ok(Some(0)) => return Ok(()),
                Ok(code) => last = code,
                Err(error) => last_exec_err = Some(error.to_string()),
            },
            Err(error) => last_exec_err = Some(error.to_string()),
        }
        // 末次失败不再 sleep，直接报错（省末次空等约 6s）。
        if attempt + 1 < RABBITMQCTL_MAX_ATTEMPTS {
            crate::await_delay(Duration::from_millis(
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
        "rabbitmqctl {args:?} 未在 {RABBITMQCTL_MAX_ATTEMPTS} 次（累计约 {total_wait_secs}s backoff）内成功（末次 exit={last:?}, last_err={last_exec_err:?}）"
    ))
}

async fn run_rabbitmqctl_output<I: testcontainers::Image>(
    container: &ContainerAsync<I>,
    args: &[&str],
) -> Result<String> {
    let cmd = std::iter::once("rabbitmqctl")
        .chain(args.iter().copied())
        .map(str::to_string)
        .collect::<Vec<_>>();
    let mut result = container
        .exec(ExecCommand::new(cmd).with_cmd_ready_condition(CmdWaitFor::exit_code(0)))
        .await?;
    let stdout = result.stdout_to_vec().await?;
    String::from_utf8(stdout).map_err(Into::into)
}

async fn run_container_command<I: testcontainers::Image>(
    container: &ContainerAsync<I>,
    operation: &'static str,
    command: &[&str],
) -> Result<()> {
    let output = run_container_command_output(container, operation, command).await?;
    if output.exit_code == Some(0) {
        Ok(())
    } else {
        Err(output.failure(operation))
    }
}

struct ContainerCommandOutput {
    exit_code: Option<i64>,
    stdout: String,
    stderr: String,
}

impl ContainerCommandOutput {
    fn failure(&self, operation: &'static str) -> anyhow::Error {
        anyhow::anyhow!(
            "container fixture '{operation}' initialization command failed (exit={:?}, stdout={:?}, stderr={:?})",
            self.exit_code,
            self.stdout,
            self.stderr
        )
    }
}

async fn run_container_command_output<I: testcontainers::Image>(
    container: &ContainerAsync<I>,
    operation: &'static str,
    command: &[&str],
) -> Result<ContainerCommandOutput> {
    let mut result = container
        .exec(
            ExecCommand::new(
                command
                    .iter()
                    .map(|part| (*part).to_owned())
                    .collect::<Vec<_>>(),
            )
            .with_cmd_ready_condition(CmdWaitFor::exit()),
        )
        .await
        .map_err(|error| {
            anyhow::anyhow!(
                "container fixture '{operation}' initialization failed (exit=unavailable): {error}"
            )
        })?;
    let exit_code = result.exit_code().await.map_err(|error| {
        anyhow::anyhow!(
            "container fixture '{operation}' exit inspection failed (exit=unavailable): {error}"
        )
    })?;
    let mut stdout = Vec::new();
    result
        .stdout()
        .take((CONTAINER_COMMAND_OUTPUT_LIMIT_BYTES + 1) as u64)
        .read_to_end(&mut stdout)
        .await
        .map_err(|error| {
            anyhow::anyhow!(
                "container fixture '{operation}' stdout collection failed (exit={exit_code:?}): {error}"
            )
        })?;
    let mut stderr = Vec::new();
    result
        .stderr()
        .take((CONTAINER_COMMAND_OUTPUT_LIMIT_BYTES + 1) as u64)
        .read_to_end(&mut stderr)
        .await
        .map_err(|error| {
            anyhow::anyhow!(
                "container fixture '{operation}' stderr collection failed (exit={exit_code:?}): {error}"
            )
        })?;
    Ok(ContainerCommandOutput {
        exit_code,
        stdout: bounded_redacted_command_output(stdout),
        stderr: bounded_redacted_command_output(stderr),
    })
}

fn bounded_redacted_command_output(mut bytes: Vec<u8>) -> String {
    let truncated = bytes.len() > CONTAINER_COMMAND_OUTPUT_LIMIT_BYTES;
    bytes.truncate(CONTAINER_COMMAND_OUTPUT_LIMIT_BYTES);
    let mut output = String::from_utf8_lossy(&bytes)
        .replace(MINIO_ROOT_PASSWORD, "<redacted>")
        .replace(MINIO_WORKLOAD_PASSWORD, "<redacted>");
    output.retain(|character| character == '\n' || character == '\t' || !character.is_control());
    if truncated {
        output.push_str("\n[rss-testkit: command output truncated]");
    }
    output
}

// ── mqtt（Mosquitto mTLS + assertion plugin）─────────────────────────────────

const MQTT_TENANT: &str = "11111111-1111-4111-8111-111111111111";
const MQTT_CROSS_TENANT: &str = "33333333-3333-4333-8333-333333333333";
const MQTT_DEVICE: &str = "22222222-2222-4222-8222-222222222222";
const MQTT_CURRENT_GENERATION: u64 = 2;
const MQTT_STALE_GENERATION: u64 = 1;
const MQTT_RSS_CLIENT_ID: &str = "rss-mqtt-adapter";
const MQTT_UPLINK_CONTRACTS: &[&str] = &[
    "identity.device-command-acked",
    "identity.device-certificate-reported",
];
const MQTT_DOWNLINK_CONTRACTS: &[&str] = &[
    "identity.commands.apply-device-certificate",
    "identity.device-ingress-receipted",
];
const MQTT_DEVICE_CURRENT_SERIAL: u64 = 2002;
const MQTT_DEVICE_STALE_SERIAL: u64 = 2001;
const MQTT_DEVICE_CROSS_SERIAL: u64 = 3002;
const MQTT_RSS_A_SERIAL: u64 = 1001;
const MQTT_RSS_B_SERIAL: u64 = 1002;
const MOSQUITTO_READY_STDOUT: &str = "mosquitto version 2.0.22 running";

/// Client-side MQTT trust and identity material. PEM fields are intentionally absent from Debug.
#[derive(Clone)]
pub struct MqttFixtureTlsPem {
    ca_pem: String,
    certificate_pem: Option<String>,
    private_key_pem: Option<String>,
}

impl MqttFixtureTlsPem {
    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    pub fn certificate_pem(&self) -> Option<&str> {
        self.certificate_pem.as_deref()
    }

    pub fn private_key_pem(&self) -> Option<&str> {
        self.private_key_pem.as_deref()
    }
}

impl std::fmt::Debug for MqttFixtureTlsPem {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MqttFixtureTlsPem")
            .field("ca", &"<redacted>")
            .field(
                "certificate",
                &self.certificate_pem.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "private_key",
                &self.private_key_pem.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// One closed credential case minted by [`mosquitto_mtls`].
#[derive(Clone)]
pub struct MqttCredential {
    revision: u64,
    stable_client_id: String,
    tls: MqttFixtureTlsPem,
}

impl MqttCredential {
    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn stable_client_id(&self) -> &str {
        &self.stable_client_id
    }

    pub fn tls(&self) -> &MqttFixtureTlsPem {
        &self.tls
    }
}

impl std::fmt::Debug for MqttCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MqttCredential")
            .field("revision", &self.revision)
            .field("stable_client_id", &self.stable_client_id)
            .field("tls", &self.tls)
            .finish()
    }
}

struct MqttGeneratedMaterial {
    ca_pem: String,
    server_certificate_pem: String,
    server_private_key_pem: String,
    assertion_signing_key_pem: String,
    assertion_public_key: [u8; 32],
    empty_crl_pem: String,
    revoked_device_current_crl_pem: String,
    acl: String,
    rss_a: MqttCredential,
    rss_b: MqttCredential,
    device_current: MqttCredential,
    device_stale: MqttCredential,
    device_cross_tenant: MqttCredential,
    device_wrong_ca: MqttCredential,
    device_no_certificate: MqttCredential,
}

/// Hermetic Mosquitto mTLS fixture. It owns the broker and exposes only client material plus the
/// Ed25519 verification key; the signing key is copied into the broker and then discarded.
pub struct MqttMtlsFixture {
    container: Box<ContainerAsync<GenericImage>>,
    url: String,
    assertion_public_key: [u8; 32],
    empty_crl_pem: String,
    revoked_device_current_crl_pem: String,
    broker_bundle: MqttBrokerBundle,
    rss_a: MqttCredential,
    rss_b: MqttCredential,
    device_current: MqttCredential,
    device_stale: MqttCredential,
    device_cross_tenant: MqttCredential,
    device_wrong_ca: MqttCredential,
    device_no_certificate: MqttCredential,
}

#[derive(Clone)]
struct MqttBrokerBundle {
    ca_pem: String,
    server_certificate_pem: String,
    server_private_key_pem: String,
    assertion_signing_key_pem: String,
    acl: String,
}

impl MqttMtlsFixture {
    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn broker_assertion_public_key(&self) -> &[u8; 32] {
        &self.assertion_public_key
    }

    pub fn rss_a(&self) -> &MqttCredential {
        &self.rss_a
    }

    pub fn rss_b(&self) -> &MqttCredential {
        &self.rss_b
    }

    pub fn device_current(&self) -> &MqttCredential {
        &self.device_current
    }

    pub fn device_stale(&self) -> &MqttCredential {
        &self.device_stale
    }

    pub fn device_cross_tenant(&self) -> &MqttCredential {
        &self.device_cross_tenant
    }

    pub fn device_wrong_ca(&self) -> &MqttCredential {
        &self.device_wrong_ca
    }

    pub fn device_no_certificate(&self) -> &MqttCredential {
        &self.device_no_certificate
    }

    pub async fn stop(&mut self) -> Result<()> {
        self.container.stop_with_timeout(Some(10)).await?;
        Ok(())
    }

    pub async fn start(&mut self) -> Result<()> {
        let prior_stdout_len = self
            .container
            .stdout_to_vec()
            .await
            .map(|bytes| bytes.len())
            .unwrap_or(0);
        self.container.start().await?;
        let host = self.container.get_host().await?;
        let port = self.container.get_host_port_ipv4(MQTTS_PORT).await?;
        self.url = format!("mqtts://{host}:{port}");
        self.wait_broker_ready(BrokerReadyMode::FreshStart { prior_stdout_len })
            .await
    }

    /// Freeze the broker process without changing published ports. Used to prove session
    /// readiness recovery across transport loss on a stable endpoint.
    pub async fn pause(&mut self) -> Result<()> {
        self.container.pause().await?;
        Ok(())
    }

    pub async fn unpause(&mut self) -> Result<()> {
        self.container.unpause().await?;
        // Process continues; readiness marker was logged at initial bring-up and is not re-emitted.
        self.wait_broker_ready(BrokerReadyMode::Resume).await
    }

    fn broker_socket(&self) -> Result<String> {
        let endpoint = url::Url::parse(&self.url)
            .map_err(|error| anyhow::anyhow!("fixture URL must stay mqtts: {error}"))?;
        let host = endpoint
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("fixture URL missing host"))?;
        let port = endpoint
            .port()
            .ok_or_else(|| anyhow::anyhow!("fixture URL missing port"))?;
        Ok(format!("{host}:{port}"))
    }

    /// Wait until the broker accepts TCP *and* has logged the same readiness marker used at
    /// initial `WaitFor` start. TCP alone is insufficient after restart because the listener can
    /// race ahead of mosquitto finishing plugin/TLS bring-up.
    ///
    /// attempts + 固定间隔 backoff：TCP/stdout 探活 I/O **不计入** attempt 预算。
    async fn wait_broker_ready(&self, mode: BrokerReadyMode) -> Result<()> {
        const ATTEMPTS: u32 = 40;
        const INTERVAL: Duration = Duration::from_millis(250);
        let socket = self.broker_socket()?;
        for _ in 0..ATTEMPTS {
            crate::await_delay(INTERVAL).await;
            if tokio::net::TcpStream::connect(&socket).await.is_err() {
                continue;
            }
            let stdout = self.container.stdout_to_vec().await.unwrap_or_default();
            let haystack = match mode {
                BrokerReadyMode::FreshStart { prior_stdout_len } => {
                    stdout.get(prior_stdout_len..).unwrap_or(stdout.as_slice())
                }
                BrokerReadyMode::Resume => stdout.as_slice(),
            };
            if String::from_utf8_lossy(haystack).contains(MOSQUITTO_READY_STDOUT) {
                return Ok(());
            }
        }
        Err(anyhow::anyhow!(
            "mosquitto container did not become ready after {ATTEMPTS} attempts (TCP + `{MOSQUITTO_READY_STDOUT}`)"
        ))
    }

    pub async fn restart(&mut self) -> Result<()> {
        self.stop().await?;
        self.start().await
    }

    /// Rebind the broker with a CRL that revokes `device_current` while leaving RSS B valid.
    pub async fn revoke_device_current_and_rebind(mut self) -> Result<Self> {
        self.stop().await?;
        drop(self.container);
        let started = start_mosquitto_mtls_container(
            &self.broker_bundle,
            &self.revoked_device_current_crl_pem,
        )
        .await?;
        Ok(Self {
            container: started.container,
            url: started.url,
            assertion_public_key: self.assertion_public_key,
            empty_crl_pem: self.empty_crl_pem,
            revoked_device_current_crl_pem: self.revoked_device_current_crl_pem,
            broker_bundle: self.broker_bundle,
            rss_a: self.rss_a,
            rss_b: self.rss_b,
            device_current: self.device_current,
            device_stale: self.device_stale,
            device_cross_tenant: self.device_cross_tenant,
            device_wrong_ca: self.device_wrong_ca,
            device_no_certificate: self.device_no_certificate,
        })
    }
}

fn mqtt_base64url(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(char::from(ALPHABET[(first >> 2) as usize]));
        output.push(char::from(
            ALPHABET[(((first & 0x03) << 4) | (second >> 4)) as usize],
        ));
        if chunk.len() >= 2 {
            output.push(char::from(
                ALPHABET[(((second & 0x0f) << 2) | (third >> 6)) as usize],
            ));
        }
        if chunk.len() == 3 {
            output.push(char::from(ALPHABET[(third & 0x3f) as usize]));
        }
    }
    output
}

fn mqtt_device_client_id(tenant_byte: u8) -> String {
    let mut identity = [0_u8; 32];
    identity[..16].fill(tenant_byte);
    identity[16..].fill(0x22);
    mqtt_base64url(&identity)
}

fn mqtt_principal(tenant: &str, generation: u64) -> String {
    format!("urn:rss:mqtt-device:v1:{tenant}:{MQTT_DEVICE}:{generation}")
}

fn mqtt_client_material(
    issuer: &rcgen::CertifiedIssuer<'_, rcgen::KeyPair>,
    ca_pem: &str,
    stable_client_id: &str,
    principal: Option<&str>,
    serial: u64,
) -> Result<MqttFixtureTlsPem> {
    use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, SanType, SerialNumber};

    let key = KeyPair::generate()?;
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::ExplicitNoCa;
    params.serial_number = Some(SerialNumber::from(serial));
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, stable_client_id);
    if let Some(principal) = principal {
        params.subject_alt_names = vec![SanType::URI(principal.try_into()?)];
    }
    let certificate = params.signed_by(&key, issuer)?;
    Ok(MqttFixtureTlsPem {
        ca_pem: ca_pem.to_owned(),
        certificate_pem: Some(certificate.pem()),
        private_key_pem: Some(key.serialize_pem()),
    })
}

fn mqtt_sign_crl(
    issuer: &rcgen::CertifiedIssuer<'_, rcgen::KeyPair>,
    revoked_serials: &[u64],
    crl_number: u64,
) -> Result<String> {
    use rcgen::{
        CertificateRevocationListParams, KeyIdMethod, RevocationReason, RevokedCertParams,
        SerialNumber, date_time_ymd,
    };

    let revoked_certs = revoked_serials
        .iter()
        .map(|serial| RevokedCertParams {
            serial_number: SerialNumber::from(*serial),
            revocation_time: date_time_ymd(2026, 1, 1),
            reason_code: Some(RevocationReason::KeyCompromise),
            invalidity_date: None,
        })
        .collect();
    let crl = CertificateRevocationListParams {
        this_update: date_time_ymd(2026, 1, 1),
        next_update: date_time_ymd(2030, 1, 1),
        crl_number: SerialNumber::from(crl_number),
        issuing_distribution_point: None,
        revoked_certs,
        key_identifier_method: KeyIdMethod::Sha256,
    }
    .signed_by(issuer)?;
    Ok(crl.pem()?)
}

fn mqtt_generated_material() -> Result<MqttGeneratedMaterial> {
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa,
        KeyPair, KeyUsagePurpose, PKCS_ED25519, SanType, SerialNumber,
    };

    let issuer = |label: &str| -> Result<CertifiedIssuer<'static, KeyPair>> {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::CrlSign,
        ];
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, label);
        Ok(CertifiedIssuer::self_signed(params, KeyPair::generate()?)?)
    };
    let ca = issuer("rss-mqtt-test-ca")?;
    let wrong_ca = issuer("rss-mqtt-test-wrong-ca")?;
    let ca_pem = ca.pem();

    let server_key = KeyPair::generate()?;
    let mut server = CertificateParams::default();
    server.is_ca = IsCa::ExplicitNoCa;
    server.serial_number = Some(SerialNumber::from(1u64));
    server.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    server.subject_alt_names = vec![
        SanType::DnsName("localhost".try_into()?),
        SanType::IpAddress("127.0.0.1".parse()?),
        SanType::IpAddress("::1".parse()?),
    ];
    let server_certificate = server.signed_by(&server_key, &ca)?;

    let primary_client_id = mqtt_device_client_id(0x11);
    let cross_client_id = mqtt_device_client_id(0x33);
    let current_principal = mqtt_principal(MQTT_TENANT, MQTT_CURRENT_GENERATION);
    let stale_principal = mqtt_principal(MQTT_TENANT, MQTT_STALE_GENERATION);
    let cross_principal = mqtt_principal(MQTT_CROSS_TENANT, MQTT_CURRENT_GENERATION);

    let credential = |revision, stable_client_id: &str, tls| MqttCredential {
        revision,
        stable_client_id: stable_client_id.to_owned(),
        tls,
    };
    let rss_a = credential(
        1,
        MQTT_RSS_CLIENT_ID,
        mqtt_client_material(&ca, &ca_pem, MQTT_RSS_CLIENT_ID, None, MQTT_RSS_A_SERIAL)?,
    );
    let rss_b = credential(
        2,
        MQTT_RSS_CLIENT_ID,
        mqtt_client_material(&ca, &ca_pem, MQTT_RSS_CLIENT_ID, None, MQTT_RSS_B_SERIAL)?,
    );
    let device_current = credential(
        MQTT_CURRENT_GENERATION,
        &primary_client_id,
        mqtt_client_material(
            &ca,
            &ca_pem,
            &primary_client_id,
            Some(&current_principal),
            MQTT_DEVICE_CURRENT_SERIAL,
        )?,
    );
    let device_stale = credential(
        MQTT_STALE_GENERATION,
        &primary_client_id,
        mqtt_client_material(
            &ca,
            &ca_pem,
            &primary_client_id,
            Some(&stale_principal),
            MQTT_DEVICE_STALE_SERIAL,
        )?,
    );
    let device_cross_tenant = credential(
        MQTT_CURRENT_GENERATION,
        &cross_client_id,
        mqtt_client_material(
            &ca,
            &ca_pem,
            &cross_client_id,
            Some(&cross_principal),
            MQTT_DEVICE_CROSS_SERIAL,
        )?,
    );
    let device_wrong_ca = credential(
        MQTT_CURRENT_GENERATION,
        &primary_client_id,
        mqtt_client_material(
            &wrong_ca,
            &ca_pem,
            &primary_client_id,
            Some(&current_principal),
            MQTT_DEVICE_CURRENT_SERIAL,
        )?,
    );
    let device_no_certificate = credential(
        MQTT_CURRENT_GENERATION,
        &primary_client_id,
        MqttFixtureTlsPem {
            ca_pem: ca_pem.clone(),
            certificate_pem: None,
            private_key_pem: None,
        },
    );

    let assertion_key = KeyPair::generate_for(&PKCS_ED25519)?;
    let assertion_public_key = assertion_key
        .public_key_raw()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Ed25519 public key must be exactly 32 bytes"))?;
    let empty_crl_pem = mqtt_sign_crl(&ca, &[], 1)?;
    let revoked_device_current_crl_pem = mqtt_sign_crl(&ca, &[MQTT_DEVICE_CURRENT_SERIAL], 2)?;
    let acl = mqtt_exact_acl(&primary_client_id, &cross_client_id);
    Ok(MqttGeneratedMaterial {
        ca_pem,
        server_certificate_pem: server_certificate.pem(),
        server_private_key_pem: server_key.serialize_pem(),
        assertion_signing_key_pem: assertion_key.serialize_pem(),
        assertion_public_key,
        empty_crl_pem,
        revoked_device_current_crl_pem,
        acl,
        rss_a,
        rss_b,
        device_current,
        device_stale,
        device_cross_tenant,
        device_wrong_ca,
        device_no_certificate,
    })
}

fn mqtt_exact_acl(primary_client_id: &str, cross_client_id: &str) -> String {
    let mut acl = format!("user {MQTT_RSS_CLIENT_ID}\n");
    for generation in [MQTT_STALE_GENERATION, MQTT_CURRENT_GENERATION] {
        for contract in MQTT_DOWNLINK_CONTRACTS {
            acl.push_str(&format!(
                "topic write rss/v1/{MQTT_TENANT}/{MQTT_DEVICE}/{generation}/downlink/{contract}\n"
            ));
        }
        for contract in MQTT_UPLINK_CONTRACTS {
            acl.push_str(&format!(
                "topic read rss/v1/{MQTT_TENANT}/{MQTT_DEVICE}/{generation}/uplink/{contract}\n"
            ));
        }
    }
    acl.push_str(&format!("\nuser {primary_client_id}\n"));
    for generation in [MQTT_STALE_GENERATION, MQTT_CURRENT_GENERATION] {
        for contract in MQTT_DOWNLINK_CONTRACTS {
            acl.push_str(&format!(
                "topic read rss/v1/{MQTT_TENANT}/{MQTT_DEVICE}/{generation}/downlink/{contract}\n"
            ));
        }
        for contract in MQTT_UPLINK_CONTRACTS {
            acl.push_str(&format!(
                "topic write rss/v1/{MQTT_TENANT}/{MQTT_DEVICE}/{generation}/uplink/{contract}\n"
            ));
        }
    }
    acl.push_str(&format!("\nuser {cross_client_id}\n"));
    for contract in MQTT_DOWNLINK_CONTRACTS {
        acl.push_str(&format!(
            "topic read rss/v1/{MQTT_CROSS_TENANT}/{MQTT_DEVICE}/{MQTT_CURRENT_GENERATION}/downlink/{contract}\n"
        ));
    }
    for contract in MQTT_UPLINK_CONTRACTS {
        acl.push_str(&format!(
            "topic write rss/v1/{MQTT_CROSS_TENANT}/{MQTT_DEVICE}/{MQTT_CURRENT_GENERATION}/uplink/{contract}\n"
        ));
    }
    acl
}

fn mqtt_broker_config() -> &'static str {
    "per_listener_settings true\
\nlistener 8883\
\nprotocol mqtt\
\nallow_anonymous false\
\ncafile /mosquitto/config/ca.pem\
\ncertfile /mosquitto/config/server.pem\
\nkeyfile /mosquitto/config/server-key.pem\
\ncrlfile /mosquitto/config/ca.crl\
\nrequire_certificate true\
\nuse_identity_as_username true\
\nuse_username_as_clientid true\
\ntls_version tlsv1.3\
\nacl_file /mosquitto/config/acl\
\npersistence true\
\npersistence_location /mosquitto/data/\
\nautosave_interval 1\
\nautosave_on_changes true\
\nplugin /usr/lib/rss_mqtt_authn.so\
\nplugin_opt_signing_key /mosquitto/config/assertion-key.pem\
\nlog_dest stdout\
\nlog_type all\
\nconnection_messages true\n"
}

struct StartedMosquittoMtls {
    container: Box<ContainerAsync<GenericImage>>,
    url: String,
}

#[derive(Clone, Copy)]
enum BrokerReadyMode {
    /// After stop/start: only accept a readiness marker emitted in the new log suffix.
    FreshStart { prior_stdout_len: usize },
    /// After unpause: process continues; historical readiness marker + TCP is sufficient.
    Resume,
}

async fn start_mosquitto_mtls_container(
    bundle: &MqttBrokerBundle,
    crl_pem: &str,
) -> Result<StartedMosquittoMtls> {
    let image = owned::build_mosquitto_mtls_image()
        .await?
        .with_exposed_port(MQTTS_PORT.tcp())
        .with_wait_for(WaitFor::message_on_stdout(MOSQUITTO_READY_STDOUT));
    let request = image
        .with_copy_to(
            "/mosquitto/config/mosquitto.conf",
            mqtt_broker_config().as_bytes().to_vec(),
        )
        .with_copy_to("/mosquitto/config/acl", bundle.acl.as_bytes().to_vec())
        .with_copy_to(
            "/mosquitto/config/ca.pem",
            bundle.ca_pem.as_bytes().to_vec(),
        )
        .with_copy_to("/mosquitto/config/ca.crl", crl_pem.as_bytes().to_vec())
        .with_copy_to(
            "/mosquitto/config/server.pem",
            bundle.server_certificate_pem.as_bytes().to_vec(),
        )
        .with_copy_to(
            CopyTargetOptions::new("/mosquitto/config/server-key.pem").with_mode(0o600),
            bundle.server_private_key_pem.as_bytes().to_vec(),
        )
        .with_copy_to(
            CopyTargetOptions::new("/mosquitto/config/assertion-key.pem").with_mode(0o600),
            bundle.assertion_signing_key_pem.as_bytes().to_vec(),
        )
        .with_cmd(["mosquitto", "-c", "/mosquitto/config/mosquitto.conf"]);
    let container = owned::start(request, ContainerService::Mosquitto).await?;
    let host = container.get_host().await?;
    let port = container.get_host_port_ipv4(MQTTS_PORT).await?;
    Ok(StartedMosquittoMtls {
        container: Box::new(container),
        url: format!("mqtts://{host}:{port}"),
    })
}

/// Starts the one production-shaped MQTT test broker. There is deliberately no environment URL
/// fallback and no plaintext listener: T2 always exercises the same mTLS/plugin/ACL boundary.
pub async fn mosquitto_mtls() -> Result<MqttMtlsFixture> {
    let material = mqtt_generated_material()?;
    let broker_bundle = MqttBrokerBundle {
        ca_pem: material.ca_pem,
        server_certificate_pem: material.server_certificate_pem,
        server_private_key_pem: material.server_private_key_pem,
        assertion_signing_key_pem: material.assertion_signing_key_pem,
        acl: material.acl,
    };
    let started = start_mosquitto_mtls_container(&broker_bundle, &material.empty_crl_pem).await?;

    Ok(MqttMtlsFixture {
        container: started.container,
        url: started.url,
        assertion_public_key: material.assertion_public_key,
        empty_crl_pem: material.empty_crl_pem,
        revoked_device_current_crl_pem: material.revoked_device_current_crl_pem,
        broker_bundle,
        rss_a: material.rss_a,
        rss_b: material.rss_b,
        device_current: material.device_current,
        device_stale: material.device_stale,
        device_cross_tenant: material.device_cross_tenant,
        device_wrong_ca: material.device_wrong_ca,
        device_no_certificate: material.device_no_certificate,
    })
}

// ── MinIO / S3-compatible object storage ────────────────────────────────────

/// Redacted MinIO connection coordinates used by the single provider conformance test.
#[derive(Clone)]
pub struct MinioCredentials {
    endpoint_url: String,
    access_key_id: String,
    secret_access_key: String,
}

impl MinioCredentials {
    pub fn endpoint_url(&self) -> &str {
        &self.endpoint_url
    }

    pub fn access_key_id(&self) -> &str {
        &self.access_key_id
    }

    pub fn secret_access_key(&self) -> &str {
        &self.secret_access_key
    }
}

impl std::fmt::Debug for MinioCredentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MinioCredentials")
            .field("endpoint_url", &self.endpoint_url)
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .finish()
    }
}

/// Hermetic TLS MinIO guard with one fixed locked bucket and one scoped workload identity.
pub struct MinioTlsFixture {
    _container: Box<ContainerAsync<GenericImage>>,
    workload: MinioCredentials,
    ca_pem: String,
    wrong_ca_pem: String,
}

impl MinioTlsFixture {
    pub fn workload(&self) -> &MinioCredentials {
        &self.workload
    }

    pub const fn archive_bucket(&self) -> &'static str {
        MINIO_ARCHIVE_BUCKET
    }

    pub const fn neighbor_bucket(&self) -> &'static str {
        MINIO_NEIGHBOR_BUCKET
    }

    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    pub fn wrong_ca_pem(&self) -> &str {
        &self.wrong_ca_pem
    }

    /// Proves that even the fixture-internal root identity cannot delete one exact retained version.
    pub async fn assert_admin_cannot_delete_retained_version(
        &self,
        object_key: &str,
        version_id: &str,
    ) -> Result<()> {
        if object_key.is_empty() || object_key.starts_with('-') || object_key.contains('\0') {
            return Err(anyhow::anyhow!("invalid retained MinIO object key"));
        }
        if version_id.is_empty()
            || !version_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(anyhow::anyhow!("invalid retained MinIO version id"));
        }
        let target = format!("rss/{MINIO_ARCHIVE_BUCKET}/{object_key}");
        let output = run_container_command_output(
            &self._container,
            "probe retained exact-version deletion",
            &[
                "mc",
                "--insecure",
                "rm",
                "--version-id",
                version_id,
                target.as_str(),
            ],
        )
        .await?;
        if output.exit_code == Some(0) {
            return Err(anyhow::anyhow!(
                "container fixture retained exact-version deletion unexpectedly succeeded"
            ));
        }
        let diagnostic = format!("{}\n{}", output.stdout, output.stderr).to_ascii_lowercase();
        if !diagnostic.contains("worm protected") {
            return Err(output.failure("probe retained exact-version deletion"));
        }
        Ok(())
    }
}

/// Starts one TLS MinIO server and provisions the exact SettingsOnly archive posture.
pub async fn minio_tls_archive(attachment: NetworkAttachment<'_>) -> Result<MinioTlsFixture> {
    let material = tls_material(attachment.dns_name)?;
    let policy = minio_archive_policy();
    let archive_alias = format!("rss/{MINIO_ARCHIVE_BUCKET}");
    let neighbor_alias = format!("rss/{MINIO_NEIGHBOR_BUCKET}");
    let image = GenericImage::new("minio/minio", "RELEASE.2025-02-28T09-55-16Z")
        .with_exposed_port(MINIO_PORT.tcp())
        .with_wait_for(WaitFor::message_on_stderr("API:"));
    let request = attach_network(
        image
            .with_env_var("MINIO_ROOT_USER", MINIO_ROOT_USER)
            .with_env_var("MINIO_ROOT_PASSWORD", MINIO_ROOT_PASSWORD)
            .with_copy_to(
                "/rss-tls/CAs/rss-test-ca.pem",
                material.ca_pem.as_bytes().to_vec(),
            )
            .with_copy_to(
                "/rss-tls/public.crt",
                material.server_cert_pem.as_bytes().to_vec(),
            )
            .with_copy_to(
                CopyTargetOptions::new("/rss-tls/private.key").with_mode(0o600),
                material.server_key_pem.as_bytes().to_vec(),
            )
            .with_copy_to("/rss-minio/archive-policy.json", policy.into_bytes())
            .with_cmd([
                "server",
                "/data",
                "--certs-dir",
                "/rss-tls",
                "--console-address",
                ":9001",
            ]),
        attachment,
    )?;
    let container = owned::start(request, ContainerService::Minio).await?;
    run_container_command(
        &container,
        "configure admin alias",
        &[
            "mc",
            "--insecure",
            "alias",
            "set",
            "rss",
            "https://127.0.0.1:9000",
            MINIO_ROOT_USER,
            MINIO_ROOT_PASSWORD,
        ],
    )
    .await?;
    run_container_command(
        &container,
        "create locked archive bucket",
        &[
            "mc",
            "--insecure",
            "mb",
            "--with-lock",
            archive_alias.as_str(),
        ],
    )
    .await?;
    run_container_command(
        &container,
        "configure archive retention",
        &[
            "mc",
            "--insecure",
            "retention",
            "set",
            "--default",
            "COMPLIANCE",
            "31d",
            archive_alias.as_str(),
        ],
    )
    .await?;
    run_container_command(
        &container,
        "configure archive lifecycle",
        &[
            "mc",
            "--insecure",
            "ilm",
            "rule",
            "add",
            "--expire-days",
            "32",
            "--noncurrent-expire-days",
            "32",
            archive_alias.as_str(),
        ],
    )
    .await?;
    run_container_command(
        &container,
        "create neighbor bucket",
        &["mc", "--insecure", "mb", neighbor_alias.as_str()],
    )
    .await?;
    run_container_command(
        &container,
        "create workload policy",
        &[
            "mc",
            "--insecure",
            "admin",
            "policy",
            "create",
            "rss",
            MINIO_POLICY_NAME,
            "/rss-minio/archive-policy.json",
        ],
    )
    .await?;
    run_container_command(
        &container,
        "create workload identity",
        &[
            "mc",
            "--insecure",
            "admin",
            "user",
            "add",
            "rss",
            MINIO_WORKLOAD_USER,
            MINIO_WORKLOAD_PASSWORD,
        ],
    )
    .await?;
    run_container_command(
        &container,
        "attach workload policy",
        &[
            "mc",
            "--insecure",
            "admin",
            "policy",
            "attach",
            "rss",
            MINIO_POLICY_NAME,
            "--user",
            MINIO_WORKLOAD_USER,
        ],
    )
    .await?;
    let host = container.get_host().await?.to_string();
    let port = container.get_host_port_ipv4(MINIO_PORT).await?;
    let credentials = |access_key_id: &str, secret_access_key: &str| MinioCredentials {
        endpoint_url: format!("https://{host}:{port}"),
        access_key_id: access_key_id.to_owned(),
        secret_access_key: secret_access_key.to_owned(),
    };
    Ok(MinioTlsFixture {
        _container: Box::new(container),
        workload: credentials(MINIO_WORKLOAD_USER, MINIO_WORKLOAD_PASSWORD),
        ca_pem: material.ca_pem,
        wrong_ca_pem: material.wrong_ca_pem,
    })
}

// ── Vault TLS ─────────────────────────────────────────────

/// Hermetic, provider-neutral Vault dev-TLS fixture.
///
/// This fixture is owned here because the workspace confines raw `testcontainers` dependencies to
/// `testkit`. It must stay limited to container lifecycle and transport coordinates: SettingsOnly
/// or any other provider-specific mounts, policies, keys, tokens, and seed data belong in the
/// consuming integration test.
pub struct VaultTlsFixture {
    _container: Box<ContainerAsync<GenericImage>>,
    endpoint_url: String,
    ca_pem: String,
}

impl VaultTlsFixture {
    /// HTTPS endpoint reachable from the host running the test.
    pub fn endpoint_url(&self) -> &str {
        &self.endpoint_url
    }

    /// Root token for one-time fixture initialization. Runtime secret bundles must use derived
    /// least-privilege tokens.
    pub fn root_token(&self) -> &str {
        VAULT_ROOT_TOKEN
    }

    /// Vault's generated dev-TLS CA in PEM format.
    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }
}

fn vault_host_endpoint(host: &str, port: u16) -> String {
    format!("https://{host}:{port}")
}

/// Starts Vault in in-memory dev-TLS mode without installing any provider-specific provisioning.
pub async fn vault_tls(attachment: NetworkAttachment<'_>) -> Result<VaultTlsFixture> {
    // attach_network fail-closed validates dns_name before it is interpolated into `sh -c`.
    let san_flags = vault_dev_tls_san_flags(attachment.dns_name).join(" ");
    let image = GenericImage::new(VAULT_IMAGE, VAULT_IMAGE_TAG)
        .with_exposed_port(VAULT_PORT.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Vault server started!"));
    // The official entrypoint drops to `vault`. Prepare its dev-TLS directory as root, then invoke
    // the same entrypoint so generated keys remain owned by the unprivileged image user.
    let startup = format!(
        "mkdir -p /tmp/rss-vault-tls && touch /tmp/rss-vault-tls/vault-ca.pem /tmp/rss-vault-tls/vault-cert.pem /tmp/rss-vault-tls/vault-key.pem && chown -R vault:vault /tmp/rss-vault-tls && exec /usr/local/bin/docker-entrypoint.sh server -dev -dev-tls -dev-no-store-token -dev-root-token-id={VAULT_ROOT_TOKEN} -dev-listen-address=0.0.0.0:{VAULT_PORT} -dev-tls-cert-dir=/tmp/rss-vault-tls {san_flags}"
    );
    let request = attach_network(
        image.with_cmd(["sh".to_owned(), "-c".to_owned(), startup]),
        attachment,
    )?;
    let container = owned::start(request, ContainerService::Vault).await?;
    let host = container.get_host().await?.to_string();
    let port = wait_published_port(
        &container,
        VAULT_PORT,
        VAULT_PORT_MAX_ATTEMPTS,
        VAULT_PORT_RETRY_BACKOFF_MS,
    )
    .await?;
    let ca_bytes = container
        .copy_file_from("/tmp/rss-vault-tls/vault-ca.pem", Vec::new())
        .await?;
    let ca_pem = String::from_utf8(ca_bytes)
        .map_err(|error| anyhow::anyhow!("Vault generated CA is not UTF-8 PEM: {error}"))?;
    Ok(VaultTlsFixture {
        _container: Box::new(container),
        endpoint_url: vault_host_endpoint(&host, port),
        ca_pem,
    })
}

fn minio_archive_policy() -> String {
    format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":["s3:GetBucketVersioning","s3:GetBucketObjectLockConfiguration","s3:GetLifecycleConfiguration"],"Resource":"arn:aws:s3:::{MINIO_ARCHIVE_BUCKET}"}},{{"Effect":"Allow","Action":["s3:GetObject","s3:GetObjectVersion","s3:GetObjectRetention","s3:PutObject"],"Resource":"arn:aws:s3:::{MINIO_ARCHIVE_BUCKET}/*"}}]}}"#
    )
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

    #[test]
    fn mqtt_acl_allows_only_the_closed_downlink_contracts() {
        let acl = mqtt_exact_acl("device-primary", "device-cross");
        let downlinks = acl
            .lines()
            .filter(|line| line.contains("/downlink/"))
            .collect::<Vec<_>>();
        assert_eq!(downlinks.len(), 10);
        for line in downlinks {
            assert!(
                MQTT_DOWNLINK_CONTRACTS
                    .iter()
                    .any(|contract| line.ends_with(contract)),
                "unknown downlink contract entered the exact ACL: {line}"
            );
            assert!(!line.contains('+') && !line.contains('#'));
        }
        assert!(
            !acl.contains("/downlink/identity.device-unknown"),
            "an extra downlink contract must remain rejected"
        );
    }

    #[test]
    fn published_port_resolution_retries_only_bounded_missing_port_metadata() {
        let missing = testcontainers::TestcontainersError::PortNotExposed {
            id: "fixture".to_string(),
            port: REDIS_PORT.tcp(),
        };
        assert!(retry_published_port_resolution(&missing, 1));
        assert!(retry_published_port_resolution(&missing, 2));
        assert!(!retry_published_port_resolution(
            &missing,
            PUBLISHED_PORT_MAX_ATTEMPTS
        ));

        let other = testcontainers::TestcontainersError::Other(Box::new(std::io::Error::other(
            "fixture error",
        )));
        assert!(!retry_published_port_resolution(&other, 1));
    }

    #[test]
    fn network_attachment_rejects_shell_metacharacters_in_dns_name() {
        let err = validate_network_attachment(NetworkAttachment {
            network: "rss-bridge",
            dns_name: "evil;rm -rf /",
        })
        .expect_err("dns_name with shell metacharacters must fail closed");
        assert!(err.to_string().contains("dns_name"));

        validate_network_attachment(NetworkAttachment {
            network: "rss-bridge",
            dns_name: "rss-so-1-vault",
        })
        .expect("safe dns_name must pass");
    }

    #[test]
    fn vault_dev_tls_san_flags_include_dns_name_and_exclude_host_gateway_aliases() {
        let flags = vault_dev_tls_san_flags("rss-fixture-dns");
        assert_eq!(
            flags,
            vec![
                "-dev-tls-san=localhost".to_string(),
                "-dev-tls-san=127.0.0.1".to_string(),
                "-dev-tls-san=rss-fixture-dns".to_string(),
            ]
        );
        let joined = flags.join(" ");
        assert!(!joined.contains("host.docker.internal"));
        assert!(!joined.contains("host.testcontainers.internal"));
    }

    #[test]
    fn tls_dns_names_include_localhost_and_fixture_dns() {
        assert_eq!(
            tls_dns_names("rss-fixture-dns"),
            ["localhost", "rss-fixture-dns"]
        );
        tls_material("rss-fixture-dns").expect("tls material must build with fixture DNS");
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
            (ContainerService::Minio, "minio"),
            (ContainerService::Vault, "vault"),
            (ContainerService::Server, "server"),
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

    #[test]
    fn vault_fixture_pins_image_and_maps_host_https_endpoint() {
        assert_eq!(
            (VAULT_IMAGE, VAULT_IMAGE_TAG),
            ("hashicorp/vault", "1.17.6")
        );
        assert_eq!(
            vault_host_endpoint("127.0.0.1", 49_152),
            "https://127.0.0.1:49152"
        );
        assert_eq!(ContainerService::Vault.name(), "vault");
    }

    #[test]
    fn exact_provider_tls_inputs_reject_wildcards_and_policy_drift() {
        for queue in ["", "settings.*", "settings/queue", "空"] {
            assert!(
                validate_exact_queue_name(queue).is_err(),
                "accepted non-exact RabbitMQ queue {queue:?}"
            );
        }
        assert!(validate_exact_queue_name("settings.config-version-changed").is_ok());

        let policy: serde_json::Value = serde_json::from_str(&minio_archive_policy())
            .expect("fixed MinIO archive policy must be valid JSON");
        assert_eq!(
            policy,
            serde_json::json!({
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "s3:GetBucketVersioning",
                            "s3:GetBucketObjectLockConfiguration",
                            "s3:GetLifecycleConfiguration"
                        ],
                        "Resource": format!("arn:aws:s3:::{MINIO_ARCHIVE_BUCKET}")
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "s3:GetObject",
                            "s3:GetObjectVersion",
                            "s3:GetObjectRetention",
                            "s3:PutObject"
                        ],
                        "Resource": format!("arn:aws:s3:::{MINIO_ARCHIVE_BUCKET}/*")
                    }
                ]
            }),
            "MinIO workload policy must remain an exact closed value"
        );
    }

    #[test]
    fn container_command_diagnostics_are_bounded_and_redacted() {
        let oversized = format!(
            "prefix {MINIO_ROOT_PASSWORD} {MINIO_WORKLOAD_PASSWORD} {}",
            "x".repeat(CONTAINER_COMMAND_OUTPUT_LIMIT_BYTES + 128)
        );
        let rendered = bounded_redacted_command_output(oversized.into_bytes());

        assert!(!rendered.contains(MINIO_ROOT_PASSWORD));
        assert!(!rendered.contains(MINIO_WORKLOAD_PASSWORD));
        assert_eq!(rendered.matches("<redacted>").count(), 2);
        assert!(rendered.ends_with("[rss-testkit: command output truncated]"));
        assert!(
            rendered.len()
                <= CONTAINER_COMMAND_OUTPUT_LIMIT_BYTES
                    + "\n[rss-testkit: command output truncated]".len()
        );

        let failure = ContainerCommandOutput {
            exit_code: Some(7),
            stdout: "safe stdout".to_owned(),
            stderr: "safe stderr".to_owned(),
        }
        .failure("provision archive");
        let diagnostic = failure.to_string();
        assert!(diagnostic.contains("provision archive"));
        assert!(diagnostic.contains("exit=Some(7)"));
        assert!(!diagnostic.contains("mc alias set"));
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
    /// test covers resolvers without starting Docker. MQTT has no external URL resolver.
    #[test]
    fn empty_external_environment_values_select_self_provision() {
        for key in [
            "RSS_TEST_ALLOW_EXTERNAL_POSTGRES",
            "REDIS_TEST_URL",
            "RSS_AMQP_TEST_URL",
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

    #[test]
    #[allow(clippy::unwrap_used)]
    // reason: 测试体构造 tokio runtime 辅助调 async fn；runtime build 失败属 programmer error。
    fn broker_forced_close_rejects_external_fixture_without_management_authority() {
        let fixture = RabbitFixture {
            inner: RabbitInner::Env {
                base: "amqps://guest:guest@example.test:5671".to_string(),
            },
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let error = rt
            .block_on(fixture.broker_force_close_one_connection("rss_test", "review test"))
            .expect_err("external AMQP URL must not imply broker management authority");

        assert!(error.to_string().contains("managed RabbitMQ container"));
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
