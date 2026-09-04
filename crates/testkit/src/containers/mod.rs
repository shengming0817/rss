//! 真容器 fixtures（testcontainers 0.27 + testcontainers-modules 0.15）。
//!
//! `env_or_*` resolver 回传**不透明 fixture guard**（`PgFixture` / `RedisFixture` / `RabbitFixture`）：
//! **默认起容器**（fail-closed 安全语义）；仅当满足显式 opt-in 条件时走外部路径：
//! - postgres：`RSS_TEST_ALLOW_EXTERNAL_POSTGRES` 存在（非空）+ endpoint 三元组
//!   `PGHOST`/`PGPORT`/`PGDATABASE` 全在；外部 owner 凭据从不读取或暴露；
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

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use testcontainers::ImageExt;
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::{ContainerAsync, CopyTargetOptions, GenericImage};
use url::Url;

#[cfg(test)]
use testcontainers_modules::redis::REDIS_PORT;

/// fixture 错误（容器起停 / 坐标解析 / env 解析）——dev/test 用，anyhow 以与任意测试返回类型组合。
pub type FixtureError = anyhow::Error;
type Result<T> = std::result::Result<T, FixtureError>;

/// 容器内固定端口（modules 镜像默认暴露端口）。
const PUBLISHED_PORT_MAX_ATTEMPTS: u32 = 3;
const PUBLISHED_PORT_RETRY_BACKOFF_MS: u64 = 100;
const MINIO_PORT: u16 = 9000;
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
    command.args(["network", "create", "--driver", "bridge", &name]);
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
const MINIO_WORKLOAD_USER: &str = "rss-test-workload";
const MINIO_WORKLOAD_PASSWORD: &str = "rss-test-workload-password";
const MINIO_ARCHIVE_BUCKET: &str = "rss-test-dlx";
const MINIO_NEIGHBOR_BUCKET: &str = "rss-test-neighbor";
const MINIO_POLICY_NAME: &str = "rss-test-archive";

/// rabbitmqctl exec 有界重试（broker 起后 rabbitmqctl/epmd 短暂不可用窗口）。
const RABBITMQCTL_MAX_ATTEMPTS: u32 = 12;
const RABBITMQCTL_BACKOFF_MS: u64 = 500;

const CONTAINER_COMMAND_OUTPUT_LIMIT_BYTES: usize = 8 * 1024;

fn is_safe_label_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
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

mod runtime;
mod tls;
use tls::*;

mod minio;
mod postgres;
mod rabbitmq;
mod redis;
mod vault;

pub use minio::{MinioCredentials, MinioTlsFixture, minio_tls_archive};
pub use postgres::{
    ExternalPgFixture, OwnedPgFixture, OwnedPostgresRequired, PgAppRole, PgAppRoleSpec,
    PgConnParams, PgFixture, PgTlsFixture, PgTlsServerIdentity, env_or_postgres, owned_postgres,
    postgres_tls,
};
pub use rabbitmq::{RabbitFixture, RabbitTlsFixture, env_or_rabbitmq, rabbitmq_tls};
pub use redis::{RedisFixture, RedisTlsFixture, env_or_redis, redis_tls};
pub use vault::{VaultTlsFixture, vault_tls};

#[cfg(test)]
mod tests;
