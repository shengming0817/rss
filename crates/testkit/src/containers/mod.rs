//! 真容器 fixtures（testcontainers 0.27）。
//!
//! The Make launcher owns shared AMQP/Kafka/MQTT containers across nextest processes.
//! Shared clients require its private descriptor; exclusive scenarios own the same constructors.
//!
//! **guard 须绑定到测试作用域结束**——其 `Drop` 停容器（提前 drop 后续连接失败）。
//! 不透明 guard 把 `testcontainers` 类型挡在消费方签名外（消费方只 name `testkit::{*Fixture,FixtureError}`）。
//!
//! 测试 fixture 不引 tracing——进度 / 失败经 testcontainers 自身日志 + fail-loud 错误冒泡可见
//! （reason: 引入 tracing 会拉 tracing subscriber 依赖、增加测试体初始化负担；container 日志由
//! testcontainers log_driver 自管，错误路径经 FixtureError 直接冒泡到测试输出）。
//!
//! ref: testcontainers/testcontainers-rs-modules-community modules/{postgres,redis,rabbitmq}

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use testcontainers::ImageExt;
use testcontainers::{ContainerAsync, CopyTargetOptions, GenericImage};

/// fixture 错误（容器起停 / 坐标解析 / env 解析）——dev/test 用，anyhow 以与任意测试返回类型组合。
pub type FixtureError = anyhow::Error;
type Result<T> = std::result::Result<T, FixtureError>;

/// 容器内固定端口（modules 镜像默认暴露端口）。
const PUBLISHED_PORT_MAX_ATTEMPTS: u32 = 3;
const PUBLISHED_PORT_RETRY_BACKOFF_MS: u64 = 100;
static BRIDGE_NETWORK_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Fixture-owned Docker network membership for TLS provider containers.
///
/// `network` is the user-defined bridge name; `dns_name` is an alias scoped to that network.
/// Docker assigns the global container identity. Host callers consume mapped endpoints.
#[derive(Clone, Copy, Debug)]
pub struct NetworkAttachment<'a> {
    pub network: &'a str,
    pub dns_name: &'a str,
}

/// Handle for a launcher-owned bridge network created by [`bridge_network`].
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

// Normal exclusive-fixture teardown releases address-pool capacity between serial tests.
// The launcher retains the final label sweep for cancellation or any failed release.
impl Drop for BridgeNetwork {
    #[allow(clippy::disallowed_methods)]
    // reason: a bounded destructor cannot depend on the test runtime still being alive.
    fn drop(&mut self) {
        let result = (|| -> std::io::Result<()> {
            let mut child = std::process::Command::new("docker")
                .args(["network", "rm", "-f", &self.name])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()?;
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            loop {
                let status = match child.try_wait() {
                    Ok(status) => status,
                    Err(error) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(error);
                    }
                };
                if let Some(status) = status {
                    return if status.success() {
                        Ok(())
                    } else {
                        Err(std::io::Error::other("Docker network removal failed"))
                    };
                }
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "Docker network removal deadline elapsed",
                    ));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        })();
        if let Err(error) = result {
            eprintln!(
                "testkit: network release id={} failed: {error}; launcher will sweep",
                self.name
            );
        }
    }
}

pub(super) const LAUNCHER_REQUIRED: &str = "fixture requires the Make launcher; from the workspace root run: make ci CI_PART=tests CI_FILTER='package(/-integration$/)'";

/// Creates a unique bridge with bounded normal release and launcher-owned fallback cleanup.
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
    let run = std::env::var("RSS_TEST_RUN_ID").map_err(|_| anyhow::anyhow!(LAUNCHER_REQUIRED))?;
    anyhow::ensure!(is_safe_label_token(&run), "invalid fixture run ID");
    command.args(["--label", &format!("rss.test-run={run}")]);
    command.arg(&name).kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(30), command.output()).await??;
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

async fn start_on_network<I: testcontainers::Image>(
    request: testcontainers::ContainerRequest<I>,
    attachment: NetworkAttachment<'_>,
) -> Result<ContainerAsync<I>> {
    validate_network_attachment(attachment)?;
    // testcontainers 0.27 has no network-alias request API. Keep the default bridge
    // and host-port publication, then attach the private network before exposing
    // the fixture. An attachment failure drops only this owned container.
    let provider = request.image().name().to_owned();
    let container = runtime::start(request).await?;
    let mut stage = runtime::Stage::new("network-attach", &provider, 0);
    let output = runtime::run_command_output(
        tokio::process::Command::new("docker").args([
            "network",
            "connect",
            "--alias",
            attachment.dns_name,
            attachment.network,
            container.id(),
        ]),
        "network-attach",
    )
    .await;
    stage.finish(matches!(&output, Ok(output) if output.exit_code == Some(0)));
    let output = output?;
    anyhow::ensure!(
        output.exit_code == Some(0),
        "fixture network attachment failed (category={}, exit={:?}, stderr_bytes={})",
        network_attachment_category(&output.stderr),
        output.exit_code,
        output.stderr.len()
    );
    Ok(container)
}

fn network_attachment_category(stderr: &str) -> &'static str {
    let message = stderr.to_ascii_lowercase();
    if message.contains("network") && message.contains("not found") {
        "network-missing"
    } else if message.contains("permission denied")
        || message.contains("cannot connect to the docker daemon")
    {
        "daemon-or-permission"
    } else if message.contains("endpoint") && message.contains("already exists") {
        "endpoint-conflict"
    } else {
        "unknown"
    }
}

#[test]
fn network_attachment_diagnostics_do_not_echo_daemon_secrets() {
    for (message, expected) in [
        ("network secret-network not found", "network-missing"),
        ("permission denied at secret-socket", "daemon-or-permission"),
        ("endpoint secret-name already exists", "endpoint-conflict"),
        ("unexpected secret-password", "unknown"),
    ] {
        assert_eq!(network_attachment_category(message), expected);
    }
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
            Err(error) => {
                if matches!(
                    error,
                    testcontainers::TestcontainersError::PortNotExposed { .. }
                ) {
                    let state = port_diagnostic::snapshot(container, port).await;
                    return Err(anyhow::Error::new(error).context(format!(
                        "published port lookup failed after {attempt} attempts: {state}"
                    )));
                }
                return Err(error.into());
            }
        }
    }
    Err(anyhow::anyhow!(
        "container port {port}/tcp was not exposed after {max_attempts} attempts: {last:?}"
    ))
}

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

mod port_diagnostic;
mod runtime;
mod tls;
use tls::*;

mod kafka;
mod postgres;
mod rabbitmq;
mod redis;

pub use kafka::{KafkaTlsFixture, KafkaTlsServerIdentity, exclusive_kafka_tls, shared_kafka_tls};
pub use postgres::{PgConnParams, PgTlsFixture, PgTlsServerIdentity, postgres_tls};
pub use rabbitmq::{
    RabbitFixture, RabbitTlsFixture, exclusive_rabbitmq, rabbitmq_tls, shared_rabbitmq,
};
pub use redis::{RedisFixture, managed_redis};

#[cfg(test)]
mod tests;

mod mqtt;
pub use mqtt::{MqttTlsFixture, exclusive_mqtt_tls, shared_mqtt_tls};

mod minio;
pub use minio::{MinioTlsFixture, minio_tls_archive};

mod launcher;
pub use launcher::launch;

mod descriptor;
