use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Duration;

use testcontainers::core::{CmdWaitFor, ExecCommand, IntoContainerPort, WaitFor};
use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use url::{Host, Url};

use super::runtime::run_container_command;
use super::{
    NetworkAttachment, RABBITMQCTL_BACKOFF_MS, RABBITMQCTL_MAX_ATTEMPTS, Result, attach_network,
    copied_tls_image, process_external_value, runtime, tls_material,
};

const AMQP_PORT: u16 = 5672;
const AMQPS_PORT: u16 = 5671;

// ── rabbitmq ─────────────────────────────────────────────────────────────---

/// rabbitmq fixture guard：持容器句柄（自起路径）到 `Drop`。**须绑定到测试结束**。
/// per-domain vhost 经 [`RabbitFixture::vhost_url`] 按需创建（同容器可建多 vhost，供跨 vhost 隔离测试）。
pub struct RabbitFixture {
    pub(super) inner: RabbitInner,
}

pub(super) enum RabbitInner {
    /// 自起容器：持句柄；`vhost_url` 经 rabbitmqctl 在该 broker 建 vhost。
    Container {
        container: Box<ContainerAsync<GenericImage>>,
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

    /// Managed-broker receipt for total queue depth, including at-least-once dead letters retained
    /// inside a source quorum queue while its target is unavailable. AMQP's passive queue-declare
    /// count exposes only ready messages, so this deliberately narrow fault-observation seam uses
    /// `rabbitmqctl list_queues` without exposing a raw management or broker handle.
    pub async fn broker_queue_total_depth(&self, vhost: &str, queue: &str) -> Result<u32> {
        validate_rabbit_vhost(vhost)?;
        if queue.is_empty()
            || queue.len() > 255
            || !queue.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_')
            })
        {
            return Err(anyhow::anyhow!(
                "RabbitMQ queue observation name is invalid"
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
                        "managed RabbitMQ vhost '{vhost}' must be created before queue observation"
                    ));
                }
                let output = run_rabbitmqctl_output(
                    container,
                    &[
                        "list_queues",
                        "-p",
                        vhost,
                        "name",
                        "messages",
                        "--formatter",
                        "json",
                    ],
                )
                .await?;
                let rows: serde_json::Value = serde_json::from_str(&output)?;
                rows.as_array()
                    .into_iter()
                    .flatten()
                    .find(|row| row.get("name").and_then(serde_json::Value::as_str) == Some(queue))
                    .and_then(|row| row.get("messages"))
                    .and_then(serde_json::Value::as_u64)
                    .and_then(|depth| u32::try_from(depth).ok())
                    .ok_or_else(|| anyhow::anyhow!("RabbitMQ queue observation was absent"))
            }
            RabbitInner::Env { .. } => Err(anyhow::anyhow!(
                "total quorum queue depth observation requires a managed RabbitMQ container"
            )),
        }
    }
}

pub(super) fn validate_rabbit_vhost(vhost: &str) -> Result<()> {
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
pub(super) fn validate_amqp_base_url(url: &str) -> Result<()> {
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

pub(super) fn is_loopback_url_host(parsed: &Url) -> bool {
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
    // Quorum queue TTL and at-least-once dead-lettering require RabbitMQ >= 3.10. Keep the plain
    // fixture on the exact same broker version as the private-CA fixture instead of inheriting the
    // testcontainers module's obsolete 3.8 default.
    let image = GenericImage::new("rabbitmq", "3.13.6-management-alpine")
        .with_exposed_port(AMQP_PORT.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Server startup complete"));
    let container = runtime::start(image).await?;
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

pub(super) const TLS_VHOST: &str = "rss_acl";
pub(super) const TLS_PUBLISHER_USER: &str = "rss_publisher";
pub(super) const TLS_PUBLISHER_PASSWORD: &str = "rss-publisher-test-password";
pub(super) const TLS_SUBSCRIBER_USER: &str = "rss_subscriber";
pub(super) const TLS_SUBSCRIBER_PASSWORD: &str = "rss-subscriber-test-password";
pub(super) const TLS_SHARED_USER: &str = "rss_shared";
pub(super) const TLS_SHARED_PASSWORD: &str = "rss-shared-test-password";

/// Hermetic RabbitMQ TLS fixture with distinct least-privilege publisher/subscriber identities.
pub struct RabbitTlsFixture {
    pub(super) container: Box<ContainerAsync<GenericImage>>,
    pub(super) publisher_url: String,
    pub(super) subscriber_url: String,
    pub(super) shared_url: String,
    pub(super) ca_pem: String,
    pub(super) wrong_ca_pem: String,
    pub(super) queue_pattern: String,
    pub(super) subscriber_configure_pattern: String,
    pub(super) subscriber_write_pattern: String,
    pub(super) subscriber_read_pattern: String,
    pub(super) subscriber_topic_write_pattern: String,
    pub(super) subscriber_topic_read_pattern: String,
}

impl RabbitTlsFixture {
    /// Managed-fixture queue depth for integration diagnostics and phase assertions.
    pub async fn broker_queue_total_depth(&self, queue: &str) -> Result<u32> {
        broker_queue_total_depth(&self.container, TLS_VHOST, queue).await
    }
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
                        self.subscriber_configure_pattern.as_str(),
                        self.subscriber_write_pattern.as_str(),
                        self.subscriber_read_pattern.as_str(),
                    ]
        });
        Ok(resource_exact
            && self
                .topic_permissions_are_exact(
                    TLS_SUBSCRIBER_USER,
                    &self.subscriber_topic_write_pattern,
                    &self.subscriber_topic_read_pattern,
                )
                .await?)
    }

    pub(super) async fn topic_permissions_are_exact(
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

async fn broker_queue_total_depth<I: testcontainers::Image>(
    container: &ContainerAsync<I>,
    vhost: &str,
    queue: &str,
) -> Result<u32> {
    let output =
        run_rabbitmqctl_output(container, &["list_queues", "-p", vhost, "name", "messages"])
            .await?;
    for line in output.lines() {
        let mut fields = line.split_whitespace();
        if fields.next() == Some(queue) {
            return fields
                .next()
                .ok_or_else(|| anyhow::anyhow!("RabbitMQ queue depth was absent"))?
                .parse()
                .map_err(Into::into);
        }
    }
    Err(anyhow::anyhow!("RabbitMQ queue observation was absent"))
}

pub(super) async fn provision_adjacent_rabbit_queue<I: testcontainers::Image>(
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

pub(super) async fn provision_rabbit_tls_permissions<I: testcontainers::Image>(
    container: &ContainerAsync<I>,
    queue_pattern: &str,
    subscriber_configure_pattern: &str,
    subscriber_write_pattern: &str,
    subscriber_read_pattern: &str,
    subscriber_topic_write_pattern: &str,
    subscriber_topic_read_pattern: &str,
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
            subscriber_configure_pattern,
            subscriber_write_pattern,
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
            subscriber_topic_write_pattern,
            subscriber_topic_read_pattern,
        ],
    )
    .await?;
    provision_rabbit_tls_shared_user(container).await
}

pub(super) async fn provision_rabbit_tls_shared_user<I: testcontainers::Image>(
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
    let subscriber_configure_pattern = format!("^({escaped_queue}|{escaped_queue}\\.dlq)$");
    // queue.bind needs write on both queues; x-dead-letter-exchange=amq.topic validation needs
    // exchange write. Exact topic permission below restricts that exchange write to only the DLQ
    // routing key, while DLQ consume/read remains absent.
    let subscriber_write_pattern = format!("^(amq\\.topic|{escaped_queue}|{escaped_queue}\\.dlq)$");
    let subscriber_read_pattern = format!("^(amq\\.topic|{escaped_queue})$");
    let subscriber_topic_write_pattern = format!("^{escaped_queue}\\.dlq$");
    let subscriber_topic_read_pattern = format!("^({escaped_queue}|{escaped_queue}\\.dlq)$");
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
    let container = runtime::start(request).await?;
    run_rabbitmqctl(&container, &["await_startup"]).await?;
    run_rabbitmqctl(&container, &["add_vhost", TLS_VHOST]).await?;
    provision_adjacent_rabbit_queue(&container, &adjacent_queue).await?;
    provision_rabbit_tls_permissions(
        &container,
        &queue_pattern,
        &subscriber_configure_pattern,
        &subscriber_write_pattern,
        &subscriber_read_pattern,
        &subscriber_topic_write_pattern,
        &subscriber_topic_read_pattern,
    )
    .await?;
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
        subscriber_configure_pattern,
        subscriber_write_pattern,
        subscriber_read_pattern,
        subscriber_topic_write_pattern,
        subscriber_topic_read_pattern,
    })
}

pub(super) fn validate_exact_queue_name(queue_name: &str) -> Result<()> {
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
pub(super) async fn create_vhost(
    container: &ContainerAsync<GenericImage>,
    vhost: &str,
) -> Result<()> {
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
pub(super) fn amqp_url_with_vhost(base: &str, vhost: &str) -> String {
    format!("{}/{vhost}", base.trim_end_matches('/'))
}

/// 容器内执行 `rabbitmqctl <args>`，有界重试（broker 起后 rabbitmqctl 短暂不可用）。
/// attempts + 线性 backoff：exec I/O **不计入**等待预算；末次失败不再 sleep（省末次空等）。
pub(super) async fn run_rabbitmqctl<I: testcontainers::Image>(
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

pub(super) async fn run_rabbitmqctl_output<I: testcontainers::Image>(
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
