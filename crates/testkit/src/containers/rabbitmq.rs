use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use testcontainers::core::{CmdWaitFor, ExecCommand, IntoContainerPort, WaitFor};
use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use tokio::sync::OnceCell;

use super::runtime::run_container_command;
use super::{
    NetworkAttachment, PUBLISHED_PORT_MAX_ATTEMPTS, PUBLISHED_PORT_RETRY_BACKOFF_MS,
    RABBITMQCTL_BACKOFF_MS, RABBITMQCTL_MAX_ATTEMPTS, Result, attach_network, copied_tls_image,
    runtime, tls_material, wait_published_port,
};

const AMQP_PORT: u16 = 5672;
const AMQPS_PORT: u16 = 5671;

// ── rabbitmq ─────────────────────────────────────────────────────────────---

/// Owns one temporary broker. Suites isolate scenarios with fixture-created vhosts.
pub struct RabbitFixture {
    container: Box<ContainerAsync<GenericImage>>,
    host: String,
    port: u16,
    created: Vhosts,
}

// The map lock only protects cell lookup; each vhost has its own fallible initialization.
// ref: tokio 1.52.3 sync/once_cell.rs get_or_try_init (error/cancellation releases the permit).
#[derive(Default)]
struct Vhosts(Mutex<HashMap<String, Arc<OnceCell<()>>>>);

impl Vhosts {
    async fn ensure_created<F, Fut>(&self, vhost: &str, create: F) -> Result<()>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<()>>,
    {
        let cell = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("vhost cache poisoned"))?
            .entry(vhost.to_owned())
            .or_default()
            .clone();
        cell.get_or_try_init(create).await?;
        Ok(())
    }

    fn is_ready(&self, vhost: &str) -> Result<bool> {
        Ok(self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("vhost cache poisoned"))?
            .get(vhost)
            .is_some_and(|cell| cell.initialized()))
    }
}

#[cfg(test)]
mod tests;

impl RabbitFixture {
    /// Creates a vhost once on this owned broker and returns its loopback test endpoint.
    /// Concurrent callers share initialization of the same vhost, including permissions.
    /// Failed or cancelled initialization can be retried; other vhosts initialize independently.
    pub async fn vhost_url(&self, vhost: &str) -> Result<String> {
        validate_rabbit_vhost(vhost)?;
        self.created
            .ensure_created(vhost, || create_vhost(&self.container, vhost))
            .await?;
        Ok(format!(
            "amqp://guest:guest@{}:{}/{vhost}",
            self.host, self.port
        ))
    }

    fn require_vhost(&self, vhost: &str) -> Result<()> {
        validate_rabbit_vhost(vhost)?;
        anyhow::ensure!(
            self.created.is_ready(vhost)?,
            "broker observation requires a fixture-created vhost"
        );
        Ok(())
    }

    /// Closes a connection from the broker side, scoped to a fixture-created vhost.
    pub async fn broker_force_close_one_connection(&self, vhost: &str, reason: &str) -> Result<()> {
        self.require_vhost(vhost)?;
        anyhow::ensure!(
            !reason.is_empty() && !reason.contains('\0'),
            "RabbitMQ forced-close reason must be non-empty and contain no NUL"
        );
        run_rabbitmqctl(
            &self.container,
            &["close_all_connections", "-p", vhost, "--limit", "1", reason],
        )
        .await
    }

    /// Observes actual broker registrations, excluding cancelled consumers holding unacked messages.
    pub async fn broker_consumer_count(&self, vhost: &str, queue: &str) -> Result<usize> {
        self.require_vhost(vhost)?;
        validate_exact_queue_name(queue)?;
        let output = run_rabbitmqctl_output(
            &self.container,
            &[
                "list_consumers",
                "-p",
                vhost,
                "queue_name",
                "--formatter",
                "json",
            ],
        )
        .await?;
        let rows: serde_json::Value = serde_json::from_str(&output)?;
        let rows = rows
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("invalid broker consumer list"))?;
        Ok(rows
            .iter()
            .filter(|row| row.get("queue_name").and_then(serde_json::Value::as_str) == Some(queue))
            .count())
    }

    /// Includes dead letters retained by a source quorum queue while its target is unavailable.
    pub async fn broker_queue_total_depth(&self, vhost: &str, queue: &str) -> Result<u32> {
        self.require_vhost(vhost)?;
        validate_exact_queue_name(queue)?;
        let output = run_rabbitmqctl_output(
            &self.container,
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

/// Start an owned broker for fault injection and management observations.
pub async fn managed_rabbitmq() -> Result<RabbitFixture> {
    // Quorum queue TTL and at-least-once dead-lettering require RabbitMQ >= 3.10. Keep the plain
    // fixture on the exact same broker version as the private-CA fixture instead of inheriting the
    // testcontainers module's obsolete 3.8 default.
    let image = GenericImage::new("rabbitmq", "3.13.6-management-alpine")
        .with_exposed_port(AMQP_PORT.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Server startup complete"));
    let container = runtime::start(image).await?;
    let host = container.get_host().await?.to_string();
    let port = wait_published_port(
        &container,
        AMQP_PORT,
        PUBLISHED_PORT_MAX_ATTEMPTS,
        PUBLISHED_PORT_RETRY_BACKOFF_MS,
    )
    .await?;
    Ok(RabbitFixture {
        container: Box::new(container),
        host,
        port,
        created: Vhosts::default(),
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

// Management credentials belong to this temporary fixture, never to the adapter subscriber.
async fn provision_delivery_fixture<I: testcontainers::Image>(
    container: &ContainerAsync<I>,
    queue: &str,
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
    let dlq = format!("{queue}.dlq");
    for (name, source) in [(dlq.as_str(), false), (queue, true)] {
        let mut arguments = serde_json::json!({"x-queue-type": "quorum"});
        if source {
            arguments["x-dead-letter-exchange"] = "amq.topic".into();
            arguments["x-dead-letter-routing-key"] = dlq.clone().into();
            arguments["x-dead-letter-strategy"] = "at-least-once".into();
            arguments["x-overflow"] = "reject-publish".into();
        }
        let name_arg = format!("name={name}");
        let arguments_arg = format!("arguments={arguments}");
        run_container_command(
            container,
            "provision TLS delivery fixture queue",
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
                &name_arg,
                "durable=true",
                &arguments_arg,
            ],
        )
        .await?;
        let destination = format!("destination={name}");
        let routing_key = format!("routing_key={name}");
        run_container_command(
            container,
            "bind TLS delivery fixture queue",
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
                &destination,
                &routing_key,
            ],
        )
        .await?;
    }
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
    let subscriber_configure_pattern = "^$".to_owned();
    let subscriber_write_pattern = "^$".to_owned();
    let subscriber_read_pattern = queue_pattern.clone();
    let subscriber_topic_write_pattern = "^$".to_owned();
    let subscriber_topic_read_pattern = "^$".to_owned();
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
    provision_delivery_fixture(&container, queue_name).await?;
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
    let port = wait_published_port(
        &container,
        AMQPS_PORT,
        PUBLISHED_PORT_MAX_ATTEMPTS,
        PUBLISHED_PORT_RETRY_BACKOFF_MS,
    )
    .await?;
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

/// Fixture management has one execution budget, including CLI startup, Docker I/O and backoff.
/// BusyBox timeout also terminates a stuck CLI process inside the owned container.
/// ref: BusyBox 1.36.1 timeout; tokio time::timeout cancellation semantics.
pub(super) async fn run_rabbitmqctl<I: testcontainers::Image>(
    container: &ContainerAsync<I>,
    args: &[&str],
) -> Result<()> {
    run_rabbitmqctl_output(container, args).await.map(|_| ())
}

pub(super) async fn run_rabbitmqctl_output<I: testcontainers::Image>(
    container: &ContainerAsync<I>,
    args: &[&str],
) -> Result<String> {
    tokio::time::timeout(
        Duration::from_secs(40),
        rabbitmqctl_attempts(container, args),
    )
    .await
    .map_err(|_| anyhow::anyhow!("RabbitMQ fixture management deadline elapsed"))?
}

async fn rabbitmqctl_attempts<I: testcontainers::Image>(
    container: &ContainerAsync<I>,
    args: &[&str],
) -> Result<String> {
    let command = ["timeout", "-s", "KILL", "10", "rabbitmqctl"]
        .into_iter()
        .chain(args.iter().copied())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let mut last_exit = None;
    for attempt in 0..RABBITMQCTL_MAX_ATTEMPTS {
        let mut result = container
            .exec(ExecCommand::new(command.clone()).with_cmd_ready_condition(CmdWaitFor::exit()))
            .await?;
        last_exit = result.exit_code().await?;
        if last_exit == Some(0) {
            return String::from_utf8(result.stdout_to_vec().await?).map_err(Into::into);
        }
        if attempt + 1 < RABBITMQCTL_MAX_ATTEMPTS {
            crate::await_delay(Duration::from_millis(
                RABBITMQCTL_BACKOFF_MS * u64::from(attempt + 1),
            ))
            .await;
        }
    }
    Err(anyhow::anyhow!(
        "RabbitMQ fixture management failed after bounded attempts (exit={last_exit:?})"
    ))
}
