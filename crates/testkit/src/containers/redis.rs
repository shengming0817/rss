use std::time::Duration;

use testcontainers::core::{IntoContainerPort as _, WaitFor};
use testcontainers::{ContainerAsync, GenericImage, ImageExt as _};
use testcontainers_modules::redis::{REDIS_PORT, Redis};

use super::{
    ContainerService, NetworkAttachment, PUBLISHED_PORT_MAX_ATTEMPTS,
    PUBLISHED_PORT_RETRY_BACKOFF_MS, Result, attach_network, copied_tls_image,
    force_remove_named_container, process_external_value, retry_published_port_resolution, runtime,
    tls_material, validate_redis_url,
};

const REDISS_PORT: u16 = 6379;

// ── redis ─────────────────────────────────────────────────────────────────-

/// redis fixture guard：持容器句柄（自起路径）到 `Drop` + `redis://` URL。**须绑定到测试结束**。
pub struct RedisFixture {
    pub(super) _container: Option<Box<ContainerAsync<Redis>>>,
    pub(super) url: String,
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
        let container = runtime::start(Redis::default(), ContainerService::Redis).await?;
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

/// Hermetic Redis TLS fixture. The guard owns the container until drop and exposes only typed
/// connection/trust material; no ambient TLS environment is consulted.
pub struct RedisTlsFixture {
    pub(super) _container: Box<ContainerAsync<GenericImage>>,
    pub(super) url: String,
    pub(super) ca_pem: String,
    pub(super) wrong_ca_pem: String,
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
        let container = runtime::start(request, ContainerService::Redis).await?;
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
