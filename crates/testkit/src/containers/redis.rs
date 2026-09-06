use std::time::Duration;

use testcontainers::core::{IntoContainerPort as _, WaitFor};
use testcontainers::{ContainerAsync, GenericImage};
pub(super) const REDIS_PORT: u16 = 6379;

use super::{
    PUBLISHED_PORT_MAX_ATTEMPTS, PUBLISHED_PORT_RETRY_BACKOFF_MS, Result,
    retry_published_port_resolution, runtime,
};

// ── redis ─────────────────────────────────────────────────────────────────-

/// redis fixture guard：持容器句柄（自起路径）到 `Drop` + `redis://` URL。**须绑定到测试结束**。
pub struct RedisFixture {
    pub(super) _container: Box<ContainerAsync<GenericImage>>,
    pub(super) url: String,
}

impl RedisFixture {
    /// `redis://host:port` 连接 URL。
    pub fn url(&self) -> &str {
        &self.url
    }
}

/// Starts an owned Redis container. Keep the guard alive for the entire scenario suite.
pub async fn managed_redis() -> Result<RedisFixture> {
    for attempt in 1..=PUBLISHED_PORT_MAX_ATTEMPTS {
        let image = GenericImage::new("redis", "7.4-alpine")
            .with_exposed_port(REDIS_PORT.tcp())
            .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"));
        let container = runtime::start(image).await?;
        let host = container.get_host().await?;
        match container.get_host_port_ipv4(REDIS_PORT).await {
            Ok(port) => {
                return Ok(RedisFixture {
                    _container: Box::new(container),
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
