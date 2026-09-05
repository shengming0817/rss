use testcontainers::core::{IntoContainerPort as _, WaitFor};
use testcontainers::{ContainerAsync, CopyTargetOptions, GenericImage, ImageExt as _};

use super::{
    NetworkAttachment, PUBLISHED_PORT_MAX_ATTEMPTS, PUBLISHED_PORT_RETRY_BACKOFF_MS, Result,
    attach_network, copied_tls_image, runtime, wait_published_port,
};

const PG_PORT: u16 = 5432;
const PG_DB: &str = "rss_test";
const PG_USER: &str = "postgres";
const PG_PASSWORD: &str = "postgres";

/// PostgreSQL fixture 连接参数，供消费者显式构造其 provider 配置。
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

/// Hermetic PostgreSQL TLS fixture. Only host-side coordinates and trust material are exposed.
pub struct PgTlsFixture {
    pub(super) _container: Box<ContainerAsync<GenericImage>>,
    pub(super) params: PgConnParams,
    pub(super) ca_pem: String,
    pub(super) wrong_ca_pem: String,
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
#[derive(Clone, Copy)]
pub enum PgTlsServerIdentity {
    /// SANs match fixture loopback and bridge addresses.
    MatchingHost,
    /// The certificate is trusted but its SANs match none of the fixture addresses.
    UnmatchedHost,
}

/// Starts PostgreSQL 16 with TLS required and an explicit test server-identity posture.
pub async fn postgres_tls(
    attachment: NetworkAttachment<'_>,
    identity: PgTlsServerIdentity,
) -> Result<PgTlsFixture> {
    let material = super::tls::tls_material_for_host(
        attachment.dns_name,
        matches!(identity, PgTlsServerIdentity::MatchingHost),
    )?;
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
    let container = runtime::start(request).await?;
    let host = container.get_host().await?.to_string();
    // Docker Desktop can publish port metadata after readiness; retry this same container.
    let port = wait_published_port(
        &container,
        PG_PORT,
        PUBLISHED_PORT_MAX_ATTEMPTS,
        PUBLISHED_PORT_RETRY_BACKOFF_MS,
    )
    .await?;
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
