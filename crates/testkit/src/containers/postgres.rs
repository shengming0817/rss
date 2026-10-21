use testcontainers::core::{IntoContainerPort as _, WaitFor};
use testcontainers::{ContainerAsync, CopyTargetOptions, GenericImage, ImageExt as _};

use super::{
    NetworkAttachment, PUBLISHED_PORT_MAX_ATTEMPTS, PUBLISHED_PORT_RETRY_BACKOFF_MS, Result,
    copied_tls_image, start_on_network, wait_published_port,
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

/// Starts PostgreSQL 17 with TLS required for every TCP client.
#[derive(Clone, Copy)]
pub enum PgTlsServerIdentity {
    /// SANs match fixture loopback and bridge addresses.
    MatchingHost,
    /// The certificate is trusted but its SANs match none of the fixture addresses.
    UnmatchedHost,
}

/// Starts PostgreSQL 17 with TLS required and an explicit test server-identity posture.
pub async fn postgres_tls(
    attachment: NetworkAttachment<'_>,
    identity: PgTlsServerIdentity,
) -> Result<PgTlsFixture> {
    postgres_image(
        attachment,
        identity,
        GenericImage::new(
            "postgres",
            "17.6@sha256:00bc86618629af00d2937fdc5a5d63db3ff8450acf52f0636ec813c7f4902929",
        ),
    )
    .await
}
/// Fixed TimescaleDB 2.30.2 / PG17 provider fixture, with the same TLS boundary.
pub async fn timescaledb_tls(
    attachment: NetworkAttachment<'_>,
    identity: PgTlsServerIdentity,
) -> Result<PgTlsFixture> {
    postgres_image(
        attachment,
        identity,
        GenericImage::new(
            "timescale/timescaledb",
            "2.30.2-pg17@sha256:b346edcdb51a1fd6020e3965e0bd1c9f3406fa6d5fbce1e28f4852587ef934e2",
        ),
    )
    .await
}
async fn postgres_image(
    attachment: NetworkAttachment<'_>,
    identity: PgTlsServerIdentity,
    image: GenericImage,
) -> Result<PgTlsFixture> {
    let material = super::tls::tls_material_for_host(
        attachment.dns_name,
        matches!(identity, PgTlsServerIdentity::MatchingHost),
    )?;
    let startup = b"#!/bin/sh\nset -eu\nchown postgres:postgres /rss-tls/server-key.pem\nchmod 600 /rss-tls/server-key.pem\nexec /usr/local/bin/docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/rss-tls/server.pem -c ssl_key_file=/rss-tls/server-key.pem -c ssl_min_protocol_version=TLSv1.2\n";
    let require_tls = b"#!/bin/sh\nset -eu\nsed -i -E 's/^host([[:space:]])/hostssl\\1/' \"$PGDATA/pg_hba.conf\"\n";
    let image = image
        .with_exposed_port(PG_PORT.tcp())
        .with_wait_for(WaitFor::message_on_stderr(
            "database system is ready to accept connections",
        ))
        .with_wait_for(WaitFor::message_on_stdout(
            "database system is ready to accept connections",
        ));
    let container = start_on_network(
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
    )
    .await?;
    let host = container.get_host().await?.to_string();
    // Query this same final server; on failure retain state before ordinary cleanup.
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
