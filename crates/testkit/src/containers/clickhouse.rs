//! Fixed single-node ClickHouse fixture and its real PostgreSQL TLS guard seam.
use super::{
    NetworkAttachment, PUBLISHED_PORT_MAX_ATTEMPTS, PUBLISHED_PORT_RETRY_BACKOFF_MS, Result,
    copied_tls_image, start_on_network, wait_published_port,
};
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt,
    core::{ExecCommand, IntoContainerPort, WaitFor},
};
use tokio::io::AsyncReadExt;
/// Owns the server; PostgreSQL and the private bridge are owned by the caller.
pub struct ClickHouseFixture {
    container: ContainerAsync<GenericImage>,
    endpoint: String,
    ca: String,
}
impl ClickHouseFixture {
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
    pub fn ca_pem(&self) -> &str {
        &self.ca
    }
    /// Only fixture-owned SQL. Provider errors are redacted; successful bounded query output is returned.
    pub async fn sql(&self, query: &str) -> Result<String> {
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            let mut exec = self
                .container
                .exec(ExecCommand::new([
                    "clickhouse-client",
                    "--multiquery",
                    "--query",
                    query,
                ]))
                .await?;
            let mut out = Vec::new();
            exec.stdout()
                .take(4 * 1024 * 1024 + 1)
                .read_to_end(&mut out)
                .await?;
            let mut err = Vec::new();
            exec.stderr().take(8192).read_to_end(&mut err).await?;
            anyhow::ensure!(
                out.len() <= 4 * 1024 * 1024,
                "ClickHouse fixture output budget"
            );
            anyhow::ensure!(
                exec.exit_code().await? == Some(0),
                "ClickHouse fixture SQL failed (stderr_bytes={})",
                err.len()
            );
            Ok(String::from_utf8(out)?)
        })
        .await?
    }
    pub async fn restart(&self) -> Result<()> {
        self.container.stop().await?;
        self.container.start().await?;
        Ok(())
    }
}
/// Named collection uses a payload-free view and PGSSLMODE=verify-full. The host
/// name is a fixture-owned private bridge alias, never a product connection string.
pub async fn clickhouse_tls(
    attachment: NetworkAttachment<'_>,
    pg_host: &str,
    pg_ca: &str,
) -> Result<ClickHouseFixture> {
    anyhow::ensure!(super::is_safe_label_token(pg_host), "invalid guard host");
    let material = super::tls::tls_material(attachment.dns_name)?;
    let config = format!(
        r#"<clickhouse>
<listen_host>0.0.0.0</listen_host><http_port remove="1"/><https_port>8443</https_port>
<openSSL><server><certificateFile>/rss-tls/server.pem</certificateFile><privateKeyFile>/rss-tls/server-key.pem</privateKeyFile><verificationMode>none</verificationMode></server></openSSL>
<logger><level>information</level><console>true</console></logger>
<max_server_memory_usage>1073741824</max_server_memory_usage>
<named_collections><rss_ts_ch_guard><host>{pg_host}</host><port>5432</port><database>rss_test</database><user>ch_guard</user><password>fixture-only</password></rss_ts_ch_guard></named_collections>
</clickhouse>"#
    );
    let users = r#"<clickhouse><users><default><networks replace="replace"><ip>127.0.0.1</ip><ip>::1</ip></networks><access_management>1</access_management><named_collection_control>1</named_collection_control><show_named_collections>1</show_named_collections></default></users></clickhouse>"#;
    let image = GenericImage::new(
        "clickhouse/clickhouse-server",
        "25.8.12.129@sha256:356f0bbb1c4bade74ca32637e944d8f42109d18f13c51f991ba334f0f0749d20",
    )
    .with_exposed_port(8443.tcp())
    .with_wait_for(WaitFor::message_on_stderr("Ready for connections"));
    let request = copied_tls_image(image, &material)
        .with_env_var("HOME", "/var/lib/clickhouse")
        .with_env_var("PGSSLMODE", "verify-full")
        .with_env_var("PGSSLROOTCERT", "/rss-tls/pg-ca.pem")
        .with_copy_to("/rss-tls/pg-ca.pem", pg_ca.as_bytes().to_vec())
        .with_copy_to(
            "/etc/clickhouse-server/config.d/rss.xml",
            config.into_bytes(),
        )
        .with_copy_to(
            "/etc/clickhouse-server/users.d/rss.xml",
            users.as_bytes().to_vec(),
        );
    let container = start_on_network(request, attachment).await?;
    let port = wait_published_port(
        &container,
        8443,
        PUBLISHED_PORT_MAX_ATTEMPTS,
        PUBLISHED_PORT_RETRY_BACKOFF_MS,
    )
    .await?;
    let endpoint = format!("https://{}:{port}", container.get_host().await?);
    Ok(ClickHouseFixture {
        container,
        endpoint,
        ca: material.ca_pem,
    })
}
