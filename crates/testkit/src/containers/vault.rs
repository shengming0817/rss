use super::{
    ContainerAsync, GenericImage, ImageExt, IntoContainerPort, NetworkAttachment, Result, WaitFor,
    attach_network, runtime, vault_dev_tls_san_flags, wait_published_port,
};

const VAULT_PORT: u16 = 8200;
const VAULT_PORT_MAX_ATTEMPTS: u32 = 20;
const VAULT_PORT_RETRY_BACKOFF_MS: u64 = 500;
pub(super) const VAULT_IMAGE: &str = "hashicorp/vault";
pub(super) const VAULT_IMAGE_TAG: &str = "1.17.6";
const VAULT_ROOT_TOKEN: &str = "rss-test-vault-root";

// ── Vault TLS ─────────────────────────────────────────────

/// Hermetic, provider-neutral Vault dev-TLS fixture.
///
/// This fixture is owned here because the workspace confines raw `testcontainers` dependencies to
/// `testkit`. It must stay limited to container lifecycle and transport coordinates: SettingsOnly
/// or any other provider-specific mounts, policies, keys, tokens, and seed data belong in the
/// consuming integration test.
pub struct VaultTlsFixture {
    pub(super) _container: Box<ContainerAsync<GenericImage>>,
    pub(super) endpoint_url: String,
    pub(super) ca_pem: String,
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

pub(super) fn vault_host_endpoint(host: &str, port: u16) -> String {
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
    let container = runtime::start(request).await?;
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
