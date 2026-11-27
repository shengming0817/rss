//! Real HTTPS OpenID Connect fixture. The caller supplies its realm and reachable private address.
use super::{CopyTargetOptions, GenericImage, ImageExt, Result};
use std::{net::Ipv4Addr, time::Duration};
use testcontainers::{
    ContainerAsync,
    core::{IntoContainerPort, WaitFor},
};

/// Owns the container for the lifetime of its public endpoint.
pub struct KeycloakFixture {
    _container: ContainerAsync<GenericImage>,
    pub origin: String,
    pub ca_pem: String,
}
/// Start pinned Keycloak with a disposable TLS key and the suite's realm.
pub async fn keycloak_tls(
    host: Ipv4Addr,
    explicit_host: bool,
    realm_json: &[u8],
) -> Result<KeycloakFixture> {
    anyhow::ensure!(
        host.is_private(),
        "Keycloak publish address must be RFC1918"
    );
    let tls = rcgen::generate_simple_self_signed(vec![host.to_string()])?;
    let ca = tls.cert.pem();
    let request = GenericImage::new(
        "quay.io/keycloak/keycloak",
        "26.7.3@sha256:ff4257d0d64efbe99ed1ddfaf07765cc3c36dc7518bf8324d41961327f441c54",
    )
    .with_exposed_port(8443.tcp())
    .with_wait_for(WaitFor::message_on_stdout("Listening on:"))
    .with_copy_to("/opt/keycloak/data/import/realm.json", realm_json.to_vec())
    .with_copy_to("/opt/keycloak/conf/tls.crt", ca.as_bytes().to_vec())
    .with_copy_to(
        CopyTargetOptions::new("/opt/keycloak/conf/tls.key").with_mode(0o644),
        tls.signing_key.serialize_pem().into_bytes(),
    )
    .with_cmd([
        "start-dev",
        "--import-realm",
        "--http-enabled=false",
        "--hostname-strict=false",
        "--https-certificate-file=/opt/keycloak/conf/tls.crt",
        "--https-certificate-key-file=/opt/keycloak/conf/tls.key",
    ])
    .with_startup_timeout(Duration::from_secs(90));
    let keycloak = super::runtime::start(request).await?;
    let docker_host = keycloak.get_host().await?;
    anyhow::ensure!(
        explicit_host
            || matches!(
                docker_host.to_string().as_str(),
                "localhost" | "127.0.0.1" | "::1"
            ),
        "set IDENTITY_TEST_PRIVATE_HOST to the reachable RFC1918 publish address of the remote Docker daemon"
    );
    let port = super::wait_published_port(
        &keycloak,
        8443,
        super::PUBLISHED_PORT_MAX_ATTEMPTS,
        super::PUBLISHED_PORT_RETRY_BACKOFF_MS,
    )
    .await?;
    Ok(KeycloakFixture {
        _container: keycloak,
        origin: format!("https://{host}:{port}"),
        ca_pem: ca,
    })
}
