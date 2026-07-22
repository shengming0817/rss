//! DLX destructive-lifecycle preflight owned by BuildInfra.

use crate::event_transport;
use crate::infra::s3::{S3DlxArchiveConfig, build_s3_dlx_archive_store};
use anyhow::Context as _;
use diport::{KeyProvider as _, RedactedBytes};
use std::sync::Arc;

/// Fully parsed, independent DLX lifecycle dependencies that do not require external I/O.
/// Startup capability probes consume this bundle only after every credential and key boundary has
/// passed fail-fast validation.
pub(crate) struct DlxLifecycleBootstrapConfig {
    pub(crate) archiver_pg: postgres::PgConfig,
    pub(crate) verifier_pg: postgres::PgConfig,
    pub(crate) purger_pg: postgres::PgConfig,
    pub(crate) archive_store: s3::S3DlxArchiveStore,
    pub(crate) hot_vault_provider: vault::VaultKeyProvider,
    pub(crate) archive_vault_provider: vault::VaultKeyProvider,
    pub(crate) hot_key: eventexec::DlxHotKeyName,
    pub(crate) archive_key: eventexec::DlxArchiveKeyName,
}

pub(crate) async fn build_dlx_lifecycle_bootstrap_config_from(
    archiver_pg: postgres::PgConfig,
    verifier_pg: postgres::PgConfig,
    purger_pg: postgres::PgConfig,
    s3_archive: S3DlxArchiveConfig,
    get: impl Fn(&str) -> Option<String>,
    clock: Arc<dyn diport::Clock>,
) -> anyhow::Result<DlxLifecycleBootstrapConfig> {
    let archive_key = event_transport::build_dlx_archive_key_name_from(&get)
        .context("build DLX archive key name")?;
    let hot_key = eventexec::DlxHotKeyName::try_new(
        get("RSS_DLX_PAYLOAD_KEY_NAME")
            .context("missing required env var: RSS_DLX_PAYLOAD_KEY_NAME")?,
    )
    .context("RSS_DLX_PAYLOAD_KEY_NAME is invalid")?;
    let (hot_vault_provider, archive_vault_provider) =
        event_transport::build_dlx_vault_key_providers_from(&get)
            .context("build independent DLX Vault key providers")?;
    let archive_store = build_s3_dlx_archive_store(s3_archive, clock)
        .await
        .context("build DLX archive S3 store")?;
    Ok(DlxLifecycleBootstrapConfig {
        archiver_pg,
        verifier_pg,
        purger_pg,
        archive_store,
        hot_vault_provider,
        archive_vault_provider,
        hot_key,
        archive_key,
    })
}

pub(crate) async fn verify_dlx_vault_key_capability(
    provider: &vault::VaultKeyProvider,
    key: &diport::KeyName,
    coordinate: &'static str,
) -> anyhow::Result<()> {
    const CANARY_TENANT: &str = "00000000-0000-4000-8000-000000001168";
    const CANARY_PLAINTEXT: &[u8] = b"rss-dlx-vault-capability-v1";
    let tenant = vocab::TenantId::parse(CANARY_TENANT).context("parse DLX canary tenant")?;
    let aad =
        secure::ProtectionContext::authorized_maintenance(tenant, coordinate, "startup-canary", 1)
            .context("derive DLX Vault canary AAD")?
            .derive();
    let wrong_aad = secure::ProtectionContext::authorized_maintenance(
        tenant,
        coordinate,
        "startup-canary-wrong-aad",
        1,
    )
    .context("derive DLX Vault wrong-AAD canary")?
    .derive();
    let encrypted = provider
        .encrypt(
            key.clone(),
            secure::Plaintext::new(CANARY_PLAINTEXT.to_vec()),
            aad.clone(),
        )
        .await
        .map_err(|_| anyhow::anyhow!("DLX Vault capability encrypt failed"))?;
    let ciphertext = encrypted.ciphertext().to_vec();
    let key_ref = encrypted.key().clone();
    let opened = provider
        .decrypt(RedactedBytes::new(ciphertext.clone()), key_ref.clone(), aad)
        .await
        .map_err(|_| anyhow::anyhow!("DLX Vault capability decrypt failed"))?;
    anyhow::ensure!(
        opened.expose() == CANARY_PLAINTEXT,
        "DLX Vault capability plaintext mismatch"
    );
    anyhow::ensure!(
        provider
            .decrypt(RedactedBytes::new(ciphertext), key_ref, wrong_aad)
            .await
            .is_err(),
        "DLX Vault capability accepted wrong AAD"
    );
    Ok(())
}
