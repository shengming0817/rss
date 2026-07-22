//! Command idempotency keyring parsing shared by BuildInfra.

use anyhow::Context as _;
use base64::Engine as _;
use std::sync::Arc;

pub(crate) const COMMAND_IDEMPOTENCY_KEYS_ENV: &str = "RSS_COMMAND_IDEMPOTENCY_KEYS_JSON";

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CommandAliasKeyConfig {
    id: String,
    key: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CommandIdempotencyKeyringConfig {
    current: CommandAliasKeyConfig,
    #[serde(default)]
    previous: Vec<CommandAliasKeyConfig>,
}

pub(crate) fn build_command_idempotency_keyring_from(
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<Arc<eventexec::command::CommandIdempotencyKeyring>> {
    let raw = get(COMMAND_IDEMPOTENCY_KEYS_ENV).ok_or_else(|| {
        anyhow::anyhow!("missing required env var: {COMMAND_IDEMPOTENCY_KEYS_ENV}")
    })?;
    let config: CommandIdempotencyKeyringConfig = serde_json::from_str(&raw)
        .with_context(|| format!("{COMMAND_IDEMPOTENCY_KEYS_ENV} must be valid keyring JSON"))?;
    let decode = |encoded: &str| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded.trim())
            .with_context(|| {
                format!("{COMMAND_IDEMPOTENCY_KEYS_ENV} keys must be base64url no-pad")
            })
    };
    let current_bytes = decode(&config.current.key)?;
    let previous_bytes = config
        .previous
        .iter()
        .map(|key| decode(&key.key))
        .collect::<anyhow::Result<Vec<_>>>()?;
    for reserved_env in [
        "RSS_TENANT_AUTHORITY_HMAC_KEY_B64URL",
        "RSS_AUDIT_CHAIN_KEY_B64URL",
    ] {
        let Some(reserved) = get(reserved_env) else {
            continue;
        };
        let Ok(reserved) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(reserved.trim())
        else {
            continue;
        };
        anyhow::ensure!(
            current_bytes != reserved && previous_bytes.iter().all(|key| key != &reserved),
            "{COMMAND_IDEMPOTENCY_KEYS_ENV} must not reuse {reserved_env} key material"
        );
    }

    let current = eventexec::command::CommandAliasKey::new(config.current.id, current_bytes)?;
    let previous = config
        .previous
        .into_iter()
        .zip(previous_bytes)
        .map(|(config, key)| eventexec::command::CommandAliasKey::new(config.id, key))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Arc::new(
        eventexec::command::CommandIdempotencyKeyring::new(current, previous)?,
    ))
}
