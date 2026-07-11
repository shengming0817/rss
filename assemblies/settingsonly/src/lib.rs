//! Minimal settings-only assembly.
//!
//! The crate deliberately has no launch entrypoint. It proves that the generated domain list and
//! the normal Cargo dependency graph can compose settings with its real Postgres and Vault
//! capabilities without pulling identity or audit into the deployable artifact.
//!
//! ref: oxidecomputer/omicron nexus/src/lib.rs@3298185e6cb3f6934a581122101e52988dc81895

use std::time::SystemTime;

use diport::KeyName;
use postgres::PgRuntimeDeps;
use vault::VaultRuntimeDeps;

#[path = "generated/modules_gen.rs"]
mod modules_gen;

/// Production system clock for the settings-only composition root.
///
/// The assembly root is the sanctioned direct clock read site (`diport::Clock` rustdoc: prod
/// `SystemClock` may call `SystemTime::now` under the clippy `disallowed_methods` allow).
pub struct SystemClock;

impl diport::Clock for SystemClock {
    fn now(&self) -> SystemTime {
        // reason: assembly-root production clock — only sanctioned direct system-clock read.
        #[allow(clippy::disallowed_methods)]
        SystemTime::now()
    }
}

/// Mandatory infrastructure inputs for the settings-only composition root.
pub struct SharedRuntimeDeps {
    pg: PgRuntimeDeps,
    vault: VaultRuntimeDeps,
    config_value_key_name: KeyName,
}

impl SharedRuntimeDeps {
    /// Construct the complete settings-only dependency set.
    #[must_use]
    pub fn new(pg: PgRuntimeDeps, vault: VaultRuntimeDeps, config_value_key_name: KeyName) -> Self {
        Self {
            pg,
            vault,
            config_value_key_name,
        }
    }
}

/// Wire the manifest-selected settings domain from the complete infrastructure dependency set.
///
/// # Errors
///
/// Returns an error when the settings KeyProvider startup self-check or domain construction fails.
pub async fn wire_domains(
    deps: &SharedRuntimeDeps,
) -> anyhow::Result<Vec<bootstrap::DomainBinding>> {
    modules_gen::wire_domains(deps).await
}

mod domains {
    pub(crate) mod settings {
        use std::sync::Arc;

        use bootstrap::DomainBinding;
        use settings_composition::SettingsModuleDeps;
        use vault::caps as vault_caps;

        use crate::{SharedRuntimeDeps, SystemClock};

        pub(crate) async fn module(deps: &SharedRuntimeDeps) -> anyhow::Result<DomainBinding> {
            settings_composition::wire(SettingsModuleDeps::new(
                deps.pg.for_domain(),
                deps.pg.readiness_handle(),
                deps.vault.for_domain::<vault_caps::Settings>(),
                deps.config_value_key_name.clone(),
                Arc::new(SystemClock),
            ))
            .await
        }

        #[cfg(test)]
        pub(crate) mod tests {
            use bootstrap::DomainBinding;

            pub(crate) async fn test_binding() -> anyhow::Result<DomainBinding> {
                settings_composition::test_support::binding().await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use base64::Engine as _;
    use bootstrap::compose_bindings;
    use postgres::PgRuntimeDeps;
    use settings_composition::{CONFIGS_READY_PROBE_NAME, KEYPROVIDER_READY_PROBE_NAME};
    use vault::{TenantStoreAllowlist, VaultKeyProvider, VaultRuntimeDeps, VaultSecretResolver};
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::SharedRuntimeDeps;

    const KEYPROVIDER_CONFIG_FIELD: &str = "settings.config.value";
    const KEYPROVIDER_CONFIG_SCHEME: u32 = 1;

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn generated_modules_wire_only_settings() {
        let mut bindings = crate::modules_gen::wire_test_domains()
            .await
            .expect("generated settings binding builds");
        assert_eq!(
            bindings
                .iter()
                .map(bootstrap::DomainBinding::name)
                .collect::<Vec<_>>(),
            ["settings"]
        );
        let (_, output) = compose_bindings(&mut bindings).expect("settings binding composes");
        assert!(bindings.is_empty());
        assert_eq!(output.probes.len(), 2);
        assert!(output.resources.is_empty());
        assert_eq!(output.workers.len(), 1);
    }

    #[allow(clippy::expect_used)]
    fn readiness_context_b64(tenant: &str) -> String {
        let tenant = vocab::TenantId::parse(tenant).expect("canonical readiness tenant");
        let aad = secure::ProtectionContext::authenticated_request(
            tenant,
            "readiness.probe",
            KEYPROVIDER_CONFIG_FIELD,
            KEYPROVIDER_CONFIG_SCHEME,
        )
        .expect("valid readiness aad")
        .derive();
        base64::engine::general_purpose::STANDARD.encode(aad.as_canonical_bytes())
    }

    async fn vault_with_readiness_mocks(server: &MockServer) -> anyhow::Result<VaultRuntimeDeps> {
        let readiness_context = readiness_context_b64("00000000-0000-4000-8000-000000000147");
        let mismatch_context = readiness_context_b64("00000000-0000-4000-8000-000000000148");
        Mock::given(method("POST"))
            .and(path("/v1/transit/encrypt/settings-config"))
            .and(body_partial_json(serde_json::json!({
                "context": readiness_context
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "ciphertext": "vault:v1:cnNzLWtleXByb3ZpZGVyLXJlYWR5",
                    "key_version": 1
                }
            })))
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/transit/decrypt/settings-config"))
            .and(body_partial_json(serde_json::json!({
                "context": mismatch_context
            })))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "errors": ["ciphertext verification failed"]
            })))
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/transit/decrypt/settings-config"))
            .and(body_partial_json(serde_json::json!({
                "context": readiness_context
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "plaintext": base64::engine::general_purpose::STANDARD.encode(b"rss-keyprovider-ready")
                }
            })))
            .mount(server)
            .await;

        let stores = TenantStoreAllowlist::new(std::iter::empty())?;
        Ok(VaultRuntimeDeps::new(
            VaultSecretResolver::new_allow_http(
                reqwest::Client::new(),
                server.uri(),
                "s.testtoken",
                Duration::from_secs(5),
                stores,
            )?,
            VaultKeyProvider::new_allow_http(
                reqwest::Client::new(),
                server.uri(),
                "s.testtoken",
                "transit",
                Duration::from_secs(5),
            )?,
        ))
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn public_wire_domains_composes_settings_from_shared_runtime_deps() {
        let vault_server = MockServer::start().await;
        let vault = vault_with_readiness_mocks(&vault_server)
            .await
            .expect("vault readiness mocks");
        let deps = SharedRuntimeDeps::new(
            PgRuntimeDeps::for_module_test(),
            vault,
            diport::KeyName::try_new("settings-config").expect("valid key name"),
        );

        let mut bindings = crate::wire_domains(&deps)
            .await
            .expect("public wire_domains succeeds");
        assert_eq!(
            bindings
                .iter()
                .map(bootstrap::DomainBinding::name)
                .collect::<Vec<_>>(),
            ["settings"]
        );
        let (_, output) = compose_bindings(&mut bindings).expect("settings binding composes");
        assert!(bindings.is_empty());
        assert_eq!(output.probes.len(), 2);
        assert_eq!(output.probes[0].0.as_str(), CONFIGS_READY_PROBE_NAME);
        assert_eq!(output.probes[1].0.as_str(), KEYPROVIDER_READY_PROBE_NAME);
        assert!(output.resources.is_empty());
        assert_eq!(output.workers.len(), 1);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn public_wire_domains_propagates_keyprovider_self_check_failure() {
        let vault_server = MockServer::start().await;
        // No Transit mocks: encrypt self-check must fail closed through the public entry.
        let stores = TenantStoreAllowlist::new(std::iter::empty()).expect("empty allowlist");
        let vault = VaultRuntimeDeps::new(
            VaultSecretResolver::new_allow_http(
                reqwest::Client::new(),
                vault_server.uri(),
                "s.testtoken",
                Duration::from_secs(5),
                stores,
            )
            .expect("http resolver"),
            VaultKeyProvider::new_allow_http(
                reqwest::Client::new(),
                vault_server.uri(),
                "s.testtoken",
                "transit",
                Duration::from_secs(5),
            )
            .expect("http key provider"),
        );
        let deps = SharedRuntimeDeps::new(
            PgRuntimeDeps::for_module_test(),
            vault,
            diport::KeyName::try_new("settings-config").expect("valid key name"),
        );

        let rendered = match crate::wire_domains(&deps).await {
            Ok(_) => "unexpected success".to_owned(),
            Err(err) => format!("{err:#}"),
        };
        assert!(
            rendered.contains("verify settings config value key provider")
                || rendered.contains("key provider readiness"),
            "unexpected error chain: {rendered}"
        );
    }
}
