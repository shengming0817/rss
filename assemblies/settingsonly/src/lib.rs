//! Executable settings-only assembly.
//!
//! This fail-closed production closure starts the real Settings providers. Federated credentials
//! enter one typed-permission funnel; Settings routes require an exact grant plus matching token,
//! principal and ambient tenants, while inventory requires only `runtime:inventory:read`.
//!
//! ref: oxidecomputer/omicron nexus/src/lib.rs@3298185e6cb3f6934a581122101e52988dc81895

use std::path::Path;
use std::time::SystemTime;

use diport::KeyName;
use postgres::PgRuntimeHandle;
use vault::VaultRuntimeDeps;

mod auth_bridge;
mod config;
mod dlx;
mod eventing;
mod inventory;
#[cfg(feature = "test-support")]
pub use inventory::test_support as runtime_inventory_test_support;
mod listeners;
mod plan;
mod projection;
mod providers;
mod readiness;
mod runtime;
#[cfg(feature = "test-support")]
pub mod test_support;

#[path = "generated/modules_gen.rs"]
mod modules_gen;
#[path = "generated/providers_gen.rs"]
mod providers_gen;
const _: () = assert!(!providers_gen::PROVIDER_CATALOG.is_empty());
pub use modules_gen::DOMAIN_LISTENER_BINDINGS;
/// The sole tracing profile admitted by the closed settingsonly deployment contract.
pub const TRACING_FILTER: &str = "info";

/// Start the executable settings-only assembly from one closed configuration document.
///
/// # Errors
///
/// Returns a redacted configuration, provider, composition, listener, or lifecycle error. All
/// resources accepted by the runtime are drained exactly once before the error is returned.
pub fn run(path: &Path) -> anyhow::Result<()> {
    let captured = config::capture(path)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| anyhow::anyhow!("build settingsonly Tokio runtime"))?;
    runtime.block_on(runtime::launch_captured(captured))
}

/// Production system clock for the settings-only composition root.
///
/// The assembly root is the sanctioned direct clock read site (`diport::Clock` rustdoc: prod
/// `SystemClock` may call `SystemTime::now` under the clippy `disallowed_methods` allow).
pub(crate) struct SystemClock;

impl diport::Clock for SystemClock {
    fn now(&self) -> SystemTime {
        // reason: assembly-root production clock — only sanctioned direct system-clock read.
        #[allow(clippy::disallowed_methods)]
        SystemTime::now()
    }
}

/// Mandatory infrastructure inputs for the settings-only composition root.
pub(crate) struct SharedRuntimeDeps {
    pg: PgRuntimeHandle,
    vault: VaultRuntimeDeps,
    config_value_key_name: KeyName,
    settings_readiness: settings_composition::SettingsReadinessDeps,
}

impl SharedRuntimeDeps {
    /// Construct the complete settings-only dependency set.
    #[cfg(test)]
    async fn new(
        pg: PgRuntimeHandle,
        vault: VaultRuntimeDeps,
        config_value_key_name: KeyName,
    ) -> anyhow::Result<Self> {
        let provider_readiness = settings_composition::SettingsProviderReadiness::new(
            &vault.for_domain::<vault::caps::Settings>(),
            config_value_key_name.clone(),
            settings_composition::KeyProviderReadinessInterval::default(),
        )
        .await?;
        let (pending, _key_output, _resolver_output) = provider_readiness.into_vault_parts();
        let (settings_readiness, _postgres_output) =
            pending.bind_postgres(pg.readiness_handle())?;
        Ok(Self {
            pg,
            vault,
            config_value_key_name,
            settings_readiness,
        })
    }

    fn production(
        pg: PgRuntimeHandle,
        vault: VaultRuntimeDeps,
        config_value_key_name: KeyName,
        settings_readiness: settings_composition::SettingsReadinessDeps,
    ) -> Self {
        Self {
            pg,
            vault,
            config_value_key_name,
            settings_readiness,
        }
    }
}

/// Wire the manifest-selected settings domain from the complete infrastructure dependency set.
///
/// # Errors
///
/// Returns an error when the settings KeyProvider startup self-check or domain construction fails.
async fn wire_domains(deps: &SharedRuntimeDeps) -> anyhow::Result<Vec<bootstrap::DomainBinding>> {
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
            settings_composition::wire(
                SettingsModuleDeps::new(
                    deps.pg.for_domain(),
                    deps.vault.for_domain::<vault_caps::Settings>(),
                    deps.config_value_key_name.clone(),
                    Arc::new(SystemClock),
                    deps.settings_readiness.clone(),
                )
                .config_cud_only(),
            )
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
    #![allow(clippy::expect_used)]
    // reason: closed assembly fixtures should stop at the first broken generated invariant.

    use std::time::Duration;

    use base64::Engine as _;
    use bootstrap::compose_bindings;
    use postgres::PgRuntimeHandle;
    use vault::{
        StoreBinding, TenantStoreAllowlist, VaultKeyProvider, VaultRuntimeDeps, VaultSecretResolver,
    };
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::SharedRuntimeDeps;

    const KEYPROVIDER_CONFIG_FIELD: &str = "settings.config.value";
    const KEYPROVIDER_CONFIG_SCHEME: u32 = 1;

    fn unused_tenant_store_allowlist() -> anyhow::Result<TenantStoreAllowlist> {
        Ok(TenantStoreAllowlist::new([(
            (
                vocab::TenantId::parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")?,
                "vault".to_owned(),
            ),
            StoreBinding {
                mount: "secret".to_owned(),
                kv_path_prefix: "tenants/a".to_owned(),
            },
        )])?)
    }

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
        assert!(output.probes.is_empty());
        assert!(output.resources.is_empty());
        assert!(output.workers.is_empty());
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

        let stores = unused_tenant_store_allowlist()?;
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
            PgRuntimeHandle::for_module_test(),
            vault,
            diport::KeyName::try_new("settings-config").expect("valid key name"),
        )
        .await
        .expect("settings readiness generation");

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
        let (mut registry, output) =
            compose_bindings(&mut bindings).expect("settings binding composes");
        assert!(bindings.is_empty());
        assert!(output.probes.is_empty());
        assert!(output.resources.is_empty());
        assert!(output.workers.is_empty());
        let routes = registry
            .finalize_routes()
            .expect("settingsonly config CUD routes finalize");
        let contracts = routes[0]
            .1
            .route_evidence()
            .iter()
            .map(vocab::HttpRouteEvidence::contract_id)
            .collect::<Vec<_>>();
        assert_eq!(
            contracts,
            [
                generated::http::settings_v1::CONTRACT_ID,
                generated::http::settings_v5::CONTRACT_ID,
                generated::http::settings_v6::CONTRACT_ID,
            ]
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn public_wire_domains_propagates_keyprovider_self_check_failure() {
        let vault_server = MockServer::start().await;
        // No Transit mocks: encrypt self-check must fail closed through the public entry.
        let stores = unused_tenant_store_allowlist().expect("valid unused fixture allowlist");
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
        let rendered = match SharedRuntimeDeps::new(
            PgRuntimeHandle::for_module_test(),
            vault,
            diport::KeyName::try_new("settings-config").expect("valid key name"),
        )
        .await
        {
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
