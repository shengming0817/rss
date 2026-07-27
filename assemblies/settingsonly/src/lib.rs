//! Executable settings-only assembly.
//!
//! This is a deliberately fail-closed deployment closure: it starts Settings with its real
//! Postgres, Vault and federated-verification providers, but it does not pretend that Identity or
//! Audit RBAC is present. Every authenticated Settings request is therefore rejected by the
//! assembly-owned authorizer after successful authentication.
//!
//! ref: oxidecomputer/omicron nexus/src/lib.rs@3298185e6cb3f6934a581122101e52988dc81895

use std::path::Path;
use std::time::SystemTime;

use diport::KeyName;
use postgres::PgRuntimeHandle;
use vault::VaultRuntimeDeps;

mod auth_bridge;
mod config;
mod deployment_facts;
mod inventory;
#[cfg(feature = "test-support")]
pub use inventory::test_support as runtime_inventory_test_support;
mod listeners;
mod plan;
mod providers;
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
    keyprovider_readiness: settings_composition::KeyProviderReadinessInterval,
}

impl SharedRuntimeDeps {
    /// Construct the complete settings-only dependency set.
    #[must_use]
    #[cfg(test)]
    fn new(pg: PgRuntimeHandle, vault: VaultRuntimeDeps, config_value_key_name: KeyName) -> Self {
        Self {
            pg,
            vault,
            config_value_key_name,
            keyprovider_readiness: settings_composition::KeyProviderReadinessInterval::default(),
        }
    }

    fn production(
        pg: PgRuntimeHandle,
        vault: VaultRuntimeDeps,
        config_value_key_name: KeyName,
        keyprovider_readiness: settings_composition::KeyProviderReadinessInterval,
    ) -> Self {
        Self {
            pg,
            vault,
            config_value_key_name,
            keyprovider_readiness,
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

fn validate_nonactivated_settings_subscriber(
    registry: &mut bootstrap::Registry,
) -> anyhow::Result<()> {
    let expected_event = generated::event::settings_v1::SPEC;
    anyhow::ensure!(
        expected_event.subscriptions().len() == 1,
        "settings event topology must contain exactly one declaration"
    );
    let mut declarations = registry.drain_subscribers().into_iter();
    let declaration = declarations
        .next()
        .ok_or_else(|| anyhow::anyhow!("settings subscriber declaration is missing"))?;
    anyhow::ensure!(
        declarations.next().is_none(),
        "settingsonly refuses extra subscriber declarations"
    );
    let (contract, topic, consumer, group, capability) = declaration.into_parts();
    validate_settings_subscriber_parts(contract, topic, consumer, group.as_str(), capability)
}

fn validate_settings_subscriber_parts(
    contract: &'static str,
    topic: &'static str,
    consumer: &'static str,
    group: &str,
    capability: bootstrap::SubscriberCapability,
) -> anyhow::Result<()> {
    let expected_event = generated::event::settings_v1::SPEC;
    let expected = expected_event
        .subscriptions()
        .first()
        .copied()
        .ok_or_else(|| anyhow::anyhow!("settings event topology has no declaration"))?;
    anyhow::ensure!(
        contract == expected_event.contract_id()
            && topic == expected_event.topic()
            && consumer == expected.consumer()
            && group == expected.group(),
        "settings subscriber declaration does not match generated topology"
    );
    let bootstrap::SubscriberCapability::DomainReconcile(owner) = capability else {
        anyhow::bail!("settings subscriber declaration has the wrong capability");
    };
    anyhow::ensure!(
        owner
            .into_owner::<settings::ConfigVersionReconciler>()
            .is_ok(),
        "settings subscriber declaration has the wrong reconcile owner"
    );
    // Deliberately consume and drop the capability. settingsonly validates the active topology
    // declaration but never activates a consumer or relay transport.
    Ok(())
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
                deps.keyprovider_readiness,
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
    #![allow(clippy::expect_used)]
    // reason: closed assembly fixtures should stop at the first broken generated invariant.

    use std::time::Duration;

    use base64::Engine as _;
    use bootstrap::compose_bindings;
    use postgres::PgRuntimeHandle;
    use settings_composition::{
        CONFIGS_READY_PROBE_NAME, KEYPROVIDER_READY_PROBE_NAME, SECRET_RESOLVER_READY_PROBE_NAME,
    };
    use vault::{
        StoreBinding, TenantStoreAllowlist, VaultKeyProvider, VaultRuntimeDeps, VaultSecretResolver,
    };
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::SharedRuntimeDeps;

    const KEYPROVIDER_CONFIG_FIELD: &str = "settings.config.value";
    const KEYPROVIDER_CONFIG_SCHEME: u32 = 1;

    #[tokio::test]
    async fn subscriber_declaration_accepts_only_the_exact_settings_owner() {
        let mut bindings = vec![
            crate::domains::settings::tests::test_binding()
                .await
                .expect("settings test binding"),
        ];
        let (mut registry, _output) = compose_bindings(&mut bindings).expect("compose settings");
        crate::validate_nonactivated_settings_subscriber(&mut registry)
            .expect("generated declaration and concrete owner match");
    }

    #[test]
    fn subscriber_declaration_rejects_missing_extra_identity_and_capability() {
        let mut empty = bootstrap::Registry::new();
        assert!(crate::validate_nonactivated_settings_subscriber(&mut empty).is_err());

        let event = generated::event::settings_v1::SPEC;
        let subscription = event.subscriptions()[0];
        let group = subscription.group();
        assert!(
            crate::validate_settings_subscriber_parts(
                "wrong.contract",
                event.topic(),
                subscription.consumer(),
                group,
                bootstrap::SubscriberCapability::AdapterNativeTransactional,
            )
            .is_err()
        );
        assert!(
            crate::validate_settings_subscriber_parts(
                event.contract_id(),
                event.topic(),
                subscription.consumer(),
                group,
                bootstrap::SubscriberCapability::AdapterNativeTransactional,
            )
            .is_err()
        );
        assert!(
            crate::validate_settings_subscriber_parts(
                event.contract_id(),
                event.topic(),
                subscription.consumer(),
                group,
                bootstrap::SubscriberCapability::DomainReconcile(
                    bootstrap::ReconcileSubscriberOwner::from_owner("wrapper owner"),
                ),
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn subscriber_declaration_rejects_an_extra_registration() {
        let mut bindings = vec![
            crate::domains::settings::tests::test_binding()
                .await
                .expect("settings test binding"),
        ];
        let (mut registry, _output) = compose_bindings(&mut bindings).expect("compose settings");
        registry
            .subscriber(
                "extra.contract",
                "extra.topic",
                "settings",
                consistency::ConsumerGroup::parse("settings.extra").expect("fixed group"),
                bootstrap::SubscriberCapability::AdapterNativeTransactional,
            )
            .expect("register synthetic extra declaration");
        assert!(crate::validate_nonactivated_settings_subscriber(&mut registry).is_err());
    }

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
        assert_eq!(output.probes.len(), 3);
        assert!(output.resources.is_empty());
        assert_eq!(output.workers.len(), 2);
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
        assert_eq!(output.probes.len(), 3);
        assert_eq!(output.probes[0].0.as_str(), CONFIGS_READY_PROBE_NAME);
        assert_eq!(output.probes[1].0.as_str(), KEYPROVIDER_READY_PROBE_NAME);
        assert_eq!(
            output.probes[2].0.as_str(),
            SECRET_RESOLVER_READY_PROBE_NAME
        );
        assert!(output.resources.is_empty());
        assert_eq!(output.workers.len(), 2);
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
        let deps = SharedRuntimeDeps::new(
            PgRuntimeHandle::for_module_test(),
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
