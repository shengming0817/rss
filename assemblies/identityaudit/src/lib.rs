//! Executable Identity + Audit production assembly.
//! ref: oxidecomputer/omicron nexus/src/lib.rs@cc4e95c57bdf029086c30d0e4c6cc930d75fa947

use std::sync::Arc;
use std::time::SystemTime;

use postgres::PgRuntimeHandle;
use primitives::MacKey;

mod auth_bridge;
mod config;
mod eventing;
mod framework_routes;
#[cfg(feature = "test-support")]
pub use framework_routes::test_support as runtime_inventory_test_support;
mod listeners;
#[path = "generated/modules_gen.rs"]
mod modules_gen;
mod plan;
mod providers;
#[path = "generated/providers_gen.rs"]
mod providers_gen;
mod runtime;
const _: () = assert!(!providers_gen::PROVIDER_CATALOG.is_empty());
pub use modules_gen::DOMAIN_LISTENER_BINDINGS;

/// Fixed tracing profile admitted by the closed deployment contract.
pub const TRACING_FILTER: &str = "info";

/// Capture a single closed configuration generation and launch until SIGINT/SIGTERM.
pub fn run(path: &std::path::Path) -> anyhow::Result<()> {
    let captured = config::capture(path)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| anyhow::anyhow!("build identityaudit Tokio runtime"))?;
    runtime.block_on(runtime::launch_captured(captured))
}

pub struct SystemClock;

impl diport::Clock for SystemClock {
    fn now(&self) -> SystemTime {
        // reason: assembly-root production clock — only sanctioned direct system-clock read.
        #[allow(clippy::disallowed_methods)]
        SystemTime::now()
    }
}

pub struct SharedRuntimeDeps {
    pg: PgRuntimeHandle,
    signer: Arc<vault::VaultSigner>,
    audit_chain_key: MacKey,
    identity_config: identity_composition::IdentityRuntimeConfig,
    blocklist: Arc<secure::DigestPasswordBlocklist>,
}

impl SharedRuntimeDeps {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn production(
        pg: PgRuntimeHandle,
        signer: Arc<vault::VaultSigner>,
        audit_chain_key: MacKey,
        identity_config: identity_composition::IdentityRuntimeConfig,
        blocklist: Arc<secure::DigestPasswordBlocklist>,
    ) -> Self {
        require_active_domains();
        Self {
            pg,
            signer,
            audit_chain_key,
            identity_config,
            blocklist,
        }
    }
}

async fn wire_domains(deps: &SharedRuntimeDeps) -> anyhow::Result<Vec<bootstrap::DomainBinding>> {
    modules_gen::wire_domains(deps).await
}

const _: () = {
    let _ = wire_domains;
};

fn require_active_domains() {
    fn require_domain<D: bootstrap::Domain>() {}
    require_domain::<identity::IdentityDomain<vault::VaultSigner>>();
    require_domain::<audit::AuditDomain<postgres::PgAuthAuditSink>>();
}

mod domains {
    pub(crate) mod identity {
        use std::sync::Arc;

        use bootstrap::DomainBinding;

        use crate::{SharedRuntimeDeps, SystemClock};

        pub(crate) async fn module(deps: &SharedRuntimeDeps) -> anyhow::Result<DomainBinding> {
            identity_composition::wire(identity_composition::IdentityModuleDeps::new(
                deps.pg.for_domain(),
                Arc::clone(&deps.signer),
                Arc::new(SystemClock),
                deps.identity_config.jwt_issuer_config()?,
                deps.identity_config.auth_grant_ttl(),
                deps.identity_config.refresh_ttl(),
                Arc::clone(&deps.blocklist),
            ))
        }

        #[cfg(test)]
        pub(crate) mod tests {
            use bootstrap::DomainBinding;

            pub(crate) async fn test_binding() -> anyhow::Result<DomainBinding> {
                identity_composition::test_support::binding()
            }
        }
    }

    pub(crate) mod audit {
        use std::sync::Arc;

        use bootstrap::DomainBinding;

        use crate::{SharedRuntimeDeps, SystemClock};

        pub(crate) async fn module(deps: &SharedRuntimeDeps) -> anyhow::Result<DomainBinding> {
            audit_composition::wire(audit_composition::AuditModuleDeps::new(
                deps.pg.for_domain(),
                crypto::RustCryptoMacVerifier,
                deps.audit_chain_key.clone(),
                Arc::new(SystemClock),
            ))
        }

        #[cfg(test)]
        pub(crate) mod tests {
            use bootstrap::DomainBinding;

            pub(crate) async fn test_binding() -> anyhow::Result<DomainBinding> {
                audit_composition::test_support::binding()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use bootstrap::compose_bindings;

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn generated_modules_wire_identity_and_audit_in_manifest_order() {
        let mut bindings = crate::modules_gen::wire_test_domains()
            .await
            .expect("generated identity/audit bindings build");
        assert_eq!(
            bindings
                .iter()
                .map(bootstrap::DomainBinding::name)
                .collect::<Vec<_>>(),
            ["identity", "audit"]
        );
        let (_, output) = compose_bindings(&mut bindings).expect("identity/audit domains compose");
        assert!(bindings.is_empty());
        assert!(output.probes.is_empty());
        assert!(output.resources.is_empty());
        assert!(output.workers.is_empty());
    }
}
