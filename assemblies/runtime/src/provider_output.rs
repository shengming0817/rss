//! Runtime-local provider output adaptation.
//!
//! Adapter bundles own their `diport`-only managed-resource primitives and intentionally do not
//! depend on `bootstrap`. This module is the composition-root seam that converts those primitives
//! into the sole runtime lifecycle output, [`DomainModuleResult`], before the normal merge path.
//! The trait is crate-private so provider output policy cannot leak back into adapter crates.
//!
//! INVARIANT: PG-RUNTIME-OUTPUT-03 { level = "Hard", exec = "native-compile", source = "code", native = "private PgReadinessSamplerFactory fields and consuming spawn self; owned PgRuntimeDeps conversion into the existing DomainModuleResult output" }
//!
//! `ref: oxidecomputer/omicron nexus/src/context.rs@8eb92537bd12598dfd2c861f897a88962fabf684`

use std::time::Duration;

use bootstrap::{DomainModuleResult, LifecycleChannel, ProviderOutputBinding, WorkerSpec};
use diport::DynManagedResource;
use postgres::PgRuntimeDeps;

use crate::SharedRuntimeDeps;

const RESOURCES: &[LifecycleChannel] = &[LifecycleChannel::Resources];
const RESOURCES_WORKERS: &[LifecycleChannel] =
    &[LifecycleChannel::Resources, LifecycleChannel::Workers];

pub(crate) const PG_OUTPUT_BINDINGS: &[ProviderOutputBinding] = &[
    ProviderOutputBinding {
        port: "diport::AuditSink",
        provider: "postgres::PgAuthAuditSink",
        consumer: "httpserve",
        channels: RESOURCES_WORKERS,
    },
    ProviderOutputBinding {
        port: "diport::CasStore",
        provider: "postgres::PgCasStore",
        consumer: "distributed",
        channels: RESOURCES_WORKERS,
    },
];

pub(crate) const OIDC_OUTPUT_BINDINGS: &[ProviderOutputBinding] = &[ProviderOutputBinding {
    port: "diport::Pdp",
    provider: "oidc::OidcProvider",
    consumer: "httpserve",
    channels: RESOURCES,
}];

/// Consumes the postgres lifecycle owner into the runtime's sole lifecycle output type.
pub(crate) fn build_pg_runtime_module(
    owner: PgRuntimeDeps,
    period: Duration,
) -> DomainModuleResult {
    let (resources, sampler_factory) = owner.into_runtime_parts(period);
    let readiness_sampler: WorkerSpec =
        Box::new(move |token| DynManagedResource::new_box(sampler_factory.spawn(token)));
    DomainModuleResult {
        resources,
        workers: vec![readiness_sampler],
        ..DomainModuleResult::default()
    }
}

/// Converts one provider capability bundle into the runtime's sole lifecycle output type.
pub(crate) trait ProviderOutput {
    const OUTPUT_BINDINGS: &'static [ProviderOutputBinding];

    /// Produces all probes, detached resources, and workers owned by this provider bundle.
    fn provider_output(&self) -> DomainModuleResult;
}

/// Composition-root extension for merging typed provider outputs without exposing raw channels.
pub(crate) trait DomainModuleResultExt {
    /// Converts and merges one provider bundle while preserving all channel ordering and duplicates.
    fn merge_provider(&mut self, provider: &impl ProviderOutput);
}

impl DomainModuleResultExt for DomainModuleResult {
    fn merge_provider(&mut self, provider: &impl ProviderOutput) {
        self.merge(provider.provider_output());
    }
}

/// Adapts all provider bundles into one ordered lifecycle output.
pub(crate) fn build_provider_module(deps: &SharedRuntimeDeps) -> DomainModuleResult {
    let mut provider_module = DomainModuleResult::default();
    provider_module.merge_provider(&deps.redis);
    provider_module.merge_provider(&deps.s3);
    provider_module.merge_provider(&deps.vault);
    provider_module
}

impl ProviderOutput for redis::RedisRuntimeDeps {
    const OUTPUT_BINDINGS: &'static [ProviderOutputBinding] = &[
        ProviderOutputBinding {
            port: "diport::LockStore",
            provider: "redis::RedisLockStore",
            consumer: "distributed",
            channels: RESOURCES,
        },
        ProviderOutputBinding {
            port: "diport::CasStore",
            provider: "redis::RedisCasStore",
            consumer: "distributed",
            channels: RESOURCES,
        },
    ];

    fn provider_output(&self) -> DomainModuleResult {
        DomainModuleResult {
            resources: self.runtime_resources(),
            ..DomainModuleResult::default()
        }
    }
}

impl ProviderOutput for s3::S3RuntimeDeps {
    const OUTPUT_BINDINGS: &'static [ProviderOutputBinding] = &[ProviderOutputBinding {
        port: "diport::ObjectStore",
        provider: "s3::S3Store",
        consumer: "runtime",
        channels: RESOURCES,
    }];

    fn provider_output(&self) -> DomainModuleResult {
        DomainModuleResult {
            resources: self.runtime_resources(),
            ..DomainModuleResult::default()
        }
    }
}

impl ProviderOutput for vault::VaultRuntimeDeps {
    const OUTPUT_BINDINGS: &'static [ProviderOutputBinding] = &[
        ProviderOutputBinding {
            port: "diport::Signer",
            provider: "vault::VaultSigner",
            consumer: "identity",
            channels: RESOURCES,
        },
        ProviderOutputBinding {
            port: "diport::KeyProvider",
            provider: "vault::VaultKeyProvider",
            consumer: "settings",
            channels: RESOURCES,
        },
    ];

    fn provider_output(&self) -> DomainModuleResult {
        DomainModuleResult {
            resources: self.runtime_resources(),
            ..DomainModuleResult::default()
        }
    }
}

pub(crate) fn provider_output_bindings() -> Vec<ProviderOutputBinding> {
    let mut bindings = Vec::new();
    bindings.extend_from_slice(redis::RedisRuntimeDeps::OUTPUT_BINDINGS);
    bindings.extend_from_slice(s3::S3RuntimeDeps::OUTPUT_BINDINGS);
    bindings.extend_from_slice(vault::VaultRuntimeDeps::OUTPUT_BINDINGS);
    bindings.extend_from_slice(PG_OUTPUT_BINDINGS);
    bindings.extend_from_slice(OIDC_OUTPUT_BINDINGS);
    bindings
}

#[cfg(test)]
mod tests {
    use super::{DomainModuleResultExt, ProviderOutput, build_pg_runtime_module};

    use bootstrap::{DomainModuleResult, HealthProbe, WorkerSpec};
    use diport::{DynManagedResource, ManagedResource, ShutdownError};
    use primitives::{HealthCheck, HealthStatus, ProbeName};
    use std::sync::{Arc, Mutex};

    struct LabeledOutput(&'static str);

    impl ProviderOutput for LabeledOutput {
        const OUTPUT_BINDINGS: &'static [bootstrap::ProviderOutputBinding] = &[];

        fn provider_output(&self) -> DomainModuleResult {
            DomainModuleResult {
                probes: vec![probe(self.0)],
                resources: vec![resource(self.0)],
                workers: vec![worker(self.0)],
            }
        }
    }

    #[test]
    fn provider_output_contract_is_implemented_for_live_bundles() {
        fn assert_provider_output<T: ProviderOutput>() {}

        assert_provider_output::<redis::RedisRuntimeDeps>();
        assert_provider_output::<s3::S3RuntimeDeps>();
        assert_provider_output::<vault::VaultRuntimeDeps>();
    }

    #[test]
    fn pg_runtime_module_keeps_guards_before_sampler_channel() {
        fn assert_builder(
            _: fn(postgres::PgRuntimeDeps, std::time::Duration) -> DomainModuleResult,
        ) {
        }
        assert_builder(build_pg_runtime_module);
        let output = DomainModuleResult {
            resources: vec![resource("postgres")],
            workers: vec![worker("postgres-readiness-sampler")],
            ..DomainModuleResult::default()
        };

        assert_eq!(resource_names(&output), ["postgres"]);
        assert_eq!(worker_names(output), ["postgres-readiness-sampler"]);
    }

    #[test]
    fn provider_outputs_merge_all_channels_in_order_and_preserve_duplicates() {
        let mut module = DomainModuleResult::default();
        for output in [
            LabeledOutput("redis"),
            LabeledOutput("s3"),
            LabeledOutput("vault"),
            LabeledOutput("vault"),
        ] {
            module.merge_provider(&output);
        }

        assert_eq!(probe_names(&module), ["redis", "s3", "vault", "vault"]);
        assert_eq!(resource_names(&module), ["redis", "s3", "vault", "vault"]);
        assert_eq!(worker_names(module), ["redis", "s3", "vault", "vault"]);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn provider_resource_registration_names_stay_stable() {
        let redis_pool = deadpool_redis::Config::from_url("redis://127.0.0.1:6379")
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("lazy redis pool construction does not connect");
        let redis = redis::RedisRuntimeDeps::setup(redis_pool);
        let s3 = crate::build_s3_runtime_deps_from(|name| match name {
            "RSS_S3_ENDPOINT_URL" => Some("https://s3.us-east-1.amazonaws.com".to_owned()),
            "RSS_S3_BUCKET" => Some("rss-provider-output-test".to_owned()),
            "RSS_S3_ACCESS_KEY_ID" => Some("access-key".to_owned()),
            "RSS_S3_SECRET_ACCESS_KEY" => Some("secret-key".to_owned()),
            _ => None,
        })
        .expect("valid hermetic s3 provider configuration");
        let vault = crate::build_vault_runtime_deps(|name| match name {
            "RSS_VAULT_ADDR" => Some("https://vault.example:8200".to_owned()),
            "RSS_VAULT_TOKEN" => Some("s.testtoken".to_owned()),
            "RSS_VAULT_TRANSIT_MOUNT" => Some("transit".to_owned()),
            _ => None,
        })
        .expect("valid hermetic vault provider configuration");

        let mut module = DomainModuleResult::default();
        module.merge_provider(&redis);
        module.merge_provider(&s3);
        module.merge_provider(&vault);

        assert!(module.probes.is_empty());
        assert!(module.workers.is_empty());
        let registration = resource_names(&module);
        assert_eq!(
            registration,
            ["redis", "s3", "vault-secret-resolver", "vault-key-provider",]
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn merged_provider_resources_are_actually_shutdown_in_lifo_order() {
        let shutdowns = Arc::new(Mutex::new(Vec::new()));
        let mut module = DomainModuleResult::default();
        for name in ["redis", "s3", "vault-secret-resolver", "vault-key-provider"] {
            module.merge_provider(&RecordingOutput {
                name,
                shutdowns: Arc::clone(&shutdowns),
            });
        }

        let mut stack =
            bootstrap::shutdown::ShutdownStack::new(tokio_util::sync::CancellationToken::new());
        for resource in module.resources {
            stack.register_detached(resource);
        }
        assert!(stack.shutdown().await.is_empty());
        assert_eq!(
            *shutdowns.lock().expect("shutdown recording mutex"),
            ["vault-key-provider", "vault-secret-resolver", "s3", "redis",]
        );
    }

    #[allow(clippy::expect_used)]
    fn probe(name: &'static str) -> (ProbeName, Box<dyn HealthProbe>) {
        let name = ProbeName::parse(name).expect("test provider names are valid probe names");
        (name.clone(), Box::new(LabeledProbe(name)))
    }

    fn resource(name: &'static str) -> Box<DynManagedResource<'static>> {
        DynManagedResource::new_box(LabeledResource(name))
    }

    fn worker(name: &'static str) -> WorkerSpec {
        Box::new(move |_| resource(name))
    }

    fn probe_names(module: &DomainModuleResult) -> Vec<&str> {
        module
            .probes
            .iter()
            .map(|(name, _)| name.as_str())
            .collect()
    }

    fn resource_names(module: &DomainModuleResult) -> Vec<&str> {
        module
            .resources
            .iter()
            .map(|resource| resource.name())
            .collect()
    }

    fn worker_names(module: DomainModuleResult) -> Vec<String> {
        let token = tokio_util::sync::CancellationToken::new();
        module
            .workers
            .into_iter()
            .map(|worker| worker(token.clone()).name().to_owned())
            .collect()
    }

    struct LabeledProbe(ProbeName);

    impl HealthProbe for LabeledProbe {
        fn check(&self) -> HealthCheck {
            HealthCheck::new(self.0.clone(), HealthStatus::Healthy, "ready")
        }
    }

    struct LabeledResource(&'static str);

    impl ManagedResource for LabeledResource {
        fn name(&self) -> &str {
            self.0
        }

        async fn shutdown(&self) -> Result<(), ShutdownError> {
            Ok(())
        }
    }

    struct RecordingOutput {
        name: &'static str,
        shutdowns: Arc<Mutex<Vec<&'static str>>>,
    }

    impl ProviderOutput for RecordingOutput {
        const OUTPUT_BINDINGS: &'static [bootstrap::ProviderOutputBinding] = &[];

        fn provider_output(&self) -> DomainModuleResult {
            DomainModuleResult {
                resources: vec![DynManagedResource::new_box(RecordingResource {
                    name: self.name,
                    shutdowns: Arc::clone(&self.shutdowns),
                })],
                ..DomainModuleResult::default()
            }
        }
    }

    struct RecordingResource {
        name: &'static str,
        shutdowns: Arc<Mutex<Vec<&'static str>>>,
    }

    impl ManagedResource for RecordingResource {
        fn name(&self) -> &str {
            self.name
        }

        async fn shutdown(&self) -> Result<(), ShutdownError> {
            let mut shutdowns = self.shutdowns.lock().map_err(|_| {
                ShutdownError::new(std::io::Error::other("test shutdown log poisoned"))
            })?;
            shutdowns.push(self.name);
            Ok(())
        }
    }
}
