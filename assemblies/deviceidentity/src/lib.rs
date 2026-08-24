//! Production-typed composition root for the deviceidentity candidate.
//!
//! The production constructor consumes one single-origin PostgreSQL receipt plus the External PKI
//! and MQTT providers, then drains generated domain lifecycle output into one local shutdown stack.

use tokio_util::sync::CancellationToken;

mod auth_bridge;
mod config;

mod listeners;
#[path = "generated/modules_gen.rs"]
mod modules_gen;
mod plan;
mod providers;
mod runtime;

pub use runtime::run;
#[path = "generated/providers_gen.rs"]
mod providers_gen;
const _: () = assert!(!providers_gen::PROVIDER_CATALOG.is_empty());

pub use modules_gen::DOMAIN_LISTENER_BINDINGS;

/// Infrastructure passed through generated module glue.
///
/// The generated domain consumes the same verified revocation provider receipt as the runtime. The
/// carrier stays infrastructure-only and introduces no second provider construction path.
pub(crate) struct SharedRuntimeDeps {
    revocations: postgres::PgRevocationStore,
}

async fn wire_domains(
    dependencies: &SharedRuntimeDeps,
    inputs: domains::DomainModuleInputs,
) -> anyhow::Result<Vec<bootstrap::DomainBinding>> {
    modules_gen::wire_domains(dependencies, inputs).await
}

/// Library owner of the production candidate runtime bundle.
///
/// Draft-only carriers cannot be named in the normal production graph:
///
/// ```compile_fail
/// use identity_composition::DraftArtifactSimulator;
/// fn production_slot(_: DraftArtifactSimulator) {}
/// ```
pub struct DeviceIdentityAssembly {
    lifecycle: DeviceIdentityLifecycleHandle,
    _registry: bootstrap::Registry,
    shutdown: tokio::sync::Mutex<Option<bootstrap::shutdown::ShutdownStack>>,
}

enum DeviceIdentityLifecycleHandle {
    Production(identity_composition::DeviceIdentityCandidateHandle),
    #[cfg(feature = "test-support")]
    Draft(identity_composition::DeviceIdentityPilotHandle),
}

impl DeviceIdentityLifecycleHandle {
    fn readiness(&self) -> identity_composition::DeviceIdentityRuntimeReadiness {
        match self {
            Self::Production(handle) => handle.readiness(),
            #[cfg(feature = "test-support")]
            Self::Draft(handle) => handle.readiness(),
        }
    }

    fn ingress_drained_changes(&self) -> tokio::sync::watch::Receiver<bool> {
        match self {
            Self::Production(handle) => handle.ingress_drained_changes(),
            #[cfg(feature = "test-support")]
            Self::Draft(handle) => handle.ingress_drained_changes(),
        }
    }

    #[cfg(feature = "test-support")]
    async fn pause_receipt_relay_for_test(&self) -> identity_composition::PilotLoopPauseGuard {
        match self {
            Self::Production(handle) => handle.pause_receipt_relay_for_test().await,
            Self::Draft(handle) => handle.pause_receipt_relay_for_test().await,
        }
    }

    #[cfg(feature = "test-support")]
    async fn pause_ingress_for_test(&self) -> identity_composition::PilotLoopPauseGuard {
        match self {
            Self::Production(handle) => handle.pause_ingress_for_test().await,
            Self::Draft(handle) => handle.pause_ingress_for_test().await,
        }
    }
}

/// Fail-fast construction boundary for the generated production candidate closure.
#[derive(Debug, thiserror::Error)]
pub enum DeviceIdentityAssemblyStartError {
    #[error("deviceidentity runtime provider construction failed")]
    Runtime(#[from] identity_composition::DeviceIdentityRuntimeStartError),
    #[error("deviceidentity generated domain composition failed")]
    Composition(#[source] anyhow::Error),
}

/// Assembly-owned shutdown failure after admission has already been closed.
#[derive(Debug, thiserror::Error)]
pub enum DeviceIdentityAssemblyShutdownError {
    #[error("deviceidentity lifecycle resource shutdown failed")]
    Resource,
}

impl DeviceIdentityAssembly {
    /// Consume the exact generated provider roles and compose the library-only candidate.
    ///
    /// # Errors
    ///
    /// Returns a typed provider/startup error before any worker is exposed, or a composition error
    /// after bounded teardown of a successfully started candidate. There is no optional or default
    /// provider path.
    pub async fn start<R>(
        postgres: postgres::PgDeviceIdentityProductionRuntime,
        artifact_source: identity_composition::ExternalPkiArtifactSource<R>,
        mqtt: std::sync::Arc<mqtt::MqttSession>,
        config: identity_composition::DeviceIdentityRuntimeConfig,
    ) -> Result<Self, DeviceIdentityAssemblyStartError>
    where
        R: diport::ExternalCsrResolver + Send + Sync + 'static,
    {
        let dependencies = SharedRuntimeDeps {
            revocations: postgres.revocation_store(),
        };
        let lifecycle = identity_composition::DeviceIdentityCandidateLifecycle::start(
            postgres,
            artifact_source,
            mqtt,
            config,
        )?;
        let (handle, adoption) = lifecycle.into_parts();
        Self::from_lifecycle(handle, adoption, dependencies).await
    }

    async fn from_lifecycle(
        lifecycle: identity_composition::DeviceIdentityCandidateHandle,
        adoption: identity_composition::DeviceIdentityCandidateAdoption,
        dependencies: SharedRuntimeDeps,
    ) -> Result<Self, DeviceIdentityAssemblyStartError> {
        let (registry, shutdown) = compose_generated_domain(
            &dependencies,
            domains::DomainModuleInputs { identity: adoption },
        )
        .await
        .map_err(DeviceIdentityAssemblyStartError::Composition)?;
        Ok(Self {
            lifecycle: DeviceIdentityLifecycleHandle::Production(lifecycle),
            _registry: registry,
            shutdown: tokio::sync::Mutex::new(Some(shutdown)),
        })
    }

    /// Start the ADR-028 draft carrier for integration tests only.
    ///
    /// This entry point is absent from the normal production dependency graph and cannot consume
    /// the production runtime bundle.
    #[cfg(feature = "test-support")]
    pub async fn start_draft_for_test(
        postgres: postgres::PgDeviceIdentityDraftRuntime,
        artifact_source: identity_composition::DraftArtifactSimulator,
        mqtt: std::sync::Arc<mqtt::MqttSession>,
        config: identity_composition::DeviceIdentityRuntimeConfig,
    ) -> Result<Self, DeviceIdentityAssemblyStartError> {
        let dependencies = SharedRuntimeDeps {
            revocations: postgres.revocation_store(),
        };
        let lifecycle = identity_composition::DeviceIdentityPilotLifecycle::start(
            postgres,
            artifact_source,
            mqtt,
            config,
        )?;
        let (handle, adoption) = lifecycle.into_parts();
        let binding = domains::identity::draft_test_module(&dependencies, adoption)
            .await
            .map_err(DeviceIdentityAssemblyStartError::Composition)?;
        let (registry, shutdown) = compose_domain_bindings(vec![binding])
            .await
            .map_err(DeviceIdentityAssemblyStartError::Composition)?;
        Ok(Self {
            lifecycle: DeviceIdentityLifecycleHandle::Draft(handle),
            _registry: registry,
            shutdown: tokio::sync::Mutex::new(Some(shutdown)),
        })
    }

    /// Read the fail-closed aggregate runtime readiness snapshot.
    #[must_use]
    pub fn readiness(&self) -> identity_composition::DeviceIdentityRuntimeReadiness {
        self.lifecycle.readiness()
    }

    /// Subscribe to ingress admission drain transitions.
    #[must_use]
    pub fn ingress_drained_changes(&self) -> tokio::sync::watch::Receiver<bool> {
        self.lifecycle.ingress_drained_changes()
    }

    /// Pause only application-receipt publication for deterministic integration observation.
    ///
    /// The returned move-only guard is available only with `test-support`; dropping it resumes the
    /// relay, including cancellation and early-return paths.
    #[cfg(feature = "test-support")]
    pub async fn pause_receipt_relay_for_test(&self) -> identity_composition::PilotLoopPauseGuard {
        self.lifecycle.pause_receipt_relay_for_test().await
    }

    /// Pause only durable ingress consumption for deterministic join-hazard observation.
    ///
    /// Shares the same move-only [`identity_composition::PilotLoopPauseGuard`] as receipt-relay
    /// pause; available only with `test-support`.
    #[cfg(feature = "test-support")]
    pub async fn pause_ingress_for_test(&self) -> identity_composition::PilotLoopPauseGuard {
        self.lifecycle.pause_ingress_for_test().await
    }

    /// Run the canonical bounded admission-first shutdown sequence.
    pub async fn shutdown(&self) -> Result<(), DeviceIdentityAssemblyShutdownError> {
        let Some(stack) = self.shutdown.lock().await.take() else {
            return Ok(());
        };
        if stack.shutdown().await.is_empty() {
            Ok(())
        } else {
            Err(DeviceIdentityAssemblyShutdownError::Resource)
        }
    }
}

async fn compose_generated_domain(
    dependencies: &SharedRuntimeDeps,
    inputs: domains::DomainModuleInputs,
) -> anyhow::Result<(bootstrap::Registry, bootstrap::shutdown::ShutdownStack)> {
    compose_domain_bindings(wire_domains(dependencies, inputs).await?).await
}

async fn compose_domain_bindings(
    mut bindings: Vec<bootstrap::DomainBinding>,
) -> anyhow::Result<(bootstrap::Registry, bootstrap::shutdown::ShutdownStack)> {
    let (mut registry, mut output) = match bootstrap::compose_bindings(&mut bindings) {
        Ok(composed) => composed,
        Err(composition) => {
            let output = bootstrap::drain_binding_outputs(&mut bindings);
            let cleanup = shutdown_output(output).await;
            return match cleanup {
                Ok(()) => Err(composition.into()),
                Err(cleanup) => Err(anyhow::anyhow!(
                    "domain composition failed ({composition}); lifecycle cleanup failed ({cleanup})"
                )),
            };
        }
    };
    let mut resources = Vec::new();
    let mut workers = Vec::new();
    for lifecycle in output.drain_outputs() {
        match lifecycle {
            bootstrap::DomainLifecycleOutput::Probe(name, probe) => {
                registry.probe(name, probe)?;
            }
            bootstrap::DomainLifecycleOutput::Resource(resource) => resources.push(resource),
            bootstrap::DomainLifecycleOutput::Worker(worker) => workers.push(worker),
        }
    }
    let mut shutdown = bootstrap::shutdown::ShutdownStack::new(CancellationToken::new());
    for resource in resources {
        shutdown.register_detached(resource);
    }
    for worker in workers {
        let _status = worker.register_into(&mut shutdown);
    }
    Ok((registry, shutdown))
}

async fn shutdown_output(mut output: bootstrap::DomainModuleResult) -> anyhow::Result<()> {
    let mut shutdown = bootstrap::shutdown::ShutdownStack::new(CancellationToken::new());
    let mut resources = Vec::new();
    let mut workers = Vec::new();
    for lifecycle in output.drain_outputs() {
        match lifecycle {
            bootstrap::DomainLifecycleOutput::Probe(_, _) => {}
            bootstrap::DomainLifecycleOutput::Resource(resource) => resources.push(resource),
            bootstrap::DomainLifecycleOutput::Worker(worker) => workers.push(worker),
        }
    }
    for resource in resources {
        shutdown.register_detached(resource);
    }
    for worker in workers {
        let _status = worker.register_into(&mut shutdown);
    }
    let errors = shutdown.shutdown().await;
    if errors.is_empty() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "{} managed resource(s) failed",
            errors.len()
        ))
    }
}

mod domains {
    pub(crate) struct DomainModuleInputs {
        pub(crate) identity: identity_composition::DeviceIdentityCandidateAdoption,
    }

    pub(crate) mod identity {
        use bootstrap::{Domain, DomainBinding, KernelError, Registry};

        struct DeviceIdentityDomain;

        impl Domain for DeviceIdentityDomain {
            fn init(&self, _registry: &mut Registry) -> Result<(), KernelError> {
                Ok(())
            }
        }

        pub(crate) async fn module(
            dependencies: &crate::SharedRuntimeDeps,
            adoption: identity_composition::DeviceIdentityCandidateAdoption,
        ) -> anyhow::Result<DomainBinding> {
            let _revocations = &dependencies.revocations;
            Ok(DomainBinding::new(
                "identity",
                Box::new(DeviceIdentityDomain),
                adoption.into_domain_output()?,
            ))
        }

        #[cfg(feature = "test-support")]
        pub(crate) async fn draft_test_module(
            dependencies: &crate::SharedRuntimeDeps,
            adoption: identity_composition::DeviceIdentityPilotAdoption,
        ) -> anyhow::Result<DomainBinding> {
            let _revocations = &dependencies.revocations;
            Ok(DomainBinding::new(
                "identity",
                Box::new(DeviceIdentityDomain),
                adoption.into_domain_output()?,
            ))
        }

        #[cfg(test)]
        pub(crate) mod tests {
            use bootstrap::{Domain, DomainBinding, DomainModuleResult, KernelError, Registry};

            struct TestIdentityDomain;

            impl Domain for TestIdentityDomain {
                fn init(&self, _registry: &mut Registry) -> Result<(), KernelError> {
                    Ok(())
                }
            }

            pub(crate) async fn test_binding() -> anyhow::Result<DomainBinding> {
                Ok(DomainBinding::new(
                    "identity",
                    Box::new(TestIdentityDomain),
                    DomainModuleResult::default(),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use bootstrap::compose_bindings;

    #[tokio::test]
    async fn generated_module_compiles_and_selects_only_identity() {
        let mut bindings = crate::modules_gen::wire_test_domains()
            .await
            .expect("generated identity binding builds");
        assert_eq!(
            bindings
                .iter()
                .map(bootstrap::DomainBinding::name)
                .collect::<Vec<_>>(),
            ["identity"]
        );
        let (_, output) = compose_bindings(&mut bindings).expect("identity binding composes");
        assert!(bindings.is_empty());
        assert_eq!(output.probe_count(), 0);
        assert_eq!(output.resource_count(), 0);
        assert_eq!(output.worker_count(), 0);
        assert_eq!(crate::DOMAIN_LISTENER_BINDINGS.len(), 1);
    }

    #[test]
    fn provider_catalog_is_the_exact_production_closure() {
        assert_eq!(crate::providers_gen::PROVIDER_CATALOG.len(), 10);
    }

    #[test]
    fn rate_limiter_synthetic_red_carrier_joins_the_generated_role() {
        let plan = crate::plan::DeviceIdentityPlan::bundled().expect("plan");
        let mut roles = plan.provider_build().expect("roles");
        let constructor = roles.listener_rate_limiter().expect("rate limiter role");
        let batch = constructor
            .finish_for_test(bootstrap::DomainModuleResult::default())
            .expect("closed empty lifecycle");
        let mut inventory = bootstrap::DomainModuleResult::default();
        let _receipt = batch.transfer(&mut inventory);
    }

    #[test]
    fn assembly_constructor_consumes_single_origin_postgres_and_exact_external_roles() {
        fn constructor<R>(
            postgres: postgres::PgDeviceIdentityProductionRuntime,
            source: identity_composition::ExternalPkiArtifactSource<R>,
            mqtt: std::sync::Arc<mqtt::MqttSession>,
            config: identity_composition::DeviceIdentityRuntimeConfig,
        ) -> impl std::future::Future<
            Output = Result<crate::DeviceIdentityAssembly, crate::DeviceIdentityAssemblyStartError>,
        >
        where
            R: diport::ExternalCsrResolver + Send + Sync + 'static,
        {
            crate::DeviceIdentityAssembly::start(postgres, source, mqtt, config)
        }
        let _ = constructor::<httpd::SpiffeMtlsExternalCsrResolver>;
    }

    #[test]
    fn runtime_handle_mints_the_closed_deviceidentity_postgres_receipt() {
        fn production_runtime(
            handle: &postgres::PgRuntimeHandle,
        ) -> postgres::PgDeviceIdentityProductionRuntime {
            handle.device_identity_production_runtime()
        }

        let _ = production_runtime;
    }

    #[test]
    fn production_and_test_support_each_own_one_typed_lifecycle_output() {
        let source = include_str!("lib.rs");
        let call = concat!("adoption.", "into_domain_output()?");
        assert_eq!(source.matches(call).count(), 2);
        assert!(source.contains("pub async fn start_draft_for_test("));
        assert!(source.contains("DeviceIdentityLifecycleHandle::Production(lifecycle)"));
        assert!(source.contains("DeviceIdentityLifecycleHandle::Draft(handle)"));
        let rejected_legacy_assertion =
            concat!("unexpectedly exported ", "duplicate lifecycle owners");
        assert!(!source.contains(rejected_legacy_assertion));
    }

    #[cfg(feature = "test-support")]
    #[test]
    fn test_support_facade_exposes_only_the_two_pilot_loop_pause_guards() {
        fn pause_receipt(
            assembly: &crate::DeviceIdentityAssembly,
        ) -> impl std::future::Future<Output = identity_composition::PilotLoopPauseGuard> + '_
        {
            assembly.pause_receipt_relay_for_test()
        }

        fn pause_ingress(
            assembly: &crate::DeviceIdentityAssembly,
        ) -> impl std::future::Future<Output = identity_composition::PilotLoopPauseGuard> + '_
        {
            assembly.pause_ingress_for_test()
        }

        let _ = (pause_receipt, pause_ingress);
    }
}
