//! Assembly-owned HTTP projection for the provider-independent runtime inventory.

use axum::extract::{Extension, State};
use generated::http::runtime_v1::inventory as wire;
#[cfg(any(test, feature = "test-support"))]
use runtimeexec::inventory as model;

#[derive(Clone)]
pub(crate) struct InventoryFrameworkRoutes {
    reader: runtimeexec::inventory::InventoryReader,
}

impl InventoryFrameworkRoutes {
    pub(crate) const fn new(reader: runtimeexec::inventory::InventoryReader) -> Self {
        Self { reader }
    }
}

impl httpserve::ClassifiedRouteState for InventoryFrameworkRoutes {
    type Effect = diport::ReadEffect;
    type Privilege = diport::LocalPrivilege;
}

impl ::bootstrap::FrameworkRoutes for InventoryFrameworkRoutes {
    fn register(
        &self,
        registry: &mut ::bootstrap::Registry,
    ) -> Result<(), ::bootstrap::KernelError> {
        let state = InventoryFrameworkRoutes::new(self.reader.clone());
        registry.route_group::<::httpserve::Admin>("/api/v1/runtime", move |routes| {
            let endpoint = ::httpserve::GeneratedEndpoint::new_declared(
                ::generated::http::runtime_v1::inventory::ROUTE,
                inventory_handler,
            )?
            .with_classified_state(state);
            Ok(routes.mount(endpoint)?)
        })
    }
}

async fn inventory_handler(
    _: ::httpserve::ContractMarker<::generated::http::runtime_v1::inventory::RouteMarker>,
    State(state): State<InventoryFrameworkRoutes>,
    Extension(request_id): Extension<httpserve::VerifiedRequestId>,
) -> wire::RuntimeInventoryHandlerResult {
    inventory_response(&state.reader, request_id)
}

fn inventory_response(
    reader: &runtimeexec::inventory::InventoryReader,
    request_id: httpserve::VerifiedRequestId,
) -> wire::RuntimeInventoryHandlerResult {
    match wire::project_read_result(reader.read()) {
        Ok(response) => Ok(wire::RuntimeInventoryResponseEnvelope::Success(response)),
        Err(failure) => {
            let error = failure.core_error();
            httpserve::error::log_contract_core_error(
                wire::CONTRACT_ID,
                &error,
                request_id.as_str(),
                failure.diagnostic_stage(),
            );
            Ok(wire::RuntimeInventoryResponseEnvelope::Error(
                failure.into_response_error(request_id.into_wire()),
            ))
        }
    }
}

#[cfg(feature = "test-support")]
pub mod test_support {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::SystemTime;

    use anyhow::Context as _;

    use super::{InventoryFrameworkRoutes, model};

    #[derive(Clone, Copy)]
    pub enum JourneyCase {
        Allow,
        Deny,
        AuditFail,
        ProbeDegraded,
        ProbeUnavailable,
    }

    struct FixturePdp(JourneyCase);

    impl diport::Pdp for FixturePdp {
        async fn verify(
            &self,
            _: &diport::RawCredential,
        ) -> Result<diport::VerifiedClaims, diport::PdpError> {
            let tenant =
                rss_request_context::TenantId::parse("00000000-0000-4000-8000-000000000179")
                    .map_err(|_| diport::PdpError::InvalidSignature)?;
            let kind = match self.0 {
                JourneyCase::Deny => rss_request_context::PrincipalKind::User,
                JourneyCase::Allow
                | JourneyCase::AuditFail
                | JourneyCase::ProbeDegraded
                | JourneyCase::ProbeUnavailable => rss_request_context::PrincipalKind::Admin,
            };
            diport::VerifiedClaims::federated_access(
                "settingsonly-inventory-journey",
                Some(tenant),
                kind,
                diport::VerifiedFederatedPermissions::new([vocab::GrantPermission::route(
                    match self.0 {
                        JourneyCase::Deny => vocab::RoutePermissionId::SettingsConfigPublish,
                        JourneyCase::Allow
                        | JourneyCase::AuditFail
                        | JourneyCase::ProbeDegraded
                        | JourneyCase::ProbeUnavailable => {
                            vocab::RoutePermissionId::RuntimeInventoryRead
                        }
                    },
                )])
                .map_err(|_| diport::PdpError::InvalidSignature)?,
            )
            .map_err(|_| diport::PdpError::InvalidSignature)
        }
    }

    struct Audit {
        fail: bool,
        calls: Arc<AtomicUsize>,
    }
    impl diport::AuditSink for Audit {
        async fn record(&self, _: diport::AuditEvent) -> Result<(), diport::AuditSinkError> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            if self.fail {
                Err(diport::AuditSinkError::new(std::io::Error::other(
                    "journey audit failure",
                )))
            } else {
                Ok(())
            }
        }
        async fn shutdown(&self) -> Result<(), diport::AuditSinkError> {
            Ok(())
        }
    }
    struct Clock;
    impl diport::Clock for Clock {
        fn now(&self) -> SystemTime {
            SystemTime::UNIX_EPOCH
        }
    }

    struct FixtureProbe {
        name: primitives::ProbeName,
        status: primitives::HealthStatus,
    }

    impl bootstrap::HealthProbe for FixtureProbe {
        fn check(&self) -> primitives::HealthCheck {
            primitives::HealthCheck::new(self.name.clone(), self.status, "journey-probe")
        }
    }

    fn journey_probe_registry(
        case: JourneyCase,
    ) -> anyhow::Result<(primitives::ProbeName, bootstrap::Registry)> {
        let name = primitives::ProbeName::parse("inventory_journey_provider")?;
        let status = match case {
            JourneyCase::ProbeDegraded => primitives::HealthStatus::Degraded,
            JourneyCase::ProbeUnavailable => primitives::HealthStatus::Unhealthy,
            JourneyCase::Allow | JourneyCase::Deny | JourneyCase::AuditFail => {
                primitives::HealthStatus::Healthy
            }
        };
        let mut registry = bootstrap::Registry::new();
        registry.probe(
            name.clone(),
            Box::new(FixtureProbe {
                name: name.clone(),
                status,
            }),
        )?;
        Ok((name, registry))
    }

    pub struct JourneyResult {
        pub status: reqwest::StatusCode,
        pub body: Vec<u8>,
        pub serving_address: std::net::SocketAddr,
        pub audit_calls: usize,
    }

    pub struct ProjectionStatusJourneyResult {
        pub responses: Vec<ProjectionStatusHttpResult>,
        pub serving_address: std::net::SocketAddr,
        pub audit_calls: usize,
    }

    pub struct ProjectionStatusHttpResult {
        pub status: reqwest::StatusCode,
        pub body: Vec<u8>,
    }

    /// Exercise the assembly-owned Admin route over the same bound socket represented in the
    /// published inventory. Authentication and authorization use the production listener funnel;
    /// only the credential PDP and durable audit outcome are controlled test evidence.
    pub async fn run_journey(case: JourneyCase) -> anyhow::Result<JourneyResult> {
        let (response, audit_calls) = run_journey_requests(case, false).await?;
        let serving_address = response.serving_address;
        let mut responses = response.responses.into_iter();
        let response = responses.next().context("single inventory response")?;
        anyhow::ensure!(responses.next().is_none(), "unexpected inventory response");
        Ok(JourneyResult {
            status: response.status,
            body: response.body,
            serving_address,
            audit_calls,
        })
    }

    pub async fn run_projection_status_journey() -> anyhow::Result<ProjectionStatusJourneyResult> {
        let (response, audit_calls) = run_journey_requests(JourneyCase::Allow, true).await?;
        Ok(ProjectionStatusJourneyResult {
            responses: response
                .responses
                .into_iter()
                .map(|response| ProjectionStatusHttpResult {
                    status: response.status,
                    body: response.body,
                })
                .collect(),
            serving_address: response.serving_address,
            audit_calls,
        })
    }

    async fn run_journey_requests(
        case: JourneyCase,
        projection_statuses: bool,
    ) -> anyhow::Result<(crate::listeners::InventoryJourneyHttpResult, usize)> {
        let plan = crate::plan::SettingsOnlyPlan::bundled()?;
        let (probe_name, mut registry) = journey_probe_registry(case)?;
        let bindings = crate::providers_gen::PROVIDER_CATALOG
            .iter()
            .map(|provider| {
                let probe_names = if provider.role() == assembly_schema::ProviderRole::ListenerPdp {
                    vec![probe_name.clone()]
                } else {
                    Vec::new()
                };
                model::ProviderProbeBinding::from_probe_receipt(
                    provider.role().as_str(),
                    probe_names,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let (seed, mut lifecycle, expected_workers, request_plan) = if projection_statuses {
            let (seed, lifecycle, observation) =
                plan.into_live_inventory_fixture(bindings)?.into_parts();
            let generation = eventexec::ProjectionVersion::parse("v3")?;
            (
                seed,
                lifecycle,
                bootstrap::ExpectedWorkerInventory::closed([
                    bootstrap::WorkerDescriptor::expected(
                        "assemblies.settingsonly.src.projection.01",
                        bootstrap::WorkerAdmissionLane::Writes,
                    ),
                ])?,
                crate::listeners::InventoryJourneyRequestPlan::projection_statuses(
                    observation,
                    [
                        eventexec::ProjectionWorkerStatus::Healthy {
                            selected_generation: eventexec::ProjectionSelectedGeneration::Uniform(
                                generation.clone(),
                            ),
                            max_lag: 7,
                        },
                        eventexec::ProjectionWorkerStatus::Retryable {
                            selected_generation: eventexec::ProjectionSelectedGeneration::Uniform(
                                generation.clone(),
                            ),
                            max_lag: 8,
                            reasons: eventexec::ProjectionReasonPosture::Uniform(
                                eventexec::ProjectionRetryableReason::SourceTransient,
                            ),
                        },
                        eventexec::ProjectionWorkerStatus::Quarantined {
                            selected_generation: eventexec::ProjectionSelectedGeneration::Uniform(
                                generation,
                            ),
                            max_lag: 9,
                            reasons: eventexec::ProjectionReasonPosture::Uniform(
                                eventexec::ProjectionQuarantineReason::ProviderPermanent,
                            ),
                        },
                        eventexec::ProjectionWorkerStatus::Stopped(
                            eventexec::ProjectionStoppedReason::InvalidTenant,
                        ),
                    ],
                ),
            )
        } else {
            (
                plan.into_inventory_seed_fixture(bindings)?,
                bootstrap::DomainModuleResult::default(),
                bootstrap::ExpectedWorkerInventory::closed([])?,
                crate::listeners::InventoryJourneyRequestPlan::single(),
            )
        };
        for (name, probe) in lifecycle.probes.drain(..) {
            registry.probe(name, probe)?;
        }
        let reporter = Arc::new(registry.take_health_reporter());
        let (publisher, reader) = model::inventory_channel(seed, Arc::clone(&reporter));
        let mut registry = bootstrap::Registry::new();
        crate::modules_gen::register_framework_routes(
            &InventoryFrameworkRoutes::new(reader),
            &mut registry,
        )?;
        let mounted = registry
            .admit_writes(primitives::prepare_dr_admission_controls().into_parts().3)
            .finalize_routes()?;
        bootstrap::validate_framework_serving(&mounted, crate::modules_gen::FRAMEWORK_HTTP_ROUTES)?;
        let (_, routes) = mounted
            .into_iter()
            .find(|(kind, _)| *kind == primitives::ListenerKind::Admin)
            .context("settingsonly journey Admin inventory route")?;
        let plan = primitives::AuthPlan::new(
            primitives::ListenerKind::Admin,
            primitives::AuthScheme::FederatedAccessToken,
        )?;
        let audit_calls = Arc::new(AtomicUsize::new(0));
        let routes = httpserve::finalize_auth_with_audit_and_authorizer(
            routes,
            plan,
            httpserve::AuditSinkHandle::new(Audit {
                fail: matches!(case, JourneyCase::AuditFail),
                calls: Arc::clone(&audit_calls),
            }),
            Arc::new(Clock),
            Arc::new(crate::listeners::FederatedPermissionAuthorizer),
        )?;
        let verifier =
            crate::auth_bridge::FederatedVerifier::test(diport::DynPdp::new_arc(FixturePdp(case)));
        let routes = crate::auth_bridge::apply(routes, verifier);
        let response = crate::listeners::serve_inventory_journey(
            routes,
            Arc::clone(&reporter),
            publisher,
            crate::test_support::valid_federated_token().to_owned(),
            lifecycle,
            expected_workers,
            request_plan,
        )
        .await?;
        Ok((response, audit_calls.load(Ordering::Acquire)))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::SystemTime;

    use super::*;
    use anyhow::Context as _;

    struct TestAuditSink {
        fail: bool,
    }

    impl diport::AuditSink for TestAuditSink {
        async fn record(&self, _event: diport::AuditEvent) -> Result<(), diport::AuditSinkError> {
            if self.fail {
                Err(diport::AuditSinkError::new(std::io::Error::other(
                    "inventory audit unavailable",
                )))
            } else {
                Ok(())
            }
        }

        async fn shutdown(&self) -> Result<(), diport::AuditSinkError> {
            Ok(())
        }
    }

    struct TestClock;

    impl diport::Clock for TestClock {
        fn now(&self) -> SystemTime {
            SystemTime::UNIX_EPOCH
        }
    }

    #[test]
    fn inventory_authorizer_contract_identity_is_generated() {
        assert_eq!(wire::CONTRACT_ID, "runtime.inventory");
        assert_eq!(wire::PATH, "/api/v1/runtime/inventory");
    }

    fn inventory_reader(publish: bool) -> anyhow::Result<runtimeexec::inventory::InventoryReader> {
        let plan = crate::plan::SettingsOnlyPlan::bundled()?;
        let bindings = crate::providers_gen::PROVIDER_CATALOG
            .iter()
            .map(|provider| {
                model::ProviderProbeBinding::from_probe_receipt(
                    provider.role().as_str(),
                    Vec::new(),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let seed = plan.into_inventory_seed_fixture(bindings)?;
        let reporter = Arc::new(bootstrap::Registry::new().take_health_reporter());
        let (publisher, reader) = model::inventory_channel(seed, reporter);
        let listeners = vec![
            model::BoundListenerObservation::from_bound(
                "primary-main",
                assembly_schema::AssemblyListenerKind::Primary,
                assembly_schema::ListenerAuth::FederatedAccessToken,
                model::InventoryEndpointScheme::Http,
                "127.0.0.1:18080".parse()?,
            ),
            model::BoundListenerObservation::from_bound(
                "admin-main",
                assembly_schema::AssemblyListenerKind::Admin,
                assembly_schema::ListenerAuth::FederatedAccessToken,
                model::InventoryEndpointScheme::Http,
                "127.0.0.1:18082".parse()?,
            ),
            model::BoundListenerObservation::from_bound(
                "health-main",
                assembly_schema::AssemblyListenerKind::Health,
                assembly_schema::ListenerAuth::NoAuth,
                model::InventoryEndpointScheme::Http,
                "127.0.0.1:18083".parse()?,
            ),
        ];
        if publish {
            publisher.publish(listeners)?;
        }
        Ok(reader)
    }

    fn published_inventory_reader() -> anyhow::Result<runtimeexec::inventory::InventoryReader> {
        inventory_reader(true)
    }

    #[tokio::test]
    async fn unpublished_inventory_returns_retryable_provider_unavailable() -> anyhow::Result<()> {
        let response = inventory_response(
            &inventory_reader(false)?,
            httpserve::VerifiedRequestId::for_test("inventory-unpublished"),
        );
        let Ok(response) = response else {
            anyhow::bail!("inventory handler returned a framework failure");
        };
        let response = axum::response::IntoResponse::into_response(response);
        assert_eq!(
            response.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
        let bytes = axum::body::to_bytes(response.into_body(), 4096).await?;
        let body: serde_json::Value = serde_json::from_slice(&bytes)?;
        assert_eq!(body["error"]["code"], "ERR_CORE_PROVIDER_UNAVAILABLE");
        assert_eq!(body["error"]["requestId"], "inventory-unpublished");
        assert_eq!(body["error"]["retryable"], true);
        assert_eq!(body["error"]["details"], serde_json::json!([]));
        Ok(())
    }

    fn published_inventory_routes() -> anyhow::Result<(
        runtimeexec::inventory::InventoryReader,
        Vec<(primitives::ListenerKind, httpserve::UnfinalizedRoutes)>,
    )> {
        let reader = published_inventory_reader()?;
        let mut registry = bootstrap::Registry::new();
        crate::modules_gen::register_framework_routes(
            &InventoryFrameworkRoutes::new(reader.clone()),
            &mut registry,
        )?;
        let mounted = registry
            .admit_writes(primitives::prepare_dr_admission_controls().into_parts().3)
            .finalize_routes()?;
        bootstrap::validate_framework_serving(&mounted, crate::modules_gen::FRAMEWORK_HTTP_ROUTES)?;
        Ok((reader, mounted))
    }

    fn authenticated_inventory_router(
        kind: rss_request_context::PrincipalKind,
        audit_fails: bool,
        permission: vocab::RoutePermissionId,
    ) -> anyhow::Result<axum::Router> {
        let (_, mut mounted) = published_inventory_routes()?;
        let (_, routes) = mounted.pop().context("mounted Admin inventory route")?;
        anyhow::ensure!(
            mounted.is_empty(),
            "unexpected additional inventory listener"
        );
        let plan = primitives::AuthPlan::new(
            primitives::ListenerKind::Admin,
            primitives::AuthScheme::FederatedAccessToken,
        )?;
        let tenant = if kind == rss_request_context::PrincipalKind::SuperAdmin {
            None
        } else {
            Some(rss_request_context::TenantId::parse(
                "00000000-0000-4000-8000-000000000001",
            )?)
        };
        let permissions =
            diport::VerifiedFederatedPermissions::new([vocab::GrantPermission::route(permission)])?;
        let authenticated = httpserve::Authenticated::new_federated(
            authmint::AuthenticatedMint::capability(),
            kind,
            "inventory-operator",
            tenant,
            &permissions,
        );
        Ok(httpserve::finalize_auth_with_audit_and_authorizer(
            routes,
            plan,
            httpserve::AuditSinkHandle::new(TestAuditSink { fail: audit_fails }),
            Arc::new(TestClock),
            Arc::new(crate::listeners::FederatedPermissionAuthorizer),
        )?
        .into_plaintext_router_for_test()
        .layer(axum::Extension(authenticated)))
    }

    #[tokio::test]
    async fn generated_global_inventory_auth_funnel_uses_exact_typed_permission()
    -> anyhow::Result<()> {
        assert_eq!(
            wire::ROUTE.evidence().resource_sharing(),
            vocab::http::HttpResourceSharing::Global
        );
        assert_eq!(wire::ROUTE.evidence().resource(), Some("runtimeInventory"));
        for kind in [
            rss_request_context::PrincipalKind::User,
            rss_request_context::PrincipalKind::Admin,
        ] {
            testkit::call(
                authenticated_inventory_router(
                    kind,
                    false,
                    vocab::RoutePermissionId::RuntimeInventoryRead,
                )?,
                testkit::ContractRequest::get(wire::PATH),
            )
            .await?
            .ensure_status(axum::http::StatusCode::OK)?;
        }
        testkit::call(
            authenticated_inventory_router(
                rss_request_context::PrincipalKind::SuperAdmin,
                false,
                vocab::RoutePermissionId::SettingsConfigPublish,
            )?,
            testkit::ContractRequest::get(wire::PATH),
        )
        .await?
        .ensure_status(axum::http::StatusCode::FORBIDDEN)?;
        Ok(())
    }

    #[tokio::test]
    async fn generated_global_inventory_audit_failure_remains_fail_closed() -> anyhow::Result<()> {
        testkit::call(
            authenticated_inventory_router(
                rss_request_context::PrincipalKind::SuperAdmin,
                true,
                vocab::RoutePermissionId::RuntimeInventoryRead,
            )?,
            testkit::ContractRequest::get(wire::PATH),
        )
        .await?
        .ensure_status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
        Ok(())
    }

    #[test]
    fn framework_route_and_generated_dto_mapping_are_exact() -> anyhow::Result<()> {
        let (reader, _) = published_inventory_routes()?;
        let response = wire::RuntimeInventoryResponse::try_from(reader.read()?)?;
        assert_eq!(
            response.data.schema_version,
            wire::RuntimeInventorySchemaVersion::V2
        );
        assert_eq!(response.data.activated_workflows.len(), 1);
        assert_eq!(response.data.domains, [wire::RuntimeDomain::Settings]);
        assert_eq!(response.data.listeners.len(), 3);
        assert_eq!(
            response.data.provider_posture.len(),
            crate::providers_gen::PROVIDER_CATALOG.len()
        );
        assert_eq!(response.data.placements.len(), 1);
        let encoded = serde_json::to_value(response)?;
        assert_eq!(
            encoded["data"]["activatedWorkflows"],
            serde_json::json!([{
                "activation": "active",
                "definitionSchemaDigest": "sha256:ce6e2126b5d5831f67955d1db29fc7c0c1cc339cdf4cec1ad2486f5fb778b4d8",
                "definitionVersion": "v3",
                "id": "settings.config-projection",
                "mode": "projection",
                "targetGeneration": "v3",
                "workerStatus": { "state": "starting" }
            }])
        );
        Ok(())
    }

    #[allow(clippy::expect_used)]
    fn finalized_runtime_inventory_router() -> (
        axum::Router,
        ::httpserve::LocalOnlyMountedRouteProof<
            ::generated::http::runtime_v1::inventory::RouteMarker,
            InventoryFrameworkRoutes,
        >,
    ) {
        let reader = published_inventory_reader().expect("published inventory reader");
        let framework_routes = InventoryFrameworkRoutes::new(reader);
        let mut registry = bootstrap::Registry::new();
        crate::modules_gen::register_framework_routes(&framework_routes, &mut registry)
            .expect("register inventory framework route");
        let mut admitted_registry =
            registry.admit_writes(primitives::prepare_dr_admission_controls().into_parts().3);
        let mut finalized = admitted_registry
            .finalize_routes()
            .expect("finalize inventory routes");
        let (_, routes) = finalized.pop().expect("mounted Admin inventory route");
        let proof =
            ::httpserve::prove_local_only_mounted_route_state::<InventoryFrameworkRoutes, _>(
                &routes,
                &::generated::http::runtime_v1::inventory::ROUTE,
            )
            .expect("inventory LocalOnly route proof");
        let plan = primitives::AuthPlan::new(
            primitives::ListenerKind::Admin,
            primitives::AuthScheme::FederatedAccessToken,
        )
        .expect("Admin auth plan");
        let router = ::httpserve::finalize_auth(routes, plan)
            .expect("finalize inventory auth")
            .into_plaintext_router_for_test()
            .layer(::axum::Extension(httpserve::Authenticated::new(
                httpserve::NonRssTestScheme::FederatedAccessToken,
                rss_request_context::PrincipalKind::Admin,
                "runtime-inventory-test",
                Some(
                    rss_request_context::TenantId::parse("00000000-0000-4000-8000-000000000001")
                        .expect("tenant"),
                ),
            )));
        (router, proof)
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn runtime_inventory_local_only_route_has_canonical_receipt() {
        let (router, proof) = self::finalized_runtime_inventory_router();
        let observers = ::testkit::local_only::LocalOnlyObservers::new(
            ::testkit::local_only::StaticExclusion::<::testkit::local_only::BusinessWrite>::from_governed(&proof),
            ::testkit::local_only::StaticExclusion::<::testkit::local_only::Outbox>::from_governed(&proof),
            ::testkit::local_only::StaticExclusion::<::testkit::local_only::Publish>::from_governed(&proof),
        );
        let (served, receipt) = ::testkit::local_only::assert_local_only_with_receipt::<
            ::generated::http::runtime_v1::inventory::LocalOnlyConformanceMarker,
            _,
            _,
            _,
        >(
            ::generated::http::runtime_v1::inventory::SPEC
                .route
                .contract_id(),
            observers,
            move || {
                ::testkit::call(
                    router,
                    ::testkit::ContractRequest::get(
                        ::generated::http::runtime_v1::inventory::SPEC.route.path(),
                    ),
                )
            },
        )
        .await
        .expect("runtime inventory remains LocalOnly");
        ::core::assert_eq!(
            receipt.contract_id(),
            ::generated::http::runtime_v1::inventory::SPEC
                .route
                .contract_id()
        );
        served
            .expect("call runtime inventory route")
            .ensure_status(axum::http::StatusCode::FORBIDDEN)
            .expect("unfinalized inventory route remains fail-closed");
    }
}
