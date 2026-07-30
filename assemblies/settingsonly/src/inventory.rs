//! Assembly-owned HTTP projection for the provider-independent runtime inventory.

use std::num::NonZeroU64;

use anyhow::Context as _;
use axum::extract::State;
use axum::response::IntoResponse as _;
use generated::http::runtime_v1::inventory as wire;
use runtimeexec::inventory as model;

#[derive(Clone)]
pub(crate) struct InventoryFrameworkRoutes {
    reader: runtimeexec::inventory::InventoryReader,
}

impl InventoryFrameworkRoutes {
    pub(crate) const fn new(reader: model::InventoryReader) -> Self {
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
            let endpoint = ::httpserve::GeneratedEndpoint::new(
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
    request: axum::extract::Request,
) -> axum::response::Response {
    let request_id =
        httpserve::request_id_str(request.extensions()).unwrap_or("settingsonly-runtime-inventory");
    inventory_response(&state.reader, request_id)
}

fn inventory_response(
    reader: &model::InventoryReader,
    request_id: &str,
) -> axum::response::Response {
    let snapshot = match reader.read() {
        Ok(snapshot) => snapshot,
        Err(model::InventoryError::Unavailable) => {
            return httpserve::error::provider_unavailable(request_id);
        }
        Err(error) => {
            tracing::error!(
                contract_id = wire::CONTRACT_ID,
                error = %error,
                "settingsonly runtime inventory is unavailable"
            );
            return httpserve::error::internal_error(request_id);
        }
    };
    project_inventory_response(&snapshot, request_id)
}

fn project_inventory_response(
    snapshot: &model::RuntimeInventorySnapshot,
    request_id: &str,
) -> axum::response::Response {
    match response_from_snapshot(snapshot) {
        Ok(response) => axum::Json(response).into_response(),
        Err(error) => {
            tracing::error!(
                contract_id = wire::CONTRACT_ID,
                error = %error,
                "settingsonly runtime inventory projection failed"
            );
            httpserve::error::internal_error(request_id)
        }
    }
}

fn response_from_snapshot(
    snapshot: &model::RuntimeInventorySnapshot,
) -> anyhow::Result<wire::RuntimeInventoryResponse> {
    Ok(wire::RuntimeInventoryResponse {
        data: wire::RuntimeInventoryData {
            activated_workflows: snapshot
                .activated_workflows()
                .iter()
                .map(activated_workflow_to_wire)
                .collect::<anyhow::Result<_>>()?,
            schema_version: i64::from(snapshot.schema_version()),
            assembly_fingerprint: snapshot
                .assembly_fingerprint()
                .parse()
                .context("convert assembly fingerprint")?,
            build_metadata: snapshot
                .build_metadata()
                .map(|metadata| {
                    Ok::<_, anyhow::Error>(wire::RuntimeBuildMetadata {
                        image_digest: metadata
                            .image_digest()
                            .parse()
                            .context("convert declared image digest")?,
                        source_revision: metadata
                            .source_revision()
                            .parse()
                            .context("convert build source revision")?,
                    })
                })
                .transpose()?,
            runtime_plan_fingerprint: snapshot
                .runtime_plan_fingerprint()
                .parse()
                .context("convert RuntimePlan fingerprint")?,
            domains: snapshot
                .domains()
                .iter()
                .map(|domain| domain.as_str().parse().context("convert runtime domain"))
                .collect::<anyhow::Result<_>>()?,
            listeners: snapshot
                .listeners()
                .iter()
                .map(listener_to_wire)
                .collect::<anyhow::Result<_>>()?,
            provider_posture: snapshot
                .provider_posture()
                .iter()
                .map(provider_to_wire)
                .collect::<anyhow::Result<_>>()?,
            placements: snapshot
                .placements()
                .iter()
                .map(placement_to_wire)
                .collect::<anyhow::Result<_>>()?,
        },
    })
}

fn activated_workflow_to_wire(
    workflow: &model::ActivatedWorkflowObservation,
) -> anyhow::Result<wire::RuntimeActivatedWorkflow> {
    match workflow.activation() {
        model::InventoryWorkflowActivation::Projection(activation) => Ok(
            wire::RuntimeActivatedWorkflow::Projection(wire::RuntimeActivatedProjection {
                activation: match activation {
                    model::InventoryProjectionActivation::CaptureOnly => {
                        wire::RuntimeActivatedProjectionActivation::CaptureOnly
                    }
                    model::InventoryProjectionActivation::Shadow => {
                        wire::RuntimeActivatedProjectionActivation::Shadow
                    }
                    model::InventoryProjectionActivation::Active => {
                        wire::RuntimeActivatedProjectionActivation::Active
                    }
                },
                definition_schema_digest: workflow
                    .definition_schema_digest()
                    .parse()
                    .context("convert workflow definition schema digest")?,
                definition_version: workflow
                    .definition_version()
                    .parse()
                    .context("convert workflow definition version")?,
                id: workflow.id().parse().context("convert workflow id")?,
                mode: wire::RuntimeActivatedProjectionMode::Projection,
            }),
        ),
        model::InventoryWorkflowActivation::Saga(model::InventorySagaActivation::Active) => Ok(
            wire::RuntimeActivatedWorkflow::Saga(wire::RuntimeActivatedSaga {
                activation: wire::RuntimeActivatedSagaActivation::Active,
                definition_schema_digest: workflow
                    .definition_schema_digest()
                    .parse()
                    .context("convert workflow definition schema digest")?,
                definition_version: workflow
                    .definition_version()
                    .parse()
                    .context("convert workflow definition version")?,
                id: workflow.id().parse().context("convert workflow id")?,
                mode: wire::RuntimeActivatedSagaMode::Saga,
            }),
        ),
    }
}

fn listener_to_wire(
    listener: &model::BoundListenerObservation,
) -> anyhow::Result<wire::RuntimeListener> {
    Ok(wire::RuntimeListener {
        id: listener.id().parse().context("convert listener id")?,
        kind: listener
            .kind()
            .as_str()
            .parse()
            .context("convert listener kind")?,
        auth_scheme: match listener.auth() {
            assembly_schema::ListenerAuth::NoAuth => wire::RuntimeAuthScheme::NoAuth,
            assembly_schema::ListenerAuth::RssAccessToken => {
                wire::RuntimeAuthScheme::RssAccessToken
            }
            assembly_schema::ListenerAuth::FederatedAccessToken => {
                wire::RuntimeAuthScheme::FederatedAccessToken
            }
            assembly_schema::ListenerAuth::Mtls => wire::RuntimeAuthScheme::Mtls,
            assembly_schema::ListenerAuth::ServiceToken => wire::RuntimeAuthScheme::ServiceToken,
        },
        endpoint: endpoint_to_wire(listener.endpoint())?,
    })
}

fn endpoint_to_wire(
    endpoint: &model::InventoryEndpoint,
) -> anyhow::Result<wire::RuntimeListenerEndpoint> {
    endpoint_parts_to_wire(endpoint.scheme(), endpoint.host(), endpoint.port())
}

fn placement_endpoint_to_wire(
    endpoint: &model::PlacementEndpoint,
) -> anyhow::Result<wire::RuntimeListenerEndpoint> {
    endpoint_parts_to_wire(endpoint.scheme(), endpoint.host(), endpoint.port())
}

fn endpoint_parts_to_wire(
    endpoint_scheme: model::InventoryEndpointScheme,
    host: &str,
    port: u16,
) -> anyhow::Result<wire::RuntimeListenerEndpoint> {
    let scheme = match endpoint_scheme {
        model::InventoryEndpointScheme::Http => wire::RuntimeListenerEndpointScheme::Http,
        model::InventoryEndpointScheme::Https => wire::RuntimeListenerEndpointScheme::Https,
    };
    Ok(wire::RuntimeListenerEndpoint {
        scheme,
        host: host.parse().context("convert listener host")?,
        port: NonZeroU64::new(u64::from(port)).context("convert listener port")?,
    })
}

fn provider_to_wire(
    provider: &model::ProviderPosture,
) -> anyhow::Result<wire::RuntimeProviderPosture> {
    let state = match provider.state() {
        model::InventoryProviderState::Ready => wire::RuntimeProviderPostureState::Ready,
        model::InventoryProviderState::Degraded => wire::RuntimeProviderPostureState::Degraded,
        model::InventoryProviderState::Unavailable => {
            wire::RuntimeProviderPostureState::Unavailable
        }
    };
    Ok(wire::RuntimeProviderPosture {
        id: provider.id().parse().context("convert provider id")?,
        state,
    })
}

fn placement_to_wire(
    placement: &model::PlacementObservation,
) -> anyhow::Result<wire::RuntimePlacement> {
    let mode = match placement.mode() {
        model::InventoryPlacementMode::Local => wire::RuntimePlacementMode::Local,
        model::InventoryPlacementMode::Remote => wire::RuntimePlacementMode::Remote,
    };
    let readiness = match placement.readiness() {
        model::InventoryPlacementReadiness::Ready => wire::RuntimePlacementReadiness::Ready,
        model::InventoryPlacementReadiness::MtlsSourceUnavailable => {
            wire::RuntimePlacementReadiness::MtlsSourceUnavailable
        }
        model::InventoryPlacementReadiness::PeerEndpointUnresolved => {
            wire::RuntimePlacementReadiness::PeerEndpointUnresolved
        }
        model::InventoryPlacementReadiness::PeerEndpointUnavailable => {
            wire::RuntimePlacementReadiness::PeerEndpointUnavailable
        }
    };
    Ok(wire::RuntimePlacement {
        domain: placement
            .domain()
            .as_str()
            .parse()
            .context("convert placement domain")?,
        workload: placement
            .workload()
            .parse()
            .context("convert placement workload")?,
        mode,
        endpoint: placement
            .endpoint()
            .map(placement_endpoint_to_wire)
            .transpose()?,
        spiffe_identity: placement
            .spiffe_identity()
            .map(str::parse)
            .transpose()
            .context("convert placement SPIFFE identity")?,
        readiness,
    })
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
            let tenant = vocab::TenantId::parse("00000000-0000-4000-8000-000000000179")
                .map_err(|_| diport::PdpError::InvalidSignature)?;
            let kind = match self.0 {
                JourneyCase::Deny => vocab::PrincipalKind::User,
                JourneyCase::Allow
                | JourneyCase::AuditFail
                | JourneyCase::ProbeDegraded
                | JourneyCase::ProbeUnavailable => vocab::PrincipalKind::Admin,
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

    fn journey_probe_chain(
        case: JourneyCase,
    ) -> anyhow::Result<(primitives::ProbeName, Arc<bootstrap::HealthReporter>)> {
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
        Ok((name, Arc::new(registry.take_health_reporter())))
    }

    pub struct JourneyResult {
        pub status: reqwest::StatusCode,
        pub body: Vec<u8>,
        pub serving_address: std::net::SocketAddr,
        pub audit_calls: usize,
    }

    /// Exercise the assembly-owned Admin route over the same bound socket represented in the
    /// published inventory. Authentication and authorization use the production listener funnel;
    /// only the credential PDP and durable audit outcome are controlled test evidence.
    pub async fn run_journey(case: JourneyCase) -> anyhow::Result<JourneyResult> {
        let plan = crate::plan::SettingsOnlyPlan::bundled()?;
        let (probe_name, reporter) = journey_probe_chain(case)?;
        let bindings = crate::providers_gen::PROVIDER_CATALOG
            .iter()
            .map(|provider| {
                model::ProviderProbeBinding::new(provider.role().as_str(), vec![probe_name.clone()])
            })
            .collect::<Result<Vec<_>, _>>()?;
        let seed = plan.into_inventory_seed_fixture(bindings)?;
        let (publisher, reader) = model::inventory_channel(seed, Arc::clone(&reporter));
        let mut registry = bootstrap::Registry::new();
        crate::modules_gen::register_framework_routes(
            &InventoryFrameworkRoutes::new(reader),
            &mut registry,
        )?;
        let mounted = registry.finalize_routes()?;
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
        )
        .await?;
        Ok(JourneyResult {
            status: response.status,
            body: response.body,
            serving_address: response.serving_address,
            audit_calls: audit_calls.load(Ordering::Acquire),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::SystemTime;

    use super::*;

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

    fn inventory_reader(publish: bool) -> anyhow::Result<model::InventoryReader> {
        let plan = crate::plan::SettingsOnlyPlan::bundled()?;
        let bindings = crate::providers_gen::PROVIDER_CATALOG
            .iter()
            .map(|provider| model::ProviderProbeBinding::new(provider.role().as_str(), Vec::new()))
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

    fn published_inventory_reader() -> anyhow::Result<model::InventoryReader> {
        inventory_reader(true)
    }

    #[tokio::test]
    async fn unpublished_inventory_returns_retryable_provider_unavailable() -> anyhow::Result<()> {
        let response = inventory_response(&inventory_reader(false)?, "inventory-unpublished");
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
        model::InventoryReader,
        Vec<(primitives::ListenerKind, httpserve::UnfinalizedRoutes)>,
    )> {
        let reader = published_inventory_reader()?;
        let mut registry = bootstrap::Registry::new();
        crate::modules_gen::register_framework_routes(
            &InventoryFrameworkRoutes::new(reader.clone()),
            &mut registry,
        )?;
        let mounted = registry.finalize_routes()?;
        bootstrap::validate_framework_serving(&mounted, crate::modules_gen::FRAMEWORK_HTTP_ROUTES)?;
        Ok((reader, mounted))
    }

    fn authenticated_inventory_router(
        kind: vocab::PrincipalKind,
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
        let tenant = if kind == vocab::PrincipalKind::SuperAdmin {
            None
        } else {
            Some(vocab::TenantId::parse(
                "00000000-0000-4000-8000-000000000001",
            )?)
        };
        let permissions =
            diport::VerifiedFederatedPermissions::new([vocab::GrantPermission::route(permission)])?;
        let authenticated = httpserve::Authenticated::new_federated(
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
        .into_router_for_test()
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
        for kind in [vocab::PrincipalKind::User, vocab::PrincipalKind::Admin] {
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
                vocab::PrincipalKind::SuperAdmin,
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
                vocab::PrincipalKind::SuperAdmin,
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
        let response = response_from_snapshot(&reader.read()?)?;
        assert_eq!(response.data.schema_version, 1);
        assert!(response.data.activated_workflows.is_empty());
        assert_eq!(response.data.domains, [wire::RuntimeDomain::Settings]);
        assert_eq!(response.data.listeners.len(), 3);
        assert_eq!(
            response.data.provider_posture.len(),
            crate::providers_gen::PROVIDER_CATALOG.len()
        );
        assert_eq!(response.data.placements.len(), 1);
        let encoded = serde_json::to_value(response)?;
        assert_eq!(encoded["data"]["activatedWorkflows"], serde_json::json!([]));
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
        let mut finalized = registry
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
            .into_router_for_test()
            .layer(::axum::Extension(httpserve::Authenticated::new(
                primitives::RequiredScheme::FederatedAccessToken,
                vocab::PrincipalKind::Admin,
                "runtime-inventory-test",
                Some(
                    vocab::TenantId::parse("00000000-0000-4000-8000-000000000001").expect("tenant"),
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
