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
    match reader.read() {
        Ok(snapshot) => match response_from_snapshot(&snapshot) {
            Ok(response) => axum::Json(response).into_response(),
            Err(error) => {
                tracing::error!(
                    contract_id = wire::CONTRACT_ID,
                    error = %error,
                    "settingsonly runtime inventory projection failed"
                );
                httpserve::error::internal_error(request_id)
            }
        },
        Err(model::InventoryError::Unavailable) => {
            httpserve::error::provider_unavailable(request_id)
        }
        Err(error) => {
            tracing::error!(
                contract_id = wire::CONTRACT_ID,
                error = %error,
                "settingsonly runtime inventory is unavailable"
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
            schema_version: i64::from(snapshot.schema_version()),
            assembly_fingerprint: snapshot
                .assembly_fingerprint()
                .parse()
                .context("convert assembly fingerprint")?,
            runtime_plan_fingerprint: snapshot
                .runtime_plan_fingerprint()
                .parse()
                .context("convert RuntimePlan fingerprint")?,
            deployment_fingerprint: snapshot
                .deployment_fingerprint()
                .parse()
                .context("convert DeploymentPlan fingerprint")?,
            build_identity: wire::RuntimeBuildIdentity {
                source_sha: snapshot
                    .build_identity()
                    .source_sha()
                    .parse()
                    .context("convert build source SHA")?,
                image_digest: snapshot
                    .build_identity()
                    .image_digest()
                    .parse()
                    .context("convert build image digest")?,
            },
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
    use std::net::TcpListener;
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
        let deployment = assembly_schema::ParsedDeploymentPlan::from_json_slice(
            plan.as_typed(),
            include_bytes!("../../../deploy/generated/settingsonly.deployment-plan.json"),
        )?;
        let workload = deployment
            .workloads()
            .first()
            .context("settingsonly journey deployment workload")?
            .name();
        let image = deployment
            .workloads()
            .iter()
            .find(|candidate| candidate.name() == workload)
            .context("settingsonly journey deployment workload")?
            .image();
        let digest = image
            .rsplit_once('@')
            .context("settingsonly journey immutable image")?
            .1;
        let build = model::BuildIdentity::parse(&"a".repeat(40), digest)?;
        let (probe_name, reporter) = journey_probe_chain(case)?;
        let bindings = crate::providers_gen::PROVIDER_CATALOG
            .iter()
            .map(|provider| {
                model::ProviderProbeBinding::new(provider.role().as_str(), vec![probe_name.clone()])
            })
            .collect::<Result<Vec<_>, _>>()?;
        let listener_port = |kind: assembly_schema::AssemblyListenerKind| {
            let name = match kind {
                assembly_schema::AssemblyListenerKind::Primary => "http",
                assembly_schema::AssemblyListenerKind::Admin => "admin",
                assembly_schema::AssemblyListenerKind::Internal => "internal",
                assembly_schema::AssemblyListenerKind::Health => "health",
            };
            deployment
                .services()
                .iter()
                .filter(|service| service.workload() == workload)
                .flat_map(|service| service.ports())
                .find(|port| port.name() == name)
                .map(|port| port.port())
                .with_context(|| format!("settingsonly journey {name} deployment port"))
        };
        let mut sockets = Vec::<(assembly_schema::AssemblyListenerKind, TcpListener)>::new();
        let observations = plan
            .as_typed()
            .listener_plans()
            .iter()
            .map(|listener| {
                let socket =
                    std::net::TcpListener::bind(("127.0.0.1", listener_port(listener.kind())?))?;
                let address = socket.local_addr()?;
                sockets.push((listener.kind(), socket));
                Ok(model::BoundListenerObservation::from_bound(
                    listener.id(),
                    listener.kind(),
                    listener.auth(),
                    model::InventoryEndpointScheme::Http,
                    address,
                ))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let seed = plan.into_inventory_seed_fixture(build, bindings)?;
        let (publisher, reader) = model::inventory_channel(seed, reporter);
        publisher.publish(observations)?;
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
            Arc::new(crate::listeners::InventoryAuthorizer),
        )?;
        let verifier =
            crate::auth_bridge::FederatedVerifier::test(diport::DynPdp::new_arc(FixturePdp(case)));
        let router = crate::auth_bridge::apply(routes, verifier).into_router_for_test();
        let admin_index = sockets
            .iter()
            .position(|(kind, _)| *kind == assembly_schema::AssemblyListenerKind::Admin)
            .context("settingsonly journey Admin socket")?;
        let (_, admin) = sockets.swap_remove(admin_index);
        let serving_address = admin.local_addr()?;
        admin.set_nonblocking(true)?;
        let listener = tokio::net::TcpListener::from_std(admin)?;
        let server = tokio::spawn(async move { axum::serve(listener, router).await });
        let response = reqwest::Client::new()
            .get(format!(
                "http://{serving_address}{}",
                generated::http::runtime_v1::inventory::PATH
            ))
            .bearer_auth(crate::test_support::valid_federated_token())
            .send()
            .await?;
        let status = response.status();
        let body = response.bytes().await?.to_vec();
        server.abort();
        let _ = server.await;
        drop(sockets);
        Ok(JourneyResult {
            status,
            body,
            serving_address,
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
        let deployment: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../deploy/generated/settingsonly.deployment-plan.json"
        ))?;
        let image = deployment["workloads"][0]["image"]
            .as_str()
            .context("deployment image")?;
        let digest = image.rsplit_once('@').context("immutable image")?.1;
        let build = model::BuildIdentity::parse(&"a".repeat(40), digest)?;
        let bindings = crate::providers_gen::PROVIDER_CATALOG
            .iter()
            .map(|provider| model::ProviderProbeBinding::new(provider.role().as_str(), Vec::new()))
            .collect::<Result<Vec<_>, _>>()?;
        let seed = plan.into_inventory_seed_fixture(build, bindings)?;
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
        let authenticated = httpserve::Authenticated::new(
            primitives::RequiredScheme::FederatedAccessToken,
            kind,
            "inventory-operator",
            tenant,
        );
        Ok(httpserve::finalize_auth_with_audit_and_authorizer(
            routes,
            plan,
            httpserve::AuditSinkHandle::new(TestAuditSink { fail: audit_fails }),
            Arc::new(TestClock),
            Arc::new(crate::listeners::InventoryAuthorizer),
        )?
        .into_router_for_test()
        .layer(axum::Extension(authenticated)))
    }

    #[tokio::test]
    async fn generated_global_inventory_auth_funnel_allows_operators_and_denies_user()
    -> anyhow::Result<()> {
        assert_eq!(
            wire::ROUTE.evidence().resource_sharing(),
            vocab::http::HttpResourceSharing::Global
        );
        assert_eq!(wire::ROUTE.evidence().resource(), Some("runtimeInventory"));
        for kind in [
            vocab::PrincipalKind::Admin,
            vocab::PrincipalKind::SuperAdmin,
        ] {
            testkit::call(
                authenticated_inventory_router(kind, false)?,
                testkit::ContractRequest::get(wire::PATH),
            )
            .await?
            .ensure_status(axum::http::StatusCode::OK)?;
        }
        testkit::call(
            authenticated_inventory_router(vocab::PrincipalKind::User, false)?,
            testkit::ContractRequest::get(wire::PATH),
        )
        .await?
        .ensure_status(axum::http::StatusCode::FORBIDDEN)?;
        Ok(())
    }

    #[tokio::test]
    async fn generated_global_inventory_audit_failure_remains_fail_closed() -> anyhow::Result<()> {
        testkit::call(
            authenticated_inventory_router(vocab::PrincipalKind::SuperAdmin, true)?,
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
        assert_eq!(response.data.domains, [wire::RuntimeDomain::Settings]);
        assert_eq!(response.data.listeners.len(), 3);
        assert_eq!(
            response.data.provider_posture.len(),
            crate::providers_gen::PROVIDER_CATALOG.len()
        );
        assert_eq!(response.data.placements.len(), 1);
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
