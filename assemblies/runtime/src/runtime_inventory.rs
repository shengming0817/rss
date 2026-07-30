//! Assembly-local projection from runtime observations to the generated inventory wire contract.

use axum::{extract::State, response::IntoResponse as _};
use generated::http::runtime_v1::inventory as wire;
use runtimeexec::inventory as model;

#[derive(Clone)]
pub(crate) struct RuntimeInventoryRoutes {
    reader: runtimeexec::inventory::InventoryReader,
}

impl RuntimeInventoryRoutes {
    pub(crate) fn new(reader: model::InventoryReader) -> Self {
        Self { reader }
    }

    #[cfg(test)]
    pub(crate) fn unpublished_fixture(
        _config: crate::config::SnapshotConfig<'_>,
    ) -> anyhow::Result<Self> {
        let snapshot = crate::config::test_snapshot(&[
            ("RSS_PRIMARY_TOKEN_PROFILE", "rss-access"),
            ("RSS_ADMIN_TOKEN_PROFILE", "rss-access"),
            ("RSS_INTERNAL_AUTH_SCHEME", "mtls"),
        ])?;
        let config = snapshot.view();
        let plan = crate::plan::RuntimePlan::bundled(config)?;
        let provider_bindings = plan
            .as_typed()
            .provider_plans()
            .iter()
            .map(|provider| model::ProviderProbeBinding::new(provider.id(), Vec::new()))
            .collect::<Result<Vec<_>, _>>()?;
        let seed = model::RuntimeInventorySeed::from_runtime_plan(
            plan.as_typed(),
            plan.workflow_runtime().activated_workflows(),
            provider_bindings,
            plan.placement_execution_plan(config)
                .inventory_observations()?,
        )?
        .with_build_metadata(model::BuildMetadata::parse(
            &"a".repeat(40),
            &format!("sha256:{}", "b".repeat(64)),
        )?);
        let (_publisher, reader, _health_publisher, _placement_publisher) =
            model::deferred_inventory_channel(seed);
        Ok(Self::new(reader))
    }
}

impl httpserve::ClassifiedRouteState for RuntimeInventoryRoutes {
    type Effect = diport::ReadEffect;
    type Privilege = diport::LocalPrivilege;
}

impl ::bootstrap::FrameworkRoutes for RuntimeInventoryRoutes {
    fn register(
        &self,
        registry: &mut ::bootstrap::Registry,
    ) -> Result<(), ::bootstrap::KernelError> {
        let state = RuntimeInventoryRoutes::new(self.reader.clone());
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
    State(state): State<RuntimeInventoryRoutes>,
    request: axum::extract::Request,
) -> axum::response::Response {
    let request_id = httpserve::request_id_str(request.extensions()).unwrap_or("unavailable");
    match state.reader.read() {
        Ok(snapshot) => match to_wire(&snapshot) {
            Ok(response) => axum::Json(response).into_response(),
            Err(()) => httpserve::error::internal_error(request_id),
        },
        Err(model::InventoryError::Unavailable) => {
            httpserve::error::provider_unavailable(request_id)
        }
        Err(_) => httpserve::error::internal_error(request_id),
    }
}

fn to_wire(
    snapshot: &model::RuntimeInventorySnapshot,
) -> Result<wire::RuntimeInventoryResponse, ()> {
    Ok(wire::RuntimeInventoryResponse {
        data: wire::RuntimeInventoryData {
            activated_workflows: snapshot
                .activated_workflows()
                .iter()
                .map(activated_workflow_to_wire)
                .collect::<Result<_, _>>()?,
            assembly_fingerprint: parse(snapshot.assembly_fingerprint())?,
            build_metadata: snapshot
                .build_metadata()
                .map(|metadata| {
                    Ok(wire::RuntimeBuildMetadata {
                        image_digest: parse(metadata.image_digest())?,
                        source_revision: parse(metadata.source_revision())?,
                    })
                })
                .transpose()?,
            domains: snapshot
                .domains()
                .iter()
                .map(|domain| parse(domain.as_str()))
                .collect::<Result<_, _>>()?,
            listeners: snapshot
                .listeners()
                .iter()
                .map(listener_to_wire)
                .collect::<Result<_, _>>()?,
            placements: snapshot
                .placements()
                .iter()
                .map(placement_to_wire)
                .collect::<Result<_, _>>()?,
            provider_posture: snapshot
                .provider_posture()
                .iter()
                .map(|provider| {
                    Ok(wire::RuntimeProviderPosture {
                        id: parse(provider.id())?,
                        state: match provider.state() {
                            model::InventoryProviderState::Ready => {
                                wire::RuntimeProviderPostureState::Ready
                            }
                            model::InventoryProviderState::Degraded => {
                                wire::RuntimeProviderPostureState::Degraded
                            }
                            model::InventoryProviderState::Unavailable => {
                                wire::RuntimeProviderPostureState::Unavailable
                            }
                        },
                    })
                })
                .collect::<Result<_, ()>>()?,
            runtime_plan_fingerprint: parse(snapshot.runtime_plan_fingerprint())?,
            schema_version: i64::from(snapshot.schema_version()),
        },
    })
}

fn activated_workflow_to_wire(
    workflow: &model::ActivatedWorkflowObservation,
) -> Result<wire::RuntimeActivatedWorkflow, ()> {
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
                definition_schema_digest: parse(workflow.definition_schema_digest())?,
                definition_version: parse(workflow.definition_version())?,
                id: parse(workflow.id())?,
                mode: wire::RuntimeActivatedProjectionMode::Projection,
            }),
        ),
        model::InventoryWorkflowActivation::Saga(model::InventorySagaActivation::Active) => Ok(
            wire::RuntimeActivatedWorkflow::Saga(wire::RuntimeActivatedSaga {
                activation: wire::RuntimeActivatedSagaActivation::Active,
                definition_schema_digest: parse(workflow.definition_schema_digest())?,
                definition_version: parse(workflow.definition_version())?,
                id: parse(workflow.id())?,
                mode: wire::RuntimeActivatedSagaMode::Saga,
            }),
        ),
    }
}

fn listener_to_wire(
    listener: &model::BoundListenerObservation,
) -> Result<wire::RuntimeListener, ()> {
    Ok(wire::RuntimeListener {
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
        id: parse(listener.id())?,
        kind: match listener.kind() {
            assembly_schema::AssemblyListenerKind::Primary => wire::RuntimeListenerKind::Primary,
            assembly_schema::AssemblyListenerKind::Internal => wire::RuntimeListenerKind::Internal,
            assembly_schema::AssemblyListenerKind::Health => wire::RuntimeListenerKind::Health,
            assembly_schema::AssemblyListenerKind::Admin => wire::RuntimeListenerKind::Admin,
        },
    })
}

fn placement_to_wire(
    placement: &model::PlacementObservation,
) -> Result<wire::RuntimePlacement, ()> {
    Ok(wire::RuntimePlacement {
        domain: parse(placement.domain().as_str())?,
        endpoint: placement
            .endpoint()
            .map(placement_endpoint_to_wire)
            .transpose()?,
        mode: match placement.mode() {
            model::InventoryPlacementMode::Local => wire::RuntimePlacementMode::Local,
            model::InventoryPlacementMode::Remote => wire::RuntimePlacementMode::Remote,
        },
        readiness: match placement.readiness() {
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
        },
        spiffe_identity: placement.spiffe_identity().map(parse).transpose()?,
        workload: parse(placement.workload())?,
    })
}

fn endpoint_to_wire(
    endpoint: &model::InventoryEndpoint,
) -> Result<wire::RuntimeListenerEndpoint, ()> {
    endpoint_parts_to_wire(endpoint.scheme(), endpoint.host(), endpoint.port())
}

fn placement_endpoint_to_wire(
    endpoint: &model::PlacementEndpoint,
) -> Result<wire::RuntimeListenerEndpoint, ()> {
    endpoint_parts_to_wire(endpoint.scheme(), endpoint.host(), endpoint.port())
}

fn endpoint_parts_to_wire(
    scheme: model::InventoryEndpointScheme,
    host: &str,
    port: u16,
) -> Result<wire::RuntimeListenerEndpoint, ()> {
    Ok(wire::RuntimeListenerEndpoint {
        host: parse(host)?,
        port: std::num::NonZeroU64::new(u64::from(port)).ok_or(())?,
        scheme: match scheme {
            model::InventoryEndpointScheme::Http => wire::RuntimeListenerEndpointScheme::Http,
            model::InventoryEndpointScheme::Https => wire::RuntimeListenerEndpointScheme::Https,
        },
    })
}

fn parse<T>(value: &str) -> Result<T, ()>
where
    T: std::str::FromStr,
{
    value.parse().map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unpublished_inventory_returns_retryable_provider_unavailable() -> anyhow::Result<()> {
        let snapshot = crate::config::test_snapshot(&[
            ("RSS_PRIMARY_TOKEN_PROFILE", "rss-access"),
            ("RSS_ADMIN_TOKEN_PROFILE", "rss-access"),
            ("RSS_INTERNAL_AUTH_SCHEME", "mtls"),
        ])?;
        let state = RuntimeInventoryRoutes::unpublished_fixture(snapshot.view())?;
        let response = inventory_handler(
            httpserve::ContractMarker::for_test(),
            State(state),
            axum::extract::Request::new(axum::body::Body::empty()),
        )
        .await;
        assert_eq!(
            response.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
        let bytes = axum::body::to_bytes(response.into_body(), 4096).await?;
        let body: serde_json::Value = serde_json::from_slice(&bytes)?;
        assert_eq!(body["error"]["code"], "ERR_CORE_PROVIDER_UNAVAILABLE");
        assert_eq!(body["error"]["requestId"], "unavailable");
        assert_eq!(body["error"]["retryable"], true);
        assert_eq!(body["error"]["details"], serde_json::json!([]));
        Ok(())
    }
}

#[cfg(feature = "integration")]
pub mod test_support {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::SystemTime;

    use anyhow::Context as _;
    use runtimeexec::inventory as model;

    use super::RuntimeInventoryRoutes;

    #[derive(Clone, Copy)]
    pub enum JourneyCase {
        Allow,
        Deny,
        AuditFail,
        ProbeDegraded,
        ProbeUnavailable,
    }

    const ALLOWED_SUBJECT: &str = "11111111-2222-4333-8444-555555555555";
    const DENIED_SUBJECT: &str = "99999999-2222-4333-8444-555555555555";
    const TENANT: &str = "00000000-0000-4000-8000-000000000197";

    struct FixturePdp(JourneyCase);
    impl diport::Pdp for FixturePdp {
        async fn verify(
            &self,
            _: &diport::RawCredential,
        ) -> Result<diport::VerifiedClaims, diport::PdpError> {
            let tenant =
                vocab::TenantId::parse(TENANT).map_err(|_| diport::PdpError::InvalidSignature)?;
            let subject = match self.0 {
                JourneyCase::Deny => DENIED_SUBJECT,
                JourneyCase::Allow
                | JourneyCase::AuditFail
                | JourneyCase::ProbeDegraded
                | JourneyCase::ProbeUnavailable => ALLOWED_SUBJECT,
            };
            let user =
                ids::UserId::parse(subject).map_err(|_| diport::PdpError::InvalidSignature)?;
            let grant = diport::VerifiedAccessGrantFacts::try_new(
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                1_700_000_000,
                1,
            )
            .map_err(|_| diport::PdpError::InvalidSignature)?;
            Ok(diport::VerifiedClaims::rss_user(user, tenant, grant))
        }
    }

    struct InventoryRoleAuthorizer;
    impl httpserve::RouteAuthorizer for InventoryRoleAuthorizer {
        fn authorize<'a>(
            &'a self,
            request: httpserve::RouteAuthorizationRequest,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = httpserve::RouteAuthorizationDecision> + Send + 'a,
            >,
        > {
            Box::pin(async move {
                if request.contract_id == generated::http::runtime_v1::inventory::CONTRACT_ID
                    && request.permission == vocab::RoutePermissionId::RuntimeInventoryRead
                    && request.principal_kind == vocab::PrincipalKind::User
                    && request.principal_id == ALLOWED_SUBJECT
                    && request.tenant_id.is_some()
                {
                    httpserve::RouteAuthorizationDecision::Allow
                } else {
                    httpserve::RouteAuthorizationDecision::Deny
                }
            })
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

    pub async fn run_journey(case: JourneyCase) -> anyhow::Result<JourneyResult> {
        let manifest =
            assembly_schema::AssemblyManifest::from_toml_str(include_str!("../assembly.toml"))?
                .canonicalize_v2()?;
        let assembly_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let repository_root = assembly_dir
            .parent()
            .and_then(std::path::Path::parent)
            .context("runtime assembly repository root")?;
        let repository_manifest = assembly_schema::RepositoryAssemblyManifestV2::discover_v2(
            repository_root,
            assembly_dir,
        )?;
        let lock = assembly_schema::ParsedAssemblyLock::from_json_slice(include_bytes!(
            "../assembly.lock.json"
        ))?
        .verify_repository_v2(&repository_manifest)?
        .into_executable();
        let parsed = assembly_schema::ParsedRuntimePlan::from_json_slice_bound(
            include_bytes!("../runtime-plan.json"),
            &manifest,
            &lock,
        )?;
        let plan = parsed.as_plan();
        let workflow_runtime = eventexec::WorkflowRuntimePlan::compile(
            plan,
            eventexec::WorkflowCapabilityCatalog::empty(),
        )?;
        let (probe_name, reporter) = journey_probe_chain(case)?;
        let bindings = plan
            .provider_plans()
            .iter()
            .map(|provider| {
                model::ProviderProbeBinding::new(provider.id(), vec![probe_name.clone()])
            })
            .collect::<Result<Vec<_>, _>>()?;
        let placements = plan
            .placement_plans()
            .iter()
            .map(|placement| {
                model::PlacementObservation::local(placement.domain(), placement.workload())
            })
            .collect();
        let seed = model::RuntimeInventorySeed::from_runtime_plan(
            plan,
            workflow_runtime.activated_workflows(),
            bindings,
            placements,
        )?
        .with_build_metadata(model::BuildMetadata::parse(
            &"a".repeat(40),
            &format!("sha256:{}", "b".repeat(64)),
        )?);
        let (publisher, reader) = model::inventory_channel(seed, reporter);
        let mut registry = bootstrap::Registry::new();
        crate::modules_gen::register_framework_routes(
            &RuntimeInventoryRoutes::new(reader),
            &mut registry,
        )?;
        let mounted = registry.finalize_routes()?;
        bootstrap::validate_framework_serving(&mounted, crate::modules_gen::FRAMEWORK_HTTP_ROUTES)?;
        let (_, routes) = mounted
            .into_iter()
            .find(|(kind, _)| *kind == primitives::ListenerKind::Admin)
            .context("runtime journey Admin inventory route")?;
        let plan = primitives::AuthPlan::new(
            primitives::ListenerKind::Admin,
            primitives::AuthScheme::RssAccessToken,
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
            Arc::new(InventoryRoleAuthorizer),
        )?;
        let routes = crate::auth_bridge::apply_rss_access_pdp_bridge_for_test(
            routes,
            FixturePdp(case),
            crate::test_support::always_current_access_grants(),
        );
        let response = crate::launch::serve_inventory_journey(
            routes,
            publisher,
            "e30.eyJzdWIiOiJydW50aW1lLWZpeHR1cmUifQ.c2ln".to_owned(),
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
