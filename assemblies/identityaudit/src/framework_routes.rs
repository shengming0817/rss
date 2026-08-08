//! Assembly-local serving adapter for framework-owned runtime inventory.

use std::num::NonZeroU64;

use anyhow::Context as _;
use assembly_schema::{AssemblyDomain, AssemblyListenerKind, ListenerAuth};
use axum::Json;
use axum::extract::State;
use axum::response::{IntoResponse as _, Response};
use generated::http::runtime_v1::inventory as wire;
use runtimeexec::inventory::{
    InventoryEndpoint, InventoryEndpointScheme, InventoryPlacementMode,
    InventoryPlacementReadiness, InventoryProviderState, RuntimeInventorySnapshot,
};

const ROUTE_PREFIX: &str = "/api/v1/runtime";

#[derive(Clone)]
pub(crate) struct IdentityAuditFrameworkRoutes {
    inventory: runtimeexec::inventory::InventoryReader,
}

impl IdentityAuditFrameworkRoutes {
    pub(crate) const fn new(inventory: runtimeexec::inventory::InventoryReader) -> Self {
        Self { inventory }
    }
}

impl httpserve::ClassifiedRouteState for IdentityAuditFrameworkRoutes {
    type Effect = diport::ReadEffect;
    type Privilege = diport::LocalPrivilege;
}

impl ::bootstrap::FrameworkRoutes for IdentityAuditFrameworkRoutes {
    fn register(
        &self,
        registry: &mut ::bootstrap::Registry,
    ) -> Result<(), ::bootstrap::KernelError> {
        let state = IdentityAuditFrameworkRoutes::new(self.inventory.clone());
        registry.route_group::<::httpserve::Admin>(ROUTE_PREFIX, move |routes| {
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
    State(state): State<IdentityAuditFrameworkRoutes>,
    request: axum::extract::Request,
) -> Response {
    let request_id = httpserve::request_id_str(request.extensions())
        .unwrap_or("identityaudit-runtime-inventory");
    inventory_http_response(&state.inventory, request_id)
}

#[allow(
    clippy::cognitive_complexity,
    reason = "closed inventory error mapping keeps each typed failure at the HTTP boundary"
)]
fn inventory_http_response(
    reader: &runtimeexec::inventory::InventoryReader,
    request_id: &str,
) -> Response {
    match reader.read() {
        Ok(snapshot) => match inventory_response(&snapshot) {
            Ok(response) => Json(response).into_response(),
            Err(error) => {
                tracing::error!(
                    contract_id = wire::CONTRACT_ID,
                    error = %error,
                    "identityaudit runtime inventory projection failed"
                );
                httpserve::error::internal_error(request_id)
            }
        },
        Err(runtimeexec::inventory::InventoryError::Unavailable) => {
            httpserve::error::provider_unavailable(request_id)
        }
        Err(error) => {
            tracing::error!(
                contract_id = wire::CONTRACT_ID,
                error = %error,
                "identityaudit runtime inventory is unavailable"
            );
            httpserve::error::internal_error(request_id)
        }
    }
}

fn inventory_response(
    snapshot: &RuntimeInventorySnapshot,
) -> anyhow::Result<wire::RuntimeInventoryResponse> {
    Ok(wire::RuntimeInventoryResponse {
        data: wire::RuntimeInventoryData {
            activated_workflows: snapshot
                .activated_workflows()
                .iter()
                .map(activated_workflow)
                .collect::<anyhow::Result<_>>()?,
            assembly_fingerprint: parse(snapshot.assembly_fingerprint(), "assembly fingerprint")?,
            build_metadata: snapshot
                .build_metadata()
                .map(|metadata| {
                    Ok::<_, anyhow::Error>(wire::RuntimeBuildMetadata {
                        image_digest: parse(metadata.image_digest(), "declared image digest")?,
                        source_revision: parse(
                            metadata.source_revision(),
                            "build source revision",
                        )?,
                    })
                })
                .transpose()?,
            domains: snapshot.domains().iter().copied().map(domain).collect(),
            listeners: snapshot
                .listeners()
                .iter()
                .map(|listener| {
                    Ok(wire::RuntimeListener {
                        auth_scheme: auth(listener.auth()),
                        endpoint: endpoint(listener.endpoint())?,
                        id: parse(listener.id(), "listener id")?,
                        kind: listener_kind(listener.kind()),
                    })
                })
                .collect::<anyhow::Result<Vec<_>>>()?,
            placements: snapshot
                .placements()
                .iter()
                .map(|placement| {
                    Ok(wire::RuntimePlacement {
                        domain: domain(placement.domain()),
                        endpoint: placement.endpoint().map(placement_endpoint).transpose()?,
                        mode: placement_mode(placement.mode()),
                        readiness: placement_readiness(placement.readiness()),
                        spiffe_identity: placement
                            .spiffe_identity()
                            .map(|identity| parse(identity, "placement SPIFFE identity"))
                            .transpose()?,
                        workload: parse(placement.workload(), "placement workload")?,
                    })
                })
                .collect::<anyhow::Result<Vec<_>>>()?,
            provider_posture: snapshot
                .provider_posture()
                .iter()
                .map(|provider| {
                    Ok(wire::RuntimeProviderPosture {
                        id: parse(provider.id(), "provider id")?,
                        state: provider_state(provider.state()),
                    })
                })
                .collect::<anyhow::Result<Vec<_>>>()?,
            runtime_plan_fingerprint: parse(
                snapshot.runtime_plan_fingerprint(),
                "runtime plan fingerprint",
            )?,
            schema_version: i64::from(snapshot.schema_version()),
        },
    })
}

fn activated_workflow(
    workflow: &runtimeexec::inventory::ActivatedWorkflowObservation,
) -> anyhow::Result<wire::RuntimeActivatedWorkflow> {
    match workflow.activation() {
        runtimeexec::inventory::InventoryWorkflowActivation::Projection(activation) => Ok(
            wire::RuntimeActivatedWorkflow::Projection(wire::RuntimeActivatedProjection {
                activation: match activation {
                    runtimeexec::inventory::InventoryProjectionActivation::CaptureOnly => {
                        wire::RuntimeActivatedProjectionActivation::CaptureOnly
                    }
                    runtimeexec::inventory::InventoryProjectionActivation::Shadow => {
                        wire::RuntimeActivatedProjectionActivation::Shadow
                    }
                    runtimeexec::inventory::InventoryProjectionActivation::Active => {
                        wire::RuntimeActivatedProjectionActivation::Active
                    }
                },
                definition_schema_digest: parse(
                    workflow.definition_schema_digest(),
                    "workflow definition schema digest",
                )?,
                definition_version: parse(
                    workflow.definition_version(),
                    "workflow definition version",
                )?,
                id: parse(workflow.id(), "workflow id")?,
                mode: wire::RuntimeActivatedProjectionMode::Projection,
            }),
        ),
        runtimeexec::inventory::InventoryWorkflowActivation::Saga(
            runtimeexec::inventory::InventorySagaActivation::Active,
        ) => Ok(wire::RuntimeActivatedWorkflow::Saga(
            wire::RuntimeActivatedSaga {
                activation: wire::RuntimeActivatedSagaActivation::Active,
                definition_schema_digest: parse(
                    workflow.definition_schema_digest(),
                    "workflow definition schema digest",
                )?,
                definition_version: parse(
                    workflow.definition_version(),
                    "workflow definition version",
                )?,
                id: parse(workflow.id(), "workflow id")?,
                mode: wire::RuntimeActivatedSagaMode::Saga,
            },
        )),
    }
}

fn parse<T>(value: &str, field: &'static str) -> anyhow::Result<T>
where
    T: std::str::FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    value.parse().with_context(|| format!("map {field}"))
}

fn endpoint(value: &InventoryEndpoint) -> anyhow::Result<wire::RuntimeListenerEndpoint> {
    endpoint_parts(value.scheme(), value.host(), value.port())
}

fn placement_endpoint(
    value: &runtimeexec::inventory::PlacementEndpoint,
) -> anyhow::Result<wire::RuntimeListenerEndpoint> {
    endpoint_parts(value.scheme(), value.host(), value.port())
}

fn endpoint_parts(
    scheme: InventoryEndpointScheme,
    host: &str,
    port: u16,
) -> anyhow::Result<wire::RuntimeListenerEndpoint> {
    Ok(wire::RuntimeListenerEndpoint {
        host: parse(host, "listener endpoint host")?,
        port: NonZeroU64::new(u64::from(port)).context("listener endpoint port is zero")?,
        scheme: match scheme {
            InventoryEndpointScheme::Http => wire::RuntimeListenerEndpointScheme::Http,
            InventoryEndpointScheme::Https => wire::RuntimeListenerEndpointScheme::Https,
        },
    })
}

const fn domain(value: AssemblyDomain) -> wire::RuntimeDomain {
    match value {
        AssemblyDomain::Identity => wire::RuntimeDomain::Identity,
        AssemblyDomain::Settings => wire::RuntimeDomain::Settings,
        AssemblyDomain::Audit => wire::RuntimeDomain::Audit,
        AssemblyDomain::Contractreg => wire::RuntimeDomain::Contractreg,
        AssemblyDomain::Syshealth => wire::RuntimeDomain::Syshealth,
    }
}

const fn listener_kind(value: AssemblyListenerKind) -> wire::RuntimeListenerKind {
    match value {
        AssemblyListenerKind::Primary => wire::RuntimeListenerKind::Primary,
        AssemblyListenerKind::Internal => wire::RuntimeListenerKind::Internal,
        AssemblyListenerKind::Health => wire::RuntimeListenerKind::Health,
        AssemblyListenerKind::Admin => wire::RuntimeListenerKind::Admin,
    }
}

const fn auth(value: ListenerAuth) -> wire::RuntimeAuthScheme {
    match value {
        ListenerAuth::NoAuth => wire::RuntimeAuthScheme::NoAuth,
        ListenerAuth::RssAccessToken => wire::RuntimeAuthScheme::RssAccessToken,
        ListenerAuth::FederatedAccessToken => wire::RuntimeAuthScheme::FederatedAccessToken,
        ListenerAuth::Mtls => wire::RuntimeAuthScheme::Mtls,
        ListenerAuth::ServiceToken => wire::RuntimeAuthScheme::ServiceToken,
    }
}

const fn provider_state(value: InventoryProviderState) -> wire::RuntimeProviderPostureState {
    match value {
        InventoryProviderState::Ready => wire::RuntimeProviderPostureState::Ready,
        InventoryProviderState::Degraded => wire::RuntimeProviderPostureState::Degraded,
        InventoryProviderState::Unavailable => wire::RuntimeProviderPostureState::Unavailable,
    }
}

const fn placement_mode(value: InventoryPlacementMode) -> wire::RuntimePlacementMode {
    match value {
        InventoryPlacementMode::Local => wire::RuntimePlacementMode::Local,
        InventoryPlacementMode::Remote => wire::RuntimePlacementMode::Remote,
    }
}

const fn placement_readiness(
    value: InventoryPlacementReadiness,
) -> wire::RuntimePlacementReadiness {
    match value {
        InventoryPlacementReadiness::Ready => wire::RuntimePlacementReadiness::Ready,
        InventoryPlacementReadiness::MtlsSourceUnavailable => {
            wire::RuntimePlacementReadiness::MtlsSourceUnavailable
        }
    }
}

#[cfg(feature = "test-support")]
pub mod test_support {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::SystemTime;

    use anyhow::Context as _;
    use runtimeexec::inventory as model;

    use super::IdentityAuditFrameworkRoutes;

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

    struct CurrentGrant;
    impl identity::ports::AuthGrantValidator for CurrentGrant {
        async fn is_current(
            &self,
            _: identity::ports::TenantRepoScope,
            _: &authn::AccessGrantValidationInput,
            _: SystemTime,
        ) -> Result<bool, identity::ports::IdentityError> {
            Ok(true)
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
        let plan = crate::plan::IdentityAuditPlan::bundled()?;
        let (probe_name, reporter) = journey_probe_chain(case)?;
        let bindings = crate::providers_gen::PROVIDER_CATALOG
            .iter()
            .map(|provider| {
                let probe_names = if provider.role() == assembly_schema::ProviderRole::ListenerPdp {
                    vec![probe_name.clone()]
                } else {
                    Vec::new()
                };
                model::ProviderProbeBinding::new(provider.role().as_str(), probe_names)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let seed = plan.inventory_seed_fixture(bindings)?;
        let (publisher, reader) = model::inventory_channel(seed, Arc::clone(&reporter));
        let mut registry = bootstrap::Registry::new();
        crate::modules_gen::register_framework_routes(
            &IdentityAuditFrameworkRoutes::new(reader),
            &mut registry,
        )?;
        let mounted = registry.finalize_routes()?;
        bootstrap::validate_framework_serving(&mounted, crate::modules_gen::FRAMEWORK_HTTP_ROUTES)?;
        let (_, routes) = mounted
            .into_iter()
            .find(|(kind, _)| *kind == primitives::ListenerKind::Admin)
            .context("identityaudit journey Admin inventory route")?;
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
        let grants = Arc::new(identity::AuthGrantValidationService::new(
            Arc::from(identity::ports::DynAuthGrantValidator::new_box(
                CurrentGrant,
            )),
            Box::new(Clock),
        ));
        let verifier = crate::auth_bridge::RssAccessVerifier::test(
            diport::DynPdp::new_arc(FixturePdp(case)),
            grants,
        );
        let routes = crate::auth_bridge::apply(routes, verifier);
        let response = crate::listeners::serve_inventory_journey(
            routes,
            reporter,
            publisher,
            "e30.eyJzdWIiOiJpZGVudGl0eWF1ZGl0LWZpeHR1cmUifQ.c2ln".to_owned(),
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

    use super::*;
    use runtimeexec::inventory::{BoundListenerObservation, ProviderProbeBinding};

    fn inventory_channel_fixture() -> anyhow::Result<(
        runtimeexec::inventory::InventoryPublisher,
        runtimeexec::inventory::InventoryReader,
    )> {
        let plan = crate::plan::IdentityAuditPlan::bundled()?;
        let provider_bindings = crate::providers_gen::PROVIDER_CATALOG
            .iter()
            .map(|entry| ProviderProbeBinding::new(entry.role().as_str(), Vec::new()))
            .collect::<Result<Vec<_>, _>>()?;
        let seed = plan.inventory_seed_fixture(provider_bindings)?;
        let reporter = Arc::new(bootstrap::Registry::new().take_health_reporter());
        Ok(runtimeexec::inventory::inventory_channel(seed, reporter))
    }

    #[tokio::test]
    async fn unpublished_inventory_returns_retryable_provider_unavailable() -> anyhow::Result<()> {
        let (_publisher, reader) = inventory_channel_fixture()?;
        let response = inventory_http_response(&reader, "inventory-unpublished");
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

    #[test]
    fn framework_route_and_dto_mapping_are_exact() -> anyhow::Result<()> {
        let mut registry = bootstrap::compose(&[])?;
        let (publisher, reader) = inventory_channel_fixture()?;
        crate::modules_gen::register_framework_routes(
            &IdentityAuditFrameworkRoutes::new(reader.clone()),
            &mut registry,
        )?;
        let mounted = registry.finalize_routes()?;
        bootstrap::validate_framework_serving(&mounted, crate::modules_gen::FRAMEWORK_HTTP_ROUTES)?;

        publisher.publish(vec![
            BoundListenerObservation::from_bound(
                "primary-main",
                AssemblyListenerKind::Primary,
                ListenerAuth::RssAccessToken,
                InventoryEndpointScheme::Http,
                "127.0.0.1:18080".parse()?,
            ),
            BoundListenerObservation::from_bound(
                "admin-main",
                AssemblyListenerKind::Admin,
                ListenerAuth::RssAccessToken,
                InventoryEndpointScheme::Http,
                "127.0.0.1:18081".parse()?,
            ),
            BoundListenerObservation::from_bound(
                "health-main",
                AssemblyListenerKind::Health,
                ListenerAuth::NoAuth,
                InventoryEndpointScheme::Http,
                "127.0.0.1:18083".parse()?,
            ),
        ])?;
        let response = inventory_response(&reader.read()?)?;
        assert_eq!(response.data.schema_version, 1);
        assert!(response.data.activated_workflows.is_empty());
        assert_eq!(response.data.listeners.len(), 3);
        assert_eq!(response.data.provider_posture.len(), 9);
        assert_eq!(response.data.placements.len(), 2);
        let encoded = serde_json::to_value(response)?;
        assert_eq!(encoded["data"]["activatedWorkflows"], serde_json::json!([]));
        Ok(())
    }
}
