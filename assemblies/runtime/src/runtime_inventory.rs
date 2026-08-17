//! Assembly-local projection from runtime observations to the generated inventory wire contract.

use axum::extract::{Extension, State};
use generated::http::runtime_v1::inventory as wire;
#[cfg(test)]
use runtimeexec::inventory as model;

#[derive(Clone)]
pub(crate) struct RuntimeInventoryRoutes {
    application: InventoryApplication,
}

#[derive(Clone)]
struct InventoryApplication {
    dispatcher: rss_platform::Dispatcher,
    context_minter: std::sync::Arc<rss_platform::TrustedContextMinter>,
}

impl InventoryApplication {
    async fn dispatch(
        &self,
        request: AdmittedInventoryRequest,
    ) -> Result<
        rss_platform::DispatchOutcome<wire::RuntimeInventoryHandlerResult>,
        rss_platform::DispatchError,
    > {
        let AdmittedInventoryRequest {
            request_id,
            context,
        } = request;
        let admitted = self.context_minter.admit(request_id, context.view());
        self.dispatcher
            .dispatch::<InventoryContract>(
                &<InventoryContract as rss_platform::Contract>::DESCRIPTOR,
                admitted,
            )
            .await
    }
}

struct AdmittedInventoryRequest {
    request_id: httpserve::VerifiedRequestId,
    context: TrustedRequestContext,
}

impl RuntimeInventoryRoutes {
    pub(crate) fn new(
        reader: runtimeexec::inventory::InventoryReader,
        host: runtimeexec::RuntimeHostView,
    ) -> anyhow::Result<Self> {
        let application = rss_platform::ApplicationBuilder::new(
            rss_platform::ApplicationName::parse("runtime")?,
            std::sync::Arc::new(host),
        )
        .module(
            rss_platform::ApplicationModule::new(rss_platform::ModuleName::parse("inventory")?)
                .handler::<InventoryContract, _>(InventoryHandler {
                reader: reader.clone(),
            }),
        )
        .build()?;
        let (dispatcher, context_minter) = application.into_parts();
        Ok(Self {
            application: InventoryApplication {
                dispatcher,
                context_minter: std::sync::Arc::new(context_minter),
            },
        })
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
        let mut plan = crate::plan::RuntimePlan::bundled(config)?;
        plan.bind_workflow_runtime(std::iter::empty())?;
        let provider_bindings = plan
            .as_typed()
            .provider_plans()
            .iter()
            .map(|provider| {
                model::ProviderProbeBinding::from_probe_receipt(provider.id(), Vec::new())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let expected_provider_ids = plan
            .as_typed()
            .provider_plans()
            .iter()
            .map(|provider| provider.id().to_owned())
            .collect::<Vec<_>>();
        let provider_receipt = model::ProviderExecutionReceipt::seal(
            runtimeinventorymint::RuntimeInventoryMint::capability(),
            plan.as_typed().runtime_plan_fingerprint().as_str(),
            expected_provider_ids,
            provider_bindings,
        )?;
        let seed = model::RuntimeInventorySeed::from_runtime_plan(
            plan.as_typed(),
            plan.workflow_runtime().activated_workflows(),
            provider_receipt,
            plan.placement_execution_plan(bootstrap::Topology::Demo, config)?
                .inventory_observations()?,
        )?
        .with_build_metadata(model::BuildMetadata::parse(
            &"a".repeat(40),
            &format!("sha256:{}", "b".repeat(64)),
        )?);
        let (_publisher, reader, _health_publisher, _placement_publisher) =
            model::deferred_inventory_channel(seed);
        let host = runtimeexec::RuntimeHostView::ready_for_test(reader.clone());
        Self::new(reader, host)
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
        let state = self.clone();
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
    State(state): State<RuntimeInventoryRoutes>,
    Extension(request_id): Extension<httpserve::VerifiedRequestId>,
    authorized: Option<Extension<httpserve::AuthorizedSubject>>,
    control: Option<Extension<std::sync::Arc<httpserve::RequestControl>>>,
) -> wire::RuntimeInventoryHandlerResult {
    let (Some(Extension(authorized)), Some(Extension(control))) = (authorized, control) else {
        return internal_response(request_id);
    };
    let Some(trusted) = TrustedRequestContext::mint(&authorized, &request_id, control) else {
        return internal_response(request_id);
    };
    match state
        .application
        .dispatch(AdmittedInventoryRequest {
            request_id: request_id.clone(),
            context: trusted,
        })
        .await
    {
        Ok(rss_platform::DispatchOutcome::Completed(response)) => response,
        Ok(rss_platform::DispatchOutcome::HandlerFailed(class)) => {
            tracing::warn!(
                contract_id = wire::CONTRACT_ID,
                request_id = request_id.as_str(),
                failure_class = ?class,
                "platform handler failed"
            );
            internal_response(request_id)
        }
        Ok(
            rss_platform::DispatchOutcome::Cancelled
            | rss_platform::DispatchOutcome::DeadlineExceeded,
        )
        | Err(
            rss_platform::DispatchError::UnknownContract
            | rss_platform::DispatchError::DescriptorMismatch
            | rss_platform::DispatchError::AdmissionCapabilityMismatch,
        ) => internal_response(request_id),
        Err(
            rss_platform::DispatchError::HostNotReady
            | rss_platform::DispatchError::HostDraining
            | rss_platform::DispatchError::HostStopped,
        ) => unavailable_response(request_id),
    }
}

/// Assembly-private carrier minted only after the route gate produced an AuthorizedSubject.
/// Foundation values remain authority-free; only this production bridge reaches the dispatcher.
struct TrustedRequestContext {
    tenant: rss_request_context::TenantId,
    request_id: rss_request_context::RequestId,
    principal: rss_request_context::PrincipalRef,
    control: std::sync::Arc<httpserve::RequestControl>,
    fields: Box<[&'static str]>,
}

impl TrustedRequestContext {
    fn mint(
        authorized: &httpserve::AuthorizedSubject,
        request_id: &httpserve::VerifiedRequestId,
        control: std::sync::Arc<httpserve::RequestControl>,
    ) -> Option<Self> {
        if authorized.contract_id() != wire::CONTRACT_ID
            || authorized.permission() != vocab::RoutePermissionId::RuntimeInventoryRead
        {
            return None;
        }
        let projection = authorized.projection();
        let fields = [
            vocab::ProjectionField::AuditActor,
            vocab::ProjectionField::AuditTenantId,
            vocab::ProjectionField::AuditResourceId,
            vocab::ProjectionField::IdentityProfileSubject,
            vocab::ProjectionField::IdentityProfileTenantId,
        ]
        .into_iter()
        .filter(|field| projection.allows(*field))
        .map(vocab::ProjectionField::obligation_key)
        .collect::<Vec<_>>()
        .into_boxed_slice();
        Some(Self {
            tenant: authorized.tenant_id(),
            request_id: rss_request_context::RequestId::parse(request_id.as_str()).ok()?,
            principal: rss_request_context::PrincipalRef::new(
                authorized.principal_kind(),
                authorized.principal_id(),
            )
            .ok()?,
            control,
            fields,
        })
    }

    fn view(&self) -> rss_request_context::RequestContextView<'_> {
        rss_request_context::RequestContextView::new(
            Some(&self.tenant),
            &self.request_id,
            &self.principal,
            self.control.deadline(),
            rss_request_context::Cancellation::observe(self.control.as_ref()),
            rss_request_context::ObligationsView::new(
                None,
                rss_request_context::FieldMaskView::new(&self.fields),
            ),
        )
    }
}

struct InventoryContract;
impl rss_platform::Contract for InventoryContract {
    type Request = httpserve::VerifiedRequestId;
    type Response = wire::RuntimeInventoryHandlerResult;
    const DESCRIPTOR: rss_contract::ContractDescriptor = *wire::CONTRACT.descriptor();
}

struct InventoryHandler {
    reader: runtimeexec::inventory::InventoryReader,
}
impl rss_platform::Handler<InventoryContract> for InventoryHandler {
    fn handle<'a>(
        &'a self,
        request_id: httpserve::VerifiedRequestId,
        _context: rss_request_context::RequestContextView<'a>,
    ) -> rss_platform::HandlerFuture<'a, wire::RuntimeInventoryHandlerResult> {
        Box::pin(async move { Ok(inventory_response(&self.reader, request_id)) })
    }
}

fn unavailable_response(
    request_id: httpserve::VerifiedRequestId,
) -> wire::RuntimeInventoryHandlerResult {
    match wire::project_read_result(Err(
        assembly_schema::runtime_inventory::RuntimeInventoryReadFailure::Unavailable,
    )) {
        Ok(response) => Ok(wire::RuntimeInventoryResponseEnvelope::Success(response)),
        Err(failure) => Ok(wire::RuntimeInventoryResponseEnvelope::Error(
            failure.into_response_error(request_id.into_wire()),
        )),
    }
}

fn internal_response(
    request_id: httpserve::VerifiedRequestId,
) -> wire::RuntimeInventoryHandlerResult {
    Err(wire::RuntimeInventoryFrameworkFailure::internal(
        request_id.into_wire(),
    ))
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
        let authorized = httpserve::AuthorizedSubject::for_test(
            wire::CONTRACT_ID,
            vocab::RoutePermissionId::RuntimeInventoryRead,
            rss_request_context::TenantId::parse("00000000-0000-4000-8000-000000000197")?,
            rss_request_context::PrincipalKind::Admin,
            "inventory-test-admin",
            None,
        );
        let response = inventory_handler(
            httpserve::ContractMarker::for_test(),
            State(state),
            Extension(httpserve::VerifiedRequestId::for_test("unavailable")),
            Some(Extension(authorized)),
            Some(Extension(httpserve::RequestControl::for_test())),
        )
        .await;
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
            let tenant = rss_request_context::TenantId::parse(TENANT)
                .map_err(|_| diport::PdpError::InvalidSignature)?;
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
                    && request.principal_kind == rss_request_context::PrincipalKind::User
                    && request.principal_id == ALLOWED_SUBJECT
                    && request.tenant_id.is_some()
                {
                    httpserve::RouteAuthorizationDecision::authorizer_local()
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

    // PreExpansionPass sees cfg'd-out `env!` even when `integration` is off; allow journey fixture path.
    #[allow(unknown_lints, rss_runtime_env_funnel)] // reason: integration journey loads bundled assembly path via CARGO_MANIFEST_DIR
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
        .verify_repository_v2(&repository_manifest)?;
        let parsed = assembly_schema::ParsedRuntimePlan::from_json_slice_bound(
            include_bytes!("../runtime-plan.json"),
            &manifest,
            &lock,
        )?;
        let plan = parsed.as_plan();
        let workflow_runtime = eventexec::WorkflowActivationPlan::select(plan)?
            .bind(std::iter::empty(), std::iter::empty())?;
        let (probe_name, reporter) = journey_probe_chain(case)?;
        let bindings = plan
            .provider_plans()
            .iter()
            .map(|provider| {
                let probe_names = if provider.id() == "listener-pdp" {
                    vec![probe_name.clone()]
                } else {
                    Vec::new()
                };
                model::ProviderProbeBinding::from_probe_receipt(provider.id(), probe_names)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let placements = plan
            .placement_plans()
            .iter()
            .map(|placement| {
                model::PlacementObservation::local(placement.domain(), placement.workload())
            })
            .collect();
        let provider_receipt = model::ProviderExecutionReceipt::seal(
            runtimeinventorymint::RuntimeInventoryMint::capability(),
            plan.runtime_plan_fingerprint().as_str(),
            plan.provider_plans()
                .iter()
                .map(|provider| provider.id().to_owned()),
            bindings,
        )?;
        let seed = model::RuntimeInventorySeed::from_runtime_plan(
            plan,
            workflow_runtime.activated_workflows(),
            provider_receipt,
            placements,
        )?
        .with_build_metadata(model::BuildMetadata::parse(
            &"a".repeat(40),
            &format!("sha256:{}", "b".repeat(64)),
        )?);
        let (publisher, reader) = model::inventory_channel(seed, reporter);
        let host = runtimeexec::RuntimeHostView::ready_for_test(reader.clone());
        let mut registry = bootstrap::Registry::new();
        crate::modules_gen::register_framework_routes(
            &RuntimeInventoryRoutes::new(reader, host)?,
            &mut registry,
        )?;
        let mounted = registry
            .admit_writes(primitives::prepare_dr_admission_controls().into_parts().3)
            .finalize_routes()?;
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
