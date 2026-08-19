//! Assembly-local serving adapter for framework-owned runtime inventory.

use axum::extract::{Extension, State};
use generated::http::runtime_v1::inventory as wire;

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
    State(state): State<IdentityAuditFrameworkRoutes>,
    Extension(request_id): Extension<httpserve::VerifiedRequestId>,
) -> wire::RuntimeInventoryHandlerResult {
    inventory_http_response(&state.inventory, request_id)
}

fn inventory_http_response(
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
                model::ProviderProbeBinding::from_probe_receipt(
                    provider.role().as_str(),
                    probe_names,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let seed = plan.inventory_seed_fixture(bindings)?;
        let (publisher, reader) = model::inventory_channel(seed, Arc::clone(&reporter));
        let mut registry = bootstrap::Registry::new();
        crate::modules_gen::register_framework_routes(
            &IdentityAuditFrameworkRoutes::new(reader),
            &mut registry,
        )?;
        let mounted = registry
            .admit_writes(primitives::prepare_dr_admission_controls().into_parts().3)
            .finalize_routes()?;
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
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use super::*;
    use assembly_schema::{AssemblyListenerKind, ListenerAuth};
    use runtimeexec::inventory::{
        BoundListenerObservation, InventoryEndpointScheme, ProviderProbeBinding,
    };

    fn inventory_channel_fixture() -> anyhow::Result<(
        runtimeexec::inventory::InventoryPublisher,
        runtimeexec::inventory::InventoryReader,
        crate::plan::IdentityAuditPlan,
    )> {
        let plan = crate::plan::IdentityAuditPlan::bundled()?;
        let provider_bindings = crate::providers_gen::PROVIDER_CATALOG
            .iter()
            .map(|entry| {
                ProviderProbeBinding::from_probe_receipt(entry.role().as_str(), Vec::new())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let seed = plan.inventory_seed_fixture(provider_bindings)?;
        let reporter = Arc::new(bootstrap::Registry::new().take_health_reporter());
        let (publisher, reader) = runtimeexec::inventory::inventory_channel(seed, reporter);
        Ok((publisher, reader, plan))
    }

    fn is_unique_exact<T: Ord>(actual: &[T], expected: &[T]) -> bool {
        !expected.is_empty()
            && actual.iter().collect::<BTreeSet<_>>().len() == actual.len()
            && expected.iter().collect::<BTreeSet<_>>().len() == expected.len()
            && actual == expected
    }

    #[tokio::test]
    async fn unpublished_inventory_returns_retryable_provider_unavailable() -> anyhow::Result<()> {
        let (_publisher, reader, _plan) = inventory_channel_fixture()?;
        let response = inventory_http_response(
            &reader,
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

    #[test]
    fn framework_route_and_dto_mapping_are_exact() -> anyhow::Result<()> {
        let mut registry = bootstrap::compose(&[])?;
        let (publisher, reader, plan) = inventory_channel_fixture()?;
        crate::modules_gen::register_framework_routes(
            &IdentityAuditFrameworkRoutes::new(reader.clone()),
            &mut registry,
        )?;
        let mounted = registry
            .admit_writes(primitives::prepare_dr_admission_controls().into_parts().3)
            .finalize_routes()?;
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
        let response = wire::RuntimeInventoryResponse::try_from(reader.read()?)?;
        assert_eq!(
            response.data.schema_version,
            wire::RuntimeInventorySchemaVersion::V2
        );
        assert!(response.data.activated_workflows.is_empty());
        let expected_listener_ids = plan
            .as_typed()
            .listener_plans()
            .iter()
            .map(|listener| listener.id().to_owned())
            .collect::<Vec<_>>();
        let actual_listener_ids = response
            .data
            .listeners
            .iter()
            .map(|listener| listener.id.as_str().to_owned())
            .collect::<Vec<_>>();
        assert!(
            is_unique_exact(&actual_listener_ids, &expected_listener_ids),
            "listener projection drift: expected={expected_listener_ids:?} actual={actual_listener_ids:?}"
        );

        let expected_provider_ids = crate::providers_gen::PROVIDER_CATALOG
            .iter()
            .map(|entry| entry.role().as_str().to_owned())
            .collect::<Vec<_>>();
        let actual_provider_ids = response
            .data
            .provider_posture
            .iter()
            .map(|provider| provider.id.as_str().to_owned())
            .collect::<Vec<_>>();
        assert!(
            is_unique_exact(&actual_provider_ids, &expected_provider_ids),
            "provider projection drift: expected={expected_provider_ids:?} actual={actual_provider_ids:?}"
        );

        let expected_placements = plan
            .as_typed()
            .placement_plans()
            .iter()
            .map(|placement| {
                (
                    placement.domain().to_string(),
                    placement.workload().to_owned(),
                )
            })
            .collect::<Vec<_>>();
        let actual_placements = response
            .data
            .placements
            .iter()
            .map(|placement| {
                (
                    placement.domain.to_string(),
                    placement.workload.as_str().to_owned(),
                )
            })
            .collect::<Vec<_>>();
        assert!(
            is_unique_exact(&actual_placements, &expected_placements),
            "placement projection drift: expected={expected_placements:?} actual={actual_placements:?}"
        );
        let encoded = serde_json::to_value(response)?;
        assert_eq!(encoded["data"]["activatedWorkflows"], serde_json::json!([]));
        Ok(())
    }

    #[test]
    fn dto_identity_comparator_rejects_replacement_and_duplicate_ids() {
        let expected = vec!["admin-main", "health-main", "primary-main"];
        assert!(is_unique_exact(&expected, &expected));
        assert!(!is_unique_exact(
            &["admin-main", "health-main", "replacement"],
            &expected
        ));
        assert!(!is_unique_exact(
            &["admin-main", "admin-main", "primary-main"],
            &expected
        ));
        assert!(!is_unique_exact(&["admin-main", "primary-main"], &expected));
        assert!(!is_unique_exact(
            &["admin-main", "extra", "health-main", "primary-main"],
            &expected
        ));
    }
}
