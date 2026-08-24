//! Federated-only verification bridge for the deviceidentity candidate.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::middleware::{self, Next};
use axum::response::Response;
use httpserve::{Authenticated, AuthenticatedRoutes};

#[derive(Clone)]
pub(crate) struct FederatedVerifier(VerifierProvider);

#[derive(Clone)]
enum VerifierProvider {
    Production(Arc<oidc::OidcProvider<diport::FederatedAccessProfile>>),
    #[cfg(any(test, feature = "test-support"))]
    Test(Arc<diport::DynPdp<'static>>),
}

impl FederatedVerifier {
    pub(crate) fn production(
        provider: Arc<oidc::OidcProvider<diport::FederatedAccessProfile>>,
    ) -> Self {
        Self(VerifierProvider::Production(provider))
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn test(provider: Arc<diport::DynPdp<'static>>) -> Self {
        Self(VerifierProvider::Test(provider))
    }

    async fn verify(
        &self,
        token: &str,
    ) -> Result<authn::VerifiedFederatedAccess, authn::AuthnError> {
        match &self.0 {
            VerifierProvider::Production(provider) => {
                let pdp = diport::DynPdp::from_ref(provider.as_ref());
                authn::verify_federated_access(token, pdp).await
            }
            #[cfg(any(test, feature = "test-support"))]
            VerifierProvider::Test(provider) => {
                authn::verify_federated_access(token, provider.as_ref()).await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{Request, StatusCode, header};
    use tower::ServiceExt as _;

    #[derive(Clone, Copy)]
    enum Failure {
        Invalid,
        Unavailable,
    }

    struct FailingPdp(Failure);

    struct DenyAuthorizer;

    impl httpserve::RouteAuthorizer for DenyAuthorizer {
        fn authorize<'a>(
            &'a self,
            _request: httpserve::RouteAuthorizationRequest,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = httpserve::RouteAuthorizationDecision> + Send + 'a,
            >,
        > {
            Box::pin(async { httpserve::RouteAuthorizationDecision::Deny })
        }
    }

    impl diport::Pdp for FailingPdp {
        async fn verify(
            &self,
            _raw: &diport::RawCredential,
        ) -> Result<diport::VerifiedClaims, diport::PdpError> {
            Err(match self.0 {
                Failure::Invalid => diport::PdpError::InvalidSignature,
                Failure::Unavailable => diport::PdpError::ProviderUnavailable,
            })
        }
    }

    #[tokio::test]
    async fn candidate_auth_preserves_invalid_and_provider_unavailable_taxonomy() {
        for (failure, expected) in [
            (Failure::Invalid, "token is invalid"),
            (
                Failure::Unavailable,
                "authentication provider is unavailable",
            ),
        ] {
            let verifier = FederatedVerifier::test(diport::DynPdp::new_arc(FailingPdp(failure)));
            let error = verifier
                .verify("e30.e30.c2ln")
                .await
                .expect_err("fixture PDP rejects");
            assert_eq!(error.to_string(), expected);
        }
    }

    #[tokio::test]
    async fn candidate_router_exercises_federated_auth_failure_surface() -> anyhow::Result<()> {
        for (failure, expected) in [
            (Failure::Invalid, StatusCode::NOT_FOUND),
            (Failure::Unavailable, StatusCode::SERVICE_UNAVAILABLE),
        ] {
            let routes = httpserve::routes::unfinalized_for_test::<httpserve::Primary>(|router| {
                router.mount_primary_raw_for_test(
                    httpserve::TestPrimaryRoute::permission(
                        axum::http::Method::GET,
                        "/devices/{deviceId}",
                        "test.deviceidentity-auth",
                        httpserve::TestRoutePermission {
                            permission:
                                vocab::RoutePermissionId::IdentityDeviceCertificatePolicyWrite,
                            scope: httpserve::TestRouteResourceScope::PathParam("deviceId"),
                        },
                    ),
                    axum::routing::get(|| async { "ok" }),
                )
            })?;
            let routes = httpserve::finalize_primary_auth(
                routes,
                primitives::AuthPlan::new(
                    primitives::ListenerKind::Primary,
                    primitives::AuthScheme::FederatedAccessToken,
                )?,
                Arc::new(DenyAuthorizer),
            )?;
            let router = apply(
                routes,
                FederatedVerifier::test(diport::DynPdp::new_arc(FailingPdp(failure))),
            )
            .into_plaintext_router_for_test();
            let response = router
                .oneshot(
                    Request::builder()
                        .uri("/missing")
                        .header(header::AUTHORIZATION, "Bearer e30.e30.c2ln")
                        .body(axum::body::Body::empty())?,
                )
                .await?;
            assert_eq!(response.status(), expected);
        }
        Ok(())
    }
}

pub(crate) fn apply(
    routes: AuthenticatedRoutes,
    verifier: FederatedVerifier,
) -> AuthenticatedRoutes {
    routes.layer(middleware::from_fn_with_state(verifier, verify_request))
}

fn federated_evidence(access: &authn::VerifiedFederatedAccess) -> Authenticated {
    let principal = access.principal();
    Authenticated::new_federated(
        authmint::AuthenticatedMint::capability(),
        principal.kind(),
        principal.audit_subject(),
        principal.tenant(),
        access.permissions(),
    )
}

async fn verify_request(
    State(verifier): State<FederatedVerifier>,
    mut request: Request,
    next: Next,
) -> Response {
    let credential = match httpserve::extract_bearer_credential(
        request.headers(),
        diport::TokenProfile::FederatedAccess,
    ) {
        Ok(Some(credential)) => credential,
        Ok(None) => return next.run(request).await,
        Err(_) => {
            return httpserve::error::unauthenticated(
                httpserve::request_id_str(request.extensions()).unwrap_or_default(),
            );
        }
    };
    let (_, token, service_tenant) = credential.into_parts();
    if service_tenant.is_some() {
        return httpserve::error::unauthenticated(
            httpserve::request_id_str(request.extensions()).unwrap_or_default(),
        );
    }
    match verifier.verify(&token).await {
        Ok(access) => {
            let access = Arc::new(access);
            let principal = access.principal_arc();
            let evidence = federated_evidence(access.as_ref());
            if let Some(tenant) = principal.tenant() {
                let facet: Arc<dyn runctx::PrincipalFacet> = principal.clone();
                request
                    .extensions_mut()
                    .insert(httpserve::PendingScopeCtx::new(runctx::RequestCtx::new(
                        tenant, facet,
                    )));
            }
            request.extensions_mut().insert(evidence);
            request.extensions_mut().insert(principal);
        }
        Err(authn::AuthnError::ProviderUnavailable) => {
            return httpserve::error::provider_unavailable(
                httpserve::request_id_str(request.extensions()).unwrap_or_default(),
            );
        }
        Err(_) => {}
    }
    next.run(request).await
}
