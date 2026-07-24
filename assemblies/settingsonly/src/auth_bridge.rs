//! Federated-only verification bridge for the settings assembly.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::middleware::{self, Next};
use axum::response::Response;
use httpserve::{Authenticated, AuthenticatedRoutes};

#[derive(Clone)]
pub(crate) struct FederatedVerifier {
    provider: VerifierProvider,
}

#[derive(Clone)]
enum VerifierProvider {
    Production(Arc<oidc::OidcProvider<diport::FederatedAccessProfile>>),
    #[cfg(feature = "test-support")]
    Test(Arc<diport::DynPdp<'static>>),
}

impl FederatedVerifier {
    pub(crate) fn production(
        provider: Arc<oidc::OidcProvider<diport::FederatedAccessProfile>>,
    ) -> Self {
        Self {
            provider: VerifierProvider::Production(provider),
        }
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn test(provider: Arc<diport::DynPdp<'static>>) -> Self {
        Self {
            provider: VerifierProvider::Test(provider),
        }
    }

    async fn verify(
        &self,
        token: &str,
    ) -> Result<(authn::VerifiedJwt, authn::Principal), authn::AuthnError> {
        match &self.provider {
            VerifierProvider::Production(provider) => {
                let pdp = diport::DynPdp::from_ref(provider.as_ref());
                authn::verify_federated_access(token, pdp).await
            }
            #[cfg(feature = "test-support")]
            VerifierProvider::Test(provider) => {
                authn::verify_federated_access(token, provider.as_ref()).await
            }
        }
    }
}

pub(crate) fn apply(
    routes: AuthenticatedRoutes,
    verifier: FederatedVerifier,
) -> AuthenticatedRoutes {
    routes.layer(middleware::from_fn_with_state(verifier, verify_request))
}

/// The single settingsonly evidence mint. The caller lint permits this exact path only.
fn federated_evidence(principal: &authn::Principal) -> Authenticated {
    Authenticated::new_federated(
        principal.kind(),
        principal.audit_subject(),
        principal.tenant(),
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
        Ok((verified, principal)) => {
            let principal = Arc::new(principal);
            let evidence = federated_evidence(principal.as_ref());
            if let Some(tenant) = principal.tenant() {
                let facet: Arc<dyn runctx::PrincipalFacet> = principal.clone();
                let ctx = runctx::RequestCtx::new(tenant, facet);
                request
                    .extensions_mut()
                    .insert(httpserve::PendingScopeCtx::new(ctx));
            }
            request.extensions_mut().insert(evidence);
            request.extensions_mut().insert(principal);
            request.extensions_mut().insert(Arc::new(verified));
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
