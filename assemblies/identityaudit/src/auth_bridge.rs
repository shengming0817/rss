//! RSS-access verification bridge for the two authenticated identityaudit listeners.

use std::sync::Arc;
use std::{future::Future, pin::Pin};

use axum::extract::{Request, State};
use axum::middleware::{self, Next};
use axum::response::Response;
use httpserve::{Authenticated, AuthenticatedRoutes};

#[derive(Clone)]
pub(crate) struct RssAccessVerifier {
    provider: VerifierProvider,
    validate_grant: Arc<GrantValidator>,
}

#[derive(Clone)]
enum VerifierProvider {
    Production(Arc<oidc::OidcProvider<diport::RssAccessProfile>>),
    #[cfg(feature = "test-support")]
    Test(Arc<diport::DynPdp<'static>>),
}

type GrantFuture = Pin<
    Box<
        dyn Future<
                Output = Result<identity::ValidatedAuthGrant, identity::AccessGrantValidationError>,
            > + Send,
    >,
>;
type GrantValidator =
    dyn Fn(authn::AccessGrantValidationInput) -> GrantFuture + Send + Sync + 'static;

impl RssAccessVerifier {
    pub(crate) fn new(
        provider: Arc<oidc::OidcProvider<diport::RssAccessProfile>>,
        grants: Arc<identity::AuthGrantValidationService>,
    ) -> Self {
        Self {
            provider: VerifierProvider::Production(provider),
            validate_grant: Arc::new(move |input| {
                let grants = Arc::clone(&grants);
                Box::pin(async move { grants.validate(input).await })
            }),
        }
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn test(
        provider: Arc<diport::DynPdp<'static>>,
        grants: Arc<identity::AuthGrantValidationService>,
    ) -> Self {
        Self {
            provider: VerifierProvider::Test(provider),
            validate_grant: Arc::new(move |input| {
                let grants = Arc::clone(&grants);
                Box::pin(async move { grants.validate(input).await })
            }),
        }
    }

    #[cfg(test)]
    fn for_test(
        provider: Arc<oidc::OidcProvider<diport::RssAccessProfile>>,
        validate_grant: Arc<GrantValidator>,
    ) -> Self {
        Self {
            provider: VerifierProvider::Production(provider),
            validate_grant,
        }
    }
}

pub(crate) fn apply(
    routes: AuthenticatedRoutes,
    verifier: RssAccessVerifier,
) -> AuthenticatedRoutes {
    routes.layer(middleware::from_fn_with_state(verifier, verify))
}

enum VerifyOutcome {
    Allowed {
        evidence: Authenticated,
        current_auth_grant: identity::CurrentAuthGrant,
        principal: Arc<authn::Principal>,
        jwt: Arc<authn::VerifiedJwt>,
        ctx: runctx::AppCtx,
    },
    Rejected,
    ProviderUnavailable,
}

async fn authenticate(
    verifier: &RssAccessVerifier,
    credential: httpserve::ExtractedBearerCredential,
) -> VerifyOutcome {
    let (profile, token, tenant_binding) = credential.into_parts();
    if profile != diport::TokenProfile::RssAccess || tenant_binding.is_some() {
        return VerifyOutcome::Rejected;
    }
    let verified = match &verifier.provider {
        VerifierProvider::Production(provider) => {
            let pdp = diport::DynPdp::from_ref(provider.as_ref());
            authn::verify_rss_access(&token, pdp).await
        }
        #[cfg(feature = "test-support")]
        VerifierProvider::Test(provider) => {
            authn::verify_rss_access(&token, provider.as_ref()).await
        }
    };
    let (jwt, principal) = match verified {
        Ok(verified) => verified,
        Err(authn::AuthnError::ProviderUnavailable) => return VerifyOutcome::ProviderUnavailable,
        Err(_) => return VerifyOutcome::Rejected,
    };
    let Some(receipt) = jwt.grant_receipt() else {
        return VerifyOutcome::Rejected;
    };
    let validated_grant = match (verifier.validate_grant)(receipt.into_validation_input()).await {
        Ok(proof) => proof,
        Err(identity::AccessGrantValidationError::Invalid) => return VerifyOutcome::Rejected,
        Err(identity::AccessGrantValidationError::Provider(_)) => {
            return VerifyOutcome::ProviderUnavailable;
        }
    };
    let Some(tenant) = principal.tenant() else {
        return VerifyOutcome::Rejected;
    };
    if principal.kind() != rss_request_context::PrincipalKind::User {
        return VerifyOutcome::Rejected;
    }
    let principal = Arc::new(principal);
    let facet: Arc<dyn runctx::PrincipalFacet> = principal.clone();
    let ctx = runctx::RequestCtx::new(tenant, facet);
    let Some((evidence, current_auth_grant)) =
        allow_evidence(validated_grant, principal.as_ref(), tenant)
    else {
        return VerifyOutcome::Rejected;
    };
    VerifyOutcome::Allowed {
        evidence,
        current_auth_grant,
        principal,
        jwt: Arc::new(jwt),
        ctx,
    }
}

fn allow_evidence(
    validated_grant: identity::ValidatedAuthGrant,
    principal: &authn::Principal,
    tenant: rss_request_context::TenantId,
) -> Option<(Authenticated, identity::CurrentAuthGrant)> {
    let current = validated_grant.into_current_auth_grant();
    if !current.binds_principal(tenant, principal.audit_subject()) {
        return None;
    }
    Some((
        Authenticated::new_rss_user(
            authmint::AuthenticatedMint::capability(),
            principal.audit_subject(),
            tenant,
        ),
        current,
    ))
}

async fn verify(
    State(verifier): State<RssAccessVerifier>,
    mut request: Request,
    next: Next,
) -> Response {
    match httpserve::extract_bearer_credential(request.headers(), diport::TokenProfile::RssAccess) {
        Ok(Some(credential)) => match authenticate(&verifier, credential).await {
            VerifyOutcome::Allowed {
                evidence,
                current_auth_grant,
                principal,
                jwt,
                ctx,
            } => {
                request.extensions_mut().insert(evidence);
                request.extensions_mut().insert(current_auth_grant);
                request.extensions_mut().insert(principal);
                request.extensions_mut().insert(jwt);
                request
                    .extensions_mut()
                    .insert(httpserve::PendingScopeCtx::new(ctx));
            }
            VerifyOutcome::Rejected => {}
            VerifyOutcome::ProviderUnavailable => {
                return httpserve::error::provider_unavailable(
                    httpserve::request_id_str(request.extensions()).unwrap_or_default(),
                );
            }
        },
        Ok(None) => {}
        Err(_) => {
            return httpserve::error::unauthenticated(
                httpserve::request_id_str(request.extensions()).unwrap_or_default(),
            );
        }
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use axum::http::{HeaderMap, HeaderValue, Request, StatusCode, header};
    use tower::ServiceExt as _;

    async fn verifier() -> anyhow::Result<(RssAccessVerifier, Arc<std::sync::atomic::AtomicUsize>)>
    {
        let root = std::env::temp_dir().join(format!(
            "rss-identityaudit-auth-coverage-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root)?;
        let jwks = root.join("rss-access.jwks.json");
        std::fs::write(
            &jwks,
            r#"{"keys":[{"kty":"EC","crv":"P-256","kid":"identity-access-es256","alg":"ES256","x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY","y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"}]}"#,
        )?;
        let document = include_str!("../identityaudit.example.toml").replace(
            "/run/rss/oidc.jwks.json",
            jwks.to_str()
                .ok_or_else(|| anyhow::anyhow!("JWKS path is not UTF-8"))?,
        );
        let config = crate::config::parse_for_test(&document)?;
        let (_, _, oidc, _, _, _, _) = config.into_sections();
        let provider = crate::providers::rss_access_provider_for_test(oidc)?;
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let validate: Arc<GrantValidator> = Arc::new(move |_input| {
            observed.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            Box::pin(async { Err(identity::AccessGrantValidationError::Invalid) })
        });
        Ok((RssAccessVerifier::for_test(provider, validate), calls))
    }

    fn credential(
        profile: diport::TokenProfile,
        token: &str,
    ) -> anyhow::Result<httpserve::ExtractedBearerCredential> {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}"))?,
        );
        if profile == diport::TokenProfile::ServiceToken {
            headers.insert(
                diport::SERVICE_TOKEN_TENANT_HEADER,
                HeaderValue::from_static("00000000-0000-4000-8000-000000001797"),
            );
        }
        httpserve::extract_bearer_credential(&headers, profile)?
            .ok_or_else(|| anyhow::anyhow!("credential unexpectedly absent"))
    }

    #[tokio::test]
    async fn authentication_rejects_wrong_profile_and_invalid_rss_token_before_grant_io()
    -> anyhow::Result<()> {
        let (verifier, grant_calls) = verifier().await?;
        assert!(matches!(
            authenticate(
                &verifier,
                credential(diport::TokenProfile::ServiceToken, "opaque-service-token")?,
            )
            .await,
            VerifyOutcome::Rejected
        ));
        assert!(matches!(
            authenticate(
                &verifier,
                credential(diport::TokenProfile::RssAccess, "not-a-jwt")?,
            )
            .await,
            VerifyOutcome::Rejected
        ));
        assert_eq!(
            grant_calls.load(std::sync::atomic::Ordering::Acquire),
            0,
            "unverified credentials must never reach durable grant validation"
        );
        Ok(())
    }

    #[tokio::test]
    async fn middleware_rejects_malformed_headers_and_passes_absent_or_invalid_credentials()
    -> anyhow::Result<()> {
        let (verifier, grant_calls) = verifier().await?;
        let routes = httpserve::finalize_auth(
            httpserve::UnfinalizedRoutes::empty(),
            primitives::AuthPlan::new(
                primitives::ListenerKind::Admin,
                primitives::AuthScheme::RssAccessToken,
            )?,
        )?;
        let router = apply(routes, verifier).into_plaintext_router_for_test();

        let missing = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/missing")
                    .body(axum::body::Body::empty())?,
            )
            .await?;
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);

        let malformed = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/missing")
                    .header(header::AUTHORIZATION, "Basic credentials")
                    .body(axum::body::Body::empty())?,
            )
            .await?;
        assert_eq!(malformed.status(), StatusCode::UNAUTHORIZED);

        let invalid = router
            .oneshot(
                Request::builder()
                    .uri("/missing")
                    .header(header::AUTHORIZATION, "Bearer not-a-jwt")
                    .body(axum::body::Body::empty())?,
            )
            .await?;
        assert_eq!(invalid.status(), StatusCode::NOT_FOUND);
        assert_eq!(grant_calls.load(std::sync::atomic::Ordering::Acquire), 0);
        Ok(())
    }
}
