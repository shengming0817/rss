//! `identity.login` served HTTP contract tests.
//!
//! These tests exercise the real axum handler backed by [`LoginService`]. There
//! is intentionally no inline credential stub here: credential verification,
//! AuthGrant minting, and `expiresAt` semantics all come from the application
//! service.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::http::StatusCode;
use diport::Clock;
use generated::http::identity_v1::login::{IdentityLoginRequest, IdentityLoginResponse, SPEC};
use testkit::ContractRequest;

use crate::application::login_router_for_test;
use crate::{AuthGrantServices, LoginService, ports::DynAccountSecurityReadRepo};

const SEED_USER: &str = "alice";
const SEED_PASSWORD: &str = "correct-horse";
const CANON_TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const CANON_USER: &str = "11111111-2222-4333-8444-555555555555";
const NOW_SECS: u64 = 1_000;
const AUTH_GRANT_TTL_SECS: u64 = 3_600;

struct FixedClock(SystemTime);

impl Clock for FixedClock {
    fn now(&self) -> SystemTime {
        self.0
    }
}

fn clock() -> Box<dyn Clock> {
    Box::new(FixedClock(
        SystemTime::UNIX_EPOCH + Duration::from_secs(NOW_SECS),
    ))
}

fn user_id() -> ids::UserId {
    #[allow(clippy::expect_used)]
    ids::UserId::parse(CANON_USER).expect("canonical user id")
}

fn tenant_id() -> rss_request_context::TenantId {
    #[allow(clippy::expect_used)]
    rss_request_context::TenantId::parse(CANON_TENANT).expect("canonical tenant")
}

/// 最小 Signer 替身（固定字节签名；域 crate 单测不依赖 adapter）。
#[derive(Clone)]
struct ContractSigner;

impl diport::Signer for ContractSigner {
    async fn sign(
        &self,
        _req: diport::SignRequest,
    ) -> Result<diport::Signature, diport::SignerError> {
        Ok(diport::Signature::new(b"contract-test-sig-bytes".to_vec()))
    }

    async fn shutdown(&self) -> Result<(), diport::SignerError> {
        Ok(())
    }
}

fn make_auth_grant_services(
    store: crate::internal::mem::InMemAuthGrantStore,
    accounts: Box<DynAccountSecurityReadRepo<'static>>,
) -> AuthGrantServices<ContractSigner> {
    #[allow(clippy::expect_used)]
    let issuer = authn::JwtIssuer::<diport::RssAccessProfile, _>::new(
        Arc::new(ContractSigner),
        clock(),
        authn::JwtIssuerConfig::rss_access(
            authn::SigningKeyRing::single(diport::KeyId::new("contract-test-key"))
                .expect("non-empty signing key id"),
            "https://test.example",
            "test-audience",
            Duration::from_secs(900),
        ),
    )
    .expect("valid jwt issuer config");
    AuthGrantServices::from_provider(
        store,
        accounts,
        Arc::new(issuer),
        clock(),
        Duration::from_secs(2_592_000),
    )
}

fn login_router() -> axum::Router {
    let grant_store = crate::internal::mem::InMemAuthGrantStore::new();
    #[allow(clippy::expect_used)]
    let service = LoginService::with_seed_credential(
        move |accounts| make_auth_grant_services(grant_store, accounts),
        clock(),
        Duration::from_secs(AUTH_GRANT_TTL_SECS),
        SEED_USER,
        user_id(),
        SEED_PASSWORD,
        tenant_id(),
    )
    .expect("seed login service");
    login_router_for_test(Arc::new(service))
}

fn request(password: &str) -> ContractRequest {
    ContractRequest::post(SPEC.route.path())
        .header("X-Tenant-ID", CANON_TENANT)
        .json(&IdentityLoginRequest {
            username: SEED_USER.to_string(),
            password: password.to_string(),
        })
}

#[tokio::test]
async fn login_ok_returns_session_matching_generated_schema()
-> Result<(), Box<dyn std::error::Error>> {
    let resp = testkit::call(login_router(), request(SEED_PASSWORD)).await?;

    resp.ensure_status(StatusCode::CREATED)?;
    let decoded: IdentityLoginResponse = resp.json()?;
    assert!(!decoded.data.session_id.is_empty(), "返回会话 id");
    assert_eq!(
        decoded.data.expires_at,
        i64::try_from(NOW_SECS + AUTH_GRANT_TTL_SECS)?,
        "expiresAt 须是 UNIX epoch 秒，而非 TTL 秒 stub"
    );
    // #1252：login 响应包含首发 access JWT + refresh token bundle。
    assert!(
        !decoded.data.access_token.is_empty(),
        "access_token 非空（#1252）"
    );
    assert!(
        !decoded.data.refresh_token.is_empty(),
        "refresh_token 非空（#1252）"
    );
    assert!(
        decoded.data.access_expires_at > 0,
        "access_expires_at > 0（#1252）"
    );
    Ok(())
}

#[tokio::test]
async fn login_malformed_body_is_validation_error() -> Result<(), Box<dyn std::error::Error>> {
    let resp = testkit::call(
        login_router(),
        ContractRequest::post(SPEC.route.path())
            .header("X-Tenant-ID", CANON_TENANT)
            .raw_json("{ not json"),
    )
    .await?;
    resp.ensure_error(StatusCode::BAD_REQUEST, "ERR_CORE_VALIDATION")?;
    Ok(())
}

#[tokio::test]
async fn login_wrong_credentials_is_unauthenticated() -> Result<(), Box<dyn std::error::Error>> {
    let resp = testkit::call(login_router(), request("wrong")).await?;
    resp.ensure_error(StatusCode::UNAUTHORIZED, "ERR_CORE_UNAUTHENTICATED")?;
    Ok(())
}

#[tokio::test]
async fn login_missing_tenant_header_is_validation_error() -> Result<(), Box<dyn std::error::Error>>
{
    let resp = testkit::call(
        login_router(),
        ContractRequest::post(SPEC.route.path()).json(&IdentityLoginRequest {
            username: SEED_USER.to_string(),
            password: SEED_PASSWORD.to_string(),
        }),
    )
    .await?;
    resp.ensure_error(StatusCode::BAD_REQUEST, "ERR_CORE_VALIDATION")?;
    Ok(())
}

#[tokio::test]
async fn login_invalid_tenant_header_is_validation_error() -> Result<(), Box<dyn std::error::Error>>
{
    let resp = testkit::call(
        login_router(),
        ContractRequest::post(SPEC.route.path())
            .header("X-Tenant-ID", "not-a-tenant")
            .json(&IdentityLoginRequest {
                username: SEED_USER.to_string(),
                password: SEED_PASSWORD.to_string(),
            }),
    )
    .await?;
    resp.ensure_error(StatusCode::BAD_REQUEST, "ERR_CORE_VALIDATION")?;
    Ok(())
}

#[tokio::test]
async fn login_duplicate_tenant_headers_are_validation_errors()
-> Result<(), Box<dyn std::error::Error>> {
    for second in [CANON_TENANT, "11111111-1111-4111-8111-111111111111"] {
        let resp = testkit::call(
            login_router(),
            ContractRequest::post(SPEC.route.path())
                .header("X-Tenant-ID", CANON_TENANT)
                .header("X-Tenant-ID", second)
                .json(&IdentityLoginRequest {
                    username: SEED_USER.to_string(),
                    password: SEED_PASSWORD.to_string(),
                }),
        )
        .await?;
        resp.ensure_error(StatusCode::BAD_REQUEST, "ERR_CORE_VALIDATION")?;
    }
    Ok(())
}
