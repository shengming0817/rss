//! `identity.login` served HTTP contract tests.
//!
//! These tests exercise the real axum handler backed by [`LoginService`]. There
//! is intentionally no inline credential stub here: credential verification,
//! session minting, and `expiresAt` semantics all come from the application
//! service.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::http::StatusCode;
use diport::Clock;
use generated::http::identity_v1::{IdentityLoginRequest, IdentityLoginResponse, SPEC};
use testkit::ContractRequest;

use crate::application::login_router_for_test;
use crate::{LoginService, ports::DynSessionLifecycle};

const SEED_USER: &str = "alice";
const SEED_PASSWORD: &str = "correct-horse";
const CANON_TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const CANON_USER: &str = "11111111-2222-4333-8444-555555555555";
const NOW_SECS: u64 = 1_000;
const SESSION_TTL_SECS: u64 = 3_600;

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

fn tenant_id() -> vocab::TenantId {
    #[allow(clippy::expect_used)]
    vocab::TenantId::parse(CANON_TENANT).expect("canonical tenant")
}

fn login_router() -> axum::Router {
    #[allow(clippy::expect_used)]
    let service = LoginService::with_seed_credential(
        Arc::from(DynSessionLifecycle::new_box(
            crate::internal::mem::InMemSessionLifecycle::default(),
        )),
        clock(),
        Duration::from_secs(SESSION_TTL_SECS),
        SEED_USER,
        user_id(),
        SEED_PASSWORD,
        tenant_id(),
    )
    .expect("seed login service");
    login_router_for_test(Arc::new(service))
}

fn request(password: &str) -> ContractRequest {
    ContractRequest::post(SPEC.path)
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
        i64::try_from(NOW_SECS + SESSION_TTL_SECS)?,
        "expiresAt 须是 UNIX epoch 秒，而非 TTL 秒 stub"
    );
    Ok(())
}

#[tokio::test]
async fn login_malformed_body_is_validation_error() -> Result<(), Box<dyn std::error::Error>> {
    let resp = testkit::call(
        login_router(),
        ContractRequest::post(SPEC.path)
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
        ContractRequest::post(SPEC.path).json(&IdentityLoginRequest {
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
        ContractRequest::post(SPEC.path)
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
