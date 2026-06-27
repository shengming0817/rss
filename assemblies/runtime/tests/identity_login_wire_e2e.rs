//! identity.login production wire e2e: PgRuntimeDeps credential/session providers → wire_identity →
//! bootstrap compose/finalize → Primary router handler.

#![cfg(feature = "integration")]

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use generated::http::identity_v1::SPEC as LOGIN_SPEC;
use identity::ports::{Credential, CredentialRepo as _, TenantId};
use postgres::{PgConfig, PgError, PgPassword, PgRuntimeDeps, PgSslMode, caps};
use primitives::ListenerKind;
use runtime::{SharedRuntimeDeps, SystemClock, TracingAuthAuditSink, wire_identity};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode as SqlxPgSslMode};
use tower::ServiceExt as _;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

const CANON_TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const CANON_USER: &str = "11111111-2222-4333-8444-555555555555";
const LOGIN_USERNAME: &str = "alice";
const PASSWORD: &str = "correct-horse";
const TEST_APP_ROLE: &str = "rss_identity_login_e2e_app";
const TEST_APP_PASSWORD: &str = "identity_login_e2e_pw";

async fn connect_pg()
-> Result<(testkit::PgFixture, PgRuntimeDeps), Box<dyn std::error::Error + Send + Sync>> {
    let fixture = testkit::env_or_postgres().await?;
    let p = fixture.params();
    let owner_config = pg_config(p, &p.username, &p.password);
    match PgRuntimeDeps::setup(&owner_config).await {
        Ok(deps) => return Ok((fixture, deps)),
        Err(PgError::RlsBypassRole) => {
            provision_nobypass_app_role(p).await?;
        }
        Err(e) => return Err(Box::new(e)),
    }
    let deps = PgRuntimeDeps::setup(&pg_config(p, TEST_APP_ROLE, TEST_APP_PASSWORD)).await?;
    Ok((fixture, deps))
}

fn pg_config(p: &testkit::PgConnParams, username: &str, password: &str) -> PgConfig {
    PgConfig::new(
        p.host.clone(),
        p.port,
        p.database.clone(),
        username.to_string(),
        PgPassword::new(password.to_string()),
    )
    .with_ssl_mode(PgSslMode::Prefer)
    .with_acquire_timeout(Duration::from_secs(5))
}

async fn provision_nobypass_app_role(
    p: &testkit::PgConnParams,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let options = PgConnectOptions::new()
        .host(&p.host)
        .port(p.port)
        .database(&p.database)
        .username(&p.username)
        .password(&p.password)
        .ssl_mode(SqlxPgSslMode::Prefer);
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(options)
        .await?;
    sqlx::query(
        r#"
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'rss_identity_login_e2e_app') THEN
                CREATE ROLE rss_identity_login_e2e_app LOGIN PASSWORD 'identity_login_e2e_pw' NOBYPASSRLS;
            ELSE
                ALTER ROLE rss_identity_login_e2e_app LOGIN PASSWORD 'identity_login_e2e_pw' NOBYPASSRLS;
            END IF;
        END
        $$;
        "#,
    )
    .execute(&pool)
    .await?;
    sqlx::query(&format!(
        "GRANT USAGE, CREATE ON SCHEMA public TO {TEST_APP_ROLE}"
    ))
    .execute(&pool)
    .await?;
    sqlx::query(&format!(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {TEST_APP_ROLE}"
    ))
    .execute(&pool)
    .await?;
    sqlx::query(&format!(
        "GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO {TEST_APP_ROLE}"
    ))
    .execute(&pool)
    .await?;
    pool.close().await;
    Ok(())
}

fn test_provider() -> oidc::OidcProvider {
    #[allow(clippy::expect_used)]
    runtime::provider_from_b64(
        "https://issuer.test",
        "rss",
        "user",
        None,
        Some(&B64.encode([7u8; 32])),
        Box::new(SystemClock),
    )
    .expect("test provider")
}

#[tokio::test(flavor = "multi_thread")]
async fn wire_identity_primary_router_serves_public_login() -> TestResult {
    let (_fixture, pg) = connect_pg().await?;
    let tenant = TenantId::parse(CANON_TENANT)?;
    let credential = Credential::hydrate(
        LOGIN_USERNAME,
        ids::UserId::parse(CANON_USER)?,
        tenant,
        secure::hash_password(PASSWORD)?,
        1,
    );
    pg.for_domain::<caps::Identity>()
        .credential_repo()
        .save(credential)
        .await?;

    // #1498：SharedRuntimeDeps 现含 vault bundle。identity wiring 不消费 vault；构造 stub bundle（合法
    // addr/token，无真实连接——resolver 仅构造期校验 URL/token）满足结构，wire_identity 不触碰它。
    let vault = runtime::build_vault_runtime_deps(|name| match name {
        "RSS_VAULT_ADDR" => Some("https://vault.example:8200".to_string()),
        "RSS_VAULT_TOKEN" => Some("test-token".to_string()),
        _ => None,
    })?;
    let redis_fixture = testkit::env_or_redis().await?;
    let redis = runtime::build_redis_runtime_deps(|name| {
        (name == "RSS_REDIS_URL").then(|| redis_fixture.url().to_string())
    })
    .await?;
    let deps = SharedRuntimeDeps {
        pg,
        redis: Some(redis),
        vault,
    };
    let identity_domain = wire_identity(&deps)?;
    let mut registry = bootstrap::compose(&[&identity_domain])?;
    let mut primary = None;
    for (listener, routes) in runtime::assemble_authed_routers(
        &mut registry,
        Arc::new(test_provider()),
        httpserve::AuditSinkHandle::new(TracingAuthAuditSink),
        Arc::new(SystemClock),
    )? {
        if listener == ListenerKind::Primary {
            primary = Some(routes.into_router_for_test());
        }
    }
    let app = primary.ok_or("identity domain did not produce Primary router")?;
    let body = format!(r#"{{"username":"{LOGIN_USERNAME}","password":"{PASSWORD}"}}"#);
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(LOGIN_SPEC.path)
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-Tenant-ID", CANON_TENANT)
                .body(Body::from(body))?,
        )
        .await?;

    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "public identity.login should pass finalize_auth without bearer token"
    );
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
    let text = String::from_utf8(bytes.to_vec())?;
    assert!(text.contains(r#""sessionId":"#), "response body: {text}");
    assert!(text.contains(r#""expiresAt":"#), "response body: {text}");
    Ok(())
}
