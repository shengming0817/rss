//! Cluster-global service-token replay E2E.
//!
//! Three independent runtime verifier/router instances share only PostgreSQL. The same token must
//! be accepted once globally, remain rejected after every runtime pool is rebuilt, and fail closed
//! with HTTP 503 when the verifier's PostgreSQL pool is unavailable.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Method, Request, Response, StatusCode, header};
use axum::routing::get;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use diport::ManagedResource as _;
use hmac::{Hmac, Mac as _};
use postgres::{PgConfig, PgPassword, PgRuntimeDeps, PgSslMode, PgTenantReadConfig};
use sha2::Sha256;
use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode as SqlxPgSslMode};
use tower::ServiceExt as _;
use uuid::Uuid;

type TestResult<T = ()> = anyhow::Result<T>;

const ISSUER: &str = "https://service-token.issuer.test";
const AUDIENCE: &str = "rss-service-token-e2e";
const KEY_ID: &str = "cell-a.runtime";
const SUBJECT: &str = "rss-maintenance-operator";
const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const SECRET: &[u8; 32] = b"cluster-global-replay-test-key!!";
const TEST_APP_ROLE: &str = "rss_app";
const TEST_APP_PASSWORD: &str = "rss_app_replay_test_pw";
const TEST_READ_ROLE: &str = "rss_app_read";
const TEST_READ_PASSWORD: &str = "rss_app_read_replay_test_pw";

struct FixedClock(SystemTime);

impl diport::Clock for FixedClock {
    fn now(&self) -> SystemTime {
        self.0
    }
}

struct ReplayRoundIds {
    concurrent: String,
    outage: String,
}

impl ReplayRoundIds {
    fn unique() -> Self {
        let prefix = format!("runtime-cluster-global-{}", Uuid::new_v4().simple());
        Self {
            concurrent: format!("{prefix}-concurrent"),
            outage: format!("{prefix}-pg-outage"),
        }
    }

    fn all(&self) -> [&str; 2] {
        [&self.concurrent, &self.outage]
    }
}

fn pg_config(p: &testkit::PgConnParams, username: &str, password: &str) -> PgConfig {
    PgConfig::new(
        p.host.clone(),
        p.port,
        p.database.clone(),
        username.to_owned(),
        PgPassword::new(password.to_owned()),
    )
    .with_ssl_mode(PgSslMode::Prefer)
    .with_acquire_timeout(Duration::from_secs(5))
}

async fn admin_pool(p: &testkit::PgConnParams) -> TestResult<PgPool> {
    let options = PgConnectOptions::new()
        .host(&p.host)
        .port(p.port)
        .database(&p.database)
        .username(&p.username)
        .password(&p.password)
        .ssl_mode(SqlxPgSslMode::Prefer);
    Ok(PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(options)
        .await?)
}

async fn database_now(pool: &PgPool) -> TestResult<(i64, SystemTime)> {
    let unix_seconds: i64 =
        sqlx::query_scalar("SELECT floor(EXTRACT(EPOCH FROM clock_timestamp()))::bigint")
            .fetch_one(pool)
            .await?;
    let unix_seconds_u64 = u64::try_from(unix_seconds)
        .map_err(|_| anyhow::anyhow!("database clock predates epoch"))?;
    let system_time = UNIX_EPOCH
        .checked_add(Duration::from_secs(unix_seconds_u64))
        .ok_or_else(|| anyhow::anyhow!("database clock is outside SystemTime range"))?;
    Ok((unix_seconds, system_time))
}

async fn cleanup_replay_keys(pool: &PgPool, ids: &ReplayRoundIds) -> TestResult {
    let mut transaction = pool.begin().await?;
    for token_id in ids.all() {
        let key = diport::ServiceTokenReplayKey::derive(diport::ServiceTokenReplayScope {
            issuer: ISSUER,
            audience: AUDIENCE,
            key_id: KEY_ID,
            token_id,
        })?;
        sqlx::query(
            "DELETE FROM public.service_token_replay_keys \
             WHERE key_digest = $1",
        )
        .bind(key.digest_bytes().as_slice())
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    Ok(())
}

async fn setup_runtime_pg(
    owner: &testkit::PgConnParams,
    app: &testkit::PgConnParams,
    reader: &testkit::PgConnParams,
) -> TestResult<PgRuntimeDeps> {
    let read = PgTenantReadConfig::new(pg_config(reader, &reader.username, &reader.password));
    let workflow = eventexec::WorkflowRuntimePlan::disabled_fixture();
    Ok(PgRuntimeDeps::setup_owned_test_fixture(
        &pg_config(owner, &owner.username, &owner.password),
        &pg_config(app, &app.username, &app.password),
        &read,
        None,
        workflow.projection_capture(),
    )
    .await?)
}

async fn shutdown_runtime_pg(owner: PgRuntimeDeps) -> TestResult {
    let monitor_config = postgres::PgRuntimeMonitorConfig::new(
        postgres::PgReadinessInterval::try_new(Duration::from_secs(1)).expect("interval"),
        postgres::PgRlsAttestationInterval::default(),
    );
    let (resources, sampler_factory) = owner.into_runtime_parts(monitor_config);
    drop(sampler_factory);
    for resource in resources.into_iter().rev() {
        resource.shutdown().await?;
    }
    Ok(())
}

fn provider(
    owner: &PgRuntimeDeps,
    now: SystemTime,
) -> TestResult<Arc<oidc::OidcProvider<diport::ServiceTokenProfile>>> {
    runtime::test_support::build_service_token_provider_from_values(
        ISSUER,
        AUDIENCE,
        KEY_ID,
        SECRET,
        owner,
        Duration::from_secs(5),
        Box::new(FixedClock(now)),
    )
}

fn router(
    provider: Arc<oidc::OidcProvider<diport::ServiceTokenProfile>>,
    handler_calls: Arc<AtomicUsize>,
) -> TestResult<httpserve::AuthenticatedRoutes> {
    let routes = httpserve::routes::unfinalized_for_test(|router| {
        router.mount_internal_raw_for_test(
            httpserve::TestRoute {
                method: Method::GET,
                path: "/service-token-replay",
                contract_id: "test.service-token-replay",
            },
            httpserve::ServiceCallerPolicy::exact(
                "test.service-token-replay",
                vocab::ServiceCallerDomain::MaintenanceOperator,
            ),
            get(move || {
                let handler_calls = Arc::clone(&handler_calls);
                async move {
                    handler_calls.fetch_add(1, Ordering::AcqRel);
                    "ok"
                }
            }),
        )
    })?;
    let plan = primitives::AuthPlan::new(
        primitives::ListenerKind::Internal,
        primitives::AuthScheme::ServiceToken,
    )?;
    let routes = httpserve::finalize_auth(routes, plan)?;
    Ok(runtime::auth_bridge::apply_service_token_verify_bridge_for_test(routes, provider))
}

fn service_token(token_id: &str, now: i64) -> TestResult<String> {
    let header = B64.encode(format!(
        r#"{{"alg":"HS256","typ":"rss-service+jwt","kid":"{KEY_ID}"}}"#
    ));
    let claims = serde_json::json!({
        "sub": SUBJECT,
        "iat": now,
        "exp": now + 300,
        "iss": ISSUER,
        "aud": AUDIENCE,
        "token_use": "service",
        "kind": "service",
        "tenant_id": TENANT,
        "jti": token_id,
    });
    let body = B64.encode(serde_json::to_vec(&claims)?);
    let signing_input = format!("{header}.{body}");
    let mut mac = Hmac::<Sha256>::new_from_slice(SECRET)?;
    mac.update(signing_input.as_bytes());
    Ok(format!(
        "{signing_input}.{}",
        B64.encode(mac.finalize().into_bytes())
    ))
}

async fn submit(routes: httpserve::AuthenticatedRoutes, token: &str) -> TestResult<Response<Body>> {
    Ok(routes
        .into_plaintext_router_for_test()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/service-token-replay")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header("X-Tenant-ID", TENANT)
                .body(Body::empty())?,
        )
        .await?)
}

async fn run_replay_round(
    owner: &testkit::PgConnParams,
    app: &testkit::PgConnParams,
    reader: &testkit::PgConnParams,
    now_seconds: i64,
    now: SystemTime,
    ids: &ReplayRoundIds,
) -> TestResult {
    let owner_a = setup_runtime_pg(owner, app, reader).await?;
    let owner_b = setup_runtime_pg(owner, app, reader).await?;
    let owner_c = setup_runtime_pg(owner, app, reader).await?;
    let handler_calls = Arc::new(AtomicUsize::new(0));
    let token = service_token(&ids.concurrent, now_seconds)?;

    let requests = [
        submit(
            router(provider(&owner_a, now)?, Arc::clone(&handler_calls))?,
            &token,
        ),
        submit(
            router(provider(&owner_b, now)?, Arc::clone(&handler_calls))?,
            &token,
        ),
        submit(
            router(provider(&owner_c, now)?, Arc::clone(&handler_calls))?,
            &token,
        ),
    ];
    let responses = futures::future::try_join_all(requests).await?;
    let mut statuses = responses
        .iter()
        .map(|response| response.status().as_u16())
        .collect::<Vec<_>>();
    statuses.sort_unstable();
    anyhow::ensure!(
        statuses
            == [
                StatusCode::OK.as_u16(),
                StatusCode::UNAUTHORIZED.as_u16(),
                StatusCode::UNAUTHORIZED.as_u16(),
            ],
        "three runtime instances must accept the token exactly once globally: {statuses:?}"
    );
    anyhow::ensure!(
        handler_calls.load(Ordering::Acquire) == 1,
        "exactly one concurrent request must reach the handler"
    );

    shutdown_runtime_pg(owner_a).await?;
    shutdown_runtime_pg(owner_b).await?;
    shutdown_runtime_pg(owner_c).await?;

    let rebuilt_owner = setup_runtime_pg(owner, app, reader).await?;
    let rebuilt_calls = Arc::new(AtomicUsize::new(0));
    let rebuilt = submit(
        router(provider(&rebuilt_owner, now)?, Arc::clone(&rebuilt_calls))?,
        &token,
    )
    .await?;
    anyhow::ensure!(
        rebuilt.status() == StatusCode::UNAUTHORIZED,
        "the replay must remain rejected after every runtime pool is rebuilt"
    );
    anyhow::ensure!(
        rebuilt_calls.load(Ordering::Acquire) == 0,
        "the rebuilt runtime must reject the replay before its handler"
    );

    let outage_calls = Arc::new(AtomicUsize::new(0));
    let outage_router = router(provider(&rebuilt_owner, now)?, Arc::clone(&outage_calls))?;
    let fresh_token = service_token(&ids.outage, now_seconds)?;
    shutdown_runtime_pg(rebuilt_owner).await?;
    let unavailable = submit(outage_router, &fresh_token).await?;
    anyhow::ensure!(
        unavailable.status() == StatusCode::SERVICE_UNAVAILABLE,
        "replay storage failure must fail closed at the HTTP boundary"
    );
    anyhow::ensure!(
        outage_calls.load(Ordering::Acquire) == 0,
        "the PostgreSQL outage must fail before the handler"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn replay_is_cluster_global_survives_rebuild_and_fails_closed_on_pg_outage() -> TestResult {
    let fixture = testkit::owned_postgres().await?;
    let p = fixture.owner_params();
    let [app, reader] = fixture
        .resolve_app_roles([
            testkit::PgAppRoleSpec::new(TEST_APP_ROLE, TEST_APP_PASSWORD),
            testkit::PgAppRoleSpec::new(TEST_READ_ROLE, TEST_READ_PASSWORD),
        ])
        .await?;
    let admin = admin_pool(p).await?;

    for _round in 0..2 {
        let ids = ReplayRoundIds::unique();
        let (now_seconds, now) = database_now(&admin).await?;
        let round_result =
            run_replay_round(p, app.params(), reader.params(), now_seconds, now, &ids).await;
        let cleanup_result = cleanup_replay_keys(&admin, &ids).await;
        match (round_result, cleanup_result) {
            (Ok(()), Ok(())) => {}
            (Err(round), Ok(())) => return Err(round),
            (Ok(()), Err(cleanup)) => return Err(cleanup),
            (Err(round), Err(cleanup)) => {
                return Err(anyhow::anyhow!(
                    "replay round failed: {round:#}; exact-key cleanup also failed: {cleanup:#}"
                ));
            }
        }
    }

    admin.close().await;
    drop(fixture);
    Ok(())
}
