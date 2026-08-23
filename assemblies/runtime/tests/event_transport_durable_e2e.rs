//! #1251/#1434 durable e2e journey：`wire_event_transport` → postgres + RabbitMQ 真容器
//! 贯通 outbox → relay → AMQP → consumer → PG inbox 幂等去重 → audit 审计链。
//!
//! 断言 A（至少一次）：登录触发 outbox 落库 → relay 中继 → AMQP consumer 消费 → audit append
//! 仅一次（20s timeout）。
//!
//! 断言 B（runtime T2 cross-provider join）：真实 AMQP frame write 后注入 connection close 仅作构造
//! duplicate 的 setup（Ambiguous/retryable/generation owner 属 AMQP catalog，本 E2E 不断言其 kind）；
//! 同 event_id 重试后再发新 event/session tracer。FIFO 单 consumer：tracer 被 audit 证明其前面的
//! duplicate 已被消费+Ack；original session 仍只有一条业务 mutation，且原 event 的 Inbox Done 仍只有一行。
//!
//! Cargo `[[test]] required-features = ["integration"]`：需真实 docker 容器；`cargo test -p runtime --features
//! integration --no-run` 仅要求编译通过（无 docker 时可用）。
//! `cargo nextest run -p runtime --features integration` 或复制 selector 输出并运行
//! `cargo xtask ci run --job integration-critical --integration-group transport --selection '<canonical SelectionPlan JSON>'`。

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use anyhow::{Context as _, Result};
use audit::AuditDomain;
use audit::ports::{
    AuditChainHasher, AuditListTenantAppend, AuditListTenantAppender, DynAuditReadRepo,
};
use audit::test_support::InMemAuditRepo;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64_URL;
use consistency::IdemKey;
use diport::{
    Clock as _, DynKeyProvider, EncryptOutput, EnvelopeMetadata, EnvelopeSubjectId, KeyName,
    KeyProvider, KeyProviderError, KeyRef, KeyVersion, ManagedResource as _, MessageId,
    OpaqueActorId, OutboxActor, PublishRequest, Publisher, RedactedBytes, SecretCoordinate,
    SecretMaterial, SecretResolver, SecretResolverError, Topic,
};
use eventexec::{L2DrRecoveryStore as _, TenantAuthorityBinding};
use generated::event::identity_v1::{
    policy_updated::{self, IdentityPolicyUpdatedPayload},
    session_created::{self, IdentitySessionCreatedPayload},
};
use generated::event::settings_v1;
use generated::http::identity_v1::{
    login::{IdentityLoginRequest, PRODUCER as LOGIN_PRODUCER},
    policies_create::PRODUCER as POLICIES_CREATE_PRODUCER,
};
use generated::http::settings_v1::{SPEC as SETTINGS_CONFIG_SPEC, SettingsConfigPublishRequest};
use httpserve::ProducerMarker;
use httpserve::{RouteAuthorizationRequest, RouteResource};
use identity::ports::{
    AttributeKey, DynPolicyLifecycle, DynPolicyRepo, DynRoleBindingLifecycle,
    DynRoleBindingReadRepo, DynRoleReadRepo, EqualityPredicate, MembershipPredicate, Operator,
    OperatorInput, POLICY_ATTR_PRINCIPAL_KIND, Policy, PolicyCondition, PolicyEffect,
    PolicyLifecycle, PolicyObligations, PolicyRouteScope, PolicyRule, PolicyScalarInput,
    PolicyValueType, ScalarOperandInput, TenantRepoScope, TypedPolicyValueInput,
};
use identity::{IdentityDomain, IdentityDomainDeps, LoginService};
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use postgres::{
    PgConfig, PgL2DrRecoveryAuditConfig, PgL2DrRecoveryDeps, PgL2DrRecoveryExecutorConfig,
    PgPassword, PgRuntimeDeps, PgTenantReadConfig, caps,
};
use primitives::{Mac, MacAlgorithm, MacKey, MacVerifier};
use rss_request_context::TenantId;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt as _;

use runtime::event_transport::{
    EventTransportTestValues, EventWorkerTestValues, bridge_generated_subscriptions,
};
use runtime::support::{SystemClock, TracingAuthAuditSink};
use runtime::test_support::{
    build_redis_runtime_deps_from_values, build_s3_runtime_deps_from_values,
    build_shared_runtime_deps, build_vault_runtime_from_values, finalize_federated_listener,
    wire_distributed, wire_event_transport, wire_event_transport_with_admission,
    wire_runtime_security_root,
};
use settings::{SecretResolveService, SettingsDomain, SettingsService};

const TEST_PUBLISH_TIMEOUT: Duration = Duration::from_secs(40);

// ── 共用常量（自 journeys/tests/common/mod.rs 复制，runtime 测试不能 mod common）────────────

const CANON_TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const SESSION_CREATED_TOPIC: &str = "identity.session-created";
const PASSWORD: &str = "correct-horse";
const LOGIN_USERNAME: &str = "alice";
const CANON_USER: &str = "11111111-2222-4333-8444-555555555555";
const AUDIT_KEY: [u8; 32] = [0x5a; 32];
const NOW_SECS: u64 = 1_000;
const TTL_SECS: u64 = 3_600;
const TEST_APP_ROLE: &str = "rss_app";
const TEST_APP_PASSWORD: &str = "rss_app_test_pw";
const TEST_READ_ROLE: &str = "rss_app_read";
const TEST_READ_PASSWORD: &str = "rss_app_read_test_pw";
const TEST_L2_DR_AUDITOR_PASSWORD: &str = "rss_l2_dr_recovery_auditor_test_pw";
const TEST_L2_DR_EXECUTOR_PASSWORD: &str = "rss_l2_dr_recovery_executor_test_pw";

#[allow(clippy::expect_used)]
fn federated_signing_key() -> SigningKey {
    let bytes: [u8; 32] = std::array::from_fn(|index| (index + 1) as u8);
    SigningKey::from_slice(&bytes).expect("valid P-256 scalar")
}

fn federated_provider() -> Result<oidc::OidcProvider<diport::FederatedAccessProfile>> {
    let keys = oidc::AccessStaticKeySource::builder()
        .add_es256_sec1(
            "federated-jwt-es256",
            federated_signing_key()
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        )?
        .build();
    let permissions = oidc::FederatedPermissionUniverse::try_new([vocab::GrantPermission::route(
        vocab::RoutePermissionId::SettingsConfigPublish,
    )])?;
    let config = oidc::VerifierConfigBuilder::<diport::FederatedAccessProfile>::new(
        "https://issuer.test",
        "rss",
        permissions,
    )
    .keys_static(keys)
    .trust_kind("admin")
    .build()?;
    Ok(oidc::OidcProvider::new(config, Box::new(SystemClock)))
}

fn settings_admin_jwt() -> String {
    let now = SystemClock
        .now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let payload = serde_json::json!({
        "sub": CANON_USER,
        "iat": now,
        "exp": now + 900,
        "iss": "https://issuer.test",
        "aud": "rss",
        "kind": "admin",
        "tenant_id": CANON_TENANT,
        "token_use": "access",
        "permissions": [vocab::RoutePermissionId::SettingsConfigPublish.as_str()],
    });
    let header = B64_URL.encode(br#"{"alg":"ES256","typ":"at+jwt","kid":"federated-jwt-es256"}"#);
    let body = B64_URL.encode(payload.to_string().as_bytes());
    let signing_input = format!("{header}.{body}");
    let signature: Signature = federated_signing_key().sign(signing_input.as_bytes());
    format!("{signing_input}.{}", B64_URL.encode(signature.to_bytes()))
}

async fn publish_settings_over_generated_http(
    router: &axum::Router,
    key: &str,
    value: &str,
) -> Result<StatusCode> {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(SETTINGS_CONFIG_SPEC.route.path())
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", settings_admin_jwt()),
                )
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({ "key": key, "value": value }).to_string(),
                ))?,
        )
        .await?;
    Ok(response.status())
}

fn test_password_blocklist() -> Result<Arc<secure::DigestPasswordBlocklist>> {
    let blocklist = crypto::load_password_blocklist_from_reader(std::io::Cursor::new(
        b"sha256:2e2b24f8ee40bb847fe85bb23336a39ef5948e6b49d897419ced68766b16967a\n",
    ))?;
    Ok(Arc::new(blocklist))
}

fn test_password_policy() -> Result<secure::PasswordPolicy> {
    Ok(secure::PasswordPolicy::new(test_password_blocklist()?))
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

struct NoopDomainTransport;

struct UnusedSecretResolver;

impl SecretResolver for UnusedSecretResolver {
    async fn resolve(
        &self,
        _tenant: rss_request_context::TenantId,
        _coordinate: &SecretCoordinate,
    ) -> Result<SecretMaterial, SecretResolverError> {
        Err(SecretResolverError::NotFound)
    }
}

impl distributed::HttpContractTransport for NoopDomainTransport {
    fn dispatch(
        &self,
        _request: distributed::HttpContractRequest,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<
                        distributed::HttpContractResponse,
                        distributed::HttpContractTransportError,
                    >,
                > + Send
                + '_,
        >,
    > {
        Box::pin(async { distributed::HttpContractResponse::try_new(204, Vec::new()) })
    }
}

fn noop_domain_transport() -> Arc<dyn distributed::HttpContractTransport> {
    Arc::new(NoopDomainTransport)
}

fn amqp_endpoint(url: &str) -> Result<secure::AmqpEndpoint> {
    Ok(secure::AmqpEndpoint::parse(
        url,
        secure::PlaintextEndpointPolicy::AllowLoopback,
    )?)
}

fn signed_session_metadata(
    authority: &eventexec::TenantAuthority,
    message_id: &str,
) -> Result<EnvelopeMetadata> {
    let tenant = TenantId::parse(CANON_TENANT)?;
    let token = authority.sign(TenantAuthorityBinding::new(
        tenant,
        session_created::CONTRACT.domain(),
        session_created::CONTRACT.contract_id(),
        session_created::TOPIC,
        message_id,
    ))?;
    let mut metadata = EnvelopeMetadata::empty();
    metadata.insert_wire_pair(diport::KEY_TENANT_ID, CANON_TENANT);
    metadata.insert_wire_pair(diport::KEY_TENANT_AUTHORITY, token);
    metadata.insert_wire_pair(
        diport::KEY_SCHEMA_VERSION,
        session_created::CONTRACT.version(),
    );
    metadata.insert_wire_pair(
        diport::KEY_SCHEMA_HASH,
        session_created::CONTRACT.schema_hash(),
    );
    Ok(metadata)
}

// ── FixedClock（inline；memory crate 被 deny.toml 限定 journeys/xtask，runtime 不可用）─────────

/// 确定性测试时钟——固定 unix_secs，impl `diport::Clock`（非 `SystemTime::now`，符合 clock 注入纪律）。
struct FixedClock(SystemTime);

impl FixedClock {
    fn at_unix_secs(secs: u64) -> Self {
        Self(std::time::UNIX_EPOCH + Duration::from_secs(secs))
    }
}

impl diport::Clock for FixedClock {
    fn now(&self) -> SystemTime {
        self.0
    }
}

#[derive(Clone)]
struct TestKeyProvider;

impl KeyProvider for TestKeyProvider {
    async fn encrypt(
        &self,
        key: KeyName,
        plaintext: secure::Plaintext,
        _aad: secure::DerivedAad,
    ) -> Result<EncryptOutput, KeyProviderError> {
        let ciphertext: Vec<u8> = plaintext.expose().iter().map(|byte| byte ^ 0xA5).collect();
        Ok(EncryptOutput::new(
            ciphertext,
            KeyRef::new(key, KeyVersion::new(1)),
        ))
    }

    async fn decrypt(
        &self,
        ciphertext: RedactedBytes,
        _key: KeyRef,
        _aad: secure::DerivedAad,
    ) -> Result<secure::Plaintext, KeyProviderError> {
        let plaintext: Vec<u8> = ciphertext
            .into_bytes()
            .into_iter()
            .map(|byte| byte ^ 0xA5)
            .collect();
        Ok(secure::Plaintext::new(plaintext))
    }

    async fn rewrap(
        &self,
        _ciphertext: RedactedBytes,
        _key: KeyRef,
        _aad: secure::DerivedAad,
    ) -> Result<EncryptOutput, KeyProviderError> {
        Err(KeyProviderError::new(
            diport::key_provider::KeyProviderErrorKind::Forbidden,
            std::io::Error::other("test key provider does not rewrap"),
        ))
    }

    async fn shutdown(&self) -> Result<(), KeyProviderError> {
        Ok(())
    }
}

fn config_value_protections() -> Result<postgres::ConfigValueProtections> {
    let key = KeyName::try_new("settings-config")?;
    Ok(postgres::ConfigValueProtections::new(
        DynKeyProvider::new_box(TestKeyProvider),
        DynKeyProvider::new_box(TestKeyProvider),
        key,
    ))
}

// ── CapturingVerifier（自 journeys/tests/common/mod.rs 复制）──────────────────────────────

/// 审计链 HMAC 测试 verifier：捕获每次 `sign` 调用的 message，确定性折叠产出 32B 标签（链一致）。
#[derive(Clone, Default)]
struct CapturingVerifier {
    messages: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl MacVerifier for CapturingVerifier {
    fn sign(&self, key: &MacKey, _algorithm: MacAlgorithm, message: &[u8]) -> Mac {
        self.messages
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(message.to_vec());
        // 确定性折叠（FNV-1a 变体；journey 只需链一致，非加密）。
        let mut acc = FNV_OFFSET;
        for &b in key.as_bytes().iter().chain(message) {
            acc ^= u64::from(b);
            acc = acc.wrapping_mul(FNV_PRIME);
        }
        let mut out = [0u8; 32];
        for chunk in out.chunks_mut(8) {
            chunk.copy_from_slice(&acc.to_be_bytes());
            acc = acc.wrapping_mul(FNV_PRIME);
        }
        Mac::from_bytes(out.to_vec())
    }

    fn verify(&self, key: &MacKey, algorithm: MacAlgorithm, message: &[u8], tag: &Mac) -> bool {
        primitives::constant_time_eq(
            self.sign(key, algorithm, message).as_bytes(),
            tag.as_bytes(),
        )
    }
}

// ── audit_domain helper（自 journeys/tests/common/mod.rs 复制）───────────────────────────

#[derive(Clone, Default)]
struct TestAuditListTenantAppender;

impl AuditListTenantAppender for TestAuditListTenantAppender {
    async fn append(&self, _command: AuditListTenantAppend) -> Result<(), diport::AuditSinkError> {
        Ok(())
    }
}

#[allow(clippy::expect_used)]
// reason: 32B audit key 满足 AuditChainHasher MIN_KEY_LEN（失败意味测试常量有误），panic 正当。
fn audit_domain() -> (AuditDomain<TestAuditListTenantAppender>, CapturingVerifier) {
    let verifier = CapturingVerifier::default();
    let hasher = AuditChainHasher::new(verifier.clone(), MacKey::from_bytes(AUDIT_KEY.to_vec()))
        .expect("32B audit key satisfies MIN_KEY_LEN");
    let provider = Arc::new(InMemAuditRepo::new(hasher));
    let read_repo: Arc<DynAuditReadRepo<'static>> = Arc::from(DynAuditReadRepo::new_box(provider));
    let domain = AuditDomain::new(
        read_repo,
        None,
        TestAuditListTenantAppender,
        Arc::new(SystemClock),
    );
    (domain, verifier)
}

// ── pg_config helper（自 journeys/tests/identity_login_audit_durable_journey.rs 复制）──────

async fn connect_pg() -> Result<(testkit::OwnedPgFixture, PgRuntimeDeps)> {
    let fixture = testkit::owned_postgres().await?;
    let p = fixture.owner_params();
    let owner_config = pg_config(p, &p.username, &p.password);
    let [app, reader] = fixture
        .resolve_app_roles([
            testkit::PgAppRoleSpec::new(TEST_APP_ROLE, TEST_APP_PASSWORD),
            testkit::PgAppRoleSpec::new(TEST_READ_ROLE, TEST_READ_PASSWORD),
        ])
        .await?;
    let reader_params = reader.params();
    let tenant_read_config = PgTenantReadConfig::new(pg_config(
        reader_params,
        &reader_params.username,
        &reader_params.password,
    ));
    let workflow = eventexec::WorkflowRuntimePlan::disabled_fixture();
    let deps = PgRuntimeDeps::setup_owned_test_fixture(
        &owner_config,
        &pg_config(app.params(), &app.params().username, &app.params().password),
        &tenant_read_config,
        None,
        workflow.projection_capture(),
    )
    .await?;
    Ok((fixture, deps))
}

async fn connect_l2_dr_operator(
    owner_pool: &sqlx::PgPool,
    params: &testkit::PgConnParams,
) -> Result<PgL2DrRecoveryDeps> {
    sqlx::query(
        "ALTER ROLE rss_l2_dr_recovery_auditor LOGIN \
         PASSWORD 'rss_l2_dr_recovery_auditor_test_pw'",
    )
    .execute(owner_pool)
    .await?;
    sqlx::query(
        "ALTER ROLE rss_l2_dr_recovery_executor LOGIN \
         PASSWORD 'rss_l2_dr_recovery_executor_test_pw'",
    )
    .execute(owner_pool)
    .await?;
    let auditor = PgL2DrRecoveryAuditConfig::new(pg_config(
        params,
        "rss_l2_dr_recovery_auditor",
        TEST_L2_DR_AUDITOR_PASSWORD,
    ));
    let executor = PgL2DrRecoveryExecutorConfig::new(pg_config(
        params,
        "rss_l2_dr_recovery_executor",
        TEST_L2_DR_EXECUTOR_PASSWORD,
    ));
    Ok(PgL2DrRecoveryDeps::connect(&auditor, &executor).await?)
}

fn broker_ahead_recovery_plan(
    recovery_epoch: uuid::Uuid,
    tenant: TenantId,
    event_id: &str,
) -> Result<eventexec::L2DrRecoveryPlan> {
    Ok(eventexec::L2DrRecoveryPlan::new(
        eventexec::RecoveryEpochId::new(recovery_epoch)?,
        tenant,
        eventexec::UtcEpochMicros::new(1_000)?,
        eventexec::UtcEpochMicros::new(2_000)?,
        eventexec::RecoveryEventSet::new(vec![IdemKey::parse(event_id)?])?,
        eventexec::RecoveryChangeTicket::parse("CHG-2009-RUNTIME-T2")?,
    )?)
}

async fn apply_fenced_recovery(
    operator: &PgL2DrRecoveryDeps,
    plan: eventexec::L2DrRecoveryPlan,
    admission_epoch: primitives::AdmissionEpochId,
) -> Result<()> {
    let subject = eventexec::L2DrRecoveryOperatorSubject::parse("service:runtime-dr-t2")?;
    let proof = operator
        .record_l2_dr_recovery_start_audit_subject(&subject, &plan, uuid::Uuid::new_v4())
        .await?;
    let capability = eventexec::OperatorL2DrRecoveryCapability::issue_for_authorized_operator();
    let authorized = eventexec::AuthorizedL2DrRecoveryPlan::from_authenticated_and_authorized(
        plan, proof, capability,
    )?;
    let receipt = operator
        .apply_l2_dr_recovery(authorized.require_admission(admission_epoch))
        .await?;
    anyhow::ensure!(
        receipt.outcome() == eventexec::L2DrRecoveryOutcome::Applied,
        "runtime T2 fenced recovery must apply exactly once"
    );
    Ok(())
}

fn pg_config(p: &testkit::PgConnParams, username: &str, password: &str) -> PgConfig {
    PgConfig::new_for_test_plaintext(
        p.host.clone(),
        p.port,
        p.database.clone(),
        username.to_string(),
        PgPassword::new(password.to_string()),
    )
    .with_acquire_timeout(Duration::from_secs(5))
}

fn pg_owner_connect_options(p: &testkit::PgConnParams) -> PgConnectOptions {
    PgConnectOptions::new()
        .host(&p.host)
        .port(p.port)
        .database(&p.database)
        .username(&p.username)
        .password(&p.password)
}

async fn seed_durable_login_account(pool: &sqlx::PgPool) -> Result<()> {
    let password = secure::PasswordHash::for_test(secure::RawPassword::new(PASSWORD.to_owned()))?;
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO credentials \
         (tenant_id, user_id, login, password_hash, version) \
         VALUES ($1::uuid, $2::uuid, $3, $4, 1)",
    )
    .bind(CANON_TENANT)
    .bind(CANON_USER)
    .bind(LOGIN_USERNAME)
    .bind(password.as_str())
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO account_security_states \
         (tenant_id, user_id, status, authn_epoch, version, status_changed_at, updated_at) \
         VALUES ($1::uuid, $2::uuid, 'active', 0, 1, now(), now())",
    )
    .bind(CANON_TENANT)
    .bind(CANON_USER)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

async fn inbox_done_count(pool: &sqlx::PgPool, event_id: &str, group: &str) -> Result<i64> {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM inbox_receipts WHERE event_id = $1 AND consumer_group = $2 AND status = 'done'",
    )
    .bind(event_id)
    .bind(group)
    .fetch_one(pool)
    .await?;
    Ok(count)
}

async fn wait_inbox_done(pool: &sqlx::PgPool, event_id: &str, group: &str) -> Result<()> {
    testkit::await_try(Duration::from_secs(20), async || {
        Ok::<Option<()>, anyhow::Error>(
            (inbox_done_count(pool, event_id, group).await? == 1).then_some(()),
        )
    })
    .await
    .with_context(|| format!("等待 event {event_id} 被 consumer group {group} 消费失败"))
}

async fn wait_admission_phase(pool: &sqlx::PgPool, expected: &str) -> Result<()> {
    testkit::await_try(Duration::from_secs(20), async || {
        let phase: Option<String> = sqlx::query_scalar(
            "SELECT phase FROM public.event_l2_dr_admission_epoch WHERE singleton",
        )
        .fetch_optional(pool)
        .await?;
        Ok::<Option<()>, anyhow::Error>((phase.as_deref() == Some(expected)).then_some(()))
    })
    .await
    .with_context(|| format!("等待 DR admission phase={expected} 失败"))
}

async fn wait_outbox_status(pool: &sqlx::PgPool, event_id: &str, expected: &str) -> Result<()> {
    let result = testkit::await_try(Duration::from_secs(20), async || {
        let status: Option<String> =
            sqlx::query_scalar("SELECT status FROM public.outbox WHERE event_id = $1")
                .bind(event_id)
                .fetch_optional(pool)
                .await?;
        Ok::<Option<()>, anyhow::Error>((status.as_deref() == Some(expected)).then_some(()))
    })
    .await;
    if result.is_err() {
        let actual: Option<(String, i32, Option<String>)> = sqlx::query_as(
            "SELECT status, retry_count, lease_token::text FROM public.outbox WHERE event_id = $1",
        )
        .bind(event_id)
        .fetch_optional(pool)
        .await?;
        anyhow::bail!("等待 outbox event {event_id} status={expected} 失败; actual={actual:?}");
    }
    Ok(())
}

async fn latest_outbox_event_id(pool: &sqlx::PgPool, domain: &str, topic: &str) -> Result<String> {
    let (event_id,): (String,) = sqlx::query_as(
        r#"
        SELECT event_id
        FROM outbox
        WHERE domain = $1 AND topic = $2
        ORDER BY created_at DESC, event_id DESC
        LIMIT 1
        "#,
    )
    .bind(domain)
    .bind(topic)
    .fetch_one(pool)
    .await?;
    Ok(event_id)
}

async fn settings_http_write_counts(pool: &sqlx::PgPool, key: &str) -> Result<(i64, i64)> {
    let config_count = sqlx::query_scalar(
        "SELECT count(*) FROM public.config_entries \
         WHERE tenant_id = $1::uuid AND config_key = $2",
    )
    .bind(CANON_TENANT)
    .bind(key)
    .fetch_one(pool)
    .await?;
    let outbox_count = sqlx::query_scalar(
        "SELECT count(*) FROM public.outbox \
         WHERE tenant_id = $1::uuid AND domain = 'settings' AND topic = $2",
    )
    .bind(CANON_TENANT)
    .bind(settings_v1::TOPIC)
    .fetch_one(pool)
    .await?;
    Ok((config_count, outbox_count))
}

/// 测试专用只读观察：不经过生产 outbox API，因此不会夺取后台 relay 的租约。
/// tenant/domain/topic 均为必填过滤条件；bounded 查询后在 Rust 解码本轮 session payload。
async fn outbox_session_event(
    pool: &sqlx::PgPool,
    tenant: TenantId,
    domain: &str,
    topic: &str,
    session_id: &str,
) -> Result<Option<(String, Vec<u8>)>> {
    let session_id = uuid::Uuid::parse_str(session_id)?;
    let rows: Vec<(String, Vec<u8>)> = sqlx::query_as(
        r#"
        SELECT event_id, payload
        FROM outbox
        WHERE tenant_id = $1::uuid AND domain = $2 AND topic = $3
        ORDER BY created_at DESC, event_id DESC
        LIMIT 64
        "#,
    )
    .bind(tenant.to_string())
    .bind(domain)
    .bind(topic)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().find(|(_, payload)| {
        serde_json::from_slice::<IdentitySessionCreatedPayload>(payload)
            .is_ok_and(|decoded| decoded.session_id == session_id)
    }))
}

async fn audit_login_count(pool: &sqlx::PgPool, tenant: TenantId, event_id: &str) -> Result<i64> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    let (count,): (i64,) = sqlx::query_as(
        r#"
        SELECT count(*)
        FROM audit_entries
        WHERE tenant_id = $1::uuid
          AND action = 'identity:login'
          AND resource_kind = 'session'
          AND resource_id = $2
          AND outcome = 'success'
        "#,
    )
    .bind(tenant.to_string())
    .bind(format!("event:{event_id}"))
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(count)
}

async fn audit_policy_count(
    pool: &sqlx::PgPool,
    tenant: TenantId,
    resource_id: &str,
) -> Result<i64> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    let (count,): (i64,) = sqlx::query_as(
        r#"
        SELECT count(*)
        FROM audit_entries
        WHERE tenant_id = $1::uuid
          AND action = 'identity:policy_create'
          AND resource_kind = 'policy'
          AND resource_id = $2
          AND outcome = 'success'
        "#,
    )
    .bind(tenant.to_string())
    .bind(resource_id)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(count)
}

async fn policy_updated_event(
    tenant: TenantId,
    policy_id: &str,
    contract_id: &str,
    permission: &str,
    event_id: &str,
) -> Result<eventexec::event::ReviewedEvent> {
    let payload = IdentityPolicyUpdatedPayload {
        policy_id: policy_id.to_string(),
        change_kind: policy_updated::IdentityPolicyUpdatedPayloadChangeKind::Created,
        version: std::num::NonZeroU32::new(1).context("policy version is non-zero")?,
        contract_id: contract_id.to_string(),
        permission: permission.to_string(),
        updated_by: uuid::Uuid::parse_str(CANON_USER)?,
        actor_kind: policy_updated::IdentityPolicyUpdatedPayloadActorKind::Admin,
        tenant_id: tenant.to_string(),
        occurred_at: i64::try_from(NOW_SECS)?,
    };
    let actor = OutboxActor::scoped(
        rss_request_context::PrincipalKind::Admin,
        OpaqueActorId::from_opaque(CANON_USER)?,
        tenant,
        rss_request_context::RowScope::Tenant,
    );
    Ok(policy_updated::emit(
        &eventexec::event::GeneratedEventEncoder,
        payload,
        tenant,
        EnvelopeSubjectId::from_opaque(CANON_USER)?,
        actor,
        IdemKey::parse(event_id)?,
    )
    .await?)
}

// ── e2e 测试主体 ───────────────────────────────────────────────────────────────────────────

/// durable e2e：`wire_event_transport` 真容器贯通验收（#1251 task 6）。
///
/// - 断言 A：login → PgOutbox(pending) → relay → AMQP → consumer → PG inbox(Fresh) → audit append（至少一次）。
/// - 断言 B（runtime T2 join）：post-send connection close + 同 event_id retry 仅作 duplicate setup；
///   独立 tracer 被消费正向见证 duplicate 经真实 PG inbox/ConsumerTx 后已 Ack，audit mutation 与
///   `inbox_receipts` Done 各保持一次（Ambiguous/retryable/generation 归 AMQP catalog）。
///
/// 需 docker：`cargo test -p runtime --features integration event_transport_durable -- --nocapture`
/// 或 `cargo nextest run -p runtime --features integration`。无 docker 时只需通过
/// `cargo test -p runtime --features integration --no-run`（编译门）。
#[tokio::test(flavor = "multi_thread")]
async fn event_transport_durable_e2e() -> Result<()> {
    // ── 步骤 1：启动两个真实容器 fixture（guard 绑到测试结束，Drop 停容器）─────────────────────

    let (pgfix, pg_owner) = connect_pg().await?;
    let pg = pg_owner.handle();
    let rmq_network = testkit::bridge_network("rss-runtime-rmq-tls").await?;
    let rmq_dns = format!("{}-node", rmq_network.name());
    let rmq = testkit::rabbitmq_tls(
        SESSION_CREATED_TOPIC,
        testkit::NetworkAttachment {
            network: rmq_network.name(),
            dns_name: &rmq_dns,
        },
    )
    .await?;

    // ── 步骤 2：postgres capability bundle（connect + run_migrations + RLS 能力门）──────────────

    let assertion_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(pg_owner_connect_options(pgfix.owner_params()))
        .await?;
    seed_durable_login_account(&assertion_pool).await?;
    let id = pg.for_domain::<caps::Identity>();
    let settings_pg = pg.for_domain::<caps::Settings>();

    // ── 步骤 3：域装配（identity + settings + audit）────────────────────────────────────────

    let (audit_domain_inst, _audit) = audit_domain();

    // identity 域：with_seed_credential 注入 in-mem 凭据 + PgAuthGrantLifecycle durable co-tx。
    let mut refresh_identity = None;
    let mut credential_security_grants = None;
    let mut credential_security_lifecycle = None;
    let login_identity = Arc::new(LoginService::with_seed_credential(
        |accounts| {
            let services = identity::seed_auth_grant_services(
                id.auth_grant_provider(
                    Box::new(FixedClock::at_unix_secs(NOW_SECS)),
                    postgres::identity_pseudonym_keys_for_test(),
                ),
                accounts,
                || Box::new(FixedClock::at_unix_secs(NOW_SECS)),
                Duration::from_secs(TTL_SECS),
            );
            refresh_identity = Some(services.refresh_service());
            credential_security_grants = Some(services.lifecycle());
            credential_security_lifecycle = Some(services.security_lifecycle());
            services
        },
        Box::new(FixedClock::at_unix_secs(NOW_SECS)),
        Duration::from_secs(TTL_SECS),
        LOGIN_USERNAME,
        ids::UserId::parse(CANON_USER)?,
        PASSWORD,
        TenantId::parse(CANON_TENANT)?,
    )?);
    let refresh_identity = refresh_identity
        .ok_or_else(|| anyhow::anyhow!("seed refresh service was not constructed"))?;
    let credential_security_grants = credential_security_grants
        .ok_or_else(|| anyhow::anyhow!("seed auth-grant lifecycle was not constructed"))?;
    let credential_security_lifecycle = credential_security_lifecycle
        .ok_or_else(|| anyhow::anyhow!("seed security lifecycle was not constructed"))?;
    let roles_for_admin = Arc::from(DynRoleReadRepo::new_box(id.role_repo()));
    let roles_for_list = Arc::from(DynRoleReadRepo::new_box(id.role_repo()));
    let policies = Arc::from(DynPolicyRepo::new_box(id.policy_repo()));
    let policy_lifecycle = Arc::from(DynPolicyLifecycle::new_box(
        id.policy_lifecycle(Box::new(FixedClock::at_unix_secs(NOW_SECS))),
    ));
    let policy_lifecycle_for_service = Arc::clone(&policy_lifecycle);
    let binding_lifecycle = Arc::from(DynRoleBindingLifecycle::new_box(
        id.role_binding_lifecycle(Box::new(FixedClock::at_unix_secs(NOW_SECS))),
    ));
    let binding_reads = Arc::from(DynRoleBindingReadRepo::new_box(id.role_binding_read_repo()));
    let rbac_admin = Arc::new(identity::RbacAdminService::new(
        roles_for_admin,
        binding_lifecycle,
        Box::new(FixedClock::at_unix_secs(NOW_SECS)),
    ));
    let policy_manage = Arc::new(identity::PolicyManageService::new(
        Arc::clone(&policies),
        policy_lifecycle_for_service,
        Box::new(FixedClock::at_unix_secs(NOW_SECS)),
    ));
    let credential_security = Arc::new(
        identity::CredentialSecurityService::new_with_shared_lifecycle(
            Arc::from(identity::ports::DynCredentialRepo::new_box(
                id.credential_repo(),
            )),
            credential_security_grants,
            identity::ports::DynAccountSecurityReadRepo::new_box(id.account_security_repo()),
            credential_security_lifecycle,
            id.account_reactivation_lifecycle(),
            test_password_policy()?,
            Box::new(FixedClock::at_unix_secs(NOW_SECS)),
        ),
    );
    let identity_domain = IdentityDomain::new(IdentityDomainDeps {
        login: login_identity,
        refresh: refresh_identity,
        credential_security,
        rbac_admin,
        policy_manage,
        roles: roles_for_list,
        binding_reads,
        policies,
        clock: Arc::new(FixedClock::at_unix_secs(NOW_SECS)),
    });
    let (settings_configs, settings_writer, settings_secrets, settings_secret_writer) = settings_pg
        .settings_bundle(
            Arc::new(FixedClock::at_unix_secs(NOW_SECS)),
            config_value_protections()?,
        )
        .into_parts();
    let subscriber_settings_service = Arc::new(SettingsService::with_postgres(
        settings_configs,
        settings_writer,
        Box::new(FixedClock::at_unix_secs(NOW_SECS)),
    ));
    let settings_secrets = Arc::from(settings_secrets);
    let settings_secret_writer = Arc::from(settings_secret_writer);
    let secret_service = Arc::new(SecretResolveService::new(
        Arc::clone(&settings_secrets),
        diport::DynSecretResolver::new_box(UnusedSecretResolver),
    ));
    let settings_domain = SettingsDomain::new(
        Arc::clone(&subscriber_settings_service),
        settings_secrets,
        settings_secret_writer,
        secret_service,
    );
    let (
        publisher_settings_configs,
        publisher_settings_writer,
        _publisher_settings_secrets,
        _publisher_settings_secret_writer,
    ) = settings_pg
        .settings_bundle(
            Arc::new(FixedClock::at_unix_secs(NOW_SECS)),
            config_value_protections()?,
        )
        .into_parts();
    let publisher_settings_service = Arc::new(SettingsService::with_postgres(
        publisher_settings_configs,
        publisher_settings_writer,
        Box::new(FixedClock::at_unix_secs(NOW_SECS)),
    ));

    let tenant = TenantId::parse(CANON_TENANT)?;
    let settings_key = "app.runtime-e2e";
    let settings_actor = OutboxActor::scoped(
        rss_request_context::PrincipalKind::Admin,
        OpaqueActorId::from_opaque("settings-event-transport-e2e")?,
        tenant,
        rss_request_context::RowScope::Tenant,
    );
    publisher_settings_service
        .publish_config(
            settings::config_publish_receipt_for_test(),
            tenant,
            settings_actor.clone(),
            SettingsConfigPublishRequest {
                key: settings_key.to_string(),
                value: "disabled".to_string(),
            },
        )
        .await?;
    assert_eq!(
        subscriber_settings_service
            .config_query_service()
            .get_config(tenant, settings_key)
            .await?
            .as_ref()
            .map(|entry| entry.value()),
        Some("disabled"),
        "subscriber settings cache must start with the old value before the ConsumerTx refresh"
    );

    // ── 步骤 4：compose + drain subscribers（generated event topology 对应的订阅绑定）────────────

    let admission_epoch = primitives::AdmissionEpochId::new(uuid::Uuid::new_v4())?;
    let (admission_control, relay_admission, consumer_admission, write_admission) =
        primitives::prepare_dr_admission_controls().into_parts();
    let mut registry =
        bootstrap::compose(&[&identity_domain, &settings_domain, &audit_domain_inst])?;
    let subscribers = bridge_generated_subscriptions(registry.drain_subscribers())?;
    let http_registry = bootstrap::compose(&[&settings_domain])?;
    let http_registry = wire_runtime_security_root(
        http_registry.admit_writes(write_admission.clone()),
        &pg,
        Arc::new(FixedClock::at_unix_secs(NOW_SECS)),
    )?;
    let route_authorizer = http_registry.authorizer();
    let settings_router = finalize_federated_listener(
        http_registry,
        Arc::new(federated_provider()?),
        httpserve::AuditSinkHandle::new(TracingAuthAuditSink),
        Arc::new(SystemClock),
        assembly_schema::AssemblyListenerKind::Primary,
    )?
    .into_plaintext_router_for_test();
    let generated_group = |contract_id: &str, consumer: &str| {
        generated::event::EVENTS
            .iter()
            .find(|event| event.contract_id() == contract_id)
            .and_then(|event| {
                event
                    .subscriptions()
                    .iter()
                    .find(|spec| spec.consumer() == consumer)
            })
            .map(|spec| spec.group().to_owned())
    };
    let consumer_group = generated_group(
        generated::event::identity_v1::session_created::SPEC.contract_id(),
        "audit",
    )
    .context("e2e must declare audit session-created subscriber")?;
    let settings_consumer_group = generated_group(settings_v1::SPEC.contract_id(), "settings")
        .context("e2e must declare settings config-version-changed subscriber")?;
    let policy_consumer_group = generated_group(policy_updated::SPEC.contract_id(), "audit")
        .context("e2e must declare audit policy-updated subscriber")?;

    // ── 步骤 5：构造 EventTransportConfig（注入式 env builder，无 ambient env 侧效应）────────────

    let vhost_url = rmq.shared_url();

    // relay_poll_interval=2s：在 [100ms, 300s] 范围内；2s 窗口使步骤 6 poll 能赢过 relay 第二次轮询。
    // relay_sample_interval=30s：在 [1s, 60s] 范围内。
    let cfg = EventTransportTestValues::durable_shared(vhost_url)
        .with_amqp_ca_pem(rmq.ca_pem().as_bytes().to_vec())
        .build()?;
    let worker = EventWorkerTestValues::canonical()?
        .with_relay_poll_interval(Duration::from_secs(2))
        .with_relay_sample_interval(Duration::from_secs(30))
        .with_outbox_sweep_interval(Duration::from_secs(60))
        .build()?;
    let redeliver_tenant_authority = cfg
        .tenant_authority_for_test()
        .context("durable e2e tenant authority missing")?;

    // ── 步骤 6：wire_event_transport → DomainModuleResult（relay OS 线程 + consumer worker 启动）────

    let redis_network = testkit::bridge_network("rss-runtime-redis-tls").await?;
    let redis_dns = format!("{}-node", redis_network.name());
    let redis_fixture = testkit::redis_tls(testkit::NetworkAttachment {
        network: redis_network.name(),
        dns_name: &redis_dns,
    })
    .await?;
    let redis_ca = redis_fixture.ca_pem().as_bytes().to_vec();
    let redis =
        build_redis_runtime_deps_from_values(redis_fixture.url().to_string(), redis_ca.clone())
            .await?;
    let s3 = build_s3_runtime_deps_from_values(
        "https://127.0.0.1:1".to_string(),
        "rss-test-bucket".to_string(),
        "access-key".to_string(),
        "secret-key".to_string(),
        true,
        redis_ca,
    )?;
    let (vault, identity_signer, settings_config_value_key_name) = build_vault_runtime_from_values(
        "https://vault.example:8200".to_string(),
        "s.testtoken".to_string(),
        "transit".to_string(),
        "rss-jwt-es256".to_string(),
        "settings-config".to_string(),
        r#"{"bindings":[{"tenantId":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","storeId":"vault","mount":"secret","kvPathPrefix":"tenants/a"}]}"#.to_string(),
    )?;
    let deps = build_shared_runtime_deps(
        test_password_blocklist()?,
        pg.clone(),
        redis,
        s3,
        vault,
        identity_signer,
        settings_config_value_key_name,
        noop_domain_transport(),
    );
    let demo_cfg = EventTransportTestValues::demo().build()?;
    let demo_worker = EventWorkerTestValues::canonical()?.build()?;
    let demo_module = wire_event_transport(
        &pg,
        wire_distributed(&deps)?,
        eventing_composition::bridge_generated_subscriptions_selected(Vec::new(), &[])?,
        demo_cfg,
        demo_worker,
        MacKey::from_bytes(AUDIT_KEY.to_vec()),
    )
    .await?;
    assert_eq!(demo_module.probe_count(), 0);
    assert_eq!(demo_module.resource_count(), 0);
    assert_eq!(demo_module.worker_count(), 0);

    let distributed = wire_distributed(&deps)?;
    let event_module = wire_event_transport_with_admission(
        &pg,
        distributed,
        subscribers,
        cfg,
        worker,
        MacKey::from_bytes(AUDIT_KEY.to_vec()),
        (
            admission_control,
            relay_admission,
            consumer_admission,
            write_admission,
        ),
        Some(admission_epoch),
    )
    .await?;
    assert_eq!(
        rmq.broker_queue_total_depth(settings_v1::TOPIC).await?,
        0,
        "consumer topology must exist before the paused worker is spawned"
    );
    let resource_names = event_module
        .resources()
        .map(|resource| diport::ManagedResource::name(resource.as_ref()))
        .collect::<Vec<_>>();
    assert_eq!(
        resource_names,
        [
            "identity-pub",
            "identity-sub",
            "settings-pub",
            "settings-sub"
        ],
        "durable event infra must leave through DomainModuleResult::resources"
    );
    let generated_subscription_count = generated::event::EVENTS
        .iter()
        .map(|event| event.subscriptions().len())
        .sum::<usize>();
    let expected_worker_count = generated_subscription_count + 7;
    assert_eq!(
        event_module.worker_count(),
        expected_worker_count,
        "identity/settings relays + generated consumers + outbox/inbox samplers + outbox/inbox sweepers + DR admission owner"
    );
    let probe_names: Vec<&str> = event_module
        .probes()
        .map(|(name, _)| name.as_str())
        .collect();
    assert_eq!(
        probe_names,
        [
            "outbox_relay_identity",
            "outbox_relay_settings",
            "outbox_sampler",
            "outbox_sweeper",
            "inbox_sampler",
            "event_consumer:settings_config-version-changed__settings__settings_config-version-changed",
            "event_consumer:identity_session-created__audit__audit_session-created",
            "event_consumer:identity_role-assigned__audit__audit_role-assigned",
            "event_consumer:identity_role-revoked__audit__audit_role-revoked",
            "event_consumer:identity_policy-updated__audit__audit_policy-updated",
            "event_consumer:identity_security-event__audit__audit_security-event",
            "inbox_sweeper",
            "dr_admission",
        ],
        "durable event probes must preserve generated topology order"
    );

    // ── 步骤 7：统一注册 ShutdownStack（resources 先注册，workers 后注册）────────

    let mut stack = bootstrap::shutdown::ShutdownStack::new(CancellationToken::new());
    let mut resources = Vec::new();
    let mut workers = Vec::new();
    for output in event_module.into_outputs() {
        match output {
            bootstrap::DomainLifecycleOutput::Probe(_, _) => {}
            bootstrap::DomainLifecycleOutput::Resource(resource) => resources.push(resource),
            bootstrap::DomainLifecycleOutput::Worker(worker) => workers.push(worker),
        }
    }
    for resource in resources {
        stack.register_detached(resource);
    }
    for worker in workers {
        match worker {
            bootstrap::WorkerSpec::PhaseOne(make) => stack.register_with_token(make.into_factory()),
            bootstrap::WorkerSpec::Deferred(make) => {
                stack.register_deferred_with_token(make.into_factory())
            }
        }
    }
    assert_eq!(
        stack.registered_names().collect::<Vec<_>>(),
        [
            "identity-pub",
            "identity-sub",
            "settings-pub",
            "settings-sub",
            "outbox-relay-identity",
            "outbox-relay-settings",
            "outbox-sampler",
            "outbox-sweeper",
            "inbox-backlog-sampler",
            "event-consumer:settings:settings.config-version-changed",
            "event-consumer:audit:identity.session-created",
            "event-consumer:audit:identity.role-assigned",
            "event-consumer:audit:identity.role-revoked",
            "event-consumer:audit:identity.policy-updated",
            "event-consumer:audit:identity.security-event",
            "inbox-sweeper",
            "runtime-dr-admission-owner",
        ],
        "resources must register before workers so LIFO drains workers first"
    );

    // ── 步骤 8a：post-restore required epoch 在任何 durable work admission 前先 pause/drain ─────

    // Drive the generated BusinessWrite + BusinessTransaction route and all durable workers
    // through the same process gate. Apply uses the function-only eleven-argument executor lane.
    let l2_operator = connect_l2_dr_operator(&assertion_pool, pgfix.owner_params()).await?;
    let recovery_epoch = uuid::Uuid::new_v4();
    let recovery_fixture_event = format!("runtime-dr-recovery-{}", uuid::Uuid::new_v4());
    let recovery_plan =
        broker_ahead_recovery_plan(recovery_epoch, tenant, &recovery_fixture_event)?;
    let declared_instances = serde_json::json!([{
        "assemblyIdentity": "runtime",
        "runtimePlanFingerprint": "sha256:runtime-integration-plan",
        "instanceId": uuid::Uuid::from_u128(0x2009).to_string(),
    }]);
    l2_operator
        .request_l2_dr_admission_pause(admission_epoch, &recovery_plan, &declared_instances, true)
        .await?;
    wait_admission_phase(&assertion_pool, "drained").await?;

    let paused_http_key = format!("app.runtime-dr-http-{}", uuid::Uuid::new_v4());
    let paused_http_before = settings_http_write_counts(&assertion_pool, &paused_http_key).await?;
    assert_eq!(
        publish_settings_over_generated_http(&settings_router, &paused_http_key, "paused").await?,
        StatusCode::SERVICE_UNAVAILABLE,
        "the generated write route must fail closed while the process is drained"
    );
    assert_eq!(
        settings_http_write_counts(&assertion_pool, &paused_http_key).await?,
        paused_http_before,
        "HTTP 503 must leave config state and the durable outbox unchanged"
    );

    // Fixture-only staging isolates the relay/consumer joins. The preceding request proves that
    // the production HTTP path cannot create this row while Writes is closed.
    publisher_settings_service
        .publish_config(
            settings::config_publish_receipt_for_test(),
            tenant,
            settings_actor.clone(),
            SettingsConfigPublishRequest {
                key: settings_key.to_string(),
                value: "relay-only".to_string(),
            },
        )
        .await?;
    let staged_event_id =
        latest_outbox_event_id(&assertion_pool, "settings", settings_v1::TOPIC).await?;
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    wait_outbox_status(&assertion_pool, &staged_event_id, "pending").await?;
    assert_eq!(
        inbox_done_count(&assertion_pool, &staged_event_id, &settings_consumer_group).await?,
        0,
        "a drained process must not consume a newly persisted event",
    );

    apply_fenced_recovery(&l2_operator, recovery_plan, admission_epoch).await?;
    wait_admission_phase(&assertion_pool, "applied_paused").await?;
    l2_operator
        .request_l2_dr_admission_resume(admission_epoch, tenant, "relay")
        .await?;
    wait_admission_phase(&assertion_pool, "relay_running").await?;
    wait_outbox_status(&assertion_pool, &staged_event_id, "published").await?;
    assert_eq!(
        inbox_done_count(&assertion_pool, &staged_event_id, &settings_consumer_group).await?,
        0,
        "relay-only recovery must leave the consumer lane closed",
    );
    l2_operator
        .request_l2_dr_admission_resume(admission_epoch, tenant, "consumer")
        .await?;
    wait_admission_phase(&assertion_pool, "consumer_running").await?;
    wait_inbox_done(&assertion_pool, &staged_event_id, &settings_consumer_group).await?;
    l2_operator
        .request_l2_dr_admission_resume(admission_epoch, tenant, "writes")
        .await?;
    wait_admission_phase(&assertion_pool, "running").await?;

    let resumed_http_before = settings_http_write_counts(&assertion_pool, &paused_http_key).await?;
    assert_eq!(
        publish_settings_over_generated_http(&settings_router, &paused_http_key, "running").await?,
        StatusCode::CREATED,
        "the same generated route must reopen only after the Writes receipt"
    );
    let resumed_http_after = settings_http_write_counts(&assertion_pool, &paused_http_key).await?;
    assert_eq!(resumed_http_after.0, resumed_http_before.0 + 1);
    assert_eq!(resumed_http_after.1, resumed_http_before.1 + 1);
    let resumed_http_event_id =
        latest_outbox_event_id(&assertion_pool, "settings", settings_v1::TOPIC).await?;
    wait_inbox_done(
        &assertion_pool,
        &resumed_http_event_id,
        &settings_consumer_group,
    )
    .await?;
    assert_eq!(
        inbox_done_count(
            &assertion_pool,
            &resumed_http_event_id,
            &settings_consumer_group,
        )
        .await?,
        1,
        "the resumed HTTP outbox fact must settle through ConsumerTx exactly once"
    );

    publisher_settings_service
        .publish_config(
            settings::config_publish_receipt_for_test(),
            tenant,
            settings_actor,
            SettingsConfigPublishRequest {
                key: settings_key.to_string(),
                value: "enabled".to_string(),
            },
        )
        .await?;
    let settings_event_id =
        latest_outbox_event_id(&assertion_pool, "settings", settings_v1::TOPIC).await?;
    wait_inbox_done(
        &assertion_pool,
        &settings_event_id,
        &settings_consumer_group,
    )
    .await?;
    assert_eq!(
        subscriber_settings_service
            .config_query_service()
            .get_config(tenant, settings_key)
            .await?
            .as_ref()
            .map(|entry| entry.value()),
        Some("enabled"),
        "settings ConsumerTx must refresh the subscriber service cache from the old value"
    );

    // ── 步骤 8b：identity.policy-updated active event 走生产 relay + audit ConsumerTx ─────────────

    // Durable typed principal policy → production authorizer join. Resource facts are seeded only
    // through the External bootstrap function and are covered by PostgreSQL integration tests.
    let typed_scope = PolicyRouteScope::parse(
        "identity.account-status-get",
        "identity:account-security:read",
    )?;
    let typed_policy = Policy::build(
        "policy-typed-resource-runtime-e2e",
        tenant,
        typed_scope,
        SystemTime::UNIX_EPOCH + Duration::from_secs(NOW_SECS),
        None,
        vec![PolicyRule::with_obligations(
            PolicyCondition::new(
                AttributeKey::parse(POLICY_ATTR_PRINCIPAL_KIND)?,
                Operator::try_from(OperatorInput::Membership {
                    predicate: MembershipPredicate::In,
                    value_type: PolicyValueType::String,
                    values: vec![PolicyScalarInput::String("user".to_string())],
                })?,
            ),
            PolicyEffect::Allow,
            PolicyObligations::empty(),
        )],
    )?;
    let typed_event_id = "policy-typed-resource-runtime-e2e-created-v1";
    policy_lifecycle
        .create_and_emit(
            ProducerMarker::for_test(POLICIES_CREATE_PRODUCER).into_receipt(),
            TenantRepoScope::for_test(tenant),
            typed_policy,
            policy_updated_event(
                tenant,
                "policy-typed-resource-runtime-e2e",
                "identity.account-status-get",
                "identity:account-security:read",
                typed_event_id,
            )
            .await?,
        )
        .await?;
    let typed_decision = route_authorizer
        .authorize(RouteAuthorizationRequest {
            contract_id: "identity.account-status-get",
            permission: vocab::RoutePermissionId::IdentityAccountSecurityRead,
            tenant_id: Some(tenant),
            principal_kind: rss_request_context::PrincipalKind::User,
            principal_id: CANON_USER.to_string(),
            resource: Some(RouteResource::new(CANON_USER).context("canonical resource")?),
            federated_permissions: None,
        })
        .await;
    assert!(
        typed_decision.is_allow(),
        "typed principal attributes must drive the production route authorizer"
    );
    let typed_authorization = typed_decision
        .durable_policy()
        .context("production route authorizer must retain durable policy lineage")?;
    assert_eq!(typed_authorization.policies().len(), 1);
    assert_eq!(
        typed_authorization.policies()[0].policy_id(),
        "policy-typed-resource-runtime-e2e"
    );
    assert_eq!(typed_authorization.policies()[0].version().get(), 1);
    assert_eq!(
        typed_authorization.evaluated_at(),
        SystemTime::UNIX_EPOCH + Duration::from_secs(NOW_SECS)
    );

    let policy_id = "policy-runtime-e2e";
    let policy_contract_id = "identity.policies-get";
    let policy_permission = "identity:policy:read";
    let policy = Policy::build(
        policy_id,
        tenant,
        PolicyRouteScope::parse(policy_contract_id, policy_permission)?,
        SystemTime::UNIX_EPOCH + Duration::from_secs(NOW_SECS),
        None,
        vec![PolicyRule::with_obligations(
            PolicyCondition::new(
                AttributeKey::parse(POLICY_ATTR_PRINCIPAL_KIND)?,
                Operator::try_from(OperatorInput::Equality {
                    predicate: EqualityPredicate::Eq,
                    operand: ScalarOperandInput::Literal(TypedPolicyValueInput::new(
                        PolicyValueType::String,
                        PolicyScalarInput::String("admin".to_string()),
                    )),
                })?,
            ),
            PolicyEffect::Allow,
            PolicyObligations::empty(),
        )],
    )?;
    let policy_event_id = "policy-runtime-e2e-created-v1";
    let policy_event = policy_updated_event(
        tenant,
        policy_id,
        policy_contract_id,
        policy_permission,
        policy_event_id,
    )
    .await?;
    policy_lifecycle
        .create_and_emit(
            ProducerMarker::for_test(POLICIES_CREATE_PRODUCER).into_receipt(),
            TenantRepoScope::for_test(tenant),
            policy,
            policy_event,
        )
        .await?;
    let policy_outbox_event_id =
        latest_outbox_event_id(&assertion_pool, "identity", policy_updated::TOPIC).await?;
    assert_eq!(
        policy_outbox_event_id, policy_event_id,
        "policy lifecycle must write the generated identity.policy-updated outbox event"
    );
    wait_inbox_done(
        &assertion_pool,
        &policy_outbox_event_id,
        &policy_consumer_group,
    )
    .await?;
    let policy_resource_id = format!(
        "tenant/{tenant}/policy/{policy_id}/contract/{policy_contract_id}/permission/{policy_permission}"
    );
    testkit::await_try(Duration::from_secs(20), async || {
        Ok::<Option<()>, anyhow::Error>(
            (audit_policy_count(&assertion_pool, tenant, &policy_resource_id).await? == 1)
                .then_some(()),
        )
    })
    .await
    .with_context(|| format!("等待 audit 收到 policy-updated 事件失败（policy_id={policy_id}）"))?;

    // ── 步骤 8：生产侧登录（PgAuthGrantLifecycle co-tx：session 行 + outbox(pending) 同事务落库）──

    // 第二个 LoginService 实例（同种子凭据），用于直接调用 .login()。
    let login_svc = LoginService::with_seed_credential(
        |accounts| {
            identity::seed_auth_grant_services(
                id.auth_grant_provider(
                    Box::new(FixedClock::at_unix_secs(NOW_SECS)),
                    postgres::identity_pseudonym_keys_for_test(),
                ),
                accounts,
                || Box::new(FixedClock::at_unix_secs(NOW_SECS)),
                Duration::from_secs(TTL_SECS),
            )
        },
        Box::new(FixedClock::at_unix_secs(NOW_SECS)),
        Duration::from_secs(TTL_SECS),
        LOGIN_USERNAME,
        ids::UserId::parse(CANON_USER)?,
        PASSWORD,
        tenant,
    )?;
    let response = login_svc
        .login(
            ProducerMarker::for_test(LOGIN_PRODUCER).into_receipt(),
            tenant,
            IdentityLoginRequest {
                username: LOGIN_USERNAME.to_string(),
                password: PASSWORD.to_string(),
            },
        )
        .await?;
    let session_id = response.data.session_id.clone();

    // ── 步骤 9：测试专用 PostgreSQL 只读观察（不 claim，不干扰后台 relay）────────────────────

    // bounded 轮询（最多 50 次 × 100ms = 5s），以 tenant/domain/topic 限定后按
    // payload.sessionId 关联本轮 entry；published 行仍保留，因此无需抢在 relay 前读取。
    let (captured_event_id, captured_payload) =
        testkit::await_try(Duration::from_secs(5), async || {
            outbox_session_event(
                &assertion_pool,
                tenant,
                "identity",
                SESSION_CREATED_TOPIC,
                &session_id,
            )
            .await
        })
        .await
        .with_context(|| {
            format!("outbox 缺本轮 session-created entry（session_id={session_id}）")
        })?;

    // ── 步骤 10：断言 A（至少一次）────────────────────────────────────────────────────────────

    // relay（后台 OS 线程）会在下次 2s 轮询时拾起 pending entry → AMQP publish → consumer → PG inbox
    // Fresh → audit append。20s timeout 覆盖 2s relay 间隔 + AMQP 投递 + consumer 处理延迟。
    testkit::await_try(Duration::from_secs(20), async || {
        Ok::<Option<()>, anyhow::Error>(
            (audit_login_count(&assertion_pool, tenant, &captured_event_id).await? >= 1)
                .then_some(()),
        )
    })
    .await
    .context("等待 audit 收到 session-created 事件失败（至少一次断言 A）")?;

    assert_eq!(
        audit_login_count(&assertion_pool, tenant, &captured_event_id).await?,
        1,
        "断言 A：login → outbox → relay → AMQP → consumer → audit，仅 append 一次"
    );
    assert_eq!(
        inbox_done_count(&assertion_pool, &captured_event_id, &consumer_group).await?,
        1,
        "断言 A：original event 必须在 PG inbox_receipts 标记 done"
    );

    // ── 步骤 11：断言 B（runtime T2 cross-provider join：duplicate → PG inbox/ConsumerTx 收敛）─

    // integration-only barrier 在真实 basic_publish frame write 完成后、poll confirm 前关闭该 snapshot 的
    // connection，仅用于构造 duplicate：首投必须失败以证明 after-send barrier 生效，但 Ambiguous/
    // retryable/generation owner 属 AMQP catalog，本 E2E 不检查错误 kind。随后等待 bounded publish
    // readiness 并以原 ID 重试。tracer 使用不同 event/session ID：单 queue 单 consumer FIFO 下 tracer
    // 被 audit，正向证明前面的 same-ID duplicate 已被消费并 Ack；原 session audit count 仍为 1 才证明
    // ConsumerTx 未重复业务写。
    let redeliver_endpoint = amqp_endpoint(vhost_url)?;
    let redeliver_ca = amqp::AmqpPrivateCa::from_pem(rmq.ca_pem().as_bytes().to_vec())?;
    let redeliver_deps = amqp::AmqpRuntimeDeps::connect_with_private_ca(
        &amqp::AmqpPublisherEndpoint::new(redeliver_endpoint.clone()),
        &amqp::AmqpSubscriberEndpoint::new(redeliver_endpoint),
        redeliver_ca,
        "e2e-redeliver",
        TEST_PUBLISH_TIMEOUT,
    )
    .await?;
    let pubr = redeliver_deps.publisher_for_integration_test();
    pubr.inject_post_send_connection_close_once();
    if pubr
        .publish(
            PublishRequest::new(
                Topic::new(SESSION_CREATED_TOPIC),
                MessageId::new(&captured_event_id),
                captured_payload.clone(),
            )
            .with_metadata(signed_session_metadata(
                &redeliver_tenant_authority,
                &captured_event_id,
            )?),
        )
        .await
        .is_ok()
    {
        return Err(anyhow::anyhow!(
            "injected post-send connection close did not interrupt the first publish"
        ));
    }

    assert!(
        pubr.wait_until_publish_ready_for_test().await,
        "AMQP publisher transport 未在 bounded recovery budget 内恢复 publish readiness"
    );

    pubr.publish(
        PublishRequest::new(
            Topic::new(SESSION_CREATED_TOPIC),
            MessageId::new(&captured_event_id),
            captured_payload.clone(),
        )
        .with_metadata(signed_session_metadata(
            &redeliver_tenant_authority,
            &captured_event_id,
        )?),
    )
    .await?;

    let tracer_id = uuid::Uuid::new_v4().to_string();
    let mut tracer_payload: IdentitySessionCreatedPayload =
        serde_json::from_slice(&captured_payload)?;
    let tracer_session_id = uuid::Uuid::new_v4();
    tracer_payload.session_id.clone_from(&tracer_session_id);
    pubr.publish(
        PublishRequest::new(
            Topic::new(SESSION_CREATED_TOPIC),
            MessageId::new(&tracer_id),
            serde_json::to_vec(&tracer_payload)?,
        )
        .with_metadata(signed_session_metadata(
            &redeliver_tenant_authority,
            &tracer_id,
        )?),
    )
    .await?;

    // 正向见证：tracer 新 event 被 audit，证明排在它之前的 same-ID duplicate 已被消费并 settle。
    testkit::await_try(Duration::from_secs(20), async || {
        Ok::<Option<()>, anyhow::Error>(
            (audit_login_count(&assertion_pool, tenant, &tracer_id).await? == 1).then_some(()),
        )
    })
    .await
    .context("等待重投流（duplicate/tracer）被消费失败——断言 B 无法正向见证")?;

    // 去重失效会让 duplicate 对 original session 再 append。再观察 2s：升到 2 即 fail-fast。
    let leaked_dup = testkit::await_try(Duration::from_secs(2), async || {
        Ok::<Option<()>, anyhow::Error>(
            (audit_login_count(&assertion_pool, tenant, &captured_event_id).await? >= 2)
                .then_some(()),
        )
    })
    .await;
    match leaked_dup {
        Ok(()) => anyhow::bail!(
            "断言 B 失败：duplicate 重复写入 original session audit，PG inbox 幂等去重未生效"
        ),
        Err(error)
            if matches!(
                error.downcast_ref::<testkit::TestkitError>(),
                Some(testkit::TestkitError::WaitTimeout { .. })
            ) => {}
        Err(error) => {
            return Err(error).context("观察 duplicate 是否重复写入 original session audit 失败");
        }
    }
    assert_eq!(
        audit_login_count(&assertion_pool, tenant, &captured_event_id).await?,
        1,
        "断言 B：close/same-ID retry 构造的 duplicate 经 PG inbox/ConsumerTx 后不得重复 original session 业务 mutation"
    );
    assert_eq!(
        audit_login_count(&assertion_pool, tenant, &tracer_id).await?,
        1,
        "断言 B：独立 tracer 必须产生一次业务 mutation"
    );
    assert_eq!(
        inbox_done_count(&assertion_pool, &captured_event_id, &consumer_group).await?,
        1,
        "断言 B：duplicate 不得新增 original 的 inbox_receipts done 行"
    );
    assert_eq!(
        inbox_done_count(&assertion_pool, &tracer_id, &consumer_group).await?,
        1,
        "断言 B：tracer 新 event 必须在 PG inbox_receipts 标记 done"
    );

    // 本 E2E 只断言 duplicate 经真实 PG inbox/ConsumerTx 后的 audit/receipt 收敛；close/same-ID
    // retry 仅为构造 duplicate 的 setup。Ambiguous/retryable/generation 归 AMQP catalog；transport
    // 两次投递由 AMQP 真实 integration 覆盖；Duplicate→Ack 由 eventexec consumer_tx 的直接 acker
    // 测试覆盖，避免用预填常量伪造不可观测结论。

    for resource in redeliver_deps.runtime_resources().into_iter().rev() {
        resource.shutdown().await?;
    }

    // ── 步骤 12：关停（LIFO：workers 先 drain，infra_guards 后断连）────────────────────────────

    let failures = stack.shutdown_within(Duration::from_secs(60)).await;
    assert!(failures.is_empty(), "shutdown 存在失败项: {failures:?}");
    l2_operator.shutdown().await?;

    // fixture guard drop：停两个容器（pg / rmq）。
    drop(id);
    drop(assertion_pool);
    drop(pg);
    drop(pgfix);
    drop(rmq);

    Ok(())
}
