use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, UNIX_EPOCH};

use anyhow::Context as _;
use axum::http::{Method, StatusCode};
use axum::routing::post;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use diport::ManagedResource as _;
#[cfg(feature = "integration")]
use diport::SecretResolver as _;
use httpserve::{TestPrimaryRoute, TestRoutePermission, TestRouteResourceScope, UnfinalizedRoutes};
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};

use super::*;

const BASE_CONFIG: &str = include_str!("../../settingsonly.example.toml");
const FEDERATED_ISSUER: &str = "https://issuer.example.com";
const FEDERATED_AUDIENCE: &str = "rss-settingsonly";
const FEDERATED_KID: &str = "settingsonly-production-input-contract";
const TENANT_A: &str = "00000000-0000-4000-8000-000000000147";
const TENANT_B: &str = "00000000-0000-4000-8000-000000000148";
const PUBLISH_PERMISSION: &str = "settings.config-publish";
const DELETE_PERMISSION: &str = "settings.config-delete";
const PUBLISH_PATH: &str = "/settings-production-input-publish";

static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct FixtureRoot(PathBuf);

impl FixtureRoot {
    fn create() -> anyhow::Result<Self> {
        let sequence = FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "rss-settingsonly-production-inputs-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&path).context("create SettingsOnly production-input fixture")?;
        Ok(Self(path))
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for FixtureRoot {
    fn drop(&mut self) {
        let _result = std::fs::remove_dir_all(&self.0);
    }
}

fn oidc_config(jwks_path: &Path) -> String {
    BASE_CONFIG.replace("/run/rss/federated.jwks.json", &jwks_path.to_string_lossy())
}

fn signing_material() -> anyhow::Result<(SigningKey, String)> {
    let key = SigningKey::from_slice(&[0x31; 32])
        .map_err(|_| anyhow::anyhow!("build production-input ES256 key"))?;
    let point = key.verifying_key().to_encoded_point(false);
    let x = point.x().context("production-input ES256 x coordinate")?;
    let y = point.y().context("production-input ES256 y coordinate")?;
    let jwks = serde_json::json!({"keys":[{
        "kty":"EC", "crv":"P-256", "kid":FEDERATED_KID, "alg":"ES256",
        "use":"sig", "x":URL_SAFE_NO_PAD.encode(x), "y":URL_SAFE_NO_PAD.encode(y)
    }]})
    .to_string();
    Ok((key, jwks))
}

fn issued_at() -> anyhow::Result<u64> {
    Ok(diport::Clock::now(&crate::SystemClock)
        .duration_since(UNIX_EPOCH)
        .context("system clock before Unix epoch")?
        .as_secs())
}

fn mint_federated_token(
    key: &SigningKey,
    permission: &str,
    lifetime: Duration,
) -> anyhow::Result<String> {
    let issued_at = issued_at()?;
    let expires_at = issued_at
        .checked_add(lifetime.as_secs())
        .context("production-input JWT expiry overflow")?;
    let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&serde_json::json!({
        "alg":"ES256", "typ":"at+jwt", "kid":FEDERATED_KID
    }))?);
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&serde_json::json!({
        "sub":"settingsonly-production-input-contract",
        "tenant_id":TENANT_A,
        "kind":"admin",
        "iat":issued_at,
        "exp":expires_at,
        "iss":FEDERATED_ISSUER,
        "aud":FEDERATED_AUDIENCE,
        "token_use":"access",
        "permissions":[permission]
    }))?);
    let input = format!("{header}.{payload}");
    let signature: Signature = key.sign(input.as_bytes());
    Ok(format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    ))
}

fn production_federated_provider(config_document: &str) -> anyhow::Result<FederatedProvider> {
    let config = crate::config::federated_production_config_from_document(config_document)?;
    let mut roles = crate::plan::SettingsOnlyPlan::bundled()?.provider_build()?;
    build_federated_access_provider(config, roles.listener_pdp()?)
}

fn publish_router(
    provider: Arc<oidc::OidcProvider<diport::FederatedAccessProfile>>,
    handler_calls: Arc<AtomicUsize>,
) -> anyhow::Result<axum::Router> {
    let routes: UnfinalizedRoutes =
        httpserve::routes::unfinalized_for_test::<httpserve::Primary>(|router| {
            router.mount_primary_raw_for_test(
                TestPrimaryRoute::permission(
                    Method::POST,
                    PUBLISH_PATH,
                    generated::http::settings_v1::CONTRACT_ID,
                    TestRoutePermission {
                        permission: vocab::RoutePermissionId::SettingsConfigPublish,
                        scope: TestRouteResourceScope::None,
                    },
                ),
                post(
                    move |axum::Extension(subject): axum::Extension<
                        httpserve::AuthorizedSubject,
                    >| {
                        let handler_calls = Arc::clone(&handler_calls);
                        async move {
                            handler_calls.fetch_add(1, Ordering::AcqRel);
                            let context_tenant = runctx::try_current()
                                .map(|ctx| ctx.tenant().to_string())
                                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                            Ok::<_, StatusCode>(axum::Json(serde_json::json!({
                                "contextTenant": context_tenant,
                                "subjectTenant": subject.tenant_id().to_string()
                            })))
                        }
                    },
                ),
            )
        })?;
    let plan = primitives::AuthPlan::new(
        primitives::ListenerKind::Primary,
        primitives::AuthScheme::FederatedAccessToken,
    )?;
    let routes = httpserve::finalize_primary_auth(
        routes,
        plan,
        Arc::new(crate::listeners::FederatedPermissionAuthorizer),
    )?;
    Ok(crate::auth_bridge::apply(
        routes,
        crate::auth_bridge::FederatedVerifier::production(provider),
    )
    .into_router_for_test())
}

async fn call_publish(
    provider: Arc<oidc::OidcProvider<diport::FederatedAccessProfile>>,
    token: &str,
    conflicting_tenant: Option<&str>,
    handler_calls: Arc<AtomicUsize>,
) -> Result<testkit::ContractResponse, testkit::TestkitError> {
    let mut request = testkit::ContractRequest::post(PUBLISH_PATH).bearer(token);
    if let Some(tenant) = conflicting_tenant {
        request = request.header(diport::SERVICE_TOKEN_TENANT_HEADER, tenant);
    }
    let router = publish_router(provider, handler_calls)
        .map_err(|error| testkit::TestkitError::Build(error.to_string()))?;
    testkit::call(router, request).await
}

#[tokio::test]
async fn settingsonly_federated_production_input_auth_contract() -> anyhow::Result<()> {
    let fixture = FixtureRoot::create()?;
    let jwks_path = fixture.join("federated.jwks.json");
    let (key, jwks) = signing_material()?;
    std::fs::write(&jwks_path, jwks).context("write production-input JWKS")?;
    let provider = production_federated_provider(&oidc_config(&jwks_path))?;
    let managed_resource = provider.managed_resource();
    let provider = provider.provider();

    let valid = mint_federated_token(
        &key,
        PUBLISH_PERMISSION,
        diport::TokenProfile::FederatedAccess
            .policy()
            .maximum_lifetime(),
    )?;
    let valid_calls = Arc::new(AtomicUsize::new(0));
    let valid_response = call_publish(
        Arc::clone(&provider),
        &valid,
        Some(TENANT_B),
        Arc::clone(&valid_calls),
    )
    .await?;
    valid_response.ensure_status(StatusCode::OK)?;
    let body: serde_json::Value = valid_response.json()?;
    assert_eq!(body["contextTenant"], TENANT_A);
    assert_eq!(body["subjectTenant"], TENANT_A);
    assert_eq!(valid_calls.load(Ordering::Acquire), 1);

    let delete = mint_federated_token(
        &key,
        DELETE_PERMISSION,
        diport::TokenProfile::FederatedAccess
            .policy()
            .maximum_lifetime(),
    )?;
    let denied_calls = Arc::new(AtomicUsize::new(0));
    call_publish(
        Arc::clone(&provider),
        &delete,
        None,
        Arc::clone(&denied_calls),
    )
    .await?
    .ensure_status(StatusCode::FORBIDDEN)?;
    assert_eq!(denied_calls.load(Ordering::Acquire), 0);

    let oversized = mint_federated_token(&key, PUBLISH_PERMISSION, Duration::from_secs(7_200))?;
    let oversized_calls = Arc::new(AtomicUsize::new(0));
    call_publish(provider, &oversized, None, Arc::clone(&oversized_calls))
        .await?
        .ensure_status(StatusCode::UNAUTHORIZED)?;
    assert_eq!(oversized_calls.load(Ordering::Acquire), 0);

    managed_resource.shutdown().await?;
    Ok(())
}

#[cfg(feature = "integration")]
const VAULT_WORKLOAD_TOKEN: &str = "settingsonly-production-inputs-1933";
#[cfg(feature = "integration")]
const VAULT_POLICY: &str = "settingsonly-production-inputs-1933";
#[cfg(feature = "integration")]
const READINESS_VALUE: &str = "settingsonly-vault-readiness-1933";

#[cfg(feature = "integration")]
fn vault_config(endpoint: &str, ca_path: &Path) -> String {
    BASE_CONFIG
        .replace("https://vault.example.com:8200", endpoint)
        .replace("/run/rss/vault-ca.pem", &ca_path.to_string_lossy())
        .replace(
            "transitMount = \"transit\"",
            "transitMount = \"settings-transit\"",
        )
        .replace("mount = \"secret\"", "mount = \"settings-secret\"")
        .replace(
            "kvPathPrefix = \"tenants/settings\"",
            "kvPathPrefix = \"tenants/settings-t2\"",
        )
}

#[cfg(feature = "integration")]
fn vault_secret_bundle() -> String {
    serde_json::json!({
        "pgWriterPassword": "settingsonly-pg-writer-1933",
        "pgReaderPassword": "settingsonly-pg-reader-1933",
        "pgDlxArchiverPassword": "settingsonly-pg-dlx-archiver-1933",
        "pgDlxVerifierPassword": "settingsonly-pg-dlx-verifier-1933",
        "pgDlxPurgerPassword": "settingsonly-pg-dlx-purger-1933",
        "pgProjectionWorkerPassword": "settingsonly-pg-projection-worker-1933",
        "vaultToken": VAULT_WORKLOAD_TOKEN,
        "settingsAmqpPublisherUrl": "amqps://publisher:secret@rabbitmq.example.com/settings",
        "settingsAmqpSubscriberUrl": "amqps://subscriber:secret@rabbitmq.example.com/settings",
        "redisUrl": "rediss://:secret@redis.example.com:6379/0",
        "tenantAuthorityKey": "settingsonly-tenant-authority-key-1933",
        "dlxHotVaultToken": "settingsonly-dlx-hot-token-1933",
        "dlxArchiveVaultToken": "settingsonly-dlx-archive-token-1933",
        "s3AccessKeyId": "settingsonly-s3-access-1933",
        "s3SecretAccessKey": "settingsonly-s3-secret-1933"
    })
    .to_string()
}

#[cfg(feature = "integration")]
fn vault_client(ca_pem: &str) -> anyhow::Result<reqwest::Client> {
    let certificate = reqwest::Certificate::from_pem(ca_pem.as_bytes())
        .context("parse test Vault generated CA")?;
    reqwest::Client::builder()
        .use_rustls_tls()
        .no_proxy()
        .tls_built_in_root_certs(false)
        .https_only(true)
        .add_root_certificate(certificate)
        .build()
        .context("build test Vault initialization client")
}

#[cfg(feature = "integration")]
async fn vault_write(
    client: &reqwest::Client,
    endpoint: &str,
    token: &str,
    path: &str,
    body: serde_json::Value,
) -> anyhow::Result<()> {
    let response = client
        .post(format!("{endpoint}/v1/{path}"))
        .header("X-Vault-Token", token)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(serde_json::to_vec(&body).context("serialize test Vault request")?)
        .send()
        .await
        .with_context(|| format!("send test Vault write to {path}"))?;
    anyhow::ensure!(
        response.status().is_success(),
        "test Vault write to {path} returned {}",
        response.status()
    );
    Ok(())
}

#[cfg(feature = "integration")]
async fn vault_read_status(
    client: &reqwest::Client,
    endpoint: &str,
    token: &str,
    path: &str,
) -> anyhow::Result<StatusCode> {
    client
        .get(format!("{endpoint}/v1/{path}"))
        .header("X-Vault-Token", token)
        .send()
        .await
        .with_context(|| format!("send test Vault read to {path}"))
        .map(|response| response.status())
}

#[cfg(feature = "integration")]
async fn provision_vault(
    client: &reqwest::Client,
    root_token: &str,
    view: &crate::config::VaultProvisioningView<'_>,
) -> anyhow::Result<()> {
    vault_write(
        client,
        view.addr,
        root_token,
        &format!("sys/mounts/{}", view.transit_mount),
        serde_json::json!({"type":"transit"}),
    )
    .await?;
    let mut mounted = std::collections::BTreeSet::new();
    for binding in &view.tenant_store_allowlist {
        if mounted.insert(binding.mount) {
            vault_write(
                client,
                view.addr,
                root_token,
                &format!("sys/mounts/{}", binding.mount),
                serde_json::json!({"type":"kv", "options":{"version":"2"}}),
            )
            .await?;
        }
    }
    vault_write(
        client,
        view.addr,
        root_token,
        &format!("{}/keys/{}", view.transit_mount, view.settings_key_name),
        serde_json::json!({"type":"aes256-gcm96", "derived":true}),
    )
    .await?;
    for binding in &view.tenant_store_allowlist {
        vault_write(
            client,
            view.addr,
            root_token,
            &format!(
                "{}/data/{}/{}",
                binding.mount,
                binding.kv_path_prefix,
                vault::SECRET_RESOLVER_READINESS_KEY
            ),
            serde_json::json!({"data":{"value":READINESS_VALUE}}),
        )
        .await?;
    }

    let mut policy = format!(
        "path \"{}/encrypt/{}\" {{ capabilities = [\"update\"] }}\npath \"{}/decrypt/{}\" {{ capabilities = [\"update\"] }}\n",
        view.transit_mount, view.settings_key_name, view.transit_mount, view.settings_key_name
    );
    for binding in &view.tenant_store_allowlist {
        use std::fmt::Write as _;
        writeln!(
            policy,
            "path \"{}/data/{}/*\" {{ capabilities = [\"read\"] }}",
            binding.mount, binding.kv_path_prefix
        )?;
    }
    vault_write(
        client,
        view.addr,
        root_token,
        &format!("sys/policies/acl/{VAULT_POLICY}"),
        serde_json::json!({"policy":policy}),
    )
    .await?;
    vault_write(
        client,
        view.addr,
        root_token,
        "auth/token/create-orphan",
        serde_json::json!({
            "id":view.token,
            "policies":[VAULT_POLICY],
            "ttl":"2h",
            "renewable":false,
            "no_default_policy":true
        }),
    )
    .await?;
    vault_write(
        client,
        view.addr,
        root_token,
        "auth/token/revoke-self",
        serde_json::json!({}),
    )
    .await
}

#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
async fn settingsonly_vault_production_inputs_close_readiness_and_aad_contract()
-> anyhow::Result<()> {
    let fixture_root = FixtureRoot::create()?;
    let vault_fixture = testkit::vault_tls().await?;
    let ca_path = fixture_root.join("vault-ca.pem");
    std::fs::write(&ca_path, vault_fixture.ca_pem()).context("write test Vault CA")?;
    let config_document = vault_config(vault_fixture.endpoint_url(), &ca_path);
    let inputs = crate::config::vault_production_inputs_from_documents(
        &config_document,
        &vault_secret_bundle(),
    )?;
    let view = inputs.provisioning_view();
    let client = vault_client(vault_fixture.ca_pem())?;

    provision_vault(&client, vault_fixture.root_token(), &view).await?;
    assert_eq!(
        vault_read_status(
            &client,
            view.addr,
            vault_fixture.root_token(),
            "auth/token/lookup-self",
        )
        .await?,
        StatusCode::FORBIDDEN,
        "one-time root token must be revoked before production construction"
    );
    let binding = view
        .tenant_store_allowlist
        .first()
        .context("validated Vault input omitted store binding")?;
    assert_eq!(
        vault_read_status(
            &client,
            view.addr,
            view.token,
            &format!(
                "{}/data/{}/{}",
                binding.mount,
                binding.kv_path_prefix,
                vault::SECRET_RESOLVER_READINESS_KEY
            ),
        )
        .await?,
        StatusCode::OK,
        "workload token must read the canonical readiness seed"
    );
    assert_eq!(
        vault_read_status(
            &client,
            view.addr,
            view.token,
            &format!("{}/data/outside/readiness", binding.mount),
        )
        .await?,
        StatusCode::FORBIDDEN,
        "workload token must not read outside its configured prefix"
    );
    let expected_tenant = vocab::TenantId::parse(binding.tenant_id)?;
    let expected_store = binding.store_id.to_owned();
    let expected_key = view.settings_key_name.to_owned();
    let expected_readiness = view.readiness_interval;
    drop(view);

    let mut roles = crate::plan::SettingsOnlyPlan::bundled()?.provider_build()?;
    let provider = build_vault(
        inputs,
        roles.settings_key_provider()?,
        roles.settings_secret_resolver()?,
    )?;
    let domain = provider.deps.for_domain::<vault::caps::Settings>();
    let targets = domain.secret_resolver_readiness_targets();
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].tenant(), expected_tenant);
    assert_eq!(targets[0].coordinate().store_id(), expected_store);
    assert_eq!(
        targets[0].coordinate().key(),
        vault::SECRET_RESOLVER_READINESS_KEY
    );
    assert_eq!(provider.settings_key.as_str(), expected_key);
    assert_eq!(provider.readiness, expected_readiness);
    let resolved = domain
        .secret_resolver()
        .resolve(targets[0].tenant(), targets[0].coordinate())
        .await?;
    assert_eq!(resolved.expose(), READINESS_VALUE.as_bytes());
    let _readiness = settings_composition::SettingsProviderReadiness::new(
        &domain,
        provider.settings_key.clone(),
        settings_composition::KeyProviderReadinessInterval::try_new(provider.readiness)?,
    )
    .await?;
    for resource in provider.deps.runtime_resources() {
        resource.shutdown().await?;
    }
    Ok(())
}
